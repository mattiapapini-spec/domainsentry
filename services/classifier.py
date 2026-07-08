"""
Classifier Service (:8007)
Baseline diffing + auto-classificazione varianti.
"""

import os, json, logging
from pathlib import Path
from fastapi import FastAPI, APIRouter, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional

from shared.security import apply_security, sanitize_error, sanitize_log_input
from shared.utils import now_iso
from shared.constants import (SEVERITY_MAP, KNOWN_PARKING_NS, KNOWN_PARKING_IPS,
                               MARKETPLACE_NS, PRIVACY_MX_PROVIDERS, FORWARDING_MX_PROVIDERS,
                               BUSINESS_MX_PROVIDERS, ENTERPRISE_CERT_PROVIDERS, PARKING_MX)

app = FastAPI(title="Classifier", version="4.0.0")
apply_security(app)
router = APIRouter()
logger = logging.getLogger("classifier")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CLASS] %(message)s")

BASELINE_DIR = Path(os.environ.get("BASELINE_DIR", "/data/baselines"))


@app.get("/health")
def health():
    return {"status": "healthy", "service": "classifier", "version": "4.0.0"}


# ═══════════════════════════════════════════════════════════════
# AUTO-CLASSIFICAZIONE VARIANTI
# ═══════════════════════════════════════════════════════════════

class VariantInput(BaseModel):
    domain: str
    fuzzer: str = ""
    dns: Optional[dict] = None
    cert: Optional[dict] = None
    http: Optional[dict] = None
    whois: Optional[dict] = None
    reputation: Optional[dict] = None


@router.post("/classify/variant", tags=["Classification"])
def classify_variant_endpoint(v: VariantInput):
    return classify_variant(v)


def _domain_age(whois_data: dict) -> dict:
    """Analizza l'età del dominio dai dati WHOIS.

    Ritorna: {age_days, created, updated, recently_reregistered}.
    La data di registrazione è il discriminante più forte per il typosquatting:
    un dominio registrato PRIMA dell'inizio di una campagna ostile è quasi sempre
    una terza parte legittima, mentre uno registrato di recente è un candidato reale.

    ATTENZIONE ai falsi negativi: un dominio scaduto e RI-REGISTRATO da un attaccante
    ha una creation_date vecchia ma è pericoloso. Rileviamo questo caso confrontando
    updated_date con creation_date: se il dominio è "vecchio" ma aggiornato di recente
    (possibile cambio di titolare), NON lo trattiamo come terza parte sicura.
    """
    from datetime import datetime, timezone
    out = {"age_days": None, "created": None, "updated": None, "recently_reregistered": False}

    def _coerce(val):
        # python-whois often returns creation_date/updated_date as a LIST of dates
        # (multiple registry records). Take the earliest for creation. Also accept
        # datetime objects directly.
        # SECURITY: the registrant controls their own WHOIS, so cap work to prevent
        # a hostile record (huge list / huge string) from causing CPU DoS.
        if val is None:
            return None
        if isinstance(val, list):
            parsed = [p for p in (_parse(x) for x in val[:10]) if p]
            return min(parsed) if parsed else None
        if isinstance(val, datetime):
            return val.replace(tzinfo=None)
        return _parse(val)

    def _parse(s):
        if isinstance(s, datetime):
            return s.replace(tzinfo=None)
        # Only strings carry a parseable date; ignore dict/bytes/int/nested lists.
        if not isinstance(s, str):
            return None
        # Bound length: a real date string is short; anything longer is junk/hostile.
        s = s.strip()[:40]
        # normalize: drop trailing Z, fractional seconds, timezone offsets
        s = s.replace("Z", "").split(".")[0].split("+")[0].strip()
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
                    "%d-%b-%Y", "%Y/%m/%d", "%d/%m/%Y", "%d.%m.%Y"):
            try:
                return datetime.strptime(s[:19] if "T" in s or ":" in s else s[:10], fmt)
            except ValueError:
                continue
        return None

    created = _coerce(whois_data.get("creation_date"))
    updated = _coerce(whois_data.get("updated_date"))
    if not created:
        return out
    now = datetime.utcnow()
    age_days = (now - created).days
    # A creation date in the future is corrupt/hostile WHOIS data: clamp to 0 and
    # treat as "unknown age" rather than a large negative number.
    if age_days < 0:
        return out
    out["age_days"] = age_days
    out["created"] = created.strftime("%Y-%m-%d")
    if updated:
        out["updated"] = updated.strftime("%Y-%m-%d")
        days_since_update = (now - updated).days
        if age_days > 730 and 0 <= days_since_update < 120:
            out["recently_reregistered"] = True
    return out


def classify_variant(v: VariantInput):
    """Auto-classificazione di una variante dnstwist."""
    logger.info(f"Classify variant: {sanitize_log_input(v.domain)} ({sanitize_log_input(v.fuzzer)})")

    dns = v.dns or {}
    http = v.http or {}
    cert = v.cert or {}
    whois_data = v.whois or {}

    records = dns.get("records") or {}
    a_records = records.get("A") or []
    mx_records = records.get("MX") or []
    ns_records = records.get("NS") or []

    # Estrai info HTTP
    http_checks = [c for c in (http.get("checks") or []) if isinstance(c, dict)]
    any_http_active = any(c.get("status_code") and c["status_code"] < 400 for c in http_checks)
    max_content_len = max((c.get("content_length") or 0 for c in http_checks), default=0)

    # Estrai info cert
    _ct = cert.get("ct_certificates") or {}
    cert_total = _ct.get("total", 0)
    cert_cns = _ct.get("unique_cn") or []

    mx_str = " ".join(mx_records).lower()
    ns_str = " ".join(ns_records).lower()
    hidden_summary = []

    # ── Regole di classificazione (ordine di priorità) ──

    # PARKING
    if any_http_active and max_content_len <= 200:
        return _result(v.domain, "parking", "high",
                       "http_active_minimal_content",
                       "HTTP attivo con contenuto minimo (<200b), tipico di pagine redirect/parking")

    if any(pk in ns_str for pk in KNOWN_PARKING_NS):
        return _result(v.domain, "parking", "high",
                       "known_parking_ns",
                       f"NS su provider parking noto: {ns_str}")

    if any(ip in KNOWN_PARKING_IPS for ip in a_records):
        return _result(v.domain, "parking", "high",
                       "known_parking_ip",
                       f"IP parking noto: {a_records}")

    # IN VENDITA
    if any(mk in ns_str for mk in MARKETPLACE_NS):
        return _result(v.domain, "for_sale", "high",
                       "marketplace_ns",
                       f"NS su marketplace domini: {ns_str}")

    if any(pmx in mx_str for pmx in PARKING_MX):
        return _result(v.domain, "for_sale", "medium",
                       "parking_mx",
                       f"MX su parking provider: {mx_str}")

    # SOSPETTO (hidden elements) — priorità su legittimo probabile
    # Un sito con hidden forms è sospetto ANCHE SE ha contenuto sostanziale
    hidden_risk = 0
    for check in http_checks:
        he = check.get("hidden_elements", {})
        if isinstance(he, dict):
            hr = he.get("risk_indicators", 0)
            if hr > hidden_risk:
                hidden_risk = hr
                hidden_summary = he.get("summary", [])
    if hidden_risk >= 30:
        return _result(v.domain, "suspicious", "high",
                       "hidden_elements_detected",
                       f"Tag nascosti ad alto rischio ({hidden_risk}/100): {'; '.join(hidden_summary[:3])}")

    # LEGITTIMO PROBABILE
    if any(ep in cn for ep in ENTERPRISE_CERT_PROVIDERS for cn in cert_cns):
        return _result(v.domain, "legitimate_probable", "medium",
                       "enterprise_cert_provider",
                       f"Certificati di provider enterprise: {cert_cns}")

    # Un sito con contenuto sostanziale è di norma legittimo, MA se il dominio è
    # recente E ha MX attivo, il "sito di facciata + email" è un profilo di typosquat,
    # non di terza parte legittima: non declassare, lascialo alla verifica.
    _age_pre = _domain_age(whois_data)
    _recent = _age_pre["age_days"] is not None and _age_pre["age_days"] < 540
    if any_http_active and max_content_len > 3000 and not (_recent and mx_records):
        return _result(v.domain, "legitimate_probable", "low",
                       "http_active_substantial_content",
                       f"Sito attivo con contenuto sostanziale ({max_content_len}b)")

    # SOSPETTO (infrastruttura)
    if mx_records and not a_records:
        return _result(v.domain, "suspicious", "high",
                       "mx_only_no_web",
                       "MX attivo senza record A — profilo solo-email")

    if any(pp in mx_str for pp in PRIVACY_MX_PROVIDERS):
        return _result(v.domain, "suspicious", "high",
                       "privacy_mx_provider",
                       f"MX su provider ad alta privacy: {mx_str}")

    if any(fw in mx_str for fw in FORWARDING_MX_PROVIDERS):
        return _result(v.domain, "suspicious", "medium",
                       "forwarding_mx",
                       f"MX su email forwarding: {mx_str}")

    # Hidden elements rischio moderato
    if hidden_risk >= 15:
        return _result(v.domain, "needs_review", "medium",
                       "hidden_elements_moderate",
                       f"Tag nascosti rilevati ({hidden_risk}/100): {'; '.join(hidden_summary[:3])}")

    # ── ETÀ DEL DOMINIO (punto 1) ──
    # La data di registrazione è il discriminante più forte: un dominio registrato
    # molto prima di una campagna ostile, e inerte da allora, è quasi sempre una
    # terza parte legittima. Questo toglie dalla coda i molti domini pre-campagna
    # (nomi propri, terzi storici) oggi marcati genericamente "needs_review".
    age = _domain_age(whois_data)
    if age["age_days"] is not None:
        # Cautela anti-falso-negativo: se il dominio è vecchio MA aggiornato di recente
        # (possibile ri-registrazione dopo scadenza / cambio titolare), NON lo declassiamo.
        if age["recently_reregistered"]:
            return _result(v.domain, "needs_review", "medium",
                           "old_domain_recently_updated",
                           f"Dominio datato ({age['created']}) ma aggiornato di recente ({age['updated']}), "
                           f"possibile ri-registrazione, verifica manuale")
        # Vecchio (>18 mesi) e senza segnali ostili emersi sopra → terza parte probabile
        if age["age_days"] > 540:
            yrs = age["age_days"] // 365
            return _result(v.domain, "likely_third_party", "low",
                           "predates_campaign",
                           f"Registrato il {age['created']} (~{yrs} anni fa), prima della finestra "
                           f"tipica di registrazione ostile e senza segnali di minaccia, "
                           f"probabile terza parte preesistente")

    # DA VERIFICARE
    return _result(v.domain, "needs_review", "low",
                   "no_matching_rule",
                   "Nessuna regola corrisponde con sufficiente certezza")


def _result(domain, category, confidence, rule, rationale):
    action_map = {
        "parking": "monitor_passive",
        "for_sale": "monitor_passive",
        "legitimate_probable": "whitelist_candidate",
        "likely_third_party": "whitelist_candidate",
        "suspicious": "block_and_monitor",
        "needs_review": "manual_review"
    }
    return JSONResponse(content={
        "domain": domain, "timestamp": now_iso(),
        "auto_classification": category,
        "confidence": confidence,
        "rule": rule,
        "rationale": rationale,
        "action": action_map.get(category, "manual_review"),
        "manual_review_required": category in ("needs_review", "suspicious")
    })


# ═══════════════════════════════════════════════════════════════
# BATCH CLASSIFICATION
# ═══════════════════════════════════════════════════════════════

class BatchInput(BaseModel):
    # Cap batch size: a legitimate scan classifies at most a few hundred variants;
    # an unbounded list is a DoS vector.
    variants: list[VariantInput] = Field(..., max_length=1000)


@router.post("/classify/batch", tags=["Classification"])
def classify_batch(batch: BatchInput):
    """Classifica un batch di varianti."""
    results = []
    counts = {"parking": 0, "for_sale": 0, "legitimate_probable": 0, "likely_third_party": 0,
              "suspicious": 0, "needs_review": 0}

    for v in batch.variants:
        resp = classify_variant(v)
        data = json.loads(resp.body)
        results.append(data)
        cat = data.get("auto_classification", "needs_review")
        counts[cat] = counts.get(cat, 0) + 1

    return JSONResponse(content={
        "timestamp": now_iso(),
        "total": len(results),
        "summary": counts,
        "results": results
    })


# ═══════════════════════════════════════════════════════════════
# BASELINE DIFFING
# ═══════════════════════════════════════════════════════════════

class DiffInput(BaseModel):
    domain: str
    client: str
    legitimate: str = ""  # dominio legittimo del cliente
    current: dict  # output aggregato dei servizi di intelligence
    baseline: Optional[dict] = None  # baseline precedente


@router.post("/diff", tags=["Diffing"])
def baseline_diff(inp: DiffInput):
    """Confronta stato corrente con baseline, genera alert."""
    logger.info(f"Diff: {sanitize_log_input(inp.domain)} client={sanitize_log_input(inp.client)}")
    alerts = []
    prev = inp.baseline or {}
    curr = inp.current

    is_legit = (inp.domain == inp.legitimate)

    # Note: a key may be PRESENT with value None (e.g. "cert": null when a domain
    # has no certificates). dict.get(k, {}) returns None in that case, not {}.
    # Use (x or {}) everywhere so a None value also falls back to empty.

    # DNS diff
    prev_dns = (prev.get("dns") or {}).get("records", {})
    curr_dns = (curr.get("dns") or {}).get("records", {})
    _diff_records(prev_dns, curr_dns, alerts)

    # Email auth diff
    prev_ea = (prev.get("dns") or {}).get("email_auth", {})
    curr_ea = (curr.get("dns") or {}).get("email_auth", {})
    _diff_email_auth(prev_ea, curr_ea, alerts)

    # HTTP diff
    prev_http = (prev.get("http") or {}).get("checks", [])
    curr_http = (curr.get("http") or {}).get("checks", [])
    _diff_http(prev_http, curr_http, alerts, is_legit)

    # Cert diff
    prev_certs = (prev.get("cert") or {}).get("ct_certificates", {})
    curr_certs = (curr.get("cert") or {}).get("ct_certificates", {})
    _diff_certs(prev_certs, curr_certs, alerts)

    # WHOIS diff
    _diff_whois(prev.get("whois") or {}, curr.get("whois") or {}, alerts)

    # Reputation diff
    _diff_reputation(prev.get("reputation") or {}, curr.get("reputation") or {}, alerts)

    # Hidden elements diff
    _diff_hidden_elements(curr.get("http") or {}, prev.get("http") or {}, is_legit, alerts)

    # Status complessivo
    max_sev = max((SEVERITY_MAP.get(a["type"], "LOW") for a in alerts), default="CLEAN",
                  key=lambda s: {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(s, 0))

    return JSONResponse(content={
        "domain": inp.domain, "client": inp.client, "timestamp": now_iso(),
        "alerts": alerts,
        "alert_count": len(alerts),
        "max_severity": max_sev,
        "overall_status": f"{max_sev} — {'AZIONE IMMEDIATA' if max_sev == 'CRITICAL' else 'ATTENZIONE' if max_sev == 'HIGH' else 'NESSUNA DIVERGENZA' if max_sev == 'CLEAN' else 'MONITORARE'}",
        "new_baseline": curr
    })


def _diff_records(prev: dict, curr: dict, alerts: list):
    type_map = {"A": "a_record_changed", "MX": "mx_record_changed",
                "NS": "ns_changed", "TXT": "txt_changed", "SOA": "soa_changed"}
    for rtype, alert_type in type_map.items():
        p = sorted(prev.get(rtype, []))
        c = sorted(curr.get(rtype, []))
        if p != c and (p or c):
            alerts.append(_alert(alert_type, f"Record {rtype} modificato: {p} → {c}",
                                 {"old": p, "new": c}))


def _diff_email_auth(prev: dict, curr: dict, alerts: list):
    for field, alert_type in [("dmarc", "dmarc_changed"), ("dkim", "dkim_added"),
                               ("bimi", "bimi_added"), ("caa", "caa_changed")]:
        p = (prev.get(field) or {}).get("present", False)
        c = (curr.get(field) or {}).get("present", False)
        if c and not p:
            alerts.append(_alert(alert_type, f"{field.upper()} aggiunto", {}))

    p_spf = (prev.get("spf") or {}).get("records", [])
    c_spf = (curr.get("spf") or {}).get("records", [])
    if p_spf != c_spf and (p_spf or c_spf):
        alerts.append(_alert("spf_changed", f"SPF modificato: {p_spf} → {c_spf}",
                             {"old": p_spf, "new": c_spf}))


def _diff_http(prev: list, curr: list, alerts: list, is_legit: bool = False):
    prev_urls = {c["url"]: c for c in prev if isinstance(c, dict)}
    for check in curr:
        if not isinstance(check, dict):
            continue
        url = check.get("url", "")
        p = prev_urls.get(url, {})
        if check.get("status_code") and check["status_code"] < 400:
            if not p.get("status_code") or p["status_code"] >= 400:
                alerts.append(_alert("http_activated", f"SITO ATTIVATO: {url} (HTTP {check['status_code']})", {}))
        if check.get("suspicious_patterns"):
            # Un'area di login è NORMALE sul dominio legittimo del cliente (portali,
            # gestionali, webmail) e su moltissimi siti di terzi. La presenza di
            # "login/password/utente" NON è di per sé phishing. Allerta solo quando
            # il pattern è una NOVITÀ rispetto alla baseline (un form di credenziali
            # comparso dove prima non c'era) E NON è il dominio legittimo.
            if is_legit:
                continue
            prev_patterns = {sp.get("pattern") for sp in (p.get("suspicious_patterns") or [])}
            for sp in check["suspicious_patterns"]:
                # solo pattern di credenziali realmente nuovi (non già presenti in baseline)
                if sp.get("pattern") in prev_patterns:
                    continue
                # ignora il semplice <form action> generico: serve un segnale di credenziali
                if "password" not in sp.get("pattern", "") and "login" not in sp.get("pattern", "") \
                   and "sign" not in sp.get("pattern", ""):
                    continue
                alerts.append(_alert("credential_form_detected",
                                     f"Nuovo pattern di credenziali su {url}: {sp['pattern']}", sp))


def _diff_certs(prev: dict, curr: dict, alerts: list):
    prev_total = prev.get("total", 0)
    curr_total = curr.get("total", 0)
    if curr_total > prev_total:
        new_count = curr_total - prev_total
        alerts.append(_alert("new_certificate_batch" if new_count > 10 else "new_certificate",
                             f"Nuovi certificati TLS: {new_count}", {"count": new_count}))


def _diff_whois(prev: dict, curr: dict, alerts: list):
    if prev.get("registrar") and curr.get("registrar") and prev["registrar"] != curr["registrar"]:
        alerts.append(_alert("whois_registrar_changed",
                             f"Registrar: {prev['registrar']} → {curr['registrar']}", {}))
    if prev.get("expiration_date") and curr.get("expiration_date"):
        if prev["expiration_date"] != curr["expiration_date"]:
            alerts.append(_alert("whois_renewed", f"Scadenza: {prev['expiration_date']} → {curr['expiration_date']}", {}))
    if prev.get("privacy_protected") and not curr.get("privacy_protected"):
        alerts.append(_alert("whois_privacy_removed", "WHOIS privacy rimossa", {}))


def _diff_reputation(prev: dict, curr: dict, alerts: list):
    pv = prev.get("virustotal") or {}
    cv = curr.get("virustotal") or {}
    if cv.get("malicious", 0) > 0 and pv.get("malicious", 0) == 0:
        alerts.append(_alert("vt_malicious_detected",
                             f"VT malicious: {cv['malicious']}", cv))
    po = prev.get("otx") or {}
    co = curr.get("otx") or {}
    if co.get("pulse_count", 0) > po.get("pulse_count", 0):
        alerts.append(_alert("otx_pulse_detected",
                             f"OTX pulse: {co['pulse_count']}", co))


def _alert(alert_type: str, message: str, detail: dict) -> dict:
    return {
        "type": alert_type,
        "severity": SEVERITY_MAP.get(alert_type, "MEDIUM"),
        "message": message,
        "detail": detail,
        "timestamp": now_iso()
    }


def _diff_hidden_elements(curr_http: dict, prev_http: dict, is_legit: bool, alerts: list):
    """
    Confronta hidden elements tra cicli. Se il dominio è il legittimo del cliente,
    qualsiasi hidden element è CRITICAL (indica compromissione).
    """
    for check in curr_http.get("checks", []):
        he = check.get("hidden_elements", {})
        if not isinstance(he, dict):
            continue

        url = check.get("url", "?")
        risk = he.get("risk_indicators", 0)

        # Cerca se nella baseline precedente c'erano già hidden elements per questo URL
        prev_risk = 0
        for prev_check in prev_http.get("checks", []):
            if prev_check.get("url") == url:
                prev_he = prev_check.get("hidden_elements", {})
                if isinstance(prev_he, dict):
                    prev_risk = prev_he.get("risk_indicators", 0)
                break

        # Alert solo se NUOVI hidden elements (risk aumentato)
        if risk <= prev_risk:
            continue

        if is_legit:
            # ── DOMINIO LEGITTIMO: qualsiasi hidden element è CRITICAL ──
            # Indica possibile compromissione dell'infrastruttura del cliente
            if he.get("hidden_forms"):
                alerts.append(_alert("legit_hidden_form_detected",
                    f"⚠ COMPROMISSIONE: form nascosto rilevato su {url} (dominio LEGITTIMO del cliente). "
                    f"Possibile web skimmer o credential harvesting iniettato.",
                    {"url": url, "forms": he["hidden_forms"], "risk": risk}))

            if he.get("invisible_iframes"):
                alerts.append(_alert("legit_invisible_iframe_detected",
                    f"⚠ COMPROMISSIONE: iframe invisibile su {url} (dominio LEGITTIMO). "
                    f"Possibile caricamento contenuto malevolo.",
                    {"url": url, "iframes": he["invisible_iframes"], "risk": risk}))

            if he.get("obfuscated_js"):
                alerts.append(_alert("legit_obfuscated_js_detected",
                    f"⚠ COMPROMISSIONE: JavaScript offuscato su {url} (dominio LEGITTIMO). "
                    f"Indicatori: {', '.join(he['obfuscated_js'][0].get('indicators', []))}",
                    {"url": url, "scripts": he["obfuscated_js"], "risk": risk}))

            if he.get("meta_redirects"):
                target_url = he["meta_redirects"][0].get("target_url", "?")
                alerts.append(_alert("legit_meta_redirect_detected",
                    f"⚠ COMPROMISSIONE: meta redirect nascosto su {url} (dominio LEGITTIMO) "
                    f"verso {target_url}. Possibile hijack.",
                    {"url": url, "redirects": he["meta_redirects"], "risk": risk}))

            if he.get("hidden_divs_with_content"):
                for div in he["hidden_divs_with_content"]:
                    if div.get("contains_form") or div.get("contains_input"):
                        alerts.append(_alert("legit_content_injected",
                            f"⚠ COMPROMISSIONE: contenuto nascosto con form iniettato su {url} "
                            f"(dominio LEGITTIMO). Testo: {div.get('visible_text_preview', '')[:100]}",
                            {"url": url, "div": div, "risk": risk}))
                        break

            # Generico per qualsiasi hidden element su legit
            if risk >= 10 and not any(a["type"].startswith("legit_") for a in alerts[-5:]):
                alerts.append(_alert("legit_hidden_elements_detected",
                    f"⚠ Tag nascosti rilevati su {url} (dominio LEGITTIMO del cliente, risk {risk}/100). "
                    f"{'; '.join(he.get('summary', [])[:3])}",
                    {"url": url, "risk": risk, "summary": he.get("summary", [])}))

        else:
            # ── VARIANTE / TARGET: severity standard ──
            if risk >= 20:
                for item in he.get("summary", []):
                    alerts.append(_alert("hidden_elements_high_risk",
                        f"Tag nascosti su {url}: {item}",
                        {"risk": risk, "url": url}))

app.include_router(router)
