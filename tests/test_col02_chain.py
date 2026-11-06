"""COL-02 (consumatori) — catena end-to-end: un guasto del DNS non deve diventare un alert né riaprire un caso.

Criterio «Catena end-to-end» di BUG-REGISTER.md («ASSEGNA · COL-02 (consumatori, secondo
commit)»). Ogni test percorre la catena VERA, senza mock dei pezzi nostri:

    spy su `subprocess.run` (stdout di `dig` nel formato nuovo, argv di `dig_lookup`)
      -> `services.dns_intel` (GET /dns, reale)
      -> `services.orchestrator._run_pipeline` (reale: raccolta, classificazione, `_persist_intel`,
         eventi, `_ingest_cases`)
      -> `services.classifier` (/classify/variant e /diff, reale, in-process)
      -> `services.case_manager` (SQLite reale su una directory temporanea)

Fuori dalla catena restano solo la rete (nessun `dig` reale, nessun HTTP) e i collector
cert/http, sostituiti da risposte fisse e neutre. Lo stato (snapshot, storia, database dei casi)
sta in `tmp_path_factory`: mai il volume `/data`.

Il ciclo di ogni scenario è ok -> guasto -> ok, con la stessa zona finta ai due estremi e il
guasto scelto dal nome dello scenario. Cosa si pretende, per ogni scenario di guasto:

  * 0 alert in tutta la storia dei diff (oggi: 6 all'andata e 9 al ritorno per il guasto
    totale, 1 + 1 HIGH per il solo A o il solo MX);
  * lo snapshot dopo il ciclo di guasto è uguale a quello di prima per le parti che il
    riporto conserva (record, stati, SPF/DMARC/BIMI/CAA); per il guasto totale è la sezione
    precedente intera (percorso CODE-01), a meno dei marcatori. Sottodomini e selettori DKIM
    si riportano per nome (COL-31, con i propri test): nei guasti parziali qui non si confrontano;
  * la classificazione del ciclo di guasto è `insufficient_data` se è indeterminato uno fra
    A, MX, NS (o il modulo intero), altrimenti quella di prima; al ritorno torna quella di prima.

Più tre casi chiusi dall'analista che devono restare chiusi, e due controlli di contrasto
(un MX NXDOMAIN vero allerta all'andata e al ritorno; un pacchetto perso, assorbito da
`+tries=2`, non produce nulla).

Le stringhe di `dig` sono nel formato registrato con `dig` 9.18.39 (vedi
`tests/test_utils.py`, `_RES01_CORPUS`, e `tests/test_dns_intel.py`, `_dig_stdout`); nomi di
esempio e indirizzi sono quelli riservati (`.example`, 192.0.2.0/24, 2001:db8::/32).
"""
import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from shared import utils
from shared.constants import SEVERITY_MAP

DOMAIN = "acme-typo.example"
CLIENT = "tenant-x"
_TOKEN = "col02-chain-test-token"
_AUTH = {"Authorization": f"Bearer {_TOKEN}"}


# ── `dig`: stdout nel formato di `dig_lookup` ─────────────────────────────

_LOST_TRY = ";; communications error to 127.0.0.1#53: timed out\n"
_REFUSED_STDOUT = (
    ";; communications error to 127.0.0.9#53: connection refused\n"
    ";; communications error to 127.0.0.9#53: connection refused\n"
    ";; no servers could be reached\n"
)
_BAD_PACKET_CAA = (
    ";; Got bad packet: FORMERR\n"
    "59 bytes\n"
    "15 0c 85 80 00 01 00 01 00 00 00 01 06 62 61 64          .............bad\n"
    "63 61 61 04 74 65 73 74 00 01 01 00 01 c0 0c 01          caa.test........\n"
    "01 00 01 00 00 00 3c 00 07 00 c8 69 73 73 75 65          ......<....issue\n"
    "00 00 29 04 d0 00 00 00 00 00 00                         ..)........\n"
)
_MALFORMED_TXT = (
    ";; Warning: Message parser reports malformed message packet.\n"
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51086\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
    ";; WARNING: Message has 15 extra bytes at end\n"
    "\n"
)


def _dig_answer(name, rtype, rdata=(), rcode="NOERROR", prefix=""):
    out = (prefix + ";; Got answer:\n"
           f";; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: 4242\n"
           f";; flags: qr aa rd ra; QUERY: 1, ANSWER: {len(rdata)}, AUTHORITY: 0, ADDITIONAL: 1\n"
           "\n"
           ";; OPT PSEUDOSECTION:\n"
           "; EDNS: version: 0, flags:; udp: 1232\n")
    if rdata:
        out += ";; ANSWER SECTION:\n" + "".join(f"{name}.\t\t{rtype}\t{r}\n" for r in rdata) + "\n"
    return out


def _respond(action, argv, name, rtype, rdata):
    if action in ("servfail", "refused", "nxdomain"):
        return subprocess.CompletedProcess(
            argv, 0, stdout=_dig_answer(name, rtype, (), action.upper()), stderr="")
    if action == "transport":
        return subprocess.CompletedProcess(argv, 9, stdout=_REFUSED_STDOUT, stderr="")
    if action == "timeout":
        raise subprocess.TimeoutExpired(argv, 20)
    if action == "bad_packet":
        return subprocess.CompletedProcess(argv, 0, stdout=_BAD_PACKET_CAA, stderr="")
    if action == "malformed_txt":
        return subprocess.CompletedProcess(argv, 0, stdout=_MALFORMED_TXT, stderr="")
    if action == "lost_first_try":
        return subprocess.CompletedProcess(
            argv, 0, stdout=_dig_answer(name, rtype, rdata, prefix=_LOST_TRY), stderr="")
    raise AssertionError(f"azione sconosciuta: {action}")


class _DigSpy:
    """Sostituto di `subprocess.run`. Risponde dalla zona finta (NODATA per ciò che non c'è);
    `rules` = [(predicato(nome, tipo), azione)] vale finché non viene svuotata: la prima regola
    che corrisponde decide la risposta, nel formato che l'argv di `dig_lookup` richiede."""

    def __init__(self, zone):
        self.zone = zone
        self.rules = []
        self.calls = 0

    def __call__(self, argv, *args, **kwargs):
        self.calls += 1
        name, rtype = argv[-2], argv[-1]
        rdata = self.zone.get((name, rtype), [])
        for predicate, action in self.rules:
            if predicate(name, rtype):
                return _respond(action, argv, name, rtype, rdata)
        return subprocess.CompletedProcess(argv, 0, stdout=_dig_answer(name, rtype, rdata), stderr="")


# ── Le tre zone finte ──────────────────────────────────────────────────────

def _zone_std(d):
    """A + MX + NS + SPF/DMARC/BIMI/CAA + due selettori DKIM + due sottodomini. Senza altri
    segnali il classificatore dice `needs_review`/`no_matching_rule` (severità di caso MEDIUM)."""
    return {
        (d, "A"): ["192.0.2.10", "192.0.2.11"],
        (d, "AAAA"): ["2001:db8::1"],
        (d, "MX"): [f"10 mail.{d}."],
        (d, "NS"): [f"ns1.{d}.", f"ns2.{d}."],
        (d, "TXT"): ['"hello world"', '"v=spf1 -all"'],
        (d, "SOA"): [f"ns1.{d}. hostmaster.{d}. 2026010101 7200 900 1209600 3600"],
        (d, "CAA"): ['0 issue "letsencrypt.org"'],
        (f"_dmarc.{d}", "TXT"): ['"v=DMARC1; p=reject"'],
        (f"default._bimi.{d}", "TXT"): ['"v=BIMI1; l=https://acme-typo.example/logo.svg"'],
        (f"google._domainkey.{d}", "TXT"): ['"v=DKIM1; k=rsa; p=KEY"'],
        (f"selector1._domainkey.{d}", "TXT"): ['"v=DKIM1; k=rsa; p=KEY2"'],
        (f"www.{d}", "A"): ["192.0.2.20"],
        (f"mail.{d}", "A"): ["192.0.2.21"],
    }


def _zone_parked(d):
    """NS su un provider di parcheggio noto, nessun MX: `parking`/`known_parking_ns` (LOW)."""
    zone = _zone_std(d)
    zone[(d, "NS")] = ["ns1.sedoparking.com.", "ns2.sedoparking.com."]
    del zone[(d, "MX")]
    return zone


def _zone_privacy(d):
    """MX su un provider ad alta privacy: `suspicious`/`privacy_mx_provider` (HIGH)."""
    zone = _zone_std(d)
    zone[(d, "MX")] = ["10 mail.protonmail.ch."]
    return zone


_ZONES = {"std": _zone_std, "parked": _zone_parked, "privacy": _zone_privacy}


# ── Collector fissi e risposta HTTP finta ──────────────────────────────────

_CERT_OK = {"domain": DOMAIN, "timestamp": "2026-10-24T10:00:00Z",
            "ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
            "tls_live": None, "san_subdomains_discovered": [], "error": None}
_HTTP_QUIET = {"domain": DOMAIN, "timestamp": "2026-10-24T10:00:00Z", "checks": [],
               "overall_status": "down", "hidden_elements_risk": 0, "error": None}
_FEED_ENTRY = {"domain": DOMAIN, "client": CLIENT, "type": "target",
               "legitimate": "acme.example", "fuzzer": "insertion"}
# WHOIS di un dominio registrato 60 giorni fa (relativo a oggi, non una data fissa). Il WHOIS non
# entra nei diff: serve a dare ai cicli del profilo del verifier la stessa classificazione di prima.
_WHOIS_RECENT = {"domain": DOMAIN, "registrar": "Example Registrar", "updated_date": None,
                 "creation_date": (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S"),
                 "expiration_date": None, "status": [], "nameservers": [], "privacy_protected": False,
                 "dnssec": False, "age_days": None, "error": None,
                 "registrant": {"name": None, "org": None, "country": None, "email": None}}


class _Resp:
    def __init__(self, payload, ok=True, status_code=200):
        self._payload = payload
        self.ok = ok
        self.status_code = status_code

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


# ── Scenari di guasto ──────────────────────────────────────────────────────

class _Outage:
    def __init__(self, rules, classification, total=False):
        self.rules = rules                    # [(predicato(nome, tipo), azione)]
        self.classification = classification  # classificazione del ciclo di guasto (profilo `std`)
        self.total = total                    # tutti e 7 i tipi base indeterminati: modulo fallito


def _all(name, rtype):
    return True


_INDETERMINATE = "insufficient_data"   # A, MX, NS o il modulo intero indeterminati
_UNCHANGED = "needs_review"            # solo TXT/DMARC/CAA: nessuna regola li legge
_OUTAGES = {
    "servfail_all": _Outage([(_all, "servfail")], _INDETERMINATE, total=True),
    "refused_all": _Outage([(_all, "refused")], _INDETERMINATE, total=True),
    "connection_refused": _Outage([(_all, "transport")], _INDETERMINATE, total=True),
    "timeout_all": _Outage([(_all, "timeout")], _INDETERMINATE, total=True),
    "servfail_a": _Outage([(lambda n, t: n == DOMAIN and t == "A", "servfail")], _INDETERMINATE),
    "servfail_mx": _Outage([(lambda n, t: t == "MX", "servfail")], _INDETERMINATE),
    "servfail_ns": _Outage([(lambda n, t: t == "NS", "servfail")], _INDETERMINATE),
    "servfail_txt": _Outage([(lambda n, t: t == "TXT", "servfail")], _UNCHANGED),
    "servfail_dmarc": _Outage([(lambda n, t: n.startswith("_dmarc."), "servfail")], _UNCHANGED),
    "servfail_caa": _Outage([(lambda n, t: t == "CAA", "servfail")], _UNCHANGED),
    "malformed_txt": _Outage([(lambda n, t: n == DOMAIN and t == "TXT", "malformed_txt")], _UNCHANGED),
    "bad_packet_caa": _Outage([(lambda n, t: t == "CAA", "bad_packet")], _UNCHANGED),
}


# ── Esecuzione della catena ────────────────────────────────────────────────

class _Cycle:
    def __init__(self, classification, dns, alerts, case):
        self.classification = classification   # la classificazione pubblicata per il dominio
        self.dns = dns                         # sezione `dns` dello snapshot dopo il ciclo (None se non c'è)
        self.alerts = alerts                   # gli alert aggiunti alla storia in questo ciclo (dict interi)
        self.new_alerts = [(a["type"], a["severity"]) for a in alerts]   # [(tipo, severità)], ordine di storia
        self.case = case                       # riga del caso (o None)


class _Run:
    def __init__(self):
        self.cycles = []
        self.errors = []        # risposte non 200 di classificatore e case-manager
        self.closed_case = None  # il caso subito dopo la chiusura dell'analista
        self.dig_calls = 0


def _run_chain(tmp_path, profile, rules, *, close_as=None):
    """Tre cicli di `_run_pipeline` sulla zona `profile`: sano, guasto (`rules` attive), sano.
    Con `close_as` l'analista chiude il caso dopo il primo ciclo."""
    zone = _ZONES[profile](DOMAIN)
    return _run_steps(tmp_path, [(zone, []), (zone, rules), (zone, [])], close_as=close_as)


def _run_steps(tmp_path, steps, *, close_as=None, whois=None):
    """Un ciclo di `_run_pipeline` per ogni passo `(zona, regole)`: la zona finta è quella del
    passo, le `regole` ([(predicato(nome, tipo), azione)]) i guasti attivi in quel ciclo. Con
    `close_as` l'analista chiude il caso dopo il primo ciclo; con `whois` il ciclo raccoglie
    anche il WHOIS (risposta fissa)."""
    spy = _DigSpy({})
    run = _Run()
    published = []
    with pytest.MonkeyPatch.context() as mp:
        # Prima di importare il case-manager (che crea il database all'import): mai il volume /data.
        mp.setenv("CASES_DB", str(tmp_path / "cases.db"))
        mp.setenv("ADMIN_PASSWORD", "col02-chain-admin-password")
        import services.case_manager as cm
        import services.orchestrator as o
        from services.classifier import app as classifier_app
        from services.dns_intel import app as dns_app

        # Case-manager vero su un database temporaneo, con il token di servizio dell'orchestrator.
        mp.setattr(cm, "DB_PATH", str(tmp_path / "cases.db"))
        mp.setattr(cm, "SERVICE_TOKEN", _TOKEN)
        cm.init_db()
        mp.setattr(o, "INTEL_STORE", True)
        mp.setattr(o, "CASE_INGEST", True)
        mp.setattr(o, "CASE_INGEST_TOKEN", _TOKEN)
        mp.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        mp.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        mp.setattr(utils.subprocess, "run", spy)

        dns_client = TestClient(dns_app)
        cls_client = TestClient(classifier_app, raise_server_exceptions=False)
        cm_client = TestClient(cm.app, raise_server_exceptions=False)

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _Resp({"domains": [_FEED_ENTRY]})
            if "/feed/whitelist" in url:
                return _Resp({"whitelist": {}})
            if url.startswith(o.DNS_URL):
                r = dns_client.get(url[len(o.DNS_URL):])
                return _Resp(r.json() if r.is_success else None, ok=r.is_success, status_code=r.status_code)
            if url.startswith(o.CERT_URL):
                return _Resp(_CERT_OK)
            if url.startswith(o.HTTP_URL):
                return _Resp(_HTTP_QUIET)
            if whois is not None and url.startswith(o.WHOIS_URL):
                return _Resp(whois)
            raise AssertionError(f"GET non atteso nella catena: {url}")

        def _post(url, json=None, timeout=None, headers=None):
            if url.endswith("/publish"):
                published.extend((json or {}).get("events", []))
                return _Resp({})
            if url.startswith(o.CLASSIFY_URL):
                r = cls_client.post(url[len(o.CLASSIFY_URL):], json=json)
            elif url.startswith(o.CASE_MANAGER_URL):
                r = cm_client.post(url[len(o.CASE_MANAGER_URL):], json=json, headers=headers)
            else:
                raise AssertionError(f"POST non atteso nella catena: {url}")
            if r.status_code != 200:
                run.errors.append((url, r.status_code))
            return _Resp(r.json() if r.is_success else None, ok=r.is_success, status_code=r.status_code)

        mp.setattr(o._session, "get", _get)
        mp.setattr(o._session, "post", _post)

        def _case():
            rows = cm_client.get("/cases", params={"client": CLIENT}, headers=_AUTH).json()["cases"]
            rows = [c for c in rows if c["domain"] == DOMAIN]
            return rows[0] if rows else None

        def _history():
            return o.intel_store.load_history(CLIENT, DOMAIN, limit=1000)

        def _cycle(zone, rules_now):
            spy.zone, spy.rules = zone, rules_now
            before = len(_history())
            published.clear()
            o._run_pipeline(o.TriggerRequest(client=CLIENT, include_whois=whois is not None,
                                             include_reputation=False, include_dnstwist=False,
                                             variant_intel=False, scope="all"))
            assert o._progress["phase"] != "error", "la pipeline è terminata con un errore"
            event = next(e for e in published if e["domain"] == DOMAIN)
            history = _history()
            new = history[:len(history) - before]
            snapshot = (o.intel_store.load_snapshot(CLIENT, DOMAIN) or {}).get("intel", {}).get("dns")
            run.cycles.append(_Cycle(event["classification"], snapshot, [a for e in new for a in e["alerts"]],
                                     _case()))

        for index, (zone, rules_now) in enumerate(steps):
            _cycle(zone, rules_now)
            if index == 0 and close_as:
                case = _case()
                resp = cm_client.patch(f"/cases/{case['id']}/status", json={"status": close_as}, headers=_AUTH)
                assert resp.status_code == 200, resp.text
                run.closed_case = _case()
    run.dig_calls = spy.calls
    return run


def _carried_view(dns):
    """Le parti dello snapshot che il riporto per parte conserva."""
    email = dns["email_auth"]
    return {"records": dns["records"], "records_status": dns["records_status"],
            "email_auth": {name: email[name] for name in ("spf", "dmarc", "bimi", "caa")}}


def _alert_summary(run):
    return [c.new_alerts for c in run.cycles]


# ── Guasti con il caso aperto ──────────────────────────────────────────────

_OUTAGE_RUNS = {}


def _outage_run(name, tmp_path_factory):
    """Una sola esecuzione della catena per scenario: la condividono i test del modulo."""
    if name not in _OUTAGE_RUNS:
        run = _run_chain(tmp_path_factory.mktemp(f"col02-{name}"), "std", _OUTAGES[name].rules)
        run.name, run.spec = name, _OUTAGES[name]
        _OUTAGE_RUNS[name] = run
    return _OUTAGE_RUNS[name]


@pytest.fixture(scope="module", params=list(_OUTAGES), ids=list(_OUTAGES))
def outage(request, tmp_path_factory):
    return _outage_run(request.param, tmp_path_factory)


_TOTAL_OUTAGES = [name for name, spec in _OUTAGES.items() if spec.total]


@pytest.fixture(scope="module", params=_TOTAL_OUTAGES, ids=_TOTAL_OUTAGES)
def total_outage(request, tmp_path_factory):
    return _outage_run(request.param, tmp_path_factory)


class TestCOL02ChainOutageDoesNotBecomeAlerts:
    """ok -> guasto -> ok sulla zona `std`, caso aperto."""

    def test_the_chain_ran_on_the_real_dns_service(self, outage):
        # Precondizione dell'intero file: il primo ciclo ha raccolto la zona vera attraverso
        # `dig_lookup`, quindi gli altri test non sono vacui. Verde anche prima del fix.
        baseline = outage.cycles[0].dns
        assert baseline["records"]["A"] == ["192.0.2.10", "192.0.2.11"]
        assert baseline["records_status"]["A"] == "ok"
        assert outage.dig_calls >= 3 * 7, outage.dig_calls
        assert outage.errors == [], outage.errors

    def test_no_cycle_produces_an_alert(self, outage):
        assert _alert_summary(outage) == [[], [], []], _alert_summary(outage)

    def test_snapshot_after_the_outage_keeps_the_previous_observation(self, outage):
        before, after = outage.cycles[0].dns, outage.cycles[1].dns

        assert _carried_view(after) == _carried_view(before)

    def test_snapshot_after_the_recovery_is_the_healthy_one_again(self, outage):
        # Controllo, verde anche prima del fix.
        assert _carried_view(outage.cycles[2].dns) == _carried_view(outage.cycles[0].dns)

    def test_outage_cycle_is_classified_from_what_was_actually_observed(self, outage):
        assert outage.cycles[1].classification["auto_classification"] == outage.spec.classification, (
            outage.name, outage.cycles[1].classification)

    def test_recovery_cycle_goes_back_to_the_baseline_classification(self, outage):
        # Controllo, verde anche prima del fix.
        assert outage.cycles[0].classification["auto_classification"] == "needs_review"
        assert outage.cycles[2].classification["auto_classification"] == "needs_review", (
            outage.cycles[2].classification)

    def test_classifier_and_case_manager_never_answer_with_an_error(self, outage):
        # Controllo, verde anche prima del fix: un 500 di `/diff` perderebbe gli alert in silenzio.
        assert outage.errors == [], outage.errors

    def test_the_open_case_is_not_escalated_by_the_outage(self, outage):
        # Un caso aperto viene sovrascritto a ogni ingest (CODE-45, fuori scope): qui si
        # pretende solo che il guasto non lo porti a HIGH.
        assert outage.cycles[1].case["severity"] != "HIGH", outage.cycles[1].case
        assert outage.cycles[1].case["status"] == "new"


class TestCOL02ChainTotalFailureKeepsTheWholeSection:
    """Guasto totale (tutti e 7 i tipi base indeterminati, `error` valorizzato)."""

    def test_snapshot_after_a_total_failure_is_the_previous_section_untouched(self, total_outage):
        # Percorso CODE-01 (verde anche prima del fix): `error` valorizzato -> sezione intera conservata.
        # COL-12: la sezione riportata porta ora il marcatore `carried_over`; il resto è la precedente.
        # COL-31: anche i marcatori di sottodomini e DKIM, che il guasto totale scrive, non contano.
        def _bare(dns):
            out = {k: v for k, v in dns.items() if k != "carried_over"}
            out["subdomains"] = {k: v for k, v in out["subdomains"].items() if k != "carried_over"}
            dkim = {k: v for k, v in out["email_auth"]["dkim"].items() if k != "carried_over"}
            out["email_auth"] = {**out["email_auth"], "dkim": dkim}
            return out
        assert _bare(total_outage.cycles[1].dns) == _bare(total_outage.cycles[0].dns)

    def test_the_module_is_declared_failed_in_the_snapshot_source_of_truth(self, total_outage):
        # La sezione salvata dopo la ripresa torna a essere un'osservazione vera, senza `error`.
        assert total_outage.cycles[2].dns["error"] is None


# ── Casi chiusi dall'analista ──────────────────────────────────────────────

class _ClosedCaseSpec:
    def __init__(self, profile, rules, close_as, detection_classification):
        self.profile, self.rules, self.close_as = profile, rules, close_as
        self.detection_classification = detection_classification


_CLOSED_CASES = {
    # A+MX, SERVFAIL sul solo A: oggi `mx_only_no_web` (HIGH) supera MEDIUM e il caso si riapre.
    "closed_fp-a+mx-servfail-on-a": _ClosedCaseSpec(
        "std", _OUTAGES["servfail_a"].rules, "closed_fp", "needs_review"),
    # Parcheggio per NS, SERVFAIL su NS: oggi `needs_review` (MEDIUM) supera LOW e il caso si riapre.
    "closed_benign-parking-servfail-on-ns": _ClosedCaseSpec(
        "parked", _OUTAGES["servfail_ns"].rules, "closed_benign", "parking"),
    # MX su provider privacy, SERVFAIL su MX: la regola HIGH viene soppressa per un ciclo.
    "closed_fp-privacy-mx-servfail-on-mx": _ClosedCaseSpec(
        "privacy", _OUTAGES["servfail_mx"].rules, "closed_fp", "suspicious"),
}


@pytest.fixture(scope="module", params=list(_CLOSED_CASES), ids=list(_CLOSED_CASES))
def closed(request, tmp_path_factory):
    spec = _CLOSED_CASES[request.param]
    run = _run_chain(tmp_path_factory.mktemp("col02-closed"), spec.profile, spec.rules, close_as=spec.close_as)
    run.spec = spec
    return run


class TestCOL02ChainClosedCasesStayClosed:
    """Un caso chiuso dall'analista non si riapre per un guasto del DNS: né all'andata né al ritorno."""

    TRIAGE = ("status", "severity", "severity_at_detection", "classification", "rationale")

    def test_the_case_was_created_by_the_baseline_cycle_and_closed_by_the_analyst(self, closed):
        # Precondizione, verde anche prima del fix.
        assert closed.cycles[0].classification["auto_classification"] == closed.spec.detection_classification
        assert closed.closed_case["status"] == closed.spec.close_as
        assert closed.closed_case["severity"] == "INFO"
        assert closed.closed_case["severity_at_detection"] in ("LOW", "MEDIUM", "HIGH")

    def test_the_case_stays_closed_through_the_outage_and_the_recovery(self, closed):
        expected = {k: closed.closed_case[k] for k in self.TRIAGE}

        assert {k: closed.cycles[1].case[k] for k in self.TRIAGE} == expected, closed.cycles[1].case
        assert {k: closed.cycles[2].case[k] for k in self.TRIAGE} == expected, closed.cycles[2].case

    def test_the_outage_cycle_is_not_a_verdict_on_empty_dns(self, closed):
        assert closed.cycles[1].classification["auto_classification"] == "insufficient_data", (
            closed.cycles[1].classification)

    def test_the_outage_does_not_leave_alerts(self, closed):
        assert _alert_summary(closed) == [[], [], []], _alert_summary(closed)

    def test_no_error_response_from_classifier_or_case_manager(self, closed):
        assert closed.errors == [], closed.errors


# ── Controlli di contrasto: ciò che DEVE continuare a succedere ────────────

@pytest.fixture(scope="module")
def mx_nxdomain(tmp_path_factory):
    return _run_chain(tmp_path_factory.mktemp("col02-mx-nxdomain"), "std",
                      [(lambda n, t: n == DOMAIN and t == "MX", "nxdomain")])


@pytest.fixture(scope="module")
def lost_packet(tmp_path_factory):
    return _run_chain(tmp_path_factory.mktemp("col02-lost-packet"), "std",
                      [(lambda n, t: n == DOMAIN and t == "MX", "lost_first_try")])


class TestCOL02ChainControls:
    """Controlli, verdi anche prima del fix: il riporto e il salto valgono per `unknown`,
    non per «vuoto»."""

    def test_an_mx_that_is_really_gone_alerts_on_the_way_out(self, mx_nxdomain):
        assert mx_nxdomain.cycles[1].new_alerts == [("mx_record_changed", "HIGH")], _alert_summary(mx_nxdomain)

    def test_an_mx_that_comes_back_alerts_on_the_way_back(self, mx_nxdomain):
        assert mx_nxdomain.cycles[2].new_alerts == [("mx_record_changed", "HIGH")], _alert_summary(mx_nxdomain)

    def test_nxdomain_is_an_answer_not_an_outage_for_the_case_channel(self, mx_nxdomain):
        assert mx_nxdomain.cycles[1].classification["auto_classification"] == "needs_review", (
            mx_nxdomain.cycles[1].classification)

    def test_nxdomain_is_saved_as_the_observation_it_is(self, mx_nxdomain):
        dns = mx_nxdomain.cycles[1].dns
        assert dns["records"]["MX"] == [] and dns["records_status"]["MX"] == "nxdomain"

    def test_a_single_lost_packet_is_absorbed_by_the_retry_and_gives_no_alert(self, lost_packet):
        assert _alert_summary(lost_packet) == [[], [], []], _alert_summary(lost_packet)

    def test_a_single_lost_packet_does_not_change_the_snapshot_or_the_verdict(self, lost_packet):
        assert _carried_view(lost_packet.cycles[1].dns) == _carried_view(lost_packet.cycles[0].dns)
        assert lost_packet.cycles[1].classification["auto_classification"] == "needs_review"
        assert lost_packet.errors == []


# ── Risveglio dopo una storia di soli `unknown` (SEC-31 riunificato in COL-02) ─────────────

def _servfail_everywhere():
    return [(_all, "servfail")]


def _zone_live(d):
    """La zona che si «sveglia»: solo A, MX e NS."""
    return {(d, "A"): ["198.51.100.7"], (d, "MX"): [f"10 mail.{d}."], (d, "NS"): [f"ns1.{d}."]}


def _zone_other_a(d):
    zone = _zone_std(d)
    zone[(d, "A")] = ["198.51.100.99"]
    return zone


_WAKE_RUNS = {}


def _wake_run(name, tmp_path_factory, steps, **kwargs):
    if name not in _WAKE_RUNS:
        _WAKE_RUNS[name] = _run_steps(tmp_path_factory.mktemp(f"col02-wake-{name}"), steps, **kwargs)
    return _WAKE_RUNS[name]


@pytest.fixture(scope="module")
def verifier_profile(tmp_path_factory):
    """Il profilo del verifier: zona vuota, WHOIS recente, due cicli di SERVFAIL su tutto, poi A+MX+NS."""
    return _wake_run("verifier", tmp_path_factory,
                     [({}, _servfail_everywhere()), ({}, _servfail_everywhere()), (_zone_live(DOMAIN), [])],
                     whois=_WHOIS_RECENT)


@pytest.fixture(scope="module")
def partial_a(tmp_path_factory):
    """Parziale: il solo A è `unknown` dal primo ciclo, MX e NS rispondono sempre; poi A risponde."""
    zone = _zone_live(DOMAIN)
    return _wake_run("partial-a", tmp_path_factory,
                     [(zone, [(lambda n, t: n == DOMAIN and t == "A", "servfail")]), (zone, [])])


@pytest.fixture(scope="module")
def partial_a_absent(tmp_path_factory):
    """Come sopra, ma quando l'A risponde è NODATA: noto e vuoto."""
    zone = {k: v for k, v in _zone_live(DOMAIN).items() if k[1] != "A"}
    return _wake_run("partial-a-absent", tmp_path_factory,
                     [(zone, [(lambda n, t: n == DOMAIN and t == "A", "servfail")]), (zone, [])])


@pytest.fixture(scope="module")
def first_total_failure_then_full_zone(tmp_path_factory):
    """Guasto totale al PRIMO ciclo senza baseline, poi la zona piena, due volte uguale."""
    zone = _zone_std(DOMAIN)
    return _wake_run("first-total", tmp_path_factory, [(zone, _servfail_everywhere()), (zone, []), (zone, [])])


@pytest.fixture(scope="module", params=["nodata", "nxdomain"])
def failed_then_known_empty(request, tmp_path_factory):
    """F -> F -> ok senza baseline e senza record: la zona è vuota, nodata oppure nxdomain."""
    final = [] if request.param == "nodata" else [(_all, "nxdomain")]
    return _wake_run(f"empty-{request.param}", tmp_path_factory,
                     [({}, _servfail_everywhere()), ({}, _servfail_everywhere()), ({}, final), ({}, final)])


@pytest.fixture(scope="module", params=["partial", "total"])
def known_baseline_outage(request, tmp_path_factory):
    """Controllo: baseline NOTA, due cicli di guasto (solo A, oppure tutto), poi A cambiato."""
    rules = [(lambda n, t: n == DOMAIN and t == "A", "servfail")] if request.param == "partial" \
        else _servfail_everywhere()
    std, other = _zone_std(DOMAIN), _zone_other_a(DOMAIN)
    return _wake_run(f"known-{request.param}", tmp_path_factory,
                     [(std, []), (std, rules), (std, rules), (other, [])])


class TestCOL02ChainWakeUpAfterOnlyUnknownHistory:
    """Profilo del verifier e varianti, sulla catena reale (spy su `dig` -> `dns_intel` ->
    `_run_pipeline` -> classificatore -> case-manager). Verdetto INSUFFICIENTE del verifier:
    prima di RES-01 una zona che si sveglia dopo due cicli di SERVFAIL dava 3 alert (A e MX HIGH,
    NS MEDIUM); con il disegno del primo giro dava 0. Comportamento deciso dal coordinator
    («giro correttivo»): il primo valore noto e non vuoto di un tipo che nella baseline è solo
    `unknown` allerta come un cambio ordinario, una volta; noto ma vuoto no."""

    # ── (c) il profilo del verifier ──
    def test_the_failed_cycles_raise_no_alert(self, verifier_profile):
        assert verifier_profile.cycles[0].new_alerts == [] and verifier_profile.cycles[1].new_alerts == []
        assert verifier_profile.errors == [], verifier_profile.errors

    def test_the_wake_up_raises_the_three_ordinary_alerts(self, verifier_profile):
        assert sorted(verifier_profile.cycles[2].new_alerts) == [
            ("a_record_changed", "HIGH"), ("mx_record_changed", "HIGH"), ("ns_changed", "MEDIUM")], (
            _alert_summary(verifier_profile))

    def test_the_failed_cycles_are_insufficient_data_and_the_wake_up_is_a_real_verdict(self, verifier_profile):
        # Controllo di contesto: la classificazione dei cicli guasti è quella dell'intero lavoro;
        # il risveglio è giudicato sui dati vivi (non `insufficient_data`).
        assert [c.classification["auto_classification"] for c in verifier_profile.cycles[:2]] == [
            "insufficient_data", "insufficient_data"]
        assert verifier_profile.cycles[2].classification["auto_classification"] != "insufficient_data"

    # ── (d) parziale ──
    def test_a_unknown_from_the_first_cycle_then_known_alerts_on_a_alone(self, partial_a):
        assert partial_a.cycles[0].new_alerts == []
        assert [(a["type"], a["severity"], a["detail"]) for a in partial_a.cycles[1].alerts] == [
            ("a_record_changed", "HIGH", {"old": [], "new": ["198.51.100.7"]})]
        assert partial_a.errors == [], partial_a.errors

    def test_a_unknown_from_the_first_cycle_then_known_but_empty_raises_no_alert(self, partial_a_absent):
        assert _alert_summary(partial_a_absent) == [[], []], _alert_summary(partial_a_absent)

    # ── (e) guasto totale al primo ciclo, poi la zona viva ──
    def test_first_cycle_total_failure_raises_no_alert_and_is_insufficient_data(self, first_total_failure_then_full_zone):
        cycle = first_total_failure_then_full_zone.cycles[0]

        assert cycle.new_alerts == []
        assert cycle.classification["auto_classification"] == "insufficient_data"

    def test_the_live_zone_after_a_first_cycle_total_failure_alerts_on_every_record_that_appears(
            self, first_total_failure_then_full_zone):
        alerts = first_total_failure_then_full_zone.cycles[1].alerts

        assert sorted(a["type"] for a in alerts) == [
            "a_record_changed", "bimi_added", "caa_changed", "dmarc_changed", "mx_record_changed",
            "ns_changed", "soa_changed", "spf_changed", "txt_changed"], _alert_summary(first_total_failure_then_full_zone)
        assert all(a["severity"] == SEVERITY_MAP[a["type"]] for a in alerts)

    def test_the_wake_up_alerts_come_once(self, first_total_failure_then_full_zone):
        assert first_total_failure_then_full_zone.cycles[1].alerts, "precondizione: il risveglio ha allertato"
        assert first_total_failure_then_full_zone.cycles[2].new_alerts == []
        assert first_total_failure_then_full_zone.errors == []

    # ── F -> F -> ok senza baseline e senza record ──
    def test_failed_cycles_then_a_known_empty_zone_raise_no_alert(self, failed_then_known_empty):
        assert _alert_summary(failed_then_known_empty) == [[], [], [], []], _alert_summary(failed_then_known_empty)
        assert failed_then_known_empty.errors == [], failed_then_known_empty.errors

    # ── controllo: una baseline NOTA resta il riferimento ──
    def test_a_known_baseline_gives_one_alert_across_the_outage(self, known_baseline_outage):
        assert _alert_summary(known_baseline_outage)[:3] == [[], [], []], _alert_summary(known_baseline_outage)
        alerts = known_baseline_outage.cycles[3].alerts
        assert [(a["type"], a["severity"], a["detail"]) for a in alerts] == [
            ("a_record_changed", "HIGH", {"old": ["192.0.2.10", "192.0.2.11"], "new": ["198.51.100.99"]})]
        assert known_baseline_outage.errors == [], known_baseline_outage.errors
