"""COL-31 — sottodomini e selettori DKIM non determinati in un ciclo si riportano dal precedente, per nome, marcati.

`/dns` interroga uno per nome i 25 sottodomini (A poi CNAME) e i 18 selettori DKIM. Un nome che in un ciclo non ha
risposta (SERVFAIL, trasporto, o la scadenza complessiva della richiesta) finisce in `subdomains.unknown` o in
`dkim.selectors_unknown`, e non in `active`/`selectors_found`. Senza un riporto per nome lo snapshot salva la sezione
com'è: un sottodominio attivo (`login.`) o un selettore trovato spariscono dalla vista per il solo fatto che il DNS non
ha risposto, e al ciclo dopo ricompaiono. Il riporto per parte di COL-02 copre i 7 tipi base e SPF/DMARC/BIMI/CAA, non
questi nomi. Nel guasto totale (e con `/dns` `None`) la sezione precedente resta intera, nomi compresi: senza un
marcatore li presenta come attuali.

Contratto (marcatore dentro la sezione):

* `dns.subdomains`: un nome dell'elenco che `/dns` prova (`DEFAULT_SUBDOMAINS` x dominio) che nel ciclo è in `unknown`
  e nel precedente era in `active` resta in `active` con la voce precedente, nella posizione dell'elenco (l'ordine di
  `/dns`); `subdomains.carried_over = {fqdn: {"observed_at": <ISO|None>, "carried_at": <ISO>}}`, una voce per nome
  riportato. `unknown` e `tested` restano quelli del ciclo: la verità del ciclo è «non determinato», il dato riportato
  sta in `active` e la sua età nel marcatore, come per i tipi base.
* `dns.email_auth.dkim`: lo stesso per selettore (`DEFAULT_DKIM_SELECTORS`): un selettore in `selectors_unknown` del
  ciclo e in `selectors_found` del precedente torna in `selectors_found` (ordine dell'elenco) con `records[sel]`
  precedente; `dkim.carried_over = {selettore: {...}}`; `selectors_unknown` e `selectors_tested` restano del ciclo.
* `carried_at` è l'istante del ciclo (`orchestrator.now_iso()`, letto una volta per `_persist_intel`, lo stesso dei
  marcatori di COL-12); `observed_at` è quello della voce per lo stesso nome nel marcatore di sezione del precedente,
  altrimenti `dns.timestamp` del precedente, con le regole di COL-12 (istante illeggibile, voce malformata o
  osservazione successiva al ciclo: `None`).
* Nessun nome riportato: la chiave `carried_over` della sezione è assente.
* Guasto totale e `/dns` `None` (percorso CODE-01): resta la sezione precedente intera, con il marcatore di sezione
  ricostruito (non copiato) su ogni sottodominio attivo e ogni selettore trovato.
* Un marcatore di sezione arrivato da `/dns` (zona non autenticata) non entra mai nello snapshot, in nessun percorso.
* Un nome sparito davvero (risposte `nxdomain`/`nodata`, quindi non in `unknown`) sparisce. Un nome con A
  `nxdomain`/`nodata` ma CNAME senza risposta è in `unknown` per `/dns` e quindi si riporta, marcato e datato.
* Nessuna scadenza del riporto (come per i tipi base).
* Con dati completi lo snapshot è identico alla risposta di `/dns`. `intel["dns"]` resta l'osservazione del ciclo.
* Nessun alert in più: nessuna regola legge questi nomi, e con il riporto una regola che li confrontasse (per esempio
  «selettore DKIM aggiunto» letto da `selectors_found`) non scatterebbe al ritorno dopo un taglio.
* Il dato precedente non si copia in profondità: un valore annidato oltre il limite di `copy.deepcopy`, che `json`
  carica, non deve far saltare il salvataggio dello snapshot.

Due livelli. Unità: `_persist_intel` con store e `/diff` finti (millisecondi), o con lo store reale su una directory
temporanea e il `/diff` del classificatore reale per i cicli consecutivi. Catena: `/dns` vero con il `dig` finto dei
test SEC-29 (nessuna rete, nessun DNS reale) -> `_run_pipeline` -> intel store -> `/classify/variant` e `/diff` veri,
dodici cicli con l'orologio dei due servizi in mano al test.

I test segnati «controllo» sono verdi anche senza il riporto: fissano ciò che il riporto non deve cambiare. Gli
altri sono rossi senza il riporto, anche quelli il cui oggetto è un limite («precondizione»).
"""
import copy
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import test_dns_deadline_sec29 as _sec29          # dig finto, zona e guardia su Popen dei test SEC-29
from services import dns_intel
from services.classifier import app as _classifier_app
from shared.constants import DEFAULT_DKIM_SELECTORS, DEFAULT_SUBDOMAINS

_DOMAIN = "acme-typo.example"
_T0 = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)


def _at(hours=0, seconds=0):
    return (_T0 + timedelta(hours=hours, seconds=seconds)).isoformat()


_NOW = _at(24, seconds=30)      # istante del ciclo nei test a un ciclo solo
_BASE = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
_ALL_UNKNOWN_ERROR = "DNS resolution failed: no base record type could be resolved"


def _sub(label, domain=_DOMAIN):
    return f"{label}.{domain}"


_WWW, _MAIL, _AUTODISCOVER, _LOGIN = (_sub(s) for s in ("www", "mail", "autodiscover", "login"))
_KEY1, _KEY2 = '"v=DKIM1; k=rsa; p=KEY1"', '"v=DKIM1; k=rsa; p=KEY2"'


def _healthy():
    """`/dns` (`full=true&subdomains=true`) di una zona sana: quattro sottodomini attivi, due selettori trovati."""
    return {
        "domain": _DOMAIN, "timestamp": _at(0),
        "records": {"A": ["192.0.2.10"], "AAAA": ["2001:db8::10"], "MX": [f"10 mail.{_DOMAIN}"],
                    "NS": [f"ns1.{_DOMAIN}", f"ns2.{_DOMAIN}"], "TXT": ['"v=spf1 -all"'],
                    "SOA": [f"ns1.{_DOMAIN} hostmaster.{_DOMAIN} 2026010101 7200 900 1209600 3600"], "CNAME": []},
        "records_status": {"A": "ok", "AAAA": "ok", "MX": "ok", "NS": "ok", "TXT": "ok", "SOA": "ok",
                           "CNAME": "nodata"},
        "email_auth": {
            "spf": {"present": True, "records": ['"v=spf1 -all"'], "policy": "fail", "status": "ok"},
            "dmarc": {"present": True, "records": ['"v=DMARC1; p=reject"'], "status": "ok"},
            "dkim": {"selectors_found": ["google", "selector1"], "selectors_tested": 18,
                     "records": {"google": [_KEY1], "selector1": [_KEY2]}, "selectors_unknown": []},
            "bimi": {"present": False, "records": [], "status": "nodata"},
            "caa": {"present": True, "records": ['0 issue "ca.example"'], "status": "ok"},
        },
        "subdomains": {"tested": 25, "unknown": [], "active": [
            {"fqdn": _WWW, "A": ["192.0.2.20"], "CNAME": []},
            {"fqdn": _MAIL, "A": ["192.0.2.21"], "CNAME": []},
            {"fqdn": _AUTODISCOVER, "A": [], "CNAME": ["autodiscover.provider.example"]},
            {"fqdn": _LOGIN, "A": ["192.0.2.30"], "CNAME": []},
        ]},
        "error": None,
    }


def _cut(dns, *, subdomains=(), selectors=(), base=()):
    """`dns` con i nomi indicati senza risposta, nella forma che `/dns` produce: sottodominio tolto da `active` ed
    elencato in `unknown`, selettore tolto da `selectors_found`/`records` ed elencato in `selectors_unknown` (ordine
    dell'elenco), tipo base `[]` con stato `unknown` (TXT trascina SPF)."""
    out = copy.deepcopy(dns)
    for rtype in base:
        out["records"][rtype] = []
        out["records_status"][rtype] = "unknown"
        if rtype == "TXT":
            out["email_auth"]["spf"] = {"present": False, "records": [], "policy": None, "status": "unknown"}
    if subdomains:
        subs = out["subdomains"]
        subs["active"] = [a for a in subs["active"] if a["fqdn"] not in subdomains]
        subs["unknown"] = [_sub(s) for s in DEFAULT_SUBDOMAINS if _sub(s) in subdomains or _sub(s) in subs["unknown"]]
    if selectors:
        dkim = out["email_auth"]["dkim"]
        dkim["selectors_found"] = [s for s in dkim["selectors_found"] if s not in selectors]
        dkim["records"] = {s: r for s, r in dkim["records"].items() if s not in selectors}
        dkim["selectors_unknown"] = [s for s in DEFAULT_DKIM_SELECTORS
                                     if s in selectors or s in dkim["selectors_unknown"]]
    return out


def _gone(dns, *, subdomains=(), selectors=()):
    """`dns` con i nomi indicati spariti davvero (`nxdomain`/`nodata`): né attivi/trovati né in `unknown`."""
    out = copy.deepcopy(dns)
    out["subdomains"]["active"] = [a for a in out["subdomains"]["active"] if a["fqdn"] not in subdomains]
    dkim = out["email_auth"]["dkim"]
    dkim["selectors_found"] = [s for s in dkim["selectors_found"] if s not in selectors]
    dkim["records"] = {s: r for s, r in dkim["records"].items() if s not in selectors}
    return out


def _total_failure(dns=None):
    out = _cut(dns or _healthy(), base=_BASE, subdomains=[_sub(s) for s in DEFAULT_SUBDOMAINS],
               selectors=DEFAULT_DKIM_SELECTORS)
    for section in ("dmarc", "bimi", "caa"):
        out["email_auth"][section] = {"present": False, "records": [], "status": "unknown"}
    out["error"] = _ALL_UNKNOWN_ERROR
    return out


_FAILED_DNS = [
    pytest.param(None, id="section-none"),
    pytest.param(_total_failure(), id="all-types-unknown"),
    pytest.param({"records": {"A": [], "MX": []}, "error": "DNS resolution failed"}, id="error-text"),
]


def _entry(observed_at, carried_at=_NOW):
    return {"observed_at": observed_at, "carried_at": carried_at}


def _fqdns(dns):
    return [a["fqdn"] for a in dns["subdomains"]["active"]]


def _sub_marker(dns):
    return dns["subdomains"].get("carried_over")


def _dkim_marker(dns):
    return dns["email_auth"]["dkim"].get("carried_over")


def _without_markers(dns):
    """La sezione senza i tre marcatori (`dns.carried_over` e quelli di sezione)."""
    out = {k: v for k, v in dns.items() if k != "carried_over"}
    if isinstance(out.get("subdomains"), dict):
        out["subdomains"] = {k: v for k, v in out["subdomains"].items() if k != "carried_over"}
    email = out.get("email_auth")
    if isinstance(email, dict) and isinstance(email.get("dkim"), dict):
        out["email_auth"] = {**email, "dkim": {k: v for k, v in email["dkim"].items() if k != "carried_over"}}
    return out


class _Resp:
    def __init__(self, payload, ok=True, status_code=200):
        self._payload, self.ok, self.status_code = payload, ok, status_code

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


_EMPTY_DIFF = {"alerts": [], "alert_count": 0, "max_severity": "CLEAN"}


def _serialized(payload):
    return json.loads(json.dumps(payload))


@pytest.fixture
def orch(monkeypatch):
    monkeypatch.setenv("INTEL_STORE", "false")
    monkeypatch.setenv("CASE_INGEST", "false")
    import importlib

    import services.orchestrator as o
    importlib.reload(o)
    return o


def _persist(monkeypatch, o, prev_dns, curr_dns, *, snapshot=True, now=_NOW):
    """Un ciclo di `_persist_intel` con store e `/diff` finti. Ritorna (sezione `dns` salvata, payload mandati a
    `/diff`, `intel` passato). Se `_persist_intel` solleva, l'eccezione arriva al test: nella pipeline salterebbe il
    salvataggio dello snapshot."""
    saved, sent = {}, []
    prev_intel = ({"dns": prev_dns, "cert": None, "http": None, "whois": None, "reputation": None}
                  if snapshot else None)
    monkeypatch.setattr(o, "now_iso", now if callable(now) else (lambda: now))
    monkeypatch.setattr(o.intel_store, "load_snapshot",
                        lambda c, d: {"intel": prev_intel} if prev_intel is not None else None)
    monkeypatch.setattr(o.intel_store, "save_snapshot", lambda c, d, current: saved.update(current=current) or True)
    # Il payload serializzato nel momento della chiamata, come la richiesta HTTP.
    monkeypatch.setattr(o._session, "post",
                        lambda url, json=None, timeout=None: sent.append(_serialized(json)) or _Resp(_EMPTY_DIFF))
    intel = {"dns": curr_dns, "cert": None, "http": None, "whois": None, "reputation": None}
    o._persist_intel("acme", _DOMAIN, "acme.example", intel)
    assert "current" in saved, "lo snapshot non è stato salvato"
    return saved["current"]["dns"], sent, intel


@pytest.fixture
def cycle(orch, monkeypatch, tmp_path):
    """Un ciclo di `_persist_intel` per chiamata, con lo store reale su una directory temporanea e il `/diff` del
    classificatore reale. `run(dns, hours)`: osservazione `hours` dopo T0 (`dns.timestamp`), persistita 30 s dopo
    (`now_iso`); `dns=None` è il modulo senza risposta. `run.alerts` raccoglie gli alert nuovi di ogni ciclo e
    `run.statuses` gli stati HTTP di `/diff` (un 500 lascerebbe la storia vuota: «nessun alert» per errore)."""
    o = orch
    monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
    clock = {}
    monkeypatch.setattr(o, "now_iso", lambda: clock["now"])
    api = TestClient(_classifier_app, raise_server_exceptions=False)
    statuses = []

    def _post(url, json=None, timeout=None, headers=None):
        r = api.post(url[len(o.CLASSIFY_URL):], json=json)
        statuses.append(r.status_code)
        return _Resp(r.json() if r.is_success else None, ok=r.is_success, status_code=r.status_code)

    monkeypatch.setattr(o._session, "post", _post)

    def history():
        return o.intel_store.load_history("acme", _DOMAIN, limit=1000)

    def run(dns, hours):
        if dns is not None:
            dns = copy.deepcopy(dns)
            dns["timestamp"] = _at(hours)
        clock["now"] = _at(hours, seconds=30)
        before = len(history())
        o._persist_intel("acme", _DOMAIN, "acme.example",
                         {"dns": dns, "cert": None, "http": None, "whois": None, "reputation": None})
        new = history()[:len(history()) - before]
        run.alerts.append([(a["type"], a["severity"]) for e in new for a in e["alerts"]])

    run.alerts = []
    run.statuses = statuses
    run.snapshot = lambda: o.intel_store.load_snapshot("acme", _DOMAIN)["intel"]["dns"]
    return run


# ── 1. Sottodomini: riporto per nome ────────────────────────────────────────────────────────────────────────

class TestSubdomainsAreCarriedByName:
    """Un sottodominio attivo nel precedente e senza risposta nel ciclo resta nello snapshot, marcato."""

    def test_an_unanswered_name_that_was_active_keeps_its_previous_entry(self, orch, monkeypatch):
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, subdomains=[_LOGIN]))

        assert saved["subdomains"]["active"] == prev["subdomains"]["active"]

    def test_the_carried_name_is_marked_with_the_previous_observation_and_the_cycle_instant(self, orch, monkeypatch):
        prev = _healthy()
        curr = _cut(prev, subdomains=[_LOGIN])
        curr["timestamp"] = _at(24)          # fresco: NON è l'istante dell'osservazione riportata

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert _sub_marker(saved) == {_LOGIN: _entry(_at(0))}

    def test_a_carried_name_keeps_its_place_in_the_list(self, orch, monkeypatch):
        # `mail.` è il secondo nome dell'elenco: riportato in coda, la vista cambierebbe ordine a ogni taglio.
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, subdomains=[_MAIL]))

        assert _fqdns(saved) == [_WWW, _MAIL, _AUTODISCOVER, _LOGIN]
        assert _sub_marker(saved) == {_MAIL: _entry(_at(0))}

    def test_names_answered_in_this_cycle_are_fresh_and_unmarked(self, orch, monkeypatch):
        prev = _healthy()
        curr = _cut(prev, subdomains=[_LOGIN])
        curr["subdomains"]["active"][0] = {"fqdn": _WWW, "A": ["198.51.100.20"], "CNAME": []}

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert _LOGIN in _fqdns(saved), "precondizione: il riporto deve essere avvenuto"
        assert saved["subdomains"]["active"][0] == {"fqdn": _WWW, "A": ["198.51.100.20"], "CNAME": []}
        assert set(_sub_marker(saved) or {}) == {_LOGIN}

    def test_unknown_and_tested_stay_this_cycles_observation(self, orch, monkeypatch):
        prev = _healthy()
        curr = _cut(prev, subdomains=[_LOGIN, _sub("vpn")])

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert _LOGIN in _fqdns(saved), "precondizione: il riporto deve essere avvenuto"
        assert saved["subdomains"]["unknown"] == [_LOGIN, _sub("vpn")]
        assert saved["subdomains"]["tested"] == 25

    def test_an_unanswered_name_that_was_not_active_is_not_invented(self, orch, monkeypatch):
        # Controllo: `vpn.` non era attivo, e `unknown` non dice che lo sia.
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, subdomains=[_sub("vpn")]))

        assert _sub("vpn") not in _fqdns(saved)
        assert "carried_over" not in saved["subdomains"]

    def test_a_name_that_really_disappeared_is_not_carried(self, orch, monkeypatch):
        # Controllo: A e CNAME `nxdomain`/`nodata` sono risposte, `/dns` non mette il nome in `unknown`.
        prev = _healthy()
        curr = _gone(prev, subdomains=[_LOGIN])

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert saved["subdomains"] == curr["subdomains"]

    def test_a_name_outside_the_tested_list_is_never_carried(self, orch, monkeypatch):
        # Le liste vengono da `/dns` (zona non autenticata) e da disco: si riporta solo un nome che `/dns` prova
        # per questo dominio. Nel precedente un nome estraneo, attivo, e lo stesso nome in `unknown` del ciclo.
        foreign = "login.other-domain.example"
        prev = _healthy()
        prev["subdomains"]["active"].append({"fqdn": foreign, "A": ["192.0.2.99"], "CNAME": []})
        curr = _cut(prev, subdomains=[_LOGIN])
        curr["subdomains"]["active"] = [a for a in curr["subdomains"]["active"] if a["fqdn"] != foreign]
        curr["subdomains"]["unknown"].append(foreign)

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert _LOGIN in _fqdns(saved), "precondizione: il riporto deve essere avvenuto"
        assert foreign not in _fqdns(saved)
        assert set(_sub_marker(saved) or {}) == {_LOGIN}

    def test_every_active_name_is_carried_when_the_whole_stage_is_cut(self, orch, monkeypatch):
        # La forma della scadenza di SEC-29: i 25 nomi in `unknown`, nessuno attivo.
        prev = _healthy()
        curr = _cut(prev, subdomains=[_sub(s) for s in DEFAULT_SUBDOMAINS])

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert saved["subdomains"]["active"] == prev["subdomains"]["active"]
        assert _sub_marker(saved) == {fqdn: _entry(_at(0)) for fqdn in _fqdns(prev)}
        assert len(saved["subdomains"]["unknown"]) == 25


# ── 2. Selettori DKIM: riporto per selettore ────────────────────────────────────────────────────────────────

class TestDkimSelectorsAreCarriedBySelector:
    """Un selettore trovato nel precedente e senza risposta nel ciclo resta nello snapshot, con i suoi record, marcato."""

    def test_an_unanswered_selector_that_was_found_keeps_its_previous_records(self, orch, monkeypatch):
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, selectors=["selector1"]))

        dkim = saved["email_auth"]["dkim"]
        assert dkim["selectors_found"] == ["google", "selector1"]
        assert dkim["records"] == {"google": [_KEY1], "selector1": [_KEY2]}

    def test_the_carried_selector_is_marked_with_the_previous_observation_and_the_cycle_instant(
            self, orch, monkeypatch):
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, selectors=["selector1"]))

        assert _dkim_marker(saved) == {"selector1": _entry(_at(0))}

    def test_a_selector_answered_in_this_cycle_is_fresh_and_unmarked(self, orch, monkeypatch):
        prev = _healthy()
        curr = _cut(prev, selectors=["selector1"])
        curr["email_auth"]["dkim"]["records"]["google"] = ['"v=DKIM1; k=rsa; p=ROTATED"']

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        dkim = saved["email_auth"]["dkim"]
        assert "selector1" in dkim["selectors_found"], "precondizione: il riporto deve essere avvenuto"
        assert dkim["records"]["google"] == ['"v=DKIM1; k=rsa; p=ROTATED"']
        assert set(_dkim_marker(saved) or {}) == {"selector1"}

    def test_selectors_unknown_and_tested_stay_this_cycles_observation(self, orch, monkeypatch):
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, selectors=["selector1", "k1"]))

        dkim = saved["email_auth"]["dkim"]
        assert "selector1" in dkim["selectors_found"], "precondizione: il riporto deve essere avvenuto"
        assert dkim["selectors_unknown"] == ["selector1", "k1"]
        assert dkim["selectors_tested"] == 18

    def test_a_carried_selector_keeps_its_place_in_the_list(self, orch, monkeypatch):
        # `google` è il primo selettore trovato dell'elenco: riportato in coda, la lista cambierebbe ordine a ogni taglio.
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, selectors=["google"]))

        assert saved["email_auth"]["dkim"]["selectors_found"] == ["google", "selector1"]
        assert _dkim_marker(saved) == {"google": _entry(_at(0))}

    def test_every_found_selector_is_carried_when_the_whole_stage_is_cut(self, orch, monkeypatch):
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, selectors=DEFAULT_DKIM_SELECTORS))

        dkim = saved["email_auth"]["dkim"]
        assert dkim["selectors_found"] == ["google", "selector1"]
        assert dkim["records"] == prev["email_auth"]["dkim"]["records"]
        assert _dkim_marker(saved) == {"google": _entry(_at(0)), "selector1": _entry(_at(0))}

    def test_an_unanswered_selector_that_was_not_found_is_not_invented(self, orch, monkeypatch):
        # Controllo.
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, selectors=["k1"]))

        assert saved["email_auth"]["dkim"]["selectors_found"] == ["google", "selector1"]
        assert "k1" not in saved["email_auth"]["dkim"]["records"]
        assert "carried_over" not in saved["email_auth"]["dkim"]

    def test_a_selector_that_really_disappeared_is_not_carried(self, orch, monkeypatch):
        # Controllo: `nxdomain`/`nodata` è una risposta, il selettore non è in `selectors_unknown`.
        prev = _healthy()
        curr = _gone(prev, selectors=["selector1"])

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert saved["email_auth"]["dkim"] == curr["email_auth"]["dkim"]


# ── 3. Guasto totale e modulo senza risposta (percorso CODE-01) ─────────────────────────────────────────────

class TestTotalFailureMarksTheKeptNames:
    """Con il modulo fallito resta la sezione precedente intera: i suoi nomi sono riportati anch'essi, e lo dicono."""

    @pytest.mark.parametrize("failed", _FAILED_DNS)
    def test_every_active_name_and_found_selector_is_marked(self, orch, monkeypatch, failed):
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, failed)

        assert _sub_marker(saved) == {fqdn: _entry(_at(0)) for fqdn in _fqdns(prev)}
        assert _dkim_marker(saved) == {"google": _entry(_at(0)), "selector1": _entry(_at(0))}

    @pytest.mark.parametrize("failed", _FAILED_DNS)
    def test_the_rest_of_the_previous_section_is_kept_unchanged(self, orch, monkeypatch, failed):
        prev = _healthy()

        saved, sent, _ = _persist(monkeypatch, orch, prev, failed)

        assert _sub_marker(saved), "precondizione: i nomi riportati devono essere marcati"
        assert _without_markers(saved) == prev
        assert sent[0]["current"]["dns"] == saved

    def test_the_previous_section_marker_is_rebuilt_not_copied(self, orch, monkeypatch):
        # Il precedente è a sua volta un ciclo di riporto: `login.` viene da T0, il resto è osservato a 24 h. Nel suo
        # marcatore anche una voce per un nome che non è attivo (`admin.`), che non deve sopravvivere.
        prev = _healthy()
        prev["timestamp"] = _at(24)
        prev["subdomains"]["carried_over"] = {_LOGIN: _entry(_at(0), _at(24, 30)),
                                              _sub("admin"): _entry(_at(0), _at(24, 30))}
        prev["email_auth"]["dkim"]["carried_over"] = {"selector1": _entry(_at(0), _at(24, 30)),
                                                      "k1": _entry(_at(0), _at(24, 30))}
        now = _at(48, seconds=30)

        saved, _, _ = _persist(monkeypatch, orch, prev, _total_failure(), now=now)

        assert _sub_marker(saved) == {_WWW: _entry(_at(24), now), _MAIL: _entry(_at(24), now),
                                      _AUTODISCOVER: _entry(_at(24), now), _LOGIN: _entry(_at(0), now)}
        assert _dkim_marker(saved) == {"google": _entry(_at(24), now), "selector1": _entry(_at(0), now)}

    def test_a_previous_section_without_names_gets_no_section_marker(self, orch, monkeypatch):
        # Controllo. Nessun nome riportato, nessuna chiave: una zona senza sottodomini né selettori resta com'era.
        prev = _healthy()
        prev["subdomains"]["active"] = []
        prev["email_auth"]["dkim"].update(selectors_found=[], records={})

        saved, _, _ = _persist(monkeypatch, orch, prev, _total_failure())

        assert saved.get("carried_over"), "precondizione: il guasto totale marca i tipi base"
        assert "carried_over" not in saved["subdomains"]
        assert "carried_over" not in saved["email_auth"]["dkim"]


# ── 4. Istanti del marcatore ────────────────────────────────────────────────────────────────────────────────

class TestMarkerInstants:
    """Le regole di COL-12 per `observed_at` e `carried_at`, applicate ai nomi."""

    @pytest.mark.parametrize("prev_marker, expected", [
        pytest.param({_LOGIN: _entry(_at(-24), _at(0, 30))}, _at(-24), id="inherited"),
        pytest.param("not-a-dict", _at(0), id="marker-not-a-dict-falls-back-to-the-timestamp"),
        pytest.param({_LOGIN: "x"}, None, id="entry-not-a-dict"),
        pytest.param({_LOGIN: {"observed_at": "<b>x</b>"}}, None, id="observed-at-not-iso"),
        pytest.param({_LOGIN: {"observed_at": 5}}, None, id="observed-at-not-a-string"),
        pytest.param({_LOGIN: _entry(_at(48), _at(0, 30))}, None, id="observed-after-the-cycle"),
    ])
    def test_observed_at_of_a_carried_name(self, orch, monkeypatch, prev_marker, expected):
        prev = _healthy()
        prev["subdomains"]["carried_over"] = prev_marker
        prev["email_auth"]["dkim"]["carried_over"] = (
            {"selector1": prev_marker[_LOGIN]} if isinstance(prev_marker, dict) else prev_marker)
        curr = _cut(_healthy(), subdomains=[_LOGIN], selectors=["selector1"])

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert _sub_marker(saved) == {_LOGIN: _entry(expected)}
        assert _dkim_marker(saved) == {"selector1": _entry(expected)}

    def test_an_unreadable_previous_timestamp_gives_an_unknown_observation(self, orch, monkeypatch):
        prev = _healthy()
        prev["timestamp"] = "yesterday"

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(_healthy(), subdomains=[_LOGIN], selectors=["selector1"]))

        assert _sub_marker(saved) == {_LOGIN: _entry(None)}
        assert _dkim_marker(saved) == {"selector1": _entry(None)}

    def test_all_the_markers_of_one_cycle_share_the_instant_read_once(self, orch, monkeypatch):
        calls = []

        def tick():
            calls.append(1)
            return _at(24, seconds=len(calls))

        prev = _healthy()
        curr = _cut(prev, base=["A"], subdomains=[_LOGIN], selectors=["selector1"])

        saved, _, _ = _persist(monkeypatch, orch, prev, curr, now=tick)

        instants = {e["carried_at"] for marker in (saved.get("carried_over"), _sub_marker(saved), _dkim_marker(saved))
                    for e in (marker or {}).values()}
        assert _sub_marker(saved) and _dkim_marker(saved), "precondizione: i nomi riportati devono essere marcati"
        assert len(instants) == 1 and len(calls) == 1, (instants, len(calls))


class TestCarryOverAcrossConsecutiveCycles:
    """Store reale su una directory temporanea e `/diff` del classificatore reale (fixture `cycle`)."""

    def test_observed_at_stays_the_last_real_observation_while_carried_at_follows_the_cycle(self, cycle):
        zone = _healthy()
        cycle(zone, 0)
        for hours in (24, 48, 72):
            cycle(_cut(zone, subdomains=[_LOGIN], selectors=["selector1"]), hours)
            entry = _entry(_at(0), _at(hours, seconds=30))
            assert _sub_marker(cycle.snapshot()) == {_LOGIN: entry}, f"ciclo a {hours} h"
            assert _dkim_marker(cycle.snapshot()) == {"selector1": entry}, f"ciclo a {hours} h"

    def test_a_name_observed_again_leaves_the_marker(self, cycle):
        zone = _healthy()
        cycle(zone, 0)
        cycle(_cut(zone, subdomains=[_LOGIN], selectors=["selector1"]), 24)
        assert _sub_marker(cycle.snapshot()), "precondizione: il riporto deve essere marcato"

        cycle(zone, 48)

        assert "carried_over" not in cycle.snapshot()["subdomains"]
        assert "carried_over" not in cycle.snapshot()["email_auth"]["dkim"]

    def test_a_total_failure_after_a_partial_carry_inherits_each_names_observation(self, cycle):
        zone = _healthy()
        cycle(zone, 0)
        cycle(_cut(zone, subdomains=[_LOGIN], selectors=["selector1"]), 24)

        cycle(None, 48)

        now = _at(48, seconds=30)
        assert _sub_marker(cycle.snapshot()) == {_WWW: _entry(_at(24), now), _MAIL: _entry(_at(24), now),
                                                 _AUTODISCOVER: _entry(_at(24), now), _LOGIN: _entry(_at(0), now)}
        assert _dkim_marker(cycle.snapshot()) == {"google": _entry(_at(24), now), "selector1": _entry(_at(0), now)}

    def test_the_carry_has_no_expiry_and_raises_no_alert(self, cycle):
        # Come per i tipi base: una soglia restituirebbe a chi controlla il DNS la leva di restare muto oltre.
        zone = _healthy()
        cycle(zone, 0)
        for hours in (24, 200, 2000):
            cycle(_cut(zone, subdomains=[_LOGIN], selectors=["selector1"]), hours)

        assert _fqdns(cycle.snapshot()) == _fqdns(zone)
        assert _sub_marker(cycle.snapshot()) == {_LOGIN: _entry(_at(0), _at(2000, seconds=30))}
        assert cycle.snapshot()["email_auth"]["dkim"]["selectors_found"] == ["google", "selector1"]
        assert cycle.alerts == [[], [], [], []] and cycle.statuses == [200, 200, 200]

    def test_a_name_that_disappeared_is_not_brought_back_by_a_later_cut(self, cycle):
        zone = _healthy()
        gone = _gone(zone, subdomains=[_LOGIN], selectors=["selector1"])
        cycle(zone, 0)
        cycle(_cut(zone, subdomains=[_LOGIN], selectors=["selector1"]), 24)
        assert _sub_marker(cycle.snapshot()), "precondizione: il riporto deve essere marcato"
        cycle(gone, 48)

        cycle(_cut(gone, subdomains=[_LOGIN], selectors=["selector1"]), 72)

        assert _LOGIN not in _fqdns(cycle.snapshot())
        assert "selector1" not in cycle.snapshot()["email_auth"]["dkim"]["selectors_found"]
        assert "carried_over" not in cycle.snapshot()["subdomains"]
        assert "carried_over" not in cycle.snapshot()["email_auth"]["dkim"]


# ── 5. Un marcatore di sezione arrivato da /dns ─────────────────────────────────────────────────────────────

def _forge(dns):
    """`dns` con marcatori di sezione forgiati dal servizio: un nome attivo, uno che non esiste, un istante antico,
    un `carried_at` con markup."""
    out = copy.deepcopy(dns)
    forged = {"observed_at": "2020-01-01T00:00:00+00:00", "carried_at": "<b>x</b>"}
    if isinstance(out.get("subdomains"), dict):
        out["subdomains"]["carried_over"] = {_LOGIN: dict(forged), _sub("admin"): dict(forged)}
    if isinstance(out.get("email_auth"), dict) and isinstance(out["email_auth"].get("dkim"), dict):
        out["email_auth"]["dkim"]["carried_over"] = {"selector1": dict(forged), "k1": dict(forged)}
    return out


class TestForgedSectionMarkersFromDns:
    """Il marcatore lo scrive solo l'orchestrator: uno arrivato da `/dns` (zona non autenticata) non entra nello
    snapshot, e non decide nulla del riporto."""

    @pytest.mark.parametrize("curr", [
        pytest.param(_healthy(), id="complete"),
        pytest.param(_cut(_healthy(), base=["A"]), id="base-type-unknown"),
    ])
    def test_a_forged_marker_is_dropped_when_no_name_is_carried(self, orch, monkeypatch, curr):
        saved, _, _ = _persist(monkeypatch, orch, _healthy(), _forge(curr))

        assert "carried_over" not in saved["subdomains"]
        assert "carried_over" not in saved["email_auth"]["dkim"]

    def test_a_forged_marker_does_not_replace_the_one_the_orchestrator_builds(self, orch, monkeypatch):
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _forge(_cut(prev, subdomains=[_LOGIN], selectors=["selector1"])))

        assert _sub_marker(saved) == {_LOGIN: _entry(_at(0))}
        assert _dkim_marker(saved) == {"selector1": _entry(_at(0))}

    def test_a_forged_marker_is_dropped_on_a_total_failure_without_a_snapshot(self, orch, monkeypatch):
        # Percorso SEC-31: senza precedente si salva la sezione guasta del ciclo, senza i marcatori del servizio.
        saved, _, _ = _persist(monkeypatch, orch, None, _forge(_total_failure()), snapshot=False)

        assert saved["error"] == _ALL_UNKNOWN_ERROR, "precondizione: è la sezione guasta del ciclo"
        assert "carried_over" not in saved["subdomains"]
        assert "carried_over" not in saved["email_auth"]["dkim"]

    def test_the_cycle_observation_keeps_what_dns_sent(self, orch, monkeypatch):
        # Il marcatore si toglie dallo snapshot, non da `intel["dns"]`: è l'osservazione del ciclo, letta dopo da
        # classificazione ed eventi, e non si modifica.
        prev = _healthy()
        curr = _forge(_cut(prev, subdomains=[_LOGIN]))
        curr_before = copy.deepcopy(curr)

        saved, _, intel = _persist(monkeypatch, orch, prev, curr)

        assert _sub_marker(saved) == {_LOGIN: _entry(_at(0))}, "precondizione: il riporto deve essere marcato"
        assert intel["dns"] == curr_before and curr == curr_before


# ── 6. Ciò che non cambia ───────────────────────────────────────────────────────────────────────────────────

class TestWhatTheCarryLeavesAlone:

    def test_complete_data_is_saved_exactly_as_dns_sent_it(self, orch, monkeypatch):
        # Controllo: stesso contenuto e stesso ordine delle chiavi (la forma del JSON scritto su disco).
        curr = _healthy()
        curr["timestamp"] = _at(24)

        saved, _, _ = _persist(monkeypatch, orch, _healthy(), curr)

        assert json.dumps(saved) == json.dumps(curr)

    def test_a_base_type_cut_leaves_complete_names_as_dns_sent_them(self, orch, monkeypatch):
        # Controllo.
        prev = _healthy()
        curr = _cut(prev, base=["A", "MX"])

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert saved["subdomains"] == curr["subdomains"]
        assert saved["email_auth"]["dkim"] == curr["email_auth"]["dkim"]

    def test_the_cycle_observation_and_the_previous_snapshot_are_not_modified(self, orch, monkeypatch):
        # Solo nomi tagliati, nessun tipo base: il ramo in cui il riporto per parte non copia la sezione.
        prev = _healthy()
        curr = _cut(prev, subdomains=[_LOGIN], selectors=["selector1"])
        curr_before, prev_before = copy.deepcopy(curr), copy.deepcopy(prev)

        saved, _, intel = _persist(monkeypatch, orch, prev, curr)

        assert _LOGIN in _fqdns(saved), "precondizione: il riporto deve essere avvenuto"
        assert intel["dns"] == curr_before and curr == curr_before
        assert prev == prev_before

    def test_the_diff_receives_the_section_that_is_saved(self, orch, monkeypatch):
        prev = _healthy()

        saved, sent, _ = _persist(monkeypatch, orch, prev, _cut(prev, subdomains=[_LOGIN], selectors=["selector1"]))

        assert _sub_marker(saved), "precondizione: il riporto deve essere marcato"
        assert sent[0]["current"]["dns"] == saved

    def test_the_base_type_marker_is_unchanged(self, orch, monkeypatch):
        # I nomi non entrano nel marcatore dei tipi base (`dns.carried_over`, elenco fisso di 11 parti).
        prev = _healthy()

        saved, _, _ = _persist(monkeypatch, orch, prev, _cut(prev, base=["AAAA"], subdomains=[_LOGIN],
                                                              selectors=["selector1"]))

        assert _sub_marker(saved), "precondizione: il riporto deve essere marcato"
        assert saved["carried_over"] == {"AAAA": _entry(_at(0))}


# ── 7. Input degradato ──────────────────────────────────────────────────────────────────────────────────────

_PREV_SUBDOMAINS = [
    pytest.param(None, id="none"),
    pytest.param({}, id="empty"),
    pytest.param("x", id="string"),
    pytest.param({"active": f"login.{_DOMAIN}"}, id="active-string"),
    pytest.param({"active": None}, id="active-none"),
    pytest.param({"active": [None, "x", 5, {"A": []}, {"fqdn": None}, {"fqdn": ["x"]}]}, id="active-bad-entries"),
]
_PREV_DKIM = [
    pytest.param(None, id="none"),
    pytest.param({}, id="empty"),
    pytest.param("x", id="string"),
    pytest.param({"selectors_found": None, "records": None}, id="found-none"),
    pytest.param({"selectors_found": ["selector1"], "records": "x"}, id="records-string"),
    pytest.param({"selectors_found": [None, 5, ["x"]], "records": {}}, id="found-bad-entries"),
]


class TestDegradedInput:
    """Snapshot vecchi o corrotti e risposte malformate: il salvataggio non salta (un'eccezione in `_persist_intel`
    lascerebbe lo snapshot vecchio a ogni ciclo) e nulla viene inventato. Controlli."""

    @pytest.mark.parametrize("prev_subs", _PREV_SUBDOMAINS)
    def test_a_previous_subdomains_section_without_usable_names_carries_nothing(self, orch, monkeypatch, prev_subs):
        prev = _healthy()
        prev["subdomains"] = prev_subs
        curr = _cut(_healthy(), subdomains=[_LOGIN])

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert saved["subdomains"] == curr["subdomains"]

    @pytest.mark.parametrize("prev_dkim", _PREV_DKIM)
    def test_a_previous_dkim_section_without_usable_selectors_carries_nothing(self, orch, monkeypatch, prev_dkim):
        prev = _healthy()
        prev["email_auth"]["dkim"] = prev_dkim
        curr = _cut(_healthy(), selectors=["selector1"])

        saved, _, _ = _persist(monkeypatch, orch, prev, curr)

        assert saved["email_auth"]["dkim"] == curr["email_auth"]["dkim"]

    @pytest.mark.parametrize("subs, dkim", [
        pytest.param(None, None, id="sections-none"),
        pytest.param("x", "x", id="sections-strings"),
        pytest.param({"active": [], "unknown": f"login.{_DOMAIN}"}, {"selectors_unknown": "selector1"},
                     id="unknown-strings"),
        pytest.param({"active": "x", "unknown": [f"login.{_DOMAIN}"]},
                     {"selectors_found": None, "records": None, "selectors_unknown": ["selector1"]},
                     id="found-and-active-malformed"),
        pytest.param({"active": [None, 5], "unknown": [None, 5, f"login.{_DOMAIN}"]},
                     {"selectors_found": [None], "records": {}, "selectors_unknown": [None, "selector1"]},
                     id="bad-entries"),
    ])
    def test_a_malformed_cycle_section_does_not_stop_the_save(self, orch, monkeypatch, subs, dkim):
        curr = _healthy()
        curr["subdomains"] = subs
        curr["email_auth"]["dkim"] = dkim
        curr_before = copy.deepcopy(curr)

        _persist(monkeypatch, orch, _healthy(), curr)

        assert curr == curr_before

    @pytest.mark.parametrize("failed", _FAILED_DNS)
    @pytest.mark.parametrize("prev_subs, prev_dkim", [
        pytest.param(None, None, id="sections-none"),
        pytest.param("x", "x", id="sections-strings"),
        pytest.param({"active": "x"}, {"selectors_found": "x"}, id="lists-strings"),
        pytest.param({"active": [None, {"fqdn": 5}]}, {"selectors_found": [None, 5]}, id="bad-entries"),
        pytest.param({"active": [{"fqdn": ["x"]}, {"fqdn": {}}]}, {"selectors_found": [["x"], {}]},
                     id="unhashable-entries"),
    ])
    def test_a_malformed_previous_section_does_not_stop_the_save_on_a_total_failure(
            self, orch, monkeypatch, prev_subs, prev_dkim, failed):
        prev = _healthy()
        prev["subdomains"] = prev_subs
        prev["email_auth"]["dkim"] = prev_dkim

        saved, _, _ = _persist(monkeypatch, orch, prev, failed)

        assert saved.get("carried_over"), "il guasto totale marca comunque i tipi base"

    @pytest.mark.parametrize("failed", _FAILED_DNS)
    def test_an_unhashable_name_in_the_previous_section_leaves_the_other_names_marked(self, orch, monkeypatch, failed):
        # Un nome che non è una stringa (qui una lista e un dict, che non possono fare da chiave) non entra nel
        # marcatore; gli altri sì, e lo snapshot si salva.
        prev = _healthy()
        prev["subdomains"]["active"] += [{"fqdn": ["x"], "A": [], "CNAME": []}, {"fqdn": {}, "A": [], "CNAME": []}]
        prev["email_auth"]["dkim"]["selectors_found"] += [["x"], {}]

        saved, _, _ = _persist(monkeypatch, orch, prev, failed)

        assert _sub_marker(saved) == {fqdn: _entry(_at(0)) for fqdn in (_WWW, _MAIL, _AUTODISCOVER, _LOGIN)}
        assert _dkim_marker(saved) == {"google": _entry(_at(0)), "selector1": _entry(_at(0))}


_DEPTH = 800        # oltre il limite di `copy.deepcopy` (circa 500 livelli), entro quello di `json` (migliaia)


def _nested(depth):
    node = "leaf"
    for _ in range(depth):
        node = {"x": node}
    return node


def _depth(node):
    """Profondità di `_nested`, senza ricorsione: il confronto con `==` di due valori così annidati può sollevare."""
    depth = 0
    while isinstance(node, dict):
        node, depth = node["x"], depth + 1
    return depth


def _deep_previous():
    """Lo snapshot sano con un valore annidato per `_DEPTH` livelli nella voce di `login.` e nei record di `selector1`,
    dopo un'andata e ritorno `json`: un dato che lo store carica da disco."""
    prev = _healthy()
    login = next(a for a in prev["subdomains"]["active"] if a["fqdn"] == _LOGIN)
    login["extra"] = _nested(_DEPTH)
    prev["email_auth"]["dkim"]["records"]["selector1"].append(_nested(_DEPTH))
    return _serialized(prev)


class TestDeeplyNestedPreviousValue:
    """Il dato precedente si riporta senza copia profonda: un valore annidato oltre il limite di `copy.deepcopy`, che
    `json` carica e salva, non fa saltare il salvataggio dello snapshot (`RecursionError`), e il nome resta riportato."""

    def test_a_partial_cycle_carries_the_deep_names_and_saves(self, orch, monkeypatch):
        prev = _deep_previous()

        saved, sent, _ = _persist(monkeypatch, orch, prev,
                                  _cut(_healthy(), subdomains=[_LOGIN], selectors=["selector1"]))

        login = next(a for a in saved["subdomains"]["active"] if a["fqdn"] == _LOGIN)
        assert _depth(login["extra"]) == _DEPTH
        assert _depth(saved["email_auth"]["dkim"]["records"]["selector1"][1]) == _DEPTH
        assert _sub_marker(saved) == {_LOGIN: _entry(_at(0))}
        assert _dkim_marker(saved) == {"selector1": _entry(_at(0))}
        assert len(sent) == 1 and _depth(_serialized(saved)["email_auth"]["dkim"]["records"]["selector1"][1]) == _DEPTH

    @pytest.mark.parametrize("failed", _FAILED_DNS)
    def test_a_total_failure_keeps_and_marks_the_deep_names_and_saves(self, orch, monkeypatch, failed):
        prev = _deep_previous()

        saved, sent, _ = _persist(monkeypatch, orch, prev, failed)

        login = next(a for a in saved["subdomains"]["active"] if a["fqdn"] == _LOGIN)
        assert _depth(login["extra"]) == _DEPTH
        assert _sub_marker(saved) == {fqdn: _entry(_at(0)) for fqdn in (_WWW, _MAIL, _AUTODISCOVER, _LOGIN)}
        assert _dkim_marker(saved) == {"google": _entry(_at(0)), "selector1": _entry(_at(0))}
        assert len(sent) == 1


# ── 8. La catena vera: /dns -> _run_pipeline -> intel store -> /classify/variant e /diff ────────────────────

_CDOMAIN = _sec29.DOMAIN
_CLIENT = "tenant-col31"
_CLOGIN = _sec29._sub("login")
_SELECTOR1 = _sec29._dkim("selector1")
_ZONE = {**_sec29._ZONE, (_CLOGIN, "A"): _sec29._ok("192.0.2.30")}
_GONE_ZONE = {**_ZONE, (_CLOGIN, "A"): _sec29._NXDOMAIN, (_CLOGIN, "CNAME"): _sec29._NXDOMAIN,
              (_SELECTOR1, "TXT"): _sec29._NXDOMAIN}
_UNANSWERED = {(_CLOGIN, "A"): _sec29._SERVFAIL, (_SELECTOR1, "TXT"): _sec29._SERVFAIL}
_ORCH_TIMEOUT_S = _sec29._DEADLINE_S + _sec29._ORCH_MARGIN_S


class _Step:
    def __init__(self, label, hours, zone, *, hang=(), deadline=40, orch_timeout=_ORCH_TIMEOUT_S):
        self.label, self.hours, self.zone, self.hang = label, hours, zone, hang
        self.deadline, self.orch_timeout = deadline, orch_timeout


# Un ciclo ogni 24 h: nessuna parte base riportata raggiunge le 72 h, quindi nessun `dns_stale_*` atteso.
_STEPS = [
    _Step("healthy", 0, _ZONE),
    # SEC-29: AAAA muto consuma la scadenza; tutto ciò che viene dopo i tipi base resta senza risposta.
    _Step("deadline-cut", 24, _ZONE, hang=[(_CDOMAIN, "AAAA")], deadline=_sec29._DEADLINE_S),
    _Step("healthy-again", 48, _ZONE),
    _Step("login-and-selector1-unanswered", 72, {**_ZONE, **_UNANSWERED}),
    _Step("total-failure", 96, {**_ZONE, **{(_CDOMAIN, t): _sec29._SERVFAIL for t in _sec29._BASE}}),
    # L'orchestrator smette di aspettare `/dns`: il modulo vale `None`.
    _Step("dns-timeout", 120, _ZONE, hang=[(_CDOMAIN, "AAAA")], orch_timeout=0.5),
    _Step("healthy-after-the-failures", 144, _ZONE),
    _Step("login-a-nxdomain-cname-unanswered", 168,
          {**_ZONE, (_CLOGIN, "A"): _sec29._NXDOMAIN, (_CLOGIN, "CNAME"): _sec29._SERVFAIL}),
    _Step("login-and-selector1-gone", 192, _GONE_ZONE),
    _Step("unanswered-after-gone", 216, {**_GONE_ZONE, **_UNANSWERED}),
    # `login.` e `selector1` tornano: un cambio vero, il solo oltre la sparizione.
    _Step("healthy-at-the-end", 240, _ZONE),
    # Senza risposta il solo `google`, il primo selettore trovato dell'elenco.
    _Step("google-unanswered", 264, {**_ZONE, (_sec29._dkim("google"), "TXT"): _sec29._SERVFAIL}),
]
_I = {step.label: i for i, step in enumerate(_STEPS)}


class _ChainCycle:
    def __init__(self, body, event, alerts, snapshot_dns, diffs, statuses):
        self.body = body                # risposta di `/dns` vista dall'orchestrator (None: nessuna risposta)
        self.event = event
        self.alerts = alerts
        self.dns = snapshot_dns         # sezione `dns` dello snapshot dopo il ciclo
        self.diffs = diffs              # payload mandati a `/diff` nel ciclo
        self.statuses = statuses        # (percorso, stato HTTP) di ogni chiamata al classificatore nel ciclo


def _run_chain(root):
    """I cicli di `_STEPS` lungo la catena vera, uno dopo l'altro sullo stesso store. Per ciclo: la zona e le query
    mute del `dig` finto, la scadenza di `/dns`, l'attesa dell'orchestrator e l'orologio dei due servizi (`/dns`
    all'ora del ciclo, l'orchestrator 30 s dopo). Una richiesta `/dns` abbandonata finisce prima del ciclo seguente."""
    import services.orchestrator as o
    clock = {}
    cycles = []
    with _sec29._installed_fake(root / "dns") as (fake, mp):
        mp.setattr(o, "INTEL_STORE", True)
        mp.setattr(o, "CASE_INGEST", False)
        mp.setattr(o.intel_store, "SNAP_DIR", root / "snapshots")
        mp.setattr(o.intel_store, "HIST_DIR", root / "history")
        mp.setattr(dns_intel, "now_iso", lambda: clock["dns"])
        mp.setattr(o, "now_iso", lambda: clock["orch"])
        dns_client = TestClient(dns_intel.app)
        cls_client = TestClient(_classifier_app, raise_server_exceptions=False)
        published, abandoned, seen = [], [], {}

        def _dns_get(path, timeout):
            box = {}

            def call():
                try:
                    box["r"] = dns_client.get(path)
                except BaseException as exc:      # come un errore di trasporto
                    box["error"] = exc
            th = threading.Thread(target=call, name="col31-orchestrator-dns", daemon=True)
            _sec29._LIVE_THREADS.append(th)
            th.start()
            th.join(timeout)
            if th.is_alive():
                abandoned.append(th)
                raise TimeoutError(f"read timeout={timeout}")
            if "error" in box:
                raise box["error"]
            r = box["r"]
            seen["body"] = r.json() if r.is_success else None
            return _Resp(r.json() if r.is_success else None, ok=r.is_success, status_code=r.status_code)

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _Resp({"domains": [{**_sec29._FEED_ENTRY, "client": _CLIENT}]})
            if "/feed/whitelist" in url:
                return _Resp({"whitelist": {}})
            if url.startswith(o.DNS_URL):
                return _dns_get(url[len(o.DNS_URL):], timeout)
            if url.startswith(o.CERT_URL):
                return _Resp(_sec29._CERT)
            if url.startswith(o.HTTP_URL):
                return _Resp(_sec29._HTTP)
            raise AssertionError(f"GET non atteso: {url}")

        def _post(url, json=None, timeout=None, headers=None):
            if url.endswith("/publish"):
                published.extend((json or {}).get("events", []))
                return _Resp({})
            if url.startswith(o.CLASSIFY_URL):
                path = url[len(o.CLASSIFY_URL):]
                if path == "/diff":
                    seen["diffs"].append(copy.deepcopy(json))
                r = cls_client.post(path, json=json)
                seen["statuses"].append((path, r.status_code))
                return _Resp(r.json() if r.is_success else None, ok=r.is_success, status_code=r.status_code)
            raise AssertionError(f"POST non atteso: {url}")

        mp.setattr(o._session, "get", _get)
        mp.setattr(o._session, "post", _post)

        for step in _STEPS:
            fake.unrelease()
            fake.reset()
            fake.configure(step.zone, hang=step.hang)
            mp.setattr(dns_intel, "DNS_DEADLINE_S", step.deadline, raising=False)
            mp.setattr(o, "TIMEOUT", step.orch_timeout)
            clock["dns"], clock["orch"] = _at(step.hours), _at(step.hours, seconds=30)
            seen.clear()
            seen["diffs"], seen["statuses"] = [], []
            published.clear()
            before = len(o.intel_store.load_history(_CLIENT, _CDOMAIN, limit=1000))
            o._run_pipeline(o.TriggerRequest(client=_CLIENT, include_whois=False, include_reputation=False,
                                             include_dnstwist=False, variant_intel=False, scope="all"))
            if abandoned:
                # La richiesta /dns abbandonata dall'orchestrator finisce prima del ciclo seguente.
                fake.release()
                for th in abandoned:
                    th.join(_sec29._RELEASE_JOIN_S)
                abandoned.clear()
            assert o._progress["phase"] != "error", f"{step.label}: la pipeline è terminata con un errore"
            history = o.intel_store.load_history(_CLIENT, _CDOMAIN, limit=1000)
            new = history[:len(history) - before]
            snapshot = (o.intel_store.load_snapshot(_CLIENT, _CDOMAIN) or {}).get("intel", {}).get("dns")
            event = next(e for e in published if e["domain"] == _CDOMAIN)
            cycles.append(_ChainCycle(seen.get("body"), event, [(a["type"], a["severity"]) for e in new
                                                                for a in e["alerts"]],
                                      snapshot, seen["diffs"], seen["statuses"]))
    return cycles


@pytest.fixture(scope="class")
def chain(tmp_path_factory):
    return _run_chain(tmp_path_factory.mktemp("col31-chain"))


def _names(dns):
    """(fqdn attivi, selettori trovati) di una sezione `dns`."""
    subs = (dns or {}).get("subdomains") or {}
    dkim = ((dns or {}).get("email_auth") or {}).get("dkim") or {}
    return [a["fqdn"] for a in subs.get("active") or []], list(dkim.get("selectors_found") or [])


class TestCarryOverAlongTheChain:
    """Dodici cicli lungo la catena vera, con l'orologio di `/dns` e dell'orchestrator in mano al test (un ciclo ogni
    24 h, persistito 30 s dopo l'osservazione). Il `dig` finto risponde dalla zona dei test SEC-29 con `login.` attivo
    (A 192.0.2.30) e due selettori trovati (`google`, `selector1`)."""

    def test_the_cycles_reach_the_orchestrator_in_the_intended_shape(self, chain):
        # Controllo dello scenario: se l'ambiente non produce queste forme, gli altri test non dicono nulla.
        cut = chain[_I["deadline-cut"]].body
        assert cut["records_status"]["A"] == "ok" and cut["error"] is None, "il taglio deve essere parziale"
        assert len(cut["subdomains"]["unknown"]) == 25 and cut["subdomains"]["active"] == []
        assert len(cut["email_auth"]["dkim"]["selectors_unknown"]) == 18
        one = chain[_I["login-and-selector1-unanswered"]].body
        assert one["subdomains"]["unknown"] == [_CLOGIN] and one["email_auth"]["dkim"]["selectors_unknown"] == ["selector1"]
        assert chain[_I["total-failure"]].body["error"] == dns_intel.DNS_ALL_UNKNOWN_ERROR
        assert chain[_I["dns-timeout"]].body is None
        assert chain[_I["login-a-nxdomain-cname-unanswered"]].body["subdomains"]["unknown"] == [_CLOGIN]
        gone = chain[_I["login-and-selector1-gone"]].body
        assert _CLOGIN not in gone["subdomains"]["unknown"] + _names(gone)[0]
        assert "selector1" not in gone["email_auth"]["dkim"]["selectors_unknown"] + _names(gone)[1]
        assert chain[_I["unanswered-after-gone"]].body["subdomains"]["unknown"] == [_CLOGIN]
        google = chain[_I["google-unanswered"]].body["email_auth"]["dkim"]
        assert (google["selectors_found"], google["selectors_unknown"]) == (["selector1"], ["google"])
        assert _names(chain[0].dns) == ([_sec29._sub(s) for s in ("www", "mail", "autodiscover", "login")],
                                        ["google", "selector1"])

    def test_no_cycle_raises_an_alert(self, chain):
        # Controllo: nessuna regola legge questi nomi, e il riporto non deve aggiungere alert. Ogni chiamata al
        # classificatore ha risposto 200: un errore di `/diff` lascerebbe la storia vuota, cioè «nessun alert».
        assert [c.alerts for c in chain] == [[] for _ in _STEPS]
        assert [c.statuses for c in chain] == [[("/classify/variant", 200)]] + [
            [("/classify/variant", 200), ("/diff", 200)] for _ in _STEPS[1:]]

    def test_the_classification_is_the_one_of_the_observation(self, chain):
        # Controllo: la classificazione legge l'osservazione del ciclo, non lo snapshot.
        verdicts = [c.event["classification"]["auto_classification"] for c in chain]
        failed = {_I["total-failure"], _I["dns-timeout"]}
        assert {v for i, v in enumerate(verdicts) if i not in failed} == {verdicts[0]} != {"insufficient_data"}
        assert [verdicts[i] for i in sorted(failed)] == ["insufficient_data", "insufficient_data"]

    def test_healthy_cycles_are_saved_exactly_as_dns_sent_them(self, chain):
        # Controllo: dati completi, nessun riporto, nessun marcatore.
        for label in ("healthy", "healthy-again", "healthy-after-the-failures", "healthy-at-the-end"):
            c = chain[_I[label]]
            assert json.dumps(c.dns) == json.dumps(c.body), label

    def test_a_deadline_cut_keeps_every_name_seen_in_the_previous_cycle(self, chain):
        healthy, cut = chain[_I["healthy"]].dns, chain[_I["deadline-cut"]].dns

        assert cut["subdomains"]["active"] == healthy["subdomains"]["active"]
        assert cut["email_auth"]["dkim"]["selectors_found"] == healthy["email_auth"]["dkim"]["selectors_found"]
        assert cut["email_auth"]["dkim"]["records"] == healthy["email_auth"]["dkim"]["records"]

    def test_a_deadline_cut_marks_each_carried_name_with_the_instants_of_the_base_types(self, chain):
        healthy, cut = chain[_I["healthy"]].dns, chain[_I["deadline-cut"]].dns
        entry = _entry(_at(0), _at(24, seconds=30))

        assert _sub_marker(cut) == {fqdn: entry for fqdn in _names(healthy)[0]}
        assert _dkim_marker(cut) == {"google": entry, "selector1": entry}
        assert cut["carried_over"]["AAAA"] == entry, "le parti base riportate nello stesso ciclo"

    def test_a_deadline_cut_keeps_its_own_unknown_lists(self, chain):
        c = chain[_I["deadline-cut"]]

        assert _sub_marker(c.dns), "precondizione: il riporto deve essere marcato"
        assert c.dns["subdomains"]["unknown"] == c.body["subdomains"]["unknown"]
        assert c.dns["email_auth"]["dkim"]["selectors_unknown"] == c.body["email_auth"]["dkim"]["selectors_unknown"]

    def test_only_the_unanswered_name_and_selector_are_carried(self, chain):
        before, c = chain[_I["healthy-again"]].dns, chain[_I["login-and-selector1-unanswered"]]
        entry = _entry(_at(48), _at(72, seconds=30))

        assert c.dns["subdomains"]["active"] == before["subdomains"]["active"]
        assert _sub_marker(c.dns) == {_CLOGIN: entry}
        assert _dkim_marker(c.dns) == {"selector1": entry}
        assert c.dns["email_auth"]["dkim"]["records"] == before["email_auth"]["dkim"]["records"]
        assert "carried_over" not in c.dns, "nessuna parte base riportata"

    def test_a_total_failure_marks_every_kept_name_and_inherits_their_observation(self, chain):
        c = chain[_I["total-failure"]]
        now = _at(96, seconds=30)
        www, mail, autodiscover = (_sec29._sub(s) for s in ("www", "mail", "autodiscover"))

        assert _names(c.dns) == _names(chain[_I["login-and-selector1-unanswered"]].dns)
        assert _sub_marker(c.dns) == {www: _entry(_at(72), now), mail: _entry(_at(72), now),
                                      autodiscover: _entry(_at(72), now), _CLOGIN: _entry(_at(48), now)}
        assert _dkim_marker(c.dns) == {"google": _entry(_at(72), now), "selector1": _entry(_at(48), now)}

    def test_a_dns_timeout_marks_every_kept_name_and_inherits_their_observation(self, chain):
        c = chain[_I["dns-timeout"]]
        now = _at(120, seconds=30)
        www, mail, autodiscover = (_sec29._sub(s) for s in ("www", "mail", "autodiscover"))

        assert _names(c.dns) == _names(chain[_I["login-and-selector1-unanswered"]].dns)
        assert _sub_marker(c.dns) == {www: _entry(_at(72), now), mail: _entry(_at(72), now),
                                      autodiscover: _entry(_at(72), now), _CLOGIN: _entry(_at(48), now)}
        assert _dkim_marker(c.dns) == {"google": _entry(_at(72), now), "selector1": _entry(_at(48), now)}

    def test_a_name_whose_a_is_nxdomain_and_cname_unanswered_is_carried_marked_and_dated(self, chain):
        # `/dns` mette il nome in `unknown` se una delle due query non ha risposta, anche quando l'A ha già detto
        # `nxdomain`. Il riporto lo tiene, con la data dell'ultima osservazione.
        before, c = chain[_I["healthy-after-the-failures"]].dns, chain[_I["login-a-nxdomain-cname-unanswered"]].dns

        assert c["subdomains"]["active"] == before["subdomains"]["active"]
        assert _sub_marker(c) == {_CLOGIN: _entry(_at(144), _at(168, seconds=30))}

    def test_a_name_and_a_selector_that_really_disappeared_are_gone(self, chain):
        # Controllo.
        c = chain[_I["login-and-selector1-gone"]]

        assert json.dumps(c.dns) == json.dumps(c.body)
        assert _CLOGIN not in _names(c.dns)[0] and "selector1" not in _names(c.dns)[1]

    def test_a_disappeared_name_is_not_brought_back_by_a_later_cut(self, chain):
        # Controllo.
        c = chain[_I["unanswered-after-gone"]]

        assert json.dumps(c.dns) == json.dumps(c.body)

    def test_the_diff_receives_the_section_that_is_saved(self, chain):
        # Controllo: ciò che `/diff` confronta è ciò che diventa la baseline del ciclo dopo.
        for step, c in zip(_STEPS[1:], chain[1:], strict=True):
            assert [d["current"]["dns"] for d in c.diffs] == [c.dns], step.label

    def test_a_cut_of_the_first_selector_keeps_the_list_order(self, chain):
        before, c = chain[_I["healthy-at-the-end"]].dns, chain[_I["google-unanswered"]].dns

        assert c["email_auth"]["dkim"]["selectors_found"] == ["google", "selector1"]
        assert c["email_auth"]["dkim"]["records"] == before["email_auth"]["dkim"]["records"]
        assert _dkim_marker(c) == {"google": _entry(_at(240), _at(264, seconds=30))}

    def test_the_diff_sees_a_change_of_names_only_when_a_name_really_changed(self, chain):
        changed = []
        for step, c in zip(_STEPS[1:], chain[1:], strict=True):
            (diff,) = c.diffs
            if _names(diff["baseline"]["dns"]) != _names(diff["current"]["dns"]):
                changed.append(step.label)

        assert changed == ["login-and-selector1-gone", "healthy-at-the-end"]

    def test_a_rule_on_dkim_selectors_found_would_not_fire_on_the_return_after_a_cut(self, chain):
        # Una regola «DKIM aggiunto» che leggesse `selectors_found` (da vuoto a non vuoto) al posto del campo
        # `present`, che la sezione DKIM non ha: senza riporto scatterebbe al ritorno dopo ogni taglio.
        fired = [step.label for step, c in zip(_STEPS[1:], chain[1:], strict=True)
                 for d in c.diffs
                 if _names(d["current"]["dns"])[1] and not _names(d["baseline"]["dns"])[1]]

        assert fired == []
