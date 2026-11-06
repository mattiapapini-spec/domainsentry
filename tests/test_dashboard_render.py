"""Resa vera della dashboard: report verso il cliente e scheda Intel, eseguiti con node.

I controlli di `tests/test_dashboard.py` leggono il TESTO dello script: non vedono una guardia tolta
che fa sollevare `TypeError` su ogni snapshot, un ternario con i rami scambiati, un `.error` letto
dall'oggetto sbagliato. Qui lo script vero di `services/dashboard_app.html` gira in un contesto `vm`
(`tests/dashboard_render.js`, un solo processo node per modulo) e si asserisce su ciò che la resa
mostra: testo delle righe, presenza o assenza di una nota, escape. Se `node` manca i test si saltano,
salvo che `DOMAINSENTRY_REQUIRE_NODE=1` li faccia fallire: serve a un runner che non deve restare verde senza la resa.

Contratto (BUG-REGISTER.md, COL-12 e COL-13):
  * `dns.carried_over = {parte: {observed_at, carried_at}}` per le sole 11 parti dell'elenco fisso;
  * `cert`, `whois`, `http`, `reputation` portano un campo diretto `carried_over = {observed_at,
    carried_at}`; vale solo per questi 4 moduli ed è valido se è un oggetto con `carried_at` vero;
  * un modulo con `error` si legge «errore» anche se porta il marcatore;
  * `observed_at` viene da un file su disco: si stampa solo se è una stringa non vuota,
    altrimenti «data ignota»; passa sempre per l'escape.
Valori di prova: indirizzi RFC 5737, nomi RFC 2606.
"""
import copy
import inspect
import json
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

_HARNESS = Path(__file__).with_name("dashboard_render.js")
_TIMEOUT_S = 60

_DOMAIN = "acme-typo.example"
_T0 = "2026-10-20T10:00:00+00:00"       # ultima osservazione reale
_NOW = "2026-10-24T10:00:30+00:00"      # ciclo che riporta
_MODULES = ("cert", "whois", "http", "reputation")
_PARTS = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "spf", "dmarc", "bimi", "caa")
_BLOCK_OF = {"http": "http", "cert": "certificates", "whois": "whois", "reputation": "reputation"}
_STATUS_LABEL = {"whois": "WHOIS", "http": "HTTP", "reputation": "reputation"}      # il certificato sta nella riga CT
_UNSET = object()                        # nel marcatore: «la chiave observed_at non c'è»
_HOSTILE = '<zz>"\'&amp;<zz>'            # un tag intero entro i primi 10 caratteri, che è dove la data si taglia


# ── Snapshot di prova ─────────────────────────────────────────────────────────────────────────

def _healthy(**sections):
    """Intel di un dominio con tutti i moduli riusciti e nessun marcatore. `sections` sostituisce
    intere sezioni (`_healthy(dns=None)`)."""
    intel = {
        "dns": {
            "domain": _DOMAIN, "timestamp": _T0,
            "records": {"A": ["192.0.2.10"], "AAAA": [], "MX": [f"10 mail.{_DOMAIN}"], "NS": [], "TXT": [],
                        "SOA": [], "CNAME": []},
            "records_status": {"A": "ok", "AAAA": "nodata", "MX": "ok", "NS": "nodata", "TXT": "nodata",
                               "SOA": "nodata", "CNAME": "nodata"},
            "email_auth": {"dkim": {"selectors_found": []}},
            "subdomains": {}, "error": None},
        "cert": {"domain": _DOMAIN, "timestamp": _T0, "error": None,
                 "ct_certificates": {"total": 21, "certificates": [
                     {"id": 1, "common_name": _DOMAIN, "issuer_name": "Example CA"}]}},
        "whois": {"domain": _DOMAIN, "timestamp": _T0, "registrar": "Registrar Example",
                  "creation_date": "2020-01-01T00:00:00", "error": None},
        "http": {"domain": _DOMAIN, "timestamp": _T0, "overall_status": "active", "error": None,
                 "checks": [{"url": f"http://{_DOMAIN}", "status_code": 200, "title": "Acme",
                             "content_length": 5400, "server": "nginx", "error": None}]},
        "reputation": {"domain": _DOMAIN, "timestamp": _T0, "risk_score": 0, "risk_level": "clean", "error": None,
                       "virustotal": {"malicious": 0, "error": None}, "otx": {"error": None},
                       "securitytrails": {"error": None}},
    }
    intel.update(copy.deepcopy(sections))
    return intel


def _mark(observed=_T0, carried=_NOW):
    marker = {"carried_at": carried}
    if observed is not _UNSET:
        marker["observed_at"] = observed
    return marker


def _modules_marked(marker, modules=_MODULES, errors=None):
    """`_healthy()` con `marker` sulle sezioni `modules`; `errors` = {modulo: valore di `error`}."""
    intel = _healthy()
    for module in modules:
        intel[module]["carried_over"] = copy.deepcopy(marker)
    for module, error in (errors or {}).items():
        intel[module]["error"] = error
    return intel


def _dns_marked(marker, **dns_fields):
    intel = _healthy()
    intel["dns"]["carried_over"] = copy.deepcopy(marker)
    intel["dns"].update(dns_fields)
    return intel


_HISTORY = [{"timestamp": _NOW, "max_severity": "HIGH", "alert_count": 1,
             "alerts": [{"type": "cert_new", "message": "1 new certificate"}]}]

_CASES = {}


def _add(name, intel, history=_HISTORY):
    """`history=_UNSET`: lo snapshot non ha la chiave `history`."""
    assert name not in _CASES, name
    _CASES[name] = {"intel": intel} if history is _UNSET else {"intel": intel, "history": history}


_add("plain", _healthy())

# DNS: parti riportate
_add("dns_a_and_mx", _dns_marked({"A": _mark(_T0), "MX": _mark(None)}))
_add("dns_a_only", _dns_marked({"A": _mark(_T0)}))
_add("dns_mx_only", _dns_marked({"MX": _mark(_T0)}))
_empty_a_mx = _dns_marked({"A": _mark(_T0), "MX": _mark(None)})
_empty_a_mx["dns"]["records"].update({"A": [], "MX": []})
_empty_a_mx["dns"]["records_status"].update({"A": "nodata", "MX": "nodata"})
_add("dns_carried_a_and_mx_without_records", _empty_a_mx)
_add("dns_unordered", _dns_marked({"spf": _mark(_T0), "MX": _mark(None), "caa": _mark(_T0), "A": _mark(_T0)}))
_add("dns_all_parts", _dns_marked({part: _mark(_T0) for part in _PARTS}))
_add("dns_names_outside_the_list", _dns_marked(
    {"zz": _mark(), "constructor": _mark(), "toString": _mark(), "a": _mark(), "mx": _mark(), "dkim": _mark(),
     "subdomains": _mark(), "carried_at": _NOW, "observed_at": _T0}))
_add("dns_one_part_among_foreign_names", _dns_marked({"zz": _mark(), "toString": _mark(), "NS": _mark(_T0)}))
_add("dns_empty_marker", _dns_marked({}))
_undetermined = _dns_marked({"A": _mark(_T0)})
_undetermined["dns"]["records_status"]["TXT"] = "unknown"
_add("dns_carried_and_undetermined", _undetermined)
_add("dns_marker_with_error", _dns_marked({"A": _mark(_T0)}, error="DNS resolution failed"))
_add("dns_null", _healthy(dns=None))
_add("dns_forged_in_module_form", _dns_marked(_mark(_T0)))
_add("dns_forged_carried_at_only", _dns_marked({"carried_at": _NOW}))
_add("dns_part_with_module_form_fields", _dns_marked({"A": _mark(_T0), "carried_at": _NOW, "observed_at": _T0}))
_add("dns_entries_not_objects", _dns_marked({"A": "x", "MX": 1, "NS": True, "TXT": [], "SOA": None, "spf": 0,
                                             "dmarc": ""}))

# Moduli: marcatore diretto
_add("mod_all", _modules_marked(_mark(_T0)))
for _module in _MODULES:
    _add(f"mod_only_{_module}", _modules_marked(_mark(_T0), modules=(_module,)))
_add("mod_observed_null", _modules_marked(_mark(None)))
_add("mod_observed_missing", _modules_marked(_mark(_UNSET)))
_add("mod_error_and_marker", _modules_marked(_mark(_T0), errors={
    "cert": "crt.sh HTTP 502", "whois": "WHOIS timeout", "http": "connection refused", "reputation": "quota exceeded"}))
_add("mod_error_on_cert_and_http_only", _modules_marked(_mark(_T0), errors={
    "cert": "crt.sh HTTP 502", "http": "connection refused"}))
_add("mod_falsy_errors_with_marker", _modules_marked(_mark(_T0), errors={"cert": "", "whois": 0, "http": False}))
_add("mod_error_without_marker", _healthy(cert={"ct_certificates": {"total": 0}, "error": "crt.sh HTTP 502"}))

_MALFORMED = {
    "string": "carried_at", "array": ["carried_at"], "empty-object": {}, "observed-at-only": {"observed_at": _T0},
    "number": 5, "true": True, "null": None, "carried-at-empty": {"observed_at": _T0, "carried_at": ""},
    "carried-at-zero": {"observed_at": _T0, "carried_at": 0}, "carried-at-null": {"observed_at": _T0, "carried_at": None},
    "carried-at-false": {"observed_at": _T0, "carried_at": False},
}
for _kind, _marker in _MALFORMED.items():
    _add(f"mod_malformed_{_kind}", _modules_marked(_marker))
    _add(f"dns_malformed_{_kind}", _dns_marked(_marker))

_foreign = _healthy()
_foreign["carried_over"] = _mark(_T0)
_foreign["foo"] = {"carried_over": _mark(_T0)}
_foreign["dns"]["subdomains"] = {"carried_over": _mark(_T0)}
_add("marker_outside_the_four_modules", _foreign)

# Moduli e DNS mancanti o di forma sbagliata
_add("sections_null", _healthy(cert=None, whois=None, http=None, reputation=None))
_add("sections_wrong_types", _healthy(cert="x", whois=5, http=[1], reputation=True))
_add("sections_empty_objects", _healthy(cert={}, whois={}, http={}, reputation={}))
_add("intel_empty", {})
_add("dns_only", {"dns": _healthy()["dns"]})

# observed_at che non è una data: ogni sito deve dire «data ignota» e non sollevare
_NOT_A_DATE = {
    "number": 5, "huge-number": 1e21, "zero": 0, "true": True, "false": False, "array": ["2026-10-20"],
    "empty-array": [], "object": {"a": "2026-10-20"}, "empty-object": {}, "own-tostring": {"toString": 1},
    "own-valueof": {"valueOf": "x", "toString": "y"}, "null": None, "missing": _UNSET,
}
for _kind, _value in _NOT_A_DATE.items():
    _add(f"not_a_date_{_kind}", {
        **_modules_marked(_mark(_value)),
        "dns": {**_healthy()["dns"], "carried_over": {part: _mark(_value) for part in ("A", "MX", "NS", "spf")}}})

# observed_at stringa vuota (viene da un file su disco)
_add("empty_observed_at", {
    **_modules_marked(_mark("")),
    "dns": {**_healthy()["dns"], "carried_over": {part: _mark("") for part in ("A", "MX", "spf")}}})

# Testo ostile in ogni punto in cui la dashboard stampa un valore letto dal disco
_add("hostile_dates", {
    **_modules_marked(_mark(_HOSTILE)),
    "dns": {**_healthy()["dns"], "carried_over": {part: _mark(_HOSTILE) for part in ("A", "MX", "NS")}}})
_add("hostile_history", _healthy(), history=[{
    "timestamp": _NOW, "max_severity": _HOSTILE, "alert_count": _HOSTILE,
    "alerts": [{"type": _HOSTILE, "message": _HOSTILE}]}])

# Storia dei cambiamenti: `message`, mai `detail`
_add("history_message", _healthy(), history=[{
    "timestamp": _NOW, "max_severity": "MEDIUM", "alert_count": 2,
    "alerts": [{"type": "dns_stale_core", "message": "DNS A, MX riportati da oltre 72 ore",
                "detail": {"parts": ["A", "MX"]}},
               {"type": "cert_new"}]}])
_add("history_message_long", _healthy(), history=[{
    "timestamp": _NOW, "max_severity": "LOW", "alert_count": 1,
    "alerts": [{"type": "cert_new", "message": "x" * 5000}]}])
_add("history_empty", _healthy(), history=[])
_add("history_absent", _healthy(), history=_UNSET)
_add("history_null", _healthy(), history=None)
_add("history_degraded", _healthy(), history=[
    {"timestamp": None, "max_severity": None, "alert_count": None, "alerts": None},
    {"alerts": [{"type": None, "message": None}, {}]}])


# ── Lettura della resa come la legge un browser ───────────────────────────────────────────────

_VOID = frozenset({"meta", "input", "br", "hr", "img", "link"})


class _Node:
    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent, self.children = tag, dict(attrs), parent, []

    def descendants(self):
        for child in self.children:
            if not isinstance(child, str):
                yield child
                yield from child.descendants()

    def classes(self):
        return (self.attrs.get("class") or "").split()

    def text(self):
        def walk(node):
            for child in node.children:
                if isinstance(child, str):
                    yield child
                else:
                    yield from walk(child)
        return " ".join("".join(walk(self)).split())


class _Builder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = self.current = _Node("#document", [], None)

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, attrs, self.current)
        self.current.children.append(node)
        if tag not in _VOID:
            self.current = node

    def handle_startendtag(self, tag, attrs):
        self.current.children.append(_Node(tag, attrs, self.current))

    def handle_endtag(self, tag):
        node = self.current
        while node is not self.root and node.tag != tag:
            node = node.parent
        if node is not self.root:
            self.current = node.parent

    def handle_data(self, data):
        self.current.children.append(data)


def _parse(markup):
    builder = _Builder()
    builder.feed(markup)
    builder.close()
    return builder.root


class _Report:
    """Il report HTML verso il cliente: righe «etichetta -> testo della cella»."""

    def __init__(self, markup):
        self.tree = _parse(markup)
        self.rows = {}
        for row in (n for n in self.tree.descendants() if n.tag == "tr"):
            cells = [c for c in row.children if not isinstance(c, str) and c.tag == "td"]
            if len(cells) >= 2:
                self.rows[cells[0].text()] = cells[1].text()

    def module_status(self):
        """«DNS ok · WHOIS riportato · …» come {modulo: stato}."""
        return dict(part.strip().partition(" ")[::2] for part in self.rows["Module status"].split("·"))


class _IntelTab:
    """La scheda Intel: un blocco `intel-sec` per sezione, chiavi di `data-sec`."""

    def __init__(self, markup):
        self.tree = _parse(markup)
        self.sections = {n.attrs.get("data-sec"): n for n in self.tree.descendants()
                         if n.tag == "div" and "intel-sec" in n.classes()}

    def module_note(self, module):
        """Il testo della riga «riportata…» che apre il blocco del modulo (subito dopo il titolo), o
        None. Una nota in un'altra posizione del blocco non è ammessa."""
        block = self.sections[_BLOCK_OF[module]]
        elements = [c for c in block.children if not isinstance(c, str)]
        assert elements and "block-title" in elements[0].classes(), "il blocco non inizia con il suo titolo"
        notes = [n for n in block.descendants()
                 if n.tag == "div" and "muted" in n.classes() and n.text().startswith("riportata")]
        assert len(notes) <= 1, [n.text() for n in notes]
        if notes:
            assert elements[1] is notes[0], f"la nota di '{module}' non apre il blocco"
            return notes[0].text()
        return None

    def dns_carried_row(self):
        """Il testo della riga DNS delle parti riportate, o None."""
        rows = [n.text() for n in self.sections["dns"].descendants()
                if n.tag == "td" and n.text().startswith("parti riportate")]
        assert len(rows) <= 1, rows
        return rows[0] if rows else None

    def dns_carried_parts(self):
        """{parte: data} dalla riga DNS delle parti riportate, nell'ordine in cui compaiono."""
        row = self.dns_carried_row()
        assert row is not None, "la scheda Intel non ha la riga delle parti riportate"
        return dict(re.findall(r"(\w+) \(([^)]*)\)", row.partition(":")[2]))

    def history_rows(self):
        return [n.text() for n in self.sections["baseline diff history"].descendants()
                if n.tag == "div" and "diff-alert" in n.classes()]


def _elements(tree, tag):
    return [n for n in tree.descendants() if n.tag == tag]


class _Rendered:
    def __init__(self, result):
        self.result = result

    def raw(self, name):
        assert self.result["load_error"] is None, f"lo script della dashboard non si carica: {self.result['load_error']}"
        case = self.result["cases"][name]
        assert case["error"] is None, f"la resa di '{name}' ha sollevato: {case['error']}"
        return case

    def __getitem__(self, name):
        case = self.raw(name)
        return _Report(case["report"]), _IntelTab(case["intel_tab"])

    def assert_same_as_plain(self, name):
        """Il report e la scheda Intel di `name` coincidono, byte per byte, con quelli senza marcatori."""
        plain, other = self.raw("plain"), self.raw(name)
        for page in ("report", "intel_tab"):
            a, b = plain[page], other[page]
            at = next((i for i, (x, y) in enumerate(zip(a, b, strict=False)) if x != y), min(len(a), len(b)))
            assert a == b, (f"'{name}': {page} diverso da quello senza marcatori, dal carattere {at}: "
                            f"{a[at:at + 80]!r} / {b[at:at + 80]!r}")


@pytest.fixture(scope="module")
def rendered():
    """Un solo processo node per modulo: tutti i casi di `_CASES`, nello script vero della dashboard."""
    node = shutil.which("node")
    if node is None:
        # Senza questa richiesta esplicita un runner senza node resterebbe verde senza aver eseguito la resa (BUILD-07).
        if os.environ.get("DOMAINSENTRY_REQUIRE_NODE") == "1":
            pytest.fail("node non disponibile ma DOMAINSENTRY_REQUIRE_NODE=1 lo richiede: la resa della dashboard "
                        "non è stata eseguita", pytrace=False)
        pytest.skip("node non disponibile: la resa della dashboard non si può eseguire")
    payload = json.dumps({"cases": [
        {"name": name, "domain": _DOMAIN, "client": "tenant-x", "updated_at": _NOW, **case}
        for name, case in _CASES.items()]})
    try:
        proc = subprocess.run([node, str(_HARNESS)], input=payload, capture_output=True, encoding="utf-8",
                              timeout=_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        proc = None
    if proc is None:
        pytest.fail(f"{_HARNESS.name} non ha terminato entro {_TIMEOUT_S} s: la resa della dashboard è bloccata",
                    pytrace=False)
    if proc.returncode != 0:
        pytest.fail(f"{_HARNESS.name} è terminato con codice {proc.returncode}: {proc.stderr[-800:]}", pytrace=False)
    return _Rendered(json.loads(proc.stdout))


# ── Nessuna eccezione, nessuna regressione ────────────────────────────────────────────────────

class TestRenderNeverThrows:
    def test_the_script_loads_and_no_snapshot_makes_a_render_function_throw(self, rendered):
        assert rendered.result["load_error"] is None, rendered.result["load_error"]
        assert rendered.result["blocks"] >= 1
        thrown = {name: case["error"] for name, case in rendered.result["cases"].items() if case["error"]}

        assert not thrown, f"la resa solleva su {len(thrown)} snapshot: {thrown}"

    def test_every_case_was_rendered(self, rendered):
        assert set(rendered.result["cases"]) == set(_CASES)


class TestUnmarkedSnapshotRendersAsBefore:
    """Uno snapshot senza marcatori si legge come quello di un ciclo in cui ogni modulo ha risposto: nessuna
    parola «riportato» o «data ignota», valori e stati ordinari. Un marcatore che non è valido non cambia
    nemmeno un byte della resa."""

    def test_the_report_shows_the_plain_values(self, rendered):
        report, _ = rendered["plain"]

        assert report.rows["A record"] == "yes"
        assert report.rows["MX (email)"] == "yes"
        assert report.rows["Website"] == "active"
        assert report.rows["Certificates"] == "21 (CT: ok)"
        assert report.rows["Registrar"] == "Registrar Example"
        assert report.rows["Registered"] == "2020-01-01"
        assert report.rows["Page title"] == "Acme"
        assert report.rows["Content size"] == "5400"
        assert report.rows["Reputation"] == "clean (0)"
        assert report.module_status() == {"DNS": "ok", "WHOIS": "ok", "HTTP": "ok", "reputation": "ok"}

    def test_nothing_in_the_report_or_the_intel_tab_says_riportato(self, rendered):
        report, tab = rendered["plain"]
        everything = " ".join(report.rows.values()) + " " + " ".join(s.text() for s in tab.sections.values())

        assert "riportat" not in everything.lower()
        assert "ignota" not in everything.lower()

    def test_the_intel_tab_has_its_six_blocks_and_the_dns_data(self, rendered):
        _, tab = rendered["plain"]

        assert list(tab.sections) == ["dns", "http", "certificates", "whois", "reputation", "baseline diff history"]
        assert "192.0.2.10" in tab.sections["dns"].text()
        assert "Registrar Example" in tab.sections["whois"].text()
        assert tab.dns_carried_row() is None
        assert [tab.module_note(m) for m in _MODULES] == [None] * 4

    @pytest.mark.parametrize("kind", _MALFORMED)
    def test_a_marker_that_is_not_an_object_with_carried_at_changes_nothing_in_a_module(self, rendered, kind):
        rendered.assert_same_as_plain(f"mod_malformed_{kind}")

    @pytest.mark.parametrize("kind", _MALFORMED)
    def test_a_dns_marker_that_is_not_a_map_of_parts_changes_nothing(self, rendered, kind):
        rendered.assert_same_as_plain(f"dns_malformed_{kind}")

    @pytest.mark.parametrize("name", ["dns_empty_marker", "dns_forged_in_module_form", "dns_forged_carried_at_only",
                                      "marker_outside_the_four_modules"])
    def test_a_marker_that_names_no_carried_part_or_module_changes_nothing(self, rendered, name):
        rendered.assert_same_as_plain(name)


# ── COL-12: DNS riportato ─────────────────────────────────────────────────────────────────────

class TestDnsCarriedPartsInTheReport:
    def test_a_carried_a_says_riportato_with_the_day_of_the_last_observation(self, rendered):
        report, _ = rendered["dns_a_and_mx"]

        assert report.rows["A record"].startswith("yes")
        assert "riportato" in report.rows["A record"]
        assert report.rows["A record"].endswith("ultima osservazione: 2026-10-20)"), "la data si taglia al giorno"

    def test_a_carried_mx_with_an_unknown_observation_says_data_ignota(self, rendered):
        report, _ = rendered["dns_a_and_mx"]

        assert report.rows["MX (email)"].startswith("yes")
        assert "riportato" in report.rows["MX (email)"]
        assert "data ignota" in report.rows["MX (email)"]

    @pytest.mark.parametrize("name, fresh_row", [("dns_a_only", "MX (email)"), ("dns_mx_only", "A record")])
    def test_only_the_carried_one_of_a_and_mx_carries_the_note(self, rendered, name, fresh_row):
        report, _ = rendered[name]

        assert report.rows[fresh_row] == "yes"

    def test_the_note_is_shown_also_when_the_carried_a_and_mx_rows_say_no(self, rendered):
        # Un A o un MX riportato può essere «nessun record» (il ciclo precedente non ne aveva): la riga dice
        # «no» e la nota dice comunque che il dato non è di questo ciclo.
        report, _ = rendered["dns_carried_a_and_mx_without_records"]

        assert report.rows["A record"].startswith("no") and report.rows["MX (email)"].startswith("no")
        assert report.rows["A record"].endswith("riportato, ultima osservazione: 2026-10-20)")
        assert report.rows["MX (email)"].endswith("riportato, ultima osservazione: data ignota)")
        assert report.module_status()["DNS"] == "parti riportate"

    def test_a_part_that_is_not_a_or_mx_leaves_both_rows_plain(self, rendered):
        report, _ = rendered["dns_one_part_among_foreign_names"]

        assert report.rows["A record"] == "yes" and report.rows["MX (email)"] == "yes"

    def test_module_status_says_parti_riportate_for_a_dns_with_a_carried_part(self, rendered):
        report, _ = rendered["dns_a_and_mx"]

        assert report.module_status()["DNS"] == "parti riportate"
        assert report.module_status()["WHOIS"] == "ok"

    @pytest.mark.parametrize("name", ["dns_one_part_among_foreign_names", "dns_all_parts", "dns_unordered"])
    def test_module_status_says_parti_riportate_for_any_listed_part(self, rendered, name):
        report, _ = rendered[name]

        assert report.module_status()["DNS"] == "parti riportate"

    def test_the_fields_of_a_module_marker_inside_the_dns_map_do_not_change_its_status(self, rendered):
        # Il DNS ha la mappa per parte; `carried_at` e `observed_at` accanto alle parti non sono parti.
        report, tab = rendered["dns_part_with_module_form_fields"]

        assert report.module_status()["DNS"] == "parti riportate"
        assert list(tab.dns_carried_parts()) == ["A"]

    def test_module_status_says_errore_for_a_dns_with_an_error_even_if_parts_are_carried(self, rendered):
        report, _ = rendered["dns_marker_with_error"]

        assert report.module_status()["DNS"] == "errore"

    def test_module_status_says_ok_when_the_marker_names_nothing_from_the_fixed_list(self, rendered):
        for name in ("dns_names_outside_the_list", "dns_empty_marker"):
            report, _ = rendered[name]

            assert report.module_status()["DNS"] == "ok", name

    def test_module_status_says_non_raccolto_for_a_missing_dns(self, rendered):
        report, tab = rendered["dns_null"]

        assert report.module_status()["DNS"] == "non raccolto"
        assert report.rows["A record"] == "unknown"
        assert tab.dns_carried_row() is None


class TestDnsCarriedPartsInTheIntelTab:
    def test_the_row_lists_the_carried_parts_with_the_observation_instant(self, rendered):
        _, tab = rendered["dns_a_and_mx"]

        assert tab.dns_carried_parts() == {"A": "2026-10-20 10:00", "MX": "data ignota"}

    def test_the_row_exists_for_a_single_carried_part(self, rendered):
        _, tab = rendered["dns_a_only"]

        assert tab.dns_carried_parts() == {"A": "2026-10-20 10:00"}

    def test_the_row_lists_the_parts_in_the_order_of_the_fixed_list(self, rendered):
        _, tab = rendered["dns_unordered"]

        assert list(tab.dns_carried_parts()) == ["A", "MX", "spf", "caa"]

    def test_the_row_lists_all_eleven_parts(self, rendered):
        _, tab = rendered["dns_all_parts"]

        assert list(tab.dns_carried_parts()) == list(_PARTS)

    def test_the_row_coexists_with_the_row_of_the_undetermined_types(self, rendered):
        _, tab = rendered["dns_carried_and_undetermined"]
        undetermined = [n.text() for n in tab.sections["dns"].descendants()
                        if n.tag == "td" and n.text().startswith("tipi non determinati")]

        assert len(undetermined) == 1 and "TXT" in undetermined[0]
        assert tab.dns_carried_parts() == {"A": "2026-10-20 10:00"}

    def test_the_row_takes_names_from_the_fixed_list_and_not_from_the_marker_keys(self, rendered):
        _, tab = rendered["dns_one_part_among_foreign_names"]

        assert tab.dns_carried_parts() == {"NS": "2026-10-20 10:00"}

    def test_there_is_no_row_when_the_marker_names_nothing_from_the_fixed_list(self, rendered):
        for name in ("dns_names_outside_the_list", "dns_empty_marker", "dns_forged_in_module_form"):
            _, tab = rendered[name]

            assert tab.dns_carried_row() is None, name


# ── COL-12: la storia dei cambiamenti ─────────────────────────────────────────────────────────

class TestHistoryShowsTheAlertMessage:
    def test_the_row_shows_the_type_and_the_message_and_never_the_detail_object(self, rendered):
        _, tab = rendered["history_message"]
        rows = tab.history_rows()

        assert len(rows) == 2
        assert "dns_stale_core" in rows[0] and "DNS A, MX riportati da oltre 72 ore" in rows[0]
        assert not any("[object Object]" in row for row in rows)

    def test_an_alert_without_a_message_shows_only_its_type(self, rendered):
        _, tab = rendered["history_message"]
        row = tab.history_rows()[1]

        assert "cert_new" in row
        assert "—" not in row and "object" not in row

    def test_a_very_long_message_is_cut(self, rendered):
        _, tab = rendered["history_message_long"]
        (row,) = tab.history_rows()

        assert "cert_new" in row and 100 < len(row) < 400

    def test_the_header_shows_the_severity_and_the_number_of_changes(self, rendered):
        _, tab = rendered["history_message"]
        head = [n.text() for n in tab.sections["baseline diff history"].descendants()
                if n.tag == "div" and "diff-head" in n.classes()]

        assert len(head) == 1 and "MEDIUM" in head[0] and "2 change(s)" in head[0]

    @pytest.mark.parametrize("name", ["history_empty", "history_absent", "history_null"])
    def test_an_empty_absent_or_null_history_says_so(self, rendered, name):
        _, tab = rendered[name]

        assert "no changes recorded yet" in tab.sections["baseline diff history"].text()
        assert tab.history_rows() == []
        assert not [n for n in tab.sections["baseline diff history"].descendants() if "diff-entry" in n.classes()]

    def test_a_degraded_history_renders_without_throwing(self, rendered):
        _, tab = rendered["history_degraded"]

        assert len(tab.history_rows()) == 2


# ── COL-13: moduli riportati ──────────────────────────────────────────────────────────────────

class TestModulesCarriedInTheReport:
    def test_the_certificates_row_says_riportato_with_the_day_of_the_last_observation(self, rendered):
        report, _ = rendered["mod_all"]

        assert report.rows["Certificates"] == "21 (CT: riportato, ultima osservazione: 2026-10-20)"

    def test_the_certificates_row_says_data_ignota_for_an_unknown_observation(self, rendered):
        for name in ("mod_observed_null", "mod_observed_missing"):
            report, _ = rendered[name]

            assert report.rows["Certificates"] == "21 (CT: riportato, ultima osservazione: data ignota)", name

    def test_module_status_says_riportato_for_all_four_modules(self, rendered):
        report, _ = rendered["mod_all"]

        assert report.module_status() == {"DNS": "ok", "WHOIS": "riportato", "HTTP": "riportato",
                                          "reputation": "riportato"}

    @pytest.mark.parametrize("module", _MODULES)
    def test_only_the_marked_module_reads_riportato(self, rendered, module):
        report, _ = rendered[f"mod_only_{module}"]
        status = {"DNS": "ok", "WHOIS": "ok", "HTTP": "ok", "reputation": "ok"}
        if module in _STATUS_LABEL:
            status[_STATUS_LABEL[module]] = "riportato"

        assert report.module_status() == status
        assert ("riportato" in report.rows["Certificates"]) == (module == "cert")

    def test_a_module_marker_does_not_change_the_other_rows_of_the_report(self, rendered):
        marked, _ = rendered["mod_all"]
        plain, _ = rendered["plain"]

        for label in ("A record", "MX (email)", "Website", "Registrar", "Registered", "Page title", "Content size",
                      "Reputation"):
            assert marked.rows[label] == plain.rows[label], label

    def test_the_marker_is_honoured_only_for_the_four_modules(self, rendered):
        for name in ("marker_outside_the_four_modules", "dns_forged_in_module_form"):
            report, _ = rendered[name]

            assert report.module_status()["DNS"] == "ok", name

    def test_errore_wins_over_the_marker(self, rendered):
        report, _ = rendered["mod_error_and_marker"]

        assert report.module_status() == {"DNS": "ok", "WHOIS": "errore", "HTTP": "errore", "reputation": "errore"}
        assert report.rows["Certificates"] == "21 (CT: errore)"

    def test_errore_wins_only_for_the_section_that_has_the_error(self, rendered):
        report, _ = rendered["mod_error_on_cert_and_http_only"]

        assert report.module_status() == {"DNS": "ok", "WHOIS": "riportato", "HTTP": "errore",
                                          "reputation": "riportato"}
        assert report.rows["Certificates"] == "21 (CT: errore)"

    def test_a_falsy_error_is_not_an_error(self, rendered):
        report, _ = rendered["mod_falsy_errors_with_marker"]

        assert report.module_status() == {"DNS": "ok", "WHOIS": "riportato", "HTTP": "riportato",
                                          "reputation": "riportato"}
        assert report.rows["Certificates"].startswith("21 (CT: riportato")

    def test_a_section_with_an_error_and_no_marker_still_reads_errore(self, rendered):
        report, _ = rendered["mod_error_without_marker"]

        assert report.rows["Certificates"] == "0 (CT: errore)"

    def test_missing_sections_read_non_raccolto(self, rendered):
        report, tab = rendered["sections_null"]

        assert report.module_status() == {"DNS": "ok", "WHOIS": "non raccolto", "HTTP": "non raccolto",
                                          "reputation": "non raccolto"}
        assert report.rows["Certificates"] == "0 (CT: non raccolto)"
        assert [tab.module_note(m) for m in _MODULES] == [None] * 4

    def test_an_empty_intel_reads_non_raccolto_everywhere(self, rendered):
        report, _ = rendered["intel_empty"]

        assert set(report.module_status().values()) == {"non raccolto"}

    def test_sections_of_the_wrong_type_render_without_a_note(self, rendered):
        report, tab = rendered["sections_wrong_types"]

        assert "riportato" not in " ".join(report.rows.values())
        assert [tab.module_note(m) for m in _MODULES] == [None] * 4


class TestModulesCarriedInTheIntelTab:
    @pytest.mark.parametrize("module", _MODULES)
    def test_the_block_of_a_carried_module_opens_with_the_riportata_note(self, rendered, module):
        _, tab = rendered["mod_all"]

        assert tab.module_note(module) == "riportata dal ciclo precedente (ultima osservazione: 2026-10-20 10:00)"

    @pytest.mark.parametrize("module", _MODULES)
    def test_only_the_block_of_the_marked_module_has_the_note(self, rendered, module):
        _, tab = rendered[f"mod_only_{module}"]

        notes = {m: tab.module_note(m) for m in _MODULES}
        assert notes[module] is not None
        assert [m for m, note in notes.items() if note is not None] == [module]
        assert "riportata" not in tab.sections["dns"].text()

    def test_an_unknown_observation_says_data_ignota_in_every_block(self, rendered):
        for name in ("mod_observed_null", "mod_observed_missing"):
            _, tab = rendered[name]

            for module in _MODULES:
                assert tab.module_note(module) == "riportata dal ciclo precedente (ultima osservazione: data ignota)", \
                    (name, module)

    def test_a_section_with_an_error_has_no_note(self, rendered):
        _, tab = rendered["mod_error_and_marker"]

        assert [tab.module_note(m) for m in _MODULES] == [None] * 4

    def test_the_note_is_missing_only_on_the_blocks_that_have_an_error(self, rendered):
        _, tab = rendered["mod_error_on_cert_and_http_only"]

        assert tab.module_note("cert") is None and tab.module_note("http") is None
        assert tab.module_note("whois") is not None and tab.module_note("reputation") is not None

    def test_a_falsy_error_does_not_hide_the_note(self, rendered):
        _, tab = rendered["mod_falsy_errors_with_marker"]

        assert all(tab.module_note(m) is not None for m in _MODULES)

    def test_the_note_does_not_remove_the_content_of_the_block(self, rendered):
        _, tab = rendered["mod_all"]

        assert "nginx" in tab.sections["http"].text() and "Acme" in tab.sections["http"].text()
        assert "total: 21" in tab.sections["certificates"].text()
        assert "Registrar Example" in tab.sections["whois"].text()
        assert "clean" in tab.sections["reputation"].text()


# ── observed_at che non è una data, vuoto, o ostile ───────────────────────────────────────────

class TestObservationDateThatIsNotADate:
    """`observed_at` viene da un file su disco: un valore che non è una stringa non si stampa e non
    fa sollevare la resa (`String(x)` solleva su un oggetto con un `toString` proprio non callabile)."""

    @pytest.mark.parametrize("kind", _NOT_A_DATE)
    def test_every_site_says_data_ignota(self, rendered, kind):
        report, tab = rendered[f"not_a_date_{kind}"]

        assert "data ignota" in report.rows["A record"] and "riportato" in report.rows["A record"]
        assert "data ignota" in report.rows["MX (email)"]
        assert report.rows["Certificates"].endswith("ultima osservazione: data ignota)")
        assert set(tab.dns_carried_parts().values()) == {"data ignota"}
        assert list(tab.dns_carried_parts()) == ["A", "MX", "NS", "spf"]
        for module in _MODULES:
            assert tab.module_note(module) == "riportata dal ciclo precedente (ultima osservazione: data ignota)", \
                module

    def test_the_entries_of_the_dns_map_that_are_not_objects_do_not_throw(self, rendered):
        report, tab = rendered["dns_entries_not_objects"]

        assert "riportato" in report.rows["A record"]
        assert list(tab.dns_carried_parts()) == ["A", "MX", "NS", "TXT"]


class TestEmptyObservationDate:
    """Un `observed_at` stringa vuota non è una data: «data ignota» nei quattro punti di resa, mai
    «ultima osservazione: )»."""

    def test_the_report_certificates_row_says_data_ignota(self, rendered):
        report, _ = rendered["empty_observed_at"]

        assert report.rows["Certificates"] == "21 (CT: riportato, ultima osservazione: data ignota)"

    def test_the_report_a_and_mx_notes_say_data_ignota(self, rendered):
        report, _ = rendered["empty_observed_at"]

        for label in ("A record", "MX (email)"):
            assert "riportato" in report.rows[label] and "data ignota" in report.rows[label], label

    def test_the_intel_dns_row_says_data_ignota_for_every_carried_part(self, rendered):
        _, tab = rendered["empty_observed_at"]

        assert tab.dns_carried_parts() == {"A": "data ignota", "MX": "data ignota", "spf": "data ignota"}

    def test_the_intel_note_of_every_module_says_data_ignota(self, rendered):
        _, tab = rendered["empty_observed_at"]

        for module in _MODULES:
            assert tab.module_note(module) == "riportata dal ciclo precedente (ultima osservazione: data ignota)", \
                module


class TestHostileTextIsEscaped:
    """Ogni valore letto dal disco passa per l'escape una volta sola: il testo compare così com'è e
    non diventa markup."""

    CUT_AT_10 = _HOSTILE[:10]          # il report taglia la data al giorno (10 caratteri)

    def test_the_report_dates_are_text(self, rendered):
        report, _ = rendered["hostile_dates"]

        assert not _elements(report.tree, "zz")
        assert self.CUT_AT_10 in report.rows["A record"]
        assert self.CUT_AT_10 in report.rows["MX (email)"]
        assert self.CUT_AT_10 in report.rows["Certificates"]

    def test_the_intel_tab_dates_are_text(self, rendered):
        _, tab = rendered["hostile_dates"]

        assert not _elements(tab.tree, "zz")
        row = tab.dns_carried_row()
        assert row is not None and row.count(_HOSTILE) == 3            # A, MX, NS: il testo per intero, una volta
        for module in _MODULES:
            assert _HOSTILE in tab.module_note(module), module

    def test_the_history_is_text(self, rendered):
        _, tab = rendered["hostile_history"]

        assert not _elements(tab.tree, "zz")
        assert any(_HOSTILE in row for row in tab.history_rows())
        head = [n for n in tab.sections["baseline diff history"].descendants()
                if n.tag == "div" and "diff-head" in n.classes()]
        assert len(head) == 1 and head[0].text().count(_HOSTILE) == 2          # gravità e numero di cambiamenti
        (badge,) = [n for n in head[0].descendants() if n.tag == "span" and "badge" in n.classes()]
        assert badge.attrs == {"class": "badge sev-" + _HOSTILE}, "il valore esce dall'attributo class"


# ── Cosa fa la fixture `rendered` quando node manca ───────────────────────────────────────────

_REQUIRE_NODE = "DOMAINSENTRY_REQUIRE_NODE"          # a «1»: l'assenza di node è un errore, non uno skip
_FAKE_RESULT = {"load_error": None, "blocks": 1, "cases": {}}


def _run_rendered_fixture(monkeypatch, *, node, require):
    """Esegue la funzione vera della fixture `rendered` e dice come è andata: `("skip", motivo)`,
    `("fail", messaggio)` o `("run", valore)`.

    `node` è ciò che `shutil.which("node")` restituisce (`None` = assente); `require` è il valore della
    variabile `DOMAINSENTRY_REQUIRE_NODE` (`None` = non impostata, anche se l'ambiente di chi esegue
    la suite, la CI, la imposta). Il processo node non parte mai: `subprocess.run` risponde un esito
    finto, quindi la prova non dipende dal fatto che node ci sia davvero né costa un avvio."""
    real_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda cmd, *a, **k: node if cmd == "node" else real_which(cmd, *a, **k))
    monkeypatch.setattr(subprocess, "run", lambda args, *a, **k: subprocess.CompletedProcess(
        args, 0, stdout=json.dumps(_FAKE_RESULT), stderr=""))
    if require is None:
        monkeypatch.delenv(_REQUIRE_NODE, raising=False)
    else:
        monkeypatch.setenv(_REQUIRE_NODE, require)
    try:
        value = inspect.unwrap(rendered)()
    except pytest.skip.Exception as exc:
        return "skip", str(exc)
    except (pytest.fail.Exception, Exception) as exc:
        return "fail", str(exc)
    return "run", value


class TestMissingNodeDecision:
    """Su un runner senza node i test di resa si saltano e la suite resta verde: la protezione di
    `CODE-51` sparisce in silenzio. Chi vuole che node ci sia (la CI) lo dichiara con
    `DOMAINSENTRY_REQUIRE_NODE=1`: allora la sua assenza fa fallire, con un messaggio che dice perché.
    Senza la variabile resta lo skip, per chi sviluppa su una macchina senza node.

    La decisione sta nella fixture `rendered`; qui se ne chiama la funzione con `shutil.which` e
    l'ambiente sostituiti. Il valore non-«1» della variabile non è fissato dal contratto: non si prova."""

    def test_missing_node_fails_when_it_is_required(self, monkeypatch):
        outcome, detail = _run_rendered_fixture(monkeypatch, node=None, require="1")

        assert outcome == "fail", (f"con {_REQUIRE_NODE}=1 e node assente la resa deve fallire, non '{outcome}'"
                                   f" ({detail!r})")

    def test_the_failure_says_node_is_missing_and_which_variable_asked_for_it(self, monkeypatch):
        outcome, detail = _run_rendered_fixture(monkeypatch, node=None, require="1")

        assert outcome == "fail", f"nessun fallimento da leggere: '{outcome}'"
        assert "node" in detail.replace(_REQUIRE_NODE, "").lower(), f"il nome della variabile non basta: {detail!r}"
        assert _REQUIRE_NODE in detail, "chi legge la CI deve capire che è la variabile a pretendere node"

    def test_missing_node_still_skips_when_it_is_not_required(self, monkeypatch):
        outcome, detail = _run_rendered_fixture(monkeypatch, node=None, require=None)

        assert outcome == "skip", f"senza {_REQUIRE_NODE} l'assenza di node resta uno skip, non '{outcome}'"
        assert "node" in detail.lower(), detail

    @pytest.mark.parametrize("require", [None, "1"], ids=["not_required", "required"])
    def test_present_node_runs_the_harness_whether_or_not_it_is_required(self, monkeypatch, require):
        outcome, value = _run_rendered_fixture(monkeypatch, node="/nonexistent/bin/node", require=require)

        assert outcome == "run", f"con node presente la resa si esegue, non '{outcome}' ({value!r})"
        assert isinstance(value, _Rendered) and value.result == _FAKE_RESULT
