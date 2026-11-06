"""SEC-34 — ogni numero che la dashboard interpola nell'HTML passa da `esc()`.

In `services/dashboard_app.html` ogni valore letto da uno snapshot, da un caso o da un cliente passa da
`esc()` (o da `e()` dentro `buildHtmlReport`), anche quando ci si aspetta un numero. Un campo numerico
scritto nel template senza escape diventerebbe markup se il servizio che lo produce, o il percorso fra
servizi, mandasse una stringa: lo snapshot è persistito com'è, e il markup arriverebbe nella pagina di un
analista autenticato, che ha il token di sessione in `sessionStorage`. Nove siti, tutti con la stessa
regola «un valore di dati o è escapato o è una costante»:

  scheda Intel (`renderIntelTab`)   `hidden_elements.risk_indicators`, `status_code`, `content_length`,
                                    `ct_certificates.total`, `reputation.risk_score`
  report del cliente                `ct_certificates.total` (`buildHtmlReport`), `case_count`
  vista Clienti (`renderClients`)   i casi aperti per cliente (`summary.by_client`)
  schede riepilogo (`loadSummary`)  i cinque conteggi (`by_status`, `open_by_severity`,
                                    `new_unassigned`, `updated_last_24h`)

Il punto non è la raggiungibilità del singolo sito (alcuni ricevono solo conteggi calcolati dal
server) ma la regola uniforme: ognuno si pilota con il payload direttamente.

Come i test di `test_dashboard_render.py`, lo script vero della pagina gira in un contesto `vm` di node
(`tests/dashboard_render.js`, modalità `--sinks`: un solo processo per modulo, `api()` finta, le
assegnazioni a `innerHTML` registrate per id) e si legge l'HTML prodotto con `html.parser`. I marcatori
sono inerti, `<b id=x34-campo>`: un elemento con un id, senza codice eseguibile. Senza escape nasce
quell'elemento. Senza node i test si saltano, salvo `DOMAINSENTRY_REQUIRE_NODE=1`.

Due gruppi: i marcatori nel solo campo (il campo esce come testo, non come elemento) e i valori veri
(interi, 0, `null`, assente) con il testo di cella o di riga fissato qui, accanto a campi di testo
escapati. Valori di prova: indirizzi RFC 5737, nomi RFC 2606.
"""
import json
import os
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

_HARNESS = Path(__file__).with_name("dashboard_render.js")
_TIMEOUT_S = 60

_DOMAIN = "acme-typo.example"
_NOW = "2026-10-24T10:00:30+00:00"
_PREFIX = "x34-"
_ABSENT = object()                       # nel payload: «la chiave non c'è»
_DASH = "—"


def _marker(field):
    return f"<b id={_PREFIX}{field}>"


# ── Payload di prova ──────────────────────────────────────────────────────────────────────────

def _put(node, keys, value):
    """Scrive `value` in `node` lungo il percorso `keys` (un indice numerico entra in una lista).
    `_ABSENT` toglie la chiave."""
    for key in keys[:-1]:
        node = node[int(key)] if isinstance(node, list) else node[key]
    last = keys[-1]
    if isinstance(node, list):
        node[int(last)] = value
    elif value is _ABSENT:
        node.pop(last, None)
    else:
        node[last] = value


def _patched(base, changes):
    for path, value in (changes or {}).items():
        _put(base, path.split("."), value)
    return base


def _intel(changes=None):
    """Intel di un dominio con tutti i moduli riusciti. `changes`: {"percorso.puntato": valore}."""
    return _patched({
        "dns": {"records": {"A": ["192.0.2.10"], "MX": [f"10 mail.{_DOMAIN}"]},
                "records_status": {"A": "ok", "MX": "ok"}, "error": None},
        "http": {"overall_status": "active", "error": None,
                 "checks": [{"url": f"http://{_DOMAIN}", "status_code": 200, "title": "Acme",
                             "content_length": 5400, "server": "nginx", "error": None}]},
        "cert": {"error": None, "ct_certificates": {"total": 21, "certificates": [
            {"id": 1, "common_name": _DOMAIN, "issuer_name": "Example CA"}]}},
        "whois": {"registrar": "Registrar Example", "creation_date": "2020-01-01T00:00:00", "error": None},
        "reputation": {"risk_score": 0, "risk_level": "clean", "error": None},
    }, changes)


def _intel_tab(changes=None):
    snapshot = {"available": True, "history": [],
                "snapshot": {"domain": _DOMAIN, "client": "tenant-x", "updated_at": _NOW, "intel": _intel(changes)}}
    return {"call": "renderIntelTab", "globals": {"CURRENT_INTEL": snapshot}}


def _report(changes=None, **fields):
    d = {"client": "tenant-x", "report_generated": _NOW, "cases": [], "targets": [], "watchlist": [],
         "case_count": 0, "intel_snapshots": {_DOMAIN: {"snapshot": {"intel": _intel(changes)}}}}
    d.update(fields)
    return {"call": "buildHtmlReport", "args": [d]}


def _clients_view(by_client, **client_fields):
    client = {"name": "acme", "targets": [f"www.{_DOMAIN}"], "watchlist": [], "legitimate": "acme.example"}
    client.update(client_fields)
    return {"call": "renderClients", "args": [[client], {"by_client": by_client}]}


def _summary(changes=None):
    return {"call": "loadSummary", "api": {"/summary": _patched({
        "by_status": {"new": 4, "in_progress": 1, "closed_tp": 0, "closed_fp": 2, "closed_benign": 0},
        "open_by_severity": {"CRITICAL": 2, "HIGH": 3}, "new_unassigned": 1, "updated_last_24h": 6}, changes)}}


_SCENARIOS = {}


def _add(name, scenario):
    assert name not in _SCENARIOS, name
    _SCENARIOS[name] = scenario


# Un marcatore nel solo campo, tutto il resto vero.
_add("hostile_risk_indicators", _intel_tab({"http.checks.0.hidden_elements": {
    "risk_indicators": _marker("risk_indicators")}}))
_add("hostile_status_code", _intel_tab({"http.checks.0.status_code": _marker("status_code")}))
_add("hostile_content_length", _intel_tab({"http.checks.0.content_length": _marker("content_length")}))
_add("hostile_intel_ct_total", _intel_tab({"cert.ct_certificates.total": _marker("intel_ct_total")}))
_add("hostile_risk_score", _intel_tab({"reputation.risk_score": _marker("risk_score")}))
_add("hostile_report_ct_total", _report({"cert.ct_certificates.total": _marker("report_ct_total")}))
_add("hostile_case_count", _report(case_count=_marker("case_count")))
_add("hostile_open_cases", _clients_view({"acme": _marker("open_cases")}))

# Le schede riepilogo: i cinque conteggi vengono da sei campi del riepilogo.
_CARD_FIELDS = ("by_status.new", "by_status.in_progress", "open_by_severity.CRITICAL", "open_by_severity.HIGH",
                "new_unassigned", "updated_last_24h")
for _field in _CARD_FIELDS:
    _add(f"hostile_card_{_field}", _summary({_field: _marker(f"card_{_field.replace('.', '_')}")}))

# Valori veri, uno per scenario: (valore del campo, testo che la pagina mostra).
_HIDDEN_RISK = [(3, "3 indicator(s)"), (17, "17 indicator(s)")]
_NO_HIDDEN_RISK = [0, None, _ABSENT]
_STATUS_CODE = [(200, "200"), (404, "404"), (0, _DASH), (None, _DASH), (_ABSENT, _DASH)]
_CONTENT_LENGTH = [(5400, "5400 b"), (1, "1 b"), (0, "0 b"), (None, "0 b"), (_ABSENT, "0 b")]
_CT_TOTAL = [(21, "21"), (0, "0"), (None, "0"), (_ABSENT, "0")]
_RISK_SCORE = [(0, "0"), (55, "55"), (12.5, "12.5"), (None, _DASH), (_ABSENT, _DASH)]
_CASE_COUNT = [(0, "Cases (0)"), (7, "Cases (7)")]
_OPEN_CASES = [(0, "0 open"), (3, "3 open")]


def _slug(value):
    return "absent" if value is _ABSENT else repr(value).replace(" ", "")


for _value, _ in _HIDDEN_RISK:
    _add(f"real_risk_indicators_{_slug(_value)}", _intel_tab({"http.checks.0.hidden_elements": {"risk_indicators": _value}}))
for _value in _NO_HIDDEN_RISK:
    _hidden = {"summary": []} if _value is _ABSENT else {"risk_indicators": _value, "summary": []}
    _add(f"real_risk_indicators_{_slug(_value)}", _intel_tab({"http.checks.0.hidden_elements": _hidden}))
for _value, _ in _STATUS_CODE:
    _add(f"real_status_code_{_slug(_value)}", _intel_tab({"http.checks.0.status_code": _value}))
for _value, _ in _CONTENT_LENGTH:
    _add(f"real_content_length_{_slug(_value)}", _intel_tab({"http.checks.0.content_length": _value}))
for _value, _ in _CT_TOTAL:
    _add(f"real_intel_ct_total_{_slug(_value)}", _intel_tab({"cert.ct_certificates.total": _value}))
    _add(f"real_report_ct_total_{_slug(_value)}", _report({"cert.ct_certificates.total": _value}))
for _value, _ in _RISK_SCORE:
    _add(f"real_risk_score_{_slug(_value)}", _intel_tab({"reputation.risk_score": _value}))
for _value, _ in _CASE_COUNT:
    _add(f"real_case_count_{_slug(_value)}", _report(case_count=_value))
for _value, _ in _OPEN_CASES:
    _add(f"real_open_cases_{_slug(_value)}", _clients_view({"acme": _value}))
_add("real_open_cases_null", _clients_view({"acme": None}))
_add("real_open_cases_other_client", _clients_view({"zeta": 5}))
_add("real_cards", _summary())
_add("real_cards_empty", {"call": "loadSummary", "api": {"/summary": {"by_status": {}, "open_by_severity": {}}}})

# Campi di testo accanto ai numeri, con marcatore: sono escapati, e il numero vero ha il suo testo.
_NEIGHBOURS_TAB = ("url", "server", "title", "issuer", "common_name", "risk_level", "registrar", "ext_resource")
_add("neighbours_tab", _intel_tab({
    "http.checks.0.url": _marker("url"), "http.checks.0.server": _marker("server"),
    "http.checks.0.title": _marker("title"),
    "http.checks.0.hidden_elements": {"risk_indicators": 3, "external_resources": [_marker("ext_resource")]},
    "cert.ct_certificates.certificates": [{"issuer_name": _marker("issuer"), "common_name": _marker("common_name")}],
    "whois.registrar": _marker("registrar"), "reputation.risk_score": 55, "reputation.risk_level": _marker("risk_level"),
}))
_NEIGHBOURS_REPORT = ("client", "legitimate", "notes", "target", "case_domain", "registrar", "title", "risk_level",
                      "risk_score", "content_length")
_add("neighbours_report", _report({
    "http.checks.0.title": _marker("title"), "http.checks.0.content_length": _marker("content_length"),
    "whois.registrar": _marker("registrar"), "reputation.risk_level": _marker("risk_level"),
    "reputation.risk_score": _marker("risk_score"), "cert.ct_certificates.total": 21,
}, client=_marker("client"), legitimate=_marker("legitimate"), notes=_marker("notes"),
    targets=[_marker("target")], case_count=7,
    cases=[{"domain": _marker("case_domain"), "classification": "x", "severity": "HIGH", "status": "new"}]))
_NEIGHBOURS_CLIENTS = ("client_name", "client_legitimate", "client_notes")
_add("neighbours_clients", _clients_view({_marker("client_name"): 3}, name=_marker("client_name"),
                                         legitimate=_marker("client_legitimate"), notes=_marker("client_notes")))


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

    def elements(self, tag=None, cls=None):
        return [n for n in self.descendants() if (tag is None or n.tag == tag) and (cls is None or cls in n.classes())]

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


def _cells(row):
    return [c for c in row.children if not isinstance(c, str) and c.tag == "td"]


def _section_rows(markup, section):
    """{etichetta: cella} delle righe `ik`/`iv` di un blocco della scheda Intel (`data-sec`)."""
    (block,) = [n for n in _parse(markup).elements("div", "intel-sec") if n.attrs.get("data-sec") == section]
    rows = {}
    for row in block.elements("tr"):
        cells = _cells(row)
        if len(cells) == 2 and "ik" in cells[0].classes():
            rows[cells[0].text()] = cells[1]
    return rows


def _report_rows(markup):
    """{etichetta: testo della cella} delle righe a due celle del report."""
    return {cells[0].text(): cells[1].text() for cells in (_cells(r) for r in _parse(markup).elements("tr"))
            if len(cells) >= 2}


def _assert_text_not_markup(markup, field, where):
    """Il marcatore di `field` compare come testo e non nasce l'elemento con il suo id."""
    marker = _marker(field)
    tree = _parse(markup)
    injected = [n for n in tree.descendants() if n.attrs.get("id") == _PREFIX + field]
    assert not injected, (f"{where}: il valore di '{field}' non passa dall'escape, nell'HTML nasce l'elemento "
                          f"<{injected[0].tag} id={_PREFIX + field}> invece del testo {marker!r}")
    assert marker in tree.text(), f"{where}: il testo {marker!r} manca dall'HTML: {tree.text()[:300]!r}"


class _Run:
    def __init__(self, result):
        self.result = result

    def _scenario(self, name):
        assert self.result["load_error"] is None, f"lo script della dashboard non si carica: {self.result['load_error']}"
        scenario = self.result["scenarios"][name]
        assert scenario["error"] is None, f"'{name}': la funzione della pagina ha sollevato: {scenario['error']}"
        return scenario

    def markup(self, name, sink=None):
        """L'HTML di uno scenario: il valore restituito dalla funzione o, con `sink`, quello assegnato a
        `innerHTML` dell'elemento con quell'id."""
        scenario = self._scenario(name)
        if sink is None:
            assert scenario["returned"] is not None, f"'{name}': la funzione non ha restituito HTML"
            return scenario["returned"]
        assert sink in scenario["sinks"], (f"'{name}': la pagina non ha scritto in #{sink} "
                                           f"(avviso mostrato: {scenario['texts'].get('toast')!r})")
        return scenario["sinks"][sink]


@pytest.fixture(scope="module")
def run():
    """Un solo processo node per modulo: tutti gli scenari di `_SCENARIOS`, nello script vero della dashboard."""
    node = shutil.which("node")
    if node is None:
        # Senza questa richiesta esplicita un runner senza node resterebbe verde senza aver eseguito la resa.
        if os.environ.get("DOMAINSENTRY_REQUIRE_NODE") == "1":
            pytest.fail("node non disponibile ma DOMAINSENTRY_REQUIRE_NODE=1 lo richiede: la resa della dashboard "
                        "non è stata eseguita", pytrace=False)
        pytest.skip("node non disponibile: la resa della dashboard non si può eseguire")
    payload = json.dumps({"scenarios": [{"name": name, **scenario} for name, scenario in _SCENARIOS.items()]})
    try:
        proc = subprocess.run([node, str(_HARNESS), "--sinks"], input=payload, capture_output=True,
                              encoding="utf-8", timeout=_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{_HARNESS.name} non ha terminato entro {_TIMEOUT_S} s: la resa della dashboard è bloccata",
                    pytrace=False)
    if proc.returncode != 0:
        pytest.fail(f"{_HARNESS.name} è terminato con codice {proc.returncode}: {proc.stderr[-800:]}", pytrace=False)
    return _Run(json.loads(proc.stdout))


# ── Un marcatore nel solo campo: esce come testo ──────────────────────────────────────────────

class TestSEC34NumbersAreTextInTheIntelTab:
    def test_hidden_risk_indicators_is_text(self, run):
        _assert_text_not_markup(run.markup("hostile_risk_indicators"), "risk_indicators",
                                "scheda Intel, riga «Hidden risk»")

    def test_http_status_code_is_text(self, run):
        _assert_text_not_markup(run.markup("hostile_status_code"), "status_code", "scheda Intel, riga «Status»")

    def test_http_content_length_is_text(self, run):
        _assert_text_not_markup(run.markup("hostile_content_length"), "content_length",
                                "scheda Intel, riga «Length»")

    def test_certificate_total_is_text(self, run):
        _assert_text_not_markup(run.markup("hostile_intel_ct_total"), "intel_ct_total",
                                "scheda Intel, riga «total:» dei certificati")

    def test_reputation_score_is_text(self, run):
        _assert_text_not_markup(run.markup("hostile_risk_score"), "risk_score", "scheda Intel, riga «Score»")


class TestSEC34NumbersAreTextInTheClientReport:
    def test_certificate_total_is_text(self, run):
        _assert_text_not_markup(run.markup("hostile_report_ct_total"), "report_ct_total",
                                "report del cliente, riga «Certificates»")

    def test_case_count_is_text(self, run):
        _assert_text_not_markup(run.markup("hostile_case_count"), "case_count",
                                "report del cliente, titolo «Cases»")


class TestSEC34NumbersAreTextInTheClientsView:
    def test_open_cases_is_text(self, run):
        _assert_text_not_markup(run.markup("hostile_open_cases", sink="clients-grid"), "open_cases",
                                "vista Clienti, contatore dei casi aperti")


class TestSEC34NumbersAreTextInTheSummaryCards:
    @pytest.mark.parametrize("field", _CARD_FIELDS)
    def test_a_count_from_the_summary_is_text(self, run, field):
        _assert_text_not_markup(run.markup(f"hostile_card_{field}", sink="cards"), f"card_{field.replace('.', '_')}",
                                f"schede riepilogo, campo '{field}' del riepilogo")


# ── Valori veri: la resa non cambia ───────────────────────────────────────────────────────────

class TestSEC34RealNumbersKeepTheirText:
    @pytest.mark.parametrize(("value", "shown"), _HIDDEN_RISK, ids=[_slug(v) for v, _ in _HIDDEN_RISK])
    def test_the_hidden_risk_row_counts_the_indicators(self, run, value, shown):
        cell = _section_rows(run.markup(f"real_risk_indicators_{_slug(value)}"), "http")["Hidden risk"]

        assert cell.elements("span")[0].text() == shown

    @pytest.mark.parametrize("value", _NO_HIDDEN_RISK, ids=[_slug(v) for v in _NO_HIDDEN_RISK])
    def test_there_is_no_hidden_risk_row_without_indicators(self, run, value):
        rows = _section_rows(run.markup(f"real_risk_indicators_{_slug(value)}"), "http")

        assert "Hidden risk" not in rows

    @pytest.mark.parametrize(("value", "shown"), _STATUS_CODE, ids=[_slug(v) for v, _ in _STATUS_CODE])
    def test_the_status_cell_shows_the_code_or_a_dash(self, run, value, shown):
        rows = _section_rows(run.markup(f"real_status_code_{_slug(value)}"), "http")

        assert rows["Status"].text() == shown

    @pytest.mark.parametrize(("value", "shown"), _CONTENT_LENGTH, ids=[_slug(v) for v, _ in _CONTENT_LENGTH])
    def test_the_length_cell_shows_the_bytes_or_zero(self, run, value, shown):
        rows = _section_rows(run.markup(f"real_content_length_{_slug(value)}"), "http")

        assert rows["Length"].text() == shown

    @pytest.mark.parametrize(("value", "shown"), _CT_TOTAL, ids=[_slug(v) for v, _ in _CT_TOTAL])
    def test_the_intel_tab_counts_the_certificates_or_zero(self, run, value, shown):
        block = _parse(run.markup(f"real_intel_ct_total_{_slug(value)}"))
        (section,) = [n for n in block.elements("div", "intel-sec") if n.attrs.get("data-sec") == "certificates"]
        lines = [n.text() for n in section.elements("div", "muted") if n.text().startswith("total:")]

        assert lines == [f"total: {shown}"]

    @pytest.mark.parametrize(("value", "shown"), _CT_TOTAL, ids=[_slug(v) for v, _ in _CT_TOTAL])
    def test_the_report_counts_the_certificates_or_zero(self, run, value, shown):
        rows = _report_rows(run.markup(f"real_report_ct_total_{_slug(value)}"))

        assert rows["Certificates"] == f"{shown} (CT: ok)"

    @pytest.mark.parametrize(("value", "shown"), _RISK_SCORE, ids=[_slug(v) for v, _ in _RISK_SCORE])
    def test_the_score_cell_shows_the_score_or_a_dash(self, run, value, shown):
        rows = _section_rows(run.markup(f"real_risk_score_{_slug(value)}"), "reputation")

        assert rows["Score"].text() == shown

    @pytest.mark.parametrize(("value", "shown"), _CASE_COUNT, ids=[_slug(v) for v, _ in _CASE_COUNT])
    def test_the_report_heading_shows_the_number_of_cases(self, run, value, shown):
        headings = [n.text() for n in _parse(run.markup(f"real_case_count_{_slug(value)}")).elements("h2")]

        assert shown in headings

    @pytest.mark.parametrize(("value", "shown"), _OPEN_CASES, ids=[_slug(v) for v, _ in _OPEN_CASES])
    def test_the_client_card_shows_the_open_cases(self, run, value, shown):
        card = _parse(run.markup(f"real_open_cases_{_slug(value)}", sink="clients-grid"))

        assert [n.text() for n in card.elements("span", "cc-cases")] == [shown]

    @pytest.mark.parametrize("name", ["real_open_cases_null", "real_open_cases_other_client"])
    def test_the_client_card_has_no_open_cases_badge_without_a_count(self, run, name):
        card = _parse(run.markup(name, sink="clients-grid"))

        assert card.elements("span", "cc-cases") == []
        assert [n.text() for n in card.elements("span", "cc-name")] == ["acme"]

    @staticmethod
    def _cards(markup):
        return [(c.elements("div", "l")[0].text(), c.elements("div", "n")[0].text())
                for c in _parse(markup).elements("div", "card")]

    def test_the_summary_cards_show_the_counts(self, run):
        cards = self._cards(run.markup("real_cards", sink="cards"))

        assert cards == [("Open cases", "5"), ("Unassigned", "1"), ("Critical", "2"), ("High", "3"),
                         ("Updated · 24h", "6")]

    def test_the_summary_cards_show_zero_for_missing_counts(self, run):
        cards = self._cards(run.markup("real_cards_empty", sink="cards"))

        assert cards == [("Open cases", "0"), ("Unassigned", "0"), ("Critical", "0"), ("High", "0"),
                         ("Updated · 24h", "0")]


class TestSEC34TextFieldsNextToTheNumbersStayEscaped:
    @staticmethod
    def _offenders(markup, fields):
        tree = _parse(markup)
        text = tree.text()
        injected = [f for f in fields if any(n.attrs.get("id") == _PREFIX + f for n in tree.descendants())]
        missing = [f for f in fields if _marker(f) not in text]
        return injected, missing

    def test_the_intel_tab_fields_are_escaped_and_the_real_numbers_keep_their_text(self, run):
        markup = run.markup("neighbours_tab")
        injected, missing = self._offenders(markup, _NEIGHBOURS_TAB)

        assert injected == [] and missing == [], f"elementi iniettati: {injected}, assenti come testo: {missing}"
        assert _section_rows(markup, "reputation")["Score"].text() == "55"
        assert _section_rows(markup, "http")["Hidden risk"].elements("span")[0].text() == "3 indicator(s)"

    def test_the_report_fields_are_escaped_and_the_real_numbers_keep_their_text(self, run):
        markup = run.markup("neighbours_report")
        injected, missing = self._offenders(markup, _NEIGHBOURS_REPORT)

        assert injected == [] and missing == [], f"elementi iniettati: {injected}, assenti come testo: {missing}"
        assert _report_rows(markup)["Certificates"] == "21 (CT: ok)"
        assert "Cases (7)" in [n.text() for n in _parse(markup).elements("h2")]

    def test_the_client_card_fields_are_escaped_and_the_real_number_keeps_its_text(self, run):
        markup = run.markup("neighbours_clients", sink="clients-grid")
        injected, missing = self._offenders(markup, _NEIGHBOURS_CLIENTS)

        assert injected == [] and missing == [], f"elementi iniettati: {injected}, assenti come testo: {missing}"
        assert [n.text() for n in _parse(markup).elements("span", "cc-cases")] == ["3 open"]
