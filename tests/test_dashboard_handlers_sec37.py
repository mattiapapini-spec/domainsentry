"""SEC-37 — ogni dato dentro un attributo `on*` di un gestore inline arriva al JS come letterale JSON.

In `services/dashboard_app.html` pulsanti e righe portano attributi `on*` che chiamano una funzione della pagina
con dati del caso, del cliente o dell'utente: `openCase(42)`, `promoteDomain("example.org", "acme")`. Il motore
JS legge l'attributo DOPO che il parser HTML ha decodificato le entità: `esc()` protegge il markup, non il
letterale JS che l'attributo contiene (`&#39;` torna ad essere `'`). L'invariante è che ogni argomento di un
gestore sia un letterale JSON, poi escapato per l'HTML: una stringa resta una stringa qualunque siano i suoi
caratteri (apici, backslash, a capo, `</script>`, entità già codificate, U+2028), un id resta un numero, un
booleano un booleano, un valore assente `null`. Vale per ogni campo, senza distinguere chi lo scrive: i campi che
un utente autenticato può scrivere liberamente sono il dominio e il client di un caso (`POST /cases/ingest`);
nome del cliente e username passano da una regex lato server, ma la pagina non dipende da quella regex.

Cosa fissano questi test, tutti sul comportamento tranne il gruppo statico:

  * `TestAHostileTextFieldCannotChangeWhatAHandlerCalls` — ogni vista che rende gestori (Clienti, utenti,
    righe e gruppi dei casi, drawer, chip dell'onboarding) resa con un valore ostile in OGNI campo di testo
    che finisce in un gestore: l'attributo, decodificato come fa un browser, chiama solo la funzione
    prevista, una volta, con la stessa stringa. Righe dei casi e chip non portano testo nel gestore: lì il
    test prova che il testo ostile accanto non cambia il gestore;
  * `TestAForgedIdentifierCannotChangeWhatAHandlerCalls` — lo stesso con un id ostile: il gestore chiama
    comunque solo la funzione prevista, una volta, con gli altri argomenti veri. Quale valore riceva
    l'argomento dell'id non è fissato;
  * `TestHandlersKeepTheTypeOfTheirArguments` — con valori veri gli id arrivano come numeri, il flag di
    `uToggleActive` come booleano, i nomi come stringhe;
  * `TestAnAbsentValueReachesAHandlerAsNull` — un campo assente (nome del cliente, dominio o client del caso,
    nome utente) o una voce `null` di una lista arriva al gestore come `null`: il gestore resta valido, chiama
    la sua funzione una volta e gli altri argomenti non cambiano;
  * `TestTheArgumentHelperAlwaysWritesAValidExpression` — l'helper `jsArg` chiamato direttamente nella pagina
    (`tests/dashboard_handlers.js --helper`): `undefined`, una funzione e un simbolo diventano `null`, `null`
    resta `null`, stringhe, numeri e booleani restano il loro letterale JSON dentro un attributo;
  * `TestRenderedTextIsUnchanged` — testo di pulsanti e righe, valori delle `<option>`, classe e testo dei
    chip dell'onboarding: la resa dei valori veri non cambia;
  * `TestAttributeAndTextValuesAreEscaped` — `<option value>` del drawer e tipo dei chip dell'onboarding;
  * `TestTheEvaluatorSeesWhatItShouldSee` — il valutatore di gestori vede una chiusura di stringa, un errore
    di sintassi, una funzione sconosciuta, e il contesto in cui gira un gestore non raggiunge l'host: senza
    questo, ogni «nessuna uscita» sarebbe verde a vuoto;
  * `TestInlineHandlersNeverInterpolateRawData` — sul sorgente della pagina: dentro un attributo `on*` solo
    `${jsArg(…)}`, in un valore fra apici, scritto per intero dentro il suo tag (nessun frammento di attributo,
    nessuna concatenazione); `<option value>` e chip passano da `esc(`. Il lessico gira sul testo con
    commenti, a capo e template annidati; le sue regole hanno una prova a parte
    (`TestTheStaticGuardSeesWhatItShouldSee`) perché una guardia che non trova nulla non è una guardia.

Come per `test_dashboard_render_sec34.py`, lo script vero della pagina gira in un contesto `vm` di node
(`tests/dashboard_render.js --sinks`: un solo processo per modulo, `api()` finta, `innerHTML` registrato per
id). Il testo di ogni attributo `on*` si legge con `html.parser`, che decodifica le entità come un browser, e
si esegue in `tests/dashboard_handlers.js`: un contesto `vm` per gestore, con stub che registrano le chiamate
e la sonda `probe37`, che esiste solo lì. I valori ostili sono inerti: chiudono una stringa e chiamano la
sonda, niente altro. Un `vm` non è un confine di sicurezza: il valutatore è isolato quanto basta per input
scritti dai test, e un controllo prova che da un gestore non si raggiunge l'host. Senza node i test
comportamentali si saltano, salvo `DOMAINSENTRY_REQUIRE_NODE=1`; quelli sul sorgente non lo richiedono.
Valori di prova: nomi RFC 2606.
"""
import bisect
import json
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path
from typing import NamedTuple

import pytest

_TESTS = Path(__file__).parent
_RENDER = _TESTS / "dashboard_render.js"
_EVALUATOR = _TESTS / "dashboard_handlers.js"
_PAGE = _TESTS.parent / "services" / "dashboard_app.html"
_TIMEOUT_S = 60

_PROBE = "probe37"                       # esiste solo negli stub del valutatore
_THIS_VALUE = "viewer"                   # `this.value` di un `<select onchange>`


class _AnyArgument:
    """Nell'atteso: «un argomento qualunque» (un id ostile: conta che il gestore sia quello giusto)."""

    def __repr__(self):
        return "<qualunque>"


_ANY = _AnyArgument()
_ABSENT = object()                       # un campo che manca dai dati (nel JSON: la chiave non c'è; in una lista: null)
_DASH = "—"


# ── Valori ostili ─────────────────────────────────────────────────────────────────────────────
#
# Ogni variante è una `testa` (che fa da valore plausibile) seguita da una coda. Con un apice singolo
# (`single_quote`, `backslash_quote`) o una parentesi (`paren`) il valore chiude la stringa o l'argomento di un
# gestore non protetto e chiama la sonda. Le altre code non fanno nulla in un gestore corretto: servono a
# vedere che il valore arrivi intatto, e ciascuna agisce contro una correzione parziale tipica: togliere gli
# apici dalla stringa (`double_quote`), proteggere l'apice con un backslash senza proteggere il backslash
# (`backslash_quote`), ignorare i caratteri speciali di una stringa JS (`backslash`, `raw_newline`,
# `line_separator` con U+2028/U+2029), decodificare due volte (`entity`), fidarsi del testo che sembra markup
# (`script_close`). `attr_injection` chiude l'attributo HTML e ne apre un altro: dove il dato non passa
# dall'escape (un id nudo) nasce un secondo gestore. La testa è `a` per i campi di testo e `1` per gli id;
# `{k}` è una chiave diversa per ogni campo, così un argomento scambiato con un altro non passa inosservato.

_VARIANTS = {
    "single_quote": "');probe37('{k}');//",
    "double_quote": '");probe37("{k}");//',
    "paren": ");probe37(0);//{k}",
    "backslash": "\\{k}",
    "backslash_quote": "\\');probe37('{k}');//",
    "raw_newline": "\n{k}",
    "script_close": "</script><b id=x37-{k}>",
    "entity": "&#39;);probe37(&#39;{k}&#39;);//",
    "line_separator": "\u2028{k}\u2029",
    "attr_injection": '" onmouseover="probe37(0)" data-k="{k}',
}


def _hostile(variant, key, lead):
    return lead + _VARIANTS[variant].replace("{k}", key)


class _Values:
    """Dove il test mette un valore ostile: `mode` = "real" (nessuno), "text" (campi di testo) o "id" (id)."""

    def __init__(self, mode, variant=None, absent=()):
        self.mode, self.variant, self.absent = mode, variant, frozenset(absent)

    def text(self, key, real):
        if key in self.absent:
            return _ABSENT
        return _hostile(self.variant, key, "a") if self.mode == "text" else real

    def ident(self, key, real):
        return _hostile(self.variant, key, "1") if self.mode == "id" else real

    def ident_arg(self, real):
        """L'argomento atteso per un id: quello vero, o «qualunque» se l'id è ostile."""
        return _ANY if self.mode == "id" else real


class _Exp(NamedTuple):
    event: str
    fn: str
    args: tuple


def _exp(fn, *args, event="onclick"):
    """Un campo assente arriva al gestore come `null`."""
    return _Exp(event, fn, tuple(None if a is _ABSENT else a for a in args))


def _clean(node):
    """Toglie dai dati i campi assenti: la chiave sparisce da un oggetto, in una lista diventa null."""
    if isinstance(node, dict):
        return {k: _clean(v) for k, v in node.items() if v is not _ABSENT}
    if isinstance(node, list):
        return [None if v is _ABSENT else _clean(v) for v in node]
    return node


class _Case(NamedTuple):
    scenario: dict
    sink: str
    expected: list


# ── Le viste ──────────────────────────────────────────────────────────────────────────────────

_DOMAIN = "acme-typo.example"
_ALL_PERMISSIONS = ["manage_cases", "assign_cases", "whitelist", "add_notes"]
_HEAD_AND_TABS = [_exp("closeDrawer"), _exp("switchTab", "overview"), _exp("switchTab", "intel"),
                  _exp("switchTab", "raw")]


def _view_clients(v):
    client = v.text("client", "acme")
    target = v.text("target", f"www.{_DOMAIN}")
    watch = v.text("watch", f"login.{_DOMAIN}")
    entry = {"name": client, "targets": [target], "watchlist": [watch], "legitimate": "acme.example", "notes": ""}
    return _Case({"call": "renderClients", "args": [[entry], {"by_client": {}}]}, "clients-grid", [
        _exp("removeDomainFromClient", target, client),
        _exp("removeDomainFromClient", watch, client),
        _exp("scanClient", client),
        _exp("openAddDomainFor", client),
        _exp("downloadReport", client, "json"),
        _exp("downloadReport", client, "html"),
    ])


def _view_users(v):
    def user(uid, name, role, active):
        return {"id": uid, "username": name, "role": role, "active": active, "created_at": None, "created_by": None}

    active_id, inactive_id = v.ident("uid_active", 7), v.ident("uid_inactive", 12)
    active_name, inactive_name = v.text("user_active", "bob"), v.text("user_inactive", "carol")
    users = [user(1, "alice", "admin", True), user(active_id, active_name, "analyst", True),
             user(inactive_id, inactive_name, "viewer", False)]
    me = {"id": 1, "username": "alice", "role": "admin", "permissions": []}
    scenario = {"call": "loadUsers", "globals": {"ME": me}, "api": {"/users": {"users": users}}}
    a, i = v.ident_arg(7), v.ident_arg(12)
    return _Case(scenario, "users-rows", [
        _exp("uSetRole", 1, _THIS_VALUE, event="onchange"),
        _exp("uSetRole", a, _THIS_VALUE, event="onchange"),
        _exp("uToggleActive", a, False),
        _exp("uResetPw", a, active_name),
        _exp("uSetRole", i, _THIS_VALUE, event="onchange"),
        _exp("uToggleActive", i, True),
        _exp("uResetPw", i, inactive_name),
    ])


def _case_row(cid, domain, client, severity, status="new"):
    return {"id": cid, "domain": domain, "client": client, "classification": "typosquat", "severity": severity,
            "status": status, "assignee_name": None, "updated_at": None}


def _view_rows(v):
    client = v.text("client", "acme")
    cases = [_case_row(v.ident("id_first", 42), v.text("domain", _DOMAIN), client, "HIGH"),
             _case_row(v.ident("id_second", 57), v.text("domain_other", f"login.{_DOMAIN}"), client, "LOW")]
    return _Case({"call": "renderRows", "args": [cases]}, "rows", [
        _exp("openCase", v.ident_arg(42)),
        _exp("openCase", v.ident_arg(57)),
    ])


def _view_grouped(v):
    first, second = v.text("group_first", "acme"), v.text("group_second", "zeta")
    cases = [_case_row(v.ident("id_high", 42), _DOMAIN, first, "HIGH"),
             _case_row(v.ident("id_low", 43), f"login.{_DOMAIN}", first, "LOW"),
             _case_row(v.ident("id_critical", 91), f"shop.{_DOMAIN}", second, "CRITICAL")]
    # I gruppi si ordinano per la severità massima: `second` (CRITICAL) prima di `first` (HIGH).
    return _Case({"call": "renderGrouped", "args": [cases]}, "rows", [
        _exp("toggleClientGroup", second), _exp("openCase", v.ident_arg(91)),
        _exp("toggleClientGroup", first), _exp("openCase", v.ident_arg(42)), _exp("openCase", v.ident_arg(43)),
    ])


def _drawer_case(v, assignable=None, **fields):
    case = {"id": v.ident("id_case", 42), "domain": v.text("domain", _DOMAIN), "client": v.text("client", "acme"),
            "classification": "typosquat", "confidence": "high", "severity": "MEDIUM", "severity_locked": False,
            "pending_severity": None, "status": "new", "assignee_id": None, "assignee_name": None,
            "created_at": None, "updated_at": None, "rationale": ""}
    case.update(fields)
    me = {"id": 1, "username": "alice", "role": "admin", "permissions": _ALL_PERMISSIONS}
    assignable = assignable or [{"id": 3, "username": "bob"}, {"id": 9, "username": "carol"}]
    return {"call": "renderDrawer", "args": [{"case": case, "notes": [], "history": []}],
            "globals": {"ME": me, "ASSIGNABLE": assignable, "CURRENT_INTEL": None}}


def _view_drawer_open(v):
    scenario = _drawer_case(v, severity_locked=True, pending_severity="CRITICAL")
    c = v.ident_arg(42)
    return _Case(scenario, "drawer", _HEAD_AND_TABS + [
        _exp("resolveProposal", c, "approve"), _exp("resolveProposal", c, "reject"),
        _exp("doAssign", c), _exp("takeCase", c), _exp("doStatus", c), _exp("doSeverity", c),
        _exp("doSeverityAuto", c), _exp("doWhitelist", c),
        _exp("promoteDomain", v.text("domain", _DOMAIN), v.text("client", "acme")),
        _exp("doNote", c), _exp("copyRaw"),
    ])


def _view_drawer_closed(v):
    scenario = _drawer_case(v, status="closed_fp")
    c = v.ident_arg(42)
    return _Case(scenario, "drawer", _HEAD_AND_TABS + [_exp("reopenCase", c), _exp("doNote", c), _exp("copyRaw")])


def _view_staged(v):
    staged = [{"domain": v.text("staged_first", _DOMAIN), "type": "target"},
              {"domain": v.text("staged_second", f"login.{_DOMAIN}"), "type": "watchlist"},
              {"domain": f"shop.{_DOMAIN}", "type": "target"}]
    return _Case({"call": "renderStaged", "globals": {"OB_DOMAINS": staged}}, "ob-staged",
                 [_exp("obRemove", 0), _exp("obRemove", 1), _exp("obRemove", 2)])


_VIEWS = {"clients": _view_clients, "users": _view_users, "rows": _view_rows, "grouped": _view_grouped,
          "drawer_open": _view_drawer_open, "drawer_closed": _view_drawer_closed, "staged": _view_staged}
_TEXT_VIEWS = ("clients", "users", "rows", "grouped", "drawer_open", "staged")     # testo ostile attorno ai gestori
_ID_VIEWS = ("users", "rows", "grouped", "drawer_open", "drawer_closed")           # con un id in un gestore

_CASES = {}
for _view, _build in _VIEWS.items():
    _CASES[f"{_view}|real"] = _build(_Values("real"))
for _view in _TEXT_VIEWS:
    for _variant in _VARIANTS:
        _CASES[f"{_view}|text|{_variant}"] = _VIEWS[_view](_Values("text", _variant))
for _view in _ID_VIEWS:
    for _variant in _VARIANTS:
        _CASES[f"{_view}|id|{_variant}"] = _VIEWS[_view](_Values("id", _variant))



def _absent_case(view, *keys):
    case = _VIEWS[view](_Values("real", absent=keys))
    return _Case(_clean(case.scenario), case.sink, case.expected)


# Campi che mancano dai dati: la chiave non c'è (`undefined` in JS) o l'elemento della lista è null.
_CASES["clients|absent_name"] = _absent_case("clients", "client")
_CASES["clients|null_entries"] = _absent_case("clients", "target", "watch")
_CASES["drawer_open|absent_domain"] = _absent_case("drawer_open", "domain")
_CASES["drawer_open|absent_client"] = _absent_case("drawer_open", "client")
_CASES["users|absent_username"] = _absent_case("users", "user_active", "user_inactive")

# Valori ostili in attributi che non sono gestori: marcatori inerti (un elemento con un id, nessun codice).
_OPTION_MARK = '3"><b id=x37-option>'
_TYPE_MARK = '"><b id=x37-type>'
_FORGED_ASSIGNABLE = [{"id": _OPTION_MARK, "username": "bob"}, {"id": 9, "username": "carol"}]
_CASES["option_value"] = _Case(_drawer_case(_Values("real"), assignable=_FORGED_ASSIGNABLE), "drawer", [])
_CASES["staged_type"] = _Case(
    {"call": "renderStaged", "globals": {"OB_DOMAINS": [{"domain": _DOMAIN, "type": _TYPE_MARK}]}}, "ob-staged", [])
_CASES["option_value_real"] = _Case(_drawer_case(_Values("real"), assignee_id=3), "drawer", [])


# ── Lettura dell'HTML come lo legge un browser ────────────────────────────────────────────────

_VOID = frozenset({"meta", "input", "br", "hr", "img", "link"})


class _Node:
    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent, self.children = tag, dict(attrs), parent, []

    def __repr__(self):
        return f"<{self.tag} {self.attrs}>"

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


class _Handler:
    """Un attributo `on*` reso: il testo che il motore JS riceve, dopo la decodifica delle entità."""

    def __init__(self, node, event, code):
        self.tag, self.event, self.code = node.tag, event, code
        cells = [c for c in node.children if not isinstance(c, str) and c.tag == "td"] if node.tag == "tr" else []
        if node.tag == "select":
            self.label = "|".join(o.text() for o in node.elements("option"))
        else:
            self.label = (cells[0] if cells else node).text()[:48]
        self.calls, self.error = None, None

    def __repr__(self):
        return self.where()

    def where(self):
        return f"<{self.tag}> «{self.label}» ({self.event})"


def _handlers(markup):
    return [_Handler(node, name, value or "")
            for node in _parse(markup).descendants() for name, value in node.attrs.items() if name.startswith("on")]


# ── Esecuzione: la pagina in node, poi i gestori in un contesto per ciascuno ──────────────────

def _page_scripts():
    """[(testo dello script, riga della sua prima riga)] per ogni blocco `<script>` della pagina."""
    page = _PAGE.read_text("utf-8")
    return [(m.group(1), page.count("\n", 0, m.start(1)) + 1)
            for m in re.finditer(r"<script(?:\s[^>]*)?>([\s\S]*?)</script>", page)]


def _page_functions():
    names = set()
    for code, _ in _page_scripts():
        names.update(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", code))
    return sorted(names)


def _node():
    node = shutil.which("node")
    if node is None:
        # Senza questa richiesta esplicita un runner senza node resterebbe verde senza aver eseguito la resa.
        if os.environ.get("DOMAINSENTRY_REQUIRE_NODE") == "1":
            pytest.fail("node non disponibile ma DOMAINSENTRY_REQUIRE_NODE=1 lo richiede: la resa della dashboard "
                        "non è stata eseguita", pytrace=False)
        pytest.skip("node non disponibile: la resa della dashboard non si può eseguire")
    return node


def _run_node(script, payload, *flags):
    try:
        proc = subprocess.run([_node(), str(script), *flags], input=json.dumps(payload), capture_output=True,
                              encoding="utf-8", timeout=_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{script.name} non ha terminato entro {_TIMEOUT_S} s", pytrace=False)
    if proc.returncode != 0:
        pytest.fail(f"{script.name} è terminato con codice {proc.returncode}: {proc.stderr[-800:]}", pytrace=False)
    return json.loads(proc.stdout)


# Gestori di controllo: provano che il valutatore vede ciò che deve vedere. Se non lo vedesse, ogni test
# «nessuna uscita dalla stringa» sarebbe verde per il motivo sbagliato.
_REACH_THE_HOST = "constructor('return typeof process')()"
# Ogni tentativo parte da un oggetto del contesto e prova a salire al `Function` del processo che valuta; se ci
# riuscisse, la sonda riceverebbe "object" (`typeof process`). Gli ultimi due nomi sono quelli con cui il
# valutatore passa i dati al contesto.
_CONTEXT_ESCAPES = {
    "constructor": f"constructor.{_REACH_THE_HOST}",
    "global_object": f"globalThis.constructor.{_REACH_THE_HOST}",
    "names_list": f"__names.constructor.{_REACH_THE_HOST}",
    "names_text": f"__names_json.constructor.{_REACH_THE_HOST}",
    "this_value": f"__thisValue.constructor.{_REACH_THE_HOST}",
    "this_object": f"this.constructor.{_REACH_THE_HOST}",
    "event_object": f"event.constructor.{_REACH_THE_HOST}",
    "recorded_calls": f"__calls.{_REACH_THE_HOST}",
    "compiled_handler": f"__handler.{_REACH_THE_HOST}",
    "stub_function": f"scanClient.{_REACH_THE_HOST}",
    "error_object": f"(() => {{ try {{ null.x; }} catch (e) {{ return e.constructor.{_REACH_THE_HOST}; }} }})()",
}
_CONTROLS = {
    **{f"escape_{key}": f"probe37({code})" for key, code in _CONTEXT_ESCAPES.items()},
    "control_host_globals": "probe37(typeof process, typeof require, typeof Buffer)",
    "control_probe": "scanClient('a');probe37('k');//')",
    "control_syntax": "scanClient('a\nb')",
    "control_unknown": "ignoreMe(1)",
    "control_eval": "eval('probe37(1)')",
    "control_brace": "scanClient(1)}); probe37('k'); (function(){",
    "control_ok": "scanClient('a')",
}


class _Rendered:
    def __init__(self, result, handlers, evaluated):
        self.result, self.handlers, self.evaluated = result, handlers, evaluated

    def markup(self, name):
        load_error = self.result["load_error"]
        assert load_error is None, f"lo script della dashboard non si carica: {load_error}"
        scenario = self.result["scenarios"][name]
        assert scenario["error"] is None, f"'{name}': la funzione della pagina ha sollevato: {scenario['error']}"
        sink = _CASES[name].sink
        assert sink in scenario["sinks"], f"'{name}': la pagina non ha scritto in #{sink}"
        return scenario["sinks"][sink]

    def handlers_of(self, name):
        self.markup(name)
        return self.handlers[name]


@pytest.fixture(scope="module")
def rendered():
    """Un processo node per la resa di tutte le viste, uno per i gestori di tutte le viste."""
    result = _run_node(_RENDER, {"scenarios": [{"name": name, **case.scenario} for name, case in _CASES.items()]},
                       "--sinks")
    handlers, jobs = {}, []
    for name, case in _CASES.items():
        scenario = result["scenarios"].get(name)
        written = scenario is not None and not scenario["error"] and case.sink in scenario["sinks"]
        if result["load_error"] is not None or not written:
            handlers[name] = []
            continue
        handlers[name] = _handlers(scenario["sinks"][case.sink])
        jobs += [{"id": f"{name}#{i}", "code": h.code} for i, h in enumerate(handlers[name])]
    jobs += [{"id": key, "code": code} for key, code in _CONTROLS.items()]
    evaluated = _run_node(_EVALUATOR, {"functions": _page_functions(), "this_value": _THIS_VALUE, "handlers": jobs})
    for name, found in handlers.items():
        for i, handler in enumerate(found):
            outcome = evaluated["results"][f"{name}#{i}"]
            handler.calls, handler.error = outcome["calls"], outcome["error"]
    return _Rendered(result, handlers, evaluated["results"])


# ── Confronto fra ciò che un gestore ha chiamato e ciò che doveva chiamare ────────────────────

def _js_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string" if isinstance(value, str) else type(value).__name__


def _show_expected(exp):
    args = ", ".join("<qualunque>" if a is _ANY else json.dumps(a, ensure_ascii=False) for a in exp.args)
    return f"{exp.fn}({args})"


def _show_calls(calls):
    def argument(a):
        return a["type"] if a["type"] in ("object", "undefined", "function") else json.dumps(a["value"], ensure_ascii=False)

    if not calls:
        return "nessuna chiamata"
    return "; ".join(f"{c['fn']}({', '.join(argument(a) for a in c['args'])})" for c in calls)


def _arguments_match(call, exp):
    if len(call["args"]) != len(exp.args):
        return False
    return all(e is _ANY or (a["type"] == _js_type(e) and a["value"] == e)
               for a, e in zip(call["args"], exp.args, strict=True))


def _problem(handler, exp):
    """Perché `handler` non fa ciò che `exp` prevede, o None."""
    calls = handler.calls
    if any(c["fn"] == _PROBE for c in calls):
        return "il dato ha chiuso la stringa del gestore: è stata eseguita la sonda probe37"
    if handler.error:
        return f"il gestore non si esegue: {handler.error}"
    if handler.event != exp.event:
        return f"l'evento è {handler.event}, atteso {exp.event}"
    if [c["fn"] for c in calls] != [exp.fn]:
        return "chiama una funzione diversa da quella prevista o più di una"
    if not _arguments_match(calls[0], exp):
        return "gli argomenti non sono quelli originali (stesso valore e stesso tipo)"
    return None


def _assert_handlers(handlers, expected):
    probing = [h.where() for h in handlers if any(c["fn"] == _PROBE for c in h.calls or [])]
    assert len(handlers) == len(expected), (
        f"gestori resi: {len(handlers)}, attesi: {len(expected)}. Resi: {[h.where() for h in handlers]}"
        + (f". Eseguono la sonda probe37: {probing}" if probing else ""))
    lines = []
    for handler, exp in zip(handlers, expected, strict=True):
        problem = _problem(handler, exp)
        if problem:
            lines.append(f"  {handler.where()}: {problem}\n      atteso   {_show_expected(exp)}\n"
                         f"      ottenuto {_show_calls(handler.calls)}\n      testo del gestore: {handler.code!r}")
    assert not lines, f"{len(lines)} gestori su {len(handlers)} non fanno ciò che devono:\n" + "\n".join(lines)


# ── Controlli del valutatore ──────────────────────────────────────────────────────────────────

class TestTheEvaluatorSeesWhatItShouldSee:
    """Il valutatore riconosce una chiusura di stringa, un errore di sintassi, una funzione sconosciuta."""

    def test_it_reports_the_probe_when_a_value_closes_the_string(self, rendered):
        calls = [c["fn"] for c in rendered.evaluated["control_probe"]["calls"]]

        assert calls == ["scanClient", _PROBE]

    def test_it_reports_a_syntax_error(self, rendered):
        outcome = rendered.evaluated["control_syntax"]

        assert outcome["calls"] == [] and "SyntaxError" in outcome["error"]

    def test_it_reports_a_function_the_page_does_not_declare(self, rendered):
        outcome = rendered.evaluated["control_unknown"]

        assert outcome["calls"] == [] and "ReferenceError" in outcome["error"]

    def test_it_refuses_code_generation_from_strings(self, rendered):
        outcome = rendered.evaluated["control_eval"]

        assert outcome["calls"] == [] and "EvalError" in outcome["error"]

    def test_a_stray_brace_does_not_leave_the_body_of_the_handler(self, rendered):
        outcome = rendered.evaluated["control_brace"]

        assert outcome["calls"] == [] and "SyntaxError" in outcome["error"]

    @pytest.mark.parametrize("attempt", list(_CONTEXT_ESCAPES))
    def test_an_attempt_to_reach_the_host_from_a_handler_fails(self, rendered, attempt):
        outcome = rendered.evaluated[f"escape_{attempt}"]

        assert outcome["calls"] == [], f"{attempt}: il gestore ha raggiunto l'host: {outcome['calls']}"
        assert outcome["error"], f"{attempt}: nessun errore e nessuna chiamata"

    def test_the_handler_context_has_no_host_globals(self, rendered):
        outcome = rendered.evaluated["control_host_globals"]

        assert outcome["error"] is None
        assert [a["value"] for a in outcome["calls"][0]["args"]] == ["undefined", "undefined", "undefined"]

    def test_it_records_the_arguments_with_their_type(self, rendered):
        outcome = rendered.evaluated["control_ok"]

        assert outcome["error"] is None
        assert outcome["calls"] == [{"fn": "scanClient", "args": [{"type": "string", "value": "a"}]}]

    def test_every_function_the_views_are_expected_to_call_is_declared_by_the_page(self):
        declared = set(_page_functions())
        wanted = {e.fn for case in _CASES.values() for e in case.expected}

        assert wanted <= declared, f"funzioni attese e non dichiarate dalla pagina: {sorted(wanted - declared)}"


# ── Il comportamento: ogni gestore chiama solo la funzione prevista, con gli argomenti originali ──

class TestAHostileTextFieldCannotChangeWhatAHandlerCalls:
    @pytest.mark.parametrize("variant", list(_VARIANTS))
    @pytest.mark.parametrize("view", _TEXT_VIEWS)
    def test_the_handlers_of_the_view_call_the_intended_function_with_the_original_strings(
            self, rendered, view, variant):
        name = f"{view}|text|{variant}"

        _assert_handlers(rendered.handlers_of(name), _CASES[name].expected)


class TestAForgedIdentifierCannotChangeWhatAHandlerCalls:
    @pytest.mark.parametrize("variant", list(_VARIANTS))
    @pytest.mark.parametrize("view", _ID_VIEWS)
    def test_the_handlers_of_the_view_call_the_intended_function_once(self, rendered, view, variant):
        name = f"{view}|id|{variant}"

        _assert_handlers(rendered.handlers_of(name), _CASES[name].expected)


class TestHandlersKeepTheTypeOfTheirArguments:
    @pytest.mark.parametrize("view", list(_VIEWS))
    def test_with_real_values_every_handler_gets_the_original_arguments(self, rendered, view):
        name = f"{view}|real"

        _assert_handlers(rendered.handlers_of(name), _CASES[name].expected)

    @staticmethod
    def _types(rendered, name, fn):
        return [[a["type"] for a in call["args"]]
                for h in rendered.handlers_of(name) for call in h.calls if call["fn"] == fn]

    @pytest.mark.parametrize("view", ["rows", "grouped"])
    def test_the_case_id_reaches_open_case_as_a_number(self, rendered, view):
        found = self._types(rendered, f"{view}|real", "openCase")

        assert found and all(t == ["number"] for t in found), f"{view}: tipi degli argomenti di openCase: {found}"

    def test_toggle_active_gets_a_number_and_a_boolean(self, rendered):
        assert self._types(rendered, "users|real", "uToggleActive") == [["number", "boolean"]] * 2

    def test_the_new_state_of_toggle_active_is_the_opposite_of_the_current_one(self, rendered):
        values = [c["args"][1]["value"] for h in rendered.handlers_of("users|real") for c in h.calls
                  if c["fn"] == "uToggleActive"]

        assert values == [False, True]          # utente attivo -> si disattiva; utente disattivo -> si attiva

    def test_the_role_change_gets_the_numeric_id_and_the_selected_role(self, rendered):
        assert self._types(rendered, "users|real", "uSetRole") == [["number", "string"]] * 3

    def test_the_staged_index_reaches_remove_as_a_number(self, rendered):
        assert self._types(rendered, "staged|real", "obRemove") == [["number"]] * 3

    @pytest.mark.parametrize("fn", ["doAssign", "takeCase", "doStatus", "doSeverity", "doSeverityAuto", "doWhitelist",
                                    "doNote"])
    def test_a_drawer_action_gets_the_numeric_case_id(self, rendered, fn):
        types = self._types(rendered, "drawer_open|real", fn)

        assert types == [["number"]]

    def test_the_proposal_buttons_get_the_numeric_id_and_the_verdict(self, rendered):
        assert self._types(rendered, "drawer_open|real", "resolveProposal") == [["number", "string"]] * 2

    def test_reopen_gets_the_numeric_case_id(self, rendered):
        assert self._types(rendered, "drawer_closed|real", "reopenCase") == [["number"]]

    @pytest.mark.parametrize(("view", "fn", "types"), [
        ("clients", "removeDomainFromClient", ["string", "string"]),
        ("clients", "scanClient", ["string"]),
        ("clients", "openAddDomainFor", ["string"]),
        ("clients", "downloadReport", ["string", "string"]),
        ("users", "uResetPw", ["number", "string"]),
        ("grouped", "toggleClientGroup", ["string"]),
        ("drawer_open", "promoteDomain", ["string", "string"])])
    def test_names_and_domains_reach_their_function_as_strings(self, rendered, view, fn, types):
        found = self._types(rendered, f"{view}|real", fn)

        assert found and all(t == types for t in found), f"{view}: tipi degli argomenti di {fn}: {found}"


# ── Un campo assente arriva al gestore come null ──────────────────────────────────────────────
#
# Un dato può mancare (`undefined`: il campo non c'è; `null`: il feed lo manda vuoto). Il gestore deve restare
# un'espressione valida e chiamare la sua funzione una volta, con `null` al posto del valore assente e gli
# altri argomenti invariati. Nei dati di una lista, che arrivano da JSON, l'assenza si presenta come `null`.

class TestAnAbsentValueReachesAHandlerAsNull:
    def test_a_client_without_a_name_gets_null_in_every_button(self, rendered):
        name = "clients|absent_name"

        _assert_handlers(rendered.handlers_of(name), _CASES[name].expected)

    def test_a_missing_target_or_watchlist_entry_gets_null_and_keeps_the_client(self, rendered):
        name = "clients|null_entries"

        _assert_handlers(rendered.handlers_of(name), _CASES[name].expected)

    def test_promote_gets_null_for_a_case_without_a_domain(self, rendered):
        name = "drawer_open|absent_domain"

        _assert_handlers(rendered.handlers_of(name), _CASES[name].expected)

    def test_promote_gets_null_for_a_case_without_a_client(self, rendered):
        name = "drawer_open|absent_client"

        _assert_handlers(rendered.handlers_of(name), _CASES[name].expected)

    def test_reset_password_gets_null_for_a_user_without_a_name(self, rendered):
        name = "users|absent_username"

        _assert_handlers(rendered.handlers_of(name), _CASES[name].expected)


# ── L'helper degli argomenti, chiamato direttamente nella pagina ──────────────────────────────

_HELPER = "jsArg"
_NOT_IN_JSON = ("undefined", "function", "symbol")           # JSON.stringify non li rappresenta
_JSON_VALUES = ["acme", "", "a'b", 'a"b', "a\\b", "a\nb", "</script><b id=x>", "&#39;", "\u2028x\u2029", "è€",
                0, 42, -3, 1.5, True, False]
_JSON_IDS = [f"{type(v).__name__}-{i}" for i, v in enumerate(_JSON_VALUES)]


_NOT_A_LITERAL = object()


def _read_literal(code):
    """Il valore del letterale JSON `code`, o `_NOT_A_LITERAL` se non lo è (per esempio il testo vuoto)."""
    try:
        return json.loads(code)
    except ValueError:
        return _NOT_A_LITERAL


class _Helper:
    def __init__(self, out):
        self.out = out

    def code(self, key):
        """Il testo che l'helper restituisce per `key`, letto come lo legge il motore JS: scritto fra gli apici
        di un attributo `onclick`, decodificato dal parser HTML, tolta la chiamata che lo contiene."""
        assert self.out["load_error"] is None, f"lo script della dashboard non si carica: {self.out['load_error']}"
        outcome = self.out["results"][key]
        assert outcome["error"] is None, f"{_HELPER}({key}) ha sollevato: {outcome['error']}"
        assert outcome["type"] == "string", f"{_HELPER}({key}) restituisce {outcome['type']}, atteso string"
        (node,) = _parse(f'<b onclick="f({outcome["value"]})">').elements("b")
        match = re.fullmatch(r"f\((.*)\)", node.attrs["onclick"], re.S)
        assert match, f"{_HELPER}({key}) esce dall'attributo: {node.attrs}"
        return match.group(1)


@pytest.fixture(scope="module")
def helper():
    """Un processo node: l'helper della pagina su `undefined`, una funzione, un simbolo, `null` e i valori JSON."""
    values = [{"id": kind, "kind": kind} for kind in (*_NOT_IN_JSON, "null")]
    values += [{"id": f"json-{i}", "kind": "json", "json": v} for i, v in enumerate(_JSON_VALUES)]
    return _Helper(_run_node(_EVALUATOR, {"values": values}, "--helper", _HELPER))


class TestTheArgumentHelperAlwaysWritesAValidExpression:
    @pytest.mark.parametrize("kind", _NOT_IN_JSON)
    def test_a_value_json_cannot_represent_becomes_null(self, helper, kind):
        code = helper.code(kind)

        assert _read_literal(code) is None, f"{_HELPER}({kind}) scrive {code!r}, atteso un letterale null"

    def test_null_stays_null(self, helper):
        code = helper.code("null")

        assert _read_literal(code) is None, f"{_HELPER}(null) scrive {code!r}, atteso un letterale null"

    @pytest.mark.parametrize("index", range(len(_JSON_VALUES)), ids=_JSON_IDS)
    def test_a_string_number_or_boolean_keeps_its_value_and_type_inside_an_attribute(self, helper, index):
        value = _JSON_VALUES[index]
        code = helper.code(f"json-{index}")
        parsed = _read_literal(code)

        assert parsed == value and type(parsed) is type(value), f"{_HELPER}({value!r}) scrive {code!r}"


# ── La resa dei valori veri non cambia ────────────────────────────────────────────────────────

class TestRenderedTextIsUnchanged:
    """Il testo visibile degli elementi che portano un gestore, nell'ordine del documento."""

    @staticmethod
    def _labels(rendered, name):
        return [h.label for h in rendered.handlers_of(name)]

    def test_client_card_buttons(self, rendered):
        assert self._labels(rendered, "clients|real") == ["×", "×", "▷ Scan", "+ Add domain", "↓ JSON", "↓ Report"]

    def test_user_row_controls(self, rendered):
        assert self._labels(rendered, "users|real") == [
            "viewer|analyst|admin",
            "viewer|analyst|admin", "Disable", "Reset password",
            "viewer|analyst|admin", "Enable", "Reset password"]

    def test_user_rows_show_name_role_and_status(self, rendered):
        shown = []
        for row in _parse(rendered.markup("users|real")).elements("tr"):
            name, role, status = [c for c in row.children if not isinstance(c, str)][:3]
            (select,) = role.elements("select")
            shown.append((name.text(), [o.attrs["value"] for o in select.elements("option") if "selected" in o.attrs],
                          "disabled" in select.attrs, status.text()))

        assert shown == [("alice (you)", ["admin"], True, "active"), ("bob", ["analyst"], False, "active"),
                         ("carol", ["viewer"], False, "disabled")]

    def test_case_rows(self, rendered):
        assert self._labels(rendered, "rows|real") == [_DOMAIN, f"login.{_DOMAIN}"]

    def test_case_row_cells(self, rendered):
        rows = _parse(rendered.markup("rows|real")).elements("tr")

        assert [[td.text() for td in r.children if not isinstance(td, str)] for r in rows] == [
            [_DOMAIN, "acme", "typosquat", "HIGH", "New", _DASH, _DASH],
            [f"login.{_DOMAIN}", "acme", "typosquat", "LOW", "New", _DASH, _DASH]]

    def test_group_headers_and_rows(self, rendered):
        assert self._labels(rendered, "grouped|real") == [
            "▾ zeta 1 case 1 critical", f"shop.{_DOMAIN}",
            "▾ acme 2 cases 1 high1 low", _DOMAIN, f"login.{_DOMAIN}"]

    def test_drawer_buttons_of_an_open_case(self, rendered):
        assert self._labels(rendered, "drawer_open|real") == [
            "×", "Overview", "Intelligence", "Raw JSON",
            "Accept CRITICAL", "Keep MEDIUM", "Assign", "Take", "Update", "Set severity", "↺ Back to auto",
            "Whitelist + close FP", "↑ Promote to monitored target", "Add note", "⧉ Copy JSON"]

    def test_drawer_buttons_of_a_closed_case(self, rendered):
        assert self._labels(rendered, "drawer_closed|real") == [
            "×", "Overview", "Intelligence", "Raw JSON", "↺ Reopen case", "Add note", "⧉ Copy JSON"]

    def test_the_assignee_options_keep_their_value_text_and_selection(self, rendered):
        select = _parse(rendered.markup("option_value_real")).elements("select")
        (assignee,) = [s for s in select if s.attrs.get("id") == "a-assignee"]

        assert [(o.attrs.get("value"), o.text(), "selected" in o.attrs) for o in assignee.elements("option")] == [
            ("", "— unassigned —", False), ("3", "bob", True), ("9", "carol", False)]

    def test_staged_chips(self, rendered):
        chips = _parse(rendered.markup("staged|real")).elements("div", "ob-chip")

        assert [(c.elements("span", "d")[0].text(), c.elements("span", "t")[0].text(),
                 c.elements("span", "t")[0].attrs.get("class"), c.elements("button")[0].text()) for c in chips] == [
            (_DOMAIN, "target", "t target", "×"),
            (f"login.{_DOMAIN}", "watchlist", "t watchlist", "×"),
            (f"shop.{_DOMAIN}", "target", "t target", "×")]


class TestAttributeAndTextValuesAreEscaped:
    def test_an_assignee_id_cannot_leave_the_option_value_attribute(self, rendered):
        tree = _parse(rendered.markup("option_value"))
        injected = [n for n in tree.descendants() if n.attrs.get("id") == "x37-option"]
        (assignee,) = [s for s in tree.elements("select") if s.attrs.get("id") == "a-assignee"]
        values = [o.attrs.get("value") for o in assignee.elements("option")]

        assert not injected, (f"<option value=…> non passa dall'escape: nell'HTML nasce l'elemento "
                              f"<{injected[0].tag} id=x37-option> invece del valore {_OPTION_MARK!r}")
        assert values == ["", _OPTION_MARK, "9"], f"valori delle option: {values}"

    def test_a_staged_type_is_shown_as_text_and_stays_inside_the_class_attribute(self, rendered):
        tree = _parse(rendered.markup("staged_type"))
        injected = [n for n in tree.descendants() if n.attrs.get("id") == "x37-type"]
        chips = tree.elements("div", "ob-chip")

        assert not injected, (f"il tipo del dominio staged non passa dall'escape: nell'HTML nasce l'elemento "
                              f"<{injected[0].tag} id=x37-type> invece del testo {_TYPE_MARK!r}")
        assert [[t.text() for t in c.elements("span", "t")] for c in chips] == [[_TYPE_MARK]]


# ── Il sorgente: lessico di JS e lettura dei template literal ─────────────────────────────────
#
# Una guardia sul testo deve sopravvivere ai commenti, agli a capo dentro un attributo e ai template annidati
# in un `${…}`: nessuna funzione si ritaglia cercando una `}` in colonna 0. Il lessico qui sotto percorre lo
# script una volta, salta commenti e regex, e restituisce ogni stringa e ogni template come lista di pezzi
# (testo fisso, espressione). Un automa di HTML (testo, tag, nome di attributo, valore fra apici o nudo) segue
# i pezzi e dice in che contesto cade ogni `${…}`.

_REGEX_AFTER_WORD = frozenset({"return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else",
                               "do", "yield", "await"})
_REGEX_AFTER_PUNCT = "(,=:[!&|?{};>"
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def _cook(raw):
    """Il valore di una stringa JS dal suo testo grezzo (escape comuni; continuazione di riga tolta)."""
    def one(m):
        s = m.group(1)
        if s[0] == "u" and len(s) > 1:
            return chr(int(s[2:-1] if s[1] == "{" else s[1:], 16))
        if s[0] == "x" and len(s) > 1:
            return chr(int(s[1:], 16))
        if s == "\n":
            return ""
        return _ESCAPES.get(s, s)
    return re.sub(r"\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[\s\S])", one, raw)


class _Literal(NamedTuple):
    offset: int
    chunks: list            # [("s", testo fisso, offset)] e [("e", espressione, offset)]


class _JsScanner:
    def __init__(self, src):
        self.src, self.n, self.literals = src, len(src), []

    def run(self):
        self._code(0, False)
        return sorted(self.literals, key=lambda lit: lit.offset)

    def _code(self, i, in_expr):
        src, n = self.src, self.n
        depth, kind, last = 0, None, ""
        while i < n:
            c, nxt = src[i], src[i + 1:i + 2]
            if c == "/" and nxt == "/":
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            if c == "/" and nxt == "*":
                j = src.find("*/", i + 2)
                if j < 0:
                    raise ValueError(f"commento non chiuso a {i}")
                i = j + 2
                continue
            if c in "'\"":
                i, kind, last = self._string(i), "str", c
                continue
            if c == "`":
                i, kind, last = self._template(i), "str", c
                continue
            if c == "/" and (kind is None or (kind == "punct" and last in _REGEX_AFTER_PUNCT)
                             or (kind == "word" and last in _REGEX_AFTER_WORD)):
                i, in_class = i + 1, False
                while i < n and src[i] != "\n":
                    if src[i] == "\\":
                        i += 2
                        continue
                    if src[i] == "[":
                        in_class = True
                    elif src[i] == "]":
                        in_class = False
                    elif src[i] == "/" and not in_class:
                        break
                    i += 1
                if i >= n or src[i] != "/":
                    raise ValueError("regex non chiusa")
                i, kind, last = i + 1, "regex", "/"
                continue
            m = re.compile(r"[\w$]+").match(src, i)
            if m:
                i, kind, last = m.end(), "word", m.group(0)
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                if in_expr and depth == 0:
                    return i
                depth -= 1
            if not c.isspace():
                kind, last = "punct", c
            i += 1
        if in_expr:
            raise ValueError("espressione `${…}` non chiusa")
        return i

    def _string(self, i):
        src, n, quote = self.src, self.n, self.src[i]
        j = i + 1
        while j < n and src[j] != quote:
            if src[j] == "\n":
                raise ValueError(f"stringa non chiusa a {i}")
            j += 2 if src[j] == "\\" else 1
        if j >= n:
            raise ValueError(f"stringa non chiusa a {i}")
        self.literals.append(_Literal(i, [("s", _cook(src[i + 1:j]), i + 1)]))
        return j + 1

    def _template(self, i):
        src, n = self.src, self.n
        chunks, buf, start, j = [], [], i + 1, i + 1
        while j < n:
            c = src[j]
            if c == "\\":
                buf.append(src[j:j + 2])
                j += 2
            elif c == "`":
                chunks.append(("s", _cook("".join(buf)), start))
                self.literals.append(_Literal(i, chunks))
                return j + 1
            elif c == "$" and src[j + 1:j + 2] == "{":
                chunks.append(("s", _cook("".join(buf)), start))
                end = self._code(j + 2, True)
                chunks.append(("e", src[j + 2:end].strip(), j + 2))
                buf, start, j = [], end + 1, end + 1
            else:
                buf.append(c)
                j += 1
        raise ValueError(f"template literal non chiuso a {i}")


class _Site(NamedTuple):
    line: int
    state: str              # "text" | "tag" | "value" | "open"
    tag: str
    attr: str
    expr: str               # l'espressione di un `${…}`; per "open", il testo fisso in cui il valore resta aperto
    literal: _Literal
    quote: str              # l'apice che racchiude il valore dell'attributo; vuoto se il valore è nudo


_NAME = re.compile(r"[^\s=>/\"']+")
_TAG = re.compile(r"<([A-Za-z][\w:-]*)")
# Un `on<nome>=` che non sta in un tag riconosciuto: un frammento di attributo (`' onclick="f(' + x + ')"'`, un helper
# che restituisce ` onclick=…`, un template annidato in posizione di tag). Preceduto da spazio, apice o inizio del
# testo fisso, così `?only=` e `&online=` di un URL non lo attivano.
_ORPHAN_HANDLER = re.compile(r"(?<![^\s\"'])(on[a-z]+)\s*=(?!=)")


def _contexts(literal):
    """Per ogni `${…}` del letterale: (stato, tag, attributo, espressione, offset, apice). Se il letterale finisce
    dentro il valore di un attributo, un ultimo elemento con stato «open». Un attributo `on*` fuori da ogni tag
    del letterale ha `tag` vuoto."""
    state, tag, attr, quote, orphan = "text", "", "", "", False
    last = literal.offset
    for kind, payload, offset in literal.chunks:
        last = offset
        if kind == "e":
            if state == "beforevalue":
                state, quote = "value", ""
            yield (state if state in ("text", "value") else "tag"), tag, attr, payload, offset, quote
            continue
        s, i = payload, 0
        while i < len(s):
            if state == "text":
                in_tag, on_attr = _TAG.search(s, i), _ORPHAN_HANDLER.search(s, i)
                if on_attr and (not in_tag or on_attr.start() < in_tag.start()):
                    tag, attr, state, i, orphan = "", on_attr.group(1).lower(), "beforevalue", on_attr.end(), True
                elif in_tag:
                    tag, attr, state, i, orphan = in_tag.group(1).lower(), "", "tag", in_tag.end(), False
                else:
                    break
            elif state == "tag":
                while i < len(s) and (s[i].isspace() or s[i] == "/"):
                    i += 1
                if i >= len(s):
                    break
                if s[i] == ">":
                    state, attr, i = "text", "", i + 1
                elif s[i] in "\"'":
                    i += 1
                else:
                    m = _NAME.match(s, i)
                    attr, state, i = m.group(0).lower(), "afterattr", m.end()
            elif state == "afterattr":
                while i < len(s) and s[i].isspace():
                    i += 1
                if i >= len(s):
                    break
                if s[i] == "=":
                    state, i = "beforevalue", i + 1
                else:
                    state = "tag"
            elif state == "beforevalue":
                while i < len(s) and s[i].isspace():
                    i += 1
                if i >= len(s):
                    break
                if s[i] in "\"'":
                    state, quote, i = "value", s[i], i + 1
                elif s[i] == ">":
                    state, i = "text", i + 1
                else:
                    state, quote = "value", ""
            else:                           # value
                if quote:
                    j = s.find(quote, i)
                    if j < 0:
                        i = len(s)
                        break
                    i = j + 1
                else:
                    m = re.compile(r"[\s>]").search(s, i)
                    if not m:
                        i = len(s)
                        break
                    i = m.start()
                state, attr = ("text", "") if orphan else ("tag", "")
                tag, orphan = ("", False) if orphan else (tag, False)
    if state == "value":
        yield "open", tag, attr, literal.chunks[-1][1], last, quote


def _sites(js, base_line=1):
    """Ogni interpolazione di ogni letterale di `js` con il suo contesto HTML e il numero di riga."""
    starts = [0] + [m.end() for m in re.finditer(r"\n", js)]
    for literal in _JsScanner(js).run():
        for state, tag, attr, expr, offset, quote in _contexts(literal):
            yield _Site(base_line + bisect.bisect_right(starts, offset) - 1, state, tag, attr, expr, literal, quote)


def _is_single_call(expr, name):
    """`expr` è esattamente una chiamata `name(…)`, non `name(…) + altro`."""
    expr = expr.strip()
    if not expr.startswith(name + "("):
        return False
    depth, i, n = 0, len(name), len(expr)
    while i < n:
        c = expr[i]
        if c in "'\"`":
            i += 1
            while i < n and expr[i] != c:
                i += 2 if expr[i] == "\\" else 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i == n - 1
        i += 1
    return False


# Le `<option value>` dei dati passano da `esc(`; queste due espressioni sono l'elemento di un array
# letterale (`["viewer", "analyst", "admin"]`, `["LOW", "MEDIUM", "HIGH", "CRITICAL"]`), cioè costanti.
_CONSTANT_OPTION_VALUES = frozenset({"x", "s"})


def _handler_violations(js, base_line=1):
    """Le interpolazioni di un attributo `on*` che la regola non ammette: solo `${jsArg(…)}`, solo in un valore
    racchiuso fra apici (un valore nudo si chiude al primo spazio, e `esc()` non protegge lo spazio), solo dentro
    il tag che lo apre (un frammento di attributo o una concatenazione sfugge a tutte e due le regole)."""
    out = []
    for site in _sites(js, base_line):
        if not site.attr.startswith("on"):
            continue
        where = f"riga {site.line}: l'attributo {site.attr}" + (f" di <{site.tag}>" if site.tag else "")
        if site.state == "open":
            out.append(f"{where} continua oltre la stringa che lo apre "
                       f"(gestore costruito per concatenazione: {site.expr[-40:]!r})")
        elif site.state != "value":
            continue
        elif not site.tag:
            out.append(f"{where} interpola ${{{site.expr}}} fuori da un tag riconosciuto (frammento di attributo o "
                       f"helper): il gestore si scrive per intero dentro il suo tag")
        elif not site.quote:
            out.append(f"{where} interpola ${{{site.expr}}} senza apici: un valore nudo si chiude al primo spazio")
        elif not _is_single_call(site.expr, "jsArg"):
            out.append(f"{where} interpola ${{{site.expr}}}, atteso un solo ${{jsArg(…)}}")
    return out


def _option_violations(js, base_line=1):
    return [f"riga {s.line}: <option value=\"${{{s.expr}}}\"> non passa da esc(…)"
            for s in _sites(js, base_line)
            if s.state == "value" and s.tag == "option" and s.attr == "value"
            and not _is_single_call(s.expr, "esc") and s.expr not in _CONSTANT_OPTION_VALUES]


def _chip_violations(js, base_line=1):
    """Nel template dei chip dell'onboarding (quello con la classe `ob-chip`) ogni interpolazione è `esc(…)` o
    `jsArg(…)`."""
    out = []
    for s in _sites(js, base_line):
        text = "".join(c[1] for c in s.literal.chunks if c[0] == "s")
        if "ob-chip" in text and s.state in ("text", "value", "tag") and s.expr and not (
                _is_single_call(s.expr, "esc") or _is_single_call(s.expr, "jsArg")):
            out.append(f"riga {s.line}: nel chip dell'onboarding ${{{s.expr}}} ({s.state}"
                       f"{' ' + s.attr if s.attr else ''}) non passa da esc(…)")
    return out


def _page_violations(check):
    out = []
    for script, line in _page_scripts():
        out += check(script, line)
    return out


class TestInlineHandlersNeverInterpolateRawData:
    def test_an_on_attribute_interpolates_only_js_arg(self):
        violations = _page_violations(_handler_violations)

        assert not violations, (f"{len(violations)} interpolazioni dentro un attributo on* non passano da "
                                f"${{jsArg(…)}}:\n  " + "\n  ".join(violations))

    def test_option_values_of_data_pass_through_esc(self):
        violations = _page_violations(_option_violations)

        assert not violations, "\n".join(violations)

    def test_the_onboarding_chip_escapes_every_interpolation(self):
        violations = _page_violations(_chip_violations)

        assert not violations, "\n".join(violations)

    def test_the_scanner_reads_every_script_block_to_the_end(self):
        blocks = _page_scripts()
        literals = [lit for script, _ in blocks for lit in _JsScanner(script).run()]
        interpolations = [c for lit in literals for c in lit.chunks if c[0] == "e"]

        assert blocks and len(interpolations) >= 100, (
            f"il lessico ha letto {len(literals)} letterali e {len(interpolations)} interpolazioni: troppo pochi per "
            f"essere lo script della pagina")


class TestTheStaticGuardSeesWhatItShouldSee:
    """Le regole della guardia su sorgenti piccoli: ciò che deve segnalare e ciò che non deve."""

    BAD_ESC = "const a = d => `<button onclick=\"f('${esc(d)}')\">go</button>`;"
    BAD_BARE = "const a = c => `<tr onclick=\"openCase(${c.id})\">`;"

    def test_it_flags_esc_inside_a_quoted_argument(self):
        assert len(_handler_violations(self.BAD_ESC)) == 1

    def test_it_flags_a_bare_identifier(self):
        assert len(_handler_violations(self.BAD_BARE)) == 1

    def test_it_accepts_js_arg(self):
        src = "const a = c => `<tr onclick=\"openCase(${jsArg(c.id)})\">`;"

        assert _handler_violations(src) == []

    def test_it_accepts_a_handler_without_interpolation(self):
        assert _handler_violations("const a = `<button onclick=\"closeDrawer()\">x</button>`;") == []

    def test_it_flags_js_arg_followed_by_something_else_in_the_same_expression(self):
        src = "const a = c => `<tr onclick=\"f(${jsArg(c.a) + c.b})\">`;"

        assert len(_handler_violations(src)) == 1

    def test_it_flags_every_interpolation_of_a_handler_not_just_the_first(self):
        src = "const a = c => `<tr onclick=\"f(${jsArg(c.a)}, ${c.b})\">`;"

        assert len(_handler_violations(src)) == 1

    def test_it_flags_a_bare_interpolation_in_an_unquoted_and_in_a_single_quoted_value(self):
        src = "const a = c => `<b onclick=f(${c.a})>` + `<i onclick='f(${c.b})'>`;"

        assert len(_handler_violations(src)) == 2

    def test_it_flags_an_unquoted_value_even_when_it_uses_js_arg(self):
        src = "const a = c => `<b onclick=f(${jsArg(c.a)})>x</b>`;"

        (violation,) = _handler_violations(src)
        assert "senza apici" in violation

    def test_it_accepts_js_arg_inside_single_or_double_quotes(self):
        src = "const a = c => `<b onclick='f(${jsArg(c.a)})'>x</b><i onclick=\"f(${jsArg(c.a)})\">y</i>`;"

        assert _handler_violations(src) == []

    def test_it_flags_an_attribute_fragment_in_tag_position(self):
        src = "const a = c => `<b ${c.on ? `onclick=\"f('${esc(c.x)}')\"` : \"\"}>x</b>`;"

        (violation,) = _handler_violations(src)
        assert "fuori da un tag" in violation

    def test_it_flags_an_attribute_fragment_even_when_it_uses_js_arg(self):
        src = "const a = c => `<b ${c.on ? `onclick=\"f(${jsArg(c.x)})\"` : \"\"}>x</b>`;"

        assert len(_handler_violations(src)) == 1

    def test_it_flags_a_helper_that_returns_an_attribute(self):
        src = "const attr = x => ` onclick=\"f('${esc(x)}')\"`;"

        (violation,) = _handler_violations(src)
        assert "fuori da un tag" in violation

    def test_it_flags_an_attribute_built_by_concatenation_outside_any_tag(self):
        src = "const attr = x => ' onclick=\"f(' + x + ')\"';"

        (violation,) = _handler_violations(src)
        assert "concatenazione" in violation

    def test_it_accepts_a_constant_attribute_fragment(self):
        src = "const attr = on => on ? ' onclick=\"closeDrawer()\"' : '';"

        assert _handler_violations(src) == []

    def test_it_is_not_triggered_by_a_url_parameter_that_starts_with_on(self):
        src = "const u = '/cases?only=' + x + '&online=' + y;\nconst v = `/cases?once=${z}&one=${w}`;"

        assert _handler_violations(src) == []

    def test_it_flags_the_same_technique_spelled_inline_because_the_helper_is_the_rule(self):
        src = "const a = c => `<tr onclick=\"f(${esc(JSON.stringify(c.a))})\">`;"

        assert len(_handler_violations(src)) == 1

    def test_it_flags_a_handler_assembled_by_concatenation(self):
        src = "const a = c => '<button onclick=\"f(' + c.name + ')\">';"

        (violation,) = _handler_violations(src)
        assert "concatenazione" in violation

    def test_it_ignores_a_handler_inside_a_comment(self):
        src = ("// onclick=\"f(${c.id})\" non e' codice\n"
               "/* `<b onclick=\"f(${c.id})\">` */\n"
               "const a = c => `<b onclick=\"f(${jsArg(c.id)})\">`;")

        assert _handler_violations(src) == []

    def test_it_reads_a_handler_split_over_several_lines(self):
        src = "const a = c => `<button\n   onclick=\n  \"f(\n    ${c.id}\n  )\"\n>x</button>`;"

        (violation,) = _handler_violations(src)
        assert violation.startswith("riga 4:")

    def test_it_is_not_misled_by_a_quote_inside_the_interpolation(self):
        src = 'const a = u => `<b onclick="g(${u.id}, ${u.active ? "false" : "true"})">${u.active ? "x" : "y"}</b>`;'

        assert len(_handler_violations(src)) == 2

    def test_it_reads_a_handler_inside_a_template_nested_in_an_interpolation(self):
        src = "const a = c => `<div>${c.on ? `<b onclick=\"f(${c.id})\">` : \"\"}</div>`;"

        assert len(_handler_violations(src)) == 1

    def test_it_is_not_misled_by_a_regex_with_quotes_or_a_url_in_a_string(self):
        src = ("const e = s => s.replace(/[&<>\"']/g, c => c);\n"
               "const u = 'http://example.org/a';\n"
               "const a = c => `<b onclick=\"f(${c.id})\">`;")

        (violation,) = _handler_violations(src)
        assert violation.startswith("riga 3:")

    def test_it_ignores_interpolations_outside_a_handler(self):
        src = "const a = c => `<b class=\"x ${c.a}\" onclick=\"f()\" title='${c.b}'>${c.t}</b>`;"

        assert _handler_violations(src) == []

    def test_it_flags_an_option_value_that_is_not_escaped(self):
        assert len(_option_violations("const a = u => `<option value=\"${u.id}\">${esc(u.name)}</option>`;")) == 1

    def test_it_accepts_an_escaped_option_value_and_a_constant_one(self):
        src = ("const a = u => `<option value=\"${esc(u.id)}\">x</option>`;\n"
               "const b = ['a'].map(x => `<option value=\"${x}\">${x}</option>`);")

        assert _option_violations(src) == []

    def test_it_flags_an_unescaped_value_in_the_onboarding_chip(self):
        src = "const a = d => `<div class=\"ob-chip\"><span class=\"t ${d.type}\">${esc(d.domain)}</span></div>`;"

        assert len(_chip_violations(src)) == 1

    def test_it_accepts_a_chip_that_escapes_everything(self):
        src = ("const a = (d, i) => `<div class=\"ob-chip\"><span class=\"t ${esc(d.type)}\">${esc(d.domain)}</span>"
               "<button onclick=\"obRemove(${jsArg(i)})\">x</button></div>`;")

        assert _chip_violations(src) == []

    def test_a_scanner_error_is_loud(self):
        with pytest.raises(ValueError):
            list(_sites("const a = `<b onclick=\"f(${x}\">;"))
