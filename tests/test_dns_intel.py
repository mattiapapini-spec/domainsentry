"""Tests for services/dns_intel.py — validazione di `dkim_selectors` su GET /dns (SEC-26).

Il parametro `dkim_selectors` dell'endpoint non autenticato `/dns` non aveva
`pattern` né `max_length`: ogni voce diventava `f"{sel}._domainkey.{domain}"`,
cioè il **primo carattere** dell'argomento-nome che `shared.utils.dig_query`
passa a `dig`. `dig` legge `@host` come server da interrogare e `-x` / `+opt`
come opzioni; inoltre il numero di selettori non aveva tetto (un processo `dig`
per voce, fino a `timeout + 10` s ciascuno) e il valore nessun limite di
lunghezza.

Comportamento atteso dopo il fix (BUG-REGISTER.md, «ASSEGNA · SEC-26 · criteri
fissati», C1-C5; la parte C6, difesa dentro `dig_query`, è in
`tests/test_utils.py::TestSEC26DigQueryNameGuard`):

* ogni selettore non vuoto rispetta la sintassi `selector` di RFC 6376 §3.5
  (label separate da `.`, ciascuna `[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?`, al
  massimo 63 caratteri, nessuna label vuota), altrimenti **422 e nessun `dig`**;
* al massimo 32 selettori non vuoti, valore lungo al massimo 2048 caratteri;
* la validazione è d'ingresso: vale anche con `full=false`;
* i selettori validi e il default (`DEFAULT_DKIM_SELECTORS`) producono gli stessi
  `dig` di prima.

Isolamento di rete: **nessun `dig` reale e nessuna rete**. `subprocess.run` viene
sostituito con uno spy che registra l'argv di ogni invocazione e restituisce un
`CompletedProcess` fisso; poiché `dig_query` risolve `subprocess` nel proprio
modulo (`shared.utils`), lo spy intercetta anche le chiamate che `dns_intel`
fa tramite `from shared.utils import dig_query`. «Zero `dig`» significa zero
invocazioni di `subprocess.run` per l'intera richiesta, non solo per lo stadio
DKIM: la validazione deve avvenire prima di qualunque query.
"""
import copy
import logging
import re
import subprocess

import pytest
from fastapi.testclient import TestClient

from services.dns_intel import app
from shared import utils
from shared.constants import DEFAULT_DKIM_SELECTORS, DEFAULT_SUBDOMAINS
from shared.utils import collection_failed

client = TestClient(app)

DOMAIN = "example.com"
DKIM_SUFFIX = f"._domainkey.{DOMAIN}"
MAX_SELECTORS = 32
MAX_PARAM_LENGTH = 2048


def _dig_stdout(argv, name, rtype, rdata=(), rcode="NOERROR", prefix=""):
    """Lo stdout che `dig` darebbe per `argv` alla risposta logica (`rcode`, `rdata`).

    RES-01 (modifica degli helper per G5, 0 asserzioni cambiate): `/dns` interroga con
    `dig_lookup`, il cui argv non ha più `+short` ma `+noall +comments +answer
    +nottlid +noclass`, perché `+short` non mostra mai lo `status:`. Gli spy di questo
    file simulano lo stdout di `dig` per l'argv che il codice usa, quindi devono
    seguirlo: con `+short` (argv di `dig_query`) è quello di sempre, le sole righe di
    rdata; altrimenti è il formato registrato con `dig` 9.18.39 (vedi
    `tests/test_utils.py`, `_RES01_CORPUS`): `;; Got answer:`, la testata
    `;; ->>HEADER<<- …`, la riga `;; flags: … ANSWER: N, …`, e le righe
    `owner TYPE rdata`. Così i test che c'erano prima di RES-01 restano verdi prima
    e dopo il fix.

    `rdata`: stringhe (il tipo è quello interrogato) oppure coppie (tipo, rdata) per
    una catena di CNAME. `prefix`: la riga `;;` di un tentativo perso, che `dig` stampa
    prima della risposta in entrambi i formati."""
    if "+short" in argv:
        return prefix + "".join(f"{r[1] if isinstance(r, tuple) else r}\n" for r in rdata)
    out = (prefix + ";; Got answer:\n"
           f";; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: 4242\n"
           f";; flags: qr aa rd ra; QUERY: 1, ANSWER: {len(rdata)}, AUTHORITY: 0, ADDITIONAL: 1\n"
           "\n"
           ";; OPT PSEUDOSECTION:\n"
           "; EDNS: version: 0, flags:; udp: 1232\n")
    if rdata:
        lines = []
        for r in rdata:
            rr_type, rr_data = r if isinstance(r, tuple) else (rtype, r)
            lines.append(f"{name}.\t\t{rr_type}\t{rr_data}\n")
        out += ";; ANSWER SECTION:\n" + "".join(lines) + "\n"
    return out


class _DigSpy:
    """Sostituto di `subprocess.run` che registra l'argv di ogni `dig`."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, *args, **kwargs):
        self.calls.append(list(argv))
        name, rtype = argv[-2], argv[-1]  # [... "+noidnout", fqdn, rtype]
        rdata = ["v=DKIM1; k=rsa; p=KEY"] if "._domainkey." in name else []
        return subprocess.CompletedProcess(argv, 0, stdout=_dig_stdout(argv, name, rtype, rdata), stderr="")

    @property
    def names(self):
        return [c[-2] for c in self.calls]

    @property
    def dkim_names(self):
        return [n for n in self.names if n.endswith(DKIM_SUFFIX)]


@pytest.fixture
def dig(monkeypatch):
    spy = _DigSpy()
    # `utils.subprocess` è il modulo stdlib: monkeypatch ripristina `run` a fine test.
    monkeypatch.setattr(utils.subprocess, "run", spy)
    return spy


def _dns(selectors=None, **extra):
    params = {"domain": DOMAIN, "full": "true"}
    if selectors is not None:
        params["dkim_selectors"] = selectors
    params.update(extra)
    return client.get("/dns", params=params)


def _non_base_names(dig_spy):
    # I nomi uguali al dominio sono le query base (A/AAAA/MX/...): si mostra il resto.
    return [n for n in dig_spy.names if n != DOMAIN]


def _assert_rejected_without_dig(resp, dig_spy, selectors):
    assert resp.status_code == 422, (
        f"dkim_selectors={selectors!r} doveva essere rifiutato con 422, "
        f"ricevuto {resp.status_code}; dig invocati: {len(dig_spy.calls)}, "
        f"nomi oltre alle query base: {_non_base_names(dig_spy)}")
    assert dig_spy.calls == [], (
        f"nessun dig doveva partire per dkim_selectors={selectors!r}, "
        f"invocazioni: {len(dig_spy.calls)}, nomi: {_non_base_names(dig_spy)}")


def _label(ch, n):
    return ch * n


class TestSEC26SelectorsStartingLikeDigArguments:
    """C1 — un selettore che inizia con `@`, `-`, `+` finirebbe in `dig` come
    server o come opzione. Va rifiutato all'ingresso, senza alcun processo."""

    @pytest.mark.parametrize("selectors", [
        "@ns.attacker.example",
        "@8.8.8.8",
        "-x",
        "-p5353",
        "+tries=9",
        "+short",
        " @padded",            # dopo lo strip() inizia comunque con '@'
        "s1,@evil",            # un selettore valido non salva quello ostile
        "@evil,s1",
        "s1, -x",
        "s1,,+time=1",
    ], ids=lambda s: repr(s))
    def test_selector_with_leading_dig_syntax_is_rejected_without_dig(self, dig, selectors):
        resp = _dns(selectors)
        _assert_rejected_without_dig(resp, dig, selectors)


class TestSEC26MalformedSelectors:
    """C2 — fuori dalla sintassi `selector` di RFC 6376 §3.5 → 422, zero `dig`."""

    @pytest.mark.parametrize("selectors", [
        "sel ector",           # spazio interno
        "a\tb",                # tab interno
        "a\nb",                # newline interno
        "a\x00b",              # NUL
        "a/b",
        "a\\b",
        "a..b",                # label vuota
        ".a",                  # punto iniziale
        "a.",                  # punto finale
        "a_b",                 # underscore non ammesso dalla sintassi fissata
        "sélector",       # non ASCII
        "ｓ１",        # cifre/lettere full-width: non sono [A-Za-z0-9]
        "١٢",        # cifre arabo-indiche: `\d` le accetterebbe
        "a-",                  # la label non può finire con '-'
        "a.-b",                # né iniziare con '-'
        "a.b-",
        "a;b",
        "a=b",
        "a:b",
        "a$(id)",
        _label("a", 64),                       # label di 64 caratteri
        "ok." + _label("b", 64),               # label lunga non in prima posizione
        _label("a", 63) + "." + _label("b", 64),
        "ok,sel ector",        # una voce ostile fra voci valide
    ], ids=lambda s: repr(s) if len(s) < 40 else f"{s[:12]!r}...(len={len(s)})")
    def test_malformed_selector_is_rejected_without_dig(self, dig, selectors):
        resp = _dns(selectors)
        _assert_rejected_without_dig(resp, dig, selectors)


class TestSEC26ValidSelectorsUnchanged:
    """C3 — i selettori leciti continuano a produrre esattamente un `dig` per
    voce, con il nome `{sel}._domainkey.{domain}` (maiuscole comprese)."""

    @pytest.mark.parametrize("selector", [
        "s1",
        "google",
        "k1.mail",
        "selector-2",
        "SeLeCtOr",
        "20240101",
        "a",
        "a-b",
        "a.b.c",
        _label("a", 63),                       # label di 63: limite incluso
        "x." + _label("b", 63),
    ], ids=lambda s: repr(s) if len(s) < 40 else f"{s[:12]!r}...(len={len(s)})")
    def test_valid_selector_gets_exactly_one_dig_with_exact_name(self, dig, selector):
        resp = _dns(selector)

        assert resp.status_code == 200, f"{selector!r} è valido: {resp.status_code} {resp.text[:200]}"
        assert dig.dkim_names == [f"{selector}{DKIM_SUFFIX}"]
        dkim = resp.json()["email_auth"]["dkim"]
        assert dkim["selectors_tested"] == 1
        assert dkim["selectors_found"] == [selector]

    def test_several_valid_selectors_each_get_one_dig(self, dig):
        resp = _dns("s1,google,k1.mail,selector-2")

        assert resp.status_code == 200
        assert sorted(dig.dkim_names) == sorted(
            f"{s}{DKIM_SUFFIX}" for s in ["s1", "google", "k1.mail", "selector-2"])
        assert resp.json()["email_auth"]["dkim"]["selectors_tested"] == 4

    def test_empty_entries_between_commas_are_still_skipped(self, dig):
        resp = _dns("a,,b")

        assert resp.status_code == 200
        assert sorted(dig.dkim_names) == [f"a{DKIM_SUFFIX}", f"b{DKIM_SUFFIX}"]
        assert resp.json()["email_auth"]["dkim"]["selectors_tested"] == 2

    def test_spaces_around_selectors_are_still_stripped(self, dig):
        resp = _dns("a, b")

        assert resp.status_code == 200
        assert sorted(dig.dkim_names) == [f"a{DKIM_SUFFIX}", f"b{DKIM_SUFFIX}"]

    def test_leading_and_trailing_commas_are_still_accepted(self, dig):
        resp = _dns(",a, ,b,")

        assert resp.status_code == 200
        assert sorted(dig.dkim_names) == [f"a{DKIM_SUFFIX}", f"b{DKIM_SUFFIX}"]


class TestSEC26SelectorCountAndLengthLimits:
    """C4 — tetto al numero di selettori (32 non vuoti) e alla lunghezza del
    valore (2048): senza, una sola richiesta non autenticata poteva lanciare
    migliaia di processi `dig`."""

    @staticmethod
    def _selectors(n):
        return [f"s{i}" for i in range(n)]

    def test_33_selectors_are_rejected_without_dig(self, dig):
        value = ",".join(self._selectors(MAX_SELECTORS + 1))

        resp = _dns(value)

        _assert_rejected_without_dig(resp, dig, value)

    def test_32_selectors_are_accepted_with_32_dkim_digs(self, dig):
        names = self._selectors(MAX_SELECTORS)

        resp = _dns(",".join(names))

        assert resp.status_code == 200
        assert len(dig.dkim_names) == MAX_SELECTORS
        assert sorted(dig.dkim_names) == sorted(f"{s}{DKIM_SUFFIX}" for s in names)
        assert resp.json()["email_auth"]["dkim"]["selectors_tested"] == MAX_SELECTORS

    def test_empty_entries_do_not_count_toward_the_limit(self, dig):
        names = self._selectors(MAX_SELECTORS)
        value = ",,".join(names)               # 32 voci non vuote, 31 vuote in mezzo
        assert len(value) <= MAX_PARAM_LENGTH

        resp = _dns(value)

        assert resp.status_code == 200
        assert len(dig.dkim_names) == MAX_SELECTORS

    def test_thousands_of_selectors_are_rejected_without_dig(self, dig):
        # Forma dell'abuso documentato: molte voci brevi in una sola richiesta.
        value = ",".join(self._selectors(1000))

        resp = _dns(value)

        assert resp.status_code == 422, (
            f"1000 selettori accettati ({resp.status_code}): {len(dig.dkim_names)} dig DKIM partiti")
        assert dig.calls == [], f"{len(dig.calls)} dig partiti per 1000 selettori"

    @staticmethod
    def _long_valid_value(total_len):
        """10 selettori validi da 191 caratteri (3 label da 63), poi virgole di
        riempimento fino a `total_len`: conteggio (10) e sintassi sono in regola,
        quindi solo `max_length` può distinguere i due casi."""
        sel = ".".join([_label("a", 63), _label("b", 63), _label("c", 63)])
        value = ",".join([sel] * 10)
        assert len(value) < MAX_PARAM_LENGTH
        return value + "," * (total_len - len(value))

    def test_value_longer_than_2048_characters_is_rejected_without_dig(self, dig):
        value = self._long_valid_value(MAX_PARAM_LENGTH + 1)
        assert len(value) == MAX_PARAM_LENGTH + 1

        resp = _dns(value)

        assert resp.status_code == 422, (
            f"valore di {len(value)} caratteri accettato ({resp.status_code}): "
            f"{len(dig.dkim_names)} dig DKIM partiti")
        assert dig.calls == [], f"{len(dig.calls)} dig partiti per un valore di {len(value)} caratteri"

    def test_value_of_exactly_2048_characters_is_still_accepted(self, dig):
        value = self._long_valid_value(MAX_PARAM_LENGTH)
        assert len(value) == MAX_PARAM_LENGTH

        resp = _dns(value)

        assert resp.status_code == 200
        assert len(dig.dkim_names) == 10


class TestSEC26DefaultSelectorsAndEarlyValidation:
    """C5 — il default non cambia; la validazione è d'ingresso (anche `full=false`)."""

    def test_without_dkim_selectors_the_default_list_is_queried_unchanged(self, dig):
        resp = _dns()

        assert resp.status_code == 200
        assert sorted(dig.dkim_names) == sorted(f"{s}{DKIM_SUFFIX}" for s in DEFAULT_DKIM_SELECTORS)
        assert len(dig.dkim_names) == len(DEFAULT_DKIM_SELECTORS)
        dkim = resp.json()["email_auth"]["dkim"]
        assert dkim["selectors_tested"] == len(DEFAULT_DKIM_SELECTORS)

    def test_empty_dkim_selectors_falls_back_to_the_default_list(self, dig):
        resp = _dns("")

        assert resp.status_code == 200
        assert sorted(dig.dkim_names) == sorted(f"{s}{DKIM_SUFFIX}" for s in DEFAULT_DKIM_SELECTORS)

    @pytest.mark.parametrize("selectors", [
        "@ns.attacker.example",
        "-x",
        "+tries=9",
        "bad selector",
        "a..b",
        _label("a", 64),
        ",".join(f"s{i}" for i in range(MAX_SELECTORS + 1)),
    ], ids=lambda s: repr(s) if len(s) < 40 else f"{s[:12]!r}...(len={len(s)})")
    @pytest.mark.parametrize("full", [None, "false"], ids=["full-omitted", "full-false"])
    def test_invalid_dkim_selectors_are_rejected_even_without_full(self, dig, selectors, full):
        params = {"domain": DOMAIN, "dkim_selectors": selectors}
        if full is not None:
            params["full"] = full

        resp = client.get("/dns", params=params)

        _assert_rejected_without_dig(resp, dig, selectors)

    def test_valid_dkim_selectors_with_full_false_still_return_200_without_dkim_digs(self, dig):
        # Controllo di contrasto: la validazione d'ingresso non deve rompere il
        # percorso `full=false`, che non interroga mai i selettori DKIM.
        resp = client.get("/dns", params={"domain": DOMAIN, "full": "false", "dkim_selectors": "s1,s2"})

        assert resp.status_code == 200
        assert dig.dkim_names == []
        assert resp.json()["email_auth"] == {}


# ═══════════════════════════════════════════════════════════════
# COL-08 — le righe di diagnostica di `dig +short` su GET /dns
# ═══════════════════════════════════════════════════════════════
#
# `dig` scrive su stdout, con prefisso `;; `, le righe che raccontano i propri
# guasti. Prima del fix `dig_query` le restituiva come record e `is_valid` le
# accettava: con il DNS irraggiungibile `/dns` riportava DMARC, BIMI, CAA, tutti
# i selettori DKIM e tutti i sottodomini come «presenti», col testo dell'errore
# come contenuto. Criterio C5 di BUG-REGISTER.md («ASSEGNA · COL-08 · criteri
# fissati»); la parte su `dig_query` è in `tests/test_utils.py::TestCOL08*`.
#
# Le stringhe sono stdout/returncode registrati con `dig` 9.18.39 reale in un
# network namespace isolato (connection refused: rc 9; primo tentativo UDP perso,
# secondo riuscito: rc 0). Nessun `dig` reale e nessuna rete: `subprocess.run` è
# sostituito da uno spy che risponde a ogni query con una zona finta.

_COL08_REFUSED_STDOUT = (
    ";; communications error to 127.0.0.9#53: connection refused\n"
    ";; communications error to 127.0.0.9#53: connection refused\n"
    ";; no servers could be reached\n"
)
_COL08_LOST_TRY = ";; communications error to 127.0.0.1#53: timed out\n"

_COL08_ZONE = {
    (DOMAIN, "A"): ["192.0.2.10"],
    (DOMAIN, "MX"): ["10 mail.example.com."],
    (DOMAIN, "NS"): ["ns1.example.com.", "ns2.example.com."],
    (DOMAIN, "TXT"): ['"v=spf1 -all"'],
    (DOMAIN, "SOA"): ["ns1.example.com. hostmaster.example.com. 2026010101 7200 900 1209600 3600"],
    (DOMAIN, "CAA"): ['0 issue "letsencrypt.org"'],
    (f"_dmarc.{DOMAIN}", "TXT"): ['"v=DMARC1; p=reject"'],
    (f"default._bimi.{DOMAIN}", "TXT"): ['"v=BIMI1; l=https://example.com/logo.svg"'],
    (f"google._domainkey.{DOMAIN}", "TXT"): ['"v=DKIM1; k=rsa; p=KEY"'],
    (f"www.{DOMAIN}", "A"): ["192.0.2.20"],
}
_COL08_BASE_RTYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
_COL08_EXPECTED_RECORDS = {
    "A": ["192.0.2.10"],
    "AAAA": [],
    "MX": ["10 mail.example.com"],
    "NS": ["ns1.example.com", "ns2.example.com"],
    "TXT": ['"v=spf1 -all"'],
    "SOA": ["ns1.example.com. hostmaster.example.com. 2026010101 7200 900 1209600 3600"],
    "CNAME": [],
}


class _Col08ZoneSpy:
    """Sostituto di `subprocess.run`. `mode`: `refused` (ogni query: rc 9, connection
    refused), `lost_first_try` (ogni query: riga `;;` del tentativo perso + la
    risposta vera della zona finta, rc 0), `clean` (solo la risposta vera, rc 0)."""

    def __init__(self, mode):
        self.mode = mode
        self.calls = []

    def __call__(self, argv, *args, **kwargs):
        self.calls.append(list(argv))
        name, rtype = argv[-2], argv[-1]  # [... "+noidnout", fqdn, rtype]
        if self.mode == "refused":
            return subprocess.CompletedProcess(argv, 9, stdout=_COL08_REFUSED_STDOUT, stderr="")
        # RES-01 (G5): lo stdout segue l'argv, come in `_dig_stdout`. Con `+short` è
        # `prefix + righe di rdata`, identico a prima; col formato nuovo c'è la testata.
        rdata = _COL08_ZONE.get((name, rtype), [])
        prefix = _COL08_LOST_TRY if self.mode == "lost_first_try" else ""
        stdout = _dig_stdout(argv, name, rtype, rdata, prefix=prefix)
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")


def _col08_get_dns(monkeypatch, mode):
    spy = _Col08ZoneSpy(mode)
    monkeypatch.setattr(utils.subprocess, "run", spy)
    resp = client.get("/dns", params={"domain": DOMAIN, "full": "true", "subdomains": "true"})
    assert resp.status_code == 200
    assert spy.calls, "nessuna query dig partita: il test non esercita /dns"
    return resp.json()


def _col08_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _col08_strings(key)
            yield from _col08_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _col08_strings(value)


def _col08_check_true_base_records(body):
    assert body["records"] == _COL08_EXPECTED_RECORDS


def _col08_check_true_email_auth(body):
    ea = body["email_auth"]
    assert ea["spf"]["present"] is True and ea["spf"]["records"] == ['"v=spf1 -all"']
    assert ea["dmarc"]["present"] is True and ea["dmarc"]["records"] == ['"v=DMARC1; p=reject"']
    assert ea["dkim"]["selectors_found"] == ["google"]
    assert ea["dkim"]["records"] == {"google": ['"v=DKIM1; k=rsa; p=KEY"']}
    assert ea["bimi"]["present"] is True and ea["bimi"]["records"] == ['"v=BIMI1; l=https://example.com/logo.svg"']
    assert ea["caa"]["present"] is True and ea["caa"]["records"] == ['0 issue "letsencrypt.org"']


def _col08_check_true_subdomains(body):
    active = body["subdomains"]["active"]
    assert [s["fqdn"] for s in active] == [f"www.{DOMAIN}"]
    assert active[0]["A"] == ["192.0.2.20"] and active[0]["CNAME"] == []


class TestCOL08DnsEndpointResolverDown:
    """C5 — con ogni query che finisce in connection refused (rc 9) non c'è alcun
    dato DNS: `/dns` deve riportare record vuoti e «non presente», non il testo
    dell'errore di `dig` come contenuto."""

    def test_connection_refused_yields_empty_base_records(self, monkeypatch):
        body = _col08_get_dns(monkeypatch, "refused")

        assert body["records"] == {rtype: [] for rtype in _COL08_BASE_RTYPES}

    def test_connection_refused_reports_no_email_authentication(self, monkeypatch):
        ea = _col08_get_dns(monkeypatch, "refused")["email_auth"]

        assert ea["spf"]["present"] is False and ea["spf"]["records"] == []
        assert ea["dmarc"]["present"] is False and ea["dmarc"]["records"] == []
        assert ea["bimi"]["present"] is False and ea["bimi"]["records"] == []
        assert ea["caa"]["present"] is False and ea["caa"]["records"] == []
        assert ea["dkim"]["selectors_found"] == []
        assert ea["dkim"]["records"] == {}

    def test_connection_refused_reports_no_active_subdomain(self, monkeypatch):
        body = _col08_get_dns(monkeypatch, "refused")

        assert body["subdomains"]["active"] == []

    def test_connection_refused_leaves_no_diagnostic_line_in_the_response(self, monkeypatch):
        body = _col08_get_dns(monkeypatch, "refused")

        leaked = [s for s in _col08_strings(body) if s.lstrip().startswith(";")]
        assert leaked == [], f"{len(leaked)} stringhe di diagnostica nella risposta, prima: {leaked[:1]}"


class TestCOL08DnsEndpointFirstAttemptLost:
    """C5 — il primo tentativo UDP si perde e il secondo risponde (rc 0): la riga
    `;; communications error …` di `dig` non deve comparire fra i record, e i
    record devono essere quelli della risposta vera."""

    def test_lost_first_attempt_returns_the_true_base_records(self, monkeypatch):
        _col08_check_true_base_records(_col08_get_dns(monkeypatch, "lost_first_try"))

    def test_lost_first_attempt_returns_the_true_email_authentication(self, monkeypatch):
        _col08_check_true_email_auth(_col08_get_dns(monkeypatch, "lost_first_try"))

    def test_lost_first_attempt_reports_only_the_subdomain_that_exists(self, monkeypatch):
        _col08_check_true_subdomains(_col08_get_dns(monkeypatch, "lost_first_try"))

    def test_lost_first_attempt_leaves_no_diagnostic_line_in_the_response(self, monkeypatch):
        body = _col08_get_dns(monkeypatch, "lost_first_try")

        leaked = [s for s in _col08_strings(body) if s.lstrip().startswith(";")]
        assert leaked == [], f"{len(leaked)} stringhe di diagnostica nella risposta, prima: {leaked[:1]}"


class TestCOL08DnsEndpointCleanAnswersUnchanged:
    """C4 sull'endpoint (controllo di contrasto): senza righe di diagnostica la
    risposta vera della stessa zona finta è riportata invariata. Se questo test
    fallisse, la zona finta o le attese dei test C5 sarebbero sbagliate."""

    def test_answers_without_diagnostic_lines_are_reported_unchanged(self, monkeypatch):
        body = _col08_get_dns(monkeypatch, "clean")

        _col08_check_true_base_records(body)
        _col08_check_true_email_auth(body)
        _col08_check_true_subdomains(body)


# ═══════════════════════════════════════════════════════════════
# COL-08 (giro correttivo, C7) — `;; Got bad packet` + dump esadecimale su /dns
# ═══════════════════════════════════════════════════════════════
#
# Una risposta che `dig` non riesce a parsare esce con rc 0: `;; Got bad packet:
# <motivo>`, `N bytes` e un dump esadecimale che non inizia con `;`. Stdout reale di
# `dig` 9.18.39 (catturato dal verifier con uno stub su loopback): CAA con tag non
# valido e CNAME con label di tipo errato, due tipi interrogati da `/dns`.

_COL08_BADPKT_CAA_TAG = (
    ";; Got bad packet: FORMERR\n"
    "53 bytes\n"
    "95 f0 85 80 00 01 00 01 00 00 00 00 0a 63 61 61          .............caa\n"
    "5f 62 61 64 74 61 67 01 67 04 74 65 73 74 00 01          _badtag.g.test..\n"
    "01 00 01 c0 0c 01 01 00 01 00 00 00 3c 00 06 00          ............<...\n"
    "03 3b 3b 3b 76                                           .;;;v\n"
)
_COL08_BADPKT_CNAME_LABEL = (
    ";; Got bad packet: bad label type\n"
    "116 bytes\n"
    "b0 6f 85 80 00 01 00 01 00 00 00 00 0e 63 6e 61          .o...........cna\n"
    "6d 65 5f 62 61 64 6c 61 62 65 6c 01 67 04 74 65          me_badlabel.g.te\n"
    "73 74 00 00 05 00 01 c0 0c 00 05 00 01 00 00 00          st..............\n"
    "3c 00 41 40 61 61 61 61 61 61 61 61 61 61 61 61          <.A@aaaaaaaaaaaa\n"
    "61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61          aaaaaaaaaaaaaaaa\n"
    "61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61          aaaaaaaaaaaaaaaa\n"
    "61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61          aaaaaaaaaaaaaaaa\n"
    "61 61 61 00                                              aaa.\n"
)


class _Col08BadPacketSpy(_Col08ZoneSpy):
    """Come la zona `clean`, ma la query `(DOMAIN, bad_rtype)` risponde con lo stdout
    di un pacchetto non parsabile (rc 0)."""

    def __init__(self, bad_rtype, bad_stdout):
        super().__init__("clean")
        self.bad_rtype = bad_rtype
        self.bad_stdout = bad_stdout

    def __call__(self, argv, *args, **kwargs):
        if (argv[-2], argv[-1]) == (DOMAIN, self.bad_rtype):
            self.calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout=self.bad_stdout, stderr="")
        return super().__call__(argv, *args, **kwargs)


def _col08_get_dns_bad_packet(monkeypatch, bad_rtype, bad_stdout):
    spy = _Col08BadPacketSpy(bad_rtype, bad_stdout)
    monkeypatch.setattr(utils.subprocess, "run", spy)
    resp = client.get("/dns", params={"domain": DOMAIN, "full": "true", "subdomains": "true"})
    assert resp.status_code == 200
    assert (DOMAIN, bad_rtype) in [(c[-2], c[-1]) for c in spy.calls], "la query con il pacchetto non parsabile non è partita"
    return resp.json()


def _col08_dump_leaks(body, bad_stdout):
    """Stringhe del JSON che contengono una riga dello stdout di `dig` (nella forma
    normalizzata da `dig_query`: strip e punti finali tolti) o il suo testo."""
    echoed = [ln.strip().rstrip(".") for ln in bad_stdout.splitlines() if ln.strip().rstrip(".")]
    return [s for s in _col08_strings(body)
            if "Got bad packet" in s or any(ln in s for ln in echoed)]


class TestCOL08DnsEndpointBadPacket:
    """C7 sull'endpoint — una risposta non parsabile non è un dato: CAA non
    «presente», CNAME vuoto, nessuna riga del dump nel JSON."""

    def test_bad_packet_on_caa_reports_caa_absent(self, monkeypatch):
        body = _col08_get_dns_bad_packet(monkeypatch, "CAA", _COL08_BADPKT_CAA_TAG)

        caa = body["email_auth"]["caa"]
        assert caa["present"] is False
        assert caa["records"] == []

    def test_bad_packet_on_cname_reports_no_cname_record(self, monkeypatch):
        body = _col08_get_dns_bad_packet(monkeypatch, "CNAME", _COL08_BADPKT_CNAME_LABEL)

        assert body["records"]["CNAME"] == []

    @pytest.mark.parametrize("rtype, bad_stdout", [
        pytest.param("CAA", _COL08_BADPKT_CAA_TAG, id="CAA"),
        pytest.param("CNAME", _COL08_BADPKT_CNAME_LABEL, id="CNAME"),
    ])
    def test_bad_packet_leaves_no_dump_line_in_the_response(self, monkeypatch, rtype, bad_stdout):
        body = _col08_get_dns_bad_packet(monkeypatch, rtype, bad_stdout)

        leaked = _col08_dump_leaks(body, bad_stdout)
        assert leaked == [], f"{len(leaked)} stringhe dal dump di dig nella risposta, prima: {leaked[:1]}"

    def test_bad_packet_on_caa_leaves_every_other_answer_untouched(self, monkeypatch):
        # Controllo di contrasto (verde anche prima del fix): l'errore di una query
        # non contamina le altre.
        body = _col08_get_dns_bad_packet(monkeypatch, "CAA", _COL08_BADPKT_CAA_TAG)

        _col08_check_true_base_records(body)
        _col08_check_true_subdomains(body)
        ea = body["email_auth"]
        assert ea["spf"]["present"] is True
        assert ea["dmarc"]["records"] == ['"v=DMARC1; p=reject"']
        assert ea["dkim"]["selectors_found"] == ["google"]
        assert ea["bimi"]["present"] is True


# ═══════════════════════════════════════════════════════════════
# RES-01 (nucleo) — `GET /dns` espone lo stato di ogni query DNS
# ═══════════════════════════════════════════════════════════════
#
# Criterio R5 di BUG-REGISTER.md («ASSEGNA · RES-01 (nucleo) · criteri»). `/dns`
# interroga con `dig_lookup`: ogni query ha uno stato `ok` / `nodata` / `nxdomain` /
# `unknown` (parser in `tests/test_utils.py::TestRES01DigLookup*`) e il JSON lo
# espone **in più**: `records_status` (sempre, anche con `full=false`), `status` in
# `email_auth.spf` (= TXT), `dmarc`, `bimi`, `caa`, `dkim.selectors_unknown`,
# `subdomains.unknown`, e `error` valorizzato con un testo costante se tutti e 7 i
# tipi base sono `unknown`. Prima di RES-01 un SERVFAIL e un NODATA erano entrambi `[]`
# e `error` era sempre `None`: l'orchestrator non poteva distinguere «il dominio non ha
# MX» da «il DNS non ha risposto» e salvava il secondo come il primo.
#
# Lo spy serve la stessa risposta logica in entrambi i formati (`_dig_stdout`), quindi
# i test dell'invariante «solo additivo» girano anche sul codice di prima del fix.
# Nessun `dig` reale, nessuna rete.

_R_NODATA = ("NOERROR", [])
_R_NXDOMAIN = ("NXDOMAIN", [])
_R_SERVFAIL = ("SERVFAIL", [])
_R_REFUSED = ("REFUSED", [])
_R_FORMERR = ("FORMERR", [])
_R_NOTIMP = ("NOTIMP", [])
_R_TRANSPORT = "transport-failure"   # rc 9, `;; communications error … connection refused`
_R_BADPACKET = "bad-packet"          # rc 0, `;; Got bad packet: FORMERR` + dump esadecimale


def _r_ok(*rdata):
    return ("NOERROR", list(rdata))


class _ZoneSpy:
    """Sostituto di `subprocess.run`: ogni query `(nome, tipo)` riceve la risposta
    logica della zona (default: NODATA) nel formato che l'argv richiede."""

    def __init__(self, zone=None, default=_R_NODATA):
        self.zone = dict(zone or {})
        self.default = default
        self.calls = []

    def __call__(self, argv, *args, **kwargs):
        self.calls.append(list(argv))
        name, rtype = argv[-2], argv[-1]
        outcome = self.zone.get((name, rtype), self.default)
        if outcome == _R_TRANSPORT:
            return subprocess.CompletedProcess(argv, 9, stdout=_COL08_REFUSED_STDOUT, stderr="")
        if outcome == _R_BADPACKET:
            return subprocess.CompletedProcess(argv, 0, stdout=_COL08_BADPKT_CAA_TAG, stderr="")
        rcode, rdata = outcome
        return subprocess.CompletedProcess(argv, 0, stdout=_dig_stdout(argv, name, rtype, rdata, rcode), stderr="")


_RES01_HEALTHY = {key: _r_ok(*rdata) for key, rdata in _COL08_ZONE.items()}
_RES01_HEALTHY_STATUS = {"A": "ok", "AAAA": "nodata", "MX": "ok", "NS": "ok", "TXT": "ok", "SOA": "ok",
                         "CNAME": "nodata"}
# (stato atteso, risposta logica). Le ultime quattro sono tutte «non si è potuto sapere».
_RES01_OUTCOMES = [
    pytest.param("ok", _r_ok("192.0.2.1"), id="ok"),
    pytest.param("nodata", _R_NODATA, id="nodata"),
    pytest.param("nxdomain", _R_NXDOMAIN, id="nxdomain"),
    pytest.param("unknown", _R_SERVFAIL, id="servfail"),
    pytest.param("unknown", _R_REFUSED, id="refused"),
    pytest.param("unknown", _R_TRANSPORT, id="transport-failure"),
    pytest.param("unknown", _R_BADPACKET, id="bad-packet"),
]
_RES01_FAILURE_CAUSES = [
    pytest.param(_R_SERVFAIL, id="servfail"), pytest.param(_R_REFUSED, id="refused"),
    pytest.param(_R_FORMERR, id="formerr"), pytest.param(_R_NOTIMP, id="notimp"),
    pytest.param(_R_TRANSPORT, id="transport-failure"), pytest.param(_R_BADPACKET, id="bad-packet"),
]
_RES01_SECTION_QUERIES = [
    pytest.param("dmarc", (f"_dmarc.{DOMAIN}", "TXT"), id="dmarc"),
    pytest.param("bimi", (f"default._bimi.{DOMAIN}", "TXT"), id="bimi"),
    pytest.param("caa", (DOMAIN, "CAA"), id="caa"),
]


def _res01_request(monkeypatch, zone=None, *, default=_R_NODATA, **params):
    """GET /dns con lo spy installato. Ritorna (JSON, spy)."""
    spy = _ZoneSpy(zone, default)
    monkeypatch.setattr(utils.subprocess, "run", spy)
    query = {"domain": DOMAIN, "full": "true"}
    query.update(params)
    resp = client.get("/dns", params=query)
    assert resp.status_code == 200, resp.text[:200]
    assert spy.calls, "nessuna query dig partita: il test non esercita /dns"
    return resp.json(), spy


def _res01_get(monkeypatch, zone=None, **kwargs):
    return _res01_request(monkeypatch, zone, **kwargs)[0]


class TestRES01DnsRecordsStatus:
    """R5 — `records_status`: lo stato di ciascuno dei 7 tipi base nel campo del proprio
    tipo, anche con `full=false`."""

    @pytest.mark.parametrize("rtype", _COL08_BASE_RTYPES)
    @pytest.mark.parametrize("status, outcome", _RES01_OUTCOMES)
    def test_outcome_lands_in_the_status_of_its_own_record_type(self, monkeypatch, rtype, status, outcome):
        body = _res01_get(monkeypatch, {(DOMAIN, rtype): outcome}, full="false")

        expected = {t: "nodata" for t in _COL08_BASE_RTYPES}
        expected[rtype] = status
        assert body["records_status"] == expected

    def test_records_status_is_the_same_with_and_without_full(self, monkeypatch):
        zone = {(DOMAIN, "A"): _r_ok("192.0.2.1"), (DOMAIN, "MX"): _R_NXDOMAIN, (DOMAIN, "NS"): _R_SERVFAIL,
                (DOMAIN, "TXT"): _R_TRANSPORT, (DOMAIN, "SOA"): _R_BADPACKET}

        brief = _res01_get(monkeypatch, zone, full="false")["records_status"]
        complete = _res01_get(monkeypatch, zone, full="true")["records_status"]

        assert brief == complete == {"A": "ok", "AAAA": "nodata", "MX": "nxdomain", "NS": "unknown",
                                     "TXT": "unknown", "SOA": "unknown", "CNAME": "nodata"}

    def test_servfail_on_a_only_marks_only_a_unknown_and_leaves_error_null(self, monkeypatch):
        body = _res01_get(monkeypatch, {**_RES01_HEALTHY, (DOMAIN, "A"): _R_SERVFAIL})

        assert body["records_status"] == {**_RES01_HEALTHY_STATUS, "A": "unknown"}
        assert body["records"]["A"] == []
        assert body["error"] is None
        assert collection_failed(body) is False

    def test_every_query_asks_dig_for_the_header_and_none_uses_plus_short(self, monkeypatch):
        # I 7 punti di chiamata di `/dns` (base, DMARC, DKIM, BIMI, CAA, A e CNAME dei
        # sottodomini) passano al nuovo risolutore: una query rimasta su `+short` non
        # avrebbe stato.
        _, spy = _res01_request(monkeypatch, _RES01_HEALTHY, subdomains="true")

        assert len(spy.calls) == 7 + 1 + len(DEFAULT_DKIM_SELECTORS) + 1 + 1 + 2 * len(DEFAULT_SUBDOMAINS)
        assert [argv for argv in spy.calls if "+short" in argv] == []
        assert [argv for argv in spy.calls if "+comments" not in argv] == []


class TestRES01DnsTotalFailure:
    """R5 — `error`: costante se i 7 tipi base sono tutti `unknown`, `None` altrimenti.
    È ciò che fa leggere il modulo `dns` come fallito a `collection_failed` e che porta
    l'orchestrator a conservare la sezione precedente invece di sovrascriverla."""

    @pytest.mark.parametrize("full", ["false", "true"])
    @pytest.mark.parametrize("outcome", _RES01_FAILURE_CAUSES)
    def test_all_seven_base_types_unknown_marks_the_module_as_failed(self, monkeypatch, outcome, full):
        body = _res01_get(monkeypatch, default=outcome, full=full)

        assert set(body["records_status"].values()) == {"unknown"}
        assert isinstance(body["error"], str) and body["error"]
        assert collection_failed(body) is True

    def test_error_text_is_the_same_for_every_cause_and_domain_and_echoes_no_dig_output(self, monkeypatch):
        errors = {}
        for case in _RES01_FAILURE_CAUSES:
            outcome = case.values[0]
            for domain in (DOMAIN, "another-domain.org"):
                errors[(case.id, domain)] = _res01_get(
                    monkeypatch, default=outcome, full="false", domain=domain)["error"]

        assert len(set(errors.values())) == 1, f"testo diverso per causa o dominio: {errors}"
        text = next(iter(errors.values()))
        assert isinstance(text, str) and text, f"error non valorizzato: {text!r}"
        assert ";;" not in text and "127.0.0.9" not in text

    def test_only_the_seven_base_types_decide_the_error(self, monkeypatch):
        # I 7 tipi base unknown, tutto il resto (DMARC, DKIM, BIMI, CAA) risponde: fallito comunque.
        zone = {**_RES01_HEALTHY, **{(DOMAIN, t): _R_SERVFAIL for t in _COL08_BASE_RTYPES}}

        body = _res01_get(monkeypatch, zone)

        assert body["error"] is not None and collection_failed(body) is True

    def test_unknown_only_outside_the_base_types_does_not_set_the_error(self, monkeypatch):
        zone = {(DOMAIN, t): _r_ok("192.0.2.1") for t in _COL08_BASE_RTYPES}

        body = _res01_get(monkeypatch, zone, default=_R_SERVFAIL, subdomains="true")

        assert set(body["records_status"].values()) == {"ok"}
        assert body["error"] is None and collection_failed(body) is False

    @pytest.mark.parametrize("known_status, known", [
        pytest.param("ok", _r_ok("192.0.2.1"), id="ok"),
        pytest.param("nodata", _R_NODATA, id="nodata"),
        pytest.param("nxdomain", _R_NXDOMAIN, id="nxdomain"),
    ])
    @pytest.mark.parametrize("rtype", _COL08_BASE_RTYPES)
    def test_one_known_base_type_among_seven_keeps_error_null(self, monkeypatch, rtype, known_status, known):
        body = _res01_get(monkeypatch, {(DOMAIN, rtype): known}, default=_R_SERVFAIL, full="false")

        assert body["records_status"][rtype] == known_status
        assert body["error"] is None
        assert collection_failed(body) is False

    @pytest.mark.parametrize("full", ["false", "true"])
    def test_nxdomain_everywhere_is_an_answer_not_a_failure(self, monkeypatch, full):
        body = _res01_get(monkeypatch, default=_R_NXDOMAIN, full=full)

        assert set(body["records_status"].values()) == {"nxdomain"}
        assert body["error"] is None
        assert collection_failed(body) is False

    @pytest.mark.parametrize("full", ["false", "true"])
    def test_nodata_everywhere_is_an_answer_not_a_failure(self, monkeypatch, full):
        body = _res01_get(monkeypatch, default=_R_NODATA, full=full)

        assert set(body["records_status"].values()) == {"nodata"}
        assert body["error"] is None
        assert collection_failed(body) is False


class TestRES01DnsEmailAuthStatus:
    """R5 — `status` in `spf` (= TXT del dominio), `dmarc`, `bimi`, `caa`: unknown, nodata
    e nxdomain sono distinguibili. `present` e `records` restano quelli di prima."""

    @pytest.mark.parametrize("section, query", _RES01_SECTION_QUERIES)
    @pytest.mark.parametrize("status, outcome", _RES01_OUTCOMES)
    def test_section_status_is_the_status_of_its_own_query(self, monkeypatch, section, query, status, outcome):
        body = _res01_get(monkeypatch, {**_RES01_HEALTHY, query: outcome})

        assert body["email_auth"][section]["status"] == status

    @pytest.mark.parametrize("section, query", _RES01_SECTION_QUERIES)
    def test_unknown_section_does_not_touch_any_other_status(self, monkeypatch, section, query):
        body = _res01_get(monkeypatch, {**_RES01_HEALTHY, query: _R_SERVFAIL})

        statuses = {s: body["email_auth"][s]["status"] for s in ("spf", "dmarc", "bimi", "caa")}
        assert statuses == {s: ("unknown" if s == section else "ok") for s in statuses}
        assert body["records_status"] == _RES01_HEALTHY_STATUS

    @pytest.mark.parametrize("status, outcome", _RES01_OUTCOMES)
    def test_spf_status_is_the_status_of_the_txt_query(self, monkeypatch, status, outcome):
        body = _res01_get(monkeypatch, {**_RES01_HEALTHY, (DOMAIN, "TXT"): outcome})

        assert body["email_auth"]["spf"]["status"] == status
        assert body["records_status"]["TXT"] == status

    def test_txt_without_an_spf_record_is_ok_not_unknown(self, monkeypatch):
        zone = {**_RES01_HEALTHY, (DOMAIN, "TXT"): _r_ok('"google-site-verification=abc"')}

        spf = _res01_get(monkeypatch, zone)["email_auth"]["spf"]

        assert spf["present"] is False
        assert spf["status"] == "ok"

    def test_dmarc_and_the_base_txt_are_independent_queries(self, monkeypatch):
        dmarc_down = _res01_get(monkeypatch, {**_RES01_HEALTHY, (f"_dmarc.{DOMAIN}", "TXT"): _R_SERVFAIL})
        txt_down = _res01_get(monkeypatch, {**_RES01_HEALTHY, (DOMAIN, "TXT"): _R_SERVFAIL})

        assert (dmarc_down["email_auth"]["dmarc"]["status"], dmarc_down["email_auth"]["spf"]["status"]) == \
            ("unknown", "ok")
        assert (txt_down["email_auth"]["dmarc"]["status"], txt_down["email_auth"]["spf"]["status"]) == \
            ("ok", "unknown")


class TestRES01DnsDkimAndSubdomains:
    """R5 — `dkim.selectors_unknown` e `subdomains.unknown`: ciò che non si è potuto
    sapere non finisce fra i selettori trovati né fra i sottodomini attivi, e non si
    confonde con ciò che non esiste."""

    @staticmethod
    def _dkim(sel):
        return (f"{sel}._domainkey.{DOMAIN}", "TXT")

    def test_selectors_are_split_between_found_and_unknown(self, monkeypatch):
        zone = {self._dkim("a"): _r_ok('"v=DKIM1; k=rsa; p=KEY"'), self._dkim("b"): _R_NODATA,
                self._dkim("c"): _R_NXDOMAIN, self._dkim("d"): _R_SERVFAIL,
                self._dkim("e"): _R_TRANSPORT, self._dkim("f"): _R_BADPACKET}

        dkim = _res01_get(monkeypatch, zone, dkim_selectors="a,b,c,d,e,f")["email_auth"]["dkim"]

        assert dkim["selectors_found"] == ["a"]
        assert sorted(dkim["selectors_unknown"]) == ["d", "e", "f"]
        assert dkim["selectors_tested"] == 6
        assert dkim["records"] == {"a": ['"v=DKIM1; k=rsa; p=KEY"']}

    def test_selectors_unknown_is_an_empty_list_when_every_selector_answers(self, monkeypatch):
        zone = {self._dkim("a"): _r_ok('"v=DKIM1; k=rsa; p=KEY"'), self._dkim("b"): _R_NODATA}

        dkim = _res01_get(monkeypatch, zone, dkim_selectors="a,b")["email_auth"]["dkim"]

        assert dkim["selectors_unknown"] == []

    def test_subdomain_is_unknown_only_when_it_is_not_active_and_a_or_cname_is_unknown(self, monkeypatch):
        def sub(label, rtype):
            return (f"{label}.{DOMAIN}", rtype)

        zone = {
            sub("www", "A"): _r_ok("192.0.2.20"),                                  # attivo
            sub("mail", "A"): _R_SERVFAIL,                                         # A unknown, CNAME nodata
            sub("webmail", "CNAME"): _R_TRANSPORT,                                 # CNAME unknown, A nodata
            sub("smtp", "A"): _R_BADPACKET, sub("smtp", "CNAME"): _R_SERVFAIL,    # entrambi unknown
            sub("imap", "A"): _r_ok("192.0.2.21"), sub("imap", "CNAME"): _R_SERVFAIL,   # attivo per l'A
            sub("pop", "A"): _R_NXDOMAIN, sub("pop", "CNAME"): _R_NXDOMAIN,       # non esiste
            sub("autodiscover", "CNAME"): _r_ok("target.example.com."),            # attivo per il CNAME
        }

        subs = _res01_get(monkeypatch, zone, subdomains="true")["subdomains"]

        assert sorted(s["fqdn"] for s in subs["active"]) == [
            f"autodiscover.{DOMAIN}", f"imap.{DOMAIN}", f"www.{DOMAIN}"]
        assert sorted(subs["unknown"]) == [f"mail.{DOMAIN}", f"smtp.{DOMAIN}", f"webmail.{DOMAIN}"]
        assert subs["tested"] == len(DEFAULT_SUBDOMAINS)

    def test_a_healthy_zone_has_no_unknown_selector_and_no_unknown_subdomain(self, monkeypatch):
        body = _res01_get(monkeypatch, _RES01_HEALTHY, subdomains="true")

        assert body["email_auth"]["dkim"]["selectors_unknown"] == []
        assert body["subdomains"]["unknown"] == []


class TestRES01DnsHealthyZoneStatus:
    """R5 — controllo di contrasto: su una zona sana tutti gli stati sono `ok`/`nodata`
    nei posti giusti e non c'è nulla di `unknown`."""

    def test_healthy_zone_reports_ok_where_there_are_records_and_nothing_unknown(self, monkeypatch):
        body = _res01_get(monkeypatch, _RES01_HEALTHY, subdomains="true")

        assert body["records_status"] == _RES01_HEALTHY_STATUS
        assert {s: body["email_auth"][s]["status"] for s in ("spf", "dmarc", "bimi", "caa")} == {
            "spf": "ok", "dmarc": "ok", "bimi": "ok", "caa": "ok"}
        assert body["error"] is None


# I campi che c'erano prima di RES-01, per una zona sana e per una piena di guasti.
_RES01_LEGACY_HEALTHY = {
    "domain": DOMAIN,
    "records": _COL08_EXPECTED_RECORDS,
    "email_auth": {
        "spf": {"present": True, "records": ['"v=spf1 -all"'], "policy": "fail"},
        "dmarc": {"present": True, "records": ['"v=DMARC1; p=reject"']},
        "dkim": {"selectors_found": ["google"], "selectors_tested": len(DEFAULT_DKIM_SELECTORS),
                 "records": {"google": ['"v=DKIM1; k=rsa; p=KEY"']}},
        "bimi": {"present": True, "records": ['"v=BIMI1; l=https://example.com/logo.svg"']},
        "caa": {"present": True, "records": ['0 issue "letsencrypt.org"']},
    },
    "subdomains": {"tested": len(DEFAULT_SUBDOMAINS),
                   "active": [{"fqdn": f"www.{DOMAIN}", "A": ["192.0.2.20"], "CNAME": []}]},
    "error": None,
}
_RES01_DEGRADED_ZONE = {
    **_RES01_HEALTHY,
    (DOMAIN, "A"): _R_SERVFAIL,
    (DOMAIN, "MX"): _R_REFUSED,
    (DOMAIN, "NS"): _R_TRANSPORT,
    (DOMAIN, "TXT"): _R_BADPACKET,
    (DOMAIN, "SOA"): _R_NXDOMAIN,
    (DOMAIN, "CAA"): _R_SERVFAIL,
    (f"_dmarc.{DOMAIN}", "TXT"): _R_REFUSED,
    (f"default._bimi.{DOMAIN}", "TXT"): _R_NXDOMAIN,
    (f"google._domainkey.{DOMAIN}", "TXT"): _R_SERVFAIL,
    (f"www.{DOMAIN}", "A"): _R_SERVFAIL,
}
_RES01_LEGACY_DEGRADED = {
    "domain": DOMAIN,
    "records": {t: [] for t in _COL08_BASE_RTYPES},
    "email_auth": {
        "spf": {"present": False, "records": [], "policy": None},
        "dmarc": {"present": False, "records": []},
        "dkim": {"selectors_found": [], "selectors_tested": len(DEFAULT_DKIM_SELECTORS), "records": {}},
        "bimi": {"present": False, "records": []},
        "caa": {"present": False, "records": []},
    },
    "subdomains": {"tested": len(DEFAULT_SUBDOMAINS), "active": []},
    "error": None,
}


def _res01_legacy_view(body):
    """`body` senza `timestamp` e senza i campi che RES-01 aggiunge: ciò che `/dns` produceva prima."""
    view = copy.deepcopy(body)
    view.pop("timestamp", None)
    view.pop("records_status", None)
    email_auth = view.get("email_auth", {})
    for section in ("spf", "dmarc", "bimi", "caa"):
        email_auth.get(section, {}).pop("status", None)
    email_auth.get("dkim", {}).pop("selectors_unknown", None)
    view.get("subdomains", {}).pop("unknown", None)
    return view


class TestRES01DnsOnlyAdditive:
    """R5 — invariante «solo additivo»: con le stesse risposte di `dig`, i campi che
    c'erano prima restano identici a quelli che `/dns` produceva (i consumatori e gli
    snapshot su disco li leggono). Questi test sono verdi anche sul codice di prima del
    fix: sono la rete contro una regressione, non il rosso."""

    def test_healthy_zone_existing_fields_are_unchanged(self, monkeypatch):
        body = _res01_get(monkeypatch, _RES01_HEALTHY, subdomains="true")

        assert _res01_legacy_view(body) == _RES01_LEGACY_HEALTHY

    def test_failed_queries_still_read_as_empty_exactly_as_before(self, monkeypatch):
        body = _res01_get(monkeypatch, _RES01_DEGRADED_ZONE, subdomains="true")

        assert _res01_legacy_view(body) == _RES01_LEGACY_DEGRADED

    def test_full_false_existing_fields_are_unchanged(self, monkeypatch):
        body = _res01_get(monkeypatch, _RES01_HEALTHY, full="false")

        assert _res01_legacy_view(body) == {
            "domain": DOMAIN, "records": _COL08_EXPECTED_RECORDS, "email_auth": {}, "subdomains": {},
            "error": None}

    def test_cname_chain_to_a_missing_name_keeps_todays_record_and_reports_nxdomain(self, monkeypatch):
        # `+short` mostrava la catena: `records.A == [target]` anche con rcode NXDOMAIN. Il
        # record resta com'è (COL-09 è un altro ID); lo stato dice che il nome finale non esiste.
        zone = {(DOMAIN, "A"): ("NXDOMAIN", [("CNAME", "gone.example.com.")])}

        body = _res01_get(monkeypatch, zone, full="false")

        assert body["records"]["A"] == ["gone.example.com"]
        assert body["records_status"]["A"] == "nxdomain"


class TestRES01DnsWarningLog:
    """Un `logger.warning` per richiesta quando almeno una query è `unknown`, con il solo
    conteggio e il dominio: l'operatore vede il guasto senza dover leggere il JSON, e il
    testo di `dig` (indirizzi del resolver, righe `;;`) non arriva nel log."""

    @staticmethod
    def _warnings(caplog):
        return [r for r in caplog.records if r.name == "dns-intel" and r.levelno == logging.WARNING]

    def test_one_warning_with_the_domain_and_the_count_of_unknown_queries(self, monkeypatch, caplog):
        zone = {(DOMAIN, "A"): _R_SERVFAIL, (DOMAIN, "MX"): _R_TRANSPORT, (DOMAIN, "NS"): _R_REFUSED}

        with caplog.at_level(logging.WARNING, logger="dns-intel"):
            _res01_get(monkeypatch, zone, full="false")

        (record,) = self._warnings(caplog)
        message = record.getMessage()
        assert DOMAIN in message
        assert re.search(r"\b3\b", message), f"conteggio 3 assente: {message!r}"

    def test_the_count_covers_every_query_of_the_request(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="dns-intel"):
            _, spy = _res01_request(monkeypatch, default=_R_TRANSPORT, subdomains="true")

        (record,) = self._warnings(caplog)
        assert re.search(rf"\b{len(spy.calls)}\b", record.getMessage())

    def test_no_warning_when_every_query_is_known(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="dns-intel"):
            _res01_get(monkeypatch, _RES01_HEALTHY, subdomains="true")

        assert self._warnings(caplog) == []

    def test_the_warning_does_not_echo_dig_output(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="dns-intel"):
            _res01_get(monkeypatch, default=_R_TRANSPORT, full="false")

        (record,) = self._warnings(caplog)
        message = record.getMessage()
        assert "127.0.0.9" not in message and "communications error" not in message and ";;" not in message
