"""Tests for services/whois_intel.py — esito di GET /whois quando il registro non dà un record (COL-17).

Un guasto del registro non fa sollevare la libreria `python-whois`. Quando la connessione al server
fallisce (rifiuto, timeout, reset, risposta vuota) la libreria sintetizza un testo
(`Socket not responding: ...`), e quando il registro oppone un limite di richieste riceve un avviso
senza campi: li passa al parser del TLD, che non solleva, e l'oggetto che ne esce ha ogni campo a
`None`. Il servizio non può trattarlo come un record valido (`error` nullo, `privacy_protected`
dedotto dal registrante assente): il consumatore (`collection_failed`, il riporto della baseline, la
guardia di classificazione) si fida di `error`, e un guasto che non lo valorizza diventa
un'osservazione.

Comportamento richiesto: un esito SENZA ALCUN CAMPO OSSERVATO è un errore di raccolta. Il controllo
vale sul risultato finale, quindi anche sul ramo CLI. «Campo osservato» è `registrar`, una delle tre
date, `status` non vuoto, `nameservers` non vuoto, uno dei `registrant.*`; non contano `dnssec`,
`privacy_protected` e `age_days`, che il servizio deduce o che dicono poco di per sé. La risposta di
un errore di raccolta ha la forma di quella del ramo che solleva (IANA irraggiungibile): campi
`None`, liste vuote, `privacy_protected` falso, `error` valorizzato con un testo del servizio e mai
con quello della libreria. Un record con almeno un campo, anche redatto o minimo, resta
un'osservazione: il WHOIS di un dominio può legittimamente essere povero, e scambiarlo per un guasto
farebbe riportare una baseline vecchia a ogni ciclo.

Isolamento di rete: **nessuna connessione reale**. La fixture `whois_network` (tests/conftest.py)
sostituisce solo il socket sotto il `NICClient` vero: la libreria sceglie il server, interroga IANA,
segue il rinvio al secondo hop e costruisce il testo d'errore come in produzione. Il ramo CLI usa un
doppio di `subprocess.run`. La cache del servizio è svuotata a ogni richiesta e l'attesa fra richieste
(`WHOIS_DELAY`) è azzerata. I nomi di dominio sono finti.

La catena completa (snapshot, diff, classificazione, caso) è in `tests/test_orchestrator.py`,
classi `TestCOL17*`.
"""
import subprocess

import pytest
from fastapi.testclient import TestClient

import services.whois_intel as whois_service

COM = "acme-typo.com"
DE = "acme-typo.de"
IT = "acme-typo.it"


# ── Risposte dei server ────────────────────────────────────────────────────

def _com_registry(registrar_server):
    """Record sottile del registro .com (Verisign): registrar, date, stato, name server. Se
    `registrar_server` è un host, il record lo nomina e la libreria interroga anche quello."""
    referral = f"   Registrar WHOIS Server: {registrar_server}\r\n" if registrar_server else ""
    return ("   Domain Name: ACME-TYPO.COM\r\n"
            "   Registry Domain ID: 1_DOMAIN_COM-VRSN\r\n"
            + referral +
            "   Registrar URL: http://www.registrar.example\r\n"
            "   Updated Date: 2026-05-01T10:00:00Z\r\n"
            "   Creation Date: 2020-01-01T00:00:00Z\r\n"
            "   Registry Expiry Date: 2027-01-01T00:00:00Z\r\n"
            "   Registrar: Registrar Example Inc.\r\n"
            "   Domain Status: clientTransferProhibited\r\n"
            "   Name Server: NS1.ACME-TYPO.COM\r\n"
            "   DNSSEC: unsigned\r\n")


_REGISTRANT_VISIBLE = ("Registrant Name: Reg Name\r\n"
                       "Registrant Organization: Reg Name Srl\r\n"
                       "Registrant Country: ZZ\r\n")
_REGISTRANT_REDACTED = ("Registrant Name: REDACTED FOR PRIVACY\r\n"
                        "Registrant Organization: Domains By Proxy, LLC\r\n")

_DE_RECORD = ("Domain: acme-typo.de\n"
              "Nserver: ns1.acme-typo.de\n"
              "Status: connect\n"
              "Changed: 2026-05-01T10:00:00+02:00\n")

_NOT_REGISTERED_COM = ('No match for "ACME-TYPO.COM".\r\n'
                       ">>> Last update of whois database: 2026-11-02T00:00:00Z <<<\r\n")

_RATE_LIMIT = "Query rate limit exceeded. Please retry later.\r\n"


# ── Fixture ────────────────────────────────────────────────────────────────

@pytest.fixture
def lookup(whois_network, monkeypatch):
    """`lookup(dominio)` interroga GET /whois sul servizio vero, libreria inclusa. Ogni chiamata è una
    raccolta da zero (cache svuotata) e non attende fra le richieste. Ritorna il corpo JSON."""
    monkeypatch.setattr(whois_service, "WHOIS_DELAY", 0.0)
    monkeypatch.setattr(whois_service, "HAS_WHOIS_LIB", True)
    monkeypatch.setattr(whois_service, "_cache", {})
    monkeypatch.setattr(whois_service, "_cache_order", [])
    api = TestClient(whois_service.app)

    def call(domain):
        whois_service._cache.clear()
        whois_service._cache_order.clear()
        response = api.get("/whois", params={"domain": domain})
        assert response.status_code == 200, response.text
        return response.json()

    return call


def _shape(body):
    """La risposta senza l'istante e senza `error`: ciò che resta quando non si è osservato nulla."""
    return {key: value for key, value in body.items() if key not in ("timestamp", "error")}


def _empty_shape(domain):
    return {"domain": domain, "registrar": None, "creation_date": None, "expiration_date": None,
            "updated_date": None, "status": [], "nameservers": [],
            "registrant": {"name": None, "org": None, "country": None, "email": None},
            "privacy_protected": False, "dnssec": False, "age_days": None}


# ── Guasti del registro: nessun campo osservato ────────────────────────────

_OUTAGE_KINDS = ["refused", "timeout", "reset", "empty-answer", "rate-limit"]
_OUTAGES = [pytest.param(tld, kind, id=f"{tld}-{kind}") for tld in ("com", "de") for kind in _OUTAGE_KINDS]
_DOMAIN_OF = {"com": COM, "de": DE}


def _break_registry(network, tld, kind):
    """Il server del registro non dà un record. Ritorna i frammenti di testo grezzo che un messaggio
    del servizio non deve riportare: quelli che la libreria incorpora nel proprio testo d'errore, o
    l'avviso del registro."""
    failures = {"refused": network.REFUSED, "timeout": network.TIMEOUT, "reset": network.RESET}
    if kind in failures:
        network.registry(tld, failures[kind])
        return ["Socket not responding", "Errno", failures[kind].text]
    network.registry(tld, "" if kind == "empty-answer" else _RATE_LIMIT)
    return [] if kind == "empty-answer" else [_RATE_LIMIT.strip()]


class TestCOL17RegistryOutageIsACollectionError:
    """Un registro che non risponde, risponde senza dati o oppone un limite di richieste dà un errore di raccolta."""

    @pytest.mark.parametrize("tld, kind", _OUTAGES)
    def test_the_response_carries_an_error(self, lookup, whois_network, tld, kind):
        _break_registry(whois_network, tld, kind)

        body = lookup(_DOMAIN_OF[tld])

        error = body["error"]
        assert isinstance(error, str) and error.strip(), (
            f"{tld}/{kind}: nessun campo osservato ma `error` è {error!r}, quindi la raccolta risulta "
            f"riuscita (campi: {_shape(body)})")

    @pytest.mark.parametrize("tld, kind", _OUTAGES)
    def test_the_error_is_the_services_own_text_and_not_the_librarys(self, lookup, whois_network, tld, kind):
        raw = _break_registry(whois_network, tld, kind)

        error = lookup(_DOMAIN_OF[tld])["error"]

        assert isinstance(error, str) and error.strip(), f"{tld}/{kind}: `error` è {error!r}, atteso un testo"
        leaked = [fragment for fragment in raw if fragment in error]
        assert not leaked, f"{tld}/{kind}: il testo grezzo della libreria o del registro è in `error`: {error!r}"

    @pytest.mark.parametrize("tld, kind", _OUTAGES)
    def test_the_response_has_the_shape_of_a_failed_lookup(self, lookup, whois_network, tld, kind):
        # `privacy_protected` si deduce da un registrante: senza record non c'è nulla da dedurre.
        _break_registry(whois_network, tld, kind)

        body = lookup(_DOMAIN_OF[tld])

        assert _shape(body) == _empty_shape(_DOMAIN_OF[tld]), f"{tld}/{kind}: {body}"

    def test_every_empty_outcome_gets_the_same_error_text(self, lookup, whois_network):
        errors = {}
        for tld in ("com", "de"):
            for kind in _OUTAGE_KINDS:
                _break_registry(whois_network, tld, kind)
                errors[f"{tld}/{kind}"] = lookup(_DOMAIN_OF[tld])["error"]

        assert all(isinstance(e, str) and e.strip() for e in errors.values()), (
            f"forme senza `error` valorizzato: {[k for k, e in errors.items() if not (isinstance(e, str) and e.strip())]}")
        assert len(set(errors.values())) == 1, f"testi diversi per forme equivalenti: {errors}"

    def test_a_record_with_only_a_dnssec_flag_is_still_empty(self, lookup, whois_network):
        # `dnssec` è dedotto da una riga di stato e non descrive il dominio: da solo non è un'osservazione.
        whois_network.registry("com", "   DNSSEC: signedDelegation\r\n")

        body = lookup(COM)

        assert isinstance(body["error"], str) and body["error"].strip(), (
            f"un record con la sola riga DNSSEC risulta una raccolta riuscita: {body}")

    def test_a_record_with_only_a_dnssec_flag_has_the_shape_of_a_failed_lookup(self, lookup, whois_network):
        # La risposta di un errore di raccolta non porta nemmeno il flag che la libreria ha letto.
        whois_network.registry("com", "   DNSSEC: signedDelegation\r\n")

        body = lookup(COM)

        assert _shape(body) == _empty_shape(COM), body


class TestCOL17FailedCollectionIsServedFromTheCache:
    """L'esito di una raccolta fallita lascia il servizio dallo stesso percorso di uscita degli altri:
    viene memorizzato, e la richiesta successiva per lo stesso dominio non interroga la rete."""

    @pytest.mark.parametrize("kind", ["refused", "empty-answer"])
    def test_the_second_request_does_not_query_the_network_and_gets_the_same_error(
            self, lookup, whois_network, kind):
        # `lookup` svuota la cache a ogni chiamata: qui serve il client, senza svuotarla.
        api = TestClient(whois_service.app)
        _break_registry(whois_network, "com", kind)

        first = api.get("/whois", params={"domain": COM}).json()
        queried = len(whois_network.contacted)
        second = api.get("/whois", params={"domain": COM}).json()

        assert isinstance(first["error"], str) and first["error"].strip(), f"precondizione: {first}"
        assert queried > 0, "precondizione: la prima richiesta interroga la rete"
        assert len(whois_network.contacted) == queried, (
            f"la seconda richiesta ha interrogato la rete: {whois_network.contacted[queried:]}")
        assert second["error"] == first["error"], (first["error"], second["error"])


_NOTICE_WITH_ADDRESS = "Query rate limit exceeded. Contact whois-abuse@registry.example for details.\r\n"
_ADDRESS = "whois-abuse@registry.example"


class TestCOL17ContactAddressIsNotAnObservedField:
    """La libreria raccoglie in `emails` qualunque indirizzo presente nel testo, e il servizio lo espone
    come `registrant.email`. Un avviso del registro che nomina un indirizzo di contatto e non ha altri campi
    non è un'osservazione del dominio."""

    @pytest.mark.parametrize("tld", ["com", "de"])
    def test_a_notice_with_only_a_contact_address_is_a_collection_error(self, lookup, whois_network, tld):
        whois_network.registry(tld, _NOTICE_WITH_ADDRESS)

        body = lookup(_DOMAIN_OF[tld])

        error = body["error"]
        assert isinstance(error, str) and error.strip(), (
            f"{tld}: avviso con un indirizzo di contatto e nessun altro campo, ma `error` è {error!r} "
            f"(registrant: {body['registrant']})")
        assert _ADDRESS not in error, f"{tld}: l'indirizzo del testo del registro è in `error`: {error!r}"

    @pytest.mark.parametrize("tld", ["com", "de"])
    def test_the_contact_address_does_not_survive_in_the_failed_response(self, lookup, whois_network, tld):
        whois_network.registry(tld, _NOTICE_WITH_ADDRESS)

        body = lookup(_DOMAIN_OF[tld])

        assert _shape(body) == _empty_shape(_DOMAIN_OF[tld]), f"{tld}: {body}"


class TestCOL17LookupErrorsAreErrors:
    """Controllo: la libreria che solleva (IANA irraggiungibile) e il dominio sconosciuto al registro sono errori
    di raccolta, con la forma di una raccolta fallita."""

    def test_an_unreachable_iana_is_an_error_with_the_failed_shape(self, lookup, whois_network):
        whois_network.iana(whois_network.REFUSED)

        body = lookup(COM)

        assert isinstance(body["error"], str) and body["error"].strip(), body
        assert _shape(body) == _empty_shape(COM)

    def test_a_domain_the_registry_does_not_know_is_an_error(self, lookup, whois_network):
        whois_network.registry("com", _NOT_REGISTERED_COM)

        body = lookup(COM)

        assert isinstance(body["error"], str) and body["error"].strip(), body
        assert _shape(body) == _empty_shape(COM)


# ── Record con almeno un campo: restano osservazioni ───────────────────────

_OBSERVED = [
    # (tld, risposta del registro, risposta del secondo hop o None)
    pytest.param("com", _com_registry("whois.registrar.example"), _REGISTRANT_VISIBLE, id="com-full-record"),
    pytest.param("com", _com_registry("whois.registrar.example"), _REGISTRANT_REDACTED,
                 id="com-redacted-registrant"),
    pytest.param("com", _com_registry(None), None, id="com-gdpr-record-without-registrant"),
    pytest.param("de", _DE_RECORD, None, id="de-record-without-registrar-and-creation-date"),
    pytest.param("it", "Domain:             acme-typo.it\nStatus:             AVAILABLE\n", None,
                 id="it-status-only-available"),
    pytest.param("it", "Domain:             acme-typo.it\nStatus:             UNASSIGNABLE\n", None,
                 id="it-status-only-unassignable"),
]
_OBSERVED_DOMAIN = {"com": COM, "de": DE, "it": IT}


class TestCOL17ARecordWithAFieldIsAnObservation:
    """Controllo: un record leggibile, anche povero o redatto, non è un errore di raccolta."""

    @pytest.mark.parametrize("tld, registry, registrar", _OBSERVED)
    def test_no_error_is_reported(self, lookup, whois_network, tld, registry, registrar):
        whois_network.registry(tld, registry)
        if registrar is not None:
            whois_network.registrar(registrar)

        body = lookup(_OBSERVED_DOMAIN[tld])

        assert body["error"] is None, body

    @pytest.mark.parametrize("registry_fields", [
        pytest.param("   Registrar: Registrar Example Inc.\r\n", id="registrar"),
        pytest.param("   Creation Date: 2020-01-01T00:00:00Z\r\n", id="creation-date"),
        pytest.param("   Registry Expiry Date: 2027-01-01T00:00:00Z\r\n", id="expiration-date"),
        pytest.param("   Updated Date: 2026-05-01T10:00:00Z\r\n", id="updated-date"),
        pytest.param("   Domain Status: clientTransferProhibited\r\n", id="status"),
        pytest.param("   Name Server: NS1.ACME-TYPO.COM\r\n", id="name-server"),
        pytest.param("   Registrant Name: Reg Name\r\n", id="registrant-name"),
        pytest.param("   Registrant Organization: Reg Name Srl\r\n", id="registrant-organization"),
        pytest.param("   Registrant Country: ZZ\r\n", id="registrant-country"),
    ])
    def test_one_observed_field_is_enough(self, lookup, whois_network, registry_fields):
        whois_network.registry("com", registry_fields)

        body = lookup(COM)

        assert body["error"] is None, f"un solo campo osservato dà un errore di raccolta: {body}"

    def test_a_record_without_a_registrant_is_still_read_as_privacy_protected(self, lookup, whois_network):
        # L'inferenza sul registrante vale per le osservazioni: un registro che ha risposto senza
        # registrante dice che i dati sono schermati.
        whois_network.registry("com", _com_registry(None))

        body = lookup(COM)

        assert body["error"] is None and body["registrar"] == "Registrar Example Inc.", body
        assert body["privacy_protected"] is True, body

    def test_a_record_with_a_visible_registrant_is_not_privacy_protected(self, lookup, whois_network):
        whois_network.registry("com", _com_registry(whois_network.REGISTRAR))
        whois_network.registrar(_REGISTRANT_VISIBLE)

        body = lookup(COM)

        assert body["error"] is None and body["registrant"]["name"] == "Reg Name", body
        assert body["privacy_protected"] is False, body

    def test_a_record_with_a_registrant_and_an_address_keeps_the_address(self, lookup, whois_network):
        # Controllo: l'indirizzo non conta come campo osservato, ma resta un dato del record che lo contiene.
        whois_network.registry("com", _com_registry(whois_network.REGISTRAR))
        whois_network.registrar(_REGISTRANT_VISIBLE + "Registrant Email: owner@registrant.example\r\n")

        body = lookup(COM)

        assert body["error"] is None, body
        assert body["registrant"]["email"] == "owner@registrant.example", body


# ── Ramo CLI ───────────────────────────────────────────────────────────────

_CLI_RECORD = _com_registry("whois.registrar.example")


@pytest.fixture
def cli(lookup, monkeypatch):
    """`cli(stdout, returncode, stderr)`: il servizio senza la libreria, con un `whois(1)` che stampa
    quanto dato. `cli(raises=...)`: il binario non parte."""
    monkeypatch.setattr(whois_service, "HAS_WHOIS_LIB", False)

    def run(stdout="", returncode=0, stderr="", raises=None, domain=COM):
        def fake_run(argv, *args, **kwargs):
            if raises is not None:
                raise raises
            return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

        monkeypatch.setattr(whois_service.subprocess, "run", fake_run)
        return lookup(domain)

    return run


class TestCOL17CliBranchFollowsTheSameRule:
    """Senza la libreria il servizio usa `whois(1)`: il controllo sul risultato finale vale anche qui."""

    @pytest.mark.parametrize("stdout, returncode, stderr", [
        pytest.param("", 2, "whois: connect: Connection refused", id="client-prints-nothing-and-fails"),
        pytest.param("", 0, "", id="client-prints-nothing"),
        pytest.param(_RATE_LIMIT, 0, "", id="registry-notice-without-fields"),
    ])
    def test_an_output_without_fields_is_an_error(self, cli, stdout, returncode, stderr):
        body = cli(stdout, returncode, stderr)

        assert isinstance(body["error"], str) and body["error"].strip(), (
            f"nessun campo letto dal client CLI ma `error` è {body['error']!r}: {_shape(body)}")
        assert _shape(body) == _empty_shape(COM)

    def test_the_cli_error_is_not_the_raw_client_output(self, cli):
        body = cli(_RATE_LIMIT, 0, "whois: connect: Connection refused")

        assert isinstance(body["error"], str) and body["error"].strip(), body
        assert _RATE_LIMIT.strip() not in body["error"] and "Connection refused" not in body["error"], body["error"]

    def test_the_cli_and_the_library_report_the_same_error_for_an_empty_outcome(
            self, cli, lookup, whois_network, monkeypatch):
        via_cli = cli("", 2, "whois: connect: Connection refused")["error"]
        monkeypatch.setattr(whois_service, "HAS_WHOIS_LIB", True)
        whois_network.registry("com", whois_network.REFUSED)

        via_library = lookup(COM)["error"]

        assert isinstance(via_cli, str) and via_cli.strip(), f"ramo CLI: {via_cli!r}"
        assert via_cli == via_library, (via_cli, via_library)

    def test_an_output_with_a_record_is_an_observation(self, cli):
        # Controllo.
        body = cli(_CLI_RECORD)

        assert body["error"] is None and body["registrar"] == "Registrar Example Inc.", body

    def test_a_client_that_cannot_start_is_an_error(self, cli):
        # Controllo.
        body = cli(raises=FileNotFoundError(2, "No such file or directory: 'whois'"))

        assert isinstance(body["error"], str) and body["error"].strip(), body

    def test_a_client_that_cannot_start_reports_the_fixed_error_text_of_the_other_empty_outcomes(
            self, cli, lookup, whois_network, monkeypatch):
        failure = FileNotFoundError(2, "No such file or directory: 'whois'")
        via_cli = cli(raises=failure)["error"]
        monkeypatch.setattr(whois_service, "HAS_WHOIS_LIB", True)
        whois_network.registry("com", whois_network.REFUSED)

        via_library = lookup(COM)["error"]

        assert isinstance(via_cli, str) and via_cli.strip(), f"ramo CLI: {via_cli!r}"
        assert via_cli == via_library, (via_cli, via_library)
        leaked = [fragment for fragment in ("CLI fallback", "Errno", str(failure)) if fragment in via_cli]
        assert not leaked, f"il testo interno del ramo CLI è in `error`: {via_cli!r}"

    def test_a_client_that_cannot_start_has_the_shape_of_a_failed_lookup(self, cli):
        body = cli(raises=FileNotFoundError(2, "No such file or directory: 'whois'"))

        assert _shape(body) == _empty_shape(COM), body
