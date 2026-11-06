"""Tests for services/cert_intel.py — Certificate Transparency collector (COL-04).

Isolamento di rete: **nessuna chiamata reale a crt.sh**. Il doppio patcha
`cert_intel.http_get_with_retry` (il nome importato nel namespace del modulo, la
stessa tecnica di monkeypatch già usata in `tests/test_orchestrator.py` per
`o.intel_store.load_snapshot`/`save_snapshot`) con una funzione locale che conta le
invocazioni e restituisce dati fissi in memoria. Nessun socket viene aperto.

Riferimento: BUG-REGISTER.md, COL-04 "Enrichment Certificate Transparency assente o
azzerato" — evidenza: `crt.sh HTTP 502` osservato su un insieme di snapshot reali (la
maggior parte dei domini con `cert.total = 0`), causa "instabilità del
servizio esterno o rate limiting sull'IP di uscita". Correzione richiesta dal registro:
"Retry con backoff esponenziale, cache locale con TTL, sorgente CT alternativa in
fallback."

Nota di scope (vedi rapporto a `pm`): la voce COL-04 non ha una sezione "Criterio di
accettazione" dedicata (a differenza di CODE-01, COL-06, CLS-01*): la "Correzione"
elenca quattro interventi senza valore di TTL, senza nome della sorgente CT
alternativa e senza il nome del campo di stato per dominio. Di questi quattro, solo
"cache locale con TTL" è oggi verificabile senza inventare un contratto: la sua
assenza si osserva direttamente in `services/cert_intel.py`, che non importa né usa
alcun meccanismo di cache — ogni chiamata a `/cert` esegue una query di rete
indipendente, anche per lo stesso dominio a distanza di millisecondi nella stessa
esecuzione della pipeline. Questo file copre solo quel sotto-comportamento.

Controlli verdi di contrasto (dichiarati, non nel file): `http_get_with_retry`
(`shared/utils.py:103`) implementa già backoff esponenziale su 429/500/502/503/504 —
quella parte della correzione non è testata qui perché non è rossa: è già presente a
monte del collector, testarla in questo file sarebbe tautologico.
"""
import json

from fastapi.testclient import TestClient

from services import cert_intel
from services.cert_intel import app

client = TestClient(app)


def _crtsh_ok(certs):
    """Simula una risposta 200 di crt.sh con la lista di certificati data."""
    return {
        "status_code": 200,
        "content": json.dumps(certs).encode(),
        "headers": {},
        "final_url": None,
        "error": None,
        "attempts": 1,
    }


class TestCertTransparencyCache:
    """COL-04 — assenza di cache locale con TTL nel collector CT."""

    def test_repeated_query_same_domain_does_not_repeat_network_call(self, monkeypatch):
        """Due interrogazioni consecutive di /cert per lo stesso dominio, a distanza
        di pochi millisecondi (stessa esecuzione di pipeline, es. richieste multiple
        di enrichment sullo stesso target), devono condividere il risultato: la
        seconda va servita da una cache locale, non da una seconda query a crt.sh.
        Con crt.sh che risponde 502 sulla maggior parte dei domini campionati, ogni
        interrogazione ripetuta e non necessaria è un tentativo in più contro un
        servizio già instabile — esattamente il meccanismo che COL-04 chiede di
        mitigare con una cache locale.
        """
        calls = []

        def _fake_get(url, **kwargs):
            calls.append(url)
            return _crtsh_ok([{
                "id": 1,
                "common_name": "example.com",
                "name_value": "example.com",
                "issuer_name": "Let's Encrypt",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
                "entry_timestamp": "2026-01-01T00:00:00",
            }])

        monkeypatch.setattr(cert_intel, "http_get_with_retry", _fake_get)

        r1 = client.get("/cert", params={"domain": "example.com"})
        r2 = client.get("/cert", params={"domain": "example.com"})

        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r1.json()["ct_certificates"]["total"] == 1
        assert r2.json()["ct_certificates"]["total"] == 1
        assert len(calls) == 1, (
            f"atteso 1 sola chiamata di rete verso crt.sh (la seconda /cert servita "
            f"da cache locale), osservate {len(calls)}: services/cert_intel.py non "
            f"implementa alcuna cache — ogni richiesta ripete la query, anche a "
            f"distanza di millisecondi per lo stesso dominio (COL-04)"
        )

    def test_error_result_is_not_served_from_cache_once_crtsh_recovers(self, monkeypatch):
        """Rilievo del G6 su COL-04: la cache introdotta dal fix non distingue un
        esito di ERRORE da un esito valido — entrambi sono memorizzati con lo stesso
        TTL di 300s. Con crt.sh che risponde 502 sulla maggior parte dei domini
        campionati (vedi intestazione del file), è il caso comune, non un caso di
        bordo. Scenario riprodotto dal verifier: prima /cert per un dominio riceve un
        errore da crt.sh; una seconda /cert per lo **stesso** dominio, entro la
        finestra TTL, con crt.sh tornato a rispondere 200 con dati validi, deve
        **andare in rete** e restituire i dati veri — non l'errore cachato. È esattamente
        lo scenario descritto in CLAUDE.md §8: un operatore che ritriggera dopo aver
        visto `cert.total = 0` resta bloccato per l'intera finestra TTL anche se
        crt.sh è già tornato disponibile.

        Contratto complessivo, entrambe le direzioni devono valere insieme (un fix che
        disabilitasse la cache del tutto supererebbe solo questo test, non il
        contratto): esito VALIDO → cachato (coperto sopra da
        `test_repeated_query_same_domain_does_not_repeat_network_call`, non ripetuto
        qui perché sarebbe tautologico); esito di ERRORE → non cachato con lo stesso
        TTL, verificato qui.

        Isolamento: la cache è stato di modulo (`cert_intel._ct_cache`,
        `_ct_cache_order`). Questo test usa un dominio dedicato, non impiegato da
        nessun altro test del file (né dal test sopra, né da eventuali test futuri),
        e rimuove esplicitamente la propria chiave di cache sia prima sia dopo
        l'esecuzione (blocco `finally`), così non eredita né lascia stato che
        influenzi altri test dello stesso modulo, incluso quello che verifica la
        direzione opposta del contratto.
        """
        domain = "flaky-recovery.example.com"
        cache_key = (domain, True)  # include_subdomains di default è True

        def _clear():
            cert_intel._ct_cache.pop(cache_key, None)
            if cache_key in cert_intel._ct_cache_order:
                cert_intel._ct_cache_order.remove(cache_key)

        _clear()  # non eredita stato lasciato da un'esecuzione precedente

        calls = []

        def _fake_get(url, **kwargs):
            calls.append(url)
            if len(calls) == 1:
                # Prima chiamata: crt.sh non disponibile (502), il caso comune nel
                # registro (la maggior parte dei domini campionati).
                return {
                    "status_code": 502,
                    "content": None,
                    "headers": {},
                    "final_url": None,
                    "error": "Bad Gateway",
                    "attempts": 2,
                }
            # Seconda chiamata: crt.sh nel frattempo è tornato disponibile.
            return _crtsh_ok([{
                "id": 2,
                "common_name": domain,
                "name_value": domain,
                "issuer_name": "Let's Encrypt",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2026-04-01T00:00:00",
                "entry_timestamp": "2026-01-01T00:00:00",
            }])

        monkeypatch.setattr(cert_intel, "http_get_with_retry", _fake_get)

        try:
            r1 = client.get("/cert", params={"domain": domain})
            assert r1.status_code == 200
            assert r1.json()["error"] is not None, "prima chiamata deve riportare l'errore crt.sh"
            assert r1.json()["ct_certificates"]["total"] == 0

            r2 = client.get("/cert", params={"domain": domain})

            assert len(calls) == 2, (
                f"atteso che la seconda /cert per lo stesso dominio, con crt.sh "
                f"tornato disponibile, vada in rete invece di essere servita "
                f"dall'errore cachato (cache_key={cache_key}); chiamate di rete "
                f"osservate: {len(calls)}, esito cachato dopo r1: "
                f"{cert_intel._ct_cache.get(cache_key)}"
            )
            assert r2.status_code == 200
            assert r2.json()["error"] is None, (
                f"la seconda risposta riporta ancora l'errore cachato invece dei "
                f"dati reali di crt.sh: {r2.json()['error']!r}"
            )
            assert r2.json()["ct_certificates"]["total"] == 1
        finally:
            _clear()  # non lascia stato che influenzi altri test
