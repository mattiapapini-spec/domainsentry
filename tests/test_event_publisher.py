"""Tests for services/event_publisher.py — GET /events read path (CODE-07).

Scrive esclusivamente in `tmp_path` di pytest (mai `/data`, mai i percorsi reali di
`EVENTS_DIR`): la fixture `ep` punta `EVENTS_DIR` a `tmp_path` prima di (ri)caricare
il modulo, seguendo la stessa tecnica di `monkeypatch.setenv` + `importlib.reload`
già usata in `tests/test_orchestrator.py` (fixture `orch`).

Riferimento: BUG-REGISTER.md, CODE-07 — `get_events` (`services/event_publisher.py:
99-113`) legge l'intero file NDJSON riga per riga e lo deserializza per intero in
memoria ad ogni chiamata `GET /events`, indipendentemente dal parametro `last`.

Criterio di accettazione (riscritto dal PM il 2026-07-28), tre punti, due fixture
obbligatorie e distinte:

1. Con `client=None` e un `last` esplicito più piccolo del totale delle righe,
   `get_events` non deve deserializzare (`json.loads`) più di O(`last`) righe.
   → `TestGetEventsClientNoneDeserializationCost` — **rosso ora** (il codice attuale
     deserializza sempre l'intero file).

2. Con `client` impostato, un'implementazione che legge "le ultime N righe grezze e
   poi filtra" è esplicitamente sbagliata: deve invece trovare i match anche quando
   sono concentrati in righe vecchie, ben oltre qualunque finestra a coda
   ragionevole. → `TestGetEventsClientFilterFindsOldMatches`.

   Controllo verde di contrasto (dichiarato qui, non tautologico): questa fixture
   **passa già oggi**, perché l'implementazione attuale (bacata sul lato costo)
   scansiona comunque l'intero file per costruire la lista dei match prima di fare
   lo slicing finale — quindi trova correttamente anche i match vecchi. Non è
   quindi il test che dimostra CODE-07 (quello è il punto 1 sopra); è la guardia
   che il registro impone esplicitamente contro un fix "veloce ma sbagliato"
   (lettura a finestra fissa poi filtro) che romperebbe la correttezza per
   guadagnare in performance. Se un fix futuro la fa fallire, il fix è da
   respingere anche se il test del punto 1 è verde.

3. Nessuna regressione sul contratto (`total`, contenuto, ordine) a parità di
   `client`/`last` — verificato per costruzione in entrambe le classi sopra tramite
   le asserzioni su `total` e sull'ordine degli eventi restituiti.
"""

import importlib
import json as json_module
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def ep(tmp_path, monkeypatch):
    """(Ri)carica services.event_publisher con EVENTS_DIR puntato a tmp_path."""
    monkeypatch.setenv("EVENTS_DIR", str(tmp_path))
    import services.event_publisher as event_publisher
    importlib.reload(event_publisher)
    return event_publisher


def _write_ndjson(path, events):
    with open(path, "w") as f:
        for event in events:
            f.write(json_module.dumps(event) + "\n")


class TestGetEventsClientNoneDeserializationCost:
    """CODE-07, criterio #1: client=None + last esplicito → costo O(last), non O(N)."""

    def test_client_none_does_not_deserialize_full_file(self, ep, tmp_path, monkeypatch):
        ndjson_path = tmp_path / "soc_events.ndjson"
        total_rows = 500
        last = 5
        events = [{"domain": f"d{i}.example.com", "client": "acme"} for i in range(total_rows)]
        _write_ndjson(ndjson_path, events)

        calls = []
        real_loads = json_module.loads

        def counting_loads(s, *args, **kwargs):
            calls.append(s)
            return real_loads(s, *args, **kwargs)

        # `ep.json` è lo stesso oggetto modulo `json` globale (import condiviso):
        # monkeypatch lo ripristina automaticamente a fine test.
        monkeypatch.setattr(ep.json, "loads", counting_loads)

        result = ep.get_events(client=None, last=last)

        assert len(calls) <= last, (
            f"get_events ha chiamato json.loads {len(calls)} volte per last={last} "
            f"su un file di {total_rows} righe: dovrebbe restare vicino a O(last), "
            f"non deserializzare l'intero file."
        )
        # Nessuna regressione sul contratto: stesso total, stesso contenuto, stesso ordine.
        assert result["total"] == total_rows
        assert len(result["events"]) == last
        assert result["events"] == events[-last:]


class TestGetEventsClientFilterFindsOldMatches:
    """CODE-07, criterio #2: con `client` impostato, i match vanno trovati anche se
    concentrati in righe vecchie, oltre qualunque finestra a coda ragionevole.

    Controllo verde di contrasto: vedi il docstring di modulo. Questo test passa già
    sul codice attuale (full-scan sempre corretto, solo costoso); serve a bloccare un
    fix che ottimizzi il caso client=None leggendo una finestra a coda fissa e
    applicandola anche (o per errore) al caso client-filtrato.
    """

    def test_old_matches_beyond_any_tail_window_are_found(self, ep, tmp_path):
        ndjson_path = tmp_path / "soc_events.ndjson"
        total_rows = 2000
        last = 10

        # I match per "acme" sono SOLO nelle primissime righe del file: qualunque
        # lettura "ultime N righe grezze" con N ragionevole (anche qualche centinaio)
        # non le vedrebbe mai.
        matching = [{"domain": f"acme-{i}.example.com", "client": "acme"} for i in range(3)]
        other = [{"domain": f"other-{i}.example.com", "client": "other-client"}
                 for i in range(total_rows - len(matching))]
        events = matching + other
        _write_ndjson(ndjson_path, events)

        result = ep.get_events(client="acme", last=last)

        assert result["total"] == len(matching), (
            f"attesi {len(matching)} eventi per client='acme' (concentrati nelle righe "
            f"più vecchie del file), trovati {result['total']}: un'implementazione a "
            f"finestra fissa seguita da filtro li perderebbe."
        )
        assert result["events"] == matching
        assert all(e["client"] == "acme" for e in result["events"])


class TestGetEventsOversizedLastNoUnhandled500:
    """Regressione introdotta dal fix di CODE-07, emersa al G6 (verifier: INSUFFICIENTE).

    Il ramo ottimizzato (`client=None`, `last > 0`) costruisce `deque(maxlen=last)`.
    `deque.maxlen` è convertito internamente in `Py_ssize_t` (C); un `last` intero
    sintatticamente valido ma oltre `sys.maxsize` fa sollevare
    `OverflowError: Python int too large to convert to C ssize_t`, non catturata da
    nessun handler (né locale né globale — `shared/security.py::apply_security`
    aggiunge solo middleware di header/dimensione richiesta, nessun exception
    handler), che propaga fino a un 500 Internal Server Error di Starlette.

    Il ramo pre-fix faceva invece `events[-last:]`: lo slicing di liste Python non ha
    quel limite (accetta interi a precisione arbitraria), quindi lo stesso input
    rispondeva 200. `GET /events` è in zona non autenticata per design (CLAUDE.md
    §1.5) e `last` è un query param interamente attaccante-controllabile: FastAPI lo
    valida solo come `int` (precisione arbitraria in Python), quindi qualunque
    grandezza sintatticamente valida supera la validazione — a differenza di valori
    non interi (`abc`, `3.5`), che restano correttamente un 422 e non sono oggetto di
    questo test.

    Il test usa `fastapi.testclient.TestClient` sul router reale (`ep.app`, che ha già
    `apply_security` applicato e il router incluso, esattamente come in produzione),
    non la chiamata diretta a `get_events`: la regressione si manifesta come 500 HTTP
    osservabile dal client, non come eccezione Python isolata.

    Il test NON impone quale delle due correzioni sia quella giusta — 200 "come
    prima del fix" oppure un 4xx esplicito e gestito. Asserisce solo (a) che la
    risposta non sia un 5xx e (b) che, quando la risposta è 200, il contratto di
    ritorno (`events`, `total`) resti coerente col contenuto del file. Se il fix
    scegliesse un 4xx, il punto (b) semplicemente non si applica in quel branch di
    parametrizzazione: nessuna delle due scelte fa fallire il test.

    Controlli di contrasto (dichiarati, non tautologici): `last` normale positivo,
    `last=0` e `last` negativo sono confermati identici pre e post fix (verificati
    empiricamente dal verifier al G6) — inclusi qui solo per assicurare che
    un'eventuale correzione della regressione non li rompa incidentalmente.
    """

    @pytest.mark.parametrize("last", [
        pytest.param(sys.maxsize, id="sys.maxsize-esatto"),
        pytest.param(sys.maxsize + 1, id="sys.maxsize+1"),
        pytest.param(99999999999999999999999999, id="molto-oltre-maxsize"),
    ])
    def test_oversized_last_does_not_produce_500(self, ep, tmp_path, last):
        ndjson_path = tmp_path / "soc_events.ndjson"
        events = [{"domain": f"d{i}.example.com", "client": "acme"} for i in range(10)]
        _write_ndjson(ndjson_path, events)

        client = TestClient(ep.app, raise_server_exceptions=False)
        response = client.get("/events", params={"last": last})

        assert response.status_code < 500, (
            f"GET /events?last={last} ha risposto {response.status_code}: un query "
            f"param interamente attaccante-controllabile, su una rotta non "
            f"autenticata per design, non deve poter produrre un errore server non "
            f"gestito (body: {response.text[:200]!r})."
        )
        if response.status_code == 200:
            body = response.json()
            assert set(body.keys()) >= {"events", "total"}
            assert body["total"] == len(events)

    @pytest.mark.parametrize("last", [
        pytest.param(5, id="last-normale"),
        pytest.param(0, id="last-zero"),
        pytest.param(-3, id="last-negativo"),
    ])
    def test_non_oversized_last_unaffected_contrast_check(self, ep, tmp_path, last):
        """Controllo verde di contrasto: questi valori sono identici pre/post fix
        (confermato dal verifier al G6) — non dimostrano la regressione, servono a
        delimitarla e a bloccare un fix che la corregga rompendo questi casi."""
        ndjson_path = tmp_path / "soc_events.ndjson"
        events = [{"domain": f"d{i}.example.com", "client": "acme"} for i in range(10)]
        _write_ndjson(ndjson_path, events)

        client = TestClient(ep.app, raise_server_exceptions=False)
        response = client.get("/events", params={"last": last})

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == len(events)
