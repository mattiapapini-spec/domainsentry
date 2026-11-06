"""
Reputation service (:8005) — regressione PERF-01.

BUG-REGISTER.md `PERF-01`: `_check_vt` esegue `time.sleep(16)` in modo
incondizionato (`services/reputation.py:82`, commento "VT free: 4 req/min"),
ma lo fa **dentro il percorso di risposta stesso**, indipendentemente
dall'esito della chiamata a VirusTotal — vedi l'evidenza citata a registro:
"Eseguito anche in caso di errore o 404". La pipeline processa i domini in
sequenza, quindi ogni singola chiamata a `_check_vt` blocca l'arricchimento
per >=16s anche quando la risposta HTTP arriva istantaneamente (qui mockata)
e non contiene nulla da salvare.

Non esiste nel registro una sezione "Criterio di accettazione" dedicata a
PERF-01 (a differenza di altre voci): c'è solo l'evidenza del difetto e una
proposta di correzione ("token bucket condiviso + cache TTL"). Il
comportamento osservabile e non ambiguo che quell'evidenza descrive — e che
questo test verifica — è che il tempo di risposta di `_check_vt` non deve
dipendere da uno sleep incondizionato applicato anche quando la richiesta
HTTP non ha prodotto nulla di utile da mettere in cache (404) o è fallita
lato server (500/altro). Qualunque implementazione corretta (token bucket,
cache, o rimozione dello sleep sull'errore) rispetta questo vincolo; il
codice attuale no.

Soglia di test. Non uso un'asserzione sul *numero* di chiamate a
`time.sleep` (fragile rispetto all'implementazione: un token bucket
legittimo potrebbe comunque chiamare `time.sleep` in altri scenari, quindi
contare le invocazioni non distinguerebbe difetto da fix corretto). Uso
invece il tempo reale trascorso, con un margine di un ordine di grandezza
rispetto alla soglia nota del difetto (16s): la rete è mockata per
rispondere istantaneamente, quindi qualunque implementazione che non
blocchi la richiesta sull'intera durata del rate limit VT resta ben sotto
i 5s (meno di un terzo dei 16s del difetto) — mentre il codice attuale, che
dorme sempre 16s prima di restituire il risultato, la supera sempre per un
ampio margine, indipendentemente da variazioni di carico della macchina che
esegue il test.
"""
import contextlib
import importlib
import logging
import time

import pytest

import services.reputation as reputation


class _FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class _FakeRequestsModule:
    """Sostituisce il modulo `requests` usato da services.reputation.

    Evita `unittest.mock.patch` su `requests.get` globale (condiviso da più
    servizi importati nello stesso processo pytest) e resta locale al modulo
    sotto test, come già fatto altrove nella suite per `services.case_manager.requests`.
    """
    def __init__(self, response):
        self._response = response

    def get(self, *args, **kwargs):
        return self._response


class TestVTUnconditionalSleep:
    """PERF-01: _check_vt blocca la richiesta indipendentemente dall'esito HTTP."""

    def test_check_vt_does_not_block_on_404(self, monkeypatch):
        # VT risponde "dominio non trovato" istantaneamente (rete mockata):
        # non c'è nulla da mettere in cache né da rispettare in termini di
        # rate limit reale, eppure il codice attuale dorme comunque 16s
        # prima di restituire — è l'evidenza citata testualmente a registro
        # ("eseguito anche in caso di errore o 404").
        monkeypatch.setattr(reputation, "requests", _FakeRequestsModule(_FakeResponse(404)))

        start = time.time()
        result = reputation._check_vt("nonexistent-domain-xyz.example")
        elapsed = time.time() - start

        assert result["error"] == "not found on VT"
        assert elapsed < 5, (
            f"_check_vt ha bloccato la richiesta per {elapsed:.1f}s anche su una "
            "risposta 404 istantanea (PERF-01: sleep(16) incondizionato in "
            "services/reputation.py, eseguito anche quando non c'è nulla da "
            "salvare o mettere in cache)."
        )

    def test_check_vt_does_not_block_on_generic_http_error(self, monkeypatch):
        # Stesso difetto sul ramo "else" (qualunque status diverso da 200/404,
        # es. un 500 del servizio VT): nessun dato utile, eppure lo sleep
        # incondizionato scatta comunque.
        monkeypatch.setattr(reputation, "requests", _FakeRequestsModule(_FakeResponse(500)))

        start = time.time()
        result = reputation._check_vt("example.com")
        elapsed = time.time() - start

        assert result["error"] == "HTTP 500"
        assert elapsed < 5, (
            f"_check_vt ha bloccato la richiesta per {elapsed:.1f}s anche su un "
            "errore HTTP 500 istantaneo (PERF-01)."
        )


@contextlib.contextmanager
def _reputation_reloaded_with_env(monkeypatch, **env_vars):
    """Ricarica `services.reputation` con le env var indicate impostate,
    per esercitare il parsing reale delle variabili d'ambiente **a
    import-time** — il livello a cui il contratto deciso dall'utente per
    `PERF-01` round 4 (`BUG-REGISTER.md`, "DECISIONE utente · PERF-01 —
    fallback ai default noti-sicuri", 2026-07-31) colloca la validazione.

    Diversa deliberatamente dalla tecnica usata altrove in questo file
    (`monkeypatch.setattr(reputation, "VT_RATE_LIMIT", ...)`, vedi
    `TestVTRateLimitMisconfiguration._isolate` sopra): quella tecnica
    assegna un valore già "pronto" all'attributo di modulo e serve a
    testare il comportamento di `_vt_wait_for_slot()` a runtime dato quel
    valore, ma **salta** completamente il parsing della stringa
    d'ambiente — che è esattamente il comportamento sotto test qui (una
    env var malformata scritta dall'operatore, non un valore Python già
    valido assegnato in memoria).

    All'uscita del blocco `with` (compreso il caso di eccezione) le env
    var impostate vengono rimosse e il modulo ricaricato una seconda
    volta, così nessuno stato di parsing malformato sopravvive verso gli
    altri test di questo file — che presuppongono tutti un modulo con
    `VT_RATE_LIMIT`/`VT_RATE_WINDOW` ai valori di default o esplicitamente
    patchati da loro stessi.
    """
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    try:
        importlib.reload(reputation)
        yield reputation
    finally:
        for key in env_vars:
            monkeypatch.delenv(key, raising=False)
        importlib.reload(reputation)


class TestVTRateLimitMisconfiguration:
    """PERF-01, difetto trovato al G6 del fix del token bucket VT.

    `_vt_wait_for_slot` (services/reputation.py) usa la guardia
    `len(_vt_call_times) >= VT_RATE_LIMIT` per decidere se attendere. Con
    `VT_RATE_LIMIT <= 0` quella guardia è sempre vera anche a lista vuota
    (`len([]) >= 0` è vero), quindi il ramo che segue esegue
    `_vt_call_times[0]` su una lista vuota e solleva `IndexError`. Il
    try/except generico di `_check_vt` la cattura e la riporta come
    `error: "list index out of range"` — un messaggio indistinguibile, per
    chi legge la risposta HTTP, da un vero errore del servizio VirusTotal.
    Effetto: una misconfigurazione plausibile della variabile d'ambiente
    appena introdotta dal fix di PERF-01 spegne il modulo VT in modo
    silenzioso e permanente, camuffato da errore VT generico (stessa
    famiglia "fallito vs assente" di CODE-01, COL-02 nel registro).

    Formulazione dell'asserzione. Il mandato lascia aperta la scelta fra due
    fix legittimi — un errore di configurazione esplicito e riconoscibile,
    oppure un fallback silenzioso a un valore di default sensato — e nota
    che quella scelta cambia cosa il test può asserire con certezza: se il
    fix è "fallback", `result["error"]` può restare `None` (la chiamata
    prosegue come se il rate limit fosse quello di default); se il fix è
    "errore esplicito", `result["error"]` conterrà un messaggio nuovo e
    riconoscibile. L'unica invariante comune a entrambe le scelte, e quindi
    l'unica cosa che questo test asserisce, è che il messaggio d'errore
    osservabile nella risposta non deve mai essere il testo grezzo
    dell'eccezione Python ("list index out of range"), cioè non deve mai
    trapelare come se fosse un esito reale di VirusTotal. Non scelgo fra le
    due opzioni: la segnalo al PM invece di deciderla in questo test.

    Tecnica per variare VT_RATE_LIMIT/VT_RATE_WINDOW nei test:
    `monkeypatch.setattr` diretto sull'attributo di modulo
    (`reputation.VT_RATE_LIMIT`), non `setenv` + `importlib.reload`.
    `_vt_wait_for_slot` legge `VT_RATE_LIMIT`/`VT_RATE_WINDOW` come nomi
    globali del modulo a ogni chiamata (non li cattura in una closure
    all'import — vedi services/reputation.py:47-48), quindi patchare
    l'attributo produce esattamente lo stesso effetto pratico di un reload
    mirato, senza gli effetti collaterali di `importlib.reload`: quest'ultimo
    rieseguirebbe l'intero modulo, ricreando `reputation.app` (un nuovo
    oggetto FastAPI, potenzialmente usato altrove nello stesso processo
    pytest) e reinizializzando `_vt_rate_lock`. `monkeypatch.setattr` inoltre
    garantisce il revert automatico e puntuale a fine test, mentre un
    reload manuale richiederebbe un secondo reload esplicito in teardown per
    tornare allo stato con l'env var originale.

    Isolamento di `_vt_call_times` (stato di modulo condiviso, popolato
    anche dai due test di `TestVTUnconditionalSleep` sopra, che chiamano
    `_check_vt` con VT_RATE_LIMIT di default): ogni test qui sotto sostituisce
    `_vt_call_times` con una lista nuova via `monkeypatch.setattr` prima di
    agire, così parte sempre da uno stato vuoto; monkeypatch ripristina la
    lista precedente a fine test, quindi nessuno stato prodotto qui filtra
    verso altri test, in nessuna delle due direzioni.

    VT_RATE_WINDOW <= 0: verificato e dichiarato innocuo rispetto a questo
    specifico difetto (non produce IndexError). La riga che filtra la
    finestra (`now - t < VT_RATE_WINDOW`) con una finestra <= 0 svuota
    `_vt_call_times` a ogni chiamata *prima* del controllo di soglia, quindi
    `len(_vt_call_times) >= VT_RATE_LIMIT` resta quasi sempre falso con il
    default VT_RATE_LIMIT=4: il rate limiter smette silenziosamente di
    limitare (fail-open), invece di andare in crash (fail-closed) come nel
    caso di VT_RATE_LIMIT<=0. È un difetto di categoria diversa — throttling
    reale disattivato invece di errore camuffato — non coperto qui: lo
    segnalo al PM come possibile voce a sé invece di deciderlo in questo test.
    """

    def _isolate(self, monkeypatch, rate_limit=None, rate_window=None):
        # Stato di modulo pulito per ogni test: parte da lista vuota, patch
        # puntuale delle sole variabili che il test vuole variare, revert
        # automatico di monkeypatch a fine test.
        monkeypatch.setattr(reputation, "_vt_call_times", [])
        if rate_limit is not None:
            monkeypatch.setattr(reputation, "VT_RATE_LIMIT", rate_limit)
        if rate_window is not None:
            monkeypatch.setattr(reputation, "VT_RATE_WINDOW", rate_window)
        # Risposta VT istantanea e innocua: se il fix scelto è "fallback",
        # la chiamata a requests.get deve poter comunque completare senza
        # rete reale.
        monkeypatch.setattr(
            reputation, "requests",
            _FakeRequestsModule(_FakeResponse(200, {"data": {"attributes": {}}}))
        )

    def test_vt_rate_limit_zero_does_not_leak_index_error(self, monkeypatch, caplog):
        self._isolate(monkeypatch, rate_limit=0)

        result = reputation._check_vt("example.com")

        assert result["error"] != "list index out of range", (
            "VT_RATE_LIMIT=0 fa sollevare IndexError a _vt_wait_for_slot "
            "(len(_vt_call_times) >= 0 è sempre vero anche a lista vuota); "
            "il try/except generico di _check_vt la traveste da errore VT "
            "generico ('list index out of range'), spegnendo il modulo VT "
            "in modo silenzioso e permanente finché non si corregge la env var."
        )

        # Estensione richiesta dalla decisione utente del 2026-07-31
        # (BUG-REGISTER.md, "DECISIONE utente · PERF-01 — fallback ai
        # default noti-sicuri", punto 2): stesso controllo di log applicato
        # a TestVTRateWindowMisconfiguration sotto, qui per VT_RATE_LIMIT.
        # A differenza del blocco sopra (che patcha l'attributo già
        # parsato, quindi non attraversa mai il parsing a import-time), qui
        # si passa per la vera env var così com'è letta all'avvio: è quel
        # punto, non `_vt_wait_for_slot`, dove il contratto impone il
        # fallback silenzioso-ma-osservabile.
        with caplog.at_level(logging.WARNING, logger="reputation"):
            with _reputation_reloaded_with_env(monkeypatch, VT_RATE_LIMIT="0"):
                assert reputation.VT_RATE_LIMIT == 4, (
                    "VT_RATE_LIMIT=0 (malformato: non strettamente positivo) "
                    "deve ricadere sul default noto-sicuro 4 a import-time "
                    "(contratto PERF-01 round 4), non restare 0 né bloccare "
                    "l'avvio del modulo."
                )
        assert any("VT_RATE_LIMIT" in rec.getMessage() for rec in caplog.records), (
            "Nessun segnale di log riconoscibile per VT_RATE_LIMIT=0: il "
            "fallback al default deve essere osservabile (collegabile a "
            "CODE-14), non silenzioso — altrimenti un typo in produzione "
            "smette di limitare la quota VT senza che nessuno se ne accorga."
        )

    def test_vt_rate_limit_negative_does_not_leak_index_error(self, monkeypatch, caplog):
        self._isolate(monkeypatch, rate_limit=-1)

        result = reputation._check_vt("example.com")

        assert result["error"] != "list index out of range", (
            "VT_RATE_LIMIT=-1 riproduce lo stesso IndexError di VT_RATE_LIMIT=0 "
            "per lo stesso motivo: len(_vt_call_times) >= -1 è sempre vero."
        )

        # Stessa estensione del test precedente, per il valore negativo.
        with caplog.at_level(logging.WARNING, logger="reputation"):
            with _reputation_reloaded_with_env(monkeypatch, VT_RATE_LIMIT="-1"):
                assert reputation.VT_RATE_LIMIT == 4, (
                    "VT_RATE_LIMIT=-1 (malformato) deve ricadere sul default "
                    "noto-sicuro 4 a import-time, non restare -1 né bloccare "
                    "l'avvio del modulo."
                )
        assert any("VT_RATE_LIMIT" in rec.getMessage() for rec in caplog.records), (
            "Nessun segnale di log riconoscibile per VT_RATE_LIMIT=-1: stesso "
            "requisito di osservabilità del caso VT_RATE_LIMIT=0 sopra."
        )

    def test_vt_rate_limit_non_numeric_string_falls_back_without_crashing_startup(self, monkeypatch, caplog):
        """Copertura esplicita aggiuntiva (punto 3 del mandato G3, decisione
        utente 2026-07-31): il caso concreto citato dal verifier al round 3
        — "un typo, `\"3.5\"` su un intero" — che oggi fa fallire `int()`
        **a import-time** con `ValueError` non gestito, mandando giù
        l'intero servizio (e, in produzione, l'intera piattaforma unificata:
        `unified.py` importa `services.reputation` senza try/except). Il
        contratto round 4 richiede che anche questa classe di
        misconfigurazione (non numerica, non solo "numerica ma fuori
        soglia") ricada sul default invece di impedire l'avvio."""
        with caplog.at_level(logging.WARNING, logger="reputation"):
            with _reputation_reloaded_with_env(monkeypatch, VT_RATE_LIMIT="3.5"):
                assert reputation.VT_RATE_LIMIT == 4, (
                    "VT_RATE_LIMIT='3.5' (non un intero valido) deve ricadere "
                    "sul default noto-sicuro 4 a import-time, non impedire "
                    "l'avvio del modulo con un ValueError non gestito."
                )
        assert any("VT_RATE_LIMIT" in rec.getMessage() for rec in caplog.records), (
            "Nessun segnale di log riconoscibile per VT_RATE_LIMIT='3.5'."
        )

    def test_vt_rate_limit_default_still_works(self, monkeypatch):
        """Controllo verde di contrasto: il default dichiarato nel commento
        di PERF-01 (services/reputation.py:36, VT_RATE_LIMIT=4) non deve mai
        produrre l'errore travestito da lista vuota."""
        self._isolate(monkeypatch, rate_limit=4)

        result = reputation._check_vt("example.com")

        assert result["error"] != "list index out of range"

    def test_vt_rate_limit_valid_positive_still_works(self, monkeypatch):
        """Controllo verde di contrasto: un valore valido diverso dal
        default (2), per escludere che il default nasconda il problema."""
        self._isolate(monkeypatch, rate_limit=2)

        result = reputation._check_vt("example.com")

        assert result["error"] != "list index out of range"


class _MixedOutcomeRequestsModule:
    """Come `_FakeRequestsModule` sopra, ma registra il timestamp di ogni
    `.get()` (= ogni chiamata di rete reale verso VirusTotal) e restituisce
    un esito diverso a ogni chiamata, ciclando sulla sequenza fornita se le
    chiamate la superano. Serve a distinguere "quante volte è stata invocata
    la rete" da "quale slot ha consumato il token bucket": è esattamente la
    distinzione che una regressione del gate (spostato dopo la risposta, o
    saltato sui rami di errore) altererebbe senza che il codice smetta di
    restituire risultati plausibili."""

    def __init__(self, outcomes):
        self._outcomes = outcomes
        self.call_times = []

    def get(self, *args, **kwargs):
        self.call_times.append(time.time())
        kind, payload = self._outcomes[(len(self.call_times) - 1) % len(self._outcomes)]
        if kind == "raise":
            raise payload
        return payload


class TestVTRateLimitQuotaAcrossOutcomes:
    """PERF-01 — freeze anti-regressione permanente (chiusura dell'ID,
    punto 5 del criterio aggiornato dal PM).

    Questo test, a differenza di tutti gli altri in questo file, **non deve
    essere rosso**: congela una proprietà che oggi vale già e che finora era
    stata verificata solo a mano dal verifier al G6 (burst di 10 chiamate
    consecutive tutte in errore/404, rete istantanea: 4+4+2 in 120s, zero
    violazioni). Senza una rete di sicurezza automatica, la prossima modifica
    al rate limiter potrebbe romperla senza che nessun test se ne accorga.

    Proprietà congelata: `_vt_wait_for_slot` non deve mai permettere più di
    `VT_RATE_LIMIT` chiamate REALI a VirusTotal (`requests.get`, qui
    mockato) in nessuna finestra scorrevole di ampiezza `VT_RATE_WINDOW` —
    **indipendentemente dall'esito** di ciascuna chiamata (200, 404, 500 o
    eccezione di rete). L'indipendenza dall'esito è il punto che rende il
    test utile: un fix futuro che spostasse il gate dopo la risposta, o che
    saltasse il consumo dello slot sui rami di errore, continuerebbe a
    restituire risultati plausibili (nessun test funzionale se ne
    accorgerebbe) ma violerebbe la quota reale verso VT — ed è esattamente
    ciò che questo test misura, contando le chiamate `.get()` effettivamente
    emesse, non gli esiti restituiti.

    Perché contare le chiamate `.get()` e non le invocazioni di
    `_vt_wait_for_slot`: la quota che conta per VT è "quante richieste HTTP
    sono partite verso i suoi server", non "quante volte il codice ha
    provato a fare la guardia". Un'implementazione con un bug potrebbe
    invocare `_vt_wait_for_slot()` il numero di volte "giusto" e comunque
    lasciar partire più chiamate di rete di quelle consentite (è esattamente
    il caso dimostrato nella prova con l'implementazione rotta, vedi il
    messaggio del PM che accompagna questo commit).

    Valori ridotti e perché la proprietà verificata su di essi vale anche
    per i default (`VT_RATE_LIMIT=4`, `VT_RATE_WINDOW=60`). Uso
    `RATE_LIMIT=2`, `RATE_WINDOW=0.5s` invece dei default: con i default un
    burst di 6 chiamate richiederebbe ~60s reali di sleep, inaccettabile in
    una suite che oggi gira in ~30-37s. La riduzione è equivalente a un
    reload mirato del modulo con valori diversi di configurazione (stessa
    tecnica di `TestVTRateLimitMisconfiguration._isolate` sopra:
    `_vt_wait_for_slot` legge `VT_RATE_LIMIT`/`VT_RATE_WINDOW` come nomi
    globali del modulo a ogni chiamata, non li cattura in una closure
    all'import), e non l'algoritmo stesso: `_vt_wait_for_slot` esegue
    esattamente lo stesso codice — stesso filtro della lista per finestra
    scorrevole, stesso confronto `len(_vt_call_times) >= VT_RATE_LIMIT`,
    stesso `time.sleep` — indipendentemente dai valori numerici di
    `VT_RATE_LIMIT`/`VT_RATE_WINDOW`; i due parametri appaiono nella formula
    solo come quantità, non come rami di codice diversi. Non c'è quindi
    alcun percorso raggiungibile solo a `VT_RATE_LIMIT=4` o solo a
    `VT_RATE_WINDOW=60` e non ai valori ridotti qui usati (a differenza, per
    esempio, del difetto `VT_RATE_LIMIT<=0` in `TestVTRateLimitMisconfiguration`
    sopra, che è un ramo distinto raggiungibile solo per quel valore
    specifico — ed è proprio per questo che quel difetto ha bisogno di un
    proprio test dedicato invece di essere coperto qui). L'unico limite
    dichiarato: una finestra ridotta a `0.5s` resta ben sopra la risoluzione
    dell'orologio di sistema (microsecondi), quindi non introduce artefatti
    di arrotondamento che non si presenterebbero anche a `60s` — se il
    difetto dipendesse da un problema di precisione temporale a grana fine,
    questo test non lo coprirebbe, ma non è il tipo di difetto che il
    registro documenta per PERF-01.

    Robustezza su macchina lenta: l'asserzione controlla un limite
    INFERIORE sullo scarto fra chiamate (`span >= window - tolleranza`). Una
    macchina più lenta del previsto può solo allungare gli scarti reali, mai
    accorciarli, quindi un carico CPU maggiore non può produrre un fallimento
    spurio — può solo mascherare, nella direzione opposta, una violazione
    vera (che qui non è il caso: si esercitano più finestre consecutive,
    quindi anche un margine ampio non nasconderebbe una quota sforata
    sistematicamente).
    """

    RATE_LIMIT = 2
    RATE_WINDOW = 0.5  # secondi

    def test_no_more_than_rate_limit_real_calls_per_sliding_window_regardless_of_outcome(self, monkeypatch):
        # Isolamento dello stato di modulo condiviso, stessa tecnica di
        # TestVTRateLimitMisconfiguration._isolate sopra.
        monkeypatch.setattr(reputation, "_vt_call_times", [])
        monkeypatch.setattr(reputation, "VT_RATE_LIMIT", self.RATE_LIMIT)
        monkeypatch.setattr(reputation, "VT_RATE_WINDOW", self.RATE_WINDOW)

        # Esiti misti richiesti dal mandato: successo, 404, 500, eccezione di
        # rete — e di nuovo successo/404 per superare un intero secondo giro
        # della sequenza. Rete istantanea (nessuna latenza reale simulata):
        # l'unico tempo che passa nel test è quello dei time.sleep interni a
        # _vt_wait_for_slot.
        fake_requests = _MixedOutcomeRequestsModule([
            ("response", _FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 3}}}})),
            ("response", _FakeResponse(404)),
            ("response", _FakeResponse(500)),
            ("raise", ConnectionError("simulated network failure")),
            ("response", _FakeResponse(200, {"data": {"attributes": {}}})),
            ("response", _FakeResponse(404)),
        ])
        monkeypatch.setattr(reputation, "requests", fake_requests)

        n_calls = 6  # con RATE_LIMIT=2 esercita almeno 3 finestre consecutive
        for _ in range(n_calls):
            reputation._check_vt("example.com")

        assert len(fake_requests.call_times) == n_calls, (
            "il test presuppone che ogni _check_vt produca esattamente una "
            "chiamata .get(): se questo non è più vero, la fixture va rivista "
            "prima dell'asserzione di quota."
        )

        # Proprietà a finestra scorrevole: per qualunque sottosequenza di
        # RATE_LIMIT + 1 chiamate consecutive (ordinate per tempo), lo scarto
        # fra la prima e l'ultima deve essere almeno RATE_WINDOW — altrimenti
        # quelle RATE_LIMIT + 1 chiamate starebbero tutte nella stessa
        # finestra di ampiezza RATE_WINDOW, sforando la quota.
        call_times = sorted(fake_requests.call_times)
        tolerance = 0.05  # margine di schedulazione, non di correttezza logica
        for i in range(len(call_times) - self.RATE_LIMIT):
            span = call_times[i + self.RATE_LIMIT] - call_times[i]
            assert span >= self.RATE_WINDOW - tolerance, (
                f"{self.RATE_LIMIT + 1} chiamate reali a VT (indici {i}..{i + self.RATE_LIMIT}) "
                f"sono finite in una finestra di soli {span:.3f}s, ma la quota è "
                f"{self.RATE_LIMIT} chiamate per {self.RATE_WINDOW}s — PERF-01: il gate "
                "non ha bloccato un burst oltre la quota consentita, indipendentemente "
                "dall'esito delle chiamate."
            )


class TestVTRateWindowMisconfiguration:
    """PERF-01 round 4 — riscritti per il contratto deciso dall'utente il
    2026-07-31 (`BUG-REGISTER.md`, "DECISIONE utente · PERF-01 — fallback ai
    default noti-sicuri"), che **sostituisce** il fail-fast dei round 1-3.

    I tre test sotto (uno per `VT_RATE_WINDOW=0`, uno per un valore non
    finito — `nan`/`inf`, la classe che ha causato il fallimento del round 3
    — e uno end-to-end via `_check_vt`) presupponevano fino a oggi
    `pytest.raises(Exception)` o `result["error"] is not None`: quel
    contratto è incompatibile con quello nuovo e va abbandonato, non
    patchato. Il nuovo contratto, per una `VT_RATE_WINDOW` malformata letta
    da env a import-time:

    1. il modulo **non solleva** e **non blocca l'avvio** (nessuna
       `pytest.raises`: l'assenza di eccezione fa ora parte
       dell'asserzione, non è più un caso da escludere);
    2. il valore malformato è sostituito dal default noto-sicuro
       **esplicitamente verificato nei round 1-3** (`VT_RATE_WINDOW=60.0`),
       non da "nessun limite" — è la precisazione che l'utente ha reso
       vincolante nella decisione, non solo (ii) generica;
    3. un segnale di log riconoscibile (livello warning/error, sul logger
       `"reputation"`, con il nome della env var malformata) è emesso,
       collegabile a `CODE-14` — senza questo, un fallback "silenzioso ma
       osservabile" degraderebbe a semplicemente silenzioso.

    Perché testare via env var + `importlib.reload` e non via
    `monkeypatch.setattr` (a differenza di `TestVTRateLimitMisconfiguration`
    sopra, che testa `_vt_wait_for_slot()` a runtime dato un valore già
    assegnato): il contratto colloca la validazione **a import-time**, cioè
    nel parsing della stringa d'ambiente in `VT_RATE_WINDOW`, non nel corpo
    di `_vt_wait_for_slot`. Patchare l'attributo di modulo già parsato
    salterebbe esattamente il codice sotto test — vedi il docstring di
    `_reputation_reloaded_with_env` sopra per il dettaglio della tecnica e
    dell'isolamento fra test.

    Perché `nan`/`inf` esplicitamente, non solo `<=0`: è il bloccante
    specifico che ha fatto fallire il round 3 (`VERDETTO` verifier ·
    `PERF-01` round 3: "la guardia chiude il caso letterale, non la
    classe" — `<=0` non intercetta `nan` perché `nan<=0` è `False`, né
    `inf` per lo stesso motivo). Il criterio del round 4 richiede
    esplicitamente `math.isfinite(v) and v > soglia_minima`: un test che
    coprisse solo `<=0` non lo eserciterebbe.
    """

    def test_vt_rate_window_zero_falls_back_to_default_without_blocking_startup(self, monkeypatch, caplog):
        with caplog.at_level(logging.WARNING, logger="reputation"):
            with _reputation_reloaded_with_env(monkeypatch, VT_RATE_LIMIT="4", VT_RATE_WINDOW="0"):
                assert reputation.VT_RATE_WINDOW == 60.0, (
                    "VT_RATE_WINDOW=0 (malformato: non strettamente positivo) "
                    "deve ricadere sul default noto-sicuro 60.0 a import-time "
                    "(contratto PERF-01 round 4, decisione utente 2026-07-31), "
                    "non restare 0.0 (fail-open silenzioso) né bloccare "
                    "l'avvio del modulo."
                )
        assert any("VT_RATE_WINDOW" in rec.getMessage() for rec in caplog.records), (
            "Nessun segnale di log riconoscibile per VT_RATE_WINDOW=0: il "
            "fallback deve essere osservabile (collegabile a CODE-14), non "
            "silenzioso — è la condizione 2 della decisione utente."
        )

    def test_vt_rate_window_non_finite_falls_back_to_default_without_blocking_startup(self, monkeypatch, caplog):
        # nan/inf: la classe di valori che ha fatto fallire il round 3 (la
        # guardia <=0 non li intercetta — vedi docstring della classe).
        for malformed in ("nan", "inf"):
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="reputation"):
                with _reputation_reloaded_with_env(monkeypatch, VT_RATE_LIMIT="4", VT_RATE_WINDOW=malformed):
                    assert reputation.VT_RATE_WINDOW == 60.0, (
                        f"VT_RATE_WINDOW={malformed!r} (non finito) deve "
                        "ricadere sul default noto-sicuro 60.0 a import-time: "
                        "una validazione di classe (math.isfinite) deve "
                        "intercettarlo, non solo il caso <=0 già corretto nei "
                        "round precedenti."
                    )
            assert any("VT_RATE_WINDOW" in rec.getMessage() for rec in caplog.records), (
                f"Nessun segnale di log riconoscibile per VT_RATE_WINDOW={malformed!r}."
            )

    def test_check_vt_uses_default_window_and_signals_fallback_when_misconfigured(self, monkeypatch, caplog):
        # Prova end-to-end della stessa proprietà attraverso il percorso
        # pubblico (_check_vt): con la finestra misconfigurata, il fallback
        # deve lasciare _check_vt libero di completare normalmente (la
        # risposta VT mockata, "malicious": 5, deve arrivare fino al
        # risultato — non è più un errore da riportare in result["error"],
        # a differenza del contratto fail-fast dei round 1-3), mentre il
        # segnale della misconfigurazione va cercato nel canale di log
        # collegabile a CODE-14, non in result["error"].
        with caplog.at_level(logging.WARNING, logger="reputation"):
            with _reputation_reloaded_with_env(monkeypatch, VT_RATE_LIMIT="4", VT_RATE_WINDOW="0"):
                monkeypatch.setattr(
                    reputation, "requests",
                    _FakeRequestsModule(_FakeResponse(
                        200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}
                    ))
                )

                result = reputation._check_vt("example.com")

                assert result["error"] is None, (
                    "Con il fallback al default noto-sicuro, una richiesta VT "
                    "valida non deve fallire: VT_RATE_WINDOW=0 va corretto a "
                    "import-time (60.0), quindi _check_vt deve comportarsi "
                    "come se la env var fosse valida fin dall'inizio, non "
                    "riportare un errore di configurazione a ogni chiamata."
                )
                assert result["malicious"] == 5

        assert any("VT_RATE_WINDOW" in rec.getMessage() for rec in caplog.records), (
            "VT_RATE_WINDOW<=0 deve produrre un segnale di log riconoscibile "
            "al momento del fallback (import-time), anche quando il percorso "
            "end-to-end (_check_vt) prosegue senza errore visibile in "
            "result['error'] — altrimenti la misconfigurazione degrada la "
            "sorveglianza VT senza che nessun canale osservabile lo segnali "
            "(fail-open silenzioso, la stessa classe di difetto che il "
            "contratto round 4 vieta esplicitamente, punto 3)."
        )

    def _isolate(self, monkeypatch, rate_limit=None, rate_window=None):
        # Non toccato dal round 4: tecnica invariata (monkeypatch.setattr
        # diretto sull'attributo già parsato), usata solo dal test di
        # contrasto sotto, non in perimetro di riscrittura di questo round —
        # vedi l'ambiguità dichiarata nel mandato G3 sull'eventuale futura
        # revisione di quel test dopo il G4 del fixer.
        monkeypatch.setattr(reputation, "_vt_call_times", [])
        if rate_limit is not None:
            monkeypatch.setattr(reputation, "VT_RATE_LIMIT", rate_limit)
        if rate_window is not None:
            monkeypatch.setattr(reputation, "VT_RATE_WINDOW", rate_window)

    def test_rate_limit_and_window_both_nonpositive_still_short_circuits_on_rate_limit(self, monkeypatch):
        """Controllo verde di contrasto, dichiarato dal mandato PM: con
        entrambe le variabili <= 0, la guardia VT_RATE_LIMIT (che compare
        per prima nel codice, riga 45) deve continuare a intercettare il
        caso per short-circuit, senza che il ramo VT_RATE_WINDOW (qualunque
        forma prenda il fix) venga mai raggiunto. Il verifier ha confermato
        che questo è già vero e innocuo oggi (nessun IndexError, nessun
        fail-open: si solleva l'errore di VT_RATE_LIMIT già testato in
        TestVTRateLimitMisconfiguration sopra) — questo test lo congela
        perché non deve smettere di esserlo quando si introduce il fix per
        VT_RATE_WINDOW da solo.

        NON riscritto in questo round (non è fra i tre test elencati dal
        mandato G3): resta con la tecnica invariata
        (`monkeypatch.setattr` post-import) e la sua asserzione originale
        (`pytest.raises(ValueError, match="VT_RATE_LIMIT")`). Ambiguità
        dichiarata al PM — vedi messaggio di fine G3 — su come questo test
        si comporrà con il fix del round 4: se il fixer sposta la
        validazione a import-time e rimuove le guardie a runtime dentro
        `_vt_wait_for_slot`, questo test tornerebbe verde per un motivo
        diverso da quello odierno (0 non raggiunge mai più
        `_vt_wait_for_slot` perché il parsing a import-time l'ha già
        sostituito con il default 4 prima che qualunque chiamata parta) —
        oppure resterebbe rosso se la guardia a runtime viene rimossa del
        tutto. Non lo risolvo qui: non è nel mio mandato riscriverlo, e
        farlo silenziosamente violerebbe la richiesta esplicita del PM."""
        self._isolate(monkeypatch, rate_limit=0, rate_window=0)

        with pytest.raises(ValueError, match="VT_RATE_LIMIT"):
            reputation._vt_wait_for_slot()


# ═══════════════════════════════════════════════════════════════
# COL-16 — l'output di `GET /reputation` è il contratto che orchestrator e classificatore leggono
# ═══════════════════════════════════════════════════════════════
#
# Il riporto per fonte sta nell'orchestrator e nel `/diff`: il collector non cambia. Questi test fissano
# la parte del suo output su cui quei due lettori si appoggiano: la forma di una fonte osservata e di
# una guasta (numeri a zero, `error` valorizzato, mai un `error` di primo livello), l'esito 404 di VT, le
# fonti non interrogate, e il punteggio (soglie e fonti escluse).

from types import SimpleNamespace

import requests
from fastapi.testclient import TestClient


class _C16Reply:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def _c16_vt_body(malicious=0, suspicious=0, reputation=0):
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": suspicious, "undetected": 60, "harmless": 10},
        "reputation": reputation, "categories": {"vendor": "phishing"}}}}


def _c16_otx_body(pulses=0, malware=()):
    return {"pulse_info": {"count": pulses, "pulses": [
        {"name": f"pulse-{i}", "tags": ["tag-a", "tag-b"],
         "malware_families": [{"display_name": m} for m in malware]} for i in range(min(pulses, 5))]}}


_C16_ST_BODY = {"subdomain_count": 4, "current_dns": {"a": {"values": []}}, "alexa_rank": 1234}


@pytest.fixture
def c16_get(monkeypatch):
    """`get(domain, sources="vt,otx,st", vt=, otx=, st=)`: chiama `GET /reputation` con la rete
    sostituita. Ogni fornitore è una risposta (`_C16Reply`) o un'eccezione da sollevare; non si
    contatta nessuna rete e VT non attende."""
    replies = {}
    monkeypatch.setattr(reputation, "VT_API_KEY", "vt-test-key")
    monkeypatch.setattr(reputation, "OTX_API_KEY", "otx-test-key")
    monkeypatch.setattr(reputation, "ST_API_KEY", "st-test-key")
    monkeypatch.setattr(reputation, "_vt_wait_for_slot", lambda: None)

    def _fetch(url, **kwargs):
        for host, key in (("virustotal", "vt"), ("alienvault", "otx"), ("securitytrails", "st")):
            if host in url:
                outcome = replies[key]
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
        raise AssertionError(f"GET non atteso in questo test: {url}")

    monkeypatch.setattr(reputation, "requests", SimpleNamespace(get=_fetch))
    api = TestClient(reputation.app)

    def get(sources="vt,otx,st", vt=None, otx=None, st=None):
        replies.update(vt=vt or _C16Reply(200, _c16_vt_body()), otx=otx or _C16Reply(200, _c16_otx_body()),
                       st=st or _C16Reply(200, _C16_ST_BODY))
        response = api.get("/reputation", params={"domain": "acme-typo.example", "sources": sources})
        assert response.status_code == 200, response.text
        return response.json()

    return get


class TestCOL16CollectorOutputShape:
    """La forma dell'output: chiavi di primo livello, fonti osservate, fonti guaste, fonti non
    interrogate."""

    TOP_LEVEL = {"domain", "timestamp", "virustotal", "otx", "securitytrails", "risk_score", "risk_level", "error"}
    VT_KEYS = {"malicious", "suspicious", "undetected", "harmless", "reputation", "categories", "error"}
    OTX_KEYS = {"pulse_count", "pulse_titles", "tags", "malware_families", "error"}
    ST_KEYS = {"subdomain_count", "current_dns", "alexa_rank", "error"}

    def test_an_answered_cycle_has_the_three_sources_and_no_marker_of_any_kind(self, c16_get):
        result = c16_get(vt=_C16Reply(200, _c16_vt_body(malicious=3, reputation=-10)),
                         otx=_C16Reply(200, _c16_otx_body(pulses=2)))

        assert set(result) == self.TOP_LEVEL
        assert result["error"] is None and result["domain"] == "acme-typo.example"
        assert set(result["virustotal"]) == self.VT_KEYS and result["virustotal"]["error"] is None
        assert set(result["otx"]) == self.OTX_KEYS and result["otx"]["error"] is None
        assert set(result["securitytrails"]) == self.ST_KEYS and result["securitytrails"]["error"] is None
        assert result["virustotal"]["malicious"] == 3 and result["otx"]["pulse_count"] == 2

    @pytest.mark.parametrize("outcome", [
        pytest.param(_C16Reply(429), id="http-429"), pytest.param(_C16Reply(500), id="http-500"),
        pytest.param(requests.exceptions.Timeout("Read timed out. (read timeout=15)"), id="timeout"),
        pytest.param(requests.exceptions.ConnectionError("Max retries exceeded"), id="connection-error"),
    ])
    def test_a_failed_source_is_a_complete_dict_with_zeros_and_an_error(self, c16_get, outcome):
        result = c16_get(vt=outcome, otx=outcome, st=outcome)

        assert set(result) == self.TOP_LEVEL
        assert result["error"] is None, "con tutte le fonti guaste l'`error` di primo livello resta null"
        assert result["virustotal"] == {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
                                        "reputation": 0, "categories": {}, "error": result["virustotal"]["error"]}
        assert result["otx"] == {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": [],
                                 "error": result["otx"]["error"]}
        assert result["securitytrails"] == {"subdomain_count": 0, "current_dns": {}, "alexa_rank": None,
                                            "error": result["securitytrails"]["error"]}
        for source in ("virustotal", "otx", "securitytrails"):
            assert isinstance(result[source]["error"], str) and result[source]["error"], source

    def test_an_http_error_is_named_in_the_error_of_the_source(self, c16_get):
        result = c16_get(vt=_C16Reply(429), otx=_C16Reply(500), st=_C16Reply(503))

        assert [result[s]["error"] for s in ("virustotal", "otx", "securitytrails")] == [
            "HTTP 429", "HTTP 500", "HTTP 503"]

    def test_a_vt_404_is_an_error_text_with_zeros(self, c16_get):
        # Il testo è il contratto con chi legge la fonte (orchestrator e classificatore): il 404 di VT
        # è un'osservazione, e la si riconosce da questa stringa.
        result = c16_get(vt=_C16Reply(404))

        assert result["virustotal"]["error"] == "not found on VT"
        assert result["virustotal"]["malicious"] == 0
        assert result["otx"]["error"] is None and result["securitytrails"]["error"] is None

    def test_a_source_that_is_not_queried_is_none(self, c16_get):
        assert [c16_get(sources=s)[k] for s, k in (("vt", "otx"), ("otx", "virustotal"), ("st", "otx"))] == [None] * 3

        only_vt = c16_get(sources="vt")
        assert only_vt["otx"] is None and only_vt["securitytrails"] is None and only_vt["virustotal"] is not None

    def test_a_source_without_an_api_key_is_none(self, c16_get, monkeypatch):
        monkeypatch.setattr(reputation, "OTX_API_KEY", "")

        result = c16_get()

        assert result["otx"] is None and result["virustotal"] is not None and result["securitytrails"] is not None


class TestCOL16CollectorScore:
    """Punteggio e livello: soglie, tetti, fonti guaste escluse, SecurityTrails che non pesa."""

    @pytest.mark.parametrize("vt, otx, score, level", [
        pytest.param((0, 0, 0), (0, ()), 0, "clean", id="nothing"),
        pytest.param((0, 0, 0), (4, ()), 20, "low", id="otx-4-pulses"),
        pytest.param((0, 0, 0), (5, ()), 25, "medium", id="otx-5-pulses"),
        pytest.param((3, 0, -10), (2, ()), 50, "medium", id="vt-3-otx-2"),
        pytest.param((5, 0, 0), (1, ()), 55, "high", id="vt-5-otx-1"),
        pytest.param((5, 4, -10), (0, ()), 80, "high", id="vt-5-susp-4-rep"),
        pytest.param((5, 4, -10), (1, ()), 85, "critical", id="above-eighty"),
        pytest.param((9, 9, -10), (9, ("fam",)), 100, "critical", id="capped-at-100"),
        pytest.param((0, 0, -5), (0, ()), 0, "clean", id="reputation-at-the-threshold"),
        pytest.param((0, 0, -6), (0, ()), 10, "low", id="reputation-below-the-threshold"),
        pytest.param((0, 0, 0), (1, ("fam",)), 25, "medium", id="otx-malware-family"),
    ])
    def test_the_score_and_the_level(self, c16_get, vt, otx, score, level):
        result = c16_get(vt=_C16Reply(200, _c16_vt_body(*vt)),
                         otx=_C16Reply(200, _c16_otx_body(pulses=otx[0], malware=otx[1])))

        assert (result["risk_score"], result["risk_level"]) == (score, level)

    def test_a_failed_source_does_not_count(self, c16_get):
        vt_down = c16_get(vt=_C16Reply(429), otx=_C16Reply(200, _c16_otx_body(pulses=2)))
        otx_down = c16_get(vt=_C16Reply(200, _c16_vt_body(malicious=3, reputation=-10)), otx=_C16Reply(429))
        st_down = c16_get(vt=_C16Reply(200, _c16_vt_body(malicious=3, reputation=-10)),
                          otx=_C16Reply(200, _c16_otx_body(pulses=2)), st=_C16Reply(500))

        assert (vt_down["risk_score"], vt_down["risk_level"]) == (10, "low")
        assert (otx_down["risk_score"], otx_down["risk_level"]) == (40, "medium")
        assert (st_down["risk_score"], st_down["risk_level"]) == (50, "medium")

    def test_every_source_failed_scores_zero(self, c16_get):
        result = c16_get(vt=_C16Reply(429), otx=_C16Reply(429), st=_C16Reply(429))

        assert (result["risk_score"], result["risk_level"]) == (0, "clean")

    def test_securitytrails_does_not_weigh_on_the_score(self, c16_get):
        with_st = c16_get(vt=_C16Reply(200, _c16_vt_body(malicious=3, reputation=-10)))
        without_st = c16_get(sources="vt,otx", vt=_C16Reply(200, _c16_vt_body(malicious=3, reputation=-10)))

        assert with_st["risk_score"] == without_st["risk_score"] == 40
