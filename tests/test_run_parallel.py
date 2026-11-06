"""La suite divisa fra più processi (BUILD-09): la scelta della parte in `tests/conftest.py` e il driver
`tests/run_parallel.py`.

Interfaccia:

- `DS_TEST_SHARD=k/n` nell'ambiente di un processo pytest: il processo raccoglie l'intera suite ed esegue solo
  la parte `k` di `n`, con le parti numerate da 1 a `n`. Assente o vuota: si esegue tutto, come senza il
  meccanismo (vuota è il modo della shell per toglierla a un solo comando, `DS_TEST_SHARD= pytest`).
- `python tests/run_parallel.py -n N [argomenti di pytest]`: N processi pytest insieme, uno per parte, con gli
  argomenti passati a ciascuno (senza argomenti, `tests`). `--collect-only` (anche `--co`) è un errore d'uso
  (uscita 2, nessun processo avviato): il driver promette che ogni test raccolto è eseguito, e una raccolta
  senza esecuzione non può mantenerlo; una parte si vede con `DS_TEST_SHARD=k/n python -m pytest --collect-only`.
- Ogni processo scrive il proprio rapporto nel file indicato da `DS_TEST_SHARD_REPORT`, entro la fine della
  sessione pytest: è ciò che il driver legge per sapere che cosa il processo ha raccolto ed eseguito.

Il driver esiste per accorciare la suite senza togliere né indebolire alcun test, quindi vale quanto le sue
garanzie, fissate qui:

- ogni test raccolto è eseguito esattamente una volta: nessuno si perde fra le parti, nessuno gira in due
  processi, e la scelta non cambia fra un processo e l'altro (ognuno ha il proprio seme di `hash()`);
- i test che condividono stato restano nello stesso processo: quelli di una classe, e tutti quelli di un
  modulo con `setup_module`/`teardown_module`, che nella suite preparano o ripristinano lo stato fuori dal
  modulo (ambiente, moduli ricaricati, percorsi fissi) e devono girare una volta sola. Un modulo con una
  fixture di modulo invece si può dividere: pytest la ricrea in ogni processo che la usa, e tenerlo intero
  metterebbe in un solo processo anche il modulo più lungo della suite, `tests/test_utils.py`;
- un valore di `DS_TEST_SHARD` presente ma malformato ferma la sessione con un errore che nomina la variabile:
  eseguire tutto ripeterebbe la suite in ogni processo senza dirlo, non eseguire nulla sembrerebbe una parte vuota;
- il driver è rosso se un processo qualsiasi è rosso, se i processi non hanno raccolto la stessa suite, se un
  test raccolto non è stato eseguito (anche quando ogni processo esce 0) o se non è stato selezionato alcun
  test; una parte senza test non è un errore, se l'unione delle parti è la suite;
- i processi girano insieme, ognuno con il proprio stato (`CASES_DB`, `FEED_DATA`, `INTEL_DIR`, `EVENTS_DIR`) e
  la propria directory temporanea di pytest, mai quelli del processo che lancia il driver;
- i filtri di pytest (`-k`, `--deselect`) valgono come in serie: si eseguono esattamente i test selezionati, e
  quelli scartati dal filtro non contano come raccolti e mai eseguiti;
- ogni processo ha un `TMPDIR` proprio dentro la cartella del driver, e la cartella sparisce a ogni uscita
  (verde, rossa, SIGTERM, SIGHUP, SIGINT) senza lasciare figli vivi: ciò che un modulo di test crea con
  `tempfile` e non rimuove non si accumula nella directory temporanea di chi lancia il driver;
- un rapporto guasto (forma sbagliata, JSON troncato o troppo annidato, byte non UTF-8) dà un errore sul rapporto
  che nomina la parte, non un traceback del driver;
- a ogni uscita, anche per un secondo segnale durante l'attesa dei figli, per un segnale mentre le parti partono o
  mentre la cartella si rimuove, nessun processo resta vivo e la cartella sparisce; i figli ricevono SIGTERM prima
  di SIGKILL, e in una parte SIGTERM esegue i teardown, così si ferma anche ciò che un test ha avviato in una
  sessione propria; l'uscita è 128 + il segnale; un segnale ricevuto già ignorato (`nohup`) resta ignorato, e i
  gestori del driver si ripristinano quando `main` è chiamata come funzione.

La suite vera non viene avviata: si lavora su mini-suite generate in `tmp_path`, accanto a una copia dei file
di supporto di `tests/` (i `.py` che non sono moduli di test: conftest, driver, eventuali moduli di appoggio).
I test generati scrivono su file ciò che vedono (processo, parte, variabili di stato, directory temporanea,
nodeid eseguito, setup e teardown di modulo) e le asserzioni guardano quei file, cioè ciò che è accaduto, non
il modo in cui conftest e driver l'hanno deciso. Tutti i processi di una fixture partono insieme, così il
modulo dura pochi secondi.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import pytest

_TESTS = Path(__file__).resolve().parent
_DRIVER = _TESTS / "run_parallel.py"

# Un processo esterno che non finisce entro questo tempo è un test rosso, non una suite ferma.
_SCADENZA_S = 120

# Le variabili con cui i servizi trovano il proprio stato su disco.
_STATO = ("CASES_DB", "FEED_DATA", "INTEL_DIR", "EVENTS_DIR")


# ── La mini-suite ──────────────────────────────────────────────────────────────────────────────────────────
#
# Ogni modulo generato annota all'import (cioè in raccolta) processo, nome, parte e variabili di stato, e a
# ogni test processo, directory temporanea di pytest e nodeid. Con `MINI_ROSSO` il test con quel nodeid
# fallisce nel proprio corpo. Con `MINI_INSIEME` ogni processo che esegue test aspetta che tutte le `n` parti
# abbiano importato la mini-suite: un driver che avvia i processi uno dopo l'altro fa scadere l'attesa, una volta
# sola per processo. All'import si annotano anche `TMPDIR` e `tempfile.gettempdir()`; con `MINI_RESIDUO` ogni
# modulo crea all'import una directory con `tempfile.mkdtemp` e non la rimuove, come un modulo di test che
# prepara lì il proprio stato. Con `MINI_CANCELLO` ogni test, annotato il proprio processo, aspetta che il file
# indicato esista: il processo resta vivo a metà della propria parte finché il test non apre il cancello.
# Per le prove di interruzione:
# - `MINI_SEGNALI=resiste`: SIGTERM, SIGHUP e SIGINT si annotano e si ignorano, come un test che installa i propri
#   gestori (un server, un'attesa protetta): a fermare il processo dev'essere il driver, non la sua cortesia;
# - `MINI_SEGNALI=pulisce`: SIGTERM si annota e diventa `KeyboardInterrupt`, come in un test che lo gestisce; con
#   `MINI_PULIZIA` la fixture, uscendo, impiega 0,2 s a «pulire» e lo annota;
# - `MINI_SESSIONE`: la fixture avvia un processo in una sessione propria e lo ferma nel proprio `finally`;
# - `MINI_NIPOTE`: un processo nello stesso gruppo della parte crea file nel suo `TMPDIR` senza sosta;
# - `MINI_MOLTI`: la parte lascia nel proprio `TMPDIR` quel numero di file, così la loro rimozione dura.

_PREAMBOLO = '''\
import os
import signal
import subprocess
import sys
import tempfile
import time

import pytest

_REGISTRO = os.environ["MINI_REGISTRO"]


def _annota(nome, *campi):
    with open(os.path.join(_REGISTRO, nome), "a") as f:
        f.write("\\t".join(str(c) for c in campi) + "\\n")


_annota("importati", os.getpid(), __name__, os.environ.get("DS_TEST_SHARD", ""),
        *(os.environ.get(v, "") for v in ("CASES_DB", "FEED_DATA", "INTEL_DIR", "EVENTS_DIR")),
        os.environ.get("TMPDIR", ""), tempfile.gettempdir())
if os.environ.get("MINI_INSIEME") and os.environ.get("DS_TEST_SHARD"):
    open(os.path.join(_REGISTRO, "vivo-%d" % os.getpid()), "a").close()


def _annota_il_segnale(numero, _frame):
    _annota("segnale", os.getpid(), signal.Signals(numero).name)


def _interrompi_il_test(numero, frame):
    _annota_il_segnale(numero, frame)
    raise KeyboardInterrupt


if os.environ.get("MINI_SEGNALI") == "resiste":
    for _segnale in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(_segnale, _annota_il_segnale)
elif os.environ.get("MINI_SEGNALI") == "pulisce":
    signal.signal(signal.SIGTERM, _interrompi_il_test)
if os.environ.get("MINI_RESIDUO"):
    _residuo = tempfile.mkdtemp(prefix="mini-residuo-")
    open(os.path.join(_residuo, "stato.db"), "w").close()
    _annota("residui", os.getpid(), _residuo)


@pytest.fixture(autouse=True)
def _annota_esecuzione(request, tmp_path_factory):
    _annota("eseguiti", os.getpid(), tmp_path_factory.getbasetemp(), request.node.nodeid)
    if os.environ.get("MINI_INSIEME"):
        parti = int(os.environ["DS_TEST_SHARD"].split("/")[1])
        limite = time.monotonic() + 20
        while sum(f.startswith("vivo-") for f in os.listdir(_REGISTRO)) < parti:
            if os.environ.get("MINI_NON_INSIEME") or time.monotonic() > limite:
                os.environ["MINI_NON_INSIEME"] = "1"
                pytest.fail("MINI-NON-INSIEME")
            time.sleep(0.02)
    _una_volta_per_processo()
    sessione = None
    if os.environ.get("MINI_SESSIONE"):
        sessione = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        _annota("sessione", sessione.pid)
    try:
        cancello = os.environ.get("MINI_CANCELLO")
        if cancello:
            _annota("in-attesa", os.getpid())
            limite = time.monotonic() + 60
            while not os.path.exists(cancello) and time.monotonic() < limite:
                time.sleep(0.02)
        yield
    finally:
        if sessione is not None:
            sessione.kill()
            sessione.wait()
            _annota("sessione-fermata", sessione.pid)
        if os.environ.get("MINI_PULIZIA"):
            time.sleep(0.2)
            _annota("pulizia", os.getpid())


_NIPOTE = (
    "import os, sys, time\\n"
    "cartella, fine, i = sys.argv[1], time.monotonic() + 30, 0\\n"
    "while time.monotonic() < fine and i < 200000:\\n"
    "    try:\\n"
    "        open(os.path.join(cartella, str(i)), 'w').close()\\n"
    "    except OSError:\\n"
    "        break\\n"
    "    i += 1\\n")


def _una_volta_per_processo():
    if os.environ.get("MINI_FATTO") == str(os.getpid()):
        return
    os.environ["MINI_FATTO"] = str(os.getpid())
    if os.environ.get("MINI_NIPOTE"):
        cartella = os.path.join(tempfile.gettempdir(), "nipote")
        os.makedirs(cartella)
        nipote = subprocess.Popen([sys.executable, "-c", _NIPOTE, cartella])
        _annota("nipote", nipote.pid, cartella)
    if os.environ.get("MINI_MOLTI"):
        cartella = os.path.join(tempfile.gettempdir(), "molti")
        os.makedirs(cartella)
        for i in range(int(os.environ["MINI_MOLTI"])):
            open(os.path.join(cartella, str(i)), "w").close()
        _annota("molti", os.getpid(), cartella)


def _corpo(request):
    if request.node.nodeid == os.environ.get("MINI_ROSSO"):
        pytest.fail("MINI-ROSSO " + request.node.nodeid)
'''


def _modulo(classi=(), funzioni=0, parametrizzata=None, di_modulo=None):
    """Sorgente di un modulo della mini-suite: classi `(nome, numero di test)`, funzioni di modulo, una classe
    con un test parametrizzato `(nome, numero di parametri)`, una funzione `setup_module`/`teardown_module`."""
    pezzi = [_PREAMBOLO]
    if di_modulo:
        pezzi.append(f"def {di_modulo}(module):\n    _annota('moduli', os.getpid(), '{di_modulo}', __name__)\n")
    for nome, quanti in classi:
        pezzi.append(f"class {nome}:\n" + "\n".join(
            f"    def test_{i}(self, request):\n        _corpo(request)\n" for i in range(quanti)))
    if parametrizzata:
        nome, quanti = parametrizzata
        pezzi.append(f"class {nome}:\n    @pytest.mark.parametrize('x', range({quanti}))\n"
                     "    def test_p(self, x, request):\n        _corpo(request)\n")
    pezzi.extend(f"def test_funzione_{i}(request):\n    _corpo(request)\n" for i in range(funzioni))
    return "\n\n".join(pezzi)


def _breve(nodeid):
    """Il nodeid senza la directory del file: quella dipende dalla radice che pytest sceglie, non dal test."""
    percorso, _, resto = nodeid.partition("::")
    return f"{Path(percorso).name}::{resto}"


def _classe(breve):
    """`<file>::<classe>` per un test di una classe, `None` per una funzione di modulo."""
    pezzi = breve.split("::")
    return "::".join(pezzi[:2]) if len(pezzi) == 3 else None


def _attesi(modulo, classi=(), funzioni=0, parametrizzata=None, di_modulo=None):
    """I test di un modulo generato da `_modulo`, come `<file>::<resto del nodeid>`."""
    attesi = {f"{modulo}::{nome}::test_{i}" for nome, quanti in classi for i in range(quanti)}
    if parametrizzata:
        nome, quanti = parametrizzata
        attesi |= {f"{modulo}::{nome}::test_p[{i}]" for i in range(quanti)}
    return attesi | {f"{modulo}::test_funzione_{i}" for i in range(funzioni)}


# Abbastanza classi e moduli perché una scelta per singolo test, invece che per classe o per modulo, ne divida
# qualcuno con ogni n provato.
_MINI_SUITE = {
    "test_alfa.py": dict(classi=[("TestAlfaUno", 3), ("TestAlfaDue", 3), ("TestAlfaTre", 3)], funzioni=2),
    "test_beta.py": dict(classi=[("TestBetaUno", 2), ("TestBetaDue", 4), ("TestBetaTre", 2), ("TestBetaQuattro", 1)],
                         parametrizzata=("TestBetaParametri", 3)),
    "test_gamma.py": dict(classi=[("TestGammaUno", 2), ("TestGammaDue", 2), ("TestGammaTre", 2)], funzioni=1,
                          di_modulo="setup_module"),
    "test_delta.py": dict(classi=[("TestDeltaUno", 2), ("TestDeltaDue", 2), ("TestDeltaTre", 2)],
                          di_modulo="teardown_module"),
    "test_epsilon.py": dict(classi=[(f"TestEpsilon{i}", 2) for i in range(6)]),
}
_ATTESI = set().union(*(_attesi(nome, **spec) for nome, spec in _MINI_SUITE.items()))
_CLASSI = {_classe(t) for t in _ATTESI} - {None}

_MALFORMATI = ("0/4", "5/4", "a/b", "1/0")


def _radice(base, moduli):
    """Una radice con `tests/`: copia dei file di supporto più i moduli dati (`nome relativo -> sorgente`)."""
    tests = base / "tests"
    tests.mkdir(parents=True)
    for sorgente in _TESTS.glob("*.py"):
        if not sorgente.name.startswith("test_"):
            shutil.copy(sorgente, tests / sorgente.name)
    for nome, testo in moduli.items():
        (tests / nome).parent.mkdir(parents=True, exist_ok=True)
        (tests / nome).write_text(testo)
    return base


# ── Processi esterni ──────────────────────────────────────────────────────────────────────────────────────


def _ambiente(registro, variabili):
    """Ambiente ricostruito da zero. Il processo che esegue questo modulo può essere a sua volta una parte del
    driver, con `DS_TEST_SHARD` e lo stato per processo nell'ambiente: nulla di questo deve arrivare alla
    mini-suite, che altrimenti eseguirebbe la parte del chiamante."""
    ambiente = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL") if k in os.environ}
    ambiente["MINI_REGISTRO"] = str(registro)
    ambiente.update(variabili)
    return ambiente


class _Esito:
    def __init__(self, rc, uscita, registro):
        self.rc, self.uscita, self.registro = rc, uscita, registro

    def righe(self, nome):
        percorso = self.registro / nome
        if not percorso.exists():
            return []
        return [riga.split("\t") for riga in percorso.read_text().splitlines()]

    def eseguiti(self):
        return [_breve(nodeid) for _, _, nodeid in self.righe("eseguiti")]

    def tmp_chiamante(self):
        """Il `TMPDIR` dato al driver: deve restare vuoto."""
        return self.registro / "tmp-chiamante"

    def figli(self):
        """I processi pytest avviati dal driver con una parte (quelli che hanno importato la mini-suite)."""
        return sorted({int(riga[0]) for riga in self.righe("importati") if riga[2]})


def _vivo(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rpartition(")")[2].split()[0] != "Z"    # uno zombie è già finito
    except FileNotFoundError:
        if os.path.isdir("/proc/self"):
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _processi_vivi(registro):
    """I processi vivi che hanno nell'ambiente questo registro: il driver, le sue parti e ciò che i test hanno
    avviato, in qualunque sessione o gruppo stiano. L'ambiente li riconosce anche se il loro pid non è annotato,
    e non confonde un pid riusato da un processo estraneo."""
    voce = b"\0MINI_REGISTRO=" + os.fsencode(str(registro)) + b"\0"
    vivi = []
    for nome in os.listdir("/proc"):
        if not nome.isdigit() or int(nome) == os.getpid():
            continue
        try:
            with open(f"/proc/{nome}/environ", "rb") as f:
                ambiente = b"\0" + f.read()
        except OSError:
            continue
        if voce in ambiente + b"\0" and _vivo(int(nome)):
            vivi.append(int(nome))
    return sorted(vivi)


def _uccidi_i_resti(processo, registro):
    """A fine prova nessun processo deve sopravvivere al test, qualunque cosa abbia fatto il driver: il gruppo
    del processo avviato, poi ogni processo ancora vivo con il suo registro nell'ambiente."""
    try:
        os.killpg(processo.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    processo.wait()
    for pid in _processi_vivi(registro):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


# Al più `_TETTO` processi avviati da questo modulo (un pytest, o un driver con le sue parti) sono vivi insieme.
# Col driver questo modulo gira accanto alle altre parti della suite, fra cui test con scadenze di pochi decimi di
# secondo: una raffica di decine di interpreti avviati insieme su pochi core tiene in coda i loro thread tanto da
# farle scadere. Con quattro alla volta i processi pronti restano una decina, e il modulo dura quasi quanto senza
# tetto.
_TETTO = 4


class _Avvio:
    """Il processo che uno scenario chiede di avviare. Un `TMPDIR` fra le variabili viene creato vuoto:
    inesistente, `tempfile` lo ignorerebbe e userebbe quello di sistema."""

    def __init__(self, comando, directory, registro, variabili, preexec_fn=None):
        self.comando, self.directory, self.registro = comando, directory, registro
        self.variabili, self.preexec_fn = variabili, preexec_fn

    def avvia(self):
        self.registro.mkdir(parents=True)
        if "TMPDIR" in self.variabili:
            Path(self.variabili["TMPDIR"]).mkdir(parents=True)
        with open(self.registro / "uscita.txt", "w") as uscita:
            return subprocess.Popen(self.comando, cwd=self.directory, env=_ambiente(self.registro, self.variabili),
                                    stdout=uscita, stderr=subprocess.STDOUT, start_new_session=True,
                                    preexec_fn=self.preexec_fn)


def _esegui(scenari):
    """`scenari`: chiave -> generatore. Un generatore cede un `_Avvio` e riceve il processo avviato, poi cede `None`
    finché aspetta qualcosa e restituisce il proprio esito. Al più `_TETTO` processi sono vivi insieme: uno
    scenario parte quando un altro è finito. Ogni processo ha un gruppo proprio e `_SCADENZA_S` secondi: alla
    scadenza, o a fine scenario, ciò che resta viene ucciso."""
    in_coda, attivi, esiti = list(scenari.items()), {}, {}
    try:
        while in_coda or attivi:
            while in_coda and len(attivi) < _TETTO:
                chiave, generatore = in_coda.pop(0)
                avvio = next(generatore)
                processo = avvio.avvia()
                attivi[chiave] = (generatore, processo, avvio.registro, time.monotonic() + _SCADENZA_S)
                _passo(chiave, attivi, esiti, lambda g, p=processo: g.send(p))
            for chiave in list(attivi):
                generatore, processo, registro, limite = attivi[chiave]
                if time.monotonic() > limite:
                    generatore.close()
                    _uccidi_i_resti(processo, registro)
                    del attivi[chiave]
                    esiti[chiave] = _Esito(None, (registro / "uscita.txt").read_text(errors="replace"), registro)
                else:
                    _passo(chiave, attivi, esiti, next)
            time.sleep(0.005)
    finally:
        for generatore, processo, registro, _ in attivi.values():
            generatore.close()
            _uccidi_i_resti(processo, registro)
    return esiti


def _passo(chiave, attivi, esiti, avanza):
    generatore, processo, registro, _ = attivi[chiave]
    try:
        avanza(generatore)
    except StopIteration as fine:
        del attivi[chiave]
        _uccidi_i_resti(processo, registro)
        esiti[chiave] = fine.value


def _fino_alla_fine(avvio):
    """Lo scenario più semplice: avvia e aspetta che il processo finisca."""
    processo = yield avvio
    while processo.poll() is None:
        yield
    return _Esito(processo.returncode, (avvio.registro / "uscita.txt").read_text(errors="replace"), avvio.registro)


def _esegui_insieme(richieste):
    """`richieste`: chiave -> (comando, directory, registro, variabili d'ambiente); vedi `_esegui`."""
    return _esegui({chiave: _fino_alla_fine(_Avvio(*richiesta)) for chiave, richiesta in richieste.items()})


def _pytest(registro):
    return [sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider", f"--basetemp={registro / 'pt'}"]


@pytest.fixture(scope="module")
def mini(tmp_path_factory):
    return _radice(tmp_path_factory.mktemp("mini"), {nome: _modulo(**spec) for nome, spec in _MINI_SUITE.items()})


# ── La scelta della parte (tests/conftest.py) ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def parti(mini, tmp_path_factory):
    """Un processo pytest per ogni caso: senza variabile, vuota, ogni parte di n = 2, 3, 4, le parti di n = 2
    una seconda volta, ogni valore malformato. Chiavi: `"serie"`, `"vuota"`, `(n, k)`, `("di nuovo", 2, k)`,
    `("malformato", valore)`."""
    base = tmp_path_factory.mktemp("parti")
    valori = {"serie": None, "vuota": ""}
    valori.update({(n, k): f"{k}/{n}" for n in (2, 3, 4) for k in range(1, n + 1)})
    valori.update({("di nuovo", 2, k): f"{k}/2" for k in (1, 2)})
    valori.update({("malformato", valore): valore for valore in _MALFORMATI})
    richieste = {}
    for i, (chiave, valore) in enumerate(valori.items()):
        registro = base / f"r{i}"
        # Un seme di `hash()` diverso per ogni processo, come fra le parti del driver: la scelta non può
        # dipendere dall'interprete che la fa.
        variabili = {"PYTHONHASHSEED": str(i + 1)}
        if valore is not None:
            variabili["DS_TEST_SHARD"] = valore
        richieste[chiave] = (_pytest(registro), mini, registro, variabili)
    return _esegui_insieme(richieste)


def _parti_di(parti, n):
    """`{k: test eseguiti dalla parte k di n}`; ogni parte deve uscire 0, o 5 se non ha test."""
    eseguiti = {}
    for k in range(1, n + 1):
        esito = parti[(n, k)]
        assert esito.rc in (0, 5), f"parte {k}/{n}, exit {esito.rc}:\n{esito.uscita}"
        eseguiti[k] = esito.eseguiti()
    return eseguiti


class TestSceltaDellaParte:
    """`DS_TEST_SHARD=k/n`: quale parte della suite esegue un processo pytest."""

    def test_senza_variabile_esegue_tutta_la_suite(self, parti):
        esito = parti["serie"]
        assert esito.rc == 0, esito.uscita
        assert Counter(esito.eseguiti()) == Counter(_ATTESI)

    def test_variabile_vuota_esegue_tutta_la_suite(self, parti):
        esito = parti["vuota"]
        assert esito.rc == 0, esito.uscita
        assert Counter(esito.eseguiti()) == Counter(_ATTESI)

    @pytest.mark.parametrize("n", (2, 3, 4))
    def test_le_n_parti_eseguono_ogni_test_una_volta(self, parti, n):
        eseguiti = Counter(t for ts in _parti_di(parti, n).values() for t in ts)
        doppi = sorted(t for t, volte in eseguiti.items() if volte > 1)
        mancanti = sorted(_ATTESI - set(eseguiti))
        assert not doppi, f"{len(doppi)} test eseguiti da più parti, p.es. {doppi[:3]}"
        assert not mancanti, f"{len(mancanti)} test in nessuna parte, p.es. {mancanti[:3]}"
        assert set(eseguiti) == _ATTESI

    def test_la_stessa_parte_contiene_sempre_gli_stessi_test(self, parti):
        for k in (1, 2):
            prima, di_nuovo = set(parti[(2, k)].eseguiti()), set(parti[("di nuovo", 2, k)].eseguiti())
            assert prima == di_nuovo, f"parte {k}/2: {sorted(prima ^ di_nuovo)[:3]}"
            # Una parte vera: né la suite intera (la variabile ignorata) né il vuoto.
            assert 0 < len(prima) < len(_ATTESI), f"parte {k}/2: {len(prima)} test su {len(_ATTESI)}"

    @pytest.mark.parametrize("n", (2, 3, 4))
    def test_i_test_di_una_classe_stanno_nella_stessa_parte(self, parti, n):
        parti_della_classe = defaultdict(set)
        for k, eseguiti in _parti_di(parti, n).items():
            for test in eseguiti:
                if _classe(test):
                    parti_della_classe[_classe(test)].add(k)
        assert set(parti_della_classe) == _CLASSI
        divise = {classe: sorted(ks) for classe, ks in parti_della_classe.items() if len(ks) > 1}
        assert not divise, f"classi divise fra parti di {n}: {divise}"

    @pytest.mark.parametrize("n", (2, 3, 4))
    @pytest.mark.parametrize("modulo, funzione", [("test_gamma.py", "setup_module"),
                                                  ("test_delta.py", "teardown_module")])
    def test_un_modulo_con_setup_o_teardown_di_modulo_sta_in_una_parte(self, parti, n, modulo, funzione):
        # Diviso, il modulo eseguirebbe la propria funzione di modulo una volta per processo: lo stato che
        # prepara o ripristina varrebbe solo per una parte dei suoi test.
        con_il_modulo = [k for k, eseguiti in _parti_di(parti, n).items()
                         if any(t.startswith(modulo + "::") for t in eseguiti)]
        assert len(con_il_modulo) == 1, f"{modulo} diviso fra le parti {con_il_modulo} di {n}"
        chiamate = [riga for k in range(1, n + 1) for riga in parti[(n, k)].righe("moduli") if riga[1] == funzione]
        assert len(chiamate) == 1, f"{funzione} di {modulo} eseguita {len(chiamate)} volte con {n} parti"

    @pytest.mark.parametrize("valore", _MALFORMATI)
    def test_un_valore_malformato_ferma_la_sessione(self, parti, valore):
        esito = parti[("malformato", valore)]
        # Non 5: è l'uscita di una parte senza test, che il driver ammette.
        assert esito.rc not in (None, 0, 5), f"exit {esito.rc}:\n{esito.uscita}"
        assert "DS_TEST_SHARD" in esito.uscita and valore in esito.uscita, esito.uscita
        assert esito.eseguiti() == []


# ── Il driver (tests/run_parallel.py) ─────────────────────────────────────────────────────────────────────

# Il primo processo che importa il modulo raccoglie un test in più: le parti non vedono la stessa suite.
_SOLO_NEL_PRIMO = _PREAMBOLO + '''

try:
    os.close(os.open(os.path.join(_REGISTRO, "primo"), os.O_CREAT | os.O_EXCL | os.O_WRONLY))
except FileExistsError:
    pass
else:
    def test_raccolto_da_un_solo_processo():
        pass
'''

# Dopo la scelta della parte, ogni processo toglie dalla propria il primo test: tutti raccolgono la stessa
# suite ed escono 0, ma qualche test raccolto non viene eseguito da nessuno.
_TOGLIE_UN_TEST = '''\
import pytest


@pytest.hookimpl(wrapper=True)
def pytest_collection_finish(session):
    risultato = yield
    if session.items:
        del session.items[0]
    return risultato
'''

# Dopo la scelta della parte, ogni processo rimette nella propria i test delle altre: tutti raccolgono la
# stessa suite, escono 0 e l'unione dei test eseguiti è la suite, ma ogni test gira in più processi.
_ESEGUE_TUTTO = '''\
import pytest

_raccolti = []


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items):
    _raccolti[:] = items


@pytest.hookimpl(wrapper=True)
def pytest_collection_finish(session):
    risultato = yield
    session.items[:] = _raccolti
    return risultato
'''

# Il processo che esegue questo test esce 0 senza arrivare alla fine della propria parte.
_ESCE_A_META = _PREAMBOLO + '''

def test_il_processo_esce_senza_finire():
    os._exit(0)
'''

# Il primo processo che importa il modulo, all'uscita dell'interprete (dopo la sessione pytest, quando il rapporto
# è già scritto), sostituisce il proprio rapporto con uno guasto (`MINI_RAPPORTO`): JSON valido di forma sbagliata,
# JSON troncato, byte che non sono UTF-8, annidamento più profondo di quanto il lettore JSON accetti.
_RAPPORTO_GUASTO = _PREAMBOLO + '''

import atexit

_GUASTI = {
    "{}": b"{}",
    "[]": b"[]",
    "null": b"null",
    "annidato": b'{"raccolti": [[1]], "eseguiti": []}',
    "troncato": b'{"raccolti": ["tests/test_comune.py::',
    "non-utf8": b'{"raccolti": ["' + bytes([0xff, 0xfe]) + b'"], "eseguiti": []}',
    "profondo": b"[" * 200000,
}


def _sostituisci_il_rapporto():
    with open(os.environ["DS_TEST_SHARD_REPORT"], "wb") as f:
        f.write(_GUASTI[os.environ["MINI_RAPPORTO"]])


try:
    os.close(os.open(os.path.join(_REGISTRO, "primo"), os.O_CREAT | os.O_EXCL | os.O_WRONLY))
except FileExistsError:
    pass
else:
    _annota("rapporto", os.getpid(), os.environ.get("DS_TEST_SHARD", ""))
    atexit.register(_sostituisci_il_rapporto)


def test_qualcosa():
    pass
'''

_COMUNE = _modulo(classi=[("TestComuneUno", 2), ("TestComuneDue", 2), ("TestComuneTre", 2)], funzioni=2)

# Filtri che tolgono una parte dei test di un gruppo (classe): la parte si sceglie dopo il filtro, altrimenti i
# test scartati risultano raccolti e mai eseguiti.
_FILTRI = {"-k": ("-k", "not test_1"), "--deselect": ("--deselect", "tests/test_alfa.py::TestAlfaUno::test_0")}
_RAPPORTI_GUASTI = ("{}", "[]", "null", "annidato", "troncato", "non-utf8", "profondo")
_SOLO_RACCOLTA = ("--collect-only", "--co")


@pytest.fixture(scope="module")
def driver(mini, tmp_path_factory):
    """Il driver su più scenari, tutti insieme; poi, per ogni processo che nello scenario verde ha eseguito
    test, il driver con uno di quei test rosso. Restituisce `(esiti, stato del chiamante)`, oppure `None` se il
    driver non esiste."""
    if not _DRIVER.exists():
        return None
    base = tmp_path_factory.mktemp("driver")
    # Lo stato del processo che lancia il driver: nessuna parte deve riceverlo.
    chiamante = {v: str(base / "chiamante" / v.lower()) for v in _STATO}

    def richiesta(nome, radice, n, *argomenti, **variabili):
        # Un `TMPDIR` dedicato come directory temporanea del chiamante: i residui si contano lì, non in /tmp.
        comando = [sys.executable, str(radice / "tests" / "run_parallel.py"), "-n", str(n), *argomenti]
        return comando, radice, base / nome, {**chiamante, "TMPDIR": str(base / nome / "tmp-chiamante"), **variabili}

    def radice(nome, moduli):
        return _radice(base / f"radice-{nome}", {"test_comune.py": _COMUNE, **moduli})

    rapporto = radice("rapporto", {"test_rapporto.py": _RAPPORTO_GUASTO})
    esiti = _esegui_insieme({
        "verde": richiesta("verde", mini, 3, MINI_INSIEME="1", MINI_RESIDUO="1"),
        "percorso": richiesta("percorso", mini, 2, "tests/test_alfa.py"),
        "parti vuote": richiesta("parti-vuote", mini, 3, "tests/test_gamma.py"),
        "nessun test": richiesta("nessun-test", mini, 2, "-k", "nessun_test_ha_questo_nome"),
        "suite diversa": richiesta("suite-diversa", radice("diversa", {"test_diversa.py": _SOLO_NEL_PRIMO}), 2),
        "test non eseguito": richiesta("non-eseguito", radice("salto", {
            "sotto/conftest.py": _TOGLIE_UN_TEST, "sotto/test_sotto.py": _modulo(classi=[("TestSotto", 2)])}), 2),
        "test doppi": richiesta("doppi", radice("doppi", {
            "sotto/conftest.py": _ESEGUE_TUTTO, "sotto/test_sotto.py": _modulo(classi=[("TestSotto", 2)])}), 2),
        "uscita a metà": richiesta("uscita", radice("uscita", {"test_uscita.py": _ESCE_A_META}), 2),
        **{("filtro", nome): richiesta(f"filtro{nome}", mini, 2, *filtro) for nome, filtro in _FILTRI.items()},
        **{("serie", nome): ([*_pytest(base / f"serie{nome}"), *filtro], mini, base / f"serie{nome}", {})
           for nome, filtro in _FILTRI.items()},
        **{("rapporto", guasto): richiesta(f"rapporto-{i}", rapporto, 1, MINI_RAPPORTO=guasto)
           for i, guasto in enumerate(_RAPPORTI_GUASTI)},
        **{("solo raccolta", opzione): richiesta(f"raccolta{opzione}", mini, 2, opzione) for opzione in _SOLO_RACCOLTA},
    })
    uno_per_processo = {}
    for pid, _, nodeid in esiti["verde"].righe("eseguiti"):
        uno_per_processo.setdefault(pid, nodeid)
    esiti.update(_esegui_insieme({
        ("rosso", nodeid): richiesta(f"rosso-{i}", mini, 3, MINI_ROSSO=nodeid, MINI_RESIDUO="1")
        for i, nodeid in enumerate(uno_per_processo.values())}))
    return esiti, chiamante


def _esiti(driver):
    assert driver is not None, f"manca il driver {_DRIVER}"
    return driver[0]


def _processi_delle_parti(esito):
    """`{pid: righe "importati" di quel processo}` per i processi avviati con una parte."""
    processi = defaultdict(list)
    for riga in esito.righe("importati"):
        if riga[2]:
            processi[riga[0]].append(riga)
    return processi


class TestDriver:
    """`python tests/run_parallel.py -n N [argomenti di pytest]`."""

    def test_esce_zero_ed_esegue_ogni_test_una_volta(self, driver):
        esito = _esiti(driver)["verde"]
        assert esito.rc == 0, esito.uscita
        assert Counter(esito.eseguiti()) == Counter(_ATTESI)

    def test_ogni_parte_ha_un_processo_che_raccoglie_tutta_la_suite(self, driver):
        processi = _processi_delle_parti(_esiti(driver)["verde"])
        parte_di = {pid: {riga[2] for riga in righe} for pid, righe in processi.items()}
        assert sorted(parte for del_pid in parte_di.values() for parte in del_pid) == ["1/3", "2/3", "3/3"], parte_di
        for pid, righe in processi.items():
            moduli = {riga[1].rpartition(".")[2] for riga in righe}
            assert moduli == {Path(m).stem for m in _MINI_SUITE}, f"processo {pid}: {sorted(moduli)}"

    def test_le_parti_girano_insieme(self, driver):
        esito = _esiti(driver)["verde"]
        assert "MINI-NON-INSIEME" not in esito.uscita, esito.uscita
        assert esito.rc == 0, esito.uscita

    @pytest.mark.parametrize("variabile", _STATO)
    def test_ogni_processo_ha_il_proprio_stato(self, driver, variabile):
        esiti, chiamante = _esiti(driver), driver[1]
        colonna = 3 + _STATO.index(variabile)
        valori = {pid: {riga[colonna] for riga in righe}
                  for pid, righe in _processi_delle_parti(esiti["verde"]).items()}
        assert len(valori) == 3 and all(len(v) == 1 for v in valori.values()), valori
        valori = [v.pop() for v in valori.values()]
        assert all(valori), valori
        assert len(set(valori)) == 3, f"{variabile} condiviso fra processi: {valori}"
        assert chiamante[variabile] not in valori, f"{variabile} del chiamante passato a una parte"
        assert not any(v == "/data" or v.startswith("/data/") for v in valori), valori

    def test_ogni_processo_ha_la_propria_directory_temporanea(self, driver):
        directory = defaultdict(set)
        for pid, basetemp, _ in _esiti(driver)["verde"].righe("eseguiti"):
            directory[pid].add(basetemp)
        assert len(directory) >= 2 and all(len(d) == 1 for d in directory.values()), directory
        tutte = [d for ds in directory.values() for d in ds]
        assert len(set(tutte)) == len(tutte), f"directory temporanea condivisa: {tutte}"
        # Non la radice di default `<tmp>/pytest-of-<utente>/pytest-<N>`: è condivisa con ogni altro pytest
        # dell'utente, che ne conserva solo le ultime tre.
        predefinite = [d for d in tutte
                       if Path(d).parent.name.startswith("pytest-of-") and re.fullmatch(r"pytest-\d+", Path(d).name)]
        assert not predefinite, predefinite

    def test_un_test_rosso_in_un_processo_qualsiasi_rende_rosso_il_driver(self, driver):
        rossi = {chiave[1]: esito for chiave, esito in _esiti(driver).items()
                 if isinstance(chiave, tuple) and chiave[0] == "rosso"}
        assert len(rossi) >= 2, f"nello scenario verde hanno eseguito test {len(rossi)} processi su 3"
        for nodeid, esito in rossi.items():
            assert esito.rc not in (None, 0), f"{nodeid} rosso, exit {esito.rc}:\n{esito.uscita}"
            assert f"MINI-ROSSO {nodeid}" in esito.uscita, esito.uscita

    def test_rosso_se_i_processi_raccolgono_suite_diverse(self, driver):
        esito = _esiti(driver)["suite diversa"]
        assert esito.rc not in (None, 0), esito.uscita

    def test_rosso_se_un_test_raccolto_non_viene_eseguito(self, driver):
        esito = _esiti(driver)["test non eseguito"]
        assert esito.rc not in (None, 0), esito.uscita

    def test_rosso_se_un_test_e_eseguito_da_piu_processi(self, driver):
        esito = _esiti(driver)["test doppi"]
        assert esito.rc not in (None, 0), esito.uscita

    def test_rosso_se_un_processo_esce_prima_di_finire_la_parte(self, driver):
        esito = _esiti(driver)["uscita a metà"]
        assert esito.rc not in (None, 0), esito.uscita

    def test_passa_a_pytest_gli_argomenti(self, driver):
        esito = _esiti(driver)["percorso"]
        assert esito.rc == 0, esito.uscita
        assert Counter(esito.eseguiti()) == Counter(t for t in _ATTESI if t.startswith("test_alfa.py::"))

    def test_parti_senza_test_non_sono_un_errore(self, driver):
        # Un solo modulo con `setup_module` è un gruppo solo: due parti su tre restano vuote.
        esito = _esiti(driver)["parti vuote"]
        assert esito.rc == 0, esito.uscita
        assert Counter(esito.eseguiti()) == Counter(t for t in _ATTESI if t.startswith("test_gamma.py::"))
        assert len(esito.righe("moduli")) == 1, esito.righe("moduli")

    def test_rosso_se_nessun_test_e_selezionato(self, driver):
        esito = _esiti(driver)["nessun test"]
        assert esito.rc not in (None, 0), esito.uscita

    @pytest.mark.parametrize("filtro", _FILTRI)
    def test_un_filtro_di_pytest_esegue_esattamente_i_test_selezionati(self, driver, filtro):
        serie, esito = _esiti(driver)[("serie", filtro)], _esiti(driver)[("filtro", filtro)]
        selezionati = serie.eseguiti()
        # Il filtro toglie davvero qualcosa, e qualcosa resta: in serie, senza driver, con lo stesso argomento.
        assert serie.rc == 0 and 0 < len(set(selezionati)) < len(_ATTESI), serie.uscita
        assert esito.rc == 0, esito.uscita
        assert Counter(esito.eseguiti()) == Counter(selezionati)

    def test_ogni_processo_ha_un_tmpdir_proprio_dentro_la_cartella_del_driver(self, driver):
        esito = _esiti(driver)["verde"]
        chiamante = Path(os.path.realpath(esito.tmp_chiamante()))
        tmpdir = {pid: {(riga[7], riga[8]) for riga in righe} for pid, righe in _processi_delle_parti(esito).items()}
        assert len(tmpdir) == 3 and all(len(v) == 1 for v in tmpdir.values()), tmpdir
        tmpdir = {pid: v.pop() for pid, v in tmpdir.items()}
        for pid, (variabile, effettiva) in tmpdir.items():
            assert variabile, f"processo {pid} senza TMPDIR"
            assert os.path.realpath(effettiva) == os.path.realpath(variabile), (pid, variabile, effettiva)
            percorso = Path(os.path.realpath(variabile))
            # Dentro la cartella del driver, che sta nella directory temporanea del chiamante, e non coincide con essa.
            assert percorso != chiamante and percorso.is_relative_to(chiamante), (pid, variabile)
        assert len({variabile for variabile, _ in tmpdir.values()}) == 3, f"TMPDIR condiviso: {tmpdir}"

    @pytest.mark.parametrize("scenario", ("verde", "rosso"))
    def test_nessun_residuo_nella_directory_temporanea_del_chiamante(self, driver, scenario):
        for esito in _scenari(_esiti(driver), scenario):
            residui = [Path(riga[1]) for riga in esito.righe("residui")]
            assert residui, "precondizione: i moduli hanno creato le loro directory temporanee"
            assert not any(r.exists() for r in residui), [str(r) for r in residui if r.exists()]
            assert sorted(p.name for p in esito.tmp_chiamante().iterdir()) == []

    @pytest.mark.parametrize("scenario", ("verde", "rosso"))
    def test_la_cartella_del_driver_sparisce_e_nessun_figlio_resta_vivo(self, driver, scenario):
        for esito in _scenari(_esiti(driver), scenario):
            assert esito.rc is not None, esito.uscita
            restano = _percorsi_dei_processi(esito)
            assert restano and not [p for p in restano if p.exists()], [str(p) for p in restano if p.exists()]
            assert not [pid for pid in esito.figli() if _vivo(pid)]

    @pytest.mark.parametrize("guasto", _RAPPORTI_GUASTI)
    def test_un_rapporto_guasto_da_un_errore_sul_rapporto_che_nomina_la_parte(self, driver, guasto):
        # Il processo è arrivato alla fine della sessione: l'errore è il rapporto, e così deve dirlo.
        esito = _esiti(driver)[("rapporto", guasto)]
        sostituiti = esito.righe("rapporto")
        assert len(sostituiti) == 1, f"precondizione: un solo rapporto sostituito, {sostituiti}"
        parte = sostituiti[0][1]
        assert esito.rc not in (None, 0), esito.uscita
        assert "Traceback" not in esito.uscita, esito.uscita
        assert any("ERRORE" in riga and parte in riga and "rapporto" in riga
                   for riga in esito.uscita.splitlines()), esito.uscita

    @pytest.mark.parametrize("opzione", _SOLO_RACCOLTA)
    def test_collect_only_e_un_errore_d_uso(self, driver, opzione):
        esito = _esiti(driver)[("solo raccolta", opzione)]
        assert esito.rc == 2, esito.uscita
        assert opzione in esito.uscita, esito.uscita
        assert esito.righe("importati") == [], "nessun processo doveva raccogliere la suite"


def _scenari(esiti, nome):
    """Gli esiti di uno scenario: `"verde"`, oppure tutti quelli con chiave `("rosso", ...)`."""
    scelti = [esito for chiave, esito in esiti.items()
              if chiave == nome or (isinstance(chiave, tuple) and chiave[0] == nome)]
    assert scelti, f"nessuno scenario {nome!r}"
    return scelti


def _percorsi_dei_processi(esito):
    """Ciò che ogni processo aveva dentro la cartella del driver: stato e directory temporanea di pytest."""
    percorsi = {Path(riga[c]) for riga in esito.righe("importati") if riga[2] for c in range(3, 7)}
    return sorted(percorsi | {Path(basetemp) for _, basetemp, _ in esito.righe("eseguiti")})


# ── Il driver interrotto ──────────────────────────────────────────────────────────────────────────────────────

_SEGNALI = ("SIGTERM", "SIGHUP", "SIGINT")
_PARTI_INTERROTTE = 2
# Un segnale durante l'avvio delle parti cade quasi sempre dentro l'avvio di un processo: provato più volte, con
# molte parti da avviare.
_AVVII_INTERROTTI = 6
_PARTI_ALL_AVVIO = 40
# File lasciati da una parte nel proprio TMPDIR: la loro rimozione dura qualche decimo di secondo.
_FILE_DA_RIMUOVERE = 20000

# Eseguito con `python -c`: chiama `main` del driver come una funzione e riferisce i gestori dei segnali prima e dopo.
_MAIN_COME_FUNZIONE = """
import json, signal, sys
sys.path.insert(0, sys.argv[1])
import run_parallel
segnali = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
prima = [repr(signal.getsignal(numero)) for numero in segnali]
rc = run_parallel.main(sys.argv[2:])
print(json.dumps({"rc": rc, "prima": prima, "dopo": [repr(signal.getsignal(numero)) for numero in segnali]}))
"""


def _segnali_di_default():
    # Come da un terminale: SIGINT, SIGTERM e SIGHUP con la disposizione di default anche se chi lancia la suite
    # li ignora (`nohup`, un job in background), perché il driver lascia ignorato un segnale che riceve già ignorato.
    for numero in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(numero, signal.SIG_DFL)


def _sighup_ignorato():
    _segnali_di_default()
    signal.signal(signal.SIGHUP, signal.SIG_IGN)


def _avvio_del_driver(mini, base, nome, n, *argomenti, cancello=True, preexec_fn=_segnali_di_default, **variabili):
    registro = base / nome
    variabili = {"TMPDIR": str(registro / "tmp-chiamante"), **variabili}
    if cancello:
        variabili["MINI_CANCELLO"] = str(registro / "cancello")
    comando = [sys.executable, str(mini / "tests" / "run_parallel.py"), "-n", str(n), *argomenti]
    return _Avvio(comando, mini, registro, variabili, preexec_fn)


def _al_cancello(esito, driver, parti):
    """Cede il passo finché tutte le parti hanno importato la mini-suite e ogni figlio ancora vivo è fermo al
    cancello (una parte vuota esce subito). Restituisce i figli fermi: il segnale arriva mentre lavorano."""
    limite = time.monotonic() + 30
    while time.monotonic() < limite and driver.poll() is None:
        importate = {riga[2] for riga in esito.righe("importati") if riga[2]}
        fermi = {int(riga[0]) for riga in esito.righe("in-attesa")}
        if len(importate) == parti and fermi and all(pid in fermi or not _vivo(pid) for pid in esito.figli()):
            return fermi
        yield
    return set()


def _attendi(condizione, secondi):
    limite = time.monotonic() + secondi
    while not condizione() and time.monotonic() < limite:
        yield
    return condizione()


def _concludi(esito, driver, **dati):
    """Ciò che resta all'uscita del driver: uscita, processi dello scenario ancora vivi, output."""
    esito.rc = driver.poll()
    esito.vivi = _processi_vivi(esito.registro)
    esito.uscita = (esito.registro / "uscita.txt").read_text(errors="replace")
    for nome, valore in dati.items():
        setattr(esito, nome, valore)
    (esito.registro / "cancello").touch()
    return esito


def _un_segnale(avvio, segnale, parti=_PARTI_INTERROTTE):
    driver = yield avvio
    esito = _Esito(None, "", avvio.registro)
    fermi = yield from _al_cancello(esito, driver, parti)
    if esito.righe("nipote"):
        # Il nipote deve già scrivere quando arriva il segnale.
        cartelle = [Path(riga[1]) for riga in esito.righe("nipote")]
        yield from _attendi(lambda: all(c.is_dir() and len(os.listdir(c)) > 100 for c in cartelle), 10)
    if driver.poll() is None:
        driver.send_signal(segnale)
    yield from _attendi(lambda: driver.poll() is not None, 30)
    return _concludi(esito, driver, fermi=fermi)


def _due_segnali(avvio, primo, secondo):
    driver = yield avvio
    esito = _Esito(None, "", avvio.registro)
    fermi = yield from _al_cancello(esito, driver, _PARTI_INTERROTTE)
    driver.send_signal(primo)
    # Il secondo arriva durante la grazia: quando un figlio ha già ricevuto SIGTERM dal driver ed è ancora vivo.
    in_grazia = yield from _attendi(lambda: any(r[1] == "SIGTERM" for r in esito.righe("segnale")), 10)
    if driver.poll() is None:
        driver.send_signal(secondo)
    yield from _attendi(lambda: driver.poll() is not None, 30)
    return _concludi(esito, driver, fermi=fermi if in_grazia else set())


def _sighup_da_ignorare(avvio):
    driver = yield avvio
    esito = _Esito(None, "", avvio.registro)
    fermi = yield from _al_cancello(esito, driver, _PARTI_INTERROTTE)
    driver.send_signal(signal.SIGHUP)
    finito = yield from _attendi(lambda: driver.poll() is not None, 0.5)
    (avvio.registro / "cancello").touch()
    yield from _attendi(lambda: driver.poll() is not None, 30)
    return _concludi(esito, driver, fermi=fermi, finito_per_il_segnale=finito)


def _segnale_durante_la_rimozione(avvio):
    driver = yield avvio
    esito = _Esito(None, "", avvio.registro)
    durante = False

    def rimozione_in_corso():
        nonlocal durante
        righe = esito.righe("molti")
        if not righe or driver.poll() is not None:
            return driver.poll() is not None
        try:
            restano = sum(1 for _ in os.scandir(righe[0][1]))
        except FileNotFoundError:
            return True
        durante = 0 < restano < _FILE_DA_RIMUOVERE
        return durante

    yield from _attendi(rimozione_in_corso, 60)
    if durante:
        driver.send_signal(signal.SIGTERM)
    yield from _attendi(lambda: driver.poll() is not None, 30)
    return _concludi(esito, driver, fermi={"durante la rimozione"} if durante else set())


def _segnale_all_avvio(avvio):
    driver = yield avvio
    figli = f"/proc/{driver.pid}/task/{driver.pid}/children"
    limite = time.monotonic() + 10
    # Senza cedere il passo (lo scenario gira da solo): il segnale deve arrivare entro pochi millisecondi dal primo
    # figlio, mentre il driver ne sta ancora avviando altri.
    while time.monotonic() < limite and driver.poll() is None:
        try:
            with open(figli) as f:
                if f.read().split():
                    break
        except OSError:
            break
    avviato = driver.poll() is None
    driver.send_signal(signal.SIGTERM)
    yield from _attendi(lambda: driver.poll() is not None, 30)
    return _concludi(_Esito(None, "", avvio.registro), driver, fermi={"all'avvio"} if avviato else set())


@pytest.fixture(scope="module")
def interruzioni(mini, tmp_path_factory):
    """Il driver interrotto in vari modi (sempre con segnali mandati al solo driver). `{chiave: esito}` con `rc`,
    `vivi` (processi dello scenario vivi all'uscita del driver), `fermi` (vuoto se il segnale non è arrivato nel
    momento voluto) e l'output; `None` se il driver non esiste. A fine scenario il cancello si apre e ciò che resta
    viene ucciso."""
    if not _DRIVER.exists():
        return None
    base = tmp_path_factory.mktemp("interruzioni")

    def avvio(nome, n=_PARTI_INTERROTTE, *argomenti, **variabili):
        return _avvio_del_driver(mini, base, nome, n, *argomenti, **variabili)

    scenari = {("segnale", nome): _un_segnale(avvio(nome, MINI_SEGNALI="resiste"), getattr(signal, nome))
               for nome in _SEGNALI}
    scenari.update({
        ("doppio", "SIGTERM"): _due_segnali(avvio("doppio-term", MINI_SEGNALI="resiste"),
                                            signal.SIGTERM, signal.SIGTERM),
        ("doppio", "SIGINT"): _due_segnali(avvio("doppio-int", MINI_SEGNALI="resiste"), signal.SIGINT, signal.SIGINT),
        "pulizia": _un_segnale(avvio("pulizia", MINI_SEGNALI="pulisce", MINI_PULIZIA="1"), signal.SIGTERM),
        "sessione": _un_segnale(avvio("sessione", MINI_SESSIONE="1"), signal.SIGTERM),
        "nipote": _un_segnale(avvio("nipote", MINI_NIPOTE="1"), signal.SIGTERM),
        "nohup": _sighup_da_ignorare(_avvio_del_driver(mini, base, "nohup", _PARTI_INTERROTTE,
                                                       preexec_fn=_sighup_ignorato)),
        "rimozione": _segnale_durante_la_rimozione(_avvio_del_driver(
            mini, base, "rimozione", 1, "tests/test_alfa.py", cancello=False, MINI_MOLTI=str(_FILE_DA_RIMUOVERE))),
        "funzione": _fino_alla_fine(_Avvio(
            [sys.executable, "-c", _MAIN_COME_FUNZIONE, str(mini / "tests"), "-n", "1", "tests/test_alfa.py"],
            mini, base / "funzione", {"TMPDIR": str(base / "funzione" / "tmp-chiamante")}, _segnali_di_default)),
    })
    esiti = _esegui(scenari)
    for i in range(_AVVII_INTERROTTI):
        esiti.update(_esegui({("avvio", i): _segnale_all_avvio(avvio(f"avvio-{i}", _PARTI_ALL_AVVIO))}))
    return esiti


def _interruzione(interruzioni, chiave):
    assert interruzioni is not None, f"manca il driver {_DRIVER}"
    esito = interruzioni[chiave]
    assert esito.fermi, f"precondizione: il segnale doveva arrivare nel momento voluto\n{esito.uscita}"
    return esito


def _cartella_rimossa(esito):
    restano = _percorsi_dei_processi(esito)
    assert restano and not [p for p in restano if p.exists()], [str(p) for p in restano if p.exists()]
    assert sorted(p.name for p in esito.tmp_chiamante().iterdir()) == []


@pytest.mark.parametrize("segnale", _SEGNALI)
class TestDriverInterrotto:
    """Un segnale al solo driver mentre i figli lavorano: chi lancia il driver lo ferma con SIGTERM (un
    `timeout`, un gestore di job), SIGHUP (il terminale che si chiude) o SIGINT. I figli non devono restare a
    scrivere nella cartella del driver, e la cartella non deve restare nella directory temporanea."""

    def test_il_driver_esce_con_128_piu_il_segnale(self, interruzioni, segnale):
        esito = _interruzione(interruzioni, ("segnale", segnale))
        assert esito.rc == 128 + getattr(signal, segnale), f"exit {esito.rc}:\n{esito.uscita}"

    def test_nessun_figlio_resta_vivo(self, interruzioni, segnale):
        esito = _interruzione(interruzioni, ("segnale", segnale))
        assert not esito.vivi, f"processi vivi dopo l'uscita del driver: {esito.vivi}\n{esito.uscita}"

    def test_la_cartella_del_driver_non_esiste_piu(self, interruzioni, segnale):
        _cartella_rimossa(_interruzione(interruzioni, ("segnale", segnale)))


class TestDriverFermaTuttoAOgniUscita:
    """«A ogni uscita i processi sono fermati e la cartella rimossa» vale anche nei casi limite: un secondo segnale,
    un segnale nei primi millisecondi, processi avviati dai test, una rimozione interrotta."""

    @pytest.mark.parametrize("segnale", ("SIGTERM", "SIGINT"))
    def test_un_secondo_segnale_durante_la_grazia_non_lascia_figli_vivi(self, interruzioni, segnale):
        esito = _interruzione(interruzioni, ("doppio", segnale))
        assert esito.rc not in (None, 0), f"exit {esito.rc}:\n{esito.uscita}"
        assert not esito.vivi, f"processi vivi dopo l'uscita del driver: {esito.vivi}\n{esito.uscita}"
        _cartella_rimossa(esito)

    def test_un_segnale_durante_l_avvio_delle_parti_non_lascia_orfani(self, interruzioni):
        assert interruzioni is not None, f"manca il driver {_DRIVER}"
        prove = [interruzioni[("avvio", i)] for i in range(_AVVII_INTERROTTI)]
        assert all(esito.fermi for esito in prove), "precondizione: il segnale doveva arrivare durante l'avvio"
        orfani = {i: esito.vivi for i, esito in enumerate(prove) if esito.vivi}
        assert not orfani, f"processi vivi dopo l'uscita del driver, per prova: {orfani}"
        assert all(esito.rc not in (None, 0) for esito in prove), [esito.rc for esito in prove]

    def test_i_figli_ricevono_sigterm_e_finiscono_la_pulizia_prima_di_sigkill(self, interruzioni):
        # Un figlio che gestisce SIGTERM (chiude un server, rimuove ciò che ha creato) ha il tempo di farlo.
        esito = _interruzione(interruzioni, "pulizia")
        puliti = {int(riga[0]) for riga in esito.righe("pulizia")}
        assert esito.fermi <= puliti, f"senza pulizia: {sorted(esito.fermi - puliti)}\n{esito.uscita}"

    def test_un_processo_in_sessione_propria_viene_fermato_dal_teardown(self, interruzioni):
        # Fuori dal gruppo della parte: lo ferma solo il `finally` della fixture che l'ha avviato, cioè una parte
        # che a SIGTERM esegue i teardown invece di morire.
        esito = _interruzione(interruzioni, "sessione")
        assert esito.righe("sessione"), "precondizione: i test hanno avviato i processi"
        assert not esito.vivi, f"processi vivi dopo l'uscita del driver: {esito.vivi}\n{esito.uscita}"
        assert esito.rc == 128 + signal.SIGTERM, f"exit {esito.rc}:\n{esito.uscita}"

    def test_un_nipote_che_scrive_durante_la_rimozione_non_da_traceback(self, interruzioni):
        esito = _interruzione(interruzioni, "nipote")
        assert "Traceback" not in esito.uscita, esito.uscita
        assert esito.rc == 128 + signal.SIGTERM, f"exit {esito.rc}:\n{esito.uscita}"
        restano = sorted(p.name for p in esito.tmp_chiamante().iterdir())
        # Rimossa, oppure il driver dice che cosa resta, senza dichiararla rimossa.
        assert not restano or (all(nome in esito.uscita for nome in restano)
                               and "directory rimossa" not in esito.uscita), (restano, esito.uscita)

    def test_un_segnale_durante_la_rimozione_non_la_interrompe(self, interruzioni):
        esito = _interruzione(interruzioni, "rimozione")
        assert "Traceback" not in esito.uscita, esito.uscita
        assert esito.rc not in (None, 0), f"exit {esito.rc}:\n{esito.uscita}"
        _cartella_rimossa(esito)

    def test_un_sighup_ignorato_da_chi_lancia_il_driver_resta_ignorato(self, interruzioni):
        # Con `nohup` (o in un job in background) il driver non si ferma alla chiusura del terminale.
        esito = _interruzione(interruzioni, "nohup")
        assert not esito.finito_per_il_segnale, f"il driver si è fermato per SIGHUP:\n{esito.uscita}"
        assert esito.rc == 0, f"exit {esito.rc}:\n{esito.uscita}"
        assert Counter(esito.eseguiti()) == Counter(_ATTESI)

    def test_main_chiamata_come_funzione_ripristina_i_gestori_dei_segnali(self, interruzioni):
        assert interruzioni is not None, f"manca il driver {_DRIVER}"
        esito = interruzioni["funzione"]
        assert esito.rc == 0, esito.uscita
        riferito = json.loads(esito.uscita.strip().splitlines()[-1])
        assert riferito["rc"] == 0 and riferito["dopo"] == riferito["prima"], riferito
