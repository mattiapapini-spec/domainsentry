"""La suite in N processi pytest insieme, con la sola libreria standard (BUILD-09).

    python tests/run_parallel.py -n N [argomenti di pytest]

Senza argomenti di pytest esegue `tests`. Il processo k esegue la parte k di N (`DS_TEST_SHARD`, vedi
tests/conftest.py) con il proprio stato (CASES_DB, FEED_DATA, INTEL_DIR, EVENTS_DIR), la propria
--basetemp e il proprio TMPDIR, in una directory temporanea rimossa alla fine: due processi sugli
stessi file si rovinerebbero i dati a vicenda, e ciò che un modulo di test crea con `tempfile` senza
rimuoverlo sparisce con la directory invece di accumularsi in quella del chiamante.

I codici d'uscita non bastano: un test che nessuna parte esegue lascia ogni processo a 0. Per questo
ogni processo scrive i test raccolti e quelli eseguiti (DS_TEST_SHARD_REPORT), e il driver esce con
errore se un processo esce fuori da 0 e 5 (5: la sua parte è vuota) o non arriva alla fine della
sessione con un rapporto ben formato, se i processi non hanno raccolto la stessa suite, se un test
raccolto non è stato eseguito o lo è stato più di una volta, o se non c'è alcun test (5, come pytest).
`--collect-only` (`--co`, `--collectonly`) è un errore d'uso (2): raccogliere senza eseguire non può
mantenere quella promessa; una parte si vede con `DS_TEST_SHARD=k/n python -m pytest --collect-only`.

Ogni parte guida un gruppo di processi proprio, con stdin da /dev/null (un gruppo che non è in primo
piano si fermerebbe leggendo dal terminale). A ogni uscita, anche per SIGTERM, SIGHUP o SIGINT (uscita
128 + segnale), ogni gruppo riceve SIGTERM, che in una parte diventa KeyboardInterrupt (tests/conftest.py):
pytest esegue i teardown e le fixture fermano ciò che hanno avviato. Dopo un secondo di grazia ciò che
resta nel gruppo riceve SIGKILL; poi la directory si rimuove, con una riprova. Un segnale che arriva
durante l'avvio di una parte, l'arresto o la rimozione si rimanda alla fine di quella fase, e dopo il
primo gli altri non cambiano nulla; uno che il driver riceve già ignorato (`nohup`, un job in background)
resta ignorato. Se la directory non sparisce del tutto il driver ne stampa il percorso ed esce con errore.

Limiti:
- tests/test_feed_manager.py fissa FEED_DATA su un percorso fisso all'import, cioè in ogni parte, e
  alcuni test di quel modulo e di tests/test_case_manager.py usano altri percorsi fissi: lì lo stato
  non è per processo, e due driver (o un driver e una suite in serie) lanciati insieme possono
  collidere;
- nessun limite di tempo per processo: un processo appeso tiene fermo il driver finché non lo si
  interrompe;
- un processo che un test stacca dal gruppo della parte (una sessione o un gruppo propri) e non ferma
  in un teardown sopravvive al driver, e può scrivere nella directory mentre questa si rimuove; un
  teardown che dura più del secondo di grazia è troncato da SIGKILL, e ciò che doveva fermare può
  sopravvivere allo stesso modo;
- le parti stanno in gruppi propri, quindi un SIGKILL al driver o al suo gruppo (`kill -9 -PGID`,
  `timeout -s KILL`) non le raggiunge: restano vive, e la directory resta. Per fermare il driver da
  fuori si usa SIGTERM, SIGHUP o SIGINT;
- `main` installa gestori di segnali, quindi va chiamata solo dal thread principale; restituisce
  l'uscita e ripristina i gestori di prima dopo la rimozione;
- i test del driver che controllano processi e segnali leggono /proc: sono provati solo su Linux.
"""
import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter

_STATO = {"CASES_DB": "cases.db", "FEED_DATA": "feed", "INTEL_DIR": "intel", "EVENTS_DIR": "events"}


class _Interrotto(BaseException):
    """Un segnale come eccezione: passa dai `finally` che fermano le parti e rimuovono la directory, invece di
    terminare il driver all'istante."""


class _Segnali:
    """SIGTERM, SIGHUP e SIGINT con la disposizione di default diventano `_Interrotto`, solo il primo: dopo, il
    driver sta già fermando tutto. Con `rinvio` si annotano soltanto, perché l'avvio di una parte (fra `Popen` e
    la sua registrazione), l'arresto e la rimozione interrotti a metà lascerebbero processi o file. All'uscita i
    gestori tornano quelli di prima."""

    def __enter__(self):
        # Rinviati fin dall'installazione: il primo `rimandati` li guarda.
        self.rinvio, self.ricevuto, self.precedenti = True, None, {}
        for numero in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            if signal.getsignal(numero) in (signal.SIG_DFL, signal.default_int_handler):
                self.precedenti[numero] = signal.signal(numero, self._gestore)
        return self

    def __exit__(self, *_eccezione):
        for numero, gestore in self.precedenti.items():
            signal.signal(numero, gestore)

    def _gestore(self, numero, _frame):
        primo = self.ricevuto is None
        self.ricevuto = self.ricevuto or numero
        if primo and not self.rinvio:
            raise _Interrotto(numero)

    @contextlib.contextmanager
    def rimandati(self):
        self.rinvio = True
        try:
            yield
        finally:
            self.rinvio = False
        if self.ricevuto:
            raise _Interrotto(self.ricevuto)


def _forma_valida(rapporto):
    # Ciò che il confronto più sotto legge: liste di stringhe e coppie di stringhe (nodeid, esito).
    return (isinstance(rapporto, dict) and isinstance(rapporto.get("raccolti"), list)
            and isinstance(rapporto.get("eseguiti"), list)
            and all(isinstance(nodeid, str) for nodeid in rapporto["raccolti"])
            and all(isinstance(voce, list) and len(voce) == 2 and all(isinstance(x, str) for x in voce)
                    for voce in rapporto["eseguiti"]))


def _al_gruppo(gruppo, numero):
    try:
        os.killpg(gruppo, numero)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _ferma(processi):
    # SIGTERM a ogni gruppo, per chi ha un gestore che fa pulizia; un secondo di grazia finché il gruppo ha
    # processi; poi SIGKILL a ciò che resta, che ignori SIGTERM o che la parte abbia lasciato nel gruppo. L'attesa
    # finale raccoglie i capigruppo.
    gruppi = [processo.pid for _, processo, _ in processi if _al_gruppo(processo.pid, signal.SIGTERM)]
    limite = time.monotonic() + 1
    while gruppi and time.monotonic() < limite:
        time.sleep(0.01)
        for _, processo, _ in processi:
            processo.poll()
        gruppi = [gruppo for gruppo in gruppi if _al_gruppo(gruppo, 0)]
    for gruppo in gruppi:
        _al_gruppo(gruppo, signal.SIGKILL)
    for _, processo, _ in processi:
        processo.wait()


def _rimuovi(cartella):
    # Una riprova dopo una pausa breve: un processo appena ucciso può avere creato un file mentre la rimozione
    # scorreva la directory. Vero se la directory non c'è più.
    shutil.rmtree(cartella, ignore_errors=True)
    if os.path.lexists(cartella):
        time.sleep(0.1)
        shutil.rmtree(cartella, ignore_errors=True)
    return not os.path.lexists(cartella)


def _esempi(test):
    return f"{len(test)}, p.es. {sorted(test)[:3]}"


def main(argv):
    try:
        n = int(argv[1]) if argv[0] == "-n" else 0
    except (IndexError, ValueError):
        n = 0
    if n < 1:
        print("uso: python tests/run_parallel.py -n N [argomenti di pytest]", file=sys.stderr)
        return 2
    argomenti = argv[2:] or ["tests"]
    solo_raccolta = [a for a in argomenti if a.split("=", 1)[0] in ("--collect-only", "--co", "--collectonly")]
    if solo_raccolta:
        print(f"uso: {solo_raccolta[0]} non si usa con il driver, che esegue ogni test raccolto; una parte si vede "
              "con DS_TEST_SHARD=k/n python -m pytest --collect-only", file=sys.stderr)
        return 2
    radice = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inizio = time.monotonic()
    processi, rapporti, rosso, tmp, rimossa = [], [], False, None, True
    with _Segnali() as segnali:
        try:
            with segnali.rimandati():
                tmp = tempfile.mkdtemp(prefix="ds-run-parallel-")
            for k in range(1, n + 1):
                cartella = os.path.join(tmp, str(k))
                os.mkdir(cartella)
                os.mkdir(os.path.join(cartella, "tmp"))
                ambiente = dict(os.environ, DS_TEST_SHARD=f"{k}/{n}",
                                DS_TEST_SHARD_REPORT=os.path.join(cartella, "rapporto.json"),
                                TMPDIR=os.path.join(cartella, "tmp"),
                                **{variabile: os.path.join(cartella, nome) for variabile, nome in _STATO.items()})
                # Dopo gli argomenti dell'utente, così vincono: una --basetemp comune verrebbe svuotata da
                # ogni processo all'avvio, e la cache di pytest scritta da N processi insieme (o --lf, che
                # toglie test dopo la scelta della parte) falserebbe il confronto con la raccolta.
                comando = [sys.executable, "-m", "pytest", *argomenti, "-q", "-p", "no:cacheprovider",
                           f"--basetemp={os.path.join(cartella, 'pytest')}"]
                with open(os.path.join(cartella, "uscita.txt"), "w") as uscita, segnali.rimandati():
                    processo = subprocess.Popen(comando, cwd=radice, env=ambiente, stdin=subprocess.DEVNULL,
                                                stdout=uscita, stderr=subprocess.STDOUT, process_group=0)
                    processi.append((k, processo, cartella))
            for k, processo, cartella in processi:
                # Senza raccoglierlo: finché il capogruppo resta zombie il suo pid, cioè l'id del gruppo, non passa
                # a un altro processo, e l'arresto finale non può colpire un gruppo estraneo.
                stato = os.waitid(os.P_PID, processo.pid, os.WEXITED | os.WNOWAIT)
                rc = stato.si_status if stato.si_code == os.CLD_EXITED else -stato.si_status
                with open(os.path.join(cartella, "uscita.txt"), errors="replace") as f:
                    testo = f.read()
                try:
                    with open(os.path.join(cartella, "rapporto.json"), "rb") as f:
                        dati = f.read()
                except OSError:
                    errore = "il processo non è arrivato alla fine della sessione"
                else:
                    try:
                        rapporto = json.loads(dati.decode("utf-8"))
                        errore = None if _forma_valida(rapporto) else "rapporto di forma non valida"
                    except (ValueError, RecursionError) as e:
                        errore = f"rapporto illeggibile ({type(e).__name__})"
                if errore is None:
                    rapporti.append(rapporto)
                righe = testo.strip().splitlines()
                print(f"[parte {k}/{n}] exit {rc}: {righe[-1] if righe else '(nessun output)'}")
                if rc not in (0, 5) or errore:
                    print(testo)
                    if errore:
                        print(f"[parte {k}/{n}] ERRORE: {errore}")
                    rosso = True
        except _Interrotto:
            pass
        finally:
            # A ogni uscita (anche per eccezione o segnale): nessun processo deve sopravvivere scrivendo nella
            # directory temporanea che sta per essere rimossa. Da qui un segnale si annota soltanto.
            segnali.rinvio = True
            _ferma(processi)
            if tmp is not None and not _rimuovi(tmp):
                rimossa, rosso = False, True
                print(f"ERRORE: la directory temporanea {tmp} non è stata rimossa del tutto")
    if segnali.ricevuto:
        print(f"interrotto da {signal.Signals(segnali.ricevuto).name}: processi fermati"
              f"{', directory rimossa' if rimossa else ''}", file=sys.stderr)
        return 128 + segnali.ricevuto
    if len(rapporti) < n:
        return 1
    raccolti = Counter(rapporti[0]["raccolti"])
    eseguiti = Counter(nodeid for rapporto in rapporti for nodeid, _ in rapporto["eseguiti"])
    esiti = Counter(esito for rapporto in rapporti for _, esito in rapporto["eseguiti"])
    problemi = []
    if any(Counter(rapporto["raccolti"]) != raccolti for rapporto in rapporti):
        problemi.append("i processi non hanno raccolto la stessa suite")
    if raccolti - eseguiti:
        problemi.append("test raccolti e non eseguiti: " + _esempi(raccolti - eseguiti))
    if eseguiti - raccolti:
        problemi.append("test eseguiti più volte o fuori dalla raccolta: " + _esempi(eseguiti - raccolti))
    print(f"== {sum(raccolti.values())} raccolti, {sum(eseguiti.values())} eseguiti in {n} processi: "
          f"{', '.join(f'{c} {e}' for e, c in sorted(esiti.items())) or 'nessun test'} "
          f"in {time.monotonic() - inizio:.2f}s ==")
    for problema in problemi:
        print("ERRORE:", problema)
    if rosso or problemi:
        return 1
    return 0 if raccolti else 5


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
