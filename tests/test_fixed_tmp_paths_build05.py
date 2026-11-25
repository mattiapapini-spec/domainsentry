"""BUILD-05: la suite deve essere ripetibile sulla stessa macchina.

Alcuni test usano percorsi fissi in /tmp (CASES_DB=/tmp/cm_svc.db, FEED_DATA=/tmp/test_feed_data,
/tmp/test_feed_auth) o impostano FEED_FILE, che services/feed_manager.py non legge: lo stato scritto
da un'esecuzione resta e la seconda fallisce (400 per duplicato, added_count 0). La CI non se ne
accorge perché ogni runner parte con /tmp vuoto.

Qui si esegue due volte di fila, con lo stesso ambiente, i test noti per lasciare stato: la seconda
esecuzione deve passare come la prima. TMPDIR e le variabili di stato puntano a una directory nuova,
così il test non dipende da cosa c'è già in /tmp e resta valido anche dentro tests/run_parallel.py.
Nessuna rete.
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

NODE_IDS = [
    "tests/test_case_manager.py::TestServiceToken::test_service_token_can_ingest",
    "tests/test_feed_manager.py::TestFeedWriteAuth::test_auth_disabled_write_open",
    "tests/test_feed_manager.py::TestFeedWriteAuth::test_auth_enabled_valid_token_with_permission",
    "tests/test_feed_manager.py::TestClientOnboard::test_onboard_adds_domains_and_notes",
    "tests/test_feed_manager.py::TestClientOnboard::test_onboard_skips_invalid_and_duplicates",
    "tests/test_feed_manager.py::TestPromoteDomain::test_promote_resolves_legitimate",
]


def _env(base: Path) -> dict:
    env = os.environ.copy()
    # Niente selezione di parte né rapporto del driver parallelo: il sotto-processo esegue tutti e 6.
    for k in ("DS_TEST_SHARD", "DS_TEST_SHARD_REPORT"):
        env.pop(k, None)
    state = base / "state"
    state.mkdir()
    tmp = base / "tmp"
    tmp.mkdir()
    env.update(
        PYTHONPATH=str(ROOT),
        TMPDIR=str(tmp),
        CASES_DB=str(state / "cases.db"),
        FEED_DATA=str(state / "feed"),
        INTEL_DIR=str(state / "intel"),
        EVENTS_DIR=str(state / "events"),
    )
    return env


def _run(env: dict, base: Path, n: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "--basetemp", str(base / f"bt{n}"), *NODE_IDS],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=300,
    )


def test_suite_is_repeatable_on_same_machine(tmp_path):
    env = _env(tmp_path)
    for n in (1, 2):
        r = _run(env, tmp_path, n)
        assert r.returncode == 0, f"esecuzione {n} fallita:\n{r.stdout}\n{r.stderr}"
