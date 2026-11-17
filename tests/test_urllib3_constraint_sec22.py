"""SEC-22: il vincolo su urllib3 in `requirements.txt` esclude le versioni su cui il tetto anti-bomba di SEC-16 non
regge.

`urllib3>=2,<3` ammetteva tutta la serie 2.x. Misurato il 2026-11-10 con
`tests/test_utils.py::TestFetchDecompressionBombGuardrail`, stesso `requests` 2.32.3, Python 3.12: con 2.0.0, 2.5.0,
2.6.0 e 2.6.1 il caso chunked + gzip decomprime un singolo blocco di circa 20 MB (soglia 32 KB); con 2.6.2, 2.6.3,
2.7.0 e 2.8.0 entrambi i casi passano. L'immagine installa da `requirements.txt` alla build: il vincolo è l'unica
garanzia sulla versione che gira.
"""

from pathlib import Path

import pytest
import urllib3
from packaging.requirements import Requirement
from packaging.version import Version

_REQUIREMENTS = Path(__file__).resolve().parent.parent / "requirements.txt"


def _urllib3_specifier():
    found = []
    for line in _REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            req = Requirement(line)
            if req.name.lower() == "urllib3":
                found.append(req.specifier)
    assert len(found) == 1, found
    return found[0]


class TestSEC22Urllib3Constraint:
    @pytest.mark.parametrize("version", ["1.26.20", "2.0.0", "2.5.0", "2.6.0", "2.6.1"])
    def test_versions_where_the_bomb_guard_fails_are_excluded(self, version):
        assert Version(version) not in _urllib3_specifier()

    @pytest.mark.parametrize("version", ["2.6.2", "2.6.3", "2.7.0", "2.8.0"])
    def test_versions_measured_with_the_guard_holding_are_allowed(self, version):
        assert Version(version) in _urllib3_specifier()

    def test_the_next_major_stays_excluded(self):
        assert Version("3.0.0") not in _urllib3_specifier()

    def test_the_installed_urllib3_satisfies_the_constraint(self):
        assert Version(urllib3.__version__) in _urllib3_specifier(), urllib3.__version__
