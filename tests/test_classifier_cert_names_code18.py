"""CODE-18: un nome di certificato che non è una stringa non manda in errore la classificazione.

crt.sh può restituire `"common_name": null`, e `/classify/variant` (zona non autenticata) riceve il payload così
com'è: un elemento `None` (o un numero) in `unique_cn` faceva fallire con 500 il confronto coi provider enterprise,
e il dominio restava senza classificazione per quel ciclo. Gli elementi che non sono nomi si ignorano: valgono come
un elenco senza di loro.
"""

import pytest
from fastapi.testclient import TestClient

from services.classifier import app

client = TestClient(app, raise_server_exceptions=False)

_DNS = {"records": {"A": ["192.0.2.10"], "MX": [], "NS": ["ns1.example.net"]}}


def _classify(unique_cn):
    body = {"domain": "acme-corp-login.com", "fuzzer": "test", "dns": _DNS,
            "cert": {"ct_certificates": {"total": 1, "unique_cn": unique_cn, "certificates": []}}}
    resp = client.post("/classify/variant", json=body)
    assert resp.status_code == 200, resp.text
    result = resp.json()
    return result["auto_classification"], result["confidence"], result.get("rule")


class TestCODE18CertificateNamesThatAreNotNames:
    @pytest.mark.parametrize("unique_cn", [[None], [None, None], [7], [{"cn": "x"}], [["a"]], [True]])
    def test_they_classify_like_an_empty_list(self, unique_cn):
        assert _classify(unique_cn) == _classify([])

    def test_a_null_next_to_an_enterprise_provider_still_finds_it(self):
        assert _classify([None, "tls.automattic.com"]) == _classify(["tls.automattic.com"])
        assert _classify(["tls.automattic.com"])[0] == "legitimate_probable"

    @pytest.mark.parametrize("unique_cn", [7, {"cn": "tls.automattic.com"}, None])
    def test_a_list_that_is_not_a_list_counts_as_empty(self, unique_cn):
        assert _classify(unique_cn) == _classify([])

    def test_a_null_next_to_an_ordinary_name_is_ignored(self):
        assert _classify(["acme-corp-login.com", None]) == _classify(["acme-corp-login.com"])
