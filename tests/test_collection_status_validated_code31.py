"""CODE-31: `/classify/variant` accetta in `collection_status` solo le cinque sezioni, con un booleano.

L'endpoint sta nella zona non autenticata e `collection_status` era un `dict` libero: qualunque chiave, di qualunque
lunghezza, con qualunque valore. Le chiavi finivano nella rationale della guardia (`CODE-30` ne limita la lunghezza
a valle) e un valore «vero» qualsiasi, anche la stringa `"false"`, dichiarava fallita una sezione. L'orchestrator
manda solo `dns`, `cert`, `http`, `whois` e `reputation` con un booleano: il resto ora è rifiutato con 422.
"""

import pytest
from fastapi.testclient import TestClient

from services.classifier import app

client = TestClient(app)


def _post(collection_status, path="/classify/variant"):
    variant = {"domain": "acme-crop.example", "fuzzer": "transposition", "collection_status": collection_status}
    body = {"variants": [variant]} if path == "/classify/batch" else variant
    return client.post(path, json=body)


class TestCODE31OnlyKnownSectionsWithABoolean:
    @pytest.mark.parametrize("status", [
        {"cert" + "X" * 2000: True},
        {"dominio": True},
        {"DNS": True},
        {"": True},
    ])
    def test_an_unknown_section_is_rejected(self, status):
        assert _post(status).status_code == 422

    @pytest.mark.parametrize("value", ["false", "true", "yes", 1, 0, None, [], {}])
    def test_a_value_that_is_not_a_boolean_is_rejected(self, value):
        assert _post({"whois": value}).status_code == 422

    def test_a_bad_variant_rejects_the_batch(self):
        assert _post({"dominio": True}, path="/classify/batch").status_code == 422


class TestCODE31WhatTheOrchestratorSendsStillWorks:
    @pytest.mark.parametrize("status", [
        None,
        {},
        {"whois": False},
        {"dns": False, "cert": False, "http": False, "whois": False, "reputation": False},
    ])
    def test_nothing_failed_classifies_normally(self, status):
        resp = _post(status)

        assert resp.status_code == 200
        assert resp.json()["auto_classification"] == "needs_review"

    def test_a_failed_section_still_triggers_the_guard(self):
        resp = _post({"cert": True, "http": False})

        assert resp.status_code == 200
        assert resp.json()["auto_classification"] == "insufficient_data"
        assert resp.json()["rationale"].startswith("Raccolta dati fallita per: cert")
