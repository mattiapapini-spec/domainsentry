"""Tests for services/cert_intel.py — righe anomale nel JSON di crt.sh (COL-32, ID provvisorio).

Difetto: una sola riga anomala nel JSON di crt.sh fa perdere l'intera raccolta CT del
dominio. Il `except Exception` di `cert_check` trasforma l'eccezione in `result["error"]`,
quindi `ct_certificates.total` resta 0 e `san_subdomains_discovered` resta `[]` anche per
le righe valide.

Comportamento voluto: una riga degradata non contamina le righe valide. Per le righe non
dict non si decide qui se vengano scartate o contate: si esige solo che non facciano
perdere le righe valide e che non compaiano come certificati con campi non stringa.
Un top-level che non è una lista resta un errore (un guasto non è un'assenza).

Isolamento di rete: `cert_intel.http_get_with_retry` è sostituito con un doppio in memoria
(stessa tecnica di tests/test_cert_intel.py). Solo domini example.com.
"""
import json

import pytest
from fastapi.testclient import TestClient

from services import cert_intel
from services.cert_intel import app

client = TestClient(app)

DOMAIN = "example.com"

GOOD = {
    "id": 1,
    "common_name": "example.com",
    "name_value": "a.example.com\nb.example.com",
    "issuer_name": "Let's Encrypt",
    "not_before": "2026-01-01T00:00:00",
    "not_after": "2026-04-01T00:00:00",
    "entry_timestamp": "2026-01-01T00:00:00",
}


@pytest.fixture(autouse=True)
def _clean_ct_cache():
    cert_intel._ct_cache.clear()
    cert_intel._ct_cache_order.clear()
    yield
    cert_intel._ct_cache.clear()
    cert_intel._ct_cache_order.clear()


def _crtsh_ok(payload):
    return {
        "status_code": 200,
        "content": json.dumps(payload).encode(),
        "headers": {},
        "final_url": None,
        "error": None,
        "attempts": 1,
    }


def _serve(monkeypatch, payload):
    """Fa rispondere il doppio con `payload`; ritorna la lista delle chiamate."""
    calls = []

    def _fake_get(url, **kwargs):
        calls.append(url)
        return _crtsh_ok(payload)

    monkeypatch.setattr(cert_intel, "http_get_with_retry", _fake_get)
    return calls


def _fetch():
    r = client.get("/cert", params={"domain": DOMAIN})
    assert r.status_code == 200
    return r.json()


def _bad(**overrides):
    return {**GOOD, "id": 2, **overrides}


# Righe dict con un campo anomalo (key presente ma valore non stringa).
BAD_NAME_VALUE = [
    pytest.param(None, id="name_value-null"),
    pytest.param(5, id="name_value-int"),
    pytest.param(["x.example.com"], id="name_value-list"),
    pytest.param({"a": 1}, id="name_value-dict"),
]
BAD_COMMON_NAME = [
    pytest.param(None, id="common_name-null"),
    pytest.param(5, id="common_name-int"),
    pytest.param(["a"], id="common_name-list"),
    pytest.param({"a": 1}, id="common_name-dict"),
]
NON_DICT_ROWS = [
    pytest.param(None, id="row-null"),
    pytest.param("x", id="row-string"),
    pytest.param([], id="row-list"),
    pytest.param(7, id="row-int"),
]


def _assert_valid_row_survived(body):
    assert body["error"] is None, f"raccolta persa per una riga anomala: {body['error']!r}"
    assert "a.example.com" in body["san_subdomains_discovered"]
    assert "b.example.com" in body["san_subdomains_discovered"]
    certs = body["ct_certificates"]["certificates"]
    assert any(c.get("id") == 1 for c in certs), "la riga valida deve essere fra i certificati"
    assert "example.com" in body["ct_certificates"]["unique_cn"]


def _assert_only_string_fields(body):
    for cn in body["ct_certificates"]["unique_cn"]:
        assert isinstance(cn, str), f"unique_cn contiene un non-stringa: {cn!r}"
    for c in body["ct_certificates"]["certificates"]:
        assert isinstance(c.get("common_name"), str), f"common_name non stringa: {c!r}"
        assert isinstance(c.get("name_value"), str), f"name_value non stringa: {c!r}"


class TestAnomalousRowsKeepValidRows:
    @pytest.mark.parametrize("value", BAD_NAME_VALUE)
    def test_bad_name_value_row_does_not_lose_valid_row(self, monkeypatch, value):
        _serve(monkeypatch, [GOOD, _bad(name_value=value)])
        body = _fetch()
        _assert_valid_row_survived(body)
        _assert_only_string_fields(body)

    @pytest.mark.parametrize("value", BAD_COMMON_NAME)
    def test_bad_common_name_row_does_not_lose_valid_row(self, monkeypatch, value):
        _serve(monkeypatch, [GOOD, _bad(common_name=value)])
        body = _fetch()
        _assert_valid_row_survived(body)
        _assert_only_string_fields(body)

    @pytest.mark.parametrize("row", NON_DICT_ROWS)
    def test_non_dict_row_does_not_lose_valid_row(self, monkeypatch, row):
        _serve(monkeypatch, [GOOD, row])
        body = _fetch()
        _assert_valid_row_survived(body)
        _assert_only_string_fields(body)

    @pytest.mark.parametrize("row", NON_DICT_ROWS)
    def test_non_dict_row_before_valid_row_does_not_lose_valid_row(self, monkeypatch, row):
        _serve(monkeypatch, [row, GOOD])
        body = _fetch()
        _assert_valid_row_survived(body)


class TestPartiallyAnomalousRow:
    @pytest.mark.parametrize("value", BAD_COMMON_NAME)
    def test_valid_name_value_sans_collected_when_common_name_bad(self, monkeypatch, value):
        _serve(monkeypatch, [_bad(common_name=value, name_value="c.example.com\nd.example.com")])
        body = _fetch()
        assert body["error"] is None
        assert body["san_subdomains_discovered"] == ["c.example.com", "d.example.com"]
        _assert_only_string_fields(body)

    @pytest.mark.parametrize("value", BAD_NAME_VALUE)
    def test_valid_common_name_collected_when_name_value_bad(self, monkeypatch, value):
        _serve(monkeypatch, [_bad(common_name="www.example.com", name_value=value)])
        body = _fetch()
        assert body["error"] is None
        assert "www.example.com" in body["ct_certificates"]["unique_cn"]
        _assert_only_string_fields(body)

    def test_mixed_common_name_types_still_sorted_strings(self, monkeypatch):
        _serve(monkeypatch, [
            GOOD,
            _bad(id=2, common_name=None),
            _bad(id=3, common_name=5),
            _bad(id=4, common_name="www.example.com"),
        ])
        body = _fetch()
        assert body["error"] is None
        assert body["ct_certificates"]["unique_cn"] == ["example.com", "www.example.com"]


class TestTopLevelNotAList:
    """Guardia: un top-level non lista è un guasto, non un'assenza. Probabilmente già verde."""

    @pytest.mark.parametrize("payload", [
        pytest.param({"error": "x"}, id="dict"),
        pytest.param(None, id="null"),
        pytest.param("x", id="string"),
        pytest.param(5, id="int"),
    ])
    def test_non_list_payload_is_error_and_not_cached(self, monkeypatch, payload):
        calls = _serve(monkeypatch, payload)
        body = _fetch()
        assert body["error"] is not None
        assert body["ct_certificates"]["total"] == 0
        _fetch()
        assert len(calls) == 2, "un esito di errore non deve andare in cache"


class TestCacheWithAnomalousRow:
    def test_outcome_with_anomalous_row_is_cached_as_success(self, monkeypatch):
        calls = _serve(monkeypatch, [GOOD, _bad(name_value=None), _bad(id=3, common_name=None), None])
        first = _fetch()
        second = _fetch()
        assert first["error"] is None
        assert second["error"] is None
        assert len(calls) == 1, "il successo con righe anomale deve essere servito da cache"
        assert "a.example.com" in second["san_subdomains_discovered"]
        assert "b.example.com" in second["san_subdomains_discovered"]


class TestAllValidRowsRegression:
    def test_all_valid_rows_output_unchanged(self, monkeypatch):
        rows = [
            GOOD,
            {**GOOD, "id": 2, "common_name": "www.example.com",
             "name_value": "*.example.com\nwww.example.com\nexample.com"},
            {**GOOD, "id": 3, "common_name": "example.com", "name_value": "c.example.com"},
        ]
        _serve(monkeypatch, rows)
        body = _fetch()
        assert body["error"] is None
        assert body["ct_certificates"]["total"] == 3
        assert body["ct_certificates"]["unique_cn"] == ["example.com", "www.example.com"]
        assert body["san_subdomains_discovered"] == [
            "a.example.com", "b.example.com", "c.example.com", "www.example.com"]
        assert body["ct_certificates"]["certificates"] == rows


# ---------------------------------------------------------------------------
# Riapertura G3: valori che json.loads accetta ma che rompono la serializzazione
# della risposta (NaN/Infinity, surrogati isolati) o il parsing (interi enormi).
# Il test non impone se la riga anomala venga scartata o ripulita.
# ---------------------------------------------------------------------------
import logging
import re

safe_client = TestClient(app, raise_server_exceptions=False)

_PLACEHOLDER = "@@X@@"
_FIELDS = ["id", "common_name", "name_value", "issuer_name",
           "not_before", "not_after", "entry_timestamp"]
_LITERALS = [
    pytest.param("NaN", id="NaN"),
    pytest.param("Infinity", id="Infinity"),
    pytest.param("-Infinity", id="-Infinity"),
    pytest.param("1e999", id="1e999"),
]


def _raw_payload(rows, literal=None):
    """JSON grezzo; `literal` sostituisce il segnaposto come token non quotato."""
    text = json.dumps(rows)  # ensure_ascii: i surrogati restano escape \\ud800
    if literal is not None:
        text = text.replace(json.dumps(_PLACEHOLDER), literal)
    return text.encode()


def _serve_raw(monkeypatch, raw):
    calls = []

    def _fake_get(url, **kwargs):
        calls.append(url)
        return {"status_code": 200, "content": raw, "headers": {}, "final_url": None,
                "error": None, "attempts": 1}

    monkeypatch.setattr(cert_intel, "http_get_with_retry", _fake_get)
    return calls


def _strict_json(resp):
    def _no_const(name):
        raise AssertionError(f"costante JSON non valida nella risposta: {name}")
    return json.loads(resp.text, parse_constant=_no_const)


def _assert_robust_outcome(resp):
    assert resp.status_code == 200, f"status {resp.status_code}: risposta non serializzabile"
    body = _strict_json(resp)
    assert body["error"] is None, f"raccolta persa: {body['error']!r}"
    assert body["san_subdomains_discovered"] == ["a.example.com", "b.example.com"]
    assert any(c.get("id") == 1 for c in body["ct_certificates"]["certificates"])
    for cn in body["ct_certificates"]["unique_cn"]:
        assert isinstance(cn, str)
        assert not re.search("[\ud800-\udfff]", cn), "surrogato in unique_cn"
    assert set(body["ct_certificates"]["unique_cn"]) - {""} == {"example.com"}
    return body


class TestNonFiniteAndHugeValues:
    @pytest.mark.parametrize("literal", _LITERALS)
    @pytest.mark.parametrize("field", _FIELDS)
    def test_non_finite_literal_in_any_field_keeps_valid_row(self, monkeypatch, field, literal):
        raw = _raw_payload([GOOD, _bad(**{field: _PLACEHOLDER})], literal)
        _serve_raw(monkeypatch, raw)
        _assert_robust_outcome(safe_client.get("/cert", params={"domain": DOMAIN}))

    @pytest.mark.parametrize("field", ["common_name", "name_value"])
    def test_lone_surrogate_keeps_valid_row_and_makes_no_san(self, monkeypatch, field):
        raw = _raw_payload([GOOD, _bad(**{field: "\ud800.example.com"})])
        assert b"\\ud800" in raw
        _serve_raw(monkeypatch, raw)
        _assert_robust_outcome(safe_client.get("/cert", params={"domain": DOMAIN}))

    def test_5000_digit_integer_id_keeps_valid_row(self, monkeypatch):
        raw = _raw_payload([GOOD, _bad(id=_PLACEHOLDER)], "9" * 5000)
        _serve_raw(monkeypatch, raw)
        _assert_robust_outcome(safe_client.get("/cert", params={"domain": DOMAIN}))

    @pytest.mark.parametrize("kind", ["NaN", "surrogate", "bigint"])
    def test_cached_outcome_is_success_and_serializable(self, monkeypatch, kind):
        if kind == "NaN":
            raw = _raw_payload([GOOD, _bad(id=_PLACEHOLDER)], "NaN")
        elif kind == "surrogate":
            raw = _raw_payload([GOOD, _bad(name_value="\ud800.example.com")])
        else:
            raw = _raw_payload([GOOD, _bad(id=_PLACEHOLDER)], "9" * 5000)
        calls = _serve_raw(monkeypatch, raw)
        first = _assert_robust_outcome(safe_client.get("/cert", params={"domain": DOMAIN}))
        second = _assert_robust_outcome(safe_client.get("/cert", params={"domain": DOMAIN}))
        assert len(calls) == 1, "il successo deve essere servito da cache"
        assert first["ct_certificates"] == second["ct_certificates"]
        assert first["san_subdomains_discovered"] == second["san_subdomains_discovered"]

    def test_discarded_rows_leave_warning_with_count(self, monkeypatch, caplog):
        rows = [GOOD, _bad(id=_PLACEHOLDER), _bad(id=3, not_after=_PLACEHOLDER),
                _bad(id=4, common_name="\ud800.example.com")]
        raw = _raw_payload(rows, "NaN")
        _serve_raw(monkeypatch, raw)
        with caplog.at_level(logging.WARNING, logger="cert-intel"):
            resp = safe_client.get("/cert", params={"domain": DOMAIN})
        _assert_robust_outcome(resp)
        warnings = [r for r in caplog.records
                    if r.name == "cert-intel" and r.levelno == logging.WARNING]
        assert warnings, "nessun WARNING dal logger cert-intel per le righe scartate"
        assert any(re.search(r"\b3\b", r.getMessage()) for r in warnings), (
            f"il WARNING deve riportare il numero di righe scartate (3): "
            f"{[r.getMessage() for r in warnings]}")
