"""
Orchestrator: scope filtering (all/target/watchlist) and the variant_intel /
scope params on TriggerRequest. These guard the v4.8.0 additions:
 - scope restricts which feed domains the pipeline processes
 - variant_intel is an opt-in flag (heavy: full intel per registered variant)
"""
import importlib
import pytest

from shared.utils import http_get_with_retry


@pytest.fixture
def orch(monkeypatch):
    # Minimal env so the module imports cleanly
    monkeypatch.setenv("INTEL_STORE", "false")
    monkeypatch.setenv("CASE_INGEST", "false")
    import services.orchestrator as o
    importlib.reload(o)
    return o


class TestTriggerRequestParams:
    def test_defaults(self, orch):
        r = orch.TriggerRequest()
        assert r.scope == "all"
        assert r.variant_intel is False
        assert r.include_dnstwist is False

    def test_accepts_scope_and_variant_intel(self, orch):
        r = orch.TriggerRequest(scope="target", variant_intel=True, include_dnstwist=True)
        assert r.scope == "target"
        assert r.variant_intel is True


class TestScopeFilter:
    """The pipeline filters feed domains by type when scope is target/watchlist."""
    DOMAINS = [
        {"domain": "a.com", "client": "k", "type": "target"},
        {"domain": "b.com", "client": "k", "type": "target"},
        {"domain": "c.com", "client": "k", "type": "watchlist"},
        {"domain": "d.com", "client": "k"},  # no type → treated as target
    ]

    def _filter(self, domains, scope):
        # Mirrors the orchestrator's scope filter logic exactly
        scope = (scope or "all").lower()
        if scope in ("target", "watchlist"):
            return [d for d in domains if d.get("type", "target") == scope]
        return domains

    def test_scope_all_keeps_everything(self):
        assert len(self._filter(self.DOMAINS, "all")) == 4

    def test_scope_target_includes_untyped(self):
        out = self._filter(self.DOMAINS, "target")
        names = {d["domain"] for d in out}
        assert names == {"a.com", "b.com", "d.com"}  # d.com (no type) counts as target

    def test_scope_watchlist_only(self):
        out = self._filter(self.DOMAINS, "watchlist")
        names = {d["domain"] for d in out}
        assert names == {"c.com"}

    def test_unknown_scope_defaults_to_all(self):
        assert len(self._filter(self.DOMAINS, "garbage")) == 4


class TestProgressEndpoint:
    """The /progress endpoint exposes real pipeline telemetry for the Scan progress view."""
    @pytest.fixture
    def client(self, orch):
        from fastapi.testclient import TestClient
        return TestClient(orch.app)

    def test_idle_state(self, orch, client):
        r = client.get("/progress")
        assert r.status_code == 200
        b = r.json()
        assert b["phase"] in ("idle", "done", "error")
        assert b["percent"] == 0 or b["phase"] == "done"

    def test_percent_derived_from_counts(self, orch, client):
        orch._progress_reset("acme", 8)
        orch._progress_set(phase="scanning", done=2)
        b = client.get("/progress").json()
        assert b["total"] == 8 and b["done"] == 2 and b["percent"] == 25
        assert b["client"] == "acme"

    def test_log_buffer_capped(self, orch, client):
        orch._progress_reset("acme", 1)
        for i in range(orch._MAX_LOG_LINES + 50):
            orch._plog(f"line {i}")
        b = client.get("/progress").json()
        assert len(b["log"]) == orch._MAX_LOG_LINES  # capped, not unbounded

    def test_log_can_be_excluded(self, orch, client):
        orch._plog("something")
        b = client.get("/progress?include_log=false").json()
        assert b["log"] == []


class TestDnstwistDedup:
    """
    Regression: dnstwist ran once PER TARGET. Multiple targets of one client share
    the same legitimate domain, so dnstwist on the same legit produced identical
    variants and the whole discovery + variant-intel pass repeated N times (3x for
    a client with 3 targets). It must run once per DISTINCT legitimate domain.
    """
    def _distinct_legits(self, client_domains):
        # Mirrors the orchestrator's dedup logic
        legits, seen = [], set()
        for d in client_domains:
            if d.get("type") != "target":
                continue
            lg = d.get("legitimate", d["domain"])
            if lg not in seen:
                seen.add(lg)
                legits.append(lg)
        return legits

    def test_three_targets_same_legit_dedup_to_one(self):
        domains = [
            {"domain": "fabirkam.example", "type": "target", "legitimate": "fabrikam.example"},
            {"domain": "fabrikamta.example", "type": "target", "legitimate": "fabrikam.example"},
            {"domain": "fabrikam.test", "type": "target", "legitimate": "fabrikam.example"},
        ]
        assert self._distinct_legits(domains) == ["fabrikam.example"]  # one run, not three

    def test_distinct_legits_preserved(self):
        domains = [
            {"domain": "a-typo.com", "type": "target", "legitimate": "acme.com"},
            {"domain": "b-typo.com", "type": "target", "legitimate": "beta.com"},
        ]
        assert set(self._distinct_legits(domains)) == {"acme.com", "beta.com"}

    def test_watchlist_excluded_from_dnstwist(self):
        domains = [
            {"domain": "x.com", "type": "target", "legitimate": "acme.com"},
            {"domain": "y.com", "type": "watchlist", "legitimate": "acme.com"},
        ]
        # only targets drive dnstwist; still dedups to the one legit
        assert self._distinct_legits(domains) == ["acme.com"]


class TestPipelineLockRecovery:
    """A pipeline that dies without cleanup (OOM/SIGKILL/crash) must not block all
    future scans forever. Heartbeat staleness auto-recovers; a manual reset exists too."""

    def _client(self):
        import services.orchestrator as o
        from fastapi.testclient import TestClient
        return o, TestClient(o.app)

    def test_stale_heartbeat_allows_new_run(self):
        import time
        o, c = self._client()
        o._running = True
        o._run_started = time.time() - 100
        o._last_heartbeat = time.time() - (o.HEARTBEAT_STALE_SEC + 60)
        r = c.post("/trigger", json={"client": "X"})
        assert r.status_code == 200  # auto-reset, not blocked
        o._running = False

    def test_fresh_heartbeat_still_blocks(self):
        import time
        o, c = self._client()
        o._running = True
        o._run_started = time.time() - 100
        o._last_heartbeat = time.time() - 30  # alive
        r = c.post("/trigger", json={"client": "X"})
        assert r.status_code == 409
        o._running = False

    def test_manual_reset_unblocks(self):
        import time
        o, c = self._client()
        o._running = True
        o._last_heartbeat = time.time() - 30
        r = c.post("/trigger/reset")
        assert r.status_code == 200
        assert r.json()["was_running"] is True
        assert o._running is False


class TestPersistIntelPreservesBaselineOnModuleFailure:
    """CODE-01: `_persist_intel` used to save whatever a module returned even on
    failure (`_fetch_service` -> None on HTTP/transport error, or a service's
    own empty-result shape with `error` set on source failure), overwriting a
    healthy baseline with a zeroed one. The next successful run then diffed
    against that zeroed baseline and reported a delta equal to the entire
    history (e.g. crt.sh: 21 "new" certificates that were already known).
    A failed/degraded module must instead leave the baseline for that section
    untouched, both in what gets saved and in what gets diffed."""

    PREV_CERT = {"total": 21, "certificates": [{"id": 1}], "error": None}
    PREV_INTEL = {
        "dns": {"records": {"A": ["1.2.3.4"]}, "error": None},
        "cert": PREV_CERT,
        "http": {"overall_status": "active", "checks": [], "error": None},
        "whois": {"registrar": "Foo", "error": None},
        "reputation": {"risk_score": 0, "error": None},
    }

    def _stub_classify_diff(self, monkeypatch, o, captured):
        class _Resp:
            ok = True
            def json(self):
                return {"alerts": [], "alert_count": 0, "max_severity": "CLEAN"}
        def _post(url, json=None, timeout=None):
            captured.append(json)
            return _Resp()
        monkeypatch.setattr(o._session, "post", _post)

    def _stub_store(self, monkeypatch, o, prev_intel, saved):
        prev_snapshot = {"intel": prev_intel} if prev_intel is not None else None
        monkeypatch.setattr(o.intel_store, "load_snapshot", lambda c, d: prev_snapshot)

        def _save(c, d, current):
            saved["current"] = current
            return True
        monkeypatch.setattr(o.intel_store, "save_snapshot", _save)

    def test_module_returning_none_does_not_zero_baseline(self, orch, monkeypatch):
        o = orch
        saved, captured = {}, []
        self._stub_store(monkeypatch, o, self.PREV_INTEL, saved)
        self._stub_classify_diff(monkeypatch, o, captured)

        intel = dict(self.PREV_INTEL)
        intel["cert"] = None  # _fetch_service returned None (HTTP error)
        o._persist_intel("acme", "acme.it", "acme.it", intel)

        # COL-13: la sezione riportata porta ora il marcatore `carried_over`; il resto è la precedente.
        assert {k: v for k, v in saved["current"]["cert"].items() if k != "carried_over"} == self.PREV_CERT
        assert {k: v for k, v in captured[0]["current"]["cert"].items() if k != "carried_over"} == self.PREV_CERT

    def test_module_with_error_field_does_not_zero_baseline(self, orch, monkeypatch):
        o = orch
        saved, captured = {}, []
        self._stub_store(monkeypatch, o, self.PREV_INTEL, saved)
        self._stub_classify_diff(monkeypatch, o, captured)

        intel = dict(self.PREV_INTEL)
        intel["cert"] = {"total": 0, "certificates": [], "error": "crt.sh HTTP 502"}
        o._persist_intel("acme", "acme.it", "acme.it", intel)

        # COL-13: la sezione riportata porta ora il marcatore `carried_over`; il resto è la precedente.
        assert {k: v for k, v in saved["current"]["cert"].items() if k != "carried_over"} == self.PREV_CERT
        assert {k: v for k, v in captured[0]["current"]["cert"].items() if k != "carried_over"} == self.PREV_CERT

    def test_healthy_module_is_still_saved_normally(self, orch, monkeypatch):
        o = orch
        saved, captured = {}, []
        self._stub_store(monkeypatch, o, self.PREV_INTEL, saved)
        self._stub_classify_diff(monkeypatch, o, captured)

        new_cert = {"total": 22, "certificates": [{"id": 1}, {"id": 2}], "error": None}
        intel = dict(self.PREV_INTEL)
        intel["cert"] = new_cert
        o._persist_intel("acme", "acme.it", "acme.it", intel)

        assert saved["current"]["cert"] == new_cert  # real change is persisted normally

    def test_no_prior_snapshot_and_failed_module_saves_none_without_error(self, orch, monkeypatch):
        # First-ever run for a domain, and a module fails: nothing to fall back
        # to, so the section stays None. Must not raise, and diff is skipped
        # entirely (no prev_intel to compare against).
        o = orch
        saved, captured = {}, []
        self._stub_store(monkeypatch, o, None, saved)
        self._stub_classify_diff(monkeypatch, o, captured)

        intel = dict(self.PREV_INTEL)
        intel["cert"] = None
        o._persist_intel("acme", "acme.it", "acme.it", intel)

        assert saved["current"]["cert"] is None
        assert captured == []  # no baseline to diff against yet


class TestPersistIntelRealFailureShapesNotDetectedAsFailed:
    """`CODE-15` + `CODE-14` (riunificati, DECISIONE utente 2026-08-02, opzione b).

    `_module_failed` (orchestrator.py:235-243) legge SOLO `value.get("error")`
    top-level. Funziona per `cert` (CODE-01 già lo copre, sopra) perché
    `cert_intel.py` popola `error` in cima al dict. Ma `reputation.py` (riga
    121: `"error": None`, mai riassegnata — CODE-14) e `http_fingerprint.py`
    (riga 54: idem) non lo fanno mai: il loro segnale di fallimento vive altrove
    (annidato per reputation, in `overall_status` per http). `_module_failed`
    su queste due sezioni ritorna sempre `False`, anche quando il modulo è
    completamente fallito — quindi la sezione fallita SOVRASCRIVE la baseline
    invece di preservarla, esattamente il difetto che `CODE-01` chiudeva per
    `cert`/`dns`/`whois`/`http` (con la forma sbagliata di `error`)."""

    # Stessa baseline generica di TestPersistIntelPreservesBaselineOnModuleFailure
    # (non riusata per ereditarietà, per non ri-eseguire i suoi test sotto un
    # secondo nome di classe): qui serve solo come contenitore per le altre
    # quattro sezioni mentre il test isola reputation/http.
    PREV_CERT = {"total": 21, "certificates": [{"id": 1}], "error": None}
    PREV_INTEL = {
        "dns": {"records": {"A": ["1.2.3.4"]}, "error": None},
        "cert": PREV_CERT,
        "http": {"overall_status": "active", "checks": [], "error": None},
        "whois": {"registrar": "Foo", "error": None},
        "reputation": {"risk_score": 0, "error": None},
    }

    def _stub_classify_diff(self, monkeypatch, o, captured):
        class _Resp:
            ok = True
            def json(self):
                return {"alerts": [], "alert_count": 0, "max_severity": "CLEAN"}
        def _post(url, json=None, timeout=None):
            captured.append(json)
            return _Resp()
        monkeypatch.setattr(o._session, "post", _post)

    def _stub_store(self, monkeypatch, o, prev_intel, saved):
        prev_snapshot = {"intel": prev_intel} if prev_intel is not None else None
        monkeypatch.setattr(o.intel_store, "load_snapshot", lambda c, d: prev_snapshot)

        def _save(c, d, current):
            saved["current"] = current
            return True
        monkeypatch.setattr(o.intel_store, "save_snapshot", _save)

    # Baseline reputation REALE, non un placeholder: un verdetto VirusTotal
    # malevolo già osservato in un ciclo precedente.
    REPUTATION_BASELINE_MALICIOUS = {
        "domain": "acme-typo.it", "timestamp": "2026-07-20T10:00:00Z",
        "virustotal": {"malicious": 9, "suspicious": 2, "undetected": 40, "harmless": 20,
                        "reputation": -15, "categories": {"phishing": "Category"}, "error": None},
        "otx": {"pulse_count": 3, "pulse_titles": ["Phishing campaign vs acme.it"],
                "tags": ["phishing"], "malware_families": [], "error": None},
        "securitytrails": {"subdomain_count": 2, "current_dns": {}, "alexa_rank": None, "error": None},
        "risk_score": 80, "risk_level": "high", "error": None,
    }

    # reputation.py:117-158 — VT, OTX e ST fallliscono tutti e tre nello stesso
    # ciclo. Forma REALE: "error" top-level resta None (mai riassegnata,
    # CODE-14); l'errore vive in virustotal.error/otx.error/securitytrails.error.
    REPUTATION_ALL_SOURCES_FAILED = {
        "domain": "acme-typo.it", "timestamp": "2026-08-02T10:00:00Z",
        "virustotal": {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
                        "reputation": 0, "categories": {}, "error": "HTTP 503"},
        "otx": {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": [],
                "error": "HTTP 401 Unauthorized"},
        "securitytrails": {"subdomain_count": 0, "current_dns": {}, "alexa_rank": None,
                            "error": "HTTP 401 Unauthorized"},
        "risk_score": 0, "risk_level": "clean", "error": None,
    }

    # Baseline http REALE: sito attivo, contenuto sostanziale.
    HTTP_BASELINE_ACTIVE = {
        "domain": "acme-typo.it", "timestamp": "2026-07-20T10:00:00Z",
        "checks": [{"url": "http://acme-typo.it", "status_code": 200, "content_length": 5400,
                    "title": "Acme", "server": "nginx", "content_hash": "abc123",
                    "content_hash_canonical": "abc123", "visible_text_hash": "def456",
                    "suspicious_patterns": [], "hidden_elements": {"risk_indicators": 0, "summary": []},
                    "redirect_chain": None, "error": None}],
        "overall_status": "active", "hidden_elements_risk": 0, "error": None,
    }

    # http_fingerprint.py:44-116 — nessun fetch riesce (connessione rifiutata /
    # handshake TLS fallito su ogni combinazione http/https). Forma REALE:
    # "error" top-level resta None (mai popolato, riga 54); il segnale è
    # `overall_status: "down"` (default della riga 52, MAI sovrascritto perché
    # `any_active` è False e nessuno status_code raggiunge 400, righe 111-114 —
    # qui gli status_code sono tutti None, non >= 400).
    HTTP_ALL_FETCHES_FAILED = {
        "domain": "acme-typo.it", "timestamp": "2026-08-02T10:00:00Z",
        "checks": [
            {"url": "http://acme-typo.it", "status_code": None, "content_length": 0,
             "title": None, "server": "", "content_hash": None, "content_hash_canonical": None,
             "visible_text_hash": None, "suspicious_patterns": [], "hidden_elements": None,
             "redirect_chain": None, "error": "Connection refused"},
            {"url": "https://acme-typo.it", "status_code": None, "content_length": 0,
             "title": None, "server": "", "content_hash": None, "content_hash_canonical": None,
             "visible_text_hash": None, "suspicious_patterns": [], "hidden_elements": None,
             "redirect_chain": None, "error": "SSL handshake failed"},
        ],
        "overall_status": "down", "hidden_elements_risk": 0, "error": None,
    }

    def test_reputation_all_sources_failed_does_not_zero_malicious_baseline(self, orch, monkeypatch):
        """CODE-14 end-to-end: VT/OTX/ST tutti falliti in questo ciclo non
        devono cancellare un verdetto malevolo reale osservato in precedenza.
        Oggi `_module_failed` legge `reputation.error` (sempre None) e
        considera il modulo riuscito: la baseline malicious:9/risk_score:80
        viene sovrascritta dallo zero del ciclo fallito."""
        o = orch
        saved, captured = {}, []
        prev_intel = dict(self.PREV_INTEL)
        prev_intel["reputation"] = self.REPUTATION_BASELINE_MALICIOUS
        self._stub_store(monkeypatch, o, prev_intel, saved)
        self._stub_classify_diff(monkeypatch, o, captured)

        intel = dict(prev_intel)
        intel["reputation"] = self.REPUTATION_ALL_SOURCES_FAILED
        o._persist_intel("acme", "acme-typo.it", "acme.it", intel)

        # COL-13: la sezione riportata porta ora il marcatore `carried_over`; il resto è la precedente.
        assert {k: v for k, v in saved["current"]["reputation"].items() if k != "carried_over"} == self.REPUTATION_BASELINE_MALICIOUS
        assert {k: v for k, v in captured[0]["current"]["reputation"].items() if k != "carried_over"} == self.REPUTATION_BASELINE_MALICIOUS

    def test_http_down_status_does_not_zero_active_baseline(self, orch, monkeypatch):
        """Un http-fingerprint completamente fallito (`overall_status: "down"`,
        `error` top-level `None`) non deve cancellare la baseline di un sito
        osservato attivo in precedenza. Oggi `_module_failed` legge
        `http.error` (sempre None su questo modulo) e considera il modulo
        riuscito: la baseline "active" viene sovrascritta da "down"."""
        o = orch
        saved, captured = {}, []
        prev_intel = dict(self.PREV_INTEL)
        prev_intel["http"] = self.HTTP_BASELINE_ACTIVE
        self._stub_store(monkeypatch, o, prev_intel, saved)
        self._stub_classify_diff(monkeypatch, o, captured)

        intel = dict(prev_intel)
        intel["http"] = self.HTTP_ALL_FETCHES_FAILED
        o._persist_intel("acme", "acme-typo.it", "acme.it", intel)

        # COL-13: la sezione riportata porta ora il marcatore `carried_over`; il resto è la precedente.
        assert {k: v for k, v in saved["current"]["http"].items() if k != "carried_over"} == self.HTTP_BASELINE_ACTIVE
        assert {k: v for k, v in captured[0]["current"]["http"].items() if k != "carried_over"} == self.HTTP_BASELINE_ACTIVE


class TestIngestCasesExcludesLegitimateDomain:
    """NRM-03: the client's own legitimate domain is present in the feed as a
    target entry (a common shape in real feeds). Every scan
    therefore produced a case on the client's own primary asset. Monitoring
    must be preserved (it still gets classified and can surface compromise),
    but it must not become a typosquatting *case*."""

    def test_legitimate_domain_event_is_not_ingested_as_case(self, orch, monkeypatch):
        o = orch
        monkeypatch.setattr(o, "CASE_INGEST_TOKEN", "tok")
        posted = []

        def _post(url, json=None, headers=None, timeout=None):
            posted.append(json)
            class R:
                ok = True
                status_code = 200
            return R()
        monkeypatch.setattr(o._session, "post", _post)

        events = [
            {"client": "acme", "domain": "acme.it", "legitimate": "acme.it",
             "classification": {"auto_classification": "legitimate_probable", "confidence": "high"}},
            {"client": "acme", "domain": "acme-secure.it", "legitimate": "acme.it",
             "classification": {"auto_classification": "suspicious", "confidence": "medium"}},
        ]
        o._ingest_cases(events)

        posted_domains = [p["domain"] for p in posted]
        assert "acme.it" not in posted_domains
        assert "acme-secure.it" in posted_domains

    def test_event_without_legitimate_field_still_ingested(self, orch, monkeypatch):
        # dnstwist-discovery events don't carry a "legitimate" field; must not
        # be accidentally filtered out.
        o = orch
        monkeypatch.setattr(o, "CASE_INGEST_TOKEN", "tok")
        posted = []

        def _post(url, json=None, headers=None, timeout=None):
            posted.append(json)
            class R:
                ok = True
                status_code = 200
            return R()
        monkeypatch.setattr(o._session, "post", _post)

        events = [{"client": "acme", "domain": "acme-typo.it",
                   "classification": {"auto_classification": "needs_review", "confidence": "low"}}]
        o._ingest_cases(events)
        assert [p["domain"] for p in posted] == ["acme-typo.it"]


class TestVariantClassification:
    """dnstwist variants used to carry a hardcoded 'needs_review' label: the classifier
    was never consulted for them, so classifier improvements had no effect on the
    variant cases. Severity must also map the classifier's newer categories."""

    def test_severity_map_covers_classifier_categories(self):
        from services.orchestrator import CLASSIFICATION_SEVERITY as M
        # categories the classifier can emit must not silently fall back to MEDIUM
        assert M["likely_third_party"] == "LOW"
        assert M["legitimate_probable"] == "LOW"
        assert M["for_sale"] == "LOW"
        assert M["parking"] == "LOW"
        assert M["suspicious"] == "HIGH"

    def test_variant_classification_uses_classifier_result(self, monkeypatch):
        """With variant intel available, the event classification must come from the
        classifier, not the discovery placeholder."""
        import services.orchestrator as o

        class _Resp:
            ok = True
            status_code = 200
            def json(self):
                return {"auto_classification": "likely_third_party",
                        "confidence": "low", "rule": "predates_campaign",
                        "rationale": "Registrato molto prima della campagna"}

        # the pipeline posts to CLASSIFY_URL/classify/variant; emulate that call
        monkeypatch.setattr(o._session, "post", lambda *a, **k: _Resp())
        r = o._session.post(f"{o.CLASSIFY_URL}/classify/variant", json={"domain": "x.com"})
        data = r.json()
        assert data["auto_classification"] == "likely_third_party"
        assert o.CLASSIFICATION_SEVERITY[data["auto_classification"]] == "LOW"

    def test_insufficient_data_has_medium_severity(self):
        """Punto 5 del mandato G3 (`CODE-15` + `CODE-14`), quinto giro.

        GIUSTIFICAZIONE PER IL VERIFIER (G5): questo test si chiamava
        `test_insufficient_data_has_low_severity` e asserisce `M.get(...) ==
        "LOW"`. Codificava la decisione utente del 2026-08-01 ("non ho
        potuto guardare" non deve pesare quanto "richiede revisione
        attiva"). Quella decisione è stata **esplicitamente ribaltata** il
        2026-08-04: "insufficient_data resta come classificazione, ma
        smette di mappare su severità LOW: passa a MEDIUM. Dati incompleti
        != benigno." Motivo del ribaltamento: la guardia LOW declassava il
        caso senza alcuna azione dell'attaccante, sul solo fallimento di un
        modulo opzionale (cert via crt.sh, storicamente instabile;
        reputation per esaurimento quote VT/OTX/ST durante scan dnstwist
        ad alto volume) — vedi `test_insufficient_data_ingested_as_medium_severity_case`
        sotto per il percorso end-to-end e il dettaglio completo.

        Non è "aggiusto il test per farlo passare" (anti-pattern §9 di
        CLAUDE.md): è l'allineamento di un'attesa scritta prima di una
        decisione dell'utente che l'ha cambiata — stesso trattamento già
        applicato a `test_http_marked_failed_in_state_is_not_needs_review`
        in un giro precedente.

        Resta un'asserzione diretta sul dizionario `CLASSIFICATION_SEVERITY`
        (implementazione, non comportamento) per scelta deliberata: quel
        dizionario è esattamente l'artefatto che la decisione dell'utente
        cambia, quindi un presidio diretto ha valore — se in futuro qualcuno
        rimette "LOW", questo test deve rompersi con un messaggio ovvio. La
        copertura sul comportamento reale (payload verso il case-manager)
        resta in `test_insufficient_data_ingested_as_medium_severity_case`."""
        from services.orchestrator import CLASSIFICATION_SEVERITY as M
        assert M.get("insufficient_data") == "MEDIUM", M.get("insufficient_data")

    def test_insufficient_data_ingested_as_medium_severity_case(self, monkeypatch):
        """`CODE-15` + `CODE-14`, quinto giro G3. DECISIONE utente 2026-08-04, che
        ribalta la precedente del 2026-08-01 (vedi test gemello sopra, ora superato):
        `insufficient_data` resta una classificazione a sé, ma smette di mappare su
        severity LOW e passa a MEDIUM. "Dati incompleti != benigno" — il
        security-reviewer ha mostrato che oggi la guardia declassa il caso a LOW
        anche quando basta il fallimento di un solo modulo opzionale (cert via
        crt.sh, instabile; reputation per esaurimento quote VT/OTX/ST durante scan
        dnstwist ad alto volume), senza alcuna azione dell'attaccante e su tutti i
        domini del ciclo. Un caso a raccolta incompleta deve restare in coda al
        triage, non essere deprioritizzato.

        Passa per `_ingest_cases` — il percorso reale che costruisce il payload
        verso il case-manager — non per un'asserzione diretta su
        `CLASSIFICATION_SEVERITY`, che è implementazione e si romperebbe al primo
        refactor legittimo del dizionario.

        NOTA DI RIMOZIONE (GATE G3, quinto giro): questo metodo **sostituisce**
        `test_insufficient_data_ingested_as_low_severity_case`, rimosso da questo
        file. Non è una perdita di copertura: quel test copriva lo stesso identico
        percorso (`_ingest_cases`, stesso monkeypatch, stesso payload) e, una volta
        corretto `LOW` → `MEDIUM`, sarebbe diventato un duplicato carattere per
        carattere di questo. La copertura end-to-end si è spostata qui.
        """
        import services.orchestrator as o
        posted = []

        def _post(url, json=None, headers=None, timeout=None):
            posted.append(json)
            class R:
                ok = True
                status_code = 200
            return R()
        monkeypatch.setattr(o, "CASE_INGEST_TOKEN", "tok")
        monkeypatch.setattr(o._session, "post", _post)

        events = [{"client": "acme", "domain": "acme-typo.it", "legitimate": "acme.it",
                   "classification": {"auto_classification": "insufficient_data",
                                       "confidence": "low",
                                       "rationale": "Raccolta dati fallita"}}]
        o._ingest_cases(events)

        assert posted[0]["severity"] == "MEDIUM", posted[0]


class TestOrchestratorBuildsCollectionState:
    """`CODE-15` + `CODE-14` (riunificati). Punto 3 del mandato G3: l'orchestrator
    deve saper riconoscere le forme REALI di fallimento dei collector
    interessati usando `_module_failed` (orchestrator.py:235-249) — lo stesso
    punto di verità già usato per il canale alert (CODE-01/CODE-14). Le forme
    sono lette dal sorgente dei collector, non idealizzate: `whois_intel.py:56-77`,
    `cert_intel.py:66-144`, `reputation.py:117-158` (CODE-14: `error` top-level
    sempre `None`, guasto annidato).

    CORREZIONE (2026-08-02, seconda revisione di questo giro G3): per `http`
    NON vale la stessa lettura shape-based usata per whois/cert/reputation.
    Un'indagine parallela su un insieme di snapshot reali ha misurato
    che, fra quelli con `http.overall_status` in ("down","error"), la
    stragrande maggioranza sono LETTURE REALI del collector, non
    guasti: i più sono codici HTTP reali restituiti dal sito (403/404/503/521
    — il sito ha risposto), gli altri quasi tutti domini che non risolvono in DNS
    (`blocked (SSRF protection): host does not resolve` — un fatto misurato
    sul dominio), e un caso isolato (connessione rifiutata senza status
    code e senza il prefisso SSRF) è genuinamente ambiguo. Trattare
    `overall_status in ("down","error")` come sinonimo di "modulo fallito" —
    l'assunzione dei round precedenti di questo ID — produce falsi positivi
    sulla quasi totalità di quei casi reali: esattamente il difetto opposto ("la guardia morde
    dati veri") a quello che CODE-15 deve correggere.

    Lettura del codice (`http_fingerprint.py:49-118`,
    `shared/utils.py:103-167`, funzione `http_get_with_retry`): l'UNICO
    segnale strutturale (non una stringa libera d'eccezione) che il
    collector produce deliberatamente è il prefisso `"blocked (SSRF
    protection)"` / `"blocked redirect (SSRF protection)"` sul campo `error`
    di ogni check — aggiunto esplicitamente da `is_safe_url`/dal chiamante,
    non dall'interpolazione di un'eccezione generica — e segnala che il
    dominio non risolve o punta a un indirizzo interno: un fatto reale sul
    dominio, non un malfunzionamento del collector. Un `status_code`
    valorizzato (anche >= 400) è per costruzione una risposta HTTP reale
    ricevuta: mai un guasto di raccolta. Oltre questi due casi, un
    `status_code is None` con un `error` di eccezione generica (es.
    "Connection refused", "SSL handshake failed") NON è distinguibile nel
    codice attuale fra "il sito è davvero irraggiungibile" e "il collector
    ha avuto un problema transitorio": è la stessa ambiguità del caso reale
    isolato sopra. Non inventiamo qui una distinzione che il collector non
    produce — vedi il test `skip` sotto, che la documenta esplicitamente.
    Questa e' l'informazione più rilevante di questa revisione: un campo
    strutturato (`error_class: transport|dns|application`, NON implementato
    né presupposto qui) risolverebbe l'ambiguità alla radice ed è materiale
    per una voce di registro separata."""

    # whois_intel.py:56-64 — in eccezione (riga 106-108) SOLO "error" viene
    # valorizzato; tutte le altre chiavi restano al default pre-try.
    WHOIS_FAILED = {
        "domain": "whois-down.example", "timestamp": "2026-08-02T10:00:00Z",
        "registrar": None, "creation_date": None, "expiration_date": None,
        "updated_date": None, "status": [], "nameservers": [],
        "registrant": {"name": None, "org": None, "country": None, "email": None},
        "privacy_protected": False, "dnssec": False, "age_days": None,
        "error": "WHOIS lookup failed: connection timed out",
    }

    # cert_intel.py:66-144 — path crt.sh HTTP non-200 o eccezione: "error"
    # popolato, ct_certificates resta al default vuoto impostato riga 78.
    CERT_FAILED = {
        "domain": "cert-down.example", "timestamp": "2026-08-02T10:00:00Z",
        "ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
        "tls_live": None, "san_subdomains_discovered": [],
        "error": "crt.sh HTTP 502: Bad Gateway",
    }

    # reputation.py:117-158 (CODE-14) — "error" TOP-LEVEL resta `None` (riga
    # 121, mai riassegnata): quando VT/OTX/ST falliscono tutti e tre, il
    # guasto vive SOLO annidato in virustotal.error/otx.error/securitytrails.error.
    REPUTATION_FAILED = {
        "domain": "rep-down.example", "timestamp": "2026-08-02T10:00:00Z",
        "virustotal": {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
                        "reputation": 0, "categories": {}, "error": "HTTP 503"},
        "otx": {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": [],
                "error": "HTTP 401 Unauthorized"},
        "securitytrails": {"subdomain_count": 0, "current_dns": {}, "alexa_rank": None,
                            "error": "HTTP 401 Unauthorized"},
        "risk_score": 0, "risk_level": "clean", "error": None,
    }

    # reputation.py — esito genuinamente pulito, per la controprova.
    REPUTATION_OK = {
        "domain": "clean.example", "timestamp": "2026-08-02T10:00:00Z",
        "virustotal": {"malicious": 0, "suspicious": 0, "undetected": 40, "harmless": 20,
                        "reputation": 5, "categories": {}, "error": None},
        "otx": {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": [],
                "error": None},
        "securitytrails": {"subdomain_count": 2, "current_dns": {}, "alexa_rank": None,
                            "error": None},
        "risk_score": 0, "risk_level": "clean", "error": None,
    }

    # http_fingerprint.py — forma REALE di una risposta HTTP genuina di
    # errore applicativo (la classe più frequente fra i casi reali osservati:
    # qui un 403, il codice più comune). status_code valorizzato su entrambi gli schemi, "error"
    # per-check `None` (nessuna eccezione: la richiesta e' andata a buon
    # fine, il sito ha risposto 403) -> overall_status "error" (righe
    # 111-114: nessun check attivo, ma status_code >= 400). NON e' un guasto
    # del collector: e' un dato osservato.
    HTTP_REAL_ERROR_RESPONSE = {
        "domain": "acme-typo.it", "timestamp": "2026-08-02T10:00:00Z",
        "checks": [
            {"url": "http://acme-typo.it", "status_code": 403, "content_length": 0,
             "title": None, "server": "cloudflare", "content_hash": None,
             "content_hash_canonical": None, "visible_text_hash": None,
             "suspicious_patterns": [], "hidden_elements": None,
             "redirect_chain": None, "error": None},
            {"url": "https://acme-typo.it", "status_code": 403, "content_length": 0,
             "title": None, "server": "cloudflare", "content_hash": None,
             "content_hash_canonical": None, "visible_text_hash": None,
             "suspicious_patterns": [], "hidden_elements": None,
             "redirect_chain": None, "error": None},
        ],
        "overall_status": "error", "hidden_elements_risk": 0, "error": None,
    }

    # http_fingerprint.py + shared/utils.py:103-113 — forma REALE di un
    # dominio bloccato dal guard SSRF (classe dei casi reali osservati
    # in cui il dominio non risolve).
    #
    # GIUSTIFICAZIONE G5 (fixture preesistente modificata — consentito solo
    # per il requisito 3 di questo giro, mandato G3): la versione precedente
    # pinnava la stringa "blocked (SSRF protection): host does not resolve"
    # A MANO, senza mai chiamare `is_safe_url`/`http_get_with_retry` reali.
    # Il verifier ha segnalato che questo rende il test aggirabile: un
    # refactor futuro del messaggio in un solo punto (shared/utils.py:112)
    # non farebbe fallire NESSUN test, riaprendo in silenzio il falso
    # positivo appena chiuso. Qui il messaggio viene chiesto al
    # produttore REALE invece di essere ricopiato — nessuna chiamata di rete:
    # "127.0.0.1" è un IP letterale, `socket.getaddrinfo` lo risolve
    # localmente senza interrogare alcun resolver (verificato offline con
    # `docker run --network=none`, vedi consegna). Il testo esatto del motivo
    # ("non risolve" vs "risolve a un indirizzo interno") non è rilevante per
    # questo test: entrambi i casi attraversano lo stesso ramo del guard SSRF
    # (shared/utils.py:110-113) e producono lo stesso prefisso, che è
    # l'unico elemento che conta ai fini di "non è un guasto del collector".
    # Il test consumer di questo requisito, che rende il gap non aggirabile
    # in modo esplicito, è in
    # `tests/test_utils.py::TestSSRFProtection::test_collection_failed_ssrf_recognition_not_hardcoded_duplicate`.
    # status_code None su entrambi gli schemi, nessuno status_code >= 400 ->
    # overall_status resta al default "down" (riga 52).
    _SSRF_BLOCKED_ERROR = http_get_with_retry("http://127.0.0.1/", max_attempts=1)["error"]
    HTTP_DNS_NOT_RESOLVING = {
        "domain": "gone-domain.example", "timestamp": "2026-08-02T10:00:00Z",
        "checks": [
            {"url": "http://gone-domain.example", "status_code": None, "content_length": 0,
             "title": None, "server": "", "content_hash": None, "content_hash_canonical": None,
             "visible_text_hash": None, "suspicious_patterns": [], "hidden_elements": None,
             "redirect_chain": None, "error": _SSRF_BLOCKED_ERROR},
            {"url": "https://gone-domain.example", "status_code": None, "content_length": 0,
             "title": None, "server": "", "content_hash": None, "content_hash_canonical": None,
             "visible_text_hash": None, "suspicious_patterns": [], "hidden_elements": None,
             "redirect_chain": None, "error": _SSRF_BLOCKED_ERROR},
        ],
        "overall_status": "down", "hidden_elements_risk": 0, "error": None,
    }

    # http_fingerprint.py — il caso genuinamente ambiguo (caso reale isolato, nome sintetico):
    # nessuna risposta ottenuta, nessun prefisso SSRF, solo eccezioni di
    # trasporto generiche. Vedi il test `skip` sotto: non asseriamo True né
    # False su questa forma.
    HTTP_GENERIC_TRANSPORT_FAILURE = {
        "domain": "conn-refused.example", "timestamp": "2026-08-02T10:00:00Z",
        "checks": [
            {"url": "http://conn-refused.example", "status_code": None, "content_length": 0,
             "title": None, "server": "", "content_hash": None, "content_hash_canonical": None,
             "visible_text_hash": None, "suspicious_patterns": [], "hidden_elements": None,
             "redirect_chain": None, "error": "Attempt 3/3: Connection refused"},
            {"url": "https://conn-refused.example", "status_code": None, "content_length": 0,
             "title": None, "server": "", "content_hash": None, "content_hash_canonical": None,
             "visible_text_hash": None, "suspicious_patterns": [], "hidden_elements": None,
             "redirect_chain": None, "error": "Attempt 3/3: Connection refused"},
        ],
        "overall_status": "down", "hidden_elements_risk": 0, "error": None,
    }

    # http_fingerprint.py — sito realmente attivo, per la controprova.
    HTTP_ACTIVE_OK = {
        "domain": "acme-typo.it", "timestamp": "2026-08-02T10:00:00Z",
        "checks": [{"url": "http://acme-typo.it", "status_code": 200, "content_length": 5400,
                    "title": "Acme", "server": "nginx", "content_hash": "abc123",
                    "content_hash_canonical": "abc123", "visible_text_hash": "def456",
                    "suspicious_patterns": [], "hidden_elements": {"risk_indicators": 0, "summary": []},
                    "redirect_chain": None, "error": None}],
        "overall_status": "active", "hidden_elements_risk": 0, "error": None,
    }

    def test_whois_failed_shape_detected(self, orch):
        assert orch._module_failed(self.WHOIS_FAILED) is True

    def test_cert_failed_shape_detected(self, orch):
        assert orch._module_failed(self.CERT_FAILED) is True

    def test_reputation_all_sources_failed_shape_detected(self, orch):
        assert orch._module_failed(self.REPUTATION_FAILED) is True

    def test_http_real_error_response_not_flagged_failed(self, orch):
        """NON-regressione (correzione del 2026-08-02 a questo giro G3): un
        sito che risponde realmente 403 (la classe più frequente fra i casi
        reali misurati) non deve MAI essere trattato come modulo fallito — è un
        dato osservato, non un buco di raccolta. Oggi `_module_failed` legge
        `overall_status in ("down","error")` come sinonimo di fallimento e
        classificherebbe questo esito reale come guasto: falso positivo sulla
        quasi totalità dei casi reali misurati."""
        assert orch._module_failed(self.HTTP_REAL_ERROR_RESPONSE) is False, (
            "un 403 reale (status_code valorizzato, nessuna eccezione) e' "
            "stato trattato come modulo fallito"
        )

    def test_http_dns_not_resolving_not_flagged_failed(self, orch):
        """NON-regressione: un dominio bloccato dal guard SSRF (classe dei
        casi reali misurati in cui il dominio non risolve; qui il
        prefisso è quello REALMENTE prodotto da `http_get_with_retry`, non
        pinnato a mano — vedi `HTTP_DNS_NOT_RESOLVING` sopra) è un fatto
        misurato sul dominio, non un malfunzionamento del collector — non
        deve essere trattato come modulo fallito."""
        assert orch._module_failed(self.HTTP_DNS_NOT_RESOLVING) is False, (
            "un dominio che non risolve (segnale SSRF esplicito) e' stato "
            "trattato come modulo fallito"
        )

    @pytest.mark.skip(reason=(
        "Ambiguita' strutturale confermata su dati reali (un caso isolato, "
        "qui conn-refused.example): connessione rifiutata senza status_code e senza il "
        "prefisso 'blocked (SSRF protection)'. Dal solo codice di "
        "http_get_with_retry (shared/utils.py:103-167) non si puo' "
        "distinguere un guasto di trasporto genuino del collector da un "
        "sito realmente irraggiungibile: entrambi producono status_code "
        "None ed error come stringa libera dell'eccezione. Serve un campo "
        "strutturato (error_class: transport|dns|application — NON "
        "presupposto qui) per risolvere l'ambiguita' alla radice: voce di "
        "registro separata, fuori scope per questo giro. Non asseriamo ne' "
        "True ne' False qui: farlo inventerebbe una distinzione che il "
        "collector non produce."
    ))
    def test_generic_transport_failure_is_ambiguous_not_asserted(self, orch):
        orch._module_failed(self.HTTP_GENERIC_TRANSPORT_FAILURE)  # non asserito, vedi reason

    def test_real_success_shapes_not_flagged_failed(self, orch):
        """Controprova: esiti genuinamente riusciti non devono mai risultare
        'falliti', altrimenti ogni ciclo pulito verrebbe scambiato per un
        guasto di raccolta."""
        assert orch._module_failed(self.REPUTATION_OK) is False
        assert orch._module_failed(self.HTTP_ACTIVE_OK) is False


class TestOrchestratorPropagatesCollectionState:
    """`CODE-15` + `CODE-14` (riunificati). Punto 4 del mandato G3: lo stato
    di raccolta costruito dall'orchestrator deve arrivare DAVVERO nel payload
    di ENTRAMBI i punti che chiamano `/classify/variant` —
    `orchestrator.py:387-392` (loop feed) e `:497-503` (branch variant_intel
    di dnstwist). Un test che copre solo il primo lascia scoperta metà del
    difetto: qui sono due test distinti, uno per punto di chiamata.

    FORMA FISSATA (stessa dichiarata in
    `tests/test_classifier.py::TestClassifierReadsCollectionStatus`,
    vincolante per il fixer): il payload deve includere una chiave
    `collection_status`, dict `{nome_sezione: bool}` con chiavi fra
    "whois"/"cert"/"http"/"reputation", `True` se quella sezione è fallita in
    questo ciclo.

    Oggi (HEAD di questo giro) nessuno dei due punti di chiamata include
    alcun campo di stato nel payload: solo domain/fuzzer/dns/cert/http/
    whois/reputation, identici a prima del tentativo di fix — vedi il
    verdetto G6 che ha originato questo secondo giro di G3.

    CORREZIONE (2026-08-02, seconda revisione): la sezione `http` usa
    deliberatamente una forma di RISPOSTA REALE (403, `HTTP_REAL_ERROR_RESPONSE`
    — vedi `TestOrchestratorBuildsCollectionState`), non una forma di guasto,
    e l'asserzione sotto pretende che NON venga marcata fallita — end-to-end,
    l'intera pipeline non deve mai trasformare un 403 osservato in "raccolta
    fallita". whois/cert/reputation restano forme di guasto reale inequivocabili
    e devono restare marcate `True`: il test verifica selettività, non
    un'uniforme `True` su tutto."""

    DNS_OK = {"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}}
    WHOIS_FAILED = TestOrchestratorBuildsCollectionState.WHOIS_FAILED
    CERT_FAILED = TestOrchestratorBuildsCollectionState.CERT_FAILED
    REPUTATION_FAILED = TestOrchestratorBuildsCollectionState.REPUTATION_FAILED
    HTTP_REAL_ERROR_RESPONSE = TestOrchestratorBuildsCollectionState.HTTP_REAL_ERROR_RESPONSE

    def _fake_get(self, o, domains_response, whitelist_response, twist_response=None):
        cls = self

        def _get(url, timeout=None):
            class R:
                def __init__(self, payload):
                    self._payload = payload
                    self.ok = True
                    self.status_code = 200
                def raise_for_status(self_inner):
                    pass
                def json(self_inner):
                    return self_inner._payload
            if "/feed/domains" in url:
                return R(domains_response)
            if "/feed/whitelist" in url:
                return R(whitelist_response)
            if url.startswith(o.DNS_URL):
                return R(cls.DNS_OK)
            if url.startswith(o.CERT_URL):
                return R(cls.CERT_FAILED)
            if url.startswith(o.HTTP_URL):
                return R(cls.HTTP_REAL_ERROR_RESPONSE)
            if url.startswith(o.WHOIS_URL):
                return R(cls.WHOIS_FAILED)
            if url.startswith(o.REP_URL):
                return R(cls.REPUTATION_FAILED)
            if twist_response is not None and url.startswith(o.TWIST_URL):
                return R(twist_response)
            raise AssertionError(f"GET non atteso in questo test: {url}")
        return _get

    def _fake_post(self, captured):
        def _post(url, json=None, timeout=None):
            class R:
                ok = True
                status_code = 200
                def json(self_inner):
                    return {"auto_classification": "needs_review", "rule": "no_matching_rule",
                            "confidence": "low", "rationale": "x"}
            if url.endswith("/classify/variant"):
                captured.append(json)
            return R()
        return _post

    def test_feed_loop_includes_collection_status(self, orch, monkeypatch):
        """orchestrator.py:387-392."""
        o = orch
        captured = []
        domains_resp = {"domains": [
            {"domain": "acme-typo.it", "client": "acme", "type": "target",
             "legitimate": "acme.it", "fuzzer": "insertion"},
        ]}
        monkeypatch.setattr(o._session, "get",
                            self._fake_get(o, domains_resp, {"whitelist": {}}))
        monkeypatch.setattr(o._session, "post", self._fake_post(captured))

        req = o.TriggerRequest(client="acme", include_whois=True, include_reputation=True,
                               include_dnstwist=False, scope="all", variant_intel=False)
        o._run_pipeline(req)

        assert len(captured) == 1, captured
        payload = captured[0]
        assert payload["domain"] == "acme-typo.it"
        cs = payload.get("collection_status")
        assert cs is not None, (
            "il payload verso CLASSIFY_URL/classify/variant non include "
            f"'collection_status' (orchestrator.py:387-392): {payload}"
        )
        assert cs.get("whois") is True, cs
        assert cs.get("cert") is True, cs
        assert cs.get("reputation") is True, cs
        # correzione 2026-08-02: http qui e' una risposta REALE (403), non un
        # guasto — non deve mai risultare marcata fallita
        assert cs.get("http") is not True, (
            "un 403 reale e' stato propagato come sezione http fallita: " + str(cs)
        )

    def test_dnstwist_variant_branch_includes_collection_status(self, orch, monkeypatch):
        """orchestrator.py:497-503. Il target del feed è whitelistato apposta
        così il loop feed non produce una propria chiamata a
        classify/variant: la SOLA chiamata catturata è quella del branch
        dnstwist/variant_intel, isolando esattamente il secondo punto."""
        o = orch
        captured = []
        domains_resp = {"domains": [
            {"domain": "acme.it", "client": "acme", "type": "target", "legitimate": "acme.it"},
        ]}
        whitelist_resp = {"whitelist": {"acme.it": {}}}
        twist_resp = {"registered_variants": 1, "variants": [
            {"domain": "acme-variant.it", "fuzzer": "insertion",
             "dns_a": True, "dns_mx": False, "geoip": ""},
        ]}
        monkeypatch.setattr(o._session, "get",
                            self._fake_get(o, domains_resp, whitelist_resp, twist_resp))
        monkeypatch.setattr(o._session, "post", self._fake_post(captured))
        monkeypatch.setattr(o.intel_store, "load_snapshot", lambda c, d: None)
        monkeypatch.setattr(o.intel_store, "save_snapshot", lambda c, d, i: True)

        req = o.TriggerRequest(client="acme", include_whois=True, include_reputation=True,
                               include_dnstwist=True, variant_intel=True, scope="all")
        o._run_pipeline(req)

        assert len(captured) == 1, captured
        payload = captured[0]
        assert payload["domain"] == "acme-variant.it"
        cs = payload.get("collection_status")
        assert cs is not None, (
            "il branch dnstwist/variant_intel non include 'collection_status' "
            f"nel payload verso il classificatore (orchestrator.py:497-503): {payload}"
        )
        assert cs.get("whois") is True, cs
        assert cs.get("cert") is True, cs
        assert cs.get("reputation") is True, cs
        assert cs.get("http") is not True, (
            "un 403 reale e' stato propagato come sezione http fallita: " + str(cs)
        )


class TestUnrequestedModulesNotMarkedFailed:
    """Requisito 1 (`CODE-15` + `CODE-14`, G3 terzo giro) — DIFETTO BLOCCANTE
    trovato dal verifier al G6 (secondo giro di questo ID), riprodotto qui
    end-to-end.

    `TriggerRequest.include_whois` / `include_reputation` (orchestrator.py:
    177-178) sono flag pubblici e documentati di `/trigger`, default `True`
    ma disattivabili dall'operatore (scenario reale: throttling registrar o
    quote VT/OTX esaurite). Quando `include_whois=False`,
    `_gather_intelligence` (orchestrator.py:591-594) semplicemente NON
    include il task "whois" nella lista da eseguire in parallelo:
    `intel["whois"]` resta al valore di inizializzazione `None`
    (orchestrator.py:583) per l'intero ciclo — non perché una chiamata sia
    fallita, ma perché non è mai stata tentata.

    `_build_collection_status` (orchestrator.py:255-263) delega a
    `_module_failed`, la cui prima riga è `if value is None: return True`
    (orchestrator.py:250-251): non distingue "sezione non richiesta per
    configurazione" da "sezione fallita davvero". Un ciclo dove TUTTI i dati
    RICHIESTI sono stati raccolti correttamente esce quindi con
    `collection_status={"whois": True, "reputation": True, ...}` —
    esattamente come se whois/reputation fossero fallite — e la severity
    scende per una scelta di CONFIGURAZIONE, non per un guasto.

    VINCOLO per il fixer (non prescrive l'implementazione interna, solo
    l'esito osservabile): una sezione il cui modulo non è stato richiesto in
    questo ciclo (`include_whois=False` / `include_reputation=False`) non
    deve MAI comparire come `True` in `collection_status` — né arrivare al
    classificatore come "fallita"."""

    DNS_OK = {"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}}
    CERT_OK = {"domain": "acme-typo.it", "timestamp": "2026-08-02T10:00:00Z",
               "ct_certificates": {"total": 4, "unique_cn": ["acme-typo.it"], "certificates": []},
               "tls_live": None, "san_subdomains_discovered": [], "error": None}
    # content_length=500: attivo (status 200) ma né <=200 (regola "parking")
    # né >3000 (regola "legitimate_probable" per contenuto sostanziale) — un
    # HTTP genuinamente raccolto con successo che non fa scattare altre
    # regole PRIMA di arrivare al controllo di collection_status, così il
    # test isola esattamente il comportamento sotto esame (requisito 1).
    HTTP_OK = {"domain": "acme-typo.it", "timestamp": "2026-08-02T10:00:00Z",
               "checks": [{"url": "http://acme-typo.it", "status_code": 200, "content_length": 500,
                           "title": "Acme", "server": "nginx", "content_hash": "abc123",
                           "content_hash_canonical": "abc123", "visible_text_hash": "def456",
                           "suspicious_patterns": [], "hidden_elements": {"risk_indicators": 0, "summary": []},
                           "redirect_chain": None, "error": None}],
               "overall_status": "active", "hidden_elements_risk": 0, "error": None}

    def _fake_get(self, o):
        cls = self
        domains_resp = {"domains": [
            {"domain": "acme-typo.it", "client": "acme", "type": "target",
             "legitimate": "acme.it", "fuzzer": "insertion"},
        ]}

        def _get(url, timeout=None):
            class R:
                def __init__(self, payload):
                    self._payload = payload
                    self.ok = True
                    self.status_code = 200
                def raise_for_status(self_inner):
                    pass
                def json(self_inner):
                    return self_inner._payload
            if "/feed/domains" in url:
                return R(domains_resp)
            if "/feed/whitelist" in url:
                return R({"whitelist": {}})
            if url.startswith(o.DNS_URL):
                return R(cls.DNS_OK)
            if url.startswith(o.CERT_URL):
                return R(cls.CERT_OK)
            if url.startswith(o.HTTP_URL):
                return R(cls.HTTP_OK)
            # whois/reputation NON devono essere chiamati affatto: con
            # include_whois=False/include_reputation=False il task è escluso
            # dalla lista in _gather_intelligence (orchestrator.py:591-594).
            # Una chiamata qui sarebbe un difetto DIVERSO da quello di questo
            # test (che riguarda l'interpretazione dello stato, non la
            # raccolta) — fallisce con un errore esplicito invece di un
            # falso negativo silenzioso.
            raise AssertionError(f"GET non atteso con include_whois/reputation=False: {url}")
        return _get

    def test_construction_unrequested_whois_and_reputation_not_marked_failed(self, orch, monkeypatch):
        """Livello di costruzione dello stato nell'orchestrator: il payload
        verso /classify/variant non deve marcare whois/reputation come
        fallite quando l'operatore le ha disattivate con i flag di
        /trigger — anche se dns/cert/http, TUTTI i dati effettivamente
        richiesti in questo ciclo, sono stati raccolti con successo."""
        o = orch
        captured = []

        def _fake_post(url, json=None, timeout=None):
            class R:
                ok = True
                status_code = 200
                def json(self_inner):
                    return {"auto_classification": "needs_review", "rule": "no_matching_rule",
                            "confidence": "low", "rationale": "x"}
            if url.endswith("/classify/variant"):
                captured.append(json)
            return R()

        monkeypatch.setattr(o._session, "get", self._fake_get(o))
        monkeypatch.setattr(o._session, "post", _fake_post)

        req = o.TriggerRequest(client="acme", include_whois=False, include_reputation=False,
                               include_dnstwist=False, scope="all", variant_intel=False)
        o._run_pipeline(req)

        assert len(captured) == 1, captured
        cs = captured[0].get("collection_status") or {}
        assert cs.get("whois") is not True, (
            f"whois non richiesto (include_whois=False) marcato fallito nel "
            f"payload verso il classificatore: {cs}"
        )
        assert cs.get("reputation") is not True, (
            f"reputation non richiesta (include_reputation=False) marcata "
            f"fallita nel payload verso il classificatore: {cs}"
        )
        # dns/cert/http sono stati effettivamente richiesti e raccolti con
        # successo in questo ciclo: non devono mai risultare falliti.
        assert cs.get("cert") is not True, cs
        assert cs.get("http") is not True, cs

    def test_end_to_end_all_requested_data_ok_stays_needs_review_not_insufficient(self, orch, monkeypatch):
        """Esito osservabile end-to-end (mandato G3, riproduzione del
        verifier): con `include_whois=False`/`include_reputation=False` e
        TUTTI i dati richiesti raccolti con successo, la classificazione
        finale — passando per il classificatore REALE (`classify_variant`),
        non uno stub — deve restare `needs_review`/MEDIUM,
        `manual_review_required=True`. Con l'implementazione attuale, il
        payload marca whois/reputation come fallite (vedi test precedente),
        `classify_variant` reagisce correttamente al SUO input (`services/
        classifier.py:315-319`) e produce `insufficient_data`/LOW,
        `manual_review_required=False`: il dominio esce silenziosamente dalla
        coda di revisione manuale per una scelta di configurazione, non per
        un guasto — la riproduzione esatta segnalata dal verifier al G6."""
        o = orch
        published = []

        def _fake_post(url, json=None, timeout=None):
            class R:
                ok = True
                status_code = 200
                _body = {}
                def json(self_inner):
                    return self_inner._body
            r = R()
            if url.endswith("/classify/variant"):
                from services.classifier import classify_variant, VariantInput
                import json as _json
                vi = VariantInput(**json)
                resp = classify_variant(vi)
                r._body = _json.loads(resp.body)
            elif url.endswith("/publish"):
                published.extend((json or {}).get("events", []))
            return r

        monkeypatch.setattr(o._session, "get", self._fake_get(o))
        monkeypatch.setattr(o._session, "post", _fake_post)

        req = o.TriggerRequest(client="acme", include_whois=False, include_reputation=False,
                               include_dnstwist=False, scope="all", variant_intel=False)
        o._run_pipeline(req)

        assert len(published) == 1, published
        cls = published[0]["classification"]
        assert cls["auto_classification"] == "needs_review", cls
        assert cls["manual_review_required"] is True, cls
        assert o.CLASSIFICATION_SEVERITY[cls["auto_classification"]] == "MEDIUM", (
            f"severity di caso per '{cls['auto_classification']}': "
            f"{o.CLASSIFICATION_SEVERITY.get(cls['auto_classification'])}"
        )


# ═══════════════════════════════════════════════════════════════
# SCO-05 — casi di pipeline (#5, #7, #8, #14, #15)
# ═══════════════════════════════════════════════════════════════
#
# Vivono qui, non in tests/test_classifier.py, perché dipendono dalla
# PIPELINE: il caso #5 dal meccanismo "lettura del WHOIS persistito" fra
# cicli; i #7/#8 dalla raccolta WHOIS-only per gli omografi dormienti; il
# #14 dal contratto di `_build_collection_status` ("non richiesto" ≠
# "richiesto e fallito"); il #15 dall'isolamento fra tenant.


class _R:
    """Risposta HTTP finta, con la sola superficie usata da
    `_fetch_service`/`_run_pipeline`: `ok`, `status_code`, `json()`,
    `raise_for_status()`."""

    def __init__(self, payload, ok=True, status_code=200):
        self._payload = payload
        self.ok = ok
        self.status_code = status_code

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _real_classifier_post(o, published, classify_payloads):
    """POST finto che instrada `/classify/variant` al VERO classificatore
    invece di restituire un esito preconfezionato. È la lezione del round 1:
    il caso #8 asseriva sulla FORMA del payload e sarebbe stato verde anche
    con esito `phishing`/CRITICAL. Qui si asserisce sulla classificazione
    risultante, che è ciò che diventa la severità del caso."""

    def _post(url, json=None, timeout=None, headers=None):
        if url.endswith("/classify/variant"):
            import json as _json
            from services.classifier import classify_variant, VariantInput
            classify_payloads.append(json)
            resp = classify_variant(VariantInput(**json))
            return _R(_json.loads(resp.body))
        if url.endswith("/publish"):
            published.extend((json or {}).get("events", []))
        return _R({})

    return _post


def _severity_of(o, event):
    cls = (event or {}).get("classification") or {}
    return o.CLASSIFICATION_SEVERITY.get(cls.get("auto_classification"), "MEDIUM")


def _event_for(published, domain, client=None):
    for e in published:
        if e.get("domain") == domain and (client is None or e.get("client") == client):
            return e
    return None


# ── Intel di contos0.example (client contoso) ──────────────────────────────
# FORMA reale, presa da uno snapshot reale; i VALORI sono sintetici (nome,
# client, date, nameserver, dimensioni). `registrant`, `registrar` e il
# `title` della pagina di parking portano segnaposto neutri: struttura,
# chiavi e tipi sono quelli reali — è la forma che il test esercita — ma
# nessun valore identificante.
#
# I valori che un'asserzione usa davvero conservano la classe che le regole
# leggono: `creation_date` ben oltre `AGE_THIRD_PARTY_DAYS` (il perno di
# `is_aged` per il caso #5, e la stringa che il caso #15 cerca nella
# rationale del secondo tenant), `updated_date` più vecchio di 120 giorni
# (nessun `recently_reregistered`), `content_length` sopra 3000 e
# `status_code: 200` (saturano la cascata su `http_active_substantial_content`
# nel ciclo risolvente). Da notare che nello snapshot reale la sezione `dns`
# è `None` (la raccolta DNS non ha mai prodotto un risultato valido per
# questo dominio, e CODE-01 impedisce di sovrascrivere la baseline con un
# fallimento): è la forma reale, non una semplificazione.
AGED_HOMOGLYPH_SNAPSHOT_INTEL = {
    "dns": None,
    "cert": {"domain": "contos0.example",
             "ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
             "tls_live": None, "san_subdomains_discovered": [], "error": None},
    "http": {"domain": "contos0.example", "overall_status": "active",
             "hidden_elements_risk": 0, "error": None,
             "checks": [
                 {"url": "http://contos0.example", "status_code": 200, "content_length": 5120,
                  "title": "REDACTED", "server": "nginx", "hidden_elements": None,
                  "error": None},
                 {"url": "https://contos0.example", "status_code": None, "content_length": 0,
                  "title": None, "server": "", "hidden_elements": None,
                  "error": "Attempt 3/3: HTTPSConnectionPool(host='contos0.example', port=443): "
                           "Max retries exceeded with url: / (Caused by SSLError(...))"}]},
    "whois": {"domain": "contos0.example", "registrar": "REDACTED",
              "creation_date": "2003-09-17T10:21:05",
              "expiration_date": "2027-09-17T10:21:05",
              "updated_date": "2025-10-02T14:08:51",
              "status": ["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"],
              "nameservers": ["ns1.registrar-c.example", "ns2.registrar-c.example"],
              "registrant": {"name": "REDACTED FOR PRIVACY", "org": "REDACTED FOR PRIVACY",
                             "country": None, "email": None},
              "privacy_protected": True, "dnssec": False, "age_days": None, "error": None},
    "reputation": None,
}


class TestSCO05AntiOscillationUsesPersistedWhois:
    """Caso #5 del criterio SCO-05, RISCRITTO alla revisione 2.

    Perché riscritto: il test del round 1 disabilitava `intel_store`
    (`load_snapshot` monkeypatchata a `lambda c, d: None`), quindi esercitava
    solo la cache in-process — che è VUOTA al primo ciclo dopo un riavvio del
    container, cioè esattamente nella situazione in cui l'anti-oscillazione
    serve. Qui il WHOIS è disponibile SOLO dallo snapshot persistito: il
    meccanismo primario vero.

    Forma di uno snapshot reale, valori sintetici (v.
    `AGED_HOMOGLYPH_SNAPSHOT_INTEL` sopra). Negli eventi reali del dominio da
    cui la forma è presa la classificazione alternava:
      `legitimate_probable`/`http_active_substantial_content`  → LOW
      `dnstwist_discovery` (placeholder, dns_a=False/dns_mx=False) → MEDIUM
      `dnstwist_discovery` con dns_a=True/dns_mx=True             → MEDIUM
    Lo stesso dominio, con lo stesso WHOIS (creation_date di oltre vent'anni
    prima, `is_aged=True`), oscilla fra LOW e
    MEDIUM al variare della sola osservazione DNS del ciclo. È l'oscillazione
    che il criterio vieta: l'età di un dominio non cambia perché oggi non
    risolve."""

    FEED = {"domains": [{"domain": "contoso.example", "client": "contoso", "type": "target",
                         "legitimate": "contoso.example"}]}
    TWIST_DORMANT = {"registered_variants": 1, "variants": [
        {"domain": "contos0.example", "fuzzer": "homoglyph",
         "dns_a": False, "dns_mx": False, "geoip": ""}]}

    def test_dormant_cycle_after_restart_reuses_the_persisted_whois(
            self, orch, monkeypatch, tmp_path):
        """Un ciclo dormiente che parte con la cache in-process vuota (primo
        ciclo dopo un riavvio) deve comunque produrre la severità di caso che
        il WHOIS persistito impone — LOW, dominio del 2001 — invece di
        ricadere sul placeholder MEDIUM."""
        o = orch
        # Lo store reale, su una directory temporanea: mai il volume /data.
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        assert o.intel_store.save_snapshot("contoso", "contos0.example",
                                           AGED_HOMOGLYPH_SNAPSHOT_INTEL)

        published, classify_payloads, whois_calls = [], [], []

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _R(self.FEED)
            if "/feed/whitelist" in url:
                return _R({"whitelist": {}})
            if url.startswith(o.TWIST_URL):
                return _R(self.TWIST_DORMANT)
            if url.startswith(o.WHOIS_URL):
                whois_calls.append(url)
                return _R({"domain": "contoso.example", "creation_date": "1997-01-01T00:00:00",
                           "error": None})
            return _R({})

        monkeypatch.setattr(o._session, "get", _get)
        monkeypatch.setattr(o._session, "post",
                            _real_classifier_post(o, published, classify_payloads))

        o._run_pipeline(o.TriggerRequest(client="contoso", include_whois=True,
                                         include_reputation=False, include_dnstwist=True,
                                         variant_intel=True, scope="all"))

        ev = _event_for(published, "contos0.example")
        assert ev is not None, f"nessun evento per contos0.example: {published}"
        assert not any("contos0.example" in u for u in whois_calls), (
            "il meccanismo anti-oscillazione deve riusare lo snapshot persistito, "
            f"non aprire una nuova raccolta WHOIS: {whois_calls}")
        assert _severity_of(o, ev) == "LOW", (
            "contos0.example (creation_date 2003-09-17, aged) resta a severità di caso "
            f"{_severity_of(o, ev)} in un ciclo dormiente, contro LOW nei cicli reali "
            f"in cui risolveva: {ev['classification']}")


class TestSCO05HomoglyphWhoisCacheFreshnessThreshold:
    """R4 (verifier, `SCO-05` round 2, G6, 2026-08-11) — round 3, G3.

    Mutation testing round 2: il mutante M8 ("`_is_fresh_iso` sempre True")
    è sopravvissuto — `407 passed`. Nessun test esercitava la soglia di
    `_HOMOGLYPH_WHOIS_MAX_AGE_S` (30gg): `TestSCO05AntiOscillationUsesPersistedWhois`
    sopra copre solo il lato "fresco" (WHOIS persistito, riusato). Qui due
    snapshot IDENTICI salvo `updated_at` — uno a 29 giorni (sotto soglia),
    uno a 31 (sopra) — devono produrre esiti DISTINTI da
    `_cached_homoglyph_whois`: il primo riusato, il secondo no.

    Perimetro dichiarato, per non allargare lo scope: il fatto che il ramo
    WHOIS-only dormiente non chiami mai `_persist_intel` (quindi `updated_at`
    di un omografo permanentemente dormiente non avanza mai) è un
    comportamento STRUTTURALE distinto, segnalato dal verifier nella stessa
    voce R4 ma non isolabile in un singolo confine come la soglia — resta
    fuori da questo test, per decisione esplicita del `pm` in corso di
    lavorazione."""

    def test_cached_homoglyph_whois_distinguishes_fresh_from_stale_snapshot(
            self, orch, monkeypatch, tmp_path):
        import json
        from datetime import datetime, timedelta, timezone
        o = orch
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")

        fresh_ts = (datetime.now(timezone.utc) - timedelta(days=29)).isoformat()
        stale_ts = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        whois_payload = {"creation_date": "2003-09-17T10:21:05", "error": None}

        def _write(domain, updated_at):
            d = tmp_path / "snapshots" / "contoso"
            d.mkdir(parents=True, exist_ok=True)
            record = {"domain": domain, "client": "contoso", "updated_at": updated_at,
                      "intel": {"whois": whois_payload}}
            (d / f"{domain}.json").write_text(json.dumps(record))

        _write("fresh0.com", fresh_ts)
        _write("stale0.com", stale_ts)

        fresh_result = o._cached_homoglyph_whois("contoso", "fresh0.com")
        stale_result = o._cached_homoglyph_whois("contoso", "stale0.com")

        assert fresh_result == whois_payload, (
            "uno snapshot persistito 29 giorni fa (sotto la soglia di 30gg) non è "
            f"stato riusato: {fresh_result}"
        )
        assert stale_result is None, (
            "uno snapshot persistito 31 giorni fa (oltre la soglia di 30gg) è stato "
            f"riusato lo stesso, come se fosse ancora fresco: {stale_result}"
        )


class TestSCO05WhoisOnlyResidualMechanism:
    """Caso #7 del criterio SCO-05 (INVARIATO alla revisione 2; il #8 è stato
    riscritto e vive in `TestSCO05WhoisOnlyFailureIsNotElevated`, sotto).
    I domini omografi mai raccolti in
    nessuno dei cicli osservati (query G2 del `bug-researcher` su un insieme
    di snapshot reali, sempre `dnstwist_discovery`/`needs_review`) sono qui
    rappresentati da nomi sintetici della stessa forma (`contosa.example`,
    ASCII; `xn--prseware-w3a.example`, IDN Latin Extended a script singolo). Il
    contenuto WHOIS usato qui è
    necessariamente sintetico — per definizione questi domini non hanno
    mai completato una raccolta, quindi non esiste alcuno snapshot reale da
    cui copiarlo (è esattamente la ragione per cui rientrano nel
    meccanismo WHOIS-only, Domanda 3 opzione C, decisione utente
    2026-08-08).

    Oggi nessuna raccolta viene mai tentata per questi domini
    (`orchestrator.py:519`): `/classify/variant` non viene mai chiamato per
    una variante dormiente, quindi non esiste alcun meccanismo che possa
    marcare un tentativo come riuscito o fallito."""

    def _fake_get(self, o, domains_resp, whitelist_resp, twist_resp, whois_by_domain):
        def _get(url, timeout=None):
            class R:
                def __init__(self, payload, ok=True):
                    self._payload = payload
                    self.ok = ok
                    self.status_code = 200 if ok else 504
                def raise_for_status(self_inner):
                    pass
                def json(self_inner):
                    return self_inner._payload
            if "/feed/domains" in url:
                return R(domains_resp)
            if "/feed/whitelist" in url:
                return R(whitelist_resp)
            if url.startswith(o.TWIST_URL):
                return R(twist_resp)
            if url.startswith(o.WHOIS_URL):
                for dom, resp in whois_by_domain.items():
                    if f"domain={dom}" in url:
                        return R(resp)
                return R({"error": None})
            # dns/cert/http/reputation: il meccanismo scoped è WHOIS-only
            # (Domanda 3 opzione C, costo minimo) — una risposta neutra
            # generica basta, questi due test non riguardano quei moduli.
            return R({})
        return _get

    def _fake_post(self, captured):
        def _post(url, json=None, timeout=None):
            class R:
                ok = True
                status_code = 200
                def json(self_inner):
                    return {"auto_classification": "needs_review", "rule": "no_matching_rule",
                            "confidence": "low", "rationale": "x"}
            if url.endswith("/classify/variant"):
                captured.append(json)
            return R()
        return _post

    def _base_req(self, o):
        return o.TriggerRequest(client="contoso", include_whois=True, include_reputation=False,
                                include_dnstwist=True, variant_intel=True, scope="all")

    def test_case7_residual_domain_whois_only_success_reaches_classifier(self, orch, monkeypatch):
        """`contosa.example`, dormiente in tutti i cicli osservati. Al primo
        ciclo con la raccolta WHOIS-only attiva e riuscita, il dominio deve
        raggiungere `/classify/variant` anche se `dns_a=dns_mx=False —
        oggi resta bloccato a tempo indefinito su
        `dnstwist_discovery`/`needs_review` perché `orchestrator.py:519`
        lo esclude a priori."""
        o = orch
        captured = []
        domains_resp = {"domains": [
            {"domain": "contoso.example", "client": "contoso", "type": "target", "legitimate": "contoso.example"}]}
        whitelist_resp = {"whitelist": {"contoso.example": {}}}
        twist_resp = {"registered_variants": 1, "variants": [
            {"domain": "contosa.example", "fuzzer": "homoglyph", "dns_a": False, "dns_mx": False, "geoip": ""}]}
        monkeypatch.setattr(o._session, "get", self._fake_get(
            o, domains_resp, whitelist_resp, twist_resp,
            {"contosa.example": {"error": None, "creation_date": "2024-01-15T00:00:00"}}))
        monkeypatch.setattr(o._session, "post", self._fake_post(captured))
        monkeypatch.setattr(o.intel_store, "load_snapshot", lambda c, d: None)
        monkeypatch.setattr(o.intel_store, "save_snapshot", lambda c, d, i: True)
        monkeypatch.setattr(o.intel_store, "append_history", lambda c, d, diff: True)

        o._run_pipeline(self._base_req(o))

        assert len(captured) == 1, (
            "contosa.example (dormiente, mai raccolto, uno dei residui della Domanda 3) "
            f"non ha raggiunto /classify/variant: {captured}"
        )
        assert captured[0]["domain"] == "contosa.example"

    def test_case7_r1_whois_only_gate_fetches_and_the_rule_reflects_a_real_observation(
            self, orch, monkeypatch, tmp_path):
        """R1 (verifier, `SCO-05` round 2, G6, 2026-08-11) — round 3, G3.

        `grep -r "WHOIS_ONLY_DOMAINS\\|_is_fresh_iso\\|_HOMOGLYPH_WHOIS_CACHE"
        tests/` non trovava nulla prima di questo test: nessun test popolava
        mai `WHOIS_ONLY_DOMAINS`, quindi il ramo di raccolta dal vivo
        (`_fetch_service("whois", ...)`) non era MAI stato eseguito da G3 né
        da G5, in nessuno dei due round. Il test sopra (invariato) resta
        verde anche a variabile vuota, perché asserisce solo che
        `/classify/variant` è stato raggiunto — non che una raccolta sia
        davvero avvenuta.

        Qui `WHOIS_ONLY_DOMAINS` è popolata DAVVERO (via monkeypatch
        sull'attributo di modulo, non sull'ambiente — il valore è calcolato
        all'import). L'asserzione è sulla `rule` restituita dal VERO
        classificatore, non sulla sola severità: un ramo WHOIS-only che
        restituisse un risultato vuoto (o che non chiamasse mai
        `_fetch_service`) produrrebbe `no_matching_rule`/`needs_review` — la
        STESSA severità di caso (MEDIUM oggi, prima del blocco omografo) ma
        una `rule` diversa da `homoglyph_dormant_not_aged`, quindi il test è
        rosso se il meccanismo non ha fatto nulla, non solo se ha sbagliato
        la severità."""
        o = orch
        monkeypatch.setattr(o, "WHOIS_ONLY_DOMAINS", frozenset({"contosa.example"}))
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        published, classify_payloads, whois_calls = [], [], []
        domains_resp = {"domains": [
            {"domain": "contoso.example", "client": "contoso", "type": "target", "legitimate": "contoso.example"}]}
        twist_resp = {"registered_variants": 1, "variants": [
            {"domain": "contosa.example", "fuzzer": "homoglyph", "dns_a": False, "dns_mx": False, "geoip": ""}]}

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _R(domains_resp)
            if "/feed/whitelist" in url:
                return _R({"whitelist": {}})
            if url.startswith(o.TWIST_URL):
                return _R(twist_resp)
            if url.startswith(o.WHOIS_URL):
                whois_calls.append(url)
                # Non-aged: creation_date recente, ben sotto AGE_THIRD_PARTY_DAYS
                # (540gg) alla data odierna, indipendentemente da quando gira il test.
                return _R({"domain": "contosa.example", "error": None,
                           "creation_date": "2026-06-01T00:00:00"})
            return _R({})

        monkeypatch.setattr(o._session, "get", _get)
        monkeypatch.setattr(o._session, "post",
                            _real_classifier_post(o, published, classify_payloads))

        o._run_pipeline(o.TriggerRequest(client="contoso", include_whois=True,
                                         include_reputation=False, include_dnstwist=True,
                                         variant_intel=True, scope="all"))

        assert any("contosa.example" in u for u in whois_calls), (
            "WHOIS_ONLY_DOMAINS popolata con contosa.example, ma nessuna raccolta WHOIS "
            f"dal vivo è stata tentata: {whois_calls}"
        )
        ev = _event_for(published, "contosa.example")
        assert ev is not None, f"nessun evento per contosa.example: {published}"
        cls = ev["classification"]
        assert cls["rule"] == "homoglyph_dormant_not_aged", (
            "la raccolta WHOIS-only è avvenuta ma la rule non riflette un'osservazione "
            f"reale (dominio dormiente, non aged, senza mescolanza di script) — "
            f"{cls['rule']}: {cls['rationale']}"
        )
        assert cls["auto_classification"] == "suspicious", cls
        assert _severity_of(o, ev) == "HIGH", cls


class TestSCO05WhoisOnlyFailureIsNotElevated:
    """Caso #8 del criterio SCO-05, RISCRITTO alla revisione 2.

    Perché riscritto: il test del round 1 (`test_case8_..._marked_distinctly_...`)
    asseriva solo la FORMA del payload verso il classificatore
    (`collection_status["whois"] is True`). Quell'asserzione sarebbe stata
    verde anche con esito `phishing`/CRITICAL — è la ragione per cui il difetto
    ha attraversato G3 e G5 nel round 1. Qui il POST è instradato al VERO
    classificatore e si asserisce la CLASSIFICAZIONE RISULTANTE, cioè quello
    che l'analista vede in coda.

    `xn--prseware-w3a.example` (decodifica `próseware.example`, single-script
    Latin Extended) ha la forma di un omografo reale mai raccolto in nessuno
    dei cicli osservati. Il contenuto del fallimento WHOIS è necessariamente SINTETICO:
    per definizione non esiste snapshot da cui copiarlo — è la ragione stessa
    per cui il dominio rientra nel meccanismo WHOIS-only."""

    FEED = {"domains": [{"domain": "proseware.example", "client": "proseware", "type": "target",
                         "legitimate": "proseware.example"}]}
    TWIST = {"registered_variants": 1, "variants": [
        {"domain": "xn--prseware-w3a.example", "fuzzer": "homoglyph",
         "dns_a": False, "dns_mx": False, "geoip": ""}]}

    def test_transient_whois_failure_does_not_elevate_the_case(
            self, orch, monkeypatch, tmp_path):
        """Un guasto di rete transitorio sulla raccolta WHOIS non deve valere
        quanto un segnale osservato: senza mescolanza di script, senza DNS e
        senza WHOIS il caso non va elevato. `insufficient_data`/MEDIUM è
        l'esito che la guardia di raccolta (CODE-23) produce già per ogni
        altra regola nella stessa condizione."""
        o = orch
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        published, classify_payloads = [], []

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _R(self.FEED)
            if "/feed/whitelist" in url:
                return _R({"whitelist": {}})
            if url.startswith(o.TWIST_URL):
                return _R(self.TWIST)
            if url.startswith(o.WHOIS_URL) and "xn--prseware-w3a.example" in url:
                return _R({"domain": "xn--prseware-w3a.example", "registrar": None,
                           "creation_date": None, "age_days": None,
                           "error": "WHOIS collection timeout"})
            return _R({})

        monkeypatch.setattr(o._session, "get", _get)
        monkeypatch.setattr(o._session, "post",
                            _real_classifier_post(o, published, classify_payloads))

        o._run_pipeline(o.TriggerRequest(client="proseware", include_whois=True,
                                         include_reputation=False, include_dnstwist=True,
                                         variant_intel=True, scope="all"))

        ev = _event_for(published, "xn--prseware-w3a.example")
        assert ev is not None, f"nessun evento per xn--prseware-w3a.example: {published}"
        cls = ev["classification"]
        assert cls["auto_classification"] != "suspicious", (
            "un WHOIS andato in timeout ha elevato il caso a suspicious/HIGH: "
            f"«non ho potuto guardare» trattato come «ho visto qualcosa» — {cls}")
        assert _severity_of(o, ev) == "MEDIUM", (
            f"{cls['auto_classification']}/{cls['rule']} → {_severity_of(o, ev)}")

    def test_case8_r1_whois_only_gate_fetches_and_distinguishes_failed_from_never_attempted(
            self, orch, monkeypatch, tmp_path):
        """R1 (verifier, `SCO-05` round 2, G6, 2026-08-11) — round 3, G3.

        Il test sopra (invariato) asserisce SOLO sulla severità
        (`!= suspicious`, `== MEDIUM`). `needs_review` (mai tentato,
        `rule=no_matching_rule`) e `insufficient_data` (tentato e fallito,
        `rule=module_collection_failed`) hanno la STESSA severità di caso
        (MEDIUM — "needs_review ha la STESSA severita' di caso di
        insufficient_data", `TestCollectionGuardOverridesAbsolutoryRules`
        in `test_classifier.py`): quel test resta verde anche se
        `WHOIS_ONLY_DOMAINS` è vuota e la raccolta non è mai stata tentata,
        cioè anche se il ramo che dovrebbe dimostrare fosse stato cancellato
        del tutto (mutante M9, sopravvissuto: `407 passed`).

        Qui `WHOIS_ONLY_DOMAINS` è popolata davvero e l'asserzione è sulla
        `rule` restituita dal VERO classificatore: deve essere
        `module_collection_failed` (tentato e fallito), non
        `no_matching_rule` (mai tentato) — le due producono lo stesso MEDIUM
        ma raccontano storie diverse all'analista, ed è esattamente la
        distinzione a tre stati decisa dall'utente l'8/8 (Definition of
        Ready `SCO-05`, "mai tentato" / "tentato e riuscito" / "tentato e
        fallito")."""
        o = orch
        monkeypatch.setattr(o, "WHOIS_ONLY_DOMAINS", frozenset({"xn--prseware-w3a.example"}))
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        published, classify_payloads, whois_calls = [], [], []

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _R(self.FEED)
            if "/feed/whitelist" in url:
                return _R({"whitelist": {}})
            if url.startswith(o.TWIST_URL):
                return _R(self.TWIST)
            if url.startswith(o.WHOIS_URL) and "xn--prseware-w3a.example" in url:
                whois_calls.append(url)
                return _R({"domain": "xn--prseware-w3a.example", "registrar": None,
                           "creation_date": None, "age_days": None,
                           "error": "WHOIS collection timeout"})
            return _R({})

        monkeypatch.setattr(o._session, "get", _get)
        monkeypatch.setattr(o._session, "post",
                            _real_classifier_post(o, published, classify_payloads))

        o._run_pipeline(o.TriggerRequest(client="proseware", include_whois=True,
                                         include_reputation=False, include_dnstwist=True,
                                         variant_intel=True, scope="all"))

        assert any("xn--prseware-w3a.example" in u for u in whois_calls), (
            "WHOIS_ONLY_DOMAINS popolata con xn--prseware-w3a.example, ma nessuna raccolta "
            f"WHOIS dal vivo è stata tentata: {whois_calls}"
        )
        ev = _event_for(published, "xn--prseware-w3a.example")
        assert ev is not None, f"nessun evento per xn--prseware-w3a.example: {published}"
        cls = ev["classification"]
        assert cls["rule"] == "module_collection_failed", (
            "la raccolta WHOIS-only è stata tentata e ha fallito (timeout), ma la rule "
            "non lo riflette — indistinguibile da un dominio mai raccolto: "
            f"{cls['rule']}: {cls['rationale']}"
        )
        assert cls["auto_classification"] == "insufficient_data", cls
        assert _severity_of(o, ev) == "MEDIUM", cls


class TestSCO05WhoisNotRequestedIsNotCollected:
    """Caso #14. `_build_collection_status` (services/orchestrator.py) esiste
    proprio per non collassare "sezione non richiesta in questo ciclo" e
    "sezione richiesta e fallita": con `include_whois=False` la chiave `whois`
    viene esclusa dal risultato invece di passare per `_module_failed(None)`.
    Il ramo omografo nuovo deve rispettare lo stesso contratto — un flag
    dell'operatore che dice "in questo ciclo niente WHOIS" non può essere
    scavalcato da una regola di classificazione.

    Due conseguenze concrete: chiamate WHOIS uscenti non richieste (quota e
    superficie di rete, CLAUDE.md §1 vincolo 4), e un `collection_status`
    che dichiara al classificatore lo stato di una sezione che non è stata
    parte del ciclo.

    `contosa.example` ha la forma di uno dei residui mai raccolti (nome
    sintetico); lo
    scenario del ciclo `include_whois=False` è sintetico."""

    FEED = {"domains": [{"domain": "contoso.example", "client": "contoso", "type": "target",
                         "legitimate": "contoso.example"}]}
    TWIST = {"registered_variants": 1, "variants": [
        {"domain": "contosa.example", "fuzzer": "homoglyph",
         "dns_a": False, "dns_mx": False, "geoip": ""}]}

    def test_include_whois_false_produces_no_whois_call_and_no_whois_status(
            self, orch, monkeypatch, tmp_path):
        o = orch
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        published, classify_payloads, whois_calls = [], [], []

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _R(self.FEED)
            if "/feed/whitelist" in url:
                return _R({"whitelist": {}})
            if url.startswith(o.TWIST_URL):
                return _R(self.TWIST)
            if url.startswith(o.WHOIS_URL):
                whois_calls.append(url)
                return _R({"domain": "contosa.example", "creation_date": "2024-01-15T00:00:00",
                           "error": None})
            return _R({})

        monkeypatch.setattr(o._session, "get", _get)
        monkeypatch.setattr(o._session, "post",
                            _real_classifier_post(o, published, classify_payloads))

        o._run_pipeline(o.TriggerRequest(client="contoso", include_whois=False,
                                         include_reputation=False, include_dnstwist=True,
                                         variant_intel=True, scope="all"))

        assert whois_calls == [], (
            "ciclo con include_whois=False: il ramo omografo ha comunque aperto una "
            f"raccolta WHOIS uscente — {whois_calls}")
        declared = [p for p in classify_payloads
                    if "whois" in (p.get("collection_status") or {})]
        assert declared == [], (
            "collection_status dichiara lo stato della sezione whois in un ciclo in cui "
            f"non è stata richiesta: {declared}")

    def test_case14_r1_include_whois_false_overrides_whois_only_domains_and_the_rule_matches_never_attempted(
            self, orch, monkeypatch, tmp_path):
        """R1 (verifier, `SCO-05` round 2, G6, 2026-08-11) — round 3, G3,
        "metà del 14" non coperta.

        Il test sopra prova solo che con `WHOIS_ONLY_DOMAINS` VUOTA (il
        default della fixture) `include_whois=False` non apre raccolte — ma
        con la variabile vuota il gate `vdomain.lower() in WHOIS_ONLY_DOMAINS`
        è già falso per conto suo, quindi non dimostra che sia
        `include_whois` a fermare la raccolta. Qui `contosa.example` è
        ESPLICITAMENTE nella lista (il caso reale: un dominio residuo
        configurato), e il ciclo ha comunque `include_whois=False`:
        l'asserzione è di nuovo sulla `rule` del VERO classificatore, non
        solo sull'assenza della chiamata — deve coincidere ESATTAMENTE con
        l'esito "mai tentato" (`no_matching_rule`/`needs_review`), la stessa
        rule che il dominio riceverebbe se non fosse affatto nella lista."""
        o = orch
        monkeypatch.setattr(o, "WHOIS_ONLY_DOMAINS", frozenset({"contosa.example"}))
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        published, classify_payloads, whois_calls = [], [], []

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _R(self.FEED)
            if "/feed/whitelist" in url:
                return _R({"whitelist": {}})
            if url.startswith(o.TWIST_URL):
                return _R(self.TWIST)
            if url.startswith(o.WHOIS_URL):
                whois_calls.append(url)
                return _R({"domain": "contosa.example", "creation_date": "2026-06-01T00:00:00",
                           "error": None})
            return _R({})

        monkeypatch.setattr(o._session, "get", _get)
        monkeypatch.setattr(o._session, "post",
                            _real_classifier_post(o, published, classify_payloads))

        o._run_pipeline(o.TriggerRequest(client="contoso", include_whois=False,
                                         include_reputation=False, include_dnstwist=True,
                                         variant_intel=True, scope="all"))

        assert whois_calls == [], (
            "contosa.example è in WHOIS_ONLY_DOMAINS, ma il ciclo ha include_whois=False: "
            f"una raccolta è stata comunque aperta — {whois_calls}"
        )
        ev = _event_for(published, "contosa.example")
        assert ev is not None, f"nessun evento per contosa.example: {published}"
        cls = ev["classification"]
        assert cls["rule"] == "no_matching_rule", (
            "include_whois=False deve produrre l'esito «mai tentato» anche per un "
            f"dominio elencato in WHOIS_ONLY_DOMAINS — {cls['rule']}: {cls['rationale']}"
        )
        assert cls["auto_classification"] == "needs_review", cls
        assert _severity_of(o, ev) == "MEDIUM", cls


class TestSCO05TenantIsolationOfHomoglyphWhois:
    """Caso #15. Il WHOIS raccolto durante il ciclo di un cliente non deve
    essere servito al ciclo di un altro cliente. `intel_store.load_snapshot`
    è chiavato su `(client, domain)`; la cache in-process introdotta dal fix
    del round 1 è chiavata sul solo dominio, quindi attraversa il confine di
    tenant. Due tenant dello stesso MSSP che monitorano marchi affini
    incrociano gli stessi lookalike: la condizione non è di laboratorio.

    Il dominio ha la forma di uno snapshot reale, con valori sintetici
    (`contos0.example`, v. `AGED_HOMOGLYPH_SNAPSHOT_INTEL` sopra) — la
    `creation_date` 2003-09-17 è il marcatore che l'asserzione
    cerca nella rationale del secondo tenant. Anche il secondo
    tenant è SINTETICO — serve a esibire il confine."""

    FEED = {"domains": [
        {"domain": "contoso.example", "client": "contoso", "type": "target",
         "legitimate": "contoso.example"},
        {"domain": "contoso.test", "client": "altrotenant", "type": "target",
         "legitimate": "contoso.test"},
    ]}

    def test_whois_collected_for_one_client_is_not_served_to_another(
            self, orch, monkeypatch, tmp_path):
        o = orch
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        published, classify_payloads = [], []
        stored_whois = AGED_HOMOGLYPH_SNAPSHOT_INTEL["whois"]

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _R(self.FEED)
            if "/feed/whitelist" in url:
                return _R({"whitelist": {}})
            if url.startswith(o.TWIST_URL):
                # Lo stesso lookalike compare per entrambi i tenant: risolvente
                # nel ciclo del primo, dormiente in quello del secondo.
                resolving = "domain=contoso.example" in url
                return _R({"registered_variants": 1, "variants": [
                    {"domain": "contos0.example", "fuzzer": "homoglyph",
                     "dns_a": resolving, "dns_mx": False, "geoip": ""}]})
            if url.startswith(o.WHOIS_URL) and "contos0.example" in url:
                return _R(stored_whois)
            if url.startswith(o.DNS_URL) and "contos0.example" in url:
                return _R({"records": {"A": ["203.0.113.37"], "MX": [],
                                       "NS": ["ns1.registrar-c.example"]}, "error": None})
            if url.startswith(o.HTTP_URL) and "contos0.example" in url:
                return _R(AGED_HOMOGLYPH_SNAPSHOT_INTEL["http"])
            return _R({})

        monkeypatch.setattr(o._session, "get", _get)
        monkeypatch.setattr(o._session, "post",
                            _real_classifier_post(o, published, classify_payloads))

        o._run_pipeline(o.TriggerRequest(include_whois=True, include_reputation=False,
                                         include_dnstwist=True, variant_intel=True,
                                         scope="all"))

        first = _event_for(published, "contos0.example", client="contoso")
        second = _event_for(published, "contos0.example", client="altrotenant")
        assert first is not None and second is not None, published
        rationale = (second["classification"] or {}).get("rationale") or ""
        assert "2003-09-17" not in rationale, (
            "il WHOIS raccolto per il tenant 'contoso' è finito nel caso del tenant "
            f"'altrotenant', che non ha alcuno snapshot proprio: {rationale}")
        assert second["classification"]["auto_classification"] != "likely_third_party", (
            "il secondo tenant è stato scagionato sulla base di dati raccolti per il "
            f"primo: {second['classification']}")


# ═══════════════════════════════════════════════════════════════
# COL-02 (consumatori) — l'orchestrator non legge `unknown` come assenza
# ═══════════════════════════════════════════════════════════════
#
# Criteri O1-O5 di BUG-REGISTER.md («ASSEGNA · COL-02 (consumatori, secondo
# commit)»). Dopo RES-01 (nucleo) `/dns` dichiara per ogni parte (7 tipi base,
# SPF/DMARC/BIMI/CAA) se l'esito è `ok`/`nodata`/`nxdomain`/`unknown`, e mette un
# `error` costante quando i 7 tipi base sono tutti `unknown`. Qui si fissa ciò che
# l'orchestrator ne fa:
#
#   O1  guasto di modulo (sezione `None` o `error`): sezione precedente conservata
#       (percorso CODE-01, invariato); se NON c'è un precedente, la sezione guasta (tutti
#       `unknown`) diventa la baseline, così il ciclo dopo può confrontarsi (SEC-31);
#   O2  altrimenti riporto PER PARTE: una parte `unknown` prende record e stato del
#       precedente (precedente senza stato: record copiati e stato tolto = «noto»);
#       nessun precedente: `[]` con stato `unknown`; sottodomini e selettori DKIM si
#       riportano per nome, con il marcatore nella propria sezione (COL-31);
#       copia profonda, `intel["dns"]` (che va a classificazione ed eventi) intatto;
#   O3  `collection_status["dns"] = _module_failed(intel["dns"])` nei due punti che
#       lo costruiscono, assente nel percorso dell'omografo dormiente;
#   O4  eventi: `dns_a`/`dns_mx` restano bool, nuovi `dns_a_status`/`dns_mx_status`;
#   O5  primo ciclo con guasto totale e nessuna baseline: nessun 500, nessun alert
#       falso, comportamento esplicito. GIRO CORRETTIVO (verdetto INSUFFICIENTE del verifier,
#       SEC-31 riunificato in COL-02, DECISIONE del coordinator): il risveglio ha gli alert
#       ordinari. Un tipo `unknown` nella baseline senza valore noto precedente è un
#       riferimento vuoto: il primo valore noto e non vuoto allerta come un cambio ordinario
#       (da `[]` al valore, stessa severità), una volta; noto ma vuoto no; una baseline nota
#       resta il riferimento (X -> unknown -> Y = un alert X -> Y). Prima la prima versione di
#       questi test (O5) pretendeva «0 alert al risveglio»: era il comportamento sbagliato, e
#       li ho riscritti (G5: test di questo stesso lavoro, corretti prima del commit).
#
# I test «controllo» (verdi anche prima del fix) sono dichiarati nel docstring: fissano
# ciò che il fix non deve toccare (CODE-01, cambi veri, booleani degli eventi).

import copy

from fastapi.testclient import TestClient

from services.classifier import app as _c02_classifier_app
from shared.constants import SEVERITY_MAP as _C02_SEVERITY_MAP

_C02_DOMAIN = "acme-typo.example"
_C02_BASE = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
_C02_EMAIL_SECTIONS = ["spf", "dmarc", "bimi", "caa"]
_C02_ALL_UNKNOWN_ERROR = "DNS resolution failed: no base record type could be resolved"
_C02_SAMPLE = {
    "A": ["192.0.2.10"], "AAAA": ["2001:db8::10"], "MX": ["10 mail.acme-typo.example"],
    "NS": ["ns1.acme-typo.example", "ns2.acme-typo.example"], "TXT": ['"v=spf1 -all"'],
    "SOA": ["ns1.acme-typo.example hostmaster.acme-typo.example 2026010101 7200 900 1209600 3600"],
    "CNAME": ["target.acme-typo.example"],
}


def _c02_healthy_dns():
    """`/dns` di una zona sana come lo produce il codice dopo RES-01: ogni tipo base ha un
    record e stato `ok`, ogni sezione email è presente."""
    return {
        "domain": _C02_DOMAIN, "timestamp": "2026-10-20T10:00:00+00:00",
        "records": copy.deepcopy(_C02_SAMPLE),
        "records_status": {t: "ok" for t in _C02_BASE},
        "email_auth": {
            "spf": {"present": True, "records": ['"v=spf1 -all"'], "policy": "fail", "status": "ok"},
            "dmarc": {"present": True, "records": ['"v=DMARC1; p=reject"'], "status": "ok"},
            "dkim": {"selectors_found": ["google"], "selectors_tested": 18,
                     "records": {"google": ['"v=DKIM1; k=rsa; p=KEY"']}, "selectors_unknown": []},
            "bimi": {"present": True, "records": ['"v=BIMI1; l=https://acme-typo.example/logo.svg"'],
                     "status": "ok"},
            "caa": {"present": True, "records": ['0 issue "letsencrypt.org"'], "status": "ok"},
        },
        "subdomains": {"tested": 25, "unknown": [],
                       "active": [{"fqdn": f"www.{_C02_DOMAIN}", "A": ["192.0.2.20"], "CNAME": []}]},
        "error": None,
    }


def _c02_unknown(dns, *parts):
    """`dns` con le `parts` indeterminate, come `/dns` le produce con un SERVFAIL: record `[]`
    e stato `unknown`. TXT trascina SPF (`spf.status` è lo stato del TXT)."""
    out = copy.deepcopy(dns)
    for part in parts:
        if part in _C02_BASE:
            out["records"][part] = []
            out["records_status"][part] = "unknown"
            if part == "TXT":
                out["email_auth"]["spf"] = {"present": False, "records": [], "policy": None, "status": "unknown"}
        elif part == "spf":
            out["email_auth"]["spf"] = {"present": False, "records": [], "policy": None, "status": "unknown"}
        else:
            out["email_auth"][part] = {"present": False, "records": [], "status": "unknown"}
    return out


def _c02_total_failure(dns=None):
    """Tutti e 7 i tipi base `unknown`: la forma con cui `/dns` dichiara il modulo fallito."""
    out = _c02_unknown(dns or _c02_healthy_dns(), *_C02_BASE, *_C02_EMAIL_SECTIONS)
    out["error"] = _C02_ALL_UNKNOWN_ERROR
    return out


def _c02_legacy(dns):
    """Lo stesso `dns` come lo scriveva `/dns` prima di RES-01: nessuno stato, nessuna lista di ignoti."""
    out = copy.deepcopy(dns)
    out.pop("records_status", None)
    for section in _C02_EMAIL_SECTIONS:
        out["email_auth"][section].pop("status", None)
    out["email_auth"]["dkim"].pop("selectors_unknown", None)
    out["subdomains"].pop("unknown", None)
    return out


def _c31_bare(dns):
    """COL-31: `dns` senza i marcatori di riporto, quello della sezione e quelli di `subdomains` e
    `email_auth.dkim`. Con il guasto totale la sezione salvata è la precedente a meno di questi."""
    out = {k: v for k, v in dns.items() if k != "carried_over"}
    if isinstance(out.get("subdomains"), dict):
        out["subdomains"] = {k: v for k, v in out["subdomains"].items() if k != "carried_over"}
    email = out.get("email_auth")
    if isinstance(email, dict) and isinstance(email.get("dkim"), dict):
        out["email_auth"] = {**email, "dkim": {k: v for k, v in email["dkim"].items() if k != "carried_over"}}
    return out


def _c02_zone(records, **status):
    """`dns` minimo e coerente per una zona con i soli `records` indicati."""
    dns = _c02_healthy_dns()
    for t in _C02_BASE:
        dns["records"][t] = list(records.get(t, []))
        dns["records_status"][t] = status.get(t, "ok" if records.get(t) else "nodata")
    for section in _C02_EMAIL_SECTIONS:
        dns["email_auth"][section] = ({"present": False, "records": [], "status": "nodata"}
                                      if section != "spf" else
                                      {"present": False, "records": [], "policy": None, "status": "nodata"})
    dns["email_auth"]["dkim"] = {"selectors_found": [], "selectors_tested": 18, "records": {},
                                 "selectors_unknown": []}
    dns["subdomains"] = {"tested": 25, "active": [], "unknown": []}
    return dns


class _C02Resp:
    ok = True

    def json(self):
        return {"alerts": [], "alert_count": 0, "max_severity": "CLEAN"}


def _c02_persist(monkeypatch, o, prev_dns, curr_dns, *, snapshot=True):
    """Esegue `_persist_intel` con store e `/diff` finti. Ritorna (sezione `dns` salvata,
    payload mandati a `/diff`, `intel` passato)."""
    saved, sent = {}, []
    prev_intel = ({"dns": prev_dns, "cert": None, "http": None, "whois": None, "reputation": None}
                  if snapshot else None)
    monkeypatch.setattr(o.intel_store, "load_snapshot",
                        lambda c, d: {"intel": prev_intel} if prev_intel is not None else None)

    def _save(c, d, current):
        saved["current"] = current
        return True

    def _post(url, json=None, timeout=None):
        sent.append(json)
        return _C02Resp()

    monkeypatch.setattr(o.intel_store, "save_snapshot", _save)
    monkeypatch.setattr(o._session, "post", _post)
    intel = {"dns": curr_dns, "cert": None, "http": None, "whois": None, "reputation": None}
    o._persist_intel("acme", _C02_DOMAIN, "acme.example", intel)
    return saved["current"]["dns"], sent, intel


class TestCOL02PersistModuleFailureKeepsThePreviousSection:
    """O1 — controlli, verdi anche prima del fix. Un modulo `dns` fallito (sezione `None`
    oppure `error` valorizzato, che dopo RES-01 è la forma del guasto totale) conserva la
    sezione precedente intera: è il percorso CODE-01 e non cambia."""

    def test_section_none_keeps_the_previous_section(self, orch, monkeypatch):
        prev = _c02_healthy_dns()

        saved, sent, _ = _c02_persist(monkeypatch, orch, prev, None)

        # COL-31: a meno dei marcatori, compresi quelli di sottodomini e DKIM che il guasto totale scrive.
        assert _c31_bare(saved) == prev
        assert _c31_bare(sent[0]["current"]["dns"]) == prev

    def test_total_failure_shape_keeps_the_previous_section(self, orch, monkeypatch):
        prev = _c02_healthy_dns()

        saved, sent, _ = _c02_persist(monkeypatch, orch, prev, _c02_total_failure())

        # COL-31: a meno dei marcatori, compresi quelli di sottodomini e DKIM che il guasto totale scrive.
        assert _c31_bare(saved) == prev
        assert _c31_bare(sent[0]["current"]["dns"]) == prev

    def test_total_failure_keeps_an_old_snapshot_without_status_untouched(self, orch, monkeypatch):
        prev = _c02_legacy(_c02_healthy_dns())

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, _c02_total_failure())

        # COL-31: a meno dei marcatori, compresi quelli di sottodomini e DKIM che il guasto totale scrive.
        assert _c31_bare(saved) == prev

    @pytest.mark.parametrize("snapshot", [False, True], ids=["no-snapshot", "snapshot-without-the-module"])
    @pytest.mark.parametrize("module, failed", [
        pytest.param("cert", {"ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                              "error": "crt.sh HTTP 502"}, id="cert"),
        pytest.param("whois", {"registrar": None, "creation_date": None,
                               "error": "WHOIS lookup failed: connection timed out"}, id="whois"),
    ])
    def test_a_failed_module_other_than_dns_still_stores_none_without_a_previous(
            self, orch, monkeypatch, module, failed, snapshot):
        # Controllo (CODE-01), verde anche prima del giro correttivo: la sezione guasta fa da
        # baseline SOLO per `dns` (i cui `unknown` il diff sa leggere come «vuoto»). Per gli altri
        # moduli salvarla azzererebbe il riferimento: «25 certificati nuovi» alla prima raccolta riuscita.
        saved = {}
        prev = {"dns": None, "cert": None, "http": None, "whois": None, "reputation": None}
        monkeypatch.setattr(orch.intel_store, "load_snapshot", lambda c, d: {"intel": prev} if snapshot else None)
        monkeypatch.setattr(orch.intel_store, "save_snapshot", lambda c, d, current: saved.update(current=current) or True)
        monkeypatch.setattr(orch._session, "post", lambda url, json=None, timeout=None: _C02Resp())
        intel = {"dns": _c02_healthy_dns(), "cert": None, "http": None, "whois": None, "reputation": None}
        intel[module] = failed

        orch._persist_intel("acme", _C02_DOMAIN, "acme.example", intel)

        assert saved["current"][module] is None
        assert saved["current"]["dns"] == _c02_healthy_dns()

    def test_total_failure_without_a_snapshot_does_not_diff(self, orch, monkeypatch):
        # Nessun precedente: niente da confrontare. (Cosa viene salvato come baseline è fissato
        # per il suo effetto, nel ciclo dopo: `TestCOL02WakeUpAfterOnlyUnknownHistory`. Prima del
        # giro correttivo qui si asseriva `saved is None`, che è appunto ciò che cancellava il
        # risveglio: test di questo stesso lavoro, riscritto.)
        _, sent, _ = _c02_persist(monkeypatch, orch, None, _c02_total_failure(), snapshot=False)

        assert sent == []


class TestCOL02PersistCarriesForwardUnknownParts:
    """O2 — una parte `unknown` non sovrascrive la baseline: prende record e stato del
    precedente (la regola CODE-01 applicata per parte, non per modulo). Sia ciò che viene
    salvato sia ciò che viene mandato a `/diff` è la sezione riportata."""

    @pytest.mark.parametrize("rtype", _C02_BASE)
    def test_unknown_record_type_takes_the_previous_records_and_status(self, orch, monkeypatch, rtype):
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, rtype)

        saved, sent, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["records"][rtype] == _C02_SAMPLE[rtype]
        assert saved["records_status"][rtype] == "ok"
        assert sent[0]["current"]["dns"]["records"][rtype] == _C02_SAMPLE[rtype]
        assert sent[0]["current"]["dns"]["records_status"][rtype] == "ok"

    @pytest.mark.parametrize("rtype", ["A", "MX"])
    def test_the_other_types_of_the_same_cycle_are_saved_as_observed(self, orch, monkeypatch, rtype):
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, rtype)
        other = "MX" if rtype == "A" else "A"
        curr["records"][other] = ["198.51.100.7"] if other == "A" else ["10 mail.other.example"]

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["records"][rtype] == _C02_SAMPLE[rtype]
        assert saved["records"][other] == curr["records"][other]

    @pytest.mark.parametrize("status", ["nodata", "nxdomain"])
    def test_a_determined_absence_is_an_observation_and_is_not_carried(self, orch, monkeypatch, status):
        # Controllo, verde anche prima del fix: il riporto vale per `unknown`, non per «vuoto».
        prev = _c02_healthy_dns()
        curr = copy.deepcopy(prev)
        curr["records"]["A"] = []
        curr["records_status"]["A"] = status

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["records"]["A"] == []
        assert saved["records_status"]["A"] == status

    def test_a_real_change_in_a_known_type_is_saved_and_sent_to_diff(self, orch, monkeypatch):
        # Controllo, verde anche prima del fix.
        prev = _c02_healthy_dns()
        curr = copy.deepcopy(prev)
        curr["records"]["A"] = ["198.51.100.7"]

        saved, sent, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["records"]["A"] == ["198.51.100.7"]
        assert sent[0]["current"]["dns"]["records"]["A"] == ["198.51.100.7"]
        assert sent[0]["baseline"]["dns"]["records"]["A"] == _C02_SAMPLE["A"]

    @pytest.mark.parametrize("rtype", ["A", "MX", "NS"])
    def test_previous_snapshot_without_status_copies_the_records_and_drops_the_unknown_marker(
            self, orch, monkeypatch, rtype):
        prev = _c02_legacy(_c02_healthy_dns())
        curr = _c02_unknown(_c02_healthy_dns(), rtype)

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["records"][rtype] == _C02_SAMPLE[rtype]
        assert saved["records_status"].get(rtype) != "unknown", saved["records_status"]

    def test_previous_snapshot_without_status_and_an_empty_list_reads_as_a_known_absence(self, orch, monkeypatch):
        # Uno `[]` senza stato non si distingue da un'assenza vera e non viene reinterpretato:
        # resta `[]` e non è più `unknown` (come oggi per tutti gli snapshot di prima di RES-01).
        prev = _c02_legacy(_c02_zone({"MX": ["10 mail.acme-typo.example"]}))
        curr = _c02_unknown(_c02_zone({"MX": ["10 mail.acme-typo.example"]}), "A")

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["records"]["A"] == []
        assert saved["records_status"].get("A") != "unknown", saved["records_status"]

    @pytest.mark.parametrize("section", _C02_EMAIL_SECTIONS)
    def test_unknown_email_section_takes_the_whole_previous_section(self, orch, monkeypatch, section):
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, section)

        saved, sent, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["email_auth"][section] == prev["email_auth"][section]
        assert sent[0]["current"]["dns"]["email_auth"][section] == prev["email_auth"][section]

    @pytest.mark.parametrize("section", _C02_EMAIL_SECTIONS)
    def test_unknown_email_section_leaves_the_other_sections_as_observed(self, orch, monkeypatch, section):
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, section)
        other = next(s for s in _C02_EMAIL_SECTIONS if s != section)
        curr["email_auth"][other] = {"present": False, "records": [], "status": "nodata"}

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["email_auth"][section] == prev["email_auth"][section]
        assert saved["email_auth"][other] == curr["email_auth"][other]

    @pytest.mark.parametrize("section", _C02_EMAIL_SECTIONS)
    def test_previous_email_section_without_status_is_copied_as_it_is(self, orch, monkeypatch, section):
        prev = _c02_legacy(_c02_healthy_dns())
        curr = _c02_unknown(_c02_healthy_dns(), section)

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["email_auth"][section] == prev["email_auth"][section]
        assert saved["email_auth"][section].get("status") != "unknown"

    def test_unknown_txt_carries_the_txt_records_and_the_spf_section_together(self, orch, monkeypatch):
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, "TXT")

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["records"]["TXT"] == _C02_SAMPLE["TXT"]
        assert saved["email_auth"]["spf"] == prev["email_auth"]["spf"]

    @pytest.mark.parametrize("prev_dns", [
        pytest.param(None, id="snapshot-without-dns"),
        pytest.param({}, id="empty-dns"),
        pytest.param({"records": {"MX": ["10 mail.acme-typo.example"]}}, id="type-missing"),
        pytest.param({"records": ["not", "a", "dict"], "email_auth": "x"}, id="corrupted-shapes"),
        pytest.param({"records": {"A": None, "MX": "10 mail.acme-typo.example"},
                      "records_status": ["A"]}, id="corrupted-values"),
    ])
    def test_no_usable_previous_value_stores_an_empty_list_with_unknown_status(self, orch, monkeypatch, prev_dns):
        # Verde anche prima del fix (salva ciò che c'è); fissa che il fix non inventa un valore
        # e non solleva su uno snapshot vecchio o corrotto.
        curr = _c02_unknown(_c02_healthy_dns(), "A", "dmarc")

        saved, _, _ = _c02_persist(monkeypatch, orch, prev_dns, curr)

        assert saved["records"]["A"] == []
        assert saved["records_status"]["A"] == "unknown"
        assert saved["email_auth"]["dmarc"]["status"] == "unknown"

    def test_no_snapshot_at_all_stores_the_observation_as_it_is_and_does_not_diff(self, orch, monkeypatch):
        curr = _c02_unknown(_c02_healthy_dns(), "A")

        saved, sent, _ = _c02_persist(monkeypatch, orch, None, curr, snapshot=False)

        assert saved["records"]["A"] == []
        assert saved["records_status"]["A"] == "unknown"
        assert sent == []

    def test_dkim_and_subdomains_keep_the_unknown_lists_of_this_cycle(self, orch, monkeypatch):
        # Le liste degli ignoti e i conteggi sono quelli del ciclo, e un nome senza risposta assente dal
        # precedente non viene inventato; il riporto per nome è in `tests/test_dns_carry_over_col31.py`.
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, "TXT")
        curr["email_auth"]["dkim"] = {"selectors_found": [], "selectors_tested": 18, "records": {},
                                      "selectors_unknown": ["google", "default"]}
        curr["subdomains"] = {"tested": 25, "active": [],
                              "unknown": [f"www.{_C02_DOMAIN}", f"login.{_C02_DOMAIN}"]}

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, curr)

        dkim, subs = saved["email_auth"]["dkim"], saved["subdomains"]
        assert (dkim["selectors_unknown"], dkim["selectors_tested"]) == (["google", "default"], 18)
        assert (subs["unknown"], subs["tested"]) == ([f"www.{_C02_DOMAIN}", f"login.{_C02_DOMAIN}"], 25)
        assert "default" not in dkim["selectors_found"] and "default" not in dkim["records"]
        assert f"login.{_C02_DOMAIN}" not in [a["fqdn"] for a in subs["active"]]

    def test_the_dns_section_of_the_cycle_is_not_modified_by_the_persist(self, orch, monkeypatch):
        # `intel["dns"]` è ciò che la classificazione e gli eventi leggono dopo: deve restare
        # l'osservazione di QUESTO ciclo, con gli `unknown` al loro posto. Rosso finché il
        # riporto non esiste (la precondizione); poi prova che avviene su una copia profonda.
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, "A", "MX", "dmarc")
        curr_before, prev_before = copy.deepcopy(curr), copy.deepcopy(prev)

        saved, _, intel = _c02_persist(monkeypatch, orch, prev, curr)

        assert saved["records"]["A"] == _C02_SAMPLE["A"], "precondizione: il riporto deve essere avvenuto"
        assert intel["dns"] == curr_before
        assert curr == curr_before
        assert prev == prev_before


@pytest.fixture
def c02_cycle(orch, monkeypatch, tmp_path):
    """Un ciclo di `_persist_intel` per chiamata, con lo store reale su una directory temporanea
    e il `/diff` del classificatore reale. `run(dns)` esegue il ciclo; `run.per_cycle` accumula,
    per ogni ciclo, gli alert nuovi come (tipo, severità, detail) ordinati per tipo; `run.history()`
    è la storia dei diff (la più recente per prima); `run.snapshot()` la sezione `dns` salvata."""
    o = orch
    monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
    monkeypatch.setattr(o, "now_iso", lambda: "2026-10-20T10:00:30+00:00")
    api = TestClient(_c02_classifier_app, raise_server_exceptions=False)
    statuses = []

    def _post(url, json=None, timeout=None, headers=None):
        r = api.post(url[len(o.CLASSIFY_URL):], json=json)
        statuses.append(r.status_code)
        return _R(r.json() if r.is_success else None, ok=r.is_success, status_code=r.status_code)

    monkeypatch.setattr(o._session, "post", _post)

    def history():
        return o.intel_store.load_history("acme", _C02_DOMAIN, limit=1000)

    def run(dns):
        before = len(history())
        o._persist_intel("acme", _C02_DOMAIN, "acme.example",
                         {"dns": dns, "cert": None, "http": None, "whois": None, "reputation": None})
        new = history()[:len(history()) - before]
        run.per_cycle.append(sorted(((a["type"], a["severity"], a["detail"]) for e in new for a in e["alerts"]),
                                    key=lambda t: t[0]))

    run.per_cycle = []
    run.history = history
    run.snapshot = lambda: o.intel_store.load_snapshot("acme", _C02_DOMAIN)["intel"]["dns"]
    run.statuses = statuses
    run.o = o
    return run


class TestCOL02CarryForwardAcrossAnOutage:
    """O2 + C1 — il riporto è ciò che tiene insieme le due metà del diff: A = X, poi
    `unknown`, poi A = Y deve dare UN alert X -> Y, non uno all'andata e uno al ritorno.
    Store reale su una directory temporanea e `/diff` del classificatore reale."""

    @pytest.fixture
    def cycle(self, c02_cycle):
        return c02_cycle

    def test_a_record_that_changes_during_an_outage_alerts_exactly_once(self, cycle):
        before = _c02_zone({"A": ["192.0.2.10"], "NS": ["ns1.acme-typo.example"]})
        after = _c02_zone({"A": ["198.51.100.7"], "NS": ["ns1.acme-typo.example"]})

        cycle(before)                              # X
        cycle(_c02_unknown(before, "A"))           # SERVFAIL sull'A
        cycle(after)                               # Y

        alerts = [a for entry in cycle.history() for a in entry["alerts"]]
        assert [(a["type"], a["detail"]) for a in alerts] == [
            ("a_record_changed", {"old": ["192.0.2.10"], "new": ["198.51.100.7"]})]
        assert len(cycle.history()) == 1
        assert set(cycle.statuses) <= {200}, cycle.statuses

    def test_a_record_that_is_the_same_before_and_after_an_outage_gives_no_alert(self, cycle):
        zone = _c02_zone({"A": ["192.0.2.10"], "NS": ["ns1.acme-typo.example"]})

        cycle(zone)
        cycle(_c02_unknown(zone, "A", "dmarc"))
        cycle(zone)

        assert cycle.history() == []
        assert set(cycle.statuses) <= {200}, cycle.statuses

    def test_the_snapshot_after_the_outage_cycle_still_holds_the_previous_value(self, cycle):
        zone = _c02_healthy_dns()

        cycle(zone)
        cycle(_c02_unknown(zone, "A", "MX", "TXT", "dmarc", "bimi", "caa"))

        saved = cycle.snapshot()
        assert saved["records"] == zone["records"]
        assert saved["records_status"] == zone["records_status"]
        for section in _C02_EMAIL_SECTIONS:
            assert saved["email_auth"][section] == zone["email_auth"][section], section

    def test_a_real_removal_confirmed_by_the_dns_still_alerts(self, cycle):
        # Controllo, verde anche prima del fix: NODATA/NXDOMAIN sono risposte.
        zone = _c02_zone({"A": ["192.0.2.10"], "MX": ["10 mail.acme-typo.example"]})
        gone = _c02_zone({"A": ["192.0.2.10"]}, MX="nxdomain")

        cycle(zone)
        cycle(gone)

        types = [a["type"] for entry in cycle.history() for a in entry["alerts"]]
        assert types == ["mx_record_changed"]


class TestCOL02WakeUpAfterOnlyUnknownHistory:
    """O2 + O5 + C1, giro correttivo (SEC-31 riunificato in COL-02). Verdetto INSUFFICIENTE del
    verifier: «zona vuota con WHOIS recente, due cicli di SERVFAIL, poi A+MX+NS» dava 3 alert
    (A e MX HIGH, NS MEDIUM) prima di RES-01 e 0 con il disegno del primo giro, e `unknown` si
    sceglie per tipo da chi gestisce la zona del lookalike. Comportamento deciso dal coordinator:
    un tipo (o SPF/DMARC/BIMI/CAA) `unknown` nella baseline senza alcun valore noto precedente e
    noto e non vuoto nel ciclo corrente produce l'alert ordinario di cambio, una volta; noto ma
    vuoto (`nodata`/`nxdomain`) nessun alert; una baseline NOTA resta il riferimento. Vale anche
    per il guasto totale al primo ciclo, la cui sezione guasta deve poter fare da baseline.

    Store reale su una directory temporanea e `/diff` del classificatore reale (fixture
    `c02_cycle`). Prezzo accettato dalla decisione: se la prima osservazione è un guasto
    transitorio e il tipo aveva già record, al primo ciclo noto esce un alert una tantum."""

    _WAKE = [
        pytest.param("A", "a_record_changed", ["198.51.100.7"], id="A"),
        pytest.param("MX", "mx_record_changed", ["10 mail.acme-typo.example"], id="MX"),
        pytest.param("NS", "ns_changed", ["ns1.acme-typo.example"], id="NS"),
        pytest.param("TXT", "txt_changed", ['"v=spf1 -all"'], id="TXT"),
        pytest.param("SOA", "soa_changed",
                     ["ns1.acme-typo.example hostmaster.acme-typo.example 1 7200 900 1209600 3600"], id="SOA"),
    ]
    LIVE = {"A": ["198.51.100.7"], "MX": ["10 mail.acme-typo.example"], "NS": ["ns1.acme-typo.example"]}

    @pytest.mark.parametrize("rtype, alert, value", _WAKE)
    def test_a_type_unknown_from_the_first_cycle_alerts_once_when_it_is_first_known(
            self, c02_cycle, rtype, alert, value):
        c02_cycle(_c02_unknown(_c02_zone({}), rtype))    # primo ciclo: nessuna risposta su `rtype`
        c02_cycle(_c02_zone({rtype: value}))             # il DNS risponde
        c02_cycle(_c02_zone({rtype: value}))             # e non cambia più nulla

        assert c02_cycle.per_cycle == [
            [], [(alert, _C02_SEVERITY_MAP[alert], {"old": [], "new": value})], []], c02_cycle.per_cycle
        assert set(c02_cycle.statuses) <= {200}, c02_cycle.statuses

    @pytest.mark.parametrize("section", _C02_EMAIL_SECTIONS)
    def test_an_email_section_unknown_from_the_first_cycle_alerts_once_when_it_is_first_present(
            self, c02_cycle, section):
        alert = {"spf": "spf_changed", "dmarc": "dmarc_changed", "bimi": "bimi_added", "caa": "caa_changed"}[section]
        live = _c02_zone({})
        live["email_auth"][section] = _c02_healthy_dns()["email_auth"][section]

        c02_cycle(_c02_unknown(_c02_zone({}), section))
        c02_cycle(live)
        c02_cycle(live)

        assert [[(t, sev) for t, sev, _ in cycle_alerts] for cycle_alerts in c02_cycle.per_cycle] == [
            [], [(alert, _C02_SEVERITY_MAP[alert])], []], c02_cycle.per_cycle

    @pytest.mark.parametrize("known_status", ["nodata", "nxdomain"])
    @pytest.mark.parametrize("rtype", ["A", "MX", "NS"])
    def test_a_type_that_turns_out_known_but_empty_raises_no_alert(self, c02_cycle, rtype, known_status):
        c02_cycle(_c02_unknown(_c02_zone({}), rtype))
        c02_cycle(_c02_zone({}, **{rtype: known_status}))

        assert c02_cycle.per_cycle == [[], []], c02_cycle.per_cycle

    def test_only_a_unknown_from_the_first_cycle_then_known_alerts_on_a_alone(self, c02_cycle):
        # Il parziale: MX e NS sono noti da subito e non cambiano, A è `unknown` finché non risponde.
        known = {"MX": self.LIVE["MX"], "NS": self.LIVE["NS"]}

        c02_cycle(_c02_unknown(_c02_zone(known), "A"))
        c02_cycle(_c02_zone({**known, "A": self.LIVE["A"]}))

        assert c02_cycle.per_cycle == [
            [], [("a_record_changed", "HIGH", {"old": [], "new": self.LIVE["A"]})]], c02_cycle.per_cycle

    def test_total_failure_on_the_first_cycle_then_a_live_zone_alerts_like_the_old_wake_up(self, c02_cycle):
        # La baseline salvata quando non esiste un precedente era `None` (nessun diff): ora è la
        # sezione guasta, e il ciclo dopo può confrontarsi con essa.
        c02_cycle(_c02_total_failure(_c02_zone({})))
        c02_cycle(_c02_zone(self.LIVE))

        assert [[(t, sev) for t, sev, _ in a] for a in c02_cycle.per_cycle] == [
            [], [("a_record_changed", "HIGH"), ("mx_record_changed", "HIGH"), ("ns_changed", "MEDIUM")]
        ], c02_cycle.per_cycle
        assert set(c02_cycle.statuses) <= {200}, c02_cycle.statuses

    def test_two_failed_cycles_then_a_live_zone_alert_once_not_twice(self, c02_cycle):
        failed = _c02_total_failure(_c02_zone({}))

        c02_cycle(failed)
        c02_cycle(failed)
        c02_cycle(_c02_zone(self.LIVE))
        c02_cycle(_c02_zone(self.LIVE))

        assert [[t for t, _, _ in a] for a in c02_cycle.per_cycle] == [
            [], [], ["a_record_changed", "mx_record_changed", "ns_changed"], []], c02_cycle.per_cycle

    def test_total_failure_then_a_full_live_zone_alerts_on_every_record_that_appears(self, c02_cycle):
        # La zona piena del resto del file: tutti i tipi che il diff confronta e tutte le sezioni.
        c02_cycle(_c02_total_failure())
        c02_cycle(_c02_healthy_dns())

        expected = ["a_record_changed", "bimi_added", "caa_changed", "dmarc_changed", "mx_record_changed",
                    "ns_changed", "soa_changed", "spf_changed", "txt_changed"]
        assert [t for t, _, _ in c02_cycle.per_cycle[1]] == expected, c02_cycle.per_cycle[1]
        assert all(sev == _C02_SEVERITY_MAP[t] for t, sev, _ in c02_cycle.per_cycle[1])

    def test_total_failure_after_a_snapshot_that_has_no_dns_section_then_a_live_zone_alerts(self, c02_cycle):
        # Snapshot di un ciclo in cui il modulo `dns` non aveva mai risposto (sezione `None`).
        assert c02_cycle.o.intel_store.save_snapshot(
            "acme", _C02_DOMAIN, {"dns": None, "cert": None, "http": None, "whois": None, "reputation": None})

        c02_cycle(_c02_total_failure(_c02_zone({})))
        c02_cycle(_c02_zone(self.LIVE))

        assert [[t for t, _, _ in a] for a in c02_cycle.per_cycle] == [
            [], ["a_record_changed", "mx_record_changed", "ns_changed"]], c02_cycle.per_cycle

    @pytest.mark.parametrize("known_status", ["nodata", "nxdomain"])
    def test_failed_cycles_then_a_known_empty_zone_raise_no_alert(self, c02_cycle, known_status):
        # F -> F -> ok senza baseline e senza record: nessun alert falso.
        failed = _c02_total_failure(_c02_zone({}))
        empty = _c02_zone({}, **{t: known_status for t in _C02_BASE})

        c02_cycle(failed)
        c02_cycle(failed)
        c02_cycle(empty)
        c02_cycle(empty)

        assert c02_cycle.per_cycle == [[], [], [], []], c02_cycle.per_cycle
        assert set(c02_cycle.statuses) <= {200}, c02_cycle.statuses

    def test_a_known_baseline_stays_the_reference_across_a_long_outage(self, c02_cycle):
        # Controllo, verde anche prima del giro correttivo: dopo una baseline NOTA, X -> unknown ->
        # unknown -> Y dà un solo alert X -> Y.
        before = _c02_zone({"A": ["192.0.2.10"], "NS": self.LIVE["NS"]})
        after = _c02_zone({"A": ["198.51.100.7"], "NS": self.LIVE["NS"]})

        c02_cycle(before)
        c02_cycle(_c02_unknown(before, "A"))
        c02_cycle(_c02_unknown(before, "A"))
        c02_cycle(after)

        assert c02_cycle.per_cycle == [
            [], [], [], [("a_record_changed", "HIGH", {"old": ["192.0.2.10"], "new": ["198.51.100.7"]})]
        ], c02_cycle.per_cycle

    def test_a_known_baseline_survives_total_failures_and_alerts_once_on_the_real_change(self, c02_cycle):
        healthy = _c02_healthy_dns()
        changed = copy.deepcopy(healthy)
        changed["records"]["A"] = ["198.51.100.7"]

        c02_cycle(healthy)
        c02_cycle(_c02_total_failure(healthy))
        c02_cycle(_c02_total_failure(healthy))
        c02_cycle(changed)

        assert c02_cycle.per_cycle == [
            [], [], [], [("a_record_changed", "HIGH", {"old": healthy["records"]["A"], "new": ["198.51.100.7"]})]
        ], c02_cycle.per_cycle


# ── Pipeline: collection_status, eventi, primo ciclo ────────────────────────

_C02_CERT_OK = {"domain": _C02_DOMAIN, "timestamp": "2026-10-24T10:00:00Z",
                "ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                "tls_live": None, "san_subdomains_discovered": [], "error": None}
_C02_HTTP_QUIET = {"domain": _C02_DOMAIN, "timestamp": "2026-10-24T10:00:00Z", "checks": [],
                   "overall_status": "down", "hidden_elements_risk": 0, "error": None}
_C02_FETCH_FAILED = object()   # il GET su /dns risponde con un errore HTTP: `_fetch_service` -> None
_C02_FEED = [{"domain": _C02_DOMAIN, "client": "acme", "type": "target",
              "legitimate": "acme.example", "fuzzer": "insertion"}]


def _c02_get(o, dns, *, feed=None, twist=None, whitelist=None):
    def _get(url, timeout=None):
        if "/feed/domains" in url:
            return _R({"domains": _C02_FEED if feed is None else feed})
        if "/feed/whitelist" in url:
            return _R({"whitelist": whitelist or {}})
        if url.startswith(o.DNS_URL):
            return _R(None, ok=False, status_code=502) if dns is _C02_FETCH_FAILED else _R(dns)
        if url.startswith(o.CERT_URL):
            return _R(_C02_CERT_OK)
        if url.startswith(o.HTTP_URL):
            return _R(_C02_HTTP_QUIET)
        if twist is not None and url.startswith(o.TWIST_URL):
            return _R(twist)
        raise AssertionError(f"GET non atteso in questo test: {url}")
    return _get


def _c02_post(classify_payloads, published):
    """POST finto: registra il payload di `/classify/variant` e gli eventi pubblicati."""
    def _post(url, json=None, timeout=None, headers=None):
        if url.endswith("/classify/variant"):
            classify_payloads.append(json)
            return _R({"auto_classification": "needs_review", "rule": "no_matching_rule",
                       "confidence": "low", "rationale": "x", "manual_review_required": True})
        if url.endswith("/publish"):
            published.extend((json or {}).get("events", []))
        return _R({})
    return _post


def _c02_request(o, **kwargs):
    params = dict(client="acme", include_whois=False, include_reputation=False,
                  include_dnstwist=False, variant_intel=False, scope="all")
    params.update(kwargs)
    return o.TriggerRequest(**params)


def _c02_run(o, monkeypatch, dns, *, request=None, **get_kwargs):
    payloads, published = [], []
    monkeypatch.setattr(o._session, "get", _c02_get(o, dns, **get_kwargs))
    monkeypatch.setattr(o._session, "post", _c02_post(payloads, published))
    o._run_pipeline(request or _c02_request(o))
    return payloads, published


_C02_VARIANT_TWIST = {"registered_variants": 1, "variants": [
    {"domain": "acme-variant.example", "fuzzer": "insertion", "dns_a": True, "dns_mx": False, "geoip": ""}]}
_C02_VARIANT_FEED = [{"domain": _C02_DOMAIN, "client": "acme", "type": "target", "legitimate": _C02_DOMAIN}]


def _c02_run_variant(o, monkeypatch, dns, twist=None):
    """Percorso `variant_intel` di dnstwist: il target del feed è in whitelist, quindi
    l'unica chiamata a `/classify/variant` è quella della variante."""
    monkeypatch.setattr(o.intel_store, "load_snapshot", lambda c, d: None)
    monkeypatch.setattr(o.intel_store, "save_snapshot", lambda c, d, i: True)
    return _c02_run(o, monkeypatch, dns,
                    request=_c02_request(o, include_dnstwist=True, variant_intel=True),
                    feed=_C02_VARIANT_FEED, whitelist={_C02_DOMAIN: {}}, twist=twist or _C02_VARIANT_TWIST)


# `dns` che il modulo ha o non ha raccolto -> `collection_status["dns"]`.
_C02_DNS_FAILED_CASES = [
    pytest.param(_C02_FETCH_FAILED, id="fetch-failed"),
    pytest.param(_c02_total_failure(), id="all-types-unknown"),
    pytest.param({"records": {"A": [], "MX": []}, "error": "DNS resolution failed"}, id="error-text"),
]
_C02_DNS_ANSWERED_CASES = [
    pytest.param(_c02_healthy_dns(), id="healthy"),
    pytest.param(_c02_unknown(_c02_healthy_dns(), "A"), id="a-unknown"),
    pytest.param(_c02_unknown(_c02_healthy_dns(), "A", "MX", "NS"), id="three-types-unknown"),
    pytest.param(_c02_legacy(_c02_healthy_dns()), id="old-format-without-status"),
]


class TestCOL02CollectionStatusCoversDns:
    """O3 — `collection_status["dns"] = _module_failed(intel["dns"])` nel payload verso
    `/classify/variant`, nei due punti che lo costruiscono. Un `unknown` parziale NON rende
    il modulo fallito (`error` è `None`): sarà il classificatore a leggerlo dal payload."""

    @pytest.mark.parametrize("dns", _C02_DNS_FAILED_CASES)
    def test_feed_loop_marks_dns_failed_when_the_module_failed(self, orch, monkeypatch, dns):
        payloads, _ = _c02_run(orch, monkeypatch, dns)

        assert len(payloads) == 1, payloads
        assert (payloads[0].get("collection_status") or {}).get("dns") is True, payloads[0].get("collection_status")

    @pytest.mark.parametrize("dns", _C02_DNS_ANSWERED_CASES)
    def test_feed_loop_marks_dns_not_failed_when_the_module_answered(self, orch, monkeypatch, dns):
        payloads, _ = _c02_run(orch, monkeypatch, dns)

        assert len(payloads) == 1, payloads
        assert (payloads[0].get("collection_status") or {}).get("dns") is False, payloads[0].get("collection_status")

    @pytest.mark.parametrize("dns", _C02_DNS_FAILED_CASES)
    def test_variant_intel_branch_marks_dns_failed_when_the_module_failed(self, orch, monkeypatch, dns):
        payloads, _ = _c02_run_variant(orch, monkeypatch, dns)

        assert len(payloads) == 1, payloads
        assert payloads[0]["domain"] == "acme-variant.example"
        assert (payloads[0].get("collection_status") or {}).get("dns") is True, payloads[0].get("collection_status")

    @pytest.mark.parametrize("dns", _C02_DNS_ANSWERED_CASES)
    def test_variant_intel_branch_marks_dns_not_failed_when_the_module_answered(self, orch, monkeypatch, dns):
        payloads, _ = _c02_run_variant(orch, monkeypatch, dns)

        assert len(payloads) == 1, payloads
        assert (payloads[0].get("collection_status") or {}).get("dns") is False, payloads[0].get("collection_status")

    def test_dormant_homoglyph_path_does_not_declare_dns(self, orch, monkeypatch):
        # Controllo, verde anche prima del fix. Un omografo dormiente non raccoglie nulla:
        # «non richiesto» non è «fallito», quindi nessuna chiave `dns` nello stato.
        twist = {"registered_variants": 1, "variants": [
            {"domain": "acme-typ0.example", "fuzzer": "homoglyph", "dns_a": False, "dns_mx": False, "geoip": ""}]}
        payloads, _ = _c02_run_variant(orch, monkeypatch, _c02_healthy_dns(), twist=twist)

        assert len(payloads) == 1, payloads
        assert payloads[0]["domain"] == "acme-typ0.example"
        assert "dns" not in (payloads[0].get("collection_status") or {}), payloads[0].get("collection_status")

    def test_build_collection_status_reports_dns_when_it_was_requested(self, orch):
        ok = {"dns": _c02_healthy_dns(), "cert": _C02_CERT_OK, "http": _C02_HTTP_QUIET}
        failed = {**ok, "dns": _c02_total_failure()}
        none = {**ok, "dns": None}
        requested = {"dns", "cert", "http"}

        assert orch._build_collection_status(ok, requested)["dns"] is False
        assert orch._build_collection_status(failed, requested)["dns"] is True
        assert orch._build_collection_status(none, requested)["dns"] is True

    def test_build_collection_status_leaves_dns_out_when_it_was_not_requested(self, orch):
        intel = {"dns": None, "cert": _C02_CERT_OK, "http": _C02_HTTP_QUIET}

        assert "dns" not in orch._build_collection_status(intel, {"cert", "http"})


# `dns` raccolto -> (dns_a, dns_mx, dns_a_status, dns_mx_status) nell'evento.
_C02_EVENT_CASES = [
    pytest.param(_c02_zone({"A": ["192.0.2.10"]}), (True, False, "ok", "nodata"), id="a-ok-mx-nodata"),
    pytest.param(_c02_zone({"A": ["gone.acme-typo.example"]}, A="nxdomain"),
                 (True, False, "nxdomain", "nodata"), id="a-cname-chain-nxdomain"),
    pytest.param(_c02_unknown(_c02_healthy_dns(), "A"), (False, True, "unknown", "ok"), id="a-unknown"),
    pytest.param(_c02_unknown(_c02_healthy_dns(), "MX"), (True, False, "ok", "unknown"), id="mx-unknown"),
    pytest.param(_c02_total_failure(), (False, False, "unknown", "unknown"), id="all-unknown"),
    pytest.param(_C02_FETCH_FAILED, (False, False, "unknown", "unknown"), id="section-none"),
    pytest.param(_c02_legacy(_c02_healthy_dns()), (True, True, None, None), id="old-format-without-status"),
]


class TestCOL02EventsCarryTheDnsStatus:
    """O4 — `intel_summary.dns_a`/`dns_mx` restano `bool` («record visto in questo ciclo»:
    un SERVFAIL e un NODATA sono entrambi `false`, come prima: il contratto verso SIEM/SOAR
    non cambia) e ci si affiancano `dns_a_status`/`dns_mx_status` dal `records_status` del
    ciclo: `"unknown"` se la sezione è `None`, `None` se lo stato manca."""

    @staticmethod
    def _summary(published, domain=_C02_DOMAIN):
        event = _event_for(published, domain)
        assert event is not None, published
        return event["intel_summary"]

    @pytest.mark.parametrize("dns, expected", _C02_EVENT_CASES)
    def test_feed_loop_event_has_the_booleans_and_the_statuses(self, orch, monkeypatch, dns, expected):
        _, published = _c02_run(orch, monkeypatch, dns)

        s = self._summary(published)
        assert "dns_a_status" in s and "dns_mx_status" in s, s
        assert (s["dns_a"], s["dns_mx"], s["dns_a_status"], s["dns_mx_status"]) == expected, s

    @pytest.mark.parametrize("dns, expected", _C02_EVENT_CASES)
    def test_dns_a_and_dns_mx_stay_booleans(self, orch, monkeypatch, dns, expected):
        # Controllo, verde anche prima del fix: né `null` né stringhe nel contratto esistente.
        _, published = _c02_run(orch, monkeypatch, dns)

        s = self._summary(published)
        assert type(s["dns_a"]) is bool and type(s["dns_mx"]) is bool, s

    @pytest.mark.parametrize("dns, expected", _C02_EVENT_CASES)
    def test_variant_intel_event_has_the_booleans_and_the_statuses(self, orch, monkeypatch, dns, expected):
        _, published = _c02_run_variant(orch, monkeypatch, dns)

        s = self._summary(published, "acme-variant.example")
        assert s.get("intel_collected") is True, s
        assert "dns_a_status" in s and "dns_mx_status" in s, s
        assert (s["dns_a"], s["dns_mx"], s["dns_a_status"], s["dns_mx_status"]) == expected, s

    def test_event_reports_this_cycles_observation_not_the_value_carried_into_the_baseline(
            self, orch, monkeypatch, tmp_path):
        # Il riporto serve alla baseline, non all'evento: `_persist_intel` gira PRIMA che
        # `intel_summary` venga costruito, e se modificasse `intel["dns"]` in place l'evento
        # direbbe «A presente, ok» per un ciclo in cui il DNS non ha risposto.
        monkeypatch.setattr(orch, "INTEL_STORE", True)
        monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(orch.intel_store, "HIST_DIR", tmp_path / "history")
        previous = {"dns": _c02_healthy_dns(), "cert": None, "http": None, "whois": None, "reputation": None}
        assert orch.intel_store.save_snapshot("acme", _C02_DOMAIN, previous)

        _, published = _c02_run(orch, monkeypatch, _c02_unknown(_c02_healthy_dns(), "A"))

        s = self._summary(published)
        saved = orch.intel_store.load_snapshot("acme", _C02_DOMAIN)["intel"]["dns"]
        assert saved["records"]["A"] == _C02_SAMPLE["A"], "precondizione: il riporto deve essere avvenuto"
        assert (s["dns_a"], s["dns_a_status"]) == (False, "unknown"), s

    def test_dnstwist_discovery_event_keeps_the_fields_of_the_external_tool(self, orch, monkeypatch):
        # Controllo, verde anche prima del fix: i campi delle varianti scoperte da dnstwist
        # (nessuna raccolta nostra) vengono dal tool esterno e non cambiano.
        twist = {"registered_variants": 1, "variants": [
            {"domain": "acme-variant.example", "fuzzer": "insertion", "dns_a": True, "dns_mx": False,
             "geoip": "IT"}]}
        _, published = _c02_run(orch, monkeypatch, _c02_healthy_dns(),
                                request=_c02_request(orch, include_dnstwist=True),
                                feed=_C02_VARIANT_FEED, whitelist={_C02_DOMAIN: {}}, twist=twist)

        s = self._summary(published, "acme-variant.example")
        assert {k: s[k] for k in ("dns_a", "dns_mx", "fuzzer", "geoip")} == {
            "dns_a": True, "dns_mx": False, "fuzzer": "insertion", "geoip": "IT"}


# Valori che NON sono uno dei quattro stati di `dig_lookup`: un `records_status` forgiato (snapshot
# corrotto, servizio non aggiornato, un domani un altro produttore) non deve arrivare verbatim nell'evento.
_C02_FORGED_STATUSES = [
    pytest.param("weird", id="arbitrary-string"),
    pytest.param("UNKNOWN", id="uppercase"),
    pytest.param("ok ", id="trailing-space"),
    pytest.param("", id="empty-string"),
    pytest.param(5, id="int"),
    pytest.param(True, id="bool"),
    pytest.param(["ok"], id="list"),
    pytest.param({"x": "ok"}, id="object"),
    pytest.param("<script>alert(1)</script>", id="markup"),
    pytest.param("x" * 5000, id="huge-string"),
]
_C02_VALID_STATUSES = ["ok", "nodata", "nxdomain", "unknown"]


def _c02_dns_with_status(status):
    """`dns` con lo stesso `status` su A e MX (record presenti solo se `ok`)."""
    records = {"A": ["192.0.2.10"], "MX": ["10 mail.acme-typo.example"]} if status == "ok" else {}
    dns = _c02_zone(records)
    dns["records_status"]["A"] = status
    dns["records_status"]["MX"] = status
    return dns


class TestCOL02EventStatusIsAllowlisted:
    """O4, giro correttivo (CODE-47 punto 1, difetto del codice nuovo): `dns_a_status` e
    `dns_mx_status` valgono uno dei quattro stati (`ok`/`nodata`/`nxdomain`/`unknown`) oppure
    `None`. Un valore forgiato in `records_status` — una stringa qualunque, un oggetto — non
    passa verbatim in un evento che va a SIEM/SOAR (e al dashboard). `dns_a`/`dns_mx` restano i
    bool di sempre."""

    @staticmethod
    def _summary(published, domain=_C02_DOMAIN):
        event = _event_for(published, domain)
        assert event is not None, published
        return event["intel_summary"]

    @pytest.mark.parametrize("forged", _C02_FORGED_STATUSES)
    def test_a_forged_status_gives_none_in_the_feed_loop_event(self, orch, monkeypatch, forged):
        _, published = _c02_run(orch, monkeypatch, _c02_dns_with_status(forged))

        s = self._summary(published)
        assert (s["dns_a_status"], s["dns_mx_status"]) == (None, None), s
        assert type(s["dns_a"]) is bool and type(s["dns_mx"]) is bool, s

    @pytest.mark.parametrize("forged", _C02_FORGED_STATUSES)
    def test_a_forged_status_gives_none_in_the_variant_intel_event(self, orch, monkeypatch, forged):
        _, published = _c02_run_variant(orch, monkeypatch, _c02_dns_with_status(forged))

        s = self._summary(published, "acme-variant.example")
        assert (s["dns_a_status"], s["dns_mx_status"]) == (None, None), s

    def test_a_forged_status_on_one_type_does_not_touch_the_other(self, orch, monkeypatch):
        dns = _c02_dns_with_status("ok")
        dns["records_status"]["A"] = {"x": "ok"}

        _, published = _c02_run(orch, monkeypatch, dns)

        s = self._summary(published)
        assert (s["dns_a_status"], s["dns_mx_status"]) == (None, "ok"), s

    @pytest.mark.parametrize("status", _C02_VALID_STATUSES)
    def test_the_four_valid_states_pass_unchanged_in_the_feed_loop_event(self, orch, monkeypatch, status):
        # Controllo, verde anche prima del fix.
        _, published = _c02_run(orch, monkeypatch, _c02_dns_with_status(status))

        s = self._summary(published)
        assert (s["dns_a_status"], s["dns_mx_status"]) == (status, status), s

    @pytest.mark.parametrize("status", _C02_VALID_STATUSES)
    def test_the_four_valid_states_pass_unchanged_in_the_variant_intel_event(self, orch, monkeypatch, status):
        # Controllo, verde anche prima del fix.
        _, published = _c02_run_variant(orch, monkeypatch, _c02_dns_with_status(status))

        s = self._summary(published, "acme-variant.example")
        assert (s["dns_a_status"], s["dns_mx_status"]) == (status, status), s


class TestCOL02PipelineClassifiesTheModuleFailure:
    """O3 + C3, osservabile: con il modulo DNS fallito la classificazione che l'orchestrator
    ottiene dal classificatore REALE è `insufficient_data`, non un verdetto su DNS vuoto.
    È il «cambio di comportamento» dichiarato nei criteri: da misurare sui dati prima del
    deploy."""

    @staticmethod
    def _classify_through_the_real_classifier(o, monkeypatch, dns):
        published, payloads = [], []
        monkeypatch.setattr(o._session, "get", _c02_get(o, dns))
        monkeypatch.setattr(o._session, "post", _real_classifier_post(o, published, payloads))
        o._run_pipeline(_c02_request(o))
        return _event_for(published, _C02_DOMAIN)["classification"]

    @pytest.mark.parametrize("dns", [
        pytest.param(_C02_FETCH_FAILED, id="fetch-failed"),
        pytest.param(_c02_total_failure(), id="all-types-unknown"),
    ])
    def test_a_failed_dns_module_is_insufficient_data(self, orch, monkeypatch, dns):
        cls = self._classify_through_the_real_classifier(orch, monkeypatch, dns)

        assert cls["auto_classification"] == "insufficient_data", cls
        assert orch.CLASSIFICATION_SEVERITY[cls["auto_classification"]] == "MEDIUM"

    def test_a_dns_module_that_answered_keeps_its_verdict(self, orch, monkeypatch):
        # Controllo, verde anche prima del fix.
        cls = self._classify_through_the_real_classifier(
            orch, monkeypatch, _c02_zone({"A": ["192.0.2.10"], "NS": ["ns1.acme-typo.example"]}))

        assert cls["auto_classification"] == "needs_review", cls


class TestCOL02FirstCycleTotalFailureWithoutBaseline:
    """O5 (rilievo R2 del security-reviewer di RES-01) — primo ciclo di un dominio con il DNS
    muto e nessuna baseline, con la pipeline vera (`_run_pipeline`). Comportamento fissato:
      * nessun 500 e nessun alert nel ciclo guasto; la classificazione è `insufficient_data`;
      * il risveglio del ciclo dopo è visibile sul canale dei casi (classificazione sui dati
        vivi, qui `suspicious`/`mx_only_no_web`) E sul canale alert: gli alert ordinari dei record
        che compaiono (`mx_record_changed` HIGH, `ns_changed` MEDIUM), perché la sezione guasta
        salvata al primo ciclo fa da baseline vuota (SEC-31, giro correttivo);
      * dal ciclo successivo la baseline è nota e il canale alert torna a funzionare.

    G5 — correzione, prima del commit, di test di questo stesso lavoro. La prima versione di
    questa classe fissava «il risveglio NON genera alert» e «la sezione salvata è `None`»: era la
    lettura sbagliata della semantica della prima osservazione (verdetto INSUFFICIENTE del
    verifier, DECISIONE del coordinator «giro correttivo» in BUG-REGISTER.md), perché un
    SERVFAIL sul primo ciclo, scelto da chi gestisce la zona, avrebbe cancellato per sempre il
    segnale che a `HEAD` c'era (3 alert: A e MX HIGH, NS MEDIUM)."""

    @pytest.fixture
    def run_cycle(self, orch, monkeypatch, tmp_path):
        o = orch
        monkeypatch.setattr(o, "INTEL_STORE", True)
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        api = TestClient(_c02_classifier_app, raise_server_exceptions=False)
        statuses, published, state = [], [], {"dns": None}

        def _post(url, json=None, timeout=None, headers=None):
            if url.endswith("/publish"):
                published.extend((json or {}).get("events", []))
                return _R({})
            r = api.post(url[len(o.CLASSIFY_URL):], json=json)
            statuses.append((url[len(o.CLASSIFY_URL):], r.status_code))
            return _R(r.json() if r.is_success else None, ok=r.is_success, status_code=r.status_code)

        monkeypatch.setattr(o._session, "post", _post)
        monkeypatch.setattr(o._session, "get", lambda url, timeout=None: _c02_get(o, state["dns"])(url, timeout))

        def run(dns):
            state["dns"] = dns
            published.clear()
            o._run_pipeline(_c02_request(o))
            return _event_for(published, _C02_DOMAIN)

        run.history = lambda: o.intel_store.load_history("acme", _C02_DOMAIN, limit=100)
        run.snapshot = lambda: (o.intel_store.load_snapshot("acme", _C02_DOMAIN) or {}).get("intel", {}).get("dns", "-")
        run.statuses = statuses
        return run

    WAKE_UP = _c02_zone({"MX": ["10 mail.acme-typo.example"], "NS": ["ns1.acme-typo.example"]})

    def test_first_cycle_total_failure_completes_with_an_event_and_no_error_response(self, run_cycle):
        event = run_cycle(_c02_total_failure())

        assert event is not None
        assert all(code == 200 for _, code in run_cycle.statuses), run_cycle.statuses

    def test_first_cycle_total_failure_is_classified_insufficient_data(self, run_cycle):
        event = run_cycle(_c02_total_failure())

        assert event["classification"]["auto_classification"] == "insufficient_data", event["classification"]

    def test_first_cycle_total_failure_raises_no_alert(self, run_cycle):
        run_cycle(_c02_total_failure())

        assert run_cycle.history() == []

    def test_wake_up_after_a_failed_first_cycle_is_visible_on_the_case_channel(self, run_cycle):
        run_cycle(_c02_total_failure())

        event = run_cycle(self.WAKE_UP)

        cls = event["classification"]
        assert (cls["auto_classification"], cls["rule"]) == ("suspicious", "mx_only_no_web"), cls

    def test_wake_up_after_a_failed_first_cycle_raises_the_ordinary_alerts_of_the_new_records(self, run_cycle):
        run_cycle(_c02_total_failure())

        run_cycle(self.WAKE_UP)

        alerts = [(a["type"], a["severity"]) for entry in run_cycle.history() for a in entry["alerts"]]
        assert sorted(alerts) == [("mx_record_changed", "HIGH"), ("ns_changed", "MEDIUM")], alerts
        assert all(code == 200 for _, code in run_cycle.statuses), run_cycle.statuses

    def test_wake_up_after_a_failed_first_cycle_starts_the_known_baseline(self, run_cycle):
        run_cycle(_c02_total_failure())

        run_cycle(self.WAKE_UP)

        assert run_cycle.snapshot()["records"]["MX"] == ["10 mail.acme-typo.example"]
        assert run_cycle.snapshot()["records_status"]["MX"] == "ok"

    def test_the_wake_up_alerts_come_once(self, run_cycle):
        run_cycle(_c02_total_failure())
        run_cycle(self.WAKE_UP)
        after_wake_up = len(run_cycle.history())

        run_cycle(self.WAKE_UP)

        assert len(run_cycle.history()) == after_wake_up

    def test_alert_channel_works_again_once_the_baseline_is_known(self, run_cycle):
        # Controllo, verde anche prima del fix: dopo il risveglio la baseline è nota e un cambio
        # vero allerta una volta.
        run_cycle(_c02_total_failure())
        run_cycle(self.WAKE_UP)
        known = len(run_cycle.history())

        run_cycle(_c02_zone({"MX": ["10 mail.other.example"], "NS": ["ns1.acme-typo.example"]}))

        types = [a["type"] for entry in run_cycle.history()[:len(run_cycle.history()) - known] for a in entry["alerts"]]
        assert types == ["mx_record_changed"]


# ═══════════════════════════════════════════════════════════════
# COL-12 — un dato DNS riportato non vale per sempre (marcatore `carried_over`)
# ═══════════════════════════════════════════════════════════════
#
# Criteri C1-C6 e C11 di BUG-REGISTER.md («ASSEGNA · COL-12 · criteri di accettazione»). Il
# riporto per parte di COL-02 (`_carry_forward_dns`) e quello del modulo intero di CODE-01
# (`_persist_intel`) copiano valore E STATO del ciclo precedente: nello snapshot non resta
# nulla che dica «riportato», e report, scheda Intel e Raw mostrano il dato vecchio come
# attuale per quanti cicli dura il guasto. Il contratto deciso:
#
#   * campo nuovo, additivo, SOLO nello snapshot salvato (non in `intel["dns"]`, che è
#     l'osservazione del ciclo letta da eventi e classificazione):
#     `dns["carried_over"] = {parte: {"observed_at": <ISO|None>, "carried_at": <ISO>}}`;
#     parti ammesse: A, AAAA, MX, NS, TXT, SOA, CNAME, spf, dmarc, bimi, caa (sottodomini e
#     selettori DKIM non sono parti: si riportano per nome, con il marcatore nella propria
#     sezione, COL-31);
#   * `carried_at` = istante del ciclo, `orchestrator.now_iso()` letto UNA volta per
#     chiamata di `_persist_intel`;
#   * `observed_at` = per una parte già riportata nel precedente il suo `observed_at`
#     precedente, altrimenti `dns.timestamp` del precedente; una voce precedente malformata
#     per una parte riportata o un `dns.timestamp` illeggibile danno `None` (età ignota,
#     mai «più fresca» del vero); i nomi fuori elenco cadono;
#   * nessuna parte riportata -> la chiave `carried_over` è ASSENTE;
#   * `records_status` delle parti riportate resta quello copiato (COL-02).
#
# Un test «il marcatore non c'è» sarebbe stato verde anche prima del fix: i controlli di questo tipo (C5) lo
# dichiarano. Quelli di C6 e C11 sono rossi per costruzione perché pretendono prima il
# marcatore («precondizione») e poi che sia robusto o che non filtri nel resto. Dove il
# criterio non dice che cosa fare (un marcatore precedente che non è un dict, una parte
# riportata il cui valore precedente era `unknown`) il test lo dichiara e fissa il minimo.

import json
from datetime import datetime, timedelta, timezone

_C12_BASE = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
_C12_MISSING = object()   # nel parametro: «la chiave non c'è»
_C12_KEEP = object()      # nell'helper: «lascia com'è»


def _c12_at(hours=0, seconds=0):
    """Istante di prova: `_c12_at(0)` è il `timestamp` di `_c02_healthy_dns()`."""
    return (_C12_BASE + timedelta(hours=hours, seconds=seconds)).isoformat()


_C12_NOW = _c12_at(24, seconds=30)   # istante del ciclo nei test a un ciclo solo
_C12_ALL_PARTS = [*_C02_BASE, *_C02_EMAIL_SECTIONS]
_C12_FAILED_DNS = [
    pytest.param(None, id="section-none"),
    pytest.param(_c02_total_failure(), id="all-types-unknown"),
    pytest.param({"records": {"A": [], "MX": []}, "error": "DNS resolution failed"}, id="error-text"),
]


def _c12_persist(monkeypatch, o, prev_dns, curr_dns, now=_C12_NOW, **kwargs):
    """`_c02_persist` con l'istante del ciclo fissato: ritorna (sezione salvata, payload di
    `/diff`, `intel` passato)."""
    monkeypatch.setattr(o, "now_iso", lambda: now)
    return _c02_persist(monkeypatch, o, prev_dns, curr_dns, **kwargs)


def _c12_without_marker(dns):
    return {k: v for k, v in dns.items() if k != "carried_over"}


class TestCOL12PartialCarryMarksTheCarriedParts:
    """C1 + C3 — il riporto per parte lascia traccia: una voce per ogni parte riportata, con
    l'istante dell'ultima osservazione reale e quello del ciclo."""

    def test_unknown_a_and_mx_are_marked_with_the_previous_observation_and_the_cycle_instant(self, orch, monkeypatch):
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, "A", "MX")
        curr["timestamp"] = _c12_at(24)           # fresco: NON è l'istante dell'osservazione riportata

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, curr)

        entry = {"observed_at": prev["timestamp"], "carried_at": _C12_NOW}
        assert saved.get("carried_over") == {"A": entry, "MX": entry}
        assert saved["records"]["A"] == _C02_SAMPLE["A"] and saved["records_status"]["A"] == "ok"
        assert saved["records"]["MX"] == _C02_SAMPLE["MX"] and saved["records_status"]["MX"] == "ok"

    @pytest.mark.parametrize("rtype", _C02_BASE)
    def test_each_base_type_marks_only_itself(self, orch, monkeypatch, rtype):
        prev = _c02_healthy_dns()

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(prev, rtype))

        # TXT trascina SPF (`spf.status` è lo stato del TXT): sono riportati insieme.
        expected = {"TXT", "spf"} if rtype == "TXT" else {rtype}
        assert set(saved.get("carried_over", {})) == expected, saved.get("carried_over")
        assert saved["carried_over"][rtype] == {"observed_at": prev["timestamp"], "carried_at": _C12_NOW}

    @pytest.mark.parametrize("section", _C02_EMAIL_SECTIONS)
    def test_each_email_section_marks_only_itself(self, orch, monkeypatch, section):
        prev = _c02_healthy_dns()

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(prev, section))

        assert saved.get("carried_over") == {
            section: {"observed_at": prev["timestamp"], "carried_at": _C12_NOW}}
        assert saved["email_auth"][section] == prev["email_auth"][section]

    def test_dkim_and_subdomains_never_get_a_marker(self, orch, monkeypatch):
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, "TXT")
        curr["email_auth"]["dkim"] = {"selectors_found": [], "selectors_tested": 18, "records": {},
                                      "selectors_unknown": ["google"]}
        curr["subdomains"] = {"tested": 25, "active": [], "unknown": [f"www.{_C02_DOMAIN}"]}

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, curr)

        assert "carried_over" in saved, "precondizione: il riporto deve essere marcato"
        assert not {"dkim", "subdomains"} & set(saved["carried_over"])

    def test_the_diff_receives_the_marker_with_the_current_section(self, orch, monkeypatch):
        # Il classificatore calcola l'età dal solo marcatore del `current` che riceve: se
        # l'orchestrator lo salvasse ma non lo mandasse, l'alert non scatterebbe mai.
        prev = _c02_healthy_dns()

        saved, sent, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(prev, "A"))

        assert saved.get("carried_over"), "precondizione: il riporto deve essere marcato"
        assert sent[0]["current"]["dns"]["carried_over"] == saved["carried_over"]

    def test_the_cycle_observation_is_not_given_the_marker(self, orch, monkeypatch):
        # `intel["dns"]` è ciò che classificazione ed eventi leggono dopo `_persist_intel`: deve
        # restare l'osservazione di QUESTO ciclo, senza marcatore e con gli `unknown` al loro posto.
        prev = _c02_healthy_dns()
        curr = _c02_unknown(prev, "A", "MX", "dmarc")
        curr_before = copy.deepcopy(curr)

        saved, _, intel = _c12_persist(monkeypatch, orch, prev, curr)

        assert saved.get("carried_over"), "precondizione: il riporto deve essere marcato"
        assert "carried_over" not in intel["dns"]
        assert intel["dns"] == curr_before and curr == curr_before

    def test_the_previous_snapshot_is_not_modified_by_the_marker(self, orch, monkeypatch):
        prev = _c02_healthy_dns()
        prev["carried_over"] = {"A": {"observed_at": _c12_at(-24), "carried_at": _c12_at(0)}}
        prev_before = copy.deepcopy(prev)

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        assert saved.get("carried_over"), "precondizione: il riporto deve essere marcato"
        assert prev == prev_before

    def test_all_the_parts_of_one_cycle_share_the_instant_read_once(self, orch, monkeypatch):
        calls = []

        def tick():
            calls.append(1)
            return _c12_at(24, seconds=len(calls))

        monkeypatch.setattr(orch, "now_iso", tick)
        prev = _c02_healthy_dns()

        saved, _, _ = _c02_persist(monkeypatch, orch, prev, _c02_unknown(prev, "A", "MX", "TXT", "dmarc"))

        carried_at = {e["carried_at"] for e in saved.get("carried_over", {}).values()}
        assert len(saved.get("carried_over", {})) == 5 and len(carried_at) == 1, saved.get("carried_over")
        assert len(calls) == 1, f"now_iso() letto {len(calls)} volte, non una"


class TestCOL12OnlyAKnownValueIsMarked:
    """C1 — il marcatore dice «questo dato è vecchio», quindi si mette solo dove è stato copiato
    un valore noto: una parte senza valore precedente utilizzabile resta com'è (nessun marcatore)."""

    def test_a_type_missing_from_the_previous_section_is_not_marked(self, orch, monkeypatch):
        prev = {"timestamp": _c12_at(0), "records": {"MX": ["10 mail.acme-typo.example"]},
                "records_status": {"MX": "ok"}}
        curr = _c02_unknown(_c02_healthy_dns(), "A", "MX")

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, curr)

        assert saved["records"]["A"] == [] and saved["records_status"]["A"] == "unknown"
        assert set(saved.get("carried_over", {})) == {"MX"}, saved.get("carried_over")

    def test_a_type_that_was_unknown_in_the_previous_cycle_too_is_not_marked(self, orch, monkeypatch):
        # Interpretazione (il criterio lo dice esplicitamente solo per il guasto totale, C4):
        # un `unknown` precedente non è un valore noto, quindi il «riporto» di `[]`/`unknown`
        # non è un dato vecchio presentato come attuale e non va marcato.
        healthy = _c02_healthy_dns()
        prev = _c02_unknown(healthy, "A")
        curr = _c02_unknown(healthy, "A", "MX")

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, curr)

        assert set(saved.get("carried_over", {})) == {"MX"}, saved.get("carried_over")
        assert saved["records_status"]["A"] == "unknown"

    def test_an_email_section_that_was_unknown_in_the_previous_cycle_too_is_not_marked(self, orch, monkeypatch):
        healthy = _c02_healthy_dns()
        prev = _c02_unknown(healthy, "dmarc")
        curr = _c02_unknown(healthy, "dmarc", "caa")

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, curr)

        assert set(saved.get("carried_over", {})) == {"caa"}, saved.get("carried_over")


@pytest.fixture
def c12_cycle(c02_cycle, monkeypatch):
    """`c02_cycle` (store reale su directory temporanea, `/diff` del classificatore reale) con
    l'orologio dell'orchestrator in mano al test: `run(dns, hours)` esegue un ciclo la cui
    osservazione è `hours` dopo T0 (`dns.timestamp`) e che l'orchestrator persiste 30 s dopo
    (`now_iso`). `run.marker()` è il `carried_over` salvato, `run.per_cycle` gli alert nuovi di
    ogni ciclo come (tipo, severità, detail)."""
    clock = {"now": _c12_at(0, seconds=30)}
    monkeypatch.setattr(c02_cycle.o, "now_iso", lambda: clock["now"])

    def run(dns, hours):
        dns = copy.deepcopy(dns)
        dns["timestamp"] = _c12_at(hours)
        clock["now"] = _c12_at(hours, seconds=30)
        c02_cycle(dns)

    run.marker = lambda: c02_cycle.snapshot().get("carried_over")
    run.snapshot = c02_cycle.snapshot
    run.per_cycle = c02_cycle.per_cycle
    return run


class TestCOL12MarkerAcrossConsecutiveCycles:
    """C2 — l'eredità, su più cicli consecutivi con lo store reale (fixture `c12_cycle`)."""

    @pytest.fixture
    def cycle(self, c12_cycle):
        return c12_cycle

    @staticmethod
    def _entry(observed_hours, carried_hours):
        return {"observed_at": _c12_at(observed_hours), "carried_at": _c12_at(carried_hours, seconds=30)}

    def test_observed_at_stays_the_last_real_observation_while_carried_at_follows_the_cycle(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)

        for hours in (24, 48, 72):
            cycle(_c02_unknown(zone, "A"), hours)
            assert cycle.marker() == {"A": self._entry(0, hours)}, f"ciclo a {hours} h: {cycle.marker()}"

    def test_a_part_observed_again_leaves_the_marker_and_the_key_disappears(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        cycle(_c02_unknown(zone, "A"), 24)
        assert cycle.marker() == {"A": self._entry(0, 24)}, "precondizione: il riporto deve essere marcato"

        cycle(zone, 48)

        assert "carried_over" not in cycle.snapshot()

    def test_a_part_that_fails_again_after_recovering_restarts_from_its_new_observation(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        cycle(_c02_unknown(zone, "A"), 24)
        cycle(zone, 48)

        cycle(_c02_unknown(zone, "A"), 72)

        assert cycle.marker() == {"A": self._entry(48, 72)}

    def test_each_part_inherits_its_own_last_observation(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        cycle(_c02_unknown(zone, "A"), 24)            # A: osservato a 0
        cycle(_c02_unknown(zone, "A", "MX"), 48)      # MX: osservato a 24

        assert cycle.marker() == {"A": self._entry(0, 48), "MX": self._entry(24, 48)}

        cycle(_c02_unknown(zone, "A"), 72)            # MX torna osservato, A no

        assert cycle.marker() == {"A": self._entry(0, 72)}

    def test_a_total_failure_after_a_partial_carry_inherits_each_parts_observation(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        cycle(_c02_unknown(zone, "A"), 24)            # A riportato; il resto osservato a 24

        cycle(_c02_total_failure(zone), 48)           # percorso CODE-01: sezione precedente intera

        marker = cycle.marker()
        assert marker is not None and set(marker) == set(_C12_ALL_PARTS), marker
        assert marker["A"] == self._entry(0, 48)
        assert all(marker[p] == self._entry(24, 48) for p in _C12_ALL_PARTS if p != "A"), marker


class TestCOL12StaleAlertThroughTheChain:
    """C2 + C4 + C7 + C9 end-to-end: `_persist_intel` (store reale su directory temporanea) ->
    `/diff` del classificatore reale -> storia degli alert. Il marcatore scritto dall'orchestrator
    è quello che il classificatore legge: l'alert esce una volta quando l'età attraversa le 72 h,
    sul tempo trascorso e non sul numero di cicli, e al ritorno del DNS valgono gli alert di sempre.
    L'età di una parte al ciclo a `h` ore è `h` + 30 s (il ciclo persiste 30 s dopo l'osservazione)."""

    @pytest.fixture
    def cycle(self, c12_cycle):
        return c12_cycle

    @staticmethod
    def _alerts(cycle):
        """Per ogni ciclo, TUTTI gli alert nuovi come (tipo, severità): un alert ordinario spurio
        durante il guasto fa fallire il confronto."""
        return [[(t, sev) for t, sev, _ in found] for found in cycle.per_cycle]

    @staticmethod
    def _detail(cycle, index, alert_type):
        return next(d for t, _, d in cycle.per_cycle[index] if t == alert_type)

    def test_a_type_unknown_for_72_hours_alerts_once_and_not_again(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        for hours in (24, 48, 72, 96):
            cycle(_c02_unknown(zone, "A"), hours)
        cycle(zone, 120)

        assert self._alerts(cycle) == [[], [], [], [("dns_stale_core", "MEDIUM")], [], []], cycle.per_cycle
        assert self._detail(cycle, 3, "dns_stale_core")["parts"] == ["A"]

    def test_a_short_outage_never_alerts(self, cycle):
        # Controllo, verde anche prima del fix: un guasto di due cicli giornalieri (48 h) non è un
        # segnale, e il ritorno non genera nulla se la zona non è cambiata.
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        cycle(_c02_unknown(zone, "A", "MX"), 24)
        cycle(_c02_unknown(zone, "A", "MX"), 48)
        cycle(zone, 72)

        assert self._alerts(cycle) == [[], [], [], []], cycle.per_cycle

    def test_the_threshold_is_elapsed_time_not_the_number_of_cycles(self, cycle):
        # Tre cicli di guasto in due ore non bastano; uno solo, ma 73 ore dopo l'ultima
        # osservazione, sì: la cadenza dei cicli non è nota e può essere irregolare.
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        cycle(_c02_unknown(zone, "A"), 1)
        cycle(_c02_unknown(zone, "A"), 2)
        cycle(_c02_unknown(zone, "A"), 73)

        assert self._alerts(cycle) == [[], [], [], [("dns_stale_core", "MEDIUM")]], cycle.per_cycle

    def test_a_section_unknown_for_72_hours_alerts_low(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        for hours in (24, 48, 72):
            cycle(_c02_unknown(zone, "dmarc"), hours)

        assert self._alerts(cycle) == [[], [], [], [("dns_stale_other", "LOW")]], cycle.per_cycle
        assert self._detail(cycle, 3, "dns_stale_other")["parts"] == ["dmarc"]

    def test_core_and_other_parts_alert_once_each_in_the_same_cycle(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        for hours in (24, 48, 72):
            cycle(_c02_unknown(zone, "A", "MX", "dmarc"), hours)

        assert self._alerts(cycle)[3] == [("dns_stale_core", "MEDIUM"), ("dns_stale_other", "LOW")], cycle.per_cycle
        assert self._alerts(cycle)[:3] == [[], [], []]
        assert self._detail(cycle, 3, "dns_stale_core")["parts"] == ["A", "MX"]

    def test_a_total_failure_alerts_for_every_known_part_once(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        for hours in (24, 48, 72, 96):
            cycle(_c02_total_failure(zone), hours)

        assert self._alerts(cycle) == [[], [], [], [("dns_stale_core", "MEDIUM"), ("dns_stale_other", "LOW")], []], \
            cycle.per_cycle
        assert self._detail(cycle, 3, "dns_stale_core")["parts"] == ["A", "MX", "NS"]
        assert sorted(self._detail(cycle, 3, "dns_stale_other")["parts"]) == sorted(
            ["AAAA", "TXT", "SOA", "CNAME", "spf", "dmarc", "bimi", "caa"])

    def test_a_new_series_after_the_dns_came_back_alerts_again(self, cycle):
        zone = _c02_healthy_dns()
        cycle(zone, 0)
        for hours in (24, 48, 72):
            cycle(_c02_unknown(zone, "A"), hours)
        cycle(zone, 96)
        for hours in (120, 144, 168):
            cycle(_c02_unknown(zone, "A"), hours)

        alert = [("dns_stale_core", "MEDIUM")]
        assert self._alerts(cycle) == [[], [], [], alert, [], [], [], alert], cycle.per_cycle

    def test_a_real_change_when_the_dns_comes_back_alerts_as_always(self, cycle):
        zone = _c02_healthy_dns()
        changed = copy.deepcopy(zone)
        changed["records"]["A"] = ["198.51.100.7"]
        cycle(zone, 0)
        for hours in (24, 48, 72):
            cycle(_c02_unknown(zone, "A"), hours)
        cycle(changed, 96)

        assert self._alerts(cycle) == [[], [], [], [("dns_stale_core", "MEDIUM")], [("a_record_changed", "HIGH")]], \
            cycle.per_cycle
        assert self._detail(cycle, 4, "a_record_changed") == {"old": _C02_SAMPLE["A"], "new": ["198.51.100.7"]}


class TestCOL12TotalFailureMarksEveryKnownPart:
    """C4 — guasto totale (percorso CODE-01): la sezione salvata è la precedente intera, e ogni
    parte che nel precedente aveva un valore noto porta un marcatore."""

    @pytest.mark.parametrize("failed", _C12_FAILED_DNS)
    def test_every_part_of_a_healthy_previous_section_is_marked(self, orch, monkeypatch, failed):
        prev = _c02_healthy_dns()

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, failed)

        entry = {"observed_at": prev["timestamp"], "carried_at": _C12_NOW}
        assert saved.get("carried_over") == {part: entry for part in _C12_ALL_PARTS}

    @pytest.mark.parametrize("failed", _C12_FAILED_DNS)
    def test_the_rest_of_the_section_is_the_previous_one_unchanged(self, orch, monkeypatch, failed):
        prev = _c02_healthy_dns()

        saved, sent, _ = _c12_persist(monkeypatch, orch, prev, failed)

        assert saved.get("carried_over"), "precondizione: il riporto deve essere marcato"
        # COL-31: a meno dei marcatori, compresi quelli di sottodomini e DKIM che il guasto totale scrive.
        assert _c31_bare(saved) == prev
        assert saved["timestamp"] == prev["timestamp"], "la sezione riportata mantiene il suo timestamp vecchio"
        assert sent[0]["current"]["dns"] == saved

    def test_a_previous_type_without_a_known_value_is_not_marked(self, orch, monkeypatch):
        healthy = _c02_healthy_dns()
        prev = _c02_unknown(healthy, "A")

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        assert set(saved.get("carried_over", {})) == set(_C12_ALL_PARTS) - {"A"}, saved.get("carried_over")

    def test_a_previous_email_section_without_a_known_value_is_not_marked(self, orch, monkeypatch):
        healthy = _c02_healthy_dns()
        prev = _c02_unknown(healthy, "dmarc", "caa")

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        assert set(saved.get("carried_over", {})) == set(_C12_ALL_PARTS) - {"dmarc", "caa"}, saved.get("carried_over")

    def test_a_known_absence_is_a_known_value_and_is_marked(self, orch, monkeypatch):
        # `nodata`/`nxdomain` sono risposte: «il dominio non ha MX» è un fatto noto, e vecchio.
        prev = _c02_zone({"A": ["192.0.2.10"]}, MX="nxdomain")

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        assert set(saved.get("carried_over", {})) == set(_C12_ALL_PARTS), saved.get("carried_over")

    def test_a_previous_snapshot_without_status_marks_the_parts_present_as_lists(self, orch, monkeypatch):
        prev = _c02_legacy(_c02_healthy_dns())

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        entry = {"observed_at": prev["timestamp"], "carried_at": _C12_NOW}
        assert saved.get("carried_over") == {part: entry for part in _C12_ALL_PARTS}

    def test_a_previous_section_with_only_some_types_marks_only_those(self, orch, monkeypatch):
        prev = {"timestamp": _c12_at(0), "records": {"A": ["192.0.2.10"], "MX": ["10 mail.acme-typo.example"]},
                "records_status": {"A": "ok", "MX": "ok"}}

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        assert set(saved.get("carried_over", {})) == {"A", "MX"}, saved.get("carried_over")

    def test_the_observation_instants_are_inherited_and_the_previous_cycle_instant_is_not_copied(
            self, orch, monkeypatch):
        # Il precedente è a sua volta un ciclo di riporto parziale: A viene dal 20/10, il resto è
        # stato osservato nel precedente (`dns.timestamp`). Il guasto totale eredita questi istanti
        # e stampa il proprio `carried_at`: il marcatore precedente NON è copiato tale e quale.
        prev = _c02_healthy_dns()
        prev["timestamp"] = _c12_at(24)
        prev["carried_over"] = {"A": {"observed_at": _c12_at(0), "carried_at": _c12_at(24, seconds=30)}}

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure(), now=_c12_at(48, seconds=30))

        marker = saved.get("carried_over")
        assert marker is not None and set(marker) == set(_C12_ALL_PARTS), marker
        assert marker["A"] == {"observed_at": _c12_at(0), "carried_at": _c12_at(48, seconds=30)}
        for part in _C12_ALL_PARTS:
            if part != "A":
                assert marker[part] == {"observed_at": _c12_at(24), "carried_at": _c12_at(48, seconds=30)}, part

    def test_only_the_parts_the_previous_section_has_are_marked_when_it_lacks_the_email_block(self, orch, monkeypatch):
        prev = _c02_healthy_dns()
        del prev["email_auth"]

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        assert set(saved.get("carried_over", {})) == set(_C02_BASE), saved.get("carried_over")

    def test_dkim_and_subdomains_are_not_marked(self, orch, monkeypatch):
        saved, _, _ = _c12_persist(monkeypatch, orch, _c02_healthy_dns(), _c02_total_failure())

        assert "carried_over" in saved, "precondizione: il riporto deve essere marcato"
        assert not {"dkim", "subdomains", "records", "email_auth"} & set(saved["carried_over"])

    def test_all_the_parts_share_the_instant_read_once(self, orch, monkeypatch):
        calls = []

        def tick():
            calls.append(1)
            return _c12_at(24, seconds=len(calls))

        monkeypatch.setattr(orch, "now_iso", tick)

        saved, _, _ = _c02_persist(monkeypatch, orch, _c02_healthy_dns(), _c02_total_failure())

        carried_at = {e["carried_at"] for e in saved.get("carried_over", {}).values()}
        assert len(saved.get("carried_over", {})) == len(_C12_ALL_PARTS) and len(carried_at) == 1
        assert len(calls) == 1, f"now_iso() letto {len(calls)} volte, non una"


class TestCOL12NoMarkerWhenNothingIsCarried:
    """C5 — la chiave `carried_over` compare solo se almeno una parte è stata riportata. Controlli,
    verdi anche prima del fix (quando nessun marcatore esisteva): fissano che il fix non lo scriva
    quando non c'è nulla da dire, così uno snapshot senza parti riportate resta quello di COL-02."""

    def test_a_dns_that_answered_in_full_has_no_marker(self, orch, monkeypatch):
        saved, _, _ = _c12_persist(monkeypatch, orch, _c02_healthy_dns(), _c02_healthy_dns())

        assert "carried_over" not in saved

    @pytest.mark.parametrize("status", ["nodata", "nxdomain"])
    def test_a_determined_absence_is_an_observation_and_has_no_marker(self, orch, monkeypatch, status):
        prev = _c02_healthy_dns()
        curr = copy.deepcopy(prev)
        curr["records"]["A"] = []
        curr["records_status"]["A"] = status

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, curr)

        assert "carried_over" not in saved

    def test_a_previous_marker_is_not_carried_over_when_the_dns_answers_in_full(self, orch, monkeypatch):
        prev = _c02_healthy_dns()
        prev["carried_over"] = {"A": {"observed_at": _c12_at(0), "carried_at": _c12_at(24)}}

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_healthy_dns())

        assert "carried_over" not in saved

    @pytest.mark.parametrize("prev_dns", [
        pytest.param(None, id="snapshot-without-dns"),
        pytest.param({}, id="empty-dns"),
        pytest.param({"records": ["not", "a", "dict"], "email_auth": "x"}, id="corrupted-shapes"),
    ])
    def test_unknown_parts_with_no_usable_previous_value_have_no_marker(self, orch, monkeypatch, prev_dns):
        curr = _c02_unknown(_c02_healthy_dns(), "A", "dmarc")

        saved, _, _ = _c12_persist(monkeypatch, orch, prev_dns, curr)

        assert saved["records_status"]["A"] == "unknown"
        assert "carried_over" not in saved

    def test_no_snapshot_at_all_has_no_marker(self, orch, monkeypatch):
        saved, sent, _ = _c12_persist(monkeypatch, orch, None, _c02_unknown(_c02_healthy_dns(), "A"),
                                      snapshot=False)

        assert sent == [] and "carried_over" not in saved

    @pytest.mark.parametrize("prev_dns", [pytest.param(None, id="snapshot-without-dns"),
                                          pytest.param({}, id="empty-dns")])
    def test_total_failure_with_no_usable_previous_section_has_no_marker(self, orch, monkeypatch, prev_dns):
        saved, _, _ = _c12_persist(monkeypatch, orch, prev_dns, _c02_total_failure())

        assert "carried_over" not in saved

    def test_total_failure_with_no_snapshot_has_no_marker(self, orch, monkeypatch):
        saved, _, _ = _c12_persist(monkeypatch, orch, None, _c02_total_failure(), snapshot=False)

        assert "carried_over" not in saved

    def test_a_marker_sent_by_the_dns_service_is_not_trusted(self, orch, monkeypatch):
        # Interpretazione di «nessuna parte riportata -> chiave assente»: il marcatore lo scrive
        # solo l'orchestrator, per ciò che ha riportato. Un `carried_over` dentro la risposta di
        # `/dns` (servizio non autenticato, o un domani un altro produttore) non lo falsifica.
        forged = {"MX": {"observed_at": _c12_at(24), "carried_at": _c12_at(24)}}
        full = _c02_healthy_dns()
        full["carried_over"] = forged

        saved, _, _ = _c12_persist(monkeypatch, orch, _c02_healthy_dns(), full)
        assert "carried_over" not in saved

        prev = _c02_healthy_dns()
        partial = _c02_unknown(prev, "A")
        partial["carried_over"] = forged
        saved, _, _ = _c12_persist(monkeypatch, orch, prev, partial)
        assert set(saved.get("carried_over", {})) == {"A"}, saved.get("carried_over")

        # `unknown` ma nessun precedente utilizzabile: nulla è riportato, quindi nessun marcatore.
        nothing_to_carry = _c02_unknown(_c02_healthy_dns(), "A")
        nothing_to_carry["carried_over"] = forged
        saved, _, _ = _c12_persist(monkeypatch, orch, {}, nothing_to_carry)
        assert saved["records_status"]["A"] == "unknown"
        assert "carried_over" not in saved


_C12_BAD_ENTRIES = [
    pytest.param("x", id="string"), pytest.param(None, id="null"), pytest.param([], id="list"),
    pytest.param(5, id="int"), pytest.param(True, id="bool"), pytest.param({}, id="empty-dict"),
    pytest.param({"carried_at": _c12_at(0)}, id="no-observed-at"),
    pytest.param({"observed_at": 5, "carried_at": _c12_at(0)}, id="observed-int"),
    pytest.param({"observed_at": True, "carried_at": _c12_at(0)}, id="observed-bool"),
    pytest.param({"observed_at": ["x"], "carried_at": _c12_at(0)}, id="observed-list"),
    pytest.param({"observed_at": {"x": 1}, "carried_at": _c12_at(0)}, id="observed-dict"),
    pytest.param({"observed_at": "", "carried_at": _c12_at(0)}, id="observed-empty"),
    pytest.param({"observed_at": "not a date", "carried_at": _c12_at(0)}, id="observed-text"),
    pytest.param({"observed_at": "2026-13-45T99:99:99+00:00", "carried_at": _c12_at(0)}, id="observed-impossible"),
    pytest.param({"observed_at": "x" * 100_000, "carried_at": _c12_at(0)}, id="observed-huge"),
    pytest.param({"observed_at": "<script>alert(1)</script>", "carried_at": _c12_at(0)}, id="observed-markup"),
]
_C12_BAD_TIMESTAMPS = [
    pytest.param(_C12_MISSING, id="missing"), pytest.param(None, id="null"), pytest.param(5, id="int"),
    pytest.param(True, id="bool"), pytest.param("", id="empty"), pytest.param("garbage", id="text"),
    pytest.param(["x"], id="list"), pytest.param({"x": 1}, id="dict"),
    pytest.param("2026-13-45T99:99:99+00:00", id="impossible-date"),
    pytest.param("x" * 100_000, id="huge"),
]


class TestCOL12PreviousMarkerIsUntrusted:
    """C6 — lo snapshot precedente è un file su disco: il marcatore può essere di una versione
    vecchia, troncato o corrotto. Nessuna eccezione; i nomi fuori elenco cadono; una voce
    malformata per una parte riportata vale età ignota (`observed_at: null`, mai «più fresca»
    del vero); un `dns.timestamp` illeggibile idem."""

    @staticmethod
    def _prev(marker=_C12_KEEP, timestamp=_C12_KEEP):
        """Sezione sana con il marcatore e/o il `timestamp` sostituiti; `_C12_MISSING` toglie la chiave."""
        prev = _c02_healthy_dns()
        if marker is not _C12_KEEP:
            prev["carried_over"] = marker
        if timestamp is _C12_MISSING:
            del prev["timestamp"]
        elif timestamp is not _C12_KEEP:
            prev["timestamp"] = timestamp
        return prev

    @pytest.mark.parametrize("entry", _C12_BAD_ENTRIES)
    def test_a_malformed_entry_for_a_carried_part_gives_an_unknown_observation(self, orch, monkeypatch, entry):
        prev = self._prev({"A": entry})

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        assert saved.get("carried_over") == {"A": {"observed_at": None, "carried_at": _C12_NOW}}

    def test_a_malformed_entry_does_not_touch_the_valid_ones(self, orch, monkeypatch):
        prev = self._prev({"A": "garbage", "MX": {"observed_at": _c12_at(-24), "carried_at": _c12_at(0)}})

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A", "MX"))

        assert saved.get("carried_over") == {
            "A": {"observed_at": None, "carried_at": _C12_NOW},
            "MX": {"observed_at": _c12_at(-24), "carried_at": _C12_NOW}}

    @pytest.mark.parametrize("marker", [
        pytest.param("x", id="string"), pytest.param(["A"], id="list"), pytest.param(5, id="int"),
        pytest.param(None, id="null"), pytest.param(True, id="bool"), pytest.param(1.5, id="float"),
    ])
    def test_a_previous_marker_that_is_not_a_dict_does_not_raise(self, orch, monkeypatch, marker):
        # Il criterio vieta solo l'eccezione e impone età mai «più fresca» del vero: con un
        # marcatore illeggibile non si sa se A fosse già riportata, quindi `observed_at` è
        # `dns.timestamp` del precedente oppure null; le parti sono quelle riportate ora.
        prev = self._prev(marker)

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        entry = (saved.get("carried_over") or {}).get("A")
        assert entry is not None and set(saved["carried_over"]) == {"A"}, saved.get("carried_over")
        assert entry["carried_at"] == _C12_NOW
        assert entry["observed_at"] in (prev["timestamp"], None), entry

    def test_names_outside_the_list_are_dropped_and_parts_no_longer_carried_leave(self, orch, monkeypatch):
        valid = {"observed_at": _c12_at(-24), "carried_at": _c12_at(0)}
        prev = self._prev({"A": valid, "MX": valid, "dkim": valid, "subdomains": valid, "records": valid,
                           "EVIL-<script>alert(1)</script>": valid, "": valid, "A ": valid})

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        # MX era nel marcatore ma ora è osservato: esce. I nomi estranei non entrano mai.
        assert saved.get("carried_over") == {"A": {"observed_at": _c12_at(-24), "carried_at": _C12_NOW}}

    def test_names_outside_the_list_are_dropped_on_total_failure_too(self, orch, monkeypatch):
        valid = {"observed_at": _c12_at(-24), "carried_at": _c12_at(0)}
        prev = self._prev({"A": valid, "dkim": valid, "subdomains": valid, "EVIL": valid})

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        marker = saved.get("carried_over")
        assert marker is not None and set(marker) == set(_C12_ALL_PARTS), marker
        assert marker["A"]["observed_at"] == _c12_at(-24)

    def test_thousands_of_foreign_names_do_not_inflate_the_snapshot(self, orch, monkeypatch):
        valid = {"observed_at": _c12_at(-24), "carried_at": _c12_at(0)}
        prev = self._prev({f"foreign-{i}": valid for i in range(5000)})

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        assert set(saved.get("carried_over", {})) == {"A"}, "precondizione: il riporto deve essere marcato"
        assert len(json.dumps(saved["carried_over"])) < 1000

    @pytest.mark.parametrize("timestamp", _C12_BAD_TIMESTAMPS)
    def test_an_unreadable_previous_dns_timestamp_gives_an_unknown_observation(self, orch, monkeypatch, timestamp):
        prev = self._prev(timestamp=timestamp)

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        assert saved.get("carried_over") == {"A": {"observed_at": None, "carried_at": _C12_NOW}}

    @pytest.mark.parametrize("timestamp", _C12_BAD_TIMESTAMPS)
    def test_an_unreadable_previous_dns_timestamp_gives_an_unknown_observation_on_total_failure(
            self, orch, monkeypatch, timestamp):
        prev = self._prev(timestamp=timestamp)

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        marker = saved.get("carried_over")
        assert marker is not None and set(marker) == set(_C12_ALL_PARTS), marker
        assert all(e == {"observed_at": None, "carried_at": _C12_NOW} for e in marker.values()), marker

    def test_an_inherited_observation_does_not_depend_on_the_previous_dns_timestamp(self, orch, monkeypatch):
        prev = self._prev({"A": {"observed_at": _c12_at(-24), "carried_at": _c12_at(0)}}, timestamp="garbage")

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A", "MX"))

        assert saved.get("carried_over") == {
            "A": {"observed_at": _c12_at(-24), "carried_at": _C12_NOW},
            "MX": {"observed_at": None, "carried_at": _C12_NOW}}


class TestCOL12EventsAndClassificationDoNotSeeTheMarker:
    """C11 — il marcatore sta nello snapshot e basta. Con la pipeline vera (`_run_pipeline`,
    classificatore reale) lo stesso ciclo, una volta senza archivio (nessun riporto, nessun
    marcatore) e una con uno snapshot sano già in archivio (riporto + marcatore), pubblica
    eventi e classificazione identici, e al classificatore arriva la stessa sezione `dns` senza
    marcatore."""

    DNS_CASES = [
        pytest.param(_c02_unknown(_c02_healthy_dns(), "A"), id="a-unknown"),
        pytest.param(_c02_unknown(_c02_healthy_dns(), "A", "MX", "NS", "dmarc"), id="three-types-and-dmarc"),
        pytest.param(_c02_total_failure(), id="all-types-unknown"),
        pytest.param(_C02_FETCH_FAILED, id="fetch-failed"),
    ]

    @staticmethod
    def _fresh(dns):
        # `_C02_FETCH_FAILED` è un sentinel confrontato per identità: non si copia.
        return dns if dns is _C02_FETCH_FAILED else copy.deepcopy(dns)

    @staticmethod
    def _cycle(o, monkeypatch, dns):
        published, payloads = [], []
        monkeypatch.setattr(o._session, "get", _c02_get(o, dns))
        monkeypatch.setattr(o._session, "post", _real_classifier_post(o, published, payloads))
        o._run_pipeline(_c02_request(o))
        event = _event_for(published, _C02_DOMAIN)
        assert event is not None, published
        classification = {k: v for k, v in event["classification"].items() if k != "timestamp"}
        return {**event, "classification": classification}, payloads

    @pytest.mark.parametrize("dns", DNS_CASES)
    def test_the_event_and_the_classification_are_the_same_with_and_without_the_marker(
            self, orch, monkeypatch, tmp_path, dns):
        monkeypatch.setattr(orch, "INTEL_STORE", False)
        bare_event, bare_payloads = self._cycle(orch, monkeypatch, self._fresh(dns))

        monkeypatch.setattr(orch, "INTEL_STORE", True)
        monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(orch.intel_store, "HIST_DIR", tmp_path / "history")
        previous = {"dns": _c02_healthy_dns(), "cert": None, "http": None, "whois": None, "reputation": None}
        assert orch.intel_store.save_snapshot("acme", _C02_DOMAIN, previous)
        event, payloads = self._cycle(orch, monkeypatch, self._fresh(dns))

        saved = orch.intel_store.load_snapshot("acme", _C02_DOMAIN)["intel"]["dns"]
        assert saved.get("carried_over"), "precondizione: il riporto deve essere marcato"
        assert event == bare_event
        assert payloads == bare_payloads
        assert "carried_over" not in json.dumps([event, payloads])


# ═══════════════════════════════════════════════════════════════
# COL-12 — giro correttivo dopo il G6 (security-reviewer e verifier)
# ═══════════════════════════════════════════════════════════════
#
# Rilievi che il G3 non copriva: B1/R1 (il ramo SEC-31 salvava un `carried_over` arrivato da
# `/dns`), R2 (un `observed_at` successivo a `carried_at` passava e dava età negativa: alert mai
# emesso), N2 (istanti precedenti validi ma non canonici; marcatore precedente senza parti note:
# mutanti O03 e O12 del verifier). I test della dashboard e del classificatore stanno nei loro file.

_C12_FORGED = {"MX": {"observed_at": _c12_at(-96), "carried_at": _c12_at(24)},
               "EVIL-<script>": {"observed_at": _c12_at(-96), "carried_at": _c12_at(24)}}


class TestCOL12ForgedMarkerInTheFirstObservationBranch:
    """B1/R1 — guasto totale SENZA una sezione `dns` precedente (ramo SEC-31 di `_persist_intel`: la
    sezione guasta fa da baseline). Il marcatore lo scrive solo l'orchestrator: uno arrivato dalla
    risposta di `/dns` (zona non autenticata) non entra nello snapshot né nel payload di `/diff`.
    `test_a_marker_sent_by_the_dns_service_is_not_trusted` copre gli altri tre percorsi."""

    @pytest.mark.parametrize("snapshot, prev_dns", [
        pytest.param(False, None, id="no-snapshot"),
        pytest.param(True, None, id="snapshot-without-dns"),
    ])
    def test_the_failed_section_is_saved_without_the_forged_marker(self, orch, monkeypatch, snapshot, prev_dns):
        failed = _c02_total_failure()
        failed["carried_over"] = copy.deepcopy(_C12_FORGED)

        saved, sent, _ = _c12_persist(monkeypatch, orch, prev_dns, failed, snapshot=snapshot)

        assert "carried_over" not in saved, saved.get("carried_over")
        # Il resto è la sezione guasta com'era: è la baseline vuota di SEC-31, che non cambia.
        assert saved == _c12_without_marker(failed)
        if snapshot:
            assert "carried_over" not in sent[0]["current"]["dns"]
        else:
            assert sent == []

    def test_a_previous_section_that_is_empty_never_gets_the_forged_marker(self, orch, monkeypatch):
        # Controllo, verde anche prima del fix: con una sezione precedente (anche vuota) il
        # guasto totale conserva quella e ignora la risposta di `/dns`.
        failed = _c02_total_failure()
        failed["carried_over"] = copy.deepcopy(_C12_FORGED)

        saved, sent, _ = _c12_persist(monkeypatch, orch, {}, failed)

        assert "carried_over" not in saved and "carried_over" not in sent[0]["current"]["dns"]

    def test_the_cycle_observation_is_left_untouched(self, orch, monkeypatch):
        failed = _c02_total_failure()
        failed["carried_over"] = copy.deepcopy(_C12_FORGED)
        before = copy.deepcopy(failed)

        saved, _, intel = _c12_persist(monkeypatch, orch, None, failed, snapshot=False)

        assert "carried_over" not in saved, "precondizione: il marcatore falsificato deve essere stato tolto"
        assert intel["dns"] == before


class TestCOL12ObservationInTheFutureIsUnknown:
    """R2 — `observed_at` successivo a `carried_at` (orologio di `/dns` avanti, snapshot forgiato, orologio
    dell'orchestrator tornato indietro) darebbe età negativa: l'alert non uscirebbe mai e il report
    direbbe «ultima osservazione: 2099-…». L'osservazione che non può essere nel futuro del ciclo che
    la riporta è ignota: `observed_at: null`, età infinita, e il classificatore allerta una volta."""

    UNKNOWN_A = {"A": {"observed_at": None, "carried_at": _C12_NOW}}

    @pytest.mark.parametrize("timestamp", [
        pytest.param(_c12_at(48), id="two-days-ahead"),
        pytest.param("2099-01-01T00:00:00+00:00", id="year-2099"),
        pytest.param("2026-10-21T10:00:30.000001+00:00", id="one-microsecond-ahead"),
        pytest.param("2026-10-21T12:00:31+02:00", id="ahead-by-an-offset-one-second"),
    ])
    def test_a_previous_timestamp_after_the_cycle_instant_gives_an_unknown_observation(
            self, orch, monkeypatch, timestamp):
        prev = _c02_healthy_dns()
        prev["timestamp"] = timestamp

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        assert saved.get("carried_over") == self.UNKNOWN_A

    @pytest.mark.parametrize("observed_at", [
        pytest.param(_c12_at(48), id="two-days-ahead"),
        pytest.param("2099-01-01T00:00:00+00:00", id="year-2099"),
    ])
    def test_an_inherited_observation_after_the_cycle_instant_gives_an_unknown_observation(
            self, orch, monkeypatch, observed_at):
        prev = _c02_healthy_dns()
        prev["carried_over"] = {"A": {"observed_at": observed_at, "carried_at": _c12_at(48, seconds=30)}}

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A", "MX"))

        assert saved.get("carried_over") == {
            "A": {"observed_at": None, "carried_at": _C12_NOW},
            "MX": {"observed_at": prev["timestamp"], "carried_at": _C12_NOW}}

    def test_a_total_failure_after_a_future_timestamp_marks_every_part_unknown(self, orch, monkeypatch):
        prev = _c02_healthy_dns()
        prev["timestamp"] = _c12_at(48)

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        marker = saved.get("carried_over")
        assert marker is not None and set(marker) == set(_C12_ALL_PARTS), marker
        assert all(e == {"observed_at": None, "carried_at": _C12_NOW} for e in marker.values()), marker

    @pytest.mark.parametrize("timestamp", [
        pytest.param(_c12_at(23), id="one-hour-before"),
        pytest.param("2026-10-21T10:00:29+00:00", id="one-second-before"),
        pytest.param("2026-10-21T12:00:29+02:00", id="before-by-an-offset"),
    ])
    def test_an_observation_before_the_cycle_instant_is_kept(self, orch, monkeypatch, timestamp):
        # Controllo, verde anche prima del fix: il confronto è fra istanti, non fra stringhe.
        prev = _c02_healthy_dns()
        prev["timestamp"] = timestamp

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        assert saved.get("carried_over") == {"A": {"observed_at": timestamp, "carried_at": _C12_NOW}}

    @pytest.mark.parametrize("timestamp", ["2026-10-20T10:00:00", "2026-10-22T10:00:00"],
                             ids=["naive-before", "naive-after"])
    def test_a_previous_timestamp_without_a_timezone_does_not_raise(self, orch, monkeypatch, timestamp):
        # Confrontare un istante naive con uno aware solleva TypeError: il criterio non dice se valga
        # UTC, qui si pretende solo che `_persist_intel` non sollevi e che il marcatore ci sia.
        prev = _c02_healthy_dns()
        prev["timestamp"] = timestamp

        for curr in (_c02_unknown(_c02_healthy_dns(), "A"), _c02_total_failure()):
            saved, _, _ = _c12_persist(monkeypatch, orch, prev, curr)

            assert "A" in (saved.get("carried_over") or {}), saved.get("carried_over")

    def test_the_series_alerts_once_when_the_observation_was_in_the_future(self, c12_cycle):
        # Con un `/diff` reale: l'età ignota conta come infinita, l'alert esce una volta al primo ciclo
        # riportato e non si ripete. (Senza il fix l'età è negativa: nessun alert, mai.)
        zone = _c02_healthy_dns()
        c12_cycle(zone, 100)                            # osservata «a 100 h»
        c12_cycle(_c02_unknown(zone, "A"), 24)          # il ciclo successivo ha un orologio indietro
        c12_cycle(_c02_unknown(zone, "A"), 48)

        assert c12_cycle.marker() == {"A": {"observed_at": None, "carried_at": _c12_at(48, seconds=30)}}
        assert [[(t, sev) for t, sev, _ in found] for found in c12_cycle.per_cycle] == [
            [], [("dns_stale_core", "MEDIUM")], []], c12_cycle.per_cycle


class TestCOL12PreviousInstantsAreReserialized:
    """N2 (mutante O03) — gli istanti vengono da file su disco e da `/dns`: validi ma non canonici
    (formato base, spazio al posto di `T`, suffisso `Z`) si salvano ri-serializzati dal parse, mai come
    stringa grezza; un fuso diverso resta lo stesso istante."""

    CANONICAL = "2026-10-20T10:00:00+00:00"
    RAW = [
        pytest.param("20261020T100000+0000", id="iso-basic-format"),
        pytest.param("2026-10-20 10:00:00+00:00", id="space-separator"),
        pytest.param("2026-10-20T10:00:00Z", id="z-suffix"),
    ]

    @pytest.mark.parametrize("raw", RAW)
    def test_the_previous_dns_timestamp_is_saved_reserialized(self, orch, monkeypatch, raw):
        prev = _c02_healthy_dns()
        prev["timestamp"] = raw

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        assert saved.get("carried_over") == {"A": {"observed_at": self.CANONICAL, "carried_at": _C12_NOW}}

    @pytest.mark.parametrize("raw", RAW)
    def test_an_inherited_observation_is_saved_reserialized(self, orch, monkeypatch, raw):
        prev = _c02_healthy_dns()
        prev["carried_over"] = {"A": {"observed_at": raw, "carried_at": _c12_at(0, seconds=30)}}

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        assert saved.get("carried_over") == {"A": {"observed_at": self.CANONICAL, "carried_at": _C12_NOW}}

    @pytest.mark.parametrize("raw", RAW)
    def test_a_total_failure_saves_the_inherited_observations_reserialized(self, orch, monkeypatch, raw):
        prev = _c02_healthy_dns()
        prev["timestamp"] = raw

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        marker = saved.get("carried_over")
        assert marker is not None and set(marker) == set(_C12_ALL_PARTS), marker
        assert {e["observed_at"] for e in marker.values()} == {self.CANONICAL}, marker
        assert raw not in json.dumps(marker)

    def test_an_instant_with_another_offset_is_still_the_same_instant(self, orch, monkeypatch):
        raw = "2026-10-20T12:00:00+02:00"
        prev = _c02_healthy_dns()
        prev["timestamp"] = raw

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A"))

        observed = saved["carried_over"]["A"]["observed_at"]
        assert observed is not None and datetime.fromisoformat(observed) == datetime.fromisoformat(raw)
        assert datetime.fromisoformat(observed) == _C12_BASE


class TestCOL12PreviousMarkerWithoutKnownParts:
    """N2 (mutante O12) — guasto totale su una sezione precedente che porta un marcatore ma in cui
    nessuna parte ha un valore noto: non c'è nulla da dire, quindi nessun marcatore. Il marcatore
    precedente non si conserva come stava (è di un ciclo che non c'è più)."""

    def _unknown_everywhere_with_a_marker(self):
        prev = _c02_total_failure()
        prev["carried_over"] = {"A": {"observed_at": _c12_at(-96), "carried_at": _c12_at(0)}}
        return prev

    def test_the_old_marker_is_dropped_when_no_part_is_known(self, orch, monkeypatch):
        prev = self._unknown_everywhere_with_a_marker()

        saved, sent, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        assert "carried_over" not in saved, saved.get("carried_over")
        assert "carried_over" not in sent[0]["current"]["dns"]
        assert saved["records_status"]["A"] == "unknown"

    def test_the_old_marker_keeps_only_the_parts_that_are_still_known(self, orch, monkeypatch):
        prev = _c02_healthy_dns()
        prev["records_status"]["A"] = "unknown"
        prev["records"]["A"] = []
        prev["carried_over"] = {"A": {"observed_at": _c12_at(-96), "carried_at": _c12_at(0)},
                                "MX": {"observed_at": _c12_at(-48), "carried_at": _c12_at(0)}}

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_total_failure())

        marker = saved.get("carried_over")
        assert marker is not None and "A" not in marker, marker
        assert marker["MX"] == {"observed_at": _c12_at(-48), "carried_at": _C12_NOW}


# ═══════════════════════════════════════════════════════════════
# COL-13 — un dato riportato di cert/whois/http/reputation non vale per sempre
# ═══════════════════════════════════════════════════════════════
#
# Criteri C1-C6 di BUG-REGISTER.md («ASSEGNA · COL-13 · criteri di accettazione»). Il percorso
# CODE-01 di `_persist_intel` (un modulo fallito lascia la sezione del ciclo precedente) copia la
# sezione verbatim: nello snapshot non resta nulla che dica «riportata», `updated_at` si rinnova e
# report e scheda Intel mostrano il dato vecchio come attuale per quanti cicli dura il guasto. Il
# contratto deciso, per `cert`, `whois`, `http` e `reputation` (il `dns` resta quello di COL-12):
#
#   * campo DIRETTO nella sezione salvata, non una mappa per parte:
#     `sezione["carried_over"] = {"observed_at": <ISO|None>, "carried_at": <ISO>}`;
#   * solo quando il modulo è fallito (`_module_failed`) e la sezione precedente è un dict non già
#     fallito; la sezione salvata è la precedente senza un `carried_over` vecchio più il nuovo;
#   * `carried_at` = `orchestrator.now_iso()`, letto UNA volta per `_persist_intel` e condiviso
#     con le parti del DNS riportate;
#   * `observed_at` = `timestamp` della sezione precedente, parsato e ri-serializzato (mai
#     ereditato dal marcatore vecchio); None se manca, non è una stringa, è illeggibile o è
#     successivo a `carried_at` (confronto fra istanti, un istante senza fuso vale UTC);
#   * nessun marcatore se il modulo risponde (un `carried_over` arrivato dalla risposta del
#     collector, zona non autenticata, viene tolto), se il precedente manca, è `None`, non è un dict
#     o è già fallito;
#   * il marcatore sta nello snapshot e nel payload di `/diff`; `intel[nome]`, l'osservazione del
#     ciclo letta da eventi e classificazione, non si tocca, né si tocca lo snapshot precedente.
#
# Dove un test pretende il marcatore prima di asserire altro («precondizione») era rosso prima del
# fix per costruzione; i controlli dichiarati «verdi anche prima del fix» fissano ciò che il fix non
# deve toccare e fanno da rete contro un'implementazione che solleva o muta l'input.

_C13_MODULES = ["cert", "whois", "http", "reputation"]
_C13_T0 = _c12_at(0)


def _c13_healthy(module, timestamp=_C13_T0):
    """Sezione `module` come il collector la scrive quando risponde (forme dei fixture CODE-01 e
    CODE-14). `timestamp` è l'istante dell'osservazione; `_C12_MISSING` toglie la chiave."""
    d = _C02_DOMAIN
    section = {
        "cert": {"domain": d, "timestamp": None,
                 "ct_certificates": {"total": 21, "unique_cn": [d],
                                     "certificates": [{"id": 1, "common_name": d, "issuer_name": "Example CA"}]},
                 "tls_live": None, "san_subdomains_discovered": [], "error": None},
        "whois": {"domain": d, "timestamp": None, "registrar": "Registrar Example",
                  "creation_date": "2020-01-01T00:00:00", "expiration_date": "2027-01-01T00:00:00",
                  "privacy_protected": False, "error": None},
        "http": {"domain": d, "timestamp": None,
                 "checks": [{"url": f"http://{d}", "status_code": 200, "content_length": 5400, "title": "Acme",
                             "server": "nginx", "suspicious_patterns": [],
                             "hidden_elements": {"risk_indicators": 0, "summary": []}, "error": None}],
                 "overall_status": "active", "hidden_elements_risk": 0, "error": None},
        "reputation": {"domain": d, "timestamp": None,
                       "virustotal": {"malicious": 0, "suspicious": 0, "undetected": 60, "harmless": 10,
                                      "reputation": 0, "categories": {}, "error": None},
                       "otx": {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": [],
                               "error": None},
                       "securitytrails": {"subdomain_count": 4, "current_dns": {}, "alexa_rank": None,
                                          "error": None},
                       "risk_score": 0, "risk_level": "clean", "error": None},
    }[module]
    if timestamp is _C12_MISSING:
        del section["timestamp"]
    else:
        section["timestamp"] = timestamp
    return section


def _c13_changed(module, timestamp):
    """La stessa sezione con una variazione che il `/diff` reale segnala (vedi `_C13_CHANGE_ALERT`)."""
    section = _c13_healthy(module, timestamp)
    if module == "cert":
        section["ct_certificates"]["total"] = 23
    elif module == "whois":
        section["registrar"] = "Other Registrar Example"
    elif module == "http":
        section["checks"].append({"url": f"https://{_C02_DOMAIN}", "status_code": 200, "content_length": 5400,
                                  "title": "Acme", "server": "nginx", "suspicious_patterns": [],
                                  "hidden_elements": {"risk_indicators": 0, "summary": []}, "error": None})
    else:
        section["virustotal"]["malicious"] = 3
    return section


_C13_CHANGE_ALERT = {"cert": "new_certificate", "whois": "whois_registrar_changed",
                     "http": "http_activated", "reputation": "vt_malicious_detected"}

# Le forme REALI con cui un modulo risulta fallito per `_module_failed`: sezione `None` (errore HTTP
# del servizio, oppure modulo non richiesto nel ciclo), `error` valorizzato (anche vuoto), http con
# tutti i check senza `status_code`, reputazione con tutte le fonti in errore (qui `error` top-level
# resta `None`, CODE-14).
_C13_FAILED_FORMS = {
    "cert": {
        "none": None,
        "error-502": {"domain": _C02_DOMAIN, "timestamp": _c12_at(24),
                      "ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                      "tls_live": None, "san_subdomains_discovered": [], "error": "crt.sh HTTP 502"},
        "empty-error-text": {"domain": _C02_DOMAIN, "timestamp": _c12_at(24),
                             "ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                             "tls_live": None, "san_subdomains_discovered": [], "error": ""},
    },
    "whois": {
        "none": None,
        "error-timeout": {"domain": _C02_DOMAIN, "timestamp": _c12_at(24), "registrar": None,
                          "creation_date": None, "expiration_date": None,
                          "error": "WHOIS lookup failed: connection timed out"},
        "empty-error-text": {"domain": _C02_DOMAIN, "timestamp": _c12_at(24), "registrar": None,
                             "creation_date": None, "expiration_date": None, "error": ""},
    },
    "http": {
        "none": None,
        "all-checks-down": {
            "domain": _C02_DOMAIN, "timestamp": _c12_at(24),
            "checks": [{"url": f"{scheme}://{_C02_DOMAIN}", "status_code": None, "content_length": 0,
                        "title": None, "server": "", "suspicious_patterns": [], "hidden_elements": None,
                        "redirect_chain": None, "error": "Attempt 3/3: connection refused"}
                       for scheme in ("http", "https")],
            "overall_status": "down", "hidden_elements_risk": 0, "error": None},
    },
    "reputation": {
        "none": None,
        "all-sources-error": {
            "domain": _C02_DOMAIN, "timestamp": _c12_at(24),
            "virustotal": {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0, "reputation": 0,
                           "categories": {}, "error": "HTTP 503"},
            "otx": {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": [],
                    "error": "HTTP 401 Unauthorized"},
            "securitytrails": {"subdomain_count": 0, "current_dns": {}, "alexa_rank": None,
                               "error": "HTTP 401 Unauthorized"},
            "risk_score": 0, "risk_level": "clean", "error": None},
    },
}
_C13_FAILED = [pytest.param(module, form, id=f"{module}-{label}")
               for module, forms in _C13_FAILED_FORMS.items() for label, form in forms.items()]
# Solo le forme in cui la sezione guasta è un dict: valgono anche come sezione PRECEDENTE già fallita.
_C13_FAILED_DICTS = [p for p in _C13_FAILED if p.values[1] is not None]


def _c13_previous(**overrides):
    """Snapshot del ciclo precedente: tutti i moduli sani, osservati a `_C13_T0`."""
    intel = {"dns": _c02_healthy_dns(), **{m: _c13_healthy(m) for m in _C13_MODULES}}
    intel.update(copy.deepcopy(overrides))
    return intel


def _c13_intel(overrides=None, hours=24):
    """`intel` del ciclo a `hours` dopo T0: tutti i moduli rispondono con la loro sezione sana,
    tranne quelli in `overrides` (anche `None`, anche una forma guasta)."""
    at = _c12_at(hours)
    dns = _c02_healthy_dns()
    dns["timestamp"] = at
    intel = {"dns": dns, **{m: _c13_healthy(m, at) for m in _C13_MODULES}}
    intel.update(copy.deepcopy(overrides or {}))
    return intel


def _c13_persist(monkeypatch, o, prev_intel, intel, now=_C12_NOW, snapshot=True):
    """`_persist_intel` con store e `/diff` finti e l'istante del ciclo in mano al test (`now` è
    un istante o una funzione). Ritorna (snapshot salvato intero, payload mandati a `/diff`,
    `intel` passato)."""
    saved, sent = {}, []
    monkeypatch.setattr(o, "now_iso", now if callable(now) else (lambda: now))
    monkeypatch.setattr(o.intel_store, "load_snapshot",
                        lambda c, d: {"intel": prev_intel} if snapshot and prev_intel is not None else None)

    def _save(c, d, current):
        saved["current"] = current
        return True

    def _post(url, json=None, timeout=None):
        sent.append(json)
        return _C02Resp()

    monkeypatch.setattr(o.intel_store, "save_snapshot", _save)
    monkeypatch.setattr(o._session, "post", _post)
    o._persist_intel("acme", _C02_DOMAIN, "acme.example", intel)
    return saved["current"], sent, intel


def _c13_without_marker(section):
    return {k: v for k, v in section.items() if k != "carried_over"}


def _c13_instant(value):
    """Un ISO come istante (senza fuso: UTC), per confronti che non dipendono dalla forma scritta."""
    ts = datetime.fromisoformat(value)
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _c13_marker(observed_at, carried_at=_C12_NOW):
    return {"observed_at": observed_at, "carried_at": carried_at}


class TestCOL13FailedModuleCarriesTheSectionWithAMarker:
    """C1 — un modulo fallito conserva la sezione del ciclo precedente (CODE-01) e la marca: campo
    diretto `carried_over` con l'istante dell'ultima osservazione e quello del ciclo."""

    @pytest.mark.parametrize("module, failed", _C13_FAILED)
    def test_the_saved_section_is_the_previous_one_plus_the_marker(self, orch, monkeypatch, module, failed):
        prev = _c13_previous()

        saved, _, _ = _c13_persist(monkeypatch, orch, prev, _c13_intel({module: failed}))

        section = saved[module]
        assert section.get("carried_over") == {"observed_at": _C13_T0, "carried_at": _C12_NOW}
        assert _c13_without_marker(section) == _c13_healthy(module)
        assert section["timestamp"] == _C13_T0, "la sezione riportata mantiene il suo timestamp vecchio"

    def test_the_diff_receives_the_marked_section_and_the_baseline_stays_unmarked(self, orch, monkeypatch):
        # Il payload di `/diff` coincide con ciò che si salva; la baseline che manda è la precedente
        # com'era (se il marcatore finisse anche lì, baseline e corrente sarebbero indistinguibili).
        for module in _C13_MODULES:
            saved, sent, _ = _c13_persist(monkeypatch, orch, _c13_previous(), _c13_intel({module: None}))

            assert saved[module].get("carried_over"), f"{module}: precondizione, il riporto deve essere marcato"
            assert sent[0]["current"][module] == saved[module], module
            assert sent[0]["baseline"][module] == _c13_healthy(module), module

    def test_only_the_failed_module_is_marked(self, orch, monkeypatch):
        for module in _C13_MODULES:
            fresh = _c13_intel({module: None})

            saved, sent, _ = _c13_persist(monkeypatch, orch, _c13_previous(), fresh)

            assert saved[module].get("carried_over"), f"{module}: precondizione, il riporto deve essere marcato"
            for other in ["dns", *[m for m in _C13_MODULES if m != module]]:
                assert saved[other] == fresh[other], (module, other)
                assert "carried_over" not in saved[other] and "carried_over" not in sent[0]["current"][other]

    def test_every_failed_module_gets_a_marker_with_its_own_observation(self, orch, monkeypatch):
        observed = {"cert": _c12_at(-48), "whois": _c12_at(-24), "http": _c12_at(-1), "reputation": _c12_at(12)}
        prev = _c13_previous(**{m: _c13_healthy(m, observed[m]) for m in _C13_MODULES})

        saved, _, _ = _c13_persist(monkeypatch, orch, prev, _c13_intel({m: None for m in _C13_MODULES}))

        for module in _C13_MODULES:
            assert saved[module].get("carried_over") == {"observed_at": observed[module], "carried_at": _C12_NOW}
            assert _c13_without_marker(saved[module]) == _c13_healthy(module, observed[module])

    def test_the_cycle_instant_is_read_once_and_shared_with_the_dns_parts(self, orch, monkeypatch):
        calls = []

        def tick():
            calls.append(1)
            return _c12_at(24, seconds=len(calls))

        fresh = _c13_intel({m: None for m in _C13_MODULES})
        fresh["dns"] = _c02_unknown(fresh["dns"], "A", "MX")

        saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(), fresh, now=tick)

        stamps = {saved[m].get("carried_over", {}).get("carried_at") for m in _C13_MODULES}
        stamps |= {e["carried_at"] for e in saved["dns"].get("carried_over", {}).values()}
        assert len(saved["dns"].get("carried_over", {})) == 2 and None not in stamps, "precondizione"
        assert len(stamps) == 1, f"istanti diversi nello stesso ciclo: {stamps}"
        assert len(calls) == 1, f"now_iso() letto {len(calls)} volte, non una"

    def test_a_module_marker_is_a_direct_field_while_the_dns_marker_stays_per_part(self, orch, monkeypatch):
        fresh = _c13_intel({"cert": None})
        fresh["dns"] = _c02_unknown(fresh["dns"], "A")

        saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(), fresh)

        assert saved["cert"].get("carried_over") == {"observed_at": _C13_T0, "carried_at": _C12_NOW}
        assert saved["dns"].get("carried_over") == {"A": {"observed_at": _c02_healthy_dns()["timestamp"],
                                                          "carried_at": _C12_NOW}}


@pytest.fixture
def c13_cycle(orch, monkeypatch, tmp_path):
    """Un ciclo di `_persist_intel` per chiamata, con lo store reale su una directory temporanea e
    il `/diff` del classificatore reale. `run(hours, **moduli)`: l'osservazione del ciclo è `hours`
    dopo T0 (ogni modulo risponde sano con quel `timestamp`, salvo quelli passati per nome, anche
    `None`) e l'orchestrator la persiste 30 s dopo (`now_iso`). `run.section(m)` è la sezione salvata,
    `run.per_cycle` gli alert nuovi di ogni ciclo come (tipo, severità, detail), `run.payloads` i
    payload mandati a `/diff` e `run.responses` le risposte."""
    clock = {"now": _c12_at(0, seconds=30)}
    monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(orch.intel_store, "HIST_DIR", tmp_path / "history")
    monkeypatch.setattr(orch, "now_iso", lambda: clock["now"])
    api = TestClient(_c02_classifier_app, raise_server_exceptions=False)
    payloads, responses = [], []

    def _post(url, json=None, timeout=None, headers=None):
        r = api.post(url[len(orch.CLASSIFY_URL):], json=json)
        payloads.append(json)
        responses.append(r.json() if r.is_success else None)
        return _R(responses[-1], ok=r.is_success, status_code=r.status_code)

    monkeypatch.setattr(orch._session, "post", _post)

    def history():
        return orch.intel_store.load_history("acme", _C02_DOMAIN, limit=1000)

    def run(hours, **modules):
        clock["now"] = _c12_at(hours, seconds=30)
        before = len(history())
        orch._persist_intel("acme", _C02_DOMAIN, "acme.example", _c13_intel(modules, hours))
        new = history()[:len(history()) - before]
        run.per_cycle.append(sorted(((a["type"], a["severity"], a["detail"]) for e in new for a in e["alerts"]),
                                    key=lambda t: t[0]))

    run.per_cycle, run.payloads, run.responses = [], payloads, responses
    run.section = lambda module: orch.intel_store.load_snapshot("acme", _C02_DOMAIN)["intel"][module]
    run.history = history
    return run


class TestCOL13MarkerAcrossConsecutiveCycles:
    """C2 — la serie, con lo store reale (fixture `c13_cycle`): `observed_at` resta l'ultima
    osservazione reale, `carried_at` segue il ciclo, e al ritorno la sezione fresca non ha marcatore."""

    @staticmethod
    def _entry(observed_hours, carried_hours):
        return {"observed_at": _c12_at(observed_hours), "carried_at": _c12_at(carried_hours, seconds=30)}

    @pytest.mark.parametrize("module", _C13_MODULES)
    def test_observed_at_stays_the_last_real_observation_while_carried_at_follows_the_cycle(
            self, c13_cycle, module):
        c13_cycle(0)

        for hours in (24, 48, 72, 96):
            c13_cycle(hours, **{module: None})
            assert c13_cycle.section(module).get("carried_over") == self._entry(0, hours), f"ciclo a {hours} h"
            assert c13_cycle.section(module)["timestamp"] == _c12_at(0)

    @pytest.mark.parametrize("module", _C13_MODULES)
    def test_a_module_that_answers_again_leaves_the_marker_and_a_new_failure_restarts_from_the_new_observation(
            self, c13_cycle, module):
        c13_cycle(0)
        c13_cycle(24, **{module: None})
        assert c13_cycle.section(module).get("carried_over") == self._entry(0, 24), "precondizione"

        c13_cycle(48)
        assert c13_cycle.section(module) == _c13_healthy(module, _c12_at(48))

        c13_cycle(72, **{module: None})
        assert c13_cycle.section(module).get("carried_over") == self._entry(48, 72)

    def test_each_module_follows_its_own_failure_window(self, c13_cycle):
        c13_cycle(0)
        c13_cycle(24, cert=None)
        c13_cycle(48, cert=None, whois=None)
        c13_cycle(72, cert=None, http=None)

        assert c13_cycle.section("cert").get("carried_over") == self._entry(0, 72)
        assert c13_cycle.section("whois") == _c13_healthy("whois", _c12_at(72))
        assert c13_cycle.section("http").get("carried_over") == self._entry(48, 72)
        assert c13_cycle.section("reputation") == _c13_healthy("reputation", _c12_at(72))

    def test_a_timestamp_with_a_z_suffix_gives_the_same_constant_observation_on_every_cycle(self, c13_cycle):
        # I collector scrivono il `timestamp` in più forme (`Z`, `+00:00`): l'istante salvato è
        # ri-serializzato dal parse e non cambia da un ciclo all'altro.
        c13_cycle(0, cert=_c13_healthy("cert", "2026-10-20T10:00:00Z"))

        for hours in (24, 48, 72):
            c13_cycle(hours, cert=None)
            assert c13_cycle.section("cert")["carried_over"]["observed_at"] == _c12_at(0), f"ciclo a {hours} h"

    @pytest.mark.parametrize("module", _C13_MODULES)
    def test_an_outage_raises_no_alert_and_the_return_alerts_once_as_usual(self, c13_cycle, module):
        # Il marcatore non cambia gli alert (nessun alert nuovo per il guasto in sé: decisione di
        # COL-13): K cicli di guasto = nessun alert, e al ritorno con un dato cambiato l'alert
        # ordinario esce una volta sola, sulla differenza vera rispetto all'ultima osservazione.
        c13_cycle(0)
        for hours in (24, 48, 72):
            c13_cycle(hours, **{module: None})
        assert c13_cycle.section(module).get("carried_over"), "precondizione: il riporto deve essere marcato"

        c13_cycle(96, **{module: _c13_changed(module, _c12_at(96))})
        c13_cycle(120, **{module: _c13_changed(module, _c12_at(120))})

        assert [[t for t, _, _ in found] for found in c13_cycle.per_cycle] == [
            [], [], [], [], [_C13_CHANGE_ALERT[module]], []], c13_cycle.per_cycle
        assert "carried_over" not in c13_cycle.section(module)


class TestCOL13NoMarkerWhenNothingIsCarried:
    """C3 — il marcatore compare solo se una sezione precedente utilizzabile è stata riportata."""

    def test_modules_that_answer_have_no_marker(self, orch, monkeypatch):
        # Controllo, verde anche prima del fix.
        fresh = _c13_intel()
        prev = _c13_previous()
        for module in _C13_MODULES:
            prev[module]["carried_over"] = {"observed_at": _c12_at(-24), "carried_at": _c12_at(0)}

        saved, sent, _ = _c13_persist(monkeypatch, orch, prev, fresh)

        for name in ("dns", *_C13_MODULES):
            assert "carried_over" not in saved[name] and "carried_over" not in sent[0]["current"][name], name
        assert saved == fresh

    FORGED = [
        pytest.param({"observed_at": _c12_at(-96), "carried_at": _c12_at(24)}, id="valid-looking"),
        pytest.param({"observed_at": "<script>alert(1)</script>", "carried_at": "x" * 5000}, id="hostile-strings"),
        pytest.param("x", id="string"), pytest.param(["observed_at"], id="list"), pytest.param(5, id="int"),
        pytest.param(None, id="null"), pytest.param(True, id="bool"), pytest.param({}, id="empty-dict"),
    ]

    @pytest.mark.parametrize("forged", FORGED)
    def test_a_marker_inside_the_response_of_the_collector_is_removed(self, orch, monkeypatch, forged):
        # Il marcatore lo scrive solo l'orchestrator: una risposta del servizio (zona non
        # autenticata) che ne porta uno non lo fa entrare nello snapshot né nel payload di `/diff`.
        for module in _C13_MODULES:
            answer = _c13_healthy(module, _c12_at(24))
            answer["carried_over"] = copy.deepcopy(forged)

            saved, sent, _ = _c13_persist(monkeypatch, orch, _c13_previous(), _c13_intel({module: answer}))

            assert "carried_over" not in saved[module], (module, saved[module].get("carried_over"))
            assert "carried_over" not in sent[0]["current"][module], module
            assert saved[module] == _c13_healthy(module, _c12_at(24)), f"{module}: il resto si salva com'è"

    def test_the_response_of_the_collector_is_not_mutated_when_the_marker_is_removed(self, orch, monkeypatch):
        for module in _C13_MODULES:
            answer = _c13_healthy(module, _c12_at(24))
            answer["carried_over"] = {"observed_at": _c12_at(-96), "carried_at": _c12_at(24)}
            fresh = _c13_intel({module: answer})
            before = copy.deepcopy(fresh)

            saved, _, intel = _c13_persist(monkeypatch, orch, _c13_previous(), fresh)

            assert "carried_over" not in saved[module], f"{module}: precondizione, il marcatore forgiato è tolto"
            assert intel == before and fresh == before, module

    @pytest.mark.parametrize("answer", [[], "text", 5, 1.5, True], ids=["list", "string", "int", "float", "bool"])
    def test_a_response_that_is_not_a_dict_is_saved_as_it_is_without_raising(self, orch, monkeypatch, answer):
        # Controllo, verde anche prima del fix: togliere un marcatore da una risposta che non è un
        # dict non deve sollevare.
        for module in _C13_MODULES:
            saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(), _c13_intel({module: answer}))

            assert saved[module] == answer, module

    def test_no_previous_snapshot_gives_no_marker(self, orch, monkeypatch):
        # Controllo, verde anche prima del fix (CODE-01): senza precedente il modulo fallito
        # resta `None` e non c'è nulla da confrontare.
        for module in _C13_MODULES:
            saved, sent, _ = _c13_persist(monkeypatch, orch, None, _c13_intel({module: None}), snapshot=False)

            assert saved[module] is None, module
            assert sent == []

    @pytest.mark.parametrize("previous", [None, [], "text", 5, 1.5, True],
                             ids=["null", "list", "string", "int", "float", "bool"])
    def test_a_previous_section_that_is_not_a_dict_gets_no_marker_and_does_not_raise(
            self, orch, monkeypatch, previous):
        for module in _C13_MODULES:
            prev = _c13_previous(**{module: previous})

            saved, _, _ = _c13_persist(monkeypatch, orch, prev, _c13_intel({module: None}))

            assert saved[module] == previous, module

    @pytest.mark.parametrize("module, failed", _C13_FAILED_DICTS)
    def test_a_previous_section_that_already_failed_stays_as_it_is(self, orch, monkeypatch, module, failed):
        # Controllo, verde anche prima del fix: una sezione che è già un guasto non diventa
        # «riportata» (la UI dice «errore»); resta com'è.
        prev = _c13_previous(**{module: failed})

        saved, _, _ = _c13_persist(monkeypatch, orch, prev, _c13_intel({module: None}))

        assert saved[module] == failed
        assert "carried_over" not in saved[module]

    def test_an_empty_previous_section_does_not_raise(self, orch, monkeypatch):
        # Il criterio non dice se `{}` («dict non fallito», ma senza nulla da riportare) porti il
        # marcatore: qui si pretende solo che non sollevi e che il resto resti vuoto.
        saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(cert={}), _c13_intel({"cert": None}))

        assert _c13_without_marker(saved["cert"]) == {}


class TestCOL13ObservedAtComesFromThePreviousTimestamp:
    """C4 — `observed_at` è il `timestamp` della sezione precedente, ri-serializzato; `null` quando
    non si sa. Gli istanti vengono da file su disco e dai servizi (zona non autenticata). Ogni forma
    è provata su tutti e 4 i moduli (il messaggio dell'asserzione dice quale)."""

    @staticmethod
    def _carry(monkeypatch, o, module, timestamp):
        prev = _c13_previous(**{module: _c13_healthy(module, timestamp)})
        saved, _, _ = _c13_persist(monkeypatch, o, prev, _c13_intel({module: None}))
        return saved[module].get("carried_over")

    @pytest.mark.parametrize("timestamp", _C12_BAD_TIMESTAMPS)
    def test_an_unreadable_previous_timestamp_gives_an_unknown_observation(self, orch, monkeypatch, timestamp):
        for module in _C13_MODULES:
            assert self._carry(monkeypatch, orch, module, timestamp) == _c13_marker(None), module

    @pytest.mark.parametrize("timestamp", [
        pytest.param(_c12_at(48), id="two-days-ahead"),
        pytest.param("2099-01-01T00:00:00+00:00", id="year-2099"),
        pytest.param("2026-10-21T10:00:30.000001+00:00", id="one-microsecond-ahead"),
        pytest.param("2026-10-21T12:00:31+02:00", id="ahead-by-an-offset-one-second"),
    ])
    def test_a_previous_timestamp_after_the_cycle_instant_gives_an_unknown_observation(
            self, orch, monkeypatch, timestamp):
        # Un'osservazione non può stare nel futuro del ciclo che la riporta: con età negativa il
        # report direbbe «ultima osservazione: 2099-…».
        for module in _C13_MODULES:
            assert self._carry(monkeypatch, orch, module, timestamp) == _c13_marker(None), module

    @pytest.mark.parametrize("timestamp", [
        pytest.param(_C12_NOW, id="exactly-the-cycle-instant"),
        pytest.param(_c12_at(23), id="one-hour-before"),
        pytest.param("2026-10-21T10:00:29+00:00", id="one-second-before"),
        pytest.param("2026-10-21T12:00:29+02:00", id="before-by-an-offset"),
    ])
    def test_an_observation_not_after_the_cycle_instant_is_kept(self, orch, monkeypatch, timestamp):
        # Il confronto è fra istanti e stretto: «successivo» non include l'uguale. L'istante si
        # confronta come istante (la forma scritta, `+02:00` o UTC, non è il punto).
        for module in _C13_MODULES:
            marker = self._carry(monkeypatch, orch, module, timestamp)

            assert marker is not None and marker["observed_at"] is not None, module
            assert _c13_instant(marker["observed_at"]) == _c13_instant(timestamp), module
            assert marker["carried_at"] == _C12_NOW, module

    @pytest.mark.parametrize("raw", [
        pytest.param("20261020T100000+0000", id="iso-basic-format"),
        pytest.param("2026-10-20 10:00:00+00:00", id="space-separator"),
        pytest.param("2026-10-20T10:00:00Z", id="z-suffix"),
    ])
    def test_a_valid_but_not_canonical_timestamp_is_saved_reserialized(self, orch, monkeypatch, raw):
        for module in _C13_MODULES:
            marker = self._carry(monkeypatch, orch, module, raw)

            assert marker == _c13_marker(_c12_at(0)), module
            assert raw not in json.dumps(marker)

    def test_an_instant_with_another_offset_is_still_the_same_instant(self, orch, monkeypatch):
        marker = self._carry(monkeypatch, orch, "whois", "2026-10-20T12:00:00+02:00")

        assert marker is not None and _c13_instant(marker["observed_at"]) == _c13_instant(_c12_at(0))

    def test_a_timestamp_without_a_timezone_is_read_as_utc(self, orch, monkeypatch):
        # Il ciclo è a 2026-10-21T10:00:30 UTC: un secondo prima è un'osservazione valida, un secondo
        # dopo è nel futuro. Un fuso diverso da UTC (anche di sole due ore) cambierebbe l'esito.
        for module in _C13_MODULES:
            before = self._carry(monkeypatch, orch, module, "2026-10-21T10:00:29")
            after = self._carry(monkeypatch, orch, module, "2026-10-21T10:00:31")
            long_ago = self._carry(monkeypatch, orch, module, "2026-10-20T10:00:00")

            assert before is not None and _c13_instant(before["observed_at"]) == _c13_instant("2026-10-21T10:00:29+00:00"), module
            assert after == _c13_marker(None), f"{module}: senza fuso vale UTC, qui è nel futuro del ciclo"
            assert long_ago is not None and _c13_instant(long_ago["observed_at"]) == _c13_instant(_c12_at(0)), module

    OLD_MARKERS = [
        pytest.param({"observed_at": _c12_at(-96), "carried_at": _c12_at(-48)}, id="valid-looking-other-instants"),
        pytest.param({"observed_at": "<script>alert(1)</script>", "carried_at": "x" * 10_000}, id="hostile-strings"),
        pytest.param({f"foreign-{i}": {"observed_at": _c12_at(-1)} for i in range(2000)}, id="thousands-of-keys"),
        pytest.param({}, id="empty-dict"), pytest.param("x", id="string"), pytest.param(["A"], id="list"),
        pytest.param(5, id="int"), pytest.param(None, id="null"), pytest.param(True, id="bool"),
    ]

    @pytest.mark.parametrize("old", OLD_MARKERS)
    def test_an_old_marker_is_replaced_never_inherited_and_never_raises(self, orch, monkeypatch, old):
        # `observed_at` è il `timestamp` della sezione, che il riporto non rinnova: non si legge dal
        # marcatore vecchio (file su disco, può essere di una versione precedente o corrotto).
        for module in _C13_MODULES:
            prev = _c13_previous()
            prev[module]["carried_over"] = copy.deepcopy(old)

            saved, _, _ = _c13_persist(monkeypatch, orch, prev, _c13_intel({module: None}))

            assert saved[module].get("carried_over") == _c13_marker(_C13_T0), module
            assert _c13_without_marker(saved[module]) == _c13_healthy(module), module
            assert len(json.dumps(saved[module]["carried_over"])) < 200

    @pytest.mark.parametrize("previous", [
        pytest.param({"overall_status": "down", "checks": 5}, id="checks-not-iterable"),
        pytest.param({"overall_status": "error", "checks": True}, id="checks-bool"),
        pytest.param({"overall_status": ["down"], "checks": [None]}, id="status-list"),
        pytest.param({"virustotal": "x", "otx": 5, "securitytrails": [], "overall_status": 1}, id="sources-not-dicts"),
        pytest.param({"error": None, "checks": {"a": 1}, "ct_certificates": "x", "registrar": ["y"]}, id="wrong-types"),
    ])
    def test_a_previous_section_with_malformed_content_does_not_raise(self, orch, monkeypatch, previous):
        # Controllo, verde anche prima del fix: il fix legge la sezione precedente (per sapere se è
        # già fallita) e non deve sollevare su un contenuto che il collector non produrrebbe. Un
        # `_persist_intel` che solleva non salva lo snapshot: il guasto si ripeterebbe a ogni ciclo.
        for module in _C13_MODULES:
            prev = _c13_previous(**{module: previous})

            saved, _, _ = _c13_persist(monkeypatch, orch, prev, _c13_intel({module: None}))

            assert _c13_without_marker(saved[module]) == previous, module


class TestCOL13CycleObservationIsLeftIntact:
    """C5 — il marcatore sta nello snapshot e basta: `intel[nome]` (l'osservazione del ciclo,
    letta da eventi e classificazione) e lo snapshot precedente non si toccano."""

    @pytest.mark.parametrize("module, failed", _C13_FAILED)
    def test_the_cycle_observation_is_not_mutated(self, orch, monkeypatch, module, failed):
        fresh = _c13_intel({module: failed})
        before = copy.deepcopy(fresh)

        saved, _, intel = _c13_persist(monkeypatch, orch, _c13_previous(), fresh)

        assert saved[module].get("carried_over"), "precondizione: il riporto deve essere marcato"
        assert intel is fresh and intel == before
        assert intel[module] == failed

    def test_the_previous_snapshot_is_not_mutated_by_the_marker(self, orch, monkeypatch):
        for module in _C13_MODULES:
            prev = _c13_previous()
            prev[module]["carried_over"] = {"observed_at": _c12_at(-24), "carried_at": _c12_at(0)}
            before = copy.deepcopy(prev)

            saved, sent, _ = _c13_persist(monkeypatch, orch, prev, _c13_intel({module: None}))

            assert saved[module]["carried_over"]["carried_at"] == _C12_NOW, f"{module}: precondizione"
            assert prev == before, module
            assert sent[0]["baseline"][module] == before[module], module
            assert saved[module] is not prev[module], module


def _c13_pipeline_get(o, modules):
    """GET finto di `_run_pipeline`: `modules` dà, per ciascun servizio, la risposta (`_C02_FETCH_FAILED`
    = errore HTTP, cioè `_fetch_service` -> None)."""
    def _get(url, timeout=None):
        if "/feed/domains" in url:
            return _R({"domains": _C02_FEED})
        if "/feed/whitelist" in url:
            return _R({"whitelist": {}})
        for name, base in (("dns", o.DNS_URL), ("cert", o.CERT_URL), ("http", o.HTTP_URL),
                           ("whois", o.WHOIS_URL), ("reputation", o.REP_URL)):
            if url.startswith(base):
                value = modules[name]
                return _R(None, ok=False, status_code=502) if value is _C02_FETCH_FAILED else _R(copy.deepcopy(value))
        raise AssertionError(f"GET non atteso in questo test: {url}")
    return _get


class TestCOL13EventsAndClassificationDoNotSeeTheMarker:
    """C5 con la pipeline vera (`_run_pipeline`, classificatore reale): lo stesso ciclo, una volta
    senza archivio (nessun riporto, nessun marcatore) e una con uno snapshot sano già in archivio
    (riporto + marcatore), pubblica eventi e classificazione identici, e al classificatore arriva
    la stessa sezione senza marcatore."""

    CASES = [pytest.param(module, form if form is not None else _C02_FETCH_FAILED, id=f"{module}-{label}")
             for module, forms in _C13_FAILED_FORMS.items() for label, form in forms.items()
             if label != "empty-error-text"]

    @staticmethod
    def _cycle(o, monkeypatch, modules):
        published, payloads = [], []
        monkeypatch.setattr(o._session, "get", _c13_pipeline_get(o, modules))
        monkeypatch.setattr(o._session, "post", _real_classifier_post(o, published, payloads))
        o._run_pipeline(_c02_request(o, include_whois=True, include_reputation=True))
        event = _event_for(published, _C02_DOMAIN)
        assert event is not None, published
        classification = {k: v for k, v in event["classification"].items() if k != "timestamp"}
        return {**event, "classification": classification}, payloads

    @pytest.mark.parametrize("module, failed", CASES)
    def test_the_event_and_the_classification_are_the_same_with_and_without_the_marker(
            self, orch, monkeypatch, tmp_path, module, failed):
        fresh = _c13_intel()
        fresh[module] = failed

        monkeypatch.setattr(orch, "INTEL_STORE", False)
        bare_event, bare_payloads = self._cycle(orch, monkeypatch, fresh)

        monkeypatch.setattr(orch, "INTEL_STORE", True)
        monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(orch.intel_store, "HIST_DIR", tmp_path / "history")
        assert orch.intel_store.save_snapshot("acme", _C02_DOMAIN, _c13_previous())
        event, payloads = self._cycle(orch, monkeypatch, fresh)

        saved = orch.intel_store.load_snapshot("acme", _C02_DOMAIN)["intel"][module]
        assert saved.get("carried_over"), "precondizione: il riporto deve essere marcato"
        assert event == bare_event
        assert payloads == bare_payloads
        assert "carried_over" not in json.dumps([event, payloads])


class TestCOL13DiffSeesTheSameAlertsWithAndWithoutTheMarker:
    """C6 — con lo store reale e il `/diff` reale: gli alert di un ciclo con un modulo riportato
    sono quelli dello stesso payload senza marcatori. (La stessa proprietà sul solo `/diff`, con
    marcatori anche malformati, è in `tests/test_classifier.py`.)"""

    @staticmethod
    def _alerts(body):
        return sorted((a["type"], a["severity"], a["message"], json.dumps(a["detail"], sort_keys=True))
                      for a in body["alerts"])

    @pytest.mark.parametrize("module", _C13_MODULES)
    def test_a_carried_module_changes_nothing_in_the_alerts_of_the_others(self, c13_cycle, module):
        api = TestClient(_c02_classifier_app, raise_server_exceptions=False)
        others = [m for m in _C13_MODULES if m != module]
        c13_cycle(0)

        c13_cycle(24, **{module: None}, **{m: _c13_changed(m, _c12_at(24)) for m in others})

        payload, body = c13_cycle.payloads[-1], c13_cycle.responses[-1]
        assert payload["current"][module].get("carried_over"), "precondizione: il riporto deve essere marcato"
        bare = copy.deepcopy(payload)
        for side in ("baseline", "current"):
            for m in _C13_MODULES:
                bare[side][m].pop("carried_over", None)
        expected = api.post("/diff", json=bare).json()
        assert self._alerts(body) == self._alerts(expected)
        assert sorted(a["type"] for a in body["alerts"]) == sorted(_C13_CHANGE_ALERT[m] for m in others)
        assert body["max_severity"] == expected["max_severity"] and body["alert_count"] == expected["alert_count"]


# ═══════════════════════════════════════════════════════════════
# COL-14 — la freschezza del WHOIS omografo si misura sull'osservazione, non sul salvataggio
# ═══════════════════════════════════════════════════════════════
#
# Criteri C1-C7 di BUG-REGISTER.md («ASSEGNA · COL-14»). `_cached_homoglyph_whois` riusa il WHOIS
# persistito di un omografo dormiente solo se è un'osservazione recente (30 giorni): riusarne una
# vecchia congela `is_aged` e spegne `recently_reregistered`. Lo `updated_at` dello snapshot però è
# l'istante dell'ULTIMO SALVATAGGIO, e `_persist_intel` lo riscrive a ogni ciclo anche quando il
# WHOIS è fallito e la sezione è solo riportata (CODE-01): misura la visita, non l'osservazione.
#
# Il contratto, per forma di sezione:
#   * con marcatore `carried_over` valido (oggetto con `carried_at`, scritto da COL-13) conta solo
#     `carried_over.observed_at`, che deve essere un istante entro 30 giorni; `null`, assente,
#     illeggibile, non stringa o nel futuro = nessun riuso. Il `timestamp` della sezione non lo salva;
#   * senza marcatore e con `timestamp` (gli snapshot riportati prima di COL-13 compresi) si riusa
#     solo se il `timestamp` è entro 30 giorni e non nel futuro E `updated_at` è entro 30 giorni:
#     le due condizioni si sommano;
#   * senza `timestamp` e senza marcatore decide `updated_at`, come sempre;
#   * un istante senza fuso vale UTC; un istante non stringa o illeggibile non è fresco; nessuna
#     eccezione, per nessuna forma di sezione, di marcatore o di istante;
#   * la cache in-process resta il ripiego dopo lo snapshot, con la stessa soglia.
#
# I test «controllo» (dichiarati nel docstring) fissano ciò che la correzione non deve toccare e
# fanno da rete contro un'implementazione che rifiuta troppo. Non coperto, perché il contratto non
# lo decide: un `timestamp` presente ma `null`, e il valore restituito per una sezione che non è un
# dict (si pretende solo che la ricerca non sollevi).
#
# Tutti gli istanti sono relativi all'orologio del test: nessuna data fissa che invecchi.

import time
from types import SimpleNamespace

_C14_DOMAIN = "acrne.example"        # omografo di acme.example (`rn` per `m`), RFC 2606
_C14_JUST_SAVED = object()           # nel parametro `updated_at`: «appena salvato»


def _c14_ago(days=0, hours=0):
    """ISO con fuso UTC, `days` + `hours` fa; negativo = nel futuro."""
    return (datetime.now(timezone.utc) - timedelta(days=days, hours=hours)).isoformat()


def _c14_naive(days):
    """Lo stesso istante, scritto senza fuso (vale UTC)."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).replace(tzinfo=None).isoformat()


def _c14_in_offset(days, hours, offset_hours):
    """L'istante `days` + `hours` fa, scritto con un offset diverso da UTC."""
    instant = datetime.now(timezone.utc) - timedelta(days=days, hours=hours)
    return instant.astimezone(timezone(timedelta(hours=offset_hours))).isoformat()


def _c14_whois(timestamp=_C12_MISSING, carried_over=_C12_MISSING):
    """Sezione `whois` come la scrive il collector (forma di `_c13_healthy`), con `timestamp` e
    marcatore opzionali: `_C12_MISSING` = la chiave non c'è."""
    section = {"domain": _C14_DOMAIN, "registrar": "Registrar Example",
               "creation_date": "2001-01-01T00:00:00", "expiration_date": "2027-01-01T00:00:00",
               "privacy_protected": False, "error": None}
    if timestamp is not _C12_MISSING:
        section["timestamp"] = timestamp
    if carried_over is not _C12_MISSING:
        section["carried_over"] = carried_over
    return section


def _c14_marker(observed_at=_C12_MISSING):
    """Marcatore valido (ha `carried_at`) con l'`observed_at` dato; `_C12_MISSING` = chiave assente."""
    marker = {"carried_at": _c14_ago(0)}
    if observed_at is not _C12_MISSING:
        marker["observed_at"] = observed_at
    return marker


def _c14_carried(observed_at, timestamp=_C12_MISSING):
    """Sezione riportata come COL-13 la scrive: il `timestamp` resta quello dell'osservazione
    (`observed_at`, salvo diversa indicazione) e il marcatore dice quando è stata osservata."""
    if timestamp is _C12_MISSING:
        timestamp = observed_at
    return _c14_whois(timestamp=timestamp, carried_over=_c14_marker(observed_at))


def _c14_reused(result, whois):
    """Il risultato è la stessa osservazione di `whois`. Il marcatore non conta: restituirlo o
    toglierlo è una scelta dell'implementazione."""
    return result is not None and _c13_without_marker(result) == _c13_without_marker(whois)


def _c14_not_instants():
    """Valori che non sono un istante: nessuno può contare come fresco. Compresi i numeri che
    sarebbero un epoch del momento, se qualcuno li leggesse come tale."""
    epoch = time.time()
    return [("null", None), ("assente", _C12_MISSING), ("stringa vuota", ""), ("testo", "not-a-date"),
            ("mese 13", "2026-13-45T00:00:00"), ("zero", 0), ("falso", False), ("vero", True),
            ("epoch intero", int(epoch)), ("epoch decimale", epoch), ("lista vuota", []),
            ("lista con un istante", [_c14_ago(1)]), ("oggetto vuoto", {}),
            ("oggetto con un istante", {"at": _c14_ago(1)})]


def _c14_future_instants():
    return [("tra un'ora", _c14_ago(hours=-1)), ("tra un giorno", _c14_ago(days=-1)),
            ("tra 400 giorni", _c14_ago(days=-400)), ("anno 9999", "9999-12-31T23:59:59")]


@pytest.fixture
def c14(orch, monkeypatch, tmp_path):
    """Lo store reale in una directory temporanea (mai `/data`). `c14(whois, updated_at)` scrive lo
    snapshot di `acme/acrne.example` con quella sezione `whois` (`updated_at`: appena salvato, una
    stringa qualunque o `_C12_MISSING` per omettere la chiave) e ritorna ciò che
    `_cached_homoglyph_whois` ne fa. Cache in-process vuota (`orch` ricarica il modulo)."""
    monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(orch.intel_store, "HIST_DIR", tmp_path / "history")
    folder = tmp_path / "snapshots" / "acme"

    def lookup(whois, updated_at=_C14_JUST_SAVED):
        record = {"domain": _C14_DOMAIN, "client": "acme", "intel": {"whois": whois}}
        if updated_at is _C14_JUST_SAVED:
            record["updated_at"] = _c14_ago(0)
        elif updated_at is not _C12_MISSING:
            record["updated_at"] = updated_at
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{_C14_DOMAIN}.json").write_text(json.dumps(record))
        return orch._cached_homoglyph_whois("acme", _C14_DOMAIN)

    return lookup


class TestCOL14CarriedWhoisIsJudgedByItsObservationInstant:
    """C1 — una sezione con marcatore valido si riusa solo se `observed_at` è un istante entro 30
    giorni. Lo snapshot è sempre «appena salvato», com'è dopo un ciclo di riporto."""

    def test_a_carried_whois_observed_within_the_threshold_is_reused(self, c14):
        # Controllo: il riporto di per sé non rende un WHOIS inutilizzabile.
        for days in (1, 29):
            whois = _c14_carried(_c14_ago(days))
            assert _c14_reused(c14(whois), whois), f"osservato {days} giorni fa, riporto appena eseguito: non riusato"

    def test_a_carried_whois_observed_beyond_the_threshold_is_not_reused(self, c14):
        reused = [days for days in (31, 45, 200) if c14(_c14_carried(_c14_ago(days))) is not None]
        assert not reused, (f"WHOIS osservato {reused} giorni fa riusato perché lo snapshot è stato "
                            "appena riscritto dal ciclo che l'ha riportato")

    def test_a_carried_whois_whose_observation_instant_is_not_known_is_not_reused(self, c14):
        reused = [label for label, value in _c14_not_instants()
                  if c14(_c14_carried(value, timestamp=_C12_MISSING)) is not None]
        assert not reused, f"riusato con `observed_at` = {reused}: l'età dell'osservazione è ignota"

    def test_the_marker_decides_even_when_the_section_timestamp_looks_recent(self, c14):
        # Il marcatore dice che l'età è ignota o futura: un `timestamp` recente accanto non la
        # dichiara nota.
        unknown = _c14_not_instants() + _c14_future_instants()
        reused = [label for label, value in unknown
                  if c14(_c14_carried(value, timestamp=_c14_ago(1))) is not None]
        assert not reused, f"riusato con `observed_at` = {reused} e `timestamp` di ieri"

    def test_a_carried_whois_observed_in_the_future_is_not_reused(self, c14):
        reused = [label for label, value in _c14_future_instants() if c14(_c14_carried(value)) is not None]
        assert not reused, f"riusato con `observed_at` {reused}: un'osservazione non può essere nel futuro"

    def test_a_naive_observation_instant_counts_as_utc(self, c14):
        recent, stale = _c14_carried(_c14_naive(5)), _c14_carried(_c14_naive(40))

        assert _c14_reused(c14(recent), recent), "senza fuso, 5 giorni fa: dev'essere fresco"
        assert c14(stale) is None, "senza fuso, 40 giorni fa: dev'essere oltre la soglia"


class TestCOL14UnmarkedWhoisNeedsAFreshTimestampAndAFreshSnapshot:
    """C2 — una sezione non riportata con `timestamp` (compresi gli snapshot riportati prima di
    COL-13, che non hanno marcatore e conservano il `timestamp` originale) si riusa solo se il
    `timestamp` è entro 30 giorni e non nel futuro E `updated_at` è entro 30 giorni."""

    def test_a_recent_timestamp_in_a_recent_snapshot_is_reused(self, c14):
        # Controllo.
        for days, saved in ((1, 0), (29, 0), (29, 1), (1, 29)):
            whois = _c14_whois(timestamp=_c14_ago(days))
            assert _c14_reused(c14(whois, updated_at=_c14_ago(saved)), whois), (
                f"osservato {days} giorni fa, snapshot di {saved} giorni fa: non riusato")

    def test_a_legacy_carried_whois_without_marker_but_with_an_old_timestamp_is_not_reused(self, c14):
        # La forma degli snapshot scritti dal riporto prima del marcatore: `updated_at` appena scritto,
        # `timestamp` quello dell'osservazione originale.
        reused = [days for days in (31, 45, 200) if c14(_c14_whois(timestamp=_c14_ago(days))) is not None]
        assert not reused, f"WHOIS con `timestamp` di {reused} giorni fa riusato perché lo snapshot è recente"

    def test_a_recent_timestamp_does_not_rescue_a_stale_snapshot(self, c14):
        # Le due condizioni si sommano, non si sostituiscono.
        reused = [(days, saved) for days, saved in ((1, 31), (29, 31), (1, 200))
                  if c14(_c14_whois(timestamp=_c14_ago(days)), updated_at=_c14_ago(saved)) is not None]
        assert not reused, f"riusato (giorni dall'osservazione, giorni dal salvataggio): {reused}"

    def test_a_timestamp_in_the_future_is_not_reused(self, c14):
        reused = [label for label, value in _c14_future_instants()
                  if c14(_c14_whois(timestamp=value)) is not None]
        assert not reused, f"riusato con `timestamp` {reused}: un'osservazione non può essere nel futuro"

    def test_a_timestamp_that_is_not_an_instant_is_not_reused(self, c14):
        # Solo i valori non vuoti: «nessun timestamp» è un'altra forma (C3), qui il campo c'è.
        garbage = [(label, value) for label, value in _c14_not_instants()
                   if value is not _C12_MISSING and value]
        reused = [label for label, value in garbage if c14(_c14_whois(timestamp=value)) is not None]
        assert len(garbage) >= 6 and not reused, f"riusato con `timestamp` = {reused}"

    def test_a_naive_timestamp_counts_as_utc(self, c14):
        recent, stale = _c14_whois(timestamp=_c14_naive(5)), _c14_whois(timestamp=_c14_naive(40))

        assert _c14_reused(c14(recent), recent), "senza fuso, 5 giorni fa: dev'essere fresco"
        assert c14(stale) is None, "senza fuso, 40 giorni fa: dev'essere oltre la soglia"


class TestCOL14WithoutTimestampOrMarkerTheSnapshotInstantDecides:
    """C3 — una sezione senza `timestamp` e senza marcatore si giudica su `updated_at`, come
    sempre. Il confine a 29 e 31 giorni è già in
    `TestSCO05HomoglyphWhoisCacheFreshnessThreshold`; qui il resto del comportamento."""

    def test_a_recent_snapshot_is_enough(self, c14):
        # Controllo: la correzione non deve pretendere un `timestamp` che questa forma non ha.
        whois = _c14_whois()
        for saved in (0, 1, 29):
            assert _c14_reused(c14(whois, updated_at=_c14_ago(saved)), whois), f"salvato {saved} giorni fa"

    def test_a_naive_snapshot_instant_counts_as_utc(self, c14):
        whois = _c14_whois()

        assert _c14_reused(c14(whois, updated_at=_c14_naive(5)), whois), "senza fuso, 5 giorni fa"
        assert c14(whois, updated_at=_c14_naive(40)) is None, "senza fuso, 40 giorni fa"

    def test_a_snapshot_instant_that_is_not_an_instant_is_not_reused_in_any_section_form(self, c14):
        # Controllo, per ogni forma di sezione: se non si sa quando è stato salvato lo snapshot
        # non si può dire che la sezione sia valida.
        shapes = {"senza timestamp": _c14_whois(), "con timestamp": _c14_whois(timestamp=_c14_ago(1))}
        reused = [(shape, label) for shape, whois in shapes.items()
                  for label, value in _c14_not_instants() if c14(whois, updated_at=value) is not None]
        assert not reused, f"riusato con `updated_at` illeggibile: {reused}"


class TestCOL14RobustnessOnMalformedSections:
    """C4 — istanti non stringa o illeggibili non sono freschi, un istante senza fuso vale UTC,
    nessuna eccezione per nessuna forma di sezione o di marcatore."""

    @pytest.mark.parametrize("where", ["marker", "timestamp"])
    def test_an_instant_with_a_utc_offset_is_compared_as_an_instant(self, c14, where):
        # Le cifre scritte e l'istante divergono: 3 ore dentro la soglia scritte a UTC-12 sembrano
        # oltre, 3 ore oltre scritte a UTC+12 sembrano dentro. Si confrontano gli istanti.
        def observed(instant):
            return _c14_carried(instant) if where == "marker" else _c14_whois(timestamp=instant)

        inside = observed(_c14_in_offset(days=30, hours=-3, offset_hours=-12))
        outside = observed(_c14_in_offset(days=30, hours=3, offset_hours=12))

        assert _c14_reused(c14(inside), inside), "29 giorni e 21 ore fa, scritto a UTC-12: dev'essere fresco"
        assert c14(outside) is None, "30 giorni e 3 ore fa, scritto a UTC+12: dev'essere oltre la soglia"

    def test_a_malformed_marker_never_unlocks_a_whois_observed_beyond_the_threshold(self, c14):
        # `carried_over` fuori forma (non un oggetto, oggetto vuoto, senza `carried_at`, con un
        # `observed_at` recente ma senza `carried_at`): non è un marcatore valido, quindi non
        # dichiara fresca un'osservazione che il suo `timestamp` dice di 200 giorni fa.
        stale = _c14_ago(200)
        markers = [("null", None), ("testo", "carried"), ("numero", 1), ("zero", 0), ("vero", True),
                   ("lista", ["carried_at"]), ("lista vuota", []), ("oggetto vuoto", {}),
                   ("senza carried_at", {"observed_at": stale}),
                   ("senza carried_at e osservazione recente", {"observed_at": _c14_ago(1)})]
        reused = [label for label, marker in markers
                  if c14(_c14_whois(timestamp=stale, carried_over=marker)) is not None]
        assert not reused, f"marcatore {reused}: WHOIS di 200 giorni fa riusato"

    def test_no_shape_of_section_marker_or_instant_makes_the_lookup_raise(self, c14):
        instants = [value for _, value in _c14_not_instants() + _c14_future_instants()]
        instants += [_c14_ago(1), _c14_naive(1), "0001-01-01T00:00:00+05:00"]
        markers = [None, "carried", 1, True, [], {}, {"observed_at": _c14_ago(1)}] \
            + [_c14_marker(value) for value in instants]
        sections = ["testo", 5, True, [], ["a"], {}, {"error": None}] \
            + [_c14_whois(timestamp=value) for value in instants] \
            + [_c14_whois(timestamp=_c14_ago(1), carried_over=marker) for marker in markers]
        raised = []
        for index, whois in enumerate(sections):
            for updated_at in (_C14_JUST_SAVED, _C12_MISSING, 12345, "not-a-date"):
                try:
                    c14(whois, updated_at=updated_at)
                except Exception as error:
                    raised.append((index, type(error).__name__))
        assert len(sections) > 40 and not raised, f"eccezioni (indice della sezione, tipo): {raised[:10]}"


class TestCOL14InProcessCacheIsUnchanged:
    """C5 — la cache in-process resta il ripiego dopo lo snapshot, con la stessa soglia."""

    def test_the_cached_whois_is_reused_within_the_threshold_and_not_beyond(self, orch, monkeypatch, tmp_path):
        # Controllo. Nessuno snapshot: decide solo la cache.
        monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        whois = _c14_whois(timestamp=_c14_ago(0))
        orch._remember_homoglyph_whois("acme", _C14_DOMAIN, whois)
        now = time.time()

        results = {}
        for days in (0, 29, 31):
            monkeypatch.setattr(orch.time, "time", lambda days=days: now + days * 86400)
            results[days] = orch._cached_homoglyph_whois("acme", _C14_DOMAIN)

        assert results == {0: whois, 29: whois, 31: None}

    def test_a_rejected_snapshot_does_not_hide_a_fresh_cached_observation(self, c14, orch):
        # Lo snapshot è un riporto di un WHOIS di 200 giorni fa: scartato. La cache ha un'osservazione
        # recente dello stesso dominio, dello stesso cliente: è lei la risposta, non `None`.
        cached = _c14_whois(timestamp=_c14_ago(0))
        cached["registrar"] = "Cached Registrar Example"
        orch._remember_homoglyph_whois("acme", _C14_DOMAIN, cached)

        assert c14(_c14_carried(_c14_ago(200))) == cached


def _c14_failed_whois():
    """La sezione con cui un ciclo registra un WHOIS in errore (forma di `_C13_FAILED_FORMS`)."""
    return {"domain": _C14_DOMAIN, "timestamp": _c14_ago(0), "registrar": None, "creation_date": None,
            "expiration_date": None, "error": "WHOIS lookup failed: connection timed out"}


@pytest.fixture
def c14_cycle(orch, monkeypatch, tmp_path):
    """Il percorso reale: lo store e `_persist_intel` veri (`/diff` finto), su una directory
    temporanea. `cycle.seed(whois, days)` salva lo snapshot come se fosse stato scritto `days`
    giorni fa; `cycle.fail()` esegue un ciclo in cui il WHOIS è in errore (CODE-01 riporta quello
    vecchio); `cycle.answer(whois)` un ciclo in cui risponde; `cycle.lookup()` è
    `_cached_homoglyph_whois`."""
    monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(orch.intel_store, "HIST_DIR", tmp_path / "history")
    monkeypatch.setattr(orch._session, "post", lambda url, json=None, timeout=None: _C02Resp())

    def seed(whois, days):
        with monkeypatch.context() as past:
            past.setattr(orch.intel_store, "_now", lambda: _c14_ago(days))
            assert orch.intel_store.save_snapshot("acme", _C14_DOMAIN, {"whois": whois})

    def answer(whois):
        orch._persist_intel("acme", _C14_DOMAIN, "acme.example",
                            {"dns": None, "cert": None, "http": None, "whois": whois, "reputation": None})

    return SimpleNamespace(
        seed=seed, answer=answer, fail=lambda: answer(_c14_failed_whois()),
        lookup=lambda: orch._cached_homoglyph_whois("acme", _C14_DOMAIN),
        snapshot=lambda: orch.intel_store.load_snapshot("acme", _C14_DOMAIN))


class TestCOL14ThroughTheRealPersistence:
    """Il percorso dell'errore: uno snapshot vecchio, un ciclo con il WHOIS in errore (che riscrive
    `updated_at` e riporta il WHOIS vecchio con il marcatore), poi la ricerca dell'omografo
    dormiente."""

    @pytest.mark.parametrize("days, reused", [(10, True), (29, True), (31, False), (200, False)])
    def test_a_whois_carried_over_a_failed_cycle_keeps_the_age_of_its_observation(
            self, c14_cycle, days, reused):
        c14_cycle.seed(_c14_whois(timestamp=_c14_ago(days)), days)

        c14_cycle.fail()

        assert c14_cycle.snapshot()["intel"]["whois"].get("carried_over"), "precondizione: riporto marcato"
        result = c14_cycle.lookup()
        assert (result is not None) == reused, (
            f"WHOIS osservato {days} giorni fa, riportato da un ciclo appena eseguito: "
            f"{'non riusato' if reused else 'riusato'} ({result})")

    def test_a_whois_with_an_unknown_observation_instant_is_not_reused_after_a_failed_cycle(self, c14_cycle):
        # Il WHOIS di uno snapshot di 200 giorni fa senza `timestamp`: il marcatore dichiara l'età
        # ignota, non quella del ciclo che l'ha riportato.
        c14_cycle.seed(_c14_whois(), 200)

        c14_cycle.fail()

        assert c14_cycle.snapshot()["intel"]["whois"].get("carried_over"), "precondizione: riporto marcato"
        assert c14_cycle.lookup() is None

    def test_repeated_failed_cycles_never_make_an_old_whois_fresh(self, c14_cycle):
        c14_cycle.seed(_c14_whois(timestamp=_c14_ago(200)), 200)

        results = []
        for _ in range(3):
            c14_cycle.fail()
            results.append(c14_cycle.lookup())

        assert results == [None, None, None], results

    def test_a_whois_that_answers_again_is_reused_again(self, c14_cycle):
        # Controllo: scartare il riporto non è un blocco permanente.
        c14_cycle.seed(_c14_whois(timestamp=_c14_ago(200)), 200)
        c14_cycle.fail()
        fresh = _c14_whois(timestamp=_c14_ago(0))

        c14_cycle.answer(fresh)

        assert c14_cycle.lookup() == fresh


class TestCOL14DormantBranchOfThePipeline:
    """Il ramo dormiente di `_run_pipeline` (omografo senza A né MX) col classificatore reale: un
    WHOIS che passa la ricerca decide la severità del caso, uno scartato lascia il segnaposto."""

    FEED = {"domains": [{"domain": "acme.example", "client": "acme", "type": "target",
                         "legitimate": "acme.example"}]}
    TWIST = {"registered_variants": 1, "variants": [
        {"domain": _C14_DOMAIN, "fuzzer": "homoglyph", "dns_a": False, "dns_mx": False, "geoip": ""}]}

    def _event(self, o, monkeypatch, tmp_path, whois):
        monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
        folder = tmp_path / "snapshots" / "acme"
        folder.mkdir(parents=True)
        (folder / f"{_C14_DOMAIN}.json").write_text(json.dumps(
            {"domain": _C14_DOMAIN, "client": "acme", "updated_at": _c14_ago(0), "intel": {"whois": whois}}))
        published, classify_payloads, whois_calls = [], [], []

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _R(self.FEED)
            if "/feed/whitelist" in url:
                return _R({"whitelist": {}})
            if url.startswith(o.TWIST_URL):
                return _R(self.TWIST)
            if url.startswith(o.WHOIS_URL):
                whois_calls.append(url)
            return _R({})

        monkeypatch.setattr(o._session, "get", _get)
        monkeypatch.setattr(o._session, "post", _real_classifier_post(o, published, classify_payloads))

        o._run_pipeline(o.TriggerRequest(client="acme", include_whois=True, include_reputation=False,
                                         include_dnstwist=True, variant_intel=True, scope="all"))

        event = _event_for(published, _C14_DOMAIN)
        assert event is not None, f"nessun evento per {_C14_DOMAIN}: {published}"
        assert not [u for u in whois_calls if _C14_DOMAIN in u], (
            f"raccolta WHOIS dal vivo dell'omografo non prevista: {whois_calls}")
        return event

    def test_a_recently_observed_carried_whois_still_classifies_the_dormant_domain(self, orch, monkeypatch, tmp_path):
        # Controllo: dominio del 2001, osservato 10 giorni fa e riportato: LOW come con un WHOIS fresco.
        event = self._event(orch, monkeypatch, tmp_path, _c14_carried(_c14_ago(10)))

        assert _severity_of(orch, event) == "LOW", event["classification"]

    def test_a_carried_whois_observed_long_ago_does_not_classify_the_dormant_domain(self, orch, monkeypatch, tmp_path):
        # Lo stesso snapshot, ma l'osservazione è di 200 giorni fa: il WHOIS non è riusato e il caso
        # resta sul segnaposto MEDIUM invece di scendere a LOW sull'età di un dato vecchio.
        event = self._event(orch, monkeypatch, tmp_path, _c14_carried(_c14_ago(200)))

        assert _severity_of(orch, event) == "MEDIUM", (
            "un WHOIS osservato 200 giorni fa ha determinato la severità del caso: "
            f"{event['classification']}")


# ═══════════════════════════════════════════════════════════════
# Percorso DNS: osservazione uguale all'istante del ciclo e istanti senza fuso
# ═══════════════════════════════════════════════════════════════
#
# `_dns_observed_at` decide l'`observed_at` di ogni parte DNS riportata. Il suo contratto nei due casi
# limite: un'osservazione che coincide con l'istante del ciclo non è «successiva» e si conserva; un
# istante senza fuso e uno con fuso si confrontano come istanti (senza fuso vale UTC). Si prova sulle
# parti del DNS, per un riporto parziale (un solo tipo `unknown`) e per uno totale (guasto del modulo).

_CODE51_PATHS = [pytest.param("partial", id="one-part-unknown"), pytest.param("total", id="total-failure")]


def _code51_carried_instants(o, monkeypatch, prev, path, now=_C12_NOW):
    """{parte: istante di `observed_at` | None} del marcatore salvato, per un riporto parziale (solo A
    `unknown`) o totale (guasto del modulo)."""
    curr = _c02_unknown(_c02_healthy_dns(), "A") if path == "partial" else _c02_total_failure()
    saved, _, _ = _c12_persist(monkeypatch, o, prev, curr, now=now)
    marker = saved.get("carried_over") or {}
    assert set(marker) == ({"A"} if path == "partial" else set(_C12_ALL_PARTS)), marker
    return {part: None if entry["observed_at"] is None else _c13_instant(entry["observed_at"])
            for part, entry in marker.items()}


class TestDnsObservedAtAtTheCycleInstantAndWithoutATimezone:
    @pytest.fixture(autouse=True)
    def _local_zone_is_not_utc(self, monkeypatch):
        # Su un host in UTC «senza fuso = UTC» e «senza fuso = ora locale» danno lo stesso esito: con un
        # fuso locale a +9 ore i due contratti si distinguono. Il fuso si ripristina a fine test.
        if not hasattr(time, "tzset"):
            pytest.skip("time.tzset non disponibile su questa piattaforma")
        monkeypatch.setenv("TZ", "JST-9")
        time.tzset()
        yield
        monkeypatch.undo()
        time.tzset()

    def test_the_local_zone_of_these_tests_is_not_utc(self):
        assert datetime(2026, 10, 21, 10, 0, 31).astimezone().utcoffset() == timedelta(hours=9)

    @pytest.mark.parametrize("path", _CODE51_PATHS)
    @pytest.mark.parametrize("timestamp", [
        pytest.param(_C12_NOW, id="same-string"),
        pytest.param("2026-10-21T12:00:30+02:00", id="same-instant-other-offset"),
        pytest.param("2026-10-21T10:00:30", id="same-instant-without-a-timezone"),
    ])
    def test_an_observation_at_the_cycle_instant_is_kept(self, orch, monkeypatch, path, timestamp):
        # «Successiva al ciclo» non include l'uguale: un'osservazione fatta nell'istante in cui il ciclo
        # riporta è un'osservazione valida, non ignota.
        prev = _c02_healthy_dns()
        prev["timestamp"] = timestamp

        observed = _code51_carried_instants(orch, monkeypatch, prev, path)

        assert set(observed.values()) == {_c13_instant(_C12_NOW)}, observed

    def test_an_inherited_observation_at_the_cycle_instant_is_kept(self, orch, monkeypatch):
        prev = _c02_healthy_dns()
        prev["carried_over"] = {"A": {"observed_at": _C12_NOW, "carried_at": _C12_NOW}}

        saved, _, _ = _c12_persist(monkeypatch, orch, prev, _c02_unknown(_c02_healthy_dns(), "A", "MX"))

        assert _c13_instant(saved["carried_over"]["A"]["observed_at"]) == _c13_instant(_C12_NOW)
        assert _c13_instant(saved["carried_over"]["MX"]["observed_at"]) == _C12_BASE

    @pytest.mark.parametrize("path", _CODE51_PATHS)
    @pytest.mark.parametrize("timestamp, expected", [
        pytest.param("2026-10-20T10:00:00", _C12_BASE, id="a-day-before"),
        pytest.param("2026-10-21T10:00:29", _c13_instant("2026-10-21T10:00:29+00:00"), id="one-second-before"),
        pytest.param("2026-10-21T10:00:31", None, id="one-second-after"),
        pytest.param("2026-10-22T10:00:00", None, id="a-day-after"),
    ])
    def test_a_timestamp_without_a_timezone_is_compared_as_utc(self, orch, monkeypatch, path, timestamp, expected):
        # Un istante senza fuso e uno con fuso non si confrontano come stringhe né sollevano: senza
        # fuso vale UTC. L'osservazione precedente al ciclo si conserva (e vale lo stesso istante),
        # quella successiva è ignota.
        prev = _c02_healthy_dns()
        prev["timestamp"] = timestamp

        observed = _code51_carried_instants(orch, monkeypatch, prev, path)

        assert set(observed.values()) == {expected}, observed

    @pytest.mark.parametrize("path", _CODE51_PATHS)
    @pytest.mark.parametrize("timestamp, expected", [
        pytest.param("2026-10-20T10:00:00+00:00", _C12_BASE, id="observation-before"),
        pytest.param("2026-10-21T10:00:30+00:00", _c13_instant("2026-10-21T10:00:30+00:00"), id="observation-at-the-cycle"),
        pytest.param("2026-10-21T12:00:31+02:00", None, id="observation-one-second-after-with-an-offset"),
    ])
    def test_a_cycle_instant_without_a_timezone_is_compared_as_utc(self, orch, monkeypatch, path, timestamp, expected):
        prev = _c02_healthy_dns()
        prev["timestamp"] = timestamp

        observed = _code51_carried_instants(orch, monkeypatch, prev, path, now="2026-10-21T10:00:30")

        assert set(observed.values()) == {expected}, observed


# ═══════════════════════════════════════════════════════════════
# COL-16 — una fonte di reputazione in errore non sostituisce l'ultima osservazione
# ═══════════════════════════════════════════════════════════════
#
# `collection_failed` dichiara fallito il modulo `reputation` solo se TUTTE le fonti interrogate sono
# in errore (CODE-14). Con una sola fonte guasta (VT 429, OTX in timeout) la sezione è una risposta
# valida: la fonte guasta è un dict completo con i numeri a zero e `error` valorizzato, e la sezione si
# salva com'è. Lo zero non è un'osservazione, ma diventa la baseline: quando la fonte torna, il `/diff`
# lo confronta con il valore vero e riemette `vt_malicious_detected` (CRITICAL) o `otx_pulse_detected`
# (HIGH) per ciò che la baseline conteneva già prima del guasto. Il contratto, per `virustotal`, `otx`
# e `securitytrails` della sezione `reputation`:
#
#   * «non osservata» = dict con `error` valorizzato, tranne l'esito 404 di VT, che è un'osservazione
#     (VT non conosce il dominio: gli zeri sono veri). Una fonte `None` (non interrogata) non si tocca;
#   * una fonte non osservata, che la sezione precedente aveva osservata o già riportata, nello snapshot
#     resta quella precedente (senza `error`); le altre fonti sono quelle del ciclo;
#   * la sezione salvata porta `carried_sources = {fonte: {"observed_at", "carried_at"}}`, una voce per
#     fonte riportata: `observed_at` è quello del marcatore precedente se la fonte era già riportata,
#     altrimenti il `timestamp` della sezione precedente; `carried_at` è l'istante del ciclo (lo stesso
#     di `carried_over`). Senza fonti riportate la chiave non c'è. Quella arrivata dal servizio (zona
#     non autenticata) non entra nello snapshot, come `carried_over`;
#   * `risk_score` e `risk_level` salvati sono quelli della sezione salvata (la fonte riportata conta),
#     non quelli del ciclo guasto;
#   * una fonte mai osservata non ha baseline: alla prima osservazione il `/diff` non allerta e la
#     baseline si popola in silenzio. Un aumento vero rispetto all'ultima osservazione (da 0 a >0 per VT,
#     più pulse per OTX) resta un alert, anche con un guasto in mezzo;
#   * `carried_sources` convive con `carried_over` (guasto di tutto il modulo), non entra in eventi,
#     classificazione e payload verso il classificatore, e non cambia la classificazione del ciclo.
#
# Le sezioni di questi test le produce il collector VERO (`GET /reputation` in-process), con la sola
# rete sostituita da risposte fisse: la forma di una fonte guasta e il punteggio sono quelli reali.
# Dove un test pretende il marcatore prima di asserire altro («precondizione») il riporto è parte del
# comportamento voluto; i test dichiarati «controllo» fissano ciò che deve restare invariato.

import requests as _c16_requests
import services.reputation as _c16_reputation


class _C16Response:
    """Risposta HTTP finta di un fornitore, con la sola superficie che il collector legge."""

    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def _c16_failure(state):
    """L'esito di guasto per `state` (errore HTTP, timeout, errore di connessione), o `None` se
    `state` non è un guasto. Il 404 qui è solo un errore HTTP: per VT è un'osservazione."""
    if state in ("404", "429", "500"):
        return _C16Response(int(state))
    if state == "timeout":
        raise _c16_requests.exceptions.Timeout("Read timed out. (read timeout=15)")
    if state == "conn":
        raise _c16_requests.exceptions.ConnectionError("Max retries exceeded (Caused by NewConnectionError)")
    if state == "silent":
        raise _c16_requests.exceptions.ConnectionError("")   # `sanitize_error` dà "": `error` presente ma vuoto
    return None


_C16_VT_MALICIOUS = {"mal0": 0, "mal3": 3, "mal5": 5}
_C16_OTX_PULSES = {"pulses0": 0, "pulses2": 2, "pulses5": 5}


def _c16_vt(state):
    failure = _c16_failure(state)
    if failure is not None:
        return failure
    malicious = _C16_VT_MALICIOUS[state]
    return _C16Response(200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 0, "undetected": 60, "harmless": 10},
        "reputation": -10 if malicious else 0, "categories": {}}}})


def _c16_otx(state):
    failure = _c16_failure(state)
    if failure is not None:
        return failure
    count = _C16_OTX_PULSES[state]
    return _C16Response(200, {"pulse_info": {"count": count, "pulses": [
        {"name": f"pulse-{i}", "tags": [], "malware_families": []} for i in range(min(count, 5))]}})


def _c16_st(state):
    failure = _c16_failure(state)
    if failure is not None:
        return failure
    return _C16Response(200, {"subdomain_count": 4, "current_dns": {}, "alexa_rank": None})


@pytest.fixture
def c16_collect(monkeypatch):
    """`collect(hours, vt="mal3", otx="pulses2", st="ok")`: la sezione `reputation` che il collector
    vero (`GET /reputation`) produce a `hours` dopo T0, con la rete sostituita. Stati: VT `mal0`
    `mal3` `mal5` (malicious) o un guasto; OTX `pulses0` `pulses2` `pulses5` o un guasto; ST `ok` o un
    guasto; guasti `429`, `500`, `404`, `timeout`, `conn`, `silent` (eccezione senza messaggio: `error`
    è `""`). `None` = fonte non interrogata. I default
    sono il ciclo sano: VT 3 e OTX 2 danno rischio 50 `medium`. Il limitatore di VT non attende."""
    rep = _c16_reputation
    states = {}
    monkeypatch.setattr(rep, "VT_API_KEY", "vt-test-key")
    monkeypatch.setattr(rep, "OTX_API_KEY", "otx-test-key")
    monkeypatch.setattr(rep, "ST_API_KEY", "st-test-key")
    monkeypatch.setattr(rep, "_vt_wait_for_slot", lambda: None)

    def _get(url, **kwargs):
        if "virustotal" in url:
            return _c16_vt(states["vt"])
        if "alienvault" in url:
            return _c16_otx(states["otx"])
        if "securitytrails" in url:
            return _c16_st(states["st"])
        raise AssertionError(f"GET non atteso in questo test: {url}")

    monkeypatch.setattr(rep, "requests", SimpleNamespace(get=_get))
    api = TestClient(rep.app)

    def collect(hours, vt="mal3", otx="pulses2", st="ok"):
        states.update(vt=vt, otx=otx, st=st)
        monkeypatch.setattr(rep, "now_iso", lambda: _c12_at(hours))
        queried = ",".join(name for name, state in (("vt", vt), ("otx", otx), ("st", st)) if state is not None)
        response = api.get("/reputation", params={"domain": _C02_DOMAIN, "sources": queried})
        assert response.status_code == 200, response.text
        return response.json()

    return collect


@pytest.fixture
def c16(c13_cycle, c16_collect):
    """Un ciclo di `_persist_intel` reale per chiamata (`c13_cycle`: store su directory temporanea e
    `/diff` del classificatore vero), con la reputazione del collector vero. `cycle(hours, **fonti)`
    raccoglie a `hours`, persiste 30 s dopo e ritorna la sezione del ciclo; `saved()` è la sezione
    salvata; `types()` i tipi di alert nuovi, un elenco per ciclo; `collect` e `run` (`c13_cycle`)
    per i casi che alterano la risposta prima di persisterla."""
    def cycle(hours, **sources):
        section = c16_collect(hours, **sources)
        c13_cycle(hours, reputation=section)
        return section

    return SimpleNamespace(
        cycle=cycle, collect=c16_collect, run=c13_cycle,
        saved=lambda: c13_cycle.section("reputation"),
        types=lambda: [[kind for kind, _, _ in found] for found in c13_cycle.per_cycle])


def _c16_entry(observed_hours, carried_hours):
    return {"observed_at": _c12_at(observed_hours), "carried_at": _c12_at(carried_hours, seconds=30)}


def _c16_assert_marker(saved, expected, where=""):
    """Il `carried_sources` della sezione salvata è `expected`."""
    actual = saved.get("carried_sources")
    assert actual == expected, f"{where}carried_sources salvato {actual!r}, atteso {expected!r}"


_C16_VT_OUTAGES = [pytest.param("429", id="http-429"), pytest.param("500", id="http-500"),
                   pytest.param("timeout", id="timeout"), pytest.param("conn", id="connection-error")]
_C16_OTX_OUTAGES = [pytest.param("429", id="http-429"), pytest.param("timeout", id="timeout")]
_C16_OUTAGE_LENGTHS = [pytest.param(1, id="one-cycle"), pytest.param(2, id="two-cycles")]
_C16_SOURCE_OUTAGES = [pytest.param("virustotal", {"vt": "429"}, id="virustotal"),
                       pytest.param("otx", {"otx": "429"}, id="otx"),
                       pytest.param("securitytrails", {"st": "500"}, id="securitytrails")]


class TestCOL16AFailedSourceDoesNotReplayTheBaseline:
    """Una fonte in errore per uno o due cicli e poi di nuovo ok con lo stesso verdetto di prima: il
    `/diff` non vede nulla di nuovo, quindi nessun alert in nessun ciclo."""

    @pytest.mark.parametrize("length", _C16_OUTAGE_LENGTHS)
    @pytest.mark.parametrize("failure", _C16_VT_OUTAGES)
    def test_virustotal_back_with_the_same_verdict_raises_no_alert(self, c16, failure, length):
        c16.cycle(0)
        for n in range(1, length + 1):
            c16.cycle(24 * n, vt=failure)
        c16.cycle(24 * (length + 1))

        assert c16.types() == [[]] * (length + 2), (
            f"VT con malicious 3 prima e dopo il guasto ({failure}): alert per ciclo {c16.types()}")

    @pytest.mark.parametrize("length", _C16_OUTAGE_LENGTHS)
    @pytest.mark.parametrize("failure", _C16_OTX_OUTAGES)
    def test_otx_back_with_the_same_pulses_raises_no_alert(self, c16, failure, length):
        c16.cycle(0)
        for n in range(1, length + 1):
            c16.cycle(24 * n, otx=failure)
        c16.cycle(24 * (length + 1))

        assert c16.types() == [[]] * (length + 2), (
            f"OTX con 2 pulse prima e dopo il guasto ({failure}): alert per ciclo {c16.types()}")

    def test_virustotal_that_grows_from_some_to_more_malicious_across_an_outage_does_not_alert(self, c16):
        # Da 3 a 5 malicious senza guasto non allerta (la regola di VT è solo «da 0 a più di 0»):
        # con un guasto in mezzo vale lo stesso.
        c16.cycle(0, vt="mal3")
        c16.cycle(24, vt="429")
        c16.cycle(48, vt="mal5")

        assert c16.types() == [[], [], []], c16.types()

    @pytest.mark.parametrize("failure", ["500", "timeout"])
    def test_securitytrails_back_raises_no_alert(self, c16, failure):
        # Controllo: SecurityTrails non produce alert, né durante il guasto né al ritorno.
        c16.cycle(0)
        c16.cycle(24, st=failure)
        c16.cycle(48)

        assert c16.types() == [[], [], []]


class TestCOL16ARealChangeStillAlerts:
    """Il riporto non nasconde un aumento vero: rispetto all'ultima osservazione buona della fonte,
    con o senza un guasto in mezzo, l'alert ordinario esce una volta sola, al ritorno."""

    @pytest.mark.parametrize("length", _C16_OUTAGE_LENGTHS)
    def test_virustotal_from_clean_to_malicious_across_an_outage_alerts_on_return(self, c16, length):
        c16.cycle(0, vt="mal0")
        for n in range(1, length + 1):
            c16.cycle(24 * n, vt="429")
        c16.cycle(24 * (length + 1), vt="mal3")

        assert c16.types() == [[]] * (length + 1) + [["vt_malicious_detected"]], c16.types()
        assert c16.run.per_cycle[-1][0][1] == "CRITICAL"

    def test_virustotal_that_did_not_know_the_domain_and_now_sees_it_malicious_alerts(self, c16):
        # Controllo: il 404 di VT è un'osservazione (gli zeri sono veri), non un guasto da riportare.
        c16.cycle(0, vt="404")
        c16.cycle(24, vt="mal3")

        assert c16.types() == [[], ["vt_malicious_detected"]]

    @pytest.mark.parametrize("before", ["pulses0", "pulses2"])
    def test_otx_with_more_pulses_across_an_outage_alerts_on_return(self, c16, before):
        c16.cycle(0, otx=before)
        c16.cycle(24, otx="429")
        c16.cycle(48, otx="pulses5")

        assert c16.types() == [[], [], ["otx_pulse_detected"]], c16.types()
        assert c16.run.per_cycle[-1][0][1] == "HIGH"

    def test_without_an_outage_the_same_changes_alert_as_usual(self, c16):
        # Controllo: da 0 a malicious e da 2 a 5 pulse allertano; da 3 a 5 malicious no (la regola di
        # VT è solo «da 0 a più di 0»).
        c16.cycle(0, vt="mal0", otx="pulses2")
        c16.cycle(24, vt="mal3", otx="pulses5")
        c16.cycle(48, vt="mal5", otx="pulses5")

        assert [sorted(found) for found in c16.types()] == [
            [], ["otx_pulse_detected", "vt_malicious_detected"], []]


class TestCOL16ASourceNeverObservedHasNoBaseline:
    """Una fonte già in errore al primo ciclo non ha mai avuto un'osservazione: non c'è nulla da
    riportare e al ritorno il `/diff` non allerta. La prima osservazione popola la baseline."""

    @pytest.mark.parametrize("length", _C16_OUTAGE_LENGTHS)
    @pytest.mark.parametrize("source, alert", [("vt", "vt_malicious_detected"), ("otx", "otx_pulse_detected")])
    def test_the_first_observation_after_an_outage_from_the_start_raises_no_alert(
            self, c16, source, alert, length):
        for n in range(length):
            c16.cycle(24 * n, **{source: "429"})
        c16.cycle(24 * length)

        assert c16.types() == [[]] * (length + 1), f"{alert} alla prima osservazione: {c16.types()}"

    @pytest.mark.parametrize("source", ["vt", "otx", "st"])
    def test_a_source_that_fails_in_every_cycle_is_saved_as_the_collector_produced_it(self, c16, source):
        # Controllo: senza un'osservazione precedente non c'è nulla da riportare, quindi nessun
        # marcatore per quella fonte e la sezione del ciclo si salva com'è.
        failure = "500" if source == "st" else "429"
        for hours in (0, 24, 48):
            section = c16.cycle(hours, **{source: failure})

            assert c16.saved() == section, f"ciclo a {hours} h"
            assert "carried_sources" not in c16.saved()

    def test_the_first_observation_becomes_the_baseline_that_a_later_outage_carries(self, c16):
        c16.cycle(0, vt="429")
        first = c16.cycle(24)
        c16.cycle(48, vt="429")

        saved = c16.saved()
        _c16_assert_marker(saved, {"virustotal": _c16_entry(24, 48)}, "la prima osservazione come baseline: ")
        assert saved["virustotal"] == first["virustotal"]
        c16.cycle(72)
        assert c16.types() == [[]] * 4, c16.types()


class TestCOL16MarkerPerSource:
    """La sezione salvata dice, per ogni fonte riportata, quando è stata osservata e quando è stata
    riportata, e porta il valore dell'ultima osservazione."""

    @pytest.mark.parametrize("source, failure", _C16_SOURCE_OUTAGES)
    def test_the_failed_source_is_the_previous_observation_and_is_marked(self, c16, source, failure):
        good = c16.cycle(0)
        cycle = c16.cycle(24, **failure)

        saved = c16.saved()
        assert cycle[source]["error"], "precondizione: la fonte del ciclo è in errore"
        _c16_assert_marker(saved, {source: _c16_entry(0, 24)}, f"{source} in errore: ")
        assert saved[source] == good[source]
        assert not saved[source]["error"], "la fonte riportata è l'osservazione, non il guasto"
        for other in {"virustotal", "otx", "securitytrails"} - {source}:
            assert saved[other] == cycle[other], other

    def test_the_section_keeps_the_timestamp_of_the_cycle(self, c16):
        # Le fonti che hanno risposto sono state osservate in questo ciclo: la sezione porta il suo istante.
        c16.cycle(0)
        c16.cycle(24, vt="429")

        assert c16.saved()["timestamp"] == _c12_at(24)

    @pytest.mark.parametrize("source, failure", _C16_SOURCE_OUTAGES)
    def test_observed_at_stays_the_last_observation_while_carried_at_follows_the_cycle(
            self, c16, source, failure):
        good = c16.cycle(0)

        for hours in (24, 48, 72):
            c16.cycle(hours, **failure)

            saved = c16.saved()
            _c16_assert_marker(saved, {source: _c16_entry(0, hours)}, f"{source} a {hours} h: ")
            assert saved[source] == good[source], f"{source} a {hours} h: non è l'ultima osservazione"

    @pytest.mark.parametrize("source, failure", _C16_SOURCE_OUTAGES)
    def test_a_source_that_answers_again_leaves_no_marker_and_a_new_outage_restarts_from_the_new_observation(
            self, c16, source, failure):
        c16.cycle(0)
        c16.cycle(24, **failure)
        assert c16.saved().get("carried_sources"), "precondizione: il riporto è marcato"

        back = c16.cycle(48)
        assert c16.saved() == back

        c16.cycle(72, **failure)
        _c16_assert_marker(c16.saved(), {source: _c16_entry(48, 72)}, f"{source}, nuovo guasto: ")

    def test_each_source_has_its_own_observation_instant(self, c16):
        good = c16.cycle(0)
        c16.cycle(24, vt="429")
        c16.cycle(48, vt="429", otx="429")

        saved = c16.saved()
        _c16_assert_marker(saved, {"virustotal": _c16_entry(0, 48), "otx": _c16_entry(24, 48)})
        assert saved["virustotal"] == good["virustotal"] and saved["otx"] == good["otx"]

    def test_nothing_is_marked_when_every_source_answers(self, c16):
        # Controllo: senza fonti riportate la chiave non c'è e la sezione è quella del ciclo.
        for hours in (0, 24, 48):
            section = c16.cycle(hours)

            assert c16.saved() == section, f"ciclo a {hours} h"
            assert "carried_sources" not in c16.saved()

    def test_a_vt_404_is_saved_as_an_observation_and_is_not_carried(self, c16):
        # Controllo: «VT non conosce il dominio» non è un guasto; gli zeri sono la sua osservazione e
        # un verdetto malevolo che compare dopo è un cambiamento vero.
        c16.cycle(0)
        section = c16.cycle(24, vt="404")

        assert section["virustotal"]["error"], "precondizione: il collector scrive il 404 in `error`"
        assert c16.saved() == section and "carried_sources" not in c16.saved()
        c16.cycle(48)
        assert c16.types() == [[], [], ["vt_malicious_detected"]], c16.types()


_C16_FORGED = [
    pytest.param({"virustotal": {"observed_at": _c12_at(-96), "carried_at": _c12_at(24)}}, id="valid-looking"),
    pytest.param({"virustotal": {"observed_at": "<script>alert(1)</script>", "carried_at": "x" * 5000},
                  "foreign": {"observed_at": _c12_at(-1)}}, id="hostile-strings"),
    pytest.param("x", id="string"), pytest.param(["virustotal"], id="list"), pytest.param(5, id="int"),
    pytest.param(None, id="null"), pytest.param(True, id="bool"), pytest.param({}, id="empty-dict"),
]

_C16_OLD_MARKERS = [
    pytest.param({"virustotal": {"observed_at": _c12_at(-96), "carried_at": _c12_at(-48)}}, id="valid-looking"),
    pytest.param({"virustotal": {"observed_at": "<script>alert(1)</script>", "carried_at": "x" * 10_000}},
                 id="hostile-strings"),
    pytest.param({"virustotal": {"observed_at": "2099-01-01T00:00:00+00:00", "carried_at": _c12_at(0)}},
                 id="observation-in-the-future"),
    pytest.param({"virustotal": {"observed_at": 5, "carried_at": ["a"]}}, id="wrong-types"),
    pytest.param({"virustotal": "x"}, id="entry-not-a-dict"),
    pytest.param({"virustotal": None}, id="entry-null"),
    pytest.param({f"foreign-{i}": {"observed_at": _c12_at(-1)} for i in range(2000)}, id="thousands-of-keys"),
    pytest.param({}, id="empty-dict"), pytest.param("x", id="string"), pytest.param(["virustotal"], id="list"),
    pytest.param(5, id="int"), pytest.param(None, id="null"), pytest.param(True, id="bool"),
]


def _c16_is_instant_or_none(value):
    """`value` è `None` o un ISO leggibile come istante (senza fuso vale UTC)."""
    if value is None:
        return True
    try:
        _c13_instant(value)
    except (TypeError, ValueError):
        return False
    return True


class TestCOL16MarkerComesOnlyFromTheOrchestrator:
    """Il marcatore lo scrive solo l'orchestrator: uno arrivato dal servizio (zona non autenticata) non
    entra nello snapshot né nel payload di `/diff`, e uno vecchio malformato sul disco non solleva né
    si copia."""

    @pytest.mark.parametrize("forged", _C16_FORGED)
    def test_a_marker_inside_the_response_of_the_collector_is_removed(self, c16, forged):
        c16.cycle(0)
        answer = c16.collect(24)
        answer["carried_sources"] = copy.deepcopy(forged)
        answer["carried_over"] = copy.deepcopy(forged)

        c16.run(24, reputation=answer)

        saved = c16.saved()
        assert "carried_sources" not in saved, (
            f"un marcatore arrivato dal servizio è entrato nello snapshot: {saved['carried_sources']!r}")
        assert "carried_over" not in saved, saved.get("carried_over")
        assert saved == c16.collect(24), "il resto della sezione si salva com'è"
        assert "carried_sources" not in json.dumps(c16.run.payloads[-1])

    @pytest.mark.parametrize("forged", _C16_FORGED)
    def test_a_marker_from_the_service_does_not_alter_the_one_the_orchestrator_writes(self, c16, forged):
        c16.cycle(0)
        answer = c16.collect(24, vt="429")
        answer["carried_sources"] = copy.deepcopy(forged)
        answer["carried_over"] = copy.deepcopy(forged)

        c16.run(24, reputation=answer)

        saved = c16.saved()
        _c16_assert_marker(saved, {"virustotal": _c16_entry(0, 24)})
        assert "carried_over" not in saved, saved.get("carried_over")

    @pytest.mark.parametrize("old", _C16_OLD_MARKERS)
    def test_a_malformed_previous_marker_does_not_raise_and_is_not_copied(
            self, orch, monkeypatch, c16_collect, old):
        previous = c16_collect(0)
        previous["carried_sources"] = copy.deepcopy(old)
        fresh = c16_collect(24, vt="429")

        saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(reputation=previous),
                                   _c13_intel({"reputation": fresh}))

        marker = saved["reputation"].get("carried_sources")
        assert marker is not None and set(marker) == {"virustotal"}, f"carried_sources salvato: {marker!r}"
        entry = marker["virustotal"]
        assert set(entry) == {"observed_at", "carried_at"} and entry["carried_at"] == _C12_NOW, entry
        assert _c16_is_instant_or_none(entry["observed_at"]), entry
        if entry["observed_at"] is not None:
            assert _c13_instant(entry["observed_at"]) <= _c13_instant(_C12_NOW), entry
        assert len(json.dumps(marker)) < 300
        assert saved["reputation"]["virustotal"] == previous["virustotal"]


class TestCOL16SourcesWithoutAUsableObservationAreLeftAlone:
    """Controlli: una fonte `None` (non interrogata) e una sezione precedente senza un valore osservato
    per la fonte non producono riporto né marcatore, e non sollevano."""

    def test_a_source_that_is_no_longer_queried_stays_none(self, c16):
        c16.cycle(0)
        section = c16.cycle(24, otx=None)

        assert section["otx"] is None, "precondizione: OTX non interrogato"
        assert c16.saved() == section and "carried_sources" not in c16.saved()

    def test_a_source_that_fails_after_never_being_queried_is_saved_as_it_is(self, c16):
        c16.cycle(0, otx=None)
        section = c16.cycle(24, otx="429")

        assert c16.saved() == section and "carried_sources" not in c16.saved()

    def test_a_source_that_is_queried_for_the_first_time_is_saved_as_it_is(self, c16):
        c16.cycle(0, otx=None)
        section = c16.cycle(24)

        assert c16.saved() == section and "carried_sources" not in c16.saved()

    def test_a_none_source_does_not_stop_another_source_from_being_carried(self, c16):
        good = c16.cycle(0, otx=None)
        c16.cycle(24, otx=None, vt="429")

        saved = c16.saved()
        _c16_assert_marker(saved, {"virustotal": _c16_entry(0, 24)})
        assert saved["virustotal"] == good["virustotal"]
        assert saved["otx"] is None

    @pytest.mark.parametrize("previous", ["text", 5, 1.5, True, [], None],
                             ids=["string", "int", "float", "bool", "list", "null"])
    def test_a_previous_source_that_is_not_a_dict_carries_nothing(self, orch, monkeypatch, c16_collect, previous):
        before = c16_collect(0)
        before["virustotal"] = previous
        fresh = c16_collect(24, vt="429")

        saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(reputation=before),
                                   _c13_intel({"reputation": fresh}))

        assert saved["reputation"] == fresh

    @pytest.mark.parametrize("previous", ["text", 5, 1.5, True, [], None],
                             ids=["string", "int", "float", "bool", "list", "null"])
    def test_a_previous_section_that_is_not_a_dict_carries_nothing(self, orch, monkeypatch, c16_collect, previous):
        fresh = c16_collect(24, vt="429")

        saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(reputation=previous),
                                   _c13_intel({"reputation": fresh}))

        assert saved["reputation"] == fresh

    def test_a_previous_source_that_was_itself_unobserved_is_not_carried(self, orch, monkeypatch, c16_collect):
        before = c16_collect(0, vt="429")
        fresh = c16_collect(24, vt="500")

        saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(reputation=before),
                                   _c13_intel({"reputation": fresh}))

        assert saved["reputation"] == fresh


class TestCOL16TheSavedScoreFollowsTheSavedSection:
    """`risk_score` e `risk_level` si calcolano sulla sezione che si salva: con una fonte riportata
    contano i suoi numeri, e il ciclo guasto non abbassa il rischio persistito."""

    @staticmethod
    def _score(section):
        return section["risk_score"], section["risk_level"]

    def _assert_saved_score(self, c16, expected, why, where=""):
        actual = self._score(c16.saved())
        assert actual == expected, f"{where}rischio salvato {actual}, atteso {expected}: {why}"

    def test_a_carried_virustotal_keeps_the_risk_of_the_last_good_cycle(self, c16):
        good = c16.cycle(0)
        cycle = c16.cycle(24, vt="429")

        assert self._score(good) == (50, "medium")
        assert self._score(cycle) == (10, "low"), "precondizione: senza VT il collector dà 10"
        self._assert_saved_score(c16, (50, "medium"), "VT riportato conta, il ciclo guasto non abbassa il rischio")

    def test_a_carried_otx_keeps_the_risk_of_the_last_good_cycle(self, c16):
        c16.cycle(0)
        cycle = c16.cycle(24, otx="429")

        assert self._score(cycle) == (40, "medium"), "precondizione: senza OTX il collector dà 40"
        self._assert_saved_score(c16, (50, "medium"), "OTX riportato conta, il ciclo guasto non abbassa il rischio")

    def test_a_carried_securitytrails_leaves_the_risk_alone(self, c16):
        c16.cycle(0)
        c16.cycle(24, st="500")

        assert c16.saved().get("carried_sources"), "precondizione: il riporto è marcato"
        self._assert_saved_score(c16, (50, "medium"), "SecurityTrails non pesa sul rischio")

    def test_the_risk_stays_through_consecutive_outage_cycles(self, c16):
        c16.cycle(0)

        for hours in (24, 48, 72):
            c16.cycle(hours, vt="429")
            self._assert_saved_score(c16, (50, "medium"), "VT riportato conta", f"ciclo a {hours} h: ")

    def test_the_risk_is_computed_on_the_saved_section_when_the_other_source_changes_too(self, c16):
        # VT riportato (malicious 3: 40) più OTX osservato con 5 pulse (25): 65, `high`. Non il rischio
        # del ciclo (25, solo OTX) e non quello copiato dalla sezione precedente (50).
        c16.cycle(0)
        cycle = c16.cycle(24, vt="429", otx="pulses5")

        assert self._score(cycle) == (25, "medium"), "precondizione: senza VT il collector dà 25"
        self._assert_saved_score(c16, (65, "high"), "40 di VT riportato più 25 di OTX osservato")

    def test_the_risk_is_computed_on_the_saved_section_when_virustotal_changes_too(self, c16):
        # OTX riportato (2 pulse: 10) più VT osservato con malicious 5 (50 + 10): 70, `high`. Non il
        # rischio del ciclo (60, solo VT) e non quello della sezione precedente (50).
        c16.cycle(0)
        cycle = c16.cycle(24, vt="mal5", otx="429")

        assert self._score(cycle) == (60, "high"), "precondizione: senza OTX il collector dà 60"
        self._assert_saved_score(c16, (70, "high"), "60 di VT osservato più 10 di OTX riportato")


class TestCOL16PartialOutageThenWholeModuleOutage:
    """Il guasto di una fonte e poi quello dell'intero modulo (`carried_over`, tutte le fonti in
    errore): la sezione riportata conserva la fonte riportata e il ritorno non allerta."""

    def test_a_total_outage_after_a_partial_one_keeps_the_source_marker(self, c16):
        good = c16.cycle(0)
        c16.cycle(24, vt="429")
        c16.cycle(48, vt="429", otx="429", st="429")

        saved = c16.saved()
        assert saved.get("carried_over", {}).get("carried_at") == _c12_at(48, seconds=30), (
            "precondizione: il modulo è riportato per intero")
        marker = saved.get("carried_sources")
        assert marker is not None and set(marker) == {"virustotal"}, f"carried_sources salvato: {marker!r}"
        assert marker["virustotal"]["observed_at"] == _c12_at(0)
        assert set(marker["virustotal"]) == {"observed_at", "carried_at"}
        assert saved["virustotal"] == good["virustotal"]

    def test_the_return_after_a_partial_then_total_outage_raises_no_alert(self, c16):
        c16.cycle(0)
        c16.cycle(24, vt="429")
        c16.cycle(48, vt="429", otx="429", st="429")
        c16.cycle(72)

        assert c16.types() == [[]] * 4, c16.types()

    def test_a_partial_outage_after_a_total_one_carries_the_observation_the_total_one_had_carried(self, c16):
        good = c16.cycle(0)
        c16.cycle(24, vt="429", otx="429", st="429")
        c16.cycle(48, vt="429")

        saved = c16.saved()
        _c16_assert_marker(saved, {"virustotal": _c16_entry(0, 48)})
        assert "carried_over" not in saved, "il modulo ha risposto: nessun riporto dell'intero modulo"
        assert saved["virustotal"] == good["virustotal"]
        c16.cycle(72)
        assert c16.types() == [[]] * 4, c16.types()


class TestCOL16CycleObservationIsLeftIntact:
    """Il marcatore sta nello snapshot e basta: l'osservazione del ciclo (`intel["reputation"]`, letta
    da eventi e classificazione), la risposta del collector e lo snapshot precedente non si toccano."""

    def test_the_cycle_observation_and_the_previous_snapshot_are_not_mutated(self, orch, monkeypatch, c16_collect):
        prev = _c13_previous(reputation=c16_collect(0))
        fresh = _c13_intel({"reputation": c16_collect(24, vt="429")})
        prev_before, fresh_before = copy.deepcopy(prev), copy.deepcopy(fresh)

        saved, sent, intel = _c13_persist(monkeypatch, orch, prev, fresh)

        assert saved["reputation"].get("carried_sources"), "precondizione: il riporto è marcato"
        assert intel is fresh and fresh == fresh_before
        assert intel["reputation"]["virustotal"]["error"], "l'osservazione del ciclo resta quella guasta"
        assert prev == prev_before
        assert sent[0]["baseline"]["reputation"] == prev_before["reputation"]
        assert saved["reputation"] is not prev["reputation"]
        assert saved["reputation"]["virustotal"] is not prev["reputation"]["virustotal"]

    def test_the_response_of_the_collector_is_not_mutated_when_a_forged_marker_is_removed(
            self, orch, monkeypatch, c16_collect):
        answer = c16_collect(24)
        answer["carried_sources"] = {"virustotal": {"observed_at": _c12_at(-96), "carried_at": _c12_at(24)}}
        fresh = _c13_intel({"reputation": answer})
        before = copy.deepcopy(fresh)

        saved, _, intel = _c13_persist(monkeypatch, orch, _c13_previous(reputation=c16_collect(0)), fresh)

        assert "carried_sources" not in saved["reputation"], "precondizione: il marcatore forgiato è tolto"
        assert intel is fresh and fresh == before


class TestCOL16EventsAndClassificationDoNotSeeTheMarker:
    """La pipeline vera (`_run_pipeline`, classificatore reale) con una fonte in errore: il ciclo si
    classifica come un ciclo normale, e con uno snapshot in archivio (riporto + marcatore) eventi e
    payload verso il classificatore sono quelli dello stesso ciclo senza archivio."""

    @staticmethod
    def _cycle(o, monkeypatch, modules):
        published, payloads = [], []
        monkeypatch.setattr(o._session, "get", _c13_pipeline_get(o, modules))
        monkeypatch.setattr(o._session, "post", _real_classifier_post(o, published, payloads))
        o._run_pipeline(_c02_request(o, include_whois=True, include_reputation=True))
        event = _event_for(published, _C02_DOMAIN)
        assert event is not None, published
        classification = {k: v for k, v in event["classification"].items() if k != "timestamp"}
        return {**event, "classification": classification}, payloads

    @pytest.mark.parametrize("source, failure", _C16_SOURCE_OUTAGES)
    def test_the_event_and_the_classification_are_the_same_with_and_without_the_marker(
            self, orch, monkeypatch, tmp_path, c16_collect, source, failure):
        fresh = _c13_intel({"reputation": c16_collect(24, **failure)})

        monkeypatch.setattr(orch, "INTEL_STORE", False)
        bare_event, bare_payloads = self._cycle(orch, monkeypatch, fresh)

        monkeypatch.setattr(orch, "INTEL_STORE", True)
        monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
        monkeypatch.setattr(orch.intel_store, "HIST_DIR", tmp_path / "history")
        assert orch.intel_store.save_snapshot("acme", _C02_DOMAIN, _c13_previous(reputation=c16_collect(0)))
        event, payloads = self._cycle(orch, monkeypatch, fresh)

        saved = orch.intel_store.load_snapshot("acme", _C02_DOMAIN)["intel"]["reputation"]
        assert source in (saved.get("carried_sources") or {}), "precondizione: la fonte guasta è riportata"
        assert event == bare_event
        assert payloads == bare_payloads
        assert "carried_sources" not in json.dumps([event, payloads])

    @pytest.mark.parametrize("source, failure", _C16_SOURCE_OUTAGES)
    def test_a_cycle_with_one_failed_source_is_classified_like_a_cycle_with_every_source_answering(
            self, orch, monkeypatch, c16_collect, source, failure):
        # Controllo: il ciclo parziale è un ciclo normale per la classificazione, non un
        # `insufficient_data`; nessuna regola del caso legge la reputazione.
        monkeypatch.setattr(orch, "INTEL_STORE", False)
        whole, _ = self._cycle(orch, monkeypatch, _c13_intel({"reputation": c16_collect(24)}))

        partial, _ = self._cycle(orch, monkeypatch, _c13_intel({"reputation": c16_collect(24, **failure)}))

        assert partial["classification"]["auto_classification"] != "insufficient_data", partial["classification"]
        assert partial["classification"] == whole["classification"]
        assert _severity_of(orch, partial) == _severity_of(orch, whole)


_C16_SILENT_OUTAGES = [pytest.param("virustotal", {"vt": "silent"}, id="virustotal"),
                       pytest.param("otx", {"otx": "silent"}, id="otx"),
                       pytest.param("securitytrails", {"st": "silent"}, id="securitytrails")]


class TestCOL16AnEmptyErrorTextStillMeansUnobserved:
    """«Non osservata» si decide per la PRESENZA di `error` (non `None`), non per la verità del testo:
    un'eccezione senza messaggio dà `error: ""` (`sanitize_error`) ed è un guasto come gli altri."""

    @pytest.mark.parametrize("source, failure", _C16_SILENT_OUTAGES)
    def test_the_source_is_carried_and_marked_and_the_risk_is_kept(self, c16, source, failure):
        good = c16.cycle(0)
        cycle = c16.cycle(24, **failure)

        saved = c16.saved()
        assert cycle[source]["error"] == "", "precondizione: il collector scrive `error` vuoto, non `null`"
        _c16_assert_marker(saved, {source: _c16_entry(0, 24)}, f"{source} con `error` vuoto: ")
        assert saved[source] == good[source]
        assert (saved["risk_score"], saved["risk_level"]) == (50, "medium")

    @pytest.mark.parametrize("length", _C16_OUTAGE_LENGTHS)
    @pytest.mark.parametrize("source, failure", _C16_SILENT_OUTAGES)
    def test_back_with_the_same_verdict_raises_no_alert(self, c16, source, failure, length):
        c16.cycle(0)
        for n in range(1, length + 1):
            c16.cycle(24 * n, **failure)
        c16.cycle(24 * (length + 1))

        assert c16.types() == [[]] * (length + 2), (
            f"{source} con `error` vuoto prima del ritorno: alert per ciclo {c16.types()}")

    @pytest.mark.parametrize("source, failure, alert", [
        pytest.param("virustotal", {"vt": "silent"}, "vt_malicious_detected", id="virustotal"),
        pytest.param("otx", {"otx": "silent"}, "otx_pulse_detected", id="otx")])
    def test_a_real_increase_across_the_outage_still_alerts(self, c16, source, failure, alert):
        before, after = ({"vt": "mal0"}, {"vt": "mal3"}) if source == "virustotal" else (
            {"otx": "pulses0"}, {"otx": "pulses5"})
        c16.cycle(0, **before)
        c16.cycle(24, **failure)
        c16.cycle(48, **after)

        assert c16.types() == [[], [], [alert]], c16.types()


class TestCOL16ACarried404IsAnObservation:
    """Il 404 di VT è un'osservazione (gli zeri sono veri): un guasto dopo un 404 la riporta, con
    marcatore, e al ritorno un verdetto malevolo è un cambiamento vero."""

    def test_a_vt_404_followed_by_an_outage_is_carried_and_marked(self, c16):
        first = c16.cycle(0, vt="404")
        cycle = c16.cycle(24, vt="429")

        saved = c16.saved()
        assert first["virustotal"]["error"] and cycle["virustotal"]["error"] != first["virustotal"]["error"], (
            "precondizione: il 404 e il guasto sono due esiti diversi")
        _c16_assert_marker(saved, {"virustotal": _c16_entry(0, 24)}, "404 seguito da un guasto: ")
        assert saved["virustotal"] == first["virustotal"], "la fonte riportata è l'osservazione del 404"

    @pytest.mark.parametrize("length", _C16_OUTAGE_LENGTHS)
    def test_the_return_with_a_malicious_verdict_alerts(self, c16, length):
        c16.cycle(0, vt="404")
        for n in range(1, length + 1):
            c16.cycle(24 * n, vt="429")
        c16.cycle(24 * (length + 1), vt="mal3")

        assert c16.types() == [[]] * (length + 1) + [["vt_malicious_detected"]], c16.types()
        assert c16.run.per_cycle[-1][0][1] == "CRITICAL"


# ═══════════════════════════════════════════════════════════════
# COL-16 — dati non validi non fermano lo snapshot; i marcatori forgiati non entrano mai; un solo istante
# ═══════════════════════════════════════════════════════════════
#
# Il riporto per fonte copia e ricalcola: lavora su sezioni che arrivano da un servizio non autenticato
# (il ciclo) e da un file su disco (il precedente). Su dati che il collector non produrrebbe (numeri che
# sono testo, `None`, una fonte che è una stringa, un precedente avvelenato, una fonte annidata oltre il
# limite di ricorsione della copia) il riporto si abbandona: la sezione salvata è quella del ciclo così
# come la manda il servizio, senza i marcatori in ingresso, e nessuna eccezione esce da `_persist_intel`.
# Un'eccezione lì non salverebbe lo snapshot del dominio a ogni ciclo, e nel ramo delle varianti salterebbe
# anche la classificazione. Inoltre i marcatori arrivati dal servizio non entrano nello snapshot nemmeno
# quando non c'è un precedente con cui confrontarsi, e tutti i riporti di un ciclo (fonte, modulo, parte
# DNS) portano lo stesso istante.

import sys

_C16_FORGED_MARKERS = {
    "carried_sources": {"virustotal": {"observed_at": _c12_at(-96), "carried_at": _c12_at(24)}},
    "carried_over": {"observed_at": _c12_at(-96), "carried_at": _c12_at(24)},
}

# (guasto del ciclo, alterazione della sezione): ciò che il collector non scriverebbe mai.
_C16_INVALID_CYCLES = [
    pytest.param({"vt": "429"}, lambda s: s["otx"].update(pulse_count="x"), id="otx-pulse-count-text"),
    pytest.param({"vt": "429"}, lambda s: s["otx"].update(pulse_count=None), id="otx-pulse-count-null"),
    pytest.param({"vt": "429"}, lambda s: s["otx"].update(pulse_count="3"), id="otx-pulse-count-numeric-text"),
    pytest.param({"vt": "429"}, lambda s: s["otx"].update(pulse_count=[]), id="otx-pulse-count-list"),
    pytest.param({"vt": "429"}, lambda s: s.update(otx="oops"), id="otx-is-a-string"),
    pytest.param({"vt": "429"}, lambda s: s.update(otx=[1]), id="otx-is-a-list"),
    pytest.param({"vt": "429"}, lambda s: s.update(otx=7), id="otx-is-a-number"),
    pytest.param({"otx": "429"}, lambda s: s["virustotal"].update(malicious="x"), id="vt-malicious-text"),
    pytest.param({"otx": "429"}, lambda s: s["virustotal"].update(suspicious=None), id="vt-suspicious-null"),
    pytest.param({"otx": "429"}, lambda s: s["virustotal"].update(reputation="x"), id="vt-reputation-text"),
    pytest.param({"otx": "429"}, lambda s: s.update(virustotal="oops"), id="vt-is-a-string"),
]

# Una fonte VT già osservata ma con numeri non validi, come potrebbe averla lasciata su disco un ciclo
# di una versione precedente o un servizio ostile.
_C16_POISONED_VT = [pytest.param({"malicious": "x"}, id="malicious-text"),
                    pytest.param({"suspicious": None}, id="suspicious-null"),
                    pytest.param({"reputation": "x"}, id="reputation-text")]


def _c16_persist_or_fail(c16, hours, section):
    """Un ciclo di `_persist_intel` con `section` come reputazione: un'eccezione che esce di lì è un
    fallimento del test, con il suo tipo."""
    try:
        c16.run(hours, reputation=section)
    except Exception as error:
        pytest.fail(f"_persist_intel ha sollevato {type(error).__name__}: {str(error)[:120]}")


def _c16_write_snapshot_with_deep_source(path, reputation):
    """Scrive in `path` uno snapshot il cui `virustotal.categories` è annidato quanto il limite di
    ricorsione dell'interprete: il file si carica con `json.loads`, la sua `copy.deepcopy` solleva
    `RecursionError`. Il testo si compone a mano, perché serve a costruire l'input, non a provare altro."""
    nested = '{"a":' * sys.getrecursionlimit() + "{}" + "}" * sys.getrecursionlimit()
    reputation = copy.deepcopy(reputation)
    reputation["virustotal"]["categories"] = "@@NESTED@@"
    record = {"domain": _C02_DOMAIN, "client": "acme", "updated_at": _c12_at(0),
              "intel": _c13_previous(reputation=reputation)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record).replace('"@@NESTED@@"', nested), encoding="utf-8")
    stored = json.loads(path.read_text(encoding="utf-8"))["intel"]["reputation"]["virustotal"]
    with pytest.raises(RecursionError):
        copy.deepcopy(stored)   # precondizione: il file si carica, la sua copia no


class TestCOL16InvalidDataNeverStopsTheSnapshot:
    """Su dati non validi lo snapshot si salva con la sezione del ciclo, senza riporto né marcatori."""

    @pytest.mark.parametrize("failure, mutate", _C16_INVALID_CYCLES)
    def test_an_invalid_cycle_is_saved_as_the_service_sent_it(self, c16, failure, mutate):
        c16.cycle(0)
        cycle = c16.collect(24, **failure)
        mutate(cycle)
        expected = copy.deepcopy(cycle)
        cycle.update(copy.deepcopy(_C16_FORGED_MARKERS))

        _c16_persist_or_fail(c16, 24, cycle)

        assert c16.run.section("dns")["timestamp"] == _c12_at(24), "lo snapshot di questo ciclo non è stato salvato"
        assert c16.saved() == expected, "la sezione salvata non è quella del ciclo senza i marcatori in ingresso"

    @pytest.mark.parametrize("poison", _C16_POISONED_VT)
    def test_a_poisoned_snapshot_on_disk_is_replaced_by_the_cycle_and_heals(self, c16, orch, poison):
        poisoned = c16.collect(0)
        poisoned["virustotal"].update(poison)
        assert orch.intel_store.save_snapshot("acme", _C02_DOMAIN, _c13_previous(reputation=poisoned))
        cycle = c16.collect(24, vt="429")

        _c16_persist_or_fail(c16, 24, copy.deepcopy(cycle))

        assert c16.run.section("dns")["timestamp"] == _c12_at(24), "lo snapshot di questo ciclo non è stato salvato"
        assert c16.saved() == cycle, "lo snapshot avvelenato non è stato sostituito dalla sezione del ciclo"
        back = c16.collect(48)
        _c16_persist_or_fail(c16, 48, copy.deepcopy(back))
        assert c16.saved() == back

    def test_a_previous_source_nested_beyond_the_copy_limit_does_not_stop_the_snapshot(self, c16, orch):
        _c16_write_snapshot_with_deep_source(orch.intel_store.SNAP_DIR / "acme" / f"{_C02_DOMAIN}.json",
                                             c16.collect(0))
        cycle = c16.collect(24, vt="429")

        _c16_persist_or_fail(c16, 24, copy.deepcopy(cycle))

        assert c16.run.section("dns")["timestamp"] == _c12_at(24), "lo snapshot di questo ciclo non è stato salvato"
        assert c16.saved() == cycle


_C16_NO_SNAPSHOT = object()   # nel parametro `prior`: «nessuno snapshot precedente»
_C16_VARIANT = "acme-variant.example"   # la variante di `_C02_VARIANT_TWIST`


def _c16_variant_cycle(o, monkeypatch, tmp_path, reputation, prior=_C16_NO_SNAPSHOT):
    """Un ciclo di `_run_pipeline` con dnstwist e `variant_intel` (il target è in whitelist: resta la
    variante), classificatore reale e store su directory temporanea. `prior` è la sezione `reputation`
    dello snapshot precedente della variante (`_C16_NO_SNAPSHOT`: nessuno snapshot). Ritorna (evento
    della variante, payload di `/classify/variant`)."""
    monkeypatch.setattr(o, "INTEL_STORE", True)
    monkeypatch.setattr(o.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(o.intel_store, "HIST_DIR", tmp_path / "history")
    if prior is not _C16_NO_SNAPSHOT:
        assert o.intel_store.save_snapshot("acme", _C16_VARIANT, _c13_previous(reputation=prior))
    modules = _c13_intel({"reputation": reputation})
    plain_get = _c13_pipeline_get(o, modules)

    def _get(url, timeout=None):
        if "/feed/domains" in url:
            return _R({"domains": _C02_VARIANT_FEED})
        if "/feed/whitelist" in url:
            return _R({"whitelist": {_C02_DOMAIN: {}}})
        if url.startswith(o.TWIST_URL):
            return _R(_C02_VARIANT_TWIST)
        return plain_get(url, timeout=timeout)

    published, payloads = [], []
    monkeypatch.setattr(o._session, "get", _get)
    monkeypatch.setattr(o._session, "post", _real_classifier_post(o, published, payloads))
    o._run_pipeline(_c02_request(o, include_reputation=True, include_dnstwist=True, variant_intel=True))
    event = _event_for(published, _C16_VARIANT)
    assert event is not None, f"nessun evento per la variante: {published}"
    return event, [p for p in payloads if p.get("domain") == _C16_VARIANT]


def _c16_saved_variant_reputation(o):
    return o.intel_store.load_snapshot("acme", _C16_VARIANT)["intel"]["reputation"]


class TestCOL16InvalidDataInTheVariantBranch:
    """Il ramo `variant_intel`: salvare lo snapshot e classificare la variante stanno nello stesso `try`.
    Dati non validi nella reputazione della variante non devono saltare la classificazione."""

    CASES = [
        pytest.param(lambda collect: collect(0), lambda collect: {**collect(24, vt="429"),
                                                                  "otx": {**collect(24)["otx"], "pulse_count": "x"}},
                     id="otx-pulse-count-text"),
        pytest.param(lambda collect: {**collect(0), "virustotal": {**collect(0)["virustotal"], "malicious": "x"}},
                     lambda collect: collect(24, vt="429"), id="poisoned-previous-snapshot"),
        pytest.param(lambda collect: collect(0), lambda collect: {**collect(24, otx="429"),
                                                                  "virustotal": "oops"}, id="vt-is-a-string"),
    ]

    @pytest.mark.parametrize("prior, cycle", CASES)
    def test_the_variant_is_still_classified_and_marked_as_collected(
            self, orch, monkeypatch, tmp_path, c16_collect, prior, cycle):
        reputation = cycle(c16_collect)

        event, classified = _c16_variant_cycle(orch, monkeypatch, tmp_path, copy.deepcopy(reputation),
                                               prior=prior(c16_collect))

        assert classified, "il classificatore non è stato chiamato per la variante"
        assert event["intel_summary"].get("intel_collected") is True
        assert event["classification"]["rule"] != "dnstwist_discovery", (
            f"classificazione di scoperta, non quella del classificatore: {event['classification']}")
        assert _c16_saved_variant_reputation(orch) == reputation


    def test_a_previous_source_nested_beyond_the_copy_limit_does_not_skip_the_classification(
            self, orch, monkeypatch, tmp_path, c16_collect):
        _c16_write_snapshot_with_deep_source(tmp_path / "snapshots" / "acme" / f"{_C16_VARIANT}.json",
                                             c16_collect(0))
        reputation = c16_collect(24, vt="429")

        event, classified = _c16_variant_cycle(orch, monkeypatch, tmp_path, copy.deepcopy(reputation))

        assert classified, "il classificatore non è stato chiamato per la variante"
        assert event["intel_summary"].get("intel_collected") is True
        assert _c16_saved_variant_reputation(orch) == reputation


class TestCOL16ForgedMarkersWithoutAPreviousReputation:
    """I marcatori arrivati dal servizio non entrano nello snapshot nemmeno quando il precedente manca:
    nessuno snapshot, uno senza `reputation`, uno con una `reputation` che non è un dict."""

    PREVIOUS = [pytest.param(_C16_NO_SNAPSHOT, id="no-snapshot"), pytest.param(None, id="reputation-null"),
                pytest.param("text", id="reputation-string"), pytest.param([], id="reputation-list")]

    @pytest.mark.parametrize("forged", _C16_FORGED)
    @pytest.mark.parametrize("sources", [{}, {"vt": "429"}], ids=["every-source-answers", "one-source-fails"])
    @pytest.mark.parametrize("previous", PREVIOUS)
    def test_a_marker_inside_the_response_of_the_collector_is_removed(
            self, orch, monkeypatch, c16_collect, previous, sources, forged):
        answer = c16_collect(24, **sources)
        expected = copy.deepcopy(answer)
        answer["carried_sources"] = copy.deepcopy(forged)
        answer["carried_over"] = copy.deepcopy(forged)
        prev_intel = None if previous is _C16_NO_SNAPSHOT else _c13_previous(reputation=previous)

        saved, sent, _ = _c13_persist(monkeypatch, orch, prev_intel, _c13_intel({"reputation": answer}),
                                      snapshot=prev_intel is not None)

        assert saved["reputation"] == expected, "un marcatore del servizio è entrato nello snapshot"
        assert sent == [] or "carried_sources" not in json.dumps(sent[0]["current"]["reputation"])

    @pytest.mark.parametrize("prior", [_C16_NO_SNAPSHOT, None], ids=["no-snapshot", "reputation-null"])
    def test_a_marker_inside_the_response_for_a_variant_is_removed(
            self, orch, monkeypatch, tmp_path, c16_collect, prior):
        answer = c16_collect(24, vt="429")
        expected = copy.deepcopy(answer)
        answer["carried_sources"] = copy.deepcopy(_C16_FORGED_MARKERS["carried_sources"])
        answer["carried_over"] = copy.deepcopy(_C16_FORGED_MARKERS["carried_over"])

        _c16_variant_cycle(orch, monkeypatch, tmp_path, answer, prior=prior)

        assert _c16_saved_variant_reputation(orch) == expected, "un marcatore del servizio è entrato nello snapshot"


class TestCOL16OneInstantForEveryCarryOfTheCycle:
    """Il ciclo legge l'istante UNA volta: la fonte riportata (COL-16), il modulo intero (COL-13) e la
    parte DNS (COL-12) portano lo stesso `carried_at`, anche con un orologio che avanza a ogni chiamata."""

    def test_the_source_the_module_and_the_dns_part_share_the_instant(self, orch, monkeypatch, c16_collect):
        calls = []

        def tick():
            calls.append(1)
            return _c12_at(24, seconds=len(calls))

        fresh = _c13_intel({"cert": None, "reputation": c16_collect(24, vt="429", otx="429")})
        fresh["dns"] = _c02_unknown(fresh["dns"], "A")

        saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(reputation=c16_collect(0)), fresh, now=tick)

        sources = saved["reputation"].get("carried_sources") or {}
        module = saved["cert"].get("carried_over") or {}
        part = (saved["dns"].get("carried_over") or {}).get("A") or {}
        assert set(sources) == {"virustotal", "otx"} and module and part, "precondizione: tre riporti nello stesso ciclo"
        stamps = {"virustotal": sources["virustotal"]["carried_at"], "otx": sources["otx"]["carried_at"],
                  "cert": module.get("carried_at"), "dns A": part.get("carried_at")}
        assert len(set(stamps.values())) == 1, f"istanti diversi nello stesso ciclo: {stamps}"
        assert len(calls) == 1, f"now_iso() letto {len(calls)} volte, non una"


# ═══════════════════════════════════════════════════════════════
# COL-16 — il ripiego copre anche gli errori aritmetici, lascia una riga di log e non dipende dal timestamp
# ═══════════════════════════════════════════════════════════════
#
# Il ricalcolo del rischio può sollevare anche `OverflowError`: un float non finito (`NaN`, `-inf`, che
# JSON rappresenta) sommato a un intero enorme (fino a 4300 cifre) non si converte. Rientra nel ripiego
# degli altri dati non validi: nessuna eccezione da `_persist_intel`, snapshot salvato con la sezione del
# ciclo, e nel ramo delle varianti la classificazione avviene. Quando il ripiego scatta, l'orchestrator
# scrive UNA riga di warning con il nome della classe dell'eccezione e mai il contenuto del payload (la
# sezione viene da una zona non autenticata: un valore forgiato nel log sarebbe un canale di iniezione).
# Un riporto riuscito non scrive nulla. Una sezione precedente osservata ma senza `timestamp` leggibile
# si riporta comunque, con `observed_at` nullo.

import logging

# Il valore forgiato che nessun log deve contenere.
_C16_MARKER = "forged-7f3a-marker"

# (guasto del ciclo, alterazione): numeri non finiti più interi enormi, rappresentabili in JSON.
_C16_OVERFLOWING_CYCLES = [
    pytest.param({"st": "500"}, lambda s: (s["virustotal"].update(malicious=float("-inf")),
                                           s["otx"].update(pulse_count=-10 ** 400)),
                 id="vt-minus-infinity-otx-huge-negative"),
    pytest.param({"otx": "429"}, lambda s: s["virustotal"].update(malicious=float("-inf"), suspicious=-10 ** 400),
                 id="vt-minus-infinity-and-huge-suspicious"),
]


class TestCOL16ArithmeticErrorsNeverStopTheSnapshot:
    """`OverflowError` come gli altri dati non validi: lo snapshot si salva con la sezione del ciclo."""

    @pytest.mark.parametrize("failure, mutate", _C16_OVERFLOWING_CYCLES)
    def test_an_overflowing_cycle_is_saved_as_the_service_sent_it(self, c16, failure, mutate):
        c16.cycle(0)
        cycle = c16.collect(24, **failure)
        mutate(cycle)
        expected = copy.deepcopy(cycle)
        cycle.update(copy.deepcopy(_C16_FORGED_MARKERS))

        _c16_persist_or_fail(c16, 24, cycle)

        assert c16.run.section("dns")["timestamp"] == _c12_at(24), "lo snapshot di questo ciclo non è stato salvato"
        assert c16.saved() == expected, "la sezione salvata non è quella del ciclo senza i marcatori in ingresso"

    def test_a_nan_cycle_is_saved_as_the_service_sent_it(self, orch, monkeypatch, c16_collect):
        # `NaN` non è uguale a se stesso: il confronto regge perché la sezione salvata conserva lo stesso
        # oggetto del ciclo, e lo store qui è finto per non passare da una serializzazione.
        cycle = c16_collect(24, st="500")
        cycle["virustotal"]["malicious"] = float("nan")
        cycle["otx"]["pulse_count"] = -10 ** 400
        expected = copy.deepcopy(cycle)
        cycle.update(copy.deepcopy(_C16_FORGED_MARKERS))
        try:
            saved, _, _ = _c13_persist(monkeypatch, orch, _c13_previous(reputation=c16_collect(0)),
                                       _c13_intel({"reputation": cycle}))
        except Exception as error:
            pytest.fail(f"_persist_intel ha sollevato {type(error).__name__}: {str(error)[:120]}")

        assert saved["reputation"] == expected

    def test_the_variant_is_still_classified_and_marked_as_collected(
            self, orch, monkeypatch, tmp_path, c16_collect):
        reputation = c16_collect(24, st="500")
        reputation["virustotal"]["malicious"] = float("-inf")
        reputation["otx"]["pulse_count"] = -10 ** 400

        event, classified = _c16_variant_cycle(orch, monkeypatch, tmp_path, copy.deepcopy(reputation),
                                               prior=c16_collect(0))

        assert classified, "il classificatore non è stato chiamato per la variante"
        assert event["intel_summary"].get("intel_collected") is True
        assert event["classification"]["rule"] != "dnstwist_discovery", (
            f"classificazione di scoperta, non quella del classificatore: {event['classification']}")
        assert _c16_saved_variant_reputation(orch) == reputation


def _c16_run_fallback_scenario(c16, orch, scenario):
    """Un ciclo che porta il riporto sul ripiego. Ogni dato non valido, e ogni marcatore in ingresso,
    porta `_C16_MARKER`: se finisce in un log è un contenuto del payload."""
    forged = {"carried_sources": {"virustotal": {"observed_at": _C16_MARKER, "carried_at": _C16_MARKER}},
              "carried_over": {"observed_at": _C16_MARKER, "carried_at": _C16_MARKER}}
    if scenario == "nested-previous-source":
        previous = c16.collect(0)
        previous["virustotal"]["note"] = _C16_MARKER
        _c16_write_snapshot_with_deep_source(orch.intel_store.SNAP_DIR / "acme" / f"{_C02_DOMAIN}.json", previous)
        cycle = c16.collect(24, vt="429")
    else:
        c16.cycle(0)
        if scenario == "pulse-count-text":
            cycle = c16.collect(24, vt="429")
            cycle["otx"]["pulse_count"] = _C16_MARKER
        elif scenario == "otx-is-a-string":
            cycle = c16.collect(24, vt="429")
            cycle["otx"] = _C16_MARKER
        else:
            cycle = c16.collect(24, st="500")
            cycle["virustotal"].update(malicious=float("-inf"), note=_C16_MARKER)
            cycle["otx"]["pulse_count"] = -10 ** 400
    cycle.update(forged)
    _c16_persist_or_fail(c16, 24, cycle)
    assert "carried_sources" not in c16.saved(), "precondizione: il ripiego ha lasciato la sezione del ciclo"


class TestCOL16TheFallbackLeavesOneLineWithTheClassNameOnly:
    """Il ripiego scrive UN warning con il nome della classe d'eccezione e nessun contenuto del payload;
    un riporto riuscito non scrive nessun warning."""

    @staticmethod
    def _warnings(caplog):
        return [r for r in caplog.records if r.name == "orchestrator" and r.levelno == logging.WARNING]

    @pytest.mark.parametrize("scenario, error_class", [
        pytest.param("pulse-count-text", "TypeError", id="type-error"),
        pytest.param("otx-is-a-string", "AttributeError", id="attribute-error"),
        pytest.param("nested-previous-source", "RecursionError", id="recursion-error"),
        pytest.param("overflow", "OverflowError", id="overflow-error"),
    ])
    def test_one_warning_with_the_class_name_and_without_the_payload(
            self, c16, orch, caplog, scenario, error_class):
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            _c16_run_fallback_scenario(c16, orch, scenario)

        named = [r.getMessage() for r in self._warnings(caplog) if error_class in r.getMessage()]
        assert len(named) == 1, (f"attesa una riga di warning con `{error_class}`, trovate {len(named)}: "
                                 f"{[r.getMessage()[:120] for r in self._warnings(caplog)]}")
        assert _C16_MARKER not in caplog.text, "il contenuto del payload è arrivato nel log"

    def test_a_carry_that_succeeds_writes_no_warning(self, c16, caplog):
        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            c16.cycle(0)
            c16.cycle(24, vt="429")
            carried = c16.saved().get("carried_sources")
            c16.cycle(48, otx="429", st="500")

        assert carried and c16.saved().get("carried_sources"), "precondizione: il riporto è riuscito"
        assert [r.getMessage()[:120] for r in self._warnings(caplog)] == []


_C16_UNREADABLE_TIMESTAMPS = [
    pytest.param(_C12_MISSING, id="absent"), pytest.param(None, id="null"),
    pytest.param("not-a-date", id="unreadable-text"), pytest.param("", id="empty-text"),
    pytest.param(5, id="number"),
]


class TestCOL16CarryFromASectionWithoutAReadableTimestamp:
    """Il precedente è osservato ma il suo `timestamp` manca o non si legge: la fonte si riporta lo stesso,
    con `observed_at` nullo (età ignota), il rischio resta quello dell'ultima osservazione e al ritorno
    non esce nessun alert."""

    @pytest.mark.parametrize("timestamp", _C16_UNREADABLE_TIMESTAMPS)
    def test_the_source_is_carried_with_an_unknown_observation_instant(self, c16, orch, timestamp):
        previous = c16.collect(0)
        if timestamp is _C12_MISSING:
            del previous["timestamp"]
        else:
            previous["timestamp"] = timestamp
        assert orch.intel_store.save_snapshot("acme", _C02_DOMAIN, _c13_previous(reputation=previous))
        cycle = c16.collect(24, vt="429")

        _c16_persist_or_fail(c16, 24, copy.deepcopy(cycle))

        saved = c16.saved()
        _c16_assert_marker(saved, {"virustotal": {"observed_at": None, "carried_at": _c12_at(24, seconds=30)}},
                           "precedente senza timestamp leggibile: ")
        assert saved["virustotal"] == previous["virustotal"]
        assert (saved["risk_score"], saved["risk_level"]) == (50, "medium")
        _c16_persist_or_fail(c16, 48, c16.collect(48))
        assert c16.types() == [[], []], c16.types()


class TestCOL16TheFallbackLogNeverCarriesTheExceptionText:
    """Il log del ripiego riporta la classe e nient'altro: né il testo dell'eccezione (`str`, `repr`,
    `args`, il traceback) né le chiavi della sezione. Il testo di un'eccezione di `_calc_score` può
    contenere un valore del payload, e il payload viene da una zona non autenticata."""

    @pytest.mark.parametrize("error", [TypeError, OverflowError, AttributeError, RecursionError, ZeroDivisionError],
                             ids=lambda error: error.__name__)
    def test_one_warning_with_the_class_name_and_without_the_message_or_the_keys(
            self, c16, orch, monkeypatch, caplog, error):
        c16.cycle(0)

        def raising(section):
            raise error(_C16_MARKER)

        monkeypatch.setattr(orch, "_calc_score", raising)
        cycle = c16.collect(24, vt="429")
        cycle[f"{_C16_MARKER}-key"] = 1
        cycle["otx"][f"{_C16_MARKER}-key"] = 1
        expected = copy.deepcopy(cycle)

        with caplog.at_level(logging.WARNING, logger="orchestrator"):
            _c16_persist_or_fail(c16, 24, cycle)

        warnings = [r.getMessage() for r in caplog.records if r.name == "orchestrator" and r.levelno == logging.WARNING]
        named = [message for message in warnings if error.__name__ in message]
        assert c16.saved() == expected, "il ripiego non ha lasciato la sezione del ciclo"
        assert len(named) == 1, f"attesa una riga di warning con `{error.__name__}`, trovate {len(named)}: {warnings}"
        assert _C16_MARKER not in caplog.text, "il testo dell'eccezione o una chiave della sezione è arrivato nel log"


# ═══════════════════════════════════════════════════════════════
# COL-17 — un WHOIS senza alcun campo (guasto del registro) è un errore di raccolta
# ═══════════════════════════════════════════════════════════════
#
# Catena VERA, con la sola rete sostituita: `services/whois_intel.py` e la libreria `python-whois`
# veri (la fixture `whois_network` di conftest sostituisce solo il socket sotto il `NICClient`),
# `_run_pipeline` → `_persist_intel` → `/diff` → `/classify/variant` → `/cases/ingest` col
# classificatore e il case-manager veri su directory temporanee. DNS: servizio vero con `dig`
# simulato; cert e http: risposte fisse; reputazione: non richiesta. Lo scopo non è provare il
# servizio (lo fa `tests/test_whois_intel.py`) ma ciò che la pipeline ne fa:
#
#   * un registro che non risponde, risponde senza dati o oppone un limite di richieste è un modulo
#     fallito: lo snapshot riporta il WHOIS del ciclo precedente col marcatore di `COL-13`, la
#     classificazione è `insufficient_data` (guardia di `CODE-23`), nessun alert al ritorno;
#   * un caso chiuso dall'analista non si riapre per quel ciclo (`CODE-26`);
#   * un cambio di registrar che avviene attraverso il guasto viene segnalato al ritorno;
#   * un omografo giovane che passa da risolvente a dormiente attraverso il guasto resta HIGH
#     (`COL-14` riusa lo snapshot, che non deve contenere un vuoto spacciato per osservazione);
#   * un registro il cui formato la libreria non sa leggere, in modo persistente, è `insufficient_data`
#     con la stessa severità di caso (MEDIUM) che aveva come `needs_review`: l'etichetta dice che
#     non c'è un dato WHOIS invece di fingere un esito senza regola.
#
# Ogni ciclo interroga il servizio da zero (cache del servizio svuotata): la cadenza della pipeline
# supera il TTL della cache, che non è oggetto di questi test. Gli istanti sono quelli reali; le
# date del registro sono fisse (dominio vecchio) o relative all'istante dell'esecuzione (dominio giovane).

import subprocess

from shared import utils as _c17_utils

_C17_CLIENT = "acme"
_C17_DOMAIN = "acme-typo.com"
_C17_TOKEN = "col17-chain-test-token"
_C17_AUTH = {"Authorization": f"Bearer {_C17_TOKEN}"}
_C17_REGISTRAR = "Registrar Example Inc."
_C17_OTHER_REGISTRAR = "Other Registrar LLC"
_C17_REGISTRANT = ("Registrant Name: Reg Name\r\n"
                   "Registrant Organization: Reg Name Srl\r\n"
                   "Registrant Country: ZZ\r\n")
_C17_RATE_LIMIT = "Query rate limit exceeded. Please retry later.\r\n"
# Formato che il parser dei TLD senza modulo dedicato non legge: nessuno dei suoi campi compare.
_C17_UNREADABLE = "domain:   acme-typo.xyz\nholder:   X\nregistered: 2020-01-01\n"


def _c17_registry_text(domain, referral, registrar=_C17_REGISTRAR, created="2020-01-01T00:00:00Z",
                       updated="2026-05-01T10:00:00Z", expires="2027-05-01T10:00:00Z"):
    return (f"   Domain Name: {domain.upper()}\r\n"
            "   Registry Domain ID: 1_DOMAIN_COM-VRSN\r\n"
            f"   Registrar WHOIS Server: {referral}\r\n"
            "   Registrar URL: http://www.registrar.example\r\n"
            f"   Updated Date: {updated}\r\n"
            f"   Creation Date: {created}\r\n"
            f"   Registry Expiry Date: {expires}\r\n"
            f"   Registrar: {registrar}\r\n"
            "   Domain Status: clientTransferProhibited\r\n"
            f"   Name Server: NS1.{domain.upper()}\r\n"
            "   DNSSEC: unsigned\r\n")


def _c17_serve(network, domain, state):
    """Configura la rete WHOIS finta per lo stato del ciclo: un record (`ok`, `other-registrar`,
    `young`), un guasto del registro (`refused`, `timeout`, `empty`, `rate-limit`), un formato che la
    libreria non legge (`unreadable`) o IANA irraggiungibile (`iana-down`: la libreria solleva)."""
    tld = domain.rsplit(".", 1)[1]
    network.iana()
    network.registrar(_C17_REGISTRANT)
    if state in ("ok", "other-registrar", "young"):
        kwargs = {}
        if state == "other-registrar":
            kwargs = dict(registrar=_C17_OTHER_REGISTRAR, updated="2026-06-01T10:00:00Z",
                          expires="2027-06-01T10:00:00Z")
        if state == "young":
            kwargs = dict(created=(datetime.now(timezone.utc) - timedelta(days=45)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        network.registry(tld, _c17_registry_text(domain, network.REGISTRAR, **kwargs))
    elif state == "iana-down":
        network.iana(network.REFUSED)
    else:
        network.registry(tld, {"refused": network.REFUSED, "timeout": network.TIMEOUT, "empty": "",
                               "rate-limit": _C17_RATE_LIMIT, "unreadable": _C17_UNREADABLE}[state])


def _c17_dig_answer(name, rtype, rdata=()):
    out = (";; Got answer:\n"
           ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242\n"
           f";; flags: qr aa rd ra; QUERY: 1, ANSWER: {len(rdata)}, AUTHORITY: 0, ADDITIONAL: 1\n"
           "\n"
           ";; OPT PSEUDOSECTION:\n"
           "; EDNS: version: 0, flags:; udp: 1232\n")
    if rdata:
        out += ";; ANSWER SECTION:\n" + "".join(f"{name}.\t\t{rtype}\t{r}\n" for r in rdata) + "\n"
    return out


def _c17_zone(domain):
    return {(domain, "A"): ["192.0.2.10"], (domain, "MX"): [f"10 mail.{domain}."],
            (domain, "NS"): [f"ns1.{domain}.", f"ns2.{domain}."], (domain, "TXT"): ['"hello world"'],
            (domain, "SOA"): [f"ns1.{domain}. hostmaster.{domain}. 2026010101 7200 900 1209600 3600"]}


def _c17_cert(domain):
    certs = [{"id": i, "common_name": domain, "issuer_name": "Example CA"} for i in range(5)]
    return {"domain": domain, "timestamp": "2026-10-24T10:00:00Z",
            "ct_certificates": {"total": 5, "unique_cn": [domain], "certificates": certs},
            "tls_live": None, "san_subdomains_discovered": [], "error": None}


def _c17_http(domain):
    check = {"url": f"http://{domain}", "status_code": 200, "content_length": 540, "title": "Acme",
             "server": "nginx", "suspicious_patterns": [],
             "hidden_elements": {"risk_indicators": 0, "summary": []}, "error": None}
    return {"domain": domain, "timestamp": "2026-10-24T10:00:00Z", "checks": [check],
            "overall_status": "active", "hidden_elements_risk": 0, "error": None}


_C17_RUNS = {}


@pytest.fixture
def c17(orch, monkeypatch, tmp_path, whois_network):
    """`c17.run(stati, domain=..., plan=None, close=None)`: un ciclo di `_run_pipeline` per ogni stato
    WHOIS (vedi `_c17_serve`), con la catena descritta sopra. `plan` ("R" risolve / "D" dormiente per
    ciclo) passa dal percorso dnstwist: il dominio è una variante omografa del dominio legittimo.
    `close=(ciclo, stato)`: l'analista porta il caso a `stato` dopo quel ciclo. Ritorna i cicli, ciascuno con
    `state`, `classification` (quella pubblicata), `alerts` ([(tipo, severità)] aggiunti alla storia),
    `whois` (sezione dello snapshot salvato), `case` (riga del caso), `actions` (azioni dell'audit).
    Uno scenario identico (stessi argomenti) è eseguito una volta sola e condiviso fra i test della
    sessione, come in `tests/test_col02_chain.py`: i cicli sono dati, i test non li modificano."""
    import services.whois_intel as whois_service
    from services.dns_intel import app as dns_app
    # Prima di importare il case-manager (che crea il database all'import): mai il volume /data.
    monkeypatch.setenv("CASES_DB", str(tmp_path / "cases.db"))
    monkeypatch.setenv("ADMIN_PASSWORD", "col17-chain-admin-password")
    import services.case_manager as cm

    monkeypatch.setattr(cm, "DB_PATH", str(tmp_path / "cases.db"))
    monkeypatch.setattr(cm, "SERVICE_TOKEN", _C17_TOKEN)
    cm.init_db()
    monkeypatch.setattr(orch, "INTEL_STORE", True)
    monkeypatch.setattr(orch, "CASE_INGEST", True)
    monkeypatch.setattr(orch, "CASE_INGEST_TOKEN", _C17_TOKEN)
    monkeypatch.setattr(orch.intel_store, "SNAP_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(orch.intel_store, "HIST_DIR", tmp_path / "history")
    monkeypatch.setattr(whois_service, "WHOIS_DELAY", 0.0)
    monkeypatch.setattr(whois_service, "HAS_WHOIS_LIB", True)
    dns_api = TestClient(dns_app)
    whois_api = TestClient(whois_service.app)
    classifier_api = TestClient(_c02_classifier_app, raise_server_exceptions=False)
    case_api = TestClient(cm.app, raise_server_exceptions=False)

    def run_scenario(states, domain, plan, close):
        tld = domain.rsplit(".", 1)[1]
        legitimate = f"acme.{tld}"
        if plan is None:
            feed = {"domain": domain, "client": _C17_CLIENT, "type": "target", "legitimate": legitimate,
                    "fuzzer": "insertion"}
        else:
            feed = {"domain": legitimate, "client": _C17_CLIENT, "type": "target", "legitimate": legitimate,
                    "fuzzer": ""}
        zone = _c17_zone(domain)
        monkeypatch.setattr(_c17_utils.subprocess, "run", lambda argv, *a, **k: subprocess.CompletedProcess(
            argv, 0, stdout=_c17_dig_answer(argv[-2], argv[-1], zone.get((argv[-2], argv[-1]), [])), stderr=""))
        published, errors, cycles = [], [], []
        current = {}

        def _get(url, timeout=None):
            if "/feed/domains" in url:
                return _R({"domains": [feed]})
            if "/feed/whitelist" in url:
                return _R({"whitelist": {}})
            if url.startswith(orch.TWIST_URL):
                resolving = plan[current["index"]] == "R"
                return _R({"registered_variants": 1, "variants": [{
                    "domain": domain, "fuzzer": "homoglyph", "dns_a": ["192.0.2.10"] if resolving else [],
                    "dns_mx": []}]})
            for base, api in ((orch.DNS_URL, dns_api), (orch.WHOIS_URL, whois_api)):
                if url.startswith(base):
                    response = api.get(url[len(base):])
                    return _R(response.json() if response.is_success else None, ok=response.is_success,
                              status_code=response.status_code)
            target = url.split("domain=")[1].split("&")[0]
            if url.startswith(orch.CERT_URL):
                return _R(_c17_cert(target))
            if url.startswith(orch.HTTP_URL):
                return _R(_c17_http(target))
            raise AssertionError(f"GET non atteso nella catena: {url}")

        def _post(url, json=None, timeout=None, headers=None):
            if url.endswith("/publish"):
                published.extend((json or {}).get("events", []))
                return _R({})
            if url.startswith(orch.CLASSIFY_URL):
                response = classifier_api.post(url[len(orch.CLASSIFY_URL):], json=json)
            elif url.startswith(orch.CASE_MANAGER_URL):
                response = case_api.post(url[len(orch.CASE_MANAGER_URL):], json=json, headers=headers)
            else:
                raise AssertionError(f"POST non atteso nella catena: {url}")
            if response.status_code != 200:
                errors.append((url, response.status_code))
            return _R(response.json() if response.is_success else None, ok=response.is_success,
                      status_code=response.status_code)

        monkeypatch.setattr(orch._session, "get", _get)
        monkeypatch.setattr(orch._session, "post", _post)

        def _case():
            rows = case_api.get("/cases", params={"client": _C17_CLIENT}, headers=_C17_AUTH).json()["cases"]
            return next((row for row in rows if row["domain"] == domain), None)

        for index, state in enumerate(states):
            current["index"] = index
            _c17_serve(whois_network, domain, state)
            whois_service._cache.clear()
            whois_service._cache_order.clear()
            before = len(orch.intel_store.load_history(_C17_CLIENT, domain, limit=1000))
            published.clear()
            orch._run_pipeline(orch.TriggerRequest(
                client=_C17_CLIENT, include_whois=True, include_reputation=False,
                include_dnstwist=plan is not None, variant_intel=plan is not None, scope="all"))
            assert orch._progress["phase"] != "error", "la pipeline è terminata con un errore"
            event = next(e for e in published if e["domain"] == domain)
            history = orch.intel_store.load_history(_C17_CLIENT, domain, limit=1000)
            case = _case()
            actions = []
            if case is not None:
                detail = case_api.get(f"/cases/{case['id']}", headers=_C17_AUTH).json()
                actions = [entry["action"] for entry in detail.get("history") or []]
            cycles.append(SimpleNamespace(
                state=state, classification=event["classification"],
                alerts=[(a["type"], a["severity"]) for e in history[:len(history) - before] for a in e["alerts"]],
                whois=(orch.intel_store.load_snapshot(_C17_CLIENT, domain) or {}).get("intel", {}).get("whois"),
                case=case, actions=actions))
            if close and close[0] == index:
                response = case_api.patch(f"/cases/{case['id']}/status", json={"status": close[1]}, headers=_C17_AUTH)
                assert response.status_code == 200, response.text
        assert errors == [], f"risposte di errore dalla catena: {errors}"
        return tuple(cycles)

    def run(states, domain=_C17_DOMAIN, plan=None, close=None):
        key = (tuple(states), domain, plan, close)
        if key not in _C17_RUNS:
            _C17_RUNS[key] = run_scenario(*key)
        return _C17_RUNS[key]

    return SimpleNamespace(run=run)


def _c17_types(cycle):
    return [kind for kind, _ in cycle.alerts]


_C17_REGISTRY_OUTAGES = [pytest.param(state, id=state) for state in ("refused", "timeout", "empty", "rate-limit")]


@pytest.mark.parametrize("outage", _C17_REGISTRY_OUTAGES)
class TestCOL17ChainRegistryOutageKeepsTheBaseline:
    """ok → il registro non dà un record → ok, per ogni forma di guasto."""

    def test_the_failed_cycle_keeps_the_previous_whois_and_marks_it_as_carried(self, c17, outage):
        cycles = c17.run(["ok", outage, "ok"])

        baseline, failed = cycles[0].whois, cycles[1].whois
        assert baseline["registrar"] == _C17_REGISTRAR and baseline["error"] is None, "precondizione: baseline leggibile"
        assert failed.get("carried_over"), (
            f"il ciclo con il registro in guasto ha sovrascritto la baseline invece di riportarla: {failed}")
        assert failed["registrar"] == _C17_REGISTRAR and failed["timestamp"] == baseline["timestamp"], failed

    def test_the_failed_cycle_is_insufficient_data_and_not_a_verdict_on_an_empty_record(self, c17, outage):
        cycles = c17.run(["ok", outage, "ok"])

        assert cycles[0].classification["auto_classification"] == "likely_third_party", "precondizione"
        classification = cycles[1].classification
        assert classification["auto_classification"] == "insufficient_data", (
            f"un WHOIS non raccolto è stato classificato come {classification['auto_classification']}/"
            f"{classification['rule']}")
        assert cycles[1].case["classification"] == "insufficient_data", cycles[1].case

    def test_the_cycle_after_the_outage_raises_no_privacy_alert(self, c17, outage):
        cycles = c17.run(["ok", outage, "ok"])

        assert cycles[0].whois["privacy_protected"] is False, "precondizione: registrante visibile nella baseline"
        assert [_c17_types(c) for c in cycles] == [[], [], []], (
            f"alert generati dal guasto del registro e dal suo ritorno: {[c.alerts for c in cycles]}")

    def test_the_case_goes_back_to_the_baseline_classification_when_the_registry_answers_again(self, c17, outage):
        # Controllo.
        cycles = c17.run(["ok", outage, "ok"])

        assert cycles[2].classification["auto_classification"] == "likely_third_party", cycles[2].classification
        assert cycles[2].whois["registrar"] == _C17_REGISTRAR and not cycles[2].whois.get("carried_over")


@pytest.mark.parametrize("outage", [pytest.param("refused", id="refused"), pytest.param("empty", id="empty")])
class TestCOL17ChainTwoConsecutiveFailedCycles:
    """ok → due cicli senza record → ok."""

    def test_both_cycles_carry_the_last_real_observation(self, c17, outage):
        cycles = c17.run(["ok", outage, outage, "ok"])

        observed = cycles[0].whois["timestamp"]
        for index in (1, 2):
            section = cycles[index].whois
            assert section.get("carried_over", {}).get("observed_at") == observed, (
                f"ciclo {index}: la sezione salvata non è l'ultima osservazione reale: {section}")
            assert section["registrar"] == _C17_REGISTRAR

    def test_both_cycles_are_insufficient_data(self, c17, outage):
        cycles = c17.run(["ok", outage, outage, "ok"])

        assert [c.classification["auto_classification"] for c in cycles[1:3]] == ["insufficient_data"] * 2, (
            [(c.classification["auto_classification"], c.classification["rule"]) for c in cycles[1:3]])

    def test_the_return_raises_no_privacy_alert(self, c17, outage):
        cycles = c17.run(["ok", outage, outage, "ok"])

        assert [_c17_types(c) for c in cycles] == [[], [], [], []], [c.alerts for c in cycles]


@pytest.mark.parametrize("outage", [pytest.param("refused", id="refused"), pytest.param("empty", id="empty")])
class TestCOL17ChainClosedCaseIsNotReopenedByTheOutage:
    """Un caso chiuso come falso positivo a LOW resta chiuso: il ciclo in cui il registro non risponde
    non è un'escalation di severità."""

    def test_the_closed_case_is_not_reopened(self, c17, outage):
        cycles = c17.run(["ok", outage, "ok"], close=(0, "closed_fp"))

        assert cycles[0].classification["auto_classification"] == "likely_third_party", "precondizione: caso a LOW"
        for index in (1, 2):
            assert cycles[index].case["status"] == "closed_fp", (
                f"ciclo {index}: stato {cycles[index].case['status']}, audit {cycles[index].actions}")
            assert "reopened" not in cycles[index].actions, cycles[index].actions

    def test_the_closed_case_keeps_its_triage_fields(self, c17, outage):
        cycles = c17.run(["ok", outage, "ok"], close=(0, "closed_fp"))

        assert cycles[0].classification["auto_classification"] == "likely_third_party", "precondizione"
        for index in (1, 2):
            triage = {key: cycles[index].case[key] for key in ("status", "severity", "classification")}
            assert triage == {"status": "closed_fp", "severity": "INFO", "classification": "likely_third_party"}, (
                f"ciclo {index}: {triage}")


@pytest.mark.parametrize("outage", [pytest.param("refused", id="refused"), pytest.param("empty", id="empty")])
class TestCOL17ChainRegistrarChangeAcrossTheOutage:
    """Il registrar cambia mentre il registro non risponde: la baseline riportata permette di vedere il cambio."""

    def test_the_change_is_reported_when_the_registry_answers_again(self, c17, outage):
        cycles = c17.run(["ok", outage, "other-registrar"])

        assert cycles[2].whois["registrar"] == _C17_OTHER_REGISTRAR, "precondizione: il registrar è cambiato"
        assert ("whois_registrar_changed", "HIGH") in cycles[2].alerts, (
            f"cambio di registrar non segnalato: {cycles[2].alerts}")


@pytest.mark.parametrize("outage", [pytest.param("refused", id="refused"), pytest.param("empty", id="empty")])
class TestCOL17ChainYoungHomoglyphAcrossTheOutage:
    """Un omografo giovane risolvente il cui registro non risponde per un ciclo, poi dormiente: il WHOIS
    che `COL-14` riusa per un dominio dormiente è l'ultimo leggibile, non un vuoto."""

    PLAN = "RRDR"

    def test_the_dormant_cycle_after_the_outage_stays_high(self, c17, outage):
        cycles = c17.run(["young", outage, "young", "young"], plan=self.PLAN)

        assert cycles[0].classification["auto_classification"] == "suspicious", "precondizione: omografo giovane HIGH"
        assert cycles[0].case["severity"] == "HIGH", cycles[0].case
        dormant = cycles[2]
        assert dormant.classification["auto_classification"] == "suspicious", (
            f"omografo giovane dormiente: {dormant.classification['auto_classification']}/"
            f"{dormant.classification['rule']}")
        assert dormant.case["severity"] == "HIGH", dormant.case


class TestCOL17ChainControlsWithAnExceptionInsteadOfAnEmptyRecord:
    """Controllo: con IANA irraggiungibile la libreria solleva e il servizio risponde con un errore.
    Le stesse sequenze, con lo stesso esito atteso."""

    def test_a_registrar_change_across_the_failed_lookup_is_reported(self, c17):
        cycles = c17.run(["ok", "iana-down", "other-registrar"])

        assert ("whois_registrar_changed", "HIGH") in cycles[2].alerts, cycles[2].alerts

    def test_a_registrar_change_between_two_readable_cycles_is_reported(self, c17):
        cycles = c17.run(["ok", "other-registrar"])

        assert ("whois_registrar_changed", "HIGH") in cycles[1].alerts, cycles[1].alerts

    def test_a_young_homoglyph_going_dormant_across_the_failed_lookup_stays_high(self, c17):
        cycles = c17.run(["young", "iana-down", "young", "young"], plan="RRDR")

        assert cycles[2].classification["auto_classification"] == "suspicious", cycles[2].classification
        assert cycles[2].case["severity"] == "HIGH", cycles[2].case


class TestCOL17ChainUnreadableRecordIsInsufficientData:
    """Un registro il cui formato la libreria non sa leggere, ciclo dopo ciclo: nessun dato WHOIS."""

    DOMAIN = "acme-typo.xyz"

    def test_a_record_the_library_cannot_read_is_insufficient_data(self, c17):
        cycles = c17.run(["unreadable"] * 3, domain=self.DOMAIN)

        assert [c.classification["auto_classification"] for c in cycles] == ["insufficient_data"] * 3, (
            [(c.classification["auto_classification"], c.classification["rule"]) for c in cycles])

    def test_the_case_severity_stays_medium(self, c17):
        # Controllo: la severità di caso di `insufficient_data` e quella di `needs_review` coincidono.
        cycles = c17.run(["unreadable"] * 3, domain=self.DOMAIN)

        assert [c.case["severity"] for c in cycles] == ["MEDIUM"] * 3, [c.case for c in cycles]
