"""Tests for services/classifier.py auto-classification rules."""

import json
from fastapi.testclient import TestClient
from services.classifier import app

client = TestClient(app)


class TestClassifyVariant:
    """Test auto-classification rules."""

    def _classify(self, domain, dns=None, http=None, cert=None, **kwargs):
        body = {"domain": domain, "fuzzer": kwargs.get("fuzzer", "test"), 
                "dns": dns, "http": http, "cert": cert}
        resp = client.post("/classify/variant", json=body)
        assert resp.status_code == 200
        return resp.json()

    def test_parking_minimal_content(self):
        """HTTP 200 with <200 bytes → parking."""
        result = self._classify("parked.com", http={
            "checks": [{"status_code": 200, "content_length": 95}],
            "overall_status": "active"
        })
        assert result["auto_classification"] == "parking"
        assert result["confidence"] == "high"

    def test_parking_known_ns(self):
        """Known parking nameservers → parking."""
        result = self._classify("parked.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns47.domaincontrol.com"]}
        })
        assert result["auto_classification"] == "parking"

    def test_parking_known_ip(self):
        """Known parking IPs → parking."""
        result = self._classify("parked.com", dns={
            "records": {"A": ["15.197.148.33"], "MX": [], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "parking"

    def test_for_sale_marketplace_ns(self):
        """Marketplace nameservers → for_sale."""
        result = self._classify("forsale.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.brandbucket.com"]}
        })
        assert result["auto_classification"] == "for_sale"

    def test_for_sale_parking_mx(self):
        """Parking MX → for_sale."""
        result = self._classify("forsale.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": ["park-mx.above.com"], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "for_sale"

    def test_legitimate_enterprise_cert(self):
        """Enterprise cert provider → legitimate_probable."""
        result = self._classify("legit.com", cert={
            "ct_certificates": {"total": 5, "unique_cn": ["tls.automattic.com", "legit.com"]}
        }, dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}})
        assert result["auto_classification"] == "legitimate_probable"

    def test_legitimate_substantial_content(self):
        """HTTP active with >3KB content → legitimate_probable."""
        result = self._classify("legit.com", 
            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}},
            http={"checks": [{"status_code": 200, "content_length": 45000}], "overall_status": "active"})
        assert result["auto_classification"] == "legitimate_probable"

    def test_suspicious_mx_only(self):
        """MX active without A record → suspicious."""
        result = self._classify("suspicious.com", dns={
            "records": {"A": [], "MX": ["10 mx.zoho.com"], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "suspicious"
        assert result["action"] == "block_and_monitor"

    def test_suspicious_privacy_mx(self):
        """ProtonMail MX → suspicious."""
        result = self._classify("suspicious.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": ["mail.protonmail.ch"], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "suspicious"

    def test_suspicious_forwarding_mx(self):
        """Namecheap email forwarding → suspicious."""
        result = self._classify("suspicious.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": ["eforward1.registrar-servers.com"], "NS": ["ns1.example.com"]}
        })
        assert result["auto_classification"] == "suspicious"

    def test_suspicious_hidden_elements(self):
        """High risk hidden elements → suspicious."""
        result = self._classify("suspicious.com",
            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}},
            http={"checks": [{"status_code": 200, "content_length": 5000,
                "hidden_elements": {"risk_indicators": 35, "summary": ["hidden form detected"]}}],
                "overall_status": "active"})
        assert result["auto_classification"] == "suspicious"

    def test_needs_review_fallback(self):
        """No matching rule → needs_review."""
        result = self._classify("unknown.com", dns={
            "records": {"A": ["1.2.3.4"], "MX": ["mx.unknown-provider.com"], "NS": ["ns1.unknown.com"]}
        })
        assert result["auto_classification"] == "needs_review"

    def test_empty_input(self):
        """No data at all → needs_review."""
        result = self._classify("empty.com")
        assert result["auto_classification"] == "needs_review"

    def test_none_content_length_no_crash(self):
        """content_length=None should not crash max()."""
        result = self._classify("test.com", 
            dns={"records": {"A": [], "MX": [], "NS": []}},
            http={"checks": [{"status_code": None, "content_length": None}], "overall_status": "down"})
        # Should not raise TypeError
        assert result["auto_classification"] == "needs_review"


class TestClassifierReadsCollectionStatus:
    """`CODE-15` + `CODE-14` (riunificati). Architettura B2 — DECISIONE utente
    2026-08-02: lo stato di raccolta (quale modulo è fallito in questo ciclo)
    va costruito UNA VOLTA nell'orchestrator (che già possiede `_module_failed`
    per il canale alert, CODE-01/CODE-14) e PROPAGATO nel payload verso
    `/classify/variant`; il classificatore lo LEGGE, senza ri-derivarlo
    ispezionando la forma dei cinque dict grezzi.

    MODIFICA DELIBERATA a una classe preesistente — giustificazione per G5.
    La versione precedente di questa classe (`TestModuleFailureNotConfusedWithNoMatch`,
    round 2 di questo ID) chiamava `classify_variant`/`VariantInput` passando i
    cinque dict grezzi dei collector SENZA alcun campo di stato, aspettandosi
    che il classificatore deducesse da solo, ispezionando la FORMA del dict,
    se un modulo fosse fallito (architettura B1). Il verifier ha bocciato il
    fix costruito su quell'assunzione al G6 (2026-08-02, secondo giro):
    l'unica implementazione che superava quei test era `collection_failed`
    chiamata DENTRO `classify_variant` sui dict grezzi — esattamente
    l'architettura scartata dall'utente, perché i due punti in cui
    l'orchestrator costruisce il payload (`orchestrator.py:387-392` e
    `:497-503`) restavano identici a HEAD: nessuno stato veniva mai costruito
    né propagato, il "fix" viveva solo lato classificatore. I vecchi test
    restano verdi con QUALUNQUE implementazione che continui a ispezionare la
    forma anziché leggere lo stato propagato: non specificano B2, specificano
    B1. Non sono stati indeboliti per far passare un fix — sono riscritti
    perché l'assunzione architetturale che codificavano è stata superata dalla
    decisione dell'utente del 2026-08-02.

    FORMA FISSATA (dichiarata qui, vincolante per il fixer — impossibile
    testare la propagazione end-to-end senza fissare la forma del campo di
    stato): `VariantInput.collection_status`, dict opzionale
    `{nome_sezione: bool}` con chiavi fra "whois"/"cert"/"http"/"reputation",
    `True` se quella sezione è fallita in questo ciclo (stessa semantica di
    `orchestrator._module_failed`). Stesso nome di campo usato
    dall'orchestrator per costruire il payload — vedi
    `tests/test_orchestrator.py::TestOrchestratorPropagatesCollectionState`.

    Le fixture `*_LOOKS_FINE` sotto sono DELIBERATAMENTE forme che l'euristica
    B1 (`collection_failed` sulla forma grezza) NON riconoscerebbe come
    fallite: nessun `error` valorizzato, nessun `overall_status` di guasto,
    nessuna fonte reputation tutta in errore. L'unico modo per questi test di
    passare è che `classify_variant` legga `collection_status`, non che
    ri-ispezioni la forma — è il punto preciso su cui il tentativo precedente
    è stato respinto. Le forme REALI di fallimento dei collector (whois a 12
    chiavi con solo `error` valorizzato, cert con `error` top-level, reputation
    con `error` top-level sempre `None` e guasto annidato — CODE-14 — e http
    con `overall_status` in "down"/"error") restano documentate e verificate
    lato orchestrator, che è il componente che le osserva per davvero — vedi
    `tests/test_orchestrator.py::TestOrchestratorBuildsCollectionState`."""

    WHOIS_LOOKS_FINE = {"registrar": "Some Registrar Inc.", "creation_date": None,
                         "updated_date": None, "error": None}
    CERT_LOOKS_FINE = {"ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                        "error": None}
    HTTP_LOOKS_FINE = {"checks": [], "overall_status": "active", "error": None}
    REPUTATION_LOOKS_FINE = {
        "virustotal": {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
                        "reputation": 0, "categories": {}, "error": None},
        "otx": {"pulse_count": 0, "pulse_titles": [], "tags": [], "malware_families": [],
                "error": None},
        "securitytrails": {"subdomain_count": 0, "current_dns": {}, "alexa_rank": None,
                            "error": None},
        "risk_score": 0, "risk_level": "clean", "error": None,
    }

    def _classify(self, domain, **kwargs):
        from services.classifier import classify_variant, VariantInput
        vi = VariantInput(domain=domain, **kwargs)
        return json.loads(classify_variant(vi).body)

    def test_whois_marked_failed_in_state_is_not_needs_review(self):
        """`collection_status` marca whois come fallito anche se il dict
        grezzo, da solo, avrebbe l'aria di un dato valido: lo stato deve
        prevalere sulla forma."""
        r = self._classify("whois-down.example", whois=self.WHOIS_LOOKS_FINE,
                            collection_status={"whois": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert r["rule"] != "no_matching_rule", r

    def test_cert_marked_failed_in_state_is_not_needs_review(self):
        r = self._classify("cert-down.example", cert=self.CERT_LOOKS_FINE,
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert r["rule"] != "no_matching_rule", r

    def test_http_marked_failed_alone_in_state_stays_needs_review(self):
        """`http` è l'ECCEZIONE fra le quattro sezioni di questa classe —
        DECISIONE UTENTE 2026-08-02 (vedi `TestHttpOnlyFailureDoesNotDowngrade`
        per il testo completo della motivazione): a differenza di
        whois/cert/reputation, `http` è l'unica sezione che un attaccante può
        far fallire A COMANDO, cloacando lo scanner (blocklist per IP/
        user-agent dei vendor, tecnica standard nei kit di phishing) mentre il
        WHOIS resta dietro privacy protection (`age_days` → `None`, comune e
        legittimo). Se `http` da sola bastasse a declassare a
        `insufficient_data`/LOW, l'attaccante otterrebbe una
        deprioritizzazione deliberata proprio sui domini che meritano più
        attenzione — la via di evasione chiusa dall'emendamento.

        Prima del 2026-08-02 questo test asseriva `insufficient_data`,
        coerente con la lettura "ogni sezione fallita declassa, `http`
        inclusa" (architettura B2 pre-emendamento, vedi il docstring della
        classe). La decisione dell'utente ha cambiato quella regola: il
        declassamento richiede ora almeno una sezione FUORI dal controllo
        dell'attaccante (whois, cert o reputation) marcata fallita insieme a
        `http` — vedi `test_multiple_sections_marked_failed_combined_is_not_needs_review`
        sotto per il caso combinato, che continua a declassare. `http`
        marcato fallito DA SOLO nello stato deve quindi restare
        `needs_review`, non `insufficient_data`: lo stato prevale sulla forma
        (il dict grezzo ha l'aria di un dato valido), ma la sola sezione
        `http` non è più sufficiente a giustificare la deprioritizzazione."""
        r = self._classify("http-down.example", http=self.HTTP_LOOKS_FINE,
                            collection_status={"http": True})
        assert r["auto_classification"] == "needs_review", r
        assert r["auto_classification"] != "insufficient_data", r

    def test_reputation_marked_failed_in_state_is_not_needs_review(self):
        """Non è `CODE-19` (regole che ignorano un verdetto REALE di
        `reputation`): qui lo stato dichiara che il modulo non ha prodotto
        alcuna evidenza in questo ciclo, non che il verdetto sia pulito."""
        r = self._classify("rep-down.example", reputation=self.REPUTATION_LOOKS_FINE,
                            collection_status={"reputation": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert r["rule"] != "no_matching_rule", r

    def test_multiple_sections_marked_failed_combined_is_not_needs_review(self):
        """Caso combinato: whois e http entrambi marcati falliti nello stato
        nello stesso ciclo."""
        r = self._classify("all-down.example",
                            whois=self.WHOIS_LOOKS_FINE, http=self.HTTP_LOOKS_FINE,
                            collection_status={"whois": True, "http": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert r["rule"] != "no_matching_rule", r

    def test_state_says_ok_and_real_isolated_datum_still_needs_review(self):
        """Non-regressione (punto 2 del mandato G3; controprova già valida nei
        round precedenti di `CODE-15`). Con lo stato che dichiara la sezione
        raccolta correttamente, un dato REALE isolato deve restare
        `needs_review` come oggi: la guardia non deve mordere dati veri
        quando le viene detto esplicitamente che la raccolta è andata bene."""
        r = self._classify("partial-real-data.example",
                            whois={"registrar": "Some Registrar Inc.", "error": None},
                            collection_status={"whois": False})
        assert r["auto_classification"] == "needs_review", r


class TestHttpOnlyFailureDoesNotDowngrade:
    """Requisito 2 (`CODE-15` + `CODE-14`, G3 terzo giro) — DECISIONE UTENTE
    2026-08-02, a valle del rilievo del security-reviewer al G6 (secondo
    giro): un dominio con WHOIS privacy (comunissimo: `age_days` porta a
    `None`) PIÙ cloaking contro lo scanner (blocklist per IP/user-agent dei
    vendor — tecnica standard nei kit di phishing, così `http_fingerprint`
    osserva un fallimento GENUINO) ottiene oggi `insufficient_data`/LOW
    invece di `needs_review`/MEDIUM: una deprioritizzazione ottenibile
    DELIBERATAMENTE, proprio sui domini che meritano più attenzione.

    `http` è l'unica sezione che un attaccante può far fallire a comando —
    whois/cert/reputation dipendono da infrastrutture terze che l'attaccante
    non controlla (registrar, Certificate Transparency, VT/OTX/
    SecurityTrails). Il declassamento a `insufficient_data`/LOW deve quindi
    richiedere che sia fallita almeno una sezione FUORI dal controllo
    dell'attaccante: whois, cert o reputation. Un `http` fallito da solo,
    per quanto genuino il guasto del collector, non deve mai declassare da
    solo.

    Oggi `classify_variant` (services/classifier.py:315-319) tratta
    QUALUNQUE sezione marcata fallita allo stesso modo:
    `failed_sections = [name for name, failed in (v.collection_status or {}).items() if failed]`
    — non distingue `http` dalle altre tre."""

    def _classify(self, domain, **kwargs):
        from services.classifier import classify_variant, VariantInput
        vi = VariantInput(domain=domain, **kwargs)
        return json.loads(classify_variant(vi).body)

    def test_http_only_failure_stays_needs_review(self):
        """Guasto GENUINO del solo collector http (forma reale: connessione
        rifiutata / handshake TLS fallito, nessun altro segnale) — deve
        restare `needs_review`/MEDIUM, NON `insufficient_data`/LOW. È
        esattamente il vettore di evasione del security-reviewer: un
        attaccante che blocca solo lo scanner non deve poter abbassare la
        severity del proprio dominio."""
        r = self._classify("http-cloaked.example",
                            collection_status={"http": True, "whois": False,
                                                "cert": False, "reputation": False})
        assert r["auto_classification"] == "needs_review", r
        assert r["auto_classification"] != "insufficient_data", r
        assert r["manual_review_required"] is True, r

    def test_http_failure_alone_without_other_keys_stays_needs_review(self):
        """Stessa pretesa, ma con `collection_status` che riporta SOLO la
        chiave http (le altre tre sezioni assenti dal dict, non esplicitate
        a False): forma realistica del payload quando l'orchestrator marca
        solo le sezioni effettivamente fallite."""
        r = self._classify("http-cloaked-2.example", collection_status={"http": True})
        assert r["auto_classification"] == "needs_review", r

    def test_whois_privacy_plus_http_cloaking_stays_needs_review(self):
        """Scenario esatto segnalato dal security-reviewer al G6 (secondo
        giro): dominio con WHOIS privacy (raccolto correttamente, `error`
        `None`, ma senza data di creazione visibile — `age_days` resta
        `None`) più cloaking contro lo scanner (http fallito a comando).
        Nessuna delle due condizioni, insieme, deve produrre
        `insufficient_data`: whois NON è fallita (solo priva di data), e
        http da sola non deve mai declassare."""
        whois_privacy = {"registrar": "NameCheap, Inc.", "creation_date": None,
                          "updated_date": None, "expiration_date": None, "status": [],
                          "nameservers": ["dns1.registrar-servers.com"],
                          "registrant": {"name": "Redacted for Privacy", "org": None,
                                         "country": None, "email": None},
                          "privacy_protected": True, "dnssec": False, "age_days": None,
                          "error": None}
        r = self._classify("cloaked-phish.example", whois=whois_privacy,
                            collection_status={"whois": False, "http": True,
                                                "cert": False, "reputation": False})
        assert r["auto_classification"] == "needs_review", r

    def test_http_plus_whois_failure_downgrades(self):
        """Non-regressione: `http` fallito INSIEME a una sezione fuori dal
        controllo dell'attaccante (qui whois) deve continuare a declassare,
        come oggi — il declassamento non va rimosso, va reso selettivo."""
        r = self._classify("http-and-whois-down.example",
                            collection_status={"http": True, "whois": True,
                                                "cert": False, "reputation": False})
        assert r["auto_classification"] == "insufficient_data", r

    def test_http_plus_cert_failure_downgrades(self):
        r = self._classify("http-and-cert-down.example",
                            collection_status={"http": True, "cert": True})
        assert r["auto_classification"] == "insufficient_data", r

    def test_http_plus_reputation_failure_downgrades(self):
        r = self._classify("http-and-rep-down.example",
                            collection_status={"http": True, "reputation": True})
        assert r["auto_classification"] == "insufficient_data", r

    def test_whois_only_failure_downgrades(self):
        """Non-regressione: whois fallita da sola (fuori dal controllo di
        chi gestisce il dominio target) deve continuare a declassare."""
        r = self._classify("whois-only-down.example",
                            collection_status={"whois": True, "http": False,
                                                "cert": False, "reputation": False})
        assert r["auto_classification"] == "insufficient_data", r

    def test_cert_only_failure_downgrades(self):
        r = self._classify("cert-only-down.example", collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r

    def test_reputation_only_failure_downgrades(self):
        r = self._classify("rep-only-down.example", collection_status={"reputation": True})
        assert r["auto_classification"] == "insufficient_data", r


class TestCollectionGuardOverridesAbsolutoryRules:
    """`CODE-23`. DECISIONE utente 2026-08-05: quando la raccolta e' fallita
    (almeno una sezione NON-`http` fra whois/cert/reputation), il verdetto
    deve diventare `insufficient_data` A MENO CHE la classificazione prodotta
    dalle regole abbia severita' di CASO superiore a quella di
    `insufficient_data` (MEDIUM in `CLASSIFICATION_SEVERITY`,
    orchestrator.py:46-59). `suspicious` (HIGH) e' l'UNICA categoria che
    supera MEDIUM: e' l'unica che deve sopravvivere alla guardia.

    Oggi la guardia (`classifier.py:315-324`) e' valutata DOPO tutte le
    regole posizionali (`:172-329`): qualunque regola che ritorni prima --
    comprese quelle ASSOLUTORIE (`parking`, `for_sale`, `legitimate_probable`,
    `likely_third_party`, e le varianti `needs_review` modulate dall'eta') --
    la scavalca, anche quando whois/cert/reputation sono realmente falliti.
    E' il controesempio del `pm` a registro (probe A): `cert` e `whois`
    falliti, `http` con contenuto sostanzioso -> esce oggi
    `legitimate_probable`/whitelist_candidate invece di `insufficient_data`.

    Le prime cinque prove sotto sono rosse oggi (una per categoria
    assolutoria). Le ultime tre sono verdi di NON REGRESSIONE: la trappola
    esplicita e' che un fix che si limita a spostare il blocco di guardia in
    cima (senza l'eccezione per severita' di caso superiore) declasserebbe
    ANCHE `suspicious` -- che deve restare tale."""

    CERT_FAILED = {"ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                    "error": "crt.sh timeout"}
    WHOIS_FAILED = {"registrar": None, "creation_date": None, "updated_date": None,
                     "error": "whois lookup timeout"}

    def _classify(self, domain, **kwargs):
        from services.classifier import classify_variant, VariantInput
        vi = VariantInput(domain=domain, **kwargs)
        return json.loads(classify_variant(vi).body)

    # ── Rosso oggi: le regole assolutorie scavalcano la guardia ──

    def test_legitimate_probable_yields_to_insufficient_data(self):
        """Controesempio storico (`BUG-REGISTER.md` CODE-23, probe A): cert e
        whois falliti, http con contenuto sostanzioso. Oggi esce
        `legitimate_probable`/whitelist_candidate -- deve uscire
        `insufficient_data`."""
        r = self._classify("http-substantial-nocert.example",
                            whois=self.WHOIS_FAILED, cert=self.CERT_FAILED,
                            http={"checks": [{"status_code": 200, "content_length": 5000}],
                                  "overall_status": "active"},
                            collection_status={"whois": True, "cert": True})
        assert r["auto_classification"] == "insufficient_data", r

    def test_parking_yields_to_insufficient_data(self):
        """`known_parking_ns` (`classifier.py:180`) e' assolutoria (LOW):
        deve cedere a `cert` fallito."""
        r = self._classify("parked-nocert.example",
                            cert=self.CERT_FAILED,
                            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns47.domaincontrol.com"]}},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r

    def test_for_sale_yields_to_insufficient_data(self):
        """`marketplace_ns` (`classifier.py:191`) e' assolutoria (LOW): deve
        cedere a `cert` fallito."""
        r = self._classify("forsale-nocert.example",
                            cert=self.CERT_FAILED,
                            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.brandbucket.com"]}},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r

    def test_likely_third_party_yields_to_insufficient_data(self):
        """`predates_campaign` (`classifier.py:289`) e' assolutoria (LOW):
        deve cedere a `cert` fallito."""
        r = self._classify("old-inert-nocert.example",
                            whois={"creation_date": "2010-01-01T00:00:00"},
                            cert=self.CERT_FAILED,
                            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r

    def test_needs_review_yields_to_insufficient_data(self):
        """`needs_review` ha la STESSA severita' di caso di `insufficient_data`
        (entrambe MEDIUM in `CLASSIFICATION_SEVERITY`): non e' "uguale" --
        cambia la rationale e cosa legge l'analista, e il criterio dell'utente
        non fa eccezione per questa categoria. Regola:
        `old_domain_recently_updated` (`classifier.py:281`)."""
        from datetime import datetime, timedelta
        recent = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00")
        r = self._classify("dropcatch-nocert.example",
                            whois={"creation_date": "2010-01-01T00:00:00", "updated_date": recent},
                            cert=self.CERT_FAILED,
                            dns={"records": {"A": ["1.2.3.4"]}},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r

    # ── Verde, non-regressione ──

    def test_suspicious_survives_the_guard_even_with_cert_failed(self):
        """La trappola: se un fix sposta la guardia IN CIMA senza
        l'eccezione per severita' superiore, questo test la intercetta.
        Modellato su due domini reali della simulazione CODE-23 (nomi
        omessi): MX senza record A,
        dominio non aged, `cert` fallito. `mx_only_no_web`
        (`classifier.py:238`) e' ACCUSATORIA (HIGH, supera MEDIUM): deve
        restare `suspicious`, non degradare a `insufficient_data`."""
        r = self._classify("mx-only-like.example",
                            cert=self.CERT_FAILED,
                            dns={"records": {"A": [], "MX": ["10 mx.zoho.com"], "NS": ["ns1.example.com"]}},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "suspicious", r
        assert r["rule"] == "mx_only_no_web", r

    def test_http_only_failure_still_does_not_override_absolutory_rule(self):
        """L'emendamento del 2026-08-02 deve sopravvivere anche in
        combinazione con una regola assolutoria: `http` fallito DA SOLO non
        fa mai scattare la guardia, nemmeno quando la regola che risponde e'
        assolutoria (qui `parking`)."""
        r = self._classify("parked-http-down.example",
                            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns47.domaincontrol.com"]}},
                            collection_status={"http": True})
        assert r["auto_classification"] == "parking", r

    def test_no_failed_section_leaves_categories_untouched(self):
        """Senza alcuna sezione fallita, la guardia non deve mai intervenire:
        verificato su due categorie assolutorie distinte."""
        parking = self._classify("parked-clean.example",
                                  dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns47.domaincontrol.com"]}})
        assert parking["auto_classification"] == "parking", parking

        third_party = self._classify("old-inert-clean.example",
                                      whois={"creation_date": "2010-01-01T00:00:00"},
                                      dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}})
        assert third_party["auto_classification"] == "likely_third_party", third_party


class TestCollectionGuardPreservesRuleRationale:
    """`CODE-30`. Rilievo del `verifier` a G6 di `CODE-23`, MEDIA, introdotto
    dal fix stesso (non preesistente). `_apply_collection_guard`
    (`classifier.py:349-368`) costruisce un `_result` nuovo da zero quando
    sovrascrive l'esito con `insufficient_data`, e con esso SCARTA `rule` e
    `rationale` prodotti da `_classify_by_rules`. Nella simulazione su un
    insieme di snapshot reali molti domini perdono il "perche'" (sembrava un parcheggio / un
    dominio legittimo / un annuncio di vendita, ma un modulo non-http e'
    fallito), sostituito da un generico "Raccolta dati fallita per: ... —
    nessun segnale osservabile".

    Le prime quattro prove (una per famiglia di regola: parking, for_sale,
    legitimate_probable, needs_review) sono ROSSE oggi — punto 1 del
    criterio d'accettazione. La quinta (tetto di lunghezza, punto 4) e'
    ROSSA anch'essa, ma non per violazione del tetto: oggi il template
    fisso e' sempre corto, quindi il tetto da solo sarebbe gia' verde. E'
    rossa perche' verifica ANCHE la presenza della regola originale nello
    stesso assert — un fix che rispettasse il tetto tornando a scartare
    `rule`/`rationale` (il difetto di oggi) la lascerebbe rossa.

    Le ultime tre sono VERDI di NON REGRESSIONE (dichiarate come tali a G3,
    non da G4 in poi): il punto 2 (nessuna regola scattata → nessuna
    corrispondenza inventata) e' gia' vero oggi perche' oggi non si afferma
    nulla sulla regola sottostante — diventa un rischio solo se il fix
    aggiunge la fusione senza questa cautela, quindi resta un test di non
    regressione anche dopo il fix, non un punto rosso a se'. Le altre due
    proteggono le quattro chiavi lette dagli 8 test di `CODE-23` e dalla
    mappa di severita' di `orchestrator.py:46-59` (punto 3), e il caso
    'suspicious sopravvive alla guardia' gia' difeso da `CODE-23` (la
    trappola dichiarata nel mandato di G3)."""

    CERT_FAILED = {"ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                    "error": "crt.sh timeout"}

    # Tetto scelto per il punto 4: 500 caratteri. Il template della guardia
    # ("Raccolta dati fallita per: cert — nessun segnale osservabile") e'
    # ~60 caratteri; un nome di regola e' al massimo qualche decina di
    # caratteri; una rationale originale limitata allo stesso tetto gia'
    # usato in casa per campi testuali attacker-controlled (`_cap_ioc`,
    # `shared/utils.py:514-523`, 300 caratteri) ci sta comodamente sotto
    # 500 col resto del template. Non e' il tetto che il fix DEVE usare:
    # e' il tetto che qualunque fix ragionevole deve rispettare, scelto qui
    # perche' il mandato lo lascia alla mia discrezione.
    _RATIONALE_CAP = 500

    def _classify(self, domain, **kwargs):
        from services.classifier import classify_variant, VariantInput
        vi = VariantInput(domain=domain, **kwargs)
        return json.loads(classify_variant(vi).body)

    # ── Punto 1: rosso oggi, una prova per famiglia di regola assolutoria/needs_review ──

    def test_parking_rule_and_rationale_survive_the_guard(self):
        """`known_parking_ns` ha risposto prima che `cert` fallisse: oggi la
        guardia butta via sia il nome della regola sia il suo perche'."""
        r = self._classify("parked-nocert-rationale.example",
                            cert=self.CERT_FAILED,
                            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns47.domaincontrol.com"]}},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert "known_parking_ns" in r["rationale"], r["rationale"]
        assert "NS su provider parking noto: ns47.domaincontrol.com" in r["rationale"], r["rationale"]

    def test_for_sale_rule_and_rationale_survive_the_guard(self):
        """`marketplace_ns` ha risposto prima che `cert` fallisse."""
        r = self._classify("forsale-nocert-rationale.example",
                            cert=self.CERT_FAILED,
                            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.brandbucket.com"]}},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert "marketplace_ns" in r["rationale"], r["rationale"]
        assert "NS su marketplace domini: ns1.brandbucket.com" in r["rationale"], r["rationale"]

    def test_legitimate_probable_rule_and_rationale_survive_the_guard(self):
        """`http_active_substantial_content` ha risposto prima che `whois` e
        `cert` fallissero — stesso scenario del controesempio storico
        `CODE-23` (probe A)."""
        r = self._classify("http-substantial-nocert-rationale.example",
                            whois={"registrar": None, "creation_date": None, "updated_date": None,
                                   "error": "whois lookup timeout"},
                            cert=self.CERT_FAILED,
                            http={"checks": [{"status_code": 200, "content_length": 5000}],
                                  "overall_status": "active"},
                            collection_status={"whois": True, "cert": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert "http_active_substantial_content" in r["rationale"], r["rationale"]
        assert "Sito attivo con contenuto sostanziale (5000b)" in r["rationale"], r["rationale"]

    def test_needs_review_rule_and_rationale_survive_the_guard(self):
        """`hidden_elements_moderate` (rischio 20/100, sotto la soglia
        accusatoria di 30) ha risposto prima che `cert` fallisse."""
        r = self._classify("hidden-moderate-nocert.example",
                            cert=self.CERT_FAILED,
                            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}},
                            http={"checks": [{"status_code": 200, "content_length": 1000,
                                  "hidden_elements": {"risk_indicators": 20,
                                                       "summary": ["obfuscated iframe embed"]}}],
                                  "overall_status": "active"},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert "hidden_elements_moderate" in r["rationale"], r["rationale"]
        assert "Tag nascosti rilevati (20/100): obfuscated iframe embed" in r["rationale"], r["rationale"]

    # ── Punto 2: nessuna regola scattata, nessuna corrispondenza inventata ──

    def test_no_matching_rule_does_not_fabricate_a_match(self):
        """Con `rule == "no_matching_rule"` non deve comparire alcun
        «avrebbe corrisposto a»: non c'e' nulla a cui la sezione fallita
        avrebbe potuto corrispondere. Il testo resta quello di oggi."""
        r = self._classify("no-rule-nocert.example", cert=self.CERT_FAILED,
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert "avrebbe corrisposto a" not in r["rationale"], r["rationale"]
        assert "no_matching_rule" not in r["rationale"], r["rationale"]

    # ── Punto 4: tetto di lunghezza anche con dato remoto enorme ──

    def test_rationale_length_is_capped_even_with_huge_remote_data(self):
        """`ns_str` (:199) e' interpolato senza tetto dentro la rationale di
        `known_parking_ns` (:199). Un NS attacker-controlled molto lungo non
        deve produrre una rationale di guardia proporzionalmente enorme —
        MA il "perche'" (punto 1) deve comunque essere presente, non solo
        troncato via lo scarto di oggi: le due proprieta' sono verificate
        insieme perche' un fix che rispetta il tetto scartando di nuovo
        `rule`/`rationale` (tornando al difetto di oggi) deve restare
        rosso qui."""
        huge_ns = "ns47.domaincontrol.com" + "a" * 5000
        r = self._classify("huge-ns-nocert.example", cert=self.CERT_FAILED,
                            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": [huge_ns]}},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "insufficient_data", r
        assert "known_parking_ns" in r["rationale"], r["rationale"]
        assert len(r["rationale"]) <= self._RATIONALE_CAP, len(r["rationale"])

    # ── CODE-30 round 2: il tetto del punto 4 copre solo la porzione appesa
    # ("avrebbe corrisposto a: ..."), non il template stesso
    # ("Raccolta dati fallita per: {', '.join(failed_sections)} — nessun
    # segnale osservabile"). `failed_sections` deriva dalle CHIAVI di
    # `collection_status`, un `Optional[dict]` senza vincolo di forma ne' di
    # lunghezza (`VariantInput.collection_status`, classifier.py:51) —
    # propagato dall'orchestrator ma non validato qui. Una chiave enorme (o
    # arbitraria) fa esplodere il template PRIMA che il budget calcolato a
    # valle abbia una qualunque possibilità di intervenire.

    def test_rationale_cap_holds_with_huge_collection_status_key_no_rule(self):
        """Variante 1: chiave enorme in `collection_status`, nessuna regola
        scattata (`no_matching_rule`). Sul percorso `no_matching_rule` oggi
        non viene appesa alcuna coda (`underlying_rule == "no_matching_rule"`,
        classifier.py:382) — quindi il tetto non ha NESSUN punto in cui
        intervenire: il template stesso, gia' gonfio della chiave enorme, e'
        l'intera rationale restituita."""
        huge_key = "cert" + "X" * 2000
        r = self._classify("huge-collection-key-norule.example", cert=self.CERT_FAILED,
                            collection_status={huge_key: True})
        assert r["auto_classification"] == "insufficient_data", r
        assert r["rule"] == "module_collection_failed", r
        assert len(r["rationale"]) <= self._RATIONALE_CAP, len(r["rationale"])

    def test_rationale_cap_holds_with_huge_collection_status_key_and_rule(self):
        """Variante 2: stessa chiave enorme, ma una regola assolutoria/
        needs_review E' scattata prima che la guardia intervenga
        (`known_parking_ns`, stesso scenario DNS del test sopra). Il budget
        calcolato a valle (classifier.py:385) sottrae la lunghezza del
        template gia' costruito, quindi con un template abbastanza grande
        `max(0, ...)` collassa a zero — ma il template stesso, che precede
        quel calcolo, resta fuori tetto: il "perche'" della regola puo'
        anche sparire (budget zero), il tetto sul totale non puo' esserlo."""
        huge_key = "cert" + "Y" * 2000
        r = self._classify("huge-collection-key-rule.example", cert=self.CERT_FAILED,
                            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns47.domaincontrol.com"]}},
                            collection_status={huge_key: True})
        assert r["auto_classification"] == "insufficient_data", r
        assert r["rule"] == "module_collection_failed", r
        assert len(r["rationale"]) <= self._RATIONALE_CAP, len(r["rationale"])

    # ── Non-regressione (verde oggi): le altre quattro chiavi dell'esito
    # della guardia restano identiche, qualunque sia la regola sottostante ──

    def test_other_result_keys_unchanged_regardless_of_underlying_rule(self):
        """Protegge gli 8 test di `CODE-23` e la mappa di severita' di
        `orchestrator.py:46-59`, che leggono queste chiavi e non la
        `rationale`. Un fix che cambia la classificazione qui deve
        risultare rosso."""
        cases = [
            ("parked-keys.example", dict(cert=self.CERT_FAILED,
                dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns47.domaincontrol.com"]}},
                collection_status={"cert": True})),
            ("norule-keys.example", dict(cert=self.CERT_FAILED, collection_status={"cert": True})),
        ]
        for domain, kwargs in cases:
            r = self._classify(domain, **kwargs)
            assert r["auto_classification"] == "insufficient_data", r
            assert r["confidence"] == "low", r
            assert r["rule"] == "module_collection_failed", r
            assert r["action"] == "manual_review", r
            # `insufficient_data` non e' in `("needs_review", "suspicious")`
            # (`_result`, classifier.py:345): oggi `manual_review_required`
            # e' False su questo percorso, non True. Verificato eseguendo
            # la suite prima di scrivere questa asserzione.
            assert r["manual_review_required"] is False, r

    def test_suspicious_still_bypasses_the_new_rationale_path(self):
        """La trappola del mandato: `suspicious` con `cert` fallito deve
        continuare a sopravvivere alla guardia con la SUA rule/rationale
        native (`mx_only_no_web`), senza mai passare dal percorso di
        fusione nuovo — stesso scenario gia' difeso da `CODE-23`
        (due domini reali, nomi omessi)."""
        r = self._classify("mx-only-like-rationale.example",
                            cert=self.CERT_FAILED,
                            dns={"records": {"A": [], "MX": ["10 mx.zoho.com"], "NS": ["ns1.example.com"]}},
                            collection_status={"cert": True})
        assert r["auto_classification"] == "suspicious", r
        assert r["rule"] == "mx_only_no_web", r
        assert r["rationale"] == "MX attivo senza record A, profilo solo-email", r


class TestClassifyBatch:
    def test_batch_classification(self):
        resp = client.post("/classify/batch", json={
            "variants": [
                {"domain": "parked.com", "fuzzer": "test", "http": {
                    "checks": [{"status_code": 200, "content_length": 50}], "overall_status": "active"}},
                {"domain": "suspicious.com", "fuzzer": "test", "dns": {
                    "records": {"A": [], "MX": ["mail.protonmail.ch"], "NS": []}}},
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert data["summary"]["parking"] == 1
        assert data["summary"]["suspicious"] == 1


class TestHealth:
    def test_health(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


# ═══════════════════════════════════════════
# REGRESSION: /diff crash on None-valued intel keys
# ═══════════════════════════════════════════

class TestDiffNoneSafety:
    """
    A stored snapshot can have a key PRESENT with value None (e.g. "cert": null
    when a domain has no certificates). baseline_diff must not crash on these.
    Reproduces an HTTP 500 observed on a real snapshot.
    """

    def _mk(self, **over):
        base = {
            "dns": {"records": {"A": ["1.2.3.4"]}, "email_auth": {}},
            "cert": None, "http": None, "whois": None, "reputation": None,
        }
        base.update(over)
        return base

    def test_diff_survives_none_cert(self):
        from services.classifier import baseline_diff, DiffInput
        r = baseline_diff(DiffInput(domain="x.com", client="c", legitimate="leg.com",
                                    baseline=self._mk(), current=self._mk()))
        assert r.status_code == 200

    def test_diff_survives_all_none_sections(self):
        from services.classifier import baseline_diff, DiffInput
        # every optional section None on both sides
        allnone = {"dns": None, "cert": None, "http": None, "whois": None, "reputation": None}
        r = baseline_diff(DiffInput(domain="x.com", client="c", legitimate="leg.com",
                                    baseline=allnone, current=allnone))
        assert r.status_code == 200

    def test_diff_detects_changes_from_none_baseline(self):
        """Sections that HAVE a baseline must still be diffed even when other
        sections are None (None-safety: no crash, no silencing of siblings).

        MODIFICA DELIBERATA (CODE-01, gap residuo). L'asserzione originale
        pretendeva anche `http_activated` da una baseline `http: None`. Quella
        aspettativa codificava il difetto: `None` in uno snapshot persistito
        significa «modulo mai raccolto con successo» — l'orchestrator lo scrive
        quando il collector fallisce e non c'era nulla di pregresso — non «sito
        era giù e ora è su». Diffarci contro produceva un delta pari all'intera
        storia alla prima raccolta riuscita (dimostrato: 25 certificati storici
        segnalati come nuovi). Ora una sezione senza baseline si popola in
        silenzio; l'asserzione su `mx_record_changed`, la cui sezione `dns` HA
        una baseline, resta invariata ed è il cuore del test."""
        from services.classifier import baseline_diff, DiffInput
        prev = {"dns": {"records": {"A": []}, "email_auth": {"spf": {"present": False}}},
                "cert": None, "http": None, "whois": None, "reputation": None}
        curr = {"dns": {"records": {"A": ["9.9.9.9"], "MX": ["10 m.x"]}, "email_auth": {"spf": {"present": True, "records": ["v=spf1 ~all"]}}},
                "cert": {"ct_certificates": {"total": 3}}, "http": {"checks": [{"url": "http://x.com", "status_code": 200}]},
                "whois": None, "reputation": None}
        r = baseline_diff(DiffInput(domain="x.com", client="c", legitimate="leg.com", baseline=prev, current=curr))
        assert r.status_code == 200
        body = json.loads(r.body)
        types = {a["type"] for a in body["alerts"]}
        # dns HA una baseline: il cambio si vede, e le sezioni None non lo zittiscono
        assert "mx_record_changed" in types
        # http NON ha baseline (None): prima osservazione, si popola in silenzio
        assert "http_activated" not in types
        # cert idem: 3 certificati storici non sono "3 nuovi certificati"
        assert not any("certificate" in t for t in types), types

    # ── CLS-01z, battuta 15: canale alert dedicato per il dominio LEGITTIMO
    # del cliente. Contratto (BUG-REGISTER.md, `CLS-01z`, decisione utente
    # 2026-08-17): un `suspicious_dead_markup` sul dominio legittimo deve
    # generare un alert CRITICAL dedicato `legit_suspicious_dead_markup_detected`
    # — simmetrico ai fratelli `legit_hidden_form_detected`/
    # `legit_invisible_iframe_detected` già esistenti (services/classifier.py,
    # `_diff_hidden_elements`), non solo il generico `legit_hidden_elements_detected`
    # (che oggi è l'unico a scattare, con severità CRITICAL a sua volta, ma sotto
    # un `type` diverso — un analista che filtra per il tipo specifico non lo
    # vedrebbe). Il finding `hidden_elements` è costruito qui a mano (come già
    # fa `test_suspicious_hidden_elements` in TestClassifyVariant), per isolare
    # il collegamento diff→alert dalla correttezza del detector stesso, testata
    # a parte in tests/test_utils.py.

    def test_legit_suspicious_dead_markup_alert_is_critical(self):
        """CLS-01z, battuta 15. Un suspicious_dead_markup NUOVO (assente dalla
        baseline) sul dominio legittimo del cliente deve produrre un alert col
        type esatto `legit_suspicious_dead_markup_detected` e severità
        CRITICAL — non solo un generico `legit_hidden_elements_detected`."""
        from services.classifier import baseline_diff, DiffInput
        baseline = self._mk(http={"checks": []})
        current = self._mk(http={"checks": [{
            "url": "https://legit-corp.example/",
            "hidden_elements": {
                "risk_indicators": 30,
                "suspicious_dead_markup": [{
                    "type": "iframe",
                    "source": "fallback_content",
                    "url": "http://evil.example/c2",
                }],
                "summary": ["markup morto sospetto verso host esterno"],
            },
        }]})
        r = baseline_diff(DiffInput(domain="legit-corp.example", client="acme",
                                    legitimate="legit-corp.example",
                                    baseline=baseline, current=current))
        assert r.status_code == 200
        body = json.loads(r.body)
        matches = [a for a in body["alerts"] if a["type"] == "legit_suspicious_dead_markup_detected"]
        assert matches, (
            "nessun alert legit_suspicious_dead_markup_detected generato per "
            f"un suspicious_dead_markup sul dominio legittimo del cliente: {body['alerts']}"
        )
        assert matches[0]["severity"] == "CRITICAL", (
            f"severita' dell'alert legit_suspicious_dead_markup_detected: "
            f"{matches[0]['severity']} (attesa CRITICAL)"
        )

    # ── CLS-01z round-4, rilievo minore (verifier/security-reviewer
    # round-3): il caso (b) "malformed_endtag_swallow" è stato rimosso
    # dallo scope del detector fin dal round-3 (decisione utente,
    # BUG-REGISTER.md §6) — resta SOLO il caso (a) "fallback_content". Il
    # testo del messaggio dell'alert dedicato (services/classifier.py:
    # 850-853) non è stato aggiornato di conseguenza: cita ancora
    # testualmente "attributi di un end-tag malformato", un riferimento al
    # caso (b) rimosso. Un analista che legge l'alert può concludere che il
    # detector copra ancora un vettore che non copre più.
    def test_legit_suspicious_dead_markup_alert_message_does_not_cite_removed_case_b(self):
        """Il messaggio di legit_suspicious_dead_markup_detected non deve
        più menzionare il caso (b) 'malformed_endtag_swallow'/'end-tag
        malformato', fuori scope dal round-3: solo il fallback content
        opaco (caso a) resta un candidato possibile per questo alert."""
        from services.classifier import baseline_diff, DiffInput
        baseline = self._mk(http={"checks": []})
        current = self._mk(http={"checks": [{
            "url": "https://legit-corp.example/",
            "hidden_elements": {
                "risk_indicators": 30,
                "suspicious_dead_markup": [{
                    "type": "iframe",
                    "source": "fallback_content",
                    "url": "http://evil.example/c2",
                }],
                "summary": ["markup morto sospetto verso host esterno"],
            },
        }]})
        r = baseline_diff(DiffInput(domain="legit-corp.example", client="acme",
                                    legitimate="legit-corp.example",
                                    baseline=baseline, current=current))
        assert r.status_code == 200
        body = json.loads(r.body)
        matches = [a for a in body["alerts"] if a["type"] == "legit_suspicious_dead_markup_detected"]
        assert matches, (
            "precondizione non soddisfatta: nessun alert "
            f"legit_suspicious_dead_markup_detected generato: {body['alerts']}"
        )
        message = matches[0]["message"]
        assert "end-tag malformato" not in message and "malformed_endtag_swallow" not in message, (
            "il messaggio dell'alert cita ancora il caso (b) rimosso "
            f"dallo scope del detector (round-3): {message!r}"
        )


class TestDomainAgeRule:
    """Point 1: domain-age classification. An old, inert domain that predates a
    campaign is likely a legitimate third party; but a recent domain with MX (even
    with a facade website) must stay flagged, and an old domain re-registered
    recently must NOT be auto-cleared."""

    def _classify(self, domain, whois=None, dns=None, http=None, cert=None):
        from services.classifier import classify_variant, VariantInput
        vi = VariantInput(domain=domain, whois=whois or {}, dns=dns or {},
                          http=http or {}, cert=cert or {})
        return json.loads(classify_variant(vi).body)

    def test_old_inert_domain_is_third_party(self):
        r = self._classify("fabrlkam.example",
                            whois={"creation_date": "2018-06-12T00:00:00"},
                            dns={"records": {"A": ["1.2.3.4"]}})
        assert r["auto_classification"] == "likely_third_party"
        assert r["confidence"] == "low"

    def test_recent_domain_with_mx_stays_suspicious(self):
        # facade site + MX on a recent domain must NOT be cleared as legitimate
        r = self._classify("facade-fake.example",
                            whois={"creation_date": "2025-10-18T00:00:00"},
                            dns={"records": {"A": ["1.2.3.4"], "MX": ["10 eforward1.registrar-servers.com"]}},
                            http={"checks": [{"status_code": 200, "content_length": 8000}]})
        assert r["auto_classification"] == "suspicious"

    def test_old_domain_recently_reregistered_needs_review(self):
        # created long ago but updated recently → possible drop-catch, don't clear
        from datetime import datetime, timedelta
        recent = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00")
        r = self._classify("dropcatch.com",
                            whois={"creation_date": "2010-01-01T00:00:00", "updated_date": recent},
                            dns={"records": {"A": ["1.2.3.4"]}})
        assert r["auto_classification"] == "needs_review"
        assert r["rule"] == "old_domain_recently_updated"

    def test_recent_inert_domain_still_needs_review(self):
        # recent, no records worth a rule → stays needs_review (not auto-cleared)
        r = self._classify("newthing.com",
                            whois={"creation_date": "2026-05-01T00:00:00"},
                            dns={"records": {}})
        assert r["auto_classification"] == "needs_review"


class TestClassifierRobustness:
    """Bug hunt findings: the classifier must not crash on malformed/partial input
    (WHOIS list-dates, future dates, None sub-objects) which occur with real data."""

    def _post(self, payload):
        return client.post("/classify/variant", json=payload)

    def test_whois_list_date_handled(self):
        # python-whois often returns creation_date as a LIST — must use earliest
        from services.classifier import _domain_age
        r = _domain_age({"creation_date": ["2017-04-21", "2017-04-22"]})
        assert r["age_days"] is not None
        assert r["created"] == "2017-04-21"

    def test_future_creation_date_clamped(self):
        from services.classifier import _domain_age
        r = _domain_age({"creation_date": "2050-01-01T00:00:00"})
        assert r["age_days"] is None  # not a negative number

    def test_none_records_no_crash(self):
        assert self._post({"domain": "x.com", "dns": {"records": None}}).status_code == 200

    def test_none_checks_no_crash(self):
        assert self._post({"domain": "x.com", "http": {"checks": None}}).status_code == 200

    def test_none_in_checks_list_no_crash(self):
        assert self._post({"domain": "x.com", "http": {"checks": [None]}}).status_code == 200

    def test_none_cert_certificates_no_crash(self):
        assert self._post({"domain": "x.com", "cert": {"ct_certificates": None}}).status_code == 200

    def test_all_none_sub_objects(self):
        r = self._post({"domain": "x.com", "dns": None, "http": None,
                        "cert": None, "whois": None})
        assert r.status_code == 200
        assert "auto_classification" in r.json()


class TestClassifierSecurity:
    """Security audit: WHOIS data is attacker-controlled (registrant sets their own
    record). Parsing it must resist DoS, log injection, and type confusion."""

    def test_huge_list_no_dos(self):
        # a hostile WHOIS returning a giant date list must be bounded
        import time
        from services.classifier import _domain_age
        t0 = time.time()
        r = _domain_age({"creation_date": ["2019-01-01"] * 100000})
        assert (time.time() - t0) < 0.2  # bounded, not O(n) over 100k
        assert r["created"] == "2019-01-01"

    def test_huge_string_no_dos(self):
        from services.classifier import _domain_age
        r = _domain_age({"creation_date": "2019-" + "0" * 100000})
        assert r["age_days"] is None  # junk, safely rejected

    def test_newline_not_in_output(self):
        # log-injection payload in a date must never reach the formatted output
        from services.classifier import _domain_age
        r = _domain_age({"creation_date": "2019-01-01\n\n\nFAKE LOG LINE"})
        assert r["created"] == "2019-01-01"
        assert "\n" not in (r["created"] or "")

    def test_non_string_date_types_rejected(self):
        from services.classifier import _domain_age
        for bad in [{"evil": "x"}, b"2019-01-01", [["2019"]], 10**100]:
            r = _domain_age({"creation_date": bad})
            assert r["age_days"] is None

    def test_batch_size_capped(self):
        big = {"variants": [{"domain": f"d{i}.com"} for i in range(1001)]}
        assert client.post("/classify/batch", json=big).status_code == 422


class TestAgeModulatedSeverity:
    """Weak threat signals (hidden elements, MX-only, forwarding/privacy MX) are normal on
    long-established third-party domains. They must alarm only on recent registrations,
    otherwise the HIGH bucket fills with decades-old legitimate businesses."""

    def _classify(self, domain, whois=None, dns=None, http=None, cert=None):
        from services.classifier import classify_variant, VariantInput
        vi = VariantInput(domain=domain, whois=whois or {}, dns=dns or {},
                          http=http or {}, cert=cert or {})
        return json.loads(classify_variant(vi).body)

    def _hidden(self, risk=45):
        return {"checks": [{"status_code": 200, "content_length": 5000,
                            "hidden_elements": {"risk_indicators": risk,
                                                "summary": ["1 iframe invisibili"]}}]}

    def test_hidden_elements_on_old_domain_is_not_high(self):
        r = self._classify("hidden-aged.example",
                           whois={"creation_date": "2002-03-11T00:00:00"},
                           dns={"records": {"A": ["1.2.3.4"]}}, http=self._hidden())
        assert r["auto_classification"] == "needs_review"
        assert r["rule"] == "hidden_elements_aged_domain"

    def test_hidden_elements_on_recent_domain_is_high(self):
        r = self._classify("newfake.com",
                           whois={"creation_date": "2026-03-01T00:00:00"},
                           dns={"records": {"A": ["1.2.3.4"]}}, http=self._hidden())
        assert r["auto_classification"] == "suspicious"
        assert r["rule"] == "hidden_elements_detected"

    def test_mx_only_on_old_domain_is_not_high(self):
        # a decades-old email-only domain is a normal small business
        r = self._classify("mxonly-aged.example",
                           whois={"creation_date": "2009-05-27T00:00:00"},
                           dns={"records": {"MX": ["10 mx1.isp.example"]}})
        assert r["auto_classification"] == "needs_review"
        assert r["rule"] == "mx_only_aged_domain"

    def test_mx_only_on_recent_domain_is_high(self):
        r = self._classify("mxonly-recent.example",
                           whois={"creation_date": "2026-01-03T00:00:00"},
                           dns={"records": {"MX": ["10 mx.mail-host-d.example"]}})
        assert r["auto_classification"] == "suspicious"
        assert r["rule"] == "mx_only_no_web"

    def test_renewal_does_not_escalate_old_domain(self):
        # WHOIS updated_date changes on routine renewal: it must not push an old domain
        # back into HIGH, only prevent auto-clearing to LOW
        from datetime import datetime, timedelta
        recent = (datetime.utcnow() - timedelta(days=20)).strftime("%Y-%m-%dT00:00:00")
        r = self._classify("renewed.it",
                           whois={"creation_date": "2001-01-01T00:00:00", "updated_date": recent},
                           dns={"records": {"A": ["1.2.3.4"]}}, http=self._hidden())
        assert r["auto_classification"] != "suspicious"

    def test_recent_inert_domain_gets_explicit_rule(self):
        r = self._classify("dormant.com",
                           whois={"creation_date": "2026-05-13T00:00:00"},
                           dns={"records": {"A": ["1.2.3.4"]}})
        assert r["rule"] == "recent_registration_inactive"
        assert r["auto_classification"] == "needs_review"


class TestSeverityThreshold:
    """SCO-01. CRITICAL e' riservato all'ATTIVITA' DOLOSA OSSERVATA. Un cambio di
    stato — registrazione, certificato, attivazione, presenza di MX — non basta,
    per quanto sospetto sia il contesto. Decisione dell'utente del 2026-07-25.

    Misura all'origine: su un insieme di snapshot reali gli alert CRITICAL emessi
    erano tutti emissioni di certificati DV su domini di terzi, con precisione
    nulla."""

    def test_state_changes_are_not_critical(self):
        from shared.constants import SEVERITY_MAP
        for alert_type in ("new_certificate", "new_certificate_batch",
                           "live_tls_cert_detected", "http_activated",
                           "dnstwist_new_registered", "dnstwist_new_with_mx",
                           "variant_http_activated", "variant_new_certificate",
                           "hidden_elements_high_risk"):
            assert SEVERITY_MAP[alert_type] != "CRITICAL", \
                f"{alert_type} e' un cambio di stato, non attivita' dolosa osservata"

    def test_observed_malicious_activity_stays_critical(self):
        from shared.constants import SEVERITY_MAP
        for alert_type in ("credential_form_detected", "brand_impersonation",
                           "hidden_form_detected", "invisible_iframe_detected",
                           "vt_malicious_detected", "otx_malware_associated",
                           "legit_hidden_form_detected", "legit_content_injected"):
            assert SEVERITY_MAP[alert_type] == "CRITICAL", \
                f"{alert_type} e' attivita' dolosa osservata e deve restare CRITICAL"

    def test_maintenance_events_are_info(self):
        from shared.constants import SEVERITY_MAP
        for alert_type in ("soa_changed", "whois_renewed", "http_headers_changed"):
            assert SEVERITY_MAP[alert_type] == "INFO"

    def test_severity_rank_orders_info_below_low(self):
        from shared.constants import severity_rank
        assert severity_rank("CLEAN") < severity_rank("INFO") < severity_rank("LOW") \
            < severity_rank("MEDIUM") < severity_rank("HIGH") < severity_rank("CRITICAL")
        assert severity_rank(None) == 0 and severity_rank("boh") == 0
        assert severity_rank("critical") == severity_rank("CRITICAL")

    def test_certificate_batch_no_longer_dominates_max_severity(self):
        """Il diff di un dominio che emette solo certificati non deve piu'
        restituire CRITICAL: era il meccanismo dei 25 falsi positivi."""
        from fastapi.testclient import TestClient
        from services.classifier import app
        c = TestClient(app)
        r = c.post("/diff", json={
            "domain": "terzo.example", "client": "acme", "legitimate": "acme.example",
            "baseline": {"cert": {"ct_certificates": {"total": 0}}},
            "current": {"cert": {"ct_certificates": {"total": 21}}},
        })
        assert r.status_code == 200
        body = r.json()
        assert body["alert_count"] == 1
        assert body["alerts"][0]["type"] == "new_certificate_batch"
        assert body["max_severity"] == "HIGH", body["max_severity"]


class TestFirstObservationEstablishesBaseline:
    """CODE-01, gap residuo individuato dalla revisione indipendente.

    Il fix originale impediva a un modulo fallito di SOVRASCRIVERE una baseline
    buona. Restava scoperto il caso opposto: la PRIMA osservazione di una sezione
    fallisce, l'orchestrator persiste `None`, e la prima raccolta riuscita al giro
    successivo veniva diffata contro quel vuoto — riproducendo lo stesso «delta =
    intera storia» che CODE-01 dichiarava eliminato.

    Regola: una sezione assente o None in baseline non è una baseline a zero, è
    l'assenza di baseline. Alla prima osservazione valida si popola in silenzio."""

    def _diff(self, baseline, current):
        from fastapi.testclient import TestClient
        from services.classifier import app
        c = TestClient(app)
        r = c.post("/diff", json={"domain": "v.example", "client": "acme",
                                  "legitimate": "acme.example",
                                  "baseline": baseline, "current": current})
        assert r.status_code == 200
        return r.json()

    def test_cert_first_success_after_failed_first_scan_is_silent(self):
        body = self._diff(
            {"cert": None},   # ciò che l'orchestrator salva dopo un primo scan fallito
            {"cert": {"ct_certificates": {"total": 25}, "error": None}},
        )
        assert body["alert_count"] == 0, body["alerts"]
        assert body["max_severity"] == "CLEAN"

    def test_dns_first_success_after_failed_first_scan_is_silent(self):
        body = self._diff(
            {"dns": None},
            {"dns": {"records": {"A": ["1.2.3.4"], "MX": ["10 mx.example"]},
                     "email_auth": {"dmarc": {"present": True}}}},
        )
        assert body["alert_count"] == 0, body["alerts"]

    def test_real_change_still_detected_once_baseline_exists(self):
        """Non deve creare falsi negativi: con una baseline vera, il delta si vede."""
        body = self._diff(
            {"cert": {"ct_certificates": {"total": 2}}},
            {"cert": {"ct_certificates": {"total": 25}}},
        )
        assert body["alert_count"] == 1
        assert body["alerts"][0]["type"] == "new_certificate_batch"

    def test_sections_are_independent(self):
        """Una sezione senza baseline non deve zittire le altre che ce l'hanno."""
        body = self._diff(
            {"cert": None, "dns": {"records": {"A": ["1.1.1.1"]}}},
            {"cert": {"ct_certificates": {"total": 9}},
             "dns": {"records": {"A": ["9.9.9.9"]}}},
        )
        types = [a["type"] for a in body["alerts"]]
        assert "a_record_changed" in types
        assert not any("certificate" in t for t in types), types


# ═══════════════════════════════════════════════════════════════
# SCO-05 — regola omografi, criterio a 12 casi (G3)
# ═══════════════════════════════════════════════════════════════
#
# Fonte del criterio: BUG-REGISTER.md, "Definition of Ready di SCO-05 — CHIUSA
# (2026-08-08, sera)" e la sezione immediatamente successiva sul rischio di
# riapertura (caso #8). Prima del fix `v.fuzzer` non era letto da
# nessuna regola di `_classify_by_rules` (`services/classifier.py`): un
# omografo senza altro segnale finiva nelle code generiche
# (`http_active_substantial_content`, `no_matching_rule`,
# `recent_registration_inactive`...) con la severità di quelle regole, non
# quella dedicata prevista dal fix.
#
# Vincolo non negoziabile della Definition of Ready: ogni caso ancorato a un
# dominio della mappa G2 usa la FORMA dei dati reali di uno snapshot
# (dns.records, http.checks, cert.ct_certificates, whois — copiati
# verbatim nella struttura, non costruiti a mano). Nomi, indirizzi,
# nameserver, date e dimensioni sono sintetici: conservano solo ciò che le
# regole leggono (età rispetto ad `AGE_THIRD_PARTY_DAYS`, presenza di A/MX,
# contenuto sopra soglia, forma Unicode del nome). I
# casi #4/#6/#9/#10 sono dichiarati sintetici nel corpo di ciascun test,
# come richiede il criterio, perché nessuno dei domini omografi reali del
# campione li esercita.

class TestSCO05HomoglyphSeverityCriterion:
    """Criterio a 12 casi (i casi #5/#7/#8 vivono in test_orchestrator.py:
    #5 è un test end-to-end di pipeline — l'anti-oscillazione dipende dal
    meccanismo "lettura da intel_store", non dal solo classificatore — e
    #7/#8 riguardano il meccanismo WHOIS-only per i domini mai raccolti,
    anch'esso fuori da questo file). #11/#12 sono i vecchi #5/#6 di
    `SCO-03`(fix), congelati e riusati **verbatim** per esplicita indicazione
    del registro ("riusabile verbatim se il criterio non cambia su quei due
    punti") — già verdi oggi, senza alcun fix: non-regressioni dichiarate,
    non falsificazioni di un difetto."""

    def _classify(self, domain, fuzzer, whois=None, dns=None, http=None, cert=None,
                  collection_status=None):
        body = {"domain": domain, "fuzzer": fuzzer, "whois": whois, "dns": dns,
                "http": http, "cert": cert, "collection_status": collection_status}
        resp = client.post("/classify/variant", json=body)
        assert resp.status_code == 200, resp.text
        return resp.json()

    def _case_severity(self, result):
        from services.orchestrator import CLASSIFICATION_SEVERITY
        return CLASSIFICATION_SEVERITY.get(result["auto_classification"], "MEDIUM")

    # ── Caso #1 — content-vs-forma, NON aged, risolvente ──────────────────
    # Forma di uno snapshot reale (omografo non aged, risolvente, sito
    # attivo); nome, date, IP, NS, dimensione e totale CT sintetici, con la
    # creation_date sotto `AGE_THIRD_PARTY_DAYS`.
    def test_case1_fabrikkam_content_vs_forma_non_aged_resolving(self):
        """Oggi: `http_active_substantial_content`/`legitimate_probable`/LOW
        (verificato con l'harness su questi stessi dati). Atteso dopo il fix:
        `suspicious`/HIGH — la forma omografa deve prevalere sul contenuto
        attivo apparentemente legittimo quando il dominio non è `is_aged`
        (Domanda 1, decisione utente 2026-08-08, opzione A)."""
        from shared.constants import severity_rank
        r = self._classify(
            "fabrikkam.example", fuzzer="homoglyph",
            whois={"creation_date": "2026-01-19T08:14:07", "updated_date": "2026-01-19T08:17:40"},
            dns={"records": {"A": ["198.51.100.35", "203.0.113.226"], "MX": [],
                              "NS": ["ada.ns.dns-host.example", "bob.ns.dns-host.example"]}},
            http={"checks": [{"status_code": 200, "content_length": 10240,
                               "url": "http://fabrikkam.example"}]},
            cert={"ct_certificates": {"total": 12, "unique_cn": ["fabrikkam.example"]}},
        )
        sev = self._case_severity(r)
        assert severity_rank(sev) >= severity_rank("HIGH"), (r["auto_classification"], sev, r["rule"])

    # ── Caso #2 — content-vs-forma, controllo AGED ─────────────────────────
    # Due domini aged con la forma di snapshot reali: c0ntoso.example e
    # pr0seware.example (nomi, date, IP, NS/MX e dimensioni sintetici, date
    # oltre `AGE_THIRD_PARTY_DAYS`). NON-REGRESSIONE DICHIARATA: il criterio prevede
    # "invariato" per i domini aged — il gate `is_aged` esclude il blocco
    # omografo indipendentemente dal fix, quindi questo test è verde OGGI e
    # deve restare verde dopo il fix. Non forzato al rosso.
    def test_case2_c0ntoso_content_vs_forma_aged_control_unchanged(self):
        r = self._classify(
            "c0ntoso.example", fuzzer="homoglyph",
            whois={"creation_date": "1998-07-22T04:00:00", "updated_date": "2025-12-15T06:41:10"},
            dns={"records": {"A": ["192.0.2.37"],
                              "MX": ["10 mx.mail-host-a.example"],
                              "NS": ["ns1.registrar-a.example"]}},
            http={"checks": [{"status_code": 200, "content_length": 11800,
                               "url": "http://c0ntoso.example"}]},
            cert={"ct_certificates": {"total": 0, "unique_cn": []}},
        )
        assert r["auto_classification"] == "legitimate_probable", r
        assert self._case_severity(r) == "LOW", r

    def test_case2_pr0seware_content_vs_forma_aged_control_unchanged(self):
        """Secondo dominio per lo stesso controllo (case #2), NS/MX
        diversi da c0ntoso.example: non è una ripetizione dello stesso input."""
        r = self._classify(
            "pr0seware.example", fuzzer="homoglyph",
            whois={"creation_date": "2000-06-13T10:02:51", "updated_date": "2025-08-04T09:15:00"},
            dns={"records": {"A": ["198.51.100.22"], "MX": ["50 mail1.hosting-b.example"],
                              "NS": ["dns.hosting-b.example", "ns7.dns-secondary.example"]}},
            http={"checks": [{"status_code": 200, "content_length": 14500,
                               "url": "http://pr0seware.example"}]},
            cert=None,
        )
        assert r["auto_classification"] == "legitimate_probable", r
        assert self._case_severity(r) == "LOW", r

    # ── Caso #3 — WHOIS TENTATO E NEGATIVO, nessuna elevazione ────────────
    # RISCRITTO alla revisione 2 del criterio (decisione utente 2026-08-11).
    # Alla revisione 1 questo caso attendeva `suspicious`/HIGH; l'esito è
    # cambiato, non l'asserzione è stata "corretta": l'invariante deciso
    # dall'utente è che il blocco omografo si attivi su un SEGNALE OSSERVATO,
    # mai sull'assenza di un segnale. Qui non c'è alcun segnale osservato — il
    # nome è single-script (cóntosō.example, Latin Extended), il DNS è vuoto, e il
    # WHOIS è stato *tentato senza successo*. `not is_aged` è vero anche qui,
    # ma solo perché non sappiamo nulla dell'età, non perché il dominio sia
    # giovane: è la classe di difetto "assente ≠ fallito" (CODE-01).
    #
    # Nome sintetico: xn--cntos-0ta84d.example. Tutte
    # e quattro le sezioni hanno la forma dello snapshot reale corrispondente:
    # whois con `error` = "No
    # match for ..." e tutti i campi a None, dns con record vuoti, http
    # bloccato da SSRF protection ("host does not resolve"), cert a zero.
    # `collection_status={"whois": True}` è esattamente ciò che l'orchestrator
    # calcola da questo whois reale (`_module_failed` → `collection_failed`,
    # shared/utils.py: `error` non vuoto ⇒ raccolta fallita).
    def test_case3_whois_attempted_and_negative_is_not_elevated(self):
        """Il canale CRITICAL resta escluso (controllo negativo invariato) E
        il caso non viene elevato: con la raccolta WHOIS fallita l'esito
        corretto è quello che la guardia di raccolta produce già oggi per
        qualunque altra regola, `insufficient_data`/MEDIUM, non `suspicious`/
        HIGH prodotto dal solo fatto che il fuzzer è "homoglyph"."""
        r = self._classify(
            "xn--cntos-0ta84d.example", fuzzer="homoglyph",
            whois={"domain": "xn--cntos-0ta84d.example", "registrar": None,
                   "creation_date": None, "expiration_date": None, "updated_date": None,
                   "status": [], "nameservers": [],
                   "registrant": {"name": None, "org": None, "country": None, "email": None},
                   "privacy_protected": False, "dnssec": False, "age_days": None,
                   "error": 'No match for "XN--CNTOS-0TA84D.EXAMPLE".'},
            dns={"records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
                             "SOA": [], "CNAME": []}, "error": None},
            http={"overall_status": "down", "hidden_elements_risk": 0, "error": None,
                  "checks": [
                      {"status_code": None, "content_length": 0,
                       "url": "http://xn--cntos-0ta84d.example", "hidden_elements": None,
                       "error": "blocked (SSRF protection): host does not resolve"},
                      {"status_code": None, "content_length": 0,
                       "url": "https://xn--cntos-0ta84d.example", "hidden_elements": None,
                       "error": "blocked (SSRF protection): host does not resolve"}]},
            cert={"ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                  "error": None},
            collection_status={"whois": True},
        )
        assert r["auto_classification"] != "phishing", r
        assert self._case_severity(r) != "CRITICAL", r
        assert r["auto_classification"] == "insufficient_data", (
            "WHOIS tentato e fallito su un omografo single-script senza alcun "
            "segnale osservato: l'assenza di informazione non è evidenza, il caso "
            f"non va elevato — {r['auto_classification']}/{r['rule']}")
        assert self._case_severity(r) == "MEDIUM", (r["auto_classification"], r["rule"])

    # ── Caso #4 — canale CRITICAL, script-mixing reale: DICHIARATO SINTETICO
    def test_case4_script_mixing_synthetic_declared(self):
        """Nessuno dei domini omografi reali della mappa G2 esercita il
        ramo mixed-script (gli `xn--` reali del campione sono Latin
        Extended a script singolo — vedi caso #3 sopra).
        Dominio SINTETICO, dichiarato come tale: `xn--pypal-login-yij.com`
        decodifica a `pаypal-login.com` con una 'a' cirillica (U+0430) fra
        lettere latine — costruito per esercitare il ramo che nessun dato
        reale del campione odierno raggiunge. Atteso: `suspicious`/HIGH,
        `rule=homoglyph_script_mixing`, MAI CRITICAL (stessa Domanda 2 del
        caso #3 — la bozza di codice parcheggiata nel registro usa ancora
        `phishing`/CRITICAL per questo ramo: è precedente alla decisione
        finale dell'utente e va corretta dal fixer, non riprodotta)."""
        r = self._classify(
            "xn--pypal-login-yij.com", fuzzer="homoglyph",
            whois={"creation_date": "2026-06-01T00:00:00"},
            dns={"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}},
        )
        assert r["auto_classification"] == "suspicious", r
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])
        assert r["rule"] == "homoglyph_script_mixing", r

    # ── Caso #6 — meccanismo primario, dormiente NON aged: DICHIARATO SINTETICO
    def test_case6_dormant_not_aged_synthetic_declared(self):
        """Nessuno dei domini reali è insieme non-aged, dormiente nel
        ciclo corrente, e con WHOIS già persistito da un ciclo precedente
        risolvente (i soli non-aged reali del campione risultano
        risolventi nell'ultimo snapshot
        osservato dal `bug-researcher` a G2). Caso SINTETICO, dichiarato:
        WHOIS non-aged noto (come da un ciclo precedente), dormiente nel
        ciclo corrente (`dns_a=False`, `dns_mx=False`). Oggi: nessuna regola
        sul fuzzer esiste, quindi il dominio cade nella coda generica
        `recent_registration_inactive`/`needs_review`/MEDIUM. Atteso dopo il
        fix: `suspicious`/HIGH via `rule=homoglyph_dormant_not_aged`."""
        r = self._classify(
            "synthetic-homoglyph-dormant.com", fuzzer="homoglyph",
            whois={"creation_date": "2026-05-01T00:00:00"},
            dns={"records": {"A": [], "MX": [], "NS": []}},
        )
        assert r["auto_classification"] == "suspicious", r
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    # ── Caso #9 — DoS `max_length` su `VariantInput.domain` ───────────────
    def test_case9_max_length_dos_guard(self):
        """Rilievo `security-reviewer`, mai implementato: `VariantInput.domain`
        (services/classifier.py:38) non ha `max_length`, e `_has_mixed_script`
        (parcheggiata, non ancora nel sorgente) itererebbe carattere per
        carattere — amplificatore di DoS non autenticato su
        `POST /classify/variant`. Oggi un dominio anomalmente lungo è
        accettato (200); atteso dopo il fix: `422` con `Field(max_length=253)`,
        coerente con `dnstwist_engine.py:38`."""
        body = {"domain": "a" * 5000 + ".com", "fuzzer": "homoglyph"}
        resp = client.post("/classify/variant", json=body)
        assert resp.status_code == 422, (
            f"dominio di 5004 caratteri accettato con status {resp.status_code}: "
            "nessun Field(max_length=...) su VariantInput.domain"
        )

    # ── Caso #10 — falso positivo Unicode (decisione tecnica del `pm`) ────
    # DICHIARATO PARZIALMENTE SINTETICO: i cinque domini sono costruiti ad
    # hoc per esercitare segni/modificatori Unicode specifici (nessuno dei
    # 30 reali li contiene); whois/dns sono sintetici (non-aged, risolvente)
    # per garantire che il blocco omografo scatti in modo deterministico.
    # Il criterio non richiede che tutti e cinque producano la STESSA regola
    # (dipende da `_has_mixed_script` post-NFKC, non ancora implementata):
    # richiede che la SEVERITÀ DI CASO sia identica per tutti e cinque —
    # "solo il nome della rule cambia" (BUG-REGISTER.md).
    def test_case10_unicode_sign_and_modifier_false_positives_synthetic(self):
        RESOLVING_NON_AGED_WHOIS = {"creation_date": "2026-06-01T00:00:00"}
        RESOLVING_DNS = {"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}}
        domains = [
            "µicrosoft-login.com",   # MICRO SIGN — resta mixed dopo NFKC (confusable genuino)
            "Ωhm-test.com",          # OHM SIGN — resta mixed dopo NFKC (confusable genuino)
            "Ångstrom-test.com",     # ANGSTROM SIGN — NFKC -> 'Å' (falso positivo corretto)
            "ℯelvin-test.com",       # SCRIPT SMALL E — NFKC -> 'e' (falso positivo corretto)
            "ʰi-test.com",           # MODIFIER LETTER SMALL H — NFKC -> 'h' (falso positivo corretto)
        ]
        for domain in domains:
            r = self._classify(domain, fuzzer="homoglyph", whois=RESOLVING_NON_AGED_WHOIS,
                                dns=RESOLVING_DNS)
            assert r["auto_classification"] == "suspicious", (domain, r)
            assert self._case_severity(r) == "HIGH", (domain, r["auto_classification"], r["rule"])

    # ── Casi #11/#12 — congelati (vecchi #5/#6 di SCO-03(fix)), verbatim ───
    RESOLVING_NOT_AGED_WHOIS = {"creation_date": "2026-06-01T00:00:00"}
    RESOLVING_DNS = {"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}}

    def test_case11_aged_homoglyph_severity_not_elevated(self):
        """Caso #11 (ex #5), congelato dal 2026-07-25: già verde SENZA alcun
        fix (regola `predates_campaign` preesistente). Riusato verbatim salvo
        il nome di dominio e la data, resi sintetici — non-regressione dichiarata,
        non falsificazione."""
        r = self._classify("fabrlkam.example", fuzzer="homoglyph",
                            whois={"creation_date": "2018-06-12T00:00:00"},
                            dns=self.RESOLVING_DNS)
        sev = self._case_severity(r)
        assert sev == "LOW", (r["auto_classification"], sev)

    def test_case12_non_homoglyph_fuzzer_control_severity_unchanged(self):
        """Caso #12 (ex #6), controllo negativo: già verde SENZA alcun fix
        (nessuna regola sul fuzzer esisteva prima di SCO-05). Riusato verbatim
        salvo il nome di dominio, reso sintetico — non-regressione dichiarata,
        non falsificazione."""
        r = self._classify("cpntoso.example", fuzzer="replacement",
                            whois=self.RESOLVING_NOT_AGED_WHOIS, dns=self.RESOLVING_DNS)
        sev = self._case_severity(r)
        assert sev == "MEDIUM", (r["auto_classification"], sev)
        assert r["rule"] == "recent_registration_inactive", r


# ═══════════════════════════════════════════════════════════════
# SCO-05 — revisione 2 del criterio (utente, 2026-08-11)
# ═══════════════════════════════════════════════════════════════
#
# Invariante che genera tutti i casi qui sotto: **il blocco omografo si attiva
# su un segnale osservato, mai sull'assenza di un segnale**, con UNA sola
# eccezione motivata, lo script-mixing — che è un'osservazione POSITIVA del
# nome, sempre integralmente disponibile, e quindi non appartiene alla classe
# di difetto «assente ≠ fallito» (CODE-01).
#
# La revisione 1 faceva scattare la regola su `not is_aged`, e `is_aged` è
# False anche quando il WHOIS è fallito o assente (services/classifier.py,
# `is_aged = age["age_days"] is not None and ...`): su intel reale questo
# eleva a HIGH domini di cui non si sa nulla.

class TestSCO05HomoglyphNoElevationWithoutSignal:
    """Casi #3 (in `TestSCO05HomoglyphSeverityCriterion` sopra), #4b e #13.

    Il caso #4b è una **guardia di non-regressione dichiarata**: contro il
    working tree attuale è VERDE per costruzione. Serve a fissare che
    l'eccezione dello script-mixing NON venga sacrificata al gate sul WHOIS —
    se il fixer implementa il gate nell'ordine sbagliato (WHOIS prima dello
    script-mixing) il caso #4 resta verde e SOLO questo diventa rosso.

    Il caso #13 era ROSSO prima del fix ed è ancorato alla forma di due
    snapshot reali distinti (nomi sintetici)."""

    def _classify(self, domain, fuzzer="homoglyph", whois=None, dns=None, http=None,
                  cert=None, collection_status=None):
        body = {"domain": domain, "fuzzer": fuzzer, "whois": whois, "dns": dns,
                "http": http, "cert": cert, "collection_status": collection_status}
        resp = client.post("/classify/variant", json=body)
        assert resp.status_code == 200, resp.text
        return resp.json()

    def _case_severity(self, result):
        from services.orchestrator import CLASSIFICATION_SEVERITY
        return CLASSIFICATION_SEVERITY.get(result["auto_classification"], "MEDIUM")

    # ── Caso #4b — script-mixing indipendente dal WHOIS ───────────────────
    # Stesso dominio SINTETICO del caso #4 (`xn--pypal-login-yij.com`,
    # decodifica `pаypal-login.com` con una 'a' cirillica U+0430 fra lettere
    # latine): nessuno degli omografi reali del campione mescola script,
    # gli `xn--` reali sono Latin Extended a script singolo.
    # DICHIARATO SINTETICO.
    def test_case4b_script_mixing_elevates_even_when_whois_is_unknown(self):
        """Le tre forme in cui il WHOIS può essere ignoto — assente, vuoto,
        e tentato-e-fallito — devono produrre tutte lo stesso esito del caso
        #4: `suspicious`/HIGH via `homoglyph_script_mixing`. Lo script-mixing
        è un'osservazione positiva del nome: non richiede il WHOIS, e il gate
        sul WHOIS non deve poterlo sopprimere.

        VERDE per costruzione contro il codice attuale (che non consulta
        affatto il WHOIS su questo ramo): guardia di non-regressione."""
        forms = [
            ("whois assente", None, None),
            ("whois vuoto", {}, None),
            ("whois tentato e fallito", {"error": "WHOIS collection timeout"},
             {"whois": True}),
        ]
        for label, whois, cs in forms:
            r = self._classify("xn--pypal-login-yij.com", whois=whois,
                               collection_status=cs)
            assert r["rule"] == "homoglyph_script_mixing", (label, r)
            assert r["auto_classification"] == "suspicious", (label, r)
            assert self._case_severity(r) == "HIGH", (label, r["auto_classification"])

    # ── Caso #13 — WHOIS riuscito ma vuoto: la forma che `collection_failed`
    #    non intercetta ────────────────────────────────────────────────────
    # Due domini con nomi sintetici, forma copiata verbatim da due snapshot
    # reali distinti:
    #   xn--ltware-iwa.example     (decodifica lïtware.example)
    #   xn--tailpi-zjb23t.example  (decodifica tailşpiɴ.example)
    # In entrambi il WHOIS è PRESENTE, con `error: null` e tutti i campi
    # (registrar/creation_date/updated_date/...) a None: `collection_failed`
    # (shared/utils.py) risponde False — raccolta "riuscita" — quindi
    # `collection_status` direbbe {"whois": False} e sul percorso
    # cache/snapshot non viene prodotto nemmeno quello. È la terza forma di
    # "non so nulla dell'età", diversa sia da "mai richiesto" sia da
    # "richiesto e fallito", e nessuna guardia la copre.
    #
    # Classificazione REALE osservata sui dati reali per entrambi:
    # `needs_review`/`no_matching_rule`.
    def test_case13_litware_whois_present_but_empty_is_not_elevated(self):
        r = self._classify(
            "xn--ltware-iwa.example",
            whois={"domain": "xn--ltware-iwa.example", "registrar": None, "creation_date": None,
                   "expiration_date": None, "updated_date": None, "status": ["AVAILABLE"],
                   "nameservers": [],
                   "registrant": {"name": None, "org": None, "country": None, "email": None},
                   "privacy_protected": True, "dnssec": False, "age_days": None,
                   "error": None},
            dns={"records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
                             "SOA": [], "CNAME": []}, "error": None},
            http={"overall_status": "down", "hidden_elements_risk": 0, "error": None,
                  "checks": [{"url": "http://xn--ltware-iwa.example", "status_code": None,
                              "content_length": 0, "hidden_elements": None,
                              "error": "blocked (SSRF protection): host does not resolve"}]},
            cert={"ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                  "error": None},
        )
        assert r["auto_classification"] == "needs_review", (
            "WHOIS riuscito ma senza creation_date: l'età è ignota, non giovane. "
            f"Nessun segnale osservato ⇒ nessuna elevazione — {r['auto_classification']}/"
            f"{r['rule']}")
        assert self._case_severity(r) == "MEDIUM", (r["auto_classification"], r["rule"])

    def test_case13_tailspin_whois_present_but_empty_is_not_elevated(self):
        """Secondo dominio, stessa forma degradata (`status: ["UNASSIGNABLE"]`
        invece di `["AVAILABLE"]`, `cert.error` valorizzato): non è una
        ripetizione dello stesso input."""
        r = self._classify(
            "xn--tailpi-zjb23t.example",
            whois={"domain": "xn--tailpi-zjb23t.example", "registrar": None, "creation_date": None,
                   "expiration_date": None, "updated_date": None,
                   "status": ["UNASSIGNABLE"], "nameservers": [],
                   "registrant": {"name": None, "org": None, "country": None, "email": None},
                   "privacy_protected": True, "dnssec": False, "age_days": None,
                   "error": None},
            dns={"records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [],
                             "SOA": [], "CNAME": []}, "error": None},
            http={"overall_status": "down", "hidden_elements_risk": 0, "error": None,
                  "checks": [{"url": "http://xn--tailpi-zjb23t.example", "status_code": None,
                              "content_length": 0, "hidden_elements": None,
                              "error": "blocked (SSRF protection): host does not resolve"}]},
            cert={"ct_certificates": {"total": 0, "unique_cn": [], "certificates": []},
                  "error": "crt.sh HTTP 502: None"},
        )
        assert r["auto_classification"] == "needs_review", (
            "WHOIS riuscito ma senza creation_date su un secondo dominio: nessun segnale "
            f"osservato ⇒ nessuna elevazione — {r['auto_classification']}/{r['rule']}")
        assert self._case_severity(r) == "MEDIUM", (r["auto_classification"], r["rule"])


class TestSCO05WhoisObservedInspectsErrorField:
    """R3 (verifier, `SCO-05` round 2, G6, 2026-08-11) — round 3, G3.

    Mutation testing round 2: il mutante M3 ("whois_observed senza
    collection_status", cioè `whois_observed = age['age_days'] is not None`,
    senza il secondo termine sul `collection_status`) è sopravvissuto —
    `407 passed`. Nessun test esistente distingue un WHOIS con
    `creation_date` valorizzata da un WHOIS con `creation_date` valorizzata
    E `error` valorizzato insieme (la forma reale prodotta da un fallback
    parziale — `whois_intel.py` scrive `creation_date` e POI `error` nello
    stesso dict quando la raccolta primaria fallisce ma un fallback CLI
    riesce a leggere la sola data).

    `whois_observed` (`services/classifier.py`) legge solo
    `age['age_days']` e `v.collection_status`, MAI `v.whois['error']`
    direttamente — pur avendo `shared.utils.collection_failed` già nel
    sistema (`orchestrator._module_failed` lo usa). Su `/classify/variant`,
    zona non autenticata per design, l'invariante "assente ≠ fallito"
    dipende quindi INTERAMENTE dalla disciplina del chiamante nel costruire
    `collection_status`: se il chiamante non lo marca (payload vuoto,
    ordine di scrittura del chiamante, o un bug a monte), un WHOIS
    genuinamente fallito viene letto come osservato."""

    def _classify(self, domain, **kw):
        body = {"domain": domain, "fuzzer": "homoglyph"}
        body.update(kw)
        resp = client.post("/classify/variant", json=body)
        assert resp.status_code == 200, resp.text
        return resp.json()

    def _case_severity(self, result):
        from services.orchestrator import CLASSIFICATION_SEVERITY
        return CLASSIFICATION_SEVERITY.get(result["auto_classification"], "MEDIUM")

    def test_whois_error_populated_alongside_creation_date_is_not_elevated(self):
        """`creation_date` E `error` valorizzati insieme, `collection_status`
        vuoto (il chiamante non l'ha marcato fallito): un WHOIS tentato e
        fallito non deve valere come segnale osservato, indipendentemente da
        cosa dichiara `collection_status`. Oggi elude la guardia ed eleva a
        `suspicious`/HIGH sul solo fatto che `age_days` non è None."""
        r = self._classify(
            "contoso-fallback-partial.example",
            whois={"creation_date": "2026-06-01T00:00:00",
                   "error": "CLI fallback: boom"},
            collection_status={},
        )
        assert r["auto_classification"] != "suspicious", (
            "creation_date presente ma affiancata da un error mai ispezionato dal "
            f"classificatore: il caso è stato elevato lo stesso — "
            f"{r['auto_classification']}/{r['rule']}")
        assert self._case_severity(r) != "HIGH", (
            r["auto_classification"], r["rule"], r["rationale"])

    def test_whois_empty_string_error_alongside_creation_date_is_not_elevated(self):
        """R3, round 4 (verifier, `SCO-05` round 3, G6, 2026-08-17) — non
        bloccante ma incluso nello stesso giro del fix R2.

        `error: ""` (stringa vuota ma PRESENTE — la forma reale prodotta da
        `sanitize_error(Exception())` quando l'eccezione non porta un
        messaggio) è distinto da `error` assente o `error` valorizzato: il
        test sopra copre solo il secondo caso. `collection_failed`
        (`shared/utils.py`) fa `if value.get("error"): return True` — una
        stringa vuota è falsy in Python, quindi il ramo non scatta e nessuno
        dei rami successivi (`virustotal`/`otx`/`securitytrails`,
        `overall_status`) copre il WHOIS: il dict con `error: ""` non conta
        come fallito, `whois_observed` diventa vero sul solo `age_days`
        valorizzato, e il caso viene elevato a `suspicious`/HIGH esattamente
        come se il WHOIS non fosse mai fallito."""
        r = self._classify(
            "tailspin-empty-error-fallback.example",
            whois={"creation_date": "2026-06-01T00:00:00", "error": ""},
            collection_status={},
        )
        assert r["auto_classification"] != "suspicious", (
            "creation_date presente ma affiancata da un error vuoto (stringa "
            f"presente, falsy) mai ispezionato correttamente dal classificatore: "
            f"il caso è stato elevato lo stesso — "
            f"{r['auto_classification']}/{r['rule']}")
        assert self._case_severity(r) != "HIGH", (
            r["auto_classification"], r["rule"], r["rationale"])


class TestSCO05HomoglyphRationaleIsBounded:
    """Caso #16. `decoded` viene interpolato nella rationale del blocco
    omografo. `decoded` è il risultato di una normalizzazione NFKC, che
    ESPANDE: `U+FDFA` (ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM) diventa 18
    caratteri. Il dominio è dato non fidato — arriva da dnstwist e
    `/classify/variant` è nella zona non autenticata per design (CLAUDE.md §1,
    vincolo 5).

    Tutti DICHIARATI SINTETICI: nessuno dei domini reali del campione contiene
    legature arabe o caratteri di controllo."""

    def _classify(self, domain, **kw):
        body = {"domain": domain, "fuzzer": "homoglyph"}
        body.update(kw)
        resp = client.post("/classify/variant", json=body)
        assert resp.status_code == 200, resp.text
        return resp.json()

    def test_nfkc_expansion_does_not_overflow_case_ingest_rationale(self):
        """Il caso deve arrivare al case-manager. `CaseIngest.rationale`
        (services/case_manager.py) è `Field(None, max_length=2000)`: una
        rationale più lunga fa rifiutare l'ingest con 422, e
        `orchestrator._ingest_cases` logga solo 401/403 — il caso viene
        **perso in silenzio**. Il tetto va applicato a `decoded` prima
        dell'interpolazione (regola di casa `_GUARD_RATIONALE_CAP`/`_cap_ioc`,
        CODE-30), non lasciato all'espansione NFKC."""
        import pytest
        from services.case_manager import CaseIngest
        from services.orchestrator import CLASSIFICATION_SEVERITY

        domain = "ﷺ" * 240 + ".com"        # 244 caratteri, sotto il max_length=253
        r = self._classify(domain, whois={"creation_date": "2026-06-01T00:00:00"})
        payload = {
            "domain": r["domain"][:253], "client": "contoso",
            "classification": r["auto_classification"],
            "confidence": r["confidence"],
            "severity": CLASSIFICATION_SEVERITY.get(r["auto_classification"], "MEDIUM"),
            "rationale": r["rationale"],
        }
        try:
            CaseIngest(**payload)
        except Exception as e:
            pytest.fail(
                f"rationale di {len(r['rationale'])} caratteri (regola {r['rule']}) "
                f"rifiutata da CaseIngest: il caso verrebbe perso in silenzio — {e}")

    def test_control_characters_from_the_domain_do_not_reach_the_rationale(self):
        """CLS-01s / `_CONTROL_CHARS` (shared/utils.py): la regola di casa è
        che nessun campo testuale costruito da input controllato dall'esterno
        porti caratteri di controllo. Qui CR/LF entrano nella rationale, che
        finisce in un evento NDJSON e nella dashboard."""
        r = self._classify("pаypal\r\n-login.com",
                           whois={"creation_date": "2026-06-01T00:00:00"})
        offenders = [c for c in r["rationale"] if ord(c) < 0x20 or ord(c) == 0x7F]
        assert not offenders, (
            f"la rationale della regola {r['rule']} riporta {len(offenders)} caratteri "
            f"di controllo copiati dal nome di dominio: {r['rationale']!r}")


class TestSCO05MixedScriptDetectionIsAboutScripts:
    """Caso #17 (R7). `_has_mixed_script` non implementa UTS #39: usa la prima
    parola di `unicodedata.name(ch)` come se fosse lo "script" del carattere.
    Non intacca la severità (tutti i rami del blocco omografo sono HIGH), ma
    sbaglia la `rule` e la rationale mostrate all'analista — cioè il "perché"
    su cui il triage decide.

    Tutti DICHIARATI SINTETICI."""

    def _classify(self, domain, **kw):
        body = {"domain": domain, "fuzzer": "homoglyph"}
        body.update(kw)
        resp = client.post("/classify/variant", json=body)
        assert resp.status_code == 200, resp.text
        return resp.json()

    def _case_severity(self, result):
        from services.orchestrator import CLASSIFICATION_SEVERITY
        return CLASSIFICATION_SEVERITY.get(result["auto_classification"], "MEDIUM")

    YOUNG_WHOIS = {"creation_date": "2026-06-01T00:00:00"}
    RESOLVING_DNS = {"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}}

    def test_japanese_multiscript_name_is_not_reported_as_script_mixing(self):
        """`日本の例.com` mescola Han e Hiragana: è giapponese ordinario, non
        confondibilità. UTS #39 tratta Latin+Han+Hiragana+Katakana come un
        profilo lecito. La severità resta HIGH (è pur sempre un omografo non
        aged con infrastruttura attiva), ma la regola non deve dichiarare una
        mescolanza di script che non c'è."""
        r = self._classify("日本の例.com", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] != "homoglyph_script_mixing", (
            "Han+Hiragana in un nome giapponese ordinario riportato come "
            f"mescolanza di script: {r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    def test_single_script_idn_with_ascii_tld_is_not_reported_as_script_mixing(self):
        """`контосо.example`: il label registrabile è interamente cirillico — un
        whole-script confusable, non un mixed-script. Oggi il TLD ASCII `com`
        basta da solo a far dichiarare la mescolanza, il che rende
        `homoglyph_script_mixing` vero per QUALUNQUE IDN monoscript sotto un
        TLD ASCII: la regola non distingue più nulla."""
        r = self._classify("контосо.example", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] != "homoglyph_script_mixing", (
            "label monoscript cirillico dichiarato mixed-script per via del solo "
            f"TLD ASCII: {r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    def test_latin_han_kana_business_name_is_not_reported_as_script_mixing(self):
        """R2 (verifier, `SCO-05` round 2, G6, 2026-08-11), riprodotto in
        proprio dal `pm`: `bicカメラ.com` (BIC CAMERA, catena reale di
        elettronica giapponese — 'bic' Latin + 'カメラ' Katakana nello
        STESSO label) è oggi dichiarato `mixed=True`. Il test
        `test_japanese_multiscript_name_is_not_reported_as_script_mixing`
        sopra copre Han+Hiragana (`日本の例.com`) ma quel dominio non
        contiene un solo carattere Latino: non esercita affatto il ramo che
        `_SCRIPT_RANGES` sbaglia, perché tiene `Latin` in un bucket separato
        da `Han/Kana`. Sotto UTS #39 *Moderately Restrictive*,
        Latin+Han+Hiragana+Katakana nello stesso identificatore è LECITO —
        `_has_mixed_script` dichiara "mai falso positivo"
        (`services/classifier.py:165-166`) e qui lo produce."""
        r = self._classify("bicカメラ.com", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] != "homoglyph_script_mixing", (
            "Latin+Katakana in un nome commerciale reale (BIC CAMERA) riportato "
            f"come mescolanza di script: {r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    def test_latin_cyrillic_confusable_is_still_detected_as_mixed_script(self):
        """Controllo negativo per il test sopra, non-negoziabile: la
        correzione di `_has_mixed_script` per Latin+Han/Kana non deve
        indebolire il rilevamento di un vero omografo Latin+Cirillico —
        quello per cui la regola esiste. `vitаmin-shop.com` ha una 'а'
        cirillica (U+0430) fra lettere latine, lo stesso pattern di
        `pаypal-login.com` (caso #4/#4b), dominio diverso per non ripetere
        esattamente lo stesso input."""
        r = self._classify("vitаmin-shop.com", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] == "homoglyph_script_mixing", (
            "un omografo Latin+Cirillico genuino non è più rilevato come "
            f"mescolanza di script dopo il ramo Latin+Han/Kana: {r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    def test_uppercase_punycode_is_decoded_like_lowercase(self):
        """I nomi DNS sono case-insensitive e dnstwist/CT/WHOIS restituiscono
        indifferentemente `xn--` e `XN--` (lo snapshot reale del caso #3
        contiene la forma maiuscola nella risposta del
        registro). Il codec `idna` della stdlib confronta il prefisso ACE
        senza normalizzare il case, quindi un label `XN--...` non viene
        decodificato affatto: il ramo mixed-script è irraggiungibile per
        input maiuscolo, e la rationale mostra l'ACE grezzo invece del nome
        Unicode che l'analista deve leggere."""
        upper = self._classify("XN--PYPAL-LOGIN-YIJ.COM")
        lower = self._classify("xn--pypal-login-yij.com")
        assert upper["rule"] == lower["rule"], (
            f"stesso dominio, case diverso, regole diverse: "
            f"{upper['rule']} vs {lower['rule']} — {upper['rationale']}")


class TestSCO05MixedScriptRestrictedException:
    """Round 4 (2026-08-17), criterio del `bug-researcher` dopo il doppio
    esito negativo del G6 di `SCO-05` round 3.

    Il `verifier` ha dimostrato (PoC `g口口gle-mail.com`) che
    `_JAPANESE_COMBINABLE_SCRIPTS` (`classifier.py:200`) esenta QUALUNQUE
    coppia Latin+Han/Kana, non solo i nomi commerciali giapponesi legittimi
    che l'aveva motivata — uno scambio falso-positivo→falso-negativo
    sfruttabile su una rotta non autenticata (`/classify/variant`). Decisione
    utente: restringere l'eccezione (approccio c del `bug-researcher`, lista
    inline di confusable Han/Kana↔Latino), non rimuoverla.

    Questi test codificano la batteria del `bug-researcher` come contratto
    OSSERVABILE: `rule == "homoglyph_script_mixing"` per un confusable a
    singolo carattere, `rule != "homoglyph_script_mixing"` per un nome
    commerciale giapponese genuino (kanji/katakana reali, nessun carattere
    della batteria confusable). Tutti i domini sono SINTETICI: nomi di
    aziende fittizie (`contoso`/`fabrikam`/`litware`/`tailspin`/`proseware`)
    o esempi tecnici — mai una forma ASCII o punycode di un
    nome cliente."""

    def _classify(self, domain, **kw):
        body = {"domain": domain, "fuzzer": "homoglyph"}
        body.update(kw)
        resp = client.post("/classify/variant", json=body)
        assert resp.status_code == 200, resp.text
        return resp.json()

    def _case_severity(self, result):
        from services.orchestrator import CLASSIFICATION_SEVERITY
        return CLASSIFICATION_SEVERITY.get(result["auto_classification"], "MEDIUM")

    YOUNG_WHOIS = {"creation_date": "2026-06-01T00:00:00"}
    RESOLVING_DNS = {"records": {"A": ["1.2.3.4"], "MX": [], "NS": ["ns1.example.com"]}}

    # ── Legittimi: l'eccezione giapponese deve continuare a valere ──

    def test_kanji_business_suffix_alias_is_not_reported_as_script_mixing(self):
        """`proseware本店.example`: 'proseware' (nome fittizio, Latin) + '本店'
        (honten, "negozio principale/sede", kanji reale) nello STESSO label.
        Nessun carattere di '本店' è nella batteria dei confusable Han/Kana
        usata dal criterio ristretto: deve restare legittimo anche dopo la
        restrizione, non solo prima."""
        r = self._classify("proseware本店.example", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] != "homoglyph_script_mixing", (
            "kanji reale, non confusable, in un alias di nome commerciale "
            f"riportato come mescolanza di script: {r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    def test_katakana_shop_suffix_alias_is_not_reported_as_script_mixing(self):
        """`tailspinショップ.example`: 'tailspin' (nome fittizio, Latin) +
        'ショップ' (shoppu, "shop", katakana reale) nello stesso label.
        Nessuno dei quattro caratteri è nella batteria dei confusable."""
        r = self._classify("tailspinショップ.example", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] != "homoglyph_script_mixing", (
            "katakana reale, non confusable, in un alias di nome commerciale "
            f"riportato come mescolanza di script: {r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    # ── Attacco: il criterio odierno (non ristretto) li esenta. Attesi ROSSI
    # finché il fix R2 non restringe l'eccezione a una lista di confusable ──

    def test_han_o_confusable_is_detected_as_script_mixing(self):
        """PoC del `verifier` (G6, `SCO-05` round 3, BLOCCANTE):
        `g口口gle-mail.com` ('口' = U+53E3, confusable visivo di 'o' minuscola)
        passa da `mixed=True` a `mixed=False` con l'eccezione
        Latin+Han/Kana non ristretta introdotta al round 3. Un carattere Han
        confusable dentro un nome altrimenti latino non è un profilo
        commerciale giapponese legittimo. Esempio tecnico dichiarato, non un
        tenant."""
        r = self._classify("g口口gle-mail.com", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] == "homoglyph_script_mixing", (
            "carattere Han confusable ('口', U+53E3) esentato dalla mescolanza "
            f"di script: {r['auto_classification']}/{r['rule']} — {r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    def test_katakana_ro_confusable_with_o_is_detected_as_script_mixing(self):
        """`fabrikamロgin.example`: 'ロ' (U+30ED, katakana 'ro') è visivamente
        confusable con la lettera latina 'o', sostituita in 'l**o**gin'.
        Nome fittizio ('fabrikam')."""
        r = self._classify("fabrikamロgin.example", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] == "homoglyph_script_mixing", (
            "carattere katakana confusable ('ロ', U+30ED) esentato dalla "
            f"mescolanza di script: {r['auto_classification']}/{r['rule']} — "
            f"{r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    def test_katakana_prolonged_mark_confusable_with_dash_is_detected_as_script_mixing(self):
        """`litwareー2.example`: 'ー' (U+30FC, katakana prolonged sound mark) è
        visivamente confusable con un trattino. Nome fittizio ('litware')."""
        r = self._classify("litwareー2.example", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] == "homoglyph_script_mixing", (
            "prolonged sound mark katakana confusable ('ー', U+30FC) esentato "
            f"dalla mescolanza di script: {r['auto_classification']}/{r['rule']} — "
            f"{r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    def test_han_yi_confusable_with_dash_is_detected_as_script_mixing(self):
        """`contoso一fabrikam.example`: '一' (U+4E00, Han "uno/one") è visivamente
        confusable con un trattino/l minuscola. Nomi fittizi ('contoso',
        'fabrikam')."""
        r = self._classify("contoso一fabrikam.example", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] == "homoglyph_script_mixing", (
            "carattere Han confusable ('一', U+4E00) esentato dalla mescolanza "
            f"di script: {r['auto_classification']}/{r['rule']} — {r['rationale']}")
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    # ── Punto B: non-regressione, già verdi oggi (il verifier li voleva
    # coperti da un test, non solo "corretti sul codice") ──

    def test_three_scripts_still_detected_as_script_mixing(self):
        """Non-regressione (punto B, `verifier` G6 round 3): un terzo script
        oltre Latin+Han/Kana fa uscire dall'eccezione per costruzione
        dell'uguaglianza d'insieme esatta — dichiarato dal fixer round 3 ma
        mai prima coperto da un test. `prosewareカбmера.example`: nome fittizio
        ('proseware') + katakana reale + cirillico (3 script nello stesso
        label)."""
        r = self._classify("prosewareカбmера.example", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] == "homoglyph_script_mixing", (
            r["auto_classification"], r["rule"], r["rationale"])
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    def test_han_kana_and_cyrillic_without_latin_still_detected_as_script_mixing(self):
        """Non-regressione (punto B): Han/Kana + Cirillico, NESSUN carattere
        Latino nel label — già fuori dalla coppia esatta dell'eccezione a
        prescindere dalla restrizione. `カメラа.com`: 'カメラ' (kamera,
        katakana reale) + 'а' cirillica (U+0430)."""
        r = self._classify("カメラа.com", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] == "homoglyph_script_mixing", (
            r["auto_classification"], r["rule"], r["rationale"])
        assert self._case_severity(r) == "HIGH", (r["auto_classification"], r["rule"])

    # ── Zona grigia dichiarata dal `bug-researcher`, limite noto accettato ──

    def test_single_non_confusable_katakana_character_remains_a_known_gap(self):
        """Zona grigia dichiarata dal `bug-researcher` per il criterio del
        round 4: un singolo carattere katakana LEGITTIMO (non nella batteria
        dei confusable) resta NON rilevato come mescolanza di script anche
        dopo la restrizione — compromesso accettato per non generare falsi
        positivi su nomi commerciali giapponesi con un solo carattere
        aggiunto. Questo test DOCUMENTA il limite, non lo contraddice: NON
        deve diventare `mixed` — se in futuro diventasse `mixed`, il
        criterio è cambiato e questo test va rivisto insieme alla decisione,
        non silenziosamente."""
        r = self._classify("contosoカ.example", whois=self.YOUNG_WHOIS, dns=self.RESOLVING_DNS)
        assert r["rule"] != "homoglyph_script_mixing", (
            "limite noto violato: un singolo katakana non-confusable è ora "
            f"trattato come mescolanza di script — {r['rationale']}")


# ═══════════════════════════════════════════════════════════════
# COL-02 (consumatori) — uno stato DNS `unknown` non è un'assenza
# ═══════════════════════════════════════════════════════════════
#
# Criteri C1-C3 di BUG-REGISTER.md («ASSEGNA · COL-02 (consumatori, secondo
# commit)»). Dopo RES-01 (nucleo) `/dns` dice, per ogni tipo di record e per
# SPF/DMARC/BIMI/CAA, se la risposta è `ok`, `nodata`, `nxdomain` o `unknown` (il
# DNS non ha risposto: SERVFAIL, REFUSED, trasporto, pacchetto non parsabile) e il
# modulo intero è «fallito» quando tutti e 7 i tipi base sono `unknown`. Il
# classificatore continua a leggere `[]` come «assente»: un SERVFAIL sul solo A di
# un dominio con A+MX produce `mx_only_no_web` (HIGH), e al ritorno il diff
# segnala l'MX o l'A «cambiato» o «aggiunto».
#
#   C1  `/diff` salta i tipi `unknown` in CORRENTE (e SPF/DMARC/BIMI/CAA con `status ==
#       "unknown"`): «il DNS non ha risposto» non è un'osservazione. Un `unknown` in
#       BASELINE, invece, è un riferimento senza valore: il primo valore noto e non
#       vuoto allerta come un cambio ordinario, una volta; noto ma vuoto (`nodata`,
#       `nxdomain`) no (SEC-31, riunificato in COL-02 con la DECISIONE del coordinator
#       «giro correttivo»). Le transizioni vere (ok -> nodata, ok -> nxdomain, nodata ->
#       ok, vecchio `[]` senza stato -> ok) allertano ancora.
#   C2  nessuna regola legge un tipo indeterminato come assente: `mx_only_*`
#       richiede A determinato; un omografo non invecchiato con A o MX indeterminato
#       e nessun record dà `homoglyph_not_aged_dns_unknown` (`suspicious`/`high`,
#       rationale che non afferma la dormienza). Le regole che scattano su un dato
#       VISTO restano quelle di prima.
#   C3  guardia CODE-23: A, MX o NS `unknown` nel payload (o `collection_status.dns`
#       vero) => `insufficient_data` salvo `suspicious`; TXT/SOA/AAAA/CNAME da soli
#       no. La guardia si deriva dal payload, non da ciò che manda il chiamante.
#       Input malformato => 200.
#
# I test «controllo» (verdi anche prima del fix) sono dichiarati nel docstring: la
# loro funzione è impedire che il fix tolga più di quanto deve (saltare un tipo
# solo perché vuoto, spegnere `mx_only_no_web` con A `nodata`, ecc.).

import pytest
from datetime import datetime, timedelta, timezone

from shared.constants import SEVERITY_MAP as _C02_SEVERITY_MAP

_C02_DOMAIN = "acme-typo.example"
_C02_BASE_RTYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
# Relativa a oggi (60 giorni), non una data fissa: una data fissa smette di essere «recente» da sola.
_C02_RECENT_WHOIS = {"creation_date": (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S")}
_C02_AGED_WHOIS = {"creation_date": "2005-03-01T00:00:00"}


def _c02_dns(records=None, unknown=(), status=None, email_auth=None):
    """Sezione `dns` come la produce `/dns` dopo RES-01: `records_status` coerente coi
    record (`ok` se ci sono, `nodata` se no), i tipi in `unknown` con record `[]` e
    stato `unknown`, `status` per forzare un esito diverso (`nxdomain`)."""
    recs = {t: [] for t in _C02_BASE_RTYPES}
    recs.update(records or {})
    st = {t: ("ok" if recs[t] else "nodata") for t in _C02_BASE_RTYPES}
    st.update(status or {})
    for t in unknown:
        recs[t] = []
        st[t] = "unknown"
    dns = {"records": recs, "records_status": st, "error": None}
    if email_auth is not None:
        dns["email_auth"] = email_auth
    return dns


def _c02_classify(dns=None, *, fuzzer="test", domain=_C02_DOMAIN, whois=None, http=None,
                  cert=None, collection_status=None):
    body = {"domain": domain, "fuzzer": fuzzer, "dns": dns, "whois": whois, "http": http,
            "cert": cert, "collection_status": collection_status}
    resp = client.post("/classify/variant", json=body)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _c02_snap(dns):
    return {"dns": dns, "cert": None, "http": None, "whois": None, "reputation": None}


def _c02_diff_payload(prev_dns, curr_dns):
    return {"domain": _C02_DOMAIN, "client": "acme", "legitimate": "acme.example",
            "baseline": _c02_snap(prev_dns), "current": _c02_snap(curr_dns)}


def _c02_diff(prev_dns, curr_dns):
    resp = client.post("/diff", json=_c02_diff_payload(prev_dns, curr_dns))
    assert resp.status_code == 200, resp.text
    return resp.json()


def _c02_alert_types(body):
    return sorted(a["type"] for a in body["alerts"])


# (tipo, alert del diff, valore prima, valore dopo): i cinque tipi che `_diff_records` confronta.
_C02_DIFF_TYPES = [
    pytest.param("A", "a_record_changed", ["192.0.2.10"], ["192.0.2.99"], id="A"),
    pytest.param("MX", "mx_record_changed", ["10 mail.acme-typo.example"], ["10 mail.other.example"], id="MX"),
    pytest.param("NS", "ns_changed", ["ns1.acme-typo.example"], ["ns1.other.example"], id="NS"),
    pytest.param("TXT", "txt_changed", ['"v=spf1 -all"'], ['"v=spf1 +all"'], id="TXT"),
    pytest.param("SOA", "soa_changed", ["ns1.acme-typo.example hostmaster.acme-typo.example 1 7200 900 1209600 3600"],
                 ["ns1.acme-typo.example hostmaster.acme-typo.example 2 7200 900 1209600 3600"], id="SOA"),
]


class TestCOL02DiffSkipsUnknownRecordTypes:
    """C1 — un tipo di record `unknown` in CORRENTE non è un'osservazione: il diff non lo
    confronta. (Il caso inverso, `unknown` in baseline, è in `TestCOL02DiffWakeUpFromAnUnknownBaseline`.)"""

    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_unknown_in_current_does_not_report_the_record_as_removed(self, rtype, alert, before, after):
        prev = _c02_dns({rtype: before})
        curr = _c02_dns({rtype: before}, unknown=(rtype,))

        assert _c02_alert_types(_c02_diff(prev, curr)) == []

    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_unknown_on_both_sides_is_silent(self, rtype, alert, before, after):
        prev = _c02_dns({rtype: before}, unknown=(rtype,))
        curr = _c02_dns(unknown=(rtype,))

        assert _c02_alert_types(_c02_diff(prev, curr)) == []

    def test_an_unknown_type_does_not_silence_a_real_change_in_another_type(self):
        prev = _c02_dns({"A": ["192.0.2.10"], "MX": ["10 mail.acme-typo.example"]})
        curr = _c02_dns({"MX": ["10 mail.other.example"]}, unknown=("A",))

        assert _c02_alert_types(_c02_diff(prev, curr)) == ["mx_record_changed"]

    def test_every_type_unknown_against_a_healthy_baseline_gives_no_alert(self):
        # Il guasto totale come lo vedrebbe un chiamante diretto di `/diff`, senza il riporto
        # dell'orchestrator: oggi sono 5 alert (A e MX HIGH, NS MEDIUM, TXT LOW, SOA INFO).
        prev = _c02_dns({"A": ["192.0.2.10"], "MX": ["10 mail.acme-typo.example"],
                         "NS": ["ns1.acme-typo.example"], "TXT": ['"v=spf1 -all"'],
                         "SOA": ["ns1.acme-typo.example hostmaster.acme-typo.example 1 7200 900 1209600 3600"]})
        curr = _c02_dns(unknown=tuple(_C02_BASE_RTYPES))

        assert _c02_alert_types(_c02_diff(prev, curr)) == []


class TestCOL02DiffTrueTransitionsStillAlert:
    """C1, controlli — verdi anche prima del fix. Il salto vale per `unknown`, non per
    «vuoto»: ciò che il DNS ha detto di non avere (`nodata`, `nxdomain`) o che prima non
    c'era è un cambiamento vero e deve allertare come sempre."""

    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_ok_to_nodata_alerts(self, rtype, alert, before, after):
        body = _c02_diff(_c02_dns({rtype: before}), _c02_dns())

        assert _c02_alert_types(body) == [alert]
        assert body["alerts"][0]["detail"] == {"old": sorted(before), "new": []}

    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_ok_to_nxdomain_alerts(self, rtype, alert, before, after):
        body = _c02_diff(_c02_dns({rtype: before}), _c02_dns(status={rtype: "nxdomain"}))

        assert _c02_alert_types(body) == [alert]

    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_nodata_to_ok_alerts(self, rtype, alert, before, after):
        body = _c02_diff(_c02_dns(), _c02_dns({rtype: after}))

        assert _c02_alert_types(body) == [alert]
        assert body["alerts"][0]["detail"] == {"old": [], "new": sorted(after)}

    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_old_snapshot_without_status_to_ok_alerts(self, rtype, alert, before, after):
        # Uno snapshot scritto prima di RES-01 non ha `records_status`: mancante vale «noto».
        legacy = {"records": {t: [] for t in _C02_BASE_RTYPES}}
        body = _c02_diff(legacy, _c02_dns({rtype: after}))

        assert _c02_alert_types(body) == [alert]

    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_ok_to_a_different_ok_value_alerts(self, rtype, alert, before, after):
        body = _c02_diff(_c02_dns({rtype: before}), _c02_dns({rtype: after}))

        assert _c02_alert_types(body) == [alert]

    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_same_ok_value_on_both_sides_is_silent(self, rtype, alert, before, after):
        assert _c02_alert_types(_c02_diff(_c02_dns({rtype: before}), _c02_dns({rtype: before}))) == []


# La sezione email come la produce `/dns`: presente, assente (nodata), non determinata.
_C02_SECTION_PRESENT = {
    "spf": {"present": True, "records": ['"v=spf1 -all"'], "policy": "fail", "status": "ok"},
    "dmarc": {"present": True, "records": ['"v=DMARC1; p=reject"'], "status": "ok"},
    "bimi": {"present": True, "records": ['"v=BIMI1; l=https://acme.example/logo.svg"'], "status": "ok"},
    "caa": {"present": True, "records": ['0 issue "letsencrypt.org"'], "status": "ok"},
}
_C02_SECTION_NODATA = {
    "spf": {"present": False, "records": [], "policy": None, "status": "nodata"},
    "dmarc": {"present": False, "records": [], "status": "nodata"},
    "bimi": {"present": False, "records": [], "status": "nodata"},
    "caa": {"present": False, "records": [], "status": "nodata"},
}
_C02_SECTION_UNKNOWN = {
    "spf": {"present": False, "records": [], "policy": None, "status": "unknown"},
    "dmarc": {"present": False, "records": [], "status": "unknown"},
    "bimi": {"present": False, "records": [], "status": "unknown"},
    "caa": {"present": False, "records": [], "status": "unknown"},
}
_C02_SECTION_ALERT = {"spf": "spf_changed", "dmarc": "dmarc_changed", "bimi": "bimi_added", "caa": "caa_changed"}
_C02_SECTIONS = list(_C02_SECTION_ALERT)


def _c02_email_dns(section, value):
    """`dns` sano per tutto il resto, con la sola sezione `section` = `value`."""
    sections = {name: _C02_SECTION_NODATA[name] for name in _C02_SECTIONS}
    sections[section] = value
    email_auth = {**sections, "dkim": {"selectors_found": [], "selectors_tested": 18, "records": {},
                                       "selectors_unknown": []}}
    return _c02_dns(email_auth=email_auth)


class TestCOL02DiffSkipsUnknownEmailAuth:
    """C1 — SPF, DMARC, BIMI e CAA con `status == "unknown"` in CORRENTE non sono
    confrontati: il guasto non è la rimozione del record. (Il caso inverso, `unknown` in
    baseline, è in `TestCOL02DiffWakeUpFromAnUnknownBaseline`.)"""

    @pytest.mark.parametrize("section", _C02_SECTIONS)
    def test_unknown_in_current_gives_no_alert(self, section):
        prev = _c02_email_dns(section, _C02_SECTION_PRESENT[section])
        curr = _c02_email_dns(section, _C02_SECTION_UNKNOWN[section])

        assert _c02_alert_types(_c02_diff(prev, curr)) == []

    @pytest.mark.parametrize("section", _C02_SECTIONS)
    def test_unknown_on_both_sides_is_silent(self, section):
        both = _c02_email_dns(section, _C02_SECTION_UNKNOWN[section])

        assert _c02_alert_types(_c02_diff(both, both)) == []


class TestCOL02DiffWakeUpFromAnUnknownBaseline:
    """C1, giro correttivo (SEC-31 riunificato in COL-02: verdetto INSUFFICIENTE del verifier e
    DECISIONE del coordinator, 2026-10-24).

    G5 — correzione, prima del commit, di test di questo stesso lavoro. La prima versione di
    questi casi (`test_unknown_in_baseline_does_not_report_...`, nelle classi `...SkipsUnknown...`)
    pretendeva SILENZIO quando la baseline era `unknown`. Il verifier ha provato che il silenzio
    cancella il risveglio: una zona vuota con due cicli di SERVFAIL e poi A+MX+NS dava 3 alert
    (A e MX HIGH, NS MEDIUM) prima di RES-01 e 0 con quel disegno, e `unknown` si può scegliere
    per tipo da chi gestisce la zona del lookalike. Il comportamento deciso: un tipo che nella
    baseline è `unknown` SENZA un valore noto precedente è un riferimento vuoto, quindi il primo
    valore noto e non vuoto produce l'alert ordinario di cambio (stesso tipo, stessa severità,
    da `[]` al valore), una volta; noto ma vuoto (`nodata`, `nxdomain`) non è un cambio. Con il
    riporto dell'orchestrator una baseline nota resta il riferimento (controlli sotto)."""

    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_first_known_non_empty_value_alerts_like_an_ordinary_change(self, rtype, alert, before, after):
        prev = _c02_dns(unknown=(rtype,))
        curr = _c02_dns({rtype: after})

        body = _c02_diff(prev, curr)

        assert [(a["type"], a["severity"], a["detail"]) for a in body["alerts"]] == [
            (alert, _C02_SEVERITY_MAP[alert], {"old": [], "new": sorted(after)})]

    def test_the_ordinary_severities_are_a_and_mx_high_and_ns_medium(self):
        # La frase della DECISIONE e del verdetto del verifier, fissata alla lettera.
        prev = _c02_dns(unknown=("A", "MX", "NS"))
        curr = _c02_dns({"A": ["192.0.2.10"], "MX": ["10 mail.acme-typo.example"], "NS": ["ns1.acme-typo.example"]})

        body = _c02_diff(prev, curr)

        assert sorted((a["type"], a["severity"]) for a in body["alerts"]) == [
            ("a_record_changed", "HIGH"), ("mx_record_changed", "HIGH"), ("ns_changed", "MEDIUM")]

    @pytest.mark.parametrize("known_status", ["nodata", "nxdomain"])
    @pytest.mark.parametrize("rtype, alert, before, after", _C02_DIFF_TYPES)
    def test_first_known_but_empty_value_is_not_a_change(self, rtype, alert, before, after, known_status):
        prev = _c02_dns(unknown=(rtype,))
        curr = _c02_dns(status={rtype: known_status})

        assert _c02_alert_types(_c02_diff(prev, curr)) == []

    def test_a_still_unknown_type_stays_silent_and_does_not_hide_the_ones_that_woke_up(self):
        prev = _c02_dns({"NS": ["ns1.acme-typo.example"]}, unknown=("A", "MX"))
        curr = _c02_dns({"MX": ["10 mail.acme-typo.example"], "NS": ["ns1.acme-typo.example"]}, unknown=("A",))

        assert _c02_alert_types(_c02_diff(prev, curr)) == ["mx_record_changed"]

    @pytest.mark.parametrize("section", _C02_SECTIONS)
    def test_first_known_present_section_alerts_like_an_ordinary_change(self, section):
        prev = _c02_email_dns(section, _C02_SECTION_UNKNOWN[section])
        curr = _c02_email_dns(section, _C02_SECTION_PRESENT[section])

        body = _c02_diff(prev, curr)

        alert = _C02_SECTION_ALERT[section]
        assert [(a["type"], a["severity"]) for a in body["alerts"]] == [(alert, _C02_SEVERITY_MAP[alert])]

    @pytest.mark.parametrize("section", _C02_SECTIONS)
    def test_first_known_absent_section_is_not_a_change(self, section):
        prev = _c02_email_dns(section, _C02_SECTION_UNKNOWN[section])
        curr = _c02_email_dns(section, _C02_SECTION_NODATA[section])

        assert _c02_alert_types(_c02_diff(prev, curr)) == []

    @pytest.mark.parametrize("section", _C02_SECTIONS)
    def test_the_carried_known_baseline_is_still_the_reference_for_sections(self, section):
        # Controllo, verde anche prima del fix: dopo il riporto la baseline porta il valore noto
        # (sezione presente) e un `unknown` in corrente non è né rimozione né aggiunta.
        prev = _c02_email_dns(section, _C02_SECTION_PRESENT[section])
        curr = _c02_email_dns(section, _C02_SECTION_UNKNOWN[section])

        assert _c02_alert_types(_c02_diff(prev, curr)) == []


class TestCOL02DiffEmailAuthTrueTransitionsStillAlert:
    """C1, controlli — verdi anche prima del fix: nodata -> presente, lo snapshot senza
    `status` e la rimozione di SPF restano segnali veri."""

    @pytest.mark.parametrize("section", _C02_SECTIONS)
    def test_nodata_to_present_alerts(self, section):
        prev = _c02_email_dns(section, _C02_SECTION_NODATA[section])
        curr = _c02_email_dns(section, _C02_SECTION_PRESENT[section])

        assert _c02_alert_types(_c02_diff(prev, curr)) == [_C02_SECTION_ALERT[section]]

    @pytest.mark.parametrize("section", _C02_SECTIONS)
    def test_section_without_status_in_an_old_snapshot_to_present_alerts(self, section):
        legacy = {k: v for k, v in _C02_SECTION_NODATA[section].items() if k != "status"}
        prev = _c02_email_dns(section, legacy)
        curr = _c02_email_dns(section, _C02_SECTION_PRESENT[section])

        assert _c02_alert_types(_c02_diff(prev, curr)) == [_C02_SECTION_ALERT[section]]

    def test_spf_present_to_nodata_alerts_as_removed(self):
        prev = _c02_email_dns("spf", _C02_SECTION_PRESENT["spf"])
        curr = _c02_email_dns("spf", _C02_SECTION_NODATA["spf"])

        body = _c02_diff(prev, curr)

        assert _c02_alert_types(body) == ["spf_changed"]
        assert body["alerts"][0]["detail"] == {"old": ['"v=spf1 -all"'], "new": []}

    @pytest.mark.parametrize("section", _C02_SECTIONS)
    def test_same_present_value_on_both_sides_is_silent(self, section):
        same = _c02_email_dns(section, _C02_SECTION_PRESENT[section])

        assert _c02_alert_types(_c02_diff(same, same)) == []


class TestCOL02MxOnlyRulesNeedADeterminedA:
    """C2 — `mx_only_no_web` e `mx_only_aged_domain` dicono «c'è posta ma nessun sito»:
    con A `unknown` non si sa se il sito c'è. Con A `nodata` o `nxdomain` sì, e le regole
    scattano come sempre."""

    MX = ["10 mx.acme-typo.example"]

    def test_mx_only_no_web_does_not_fire_when_a_is_unknown(self):
        r = _c02_classify(_c02_dns({"MX": self.MX}, unknown=("A",)), whois=_C02_RECENT_WHOIS)

        assert r["rule"] != "mx_only_no_web", r
        assert r["auto_classification"] == "insufficient_data", r

    def test_mx_only_aged_domain_does_not_fire_when_a_is_unknown(self):
        r = _c02_classify(_c02_dns({"MX": self.MX}, unknown=("A",)), whois=_C02_AGED_WHOIS)

        assert r["rule"] != "mx_only_aged_domain", r
        assert r["auto_classification"] == "insufficient_data", r

    @pytest.mark.parametrize("a_status", ["nodata", "nxdomain"])
    def test_mx_only_no_web_still_fires_when_a_is_determined_absent(self, a_status):
        # Controllo, verde anche prima del fix.
        r = _c02_classify(_c02_dns({"MX": self.MX}, status={"A": a_status}), whois=_C02_RECENT_WHOIS)

        assert (r["auto_classification"], r["rule"]) == ("suspicious", "mx_only_no_web"), r

    @pytest.mark.parametrize("a_status", ["nodata", "nxdomain"])
    def test_mx_only_aged_domain_still_fires_when_a_is_determined_absent(self, a_status):
        r = _c02_classify(_c02_dns({"MX": self.MX}, status={"A": a_status}), whois=_C02_AGED_WHOIS)

        assert (r["auto_classification"], r["rule"]) == ("needs_review", "mx_only_aged_domain"), r

    @pytest.mark.parametrize("a_status", ["nodata", "nxdomain"])
    @pytest.mark.parametrize("unknown", [("NS",), ("NS", "TXT", "SOA")], ids=["NS", "NS+TXT+SOA"])
    def test_an_unknown_ns_does_not_suppress_mx_only_no_web(self, a_status, unknown):
        # Controllo, verde anche prima del fix (rilievo del verifier di COL-02): A determinato
        # vuoto e MX visto è ancora il profilo «solo posta». Un NS indeterminato attiva la guardia,
        # ma `suspicious` la supera: «non ho potuto guardare» non zittisce «ho visto qualcosa».
        r = _c02_classify(_c02_dns({"MX": self.MX}, status={"A": a_status}, unknown=unknown),
                          whois=_C02_RECENT_WHOIS)

        assert (r["auto_classification"], r["rule"]) == ("suspicious", "mx_only_no_web"), r

    def test_mx_only_does_not_fire_when_the_whole_dns_module_failed(self):
        # `collection_status.dns` vero: A, MX e NS sono indeterminati anche se il payload
        # non porta `records_status` (modulo `None`, oltre il timeout di servizio).
        dns = {"records": {"A": [], "MX": self.MX, "NS": ["ns1.acme-typo.example"]}}

        r = _c02_classify(dns, whois=_C02_RECENT_WHOIS, collection_status={"dns": True})

        assert r["rule"] != "mx_only_no_web", r
        assert r["auto_classification"] == "insufficient_data", r

    def test_legacy_payload_without_status_keeps_the_old_reading(self):
        # Controllo: nessuno stato = noto, come per gli snapshot e i fixture di prima.
        dns = {"records": {"A": [], "MX": self.MX, "NS": ["ns1.acme-typo.example"]}}

        r = _c02_classify(dns, whois=_C02_RECENT_WHOIS)

        assert (r["auto_classification"], r["rule"]) == ("suspicious", "mx_only_no_web"), r


class TestCOL02HomoglyphWithUndeterminedDns:
    """C2 — un omografo non invecchiato resta `suspicious`/`high` anche se A o MX sono
    `unknown` e non c'è alcun record: l'HIGH viene dal nome e dall'età, non dal DNS, e chi
    controlla il DNS del lookalike non deve poterlo far scendere con un SERVFAIL. La
    rationale non può però dire «dormiente»: non si sa se lo sia."""

    DOMAIN = "synthetic-homoglyph-dormant.com"

    def _classify(self, dns, **kwargs):
        kwargs.setdefault("whois", _C02_RECENT_WHOIS)
        return _c02_classify(dns, fuzzer="homoglyph", domain=self.DOMAIN, **kwargs)

    @pytest.mark.parametrize("unknown", [("A",), ("MX",), ("A", "MX")], ids=["A", "MX", "A+MX"])
    def test_a_or_mx_unknown_and_no_record_gives_the_dedicated_high_rule(self, unknown):
        r = self._classify(_c02_dns(unknown=unknown))

        assert (r["auto_classification"], r["confidence"], r["rule"]) == (
            "suspicious", "high", "homoglyph_not_aged_dns_unknown"), r

    @pytest.mark.parametrize("unknown", [("A",), ("MX",), ("A", "MX")], ids=["A", "MX", "A+MX"])
    def test_the_rationale_does_not_claim_the_domain_is_dormant(self, unknown):
        r = self._classify(_c02_dns(unknown=unknown))

        assert r["rule"] == "homoglyph_not_aged_dns_unknown", r
        assert "dormient" not in r["rationale"].lower(), r["rationale"]

    def test_dns_module_failed_gives_the_dedicated_high_rule(self):
        r = self._classify(None, collection_status={"dns": True})

        assert (r["auto_classification"], r["confidence"], r["rule"]) == (
            "suspicious", "high", "homoglyph_not_aged_dns_unknown"), r

    def test_dormant_rule_is_unchanged_when_both_a_and_mx_are_determined_empty(self):
        # Controllo, verde anche prima del fix: nodata/nxdomain sono risposte.
        r = self._classify(_c02_dns(status={"A": "nxdomain", "MX": "nodata"}))

        assert (r["auto_classification"], r["rule"]) == ("suspicious", "homoglyph_dormant_not_aged"), r

    @pytest.mark.parametrize("dns", [
        pytest.param(_c02_dns({"MX": ["10 mx.acme-typo.example"]}, unknown=("A",)), id="MX-seen-A-unknown"),
        pytest.param(_c02_dns({"A": ["192.0.2.10"]}, unknown=("MX",)), id="A-seen-MX-unknown"),
    ])
    def test_a_record_that_was_seen_keeps_the_resolving_rule(self, dns):
        # Controllo, verde anche prima del fix: una regola su un dato visto non cambia.
        r = self._classify(dns)

        assert (r["auto_classification"], r["rule"]) == ("suspicious", "homoglyph_resolving"), r

    def test_script_mixing_still_wins_over_an_undetermined_dns(self):
        # Controllo, verde anche prima del fix: lo script-mixing è un'osservazione del nome.
        r = _c02_classify(_c02_dns(unknown=("A", "MX")), fuzzer="homoglyph",
                          domain="xn--pypal-login-yij.com", whois=_C02_RECENT_WHOIS)

        assert (r["auto_classification"], r["rule"]) == ("suspicious", "homoglyph_script_mixing"), r

    def test_unknown_age_is_still_not_elevated_even_with_an_undetermined_dns(self):
        # Revisione 2 di SCO-05: nessuna elevazione senza un segnale osservato. WHOIS ignoto
        # + DNS ignoto = nessuna informazione: l'esito è la guardia di raccolta, non un HIGH.
        r = self._classify(_c02_dns(unknown=("A", "MX")), whois=None)

        assert r["auto_classification"] == "insufficient_data", r


class TestCOL02CollectionGuardReadsDnsFromThePayload:
    """C3 — la guardia di raccolta (CODE-23) conta il DNS fra le sezioni fallite quando A,
    MX o NS sono `unknown`, leggendolo dal payload: non dipende da ciò che manda il
    chiamante in `collection_status`. TXT, SOA, AAAA e CNAME `unknown` da soli non bastano,
    perché nessuna regola li legge."""

    def _plain(self, **kwargs):
        """Un dominio senza segnali: con DNS determinato è `needs_review`/`no_matching_rule`."""
        dns = kwargs.pop("dns", None) or _c02_dns({"A": ["192.0.2.10"], "NS": ["ns1.acme-typo.example"]})
        return _c02_classify(dns, **kwargs)

    def test_control_without_unknown_the_plain_domain_is_needs_review(self):
        r = self._plain()

        assert (r["auto_classification"], r["rule"]) == ("needs_review", "no_matching_rule"), r

    @pytest.mark.parametrize("dns", [
        # Ogni payload porta un solo tipo base `unknown` e nessun record che attivi una regola
        # (niente MX senza A: scatterebbe `mx_only_no_web`), così il solo effetto è la guardia.
        pytest.param(_c02_dns({"NS": ["ns1.acme-typo.example"]}, unknown=("A",)), id="A"),
        pytest.param(_c02_dns({"A": ["192.0.2.10"], "NS": ["ns1.acme-typo.example"]}, unknown=("MX",)), id="MX"),
        pytest.param(_c02_dns({"A": ["192.0.2.10"]}, unknown=("NS",)), id="NS"),
    ])
    def test_unknown_a_mx_or_ns_turns_a_non_suspicious_verdict_into_insufficient_data(self, dns):
        r = _c02_classify(dns)

        assert (r["auto_classification"], r["rule"]) == ("insufficient_data", "module_collection_failed"), r
        assert "dns" in r["rationale"], r["rationale"]

    @pytest.mark.parametrize("rtype", ["AAAA", "TXT", "SOA", "CNAME"])
    def test_unknown_txt_soa_aaaa_or_cname_alone_does_not_activate_the_guard(self, rtype):
        r = self._plain(dns=_c02_dns({"A": ["192.0.2.10"], "NS": ["ns1.acme-typo.example"]}, unknown=(rtype,)))

        assert (r["auto_classification"], r["rule"]) == ("needs_review", "no_matching_rule"), r

    @pytest.mark.parametrize("status", ["ok", "nodata", "nxdomain"])
    def test_determined_statuses_do_not_activate_the_guard(self, status):
        r = self._plain(dns=_c02_dns({"A": ["192.0.2.10"], "NS": ["ns1.acme-typo.example"]},
                                     status={"MX": status, "AAAA": status, "TXT": status}))

        assert (r["auto_classification"], r["rule"]) == ("needs_review", "no_matching_rule"), r

    @pytest.mark.parametrize("collection_status", [None, {}, {"dns": False}, {"cert": False}],
                             ids=["none", "empty", "dns-false", "other-section"])
    def test_guard_is_derived_from_the_payload_whatever_the_caller_sends(self, collection_status):
        dns = _c02_dns({"A": ["192.0.2.10"]}, unknown=("NS",))

        r = _c02_classify(dns, collection_status=collection_status)

        assert (r["auto_classification"], r["rule"]) == ("insufficient_data", "module_collection_failed"), r

    @pytest.mark.parametrize("dns", [
        pytest.param(None, id="dns-null"),
        pytest.param({"records": {"A": ["192.0.2.10"], "MX": [], "NS": ["ns1.acme-typo.example"]}},
                     id="dns-without-status"),
    ])
    def test_collection_status_dns_true_activates_the_guard(self, dns):
        r = _c02_classify(dns, collection_status={"dns": True})

        assert (r["auto_classification"], r["rule"]) == ("insufficient_data", "module_collection_failed"), r

    def test_total_failure_shape_alone_activates_the_guard(self):
        # Tutti e 7 `unknown` più `error`: la forma che `/dns` produce quando il DNS non risponde.
        dns = _c02_dns(unknown=tuple(_C02_BASE_RTYPES))
        dns["error"] = "DNS resolution failed: no base record type could be resolved"

        r = _c02_classify(dns)

        assert (r["auto_classification"], r["rule"]) == ("insufficient_data", "module_collection_failed"), r

    def test_a_legitimate_looking_site_with_an_unknown_mx_is_not_called_legitimate(self):
        # `legitimate_probable` dice «tutto a posto»: con l'MX ignoto non si può dire.
        http = {"checks": [{"url": "http://acme-typo.example", "status_code": 200, "content_length": 45000,
                            "hidden_elements": {"risk_indicators": 0, "summary": []}}], "overall_status": "active"}
        control = _c02_classify(_c02_dns({"A": ["192.0.2.10"], "NS": ["ns1.acme-typo.example"]}), http=http)
        assert control["auto_classification"] == "legitimate_probable", control

        r = _c02_classify(_c02_dns({"A": ["192.0.2.10"], "NS": ["ns1.acme-typo.example"]}, unknown=("MX",)),
                          http=http)

        assert r["auto_classification"] == "insufficient_data", r

    @pytest.mark.parametrize("dns, rule", [
        pytest.param(_c02_dns({"A": ["192.0.2.10"], "NS": ["ns1.sedoparking.com"]}, unknown=("MX",)),
                     "known_parking_ns", id="parking-ns-seen-mx-unknown"),
        pytest.param(_c02_dns({"A": ["15.197.148.33"], "NS": ["ns1.acme-typo.example"]}, unknown=("MX",)),
                     "known_parking_ip", id="parking-ip-seen-mx-unknown"),
        pytest.param(_c02_dns({"A": ["192.0.2.10"], "NS": ["ns1.brandbucket.com"]}, unknown=("MX",)),
                     "marketplace_ns", id="marketplace-ns-seen-mx-unknown"),
        pytest.param(_c02_dns({"A": ["192.0.2.10"], "MX": ["10 park-mx.above.com"]}, unknown=("NS",)),
                     "parking_mx", id="parking-mx-seen-ns-unknown"),
    ])
    def test_the_rule_that_matched_a_seen_record_is_still_named_by_the_guard(self, dns, rule):
        # Le regole su un dato visto (parking NS/IP, marketplace, MX di parking) restano quelle
        # di prima: poi la guardia declassa il verdetto, e la rationale dice quale regola sarebbe
        # scattata (CODE-30). Non diventano «assenza di segnale».
        r = _c02_classify(dns)

        assert r["auto_classification"] == "insufficient_data", r
        assert rule in r["rationale"], r["rationale"]

    @pytest.mark.parametrize("dns, http, whois, rule", [
        pytest.param(_c02_dns({"MX": ["10 mail.protonmail.ch"]}, unknown=("A",)), None, _C02_RECENT_WHOIS,
                     "privacy_mx_provider", id="privacy-mx-seen-a-unknown"),
        pytest.param(_c02_dns({"A": ["192.0.2.10"], "MX": ["10 mx1.protonmail.ch"]}, unknown=("NS",)),
                     None, _C02_RECENT_WHOIS, "privacy_mx_provider", id="privacy-mx-seen-ns-unknown"),
        pytest.param(_c02_dns({"MX": ["10 mx.forwardemail.net"]}, unknown=("A",)), None, _C02_RECENT_WHOIS,
                     "forwarding_mx", id="forwarding-mx-seen-a-unknown"),
        pytest.param(_c02_dns({"A": ["192.0.2.10"]}, unknown=("MX",)),
                     {"checks": [{"url": "http://acme-typo.example", "status_code": 200, "content_length": 5000,
                                  "hidden_elements": {"risk_indicators": 35, "summary": ["1 form nascosti"]}}],
                      "overall_status": "active"}, _C02_RECENT_WHOIS,
                     "hidden_elements_detected", id="hidden-elements-seen-mx-unknown"),
    ])
    def test_suspicious_verdicts_on_seen_data_survive_the_dns_guard(self, dns, http, whois, rule):
        # `suspicious` è l'unico esito che sopravvive alla guardia (CODE-23): «non ho potuto
        # guardare» non zittisce «ho visto qualcosa di brutto».
        r = _c02_classify(dns, http=http, whois=whois)

        assert (r["auto_classification"], r["rule"]) == ("suspicious", rule), r


class TestCOL02MalformedDnsStatusIsHandled:
    """C3 — `records_status` e `status` arrivano da altri servizi e da file su disco: una
    forma imprevista non può fare un 500. Una forma che non è un dizionario di stati vale
    «nessuno stato» (= noto), come per gli snapshot di prima di RES-01. Verdi anche prima
    del fix: sono la rete contro un fix che legga lo stato senza guardarlo."""

    _api = TestClient(app, raise_server_exceptions=False)

    MALFORMED_STATUS = [
        pytest.param([], id="list-empty"),
        pytest.param(["A", "unknown"], id="list"),
        pytest.param("unknown", id="string"),
        pytest.param(None, id="null"),
        pytest.param(5, id="int"),
        pytest.param({"A": ["unknown"]}, id="unhashable-value"),
        pytest.param({"A": {"x": "unknown"}}, id="dict-value"),
        pytest.param({"A": None, "MX": 5}, id="odd-values"),
        pytest.param({f"TYPE{i}": "unknown" for i in range(5000)}, id="huge"),
    ]

    @pytest.mark.parametrize("status", MALFORMED_STATUS)
    def test_classify_survives_a_malformed_records_status(self, status):
        dns = {"records": {"A": ["192.0.2.10"], "MX": [], "NS": ["ns1.acme-typo.example"]}, "records_status": status}

        resp = self._api.post("/classify/variant", json={"domain": _C02_DOMAIN, "fuzzer": "test", "dns": dns})

        assert resp.status_code == 200, resp.text[:200]
        assert resp.json()["auto_classification"], resp.text[:200]

    @pytest.mark.parametrize("status", [s for s in MALFORMED_STATUS if s.id not in ("huge", "dict-value",
                                                                                   "unhashable-value", "odd-values")])
    def test_a_records_status_that_is_not_a_dict_of_states_reads_as_known(self, status):
        dns = {"records": {"A": ["192.0.2.10"], "MX": [], "NS": ["ns1.acme-typo.example"]}, "records_status": status}

        r = _c02_classify(dns)

        assert (r["auto_classification"], r["rule"]) == ("needs_review", "no_matching_rule"), r

    @pytest.mark.parametrize("status", MALFORMED_STATUS)
    def test_diff_survives_a_malformed_records_status_on_either_side(self, status):
        good = _c02_dns({"A": ["192.0.2.10"]})
        bad = {**good, "records_status": status}

        for prev, curr in ((good, bad), (bad, good), (bad, bad)):
            resp = self._api.post("/diff", json=_c02_diff_payload(prev, curr))
            assert resp.status_code == 200, resp.text[:200]

    @pytest.mark.parametrize("status", [None, 5, ["unknown"], {"x": "unknown"}, "UNKNOWN", ""],
                             ids=["null", "int", "list", "dict", "uppercase", "empty"])
    def test_diff_survives_a_malformed_email_section_status(self, status):
        section = {"present": True, "records": ['"v=DMARC1; p=reject"'], "status": status}
        prev = _c02_dns(email_auth={"dmarc": section})
        curr = _c02_dns(email_auth={"dmarc": {"present": False, "records": [], "status": status}})

        resp = self._api.post("/diff", json=_c02_diff_payload(prev, curr))

        assert resp.status_code == 200, resp.text[:200]


# ═══════════════════════════════════════════════════════════════
# COL-12 — un dato DNS riportato non vale per sempre
# ═══════════════════════════════════════════════════════════════
#
# Criteri C7-C9 di BUG-REGISTER.md («ASSEGNA · COL-12 · criteri di accettazione»). Dopo il
# riporto per parte di COL-02 l'orchestrator salva, per ogni parte del `dns` che in questo
# ciclo è `unknown`, il valore del ciclo precedente. COL-12 aggiunge nello snapshot un
# marcatore `dns.carried_over = {parte: {"observed_at", "carried_at"}}` (istante
# dell'ultima osservazione reale; istante del ciclo che l'ha riportata) e questo `/diff`
# lo legge: due alert nuovi, al più uno per tipo per diff,
#
#   dns_stale_core   MEDIUM   parti A, MX, NS
#   dns_stale_other  LOW      parti AAAA, TXT, SOA, CNAME, spf, dmarc, bimi, caa
#
# quando l'età di una parte (`carried_at - observed_at`, letta dal solo marcatore: nessun
# orologio nel classificatore) attraversa le 72 h. Una volta per serie: scatta se la baseline
# è sotto soglia e il corrente è >= soglia. `observed_at` null = età infinita. Una parte non
# riportata ha età 0. Il payload di `/diff` arriva dalla zona NON autenticata, quindi
# messaggio e dettaglio possono contenere solo nomi dell'elenco e istanti ri-serializzati
# dal parse, mai stringhe del payload.
#
#   C7  alert una tantum, per gruppo, `observed_at` null, `max_severity`
#   C8  marcatore malformato (corrente o baseline): nessuna eccezione, nessun alert per
#       quelle voci, nessuna stringa grezza negli alert
#   C9  gli alert esistenti non cambiano con e senza marcatore; al ritorno del DNS escono
#       gli alert ordinari di cambio
#
# Un test «nessun alert per questa voce» sarebbe stato verde anche prima del fix, quando il
# classificatore ignorava il marcatore e non emetteva mai nulla: per questo ogni voce che non deve
# alertare sta accanto a una voce valida dello stesso gruppo che DEVE alertare, e si pretende che
# l'alert elenchi solo quella (`parts`). Così il test era rosso senza la funzione e resta
# discriminante dopo il fix. Fanno eccezione, dichiarati, i controlli che non hanno una voce valida
# a cui affiancarsi (marcatore intero che non è un dict, baseline illeggibile) e i C9: verdi
# anche prima del fix, fissano ciò che il fix non deve toccare. Dove il criterio non dice che
# cosa fare di un input (es. `observed_at` illeggibile ma non null) il test asserisce solo il
# 200, la voce valida accanto e l'assenza di stringhe grezze.

import re

_C12_T0 = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
_C12_THRESHOLD = timedelta(hours=72)
_C12_JUST_UNDER = _C12_THRESHOLD - timedelta(microseconds=1)
_C12_CORE = ["A", "MX", "NS"]
_C12_OTHER = ["AAAA", "TXT", "SOA", "CNAME", "spf", "dmarc", "bimi", "caa"]
_C12_STALE_TYPES = ("dns_stale_core", "dns_stale_other")
_C12_ABSENT = object()   # chiave `carried_over` assente (diverso da `carried_over: null`)
_C12_API = TestClient(app, raise_server_exceptions=False)


def _c12_entry(age, observed=_C12_T0):
    """Voce del marcatore: osservata a `observed`, riportata `age` più tardi."""
    return {"observed_at": observed.isoformat(), "carried_at": (observed + age).isoformat()}


def _c12_unobserved(carried_at=_C12_T0 + timedelta(hours=1)):
    """Voce di una parte riportata senza istante di osservazione noto (età infinita)."""
    return {"observed_at": None, "carried_at": carried_at.isoformat()}


_C12_OLD = _c12_entry(timedelta(hours=96))   # oltre la soglia, la voce valida che deve alertare


def _c12_zone(carried=_C12_ABSENT):
    """`dns` identico sui due lati del diff, come lo lascia il riporto (valori e stati
    copiati): l'unica differenza fra baseline e corrente è il marcatore."""
    dns = _c02_dns(
        {"A": ["192.0.2.10"], "AAAA": ["2001:db8::10"], "MX": ["10 mail.acme-typo.example"],
         "NS": ["ns1.acme-typo.example"], "TXT": ['"v=spf1 -all"'], "CNAME": ["target.acme-typo.example"],
         "SOA": ["ns1.acme-typo.example hostmaster.acme-typo.example 1 7200 900 1209600 3600"]},
        email_auth={**_C02_SECTION_PRESENT, "dkim": {"selectors_found": [], "selectors_tested": 18,
                                                      "records": {}, "selectors_unknown": []}})
    if carried is not _C12_ABSENT:
        dns["carried_over"] = carried
    return dns


def _c12_post(prev_dns, curr_dns):
    resp = _C12_API.post("/diff", json=_c02_diff_payload(prev_dns, curr_dns))
    assert resp.status_code == 200, resp.text[:300]
    return resp.json()


def _c12_diff(baseline=_C12_ABSENT, current=_C12_ABSENT):
    """`/diff` fra due zone uguali che differiscono solo per il valore di `carried_over`."""
    return _c12_post(_c12_zone(baseline), _c12_zone(current))


def _c12_stale(body):
    """Gli alert `dns_stale_*` di un diff, per tipo. Più di uno per tipo è già un errore."""
    found = {}
    for alert in body["alerts"]:
        if alert["type"] in _C12_STALE_TYPES:
            assert alert["type"] not in found, f"{alert['type']} emesso più volte: {body['alerts']}"
            found[alert["type"]] = alert
    return found


def _c12_core_parts(body):
    """Le parti dell'unico `dns_stale_core` del diff; l'alert deve esserci."""
    stale = _c12_stale(body)
    assert "dns_stale_core" in stale, body["alerts"]
    return stale["dns_stale_core"]["detail"]["parts"]


class TestCOL12StaleAlertOnThresholdCrossing:
    """C7 — una parte riportata attraversa le 72 h: un alert, nel gruppo giusto, con la severità
    giusta, che elenca solo le parti che hanno attraversato in questo diff."""

    @pytest.mark.parametrize("part", _C12_CORE)
    def test_a_core_part_reaching_72_hours_alerts_medium(self, part):
        body = _c12_diff(current={part: _c12_entry(_C12_THRESHOLD)})

        stale = _c12_stale(body)
        assert list(stale) == ["dns_stale_core"], body["alerts"]
        alert = stale["dns_stale_core"]
        assert alert["severity"] == "MEDIUM"
        assert alert["detail"]["parts"] == [part]
        assert re.search(rf"\b{part}\b", alert["message"]), alert["message"]
        assert (body["alert_count"], body["max_severity"]) == (1, "MEDIUM")

    @pytest.mark.parametrize("part", _C12_OTHER)
    def test_any_other_part_reaching_72_hours_alerts_low(self, part):
        body = _c12_diff(current={part: _c12_entry(_C12_THRESHOLD)})

        stale = _c12_stale(body)
        assert list(stale) == ["dns_stale_other"], body["alerts"]
        alert = stale["dns_stale_other"]
        assert alert["severity"] == "LOW"
        assert alert["detail"]["parts"] == [part]
        assert re.search(rf"\b{part}\b", alert["message"]), alert["message"]
        assert (body["alert_count"], body["max_severity"]) == (1, "LOW")

    @pytest.mark.parametrize("age", [
        pytest.param(timedelta(0), id="zero"),
        pytest.param(timedelta(hours=24), id="24h"),
        pytest.param(timedelta(hours=48), id="48h"),
        pytest.param(timedelta(hours=71, minutes=59), id="71h59m"),
        pytest.param(timedelta(hours=71, minutes=59, seconds=59), id="71h59m59s"),
        pytest.param(_C12_JUST_UNDER, id="one-microsecond-under"),
        pytest.param(timedelta(hours=-5), id="carried-before-observed"),
    ])
    def test_a_part_under_the_threshold_gives_no_alert(self, age):
        # MX, oltre la soglia, alerta; A (stesso gruppo) e dmarc (altro gruppo) sono sotto e non
        # compaiono: non nell'elenco di `dns_stale_core`, e nessun `dns_stale_other`.
        body = _c12_diff(current={"A": _c12_entry(age), "dmarc": _c12_entry(age), "MX": _C12_OLD})

        assert list(_c12_stale(body)) == ["dns_stale_core"], body["alerts"]
        assert _c12_core_parts(body) == ["MX"]

    @pytest.mark.parametrize("age", [
        pytest.param(_C12_THRESHOLD, id="exactly-72h"),
        pytest.param(_C12_THRESHOLD + timedelta(microseconds=1), id="one-microsecond-over"),
        pytest.param(timedelta(hours=100), id="100h"),
        pytest.param(timedelta(days=3650), id="ten-years"),
    ])
    def test_a_part_at_or_over_the_threshold_alerts(self, age):
        body = _c12_diff(current={"MX": _c12_entry(age)})

        assert _c12_core_parts(body) == ["MX"]

    @pytest.mark.parametrize("baseline_age", [
        pytest.param(timedelta(0), id="baseline-age-0"),
        pytest.param(timedelta(hours=24), id="baseline-24h"),
        pytest.param(timedelta(hours=71, minutes=59, seconds=59), id="baseline-71h59m59s"),
        pytest.param(_C12_JUST_UNDER, id="baseline-one-microsecond-under"),
    ])
    def test_the_alert_fires_when_the_baseline_was_under_the_threshold(self, baseline_age):
        body = _c12_diff(baseline={"A": _c12_entry(baseline_age)}, current={"A": _c12_entry(_C12_THRESHOLD)})

        assert _c12_core_parts(body) == ["A"]

    @pytest.mark.parametrize("baseline", [
        pytest.param(_c12_entry(_C12_THRESHOLD), id="baseline-exactly-72h"),
        pytest.param(_c12_entry(timedelta(hours=100)), id="baseline-100h"),
        pytest.param(_c12_unobserved(), id="baseline-observed-at-null"),
    ])
    def test_no_repeat_when_the_baseline_was_already_over_the_threshold(self, baseline):
        # A era già oltre in baseline e resta oltre: niente. MX attraversa adesso: solo lui.
        body = _c12_diff(baseline={"A": baseline, "MX": _c12_entry(timedelta(hours=48))},
                         current={"A": _c12_entry(timedelta(hours=124)), "MX": _c12_entry(timedelta(hours=96))})

        assert _c12_core_parts(body) == ["MX"]

    def test_a_part_with_no_observed_at_counts_as_infinitely_old(self):
        body = _c12_diff(current={"A": _c12_unobserved()})

        assert _c12_core_parts(body) == ["A"]

    def test_a_part_with_no_observed_at_does_not_repeat_when_the_baseline_had_it_too(self):
        body = _c12_diff(baseline={"A": _c12_unobserved(), "MX": _c12_entry(timedelta(hours=48))},
                         current={"A": _c12_unobserved(), "MX": _C12_OLD})

        assert _c12_core_parts(body) == ["MX"]

    def test_the_series_is_over_when_the_part_is_observed_again_and_a_new_one_alerts_again(self):
        # Baseline vecchia di 100 h e corrente giovane: la serie è ripartita da un'osservazione
        # nuova (nessun alert per A). Da lì, attraversando di nuovo la soglia, l'alert esce di nuovo.
        later = _C12_T0 + timedelta(hours=100)
        restarted = _c12_entry(timedelta(hours=24), observed=later)
        crossing = _c12_entry(_C12_THRESHOLD, observed=later)

        during = _c12_diff({"A": _c12_entry(timedelta(hours=100)), "MX": _c12_entry(timedelta(hours=48))},
                           {"A": restarted, "MX": _C12_OLD})
        assert _c12_core_parts(during) == ["MX"]

        again = _c12_diff({"A": restarted}, {"A": crossing})
        assert _c12_core_parts(again) == ["A"]

    def test_a_part_not_carried_in_the_baseline_counts_as_age_zero(self):
        body = _c12_diff(baseline={"MX": _c12_entry(timedelta(hours=100))}, current={"A": _c12_entry(_C12_THRESHOLD)})

        assert _c12_core_parts(body) == ["A"]

    def test_parts_of_the_same_group_crossing_together_make_one_alert_that_lists_them(self):
        body = _c12_diff(current={p: _c12_entry(timedelta(hours=96)) for p in _C12_CORE})

        assert list(_c12_stale(body)) == ["dns_stale_core"] and body["alert_count"] == 1, body["alerts"]
        alert = _c12_stale(body)["dns_stale_core"]
        assert alert["detail"]["parts"] == ["A", "MX", "NS"]
        for part in _C12_CORE:
            assert re.search(rf"\b{part}\b", alert["message"]), alert["message"]

    def test_all_the_other_parts_crossing_together_make_one_alert(self):
        body = _c12_diff(current={p: _c12_entry(timedelta(hours=96)) for p in _C12_OTHER})

        stale = _c12_stale(body)
        assert list(stale) == ["dns_stale_other"] and body["alert_count"] == 1, body["alerts"]
        parts = stale["dns_stale_other"]["detail"]["parts"]
        assert sorted(parts) == sorted(_C12_OTHER) and len(set(parts)) == len(parts)
        assert parts == sorted(parts), "`parts` è la lista ordinata (stabile fra un diff e l'altro)"

    def test_the_alert_lists_only_the_parts_that_crossed_in_this_diff(self):
        # A attraversa ora; MX era già oltre la soglia in baseline: non rientra nell'alert.
        body = _c12_diff(
            baseline={"A": _c12_entry(timedelta(hours=48)), "MX": _c12_entry(timedelta(hours=100))},
            current={"A": _c12_entry(timedelta(hours=72)), "MX": _c12_entry(timedelta(hours=124))})

        assert _c12_core_parts(body) == ["A"]
        assert not re.search(r"\bMX\b", _c12_stale(body)["dns_stale_core"]["message"])

    def test_the_message_does_not_name_a_part_that_did_not_cross(self):
        body = _c12_diff(current={"A": _c12_entry(timedelta(hours=96)), "MX": _c12_entry(timedelta(hours=24))})

        message = _c12_stale(body)["dns_stale_core"]["message"]
        assert re.search(r"\bA\b", message) and not re.search(r"\bMX\b", message), message

    def test_core_and_other_parts_crossing_together_make_one_alert_each(self):
        body = _c12_diff(current={"A": _c12_entry(timedelta(hours=96)), "spf": _c12_entry(timedelta(hours=96))})

        stale = _c12_stale(body)
        assert sorted(stale) == ["dns_stale_core", "dns_stale_other"], body["alerts"]
        assert (stale["dns_stale_core"]["severity"], stale["dns_stale_other"]["severity"]) == ("MEDIUM", "LOW")
        assert stale["dns_stale_core"]["detail"]["parts"] == ["A"]
        assert stale["dns_stale_other"]["detail"]["parts"] == ["spf"]
        assert body["max_severity"] == "MEDIUM"

    def test_an_empty_marker_gives_no_alert(self):
        # Controllo, verde anche prima del fix: nessuna voce valida a cui affiancarsi.
        assert _c12_stale(_c12_diff(baseline={}, current={})) == {}


class TestCOL12StaleAlertSeverity:
    """C7 — i due tipi sono in `SEVERITY_MAP` e `max_severity` li conta come dichiarato (senza la
    voce nella mappa `_alert` assegna MEDIUM ma `max_severity` ripiega su LOW)."""

    def test_the_severity_map_declares_both_types(self):
        assert _C02_SEVERITY_MAP.get("dns_stale_core") == "MEDIUM"
        assert _C02_SEVERITY_MAP.get("dns_stale_other") == "LOW"

    def test_max_severity_counts_medium_for_a_lone_dns_stale_core(self):
        body = _c12_diff(current={"NS": _C12_OLD})

        assert body["max_severity"] == "MEDIUM", body

    def test_max_severity_counts_low_for_a_lone_dns_stale_other(self):
        body = _c12_diff(current={"caa": _C12_OLD})

        assert body["max_severity"] == "LOW", body

    def test_dns_stale_core_outranks_a_low_alert_in_the_same_diff(self):
        prev = _c12_zone()
        curr = _c12_zone({"A": _C12_OLD})
        curr["records"]["TXT"] = ['"v=spf1 +all"']          # txt_changed è LOW

        body = _c12_post(prev, curr)

        assert sorted(a["type"] for a in body["alerts"]) == ["dns_stale_core", "txt_changed"]
        assert body["max_severity"] == "MEDIUM"

    def test_dns_stale_other_outranks_an_info_alert_in_the_same_diff(self):
        prev = _c12_zone()
        curr = _c12_zone({"dmarc": _C12_OLD})
        curr["records"]["SOA"] = ["ns1.acme-typo.example hostmaster.acme-typo.example 2 7200 900 1209600 3600"]

        body = _c12_post(prev, curr)

        assert sorted(a["type"] for a in body["alerts"]) == ["dns_stale_other", "soa_changed"]
        assert body["max_severity"] == "LOW"

    def test_a_stale_part_does_not_hide_a_real_change_in_another_type(self):
        prev = _c12_zone()
        curr = _c12_zone({"A": _C12_OLD})
        curr["records"]["MX"] = ["10 mail.other.example"]

        body = _c12_post(prev, curr)

        assert sorted(a["type"] for a in body["alerts"]) == ["dns_stale_core", "mx_record_changed"]
        assert body["max_severity"] == "HIGH"


class TestCOL12StaleMarkerRobustness:
    """C8 — il marcatore arriva dalla zona non autenticata (`/diff`) e dai file su disco. Una
    forma imprevista non fa un 500, non produce alert per quelle voci e non finisce negli alert.
    Ogni voce malformata sta accanto a `MX` valido, che deve alertare da solo."""

    SENTINEL = "zzz-foreign-part-<script>alert(1)</script>"

    @staticmethod
    def _only_mx_alerts(body):
        assert list(_c12_stale(body)) == ["dns_stale_core"], body["alerts"]
        assert _c12_core_parts(body) == ["MX"], body["alerts"]

    @pytest.mark.parametrize("marker", [
        pytest.param("A", id="string"),
        pytest.param(["A", "MX"], id="list-of-names"),
        pytest.param([_C12_OLD], id="list-of-entries"),
        pytest.param(5, id="int"),
        pytest.param(True, id="bool"),
        pytest.param(1.5, id="float"),
        pytest.param(None, id="null"),
        pytest.param([0] * 100_000, id="huge-list"),
    ])
    def test_a_current_marker_that_is_not_a_dict_gives_no_alert(self, marker):
        # Controllo, verde anche prima del fix: nessuna voce valida a cui affiancarsi.
        body = _c12_diff(current=marker)

        assert _c12_stale(body) == {}

    @pytest.mark.parametrize("marker", [
        pytest.param("A", id="string"),
        pytest.param(["A", "MX"], id="list"),
        pytest.param(5, id="int"),
        pytest.param(None, id="null"),
        pytest.param([0] * 100_000, id="huge-list"),
    ])
    def test_a_baseline_marker_that_is_not_a_dict_does_not_raise(self, marker):
        # Controllo, verde anche prima del fix. Che cosa valga una baseline illeggibile (età 0
        # o «mai riportata») il criterio non lo dice: conta solo che non sia un 500 e che il
        # corrente valido non esca doppio.
        body = _c12_diff(baseline=marker, current={"A": _C12_OLD})

        assert len(_c12_stale(body)) <= 1

    @pytest.mark.parametrize("entry", [
        pytest.param("x", id="string"), pytest.param(None, id="null"), pytest.param([], id="empty-list"),
        pytest.param(5, id="int"), pytest.param(True, id="bool"), pytest.param(1.5, id="float"),
        pytest.param({}, id="empty-dict"),
        pytest.param([_C12_OLD], id="entry-wrapped-in-a-list"),
    ])
    def test_a_current_entry_that_is_not_a_valid_dict_gives_no_alert(self, entry):
        self._only_mx_alerts(_c12_diff(current={"A": entry, "MX": _C12_OLD}))

    @pytest.mark.parametrize("carried_at", [
        pytest.param(None, id="null"), pytest.param(5, id="int"), pytest.param(True, id="bool"),
        pytest.param("", id="empty"), pytest.param("not a date", id="text"),
        pytest.param(["2026-10-25T10:00:00+00:00"], id="list"), pytest.param({"x": 1}, id="dict"),
        pytest.param("2026-13-45T99:99:99+00:00", id="impossible-date"),
        pytest.param("<script>alert(1)</script>", id="markup"),
        pytest.param("x" * 200_000, id="huge-string"),
    ])
    def test_an_invalid_carried_at_gives_no_alert_and_is_not_echoed(self, carried_at):
        entry = {"observed_at": _C12_T0.isoformat(), "carried_at": carried_at}

        body = _c12_diff(current={"A": entry, "MX": _C12_OLD})

        self._only_mx_alerts(body)
        if isinstance(carried_at, str) and carried_at:
            assert carried_at not in json.dumps(body["alerts"])

    @pytest.mark.parametrize("carried_at", [None, 5, "", "not a date", "x" * 200_000],
                             ids=["null", "int", "empty", "text", "huge-string"])
    def test_an_invalid_carried_at_in_the_baseline_does_not_raise(self, carried_at):
        # Sul valore di una baseline illeggibile il criterio tace: si pretende il 200 e che la
        # voce valida (MX, che in baseline era a 48 h) alerti.
        baseline = {"A": {"observed_at": _C12_T0.isoformat(), "carried_at": carried_at},
                    "MX": _c12_entry(timedelta(hours=48))}

        body = _c12_diff(baseline=baseline, current={"A": _C12_OLD, "MX": _C12_OLD})

        assert "MX" in _c12_core_parts(body)

    @pytest.mark.parametrize("observed_at", [
        pytest.param(5, id="int"), pytest.param(True, id="bool"), pytest.param("", id="empty"),
        pytest.param("not a date", id="text"), pytest.param(["x"], id="list"),
        pytest.param("<script>alert(1)</script>", id="markup"), pytest.param("x" * 200_000, id="huge-string"),
    ])
    def test_an_unreadable_observed_at_does_not_raise_and_is_not_echoed(self, observed_at):
        # Se un `observed_at` illeggibile (non null) valga «età ignota» o «voce malformata» il
        # criterio non lo dice, e l'orchestrator scrive null in quel caso: qui si pretende il 200,
        # la voce valida accanto e nessuna stringa grezza negli alert.
        entry = {"observed_at": observed_at, "carried_at": (_C12_T0 + timedelta(hours=96)).isoformat()}

        body = _c12_diff(current={"A": entry, "MX": _C12_OLD})

        assert "MX" in _c12_core_parts(body)
        if isinstance(observed_at, str) and observed_at:
            assert observed_at not in json.dumps(body["alerts"])

    @pytest.mark.parametrize("name", [
        "dkim", "subdomains", "records", "email_auth", "", "A ", "__proto__", "constructor", "x" * 10_000,
        "EVIL-<script>alert(1)</script>",
    ], ids=["dkim", "subdomains", "records", "email_auth", "empty", "trailing-space", "proto", "constructor",
            "huge", "markup"])
    def test_a_name_outside_the_list_gives_no_alert(self, name):
        self._only_mx_alerts(_c12_diff(current={name: _C12_OLD, "MX": _C12_OLD}))

    def test_a_name_outside_the_list_never_reaches_the_alerts(self):
        # Accanto a una parte valida, che alerta, il nome estraneo non compare né nel messaggio
        # né nel dettaglio: il payload è della zona non autenticata.
        body = _c12_diff(current={"A": _C12_OLD, self.SENTINEL: _C12_OLD})

        assert _c12_core_parts(body) == ["A"]
        assert "zzz-foreign-part" not in json.dumps(body["alerts"])

    def test_valid_entries_alert_even_next_to_malformed_ones(self):
        marker = {
            "MX": _C12_OLD,
            "A": "garbage",
            "NS": {"observed_at": _C12_T0.isoformat(), "carried_at": "nope"},
            "TXT": None,
            "dkim": _C12_OLD,
            self.SENTINEL: _C12_OLD,
        }

        body = _c12_diff(current=marker)

        self._only_mx_alerts(body)
        assert "zzz-foreign-part" not in json.dumps(body["alerts"])

    def test_thousands_of_foreign_names_do_not_inflate_the_alert(self):
        marker = {f"foreign-{i}": _C12_OLD for i in range(5000)}
        marker["MX"] = _C12_OLD

        body = _c12_diff(current=marker)

        self._only_mx_alerts(body)
        assert len(json.dumps(body["alerts"])) < 4000

    def test_raw_instant_strings_are_not_copied_into_the_alerts(self):
        # Istanti validi ma scritti in forme non canoniche (spazio al posto di `T`, suffisso `Z`,
        # formato base): se compaiono nell'alert devono essere ri-serializzati dal parse, mai la
        # stringa del payload. MX, canonico, garantisce che l'alert esca comunque.
        raw_observed, raw_carried = "2026-10-20 10:00:00+00:00", "2026-10-25T10:00:00Z"
        raw_basic = "20261025T100000+0000"
        marker = {
            "A": {"observed_at": raw_observed, "carried_at": raw_carried},
            "NS": {"observed_at": raw_basic, "carried_at": raw_basic},
            "MX": _C12_OLD,
        }

        body = _c12_diff(current=marker)

        assert "MX" in _c12_core_parts(body)
        dumped = json.dumps(body["alerts"])
        for raw in (raw_observed, raw_carried, raw_basic):
            assert raw not in dumped, dumped

    def test_instants_with_different_offsets_are_compared_as_instants_not_as_wall_clock(self):
        # 2026-10-23T11:00+02:00 è le 09:00Z: 71 h dopo le 10:00Z del 20. Letto «a cifre» (11:00 -
        # 10:00 + 3 giorni) sarebbero 73 h.
        entry = {"observed_at": "2026-10-20T10:00:00+00:00", "carried_at": "2026-10-23T11:00:00+02:00"}

        self._only_mx_alerts(_c12_diff(current={"A": entry, "MX": _C12_OLD}))

    def test_instants_with_different_offsets_alert_when_the_real_age_is_over(self):
        # 2026-10-23T09:00-02:00 è le 11:00Z: 73 h dopo le 10:00Z del 20. Letto «a cifre» sarebbero 71 h.
        entry = {"observed_at": "2026-10-20T10:00:00+00:00", "carried_at": "2026-10-23T09:00:00-02:00"}

        assert _c12_core_parts(_c12_diff(current={"A": entry})) == ["A"]

    @pytest.mark.parametrize("observed_at, carried_at", [
        pytest.param("2026-10-20T10:00:00", "2026-10-25T10:00:00+00:00", id="naive-observed"),
        pytest.param("2026-10-20T10:00:00+00:00", "2026-10-25T10:00:00", id="naive-carried"),
        pytest.param("2026-10-20T10:00:00", "2026-10-25T10:00:00", id="both-naive"),
    ])
    def test_naive_and_aware_instants_do_not_raise(self, observed_at, carried_at):
        # Sottrarre un istante naive da uno aware solleva TypeError: il criterio non dice se
        # contino come UTC, qui si pretende solo che non sia un 500 e che MX alerti.
        body = _c12_diff(current={"A": {"observed_at": observed_at, "carried_at": carried_at}, "MX": _C12_OLD})

        assert "MX" in _c12_core_parts(body)

    @pytest.mark.parametrize("observed_at, carried_at", [
        pytest.param("0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-12:00", id="widest-span"),
        pytest.param("0001-01-01T00:00:00+00:00", "0001-01-01T00:00:00+14:00", id="year-one-positive-offset"),
        pytest.param("9999-12-31T23:59:59-12:00", "0001-01-01T00:00:00+14:00", id="reversed"),
        pytest.param("9999-12-31T23:59:59+00:00", "9999-12-31T23:59:59-23:59", id="year-9999-negative-offset"),
    ])
    def test_extreme_instants_do_not_raise(self, observed_at, carried_at):
        # Un'aritmetica che converte in UTC (`astimezone`) esce dall'intervallo con questi valori.
        extreme = {"observed_at": observed_at, "carried_at": carried_at}

        body = _c12_diff(baseline={"NS": extreme}, current={"A": extreme, "NS": extreme, "MX": _C12_OLD})

        assert "MX" in _c12_core_parts(body)


# Scenari di cambio già coperti altrove, riusati come oggetto di confronto con e senza marcatore.
def _c12_change_scenarios():
    base = _c12_zone()
    changed_a = _c12_zone()
    changed_a["records"]["A"] = ["198.51.100.7"]
    mx_ns_txt = _c12_zone()
    mx_ns_txt["records"]["MX"] = ["10 mail.other.example"]
    mx_ns_txt["records"]["NS"] = ["ns1.other.example"]
    mx_ns_txt["records"]["TXT"] = ['"v=spf1 +all"']
    removed = _c12_zone()
    removed["records"]["A"] = []
    removed["records_status"]["A"] = "nodata"
    email = _c12_zone()
    email["email_auth"]["spf"] = {"present": True, "records": ['"v=spf1 +all"'], "policy": "pass", "status": "ok"}
    email["email_auth"]["dmarc"] = {"present": False, "records": [], "status": "nodata"}
    return [
        pytest.param(base, changed_a, id="a-changed"),
        pytest.param(base, mx_ns_txt, id="mx-ns-txt-changed"),
        pytest.param(base, removed, id="a-removed-nodata"),
        pytest.param(base, email, id="email-auth-changed"),
        pytest.param(base, base, id="no-change"),
    ]


class TestCOL12ExistingAlertsAreUnchanged:
    """C9, controlli — verdi anche prima del fix. Il marcatore aggiunge due tipi di alert e non
    cambia gli altri: stessi alert (tipo, severità, messaggio, dettaglio), stesso `max_severity`,
    con e senza marcatore, per un marcatore giovane (sotto soglia) su entrambi i lati."""

    YOUNG = {"A": _c12_entry(timedelta(hours=24)), "dmarc": _c12_entry(timedelta(hours=24))}

    @staticmethod
    def _shape(body):
        return ([(a["type"], a["severity"], a["message"], a["detail"]) for a in body["alerts"]],
                body["alert_count"], body["max_severity"])

    @pytest.mark.parametrize("prev, curr", _c12_change_scenarios())
    def test_same_alerts_with_and_without_a_young_marker(self, prev, curr):
        bare = self._shape(_c12_post(prev, curr))

        with_marker = self._shape(_c12_post({**prev, "carried_over": self.YOUNG},
                                            {**curr, "carried_over": self.YOUNG}))

        assert with_marker == bare

    @pytest.mark.parametrize("prev, curr", _c12_change_scenarios())
    def test_same_alerts_with_a_marker_only_on_the_current_side(self, prev, curr):
        bare = self._shape(_c12_post(prev, curr))

        with_marker = self._shape(_c12_post(prev, {**curr, "carried_over": self.YOUNG}))

        assert with_marker == bare

    def test_the_return_of_the_dns_after_a_stale_series_raises_the_ordinary_change_alert(self):
        # Baseline con A riportata da 100 h; il DNS torna e l'A è cambiato: l'alert è quello di
        # sempre (`a_record_changed`, HIGH, da/a) e non c'è nessun alert di «serie finita».
        prev = _c12_zone({"A": _c12_entry(timedelta(hours=100))})
        curr = _c12_zone()
        curr["records"]["A"] = ["198.51.100.7"]

        body = _c12_post(prev, curr)

        assert [(a["type"], a["severity"], a["detail"]) for a in body["alerts"]] == [
            ("a_record_changed", "HIGH", {"old": ["192.0.2.10"], "new": ["198.51.100.7"]})]

    def test_the_return_of_the_dns_with_the_same_values_is_silent(self):
        prev = _c12_zone({"A": _c12_entry(timedelta(hours=100)), "spf": _c12_entry(timedelta(hours=100))})

        body = _c12_post(prev, _c12_zone())

        assert body["alerts"] == [] and body["max_severity"] == "CLEAN"


class TestCOL12OtherSectionsAreDiffedAsBefore:
    """C9 — con una parte `dns` stantia accanto, le altre sezioni producono gli stessi alert di
    sempre; l'alert nuovo è in più. Rosso prima del fix solo per `dns_stale_core`."""

    def test_a_certificate_alert_is_unchanged_next_to_a_stale_part(self):
        prev = {"dns": _c12_zone(), "cert": {"ct_certificates": {"total": 1}}, "http": None,
                "whois": None, "reputation": None}
        curr = {"dns": _c12_zone({"A": _C12_OLD}),
                "cert": {"ct_certificates": {"total": 3}}, "http": None, "whois": None, "reputation": None}

        resp = _C12_API.post("/diff", json={"domain": _C02_DOMAIN, "client": "acme", "legitimate": "acme.example",
                                            "baseline": prev, "current": curr})

        assert resp.status_code == 200, resp.text[:300]
        body = resp.json()
        assert sorted(a["type"] for a in body["alerts"]) == ["dns_stale_core", "new_certificate"]
        cert = next(a for a in body["alerts"] if a["type"] == "new_certificate")
        assert (cert["severity"], cert["detail"]) == ("MEDIUM", {"count": 2})


class TestCOL12NoStaleAlertWithoutADnsBaseline:
    """N1 (mutante C16 del verifier) — la baseline `dns` mancante o illeggibile non è una baseline a
    zero: `_has_baseline("dns")` vale anche per l'alert di dato riportato. Un marcatore corrente già
    oltre le 72 h, senza nulla con cui confrontarsi, non allerta: la baseline si popola in silenzio
    (come per ogni altra sezione, CODE-01). Controlli, verdi anche prima del fix: tengono il nuovo
    alert dentro la guardia."""

    OLD = {"A": _c12_entry(timedelta(hours=96)), "dmarc": _c12_entry(timedelta(hours=96))}

    @staticmethod
    def _post(baseline):
        payload = {"domain": _C02_DOMAIN, "client": "acme", "legitimate": "acme.example",
                   "baseline": baseline, "current": _c02_snap(_c12_zone(TestCOL12NoStaleAlertWithoutADnsBaseline.OLD))}
        resp = _C12_API.post("/diff", json=payload)
        assert resp.status_code == 200, resp.text[:300]
        return resp.json()

    @pytest.mark.parametrize("baseline", [
        pytest.param(_c02_snap(None), id="dns-null"),
        pytest.param(_c02_snap("not a dict"), id="dns-string"),
        pytest.param(_c02_snap([]), id="dns-list"),
        pytest.param({"cert": None, "http": None, "whois": None, "reputation": None}, id="dns-key-missing"),
        pytest.param({}, id="empty-baseline"),
        pytest.param(None, id="no-baseline"),
    ])
    def test_a_marker_over_the_threshold_is_silent_without_a_dns_baseline(self, baseline):
        body = self._post(baseline)

        assert _c12_stale(body) == {}
        assert body["alerts"] == [] and body["max_severity"] == "CLEAN"

    def test_the_same_marker_alerts_once_a_dns_baseline_exists(self):
        # Contrasto: con una baseline `dns` (anche solo una zona senza marcatore) l'alert esce.
        body = self._post(_c02_snap(_c12_zone()))

        assert sorted(_c12_stale(body)) == ["dns_stale_core", "dns_stale_other"], body["alerts"]


# ═══════════════════════════════════════════════════════════════
# COL-13 — `/diff` non cambia con il marcatore di un modulo riportato
# ═══════════════════════════════════════════════════════════════
#
# Criterio C6 di BUG-REGISTER.md («ASSEGNA · COL-13 · criteri di accettazione»). Quando `cert`,
# `whois`, `http` o `reputation` falliscono, l'orchestrator salva la sezione precedente più un
# campo diretto `carried_over = {"observed_at", "carried_at"}` e lo manda così a `/diff` (nel
# `current`; nella baseline se il ciclo prima era già riportato). Il `/diff` non deve leggerlo né
# farsene influenzare: stessi alert, stessa gravità, con e senza marcatore — valido, con
# `observed_at` null o malformato, perché il `current` arriva dalla zona NON autenticata.
# Controlli verdi anche prima del fix (il classificatore ignora la chiave): fissano ciò che il fix
# non deve toccare, e proteggono da un `/diff` che scorra le chiavi delle sezioni.

_C13_DOMAIN = "acme-typo.example"
_C13_API = TestClient(app, raise_server_exceptions=False)
_C13_MODULES = ["cert", "whois", "http", "reputation"]
_C13_MARKER = {"observed_at": "2026-10-20T10:00:00+00:00", "carried_at": "2026-10-24T10:00:30+00:00"}


def _c13_section(module, changed=False):
    """Sezione sana del modulo; con `changed` una variazione che `/diff` segnala (nuovo certificato,
    registrar diverso, sito attivato su un URL nuovo, fonte VT che vede malevolo)."""
    d = _C13_DOMAIN
    if module == "cert":
        return {"ct_certificates": {"total": 23 if changed else 21, "unique_cn": [d], "certificates": []},
                "error": None}
    if module == "whois":
        return {"registrar": "Other Registrar Example" if changed else "Registrar Example",
                "expiration_date": "2027-01-01T00:00:00", "privacy_protected": False, "error": None}
    if module == "http":
        checks = [{"url": f"http://{d}", "status_code": 200, "content_length": 5400, "error": None}]
        if changed:
            checks.append({"url": f"https://{d}", "status_code": 200, "content_length": 5400, "error": None})
        return {"checks": checks, "overall_status": "active", "error": None}
    return {"virustotal": {"malicious": 3 if changed else 0, "error": None},
            "otx": {"pulse_count": 0, "error": None}, "securitytrails": {"error": None},
            "risk_score": 0, "risk_level": "clean", "error": None}


def _c13_payload(changed, baseline_marker=None, current_marker=None, marked=_C13_MODULES):
    """Payload di `/diff` con i 4 moduli: in `changed` quelli che cambiano fra baseline e corrente;
    i marcatori (se dati) sono messi sui moduli `marked`, sul lato indicato."""
    baseline = {"dns": None, **{m: _c13_section(m) for m in _C13_MODULES}}
    current = {"dns": None, **{m: _c13_section(m, changed=m in changed) for m in _C13_MODULES}}
    for side, marker in ((baseline, baseline_marker), (current, current_marker)):
        if marker is not None:
            for m in marked:
                side[m]["carried_over"] = json.loads(json.dumps(marker))
    return {"domain": _C13_DOMAIN, "client": "acme", "legitimate": "acme.example",
            "baseline": baseline, "current": current}


def _c13_alerts(payload):
    resp = _C13_API.post("/diff", json=payload)
    assert resp.status_code == 200, resp.text[:300]
    body = resp.json()
    return (sorted((a["type"], a["severity"], a["message"], json.dumps(a["detail"], sort_keys=True))
                   for a in body["alerts"]), body["alert_count"], body["max_severity"])


class TestCOL13DiffIgnoresTheModuleMarker:
    """C6 — stessi alert con e senza marcatore, per ciascuno dei 4 moduli, sia che il modulo
    riportato sia identico alla baseline sia che il resto del payload cambi."""

    @pytest.mark.parametrize("module", _C13_MODULES)
    @pytest.mark.parametrize("others_change", [False, True], ids=["nothing-else-changes", "the-others-change"])
    def test_a_carried_module_raises_the_same_alerts_with_a_valid_marker(self, module, others_change):
        changed = [m for m in _C13_MODULES if m != module] if others_change else []
        bare = _c13_alerts(_c13_payload(changed))

        for baseline_marker, current_marker in ((None, _C13_MARKER), (_C13_MARKER, None), (_C13_MARKER, _C13_MARKER)):
            marked = _c13_alerts(_c13_payload(changed, baseline_marker, current_marker, marked=[module]))
            assert marked == bare, (baseline_marker, current_marker)
        assert (bare[1] > 0) == others_change, bare

    @pytest.mark.parametrize("module", _C13_MODULES)
    def test_a_marker_does_not_hide_a_change_in_the_module_itself(self, module):
        # Un modulo che ha risposto di nuovo ma con un dato cambiato allerta come sempre, anche se
        # la baseline è quella di un ciclo riportato (marcatore nella baseline).
        bare = _c13_alerts(_c13_payload([module]))
        marked = _c13_alerts(_c13_payload([module], baseline_marker=_C13_MARKER, marked=[module]))

        assert marked == bare and bare[1] > 0, bare

    @pytest.mark.parametrize("marker", [
        pytest.param({"observed_at": None, "carried_at": "2026-10-24T10:00:30+00:00"}, id="observed-at-null"),
        pytest.param({"observed_at": "<script>alert(1)</script>", "carried_at": "x" * 5000}, id="hostile-strings"),
        pytest.param({"observed_at": 5, "carried_at": ["a"]}, id="wrong-types"),
        pytest.param({}, id="empty-dict"), pytest.param("x", id="string"), pytest.param(["observed_at"], id="list"),
        pytest.param(5, id="int"), pytest.param(None, id="null"), pytest.param(True, id="bool"),
        pytest.param({f"foreign-{i}": i for i in range(2000)}, id="thousands-of-keys"),
    ])
    def test_a_malformed_marker_neither_raises_nor_changes_the_alerts(self, marker):
        changed = ["cert", "http"]
        bare = _c13_alerts(_c13_payload(changed))
        payload = _c13_payload(changed)
        for m in _C13_MODULES:
            payload["current"][m]["carried_over"] = json.loads(json.dumps(marker))
            payload["baseline"][m]["carried_over"] = json.loads(json.dumps(marker))

        assert _c13_alerts(payload) == bare

    def test_the_marker_is_not_an_alert_by_itself_even_when_very_old(self):
        # COL-13 non introduce alcun alert «non riosservato»: un modulo riportato da un anno,
        # identico alla baseline, non produce nulla.
        old = {"observed_at": "2025-10-20T10:00:00+00:00", "carried_at": "2026-10-24T10:00:30+00:00"}

        assert _c13_alerts(_c13_payload([], current_marker=old)) == ([], 0, "CLEAN")


# ═══════════════════════════════════════════════════════════════
# COL-16 — `/diff`: una fonte di reputazione non osservata non è una baseline a zero
# ═══════════════════════════════════════════════════════════════
#
# Una fonte di reputazione in errore è un dict completo con i numeri a zero e `error` valorizzato (il
# collector la scrive così). Come baseline non vale zero: non è un'osservazione. Alla prima osservazione
# riuscita il `/diff` non allerta (come per una sezione assente, principio di `_has_baseline`): la
# baseline si popola in silenzio. Restano alert gli aumenti veri rispetto a un'osservazione: da 0 a più
# di 0 malicious per VT, più pulse per OTX. L'esito 404 di VT, con `error` valorizzato, è
# un'osservazione (VT non conosce il dominio: gli zeri sono veri). La stringa è quella che il collector
# scrive per un 404. «Non osservata» si decide per PRESENZA di `error` (non `None`), non per la verità
# del testo: un'eccezione senza messaggio dà `error: ""`. La regola vale da entrambi i lati: un dato non
# osservato, in baseline o nel corrente, non produce alert, anche se porta numeri diversi da zero.

_C16_DOMAIN = "acme-typo.example"
_C16_API = TestClient(app, raise_server_exceptions=False)
_C16_VT_NOT_FOUND = "not found on VT"
_C16_ERRORS = [pytest.param("HTTP 429", id="http-429"), pytest.param("HTTP 500", id="http-500"),
               pytest.param("Read timed out. (read timeout=15)", id="timeout")]


def _c16_vt(malicious=0, error=None):
    """Fonte VT come la scrive il collector: osservata (`error` null) o guasta (numeri a zero)."""
    if error is not None:
        return {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0, "reputation": 0,
                "categories": {}, "error": error}
    return {"malicious": malicious, "suspicious": 0, "undetected": 60, "harmless": 10,
            "reputation": -10 if malicious else 0, "categories": {}, "error": None}


def _c16_otx(pulses=0, error=None):
    """Fonte OTX come la scrive il collector."""
    return {"pulse_count": 0 if error is not None else pulses, "pulse_titles": [], "tags": [], "malware_families": [],
            "error": error}


def _c16_reputation(vt, otx, **extra):
    return {"domain": _C16_DOMAIN, "virustotal": vt, "otx": otx,
            "securitytrails": {"subdomain_count": 4, "current_dns": {}, "alexa_rank": None, "error": None},
            "risk_score": 0, "risk_level": "clean", "error": None, **extra}


def _c16_alerts(baseline, current):
    """[(tipo, severità)] che `/diff` produce sulla sola sezione `reputation`."""
    response = _C16_API.post("/diff", json={
        "domain": _C16_DOMAIN, "client": "acme", "legitimate": "acme.example",
        "baseline": {"reputation": baseline}, "current": {"reputation": current}})
    assert response.status_code == 200, response.text[:300]
    return sorted((a["type"], a["severity"]) for a in response.json()["alerts"])


class TestCOL16DiffIgnoresAnUnobservedBaselineSource:
    """La baseline di una fonte in errore non è un'osservazione: la prima osservazione riuscita non
    allerta."""

    @pytest.mark.parametrize("error", _C16_ERRORS)
    def test_virustotal_malicious_after_a_failed_baseline_source_is_not_an_alert(self, error):
        baseline = _c16_reputation(_c16_vt(error=error), _c16_otx(2))
        current = _c16_reputation(_c16_vt(3), _c16_otx(2))

        assert _c16_alerts(baseline, current) == []

    @pytest.mark.parametrize("error", _C16_ERRORS)
    def test_otx_pulses_after_a_failed_baseline_source_are_not_an_alert(self, error):
        baseline = _c16_reputation(_c16_vt(3), _c16_otx(error=error))
        current = _c16_reputation(_c16_vt(3), _c16_otx(2))

        assert _c16_alerts(baseline, current) == []

    def test_two_failed_baseline_sources_give_no_alert_when_both_return(self):
        baseline = _c16_reputation(_c16_vt(error="HTTP 429"), _c16_otx(error="HTTP 429"))
        current = _c16_reputation(_c16_vt(3), _c16_otx(5))

        assert _c16_alerts(baseline, current) == []

    def test_a_failed_baseline_source_does_not_hide_a_real_change_in_the_other(self):
        baseline = _c16_reputation(_c16_vt(error="HTTP 429"), _c16_otx(2))
        current = _c16_reputation(_c16_vt(3), _c16_otx(5))

        assert _c16_alerts(baseline, current) == [("otx_pulse_detected", "HIGH")]


class TestCOL16DiffStillAlertsOnARealChange:
    """Controlli: una baseline osservata, anche con zero, e un 404 di VT restano un confronto vero."""

    def test_virustotal_from_clean_to_malicious_alerts(self):
        baseline = _c16_reputation(_c16_vt(0), _c16_otx(2))
        current = _c16_reputation(_c16_vt(3), _c16_otx(2))

        assert _c16_alerts(baseline, current) == [("vt_malicious_detected", "CRITICAL")]

    def test_otx_with_more_pulses_alerts_from_zero_and_from_some(self):
        for before in (0, 2):
            baseline = _c16_reputation(_c16_vt(3), _c16_otx(before))
            current = _c16_reputation(_c16_vt(3), _c16_otx(5))

            assert _c16_alerts(baseline, current) == [("otx_pulse_detected", "HIGH")], before

    def test_virustotal_that_grows_from_some_to_more_malicious_does_not_alert(self):
        baseline = _c16_reputation(_c16_vt(3), _c16_otx(2))
        current = _c16_reputation(_c16_vt(5), _c16_otx(2))

        assert _c16_alerts(baseline, current) == []

    def test_a_vt_404_in_the_baseline_is_an_observation(self):
        baseline = _c16_reputation(_c16_vt(error=_C16_VT_NOT_FOUND), _c16_otx(2))
        current = _c16_reputation(_c16_vt(3), _c16_otx(2))

        assert _c16_alerts(baseline, current) == [("vt_malicious_detected", "CRITICAL")]

    def test_a_source_that_fails_in_the_current_cycle_never_alerts(self):
        baseline = _c16_reputation(_c16_vt(3), _c16_otx(2))
        current = _c16_reputation(_c16_vt(error="HTTP 429"), _c16_otx(error="HTTP 429"))

        assert _c16_alerts(baseline, current) == []

    def test_a_carried_source_in_the_baseline_alerts_on_a_real_increase(self):
        # La fonte riportata è l'osservazione precedente, senza `error`: la baseline la tratta da tale.
        marker = {"virustotal": {"observed_at": "2026-10-20T10:00:00+00:00",
                                 "carried_at": "2026-10-21T10:00:30+00:00"}}
        baseline = _c16_reputation(_c16_vt(0), _c16_otx(2), carried_sources=marker)
        current = _c16_reputation(_c16_vt(3), _c16_otx(2))

        assert _c16_alerts(baseline, current) == [("vt_malicious_detected", "CRITICAL")]


class TestCOL16DiffIgnoresTheSourceMarker:
    """`carried_sources` sta nella sezione ma non decide nulla: stessi alert con e senza, anche se
    malformato (il `current` arriva dalla zona non autenticata) e senza sollevare."""

    MARKERS = [
        pytest.param({"virustotal": {"observed_at": "2026-10-20T10:00:00+00:00",
                                     "carried_at": "2026-10-21T10:00:30+00:00"}}, id="valid"),
        pytest.param({"virustotal": {"observed_at": None, "carried_at": "2026-10-21T10:00:30+00:00"}},
                     id="observed-at-null"),
        pytest.param({"virustotal": {"observed_at": "<script>alert(1)</script>", "carried_at": "x" * 5000}},
                     id="hostile-strings"),
        pytest.param({"virustotal": {"observed_at": 5, "carried_at": ["a"]}}, id="wrong-types"),
        pytest.param({}, id="empty-dict"), pytest.param("x", id="string"), pytest.param(["virustotal"], id="list"),
        pytest.param(5, id="int"), pytest.param(None, id="null"), pytest.param(True, id="bool"),
        pytest.param({f"foreign-{i}": i for i in range(2000)}, id="thousands-of-keys"),
    ]

    @pytest.mark.parametrize("marker", MARKERS)
    @pytest.mark.parametrize("side", ["baseline", "current", "both"])
    def test_a_marker_neither_raises_nor_changes_the_alerts(self, marker, side):
        baseline = _c16_reputation(_c16_vt(0), _c16_otx(2))
        current = _c16_reputation(_c16_vt(3), _c16_otx(5))
        bare = _c16_alerts(baseline, current)
        if side in ("baseline", "both"):
            baseline["carried_sources"] = json.loads(json.dumps(marker))
        if side in ("current", "both"):
            current["carried_sources"] = json.loads(json.dumps(marker))

        assert bare == [("otx_pulse_detected", "HIGH"), ("vt_malicious_detected", "CRITICAL")]
        assert _c16_alerts(baseline, current) == bare


class TestCOL16DiffTreatsAnEmptyErrorTextAsUnobserved:
    """`error: ""` (eccezione senza messaggio) è un guasto come `error: "HTTP 429"`: si decide per
    presenza, non per verità."""

    def test_virustotal_malicious_after_an_empty_error_baseline_is_not_an_alert(self):
        baseline = _c16_reputation(_c16_vt(error=""), _c16_otx(2))
        current = _c16_reputation(_c16_vt(3), _c16_otx(2))

        assert baseline["virustotal"] == {"malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0,
                                          "reputation": 0, "categories": {}, "error": ""}
        assert _c16_alerts(baseline, current) == []

    def test_otx_pulses_after_an_empty_error_baseline_are_not_an_alert(self):
        baseline = _c16_reputation(_c16_vt(3), _c16_otx(error=""))
        current = _c16_reputation(_c16_vt(3), _c16_otx(2))

        assert _c16_alerts(baseline, current) == []


class TestCOL16DiffIgnoresAnUnobservedCurrentSource:
    """Un dato non osservato nel corrente non produce alert, qualunque siano i suoi numeri: `/diff` è
    chiamabile direttamente e non dipende dal riporto dell'orchestrator."""

    ERRORS = [*_C16_ERRORS, pytest.param("x", id="any-text"), pytest.param("", id="empty-text")]

    @pytest.mark.parametrize("error", ERRORS)
    @pytest.mark.parametrize("before", [0, 2])
    def test_otx_pulses_of_a_failed_current_source_are_not_an_alert(self, error, before):
        baseline = _c16_reputation(_c16_vt(3), _c16_otx(before))
        current = _c16_reputation(_c16_vt(3), {**_c16_otx(5), "error": error})

        assert _c16_alerts(baseline, current) == []

    @pytest.mark.parametrize("error", ERRORS)
    def test_virustotal_malicious_of_a_failed_current_source_is_not_an_alert(self, error):
        baseline = _c16_reputation(_c16_vt(0), _c16_otx(2))
        current = _c16_reputation({**_c16_vt(3), "error": error}, _c16_otx(2))

        assert _c16_alerts(baseline, current) == []

    def test_a_failed_current_source_does_not_hide_a_real_change_in_the_other(self):
        baseline = _c16_reputation(_c16_vt(0), _c16_otx(2))
        current = _c16_reputation({**_c16_vt(3), "error": "HTTP 429"}, _c16_otx(5))

        assert _c16_alerts(baseline, current) == [("otx_pulse_detected", "HIGH")]

    def test_a_vt_404_in_the_current_cycle_is_an_observation_too(self):
        # Il testo del 404 è un'osservazione da entrambi i lati: con numeri diversi da zero (payload
        # sintetico, il collector scrive zeri) il confronto è quello ordinario.
        baseline = _c16_reputation(_c16_vt(0), _c16_otx(2))
        current = _c16_reputation({**_c16_vt(3), "error": _C16_VT_NOT_FOUND}, _c16_otx(2))

        assert _c16_alerts(baseline, current) == [("vt_malicious_detected", "CRITICAL")]
