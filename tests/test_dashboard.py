"""Tests for services/dashboard.py — route serving and asset integrity."""

from fastapi.testclient import TestClient

from services.dashboard import app

client = TestClient(app)


class TestDashboardServing:
    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["service"] == "dashboard"

    def test_dashboard_served(self):
        r = client.get("/dashboard")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "DomainSentry" in r.text

    def test_no_external_dependencies(self):
        """Critical: the page must not load external resources (locked-down network)."""
        r = client.get("/dashboard")
        html = r.text.lower()
        # No CDN / external script or style references
        assert "http://" not in html.replace("http://www.w3.org", "")  # svg ns is fine
        assert "cdn." not in html
        assert "googleapis" not in html
        assert "unpkg" not in html
        assert "jsdelivr" not in html

    def test_calls_expected_endpoints(self):
        """The page references the case-manager endpoints it depends on."""
        html = client.get("/dashboard").text
        for ep in ["/auth/login", "/auth/me", "/summary", "/cases",
                   "/users/assignable", "/whitelist", "/assign", "/notes", "/status", "/intel",
                   "/trigger", "/feed/clients", "/feed/clients/onboard", "/feed/domains/promote", "/progress"]:
            assert ep in html, f"dashboard missing reference to {ep}"

    def test_intel_tabs_present(self):
        """The drawer has Overview / Intelligence / Raw JSON tabs."""
        html = client.get("/dashboard").text
        assert "renderIntelTab" in html
        assert "renderRawTab" in html
        assert "switchTab" in html
        assert "Baseline diff history" in html

    def test_permission_gating_present(self):
        """Action buttons are gated by permission checks in the JS."""
        html = client.get("/dashboard").text
        for perm in ["manage_cases", "assign_cases", "whitelist", "add_notes"]:
            assert perm in html


class TestClientReportBuiltHtml:
    """
    Regression for CODE-03 / RPT-01 (BUG-REGISTER.md). This is a *static* source
    check, not a behavioural one: it asserts on the text of buildHtmlReport() rather
    than executing it. It cannot prove the function renders correctly for a given
    snapshot — only that the truthy-array pattern is gone and that the new fields are
    referenced. The rendering itself is exercised in tests/test_dashboard_render.py,
    which runs the real script in `node` and is skipped where `node` is not installed.
    """

    def test_no_truthy_array_check_on_dns_records(self):
        """CODE-03: `dns.A ? … : …` / `dns.MX ? … : …` treat `[]` (record absent) as
        present, because a JS array is truthy regardless of length. The fix must check
        `.length`, not existence."""
        html = client.get("/dashboard").text
        assert 'dns.A ? "yes"' not in html, "CODE-03 regressed: dns.A truthy-array check is back"
        assert 'dns.MX ? "yes"' not in html, "CODE-03 regressed: dns.MX truthy-array check is back"
        assert "dns.A && dns.A.length" in html
        assert "dns.MX && dns.MX.length" in html

    def test_report_projection_includes_triage_fields(self):
        """RPT-01: buildHtmlReport() must project registrar, WHOIS dates, page title,
        content size, reputation, and per-module ok/errore status — not just the
        original four fields (A, MX, Website, Certificates)."""
        html = client.get("/dashboard").text
        start = html.find("function buildHtmlReport")
        assert start != -1, "buildHtmlReport() not found in dashboard source"
        end = html.find("\n}", start)
        fn_src = html[start:end]

        for needle in [
            "whois.registrar",
            "whois.creation_date",
            "whois.updated_date",
            "firstCheck.title",
            "firstCheck.content_length",
            "rep.risk_level",
            "rep.risk_score",
            "modStatus",
        ]:
            assert needle in fn_src, f"buildHtmlReport() is missing projection of {needle}"


class TestDashboardNoUndeclaredGlobals:
    """
    Regression: rewrites of the dashboard JS dropped `let viewAssignee` and
    `const VIEW_TITLES`, causing a ReferenceError that left the case table blank
    while the summary cards still rendered. Guard that the state globals used by
    the load/render path are actually declared.
    """
    def test_state_globals_declared(self):
        import re
        html = client.get("/dashboard").text
        script = html[html.rfind("<script>"):]
        declared = set(re.findall(r'\b(?:let|const|var)\s+([A-Za-z_$][\w$]*)', script))
        for name in ["TOKEN", "ME", "ASSIGNABLE", "CURRENT", "VIEW", "viewAssignee",
                     "VIEW_TITLES", "CURRENT_INTEL", "OB_DOMAINS", "DOMAIN_RE"]:
            assert name in declared, f"global '{name}' is used but never declared (ReferenceError risk)"


class TestCOL02DnsUnknownIsNotShownAsNo:
    """
    COL-02 (consumatori), criterio «Dashboard» di BUG-REGISTER.md. Dopo RES-01 la sezione
    `dns` di uno snapshot può dire, per ciascun tipo di record, `records_status[T] ==
    "unknown"` («il DNS non ha risposto»), e l'orchestrator salva `dns: null` quando il
    modulo è fallito e non c'era nulla di pregresso. La dashboard rendeva entrambi come
    «no»: l'analista leggeva «il dominio non ha MX» dove non lo si sapeva.

    Come `TestClientReportBuiltHtml`, sono controlli STATICI sul testo delle funzioni, non
    sull'esito del rendering (che è in `tests/test_dashboard_render.py`). Fissano che le stringhe nuove
    esistano e che le sottostringhe già fissate restino; non provano che il rendering sia
    corretto per un dato snapshot. Non è verificabile staticamente (e quindi non è qui) che
    siano rese solo stringhe costanti.
    """

    @staticmethod
    def _function_source(name):
        html = client.get("/dashboard").text
        start = html.find(f"function {name}")
        assert start != -1, f"{name}() not found in dashboard source"
        return html[start:html.find("\n}", start)]

    def test_report_reads_the_per_type_status(self):
        fn_src = self._function_source("buildHtmlReport")

        assert "records_status" in fn_src, "buildHtmlReport() never looks at dns.records_status"

    def test_report_can_say_unknown_for_the_a_and_mx_rows(self):
        fn_src = self._function_source("buildHtmlReport")

        assert '"unknown"' in fn_src or "'unknown'" in fn_src, (
            "buildHtmlReport() has no 'unknown' value: an undetermined A/MX can only read yes/no")

    def test_report_keeps_the_length_checks_fixed_by_code_03(self):
        fn_src = self._function_source("buildHtmlReport")

        assert "dns.A && dns.A.length" in fn_src
        assert "dns.MX && dns.MX.length" in fn_src
        assert 'dns.A ? "yes"' not in fn_src and 'dns.MX ? "yes"' not in fn_src

    def test_report_still_projects_the_triage_fields(self):
        fn_src = self._function_source("buildHtmlReport")

        for needle in ["whois.registrar", "firstCheck.title", "rep.risk_level", "modStatus"]:
            assert needle in fn_src, f"buildHtmlReport() lost the projection of {needle}"

    def test_intel_tab_says_dns_was_not_collected_when_the_section_is_null(self):
        fn_src = self._function_source("renderIntelTab")

        assert "DNS non raccolto" in fn_src

    def test_intel_tab_lists_the_undetermined_record_types(self):
        fn_src = self._function_source("renderIntelTab")

        assert "records_status" in fn_src, "renderIntelTab() never looks at dns.records_status"
        assert "non determinat" in fn_src.lower(), "renderIntelTab() has no row for the undetermined types"


# ── COL-12, giro correttivo: i controlli statici lavorano sul sorgente SENZA commenti ──
#
# Il verifier ha mutato la dashboard in 10 modi (escape tolti, nomi dalle chiavi dello snapshot,
# stato DNS sempre «ok», note «riportato» tolte, riga della scheda Intel tolta): 7 su 10 sono
# sopravvissuti, perché i controlli cercavano sottostringhe («riportato», `carried_over`,
# `observed_at`) che compaiono già nei COMMENTI del codice nuovo. Qui i commenti si tolgono prima di
# cercare, e dove serve si asserisce su espressioni esatte (l'argomento di `e(`/`esc(`, il guard di
# un `if`, la definizione di una variabile), non su una parola in un punto qualsiasi.

import functools
import re

import pytest


def _strip_js_comments(src):
    """Toglie da `src` i commenti `//` e `/* */` senza toccare stringhe, template literal (anche con
    `${...}` annidati: `https://` e gli apostrofi nel testo restano) e regex literal. Verificato
    contro il tokenizer di TypeScript sull'intero script della dashboard: stessi 11.364 token."""
    out, n = [], len(src)

    def code(i, in_expr):
        depth, prev = 0, ""
        while i < n:
            c, nxt = src[i], src[i + 1:i + 2]
            if c == "/" and nxt == "/":
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            if c == "/" and nxt == "*":
                j = src.find("*/", i + 2)
                i = n if j < 0 else j + 2
                out.append(" ")
                continue
            if c in "'\"":
                j = i + 1
                while j < n and src[j] != c:
                    j += 2 if src[j] == "\\" else 1
                out.append(src[i:j + 1])
                i, prev = j + 1, c
                continue
            if c == "`":
                i, prev = template(i), "`"
                continue
            if c == "/" and (prev == "" or prev in "(,=:[!&|?{;>"):      # regex literal, non una divisione
                j, in_class = i + 1, False
                while j < n and src[j] != "\n":
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == "[":
                        in_class = True
                    elif src[j] == "]":
                        in_class = False
                    elif src[j] == "/" and not in_class:
                        break
                    j += 1
                out.append(src[i:j + 1])
                i, prev = j + 1, "/"
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                if in_expr and depth == 0:
                    return i
                depth -= 1
            out.append(c)
            if not c.isspace():
                prev = c
            i += 1
        return i

    def template(i):
        out.append("`")
        i += 1
        while i < n:
            c = src[i]
            if c == "\\":
                out.append(src[i:i + 2])
                i += 2
            elif c == "`":
                out.append("`")
                return i + 1
            elif c == "$" and src[i + 1:i + 2] == "{":
                out.append("${")
                i = code(i + 2, True) + 1
                out.append("}")
            else:
                out.append(c)
                i += 1
        return i

    code(0, False)
    return "".join(out)


@functools.lru_cache(maxsize=1)
def _dashboard_script():
    """L'ultimo blocco `<script>` della dashboard servita, senza commenti (calcolato una volta)."""
    html = client.get("/dashboard").text
    return _strip_js_comments(html[html.rfind("<script>"):])


class TestCOL12CarriedOverIsShown:
    """
    COL-12, criterio C10 di BUG-REGISTER.md. L'orchestrator marca nello snapshot le parti del
    `dns` riportate dal ciclo precedente (`dns.carried_over = {parte: {observed_at, carried_at}}`)
    e il classificatore emette `dns_stale_core`/`dns_stale_other` nella storia degli alert. La
    dashboard deve: dire «riportato» con la data dell'ultima osservazione (o «data ignota») nelle
    righe A/MX del report verso il cliente, non scrivere «DNS ok» per un dato riportato, elencare
    le parti riportate nella scheda Intel, e mostrare il `message` dell'alert nella storia invece
    di «[object Object]» (`String(a.detail)` su un oggetto).

    Come le altre classi di questo file, sono controlli STATICI sul testo delle funzioni senza
    commenti, non sull'esito del rendering. Fissano che il codice legga il marcatore, che date e
    nomi passino per `esc`/`e` e che la riga della storia non usi più `String(a.detail)`; la resa
    per un dato snapshot è provata in `tests/test_dashboard_render.py` (node, saltato se manca).
    """

    @staticmethod
    def _function_source(name):
        # Senza commenti (giro correttivo, B2): prima un commento che citava `carried_over` o
        # «riportato» bastava a far passare il test anche con il codice vivo tolto.
        script = _dashboard_script()
        start = script.find(f"function {name}")
        assert start != -1, f"{name}() not found in dashboard source"
        return script[start:script.find("\n}", start)]

    def test_report_reads_the_carried_over_marker(self):
        fn_src = self._function_source("buildHtmlReport")

        assert "carried_over" in fn_src, "buildHtmlReport() never looks at dns.carried_over"
        assert "observed_at" in fn_src, "buildHtmlReport() never reads the date of the last real observation"

    def test_report_says_riportato_for_a_carried_a_or_mx(self):
        fn_src = self._function_source("buildHtmlReport")

        assert "riportato" in fn_src.lower(), "buildHtmlReport() has no 'riportato' wording"

    def test_report_says_data_ignota_when_the_observation_date_is_unknown(self):
        fn_src = self._function_source("buildHtmlReport")

        assert "data ignota" in fn_src.lower(), "buildHtmlReport() has no fallback for observed_at null"

    def test_report_keeps_the_a_mx_checks_of_code_03_and_col_02(self):
        # Controllo, verde anche prima del fix: il nuovo ramo non toglie i controlli esistenti.
        fn_src = self._function_source("buildHtmlReport")

        assert "dns.A && dns.A.length" in fn_src and "dns.MX && dns.MX.length" in fn_src
        assert "records_status" in fn_src and '"unknown"' in fn_src

    def test_intel_tab_reads_the_carried_over_marker(self):
        fn_src = self._function_source("renderIntelTab")

        assert "carried_over" in fn_src, "renderIntelTab() never looks at dns.carried_over"
        assert "observed_at" in fn_src, "renderIntelTab() never reads the date of the last real observation"

    def test_intel_tab_has_a_row_for_the_carried_parts(self):
        fn_src = self._function_source("renderIntelTab")

        assert "riportat" in fn_src.lower(), "renderIntelTab() has no row for the carried parts"

    def test_intel_tab_keeps_the_rows_for_the_undetermined_types(self):
        # Controllo, verde anche prima del fix (COL-02): la riga nuova si affianca a quella esistente.
        fn_src = self._function_source("renderIntelTab")

        assert "non determinat" in fn_src.lower() and "records_status" in fn_src

    @staticmethod
    def _history_row():
        fn_src = TestCOL12CarriedOverIsShown._function_source("renderIntelTab")
        rows = [line for line in fn_src.splitlines() if 'class="diff-alert"' in line]
        assert len(rows) == 1, f"expected exactly one diff-alert row in renderIntelTab(), found {len(rows)}"
        return rows[0]

    def test_history_row_no_longer_stringifies_the_detail_object(self):
        # `a.detail` è un oggetto: `String(a.detail)` rende «[object Object]» per ogni alert.
        assert "String(a.detail)" not in self._history_row()

    def test_history_row_shows_the_alert_message_escaped(self):
        import re
        row = self._history_row()

        assert re.search(r"esc\([^)]*\ba\.message\b", row), f"the history row does not esc(a.message): {row.strip()}"

    def test_history_row_still_shows_the_alert_type(self):
        # Controllo, verde anche prima del fix.
        assert "a.type" in self._history_row()

    # ── Giro correttivo (B2, R3, D2): controlli che uccidono i mutanti D01-D04, D07, D08, D10 ──

    CARRY_PARTS = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "spf", "dmarc", "bimi", "caa"]

    @staticmethod
    def _definition(src, name):
        """Il corpo di `const|let|var name = ...` fino al prossimo statement alla stessa indentazione."""
        m = re.search(rf"^([ \t]*)(?:const|let|var)\s+{re.escape(name)}\s*=", src, re.M)
        if not m:
            return ""
        rest = src[m.end():]
        end = re.search(rf"\n{m.group(1)}(?:const|let|var|return|if|for|function)\b", rest)
        return rest[:end.start()] if end else rest

    @staticmethod
    def _interpolations(text):
        """Le espressioni `${...}` di un frammento di template, con le graffe annidate."""
        found, i = [], 0
        while (i := text.find("${", i)) != -1:
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            found.append(text[i + 2:j - 1])
            i = j
        return found

    @classmethod
    def _fixed_part_lists(cls, src):
        """Gli array letterali di sole stringhe di `src`, come liste di nomi."""
        return [re.findall(r'"([^"]*)"', m.group(0))
                for m in re.finditer(r'\[\s*"[^"]*"(?:\s*,\s*"[^"]*")*\s*\]', src)]

    @classmethod
    def _reads_the_fixed_part_list(cls, src):
        """True se `src` contiene l'elenco fisso delle 11 parti, scritto lì o dichiarato altrove nello
        script (`const NOME = [...]`) e usato per nome."""
        if any(set(cls.CARRY_PARTS) <= set(names) for names in cls._fixed_part_lists(src)):
            return True
        script = _dashboard_script()
        for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*(\[[^\]]*\])", script):
            if set(cls.CARRY_PARTS) <= set(re.findall(r'"([^"]*)"', m.group(2))) and re.search(rf"\b{m.group(1)}\b", src):
                return True
        return False

    @staticmethod
    def _unescaped_value_uses(src, field, escapers=("e", "esc")):
        """Gli usi di `.field` come VALORE (non come test di un ternario o di un `&&`) che non sono
        l'argomento di `e(`/`esc(`, anche dentro `String(...)`. Ritorna (n. usi come valore, non escapati)."""
        values, bare = 0, []
        for m in re.finditer(rf"\.{field}\b", src):
            if re.match(r"\s*(?:\?|&&|\|\||[!=]==?)", src[m.end():]):
                continue
            values += 1
            head = src[:m.start()]
            if not re.search(rf"\b(?:{'|'.join(escapers)})\(\s*(?:String\(\s*)?[\w$\[\].]*$", head):
                bare.append(src[max(0, m.start() - 40):m.end() + 20])
        return values, bare

    # D01: la data dell'ultima osservazione nel report passa per `e(`
    def test_report_date_of_the_last_observation_is_escaped(self):
        values, bare = self._unescaped_value_uses(self._function_source("buildHtmlReport"), "observed_at", ("e",))

        assert values >= 1, "buildHtmlReport() never prints the date of the last real observation"
        assert not bare, f"observed_at reaches the report page without e(): {bare}"

    # D02: la stessa data nella scheda Intel passa per `esc(`
    def test_intel_tab_date_of_the_last_observation_is_escaped(self):
        values, bare = self._unescaped_value_uses(self._function_source("renderIntelTab"), "observed_at", ("esc",))

        assert values >= 1, "renderIntelTab() never prints the date of the last real observation"
        assert not bare, f"observed_at reaches the Intel tab without esc(): {bare}"

    # D03: i nomi vengono dall'elenco fisso delle parti, mai dalle chiavi dello snapshot
    def test_intel_tab_names_come_from_the_fixed_list_not_from_the_snapshot_keys(self):
        src = self._function_source("renderIntelTab")

        assert self._reads_the_fixed_part_list(src), "renderIntelTab() has no fixed list of the 11 carried parts"
        assert not re.search(r"Object\.(?:keys|entries|values)\(\s*[^()]*carried", src), \
            "renderIntelTab() takes names from the keys of the snapshot marker"
        assert not re.search(r"\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+[^)]*carried", src)

    # R3: lo stato DNS di «Module status» deriva dall'elenco fisso, non da `Object.keys(...)` del marcatore
    def test_report_module_status_counts_the_fixed_list_not_the_snapshot_keys(self):
        src = self._function_source("buildHtmlReport")

        assert not re.search(r"Object\.(?:keys|entries|values)\(\s*[^()]*carried", src), \
            "buildHtmlReport() counts the keys of the snapshot marker: a forged key reads as 'parti riportate'"
        assert not re.search(r"\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+[^)]*carried", src)
        assert self._reads_the_fixed_part_list(src), "buildHtmlReport() has no fixed list of the 11 carried parts"

    # D04: cercare la parola «riportato» nel sorgente della funzione non basta, compare anche nei
    # commenti e in variabili che restano vive se il comportamento viene tolto
    def test_report_module_status_dns_segment_says_riportate_for_a_carried_dns(self):
        src = self._function_source("buildHtmlReport")
        row = next((line for line in src.splitlines() if "Module status" in line), None)
        assert row, "'Module status' row not found in buildHtmlReport()"
        segment = re.search(r"DNS\s*\$\{([^}]*)\}", row)
        assert segment, f"the DNS segment of 'Module status' not found: {row.strip()}"
        expression = segment.group(1)
        # L'espressione e le definizioni degli identificatori che usa: ciò che decide cosa si legge.
        deciding = expression + " " + " ".join(
            self._definition(src, ident) for ident in set(re.findall(r"[A-Za-z_$][\w$]*", expression)))

        assert "riportat" in deciding.lower() and "carried" in deciding, (
            f"the DNS status of 'Module status' ({expression.strip()}) does not depend on the carried parts: "
            "a carried DNS section reads 'DNS ok'")

    # D07 e D08: le righe A e MX portano la nota «riportato»
    @pytest.mark.parametrize("label, part", [("A record", "A"), ("MX (email)", "MX")], ids=["A", "MX"])
    def test_report_row_carries_the_riportato_note(self, label, part):
        src = self._function_source("buildHtmlReport")
        row = re.search(rf"<td>{re.escape(label)}</td>\s*<td[^>]*>(.*?)</td>", src, re.S)
        assert row, f"the '{label}' row not found in buildHtmlReport()"

        notes = []
        for expression in self._interpolations(row.group(1)):
            call = re.fullmatch(rf'\s*(\w+)\(\s*"{part}"\s*\)\s*', expression)
            if call:
                body = self._definition(src, call.group(1))
                notes.append("carried" in body and "riportato" in body and "data ignota" in body)
        assert any(notes), f"the '{label}' cell has no call that adds the 'riportato' note for {part}"

    # D10: la riga «parti riportate» della scheda Intel c'è solo se ci sono parti riportate
    def test_intel_tab_row_of_the_carried_parts_is_guarded_by_the_carried_list(self):
        src = self._function_source("renderIntelTab")
        statement = re.search(r"dnsRows\s*\+=\s*`[^`]*riportat", src)
        assert statement, "renderIntelTab() has no dnsRows row that says 'riportat…'"
        guard = re.search(r"\bif\s*\(((?:[^()]|\([^()]*\))*)\)\s*\{?\s*$", src[:statement.start()])

        assert guard, "the row of the carried parts is not under an if"
        assert re.search(r"carried\w*", guard.group(1)) and re.search(r"length|some\(|size", guard.group(1)), (
            f"the guard of the carried-parts row ({guard.group(1).strip()}) does not look at the carried parts")

    # D2: il numero di cambiamenti della storia passa per `esc(` come ogni altro campo della riga
    def test_history_head_escapes_the_alert_count(self):
        src = self._function_source("renderIntelTab")

        assert not re.search(r"\$\{\s*h\.alert_count\s*\}", src), "${h.alert_count} is printed without esc()"
        assert re.search(r"\$\{\s*esc\(\s*(?:String\(\s*)?h\.alert_count\b", src), "h.alert_count never goes through esc()"


# ═══════════════════════════════════════════════════════════════
# COL-13 — un modulo riportato non si presenta come attuale (marcatore `carried_over` diretto)
# ═══════════════════════════════════════════════════════════════
#
# Criterio C7 di BUG-REGISTER.md («ASSEGNA · COL-13 · criteri di accettazione»). Per `cert`, `whois`,
# `http` e `reputation` l'orchestrator marca la sezione riportata con un campo DIRETTO
# `carried_over = {"observed_at", "carried_at"}` (il `dns` resta la mappa per parte di COL-12). La
# dashboard deve: far restituire «riportato» a `modStatus` per una sezione con marcatore valido
# (oggetto con `carried_at`) e solo per questi 4 moduli; scrivere nel report «(CT: riportato, ultima
# osservazione: <giorno> | data ignota)» e, in «Module status», «<MODULO> riportato»; aprire ciascuno
# dei 4 blocchi della scheda Intel con una riga muted «riportata»; passare per `e(`/`esc(` la data
# letta dal disco; lasciare invariata la resa DNS di COL-12.
#
# Come le altre classi di questo file, sono controlli STATICI sul sorgente SENZA commenti, su
# espressioni e sulle definizioni da cui dipendono (la funzione che decide cosa si legge, non una
# parola in un punto qualsiasi del file). Non provano che la resa sia corretta per un dato snapshot:
# un marcatore malformato che non deve cambiare nulla, o l'inversione di una condizione, si
# verificano con la resa vera in `tests/test_dashboard_render.py` (node, saltato se manca).

_C13_FOUR_MODULES = {"cert", "whois", "http", "reputation"}


class TestCOL13CarriedModuleIsShown:
    @staticmethod
    def _source(name):
        return TestCOL12CarriedOverIsShown._function_source(name)

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _top_level():
        """Le definizioni a livello superiore dello script (`const|let|var|function NOME`): nome ->
        corpo. Un `const` finisce alla prima riga che torna a colonna 0 senza essere una chiusura
        (`}`, `)`, `]`); una `function` alla sua `}` di chiusura. Corpi stretti: seguirli non deve
        trascinare dentro il resto dello script."""
        script = _dashboard_script()
        index = {}
        for m in re.finditer(r"^(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=|function\s+([A-Za-z_$][\w$]*)\s*\()",
                             script, re.M):
            if m.group(2):
                end = script.find("\n}", m.end())
            else:
                stop = re.search(r"\n(?![ \t}\])])", script[m.end():])
                end = m.end() + stop.start() if stop else len(script)
            index.setdefault(m.group(1) or m.group(2), script[m.end():end])
        return index

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def _body(ident, scope):
        """La definizione di `ident`: `const|let|var` nello `scope` (sorgente della funzione che lo usa),
        oppure a livello superiore dello script. Stringa vuota se non c'è."""
        body = TestCOL12CarriedOverIsShown._definition(scope, ident)
        if body:
            return body
        nested = re.search(rf"^([ \t]*)function\s+{re.escape(ident)}\s*\(", scope, re.M)
        if nested:
            end = scope.find("\n" + nested.group(1) + "}", nested.end())
            return scope[nested.end():end if end >= 0 else len(scope)]
        later = re.search(rf",\s*{re.escape(ident)}\s*=(?!=)([^\n]*)", scope)    # `const a = ..., ident = ...`
        if later:
            return later.group(1)
        return TestCOL13CarriedModuleIsShown._top_level().get(ident, "")

    @classmethod
    def _deciding_parts(cls, expression, scope, depth=4):
        """L'espressione e, una per elemento, le definizioni degli identificatori che usa, a cascata
        per `depth` livelli: tutto ciò da cui dipende cosa viene scritto. Non si scorrono i nomi
        senza definizione (proprietà, parole chiave)."""
        parts, seen, frontier = [expression], set(), [expression]
        for _ in range(depth):
            found = []
            for ident in sorted({i for text in frontier for i in re.findall(r"[A-Za-z_$][\w$]*", text)} - seen):
                seen.add(ident)
                body = cls._body(ident, scope)
                if body:
                    found.append(body)
            parts += found
            frontier = found
        return parts

    @classmethod
    def _deciding(cls, expression, scope, depth=4):
        """Le parti di `_deciding_parts` in un solo testo."""
        return " ".join(cls._deciding_parts(expression, scope, depth))

    @staticmethod
    def _has_the_four_module_list(text):
        """True se `text` contiene un array letterale di sole stringhe che sono ESATTAMENTE i 4 moduli."""
        for m in re.finditer(r"""\[\s*(?:"[^"]*"|'[^']*')(?:\s*,\s*(?:"[^"]*"|'[^']*'))*\s*\]""", text):
            if set(re.findall(r"""["']([^"']*)["']""", m.group(0))) == _C13_FOUR_MODULES:
                return True
        return False

    @staticmethod
    def _unescaped_uses(text, field, escapers=("e", "esc")):
        """Gli usi di `.field` in `text` come VALORE (non come test di un ternario o di un `&&`) che non
        sono l'argomento di `e(`/`esc(`, anche dentro `String(...)` e con un'espressione di chiamata
        come `marker('cert', i.cert).observed_at`. Ritorna (n. usi come valore, contesti non escapati)."""
        values, bare = 0, []
        for m in re.finditer(rf"\.{field}\b", text):
            if re.match(r"\s*(?:\?|&&|\|\||[!=]==?)", text[m.end():m.end() + 8]):
                continue
            values += 1
            head = text[max(0, m.start() - 120):m.start()]
            if not re.search(rf"\b(?:{'|'.join(escapers)})\(\s*(?:String\(\s*)?(?:[\w$\[\].]|\([^()]*\))*$", head):
                bare.append(text[max(0, m.start() - 40):m.end() + 20])
        return values, bare

    def _mod_status(self):
        scope = self._source("buildHtmlReport")
        body = self._body("modStatus", scope)
        assert body, "modStatus() not found in buildHtmlReport() or at the top level of the script"
        return scope, body

    # ── modStatus ────────────────────────────────────────────────────────────

    def test_mod_status_says_riportato_for_a_section_with_a_valid_marker(self):
        scope, body = self._mod_status()
        deciding = self._deciding(body, scope)

        assert "riportato" in deciding, "modStatus() never returns 'riportato'"
        assert re.search(r"\bcarried_over\b[^;\n]*\bcarried_at\b", deciding), (
            "modStatus() does not look for carried_at inside carried_over: a malformed marker "
            "(string, array, object without carried_at) would read 'riportato'")

    def test_mod_status_keeps_its_three_old_answers(self):
        # Controllo, verde anche prima del fix.
        _, body = self._mod_status()

        for answer in ("non raccolto", "errore", "ok"):
            assert re.search(rf"""["']{answer}["']""", body), f"modStatus() lost the answer '{answer}'"
        assert ".error" in body, "modStatus() no longer reads the error field of the section"

    def test_the_marker_is_honoured_only_for_the_four_fixed_modules(self):
        # Il DNS ha un marcatore di forma diversa (mappa per parte): una voce `carried_at` forgiata
        # in `dns.carried_over` non deve far leggere «DNS riportato». O lo stato DNS non passa dal
        # controllo del marcatore, oppure quel controllo è vincolato all'elenco fisso dei 4 moduli.
        scope, _ = self._mod_status()
        row = next((line for line in scope.splitlines() if "Module status" in line), None)
        assert row, "'Module status' row not found in buildHtmlReport()"
        segment = re.search(r"DNS\s*\$\{([^}]*)\}", row)
        assert segment, f"the DNS segment of 'Module status' not found: {row.strip()}"
        dns_chain = self._deciding(segment.group(1), scope)

        assert "carried_at" not in dns_chain or self._has_the_four_module_list(dns_chain), (
            "the DNS status depends on the module marker check, which is not limited to "
            "['cert', 'whois', 'http', 'reputation']")

    # ── Nome del modulo, obbligatorio: senza, `modStatus` non vede il marcatore e torna «ok» ──

    @pytest.mark.parametrize("label, section", [
        ("WHOIS", "whois"), ("HTTP", "http"), ("reputation", "reputation")], ids=["whois", "http", "reputation"])
    def test_module_status_row_passes_each_module_its_own_section_and_its_own_name(self, label, section):
        # Il nome del modulo è obbligatorio: `modStatus(i.whois)` senza nome non riconosce il
        # marcatore, quindi la riga direbbe «WHOIS ok» per un dato riportato.
        scope, _ = self._mod_status()
        row = next((line for line in scope.splitlines() if "Module status" in line), "")

        assert re.search(
            rf"""{label}\s*\$\{{\s*modStatus\(\s*i\.{section}\s*,\s*["']{section}["']\s*\)\s*\}}""", row), (
            f"'Module status' does not read {label} from modStatus(i.{section}, \"{section}\"): {row.strip()}")

    @staticmethod
    def _module_tokens(key):
        return {"cert": r"cert", "whois": r"whois", "http": r"http", "reputation": r"rep"}[key]

    def _assert_names_match_sections(self, text, where):
        """Ogni chiamata `f(sezione, "modulo")` (o `f("modulo", sezione)`) di `text` passa al modulo la
        propria sezione: `modNote(whois, "cert")` sarebbe la nota dei certificati letta dal WHOIS.
        Ritorna le coppie (sezione, modulo) trovate."""
        literal = r"""(?P<q>["'])(?P<k>cert|whois|http|reputation)(?P=q)"""
        call = r"[A-Za-z_$][\w$]*\(\s*"
        pairs = [(m.group("s"), m.group("k")) for pattern in (
            rf"""{call}(?P<s>[^(),"']+?)\s*,\s*{literal}\s*\)""",
            rf"""{call}{literal}\s*,\s*(?P<s>[^(),"']+?)\s*\)""") for m in re.finditer(pattern, text)]
        for section, key in pairs:
            assert re.search(self._module_tokens(key), section, re.I), (
                f"{where}: the section '{section.strip()}' is passed with the module name \"{key}\"")
        return pairs

    # ── Report: riga Certificates ────────────────────────────────────────────

    def _certificates_row(self):
        scope, _ = self._mod_status()
        row = re.search(r"<tr><td>Certificates</td><td>(.*?)</td></tr>", scope, re.S)
        assert row, "the Certificates row not found in buildHtmlReport()"
        expressions = TestCOL12CarriedOverIsShown._interpolations(row.group(1))
        return scope, row.group(1), [part for x in expressions for part in self._deciding_parts(x, scope)]

    def test_certificates_row_says_the_last_observation_or_data_ignota(self):
        # Il nome è obbligatorio: `modStatus(i.cert)` senza nome direbbe «CT: ok» per un dato riportato.
        _, row, parts = self._certificates_row()
        deciding = " ".join(parts)

        assert re.search(r"""modStatus\(\s*i\.cert\s*,\s*["']cert["']\s*\)""", row), (
            "the CT status of the Certificates row is not modStatus(i.cert, \"cert\")")
        assert "ultima osservazione" in deciding, "the Certificates row never says 'ultima osservazione'"
        assert "data ignota" in deciding, "the Certificates row has no fallback for observed_at null"
        assert "observed_at" in deciding, "the Certificates row never reads observed_at"
        assert re.search(r"slice\(\s*0\s*,\s*10\s*\)", deciding), "the date of the Certificates row is not cut to the day"

    def test_certificates_row_reads_the_marker_of_the_certificates_section(self):
        _, row, parts = self._certificates_row()

        pairs = self._assert_names_match_sections(row + " " + " ".join(parts), "Certificates row")
        assert ("i.cert", "cert") in [(a.strip(), k) for a, k in pairs], pairs

    def test_module_status_row_names_match_their_sections(self):
        scope, _ = self._mod_status()
        row = next((line for line in scope.splitlines() if "Module status" in line), "")

        self._assert_names_match_sections(row, "Module status row")

    # ── modStatus: precedenza e guardia del marcatore ────────────────────────

    def test_mod_status_gives_errore_the_precedence_over_riportato(self):
        # Una sezione con `error` si legge «errore» anche se porta un marcatore (disco forgiato o
        # versioni miste): «riportato» non deve nascondere un guasto.
        scope, body = self._mod_status()
        error_at = body.find(".error")
        marker_at = [body.find("riportato")]
        marker_at += [m.start() for m in re.finditer(r"([A-Za-z_$][\w$]*)\(", body)
                      if "riportato" in self._body(m.group(1), scope)]
        marker_at = [pos for pos in marker_at if pos >= 0]

        assert error_at >= 0 and marker_at, "modStatus() does not read the error field or never says 'riportato'"
        assert error_at < min(marker_at), "modStatus() decides 'riportato' before looking at the error of the section"

    def test_the_marker_guard_requires_carried_at_to_be_truthy(self):
        # Marcatore valido = oggetto con `carried_at`: la condizione è la congiunzione POSITIVA
        # `... && x.carried_over.carried_at`, oppure l'uscita anticipata su `!x.carried_over.carried_at`.
        # Una guardia invertita («solo se manca carried_at») rovescerebbe tutto il comportamento.
        scope, body = self._mod_status()
        deciding = self._deciding(body, scope)

        assert (re.search(r"&&\s*[\w$.]+\.carried_over\.carried_at\b", deciding)
                or re.search(r"if\s*\([^)]*![\w$.]+\.carried_over\.carried_at\s*\)\s*return\s+(?:null|false|undefined)",
                             deciding)), "the marker guard is not 'carried_over && carried_over.carried_at'"

    # ── Scheda Intel: una riga «riportata» in testa a ciascuno dei 4 blocchi ──

    BLOCKS = [("http", "http"), ("certificates", "cert"), ("whois", "whois"), ("reputation", "reputation")]

    def _first_in_block(self, block):
        scope = self._source("renderIntelTab")
        template = scope[scope.rfind("return `"):]
        section = re.search(rf'data-sec="{block}">(.*?)(?=<div class="intel-sec"|$)', template, re.S)
        assert section, f"the {block} block not found in the template of renderIntelTab()"
        after_title = re.sub(r'^.*?class="block-title">[^<]*</div>', "", section.group(1), count=1, flags=re.S)
        interpolations = TestCOL12CarriedOverIsShown._interpolations(after_title)
        assert interpolations, f"the {block} block has no content after its title"
        return scope, interpolations[0]

    @pytest.mark.parametrize("block, key", BLOCKS, ids=[b for b, _ in BLOCKS])
    def test_intel_block_opens_with_the_riportata_note(self, block, key):
        # Il modulo si riconosce dalla coppia (sezione, nome) passata alla nota, non da una stringa
        # qualsiasi: `modNote(cert, "http")` aprirebbe il blocco http con la nota letta dalla sezione sbagliata.
        scope, first = self._first_in_block(block)
        parts = self._deciding_parts(first, scope)
        deciding = " ".join(parts)

        pairs = self._assert_names_match_sections(deciding, f"{block} block")
        assert key in [k for _, k in pairs], f"the note of the {block} block is not built for the module \"{key}\""
        assert "riportata dal ciclo precedente" in deciding, (
            f"the {block} block does not start with a 'riportata dal ciclo precedente' note (it starts with {first.strip()})")
        assert re.search(r"\bcarried_over\b[^;\n]*\bcarried_at\b", deciding), (
            f"the 'riportata' note of {block} does not require a marker with carried_at")
        assert "muted" in deciding, f"the 'riportata' note of {block} is not muted"
        assert re.search(r"slice\(\s*0\s*,\s*16\s*\)", deciding), f"the date of the {block} note is not cut to the minute"
        assert re.search(r"""replace\(\s*["']T["']\s*,\s*["'] ["']\s*\)""", deciding), (
            f"the date of the {block} note keeps the 'T' separator (the DNS row of the Intel tab shows 'AAAA-MM-GG HH:MM')")

    @pytest.mark.parametrize("block, key", BLOCKS, ids=[b for b, _ in BLOCKS])
    def test_intel_note_appears_only_when_the_marker_condition_is_true(self, block, key):
        # Nel ramo «vero» di un ternario o di un `&&`, la condizione deve avere almeno un operando
        # positivo che non sia una costante (`false`) e non sia negato (`!mark`). Un'inversione più
        # sottile della stessa condizione resta fuori da un controllo statico.
        scope, first = self._first_in_block(block)
        for part in self._deciding_parts(first, scope):
            template = re.search(r"`[^`]*riportata dal ciclo precedente", part)
            if not template:
                continue
            prefix = part[:template.start()].rstrip()
            if not prefix.endswith(("?", "&&")):
                continue                  # la nota è il ramo «altrimenti»: la polarità non si legge a vista
            test = re.search(r"(?:return|=>|[=(,{;:])\s*([^;{}]*?)$", prefix[:-1].rstrip() if prefix.endswith("?") else prefix[:-2],
                             re.S)
            operands = [re.sub(r"^(?:return\b|=>)\s*", "", o.strip()) for o in re.split(r"&&|\|\|", test.group(1) if test else "")]
            condition = test.group(1).strip() if test else ""
            positive = [o for o in operands if o and not o.startswith("!") and ".error" not in o
                        and o not in ("false", "true", "null", "undefined", "0", "1")]
            assert positive, f"the {block} note is shown under a condition with no positive operand: {condition}"
            # Se la stessa condizione guarda `error`, la nota esce solo quando NON c'è: `&& !x.error`.
            # Condizioni con parentesi (`!(x && x.error)`) non si leggono a vista e restano fuori.
            if ".error" in condition and "(" not in condition:
                assert "||" not in condition, f"the {block} note condition mixes error with '||': {condition}"
                assert all(o.startswith("!") for o in operands if ".error" in o), (
                    f"the {block} note is shown when the section HAS an error: {condition}")

    @pytest.mark.parametrize("block, key", BLOCKS, ids=[b for b, _ in BLOCKS])
    def test_intel_note_is_silent_for_a_section_with_an_error(self, block, key):
        # Nel report vince «errore» (modStatus guarda `error` prima del marcatore): la scheda Intel non
        # deve mostrare la nota «riportata» sopra una sezione che dichiara un guasto.
        scope, first = self._first_in_block(block)
        parts = self._deciding_parts(first, scope)

        assert any(".error" in part for part in parts), (
            f"the note of the {block} block never looks at the error of the section")
        for part in parts:
            if "riportata dal ciclo precedente" in part and ".error" in part:
                assert part.index(".error") < part.index("riportata dal ciclo precedente"), (
                    f"the {block} note decides 'riportata' before looking at the error of the section")

    # ── observed_at viene da un file su disco: solo una stringa si stampa, altrimenti «data ignota» ──

    @classmethod
    def _unguarded_observed_at(cls, part, scope):
        """I contesti in cui `part` usa `.observed_at` come VALORE senza passare da una guardia
        `typeof <stessa espressione> === "string"` nello stesso ramo, né da un helper che la contiene.
        Ritorna (n. usi come valore, contesti senza guardia)."""
        values, bad = 0, []
        for m in re.finditer(r"\.observed_at\b", part):
            if re.match(r"\s*(?:\?|&&|\|\||[!=]==?)", part[m.end():m.end() + 8]):
                continue                  # test di un ternario o confronto, compresa la guardia stessa
            values += 1
            before = part[:m.start()]
            receiver = re.search(r"[A-Za-z_$][\w$]*(?:\[[^\]]*\]|\.[A-Za-z_$][\w$]*)*$", before)
            expression = (receiver.group(0) if receiver else "") + ".observed_at"
            head = before[max(0, len(before) - 250):]
            if re.search(rf"""typeof\s*\(?\s*{re.escape(expression)}\s*\)?\s*===\s*["']string["'][^:;]*$""", head):
                continue
            helper = re.search(r"([A-Za-z_$][\w$]*)\(\s*$", before[:receiver.start()] if receiver else before)
            if helper:
                body = cls._body(helper.group(1), scope)
                if "typeof" in body and re.search(r"""["']string["']""", body):
                    continue
            bad.append(part[max(0, m.start() - 60):m.end() + 30])
        return values, bad

    def test_every_value_use_of_observed_at_goes_through_a_string_guard(self):
        # `String(x)` solleva se `x` è un oggetto con un `toString` proprio non callabile: un
        # `observed_at` scritto a mano nello snapshot romperebbe report e scheda di tutto il cliente.
        script = _dashboard_script()

        values, bad = self._unguarded_observed_at(script, script)

        assert values >= 4, "expected the four sites that print observed_at"
        assert not bad, f"observed_at is used as a value without a string guard: {bad}"

    SITES = [
        pytest.param("report-ct", id="report-ct"), pytest.param("report-dns", id="report-dns"),
        pytest.param("intel-http", id="intel-http"), pytest.param("intel-cert", id="intel-cert"),
        pytest.param("intel-whois", id="intel-whois"), pytest.param("intel-reputation", id="intel-reputation"),
        pytest.param("intel-dns", id="intel-dns"),
    ]

    def _site_parts(self, site):
        if site == "report-ct":
            scope, _, parts = self._certificates_row()
            return scope, parts
        if site == "report-dns":
            scope = self._source("buildHtmlReport")
            row = re.search(r"<td>A record</td>\s*<td[^>]*>(.*?)</td>", scope, re.S)
            assert row, "the 'A record' row not found in buildHtmlReport()"
            call = next((x for x in TestCOL12CarriedOverIsShown._interpolations(row.group(1))
                         if re.fullmatch(r"""\s*\w+\(\s*"A"\s*\)\s*""", x)), None)
            assert call, "the 'A record' row has no note call"
            return scope, self._deciding_parts(call, scope)
        if site == "intel-dns":
            scope = self._source("renderIntelTab")
            row = re.search(r"dnsRows\s*\+=\s*`[^`]*parti riportate dal ciclo precedente[^`]*`", scope)
            assert row, "the DNS row of the carried parts not found in renderIntelTab()"
            return scope, [part for x in TestCOL12CarriedOverIsShown._interpolations(row.group(0))
                           for part in self._deciding_parts(x, scope)]
        block = {"intel-http": "http", "intel-cert": "certificates", "intel-whois": "whois",
                 "intel-reputation": "reputation"}[site]
        scope, first = self._first_in_block(block)
        return scope, self._deciding_parts(first, scope)

    @pytest.mark.parametrize("site", SITES)
    def test_each_site_prints_observed_at_only_through_a_string_guard_and_says_data_ignota_otherwise(self, site):
        scope, parts = self._site_parts(site)

        counted = [self._unguarded_observed_at(part, scope) for part in parts]
        assert sum(v for v, _ in counted) >= 1, f"{site}: the site never prints observed_at"
        assert not [b for _, bad in counted for b in bad], (
            f"{site}: observed_at is printed without a string guard: {[b for _, bad in counted for b in bad]}")
        assert "data ignota" in " ".join(parts), f"{site}: no 'data ignota' fallback"

    # ── La data letta dal disco passa per l'escape ───────────────────────────

    @pytest.mark.parametrize("field", ["observed_at", "carried_at"])
    def test_every_instant_read_from_the_marker_is_escaped(self, field):
        # Su tutto lo script, non solo sulle due funzioni: la resa può stare in un helper. Include
        # la resa DNS di COL-12 (`e(` nel report, `esc(` nella scheda Intel). Un uso come VALORE (non
        # come test di un ternario o di un `&&`) deve essere l'argomento di `e(`/`esc(`.
        _, bare = self._unescaped_uses(_dashboard_script(), field)

        assert not bare, f"{field} reaches the page without e()/esc(): {bare}"

    def test_the_report_prints_the_observation_date_of_a_carried_certificate_escaped(self):
        scope, _ = self._mod_status()
        row = re.search(r"<tr><td>Certificates</td><td>(.*?)</td></tr>", scope, re.S)
        assert row, "the Certificates row not found in buildHtmlReport()"
        deciding = " ".join(self._deciding(x, scope) for x in TestCOL12CarriedOverIsShown._interpolations(row.group(1)))
        values, bare = self._unescaped_uses(deciding, "observed_at", ("e",))

        assert values >= 1, "the Certificates row never prints the date of the last real observation"
        assert not bare, f"the Certificates row prints observed_at without e(): {bare}"

    # ── La resa DNS di COL-12 non cambia ─────────────────────────────────────

    def test_the_dns_rendering_of_col_12_is_still_there(self):
        # Controllo, verde anche prima del fix: il marcatore dei moduli si affianca, non sostituisce.
        report, intel = self._source("buildHtmlReport"), self._source("renderIntelTab")

        assert 'carriedNote("A")' in report and 'carriedNote("MX")' in report
        assert "parti riportate" in report
        assert "DNS_CARRY_PARTS.some(" in report
        assert "parti riportate dal ciclo precedente" in intel and "DNS_CARRY_PARTS" in intel


# ═══════════════════════════════════════════════════════════════
# Sentinella per `_strip_js_comments`
# ═══════════════════════════════════════════════════════════════
#
# I controlli statici di COL-12 e COL-13 cercano nel sorgente SENZA commenti. `_strip_js_comments` è un
# lexer approssimato: una regex letterale con un apice, o con `//`, dopo `return`, `typeof`, `)` o `}`
# viene scambiata per una divisione; da lì stringhe e commenti sono letti a rovescio e i commenti
# restano nel sorgente «spogliato». Un controllo del tipo «il codice legge `carried_over`» sarebbe
# allora soddisfatto da un commento. Queste asserzioni fanno rumore se il lexer sbaglia sul file vero.

class TestStripJsCommentsSentinel:
    # Un commento di riga (`//` a inizio riga o dopo uno spazio) o di blocco: fuori dalle stringhe, nel
    # sorgente spogliato non ne resta nessuno. `https://` e i testi tra apici non corrispondono.
    COMMENT = re.compile(r"(?:^|\s)//|/\*|\*/")

    @classmethod
    def _survivors(cls, source):
        return [line.strip() for line in source.splitlines() if cls.COMMENT.search(line)]

    @pytest.mark.parametrize("name", ["buildHtmlReport", "renderIntelTab"])
    def test_no_comment_survives_in_the_functions_the_static_tests_read(self, name):
        survivors = self._survivors(TestCOL12CarriedOverIsShown._function_source(name))

        assert not survivors, f"{name}(): _strip_js_comments left comments in the source: {survivors[:3]}"

    def test_no_comment_survives_anywhere_in_the_script(self):
        survivors = self._survivors(_dashboard_script())

        assert not survivors, f"_strip_js_comments left comments in the script: {survivors[:3]}"

    def test_the_html_escape_regex_literal_survives_the_stripping_intact(self):
        # `/[&<>"']/g` contiene entrambi gli apici: se il lexer lo scambia per una divisione apre una
        # stringa e legge a rovescio tutto ciò che segue.
        assert '.replace(/[&<>"\']/g,' in _dashboard_script()
