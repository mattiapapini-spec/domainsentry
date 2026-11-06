"""Tests for shared/utils.py"""

import gzip
import http.server
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

from shared.utils import (
    is_valid, content_hash, normalize_html_for_fingerprint,
    extract_visible_text, detect_suspicious_patterns,
    detect_hidden_elements, now_iso, is_check_due,
)


class TestIsValid:
    def test_valid_records(self):
        assert is_valid(["93.184.216.34"]) is True

    def test_empty_list(self):
        assert is_valid([]) is False

    def test_empty_string(self):
        assert is_valid([""]) is False

    def test_error_message(self):
        assert is_valid(["ERROR: timeout"]) is False

    def test_multiple_records(self):
        assert is_valid(["1.2.3.4", "5.6.7.8"]) is True


class TestContentHash:
    def test_string_input(self):
        h = content_hash("hello")
        assert len(h) == 64  # sha256 hex

    def test_bytes_input(self):
        h = content_hash(b"hello")
        assert len(h) == 64

    def test_deterministic(self):
        assert content_hash("test") == content_hash("test")

    def test_different_input(self):
        assert content_hash("a") != content_hash("b")


class TestNormalizeHtml:
    def test_removes_scripts(self):
        html = '<p>Hello</p><script>alert(1)</script><p>World</p>'
        result = normalize_html_for_fingerprint(html)
        assert "alert" not in result
        assert "Hello" in result

    def test_removes_styles(self):
        html = '<style>body{color:red}</style><p>Text</p>'
        result = normalize_html_for_fingerprint(html)
        assert "color:red" not in result

    def test_removes_timestamps(self):
        html = '<p>Generated 1714200000000</p>'
        result = normalize_html_for_fingerprint(html)
        assert "1714200000000" not in result

    def test_removes_hashes(self):
        html = '<p>Token: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4</p>'
        result = normalize_html_for_fingerprint(html)
        assert "a1b2c3d4e5f6" not in result

    def test_collapses_whitespace(self):
        html = '<p>  lots   of    space  </p>'
        result = normalize_html_for_fingerprint(html)
        assert "  " not in result


class TestExtractVisibleText:
    def test_strips_tags(self):
        html = '<div><p>Hello <b>World</b></p></div>'
        assert "Hello" in extract_visible_text(html)
        assert "<div>" not in extract_visible_text(html)

    def test_strips_scripts(self):
        html = '<p>Visible</p><script>hidden()</script>'
        text = extract_visible_text(html)
        assert "Visible" in text
        assert "hidden" not in text


class TestDetectSuspiciousPatterns:
    def test_detects_password_field(self):
        html = '<input type="password" name="pwd">'
        findings = detect_suspicious_patterns(html, [r"password|passwd|pwd"])
        assert len(findings) > 0

    def test_no_false_positive(self):
        html = '<p>Welcome to our website</p>'
        findings = detect_suspicious_patterns(html, [r"password|passwd|pwd"])
        assert len(findings) == 0

    def test_invalid_regex_handled(self):
        html = '<p>test</p>'
        findings = detect_suspicious_patterns(html, [r"[invalid"])
        assert len(findings) == 0


class TestDetectHiddenElements:
    def test_hidden_form(self):
        html = '<form style="display:none" action="https://evil.com/steal.php"><input type="text"></form>'
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms")
        assert result["risk_indicators"] >= 30

    def test_invisible_iframe_zero_size(self):
        html = '<iframe src="https://evil.com" width="0" height="0"></iframe>'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        assert result["risk_indicators"] >= 25

    def test_invisible_iframe_css(self):
        html = '<iframe src="https://evil.com" style="display:none"></iframe>'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")

    def test_tracking_pixel(self):
        html = '<img src="https://tracker.com/px.gif" width="1" height="1">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")

    def test_meta_redirect(self):
        html = '<meta http-equiv="refresh" content="0;url=https://phishing.com">'
        result = detect_hidden_elements(html)
        assert result.get("meta_redirects")
        assert result["meta_redirects"][0]["target_url"] == "https://phishing.com"

    def test_obfuscated_js_eval(self):
        html = '<script>eval(atob("YWxlcnQoMSk="))</script>'
        result = detect_hidden_elements(html)
        assert result.get("obfuscated_js")
        indicators = result["obfuscated_js"][0]["indicators"]
        assert "eval" in indicators
        assert "atob_base64" in indicators

    def test_hidden_div_with_form(self):
        html = '<div style="display:none"><form action="/login"><input type="password">This is a hidden credential form</form></div>'
        result = detect_hidden_elements(html)
        assert result.get("hidden_divs_with_content")
        assert result["hidden_divs_with_content"][0]["contains_form"] is True

    def test_large_comment_with_code(self):
        html = '<!-- <script>function steal(){document.cookie}</script>' + 'x' * 200 + ' -->'
        result = detect_hidden_elements(html)
        assert result.get("large_comments")
        assert result["large_comments"][0]["contains_javascript"] is True

    def test_clean_page(self):
        html = '<html><head><title>Hello</title></head><body><p>Clean page</p></body></html>'
        result = detect_hidden_elements(html)
        assert result["risk_indicators"] == 0

    def test_legitimate_hidden_input(self):
        """A single hidden input (CSRF token) should not trigger high risk."""
        html = '<form><input type="hidden" name="csrf_token" value="abc123"><input type="text" name="search"></form>'
        result = detect_hidden_elements(html)
        # Should have hidden_inputs but risk should be low (<=3 hidden inputs)
        assert result.get("hidden_inputs")
        assert result["risk_indicators"] < 15

    def test_invisible_iframe_self_closing_no_space(self):
        """CLS-01g. Self-closing XHTML-style iframe with no space before '/>'
        must still be recognized as an invisible iframe. The current pattern
        `<iframe[^>]*>(.*?)</iframe>` requires a literal `</iframe>` closing
        tag and never matches a self-closing element, producing a total
        false negative on a malicious hidden iframe."""
        html = '<iframe src="https://evil.com" width="0" height="0"/>'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        assert result["risk_indicators"] >= 25

    def test_invisible_iframe_self_closing_with_space(self):
        """CLS-01g. Same self-closing form, but with a space before '/>'
        (the more common XHTML style)."""
        html = '<iframe src="https://evil.com" width="0" height="0" />'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        assert result["risk_indicators"] >= 25

    def test_invisible_iframe_self_closing_attribute_order(self):
        """CLS-01g. Self-closing iframe with attributes in a different order
        (src last) must not affect detection."""
        html = '<iframe height="0" width="0" src="https://evil.com"/>'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        found_srcs = [f.get("src") for f in result["invisible_iframes"]]
        assert "https://evil.com" in found_srcs

    def test_invisible_iframe_not_truncated_by_slash_gt_in_attribute_value(self):
        """CLS-01g (second round). The self-closing alternative added in the
        first fix (`<iframe[^>]*/>`) is tried FIRST in the `|` alternation,
        and Python's re alternation is ordered, not longest-match: as soon
        as ANY attribute value contains the literal substring '/>' before the
        revealing attributes (width/height/src), the self-closing branch
        matches up to that '/>' and truncates the tag there — src, width and
        height (which come later in the real tag) end up outside the match
        entirely. This is a non-self-closing, `</iframe>`-terminated iframe
        that the pre-fix code correctly recognized as invisible; it must
        still be recognized now."""
        html = ('<iframe data-x="a/>b" width="0" height="0" '
                'src="https://evil.com">payload</iframe>')
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        found_srcs = [f.get("src") for f in result["invisible_iframes"]]
        assert "https://evil.com" in found_srcs

    def test_invisible_iframe_srcdoc_with_embedded_self_closing_tag(self):
        """CLS-01g (second round). `srcdoc` is a standard HTML5 iframe
        attribute (common in phishing kits that inline a spoofed page) whose
        value can itself contain a self-closing tag such as `<img src=x/>`.
        The literal '/>' inside that value must not truncate the outer
        iframe match before the real width/height/src attributes are seen."""
        html = ('<iframe srcdoc="<img src=x/>" width="0" height="0" '
                'src="https://evil.com/collect">stolen creds relay</iframe>')
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        found_srcs = [f.get("src") for f in result["invisible_iframes"]]
        assert "https://evil.com/collect" in found_srcs

    def test_invisible_iframe_true_self_closing_with_slash_gt_in_attribute(self):
        """CLS-01g (second round), positive control. A genuinely
        self-closing iframe whose own attribute value happens to contain the
        substring '/>' (e.g. an escaped/encoded fragment stashed in a data
        attribute) must still be detected — the fix must not overcorrect by
        dropping the self-closing case that the first round of CLS-01g was
        meant to cover."""
        html = ('<iframe data-note="a/>b" width="0" height="0" '
                'src="https://evil.com/beacon"/>')
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        found_srcs = [f.get("src") for f in result["invisible_iframes"]]
        assert "https://evil.com/beacon" in found_srcs

    def test_invisible_iframe_unquoted_src_with_query_string_equals(self):
        """CLS-01g (third round). The second-round fix consumes attributes one
        by one with an explicit grammar, but an UNQUOTED value is only allowed
        to contain characters outside {space, ", ', =, <, >} — it treats '='
        as a value terminator, i.e. as if it could only ever start a new
        attribute. A real, unquoted `src` whose querystring contains its own
        '=' (extremely common: `?a=1`, `?token=...`) is therefore not a valid
        value for the grammar. Because every quantifier in the per-attribute
        group is possessive (no backtracking allowed), the parser doesn't fall
        back to treating the rest as plain text either: the whole `<iframe
        ...>` match fails to occur at all, and a browser-valid, genuinely
        invisible iframe becomes a complete false negative — a worse
        regression than the original bug this rule chain was meant to fix.
        Browsers accept this markup without complaint."""
        html = ('<iframe src=https://evil.example.com/path/x?a=1 '
                'width=0 height=0></iframe>')
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        found_srcs = [f.get("src") for f in result["invisible_iframes"]]
        assert "https://evil.example.com/path/x?a=1" in found_srcs

    def test_invisible_iframe_orphan_equals_attribute(self):
        """CLS-01g (third round). An attribute with a trailing '=' and no
        value at all (a stray/malformed `data-x=` before whitespace — browsers
        tolerate this and simply treat the value as empty) cannot be consumed
        by the per-attribute grammar: the optional `=value` group requires at
        least one value character (quoted or not) to match, so it matches zero
        times, leaving the bare '=' unconsumed. The following repetition
        requires whitespace before the next attribute name, but the very next
        character is '=', so the whole attribute list — and therefore the
        entire `<iframe ...>` match — fails at that point, again due to
        possessive (non-backtracking) quantifiers. The real `src` that follows
        is invisible to the detector even though it is preceded only by one
        malformed attribute."""
        html = ('<iframe data-x= width="0" height="0" '
                'src="https://evil.com"></iframe>')
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        found_srcs = [f.get("src") for f in result["invisible_iframes"]]
        assert "https://evil.com" in found_srcs

    def test_invisible_iframe_unquoted_value_with_apostrophe(self):
        """CLS-01g (third round). Browser HTML tokenizers treat an unquoted
        attribute value as everything up to the next whitespace or '>' — a
        stray apostrophe or double quote inside it (e.g. `alt=it's`, common in
        hand-written or templated markup) does NOT start a quoted value and
        does NOT terminate the unquoted one. The per-attribute grammar here
        disagrees: unquoted values explicitly exclude `'` and `"`, so the
        attribute fails to match past `it`, the possessive quantifiers forbid
        backtracking to recover, and the whole tag — including the real
        `src`/`width`/`height` that make it invisible — is never matched."""
        html = ("<iframe src=https://evil.com/relay width=0 height=0 "
                "alt=it's tracking></iframe>")
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        found_srcs = [f.get("src") for f in result["invisible_iframes"]]
        assert "https://evil.com/relay" in found_srcs

    def test_invisible_iframe_duplicate_dimension_attrs_first_wins(self):
        """CLS-01g (4° giro). Per la spec HTML5 (e nel comportamento dei
        browser reali), quando un tag ha lo stesso attributo ripetuto vince
        il PRIMO valore incontrato; ogni occorrenza successiva viene
        ignorata dal tokenizer. `_TagCollector._collect` costruisce invece
        `{name.lower(): value for name, value in attrs}`: in una dict
        comprehension una chiave ripetuta viene sovrascritta dall'ULTIMA
        occorrenza, non dalla prima. Un iframe con `width="0" width="400"
        height="0" height="300"` viene quindi renderizzato 0x0 (invisibile)
        da qualunque browser, ma il detector — leggendo 400/300 dal dict —
        non lo segnala affatto: evasione totale della regola zero_dimension."""
        html = ('<iframe src="https://evil-c2.example.net/beacon" '
                'width="0" width="400" height="0" height="300"></iframe>')
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes"), (
            "iframe 0x0 per il browser (primo width/height vince) non rilevato come invisibile"
        )
        techniques = result["invisible_iframes"][0].get("technique", [])
        assert "zero_dimension" in techniques

    def test_invisible_iframe_duplicate_src_attr_reports_first_value(self):
        """CLS-01g (4° giro). Stesso difetto della dict comprehension
        (ultimo-vince invece di primo-vince), ma sull'attributo `src`: un
        iframe con `src` duplicato viene renderizzato dal browser con il
        PRIMO valore — il secondo è markup morto. Un kit di phishing può
        sfruttarlo per nascondere il vero endpoint C2 dietro un secondo
        `src` "decoy" che il detector riporta come IOC al posto di quello
        realmente attivo: l'alert CRITICAL `legit_invisible_iframe_detected`
        finirebbe con l'indicatore sbagliato in mano all'analista."""
        html = ('<iframe src="https://evil-c2.example.net/beacon" '
                'src="https://decoy.example.org/" '
                'width="0" height="0" style="display:none"></iframe>')
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        assert result["invisible_iframes"][0].get("src") == "https://evil-c2.example.net/beacon", (
            "src riportato è l'ultimo valore (decoy) invece del primo (vero C2), "
            f"trovato: {result['invisible_iframes'][0].get('src')}"
        )

    # ── CLS-01h: form self-closing mai rilevato (falso negativo totale) ──
    # Tutti i pattern di `hidden_form_patterns` richiedono un `</form>`
    # letterale: un form self-closing in stile XHTML non produce alcun match,
    # qualunque tecnica di nascondimento porti addosso. Stesso difetto
    # strutturale corretto da CLS-01g per l'iframe. I test asseriscono sul
    # COMPORTAMENTO (finding presente, action riportata, contributo al risk),
    # non sull'implementazione.

    def test_hidden_form_self_closing(self):
        """CLS-01h, caso base. Un form self-closing con `display:none` e
        action verso un dominio ostile deve produrre lo stesso finding
        `hidden_forms` (con la action come IOC) e lo stesso contributo al
        risk (+30) dell'equivalente `<form ...></form>` — che oggi è già
        rilevato (vedi test_hidden_form_explicit_close_control)."""
        html = '<form style="display:none" action="http://evil.example/collect"/>'
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms"), (
            "form self-closing nascosto non rilevato: falso negativo totale "
            "su un segnale di credential harvesting"
        )
        actions = [f.get("action") for f in result["hidden_forms"]]
        assert "http://evil.example/collect" in actions
        assert result["risk_indicators"] >= 30

    def test_hidden_form_self_closing_with_space(self):
        """CLS-01h. Stessa forma self-closing ma con spazio prima di '/>'
        (lo stile XHTML più comune)."""
        html = '<form style="display:none" action="http://evil.example/collect" />'
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms")
        assert result["risk_indicators"] >= 30

    def test_hidden_form_self_closing_visibility_hidden(self):
        """CLS-01h. La tecnica `visibility:hidden` è già coperta per i form
        chiusi (secondo pattern): la variante self-closing deve essere
        rilevata allo stesso modo."""
        html = '<form style="visibility:hidden" action="http://evil.example/collect" />'
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms")
        assert result["risk_indicators"] >= 30

    def test_hidden_form_self_closing_class_hidden(self):
        """CLS-01h. Il nascondimento via `class` contenente "hidden" (quarto
        pattern, l'unico non basato su `style`) combinato con la forma
        self-closing: anche questa combinazione oggi non matcha mai."""
        html = '<form class="hidden" action="http://evil.example/collect" />'
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms")
        assert result["risk_indicators"] >= 30

    def test_hidden_form_self_closing_mixed_quotes(self):
        """CLS-01h. Quote miste (style con apici singoli, action con doppi)
        su un form self-closing: variante pertinente perché un tokenizer
        reale deve chiudere il tag su '/>' indipendentemente dallo stile di
        quoting dei valori che lo precedono. Il nascondimento è identico ai
        casi già verdi per i form chiusi."""
        html = "<form style='display:none' action=\"http://evil.example/collect\" />"
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms")
        assert result["risk_indicators"] >= 30

    def test_hidden_form_self_closing_inside_hidden_div(self):
        """CLS-01h. Contesto reale del segnale: kit di phishing pronto ma non
        visibile, con il form dentro un div `display:none`. Oggi il div
        nascosto viene segnalato (`hidden_divs_with_content`, contains_form,
        +25) ma il form self-closing al suo interno NON produce il finding
        `hidden_forms`: con l'equivalente chiuso i due segnali si sommano
        (30 + 25 = 55, verificato sul codice attuale), con il self-closing
        il risk si ferma a 25."""
        html = (
            '<div style="display:none">Please verify your account credentials to continue'
            '<form style="display:none" action="http://evil.example/collect"/></div>'
        )
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms"), (
            "form self-closing dentro un div nascosto non rilevato come hidden_form"
        )
        actions = [f.get("action") for f in result["hidden_forms"]]
        assert "http://evil.example/collect" in actions
        assert result["risk_indicators"] >= 55

    def test_hidden_form_self_closing_risk_parity_with_explicit_close(self):
        """CLS-01h, criterio di accettazione del PM codificato direttamente:
        un form self-closing deve produrre lo stesso numero di finding, la
        stessa action riportata e lo stesso contributo al risk
        dell'equivalente aperto+chiuso. Oggi: chiuso → 1 finding, risk 30;
        self-closing → 0 finding, risk 0."""
        closed = detect_hidden_elements(
            '<form style="display:none" action="http://evil.example/collect"></form>')
        self_closing = detect_hidden_elements(
            '<form style="display:none" action="http://evil.example/collect"/>')
        assert len(self_closing.get("hidden_forms", [])) == len(closed.get("hidden_forms", [])), (
            "il form self-closing non produce lo stesso finding dell'equivalente chiuso"
        )
        assert ([f.get("action") for f in self_closing.get("hidden_forms", [])]
                == [f.get("action") for f in closed.get("hidden_forms", [])])
        assert self_closing["risk_indicators"] == closed["risk_indicators"], (
            f"contributo al risk asimmetrico: self-closing "
            f"{self_closing['risk_indicators']} vs chiuso {closed['risk_indicators']}"
        )

    def test_hidden_form_explicit_close_control(self):
        """CLS-01h, controllo VERDE (deve passare già oggi). L'equivalente
        aperto+chiuso — stessi attributi del caso base self-closing, solo il
        tag di chiusura esplicito in più — è già rilevato: dimostra che il
        falso negativo dei test precedenti dipende ESCLUSIVAMENTE dalla forma
        self-closing del tag, non dagli attributi usati."""
        html = '<form style="display:none" action="http://evil.example/collect"></form>'
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms")
        actions = [f.get("action") for f in result["hidden_forms"]]
        assert "http://evil.example/collect" in actions
        assert result["risk_indicators"] >= 30

    # ── CLS-01i: sezione tracking pixel <img> ancora a regex grezza ──
    # Post CLS-01g/h i rami iframe e form leggono gli attributi dal tokenizer;
    # la sezione 4 (tracking pixel) usa ancora `<img[^>]*>` + regex a boundary
    # fisse per width/height/src. I test asseriscono su come un BROWSER legge
    # il tag (valori quotati integri, attributi duplicati primo-vince), non
    # sull'implementazione. Include R1 del security-reviewer: le stringhe
    # attacker-controlled riportate come IOC (src/action) vanno limitate nello
    # snapshot come già avviene per snippet/tag ([:300]).

    def test_tracking_pixel_gt_in_quoted_attribute_value(self):
        """CLS-01i. Un `>` dentro un valore d'attributo quotato è HTML
        legale e per il browser NON chiude il tag: questo <img> è un pixel
        1x1 a tutti gli effetti. La regex `<img[^>]*>` tronca invece il tag
        al primo `>`, perde width/height e produce un falso negativo totale
        su un tracking pixel reale."""
        html = '<img alt="logo > banner" width="1" height="1" src="http://evil.example/px.gif">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels"), (
            "pixel 1x1 con '>' in un attributo quotato non rilevato: "
            "falso negativo totale del ramo <img>"
        )
        assert result["tracking_pixels"][0].get("src") == "http://evil.example/px.gif"

    def test_tracking_pixel_gt_in_quoted_src(self):
        """CLS-01i. Stesso difetto ma con il `>` dentro la src stessa
        (querystring): il browser rende il pixel e richiede l'URL integro;
        il detector oggi non produce alcun finding. L'IOC deve essere il
        valore completo dell'attributo, come lo leggerebbe il browser."""
        html = '<img src="http://evil.example/px.gif?a>b" width="1" height="1">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels"), (
            "pixel 1x1 con '>' nella querystring della src non rilevato"
        )
        assert result["tracking_pixels"][0].get("src") == "http://evil.example/px.gif?a>b"

    def test_tracking_pixel_duplicate_width_first_wins(self):
        """CLS-01i. Semantica primo-vince (HTML5/browser) sugli attributi
        duplicati, già stabilita da CLS-01g/h per iframe e form, applicata
        al ramo <img>: con `width="600" width="1"` il browser rende
        un'immagine larga 600px — NON è un pixel di tracking. La regex
        attuale cerca `width=...1` ovunque nel tag, aggancia il duplicato
        morto e produce un falso positivo incoerente con il resto del
        detector."""
        html = '<img width="600" width="1" height="1" src="http://evil.example/banner.gif">'
        result = detect_hidden_elements(html)
        assert not result.get("tracking_pixels"), (
            "immagine 600x1 per il browser (primo width vince) segnalata "
            "come tracking pixel sul valore del duplicato ignorato"
        )

    def test_tracking_pixel_src_with_space_reported_whole(self):
        """CLS-01i. In un valore quotato lo spazio è legale: il browser
        legge la src per intero. L'estrazione `[^"\\'>\\s]+` si ferma al
        primo spazio e consegna all'analista un IOC troncato (URL che non
        esiste, indicatore non actionable)."""
        html = '<img width="1" height="1" src="http://evil.example/track me.gif">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")
        assert result["tracking_pixels"][0].get("src") == "http://evil.example/track me.gif", (
            f"src troncata allo spazio: {result['tracking_pixels'][0].get('src')!r}"
        )

    def test_tracking_pixel_src_mixed_quotes_reported_whole(self):
        """CLS-01i. Src delimitata da apici singoli con doppi apici legittimi
        nel valore: il browser la legge integra fino all'apice singolo di
        chiusura; l'estrazione attuale si ferma al primo doppio apice e
        tronca l'IOC a metà querystring."""
        html = '<img width="1" height="1" src=\'http://evil.example/px.gif?id="42"\'>'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")
        assert result["tracking_pixels"][0].get("src") == 'http://evil.example/px.gif?id="42"', (
            f"src troncata all'apice doppio interno: {result['tracking_pixels'][0].get('src')!r}"
        )

    def test_tracking_pixel_long_src_capped(self):
        """CLS-01i / R1 del security-reviewer. La src è attacker-controlled:
        senza cap un attributo artificialmente lungo finisce integro nel
        finding e da lì nello snapshot persistito. Il campo memorizzato deve
        essere limitato a 300 caratteri — la stessa soglia già usata per gli
        snapshot testuali (`snippet[:300]`, `tag[:300]`); il test asserisce
        un limite superiore, quindi un cap più stretto resta conforme.
        Il prefisso dell'IOC deve sopravvivere al taglio."""
        src = "http://evil.example/px.gif?pad=" + "A" * 5000
        html = f'<img width="1" height="1" src="{src}">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")
        stored = result["tracking_pixels"][0].get("src")
        assert stored is not None
        assert len(stored) <= 300, (
            f"src del tracking pixel memorizzata integra: {len(stored)} caratteri (attesi <= 300)"
        )
        assert stored.startswith("http://evil.example/px.gif?pad=")

    def test_invisible_iframe_long_src_capped(self):
        """CLS-01i / R1. Stesso cap sul ramo iframe: `tag` è già troncato a
        300, ma `src` — il campo che diventa IOC dell'alert CRITICAL
        `legit_invisible_iframe_detected` — è memorizzato senza limite."""
        src = "http://evil.example/c2?pad=" + "A" * 5000
        html = f'<iframe width="0" src="{src}"></iframe>'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        stored = result["invisible_iframes"][0].get("src")
        assert stored is not None
        assert len(stored) <= 300, (
            f"src dell'iframe invisibile memorizzata integra: {len(stored)} caratteri (attesi <= 300)"
        )
        assert stored.startswith("http://evil.example/c2?pad=")

    def test_hidden_form_long_action_capped(self):
        """CLS-01i / R1. Stesso cap sul ramo form: `snippet` è già troncato a
        300, ma `action` è memorizzata senza limite."""
        action = "https://evil.example/steal.php?pad=" + "A" * 5000
        html = f'<form style="display:none" action="{action}"></form>'
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms")
        stored = result["hidden_forms"][0].get("action")
        assert stored is not None
        assert len(stored) <= 300, (
            f"action del form nascosto memorizzata integra: {len(stored)} caratteri (attesi <= 300)"
        )
        assert stored.startswith("https://evil.example/steal.php?pad=")

    def test_tracking_pixel_data_src_not_reported_as_ioc(self):
        """CLS-01i (criterio esteso dal PM, 2026-07-26). L'IOC riportato deve
        essere il valore dell'attributo `src` reale, mai di attributi che lo
        contengono come sottostringa del nome: per il browser `data-src` è un
        data-attribute inerte e il pixel viene richiesto dalla `src`. La regex
        attuale (`src\\s*=`) non ancora il nome dell'attributo, aggancia
        `data-src=` che compare prima nel tag e consegna all'analista il
        decoy al posto del vero endpoint di tracking."""
        html = ('<img width="1" height="1" '
                'data-src="http://decoy.example/d.gif" src="http://evil.example/px.gif">')
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")
        assert result["tracking_pixels"][0].get("src") == "http://evil.example/px.gif", (
            "IOC del tracking pixel preso da data-src (decoy) invece che dalla src reale: "
            f"trovato {result['tracking_pixels'][0].get('src')!r}"
        )

    def test_tracking_pixel_quote_variants_control(self):
        """CLS-01i, controllo VERDE (passa già oggi). Quote miste e spazi
        DENTRO i valori di width/height sono già letti correttamente anche
        dalla regex attuale: il test congela questo comportamento come rete
        di sicurezza per la migrazione del ramo <img> al tokenizer, e
        dimostra che i falsi negativi dei test precedenti dipendono dai casi
        specifici (`>` quotato, duplicati, src troncata), non dal quoting in
        sé."""
        mixed = detect_hidden_elements(
            '<img width=\'1\' height="1" src="http://evil.example/px.gif">')
        assert mixed.get("tracking_pixels")
        assert mixed["tracking_pixels"][0].get("src") == "http://evil.example/px.gif"
        spaced = detect_hidden_elements(
            '<img width=" 1 " height=\' 1 \' src="http://evil.example/px.gif">')
        assert spaced.get("tracking_pixels")
        assert spaced["tracking_pixels"][0].get("src") == "http://evil.example/px.gif"

    # ── CLS-01q: RAWTEXT di un iframe mai chiuso inghiotte i tag successivi ──
    # `HTMLParser.CDATA_CONTENT_ELEMENTS` include "iframe": un <iframe> mai
    # chiuso in un punto qualsiasi precedente del documento fa trattare tutto
    # il resto come RAWTEXT fino a EOF, e nessuno dei tag che seguono viene
    # più tokenizzato — non solo <img> (regressione originale segnalata dal
    # verifier su CLS-01i), ma qualunque sezione che usa lo stesso tokenizer
    # condiviso (`_TagCollector`): form e iframe compresi. I test asseriscono
    # sul COMPORTAMENTO osservabile (il finding compare o non compare), non
    # sull'implementazione (stato reale via `handle_endtag` è la scelta di
    # design del fixer, non qualcosa su cui questi test si ancorano).

    def test_tracking_pixel_lost_after_unclosed_iframe(self):
        """CLS-01q, riproduzione esatta del verifier (G6 `CLS-01i`,
        2026-07-28). Un iframe civetta mai chiuso prima nel documento
        inghiotte come RAWTEXT anche un tracking pixel 1x1 reale che segue:
        il vecchio codice a regex lo rilevava (`tracking_pixels = 1`), il
        tokenizer condiviso lo perde silenziosamente (`tracking_pixels = 0`).
        Impatto: falso negativo silenzioso sull'alert CRITICAL
        `legit_hidden_elements_detected` (classifier.py:538,
        shared/constants.py:64-68) — evasione a costo zero per un
        attaccante che lascia un iframe aperto per errore od obfuscation."""
        html = ('<iframe src="decoy.html"><img width="1" height="1" '
                'src="http://evil.tld/px.gif">')
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels"), (
            "tracking pixel dopo un iframe mai chiuso non rilevato: "
            "inghiottito come RAWTEXT dell'iframe precedente"
        )
        assert result["tracking_pixels"][0].get("src") == "http://evil.tld/px.gif"

    def test_hidden_form_lost_after_unclosed_iframe(self):
        """CLS-01q, ramo form. Stessa causa radice del test precedente, ma
        sulla sezione `hidden_forms`: un iframe civetta mai chiuso prima nel
        documento inghiotte anche un form nascosto (credential harvesting)
        che segue. Il tokenizer è condiviso da tutte le sezioni — la
        cecità non è specifica del ramo <img>."""
        html = ('<iframe src="decoy.html">junk'
                '<form style="display:none" action="http://evil.tld/collect"></form>')
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms"), (
            "form nascosto dopo un iframe mai chiuso non rilevato: "
            "inghiottito come RAWTEXT dell'iframe precedente"
        )
        actions = [f.get("action") for f in result["hidden_forms"]]
        assert "http://evil.tld/collect" in actions

    def test_invisible_iframe_lost_after_unclosed_iframe(self):
        """CLS-01q, ramo iframe. Stessa causa radice, sulla sezione
        `invisible_iframes`: un secondo iframe (self-closing, 0x0) collocato
        dopo un primo iframe mai chiuso viene inghiottito come RAWTEXT del
        primo e non tokenizzato affatto — il caso base misurato da `CLS-01k`
        (1 rilevato su 20.000 iframe self-closing in questa posizione)."""
        html = ('<iframe src="decoy.html">'
                '<iframe width="0" height="0" src="http://evil.tld/c2" />')
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes"), (
            "iframe self-closing invisibile dopo un iframe mai chiuso non "
            "rilevato: inghiottito come RAWTEXT del primo"
        )
        srcs = [f.get("src") for f in result["invisible_iframes"]]
        assert "http://evil.tld/c2" in srcs

    def test_tracking_pixel_after_properly_closed_iframe_control(self):
        """CLS-01q, controllo VERDE (deve passare già oggi). Un iframe
        REGOLARMENTE chiuso prima del tracking pixel non attiva alcuna
        modalità RAWTEXT residua: il pixel che segue è rilevato normalmente.
        Isola la causa dai test precedenti — è specificamente l'iframe MAI
        chiuso a causare la cecità, non la sola presenza di un iframe prima
        nel documento."""
        html = ('<iframe src="decoy.html"></iframe>'
                '<img width="1" height="1" src="http://evil.tld/px.gif">')
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")
        assert result["tracking_pixels"][0].get("src") == "http://evil.tld/px.gif"

    # ── CLS-01j: semantica RAWTEXT sull'iframe "civetta" annidato ──
    # Decisione utente 2026-07-28 (opzione (a)): stato reale via
    # `handle_endtag`, condiviso da tutte le sezioni che usano
    # `_TagCollector`. Chiarimento esplicito del PM: il criterio va letto in
    # modo agnostico rispetto all'implementazione — è il comportamento di
    # rilevazione osservabile su `invisible_iframes` a dover soddisfare i 3
    # controesempi del verifier round 5 di CLS-01g, non un indicatore
    # booleano separato (`unclosed_iframes`, rimosso). I test qui sotto
    # asseriscono quindi solo su `invisible_iframes`.

    def test_nested_evil_iframe_detected_despite_trailing_text(self):
        """CLS-01j, controesempio 1 del verifier round 5 di `CLS-01g`.

        ASPETTATIVA CAMBIATA (G4 round 3, 2026-07-28): questo test asseriva
        in origine che l'iframe "nascosto" annidato dovesse comparire in
        `invisible_iframes` anche con del testo di coda dopo di esso. Quella
        aspettativa nasceva da un modello a pila (LIFO) del nesting RAWTEXT,
        refutato dal verifier al G6 round 3: in HTML5 gli elementi RAWTEXT
        non hanno nesting, il contenuto di un `<iframe>` termina alla PRIMA
        occorrenza letterale di `</iframe`, punto. In questo markup c'è
        UNA sola `</iframe>` per DUE `<iframe` aperti (2/1, sbilanciato):
        per un browser reale quella `</iframe>` chiude l'iframe ESTERNO
        (`decoy.html`), e tutto ciò che segue — incluso il secondo
        `<iframe>` 0x0 e il testo di coda — è fallback content opaco del
        primo, mai tokenizzato né renderizzato. Il tokenizer, corretto alla
        semantica reale RAWTEXT, ora esclude quel contenuto da
        `invisible_iframes` a ragione: non è un falso negativo, è la lettura
        corretta dello spec.

        Il pattern resta pericoloso — un fallback content con markup che
        assomiglia a un iframe di tracking è comunque un segnale sospetto
        potenziale — ma la sua detection spetta a un detector SEPARATO dal
        tokenizer di `_TagCollector`, tracciato come `CLS-01w` in
        `BUG-REGISTER.md` e NON ANCORA IMPLEMENTATO. Allo stato attuale
        questo pattern è quindi un gap di rilevamento aperto: nessun
        finding viene prodotto da nessuna parte. Questo test resta a
        documentare il markup e a congelare il comportamento del tokenizer
        (che non deve tokenizzare quel contenuto), non a coprire il
        rilevamento del fallback sospetto."""
        html = ('<iframe src="decoy.html"><iframe src="http://evil.tld/c2" '
                'width="0" height="0">filler text after</iframe>')
        result = detect_hidden_elements(html)
        iframes = result.get("invisible_iframes", [])
        assert not any(f.get("src") == "http://evil.tld/c2" for f in iframes), (
            "l'iframe 0x0 annidato nel fallback content di un iframe "
            "esterno regolarmente chiuso (2 aperture/1 chiusura) e' stato "
            "tokenizzato come elemento del documento, in violazione della "
            f"semantica RAWTEXT reale: {iframes}"
        )

    def test_nested_evil_iframe_detected_with_gt_in_quoted_attribute(self):
        """CLS-01j, controesempio 3 del verifier round 5 di `CLS-01g`.

        ASPETTATIVA CAMBIATA (G4 round 3, 2026-07-28), stessa motivazione di
        `test_nested_evil_iframe_detected_despite_trailing_text` qui sopra:
        modello a pila (LIFO) refutato, RAWTEXT non ha nesting, la PRIMA
        `</iframe` letterale chiude. Questo markup ha anch'esso 2 aperture
        di `<iframe` e 1 sola chiusura: la `</iframe>` presente chiude
        l'iframe esterno (`decoy.html`), non quello annidato. Il `>`
        dentro l'attributo quotato (`src="...?a>b"`) resta interessante di
        per sé — dimostra che l'estrazione attributi quote-aware funziona
        correttamente e non tronca il tag prematuramente — ma l'intero
        secondo `<iframe>`, `>` compreso, è comunque fallback content
        opaco del primo per la stessa ragione del test precedente: mai
        renderizzato da un browser, quindi correttamente escluso da
        `invisible_iframes`.

        Il rilevamento di questo pattern come fallback content sospetto è
        compito di un detector SEPARATO dal tokenizer, tracciato come
        `CLS-01w` in `BUG-REGISTER.md` e NON ANCORA IMPLEMENTATO: oggi
        questo pattern non produce alcun finding, è un gap aperto. Il
        markup resta qui a documentare il comportamento corretto del
        tokenizer su un `>` quotato dentro una regione RAWTEXT
        sbilanciata."""
        html = ('<iframe src="decoy.html"><iframe src="http://evil.tld/c2?a>b" '
                'width="0" height="0"></iframe>')
        result = detect_hidden_elements(html)
        iframes = result.get("invisible_iframes", [])
        assert not any(f.get("src") == "http://evil.tld/c2?a>b" for f in iframes), (
            "l'iframe 0x0 annidato (con '>' in un attributo quotato) nel "
            "fallback content di un iframe esterno regolarmente chiuso "
            "(2 aperture/1 chiusura) e' stato tokenizzato come elemento "
            f"del documento, in violazione della semantica RAWTEXT reale: {iframes}"
        )

    def test_iframe_documentation_text_no_false_positive_control(self):
        """CLS-01j, controesempio 2 del verifier round 5 di `CLS-01g`,
        controllo VERDE dichiarato (già vero oggi, e deve restare vero dopo
        il fix). Un iframe realmente visibile (640x480, nessuna tecnica di
        nascondimento) il cui contenuto RAWTEXT menziona testualmente
        "<iframe>" (fallback per browser che non lo supportano) non deve
        produrre alcun finding in `invisible_iframes`: non c'è alcun
        elemento nascosto, solo testo che assomiglia a markup. Congela
        questo comportamento come rete di sicurezza per l'eventuale
        ri-scansione del contenuto RAWTEXT introdotta dal fix di CLS-01j/q."""
        html = ('<iframe src="https://legit.example/widget" width="640" '
                'height="480">Browser too old. Tip: use <iframe>')
        result = detect_hidden_elements(html)
        assert not result.get("invisible_iframes"), (
            "falso positivo: testo di documentazione che menziona <iframe> "
            f"ha prodotto un finding invisible_iframes: {result.get('invisible_iframes')}"
        )

    # ── CLS-01j/CLS-01q, bloccante 1 del verifier G6 round 2 (28/7) — il più
    # importante del giro. `_SUPPRESS_RAWTEXT` (working tree corrente)
    # sopprime la modalità RAWTEXT di `HTMLParser` in modo INCONDIZIONATO per
    # ogni <iframe>, chiuso o no. Per la spec WHATWG il contenuto testuale di
    # un iframe REGOLARMENTE CHIUSO è opaco: nessun browser lo renderizza né
    # lo tokenizza come markup del documento — è fallback content per user
    # agent che non supportano gli iframe. Un iframe legittimo e visibile il
    # cui fallback contiene markup che assomiglia a form/pixel/iframe
    # nascosti non deve produrre alcun finding su quel contenuto.
    #
    # Ognuno dei tre test sotto verifica ENTRAMBE le direzioni del contratto
    # nello stesso scenario A/B, per non poter essere soddisfatto da un fix
    # che sposti il confine invece di correggerlo: (1) l'iframe chiuso
    # regolarmente non deve produrre alcun finding sul suo contenuto interno;
    # (2) lo STESSO markup, con l'iframe che lo precede mai chiuso (stato
    # RAWTEXT reale, causa condivisa con CLS-01q, già coperta sopra in
    # questo file con fixture indipendenti) deve restare rilevato — un fix
    # che ripristinasse la soppressione condizionata solo per il caso
    # "mai chiuso" ma la applicasse anche al caso chiuso non supererebbe
    # comunque questi test.

    def test_hidden_form_inside_properly_closed_iframe_not_detected(self):
        """CLS-01j/CLS-01q bloccante 1, ramo form. A/B esatto del verifier
        (G6 round 2, 28/7): `<iframe src="x" width="640" height="480">
        fallback <form style="display:none" action="...">
        </form></iframe>` — iframe VISIBILE e REGOLARMENTE CHIUSO. Oggi:
        `hidden_forms` popolato, risk 40 (`legit_hidden_form_detected`
        CRITICAL + `legit_hidden_elements_detected` CRITICAL, caso
        instradato a `suspicious`/HIGH bypassando `legitimate_probable`).
        Atteso: `hidden_forms` vuoto — il form non è un elemento VIVO del
        documento. CLS-01z (riconciliato, decisione utente: peso 30): lo
        stesso form, essendo markup morto verso un host esterno
        (`evil.example`) nel fallback content di un iframe regolarmente
        chiuso, è ORA il bersaglio del detector separato
        `suspicious_dead_markup` — contribuisce 30 al risk, non 0."""
        closed = ('<iframe src="x" width="640" height="480">fallback '
                  '<form style="display:none" action="http://evil.example/collect">'
                  '</form></iframe>')
        result_closed = detect_hidden_elements(closed)
        assert not result_closed.get("hidden_forms"), (
            "iframe visibile e regolarmente chiuso: il form nel fallback "
            "content (mai renderizzato da un browser) e' stato rilevato "
            f"come elemento VIVO in hidden_forms: {result_closed.get('hidden_forms')}"
        )
        dead = result_closed.get("suspicious_dead_markup")
        assert dead, (
            "CLS-01z: il form morto nel fallback content verso l'host "
            "esterno evil.example doveva essere rilevato in "
            f"suspicious_dead_markup, nessun finding prodotto: {result_closed}"
        )
        assert all(d.get("type") == "form" for d in dead), (
            f"suspicious_dead_markup con type inatteso (atteso solo 'form'): {dead}"
        )
        assert all(d.get("source") == "fallback_content" for d in dead), (
            f"suspicious_dead_markup con source inatteso (atteso 'fallback_content'): {dead}"
        )
        assert result_closed["risk_indicators"] == 30, (
            "CLS-01z: peso 30 (per-categoria, deciso dall'utente) per la "
            "presenza di suspicious_dead_markup su un form morto verso "
            f"host esterno, ottenuto: {result_closed['risk_indicators']}"
        )

        # Controllo di coerenza CLS-01q, nello stesso test: lo stesso form,
        # con l'iframe che lo precede MAI chiuso, deve restare rilevato.
        unclosed = ('<iframe src="x" width="640" height="480">fallback '
                    '<form style="display:none" action="http://evil.example/collect">'
                    '</form>')
        result_unclosed = detect_hidden_elements(unclosed)
        assert result_unclosed.get("hidden_forms"), (
            "controllo di coerenza CLS-01q: lo stesso form, con l'iframe "
            "MAI chiuso, deve restare rilevato — un fix che sopprime la "
            "tokenizzazione anche in questo caso violerebbe CLS-01q"
        )

    def test_tracking_pixel_inside_properly_closed_iframe_not_detected(self):
        """CLS-01j/CLS-01q bloccante 1, ramo pixel di tracking (`<img>`).
        Stesso A/B del verifier, riprodotto indipendentemente dal
        security-reviewer su `tracking_pixels` (risk 10): un pixel 1x1 nel
        fallback content di un iframe visibile e regolarmente chiuso non è
        un pixel di tracking del documento — un browser non lo carica mai.
        CLS-01z (riconciliato, decisione utente: peso 30): lo stesso `<img>`,
        essendo markup morto verso un host esterno (`evil.example`) nel
        fallback content di un iframe regolarmente chiuso, è ORA il
        bersaglio del detector separato `suspicious_dead_markup` —
        contribuisce 30 al risk, non 0."""
        closed = ('<iframe src="x" width="640" height="480">fallback '
                  '<img width="1" height="1" src="http://evil.example/px.gif">'
                  '</iframe>')
        result_closed = detect_hidden_elements(closed)
        assert not result_closed.get("tracking_pixels"), (
            "iframe visibile e regolarmente chiuso: il pixel 1x1 nel "
            "fallback content (mai caricato da un browser) e' stato "
            f"rilevato come elemento VIVO in tracking_pixels: {result_closed.get('tracking_pixels')}"
        )
        dead = result_closed.get("suspicious_dead_markup")
        assert dead, (
            "CLS-01z: il pixel morto nel fallback content verso l'host "
            "esterno evil.example doveva essere rilevato in "
            f"suspicious_dead_markup, nessun finding prodotto: {result_closed}"
        )
        assert all(d.get("type") == "img" for d in dead), (
            f"suspicious_dead_markup con type inatteso (atteso solo 'img'): {dead}"
        )
        assert all(d.get("source") == "fallback_content" for d in dead), (
            f"suspicious_dead_markup con source inatteso (atteso 'fallback_content'): {dead}"
        )
        assert result_closed["risk_indicators"] == 30, (
            "CLS-01z: peso 30 (per-categoria, deciso dall'utente) per la "
            "presenza di suspicious_dead_markup su un pixel morto verso "
            f"host esterno, ottenuto: {result_closed['risk_indicators']}"
        )

        unclosed = ('<iframe src="x" width="640" height="480">fallback '
                    '<img width="1" height="1" src="http://evil.example/px.gif">')
        result_unclosed = detect_hidden_elements(unclosed)
        assert result_unclosed.get("tracking_pixels"), (
            "controllo di coerenza CLS-01q: lo stesso pixel, con l'iframe "
            "MAI chiuso, deve restare rilevato"
        )

    def test_invisible_iframe_nested_inside_properly_closed_iframe_not_detected(self):
        """CLS-01j/CLS-01q bloccante 1, ramo iframe annidato (risk 25,
        `legit_invisible_iframe_detected` CRITICAL). Stesso A/B, riprodotto
        indipendentemente dal security-reviewer: un iframe 0x0 nel fallback
        content di un iframe esterno visibile e regolarmente chiuso non è
        un iframe del documento — non va confuso con la civetta MAI chiusa
        di CLS-01j (test più sopra in questo file), che è un markup
        oggettivamente malformato, non un fallback content valido.

        ASPETTATIVA CAMBIATA sul secondo blocco (`unclosed`, sotto) — G4
        round 3, 2026-07-28. Il primo blocco (`closed`, 2 aperture/2
        chiusure, bilanciato) era e resta corretto, non toccato qui. Il
        secondo blocco, nonostante il nome della variabile `unclosed`,
        NON è in realtà l'iframe esterno mai chiuso: ha 2 aperture di
        `<iframe` e UNA sola `</iframe>` (2/1, sbilanciato) — esattamente
        il PoC del bloccante 1 del verifier round 3, non il caso "civetta
        mai chiusa" di `CLS-01q`/`CLS-01j` (che ha ZERO occorrenze di
        `</iframe` in tutto il documento, v.
        `test_invisible_iframe_lost_after_unclosed_iframe` più sopra in
        questo file). L'unica `</iframe>` presente chiude, per la
        semantica RAWTEXT reale (prima occorrenza letterale, niente
        nesting), l'iframe ESTERNO (`src="x"`) — l'iframe 0x0 annidato
        e' quindi fallback content opaco, mai un elemento del documento,
        e va escluso da `invisible_iframes` esattamente come nel blocco
        `closed`. L'assert di coerenza interno che imponeva il rilevamento
        era la manifestazione di questo stesso bloccante, non una
        proprietà indipendente da preservare: viene corretto qui, non
        rimosso — il markup resta a documentare che 2 aperture/1 chiusura
        producono NON rilevato tanto quanto 2 aperture/2 chiusure.

        Il rilevamento del fallback content sospetto (in entrambi i blocchi
        di questo test) era stato tracciato come `CLS-01w` in
        `BUG-REGISTER.md`; QUEL gap è ora chiuso da `CLS-01z` (riconciliato,
        decisione utente: peso 30, host esterno). Entrambi i blocchi sotto
        — `closed` (2 aperture/2 chiusure) e `unclosed` (2 aperture/1
        chiusura, nonostante il nome storico della variabile) — chiudono
        regolarmente l'iframe esterno con almeno un `</iframe>` letterale:
        in entrambi l'iframe 0x0 annidato finisce nel fallback content,
        quindi in entrambi è ORA il bersaglio di `suspicious_dead_markup`,
        non solo escluso da `invisible_iframes`."""
        closed = ('<iframe src="x" width="640" height="480">fallback '
                  '<iframe width="0" height="0" src="http://evil.example/c2">'
                  '</iframe></iframe>')
        result_closed = detect_hidden_elements(closed)
        assert not result_closed.get("invisible_iframes"), (
            "iframe visibile e regolarmente chiuso: l'iframe 0x0 annidato "
            "nel fallback content (mai renderizzato da un browser) e' "
            "stato rilevato come elemento VIVO in invisible_iframes: "
            f"{result_closed.get('invisible_iframes')}"
        )
        dead_closed = result_closed.get("suspicious_dead_markup")
        assert dead_closed, (
            "CLS-01z: l'iframe 0x0 morto nel fallback content verso l'host "
            "esterno evil.example doveva essere rilevato in "
            f"suspicious_dead_markup, nessun finding prodotto: {result_closed}"
        )
        assert all(d.get("type") == "iframe" for d in dead_closed), (
            f"suspicious_dead_markup con type inatteso (atteso solo 'iframe'): {dead_closed}"
        )
        assert all(d.get("source") == "fallback_content" for d in dead_closed), (
            f"suspicious_dead_markup con source inatteso (atteso 'fallback_content'): {dead_closed}"
        )
        assert result_closed["risk_indicators"] == 30, (
            "CLS-01z: peso 30 (per-categoria, deciso dall'utente) per la "
            "presenza di suspicious_dead_markup sull'iframe annidato morto "
            f"verso host esterno, ottenuto: {result_closed['risk_indicators']}"
        )

        # Nome storico "unclosed" mantenuto per continuità col markup
        # originale, ma non è il caso "iframe esterno mai chiuso" (quello
        # è coperto altrove, v. docstring sopra): è lo stesso PoC 2/1
        # sbilanciato del bloccante 1, e per la semantica RAWTEXT reale
        # produce lo stesso esito — morto, non vivo — del blocco `closed`.
        unclosed = ('<iframe src="x" width="640" height="480">fallback '
                    '<iframe width="0" height="0" src="http://evil.example/c2">'
                    '</iframe>')
        result_unclosed = detect_hidden_elements(unclosed)
        assert not result_unclosed.get("invisible_iframes"), (
            "l'iframe 0x0 annidato (2 aperture/1 chiusura: l'unica "
            "</iframe> chiude l'iframe esterno per semantica RAWTEXT "
            "reale) e' stato tokenizzato come elemento VIVO del documento: "
            f"{result_unclosed.get('invisible_iframes')}"
        )
        dead_unclosed = result_unclosed.get("suspicious_dead_markup")
        assert dead_unclosed, (
            "CLS-01z: lo stesso iframe 0x0 morto (2 aperture/1 chiusura) "
            "doveva essere rilevato in suspicious_dead_markup, nessun "
            f"finding prodotto: {result_unclosed}"
        )
        assert all(d.get("type") == "iframe" for d in dead_unclosed), (
            f"suspicious_dead_markup con type inatteso (atteso solo 'iframe'): {dead_unclosed}"
        )
        assert all(d.get("source") == "fallback_content" for d in dead_unclosed), (
            f"suspicious_dead_markup con source inatteso (atteso 'fallback_content'): {dead_unclosed}"
        )
        assert result_unclosed["risk_indicators"] == 30, (
            "CLS-01z: peso 30 (per-categoria) anche sul blocco 2/1 "
            f"sbilanciato, ottenuto: {result_unclosed['risk_indicators']}"
        )

    # ── CLS-01r: width="1x"/suffissi non-px non riconosciuti dal pixel-detector ──
    # Criterio a registro (aggiornato 2026-07-28, dopo il bloccante 3 del G6
    # round 2): `width`/`height` NON seguono "rules for parsing non-negative
    # integers" (quello di colspan/rowspan/size) — seguono "rules for parsing
    # dimension values", che (a) arrotondano un punto decimale round-half-up
    # sulla PRIMA cifra frazionaria ("0.5" -> 1, "1.5" -> 2, non 1) e (b)
    # distinguono un risultato in pixel da un risultato in percentuale. Per
    # la parte (a)/(b) l'algoritmo *è* conformità alla spec.
    #
    # Il trattamento del "%" invece NON lo è: è una scelta di postura di
    # prodotto (decisione utente 2026-07-28, opzione (ii)) — una percentuale
    # che risolve a "1"/"0" resta comunque sospetta, a prescindere dal
    # rendering reale, per preservare il richiamo su un vettore usato da kit
    # di phishing reali. Il vincolo esplicito dell'utente è che questa
    # divergenza NON sia indistinguibile da un 1px assoluto reale nel
    # finding riportato all'analista (campo `technique`) — i test su "0.5" e
    # "1%" verificano quella distinzione, non solo la presenza del finding.

    def test_tracking_pixel_width_1x_suffix(self):
        """CLS-01r, fixture 1 (il caso che ha innescato il rilievo del
        security-reviewer). `width="1x" height="1x"`: nessun `.`, nessun
        `%` — le "rules for parsing dimension values" collezionano il
        prefisso numerico "1" e lo trattano come pixel, ignorando il
        suffisso "spazzatura". `_is_one_px` richiede oggi un match esatto
        `"1"`/`"1px"` e non lo riconosce: falso negativo."""
        html = '<img width="1x" height="1x" src="http://evil.tld/px.gif">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels"), (
            'width="1x" height="1x" (1px per il browser) non rilevato come tracking pixel'
        )

    def test_tracking_pixel_width_1px_control(self):
        """CLS-01r, fixture 2, controllo VERDE (già rilevato oggi, non deve
        regredire). `"1px"` è la forma standard già gestita da `_is_one_px`."""
        html = '<img width="1px" height="1px" src="http://evil.tld/px.gif">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")

    def test_tracking_pixel_width_1abc_suffix(self):
        """CLS-01r, fixture 3. Suffisso alfabetico arbitrario dopo la cifra
        iniziale ("1abc" non è né `.` né whitespace-poi-`%`): stesso ramo
        pixel dell'algoritmo "dimension values", stesso esito atteso."""
        html = '<img width="1abc" height="1abc" src="http://evil.tld/px.gif">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels"), (
            'width="1abc" height="1abc" (prefisso di cifre "1") non rilevato come tracking pixel'
        )

    def test_tracking_pixel_width_100_percent_no_regression_control(self):
        """CLS-01r, fixture 4, controllo VERDE (caso originale di CLS-01b,
        non deve regredire). `width="100%" height="450"`: il prefisso
        numerico è "100", non "1" — non è un tracking pixel, qualunque ramo
        (pixel o percentuale) dell'algoritmo si applichi."""
        html = '<img width="100%" height="450" src="http://evil.tld/banner.gif">'
        result = detect_hidden_elements(html)
        assert not result.get("tracking_pixels"), (
            'width="100%" height="450" erroneamente rilevato come tracking pixel'
        )

    def test_iframe_width_0_5_rounds_to_1px_distinct_from_real_zero(self):
        """CLS-01r, fixture 5 (nuova, bloccante 3 del G6 round 2). Le "rules
        for parsing dimension values" arrotondano `"0.5"` per eccesso a 1
        (round-half-up sulla prima cifra frazionaria): un iframe con
        `width="0.5" height="0.5"` è 1px REALE e VISIBILE, non un iframe
        0x0. Con l'implementazione corrente (`_leading_int` tronca al
        prefisso di cifre ASCII prima del punto, senza gestire il decimale)
        risulta `_is_zero_or_one_px = True` per il ramo "0" — comunque un
        finding, ma con la motivazione (`technique`) INDISTINGUIBILE da un
        iframe genuinamente 0x0: falso positivo CRITICAL su
        `legit_invisible_iframe_detected` con una motivazione fuorviante.
        Il vincolo esplicito del PM/utente è che questa distinzione compaia
        nel finding, non solo che il predicato booleano torni vero — quindi
        il test confronta la `technique` riportata per "0.5" con quella di
        un iframe letteralmente 0x0 e pretende che siano diverse."""
        real_zero = detect_hidden_elements(
            '<iframe width="0" height="0" src="http://evil.tld/c2"></iframe>')
        rounded = detect_hidden_elements(
            '<iframe width="0.5" height="0.5" src="http://evil.tld/c2"></iframe>')
        assert rounded.get("invisible_iframes"), (
            'width="0.5" height="0.5" (arrotonda a 1px reale) non rilevato affatto'
        )
        technique_zero = real_zero["invisible_iframes"][0].get("technique")
        technique_rounded = rounded["invisible_iframes"][0].get("technique")
        assert technique_rounded != technique_zero, (
            "la motivazione riportata per width=\"0.5\" (1px arrotondato, "
            "reale e visibile) e' indistinguibile da quella di un iframe "
            f"letteralmente 0x0: entrambe {technique_zero!r}"
        )

    def test_tracking_pixel_width_1_5_not_flagged_control(self):
        """CLS-01r, fixture 6 (nuova, controllo negativo del bloccante 3).
        `"1.5"` arrotonda per eccesso a 2, NON a 1 (round-half-up sulla
        prima cifra frazionaria "5" applicato a "1.5" supera la metà):
        un elemento realmente largo 2px non è un pixel di tracciamento
        1x1. Con l'implementazione corrente `_leading_int` tronca al
        prefisso "1" ignorando ".5" del tutto, senza applicare alcun
        arrotondamento: falso positivo, `_is_one_px("1.5")` torna `True`
        quando dovrebbe tornare `False`."""
        html = '<img width="1.5" height="1.5" src="http://evil.tld/px.gif">'
        result = detect_hidden_elements(html)
        assert not result.get("tracking_pixels"), (
            'width="1.5" height="1.5" (arrotonda a 2px reale, non 1px) '
            f"erroneamente rilevato come tracking pixel: {result.get('tracking_pixels')}"
        )

    def test_tracking_pixel_width_1_percent_flagged_with_distinct_technique(self):
        """CLS-01r, fixture 7 (sbloccata dalla decisione utente 2026-07-28,
        opzione (ii), euristica di prodotto — NON conformità alla spec: per
        le "rules for parsing dimension values" un valore seguito da `%` è
        una percentuale relativa al contenitore, non ha una dimensione
        fissa nota, e la spec NON lo tratterebbe come 1px. È una scelta di
        rilevamento deliberata, mantenuta per preservare il richiamo su un
        vettore usato da kit di phishing reali (rischio di falso positivo
        accettato consapevolmente dall'utente). Il vincolo esplicito è che
        questa scelta non sia indistinguibile da un 1px assoluto reale nel
        finding: il test verifica che `width="1%"` produca un finding CON
        una `technique` diversa da quella di `width="1x"` (1px assoluto),
        non solo che il finding sia presente."""
        percent = detect_hidden_elements(
            '<img width="1%" height="1%" src="http://evil.tld/px.gif">')
        absolute = detect_hidden_elements(
            '<img width="1x" height="1x" src="http://evil.tld/px.gif">')
        assert percent.get("tracking_pixels"), (
            'width="1%" height="1%" (euristica di prodotto) non rilevato come '
            "tracking pixel sospetto"
        )
        technique_percent = percent["tracking_pixels"][0].get("technique")
        technique_absolute = absolute["tracking_pixels"][0].get("technique")
        assert technique_percent is not None, (
            "nessuna motivazione (technique) riportata per width=\"1%\": "
            "il finding non e' distinguibile da un 1px assoluto reale"
        )
        assert technique_percent != technique_absolute, (
            "la motivazione riportata per width=\"1%\" (euristica di "
            "prodotto su percentuale) e' indistinguibile da quella di "
            f"width=\"1x\" (1px assoluto reale): entrambe {technique_absolute!r}"
        )

    # ── CLS-01t: `_leading_int` senza limite di lunghezza — crash `int()` ──
    # Bloccante, security-reviewer G6 round 2 (28/7), introdotto da CLS-01r.
    # `_leading_int` fa `int(match.group(1))` su una sequenza di cifre ASCII
    # senza alcun limite di lunghezza. Oltre 4300 cifre scatta la protezione
    # nativa di CPython `sys.set_int_max_str_digits` (default 4300) e
    # solleva `ValueError` NON CATTURATO in nessun punto della catena, fino
    # alla route `/http`. Un dominio ostile disattiva così, in modo
    # affidabile e riproducibile, l'intero `detect_hidden_elements` su se
    # stesso ad ogni scansione. I test asseriscono che nessuna eccezione
    # attraversi la funzione e che il resto del documento venga comunque
    # scansionato normalmente — non solo che l'elemento incriminato non
    # produca (o produca) un finding.

    def test_leading_int_huge_width_img_branch_does_not_crash(self):
        """CLS-01t, PoC del security-reviewer riprodotto sul ramo pixel
        (`<img>`, `_is_one_px`). 4359 cifre nel valore di `width` (soglia
        CPython 4300 superata) sollevano oggi `ValueError` non gestito.
        Il documento contiene anche un form nascosto separato, per
        verificare che il crash non impedisca la scansione del resto del
        markup una volta corretto."""
        digits = "1" * 4359
        html = (f'<img width="{digits}" height="1" src="http://evil.example/px.gif">'
                '<form style="display:none" action="http://evil.example/collect"></form>')
        try:
            result = detect_hidden_elements(html)
        except ValueError as exc:
            raise AssertionError(
                f"detect_hidden_elements ha sollevato ValueError non gestita "
                f"su width con 4359 cifre: {exc}"
            ) from exc
        assert result.get("hidden_forms"), (
            "il form nascosto dopo l'elemento con width a 4359 cifre non è "
            "stato rilevato: la scansione del resto del documento non è "
            "ripresa dopo il valore che causa il crash"
        )

    def test_leading_int_huge_width_iframe_branch_does_not_crash(self):
        """CLS-01t, stesso PoC sul ramo iframe (`_is_zero_or_one_px`,
        canale CRITICAL `legit_invisible_iframe_detected`)."""
        digits = "1" * 4359
        html = f'<iframe width="{digits}" height="0" src="http://evil.example/c2"></iframe>'
        try:
            detect_hidden_elements(html)
        except ValueError as exc:
            raise AssertionError(
                f"detect_hidden_elements ha sollevato ValueError non gestita "
                f"su width iframe con 4359 cifre: {exc}"
            ) from exc

    def test_leading_int_very_large_digit_count_does_not_crash(self):
        """CLS-01t, fixture aggiuntiva raccomandata dal registro (10.000+
        cifre): il cap/gestione dell'eccezione non deve dipendere dalla
        lunghezza esatta del PoC minimo."""
        digits = "9" * 12000
        html = f'<img width="{digits}" height="1" src="http://evil.example/px.gif">'
        try:
            detect_hidden_elements(html)
        except ValueError as exc:
            raise AssertionError(
                f"detect_hidden_elements ha sollevato ValueError non gestita "
                f"su width con 12000 cifre: {exc}"
            ) from exc

    def test_leading_int_just_over_cpython_limit_does_not_crash(self):
        """CLS-01t, confine della soglia CPython (`sys.set_int_max_str_digits`,
        default 4300): 4301 cifre, un solo carattere oltre il limite che
        oggi fa scattare `ValueError`. Isola il confine esatto dal PoC più
        largo (4359) usato negli altri test."""
        digits = "1" * 4301
        html = f'<img width="{digits}" height="1" src="http://evil.example/px.gif">'
        try:
            detect_hidden_elements(html)
        except ValueError as exc:
            raise AssertionError(
                f"detect_hidden_elements ha sollevato ValueError non gestita "
                f"su width con 4301 cifre (un solo carattere oltre la soglia "
                f"CPython 4300): {exc}"
            ) from exc

    def test_leading_int_exactly_at_cpython_limit_control(self):
        """CLS-01t, controllo VERDE (già vero oggi). Esattamente 4300 cifre
        — il limite di CPython, non ancora superato — non solleva
        eccezione anche prima del fix: isola il confine esatto della
        soglia dal caso appena sopra (4301, rosso oggi)."""
        digits = "1" * 4300
        html = f'<img width="{digits}" height="1" src="http://evil.example/px.gif">'
        detect_hidden_elements(html)  # non deve sollevare, né oggi né dopo il fix

    # ── CLS-01s: CR/LF e caratteri di controllo non filtrati in src/action ──
    # Criterio aggiunto dal PM (2026-07-28): un valore src/action contenente
    # CR/LF o caratteri di controllo (categoria Unicode Cc, \x00-\x1F, \x7F)
    # va normalizzato (rimosso o sostituito) prima di finire nel finding
    # persistito nello snapshot. Nessuna regressione sul cap a 300 char
    # (CLS-01i) né sul comportamento None -> None.

    def test_tracking_pixel_src_crlf_stripped(self):
        """CLS-01s, fixture minima del registro. Un tracking pixel con
        CR/LF letterali nella src (tentativo di header/response injection
        se mai loggato non sanitizzato) non deve conservarli nel finding
        persistito."""
        html = '<img width="1" height="1" src="http://evil.example/x\r\nSet-Cookie: evil">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")
        stored = result["tracking_pixels"][0].get("src")
        assert stored is not None
        assert "\r" not in stored and "\n" not in stored, (
            f"CR/LF preservati nella src del tracking pixel: {stored!r}"
        )

    def test_invisible_iframe_src_control_chars_stripped(self):
        """CLS-01s, ramo iframe. Stesso difetto preesistente sul campo
        `src` di `invisible_iframes`: un carattere di controllo (\\x01) non
        deve sopravvivere nel valore persistito."""
        html = '<iframe width="0" height="0" src="http://evil.example/c2\x01injected"></iframe>'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes")
        stored = result["invisible_iframes"][0].get("src")
        assert stored is not None
        assert "\x01" not in stored, (
            f"carattere di controllo preservato nella src dell'iframe invisibile: {stored!r}"
        )

    def test_hidden_form_action_crlf_stripped(self):
        """CLS-01s, ramo form. Stesso difetto preesistente sul campo
        `action` di `hidden_forms`."""
        html = '<form style="display:none" action="http://evil.example/collect\r\nX-Injected: 1"></form>'
        result = detect_hidden_elements(html)
        assert result.get("hidden_forms")
        stored = result["hidden_forms"][0].get("action")
        assert stored is not None
        assert "\r" not in stored and "\n" not in stored, (
            f"CR/LF preservati nella action del form nascosto: {stored!r}"
        )

    def test_tracking_pixel_src_none_still_none_control(self):
        """CLS-01s, controllo VERDE (deve restare vero dopo il fix). La
        normalizzazione CR/LF non deve trasformare un attributo `src`
        assente (`None`) in una stringa vuota o in altro: `_cap_ioc`
        distingue esplicitamente l'attributo assente dal valore vuoto, e la
        normalizzazione non deve rompere quella distinzione."""
        html = '<img width="1" height="1">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")
        assert result["tracking_pixels"][0].get("src") is None

    def test_tracking_pixel_src_crlf_still_capped_at_300_control(self):
        """CLS-01s, controllo VERDE su interazione con CLS-01i. Un src con
        CR/LF ripetuti e comunque molto lunga resta troncata a 300 caratteri
        dopo la normalizzazione — le due protezioni (cap di lunghezza,
        rimozione di CR/LF/caratteri di controllo) devono continuare a
        convivere."""
        src = "http://evil.example/x" + ("\r\n" * 200) + ("A" * 400)
        html = f'<img width="1" height="1" src="{src}">'
        result = detect_hidden_elements(html)
        assert result.get("tracking_pixels")
        stored = result["tracking_pixels"][0].get("src")
        assert stored is not None
        assert len(stored) <= 300, (
            f"src del tracking pixel oltre il cap di 300 caratteri dopo normalizzazione CR/LF: {len(stored)}"
        )

    # ── CLS-01j/CLS-01q, G6 round 3, bloccante 1 (verifier, ALTA) — conteggio
    # SBILANCIATO di aperture/chiusure iframe ──
    # In HTML5 gli elementi RAWTEXT non hanno nesting: il contenuto di un
    # <iframe> si chiude alla PRIMA occorrenza letterale di `</iframe`, punto.
    # Non esiste un secondo iframe "annidato" dal punto di vista del parser
    # reale — quel markup è testo inerte dentro il primo. La pila LIFO +
    # marcatura retroattiva del working tree corrente modella una gerarchia
    # che non esiste e coincide col comportamento reale SOLO a conteggi
    # bilanciati (1/1, 2/2) — esattamente gli unici casi già coperti dai test
    # `test_*_inside_properly_closed_iframe_not_detected` più sopra in questa
    # classe. Quei test restano i controlli VERDI bilanciati di riferimento:
    # non li duplico qui, li richiamo per nome nei docstring sotto.
    #
    # Ogni test qui sotto verifica ANCHE, nello stesso scenario, la coerenza
    # con CLS-01q (l'iframe "civetta" MAI chiuso deve restare rilevato): un
    # fix che eliminasse semplicemente la marcatura opaca in ogni caso
    # (invece di implementare "prima `</iframe` letterale chiude il
    # container aperto più esterno") romperebbe quella parte del contratto,
    # e questi test lo intercettano.

    def test_iframe_unbalanced_2open_1close_not_detected(self):
        """CLS-01j/CLS-01q bloccante 1, G6 round 3. PoC minimale esatto del
        verifier: un solo `</iframe>` in tutto il documento, due `<iframe>`
        aperti (l'esterno, visibile 640x480; un secondo "iframe" che compare
        solo come testo nel fallback dell'esterno). Per un browser reale
        quell'unico `</iframe>` chiude l'iframe ESTERNO legittimo — tutto il
        resto, incluso il testo `<iframe width="0" ...>`, è fallback opaco,
        mai tokenizzato. Oggi (pila LIFO) il secondo tag viene invece
        rilevato come iframe nascosto reale: `invisible_iframes` popolato,
        risk 25, falso positivo CRITICAL `legit_invisible_iframe_detected`.
        CLS-01z (riconciliato, decisione utente: peso 30): la civetta,
        essendo markup morto verso un host esterno (`evil.example`), è ORA
        il bersaglio di `suspicious_dead_markup` — contribuisce 30 al risk,
        non 0."""
        html = ('<iframe src="x" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="http://evil.example/c2"></iframe>')
        result = detect_hidden_elements(html)
        assert not result.get("invisible_iframes"), (
            "iframe esterno legittimo (640x480) chiuso dall'unico </iframe> "
            "del documento: il testo '<iframe width=0...>' nel suo fallback "
            "e' stato trattato come un iframe VIVO in invisible_iframes: "
            f"{result.get('invisible_iframes')}"
        )
        dead = result.get("suspicious_dead_markup")
        assert dead, (
            "CLS-01z: la civetta morta (2 aperture/1 chiusura) verso l'host "
            "esterno evil.example doveva essere rilevata in "
            f"suspicious_dead_markup, nessun finding prodotto: {result}"
        )
        assert all(d.get("type") == "iframe" for d in dead), (
            f"suspicious_dead_markup con type inatteso (atteso solo 'iframe'): {dead}"
        )
        assert all(d.get("source") == "fallback_content" for d in dead), (
            f"suspicious_dead_markup con source inatteso (atteso 'fallback_content'): {dead}"
        )
        assert result["risk_indicators"] == 30, (
            "CLS-01z: peso 30 (per-categoria, deciso dall'utente) su "
            f"conteggio sbilanciato 2 aperture/1 chiusura, ottenuto: {result['risk_indicators']}"
        )

        # Coerenza CLS-01q: lo stesso iframe civetta, mai chiuso stavolta
        # (nessun </iframe> affatto), deve restare rilevato.
        never_closed = ('<iframe src="x" width="640" height="480">fallback '
                         '<iframe width="0" height="0" src="http://evil.example/c2">')
        result_unclosed = detect_hidden_elements(never_closed)
        assert result_unclosed.get("invisible_iframes"), (
            "controllo di coerenza CLS-01q: lo stesso iframe annidato, con "
            "l'esterno MAI chiuso (zero </iframe> nel documento), deve "
            "restare rilevato"
        )

    def test_iframe_unbalanced_3open_1close_not_detected(self):
        """CLS-01j/CLS-01q bloccante 1, matrice 3 aperture/1 chiusura. Tre
        `<iframe>` testuali (l'esterno legittimo + due "civette" annidate nel
        suo fallback) ma un solo `</iframe>` in tutto il documento: chiude
        l'esterno, tutto il resto — comprese le due civette — è fallback
        inerte. Oggi la pila LIFO tratta ENTRAMBE le civette come iframe
        reali (nessuna delle due viene mai marcata opaca, perché lo stack
        resta con 2 container aperti quando arriva l'unico `</iframe>`).
        CLS-01z (riconciliato, decisione utente: peso 30): entrambe le
        civette, essendo markup morto verso host esterno (`evil.example`),
        sono ORA il bersaglio di `suspicious_dead_markup` — la CATEGORIA
        contribuisce 30 al risk una sola volta (peso per-categoria, non
        per-elemento, coerente con `hidden_forms`/`invisible_iframes` —
        v. `shared/utils.py`, blocco di scoring), non 0, anche con due
        elementi morti."""
        html = ('<iframe src="x" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="http://evil.example/c2">'
                '<iframe width="0" height="0" src="http://evil.example/c3"></iframe>')
        result = detect_hidden_elements(html)
        assert not result.get("invisible_iframes"), (
            "conteggio 3 aperture/1 chiusura: markup interamente fallback "
            "dell'esterno, ma rilevato come iframe VIVI in invisible_iframes: "
            f"{result.get('invisible_iframes')}"
        )
        dead = result.get("suspicious_dead_markup")
        assert dead, (
            "CLS-01z: le due civette morte (3 aperture/1 chiusura) verso "
            "l'host esterno evil.example dovevano essere rilevate in "
            f"suspicious_dead_markup, nessun finding prodotto: {result}"
        )
        assert all(d.get("type") == "iframe" for d in dead), (
            f"suspicious_dead_markup con type inatteso (atteso solo 'iframe'): {dead}"
        )
        assert all(d.get("source") == "fallback_content" for d in dead), (
            f"suspicious_dead_markup con source inatteso (atteso 'fallback_content'): {dead}"
        )
        assert result["risk_indicators"] == 30, (
            "CLS-01z: peso 30 per-categoria (non per-elemento) anche con "
            f"due civette morte, ottenuto: {result['risk_indicators']}"
        )

        never_closed = ('<iframe src="x" width="640" height="480">fallback '
                         '<iframe width="0" height="0" src="http://evil.example/c2">'
                         '<iframe width="0" height="0" src="http://evil.example/c3">')
        result_unclosed = detect_hidden_elements(never_closed)
        assert result_unclosed.get("invisible_iframes"), (
            "controllo di coerenza CLS-01q: le stesse civette, con l'esterno "
            "MAI chiuso, devono restare rilevate"
        )

    def test_iframe_unbalanced_3open_2close_not_detected(self):
        """CLS-01j/CLS-01q bloccante 1, matrice 3 aperture/2 chiusure. Il
        PRIMO `</iframe>` del documento chiude l'esterno (RAWTEXT termina
        lì): tutto ciò che precede — comprese le due civette annidate — è
        fallback inerte. Il SECONDO `</iframe>`, che segue, è un tag di
        chiusura senza alcun elemento realmente aperto sullo stack del
        parser (l'esterno si e' gia' chiuso): per un browser e' un end-tag
        orfano, ignorato. Oggi la pila LIFO pop-pa un container ad ogni
        chiusura letterale indipendentemente da quale iframe sia realmente
        "il primo", e produce comunque un finding sulla prima civetta.
        CLS-01z (riconciliato, decisione utente: peso 30): entrambe le
        civette, essendo markup morto verso host esterno (`evil.example`),
        sono ORA il bersaglio di `suspicious_dead_markup` — 30 al risk
        (peso per-categoria, una volta sola anche con due elementi morti),
        non 0."""
        html = ('<iframe src="x" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="http://evil.example/c2">'
                '<iframe width="0" height="0" src="http://evil.example/c3">'
                '</iframe></iframe>')
        result = detect_hidden_elements(html)
        assert not result.get("invisible_iframes"), (
            "conteggio 3 aperture/2 chiusure: il primo </iframe> letterale "
            "chiude l'esterno, tutto il resto e' fallback inerte, ma e' "
            f"stato rilevato come iframe VIVI in invisible_iframes: {result.get('invisible_iframes')}"
        )
        dead = result.get("suspicious_dead_markup")
        assert dead, (
            "CLS-01z: le due civette morte (3 aperture/2 chiusure) verso "
            "l'host esterno evil.example dovevano essere rilevate in "
            f"suspicious_dead_markup, nessun finding prodotto: {result}"
        )
        assert all(d.get("type") == "iframe" for d in dead), (
            f"suspicious_dead_markup con type inatteso (atteso solo 'iframe'): {dead}"
        )
        assert all(d.get("source") == "fallback_content" for d in dead), (
            f"suspicious_dead_markup con source inatteso (atteso 'fallback_content'): {dead}"
        )
        assert result["risk_indicators"] == 30, (
            "CLS-01z: peso 30 per-categoria (non per-elemento) anche con "
            f"due civette morte, ottenuto: {result['risk_indicators']}"
        )

        never_closed = ('<iframe src="x" width="640" height="480">fallback '
                         '<iframe width="0" height="0" src="http://evil.example/c2">'
                         '<iframe width="0" height="0" src="http://evil.example/c3">')
        result_unclosed = detect_hidden_elements(never_closed)
        assert result_unclosed.get("invisible_iframes"), (
            "controllo di coerenza CLS-01q: le stesse civette, con l'esterno "
            "MAI chiuso, devono restare rilevate"
        )

    def test_hidden_form_inside_unbalanced_nested_iframe_not_detected(self):
        """CLS-01j/CLS-01q bloccante 1, ramo form, stessa forma sbilanciata
        (2 aperture/1 chiusura) applicata a un form nascosto invece di un
        iframe annidato: un form di credential harvesting che compare solo
        nel testo fallback dell'esterno (dopo una civetta "<iframe>" mai
        realmente aperta) non e' un elemento del documento per un browser —
        l'unico `</iframe>` chiude l'esterno legittimo prima che il form
        possa essere considerato "fuori" da esso.
        CLS-01z (riconciliato, decisione utente: peso 30): sia la civetta
        sia il form, essendo markup morto verso host esterno
        (`evil.example`), sono ORA il bersaglio di `suspicious_dead_markup`
        — 30 al risk (peso per-categoria, una volta sola anche con due tipi
        diversi di elemento morto), non 0."""
        html = ('<iframe src="x" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="http://evil.example/c2">junk '
                '<form style="display:none" action="http://evil.example/collect">'
                '</form></iframe>')
        result = detect_hidden_elements(html)
        assert not result.get("hidden_forms"), (
            "form nel fallback di un iframe esterno chiuso da un </iframe> "
            f"sbilanciato (2 aperture/1 chiusura) e' stato rilevato come "
            f"elemento VIVO in hidden_forms: {result.get('hidden_forms')}"
        )
        assert not result.get("invisible_iframes"), (
            "la civetta testuale nello stesso fallback e' stata rilevata "
            f"come iframe VIVO in invisible_iframes: {result.get('invisible_iframes')}"
        )
        dead = result.get("suspicious_dead_markup")
        assert dead, (
            "CLS-01z: la civetta e il form morti (2 aperture/1 chiusura) "
            "verso l'host esterno evil.example dovevano essere rilevati in "
            f"suspicious_dead_markup, nessun finding prodotto: {result}"
        )
        assert {d.get("type") for d in dead} == {"iframe", "form"}, (
            f"suspicious_dead_markup con i type attesi (iframe + form) mancanti o inattesi: {dead}"
        )
        assert all(d.get("source") == "fallback_content" for d in dead), (
            f"suspicious_dead_markup con source inatteso (atteso 'fallback_content'): {dead}"
        )
        assert result["risk_indicators"] == 30, (
            "CLS-01z: peso 30 per-categoria su conteggio sbilanciato, "
            f"ottenuto: {result['risk_indicators']}"
        )

        never_closed = ('<iframe src="x" width="640" height="480">fallback '
                         '<iframe width="0" height="0" src="http://evil.example/c2">junk '
                         '<form style="display:none" action="http://evil.example/collect"></form>')
        result_unclosed = detect_hidden_elements(never_closed)
        assert result_unclosed.get("hidden_forms"), (
            "controllo di coerenza CLS-01q: lo stesso form, con l'esterno "
            "MAI chiuso, deve restare rilevato"
        )

    def test_tracking_pixel_inside_unbalanced_nested_iframe_not_detected(self):
        """CLS-01j/CLS-01q bloccante 1, ramo pixel (`<img>`), stessa forma
        sbilanciata (2 aperture/1 chiusura). Un pixel 1x1 nel fallback
        testuale dell'esterno, dopo una civetta "<iframe>" mai realmente
        aperta, non viene mai caricato da un browser: l'unico `</iframe>`
        del documento chiude l'esterno prima.
        CLS-01z (riconciliato, decisione utente: peso 30): sia la civetta
        sia il pixel, essendo markup morto verso host esterno
        (`evil.example`), sono ORA il bersaglio di `suspicious_dead_markup`
        — 30 al risk (peso per-categoria, una volta sola anche con due tipi
        diversi di elemento morto), non 0."""
        html = ('<iframe src="x" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="http://evil.example/c2">junk '
                '<img width="1" height="1" src="http://evil.example/px.gif"></iframe>')
        result = detect_hidden_elements(html)
        assert not result.get("tracking_pixels"), (
            "pixel nel fallback di un iframe esterno chiuso da un </iframe> "
            f"sbilanciato (2 aperture/1 chiusura) e' stato rilevato come "
            f"elemento VIVO in tracking_pixels: {result.get('tracking_pixels')}"
        )
        assert not result.get("invisible_iframes"), (
            "la civetta testuale nello stesso fallback e' stata rilevata "
            f"come iframe VIVO in invisible_iframes: {result.get('invisible_iframes')}"
        )
        dead = result.get("suspicious_dead_markup")
        assert dead, (
            "CLS-01z: la civetta e il pixel morti (2 aperture/1 chiusura) "
            "verso l'host esterno evil.example dovevano essere rilevati in "
            f"suspicious_dead_markup, nessun finding prodotto: {result}"
        )
        assert {d.get("type") for d in dead} == {"iframe", "img"}, (
            f"suspicious_dead_markup con i type attesi (iframe + img) mancanti o inattesi: {dead}"
        )
        assert all(d.get("source") == "fallback_content" for d in dead), (
            f"suspicious_dead_markup con source inatteso (atteso 'fallback_content'): {dead}"
        )
        assert result["risk_indicators"] == 30, (
            "CLS-01z: peso 30 per-categoria su conteggio sbilanciato, "
            f"ottenuto: {result['risk_indicators']}"
        )

        never_closed = ('<iframe src="x" width="640" height="480">fallback '
                         '<iframe width="0" height="0" src="http://evil.example/c2">junk '
                         '<img width="1" height="1" src="http://evil.example/px.gif">')
        result_unclosed = detect_hidden_elements(never_closed)
        assert result_unclosed.get("tracking_pixels"), (
            "controllo di coerenza CLS-01q: lo stesso pixel, con l'esterno "
            "MAI chiuso, deve restare rilevato"
        )

    # ── CLS-01j/CLS-01q, G6 round 3, bloccante 2 (security-reviewer,
    # BLOCCANTE) — DoS CPU O(n^2) su nesting BEN CHIUSO ──
    # `handle_endtag` marca opaco con `for t in self.tags[start:]`: O(k) per
    # ogni chiusura. Su n iframe annidati e regolarmente chiusi il lavoro
    # totale e' n(n-1)/2. Misure del security-reviewer (post-diff round 2 vs
    # HEAD pre-diff): n=5000 -> 0,445s vs 0,042s; n=20000 -> 6,86s vs 0,123s;
    # n=80000 -> non terminato entro 120s vs 0,497s.
    #
    # Logica della soglia (perche' non e' flaky): il test NON usa un tempo
    # assoluto in secondi (dipenderebbe dalla velocita' della macchina che
    # esegue la suite). Misura invece il RAPPORTO fra il tempo a due taglie
    # in scala 4x (n_small -> n_large = 4 * n_small), sullo stesso host,
    # nella stessa esecuzione: se il costo e' O(n) il rapporto atteso e'
    # ~4x (l'overhead fisso di parsing/setup lo tiene anche leggermente
    # sotto, mai sopra di molto); se e' O(n^2) il rapporto atteso e' ~16x
    # (4^2). La soglia scelta (6x) sta a meta' strada, con ampio margine da
    # entrambi i lati: un fix lineare non la sfiora nemmeno (misurato
    # empiricamente ~4x-5x su HEAD pre-diff con lo stesso generatore), il
    # difetto quadratico attuale la supera nettamente (misurato qui sotto,
    # ~9-10x a queste taglie, in crescita verso l'asintoto 16x a taglie
    # maggiori — le taglie scelte restano modeste per non appesantire la
    # suite). Essendo un rapporto fra due misure sullo STESSO host nella
    # STESSA esecuzione, un host piu' lento o piu' veloce sposta entrambi i
    # tempi nella stessa direzione e lascia il rapporto pressoche' invariato
    # — e' quindi robusto a macchine lente, a differenza di una soglia in
    # secondi. Si misura il tempo di CPU del thread (`time.thread_time`), non
    # il tempo di parete: quando altri processi si contendono i core (come
    # con la suite divisa fra piu' processi da tests/run_parallel.py,
    # BUILD-09) il tempo di parete conta anche le attese del processo e
    # gonfia la sola misura che cade in un picco di carico, fino a portare
    # un costo lineare oltre la soglia; il tempo di CPU conta solo il lavoro
    # fatto. Le misure delle due taglie si alternano (piccola, grande,
    # piccola, grande, ...) e per ogni taglia vale il minimo di 3: un
    # disturbo che dura qualche misura colpisce entrambe le taglie invece di
    # una sola, e il minimo attutisce il rumore che resta (cache, frequenza
    # del processore), non sposta la soglia.

    def test_nested_closed_iframes_endtag_marking_scales_linearly_not_quadratically(self):
        """CLS-01j/CLS-01q bloccante 2. Nesting ben chiuso e regolare
        (n `<iframe>` annidati, tutti richiusi correttamente), NON la catena
        di civette mai chiuse gia' misurata (e accettata come lineare) al
        round 2. Vedi il commento sopra la classe per la logica della soglia."""
        def make_html(n):
            return ('<iframe src="x" width="0" height="0">' * n) + ('</iframe>' * n)

        small_n, large_n = 2000, 8000  # rapporto di taglia 4x
        pages = {n: make_html(n) for n in (small_n, large_n)}
        best = dict.fromkeys(pages, float("inf"))
        for _ in range(3):
            for n, html in pages.items():
                t0 = time.thread_time()
                detect_hidden_elements(html)
                best[n] = min(best[n], time.thread_time() - t0)
        t_small, t_large = best[small_n], best[large_n]
        ratio = t_large / t_small
        assert ratio < 6.0, (
            f"tempo non scala linearmente su nesting ben chiuso: n={small_n} -> "
            f"{t_small:.4f}s, n={large_n} -> {t_large:.4f}s, rapporto {ratio:.2f}x "
            f"per un aumento di taglia 4x (atteso ~4x se lineare, soglia 6x; "
            "un rapporto vicino a 16x indica complessita' quadratica O(n^2) in "
            "`handle_endtag`)"
        )

    # ── CLS-01r, G6 round 3, rilievo MEDIA (verifier, punto C) —
    # `_zero_dimension_technique` sul ramo IFRAME ignora `percent` ──
    # La distinzione fra 1px assoluto reale e percentuale trattata come
    # sospetta per euristica di prodotto (decisione utente 2026-07-28) esiste
    # gia' sul ramo <img> (`_pixel_technique`, fixture 7 del G3 emendato) ma
    # NON sul ramo iframe (`_zero_dimension_technique`, che controlla solo
    # `rounded` e ignora del tutto `percent`): `width="1%"` e `width="0"`
    # producono oggi entrambi `technique=['zero_dimension']`, indistinguibili
    # per l'analista. Stessa disciplina della fixture 7: disuguaglianza in
    # senso debole (`!=`), nessuna stringa esatta imposta.

    def test_invisible_iframe_percent_technique_distinct_from_absolute_zero(self):
        """CLS-01r, ramo iframe. `width="1%"` (euristica su percentuale) deve
        produrre una `technique` diversa da `width="0"` (davvero 0x0): oggi
        sono identiche (`['zero_dimension']` in entrambi i casi), quindi
        l'analista non puo' distinguere un falso positivo potenziale
        (percentuale) da un iframe genuinamente invisibile."""
        absolute_zero = detect_hidden_elements(
            '<iframe width="0" height="480" src="http://evil.tld/c2"></iframe>')
        percent = detect_hidden_elements(
            '<iframe width="1%" height="480" src="http://evil.tld/c2"></iframe>')
        assert percent.get("invisible_iframes"), (
            'width="1%" non rilevato affatto come dimensione sospetta sul ramo iframe'
        )
        technique_zero = absolute_zero["invisible_iframes"][0].get("technique")
        technique_percent = percent["invisible_iframes"][0].get("technique")
        assert technique_percent != technique_zero, (
            "la motivazione riportata per width=\"1%\" sul ramo iframe e' "
            f"indistinguibile da quella di width=\"0\" (davvero 0x0): entrambe {technique_zero!r}"
        )

    def test_invisible_iframe_rounded_percent_technique_distinct_from_rounded_only(self):
        """CLS-01r, combinazione ROUNDED + PERCENT sul ramo iframe, non
        etichettata dal fixer (dichiarato nel registro): `width="0.5%"` e'
        insieme un valore che arrotonda per eccesso (round-half-up) E una
        percentuale. Deve produrre una `technique` diversa da `width="0.5"`
        (arrotondato ma NON percentuale, gia' distinto da CLS-01r fixture 5
        da un vero 0x0): oggi entrambi risolvono a
        `['zero_dimension_rounded']`, identici."""
        rounded_only = detect_hidden_elements(
            '<iframe width="0.5" height="480" src="http://evil.tld/c2"></iframe>')
        rounded_percent = detect_hidden_elements(
            '<iframe width="0.5%" height="480" src="http://evil.tld/c2"></iframe>')
        assert rounded_percent.get("invisible_iframes"), (
            'width="0.5%" non rilevato affatto come dimensione sospetta sul ramo iframe'
        )
        technique_rounded_only = rounded_only["invisible_iframes"][0].get("technique")
        technique_rounded_percent = rounded_percent["invisible_iframes"][0].get("technique")
        assert technique_rounded_percent != technique_rounded_only, (
            "la motivazione riportata per width=\"0.5%\" (arrotondato E "
            "percentuale) e' indistinguibile da quella di width=\"0.5\" "
            f"(arrotondato, non percentuale): entrambe {technique_rounded_only!r}"
        )

    # ── CLS-01t, G6 round 3, rilievo MEDIA (verifier, punto D) —
    # `PYTHONINTMAXSTRDIGITS=0` disattiva silenziosamente la guardia ──
    # `_MAX_INT_DIGITS = sys.get_int_max_str_digits()` e' letta correttamente
    # a import-time (il security-reviewer ha ragione su questo aspetto: non
    # e' un problema di staleness). Il difetto e' un altro: con
    # `PYTHONINTMAXSTRDIGITS=0` (valore documentato da CPython per "nessun
    # limite"), `_MAX_INT_DIGITS` vale 0, e la guardia
    # `len(digits) > _MAX_INT_DIGITS` diventa `len(digits) > 0` — VERO per
    # qualunque cifra non vuota, quindi OGNI prefisso numerico viene scartato
    # (`_parse_dimension` ritorna sempre `None`). L'intero rilevamento
    # zero/one-px si spegne silenziosamente per tutti i domini: "0 finding"
    # indistinguibile da "pagina pulita".
    #
    # `_MAX_INT_DIGITS` e' letta A IMPORT-TIME del modulo: nel processo
    # pytest corrente `shared.utils` e' gia' importato con l'ambiente del
    # runner (senza `PYTHONINTMAXSTRDIGITS=0`), e ne modificare
    # l'attributo del modulo a mano testerebbe l'implementazione (il nome
    # della costante), non il comportamento reale di un processo avviato
    # con quella variabile d'ambiente. Uso quindi un subprocess Python
    # indipendente, con l'ambiente modificato PRIMA dell'avvio
    # dell'interprete (dove la lettura a import-time e' effettivamente presa
    # in considerazione da CPython) — dichiarato esplicitamente qui come
    # richiesto: e' l'unico modo pulito di riprodurre questo comportamento
    # dal processo di test corrente, senza toccare `shared/utils.py`.

    def test_int_max_str_digits_zero_silently_disables_zero_one_px_detection(self):
        """CLS-01t, rilievo MEDIA del verifier. Sottoprocesso Python con
        `PYTHONINTMAXSTRDIGITS=0` impostata nell'ambiente PRIMA dell'avvio
        dell'interprete: un iframe 0x0 palesemente nascosto
        (`width="0" height="0"`) non produce ALCUN finding e
        `risk_indicators` resta a 0 — l'intero canale di rilevamento
        zero/one-px e' silenziosamente spento, senza errori né segnali di
        degrado, per qualunque dominio scansionato in quel processo."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script = (
            "import sys; sys.path.insert(0, %r)\n"
            "from shared.utils import detect_hidden_elements, _MAX_INT_DIGITS\n"
            "html = '<iframe width=\"0\" height=\"0\" src=\"http://evil.tld/c2\"></iframe>'\n"
            "r = detect_hidden_elements(html)\n"
            "print('MAX_INT_DIGITS=%%d' %% _MAX_INT_DIGITS)\n"
            "print('invisible_iframes=%%r' %% (r.get('invisible_iframes'),))\n"
            "print('risk=%%d' %% r['risk_indicators'])\n"
        ) % (repo_root,)

        env = dict(os.environ)
        env["PYTHONINTMAXSTRDIGITS"] = "0"
        env["PYTHONPATH"] = repo_root
        proc = subprocess.run(
            [sys.executable, "-c", script],
            env=env, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0, (
            f"il sottoprocesso con PYTHONINTMAXSTRDIGITS=0 e' terminato con "
            f"errore (returncode={proc.returncode}):\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
        assert "MAX_INT_DIGITS=0" in proc.stdout, (
            f"la sentinella PYTHONINTMAXSTRDIGITS=0 non e' stata letta a "
            f"import-time come atteso: {proc.stdout!r}"
        )
        assert "invisible_iframes=None" not in proc.stdout, (
            "un iframe palesemente 0x0 (width=0 height=0) non produce alcun "
            "finding quando PYTHONINTMAXSTRDIGITS=0: il rilevamento "
            f"zero/one-px e' silenziosamente disattivato. Output: {proc.stdout!r}"
        )
        assert "risk=0" not in proc.stdout, (
            f"risk_indicators resta a 0 su un iframe 0x0 palese quando "
            f"PYTHONINTMAXSTRDIGITS=0: {proc.stdout!r}"
        )

    # ── CLS-01z: detector "markup iframe/form/img sospetto verso host
    # esterno" — nasce da CLS-01y + CLS-01w, ma **round-3 (decisione utente,
    # BUG-REGISTER.md §6)** ne ha RISTRETTO lo scope al SOLO caso (a)
    # "fallback_content" (markup nel fallback content di un iframe
    # REGOLARMENTE CHIUSO — il vettore originale di CLS-01w). I casi (b)
    # "malformed_endtag_swallow" e (c) "bogus_comment" sono stati RIMOSSI
    # dallo scope (doppio conteggio e DoS per-span, entrambi bocciati al
    # G6) — i relativi test sono stati rimossi da questa suite nello stesso
    # round, non solo dalla produzione. Contratto attuale (BUG-REGISTER.md,
    # `CLS-01z`): nuova chiave `suspicious_dead_markup` (lista) in
    # `detect_hidden_elements`, ogni elemento con `source == "fallback_content"`;
    # discriminante primario è l'HOST ESTERNO, NON un `AND` con
    # l'invisibilità (l'errore concettuale bocciato dal verifier su
    # CLS-01w) — un tag morto a grandezza piena e senza alcuna tecnica di
    # occultamento è comunque sospetto, perché non è mai stato renderizzato
    # per costruzione (fallback content opaco). Peso 30 in `risk_indicators`
    # (deciso dall'utente): un solo finding porta il caso a suspicious/HIGH
    # da solo in `classify_variant` (services/classifier.py:365-382).
    #
    # I test asseriscono sul COMPORTAMENTO osservabile (presenza/assenza del
    # finding, campo `source`, contributo al risk), non sul meccanismo
    # interno. Solo host `evil.example`/`legit.example`/`example.com`/CDN
    # reali già presenti in `_CDN_WHITELIST` — mai nomi di tenant reali, per
    # costruzione (vincolo del mandato).

    def test_suspicious_dead_markup_fallback_iframe_zero_size_external(self):
        """Battuta 1. Iframe morto (0x0, host esterno) annidato nel fallback
        content di un iframe esterno regolarmente chiuso (già escluso da
        `invisible_iframes` per la semantica RAWTEXT reale, CLS-01j/q) deve
        comparire in `suspicious_dead_markup` con source=fallback_content."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="http://evil.example/c2">'
                '</iframe></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "iframe morto (0x0, esterno) nel fallback content di un iframe "
            f"regolarmente chiuso non e' stato rilevato: {result}"
        )
        assert any(f.get("source") == "fallback_content" for f in findings), findings

    def test_suspicious_dead_markup_fallback_iframe_full_size_external_still_detected(self):
        """Battuta 2 (punto-B del verifier: niente AND con l'invisibilità).
        Stesso markup del caso 1, ma l'iframe morto annidato è a GRANDEZZA
        PIENA (640x480, nessun segnale di invisibilità/nascondimento): deve
        restare rilevato lo stesso, perché non è mai stato renderizzato da
        nessun browser — è opaco per costruzione, non per occultamento."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<iframe width="640" height="480" src="http://evil.example/c2">'
                '</iframe></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "iframe morto a grandezza piena (640x480, nessun segnale di "
            f"invisibilita') nel fallback content non e' stato rilevato: {result}"
        )

    def test_suspicious_dead_markup_fallback_iframe_internal_host_no_finding(self):
        """Battuta 3. Lo stesso markup morto, ma verso l'host INTERNO
        (self_domain del sito): il criterio è "host esterno", non basta che
        il markup sia morto — un self-reference innocuo nel fallback non è
        un indicatore di rischio."""
        html = ('<iframe src="https://legit-corp.example/" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="https://legit-corp.example/internal">'
                '</iframe></iframe>')
        result = detect_hidden_elements(html, self_domain="legit-corp.example")
        assert not result.get("suspicious_dead_markup"), (
            "markup morto verso l'host INTERNO (self_domain) e' stato "
            f"erroneamente segnalato come sospetto: {result.get('suspicious_dead_markup')}"
        )

    def test_suspicious_dead_markup_fallback_form_external(self):
        """Battuta 8. Rischio residuo 3 del G2 (BUG-REGISTER.md): il form
        morto via FALLBACK CONTENT (non swallow) non aveva un PoC dedicato
        del researcher — verificato qui esplicitamente, non per analogia
        con gli altri PoC (iframe/img)."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<form action="http://evil.example/collect">steal me</form>'
                '</iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "form nel fallback content di un iframe regolarmente chiuso, "
            f"verso host esterno, non e' stato rilevato: {result}"
        )
        assert any(f.get("type") == "form" and f.get("source") == "fallback_content"
                   for f in findings), findings

    def test_suspicious_dead_markup_fallback_img_external_any_size(self):
        """Battuta 9. Img morto nel fallback content, host esterno, a
        grandezza QUALUNQUE (600x400, nessun segnale di invisibilità/pixel
        di tracciamento): deve essere rilevato lo stesso, stesso principio
        del caso 2 applicato al ramo img."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="http://evil.example/px.gif" width="600" height="400">'
                '</iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "img nel fallback content di un iframe regolarmente chiuso, "
            "verso host esterno e a grandezza qualunque (600x400, nessun "
            f"segnale di invisibilita'), non e' stato rilevato: {result}"
        )
        assert any(f.get("type") == "img" and f.get("source") == "fallback_content"
                   for f in findings), findings

    def test_suspicious_dead_markup_fallback_img_and_form_internal_host_no_finding(self):
        """Battuta 10. Img e form morti nel fallback content, ma verso
        l'host INTERNO (self_domain): nessun finding, stesso principio del
        caso 3 applicato ai rami img/form."""
        html = ('<iframe src="https://legit-corp.example/" width="640" height="480">fallback '
                '<img src="https://legit-corp.example/assets/px.gif" width="600" height="400">'
                '<form action="https://legit-corp.example/opt-in">stay</form>'
                '</iframe>')
        result = detect_hidden_elements(html, self_domain="legit-corp.example")
        assert not result.get("suspicious_dead_markup"), (
            "img/form nel fallback content verso l'host INTERNO (self_domain) "
            f"segnalati erroneamente come sospetti: {result.get('suspicious_dead_markup')}"
        )

    def test_suspicious_dead_markup_literal_markup_inside_script_and_style_not_detected(self):
        """Battuta 11. Un `<iframe src="http://evil.example/...">` che
        compare LETTERALMENTE dentro `<script>` o `<style>` non è mai
        renderizzato né tokenizzato da un browser (RAWTEXT reale, non
        soppresso per script/style — a differenza di iframe): non deve
        produrre alcun finding, in nessuno dei due contesti."""
        in_script = ('<script>var x = "<iframe src=\'http://evil.example/x\' '
                     'width=0 height=0></iframe>";</script>')
        result_script = detect_hidden_elements(in_script)
        assert not result_script.get("suspicious_dead_markup"), (
            "markup <iframe> letterale dentro <script> (mai renderizzato, "
            f"RAWTEXT reale) e' stato segnalato come sospetto: "
            f"{result_script.get('suspicious_dead_markup')}"
        )

        in_style = ('<style>/* <iframe src="http://evil.example/x" width=0 '
                    'height=0></iframe> */</style>')
        result_style = detect_hidden_elements(in_style)
        assert not result_style.get("suspicious_dead_markup"), (
            "markup <iframe> letterale dentro <style> (mai renderizzato, "
            f"RAWTEXT reale) e' stato segnalato come sospetto: "
            f"{result_style.get('suspicious_dead_markup')}"
        )

    def test_suspicious_dead_markup_relative_url_no_finding(self):
        """Battuta 12. Src relativo (nessun host assoluto): il criterio
        host-esterno non si applica, non c'è un host da valutare — nessun
        finding, coerente con `external_resources` che richiede
        `https?://` assoluto."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="/relative/path/c2"></iframe>'
                '</iframe>')
        result = detect_hidden_elements(html)
        assert not result.get("suspicious_dead_markup"), (
            "markup morto con src/action RELATIVO (nessun host assoluto) e' "
            f"stato erroneamente segnalato come sospetto: {result.get('suspicious_dead_markup')}"
        )

    def test_suspicious_dead_markup_no_double_count_with_invisible_iframes_control(self):
        """Battuta 13, controllo di non regressione (verde già oggi, perché
        `suspicious_dead_markup` non esiste ancora — deve RESTARE verde dopo
        il fix). Un iframe VIVO (0x0, esterno, regolarmente chiuso, già
        tokenizzato normalmente e presente in `invisible_iframes`) non deve
        comparire ANCHE in `suspicious_dead_markup`: i due canali coprono
        markup vivo e morto rispettivamente, senza sovrapposizione — per
        costruzione, un tag vivo non è mai parte di una regione opaca o di
        un end-tag malformato. Con `</iframe>` PULITO come qui, questo
        controllo è verde a prescindere dall'esistenza del caso (b) — v.
        `test_suspicious_dead_markup_no_double_count_live_iframe_malformed_endtag_real_poc`
        sotto per il PoC reale del doppio conteggio con un end-tag bogus."""
        html = '<iframe src="http://evil.example/c2" width="0" height="0"></iframe>'
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes"), (
            "controllo di base: l'iframe vivo 0x0 esterno deve restare "
            f"rilevato da invisible_iframes: {result}"
        )
        dead = result.get("suspicious_dead_markup") or []
        assert not any("evil.example" in str(f) for f in dead), (
            "lo stesso iframe VIVO (gia' in invisible_iframes) e' stato "
            f"contato ANCHE come suspicious_dead_markup, doppio conteggio: {dead}"
        )

    def test_suspicious_dead_markup_no_double_count_live_iframe_malformed_endtag_real_poc(self):
        """CLS-01z, decisione utente (BUG-REGISTER.md §6, round-3): il caso
        (b) "malformed_endtag_swallow" e' RIMOSSO dallo scope del detector
        (portava doppio conteggio, bocciato al G6). PoC del verifier: un
        iframe VIVO invisibile esterno (`style="display:none"`,
        regolarmente chiuso da un end-tag CHE PORTA COMUNQUE ATTRIBUTI
        bogus, quindi "non pulito" secondo `_CLEAN_ENDTAG_RE`) e' un
        elemento reale del documento — un browser lo renderizza (nascosto)
        e ignora silenziosamente gli attributi spuri sull'end-tag, non lo
        tratta come due elementi distinti. A differenza del vecchio
        controllo con `</iframe>` pulito (banalmente verde perche' nessuna
        implementazione del caso b poteva mai intercettarlo), qui l'end-tag
        e' deliberatamente malformato (`data-x="decoy" src="..."`) — con il
        caso (b) ancora presente nel codice, lo STESSO host esterno viene
        contato SIA in `invisible_iframes` SIA in `suspicious_dead_markup`
        (risk 25+30=55 invece di 25): e' il doppio conteggio reale
        refutato dal verifier, non un caso limite sintetico. Con il caso
        (b) rimosso, l'iframe vivo deve restare SOLO in `invisible_iframes`."""
        html = ('<iframe style="display:none" src="http://evil.example/c2">'
                '</iframe data-x="decoy" src="http://evil.example/c2">')
        result = detect_hidden_elements(html)
        assert result.get("invisible_iframes"), (
            "controllo di base: l'iframe vivo nascosto (display:none, host "
            f"esterno) deve restare rilevato da invisible_iframes: {result}"
        )
        dead = result.get("suspicious_dead_markup") or []
        assert not any("evil.example" in str(f) for f in dead), (
            "lo stesso iframe VIVO, chiuso da un end-tag con attributi "
            "bogus (ma comunque un end-tag che chiude regolarmente "
            "l'elemento per un browser reale), e' stato contato ANCHE "
            "come suspicious_dead_markup (caso 'malformed_endtag_swallow', "
            f"ora fuori scope): doppio conteggio reale: {dead}"
        )

    def test_suspicious_dead_markup_risk_score_at_least_30(self):
        """Battuta 14. Peso deciso dall'utente (BUG-REGISTER.md, `CLS-01z`):
        un solo `suspicious_dead_markup` verso host esterno porta
        `risk_indicators` a >= 30 — soglia sufficiente da sola a far
        scattare `suspicious`/HIGH in `classify_variant`
        (services/classifier.py:365-382, `hidden_risk >= 30`), a differenza
        del peso 25 di `invisible_iframes` che richiede un secondo segnale.
        Markup a singolo segnale (nessun hidden_forms/invisible_iframes
        prodotto da questo HTML): il contributo al risk è isolabile.
        Riscritto per lo scope ristretto al solo caso (a) `fallback_content`
        (round-3, decisione utente §6): l'HTML precedente si appoggiava al
        caso (b) `malformed_endtag_swallow`, ora fuori scope."""
        html = ('<iframe src="https://legit.example/x" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="http://evil.example/c2"></iframe>'
                '</iframe>')
        result = detect_hidden_elements(html)
        assert result.get("suspicious_dead_markup"), (
            f"precondizione del test di scoring non soddisfatta, nessun finding: {result}"
        )
        assert not result.get("invisible_iframes") and not result.get("hidden_forms"), (
            "precondizione del test di scoring non soddisfatta: altri "
            f"finding contribuiscono al risk oltre a suspicious_dead_markup: {result}"
        )
        assert result["risk_indicators"] >= 30, (
            "un solo suspicious_dead_markup verso host esterno non porta "
            f"risk_indicators a >= 30 (peso deciso dall'utente): {result['risk_indicators']}"
        )

    # ── CLS-01z round-2, falso positivo CDN ──
    # `_dead_markup_external_host` valuta OGNI host assoluto diverso dal
    # self_domain come "esterno", inclusi gli host della whitelist CDN già
    # usata da `external_resources` (sezione 8 di `detect_hidden_elements`,
    # shared/utils.py ~968-976) per non segnalare risorse legittime
    # (Google Fonts, jsDelivr, YouTube embed, ...). Un embed YouTube in
    # fallback content/swallow/bogus-comment è markup MORTO (mai
    # renderizzato) ma NON è di per sé un indicatore di compromissione: è
    # lo stesso principio che tiene questi host fuori da
    # `external_resources`. Il fix atteso riusa la stessa whitelist anche
    # qui. `youtube.com` è scelto perché è un host reale già presente in
    # quella lista (shared/utils.py:975), non inventato per questo test.
    def test_suspicious_dead_markup_fallback_content_cdn_whitelisted_no_finding(self):
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<iframe width="0" height="0" src="https://www.youtube.com/embed/dQw4w9WgXcQ">'
                '</iframe></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup") or []
        assert not any("youtube.com" in str(f) for f in findings), (
            "un iframe morto (fallback_content) verso un host della "
            "whitelist CDN (youtube.com), gia' escluso da "
            f"external_resources, e' stato segnalato come sospetto: {findings}"
        )

    # ── CLS-01z round-3, voce-frammento della whitelist CDN ──
    # `_CDN_WHITELIST` (shared/utils.py) contiene due voci FRAMMENTO, non
    # domini pieni: `'fonts.'` e `'fontawesome'`. `_dead_markup_external_host`
    # le confronta con `host == cdn or host.endswith("." + cdn)` — un
    # confronto per host/suffisso ESATTO, mai vero per un frammento: un host
    # reale non e' mai uguale a `'fontawesome'` ne' finisce per
    # `.fontawesome` (finisce per `.fontawesome.com`, `.com` != `.fontawesome`).
    # Le due voci restano quindi SENZA EFFETTO in questo detector — un CDN
    # legittimo coperto solo dal frammento (es. `use.fontawesome.com`,
    # `fonts.shopifycdn.com`) resta flaggato come sospetto: e' lo stesso FP
    # CDN gia' chiuso per i domini pieni (`youtube.com` ecc. sopra), ma non
    # per i frammenti. Contratto per il fixer: il match deve riconoscere
    # anche i frammenti SENZA tornare a un `in` largo su tutta la stringa
    # (evaderebbe di nuovo un quasi-CDN come `fontawesome.evil.example`, che
    # contiene 'fontawesome' come sottostringa letterale ma non e' il CDN —
    # v. `test_suspicious_dead_markup_fallback_content_quasi_cdn_fragment_fontawesome_still_flagged`
    # sotto, che documenta il contro-esempio da non reintrodurre).
    def test_suspicious_dead_markup_fallback_content_cdn_fragment_fontawesome_whitelisted_no_finding(self):
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="https://use.fontawesome.com/releases/v5/css/all.css" '
                'width="1" height="1"></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup") or []
        assert not any("fontawesome.com" in str(f) for f in findings), (
            "un img morto (fallback_content) verso un CDN legittimo coperto "
            "dalla voce-frammento 'fontawesome' della whitelist "
            "(use.fontawesome.com) e' stato segnalato come sospetto: "
            f"{findings}"
        )

    def test_suspicious_dead_markup_fallback_content_cdn_fragment_fonts_whitelisted_no_finding(self):
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="https://fonts.shopifycdn.com/some/font.woff2" '
                'width="1" height="1"></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup") or []
        assert not any("shopifycdn.com" in str(f) for f in findings), (
            "un img morto (fallback_content) verso un CDN legittimo coperto "
            "dalla voce-frammento 'fonts.' della whitelist "
            "(fonts.shopifycdn.com) e' stato segnalato come sospetto: "
            f"{findings}"
        )

    def test_suspicious_dead_markup_fallback_content_quasi_cdn_fragment_fontawesome_still_flagged(self):
        """Contro-esempio: un host che CONTIENE 'fontawesome' come
        sottostringa letterale ma non e' il CDN (`fontawesome.evil.example`)
        deve restare FLAGGATO. Se il fixer risolve il rilievo sopra con un
        `in` largo sull'URL/host intero (lo stesso operatore gia' usato da
        `external_resources`), questo test evade in falso negativo — il
        contratto per i frammenti va risolto senza allargare il criterio
        a un match di sottostringa non ancorato."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="http://fontawesome.evil.example/px.gif" width="1" height="1">'
                '</iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "un host 'quasi-CDN' che contiene 'fontawesome' come "
            "sottostringa ma non e' il CDN (fontawesome.evil.example) "
            f"non e' stato segnalato: {result}"
        )
        assert any(f.get("type") == "img" for f in findings), findings

    def test_suspicious_dead_markup_quasi_cdn_substring_host_still_flagged(self):
        """Controllo substring (G6 round-1): un host che CONTIENE la
        stringa della whitelist come sottostringa ma non è il CDN
        (`notyoutube.com.evil.example` contiene `youtube.com`) deve restare
        FLAGGATO — il fix non deve permettere l'evasione tramite un host
        scelto apposta per far scattare il match. Documenta anche il
        comportamento preesistente: `external_resources` (sezione 8, riga
        ~969) usa lo stesso confronto largo `safe in url_lowercase`, non un
        confronto sull'host esatto o sul suffisso di dominio — se il fix
        riusa quella whitelist COSÌ COM'È (stessa funzione/stesso operatore
        `in`), eredita lo stesso comportamento qui; se il fix la
        restringe a un confronto sull'host, il comportamento resta lo
        stesso su questo caso (l'host intero non è mai uguale a
        'youtube.com' né suo sottodominio) — le due implementazioni
        divergono solo su input più subdoli di questo, fuori scope qui."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="http://notyoutube.com.evil.example/px.gif" width="600" height="400">'
                '</iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "un host 'quasi-CDN' che contiene 'youtube.com' come "
            "sottostringa ma non e' il CDN (notyoutube.com.evil.example) "
            f"non e' stato segnalato: {result}"
        )
        assert any(f.get("type") == "img" for f in findings), findings

    def test_suspicious_dead_markup_non_whitelisted_external_host_still_flagged(self):
        """Non-regressione esplicita per il gruppo CDN: un host esterno che
        non è in nessuna whitelist (`evil.example`) resta flaggato — il fix
        deve escludere SOLO gli host della whitelist, non allargare il
        criterio di esclusione. Ristretto al solo caso (a)
        `fallback_content` (round-3, decisione utente §6): i casi (b)
        `malformed_endtag_swallow` e (c) `bogus_comment` sono ora fuori
        scope del detector."""
        html_fallback = ('<iframe src="https://legit.example/" width="640" height="480">'
                          'fallback <iframe width="0" height="0" '
                          'src="http://evil.example/c2"></iframe></iframe>')
        result = detect_hidden_elements(html_fallback)
        assert result.get("suspicious_dead_markup"), (
            "[fallback_content] host esterno non in whitelist (evil.example) "
            f"non piu' segnalato: {result}"
        )

    # ── CLS-01z round-4 (Gate 3, round-4; decisione utente): whitelist
    # ancorata a HOST CDN PIENI, non più a frammenti. Il verifier e il
    # security-reviewer del round-3 hanno dimostrato un falso negativo
    # reale, non un caso limite sintetico: le due voci-frammento residue di
    # `_CDN_WHITELIST` ('fonts.' e 'fontawesome') restano SENZA ancoraggio
    # al dominio registrabile reale. `_cdn_whitelist_match` le confronta
    # rispettivamente con `host.startswith(cdn)` (frammento che termina con
    # '.') e col PENULTIMO label dell'host (frammento senza punto interno)
    # — nessuno dei due confronti verifica che il RESTO dell'host appartenga
    # a un dominio CDN reale, solo che un prefisso/una label coincida
    # testualmente. Un attaccante che registra un dominio la cui SLD è
    # letteralmente 'fontawesome' (`fontawesome.xyz`, `fontawesome.ru`, o un
    # suo sottodominio `cdn.fontawesome.xyz`) o il cui PRIMO LABEL è
    # 'fonts' (`fonts.evil.example`, `fonts.c2-panel.ru`) EVADE oggi il
    # detector: `suspicious_dead_markup` resta vuoto, risk 0. PoC
    # confermato dal verifier round-3 con `http://fontawesome.xyz/c2`.
    #
    # Contratto round-4 (decisione utente): whitelist di host CDN PIENI
    # (eTLD+1 esatti, es. `fonts.googleapis.com`, `fonts.gstatic.com`,
    # `use.fontawesome.com`, `kit.fontawesome.com`, `fonts.shopifycdn.com`),
    # matching per suffisso ESATTO (`host == w or host.endswith("." + w)`)
    # — nessun frammento, nessuno `startswith`/label-nudo. Con la whitelist
    # ancorata, nessuno di questi 5 host attaccante può matchare per
    # costruzione: non sono uguali né suffisso di alcun host CDN pieno.
    #
    # Questi 5 test devono restare ROSSI finché la whitelist non è
    # ancorata (bug attuale: questi host EVADONO il detector, finding
    # assente) e VERDI dopo il fix (host esterno non whitelistato, flaggato
    # come ogni altro).
    def test_suspicious_dead_markup_fragment_bypass_fontawesome_sld_non_com_tld_flagged(self):
        """`fontawesome.xyz`: SLD letteralmente 'fontawesome' ma TLD .xyz,
        non .com. Il confronto per PENULTIMO LABEL della voce-frammento
        'fontawesome' non richiede alcun TLD/dominio pieno specifico —
        matcha comunque, evadendo oggi il detector."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="http://fontawesome.xyz/c2" width="1" height="1"></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "un host attaccante con SLD 'fontawesome' su TLD non-.com "
            "(fontawesome.xyz) evade il detector via la voce-frammento non "
            f"ancorata della whitelist CDN: {result}"
        )

    def test_suspicious_dead_markup_fragment_bypass_fontawesome_sld_ru_tld_flagged(self):
        """`fontawesome.ru`: stesso bypass del caso .xyz, TLD diverso a
        conferma che il difetto non dipende dal TLD scelto dall'attaccante."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="http://fontawesome.ru/x" width="1" height="1"></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "un host attaccante con SLD 'fontawesome' su TLD .ru "
            "(fontawesome.ru) evade il detector via la voce-frammento non "
            f"ancorata della whitelist CDN: {result}"
        )

    def test_suspicious_dead_markup_fragment_bypass_fontawesome_arbitrary_subdomain_flagged(self):
        """`cdn.fontawesome.xyz`: un sottodominio arbitrario di un dominio
        attaccante la cui SLD è 'fontawesome' — il confronto per penultimo
        label matcha allo stesso modo di `use.fontawesome.com` legittimo,
        perché non distingue affatto il dominio registrabile."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<iframe width="1" height="1" src="http://cdn.fontawesome.xyz/x"></iframe>'
                '</iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "un sottodominio arbitrario di un dominio attaccante con SLD "
            "'fontawesome' (cdn.fontawesome.xyz) evade il detector via la "
            f"voce-frammento non ancorata della whitelist CDN: {result}"
        )

    def test_suspicious_dead_markup_fragment_bypass_fonts_prefix_evil_example_flagged(self):
        """`fonts.evil.example`: primo label 'fonts' su un dominio
        attaccante (`evil.example`). Il confronto `host.startswith('fonts.')`
        della voce-frammento 'fonts.' non richiede alcun dominio pieno dopo
        il prefisso — matcha comunque, evadendo oggi il detector."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="http://fonts.evil.example/beacon" width="1" height="1"></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "un host attaccante con prefisso 'fonts.' (fonts.evil.example) "
            "evade il detector via la voce-frammento non ancorata della "
            f"whitelist CDN: {result}"
        )

    def test_suspicious_dead_markup_fragment_bypass_fonts_prefix_c2_panel_flagged(self):
        """`fonts.c2-panel.ru`: stesso bypass del prefisso 'fonts.', dominio
        attaccante diverso a conferma che il difetto non dipende dal
        dominio registrato scelto."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="http://fonts.c2-panel.ru/x" width="1" height="1"></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "un host attaccante con prefisso 'fonts.' (fonts.c2-panel.ru) "
            "evade il detector via la voce-frammento non ancorata della "
            f"whitelist CDN: {result}"
        )

    # ── CLS-01z round-4, host CDN pieni legittimi (devono RESTARE verdi) ──
    # `use.fontawesome.com` e `fonts.shopifycdn.com` sono già coperti dai
    # test round-3 sopra
    # (`test_suspicious_dead_markup_fallback_content_cdn_fragment_fontawesome_whitelisted_no_finding`,
    # `test_suspicious_dead_markup_fallback_content_cdn_fragment_fonts_whitelisted_no_finding`)
    # — non duplicati qui. `fonts.googleapis.com` è nuovo: è coperto oggi
    # solo di riflesso dalla voce a dominio pieno `googleapis.com` già
    # presente in `_CDN_WHITELIST` (suffisso `.googleapis.com`), non dalla
    # voce-frammento — la whitelist ancorata del round-4 deve mantenerlo
    # whitelistato esplicitamente come host CDN pieno.
    def test_suspicious_dead_markup_cdn_full_host_fonts_googleapis_com_whitelisted_no_finding(self):
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="https://fonts.googleapis.com/css2?family=Roboto" '
                'width="1" height="1"></iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup") or []
        assert not any("googleapis.com" in str(f) for f in findings), (
            "un img morto (fallback_content) verso l'host CDN pieno "
            "fonts.googleapis.com e' stato segnalato come sospetto: "
            f"{findings}"
        )

    # ── CLS-01z round-4, non-regressione host-pieni già sicuri ──
    # `youtube.com`/`schema.org` sono host CDN pieni già in whitelist prima
    # del round-4 (comportamento invariato, matching per suffisso non
    # toccato dall'ancoraggio): restano whitelistati. `youtube.com.evil.
    # example` non è né uguale né suffisso di `youtube.com` (finisce per
    # `.evil.example`): resta flaggato, come già verificato dal test round-1
    # `test_suspicious_dead_markup_quasi_cdn_substring_host_still_flagged`
    # con `notyoutube.com.evil.example` — qui il contro-esempio è il PREFISSO
    # esatto seguito da un dominio attaccante, non una sottostringa diversa.
    def test_suspicious_dead_markup_cdn_full_host_schema_org_whitelisted_no_finding(self):
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<iframe width="1" height="1" src="https://schema.org/Product"></iframe>'
                '</iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup") or []
        assert not any("schema.org" in str(f) for f in findings), (
            "un iframe morto (fallback_content) verso l'host CDN pieno "
            f"schema.org e' stato segnalato come sospetto: {findings}"
        )

    def test_suspicious_dead_markup_quasi_cdn_full_prefix_youtube_com_evil_example_still_flagged(self):
        """`youtube.com.evil.example`: il dominio CDN pieno 'youtube.com'
        appare come PREFISSO esatto dell'host, seguito da un dominio
        attaccante — non e' ne' uguale ne' suffisso di 'youtube.com'.
        Deve restare flaggato, whitelist ancorata o meno."""
        html = ('<iframe src="https://legit.example/" width="640" height="480">fallback '
                '<img src="http://youtube.com.evil.example/px.gif" width="1" height="1">'
                '</iframe>')
        result = detect_hidden_elements(html)
        findings = result.get("suspicious_dead_markup")
        assert findings, (
            "un host 'quasi-CDN' col dominio pieno 'youtube.com' come "
            "prefisso ma non e' il CDN (youtube.com.evil.example) non e' "
            f"stato segnalato: {result}"
        )


# ═══════════════════════════════════════════════════════════════
# CLS-01z round-5 — estrazione dell'host di `suspicious_dead_markup`
# ═══════════════════════════════════════════════════════════════
#
# Verifier round-4 (G6 INSUFFICIENTE, rilievi 1-3 e 6) + decisione utente
# del 2026-10-21 («A, sì a //host esterno»). Criteri R5-1…R5-4 di
# BUG-REGISTER.md, «ASSEGNA · CLS-01z round-5 · G1». Setup comune: il
# markup morto sta nel fallback content di un
# `<iframe src="x" width="640" height="480">…</iframe>` regolarmente chiuso,
# chiamata end-to-end a `detect_hidden_elements(html, self_domain=...)`.
_CLS01Z_R5_SELF = "legit.example"

# R5-1 — URL che un browser risolve verso `evil.example` (oracolo del
# verifier: `new URL()` WHATWG) e che il detector DEVE flaggare. Caratteri
# di controllo e backslash sono REALI (tab, LF, `\`), non sequenze di escape
# dell'HTML: sono proprio la forma che l'estrazione dell'host deve normalizzare.
_CLS01Z_R5_FLAGGED_URLS = [
    pytest.param("http://evil.example/c2", id="http_semplice_controllo"),
    pytest.param("https://evil.example/c2", id="https_semplice"),
    pytest.param("HTTPS://EVIL.EXAMPLE/c2", id="https_maiuscolo"),
    pytest.param("http://evil.example#.googleapis.com/c2",
                 id="cancelletto_aggira_whitelist_cdn"),
    pytest.param("http://evil.example?.googleapis.com/c2",
                 id="punto_interrogativo_aggira_whitelist_cdn"),
    pytest.param("http://evil.example\\.googleapis.com/c2",
                 id="backslash_aggira_whitelist_cdn"),
    pytest.param("http://googleapis.com:x@evil.example/c2",
                 id="userinfo_con_due_punti_finge_host_cdn"),
    pytest.param("http://evil.example#.legit.example/c2",
                 id="cancelletto_finge_dominio_cliente"),
    pytest.param("http://evil.example?.legit.example/c2",
                 id="punto_interrogativo_finge_dominio_cliente"),
    pytest.param("http://legit.example:x@evil.example/c2",
                 id="userinfo_finge_dominio_cliente"),
    pytest.param("//evil.example/c2", id="protocol_relative"),
    pytest.param("///evil.example/c2", id="tre_slash_iniziali"),
    pytest.param("\\\\evil.example\\c2", id="doppio_backslash_iniziale"),
    pytest.param("http:///evil.example/c2", id="schema_con_tre_slash"),
    pytest.param("http:/evil.example/c2", id="schema_con_slash_singolo"),
    pytest.param("http:evil.example/c2", id="schema_senza_slash"),
    pytest.param("http:\\\\evil.example\\c2", id="schema_con_backslash"),
    pytest.param(" http://evil.example/c2", id="spazio_iniziale"),
    pytest.param("\thttp://evil.example/c2", id="tab_iniziale"),
    pytest.param("\nhttp://evil.example/c2", id="newline_iniziale"),
    pytest.param("ht\ttp://evil.example/c2", id="tab_dentro_lo_schema"),
    pytest.param("http://evil.ex\nample/c2", id="newline_dentro_l_host"),
]

# R5-2 — URL che NON devono produrre alcun finding: CDN legittimi, host del
# cliente (o suoi sottodomini), URL senza host assoluto, schemi fuori contratto.
_CLS01Z_R5_NOT_FLAGGED_URLS = [
    pytest.param("https://fonts.googleapis.com/css", id="cdn_fonts_googleapis"),
    pytest.param("https://fonts.gstatic.com/x", id="cdn_fonts_gstatic"),
    pytest.param("https://use.fontawesome.com/x.js", id="cdn_use_fontawesome"),
    pytest.param("https://kit.fontawesome.com/abc.js", id="cdn_kit_fontawesome"),
    pytest.param("https://fonts.shopifycdn.com/x", id="cdn_fonts_shopifycdn"),
    pytest.param("HTTPS://FONTS.GOOGLEAPIS.COM/x", id="cdn_maiuscolo"),
    pytest.param("https://legit.example/x", id="dominio_cliente"),
    pytest.param("https://www.legit.example/x", id="dominio_cliente_www"),
    pytest.param("https://sub.legit.example/x", id="sottodominio_cliente"),
    pytest.param("https://legit.example:8443/x", id="dominio_cliente_con_porta"),
    pytest.param("//legit.example/x", id="protocol_relative_dominio_cliente"),
    pytest.param("//sub.legit.example/x", id="protocol_relative_sottodominio_cliente"),
    pytest.param("https://legit.example./x", id="dominio_cliente_trailing_dot"),
    pytest.param("https://googleapis.com./x", id="cdn_trailing_dot"),
    pytest.param("https://evil.example@legit.example/x",
                 id="userinfo_ingannevole_host_e_il_cliente"),
    pytest.param("/img.png", id="relativo_assoluto_sul_sito"),
    pytest.param("img.png", id="relativo_semplice"),
    pytest.param("?q=1", id="relativo_solo_query"),
    pytest.param("#frag", id="relativo_solo_frammento"),
    pytest.param("", id="stringa_vuota"),
    pytest.param("javascript:alert(1)", id="schema_javascript"),
    pytest.param("data:image/png;base64,AAAA", id="schema_data"),
    pytest.param("mailto:x@evil.example", id="schema_mailto"),
]

# R5-3 — host che CONTIENE il testo di una voce/del dominio cliente ma non ne
# è un sottodominio: l'ancoraggio al punto deve restare.
_CLS01Z_R5_DOT_ANCHOR_URLS = [
    pytest.param("https://evilgoogleapis.com/x", id="suffisso_cdn_senza_punto"),
    pytest.param("https://evil-legit.example/x", id="suffisso_cliente_con_trattino"),
    pytest.param("https://xlegit.example/x", id="suffisso_cliente_senza_punto"),
]


def _cls01z_r5_dead_tag(tag, url):
    """Un singolo tag `tag` il cui URL è `url`, nella forma che il detector
    legge: `src` per img/iframe, `action` per form. Il valore sta tra doppi
    apici: nessuno degli URL sotto test contiene `"` né `&`."""
    if tag == "img":
        return f'<img src="{url}">'
    if tag == "form":
        return f'<form action="{url}"></form>'
    if tag == "iframe":
        # Annidato dentro il fallback: il primo `</iframe>` chiude il
        # contenitore, l'ultimo del wrapper è un end-tag orfano.
        return f'<iframe src="{url}"></iframe>'
    raise ValueError(tag)


def _cls01z_r5_html(inner):
    return f'<iframe src="x" width="640" height="480">{inner}</iframe>'


class TestCLS01zRound5UrlHostExtraction:
    """CLS-01z round-5 (verifier round-4, G6 INSUFFICIENTE, rilievi 1, 2, 3, 6;
    decisione utente 2026-10-21: «A, sì a //host esterno»).

    `_dead_markup_external_host` estraeva l'host con `https?://([^/]+)`: un
    URL che il browser risolve verso un host attaccante, ma con `#`, `?`, `\\`,
    `user:pw@`, `//host`, `http:/host` o whitespace/controlli, evadeva sia la
    whitelist CDN sia l'esclusione del dominio cliente (costo del bypass: un
    carattere). Qui si fissa il COMPORTAMENTO: quale host il browser contatta,
    non come il codice lo estrae."""

    # ── R5-1: devono essere flaggati ──

    @pytest.mark.parametrize("url", _CLS01Z_R5_FLAGGED_URLS)
    def test_dead_img_resolving_to_external_host_is_flagged_and_scores_30(self, url):
        result = detect_hidden_elements(
            _cls01z_r5_html(_cls01z_r5_dead_tag("img", url)),
            self_domain=_CLS01Z_R5_SELF)
        dead = result.get("suspicious_dead_markup")
        assert dead, (
            f"un <img src={url!r}> morto nel fallback di un iframe chiuso "
            "risolve verso un host esterno (evil.example) per il browser, ma "
            f"non è stato segnalato: {result}"
        )
        assert result["risk_indicators"] >= 30, (
            f"<img src={url!r}> morto verso host esterno: il peso della "
            f"categoria (30) non è entrato nel risk: {result['risk_indicators']}"
        )

    @pytest.mark.parametrize("tag", ["form", "iframe"])
    @pytest.mark.parametrize("url", [
        pytest.param("//evil.example/c2", id="protocol_relative"),
        pytest.param("http://evil.example#.googleapis.com/c2",
                     id="cancelletto_aggira_whitelist_cdn"),
    ])
    def test_dead_form_and_iframe_resolving_to_external_host_are_flagged(self, tag, url):
        """Stessa estrazione dell'host per `<form action>` e `<iframe src>`:
        il difetto non è specifico di `<img>`."""
        result = detect_hidden_elements(
            _cls01z_r5_html(_cls01z_r5_dead_tag(tag, url)),
            self_domain=_CLS01Z_R5_SELF)
        dead = result.get("suspicious_dead_markup")
        assert dead, (
            f"un <{tag}> morto con URL {url!r} nel fallback di un iframe "
            f"chiuso risolve verso evil.example ma non è stato segnalato: {result}"
        )
        assert {d["type"] for d in dead} == {tag}, dead
        assert result["risk_indicators"] >= 30, result["risk_indicators"]

    # ── R5-2: NON devono essere flaggati ──

    @pytest.mark.parametrize("url", _CLS01Z_R5_NOT_FLAGGED_URLS)
    def test_dead_img_to_cdn_own_domain_or_non_host_url_is_not_flagged(self, url):
        """Il fix deve restringere cosa è «esterno» solo dove il browser
        contatta davvero un host terzo: CDN in whitelist, dominio del cliente
        (anche con porta, `www.`, trailing dot, userinfo ingannevole), URL
        senza host assoluto e schemi fuori contratto restano fuori. Il confronto
        del risk è differenziale (stesso HTML senza il tag morto) perché non
        dipende dal peso assoluto delle altre categorie."""
        result = detect_hidden_elements(
            _cls01z_r5_html(_cls01z_r5_dead_tag("img", url)),
            self_domain=_CLS01Z_R5_SELF)
        control = detect_hidden_elements(
            _cls01z_r5_html("fallback"), self_domain=_CLS01Z_R5_SELF)
        assert not result.get("suspicious_dead_markup"), (
            f"<img src={url!r}> morto non contatta alcun host terzo (CDN in "
            "whitelist, dominio del cliente o URL senza host assoluto) ma è "
            f"stato segnalato: {result.get('suspicious_dead_markup')}"
        )
        assert result["risk_indicators"] == control["risk_indicators"], (
            f"<img src={url!r}> morto non segnalato ma il risk è cambiato "
            f"({control['risk_indicators']} -> {result['risk_indicators']})"
        )

    # ── R5-3: ancoraggio al punto ──

    @pytest.mark.parametrize("url", _CLS01Z_R5_DOT_ANCHOR_URLS)
    def test_dead_img_host_merely_ending_with_cdn_or_own_domain_text_is_flagged(self, url):
        """Guardia contro i mutanti del verifier M5/M7 (confronto per suffisso
        senza il punto, per la whitelist CDN e per il dominio del cliente):
        `evilgoogleapis.com` non è un sottodominio di `googleapis.com`,
        `xlegit.example` non lo è di `legit.example`. Può essere già verde
        sul codice attuale: serve a restare verde dopo la riscrittura."""
        result = detect_hidden_elements(
            _cls01z_r5_html(_cls01z_r5_dead_tag("img", url)),
            self_domain=_CLS01Z_R5_SELF)
        assert result.get("suspicious_dead_markup"), (
            f"<img src={url!r}>: host che termina con lo stesso testo di una "
            "voce CDN / del dominio cliente ma non ne è un sottodominio, "
            f"non è stato segnalato: {result}"
        )

    # ── R5-4: lavoro limitato ──

    def test_dead_markup_evaluates_at_most_20_hosts_and_keeps_first_20_in_order(self, monkeypatch):
        """Rilievo 6 del verifier: il cap `[:20]` limitava l'output ma non il
        lavoro, il ciclo valutava l'host di TUTTI i tag opachi (+0,7-0,8 s su
        2 MB di markup morto denso). Un test sul tempo sarebbe flaky su CPU
        contesa (rilievo 9e), quindi si osserva il lavoro, non il tempo.

        CONTRATTO D'INTERFACCIA PER IL FIXER: questo test fissa
        `shared.utils._dead_markup_external_host` come PUNTO DI VALUTAZIONE
        dell'host (uno spy lo sostituisce con un contatore che delega
        all'originale), sul modello dello spy su `iter_content` di
        `TestFetchDecompressionBombGuardrail` (SEC-16). Se la funzione viene
        rinominata o la valutazione si sposta altrove, il test va aggiornato
        di proposito con una motivazione, non aggirato.

        1.000 `<img>` esterni morti nel fallback di un iframe chiuso: al più
        20 valutazioni, esattamente 20 finding, e sono i primi 20 in ordine
        di documento (`evil0`…`evil19`)."""
        import shared.utils as u
        original = u._dead_markup_external_host
        calls = []

        def _spy(*args, **kwargs):
            calls.append(args)
            return original(*args, **kwargs)

        monkeypatch.setattr(u, "_dead_markup_external_host", _spy)

        imgs = "".join(f'<img src="https://evil{i}.example/p">' for i in range(1000))
        result = detect_hidden_elements(
            _cls01z_r5_html(imgs), self_domain=_CLS01Z_R5_SELF)

        dead = result.get("suspicious_dead_markup") or []
        assert len(dead) == 20, f"attesi esattamente 20 finding, trovati {len(dead)}"
        assert [d["src"] for d in dead] == [
            f"https://evil{i}.example/p" for i in range(20)
        ], "i 20 finding non sono i primi 20 in ordine di documento"
        assert len(calls) <= 20, (
            f"{len(calls)} valutazioni dell'host per 20 finding su 1.000 tag "
            "morti: il ciclo deve fermarsi a 20 voci, non valutarli tutti"
        )


# ═══════════════════════════════════════════════════════════════
# CLS-01z round-5b — discriminanza dei test del round 5
# ═══════════════════════════════════════════════════════════════
#
# Verdetto verifier round-5 (G6 INSUFFICIENTE, BUG-REGISTER.md): il codice
# regge (0 falsi negativi su 2,6 milioni di URL contro `new URL()`, 0 richieste
# esterne in Chromium) ma 12 mutanti non equivalenti sopravvivono alla suite.
# Qui si fissano i comportamenti che quei mutanti cambiano. Gli esiti attesi
# sono quelli del browser (oracolo: `new URL(u, "https://legit.example/page")`
# di Node 22), non quelli dell'implementazione.

_CLS01Z_R5B_EXTERNAL_C2 = "https://evil.example/c2"

# Un tag morto per ciascuna ragione per cui NON è «esterno»: URL relativo,
# CDN in whitelist, dominio del cliente, schema fuori contratto, host vuoto,
# nessun URL. Serve a provare che nessuno di questi interrompe la scansione.
_CLS01Z_R5B_NON_EXTERNAL_TAGS = [
    pytest.param('<img src="/a.png">', id="relativo_assoluto_sul_sito"),
    pytest.param('<img src="a.png">', id="relativo_semplice"),
    pytest.param('<img src="https://fonts.googleapis.com/css">', id="cdn_in_whitelist"),
    pytest.param('<img src="https://legit.example/x">', id="dominio_cliente"),
    pytest.param('<img src="javascript:alert(1)">', id="schema_fuori_contratto"),
    pytest.param('<img src="http://?x">', id="host_vuoto"),
    pytest.param("<img>", id="img_senza_src"),
    pytest.param('<form action="/submit"></form>', id="form_relativo"),
    # Aperto e NON chiuso: un `</iframe>` annidato chiuderebbe il contenitore e
    # lascerebbe i tag successivi fuori dal fallback content.
    pytest.param("<iframe>", id="iframe_senza_src"),
]

# Tag morti il cui URL manca del tutto: `attrs.get(...)` restituisce `None`
# (attributo assente) oppure `None` per attributo booleano (`<img src>`).
_CLS01Z_R5B_URLLESS_TAGS = [
    pytest.param("<img>", id="img"),
    pytest.param("<img src>", id="img_src_booleano"),
    pytest.param("<form></form>", id="form"),
    pytest.param("<form action></form>", id="form_action_booleano"),
    pytest.param("<iframe></iframe>", id="iframe"),
    pytest.param("<iframe src></iframe>", id="iframe_src_booleano"),
    pytest.param("<iframe>", id="iframe_aperto"),
]


def _cls01z_r5b_scan(inner):
    """`detect_hidden_elements` su un documento il cui fallback content opaco
    è `inner` (stesso setup del round 5). Ritorna il risultato intero."""
    return detect_hidden_elements(
        _cls01z_r5_html(inner), self_domain=_CLS01Z_R5_SELF)


def _cls01z_r5b_img(url):
    return _cls01z_r5_dead_tag("img", url)


class TestCLS01zRound5bMutantKillers:
    """CLS-01z round-5b (G3 correttivo dopo il verdetto INSUFFICIENTE del
    verifier round-5): test che fissano i comportamenti corretti già presenti
    nel codice del round 5 ma non coperti da alcun test. Sono VERDI sul codice
    attuale per costruzione; il «rosso» sta nei mutanti, ciascuno nominato
    nella docstring del test che lo uccide.

    Gli URL sono scritti come arrivano al detector dopo `HTMLParser`: i
    caratteri di controllo sono REALI (`\\x01`, LF, CR), non sequenze di
    escape dell'HTML, perché `html.unescape` scarta le entità `&#1;` (non il
    carattere) e un test costruito con quelle non eserciterebbe il trim."""

    # ── Tetto di 20: conta i finding, non i tag valutati (C07, C05) ──

    def test_mixed_dead_document_flags_only_the_external_tag(self):
        """C07 (`continue`→`break` sul ramo «host assente»): un URL relativo,
        un CDN e il dominio del cliente PRIMA dell'esterno non devono farlo
        perdere. Esattamente 1 finding, quello esterno."""
        result = _cls01z_r5b_scan(
            _cls01z_r5b_img("/a.png")
            + _cls01z_r5b_img("https://fonts.googleapis.com/css")
            + _cls01z_r5b_img("https://legit.example/x")
            + _cls01z_r5b_img(_CLS01Z_R5B_EXTERNAL_C2))
        dead = result.get("suspicious_dead_markup") or []
        assert [d["src"] for d in dead] == [_CLS01Z_R5B_EXTERNAL_C2], (
            "documento [relativo, CDN, cliente, esterno]: attesi esattamente "
            f"1 finding (l'esterno), trovati {dead}"
        )

    @pytest.mark.parametrize("non_external", _CLS01Z_R5B_NON_EXTERNAL_TAGS)
    def test_non_external_dead_tag_does_not_stop_the_scan_for_external_ones(self, non_external):
        """C07, una ragione di «non esterno» per volta: il tag non esterno sta
        PRIMA e FRA due esterni, entrambi vanno segnalati, in ordine."""
        second = "https://evil2.example/c2"
        result = _cls01z_r5b_scan(
            non_external + _cls01z_r5b_img(_CLS01Z_R5B_EXTERNAL_C2)
            + non_external + _cls01z_r5b_img(second))
        dead = result.get("suspicious_dead_markup") or []
        assert [d["src"] for d in dead] == [_CLS01Z_R5B_EXTERNAL_C2, second], (
            f"un tag morto non esterno ({non_external}) ha interrotto la "
            f"scansione o ha fatto perdere un esterno: {dead}"
        )

    @pytest.mark.parametrize("count", [20, 25])
    @pytest.mark.parametrize("non_external", [
        pytest.param('<img src="https://fonts.googleapis.com/css">', id="cdn"),
        pytest.param('<img src="/a.png">', id="relativi"),
        pytest.param('<img src="https://legit.example/x">', id="dominio_cliente"),
    ])
    def test_external_tag_after_many_non_external_dead_tags_is_flagged(self, non_external, count):
        """C05 (il tetto conta i tag valutati): il tetto di 20 limita i
        FINDING, non i tag esaminati. 20 o 25 tag morti non esterni seguiti da
        un esterno: l'esterno è segnalato (25 e 20 sono entrambi > di quanto
        il mutante tollera prima di fermarsi)."""
        result = _cls01z_r5b_scan(
            non_external * count + _cls01z_r5b_img(_CLS01Z_R5B_EXTERNAL_C2))
        dead = result.get("suspicious_dead_markup") or []
        assert [d["src"] for d in dead] == [_CLS01Z_R5B_EXTERNAL_C2], (
            f"{count} tag morti non esterni hanno esaurito il tetto prima di "
            f"raggiungere l'esterno, che non è stato segnalato: {dead}"
        )
        assert result["risk_indicators"] >= 30, result["risk_indicators"]

    def test_cap_of_20_counts_findings_not_inspected_tags(self):
        """C05, lato tetto: 25 CDN poi 30 esterni → esattamente 20 finding,
        i primi 20 esterni in ordine di documento. Se il tetto contasse i tag
        valutati non ne uscirebbe nessuno."""
        cdn = _cls01z_r5b_img("https://fonts.googleapis.com/css") * 25
        external = "".join(
            _cls01z_r5b_img(f"https://evil{i}.example/p") for i in range(30))
        dead = _cls01z_r5b_scan(cdn + external).get("suspicious_dead_markup") or []
        assert [d["src"] for d in dead] == [
            f"https://evil{i}.example/p" for i in range(20)
        ], f"attesi i primi 20 esterni in ordine, trovati {len(dead)}: {dead}"

    # ── Input degradato: nessun URL (N28) ──

    @pytest.mark.parametrize("tag", _CLS01Z_R5B_URLLESS_TAGS)
    def test_dead_tag_without_url_does_not_crash_and_is_not_flagged(self, tag):
        """N28 (`(url or "")`→`url`): un `<img>`/`<form>`/`<iframe>` morto
        senza URL (attributo assente o booleano) non ha host da valutare:
        nessuna eccezione, nessun finding, nessun peso aggiunto al risk. È la
        classe di difetti più frequente del progetto (input degradato,
        `CODE-01`): un'eccezione qui spegnerebbe l'intero detector per la
        pagina."""
        result = _cls01z_r5b_scan(tag)
        control = _cls01z_r5b_scan("fallback")
        assert not result.get("suspicious_dead_markup"), (
            f"{tag} morto senza URL è stato segnalato: "
            f"{result.get('suspicious_dead_markup')}"
        )
        assert result["risk_indicators"] == control["risk_indicators"], (
            f"{tag} senza URL non segnalato ma il risk è cambiato "
            f"({control['risk_indicators']} -> {result['risk_indicators']})"
        )

    # ── IPv6 letterale (N30 e rilievo 2 del security-reviewer) ──

    @pytest.mark.parametrize("url", [
        pytest.param("http://[2001:db8::1]/x", id="ipv6_documentazione"),
        pytest.param("http://[::1]/x", id="ipv6_loopback_con_percorso"),
        pytest.param("http://[::1]/", id="ipv6_loopback"),
        pytest.param("http://[::1]:8080/x", id="ipv6_con_porta"),
        pytest.param("//[::1]/x", id="ipv6_protocol_relative"),
    ])
    def test_dead_img_to_ipv6_literal_host_is_flagged(self, url):
        """N30 (host IPv6 ridotto a stringa vuota → «nessun host»): un
        letterale IPv6 è un host assoluto per il browser (`new URL()` →
        `[::1]`, `[2001:db8::1]`) e non è né il cliente né un CDN: va
        segnalato. Copre anche `http://[::1]/` del rilievo 2 del
        security-reviewer."""
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert result.get("suspicious_dead_markup"), (
            f"<img src={url!r}> morto verso un host IPv6 letterale non è "
            f"stato segnalato: {result}"
        )
        assert result["risk_indicators"] >= 30, result["risk_indicators"]

    @pytest.mark.parametrize("url", [
        pytest.param("http://[::1]@googleapis.com/", id="userinfo_ipv6_poi_cdn"),
        pytest.param("http://[::1]:80@googleapis.com/", id="userinfo_ipv6_con_porta_poi_cdn"),
        pytest.param("http://[::1]@legit.example/x", id="userinfo_ipv6_poi_cliente"),
    ])
    def test_ipv6_in_userinfo_does_not_make_a_cdn_or_own_host_external(self, url):
        """Rilievo 2 del security-reviewer, lato opposto: `[::1]` PRIMA della
        `@` è userinfo, non l'host. Per il browser l'host è `googleapis.com`
        (CDN) o `legit.example` (cliente): nessun host terzo, nessun finding."""
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert not result.get("suspicious_dead_markup"), (
            f"<img src={url!r}>: l'IPv6 prima della '@' è userinfo, l'host è "
            f"un CDN/il cliente, ma è stato segnalato: "
            f"{result.get('suspicious_dead_markup')}"
        )

    # ── Normalizzazione del WHATWG URL parser (N08, N09, N02, N03, N04) ──

    @pytest.mark.parametrize("url", [
        pytest.param("ht\ntp://evil.example/c2", id="lf_dentro_lo_schema"),
        pytest.param("ht\rtp://evil.example/c2", id="cr_dentro_lo_schema"),
        pytest.param("ht&#10;tp://evil.example/c2", id="lf_come_entita_dentro_lo_schema"),
        pytest.param("ht&#13;tp://evil.example/c2", id="cr_come_entita_dentro_lo_schema"),
        pytest.param("h\nt\rt\np://evil.example/c2", id="lf_e_cr_alternati_nello_schema"),
    ])
    def test_dead_img_with_lf_or_cr_inside_scheme_is_flagged(self, url):
        """N08 (niente rimozione di LF), N09 (niente rimozione di CR): per lo
        URL parser WHATWG tab, LF e CR sono tolti OVUNQUE, anche dentro lo
        schema. `ht\\ntp://evil.example/c2` è `http://evil.example/c2`. A
        differenza di `newline_dentro_l_host` del round 5 (esterno comunque),
        qui senza la rimozione l'URL non avrebbe schema e passerebbe per
        relativo: il carattere elude il detector."""
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert result.get("suspicious_dead_markup"), (
            f"<img src={url!r}> morto: il browser rimuove LF/CR e contatta "
            f"evil.example, ma non è stato segnalato: {result}"
        )

    @pytest.mark.parametrize("url", [
        pytest.param("https://legit.exam\nple/x", id="lf_dentro_il_dominio_cliente"),
        pytest.param("https://legit.exam\rple/x", id="cr_dentro_il_dominio_cliente"),
        pytest.param("https://fonts.googleapis.\ncom/x", id="lf_dentro_un_cdn"),
    ])
    def test_dead_img_to_own_domain_or_cdn_split_by_lf_or_cr_is_not_flagged(self, url):
        """N08/N09, lato opposto: LF/CR dentro l'host sono rimossi dal
        browser, quindi l'host è il dominio del cliente o il CDN. Senza la
        rimozione l'host letto sarebbe `legit.exam\\nple` e diventerebbe un
        falso positivo."""
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert not result.get("suspicious_dead_markup"), (
            f"<img src={url!r}>: per il browser l'host è il cliente/un CDN "
            f"(LF/CR rimossi), ma è stato segnalato: "
            f"{result.get('suspicious_dead_markup')}"
        )

    @pytest.mark.parametrize("prefix", [
        pytest.param("\x01", id="c0_x01"),
        pytest.param("\x08", id="c0_x08_backspace"),
        pytest.param("\x0c", id="c0_x0c_form_feed"),
        pytest.param("\x1b", id="c0_x1b_escape"),
        pytest.param("\x1f", id="c0_x1f"),
        pytest.param("\x01\x02\x03", id="piu_c0_consecutivi"),
        pytest.param("\x01 \x1f ", id="c0_e_spazi_alternati"),
    ])
    def test_dead_img_with_leading_c0_control_chars_is_flagged(self, prefix):
        """N02 (`strip()` di default), N03 (`strip(" ")`): lo URL parser
        toglie agli estremi OGNI C0 control (U+0000-U+001F) e lo spazio, non
        solo i whitespace di `str.strip()`. `\\x01http://evil.example/c2` è
        `http://evil.example/c2` per il browser; con un trim debole non ha più
        schema e il carattere fa passare l'URL per relativo.

        U+0000 resta fuori da questo elenco di proposito: il tokenizer HTML
        sostituisce un NUL letterale in un attributo con U+FFFD (che non è un
        C0 e non viene tolto), quindi per il browser `\\x00http://…` è
        relativo e segnalarlo sarebbe un falso positivo fail-safe, non il
        comportamento del browser."""
        url = prefix + "http://evil.example/c2"
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert result.get("suspicious_dead_markup"), (
            f"<img src={url!r}> morto: il browser toglie i C0 iniziali e "
            f"contatta evil.example, ma non è stato segnalato: {result}"
        )

    @pytest.mark.parametrize("url", [
        pytest.param("https://legit.example\x01", id="cliente_con_c0_finale"),
        pytest.param("https://legit.example\x1f", id="cliente_con_x1f_finale"),
        pytest.param("https://legit.example ", id="cliente_con_spazio_finale"),
        pytest.param("https://googleapis.com\x01", id="cdn_con_c0_finale"),
        pytest.param("https://fonts.googleapis.com\x1b", id="cdn_con_escape_finale"),
        pytest.param("https://legit.example\x01\x02 ", id="cliente_con_c0_e_spazio_finali"),
        pytest.param("\x01https://legit.example/x", id="cliente_con_c0_iniziale"),
        pytest.param("\x1bhttps://fonts.googleapis.com/css", id="cdn_con_c0_iniziale"),
    ])
    def test_dead_img_to_own_domain_or_cdn_wrapped_in_c0_chars_is_not_flagged(self, url):
        """N04 (solo `lstrip`), N03, N02: il trim vale ANCHE in coda. Un C0 o
        uno spazio dopo l'host non lo cambia per il browser (`new URL(
        'https://legit.example\\x01')` → `legit.example`); senza il trim finale
        l'host letto sarebbe `legit.example\\x01`, quindi «esterno». In coda
        l'unico esito che cambia è il falso positivo, perciò questo caso
        (non flaggato) è l'unico a discriminare N04."""
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert not result.get("suspicious_dead_markup"), (
            f"<img src={url!r}>: C0/spazio agli estremi tolti dal browser, "
            f"l'host è il cliente/un CDN, ma è stato segnalato: "
            f"{result.get('suspicious_dead_markup')}"
        )

    # ── Host vuoto, URL relativi, userinfo (N24, N27, N12) ──

    @pytest.mark.parametrize("url", [
        pytest.param("http://?x", id="schema_poi_query"),
        pytest.param("http:///?x", id="schema_tre_slash_poi_query"),
        pytest.param("//#x", id="protocol_relative_poi_frammento"),
        pytest.param("//?x", id="protocol_relative_poi_query"),
        pytest.param("http://", id="schema_e_basta"),
        pytest.param("https://:80/", id="solo_porta"),
        pytest.param("http://@/x", id="solo_userinfo"),
    ])
    def test_dead_img_with_empty_host_is_not_flagged(self, url):
        """N24 (`host or None`→`host`): per il browser questi URL sono
        invalidi (`new URL()` solleva), nessuna richiesta parte. L'host
        estratto è la stringa vuota, che deve contare come «nessun host»,
        non come un host esterno."""
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert not result.get("suspicious_dead_markup"), (
            f"<img src={url!r}> non ha un host (URL invalido per il "
            f"browser) ma è stato segnalato: {result.get('suspicious_dead_markup')}"
        )
        assert result["risk_indicators"] == _cls01z_r5b_scan("fallback")["risk_indicators"]

    @pytest.mark.parametrize("url", [
        pytest.param("/redirect?u=http://evil.example/c2", id="query_con_url_assoluto"),
        pytest.param("a/http://evil.example", id="percorso_relativo_con_url_assoluto"),
        pytest.param("x/https://evil.example/", id="percorso_con_https_dentro"),
        pytest.param("redirect?u=//evil.example/c2", id="query_con_protocol_relative"),
        pytest.param("/a//evil.example/c2", id="doppio_slash_dentro_il_percorso"),
    ])
    def test_dead_img_with_absolute_url_inside_relative_path_is_not_flagged(self, url):
        """N27 (`re.match`→`re.search` sull'inizio dell'authority): l'URL è
        relativo, il browser lo risolve sull'host della pagina
        (`new URL()` → `legit.example`); `http://evil.example` compare solo
        come TESTO nel percorso o nella query. Cercare lo schema in qualunque
        punto della stringa segnalerebbe ogni link di redirect del sito."""
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert not result.get("suspicious_dead_markup"), (
            f"<img src={url!r}> è relativo (nessun host terzo contattato) ma "
            f"è stato segnalato: {result.get('suspicious_dead_markup')}"
        )

    @pytest.mark.parametrize("url", [
        pytest.param("http://evil.example@a@legit.example/x", id="due_chiocciole_poi_cliente"),
        pytest.param("http://evil.example@a@googleapis.com/x", id="due_chiocciole_poi_cdn"),
        pytest.param("http://a@b@legit.example/x", id="userinfo_neutro_poi_cliente"),
    ])
    def test_dead_img_host_is_after_the_last_at_sign_own_or_cdn_not_flagged(self, url):
        """N12 (partizione alla PRIMA `@`): per lo URL parser WHATWG l'host
        segue l'ULTIMA `@`, tutto ciò che precede (anche un'altra `@` e il
        testo di un host) è userinfo. `http://evil.example@a@legit.example/x`
        contatta `legit.example`: nessun host terzo. Alla prima `@` l'host
        letto sarebbe `a@legit.example`, quindi «esterno»."""
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert not result.get("suspicious_dead_markup"), (
            f"<img src={url!r}>: l'host dopo l'ultima '@' è il cliente/un "
            f"CDN, ma è stato segnalato: {result.get('suspicious_dead_markup')}"
        )

    @pytest.mark.parametrize("url", [
        pytest.param("http://a@b@evil.example/x", id="due_chiocciole_poi_esterno"),
        pytest.param("http://legit.example@a@evil.example/x",
                     id="cliente_nello_userinfo_poi_esterno"),
        pytest.param("http://googleapis.com@a@evil.example/x",
                     id="cdn_nello_userinfo_poi_esterno"),
    ])
    def test_dead_img_host_is_after_the_last_at_sign_external_is_flagged(self, url):
        """N12, lato opposto: con più `@` l'host è dopo l'ultima, quindi un
        userinfo che nomina il cliente o un CDN non salva un host esterno."""
        result = _cls01z_r5b_scan(_cls01z_r5b_img(url))
        assert result.get("suspicious_dead_markup"), (
            f"<img src={url!r}>: l'host dopo l'ultima '@' è evil.example "
            f"(`new URL()` lo conferma) ma non è stato segnalato: {result}"
        )


class TestTimeHelpers:
    def test_now_iso_format(self):
        ts = now_iso()
        assert "T" in ts
        assert "+" in ts or "Z" in ts

    def test_is_check_due_none(self):
        assert is_check_due(None, 24) is True

    def test_is_check_due_recent(self):
        assert is_check_due(now_iso(), 24) is False

    def test_is_check_due_old(self):
        assert is_check_due("2020-01-01T00:00:00+00:00", 24) is True

    def test_is_check_due_invalid(self):
        assert is_check_due("not-a-date", 24) is True


class TestHiddenElementsFalsePositives:
    """
    Regression: the classifier flagged legitimate sites (a real WordPress app
    with a login area, here appsuite.example) as CRITICAL "compromise/credential kit".
    Causes: (1) wp-emoji \\uXXXX sequences marked as obfuscated JS, (2) the site's
    own /wp-content/ resources counted as external, (3) any login text = alert.
    Fix must clear these FPs WITHOUT creating false negatives on real phishing.
    """
    from shared.utils import detect_hidden_elements as _d

    def test_wp_emoji_unicode_not_flagged_as_obfuscated(self):
        from shared.utils import detect_hidden_elements
        html = ('<script>const a=JSON.parse(document.getElementById("wp-emoji-settings").textContent);'
                'var e="\\u1f600\\u1f601\\u1f602\\u1f603\\u1f604\\u1f605\\u1f606\\u1f607\\u1f608\\u1f609'
                '\\u1f60a\\u1f60b\\u1f60c\\u1f60d\\u1f60e";</script>')
        r = detect_hidden_elements(html, self_domain="appsuite.example")
        # unicode escapes alone (no eval/atob/etc) must NOT count as obfuscation
        assert len(r.get("obfuscated_js", [])) == 0

    def test_self_hosted_resources_not_external(self):
        from shared.utils import detect_hidden_elements
        html = ('<link href="https://appsuite.example/wp-content/themes/x/style.css">'
                '<script src="https://appsuite.example/wp-includes/js/jquery.js"></script>'
                '<a href="https://download.appsuite.example/files/tool.exe">dl</a>')
        r = detect_hidden_elements(html, self_domain="appsuite.example")
        ext = r.get("external_resources", [])
        assert not any("appsuite.example" in u for u in ext)

    def test_real_obfuscation_still_detected(self):
        from shared.utils import detect_hidden_elements
        html = ('<script>eval(atob("dmFy"));document.write(unescape("%3C"));'
                'var x=String.fromCharCode(104,116);</script>')
        r = detect_hidden_elements(html, self_domain="evil.com")
        # genuine obfuscation (eval/atob/document_write/fromCharCode) MUST be flagged
        assert len(r.get("obfuscated_js", [])) >= 1

    def test_real_external_malicious_still_detected(self):
        from shared.utils import detect_hidden_elements
        html = ('<script src="https://evil-exfil.ru/c.js"></script>'
                '<form action="https://evil-exfil.ru/steal.php"></form>')
        r = detect_hidden_elements(html, self_domain="lookalike-fake.example")
        ext = r.get("external_resources", [])
        assert any("evil-exfil.ru" in u for u in ext)

    def test_self_domain_starting_with_w_is_not_truncated(self):
        """CODE-02. `lstrip("www.")` rimuove QUALUNQUE carattere iniziale
        dell'insieme {w, .}, non il prefisso "www.". Con un dominio che inizia
        per 'w' la base del confronto veniva troncata ("wind.it" -> "ind.it"),
        quindi i sottodomini del sito stesso risultavano risorse di terzi."""
        from shared.utils import detect_hidden_elements
        html = ('<link href="https://wind.it/assets/style.css">'
                '<script src="https://static.wind.it/app.js"></script>')
        r = detect_hidden_elements(html, self_domain="wind.it")
        ext = r.get("external_resources", [])
        assert not any("wind.it" in u for u in ext), \
            f"risorse self-hosted contate come esterne: {ext}"

    def test_third_party_colliding_with_truncated_self_stays_external(self):
        """CODE-02, direzione opposta: il troncamento faceva collidere un terzo
        estraneo con il dominio proprio troncato ("wallmart.com" -> "allmart.com"),
        escludendo in silenzio una risorsa realmente esterna."""
        from shared.utils import detect_hidden_elements
        html = '<script src="https://allmart.com/tracker.js"></script>'
        r = detect_hidden_elements(html, self_domain="wallmart.com")
        ext = r.get("external_resources", [])
        assert any("allmart.com" in u for u in ext), \
            f"risorsa di terzi esclusa per errore: {ext}"

    def test_self_hosted_resource_on_nonstandard_port_not_external(self):
        """CODE-02, rilievo R2 della revisione indipendente: l'host di una risorsa
        è estratto dall'URL nell'HTML e può contenere la porta, mentre il dominio
        del sito non l'ha mai. Senza normalizzarla, `static.wind.it:8443` non
        termina per `.wind.it` e una risorsa self-hosted risultava di terzi."""
        from shared.utils import detect_hidden_elements
        html = ('<script src="https://static.wind.it:8443/app.js"></script>'
                '<link href="https://wind.it:8443/style.css">')
        r = detect_hidden_elements(html, self_domain="wind.it")
        ext = r.get("external_resources", [])
        assert not any("wind.it" in u for u in ext), \
            f"risorsa self-hosted su porta non standard contata come esterna: {ext}"

    def test_strip_www_normalises_host(self):
        """CODE-02, rilievo R3: il registro dichiarava casi limite «verificati»
        senza un test che li coprisse. Questi sono quei casi."""
        from shared.utils import _strip_www
        assert _strip_www("www.wind.it") == "wind.it"
        assert _strip_www("WWW.Wind.IT") == "wind.it"
        assert _strip_www("wind.it") == "wind.it"
        assert _strip_www("wallmart.com") == "wallmart.com"   # nessun troncamento
        assert _strip_www("wwwx.com") == "wwwx.com"           # serve il punto
        assert _strip_www("www.wind.it:8443") == "wind.it"    # porta rimossa
        assert _strip_www(None) == ""
        assert _strip_www("") == ""

    def test_iframe_percent_width_not_flagged_invisible(self):
        """CLS-01b: la regex non ancorata `[01]\\s*(px)?["\\']?` combaciava con
        la prima cifra di un numero qualunque, quindi un embed SoundCloud
        width="100%" height="450" (dimensione reale, non nascosta) veniva
        classificato iframe invisibile per via dell'1 iniziale di "100%"."""
        from shared.utils import detect_hidden_elements
        html = ('<iframe width="100%" height="450" scrolling="no" frameborder="no" '
                'src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/1">'
                '</iframe>')
        r = detect_hidden_elements(html)
        # Le liste vuote vengono rimosse dal dizionario finale (shared/utils.py:533),
        # quindi "non rilevato" si esprime con un valore falsy, non con [].
        assert not r.get("invisible_iframes"), \
            f"iframe di dimensione reale classificato invisibile: {r.get('invisible_iframes')}"

    def test_img_logo_146x172_not_flagged_tracking_pixel(self):
        """CLS-01c: stesso difetto sulla regex del pixel di tracking. Un logo
        146x172 servito da /wp-content/uploads/ veniva classificato pixel di
        tracking per via dell'1 iniziale di "146" e "172"."""
        from shared.utils import detect_hidden_elements
        html = '<img src="/wp-content/uploads/logo.png" width="146" height="172" alt="Logo">'
        r = detect_hidden_elements(html)
        assert not r.get("tracking_pixels"), \
            f"logo classificato pixel di tracking: {r.get('tracking_pixels')}"

    def test_iframe_unquoted_percent_width_not_flagged_invisible(self):
        """CLS-01b, variante senza virgolette: `width=100%` (HTML5 valido,
        attributo non quotato) non deve essere trattato come dimensione 1."""
        from shared.utils import detect_hidden_elements
        html = '<iframe width=100% height=450 src="https://example.com/embed"></iframe>'
        r = detect_hidden_elements(html)
        assert not r.get("invisible_iframes")

    def test_gtm_noscript_iframe_zero_size_still_flagged_invisible(self):
        """CLS-01b, controllo di non regressione: l'iframe noscript di Google
        Tag Manager con dimensione realmente 0x0 deve restare invisibile."""
        from shared.utils import detect_hidden_elements
        html = ('<iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXX" '
                'height="0" width="0" style="display:none;visibility:hidden"></iframe>')
        r = detect_hidden_elements(html)
        assert r.get("invisible_iframes")

    def test_real_tracking_pixel_1x1_still_flagged(self):
        """CLS-01c, controllo di non regressione: un pixel di tracking reale
        1x1 (es. Twitter/X ads conversion) deve restare rilevato."""
        from shared.utils import detect_hidden_elements
        html = '<img src="https://t.co/i/adsct" width="1" height="1">'
        r = detect_hidden_elements(html)
        assert r.get("tracking_pixels")


class TestSSRFProtection:
    """The tool fetches user-supplied domains; it must not be usable to reach
    internal infrastructure (cloud metadata, localhost, private ranges)."""
    def test_internal_ips_blocked(self):
        from shared.utils import _is_blocked_ip
        for ip in ["169.254.169.254", "127.0.0.1", "10.0.0.1", "192.168.1.1",
                   "172.16.0.1", "0.0.0.0", "::1", "fe80::1"]:
            assert _is_blocked_ip(ip) is True, ip

    def test_public_ip_allowed(self):
        from shared.utils import _is_blocked_ip
        assert _is_blocked_ip("8.8.8.8") is False
        assert _is_blocked_ip("1.1.1.1") is False

    def test_is_safe_url_blocks_localhost_and_metadata(self):
        from shared.utils import is_safe_url
        for u in ["http://127.0.0.1/x", "http://169.254.169.254/latest/meta-data/",
                  "http://localhost:8010/trigger"]:
            safe, _ = is_safe_url(u)
            assert safe is False, u

    def test_fetch_refuses_internal(self):
        from shared.utils import http_get_with_retry
        r = http_get_with_retry("http://127.0.0.1:8010/trigger", max_attempts=1)
        assert r["status_code"] is None
        assert "SSRF" in (r["error"] or "")

    def test_collection_failed_ssrf_recognition_not_hardcoded_duplicate(self):
        """CODE-15 + CODE-14 (G3 terzo giro, requisito 3) — fragilità
        segnalata dal verifier: `collection_failed` (shared/utils.py,
        blocco "Stato dei moduli di raccolta") riconosce il segnale SSRF con
        uno string-match ESATTO su `"blocked (SSRF protection)"` /
        `"blocked redirect (SSRF protection)"`, duplicato LETTERALMENTE
        rispetto ai punti che producono quelle stesse stringhe
        (`http_get_with_retry`, shared/utils.py:112, 134, 157 — tre f-string
        indipendenti). Le fixture esistenti (es.
        `tests/test_orchestrator.py::TestOrchestratorBuildsCollectionState.
        HTTP_DNS_NOT_RESOLVING`, prima di questo giro) pinnavano quella
        stringa A MANO nelle fixture, senza mai chiamare `is_safe_url`/
        `http_get_with_retry` reali: un refactor futuro del messaggio in un
        SOLO punto (es. solo la riga 112, non le altre due, o non
        `collection_failed`) non avrebbe fatto fallire NESSUN test,
        riaprendo IN SILENZIO il falso positivo appena chiuso da
        questo stesso ID.

        Questo test chiama il PRODUTTORE reale (`http_get_with_retry`, che
        internamente usa `is_safe_url`) su un input che scatena DAVVERO la
        protezione — un host che risolve a un indirizzo interno. Nessuna
        chiamata di rete reale: "127.0.0.1" è un IP letterale,
        `socket.getaddrinfo` lo risolve localmente senza interrogare alcun
        resolver DNS (verificato offline con `docker run --network=none`,
        vedi consegna del test-author).

        VINCOLO PER IL FIXER, dichiarato qui e vincolante: introdurre una
        costante condivisa `shared.utils.SSRF_ERROR_PREFIX` (valore
        `"blocked (SSRF protection)"`, oggi scritto a mano alla riga 112) e
        farla usare SIA dal punto che produce il messaggio SIA da
        `collection_failed` che lo consuma — invece di due letterali
        indipendenti che oggi coincidono per coincidenza, non per
        costruzione. Senza una costante chiamata esattamente così, questo
        test fallisce: non è aggirabile lasciando i due lati sincronizzati
        "a mano" un'altra volta."""
        import shared.utils as u

        result = u.http_get_with_retry("http://127.0.0.1/", max_attempts=1)
        assert result["error"] is not None, (
            "il guard SSRF non si è attivato su un host interno: fixture del "
            "test inefficace, non prova nulla sul difetto"
        )

        assert hasattr(u, "SSRF_ERROR_PREFIX"), (
            "manca 'shared.utils.SSRF_ERROR_PREFIX': il prefisso del "
            "messaggio SSRF è duplicato a mano fra il produttore "
            "(http_get_with_retry, shared/utils.py:112) e il consumatore "
            "(collection_failed) invece di condividere un'unica fonte di "
            "verità — un refactor del messaggio in un solo punto non "
            "farebbe fallire questo test come dovrebbe"
        )
        assert result["error"].startswith(u.SSRF_ERROR_PREFIX), (
            f"http_get_with_retry non usa la costante condivisa per produrre "
            f"l'errore SSRF: {result['error']!r} non comincia per "
            f"{u.SSRF_ERROR_PREFIX!r}"
        )

        # Il consumatore deve riconoscere ESATTAMENTE l'output reale appena
        # prodotto dal produttore — non una sua imitazione scritta a mano nel
        # test — come "non un guasto del collector".
        http_dict = {"checks": [{"status_code": None, "error": result["error"]}],
                     "overall_status": "down", "error": None}
        assert u.collection_failed(http_dict) is False, (
            "collection_failed non ha riconosciuto come 'non fallito' il "
            "segnale SSRF prodotto realmente da http_get_with_retry: " +
            repr(result["error"])
        )


# ═══════════════════════════════════════════════════════════════
# SEC-16 — cap sulla dimensione del body HTTP scaricato
# ═══════════════════════════════════════════════════════════════
#
# CONTRATTO fissato da questo test-author per il fixer (G3, SEC-16):
#
#   Costante:  shared.utils.MAX_FETCH_BODY_BYTES
#   Env var:   MAX_FETCH_BODY_BYTES (stesso nome), default 2*1024*1024 (2 MiB)
#   Pattern:   coerente con shared/security.py:15 (MAX_BODY_SIZE) e
#              services/cert_intel.py:20 (MAX_CRTSH_BYTES = int(os.environ.get(
#              "MAX_CRTSH_BYTES", str(10*1024*1024)))) — costante di modulo,
#              letta a runtime (non bindata come default-arg), configurabile
#              via env var omonima.
#   Nota per il fixer: shared/utils.py importa `os` con l'alias `_os`
#              (riga 14): la nuova costante deve usare `_os.environ.get(...)`,
#              non un secondo `import os`.
#   Approccio: streaming (`requests.get(..., stream=True)` +
#              `resp.iter_content(chunk_size=...)`, stop non appena il
#              body accumulato raggiunge MAX_FETCH_BODY_BYTES — il byte
#              N+1 non deve mai essere letto dal socket). NON troncamento
#              post-download: il test
#              `test_stream_stops_reading_after_cap_not_post_download_truncation`
#              sotto è costruito apposta per fallire se il fix scarica tutto
#              e tronca in Python.
#
# I test usano un cap PICCOLO (impostato via monkeypatch, non l'env var reale)
# per non generare payload multi-MB nella suite. Nessuna rete reale: i server
# sono processi locali su 127.0.0.1, con SSRF_PROTECTION disattivata via
# monkeypatch per la durata del singolo test (127.0.0.1 è altrimenti bloccato
# dal guard SSRF testato sopra — comportamento voluto e NON toccato qui).


def _start_local_http_server(routes: dict) -> tuple[http.server.HTTPServer, int]:
    """Avvia un server HTTP su 127.0.0.1 (porta effimera) che risponde secondo
    `routes`: path -> {"status": int, "body": bytes, "headers": dict}.
    `routes` può essere mutato DOPO l'avvio (es. per inserire l'URL di
    redirect che contiene la porta, nota solo a server già avviato), purché
    la mutazione avvenga prima che il client emetta la richiesta."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            spec = routes.get(self.path.split("?", 1)[0])
            if spec is None:
                self.send_response(404)
                self.end_headers()
                return
            body = spec.get("body", b"")
            self.send_response(spec.get("status", 200))
            for k, v in spec.get("headers", {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # il client (SUT) può chiudere presto: atteso, non un errore del server

        def log_message(self, fmt, *args):
            pass  # silenzia l'access log del server di test

    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    # BUILD-06: `shutdown()` aspetta che il ciclo di `serve_forever` torni a
    # controllare la richiesta di arresto, cioè fino a un `poll_interval` (0,5 s
    # di default) per OGNI test che chiude il server. Un intervallo breve toglie
    # solo quell'attesa: il ciclo accetta le connessioni e le serve come prima.
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    t.start()
    return srv, port


class _PacedServerResult:
    def __init__(self):
        self.bytes_sent = 0
        self.connection_broke_early = False


def _run_paced_server(listen_sock: socket.socket, body: bytes,
                       chunk_size: int = 256, delay: float = 0.01,
                       sndbuf: int = 2048) -> _PacedServerResult:
    """Accetta UNA connessione su `listen_sock` e invia `body` a piccoli
    passi, con un SO_SNDBUF ridotto e una pausa fra un invio e l'altro, per
    dare al client la possibilità reale di abbandonare la connessione a metà
    (chiusura del socket) invece di ricevere l'intero body. Ritorna quanti
    byte sono STATI EFFETTIVAMENTE inviati con successo prima che il client
    chiudesse (o l'intero body, se il client non lo ha mai fatto)."""
    result = _PacedServerResult()
    listen_sock.settimeout(5)
    conn, _addr = listen_sock.accept()
    conn.settimeout(5)
    try:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        header = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        conn.sendall(header)
        for i in range(0, len(body), chunk_size):
            piece = body[i:i + chunk_size]
            conn.sendall(piece)
            result.bytes_sent += len(piece)
            time.sleep(delay)
    except (BrokenPipeError, ConnectionResetError, OSError):
        result.connection_broke_early = True
    finally:
        try:
            conn.close()
        except OSError:
            pass
    return result


class TestFetchBodySizeCap:
    """SEC-16 — `http_get_with_retry` (shared/utils.py:113) scarica il body
    HTTP intero senza alcun limite di dimensione, in zona NON autenticata
    (services/http_fingerprint.py:63) con body controllato dall'attaccante
    (dominio lookalike). DoS confermato dal researcher: 16,44s wall-clock per
    una singola /http (4 fetch paralleli di 5MB). Contratto fissato sopra:
    `shared.utils.MAX_FETCH_BODY_BYTES`, default 2 MiB, streaming con stop a
    N byte (non troncamento post-download)."""

    @pytest.fixture
    def server(self):
        """Factory: server(routes) -> port. Chiude il server a fine test."""
        started = []

        def _start(routes):
            srv, port = _start_local_http_server(routes)
            started.append(srv)
            return port

        yield _start
        for srv in started:
            srv.shutdown()
            srv.server_close()

    @pytest.fixture(autouse=True)
    def _disable_ssrf_for_localhost(self, monkeypatch):
        """I server di prova girano su 127.0.0.1: senza questo, il guard SSRF
        (TestSSRFProtection, comportamento voluto) bloccherebbe la richiesta
        prima ancora di arrivare al codice sotto test. Non riguarda il difetto
        SEC-16 — è solo l'infrastruttura del test."""
        import shared.utils as u
        monkeypatch.setattr(u, "SSRF_PROTECTION", False, raising=False)

    def test_body_under_cap_is_returned_intact(self, server, monkeypatch):
        """Caso 1 — non-regressione: un body più piccolo del cap non deve
        essere toccato."""
        import shared.utils as u
        cap = 1024
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", cap, raising=False)
        body = b"x" * (cap - 100)
        port = server({"/": {"status": 200, "body": body}})

        r = u.http_get_with_retry(f"http://127.0.0.1:{port}/", timeout=5, max_attempts=1)

        assert r["content"] == body, (
            "un body sotto il cap non deve essere alterato: atteso il body "
            f"originale di {len(body)} byte, ottenuto "
            f"{len(r['content']) if r['content'] is not None else None}"
        )

    def test_body_exactly_at_cap_is_not_truncated(self, server, monkeypatch):
        """Caso 2 — bordo esatto: N byte non devono essere troncati."""
        import shared.utils as u
        cap = 1024
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", cap, raising=False)
        body = b"y" * cap
        port = server({"/": {"status": 200, "body": body}})

        r = u.http_get_with_retry(f"http://127.0.0.1:{port}/", timeout=5, max_attempts=1)

        assert r["content"] == body, (
            f"un body di esattamente {cap} byte (il limite) non deve essere "
            f"troncato: ottenuti "
            f"{len(r['content']) if r['content'] is not None else None} byte"
        )

    @pytest.mark.parametrize("multiplier", [1, 5])
    def test_body_over_cap_is_truncated_to_exactly_the_cap(self, server, monkeypatch, multiplier):
        """Caso 3 — il difetto: SEC-16. Oggi `http_get_with_retry` non ha
        alcun limite, quindi un body di N+1 byte (o 5×N) viene restituito
        PER INTERO. Deve invece essere troncato a esattamente N byte,
        indipendentemente da quanto lo supera (vedi anche caso 7 sotto)."""
        import shared.utils as u
        cap = 1024
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", cap, raising=False)
        over_size = cap + 1 if multiplier == 1 else cap * multiplier
        body = b"z" * over_size
        port = server({"/": {"status": 200, "body": body}})

        r = u.http_get_with_retry(f"http://127.0.0.1:{port}/", timeout=5, max_attempts=1)

        content = r["content"]
        assert content is not None, f"nessun content restituito: error={r['error']!r}"
        assert len(content) == cap, (
            f"body di {over_size} byte (cap={cap}): atteso troncamento a "
            f"esattamente {cap} byte, ottenuti {len(content)} byte — "
            f"SEC-16, http_get_with_retry non applica alcun limite di "
            f"dimensione al body scaricato"
        )

    def test_stream_stops_reading_after_cap_not_post_download_truncation(self, server, monkeypatch):
        """Caso 4 — distingue l'approccio scelto al G2 (streaming, stop reale
        alla connessione) dall'approccio scartato (download completo poi
        troncamento in Python). Un server locale mette in pausa l'invio a
        piccoli chunk con un SO_SNDBUF ridotto: se il client si ferma
        davvero dopo il cap e chiude la connessione, il server incontra un
        errore di socket (BrokenPipe/ConnectionReset) PRIMA di essere
        riuscito a inviare l'intero body. Se il client invece scarica tutto
        (comportamento attuale, e comportamento di un fix "trunca dopo"), il
        server consegna l'intero body senza interruzioni.

        Questo test deve fallire anche se un fixer implementasse per errore
        il troncamento post-download invece dello streaming richiesto dal
        contratto."""
        import shared.utils as u
        cap = 1024
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", cap, raising=False)

        full_size = cap * 20  # 20 KiB: ben oltre il cap, ma piccolo (niente MB)
        body = b"w" * full_size

        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(("127.0.0.1", 0))
        listen_sock.listen(1)
        port = listen_sock.getsockname()[1]

        holder = {}

        def _serve():
            holder["result"] = _run_paced_server(listen_sock, body)

        server_thread = threading.Thread(target=_serve, daemon=True)
        server_thread.start()

        try:
            u.http_get_with_retry(f"http://127.0.0.1:{port}/", timeout=10, max_attempts=1)
        finally:
            server_thread.join(timeout=10)
            listen_sock.close()

        result = holder.get("result")
        assert result is not None, "il server di prova non ha completato l'accept/invio in tempo"
        assert result.bytes_sent < full_size, (
            f"il server e' riuscito a inviare l'intero body ({result.bytes_sent}/"
            f"{full_size} byte) senza che la connessione venisse interrotta: "
            f"la lettura non si e' fermata al cap ({cap} byte) — significa che "
            f"il download NON viene interrotto in streaming (approccio scelto "
            f"al G2), quindi un eventuale troncamento avverrebbe DOPO aver "
            f"scaricato tutto (approccio scartato)"
        )

    def test_redirect_target_body_capped_after_following_redirect(self, server, monkeypatch):
        """Caso 5, prima metà — il cap si applica ANCHE al body ottenuto dopo
        aver seguito un redirect, non solo alla prima richiesta diretta."""
        import shared.utils as u
        cap = 1024
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", cap, raising=False)
        over_size = cap * 5
        routes = {"/start": {"status": 302, "headers": {}},
                  "/big": {"status": 200, "body": b"r" * over_size}}
        port = server(routes)
        routes["/start"]["headers"]["Location"] = f"http://127.0.0.1:{port}/big"

        r = u.http_get_with_retry(f"http://127.0.0.1:{port}/start", timeout=5, max_attempts=1)

        content = r["content"]
        assert content is not None, f"nessun content dopo il redirect: error={r['error']!r}"
        assert len(content) == cap, (
            f"il body ottenuto DOPO il redirect ({over_size} byte) doveva "
            f"essere troncato a {cap} byte, ottenuti {len(content)} byte — "
            f"il cap non si applica al body raggiunto tramite redirect"
        )

    def test_redirect_to_internal_address_still_blocked_with_cap_active(self, server, monkeypatch):
        """Caso 5, seconda metà — controllo di non-regressione: il guard SSRF
        sui redirect (shared/utils.py ~137-148, SSRF_REDIRECT_ERROR_PREFIX)
        deve restare intatto quando il cap sulla dimensione del body è
        attivo. Qui il guard SSRF resta ATTIVO (a differenza degli altri
        test della classe): solo l'hop di redirect punta a un indirizzo
        interno vero (169.254.169.254, metadata cloud), il server di
        partenza è il localhost di test consentito esplicitamente."""
        import shared.utils as u
        cap = 1024
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", cap, raising=False)

        # SSRF_PROTECTION resta disattivata (fixture di classe, autouse): è
        # l'unico modo per far raggiungere il server LOCALE di prova, che è
        # esso stesso un indirizzo interno (127.0.0.1) — con la protezione
        # attiva la prima richiesta verrebbe bloccata per quello, non per il
        # redirect, e il test non proverebbe nulla sul guard sul redirect.
        # Per verificare comunque che il guard sul redirect (righe ~137-148,
        # SSRF_REDIRECT_ERROR_PREFIX) resti collegato quando il cap è attivo,
        # sostituisco `is_safe_url` con una versione che si comporta come il
        # guard reale farebbe se il server di test fosse un host pubblico che
        # reindirizza a un indirizzo interno vero: consente l'hop verso il
        # server locale (comportamento reale con SSRF_PROTECTION disattivata),
        # blocca esplicitamente l'hop verso il bersaglio "sentinella" interno.
        # Il codice sotto test (http_get_with_retry) resta quello vero: viene
        # sostituita solo la funzione di giudizio del guard, non la logica che
        # la chiama e ne rispetta l'esito.
        real_is_safe_url = u.is_safe_url
        blocked_target = "http://internal.invalid/metadata"

        def _fake_is_safe_url(url):
            if url.startswith(blocked_target):
                return False, "simulated internal address (SSRF redirect guard test)"
            return real_is_safe_url(url)

        monkeypatch.setattr(u, "is_safe_url", _fake_is_safe_url)

        routes = {"/start": {"status": 302, "headers": {"Location": blocked_target}}}
        port = server(routes)

        r = u.http_get_with_retry(f"http://127.0.0.1:{port}/start", timeout=5, max_attempts=1)

        assert r["content"] is None
        assert r["error"] is not None and u.SSRF_REDIRECT_ERROR_PREFIX in r["error"], (
            f"il redirect verso un indirizzo interno doveva essere bloccato dal "
            f"guard SSRF (prefisso {u.SSRF_REDIRECT_ERROR_PREFIX!r}), ottenuto "
            f"error={r['error']!r}"
        )

    def test_oversize_result_identical_regardless_of_how_far_over_the_cap(self, server, monkeypatch):
        """Caso 7 — proprietà che oggi manca: il risultato (dimensione del
        content restituito) deve essere lo STESSO — troncato a N — sia per un
        body appena oltre il cap sia per uno molto più grande. Oggi invece
        cresce linearmente con la dimensione reale del body (nessun cap)."""
        import shared.utils as u
        cap = 1024
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", cap, raising=False)

        small_over = server({"/": {"status": 200, "body": b"p" * (cap + 50)}})
        r_small = u.http_get_with_retry(f"http://127.0.0.1:{small_over}/", timeout=5, max_attempts=1)

        big_over = server({"/": {"status": 200, "body": b"q" * (cap * 50)}})
        r_big = u.http_get_with_retry(f"http://127.0.0.1:{big_over}/", timeout=5, max_attempts=1)

        len_small = len(r_small["content"]) if r_small["content"] is not None else None
        len_big = len(r_big["content"]) if r_big["content"] is not None else None
        assert len_small == cap and len_big == cap and len_small == len_big, (
            f"il risultato deve essere identico (troncato a {cap} byte) "
            f"indipendentemente da quanto il body reale supera il cap: "
            f"body di cap+50 byte -> content di {len_small} byte, "
            f"body di cap*50 byte -> content di {len_big} byte"
        )


class TestCrtShLegitimateResponseNotBrokenByGlobalCap:
    """SEC-16, caso 6 — se il fix centralizza il cap in `http_get_with_retry`
    a un default molto più piccolo di `MAX_CRTSH_BYTES`
    (services/cert_intel.py:20, 10 MiB), un JSON legittimo di crt.sh più
    grande del nuovo default globale ma sotto MAX_CRTSH_BYTES non deve essere
    troncato a metà JSON: cert_intel.py si aspetta di poter analizzare fino a
    MAX_CRTSH_BYTES, non fino al nuovo cap generico.

    Qui la proporzione reale (2 MiB « 10 MiB) è riprodotta in scala ridotta
    (cap generico piccolo « MAX_CRTSH_BYTES piccolo) per non generare
    payload multi-MB, con `cert_intel.http_get_with_retry` sostituito da un
    wrapper che redirige SOLO l'host verso il server locale, delegando
    tutto il resto (incluso l'eventuale cap) alla vera
    `shared.utils.http_get_with_retry` — non un mock che aggira il codice
    sotto test.

    Se questo test non fosse esprimibile in modo deterministico senza
    toccare cert_intel.py, andrebbe segnalato invece di forzato: qui è
    esprimibile, perché cert_intel.py costruisce l'URL crt.sh con un solo
    schema+host fisso (`https://crt.sh/?q=...`, services/cert_intel.py:95),
    sostituibile in blocco con una stringa nota."""

    def test_legitimate_crtsh_json_between_generic_cap_and_crtsh_cap_not_corrupted(self, monkeypatch):
        import json as _json
        import shared.utils as u
        from fastapi.testclient import TestClient
        from services import cert_intel

        generic_cap = 2000          # sta al posto dei 2 MiB del cap globale
        crtsh_cap = 20000           # sta al posto dei 10 MiB di MAX_CRTSH_BYTES
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", generic_cap, raising=False)
        monkeypatch.setattr(cert_intel, "MAX_CRTSH_BYTES", crtsh_cap, raising=False)
        monkeypatch.setattr(u, "SSRF_PROTECTION", False, raising=False)

        # Dominio dedicato, non condiviso con tests/test_cert_intel.py (che usa
        # "example.com" e popola la cache locale di cert_intel, COL-04, con
        # TTL 300s — condividerlo qui farebbe leggere un risultato cachato da
        # un'esecuzione precedente invece di passare per il codice sotto
        # test). La cache viene comunque ripulita prima e dopo, stessa
        # tecnica di tests/test_cert_intel.py, per non lasciare né ereditare
        # stato fra test.
        domain = "sec16-body-cap-test.example"
        cache_key = (domain, True)

        def _clear_cache():
            cert_intel._ct_cache.pop(cache_key, None)
            if cache_key in cert_intel._ct_cache_order:
                cert_intel._ct_cache_order.remove(cache_key)

        _clear_cache()

        certs = [{
            "id": i,
            "common_name": f"host{i}.{domain}",
            "name_value": f"host{i}.{domain}",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
            "entry_timestamp": "2026-01-01T00:00:00",
        } for i in range(60)]
        body = _json.dumps(certs).encode()
        assert generic_cap < len(body) < crtsh_cap, (
            f"fixture inefficace: il body ({len(body)} byte) deve stare fra "
            f"il cap generico ({generic_cap}) e MAX_CRTSH_BYTES ({crtsh_cap}) "
            f"per rappresentare una risposta crt.sh legittima più grande del "
            f"nuovo default globale — altrimenti il test non dimostra nulla"
        )

        srv, port = _start_local_http_server({"/": {"status": 200, "body": body}})
        try:
            real_get = u.http_get_with_retry

            def _redirect_to_local(url, **kwargs):
                local_url = url.replace("https://crt.sh", f"http://127.0.0.1:{port}")
                return real_get(local_url, **kwargs)

            monkeypatch.setattr(cert_intel, "http_get_with_retry", _redirect_to_local)

            client = TestClient(cert_intel.app)
            r = client.get("/cert", params={"domain": domain})
        finally:
            srv.shutdown()
            srv.server_close()
            _clear_cache()

        assert r.status_code == 200
        payload = r.json()
        assert payload["error"] is None, (
            f"la risposta crt.sh legittima ({len(body)} byte, sotto "
            f"MAX_CRTSH_BYTES={crtsh_cap}) è stata segnalata come errore: "
            f"{payload['error']!r} — probabile troncamento a metà JSON da "
            f"parte del cap generico di http_get_with_retry (generic_cap="
            f"{generic_cap}), applicato a crt.sh senza tenere conto del "
            f"limite più permissivo MAX_CRTSH_BYTES"
        )
        assert payload["ct_certificates"]["total"] == len(certs), (
            f"attesi {len(certs)} certificati dal JSON legittimo di crt.sh, "
            f"ottenuti {payload['ct_certificates']['total']} — il body è "
            f"stato troncato a metà JSON dal cap generico invece di essere "
            f"analizzato per intero (è sotto MAX_CRTSH_BYTES)"
        )


# ═══════════════════════════════════════════════════════════════
# SEC-16 — G6 round 2, RESPINTO. Due gruppi di regressione sul fix round-1
# (già applicato in shared/utils.py/cert_intel.py, non toccato da questo
# file): il cap conta i byte scaricati, ma non chiude sempre la connessione
# (rilievo ALTO) e la sua tenuta sui byte DECOMPRESSI non aveva mai un test
# che toccasse Content-Encoding (rilievo MEDIO, buco di copertura).
# ═══════════════════════════════════════════════════════════════

def _run_incomplete_read_server(listen_sock: socket.socket, declared_extra: int,
                                 actual_body: bytes) -> None:
    """Accetta UNA connessione, dichiara un `Content-Length` più GRANDE del
    body realmente inviato (`len(actual_body) + declared_extra`), invia solo
    `actual_body` e poi rompe la connessione con un RST (`SO_LINGER` a 0,
    non una `FIN` pulita — con una `FIN` alcuni stack digeriscono comunque
    l'EOF come regolare e il client non solleva nulla). Il client
    (`requests`/`urllib3`) si aspetta ancora `declared_extra` byte quando la
    connessione si rompe: sul prossimo `read()` dentro
    `resp.iter_content(...)` questo produce un `ProtocolError`
    ("Connection broken: IncompleteRead(...)") — un'eccezione SOLLEVATA A
    META' STREAMING, con `_total` ancora ben sotto il cap. È esattamente il
    punto in cui shared/utils.py (righe ~178-185, ciclo `iter_content`) non
    passa da `resp.close()` e cade nell'`except` generico (~220-224) che non
    chiude la connessione."""
    listen_sock.settimeout(5)
    conn, _addr = listen_sock.accept()
    conn.settimeout(5)
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        declared_length = len(actual_body) + declared_extra
        header = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {declared_length}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        conn.sendall(header + actual_body)
        # RST invece di una chiusura pulita: rende deterministico l'errore
        # di IncompleteRead lato client (una FIN pulita può in certi stack
        # essere digerita come EOF regolare invece che come rottura a metà).
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        conn.close()


def _run_stall_after_partial_body_server(listen_sock: socket.socket, declared_extra: int,
                                          actual_body: bytes, stall_seconds: float,
                                          release: threading.Event) -> None:
    """Come `_run_incomplete_read_server`, ma invece di rompere la
    connessione la lascia aperta e MUTA per `stall_seconds` (maggiore del
    `timeout` che il client passa a `http_get_with_retry`): il prossimo
    `read()` dentro `resp.iter_content(...)` va in timeout — un secondo
    scenario reale di eccezione a metà streaming (`ReadTimeout`/
    `ConnectionError` per timeout), distinto da `IncompleteRead` ma con lo
    stesso punto di rottura nel codice sotto test.

    BUILD-06: la muta è un'attesa su `release`, non uno `sleep`. Il chiamante
    imposta l'evento SOLO dopo che il client è tornato; finché non lo fa il
    server tace per `stall_seconds` esatti, come con lo `sleep`, quindi il
    client vede lo stesso silenzio: scatta il suo read-timeout, e se non
    scattasse resterebbe bloccato fino alla chiusura del server a
    `stall_seconds`. Cambia solo la coda: a client già tornato il server non
    dorme più i secondi restanti, e il `join` del test non li aspetta."""
    listen_sock.settimeout(5)
    conn, _addr = listen_sock.accept()
    conn.settimeout(stall_seconds + 5)
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        declared_length = len(actual_body) + declared_extra
        header = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            f"Content-Length: {declared_length}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        conn.sendall(header + actual_body)
        release.wait(stall_seconds)  # oltre il timeout del client: provoca ReadTimeout
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


class TestConnectionLeakOnStreamingException:
    """SEC-16 — G6 round 2, rilievo ALTO. `http_get_with_retry`
    (shared/utils.py) scarica il body in streaming con
    `resp.iter_content(...)` (righe ~178-185) e chiama `resp.close()` subito
    dopo il ciclo — MA SOLO se il ciclo esce normalmente. Se `iter_content`
    solleva un'eccezione a metà streaming (connessione interrotta,
    `IncompleteRead`/`ChunkedEncodingError`; o timeout di lettura,
    `ReadTimeout`), il controllo salta direttamente da dentro il `for` fino
    all'`except` generico (~220-224), che NON chiama `resp.close()`.
    Confermato dal security-reviewer: 0 chiamate a `close()` in quel ramo.
    Connessione (socket + risorse urllib3 associate) mai rilasciata —
    connection leak, non un difetto di correttezza del contenuto.

    Verifica: uno SPY su `requests.Response.close` (monkeypatch che
    incrementa un contatore e poi chiama l'originale) deve registrare
    ALMENO una chiamata dopo `http_get_with_retry`, anche quando lo
    streaming fallisce a metà. Sul fix round-1 (nessun try/finally attorno
    al ciclo iter_content) questo è ROSSO: il contatore resta a 0."""

    @pytest.fixture(autouse=True)
    def _disable_ssrf_for_localhost(self, monkeypatch):
        import shared.utils as u
        monkeypatch.setattr(u, "SSRF_PROTECTION", False, raising=False)

    @pytest.fixture
    def close_spy(self, monkeypatch):
        """Spy su `requests.Response.close`: un wrapper che conta le
        invocazioni e poi delega all'implementazione reale — non un mock che
        sostituisce il comportamento, solo un contatore aggiunto."""
        import requests as req_lib
        calls = []
        original_close = req_lib.Response.close

        def _spy(self):
            calls.append(1)
            return original_close(self)

        monkeypatch.setattr(req_lib.Response, "close", _spy)
        return calls

    def test_close_called_when_connection_breaks_mid_stream_incomplete_read(self, close_spy):
        """Caso 1 — la connessione si rompe a metà streaming (RST), con
        `Content-Length` dichiarato più grande del body realmente inviato:
        `iter_content` solleva `IncompleteRead`/`ChunkedEncodingError` con
        `_total` ancora ben sotto il cap. `resp.close()` deve comunque
        essere chiamato."""
        import shared.utils as u
        cap = 1024 * 1024  # ben sopra il body inviato: la rottura arriva
                            # PRIMA che il ciclo raggiunga il cap da solo
        # cap non è monkeypatchato qui: usiamo `max_bytes` esplicito per non
        # toccare lo stato globale del modulo fra i due test della classe.

        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(("127.0.0.1", 0))
        listen_sock.listen(1)
        port = listen_sock.getsockname()[1]

        actual_body = b"x" * 4096  # pochi KB, ben sotto il cap
        server_thread = threading.Thread(
            target=_run_incomplete_read_server,
            args=(listen_sock, 10 * 1024 * 1024, actual_body),
            daemon=True,
        )
        server_thread.start()

        try:
            result = u.http_get_with_retry(
                f"http://127.0.0.1:{port}/", timeout=5, max_attempts=1, max_bytes=cap)
        finally:
            server_thread.join(timeout=10)
            listen_sock.close()

        assert result["error"] is not None, (
            "l'eccezione a metà streaming (IncompleteRead/ChunkedEncodingError) "
            f"deve essere gestita e riportata in `error`, non propagata senza "
            f"controllo: result={result!r}"
        )
        assert len(close_spy) >= 1, (
            "resp.close() NON e' stato chiamato quando iter_content solleva "
            "un'eccezione a meta' streaming (connessione rotta a meta', "
            "Content-Length dichiarato non soddisfatto) — shared/utils.py: "
            "il ciclo `for _chunk in resp.iter_content(...)` (~178-185) "
            "chiama resp.close() solo se esce normalmente; l'eccezione salta "
            "all'except generico (~220-224) che non chiude la connessione. "
            f"close_spy={close_spy}"
        )

    def test_close_called_when_read_times_out_mid_stream(self, close_spy):
        """Caso 2 — la connessione resta aperta ma il server si ammutolisce
        a metà body oltre il `timeout` del client: `iter_content` va in
        timeout di lettura. Stesso punto di rottura, eccezione diversa
        (`ReadTimeout`/`ConnectionError` per timeout invece di
        `IncompleteRead`) — `resp.close()` deve comunque essere chiamato."""
        import shared.utils as u
        cap = 1024 * 1024

        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(("127.0.0.1", 0))
        listen_sock.listen(1)
        port = listen_sock.getsockname()[1]

        actual_body = b"y" * 4096
        client_timeout = 1  # secondi — piccolo per non appesantire la suite
        # BUILD-06: il server muto resta tale per `client_timeout + 3` secondi
        # (il client scatta a 1 s, come prima) finché il client non è tornato;
        # solo allora lo si rilascia, così il join non aspetta i secondi che
        # restano di una muta ormai inutile. Se il read-timeout del client non
        # scattasse, l'evento non verrebbe impostato prima della fine della muta
        # e il limite superiore resterebbe quello di prima.
        release_stall = threading.Event()
        server_thread = threading.Thread(
            target=_run_stall_after_partial_body_server,
            args=(listen_sock, 10 * 1024 * 1024, actual_body, client_timeout + 3,
                  release_stall),
            daemon=True,
        )
        server_thread.start()

        try:
            result = u.http_get_with_retry(
                f"http://127.0.0.1:{port}/", timeout=client_timeout,
                max_attempts=1, max_bytes=cap)
        finally:
            release_stall.set()
            server_thread.join(timeout=client_timeout + 10)
            listen_sock.close()

        assert result["error"] is not None, (
            "il timeout di lettura a meta' streaming deve essere gestito e "
            f"riportato in `error`, non propagato senza controllo: "
            f"result={result!r}"
        )
        assert len(close_spy) >= 1, (
            "resp.close() NON e' stato chiamato quando iter_content va in "
            "timeout a meta' streaming — stesso connection leak del caso "
            f"IncompleteRead sopra, punto di rottura identico in "
            f"shared/utils.py (~178-185 / ~220-224). close_spy={close_spy}"
        )


def _run_chunked_gzip_server(listen_sock: socket.socket, gzip_body: bytes,
                              chunk_size: int = 4096) -> None:
    """Serve `gzip_body` (già compresso, generato UNA volta dal chiamante,
    non ad ogni richiesta) con `Transfer-Encoding: chunked` +
    `Content-Encoding: gzip` — combina i due meccanismi di decodifica dello
    stream (framing chunked + decompressione gzip) per il caso in cui non
    esiste un `Content-Length` noto in anticipo (risposta gzip generata al
    volo, scenario realistico per un server compromesso)."""
    listen_sock.settimeout(5)
    conn, _addr = listen_sock.accept()
    conn.settimeout(10)
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        header = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Encoding: gzip\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        conn.sendall(header)
        for i in range(0, len(gzip_body), chunk_size):
            piece = gzip_body[i:i + chunk_size]
            conn.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
        conn.sendall(b"0\r\n\r\n")
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        conn.close()


def _spy_max_iter_content_chunk(monkeypatch) -> dict:
    """Wrappa `requests.Response.iter_content` per REGISTRARE la dimensione
    del chunk decompresso più grande consumato durante lo streaming — non ne
    cambia il comportamento, si limita a osservarlo (stesso pattern dello
    spy su `close` del Gruppo A). Restituisce un dict mutabile
    `{"max": int}` aggiornato man mano che il generatore viene consumato.

    Serve perché `shared/utils.py:197` tronca `content` con `[:cap]` DOPO lo
    streaming: un'asserzione su `len(content)` finale è sempre vera a
    prescindere da come i chunk sono arrivati, e non vede il picco di
    memoria reale di un singolo chunk decompresso (il vettore del DoS —
    round-2 del verifier su SEC-16). Il picco per-chunk, catturato QUI,
    prima del troncamento, è l'unico osservabile che distingue "urllib3
    limita la decompressione per singola lettura ad `amt`" (>=2.0, il bound
    che il pin `urllib3>=2,<3` garantisce) da "la decompressione di un
    singolo chunk letto dal socket produce in un colpo solo l'intero output
    bufferizzato" (<2.0, dove un solo chunk può materializzare l'intera
    bomba in memoria prima che il ciclo di `http_get_with_retry` abbia anche
    solo la possibilità di controllare `_total >= cap`)."""
    import requests

    peak = {"max": 0}
    original_iter_content = requests.Response.iter_content

    def _spy(self, chunk_size=1, *args, **kwargs):
        for chunk in original_iter_content(self, chunk_size, *args, **kwargs):
            if chunk:
                peak["max"] = max(peak["max"], len(chunk))
            yield chunk

    monkeypatch.setattr(requests.Response, "iter_content", _spy)
    return peak


class TestFetchDecompressionBombGuardrail:
    """SEC-16 — round 3. Verifica il PICCO PER-CHUNK della decompressione
    gzip, non il `content` finale.

    Il round-2 aveva un'asserzione tautologica: `len(content) <= cap` è
    SEMPRE vera perché `shared/utils.py:197` fa `content = b"".join(_chunks)
    [:cap]` — il troncamento esplicito garantisce quel limite
    indipendentemente da come si comporta `urllib3` a monte. Con urllib3
    1.26.20 installato in un venv pulito, questo stesso body (rapporto di
    compressione ~1:20 sul cap) produce un SINGOLO chunk decompresso da
    `iter_content(chunk_size=8192)` di ~8,4 MB — il DoS avviene comunque, il
    test round-2 restava verde perché guardava solo il risultato già
    tagliato, mai il picco intermedio.

    Questi test spiano `requests.Response.iter_content` (vedi
    `_spy_max_iter_content_chunk` sopra) per catturare la dimensione del
    chunk decompresso più grande PRIMA del troncamento, e asseriscono che
    resti BOUNDED entro una piccola tolleranza rispetto a `chunk_size=8192`
    (il valore passato da `shared/utils.py:188`). Soglia scelta:
    `8192 * 4 = 32768` byte. Il fattore 4 è tolleranza, non un limite
    stretto: su urllib3>=2 il bound `amt` passato a
    `zlib.decompressobj().decompress(data, amt)` fa sì che ogni chunk
    decompresso resti dell'ordine di `chunk_size` (osservato: esattamente
    8192 byte per i chunk pieni su questa immagine, 2.7.0), quindi un
    fattore 4 lascia ampio margine a piccole variazioni implementative
    senza indebolire la discriminazione — un singolo chunk da ~8,4 MB
    (urllib3<2, misurato in un venv separato) lo supera di oltre 250x, non
    di poco: non è un confine sottile.

    Verificato che il test è discriminante (round-3, prova di efficacia):
    - urllib3 2.7.0 (questa immagine): picco per-chunk osservato ~8192 byte
      → PASSA.
    - urllib3 1.26.20 (venv pulito in /tmp, stesso `requests`): picco
      per-chunk osservato ~8,4 MB → il test diventa ROSSO nettamente sopra
      soglia. È la prova che senza il pin `urllib3>=2,<3`
      (`requirements.txt`) la difesa round-1 non è garantita, e che QUESTO
      test — a differenza del round-2 — lo rileva."""

    @pytest.fixture(autouse=True)
    def _disable_ssrf_for_localhost(self, monkeypatch):
        import shared.utils as u
        monkeypatch.setattr(u, "SSRF_PROTECTION", False, raising=False)

    # Tolleranza sul picco per-chunk: multiplo di chunk_size=8192
    # (`shared/utils.py:188`). Vedi motivazione nel docstring di classe.
    PEAK_CHUNK_THRESHOLD = 8192 * 4

    def test_gzip_body_per_chunk_peak_is_bounded_by_chunk_size(self, monkeypatch):
        import shared.utils as u

        cap = 1024 * 1024  # 1 MiB — piccolo apposta: il cap va tenuto basso
                            # per non generare payload multi-MB reali nella suite
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", cap, raising=False)

        decompressed_size = cap * 20  # 20x il cap: basta a dimostrare il bounding
        # Pattern altamente ripetitivo: comprime a pochissimi KB anche per
        # decine di MB decompressi — solo il RISULTATO decompresso è grande,
        # il body che viaggia sul filo resta piccolo (bomba reale).
        raw = b"A" * decompressed_size
        gzip_body = gzip.compress(raw, compresslevel=9)
        assert len(gzip_body) < decompressed_size / 100, (
            "fixture inefficace: il body compresso deve restare piccolo "
            f"rispetto al decompresso per rappresentare una bomba reale "
            f"({len(gzip_body)} byte compressi vs {decompressed_size} decompressi)"
        )

        peak = _spy_max_iter_content_chunk(monkeypatch)

        srv, port = _start_local_http_server({
            "/": {"status": 200, "body": gzip_body,
                  "headers": {"Content-Encoding": "gzip"}}
        })
        try:
            r = u.http_get_with_retry(f"http://127.0.0.1:{port}/", timeout=10, max_attempts=1)
        finally:
            srv.shutdown()
            srv.server_close()

        assert r["content"] is not None, f"nessun content restituito: error={r['error']!r}"
        assert peak["max"] <= self.PEAK_CHUNK_THRESHOLD, (
            f"picco per-chunk decompresso = {peak['max']} byte, sopra la "
            f"soglia di {self.PEAK_CHUNK_THRESHOLD} byte (4x chunk_size=8192): "
            f"un chunk singolo così grande materializza in memoria una parte "
            f"rilevante della bomba PRIMA che il ciclo di "
            f"`http_get_with_retry` possa controllare `_total >= cap` — "
            f"comportamento tipico di urllib3<2 (nessun bound `amt` sulla "
            f"decompressione per singola lettura); indica che il pin "
            f"`urllib3>=2,<3` (requirements.txt) non è rispettato "
            f"nell'ambiente in cui gira questo test"
        )

    def test_chunked_transfer_encoding_plus_gzip_peak_bounded_by_chunk_size(self, monkeypatch):
        """Combinazione chunked + gzip: nessun `Content-Length` noto in
        anticipo (framing `Transfer-Encoding: chunked`), il body decodifica
        due livelli di stream (chunk framing, poi gzip) prima che
        `http_get_with_retry` veda i byte. Stessa proprietà attesa: il
        picco per-chunk decompresso resta bounded, non solo il content
        finale già troncato."""
        import shared.utils as u

        cap = 1024 * 1024
        monkeypatch.setattr(u, "MAX_FETCH_BODY_BYTES", cap, raising=False)

        decompressed_size = cap * 20
        raw = b"B" * decompressed_size
        gzip_body = gzip.compress(raw, compresslevel=9)

        peak = _spy_max_iter_content_chunk(monkeypatch)

        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(("127.0.0.1", 0))
        listen_sock.listen(1)
        port = listen_sock.getsockname()[1]

        server_thread = threading.Thread(
            target=_run_chunked_gzip_server, args=(listen_sock, gzip_body), daemon=True)
        server_thread.start()

        try:
            r = u.http_get_with_retry(f"http://127.0.0.1:{port}/", timeout=10, max_attempts=1)
        finally:
            server_thread.join(timeout=15)
            listen_sock.close()

        assert r["content"] is not None, f"nessun content restituito: error={r['error']!r}"
        assert peak["max"] <= self.PEAK_CHUNK_THRESHOLD, (
            f"chunked+gzip: picco per-chunk decompresso = {peak['max']} byte, "
            f"sopra la soglia di {self.PEAK_CHUNK_THRESHOLD} byte "
            f"(4x chunk_size=8192) — stesso rischio del caso non-chunked, "
            f"osservato attraverso un secondo livello di framing dello stream"
        )


# ═══════════════════════════════════════════════════════════════
# SEC-18 — durata massima complessiva di http_get_with_retry (slowloris)
# ═══════════════════════════════════════════════════════════════
#
# CONTRATTO fissato da questo test-author per il fixer (G3, SEC-18). Fonte:
# BUG-REGISTER.md, sezione «SEC-18 — apertura (2026-10-21…)»: G2 superato
# (causa radice), DECISIONE utente («Ok» alla raccomandazione) e criteri
# S18-1…S18-9. Nessun criterio è stato reinterpretato.
#
#   Costante:  shared.utils.MAX_FETCH_SECONDS, default 40, letta dall'env
#              MAX_FETCH_SECONDS. Va letta A RUNTIME dentro
#              http_get_with_retry (non bindata come default-arg): stesso
#              pattern e stesso motivo di MAX_FETCH_BODY_BYTES / max_bytes. I
#              test la variano con monkeypatch.setattr(shared.utils, ...).
#   Parametro: http_get_with_retry(..., max_seconds=None). Se non è None ha
#              PRECEDENZA sulla costante, sia verso il basso sia verso l'alto
#              (un min() fra i due non è conforme).
#   Portata:   l'INTERA chiamata — tentativi, redirect e backoff inclusi.
#   Errore:    shared.utils.FETCH_DEADLINE_ERROR_PREFIX, sul modello di
#              SSRF_ERROR_PREFIX / SSRF_REDIRECT_ERROR_PREFIX. Allo scadere
#              result["error"] COMINCIA per quel prefisso, result["content"]
#              è None e result["status_code"] è None (nessun risultato
#              parziale, nemmeno lo status già visto da un hop o da un
#              tentativo precedente: coordinator, corollario della semantica
#              «non ho potuto guardare» di CODE-15). La scadenza è terminale:
#              nessun nuovo tentativo parte dopo D.
#   Config:    MAX_FETCH_SECONDS malformato (non numerico, 0, negativo, nan,
#              inf, stringa vuota) non fa fallire l'import: ricade su 40 con
#              un logger.warning che nomina la variabile (precedente PERF-01,
#              services/reputation.py).
#
# TEMPI. D = 0,5 s (1 s dove servono due tentativi) e `timeout` per-lettura
# > D, per dimostrare che il timeout per lettura non allunga il limite. La
# suite è al limite dei 90 s di CLAUDE.md §4 e sul codice fixato ogni scenario
# costa ~D di attesa reale: la scala è stata ridotta (D=2 s -> 0,5 s) senza
# toccare le proprietà verificate. Le gocce durano 6-8 s (molto oltre D) con un
# passo di 0,1 s (molto sotto D, vedi «PASSO DELLA GOCCIA»); tolleranza ε = D
# (1 s per il servizio, che aggiunge il serializzatore JSON e il threadpool di
# anyio). I mutanti restano molto oltre D + ε (3-10 s).
#
# RETE. Nessuna rete reale: i server sono socket grezzi su 127.0.0.1 in thread
# daemon, chiusi dalla fixture a fine test (anche se il test fallisce). La
# guardia SSRF è disattivata SOLO dalla fixture di classe, come in
# TestFetchBodySizeCap; i test della guardia stessa la riattivano.

import inspect
import json
import logging
import select
import shutil
import ssl


class _DripServer:
    """Server HTTP "a goccia" su socket grezzi (127.0.0.1, porta effimera).

    Ogni connessione accettata gira in un thread daemon proprio: il thread
    legge la richiesta fino a `\\r\\n\\r\\n` e poi delega a `handler(srv, conn,
    path)`. L'handler scrive con `srv.send` e attende con `srv.wait`, che
    mentre aspetta OSSERVA il socket: se il client chiude (FIN, RST o `send`
    fallita) imposta `client_closed` e restituisce True, così gli handler
    smettono subito e il test può dire se il client ha davvero liberato la
    connessione. `accept_times` (time.monotonic) permette di contare le
    connessioni accettate dopo un dato istante.

    `close()` (chiamato dalla fixture) ferma tutto e fa il join dei thread:
    nessun thread del server sopravvive al test, così le baseline di
    `threading.active_count()` dei test successivi restano pulite."""

    def __init__(self, handler, ssl_context=None, raw=False):
        """`ssl_context`: server TLS (handshake lato server nel thread della
        connessione). `raw=True`: l'handler parte subito dopo l'accept, senza
        attendere una richiesta HTTP (serve a simulare un server TLS muto o a
        goccia, che non parla HTTP)."""
        self._handler = handler
        self._ssl_context = ssl_context
        self._raw = raw
        self.stop = threading.Event()
        self.client_closed = threading.Event()
        self.accept_times = []
        self.paths = []
        self._conns = []
        self._threads = []
        self._lock = threading.Lock()
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen.bind(("127.0.0.1", 0))
        self._listen.listen(16)
        self._listen.settimeout(0.1)
        self.port = self._listen.getsockname()[1]
        self._acceptor = threading.Thread(target=self._accept_loop, daemon=True)
        self._acceptor.start()

    def _accept_loop(self):
        while not self.stop.is_set():
            try:
                conn, _addr = self._listen.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(5)
            thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
            with self._lock:
                self.accept_times.append(time.monotonic())
                self._conns.append(conn)
                self._threads.append(thread)
            thread.start()

    def _serve(self, conn):
        try:
            if self._ssl_context is not None:
                conn = self._ssl_context.wrap_socket(conn, server_side=True)
                with self._lock:
                    self._conns.append(conn)
            if self._raw:
                self._handler(self, conn, "")
                return
            buf = b""
            give_up = time.monotonic() + 5
            while b"\r\n\r\n" not in buf:
                if self.stop.is_set() or time.monotonic() > give_up:
                    return
                ready, _, _ = select.select([conn], [], [], 0.1)
                if not ready and not (self._ssl_context is not None and conn.pending()):
                    continue
                try:
                    chunk = conn.recv(4096)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    continue
                if not chunk:
                    return
                buf += chunk
            path = buf.split(b" ", 2)[1].decode("latin-1")
            with self._lock:
                self.paths.append(path)
            self._handler(self, conn, path)
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def send(self, conn, data):
        """True se i byte sono stati consegnati al kernel; False (e
        `client_closed`) se il client non c'è più."""
        try:
            conn.sendall(data)
            return True
        except OSError:
            if not self.stop.is_set():
                self.client_closed.set()
            return False

    def wait(self, conn, seconds):
        """Attende `seconds` osservando il client. True = l'handler deve
        smettere (il client ha chiuso, oppure è in corso il teardown)."""
        end = time.monotonic() + seconds
        while True:
            if self.stop.is_set():
                return True
            remaining = end - time.monotonic()
            if remaining <= 0:
                return False
            try:
                ready, _, _ = select.select([conn], [], [], min(remaining, 0.05))
                if ready and not conn.recv(4096):
                    if not self.stop.is_set():
                        self.client_closed.set()
                    return True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                continue            # record TLS incompleto: il client NON ha chiuso
            except (OSError, ValueError):
                if not self.stop.is_set():
                    self.client_closed.set()
                return True

    def close(self):
        self.stop.set()
        try:
            # shutdown prima di close: sveglia subito l'`accept` bloccato
            # nell'altro thread invece di aspettarne il timeout (100 ms/test).
            self._listen.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._listen.close()
        except OSError:
            pass
        with self._lock:
            conns = list(self._conns)
            threads = list(self._threads)
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        self._acceptor.join(timeout=2)
        for thread in threads:
            thread.join(timeout=2)


def _sec18_head(status, reason, headers, complete=True):
    """Status line + header + `Connection: close`. Con complete=False manca la
    riga vuota finale: il chiamante la invia più tardi (header a goccia)."""
    lines = [f"HTTP/1.1 {status} {reason}"]
    lines += [f"{name}: {value}" for name, value in headers]
    lines.append("Connection: close")
    return ("\r\n".join(lines) + ("\r\n\r\n" if complete else "\r\n")).encode("latin-1")


def _sec18_respond(status=200, reason="OK", body=b"", headers=()):
    """Risposta completa e immediata."""
    def handler(srv, conn, path):
        head = _sec18_head(status, reason, [*headers, ("Content-Length", str(len(body)))])
        srv.send(conn, head + body)
    return handler


def _sec18_drip_body(n_bytes, delay, status=200, reason="OK", declare_length=True):
    """Header subito, poi il body (`n_bytes` di b"a") un byte ogni `delay`
    secondi: durata totale n_bytes * delay. Ogni singola lettura del client
    riceve dati ben prima di qualunque `timeout` ragionevole.

    `declare_length=False` omette `Content-Length` (body delimitato dalla
    chiusura, `Connection: close`): se la connessione viene chiusa a metà il
    client vede un EOF PULITO e non un'eccezione `IncompleteRead`, quindi un
    fix che interrompe la lettura ottiene un body parziale con status 200
    invece di un errore: è il caso in cui lo status residuo si nota."""
    def handler(srv, conn, path):
        headers = [("Content-Type", "text/html")]
        if declare_length:
            headers.append(("Content-Length", str(n_bytes)))
        head = _sec18_head(status, reason, headers)
        if not srv.send(conn, head):
            return
        for _ in range(n_bytes):
            if srv.wait(conn, delay) or not srv.send(conn, b"a"):
                return
    return handler


def _sec18_drip_headers(n_bytes, delay):
    """Status line subito, poi UN header non terminato che cresce di un byte
    ogni `delay` secondi: `requests.get` non ha ancora restituito la risposta
    per tutta la durata (n_bytes * delay). A goccia finita completa la
    risposta ("ok"), così sul codice non fixato la chiamata riesce dopo
    n_bytes * delay secondi."""
    def handler(srv, conn, path):
        if not srv.send(conn, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                              b"Connection: close\r\nX-Drip: "):
            return
        for _ in range(n_bytes):
            if srv.wait(conn, delay) or not srv.send(conn, b"a"):
                return
        srv.send(conn, b"\r\n\r\nok")
    return handler


def _sec18_redirect_chain(n_redirects, hop_delay):
    """Catena /h0 -> /h1 -> ... -> /h<n_redirects> (200). Ogni hop invia
    status line e header subito ma trattiene la riga vuota finale per
    `hop_delay` secondi: preso da solo sta sotto D, la catena intera no."""
    def handler(srv, conn, path):
        try:
            hop = int(path.rsplit("/h", 1)[1])
        except (IndexError, ValueError):
            hop = n_redirects
        if hop < n_redirects:
            head = _sec18_head(302, "Found",
                               [("Location", f"http://127.0.0.1:{srv.port}/h{hop + 1}"),
                                ("Content-Length", "0")], complete=False)
            tail = b"\r\n"
        else:
            head = _sec18_head(200, "OK", [("Content-Length", "2")], complete=False)
            tail = b"\r\nok"
        if srv.send(conn, head) and not srv.wait(conn, hop_delay):
            srv.send(conn, tail)
    return handler


def _sec18_silent(srv, conn, path):
    """Accetta, legge la richiesta e non risponde mai (connessione muta)."""
    srv.wait(conn, 3600)


class _Sec18Base:
    """Infrastruttura comune alle classi SEC-18 (non è una classe di test)."""

    # Scala dei tempi: D piccolo, perché sul codice fixato OGNI scenario costa
    # ~D di attesa reale (la suite è al limite dei 90 s di CLAUDE.md §4). La
    # tolleranza ε è proporzionale (ε = D) e le gocce sono molto più lunghe di D
    # (6-8 s) con un passo molto sotto D (0,1 s): il timeout per lettura è
    # clampato a D e un passo vicino a D farebbe scattare quello al posto della
    # scadenza (vedi «PASSO DELLA GOCCIA»). I tempi dei mutanti (3-10 s) restano
    # molto oltre D + ε.
    D = 0.5        # durata massima usata dai test, in secondi
    SLACK = 0.5    # ε: tolleranza su D per la chiamata diretta

    # Il container di sviluppo instrada https:// (e a volte http://) verso un
    # proxy esterno: un test su 127.0.0.1 non deve MAI passarne. Variabili
    # rimosse per la durata del singolo test, ripristinate da monkeypatch.
    _PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                   "http_proxy", "https_proxy", "all_proxy", "no_proxy")

    @pytest.fixture(autouse=True)
    def _local_network_only(self, monkeypatch):
        """I server di prova stanno su 127.0.0.1: senza questo il guard SSRF
        (TestSSRFProtection, comportamento voluto) bloccherebbe la richiesta
        prima del codice sotto test. Solo infrastruttura del test."""
        import shared.utils as u
        monkeypatch.setattr(u, "SSRF_PROTECTION", False, raising=False)
        for var in self._PROXY_VARS:
            monkeypatch.delenv(var, raising=False)

    @pytest.fixture
    def drip_server(self):
        """Factory: drip_server(handler) -> _DripServer. Chiude tutto a fine
        test, anche se il test fallisce."""
        started = []

        def _start(handler, **options):
            srv = _DripServer(handler, **options)
            started.append(srv)
            return srv

        yield _start
        for srv in started:
            srv.close()

    @pytest.fixture(params=["requests", "urllib"])
    def branch(self, request, monkeypatch):
        """Esegue il test sui due rami di `http_get_with_retry`."""
        if request.param == "urllib":
            self._force_urllib(monkeypatch)
        return request.param

    def _set_deadline(self, monkeypatch, seconds):
        # raising=False: sul codice non ancora fixato la costante non esiste
        # e il test deve fallire per il COMPORTAMENTO, non per l'attributo.
        import shared.utils as u
        monkeypatch.setattr(u, "MAX_FETCH_SECONDS", seconds, raising=False)

    def _force_urllib(self, monkeypatch):
        """Forza il ramo di fallback `urllib` (HAS_REQUESTS=False). Con
        `requests` installato `shared.utils` non ha il nome `urllib` nel
        proprio namespace (lo importa solo nell'`except ImportError`), quindi
        lo si fornisce qui: infrastruttura del test, non parte del difetto."""
        import urllib.request
        import shared.utils as u
        monkeypatch.setattr(u, "HAS_REQUESTS", False)
        monkeypatch.setattr(u, "urllib", urllib, raising=False)

    def _fetch(self, url, **kwargs):
        import shared.utils as u
        t0 = time.monotonic()
        result = u.http_get_with_retry(url, **kwargs)
        return result, time.monotonic() - t0, t0

    def _deadline_problems(self, result, elapsed, limit=None, slack=None):
        """Verifica composta dell'esito «durata massima scaduta»: tempo,
        errore riconoscibile, nessun contenuto parziale, nessuno status
        parziale. Restituisce la lista dei problemi (vuota = ok), così un
        test fallito li mostra TUTTI e non solo il primo.

        `status_code` deve essere None perché `collection_failed`
        (shared/utils.py) conta un check con `status_code` valorizzato come
        LETTURA REALE: una scadenza che lasciasse 200 (header già ricevuti)
        o 503 (primo tentativo) produrrebbe uno snapshot «vuoto ma valido»
        e avvelenerebbe la baseline, la classe di difetti di CODE-01."""
        import shared.utils as u
        limit = self.D if limit is None else limit
        slack = self.SLACK if slack is None else slack
        problems = []
        if elapsed > limit + slack:
            problems.append(
                f"la chiamata è tornata dopo {elapsed:.2f}s: oltre D + {slack:g}s = "
                f"{limit + slack:g}s (D={limit}s) — il tempo non è limitato"
            )
        prefix = getattr(u, "FETCH_DEADLINE_ERROR_PREFIX", None)
        if not isinstance(prefix, str) or not prefix:
            problems.append("manca shared.utils.FETCH_DEADLINE_ERROR_PREFIX (stringa non vuota)")
        elif not str(result.get("error") or "").startswith(prefix):
            problems.append(
                f"error={result.get('error')!r} non comincia per "
                f"FETCH_DEADLINE_ERROR_PREFIX ({prefix!r}): la scadenza non è riconoscibile"
            )
        if result.get("content") is not None:
            problems.append(
                f"content è {type(result['content']).__name__} di "
                f"{len(result['content'])} byte: allo scadere non deve restare "
                "nessun contenuto parziale (deve essere None)"
            )
        if result.get("status_code") is not None:
            problems.append(
                f"status_code={result['status_code']!r}: allo scadere deve essere None, "
                "altrimenti collection_failed conta il check come lettura reale e la "
                "baseline si avvelena (CODE-01)"
            )
        if result.get("headers") != {}:
            problems.append(
                f"headers={result.get('headers')!r}: allo scadere devono essere {{}} "
                "(nessun header di un tentativo o hop precedente)"
            )
        if result.get("final_url") is not None:
            problems.append(
                f"final_url={result.get('final_url')!r}: allo scadere deve essere None "
                "(nessun redirect di un tentativo precedente)"
            )
        return problems


class TestSEC18FetchDeadline(_Sec18Base):
    """SEC-18 — slowloris su `http_get_with_retry` (shared/utils.py), zona NON
    autenticata (`/http`, services/http_fingerprint.py:63).

    Causa radice (G2): `timeout=` arriva a `requests` (e a `urlopen`) come
    timeout PER SINGOLA OPERAZIONE sul socket, che si riarma a ogni byte
    ricevuto, e il ciclo di lettura non ha un orologio proprio: un server che
    manda 1 byte ogni 2 s tiene occupato il thread per ore (4 s / 9 s / 19 s
    per 5 / 10 / 20 byte misurati, 56,5 s con 3 tentativi 503 a goccia, +49
    thread lasciati vivi lato server dopo l'abbandono del client).

    DECISIONE utente (21/10, «Ok» alla raccomandazione): D = 40 s di default,
    env `MAX_FETCH_SECONDS`, parametro `max_seconds` per chiamante; la durata
    vale per l'INTERA chiamata (tentativi, redirect e backoff inclusi); allo
    scadere errore riconoscibile e nessun contenuto parziale.

    Qui D è ridotto a 2 s (costante monkeypatchata) e il `timeout` per
    lettura è > D: il limite deve valere anche se ogni singola lettura
    riceve dati in tempo."""

    # ── S18-1 ─────────────────────────────────────────────────────────

    def test_trickled_body_is_cut_at_deadline_not_at_per_read_timeout(self, monkeypatch, drip_server):
        """S18-1 — body a goccia: 1 byte ogni 0,1 s per 8 s, `timeout=10`
        (ogni lettura riceve dati molto prima). La chiamata deve tornare entro
        D + ε con errore riconoscibile e content None; la scadenza è
        terminale, quindi con `max_attempts=3` il server vede UNA sola
        connessione (nessun nuovo tentativo dopo D)."""
        self._set_deadline(monkeypatch, self.D)
        # Senza Content-Length: un'interruzione della lettura dà un EOF pulito
        # (body parziale + status 200), non un'eccezione — vedi _sec18_drip_body.
        srv = drip_server(_sec18_drip_body(80, 0.1, declare_length=False))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=3, base_delay=1)

        problems = self._deadline_problems(result, elapsed)
        if len(srv.accept_times) != 1:
            problems.append(
                f"il server ha accettato {len(srv.accept_times)} connessioni: la scadenza "
                "di D deve essere terminale, non innescare un nuovo tentativo"
            )
        assert not problems, "SEC-18 / S18-1, body a goccia:\n  - " + "\n  - ".join(problems)

    # ── S18-2 ─────────────────────────────────────────────────────────

    def test_trickled_headers_are_cut_at_deadline_before_requests_get_returns(self, monkeypatch, drip_server):
        """S18-2 — header a goccia: la status line arriva subito, poi un
        header non terminato cresce di 1 byte ogni 0,1 s per 8 s. Stesso
        limite, anche se `requests.get` non ha ancora restituito la risposta
        (il controllo non può stare solo nel ciclo `iter_content`)."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_headers(80, 0.1))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, "SEC-18 / S18-2, header a goccia:\n  - " + "\n  - ".join(problems)

    # ── S18-3 ─────────────────────────────────────────────────────────

    def test_redirect_chain_slow_in_total_is_cut_at_deadline(self, monkeypatch, drip_server):
        """S18-3 — catena di 4 redirect + risposta finale (i 5 hop che il
        codice segue): ogni hop impiega 0,4 s, quindi preso da solo sta sotto
        D=0,5 s, ma la catena intera ne impiega 2. Deve essere limitata a
        D + ε: la durata massima non si azzera a ogni hop."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_redirect_chain(4, 0.4))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/h0", timeout=10, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, "SEC-18 / S18-3, catena di redirect:\n  - " + "\n  - ".join(problems)

    # ── S18-4 ─────────────────────────────────────────────────────────

    def test_slow_503_retries_are_bounded_and_no_attempt_starts_after_deadline(self, monkeypatch, drip_server):
        """S18-4 — risposte 503 lente (0,6 s ciascuna) con D=1 s,
        `max_attempts=3` e `base_delay=0.25`: il primo tentativo finisce a
        0,6 s, il secondo parte a 0,85 s e la scadenza lo interrompe a metà;
        senza limite totale la chiamata dura ~2,55 s (il terzo tentativo
        parte a 1,95 s). Deve essere limitata a D + ε in totale e NESSUN
        tentativo deve partire oltre D: il server non deve accettare
        connessioni dopo D (tolleranza 0,2 s)."""
        deadline_s = 1.0       # più grande della base: serve spazio per due tentativi
        self._set_deadline(monkeypatch, deadline_s)
        srv = drip_server(_sec18_drip_body(6, 0.1, status=503, reason="Service Unavailable"))

        result, elapsed, t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=3, base_delay=0.25)

        problems = self._deadline_problems(result, elapsed, limit=deadline_s)
        late = [round(t - t0, 2) for t in srv.accept_times if t - t0 > deadline_s + 0.2]
        if late:
            problems.append(
                f"il server ha accettato connessioni a t={late}s dall'inizio: un nuovo "
                f"tentativo è partito dopo D={deadline_s}s"
            )
        assert not problems, "SEC-18 / S18-4, retry 503 a goccia:\n  - " + "\n  - ".join(problems)

    def test_backoff_wait_is_bounded_by_deadline(self, monkeypatch, drip_server):
        """S18-4 — il backoff fa parte della durata («tentativi, redirect e
        backoff inclusi», decisione utente). 503 immediato, `max_attempts=2`
        e `base_delay=3`: il secondo tentativo partirebbe a t=3 s, oltre
        D=0,5 s. La chiamata deve tornare entro D + ε con la scadenza e il
        server deve aver visto UNA sola connessione. Non basta controllare
        la scadenza solo prima di ogni tentativo."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_respond(503, "Service Unavailable", body=b"ko"))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=2, base_delay=3)

        problems = self._deadline_problems(result, elapsed)
        if len(srv.accept_times) != 1:
            problems.append(
                f"il server ha accettato {len(srv.accept_times)} connessioni: il secondo "
                "tentativo, schedulato dopo D dal backoff, non doveva partire"
            )
        assert not problems, "SEC-18 / S18-4, backoff oltre D:\n  - " + "\n  - ".join(problems)

    # ── bozza G1 (e): connessione muta ────────────────────────────────

    def test_silent_connection_is_cut_at_deadline_not_at_per_read_timeout(self, monkeypatch, drip_server):
        """Caso (e) della bozza G1 («connessione aperta che non risponde
        mai») e ultima frase di S18-1 («il `timeout` per lettura non deve
        allungare il limite»): `timeout=3` > D=0,5, il server accetta e tace.
        Oggi la chiamata torna solo al timeout per lettura (3 s); con la
        durata massima deve tornare entro D + ε. Distingue chi limita il
        tempo complessivo da chi non accorcia la singola lettura."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_silent)

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=3, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, "SEC-18 / (e), connessione muta:\n  - " + "\n  - ".join(problems)

    # ── S18-5 ─────────────────────────────────────────────────────────

    def test_urllib_branch_trickled_body_is_cut_at_deadline(self, monkeypatch, drip_server):
        """S18-5 — ramo `urllib` (HAS_REQUESTS=False), body a goccia: stesso
        limite di S18-1."""
        self._force_urllib(monkeypatch)
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_body(80, 0.1))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, "SEC-18 / S18-5, urllib + body a goccia:\n  - " + "\n  - ".join(problems)

    def test_urllib_branch_trickled_headers_are_cut_at_deadline(self, monkeypatch, drip_server):
        """S18-5 — ramo `urllib`, header a goccia: stesso limite di S18-2
        (qui `urlopen` non è ancora tornato)."""
        self._force_urllib(monkeypatch)
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_headers(80, 0.1))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, "SEC-18 / S18-5, urllib + header a goccia:\n  - " + "\n  - ".join(problems)

    # ── S18-6: invarianti (verdi oggi, devono restare verdi) ──────────

    def test_fast_response_is_unchanged(self, monkeypatch, drip_server):
        """S18-6 — una risposta veloce resta identica: status, content,
        headers, final_url, error e numero di tentativi. Invariante: verde
        oggi, deve restare verde col fix."""
        self._set_deadline(monkeypatch, self.D)
        body = b"<html><body>ciao</body></html>"
        srv = drip_server(_sec18_respond(200, "OK", body=body, headers=[("X-Probe", "sec18")]))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=3)

        assert result["status_code"] == 200
        assert result["content"] == body
        assert result["headers"].get("X-Probe") == "sec18"
        assert result["final_url"] is None
        assert result["error"] is None
        assert result["attempts"] == 1
        assert elapsed < self.D, f"una risposta immediata ha impiegato {elapsed:.2f}s"

    def test_slow_response_within_deadline_is_unchanged(self, monkeypatch, drip_server):
        """S18-6 — una risposta lenta ma dentro D resta identica: 8 byte a
        goccia in ~0,4 s con D=1 s. Il limite non deve tagliare un server
        lento-ma-onesto (è il motivo per cui D=40 e non un valore stretto)."""
        self._set_deadline(monkeypatch, 1)
        srv = drip_server(_sec18_drip_body(8, 0.05))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1)

        assert result["status_code"] == 200
        assert result["content"] == b"a" * 8
        assert result["error"] is None
        assert result["final_url"] is None
        assert elapsed < 1, f"la risposta entro D è arrivata dopo {elapsed:.2f}s"

    def test_redirect_within_deadline_keeps_final_url(self, monkeypatch, drip_server):
        """S18-6 — un redirect seguito entro D resta identico: stesso
        content e `final_url` valorizzato con l'ultimo hop."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_redirect_chain(1, 0.1))

        result, _elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/h0", timeout=10, max_attempts=1)

        assert result["status_code"] == 200
        assert result["content"] == b"ok"
        assert result["final_url"] == f"http://127.0.0.1:{srv.port}/h1"
        assert result["error"] is None

    def test_ssrf_guard_on_redirect_hop_is_unchanged_with_deadline_active(self, monkeypatch, drip_server):
        """S18-6 — la guardia SSRF per hop resta invariata: un redirect verso
        un indirizzo interno è bloccato con SSRF_REDIRECT_ERROR_PREFIX (non
        con la scadenza) e il bersaglio non viene contattato. Stessa tecnica
        di TestFetchBodySizeCap: solo il giudizio di `is_safe_url` è
        sostituito, la logica che lo chiama è quella vera."""
        import shared.utils as u
        self._set_deadline(monkeypatch, 5)
        real_is_safe_url = u.is_safe_url
        blocked_target = "http://internal.invalid/metadata"

        def _fake_is_safe_url(url):
            if url.startswith(blocked_target):
                return False, "simulated internal address (SSRF redirect guard test)"
            return real_is_safe_url(url)

        monkeypatch.setattr(u, "is_safe_url", _fake_is_safe_url)
        srv = drip_server(_sec18_respond(302, "Found", headers=[("Location", blocked_target)]))

        result, _elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1)

        assert result["content"] is None
        assert result["error"] is not None and u.SSRF_REDIRECT_ERROR_PREFIX in result["error"], (
            f"il redirect verso un indirizzo interno doveva essere bloccato dalla guardia "
            f"SSRF ({u.SSRF_REDIRECT_ERROR_PREFIX!r}), ottenuto error={result['error']!r}"
        )

    def test_ssrf_guard_on_direct_url_is_unchanged_with_deadline_active(self, monkeypatch, drip_server):
        """S18-6 — la guardia SSRF sull'URL iniziale resta invariata: con la
        protezione RIATTIVATA, 127.0.0.1 è bloccato con SSRF_ERROR_PREFIX e
        il server non riceve nessuna connessione."""
        import shared.utils as u
        self._set_deadline(monkeypatch, 5)
        monkeypatch.setattr(u, "SSRF_PROTECTION", True)
        srv = drip_server(_sec18_respond(200, "OK", body=b"non deve essere raggiunto"))

        result, _elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1)

        assert result["error"] is not None and result["error"].startswith(u.SSRF_ERROR_PREFIX), (
            f"atteso blocco SSRF diretto ({u.SSRF_ERROR_PREFIX!r}), ottenuto error={result['error']!r}"
        )
        assert result["content"] is None
        assert srv.accept_times == [], "la guardia SSRF doveva bloccare PRIMA di connettersi"

    def test_body_size_cap_is_unchanged_with_deadline_active(self, monkeypatch, drip_server):
        """S18-6 — il cap di SEC-16 resta invariato: un body di 5 KiB con
        `max_bytes=1024` è troncato a esattamente 1024 byte, senza errore,
        anche con la durata massima attiva."""
        self._set_deadline(monkeypatch, 5)
        srv = drip_server(_sec18_respond(200, "OK", body=b"z" * 5120))

        result, _elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1, max_bytes=1024)

        assert result["status_code"] == 200
        assert result["error"] is None
        assert result["content"] is not None and len(result["content"]) == 1024

    # ── S18-7: risorse ────────────────────────────────────────────────

    @pytest.fixture(params=["requests", "urllib"])
    def fetch_branch(self, request, monkeypatch):
        if request.param == "urllib":
            self._force_urllib(monkeypatch)
        return request.param

    def test_after_deadline_no_thread_is_left_and_connection_is_closed(
            self, fetch_branch, monkeypatch, drip_server):
        """S18-7 — risorse: quando la scadenza scatta (precondizione: senza
        di essa «nessun thread / socket chiuso» sarebbe vero per il solo
        fatto che la goccia è finita), dopo il ritorno
        1. il conteggio dei thread torna alla baseline entro 2 s (nessun
           worker abbandonato che continua a leggere la goccia);
        2. il server di prova vede la connessione chiusa (FIN/RST o `send`
           fallita) entro 2 s, mentre la goccia ha ancora diversi secondi da fare.
        Su entrambi i rami (`requests` e `urllib`)."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_body(60, 0.1))      # goccia di 6 s
        baseline = threading.active_count()

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        # Se la scadenza non è scattata, thread e socket «a posto» sarebbero
        # un'osservazione vuota (la goccia è semplicemente finita): si ferma qui.
        assert elapsed <= self.D + self.SLACK, (
            f"SEC-18 / S18-7 (ramo {fetch_branch}): precondizione non soddisfatta, la "
            "scadenza non è scattata e le osservazioni su thread e socket non sarebbero "
            "significative:\n  - " + "\n  - ".join(problems)
        )
        end = time.monotonic() + 2.0
        while threading.active_count() > baseline and time.monotonic() < end:
            time.sleep(0.05)
        extra = threading.active_count() - baseline
        if extra > 0:
            problems.append(
                f"{extra} thread in più rispetto alla baseline ({baseline}) 2 s dopo il "
                f"ritorno: {sorted(t.name for t in threading.enumerate())}"
            )
        if not srv.client_closed.wait(2.0):
            problems.append(
                "il server non ha visto la connessione chiusa entro 2 s dal ritorno "
                "(né FIN/RST né errore di send): il socket del client è rimasto aperto"
            )
        assert not problems, (
            f"SEC-18 / S18-7 (ramo {fetch_branch}), risorse dopo la scadenza:\n  - "
            + "\n  - ".join(problems)
        )

    # ── S18-8: parametro per chiamante ────────────────────────────────

    def test_max_seconds_parameter_overrides_constant_downward(self, drip_server):
        """S18-8 — il parametro `max_seconds` ha precedenza sulla costante
        (qui lasciata al default 40): `max_seconds=0,5` taglia la goccia da 8 s
        entro D + ε. Non patcha la costante di proposito: se il parametro
        fosse ignorato, il limite effettivo sarebbe 40 s."""
        srv = drip_server(_sec18_drip_body(80, 0.1))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1, max_seconds=self.D)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, "SEC-18 / S18-8, max_seconds < costante:\n  - " + "\n  - ".join(problems)

    def test_max_seconds_parameter_overrides_constant_upward(self, monkeypatch, drip_server):
        """S18-8 — precedenza anche verso l'ALTO: con la costante a 0,3 s,
        `max_seconds=2` deve lasciar completare una risposta lenta ma
        legittima di ~0,6 s (è il caso d'uso di un chiamante con host fisso e
        fidato, come crt.sh, che chiede un limite più largo). Un `min()` fra
        parametro e costante non è conforme alla decisione."""
        self._set_deadline(monkeypatch, 0.3)
        srv = drip_server(_sec18_drip_body(8, 0.075))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1, max_seconds=2)

        assert result["error"] is None, (
            f"con max_seconds=2 la risposta da ~0,6 s doveva completare, error={result['error']!r} "
            f"dopo {elapsed:.2f}s: il parametro non ha la precedenza sulla costante (=0,3)"
        )
        assert result["status_code"] == 200
        assert result["content"] == b"a" * 8


# ═══════════════════════════════════════════════════════════════
# SEC-18 — S18-8: interfaccia e configurazione di MAX_FETCH_SECONDS
# ═══════════════════════════════════════════════════════════════

# Eseguito in un SOTTOPROCESSO per ogni valore di env: `shared.utils` è
# importato da tutti i servizi e dalla suite, quindi un `importlib.reload` nel
# processo di test toccherebbe tutti gli importatori. Il figlio importa il
# modulo con l'env indicata, cattura i log WARNING+ (su root, quindi
# indipendentemente dal nome del logger scelto dal fixer) e stampa un JSON.
_SEC18_CHILD = r"""
import json, logging
records = []
class _Collect(logging.Handler):
    def emit(self, record):
        records.append(record.getMessage())
root = logging.getLogger()
root.addHandler(_Collect())
root.setLevel(logging.WARNING)
out = {"import_error": None, "value": None, "warnings": records}
try:
    import shared.utils as u
    out["value"] = getattr(u, "MAX_FETCH_SECONDS", None)
except BaseException as exc:
    out["import_error"] = type(exc).__name__ + ": " + str(exc)
print(json.dumps(out))
"""


def _sec18_import_child(env_updates):
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env.pop("MAX_FETCH_SECONDS", None)
    env["PYTHONPATH"] = repo_root
    env.update(env_updates)
    proc = subprocess.run([sys.executable, "-c", _SEC18_CHILD], cwd=repo_root, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0 and proc.stdout.strip(), (
        f"il sottoprocesso di prova è fallito (codice {proc.returncode}):\n{proc.stderr[-800:]}"
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


class TestSEC18FetchDeadlineConfig:
    """SEC-18 / S18-8 — interfaccia fissata dalla decisione utente e
    comportamento della configurazione `MAX_FETCH_SECONDS` all'import.
    Pattern e contratto del precedente PERF-01 (tests/test_reputation.py,
    `_reputation_reloaded_with_env`): un valore non valido NON impedisce
    l'avvio (`unified.py` importa tutto senza try/except: un typo nell'env
    spegnerebbe l'intera piattaforma), ricade sul default noto-sicuro e lo
    dice in un log WARNING che nomina la variabile."""

    def test_constant_exists_and_is_a_positive_number(self):
        import shared.utils as u
        value = getattr(u, "MAX_FETCH_SECONDS", None)
        assert isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0, (
            f"shared.utils.MAX_FETCH_SECONDS deve esistere ed essere un numero > 0, trovato {value!r}"
        )

    def test_max_seconds_parameter_exists_with_none_default(self):
        """`max_seconds=None` è il segnale «usa la costante, letta a
        runtime»: un default numerico sarebbe bindato all'import e un
        monkeypatch (o un'env cambiata) non avrebbe effetto."""
        import shared.utils as u
        params = inspect.signature(u.http_get_with_retry).parameters
        assert "max_seconds" in params, "http_get_with_retry non ha il parametro `max_seconds`"
        assert params["max_seconds"].default is None, (
            f"`max_seconds` deve avere default None, ha {params['max_seconds'].default!r}"
        )

    def test_deadline_error_prefix_is_a_distinct_recognizable_constant(self):
        """L'errore di scadenza deve essere riconoscibile come i due SSRF e
        non confondibile con loro (`collection_failed` li tratta in modo
        diverso)."""
        import shared.utils as u
        prefix = getattr(u, "FETCH_DEADLINE_ERROR_PREFIX", None)
        assert isinstance(prefix, str) and prefix, (
            "manca shared.utils.FETCH_DEADLINE_ERROR_PREFIX (stringa non vuota)"
        )
        for other in (u.SSRF_ERROR_PREFIX, u.SSRF_REDIRECT_ERROR_PREFIX):
            assert not other.startswith(prefix) and not prefix.startswith(other), (
                f"FETCH_DEADLINE_ERROR_PREFIX ({prefix!r}) non deve essere confondibile con {other!r}"
            )

    def test_default_is_40_seconds_when_env_is_unset(self):
        data = _sec18_import_child({})
        assert data["import_error"] is None, f"import di shared.utils fallito: {data['import_error']}"
        assert data["value"] == 40, (
            f"senza env il default deve essere 40, ottenuto {data['value']!r} "
            "(None = shared.utils.MAX_FETCH_SECONDS non esiste)"
        )
        assert not any("MAX_FETCH_SECONDS" in m for m in data["warnings"]), (
            f"nessun warning atteso con l'env non impostata: {data['warnings']}"
        )

    def test_valid_env_value_is_honoured(self):
        """Controllo di contrasto: l'env è davvero letta (altrimenti i test
        di fallback sotto passerebbero anche con un `40` cablato)."""
        data = _sec18_import_child({"MAX_FETCH_SECONDS": "7"})
        assert data["import_error"] is None, f"import di shared.utils fallito: {data['import_error']}"
        assert data["value"] == 7, (
            f"MAX_FETCH_SECONDS=7 deve essere letta dall'env, ottenuto {data['value']!r}"
        )
        assert not any("MAX_FETCH_SECONDS" in m for m in data["warnings"]), (
            f"nessun warning atteso per un valore valido: {data['warnings']}"
        )

    @pytest.mark.parametrize("raw", ["abc", "0", "-5", "nan", "inf", ""])
    def test_invalid_env_value_falls_back_to_40_with_warning(self, raw):
        """S18-8 — non numerico (`abc`), non positivo (`0`, `-5`), non finito
        (`nan`, `inf`) o stringa vuota (la produce docker-compose con una
        variabile non definita): l'import non solleva, il valore effettivo è
        40 e un log WARNING nomina `MAX_FETCH_SECONDS`. Un 0 o un `nan`
        lasciati passare produrrebbero una scadenza immediata o mai."""
        data = _sec18_import_child({"MAX_FETCH_SECONDS": raw})
        assert data["import_error"] is None, (
            f"MAX_FETCH_SECONDS={raw!r} fa fallire l'import di shared.utils "
            f"(e con esso l'intera piattaforma): {data['import_error']}"
        )
        assert data["value"] == 40, (
            f"MAX_FETCH_SECONDS={raw!r} (non valido) deve ricadere su 40, ottenuto "
            f"{data['value']!r} (None = shared.utils.MAX_FETCH_SECONDS non esiste)"
        )
        assert any("MAX_FETCH_SECONDS" in m for m in data["warnings"]), (
            f"nessun log WARNING che nomini MAX_FETCH_SECONDS per il valore {raw!r}: "
            f"il fallback deve essere osservabile, non silenzioso. Warning visti: {data['warnings']}"
        )


# ═══════════════════════════════════════════════════════════════
# SEC-18 — S18-9: il servizio /http
# ═══════════════════════════════════════════════════════════════

class TestSEC18FetchDeadlineHttpEndpoint(_Sec18Base):
    """SEC-18 / S18-9 — `/http` (services/http_fingerprint.py), zona NON
    autenticata, apre un `ThreadPoolExecutor` con un worker per URL (4 con
    `check_www=True`) e chiama `http_get_with_retry` con i default
    (`max_attempts=3`, `base_delay=2`). Misurato dal researcher (G2): 40 `/http`
    a goccia concorrenti portano `/health` da 0,003 s a 5,74 s, e l'abbandono
    del client lascia +49 thread vivi lato server.

    Qui: TestClient reale su `services.http_fingerprint`, con la costante
    portata a D=0,5 s e un dominio fittizio valido per la regex dell'endpoint
    (`sec18-drip.test`, `www.` incluso) fatto risolvere a 127.0.0.1 con un
    monkeypatch di `socket.getaddrinfo` limitato a quei due host (la porta 80
    è dirottata sul server a goccia, qualunque altra su una porta chiusa).
    I due URL `https://` falliscono SUBITO in locale (connessione rifiutata,
    nessun proxy): non si può servire una goccia TLS senza certificati, e
    questo evita che un handshake muto allunghi la suite di 15 s per
    tentativo. Quindi due URL su quattro sono a goccia; il criterio S18-9
    («risponde entro D + ε») è comunque verificato, perché la risposta del
    servizio attende TUTTI i worker."""

    DOMAIN = "sec18-drip.test"
    SERVICE_SLACK = 1.0     # ε del servizio: JSON + threadpool di anyio (~0,25 s misurati)

    def _call_http_with_dripping_urls(self, monkeypatch, drip_server):
        """Chiama `/http` (domain + www, 4 URL) con i due `http://` a goccia
        (body: 8 s) e i due `https://` su una porta chiusa. Restituisce
        `(resp, elapsed, extra_threads, baseline, thread_names)`, dove
        `extra_threads` è il numero di thread in più rispetto alla baseline
        dopo un polling di 2 s."""
        from fastapi.testclient import TestClient
        from services.http_fingerprint import app

        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_body(80, 0.1))

        closed_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed_probe.bind(("127.0.0.1", 0))
        refused_port = closed_probe.getsockname()[1]
        closed_probe.close()                      # porta libera e chiusa: ECONNREFUSED

        fake_hosts = {self.DOMAIN, f"www.{self.DOMAIN}"}
        real_getaddrinfo = socket.getaddrinfo

        def _fake_getaddrinfo(host, port, *args, **kwargs):
            if host in fake_hosts:
                target = srv.port if str(port) == "80" else refused_port
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", target))]
            return real_getaddrinfo(host, port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

        with TestClient(app) as client:
            client.get("/health")             # avvia portal e worker di anyio PRIMA della baseline
            baseline = threading.active_count()
            t0 = time.monotonic()
            resp = client.get("/http", params={"domain": self.DOMAIN, "check_www": True})
            elapsed = time.monotonic() - t0
            end = time.monotonic() + 2.0
            while threading.active_count() > baseline and time.monotonic() < end:
                time.sleep(0.05)
            extra = threading.active_count() - baseline
            names = sorted(t.name for t in threading.enumerate())
        return resp, elapsed, extra, baseline, names

    def test_http_endpoint_answers_within_deadline_when_http_urls_drip(self, monkeypatch, drip_server):
        """S18-9 — `/http` con gli URL `http://` a goccia (body: 8 s) risponde
        entro D + 1,5 s; i due check a goccia riportano l'errore di scadenza,
        nessun contenuto e nessuno status; i thread interni (executor) si
        liberano entro 2 s dalla risposta."""
        import shared.utils as u

        resp, elapsed, extra, baseline, names = self._call_http_with_dripping_urls(
            monkeypatch, drip_server)

        problems = []
        limit = self.D + self.SERVICE_SLACK
        if elapsed > limit:
            problems.append(
                f"/http ha risposto dopo {elapsed:.2f}s: oltre D + {self.SERVICE_SLACK:g}s = "
                f"{limit:g}s (D={self.D}s) — gli URL a goccia occupano il servizio"
            )
        if resp.status_code != 200:
            problems.append(f"/http ha risposto HTTP {resp.status_code}: {resp.text[:200]!r}")
        else:
            body = resp.json()
            prefix = getattr(u, "FETCH_DEADLINE_ERROR_PREFIX", None)
            plain = [c for c in body["checks"] if c["url"].startswith("http://")]
            if len(plain) != 2:
                problems.append(f"attesi 2 check http:// (domain e www), trovati {len(plain)}")
            for check in plain:
                if not isinstance(prefix, str) or not prefix:
                    problems.append("manca shared.utils.FETCH_DEADLINE_ERROR_PREFIX")
                    break
                if not str(check["error"] or "").startswith(prefix):
                    problems.append(
                        f"{check['url']}: error={check['error']!r} non comincia per "
                        f"{prefix!r} (scadenza non riconoscibile nel check)"
                    )
                if check["content_length"] != 0:
                    problems.append(
                        f"{check['url']}: content_length={check['content_length']} — "
                        "nessun contenuto parziale deve arrivare al check"
                    )
                if check["status_code"] is not None:
                    problems.append(
                        f"{check['url']}: status_code={check['status_code']!r} — allo scadere "
                        "nessuno status parziale deve arrivare al check"
                    )
            if body["overall_status"] == "active":
                problems.append("overall_status='active' costruito su una goccia scaduta")
        if extra > 0:
            problems.append(
                f"{extra} thread in più rispetto alla baseline ({baseline}) 2 s dopo la "
                f"risposta di /http: {names}"
            )

        assert not problems, "SEC-18 / S18-9, /http con URL a goccia:\n  - " + "\n  - ".join(problems)

    def test_http_response_with_expired_deadline_is_recognized_as_collection_failure(
            self, monkeypatch, drip_server):
        """SEC-18 (coordinator, corollario di CODE-15) — la risposta REALE di
        `/http` ottenuta end-to-end con tutti gli URL falliti (due a goccia
        scaduti, due rifiutati) deve essere letta da
        `shared.utils.collection_failed` come «non ho potuto guardare»
        (True). `collection_failed` è il punto unico di verità condiviso da
        `orchestrator._module_failed` (canale alert/baseline, CODE-01) e dal
        classificatore (CODE-15): se anche un solo check conserva uno
        `status_code` (es. il 200 degli header già ricevuti prima che la
        goccia scadesse) il modulo conta come LETTURA REALE, e lo snapshot
        «vuoto ma valido» avvelena la baseline. Stesso schema del test SSRF
        `test_collection_failed_ssrf_recognition_not_hardcoded_duplicate`:
        il consumatore giudica l'output vero del produttore, non una sua
        imitazione scritta a mano."""
        import shared.utils as u

        resp, _elapsed, _extra, _baseline, _names = self._call_http_with_dripping_urls(
            monkeypatch, drip_server)

        assert resp.status_code == 200, f"/http ha risposto HTTP {resp.status_code}: {resp.text[:200]!r}"
        http_dict = resp.json()
        summary = [(c["url"], c["status_code"], c["error"]) for c in http_dict["checks"]]
        assert len(summary) == 4, f"attesi 4 check (http/https x domain/www), trovati: {summary}"
        assert u.collection_failed(http_dict) is True, (
            "collection_failed non riconosce come fallimento di raccolta la risposta di /http "
            "con tutti gli URL falliti o scaduti: un check con status_code valorizzato conta "
            "come lettura reale e la baseline verrebbe avvelenata (CODE-01). "
            f"overall_status={http_dict['overall_status']!r}, check (url, status_code, error)={summary}"
        )


# ═══════════════════════════════════════════════════════════════
# SEC-18 — round 2 (G6 round 1 negativo): connect, TLS, watchdog, max_seconds
# ═══════════════════════════════════════════════════════════════
#
# Fonte: BUG-REGISTER.md, «VERDETTO security-reviewer · SEC-18 · G6»,
# «VERDETTO verifier · SEC-18 · G6 · INSUFFICIENTE» e «ASSEGNA · SEC-18 round
# 2». Contratto aggiunto a quello del round 1:
#
#   * La fase di CONNECT rientra in D: un host con più record A morti (ne
#     decide il numero chi controlla il DNS del lookalike) non può far durare
#     la chiamata N x timeout. Ogni indirizzo va provato col tempo residuo.
#   * L'handshake TLS parte col tempo residuo DOPO il connect, non con il
#     valore fissato a inizio tentativo.
#   * Il watchdog non muore su un socket tracciato privo di `shutdown()` (es.
#     SSLTransport): gli altri socket vengono comunque chiusi. Un
#     `Thread.start()` fallito non fa sollevare `http_get_with_retry`.
#   * `max_seconds` come parametro: stessa regola dell'env. Non finito o <= 0
#     (0, -1, nan, inf) ricade su MAX_FETCH_SECONDS con un warning che nomina
#     `max_seconds`; un valore finito > 0 vince sulla costante.
#   * Allo scadere anche `headers == {}` e `final_url is None` (oltre a
#     content/status None): `_Sec18Base._deadline_problems` li controlla.
#
# INTERFACCIA INTERNA. Alcuni test sono a livello di `shared.utils.
# _FetchDeadline` (costruttore `_FetchDeadline(seconds)`, `.track(conn)` che
# registra `conn.sock` alla successiva `conn.getresponse()`, `.close()`): non
# è API pubblica ma è l'unico punto in cui il watchdog si può provare in modo
# deterministico, senza dipendere da temporizzazioni di rete. Un refactor del
# fix che ne cambi la forma deve aggiornare questi test (non il contrario).
#
# MUTANTI. I test «uccisori» sono verdi sul codice attuale e rossi sul
# mutante che nominano (harness del verifier, /tmp/v18/mut/gen.py). Per
# ognuno il docstring indica il mutante.
#
# CERTIFICATO. L'HTTPS reale usa un certificato autofirmato generato A RUNTIME
# con `openssl` in una directory temporanea di pytest: nessun materiale
# crittografico entra nel repository. Senza `openssl` i test sono saltati.
#
# TEMPI. D piccolo (0,5 s dove basta): il costo dei test nuovi sul codice
# fixato è di ~13 s in totale.
#
# PASSO DELLA GOCCIA. Il timeout per lettura è clampato a D: con D=0,5 s una
# goccia a 0,5 s per byte farebbe scattare il timeout per lettura invece della
# scadenza, e M21/M22 (socket non tracciato) passerebbero lo stesso. Nei test a
# D=0,5 s il passo è quindi 0,1 s (molto sotto D) e la goccia dura 80 passi.


class _Sec18FakeConn:
    """Finta connessione per `_FetchDeadline.track`: espone `sock` e una
    `getresponse` che il watchdog avvolge, come fa con una vera connessione."""

    def __init__(self, sock):
        self.sock = sock

    def getresponse(self, *args, **kwargs):
        return "response"


class _Sec18NoShutdownSock:
    """Socket tracciato SENZA `shutdown()` (come `SSLTransport`, TLS-in-TLS
    via proxy HTTPS): ha solo `fileno()` e `close()`."""

    def __init__(self):
        self.closed = False

    def fileno(self):
        return -1 if self.closed else 987654

    def close(self):
        self.closed = True


def _sec18_noncoop_body(n_bytes, delay):
    """Server NON cooperativo: dichiara `Content-Length: n_bytes` e manda un
    byte ogni `delay` secondi IGNORANDO FIN/RST e gli errori di `send`, fino
    alla fine della goccia (o del teardown). Chi chiude solo la metà in
    scrittura (SHUT_WR) non lo interrompe: serve `shutdown(SHUT_RDWR)`."""
    def handler(srv, conn, path):
        try:
            conn.sendall(_sec18_head(200, "OK", [("Content-Length", str(n_bytes))]))
        except OSError:
            return
        for _ in range(n_bytes):
            if srv.stop.wait(delay):
                return
            try:
                conn.sendall(b"a")
            except OSError:
                pass            # ignora il client che se n'è andato e prosegue
    return handler


def _sec18_tls_handshake_drip(srv, conn, path):
    """Server TLS che non completa mai l'handshake: legge il ClientHello,
    risponde con l'intestazione di un record da 16 KiB e poi 1 byte ogni
    0,3 s. Ogni singola `recv` del client riceve dati in tempo."""
    try:
        ready, _, _ = select.select([conn], [], [], 3)
        if ready:
            conn.recv(65536)
    except (OSError, ValueError):
        return
    if not srv.send(conn, b"\x16\x03\x03\x40\x00"):
        return
    for _ in range(200):
        if srv.wait(conn, 0.3) or not srv.send(conn, b"\x02"):
            return


def _sec18_redirect_then_503_then_drip(state):
    """`/start` -> 302 -> `/busy`. La PRIMA volta `/busy` risponde 503
    completo e subito (con un header riconoscibile); dalla seconda in poi il
    503 arriva a goccia. Con `max_attempts >= 2` il primo tentativo lascia in
    `result` status, headers e `final_url`; la scadenza che interrompe il
    secondo li deve azzerare tutti."""
    def handler(srv, conn, path):
        if path == "/start":
            srv.send(conn, _sec18_head(302, "Found", [
                ("Location", f"http://127.0.0.1:{srv.port}/busy"),
                ("Content-Length", "0"), ("X-Stale", "start")]))
        elif path == "/busy":
            state["busy"] += 1
            if state["busy"] == 1:
                srv.send(conn, _sec18_head(503, "Service Unavailable", [
                    ("Content-Length", "2"), ("X-Stale", "busy")]) + b"ko")
            else:
                _sec18_drip_body(40, 0.1, status=503, reason="Service Unavailable")(srv, conn, path)
    return handler


@pytest.fixture(scope="module")
def sec18_blackhole():
    """Porta di un listener con accept queue piena (backlog=1, filler non
    accettati): ogni connect verso di essa resta appeso fino al proprio
    timeout. Saltato se la piattaforma non lo simula. Di modulo e non di
    classe per essere condiviso e creato una volta sola."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    fillers = []
    for _ in range(4):
        filler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        filler.setblocking(False)
        try:
            filler.connect(("127.0.0.1", port))
        except BlockingIOError:
            pass
        fillers.append(filler)
    time.sleep(0.3)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.3)
    try:
        probe.connect(("127.0.0.1", port))
        simulated = False
    except OSError:
        simulated = True
    finally:
        probe.close()
    if not simulated:
        for sock in fillers + [listener]:
            sock.close()
        pytest.skip("accept queue piena non simulabile su questa piattaforma")
    yield port
    for sock in fillers + [listener]:
        sock.close()


@pytest.fixture(scope="module")
def sec18_tls_context(tmp_path_factory):
    """Contesto TLS lato server con un certificato autofirmato valido un
    giorno, generato qui con `openssl` in una directory temporanea di pytest
    (mai nel repository). Saltato se `openssl` non c'è."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl non disponibile: nessun certificato autofirmato generabile")
    workdir = tmp_path_factory.mktemp("sec18_tls")
    key_file, cert_file = workdir / "server.key", workdir / "server.crt"
    proc = subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
         "-days", "1", "-keyout", str(key_file), "-out", str(cert_file)],
        capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        pytest.skip(f"openssl non ha generato il certificato: {proc.stderr[-200:]}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_file), str(key_file))
    return context


class TestSEC18Round2ConnectPhase(_Sec18Base):
    """SEC-18 round 2 — BLOCCANTE del verifier (converge con il rilievo 1 del
    security-reviewer): la fase di connect non è limitata da D quando l'host
    ha più record A. urllib3 e `socket.create_connection` provano OGNI
    indirizzo restituito da `getaddrinfo` col timeout intero, e `clamp` lo
    calcola una volta sola: con D=2 si misurano 8,01 s per 4 indirizzi morti
    e 16,01 s per 8; con i parametri reali di `/http` (timeout=15, D=40, 5
    record morti) 75 s. Il numero di record lo decide chi controlla il DNS
    del proprio lookalike, per definizione dell'attaccante.

    I «record morti» sono un listener con accept queue piena (backlog=1 e
    filler non accettati): il SYN è scartato e il connect resta appeso fino
    al proprio timeout, senza rete reale. Se la piattaforma non si comporta
    così il test è saltato. Il watchdog NON può aiutare qui: durante il
    connect il socket non è ancora raggiungibile."""

    D = 0.5
    DEAD_ADDRESSES = 5

    def _resolve_all_to(self, monkeypatch, host, addresses):
        """`getaddrinfo(host)` restituisce tutti gli `addresses` (ip, porta),
        ignorando la porta richiesta; ogni altro host passa al resolver vero."""
        real_getaddrinfo = socket.getaddrinfo

        def _fake_getaddrinfo(name, port, *args, **kwargs):
            if name == host:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", addr) for addr in addresses]
            return real_getaddrinfo(name, port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    def test_many_dead_addresses_are_cut_at_deadline(self, branch, monkeypatch, sec18_blackhole):
        """BLOCCANTE — 5 record A che non completano il connect, D=0,5 s e
        `timeout=10`: la chiamata torna entro D + ε con errore di scadenza,
        status e content None, su entrambi i rami. Oggi dura ~5 x D: ogni
        indirizzo riceve il timeout intero (clamp calcolato una volta sola)."""
        self._set_deadline(monkeypatch, self.D)
        self._resolve_all_to(monkeypatch, "multi.test", [("127.0.0.1", sec18_blackhole)] * self.DEAD_ADDRESSES)

        result, elapsed, _t0 = self._fetch(
            "http://multi.test/", timeout=10, max_attempts=3, base_delay=0.5)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, (
            f"SEC-18 round 2 / più record A (ramo {branch}):\n  - " + "\n  - ".join(problems))

    def test_single_dead_address_is_cut_at_deadline(self, branch, monkeypatch, sec18_blackhole):
        """Uccisore di M01 (clamp assente nel ramo `requests`), M02 (clamp
        assente nel ramo `urllib`) e M03 (`clamp` senza `min`, cioè
        `return timeout`): UN solo indirizzo morto, D=0,5 s, `timeout=10`. Il
        connect non è interrompibile dal watchdog, quindi lo ferma solo il
        timeout clampato al tempo residuo. Verde oggi; senza `clamp` dura 10 s."""
        self._set_deadline(monkeypatch, self.D)

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{sec18_blackhole}/", timeout=10, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, (
            f"SEC-18 round 2 / un indirizzo morto (ramo {branch}):\n  - " + "\n  - ".join(problems))

    def test_slow_connect_then_tls_handshake_drip_is_cut_at_deadline(self, branch, monkeypatch, drip_server):
        """Connect lento seguito da handshake TLS a goccia (`e11` del
        verifier, +4,1 s misurati). Il connect impiega 0,9 s con D=1 s, poi il
        server manda un record TLS da 16 KiB a 1 byte ogni 0,3 s, senza mai
        completare l'handshake. CPython applica il timeout del socket
        all'INTERO handshake, ma oggi quel timeout è quello fissato a inizio
        tentativo (1 s) e non il residuo dopo il connect (0,1 s): la chiamata
        dura 0,9 + 1 = 1,9 s. Deve tornare entro D + 0,5 s (soglia 1,5 s:
        verde ~1,0 s, rosso ~1,9 s). Il connect
        lento è simulato in modo deterministico: `socket.socket.connect` dorme
        rispettando il timeout del socket, senza dipendere dalle
        ritrasmissioni SYN del kernel."""
        deadline_s = 1.0
        connect_delay = 0.9
        self._set_deadline(monkeypatch, deadline_s)
        srv = drip_server(_sec18_tls_handshake_drip, raw=True)
        original_connect = socket.socket.connect

        def _slow_connect(sock, address):
            if isinstance(address, tuple) and len(address) >= 2 and address[1] == srv.port:
                limit = sock.gettimeout()
                if limit is not None and limit < connect_delay:
                    time.sleep(limit)
                    raise socket.timeout("timed out")
                time.sleep(connect_delay)
            return original_connect(sock, address)

        monkeypatch.setattr(socket.socket, "connect", _slow_connect)

        result, elapsed, _t0 = self._fetch(
            f"https://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1, verify_ssl=False)

        problems = self._deadline_problems(result, elapsed, limit=deadline_s, slack=0.5)
        assert not problems, (
            f"SEC-18 round 2 / connect lento + handshake a goccia (ramo {branch}):\n  - "
            + "\n  - ".join(problems))


class TestSEC18Round2RealHttps(_Sec18Base):
    """SEC-18 round 2 — HTTPS REALE. In produzione 2 URL su 4 di `/http` e
    crt.sh sono HTTPS, ma il round 1 non aveva nessun test TLS: i mutanti
    M21 (manca il mount `https://` dell'adapter di `requests`) e M22 (handler
    HTTPS di `urllib` non tracciato) davano 9,1 s invece di 2,0 s a suite
    verde. Qui un server TLS vero (certificato autofirmato generato a runtime
    con `openssl`, `verify_ssl=False`) serve body e header a goccia, su
    entrambi i rami. Verdi oggi; M21 uccide i test del ramo `requests`, M22
    quelli del ramo `urllib`."""

    D = 0.5

    def test_https_trickled_body_is_cut_at_deadline(self, branch, monkeypatch, drip_server, sec18_tls_context):
        """Body a goccia (80 byte, 8 s) su `https://`, D=0,5 s: limite rispettato anche
        con TLS completato. M21/M22: senza il tracciamento del socket TLS la
        goccia dura fino in fondo."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_body(80, 0.1), ssl_context=sec18_tls_context)

        result, elapsed, _t0 = self._fetch(
            f"https://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1, verify_ssl=False)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, (
            f"SEC-18 round 2 / HTTPS reale, body a goccia (ramo {branch}):\n  - " + "\n  - ".join(problems))

    def test_https_trickled_headers_are_cut_at_deadline(self, branch, monkeypatch, drip_server, sec18_tls_context):
        """Header a goccia (8 s) su `https://`, D=0,5 s: la risposta non è
        ancora tornata a `requests.get`/`urlopen` quando scatta la scadenza."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_headers(80, 0.1), ssl_context=sec18_tls_context)

        result, elapsed, _t0 = self._fetch(
            f"https://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1, verify_ssl=False)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, (
            f"SEC-18 round 2 / HTTPS reale, header a goccia (ramo {branch}):\n  - " + "\n  - ".join(problems))


class TestSEC18Round2Watchdog(_Sec18Base):
    """SEC-18 round 2 — robustezza del watchdog (`_FetchDeadline`), rilievi
    BASSI del security-reviewer e del verifier. Sono difetti INTRODOTTI dal
    diff di SEC-18, non preesistenti: il limite non deve fallire aperto.
    Questi test usano l'interfaccia interna `_FetchDeadline(seconds)`,
    `.track(conn)` e `.close()` (vedi il blocco di contratto): un socket
    finto si registra con `track(conn)` e `conn.getresponse()`."""

    D = 0.5

    @staticmethod
    def _register(deadline, sock):
        conn = _Sec18FakeConn(sock)
        deadline.track(conn)
        conn.getresponse()

    def test_watchdog_survives_a_tracked_socket_without_shutdown(self):
        """Rilievo BASSO: un socket tracciato privo di `shutdown()` (oggetto
        finto, o `SSLTransport`) faceva sollevare `AttributeError` al
        watchdog, che moriva in silenzio: il limite falliva aperto. Qui il
        socket senza `shutdown` è registrato PRIMA di uno vero: il vero deve
        essere chiuso comunque (l'altro estremo vede EOF) entro 1,5 s dalla
        scadenza di 0,2 s."""
        import shared.utils as u
        real, peer = socket.socketpair()
        peer.settimeout(1.5)
        deadline = u._FetchDeadline(0.2)
        try:
            self._register(deadline, _Sec18NoShutdownSock())
            self._register(deadline, real)
            try:
                data = peer.recv(1)
            except socket.timeout:
                data = None
        finally:
            deadline.close()
            real.close()
            peer.close()
        assert data == b"", (
            "il watchdog non ha chiuso il socket vero registrato dopo uno privo di "
            f"shutdown(): recv ha dato {data!r} (None = nessun EOF entro 1,5 s). Il thread "
            "del watchdog è morto sul primo socket e il limite ha fallito aperto."
        )

    def test_call_returns_at_deadline_when_a_tracked_socket_has_no_shutdown(self, monkeypatch, drip_server):
        """Stesso rilievo, end-to-end: a ogni chiamata si registra per primo
        un socket senza `shutdown()`, poi il socket vero di un body a goccia
        (8 s). Con D=0,5 s la chiamata deve tornare entro D + ε."""
        import shared.utils as u
        self._set_deadline(monkeypatch, self.D)
        original_track = u._FetchDeadline.track
        poisoned = set()

        def _track_with_poison(deadline, conn):
            if id(deadline) not in poisoned:
                poisoned.add(id(deadline))
                self._register(deadline, _Sec18NoShutdownSock())
            return original_track(deadline, conn)

        monkeypatch.setattr(u._FetchDeadline, "track", _track_with_poison)
        srv = drip_server(_sec18_drip_body(80, 0.1))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, (
            "SEC-18 round 2 / socket senza shutdown() tracciato:\n  - " + "\n  - ".join(problems))

    def test_socket_registered_after_the_deadline_fired_is_still_closed(self):
        """Uccisore di M15 (polling del watchdog assente: un solo passaggio
        alla scadenza). Un socket registrato in ritardo (connect o handshake
        terminati oltre il limite, `e13_late_reg.py` del verifier) non deve
        poter ripartire con una nuova goccia: il watchdog continua a chiudere
        anche dopo lo scatto. Qui la scadenza (0,15 s) è già scattata e il
        primo passaggio è fatto quando il socket si registra; l'altro estremo
        deve vedere EOF entro 1,5 s. Verde oggi."""
        import shared.utils as u
        late, peer = socket.socketpair()
        peer.settimeout(1.5)
        deadline = u._FetchDeadline(0.15)
        try:
            time.sleep(0.3)                       # scadenza scattata, primo passaggio fatto
            self._register(deadline, late)
            try:
                data = peer.recv(1)
            except socket.timeout:
                data = None
        finally:
            deadline.close()
            late.close()
            peer.close()
        assert data == b"", (
            "un socket registrato DOPO lo scatto del watchdog non è stato chiuso "
            f"(recv ha dato {data!r}; None = nessun EOF entro 1,5 s): manca il polling "
            "dopo la scadenza (M15)."
        )

    def test_thread_start_failure_returns_an_error_dict(self, monkeypatch):
        """INFO del security-reviewer: se il thread del watchdog non parte
        (`RuntimeError: can't start new thread`, es. limite di thread del
        container) `http_get_with_retry` sollevava, mentre il contratto di
        tutti i chiamanti (`/http`, crt.sh) è un dict con `error`. Porta
        chiusa: anche un ripiego senza watchdog termina subito."""
        import shared.utils as u
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        def _failing_start(thread):
            raise RuntimeError("can't start new thread")

        monkeypatch.setattr(threading.Thread, "start", _failing_start)
        try:
            result = u.http_get_with_retry(
                f"http://127.0.0.1:{closed_port}/", timeout=2, max_attempts=1)
        except RuntimeError as exc:
            pytest.fail(f"http_get_with_retry ha sollevato RuntimeError invece di restituire un dict: {exc}")

        assert isinstance(result, dict)
        assert isinstance(result["error"], str) and result["error"], (
            f"atteso un errore esplicito nel dict, ottenuto error={result['error']!r}")
        assert result["content"] is None
        assert result["status_code"] is None

    @pytest.mark.parametrize("branch_name", ["requests", "urllib"])
    def test_server_ignoring_fin_is_cut_at_deadline(self, branch_name, monkeypatch, drip_server):
        """Uccisore di M27 (`SHUT_WR` al posto di `SHUT_RDWR`, `e15_noncoop.py`
        del verifier: 12 s contro un server non cooperativo). Il server
        ignora FIN/RST e continua a mandare un byte ogni 0,1 s per 6 s: se il
        watchdog chiude solo la metà in scrittura, la `recv` del chiamante
        non si sveglia e la goccia dura fino in fondo. Gli altri test non lo
        vedono perché i loro server, vedendo il FIN, smettono di mandare.
        Verde oggi; entrambi i rami."""
        if branch_name == "urllib":
            self._force_urllib(monkeypatch)
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_noncoop_body(60, 0.1))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, (
            f"SEC-18 round 2 / server non cooperativo (ramo {branch_name}):\n  - " + "\n  - ".join(problems))

    def test_exception_path_backoff_is_bounded_by_deadline(self, monkeypatch):
        """Uccisore di M05 (backoff del ramo ECCEZIONE non limitato). Porta
        chiusa: il connect fallisce subito con un'eccezione, il backoff
        successivo è 5 s ma D=0,5 s. Il test del backoff del round 1 copre
        solo il ramo 503; qui l'eccezione passa dal blocco `except`. Deve
        tornare entro D + ε con la scadenza, non dopo 5 s. Verde oggi."""
        self._set_deadline(monkeypatch, self.D)
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{closed_port}/", timeout=5, max_attempts=2, base_delay=5)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, (
            "SEC-18 round 2 / backoff del ramo eccezione:\n  - " + "\n  - ".join(problems))

    def test_deadline_clears_headers_and_final_url_of_a_previous_attempt(self, monkeypatch, drip_server):
        """Uccisore di M12 (`headers` non azzerati) e M13 (`final_url` non
        azzerato). Il primo tentativo segue un redirect `/start` -> `/busy` e
        riceve un 503 completo: `result` conserva status, headers e
        `final_url`. Il secondo, a goccia, viene interrotto da D=0,4 s: la
        scadenza deve restituire headers `{}` e `final_url` None (oltre a
        status e content None), non gli avanzi del primo. Verde oggi."""
        self._set_deadline(monkeypatch, 0.4)
        srv = drip_server(_sec18_redirect_then_503_then_drip({"busy": 0}))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/start", timeout=10, max_attempts=2, base_delay=0.1)

        problems = self._deadline_problems(result, elapsed, limit=0.4)
        assert not problems, (
            "SEC-18 round 2 / avanzi del tentativo precedente:\n  - " + "\n  - ".join(problems))


class TestSEC18Round2MaxSeconds(_Sec18Base):
    """SEC-18 round 2 — `max_seconds` come parametro, DECISIONE del
    coordinator: stessa regola dell'env `MAX_FETCH_SECONDS`. Un valore non
    finito o <= 0 (0, -1, nan, inf) ricade sulla costante `MAX_FETCH_SECONDS`
    con un warning che nomina `max_seconds`; un valore finito > 0 vince sulla
    costante (già fissato dal round 1).

    Oggi 0, negativo e `nan` danno una scadenza IMMEDIATA (la chiamata torna
    in pochi ms con l'errore di scadenza, senza provare la richiesta) e `inf`
    toglie il limite del tutto."""

    D = 0.5

    @pytest.mark.parametrize("invalid", [0, -1, float("nan"), float("inf")], ids=["zero", "negative", "nan", "inf"])
    def test_invalid_max_seconds_falls_back_to_the_constant_with_a_warning(
            self, invalid, monkeypatch, drip_server, caplog):
        """Con `MAX_FETCH_SECONDS` a 0,5 s e `max_seconds` non valido su una
        goccia da 4 s, la chiamata NON torna subito ma a ~0,5 s (il default),
        con l'errore di scadenza, e un log WARNING nomina `max_seconds`.
        Uccide anche M18 (`max_seconds or MAX_FETCH_SECONDS`): ricade sul
        default per `0` ma senza warning, e `nan`/`-1` restano truthy."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_body(40, 0.1))

        with caplog.at_level(logging.WARNING):
            result, elapsed, _t0 = self._fetch(
                f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1, max_seconds=invalid)

        problems = self._deadline_problems(result, elapsed)
        if elapsed < self.D * 0.7:
            problems.append(
                f"la chiamata è tornata dopo {elapsed:.2f}s, quasi subito: il valore non valido "
                f"max_seconds={invalid!r} è stato preso come scadenza immediata invece di ricadere "
                f"su MAX_FETCH_SECONDS ({self.D}s)")
        if not any(record.levelno >= logging.WARNING and "max_seconds" in record.getMessage()
                   for record in caplog.records):
            problems.append(
                f"nessun log WARNING che nomini max_seconds per il valore {invalid!r}: il "
                "fallback deve essere osservabile, non silenzioso. Log visti: "
                f"{[r.getMessage() for r in caplog.records]}")
        assert not problems, (
            f"SEC-18 round 2 / max_seconds={invalid!r}:\n  - " + "\n  - ".join(problems))

    def test_huge_finite_max_seconds_is_accepted_without_errors(self, monkeypatch, drip_server):
        """Uccisore di M20 (niente `TIMEOUT_MAX` nel watchdog). Con la nuova
        regola `1e300` è finito > 0, quindi valido e senza limite pratico:
        su una risposta veloce la chiamata restituisce la risposta e NESSUN
        thread solleva. Senza il tetto `threading.TIMEOUT_MAX`
        `Event.wait(1e300)` solleva `OverflowError` nel thread del watchdog,
        che muore in silenzio (qui intercettato con `threading.excepthook`).
        Verde oggi."""
        errors = []
        monkeypatch.setattr(threading, "excepthook", lambda args: errors.append(args.exc_value))
        srv = drip_server(_sec18_respond(200, "OK", body=b"ok"))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=10, max_attempts=1, max_seconds=1e300)

        assert result["error"] is None, f"errore inatteso con max_seconds=1e300: {result['error']!r}"
        assert result["status_code"] == 200
        assert result["content"] == b"ok"
        assert not errors, (
            f"un thread ha sollevato con max_seconds=1e300 (atteso nessuno): {errors!r}")


class TestSEC18Round2TimeoutNone(_Sec18Base):
    """SEC-18 round 2 — regressione introdotta dal round 1 e dichiarata dal
    fixer: `http_get_with_retry(url, timeout=None, ...)` fallisce SEMPRE con
    `'<' not supported between instances of 'float' and 'NoneType'`
    (`_FetchDeadline.clamp` fa `min(timeout, residuo)` con `timeout=None`),
    su entrambi i rami. Prima del diff `timeout=None` voleva dire «nessun
    limite per singola operazione» e la richiesta funzionava.

    Contratto da ripristinare: con `timeout=None` la richiesta funziona e il
    limite di durata (`max_seconds` / `MAX_FETCH_SECONDS`) vale lo stesso: è
    proprio il caso in cui nessun timeout per lettura ferma una goccia, quindi
    il watchdog è l'unica difesa.

    `max_attempts=1` è voluto: con i tentativi di default il TypeError del
    primo tentativo viene ritentato dopo il backoff (che `deadline.sleep`
    limita al residuo), il secondo tentativo trova la scadenza e il risultato
    sembrerebbe una scadenza regolare a ~D: la regressione resterebbe mascherata."""

    def test_timeout_none_on_a_fast_response_works(self, branch, monkeypatch, drip_server):
        """`timeout=None` su una risposta veloce: status 200, content
        completo, `error` None. Oggi la richiesta non parte nemmeno: la
        chiamata torna in pochi ms con il TypeError nell'`error`."""
        self._set_deadline(monkeypatch, self.D)
        body = b"<html><body>timeout none</body></html>"
        srv = drip_server(_sec18_respond(200, "OK", body=body))

        result, _elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=None, max_attempts=1)

        assert result["error"] is None, (
            f"timeout=None deve funzionare (ramo {branch}), ottenuto error={result['error']!r}")
        assert result["status_code"] == 200
        assert result["content"] == body

    def test_timeout_none_still_honours_the_deadline_on_a_trickled_body(self, branch, monkeypatch, drip_server):
        """`timeout=None` su un body a goccia (8 s) con D=0,5 s: nessun timeout
        per lettura, quindi solo il watchdog può fermare la goccia. Deve
        tornare entro D + ε con l'errore di scadenza, status e content None.
        Oggi è rosso per un motivo DIVERSO dalla durata: la chiamata torna
        subito (~0 s) con il TypeError al posto dell'errore di scadenza."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_body(80, 0.1))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=None, max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, (
            f"SEC-18 round 2 / timeout=None + body a goccia (ramo {branch}):\n  - "
            + "\n  - ".join(problems))


class TestSEC18Round3(_Sec18Base):
    """SEC-18 round 3 (opzione A scelta dall'utente dopo il secondo G6
    negativo, `VERDETTO verifier · SEC-18 round 2`).

    1. Contratto di `timeout` sul ramo `requests`: una tupla `(connect, read)`
       e un `urllib3.util.Timeout(connect=..., read=...)` funzionavano su HEAD
       (200) e dopo il round 1 falliscono con `'<' not supported between
       instances of 'float' and 'tuple'` in `_FetchDeadline.clamp`: è la
       stessa classe di `timeout=None` (`TestSEC18Round2TimeoutNone`).
       Contratto: ogni componente è limitato al tempo residuo, la richiesta
       funziona e il limite di durata vale lo stesso. `max_attempts=1` come
       in `TimeoutNone`, per non mascherare l'errore con i retry. Sul ramo
       `urllib` tupla e `Timeout` fallivano già su HEAD: lì NON si fissa
       nessun contratto, un solo test documenta che non si solleva.
    2. Ricalcolo del connect PER INDIRIZZO nel regime di produzione
       (`timeout` < D, es. `/http`: timeout=15, D=40): uccide N01b, il
       mutante di `create_connection` con `clamp` calcolato una volta sola.
       I test del round 2 usano `timeout=10` > D=0,5, dove il clamp iniziale
       coincide con il residuo e il mutante sopravvive.

    Costo contenuto (suite al limite dei 90 s): D=0,5-0,75 s, ~2,5 s in totale."""

    D = 0.5

    @staticmethod
    def _resolve_all_to(monkeypatch, host, addresses):
        """`getaddrinfo(host)` restituisce tutti gli `addresses` (ip, porta),
        ignorando la porta richiesta; ogni altro host passa al resolver vero."""
        real_getaddrinfo = socket.getaddrinfo

        def _fake_getaddrinfo(name, port, *args, **kwargs):
            if name == host:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", addr) for addr in addresses]
            return real_getaddrinfo(name, port, *args, **kwargs)

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)

    @staticmethod
    def _timeout_value(kind):
        import urllib3
        if kind == "tuple":
            return (3, 5)
        return urllib3.Timeout(connect=3, read=5)

    # ── 1. tupla e urllib3.Timeout sul ramo requests ──────────────────

    @pytest.mark.parametrize("kind", ["tuple", "urllib3_timeout"])
    def test_requests_branch_accepts_tuple_and_timeout_object_on_a_fast_response(
            self, kind, monkeypatch, drip_server):
        """(a) Come su HEAD: 200, content completo, `error` None. Oggi rosso:
        `clamp` fa `min(timeout, residuo)` con una tupla / un `Timeout` e
        solleva TypeError, quindi la richiesta non parte."""
        self._set_deadline(monkeypatch, self.D)
        body = b"<html><body>timeout composto</body></html>"
        srv = drip_server(_sec18_respond(200, "OK", body=body))

        result, _elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=self._timeout_value(kind), max_attempts=1)

        assert result["error"] is None, (
            f"timeout={kind} deve funzionare come su HEAD, ottenuto error={result['error']!r}")
        assert result["status_code"] == 200
        assert result["content"] == body

    @pytest.mark.parametrize("kind", ["tuple", "urllib3_timeout"])
    def test_requests_branch_tuple_and_timeout_object_are_still_bounded_by_the_deadline(
            self, kind, monkeypatch, drip_server):
        """(b) Con `connect=3` e `read=5` molto sopra D=0,5 s, su un body a
        goccia (8 s a 0,1 s per byte) la scadenza deve valere comunque: entro
        D + ε, errore di scadenza, status/content/headers/final_url
        azzerati. Oggi rosso per un motivo DIVERSO dalla durata: la chiamata
        torna subito col TypeError al posto dell'errore di scadenza."""
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_drip_body(80, 0.1))

        result, elapsed, _t0 = self._fetch(
            f"http://127.0.0.1:{srv.port}/", timeout=self._timeout_value(kind), max_attempts=1)

        problems = self._deadline_problems(result, elapsed)
        assert not problems, (
            f"SEC-18 round 3 / timeout={kind} + body a goccia:\n  - " + "\n  - ".join(problems))

    @pytest.mark.parametrize("kind", ["tuple", "urllib3_timeout"])
    def test_urllib_branch_tuple_and_timeout_object_never_raise(self, kind, monkeypatch, drip_server):
        """Ramo `urllib`: tupla e `Timeout` fallivano già su HEAD (`urlopen`
        vuole un numero) e NON si fissa un contratto. Questo test documenta
        solo l'invariante di HEAD: nessuna eccezione esce da
        `http_get_with_retry`, e se la richiesta non riesce il dict porta un
        `error` esplicito. Non impedisce a un fix futuro di far funzionare
        il ramo (200 è ammesso)."""
        self._force_urllib(monkeypatch)
        self._set_deadline(monkeypatch, self.D)
        srv = drip_server(_sec18_respond(200, "OK", body=b"ok"))

        try:
            result, _elapsed, _t0 = self._fetch(
                f"http://127.0.0.1:{srv.port}/", timeout=self._timeout_value(kind), max_attempts=1)
        except Exception as exc:
            pytest.fail(f"http_get_with_retry ha sollevato {type(exc).__name__} sul ramo urllib "
                        f"con timeout={kind}: {exc}")

        assert isinstance(result, dict)
        if result["status_code"] is None:
            assert isinstance(result["error"], str) and result["error"], (
                f"richiesta non riuscita ma nessun errore nel dict: {result!r}")
            assert result["content"] is None

    # ── 2. ricalcolo per indirizzo con timeout < D (uccisore di N01b) ──

    def test_connect_timeout_is_recomputed_per_address_when_timeout_is_below_the_deadline(
            self, branch, monkeypatch, sec18_blackhole):
        """Uccisore di N01b (`create_connection` con `clamp` calcolato una
        volta sola, fuori dal ciclo): regime di produzione, `timeout` < D. Con
        5 indirizzi morti, D=0,75 s e `timeout=0,7` s il primo indirizzo
        consuma 0,7 s e il secondo deve ricevere solo il residuo (0,05 s):
        totale ~0,75 s. Con il timeout calcolato una volta il secondo riceve
        di nuovo 0,7 s e la chiamata dura ~1,4 s. Limite D + 0,3 s (soglia
        1,05 s: verde ~0,75 s, N01b ~1,4 s). Verde oggi, su entrambi i rami."""
        deadline_s, per_attempt = 0.75, 0.7
        self._set_deadline(monkeypatch, deadline_s)
        self._resolve_all_to(monkeypatch, "multi.test", [("127.0.0.1", sec18_blackhole)] * 5)

        result, elapsed, _t0 = self._fetch(
            "http://multi.test/", timeout=per_attempt, max_attempts=1)

        problems = self._deadline_problems(result, elapsed, limit=deadline_s, slack=0.3)
        assert not problems, (
            f"SEC-18 round 3 / ricalcolo per indirizzo, timeout < D (ramo {branch}):\n  - "
            + "\n  - ".join(problems))


# ═══════════════════════════════════════════════════════════════
# SEC-24 + SEC-21 — guardia sull'IP effettivamente contattato
# ═══════════════════════════════════════════════════════════════
#
# Fonte: BUG-REGISTER.md, «SEC-24 + SEC-21 — apertura» e «ASSEGNA · SEC-24+SEC-21
# · criteri fissati» (C1…C8). INTERVENTO DIFENSIVO: si aggiunge una guardia
# sull'IP passato a `connect` dentro `_FetchDeadline.create_connection` e si
# chiudono le lacune di `_is_blocked_ip`. Questi test verificano la guardia, non
# costruiscono attacchi:
#
#   * nessuna connessione reale verso indirizzi interni: `socket.getaddrinfo` è
#     simulato e `socket.socket.connect` è sostituito da uno SPY che registra
#     l'indirizzo e solleva subito `ConnectionRefusedError`;
#   * per i casi «pubblici» (C4, hop iniziale, proxy) l'indirizzo fittizio è
#     mappato dallo spy sul server locale già usato dagli altri test SEC-18: la
#     connessione reale va sempre e solo al loopback;
#   * asserzione centrale: lo spy non vede MAI un `connect` verso un indirizzo
#     bloccato (insieme dichiarato dal test + `_is_blocked_ip`).
#
# CONTRATTO per il fixer:
#   * un indirizzo bloccato → nessun `connect` e `result["error"]` che COMINCIA
#     per `SSRF_ERROR_PREFIX` o `SSRF_REDIRECT_ERROR_PREFIX` (stessa semantica di
#     `http_get_with_retry`: URL iniziale / hop di redirect; i test accettano
#     l'uno o l'altro). Il blocco è TERMINALE (`attempts == 1`, niente retry) e
#     status/content restano None.
#   * semantica «uno bloccato blocca tutto» (come `is_safe_url`): se anche uno
#     solo degli indirizzi di `getaddrinfo` è bloccato, nessun `connect` verso
#     l'host, nemmeno verso gli indirizzi pubblici, e in qualunque ordine.
#   * guardia attiva solo con `SSRF_PROTECTION`; la connessione al proxy da env
#     NON è bloccata (proxy fidato, gap dichiarato e accorpato a SEC-23).
#   * `_is_blocked_ip`: blocca 100.64.0.0/10 e 192.88.99.0/24, valuta l'IPv4
#     incapsulato di un indirizzo mappato (`::ffff:a.b.c.d`) con lo stesso esito
#     su ogni versione di Python, nessun falso positivo sui pubblici.
#   * IPv6: il sandbox può non avere socket AF_INET6; il resolver finto usa
#     allora l'etichetta AF_INET con lo stesso indirizzo testuale (la guardia
#     legge l'indirizzo, non la famiglia).


def _sec24_ipv6_sockets_available():
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close()
        return True
    except OSError:
        return False


class TestSEC24ConnectTimeIpGuard(_Sec18Base):
    """SEC-24 + SEC-21 — `is_safe_url` valida un NOME (`urlparse().hostname`),
    ma `create_connection` risolve di nuovo e fa `connect` su qualunque
    indirizzo restituisca: nessun controllo sull'IP contattato (SEC-21,
    rebinding DNS fra guardia e connessione) e, per un `Location` costruito ad
    arte, il parser della guardia e quello della connessione possono divergere
    (SEC-24). La correzione controlla l'IP effettivo, dentro
    `_FetchDeadline.create_connection`, su entrambi i rami e a ogni hop.

    `_Sec18Base._local_network_only` disattiva la guardia SSRF: qui è
    sovrascritta e la guardia resta ATTIVA. Dove si vuole verificare il solo
    controllo al `connect`, la guardia per nome `is_safe_url` è resa
    permissiva nel test (monkeypatch)."""

    PUBLIC_IP = "93.184.216.34"      # indirizzo pubblico di documentazione

    BLOCKED_CASES = [
        pytest.param("127.0.0.1", id="loopback"),
        pytest.param("10.0.0.5", id="rfc1918"),
        pytest.param("169.254.169.254", id="link_local_metadati"),
        pytest.param("100.64.0.1", id="cgnat"),
        pytest.param("::ffff:10.0.0.5", id="ipv4_mappato_privato"),
    ]

    @pytest.fixture(autouse=True)
    def _local_network_only(self, monkeypatch):
        """Sovrascrive la fixture della base: guardia SSRF ATTIVA, nessun proxy
        da env (i test che ne vogliono uno lo impostano da sé)."""
        import shared.utils as u
        monkeypatch.setattr(u, "SSRF_PROTECTION", True)
        for var in self._PROXY_VARS:
            monkeypatch.delenv(var, raising=False)

    # ── infrastruttura: resolver finto e spy sul connect ─────────────

    @staticmethod
    def _install_resolver(monkeypatch, answers):
        """`getaddrinfo(host)` risponde con gli indirizzi di `answers[host]`
        (lista, oppure callable(n_chiamata) -> lista); gli altri host vanno al
        resolver vero. Restituisce il contatore delle chiamate per host."""
        real_getaddrinfo = socket.getaddrinfo
        counts = {}
        ipv6 = _sec24_ipv6_sockets_available()

        def _fake_getaddrinfo(host, port, *args, **kwargs):
            if host not in answers:
                return real_getaddrinfo(host, port, *args, **kwargs)
            counts[host] = counts.get(host, 0) + 1
            spec = answers[host]
            ips = spec(counts[host]) if callable(spec) else spec
            tcp_port = int(port or 0)
            out = []
            for ip in ips:
                if ":" in ip and ipv6:
                    out.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, tcp_port, 0, 0)))
                else:
                    out.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, tcp_port)))
            return out

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
        return counts

    @staticmethod
    def _install_connect_spy(monkeypatch, passthrough=None):
        """`socket.socket.connect` sostituito da uno spy: registra
        `(ip, porta)` e solleva subito ConnectionRefusedError. Solo per gli
        indirizzi in `passthrough` (ip -> (host, porta) del server LOCALE) la
        connessione è reale, ma verso il loopback."""
        calls = []
        original_connect = socket.socket.connect

        def _spy(sock, address):
            calls.append((address[0], address[1]))
            if passthrough and address[0] in passthrough:
                return original_connect(sock, passthrough[address[0]])
            raise ConnectionRefusedError("spy SEC-24: nessuna connessione reale")

        monkeypatch.setattr(socket.socket, "connect", _spy)
        return calls

    @staticmethod
    def _permissive_name_guard(monkeypatch):
        """Neutralizza la guardia per NOME, così il solo controllo al
        `connect` è verificato in isolamento."""
        import shared.utils as u
        monkeypatch.setattr(u, "is_safe_url", lambda url: (True, "test: guardia per nome neutralizzata"))

    @staticmethod
    def _assert_never_connected_to_blocked(calls, declared_blocked):
        """Asserzione centrale: nessun `connect` verso un indirizzo bloccato,
        né fra quelli dichiarati dal test né per `_is_blocked_ip`."""
        import shared.utils as u
        declared = [c for c in calls if c[0] in declared_blocked]
        by_function = [c for c in calls if u._is_blocked_ip(c[0])]
        assert not declared and not by_function, (
            f"connect verso un indirizzo bloccato: dichiarati={declared}, "
            f"_is_blocked_ip={by_function}; tutti i connect: {calls}")

    @staticmethod
    def _assert_ssrf_block(result):
        import shared.utils as u
        error = result["error"] or ""
        assert error.startswith((u.SSRF_ERROR_PREFIX, u.SSRF_REDIRECT_ERROR_PREFIX)), (
            f"atteso un errore con prefisso SSRF ({u.SSRF_ERROR_PREFIX!r} o "
            f"{u.SSRF_REDIRECT_ERROR_PREFIX!r}), ottenuto error={result['error']!r}")
        assert result["status_code"] is None and result["content"] is None
        assert result["attempts"] == 1, (
            f"il blocco SSRF è terminale, ma i tentativi sono {result['attempts']}")

    # ── C1: indirizzo bloccato, URL iniziale ─────────────────────────

    @pytest.mark.parametrize("blocked_ip", BLOCKED_CASES)
    def test_c1_name_resolving_to_a_blocked_address_is_never_connected(
            self, branch, monkeypatch, blocked_ip):
        """C1 — un nome che si risolve a un indirizzo bloccato (loopback,
        RFC1918, link-local/metadati, CGNAT, IPv4 mappato privato): nessun
        `connect` verso di esso ed errore col prefisso SSRF, su entrambi i
        rami. Guardia per nome neutralizzata: si prova il solo controllo al
        connect. Oggi rosso: la connessione parte verso l'indirizzo."""
        self._permissive_name_guard(monkeypatch)
        self._install_resolver(monkeypatch, {"blocked.test": [blocked_ip]})
        calls = self._install_connect_spy(monkeypatch)

        result, _elapsed, _t0 = self._fetch(
            "http://blocked.test/", timeout=2, max_attempts=2, base_delay=0.2)

        self._assert_never_connected_to_blocked(calls, {blocked_ip})
        self._assert_ssrf_block(result)

    # ── C1 su un hop di redirect ─────────────────────────────────────

    @pytest.mark.parametrize("blocked_ip", ["10.0.0.5", "100.64.0.1"], ids=["rfc1918", "cgnat"])
    def test_c1_redirect_hop_resolving_to_a_blocked_address_is_never_connected(
            self, branch, monkeypatch, drip_server, blocked_ip):
        """C1 su un hop: l'URL iniziale si risolve a un indirizzo pubblico
        (mappato dallo spy sul server locale, che risponde 302) e il secondo
        hop a un indirizzo bloccato: nessun `connect` verso il secondo, errore
        col prefisso SSRF. Il primo hop deve essere partito davvero, altrimenti
        il test non proverebbe nulla sul secondo."""
        srv = drip_server(_sec18_respond(302, "Found", headers=[("Location", "http://blocked.test/next")]))
        self._permissive_name_guard(monkeypatch)
        self._install_resolver(monkeypatch, {"start.test": [self.PUBLIC_IP], "blocked.test": [blocked_ip]})
        calls = self._install_connect_spy(monkeypatch, passthrough={self.PUBLIC_IP: ("127.0.0.1", srv.port)})

        result, _elapsed, _t0 = self._fetch(
            "http://start.test/", timeout=2, max_attempts=2, base_delay=0.2)

        assert (self.PUBLIC_IP, 80) in calls, f"il primo hop non è partito: {calls}"
        self._assert_never_connected_to_blocked(calls, {blocked_ip})
        self._assert_ssrf_block(result)

    # ── C2: rebinding DNS fra guardia e connessione ───────────────────

    def test_c2_dns_rebinding_between_guard_and_connect_is_never_connected(self, branch, monkeypatch):
        """C2 (SEC-21) — il resolver risponde con un indirizzo pubblico alla
        PRIMA chiamata (la guardia per nome, qui quella reale) e con uno
        bloccato (metadati cloud) a quelle successive (la connessione): nessun
        `connect` verso quello bloccato. Non si pretende il prefisso SSRF: sia
        «blocca al connect» sia «connettiti all'IP già validato» sono corretti."""
        counts = self._install_resolver(
            monkeypatch, {"rebind.test": lambda n: [self.PUBLIC_IP] if n == 1 else ["169.254.169.254"]})
        calls = self._install_connect_spy(monkeypatch)

        result, _elapsed, _t0 = self._fetch(
            "http://rebind.test/", timeout=2, max_attempts=2, base_delay=0.2)

        assert counts["rebind.test"] >= 1 and isinstance(result, dict)
        self._assert_never_connected_to_blocked(calls, {"169.254.169.254"})

    # ── C3: risposta mista, «uno bloccato blocca tutto» ───────────────

    @pytest.mark.parametrize("answers", [
        pytest.param(["93.184.216.34", "10.0.0.9"], id="pubblico_poi_bloccato"),
        pytest.param(["10.0.0.9", "93.184.216.34"], id="bloccato_poi_pubblico"),
    ])
    def test_c3_mixed_answer_blocks_every_connect(self, branch, monkeypatch, answers):
        """C3 — risposta mista, un indirizzo pubblico e uno bloccato (in
        entrambi gli ordini): NESSUN `connect`, nemmeno verso il pubblico
        (stessa semantica di `is_safe_url`: «anche uno solo interno blocca
        l'host»). Guardia per nome neutralizzata. Oggi rosso: la connessione
        parte verso il primo indirizzo."""
        self._permissive_name_guard(monkeypatch)
        self._install_resolver(monkeypatch, {"mixed.test": answers})
        calls = self._install_connect_spy(monkeypatch)

        result, _elapsed, _t0 = self._fetch(
            "http://mixed.test/", timeout=2, max_attempts=2, base_delay=0.2)

        assert calls == [], f"nessun connect atteso su una risposta mista, visti: {calls}"
        self._assert_ssrf_block(result)

    # ── C4: indirizzo pubblico, comportamento invariato ───────────────

    def test_c4_public_address_still_works(self, branch, monkeypatch, drip_server):
        """C4 — non-regressione: un indirizzo pubblico fittizio, mappato dallo
        spy sul server locale, dà 200 con il body completo e `error` None, su
        entrambi i rami, con la guardia per nome REALE. Il solo `connect` visto
        è verso quell'indirizzo pubblico. Probabilmente verde oggi."""
        body = b"<html>sec24 public</html>"
        srv = drip_server(_sec18_respond(200, "OK", body=body))
        self._install_resolver(monkeypatch, {"public.test": [self.PUBLIC_IP]})
        calls = self._install_connect_spy(monkeypatch, passthrough={self.PUBLIC_IP: ("127.0.0.1", srv.port)})

        result, _elapsed, _t0 = self._fetch("http://public.test/", timeout=2, max_attempts=1)

        assert result["error"] is None, f"errore inatteso su un indirizzo pubblico: {result['error']!r}"
        assert result["status_code"] == 200 and result["content"] == body
        assert calls == [(self.PUBLIC_IP, 80)], f"connect inattesi: {calls}"

    # ── C6: SSRF_PROTECTION disattivato ──────────────────────────────

    def test_c6_guard_is_inactive_when_ssrf_protection_is_off(self, branch, monkeypatch):
        """C6 — con `SSRF_PROTECTION` disattivato la guardia al connect NON
        blocca: la connessione verso un indirizzo privato parte (lo spy la
        vede e la rifiuta) e l'errore è quello generico, non un blocco SSRF.
        Verde oggi: fissa che l'opt-out dei laboratori offline resta tale."""
        import shared.utils as u
        monkeypatch.setattr(u, "SSRF_PROTECTION", False)
        self._install_resolver(monkeypatch, {"off.test": ["10.0.0.9"]})
        calls = self._install_connect_spy(monkeypatch)

        result, _elapsed, _t0 = self._fetch("http://off.test/", timeout=2, max_attempts=1)

        assert ("10.0.0.9", 80) in calls, f"con la protezione spenta il connect deve partire: {calls}"
        assert not (result["error"] or "").startswith((u.SSRF_ERROR_PREFIX, u.SSRF_REDIRECT_ERROR_PREFIX)), (
            f"blocco SSRF con la protezione spenta: {result['error']!r}")

    # ── C7: proxy da env su IP privato ────────────────────────────────

    def test_c7_connection_to_the_env_proxy_is_not_blocked(self, branch, monkeypatch, drip_server):
        """C7 — decisione del coordinator: il proxy da env è configurato
        dall'operatore (fidato) e la connessione AL PROXY non è bloccata dalla
        guardia per IP, anche se il proxy sta su un indirizzo privato; il
        target resta protetto dalla sola guardia per nome (gap dichiarato,
        accorpato a SEC-23). Qui il proxy è un nome fittizio risolto a un
        indirizzo privato che lo spy mappa sul server locale, che fa da proxy
        http semplice: la richiesta passa dal proxy (il server vede l'URL
        assoluto) e dà 200, su entrambi i rami. Verde oggi: fissa che il fix
        non blocchi il proxy."""
        body = b"via proxy"
        srv = drip_server(_sec18_respond(200, "OK", body=body))
        for var in ("http_proxy", "HTTP_PROXY"):
            monkeypatch.setenv(var, "http://proxy.test:3128")
        self._install_resolver(monkeypatch, {"proxy.test": ["10.9.9.9"], "public.test": [self.PUBLIC_IP]})
        calls = self._install_connect_spy(monkeypatch, passthrough={"10.9.9.9": ("127.0.0.1", srv.port)})

        result, _elapsed, _t0 = self._fetch("http://public.test/", timeout=2, max_attempts=1)

        assert ("10.9.9.9", 3128) in calls, f"la connessione al proxy non è partita: {calls}"
        assert result["error"] is None, f"errore passando dal proxy: {result['error']!r}"
        assert result["status_code"] == 200 and result["content"] == body
        assert srv.paths and srv.paths[0].startswith("http://public.test/"), (
            f"la richiesta non è passata dal proxy (percorso visto: {srv.paths})")

    # ── C5: _is_blocked_ip, matrice del G2 ────────────────────────────

    @pytest.mark.parametrize("ip", [
        pytest.param("100.64.0.1", id="cgnat_inizio"),
        pytest.param("100.127.255.255", id="cgnat_fine"),
        pytest.param("192.88.99.1", id="6to4_relay_anycast"),
        pytest.param("::ffff:127.0.0.1", id="mappato_loopback"),
        pytest.param("::ffff:10.0.0.1", id="mappato_privato"),
        pytest.param("::ffff:100.64.0.1", id="mappato_cgnat"),
    ])
    def test_c5_new_blocks(self, ip):
        """C5 — i nuovi blocchi: CGNAT 100.64.0.0/10 (comprende un endpoint
        di metadati cloud noto), 192.88.99.0/24 e gli IPv4 mappati in IPv6
        valutati sull'IPv4 incapsulato, con lo stesso esito su ogni versione
        di Python (`::ffff:100.64.0.1` era False su 3.13 e True su 3.12)."""
        import shared.utils as u
        assert u._is_blocked_ip(ip) is True, f"{ip} deve essere bloccato"

    @pytest.mark.parametrize("ip", [
        "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
        "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fd12:3456::1", "fe80::1",
        "::ffff:192.168.1.1", "::ffff:169.254.169.254",
    ])
    def test_c5_already_blocked_addresses_stay_blocked(self, ip):
        """Guardia contro le regressioni: gli indirizzi già bloccati prima
        del fix (loopback, RFC1918, metadati, multicast, fc00::/7, link-local
        IPv6, IPv4 mappati interni) restano bloccati."""
        import shared.utils as u
        assert u._is_blocked_ip(ip) is True, f"{ip} deve restare bloccato"

    @pytest.mark.parametrize("ip", [
        "8.8.8.8", "1.1.1.1", "93.184.216.34", "::ffff:8.8.8.8", "::ffff:93.184.216.34",
        "2001:4860:4860::8888", "2606:4700:4700::1111",
    ])
    def test_c5_public_addresses_are_not_blocked(self, ip):
        """Nessun falso positivo: gli indirizzi pubblici, anche mappati in
        IPv6 (`::ffff:8.8.8.8`), passano."""
        import shared.utils as u
        assert u._is_blocked_ip(ip) is False, f"{ip} è pubblico e non deve essere bloccato"

    # ── round 2 (verifier, G6 INSUFFICIENTE «solo per i test») ────────
    #
    # Test VERDI sul codice attuale: il loro scopo è uccidere i mutanti G14,
    # G11c, G07d, G07e, G07f del verifier (/tmp/v24/mut/gen.py), che il round 1
    # lasciava sopravvivere. Stesso metodo: resolver e `connect` simulati,
    # nessuna connessione verso indirizzi non di loopback.

    @staticmethod
    def _set_env_proxy(monkeypatch, no_proxy=None):
        """Proxy http/https da env verso un nome fittizio, più `NO_PROXY`."""
        for var in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"):
            monkeypatch.setenv(var, "http://proxy.test:3128")
        if no_proxy is not None:
            for var in ("no_proxy", "NO_PROXY"):
                monkeypatch.setenv(var, no_proxy)

    def test_r2_create_connection_resolves_once_and_never_re_resolves(self, branch, monkeypatch, drip_server):
        """Uccisore di G14 (`getaddrinfo` rifatto nel ciclo di connect). Il
        resolver risponde `[pubblico]` alle prime due chiamate (guardia per
        nome, poi la validazione in `create_connection`) e un indirizzo
        bloccato (metadati cloud) a ogni chiamata successiva: se
        `create_connection` risolvesse una terza volta per connettersi,
        l'indirizzo connesso non sarebbe più quello validato (rebinding fra
        validazione e connect). Lo spy non deve vedere l'indirizzo bloccato, la
        risoluzione di `create_connection` deve essere UNA sola (2 chiamate in
        tutto) e la richiesta deve riuscire verso l'indirizzo validato.
        Verde oggi, su entrambi i rami."""
        srv = drip_server(_sec18_respond(200, "OK", body=b"ok"))
        counts = self._install_resolver(
            monkeypatch, {"once.test": lambda n: [self.PUBLIC_IP] if n <= 2 else ["169.254.169.254"]})
        calls = self._install_connect_spy(monkeypatch, passthrough={self.PUBLIC_IP: ("127.0.0.1", srv.port)})

        result, _elapsed, _t0 = self._fetch("http://once.test/", timeout=2, max_attempts=1)

        self._assert_never_connected_to_blocked(calls, {"169.254.169.254"})
        assert counts["once.test"] == 2, (
            f"risoluzioni di once.test: {counts['once.test']} (attese 2: guardia per nome + "
            "UNA in create_connection; una terza apre la finestra di rebinding fra validazione e connect)")
        assert result["error"] is None and result["status_code"] == 200
        assert calls == [(self.PUBLIC_IP, 80)], f"connect inattesi: {calls}"

    def test_r2_https_target_behind_env_proxy_connects_to_the_proxy(self, branch, monkeypatch, drip_server):
        """Uccisore di G11c (`_tunnel_host` ignorato sul ramo `urllib`). Con un
        proxy da env un target `https://` passa da un tunnel CONNECT: la
        connessione è AL PROXY (qui su un indirizzo privato, `10.9.9.9`, che lo
        spy mappa su un finto proxy locale), quindi non va bloccata dalla guardia
        per IP — su `urllib` `request.has_proxy()` è False per i target https e
        solo `_tunnel_host` lo rivela. Il finto proxy risponde 200 al CONNECT e
        chiude: l'handshake TLS poi fallisce con un errore GENERICO, non SSRF.
        Il proxy deve aver ricevuto `CONNECT pub.test:443`. Verde oggi."""
        import shared.utils as u

        def _connect_then_close(srv, conn, path):
            srv.send(conn, b"HTTP/1.1 200 Connection established\r\n\r\n")

        srv = drip_server(_connect_then_close)
        self._set_env_proxy(monkeypatch)
        self._install_resolver(monkeypatch, {"proxy.test": ["10.9.9.9"], "pub.test": [self.PUBLIC_IP]})
        calls = self._install_connect_spy(monkeypatch, passthrough={"10.9.9.9": ("127.0.0.1", srv.port)})

        result, _elapsed, _t0 = self._fetch("https://pub.test/", timeout=2, max_attempts=1)

        assert ("10.9.9.9", 3128) in calls, f"la connessione al proxy non è partita: {calls}"
        assert srv.paths and srv.paths[0] == "pub.test:443", (
            f"il proxy doveva ricevere CONNECT pub.test:443, ha visto {srv.paths}")
        assert not (result["error"] or "").startswith((u.SSRF_ERROR_PREFIX, u.SSRF_REDIRECT_ERROR_PREFIX)), (
            f"la connessione al proxy è stata bloccata come SSRF: {result['error']!r}")

    @pytest.mark.parametrize("no_proxy", ["blocked.test", "*"], ids=["host", "tutti"])
    def test_r2_no_proxy_covering_the_target_keeps_the_guard_active(self, branch, monkeypatch, no_proxy):
        """Con il proxy configurato ma `NO_PROXY` che copre il target, la
        connessione è DIRETTA e la guardia per IP resta attiva: un target che
        si risolve a un indirizzo bloccato viene bloccato (nessun connect verso
        di esso), e il proxy non viene nemmeno contattato (nessun connect
        verso `10.9.9.9`). Guardia per nome neutralizzata per provare il solo
        controllo al connect. Verde oggi, su entrambi i rami."""
        self._permissive_name_guard(monkeypatch)
        self._set_env_proxy(monkeypatch, no_proxy=no_proxy)
        self._install_resolver(monkeypatch, {"proxy.test": ["10.9.9.9"], "blocked.test": ["10.0.0.5"]})
        calls = self._install_connect_spy(monkeypatch)

        result, _elapsed, _t0 = self._fetch(
            "http://blocked.test/", timeout=2, max_attempts=2, base_delay=0.2)

        assert calls == [], f"nessun connect atteso (né al bloccato né al proxy), visti: {calls}"
        self._assert_ssrf_block(result)

    # ── confini delle nuove reti (G07d, G07e, G07f) ───────────────────

    @pytest.mark.parametrize("ip", ["100.63.255.255", "100.128.0.0", "192.88.98.255", "192.88.100.0"])
    def test_r2_addresses_just_outside_the_new_networks_are_not_blocked(self, ip):
        """Confini ESTERNI delle reti aggiunte: l'ultimo indirizzo prima del
        CGNAT (`100.63.255.255`), il primo dopo (`100.128.0.0`) e i due vicini
        di `192.88.99.0/24`. Uccidono i mutanti che allargano le reti: G07d
        (CGNAT come /9) e G07f (relay come /23). Nessun falso positivo."""
        import shared.utils as u
        assert u._is_blocked_ip(ip) is False, f"{ip} è fuori dalle reti bloccate e deve passare"

    @pytest.mark.parametrize("ip", ["100.64.0.0", "192.88.99.0", "192.88.99.255"])
    def test_r2_first_and_last_addresses_of_the_new_networks_are_blocked(self, ip):
        """Confini INTERNI: il primo indirizzo del CGNAT (`100.64.0.0`) e il
        primo e l'ultimo di `192.88.99.0/24`. Uccidono il mutante che restringe
        il relay (G07e, /25: `192.88.99.255` fuori)."""
        import shared.utils as u
        assert u._is_blocked_ip(ip) is True, f"{ip} è dentro le reti bloccate e deve essere bloccato"


# ═══════════════════════════════════════════════════════════════
# SEC-25 — inspect_tls: guardia SSRF e limite di durata
# ═══════════════════════════════════════════════════════════════
#
# Fonte: BUG-REGISTER.md, «SEC-25 — apertura» (G1, criteri T1…T7). `inspect_tls`
# (shared/utils.py) si collega a `hostname:443` del lookalike con
# `socket.create_connection`, senza guardia SSRF (né per nome né per IP) e senza
# limite di durata: ogni indirizzo di `getaddrinfo` riceve il `timeout` intero.
# Unico chiamante: `services/cert_intel.py` con `GET /cert?tls_live=true`
# (zona engine, non autenticata). Il fix previsto riusa
# `_FetchDeadline.create_connection` di SEC-18/SEC-24: guardia sull'IP
# effettivamente contattato e limite `MAX_FETCH_SECONDS`.
#
# STESSO METODO di TestSEC24ConnectTimeIpGuard (di cui si riusano gli helper
# statici): resolver e `connect` simulati, nessuna connessione reale verso
# indirizzi non di loopback; i casi «pubblici» mappano l'indirizzo fittizio sul
# server locale (qui un server TLS con certificato generato a runtime da
# `openssl` in una directory temporanea, mai nel repository).
#
# CONTRATTO per il fixer:
#   * `inspect_tls(hostname, port=443, timeout=10)` mantiene la firma e la forma
#     del risultato `{"connected", "certificate", "error"}`.
#   * Un indirizzo bloccato (anche uno solo fra quelli risolti, in qualunque
#     ordine) → nessun `connect`, `connected` False, `certificate` None e
#     `error` che COMINCIA per `SSRF_ERROR_PREFIX` (URL diretto, non redirect).
#   * Il limite di durata è `MAX_FETCH_SECONDS` letto a RUNTIME (i test lo
#     monkeypatchano), non un parametro nuovo: `inspect_tls` non ha `max_seconds`.
#   * Guardia attiva solo con `SSRF_PROTECTION`. SNI invariato.
#   * `services.cert_intel` continua a chiamare `inspect_tls(domain)` e a
#     riportare il risultato in `tls_live`, senza altro cambiamento della risposta.


class TestSEC25InspectTlsGuard(_Sec18Base):
    """SEC-25 — `inspect_tls` e `/cert?tls_live=true` con guardia SSRF e
    limite di durata. `_Sec18Base._local_network_only` (guardia SSRF
    disattivata) è sovrascritta: qui la guardia è ATTIVA."""

    D = 0.5
    PUBLIC_IP = TestSEC24ConnectTimeIpGuard.PUBLIC_IP
    _install_resolver = staticmethod(TestSEC24ConnectTimeIpGuard._install_resolver)
    _install_connect_spy = staticmethod(TestSEC24ConnectTimeIpGuard._install_connect_spy)
    _permissive_name_guard = staticmethod(TestSEC24ConnectTimeIpGuard._permissive_name_guard)
    _assert_never_connected_to_blocked = staticmethod(
        TestSEC24ConnectTimeIpGuard._assert_never_connected_to_blocked)

    @pytest.fixture(autouse=True)
    def _local_network_only(self, monkeypatch):
        import shared.utils as u
        monkeypatch.setattr(u, "SSRF_PROTECTION", True)
        for var in self._PROXY_VARS:
            monkeypatch.delenv(var, raising=False)

    @staticmethod
    def _assert_ssrf_block(result):
        import shared.utils as u
        assert (result["error"] or "").startswith(u.SSRF_ERROR_PREFIX), (
            f"atteso un errore con prefisso SSRF ({u.SSRF_ERROR_PREFIX!r}), "
            f"ottenuto error={result['error']!r}")
        assert result["connected"] is False and result["certificate"] is None

    # ── T1: indirizzo bloccato ────────────────────────────────────────

    @pytest.mark.parametrize("blocked_ip", TestSEC24ConnectTimeIpGuard.BLOCKED_CASES)
    def test_t1_name_resolving_to_a_blocked_address_is_never_connected(self, monkeypatch, blocked_ip):
        """T1 — un nome che si risolve a un indirizzo bloccato (loopback,
        RFC1918, link-local/metadati, CGNAT, IPv4 mappato privato): nessun
        `connect` verso di esso, `error` col prefisso SSRF, `connected` False.
        Guardia per nome neutralizzata: si prova il controllo sull'IP
        contattato. Oggi rosso: `socket.create_connection` si collega."""
        import shared.utils as u
        self._permissive_name_guard(monkeypatch)
        self._install_resolver(monkeypatch, {"blocked.test": [blocked_ip]})
        calls = self._install_connect_spy(monkeypatch)

        result = u.inspect_tls("blocked.test", timeout=2)

        self._assert_never_connected_to_blocked(calls, {blocked_ip})
        self._assert_ssrf_block(result)

    # ── T2: risposta mista ────────────────────────────────────────────

    @pytest.mark.parametrize("answers", [
        pytest.param(["93.184.216.34", "10.0.0.9"], id="pubblico_poi_bloccato"),
        pytest.param(["10.0.0.9", "93.184.216.34"], id="bloccato_poi_pubblico"),
    ])
    def test_t2_mixed_answer_blocks_every_connect(self, monkeypatch, answers):
        """T2 — risposta mista, un indirizzo pubblico e uno bloccato, in
        entrambi gli ordini: NESSUN `connect`, nemmeno verso il pubblico
        («uno bloccato blocca tutto», come `is_safe_url`). Oggi rosso."""
        import shared.utils as u
        self._permissive_name_guard(monkeypatch)
        self._install_resolver(monkeypatch, {"mixed.test": answers})
        calls = self._install_connect_spy(monkeypatch)

        result = u.inspect_tls("mixed.test", timeout=2)

        assert calls == [], f"nessun connect atteso su una risposta mista, visti: {calls}"
        self._assert_ssrf_block(result)

    # ── T3: pubblico, comportamento invariato ─────────────────────────

    def test_t3_public_address_still_returns_the_certificate_hash(
            self, monkeypatch, drip_server, sec18_tls_context):
        """T3 — non-regressione: un indirizzo pubblico fittizio, mappato dallo
        spy sul server TLS locale (certificato autofirmato generato a
        runtime), dà `connected` True, un `certificate` con `der_sha256`
        (SHA-256 esadecimale di 64 caratteri; `ssl.CERT_NONE` voluto, quindi
        solo l'hash del DER) ed `error` None, con la guardia per nome REALE. Il
        solo `connect` visto è verso quell'indirizzo, porta 443. Verde oggi."""
        import shared.utils as u

        def _handshake_only(srv, conn, path):
            return None       # l'handshake è già fatto da _DripServer; poi chiude

        srv = drip_server(_handshake_only, ssl_context=sec18_tls_context, raw=True)
        self._install_resolver(monkeypatch, {"tls.test": [self.PUBLIC_IP]})
        calls = self._install_connect_spy(monkeypatch, passthrough={self.PUBLIC_IP: ("127.0.0.1", srv.port)})

        result = u.inspect_tls("tls.test", timeout=2)

        assert result["error"] is None, f"errore inatteso su un indirizzo pubblico: {result['error']!r}"
        assert result["connected"] is True
        digest = (result["certificate"] or {}).get("der_sha256")
        assert isinstance(digest, str) and len(digest) == 64 and int(digest, 16) >= 0, (
            f"der_sha256 atteso (64 hex), ottenuto certificate={result['certificate']!r}")
        assert calls == [(self.PUBLIC_IP, 443)], f"connect inattesi: {calls}"

    # ── T4: SSRF_PROTECTION disattivato ───────────────────────────────

    def test_t4_guard_is_inactive_when_ssrf_protection_is_off(self, monkeypatch):
        """T4 — con `SSRF_PROTECTION` disattivato nessun blocco: il connect
        verso un indirizzo privato parte (lo spy lo vede e lo rifiuta) e
        l'errore è quello generico, non un blocco SSRF. Verde oggi: l'opt-out
        dei laboratori offline resta tale."""
        import shared.utils as u
        monkeypatch.setattr(u, "SSRF_PROTECTION", False)
        self._install_resolver(monkeypatch, {"off.test": ["10.0.0.9"]})
        calls = self._install_connect_spy(monkeypatch)

        result = u.inspect_tls("off.test", timeout=2)

        assert ("10.0.0.9", 443) in calls, f"con la protezione spenta il connect deve partire: {calls}"
        assert result["connected"] is False and result["error"]
        assert not result["error"].startswith(u.SSRF_ERROR_PREFIX), (
            f"blocco SSRF con la protezione spenta: {result['error']!r}")

    # ── T5: limite di durata ──────────────────────────────────────────

    def test_t5_dead_addresses_are_cut_by_the_overall_deadline(self, monkeypatch, sec18_blackhole):
        """T5 — 5 indirizzi pubblici fittizi che non completano il connect
        (lo spy li mappa sul listener con accept queue piena, `sec18_blackhole`)
        con `MAX_FETCH_SECONDS` a 0,5 s e `timeout=0,4` s: ogni indirizzo
        riceverebbe 0,4 s, 2 s in tutto, oggi senza limite. Con il limite la
        chiamata torna entro D + ε (1,0 s) con `connected` False. Gli indirizzi
        sono pubblici perché un loopback sarebbe fermato dalla guardia SSRF e
        il test non proverebbe il tempo."""
        import shared.utils as u
        self._set_deadline(monkeypatch, self.D)
        dead_ips = [f"93.184.216.{n}" for n in range(34, 39)]
        self._install_resolver(monkeypatch, {"dead.test": dead_ips})
        self._install_connect_spy(monkeypatch, passthrough={ip: ("127.0.0.1", sec18_blackhole) for ip in dead_ips})

        t0 = time.monotonic()
        result = u.inspect_tls("dead.test", timeout=0.4)
        elapsed = time.monotonic() - t0

        assert result["connected"] is False and result["error"]
        assert elapsed <= self.D + 0.5, (
            f"inspect_tls è tornata dopo {elapsed:.2f}s: oltre D + 0,5 s = {self.D + 0.5:g}s "
            f"(D={self.D}s) — il tempo complessivo non è limitato (5 indirizzi x 0,4 s)")

    # ── T6: GET /cert?tls_live=true ───────────────────────────────────

    def test_t6_cert_endpoint_tls_live_reports_the_ssrf_block(self, monkeypatch):
        """T6 — `GET /cert?domain=<valido>&tls_live=true` (TestClient su
        `services.cert_intel`, zona engine non autenticata): con il dominio
        che si risolve a un indirizzo bloccato `tls_live.error` ha il prefisso
        SSRF, `connected` è False e nessun `connect` parte. Il resto della
        risposta è invariato (dominio, `ct_certificates` vuoto, `error` None).
        La parte crt.sh non fa rete: `http_get_with_retry` di
        `services.cert_intel` è sostituita da uno stub con un risultato vuoto
        valido, e la cache CT del modulo è isolata. Oggi rosso."""
        import shared.utils as u
        from fastapi.testclient import TestClient
        from services import cert_intel

        monkeypatch.setattr(cert_intel, "http_get_with_retry", lambda *a, **k: {
            "status_code": 200, "content": b"[]", "headers": {}, "final_url": None,
            "error": None, "attempts": 1})
        monkeypatch.setattr(cert_intel, "_ct_cache", {})
        monkeypatch.setattr(cert_intel, "_ct_cache_order", [])
        domain = "sec25-live.example"
        self._permissive_name_guard(monkeypatch)
        self._install_resolver(monkeypatch, {domain: ["10.0.0.5"]})
        calls = self._install_connect_spy(monkeypatch)

        with TestClient(cert_intel.app) as client:
            resp = client.get("/cert", params={"domain": domain, "tls_live": "true"})

        assert resp.status_code == 200, f"/cert ha risposto HTTP {resp.status_code}: {resp.text[:200]!r}"
        body = resp.json()
        assert calls == [], f"nessun connect atteso, visti: {calls}"
        live = body["tls_live"]
        assert isinstance(live, dict) and live["connected"] is False
        assert (live["error"] or "").startswith(u.SSRF_ERROR_PREFIX), (
            f"tls_live.error atteso con prefisso SSRF, ottenuto {live!r}")
        assert body["domain"] == domain and body["error"] is None
        assert body["ct_certificates"]["total"] == 0

    # ── giro correttivo (verifier, G6 INSUFFICIENTE): mutanti sopravvissuti ──
    #
    # Test VERDI sul codice attuale; il loro scopo è uccidere i mutanti I04, I07,
    # I08, I09 e I10 del verifier (/tmp/v25/mut/gen.py). Stesso metodo: resolver
    # simulato, spy su `socket.socket.connect`, server TLS solo su loopback.

    @staticmethod
    def _assert_no_thread_left(before, outcome):
        """Dopo il ritorno di `inspect_tls` nessun thread in più rispetto a
        `before`, con una breve attesa (fino a ~1 s) per i thread del server di
        prova che finiscono da soli. Si confronta l'insieme dei thread, non il
        nome: robusto a un rinomina del watchdog e ai thread di altri test."""
        left = set()
        end = time.monotonic() + 1.0
        while time.monotonic() < end:
            left = set(threading.enumerate()) - before
            if not left:
                return
            time.sleep(0.02)
        assert not left, (
            f"thread rimasti vivi dopo inspect_tls (esito: {outcome}): "
            f"{sorted(t.name for t in left)}. Il watchdog di `_FetchDeadline` non è stato "
            "fermato: `deadline.close()` deve stare in un `finally` su ogni uscita.")

    def test_i04_watchdog_thread_is_released_after_a_successful_call(
            self, monkeypatch, drip_server, sec18_tls_context):
        """Uccisore di I04 (`finally: deadline.close()` rimosso) — esito
        SUCCESSO. Ogni chiamata crea un thread watchdog `fetch-deadline`; senza
        `close()` resta vivo per sempre (dopo D continua a girare a 50 ms), uno
        per chiamata a `GET /cert?tls_live=true`, in zona non autenticata.
        Handshake riuscito contro il server TLS locale: dopo il ritorno nessun
        thread in più. Modello: S18-7 per `http_get_with_retry`."""
        import shared.utils as u
        srv = drip_server(lambda s, c, p: None, ssl_context=sec18_tls_context, raw=True)
        self._install_resolver(monkeypatch, {"ok.test": [self.PUBLIC_IP]})
        self._install_connect_spy(monkeypatch, passthrough={self.PUBLIC_IP: ("127.0.0.1", srv.port)})
        before = set(threading.enumerate())

        result = u.inspect_tls("ok.test", timeout=2)

        assert result["connected"] is True and result["error"] is None
        self._assert_no_thread_left(before, "successo")

    def test_i04_watchdog_thread_is_released_after_an_ssrf_block(self, monkeypatch):
        """Uccisore di I04 — esito BLOCCO SSRF: l'eccezione `_SSRFConnectBlocked`
        esce prima di qualunque connessione, ma il watchdog è già partito e va
        fermato lo stesso."""
        import shared.utils as u
        self._permissive_name_guard(monkeypatch)
        self._install_resolver(monkeypatch, {"blocked.test": ["10.0.0.5"]})
        self._install_connect_spy(monkeypatch)
        before = set(threading.enumerate())

        result = u.inspect_tls("blocked.test", timeout=2)

        assert (result["error"] or "").startswith(u.SSRF_ERROR_PREFIX)
        self._assert_no_thread_left(before, "blocco SSRF")

    def test_i04_watchdog_thread_is_released_after_the_deadline_expired(self, monkeypatch, sec18_blackhole):
        """Uccisore di I04 — esito SCADENZA (D=0,5 s): il watchdog è scattato
        (`fired`) e, senza `close()`, continuerebbe a chiudere socket ogni 50 ms
        per sempre. Indirizzi pubblici fittizi mappati sul listener con accept
        queue piena."""
        import shared.utils as u
        self._set_deadline(monkeypatch, self.D)
        dead_ips = [f"93.184.216.{n}" for n in range(34, 37)]
        self._install_resolver(monkeypatch, {"dead.test": dead_ips})
        self._install_connect_spy(monkeypatch, passthrough={ip: ("127.0.0.1", sec18_blackhole) for ip in dead_ips})
        before = set(threading.enumerate())

        result = u.inspect_tls("dead.test", timeout=0.4)

        assert result["connected"] is False and result["error"]
        self._assert_no_thread_left(before, "scadenza")

    def test_i09_sni_is_the_requested_hostname(self, monkeypatch, drip_server, sec18_tls_context):
        """Uccisore di I09 (`server_hostname=hostname` rimosso, SNI perso): il
        server TLS locale registra il nome richiesto con `sni_callback`. Senza
        SNI un server con più certificati serve quello sbagliato e l'hash DER
        riportato non è quello del lookalike. Il callback è impostato sul
        contesto condiviso solo per la durata del test (monkeypatch)."""
        import shared.utils as u
        seen = []
        monkeypatch.setattr(sec18_tls_context, "sni_callback", lambda ssl_sock, name, ctx: seen.append(name))
        srv = drip_server(lambda s, c, p: None, ssl_context=sec18_tls_context, raw=True)
        self._install_resolver(monkeypatch, {"sni.test": [self.PUBLIC_IP]})
        self._install_connect_spy(monkeypatch, passthrough={self.PUBLIC_IP: ("127.0.0.1", srv.port)})

        result = u.inspect_tls("sni.test", timeout=2)

        assert result["connected"] is True, f"handshake non riuscito: {result['error']!r}"
        assert seen == ["sni.test"], f"SNI visto dal server: {seen!r} (atteso ['sni.test'])"

    def test_i07_watchdog_start_failure_returns_an_error_dict_without_connecting(self, monkeypatch):
        """Uccisore di I07 (`deadline = None` iniziale rimosso). Se il thread del
        watchdog non parte (`RuntimeError: can't start new thread`, limite di
        thread del container) `_FetchDeadline(...)` solleva prima di assegnare
        `deadline`: il `finally` non deve fallire con `UnboundLocalError`.
        `inspect_tls` restituisce il dict con `error` valorizzato,
        `connected` False e NESSUN connect (senza watchdog il limite di durata
        non c'è, meglio non collegarsi)."""
        import shared.utils as u

        def _failing_start(thread):
            raise RuntimeError("can't start new thread")

        self._install_resolver(monkeypatch, {"nostart.test": [self.PUBLIC_IP]})
        calls = self._install_connect_spy(monkeypatch)
        monkeypatch.setattr(threading.Thread, "start", _failing_start)
        try:
            result = u.inspect_tls("nostart.test", timeout=2)
        except Exception as exc:
            pytest.fail(f"inspect_tls ha sollevato {type(exc).__name__} invece di restituire un dict: {exc}")

        assert isinstance(result, dict) and result["connected"] is False
        assert isinstance(result["error"], str) and result["error"]
        assert result["certificate"] is None
        assert calls == [], f"nessun connect atteso senza watchdog, visti: {calls}"

    def test_i10_per_operation_timeout_is_honoured_below_the_deadline(self, monkeypatch, sec18_blackhole):
        """Uccisore di I10 (`timeout` ignorato: `create_connection(..., None)`).
        Un indirizzo che non completa il connect (listener con accept queue piena,
        mappato dallo spy), `timeout=0,5` e D grande (3 s): la durata deve stare
        vicino al `timeout` (0,5 s), non a D. Limite 1,0 s; il connect è
        davvero partito (lo spy lo vede)."""
        import shared.utils as u
        self._set_deadline(monkeypatch, 3)
        self._install_resolver(monkeypatch, {"slow.test": [self.PUBLIC_IP]})
        calls = self._install_connect_spy(monkeypatch, passthrough={self.PUBLIC_IP: ("127.0.0.1", sec18_blackhole)})

        t0 = time.monotonic()
        result = u.inspect_tls("slow.test", timeout=0.5)
        elapsed = time.monotonic() - t0

        assert (self.PUBLIC_IP, 443) in calls, f"il connect non è partito: {calls}"
        assert result["connected"] is False and result["error"]
        assert elapsed <= 1.0, (
            f"inspect_tls è tornata dopo {elapsed:.2f}s con timeout=0,5 e D=3: il `timeout` "
            "per operazione è stato ignorato (durata ~D invece di ~timeout)")

    def test_i08_requested_port_is_the_one_contacted(self, monkeypatch):
        """Uccisore di I08 (porta fissa 443): `inspect_tls(host, 8443)` deve
        contattare la porta 8443. Lo spy vede la porta del sockaddr risolto."""
        import shared.utils as u
        self._install_resolver(monkeypatch, {"port.test": [self.PUBLIC_IP]})
        calls = self._install_connect_spy(monkeypatch)

        u.inspect_tls("port.test", 8443, timeout=2)

        assert calls == [(self.PUBLIC_IP, 8443)], f"connect inattesi: {calls}"


# ═══════════════════════════════════════════════════════════════
# SEC-26 — difesa sul punto di uscita: dig_query rifiuta nomi che `dig`
# leggerebbe come server (@), opzione (- / +) o che non sono un nome DNS.
# ═══════════════════════════════════════════════════════════════

class TestSEC26DigQueryNameGuard:
    """C6 — `dig_query(fqdn, ...)` passa `fqdn` come argomento a `dig`: `@host`
    è un server, `-x` / `+opt` sono opzioni. Un nome che non è un nome DNS
    (vuoto, > 253, non inizia con alfanumerico o `_`, caratteri fuori da
    `[A-Za-z0-9_.-]`) deve tornare come errore (primo elemento `ERROR...`,
    quindi `is_valid` falso) **senza** lanciare `subprocess.run`; per i nomi
    validi l'argv resta identico a quello storico.

    Isolamento: `subprocess.run` è sostituito da uno spy, nessun `dig` reale e
    nessuna rete."""

    EXPECTED_PREFIX = ["dig", "+short", "+ndots=1"]
    EXPECTED_SUFFIX = ["+tries=2", "+noidnout"]

    @staticmethod
    def _install_spy(monkeypatch, stdout=""):
        import shared.utils as u
        calls = []

        def _spy(argv, *args, **kwargs):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

        monkeypatch.setattr(u.subprocess, "run", _spy)
        return calls

    @classmethod
    def _expected_argv(cls, name, rtype, timeout):
        return cls.EXPECTED_PREFIX + [f"+time={timeout}"] + cls.EXPECTED_SUFFIX + [name, rtype]

    @staticmethod
    def _dns_name(length):
        """Nome fatto di label valide (<= 63) lungo esattamente `length`."""
        labels, remaining = [], length
        while remaining > 0:
            take = min(63, remaining)
            labels.append("a" * take)
            remaining -= take + 1  # +1 per il punto separatore
        name = ".".join(labels)
        assert len(name) == length and all(len(x) <= 63 for x in labels)
        return name

    @pytest.mark.parametrize("name", [
        "@8.8.8.8",
        "@ns.attacker.example._domainkey.example.com",
        "-x",
        "-p5353._domainkey.example.com",
        "+tries=9",
        "+short._domainkey.example.com",
        " example.com",         # spazio iniziale
        "example.com ",         # spazio finale
        "exam ple.com",         # spazio interno
        "example.com\n",
        "exam\nple.com",
        "example\t.com",
        "example.com\x00",
        "exam\x00ple.com",
        "example.com\r",
        "ex/ample.com",
        "ex\\ample.com",
        "example.com;id",
        "$(id).example.com",
        "exämple.com",     # non ASCII
        ".example.com",         # punto iniziale: non alfanumerico né '_'
        "",
    ], ids=lambda s: repr(s))
    def test_non_dns_name_is_refused_without_running_dig(self, monkeypatch, name):
        from shared.utils import dig_query, is_valid
        calls = self._install_spy(monkeypatch)

        res = dig_query(name, "TXT", 5)

        assert calls == [], f"subprocess.run chiamato per {name!r}: {calls}"
        assert isinstance(res, list) and res, f"atteso un errore in lista, ricevuto {res!r}"
        assert res[0].startswith("ERROR"), f"primo elemento {res[0]!r} non inizia con ERROR"
        assert is_valid(res) is False

    def test_name_longer_than_253_is_refused_without_running_dig(self, monkeypatch):
        from shared.utils import dig_query, is_valid
        calls = self._install_spy(monkeypatch)
        name = self._dns_name(254)

        res = dig_query(name, "A", 5)

        assert calls == [], f"subprocess.run chiamato per un nome di {len(name)} caratteri"
        assert res and res[0].startswith("ERROR")
        assert is_valid(res) is False

    @pytest.mark.parametrize("rtype", ["A", "TXT", "CAA"])
    def test_refusal_does_not_depend_on_record_type(self, monkeypatch, rtype):
        from shared.utils import dig_query
        calls = self._install_spy(monkeypatch)

        res = dig_query("@evil._domainkey.example.com", rtype, 5)

        assert calls == []
        assert res and res[0].startswith("ERROR")

    @pytest.mark.parametrize("name", [
        "example.com",
        "Example.COM",
        "123.example.com",
        "a-b.example.com",
        "xn--bcher-kva.example",
        "_dmarc.example.com",
        "default._bimi.example.com",
        "s1._domainkey.example.com",
        "k1.mail._domainkey.example.com",
        "SeLeCtOr._domainkey.example.com",
        "www.example.com",
    ], ids=lambda s: repr(s))
    def test_valid_name_reaches_dig_with_unchanged_argv(self, monkeypatch, name):
        from shared.utils import dig_query
        calls = self._install_spy(monkeypatch)

        dig_query(name, "TXT", 7)

        assert calls == [self._expected_argv(name, "TXT", 7)]

    def test_name_of_exactly_253_characters_still_reaches_dig(self, monkeypatch):
        from shared.utils import dig_query
        calls = self._install_spy(monkeypatch)
        name = self._dns_name(253)

        dig_query(name, "A", 10)

        assert calls == [self._expected_argv(name, "A", 10)]

    def test_valid_name_result_parsing_is_unchanged(self, monkeypatch):
        from shared.utils import dig_query
        self._install_spy(monkeypatch, stdout="b.example.\na.example.\n\n")

        res = dig_query("example.com", "NS", 5)

        assert res == ["a.example", "b.example"]


# ═══════════════════════════════════════════════════════════════
# COL-08 — le righe di diagnostica di `dig +short` non sono record.
# ═══════════════════════════════════════════════════════════════

# stdout / returncode registrati con `dig` 9.18.39 reale, in un network namespace
# isolato con un resolver su loopback (BUG-REGISTER.md, «GATE G2 · COL-08»).
# `dig` scrive le proprie diagnostiche su **stdout**, con prefisso `;; `, anche con
# `+short`. Due eccezioni dichiarate, non catturate da un binario: il testo 9.16
# (`;; connection timed out; no servers could be reached`, da dighost.c) e le
# risposte vuote dopo un tentativo perso (riga `;;` della cattura + stdout vuoto
# di un NODATA, entrambi registrati, composti).
_COL08_LOST_TRY = ";; communications error to 127.0.0.1#53: timed out\n"
_COL08_LOST_TRY_2ND_SERVER = (
    ";; communications error to 127.0.0.3#53: timed out\n"
    ";; communications error to 127.0.0.3#53: timed out\n"
)
_COL08_REFUSED = (
    ";; communications error to 127.0.0.9#53: connection refused\n"
    ";; communications error to 127.0.0.9#53: connection refused\n"
    ";; no servers could be reached\n"
)
_COL08_NET_UNREACHABLE = (
    ";; UDP setup with 192.0.2.53#53(192.0.2.53) for normal.test failed: network unreachable.\n"
    ";; no servers could be reached\n"
    ";; UDP setup with 192.0.2.53#53(192.0.2.53) for normal.test failed: network unreachable.\n"
    ";; no servers could be reached\n"
)
_COL08_MUTE_T2 = (
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; no servers could be reached\n"
)
_COL08_ID_MISMATCH_T2 = (
    ";; Warning: ID mismatch: expected ID 20696, got 1421\n"
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; Warning: ID mismatch: expected ID 20696, got 1421\n"
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; no servers could be reached\n"
)
_COL08_BOTH_SERVERS_MUTE = (
    ";; communications error to 127.0.0.3#53: timed out\n"
    ";; communications error to 127.0.0.3#53: timed out\n"
    ";; communications error to 127.0.0.3#53: timed out\n"
    ";; no servers could be reached\n"
)
_COL08_DIG916_TIMEOUT = ";; connection timed out; no servers could be reached\n"


def _col08_run_dig_query(monkeypatch, rtype, stdout, returncode=0, raises=None):
    """Esegue `dig_query` con `subprocess.run` sostituito: nessun `dig`, nessuna rete.
    Ritorna (risultato, lista degli argv con cui lo spy è stato chiamato)."""
    import shared.utils as u
    calls = []

    def _spy(argv, *args, **kwargs):
        calls.append(list(argv))
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(u.subprocess, "run", _spy)
    return u.dig_query("example.com", rtype, 10), calls


class TestCOL08DigDiagnosticLines:
    """`dig_query` deve restituire solo record DNS. Le righe che `dig` scrive su
    stdout per raccontare i propri guasti (`;; communications error …`,
    `;; no servers could be reached`) non lo sono, e un `returncode` diverso da 0
    significa «nessuna risposta», non «record vuoti»: è un errore, nella forma
    già usata per il timeout (primo elemento `ERROR…`, quindi `is_valid` falso).

    Criteri C1-C3 di BUG-REGISTER.md («ASSEGNA · COL-08 · criteri fissati»)."""

    # ── C1 — rc 0: la riga `;;` di un tentativo perso accompagna una risposta vera ──

    @pytest.mark.parametrize("rtype, noisy, clean, expected", [
        pytest.param(
            "A",
            _COL08_LOST_TRY + "192.0.2.10\n192.0.2.11\n",
            "192.0.2.10\n192.0.2.11\n",
            ["192.0.2.10", "192.0.2.11"],
            id="A-first-attempt-lost"),
        pytest.param(
            "MX",
            _COL08_LOST_TRY + "10 mail.retry.test.\n",
            "10 mail.retry.test.\n",
            ["10 mail.retry.test"],
            id="MX-first-attempt-lost"),
        pytest.param(
            "TXT",
            _COL08_LOST_TRY + '"v=spf1 -all"\n"hello world"\n',
            '"v=spf1 -all"\n"hello world"\n',
            ['"hello world"', '"v=spf1 -all"'],
            id="TXT-first-attempt-lost"),
        pytest.param(
            "A",
            _COL08_LOST_TRY_2ND_SERVER + "192.0.2.10\n192.0.2.11\n",
            "192.0.2.10\n192.0.2.11\n",
            ["192.0.2.10", "192.0.2.11"],
            id="A-first-server-mute-second-answers"),
    ])
    def test_diagnostic_line_next_to_real_records_is_dropped(
            self, monkeypatch, rtype, noisy, clean, expected):
        got, _ = _col08_run_dig_query(monkeypatch, rtype, noisy, returncode=0)
        without_noise, _ = _col08_run_dig_query(monkeypatch, rtype, clean, returncode=0)

        assert got == expected, f"record restituiti: {got!r}"
        assert got == without_noise, "la riga di diagnostica ha cambiato il risultato"
        assert is_valid(got) is True

    # ── C2 — rc != 0: nessuna risposta → errore, non record ──

    NO_ANSWER_CASES = [
        pytest.param(9, _COL08_REFUSED, id="connection-refused"),
        pytest.param(9, _COL08_NET_UNREACHABLE, id="network-unreachable"),
        pytest.param(9, _COL08_MUTE_T2, id="resolver-mute-9.18"),
        pytest.param(9, _COL08_BOTH_SERVERS_MUTE, id="both-servers-mute"),
        pytest.param(9, _COL08_ID_MISMATCH_T2, id="id-mismatch-then-no-servers"),
        pytest.param(9, _COL08_DIG916_TIMEOUT, id="resolver-mute-9.16"),
    ]

    @pytest.mark.parametrize("returncode, stdout", NO_ANSWER_CASES)
    def test_exit_without_answer_returns_an_error_marker(self, monkeypatch, returncode, stdout):
        got, calls = _col08_run_dig_query(monkeypatch, "A", stdout, returncode=returncode)

        assert len(calls) == 1, "lo spy di subprocess.run non è stato raggiunto"
        assert got and got[0].startswith("ERROR"), f"primo elemento non ERROR: {got!r}"
        assert is_valid(got) is False, f"is_valid accetta {got!r}"

    @pytest.mark.parametrize("returncode, stdout", NO_ANSWER_CASES)
    def test_exit_without_answer_exposes_no_diagnostic_line(self, monkeypatch, returncode, stdout):
        got, _ = _col08_run_dig_query(monkeypatch, "A", stdout, returncode=returncode)

        assert all(not item.startswith(";") for item in got), f"riga di diagnostica restituita: {got!r}"
        # Il messaggio d'errore è breve e proprio: non riecheggia lo stdout di `dig`.
        echoed = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        assert not any(ln in item for ln in echoed for item in got), f"stdout riecheggiato in {got!r}"
        assert not any(";;" in item for item in got), f"prefisso ';;' in {got!r}"

    @pytest.mark.parametrize("returncode", [1, 10], ids=["rc1-usage", "rc10-fatal"])
    def test_nonzero_exit_with_empty_stdout_returns_an_error_marker(self, monkeypatch, returncode):
        got, calls = _col08_run_dig_query(monkeypatch, "A", "", returncode=returncode)

        assert len(calls) == 1, "lo spy di subprocess.run non è stato raggiunto"
        assert got and got[0].startswith("ERROR"), f"rc {returncode} → {got!r}"
        assert is_valid(got) is False

    # ── C3 — rc 0 con sole righe `;`: una risposta vera, vuota ──

    @pytest.mark.parametrize("stdout", [
        pytest.param(_COL08_LOST_TRY, id="one-lost-attempt-then-empty-answer"),
        pytest.param(_COL08_LOST_TRY_2ND_SERVER, id="first-server-mute-then-empty-answer"),
    ])
    def test_only_diagnostic_lines_with_rc0_is_an_empty_answer(self, monkeypatch, stdout):
        got, _ = _col08_run_dig_query(monkeypatch, "A", stdout, returncode=0)

        assert got == [], f"restituito {got!r}"
        assert is_valid(got) is False


class TestCOL08DigNormalOutputUnchanged:
    """C4 — invarianti: l'output normale di `dig +short`, le sue eccezioni di
    sintassi e i rami d'errore storici non cambiano. In particolare un `;` dentro
    il contenuto di un record (TXT tra virgolette) non è una riga di
    diagnostica: `dig` stampa il `;` non quotato solo come commento."""

    @pytest.mark.parametrize("rtype, stdout, expected", [
        pytest.param("A", "192.0.2.11\n192.0.2.10\n", ["192.0.2.10", "192.0.2.11"], id="A-multiple-sorted"),
        pytest.param("AAAA", "2001:db8::1\n", ["2001:db8::1"], id="AAAA"),
        pytest.param("MX", "10 mail.normal.test.\n", ["10 mail.normal.test"], id="MX"),
        pytest.param("NS", "ns2.normal.test.\nns1.normal.test.\n",
                     ["ns1.normal.test", "ns2.normal.test"], id="NS-sorted"),
        pytest.param("TXT", '"v=spf1 -all"\n"hello world"\n',
                     ['"hello world"', '"v=spf1 -all"'], id="TXT-multiple"),
        pytest.param("TXT", '"v=DKIM1; k=rsa; p=AB"\n',
                     ['"v=DKIM1; k=rsa; p=AB"'], id="TXT-semicolons-inside"),
        pytest.param("TXT", '"; leading"\n', ['"; leading"'], id="TXT-content-starting-with-semicolon"),
        pytest.param("TXT", '"first part" "; second part"\n',
                     ['"first part" "; second part"'], id="TXT-multistring-semicolon-in-2nd-string"),
        pytest.param("CAA", '0 issue "letsencrypt.org"\n',
                     ['0 issue "letsencrypt.org"'], id="CAA"),
        pytest.param("SOA", "ns1.normal.test. hostmaster.normal.test. 2026010101 7200 900 1209600 3600\n",
                     ["ns1.normal.test. hostmaster.normal.test. 2026010101 7200 900 1209600 3600"], id="SOA"),
        pytest.param("A", "target.normal.test.\n192.0.2.20\n",
                     ["192.0.2.20", "target.normal.test"], id="CNAME-then-A"),
        pytest.param("CNAME", "target.normal.test.\n", ["target.normal.test"], id="CNAME"),
    ])
    def test_normal_output_is_returned_unchanged(self, monkeypatch, rtype, stdout, expected):
        got, _ = _col08_run_dig_query(monkeypatch, rtype, stdout, returncode=0)

        assert got == expected
        assert is_valid(got) is True

    @pytest.mark.parametrize("stdout", ["", "\n"], ids=["empty", "blank-line"])
    def test_empty_answer_with_rc0_is_an_empty_list(self, monkeypatch, stdout):
        # NXDOMAIN, NODATA, SERVFAIL, REFUSED e FORMERR escono tutti da `dig` con
        # rc 0 e stdout vuoto: restano «nessun record», non un errore.
        got, _ = _col08_run_dig_query(monkeypatch, "A", stdout, returncode=0)

        assert got == []
        assert is_valid(got) is False

    def test_timeout_still_returns_the_timeout_error(self, monkeypatch):
        got, _ = _col08_run_dig_query(
            monkeypatch, "A", "", raises=subprocess.TimeoutExpired(["dig"], 20))

        assert got == ["ERROR: timeout"]

    def test_missing_dig_binary_still_returns_the_dig_not_found_error(self, monkeypatch):
        got, _ = _col08_run_dig_query(monkeypatch, "A", "", raises=FileNotFoundError("dig"))

        assert got == ["ERROR: dig not found"]

    def test_unexpected_exception_still_returns_an_error_marker(self, monkeypatch):
        got, _ = _col08_run_dig_query(monkeypatch, "A", "", raises=RuntimeError("boom"))

        assert got and got[0].startswith("ERROR")
        assert is_valid(got) is False


# ═══════════════════════════════════════════════════════════════
# COL-08 (giro correttivo, C7) — il dump esadecimale di `;; Got bad packet`.
# ═══════════════════════════════════════════════════════════════

# Anche questo è stdout di `dig` 9.18.39 reale (rc 0, catturato dal verifier in un
# network namespace isolato, con uno stub su loopback che serve una risposta non
# parsabile). Il testo `;; Got bad packet: %s` è identico in dighost.c 9.16/9.18/9.20.
# Solo la prima riga inizia con `;`: «N bytes» e il dump esadecimale no.
_COL08_BADPKT_CAA_TAG = (
    ";; Got bad packet: FORMERR\n"
    "53 bytes\n"
    "95 f0 85 80 00 01 00 01 00 00 00 00 0a 63 61 61          .............caa\n"
    "5f 62 61 64 74 61 67 01 67 04 74 65 73 74 00 01          _badtag.g.test..\n"
    "01 00 01 c0 0c 01 01 00 01 00 00 00 3c 00 06 00          ............<...\n"
    "03 3b 3b 3b 76                                           .;;;v\n"
)
_COL08_BADPKT_CAA_TAGLEN = (
    ";; Got bad packet: FORMERR\n"
    "63 bytes\n"
    "3e 1b 85 80 00 01 00 01 00 00 00 00 13 63 61 61          >............caa\n"
    "5f 74 61 67 6c 65 6e 5f 6f 76 65 72 66 6c 6f 77          _taglen_overflow\n"
    "01 67 04 74 65 73 74 00 01 01 00 01 c0 0c 01 01          .g.test.........\n"
    "00 01 00 00 00 3c 00 07 00 c8 69 73 73 75 65             .....<....issue\n"
)
_COL08_BADPKT_CNAME_LABEL = (
    ";; Got bad packet: bad label type\n"
    "116 bytes\n"
    "b0 6f 85 80 00 01 00 01 00 00 00 00 0e 63 6e 61          .o...........cna\n"
    "6d 65 5f 62 61 64 6c 61 62 65 6c 01 67 04 74 65          me_badlabel.g.te\n"
    "73 74 00 00 05 00 01 c0 0c 00 05 00 01 00 00 00          st..............\n"
    "3c 00 41 40 61 61 61 61 61 61 61 61 61 61 61 61          <.A@aaaaaaaaaaaa\n"
    "61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61          aaaaaaaaaaaaaaaa\n"
    "61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61          aaaaaaaaaaaaaaaa\n"
    "61 61 61 61 61 61 61 61 61 61 61 61 61 61 61 61          aaaaaaaaaaaaaaaa\n"
    "61 61 61 00                                              aaa.\n"
)
# Catturato con una query NAPTR; il tipo passato a `dig_query` nei test è irrilevante
# per lo spy ed è uno dei tipi che il servizio interroga davvero.
_COL08_BADPKT_NAPTR_SYNTAX = (
    ";; Got bad packet: syntax error\n"
    "110 bytes\n"
    "a3 82 85 80 00 01 00 02 00 00 00 00 05 6e 61 70          .............nap\n"
    "74 72 06 6d 61 74 72 69 78 04 74 65 73 74 00 00          tr.matrix.test..\n"
    "23 00 01 c0 0c 00 23 00 01 00 00 00 3c 00 21 00          #.....#.....<.!.\n"
    "64 00 0a 01 53 07 53 49 50 2b 44 32 55 00 04 5f          d...S.SIP+D2U.._\n"
    "73 69 70 04 5f 75 64 70 01 78 04 74 65 73 74 00          sip._udp.x.test.\n"
    "c0 0c 00 23 00 01 00 00 00 3c 00 12 00 64 00 0a          ...#.....<...d..\n"
    "01 3b 01 3b 01 3b 01 78 04 74 65 73 74 00                .;.;.;.x.test.\n"
)
_COL08_ID_MISMATCH_LEADING = ";; Warning: ID mismatch: expected ID 19636, got 4661\n"


class TestCOL08DigBadPacketDump:
    """C7 — una risposta che `dig` non riesce a parsare esce con `rc 0`: prima la
    riga `;; Got bad packet: <motivo>`, poi `N bytes` e un dump esadecimale che
    **non** inizia con `;`. Non è una risposta: è «non si è potuto sapere», quindi
    un errore (primo elemento `ERROR…`, `is_valid` falso), senza che righe del dump
    né il testo di `dig` finiscano nel risultato o nel messaggio."""

    BAD_PACKET_CASES = [
        pytest.param("CAA", _COL08_BADPKT_CAA_TAG, id="CAA-invalid-tag-FORMERR"),
        pytest.param("CAA", _COL08_BADPKT_CAA_TAGLEN, id="CAA-tag-length-overflow-FORMERR"),
        pytest.param("CNAME", _COL08_BADPKT_CNAME_LABEL, id="CNAME-bad-label-type"),
        pytest.param("TXT", _COL08_BADPKT_NAPTR_SYNTAX, id="other-reason-syntax-error"),
        # Composto da due frammenti reali: il primo server muto stampa le sue righe
        # prima che il secondo risponda con il pacchetto non parsabile.
        pytest.param("CAA", _COL08_LOST_TRY_2ND_SERVER + _COL08_BADPKT_CAA_TAG,
                     id="CAA-first-server-mute-then-bad-packet"),
    ]

    @pytest.mark.parametrize("rtype, stdout", BAD_PACKET_CASES)
    def test_bad_packet_with_rc0_returns_an_error_marker(self, monkeypatch, rtype, stdout):
        got, calls = _col08_run_dig_query(monkeypatch, rtype, stdout, returncode=0)

        assert len(calls) == 1, "lo spy di subprocess.run non è stato raggiunto"
        assert got and got[0].startswith("ERROR"), f"primo elemento non ERROR: {got[:2]!r}"
        assert is_valid(got) is False, f"is_valid accetta {got[:2]!r}"

    @pytest.mark.parametrize("rtype, stdout", BAD_PACKET_CASES)
    def test_bad_packet_exposes_neither_dump_lines_nor_dig_text(self, monkeypatch, rtype, stdout):
        got, _ = _col08_run_dig_query(monkeypatch, rtype, stdout, returncode=0)

        assert all(item.startswith("ERROR") for item in got), f"elementi non ERROR: {got[:3]!r}"
        echoed = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        assert not any(ln in item for ln in echoed for item in got), f"stdout riecheggiato in {got[:3]!r}"
        assert not any(";;" in item for item in got), f"prefisso ';;' in {got[:3]!r}"


class TestCOL08DigFilterBoundaries:
    """Confini del filtro di COL-08: cosa va scartato (righe che dopo `strip()`
    iniziano con `;`, in qualunque posizione e con qualunque rientro), cosa deve
    sopravvivere (ogni rdata che inizia con altro, compreso `\\;` di un nome con
    `;` in una label e `\\#` dei tipi ignoti) e che un `returncode` diverso da 0
    — negativo compreso — prevale sulle righe che sembrano record.

    Fixture reali di `dig` 9.18.39, salvo dove dichiarato «composto»."""

    # ── returncode ──

    @pytest.mark.parametrize("returncode, stdout", [
        pytest.param(-9, "", id="rc-9-SIGKILL-no-output"),
        pytest.param(-11, "", id="rc-11-SIGSEGV-no-output"),
        # Un processo ucciso a metà ha scritto una parte dell'output: non è fidabile.
        pytest.param(-9, "192.0.2.10\n", id="rc-9-SIGKILL-partial-output"),
        pytest.param(-11, _COL08_LOST_TRY + "192.0.2.10\n", id="rc-11-SIGSEGV-partial-output"),
    ])
    def test_negative_returncode_is_an_error_marker(self, monkeypatch, returncode, stdout):
        got, _ = _col08_run_dig_query(monkeypatch, "A", stdout, returncode=returncode)

        assert got and all(item.startswith("ERROR") for item in got), f"rc {returncode} → {got!r}"
        assert is_valid(got) is False

    @pytest.mark.parametrize("returncode, stdout", [
        # Composti: l'uscita non-zero reale di `dig` non porta righe di record, ma
        # l'esito non deve dipendere dal fatto che lo stdout «sembri» una risposta.
        pytest.param(9, _COL08_LOST_TRY + "192.0.2.10\n", id="rc9-diagnostic-then-record"),
        pytest.param(9, "192.0.2.10\n192.0.2.11\n", id="rc9-records-only"),
        pytest.param(1, "192.0.2.10\n", id="rc1-record"),
        pytest.param(10, _COL08_MUTE_T2 + "10 mail.retry.test.\n", id="rc10-diagnostics-then-MX"),
    ])
    def test_nonzero_exit_prevails_over_lines_that_look_like_records(
            self, monkeypatch, returncode, stdout):
        got, _ = _col08_run_dig_query(monkeypatch, "A", stdout, returncode=returncode)

        assert got and all(item.startswith("ERROR") for item in got), f"rc {returncode} → {got!r}"
        assert is_valid(got) is False
        echoed = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
        assert not any(ln in item for ln in echoed for item in got), f"stdout riecheggiato in {got!r}"

    # ── righe `;` da scartare ──

    @pytest.mark.parametrize("stdout, expected", [
        # Posizioni composte da frammenti reali: `dig` ne ha catturate solo in testa.
        pytest.param("192.0.2.10\n" + _COL08_LOST_TRY + "192.0.2.11\n",
                     ["192.0.2.10", "192.0.2.11"], id="between-records"),
        pytest.param("192.0.2.10\n192.0.2.11\n" + _COL08_LOST_TRY,
                     ["192.0.2.10", "192.0.2.11"], id="after-records"),
        pytest.param(_COL08_LOST_TRY + "192.0.2.10\n" + _COL08_ID_MISMATCH_LEADING
                     + "192.0.2.11\n" + _COL08_LOST_TRY,
                     ["192.0.2.10", "192.0.2.11"], id="before-between-and-after"),
        pytest.param(_COL08_ID_MISMATCH_LEADING + "192.0.2.10\n",
                     ["192.0.2.10"], id="real-id-mismatch-before-answer"),
        # `puts("; Transfer failed.")` di dighost.c: stdout, un solo `;`.
        pytest.param("; Transfer failed.\n192.0.2.10\n",
                     ["192.0.2.10"], id="single-semicolon-dig-line"),
    ])
    def test_semicolon_lines_are_dropped_wherever_they_are(self, monkeypatch, stdout, expected):
        got, _ = _col08_run_dig_query(monkeypatch, "A", stdout, returncode=0)

        assert got == expected, f"restituito {got!r}"
        assert is_valid(got) is True

    @pytest.mark.parametrize("indent", ["   ", "\t", " \t ", "        "],
                             ids=["spaces", "tab", "space-tab-space", "eight-spaces"])
    def test_indented_semicolon_line_is_dropped(self, monkeypatch, indent):
        stdout = indent + _COL08_LOST_TRY + "192.0.2.10\n" + indent + ";; no servers could be reached\n"

        got, _ = _col08_run_dig_query(monkeypatch, "A", stdout, returncode=0)

        assert got == ["192.0.2.10"], f"restituito {got!r}"

    # ── righe che NON iniziano con `;`: restano record ──

    @pytest.mark.parametrize("rtype, stdout, expected", [
        pytest.param("NS", "\\;ns1.x.test.\nns2.\\;x.test.\n\\032sp.test.\n",
                     ["\\032sp.test", "\\;ns1.x.test", "ns2.\\;x.test"], id="NS-semicolon-in-label"),
        pytest.param("MX", "10 \\;mx.test.\n20 a\\;b.test.\n",
                     ["10 \\;mx.test", "20 a\\;b.test"], id="MX-semicolon-in-label"),
        pytest.param("CNAME", "\\;evil.test.\n",
                     ["\\;evil.test"], id="CNAME-leading-escaped-semicolon"),
        pytest.param("SOA", "\\;m.test. \\;r.test. 1 7200 900 1209600 3600\n",
                     ["\\;m.test. \\;r.test. 1 7200 900 1209600 3600"], id="SOA-escaped-semicolons"),
        # Catturato con una query TYPE65400 (tipo ignoto, rdata `;;;`): formato RFC 3597.
        pytest.param("TXT", "\\# 3 3B3B3B\n", ["\\# 3 3B3B3B"], id="unknown-type-rfc3597"),
        # Sintetico: nessun tipo noto stampa una riga che inizia con `#`. Fissa che il
        # filtro guarda solo `;`, non un insieme più largo di prefissi «da commento».
        pytest.param("TXT", "# not a dig diagnostic\n", ["# not a dig diagnostic"], id="hash-prefix-synthetic"),
    ])
    def test_record_not_starting_with_a_semicolon_is_kept(self, monkeypatch, rtype, stdout, expected):
        got, _ = _col08_run_dig_query(monkeypatch, rtype, stdout, returncode=0)

        assert got == expected, f"restituito {got!r}"
        assert is_valid(got) is True


class TestCOL08DigBadPacketAnchoring:
    """Ancoraggio della regola `;; Got bad packet` → errore. La regola riguarda la
    riga che `dig` stampa per un pacchetto non parsabile, cioè una riga che
    **inizia** con quel testo. Un rdata il cui *contenuto* è quel testo esce da
    `dig` con un altro primo carattere (le virgolette di un TXT o di un CAA, il
    `\\;` di una label) e resta un record: errore o scarto qui farebbero sparire
    dati veri, e chi controlla il DNS di un dominio può scriverli a piacere.

    Stdout reale di `dig` 9.18.39 (`rc 0`, stub su loopback in un network
    namespace isolato) con rdata il cui testo è `;; Got bad packet: FORMERR`."""

    @pytest.mark.parametrize("rtype, stdout, expected", [
        pytest.param(
            "TXT",
            '";; Got bad packet: FORMERR"\n"v=spf1 -all"\n',
            ['";; Got bad packet: FORMERR"', '"v=spf1 -all"'],
            id="TXT-quoted-banner-next-to-a-real-record"),
        pytest.param(
            "TXT",
            '";; Got bad packet: FORMERR"\n'
            '"x\\010;; Got bad packet: FORMERR"\n'
            '"  ;; Got bad packet: FORMERR"\n'
            '"ok" ";; Got bad packet: FORMERR"\n',
            ['"  ;; Got bad packet: FORMERR"',
             '";; Got bad packet: FORMERR"',
             '"ok" ";; Got bad packet: FORMERR"',
             '"x\\010;; Got bad packet: FORMERR"'],
            id="TXT-banner-quoted-embedded-indented-and-second-string"),
        pytest.param(
            "CAA",
            '0 issue ";; Got bad packet: FORMERR"\n',
            ['0 issue ";; Got bad packet: FORMERR"'],
            id="CAA-value-is-the-banner"),
        pytest.param(
            "NS",
            "\\;\\;\\032Got\\032bad\\032packet:\\032FORMERR.test.\n"
            "\\;.\\;.Got\\032bad\\032packet.test.\n",
            ["\\;.\\;.Got\\032bad\\032packet.test",
             "\\;\\;\\032Got\\032bad\\032packet:\\032FORMERR.test"],
            id="NS-label-is-the-banner"),
        pytest.param(
            "CNAME",
            "\\;\\;\\032Got\\032bad\\032packet:\\032FORMERR.test.\n",
            ["\\;\\;\\032Got\\032bad\\032packet:\\032FORMERR.test"],
            id="CNAME-label-is-the-banner"),
        pytest.param(
            "MX",
            "10 a.test.\n20 \\;\\;\\032Got\\032bad\\032packet:\\032FORMERR.test.\n",
            ["10 a.test", "20 \\;\\;\\032Got\\032bad\\032packet:\\032FORMERR.test"],
            id="MX-label-is-the-banner"),
    ])
    def test_rdata_whose_text_mimics_the_bad_packet_banner_stays_a_record(
            self, monkeypatch, rtype, stdout, expected):
        got, _ = _col08_run_dig_query(monkeypatch, rtype, stdout, returncode=0)

        assert got == expected, f"restituito {got!r}"
        assert is_valid(got) is True


# ═══════════════════════════════════════════════════════════════
# RES-01 (nucleo) — `dig_lookup`: ogni query DNS ha uno stato, non solo una lista.
# ═══════════════════════════════════════════════════════════════
#
# Contratto (BUG-REGISTER.md, «ASSEGNA · RES-01 (nucleo) · criteri», R1-R4):
# `dig_lookup(fqdn, rtype, timeout=10) -> (status, records)` con `status` in
# `ok` / `nodata` / `nxdomain` / `unknown`. `dig_query` (`+short`) non vede lo
# `status:` della risposta: NODATA, NXDOMAIN, SERVFAIL, REFUSED, FORMERR e NOTIMP
# escono tutti da `dig` come stdout vuoto e rc 0, cioè `[]`. `dig_lookup` lancia
# `dig +noall +comments +answer +nottlid +noclass`, che stampa la testata
# (`;; ->>HEADER<<- opcode: QUERY, status: X, id: N`), la riga
# `;; flags: … ANSWER: N, …` e le righe `owner TYPE rdata`.
#
# Isolamento: `subprocess.run` è sostituito da uno spy; nessun `dig` reale, nessuna rete.
#
# Fixture. Gli stdout sono registrati con `dig` 9.18.39 reale (rc 0 salvo dove
# dichiarato) in un network namespace con la sola interfaccia `lo` (`unshare -n -m`,
# `/proc/net/route` vuoto), `resolv.conf` privato al mount namespace e uno stub DNS
# su loopback, con l'argv di `dig_lookup` e `+time=2`:
#   * `_RES01_CORPUS` — 54 casi del bug-researcher (`COL-02` G2): lo stdout nel formato
#     nuovo e, come oracolo, ciò che `+short` + filtro davano sulla stessa risposta;
#   * `_RES01_FORGE_*` — owner, rdata CNAME, TXT e CAA che imitano la testata, la riga
#     `flags`, `Got bad packet` e `Warning: Message parser…`;
#   * `_RES01_RETRY_*`, `_RES01_SECOND_SERVER_ANSWERS_A` — primo tentativo o primo server
#     persi, poi la risposta;
#   * `_RES01_YXDOMAIN_A`, `_RES01_NOTAUTH_A`, `_RES01_RESERVED1x_A` — rcode che `/dns`
#     non provoca mai ma che un resolver può restituire;
#   * `_RES01_RC9_*` — i guasti di trasporto (rc 9, TCP muto compreso).
# Il testo della testata e della riga `flags` è identico in `dig` 9.16, 9.18 e 9.20
# (stringhe di `dns_message_headertotext`, `lib/dns/message.c`, confrontate dal researcher).
#
# Fixture COMPOSTE (dichiarate: `dig` non le produce in condizioni normali): due
# testate, testata senza `flags`, `ANSWER: N` diverso dal numero di righe, riga di
# risposta con meno di tre campi, `opcode` diverso da QUERY, rcode che nessun resolver
# restituisce, rc 1/10/negativi con uno stdout che sembra una risposta valida. Sono
# costruite con `_res01_stdout`, la cui fedeltà alle catture reali è verificata da
# `TestRES01FixtureSelfCheck`, oppure modificando una cattura reale con `str.replace`
# (la modifica è nel nome del caso).

_RES01_CORPUS = [
    ("normal.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8329\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "normal.test.\t\tA\t192.0.2.10\n"
        "normal.test.\t\tA\t192.0.2.11\n"
        "\n"
    ), "ok", ["192.0.2.10", "192.0.2.11"]),
    ("normal.test", "AAAA", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41238\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "normal.test.\t\tAAAA\t2001:db8::1\n"
        "\n"
    ), "ok", ["2001:db8::1"]),
    ("normal.test", "MX", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40526\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "normal.test.\t\tMX\t10 mail.normal.test.\n"
        "\n"
    ), "ok", ["10 mail.normal.test"]),
    ("normal.test", "NS", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61576\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "normal.test.\t\tNS\tns1.normal.test.\n"
        "normal.test.\t\tNS\tns2.normal.test.\n"
        "\n"
    ), "ok", ["ns1.normal.test", "ns2.normal.test"]),
    ("normal.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13007\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        'normal.test.\t\tTXT\t"v=spf1 -all"\n'
        'normal.test.\t\tTXT\t"hello world"\n'
        "\n"
    ), "ok", ['"hello world"', '"v=spf1 -all"']),
    ("normal.test", "CAA", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2246\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        'normal.test.\t\tCAA\t0 issue "letsencrypt.org"\n'
        "\n"
    ), "ok", ['0 issue "letsencrypt.org"']),
    ("normal.test", "SOA", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 14111\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "normal.test.\t\tSOA\tns1.normal.test. hostmaster.normal.test. 2026010101 7200 900 1209600 3600\n"
        "\n"
    ), "ok", ["ns1.normal.test. hostmaster.normal.test. 2026010101 7200 900 1209600 3600"]),
    ("normal.test", "CNAME", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11192\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nodata", []),
    ("multi.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58943\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "multi.test.\t\tA\t192.0.2.3\n"
        "multi.test.\t\tA\t192.0.2.1\n"
        "multi.test.\t\tA\t192.0.2.2\n"
        "\n"
    ), "ok", ["192.0.2.1", "192.0.2.2", "192.0.2.3"]),
    ("multi.test", "MX", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45315\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "multi.test.\t\tMX\t20 mx2.example.test.\n"
        "multi.test.\t\tMX\t10 mx1.example.test.\n"
        "multi.test.\t\tMX\t5 a.mx0.example.test.\n"
        "\n"
    ), "ok", ["10 mx1.example.test", "20 mx2.example.test", "5 a.mx0.example.test"]),
    ("multi.test", "NS", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12494\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "multi.test.\t\tNS\tns3.example.test.\n"
        "multi.test.\t\tNS\tns1.example.test.\n"
        "multi.test.\t\tNS\tns2.example.test.\n"
        "\n"
    ), "ok", ["ns1.example.test", "ns2.example.test", "ns3.example.test"]),
    ("multi.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 6367\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        'multi.test.\t\tTXT\t"v=spf1 mx -all"\n'
        'multi.test.\t\tTXT\t"v=DMARC1; p=reject"\n'
        'multi.test.\t\tTXT\t"quote\\"inside" "back\\\\slash"\n'
        "\n"
    ), "ok", ['"quote\\"inside" "back\\\\slash"', '"v=DMARC1; p=reject"', '"v=spf1 mx -all"']),
    ("multi.test", "CAA", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51803\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        'multi.test.\t\tCAA\t0 issue "letsencrypt.org"\n'
        'multi.test.\t\tCAA\t0 iodef "mailto:sec@example.test"\n'
        'multi.test.\t\tCAA\t128 issuewild ";"\n'
        "\n"
    ), "ok", ['0 iodef "mailto:sec@example.test"', '0 issue "letsencrypt.org"', '128 issuewild ";"']),
    ("multi.test", "SOA", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40669\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "multi.test.\t\tSOA\tns1.multi.test. hostmaster.multi.test. 2026010101 7200 900 1209600 3600\n"
        "\n"
    ), "ok", ["ns1.multi.test. hostmaster.multi.test. 2026010101 7200 900 1209600 3600"]),
    ("_dmarc.normal.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 43709\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        '_dmarc.normal.test.\tTXT\t"v=DMARC1; p=none"\n'
        "\n"
    ), "ok", ['"v=DMARC1; p=none"']),
    ("default._bimi.normal.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18988\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        'default._bimi.normal.test. TXT\t"v=BIMI1; l=https://example.invalid/logo.svg"\n'
        "\n"
    ), "ok", ['"v=BIMI1; l=https://example.invalid/logo.svg"']),
    ("google._domainkey.normal.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 6775\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        'google._domainkey.normal.test. TXT "v=DKIM1; k=rsa; p=ABC"\n'
        "\n"
    ), "ok", ['"v=DKIM1; k=rsa; p=ABC"']),
    ("foo._domainkey.normal.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38014\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nodata", []),
    ("longtxt.test", "TXT", "".join([
        ";; Got answer:\n",
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25487\n",
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n",
        "\n",
        ";; OPT PSEUDOSECTION:\n",
        "; EDNS: version: 0, flags:; udp: 1232\n",
        ";; ANSWER SECTION:\n",
        ('longtxt.test.\t\tTXT\t"' + "A" * 255 + '" "' + "B" * 255 + '" "' + "C" * 90 + '"\n'),
        'longtxt.test.\t\tTXT\t"v=spf1 -all"\n',
        "\n",
    ]), "ok", [('"' + "A" * 255 + '" "' + "B" * 255 + '" "' + "C" * 90 + '"'), '"v=spf1 -all"']),
    ("multitxt.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27628\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        'multitxt.test.\t\tTXT\t"v=spf1 include:_spf.example.net " "include:_spf.example.org " "-all"\n'
        'multitxt.test.\t\tTXT\t"google-site-verification=abcDEF123"\n'
        'multitxt.test.\t\tTXT\t"a" "" "b"\n'
        "\n"
    ), "ok", ['"a" "" "b"', '"google-site-verification=abcDEF123"', '"v=spf1 include:_spf.example.net " "include:_spf.example.org " "-all"']),
    ("apos.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36546\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "apos.test.\t\tTXT\t\"it's 'quoted' \\\"ok\\\"\"\n"
        "apos.test.\t\tTXT\t\"a''b\" \"'\"\n"
        "\n"
    ), "ok", ["\"a''b\" \"'\"", "\"it's 'quoted' \\\"ok\\\"\""]),
    ("special.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7961\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        'special.test.\t\tTXT\t"; leading semicolon"\n'
        'special.test.\t\tTXT\t";; double"\n'
        'special.test.\t\tTXT\t"abc" ";def"\n'
        'special.test.\t\tTXT\t"line1\\010line2;x"\n'
        'special.test.\t\tTXT\t"quote\\"and\\\\backslash;"\n'
        'special.test.\t\tTXT\t""\n'
        "\n"
    ), "ok", ['""', '"; leading semicolon"', '";; double"', '"abc" ";def"', '"line1\\010line2;x"', '"quote\\"and\\\\backslash;"']),
    ("special.test", "CAA", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41720\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        'special.test.\t\tCAA\t0 issue ";"\n'
        'special.test.\t\tCAA\t128 issue ";policy=x"\n'
        'special.test.\t\tCAA\t0 iodef "mailto:a;b@example.invalid"\n'
        "\n"
    ), "ok", ['0 iodef "mailto:a;b@example.invalid"', '0 issue ";"', '128 issue ";policy=x"']),
    ("special.test", "MX", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54788\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "special.test.\t\tMX\t10 \\;foo.example.invalid.\n"
        "special.test.\t\tMX\t20 \\;\\;bar.example.invalid.\n"
        "\n"
    ), "ok", ["10 \\;foo.example.invalid", "20 \\;\\;bar.example.invalid"]),
    ("special.test", "NS", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32336\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "special.test.\t\tNS\t\\;foo.example.invalid.\n"
        "special.test.\t\tNS\t\\;\\;bar.example.invalid.\n"
        "\n"
    ), "ok", ["\\;\\;bar.example.invalid", "\\;foo.example.invalid"]),
    ("special.test", "CNAME", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 60375\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "special.test.\t\tCNAME\t\\;foo.example.invalid.\n"
        "\n"
    ), "ok", ["\\;foo.example.invalid"]),
    ("special.test", "SOA", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45035\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "special.test.\t\tSOA\t\\;foo.example.invalid. \\;adm.example.invalid. 1 2 3 4 5\n"
        "\n"
    ), "ok", ["\\;foo.example.invalid. \\;adm.example.invalid. 1 2 3 4 5"]),
    ("special.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59950\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "special.test.\t\tA\t192.0.2.30\n"
        "\n"
    ), "ok", ["192.0.2.30"]),
    ("www.cname.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52446\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "www.cname.test.\t\tCNAME\ttarget.normal.test.\n"
        "target.normal.test.\tA\t192.0.2.20\n"
        "\n"
    ), "ok", ["192.0.2.20", "target.normal.test"]),
    ("www.cname.test", "MX", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29438\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "www.cname.test.\t\tCNAME\ttarget.normal.test.\n"
        "\n"
    ), "ok", ["target.normal.test"]),
    ("www.cname.test", "CNAME", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7813\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "www.cname.test.\t\tCNAME\ttarget.normal.test.\n"
        "\n"
    ), "ok", ["target.normal.test"]),
    ("cnamenx.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 37093\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "cnamenx.test.\t\tCNAME\tgone.nxdomain.test.\n"
        "\n"
    ), "nxdomain", ["gone.nxdomain.test"]),
    ("cnamenx.test", "MX", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 29219\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "cnamenx.test.\t\tCNAME\tgone.nxdomain.test.\n"
        "\n"
    ), "nxdomain", ["gone.nxdomain.test"]),
    ("cnamenodata.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15685\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "cnamenodata.test.\tCNAME\ttarget.nodata.test.\n"
        "\n"
    ), "ok", ["target.nodata.test"]),
    ("cnamenodata.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2414\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "cnamenodata.test.\tCNAME\ttarget.nodata.test.\n"
        "\n"
    ), "ok", ["target.nodata.test"]),
    ("forge.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51551\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "forge.test.\t\tCNAME\t\\;\\;\\032->>HEADER<<-\\032opcode:\\032QUERY,\\032status:\\032NOERROR,\\032id:\\0321.evil.test.\n"
        "\\;\\;\\032->>HEADER<<-\\032opcode:\\032QUERY,\\032status:\\032NOERROR,\\032id:\\0321.evil.test.\tA 192.0.2.99\n"
        "\n"
    ), "ok", ["192.0.2.99", "\\;\\;\\032->>HEADER<<-\\032opcode:\\032QUERY,\\032status:\\032NOERROR,\\032id:\\0321.evil.test"]),
    ("nodata.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2685\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nodata", []),
    ("nodata.test", "MX", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10449\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nodata", []),
    ("nodata.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9538\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nodata", []),
    ("nxdomain.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 56956\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nxdomain", []),
    ("nxdomain.test", "MX", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 63986\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nxdomain", []),
    ("nxdomain.test", "TXT", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 32199\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nxdomain", []),
    ("servfail.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 13358\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "unknown", []),
    ("refused.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 13353\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "unknown", []),
    ("formerr.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: FORMERR, id: 62319\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "unknown", []),
    ("notimp.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOTIMP, id: 20623\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "unknown", []),
    ("nxede.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 19272\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        "; EDE: 22 (No Reachable Authority): (No Reachable Authority)\n"
    ), "nxdomain", []),
    ("sfede.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 30586\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        "; EDE: 22 (No Reachable Authority): (No Reachable Authority)\n"
    ), "unknown", []),
    ("trunc.test", "A", (
        ";; Truncated, retrying in TCP mode.\n"
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 42067\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "trunc.test.\t\tA\t192.0.2.10\n"
        "trunc.test.\t\tA\t192.0.2.11\n"
        "\n"
    ), "ok", ["192.0.2.10", "192.0.2.11"]),
    ("retry.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19194\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
        ";; ANSWER SECTION:\n"
        "retry.test.\t\tA\t192.0.2.10\n"
        "retry.test.\t\tA\t192.0.2.11\n"
        "\n"
    ), "ok", ["192.0.2.10", "192.0.2.11"]),
    ("retrynx.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 39751\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nxdomain", []),
    ("retrynodata.test", "A", (
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 21718\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
        "\n"
        ";; OPT PSEUDOSECTION:\n"
        "; EDNS: version: 0, flags:; udp: 1232\n"
    ), "nodata", []),
    ("badcaa.test", "CAA", (
        ";; Got bad packet: FORMERR\n"
        "59 bytes\n"
        "15 0c 85 80 00 01 00 01 00 00 00 01 06 62 61 64          .............bad\n"
        "63 61 61 04 74 65 73 74 00 01 01 00 01 c0 0c 01          caa.test........\n"
        "01 00 01 00 00 00 3c 00 07 00 c8 69 73 73 75 65          ......<....issue\n"
        "00 00 29 04 d0 00 00 00 00 00 00                         ..)........\n"
    ), "unknown", None),
    ("badtxt.test", "TXT", (
        ";; Warning: Message parser reports malformed message packet.\n"
        ";; Got answer:\n"
        ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51086\n"
        ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
        ";; WARNING: Message has 15 extra bytes at end\n"
        "\n"
    ), "unknown", []),
]


_RES01_FORGE_BADPACKET_A = (
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58667\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
    ";; ANSWER SECTION:\n"
    "forgebad.test.\t\tCNAME\t\\;\\;\\032Got\\032bad\\032packet:\\032FORMERR.evil.test.\n"
    "\\;\\;\\032Got\\032bad\\032packet:\\032FORMERR.evil.test. A 192.0.2.98\n"
    "\n"
)
_RES01_FORGE_WARNING_A = (
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8589\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
    ";; ANSWER SECTION:\n"
    "forgewarn.test.\t\tCNAME\t\\;\\;\\032Warning:\\032Message\\032parser\\032reports\\032malformed.evil.test.\n"
    "\\;\\;\\032Warning:\\032Message\\032parser\\032reports\\032malformed.evil.test. A 192.0.2.97\n"
    "\n"
)
_RES01_FORGE_FLAGS_A = (
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 64182\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
    ";; ANSWER SECTION:\n"
    "forgeflags.test.\tCNAME\t\\;\\;\\032flags:\\032qr\\032aa\\032rd\\032ra\\;\\032ANSWER:\\0327,\\032x.evil.test.\n"
    "\\;\\;\\032flags:\\032qr\\032aa\\032rd\\032ra\\;\\032ANSWER:\\0327,\\032x.evil.test. A 192.0.2.96\n"
    "\n"
)
_RES01_FORGE_TXT = (
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39074\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
    ";; ANSWER SECTION:\n"
    'forgetxt.test.\t\tTXT\t";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1"\n'
    'forgetxt.test.\t\tTXT\t";; flags: qr aa rd ra; QUERY: 1, ANSWER: 99, AUTHORITY: 0, ADDITIONAL: 0"\n'
    'forgetxt.test.\t\tTXT\t";; Got bad packet: FORMERR"\n'
    'forgetxt.test.\t\tTXT\t";; Warning: Message parser reports malformed message packet."\n'
    'forgetxt.test.\t\tTXT\t"x" ";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 2"\n'
    'forgetxt.test.\t\tTXT\t"v=spf1 -all"\n'
    "\n"
)
_RES01_FORGE_CAA = (
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32227\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
    ";; ANSWER SECTION:\n"
    'forgetxt.test.\t\tCAA\t0 issue ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1"\n'
    'forgetxt.test.\t\tCAA\t0 iodef ";; Got bad packet: FORMERR"\n'
    "\n"
)
_RES01_RETRY_A = (
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 507\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
    ";; ANSWER SECTION:\n"
    "retry.test.\t\tA\t192.0.2.10\n"
    "retry.test.\t\tA\t192.0.2.11\n"
    "\n"
)
_RES01_RETRY_NXDOMAIN_A = (
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 3367\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
)
_RES01_RETRY_NODATA_A = (
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 34184\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
)
_RES01_YXDOMAIN_A = (
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: YXDOMAIN, id: 21132\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
)
_RES01_NOTAUTH_A = (
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOTAUTH, id: 50252\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
)
_RES01_RESERVED11_A = (
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: RESERVED11, id: 46089\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
)
_RES01_RESERVED15_A = (
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: RESERVED15, id: 55468\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
    "\n"
    ";; OPT PSEUDOSECTION:\n"
    "; EDNS: version: 0, flags:; udp: 1232\n"
)
_RES01_RC9_MUTE = (
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; no servers could be reached\n"
)
_RES01_RC9_CONNECTION_REFUSED = (
    ";; communications error to 127.0.0.9#53: connection refused\n"
    ";; communications error to 127.0.0.9#53: connection refused\n"
    ";; no servers could be reached\n"
)
_RES01_RC9_NETWORK_UNREACHABLE = (
    ";; UDP setup with 192.0.2.53#53(192.0.2.53) for normal.test failed: network unreachable.\n"
    ";; no servers could be reached\n"
    ";; UDP setup with 192.0.2.53#53(192.0.2.53) for normal.test failed: network unreachable.\n"
    ";; no servers could be reached\n"
)
_RES01_RC9_ID_MISMATCH = (
    ";; Warning: ID mismatch: expected ID 60917, got 47264\n"
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; Warning: ID mismatch: expected ID 60917, got 47264\n"
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; no servers could be reached\n"
)
_RES01_RC9_TCP_MUTE = (
    ";; Truncated, retrying in TCP mode.\n"
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; communications error to 127.0.0.1#53: timed out\n"
    ";; no servers could be reached\n"
)
_RES01_SECOND_SERVER_ANSWERS_A = (
    ";; communications error to 127.0.0.3#53: timed out\n"
    ";; communications error to 127.0.0.3#53: timed out\n"
    ";; Got answer:\n"
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55144\n"
    ";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0\n"
    "\n"
    ";; ANSWER SECTION:\n"
    "multi.test.\t\tA\t192.0.2.10\n"
    "multi.test.\t\tA\t192.0.2.11\n"
    "\n"
)


# Indice per nome e tipo dei 54 stdout reali, per costruire le fixture composte.
_RES01_STDOUT = {(name, rtype): stdout for name, rtype, stdout, _status, _oracle in _RES01_CORPUS}
_RES01_CORPUS_IDS = [f"{name}-{rtype}" for name, rtype, *_ in _RES01_CORPUS]
# Casi con un oracolo `+short` confrontabile: l'oracolo di `badcaa.test` è un ERROR, non un risultato.
_RES01_WITH_ORACLE = [case for case in _RES01_CORPUS if case[4] is not None]
_RES01_WITH_ORACLE_IDS = [f"{name}-{rtype}" for name, rtype, *_ in _RES01_WITH_ORACLE]
_RES01_UNKNOWN_CASES = [case for case in _RES01_CORPUS if case[3] == "unknown"]
_RES01_UNKNOWN_IDS = [f"{name}-{rtype}" for name, rtype, *_ in _RES01_UNKNOWN_CASES]

_RES01_UNKNOWN = ("unknown", [])
_RES01_A1 = "example.com.\t\tA\t192.0.2.10"
_RES01_A2 = "example.com.\t\tA\t192.0.2.11"
_RES01_NORMAL_A = _RES01_STDOUT[("normal.test", "A")]
_RES01_HEADER_LINE = next(ln for ln in _RES01_NORMAL_A.splitlines(keepends=True) if "->>HEADER<<-" in ln)
_RES01_FLAGS_LINE = next(ln for ln in _RES01_NORMAL_A.splitlines(keepends=True) if ln.startswith(";; flags:"))


def _res01_stdout(rcode="NOERROR", records=(), *, count=None, prefix="", dig_id=4242):
    """Stdout nello schema delle catture reali (`AUTHORITY: 0`, `ADDITIONAL: 1`, OPT).
    `records`: righe intere `owner TYPE rdata`; `count`: valore di `ANSWER: N` se diverso
    dal numero di righe; `prefix`: righe `;;` che `dig` stampa prima della risposta."""
    n = len(records) if count is None else count
    out = (prefix + ";; Got answer:\n"
           f";; ->>HEADER<<- opcode: QUERY, status: {rcode}, id: {dig_id}\n"
           f";; flags: qr aa rd ra; QUERY: 1, ANSWER: {n}, AUTHORITY: 0, ADDITIONAL: 1\n"
           "\n"
           ";; OPT PSEUDOSECTION:\n"
           "; EDNS: version: 0, flags:; udp: 1232\n")
    if records:
        out += ";; ANSWER SECTION:\n" + "".join(f"{r}\n" for r in records) + "\n"
    return out


def _res01_run(monkeypatch, stdout="", returncode=0, *, stderr="", raises=None,
               name="example.com", rtype="A", timeout=10):
    """Esegue `dig_lookup` con `subprocess.run` sostituito: nessun `dig`, nessuna rete.
    Ritorna (risultato, [(argv, kwargs), ...]); `timeout=None` non passa il parametro."""
    import shared.utils as u
    calls = []

    def _spy(argv, *args, **kwargs):
        calls.append((list(argv), kwargs))
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(u.subprocess, "run", _spy)
    args = (name, rtype) if timeout is None else (name, rtype, timeout)
    return u.dig_lookup(*args), calls


class TestRES01FixtureSelfCheck:
    """Controllo delle fixture composte: `_res01_stdout` riproduce, a parità di id,
    due stdout registrati con `dig` reale. Se questo fallisse, le fixture composte
    non somiglierebbero all'output vero e i test che le usano non proverebbero nulla."""

    def test_composed_noerror_answer_equals_the_real_capture(self):
        composed = _res01_stdout(
            "NOERROR", ["normal.test.\t\tA\t192.0.2.10", "normal.test.\t\tA\t192.0.2.11"], dig_id=8329)

        assert composed == _RES01_NORMAL_A

    def test_composed_servfail_equals_the_real_capture(self):
        composed = _res01_stdout("SERVFAIL", dig_id=13358)

        assert composed == _RES01_STDOUT[("servfail.test", "A")]


class TestRES01DigLookupRealCaptures:
    """R1 + R2 — su 54 stdout reali di `dig` 9.18.39: lo stato segue l'esito DNS e i
    record coincidono con quelli che `+short` dava sulla stessa risposta (oracolo
    registrato nello stesso run). `unknown` non porta mai record."""

    @pytest.mark.parametrize("name, rtype, stdout, status, oracle", _RES01_CORPUS, ids=_RES01_CORPUS_IDS)
    def test_status_follows_the_dns_outcome(self, monkeypatch, name, rtype, stdout, status, oracle):
        got, calls = _res01_run(monkeypatch, stdout, name=name, rtype=rtype)

        assert len(calls) == 1, "lo spy di subprocess.run non è stato raggiunto"
        assert got[0] == status, f"{name} {rtype}: atteso {status!r}, ricevuto {got!r}"

    @pytest.mark.parametrize("name, rtype, stdout, status, oracle", _RES01_WITH_ORACLE, ids=_RES01_WITH_ORACLE_IDS)
    def test_records_equal_the_plus_short_oracle(self, monkeypatch, name, rtype, stdout, status, oracle):
        got, _ = _res01_run(monkeypatch, stdout, name=name, rtype=rtype)

        assert got[1] == oracle, f"{name} {rtype}: record {got[1]!r} diversi dall'oracolo {oracle!r}"

    @pytest.mark.parametrize("name, rtype, stdout, status, oracle", _RES01_UNKNOWN_CASES, ids=_RES01_UNKNOWN_IDS)
    def test_unknown_outcome_returns_exactly_unknown_and_no_records(
            self, monkeypatch, name, rtype, stdout, status, oracle):
        got, _ = _res01_run(monkeypatch, stdout, name=name, rtype=rtype)

        assert got == _RES01_UNKNOWN

    def test_result_is_a_tuple_of_a_status_string_and_a_list_of_strings(self, monkeypatch):
        got, _ = _res01_run(monkeypatch, _RES01_NORMAL_A, name="normal.test")

        assert isinstance(got, tuple) and len(got) == 2
        assert isinstance(got[0], str)
        assert isinstance(got[1], list) and all(isinstance(r, str) for r in got[1])

    @pytest.mark.parametrize("stdout, expected", [
        pytest.param(_res01_stdout("NOERROR", [_RES01_A2, _RES01_A1]),
                     ("ok", ["192.0.2.10", "192.0.2.11"]), id="NOERROR-with-answers"),
        pytest.param(_res01_stdout("NOERROR"), ("nodata", []), id="NOERROR-without-answers"),
        pytest.param(_res01_stdout("NXDOMAIN"), ("nxdomain", []), id="NXDOMAIN-without-answers"),
        pytest.param(_res01_stdout("NXDOMAIN", ["example.com.\t\tCNAME\tgone.example.com."]),
                     ("nxdomain", ["gone.example.com"]), id="NXDOMAIN-with-a-CNAME-chain"),
    ])
    def test_the_three_answer_states_in_their_plainest_form(self, monkeypatch, stdout, expected):
        got, _ = _res01_run(monkeypatch, stdout)

        assert got == expected


class TestRES01DigLookupUnknownWhenDigCannotTell:
    """R1 — righe della tabella di parsing che portano a `unknown`: guasto del
    processo, rc != 0, pacchetto non parsabile, struttura dello stdout non quella
    attesa. In ogni caso il risultato è esattamente `("unknown", [])`."""

    # ── eccezioni e stdout mancante ──

    @pytest.mark.parametrize("exc", [
        FileNotFoundError("dig"),
        subprocess.TimeoutExpired(["dig"], 20),
        OSError("boom"),
        PermissionError("denied"),
        RuntimeError("SECRET-EXCEPTION-TEXT"),
        ValueError("x"),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
    ], ids=lambda e: type(e).__name__)
    def test_exception_from_the_process_is_unknown(self, monkeypatch, exc):
        got, calls = _res01_run(monkeypatch, raises=exc)

        assert len(calls) == 1
        assert got == _RES01_UNKNOWN

    def test_missing_stdout_is_unknown(self, monkeypatch):
        got, _ = _res01_run(monkeypatch, stdout=None)

        assert got == _RES01_UNKNOWN

    # ── rc != 0 ──

    @pytest.mark.parametrize("stdout", [
        _RES01_RC9_MUTE, _RES01_RC9_CONNECTION_REFUSED, _RES01_RC9_NETWORK_UNREACHABLE,
        _RES01_RC9_ID_MISMATCH, _RES01_RC9_TCP_MUTE,
    ], ids=["mute", "connection-refused", "network-unreachable", "id-mismatch", "tcp-mute"])
    def test_real_transport_failures_with_rc9_are_unknown(self, monkeypatch, stdout):
        got, _ = _res01_run(monkeypatch, stdout, returncode=9)

        assert got == _RES01_UNKNOWN

    @pytest.mark.parametrize("returncode", [1, 2, 9, 10, 127, 255, -9, -11])
    def test_nonzero_exit_prevails_over_a_perfect_answer(self, monkeypatch, returncode):
        # Composto: un `dig` che esce con rc != 0 non porta una risposta (rc 9) o non è
        # affidabile (ucciso a metà, rc negativo); l'esito non dipende dal fatto che
        # lo stdout «sembri» una risposta valida.
        got, _ = _res01_run(monkeypatch, _RES01_NORMAL_A, returncode=returncode)

        assert got == _RES01_UNKNOWN

    # ── `;; Got bad packet` ──

    @pytest.mark.parametrize("stdout", [
        _RES01_STDOUT[("badcaa.test", "CAA")],
        _COL08_BADPKT_CAA_TAG,
        _COL08_BADPKT_CAA_TAGLEN,
        _COL08_BADPKT_CNAME_LABEL,
        _COL08_BADPKT_NAPTR_SYNTAX,
        # Composto da due frammenti reali: il primo server muto, poi il pacchetto non parsabile.
        _COL08_LOST_TRY_2ND_SERVER + _COL08_BADPKT_CAA_TAG,
    ], ids=["badcaa-test", "CAA-invalid-tag", "CAA-tag-length-overflow", "CNAME-bad-label-type",
            "NAPTR-syntax-error", "first-server-mute-then-bad-packet"])
    def test_got_bad_packet_is_unknown(self, monkeypatch, stdout):
        got, _ = _res01_run(monkeypatch, stdout, returncode=0)

        assert got == _RES01_UNKNOWN

    @pytest.mark.parametrize("where", ["before", "after"])
    def test_got_bad_packet_prevails_over_a_well_formed_answer(self, monkeypatch, where):
        # Composto: la riga `;; Got bad packet` accanto a una risposta che da sola darebbe
        # `ok` (testata, `ANSWER: 2`, due righe). Il numero di righe torna: solo la regola
        # sul pacchetto non parsabile può decidere `unknown`.
        banner = ";; Got bad packet: FORMERR\n"
        stdout = banner + _RES01_NORMAL_A if where == "before" else _RES01_NORMAL_A + banner

        got, _ = _res01_run(monkeypatch, stdout)

        assert got == _RES01_UNKNOWN

    # ── `;; Warning: Message parser reports malformed` ──

    def test_malformed_message_warning_is_unknown(self, monkeypatch):
        # Reale (`badtxt.test`): rc 0, testata NOERROR con `ANSWER: 1` e nessuna riga di
        # risposta. Con `+short` questo era NODATA.
        got, _ = _res01_run(monkeypatch, _RES01_STDOUT[("badtxt.test", "TXT")], rtype="TXT")

        assert got == _RES01_UNKNOWN

    @pytest.mark.parametrize("where", ["before", "after"])
    def test_malformed_message_warning_prevails_over_a_well_formed_answer(self, monkeypatch, where):
        # Composto, come sopra: l'avviso del parser accanto a una risposta coerente.
        warning = ";; Warning: Message parser reports malformed message packet.\n"
        stdout = warning + _RES01_NORMAL_A if where == "before" else _RES01_NORMAL_A + warning

        got, _ = _res01_run(monkeypatch, stdout)

        assert got == _RES01_UNKNOWN

    # ── testata e riga `flags` ──

    @pytest.mark.parametrize("stdout", [
        pytest.param("", id="empty-stdout"),
        pytest.param("\n\n", id="blank-lines-only"),
        # Fail-closed: lo stdout di `+short` non ha testata. Ricadere sul vecchio parsing
        # sarebbe la classe di difetti di COL-08 (un guasto che diventa un dato).
        pytest.param("192.0.2.10\n192.0.2.11\n", id="plus-short-style-records"),
        pytest.param(_RES01_NORMAL_A.replace(_RES01_HEADER_LINE, ""), id="real-capture-without-the-header"),
        pytest.param(_RES01_NORMAL_A.replace(_RES01_FLAGS_LINE, ""), id="real-capture-without-the-flags-line"),
        pytest.param(_RES01_NORMAL_A.replace("ANSWER: 2, ", ""), id="real-capture-flags-without-ANSWER"),
        pytest.param(_RES01_NORMAL_A + _RES01_NORMAL_A, id="two-complete-answers"),
        pytest.param(_RES01_NORMAL_A.replace(_RES01_HEADER_LINE, _RES01_HEADER_LINE * 2),
                     id="real-capture-with-the-header-twice"),
        pytest.param(_RES01_NORMAL_A.replace(_RES01_FLAGS_LINE, _RES01_FLAGS_LINE * 2),
                     id="real-capture-with-the-flags-line-twice"),
        pytest.param(_RES01_NORMAL_A.replace("opcode: QUERY", "opcode: NOTIFY"), id="opcode-NOTIFY"),
        pytest.param(_RES01_NORMAL_A.replace("opcode: QUERY", "opcode: UPDATE"), id="opcode-UPDATE"),
        # Solo righe di risposta: senza testata non c'è modo di sapere lo stato.
        pytest.param(f"{_RES01_A1}\n{_RES01_A2}\n", id="answer-lines-without-comments"),
        # Un TXT il cui testo è una testata completa non è una testata: l'owner apre la riga.
        pytest.param('x.test.\t\tTXT\t";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1"\n'
                     'x.test.\t\tTXT\t";; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0"\n',
                     id="quoted-header-and-flags-inside-TXT-lines"),
    ])
    def test_stdout_without_exactly_one_header_and_one_flags_line_is_unknown(self, monkeypatch, stdout):
        got, _ = _res01_run(monkeypatch, stdout)

        assert got == _RES01_UNKNOWN

    # ── `ANSWER: N` contro le righe di risposta ──

    @pytest.mark.parametrize("stdout", [
        pytest.param(_res01_stdout("NOERROR", [_RES01_A1, _RES01_A2], count=3), id="ANSWER-3-with-2-lines"),
        pytest.param(_res01_stdout("NOERROR", [_RES01_A1, _RES01_A2], count=1), id="ANSWER-1-with-2-lines"),
        pytest.param(_res01_stdout("NOERROR", [_RES01_A1], count=0), id="ANSWER-0-with-1-line"),
        pytest.param(_res01_stdout("NOERROR", [], count=2), id="ANSWER-2-with-no-lines"),
        pytest.param(_res01_stdout("NXDOMAIN", [], count=1), id="NXDOMAIN-ANSWER-1-with-no-lines"),
    ])
    def test_answer_count_different_from_the_answer_lines_is_unknown(self, monkeypatch, stdout):
        got, _ = _res01_run(monkeypatch, stdout)

        assert got == _RES01_UNKNOWN

    @pytest.mark.parametrize("records", [
        pytest.param(["example.com.\t\tA"], id="owner-and-type-only"),
        pytest.param(["example.com."], id="owner-only"),
        pytest.param([_RES01_A1, "example.com.\t\tA"], id="one-good-line-one-short-line"),
    ])
    def test_answer_line_with_fewer_than_three_fields_is_unknown(self, monkeypatch, records):
        got, _ = _res01_run(monkeypatch, _res01_stdout("NOERROR", records))

        assert got == _RES01_UNKNOWN


class TestRES01DigLookupRcodes:
    """R1 — lista bianca degli rcode: solo NOERROR e NXDOMAIN sono risposte. Ogni altro
    token è «non si è potuto sapere», con record sempre vuoti e senza riecheggiare il token."""

    @pytest.mark.parametrize("stdout", [
        _RES01_STDOUT[("servfail.test", "A")], _RES01_STDOUT[("refused.test", "A")],
        _RES01_STDOUT[("formerr.test", "A")], _RES01_STDOUT[("notimp.test", "A")],
        _RES01_YXDOMAIN_A, _RES01_NOTAUTH_A, _RES01_RESERVED11_A, _RES01_RESERVED15_A,
    ], ids=["SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "YXDOMAIN", "NOTAUTH", "RESERVED11", "RESERVED15"])
    def test_real_rcode_other_than_noerror_and_nxdomain_is_unknown(self, monkeypatch, stdout):
        got, _ = _res01_run(monkeypatch, stdout)

        assert got == _RES01_UNKNOWN

    @pytest.mark.parametrize("rcode", [
        "YXRRSET", "NXRRSET", "NOTZONE", "BADVERS", "BADSIG", "BADCOOKIE", "RESERVED12", "FOO", "NOERROR2",
    ])
    def test_synthetic_rcode_is_unknown(self, monkeypatch, rcode):
        # Composti: la lista bianca non deve riconoscere un token solo perché «sembra» un rcode.
        got, _ = _res01_run(monkeypatch, _res01_stdout(rcode))

        assert got == _RES01_UNKNOWN

    @pytest.mark.parametrize("rcode", ["SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "YXDOMAIN", "NOTAUTH", "FOO"])
    def test_rcode_that_is_not_an_answer_never_returns_records(self, monkeypatch, rcode):
        # Composto: anche se il server mette righe di risposta accanto a un rcode d'errore,
        # quei record non sono dati sul dominio.
        got, _ = _res01_run(monkeypatch, _res01_stdout(rcode, [_RES01_A1]))

        assert got == _RES01_UNKNOWN

    def test_rcode_token_is_never_echoed_in_the_result(self, monkeypatch):
        got, _ = _res01_run(monkeypatch, _res01_stdout("SECRET_RCODE_TOKEN"))

        assert got == _RES01_UNKNOWN
        assert "SECRET_RCODE_TOKEN" not in repr(got)


class TestRES01DigLookupNoiseAroundTheAnswer:
    """Le righe `;;` che `dig` stampa prima della risposta (primo tentativo perso,
    secondo server, ritorno su TCP) non cambiano né lo stato né i record."""

    @pytest.mark.parametrize("stdout, expected", [
        pytest.param(_RES01_RETRY_A, ("ok", ["192.0.2.10", "192.0.2.11"]), id="first-attempt-lost-then-answer"),
        pytest.param(_RES01_RETRY_NXDOMAIN_A, ("nxdomain", []), id="first-attempt-lost-then-NXDOMAIN"),
        pytest.param(_RES01_RETRY_NODATA_A, ("nodata", []), id="first-attempt-lost-then-NODATA"),
        pytest.param(_RES01_SECOND_SERVER_ANSWERS_A, ("ok", ["192.0.2.10", "192.0.2.11"]),
                     id="first-server-mute-second-answers"),
        pytest.param(_RES01_STDOUT[("trunc.test", "A")], ("ok", ["192.0.2.10", "192.0.2.11"]),
                     id="truncated-then-TCP"),
        # Composto da due frammenti reali (la riga `ID mismatch` di COL-08 e una risposta): un
        # avviso che non è `Message parser reports malformed` non invalida una risposta coerente.
        pytest.param(_COL08_ID_MISMATCH_LEADING + _RES01_NORMAL_A, ("ok", ["192.0.2.10", "192.0.2.11"]),
                     id="ID-mismatch-warning-then-answer"),
    ])
    def test_lines_printed_before_the_answer_do_not_change_the_outcome(self, monkeypatch, stdout, expected):
        got, _ = _res01_run(monkeypatch, stdout, returncode=0)

        assert got == expected

    def test_diagnostic_lines_never_become_records(self, monkeypatch):
        got, _ = _res01_run(monkeypatch, _RES01_RETRY_A)

        assert not [r for r in got[1] if r.lstrip().startswith(";") or "communications error" in r]


class TestRES01DigLookupRecordText:
    """Il record è il terzo campo di `owner TYPE rdata` (split sul primo e secondo
    spazio bianco, qualunque ne sia la forma), senza spazi ai bordi né punti finali;
    gli spazi interni all'rdata si conservano. Righe composte: `dig` stampa tabulazioni,
    ma il parsing non deve dipendere dalla forma del separatore."""

    @pytest.mark.parametrize("line, expected", [
        pytest.param("example.com.\t\tA\t192.0.2.10", "192.0.2.10", id="two-tabs-then-tab"),
        pytest.param("example.com.   A   192.0.2.10", "192.0.2.10", id="spaces"),
        pytest.param("example.com. \t A \t 192.0.2.10", "192.0.2.10", id="mixed-whitespace"),
        pytest.param("example.com.\t\tA\t192.0.2.10   ", "192.0.2.10", id="trailing-spaces"),
        pytest.param("example.com.\t\tMX\t10 mail.example.com.", "10 mail.example.com", id="MX-trailing-dot"),
        pytest.param('example.com.\t\tTXT\t"a  b" "c"', '"a  b" "c"', id="TXT-inner-spaces-kept"),
    ])
    def test_record_is_the_third_field_stripped_and_without_trailing_dot(self, monkeypatch, line, expected):
        got, _ = _res01_run(monkeypatch, _res01_stdout("NOERROR", [line]))

        assert got == ("ok", [expected])


class TestRES01DigLookupHostileContent:
    """R3 — un nome o un TXT che imita la testata, la riga `flags`, `Got bad packet`
    o `Warning: Message parser…` non è una testata: resta un record e non cambia lo
    stato. Chi controlla il DNS di un dominio può scrivere quei testi a piacere;
    `dig` li esce con un altro primo carattere (le virgolette di un TXT/CAA, il `\\;`
    di una label), quindi l'ancoraggio a inizio riga basta, e va rispettato."""

    @pytest.mark.parametrize("name, stdout, expected", [
        pytest.param(
            "forge.test", _RES01_STDOUT[("forge.test", "A")],
            ["192.0.2.99", "\\;\\;\\032->>HEADER<<-\\032opcode:\\032QUERY,\\032status:\\032NOERROR,"
                           "\\032id:\\0321.evil.test"],
            id="CNAME-label-imitates-the-header"),
        pytest.param(
            "forgebad.test", _RES01_FORGE_BADPACKET_A,
            ["192.0.2.98", "\\;\\;\\032Got\\032bad\\032packet:\\032FORMERR.evil.test"],
            id="CNAME-label-imitates-Got-bad-packet"),
        pytest.param(
            "forgewarn.test", _RES01_FORGE_WARNING_A,
            ["192.0.2.97", "\\;\\;\\032Warning:\\032Message\\032parser\\032reports\\032malformed.evil.test"],
            id="CNAME-label-imitates-the-malformed-warning"),
        pytest.param(
            "forgeflags.test", _RES01_FORGE_FLAGS_A,
            ["192.0.2.96", "\\;\\;\\032flags:\\032qr\\032aa\\032rd\\032ra\\;\\032ANSWER:\\0327,\\032x.evil.test"],
            id="CNAME-label-imitates-the-flags-line"),
    ])
    def test_name_that_imitates_dig_output_stays_a_record(self, monkeypatch, name, stdout, expected):
        got, _ = _res01_run(monkeypatch, stdout, name=name)

        assert got == ("ok", expected)

    def test_txt_whose_text_imitates_dig_output_stays_a_record(self, monkeypatch):
        got, _ = _res01_run(monkeypatch, _RES01_FORGE_TXT, name="forgetxt.test", rtype="TXT")

        assert got == ("ok", sorted([
            '";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1"',
            '";; flags: qr aa rd ra; QUERY: 1, ANSWER: 99, AUTHORITY: 0, ADDITIONAL: 0"',
            '";; Got bad packet: FORMERR"',
            '";; Warning: Message parser reports malformed message packet."',
            '"x" ";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 2"',
            '"v=spf1 -all"',
        ]))

    def test_caa_whose_value_imitates_dig_output_stays_a_record(self, monkeypatch):
        got, _ = _res01_run(monkeypatch, _RES01_FORGE_CAA, name="forgetxt.test", rtype="CAA")

        assert got == ("ok", [
            '0 iodef ";; Got bad packet: FORMERR"',
            '0 issue ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 1"',
        ])


class TestRES01DigLookupArgvAndNameGuard:
    """R4 — argv esatto, `timeout=T+10` di `subprocess.run`, un solo processo per query,
    nessuna shell; la guardia del nome di SEC-26 vale anche qui e non lancia alcun processo."""

    EXPECTED_PREFIX = ["dig", "+noall", "+comments", "+answer", "+nottlid", "+noclass", "+ndots=1"]
    EXPECTED_SUFFIX = ["+tries=2", "+noidnout"]

    @classmethod
    def _expected_argv(cls, name, rtype, timeout):
        return cls.EXPECTED_PREFIX + [f"+time={timeout}"] + cls.EXPECTED_SUFFIX + [name, rtype]

    @staticmethod
    def _dns_name(length):
        """Nome fatto di label valide (<= 63) lungo esattamente `length`."""
        labels, remaining = [], length
        while remaining > 0:
            take = min(63, remaining)
            labels.append("a" * take)
            remaining -= take + 1
        name = ".".join(labels)
        assert len(name) == length and all(len(x) <= 63 for x in labels)
        return name

    @pytest.mark.parametrize("name", [
        "example.com", "Example.COM", "123.example.com", "a-b.example.com", "xn--bcher-kva.example",
        "_dmarc.example.com", "default._bimi.example.com", "s1._domainkey.example.com",
        "k1.mail._domainkey.example.com", "SeLeCtOr._domainkey.example.com", "www.example.com",
    ], ids=lambda s: repr(s))
    def test_argv_is_exact(self, monkeypatch, name):
        _, calls = _res01_run(monkeypatch, _RES01_NORMAL_A, name=name, rtype="TXT", timeout=7)

        assert [argv for argv, _ in calls] == [self._expected_argv(name, "TXT", 7)]

    def test_name_of_exactly_253_characters_still_reaches_dig(self, monkeypatch):
        name = self._dns_name(253)

        _, calls = _res01_run(monkeypatch, _RES01_NORMAL_A, name=name)

        assert [argv for argv, _ in calls] == [self._expected_argv(name, "A", 10)]

    @pytest.mark.parametrize("timeout", [1, 3, 10, 30])
    def test_subprocess_timeout_is_the_dig_timeout_plus_ten(self, monkeypatch, timeout):
        _, calls = _res01_run(monkeypatch, _RES01_NORMAL_A, timeout=timeout)

        (argv, kwargs), = calls
        assert f"+time={timeout}" in argv
        assert kwargs.get("timeout") == timeout + 10

    def test_default_timeout_is_ten_seconds_of_dig_and_twenty_of_subprocess(self, monkeypatch):
        _, calls = _res01_run(monkeypatch, _RES01_NORMAL_A, timeout=None)

        (argv, kwargs), = calls
        assert "+time=10" in argv
        assert kwargs.get("timeout") == 20

    def test_process_is_started_from_an_argument_list_without_a_shell(self, monkeypatch):
        _, calls = _res01_run(monkeypatch, _RES01_NORMAL_A)

        (argv, kwargs), = calls
        assert isinstance(argv, list)
        assert not kwargs.get("shell")

    @pytest.mark.parametrize("stdout, returncode, raises", [
        pytest.param(_RES01_NORMAL_A, 0, None, id="answer"),
        pytest.param(_RES01_STDOUT[("servfail.test", "A")], 0, None, id="SERVFAIL"),
        pytest.param(_RES01_RC9_MUTE, 9, None, id="rc9"),
        pytest.param("", 0, subprocess.TimeoutExpired(["dig"], 20), id="timeout"),
    ])
    def test_exactly_one_process_per_query_whatever_the_outcome(self, monkeypatch, stdout, returncode, raises):
        _, calls = _res01_run(monkeypatch, stdout, returncode, raises=raises)

        assert len(calls) == 1, "nessun tentativo in più: la durata del caso peggiore non deve crescere"

    @pytest.mark.parametrize("name", [
        "@8.8.8.8",
        "@ns.attacker.example._domainkey.example.com",
        "-x",
        "-p5353._domainkey.example.com",
        "+tries=9",
        "+short._domainkey.example.com",
        " example.com",
        "example.com ",
        "exam ple.com",
        "example.com\n",
        "exam\nple.com",
        "example\t.com",
        "example.com\x00",
        "exam\x00ple.com",
        "example.com\r",
        "ex/ample.com",
        "ex\\ample.com",
        "example.com;id",
        "$(id).example.com",
        "exämple.com",
        ".example.com",
        "",
    ], ids=lambda s: repr(s))
    def test_name_that_is_not_a_dns_name_is_refused_without_a_process(self, monkeypatch, name):
        got, calls = _res01_run(monkeypatch, _RES01_NORMAL_A, name=name)

        assert calls == [], f"subprocess.run chiamato per {name!r}: {calls}"
        assert got == _RES01_UNKNOWN

    def test_name_longer_than_253_is_refused_without_a_process(self, monkeypatch):
        got, calls = _res01_run(monkeypatch, _RES01_NORMAL_A, name=self._dns_name(254))

        assert calls == []
        assert got == _RES01_UNKNOWN

    @pytest.mark.parametrize("name", [None, 12345, b"example.com", ["example.com"]],
                             ids=["None", "int", "bytes", "list"])
    def test_non_string_name_is_unknown_without_a_process_and_without_raising(self, monkeypatch, name):
        got, calls = _res01_run(monkeypatch, _RES01_NORMAL_A, name=name)

        assert calls == []
        assert got == _RES01_UNKNOWN

    @pytest.mark.parametrize("rtype", ["A", "TXT", "CAA"])
    def test_refusal_does_not_depend_on_record_type(self, monkeypatch, rtype):
        got, calls = _res01_run(monkeypatch, _RES01_NORMAL_A, name="@evil._domainkey.example.com", rtype=rtype)

        assert calls == []
        assert got == _RES01_UNKNOWN

    def test_stderr_and_exception_text_are_never_echoed(self, monkeypatch):
        got, _ = _res01_run(monkeypatch, _RES01_RC9_MUTE, 9, stderr="SECRET-STDERR: dig: couldn't get address")
        assert got == _RES01_UNKNOWN
        assert "SECRET" not in repr(got)

        got, _ = _res01_run(monkeypatch, raises=RuntimeError("SECRET-EXCEPTION-TEXT"))
        assert got == _RES01_UNKNOWN
        assert "SECRET" not in repr(got)

    def test_diagnostic_stdout_of_a_failed_run_is_never_echoed(self, monkeypatch):
        got, _ = _res01_run(monkeypatch, _RES01_RC9_CONNECTION_REFUSED, 9)

        assert got == _RES01_UNKNOWN
        assert "127.0.0.9" not in repr(got) and ";;" not in repr(got)


class TestRES01DnsUnknownRtypes:
    """`dns_unknown_rtypes(dns)`: i tipi di record il cui `records_status` è `unknown`.
    Un dato mancante o malformato conta come **noto**: gli snapshot già su disco non
    hanno `records_status` e devono leggersi come oggi. Non deve mai sollevare, perché
    chi la chiama (orchestrator, classificatore) riceve JSON di servizi e file su disco."""

    def test_returns_the_types_whose_status_is_unknown(self):
        from shared.utils import dns_unknown_rtypes
        dns = {"records": {"A": [], "MX": []},
               "records_status": {"A": "unknown", "AAAA": "nodata", "MX": "ok", "NS": "unknown",
                                  "TXT": "nxdomain", "SOA": "ok", "CNAME": "nodata"}}

        assert dns_unknown_rtypes(dns) == {"A", "NS"}

    def test_returns_a_set(self):
        from shared.utils import dns_unknown_rtypes

        assert isinstance(dns_unknown_rtypes({"records_status": {"A": "unknown"}}), set)

    def test_no_unknown_type_returns_the_empty_set(self):
        from shared.utils import dns_unknown_rtypes
        dns = {"records_status": {"A": "ok", "MX": "nodata", "NS": "nxdomain"}}

        assert dns_unknown_rtypes(dns) == set()

    def test_a_type_missing_from_the_status_is_known(self):
        from shared.utils import dns_unknown_rtypes

        assert dns_unknown_rtypes({"records_status": {"A": "unknown"}}) == {"A"}

    @pytest.mark.parametrize("dns", [
        None, [], "", "unknown", 42, 4.2, True, ("A",), set(),
        {},
        {"records": {"A": []}},
        {"records": {"A": ["192.0.2.1"]}, "email_auth": {"spf": {"present": False}}},
        {"records_status": None},
        {"records_status": []},
        {"records_status": ["A"]},
        {"records_status": "unknown"},
        {"records_status": 7},
    ], ids=lambda v: repr(v))
    def test_missing_or_malformed_input_means_nothing_is_unknown(self, dns):
        from shared.utils import dns_unknown_rtypes

        assert dns_unknown_rtypes(dns) == set()

    @pytest.mark.parametrize("odd", [None, 0, 1, "", "ok", ["unknown"], {"unknown": 1}, 3.5, True],
                             ids=lambda v: repr(v))
    def test_a_status_value_other_than_the_string_unknown_is_not_counted(self, odd):
        from shared.utils import dns_unknown_rtypes

        assert dns_unknown_rtypes({"records_status": {"A": odd, "MX": "unknown"}}) == {"MX"}

    def test_the_input_is_not_modified(self):
        from shared.utils import dns_unknown_rtypes
        dns = {"records_status": {"A": "unknown", "MX": "ok"}, "records": {"A": [], "MX": ["10 m.example.com"]}}
        before = {"records_status": dict(dns["records_status"]),
                  "records": {k: list(v) for k, v in dns["records"].items()}}

        dns_unknown_rtypes(dns)

        assert dns == before
