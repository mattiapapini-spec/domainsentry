"""SEC-51: una sezione `<![…` nella pagina non fa fallire l'analisi, qualunque sia la versione di Python.

Fino a CPython 3.12.11 `HTMLParser` passa ogni `<![` a `_markupbase.ParserBase.parse_marked_section`, che con una
parola chiave sconosciuta (`<![foo[x]]>`, 11 byte) solleva `AssertionError`: l'analisi del corpo di `/http` falliva
come in SEC-50. Da 3.12.12 la libreria la tratta come un commento fino al primo `>`, come il browser. `_TagCollector`
ora fa lo stesso su ogni versione. Il test di fine catena è rosso solo su un Python esposto: provato rosso su CPython
3.12.3 originale, verde su 3.12.12; il test sul metodo è rosso senza la correzione su ogni versione.
"""

import pytest

from shared.utils import _TagCollector, detect_hidden_elements

_FORM = '<form hidden action="https://raccolta.example/p"></form>'


class TestSEC51MarkedSectionGrammar:
    @pytest.mark.parametrize("raw, end", [
        ("<![foo[x]]><b>", len("<![foo[x]]>")),
        ("<![CDATA[ a > b ]]><b>", len("<![CDATA[ a >")),
        ("<![if !IE]><b>", len("<![if !IE]>")),
        ("<![ <b>", len("<![ <b>")),
    ])
    def test_a_marked_section_ends_at_the_first_gt_without_raising(self, raw, end):
        collector = _TagCollector(("b",))
        collector.rawdata = raw

        assert collector.parse_marked_section(0) == end

    def test_an_unterminated_marked_section_waits_for_more_data(self):
        collector = _TagCollector(("b",))
        collector.rawdata = "<![foo[x"

        assert collector.parse_marked_section(0) == -1


class TestSEC51PageAnalysis:
    @pytest.mark.parametrize("prefix", ["<![foo[x]]>", "<![CDATA[ a > b ]]>", "<![x y]>"])
    def test_the_markup_after_a_marked_section_is_still_analysed(self, prefix):
        result = detect_hidden_elements(prefix + _FORM)

        assert [f["action"] for f in result.get("hidden_forms", [])] == ["https://raccolta.example/p"]

    def test_a_cdata_opening_does_not_hide_the_markup_up_to_its_closing(self):
        # Nel contenuto HTML il browser chiude `<![CDATA[` al primo `>`: il form dopo è vivo. Con `_support_cdata`
        # acceso (CPython 3.12.12, 3.13) la libreria lo nascondeva fino a `]]>`.
        result = detect_hidden_elements("<![CDATA[ a > " + _FORM + " ]]>")

        assert [f["action"] for f in result.get("hidden_forms", [])] == ["https://raccolta.example/p"]

    @pytest.mark.parametrize("raw", ["<script>var a = 1;</script>", "<style>a { color: red }</style>"])
    def test_script_and_style_do_not_break_the_analysis(self, raw):
        # Fino a CPython 3.12.11 `set_cdata_mode` non accetta `escapable`.
        result = detect_hidden_elements(raw + _FORM)

        assert [f["action"] for f in result.get("hidden_forms", [])] == ["https://raccolta.example/p"]
