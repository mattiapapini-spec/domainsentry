"""CLS-01p: l'attributo booleano `hidden` di HTML5 nasconde un form o un iframe come `display:none`.

Prima `hidden_forms` guardava solo `style` e `class`, `invisible_iframes` solo dimensioni e `style`: un form o un
iframe con il solo attributo `hidden` non veniva rilevato. L'attributo nasconde l'elemento con qualunque valore,
anche vuoto o `until-found`; conta il nome dell'attributo, non una sottostringa di un altro.
"""

import pytest

from shared.utils import detect_hidden_elements

_ACTION = "https://raccolta.example/p"
_SRC = "https://cornice.example/f"


def _forms(html):
    return detect_hidden_elements(html).get("hidden_forms", [])


def _iframes(html):
    return detect_hidden_elements(html).get("invisible_iframes", [])


class TestCLS01pHiddenForms:
    @pytest.mark.parametrize("attr", ["hidden", 'hidden=""', 'hidden="hidden"', "HIDDEN", 'hidden="until-found"'])
    def test_a_form_with_the_hidden_attribute_is_hidden(self, attr):
        [form] = _forms(f'<form {attr} action="{_ACTION}"><input name=u><input type=password name=p></form>')

        assert form["action"] == _ACTION
        assert form["technique"] == "hidden_attribute"

    def test_it_raises_the_hidden_form_signal(self):
        result = detect_hidden_elements(f'<form hidden action="{_ACTION}"><input name=u></form>')

        assert result["risk_indicators"] == 30
        assert "1 form nascosti — possibile credential harvesting" in result["summary"]

    def test_a_self_closing_form_with_the_attribute_is_hidden(self):
        assert [f["technique"] for f in _forms(f'<form hidden action="{_ACTION}"/>')] == ["hidden_attribute"]

    def test_css_keeps_its_technique_when_both_are_present(self):
        [form] = _forms(f'<form hidden style="display:none" action="{_ACTION}"></form>')

        assert form["technique"] == "css_hidden"

    @pytest.mark.parametrize("html", [
        f'<form data-hidden action="{_ACTION}"></form>',
        f'<form title="hidden" action="{_ACTION}"></form>',
        f'<form aria-hidden="true" action="{_ACTION}"></form>',
        f'<form action="{_ACTION}"></form>',
    ])
    def test_other_attributes_do_not_hide_a_form(self, html):
        assert _forms(html) == []

    def test_a_hidden_form_in_the_fallback_of_a_closed_iframe_is_not_live(self):
        html = f'<iframe src="/v" width="640" height="480"><form hidden action="{_ACTION}"></form></iframe>'

        assert _forms(html) == []


class TestCLS01pHiddenIframes:
    @pytest.mark.parametrize("attr", ["hidden", 'hidden="hidden"', "Hidden", 'hidden="until-found"'])
    def test_an_iframe_with_the_hidden_attribute_is_invisible(self, attr):
        [iframe] = _iframes(f'<iframe {attr} src="{_SRC}" width="640" height="480"></iframe>')

        assert iframe["src"] == _SRC
        assert iframe["technique"] == ["hidden_attribute"]

    def test_it_raises_the_invisible_iframe_signal(self):
        result = detect_hidden_elements(f'<iframe hidden src="{_SRC}"></iframe>')

        assert result["risk_indicators"] == 25

    def test_the_attribute_adds_to_the_other_techniques(self):
        [iframe] = _iframes(f'<iframe hidden src="{_SRC}" width="0" height="0" style="display:none"></iframe>')

        assert "hidden_attribute" in iframe["technique"]
        assert "css_hidden" in iframe["technique"]
        assert len(iframe["technique"]) == 3

    @pytest.mark.parametrize("html", [
        f'<iframe data-hidden src="{_SRC}" width="640" height="480"></iframe>',
        f'<iframe title="hidden" src="{_SRC}" width="640" height="480"></iframe>',
        f'<iframe src="{_SRC}" width="640" height="480"></iframe>',
    ])
    def test_other_attributes_do_not_hide_an_iframe(self, html):
        assert _iframes(html) == []
