"""CLS-01u: gli input nascosti si leggono come li legge un browser, col tokenizer già usato per form, iframe e pixel.

Prima un `>` dentro il valore quotato di un attributo precedente chiudeva il tag per l'estrazione, e `type=hidden`
dopo di lui non veniva più visto; nomi e valori si fermavano al primo spazio o apice; `type=hidden` contava anche
dentro un altro attributo (`data-type`) o come secondo `type` ripetuto, che il browser ignora.
"""

from shared.utils import detect_hidden_elements


def _inputs(html):
    return detect_hidden_elements(html).get("hidden_inputs", [])


def _pairs(html):
    return [(i["name"], i["value"]) for i in _inputs(html)]


class TestCLS01uAGreaterThanInAnEarlierValue:
    def test_the_input_after_it_is_still_read(self):
        html = '<form><input data-note="a>b" type="hidden" name="session" value="v1"></form>'

        assert _pairs(html) == [("session", "v1")]

    def test_four_such_inputs_still_raise_the_collection_signal(self):
        html = "<form>" + "".join(
            f'<input title="x>y" type="hidden" name="f{i}" value="{i}">' for i in range(4)) + "</form>"

        result = detect_hidden_elements(html)

        assert len(result.get("hidden_inputs", [])) == 4
        assert result["risk_indicators"] == 15
        assert "4 input nascosti — possibile form di raccolta dati" in result["summary"]


class TestCLS01uWholeNamesAndValues:
    def test_spaces_and_quotes_inside_quoted_values_are_kept(self):
        html = """<input type="hidden" name="return url" value="https://a.example/x y?q='1'">"""

        assert _pairs(html) == [("return url", "https://a.example/x y?q='1'")]

    def test_entities_are_decoded_as_the_browser_submits_them(self):
        html = '<input type=hidden name=next value="a&amp;b">'

        assert _pairs(html) == [("next", "a&b")]

    def test_missing_name_and_value_stay_none(self):
        assert _pairs("<input type=hidden>") == [(None, None)]

    def test_value_keeps_its_cap(self):
        [found] = _inputs('<input type=hidden name=t value="' + "v" * 500 + '">')

        assert found["value"] == "v" * 100

    def test_control_characters_do_not_reach_the_snapshot(self):
        [found] = _inputs('<input type=hidden name="a&#10;b" value="c&#13;d">')

        assert (found["name"], found["value"]) == ("ab", "cd")


class TestCLS01uOnlyTheRealTypeCounts:
    def test_hidden_in_another_attribute_is_not_a_hidden_input(self):
        assert _inputs('<input data-type="hidden" type="text" name="q">') == []

    def test_a_repeated_type_keeps_the_first_value(self):
        assert _inputs('<input type="text" type="hidden" name="q">') == []
        assert _pairs('<input type="hidden" type="text" name="q">') == [("q", None)]

    def test_type_is_case_insensitive_and_may_be_unquoted(self):
        assert _pairs("<INPUT TYPE=HIDDEN NAME=a VALUE=b>") == [("a", "b")]

    def test_self_closing_inputs_are_read(self):
        assert _pairs('<input type="hidden" name="a" value="b"/>') == [("a", "b")]


class TestCLS01uSameScopeAsTheOtherTokenizerCategories:
    def test_inputs_in_the_fallback_content_of_a_closed_iframe_are_not_live(self):
        html = '<iframe src="/f"><input type=hidden name=a value=b></iframe>'

        assert _inputs(html) == []

    def test_inputs_inside_a_comment_are_not_live(self):
        assert _inputs("<!-- <input type=hidden name=a value=b> -->") == []

    def test_inputs_written_inside_a_script_are_not_live_markup(self):
        assert _inputs('<script>document.write("<input type=hidden name=a value=b>")</script>') == []

    def test_a_hidden_input_does_not_become_dead_markup(self):
        html = '<iframe src="/f"><input type=hidden src="https://esterno.example/x" name=a></iframe>'

        assert "suspicious_dead_markup" not in detect_hidden_elements(html, "sito.example")
