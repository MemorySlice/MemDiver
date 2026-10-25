"""engine.yara_diagnostics.locate against REAL libyara messages."""

import pytest

yara = pytest.importorskip("yara")

from memdiver.app.tools_yara import yara_check_result  # noqa: E402
from memdiver.engine.yara_diagnostics import locate  # noqa: E402


def _error(source):
    res = yara_check_result(source)
    data = res.payload
    assert data["valid"] is False
    return data["errors"][0]


def _at(err, line, col=None):
    assert err["line"] == line, err
    if col is not None:
        assert err["column"] == col, err


def test_undefined_string():
    err = _error('rule a {\n strings:\n $a = "x"\n $b = "y"\n condition:\n $a and $c\n}')
    _at(err, 6, 9)
    assert err["reported_line"] == 7 and err["relocated"] and err["rule"] == "a"
    assert err["message"].startswith("undefined string")


def test_unreferenced_string():
    err = _error('rule a {\n strings:\n $a = "x"\n $b = "y"\n condition:\n $a\n}')
    _at(err, 4, 2)
    assert err["reported_line"] == 7


def test_undefined_identifier():
    err = _error('rule a {\n strings:\n $a = "x"\n condition:\n $a and filesizee > 10\n}')
    _at(err, 5, 9)
    assert err["end_column"] == 18 and err["relocated"]


def test_unterminated_string():
    err = _error('rule a {\n strings:\n $a = "x\n condition:\n $a\n}')
    _at(err, 3, 7)
    assert err["reported_line"] == 4 and err["hint"]


def test_unclosed_rule():
    src = 'rule a {\n strings:\n $a = "x"\n condition:\n $a\n\nrule b {\n condition:\n true\n}'
    err = _error(src)
    _at(err, 1, 6)
    assert err["reported_line"] == 7
    assert err["hint"] == "rule 'a' is not closed with '}'"


def test_multi_rule_picks_right_rule():
    src = ('rule a {\n strings:\n $a = "x"\n condition:\n $a\n}\n'
           'rule b {\n strings:\n $y = "y"\n condition:\n $y and\n $z\n}')
    err = _error(src)
    assert err["rule"] == "b" and err["line"] == 12 and err["column"] == 2


def test_multiline_condition():
    src = 'rule a {\n strings:\n $a = "x"\n condition:\n $a and\n $z\n}'
    _at(_error(src), 6, 2)
    src = 'rule a {\n strings:\n $a = "x"\n condition:\n $a and\n $z\n}\nrule b {\n condition:\n true\n}'
    _at(_error(src), 6, 2)


@pytest.mark.parametrize("src", [
    'rule a {\n strings:\n $a = { ZZ }\n condition:\n $a\n}',
    'rule a {\n strings:\n $a = /(/\n condition:\n $a\n}',
    'rule a {\n strings:\n $a = "x"\n $a = "y"\n condition:\n $a\n}',
    'rule a {\n strings:\n $a = "x" bogus\n condition:\n $a\n}',
    'rule a {\n strings:\n $a = "x"\n $a\n}',
])
def test_already_correct_errors_unchanged(src):
    err = _error(src)
    assert err["relocated"] is False and err["line"] == err["reported_line"]


def test_comment_string_regex_traps():
    src = ('rule a {\n strings:\n $a = "x"\n $b = /\\$c/\n condition:\n'
           ' // $c here\n /* $c */ $a and $b and "$c" and\n $c\n}')
    _at(_error(src), 8, 2)
    src = 'rule a {\n strings:\n $a = "x" // $c\n condition:\n $a and\n $c\n}'
    _at(_error(src), 6, 2)


def test_count_offset_length_refs():
    for sigil in "#@!":
        src = f'rule a {{\n strings:\n $a = "x"\n condition:\n $a and\n {sigil}c > 1\n}}'
        _at(_error(src), 6, 2)


def test_set_patterns():
    # `$a*` references $a1/$a2 (so only $b is unreferenced) and is not a $a... mention
    src = ('rule a {\n strings:\n $a1 = "x"\n $a2 = "y"\n $b = "z"\n condition:\n'
           ' any of ($a*)\n}')
    _at(_error(src), 5, 2)
    src = 'rule a {\n strings:\n $a = "x"\n condition:\n any of ($a*) and\n $bb\n}'
    _at(_error(src), 6, 2)


def test_tags_private_global():
    src = ('global private rule a : t1 t2 {\n strings:\n $a = "x"\n condition:\n $a and\n $c\n}')
    err = _error(src)
    _at(err, 6, 2)
    assert err["rule"] == "a"
    src = 'private rule a : t {\n condition:\n true\n}\nrule b : u {\n strings:\n $p = "q"\n condition:\n true\n}'
    err = _error(src)
    assert err["rule"] == "b" and err["line"] == 7


def test_windows_line_endings():
    src = 'rule a {\n strings:\n $a = "x"\n $b = "y"\n condition:\n $a and $c\n}'.replace("\n", "\r\n")
    err = _error(src)
    _at(err, 6, 9)


def test_unknown_messages_pass_through():
    out = locate("rule a { condition: true }", 3, "something libyara never said")
    assert out == {"line": 3, "column": None, "end_column": None, "reported_line": 3,
                   "relocated": False, "rule": None, "hint": None}
    assert locate("x", None, 'undefined string "$c"')["line"] is None
    # named token absent from the source: never guess
    out = locate("rule a {\n condition:\n true\n}", 4, 'undefined string "$c"')
    assert out["relocated"] is False and out["line"] == 4


def test_empty_wildcard_does_not_hide_the_real_undefined_string():
    err = _error('rule a {\n strings:\n $a = "x"\n condition:\n any of ($*) and $c\n}')
    assert err["line"] == 5 and err["message"].startswith("undefined string")
    line = 'any of ($*) and $c'
    assert err["column"] == 1 + line.index("$c") + 1


def test_unclosed_last_rule_is_located_not_line_zero():
    src = 'rule a { condition: true }\n\nrule b {\n  strings:\n    $a = "x"\n  condition:\n    $a\n'
    err = _error(src)
    assert err["line"] == 3 and err["column"] == 6, err
    assert err["line"] != 0 and err["reported_line"] != 0
    assert err["rule"] == "b"
    assert err["hint"] == "rule 'b' is not closed with '}'"


def test_line_zero_without_an_unclosed_rule_is_never_reported_as_zero():
    out = locate("", 0, "syntax error, unexpected end of file")
    assert out["line"] is None and out["reported_line"] is None
