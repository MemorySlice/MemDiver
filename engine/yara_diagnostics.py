"""Place a libyara compile error on the token that is actually wrong.

libyara reports an error that names an identifier at the line where the rule
ENDS (``undefined string "$c"``, ``unreferenced string "$b"``) or at the next
token after the mistake (an unterminated ``"`` is reported on the following
line; a rule missing its ``}`` is reported at the next ``rule``). An editor that
underlines the reported line therefore underlines the wrong line.

:func:`locate` re-reads the source with a small YARA-aware lexer (comments, text
strings, regexes and hex strings are skipped, so a ``$c`` inside any of them is
never mistaken for a reference) and moves the error to the token that caused it.
It only relocates the message shapes it understands and only when it finds the
token; otherwise the reported line is returned unchanged. It never guesses.

Pure compute: no imports from ``app`` or ``presentation``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

_STRING_REF_PREFIX = "$#@!"
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class Token:
    kind: str          # ident | strid | text | regex | hex | punct | other
    text: str
    line: int
    column: int        # 1-based
    unterminated: bool = False

    @property
    def end_column(self) -> int:
        return self.column + len(self.text)


@dataclass
class RuleSpan:
    name: str
    name_token: Token
    start_line: int
    end_line: int
    closed: bool = True
    strings: List[Token] = field(default_factory=list)
    condition: List[Token] = field(default_factory=list)


class _Lexer:
    def __init__(self, src: str) -> None:
        self.src, self.i, self.line, self.col = src, 0, 1, 1
        self.tokens: List[Token] = []

    def _advance(self, n: int = 1) -> None:
        for ch in self.src[self.i:self.i + n]:
            if ch == "\n":
                self.line, self.col = self.line + 1, 1
            else:
                self.col += 1
        self.i += n

    def _prev(self) -> Optional[Token]:
        return self.tokens[-1] if self.tokens else None

    def _emit(self, kind: str, start: int, line: int, col: int, **kw: Any) -> None:
        self.tokens.append(Token(kind, self.src[start:self.i], line, col, **kw))

    def _skip_comment(self) -> bool:
        s = self.src
        if s.startswith("//", self.i):
            end = s.find("\n", self.i)
            self._advance((len(s) if end < 0 else end) - self.i)
            return True
        if s.startswith("/*", self.i):
            end = s.find("*/", self.i + 2)
            self._advance((len(s) if end < 0 else end + 2) - self.i)
            return True
        return False

    def _quoted(self, quote: str, kind: str) -> None:
        """A ``"..."`` or ``/.../`` token; it cannot span a newline."""
        s, start, line, col = self.src, self.i, self.line, self.col
        j, closed = self.i + 1, False
        while j < len(s) and s[j] != "\n":
            if s[j] == "\\" and j + 1 < len(s) and s[j + 1] != "\n":
                j += 2
                continue
            if s[j] == quote:
                closed, j = True, j + 1
                break
            j += 1
        self._advance(j - self.i)
        if closed and kind == "regex":
            while self.i < len(s) and s[self.i] in "is":
                self._advance()
        self._emit(kind, start, line, col, unterminated=not closed)

    def _hex(self) -> None:
        s, start, line, col = self.src, self.i, self.line, self.col
        j = self.i + 1
        while j < len(s) and s[j] != "}":
            if s.startswith("//", j):
                j = s.find("\n", j)
                j = len(s) if j < 0 else j
            elif s.startswith("/*", j):
                j = s.find("*/", j + 2)
                j = len(s) if j < 0 else j + 2
            else:
                j += 1
        self._advance(min(j + 1, len(s)) - self.i)
        self._emit("hex", start, line, col)

    def _regex_may_start(self, section: str) -> bool:
        prev = self._prev()
        if prev is None:
            return False
        if section == "strings":
            return prev.text == "="
        return prev.kind == "ident" and prev.text == "matches"

    def run(self) -> List[Token]:
        s, section = self.src, ""
        while self.i < len(s):
            ch = s[self.i]
            if ch.isspace() or self._skip_comment():
                self._advance(1 if ch.isspace() else 0)
                continue
            line, col, start = self.line, self.col, self.i
            prev = self._prev()
            if ch == '"':
                self._quoted('"', "text")
            elif ch == "/" and self._regex_may_start(section):
                self._quoted("/", "regex")
            elif ch == "{" and section == "strings" and prev is not None and prev.text == "=":
                self._hex()
            elif ch in _STRING_REF_PREFIX and (m := re.compile(r"[A-Za-z0-9_]*\*?").match(s, self.i + 1)):
                self._advance(1 + m.end() - m.start())
                self._emit("strid", start, line, col)
            elif m := _IDENT_RE.match(s, self.i):
                self._advance(m.end() - m.start())
                self._emit("ident", start, line, col)
            else:
                self._advance()
                self._emit("punct" if not ch.isalnum() else "other", start, line, col)
            section = self._section(section)
        return self.tokens

    def _section(self, section: str) -> str:
        t = self.tokens
        if len(t) >= 2 and t[-1].text == ":" and t[-2].kind == "ident" \
                and t[-2].text in ("strings", "condition", "meta"):
            return t[-2].text
        if t and t[-1].kind == "ident" and t[-1].text == "rule":
            return ""
        return section


def _is_rule_header(tokens: List[Token], k: int) -> bool:
    return (tokens[k].kind == "ident" and tokens[k].text == "rule" and k + 1 < len(tokens)
            and tokens[k + 1].kind == "ident")


def _parse_rules(tokens: List[Token]) -> List[RuleSpan]:
    rules: List[RuleSpan] = []
    current: Optional[RuleSpan] = None
    depth, section, k = 0, "", 0
    while k < len(tokens):
        tok = tokens[k]
        if _is_rule_header(tokens, k) and (current is None or depth > 0):
            if current is not None:                       # previous rule never closed
                current.closed = False
                current.end_line = tokens[k - 1].line
            current = RuleSpan(tokens[k + 1].text, tokens[k + 1], tok.line, tok.line)
            rules.append(current)
            depth, section = 0, ""
            while k < len(tokens) and tokens[k].text != "{":
                k += 1
            depth = 1
        elif current is not None:
            current.end_line = tok.line
            if tok.kind == "punct" and tok.text == "{":
                depth += 1
            elif tok.kind == "punct" and tok.text == "}":
                depth -= 1
                if depth == 0:
                    current = None
            elif tok.kind == "ident" and tok.text in ("strings", "condition", "meta") \
                    and k + 1 < len(tokens) and tokens[k + 1].text == ":":
                section = tok.text
            elif section == "strings":
                current.strings.append(tok)
            elif section == "condition":
                current.condition.append(tok)
        k += 1
    if current is not None and depth > 0:
        current.closed = False
    return rules


def _lex_with_sections(source: str) -> List[Token]:
    """Lex *source*; the lexer needs to know the section to tell a regex from a division."""
    lexer = _Lexer(source)
    return lexer.run()


def _rule_at(rules: List[RuleSpan], line: int) -> Optional[RuleSpan]:
    best = None
    for rule in rules:
        if rule.start_line <= line <= rule.end_line + 1:
            best = rule
    return best


def _name_matches(token: Token, name: str) -> bool:
    if token.kind != "strid":
        return False
    body = token.text[1:]
    if body.endswith("*"):
        prefix = body[:-1]
        return bool(prefix) and name.startswith(prefix)
    return body == name


def _result(reported: Optional[int], tok: Optional[Token], rule: Optional[RuleSpan],
            hint: Optional[str] = None) -> Dict[str, Any]:
    if tok is None:
        return {"line": reported, "column": None, "end_column": None, "reported_line": reported,
                "relocated": False, "rule": rule.name if rule else None, "hint": None}
    return {"line": tok.line, "column": tok.column, "end_column": tok.end_column,
            "reported_line": reported, "relocated": True,
            "rule": rule.name if rule else None, "hint": hint}


_RELOCATORS = (
    (re.compile(r'undefined string "[$#@!]?(\w+)"'), "undefined"),
    (re.compile(r'unreferenced string "[$#@!]?(\w+)"'), "unreferenced"),
    (re.compile(r'undefined identifier "(\w+)"'), "identifier"),
)


def _find(rule: RuleSpan, kind: str, name: str) -> Optional[Token]:
    if kind == "undefined":
        exact = next((t for t in rule.condition
                      if t.kind == "strid" and t.text[1:] == name), None)
        if exact is not None:
            return exact
        return next((t for t in rule.condition if _name_matches(t, name)), None)
    if kind == "unreferenced":
        for k, t in enumerate(rule.strings):
            nxt = rule.strings[k + 1] if k + 1 < len(rule.strings) else None
            if t.kind == "strid" and t.text == "$" + name and nxt is not None and nxt.text == "=":
                return t
        return None
    return next((t for t in rule.condition if t.kind == "ident" and t.text == name), None)


def _locate_unclosed_last_rule(source: str, message: str) -> Optional[Dict[str, Any]]:
    """An unclosed LAST rule is reported as ``line 0: unexpected end of file, expecting '}'``."""
    if "end of file" not in message:
        return None
    rules = _parse_rules(_lex_with_sections(source))
    open_rules = [r for r in rules if not r.closed]
    if not open_rules:
        return None
    pick = open_rules[-1]
    return _result(None, pick.name_token, pick, f"rule '{pick.name}' is not closed with '}}'")


def locate(source: str, reported_line: Optional[int], message: str) -> Dict[str, Any]:
    """Return ``{line, column, end_column, reported_line, relocated, rule, hint}``.

    ``column`` / ``end_column`` are 1-based (``end_column`` is one past the last
    character) and ``None`` when no token was found. ``relocated`` is True when a
    token was identified (its line may equal ``reported_line``); False means the
    reported line is returned untouched.
    """
    if reported_line is not None and reported_line < 1:
        reported_line = None        # libyara's "line 0" names no line at all
    unchanged = _result(reported_line, None, None)
    if not isinstance(source, str):
        return unchanged
    if reported_line is None:
        return _locate_unclosed_last_rule(source, message) or unchanged
    tokens = _lex_with_sections(source)
    rules = _parse_rules(tokens)
    rule = _rule_at(rules, reported_line)

    if "unexpected <rule>, expecting '}'" in message:
        open_rules = [r for r in rules if not r.closed]
        pick = next((r for r in open_rules if r.end_line + 1 >= reported_line - 1
                     and r.end_line <= reported_line), None)
        if pick is not None:
            return _result(reported_line, pick.name_token, pick,
                           f"rule '{pick.name}' is not closed with '}}'")
        return unchanged
    if "expecting text string" in message or "unterminated" in message:
        bad = next((t for t in tokens if t.kind == "text" and t.unterminated), None)
        if bad is not None:
            return _result(reported_line, Token("text", '"', bad.line, bad.column), rule,
                           "unterminated text string")
        return unchanged
    for pattern, kind in _RELOCATORS:
        found = pattern.search(message)
        if found and rule is not None:
            tok = _find(rule, kind, found.group(1))
            return _result(reported_line, tok, rule) if tok else unchanged
    return unchanged
