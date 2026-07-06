"""Evaluate parsed Sigma rules against flat event dicts.

Matching semantics (per the Sigma spec subset we support):
- A selection is a mapping of field->value(s); all fields must match (AND).
- A list of values for one field is OR (any value matches), unless the
  field carries the |all modifier.
- A selection may also be a LIST of mappings — any mapping matching = match.
- String comparison is case-insensitive; plain values support * and ?
  wildcards. Modifiers: contains, startswith, endswith, re, all.
- The condition string combines selections with and/or/not, parentheses,
  and the quantifiers `1 of X*`, `all of X*`, `1 of them`, `all of them`.
"""
import fnmatch
import re

from app.detection.sigma.field_map import resolve_field
from app.detection.sigma.parser import SigmaRule


def _match_value(actual, expected, modifiers: list[str]) -> bool:
    if actual is None:
        return expected is None

    # list-typed event fields (e.g. mitre_ids): match if any element matches
    if isinstance(actual, list):
        return any(_match_value(item, expected, modifiers) for item in actual)

    if expected is None:
        return False

    a = str(actual).lower()
    e = str(expected).lower()

    if "re" in modifiers:
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    if "contains" in modifiers:
        return e in a
    if "startswith" in modifiers:
        return a.startswith(e)
    if "endswith" in modifiers:
        return a.endswith(e)
    if isinstance(expected, bool) or isinstance(actual, bool):
        return bool(actual) == bool(expected)
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    if "*" in e or "?" in e:
        return fnmatch.fnmatch(a, e)
    return a == e


def _match_field(event: dict, raw_field: str, expected) -> bool:
    parts = raw_field.split("|")
    field, modifiers = parts[0], [m.lower() for m in parts[1:]]
    actual = resolve_field(event, field)

    if isinstance(expected, list):
        if "all" in modifiers:
            return all(_match_value(actual, v, modifiers) for v in expected)
        return any(_match_value(actual, v, modifiers) for v in expected)
    return _match_value(actual, expected, modifiers)


def _match_selection(event: dict, selection) -> bool:
    # list of mappings: OR across entries; list of scalars: keyword search in message
    if isinstance(selection, list):
        if selection and isinstance(selection[0], dict):
            return any(_match_selection(event, entry) for entry in selection)
        message = str(event.get("message", "")).lower()
        return any(str(v).lower() in message for v in selection)
    if isinstance(selection, dict):
        return all(_match_field(event, f, v) for f, v in selection.items())
    return False


# ── condition grammar ──────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


class _ConditionParser:
    """Recursive-descent parser for Sigma condition strings."""

    def __init__(self, condition: str, results: dict[str, bool]):
        self.tokens = _TOKEN_RE.findall(condition)
        self.pos = 0
        self.results = results

    def parse(self) -> bool:
        value = self._or()
        if self.pos != len(self.tokens):
            raise ValueError(f"unexpected token: {self.tokens[self.pos]!r}")
        return value

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self):
        token = self._peek()
        self.pos += 1
        return token

    def _or(self) -> bool:
        left = self._and()
        while self._peek() == "or":
            self._next()
            right = self._and()
            left = left or right
        return left

    def _and(self) -> bool:
        left = self._not()
        while self._peek() == "and":
            self._next()
            right = self._not()
            left = left and right
        return left

    def _not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        token = self._next()
        if token is None:
            raise ValueError("unexpected end of condition")
        if token == "(":
            value = self._or()
            if self._next() != ")":
                raise ValueError("missing closing parenthesis")
            return value
        if token in ("1", "all"):
            if self._next() != "of":
                raise ValueError(f"expected 'of' after {token!r}")
            pattern = self._next()
            if pattern is None:
                raise ValueError("expected selector after 'of'")
            names = (
                list(self.results)
                if pattern == "them"
                else [n for n in self.results if fnmatch.fnmatch(n, pattern)]
            )
            if not names:
                return False
            values = [self.results[n] for n in names]
            return all(values) if token == "all" else any(values)
        if token in self.results:
            return self.results[token]
        raise ValueError(f"unknown selection {token!r} in condition")


def evaluate(rule: SigmaRule, event: dict) -> bool:
    """True if the event satisfies the rule's detection condition."""
    results = {name: _match_selection(event, sel) for name, sel in rule.selections.items()}
    return _ConditionParser(rule.condition, results).parse()
