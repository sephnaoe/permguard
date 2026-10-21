"""Glob matching and rule table storage."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Literal

Verdict = Literal["allow", "ask", "deny"]


@dataclass(frozen=True)
class Rule:
    pattern: str
    verdict: Verdict
    note: str = ""

    def matches(self, command: str) -> bool:
        return glob_match(self.pattern, command)


def glob_to_regex(pattern: str) -> str:
    """Translate a substring glob to a regex that must match the whole string.

    `*` matches any characters including whitespace; `?` matches one char;
    everything else is literal. Matching is case-sensitive.
    """
    out: List[str] = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "^" + "".join(out) + "$"


_GLOB_CACHE: dict[str, re.Pattern] = {}


def glob_match(pattern: str, command: str) -> bool:
    compiled = _GLOB_CACHE.get(pattern)
    if compiled is None:
        compiled = re.compile(glob_to_regex(pattern))
        _GLOB_CACHE[pattern] = compiled
    return compiled.match(command) is not None


@dataclass
class RuleTable:
    version: int
    rules: List[Rule]

    def resolve(self, command: str) -> Verdict:
        """Return the verdict of the last rule whose pattern matches `command`."""
        verdict: Verdict = "allow"
        for rule in self.rules:
            if rule.matches(command):
                verdict = rule.verdict
        return verdict

    def to_list(self) -> list[dict]:
        return [
            {"pattern": r.pattern, "verdict": r.verdict, "note": r.note}
            for r in self.rules
        ]

    @classmethod
    def from_list(cls, version: int, items: list[dict]) -> "RuleTable":
        rules = [
            Rule(pattern=i["pattern"], verdict=i["verdict"], note=i.get("note", ""))
            for i in items
        ]
        return cls(version=version, rules=rules)
