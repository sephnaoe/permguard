"""Glob matching and rule table storage with a must-contain literal index.

The index makes `resolve` sub-linear in regex evaluations for the realistic
(selective) workload: each rule is bucketed by its longest maximal literal
run (a sound must-contain substring), and at query time only rules whose
literal appears verbatim in the command are regex-tested, highest-index-first
so the first true match *is* last-match-wins with early termination.

Worst case (tables dominated by `*-only` rules with no literal run) degrades
gracefully to the previous O(n) scan — never to wrongness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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


def _extract_must_contain(pattern: str) -> str | None:
    """Return the longest maximal run of literal characters in `pattern`.

    A literal run is a maximal contiguous span containing neither `*` nor `?`.
    Any command matching the glob must contain this substring contiguously
    (the compiled regex places those literal chars contiguously, with only
    `*`/? consuming characters in between). Returns None when no literal run
    exists (e.g. `*`, `*?`, `???`), meaning the rule matches nothing
    structurally constraining and must be tested on every query.
    """
    best: str | None = None
    current: List[str] = []
    for ch in pattern:
        if ch in "*?":
            run = "".join(current)
            if run and (best is None or len(run) > len(best)):
                best = run
            current = []
        else:
            current.append(ch)
    run = "".join(current)
    if run and (best is None or len(run) > len(best)):
        best = run
    return best


@dataclass
class RuleTable:
    version: int
    rules: List[Rule]
    _buckets: dict[str, list[int]] = field(init=False, repr=False, default_factory=dict)
    _always: list[int] = field(init=False, repr=False, default_factory=list)

    def __post_init__(self) -> None:
        buckets: dict[str, list[int]] = {}
        always: list[int] = []
        for idx, rule in enumerate(self.rules):
            key = _extract_must_contain(rule.pattern)
            if key is None:
                always.append(idx)
            else:
                buckets.setdefault(key, []).append(idx)
        self._buckets = buckets
        self._always = always

    def resolve(self, command: str) -> Verdict:
        """Return the verdict of the last rule whose pattern matches `command`.

        Uses a must-contain literal index: candidate rule indices are those
        whose pattern's longest literal run appears verbatim in `command`,
        plus the unfilterable `always` bucket. Candidates are tested
        highest-index-first so the first true match *is* last-match-wins,
        with early termination. Returns `allow` when nothing matches.
        """
        candidates: set[int] = set(self._always)
        for key, indices in self._buckets.items():
            if key in command:
                candidates.update(indices)
        if not candidates:
            return "allow"
        # Highest index first -> first match is last-match-wins, early exit.
        for idx in sorted(candidates, reverse=True):
            if self.rules[idx].matches(command):
                return self.rules[idx].verdict
        return "allow"

    def _resolve_naive(self, command: str) -> Verdict:
        """Reference linear scan (kept for parity testing)."""
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
