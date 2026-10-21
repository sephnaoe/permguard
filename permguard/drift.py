"""Order-preserving drift detection between two rule tables.

Under last-match-wins semantics, reordering two rules with identical content
*is* a behavior change, so drift compares sequence position, not just set
membership. A pattern present in both tables but at a different index is
reported once as `reordered` (not also as `removed`+`added`). Patterns that
appear in only one table are `added` or `removed`; same-pattern/same-index
rules with a different verdict are `changed_verdict`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .rules import Rule, RuleTable

DriftKind = Literal["added", "removed", "reordered", "changed_verdict"]


@dataclass(frozen=True)
class DriftEntry:
    index: int
    kind: DriftKind
    pattern: str
    old_verdict: str | None = None
    new_verdict: str | None = None


def drift(old: RuleTable, new: RuleTable) -> list[DriftEntry]:
    """Return a list of behavioral drift entries between `old` and `new`.

    Under last-match-wins:
    - added        : pattern present in new but not old
    - removed      : pattern present in old but not new
    - reordered    : same pattern at a different index (behavior change)
    - changed_verdict: same pattern at same index but different verdict
    """
    entries: list[DriftEntry] = []
    old_by_pattern = {r.pattern: i for i, r in enumerate(old.rules)}
    new_by_pattern = {r.pattern: i for i, r in enumerate(new.rules)}

    old_patterns = set(old_by_pattern)
    new_patterns = set(new_by_pattern)

    # Added and removed: symmetric difference of pattern sets.
    for pattern in sorted(new_patterns - old_patterns):
        i = new_by_pattern[pattern]
        entries.append(
            DriftEntry(index=i, kind="added", pattern=pattern, new_verdict=new.rules[i].verdict)
        )
    for pattern in sorted(old_patterns - new_patterns):
        i = old_by_pattern[pattern]
        entries.append(
            DriftEntry(index=i, kind="removed", pattern=pattern, old_verdict=old.rules[i].verdict)
        )

    # Shared patterns: verdict and/or position changed.
    for pattern in sorted(old_patterns & new_patterns):
        old_i = old_by_pattern[pattern]
        new_i = new_by_pattern[pattern]
        old_rule = old.rules[old_i]
        new_rule = new.rules[new_i]
        if old_i != new_i:
            entries.append(
                DriftEntry(
                    index=new_i,
                    kind="reordered",
                    pattern=pattern,
                    old_verdict=old_rule.verdict,
                    new_verdict=new_rule.verdict,
                )
            )
        elif old_rule.verdict != new_rule.verdict:
            entries.append(
                DriftEntry(
                    index=new_i,
                    kind="changed_verdict",
                    pattern=pattern,
                    old_verdict=old_rule.verdict,
                    new_verdict=new_rule.verdict,
                )
            )

    return entries
