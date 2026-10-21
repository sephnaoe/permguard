"""Order-preserving drift detection between two rule tables.

Under last-match-wins semantics, reordering two rules with identical content
*is* a behavior change, so drift compares sequence position, not just set
membership.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Literal

from .rules import Rule, RuleTable

DriftKind = Literal["added", "removed", "reordered", "changed_verdict"]


@dataclass(frozen=True)
class DriftEntry:
    index: int
    kind: DriftKind
    pattern: str
    old_verdict: str | None = None
    new_verdict: str | None = None


def drift(old: RuleTable, new: RuleTable) -> List[DriftEntry]:
    """Return a list of behavioral drift entries between `old` and `new`.

    Compares rules position-by-position under last-match-wins:
    - added      : rule present at index in new but not old
    - removed    : rule present at index in old but not new
    - reordered  : same pattern appears at a different index (behavior change)
    - changed_verdict: same pattern at same index but different verdict
    """
    entries: List[DriftEntry] = []
    old_by_pattern = {r.pattern: i for i, r in enumerate(old.rules)}
    new_by_pattern = {r.pattern: i for i, r in enumerate(new.rules)}

    # Reordering: same pattern, different index
    for pattern, old_idx in old_by_pattern.items():
        new_idx = new_by_pattern.get(pattern)
        if new_idx is not None and new_idx != old_idx:
            entries.append(
                DriftEntry(
                    index=new_idx,
                    kind="reordered",
                    pattern=pattern,
                    old_verdict=old.rules[old_idx].verdict,
                    new_verdict=new.rules[new_idx].verdict,
                )
            )

    # Position-by-position comparison for same-length overlap
    for i in range(max(len(old.rules), len(new.rules))):
        old_rule = old.rules[i] if i < len(old.rules) else None
        new_rule = new.rules[i] if i < len(new.rules) else None
        if old_rule is None and new_rule is not None:
            entries.append(
                DriftEntry(index=i, kind="added", pattern=new_rule.pattern, new_verdict=new_rule.verdict)
            )
        elif old_rule is not None and new_rule is None:
            entries.append(
                DriftEntry(index=i, kind="removed", pattern=old_rule.pattern, old_verdict=old_rule.verdict)
            )
        elif old_rule is not None and new_rule is not None:
            if old_rule.pattern != new_rule.pattern:
                entries.append(
                    DriftEntry(index=i, kind="removed", pattern=old_rule.pattern, old_verdict=old_rule.verdict)
                )
                entries.append(
                    DriftEntry(index=i, kind="added", pattern=new_rule.pattern, new_verdict=new_rule.verdict)
                )
            elif old_rule.verdict != new_rule.verdict:
                entries.append(
                    DriftEntry(
                        index=i,
                        kind="changed_verdict",
                        pattern=new_rule.pattern,
                        old_verdict=old_rule.verdict,
                        new_verdict=new_rule.verdict,
                    )
                )

    return entries
