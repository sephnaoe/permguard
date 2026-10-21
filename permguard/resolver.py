"""Resolve a command string against a RuleTable (last match wins)."""

from __future__ import annotations

from .rules import RuleTable, Verdict


def resolve(table: RuleTable, command: str) -> Verdict:
    """Resolve `command` to allow / ask / deny using last-match-wins semantics.

    The entire command string is matched against each rule pattern; the last
    matching rule's verdict wins. If no rule matches, the default is `allow`.
    """
    return table.resolve(command)
