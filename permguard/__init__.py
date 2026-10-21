"""permguard - declarative permission-shape engine with order-aware drift detection.

Matches whole command strings against substring glob rules (last match wins,
case-sensitive, `*` crosses whitespace) and reports allow / ask / deny.
"""

from .rules import Rule, RuleTable, glob_match
from .resolver import resolve, Verdict
from .drift import drift

__all__ = ["Rule", "RuleTable", "glob_match", "resolve", "Verdict", "drift"]

__version__ = "0.1.0"
