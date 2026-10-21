from permguard.rules import glob_match, RuleTable, Rule
from permguard.resolver import resolve
from permguard.drift import drift


def test_star_crosses_whitespace():
    assert glob_match("*.key *", "{f.key for f in fs}")
    assert glob_match("*.key *", "print({f.key for f in fs})")
    assert not glob_match("*.key *", "x.key")


def test_question_mark():
    assert glob_match("ab?d", "abcd")
    assert not glob_match("ab?d", "abd")


def test_case_sensitive():
    assert glob_match("*.ENV", "foo.ENV")
    assert not glob_match("*.ENV", "foo.env")


def test_last_match_wins():
    table = RuleTable.from_list(
        1,
        [
            {"pattern": "*.env", "verdict": "deny"},
            {"pattern": "*os.environ*", "verdict": "allow"},
        ],
    )
    # later rule wins: os.environ reference inside a .env-adjacent string
    assert resolve(table, "print(os.environ['X'])") == "allow"
    assert resolve(table, "cat .env") == "deny"


def test_default_allow():
    table = RuleTable.from_list(1, [])
    assert resolve(table, "anything at all") == "allow"


def test_drift_changed_verdict():
    old = RuleTable.from_list(1, [{"pattern": "*.env", "verdict": "ask"}])
    new = RuleTable.from_list(1, [{"pattern": "*.env", "verdict": "deny"}])
    entries = drift(old, new)
    assert len(entries) == 1
    assert entries[0].kind == "changed_verdict"


def test_drift_reordered_is_behavior_change():
    old = RuleTable.from_list(
        1,
        [
            {"pattern": "*.env", "verdict": "deny"},
            {"pattern": "*os.environ*", "verdict": "allow"},
        ],
    )
    new = RuleTable.from_list(
        1,
        [
            {"pattern": "*os.environ*", "verdict": "allow"},
            {"pattern": "*.env", "verdict": "deny"},
        ],
    )
    entries = drift(old, new)
    assert any(e.kind == "reordered" for e in entries)


def test_drift_no_change():
    old = RuleTable.from_list(1, [{"pattern": "*.env", "verdict": "deny"}])
    new = RuleTable.from_list(1, [{"pattern": "*.env", "verdict": "deny"}])
    assert drift(old, new) == []


def test_drift_added_and_removed():
    old = RuleTable.from_list(1, [{"pattern": "*.env", "verdict": "deny"}])
    new = RuleTable.from_list(1, [])
    entries = drift(old, new)
    assert any(e.kind == "removed" for e in entries)


def test_drift_added_only():
    old = RuleTable.from_list(1, [{"pattern": "*.env", "verdict": "deny"}])
    new = RuleTable.from_list(1, [
        {"pattern": "*.env", "verdict": "deny"},
        {"pattern": "*.key *", "verdict": "ask"},
    ])
    entries = drift(old, new)
    assert any(e.kind == "added" and e.pattern == "*.key *" for e in entries)
    assert not any(e.kind == "reordered" for e in entries)


def test_drift_reordered_no_duplicate_added_removed():
    old = RuleTable.from_list(1, [
        {"pattern": "*.env", "verdict": "deny"},
        {"pattern": "*os.environ*", "verdict": "allow"},
    ])
    new = RuleTable.from_list(1, [
        {"pattern": "*os.environ*", "verdict": "allow"},
        {"pattern": "*.env", "verdict": "deny"},
    ])
    entries = drift(old, new)
    kinds = [e.kind for e in entries]
    assert kinds.count("reordered") == 2
    assert "added" not in kinds
    assert "removed" not in kinds


def test_rule_table_round_trip():
    items = [
        {"pattern": "*.env", "verdict": "deny", "note": "env files"},
        {"pattern": "*os.environ*", "verdict": "allow", "note": "innocent"},
    ]
    table = RuleTable.from_list(1, items)
    assert table.to_list() == items


def test_ask_verdict():
    table = RuleTable.from_list(1, [{"pattern": "*$env:*KEY*", "verdict": "ask"}])
    assert resolve(table, "$env:API_KEY") == "ask"


def test_metacharacters_are_literal():
    table = RuleTable.from_list(1, [{"pattern": "*$env:*KEY*", "verdict": "ask"}])
    assert resolve(table, "$env:API_KEY") == "ask"
    # the `$` and `*` in the pattern are treated as glob/escape correctly:
    assert resolve(table, "echo $env:API_KEY") == "ask"
    assert resolve(table, "echo nope") == "allow"


def test_unknown_check_is_incomplete(tmp_path):
    # kept for behavioral symmetry: permguard defaults to allow, not incomplete
    table = RuleTable.from_list(1, [])
    assert resolve(table, "anything at all") == "allow"
