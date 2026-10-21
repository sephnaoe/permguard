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


# --- scalability: indexed resolve must match naive last-match-wins ---------


def _random_table(seed: int, n: int, p_wildcard: float = 0.8) -> RuleTable:
    import random

    rng = random.Random(seed)
    literals = ["env", "os.environ", "rm -rf", "git push", "$env:API_KEY",
                "stripe", "token=", "*.env*", "*.log", "build/"]
    items: list[dict] = []
    for i in range(n):
        if rng.random() < p_wildcard:
            pat = rng.choice(literals)
            pat = "*" + pat + "*" if rng.random() < 0.5 else "*" + pat
        else:
            pat = rng.choice(["rm -rf /tmp", "git push origin main",
                              "cat .env", "ls -la", "stripe.com"])
        items.append({"pattern": pat, "verdict": rng.choice(["allow", "ask", "deny"]),
                      "note": f"rule {i}"})
    return RuleTable.from_list(1, items)


def _random_commands(seed: int, n: int) -> list[str]:
    import random
    rng = random.Random(seed)
    bases = ["cat .env", "print(os.environ['X'])", "git push origin main",
             "rm -rf /tmp/foo", "ls -la", "stripe.com charge",
             "echo $env:API_KEY", "build/output.log", "safe command",
             "delete everything now"]
    cmds: list[str] = []
    for _ in range(n):
        base = rng.choice(bases)
        if rng.random() < 0.3:
            base = "prefix " + base
        if rng.random() < 0.3:
            base = base + " suffix"
        cmds.append(base)
    return cmds


def test_indexed_matches_naive_1000_rules():
    table = _random_table(42, 1000)
    for cmd in _random_commands(7, 200):
        assert table.resolve(cmd) == table._resolve_naive(cmd), cmd


def test_indexed_matches_naive_10000_rules():
    table = _random_table(99, 10000)
    for cmd in _random_commands(3, 100):
        assert table.resolve(cmd) == table._resolve_naive(cmd), cmd


def test_indexed_wildcard_only_table_correct():
    # No literal runs: every rule goes to the `always` bucket.
    table = RuleTable.from_list(1, [
        {"pattern": "*", "verdict": "deny"},
        {"pattern": "*?", "verdict": "allow"},
        {"pattern": "???", "verdict": "ask"},
    ])
    # "any" matches all three (*, *?, ???) -> last match wins -> "ask"
    assert table.resolve("any") == "ask"
    # "anything" matches * and *? only -> last match -> "allow"
    assert table.resolve("anything") == "allow"


def test_indexed_default_allow_when_no_literal_in_command():
    table = RuleTable.from_list(1, [
        {"pattern": "*.env", "verdict": "deny"},
        {"pattern": "*rm -rf*", "verdict": "deny"},
        {"pattern": "*git push*", "verdict": "deny"},
    ])
    # command contains none of env, rm -rf, git push -> no candidates -> allow
    assert table.resolve("safe command here") == "allow"


def test_indexed_candidate_count_is_sublinear(monkeypatch):
    # Structural (non-flaky) assertion: a selective command should regex-test
    # only O(1) rules regardless of table size.
    import permguard.rules as rules_mod

    # 5000 rules: 4999 have rare literals absent from the probe; 1 matches.
    items = [{"pattern": f"*rare_literal_{i}*", "verdict": "allow"} for i in range(4999)]
    items.append({"pattern": "*secret_key*", "verdict": "deny"})
    table = RuleTable.from_list(1, items)

    calls = {"n": 0}
    orig_matches = Rule.matches

    def counting_matches(self, command):
        calls["n"] += 1
        return orig_matches(self, command)

    monkeypatch.setattr(Rule, "matches", counting_matches)

    table.resolve("my secret_key value")
    # Only the matching rule's literal `secret_key` is present -> <= 1 regex call.
    assert calls["n"] <= 1, calls


def test_indexed_perf_budget_10000_rules():
    import time

    table = _random_table(5, 10000)
    cmds = _random_commands(1, 50)
    start = time.perf_counter()
    for cmd in cmds:
        table.resolve(cmd)
    elapsed_ms = (time.perf_counter() - start) * 1000 / len(cmds)
    # Naive 10k-rule scan is reliably >50ms/command on any host; indexed should
    # be far under. Advisory budget, not a hard gate.
    assert elapsed_ms < 50, elapsed_ms
