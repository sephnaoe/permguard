# permguard

Declarative permission-shape engine. Match whole command strings against
substring glob rules (last match wins, case-sensitive, `*` crosses whitespace)
and resolve to `allow` / `ask` / `deny` — with order-aware drift detection so a
rule-table reorder is caught as a behavior change, not a no-op.

## Why this exists

Permission gates are usually a list of globs that "seem right" until an
innocent command trips one and an operator clicks "always allow." Over time the
table drifts: a broad `allow` slides ahead of a narrow `deny`, and a hole opens
silently. `permguard` treats the rule table as a versioned, order-sensitive
artifact and proves both directions:

- **9 innocent commands must still resolve `allow`** (regression guard against
  over-broad globs like `*.env*` firing on `os.environ`).
- **Boundary commands must still resolve `ask`/`deny`** (real `.env` files,
  secret paths, recursive delete, payment-shaped strings).
- **Reordering two rules is a behavior change**, not a no-op — under
  last-match-wins, position is semantics.

The idea is generalized from a permission overlay I built for a personal
agent system, then stripped of all yard coupling into a tiny, dependency-free
Python package. Nothing here depends on that system.

## Quick start

```bash
pip install permguard
```

Create `rules.json`:

```json
{
  "version": 1,
  "rules": [
    {"pattern": "*.env*", "verdict": "deny", "note": "environment files"},
    {"pattern": "*os.environ*", "verdict": "allow", "note": "innocent env reads"},
    {"pattern": "*$env:*KEY*", "verdict": "ask", "note": "PowerShell secret access"}
  ]
}
```

Resolve a command:

```bash
permguard check "cat .env" --rules rules.json
# "cat .env" -> deny

permguard check "print(os.environ['X'])" --rules rules.json
# "print(os.environ['X'])" -> allow
```

Last match wins, so `os.environ` inside an otherwise-denied string resolves
to `allow`.

## Drift detection

Compare two rule tables; reordering is flagged because position is meaning:

```bash
permguard drift --old rules.v1.json --new rules.v2.json
# drift: 1 behavioral change(s):
#   [1] reordered: "*.env*" (deny -> deny)
```

Exit 0 = no drift, 1 = drift detected — suitable for a pre-commit or CI gate.

## Expectation tests

Store `command => verdict` pairs and run them as a regression suite:

```text
cat .env => deny
print(os.environ['X']) => allow
ls -la => allow
```

```bash
permguard test --rules rules.json --expect expectations.txt
```

Exit non-zero on any mismatch — pin the table's behavior.

## License

MIT.
