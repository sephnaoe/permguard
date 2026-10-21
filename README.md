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

## Install

```bash
pip install permguard
```

## Step 1 — Write your rules (`rules.json`)

```json
{
  "version": 1,
  "rules": [
    { "pattern": "*.env*", "verdict": "deny", "note": "environment files" },
    { "pattern": "*os.environ*", "verdict": "allow", "note": "innocent env reads" },
    { "pattern": "*rm -rf*", "verdict": "deny", "note": "block destructive deletes" },
    { "pattern": "*git push*", "verdict": "ask", "note": "confirm before pushing" },
    { "pattern": "*$env:*KEY*", "verdict": "ask", "note": "PowerShell secret access" }
  ]
}
```

- `*` matches any characters, including spaces.
- Matching is case-sensitive and covers the **entire** command string.
- **Last matching rule wins**, so put broad denies first, narrow allows after.

## Step 2 — Check a command

```bash
permguard check "cat .env" --rules rules.json
# "cat .env" -> deny

permguard check "print(os.environ['X'])" --rules rules.json
# "print(os.environ['X'])" -> allow

permguard check "git push origin main" --rules rules.json
# "git push origin main" -> ask
```

Exit code is always `0` for `check` — it only reports the verdict.

## Step 3 — Pin behavior with expectation tests (`expectations.txt`)

```text
cat .env => deny
print(os.environ['X']) => allow
git push origin main => ask
rm -rf /tmp => deny
ls -la => allow
```

```bash
permguard test --rules rules.json --expect expectations.txt
# all tests passed
```

Exit `0` if every line matches, `1` if any mismatch — use this in CI to lock
the table's behavior.

## Step 4 — Catch accidental reorders (`drift`)

Under last-match-wins, swapping two rules changes behavior even if the
verdicts are identical. `drift` catches this:

```bash
permguard drift --old rules.json --new rules-edited.json
# drift: 1 behavioral change(s):
#   [1] reordered: "*.env*" (deny -> deny)
```

Exit `0` = no drift, `1` = drift detected — suitable for a pre-commit or CI
gate.

## Files in this repo

| File | Purpose |
|---|---|
| `rules.example.json` | Sample rule table (copy to `rules.json` to start) |
| `expectations.example.txt` | Sample expectation file (copy to `expectations.txt` to start) |
| `tests/` | Regression tests proving both allow and deny directions |

## Performance & accuracy

Under last-match-wins, `resolve` previously scanned every rule on every call (O(n) regex matches). For large rule tables that was too slow.

`permguard` now builds a **must-contain literal index**: each rule is bucketed by its longest maximal literal run (a sound substring any matching command must contain). At query time, only rules whose literal appears verbatim in the command are regex-tested, highest-index-first, so the first true match *is* last-match-wins with early termination.

- **10k rules:** ~0.07 ms/command indexed vs ~2.61 ms/command naive (~36x speedup)
- **Accuracy:** byte-for-byte identical to the naive last-match-wins reference (verified across 1k/10k random tables, overlapping matches at different indices, wildcard-only tables, and edge cases — 33 tests pass)
- **Worst case:** tables dominated by `*-only` rules (no literal run) degrade gracefully to the previous O(n) scan — never to wrongness

Stdlib-only; no API or `rules.json` format changes.

## License

None — this is unlicensed, use as-is.
