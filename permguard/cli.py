"""Command-line interface for permguard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .rules import RuleTable
from .resolver import resolve
from .drift import drift


def _load_table(path: Path) -> tuple[RuleTable, str | None]:
    """Load a rule table, returning (table, error_message).

    On success the error message is None. On failure the table is an empty
    table and the message describes what went wrong, so the caller can print
    a clean error instead of dumping a traceback.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return RuleTable.from_list(version=1, items=[]), f"rules file not found: {path}"
    except json.JSONDecodeError as exc:
        return RuleTable.from_list(version=1, items=[]), f"invalid JSON in {path}: {exc}"
    except UnicodeDecodeError as exc:
        return RuleTable.from_list(version=1, items=[]), f"cannot decode {path} as UTF-8: {exc}"
    except OSError as exc:
        return RuleTable.from_list(version=1, items=[]), f"cannot read {path}: {exc}"
    return (
        RuleTable.from_list(version=int(data.get("version", 1)), items=data.get("rules", [])),
        None,
    )


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def _cmd_check(args: argparse.Namespace) -> int:
    table, error = _load_table(Path(args.rules))
    if error is not None:
        return _fail(error)
    verdict = resolve(table, args.command)
    print(f"{args.command!r} -> {verdict}")
    return 0


def _cmd_drift(args: argparse.Namespace) -> int:
    old, error = _load_table(Path(args.old))
    if error is not None:
        return _fail(error)
    new, error = _load_table(Path(args.new))
    if error is not None:
        return _fail(error)
    entries = drift(old, new)
    if not entries:
        print("drift: no behavioral changes")
        return 0
    print(f"drift: {len(entries)} behavioral change(s):")
    for e in entries:
        print(
            f"  [{e.index}] {e.kind}: {e.pattern!r} "
            f"({e.old_verdict} -> {e.new_verdict})"
        )
    return 1


def _cmd_test(args: argparse.Namespace) -> int:
    table, error = _load_table(Path(args.rules))
    if error is not None:
        return _fail(error)
    try:
        lines = Path(args.expect).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return _fail(f"cannot read {args.expect}: {exc}")
    failures = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # format: COMMAND => verdict   (commands may contain spaces)
        if "=>" not in line:
            continue
        command, _, expect = line.partition("=>")
        command = command.strip()
        expect = expect.strip()
        got = resolve(table, command)
        status = "OK" if got == expect else "FAIL"
        if got != expect:
            failures += 1
        print(f"{status}: {command!r} -> {got} (expected {expect})")
    if failures:
        print(f"\n{failures} test(s) failed")
        return 1
    print("\nall tests passed")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="permguard", description="Declarative permission-shape engine")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_check = sub.add_parser("check", help="resolve a command to allow/ask/deny")
    p_check.add_argument("command")
    p_check.add_argument("--rules", required=True)

    p_drift = sub.add_parser("drift", help="compare two rule tables for behavioral drift")
    p_drift.add_argument("--old", required=True)
    p_drift.add_argument("--new", required=True)

    p_test = sub.add_parser("test", help="run command=>verdict expectation file")
    p_test.add_argument("--rules", required=True)
    p_test.add_argument("--expect", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.subcommand == "check":
        return _cmd_check(args)
    if args.subcommand == "drift":
        return _cmd_drift(args)
    if args.subcommand == "test":
        return _cmd_test(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
