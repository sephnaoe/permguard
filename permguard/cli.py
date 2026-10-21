"""Command-line interface for permguard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .rules import RuleTable
from .resolver import resolve
from .drift import drift


def _load_table(path: Path) -> RuleTable:
    data = json.loads(path.read_text(encoding="utf-8"))
    return RuleTable.from_list(version=int(data.get("version", 1)), items=data.get("rules", []))


def _cmd_check(args: argparse.Namespace) -> int:
    table = _load_table(Path(args.rules))
    verdict = resolve(table, args.command)
    print(f"{args.command!r} -> {verdict}")
    return 0


def _cmd_drift(args: argparse.Namespace) -> int:
    old = _load_table(Path(args.old))
    new = _load_table(Path(args.new))
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
    table = _load_table(Path(args.rules))
    failures = 0
    for line in Path(args.expect).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # format: COMMAND => expect:verdict   (commands may contain spaces)
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


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.subcommand == "check":
        return _cmd_check(args)
    if args.subcommand == "drift":
        return _cmd_drift(args)
    if args.subcommand == "test":
        return _cmd_test(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
