import json
import subprocess
import sys
from pathlib import Path

MODULE = [sys.executable, "-m", "permguard"]


def run(args, cwd):
    return subprocess.run(MODULE + args, cwd=cwd, capture_output=True, text=True)


def test_check_deny(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps({"version": 1, "rules": [{"pattern": "*rm -rf*", "verdict": "deny"}]}),
        encoding="utf-8",
    )
    res = run(["check", "rm -rf /tmp/foo", "--rules", str(rules)], tmp_path)
    assert res.returncode == 0
    assert "deny" in res.stdout


def test_check_allow_default(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"version": 1, "rules": []}), encoding="utf-8")
    res = run(["check", "ls -la", "--rules", str(rules)], tmp_path)
    assert res.returncode == 0
    assert "allow" in res.stdout


def test_drift_no_change(tmp_path):
    r1 = tmp_path / "r1.json"; r2 = tmp_path / "r2.json"
    content = {"version": 1, "rules": [{"pattern": "*.key *", "verdict": "ask"}]}
    r1.write_text(json.dumps(content), encoding="utf-8")
    r2.write_text(json.dumps(content), encoding="utf-8")
    res = run(["drift", "--old", str(r1), "--new", str(r2)], tmp_path)
    assert res.returncode == 0
    assert "no behavioral changes" in res.stdout


def test_drift_reordered(tmp_path):
    r1 = tmp_path / "r1.json"; r2 = tmp_path / "r2.json"
    r1.write_text(
        json.dumps({"version": 1, "rules": [
            {"pattern": "*.env*", "verdict": "deny"},
            {"pattern": "*os.environ*", "verdict": "allow"},
        ]}),
        encoding="utf-8",
    )
    r2.write_text(
        json.dumps({"version": 1, "rules": [
            {"pattern": "*os.environ*", "verdict": "allow"},
            {"pattern": "*.env*", "verdict": "deny"},
        ]}),
        encoding="utf-8",
    )
    res = run(["drift", "--old", str(r1), "--new", str(r2)], tmp_path)
    assert res.returncode == 1
    assert "reordered" in res.stdout


def test_test_file_all_pass(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps({"version": 1, "rules": [
            {"pattern": "*.env*", "verdict": "deny"},
            {"pattern": "*os.environ*", "verdict": "allow"},
        ]}),
        encoding="utf-8",
    )
    expect = tmp_path / "expect.txt"
    expect.write_text(
        "cat .env => deny\nprint(os.environ['X']) => allow\nls -la => allow\n",
        encoding="utf-8",
    )
    res = run(["test", "--rules", str(rules), "--expect", str(expect)], tmp_path)
    assert res.returncode == 0
    assert "all tests passed" in res.stdout
