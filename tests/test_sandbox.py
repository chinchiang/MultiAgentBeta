"""Control-plane tests for the bounded scanner input and result-parsing helpers.

Scanner execution lives in the isolated worker path (WorkerRuntime.run_scanner
→ execute_tool → worker_entry) and requires Docker; these tests exercise the
pure helpers the worker path shares: path confinement, source bounds and the
bounded finding parser.
"""
import json
import os
from pathlib import Path
from unittest.mock import patch

from vibe_audit import sandbox


def test_safe_path_rejects_roots_links_and_missing_paths(tmp_path):
    for value in ["/", str(tmp_path / "missing"), ""]:
        try:
            sandbox._safe_path(value)
        except sandbox.SandboxBlocked:
            pass
        else:
            raise AssertionError(f"accepted {value!r}")
    link = tmp_path / "link"
    if os.name == "posix":
        link.symlink_to(tmp_path)
        try:
            sandbox._safe_path(str(link))
        except sandbox.SandboxBlocked:
            pass
        else:
            raise AssertionError("accepted a symlinked path")


def test_safe_path_accepts_real_directory_and_file(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n", encoding="utf-8")
    assert sandbox._safe_path(str(source)).is_dir()
    assert sandbox._safe_path(str(source / "app.py"), directory=False).is_file()


def test_safe_path_rejects_control_characters():
    with patch.object(Path, "absolute", return_value=Path("/bad\npath")):
        try:
            sandbox._safe_path("anything")
        except sandbox.SandboxBlocked:
            pass
        else:
            raise AssertionError("accepted newline in path")


def test_check_source_bounds_and_ignore_files(tmp_path):
    source = tmp_path / "source"
    (source / "pkg").mkdir(parents=True)
    (source / "pkg" / "app.py").write_text("print('x')\n", encoding="utf-8")
    assert sandbox._check_source(source) == 1
    (source / ".semgrepignore").write_text("*", encoding="utf-8")
    try:
        sandbox._check_source(source)
    except sandbox.SandboxBlocked:
        pass
    else:
        raise AssertionError("accepted an untrusted ignore file")
    (source / ".semgrepignore").unlink()
    with patch.object(sandbox, "MAX_FILES", 1):
        try:
            sandbox._check_source(source)
        except sandbox.SandboxBlocked:
            pass
        else:
            raise AssertionError("accepted a tree beyond the entry limit")


def test_check_source_rejects_empty_and_link_containing_trees(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    try:
        sandbox._check_source(empty)
    except sandbox.SandboxBlocked:
        pass
    else:
        raise AssertionError("accepted an empty tree")
    if os.name != "posix":
        return
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "app.py").write_text("print('x')\n", encoding="utf-8")
    (linked / "lead.py").symlink_to(linked / "app.py")
    try:
        sandbox._check_source(linked)
    except sandbox.SandboxBlocked:
        pass
    else:
        raise AssertionError("accepted a symlink")


def test_gitleaks_findings_discard_secret_content():
    output = json.dumps([{"RuleID": "fixture-rule", "File": "/src/app.py", "StartLine": 3,
                          "Description": "Synthetic secret candidate", "Secret": "NEVER_RETURN_RAW_SECRET",
                          "Match": "source-line-with-secret"}]).encode()
    findings, gaps = sandbox._parse("gitleaks", output, 1)
    assert findings[0]["file"] == "app.py" and findings[0]["state"] == "corroborated_static"
    dumped = json.dumps(findings)
    assert "NEVER_RETURN_RAW_SECRET" not in dumped and "source-line-with-secret" not in dumped
    assert gaps == []


def test_semgrep_errors_are_gaps_and_results_must_keep_schema():
    output = json.dumps({"results": [], "errors": [{"message": "parse error"}], "paths": {"scanned": ["/src/app.py"]}})
    findings, gaps = sandbox._parse("semgrep", output.encode(), 0)
    assert findings == [] and any("analysis errors" in gap for gap in gaps)
    output = json.dumps({"results": [], "paths": {}})
    findings, gaps = sandbox._parse("semgrep", output.encode(), 0)
    assert any("scanned path list" in gap for gap in gaps)
    for bad in [b"[]", b'{"paths":{}}']:
        try:
            sandbox._parse("semgrep", bad, 0)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted schema-violating output {bad!r}")


def test_osv_reports_offline_database_limitations():
    output = json.dumps({"results": [{"source": {"path": "/src/package-lock.json"},
                                      "packages": [{"vulnerabilities": [{"id": "GHSA-xxxx"}]}]}]})
    findings, gaps = sandbox._parse("osv", output.encode(), 0)
    assert findings[0]["rule_id"] == "GHSA-xxxx" and gaps


def test_exit_and_schema_failures_never_pass():
    for scanner, output, code in [("gitleaks", b"", 0), ("gitleaks", b"not JSON", 0),
                                  ("gitleaks", b"[]", 2), ("gitleaks", b"[]", 1),
                                  ("semgrep", b"{}", 0), ("osv", b"[]", 0)]:
        try:
            sandbox._parse(scanner, output, code)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted {scanner} exit={code} output={output[:20]!r}")


def test_finding_import_is_bounded():
    rows = [{"RuleID": "r", "File": "/src/app.py", "StartLine": 1, "Description": "d"}] * 1200
    findings, gaps = sandbox._parse("gitleaks", json.dumps(rows).encode(), 0)
    assert len(findings) == 1000 and any("bounded limit" in gap for gap in gaps)
