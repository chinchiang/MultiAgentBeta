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
    output = json.dumps([{"RuleID": "generic-api-key", "File": "/src/app.py", "StartLine": 3,
                          "Description": "Synthetic secret candidate", "Secret": "NEVER_RETURN_RAW_SECRET",
                          "Match": "source-line-with-secret"}]).encode()
    findings, gaps = sandbox._parse("gitleaks", output, 1)
    assert findings[0]["file"] == "app.py" and findings[0]["state"] == "corroborated_static"
    dumped = json.dumps(findings)
    assert "NEVER_RETURN_RAW_SECRET" not in dumped and "source-line-with-secret" not in dumped
    # The scanner's own description is not imported either; the harness writes the title.
    assert findings[0]["title"] == "Potential secret exposure" and "Synthetic secret candidate" not in dumped
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
    findings, gaps = sandbox._parse("osv", output.encode(), 0, frozenset({"GHSA-xxxx"}))
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
    rows = [{"RuleID": "generic-api-key", "File": "/src/app.py", "StartLine": n, "Description": "d"} for n in range(1, 1201)]
    findings, gaps = sandbox._parse("gitleaks", json.dumps(rows).encode(), 0)
    assert len(findings) == 1000 and any("bounded limit" in gap for gap in gaps)


def test_scanner_text_is_a_claim_titles_come_from_the_harness():
    # A compromised scanner could copy staged secret files into any free-text field it returns.
    leaked = "AKIA" + "Z" * 16
    semgrep = json.dumps({"results": [
        {"check_id": "inputs.rules.vibe-python-dynamic-eval", "path": "/src/app.py", "start": {"line": 2},
         "extra": {"message": "copied secret " + leaked}},
        {"check_id": "attacker." + leaked, "path": "/src/app.py", "start": {"line": 3}, "extra": {"message": leaked}}],
        "paths": {"scanned": ["/src/app.py"]}})
    findings, gaps = sandbox._parse("semgrep", semgrep.encode(), 1)
    assert findings[0]["rule_id"] == "vibe-python-dynamic-eval"
    assert findings[0]["title"] == "Dynamic evaluation requires manual input and trust-boundary review."
    assert findings[1]["rule_id"] == sandbox.UNRECOGNIZED and any("does not recognize" in gap for gap in gaps)
    gitleaks = json.dumps([{"RuleID": "aws-access-token", "File": "/src/.env", "StartLine": 1, "Description": leaked},
                           {"RuleID": leaked, "File": "/src/.env", "StartLine": 2, "Description": "d"}])
    findings += sandbox._parse("gitleaks", gitleaks.encode(), 1)[0]
    osv = json.dumps({"results": [{"source": {"path": "/src/package-lock.json"},
                                   "packages": [{"vulnerabilities": [{"id": "GHSA-abcd-efgh-ijkl"}, {"id": "secret text " + leaked}]}]}]})
    findings += sandbox._parse("osv", osv.encode(), 1, frozenset({"GHSA-abcd-efgh-ijkl"}))[0]
    assert [f["rule_id"] for f in findings[2:]] == ["aws-access-token", sandbox.UNRECOGNIZED, "GHSA-abcd-efgh-ijkl", sandbox.UNRECOGNIZED]
    assert leaked not in json.dumps(findings)


def test_rule_ids_are_names_the_harness_lists_not_shapes():
    # The right shape is not enough: a lowercase hex or base62 string can spell out a staged secret file.
    encoded = b"DB_PASSWORD=hunter2".hex()
    gitleaks = json.dumps([{"RuleID": rule, "File": "/src/.env", "StartLine": 1} for rule in
                           ["generic-api-key", encoded, "aws-" + encoded[:20]]])
    findings, gaps = sandbox._parse("gitleaks", gitleaks.encode(), 1)
    assert sorted(f["rule_id"] for f in findings) == ["generic-api-key", sandbox.UNRECOGNIZED]
    # Both unlisted names become the same fact, so they are imported once.
    assert encoded not in json.dumps(findings) and any("1 gitleaks finding(s)" in gap for gap in gaps)
    # The list is the pinned image's defaults, so the harness's own config adds nothing it does not name.
    assert len(sandbox.gitleaks_rule_ids()) == 222 and "generic-api-key" in sandbox.gitleaks_rule_ids()
    osv = json.dumps({"results": [{"source": {"path": "/src/package-lock.json"}, "packages": [
        {"vulnerabilities": [{"id": "GHSA-2222-3333-4444"}, {"id": "GHSA-" + encoded}, {"id": "PYSEC-2024-1"}]}]}]})
    findings, gaps = sandbox._parse("osv", osv.encode(), 1, frozenset({"GHSA-2222-3333-4444"}))
    assert sorted(f["rule_id"] for f in findings) == ["GHSA-2222-3333-4444", sandbox.UNRECOGNIZED]
    # Without a provisioned database nothing names an OSV record.
    findings, _ = sandbox._parse("osv", osv.encode(), 1)
    assert {f["rule_id"] for f in findings} == {sandbox.UNRECOGNIZED}


def test_order_and_repetition_of_findings_carry_nothing():
    rows = [{"RuleID": "generic-api-key", "File": "/src/b.py", "StartLine": 2},
            {"RuleID": "aws-access-token", "File": "/src/a.py", "StartLine": 9},
            {"RuleID": "generic-api-key", "File": "/src/b.py", "StartLine": 2},
            {"RuleID": "generic-api-key", "File": "/src/a.py", "StartLine": 9}]
    findings, _ = sandbox._parse("gitleaks", json.dumps(rows).encode(), 1)
    reordered, _ = sandbox._parse("gitleaks", json.dumps(rows[::-1] + rows[:1] * 5).encode(), 1)
    assert findings == reordered
    assert [(f["file"], f["line"], f["rule_id"]) for f in findings] == [
        ("a.py", 9, "aws-access-token"), ("a.py", 9, "generic-api-key"), ("b.py", 2, "generic-api-key")]


def test_osv_ids_come_from_the_provisioned_archives(tmp_path):
    import zipfile
    for ecosystem, names in [("PyPI", ["PYSEC-2024-1.json", "GHSA-2222-3333-4444.json"]), ("npm", ["MAL-2025-7.json", "README"])]:
        archive = tmp_path / "osv-scanner" / ecosystem / "all.zip"
        archive.parent.mkdir(parents=True)
        with zipfile.ZipFile(archive, "w") as bundle:
            for name in names:
                bundle.writestr(name, "{}")
    assert sandbox.osv_database_ids(tmp_path) == {"PYSEC-2024-1", "GHSA-2222-3333-4444", "MAL-2025-7"}
    assert sandbox.osv_database_ids(tmp_path / "missing") == frozenset()
