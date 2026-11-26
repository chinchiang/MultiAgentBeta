"""The pull-request mutation gate covers what [tool.mutmut] mutates, and a changed test file mutates what it tests."""
import importlib.util
import json
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "mutation-pr.yml"
# The copy of the tests that mutation testing runs has no checkout around it (see test_error_messages.py).
from_checkout = pytest.mark.skipif(not WORKFLOW.is_file(), reason="the workflow and the script are not next to these tests")


def tool():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]


def script():
    spec = importlib.util.spec_from_file_location("mutation_test", ROOT / "scripts" / "mutation-test.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@from_checkout
def test_the_pull_request_run_starts_for_every_mutated_module_and_for_the_tests():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # YAML 1.1 reads the bare key "on" as true.
    paths = (workflow.get("on") or workflow[True])["pull_request"]["paths"]
    expected = {"backend/" + module.removeprefix("src/") for module in tool()["mutmut"]["only_mutate"]} | {"tests/**"}
    assert set(paths) == expected and len(paths) == len(expected)


def test_every_selected_test_file_names_what_it_tests():
    mutmut, table = tool()["mutmut"], tool()["vibeaudit"]["mutation"]["tests"]
    assert set(table) == set(mutmut["pytest_add_cli_args_test_selection"])
    assert all(set(modules) <= set(mutmut["only_mutate"]) for modules in table.values()), table
    # Every mutated module has a test file whose change mutates it.
    assert set(mutmut["only_mutate"]) == {module for modules in table.values() for module in modules}


@from_checkout
def test_a_changed_test_file_names_the_modules_it_tests(monkeypatch):
    module = script()
    def diff(args, **kwargs):
        assert args[:4] == ["git", "diff", "--name-only", "origin/main"] and args[-2:] == ["--", "tests"]
        names = "tests/test_policy_gates.py\ntests/test_snapshot_catalog.py\ntests/test_engine.py\ntests/mutation-baseline.json\n"
        return subprocess.CompletedProcess(args, 0, names, "")
    monkeypatch.setattr(module.subprocess, "run", diff)
    # test_engine.py is not in the selection, so it names nothing.
    assert module.tested_modules("origin/main") == ["src/vibe_audit/catalog.py", "src/vibe_audit/policy.py", "src/vibe_audit/snapshot.py"]


def run_changed(monkeypatch, tmp_path, functions, whole, states=None, ceilings=None):
    module = script()
    monkeypatch.setattr(module, "changed_functions", lambda ref: functions)
    monkeypatch.setattr(module, "tested_modules", lambda ref: whole)
    monkeypatch.setattr(module, "TEST_MAP", tmp_path / "mutmut-stats.json")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(ceilings or {"modules": {}, "functions": {}}), encoding="utf-8")
    monkeypatch.setattr(module, "BASELINE", baseline)
    calls = []
    monkeypatch.setattr(module, "with_link", lambda action: action())
    monkeypatch.setattr(module, "mutmut", lambda *args: calls.append(args) or (0 if states is not None else 1))
    monkeypatch.setattr(module, "states", lambda: states or {})
    return module.main(["--changed", "origin/main"]), calls


@from_checkout
def test_a_function_inside_a_module_mutated_whole_is_not_named_twice(monkeypatch, tmp_path):
    code, calls = run_changed(monkeypatch, tmp_path, ["vibe_audit.policy.xǁPolicyǁauthorize__mutmut_*", "vibe_audit.lease.x_canonical_hash__mutmut_*"],
                              ["src/vibe_audit/policy.py"])
    assert code == 1 and calls == [("run", "vibe_audit.lease.x_canonical_hash__mutmut_*", "vibe_audit.policy.*")]


@from_checkout
def test_only_unmapped_test_files_changed_means_nothing_to_mutate(monkeypatch, tmp_path, capsys):
    code, calls = run_changed(monkeypatch, tmp_path, [], [])
    assert code == 0 and calls == []
    assert "nothing to mutate" in capsys.readouterr().out


@from_checkout
@pytest.mark.parametrize("ceiling,expected", [(1, 0), (0, 1)])
def test_a_module_whose_tests_changed_is_held_to_its_module_ceiling(monkeypatch, tmp_path, ceiling, expected):
    # One mutant escapes in a function no diff touched: only the module's own ceiling can stop it.
    states = {"vibe_audit.policy.x_sealed__mutmut_1": "killed", "vibe_audit.policy.x_sealed__mutmut_2": "survived",
              "vibe_audit.lease.x_canonical_hash__mutmut_1": "survived"}
    code, calls = run_changed(monkeypatch, tmp_path, [], ["src/vibe_audit/policy.py"], states,
                              {"modules": {"src/vibe_audit/policy.py": ceiling}, "functions": {}})
    # lease.py was not named, so its escaped mutant does not count here.
    assert code == expected
    shown = [args for args in calls if args[0] == "show"]
    assert shown == ([] if expected == 0 else [("show", "vibe_audit.policy.x_sealed__mutmut_2")])
