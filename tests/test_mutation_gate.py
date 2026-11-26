"""The pull-request mutation gate covers what [tool.mutmut] mutates, and a changed test file mutates what it tests."""
import importlib.util
import json
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


def workflow(name="mutation-pr.yml"):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))


@from_checkout
def test_the_pull_request_run_starts_for_every_mutated_module_the_tests_and_their_table():
    # YAML 1.1 reads the bare key "on" as true.
    paths = (workflow().get("on") or workflow()[True])["pull_request"]["paths"]
    # pyproject.toml holds the selection and [tool.vibeaudit.mutation.tests]: changing either is a test change.
    expected = {"backend/" + module.removeprefix("src/") for module in tool()["mutmut"]["only_mutate"]} | {"tests/**", "pyproject.toml"}
    assert set(paths) == expected and len(paths) == len(expected)


@from_checkout
def test_the_pull_request_run_has_the_full_runs_time():
    # A test change can mutate several modules whole, close to a full run.
    assert workflow()["jobs"]["changed"]["timeout-minutes"] == workflow("mutation.yml")["jobs"]["mutmut"]["timeout-minutes"]


@from_checkout
def test_a_manual_dispatch_compares_with_the_default_branch():
    # base_ref is empty outside a pull request; "origin/" alone is no revision.
    runs = [step["run"] for step in workflow()["jobs"]["changed"]["steps"] if "mutation-test.py" in step.get("run", "")]
    assert runs == ['python scripts/mutation-test.py --changed "origin/${{ github.base_ref || github.event.repository.default_branch }}"']


def test_every_selected_test_file_names_what_it_tests():
    mutmut, table = tool()["mutmut"], tool()["vibeaudit"]["mutation"]["tests"]
    assert set(table) == set(mutmut["pytest_add_cli_args_test_selection"])
    assert all(set(modules) <= set(mutmut["only_mutate"]) for modules in table.values()), table
    # Every mutated module has a test file whose change mutates it.
    assert set(mutmut["only_mutate"]) == {module for modules in table.values() for module in modules}


def modules_for(monkeypatch, names, then=None):
    """tested_modules with these files changed since the base, and the table at the base as given (as now if None)."""
    module = script()
    now = tool()["vibeaudit"]["mutation"]["tests"]
    monkeypatch.setattr(module, "changed_test_files", lambda base: names)
    monkeypatch.setattr(module, "table_at", lambda base: now if then is None else then)
    return module.tested_modules("base")


@from_checkout
def test_a_changed_test_file_names_the_modules_it_tests(monkeypatch):
    # test_engine.py is not in the selection and the baseline is no test, so neither names anything.
    names = ["tests/test_policy_gates.py", "tests/test_snapshot_catalog.py", "tests/test_engine.py", "tests/mutation-baseline.json"]
    assert modules_for(monkeypatch, names) == ["src/vibe_audit/catalog.py", "src/vibe_audit/policy.py", "src/vibe_audit/snapshot.py"]


@from_checkout
def test_a_deleted_test_file_names_what_it_tested_at_the_base(monkeypatch):
    then = {**tool()["vibeaudit"]["mutation"]["tests"], "tests/test_gone.py": ["src/vibe_audit/lease.py"]}
    assert modules_for(monkeypatch, ["tests/test_gone.py"], then) == ["src/vibe_audit/lease.py"]


@from_checkout
def test_an_entry_of_the_table_that_changed_names_both_its_old_and_new_modules(monkeypatch):
    # No test file changed: only what the table says one tests.
    then = {**tool()["vibeaudit"]["mutation"]["tests"], "tests/test_lease.py": ["src/vibe_audit/catalog.py"]}
    assert modules_for(monkeypatch, [], then) == ["src/vibe_audit/catalog.py", "src/vibe_audit/lease.py"]


@from_checkout
def test_a_changed_helper_names_what_the_test_files_importing_it_test(monkeypatch):
    importers = [name for name in tool()["vibeaudit"]["mutation"]["tests"] if "from fakes import" in (ROOT / name).read_text(encoding="utf-8")]
    assert "tests/test_answers.py" in importers
    expected = sorted({module for name in importers for module in tool()["vibeaudit"]["mutation"]["tests"][name]})
    assert modules_for(monkeypatch, ["tests/fakes.py"]) == expected and "src/vibe_audit/answers.py" in expected


@from_checkout
def test_the_comparison_is_against_where_the_branch_left_the_base(monkeypatch, tmp_path):
    module = script()
    seen = []
    # mutmut itself needs Linux; nothing here runs it, so these run on Windows too.
    monkeypatch.setattr(module, "require_posix", lambda: None)
    monkeypatch.setattr(module, "merge_base", lambda ref: "base-commit")
    monkeypatch.setattr(module, "changed_functions", lambda base: seen.append(("functions", base)) or [])
    monkeypatch.setattr(module, "tested_modules", lambda base: seen.append(("tests", base)) or [])
    assert module.main(["--changed", "origin/main"]) == 0
    assert seen == [("tests", "base-commit"), ("functions", "base-commit")]


def run_changed(monkeypatch, tmp_path, functions, whole, states=None, ceilings=None):
    module = script()
    monkeypatch.setattr(module, "require_posix", lambda: None)
    monkeypatch.setattr(module, "merge_base", lambda ref: "base-commit")
    monkeypatch.setattr(module, "changed_functions", lambda base: functions)
    monkeypatch.setattr(module, "tested_modules", lambda base: whole)
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


@from_checkout
def test_a_changed_function_in_a_module_mutated_whole_keeps_its_own_ceiling(monkeypatch, tmp_path, capsys):
    # The module stays within its total, yet the new function lets a mutant escape: new code must let none.
    states = {"vibe_audit.policy.x_fresh__mutmut_1": "survived", "vibe_audit.policy.x_sealed__mutmut_1": "killed"}
    code, calls = run_changed(monkeypatch, tmp_path, ["vibe_audit.policy.x_fresh__mutmut_*"], ["src/vibe_audit/policy.py"], states,
                              {"modules": {"src/vibe_audit/policy.py": 2}, "functions": {}})
    assert calls[0] == ("run", "vibe_audit.policy.*")
    assert code == 1 and "vibe_audit.policy.x_fresh: 1 escaped, ceiling none (new code)" in capsys.readouterr().out
