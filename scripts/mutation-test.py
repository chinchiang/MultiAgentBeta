"""Mutation-test the deterministic gates and parsers with mutmut (Linux only, no network, no credentials).

  python -m pip install --require-hashes -r requirements.mutation.lock.txt
  python scripts/mutation-test.py                     mutate the modules [tool.mutmut] in pyproject.toml names, run their tests
  python scripts/mutation-test.py --update-baseline   the same, then record the escaped mutants per module and per function
  python scripts/mutation-test.py --changed <ref>     only the functions the diff against <ref> touched (a pull request);
                                                      prints the change each escaped mutant of a function over its ceiling made
  python scripts/mutation-test.py <mutant name>...    re-test the named mutants only (see mutmut results / mutmut show)

mutmut changes one operator, constant or branch of the code at a time and runs the tests that cover the changed
function; a mutant the tests still pass ("survived") or that no test reaches ("no tests") is a blind spot.
tests/mutation-baseline.json records how many such mutants each module, and each function, had when it was last
accepted, so a full run fails when a module's count rises and a --changed run fails when a touched function's count
rises: a change that loosens a test or adds untested logic. A function the baseline does not name (new code) must
leave none. Lower a ceiling by adding tests, then --update-baseline; it never goes up by itself. mutmut keeps its
working copy and results in mutants/ (ignored by git) and reuses a result whose mutant text is unchanged, even
when the tests changed, so a full run starts from an empty mutants/ and runs every mutant; a --changed or named run
re-runs the mutants it names.

mutmut maps src/<package>/<module>.py to the module <package>.<module> that the tests import, so the run links
src -> backend and removes the link afterwards. mutmut remembers which tests reach each function
(mutants/mutmut-stats.json) and, between runs, re-maps only tests that are new; a function that is new, or newly
called from one the tests already reached, would keep an empty map and its mutants would face only the new tests.
A --changed run therefore drops that map first, at the cost of one plain test run, so every mutant meets every test
that reaches it.
"""
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = ROOT / "src"
BASELINE = ROOT / "tests" / "mutation-baseline.json"
MUTANTS = ROOT / "mutants"
TEST_MAP = MUTANTS / "mutmut-stats.json"
ESCAPED = ("survived", "no tests")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)


def mutmut(*args):
    # What this script printed so far goes out first: mutmut writes to the same output, and a redirected stdout is buffered.
    sys.stdout.flush()
    return subprocess.run([sys.executable, "-m", "mutmut", *args], cwd=ROOT).returncode


def modules():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mutmut"]["only_mutate"]


def function_of(key):
    """The mutant key without its __mutmut_<n> suffix: the function it mutates."""
    return key.rsplit("__mutmut_", 1)[0]


def states():
    """{mutant key: state} for every mutant mutmut has a result for, read from its .meta files."""
    from mutmut.stats import status_by_exit_code
    result = {}
    for module in modules():
        meta = ROOT / "mutants" / (module + ".meta")
        if not meta.exists():
            raise SystemExit(f"{meta} is missing; mutmut did not finish {module}")
        for key, code in json.loads(meta.read_text(encoding="utf-8"))["exit_code_by_key"].items():
            result[key] = status_by_exit_code[code]
    return result


def module_of(key):
    """The source path, as [tool.mutmut] names it, of a mutant key like vibe_audit.policy.x_f__mutmut_1."""
    return "src/" + key.rsplit(".", 1)[0].replace(".", "/") + ".py"


def counts(keys_states):
    """Per module and per function: how many mutants are in each state."""
    by_module, by_function = {}, {}
    for key, state in keys_states.items():
        for table, name in ((by_module, module_of(key)), (by_function, function_of(key))):
            table.setdefault(name, {})
            table[name][state] = table[name].get(state, 0) + 1
    return by_module, by_function


def escaped(states_of_one):
    return sum(states_of_one.get(state, 0) for state in ESCAPED)


def changed_functions(ref):
    """Mutant name patterns for every top-level function and method the working tree changed against ref."""
    patterns = []
    for module in modules():
        source = ROOT / "backend" / module.removeprefix("src/")
        dotted = module.removeprefix("src/").removesuffix(".py").replace("/", ".")
        diff = subprocess.run(["git", "diff", "-U0", ref, "--", str(source)], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        touched = set()
        for start, length in HUNK.findall(diff):
            start, length = int(start), int(length) if length else 1
            # A pure deletion names the line after it; the function around that line is the one that changed.
            touched.update(range(start, start + max(length, 1)))
        if not touched:
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in tree.body:
            members = [(node, f"x_{node.name}")] if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else []
            if isinstance(node, ast.ClassDef):
                members = [(item, f"xǁ{node.name}ǁ{item.name}") for item in node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))]
            for item, mangled in members:
                first = min([item.lineno, *(d.lineno for d in item.decorator_list)])
                if any(first <= line <= item.end_lineno for line in touched):
                    patterns.append(f"{dotted}.{mangled}__mutmut_*")
    return patterns


def with_link(action):
    if LINK.is_symlink():
        if LINK.resolve() != (ROOT / "backend").resolve():
            raise SystemExit(f"{LINK} links elsewhere; remove it first")
    elif LINK.exists():
        raise SystemExit(f"{LINK} exists and is not the backend link; remove it first")
    else:
        LINK.symlink_to("backend", target_is_directory=True)
    try:
        return action()
    finally:
        LINK.unlink()


def report(rows, ceilings, label):
    print()
    print(f"{label:60} {'total':>6} {'killed':>7} {'survived':>9} {'no tests':>9} {'ceiling':>8}")
    worse = []
    for name, states_of_one in rows.items():
        ceiling = ceilings.get(name)
        print(f"{name:60} {sum(states_of_one.values()):>6} {states_of_one.get('killed', 0):>7} {states_of_one.get('survived', 0):>9} "
              f"{states_of_one.get('no tests', 0):>9} {'-' if ceiling is None else ceiling:>8}")
        if escaped(states_of_one) > (ceiling or 0):
            worse.append(f"{name}: {escaped(states_of_one)} escaped, ceiling {ceiling if ceiling is not None else 'none (new code)'}")
    other = {state: sum(s.get(state, 0) for s in rows.values()) for state in ("timeout", "suspicious", "skipped", "not checked")}
    if any(other.values()):
        print("Also: " + ", ".join(f"{count} {state}" for state, count in other.items() if count))
    return worse


def main(argv):
    if os.name != "posix":
        raise SystemExit("mutmut forks test workers; run this on Linux (WSL2 is fine)")
    update = "--update-baseline" in argv
    ref = argv[argv.index("--changed") + 1] if "--changed" in argv else None
    mutant_names = [arg for arg in argv if arg not in ("--update-baseline", "--changed", ref)]
    baseline = json.loads(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else {}
    if ref is not None:
        mutant_names = changed_functions(ref)
        if not mutant_names:
            print(f"No function of the mutated modules changed against {ref}; nothing to mutate")
            return 0
        print("Changed functions: " + ", ".join(name.removesuffix("__mutmut_*") for name in mutant_names))
        # The remembered test map does not learn which existing tests reach a changed function (see the module docstring).
        TEST_MAP.unlink(missing_ok=True)
    if not mutant_names:
        # A kept result would stand for a mutant the new tests never met (see the module docstring).
        shutil.rmtree(MUTANTS, ignore_errors=True)
    if (code := with_link(lambda: mutmut("run", *mutant_names))) != 0:
        return code
    if mutant_names and ref is None:
        return 0
    keys_states = states()
    print()
    print("Mutants the tests did not catch (mutmut show <name> prints the change):")
    if ref is not None:
        keys_states = {key: state for key, state in keys_states.items()
                       if any(function_of(key) == name.removesuffix("__mutmut_*") for name in mutant_names)}
        for key, state in keys_states.items():
            if state in ESCAPED:
                print(f"    {key}: {state}")
        rows = counts(keys_states)[1]
        worse = report(rows, baseline.get("functions", {}), "changed function")
        # The mutants to act on are those of a function over its ceiling: show what each one changed, so no one has
        # to link src and ask mutmut for them one at a time.
        over = {name for name, s in rows.items() if escaped(s) > (baseline.get("functions", {}).get(name) or 0)}
        shown = [key for key, state in keys_states.items() if state in ESCAPED and function_of(key) in over]
        if shown:
            print()
            print("What each of those functions' escaped mutants changed:")
            with_link(lambda: [mutmut("show", key) for key in shown])
    else:
        with_link(lambda: mutmut("results"))
        by_module, by_function = counts(keys_states)
        worse = report(by_module, baseline.get("modules", {}), "module")
        if update:
            BASELINE.write_text(json.dumps({"modules": {name: escaped(s) for name, s in by_module.items()},
                                            "functions": {name: escaped(s) for name, s in sorted(by_function.items()) if escaped(s)}},
                                           indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"Recorded the current counts in {BASELINE.relative_to(ROOT)}")
            return 0
    if worse:
        print("More mutants escape the tests than the baseline allows:\n  " + "\n  ".join(worse))
        print("Add or sharpen tests; mark genuinely unreachable code with '# pragma: no mutate'.")
        return 1
    print("Nothing lets more mutants escape than its baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
