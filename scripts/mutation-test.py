"""Mutation-test the deterministic gates and parsers with mutmut (Linux only, no network, no credentials).

  python -m pip install --require-hashes -r requirements.mutation.lock.txt
  python scripts/mutation-test.py                     mutate the modules [tool.mutmut] in pyproject.toml names, run their tests
  python scripts/mutation-test.py --update-baseline   the same, then record the escaped mutants per module as the new ceiling
  python scripts/mutation-test.py <mutant name>...    re-test the named mutants only (see mutmut results / mutmut show)

mutmut changes one operator, constant or branch of the code at a time and runs the tests that cover the changed
function; a mutant the tests still pass ("survived") or that no test reaches ("no tests") is a blind spot.
tests/mutation-baseline.json records how many such mutants each module had when it was last accepted, so this
fails when a module's count rises: a change that loosens a test or adds untested logic. Lower a ceiling by adding
tests, then --update-baseline; it never goes up by itself. mutmut keeps its working copy and results in mutants/
(ignored by git); delete it to start afresh.

mutmut maps src/<package>/<module>.py to the module <package>.<module> that the tests import, so the run links
src -> backend and removes the link afterwards.
"""
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = ROOT / "src"
BASELINE = ROOT / "tests" / "mutation-baseline.json"
ESCAPED = ("survived", "no tests")


def mutmut(*args):
    return subprocess.run([sys.executable, "-m", "mutmut", *args], cwd=ROOT).returncode


def counts():
    """Per module: how many mutants are in each state, read from mutmut's .meta files."""
    from mutmut.stats import status_by_exit_code
    modules = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mutmut"]["only_mutate"]
    result = {}
    for module in modules:
        meta = ROOT / "mutants" / (module + ".meta")
        if not meta.exists():
            raise SystemExit(f"{meta} is missing; mutmut did not finish {module}")
        states = {}
        for code in json.loads(meta.read_text(encoding="utf-8"))["exit_code_by_key"].values():
            state = status_by_exit_code[code]
            states[state] = states.get(state, 0) + 1
        result[module] = states
    return result


def main(argv):
    if os.name != "posix":
        raise SystemExit("mutmut forks test workers; run this on Linux (WSL2 is fine)")
    update = "--update-baseline" in argv
    mutant_names = [arg for arg in argv if arg != "--update-baseline"]
    if LINK.is_symlink():
        if LINK.resolve() != (ROOT / "backend").resolve():
            raise SystemExit(f"{LINK} links elsewhere; remove it first")
    elif LINK.exists():
        raise SystemExit(f"{LINK} exists and is not the backend link; remove it first")
    else:
        LINK.symlink_to("backend", target_is_directory=True)
    try:
        if (code := mutmut("run", *mutant_names)) != 0:
            return code
        if mutant_names:
            return 0
        print()
        print("Mutants the tests did not catch (mutmut show <name> prints the change):")
        mutmut("results")
    finally:
        LINK.unlink()
    baseline = json.loads(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else {}
    current = counts()
    print()
    print(f"{'module':44} {'total':>6} {'killed':>7} {'survived':>9} {'no tests':>9} {'ceiling':>8}")
    worse = []
    for module, states in current.items():
        escaped = sum(states.get(state, 0) for state in ESCAPED)
        ceiling = baseline.get(module)
        print(f"{module:44} {sum(states.values()):>6} {states.get('killed', 0):>7} {states.get('survived', 0):>9} "
              f"{states.get('no tests', 0):>9} {'-' if ceiling is None else ceiling:>8}")
        if ceiling is None or escaped > ceiling:
            worse.append(f"{module}: {escaped} escaped, ceiling {ceiling}")
    other = {state: sum(states.get(state, 0) for states in current.values())
             for state in ("timeout", "suspicious", "skipped", "not checked")}
    if any(other.values()):
        print("Also: " + ", ".join(f"{count} {state}" for state, count in other.items() if count))
    if update:
        BASELINE.write_text(json.dumps({module: sum(states.get(state, 0) for state in ESCAPED)
                                        for module, states in current.items()}, indent=2) + "\n", encoding="utf-8")
        print(f"Recorded the current counts in {BASELINE.relative_to(ROOT)}")
        return 0
    if worse:
        print("More mutants escape the tests than the baseline allows:\n  " + "\n  ".join(worse))
        print("Add or sharpen tests; mark genuinely unreachable code with '# pragma: no mutate'.")
        return 1
    print("No module lets more mutants escape than its baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
