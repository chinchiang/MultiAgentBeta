"""Mutation-test the deterministic gates and parsers with mutmut (Linux only, no network, no credentials).

  python -m pip install --require-hashes -r requirements.mutation.lock.txt
  python scripts/mutation-test.py                 mutate the modules [tool.mutmut] in pyproject.toml names, run their tests
  python scripts/mutation-test.py <mutant name>   re-test one mutant (see mutmut results / mutmut show)

mutmut changes one operator, constant or branch of the code at a time and runs the tests that cover the changed
function; a mutant the tests still pass is a blind spot. This exits non-zero while any mutant survives or has no
covering test. mutmut keeps its working copy and results in mutants/ (ignored by git); delete it to start afresh.

mutmut maps src/<package>/<module>.py to the module <package>.<module> that the tests import, so the run links
src -> backend and removes the link afterwards.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK = ROOT / "src"
STATS = ROOT / "mutants" / "mutmut-cicd-stats.json"


def mutmut(*args):
    return subprocess.run([sys.executable, "-m", "mutmut", *args], cwd=ROOT).returncode


def main(argv):
    if os.name != "posix":
        raise SystemExit("mutmut forks test workers; run this on Linux (WSL2 is fine)")
    if LINK.is_symlink():
        if LINK.resolve() != (ROOT / "backend").resolve():
            raise SystemExit(f"{LINK} links elsewhere; remove it first")
    elif LINK.exists():
        raise SystemExit(f"{LINK} exists and is not the backend link; remove it first")
    else:
        LINK.symlink_to("backend", target_is_directory=True)
    try:
        if (code := mutmut("run", *argv)) != 0:
            return code
        print()
        print("Surviving, untested and suspicious mutants (mutmut show <name> prints the change):")
        mutmut("results")
        mutmut("export-cicd-stats")
    finally:
        LINK.unlink()
    stats = json.loads(STATS.read_text(encoding="utf-8"))
    print(json.dumps(stats, indent=2))
    blind = stats["survived"] + stats["no_tests"]
    if blind:
        print(f"{blind} mutant(s) escaped the tests; add or sharpen tests, or mark unreachable code with '# pragma: no mutate'")
        return 1
    print(f"Every one of the {stats['total']} mutants was caught")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
