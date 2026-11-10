"""Line references in the threat model and the advisory triage point inside files that exist.

This cannot prove a reference names the right line, only that it still lands in its file after code moves;
scripts/reanchor-doc-refs.py follows the lines a reference names to where the code moved them (CI runs its --check)."""
import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def reanchor_module():
    """scripts/reanchor-doc-refs.py, which owns how a reference is spelled and where its file is looked for."""
    spec = importlib.util.spec_from_file_location("reanchor_doc_refs", ROOT / "scripts" / "reanchor-doc-refs.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REANCHOR = reanchor_module()
REF = REANCHOR.REF


def resolve(name):
    found = REANCHOR.resolve(ROOT, name)
    return None if found is None else ROOT / found


@pytest.mark.parametrize("doc", ["docs/threat-model.yaml", "docs/VIBESEC_ADVISORIES.md"])
def test_every_line_reference_lands_inside_its_file(doc):
    text = (ROOT / doc).read_text(encoding="utf-8")
    problems, checked = [], 0
    for match in REF.finditer(text):
        path = resolve(match.group(1))
        if path is None:
            problems.append(f"{match.group(0)}: no such file")
            continue
        length = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        for token in re.split(r"、|, ", match.group(2)):
            numbers = [int(part) for part in token.split("-")]
            checked += 1
            if any(n < 1 or n > length for n in numbers) or numbers != sorted(numbers):
                problems.append(f"{match.group(0)}: {token} outside 1-{length}")
    assert checked and problems == []


def repo_with_moved_code(tmp_path):
    """A git repository whose doc names lines of app.py; the working tree then moves those lines down by two."""
    import subprocess
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "test")
    (tmp_path / "app.py").write_text("def a():\n    return 1\n\n\ndef b():\n    return 2\n")
    (tmp_path / "doc.yaml").write_text("a lives at app.py:1-2; b at app.py:5-6 and app.py:6\n")
    git("add", ".")
    git("commit", "-q", "-m", "base")
    (tmp_path / "app.py").write_text("import os\n\ndef a():\n    return 1\n\n\ndef b():\n    return 2\n")
    return tmp_path


def test_a_reference_left_behind_by_moved_code_is_found_and_re_anchored(tmp_path):
    reanchor = REANCHOR
    root = repo_with_moved_code(tmp_path)
    found = reanchor.reanchor(root, ["doc.yaml"], base="HEAD", search=[""], write=False)
    assert [(f.ref, f.expected) for f in found.stale] == [("app.py:1-2", "app.py:3-4"), ("app.py:5-6", "app.py:7-8"), ("app.py:6", "app.py:8")]
    reanchor.reanchor(root, ["doc.yaml"], base="HEAD", search=[""], write=True)
    assert (root / "doc.yaml").read_text() == "a lives at app.py:3-4; b at app.py:7-8 and app.py:8\n"
    # Once re-anchored, nothing is left behind.
    assert reanchor.reanchor(root, ["doc.yaml"], base="HEAD", search=[""], write=False).stale == []


def test_a_reference_someone_already_moved_or_whose_lines_were_rewritten_is_not_stale(tmp_path):
    reanchor = REANCHOR
    root = repo_with_moved_code(tmp_path)
    # Pointed elsewhere by hand: the author's choice stands.
    (root / "doc.yaml").write_text("a lives at app.py:3-4; b at app.py:5-6 and app.py:6\n")
    assert [f.ref for f in reanchor.reanchor(root, ["doc.yaml"], base="HEAD", search=[""], write=False).stale] == ["app.py:5-6", "app.py:6"]
    # Lines rewritten where they stood: no line of them survives to follow, so it is for a person to check.
    (root / "app.py").write_text("def a():\n    return 1\n\n\ndef c():\n    return 3\n")
    (root / "doc.yaml").write_text("b at app.py:5-6\n")
    found = reanchor.reanchor(root, ["doc.yaml"], base="HEAD", search=[""], write=False)
    assert found.stale == [] and [f.ref for f in found.rewritten] == ["app.py:5-6"]
