"""Find and re-anchor line references in the docs that code moved out from under.

  python scripts/reanchor-doc-refs.py                  rewrite references the code moved, against origin/main
  python scripts/reanchor-doc-refs.py --check          report them and fail instead (CI runs this on pull requests)
  python scripts/reanchor-doc-refs.py --base <ref>     compare against another base than origin/main

docs/threat-model.yaml and docs/VIBESEC_ADVISORIES.md name code as file:line or file:first-last.
tests/test_doc_refs.py only checks that each lands inside its file; this compares each file with its version at the
merge base and follows the referenced lines to where they are now. A reference counts as left behind only if the doc
still says what it said at the base while the lines it named moved; one an author already changed is theirs. Lines
rewritten where they stood leave nothing to follow, so they are listed for a person to check, and do not fail --check.
A reference followed by a commit in parentheses, such as app.py:12（c7ae273）, names that commit's lines and is left alone.
Only the standard library is used, so CI runs this without installing anything.
"""
from __future__ import annotations

import difflib
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ["docs/threat-model.yaml", "docs/VIBESEC_ADVISORIES.md"]
# Where a bare file name in a reference is looked for, in order.
SEARCH = ["backend/vibe_audit", "", "scripts", "tests", "fixtures/web-api", "fixtures/ai-agent", "frontend/src", "frontend/scripts"]
NUM = r"\d+(?:-\d+)?"
REF = re.compile(r"((?:[\w/-]+/)?[\w-]+\.(?:py|ts|tsx|mjs|cjs)):(" + NUM + r"(?:(?:、|, )" + NUM + r")*)")
PINNED = re.compile(r"`?\s*[（(][0-9a-f]{7,40}\b")


def resolve(root, name, search=SEARCH):
    """The repository-relative path a reference's file name means, or None."""
    for base in search:
        path = Path(base) / name
        if (root / path).is_file():
            return path.as_posix()
    return None


@dataclass
class Finding:
    doc: str
    ref: str
    expected: str = ""


@dataclass
class Found:
    stale: list = field(default_factory=list)
    rewritten: list = field(default_factory=list)


def _git(root, *args):
    # Git writes file content as it is stored, UTF-8 here; the platform's own encoding (cp1252 on Windows) would garble it.
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8")


def _at(root, commit, path):
    shown = _git(root, "show", f"{commit}:{path}")
    return shown.stdout if shown.returncode == 0 else None


def _line_map(old, new):
    """{old line number: new line number} for every line that survives unchanged."""
    lines = {}
    matcher = difflib.SequenceMatcher(None, old.splitlines(), new.splitlines(), autojunk=False)
    for tag, i1, i2, j1, _ in matcher.get_opcodes():
        if tag == "equal":
            lines.update({i1 + k + 1: j1 + k + 1 for k in range(i2 - i1)})
    return lines


def _follow(token, lines):
    """Where the lines of one token (n or first-last) are now, or None when none of them survives."""
    numbers = [int(part) for part in token.split("-")]
    first, last = numbers[0], numbers[-1]
    kept = [n for n in range(first, last + 1) if n in lines]
    if not kept:
        return None
    # A first or last line edited in place keeps its distance from the nearest line that survived.
    start, end = lines[kept[0]] - (kept[0] - first), lines[kept[-1]] + (last - kept[-1])
    return str(start) if len(numbers) == 1 else f"{start}-{end}"


def _refs(text):
    return [(m.group(0), m.start(), m.end(), m.group(1), m.group(2)) for m in REF.finditer(text)
            if not PINNED.match(text, m.end())]


def reanchor(root, docs=DOCS, *, base="origin/main", search=SEARCH, write=False):
    root = Path(root)
    merged = _git(root, "merge-base", base, "HEAD")
    commit = merged.stdout.strip() if merged.returncode == 0 else base
    found = Found()
    for doc in docs:
        then = _at(root, commit, doc)
        path = root / doc
        if then is None or not path.is_file():
            continue
        now = path.read_text(encoding="utf-8")
        old_refs, new_refs = _refs(then), _refs(now)
        # A reference still spelled as it was at the base, in the same place among the others, is one no one touched.
        matcher = difflib.SequenceMatcher(None, [r[0] for r in old_refs], [r[0] for r in new_refs], autojunk=False)
        untouched = [new_refs[j1 + k] for tag, i1, i2, j1, _ in matcher.get_opcodes() if tag == "equal" for k in range(i2 - i1)]
        edits = []
        for ref, start, end, name, tokens in untouched:
            source = resolve(root, name, search)
            before = _at(root, commit, source) if source else None
            if before is None:
                continue
            after = (root / source).read_text(encoding="utf-8", errors="replace")
            if before == after:
                continue
            lines = _line_map(before, after)
            followed = [_follow(token, lines) for token in re.split(r"、|, ", tokens)]
            if None in followed:
                found.rewritten.append(Finding(doc, ref))
                continue
            separator = "、" if "、" in tokens else ", "
            moved = f"{name}:{separator.join(followed)}"
            if moved != ref:
                found.stale.append(Finding(doc, ref, moved))
                edits.append((start, end, moved))
        if write and edits:
            for start, end, moved in reversed(edits):
                now = now[:start] + moved + now[end:]
            path.write_text(now, encoding="utf-8")
    return found


def main(argv):
    check = "--check" in argv
    base = argv[argv.index("--base") + 1] if "--base" in argv else "origin/main"
    found = reanchor(ROOT, base=base, write=not check)
    for finding in found.stale:
        print(f"{finding.doc}: {finding.ref} -> {finding.expected}" + ("" if check else " (rewritten)"))
    for finding in found.rewritten:
        print(f"{finding.doc}: {finding.ref}: the lines it names were rewritten; check it by hand")
    if check and found.stale:
        print("These references still name lines the code moved; run python scripts/reanchor-doc-refs.py")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
