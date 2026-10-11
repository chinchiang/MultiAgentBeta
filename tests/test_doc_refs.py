"""Line references in the threat model and the advisory triage point inside files that exist.

This cannot prove a reference names the right line, only that it still lands in its file after code moves;
docs/threat-model.yaml is re-anchored by matching line text when code is refactored."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NUM = r"\d+(?:-\d+)?"
REF = re.compile(r"((?:[\w/-]+/)?[\w-]+\.(?:py|ts|tsx|mjs|cjs)):(" + NUM + r"(?:(?:、|, )" + NUM + r")*)")
SEARCH = ["backend/vibe_audit", "", "scripts", "tests", "fixtures/web-api", "fixtures/ai-agent", "frontend/src", "frontend/scripts"]


def resolve(name):
    for base in SEARCH:
        path = ROOT / base / name
        if path.is_file():
            return path
    return None


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
