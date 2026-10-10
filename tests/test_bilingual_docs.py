"""Documentation stays bilingual (Traditional Chinese first, then English) and names the current release."""
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CJK = re.compile(r"[一-鿿]")


def documents():
    tracked = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    # Upstream source snapshots are not project documentation.
    names = [name for name in tracked if not name.startswith("catalogs/sources/")]
    return sorted(names + ["NOTICE"])


def halves(name):
    text = (ROOT / name).read_text(encoding="utf-8").replace("\r\n", "\n")
    lines = text.split("\n")
    separators = [i for i, line in enumerate(lines) if line == "---"]
    assert len(separators) == 1, f"{name}: needs exactly one '---' line between the Chinese and English halves"
    return "\n".join(lines[:separators[0]]), "\n".join(lines[separators[0] + 1:])


def headings(text):
    # Shell comments inside fenced code blocks are not headings.
    prose = re.sub(r"^```.*?^```", "", text, flags=re.S | re.M)
    return [line for line in prose.split("\n") if re.match(r"#{1,6} ", line)]


@pytest.mark.parametrize("name", documents())
def test_each_document_has_a_chinese_half_then_an_english_half(name):
    chinese, english = halves(name)
    # A title can be a name in either language (the sample report's title is its run's name), so titles do not count.
    zh, en = (len(CJK.findall(re.sub(r"^# .*$", "", half, flags=re.M))) for half in (chinese, english))
    assert zh >= 50, f"{name}: the first half should be the Chinese text"
    # The English half may quote a few interface labels (for example 合成示範), nothing more.
    assert en * 10 <= zh, f"{name}: the second half should be the English text"
    assert len(headings(chinese)) == len(headings(english)), f"{name}: the two halves have different headings"


def test_document_titles_name_the_current_release():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    stale = []
    for name in documents():
        for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
            first_heading = line.startswith("# ") or line.startswith("Vibe Audit ")
            for found in re.findall(r"\b0\.\d+\.\d+\b", line) if first_heading else []:
                if found != version:
                    stale.append(f"{name}: {line.strip()}")
    assert not stale, "Titles still name an older release:\n" + "\n".join(stale)


def test_sample_report_is_the_report_generators_output():
    # docs/sample-report.md is the Chinese and English Markdown export of the run stored in docs/sample-report.json.
    subprocess.run([sys.executable, "scripts/render-sample-report.py", "--check"], cwd=ROOT, check=True)
