"""Render docs/sample-report.md from the stored demo run in docs/sample-report.json: the Chinese report, '---', the English report.

  python scripts/render-sample-report.py          rewrite docs/sample-report.md
  python scripts/render-sample-report.py --check  fail if docs/sample-report.md differs from the report generator's output
"""
from pathlib import Path
import json
import sys

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root/"backend"))
from vibe_audit.service import report_markdown  # noqa: E402

run = json.loads((root/"docs"/"sample-report.json").read_text(encoding="utf-8"))
text = report_markdown(run, "zh-Hant") + "\n---\n\n" + report_markdown(run, "en")
# The file keeps its CRLF line endings (.gitattributes sets -text).
expected = text.replace("\n", "\r\n").encode("utf-8")
target = root/"docs"/"sample-report.md"
if "--check" in sys.argv[1:]:
    if target.read_bytes() != expected:
        raise SystemExit("docs/sample-report.md differs from the report generator; run python scripts/render-sample-report.py")
    print("docs/sample-report.md matches the report generator")
else:
    target.write_bytes(expected)
    print("wrote docs/sample-report.md")
