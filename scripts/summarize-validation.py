"""Collect real JUnit receipts; never convert a skip/failure to a pass."""
from pathlib import Path
import datetime
import json
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
reports = []
for path in sorted((root/"docs").glob("*.xml")):
    data = path.read_bytes()
    # JUnit receipts never need a DTD; refusing one rules out entity expansion in the stdlib parser.
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise SystemExit(f"{path.name}: XML declarations are not accepted in a test receipt")
    doc = ET.fromstring(data)
    suites = [doc] if doc.tag == "testsuite" else list(doc.findall("testsuite"))
    counts = {key:sum(int(s.get(key,0)) for s in suites) for key in ("tests","failures","errors","skipped")}
    reports.append({"file":path.relative_to(root).as_posix(),**counts,
        "passed":counts["tests"]-counts["failures"]-counts["errors"]-counts["skipped"],
        "seconds":round(sum(float(s.get("time",0)) for s in suites),3),
        "timestamp":[s.get("timestamp") for s in suites],
        "skip_reasons":sorted({node.get("message","") for node in doc.iter("skipped")}),
        "failures_detail":[{"test":test.get("classname","")+"."+test.get("name",""),"reason":node.get("message","")}
            for test in doc.iter("testcase") for node in list(test) if node.tag in {"failure","error"}]})
result = {"generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "model_endpoints_tested":False,"efficacy_established":False,
    "note":"Suites overlap; do not add counts as distinct tests. JUnit successful records include subtests where emitted. Docker, database and synthetic model contracts are separate evidence.",
    "reports":reports}
# Fixed CRLF, so a summary regenerated on Linux or Windows has the same bytes.
(root/"docs/validation-summary.json").write_bytes(json.dumps(result,ensure_ascii=False,indent=2).replace("\n","\r\n").encode("utf-8"))
print(json.dumps(result,ensure_ascii=False,indent=2))
