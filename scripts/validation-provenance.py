"""Bind local validation receipts to exact source inputs; hashes do not prove external authenticity."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PREFIXES = ("backend/", "frontend/src/", "frontend/tests/", "frontend/scripts/", "scripts/", "tests/",
                   "fixtures/", "deploy/", "catalogs/", ".github/")
BUILD_INPUTS = {"pyproject.toml", "requirements.lock.txt", "requirements.mutation.lock.txt", "frontend/package.json",
                "frontend/package-lock.json", "frontend/tsconfig.json", "frontend/vite.config.ts", "frontend/eslint.config.js"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_inputs(root=ROOT):
    names = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root,
                           capture_output=True, check=True).stdout.decode().split("\0")
    return {name: sha((root / name).read_bytes()) for name in sorted(set(names))
            if (name.startswith(SOURCE_PREFIXES) or name in BUILD_INPUTS) and (root / name).is_file()
            and not (root / name).is_symlink()}


def receipt(path):
    path = Path(path)
    data = path.read_bytes()
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("JUnit declarations are not accepted")
    document = ET.fromstring(data)
    suites = [document] if document.tag == "testsuite" else list(document.findall("testsuite"))
    if not suites:
        raise ValueError("JUnit receipt contains no test suite")
    counts = {key: sum(int(s.get(key, 0)) for s in suites) for key in ("tests", "failures", "errors", "skipped")}
    return {"file": path.name, "sha256": sha(data), **counts,
            "successful_records": counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"],
            "skip_reasons": sorted({s.get("message", "") for s in document.iter("skipped")})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    inputs = source_inputs()
    records = [receipt(path) for path in args.receipt]
    if any(r["failures"] or r["errors"] for r in records):
        raise SystemExit("Failed receipts cannot be published as passing validation")
    report = {"git_head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                                        check=True).stdout.strip(),
              "source_inputs_sha256": sha(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()),
              "source_inputs": inputs, "receipts": records,
              "limitations": "Local receipts only; suites overlap, successful records can include subtests, skips are not passes. "
                             "No paid model/effectiveness experiment was performed by these tests. Documentation and generated artifacts are outside the code-input digest."}
    Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
