"""Explicit OWASP catalog ingestion. Default is offline; --fetch refreshes pinned sources.

No network is used by the application registry. Catalog data stays CC-BY-SA-4.0.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1] / "catalogs"
ASVS = "5cf9b032440be53ce345ab3c130fda46ba1ce7a2"
WSTG = "dd33419e10edb22b78d89325a6c2aad9f184e3a2"
LLM = "9253e38ade58e959b531c0c5c9a4842272c9cd0e"
LLM_FILES = ["LLM01_PromptInjection", "LLM02_SensitiveInformationDisclosure", "LLM03_ExcessiveAgency",
             "LLM04_SupplyChain", "LLM05_DataModelPoisoning", "LLM06_UnboundedConsumption", "LLM07_Misinformation",
             "LLM08_HiddenContextExposure", "LLM09_VectorAndEmbeddingWeaknesses", "LLM10_ImproperOutputHandling"]
SPECS: dict[str, dict] = {}


def source(name, url, *, commit=None):
    SPECS[name] = {"url": url, "commit": commit, "file": "sources/" + name}


def raw(name, repo, commit, path):
    source(name, f"https://raw.githubusercontent.com/{repo}/{commit}/{quote(path)}", commit=commit)


for ext in ["json", "csv"]:
    raw("asvs-5.0.0." + ext, "OWASP/ASVS", ASVS, f"5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.{ext}")
raw("asvs-LICENSE.md", "OWASP/ASVS", ASVS, "LICENSE.md")
source("asvs-project.html", "https://owasp.org/projects/asvs")
raw("wstg-4.2.json", "OWASP/wstg", WSTG, "checklist/checklist.json")
raw("wstg-4.2.md", "OWASP/wstg", WSTG, "checklist/Testing_Checklist.md")
raw("wstg-LICENSE.txt", "OWASP/wstg", WSTG, "LICENSE")
source("wstg-project.html", "https://owasp.org/www-project-web-security-testing-guide/")
for filename in LLM_FILES:
    raw(filename + ".md", "GenAI-Security-Project/GenAI-LLM-Top10", LLM, "2026/final/" + filename + ".md")
raw("llm-2026-README.md", "GenAI-Security-Project/GenAI-LLM-Top10", LLM, "README.md")
source("llm-2026-release.html", "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/")
raw("asi-2026.json", "GenAI-Security-Project/GenAI-LLM-Top10", LLM, "2026/final/mappings/asi-2026.json")
source("agentic-2026-announcement.html", "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/")
source("agentic-2026-release.html", "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def fetch(item):
    name, spec = item
    request = Request(spec["url"], headers={"User-Agent": "VibeAudit-CatalogIngest/0.1"})
    with urlopen(request, timeout=45) as response:
        data = response.read(10_000_001)
        if len(data) > 10_000_000 or "/no-access/" in response.url:
            raise ValueError(f"Source unavailable or oversized: {name}")
        if name.endswith(".json"):
            json.loads(data)
        (ROOT / spec["file"]).write_bytes(data)
        return name, spec | {"sha256": sha(data), "final_url": response.url,
                             "retrieved_at": datetime.now(timezone.utc).isoformat()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="Explicitly download the fixed official source revisions")
    args = parser.parse_args()
    (ROOT / "sources").mkdir(parents=True, exist_ok=True)
    if args.fetch:
        with ThreadPoolExecutor(max_workers=5) as pool:
            lock = dict(pool.map(fetch, SPECS.items()))
        write_json(ROOT / "source-lock.json", lock)
    else:
        lock = json.loads((ROOT / "source-lock.json").read_text(encoding="utf-8"))
    def text(name):
        entry = lock[name]
        if entry["url"] != SPECS[name]["url"] or entry.get("commit") != SPECS[name].get("commit"):
            raise ValueError("Source lock differs from fixed ingest configuration")
        data = (ROOT / entry["file"]).read_bytes()
        if sha(data) != entry["sha256"]:
            raise ValueError("Source integrity mismatch: " + name)
        return data.decode("utf-8-sig")
    def entry(id_, official, standard, version, title, src, description="", level=None):
        return dict(id=id_, official_id=official, standard=standard, version=version, title=title,
                    source=lock[src]["url"], description=description, level=level, license="CC-BY-SA-4.0")
    collections = []
    def save(standard, version, entries, names, verification, notes=None):
        filename = f"{standard.lower()}-{version}.json"
        write_json(ROOT / filename, entries)
        collections.append(dict(standard=standard, version=version, file=filename, count=len(entries),
                                sha256=sha((ROOT / filename).read_bytes()), license="CC-BY-SA-4.0",
                                attribution="OWASP Foundation and the respective project contributors",
                                sources=[lock[n] for n in names], verification=verification, quality_notes=notes or []))
    asvs = json.loads(text("asvs-5.0.0.json"))
    assert asvs["Version"] == "5.0.0"
    entries = []
    for chapter in asvs["Requirements"]:
        for section in chapter["Items"]:
            for req in section["Items"]:
                number = req["Shortcode"].removeprefix("V")
                entries.append(entry("ASVS-v5.0.0-" + number, "v5.0.0-" + number, "ASVS", "5.0.0",
                                     section["Name"], "asvs-5.0.0.json", req["Description"], int(req["L"])))
    csv_rows = list(csv.DictReader(io.StringIO(text("asvs-5.0.0.csv"))))
    csv_ids = {m.group(1) for row in csv_rows for value in row.values() if value
               if (m := re.fullmatch(r"(?:v5\.0\.0-|V)?(\d+\.\d+\.\d+)", value.strip()))}
    assert {e["official_id"].removeprefix("v5.0.0-") for e in entries} == csv_ids, "ASVS JSON/CSV ID sets differ"
    save("ASVS", "5.0.0", entries, ["asvs-5.0.0.json", "asvs-5.0.0.csv", "asvs-LICENSE.md", "asvs-project.html"],
         "Exact requirement ID equality across release-tag JSON and CSV; official project confirms edition.")
    wstg = json.loads(text("wstg-4.2.json"))
    entries = []
    for category in wstg["categories"].values():
        for req in category["tests"]:
            entries.append(entry(req["id"].replace("WSTG-", "WSTG-v42-"), req["id"], "WSTG", "4.2",
                                 req["name"], "wstg-4.2.json", "\n".join(req.get("objectives", []))))
    markdown_ids = set(re.findall(r"WSTG-[A-Z]{4}-\d{2}", text("wstg-4.2.md")))
    assert {e["official_id"] for e in entries} == markdown_ids, "WSTG JSON/Markdown ID sets differ"
    # Upstream assigns INPV-13 to both Buffer Overflow and Format String Injection.
    # Preserve both documented subtopics under the same real ID; never invent a new ID.
    grouped = {}
    duplicate_ids = []
    for item in entries:
        if item["id"] in grouped:
            assert item["official_id"] == "WSTG-INPV-13", "New upstream ID collision requires review"
            duplicate_ids.append(item["official_id"])
            grouped[item["id"]]["title"] += " / " + item["title"]
            grouped[item["id"]]["description"] += "\n" + item["description"]
        else:
            grouped[item["id"]] = item
    entries = list(grouped.values())
    save("WSTG", "4.2", entries, ["wstg-4.2.json", "wstg-4.2.md", "wstg-LICENSE.txt", "wstg-project.html"],
         "Exact scenario ID equality across pinned checklist JSON and Markdown; official project confirms v4.2.",
         ["Pinned checklist originally used mutable /stable/ references; catalog cites the immutable raw source instead.",
          "Upstream checklist has 98 rows and 97 unique IDs. WSTG-INPV-13 covers Buffer Overflow and Format String Injection; both titles/objectives are retained in one entry."])
    entries = []
    readme = text("llm-2026-README.md")
    for filename in LLM_FILES:
        name = filename + ".md"
        match = re.search(r"^#{1,3}\s+(LLM\d{2}:2026)\s+(.+)$", text(name), re.MULTILINE)
        assert match, "Canonical LLM heading absent"
        identifier, title = match.groups()
        assert identifier + " " + title in readme, "LLM final heading/README mismatch"
        entries.append(entry(identifier, identifier, "LLM", "2026", title, name))
    save("LLM", "2026", entries, [f + ".md" for f in LLM_FILES] + ["llm-2026-README.md", "llm-2026-release.html"],
         "All ten canonical final-source headings equal the official repository release list; publication page confirms 2026.",
         ["Official landing page date is August 3, README date August 4, 2026; edition and IDs agree.",
          "Official PDF download redirected to no-access HTML during retrieval; no PDF hash or PDF equivalence is claimed.",
          "Older /llm-top-10/ page still lists 2025; it is not used for 2026 identifiers."])
    entries = []
    announcement = unescape(re.sub(r"<[^>]*>", " ", text("agentic-2026-announcement.html")))
    for item in json.loads(text("asi-2026.json"))["elements"]:
        assert item["id"] in announcement, "Agentic ID missing from official announcement"
        title = item["title"]
        # Announcement abbreviates ASI02 and ASI05; remaining published titles agree.
        check_title = {"ASI02": "Tool Misuse", "ASI05": "Unexpected Code Execution"}.get(item["id"], title)
        assert check_title in announcement, "Agentic title differs from official announcement"
        entries.append(entry(item["id"] + ":2026", item["id"], "AGENTIC", "2026", title, "asi-2026.json"))
    save("AGENTIC", "2026", entries, ["asi-2026.json", "agentic-2026-announcement.html", "agentic-2026-release.html", "llm-2026-README.md"],
         "All ten IDs and titles checked against the official launch announcement and pinned official LLM2026 ASI catalog mapping.",
         ["The :2026 suffix is a Vibe Audit version qualifier; OWASP's published Agentic IDs are ASI01 through ASI10.",
          "ASI02 and ASI05 have shortened titles in the launch blog; full mapping titles are retained.",
          "Official PDF download returned no-access HTML; published repository mapping and announcement are the ingested sources."])
    manifest = {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(), "collections": collections,
                "trust_note": "Hashes detect local drift against this trusted manifest; they are not OWASP signatures.",
                "id_conventions": {"ASVS": "ASVS- namespace + official versioned ID; official v5.0.0-* accepted as explicit aliases", "WSTG": "OWASP version-qualified WSTG-v42-*", "LLM": "Official LLMnn:2026", "AGENTIC": "Official ASInn with explicit :2026 application qualifier"}}
    write_json(ROOT / "manifest.json", manifest)
    print(json.dumps({c["standard"]: c["count"] for c in collections}))


if __name__ == "__main__":
    main()
