"""Report how far the pinned dependencies lag behind their registries and which carry security advisories.

  python scripts/dependency-drift.py            Markdown report of the pins that lag or have an advisory
  python scripts/dependency-drift.py --all      every pin, lagging or not
  python scripts/dependency-drift.py --json     the same data as JSON

Reads requirements.lock.txt, requirements.mutation.lock.txt and frontend/package-lock.json; asks PyPI and the npm
registry for the latest release of each pin and OSV (api.osv.dev) for advisories against the pinned version.
Nothing is upgraded: the pins change only through scripts/hash-lock.py and npm, after a review. Exits non-zero when
any pinned version has an advisory, so the weekly workflow turns red for that and only that.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import re
import sys
import urllib.request
from pathlib import Path

from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._+!-]+)")
LOCKS = ["requirements.lock.txt", "requirements.mutation.lock.txt"]
PACKAGE_LOCK = ROOT / "frontend" / "package-lock.json"
TIMEOUT = 30


def fetch(url, data=None):
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "vibe-audit dependency-drift"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.load(response)


def pins():
    """[(ecosystem, name, version, where)] for every Python and npm pin; a package pinned twice is listed twice."""
    found = []
    for lock in LOCKS:
        for line in (ROOT / lock).read_text(encoding="ascii").splitlines():
            if match := PIN.match(line):
                found.append(("PyPI", match[1].lower(), match[2], lock))
    packages = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))["packages"]
    direct = set(packages[""].get("dependencies", {})) | set(packages[""].get("devDependencies", {}))
    for path, info in packages.items():
        if path.startswith("node_modules/") and "version" in info:
            name = path.split("node_modules/")[-1]
            found.append(("npm", name, info["version"], "frontend/package-lock.json" + (" (direct)" if name in direct else "")))
    return found


def parse(version):
    try:
        return Version(version)
    except InvalidVersion:
        return None


def latest(ecosystem, name):
    """(latest stable version, its release date) from the package's registry."""
    if ecosystem == "PyPI":
        data = fetch(f"https://pypi.org/pypi/{name}/json")
        version = data["info"]["version"]
        files = data["releases"].get(version) or []
    else:
        data = fetch(f"https://registry.npmjs.org/{name}")
        version = data["dist-tags"]["latest"]
        files = [{"upload_time_iso_8601": data.get("time", {}).get(version, "")}]
    released = min((file.get("upload_time_iso_8601") or "" for file in files), default="")
    return version, released[:10]


def advisories(entries):
    """{(ecosystem, name, version): [advisory ids]} from OSV, in one batch query per 1000 pins."""
    result = {}
    for start in range(0, len(entries), 1000):
        chunk = entries[start:start + 1000]
        queries = [{"package": {"name": name, "ecosystem": ecosystem}, "version": version} for ecosystem, name, version, _ in chunk]
        answers = fetch("https://api.osv.dev/v1/querybatch", json.dumps({"queries": queries}).encode())["results"]
        for (ecosystem, name, version, _), answer in zip(chunk, answers):
            result[(ecosystem, name, version)] = sorted(vuln["id"] for vuln in answer.get("vulns", []))
    return result


def advisory_summary(identifier):
    data = fetch(f"https://api.osv.dev/v1/vulns/{identifier}")
    severity = ", ".join(f"{item.get('type')} {item.get('score')}" for item in data.get("severity", []))
    return {"id": identifier, "summary": data.get("summary", ""), "severity": severity, "aliases": data.get("aliases", [])}


def report():
    entries = pins()
    unique = sorted({(ecosystem, name) for ecosystem, name, _, _ in entries})
    with ThreadPoolExecutor(8) as pool:
        newest = dict(zip(unique, pool.map(lambda item: latest(*item), unique)))
        vulnerable = advisories(entries)
        details = {identifier: summary for identifier, summary in
                   zip(sorted({v for ids in vulnerable.values() for v in ids}), pool.map(advisory_summary, sorted({v for ids in vulnerable.values() for v in ids})))}
    rows = []
    for ecosystem, name, version, where in entries:
        latest_version, released = newest[(ecosystem, name)]
        pinned, current = parse(version), parse(latest_version)
        behind = pinned is not None and current is not None and pinned < current
        rows.append({"ecosystem": ecosystem, "name": name, "pinned": version, "latest": latest_version, "latest_released": released,
                     "behind": behind, "where": where, "advisories": [details[v] for v in vulnerable[(ecosystem, name, version)]]})
    return rows


def markdown(rows, show_all):
    today = datetime.now(timezone.utc).date().isoformat()
    lines = [f"# Dependency drift ({today})", ""]
    shown = [row for row in rows if show_all or row["behind"] or row["advisories"]]
    lines.append(f"{len(rows)} pins checked; {sum(row['behind'] for row in rows)} behind the latest release; "
                 f"{sum(bool(row['advisories']) for row in rows)} with an advisory.")
    lines += ["", "| Ecosystem | Package | Pinned | Latest | Released | Advisories | Where |", "|---|---|---|---|---|---|---|"]
    for row in shown:
        advisories_text = "<br>".join(f"{a['id']}{' (' + a['severity'] + ')' if a['severity'] else ''}: {a['summary']}" for a in row["advisories"]) or "-"
        lines.append(f"| {row['ecosystem']} | {row['name']} | {row['pinned']} | {row['latest'] if row['behind'] else '='} | "
                     f"{row['latest_released'] if row['behind'] else ''} | {advisories_text} | {row['where']} |")
    return "\n".join(lines) + "\n"


def main(argv):
    rows = report()
    if "--json" in argv:
        print(json.dumps(rows, indent=2))
    else:
        print(markdown(rows, "--all" in argv), end="")
    return 1 if any(row["advisories"] for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
