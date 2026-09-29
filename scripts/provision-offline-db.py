"""Explicit administrator provisioning; never runs as part of a target scan.

Downloads complete ecosystem archives from OSV's official public bucket. No
source inventory or dependency names are transmitted. Pin the resulting manifest.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile


def provision(root):
    manifest = {"schema_version": 1, "downloaded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "scanner_version": "2.3.5", "ecosystems": []}
    for ecosystem in ("PyPI", "npm"):
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        folder = root / "osv-scanner" / ecosystem
        folder.mkdir(parents=True, exist_ok=True)
        temporary = folder / "all.zip.download"
        checksum, size = hashlib.sha256(), 0
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as output:
            if response.geturl() != url:
                raise RuntimeError("Unexpected database download redirect")
            etag = response.headers.get("ETag")
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 4 * 1024**3:
                    raise RuntimeError("Database download exceeded the provisioning size bound")
                checksum.update(chunk)
                output.write(chunk)
        with zipfile.ZipFile(temporary) as archive:
            count = len(archive.infolist())
            if not count or archive.testzip() is not None:
                raise RuntimeError("Downloaded database failed archive integrity checks")
        temporary.replace(folder / "all.zip")
        record = {"ecosystem": ecosystem, "url": url, "etag": etag, "sha256": checksum.hexdigest(),
                  "bytes": size, "entries": count, "coverage": "complete upstream ecosystem archive"}
        manifest["ecosystems"].append(record)
        print(json.dumps(record), flush=True)
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    provision(args.directory.resolve())
