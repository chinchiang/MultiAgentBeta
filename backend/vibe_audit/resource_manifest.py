"""Pin scanner inputs and provisioning resources without contacting external services."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def file_hash(path: Path):
    checksum=hashlib.sha256()
    with path.open("rb") as stream:
        while block:=stream.read(1024*1024):
            checksum.update(block)
    return checksum.hexdigest()


def resource_manifest(config, tools):
    root=Path(__file__).resolve().parents[2]
    rules={name:file_hash(root/"fixtures"/name) for name in ("semgrep-rules.yml","gitleaks.toml","osv-scanner.toml")}
    result={"image_pins":config.get("image_pins",{}),"rules":rules,"offline_database":None}
    if "osv" in tools:
        directory=Path(config.get("offline_db_dir") or "__not_provisioned__")
        manifest=directory/"manifest.json"
        if not manifest.is_file():
            raise ValueError("OSV offline database needs a provisioning manifest")
        data=json.loads(manifest.read_text(encoding="utf-8"))
        if data.get("schema_version")!=1 or data.get("scanner_version")!="2.3.5":
            raise ValueError("Unsupported OSV database manifest")
        if {e["ecosystem"] for e in data["ecosystems"]}!={"npm","PyPI"}:
            raise ValueError("Both Python and npm offline databases must be provisioned")
        for entry in data["ecosystems"]:
            path=directory/"osv-scanner"/entry["ecosystem"]/"all.zip"
            if path.stat().st_size!=entry["bytes"] or file_hash(path)!=entry["sha256"]:
                raise ValueError("Offline vulnerability database integrity mismatch")
        result["offline_database"]=data
    return result
