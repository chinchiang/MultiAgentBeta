"""Record immutable image IDs from an already provisioned local Docker daemon."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"backend"))
from vibe_audit.worker_entry import docker_api

REFERENCES={"worker":"vibeaudit-worker:test","semgrep":"semgrep/semgrep:1.153.0",
    "gitleaks":"vibeaudit-gitleaks:8.30.1","osv":"vibeaudit-osv:2.3.5",
    "zap":"ghcr.io/zaproxy/zaproxy:2.17.0",**{tool:"vibeaudit-tools:integration" for tool in ("schemathesis","playwright","promptfoo","pyrit")}}

DIGEST_REFERENCE=re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
BASE_LABEL="org.opencontainers.image.base.name"

def worker_base(image):
    """deploy/worker/Dockerfile records its BASE_IMAGE in the OCI base-image label and refuses tags.
    An image without a digest-pinned label was not built from that recipe, so its ID is not recorded.
    The label is self-declared: anyone who can build or tag images on the Docker daemon can set it, and an
    image built FROM a labeled worker inherits it, so a present label is a claim, not proof of the base image."""
    base=((image.get("Config") or {}).get("Labels") or {}).get(BASE_LABEL)
    if not isinstance(base,str) or not DIGEST_REFERENCE.fullmatch(base):
        raise SystemExit("Worker image has no digest-pinned "+BASE_LABEL+" label; rebuild it from "
                         "deploy/worker/Dockerfile with BASE_IMAGE=<name>@sha256:<digest>")
    return base

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--work-root",default="/var/lib/vibeaudit/workers")
    parser.add_argument("--database-env",default="VIBEAUDIT_DATABASE_URL")
    parser.add_argument("--offline-db",default="/opt/vibeaudit/osv")
    parser.add_argument("--static-only",action="store_true")
    args=parser.parse_args()
    if os.name!="posix" or not re.fullmatch(r"VIBEAUDIT_[A-Z0-9_]+",args.database_env):
        parser.error("Use local Linux and a VIBEAUDIT_* database credential reference")
    images={}
    provenance={}
    for tool,reference in REFERENCES.items():
        if args.static_only and tool not in {"worker","semgrep","gitleaks","osv"}:
            continue
        status,data=docker_api("GET","/images/"+quote(reference,safe="")+"/json",timeout=20)
        if status!=200:
            raise SystemExit("Missing local provisioned image: "+reference)
        images[tool]=data["Id"]
        provenance[tool]={"reference":reference,"image_id":data["Id"],"repository_digests":data.get("RepoDigests",[])}
        if tool=="worker":
            provenance[tool]["base_image_label"]=worker_base(data)
    profile={"backend":"docker","work_root":args.work_root,"database_url_env":args.database_env,
             "image_pins":images,"offline_db_dir":args.offline_db,"ttl_seconds":10}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps({"profiles":{"default":profile}},indent=2),encoding="utf-8")
    args.output.with_suffix(".images.json").write_text(json.dumps(provenance,indent=2),encoding="utf-8")
    print("Recorded "+str(len(images))+" local immutable image IDs; model capability tests remain separate.")

if __name__=="__main__":
    main()
