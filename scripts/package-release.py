"""Package only project deliverables; exclude credentials, live data, caches and local tool state.

  python scripts/package-release.py                  write source-manifest.sha256 and the release archive
  python scripts/package-release.py --manifest-only  regenerate source-manifest.sha256 only
  python scripts/package-release.py --check          fail if source-manifest.sha256 does not match the tree
"""
from pathlib import Path, PureWindowsPath
import argparse
import hashlib
import json
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"
MANIFEST = "source-manifest.sha256"
PRIVATE = (".env", "local-secrets.", ".data")


def deliverables(root=ROOT):
    # Git decides what ships, so editor or agent state and scratch files never enter a release; the built UI is added explicitly.
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout.decode("utf-8").split("\0")
    built = [p.relative_to(root).as_posix() for p in (root/"frontend"/"dist").rglob("*")]
    names = {name for name in tracked+built if name and name != MANIFEST and (root/name).is_file() and not (root/name).is_symlink()
             and not any(part.startswith(PRIVATE) for part in PureWindowsPath(name).parts)}
    return sorted(names, key=PureWindowsPath)


def render(names, root=ROOT):
    # CRLF and Windows path order on every platform, so Linux and Windows reproduce the same committed bytes.
    return "".join(hashlib.sha256((root/name).read_bytes()).hexdigest()+"  "+name+"\r\n" for name in names).encode("utf-8")


def check(root=ROOT):
    expected = render(deliverables(root), root)
    recorded = (root/MANIFEST).read_bytes() if (root/MANIFEST).is_file() else b""
    if expected == recorded:
        return []
    old, new = set(recorded.decode("utf-8").splitlines()), set(expected.decode("utf-8").splitlines())
    return sorted({line.split("  ", 1)[1] for line in old ^ new}, key=PureWindowsPath)


def package(root=ROOT):
    names = deliverables(root)
    (root/MANIFEST).write_bytes(render(names, root))
    names.append(MANIFEST)
    archive = root.parent/("vibe-audit-"+VERSION+".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name in names:
            output.write(root/name, "vibe-audit/"+name)
    with zipfile.ZipFile(archive) as output:
        assert output.testzip() is None
        packed = output.namelist()
        assert "vibe-audit/frontend/dist/index.html" in packed
        assert "vibe-audit/docs/VALIDATION.md" in packed
        assert not any(part.startswith(PRIVATE) or part in {".claude", ".git", "node_modules", "__pycache__"} for name in packed for part in Path(name).parts[1:])
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(checksum+"  "+archive.name+"\n", encoding="ascii")
    return {"archive": str(archive), "files": len(names), "bytes": archive.stat().st_size, "sha256": checksum}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--manifest-only", action="store_true")
    args = parser.parse_args()
    if args.check:
        stale = check()
        if stale:
            print(MANIFEST+" does not match the tree; regenerate with --manifest-only:\n  "+"\n  ".join(stale), file=sys.stderr)
            return 1
        print(MANIFEST+" matches "+str(len(deliverables()))+" files")
    elif args.manifest_only:
        names = deliverables()
        (ROOT/MANIFEST).write_bytes(render(names))
        print(json.dumps({"manifest": MANIFEST, "files": len(names)}))
    else:
        print(json.dumps(package()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
