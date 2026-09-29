"""Package only project deliverables; exclude credentials, live data and caches."""
from pathlib import Path
import hashlib
import json
import os
import zipfile

root = Path(__file__).resolve().parents[1]
version = "0.2.0"
excluded = {"node_modules", "__pycache__", ".pytest_cache", ".venv", ".git", ".npm-cache", ".vite", ".vite-temp"}
files = []
for directory, dirs, names in os.walk(root, followlinks=False):
    dirs[:] = [d for d in dirs if d not in excluded and not d.startswith((".data", "pytest-cache-files-")) and not d.endswith(".egg-info") and not (Path(directory)/d).is_symlink()]
    for name in names:
        path = Path(directory)/name
        if path.is_symlink() or name.startswith((".env", "local-secrets.")) or name.endswith((".pyc", ".tsbuildinfo", ".log", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm")) or name == "source-manifest.sha256":
            continue
        files.append(path)
manifest = root/"source-manifest.sha256"
manifest.write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest()+"  "+p.relative_to(root).as_posix()+"\n" for p in sorted(files)), encoding="utf-8")
files.append(manifest)
archive = root.parent/("vibe-audit-"+version+".zip")
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as output:
    for path in sorted(files):
        output.write(path, "vibe-audit/"+path.relative_to(root).as_posix())
with zipfile.ZipFile(archive) as output:
    assert output.testzip() is None
    names = output.namelist()
    assert "vibe-audit/frontend/dist/index.html" in names
    assert "vibe-audit/docs/VALIDATION.md" in names
    assert not any(any(part in excluded or part.startswith((".data",".env","local-secrets.")) for part in Path(name).parts) for name in names)
checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_suffix(".zip.sha256").write_text(checksum+"  "+archive.name+"\n", encoding="ascii")
print(json.dumps({"archive":str(archive),"files":len(files),"bytes":archive.stat().st_size,"sha256":checksum}))
