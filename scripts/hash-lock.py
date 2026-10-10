"""Pin every requirements.lock.txt entry to the files PyPI publishes for that exact release.

  python scripts/hash-lock.py           fail if the recorded hashes differ from PyPI's
  python scripts/hash-lock.py --write   rewrite requirements.lock.txt from its name==version pins
  python scripts/hash-lock.py --lock requirements.mutation.lock.txt [--write]   the same for another lock file

A pin may carry an environment marker (name==version ; python_version == "3.13"), which is kept.

Every published file of a release is listed, so the Windows and Linux wheels of each supported
Python verify. pip then installs in hash-checking mode: a changed artifact, or a dependency the
lock does not pin, stops the install instead of being resolved silently.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements.lock.txt"
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._+!-]+)( ; [^\\\r\n]+)?")


def published(pin):
    name, version = pin
    with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=30) as response:
        files = json.load(response)["urls"]
    if not files:
        raise SystemExit(f"PyPI lists no files for {name}=={version}")
    return sorted({file["digests"]["sha256"] for file in files})


def main():
    args = sys.argv[1:]
    lock = ROOT / args[args.index("--lock") + 1] if "--lock" in args else LOCK
    current = lock.read_bytes().decode("ascii")
    pins = [match.groups() for match in map(PIN.match, current.splitlines()) if match]
    with ThreadPoolExecutor(8) as pool:
        hashes = list(pool.map(published, [pin[:2] for pin in pins]))
    # CRLF like the committed file, which is hash-verified byte for byte.
    expected = "".join(f"{name}=={version}{(marker or '').rstrip()}" + "".join(f" \\\r\n    --hash=sha256:{h}" for h in digests) + "\r\n"
                       for (name, version, marker), digests in zip(pins, hashes))
    if "--write" in args:
        lock.write_bytes(expected.encode("ascii"))
        print(f"Recorded {sum(map(len, hashes))} file hashes for {len(pins)} pins in {lock.name}")
        return 0
    if current != expected:
        print(f"{lock.name} does not match PyPI's published files; rerun with --write", file=sys.stderr)
        return 1
    print(f"{len(pins)} pins match PyPI's published files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
