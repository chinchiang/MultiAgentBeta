"""Remove host and account names from JUnit receipts before they are committed.

  python scripts/redact-receipts.py           rewrite docs/**/*.xml in place
  python scripts/redact-receipts.py --check   fail if any receipt still names a host or account

Only the hostname attribute and the account segment of home-directory paths change; test names,
counts, durations, skip reasons and failures stay byte-for-byte as recorded.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = [
    (re.compile(rb'hostname="(?!redacted-host")[^"]*"'), rb'hostname="redacted-host"'),
    (re.compile(rb"([A-Za-z]:\\Users\\)(?!user\\)[^\\\"<]+"), rb"\1user"),
    (re.compile(rb"(/mnt/[a-z]/Users/)(?!user/)[^/\"<]+"), rb"\1user"),
    (re.compile(rb"(/home/)(?!user/)[^/\"<]+"), rb"\1user"),
]


def redact(data: bytes) -> bytes:
    for pattern, replacement in PATTERNS:
        data = pattern.sub(replacement, data)
    return data


def main() -> int:
    receipts = sorted((ROOT / "docs").rglob("*.xml"))
    changed = [path for path in receipts if redact(path.read_bytes()) != path.read_bytes()]
    if "--check" in sys.argv[1:]:
        for path in changed:
            print("Receipt names a host or account: " + path.relative_to(ROOT).as_posix(), file=sys.stderr)
        return 1 if changed else 0
    for path in changed:
        path.write_bytes(redact(path.read_bytes()))
    print(f"Redacted {len(changed)} of {len(receipts)} receipts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
