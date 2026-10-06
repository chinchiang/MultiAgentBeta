from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from .domain import digest, now


_SURROGATE = re.compile("[\ud800-\udfff]")


def scrub(value):
    """Replace lone surrogates, which untrusted \\udXXX escapes can create and UTF-8 storage cannot hold."""
    if isinstance(value, str):
        return _SURROGATE.sub("\ufffd", value)
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, dict):
        return {scrub(key) if isinstance(key, str) else key: scrub(item) for key, item in value.items()}
    return value


def private_dirs(*paths):
    """Runs, evidence and reports are readable only by the console's own account.

    The HTTP session guards the API, but other local accounts are also adversaries: on POSIX the data
    directories are owner-only, and a directory that cannot be made so stops the console from starting."""
    if os.name != "posix":
        return
    for path in paths:
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        if stat.S_IMODE(os.stat(path).st_mode) & 0o077:
            raise PermissionError(f"Data directory {path} is accessible to other local accounts; make it owner-only (chmod 700)")


class RunNotFound(KeyError):
    """Only an unknown run is a 404; any other KeyError is a bug and must not read as one."""


class Store:
    """Durable job journal. PostgreSQL for live; SQLite only for local synthetic demo."""

    def __init__(self, data_dir: str | Path, database_url: str | None = None):
        self.root = Path(data_dir).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(exist_ok=True, mode=0o700)
        private_dirs(self.root, self.artifacts)
        self.lock = threading.RLock()
        self.postgres = bool(database_url)
        if database_url:
            import psycopg
            self.conn = psycopg.connect(database_url, autocommit=True)
        else:
            self.conn = sqlite3.connect(str(self.root / "demo.sqlite3"), check_same_thread=False, isolation_level=None)
            self.conn.execute("PRAGMA journal_mode=WAL")
        self._execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated TEXT NOT NULL)")
        self._execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, case_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL)")
        self._execute("CREATE TABLE IF NOT EXISTS entity_versions (run_id TEXT NOT NULL, kind TEXT NOT NULL, entity_id TEXT NOT NULL, version TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(run_id,kind,entity_id,version))")
        self._execute("CREATE TABLE IF NOT EXISTS relations (run_id TEXT NOT NULL, version TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(run_id,version))")
        self._execute("CREATE TABLE IF NOT EXISTS settings (kind TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(kind,id))")

    def _execute(self, sql, args=()):
        return self.conn.execute(sql.replace("?", "%s") if self.postgres else sql, args)

    @contextmanager
    def transaction(self):
        """Nested callers share the outer atomic boundary under the same lock."""
        with self.lock:
            active = self.conn.info.transaction_status != 0 if self.postgres else self.conn.in_transaction
            if not active:
                self._execute("BEGIN")
            try:
                yield
                if not active:
                    self._execute("COMMIT")
            except BaseException:
                if not active:
                    self._execute("ROLLBACK")
                raise

    def save(self, run: dict):
        run["updated_at"] = now()
        payload = json.dumps(run, ensure_ascii=False)
        if _SURROGATE.search(payload):
            # Model or target JSON carried an invalid escape; keep the run saveable rather than stuck as running.
            clean = scrub(run)
            run.clear()
            run.update(clean)
            payload = json.dumps(run, ensure_ascii=False)
        with self.transaction():
            self._execute("INSERT INTO runs (id,payload,updated) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated=excluded.updated", (run["id"], payload, run["updated_at"]))
            from .traceability import entities_and_links
            entities, links = entities_and_links(run)
            for item in entities:
                self._execute("INSERT INTO entity_versions VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING", (run["id"],item["kind"],item["id"],item["version"],json.dumps(item["value"],ensure_ascii=False)))
            for item in links:
                self._execute("INSERT INTO relations VALUES (?,?,?) ON CONFLICT DO NOTHING", (run["id"],digest(item),json.dumps(item,ensure_ascii=False)))

    def trace(self, run_id: str):
        from .traceability import entities_and_links
        # Versions are content digests with no order of their own; the run as it is now marks the current one.
        current={(item["kind"],item["id"],item["version"]) for item in entities_and_links(self.get(run_id))[0]}
        with self.lock:
            entities=[{"kind":r[0],"id":r[1],"version":r[2],"current":(r[0],r[1],r[2]) in current,"value":json.loads(r[3])} for r in self._execute("SELECT kind,entity_id,version,payload FROM entity_versions WHERE run_id=? ORDER BY kind,entity_id",(run_id,)).fetchall()]
            links=[json.loads(r[0]) for r in self._execute("SELECT payload FROM relations WHERE run_id=?",(run_id,)).fetchall()]
        entities.sort(key=lambda item:(item["kind"],item["id"],not item["current"]))
        return {"run_id":run_id,"entities":entities,"links":links}

    def save_setting(self, kind: str, key: str, value: dict):
        with self.lock:
            self._execute("INSERT INTO settings VALUES (?,?,?) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload", (kind,key,json.dumps(value,ensure_ascii=False)))

    def settings(self, kind: str):
        with self.lock:
            return [json.loads(r[0]) for r in self._execute("SELECT payload FROM settings WHERE kind=? ORDER BY id",(kind,)).fetchall()]

    def get(self, run_id: str) -> dict:
        with self.lock:
            row = self._execute("SELECT payload FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise RunNotFound(run_id)
        return json.loads(row[0])

    def list(self) -> list[dict]:
        with self.lock:
            return [json.loads(r[0]) for r in self._execute("SELECT payload FROM runs ORDER BY updated DESC").fetchall()]

    def job(self, run_id: str, case: dict) -> str:
        job_id = str(uuid.uuid4())
        payload = {"case_hash": case["hash"], "side_effects": case.get("side_effects",False), "created_at":now(), "attempt":1}
        with self.lock:
            self._execute("INSERT INTO jobs VALUES (?,?,?,?,?)", (job_id,run_id,case["id"],"prepared",json.dumps(payload)))
        return job_id

    def update_job(self, job_id: str, status: str, payload: dict):
        with self.lock:
            self._execute("UPDATE jobs SET status=?,payload=? WHERE id=?", (status,json.dumps(payload),job_id))

    def finish_job(self, job_id: str, execution: dict, run: dict):
        """Commit the completed execution and aggregate run together; no replay window."""
        # The nesting-aware transaction helper, so a future caller inside another
        # transaction joins it instead of raising on a nested BEGIN.
        with self.transaction():
            self._execute("UPDATE jobs SET status=?,payload=? WHERE id=?", ("finished",json.dumps(execution),job_id))
            self.save(run)

    def jobs(self, run_id: str):
        with self.lock:
            return [{"id":r[0],"case_id":r[1],"status":r[2],"payload":json.loads(r[3])} for r in self._execute("SELECT id,case_id,status,payload FROM jobs WHERE run_id=?",(run_id,)).fetchall()]

    def put_evidence(self, run_id: str, producer: str, content: dict) -> dict:
        artifact_id = str(uuid.uuid4())
        body = scrub({"run_id":run_id,"id":artifact_id,"producer":producer,"at":now(),"content":content})
        checksum = digest(body)
        path = self.artifacts / f"{artifact_id}.json"
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as f:
            json.dump(body,f,ensure_ascii=False,sort_keys=True)
        return {"id":artifact_id,"run_id":run_id,"producer":producer,"sha256":checksum,"filename":path.name}

    def evidence(self, record: dict, run_id: str) -> dict:
        filename = record["filename"]
        if Path(filename).name != filename or not filename.endswith(".json"):
            raise ValueError("Invalid artifact path")
        body = json.loads((self.artifacts / filename).read_text(encoding="utf-8"))
        if body["run_id"] != run_id or record["run_id"] != run_id or digest(body) != record["sha256"]:
            raise ValueError("Evidence integrity or run attribution mismatch")
        return body

    def close(self):
        self.conn.close()
