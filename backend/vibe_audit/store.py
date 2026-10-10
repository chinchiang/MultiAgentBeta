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


SUMMARY_FIELDS = ("id", "name", "mode", "status", "stage", "created_at", "updated_at", "usage", "usage_unknown", "error", "error_zh",
                  "workers_pending_cleanup", "deployment_changed")


# Every statement, written once with SQLite's "?" placeholders; a Store converts the table to its dialect at construction,
# so no SQL is rewritten per call and tests can check the constants. Values are always bound, never spliced in.
SQL = {
    "create_runs": "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated TEXT NOT NULL)",
    "create_jobs": "CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, case_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL)",
    "create_entity_versions": "CREATE TABLE IF NOT EXISTS entity_versions (run_id TEXT NOT NULL, kind TEXT NOT NULL, entity_id TEXT NOT NULL, version TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(run_id,kind,entity_id,version))",
    "create_relations": "CREATE TABLE IF NOT EXISTS relations (run_id TEXT NOT NULL, version TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(run_id,version))",
    "create_settings": "CREATE TABLE IF NOT EXISTS settings (kind TEXT NOT NULL, id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(kind,id))",
    "create_events": "CREATE TABLE IF NOT EXISTS events (run_id TEXT NOT NULL, seq INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(run_id,seq))",
    "last_event": "SELECT max(seq) FROM events WHERE run_id=?",
    "insert_event": "INSERT INTO events VALUES (?,?,?) ON CONFLICT DO NOTHING",
    "events": "SELECT payload FROM events WHERE run_id=? ORDER BY seq",
    "events_after": "SELECT payload FROM events WHERE run_id=? AND seq>? ORDER BY seq",
    "all_events": "SELECT run_id,payload FROM events ORDER BY run_id,seq",
    "upsert_run": "INSERT INTO runs (id,payload,updated) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated=excluded.updated",
    "insert_entity": "INSERT INTO entity_versions VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING",
    "insert_relation": "INSERT INTO relations VALUES (?,?,?) ON CONFLICT DO NOTHING",
    "entities": "SELECT kind,entity_id,version,payload FROM entity_versions WHERE run_id=? ORDER BY kind,entity_id",
    "relations": "SELECT payload FROM relations WHERE run_id=?",
    "upsert_setting": "INSERT INTO settings VALUES (?,?,?) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload",
    "settings": "SELECT payload FROM settings WHERE kind=? ORDER BY id",
    "run": "SELECT payload FROM runs WHERE id=?",
    "runs": "SELECT payload FROM runs ORDER BY updated DESC",
    "insert_job": "INSERT INTO jobs VALUES (?,?,?,?,?)",
    "update_job": "UPDATE jobs SET status=?,payload=? WHERE id=?",
    "jobs": "SELECT id,case_id,status,payload FROM jobs WHERE run_id=?",
}


def placeholders(text: str, postgres: bool) -> str:
    """One statement written with ? placeholders, as the driver wants it: psycopg binds with %s, sqlite3 with ?."""
    return text.replace("?", "%s") if postgres else text


def dialect(statements: dict, postgres: bool) -> dict:
    """Every statement of a table in the driver's dialect."""
    return {name: placeholders(text, postgres) for name, text in statements.items()}


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
        self.transacting = False
        self.postgres = bool(database_url)
        self.database_url = database_url
        self.sql = dialect(SQL, self.postgres)
        if database_url:
            self.conn = self._connect()
        else:
            self.conn = sqlite3.connect(str(self.root / "demo.sqlite3"), check_same_thread=False, isolation_level=None)
            self.conn.execute("PRAGMA journal_mode=WAL")
        for name in ("create_runs", "create_jobs", "create_entity_versions", "create_relations", "create_settings", "create_events"):
            self._execute(self.sql[name])

    def _connect(self):
        import psycopg
        conn = psycopg.connect(self.database_url, autocommit=True, connect_timeout=5)
        # A SQL_ASCII database or client encoding hands every text column back as undecoded bytes.
        # Compare the names the server reports: asking for the Python codec raises for an encoding Python lacks.
        if any(conn.info.parameter_status(name) != "UTF8" for name in ("server_encoding", "client_encoding")):
            conn.close()
            raise ValueError("The PostgreSQL database and connection must use UTF8 encoding")
        return conn

    def _execute(self, sql, args=()):
        """Run one statement from self.sql (or a bare BEGIN/COMMIT/ROLLBACK) with its bound values."""
        if not self.postgres:
            return self.conn.execute(sql, args)
        import psycopg
        try:
            return self.conn.execute(sql, args)
        except psycopg.OperationalError:
            # A database restart drops the connection. Outside a transaction the statement is repeated once on a new
            # connection; inside one the statements before it are lost with the connection, so the error stands.
            if self.transacting:
                raise
            self.conn = self._connect()
            return self.conn.execute(sql, args)

    @contextmanager
    def transaction(self):
        """Nested callers share the outer atomic boundary under the same lock."""
        with self.lock:
            active = self.conn.info.transaction_status != 0 if self.postgres else self.conn.in_transaction
            if not active:
                self._execute("BEGIN")
                self.transacting = True
            try:
                yield
                if not active:
                    self._execute("COMMIT")
            except BaseException:
                if not active:
                    try:
                        self._execute("ROLLBACK")
                    except Exception:
                        # A connection the failure itself closed has nothing left to roll back.
                        pass
                raise
            finally:
                if not active:
                    self.transacting = False

    def save(self, run: dict):
        """Write the run; its events are appended to their own table, so a run with thousands of them is not rewritten
        whole on every event, and an event once stored is never rewritten."""
        run["updated_at"] = now()
        payload = json.dumps(run, ensure_ascii=False)
        if _SURROGATE.search(payload):
            # Model or target JSON carried an invalid escape; keep the run saveable rather than stuck as running.
            clean = scrub(run)
            run.clear()
            run.update(clean)
        events = run.get("events") or []
        payload = json.dumps({key: value for key, value in run.items() if key != "events"}, ensure_ascii=False)
        with self.transaction():
            self._execute(self.sql["upsert_run"], (run["id"], payload, run["updated_at"]))
            stored = self._execute(self.sql["last_event"], (run["id"],)).fetchone()[0] or 0
            for event in events[stored:]:
                self._execute(self.sql["insert_event"], (run["id"], event["seq"], json.dumps(event, ensure_ascii=False)))
            from .traceability import entities_and_links
            entities, links = entities_and_links(run)
            for item in entities:
                self._execute(self.sql["insert_entity"], (run["id"],item["kind"],item["id"],item["version"],json.dumps(item["value"],ensure_ascii=False)))
            for item in links:
                self._execute(self.sql["insert_relation"], (run["id"],digest(item),json.dumps(item,ensure_ascii=False)))

    def trace(self, run_id: str):
        from .traceability import entities_and_links
        # Versions are content digests with no order of their own; the run as it is now marks the current one.
        current={(item["kind"],item["id"],item["version"]) for item in entities_and_links(self.get(run_id))[0]}
        with self.lock:
            entities=[{"kind":r[0],"id":r[1],"version":r[2],"current":(r[0],r[1],r[2]) in current,"value":json.loads(r[3])} for r in self._execute(self.sql["entities"],(run_id,)).fetchall()]
            links=[json.loads(r[0]) for r in self._execute(self.sql["relations"],(run_id,)).fetchall()]
        entities.sort(key=lambda item:(item["kind"],item["id"],not item["current"]))
        return {"run_id":run_id,"entities":entities,"links":links}

    def save_setting(self, kind: str, key: str, value: dict):
        with self.lock:
            self._execute(self.sql["upsert_setting"], (kind,key,json.dumps(value,ensure_ascii=False)))

    def settings(self, kind: str):
        with self.lock:
            return [json.loads(r[0]) for r in self._execute(self.sql["settings"],(kind,)).fetchall()]

    @staticmethod
    def _assemble(run: dict, events: list[dict]) -> dict:
        """A run as its callers know it: the stored body with its events in sequence. A row written before events had
        their own table still carries them in its body; those are read until the next save moves them."""
        if events or "events" not in run:
            run["events"] = events
        return run

    def get(self, run_id: str) -> dict:
        with self.lock:
            row = self._execute(self.sql["run"], (run_id,)).fetchone()
            if not row:
                raise RunNotFound(run_id)
            events = [json.loads(r[0]) for r in self._execute(self.sql["events"], (run_id,)).fetchall()]
        return self._assemble(json.loads(row[0]), events)

    def events_after(self, run_id: str, seq: int) -> list[dict]:
        """The run's events with a sequence number above seq, in order: what a progress stream still has to send."""
        with self.lock:
            if not self._execute(self.sql["run"], (run_id,)).fetchone():
                raise RunNotFound(run_id)
            rows = self._execute(self.sql["events_after"], (run_id, seq)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def list(self) -> list[dict]:
        """Every run, whole; the engine's startup recovery saves them back, so their events come along."""
        with self.lock:
            rows = self._execute(self.sql["runs"]).fetchall()
            events = {}
            for run_id, payload in self._execute(self.sql["all_events"]).fetchall():
                events.setdefault(run_id, []).append(json.loads(payload))
        runs = [json.loads(r[0]) for r in rows]
        return [self._assemble(run, events.get(run["id"], [])) for run in runs]

    def summary(self, run_id: str) -> dict:
        """One run's inventory entry: its status and sizes, without its events or records."""
        with self.lock:
            row = self._execute(self.sql["run"], (run_id,)).fetchone()
        if not row:
            raise RunNotFound(run_id)
        run = json.loads(row[0])
        return {key: run.get(key) for key in SUMMARY_FIELDS}

    def summaries(self) -> list[dict]:
        """The inventory of runs: what a list shows, without events, findings, cases or evidence records."""
        with self.lock:
            rows = self._execute(self.sql["runs"]).fetchall()
        return [{key: run.get(key) for key in SUMMARY_FIELDS} for run in (json.loads(r[0]) for r in rows)]

    def job(self, run_id: str, case: dict) -> str:
        job_id = str(uuid.uuid4())
        payload = {"case_hash": case["hash"], "side_effects": case.get("side_effects",False), "created_at":now(), "attempt":1}
        with self.lock:
            self._execute(self.sql["insert_job"], (job_id,run_id,case["id"],"prepared",json.dumps(payload)))
        return job_id

    def update_job(self, job_id: str, status: str, payload: dict):
        with self.lock:
            self._execute(self.sql["update_job"], (status,json.dumps(payload),job_id))

    def finish_job(self, job_id: str, execution: dict, run: dict):
        """Commit the completed execution and aggregate run together; no replay window."""
        # The nesting-aware transaction helper, so a future caller inside another
        # transaction joins it instead of raising on a nested BEGIN.
        with self.transaction():
            self._execute(self.sql["update_job"], ("finished",json.dumps(execution),job_id))
            self.save(run)

    def jobs(self, run_id: str):
        with self.lock:
            return [{"id":r[0],"case_id":r[1],"status":r[2],"payload":json.loads(r[3])} for r in self._execute(self.sql["jobs"],(run_id,)).fetchall()]

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
