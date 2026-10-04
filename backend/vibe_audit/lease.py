"""Durable, one-use worker capabilities and non-replayable dispatch journals.

PostgreSQL uses its server clock and row locks; SQLite is a single-host test
backend using BEGIN IMMEDIATE. Clear capability/renewal secrets are never stored.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
import uuid


class LeaseError(RuntimeError):
    pass


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _secret_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


class LeaseStore:
    def __init__(self, database_path=None, *, database_url=None, clock=None):
        self.database_path = str(database_path) if database_path is not None else None
        self.database_url = database_url
        self.postgres = bool(database_url)
        self.clock = clock or time.time
        self.lock = threading.RLock()
        if self.postgres:
            import psycopg
            self.conn = psycopg.connect(database_url, autocommit=True, connect_timeout=3, options="-c statement_timeout=2000 -c lock_timeout=1000")
        else:
            if not self.database_path:
                raise LeaseError("A durable lease database is required")
            self.conn = sqlite3.connect(self.database_path, isolation_level=None, check_same_thread=False, timeout=10)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=FULL")
        self._sql("CREATE TABLE IF NOT EXISTS worker_leases (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, renew_hash TEXT NOT NULL, binding TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL, deadline DOUBLE PRECISION NOT NULL, max_requests INTEGER NOT NULL, used_requests INTEGER NOT NULL, worker_id TEXT, state TEXT NOT NULL)")
        self._sql("CREATE TABLE IF NOT EXISTS worker_tasks (id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE NOT NULL, lease_id TEXT NOT NULL, state TEXT NOT NULL, payload TEXT NOT NULL)")
        self._sql("CREATE TABLE IF NOT EXISTS worker_dispatches (task_id TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL, state TEXT NOT NULL, result_hash TEXT, PRIMARY KEY(task_id,request_id))")

    def _sql(self, query, args=()):
        return self.conn.execute(query.replace("?", "%s") if self.postgres else query, args)

    def _now(self):
        return float(self._sql("SELECT EXTRACT(EPOCH FROM clock_timestamp())").fetchone()[0]) if self.postgres else float(self.clock())

    @contextmanager
    def _transaction(self):
        with self.lock:
            self._sql("BEGIN" if self.postgres else "BEGIN IMMEDIATE")
            try:
                yield
                self._sql("COMMIT")
            except BaseException:
                self._sql("ROLLBACK")
                raise

    def _row(self, lease_id, *, lock=False):
        row = self._sql("SELECT token_hash,renew_hash,binding,expires,deadline,max_requests,used_requests,worker_id,state FROM worker_leases WHERE id=?" + (" FOR UPDATE" if lock and self.postgres else ""), (lease_id,)).fetchone()
        if not row:
            raise LeaseError("Worker lease not found")
        return dict(zip(("token_hash", "renew_hash", "binding", "expires", "deadline", "max_requests", "used_requests", "worker_id", "state"), row))

    @staticmethod
    def _idempotency_key(binding):
        # Recipe changes cannot turn an already-issued external task into
        # a fresh attempt. A deliberate retry requires a new run/repetition.
        return canonical_hash({k: v for k, v in binding.items() if k != "spec_hash"})

    def issue(self, *, run_id, case_hash, threat_hash, manifest_hash, max_requests, ttl_seconds=5, max_seconds=120, operation="http_case", repetition=0, spec_hash=None):
        if any(not isinstance(v, str) or not v for v in (run_id, case_hash, threat_hash, manifest_hash, operation)):
            raise LeaseError("Complete immutable capability bindings are required")
        if type(max_requests) is not int or not 1 <= max_requests <= 10000 or not 0.1 <= ttl_seconds <= 30 or not ttl_seconds <= max_seconds <= 14400 or type(repetition) is not int or repetition < 0:
            raise LeaseError("Invalid worker lease limits")
        binding = {"run_id":run_id,"case_hash":case_hash,"threat_hash":threat_hash,"manifest_hash":manifest_hash,"operation":operation,"repetition":repetition,"spec_hash":spec_hash or case_hash}
        lease_id, task_id = uuid.uuid4().hex, uuid.uuid4().hex
        token, renewal = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self._transaction():
            now = self._now()
            key = self._idempotency_key(binding)
            if self._sql("SELECT state FROM worker_tasks WHERE idempotency_key=?", (key,)).fetchone():
                raise LeaseError("Task already exists; prepared/sent/finished/unknown tasks are never implicitly replayed")
            self._sql("INSERT INTO worker_leases VALUES (?,?,?,?,?,?,?,?,?,?)", (lease_id,_secret_hash(token),_secret_hash(renewal),json.dumps(binding),now+ttl_seconds,now+max_seconds,max_requests,0,None,"issued"))
            self._sql("INSERT INTO worker_tasks VALUES (?,?,?,?,?)", (task_id,key,lease_id,"prepared",json.dumps({"binding":binding})))
        return {"id":lease_id,"task_id":task_id,"token":token,"renewal_token":renewal,"binding":binding,"ttl_seconds":ttl_seconds,"max_seconds":max_seconds,"max_requests":max_requests}

    def finished_result(self, *, run_id, case_hash, threat_hash, manifest_hash, operation, repetition, spec_hash=None):
        """Return the journaled result of a finished task with this exact binding, else None.

        A controller crash after the worker finished must not force replay or
        reconciliation: the paid, journaled result is reused. Prepared, sent or
        unknown tasks stay unreplayable and keep their reconciliation path.
        """
        if any(not isinstance(v, str) or not v for v in (run_id, case_hash, threat_hash, manifest_hash, operation)):
            raise LeaseError("Complete immutable capability bindings are required")
        binding = {"run_id":run_id,"case_hash":case_hash,"threat_hash":threat_hash,"manifest_hash":manifest_hash,"operation":operation,"repetition":repetition,"spec_hash":spec_hash or case_hash}
        key = self._idempotency_key(binding)
        with self.lock:
            row = self._sql("SELECT state,payload FROM worker_tasks WHERE idempotency_key=?", (key,)).fetchone()
            if not row or row[0] != "finished":
                return None
            result = json.loads(row[1]).get("result")
            return result if isinstance(result, dict) else None

    def _validate(self, row, token, binding, worker_id=None, *, issued=False):
        if not isinstance(token,str) or not hmac.compare_digest(row["token_hash"],_secret_hash(token)) or json.loads(row["binding"]) != binding:
            raise LeaseError("Worker capability identity or binding mismatch")
        if row["state"] not in ({"issued","active"} if issued else {"active"}) or self._now() >= min(row["expires"],row["deadline"]):
            raise LeaseError("Worker capability revoked or expired")
        if worker_id is not None and row["worker_id"] != worker_id:
            raise LeaseError("Capability is claimed by another worker")

    def claim(self, capability, worker_id):
        if not isinstance(worker_id,str) or not worker_id:
            raise LeaseError("Worker identity is required")
        with self._transaction():
            row = self._row(capability["id"],lock=True)
            self._validate(row,capability["token"],capability["binding"],issued=True)
            if row["state"] != "issued" or row["worker_id"] is not None:
                raise LeaseError("Worker capability has already been claimed")
            self._sql("UPDATE worker_leases SET worker_id=?,state='active' WHERE id=?", (worker_id,capability["id"]))

    def validate(self, capability, worker_id):
        with self._transaction():
            row = self._row(capability["id"],lock=True)
            self._validate(row,capability["token"],capability["binding"],worker_id)
            return {k:row[k] for k in ("expires","deadline","max_requests","used_requests","state")}

    def renew(self, capability):
        with self._transaction():
            row = self._row(capability["id"],lock=True)
            self._validate(row,capability["token"],capability["binding"],issued=True)
            if not hmac.compare_digest(row["renew_hash"],_secret_hash(capability.get("renewal_token",""))):
                raise LeaseError("Only the controller can renew a lease")
            expires = min(self._now()+capability["ttl_seconds"],row["deadline"])
            self._sql("UPDATE worker_leases SET expires=? WHERE id=?", (expires,capability["id"]))
            return expires

    def reserve_dispatch(self, capability, worker_id, request_id, request):
        """Commit request consumption and 'sent' BEFORE any external I/O."""
        if not isinstance(request_id,str) or not request_id:
            raise LeaseError("A unique request ID is required")
        with self._transaction():
            row = self._row(capability["id"],lock=True)
            self._validate(row,capability["token"],capability["binding"],worker_id)
            task = self._sql("SELECT lease_id,state FROM worker_tasks WHERE id=?", (capability["task_id"],)).fetchone()
            if not task or task[0] != capability["id"] or task[1] not in {"prepared","sent"}:
                raise LeaseError("External task is terminal or has a different lease")
            if self._sql("SELECT state FROM worker_dispatches WHERE task_id=? AND request_id=?", (capability["task_id"],request_id)).fetchone():
                raise LeaseError("Request ID already journaled; dispatch cannot be replayed")
            if row["used_requests"] >= row["max_requests"]:
                raise LeaseError("Worker request budget exhausted")
            self._sql("UPDATE worker_leases SET used_requests=used_requests+1 WHERE id=?", (capability["id"],))
            self._sql("INSERT INTO worker_dispatches VALUES (?,?,?,?,?)", (capability["task_id"],request_id,canonical_hash(request),"sent",None))
            self._sql("UPDATE worker_tasks SET state='sent' WHERE id=?", (capability["task_id"],))

    def finish_dispatch(self, capability, worker_id, request_id, request, result):
        """Bind a recorded result to the exact journaled request it answers."""
        with self._transaction():
            row = self._row(capability["id"],lock=True)
            self._validate(row,capability["token"],capability["binding"],worker_id)
            journaled = self._sql("SELECT request_hash FROM worker_dispatches WHERE task_id=? AND request_id=? AND state='sent'", (capability["task_id"],request_id)).fetchone()
            if not journaled or journaled[0] != canonical_hash(request):
                raise LeaseError("Result does not match the journaled dispatch request")
            changed = self._sql("UPDATE worker_dispatches SET state='finished',result_hash=? WHERE task_id=? AND request_id=? AND state='sent'", (canonical_hash(result),capability["task_id"],request_id)).rowcount
            if changed != 1:
                raise LeaseError("No pending dispatch matches this result")

    def finish_task(self, capability, worker_id, result):
        with self._transaction():
            row = self._row(capability["id"],lock=True)
            self._validate(row,capability["token"],capability["binding"],worker_id)
            if self._sql("SELECT 1 FROM worker_dispatches WHERE task_id=? AND state<>'finished'", (capability["task_id"],)).fetchone():
                raise LeaseError("An external dispatch outcome remains unknown")
            changed = self._sql("UPDATE worker_tasks SET state='finished',payload=? WHERE id=? AND state IN ('prepared','sent')", (json.dumps({"binding":capability["binding"],"result":result}),capability["task_id"])).rowcount
            if changed != 1:
                raise LeaseError("Task is already terminal")
            self._sql("UPDATE worker_leases SET state='finished' WHERE id=?", (capability["id"],))

    def revoke(self, lease_id, reason="revoked"):
        with self._transaction():
            row = self._row(lease_id,lock=True)
            if row["state"] == "finished":
                return
            self._sql("UPDATE worker_leases SET state='revoked' WHERE id=?", (lease_id,))
            self._sql("UPDATE worker_dispatches SET state='outcome_unknown' WHERE task_id IN (SELECT id FROM worker_tasks WHERE lease_id=?) AND state='sent'", (lease_id,))
            self._sql("UPDATE worker_tasks SET state='outcome_unknown',payload=? WHERE lease_id=? AND state IN ('prepared','sent')", (json.dumps({"binding":json.loads(row["binding"]),"reason":str(reason)[:160]}),lease_id))

    def expire(self):
        with self.lock:
            now = self._now()
            ids = [r[0] for r in self._sql("SELECT id FROM worker_leases WHERE state IN ('issued','active') AND (expires<=? OR deadline<=?)", (now,now)).fetchall()]
        for lease_id in ids:
            self.revoke(lease_id,"Lease expired; external task must be reconciled")
        return ids

    def task(self, task_id):
        with self.lock:
            row = self._sql("SELECT idempotency_key,lease_id,state,payload FROM worker_tasks WHERE id=?", (task_id,)).fetchone()
            if not row:
                raise LeaseError("Worker task not found")
            return {"id":task_id,"key":row[0],"lease_id":row[1],"state":row[2],"payload":json.loads(row[3])}

    def close(self):
        self.conn.close()
