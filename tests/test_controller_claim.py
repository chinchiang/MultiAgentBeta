"""One controller per data directory and per database: a second process must not recover a live controller's runs."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vibe_audit.domain import RunInput
from vibe_audit.service import Engine
from vibe_audit.store import ControllerBusy, Store

ROOT = Path(__file__).resolve().parents[1]
# The other process: an engine on the same data, refused after a short wait. It prints what it saw of the runs.
OTHER = """
import sys
from vibe_audit import store
store.CONTROLLER_WAIT_SECONDS = 0.5
from vibe_audit.service import Engine
data = store.Store(sys.argv[1], sys.argv[2] or None)
try:
    Engine(data)
except store.ControllerBusy as exc:
    print("busy:", exc)
else:
    print("claimed")
"""


def other_controller(data_dir, database_url=None):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "backend")}
    done = subprocess.run([sys.executable, "-c", OTHER, str(data_dir), database_url or ""], capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def running_run(engine):
    run = engine.create(RunInput(name="Live elsewhere"))
    run.update(status="running", stage="whitebox")
    engine.store.save(run)
    return run


def test_a_second_process_on_the_same_data_directory_is_refused(tmp_path):
    store = Store(tmp_path)
    engine = Engine(store)
    run = running_run(engine)
    try:
        answer = other_controller(tmp_path)
        assert answer.startswith("busy: Another Vibe Audit process already uses the data directory")
        # Refused before its startup recovery: the live controller's run is untouched.
        assert store.get(run["id"])["status"] == "running"
    finally:
        store.close()
    # Closing the last store that held the claim lets another process take it.
    assert other_controller(tmp_path) == "claimed"


def test_engines_in_one_process_share_the_claim_until_the_last_store_closes(tmp_path):
    first = Store(tmp_path)
    Engine(first)
    second = Store(tmp_path)
    Engine(second)
    first.close()
    assert other_controller(tmp_path).startswith("busy:")
    second.close()
    assert other_controller(tmp_path) == "claimed"


def test_a_controller_that_lets_go_within_the_wait_is_followed(tmp_path, monkeypatch):
    from vibe_audit import store as module
    holder = Store(tmp_path)
    holder.claim_controller()
    held = module._CLAIMS["dir:" + str(holder.root)]
    slept = []
    def sleep(seconds):
        # The old controller finishes shutting down during the first wait.
        slept.append(seconds)
        held.handle.close()
    monkeypatch.setattr(module.time, "sleep", sleep)
    # A claim this process holds is shared, so the waiting process is played by a fresh claim on the same lock file.
    monkeypatch.setattr(module, "_CLAIMS", {})
    follower = Store(tmp_path)
    try:
        follower.claim_controller()
        assert slept == [0.2]
    finally:
        follower.close()
        monkeypatch.undo()
        holder.close()


def test_a_refused_claim_raises_controller_busy_in_process(tmp_path, monkeypatch):
    from vibe_audit import store as module
    holder = Store(tmp_path)
    holder.claim_controller()
    monkeypatch.setattr(module, "_CLAIMS", {})
    monkeypatch.setattr(module, "CONTROLLER_WAIT_SECONDS", 0)
    other = Store(tmp_path)
    try:
        with pytest.raises(ControllerBusy, match="data directory"):
            Engine(other)
    finally:
        other.close()
        monkeypatch.undo()
        holder.close()


def test_a_lost_database_claim_is_tried_once_while_serving(monkeypatch):
    # A database restart ended the lock's session and another process took the lock: it will not let go, and the
    # console must not stall its requests waiting for it.
    import psycopg
    from vibe_audit import store as module
    class Dead:
        def execute(self, *args):
            raise psycopg.OperationalError("synthetic: the session ended")
        def close(self):
            pass
    class Taken:
        closed = False
        def execute(self, *args):
            class Row:
                def fetchone(self):
                    return (False,)
            return Row()
        def close(self):
            self.closed = True
    taken = Taken()
    monkeypatch.setattr(module, "_CLAIMS", {"db:synthetic": module._Claim(Dead())})
    slept = []
    monkeypatch.setattr(module.time, "sleep", slept.append)
    with pytest.raises(ControllerBusy, match="already controls this database"):
        module._confirm_database("db:synthetic", lambda: taken)
    assert slept == [] and taken.closed


def postgres_url():
    url = os.getenv("VIBEAUDIT_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Provide dedicated PostgreSQL integration database")
    return url


def test_a_second_process_on_the_same_database_is_refused(tmp_path):
    url = postgres_url()
    store = Store(tmp_path / "one", url)
    engine = Engine(store, url)
    run = running_run(engine)
    try:
        # Another data directory, the same database: its recovery would rewrite this controller's runs.
        answer = other_controller(tmp_path / "two", url)
        assert answer.startswith("busy: Another Vibe Audit process already controls this database")
        assert store.get(run["id"])["status"] == "running"
    finally:
        store.close()
    assert other_controller(tmp_path / "two", url) == "claimed"


def test_a_database_restart_is_noticed_and_the_lock_taken_again(tmp_path):
    import psycopg
    from vibe_audit import store as module
    url = postgres_url()
    store = Store(tmp_path, url)
    engine = Engine(store, url)
    try:
        claim = module._CLAIMS["db:" + url]
        pid = claim.handle.info.backend_pid
        with psycopg.connect(url, autocommit=True) as admin:
            admin.execute("SELECT pg_terminate_backend(%s)", (pid,))
        # The lock went with its session; the next recovery confirms it and takes it on a new session.
        run = running_run(engine)
        engine.cancel(run["id"])
        assert claim.handle.info.backend_pid != pid
        assert other_controller(tmp_path / "two", url).startswith("busy:")
    finally:
        store.close()


def test_a_store_without_a_database_claim_confirms_nothing(tmp_path, monkeypatch):
    from vibe_audit import store as module
    calls = []
    monkeypatch.setattr(module, "_confirm_database", lambda *args: calls.append(args))
    store = Store(tmp_path)
    try:
        Engine(store)
        store.confirm_controller()
        assert calls == []
    finally:
        store.close()


def test_a_forked_child_takes_a_database_lock_of_its_own(monkeypatch):
    # The parent's claim is in the inherited table; confirming it must not touch the parent's session.
    from vibe_audit import store as module
    class Parent:
        def execute(self, *args):
            raise AssertionError("the parent's session was used")
    class Fresh:
        def execute(self, *args):
            class Row:
                def fetchone(self):
                    return (True,)
            return Row()
    inherited = module._Claim(Parent())
    inherited.pid = os.getpid() + 1
    monkeypatch.setattr(module, "_CLAIMS", {"db:synthetic": inherited})
    fresh = Fresh()
    module._confirm_database("db:synthetic", lambda: fresh)
    assert module._CLAIMS["db:synthetic"].handle is fresh and module._CLAIMS["db:synthetic"].pid == os.getpid()


def lock_session(url):
    from vibe_audit import store as module
    return module._CLAIMS["db:" + url].handle.info.backend_pid


def terminate(url, *pids):
    import psycopg
    with psycopg.connect(url, autocommit=True) as admin:
        for pid in pids:
            admin.execute("SELECT pg_terminate_backend(%s)", (pid,))


def test_a_lock_session_lost_unseen_is_taken_again_before_the_next_write(tmp_path):
    url = postgres_url()
    store = Store(tmp_path, url)
    engine = Engine(store, url)
    try:
        run = engine.create(RunInput(name="Writes on"))
        pid = lock_session(url)
        # An idle timeout or a proxy ended only the lock's session; the store's own connection is fine.
        terminate(url, pid)
        store.save(run)
        assert lock_session(url) != pid
        assert other_controller(tmp_path / "two", url).startswith("busy:")
    finally:
        store.close()


def test_a_reconnect_confirms_the_lock_before_its_statement(tmp_path):
    url = postgres_url()
    store = Store(tmp_path, url)
    engine = Engine(store, url)
    try:
        run = engine.create(RunInput(name="Database restarted"))
        pid = lock_session(url)
        # A database restart ends both sessions; a read reconnects first.
        terminate(url, pid, store.conn.info.backend_pid)
        assert store.get(run["id"])["name"] == "Database restarted"
        assert lock_session(url) != pid
    finally:
        store.close()


def test_a_controller_whose_lock_was_taken_writes_nothing(tmp_path):
    import psycopg
    from vibe_audit import store as module
    url = postgres_url()
    store = Store(tmp_path, url)
    engine = Engine(store, url)
    other = psycopg.connect(url, autocommit=True)
    try:
        run = engine.create(RunInput(name="Taken over"))
        terminate(url, lock_session(url))
        # Another process started meanwhile and holds the lock now.
        assert other.execute("SELECT pg_try_advisory_lock(%s)", (module.CONTROLLER_LOCK_KEY,)).fetchone()[0]
        run["name"] = "must not be written"
        with pytest.raises(ControllerBusy, match="already controls this database"):
            store.save(run)
        with pytest.raises(ControllerBusy):
            store.update_job("job", "sent", {})
        assert store.get(run["id"])["name"] == "Taken over"
    finally:
        other.close()
        store.close()
