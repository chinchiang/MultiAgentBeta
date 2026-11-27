"""A run's row carries a version: a save from a copy that another save overtook writes nothing and raises RunConflict.

The PostgreSQL cases need VIBEAUDIT_TEST_DATABASE_URL; without it they skip."""
import json
import os
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from vibe_audit.api import create_app
from vibe_audit.domain import RunInput
from vibe_audit.service import Engine
from vibe_audit.store import RunConflict, Store, placeholders


@pytest.fixture(autouse=True)
def private_store(monkeypatch):
    monkeypatch.delenv("VIBEAUDIT_DATABASE_URL", raising=False)


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    url = os.getenv("VIBEAUDIT_TEST_DATABASE_URL") if request.param == "postgres" else None
    if request.param == "postgres" and not url:
        pytest.skip("Provide dedicated PostgreSQL integration database")
    value = Store(tmp_path, url)
    yield value
    value.close()


def event(seq):
    return {"seq": seq, "at": f"2026-11-27T00:00:0{seq}Z", "stage": "intake", "message": f"Event {seq}", "level": "info", "agent_id": None}


def new_run(name="versions"):
    return {"id": "run-" + uuid.uuid4().hex, "name": name, "mode": "demo", "status": "created", "stage": "intake",
            "created_at": "2026-11-27T00:00:00Z", "updated_at": "", "manifest": {"name": name, "mode": "demo", "parent_run_id": None},
            "events": [], "usage": {"requests": 0}, "error": None}


def body(store, run_id):
    payload, version = store._execute(placeholders("SELECT payload,version FROM runs WHERE id=?", store.postgres), (run_id,)).fetchone()
    return json.loads(payload), version


def test_each_save_counts_a_version_that_the_body_never_carries(store):
    run = new_run()
    store.save(run)
    assert run["version"] == 1 and store.get(run["id"])["version"] == 1
    store.save(run)
    store.save(run)
    assert run["version"] == 3 and store.get(run["id"])["version"] == 3
    stored, version = body(store, run["id"])
    assert version == 3 and "version" not in stored
    assert next(r for r in store.list() if r["id"] == run["id"])["version"] == 3


def test_a_copy_another_save_overtook_writes_nothing(store):
    run = new_run()
    store.save(run)
    first, second = store.get(run["id"]), store.get(run["id"])
    first["name"] = "first"
    store.save(first)
    second["name"] = "second"
    second["events"].append(event(1))
    with pytest.raises(RunConflict, match="changed by another action"):
        store.save(second)
    # Nothing of the stale copy was stored: neither its body nor its event, and its version is the one it read.
    assert store.get(run["id"])["name"] == "first" and store.get(run["id"])["events"] == [] and second["version"] == 1
    # The copy that won keeps saving; a copy read after it saves too.
    store.save(first)
    fresh = store.get(run["id"])
    fresh["name"] = "fresh"
    store.save(fresh)
    assert store.get(run["id"])["name"] == "fresh" and store.get(run["id"])["version"] == 4
    # A new copy of a run that is already stored is a conflict as well, not a second insert.
    with pytest.raises(RunConflict):
        store.save({**new_run(), "id": run["id"]})


def test_a_save_whose_reply_was_lost_still_belongs_to_its_copy(store, monkeypatch):
    run = new_run()
    store.save(run)
    stale = store.get(run["id"])
    execute = store._execute
    def commit_then_fail(sql, args=()):
        result = execute(sql, args)
        if sql == "COMMIT":
            raise OSError("synthetic: the commit landed but its reply was lost")
        return result
    monkeypatch.setattr(store, "_execute", commit_then_fail)
    run["name"] = "landed"
    with pytest.raises(OSError):
        store.save(run)
    monkeypatch.setattr(store, "_execute", execute)
    # The copy cannot tell whether its save landed; it did, and the copy that sent it may write again.
    assert body(store, run["id"])[1] == 2 and run["version"] == 1
    run["name"] = "again"
    store.save(run)
    assert store.get(run["id"])["name"] == "again" and run["version"] == 3
    # A copy read before that save did not see it.
    with pytest.raises(RunConflict):
        store.save(stale)


def test_a_rolled_back_save_leaves_the_copy_at_the_version_the_row_kept(store, monkeypatch):
    run = new_run()
    store.save(run)
    other = store.get(run["id"])
    other["name"] = "other"
    store.save(other)
    fresh = store.get(run["id"])
    execute = store._execute
    def fail_after_row(sql, args=()):
        if sql.startswith("INSERT INTO events"):
            raise RuntimeError("synthetic failure after the run row")
        return execute(sql, args)
    monkeypatch.setattr(store, "_execute", fail_after_row)
    fresh["events"].append(event(1))
    with pytest.raises(RuntimeError):
        store.save(fresh)
    monkeypatch.setattr(store, "_execute", execute)
    # The row kept version 2 and the other copy's name; the copy that rolled back is at version 2 again and may save.
    assert fresh["version"] == 2 and store.get(run["id"])["name"] == "other"
    fresh["name"] = "after rollback"
    store.save(fresh)
    assert store.get(run["id"])["name"] == "after rollback"


async def test_saves_from_the_event_loop_take_turns_so_a_later_snapshot_stands(store, monkeypatch):
    import asyncio
    import time
    run = new_run()
    store.save(run)
    write = store.write
    order = []
    def first_slow(copy, text):
        name = json.loads(text)["name"]
        if name == "first":
            # A thread that happens to finish late: without turns, its older snapshot would land last.
            time.sleep(0.3)
        order.append(name)
        return write(copy, text)
    monkeypatch.setattr(store, "write", first_slow)
    run["name"] = "first"
    earlier = asyncio.create_task(store.persist(run))
    await asyncio.sleep(0)
    run["name"] = "second"
    later = asyncio.create_task(store.persist(run))
    await asyncio.gather(earlier, later)
    assert order == ["first", "second"]
    assert store.get(run["id"])["name"] == "second" and run["version"] == 3 == store.get(run["id"])["version"]


def test_one_store_serves_saves_from_one_event_loop_after_another(tmp_path):
    import asyncio
    store = Store(tmp_path)
    try:
        run = new_run()
        store.save(run)
        async def two_at_once():
            # Two saves at once: the second waits on the run's lock, which ties that lock to this loop.
            await asyncio.gather(store.persist(run), store.persist(run))
        asyncio.run(two_at_once())
        asyncio.run(two_at_once())
        assert store.get(run["id"])["version"] == 5
    finally:
        store.close()


def test_a_runs_table_from_before_versions_gains_them(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "demo.sqlite3"))
    conn.execute("CREATE TABLE runs (id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated TEXT NOT NULL)")
    legacy = new_run("legacy")
    conn.execute("INSERT INTO runs VALUES (?,?,?)", (legacy["id"], json.dumps(legacy), "2026-11-27T00:00:00Z"))
    conn.commit()
    conn.close()
    store = Store(tmp_path)
    try:
        run = store.get(legacy["id"])
        assert run["version"] == 0
        store.save(run)
        assert store.get(legacy["id"])["version"] == 1
        # Opening it again finds the columns there and adds nothing.
        Store(tmp_path).close()
    finally:
        store.close()


async def test_a_retest_write_back_overtaken_by_a_decision_reads_the_parent_again(tmp_path, monkeypatch):
    store = Store(tmp_path)
    engine = Engine(store)
    try:
        parent = engine.create(RunInput(name="Parent"))
        engine.start(parent["id"])
        await engine.tasks[parent["id"]]
        observed = next(f for f in store.get(parent["id"])["findings"] if f["state"] == "validated_dynamic")
        retest = engine.create(RunInput(name="Retest", mode="demo", parent_run_id=parent["id"], parent_finding_ids=[observed["id"]]))
        engine.start(retest["id"])
        await engine.tasks[retest["id"]]
        finished = store.get(retest["id"])
        second = {**finished, "id": "second-retest", "executions": [{**e, "status": "pass"} for e in finished["executions"]]}
        reads = []
        get = store.get
        def overtaken(run_id):
            copy = get(run_id)
            if run_id == parent["id"] and not reads:
                # Between the write-back's read and its save, an operator's change lands on the parent.
                other = get(run_id)
                other["name"] = "renamed by an operator"
                store.save(other)
            reads.append(run_id)
            return copy
        monkeypatch.setattr(store, "get", overtaken)
        engine.record_retest(second)
        monkeypatch.setattr(store, "get", get)
        after = store.get(parent["id"])
        # Both changes stand: the operator's, and the outcome applied again to the parent as it left it.
        assert reads.count(parent["id"]) == 2 and after["name"] == "renamed by an operator"
        assert next(f for f in after["findings"] if f["id"] == observed["id"])["state"] == "resolved_in_retest"
        assert after["events"][-1]["message"].startswith("Linked retest second-retest")
        assert [e["seq"] for e in after["events"]] == list(range(1, len(after["events"]) + 1))
    finally:
        store.close()


def test_an_action_on_an_overtaken_copy_is_a_conflict(tmp_path, monkeypatch):
    with TestClient(create_app(tmp_path, testing=True)) as client:
        from test_engine import authorize
        authorize(client)
        engine = client.app.state.engine
        run = engine.create(RunInput(name="Overtaken"))
        def overtaken(run_id):
            raise RunConflict("The run was changed by another action since this copy was read; reload it and try again")
        monkeypatch.setattr(engine, "recover", overtaken)
        response = client.post(f"/api/runs/{run['id']}/cancel")
        assert response.status_code == 409
        assert response.json()["detail_zh"] == "讀取這份執行之後，另一個操作已經改過它；請重新載入後再試一次"
