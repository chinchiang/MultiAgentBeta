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


def held_in_thread(store, monkeypatch, request, name, fails=None):
    """The store's method name, made to wait in its thread until the test lets it go (and then raise fails, if
    given); returns the event it waits on and the one it sets once it has started. A test that fails first still lets
    the thread go, so it does not write later through a closed store."""
    import threading
    work, release, started = getattr(store, name), threading.Event(), threading.Event()
    request.addfinalizer(release.set)
    def held(*args):
        started.set()
        assert release.wait(5)
        if fails is not None:
            raise fails
        return work(*args)
    monkeypatch.setattr(store, name, held)
    return release, started


async def in_thread(started):
    import asyncio
    while not started.is_set():
        await asyncio.sleep(0.01)


CONFLICT = "The run was changed by another action since this copy was read; reload it and try again"


async def test_a_save_cancelled_in_its_thread_waits_for_it_and_keeps_the_version_it_wrote(store, monkeypatch, request):
    import asyncio
    run = new_run()
    store.save(run)
    release, started = held_in_thread(store, monkeypatch, request, "write")
    run["name"] = "first"
    first = asyncio.create_task(store.persist(run))
    await in_thread(started)
    first.cancel()
    await asyncio.sleep(0.05)
    # Cancelled, it still holds the run's turn while its thread writes: the next save waits instead of overlapping it.
    assert not first.done()
    # The next save writes at once, so only the turn can hold it back.
    monkeypatch.delattr(store, "write")
    run["name"] = "second"
    second = asyncio.create_task(store.persist(run))
    await asyncio.sleep(0.05)
    assert not second.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await first
    # The copy learned the version its cancelled save wrote, so its next save is no conflict.
    await second
    assert store.get(run["id"])["name"] == "second" and run["version"] == 3 == body(store, run["id"])[1]


async def test_a_save_cancelled_again_while_it_waits_still_waits_for_its_thread(store, monkeypatch, request):
    import asyncio
    run = new_run()
    store.save(run)
    release, started = held_in_thread(store, monkeypatch, request, "write")
    saving = asyncio.create_task(store.persist(run))
    await in_thread(started)
    saving.cancel()
    await asyncio.sleep(0.01)
    saving.cancel()
    await asyncio.sleep(0.05)
    assert not saving.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await saving
    assert run["version"] == 2 == body(store, run["id"])[1]


def test_a_save_still_writing_when_its_loop_closes_keeps_the_version_it_wrote(store, monkeypatch, request):
    import asyncio
    import threading
    run = new_run()
    store.save(run)
    release, started = held_in_thread(store, monkeypatch, request, "write")
    saves = []
    async def leave_it_saving():
        saves.append(asyncio.create_task(store.persist(run)))
        await asyncio.to_thread(started.wait, 5)
        # The loop closes with the save in its thread: closing cancels every task the loop still has.
        threading.Timer(0.1, release.set).start()
    asyncio.run(leave_it_saving())
    assert saves[0].cancelled()
    assert run["version"] == 2 == body(store, run["id"])[1]


async def test_a_cancelled_save_whose_write_fails_ends_in_the_cancellation_and_logs_the_failure(store, monkeypatch, request, caplog):
    import asyncio
    import logging
    run = new_run()
    store.save(run)
    release, started = held_in_thread(store, monkeypatch, request, "write", fails=RunConflict(CONFLICT))
    saving = asyncio.create_task(store.persist(run))
    await in_thread(started)
    saving.cancel()
    release.set()
    # The caller asked to stop, so that is what it gets; the copy keeps the version it had, and the failure is logged.
    with caplog.at_level(logging.WARNING, logger="vibe_audit"), pytest.raises(asyncio.CancelledError):
        await saving
    assert [record.getMessage().split(" at ")[0] for record in caplog.records] == [f"run {run['id']} save cancelled: RunConflict"]
    assert run["version"] == 1 == body(store, run["id"])[1]
    monkeypatch.delattr(store, "write")
    await store.persist(run)
    assert run["version"] == 2


async def test_a_finish_cancelled_in_its_thread_keeps_the_version_it_wrote(store, monkeypatch, request):
    import asyncio
    run = new_run()
    store.save(run)
    release, started = held_in_thread(store, monkeypatch, request, "_finish")
    finishing = asyncio.create_task(store.finish("job-" + uuid.uuid4().hex, {"status": "finished"}, run))
    await in_thread(started)
    finishing.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await finishing
    assert run["version"] == 2 == body(store, run["id"])[1]
    await store.persist(run)
    assert run["version"] == 3


@pytest.mark.parametrize("outcome", ["lands", "fails", "overtaken"])
async def test_a_final_save_cancelled_in_its_thread_keeps_the_final_state_only_if_it_can_still_be_stored(tmp_path, monkeypatch, request, outcome):
    import asyncio
    store = Store(tmp_path)
    engine = Engine(store)
    try:
        run = engine.create(RunInput(name="Cancelled final save"))
        before = run["version"]
        run["status"] = "completed"
        fails = {"lands": None, "fails": RuntimeError("database unreachable"), "overtaken": RunConflict(CONFLICT)}[outcome]
        release, started = held_in_thread(store, monkeypatch, request, "write", fails=fails)
        saving = asyncio.create_task(engine.save_final(run))
        await in_thread(started)
        saving.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await saving
        if outcome == "lands":
            # Stored: nothing is left for flush_unsaved.
            assert run["id"] not in engine.unsaved and run["version"] == before + 1 and store.get(run["id"])["status"] == "completed"
        elif outcome == "overtaken":
            # Another save overtook the copy: no flush could ever store it, so none is kept.
            assert run["id"] not in engine.unsaved and run["version"] == before
        else:
            # Not stored: the final state stays in memory, and the next flush stores it.
            assert engine.unsaved[run["id"]] is run and run["version"] == before
            monkeypatch.delattr(store, "write")
            assert engine.flush_unsaved(run["id"]) is True and store.get(run["id"])["status"] == "completed"
    finally:
        store.close()


async def test_a_final_save_cancelled_while_it_settles_waits_for_the_settling_and_then_saves(tmp_path, monkeypatch, request):
    import asyncio
    import threading
    store = Store(tmp_path)
    engine = Engine(store)
    release, started, order = threading.Event(), threading.Event(), []
    request.addfinalizer(release.set)
    try:
        run = engine.create(RunInput(name="Cancelled while settling"))
        run["status"] = "completed"
        def settling(copy, reason):
            started.set()
            assert release.wait(5)
            order.append("settled")
        write = store.write
        def writing(copy, text):
            order.append("saved")
            return write(copy, text)
        monkeypatch.setattr(engine, "settle_sent_jobs", settling)
        monkeypatch.setattr(store, "write", writing)
        saving = asyncio.create_task(engine.save_final(run, settle=True))
        await in_thread(started)
        saving.cancel()
        await asyncio.sleep(0.05)
        # The settling still writes this copy: nothing is decided, and nothing else saves it, until it has ended.
        assert not saving.done() and order == []
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await saving
        # Then the save is tried once more and lands, so no final state is left for a flush to settle a second time.
        assert order == ["settled", "saved"] and run["id"] not in engine.unsaved and store.get(run["id"])["status"] == "completed"
    finally:
        store.close()


async def test_a_final_save_cancelled_between_its_tries_keeps_the_final_state(tmp_path, monkeypatch):
    import asyncio
    from vibe_audit import service
    store = Store(tmp_path)
    engine = Engine(store)
    try:
        run = engine.create(RunInput(name="Cancelled between tries"))
        run["status"] = "completed"
        tries = []
        def unreachable(copy, text):
            tries.append(text)
            raise RuntimeError("database unreachable")
        monkeypatch.setattr(store, "write", unreachable)
        monkeypatch.setattr(service, "FINAL_SAVE_RETRY_SECONDS", (30,))
        saving = asyncio.create_task(engine.save_final(run))
        while not tries:
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        # Waiting out the retry delay when it is stopped.
        saving.cancel()
        with pytest.raises(asyncio.CancelledError):
            await saving
        assert len(tries) == 1 and engine.unsaved[run["id"]] is run
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


async def finished_parent_and_retest(engine):
    parent = engine.create(RunInput(name="Parent"))
    engine.start(parent["id"])
    await engine.tasks[parent["id"]]
    observed = next(f for f in engine.store.get(parent["id"])["findings"] if f["state"] == "validated_dynamic")
    retest = engine.create(RunInput(name="Retest", mode="demo", parent_run_id=parent["id"], parent_finding_ids=[observed["id"]]))
    engine.start(retest["id"])
    await engine.tasks[retest["id"]]
    finished = engine.store.get(retest["id"])
    return parent, observed, {**finished, "id": "second-retest", "executions": [{**e, "status": "pass"} for e in finished["executions"]]}


async def test_a_write_back_that_finds_the_parent_started_meanwhile_leaves_it_alone(tmp_path, monkeypatch):
    store = Store(tmp_path)
    engine = Engine(store)
    try:
        parent, observed, second = await finished_parent_and_retest(engine)
        get = store.get
        def resumed(run_id):
            copy = get(run_id)
            if run_id == parent["id"] and copy["status"] != "running":
                # The parent is resumed between the write-back's read and its save.
                other = get(run_id)
                other["status"] = "running"
                store.save(other)
            return copy
        monkeypatch.setattr(store, "get", resumed)
        engine.record_retest(second)
        monkeypatch.setattr(store, "get", get)
        after = store.get(parent["id"])
        # The running parent is not written: its attempt's copy stays the newest one.
        assert after["status"] == "running" and not any(r.get("run_id") == "second-retest" for f in after["findings"] for r in f.get("retests", []))
        assert any("parent assessment was running" in gap for gap in second["gaps"])
    finally:
        store.close()


async def test_a_final_state_another_save_overtook_is_dropped_not_kept_for_ever(tmp_path):
    store = Store(tmp_path)
    engine = Engine(store)
    try:
        run = engine.create(RunInput(name="Overtaken final state"))
        run["status"] = "running"
        store.save(run)
        other = store.get(run["id"])
        other["name"] = "renamed"
        store.save(other)
        run["status"] = "completed"
        # The last save of the overtaken copy is refused once; it is not kept for a retry that can never land.
        await engine.save_final(run)
        assert run["id"] not in engine.unsaved
        # One kept from before is dropped by the next recover, which then closes the stored run as interrupted.
        engine.unsaved[run["id"]] = run
        engine.recover(run["id"])
        stored = store.get(run["id"])
        assert run["id"] not in engine.unsaved and stored["status"] == "incomplete" and stored["name"] == "renamed"
    finally:
        store.close()


async def test_a_run_whose_start_is_being_prepared_is_left_alone(tmp_path):
    import asyncio
    import threading
    from vibe_audit.policy import PolicyError
    store = Store(tmp_path)
    engine = Engine(store)
    try:
        run = engine.create(RunInput(name="Starting"))
        saved, release = threading.Event(), threading.Event()
        prepare = engine.prepare_start
        def slow(run_id, *args):
            prepared = prepare(run_id, *args)
            saved.set()
            release.wait(10)
            return prepared
        starting = asyncio.create_task(engine.begin(slow, run["id"]))
        await asyncio.to_thread(saved.wait, 10)
        # Stored as running, not registered yet: another request's recover must not close it as interrupted.
        assert store.get(run["id"])["status"] == "running"
        await asyncio.to_thread(engine.recover, run["id"])
        assert store.get(run["id"])["status"] == "running"
        with pytest.raises(PolicyError, match="already executing"):
            await engine.begin(engine.prepare_start, run["id"], True)
        with pytest.raises(PolicyError, match="starting"):
            await engine.stop(run["id"])
        release.set()
        await starting
        await engine.tasks[run["id"]]
        assert store.get(run["id"])["stage"] == "complete" and run["id"] not in engine.starting
    finally:
        store.close()


async def test_a_cancel_during_the_write_back_still_cancels_the_retest(tmp_path, monkeypatch):
    store = Store(tmp_path)
    engine = Engine(store)
    try:
        parent = engine.create(RunInput(name="Parent"))
        engine.start(parent["id"])
        await engine.tasks[parent["id"]]
        observed = next(f for f in store.get(parent["id"])["findings"] if f["state"] == "validated_dynamic")
        retest = engine.create(RunInput(name="Retest", mode="demo", parent_run_id=parent["id"], parent_finding_ids=[observed["id"]]))
        record = engine.record_retest
        def cancelled_meanwhile(run):
            # The cancel lands while the write-back runs in its thread.
            engine.cancel_flags[run["id"]].set()
            return record(run)
        monkeypatch.setattr(engine, "record_retest", cancelled_meanwhile)
        engine.start(retest["id"])
        await engine.tasks[retest["id"]]
        assert store.get(retest["id"])["status"] == "cancelled"
    finally:
        store.close()


def test_the_copy_is_held_only_while_its_save_is_uncertain(store, monkeypatch):
    run = new_run()
    store.save(run)
    # Committed: the version alone decides, and the store keeps no reference to the copy.
    assert run["id"] not in store.writers
    execute = store._execute
    def commit_then_fail(sql, args=()):
        result = execute(sql, args)
        if sql == "COMMIT":
            raise OSError("synthetic: reply lost")
        return result
    monkeypatch.setattr(store, "_execute", commit_then_fail)
    with pytest.raises(OSError):
        store.save(run)
    monkeypatch.setattr(store, "_execute", execute)
    # Uncertain: the copy itself is held, so no other object can be taken for it.
    assert store.writers[run["id"]][0] is run
    store.save(run)
    assert run["id"] not in store.writers


def test_a_column_another_process_added_first_is_not_an_error(tmp_path, monkeypatch):
    conn = sqlite3.connect(str(tmp_path / "demo.sqlite3"))
    conn.execute("CREATE TABLE runs (id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated TEXT NOT NULL)")
    conn.commit()
    conn.close()
    execute = Store._execute
    def raced(self, sql, args=()):
        if sql.startswith("ALTER TABLE runs ADD COLUMN"):
            # The other process's ALTER lands first; this one then fails on the duplicate column.
            execute(self, sql, args)
        return execute(self, sql, args)
    monkeypatch.setattr(Store, "_execute", raced)
    store = Store(tmp_path)
    try:
        assert {"version", "writer"} <= store._run_columns()
    finally:
        store.close()


def test_a_sqlite_without_returning_is_refused_with_a_reason(tmp_path, monkeypatch):
    from vibe_audit import store as store_module
    monkeypatch.setattr(store_module.sqlite3, "sqlite_version_info", (3, 34, 1))
    with pytest.raises(RuntimeError, match="older than 3.35"):
        Store(tmp_path)


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
