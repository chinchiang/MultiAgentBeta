"""Worker leases on both backends: SQLite under a test clock, and PostgreSQL (its own clock and row locks) when
VIBEAUDIT_TEST_DATABASE_URL names a server; each PostgreSQL test gets a database of its own."""
import copy
from concurrent.futures import ThreadPoolExecutor
import os
import time
import uuid
import pytest
import threading
from unittest.mock import patch
from vibe_audit.lease import LeaseStore,LeaseError,canonical_hash,placeholders


class Backend:
    """One lease database for one test. open() connects to it again; advance() moves its clock forward."""
    def __init__(self,kind,tmp_path):
        self.kind=kind
        if kind=="sqlite":
            self.clock=[100.0];self.path=tmp_path/"lease.sqlite3";return
        service=os.getenv("VIBEAUDIT_TEST_DATABASE_URL")
        if not service:pytest.skip("Real PostgreSQL test service not configured")
        import psycopg
        self.service,self.name=service,"lease_test_"+uuid.uuid4().hex
        with psycopg.connect(service,autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{self.name}" TEMPLATE template0 ENCODING \'UTF8\'')
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        self.url=make_conninfo(**(conninfo_to_dict(service)|{"dbname":self.name}))

    def open(self):
        if self.kind=="sqlite":return LeaseStore(self.path,clock=lambda:self.clock[0])
        return LeaseStore(database_url=self.url)

    def advance(self,seconds):
        if self.kind=="sqlite":self.clock[0]+=seconds
        else:time.sleep(seconds)

    def close(self):
        if self.kind=="postgres":
            import psycopg
            with psycopg.connect(self.service,autocommit=True) as conn:
                conn.execute(f'DROP DATABASE "{self.name}" WITH (FORCE)')


@pytest.fixture(params=["sqlite","postgres"])
def leases(request,tmp_path):
    db=Backend(request.param,tmp_path)
    store=db.open()
    yield store,db
    store.close()
    db.close()


def issue(store,**kwargs):
    args=dict(run_id=uuid.uuid4().hex,case_hash="case",threat_hash="threat",manifest_hash="manifest",max_requests=2,ttl_seconds=2,max_seconds=10)
    args.update(kwargs)
    return store.issue(**args)


def test_bound_capability_is_single_claim_and_secrets_not_persisted(leases):
    store,_=leases;cap=issue(store)
    altered=copy.deepcopy(cap);altered["binding"]["case_hash"]="other"
    with pytest.raises(LeaseError,match="^Worker capability identity or binding mismatch$"):store.claim(altered,"worker")
    bad=copy.deepcopy(cap);bad["token"]="wrong"
    with pytest.raises(LeaseError,match="^Worker capability identity or binding mismatch$"):store.claim(bad,"worker")
    store.claim(cap,"worker")
    with pytest.raises(LeaseError):store.claim(cap,"worker")
    with pytest.raises(LeaseError):store.validate(cap,"other")
    stored=str(store._sql(placeholders("SELECT * FROM worker_leases WHERE id=?",store.postgres),(cap["id"],)).fetchall())
    assert cap["token"] not in stored and cap["renewal_token"] not in stored


def test_expiry_cannot_be_resurrected_and_renewal_is_controller_only(leases):
    store,db=leases;cap=issue(store,ttl_seconds=0.5);store.claim(cap,"worker")
    worker_cap={k:v for k,v in cap.items() if k!="renewal_token"}
    with pytest.raises(LeaseError,match="^Only the controller can renew a lease$"):store.renew(worker_cap)
    db.advance(0.1)
    before=store._now();expires=store.renew(cap)
    assert before+0.5<=expires<=store._now()+0.5
    assert store.validate(cap,"worker")["expires"]==expires
    db.advance(0.6)
    with pytest.raises(LeaseError):store.renew(cap)
    with pytest.raises(LeaseError):store.validate(cap,"worker")
    assert store.expire()==[cap["id"]]
    assert store.expire()==[]
    assert store.task(cap["task_id"])["state"]=="outcome_unknown"


def test_renewal_never_outlives_the_deadline(leases):
    store,db=leases;cap=issue(store,ttl_seconds=0.5,max_seconds=0.5);store.claim(cap,"worker")
    deadline=store.validate(cap,"worker")["deadline"]
    db.advance(0.2)
    assert store.renew(cap)==deadline
    db.advance(0.4)
    with pytest.raises(LeaseError):store.validate(cap,"worker")
    assert store.expire()==[cap["id"]]


def test_dispatch_budget_is_atomic_and_request_ids_cannot_replay(leases):
    store,_=leases;cap=issue(store,max_requests=1);store.claim(cap,"worker")
    store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    assert store.task(cap["task_id"])["state"]=="sent"
    with pytest.raises(LeaseError):store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    with pytest.raises(LeaseError):store.reserve_dispatch(cap,"worker","request-2",{"path":"/a"})
    assert store.validate(cap,"worker")["used_requests"]==1
    with pytest.raises(LeaseError):store.finish_task(cap,"worker",{"status":"pass"})
    store.finish_dispatch(cap,"worker","request-1",{"path":"/a"},{"status_code":200})
    store.finish_task(cap,"worker",{"status":"pass"})
    assert store.task(cap["task_id"])["state"]=="finished"
    binding=cap["binding"]
    with pytest.raises(LeaseError):
        store.issue(**binding,max_requests=1,ttl_seconds=2,max_seconds=10)


def test_finish_dispatch_must_match_the_journaled_request(leases):
    store,_=leases;cap=issue(store);store.claim(cap,"worker")
    store.reserve_dispatch(cap,"worker","request-1",{"path":"/a","method":"GET"})
    # A result may only be journaled for the exact request that was reserved.
    with pytest.raises(LeaseError):store.finish_dispatch(cap,"worker","request-1",{"path":"/b","method":"GET"},{"status_code":200})
    with pytest.raises(LeaseError):store.finish_dispatch(cap,"worker","request-1",{"path":"/a","method":"POST"},{"status_code":200})
    dispatch=lambda:store._sql(placeholders("SELECT state,result_hash FROM worker_dispatches WHERE task_id=?",store.postgres),(cap["task_id"],)).fetchone()
    assert dispatch()==("sent",None)
    store.finish_dispatch(cap,"worker","request-1",{"path":"/a","method":"GET"},{"status_code":200})
    assert dispatch()==("finished",canonical_hash({"status_code":200}))


def test_a_lease_that_cannot_dispatch_is_invalid(leases):
    store,_=leases
    with pytest.raises(LeaseError):issue(store,max_requests=0)
    with pytest.raises(LeaseError):issue(store,max_requests=-1)


def test_revoke_persists_unknown_dispatch_across_connections(leases):
    store,db=leases;cap=issue(store);store.claim(cap,"worker")
    store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    store.revoke(cap["id"],"Controller died")
    second=db.open()
    try:
        assert second.task(cap["task_id"])["state"]=="outcome_unknown"
        assert second._sql(placeholders("SELECT state FROM worker_dispatches WHERE task_id=?",second.postgres),(cap["task_id"],)).fetchone()[0]=="outcome_unknown"
        with pytest.raises(LeaseError):second.claim(cap,"replacement")
    finally:second.close()


def test_separate_connections_cannot_both_claim(leases):
    store,db=leases;cap=issue(store,max_requests=1)
    def claim(worker):
        other=db.open()
        try:
            other.claim(cap,worker);return worker
        except LeaseError:return None
        finally:other.close()
    with ThreadPoolExecutor(2) as pool:
        winners=[w for w in pool.map(claim,["worker-a","worker-b"]) if w]
    assert len(winners)==1
    # The journal written by the winner's connection is what every other connection sees.
    store.reserve_dispatch(cap,winners[0],"one",{"path":"/authorized"})
    with pytest.raises(LeaseError):store.reserve_dispatch(cap,winners[0],"two",{"path":"/authorized"})
    store.revoke(cap["id"],"Synthetic controller crash")
    assert db.open().task(cap["task_id"])["state"]=="outcome_unknown"


# MULE_INTERNAL has no Python codec: psycopg raises NotSupportedError when asked for the connection's Python encoding.
@pytest.mark.parametrize("server,client",[("SQL_ASCII","SQL_ASCII"),("UTF8","SQL_ASCII"),("SQL_ASCII","UTF8"),("UTF8","MULE_INTERNAL")])
def test_postgres_lease_store_refuses_a_non_utf8_database(monkeypatch,server,client):
    import psycopg
    closed=[]
    class Info:
        @property
        def encoding(self):
            if client=="MULE_INTERNAL":raise psycopg.NotSupportedError("codec not available in Python: 'MULE_INTERNAL'")
            return {"UTF8":"utf-8","SQL_ASCII":"ascii"}[client]
        @staticmethod
        def parameter_status(name):return {"server_encoding":server,"client_encoding":client}.get(name)
    class Conn:
        info=Info()
        def close(self):closed.append(True)
        def execute(self,*_):raise AssertionError("No statement may run on a non-UTF8 database")
    monkeypatch.setattr(psycopg,"connect",lambda *a,**k:Conn())
    with pytest.raises(LeaseError,match="^The PostgreSQL lease database and connection must use UTF8 encoding$"):
        LeaseStore(database_url="postgresql://synthetic/db")
    assert closed==[True]


def test_finished_result_returns_only_the_journaled_result_of_a_finished_task(leases):
    store,_=leases;cap=issue(store);binding=cap["binding"]
    lookup={k:binding[k] for k in ("run_id","case_hash","threat_hash","manifest_hash","operation","repetition")}
    assert store.finished_result(**lookup) is None
    store.claim(cap,"worker")
    store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    assert store.finished_result(**lookup) is None
    store.finish_dispatch(cap,"worker","request-1",{"path":"/a"},{"status_code":200})
    store.finish_task(cap,"worker",{"status":"pass","reason":"held"})
    assert store.finished_result(**lookup)=={"status":"pass","reason":"held"}
    assert store.task(cap["task_id"])["payload"]=={"binding":binding,"result":{"status":"pass","reason":"held"}}
    # The recipe hash is not part of the task's identity: a changed recipe still finds the paid result.
    assert store.finished_result(**lookup,spec_hash="another-recipe")=={"status":"pass","reason":"held"}
    for key,other in [("repetition",1),("run_id","other-run"),("case_hash","other"),("threat_hash","other"),("manifest_hash","other"),("operation","ai_http")]:
        assert store.finished_result(**{**lookup,key:other}) is None
    with pytest.raises(LeaseError,match="^Complete immutable capability bindings are required$"):
        store.finished_result(**{**lookup,"run_id":""})
    with pytest.raises(LeaseError,match="^Complete immutable capability bindings are required$"):
        store.finished_result(**{**lookup,"case_hash":None})
    # Only a dict result is a usable journal entry.
    other=issue(store,run_id=binding["run_id"],repetition=1);store.claim(other,"worker");store.finish_task(other,"worker",["not","a","result"])
    assert store.task(other["task_id"])["state"]=="finished" and store.finished_result(**{**lookup,"repetition":1}) is None


def test_task_records_and_revocation_reasons(leases):
    store,db=leases;cap=issue(store)
    assert store.task(cap["task_id"])=={"id":cap["task_id"],"key":store._idempotency_key(cap["binding"]),"lease_id":cap["id"],"state":"prepared","payload":{"binding":cap["binding"]}}
    with pytest.raises(LeaseError,match="^Worker task not found$"):store.task("missing")
    store.revoke(cap["id"])
    assert store.task(cap["task_id"])["payload"]=={"binding":cap["binding"],"reason":"revoked"}
    long_reason=issue(store,repetition=1);store.revoke(long_reason["id"],"x"*200)
    assert store.task(long_reason["task_id"])["payload"]["reason"]=="x"*160
    expiring=issue(store,repetition=2,ttl_seconds=0.3);db.advance(0.4)
    assert store.expire()==[expiring["id"]]
    assert store.task(expiring["task_id"])["payload"]["reason"]=="Lease expired; external task must be reconciled"
    finished=issue(store,repetition=3);store.claim(finished,"worker");store.finish_task(finished,"worker",{"status":"pass"})
    store.revoke(finished["id"],"too late")
    assert store.task(finished["task_id"])["state"]=="finished" and store._row(finished["id"])["state"]=="finished"


def test_lease_errors_name_their_cause(leases):
    store,_=leases;cap=issue(store,max_requests=1)
    with pytest.raises(LeaseError,match="^Worker identity is required$"):store.claim(cap,"")
    store.claim(cap,"worker")
    with pytest.raises(LeaseError,match="^Worker capability has already been claimed$"):store.claim(cap,"worker")
    with pytest.raises(LeaseError,match="^Capability is claimed by another worker$"):store.validate(cap,"other")
    with pytest.raises(LeaseError,match="^A unique request ID is required$"):store.reserve_dispatch(cap,"worker","",{"path":"/a"})
    store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    with pytest.raises(LeaseError,match="^Request ID already journaled; dispatch cannot be replayed$"):store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    with pytest.raises(LeaseError,match="^Worker request budget exhausted$"):store.reserve_dispatch(cap,"worker","request-2",{"path":"/a"})
    with pytest.raises(LeaseError,match="^An external dispatch outcome remains unknown$"):store.finish_task(cap,"worker",{"status":"pass"})
    with pytest.raises(LeaseError,match="^Result does not match the journaled dispatch request$"):store.finish_dispatch(cap,"worker","request-1",{"path":"/b"},{})
    with pytest.raises(LeaseError,match="^Result does not match the journaled dispatch request$"):store.finish_dispatch(cap,"worker","request-9",{"path":"/a"},{})
    store.finish_dispatch(cap,"worker","request-1",{"path":"/a"},{"status_code":200})
    with pytest.raises(LeaseError,match="^Result does not match the journaled dispatch request$"):store.finish_dispatch(cap,"worker","request-1",{"path":"/a"},{"status_code":200})
    store.finish_task(cap,"worker",{"status":"pass"})
    with pytest.raises(LeaseError,match="^Worker capability revoked or expired$"):store.finish_task(cap,"worker",{"status":"pass"})
    with pytest.raises(LeaseError,match="^Worker lease not found$"):store.revoke("missing")
    with pytest.raises(LeaseError,match="^Invalid worker lease limits$"):issue(store,repetition=-1)
    with pytest.raises(LeaseError,match="^Task already exists; prepared/sent/finished/unknown tasks are never implicitly replayed$"):issue(store,run_id=cap["binding"]["run_id"])


def test_sql_table_holds_only_bound_placeholders_and_differs_by_dialect_alone():
    """Every statement is a constant: values are bound, never spliced, so a ? is always a placeholder and % never appears."""
    import re
    from vibe_audit import lease
    for name, text in lease.SQL.items():
        assert "%" not in text, name
        assert "?" not in "".join(re.findall(r"'[^']*'", text)), f"{name}: a ? inside quotes would be rewritten on PostgreSQL"
    for_sqlite, for_postgres = lease.dialect(lease.SQL, False), lease.dialect(lease.SQL, True)
    assert for_sqlite == lease.SQL and for_sqlite is not lease.SQL
    assert set(for_postgres) == set(lease.SQL)
    assert all("?" not in text and text.count("%s") == lease.SQL[name].count("?") for name, text in for_postgres.items())
    assert placeholders("UPDATE t SET a=? WHERE b=?", True) == "UPDATE t SET a=%s WHERE b=%s"
    assert placeholders("UPDATE t SET a=? WHERE b=?", False) == "UPDATE t SET a=? WHERE b=?"


def test_lease_store_keeps_the_statements_of_its_own_dialect(leases):
    """A store converts the table once, for the backend it was given, and keeps where it connected."""
    from vibe_audit import lease
    store,backend=leases
    assert store.postgres is (backend.kind=="postgres")
    assert store.sql==lease.dialect(lease.SQL,store.postgres)
    assert (store.database_url,store.database_path)==((backend.url,None) if store.postgres else (None,str(backend.path)))
    assert all(store.sql[name].count("%s" if store.postgres else "?")==lease.SQL[name].count("?") for name in lease.SQL)


def test_issue_checks_every_limit_at_its_boundary(leases):
    store,_=leases
    for n,kwargs in enumerate([dict(max_requests=10000),dict(ttl_seconds=0.1),dict(ttl_seconds=30,max_seconds=30),dict(max_seconds=14400),dict(ttl_seconds=5,max_seconds=5)]):
        cap=issue(store,repetition=n,**kwargs)
        assert set(cap)=={"id","task_id","token","renewal_token","binding","ttl_seconds","max_seconds","max_requests"}
        assert (cap["ttl_seconds"],cap["max_seconds"],cap["max_requests"])==(kwargs.get("ttl_seconds",2),kwargs.get("max_seconds",10),kwargs.get("max_requests",2))
        # token_urlsafe(32) is 43 characters; the two secrets are independent.
        assert len(cap["token"])==len(cap["renewal_token"])==43 and cap["token"]!=cap["renewal_token"]
    for kwargs in [dict(max_requests=10001),dict(max_requests=1.0),dict(ttl_seconds=0.09),dict(ttl_seconds=30.1,max_seconds=60),dict(max_seconds=14401),
                   dict(ttl_seconds=5,max_seconds=4.9),dict(repetition=1.0),dict(repetition=True),dict(repetition=-1)]:
        with pytest.raises(LeaseError,match="^Invalid worker lease limits$"):issue(store,**kwargs)
    for kwargs in [dict(run_id=5),dict(run_id=""),dict(case_hash=None),dict(threat_hash=b"x"),dict(manifest_hash=""),dict(operation=0)]:
        with pytest.raises(LeaseError,match="^Complete immutable capability bindings are required$"):issue(store,**kwargs)
    plain=store.issue(run_id=uuid.uuid4().hex,case_hash="case",threat_hash="threat",manifest_hash="manifest",max_requests=1)
    assert (plain["ttl_seconds"],plain["max_seconds"],plain["binding"]["operation"],plain["binding"]["repetition"])==(5,120,"http_case",0)
    # The recipe hash defaults to the case hash and is kept when given.
    assert issue(store,repetition=10)["binding"]["spec_hash"]=="case"
    recipe=issue(store,repetition=11,spec_hash="recipe")["binding"]
    assert recipe=={"run_id":recipe["run_id"],"case_hash":"case","threat_hash":"threat","manifest_hash":"manifest","operation":"http_case","repetition":11,"spec_hash":"recipe"}


def test_each_worker_action_checks_the_worker_the_lease_was_claimed_by(leases):
    store,_=leases;cap=issue(store)
    # Before a claim the lease is issued, not active: only claim and renew accept it.
    with pytest.raises(LeaseError,match="^Worker capability revoked or expired$"):store.validate(cap,"worker")
    with pytest.raises(LeaseError,match="^Worker capability revoked or expired$"):store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    assert store.renew(cap)>store._now()
    store.claim(cap,"worker")
    store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    with pytest.raises(LeaseError,match="^Capability is claimed by another worker$"):store.reserve_dispatch(cap,"other","request-2",{"path":"/a"})
    with pytest.raises(LeaseError,match="^Capability is claimed by another worker$"):store.finish_dispatch(cap,"other","request-1",{"path":"/a"},{})
    with pytest.raises(LeaseError,match="^Capability is claimed by another worker$"):store.finish_task(cap,"other",{"status":"pass"})
    assert store.validate(cap,"worker")["used_requests"]==1


def test_a_task_the_journal_no_longer_owns_cannot_dispatch(leases):
    store,_=leases
    def sent(**changes):
        cap=issue(store,**changes);store.claim(cap,"worker");return cap
    cap=sent()
    store._sql(placeholders("UPDATE worker_tasks SET state='finished' WHERE id=?",store.postgres),(cap["task_id"],))
    with pytest.raises(LeaseError,match="^External task is terminal or has a different lease$"):store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    with pytest.raises(LeaseError,match="^Task is already terminal$"):store.finish_task(cap,"worker",{"status":"pass"})
    other=sent(repetition=1)
    store._sql(placeholders("UPDATE worker_tasks SET lease_id='other' WHERE id=?",store.postgres),(other["task_id"],))
    with pytest.raises(LeaseError,match="^External task is terminal or has a different lease$"):store.reserve_dispatch(other,"worker","request-1",{"path":"/a"})
    gone=sent(repetition=2)
    store._sql(placeholders("DELETE FROM worker_tasks WHERE id=?",store.postgres),(gone["task_id"],))
    with pytest.raises(LeaseError,match="^External task is terminal or has a different lease$"):store.reserve_dispatch(gone,"worker","request-1",{"path":"/a"})
    # A dispatch the journal shows as sent but that no longer updates is reported, not silently finished.
    stuck=sent(repetition=3);store.reserve_dispatch(stuck,"worker","request-1",{"path":"/a"})
    with patch.dict(store.sql,{"finish_dispatch":placeholders("UPDATE worker_dispatches SET result_hash=? WHERE task_id=? AND request_id=? AND state='never'",store.postgres)}):
        with pytest.raises(LeaseError,match="^No pending dispatch matches this result$"):store.finish_dispatch(stuck,"worker","request-1",{"path":"/a"},{})


def test_a_lease_expires_at_its_expiry_instant(tmp_path):
    db=Backend("sqlite",tmp_path);store=db.open()
    try:
        cap=issue(store,ttl_seconds=2);store.claim(cap,"worker")
        db.clock[0]=102.0-1e-6
        assert store.validate(cap,"worker")["expires"]==102.0
        db.clock[0]=102.0
        with pytest.raises(LeaseError,match="^Worker capability revoked or expired$"):store.validate(cap,"worker")
    finally:store.close()


@pytest.mark.parametrize("action,message",[
    ("claim","Worker capability revoked or expired"),("validate","Worker capability revoked or expired"),("renew","Worker capability revoked or expired"),
    ("reserve_dispatch","Worker request budget exhausted"),("finish_dispatch","Worker capability revoked or expired"),("finish_task","Worker capability revoked or expired"),
    ("revoke",None),
])
def test_every_lease_action_reads_its_row_under_the_row_lock(tmp_path,action,message):
    """A change another connection commits while it holds the row is what the action sees, not the row it read before."""
    db=Backend("postgres",tmp_path);store=db.open()
    try:
        cap=issue(store,max_requests=1)
        if action!="claim":store.claim(cap,"worker")
        if action in ("finish_dispatch","finish_task"):store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
        calls={"claim":lambda:store.claim(cap,"worker"),"validate":lambda:store.validate(cap,"worker"),"renew":lambda:store.renew(cap),
               "reserve_dispatch":lambda:store.reserve_dispatch(cap,"worker","request-2",{"path":"/b"}),
               "finish_dispatch":lambda:store.finish_dispatch(cap,"worker","request-1",{"path":"/a"},{"status_code":200}),
               "finish_task":lambda:store.finish_task(cap,"worker",{"status":"pass"}),"revoke":lambda:store.revoke(cap["id"])}
        change={"reserve_dispatch":"UPDATE worker_leases SET used_requests=max_requests WHERE id=%s","revoke":"UPDATE worker_leases SET state='finished' WHERE id=%s"
                }.get(action,"UPDATE worker_leases SET state='revoked' WHERE id=%s")
        outcome=[]
        import psycopg
        with psycopg.connect(db.url) as holder:
            holder.execute("SELECT 1 FROM worker_leases WHERE id=%s FOR UPDATE",(cap["id"],))
            started=threading.Event()
            def act():
                started.set()
                try:outcome.append(calls[action]())
                except Exception as exc:outcome.append(exc)
            worker=threading.Thread(target=act);worker.start()
            started.wait();time.sleep(0.3)
            assert outcome==[], "the action must wait for the row lock"
            holder.execute(change,(cap["id"],));holder.commit()
        worker.join(5)
        if message is None:
            # Revoking a lease another connection just finished leaves it finished.
            assert outcome==[None] and store._row(cap["id"])["state"]=="finished"
        else:
            assert len(outcome)==1 and isinstance(outcome[0],LeaseError) and str(outcome[0])==message, outcome
    finally:
        store.close();db.close()


def test_connections_are_opened_with_the_parameters_the_journal_needs(tmp_path,monkeypatch):
    import sqlite3
    seen=[]
    real=sqlite3.connect
    monkeypatch.setattr(sqlite3,"connect",lambda *a,**k:seen.append((a,k)) or real(*a,**k))
    store=LeaseStore(tmp_path/"lease.sqlite3")
    try:
        assert seen==[((str(tmp_path/"lease.sqlite3"),),{"isolation_level":None,"check_same_thread":False,"timeout":10})]
        assert store.conn.execute("PRAGMA journal_mode").fetchone()[0]=="wal" and store.conn.execute("PRAGMA synchronous").fetchone()[0]==2
        with ThreadPoolExecutor(1) as pool:
            assert pool.submit(lambda:store.expire()).result()==[]
    finally:store.close()
    with pytest.raises(LeaseError,match="^A durable lease database is required$"):LeaseStore()
    with pytest.raises(LeaseError,match="^A durable lease database is required$"):LeaseStore("")
    service=os.getenv("VIBEAUDIT_TEST_DATABASE_URL")
    if not service:pytest.skip("Real PostgreSQL test service not configured")
    import psycopg
    seen.clear();real_pg=psycopg.connect
    monkeypatch.setattr(psycopg,"connect",lambda *a,**k:seen.append((a,k)) or real_pg(*a,**k))
    store=LeaseStore(database_url=service)
    try:
        assert seen==[((service,),{"autocommit":True,"connect_timeout":3,"options":"-c statement_timeout=2000 -c lock_timeout=1000"})]
        assert store.conn.autocommit and store.conn.execute("SHOW statement_timeout").fetchone()==("2s",) and store.conn.execute("SHOW lock_timeout").fetchone()==("1s",)
    finally:store.close()


def test_canonical_hash_is_compact_sorted_utf8_json_without_nan():
    value={"b":[1,{"z":None,"y":"\u00e9"}],"a":"\u65e5\u672c"}
    assert canonical_hash(value)=="7baf084910a6febb9b817cc2475aced0416889cd9582bef43aa2cd3302554877"
    assert canonical_hash({"a":"\u65e5\u672c","b":[1,{"y":"\u00e9","z":None}]})==canonical_hash(value)
    with pytest.raises(ValueError):canonical_hash({"x":float("nan")})
