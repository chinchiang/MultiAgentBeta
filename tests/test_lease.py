import copy
from concurrent.futures import ThreadPoolExecutor
import os
import uuid
import pytest
from vibe_audit.lease import LeaseStore,LeaseError


@pytest.fixture
def leases(tmp_path):
    clock=[100.0]
    store=LeaseStore(tmp_path/"lease.sqlite3",clock=lambda:clock[0])
    yield store,clock
    store.close()


def issue(store,**kwargs):
    args=dict(run_id=uuid.uuid4().hex,case_hash="case",threat_hash="threat",manifest_hash="manifest",max_requests=2,ttl_seconds=2,max_seconds=10)
    args.update(kwargs)
    return store.issue(**args)


def test_bound_capability_is_single_claim_and_secrets_not_persisted(leases):
    store,_=leases;cap=issue(store)
    altered=copy.deepcopy(cap);altered["binding"]["case_hash"]="other"
    with pytest.raises(LeaseError):store.claim(altered,"worker")
    bad=copy.deepcopy(cap);bad["token"]="wrong"
    with pytest.raises(LeaseError):store.claim(bad,"worker")
    store.claim(cap,"worker")
    with pytest.raises(LeaseError):store.claim(cap,"worker")
    with pytest.raises(LeaseError):store.validate(cap,"other")
    stored=str(store.conn.execute("SELECT * FROM worker_leases").fetchall())
    assert cap["token"] not in stored and cap["renewal_token"] not in stored


def test_expiry_cannot_be_resurrected_and_renewal_is_controller_only(leases):
    store,clock=leases;cap=issue(store);store.claim(cap,"worker")
    worker_cap={k:v for k,v in cap.items() if k!="renewal_token"}
    with pytest.raises(LeaseError):store.renew(worker_cap)
    clock[0]=101;assert store.renew(cap)==103
    clock[0]=103
    with pytest.raises(LeaseError):store.renew(cap)
    with pytest.raises(LeaseError):store.validate(cap,"worker")
    assert store.expire()==[cap["id"]]
    assert store.task(cap["task_id"])["state"]=="outcome_unknown"


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
    row=store.conn.execute("SELECT state,result_hash FROM worker_dispatches").fetchone()
    assert row[0]=="sent" and row[1] is None
    store.finish_dispatch(cap,"worker","request-1",{"path":"/a","method":"GET"},{"status_code":200})
    assert store.conn.execute("SELECT state FROM worker_dispatches").fetchone()[0]=="finished"


def test_a_lease_that_cannot_dispatch_is_invalid(leases):
    store,_=leases
    with pytest.raises(LeaseError):issue(store,max_requests=0)
    with pytest.raises(LeaseError):issue(store,max_requests=-1)


def test_revoke_persists_unknown_dispatch_across_connections(leases):
    store,clock=leases;cap=issue(store);store.claim(cap,"worker")
    store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    store.revoke(cap["id"],"Controller died")
    second=LeaseStore(store.database_path,clock=lambda:clock[0])
    try:
        assert second.task(cap["task_id"])["state"]=="outcome_unknown"
        assert second.conn.execute("SELECT state FROM worker_dispatches").fetchone()[0]=="outcome_unknown"
        with pytest.raises(LeaseError):second.claim(cap,"replacement")
    finally:second.close()


def test_separate_connections_cannot_both_claim(leases):
    store,clock=leases;cap=issue(store)
    def claim(worker):
        db=LeaseStore(store.database_path,clock=lambda:clock[0])
        try:
            db.claim(cap,worker);return True
        except LeaseError:return False
        finally:db.close()
    with ThreadPoolExecutor(2) as pool:
        outcomes=list(pool.map(claim,["worker-a","worker-b"]))
    assert sorted(outcomes)==[False,True]


@pytest.mark.skipif(not os.getenv("VIBEAUDIT_TEST_DATABASE_URL"),reason="Real PostgreSQL test service not configured")
def test_postgres_claim_budget_and_durable_journal():
    url=os.environ["VIBEAUDIT_TEST_DATABASE_URL"]
    store=LeaseStore(database_url=url)
    cap=issue(store,ttl_seconds=5,max_seconds=30,max_requests=1)
    def claim(worker):
        db=LeaseStore(database_url=url)
        try:db.claim(cap,worker);return worker
        except LeaseError:return None
        finally:db.close()
    try:
        with ThreadPoolExecutor(2) as pool:winners=[w for w in pool.map(claim,["worker-a","worker-b"]) if w]
        assert len(winners)==1
        store.reserve_dispatch(cap,winners[0],"one",{"path":"/authorized"})
        with pytest.raises(LeaseError):store.reserve_dispatch(cap,winners[0],"two",{"path":"/authorized"})
        store.revoke(cap["id"],"Synthetic controller crash")
        assert store.task(cap["task_id"])["state"]=="outcome_unknown"
    finally:store.close()


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
    with pytest.raises(LeaseError,match="UTF8"):
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
    # The recipe hash is not part of the task's identity: a changed recipe still finds the paid result.
    assert store.finished_result(**lookup,spec_hash="another-recipe")=={"status":"pass","reason":"held"}
    for key,other in [("repetition",1),("run_id","other-run"),("case_hash","other"),("threat_hash","other"),("manifest_hash","other"),("operation","ai_http")]:
        assert store.finished_result(**{**lookup,key:other}) is None
    with pytest.raises(LeaseError,match="Complete immutable capability bindings are required"):
        store.finished_result(**{**lookup,"run_id":""})
    with pytest.raises(LeaseError,match="Complete immutable capability bindings"):
        store.finished_result(**{**lookup,"case_hash":None})
    # Only a dict result is a usable journal entry.
    other=issue(store,repetition=1);store.claim(other,"worker");store.finish_task(other,"worker",["not","a","result"])
    assert store.finished_result(**{**lookup,"repetition":1}) is None


def test_task_records_and_revocation_reasons(leases):
    store,clock=leases;cap=issue(store)
    assert store.task(cap["task_id"])=={"id":cap["task_id"],"key":store._idempotency_key(cap["binding"]),"lease_id":cap["id"],"state":"prepared","payload":{"binding":cap["binding"]}}
    with pytest.raises(LeaseError,match="Worker task not found"):store.task("missing")
    store.revoke(cap["id"])
    assert store.task(cap["task_id"])["payload"]=={"binding":cap["binding"],"reason":"revoked"}
    long_reason=issue(store,repetition=1);store.revoke(long_reason["id"],"x"*200)
    assert store.task(long_reason["task_id"])["payload"]["reason"]=="x"*160
    expiring=issue(store,repetition=2);clock[0]=200
    assert store.expire()==[expiring["id"]]
    assert store.task(expiring["task_id"])["payload"]["reason"]=="Lease expired; external task must be reconciled"
    finished=issue(store,repetition=3);store.claim(finished,"worker");store.finish_task(finished,"worker",{"status":"pass"})
    store.revoke(finished["id"],"too late")
    assert store.task(finished["task_id"])["state"]=="finished"


def test_lease_errors_name_their_cause(leases):
    store,_=leases;cap=issue(store,max_requests=1)
    with pytest.raises(LeaseError,match="Worker identity is required"):store.claim(cap,"")
    store.claim(cap,"worker")
    with pytest.raises(LeaseError,match="already been claimed"):store.claim(cap,"worker")
    with pytest.raises(LeaseError,match="claimed by another worker"):store.validate(cap,"other")
    with pytest.raises(LeaseError,match="A unique request ID is required"):store.reserve_dispatch(cap,"worker","",{"path":"/a"})
    store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    with pytest.raises(LeaseError,match="already journaled"):store.reserve_dispatch(cap,"worker","request-1",{"path":"/a"})
    with pytest.raises(LeaseError,match="budget exhausted"):store.reserve_dispatch(cap,"worker","request-2",{"path":"/a"})
    with pytest.raises(LeaseError,match="outcome remains unknown"):store.finish_task(cap,"worker",{"status":"pass"})
    with pytest.raises(LeaseError,match="does not match the journaled dispatch request"):store.finish_dispatch(cap,"worker","request-1",{"path":"/b"},{})
    with pytest.raises(LeaseError,match="does not match the journaled dispatch request"):store.finish_dispatch(cap,"worker","request-9",{"path":"/a"},{})
    store.finish_dispatch(cap,"worker","request-1",{"path":"/a"},{"status_code":200})
    with pytest.raises(LeaseError,match="does not match the journaled dispatch request"):store.finish_dispatch(cap,"worker","request-1",{"path":"/a"},{"status_code":200})
    store.finish_task(cap,"worker",{"status":"pass"})
    with pytest.raises(LeaseError,match="revoked or expired"):store.finish_task(cap,"worker",{"status":"pass"})
    with pytest.raises(LeaseError,match="Worker lease not found"):store.revoke("missing")
    with pytest.raises(LeaseError,match="Invalid worker lease limits"):issue(store,repetition=-1)
    with pytest.raises(LeaseError,match="never implicitly replayed"):issue(store,run_id=cap["binding"]["run_id"])
