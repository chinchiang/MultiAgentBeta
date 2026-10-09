"""Worker leases on both backends: SQLite under a test clock, and PostgreSQL (its own clock and row locks) when
VIBEAUDIT_TEST_DATABASE_URL names a server; each PostgreSQL test gets a database of its own."""
import copy
from concurrent.futures import ThreadPoolExecutor
import os
import time
from urllib.parse import urlsplit, urlunsplit
import uuid
import pytest
from vibe_audit.lease import LeaseStore,LeaseError


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
        parts=urlsplit(service)
        self.url=urlunsplit(parts._replace(path="/"+self.name))

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
    with pytest.raises(LeaseError):store.claim(altered,"worker")
    bad=copy.deepcopy(cap);bad["token"]="wrong"
    with pytest.raises(LeaseError):store.claim(bad,"worker")
    store.claim(cap,"worker")
    with pytest.raises(LeaseError):store.claim(cap,"worker")
    with pytest.raises(LeaseError):store.validate(cap,"other")
    stored=str(store._sql("SELECT * FROM worker_leases WHERE id=?",(cap["id"],)).fetchall())
    assert cap["token"] not in stored and cap["renewal_token"] not in stored


def test_expiry_cannot_be_resurrected_and_renewal_is_controller_only(leases):
    store,db=leases;cap=issue(store,ttl_seconds=0.5);store.claim(cap,"worker")
    worker_cap={k:v for k,v in cap.items() if k!="renewal_token"}
    with pytest.raises(LeaseError):store.renew(worker_cap)
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
    dispatch=lambda:store._sql("SELECT state,result_hash FROM worker_dispatches WHERE task_id=?",(cap["task_id"],)).fetchone()
    assert dispatch()==("sent",None)
    store.finish_dispatch(cap,"worker","request-1",{"path":"/a","method":"GET"},{"status_code":200})
    assert dispatch()[0]=="finished" and dispatch()[1]


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
        assert second._sql("SELECT state FROM worker_dispatches WHERE task_id=?",(cap["task_id"],)).fetchone()[0]=="outcome_unknown"
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
    store,db=leases;cap=issue(store)
    assert store.task(cap["task_id"])=={"id":cap["task_id"],"key":store._idempotency_key(cap["binding"]),"lease_id":cap["id"],"state":"prepared","payload":{"binding":cap["binding"]}}
    with pytest.raises(LeaseError,match="Worker task not found"):store.task("missing")
    store.revoke(cap["id"])
    assert store.task(cap["task_id"])["payload"]=={"binding":cap["binding"],"reason":"revoked"}
    long_reason=issue(store,repetition=1);store.revoke(long_reason["id"],"x"*200)
    assert store.task(long_reason["task_id"])["payload"]["reason"]=="x"*160
    expiring=issue(store,repetition=2,ttl_seconds=0.3);db.advance(0.4)
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
