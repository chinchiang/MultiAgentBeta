"""Full orchestration with synthetic model contracts and REAL Docker HTTP I/O.

This validates wiring, stage gates and durability; it does not measure any LLM.
"""
import copy
import json
import os
from pathlib import Path
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

import pytest
from jsonschema import validate

from vibe_audit.domain import RunInput
from vibe_audit.service import Engine
from vibe_audit.store import Store


@pytest.mark.skipif(not os.getenv("VIBEAUDIT_TEST_RUNTIME_CONFIG"),reason="Real Docker/PostgreSQL runtime required")
@pytest.mark.parametrize("static_tools", [[], ["semgrep", "gitleaks", "osv"]])
async def test_full_pipeline_with_synthetic_models_and_real_isolated_http(tmp_path,monkeypatch,static_tools):
    from vibe_audit import providers
    config=json.loads(Path(os.environ["VIBEAUDIT_TEST_RUNTIME_CONFIG"]).read_text())
    url=os.environ[config["profiles"]["default"]["database_url_env"]]
    monkeypatch.setenv("VIBEAUDIT_RUNTIME_CONFIG",os.environ["VIBEAUDIT_TEST_RUNTIME_CONFIG"])
    source=tmp_path/"source";source.mkdir()
    (source/"app.py").write_text("def private():\n    return 'Forbidden'\n")
    (source/"requirements.txt").write_text("urllib3==1.26.4\n")
    ref={"file":"app.py","line":1,"quote":"def private():"}
    assets=[{"id":"caller","name":"Caller","kind":"actor","source_refs":[ref]},
            {"id":"private","name":"Private data","kind":"data","source_refs":[ref]}]
    flows=[{"id":"F1","source":"caller","target":"private","boundary":"authentication","source_refs":[ref]}]
    requirement={"id":"R1","statement":"An unauthenticated request must not receive the private canary",
                 "source_kind":"operator","source":"Synthetic contract fixture owner","threat_ids":["T1"],"standard_ids":[]}
    threat={"id":"T1","title":"Private data disclosure","asset_ids":["private"],"category":"Information disclosure",
            "invariant":requirement["statement"],"impact":"Synthetic private canary exposed","requirement_id":"R1",
            "dataflow_ids":["F1"],"testability":"automated","control_evidence":[ref]}
    calls=[];review_inputs=[];sent=[]
    class Target(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            sent.append(self.path)
            raw=b'LOCAL_PIPELINE_CANARY' if self.path=='/fixture' else b'Forbidden'
            self.send_response(200 if self.path=='/fixture' else 403)
            self.send_header('X-Deployment-Id','synthetic-v1')
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    server=ThreadingHTTPServer(('127.0.0.1',0),Target)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    async def contract_model(profile,system,payload,policy):
        await policy['request_hook']()
        calls.append(profile['id'])
        if payload.get('request')=='probe':data={'probe':'vibeaudit','ok':True}
        elif 'reviewers' in payload:data={'reviewer_order':payload['reviewers'],'focus':[],'rationale':'Synthetic protocol test'}
        elif 'core_questions' in payload:
            review_inputs.append(copy.deepcopy(payload))
            data={'findings':[],'gaps':[]}
        elif 'candidates' in payload:data={'challenges':[]}
        elif 'Map actors' in system:data={'assets':assets,'dataflows':flows,'roles':[],'gaps':[]}
        elif 'Build a complete' in system:data={'id':'TM1','version':1,'assets':assets,'dataflows':flows,'threats':[threat],'requirements':[requirement],'standards':[]}
        else:raise AssertionError('Unexpected model operation in local contract test')
        validate(data,policy.get('response_schema',{'type':'object'}))
        return {'data':data,'usage':{'tokens':1,'tokens_known':True},'synthetic_contract':True}
    monkeypatch.setattr(providers,'generate_json',contract_model)
    profiles=[{'id':key,'role':'commander' if key=='commander' else 'reviewer','provider':'openai_compatible',
               'model_id':'synthetic-contract-'+key,'family':'fixture-'+key,'endpoint':'http://127.0.0.1:9/v1'}
              for key in ('commander','a','b','c')]
    case={'id':'C1','title':'Synthetic contract read','threat_ids':['T1'],'requirement_id':'R1','adapter':'http',
          'method':'GET','path':'/private','identity':None,'headers':{},'side_effects':False,'cleanup':None,
          'repetitions':1,'observation_mode':'external_observation',
          'preconditions':[{'name':'fixture','method':'GET','path':'/fixture','expected_status':200,'required_text':['LOCAL_PIPELINE_CANARY']}],
          'oracle':{'kind':'deny_sensitive','forbidden_text':['LOCAL_PIPELINE_CANARY'],'allowed_statuses':[403],'required_observations':['http_response']}}
    store=Store(tmp_path/'data',url)
    engine=Engine(store,url)
    try:
        run=engine.create(RunInput(name='SYNTHETIC MODEL CONTRACT — REAL DOCKER HTTP',mode='live',models=profiles,
            source_path=str(source),target_url=f'http://127.0.0.1:{server.server_port}',allowed_target_ips=['127.0.0.1'],
            deployment_id='synthetic-v1',deployment_header='X-Deployment-Id',static_tools=static_tools,
            budget={'max_seconds':600,'max_requests':10,'max_model_calls':30,'max_tokens':200000},
            allowed_requests=[{'method':'GET','path':p} for p in ('/fixture','/private')],requirements=[requirement],cases=[case]))
        engine.start(run['id']);await engine.tasks[run['id']]
        result=store.get(run['id'])
        assert result['stage']=='complete',result.get('error')
        assert result['status']=='completed',result.get('gaps')
        assert len(review_inputs)==3 and review_inputs[0]==review_inputs[1]==review_inputs[2]
        assert review_inputs[0]['core_questions'] and review_inputs[0]['untrusted_commander_focus']==[]
        assert result['executions'][0]['status']=='pass'
        assert result['executions'][0]['isolation']=='docker_network_none'
        assert sent==['/fixture','/private']
        assert len(result['gate_receipts'])==3
        assert result['usage']['model_calls']==len(calls)
        assert result['usage']['requests']==2
        assert store.trace(run['id'])['links']
        if static_tools:
            assert len(result['tool_results']) == 3
            assert all(item['status'] == 'completed' for item in result['tool_results'])
            assert any(f['state'] == 'corroborated_static' for f in result['findings'])
            assert all('tool_results' not in payload for payload in review_inputs)
    finally:
        for runtime in engine.runtimes.values():runtime.leases.close()
        store.close();server.shutdown();server.server_close();thread.join(timeout=2)
