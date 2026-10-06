"""Fixed, source-free dynamic-tool adapters. All HTTP traverses the worker relay.

Tool findings are auxiliary evidence, never a security pass or a tool commit.
Actual authorization/canary/effect oracles are evaluated by the controller using
broker observations and independently verified collector receipts.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat
from urllib.parse import urlsplit

VERSIONS = {"schemathesis": "4.28.0", "playwright": "1.63.0", "promptfoo": "0.123.1", "pyrit": "1.1.0", "zap": "2.17.0"}
DOCS = {
    "zap": "https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/",
    "schemathesis": "https://schemathesis.readthedocs.io/en/latest/reference/cli/",
    "playwright": "https://playwright.dev/docs/api-testing",
    "promptfoo": "https://www.promptfoo.dev/docs/providers/custom-api/",
    "pyrit": "https://github.com/microsoft/PyRIT/tree/v1.1.0/pyrit/executor/attack",
}


class ToolInputError(ValueError):
    pass


def _refuse_xml_declarations(data):
    """Refuse any DTD or entity declaration before ElementTree parses untrusted XML.

    The byte check alone misses encodings that are not ASCII-compatible (a UTF-16 BOM),
    so expat, which decodes exactly as ElementTree's parser will, scans the document first."""
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ToolInputError("Untrusted XML declaration")
    def refuse(*_):
        raise ToolInputError("Untrusted XML declaration")
    scan = expat.ParserCreate()
    scan.StartDoctypeDeclHandler = refuse
    scan.EntityDeclHandler = refuse
    try:
        scan.Parse(data, True)
    except expat.ExpatError as exc:
        raise ToolInputError("Malformed XML artifact") from exc


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _request(case):
    method = case.get("method", "GET")
    path = case.get("path", "/")
    p = urlsplit(path)
    if (method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} or not path.startswith("/") or path.startswith("//")
            or p.scheme or p.netloc or p.fragment or "\\" in path or any(ord(c) < 32 for c in path)):
        raise ToolInputError("A sealed exact GET/POST relative path is required")
    if not isinstance(case.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", case["id"]):
        raise ToolInputError("Invalid case identifier")
    headers = dict(case.get("headers") or {})
    for key, value in headers.items():
        if (key.lower() not in {"accept", "content-type", "x-fixture-control"}
                or not isinstance(value, str) or any(ord(c) < 32 for c in key + value)):
            raise ToolInputError("Tool headers cannot contain credentials or transport controls")
    headers["X-Vibe-Case"] = case["id"]
    if case.get("identity") is not None:
        headers["X-Vibe-Identity"] = case["identity"]
    body = case.get("body")
    if body is not None:
        if not isinstance(body, (dict, list, str)) or len(_json(body).encode()) > 65536:
            raise ToolInputError("Invalid or oversized request body")
        headers["Content-Type"] = "application/json"
    return {"id": case["id"], "method": method, "path": path, "headers": headers, "body": body}


# These files are controller-owned code. No user-supplied JS/Python is executed.
_PLAYWRIGHT = r'''
const fs=require('fs'); const {request}=require('playwright');
(async()=>{
 const c=JSON.parse(fs.readFileSync('/inputs/case.json','utf8'));
 const ctx=await request.newContext({baseURL:process.env.VIBEAUDIT_RELAY_ORIGIN,extraHTTPHeaders:c.headers,timeout:10000,ignoreHTTPSErrors:false});
 try {
  const r=await ctx.fetch(c.path,{method:c.method,data:c.body===null?undefined:c.body,maxRedirects:0,maxRetries:0,failOnStatusCode:false});
  const b=await r.body(); if(b.length>262144) throw Error('response limit');
  fs.writeFileSync('/out/playwright.json',JSON.stringify({schema:1,tool:'playwright',api_only:true,case_id:c.id,status_code:r.status(),body:b.toString('utf8'),complete:true}));
 } finally {await ctx.dispose();}
})().catch(()=>{process.exitCode=1;});
'''

_PROMPTFOO_PROVIDER = r'''
const fs=require('fs'); const http=require('http');
module.exports=class {
 id(){return 'vibe-audit-controlled-http';}
 async callApi(prompt){
  const c=JSON.parse(fs.readFileSync('/inputs/case.json','utf8'));
  const u=new URL(c.path,process.env.VIBEAUDIT_RELAY_ORIGIN);
  const raw=c.body===null?null:JSON.stringify(c.body);
  const result=await new Promise((resolve,reject)=>{
   const req=http.request(u,{method:c.method,headers:{...c.headers,...(raw?{'Content-Length':Buffer.byteLength(raw)}:{})},timeout:10000},res=>{
    let n=0,chunks=[];res.on('data',b=>{n+=b.length;if(n>262144){req.destroy(Error('limit'));return;}chunks.push(b);});
    res.on('end',()=>resolve({status_code:res.statusCode,body:Buffer.concat(chunks).toString('utf8'),complete:true}));
   });req.on('error',reject);req.on('timeout',()=>req.destroy(Error('timeout')));req.end(raw);
  });
  fs.writeFileSync('/out/promptfoo-http.json',JSON.stringify({schema:1,tool:'promptfoo',case_id:c.id,...result}));
  return {output:result.body,metadata:{status_code:result.status_code,transport:'broker-relay'}};
 }
};
'''

_PYRIT = r'''
import asyncio, json, os, http.client
from pathlib import Path
from urllib.parse import urlsplit
from pyrit.prompt_target import PromptTarget
from pyrit.models import Message
from pyrit.executor.attack import PromptSendingAttack
from pyrit.setup import IN_MEMORY, initialize_pyrit_async

# Exact API compatibility is covered by the pinned-tool integration test.
class RelayTarget(PromptTarget):
    def __init__(self):
        super().__init__()
        self.case=json.loads(Path('/inputs/case.json').read_text())
    async def _send_prompt_to_target_async(self, *, normalized_conversation):
        c=self.case;u=urlsplit(os.environ['VIBEAUDIT_RELAY_ORIGIN'])
        conn=http.client.HTTPConnection(u.hostname,u.port,timeout=10)
        raw=None if c['body'] is None else json.dumps(c['body'])
        try:
            conn.request(c['method'],c['path'],raw,c['headers'])
            response=conn.getresponse();body=response.read(262145)
            if len(body)>262144: raise ValueError('response limit')
            result={'schema':1,'tool':'pyrit','case_id':c['id'],'status_code':response.status,'body':body.decode('utf8','replace'),'complete':True}
            Path('/out/pyrit.json').write_text(json.dumps(result))
        finally:
            conn.close()
        response=Message.from_prompt(prompt=result['body'],role='assistant')
        response.get_piece().conversation_id=normalized_conversation[-1].get_piece().conversation_id
        return [response]

async def main():
    await initialize_pyrit_async(memory_db_type=IN_MEMORY,initializers=[],env_files=[],silent=True)
    attack=PromptSendingAttack(objective_target=RelayTarget())
    await attack.execute_async(objective='Execute the sealed synthetic fixture input.')
asyncio.run(main())
'''


def compile_tool(tool_id, case, *, image_pin=None, timeout_seconds=120):
    """Compile one threat-bound case, fixed argv and private input artifacts.

    ZAP runs requestor + passive rules only. Schemathesis executes the explicitly
    provided OpenAPI example only. The broker still checks every generated URL.
    This deliberately does not grant a scanner authority to discover new scope.
    """
    if tool_id not in VERSIONS:
        raise ToolInputError("Unsupported dynamic tool")
    req = _request(case)
    if not case.get("hash") or not case.get("threat_model_hash"):
        raise ToolInputError("Threat-bound sealed case required")
    if not 10 <= timeout_seconds <= 600:
        raise ToolInputError("Invalid tool deadline")
    spec = {"tool_id": tool_id, "phase": "blackbox", "operation": "tool", "cases": [copy.deepcopy(case)],
            "timeout_seconds": timeout_seconds, "max_output_bytes": 262144, "max_requests": 20,
            "input_files": {"case.json": _json(req)}, "output_files": []}
    if image_pin:
        spec["image_pin"] = image_pin
    if tool_id == "playwright":
        spec["argv"] = ["node", "/inputs/playwright-runner.cjs"]
        spec["input_files"]["playwright-runner.cjs"] = _PLAYWRIGHT
        spec["output_files"] = ["playwright.json"]
    elif tool_id == "promptfoo":
        config = {"description": "Fixed synthetic dataset; no remote generation or model grader",
            "prompts": ["Execute the sealed fixture case"], "providers": ["file:///inputs/provider.cjs"],
            "tests": [{"assert": [{"type": "is-json"}]}],
            "evaluateOptions": {"maxConcurrency": 1, "cache": False}}
        spec["input_files"].update({"provider.cjs": _PROMPTFOO_PROVIDER, "promptfoo.json": _json(config)})
        spec["argv"] = ["promptfoo", "eval", "--config", "/inputs/promptfoo.json", "--output", "/out/promptfoo.json",
                        "--no-share", "--no-cache", "--max-concurrency", "1"]
        spec["output_files"] = ["promptfoo.json", "promptfoo-http.json"]
    elif tool_id == "pyrit":
        spec["input_files"]["pyrit-runner.py"] = _PYRIT
        spec["argv"] = ["python3", "/inputs/pyrit-runner.py"]
        spec["output_files"] = ["pyrit.json"]
    elif tool_id == "schemathesis":
        # Exact path and a single explicit example: no unintended discovery.
        op = {"operationId": case["id"], "responses": {"200": {"description": "Synthetic response"},
                  "401": {"description": "Denied"}, "403": {"description": "Denied"}}}
        if req["body"] is not None:
            op["requestBody"] = {"required": True, "content": {"application/json": {
                "schema": {"type": "object"}, "example": req["body"]}}}
        else:
            # Reuse the relay's existing case routing header as the explicit
            # example. Never add an unsealed header to the target request.
            op["parameters"] = [{"in": "header", "name": "X-Vibe-Case", "schema": {"type": "string"}, "example": case["id"]}]
        schema = {"openapi": "3.0.3", "info": {"title": "Bound fixture case", "version": "1"},
                  "paths": {req["path"]: {req["method"].lower(): op}}}
        spec["input_files"]["openapi.json"] = _json(schema)
        spec["argv"] = ["st", "run", "/inputs/openapi.json", "--url", "{relay_origin}", "--workers", "1",
                        "--phases", "examples", "--max-examples", "1", "--max-failures", "1",
                        "--report", "junit", "--report-junit-path", "/out/schemathesis.xml"]
        for key, value in req["headers"].items():
            spec["argv"] += ["--header", key + ":" + value]
        spec["output_files"] = ["schemathesis.xml"]
    else:
        request = {"url": "{relay_origin}" + req["path"], "method": req["method"], "name": case["id"],
                   "headers": [k + ": " + v for k, v in req["headers"].items()]}
        if req["body"] is not None:
            request["data"] = _json(req["body"])
        plan = {"env": {"contexts": [{"name": "sealed-case", "urls": ["{relay_origin}"]}],
                        "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True}},
                "jobs": [{"type": "requestor", "requests": [request]},
                         {"type": "passiveScan-wait", "parameters": {"maxDuration": 1}},
                         {"type": "report", "parameters": {"template": "traditional-json", "reportDir": "/out", "reportFile": "zap.json"}}]}
        # JSON is a strict subset of YAML and avoids arbitrary YAML tags.
        spec["input_files"]["zap.yaml"] = _json(plan)
        spec["argv"] = ["zap.sh", "-cmd", "-dir", "/tmp/zap", "-config", "autoupdate.checkOnStart=false",
                        "-config", "autoupdate.installAddonUpdates=false", "-autorun", "/inputs/zap.yaml"]
        spec["output_files"] = ["zap.json"]
    return spec


def parse_tool_result(tool_id, result, *, case_id):
    """Strict bounded artifact parsing; findings do not imply a security pass."""
    base = {"tool": tool_id, "version": VERSIONS[tool_id], "status": result.get("status", "execution_error"),
            "security_status": "inconclusive", "cleanup_confirmed": result.get("cleanup_confirmed") is True,
            "deployment_changed": result.get("deployment_changed") is True,
            "isolation": result.get("isolation"), "findings": [], "observations": []}
    if result.get("status") != "completed" or not base["cleanup_confirmed"]:
        base["reason"] = result.get("reason", "Tool did not complete with confirmed cleanup")
        return base
    artifacts = result.get("artifacts", {})
    def raw(name):
        content = artifacts.get(name)
        if isinstance(content, str):
            content = content.encode()
        if not isinstance(content, bytes) or not 0 < len(content) <= 262144:
            raise ToolInputError("Missing or oversized tool artifact")
        return content
    def decoded(name):
        return json.loads(raw(name))
    try:
        if tool_id in {"playwright", "promptfoo", "pyrit"}:
            artifact = decoded("promptfoo-http.json" if tool_id == "promptfoo" else tool_id + ".json")
            if (artifact.get("schema") != 1 or artifact.get("tool") != tool_id or artifact.get("case_id") != case_id
                    or type(artifact.get("status_code")) is not int or not 100 <= artifact["status_code"] <= 599
                    or artifact.get("complete") is not True or not isinstance(artifact.get("body"), str)):
                raise ToolInputError("Invalid tool HTTP observation")
            base["observations"] = [{"kind": "tool_http_response", "provenance": "worker.tool", **artifact}]
            if tool_id == "promptfoo":
                report = decoded("promptfoo.json")
                if not isinstance(report, dict) or not isinstance(report.get("results"), dict):
                    raise ToolInputError("Invalid promptfoo report")
                base["tool_assertions"] = report["results"].get("stats", {})
        elif tool_id == "schemathesis":
            data = raw("schemathesis.xml")
            _refuse_xml_declarations(data)
            root = ET.fromstring(data)
            tests = list(root.iter("testcase"))
            if not tests:
                raise ToolInputError("Schemathesis executed no test cases")
            base["tool_tests"] = len(tests)
            base["findings"] = [{"kind": "schema_check_failure", "name": t.get("name", "")[:200]} for t in tests if t.find("failure") is not None]
        else:
            data = decoded("zap.json")
            sites = data.get("site")
            if not isinstance(sites, list) or not sites:
                raise ToolInputError("ZAP report contains no observed site")
            for site in sites:
                for alert in site.get("alerts", []):
                    base["findings"].append({"kind": "zap_passive_alert", "rule_id": str(alert.get("pluginid", ""))[:30],
                        "risk": str(alert.get("riskcode", ""))[:10], "name": str(alert.get("name", ""))[:200]})
        if result.get("exit_code") not in ({0, 1, 2} if tool_id == "zap" else {0, 1} if tool_id in {"schemathesis", "promptfoo"} else {0}):
            raise ToolInputError("Unexpected tool process exit")
        base["status"] = "completed"
        base["artifact_sha256"] = {name: hashlib.sha256(raw(name)).hexdigest() for name in artifacts}
        base["reason"] = "Tool evidence requires the threat-specific oracle and verified preconditions"
    except Exception as exc:
        # Artifacts are untrusted: any shape the parser does not expect is an execution error, never a crash.
        reason = str(exc) if isinstance(exc, (ToolInputError, ET.ParseError)) else "Tool artifact did not match its expected structure"
        base.update(status="execution_error", reason=reason, findings=[], observations=[])
    return base


async def run_tool(runtime, tool_id, manifest, case, *, cancel_event, request_hook, lease_hook=None,
                   image_pin=None, repetition=0):
    from .adapters import evaluate_oracle
    from .fixture_protocol import _ordinary_steps, _sequence, _completed, _observations
    # Reject an uncompilable case before any positive control reaches the target.
    try:
        spec = compile_tool(tool_id, case, image_pin=image_pin)
    except (ToolInputError, ValueError, KeyError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, ToolInputError) else "Case cannot be compiled for this tool"
        return {"tool": tool_id, "status": "blocked", "security_status": "blocked", "reason": reason,
                "observations": [], "cleanup_confirmed": True}
    controls = _ordinary_steps(case)[:-1]
    observations = []
    if controls:
        setup = await _sequence(runtime, manifest, case, controls, cancel_event=cancel_event,
            request_hook=request_hook, lease_hook=lease_hook, repetition=repetition)
        if not _completed(setup):
            return {"tool": tool_id, "status": "inconclusive", "security_status": "inconclusive",
                    "reason": "Positive controls failed before tool dispatch", "observations": [],
                    "cleanup_confirmed": setup.get("cleanup_confirmed") is True,
                    "deployment_changed": setup.get("deployment_changed") is True}
        observations = _observations(case, setup, repetition)
    result = await runtime.execute_tool(spec, manifest=manifest, cancel_event=cancel_event,
        request_hook=request_hook, lease_hook=lease_hook, repetition=repetition)
    normalized = parse_tool_result(tool_id, result, case_id=case["id"])
    normalized["tool_observations"] = normalized.pop("observations", [])
    # Only the independent supervisor's response records become HTTP evidence.
    # A scanner artifact or target-supplied 'trusted' field cannot take this path.
    if normalized["status"] == "completed":
        for row in result.get("broker_observations", []):
            if (row.get("case_id") == case["id"] and row.get("method") == case.get("method", "GET")
                    and row.get("path") == case["path"] and row.get("identity") == case.get("identity")):
                observations.append({"kind": "http_response", "provenance": "adapter.http", "case_id": case["id"],
                    "repetition": repetition, "status_code": row.get("status_code"), "body": row.get("body", ""),
                    "complete": row.get("complete") is True, "peer_ip": row.get("peer_ip")})
        verdict = evaluate_oracle(case, observations)
        normalized["security_status"] = verdict["status"]
        normalized["reason"] = verdict.get("reason", normalized["reason"])
    normalized["observations"] = observations
    return normalized
