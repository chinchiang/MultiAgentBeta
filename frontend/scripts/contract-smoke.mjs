/** Real loopback API + React SSR integration. This is not a browser E2E test. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createRequire, Module } from 'node:module';
import { setTimeout as delay } from 'node:timers/promises';
import ts from 'typescript';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
assert(args.length === 0 || (args.length === 2 && args[0] === '--base-url'), 'Usage: npm run smoke -- --base-url http://127.0.0.1:8000');
const base = new URL(args[1] || 'http://127.0.0.1:8000');
assert(['127.0.0.1', '[::1]'].includes(base.hostname) && base.protocol === 'http:' && !base.username && !base.password && base.pathname === '/' && !base.search && !base.hash, 'Smoke accepts only an explicit numeric loopback HTTP origin.');
let cookie = '';
let csrf = '';
async function request(path, body) {
  const headers = { Accept: 'application/json', ...(cookie ? { Cookie: cookie } : {}) };
  if (body !== undefined) Object.assign(headers, { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, Origin: base.origin });
  const response = await fetch(new URL(`/api${path}`, base), {
    method: body === undefined ? 'GET' : 'POST', headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(60000), redirect: 'error',
  });
  const setCookie = response.headers.getSetCookie();
  if (setCookie.length) cookie = setCookie.map(value => value.split(';')[0]).join('; ');
  const text = await response.text();
  assert(response.ok, `${path}: HTTP ${response.status} ${text.slice(0, 500)}`);
  return response.headers.get('content-type')?.includes('application/json') ? JSON.parse(text) : text;
}

const session = await request('/session');
csrf = session.csrf_token;
assert(csrf && cookie, 'Session must establish CSRF and cookie.');
const capabilities = await request('/capabilities');
const created = await request('/runs', { name: '前端契約驗證 · 合成示範', mode: 'demo' });
assert.equal(created.mode, 'demo');
await request(`/runs/${created.id}/start`, {});
let run;
const deadline = Date.now() + 120000;
do {
  run = await request(`/runs/${created.id}`);
  if (!['created', 'running', 'cancelling'].includes(run.status)) break;
  await delay(250);
} while (Date.now() < deadline);
assert.equal(run.status, 'incomplete', 'Demo must truthfully retain its intentionally incomplete observation.');
assert.equal(run.reviews.length, 3);
assert(run.reviews.every(review => review.simulated === true));
assert.equal(run.usage.model_calls, 0);
assert.equal(run.usage.tokens, 0);
const outcomes = new Set(run.executions.map(ex => (ex.result ?? ex).status));
for (const status of ['pass', 'fail', 'inconclusive']) assert(outcomes.has(status), `Missing demo outcome: ${status}`);
assert(run.artifacts.length > 0);
for (const artifact of run.artifacts) {
  const evidence = await request(`/runs/${run.id}/evidence/${artifact.id}`);
  assert.equal(evidence.run_id, run.id);
  assert.equal(evidence.id, artifact.id);
}
for (const format of ['markdown', 'json', 'sarif']) {
  const report = await request(`/runs/${run.id}/report?format=${format}`);
  if (format === 'json') assert.equal(report.id, run.id);
  else if (format === 'sarif') { assert.equal(report.version, '2.1.0'); assert(report.runs.length); }
  else assert(/demo|synthetic|合成|示範/i.test(report));
}

// Use the actual components without adding testing exports to the production bundle.
// TypeScript's in-process transpiler avoids spawning a compiler or a browser.
const require = createRequire(resolve(root, 'package.json'));
function compile(source, name, overrides = {}) {
  const mod = new Module(resolve(root, 'src', name));
  mod.filename = resolve(root, 'src', name);
  mod.paths = require.resolve.paths('react');
  mod.require = id => Object.hasOwn(overrides, id) ? overrides[id] : require(id);
  const output = ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
    jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true,
  }, fileName: name });
  mod._compile(output.outputText, mod.filename);
  return mod.exports;
}
const api = compile(await readFile(resolve(root, 'src/api.ts'), 'utf8'), 'api.ts');
const extensions = compile(await readFile(resolve(root, 'src/extensions.tsx'), 'utf8'), 'extensions.tsx', { './api': api, './extensions.css': {} });
const source = await readFile(resolve(root, 'src/App.tsx'), 'utf8');
const components = compile(`${source}\nexport { RunDetail, CreateForm, CapabilitiesView, SafeText };`, 'App.tsx', { './api': api, './extensions': extensions });
const noop = () => {};
const render = (component, props) => renderToStaticMarkup(React.createElement(component, props));
const tabs = ['overview', 'trace', 'findings', 'evidence', 'activity'];
for (const tab of tabs) {
  const html = render(components.RunDetail, { run, tab, setTab: noop, action: async () => {}, busy: '' });
  assert(html.includes('合成示範'), `Missing synthetic banner in ${tab}`);
  assert(html.includes('未完整完成'), `Missing truthful completion state in ${tab}`);
  assert(html.includes(`tab-${tab}`));
  if (tab === 'trace') for (const threat of run.threat_model.threats) assert(html.includes(threat.id));
  if (tab === 'evidence') for (const artifact of run.artifacts) assert(html.includes(artifact.id));
}
assert(render(components.CreateForm, { onCreate: async () => {}, busy: false, connected: true }).includes('合成示範'));
assert(render(components.CapabilitiesView, { capabilities, session }).includes('已知限制'));
const hostile = '<script>alert("unsafe")</script><img src=x onerror=alert(1)>';
const safeHtml = render(components.SafeText, { value: hostile });
assert(!safeHtml.includes('<script>') && !safeHtml.includes('<img'));
assert(safeHtml.includes('&lt;script&gt;'));
console.log(JSON.stringify({ check: 'loopback API + React SSR, not browser E2E', run_id: run.id, status: run.status,
  reviews: run.reviews.length, outcomes: [...outcomes], tabs_rendered: tabs,
  evidence_verified: run.artifacts.length, report_formats: ['markdown', 'json', 'sarif'],
  safe_text_escaped: true, live_models_tested: false }, null, 2));
