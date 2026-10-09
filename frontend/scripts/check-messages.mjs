/** The console's zh() (src/messages.ts) must read every engine message exactly as the backend's zh() does. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createRequire, Module } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repo = resolve(root, '..');

// The backend table and its readings of a corpus: every fixed message, the demo run's engine text, messages that
// carry values for each pattern, labelled messages, and text with no entry.
const PYTHON = String.raw`
import json, sys
sys.path.insert(0, "backend")
from vibe_audit.messages import PATTERNS, STATUS_ZH, ZH, zh
run = json.load(open("docs/sample-report.json", encoding="utf-8"))
corpus = list(ZH) + [e["message"] for e in run["events"]] + run["gaps"] + [f["title"] for f in run["findings"]]
corpus += [e["reason"] for e in run["executions"]] + [c["title"] for c in run["cases"]]
corpus += ["Excluded directory: node_modules/", "semgrep: Scanner did not establish coverage", "C-9: outcome_unknown — Worker sequence incomplete",
           "Entering report", "Static tool completed: gitleaks / blocked", "Catalog file unavailable: a.json", "Automated threats without cases: T-1, T-2",
           "Model call failed (refusal): Model refused the request", "Invalid run configuration: field required", "Gate: pass",
           "R-1: dropped 2 citation(s) of F-1 that do not match the frozen snapshot", "Model request failed; no request was sent",
           "Note: something a model wrote", "constructor", "toString: x", "", "Unknown text"]
json.dump({"table": {"exact": ZH, "status": STATUS_ZH, "patterns": [list(p) for p in PATTERNS]},
           "cases": [[text, zh(text)] for text in corpus]}, sys.stdout, ensure_ascii=False)
`;
const { table, cases } = JSON.parse(execFileSync(process.env.PYTHON || 'python3', ['-c', PYTHON], { cwd: repo, encoding: 'utf8' }));

const require = createRequire(resolve(root, 'package.json'));
function compile(source, name, overrides = {}) {
  // Mounted as .cjs for the same reason as in contract-smoke.mjs: this package is "type": "module".
  const file = resolve(root, 'src', name.replace(/\.[cm]?[jt]sx?$/, '.cjs'));
  const mod = new Module(file);
  mod.filename = file;
  mod.require = id => Object.hasOwn(overrides, id) ? overrides[id] : require(id);
  const output = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 }, fileName: name });
  mod._compile(output.outputText, file);
  return mod.exports;
}
const i18n = compile(await readFile(resolve(root, 'src/i18n.ts'), 'utf8'), 'i18n.ts');
const api = { api: async path => { assert.equal(path, '/messages'); return table; } };
const messages = compile(await readFile(resolve(root, 'src/messages.ts'), 'utf8'), 'messages.ts', { './api': api, './i18n': i18n });
await messages.loadMessages();

const differences = cases.filter(([text, expected]) => (messages.zh(text) ?? null) !== expected);
assert.deepEqual(differences.map(([text, expected]) => ({ text, backend: expected, console: messages.zh(text) ?? null })), []);
assert.equal(messages.say(42), '42');
console.log(`check-messages: the console reads ${cases.length} messages exactly as the backend does`);
