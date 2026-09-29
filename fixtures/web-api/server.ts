/** Synthetic loopback fixture. Deliberate defects; never a production service. */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';

type Tenant = 'A' | 'B';
type Session = { tenant: Tenant; username: string; token: string };
const args = process.argv.slice(2);
let mode: 'vulnerable' | 'fixed' = 'fixed';
let port = 8911;
for (let i = 0; i < args.length; i += 2) {
  if (args[i] === '--mode' && ['vulnerable', 'fixed'].includes(args[i + 1])) mode = args[i + 1] as typeof mode;
  else if (args[i] === '--port' && /^\d+$/.test(args[i + 1] ?? '') && Number(args[i + 1]) <= 65535) port = Number(args[i + 1]);
  else throw new Error('Usage: node server.ts --mode fixed|vulnerable --port 0..65535; host is always 127.0.0.1');
}
const CONTROL = 'local-synthetic-control';
const users = {
  alice: { password: 'synthetic-alice', tenant: 'A' as Tenant },
  bob: { password: 'synthetic-bob', tenant: 'B' as Tenant },
};
const orders = {
  'order-a': { id: 'order-a', tenant_id: 'A', private_note: 'TENANT_A_ORDER_CANARY' },
  'order-b': { id: 'order-b', tenant_id: 'B', private_note: 'TENANT_B_ORDER_CANARY' },
};
const sessions = new Map<string, Session>();
const events: object[] = [];
function record(event: object) { events.push(event); if (events.length > 500) events.shift(); }
function reset() {
  sessions.clear(); events.length = 0;
  sessions.set('fixture-web-a', { tenant: 'A', username: 'alice', token: 'fixture-web-a' });
  sessions.set('fixture-web-b', { tenant: 'B', username: 'bob', token: 'fixture-web-b' });
}
reset();
let origin = '';
function reply(res: ServerResponse, status: number, value: unknown) {
  const payload = JSON.stringify(value);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store', 'X-Fixture-Synthetic': 'true', 'X-Content-Type-Options': 'nosniff' });
  res.end(payload);
}
async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
  if (!String(req.headers['content-type'] ?? '').startsWith('application/json')) throw new Error('JSON content type required');
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length; if (size > 8192) throw new Error('Fixture request too large');
    chunks.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('JSON object required');
  return value;
}
function identity(req: IncomingMessage) {
  const authorization = req.headers.authorization ?? '';
  return authorization.startsWith('Bearer ') ? sessions.get(authorization.slice(7)) : undefined;
}
const server = createServer(async (req, res) => {
  try {
    const expectedHost = new URL(origin).host;
    if (req.headers.host !== expectedHost || (req.headers.origin && req.headers.origin !== origin)) {
      reply(res, 403, { synthetic: true, error: 'Fixture host/origin mismatch' }); return;
    }
    const path = new URL(req.url ?? '/', origin).pathname;
    if (req.method === 'GET' && path === '/') {
      const html = `<!doctype html><meta charset="utf-8"><title>Synthetic Web fixture</title><h1>合成 Web/API 靶場</h1><p>模式：${mode}</p><p>只有假帳號、假訂單與記憶體 session。此服務包含刻意設計的缺陷，只監聽本機。</p><p>API：/orders/order-a、/orders/order-b、/me、/auth/login、/auth/logout。</p>`;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'" }); res.end(html); return;
    }
    if (path === '/__fixture/shutdown' && req.method === 'POST') {
      if (req.headers['x-fixture-control'] !== CONTROL) { reply(res, 403, { error: 'Fixture control header required' }); return; }
      await body(req);
      res.once('finish', shutdown);
      reply(res, 200, { synthetic: true, shutting_down: true }); return;
    }
    if (path === '/__fixture/reset' && req.method === 'POST') {
      if (req.headers['x-fixture-control'] !== CONTROL) { reply(res, 403, { error: 'Fixture control header required' }); return; }
      await body(req); reset(); reply(res, 200, { synthetic: true, reset: true, tokens: ['fixture-web-a', 'fixture-web-b'] }); return;
    }
    if (path === '/__fixture/state' && req.method === 'GET') {
      if (req.headers['x-fixture-control'] !== CONTROL) { reply(res, 403, { error: 'Fixture control header required' }); return; }
      reply(res, 200, { synthetic: true, mode, active_sessions: sessions.size, events }); return;
    }
    if (path === '/auth/login' && req.method === 'POST') {
      const input = await body(req); const username = String(input.username ?? '');
      const account = users[username as keyof typeof users];
      if (!account || input.password !== account.password) { reply(res, 401, { error: 'Synthetic credentials invalid' }); return; }
      const token = `fixture-web-${randomUUID()}`;
      sessions.set(token, { tenant: account.tenant, username, token });
      record({ type: 'session_created', tenant: account.tenant });
      reply(res, 200, { synthetic: true, token, tenant_id: account.tenant }); return;
    }
    const session = identity(req);
    if (!session) { reply(res, 401, { synthetic: true, error: 'Active synthetic bearer session required' }); return; }
    if (path === '/me' && req.method === 'GET') {
      reply(res, 200, { synthetic: true, username: session.username, tenant_id: session.tenant, role: 'reader' }); return;
    }
    if (path === '/auth/logout' && req.method === 'POST') {
      await body(req);
      // Deliberate fixture defect: vulnerable mode only displays logout success.
      if (mode === 'fixed') sessions.delete(session.token);
      record({ type: 'logout_requested', tenant: session.tenant, revoked: mode === 'fixed' });
      reply(res, 200, { synthetic: true, logged_out: true }); return;
    }
    if (path.startsWith('/orders/') && req.method === 'GET') {
      const order = orders[path.slice('/orders/'.length) as keyof typeof orders];
      if (!order) { reply(res, 404, { error: 'Synthetic order missing' }); return; }
      // Deliberate BOLA defect in vulnerable mode; fixed mode checks ownership.
      if (mode === 'fixed' && order.tenant_id !== session.tenant) {
        record({ type: 'order_read_denied', actor_tenant: session.tenant, order_id: order.id });
        reply(res, 403, { synthetic: true, error: 'Tenant boundary denied' }); return;
      }
      record({ type: 'order_read', actor_tenant: session.tenant, owner_tenant: order.tenant_id, order_id: order.id });
      reply(res, 200, { synthetic: true, ...order }); return;
    }
    reply(res, 404, { synthetic: true, error: 'Fixture route not found' });
  } catch {
    if (!res.headersSent) reply(res, 400, { synthetic: true, error: 'Invalid bounded fixture request' });
    else res.end();
  }
});
server.requestTimeout = 2000;
server.headersTimeout = 2000;
server.timeout = 3000;
server.maxHeadersCount = 30;
server.listen(port, '127.0.0.1', () => {
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No loopback address');
  origin = `http://127.0.0.1:${address.port}`;
  process.stdout.write(JSON.stringify({ fixture: 'web-api', synthetic: true, mode, origin, pid: process.pid }) + '\n');
});
function shutdown() { server.close(() => process.exit(0)); server.closeAllConnections(); }
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
