import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');
const [abuse, apiRouter, authRoutes, reportRoutes, protocolSession, messaging, xmlUtil, migration, client, clientHtml, admin, adminHtml, workerSource] = await Promise.all([
  read('src/abuse.rs'), read('src/api/mod.rs'), read('src/api/auth_routes.rs'),
  read('src/api/reports.rs'), read('src/xmpp/protocol.rs'),
  read('src/xmpp/protocol/messaging.rs'), read('src/xmpp/xml_util.rs'),
  read('migrations/0009_abuse_reports.sql'), read('web/client.js'), read('web/client.html'),
  read('web/app.js'), read('web/index.html'), read('web/pow-worker.js'),
]);
const api = `${apiRouter}\n${authRoutes}\n${reportRoutes}`;
const protocol = `${protocolSession}\n${messaging}\n${xmlUtil}`;

assert.match(abuse, /saturating_mul\(squared\)/, 'PoW must include the quadratic n² multiplier');
assert.match(abuse, /AbuseAction::Message\s*=>\s*Policy\s*\{\s*free_burst:\s*6/);
assert.match(abuse, /AbuseAction::Report\s*=>\s*Policy\s*\{\s*free_burst:\s*0/);
assert.match(abuse, /AbuseAction::Appeal[\s\S]*base\.saturating_mul\(8\)/);
assert.match(abuse, /if action == AbuseAction::Appeal \{ 15 \}/);
assert.match(abuse, /4\.\.=7 => 2,[\s\S]*8\.\.=11 => 10,[\s\S]*12\.\.=15 => 30/);
assert.match(abuse, /latest_challenges/, 'issuing a new operation challenge must invalidate the old one');
assert.match(abuse, /actor\.starts_with\("behavior:"\)/, 'behavior state must be shared between actions');
assert.match(protocol, /is_abuse_rated_message/, 'XMPP messages must pass through the abuse guard');
assert.match(protocol, /strip_pow_element/, 'PoW data must be removed before routing and archiving');
assert.match(api, /ConnectInfo\(peer\)/, 'HTTP operations must use the source IP');

for (const route of [
  '/api/v1/anti-abuse/challenge', '/api/v1/reports', '/api/v1/admin/reports',
  '/api/v1/admin/invitations',
]) assert.ok(api.includes(route), `missing route ${route}`);
for (const table of ['invitation_tokens', 'abuse_reports', 'abuse_report_evidence', 'abuse_appeals']) {
  assert.match(migration, new RegExp(`CREATE TABLE ${table}`));
}
assert.match(migration, /position BETWEEN 0 AND 19/);
assert.match(migration, /report_id UUID NOT NULL UNIQUE/, 'only one appeal may be submitted per report');

for (const id of [
  'report-dialog', 'report-message-list', 'report-history-dialog', 'report-pow-status',
  'appeal-pow-status', 'register-invitation', 'pow-status',
]) assert.ok(clientHtml.includes(`id="${id}"`), `missing client UI #${id}`);
for (const id of ['reports', 'invitations', 'invitation-form']) {
  assert.ok(adminHtml.includes(`id="${id}"`), `missing administration UI #${id}`);
}
assert.match(client, /sender_jid:[\s\S]*body_text:[\s\S]*encrypted:/);
assert.match(client, /queuedProof\('message'/);
assert.match(client, /queuedProof\('report'/);
assert.match(client, /queuedProof\('appeal'/);
assert.match(admin, /data-update-report/);
assert.match(admin, /data-update-appeal/);

let workerHandler;
const messages = [];
const workerSelf = {
  addEventListener(type, handler) { if (type === 'message') workerHandler = handler; },
  postMessage(message) { messages.push(message); },
};
const workerContext = {
  self: workerSelf,
  Uint8Array,
  Uint32Array,
  DataView,
  BigInt,
  Number,
  Math,
  TextEncoder,
  performance,
};
vm.runInNewContext(workerSource, workerContext);
assert.equal(typeof workerHandler, 'function');
for (let index = 0; index < 32; index += 1) {
  const value = `sha256-cross-check-${index}-${'x'.repeat(index * 3)}`;
  const expected = createHash('sha256').update(value).digest();
  const [high, low] = workerContext.sha256Prefix64(new TextEncoder().encode(value));
  assert.equal((BigInt(high) << 32n) | BigInt(low), expected.readBigUInt64BE(0));
}
const prefix = 'northstar:static-test:';
const workFactor = 512;
workerHandler({ data: { prefix, workFactor } });
const solved = messages.findLast((message) => message.type === 'solved');
assert.ok(solved?.nonce, 'browser PoW worker did not solve a test challenge');
const digest = createHash('sha256').update(prefix).update(solved.nonce).digest();
const value = digest.readBigUInt64BE(0);
assert.ok(value <= ((1n << 64n) - 1n) / BigInt(workFactor), 'browser proof does not satisfy server target');

console.log(`anti-abuse static checks passed; browser PoW solved factor ${workFactor} in ${solved.hashes} hashes`);
