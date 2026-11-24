import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { readModuleParts, readProductionModule, readRoleSplitFile, rustItemBody } from './lib/source-module.mjs';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');
const [abuseSources, envExample, apiRouter, authRoutes, reportRoutes, messaging, miscProtocol, ibrProtocol, accountRepository, migration, messageAdmissionMigration, powIntentMigration, parallelChallengeMigration, deletionRecoveryMigration, maintenanceWorkers, client, powClient, clientHtml, admin, adminHtml, workerSource] = await Promise.all([
  Promise.all([
    readModuleParts('crates/contexts/abuse/northstar-abuse-application/src/guard.rs', { includeTests: false }).map(({ source }) => source),
    read('crates/contexts/abuse/northstar-abuse-policy/src/lib.rs'),
    read('crates/contexts/abuse/northstar-abuse-policy/src/model.rs'),
    read('crates/contexts/abuse/northstar-abuse-policy/src/escalation.rs'),
    read('crates/contexts/abuse/northstar-abuse-policy/src/admission.rs'),
    read('crates/contexts/abuse/northstar-abuse-policy/src/pow.rs'),
    read('crates/contexts/abuse/northstar-abuse-policy/src/cooldown.rs'),
    read('crates/contexts/abuse/northstar-abuse-policy/src/config.rs'),
  ]).then(([parts, ...policyParts]) => [...parts, policyParts.join('\n')]),
  read('.env.example'),
  readRoleSplitFile('crates/edges/northstar-http/src/lib.rs'), read('crates/edges/northstar-http/src/auth_routes.rs'),
  read('crates/edges/northstar-http/src/reports.rs'),
  readProductionModule('crates/contexts/message/northstar-message-xmpp/src/messaging.rs'), readProductionModule('crates/edges/northstar-stream/src/protocol/misc.rs'), read('crates/edges/northstar-stream/src/protocol/ibr.rs'), read('crates/contexts/workflows/northstar-workflows/src/account_repository.rs'),
  read('migrations/0009_abuse_reports.sql'), read('migrations/0078_message_pow_admissions.sql'),
  read('migrations/0084_pow_intent_v2.sql'), read('migrations/0100_parallel_pow_challenges.sql'), read('migrations/0101_durable_account_deletion_recovery.sql'), Promise.all([
    read('src/node/workers/maintenance.rs'),
    read('crates/contexts/operations/northstar-operations-application/src/maintenance_worker.rs'),
  ]).then((sources) => sources.join('\n')), read('web/client.js'), read('web/pow.js'), read('web/client.html'),
  read('web/app.js'), read('web/index.html'), read('web/pow-worker.js'),
]);
const abuse = abuseSources.join('\n');
const api = `${apiRouter}\n${authRoutes}\n${reportRoutes}`;
const { httpPowIntent, xmppPowIntent } = await import(new URL('../web/pow.js', import.meta.url));

const browserIntentVector = await httpPowIntent('/api/v1/register', {
  username: 'alice', password: '秘密pass123', invitation_token: null,
});
assert.deepEqual(browserIntentVector, {
  version: 2,
  method: 'POST',
  path: '/api/v1/register',
  body_sha256: 'YQTJXLqYiX5ozfSad42LkiW0yxb40r7JzrfODA-h1YY',
}, 'browser canonical JSON must match the Rust cross-language test vector');
assert.doesNotMatch(JSON.stringify(browserIntentVector), /秘密|pass123/,
  'sensitive body values must never enter the challenge request');
assert.equal((await httpPowIntent('/api/v1/reports', { '😀': 2, '': 1 })).body_sha256,
  'hxlUUxhZx1csYnn5Drg6WU3cOiiei9wo0qhP-4waFwM',
  'browser object-key order must match Rust Unicode scalar ordering');
const stanzaIntent = await xmppPowIntent(
  '/xmpp/message',
  "<message xmlns='jabber:client' to='bob@example.test' type='chat' id='m1'><encrypted xmlns='urn:xmpp:omemo:2'/></message>",
);
assert.equal(stanzaIntent.method, 'XMPP');
assert.match(stanzaIntent.body_sha256, /^[A-Za-z0-9_-]{43}$/);

assert.match(envExample, /^ABUSE_MESSAGE_FREE_BURST=60$/m,
  'the deployment example must agree with the Rust default');
assert.match(abuse, /prefetched_message_challenge_remains_sufficient/,
  'parallel message challenges must be revalidated against the live rate-limit step');
assert.match(parallelChallengeMigration, /DROP CONSTRAINT IF EXISTS abuse_pow_challenges_action_subject_hash_key/,
  'parallel operation-bound challenges must not overwrite each other');
assert.match(parallelChallengeMigration, /CREATE INDEX abuse_pow_challenges_action_subject_expiry_idx/,
  'parallel challenges must retain a bounded cleanup and lookup index');
assert.match(messaging, /pub async fn message<S: MessageSession>\([\s\S]*client_raw:\s*&str/,
  'message admission must receive the original client frame separately from the authoritative routed stanza');
assert.doesNotMatch(messaging, /pow_intent_payload:\s*&routed_raw/,
  'server-injected from/xml:lang bytes must never become part of the client PoW commitment');
const messageHandler = rustItemBody(messaging, 'pub async fn message<S: MessageSession>');
const ratedAdmission = rustItemBody(messaging, 'pub(super) async fn begin<S: MessageSession>');
assert.match(messageHandler, /\blet pow_intent_payload = message_pow_intent_payload\(client_raw\);/,
  'the client PoW commitment must come from the original client frame');
assert.match(messageHandler, /\brated_admission::begin\(\s*session,\s*state,\s*root,\s*user_id,\s*from,\s*to,\s*&original_direct,\s*&pow_intent_payload\s*,/,
  'the handler must pass that commitment to the rated-admission leaf');
assert.match(ratedAdmission, /\blet request = MessageAdmissionRequest \{[^{}]*\bpow_intent_payload\s*,/,
  'the rated-admission leaf must use the passed commitment in the request');
assert.match(powIntentMigration, /protocol_version SMALLINT NOT NULL DEFAULT 1/);
assert.match(powIntentMigration, /intent_method[\s\S]*intent_path[\s\S]*body_sha256[\s\S]*server_nonce[\s\S]*issued_at/,
  'durable challenges must store every v2 intent/time/nonce component');
const xmppRegistration = accountRepository.slice(
  accountRepository.indexOf('async fn register('),
  accountRepository.indexOf('async fn change_password('),
);
assert.match(xmppRegistration, /password_work: northstar_security::password_work::PasswordWorkReservation/,
  'the registration transaction must require the service-reserved CPU permit');
assert.doesNotMatch(xmppRegistration, /verify_or_allow_in_tx\(/,
  'XMPP registration must not retain an unbound v1 proof path');
assert.doesNotMatch(`${miscProtocol}\n${ibrProtocol}`, /\.issue\(\s*AbuseAction::Registration/,
  'XMPP registration must not issue legacy v1 challenges');
assert.match(deletionRecoveryMigration, /user_id UUID PRIMARY KEY REFERENCES users\(id\) ON DELETE CASCADE/);
assert.match(deletionRecoveryMigration, /recovery_after TIMESTAMPTZ NOT NULL[\s\S]+claim_token UUID[\s\S]+claim_until TIMESTAMPTZ/,
  'account deletion recovery must be delayed and lease-fenced');
assert.match(maintenanceWorkers, /"account-deletion-recovery"[\s\S]+WorkerCriticality::Restartable/,
  'account deletion recovery must remain under the worker supervisor');
assert.match(messageAdmissionMigration, /payload_mac BYTEA NOT NULL,[\s\S]*CHECK \(octet_length\(payload_mac\) = 32\)/,
  'message admission must retain only a keyed payload digest');
assert.doesNotMatch(messageAdmissionMigration, /normalized_payload|stanza\s+TEXT|payload\s+TEXT/,
  'message admission must never retain plaintext content');
assert.match(messageAdmissionMigration, /capacity_shard SMALLINT NOT NULL\s+REFERENCES abuse_message_admission_capacity/,
  'message admission capacity must remain transactionally sharded');

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
const submitReportSource = client.slice(
  client.indexOf('async function submitReport'),
  client.indexOf('const reportStatus'),
);
assert.match(submitReportSource, /archive_id:\s*message\.archiveId[\s\S]*client_message_id:\s*message\.clientMessageId[\s\S]*body_text:\s*message\.body/,
  'report evidence must carry the authoritative archive ID and only user-verifiable fields');
assert.doesNotMatch(submitReportSource, /sender_jid|sent_at|encrypted\s*:/,
  'the browser must not submit server-authoritative report metadata');
assert.match(client, /if \(archiveId && !duplicate\.archiveId\) duplicate\.archiveId = archiveId/,
  'MAM duplicate processing must enrich live messages with the authoritative archive ID');
assert.match(client, /checkbox\.disabled = !reportable/,
  'unarchived or otherwise unverifiable messages must not be selectable as evidence');
assert.match(client, /queuedMessageProof/);
assert.match(client, /queuedHttpProof\(\s*'report'/);
assert.match(client, /queuedHttpProof\('appeal'/);
assert.match(powClient, /if \(!context\.intent\) throw new Error/,
  'the bundled browser must fail closed rather than request an unbound challenge');
assert.match(powClient, /crypto\.subtle\.digest\('SHA-256'/,
  'the challenge API must receive only a local SHA-256 body commitment');
assert.match(client, /headers\.set\('Idempotency-Key', idempotencyKey \|\| newClientIdempotencyKey\(\)\)/,
  'browser mutations must carry a replay-safe idempotency key');
assert.match(admin, /data-update-report/);
assert.match(admin, /data-update-appeal/);
assert.match(admin, /headers\['Idempotency-Key'\] = idempotencyKey \|\| newIdempotencyKey\(\)/,
  'administration mutations must carry a replay-safe idempotency key');

function retryResponse(status, body, retryAfter = null) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        if (String(name).toLowerCase() === 'retry-after') return retryAfter;
        return String(name).toLowerCase() === 'content-type' ? 'application/json' : null;
      },
    },
    async text() { return body === null ? '' : JSON.stringify(body); },
  };
}

async function checkRetryContract(source, startMarker, endMarker, functionName, state, keyReader) {
  const calls = [];
  const outcomes = [
    new TypeError('uncertain network result'),
    retryResponse(503, { error: { code: 'service_unavailable', message: 'retry' } }),
    retryResponse(409, { error: { code: 'idempotency_in_progress', message: 'busy' } }, '0'),
    retryResponse(200, { accepted: true }),
  ];
  const context = {
    crypto: globalThis.crypto,
    Headers,
    DOMException,
    Date,
    JSON,
    Number,
    Set,
    TypeError,
    state,
    setTimeout(callback) { callback(); return 1; },
    clearTimeout() {},
    async fetch(path, options) {
      calls.push({ path, options });
      const outcome = outcomes.shift();
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
  };
  const excerpt = source.slice(source.indexOf(startMarker), source.indexOf(endMarker));
  vm.runInNewContext(`${excerpt}\nglobalThis.retryingRequest = ${functionName};`, context);
  const body = JSON.stringify({ operation: 'same-payload' });
  const result = await context.retryingRequest('/api/test', { method: 'POST', body });
  assert.equal(result.accepted, true);
  assert.equal(calls.length, 4, 'network, 503, and in-progress outcomes must be retried only within the bound');
  const keys = calls.map(({ options }) => keyReader(options.headers));
  assert.ok(keys[0], 'a retryable mutation must have an idempotency key');
  assert.equal(new Set(keys).size, 1, 'every retry must reuse the exact same idempotency key');
  assert.deepEqual(calls.map(({ options }) => options.body), Array(4).fill(body),
    'every retry must reuse the exact same serialized body');
}

await checkRetryContract(
  client,
  'function newClientIdempotencyKey',
  'function updatePowStatus',
  'request',
  { apiToken: 'client-token' },
  (headers) => headers.get('Idempotency-Key'),
);
await checkRetryContract(
  admin,
  'function newIdempotencyKey',
  'async function checkServer',
  'api',
  { token: 'admin-token' },
  (headers) => headers['Idempotency-Key'],
);

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
