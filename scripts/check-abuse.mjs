import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');
const [abuse, config, envExample, apiRouter, authRoutes, reportRoutes, protocolSession, dispatch, messaging, miscProtocol, ibrProtocol, accountService, accountRecovery, dbUsers, apiControl, appError, xmlUtil, migration, messageAdmissionMigration, powIntentMigration, parallelChallengeMigration, deletionRecoveryMigration, main, client, powClient, clientHtml, admin, adminHtml, workerSource] = await Promise.all([
  read('src/abuse.rs'), read('src/config.rs'), read('.env.example'),
  read('src/api/mod.rs'), read('src/api/auth_routes.rs'),
  read('src/api/reports.rs'), read('src/xmpp/protocol.rs'), read('src/xmpp/protocol/dispatch.rs'),
  read('src/xmpp/protocol/messaging.rs'), read('src/xmpp/protocol/misc.rs'), read('src/xmpp/protocol/ibr.rs'), read('src/services/account.rs'), read('src/account_recovery.rs'), read('src/db/users.rs'), read('src/db/api_control.rs'), read('src/error.rs'), read('src/xmpp/xml_util.rs'),
  read('migrations/0009_abuse_reports.sql'), read('migrations/0078_message_pow_admissions.sql'),
  read('migrations/0084_pow_intent_v2.sql'), read('migrations/0100_parallel_pow_challenges.sql'), read('migrations/0101_durable_account_deletion_recovery.sql'), read('src/main.rs'), read('web/client.js'), read('web/pow.js'), read('web/client.html'),
  read('web/app.js'), read('web/index.html'), read('web/pow-worker.js'),
]);
const api = `${apiRouter}\n${authRoutes}\n${reportRoutes}`;
const protocol = `${protocolSession}\n${messaging}\n${xmlUtil}`;
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

assert.match(abuse, /saturating_mul\(squared\)/, 'PoW must include the quadratic n² multiplier');
assert.match(abuse, /fn policy\(action: AbuseAction, base: u64, message_free_burst: usize\)/,
  'message burst must be an explicit policy input');
assert.match(abuse, /AbuseAction::Message\s*=>\s*Policy\s*\{\s*free_burst:\s*message_free_burst/,
  'message policy must use the configured burst instead of a hidden constant');
assert.match(config, /fn default_message_free_burst\(\) -> usize \{\s*60\s*\}/,
  'the documented default message burst must remain explicit');
assert.match(config, /\(10\.\.=10_000\)\.contains\(&raw\.abuse_message_free_burst\)/,
  'message burst configuration must have a bounded validation range');
assert.match(envExample, /^ABUSE_MESSAGE_FREE_BURST=60$/m,
  'the deployment example must agree with the Rust default');
assert.match(abuse, /AbuseAction::Report\s*=>\s*Policy\s*\{\s*free_burst:\s*0/);
assert.match(abuse, /AbuseAction::Appeal[\s\S]*base\.saturating_mul\(8\)/);
assert.match(abuse, /AbuseAction::Appeal\s*=>\s*15/,
  'appeals must keep a non-zero minimum hard wait');
assert.match(abuse, /4\.\.=7 => 2,[\s\S]*8\.\.=11 => 10,[\s\S]*12\.\.=15 => 30/);
assert.match(abuse, /prefetched_message_challenge_remains_sufficient/,
  'parallel message challenges must be revalidated against the live rate-limit step');
assert.match(abuse, /challenge\.work_factor >= current\.work_factor[\s\S]*challenge\.hard_wait_seconds >= current\.hard_wait_seconds/,
  'a prefetched message challenge must never cross a stricter work or wait step');
assert.match(parallelChallengeMigration, /DROP CONSTRAINT IF EXISTS abuse_pow_challenges_action_subject_hash_key/,
  'parallel operation-bound challenges must not overwrite each other');
assert.match(parallelChallengeMigration, /CREATE INDEX abuse_pow_challenges_action_subject_expiry_idx/,
  'parallel challenges must retain a bounded cleanup and lookup index');
assert.match(abuse, /actor\.starts_with\("behavior:"\)/, 'behavior state must be shared between actions');
assert.match(protocol, /is_abuse_rated_message/, 'XMPP messages must pass through the abuse guard');
assert.match(protocol, /strip_pow_element/, 'PoW data must be removed before routing and archiving');
assert.match(messaging, /begin_message_admission/, 'rated messages must use durable PoW admission');
assert.match(messaging, /finalize_message_admission/, 'accepted routes must finalize their fenced admission');
assert.match(messaging, /pub\(crate\) async fn message\([\s\S]*client_raw:\s*&str/,
  'message admission must receive the original client frame separately from the authoritative routed stanza');
assert.match(messaging, /let pow_intent_payload = message_pow_intent_payload\(client_raw\);/,
  'message PoW must reconstruct its commitment from the original client-controlled frame');
assert.match(messaging, /pow_intent_payload:\s*&pow_intent_payload/,
  'message admission must verify the reconstructed client commitment');
assert.doesNotMatch(messaging, /pow_intent_payload:\s*&routed_raw/,
  'server-injected from/xml:lang bytes must never become part of the client PoW commitment');
assert.match(dispatch, /"message"\s*=>\s*self\.message\(root,\s*xml,\s*client_xml\)\.await/,
  'dispatch must preserve the pre-rewrite client frame for message PoW verification');
assert.match(powIntentMigration, /protocol_version SMALLINT NOT NULL DEFAULT 1/);
assert.match(powIntentMigration, /intent_method[\s\S]*intent_path[\s\S]*body_sha256[\s\S]*server_nonce[\s\S]*issued_at/,
  'durable challenges must store every v2 intent/time/nonce component');
assert.match(abuse, /verify_or_allow_in_tx_v2/,
  'v2 proof consumption must remain available inside the mutation transaction');
assert.match(abuse, /PasswordChange, "XMPP", "\/xmpp\/account-remove"/,
  'authenticated XMPP account removal must have a closed v2 intent route');
assert.match(miscProtocol, /PasswordChangeRequest[\s\S]+\/xmpp\/account-remove[\s\S]+DeletionQuiesceRequest/,
  'XMPP password changes and account removal must reconstruct a v2 body commitment through the account service');
assert.match(accountService, /change_password_guarded_v2[\s\S]+begin_account_deletion_quiesce_guarded_v2/,
  'the account service must own guarded credential and deletion transactions');
const xmppRegistration = accountService.slice(
  accountService.indexOf('pub(crate) async fn register('),
  accountService.indexOf('pub(crate) async fn change_password('),
);
assert.ok(
  xmppRegistration.indexOf('password_work::reserve()') >= 0
    && xmppRegistration.indexOf('password_work::reserve()')
      < xmppRegistration.indexOf('.pool\n            .begin()'),
  'XMPP registration must reserve bounded CPU capacity before borrowing PostgreSQL',
);
assert.match(xmppRegistration,
  /verify_or_allow_in_tx_v2[\s\S]+prepare_registration_with_reservation[\s\S]+create_user_with_invitation_guarded_in_tx_v2/,
  'XMPP registration must reject invalid body-bound proofs before password derivation');
assert.match(xmppRegistration, /request\.proof,\s*request\.intent,\s*true,\s*prepared/,
  'XMPP registration must keep proof consumption and account creation in one transaction');
assert.doesNotMatch(xmppRegistration, /verify_or_allow_in_tx\(/,
  'XMPP registration must not retain an unbound v1 proof path');
assert.match(abuse, /pub fn xmpp_registration\([\s\S]+northstar\/xmpp-registration-intent\/v1/,
  'both XMPP registration transports need one semantic body commitment');
assert.match(miscProtocol, /PowIntent::xmpp_registration[\s\S]+issue_v2\(AbuseAction::Registration/,
  'XEP-0077 metered retries must issue body-bound v2 challenges only after submission');
assert.match(ibrProtocol, /ibr_challenge\(None\)[\s\S]+PowIntent::xmpp_registration[\s\S]+issue_v2\(AbuseAction::Registration/,
  'XEP-0389 must start without an unbound challenge and use an iterative v2 retry');
assert.doesNotMatch(`${miscProtocol}\n${ibrProtocol}`, /\.issue\(\s*AbuseAction::Registration/,
  'XMPP registration must not issue legacy v1 challenges');
assert.match(apiControl, /FOR UPDATE SKIP LOCKED[\s\S]+IdempotencyAcquire::Busy/,
  'the global idempotency capacity authority must fail fast instead of convoying PgPool');
assert.match(apiControl, /SELECT EXISTS\(\s*SELECT 1 FROM api_idempotency_capacity WHERE singleton=TRUE\s*\)/,
  'a missing idempotency authority row must not be misreported as ordinary contention');
assert.match(appError, /IdempotencyBusy[\s\S]+StatusCode::SERVICE_UNAVAILABLE[\s\S]+RETRY_AFTER/,
  'idempotency contention must remain an explicit retryable 503 response');
const httpRegistration = authRoutes.slice(
  authRoutes.indexOf('pub async fn register('),
  authRoutes.indexOf('fn registration_rejection_body('),
);
assert.ok(
  httpRegistration.indexOf('verify_or_allow_in_tx_v2(') >= 0
    && httpRegistration.indexOf('verify_or_allow_in_tx_v2(')
      < httpRegistration.indexOf('prepare_registration('),
  'HTTP registration must commit its proof marker before password derivation',
);
assert.match(httpRegistration, /yield_idempotency_lease/,
  'temporary password-worker overload must preserve the committed proof marker while fencing the old worker');
assert.match(dbUsers, /change_password_guarded_v2[\s\S]+verify_or_allow_in_tx_v2[\s\S]+apply_password_credentials_in_tx/,
  'XMPP password proof consumption and credential rotation must share one transaction');
assert.match(dbUsers, /begin_account_deletion_quiesce_guarded_v2[\s\S]+verify_or_allow_in_tx_v2[\s\S]+begin_account_deletion_quiesce_in_tx[\s\S]+transaction\.commit/,
  'account-removal proof consumption and durable account quiesce must share one transaction');
assert.match(dbUsers, /begin_account_deletion_quiesce_in_tx[\s\S]+INSERT INTO account_deletion_requests/,
  'a committed account quiesce must create its crash-recovery owner in the same transaction');
assert.match(deletionRecoveryMigration, /user_id UUID PRIMARY KEY REFERENCES users\(id\) ON DELETE CASCADE/);
assert.match(deletionRecoveryMigration, /recovery_after TIMESTAMPTZ NOT NULL[\s\S]+claim_token UUID[\s\S]+claim_until TIMESTAMPTZ/,
  'account deletion recovery must be delayed and lease-fenced');
assert.match(accountRecovery, /revoke_user_sm_sessions_with_teardown[\s\S]+delete_quiesced/,
  'durable SM state must be torn down before the account row can cascade it');
assert.match(accountService, /claim_account_deletion_jobs[\s\S]+release_account_deletion_job/,
  'the account service must retain deletion claim-token authority');
assert.match(accountRecovery, /claim_deletion_recovery[\s\S]+release_deletion_recovery/,
  'failed deletion recovery must release its durable lease with backoff');
assert.match(main, /"account-deletion-recovery"[\s\S]+WorkerCriticality::Restartable/,
  'account deletion recovery must remain under the worker supervisor');
assert.match(messageAdmissionMigration, /payload_mac BYTEA NOT NULL,[\s\S]*CHECK \(octet_length\(payload_mac\) = 32\)/,
  'message admission must retain only a keyed payload digest');
assert.doesNotMatch(messageAdmissionMigration, /normalized_payload|stanza\s+TEXT|payload\s+TEXT/,
  'message admission must never retain plaintext content');
assert.match(messageAdmissionMigration, /capacity_shard SMALLINT NOT NULL\s+REFERENCES abuse_message_admission_capacity/,
  'message admission capacity must remain transactionally sharded');
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
