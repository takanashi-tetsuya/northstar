import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  AckSettlementWindow,
  messageErrorDisposition,
  OUTBOX_MAX_SERVER_RETRIES,
  prepareFreshProofAttempt,
} from '../web/outbox-delivery.js';

function fakeClock() {
  const timers = [];
  return {
    schedule(callback) {
      const timer = { callback, cancelled: false };
      timers.push(timer);
      return timer;
    },
    cancel(timer) { timer.cancelled = true; },
    flush() {
      for (const timer of timers.splice(0)) if (!timer.cancelled) timer.callback();
    },
  };
}

{
  const clock = fakeClock();
  const settled = [];
  const window = new AckSettlementWindow({ schedule: clock.schedule, cancel: clock.cancel });
  window.recordError('error-before-ack');
  assert.equal(window.recordAck('error-before-ack', (id) => settled.push(id)), false);
  clock.flush();
  assert.deepEqual(settled, [], 'an error observed before ACK must prevent deletion');
}

{
  const clock = fakeClock();
  const settled = [];
  const window = new AckSettlementWindow({ schedule: clock.schedule, cancel: clock.cancel });
  assert.equal(window.recordAck('ack-before-error', (id) => settled.push(id)), true);
  window.recordError('ack-before-error');
  clock.flush();
  assert.deepEqual(settled, [], 'a delayed ordered error must cancel pending ACK settlement');
}

{
  const clock = fakeClock();
  const settled = [];
  const window = new AckSettlementWindow({ schedule: clock.schedule, cancel: clock.cancel });
  assert.equal(window.recordAck('normal-ack', (id) => settled.push(id)), true);
  clock.flush();
  assert.deepEqual(settled, ['normal-ack'], 'a normal ACK must settle after the verdict window');
}

{
  const clock = fakeClock();
  const settled = [];
  const window = new AckSettlementWindow({ schedule: clock.schedule, cancel: clock.cancel });
  window.recordError('retry');
  window.beginAttempt('retry');
  assert.equal(window.recordAck('retry', (id) => settled.push(id)), true);
  clock.flush();
  assert.deepEqual(settled, ['retry'], 'a fresh reconnect attempt must have its own ACK verdict');

  const basePayload = "<encrypted xmlns='urn:xmpp:omemo:2'>ciphertext</encrypted>";
  const retry = prepareFreshProofAttempt({
    id: 'retry',
    basePayload,
    payload: `${basePayload}<pow xmlns='urn:northstar:pow:1' challenge='old' nonce='1'/>`,
    proofChallengeId: 'old',
    powPending: false,
  });
  assert.equal(retry.payload, basePayload);
  assert.equal(retry.proofChallengeId, null);
  assert.equal(retry.powPending, true);
  assert.equal(retry.deliveryState, 'proof-pending');
}

assert.equal(messageErrorDisposition({
  errorType: 'wait', condition: 'resource-constraint', powRequired: true,
}, 0).kind, 'retry');
assert.equal(messageErrorDisposition({
  errorType: 'cancel', condition: 'conflict', powRequired: false,
}, 0).kind, 'terminal');
assert.deepEqual(messageErrorDisposition({
  errorType: 'wait', condition: 'service-unavailable', powRequired: false,
}, OUTBOX_MAX_SERVER_RETRIES), {
  kind: 'terminal', retryCount: OUTBOX_MAX_SERVER_RETRIES + 1, exhausted: true,
});

const root = new URL('../', import.meta.url);
const [client, xmpp] = await Promise.all([
  readFile(new URL('web/client.js', root), 'utf8'),
  readFile(new URL('web/xmpp.js', root), 'utf8'),
]);
assert.match(xmpp, /this\.emit\('message-error'/,
  'XmppClient must expose correlated message errors before ordinary message processing');
assert.match(client, /settleEncryptedOutbound\(event\.detail\.id, event\.detail\.xml\)/,
  'ACK settlement must compare the acknowledged serialized attempt');
assert.match(client, /messageErrorDisposition[\s\S]+retryEncryptedOutbound/,
  'retryable message errors must retain ciphertext and obtain a new proof');
assert.match(client, /deliveryState:[^\n]+\? 'retry-pending' : 'terminal'/,
  'permanent or exhausted errors must not retry without a bound');
assert.match(client, /outboxGeneration \+= 1[\s\S]+encryptedOutbox\.clear\(\)/,
  'logout/device retirement must fence stale asynchronous outbox writers');
assert.match(client, /await drainEncryptedOutboxWrites\(\);[\s\S]+outboxErasing = false/,
  'a new login must drain older writes before reopening its outbox generation');

console.log('encrypted outbox ACK/error settlement unit checks passed');
