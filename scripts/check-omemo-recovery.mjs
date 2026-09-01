import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { webcrypto } from 'node:crypto';
import {
  createOmemoTransferPackage,
  newOmemoTransferSecret,
  omemoConsumerCommitmentHex,
  omemoReplacementJournalMatches,
  openOmemoTransferPackage,
  OMEMO_TRANSFER_KDF,
  OMEMO_TRANSFER_MAX_BYTES,
} from '../web/omemo-recovery.mjs';
import { validateTransferredOmemoState } from '../web/omemo-state-validation.mjs';
import { omemoTransferMemoryBudget } from '../web/omemo-recovery-worker-client.mjs';

globalThis.crypto ||= webcrypto;
const require = createRequire(import.meta.url);
const { argon2id } = require('../web/crypto/hash-wasm-argon2.umd.min.js');

const now = Date.now();
const metadata = {
  account: 'alice@example.org',
  transfer_id: '018f47bb-2f50-7cc3-9a8c-bf68c988c131',
  generation: 7,
  source_device_id: 424242,
  created_at: new Date(now - 1000).toISOString(),
  expires_at: new Date(now + 60_000).toISOString(),
};
const state = {
  version: 5,
  deviceId: 424242,
  identityKeyPair: { pubKey: 'public', privKey: 'private' },
  identities: { 'bob@example.org.8': 'identity' },
  trustDecisions: {},
  sessions: { 'bob@example.org.8': 'ratchet' },
};

const b64 = (length, byte) => Buffer.alloc(length, byte).toString('base64');
const strictState = {
  version: 5,
  deviceId: 424242,
  deviceIdExpanded: true,
  identityKeyPair: { pubKey: b64(33, 1), privKey: b64(32, 2) },
  signedPreKey: {
    id: 1,
    keyPair: { pubKey: b64(33, 3), privKey: b64(32, 4) },
    signature: b64(64, 5),
    createdAt: new Date(now - 2000).toISOString(),
  },
  prekeys: { 1: { pubKey: b64(33, 6), privKey: b64(32, 7) } },
  retiredPrekeys: {},
  identities: {},
  trustDecisions: {},
  pendingTrustMessages: [],
  lastTrustTimestamps: {},
  sessions: {},
  nextPreKeyId: 2,
  oldSignedPreKeys: [],
};
assert.equal(validateTransferredOmemoState(strictState, 424242), strictState);
assert.throws(() => validateTransferredOmemoState({ ...strictState, version: 6 }, 424242), /version is unsupported/);
assert.throws(() => validateTransferredOmemoState({ ...strictState, futureRatchet: {} }, 424242), /unsupported schema/);
assert.throws(() => validateTransferredOmemoState({
  ...strictState,
  identityKeyPair: { ...strictState.identityKeyPair, privKey: b64(31, 2) },
}, 424242), /invalid length or encoding/);
assert.throws(() => validateTransferredOmemoState({
  ...strictState,
  sessions: { 'bob@example.org.8': 'canonical-session' },
}, 424242, (serialized) => ({
  canonical: serialized,
  ratchets: [{ rootKey: new Uint8Array(31) }],
})), /missing registrationId/);

assert.deepEqual(OMEMO_TRANSFER_KDF, {
  name: 'Argon2id', version: 19, memory_kib: 65536, iterations: 3,
  parallelism: 1, output_bytes: 32,
});
assert.equal(OMEMO_TRANSFER_MAX_BYTES, 44 * 1024 * 1024);
assert.equal(omemoTransferMemoryBudget({
  deviceMemoryGiB: 8,
  inputBytes: OMEMO_TRANSFER_MAX_BYTES,
  operation: 'open',
}).allowed, true);
assert.equal(omemoTransferMemoryBudget({
  deviceMemoryGiB: 0.5,
  inputBytes: OMEMO_TRANSFER_MAX_BYTES,
  operation: 'open',
}).allowed, false);
assert.throws(() => omemoTransferMemoryBudget({
  deviceMemoryGiB: 8,
  inputBytes: OMEMO_TRANSFER_MAX_BYTES + 1,
  operation: 'open',
}), /budget input is invalid/);

const consumerSecret = 'WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo';
const consumerCommitment = await omemoConsumerCommitmentHex(
  metadata.account,
  metadata.transfer_id,
  consumerSecret,
);
assert.equal(consumerCommitment, '4b5b22fa2705912b121f4f33c0b2633552f051d9bd1fb3980c8a4b5a6c7c85a3');
assert.match(newOmemoTransferSecret(), /^[A-Za-z0-9_-]{43}$/);

// An authenticated peer may read the complete public transfer and high-water
// representations, but those contain only the commitment. It cannot construct
// the exact consume replay proof without the destination's 256-bit secret.
const publicReads = JSON.stringify({
  transfer: { consumer_commitment: consumerCommitment },
  authority: { latest_consumer_commitment: consumerCommitment },
});
assert.ok(!publicReads.includes(consumerSecret));
assert.ok(!publicReads.includes('consumer_secret'));
const attackerSecret = 'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE';
assert.notEqual(
  await omemoConsumerCommitmentHex(metadata.account, metadata.transfer_id, attackerSecret),
  consumerCommitment,
);

const replacementJournal = {
  transferId: metadata.transfer_id,
  generation: metadata.generation,
  sourceDeviceId: metadata.source_device_id,
  destinationDeviceId: 99,
  consumerCommitment,
  packageSha256: 'ab'.repeat(32),
};
assert.equal(await omemoReplacementJournalMatches({
  account: metadata.account,
  journal: replacementJournal,
  marker: null,
  installedDeviceId: 99,
}), false, 'a crash before installing the moved marker must not revive the old destination');
assert.equal(await omemoReplacementJournalMatches({
  account: metadata.account,
  journal: replacementJournal,
  marker: {
    role: 'destination',
    transferId: metadata.transfer_id,
    generation: metadata.generation,
    consumerSecret,
    consumerCommitment,
    packageSha256: 'ab'.repeat(32),
  },
  installedDeviceId: metadata.source_device_id,
}), true, 'an installed but commit-uncertain destination must remain sealed and recoverable');
assert.equal(await omemoReplacementJournalMatches({
  account: metadata.account,
  journal: replacementJournal,
  marker: {
    role: 'destination',
    transferId: metadata.transfer_id,
    generation: metadata.generation,
    consumerCommitment,
    packageSha256: 'ab'.repeat(32),
  },
  installedDeviceId: metadata.source_device_id,
}), true, 'a confirmed destination remains recognizable after dropping its consumer secret');

const created = await createOmemoTransferPackage({
  metadata, state, passphrase: 'correct horse battery staple', argon2id,
});
assert.match(created.sha256, /^[0-9a-f]{64}$/);
assert.ok(!created.serialized.includes('private'));
assert.ok(!created.serialized.includes('ratchet'));

const opened = await openOmemoTransferPackage({
  serialized: created.serialized,
  expectedAccount: metadata.account,
  passphrase: 'correct horse battery staple',
  argon2id,
  now,
});
assert.deepEqual(opened.state, state);
assert.equal(opened.sha256, created.sha256);

await assert.rejects(openOmemoTransferPackage({
  serialized: created.serialized,
  expectedAccount: metadata.account,
  passphrase: 'wrong transfer passphrase',
  argon2id,
  now,
}), /wrong or the package was modified/);

const changedAccount = JSON.parse(created.serialized);
changedAccount.account = 'mallory@example.org';
await assert.rejects(openOmemoTransferPackage({
  serialized: JSON.stringify(changedAccount),
  expectedAccount: metadata.account,
  passphrase: 'correct horse battery staple',
  argon2id,
  now,
}), /different account/);

const weakened = JSON.parse(created.serialized);
weakened.kdf.memory_kib = 8;
await assert.rejects(openOmemoTransferPackage({
  serialized: JSON.stringify(weakened),
  expectedAccount: metadata.account,
  passphrase: 'correct horse battery staple',
  argon2id,
  now,
}), /unsupported Argon2id parameters/);

await assert.rejects(createOmemoTransferPackage({
  metadata, state, passphrase: 'too short', argon2id,
}), /at least 12 characters/);

// Crash-boundary authority model for the source marker. Anonymous 404 is
// never sufficient: the authenticated exact-transfer view and the durable
// high-water baseline decide whether cancellation is recoverable.
function sourceCrashResolution({ marker, exactTransfer, highWater }) {
  if (exactTransfer) return {
    state: exactTransfer.state,
    generation: exactTransfer.generation,
    recoverable: ['preparing', 'prepared'].includes(exactTransfer.state),
  };
  if (marker.generation === null && highWater === marker.baselineGeneration) {
    return { state: 'locally-unallocated', generation: null, recoverable: true };
  }
  if (marker.generation === null && highWater > marker.baselineGeneration) {
    return { state: 'authority-advanced', generation: null, recoverable: true };
  }
  return { state: 'authority-conflict', recoverable: false };
}
const frozenMarker = { generation: null, baselineGeneration: 7 };
assert.deepEqual(sourceCrashResolution({ marker: frozenMarker, exactTransfer: null, highWater: 7 }), {
  state: 'locally-unallocated', generation: null, recoverable: true,
});
assert.deepEqual(sourceCrashResolution({ marker: frozenMarker, exactTransfer: null, highWater: 8 }), {
  state: 'authority-advanced', generation: null, recoverable: true,
});
assert.deepEqual(sourceCrashResolution({
  marker: frozenMarker,
  exactTransfer: { state: 'preparing', generation: 8 },
  highWater: 7,
}), { state: 'preparing', generation: 8, recoverable: true });

// Re-sealing never exposes an empty-marker/ready interval to a watcher. A
// crash before the atomic write observes the old revoked marker; a crash after
// it observes the new frozen marker, and only then may polling resume.
function replacementCrashSnapshot(crashPoint) {
  const oldMarker = { transferId: 'old', phase: 'package-sealed', ready: false };
  if (crashPoint === 'before-marker-write') return { marker: oldMarker, watcher: 'paused' };
  const next = { transferId: 'new', phase: 'source-frozen', ready: false };
  if (crashPoint === 'after-marker-write') return { marker: next, watcher: 'paused' };
  return { marker: next, watcher: 'running' };
}
for (const point of ['before-marker-write', 'after-marker-write', 'after-watcher-resume']) {
  const snapshot = replacementCrashSnapshot(point);
  assert.ok(snapshot.marker);
  assert.equal(snapshot.marker.ready, false);
  if (snapshot.watcher === 'running') assert.equal(snapshot.marker.transferId, 'new');
}

function watcherMayCommit({ capturedEpoch, currentEpoch, capturedTransfer, currentTransfer, transition }) {
  return !transition && capturedEpoch === currentEpoch && capturedTransfer === currentTransfer;
}
assert.equal(watcherMayCommit({
  capturedEpoch: 4, currentEpoch: 5, capturedTransfer: 'old', currentTransfer: 'old', transition: true,
}), false, 'an in-flight old watcher must become stale before marker replacement');
assert.equal(watcherMayCommit({
  capturedEpoch: 5, currentEpoch: 6, capturedTransfer: 'old', currentTransfer: 'new', transition: false,
}), false, 'an old watcher must not commit after the new marker is installed');
assert.equal(watcherMayCommit({
  capturedEpoch: 6, currentEpoch: 6, capturedTransfer: 'new', currentTransfer: 'new', transition: false,
}), true, 'only the watcher started for the durable new marker may commit');

console.log('OMEMO one-time recovery package checks passed');
