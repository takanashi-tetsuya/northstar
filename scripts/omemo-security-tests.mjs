import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

process.setMaxListeners(0);
globalThis.require = createRequire(import.meta.url);
globalThis.__WASM_BASE__ = `${fileURLToPath(new URL('../web/crypto/', import.meta.url))}/`;
// The vendored Emscripten module predates Node's global fetch. Force its
// tested filesystem loader instead of attempting to fetch a Windows path.
globalThis.fetch = undefined;
globalThis.DOMParser = class DOMParser {};
globalThis.location = new URL('https://example.test/client.html');
const {
  OmemoManager,
  cryptoUtilities,
  validateEncryptedAttachmentUrl,
} = await import('../web/omemo.js');

assert.equal(
  validateEncryptedAttachmentUrl('https://example.test/uploads/final.bin'),
  'https://example.test/uploads/final.bin',
  'same-origin attachment redirect endpoint should remain authorized',
);
assert.throws(
  () => validateEncryptedAttachmentUrl('https://cdn.example.net/uploads/final.bin'),
  /跨域|cross-origin/i,
  'cross-origin HTTPS attachment redirect endpoint must be rejected',
);
const { validateTransferredOmemoState } = await import('../web/omemo-state-validation.mjs');
const {
  InMemoryStore,
  KeyHelper,
  OMEMOAddress,
  SessionBuilder,
  SessionCipher,
  SessionRecord,
  curvePubKeyToEd25519PubKey,
} = await import('../web/crypto/libomemo.js');

const PROFILE = 'urn:xmpp:omemo:2';

{
  const fragment = '00'.repeat(44);
  assert.equal(
    cryptoUtilities.parseAesGcmBody(`aesgcm://example.test/uploads/opaque.bin#${fragment}`).url,
    'https://example.test/uploads/opaque.bin',
  );
  assert.throws(
    () => cryptoUtilities.parseAesGcmBody(`aesgcm://uploads.example.net/opaque.bin#${fragment}`),
    /跨域地址/,
    'legacy encrypted attachment metadata authorized a cross-origin fetch',
  );
}

function protobufVarint(value) {
  const encoded = [];
  let current = BigInt(value);
  do {
    let byte = Number(current & 0x7fn);
    current >>= 7n;
    if (current) byte |= 0x80;
    encoded.push(byte);
  } while (current);
  return encoded;
}

function protobufField(field, wire, value) {
  const tag = protobufVarint((field << 3) | wire);
  if (wire === 0) return [...tag, ...protobufVarint(value)];
  const bytes = value instanceof Uint8Array ? value : Uint8Array.from(value);
  return [...tag, ...protobufVarint(bytes.length), ...bytes];
}

function omemoKeyExchangeFixture({ prekey = 1, duplicatePrekey = false, identityLength = 32 } = {}) {
  const fields = [
    ...protobufField(1, 0, prekey),
    ...(duplicatePrekey ? protobufField(1, 0, 2) : []),
    ...protobufField(2, 0, 3),
    ...protobufField(3, 2, new Uint8Array(identityLength)),
    ...protobufField(4, 2, new Uint8Array(32)),
    ...protobufField(5, 2, Uint8Array.of(1)),
  ];
  return Uint8Array.from(fields);
}

cryptoUtilities.requireOmemoKeyExchangePreKey(omemoKeyExchangeFixture());
assert.throws(
  () => cryptoUtilities.requireOmemoKeyExchangePreKey(omemoKeyExchangeFixture({ prekey: 0 })),
  /one-time PreKey/,
  'an X3DH exchange without its mandatory one-time PreKey was accepted',
);
assert.throws(
  () => cryptoUtilities.requireOmemoKeyExchangePreKey(omemoKeyExchangeFixture({ duplicatePrekey: true })),
  /repeats required field/,
  'a duplicated OMEMO key-exchange field was accepted',
);
assert.throws(
  () => cryptoUtilities.requireOmemoKeyExchangePreKey(omemoKeyExchangeFixture({ identityLength: 31 })),
  /required key material/,
  'an invalid OMEMO key-exchange identity key length was accepted',
);
const stripCurvePrefix = (buffer) => (buffer.byteLength === 33 ? buffer.slice(1) : buffer);

function managerFor(account = 'alice@example.test') {
  const manager = new OmemoManager({}, account);
  manager.state = {
    identities: {},
    trustDecisions: {},
    pendingTrustMessages: [],
    lastTrustTimestamps: {},
    sessions: {},
  };
  manager.store = { persist: async () => {} };
  return manager;
}

function encodedPair(pair) {
  const encode = (value) => btoa(String.fromCharCode(...new Uint8Array(value)));
  return { pubKey: encode(pair.pubKey), privKey: encode(pair.privKey) };
}

async function persistedStateFixture({ recoveryTransfer } = {}) {
  const identity = await KeyHelper.generateIdentityKeyPair();
  const signed = await KeyHelper.generateSignedPreKey(identity, 1, PROFILE);
  const prekey = await KeyHelper.generatePreKey(1);
  const encode = (value) => btoa(String.fromCharCode(...new Uint8Array(value)));
  return {
    version: 5,
    deviceId: 701,
    deviceIdExpanded: true,
    identityKeyPair: encodedPair(identity),
    signedPreKey: {
      id: signed.keyId,
      keyPair: encodedPair(signed.keyPair),
      signature: encode(signed.signature),
      createdAt: new Date().toISOString(),
    },
    oldSignedPreKeys: [],
    prekeys: { 1: encodedPair(prekey.keyPair) },
    retiredPrekeys: {},
    identities: {},
    trustDecisions: {},
    pendingTrustMessages: [],
    lastTrustTimestamps: {},
    sessions: {},
    nextPreKeyId: 2,
    ...(recoveryTransfer ? { recoveryTransfer } : {}),
  };
}

{
  // A legacy plaintext record must become one authenticated IndexedDB value
  // before recovery authority is contacted. If the network then fails or the
  // tab crashes, the next process can only reopen the sealed record.
  const account = 'legacy@example.test';
  const legacy = await persistedStateFixture({
    recoveryTransfer: {
      transferId: '123e4567-e89b-42d3-a456-426614174000',
      role: 'source',
      generation: 1,
      packageSha256: 'a'.repeat(64),
      phase: 'server-prepared',
      pollSecret: 'A'.repeat(43),
      baselineGeneration: 0,
    },
  });
  const wrappingKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const events = [];
  let durableRecord = legacy;
  await cryptoUtilities.replaceLegacyPlaintextState(
    account,
    legacy,
    wrappingKey,
    async (store, key, sealed) => {
      assert.equal(store, 'crypto');
      assert.equal(key, account);
      assert.equal(sealed.sealedVersion, 1);
      events.push('sealed-write');
      durableRecord = sealed;
    },
  );
  await assert.rejects((async () => {
    events.push('authority-network');
    throw new Error('simulated recovery authority outage');
  })(), /simulated recovery authority outage/);
  assert.deepEqual(events, ['sealed-write', 'authority-network']);
  assert.equal(durableRecord.sealedVersion, 1, 'network failure restored the plaintext legacy record');
  const reopened = await cryptoUtilities.unsealState(account, durableRecord, wrappingKey);
  assert.deepEqual(reopened, legacy, 'a crash after sealing could not reopen the migrated OMEMO state');
  assert.equal(cryptoUtilities.validatePersistedOmemoState(reopened), reopened);

  let invalidWrite = false;
  await assert.rejects(
    cryptoUtilities.replaceLegacyPlaintextState(
      account,
      { ...legacy, prekeys: {} },
      wrappingKey,
      async () => { invalidWrite = true; },
    ),
    /prekey count is invalid/i,
  );
  assert.equal(invalidWrite, false, 'malformed plaintext state was sealed before validation');
}

{
  const manager = managerFor();
  manager.state.deviceId = 1;
  const fetches = [];
  manager.fetchDeviceIds = async (jid, useCache) => {
    fetches.push([jid, useCache]);
    return jid === 'alice@example.test' ? [1, 2] : [3];
  };
  manager.fetchBundle = async (jid, id) => ({ jid, id, identityKey: 'unused' });
  manager.identityState = () => ({ trustState: 'verified' });
  manager.ensureSession = async () => {};
  const selection = await manager.devicesForChat('bob@example.test', { refresh: true });
  assert.deepEqual(fetches, [
    ['bob@example.test', false],
    ['alice@example.test', false],
  ], 'outbound device selection did not refresh the peer and own endpoint lists together');
  assert.deepEqual(selection.bundles.map(({ jid, id }) => [jid, id]), [
    ['bob@example.test', 3],
    ['alice@example.test', 2],
  ]);
}

{
  // Two newly-created resources can both read an empty device list before
  // either publishes. Every convergence round must bypass cache, merge the
  // latest server value, publish, and confirm so last-writer-wins does not
  // strand either valid bundle.
  let serverIds = [];
  const firstReaders = [];
  const cacheArguments = [];
  const managers = [101, 202].map((deviceId) => {
    const manager = managerFor();
    manager.state.deviceId = deviceId;
    let firstRead = true;
    manager.fetchDeviceIds = async (_jid, useCache) => {
      cacheArguments.push(useCache);
      if (firstRead) {
        firstRead = false;
        await new Promise((resolve) => {
          firstReaders.push(resolve);
          if (firstReaders.length === 2) firstReaders.splice(0).forEach((release) => release());
        });
        return [];
      }
      return [...serverIds];
    };
    manager.publishDeviceList = async (ids) => { serverIds = [...ids]; };
    manager.deviceAnnouncementDelay = async () => {};
    return manager;
  });
  const confirmations = await Promise.all(managers.map((manager) => manager.ensureDeviceAnnouncement([])));
  assert.deepEqual(serverIds, [101, 202], 'concurrent device-list publications did not converge');
  assert(confirmations[0].includes(101) && confirmations[1].includes(202));
  assert(cacheArguments.every((useCache) => useCache === false), 'a convergence read used the PEP cache');
}

{
  // A sender must repair a list overwrite before selecting recipients. It may
  // only do so while its own public bundle still exists; intentional remote
  // retirement is handled separately and must not be resurrected.
  const manager = managerFor();
  manager.state.deviceId = 7;
  let ownServerIds = [8];
  manager.fetchDeviceIds = async (jid, useCache) => {
    assert.equal(useCache, false);
    return jid === 'alice@example.test' ? [...ownServerIds] : [9];
  };
  manager.publishDeviceList = async (ids) => { ownServerIds = [...ids]; };
  manager.deviceAnnouncementDelay = async () => {};
  manager.deviceRetirementGrace = async () => {};
  manager.fetchBundle = async (jid, id) => ({ jid, id, identityKey: 'unused' });
  manager.identityState = () => ({ trustState: 'verified' });
  const selection = await manager.devicesForChat('bob@example.test', {
    refresh: true,
    establishSessions: false,
  });
  assert.deepEqual(ownServerIds, [7, 8], 'send preflight failed to reannounce the current device');
  assert.deepEqual(selection.bundles.map(({ jid, id }) => [jid, id]), [
    ['bob@example.test', 9],
    ['alice@example.test', 8],
  ]);
}

{
  // Account-wide retirement publishes the shortened list before retracting
  // the bundle. A send in that bounded window must wait, force-refresh, and
  // observe the missing bundle instead of resurrecting the retired device.
  const manager = managerFor();
  manager.state.deviceId = 7;
  let bundleExists = true;
  let announcementCalls = 0;
  manager.deviceRetirementGrace = async () => { bundleExists = false; };
  manager.fetchDeviceIds = async (_jid, useCache) => {
    assert.equal(useCache, false);
    return [8];
  };
  manager.fetchBundle = async () => {
    if (!bundleExists) throw new Error('item-not-found');
    return { jid: manager.account, id: 7, identityKey: 'unused' };
  };
  manager.ensureDeviceAnnouncement = async () => {
    announcementCalls += 1;
    return [7, 8];
  };
  let retiredDevice = null;
  manager.completeRemoteRetirement = async (deviceId) => { retiredDevice = deviceId; };
  await assert.rejects(
    manager.ensureOwnDeviceForSend([8]),
    (error) => error?.code === 'OMEMO_DEVICE_RETIRED' && error.deviceId === 7,
  );
  assert.equal(retiredDevice, 7, 'send-time retirement did not invoke local key erasure');
  assert.equal(announcementCalls, 0, 'send-time retirement resurrected a removed device');
}

{
  // Exercise the vendored OMEMO:2 implementation itself: authenticated X3DH
  // with a mandatory one-time prekey, both ratchet directions, skipped-key
  // delivery, duplicate rejection, and ciphertext authentication.
  const aliceStore = new InMemoryStore();
  const bobStore = new InMemoryStore();
  const aliceIdentity = await KeyHelper.generateIdentityKeyPair();
  const bobIdentity = await KeyHelper.generateIdentityKeyPair();
  const bobSigned = await KeyHelper.generateSignedPreKey(bobIdentity, 1, PROFILE);
  const bobPrekey = await KeyHelper.generatePreKey(1);
  aliceStore.put('identityKey', aliceIdentity);
  aliceStore.put('registrationId', 101);
  bobStore.put('identityKey', bobIdentity);
  bobStore.put('registrationId', 202);
  bobStore.storeSignedPreKey(bobSigned.keyId, bobSigned.keyPair);
  bobStore.storePreKey(bobPrekey.keyId, bobPrekey.keyPair);

  const bobAddress = new OMEMOAddress('bob@example.test', 202);
  await new SessionBuilder(aliceStore, bobAddress, PROFILE).processPreKey({
    registrationId: 202,
    identityKey: await curvePubKeyToEd25519PubKey(bobIdentity.pubKey),
    signedPreKey: {
      keyId: bobSigned.keyId,
      publicKey: stripCurvePrefix(bobSigned.keyPair.pubKey),
      signature: bobSigned.signature,
    },
    preKey: { keyId: bobPrekey.keyId, publicKey: stripCurvePrefix(bobPrekey.keyPair.pubKey) },
  });
  const first = await new SessionCipher(aliceStore, bobAddress, PROFILE).encrypt('first');
  assert.equal(first.kex, true, 'the first OMEMO:2 message must carry a prekey exchange');
  cryptoUtilities.requireOmemoKeyExchangePreKey(first.body);
  const aliceAddress = new OMEMOAddress('alice@example.test', 101);
  const bobCipher = new SessionCipher(bobStore, aliceAddress, PROFILE);
  assert.equal(
    new TextDecoder().decode((await bobCipher.decryptPreKeyWhisperMessage(first.body, 'binary')).plaintext),
    'first',
  );
  assert.equal(await bobStore.loadPreKey(bobPrekey.keyId), undefined, 'the used one-time prekey must be consumed');
  const serializedSession = await aliceStore.loadSession(bobAddress.toString());
  const aliceSigned = await KeyHelper.generateSignedPreKey(aliceIdentity, 1, PROFILE);
  const alicePrekey = await KeyHelper.generatePreKey(1);
  const encode = (value) => btoa(String.fromCharCode(...new Uint8Array(value)));
  const pair = (value) => ({ pubKey: encode(value.pubKey), privKey: encode(value.privKey) });
  const transferred = {
    version: 5,
    deviceId: 101,
    deviceIdExpanded: true,
    identityKeyPair: pair(aliceIdentity),
    signedPreKey: {
      id: 1,
      keyPair: pair(aliceSigned.keyPair),
      signature: encode(aliceSigned.signature),
      createdAt: new Date().toISOString(),
    },
    oldSignedPreKeys: [],
    prekeys: { 1: pair(alicePrekey.keyPair) },
    retiredPrekeys: {},
    identities: {},
    trustDecisions: {},
    pendingTrustMessages: [],
    lastTrustTimestamps: {},
    sessions: { [bobAddress.toString()]: serializedSession },
    nextPreKeyId: 2,
  };
  const sessionAdapter = (serialized) => {
    const record = SessionRecord.deserialize(serialized);
    return { canonical: record.serialize(), ratchets: record.getSessions() };
  };
  assert.equal(validateTransferredOmemoState(transferred, 101, sessionAdapter), transferred,
    'a real non-empty pinned-libomemo SessionRecord was rejected');
  assert.throws(() => validateTransferredOmemoState(transferred, 101, (serialized) => {
    const decoded = sessionAdapter(serialized);
    decoded.ratchets[0].currentRatchet.rootKey = new ArrayBuffer(0);
    return decoded;
  }), /root key.*invalid key material/i, 'zero-length required ratchet key material was accepted');
  const invalidTrust = { ...transferred, trustDecisions: {
    [bobAddress.toString()]: { state: 'verified', updatedAt: 'not-a-time', accepted: 'yes' },
  } };
  assert.throws(() => validateTransferredOmemoState(invalidTrust, 101, sessionAdapter), /trust accepted is invalid/i,
    'malformed trust-decision types were accepted');

  const reply = await bobCipher.encrypt('reply');
  assert.equal(reply.kex, false);
  const aliceCipher = new SessionCipher(aliceStore, bobAddress, PROFILE);
  assert.equal(new TextDecoder().decode((await aliceCipher.decryptWhisperMessage(reply.body, 'binary')).plaintext), 'reply');

  const delayed = await Promise.all(['one', 'two', 'three'].map((value) => aliceCipher.encrypt(value)));
  assert.equal(new TextDecoder().decode((await bobCipher.decryptWhisperMessage(delayed[2].body, 'binary')).plaintext), 'three');
  assert.equal(new TextDecoder().decode((await bobCipher.decryptWhisperMessage(delayed[0].body, 'binary')).plaintext), 'one');
  assert.equal(new TextDecoder().decode((await bobCipher.decryptWhisperMessage(delayed[1].body, 'binary')).plaintext), 'two');
  await assert.rejects(bobCipher.decryptWhisperMessage(delayed[1].body, 'binary'), (error) => error.name === 'MessageCounterError');

  const tampered = await aliceCipher.encrypt('authenticated');
  const tamperedBytes = Uint8Array.from(tampered.body, (character) => character.charCodeAt(0));
  tamperedBytes[tamperedBytes.length - 1] ^= 1;
  const tamperedBody = String.fromCharCode(...tamperedBytes);
  await assert.rejects(bobCipher.decryptWhisperMessage(tamperedBody, 'binary'));
  assert.equal(
    new TextDecoder().decode((await bobCipher.decryptWhisperMessage(tampered.body, 'binary')).plaintext),
    'authenticated',
    'a failed authentication attempt must not corrupt or reset the ratchet',
  );
}

{
  const manager = managerFor();
  const events = [];
  await Promise.all([
    manager.withSessionOperation('bob@example.test.7', async () => {
      events.push('first:start');
      await new Promise((resolve) => setTimeout(resolve, 20));
      events.push('first:end');
    }),
    manager.withSessionOperation('bob@example.test.7', async () => events.push('second')),
  ]);
  assert.deepEqual(events, ['first:start', 'first:end', 'second']);

  await assert.rejects(manager.withSessionOperation('bob@example.test.7', async () => {
    throw new Error('expected failure');
  }), /expected failure/);
  await manager.withSessionOperation('bob@example.test.7', async () => events.push('after-failure'));
  assert.equal(events.at(-1), 'after-failure');
}

{
  const manager = managerFor();
  let finishOperation;
  let released = false;
  const operation = new Promise((resolve) => { finishOperation = resolve; });
  manager.sessionOperations.set('bob@example.test.7', operation);
  manager.store.flush = async () => {};
  manager.releaseStateLock = () => { released = true; };
  const teardown = manager.destroy();
  assert.notEqual(manager.state, null, 'teardown must not invalidate state used by an in-flight ratchet');
  assert.equal(released, false, 'the exclusive state lock must stay held during teardown');
  finishOperation();
  await teardown;
  assert.equal(manager.state, null);
  assert.equal(released, true);
}

{
  const manager = managerFor();
  let captured;
  manager.encrypt = async (peer, body, options) => {
    captured = { peer, body, ...options };
    return { xml: '<encrypted/>', failures: [] };
  };
  await manager.encryptOptOut('bob@example.test', 'server archive requested');
  assert.equal(captured.peer, 'bob@example.test');
  assert.equal(captured.body, '');
  assert.match(captured.contentXml, /<opt-out xmlns='urn:xmpp:omemo:2'><reason>server archive requested<\/reason><\/opt-out>/);
  await assert.rejects(manager.encryptOptOut('bob@example.test', 'x'.repeat(1025)), /too long/);
}

{
  const manager = managerFor();
  const identity = Buffer.alloc(32).toString('base64');
  manager.fetchDeviceIds = async () => [8];
  manager.fetchBundle = async (jid, id) => ({ jid, id, identityKey: identity });
  manager.state.trustDecisions['bob@example.test.8'] = {
    identity,
    state: 'distrusted',
    updatedAt: new Date(Date.now() - 10_000).toISOString(),
  };

  await manager.applyTrustMessage(
    'bob@example.test.7',
    new Date(Date.now() - 2000).toISOString(),
    [{ jid: 'mallory@example.test', entries: [{ identity, state: 'verified' }] }],
    true,
  );
  assert.equal(manager.state.trustDecisions['mallory@example.test.8'], undefined,
    'a contact endpoint must not authenticate a third-party account');

  await manager.applyTrustMessage(
    'bob@example.test.7',
    new Date(Date.now() - 1000).toISOString(),
    [{ jid: 'bob@example.test', entries: [{ identity, state: 'verified' }] }],
    true,
  );
  assert.equal(manager.state.trustDecisions['bob@example.test.8'].state, 'distrusted',
    'ATM must not overwrite a manual local decision');

  await assert.rejects(manager.applyTrustMessage(
    'bob@example.test.7',
    new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    [{ jid: 'bob@example.test', entries: [{ identity, state: 'verified' }] }],
    true,
  ), /too far in the future/);

  manager.state.trustDecisions['bob@example.test.8'] = {
    identity,
    state: 'verified',
    updatedAt: new Date(Date.now() - 500).toISOString(),
  };
  await manager.applyTrustMessage(
    'bob@example.test.7',
    new Date().toISOString(),
    [{ jid: 'bob@example.test', entries: [{ identity, state: 'distrusted' }] }],
    true,
  );
  assert.equal(manager.state.trustDecisions['bob@example.test.8'].state, 'distrusted',
    'an authenticated revocation must fail closed even after a manual verification');

  await assert.rejects(manager.applyTrustMessage(
    'bob@example.test.7',
    new Date().toISOString(),
    [{
      jid: 'bob@example.test',
      entries: Array.from({ length: 8193 }, () => ({ identity, state: 'verified' })),
    }],
    false,
  ), /safety limit/);

  const pending = Array.from({ length: 70 }, (_, index) => ({
    senderAddress: `bob@example.test.${index + 1}`,
    timestamp: new Date(Date.now() - (70 - index) * 1000).toISOString(),
    owners: [{ jid: 'bob@example.test', entries: [{ identity, state: 'verified' }] }],
  }));
  assert.equal(manager.trimPendingTrustMessages(pending).length, 64,
    'pending trust replay state must have a hard message limit');
}

{
  const manager = managerFor();
  manager.ready = true;
  const newOwnIdentity = Buffer.alloc(32, 4).toString('base64');
  const oldOwnIdentity = Buffer.alloc(32, 5).toString('base64');
  const contactIdentity = Buffer.alloc(32, 6).toString('base64');
  manager.verifiedIdentityMap = async () => new Map([
    ['alice@example.test', new Set([oldOwnIdentity, newOwnIdentity])],
    ['bob@example.test', new Set([contactIdentity])],
  ]);
  const sent = [];
  manager.sendTrustMessage = async (target, owners) => sent.push({ target, owners });
  manager.scheduleTrustPropagation('alice@example.test', newOwnIdentity, 'verified');
  await manager.trustFanout;
  const contactMessage = sent.find(({ target }) => target === 'bob@example.test');
  assert.deepEqual(contactMessage.owners, [{
    jid: 'alice@example.test',
    entries: [{ identity: newOwnIdentity, state: 'verified' }],
  }], 'ATM must not disclose unrelated trust decisions to a contact');
  assert(sent.find(({ target }) => target === 'alice@example.test').owners.length > 1,
    'authenticated own endpoints should receive the complete catch-up trust graph');
}

{
  const manager = managerFor();
  const identity = Buffer.alloc(32, 1).toString('base64');
  const bundle = { jid: 'bob@example.test', id: 9, identityKey: identity };
  assert.equal(manager.identityState(bundle).trustState, 'untrusted');
  manager.state.identities['bob@example.test.9'] = identity;
  manager.state.trustDecisions['bob@example.test.9'] = {
    identity,
    state: 'tofu',
    accepted: false,
  };
  assert.equal(manager.identityState(bundle).trustState, 'untrusted');
  manager.state.trustDecisions['bob@example.test.9'].accepted = true;
  assert.equal(manager.identityState(bundle).trustState, 'tofu');
  manager.state.trustDecisions['bob@example.test.9'].state = 'verified';
  assert.equal(manager.identityState(bundle).trustState, 'verified');
  assert.equal(manager.identityState({ ...bundle, identityKey: Buffer.alloc(32, 2).toString('base64') }).trustState, 'changed');
}

{
  // Device provisioning publishes a healthy reserve instead of the protocol
  // minimum, and replenishment must never reuse a still-retained one-time key.
  const manager = managerFor();
  let persists = 0;
  manager.state = {
    deviceId: 700,
    identityKeyPair: null,
    signedPreKey: null,
    oldSignedPreKeys: [],
    prekeys: {},
    retiredPrekeys: {},
    nextPreKeyId: 101,
    identities: {},
    trustDecisions: {},
    sessions: {},
  };
  manager.store = { persist: async () => { persists += 1; } };
  await manager.provision();
  assert.equal(Object.keys(manager.state.prekeys).length, 100);
  assert.equal(new Set(Object.keys(manager.state.prekeys)).size, 100);
  assert.equal(Buffer.from(manager.state.signedPreKey.signature, 'base64').byteLength, 64);

  const retired = manager.state.prekeys['1'];
  manager.state.retiredPrekeys['1'] = {
    keyPair: retired,
    retiredAt: new Date().toISOString(),
  };
  delete manager.state.prekeys['1'];
  for (let id = 2; id <= 26; id += 1) delete manager.state.prekeys[String(id)];
  manager.state.nextPreKeyId = 1;
  assert.equal(await manager.ensurePrekeys(), true);
  assert.equal(Object.keys(manager.state.prekeys).length, 100);
  assert.equal(manager.state.prekeys['1'], undefined, 'a retained one-time prekey was reused');
  assert.equal(manager.state.retiredPrekeys['1'].keyPair, retired);

  const oldSigned = manager.state.signedPreKey;
  oldSigned.createdAt = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString();
  assert.equal(await manager.rotateSignedPreKeyIfNeeded(), true);
  assert.notEqual(manager.state.signedPreKey.id, oldSigned.id);
  assert(manager.state.oldSignedPreKeys.some(({ id }) => id === oldSigned.id));
  assert.equal(await manager.rotateSignedPreKeyIfNeeded(), false, 'a fresh signed prekey rotated again');
  assert(persists >= 3, 'lifecycle changes were not durably staged');
}

{
  // Removing another endpoint must first remove it from the account device
  // list, retract its public bundle, remember a fail-closed distrust decision,
  // and invalidate sessions with the account's other endpoints.
  const manager = managerFor();
  const identity = Buffer.alloc(32, 9).toString('base64');
  manager.ready = true;
  manager.state.deviceId = 7;
  manager.state.sessions = {
    'alice@example.test.8': { ratchet: true },
    'bob@example.test.9': { ratchet: true },
  };
  let publishedIds = [7, 8];
  manager.fetchDeviceIds = async () => [...publishedIds];
  manager.fetchBundle = async (jid, id) => ({ jid, id, identityKey: identity });
  const calls = [];
  manager.publishDeviceList = async (ids) => {
    publishedIds = [...ids];
    calls.push(['list', ids]);
  };
  manager.xmpp = { retractPep: async (node, id) => calls.push(['retract', node, id]) };
  manager.store = {
    persist: async () => {},
    removeAllSessions: async (prefix) => {
      calls.push(['sessions', prefix]);
      for (const address of Object.keys(manager.state.sessions)) {
        if (address.startsWith(prefix)) delete manager.state.sessions[address];
      }
    },
  };
  await manager.retireOtherOwnDevice(8);
  assert.deepEqual(calls[0], ['list', [7]]);
  assert.deepEqual(calls[1].slice(0, 2), ['retract', 'urn:xmpp:omemo:2:bundles']);
  assert.deepEqual(calls[2], ['sessions', 'alice@example.test.']);
  assert.equal(manager.state.trustDecisions['alice@example.test.8'].state, 'distrusted');
  assert.equal(manager.state.sessions['alice@example.test.8'], undefined);
  assert.deepEqual(manager.state.sessions['bob@example.test.9'], { ratchet: true });
}

{
  // A stale device whose bundle disappeared must remain removable. The
  // address-level distrust tombstone also rejects later inbound traffic from
  // that retired id until the user explicitly reviews it again.
  const manager = managerFor();
  manager.state.deviceId = 7;
  let staleIds = [7, 8];
  manager.fetchDeviceIds = async () => [...staleIds];
  manager.fetchBundle = async () => { throw new Error('item-not-found'); };
  let removedSessions = false;
  manager.publishDeviceList = async (ids) => {
    assert.deepEqual(ids, [7]);
    staleIds = [...ids];
  };
  manager.xmpp = { retractPep: async () => {} };
  manager.store = {
    removeAllSessions: async () => { removedSessions = true; },
  };
  await manager.retireOtherOwnDevice(8);
  assert.equal(manager.state.trustDecisions['alice@example.test.8'].state, 'distrusted');
  assert.equal(manager.state.trustDecisions['alice@example.test.8'].identity, undefined);
  assert.equal(removedSessions, true);
  await assert.rejects(manager.retireOtherOwnDevice(0), /超出允许范围/);
  await assert.rejects(manager.retireOtherOwnDevice(0x80000000), /超出允许范围/);
}

{
  // Self-retirement is intentionally fail closed: publication and public
  // bundle removal complete before the manager stops accepting new sends.
  const manager = managerFor();
  manager.ready = true;
  manager.state.deviceId = 7;
  let ownIds = [4, 7, 9];
  manager.fetchDeviceIds = async () => [...ownIds];
  const calls = [];
  manager.publishDeviceList = async (ids) => {
    ownIds = [...ids];
    calls.push(['list', ids]);
  };
  manager.xmpp = { retractPep: async (node, id) => calls.push(['retract', node, id]) };
  await manager.retireOwnDevice();
  assert.deepEqual(calls[0], ['list', [4, 9]]);
  assert.equal(calls[1][2], '7');
  assert.equal(manager.ready, false);
  assert.equal(manager.retiring, true);
}

console.log('OMEMO security behavior tests passed');
