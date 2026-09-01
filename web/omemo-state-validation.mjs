const MAX_DEVICE_ID = 0x7fffffff;
const MAX_PREKEYS = 1000;
const MAX_RETIRED_PREKEYS = 100;
const MAX_IDENTITIES = 8192;
const MAX_SESSIONS = 8192;
const MAX_SESSION_BYTES = 1024 * 1024;
const STATE_VERSION = 5;

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function exactKeys(value, allowed, required, label) {
  object(value, label);
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key))
    || required.some((key) => !Object.hasOwn(value, key))) {
    throw new Error(`${label} has an unsupported schema`);
  }
}

function integer(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function timestamp(value, label) {
  if (typeof value !== 'string' || value.length > 40
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${label} is invalid`);
  }
}

function base64Bytes(value, allowedLengths, label) {
  if (typeof value !== 'string' || value.length > 512 || /\s/.test(value)) {
    throw new Error(`${label} is not canonical Base64`);
  }
  let binary;
  try { binary = atob(value); } catch { throw new Error(`${label} is not valid Base64`); }
  if (!allowedLengths.includes(binary.length)
    || btoa(binary) !== value) {
    throw new Error(`${label} has an invalid length or encoding`);
  }
}

function keyPair(value, label) {
  exactKeys(value, ['pubKey', 'privKey'], ['pubKey', 'privKey'], label);
  base64Bytes(value.pubKey, [33], `${label}.pubKey`);
  base64Bytes(value.privKey, [32], `${label}.privKey`);
}

function keyId(value, label) {
  if (!/^(?:[1-9][0-9]{0,9})$/.test(value)) throw new Error(`${label} is invalid`);
  return integer(Number(value), 1, MAX_DEVICE_ID, label);
}

function signedPreKey(value, { retired = false } = {}) {
  const allowed = retired
    ? ['id', 'keyPair', 'signature', 'createdAt', 'expiresAt']
    : ['id', 'keyPair', 'signature', 'createdAt'];
  exactKeys(value, allowed, allowed, 'OMEMO signed prekey');
  integer(value.id, 1, MAX_DEVICE_ID, 'OMEMO signed prekey ID');
  keyPair(value.keyPair, 'OMEMO signed prekey pair');
  base64Bytes(value.signature, [64], 'OMEMO signed prekey signature');
  timestamp(value.createdAt, 'OMEMO signed prekey creation time');
  if (retired) timestamp(value.expiresAt, 'OMEMO signed prekey expiry');
}

function addressKey(value, label) {
  if (typeof value !== 'string' || value.length > 3100
    || !/^.+\.[1-9][0-9]{0,9}$/.test(value)) {
    throw new Error(`${label} is invalid`);
  }
}

function buffer(value, length, label, { optional = false } = {}) {
  if (optional && value === undefined) return;
  if (!(value instanceof ArrayBuffer) || value.byteLength !== length || length === 0) {
    throw new Error(`${label} has invalid key material`);
  }
}

function validateSession(session) {
  const fixed = ['registrationId', 'protocolVersion', 'ad', 'currentRatchet', 'indexInfo', 'oldRatchetList'];
  const optional = ['pendingPreKey'];
  object(session, 'OMEMO session');
  for (const key of fixed) {
    if (!Object.hasOwn(session, key) || session[key] === undefined) {
      throw new Error(`OMEMO session is missing ${key}`);
    }
  }
  integer(session.registrationId, 1, 0xffffffff, 'OMEMO remote registration ID');
  if (session.protocolVersion !== 'urn:xmpp:omemo:2') throw new Error('OMEMO session profile is invalid');
  buffer(session.ad, 64, 'OMEMO associated data');

  exactKeys(session.currentRatchet,
    ['rootKey', 'lastRemoteEphemeralKey', 'previousCounter', 'ephemeralKeyPair'],
    ['rootKey', 'lastRemoteEphemeralKey', 'previousCounter', 'ephemeralKeyPair'],
    'OMEMO current ratchet');
  buffer(session.currentRatchet.rootKey, 32, 'OMEMO ratchet root key');
  buffer(session.currentRatchet.lastRemoteEphemeralKey, 33, 'OMEMO remote ephemeral key');
  integer(session.currentRatchet.previousCounter, 0, 0xffffffff, 'OMEMO previous counter');
  const ephemeral = session.currentRatchet.ephemeralKeyPair;
  exactKeys(ephemeral, ['pubKey', 'privKey'], ['pubKey', 'privKey'], 'OMEMO ephemeral key pair');
  buffer(ephemeral.pubKey, 33, 'OMEMO ephemeral public key');
  buffer(ephemeral.privKey, 32, 'OMEMO ephemeral private key');

  exactKeys(session.indexInfo,
    ['baseKey', 'baseKeyType', 'closed', 'remoteIdentityKey', 'remoteIdentityKeyEd'],
    ['baseKey', 'baseKeyType', 'closed', 'remoteIdentityKey'], 'OMEMO session index');
  buffer(session.indexInfo.baseKey, 33, 'OMEMO base key');
  if (![1, 2].includes(session.indexInfo.baseKeyType)) throw new Error('OMEMO base-key type is invalid');
  integer(session.indexInfo.closed, -1, Number.MAX_SAFE_INTEGER, 'OMEMO closed timestamp');
  buffer(session.indexInfo.remoteIdentityKey, 33, 'OMEMO remote identity key');
  buffer(session.indexInfo.remoteIdentityKeyEd, 32, 'OMEMO remote Ed25519 identity key', { optional: true });

  if (!Array.isArray(session.oldRatchetList) || session.oldRatchetList.length > 64) {
    throw new Error('OMEMO old-ratchet list is invalid');
  }
  for (const entry of session.oldRatchetList) {
    exactKeys(entry, ['added', 'ephemeralKey'], ['added', 'ephemeralKey'], 'OMEMO old ratchet');
    integer(entry.added, 0, Number.MAX_SAFE_INTEGER, 'OMEMO old-ratchet timestamp');
    buffer(entry.ephemeralKey, 33, 'OMEMO old-ratchet ephemeral key');
  }

  if (session.pendingPreKey !== undefined) {
    exactKeys(session.pendingPreKey, ['signedKeyId', 'baseKey', 'preKeyId'],
      ['signedKeyId', 'baseKey'], 'OMEMO pending prekey');
    integer(session.pendingPreKey.signedKeyId, 1, MAX_DEVICE_ID, 'OMEMO pending signed-prekey ID');
    if (session.pendingPreKey.preKeyId !== undefined) {
      integer(session.pendingPreKey.preKeyId, 1, MAX_DEVICE_ID, 'OMEMO pending prekey ID');
    }
    buffer(session.pendingPreKey.baseKey, 33, 'OMEMO pending base key');
  }

  const chains = Object.entries(session)
    .filter(([key]) => !fixed.includes(key) && !optional.includes(key));
  if (!chains.length || chains.length > 64) throw new Error('OMEMO session chain count is invalid');
  for (const [, chain] of chains) {
    exactKeys(chain, ['messageKeys', 'chainKey', 'chainType'],
      ['messageKeys', 'chainKey', 'chainType'], 'OMEMO chain');
    if (![1, 2].includes(chain.chainType)) throw new Error('OMEMO chain type is invalid');
    exactKeys(chain.chainKey, ['counter', 'key'], ['counter'], 'OMEMO chain key');
    integer(chain.chainKey.counter, -1, 0xffffffff, 'OMEMO chain counter');
    buffer(chain.chainKey.key, 32, 'OMEMO chain key', { optional: true });
    const messages = Object.entries(object(chain.messageKeys, 'OMEMO message keys'));
    if (messages.length > 2000) throw new Error('OMEMO skipped-message keys are oversized');
    for (const [counter, key] of messages) {
      if (!/^(?:0|[1-9][0-9]{0,9})$/.test(counter)) throw new Error('OMEMO message-key counter is invalid');
      integer(Number(counter), 0, 0xffffffff, 'OMEMO message-key counter');
      buffer(key, 32, 'OMEMO skipped-message key');
    }
  }
}

export function validateTransferredOmemoState(state, expectedDeviceId, deserializeSession) {
  const required = [
    'version', 'deviceId', 'deviceIdExpanded', 'identityKeyPair', 'signedPreKey',
    'prekeys', 'retiredPrekeys', 'identities', 'trustDecisions',
    'pendingTrustMessages', 'lastTrustTimestamps', 'sessions', 'nextPreKeyId',
    'oldSignedPreKeys',
  ];
  exactKeys(state, [...required, 'legacyDeviceId'], required, 'Transferred OMEMO state');
  if (state.version !== STATE_VERSION) throw new Error('Transferred OMEMO state version is unsupported');
  integer(state.deviceId, 1, MAX_DEVICE_ID, 'Transferred OMEMO device ID');
  if (state.deviceId !== Number(expectedDeviceId) || state.deviceIdExpanded !== true) {
    throw new Error('Transferred OMEMO device identity is inconsistent');
  }
  if (state.legacyDeviceId !== undefined) integer(state.legacyDeviceId, 0, MAX_DEVICE_ID, 'Legacy device ID');
  keyPair(state.identityKeyPair, 'OMEMO identity key pair');
  signedPreKey(state.signedPreKey);
  if (!Array.isArray(state.oldSignedPreKeys) || state.oldSignedPreKeys.length > 3) {
    throw new Error('Transferred OMEMO retired signed prekeys are invalid');
  }
  for (const value of state.oldSignedPreKeys) signedPreKey(value, { retired: true });

  const prekeys = Object.entries(object(state.prekeys, 'OMEMO prekeys'));
  if (prekeys.length < 1 || prekeys.length > MAX_PREKEYS) throw new Error('Transferred OMEMO prekey count is invalid');
  for (const [id, pair] of prekeys) {
    keyId(id, 'OMEMO prekey ID');
    keyPair(pair, 'OMEMO prekey pair');
  }
  const retired = Object.entries(object(state.retiredPrekeys, 'OMEMO retired prekeys'));
  if (retired.length > MAX_RETIRED_PREKEYS) throw new Error('Transferred OMEMO retired prekey count is invalid');
  for (const [id, entry] of retired) {
    keyId(id, 'OMEMO retired prekey ID');
    exactKeys(entry, ['keyPair', 'retiredAt'], ['keyPair', 'retiredAt'], 'OMEMO retired prekey');
    keyPair(entry.keyPair, 'OMEMO retired prekey pair');
    timestamp(entry.retiredAt, 'OMEMO retired prekey time');
  }
  integer(state.nextPreKeyId, 1, MAX_DEVICE_ID, 'OMEMO next prekey ID');

  const identities = Object.entries(object(state.identities, 'OMEMO identities'));
  if (identities.length > MAX_IDENTITIES) throw new Error('Transferred OMEMO identity count is invalid');
  for (const [address, identity] of identities) {
    addressKey(address, 'OMEMO identity address');
    base64Bytes(identity, [32, 33], 'OMEMO remote identity');
  }

  const sessions = Object.entries(object(state.sessions, 'OMEMO sessions'));
  if (sessions.length > MAX_SESSIONS) throw new Error('Transferred OMEMO session count is invalid');
  if (sessions.length && typeof deserializeSession !== 'function') {
    throw new Error('OMEMO session validator is unavailable');
  }
  for (const [address, serialized] of sessions) {
    addressKey(address, 'OMEMO session address');
    if (typeof serialized !== 'string' || serialized.length < 2
      || new TextEncoder().encode(serialized).byteLength > MAX_SESSION_BYTES) {
      throw new Error('Transferred OMEMO session encoding is invalid');
    }
    let decoded;
    try { decoded = deserializeSession(serialized); } catch {
      throw new Error('Transferred OMEMO session cannot be decoded');
    }
    if (!decoded || decoded.canonical !== serialized) {
      throw new Error('Transferred OMEMO session is not canonical');
    }
    if (!Array.isArray(decoded.ratchets) || !decoded.ratchets.length || decoded.ratchets.length > 40) {
      throw new Error('Transferred OMEMO session set is invalid');
    }
    for (const session of decoded.ratchets) validateSession(session);
  }

  if (!Array.isArray(state.pendingTrustMessages) || state.pendingTrustMessages.length > 64) {
    throw new Error('Transferred OMEMO pending trust messages are invalid');
  }
  const decisions = Object.entries(object(state.trustDecisions, 'OMEMO trust decisions'));
  if (decisions.length > MAX_IDENTITIES) throw new Error('Transferred OMEMO trust decisions are oversized');
  for (const [address, decision] of decisions) {
    addressKey(address, 'OMEMO trust address');
    exactKeys(decision,
      ['identity', 'state', 'accepted', 'updatedAt', 'automatic', 'source', 'recoveryReverification'],
      ['state', 'updatedAt'], 'OMEMO trust decision');
    if (!['tofu', 'verified', 'distrusted'].includes(decision.state)) throw new Error('OMEMO trust state is invalid');
    if (decision.identity !== undefined) base64Bytes(decision.identity, [32, 33], 'OMEMO trusted identity');
    for (const key of ['accepted', 'automatic', 'recoveryReverification']) {
      if (decision[key] !== undefined && typeof decision[key] !== 'boolean') throw new Error(`OMEMO trust ${key} is invalid`);
    }
    if (decision.source !== undefined) addressKey(decision.source, 'OMEMO trust source');
    timestamp(decision.updatedAt, 'OMEMO trust update time');
  }
  const timestamps = Object.entries(object(state.lastTrustTimestamps, 'OMEMO trust timestamps'));
  if (timestamps.length > MAX_IDENTITIES) throw new Error('Transferred OMEMO trust timestamps are oversized');
  for (const [address, value] of timestamps) {
    addressKey(address, 'OMEMO trust timestamp address');
    integer(value, 0, Number.MAX_SAFE_INTEGER, 'OMEMO trust timestamp');
  }
  return state;
}
