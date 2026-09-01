const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const OMEMO_TRANSFER_FORMAT = 'northstar-omemo-device-transfer';
export const OMEMO_TRANSFER_VERSION = 1;
export const OMEMO_TRANSFER_MAX_BYTES = 44 * 1024 * 1024;
export const OMEMO_TRANSFER_MAX_STATE_BYTES = 32 * 1024 * 1024;
export const OMEMO_TRANSFER_KDF = Object.freeze({
  name: 'Argon2id',
  version: 19,
  memory_kib: 65536,
  iterations: 3,
  parallelism: 1,
  output_bytes: 32,
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CONSUMER_COMMITMENT_DOMAIN = encoder.encode('Northstar OMEMO recovery consumer v1\0');

function exactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains missing or unsupported fields`);
  }
}

function base64UrlEncode(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function base64UrlDecode(value, expectedBytes, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} is not canonical Base64url`);
  }
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  let binary;
  try {
    binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  } catch {
    throw new Error(`${label} is not valid Base64url`);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (expectedBytes !== null && bytes.byteLength !== expectedBytes) {
    throw new Error(`${label} has an invalid length`);
  }
  if (base64UrlEncode(bytes) !== value) throw new Error(`${label} is not canonical Base64url`);
  return bytes;
}

function uuidBytes(value) {
  if (!UUID.test(value)) throw new Error('The transfer identifier is invalid');
  const compact = value.replaceAll('-', '');
  return Uint8Array.from(compact.match(/../g), (pair) => Number.parseInt(pair, 16));
}

export function newOmemoTransferSecret() {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
}

export function validateOmemoTransferSecret(value, label = 'OMEMO recovery secret') {
  const bytes = base64UrlDecode(value, 32, label);
  bytes.fill(0);
  return value;
}

export async function omemoConsumerCommitmentHex(account, transferId, consumerSecret) {
  if (typeof account !== 'string' || account.length > 3071
    || !account.includes('@') || account !== account.toLowerCase()) {
    throw new Error('The transfer account is invalid');
  }
  const secret = base64UrlDecode(consumerSecret, 32, 'OMEMO recovery consumer secret');
  const transfer = uuidBytes(transferId);
  const accountBytes = encoder.encode(account);
  const material = new Uint8Array(
    CONSUMER_COMMITMENT_DOMAIN.byteLength + accountBytes.byteLength + 1
      + transfer.byteLength + secret.byteLength,
  );
  let offset = 0;
  material.set(CONSUMER_COMMITMENT_DOMAIN, offset);
  offset += CONSUMER_COMMITMENT_DOMAIN.byteLength;
  material.set(accountBytes, offset);
  offset += accountBytes.byteLength;
  material[offset] = 0;
  offset += 1;
  material.set(transfer, offset);
  offset += transfer.byteLength;
  material.set(secret, offset);
  try {
    return await sha256Hex(material);
  } finally {
    material.fill(0);
    secret.fill(0);
  }
}

/// Pure crash-recovery predicate used before any network publication.  A
/// replacement journal without an exactly matching installed marker means the
/// pre-existing destination device was already selected for retirement and
/// must never be allowed to revive after a tab/process crash.
export async function omemoReplacementJournalMatches({
  account, journal, marker, installedDeviceId,
}) {
  if (!journal || !marker || marker.role !== 'destination') return false;
  const commitment = marker.consumerSecret
    ? await omemoConsumerCommitmentHex(account, marker.transferId, marker.consumerSecret)
    : marker.consumerCommitment;
  return marker.transferId === journal.transferId
    && marker.generation === journal.generation
    && commitment === journal.consumerCommitment
    && marker.packageSha256 === journal.packageSha256
    && Number(installedDeviceId) === Number(journal.sourceDeviceId);
}

function transferHeader(metadata, salt, nonce) {
  return {
    format: OMEMO_TRANSFER_FORMAT,
    version: OMEMO_TRANSFER_VERSION,
    account: metadata.account,
    transfer_id: metadata.transfer_id,
    generation: metadata.generation,
    source_device_id: metadata.source_device_id,
    created_at: metadata.created_at,
    expires_at: metadata.expires_at,
    kdf: {
      name: OMEMO_TRANSFER_KDF.name,
      version: OMEMO_TRANSFER_KDF.version,
      memory_kib: OMEMO_TRANSFER_KDF.memory_kib,
      iterations: OMEMO_TRANSFER_KDF.iterations,
      parallelism: OMEMO_TRANSFER_KDF.parallelism,
      output_bytes: OMEMO_TRANSFER_KDF.output_bytes,
      salt: base64UrlEncode(salt),
    },
    aead: {
      name: 'AES-256-GCM',
      nonce: base64UrlEncode(nonce),
      tag_bits: 128,
    },
  };
}

function validateMetadata(metadata, expectedAccount = null, now = Date.now()) {
  if (typeof metadata.account !== 'string' || metadata.account.length > 3071
    || !metadata.account.includes('@') || metadata.account !== metadata.account.toLowerCase()) {
    throw new Error('The transfer account is invalid');
  }
  if (expectedAccount !== null && metadata.account !== expectedAccount) {
    throw new Error('The transfer package belongs to a different account');
  }
  if (!UUID.test(metadata.transfer_id)) throw new Error('The transfer identifier is invalid');
  if (!Number.isSafeInteger(metadata.generation) || metadata.generation < 1) {
    throw new Error('The transfer generation is invalid');
  }
  if (!Number.isInteger(metadata.source_device_id)
    || metadata.source_device_id < 1 || metadata.source_device_id > 0x7fffffff) {
    throw new Error('The source OMEMO device identifier is invalid');
  }
  const created = Date.parse(metadata.created_at);
  const expires = Date.parse(metadata.expires_at);
  if (!Number.isFinite(created) || !Number.isFinite(expires)
    || expires <= created || expires - created > 7 * 24 * 60 * 60 * 1000
    || created > now + 5 * 60 * 1000) {
    throw new Error('The transfer validity interval is invalid');
  }
  if (expires <= now) throw new Error('The transfer package has expired');
}

function validateStateTree(value, depth = 0, budget = { nodes: 0 }) {
  if (depth > 32 || ++budget.nodes > 250000) throw new Error('The transferred OMEMO state is too complex');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('The transferred OMEMO state contains an invalid number');
    return;
  }
  if (typeof value === 'string') {
    if (value.length > 8 * 1024 * 1024) throw new Error('The transferred OMEMO state contains an oversized string');
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 100000) throw new Error('The transferred OMEMO state contains an oversized array');
    for (const entry of value) validateStateTree(entry, depth + 1, budget);
    return;
  }
  if (!value || typeof value !== 'object') throw new Error('The transferred OMEMO state contains an unsupported value');
  const keys = Object.keys(value);
  if (keys.length > 100000 || keys.some((key) => ['__proto__', 'prototype', 'constructor'].includes(key))) {
    throw new Error('The transferred OMEMO state contains unsafe object keys');
  }
  for (const key of keys) validateStateTree(value[key], depth + 1, budget);
}

function passwordBytes(passphrase) {
  if (typeof passphrase !== 'string' || [...passphrase].length < 12) {
    throw new Error('The independent transfer passphrase must contain at least 12 characters');
  }
  const bytes = encoder.encode(passphrase);
  if (bytes.byteLength > 1024) {
    bytes.fill(0);
    throw new Error('The transfer passphrase is too long');
  }
  return bytes;
}

async function deriveKey(passphrase, salt, argon2id) {
  if (typeof argon2id !== 'function') throw new Error('The pinned Argon2id implementation is unavailable');
  const password = passwordBytes(passphrase);
  let derived;
  try {
    derived = await argon2id({
      password,
      salt,
      iterations: OMEMO_TRANSFER_KDF.iterations,
      parallelism: OMEMO_TRANSFER_KDF.parallelism,
      memorySize: OMEMO_TRANSFER_KDF.memory_kib,
      hashLength: OMEMO_TRANSFER_KDF.output_bytes,
      outputType: 'binary',
    });
  } finally {
    password.fill(0);
  }
  const bytes = derived instanceof Uint8Array ? derived : new Uint8Array(derived);
  if (bytes.byteLength !== 32) throw new Error('Argon2id returned an invalid key length');
  try {
    return await crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  } finally {
    bytes.fill(0);
  }
}

export async function sha256Hex(value) {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function createOmemoTransferPackage({ metadata, state, passphrase, argon2id }) {
  exactKeys(metadata, ['account', 'transfer_id', 'generation', 'source_device_id', 'created_at', 'expires_at'], 'Transfer metadata');
  validateMetadata(metadata);
  validateStateTree(state);
  const plaintextObject = {
    format: 'northstar-omemo-device-state',
    version: 1,
    account: metadata.account,
    transfer_id: metadata.transfer_id,
    generation: metadata.generation,
    source_device_id: metadata.source_device_id,
    state,
  };
  const plaintext = encoder.encode(JSON.stringify(plaintextObject));
  if (plaintext.byteLength > OMEMO_TRANSFER_MAX_STATE_BYTES) {
    plaintext.fill(0);
    throw new Error('The OMEMO device state exceeds the transfer safety limit');
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const header = transferHeader(metadata, salt, nonce);
  const additionalData = encoder.encode(`Northstar OMEMO device transfer v1\0${JSON.stringify(header)}`);
  let ciphertext;
  try {
    const key = await deriveKey(passphrase, salt, argon2id);
    ciphertext = await crypto.subtle.encrypt({
      name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128,
    }, key, plaintext);
  } finally {
    plaintext.fill(0);
  }
  const serialized = JSON.stringify({ ...header, ciphertext: base64UrlEncode(ciphertext) });
  const bytes = encoder.encode(serialized);
  if (bytes.byteLength > OMEMO_TRANSFER_MAX_BYTES) throw new Error('The encrypted transfer package exceeds the safety limit');
  return { serialized, bytes, sha256: await sha256Hex(bytes), metadata: header };
}

function parseTransferPackage(serialized, expectedAccount, now) {
  const raw = typeof serialized === 'string' ? serialized : decoder.decode(serialized);
  if (encoder.encode(raw).byteLength > OMEMO_TRANSFER_MAX_BYTES) throw new Error('The transfer package exceeds the safety limit');
  let value;
  try { value = JSON.parse(raw); } catch { throw new Error('The transfer package is not valid JSON'); }
  exactKeys(value, [
    'format', 'version', 'account', 'transfer_id', 'generation', 'source_device_id',
    'created_at', 'expires_at', 'kdf', 'aead', 'ciphertext',
  ], 'Transfer package');
  if (value.format !== OMEMO_TRANSFER_FORMAT || value.version !== OMEMO_TRANSFER_VERSION) {
    throw new Error('The transfer package format is unsupported');
  }
  validateMetadata(value, expectedAccount, now);
  exactKeys(value.kdf, ['name', 'version', 'memory_kib', 'iterations', 'parallelism', 'output_bytes', 'salt'], 'Transfer KDF');
  if (value.kdf.name !== OMEMO_TRANSFER_KDF.name
    || value.kdf.version !== OMEMO_TRANSFER_KDF.version
    || value.kdf.memory_kib !== OMEMO_TRANSFER_KDF.memory_kib
    || value.kdf.iterations !== OMEMO_TRANSFER_KDF.iterations
    || value.kdf.parallelism !== OMEMO_TRANSFER_KDF.parallelism
    || value.kdf.output_bytes !== OMEMO_TRANSFER_KDF.output_bytes) {
    throw new Error('The transfer package uses unsupported Argon2id parameters');
  }
  exactKeys(value.aead, ['name', 'nonce', 'tag_bits'], 'Transfer AEAD');
  if (value.aead.name !== 'AES-256-GCM' || value.aead.tag_bits !== 128) {
    throw new Error('The transfer package uses an unsupported AEAD');
  }
  const salt = base64UrlDecode(value.kdf.salt, 16, 'Argon2id salt');
  const nonce = base64UrlDecode(value.aead.nonce, 12, 'AES-GCM nonce');
  const ciphertext = base64UrlDecode(value.ciphertext, null, 'Encrypted OMEMO state');
  if (ciphertext.byteLength < 17 || ciphertext.byteLength > OMEMO_TRANSFER_MAX_STATE_BYTES + 16) {
    throw new Error('The encrypted OMEMO state has an invalid length');
  }
  const header = transferHeader(value, salt, nonce);
  return { raw, value, header, salt, nonce, ciphertext };
}

export async function openOmemoTransferPackage({ serialized, expectedAccount, passphrase, argon2id, now = Date.now() }) {
  const parsed = parseTransferPackage(serialized, expectedAccount, now);
  const additionalData = encoder.encode(`Northstar OMEMO device transfer v1\0${JSON.stringify(parsed.header)}`);
  const key = await deriveKey(passphrase, parsed.salt, argon2id);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: parsed.nonce, additionalData, tagLength: 128,
    }, key, parsed.ciphertext);
  } catch {
    throw new Error('The transfer passphrase is wrong or the package was modified');
  }
  let content;
  try {
    content = JSON.parse(decoder.decode(plaintext));
  } catch {
    throw new Error('The decrypted OMEMO device state is invalid');
  } finally {
    new Uint8Array(plaintext).fill(0);
  }
  exactKeys(content, ['format', 'version', 'account', 'transfer_id', 'generation', 'source_device_id', 'state'], 'Transferred OMEMO state');
  if (content.format !== 'northstar-omemo-device-state' || content.version !== 1
    || content.account !== parsed.header.account
    || content.transfer_id !== parsed.header.transfer_id
    || content.generation !== parsed.header.generation
    || content.source_device_id !== parsed.header.source_device_id) {
    throw new Error('The encrypted state does not match its authenticated transfer header');
  }
  if (!content.state || typeof content.state !== 'object' || Array.isArray(content.state)
    || Number(content.state.deviceId) !== content.source_device_id) {
    throw new Error('The transferred OMEMO device state is inconsistent');
  }
  validateStateTree(content.state);
  const packageBytes = encoder.encode(parsed.raw);
  return {
    state: content.state,
    metadata: parsed.header,
    packageBytes,
    sha256: await sha256Hex(packageBytes),
  };
}
