import {
  KeyHelper,
  OMEMOAddress,
  SessionBuilder,
  SessionCipher,
  SessionRecord,
  curvePubKeyToEd25519PubKey,
  ed25519PubKeyToCurvePubKey,
  util,
} from './crypto/libomemo.js';
import { deleteValue, getValue, setValue } from './storage.js';
import { NS, bareJid, child, descendant, xmlEscape } from './xmpp.js';
import {
  omemoConsumerCommitmentHex,
  omemoReplacementJournalMatches,
  validateOmemoTransferSecret,
} from './omemo-recovery.mjs';
import { validateTransferredOmemoState } from './omemo-state-validation.mjs';
import {
  createOmemoTransferPackageInWorker,
  openOmemoTransferPackageInWorker,
} from './omemo-recovery-worker-client.mjs';

const STORE_VERSION = 5;
const PREKEY_COUNT = 100;
const RETIRED_PREKEY_RETENTION_MS = 60 * 60 * 1000;
const MAX_RETIRED_PREKEYS = PREKEY_COUNT;
const MAX_KEY_ID = 0x7fffffff;
const SIGNED_PREKEY_ROTATION_MS = 30 * 24 * 60 * 60 * 1000;
const OLD_SIGNED_PREKEY_RETENTION_MS = 45 * 24 * 60 * 60 * 1000;
const MAX_XMPP_UINT32 = 0xffffffff;
const MAX_OMEMO_KEY_BYTES = 64 * 1024;
const MAX_OMEMO_PAYLOAD_BYTES = 1024 * 1024;
const MAX_OMEMO_KEY_GROUPS = 1024;
const MAX_OMEMO_KEYS_PER_GROUP = 1024;
const MAX_OMEMO_TOTAL_KEYS = 8192;
const MAX_OMEMO_DEVICES = 512;
const MAX_OMEMO_PREKEYS = 1000;
const MAX_TRUST_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_SCE_TIME_SKEW_MS = 10 * 60 * 1000;
const SCE_MINIMUM_ENVELOPE_CHARACTERS = 512;
const MAX_TRUST_OWNERS = 1024;
const MAX_TRUST_ENTRIES = 8192;
const MAX_PENDING_TRUST_MESSAGES = 64;
const DEVICE_ANNOUNCEMENT_ATTEMPTS = 8;
const DEVICE_ANNOUNCEMENT_STABLE_READS = 2;
const PROFILE = NS.OMEMO2;
const SCE = 'urn:xmpp:sce:1';
const EME = 'urn:xmpp:eme:0';
const SFS = 'urn:xmpp:sfs:0';
const FILE_METADATA = 'urn:xmpp:file:metadata:0';
const ESFS = 'urn:xmpp:esfs:0';
const HASHES = 'urn:xmpp:hashes:2';
const URL_DATA = 'http://jabber.org/protocol/url-data';
const AES_256_GCM = 'urn:xmpp:ciphers:aes-256-gcm-nopadding:0';
const TRUST_MESSAGES = 'urn:xmpp:tm:1';
const ATM = 'urn:xmpp:atm:1';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SEALED_STATE_VERSION = 1;
const MAX_SEALED_STATE_BYTES = 32 * 1024 * 1024;
const WRAPPING_KEY_PREFIX = 'omemo-wrapping-key:';
const REPLACEMENT_JOURNAL_PREFIX = 'omemo-replacement-journal:';
const RECOVERY_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RECOVERY_SHA256 = /^[0-9a-f]{64}$/;
const RECOVERY_PHASES = new Set([
  'source-frozen', 'server-prepared', 'package-sealed', 'destination-installed',
  'consume-uncertain', 'consumed-confirmed', 'retirement-complete',
]);

function bytesToBase64(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function base64ToBuffer(value) {
  const binary = atob(String(value || '').replaceAll(/\s/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes.buffer;
}

function protocolAttributes(element) {
  return [...(element?.attributes || [])]
    .filter((attribute) => attribute.namespaceURI !== 'http://www.w3.org/2000/xmlns/');
}

function requireAttributes(element, allowed, required = allowed) {
  const attributes = protocolAttributes(element);
  if (attributes.some((attribute) => attribute.namespaceURI || !allowed.includes(attribute.localName))) {
    throw new Error(`OMEMO ${element.localName} 包含不支持的属性`);
  }
  for (const name of required) if (!element.hasAttribute(name)) throw new Error(`OMEMO ${element.localName} 缺少 ${name}`);
}

function requireLeaf(element) {
  if ([...(element?.children || [])].length) throw new Error(`OMEMO ${element.localName} 不能包含子元素`);
}

function parseUint32(value, label, { positive = false, maximum = MAX_XMPP_UINT32 } = {}) {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value || '')) throw new Error(`${label} 不是有效整数`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum || (positive && parsed === 0)) {
    throw new Error(`${label} 超出允许范围`);
  }
  return parsed;
}

function strictBareJid(value, label) {
  const raw = String(value || '');
  const at = raw.indexOf('@');
  if (!raw || raw.length > 3071 || raw !== raw.trim() || raw.includes('/')
    || at <= 0 || at !== raw.lastIndexOf('@') || at === raw.length - 1
    || /[\u0000-\u0020\u007f]/.test(raw)) {
    throw new Error(`${label} 不是有效的 bare JID`);
  }
  return bareJid(raw);
}

function validXmppTimestamp(value) {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value || '')
    && Number.isFinite(Date.parse(value));
}

function canonicalBase64(value, expectedBytes, label) {
  const normalized = String(value || '').replaceAll(/\s/g, '');
  if (!normalized || normalized.length > expectedBytes * 2) throw new Error(`${label} 长度无效`);
  let decoded;
  try {
    decoded = base64ToBuffer(normalized);
  } catch {
    throw new Error(`${label} 不是有效的 Base64`);
  }
  if (decoded.byteLength !== expectedBytes) throw new Error(`${label} 长度无效`);
  return bytesToBase64(decoded);
}

function boundedBase64(value, { minBytes = 1, maxBytes, label }) {
  const normalized = String(value || '').replaceAll(/\s/g, '');
  if (!normalized || normalized.length > Math.ceil(maxBytes / 3) * 4 + 4) {
    throw new Error(`${label} 长度无效`);
  }
  let decoded;
  try {
    decoded = base64ToBuffer(normalized);
  } catch {
    throw new Error(`${label} 不是有效的 Base64`);
  }
  if (decoded.byteLength < minBytes || decoded.byteLength > maxBytes) throw new Error(`${label} 长度无效`);
  if (bytesToBase64(decoded).replace(/=+$/, '') !== normalized.replace(/=+$/, '')) {
    throw new Error(`${label} 不是规范的 Base64`);
  }
  return decoded;
}

function protobufVarint(bytes, offset) {
  let value = 0n;
  for (let index = 0; index < 10; index += 1) {
    if (offset >= bytes.length) throw new Error('OMEMO key exchange contains a truncated varint');
    const byte = bytes[offset];
    offset += 1;
    value |= BigInt(byte & 0x7f) << BigInt(index * 7);
    if ((byte & 0x80) === 0) {
      if (index === 9 && byte > 1) throw new Error('OMEMO key exchange varint overflows uint64');
      return { value, offset };
    }
  }
  throw new Error('OMEMO key exchange varint is too long');
}

function requireOmemoKeyExchangePreKey(value) {
  const bytes = value instanceof Uint8Array
    ? value
    : value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : typeof value === 'string'
        ? Uint8Array.from(value, (character) => character.charCodeAt(0) & 0xff)
        : null;
  if (!bytes?.length || bytes.length > MAX_OMEMO_KEY_BYTES) {
    throw new Error('OMEMO key exchange size is invalid');
  }
  const fields = new Map();
  let offset = 0;
  while (offset < bytes.length) {
    const tag = protobufVarint(bytes, offset);
    offset = tag.offset;
    const field = Number(tag.value >> 3n);
    const wire = Number(tag.value & 7n);
    if (!field || wire === 3 || wire === 4 || wire > 5) {
      throw new Error('OMEMO key exchange contains an invalid Protobuf tag');
    }
    let contents;
    if (wire === 0) {
      const decoded = protobufVarint(bytes, offset);
      offset = decoded.offset;
      contents = decoded.value;
    } else if (wire === 1) {
      if (offset + 8 > bytes.length) throw new Error('OMEMO key exchange is truncated');
      contents = bytes.subarray(offset, offset + 8);
      offset += 8;
    } else if (wire === 2) {
      const decoded = protobufVarint(bytes, offset);
      offset = decoded.offset;
      if (decoded.value > BigInt(bytes.length - offset)) throw new Error('OMEMO key exchange is truncated');
      const length = Number(decoded.value);
      contents = bytes.subarray(offset, offset + length);
      offset += length;
    } else {
      if (offset + 4 > bytes.length) throw new Error('OMEMO key exchange is truncated');
      contents = bytes.subarray(offset, offset + 4);
      offset += 4;
    }
    if (field <= 5) {
      if (fields.has(field)) throw new Error(`OMEMO key exchange repeats required field ${field}`);
      fields.set(field, { wire, contents });
    }
  }
  const positiveI31 = (field) => {
    const entry = fields.get(field);
    return entry?.wire === 0 && entry.contents > 0n && entry.contents <= BigInt(MAX_KEY_ID);
  };
  const fixedBytes = (field, length) => {
    const entry = fields.get(field);
    return entry?.wire === 2 && entry.contents.length === length;
  };
  // XEP-0384's OMEMOKeyExchange protobuf has five required fields. In
  // particular pk_id must identify a real one-time PreKey: accepting zero or
  // an omitted field silently degrades X3DH to a weaker three-DH exchange.
  if (!positiveI31(1) || !positiveI31(2)
    || !fixedBytes(3, 32) || !fixedBytes(4, 32)
    || fields.get(5)?.wire !== 2 || fields.get(5).contents.length === 0) {
    throw new Error('OMEMO key exchange is missing a valid one-time PreKey or required key material');
  }
}

function requireNoText(element, label) {
  if ([...(element?.childNodes || [])]
    .some((node) => node.nodeType === Node.TEXT_NODE && node.textContent.trim())) {
    throw new Error(`${label} 包含无效文本`);
  }
}

function parseEncryptedElement(encrypted) {
  if (!encrypted || encrypted.localName !== 'encrypted' || encrypted.namespaceURI !== NS.OMEMO2) {
    throw new Error('OMEMO encrypted 结构无效');
  }
  requireAttributes(encrypted, [], []);
  requireNoText(encrypted, 'OMEMO encrypted');
  const direct = [...encrypted.children];
  if (direct.some((node) => node.namespaceURI !== NS.OMEMO2
    || !['header', 'payload'].includes(node.localName))) {
    throw new Error('OMEMO encrypted 包含未知元素');
  }
  const headers = direct.filter((node) => node.localName === 'header');
  const payloads = direct.filter((node) => node.localName === 'payload');
  if (headers.length !== 1 || payloads.length > 1
    || direct[0]?.localName !== 'header'
    || (payloads.length === 1 && direct[1]?.localName !== 'payload')) {
    throw new Error('OMEMO encrypted 子元素数量无效');
  }
  const header = headers[0];
  requireAttributes(header, ['sid']);
  requireNoText(header, 'OMEMO header');
  const senderDevice = parseUint32(header.getAttribute('sid'), 'OMEMO 发送设备 ID', { positive: true, maximum: MAX_KEY_ID });
  const groupElements = [...header.children];
  if (!groupElements.length || groupElements.length > MAX_OMEMO_KEY_GROUPS) throw new Error('OMEMO keys 分组数量无效');
  const seenJids = new Set();
  let totalKeys = 0;
  const groups = [];
  for (const keys of groupElements) {
    if (keys.localName !== 'keys' || keys.namespaceURI !== NS.OMEMO2) throw new Error('OMEMO header 包含未知元素');
    requireAttributes(keys, ['jid']);
    requireNoText(keys, 'OMEMO keys');
    const jid = strictBareJid(keys.getAttribute('jid'), 'OMEMO keys 的 JID');
    if (seenJids.has(jid)) {
      throw new Error('OMEMO keys 的 JID 无效或重复');
    }
    seenJids.add(jid);
    const keyElements = [...keys.children];
    if (!keyElements.length || keyElements.length > MAX_OMEMO_KEYS_PER_GROUP) throw new Error('OMEMO key 数量无效');
    totalKeys += keyElements.length;
    if (totalKeys > MAX_OMEMO_TOTAL_KEYS) throw new Error('OMEMO encrypted element has too many recipient keys');
    const seenRecipients = new Set();
    const parsedKeys = [];
    for (const key of keyElements) {
      if (key.localName !== 'key' || key.namespaceURI !== NS.OMEMO2) throw new Error('OMEMO keys 包含未知元素');
      requireAttributes(key, ['rid', 'kex'], ['rid']);
      requireLeaf(key);
      const recipientDevice = parseUint32(key.getAttribute('rid'), 'OMEMO 接收设备 ID', { positive: true, maximum: MAX_KEY_ID });
      if (seenRecipients.has(recipientDevice)) throw new Error('OMEMO keys 包含重复接收设备 ID');
      seenRecipients.add(recipientDevice);
      const kexValue = key.getAttribute('kex');
      if (kexValue && !['true', 'false', '1', '0'].includes(kexValue)) throw new Error('OMEMO kex 属性无效');
      const bytes = boundedBase64(key.textContent, {
        maxBytes: MAX_OMEMO_KEY_BYTES,
        label: 'OMEMO 加密密钥',
      });
      parsedKeys.push({ recipientDevice, bytes, kex: kexValue === 'true' || kexValue === '1' });
    }
    groups.push({ jid, keys: parsedKeys });
  }
  let payload = null;
  if (payloads.length === 1) {
    requireAttributes(payloads[0], [], []);
    requireLeaf(payloads[0]);
    payload = boundedBase64(payloads[0].textContent, {
      maxBytes: MAX_OMEMO_PAYLOAD_BYTES,
      label: 'OMEMO payload',
    });
  }
  return { senderDevice, groups, payload };
}

function exactElement(parent, name, namespace, { required = true } = {}) {
  const matches = [...(parent?.children || [])]
    .filter((node) => node.localName === name && node.namespaceURI === namespace);
  if (matches.length > 1 || (required && matches.length !== 1)) throw new Error(`加密文件的 ${name} 元素数量无效`);
  return matches[0] || null;
}

function strictElementText(element, label, maximum = 4096) {
  if (!element) throw new Error(`加密文件缺少 ${label}`);
  requireAttributes(element, [], []);
  requireLeaf(element);
  const value = element.textContent || '';
  if (!value || value.length > maximum) throw new Error(`加密文件的 ${label} 无效`);
  return value;
}

function safeDownloadUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('加密文件下载地址无效');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) {
    throw new Error('加密文件下载地址必须使用 HTTPS');
  }
  let pageOrigin;
  try {
    pageOrigin = new URL(globalThis.location?.origin).origin;
  } catch {
    throw new Error('加密文件下载缺少可信网页来源');
  }
  if (url.origin !== pageOrigin) {
    throw new Error('不允许从跨域地址下载加密文件');
  }
  url.hash = '';
  return url.href;
}

// Reuse the same exact-origin invariant when Fetch exposes the final URL after
// following redirects. Keeping one validator prevents the parser and the
// download path from drifting into different trust policies.
export function validateEncryptedAttachmentUrl(value) {
  return safeDownloadUrl(value);
}

function hexBytes(buffer) {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function parseAesGcmBody(value) {
  const lines = String(value || '').split('\n');
  if (lines.length > 2 || !lines[0].startsWith('aesgcm://')) return null;
  if (lines.length === 2 && !/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(lines[1])) return null;
  let encryptedUrl;
  try {
    encryptedUrl = new URL(lines[0]);
  } catch {
    return null;
  }
  if (encryptedUrl.protocol !== 'aesgcm:' || !/^[0-9a-fA-F]{88}$/.test(encryptedUrl.hash.slice(1))) return null;
  const fragment = encryptedUrl.hash.slice(1);
  const url = new URL(lines[0].replace(/^aesgcm:/, 'https:'));
  url.hash = '';
  if (url.username || url.password) return null;
  const decodeHex = (hex) => Uint8Array.from(hex.match(/../g), (byte) => Number.parseInt(byte, 16));
  return {
    url: safeDownloadUrl(url.href),
    name: decodeURIComponent(url.pathname.split('/').pop() || 'attachment'),
    type: 'application/octet-stream',
    size: null,
    key: bytesToBase64(decodeHex(fragment.slice(24))),
    iv: bytesToBase64(decodeHex(fragment.slice(0, 24))),
    hash: null,
    encryptedHash: null,
    standard: 'XEP-0454',
  };
}

function parseEncryptedFileSharing(fileSharing) {
  if (!fileSharing) return null;
  requireAttributes(fileSharing, ['disposition', 'id'], []);
  requireNoText(fileSharing, 'XEP-0447 file-sharing');
  const disposition = fileSharing.getAttribute('disposition');
  if (disposition && !['inline', 'attachment'].includes(disposition)) throw new Error('加密文件 disposition 无效');
  const file = exactElement(fileSharing, 'file', FILE_METADATA);
  const sources = exactElement(fileSharing, 'sources', SFS);
  if (fileSharing.children.length !== 2) throw new Error('加密文件 file-sharing 包含未知元素');
  requireAttributes(file, [], []);
  requireNoText(file, 'XEP-0446 file metadata');
  const metadataNames = new Set(['media-type', 'name', 'size', 'width', 'height', 'desc']);
  if ([...file.children].some((node) => (node.namespaceURI !== FILE_METADATA || !metadataNames.has(node.localName))
    && !(node.namespaceURI === HASHES && node.localName === 'hash'))) {
    throw new Error('加密文件 metadata 包含未知元素');
  }
  const name = strictElementText(exactElement(file, 'name', FILE_METADATA), 'name', 255);
  if (/[\\/\x00-\x1f]/.test(name)) throw new Error('加密文件名无效');
  const type = strictElementText(exactElement(file, 'media-type', FILE_METADATA), 'media-type', 255);
  const sizeText = strictElementText(exactElement(file, 'size', FILE_METADATA), 'size', 32);
  if (!/^(?:0|[1-9][0-9]*)$/.test(sizeText) || !Number.isSafeInteger(Number(sizeText))) throw new Error('加密文件大小无效');
  const size = Number(sizeText);
  const hashes = [...file.children].filter((node) => node.localName === 'hash' && node.namespaceURI === HASHES);
  const originalHash = hashes.find((node) => node.getAttribute('algo') === 'sha-256');
  if (!originalHash) throw new Error('加密文件缺少 SHA-256 完整性值');
  requireAttributes(originalHash, ['algo']);
  requireLeaf(originalHash);
  const hash = bytesToBase64(boundedBase64(originalHash.textContent, { minBytes: 32, maxBytes: 32, label: '文件 SHA-256' }));
  requireAttributes(sources, [], []);
  requireNoText(sources, 'XEP-0447 sources');
  const encrypted = exactElement(sources, 'encrypted', ESFS);
  if (sources.children.length !== 1) throw new Error('加密文件 sources 包含未加密来源');
  requireAttributes(encrypted, ['cipher']);
  if (encrypted.getAttribute('cipher') !== AES_256_GCM) throw new Error('加密文件使用不支持的密码套件');
  requireNoText(encrypted, 'XEP-0448 encrypted');
  const allowedEncrypted = new Set(['key', 'iv', 'hash']);
  if ([...encrypted.children].some((node) => (node.namespaceURI !== ESFS || !allowedEncrypted.has(node.localName))
    && !(node.namespaceURI === HASHES && node.localName === 'hash')
    && !(node.namespaceURI === SFS && node.localName === 'sources'))) {
    throw new Error('加密文件 encrypted 包含未知元素');
  }
  const key = bytesToBase64(boundedBase64(strictElementText(exactElement(encrypted, 'key', ESFS), 'key'), {
    minBytes: 32, maxBytes: 32, label: '加密文件密钥',
  }));
  const iv = bytesToBase64(boundedBase64(strictElementText(exactElement(encrypted, 'iv', ESFS), 'iv'), {
    minBytes: 12, maxBytes: 12, label: '加密文件 IV',
  }));
  const encryptedHashes = [...encrypted.children].filter((node) => node.localName === 'hash' && node.namespaceURI === HASHES);
  const encryptedHashElement = encryptedHashes.find((node) => node.getAttribute('algo') === 'sha-256');
  if (!encryptedHashElement) throw new Error('加密文件缺少密文 SHA-256 完整性值');
  requireAttributes(encryptedHashElement, ['algo']);
  requireLeaf(encryptedHashElement);
  const encryptedHash = bytesToBase64(boundedBase64(encryptedHashElement.textContent, {
    minBytes: 32, maxBytes: 32, label: '密文 SHA-256',
  }));
  const nestedSources = exactElement(encrypted, 'sources', SFS);
  requireAttributes(nestedSources, [], []);
  requireNoText(nestedSources, 'XEP-0448 nested sources');
  const urlData = exactElement(nestedSources, 'url-data', URL_DATA);
  if (nestedSources.children.length !== 1) throw new Error('加密文件包含多个下载来源');
  requireAttributes(urlData, ['target']);
  requireLeaf(urlData);
  return {
    url: safeDownloadUrl(urlData.getAttribute('target')),
    name,
    type,
    size,
    key,
    iv,
    hash,
    encryptedHash,
    standard: 'XEP-0447/XEP-0448',
  };
}

function parseTrustMessage(element) {
  if (!element || element.localName !== 'trust-message' || element.namespaceURI !== TRUST_MESSAGES) return null;
  requireAttributes(element, ['usage', 'encryption']);
  if (element.getAttribute('usage') !== ATM || element.getAttribute('encryption') !== NS.OMEMO2) {
    throw new Error('不支持的加密信任消息用途');
  }
  requireNoText(element, 'XEP-0434 trust-message');
  const owners = [...element.children];
  if (!owners.length || owners.length > MAX_TRUST_OWNERS) throw new Error('信任消息的 key-owner 数量无效');
  const seenOwners = new Set();
  const parsed = [];
  let totalEntries = 0;
  for (const owner of owners) {
    if (owner.localName !== 'key-owner' || owner.namespaceURI !== TRUST_MESSAGES) throw new Error('信任消息包含未知元素');
    requireAttributes(owner, ['jid']);
    requireNoText(owner, 'XEP-0434 key-owner');
    const jid = strictBareJid(owner.getAttribute('jid'), '信任消息的 key-owner JID');
    if (seenOwners.has(jid)) {
      throw new Error('信任消息的 key-owner JID 无效或重复');
    }
    seenOwners.add(jid);
    const actions = [...owner.children];
    if (!actions.length || actions.length > MAX_OMEMO_DEVICES) throw new Error('信任消息的密钥操作数量无效');
    totalEntries += actions.length;
    if (totalEntries > MAX_TRUST_ENTRIES) throw new Error('Trust message exceeds the safety limit');
    const seenKeys = new Set();
    const entries = [];
    for (const action of actions) {
      if (!['trust', 'distrust'].includes(action.localName) || action.namespaceURI !== TRUST_MESSAGES) {
        throw new Error('信任消息包含未知密钥操作');
      }
      requireAttributes(action, [], []);
      requireLeaf(action);
      const identity = bytesToBase64(boundedBase64(action.textContent, {
        minBytes: 32,
        maxBytes: 32,
        label: 'OMEMO 信任密钥标识',
      }));
      if (seenKeys.has(identity)) throw new Error('信任消息对同一密钥包含重复操作');
      seenKeys.add(identity);
      entries.push({ identity, state: action.localName === 'trust' ? 'verified' : 'distrusted' });
    }
    parsed.push({ jid, entries });
  }
  return parsed;
}

function parseOptOut(element) {
  if (!element || element.localName !== 'opt-out' || element.namespaceURI !== NS.OMEMO2) return null;
  requireAttributes(element, [], []);
  requireNoText(element, 'OMEMO opt-out');
  const children = [...element.children];
  if (children.length > 1
    || children.some((node) => node.localName !== 'reason' || node.namespaceURI !== NS.OMEMO2)) {
    throw new Error('OMEMO opt-out structure is invalid');
  }
  const reason = children[0];
  if (!reason) return { reason: '' };
  requireAttributes(reason, [], []);
  requireLeaf(reason);
  if (reason.textContent.length > 1024) throw new Error('OMEMO opt-out reason is too long');
  return { reason: reason.textContent };
}

export function buildEncryptedFileContent(attachment) {
  const url = safeDownloadUrl(attachment.url);
  const key = canonicalBase64(attachment.key, 32, '加密文件密钥');
  const iv = canonicalBase64(attachment.iv, 12, '加密文件 IV');
  const hash = canonicalBase64(attachment.hash, 32, '文件 SHA-256');
  const encryptedHash = canonicalBase64(attachment.encryptedHash, 32, '密文 SHA-256');
  const name = String(attachment.name || '').slice(0, 255);
  if (!name || /[\\/\x00-\x1f]/.test(name)) throw new Error('加密文件名无效');
  const type = String(attachment.type || 'application/octet-stream').slice(0, 255);
  if (!Number.isSafeInteger(attachment.size) || attachment.size < 0) throw new Error('加密文件大小无效');
  const id = String(attachment.id || crypto.randomUUID());
  const legacy = new URL(url).protocol === 'https:'
    ? `aesgcm://${new URL(url).host}${new URL(url).pathname}${new URL(url).search}#${hexBytes(base64ToBuffer(iv))}${hexBytes(base64ToBuffer(key))}`
    : '';
  const xml = `${legacy ? `<body xmlns='${NS.CLIENT}'>${xmlEscape(legacy)}</body>` : ''}<file-sharing xmlns='${SFS}' disposition='attachment' id='${xmlEscape(id)}'><file xmlns='${FILE_METADATA}'><media-type>${xmlEscape(type)}</media-type><name>${xmlEscape(name)}</name><size>${attachment.size}</size><hash xmlns='${HASHES}' algo='sha-256'>${hash}</hash></file><sources><encrypted xmlns='${ESFS}' cipher='${AES_256_GCM}'><key>${key}</key><iv>${iv}</iv><hash xmlns='${HASHES}' algo='sha-256'>${encryptedHash}</hash><sources xmlns='${SFS}'><url-data xmlns='${URL_DATA}' target='${xmlEscape(url)}'/></sources></encrypted></sources></file-sharing>`;
  return { body: legacy, contentXml: xml };
}

function parseDeviceList(devices) {
  if (!devices || devices.localName !== 'devices' || devices.namespaceURI !== NS.OMEMO2) {
    throw new Error('OMEMO 设备列表结构无效');
  }
  requireAttributes(devices, [], []);
  if ([...devices.childNodes].some((node) => node.nodeType === Node.TEXT_NODE && node.textContent.trim())) {
    throw new Error('OMEMO 设备列表包含无效文本');
  }
  const ids = [];
  for (const device of devices.children) {
    if (ids.length >= MAX_OMEMO_DEVICES) throw new Error('OMEMO device list exceeds the safety limit');
    if (device.localName !== 'device' || device.namespaceURI !== NS.OMEMO2) throw new Error('OMEMO 设备列表包含未知元素');
    // XEP-0384 permits authenticated human-readable labels. Northstar does
    // not display a label until label-signature verification is implemented,
    // but the standard attributes must not make the whole device disappear.
    requireAttributes(device, ['id', 'label', 'labelsig'], ['id']);
    if ((device.getAttribute('label') || '').length > 256
      || (device.getAttribute('labelsig') || '').length > 4096) {
      throw new Error('OMEMO device label exceeds the safety limit');
    }
    requireLeaf(device);
    if (device.textContent.trim()) throw new Error('OMEMO device 不能包含文本');
    ids.push(parseUint32(device.getAttribute('id'), 'OMEMO 设备 ID', { positive: true, maximum: MAX_KEY_ID }));
  }
  if (new Set(ids).size !== ids.length) throw new Error('OMEMO 设备列表包含重复 ID');
  return ids.sort((left, right) => left - right);
}

function parseBundleElement(bundle, jid, deviceId) {
  if (!bundle || bundle.localName !== 'bundle' || bundle.namespaceURI !== NS.OMEMO2) {
    throw new Error(`设备 ${deviceId} 的 OMEMO 公钥包不存在`);
  }
  requireAttributes(bundle, [], []);
  if ([...bundle.childNodes].some((node) => node.nodeType === Node.TEXT_NODE && node.textContent.trim())) {
    throw new Error(`设备 ${deviceId} 的 OMEMO 公钥包包含无效文本`);
  }
  const allowed = new Set(['spk', 'spks', 'ik', 'prekeys']);
  const children = [...bundle.children];
  if (children.some((node) => node.namespaceURI !== NS.OMEMO2 || !allowed.has(node.localName))) {
    throw new Error(`设备 ${deviceId} 的 OMEMO 公钥包包含未知元素`);
  }
  const exactlyOne = (name) => {
    const matches = children.filter((node) => node.localName === name);
    if (matches.length !== 1) throw new Error(`设备 ${deviceId} 的 OMEMO 公钥包必须包含一个 ${name}`);
    return matches[0];
  };
  const signed = exactlyOne('spk');
  const signature = exactlyOne('spks');
  const identity = exactlyOne('ik');
  const prekeysElement = exactlyOne('prekeys');
  requireAttributes(signed, ['id']);
  requireAttributes(signature, [], []);
  requireAttributes(identity, [], []);
  requireAttributes(prekeysElement, [], []);
  requireLeaf(signed);
  requireLeaf(signature);
  requireLeaf(identity);
  if ([...prekeysElement.childNodes].some((node) => node.nodeType === Node.TEXT_NODE && node.textContent.trim())) {
    throw new Error(`设备 ${deviceId} 的 OMEMO prekeys 包含无效文本`);
  }
  const prekeyElements = [...prekeysElement.children];
  if (prekeyElements.length < 25 || prekeyElements.length > MAX_OMEMO_PREKEYS) {
    throw new Error(`设备 ${deviceId} 的 OMEMO 预密钥数量无效`);
  }
  const prekeys = prekeyElements.map((prekey) => {
    if (prekey.localName !== 'pk' || prekey.namespaceURI !== NS.OMEMO2) throw new Error('OMEMO prekeys 包含未知元素');
    requireAttributes(prekey, ['id']);
    requireLeaf(prekey);
    return {
      id: parseUint32(prekey.getAttribute('id'), 'OMEMO 预密钥 ID', { positive: true, maximum: MAX_KEY_ID }),
      key: canonicalBase64(prekey.textContent, 32, 'OMEMO 预密钥'),
    };
  });
  if (new Set(prekeys.map(({ id }) => id)).size !== prekeys.length) {
    throw new Error(`设备 ${deviceId} 的 OMEMO 预密钥少于 25 个或 ID 重复`);
  }
  return {
    jid: bareJid(jid),
    id: Number(deviceId),
    identityKey: canonicalBase64(identity.textContent, 32, 'OMEMO 身份密钥'),
    signedPreKey: {
      id: parseUint32(signed.getAttribute('id'), 'OMEMO 签名预密钥 ID', { positive: true, maximum: MAX_KEY_ID }),
      key: canonicalBase64(signed.textContent, 32, 'OMEMO 签名预密钥'),
      signature: canonicalBase64(signature.textContent, 64, 'OMEMO 预密钥签名'),
    },
    prekeys,
  };
}

function pairToJson(pair) {
  return { pubKey: bytesToBase64(pair.pubKey), privKey: bytesToBase64(pair.privKey) };
}

function pairFromJson(pair) {
  return pair ? { pubKey: base64ToBuffer(pair.pubKey), privKey: base64ToBuffer(pair.privKey) } : undefined;
}

function wrappingKeyName(account) {
  return `${WRAPPING_KEY_PREFIX}${bareJid(account)}`;
}

function replacementJournalName(account) {
  return `${REPLACEMENT_JOURNAL_PREFIX}${bareJid(account)}`;
}

function validateReplacementJournal(value) {
  if (value?.version === 1 && value.phase === undefined) {
    // One-time migration from the pre-state-machine journal. Presence of this
    // journal already means replacement began; package-sealed is the earliest
    // safe phase and never authorizes the old destination to revive.
    value.phase = 'package-sealed';
  }
  const keys = value && typeof value === 'object' && !Array.isArray(value)
    ? Object.keys(value).sort()
    : [];
  const expected = [
    'consumerCommitment', 'destinationDeviceId', 'generation', 'packageSha256',
    'phase', 'sourceDeviceId', 'transferId', 'version',
  ].sort();
  if (keys.length !== expected.length
    || keys.some((key, index) => key !== expected[index])
    || value.version !== 1
    || !RECOVERY_UUID.test(value.transferId)
    || !RECOVERY_SHA256.test(value.consumerCommitment)
    || !RECOVERY_SHA256.test(value.packageSha256)
    || !RECOVERY_PHASES.has(value.phase)
    || !Number.isSafeInteger(value.generation) || value.generation < 1
    || !Number.isInteger(value.sourceDeviceId) || value.sourceDeviceId < 1
    || value.sourceDeviceId > MAX_KEY_ID
    || !Number.isInteger(value.destinationDeviceId) || value.destinationDeviceId < 1
    || value.destinationDeviceId > MAX_KEY_ID) {
    throw new Error('Local OMEMO replacement journal is invalid');
  }
  return value;
}

function validateRecoveryMarkerValue(marker) {
  if (!marker || typeof marker !== 'object' || Array.isArray(marker)
    || !RECOVERY_UUID.test(marker.transferId)
    || !['source', 'destination'].includes(marker.role)) {
    throw new Error('Local OMEMO transfer authority marker is invalid');
  }
  const validGeneration = Number.isSafeInteger(marker.generation) && marker.generation >= 1;
  if ((!validGeneration && !(marker.role === 'source' && marker.generation === null))
    || (marker.role === 'destination' && !validGeneration)) {
    throw new Error('Local OMEMO transfer authority marker is invalid');
  }
  const common = ['generation', 'packageSha256', 'phase', 'role', 'transferId'];
  const allowed = marker.role === 'source'
    ? [...common, 'pollSecret', 'baselineGeneration']
    : [...common, 'consumerCommitment', 'consumerSecret'];
  if (Object.keys(marker).some((key) => !allowed.includes(key))
    || (marker.packageSha256 !== undefined && !RECOVERY_SHA256.test(marker.packageSha256))) {
    throw new Error('Local OMEMO transfer authority marker is invalid');
  }
  if (!RECOVERY_PHASES.has(marker.phase)) {
    throw new Error('Local OMEMO transfer authority marker is invalid');
  }
  if (marker.role === 'source') {
    validateOmemoTransferSecret(marker.pollSecret, 'OMEMO source poll secret');
    if (marker.baselineGeneration !== undefined
      && (!Number.isSafeInteger(marker.baselineGeneration) || marker.baselineGeneration < 0)) {
      throw new Error('Local OMEMO transfer authority marker is invalid');
    }
    return marker;
  }
  if (!RECOVERY_SHA256.test(marker.packageSha256)
    || !RECOVERY_SHA256.test(marker.consumerCommitment)) {
    throw new Error('Local OMEMO transfer authority marker is invalid');
  }
  if (marker.consumerSecret !== undefined) {
    validateOmemoTransferSecret(marker.consumerSecret, 'OMEMO destination consumer secret');
  }
  return marker;
}

function deserializePersistedSession(serialized) {
  const record = SessionRecord.deserialize(serialized);
  return { canonical: record.serialize(), ratchets: record.getSessions() };
}

function validatePersistedOmemoState(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new Error('Local OMEMO state must be an object');
  }
  const stateWithoutRecovery = { ...state };
  const recoveryMarker = stateWithoutRecovery.recoveryTransfer;
  delete stateWithoutRecovery.recoveryTransfer;
  validateTransferredOmemoState(
    stateWithoutRecovery,
    Number(stateWithoutRecovery.deviceId),
    deserializePersistedSession,
  );
  if (recoveryMarker !== undefined) validateRecoveryMarkerValue(recoveryMarker);
  return state;
}

function validWrappingKey(key) {
  return key?.type === 'secret'
    && key.extractable === false
    && key.algorithm?.name === 'AES-GCM'
    && key.algorithm?.length === 256
    && key.usages?.includes('encrypt')
    && key.usages?.includes('decrypt');
}

async function loadWrappingKey(account, { create = false } = {}) {
  const name = wrappingKeyName(account);
  const existing = await getValue('preferences', name);
  if (existing !== undefined) {
    if (!validWrappingKey(existing)) throw new Error('本机 OMEMO 存储密钥无效');
    return existing;
  }
  if (!create) throw new Error('本机 OMEMO 存储密钥丢失；为防止静默更换身份，客户端已停止初始化');
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  await setValue('preferences', name, key);
  return key;
}

function stateAdditionalData(account) {
  return encoder.encode(`Northstar OMEMO state\0${bareJid(account)}`);
}

async function sealState(account, state, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(state));
  let additionalData;
  let ciphertext;
  try {
    // AES-GCM adds a 16-byte authentication tag. The check belongs inside
    // the cleanup scope so an oversized serialization is zeroed as well.
    if (plaintext.byteLength > MAX_SEALED_STATE_BYTES - 16) {
      throw new Error('Local OMEMO state exceeds the safety limit');
    }
    additionalData = stateAdditionalData(account);
    ciphertext = await crypto.subtle.encrypt({
      name: 'AES-GCM',
      iv,
      additionalData,
      tagLength: 128,
    }, key, plaintext);
    return {
      sealedVersion: SEALED_STATE_VERSION,
      algorithm: 'AES-256-GCM',
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(ciphertext),
    };
  } finally {
    plaintext.fill(0);
    iv.fill(0);
    additionalData?.fill(0);
    if (ciphertext) new Uint8Array(ciphertext).fill(0);
  }
}

async function unsealState(account, sealed, key) {
  if (sealed?.sealedVersion !== SEALED_STATE_VERSION
    || sealed.algorithm !== 'AES-256-GCM'
    || typeof sealed.iv !== 'string'
    || typeof sealed.ciphertext !== 'string') {
    throw new Error('本机 OMEMO 加密状态格式无效');
  }
  if (sealed.iv.length > 64
    || sealed.ciphertext.length > Math.ceil(MAX_SEALED_STATE_BYTES / 3) * 4 + 4) {
    throw new Error('Local OMEMO encrypted state exceeds the safety limit');
  }
  let iv;
  let ciphertext;
  try {
    iv = base64ToBuffer(sealed.iv);
    ciphertext = base64ToBuffer(sealed.ciphertext);
  } catch {
    if (iv) new Uint8Array(iv).fill(0);
    if (ciphertext) new Uint8Array(ciphertext).fill(0);
    throw new Error('本机 OMEMO 加密状态不是有效的 Base64 数据');
  }
  if (iv.byteLength !== 12 || ciphertext.byteLength < 17 || ciphertext.byteLength > MAX_SEALED_STATE_BYTES) {
    new Uint8Array(iv).fill(0);
    new Uint8Array(ciphertext).fill(0);
    throw new Error('本机 OMEMO 加密状态长度无效');
  }
  let plaintext;
  const additionalData = stateAdditionalData(account);
  try {
    plaintext = await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv,
      additionalData,
      tagLength: 128,
    }, key, ciphertext);
  } catch {
    new Uint8Array(iv).fill(0);
    new Uint8Array(ciphertext).fill(0);
    additionalData.fill(0);
    throw new Error('无法解封本机 OMEMO 状态；数据可能损坏或不属于此浏览器配置');
  }
  try {
    let state;
    try {
      state = JSON.parse(decoder.decode(plaintext));
    } catch {
      throw new Error('本机 OMEMO 状态明文结构无效');
    }
    if (!state || typeof state !== 'object' || Array.isArray(state)) throw new Error('本机 OMEMO 状态不是对象');
    return state;
  } finally {
    new Uint8Array(plaintext).fill(0);
    new Uint8Array(iv).fill(0);
    new Uint8Array(ciphertext).fill(0);
    additionalData.fill(0);
  }
}

async function replaceLegacyPlaintextState(account, state, key, write = setValue) {
  validatePersistedOmemoState(state);
  const sealed = await sealState(account, state, key);
  // IndexedDB object-store put is one read/write transaction. Replacing the
  // value under the same account key therefore cannot expose a half-sealed
  // state, and the caller must await it before consulting network authority.
  await write('crypto', bareJid(account), sealed);
  return sealed;
}

function stripCurvePrefix(buffer) {
  return buffer.byteLength === 33 ? buffer.slice(1) : buffer;
}

function addCurvePrefix(buffer) {
  if (buffer.byteLength === 33) return buffer;
  const result = new Uint8Array(33);
  result[0] = 5;
  result.set(new Uint8Array(buffer), 1);
  return result.buffer;
}

function randomUintBelow(limit) {
  if (!Number.isSafeInteger(limit) || limit <= 0 || limit > 0x100000000) throw new Error('随机数范围无效');
  const ceiling = Math.floor(0x100000000 / limit) * limit;
  const values = new Uint32Array(1);
  do crypto.getRandomValues(values); while (values[0] >= ceiling);
  return values[0] % limit;
}

function randomIndex(length) {
  if (!length) throw new Error('对方设备没有可用的 OMEMO 预密钥');
  return randomUintBelow(length);
}

function randomOmemoId() {
  return 1 + randomUintBelow(MAX_KEY_ID);
}

function constantTimeEqual(left, right) {
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index++) difference |= (a[index] || 0) ^ (b[index] || 0);
  return difference === 0;
}

async function derivePayloadKeys(contentKey) {
  const key = await crypto.subtle.importKey('raw', contentKey, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: new Uint8Array(32),
    info: encoder.encode('OMEMO Payload'),
  }, key, 640);
  return { encryption: bits.slice(0, 32), authentication: bits.slice(32, 64), iv: bits.slice(64, 80) };
}

function randomPadding(length) {
  if (!Number.isSafeInteger(length) || length < 0 || length > 4096) throw new Error('SCE padding length is invalid');
  const bytes = crypto.getRandomValues(new Uint8Array(Math.ceil(length * 3 / 4)));
  return bytesToBase64(bytes).slice(0, length);
}

async function encryptEnvelope(body, {
  from, to = null, contentXml = null, timeStamp = null,
}) {
  const contentKey = crypto.getRandomValues(new Uint8Array(32)).buffer;
  const keys = await derivePayloadKeys(contentKey);
  const toAffix = to ? `<to jid='${xmlEscape(bareJid(to))}'/>` : '';
  const timeAffix = timeStamp ? `<time stamp='${xmlEscape(timeStamp)}'/>` : '';
  const protectedContent = contentXml || `<body xmlns='${NS.CLIENT}'>${xmlEscape(body)}</body>`;
  const prefix = `<envelope xmlns='${SCE}'><content>${protectedContent}</content>`;
  const suffix = `${timeAffix}<from jid='${xmlEscape(bareJid(from))}'/>${toAffix}</envelope>`;
  const fixedPadding = Math.max(0,
    SCE_MINIMUM_ENVELOPE_CHARACTERS - prefix.length - suffix.length - '<rpad></rpad>'.length);
  const padding = randomPadding(fixedPadding + randomUintBelow(201));
  const envelope = `${prefix}<rpad>${padding}</rpad>${suffix}`;
  const aesKey = await crypto.subtle.importKey('raw', keys.encryption, 'AES-CBC', false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: keys.iv }, aesKey, encoder.encode(envelope));
  const hmacKey = await crypto.subtle.importKey('raw', keys.authentication, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const hmac = (await crypto.subtle.sign('HMAC', hmacKey, ciphertext)).slice(0, 16);
  const keyAndTag = new Uint8Array(48);
  keyAndTag.set(new Uint8Array(contentKey), 0);
  keyAndTag.set(new Uint8Array(hmac), 32);
  return { keyAndTag: keyAndTag.buffer, payload: bytesToBase64(ciphertext) };
}

async function decryptEnvelope(keyAndTag, payload, {
  from: expectedFrom,
  to: expectedTo = null,
  requireTo = false,
  details = false,
  referenceTime = null,
}) {
  if (keyAndTag.byteLength !== 48) throw new Error('OMEMO 内容密钥长度无效');
  const contentKey = keyAndTag.slice(0, 32);
  const expectedHmac = keyAndTag.slice(32);
  const keys = await derivePayloadKeys(contentKey);
  const ciphertext = payload instanceof ArrayBuffer
    ? payload
    : boundedBase64(payload, { maxBytes: MAX_OMEMO_PAYLOAD_BYTES, label: 'OMEMO payload' });
  const hmacKey = await crypto.subtle.importKey('raw', keys.authentication, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const actualHmac = (await crypto.subtle.sign('HMAC', hmacKey, ciphertext)).slice(0, 16);
  if (!constantTimeEqual(actualHmac, expectedHmac)) throw new Error('OMEMO 完整性校验失败');
  const aesKey = await crypto.subtle.importKey('raw', keys.encryption, 'AES-CBC', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: keys.iv }, aesKey, ciphertext);
  const document = new DOMParser().parseFromString(decoder.decode(plaintext), 'application/xml');
  if (document.querySelector('parsererror')) throw new Error('OMEMO 明文结构无效');
  const envelope = document.documentElement;
  if (envelope.localName !== 'envelope' || envelope.namespaceURI !== SCE) throw new Error('缺少 OMEMO SCE 信封');
  requireAttributes(envelope, [], []);
  requireNoText(envelope, 'OMEMO SCE envelope');
  const direct = [...envelope.children];
  if (direct.some((node) => node.namespaceURI !== SCE
    || !['content', 'rpad', 'from', 'to', 'time'].includes(node.localName))) {
    throw new Error('OMEMO SCE 信封包含未知元素');
  }
  const fromElements = direct.filter((node) => node.localName === 'from' && node.namespaceURI === SCE);
  for (const from of fromElements) {
    requireAttributes(from, ['jid']);
    requireLeaf(from);
  }
  if (fromElements.length > 1
    || (fromElements.length === 1
      && (!expectedFrom
        || strictBareJid(fromElements[0].getAttribute('jid'), 'OMEMO SCE from') !== bareJid(expectedFrom)))) {
    throw new Error('OMEMO 发件人校验失败');
  }
  const toElements = direct.filter((node) => node.localName === 'to' && node.namespaceURI === SCE);
  for (const to of toElements) {
    requireAttributes(to, ['jid']);
    requireLeaf(to);
  }
  if ((requireTo && toElements.length !== 1)
    || toElements.length > 1
    || (toElements.length === 1
      && (!expectedTo
        || strictBareJid(toElements[0].getAttribute('jid'), 'OMEMO SCE to') !== bareJid(expectedTo)))) {
    throw new Error('OMEMO 群聊上下文校验失败');
  }
  const contentElements = direct.filter((node) => node.localName === 'content' && node.namespaceURI === SCE);
  if (contentElements.length !== 1) throw new Error('OMEMO SCE 内容结构无效');
  const content = contentElements[0];
  requireAttributes(content, [], []);
  requireNoText(content, 'OMEMO SCE content');
  const contentChildren = [...content.children];
  const bodies = contentChildren.filter((node) => node.localName === 'body' && node.namespaceURI === NS.CLIENT);
  const fileSharings = contentChildren.filter((node) => node.localName === 'file-sharing' && node.namespaceURI === SFS);
  const trustMessages = contentChildren.filter((node) => node.localName === 'trust-message' && node.namespaceURI === TRUST_MESSAGES);
  const optOuts = contentChildren.filter((node) => node.localName === 'opt-out' && node.namespaceURI === NS.OMEMO2);
  const receiptRequests = contentChildren.filter((node) => node.localName === 'request' && node.namespaceURI === NS.RECEIPTS);
  const receiptResponses = contentChildren.filter((node) => node.localName === 'received' && node.namespaceURI === NS.RECEIPTS);
  const chatStates = contentChildren.filter((node) => node.namespaceURI === NS.CHAT_STATES
    && ['active', 'composing', 'paused', 'inactive', 'gone'].includes(node.localName));
  if (bodies.length > 1 || fileSharings.length > 1 || trustMessages.length > 1 || optOuts.length > 1
    || receiptRequests.length > 1 || receiptResponses.length > 1 || chatStates.length > 1
    || contentChildren.length !== bodies.length + fileSharings.length + trustMessages.length
      + optOuts.length + receiptRequests.length + receiptResponses.length + chatStates.length
    || (!bodies.length && !fileSharings.length && !trustMessages.length && !optOuts.length
      && !receiptResponses.length && !chatStates.length)
    || ((trustMessages.length || optOuts.length || receiptResponses.length) && contentChildren.length !== 1)
    || (receiptRequests.length && (trustMessages.length || optOuts.length || receiptResponses.length))
    || (chatStates.length && (trustMessages.length || optOuts.length || receiptResponses.length))) {
    throw new Error('加密消息正文结构无效');
  }
  const body = bodies[0] || null;
  if (body) {
    requireAttributes(body, [], []);
    requireLeaf(body);
  }
  if (receiptRequests.length) {
    requireAttributes(receiptRequests[0], [], []);
    requireLeaf(receiptRequests[0]);
    if (receiptRequests[0].textContent.trim()) throw new Error('加密消息回执请求结构无效');
  }
  let receiptReceivedId = null;
  if (receiptResponses.length) {
    requireAttributes(receiptResponses[0], ['id']);
    requireLeaf(receiptResponses[0]);
    receiptReceivedId = receiptResponses[0].getAttribute('id');
    if (!receiptReceivedId || receiptReceivedId.length > 256
      || /[\u0000-\u001f\u007f]/.test(receiptReceivedId)
      || receiptResponses[0].textContent.trim()) {
      throw new Error('加密消息回执响应结构无效');
    }
  }
  if (chatStates.length) {
    requireAttributes(chatStates[0], [], []);
    requireLeaf(chatStates[0]);
    if (chatStates[0].textContent.trim()) throw new Error('加密聊天状态结构无效');
  }
  const padding = direct.filter((node) => node.localName === 'rpad');
  // XEP-0420 0.5.0 explicitly says longer-than-expected random padding MUST
  // NOT be rejected. The authenticated OMEMO payload already has a 1 MiB cap.
  if (padding.length !== 1) {
    throw new Error('OMEMO SCE 随机填充无效');
  }
  requireAttributes(padding[0], [], []);
  requireLeaf(padding[0]);
  const times = direct.filter((node) => node.localName === 'time');
  if (times.length > 1) throw new Error('OMEMO SCE 时间元素重复');
  if (times.length) {
    requireAttributes(times[0], ['stamp']);
    requireLeaf(times[0]);
    if (!validXmppTimestamp(times[0].getAttribute('stamp'))) throw new Error('OMEMO SCE 时间戳无效');
    const reference = Number.isFinite(Date.parse(referenceTime || '')) ? Date.parse(referenceTime) : Date.now();
    if (Math.abs(Date.parse(times[0].getAttribute('stamp')) - reference) > MAX_SCE_TIME_SKEW_MS) {
      throw new Error('OMEMO SCE timestamp does not match the stanza delivery/archive time');
    }
  }
  const bodyText = body?.textContent || '';
  const attachment = fileSharings.length
    ? parseEncryptedFileSharing(fileSharings[0])
    : parseAesGcmBody(bodyText);
  const trustMessage = trustMessages.length ? parseTrustMessage(trustMessages[0]) : null;
  const optOut = optOuts.length ? parseOptOut(optOuts[0]) : null;
  if (trustMessage && (times.length !== 1 || toElements.length !== 1)) {
    throw new Error('XEP-0434 信任消息缺少防重放时间或接收方绑定');
  }
  return details ? {
    body: bodyText,
    attachment,
    trustMessage,
    trustTimestamp: times[0]?.getAttribute('stamp') || null,
    optOut,
    receiptRequest: receiptRequests.length === 1,
    receiptReceivedId,
    chatState: chatStates[0]?.localName || null,
  } : bodyText;
}

function pruneRetiredPrekeys(state, now = Date.now()) {
  const retained = Object.entries(state.retiredPrekeys || {})
    .filter(([, value]) => value?.keyPair
      && Number.isFinite(Date.parse(value.retiredAt || ''))
      && now - Date.parse(value.retiredAt) <= RETIRED_PREKEY_RETENTION_MS)
    .sort((left, right) => Date.parse(left[1].retiredAt) - Date.parse(right[1].retiredAt))
    .slice(-MAX_RETIRED_PREKEYS);
  state.retiredPrekeys = Object.fromEntries(retained);
}

class PersistentOmemoStore {
  constructor(account, state, wrappingKey) {
    this.account = account;
    this.state = state;
    this.wrappingKey = wrappingKey;
    this.writeChain = Promise.resolve();
  }

  persist() {
    // A failed IndexedDB write must reject that caller but must not poison
    // every later repair attempt for the lifetime of this OMEMO manager.
    this.writeChain = this.writeChain.catch(() => {}).then(async () => {
      const sealed = await sealState(this.account, this.state, this.wrappingKey);
      await setValue('crypto', this.account, sealed);
    });
    return this.writeChain;
  }

  flush() { return this.writeChain; }

  getIdentityKeyPair() { return Promise.resolve(pairFromJson(this.state.identityKeyPair)); }
  getLocalRegistrationId() { return Promise.resolve(Number(this.state.deviceId)); }

  isTrustedIdentity(address, identityKey) {
    const encoded = bytesToBase64(identityKey);
    const saved = this.state.identities[address];
    const decision = this.state.trustDecisions[address];
    if (decision?.identity === encoded && decision.state === 'distrusted') return Promise.resolve(false);
    return Promise.resolve(!saved || saved === encoded);
  }

  saveIdentity(address, identityKey) {
    const encoded = bytesToBase64(identityKey);
    const changed = Boolean(this.state.identities[address] && this.state.identities[address] !== encoded);
    if (!changed) {
      this.state.identities[address] = encoded;
      this.state.trustDecisions[address] ||= {
        identity: encoded,
        state: 'tofu',
        updatedAt: new Date().toISOString(),
      };
      return this.persist().then(() => false);
    }
    return Promise.resolve(true);
  }

  loadPreKey(keyId) {
    const pair = this.state.prekeys[String(keyId)]
      || this.state.retiredPrekeys?.[String(keyId)]?.keyPair;
    return Promise.resolve(pair ? { keyPair: pairFromJson(pair) } : undefined);
  }

  storePreKey(keyId, keyPair) {
    this.state.prekeys[String(keyId)] = pairToJson(keyPair);
    delete this.state.retiredPrekeys?.[String(keyId)];
    return this.persist();
  }

  removePreKey(keyId) {
    const id = String(keyId);
    const pair = this.state.prekeys[id];
    if (pair) {
      this.state.retiredPrekeys ||= {};
      // Signal's store interface calls this immediately after the first
      // successful pre-key decrypt. Keep the private key out of future PEP
      // bundles, but retain it briefly so another sender that fetched the
      // same old bundle (or a MAM catch-up batch) can finish establishing its
      // independent session. The bounded grace set is never republished.
      this.state.retiredPrekeys[id] = {
        keyPair: pair,
        retiredAt: new Date().toISOString(),
      };
      delete this.state.prekeys[id];
      pruneRetiredPrekeys(this.state);
    }
    return this.persist();
  }

  loadSignedPreKey(keyId) {
    const signed = this.state.signedPreKey;
    const previous = (this.state.oldSignedPreKeys || [])
      .find((candidate) => Number(candidate.id) === Number(keyId));
    const match = signed && Number(signed.id) === Number(keyId) ? signed : previous;
    return Promise.resolve(match ? { keyPair: pairFromJson(match.keyPair) } : undefined);
  }

  storeSignedPreKey(keyId, keyPair) {
    this.state.signedPreKey = {
      id: Number(keyId), keyPair: pairToJson(keyPair), signature: '', createdAt: new Date().toISOString(),
    };
    return this.persist();
  }

  removeSignedPreKey(keyId) {
    this.state.oldSignedPreKeys = (this.state.oldSignedPreKeys || [])
      .filter((candidate) => Number(candidate.id) !== Number(keyId));
    if (Number(this.state.signedPreKey?.id) === Number(keyId)) delete this.state.signedPreKey;
    return this.persist();
  }

  loadSession(address) { return Promise.resolve(this.state.sessions[address]); }
  storeSession(address, record) { this.state.sessions[address] = record; return this.persist(); }
  removeSession(address) { delete this.state.sessions[address]; return this.persist(); }
  removeAllSessions(address = '') {
    for (const key of Object.keys(this.state.sessions)) if (key.startsWith(address)) delete this.state.sessions[key];
    return this.persist();
  }
}

export class OmemoManager {
  constructor(xmpp, account, {
    prepareOutbound = null,
    sendEncrypted = null,
    onRemoteRetired = null,
    lookupRecoveryAuthority = null,
    lookupRecoveryTransfer = null,
    retryPendingRecoveryConsume = null,
    resolvePendingRecoveryTransfer = null,
    pollRecoveryTransfer = null,
  } = {}) {
    this.xmpp = xmpp;
    this.account = bareJid(account);
    this.state = null;
    this.store = null;
    this.deviceCache = new Map();
    this.ready = false;
    this.fresh = false;
    this.deviceRepair = Promise.resolve();
    this.deviceAnnouncement = Promise.resolve();
    this.bundleRepair = Promise.resolve();
    this.bundleOperation = Promise.resolve();
    this.trustFanout = Promise.resolve();
    this.sessionOperations = new Map();
    this.teardownTask = null;
    this.remoteRetirementTask = null;
    this.releaseStateLock = null;
    this.stateLockTask = null;
    this.retiring = false;
    this.prepareOutbound = prepareOutbound;
    this.sendEncrypted = sendEncrypted;
    this.onRemoteRetired = onRemoteRetired;
    this.lookupRecoveryAuthority = lookupRecoveryAuthority;
    this.lookupRecoveryTransfer = lookupRecoveryTransfer;
    this.retryPendingRecoveryConsume = retryPendingRecoveryConsume;
    this.resolvePendingRecoveryTransfer = resolvePendingRecoveryTransfer;
    this.pollRecoveryTransfer = pollRecoveryTransfer;
    this.recoveryOperation = null;
  }

  async initialize() {
    await this.acquireStateLock();
    try {
      return await this.initializeLocked();
    } catch (error) {
      if (error?.code === 'OMEMO_DEVICE_RETIRED') {
        await this.completeRemoteRetirement(error.deviceId);
      } else {
        await this.destroy();
      }
      throw error;
    }
  }

  async acquireStateLock() {
    if (!navigator.locks?.request) {
      throw new Error('此浏览器缺少安全操作 OMEMO 状态所需的 Web Locks API');
    }
    let settleAcquired;
    let rejectAcquired;
    let release;
    const acquired = new Promise((resolve, reject) => {
      settleAcquired = resolve;
      rejectAcquired = reject;
    });
    const held = new Promise((resolve) => { release = resolve; });
    let acquisitionSettled = false;
    this.stateLockTask = navigator.locks.request(
      `northstar-omemo-state:${this.account}`,
      { mode: 'exclusive', ifAvailable: true },
      async (lock) => {
        acquisitionSettled = true;
        settleAcquired(Boolean(lock));
        if (lock) await held;
      },
    ).catch((error) => {
      if (!acquisitionSettled) rejectAcquired(error);
      else console.error('OMEMO state lock failed', error);
    });
    if (!await acquired) {
      throw new Error('此账号已在当前浏览器的另一个标签页中使用；请关闭另一标签页后重试');
    }
    this.releaseStateLock = release;
  }

  async initializeLocked() {
    let replacementJournal = await getValue('preferences', replacementJournalName(this.account));
    if (replacementJournal !== undefined) {
      try {
        replacementJournal = validateReplacementJournal(replacementJournal);
      } catch (error) {
        await Promise.allSettled([
          deleteValue('crypto', this.account),
          deleteValue('preferences', wrappingKeyName(this.account)),
          deleteValue('preferences', replacementJournalName(this.account)),
        ]);
        throw error;
      }
    }
    const persisted = await getValue('crypto', this.account);
    const sealed = persisted?.sealedVersion !== undefined;
    const wrappingKey = await loadWrappingKey(this.account, { create: !sealed });
    this.state = sealed ? await unsealState(this.account, persisted, wrappingKey) : persisted;
    if (replacementJournal) {
      const marker = this.state?.recoveryTransfer;
      const journalMatchesInstalledState = await omemoReplacementJournalMatches({
        account: this.account,
        journal: replacementJournal,
        marker,
        installedDeviceId: this.state?.deviceId,
      });
      if (!journalMatchesInstalledState) {
        const interrupted = new Error('An interrupted OMEMO device replacement cannot reactivate the retired destination device.');
        interrupted.code = 'OMEMO_DEVICE_RETIRED';
        interrupted.deviceId = replacementJournal.destinationDeviceId;
        throw interrupted;
      }
    }
    if (!this.state) {
      this.fresh = true;
      this.state = {
        version: STORE_VERSION,
        deviceId: randomOmemoId(),
        deviceIdExpanded: true,
        identityKeyPair: null,
        signedPreKey: null,
        prekeys: {},
        retiredPrekeys: {},
        identities: {},
        trustDecisions: {},
        pendingTrustMessages: [],
        lastTrustTimestamps: {},
        sessions: {},
        nextPreKeyId: PREKEY_COUNT + 1,
      };
      this.store = new PersistentOmemoStore(this.account, this.state, wrappingKey);
      await this.provision();
    } else {
      this.upgradeState();
      validatePersistedOmemoState(this.state);
      this.store = new PersistentOmemoStore(this.account, this.state, wrappingKey);
      if (!sealed) {
        // Legacy plaintext is validated and atomically replaced before any
        // recovery-authority request. A network failure or crash after this
        // point can only leave the encrypted record behind.
        await replaceLegacyPlaintextState(this.account, this.state, wrappingKey);
      }
      const recovery = await this.validateRecoveryAuthorityLocked();
      await this.store.persist();
      if (recovery?.recoverable) {
        this.ready = false;
        return {
          ...(await this.getOwnDevice()),
          recoveryFrozen: true,
          transferId: recovery.transferId,
          generation: recovery.generation,
          transferState: recovery.state,
        };
      }
      if (replacementJournal) {
        await deleteValue('preferences', replacementJournalName(this.account));
        replacementJournal = undefined;
      }
      await this.ensurePrekeys();
      await this.rotateSignedPreKeyIfNeeded();
    }

    const existing = await this.fetchDeviceIds(this.account, false);
    if (this.fresh) {
      let attempts = 0;
      while (existing.includes(Number(this.state.deviceId)) && attempts < 10) {
        this.state.deviceId = randomOmemoId();
        attempts += 1;
      }
      if (existing.includes(Number(this.state.deviceId))) throw new Error('无法生成唯一的 OMEMO 设备 ID');
    } else if (!existing.includes(Number(this.state.deviceId))) {
      try {
        await this.fetchBundle(this.account, Number(this.state.deviceId));
      } catch (error) {
        if (error?.message !== 'item-not-found') throw error;
        const retired = new Error('This OMEMO device was removed by another authenticated account endpoint.');
        retired.code = 'OMEMO_DEVICE_RETIRED';
        retired.deviceId = Number(this.state.deviceId);
        throw retired;
      }
    }
    await this.publishBundle();
    const announced = await this.ensureDeviceAnnouncement(existing);
    await this.cleanupLegacyDeviceId(announced);
    this.ready = true;
    return this.getOwnDevice();
  }

  destroy() {
    if (this.teardownTask) return this.teardownTask;
    this.ready = false;
    this.retiring = true;
    const release = this.releaseStateLock;
    const store = this.store;
    const operations = [
      this.deviceRepair,
      this.deviceAnnouncement,
      this.bundleRepair,
      this.bundleOperation,
      this.trustFanout,
      ...this.sessionOperations.values(),
    ];
    this.releaseStateLock = null;
    this.teardownTask = Promise.allSettled(operations)
      .then(() => store?.flush())
      .catch((error) => console.error('OMEMO state flush failed during teardown', error))
      .finally(() => {
        if (this.store === store) {
          this.store = null;
          this.state = null;
          this.deviceCache.clear();
          this.sessionOperations.clear();
        }
        release?.();
      });
    return this.teardownTask;
  }

  async quiesceStateOperations() {
    // Drain every producer while retaining the account-scoped Web Lock. This
    // is intentionally distinct from destroy(): releasing that lock between
    // destination retirement and the durable replacement marker would allow
    // another tab to revive or advance the state being replaced.
    const operations = [
      this.deviceRepair,
      this.deviceAnnouncement,
      this.bundleRepair,
      this.bundleOperation,
      this.trustFanout,
      ...this.sessionOperations.values(),
    ];
    const outcomes = await Promise.allSettled(operations);
    const failed = outcomes.find((outcome) => outcome.status === 'rejected');
    if (failed) throw failed.reason;
    await this.store?.flush();
  }

  completeRemoteRetirement(deviceId) {
    if (this.remoteRetirementTask) return this.remoteRetirementTask;
    this.ready = false;
    this.retiring = true;
    const account = this.account;
    this.remoteRetirementTask = (async () => {
      const journalName = replacementJournalName(account);
      const journal = await getValue('preferences', journalName);
      if (journal !== undefined) {
        validateReplacementJournal(journal);
        journal.phase = 'retirement-complete';
        await setValue('preferences', journalName, journal);
      }
      await this.destroy();
      const erasures = await Promise.allSettled([
        deleteValue('crypto', account),
        deleteValue('preferences', wrappingKeyName(account)),
        deleteValue('preferences', journalName),
      ]);
      const failed = erasures.find((result) => result.status === 'rejected');
      await this.onRemoteRetired?.({
        account,
        deviceId: Number(deviceId),
        keyErasureComplete: !failed,
      });
      if (failed) throw failed.reason;
    })();
    return this.remoteRetirementTask;
  }

  validateRecoveryMarker(marker) {
    return validateRecoveryMarkerValue(marker);
  }

  async validateRecoveryAuthorityLocked(isCurrent = () => true) {
    const marker = this.state?.recoveryTransfer;
    if (!marker) return true;
    this.validateRecoveryMarker(marker);
    if (marker.role === 'source') {
      if (typeof this.pollRecoveryTransfer !== 'function') {
        throw new Error('OMEMO source transfer completion cannot be verified; the device remains frozen');
      }
      let polled;
      try {
        polled = await this.pollRecoveryTransfer({
          transferId: marker.transferId,
          pollSecret: marker.pollSecret,
        });
        if (!isCurrent()) return { stale: true };
      } catch (error) {
        if (error?.status !== 404) throw error;
        // Capability rows expire before the permanent account high-water.
        // Fall back only to authenticated, account-bound views; never treat a
        // public capability miss as revocation or permission to unfreeze.
        let transfer;
        try {
          transfer = await this.lookupRecoveryTransfer?.(marker.transferId);
          if (!isCurrent()) return { stale: true };
        } catch (lookupError) {
          if (lookupError?.status !== 404) throw lookupError;
        }
        if (transfer) {
          polled = { generation: Number(transfer.generation), state: transfer.state };
        } else {
          const authority = await this.lookupRecoveryAuthority?.();
          if (!isCurrent()) return { stale: true };
          const highWater = Number(authority?.latest_consumed_generation || 0);
          if (marker.generation !== null && highWater >= marker.generation
            && authority?.latest_consumed_transfer_id === marker.transferId) {
            polled = { generation: marker.generation, state: 'consumed' };
          } else if (marker.generation === null
            && Number.isSafeInteger(marker.baselineGeneration)
            && highWater === marker.baselineGeneration) {
            // Freeze committed locally, but prepare never committed. This is
            // recoverable only through authenticated cancellation; anonymous
            // 404 alone never authorizes reactivation.
            return {
              recoverable: true,
              transferId: marker.transferId,
              generation: null,
              state: 'locally-unallocated',
            };
          } else if (marker.generation === null
            && Number.isSafeInteger(marker.baselineGeneration)
            && highWater > marker.baselineGeneration) {
            if (authority?.latest_consumed_transfer_id === marker.transferId) {
              const retired = new Error('This locally frozen OMEMO source was consumed before its response was observed.');
              retired.code = 'OMEMO_DEVICE_RETIRED';
              retired.deviceId = Number(this.state.deviceId);
              throw retired;
            }
            return {
              recoverable: true,
              transferId: marker.transferId,
              generation: null,
              state: 'authority-advanced',
            };
          } else {
            polled = null;
          }
        }
      }
      if (!polled || !Number.isSafeInteger(Number(polled.generation))
        || Number(polled.generation) < 1
        || (marker.generation !== null && Number(polled.generation) !== marker.generation)) {
        throw new Error('Server returned an invalid OMEMO source transfer result');
      }
      if (marker.generation === null) {
        if (!isCurrent()) return { stale: true };
        marker.generation = Number(polled.generation);
        await this.store.persist();
      }
      if (polled.state === 'consumed') {
        if (!isCurrent()) return { stale: true };
        const retired = new Error('This OMEMO device was moved to another authenticated account endpoint.');
        retired.code = 'OMEMO_DEVICE_RETIRED';
        retired.deviceId = Number(this.state.deviceId);
        throw retired;
      }
      if (['revoked', 'expired'].includes(polled.state)) {
        if (!isCurrent()) return { stale: true };
        delete this.state.recoveryTransfer;
        await this.store.persist();
        if (!this.retiring) this.ready = true;
        return true;
      }
      if (['preparing', 'prepared'].includes(polled.state)) {
        return {
          recoverable: true,
          transferId: marker.transferId,
          generation: marker.generation,
          state: polled.state,
        };
      }
      throw new Error('Server returned an invalid OMEMO source transfer state');
    }

    if (typeof this.lookupRecoveryAuthority !== 'function') {
      throw new Error('OMEMO transfer authority cannot be verified; initialization stopped');
    }
    const markerCommitment = marker.consumerSecret
      ? await omemoConsumerCommitmentHex(this.account, marker.transferId, marker.consumerSecret)
      : marker.consumerCommitment;
    if (markerCommitment !== marker.consumerCommitment) {
      throw new Error('Local OMEMO transfer consumer commitment is invalid');
    }
    const authority = await this.lookupRecoveryAuthority();
    if (!isCurrent()) return { stale: true };
    const latest = Number(authority?.latest_consumed_generation || 0);
    if (!Number.isSafeInteger(latest) || latest < 0) {
      throw new Error('Server returned an invalid OMEMO transfer authority');
    }
    const consumedByAnotherEndpoint = latest > marker.generation
      || (latest === marker.generation && (
        authority.latest_consumed_transfer_id !== marker.transferId
        || authority.latest_consumer_commitment !== markerCommitment
      ));
    if (consumedByAnotherEndpoint) {
      const retired = new Error('This OMEMO device was moved to another authenticated account endpoint.');
      retired.code = 'OMEMO_DEVICE_RETIRED';
      retired.deviceId = Number(this.state.deviceId);
      throw retired;
    }
    if (latest < marker.generation) {
      // A lost HTTP response must not strand an installed destination. The
      // high-entropy secret is kept only inside the sealed local marker and
      // may be replayed against the exact transfer until authority confirms
      // the same commitment. The server handles this as an exact idempotent
      // replay; a different endpoint cannot derive the secret from GET data.
      if (marker.consumerSecret && typeof this.retryPendingRecoveryConsume === 'function') {
        try {
          await this.retryPendingRecoveryConsume({
            transferId: marker.transferId,
            packageSha256: marker.packageSha256,
            consumerSecret: marker.consumerSecret,
          });
          if (!isCurrent()) return { stale: true };
        } catch (error) {
          // Resolve through the authenticated authority views below. A
          // transport error can mean that the consume transaction committed.
          console.warn('OMEMO transfer consume replay was inconclusive', error);
        }
      }
      if (typeof this.resolvePendingRecoveryTransfer !== 'function') {
        throw new Error('The destination OMEMO transfer outcome cannot be verified');
      }
      const resolution = await this.resolvePendingRecoveryTransfer({
        transferId: marker.transferId,
        generation: marker.generation,
        packageSha256: marker.packageSha256,
        consumerCommitment: markerCommitment,
      });
      if (!isCurrent()) return { stale: true };
      if (resolution === 'pending') {
        throw new Error('The destination OMEMO transfer outcome is still uncertain; its encrypted state remains frozen');
      }
      if (resolution !== 'consumed') {
        const retired = new Error('This destination OMEMO transfer was not committed and its local copy must be erased.');
        retired.code = 'OMEMO_DEVICE_RETIRED';
        retired.deviceId = Number(this.state.deviceId);
        throw retired;
      }
    }
    if (marker.consumerSecret) {
      if (!isCurrent()) return { stale: true };
      delete marker.consumerSecret;
      marker.phase = 'consumed-confirmed';
      await this.store.persist();
    }
    return true;
  }

  async validateRecoveryAuthority(isCurrent = () => true) {
    try {
      return await this.validateRecoveryAuthorityLocked(isCurrent);
    } catch (error) {
      if (error?.code === 'OMEMO_DEVICE_RETIRED' && isCurrent()) {
        await this.completeRemoteRetirement(error.deviceId);
      }
      throw error;
    }
  }

  async withSessionOperation(address, operation) {
    const key = typeof address === 'string' ? address : address.toString();
    const previous = this.sessionOperations.get(key) || Promise.resolve();
    const current = previous.catch(() => {}).then(operation);
    this.sessionOperations.set(key, current);
    try {
      return await current;
    } finally {
      if (this.sessionOperations.get(key) === current) this.sessionOperations.delete(key);
    }
  }

  upgradeState() {
    if (Number.isInteger(this.state.version) && this.state.version > STORE_VERSION) {
      throw new Error('Local OMEMO state was created by a newer incompatible client');
    }
    this.state.version = STORE_VERSION;
    this.state.prekeys ||= {};
    this.state.retiredPrekeys ||= {};
    pruneRetiredPrekeys(this.state);
    this.state.identities ||= {};
    this.state.trustDecisions ||= {};
    this.state.pendingTrustMessages = Array.isArray(this.state.pendingTrustMessages)
      ? this.trimPendingTrustMessages(this.state.pendingTrustMessages)
      : [];
    this.state.lastTrustTimestamps ||= {};
    this.state.sessions ||= {};
    this.state.oldSignedPreKeys ||= [];
    if (this.state.recoveryTransfer !== undefined) {
      if (this.state.recoveryTransfer.phase === undefined) {
        const marker = this.state.recoveryTransfer;
        marker.phase = marker.role === 'destination'
          ? 'destination-installed'
          : marker.packageSha256 ? 'package-sealed'
            : marker.generation === null ? 'source-frozen' : 'server-prepared';
      }
      this.validateRecoveryMarker(this.state.recoveryTransfer);
    }
    if (this.state.signedPreKey && !this.state.signedPreKey.createdAt) {
      this.state.signedPreKey.createdAt = new Date().toISOString();
    }
    // Early builds inherited libsignal's 14-bit registration id generator.
    // Expand those ids once so a 1000-user installation does not suffer a
    // birthday-collision-prone device namespace.
    if (!this.state.deviceIdExpanded && Number(this.state.deviceId) <= 0x3fff) {
      this.state.legacyDeviceId = Number(this.state.deviceId);
      this.state.deviceId = randomOmemoId();
      this.state.deviceIdExpanded = true;
      this.state.sessions = {};
    }
    const highest = [...Object.keys(this.state.prekeys), ...Object.keys(this.state.retiredPrekeys)]
      .map(Number)
      .filter((id) => Number.isInteger(id) && id > 0 && id <= MAX_KEY_ID)
      .reduce((maximum, id) => Math.max(maximum, id), 0);
    if (!Number.isInteger(this.state.nextPreKeyId) || this.state.nextPreKeyId <= highest) {
      this.state.nextPreKeyId = highest >= MAX_KEY_ID ? 1 : highest + 1;
    }
  }

  async provision() {
    const identity = await KeyHelper.generateIdentityKeyPair();
    const signed = await KeyHelper.generateSignedPreKey(identity, 1, PROFILE);
    this.state.identityKeyPair = pairToJson(identity);
    this.state.signedPreKey = {
      id: signed.keyId,
      keyPair: pairToJson(signed.keyPair),
      signature: bytesToBase64(signed.signature),
      createdAt: new Date().toISOString(),
    };
    this.state.oldSignedPreKeys = [];
    this.state.retiredPrekeys = {};
    const prekeys = await Promise.all(Array.from({ length: PREKEY_COUNT }, (_, id) => KeyHelper.generatePreKey(id + 1)));
    for (const prekey of prekeys) this.state.prekeys[String(prekey.keyId)] = pairToJson(prekey.keyPair);
    this.state.nextPreKeyId = PREKEY_COUNT + 1;
    await this.store.persist();
  }

  async ensurePrekeys() {
    const missingCount = Math.max(0, PREKEY_COUNT - Object.keys(this.state.prekeys).length);
    if (!missingCount) return false;
    const ids = Array.from({ length: missingCount }, () => this.allocatePreKeyId());
    const generated = await Promise.all(ids.map((id) => KeyHelper.generatePreKey(id)));
    for (const prekey of generated) this.state.prekeys[String(prekey.keyId)] = pairToJson(prekey.keyPair);
    await this.store.persist();
    return true;
  }

  async rotateSignedPreKeyIfNeeded() {
    const now = Date.now();
    const current = this.state.signedPreKey;
    this.state.oldSignedPreKeys = (this.state.oldSignedPreKeys || [])
      .filter((candidate) => Date.parse(candidate.expiresAt || '') > now)
      .slice(-3);
    if (current && now - Date.parse(current.createdAt || 0) < SIGNED_PREKEY_ROTATION_MS) return false;
    const identity = pairFromJson(this.state.identityKeyPair);
    let id = current ? Number(current.id) + 1 : 1;
    if (id <= 0 || id > MAX_KEY_ID) id = 1;
    while (this.state.oldSignedPreKeys.some((candidate) => Number(candidate.id) === id)) {
      id = id === MAX_KEY_ID ? 1 : id + 1;
    }
    const next = await KeyHelper.generateSignedPreKey(identity, id, PROFILE);
    if (current) {
      this.state.oldSignedPreKeys.push({
        ...current,
        expiresAt: new Date(now + OLD_SIGNED_PREKEY_RETENTION_MS).toISOString(),
      });
    }
    this.state.signedPreKey = {
      id: next.keyId,
      keyPair: pairToJson(next.keyPair),
      signature: bytesToBase64(next.signature),
      createdAt: new Date(now).toISOString(),
    };
    await this.store.persist();
    return true;
  }

  async cleanupLegacyDeviceId(existing) {
    const legacy = Number(this.state.legacyDeviceId);
    if (!Number.isInteger(legacy) || legacy < 0 || legacy === Number(this.state.deviceId)) return;
    const remaining = [...new Set(existing
      .filter((id) => id !== legacy)
      .concat(Number(this.state.deviceId)))];
    await this.publishDeviceList(remaining);
    await this.xmpp.retractPep(NS.OMEMO2_BUNDLES, String(legacy)).catch((error) => {
      if (error?.message !== 'item-not-found') throw error;
    });
    delete this.state.legacyDeviceId;
    this.deviceCache.set(this.account, remaining);
    await this.store.persist();
  }

  scheduleBundleRepair() {
    if (!this.ready || this.retiring) return this.bundleRepair;
    this.bundleRepair = this.bundleRepair
      .catch(() => {})
      .then(async () => {
        await this.publishBundle();
      })
      .catch((error) => console.error('OMEMO bundle replenishment failed; retrying after the next key exchange', error));
    return this.bundleRepair;
  }

  allocatePreKeyId() {
    let candidate = Number(this.state.nextPreKeyId) || 1;
    for (let attempts = 0; attempts < MAX_KEY_ID; attempts += 1) {
      if (candidate <= 0 || candidate > MAX_KEY_ID) candidate = 1;
      this.state.nextPreKeyId = candidate === MAX_KEY_ID ? 1 : candidate + 1;
      if (!this.state.prekeys[String(candidate)] && !this.state.retiredPrekeys[String(candidate)]) return candidate;
      candidate = this.state.nextPreKeyId;
    }
    throw new Error('OMEMO 预密钥编号空间已耗尽');
  }

  async publishBundle() {
    this.bundleOperation = this.bundleOperation
      .catch(() => {})
      .then(() => this.publishBundleLocked());
    return this.bundleOperation;
  }

  async publishBundleLocked() {
    await this.ensurePrekeys();
    await this.rotateSignedPreKeyIfNeeded();
    const identity = pairFromJson(this.state.identityKeyPair);
    const signed = this.state.signedPreKey;
    const edIdentity = await curvePubKeyToEd25519PubKey(identity.pubKey);
    const prekeys = Object.entries(this.state.prekeys).map(([id, pair]) => `<pk id='${id}'>${bytesToBase64(stripCurvePrefix(pairFromJson(pair).pubKey))}</pk>`).join('');
    const payload = `<bundle xmlns='${NS.OMEMO2}'><spk id='${signed.id}'>${bytesToBase64(stripCurvePrefix(pairFromJson(signed.keyPair).pubKey))}</spk><spks>${signed.signature}</spks><ik>${bytesToBase64(edIdentity)}</ik><prekeys>${prekeys}</prekeys></bundle>`;
    await this.xmpp.publishPep(NS.OMEMO2_BUNDLES, String(this.state.deviceId), payload, { accessModel: 'open', maxItems: 'max' });
  }

  publishDeviceList(ids) {
    const devices = ids.map((id) => `<device id='${Number(id)}'/>`).join('');
    return this.xmpp.publishPep(NS.OMEMO2_DEVICES, 'current', `<devices xmlns='${NS.OMEMO2}'>${devices}</devices>`, { accessModel: 'open' });
  }

  deviceAnnouncementDelay(attempt) {
    const jitter = crypto.getRandomValues(new Uint8Array(1))[0] / 2;
    return new Promise((resolve) => setTimeout(resolve, 125 + attempt * 75 + jitter));
  }

  deviceRetirementGrace() {
    return new Promise((resolve) => setTimeout(
      resolve,
      500 + crypto.getRandomValues(new Uint8Array(1))[0],
    ));
  }

  async ensureDeviceAnnouncement(knownIds = null) {
    const operation = this.deviceAnnouncement
      .catch(() => {})
      .then(() => this.ensureDeviceAnnouncementLocked(knownIds));
    this.deviceAnnouncement = operation;
    return operation;
  }

  async ensureDeviceAnnouncementLocked(knownIds = null) {
    const ownId = Number(this.state?.deviceId);
    if (!Number.isInteger(ownId) || ownId <= 0 || ownId > MAX_KEY_ID || this.retiring) {
      throw new Error('OMEMO 设备状态不可用于发布');
    }
    let stableReads = 0;
    let lastConfirmed = Array.isArray(knownIds) ? knownIds : [];
    for (let attempt = 0; attempt < DEVICE_ANNOUNCEMENT_ATTEMPTS; attempt += 1) {
      // This read must bypass the PEP cache on every attempt. Two resources can
      // both have fetched the old list before either publishes its bundle; a
      // cached read here would make their last-writer-wins loop permanent.
      const latest = await this.fetchDeviceIds(this.account, false);
      const merged = [...new Set([...latest, ownId])].sort((left, right) => left - right);
      await this.publishDeviceList(merged);
      await this.deviceAnnouncementDelay(attempt);
      const confirmed = await this.fetchDeviceIds(this.account, false);
      lastConfirmed = confirmed;
      if (confirmed.includes(ownId)) {
        stableReads += 1;
        if (stableReads >= DEVICE_ANNOUNCEMENT_STABLE_READS) {
          this.deviceCache.set(this.account, confirmed);
          return confirmed;
        }
      } else {
        stableReads = 0;
      }
    }
    this.deviceCache.set(this.account, lastConfirmed);
    throw new Error(`OMEMO 设备列表在 ${DEVICE_ANNOUNCEMENT_ATTEMPTS} 次尝试后仍未收敛；已停止发送`);
  }

  async ensureOwnDeviceForSend(knownIds) {
    const ownId = Number(this.state?.deviceId);
    if (knownIds.includes(ownId)) return knownIds;
    // Removing another endpoint is a two-step PEP operation: first publish a
    // list without the device, then retract its bundle. A send that observes
    // the intermediate state must not resurrect an intentionally retired
    // endpoint merely because its bundle is still visible for a moment.
    await this.deviceRetirementGrace();
    const latest = await this.fetchDeviceIds(this.account, false);
    if (latest.includes(ownId)) return latest;
    try {
      await this.fetchBundle(this.account, ownId);
    } catch (error) {
      if (error?.message !== 'item-not-found') throw error;
      const retired = new Error('This OMEMO device was removed by another authenticated account endpoint.');
      retired.code = 'OMEMO_DEVICE_RETIRED';
      retired.deviceId = ownId;
      this.ready = false;
      this.retiring = true;
      await this.completeRemoteRetirement(ownId);
      throw retired;
    }
    return this.ensureDeviceAnnouncement(latest);
  }

  async fetchDeviceIds(jid, useCache = true) {
    jid = bareJid(jid);
    if (useCache && this.deviceCache.has(jid)) return this.deviceCache.get(jid);
    let iq;
    try {
      iq = await this.xmpp.getPep(jid, NS.OMEMO2_DEVICES);
    } catch (error) {
      if (error?.message !== 'item-not-found') throw error;
      this.deviceCache.set(jid, []);
      return [];
    }
    const items = descendant(iq, 'items', NS.PUBSUB);
    const item = [...(items?.children || [])]
      .find((node) => node.localName === 'item' && node.namespaceURI === NS.PUBSUB && node.getAttribute('id') === 'current');
    if (!item) {
      this.deviceCache.set(jid, []);
      return [];
    }
    const ids = parseDeviceList(child(item, 'devices', NS.OMEMO2));
    this.deviceCache.set(jid, ids);
    return this.deviceCache.get(jid);
  }

  handlePepEvent(from, event) {
    const items = child(event, 'items', `${NS.PUBSUB}#event`);
    if (!items || items.getAttribute('node') !== NS.OMEMO2_DEVICES) return;
    const owner = bareJid(from);
    let normalized;
    try {
      const item = [...items.children]
        .find((node) => node.localName === 'item' && node.namespaceURI === NS.PUBSUB_EVENT && node.getAttribute('id') === 'current');
      if (!item) {
        const retract = [...items.children]
          .find((node) => node.localName === 'retract' && node.namespaceURI === NS.PUBSUB_EVENT && node.getAttribute('id') === 'current');
        if (!retract) return;
        normalized = [];
      } else {
        normalized = parseDeviceList(child(item, 'devices', NS.OMEMO2));
      }
    } catch (error) {
      console.warn('Ignored malformed OMEMO device-list event', error);
      return;
    }
    this.deviceCache.set(owner, normalized);
    if (owner !== this.account || !this.state || this.retiring || normalized.includes(Number(this.state.deviceId))) return;

    // XEP-0384 explicitly requires a device to reannounce itself if a
    // concurrent device-list publication overwrites its ID. Serialize repairs
    // and re-read the latest list so simultaneous resources converge.
    this.deviceRepair = this.deviceRepair
      .catch(() => {})
      .then(async () => {
        // A remote retirement publishes the converged list and retracts the
        // bundle as two PEP operations. Give the second operation a bounded
        // grace period before deciding whether this was merely a concurrent
        // list overwrite or an intentional revocation.
        await this.deviceRetirementGrace();
        if (this.retiring || !this.state) return;
        const latest = await this.fetchDeviceIds(this.account, false);
        if (!latest.includes(Number(this.state.deviceId))) {
          try {
            await this.fetchBundle(this.account, Number(this.state.deviceId));
          } catch (error) {
            if (error?.message !== 'item-not-found') throw error;
            const retiredId = Number(this.state.deviceId);
            this.ready = false;
            this.retiring = true;
            // Let this repair promise settle before teardown waits for all
            // in-flight state operations, otherwise it would await itself.
            setTimeout(() => {
              this.completeRemoteRetirement(retiredId)
                .catch((retirementError) => console.error('Remote OMEMO retirement failed', retirementError));
            }, 0);
            return;
          }
          await this.ensureDeviceAnnouncement(latest);
        }
      })
      .catch((error) => console.error('OMEMO device-list repair failed', error));
  }

  async fetchBundle(jid, deviceId) {
    deviceId = parseUint32(String(deviceId), 'OMEMO 设备 ID', { positive: true, maximum: MAX_KEY_ID });
    const iq = await this.xmpp.getPep(jid, NS.OMEMO2_BUNDLES, String(deviceId));
    const items = descendant(iq, 'items', NS.PUBSUB);
    const item = [...(items?.children || [])]
      .find((node) => node.localName === 'item' && node.namespaceURI === NS.PUBSUB && node.getAttribute('id') === String(deviceId));
    return parseBundleElement(child(item, 'bundle', NS.OMEMO2), jid, deviceId);
  }

  async ensureSessionUnlocked(bundle) {
    const address = new OMEMOAddress(bundle.jid, bundle.id);
    if (await this.store.loadSession(address.toString())) return;
    const prekey = bundle.prekeys[randomIndex(bundle.prekeys.length)];
    const builder = new SessionBuilder(this.store, address, PROFILE);
    await builder.processPreKey({
      registrationId: bundle.id,
      identityKey: base64ToBuffer(bundle.identityKey),
      signedPreKey: {
        keyId: bundle.signedPreKey.id,
        publicKey: base64ToBuffer(bundle.signedPreKey.key),
        signature: base64ToBuffer(bundle.signedPreKey.signature),
      },
      preKey: { keyId: prekey.id, publicKey: base64ToBuffer(prekey.key) },
    });
  }

  async ensureSession(bundle) {
    const address = new OMEMOAddress(bundle.jid, bundle.id);
    return this.withSessionOperation(address, () => this.ensureSessionUnlocked(bundle));
  }

  identityState(bundle) {
    const address = new OMEMOAddress(bundle.jid, bundle.id).toString();
    const encodedIdentity = bytesToBase64(base64ToBuffer(bundle.identityKey));
    const savedIdentity = this.state.identities[address];
    const decision = this.state.trustDecisions[address];
    if (decision?.identity === encodedIdentity && decision.state === 'distrusted') {
      return { address, encodedIdentity, trustState: 'distrusted' };
    }
    if (savedIdentity && savedIdentity !== encodedIdentity) {
      return { address, encodedIdentity, trustState: 'changed' };
    }
    if (decision?.identity === encodedIdentity && decision.state === 'verified') {
      return { address, encodedIdentity, trustState: 'verified' };
    }
    if (decision?.identity === encodedIdentity && decision.state === 'tofu' && decision.accepted === true) {
      return { address, encodedIdentity, trustState: 'tofu' };
    }
    return { address, encodedIdentity, trustState: 'untrusted' };
  }

  async setDeviceTrust(peer, deviceId, expectedIdentity, state) {
    if (!['tofu', 'verified', 'distrusted'].includes(state)) throw new Error('OMEMO 信任状态无效');
    const bundle = await this.fetchBundle(bareJid(peer), Number(deviceId));
    const currentIdentity = bytesToBase64(base64ToBuffer(bundle.identityKey));
    if (currentIdentity !== expectedIdentity) {
      throw new Error('设备身份密钥在确认期间再次变化；请刷新并重新核对指纹');
    }
    const address = new OMEMOAddress(bundle.jid, bundle.id).toString();
    this.state.trustDecisions[address] = {
      identity: currentIdentity,
      state,
      accepted: state === 'tofu',
      updatedAt: new Date().toISOString(),
    };
    // An explicit trust decision for the current key replaces an old TOFU
    // identity and session. Distrust deliberately leaves the last accepted
    // identity in place so no library callback can silently accept the key.
    if (state !== 'distrusted') this.state.identities[address] = currentIdentity;
    delete this.state.sessions[address];
    await this.store.persist();
    if (state === 'verified') await this.processPendingTrustMessages(address);
    if (state !== 'tofu') this.scheduleTrustPropagation(bundle.jid, currentIdentity, state);
  }

  addressOwner(address) {
    const separator = String(address).lastIndexOf('.');
    return separator > 0 ? bareJid(String(address).slice(0, separator)) : '';
  }

  async verifiedIdentityMap() {
    const identities = new Map();
    const append = (jid, identity) => {
      if (!identities.has(jid)) identities.set(jid, new Set());
      identities.get(jid).add(identity);
    };
    const ownIdentity = pairFromJson(this.state.identityKeyPair);
    append(this.account, bytesToBase64(await curvePubKeyToEd25519PubKey(ownIdentity.pubKey)));
    for (const [address, decision] of Object.entries(this.state.trustDecisions)) {
      if (decision?.state !== 'verified' || !decision.identity) continue;
      const owner = this.addressOwner(address);
      if (owner) append(owner, decision.identity);
    }
    return identities;
  }

  trustMessageXml(owners) {
    const ownerXml = owners.map(({ jid, entries }) => {
      const actions = entries.map(({ identity, state }) => `<${state === 'distrusted' ? 'distrust' : 'trust'}>${canonicalBase64(identity, 32, 'OMEMO 信任密钥标识')}</${state === 'distrusted' ? 'distrust' : 'trust'}>`).join('');
      return `<key-owner jid='${xmlEscape(bareJid(jid))}'>${actions}</key-owner>`;
    }).join('');
    return `<trust-message xmlns='${TRUST_MESSAGES}' usage='${ATM}' encryption='${NS.OMEMO2}'>${ownerXml}</trust-message>`;
  }

  async verifiedBundlesFor(target) {
    const owners = [...new Set([bareJid(target), this.account])];
    const bundles = [];
    for (const owner of owners) {
      const ids = await this.fetchDeviceIds(owner, false);
      for (const id of ids) {
        if (owner === this.account && id === Number(this.state.deviceId)) continue;
        try {
          const bundle = await this.fetchBundle(owner, id);
          if (this.identityState(bundle).trustState !== 'verified') continue;
          await this.ensureSession(bundle);
          bundles.push(bundle);
        } catch (error) {
          console.warn('Skipped unavailable authenticated endpoint during ATM fanout', owner, id, error);
        }
      }
    }
    return bundles;
  }

  async sendTrustMessage(target, owners) {
    target = bareJid(target);
    const bundles = await this.verifiedBundlesFor(target);
    if (!bundles.length) return false;
    const timestamp = new Date().toISOString();
    const encrypted = await this.encryptWithBundles(bundles, [], '', {
      from: this.account,
      to: target,
      timeStamp: timestamp,
      contentXml: this.trustMessageXml(owners),
    });
    const id = `trust-${crypto.randomUUID()}`;
    // A v2 proof commits to the completed ciphertext without disclosing its
    // payload to the challenge endpoint. The ratchet has advanced at this
    // point, so any proof failure remains fail-closed and the ciphertext is
    // never sent or staged.
    const outerPayload = this.prepareOutbound
      ? await this.prepareOutbound({
        kind: 'trust', to: target, type: 'chat', payload: encrypted.xml, id,
      })
      : '';
    const record = {
      id,
      to: target,
      type: 'chat',
      payload: `${encrypted.xml}${outerPayload}`,
    };
    if (this.sendEncrypted) await this.sendEncrypted(record);
    else this.xmpp.sendMessage(record.to, record.payload, record.id);
    return true;
  }

  scheduleTrustPropagation(owner, identity, state) {
    if (!this.ready || this.retiring) return;
    this.trustFanout = this.trustFanout
      .catch(() => {})
      .then(async () => {
        owner = bareJid(owner);
        const verified = await this.verifiedIdentityMap();
        const singleDecision = [{ jid: owner, entries: [{ identity, state }] }];
        if (owner !== this.account) {
          // Contact trust changes are first synchronized to our authenticated
          // endpoints. A distrust decision is intentionally not disclosed to
          // the contact; XEP-0450 requires that message only for own endpoints.
          await this.sendTrustMessage(this.account, singleDecision);
          if (state === 'verified') {
            const ownEntries = [...(verified.get(this.account) || [])]
              .map((ownIdentity) => ({ identity: ownIdentity, state: 'verified' }));
            if (ownEntries.length) await this.sendTrustMessage(owner, [{ jid: this.account, entries: ownEntries }]);
          }
          return;
        }
        const contactTargets = [...verified.keys()].filter((jid) => jid !== this.account);
        if (state === 'verified') {
          // Existing authenticated own endpoints may receive the complete
          // trust graph so the newly authenticated own endpoint can catch up.
          // Contacts receive only the new own key: disclosing our decisions
          // about unrelated contacts would violate ATM's trust graph and leak
          // relationship metadata.
          const ownPayload = [...verified.entries()].map(([jid, keys]) => ({
            jid,
            entries: [...keys].map((key) => ({ identity: key, state: 'verified' })),
          }));
          await this.sendTrustMessage(this.account, ownPayload);
        } else {
          await this.sendTrustMessage(this.account, singleDecision);
        }
        for (const target of contactTargets) await this.sendTrustMessage(target, singleDecision);
      })
      .catch((error) => console.error('XEP-0450 trust propagation failed', error));
  }

  async applyTrustMessage(senderAddress, timestamp, owners, authenticated, { queue = true } = {}) {
    const stamp = Date.parse(timestamp);
    if (!Number.isFinite(stamp)) throw new Error('信任消息时间戳无效');
    if (stamp > Date.now() + MAX_TRUST_CLOCK_SKEW_MS) throw new Error('Trust message timestamp is too far in the future');
    const entryCount = owners.reduce((total, owner) => total + (owner.entries?.length || 0), 0);
    if (!owners.length || owners.length > MAX_TRUST_OWNERS || entryCount > MAX_TRUST_ENTRIES) {
      throw new Error('Trust message exceeds the safety limit');
    }
    // Enforce resource bounds before the replay fast-path. The XML parser
    // already performs the same checks, but callers of this internal entry
    // point must not be able to bypass validation merely by reusing an old
    // timestamp.
    const last = Number(this.state.lastTrustTimestamps[senderAddress] || 0);
    if (stamp <= last) return { applied: false, replay: true };
    const pending = [];
    const senderOwner = this.addressOwner(senderAddress);
    if (authenticated) {
      for (const owner of owners) {
        // XEP-0450 lets an authenticated own endpoint propagate decisions for
        // any owner. A contact endpoint may only introduce or revoke keys of
        // that same contact; it must never become a trust oracle for a third
        // party account.
        if (senderOwner !== this.account && owner.jid !== senderOwner) continue;
        let bundles = [];
        try {
          const ids = await this.fetchDeviceIds(owner.jid, false);
          bundles = await Promise.all(ids.map((id) => this.fetchBundle(owner.jid, id)));
        } catch (error) {
          console.warn('ATM key lookup deferred', owner.jid, error);
        }
        for (const entry of owner.entries) {
          const bundle = bundles.find((candidate) => candidate.identityKey === entry.identity);
          if (!bundle) {
            pending.push({ jid: owner.jid, entries: [entry] });
            continue;
          }
          const address = new OMEMOAddress(bundle.jid, bundle.id).toString();
          const existing = this.state.trustDecisions[address];
          // A trust assertion never overrides a local manual decision. A
          // cryptographically authenticated distrust assertion is different:
          // treating it as a revocation is the fail-closed behavior required
          // when another authenticated endpoint reports compromise/removal.
          if (existing && !existing.automatic
            && (entry.state !== 'distrusted' || existing.state === 'distrusted')) continue;
          this.state.trustDecisions[address] = {
            identity: entry.identity,
            state: entry.state,
            updatedAt: new Date(stamp).toISOString(),
            automatic: true,
            source: senderAddress,
          };
          if (entry.state === 'verified') this.state.identities[address] = entry.identity;
          delete this.state.sessions[address];
        }
      }
    } else {
      pending.push(...owners);
    }
    if (pending.length && queue) {
      this.state.pendingTrustMessages = this.state.pendingTrustMessages
        .filter((item) => !(item.senderAddress === senderAddress && item.timestamp === timestamp));
      this.state.pendingTrustMessages.push({ senderAddress, timestamp, owners: pending });
      this.state.pendingTrustMessages = this.trimPendingTrustMessages(this.state.pendingTrustMessages);
    } else if (!pending.length) {
      this.state.lastTrustTimestamps[senderAddress] = stamp;
      this.state.pendingTrustMessages = this.state.pendingTrustMessages
        .filter((item) => !(item.senderAddress === senderAddress && item.timestamp === timestamp));
    }
    await this.store.persist();
    return { applied: authenticated && !pending.length, pending: pending.length };
  }

  trimPendingTrustMessages(messages) {
    const sorted = [...messages]
      .filter((item) => item && Array.isArray(item.owners) && Number.isFinite(Date.parse(item.timestamp)))
      .sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp));
    const retained = [];
    let totalEntries = 0;
    for (let index = sorted.length - 1; index >= 0 && retained.length < MAX_PENDING_TRUST_MESSAGES; index -= 1) {
      const item = sorted[index];
      const count = item.owners.reduce((total, owner) => total + (owner.entries?.length || 0), 0);
      if (!count || count > MAX_TRUST_ENTRIES || totalEntries + count > MAX_TRUST_ENTRIES) continue;
      retained.unshift(item);
      totalEntries += count;
    }
    return retained;
  }

  async processPendingTrustMessages(senderAddress) {
    const pending = this.state.pendingTrustMessages
      .filter((item) => item.senderAddress === senderAddress)
      .sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp));
    for (const item of pending) {
      await this.applyTrustMessage(senderAddress, item.timestamp, item.owners, true);
    }
  }

  async resetSession(peer, deviceId) {
    peer = bareJid(peer);
    deviceId = parseUint32(String(deviceId), 'OMEMO 设备 ID', { positive: true, maximum: MAX_KEY_ID });
    const address = new OMEMOAddress(peer, deviceId).toString();
    await this.store.removeSession(address);
  }

  async devicesForChat(peer, { refresh = false, establishSessions = true } = {}) {
    peer = bareJid(peer);
    if (refresh) this.deviceCache.delete(peer);
    const recipientIds = await this.fetchDeviceIds(peer, !refresh);
    if (!recipientIds.length) throw new Error('对方尚未发布 OMEMO 设备，不能安全发送消息');
    // A send must use one coherent, freshly fetched view for both the peer
    // and our other endpoints. Depending only on a self-PEP event here can
    // omit a just-added own device if that notification was delayed/lost.
    let announcedOwnIds = await this.fetchDeviceIds(this.account, false);
    announcedOwnIds = await this.ensureOwnDeviceForSend(announcedOwnIds);
    const ownIds = announcedOwnIds
      .filter((id) => id !== Number(this.state.deviceId));
    const descriptors = [
      ...recipientIds.map((id) => ({ jid: peer, id })),
      ...ownIds.map((id) => ({ jid: this.account, id })),
    ];
    const bundles = [];
    const failures = [];
    const excluded = [];
    for (const descriptor of descriptors) {
      try {
        const bundle = await this.fetchBundle(descriptor.jid, descriptor.id);
        const identity = this.identityState(bundle);
        if (identity.trustState === 'distrusted') {
          excluded.push(descriptor);
          continue;
        }
        if (identity.trustState === 'changed') {
          throw new Error(`设备 ${descriptor.id} 的身份密钥已变化；请先核对并明确处理新指纹`);
        }
        if (!['verified', 'tofu'].includes(identity.trustState)) {
          throw new Error(`设备 ${descriptor.jid}#${descriptor.id} 尚未作出信任决定；发送已暂停`);
        }
        if (establishSessions) await this.ensureSession(bundle);
        bundles.push(bundle);
      } catch (error) {
        failures.push({ ...descriptor, error: error.message });
      }
    }
    if (!bundles.some((bundle) => bundle.jid === peer)) {
      throw new Error(failures[0]?.error || '对方的所有 OMEMO 设备均已标记为不信任');
    }
    if (failures.length) {
      const failed = failures.map(({ jid, id }) => `${jid}#${id}`).join(', ');
      throw new Error(`设备列表与公钥包不一致，已停止发送以避免遗漏设备：${failed}`);
    }
    return { bundles, failures, excluded };
  }

  async assertEncryptable(peer) {
    if (!this.ready) throw new Error('OMEMO 尚未初始化');
    await this.devicesForChat(peer, { refresh: true, establishSessions: false });
  }

  async assertGroupEncryptable(peers, roomJid) {
    if (!this.ready) throw new Error('OMEMO 尚未初始化');
    if (!roomJid || !bareJid(roomJid)) throw new Error('OMEMO 群聊缺少房间上下文');
    const recipients = [...new Set(peers.map(bareJid).filter((jid) => jid && jid !== this.account))];
    if (!recipients.length) throw new Error('群聊中还没有其他可加密的成员');
    for (const peer of recipients) {
      try {
        await this.devicesForChat(peer, { refresh: true, establishSessions: false });
      } catch (error) {
        throw new Error(`${peer}：${error.message}`);
      }
    }
  }

  async encrypt(peer, plaintext, { contentXml = null } = {}) {
    if (!this.ready) throw new Error('OMEMO 尚未初始化');
    const { bundles, failures } = await this.devicesForChat(peer, { refresh: true });
    return this.encryptWithBundles(bundles, failures, plaintext, { from: this.account, contentXml });
  }

  async encryptOptOut(peer, reason = '') {
    reason = String(reason || '');
    if (reason.length > 1024) throw new Error('OMEMO opt-out reason is too long');
    const reasonXml = reason ? `<reason>${xmlEscape(reason)}</reason>` : '';
    return this.encrypt(peer, '', {
      contentXml: `<opt-out xmlns='${NS.OMEMO2}'>${reasonXml}</opt-out>`,
    });
  }

  async encryptGroup(peers, plaintext, roomJid, { contentXml = null } = {}) {
    if (!this.ready) throw new Error('OMEMO 尚未初始化');
    if (!roomJid || !bareJid(roomJid)) throw new Error('OMEMO 群聊缺少房间上下文');
    const recipients = [...new Set(peers.map(bareJid).filter((jid) => jid && jid !== this.account))];
    if (!recipients.length) throw new Error('群聊中还没有其他可加密的成员');
    const bundlesByAddress = new Map();
    const failures = [];
    for (const peer of recipients) {
      try {
        // MUC participants are often not roster contacts and therefore do not
        // reliably receive PEP device-list events. Refetch before every group
        // send so a newly added or removed device cannot be silently omitted.
        const result = await this.devicesForChat(peer, { refresh: true });
        for (const bundle of result.bundles) bundlesByAddress.set(`${bundle.jid}\0${bundle.id}`, bundle);
        failures.push(...result.failures);
      } catch (error) {
        throw new Error(`${peer}：${error.message}`);
      }
    }
    return this.encryptWithBundles([...bundlesByAddress.values()], failures, plaintext, {
      from: this.account,
      to: bareJid(roomJid),
      contentXml,
    });
  }

  async encryptWithBundles(bundles, failures, plaintext, context) {
    const { keyAndTag, payload } = await encryptEnvelope(plaintext, context);
    const grouped = new Map();
    for (const bundle of bundles) {
      const address = new OMEMOAddress(bundle.jid, bundle.id);
      const result = await this.withSessionOperation(address, async () => {
        await this.ensureSessionUnlocked(bundle);
        const cipher = new SessionCipher(this.store, address, PROFILE);
        return cipher.encrypt(keyAndTag);
      });
      const key = `<key rid='${bundle.id}'${result.kex ? " kex='true'" : ''}>${btoa(result.body)}</key>`;
      if (!grouped.has(bundle.jid)) grouped.set(bundle.jid, []);
      grouped.get(bundle.jid).push(key);
    }
    const keyGroups = [...grouped.entries()].map(([jid, keys]) => `<keys jid='${xmlEscape(jid)}'>${keys.join('')}</keys>`).join('');
    return {
      xml: `<encrypted xmlns='${NS.OMEMO2}'><header sid='${this.state.deviceId}'>${keyGroups}</header><payload>${payload}</payload></encrypted><encryption xmlns='${EME}' namespace='${NS.OMEMO2}' name='OMEMO'/><store xmlns='${NS.HINTS}'/>`,
      failures,
    };
  }

  async encryptEmpty(peer, recipientDevice) {
    if (!this.ready) throw new Error('OMEMO 尚未初始化');
    peer = bareJid(peer);
    recipientDevice = parseUint32(String(recipientDevice), 'OMEMO 接收设备 ID', { positive: true, maximum: MAX_KEY_ID });
    const address = new OMEMOAddress(peer, recipientDevice);
    const result = await this.withSessionOperation(address, async () => {
      if (!await this.store.loadSession(address.toString())) {
        const bundle = await this.fetchBundle(peer, recipientDevice);
        await this.ensureSessionUnlocked(bundle);
      }
      const cipher = new SessionCipher(this.store, address, PROFILE);
      return cipher.encrypt(new Uint8Array(32).buffer);
    });
    return `<encrypted xmlns='${NS.OMEMO2}'><header sid='${this.state.deviceId}'><keys jid='${xmlEscape(peer)}'><key rid='${recipientDevice}'${result.kex ? " kex='true'" : ''}>${btoa(result.body)}</key></keys></header></encrypted><encryption xmlns='${EME}' namespace='${NS.OMEMO2}' name='OMEMO'/><no-store xmlns='${NS.HINTS}'/>`;
  }

  async decrypt(message, sender, { roomJid = null, toJid = null, stanzaTimestamp = null } = {}) {
    if (!this.ready) throw new Error('OMEMO device is frozen or not initialized');
    const encrypted = child(message, 'encrypted', NS.OMEMO2);
    if (!encrypted) return null;
    const parsed = parseEncryptedElement(encrypted);
    const { payload, senderDevice } = parsed;
    // Refresh stale PEP state when a stanza references an unknown sender id.
    // Retired devices can still occur in MAM, so absence after the refresh is
    // surfaced to the caller but is not treated as a decryption oracle.
    let announced = null;
    try {
      const announcedDevices = await this.fetchDeviceIds(sender, false);
      announced = announcedDevices.includes(senderDevice);
    } catch (error) {
      const cached = this.deviceCache.get(bareJid(sender));
      if (cached) announced = cached.includes(senderDevice);
      console.warn('OMEMO device-list refresh failed during decryption; continuing with authenticated ratchet state', error);
    }
    const senderAddress = new OMEMOAddress(bareJid(sender), senderDevice).toString();
    if (this.state.trustDecisions[senderAddress]?.state === 'distrusted') {
      throw new Error('消息来自已标记为不信任的 OMEMO 设备');
    }
    const ownKeys = parsed.groups.find(({ jid }) => jid === this.account);
    const key = ownKeys?.keys.find(({ recipientDevice }) => recipientDevice === Number(this.state.deviceId));
    if (!key) throw new Error('这条消息没有加密给当前设备');
    const keyBytes = key.bytes;
    const isKeyExchange = key.kex;
    const address = new OMEMOAddress(bareJid(sender), senderDevice);
    let result;
    try {
      result = await this.withSessionOperation(address, async () => {
        const cipher = new SessionCipher(this.store, address, PROFILE);
        if (isKeyExchange) {
          requireOmemoKeyExchangePreKey(keyBytes);
          return cipher.decryptPreKeyWhisperMessage(keyBytes, 'binary');
        }
        return cipher.decryptWhisperMessage(keyBytes, 'binary');
      });
      // The plaintext is already authenticated at this point. A temporary
      // PEP outage must not turn a successfully decrypted message into a
      // visible failure; replenishment is serialized and retried later.
      if (isKeyExchange) this.scheduleBundleRepair();
    } catch (error) {
      if (error?.name === 'MessageCounterError') {
        return { body: '', duplicate: true, senderDevice, announced, authenticated: false, trustState: 'unknown' };
      }
      throw error;
    }
    const savedIdentity = this.state.identities[senderAddress];
    const decision = this.state.trustDecisions[senderAddress];
    const explicitlyTofu = decision?.state === 'tofu'
      && decision.accepted === true
      && decision.identity === savedIdentity;
    const trust = {
      authenticated: decision?.state === 'verified' && decision.identity === savedIdentity,
      trustState: decision?.state === 'verified' && decision.identity === savedIdentity
        ? 'verified'
        : explicitlyTofu ? 'tofu' : 'untrusted',
    };
    if (!payload) {
      const emptyKey = new Uint8Array(result.plaintext);
      if (emptyKey.byteLength !== 32 || emptyKey.some((byte) => byte !== 0)) {
        throw new Error('OMEMO 空消息密钥无效');
      }
      return {
        body: '',
        empty: true,
        needsReply: isKeyExchange || Number(result.ratchet?.counter) >= 53,
        senderDevice,
        announced,
        ...trust,
      };
    }
    const cleartext = await decryptEnvelope(result.plaintext, payload, {
      from: sender,
      to: bareJid(roomJid || toJid),
      requireTo: Boolean(roomJid),
      details: true,
      referenceTime: stanzaTimestamp,
    });
    const trustResult = cleartext.trustMessage
      ? await this.applyTrustMessage(
        senderAddress,
        cleartext.trustTimestamp,
        cleartext.trustMessage,
        trust.authenticated,
      )
      : null;
    return {
      body: cleartext.body,
      attachment: cleartext.attachment,
      optOut: cleartext.optOut,
      trustProcessed: trustResult,
      needsReply: isKeyExchange || Number(result.ratchet?.counter) >= 53,
      senderDevice,
      announced,
      ...trust,
    };
  }

  async inspectDevices(peer, refresh = false) {
    const ids = await this.fetchDeviceIds(peer, !refresh);
    const devices = [];
    for (const id of ids) {
      try {
        const bundle = await this.fetchBundle(peer, id);
        const address = new OMEMOAddress(bareJid(peer), id).toString();
        const encodedIdentity = bytesToBase64(base64ToBuffer(bundle.identityKey));
        const identity = this.identityState(bundle);
        devices.push({
          id,
          identityKey: encodedIdentity,
          fingerprint: fingerprint(await ed25519PubKeyToCurvePubKey(base64ToBuffer(bundle.identityKey))),
          trusted: identity.trustState === 'verified',
          trustState: identity.trustState,
        });
      } catch (error) {
        devices.push({ id, fingerprint: null, trusted: false, error: error.message });
      }
    }
    return devices;
  }

  async getOwnDevice() {
    const identity = pairFromJson(this.state.identityKeyPair);
    return { id: Number(this.state.deviceId), fingerprint: fingerprint(stripCurvePrefix(identity.pubKey)) };
  }

  getRecoverableSourceTransfer() {
    const marker = this.state?.recoveryTransfer;
    if (marker?.role !== 'source') return null;
    this.validateRecoveryMarker(marker);
    return { ...marker };
  }

  async replaceSourceRecoveryMarker(oldTransferId, newTransferId, newPollSecret) {
    const marker = this.state?.recoveryTransfer;
    if (marker?.role !== 'source' || marker.transferId !== String(oldTransferId)
      || !RECOVERY_UUID.test(String(newTransferId))) {
      throw new Error('The frozen OMEMO source marker cannot be replaced');
    }
    validateOmemoTransferSecret(newPollSecret, 'OMEMO source poll secret');
    this.ready = false;
    await this.quiesceStateOperations();
    let oldTransfer;
    try {
      oldTransfer = await this.lookupRecoveryTransfer?.(marker.transferId);
    } catch (error) {
      if (error?.status !== 404) throw error;
    }
    if (oldTransfer && !['revoked', 'expired'].includes(oldTransfer.state)) {
      throw new Error('The previous OMEMO transfer revocation is not authoritative');
    }
    const authority = await this.lookupRecoveryAuthority?.();
    const highWater = Number(authority?.latest_consumed_generation || 0);
    if (!Number.isSafeInteger(marker.baselineGeneration)
      || highWater !== marker.baselineGeneration
      || authority?.latest_consumed_transfer_id === marker.transferId) {
      throw new Error('OMEMO recovery authority advanced while replacing the frozen transfer');
    }
    // One sealed write replaces the old marker directly. There is no state in
    // which the ratchet is unfrozen, ready, or missing its recovery fence.
    this.state.recoveryTransfer = {
      transferId: String(newTransferId),
      generation: null,
      role: 'source',
      pollSecret: newPollSecret,
      baselineGeneration: highWater,
      phase: 'source-frozen',
    };
    await this.store.persist();
    return { transferId: String(newTransferId), baselineGeneration: highWater };
  }

  async freezeDeviceTransfer(transferId, pollSecret, baselineGeneration) {
    if (!this.ready || this.retiring || this.recoveryOperation || this.state?.recoveryTransfer) {
      throw new Error('The OMEMO device is not ready for transfer');
    }
    if (!RECOVERY_UUID.test(String(transferId))) throw new Error('The transfer identifier is invalid');
    validateOmemoTransferSecret(pollSecret, 'OMEMO source poll secret');
    if (!Number.isSafeInteger(baselineGeneration) || baselineGeneration < 0) {
      throw new Error('The OMEMO recovery authority baseline is invalid');
    }
    this.ready = false;
    const operation = (async () => {
      const pending = [
        this.deviceRepair,
        this.deviceAnnouncement,
        this.bundleRepair,
        this.bundleOperation,
        this.trustFanout,
        ...this.sessionOperations.values(),
      ];
      const outcomes = await Promise.allSettled(pending);
      const failed = outcomes.find((outcome) => outcome.status === 'rejected');
      if (failed) throw failed.reason;
      await this.store.flush();
      this.state.recoveryTransfer = {
        transferId: String(transferId),
        generation: null,
        role: 'source',
        pollSecret,
        baselineGeneration,
        phase: 'source-frozen',
      };
      await this.store.persist();
    })();
    this.recoveryOperation = operation;
    try {
      await operation;
    } catch (error) {
      // A failure before the durable marker exists did not freeze anything;
      // restore normal use. Once the marker may exist, remain fail closed and
      // let initialization/authority recovery decide the state.
      if (!this.state?.recoveryTransfer && !this.retiring) this.ready = true;
      throw error;
    } finally {
      if (this.recoveryOperation === operation) this.recoveryOperation = null;
    }
  }

  async createDeviceTransfer(passphrase, transfer, pollSecret, { signal } = {}) {
    if (this.retiring || this.recoveryOperation
      || this.state?.recoveryTransfer?.role !== 'source') {
      throw new Error('The OMEMO device is not frozen for this transfer');
    }
    const metadata = {
      account: this.account,
      transfer_id: String(transfer.id),
      generation: Number(transfer.generation),
      source_device_id: Number(transfer.source_device_id),
      created_at: String(transfer.created_at),
      expires_at: String(transfer.expires_at),
    };
    if (metadata.source_device_id !== Number(this.state.deviceId)) {
      throw new Error('The server prepared the transfer for a different OMEMO device');
    }
    validateOmemoTransferSecret(pollSecret, 'OMEMO source poll secret');
    if (this.state.recoveryTransfer.transferId !== metadata.transfer_id
      || this.state.recoveryTransfer.pollSecret !== pollSecret
      || (this.state.recoveryTransfer.generation !== null
        && this.state.recoveryTransfer.generation !== metadata.generation)) {
      throw new Error('The prepared transfer does not match the local source freeze');
    }
    const operation = (async () => {
      this.state.recoveryTransfer.generation = metadata.generation;
      this.state.recoveryTransfer.phase = 'server-prepared';
      await this.store.persist();
      const snapshot = JSON.parse(JSON.stringify(this.state));
      // The poll capability belongs only to the source. Never include it (or
      // even its recovery marker) in the encrypted package delivered to the
      // destination.
      delete snapshot.recoveryTransfer;
      const encrypted = await createOmemoTransferPackageInWorker({
        metadata,
        state: snapshot,
        passphrase,
        signal,
      });
      // Persist the exact encrypted-file digest only after encryption; it
      // cannot be part of the package snapshot without becoming circular.
      this.state.recoveryTransfer.packageSha256 = encrypted.sha256;
      this.state.recoveryTransfer.phase = 'package-sealed';
      await this.store.persist();
      return encrypted;
    })();
    this.recoveryOperation = operation;
    try {
      return await operation;
    } finally {
      if (this.recoveryOperation === operation) this.recoveryOperation = null;
      if (!this.retiring && !this.state?.recoveryTransfer) this.ready = true;
    }
  }

  async cancelDeviceTransfer(transferId) {
    if (this.state?.recoveryTransfer?.transferId !== String(transferId)) return;
    delete this.state.recoveryTransfer;
    await this.store.persist();
    if (!this.retiring) this.ready = true;
  }

  async decryptDeviceTransfer(packageBuffer, passphrase, { signal } = {}) {
    return openOmemoTransferPackageInWorker({
      packageBuffer,
      expectedAccount: this.account,
      passphrase,
      signal,
    });
  }

  async installDeviceTransfer(imported, consumerSecret) {
    if (!this.ready || this.retiring || this.recoveryOperation) {
      throw new Error('The current OMEMO device is not ready to be replaced');
    }
    const metadata = imported?.metadata;
    if (metadata?.account !== this.account
      || Number(imported?.state?.deviceId) !== Number(metadata?.source_device_id)) {
      throw new Error('The transferred OMEMO state is inconsistent');
    }
    if (Number(this.state.deviceId) === Number(metadata.source_device_id)) {
      throw new Error('This transfer package contains the device already active in this browser');
    }
    // This is the last non-destructive boundary. Decode every serialized
    // Double Ratchet record and validate the complete versioned state before
    // writing a replacement journal, touching PEP, or deleting local keys.
    validateTransferredOmemoState(
      imported.state,
      metadata.source_device_id,
      (serialized) => {
        const record = SessionRecord.deserialize(serialized);
        return { canonical: record.serialize(), ratchets: record.getSessions() };
      },
    );
    validateOmemoTransferSecret(consumerSecret, 'OMEMO destination consumer secret');
    if (!RECOVERY_SHA256.test(imported.sha256)) {
      throw new Error('The transfer package digest is invalid');
    }
    const consumerCommitment = await omemoConsumerCommitmentHex(
      this.account,
      String(metadata.transfer_id),
      consumerSecret,
    );

    const replacementJournal = {
      version: 1,
      transferId: String(metadata.transfer_id),
      generation: Number(metadata.generation),
      sourceDeviceId: Number(metadata.source_device_id),
      destinationDeviceId: Number(this.state.deviceId),
      consumerCommitment,
      packageSha256: imported.sha256,
      phase: 'package-sealed',
    };
    validateReplacementJournal(replacementJournal);
    // This journal is independent of the crypto record being replaced.  It
    // commits before any PEP retirement or local deletion, so a crash can
    // never make the old destination state look like an active device again.
    await setValue(
      'preferences',
      replacementJournalName(this.account),
      replacementJournal,
    );

    // Remove the destination's temporary device while it still owns an XMPP
    // connection. The source device ID remains published: ownership is moved
    // by the server-side generation fence, not by cloning or retracting it.
    await this.retireOwnDevice();
    await this.quiesceStateOperations();
    const oldStateErasures = await Promise.allSettled([
      deleteValue('crypto', this.account),
      deleteValue('preferences', wrappingKeyName(this.account)),
    ]);
    const oldStateFailure = oldStateErasures.find((result) => result.status === 'rejected');
    if (oldStateFailure) throw oldStateFailure.reason;

    const restored = JSON.parse(JSON.stringify(imported.state));
    restored.recoveryTransfer = {
      transferId: String(metadata.transfer_id),
      generation: Number(metadata.generation),
      role: 'destination',
      consumerSecret,
      consumerCommitment,
      packageSha256: imported.sha256,
      phase: 'destination-installed',
    };
    restored.pendingTrustMessages = [];
    restored.trustDecisions = Object.fromEntries(
      Object.entries(restored.identities || {}).map(([address, identity]) => [address, {
        identity,
        state: 'distrusted',
        accepted: false,
        recoveryReverification: true,
        updatedAt: new Date().toISOString(),
      }]),
    );

    const wrappingKey = await loadWrappingKey(this.account, { create: true });
    try {
      const sealed = await sealState(this.account, restored, wrappingKey);
      await setValue('crypto', this.account, sealed);
      replacementJournal.phase = 'destination-installed';
      await setValue('preferences', replacementJournalName(this.account), replacementJournal);
      // Keep the same account Web Lock, but move the live manager reference to
      // the newly sealed state so teardown cannot flush the retired store over
      // the replacement after the server consume request resolves.
      this.state = restored;
      this.store = new PersistentOmemoStore(this.account, restored, wrappingKey);
      this.ready = false;
    } catch (error) {
      await Promise.allSettled([
        deleteValue('crypto', this.account),
        deleteValue('preferences', wrappingKeyName(this.account)),
      ]);
      throw error;
    }
    return { id: Number(restored.deviceId), consumerCommitment };
  }

  async markDeviceTransferPhase(phase) {
    if (!RECOVERY_PHASES.has(phase) || !this.state?.recoveryTransfer) {
      throw new Error('OMEMO device-transfer phase transition is invalid');
    }
    this.state.recoveryTransfer.phase = phase;
    await this.store.persist();
    const journal = await getValue('preferences', replacementJournalName(this.account));
    if (journal !== undefined) {
      validateReplacementJournal(journal);
      journal.phase = phase;
      await setValue('preferences', replacementJournalName(this.account), journal);
    }
  }

  async eraseInstalledDeviceTransfer() {
    const journalName = replacementJournalName(this.account);
    const journal = await getValue('preferences', journalName);
    if (journal !== undefined) {
      validateReplacementJournal(journal);
      journal.phase = 'retirement-complete';
      await setValue('preferences', journalName, journal);
    }
    const erasures = await Promise.allSettled([
      deleteValue('crypto', this.account),
      deleteValue('preferences', wrappingKeyName(this.account)),
      deleteValue('preferences', journalName),
    ]);
    const failed = erasures.find((result) => result.status === 'rejected');
    if (failed) throw failed.reason;
  }

  async retireOwnDevice() {
    this.retiring = true;
    const ownId = Number(this.state.deviceId);
    try {
      const current = await this.fetchDeviceIds(this.account, false);
      const remaining = current.filter((id) => id !== ownId);
      await this.publishDeviceList(remaining);
      await this.xmpp.retractPep(NS.OMEMO2_BUNDLES, String(ownId)).catch((error) => {
        if (error?.message !== 'item-not-found') throw error;
      });
      await this.convergeRetiredDeviceId(ownId);
      this.deviceCache.set(this.account, remaining);
      this.ready = false;
    } catch (error) {
      this.retiring = false;
      throw error;
    }
  }

  async convergeRetiredDeviceId(deviceId) {
    // A different authenticated endpoint can publish a stale device-list
    // snapshot between our first list update and bundle retraction. Re-read
    // after the bundle is gone and remove that now-unusable ghost ID. A live
    // endpoint cannot legitimately republish the missing private bundle.
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const current = await this.fetchDeviceIds(this.account, false);
      if (!current.includes(Number(deviceId))) return current;
      await this.publishDeviceList(current.filter((id) => id !== Number(deviceId)));
      await this.deviceAnnouncementDelay(attempt);
    }
    const final = await this.fetchDeviceIds(this.account, false);
    if (final.includes(Number(deviceId))) throw new Error('OMEMO retired device list did not converge');
    return final;
  }

  async retireAndEraseLocalState() {
    await this.retireOwnDevice();
    // Drain every in-flight ratchet/store operation before deleting the
    // sealed record; otherwise a late IndexedDB write could recreate keys
    // after the user selected permanent erasure.
    await this.destroy();
    await deleteValue('crypto', this.account);
    await deleteValue('preferences', wrappingKeyName(this.account));
  }

  async retireOtherOwnDevice(deviceId) {
    deviceId = parseUint32(String(deviceId), 'OMEMO 设备 ID', {
      positive: true,
      maximum: MAX_KEY_ID,
    });
    if (deviceId === Number(this.state.deviceId)) {
      throw new Error('不能通过此操作移除当前 OMEMO 设备');
    }
    const current = await this.fetchDeviceIds(this.account, false);
    if (!current.includes(deviceId)) return;
    const address = new OMEMOAddress(this.account, deviceId).toString();
    let identity = this.state.trustDecisions[address]?.identity || this.state.identities[address];
    try {
      identity = (await this.fetchBundle(this.account, deviceId)).identityKey;
    } catch (error) {
      // A missing or damaged public bundle must never make a stale endpoint
      // impossible to revoke. Keep an address-level distrust tombstone even
      // when there is no identity key to attach to the decision.
      if (identity) console.warn('Retiring OMEMO device using its cached identity', error);
    }
    const remaining = current.filter((id) => id !== deviceId);
    await this.publishDeviceList(remaining);
    await this.xmpp.retractPep(NS.OMEMO2_BUNDLES, String(deviceId)).catch((error) => {
      if (error?.message !== 'item-not-found') throw error;
    });
    await this.convergeRetiredDeviceId(deviceId);
    this.deviceCache.set(this.account, remaining);
    this.state.trustDecisions[address] = {
      ...(identity ? { identity } : {}),
      state: 'distrusted',
      accepted: false,
      updatedAt: new Date().toISOString(),
    };
    await this.store.removeAllSessions(`${this.account}.`);
  }
}

export function isOmemoMessage(message) {
  return Boolean(child(message, 'encrypted', NS.OMEMO2));
}

export function fingerprint(buffer) {
  const hex = [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{1,8}/g)?.join(' ') || hex;
}

export const cryptoUtilities = {
  bytesToBase64,
  base64ToBuffer,
  addCurvePrefix,
  parseDeviceList,
  parseBundleElement,
  parseEncryptedElement,
  parseEncryptedFileSharing,
  parseAesGcmBody,
  parseTrustMessage,
  parseOptOut,
  requireOmemoKeyExchangePreKey,
  encryptEnvelope,
  decryptEnvelope,
  validatePersistedOmemoState,
  replaceLegacyPlaintextState,
  unsealState,
  util,
};
