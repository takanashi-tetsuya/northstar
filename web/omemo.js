import {
  KeyHelper,
  OMEMOAddress,
  SessionBuilder,
  SessionCipher,
  curvePubKeyToEd25519PubKey,
  util,
} from './crypto/libomemo.js';
import { getValue, setValue } from './storage.js';
import { NS, bareJid, child, descendant, xmlEscape } from './xmpp.js';

const STORE_VERSION = 1;
const PREKEY_COUNT = 100;
const PROFILE = NS.OMEMO2;
const SCE = 'urn:xmpp:sce:1';
const EME = 'urn:xmpp:eme:0';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

function pairToJson(pair) {
  return { pubKey: bytesToBase64(pair.pubKey), privKey: bytesToBase64(pair.privKey) };
}

function pairFromJson(pair) {
  return pair ? { pubKey: base64ToBuffer(pair.pubKey), privKey: base64ToBuffer(pair.privKey) } : undefined;
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

function randomIndex(length) {
  if (!length) throw new Error('对方设备没有可用的 OMEMO 预密钥');
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return values[0] % length;
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

function randomPadding() {
  const length = 1 + crypto.getRandomValues(new Uint8Array(1))[0] % 100;
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(length)));
}

async function encryptEnvelope(body, from) {
  const contentKey = crypto.getRandomValues(new Uint8Array(32)).buffer;
  const keys = await derivePayloadKeys(contentKey);
  const envelope = `<envelope xmlns='${SCE}'><content><body xmlns='${NS.CLIENT}'>${xmlEscape(body)}</body></content><rpad>${randomPadding()}</rpad><from jid='${xmlEscape(from)}'/></envelope>`;
  const aesKey = await crypto.subtle.importKey('raw', keys.encryption, 'AES-CBC', false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: keys.iv }, aesKey, encoder.encode(envelope));
  const hmacKey = await crypto.subtle.importKey('raw', keys.authentication, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const hmac = (await crypto.subtle.sign('HMAC', hmacKey, ciphertext)).slice(0, 16);
  const keyAndTag = new Uint8Array(48);
  keyAndTag.set(new Uint8Array(contentKey), 0);
  keyAndTag.set(new Uint8Array(hmac), 32);
  return { keyAndTag: keyAndTag.buffer, payload: bytesToBase64(ciphertext) };
}

async function decryptEnvelope(keyAndTag, payload, expectedFrom) {
  if (keyAndTag.byteLength !== 48) throw new Error('OMEMO 内容密钥长度无效');
  const contentKey = keyAndTag.slice(0, 32);
  const expectedHmac = keyAndTag.slice(32);
  const keys = await derivePayloadKeys(contentKey);
  const ciphertext = base64ToBuffer(payload);
  const hmacKey = await crypto.subtle.importKey('raw', keys.authentication, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const actualHmac = (await crypto.subtle.sign('HMAC', hmacKey, ciphertext)).slice(0, 16);
  if (!constantTimeEqual(actualHmac, expectedHmac)) throw new Error('OMEMO 完整性校验失败');
  const aesKey = await crypto.subtle.importKey('raw', keys.encryption, 'AES-CBC', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: keys.iv }, aesKey, ciphertext);
  const document = new DOMParser().parseFromString(decoder.decode(plaintext), 'application/xml');
  if (document.querySelector('parsererror')) throw new Error('OMEMO 明文结构无效');
  const envelope = document.documentElement;
  if (envelope.localName !== 'envelope' || envelope.namespaceURI !== SCE) throw new Error('缺少 OMEMO SCE 信封');
  const fromElement = child(envelope, 'from', SCE);
  if (fromElement && bareJid(fromElement.getAttribute('jid')) !== bareJid(expectedFrom)) throw new Error('OMEMO 发件人校验失败');
  const content = child(envelope, 'content', SCE);
  const body = child(content, 'body', NS.CLIENT);
  if (!body) throw new Error('加密消息没有正文');
  return body.textContent || '';
}

class PersistentOmemoStore {
  constructor(account, state) {
    this.account = account;
    this.state = state;
    this.writeChain = Promise.resolve();
  }

  persist() {
    this.writeChain = this.writeChain.then(() => setValue('crypto', this.account, this.state));
    return this.writeChain;
  }

  getIdentityKeyPair() { return Promise.resolve(pairFromJson(this.state.identityKeyPair)); }
  getLocalRegistrationId() { return Promise.resolve(Number(this.state.deviceId)); }

  isTrustedIdentity(address, identityKey) {
    const saved = this.state.identities[address];
    return Promise.resolve(!saved || saved === bytesToBase64(identityKey));
  }

  saveIdentity(address, identityKey) {
    const encoded = bytesToBase64(identityKey);
    const changed = Boolean(this.state.identities[address] && this.state.identities[address] !== encoded);
    if (!changed) {
      this.state.identities[address] = encoded;
      this.persist();
    }
    return Promise.resolve(changed);
  }

  loadPreKey(keyId) {
    const pair = this.state.prekeys[String(keyId)];
    return Promise.resolve(pair ? { keyPair: pairFromJson(pair) } : undefined);
  }

  storePreKey(keyId, keyPair) {
    this.state.prekeys[String(keyId)] = pairToJson(keyPair);
    return this.persist();
  }

  removePreKey(keyId) {
    delete this.state.prekeys[String(keyId)];
    return this.persist();
  }

  loadSignedPreKey(keyId) {
    const signed = this.state.signedPreKey;
    return Promise.resolve(signed && Number(signed.id) === Number(keyId) ? { keyPair: pairFromJson(signed.keyPair) } : undefined);
  }

  storeSignedPreKey(keyId, keyPair) {
    this.state.signedPreKey = { id: Number(keyId), keyPair: pairToJson(keyPair), signature: '' };
    return this.persist();
  }

  removeSignedPreKey(keyId) {
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
  constructor(xmpp, account) {
    this.xmpp = xmpp;
    this.account = bareJid(account);
    this.state = null;
    this.store = null;
    this.deviceCache = new Map();
    this.ready = false;
    this.fresh = false;
  }

  async initialize() {
    this.state = await getValue('crypto', this.account);
    if (!this.state || this.state.version !== STORE_VERSION) {
      this.fresh = true;
      this.state = {
        version: STORE_VERSION,
        deviceId: Number(KeyHelper.generateRegistrationId()),
        identityKeyPair: null,
        signedPreKey: null,
        prekeys: {},
        identities: {},
        sessions: {},
      };
      this.store = new PersistentOmemoStore(this.account, this.state);
      await this.provision();
    } else {
      this.store = new PersistentOmemoStore(this.account, this.state);
      await this.ensurePrekeys();
    }

    const existing = await this.fetchDeviceIds(this.account, false);
    if (this.fresh) {
      let attempts = 0;
      while (existing.includes(Number(this.state.deviceId)) && attempts < 10) {
        this.state.deviceId = Number(KeyHelper.generateRegistrationId());
        attempts += 1;
      }
      if (existing.includes(Number(this.state.deviceId))) throw new Error('无法生成唯一的 OMEMO 设备 ID');
    }
    await this.publishBundle();
    await this.publishDeviceList([...new Set([...existing, Number(this.state.deviceId)])]);
    this.deviceCache.set(this.account, [...new Set([...existing, Number(this.state.deviceId)])]);
    this.ready = true;
    return this.getOwnDevice();
  }

  async provision() {
    const identity = await KeyHelper.generateIdentityKeyPair();
    const signed = await KeyHelper.generateSignedPreKey(identity, 1, PROFILE);
    this.state.identityKeyPair = pairToJson(identity);
    this.state.signedPreKey = { id: signed.keyId, keyPair: pairToJson(signed.keyPair), signature: bytesToBase64(signed.signature) };
    const prekeys = await Promise.all(Array.from({ length: PREKEY_COUNT }, (_, id) => KeyHelper.generatePreKey(id + 1)));
    for (const prekey of prekeys) this.state.prekeys[String(prekey.keyId)] = pairToJson(prekey.keyPair);
    await this.store.persist();
  }

  async ensurePrekeys() {
    const existing = new Set(Object.keys(this.state.prekeys));
    const missing = Array.from({ length: PREKEY_COUNT }, (_, index) => String(index + 1)).filter((id) => !existing.has(id));
    if (!missing.length) return;
    const generated = await Promise.all(missing.map((id) => KeyHelper.generatePreKey(Number(id))));
    for (const prekey of generated) this.state.prekeys[String(prekey.keyId)] = pairToJson(prekey.keyPair);
    await this.store.persist();
  }

  async publishBundle() {
    const identity = pairFromJson(this.state.identityKeyPair);
    const signed = this.state.signedPreKey;
    const edIdentity = await curvePubKeyToEd25519PubKey(identity.pubKey);
    const prekeys = Object.entries(this.state.prekeys).map(([id, pair]) => `<pk id='${id}'>${bytesToBase64(stripCurvePrefix(pairFromJson(pair).pubKey))}</pk>`).join('');
    const payload = `<bundle xmlns='${NS.OMEMO2}'><spk id='${signed.id}'>${bytesToBase64(stripCurvePrefix(pairFromJson(signed.keyPair).pubKey))}</spk><spks>${signed.signature}</spks><ik>${bytesToBase64(edIdentity)}</ik><prekeys>${prekeys}</prekeys></bundle>`;
    await this.xmpp.publishPep(NS.OMEMO2_BUNDLES, String(this.state.deviceId), payload);
  }

  publishDeviceList(ids) {
    const devices = ids.map((id) => `<device id='${Number(id)}'/>`).join('');
    return this.xmpp.publishPep(NS.OMEMO2_DEVICES, 'current', `<devices xmlns='${NS.OMEMO2}'>${devices}</devices>`);
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
    const devices = descendant(iq, 'devices', NS.OMEMO2);
    const ids = [...(devices?.children || [])]
      .filter((node) => node.localName === 'device')
      .map((node) => Number(node.getAttribute('id')))
      .filter((id) => Number.isInteger(id) && id > 0);
    this.deviceCache.set(jid, [...new Set(ids)]);
    return this.deviceCache.get(jid);
  }

  handlePepEvent(from, event) {
    const items = child(event, 'items', `${NS.PUBSUB}#event`);
    if (!items || items.getAttribute('node') !== NS.OMEMO2_DEVICES) return;
    const devices = descendant(items, 'devices', NS.OMEMO2);
    const ids = [...(devices?.children || [])].filter((node) => node.localName === 'device').map((node) => Number(node.getAttribute('id'))).filter(Boolean);
    this.deviceCache.set(bareJid(from), [...new Set(ids)]);
  }

  async fetchBundle(jid, deviceId) {
    const iq = await this.xmpp.getPep(jid, NS.OMEMO2_BUNDLES, String(deviceId));
    const item = [...iq.getElementsByTagName('item')].find((node) => node.getAttribute('id') === String(deviceId));
    const bundle = item && descendant(item, 'bundle', NS.OMEMO2);
    const signed = bundle && child(bundle, 'spk', NS.OMEMO2);
    const identity = bundle && child(bundle, 'ik', NS.OMEMO2);
    const signature = bundle && child(bundle, 'spks', NS.OMEMO2);
    const prekeysElement = bundle && child(bundle, 'prekeys', NS.OMEMO2);
    const prekeys = [...(prekeysElement?.children || [])].filter((node) => node.localName === 'pk').map((node) => ({ id: Number(node.getAttribute('id')), key: node.textContent.trim() }));
    if (!signed || !identity || !signature || !prekeys.length) throw new Error(`设备 ${deviceId} 的 OMEMO 公钥包不完整`);
    return {
      jid: bareJid(jid),
      id: Number(deviceId),
      identityKey: identity.textContent.trim(),
      signedPreKey: { id: Number(signed.getAttribute('id')), key: signed.textContent.trim(), signature: signature.textContent.trim() },
      prekeys,
    };
  }

  async ensureSession(bundle) {
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

  async devicesForChat(peer, { refresh = false } = {}) {
    peer = bareJid(peer);
    if (refresh) this.deviceCache.delete(peer);
    const recipientIds = await this.fetchDeviceIds(peer, !refresh);
    if (!recipientIds.length) throw new Error('对方尚未发布 OMEMO 设备，不能安全发送消息');
    const ownIds = (await this.fetchDeviceIds(this.account)).filter((id) => id !== Number(this.state.deviceId));
    const descriptors = [
      ...recipientIds.map((id) => ({ jid: peer, id })),
      ...ownIds.map((id) => ({ jid: this.account, id })),
    ];
    const bundles = [];
    const failures = [];
    for (const descriptor of descriptors) {
      try {
        const bundle = await this.fetchBundle(descriptor.jid, descriptor.id);
        await this.ensureSession(bundle);
        bundles.push(bundle);
      } catch (error) {
        failures.push({ ...descriptor, error: error.message });
      }
    }
    if (!bundles.some((bundle) => bundle.jid === peer)) throw new Error(failures[0]?.error || '无法建立对方的 OMEMO 会话');
    return { bundles, failures };
  }

  async encrypt(peer, plaintext) {
    if (!this.ready) throw new Error('OMEMO 尚未初始化');
    const { bundles, failures } = await this.devicesForChat(peer);
    return this.encryptWithBundles(bundles, failures, plaintext);
  }

  async encryptGroup(peers, plaintext) {
    if (!this.ready) throw new Error('OMEMO 尚未初始化');
    const recipients = [...new Set(peers.map(bareJid).filter((jid) => jid && jid !== this.account))];
    if (!recipients.length) throw new Error('群聊中还没有其他可加密的成员');
    const bundlesByAddress = new Map();
    const failures = [];
    for (const peer of recipients) {
      try {
        const result = await this.devicesForChat(peer);
        for (const bundle of result.bundles) bundlesByAddress.set(`${bundle.jid}\0${bundle.id}`, bundle);
        failures.push(...result.failures);
      } catch (error) {
        throw new Error(`${peer}：${error.message}`);
      }
    }
    return this.encryptWithBundles([...bundlesByAddress.values()], failures, plaintext);
  }

  async encryptWithBundles(bundles, failures, plaintext) {
    const { keyAndTag, payload } = await encryptEnvelope(plaintext, this.account);
    const grouped = new Map();
    for (const bundle of bundles) {
      const cipher = new SessionCipher(this.store, new OMEMOAddress(bundle.jid, bundle.id), PROFILE);
      const result = await cipher.encrypt(keyAndTag);
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

  async decrypt(message, sender) {
    const encrypted = child(message, 'encrypted', NS.OMEMO2);
    if (!encrypted) return null;
    const header = child(encrypted, 'header', NS.OMEMO2);
    const payload = child(encrypted, 'payload', NS.OMEMO2)?.textContent.trim();
    const senderDevice = Number(header?.getAttribute('sid'));
    const ownKeys = [...(header?.children || [])].find((node) => node.localName === 'keys' && bareJid(node.getAttribute('jid')) === this.account);
    const key = [...(ownKeys?.children || [])].find((node) => node.localName === 'key' && Number(node.getAttribute('rid')) === Number(this.state.deviceId));
    if (!key) throw new Error('这条消息没有加密给当前设备');
    if (!payload) return '';
    const keyBytes = base64ToBuffer(key.textContent.trim());
    const isKeyExchange = new Uint8Array(keyBytes)[0] === 0x08 || key.getAttribute('kex') === 'true';
    const cipher = new SessionCipher(this.store, new OMEMOAddress(bareJid(sender), senderDevice), PROFILE);
    let result;
    if (isKeyExchange) {
      result = await cipher.decryptPreKeyWhisperMessage(keyBytes, 'binary');
      await this.ensurePrekeys();
      await this.publishBundle();
    } else {
      result = await cipher.decryptWhisperMessage(keyBytes, 'binary');
    }
    return decryptEnvelope(result.plaintext, payload, sender);
  }

  async inspectDevices(peer, refresh = false) {
    const ids = await this.fetchDeviceIds(peer, !refresh);
    const devices = [];
    for (const id of ids) {
      try {
        const bundle = await this.fetchBundle(peer, id);
        const address = new OMEMOAddress(bareJid(peer), id).toString();
        const encodedIdentity = bytesToBase64(base64ToBuffer(bundle.identityKey));
        const savedIdentity = this.state.identities[address];
        devices.push({
          id,
          fingerprint: fingerprint(base64ToBuffer(bundle.identityKey)),
          trusted: !savedIdentity || savedIdentity === encodedIdentity,
          trustState: savedIdentity
            ? (savedIdentity === encodedIdentity ? 'trusted' : 'changed')
            : 'tofu',
        });
      } catch (error) {
        devices.push({ id, fingerprint: null, trusted: false, error: error.message });
      }
    }
    return devices;
  }

  async getOwnDevice() {
    const identity = pairFromJson(this.state.identityKeyPair);
    const edIdentity = await curvePubKeyToEd25519PubKey(identity.pubKey);
    return { id: Number(this.state.deviceId), fingerprint: fingerprint(edIdentity) };
  }
}

export function isOmemoMessage(message) {
  return Boolean(child(message, 'encrypted', NS.OMEMO2));
}

export function fingerprint(buffer) {
  const hex = [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  return hex.match(/.{1,8}/g)?.join(' ') || hex;
}

export const cryptoUtilities = { bytesToBase64, base64ToBuffer, addCurvePrefix, util };
