export const NS = Object.freeze({
  CLIENT: 'jabber:client',
  FRAMING: 'urn:ietf:params:xml:ns:xmpp-framing',
  SASL2: 'urn:xmpp:sasl:2',
  BIND2: 'urn:xmpp:bind:0',
  FAST: 'urn:xmpp:fast:0',
  ROSTER: 'jabber:iq:roster',
  REGISTER: 'jabber:iq:register',
  DISCO_INFO: 'http://jabber.org/protocol/disco#info',
  PUBSUB: 'http://jabber.org/protocol/pubsub',
  PUBSUB_EVENT: 'http://jabber.org/protocol/pubsub#event',
  MAM: 'urn:xmpp:mam:2',
  CARBONS: 'urn:xmpp:carbons:2',
  BLOCKING: 'urn:xmpp:blocking',
  FORWARD: 'urn:xmpp:forward:0',
  DELAY: 'urn:xmpp:delay',
  RSM: 'http://jabber.org/protocol/rsm',
  CHAT_STATES: 'http://jabber.org/protocol/chatstates',
  RECEIPTS: 'urn:xmpp:receipts',
  HINTS: 'urn:xmpp:hints',
  MUC: 'http://jabber.org/protocol/muc',
  MUC_USER: 'http://jabber.org/protocol/muc#user',
  MUC_ADMIN: 'http://jabber.org/protocol/muc#admin',
  MUC_OWNER: 'http://jabber.org/protocol/muc#owner',
  X_DATA: 'jabber:x:data',
  MUC_SENDER: 'urn:northstar:muc:sender:0',
  HTTP_UPLOAD: 'urn:xmpp:http:upload:0',
  AVATAR_DATA: 'urn:xmpp:avatar:data',
  AVATAR_METADATA: 'urn:xmpp:avatar:metadata',
  OMEMO2: 'urn:xmpp:omemo:2',
  OMEMO2_DEVICES: 'urn:xmpp:omemo:2:devices',
  OMEMO2_BUNDLES: 'urn:xmpp:omemo:2:bundles',
  STANZA_ID: 'urn:xmpp:sid:0',
  SM: 'urn:xmpp:sm:3',
});

const parser = new DOMParser();
const MAX_SM_UNACKED_STANZAS = 1000;
const MAX_SM_UNACKED_BYTES = 8 * 1024 * 1024;
const MAX_SCRAM_SERVER_FIRST_BYTES = 8 * 1024;
const MAX_SCRAM_SERVER_FIRST_ATTRIBUTES = 32;
const MAX_SCRAM_ATTRIBUTE_VALUE_CHARACTERS = 4096;

export function xmlEscape(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

export function parseXml(text) {
  const document = parser.parseFromString(text, 'application/xml');
  if (document.querySelector('parsererror')) throw new Error('服务器返回了无法解析的 XML');
  return document.documentElement;
}

export function bareJid(jid = '') {
  return String(jid).split('/')[0].toLowerCase();
}

export function localpart(jid = '') {
  return bareJid(jid).split('@')[0] || '';
}

export function child(element, name, namespace) {
  return [...(element?.children || [])].find((node) => node.localName === name && (!namespace || node.namespaceURI === namespace)) || null;
}

function protocolAttributes(element) {
  return [...(element?.attributes || [])]
    .filter((attribute) => attribute.namespaceURI !== 'http://www.w3.org/2000/xmlns/');
}

export function descendant(element, name, namespace) {
  return [...(element?.getElementsByTagNameNS(namespace || '*', name) || [])][0] || null;
}

export function randomId(prefix = 'n') {
  return `${prefix}-${crypto.randomUUID()}`;
}

function utf8Base64(value) {
  return bytesBase64(new TextEncoder().encode(value));
}

function bytesBase64(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64Bytes(value) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('服务器返回了无效的 Base64 认证数据');
  }
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function parseScramServerFirst(encoded, clientNonce) {
  if (typeof encoded !== 'string'
    || encoded.length > Math.ceil(MAX_SCRAM_SERVER_FIRST_BYTES / 3) * 4 + 4) {
    throw new Error('SCRAM challenge exceeds the safety limit');
  }
  let decoded = null;
  try {
    decoded = base64Bytes(encoded);
    if (decoded.byteLength > MAX_SCRAM_SERVER_FIRST_BYTES) {
      throw new Error('SCRAM challenge exceeds the safety limit');
    }
    const raw = new TextDecoder('utf-8', { fatal: true }).decode(decoded);
    if (!raw || /[\u0000-\u001f\u007f-\u009f]/u.test(raw)) {
      throw new Error('SCRAM challenge contains control characters');
    }
    const parts = raw.split(',');
    if (parts.length < 3 || parts.length > MAX_SCRAM_SERVER_FIRST_ATTRIBUTES) {
      throw new Error('SCRAM challenge contains an invalid attribute count');
    }
    const attributes = new Map();
    for (const part of parts) {
      if (part.length < 3 || part.length > MAX_SCRAM_ATTRIBUTE_VALUE_CHARACTERS + 2
        || part[1] !== '=' || !/^[A-Za-z]$/.test(part[0])) {
        throw new Error('SCRAM challenge contains a malformed attribute');
      }
      const name = part[0];
      const value = part.slice(2);
      if (!value || attributes.has(name)) {
        throw new Error('SCRAM challenge contains an empty or duplicate attribute');
      }
      if (name === 'm') {
        throw new Error('SCRAM challenge requires an unsupported mandatory extension');
      }
      attributes.set(name, value);
    }
    const r = attributes.get('r');
    const s = attributes.get('s');
    const i = attributes.get('i');
    if (!r || !s || !i) throw new Error('SCRAM challenge is missing a required attribute');
    if (!r.startsWith(clientNonce) || r === clientNonce) {
      throw new Error('SCRAM challenge nonce 不匹配');
    }
    if (!/^(?:[1-9][0-9]*)$/.test(i)) {
      throw new Error('SCRAM challenge 迭代次数格式错误');
    }
    return { raw, r, s, i };
  } finally {
    decoded?.fill?.(0);
  }
}

function constantTimeEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function saslName(value) {
  return String(value).replaceAll('=', '=3D').replaceAll(',', '=2C');
}

async function hmacSha256(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, dataBytes));
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', value));
}

async function scramSaltedPassword(key, salt, iterations) {
  if (!(key instanceof CryptoKey)
    || key.type !== 'secret'
    || key.algorithm?.name !== 'PBKDF2'
    || key.extractable !== false
    || !key.usages.includes('deriveBits')) {
    throw new Error('SCRAM requires a non-extractable PBKDF2 key');
  }
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    256,
  ));
}

function secureTransferUrl(value) {
  if (typeof value !== 'string' || !value || value.length > 8192) {
    throw new Error('File transfer service returned an invalid URL');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('File transfer service returned an invalid URL');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))) {
    throw new Error('File transfer URLs must use HTTPS');
  }
  let pageOrigin;
  try {
    pageOrigin = new URL(globalThis.location?.origin).origin;
  } catch {
    throw new Error('File transfer URLs require a trusted page origin');
  }
  if (url.origin !== pageOrigin) {
    throw new Error('Cross-origin file transfer URLs are not permitted');
  }
  url.hash = '';
  return url.href;
}

function validateWebsocketUrl(value) {
  if (typeof value !== 'string' || !value || value.length > 8192) {
    throw new Error('无效的 WebSocket URL');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('无效的 WebSocket URL');
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password) {
    throw new Error('WebSocket URL 不得包含认证凭据');
  }
  if (url.protocol !== 'wss:' && !(url.protocol === 'ws:' && loopback)) {
    throw new Error('生产环境下 XMPP WebSocket 连接必须使用安全的 WSS (TLS)');
  }
  return url.href;
}

function xmppError(iq) {
  const error = child(iq, 'error');
  const condition = [...(error?.children || [])].find((node) => node.namespaceURI === 'urn:ietf:params:xml:ns:xmpp-stanzas');
  const result = new Error(condition?.localName || 'XMPP 请求失败');
  result.condition = condition?.localName || '';
  return result;
}

export class XmppClient extends EventTarget {
  constructor({ domain, websocketUrl }) {
    super();
    this.domain = domain;
    this.websocketUrl = validateWebsocketUrl(websocketUrl);
    this.socket = null;
    this.username = null;
    this.scramKey = null;
    this.userAgentId = crypto.randomUUID();
    this.fastCredential = null;
    this.sasl2Context = null;
    this.authenticationTimer = null;
    this.jid = null;
    this.resource = null;
    this.phase = 'idle';
    this.pending = new Map();
    this.mamQueries = new Map();
    this.smEnabled = false;
    this.smOutbound = 0;
    this.smInbound = 0;
    this.smServerAck = 0;
    this.smUnacked = [];
    this.smUnackedBytes = 0;
    this.smResumeId = null;
    this.lastConnectResumed = false;
    this.connectPromise = null;
    this.intentionalClose = false;
  }

  emit(type, detail = {}) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  async connect(username, scramKey = null) {
    if (this.connectPromise) return this.connectPromise;
    this.username = username.toLowerCase();
    this.scramKey = null;

    if (scramKey !== null) {
      if (!(scramKey instanceof CryptoKey)
        || scramKey.type !== 'secret'
        || scramKey.algorithm?.name !== 'PBKDF2'
        || scramKey.extractable !== false
        || !scramKey.usages.includes('deriveBits')) {
        return Promise.reject(new Error('SCRAM CryptoKey 必须为 non-extractable PBKDF2 密钥'));
      }
      this.scramKey = scramKey;
    }

    if (this.fastCredential && (!Number.isFinite(this.fastCredential.expiry) || this.fastCredential.expiry <= Date.now())) {
      this.fastCredential = null;
    }
    if (!this.scramKey && !this.fastCredential) {
      return Promise.reject(new Error('安全会话已过期，请重新输入密码'));
    }
    this.lastConnectResumed = false;
    this.intentionalClose = false;
    this.phase = 'opening';
    let socket;
    try {
      socket = new WebSocket(this.websocketUrl, 'xmpp');
    } catch (error) {
      this.phase = 'closed';
      this.clearAuthenticationSecret();
      return Promise.reject(error);
    }
    this.socket = socket;
    this.connectPromise = new Promise((resolve, reject) => {
      this.resolveConnect = resolve;
      this.rejectConnect = reject;
      socket.addEventListener('open', () => this.openStream());
      socket.addEventListener('message', (event) => this.receive(String(event.data)));
      socket.addEventListener('error', () => this.failConnect(new Error('无法连接 XMPP WebSocket')));
      socket.addEventListener('close', () => this.closed());
    });
    return this.connectPromise;
  }

  openStream() {
    const from = this.username ? ` from='${xmlEscape(`${this.username}@${this.domain}`)}'` : '';
    this.sendRaw(`<open xmlns='${NS.FRAMING}' to='${xmlEscape(this.domain)}'${from} version='1.0'/>`);
  }

  sendRaw(xml) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) throw new Error('XMPP 尚未连接');
    const smCounted = this.smEnabled && /^<(?:iq|message|presence)\b/.test(xml);
    const xmlBytes = smCounted ? new TextEncoder().encode(xml).byteLength : 0;
    if (smCounted && (this.smUnacked.length >= MAX_SM_UNACKED_STANZAS
      || this.smUnackedBytes + xmlBytes > MAX_SM_UNACKED_BYTES)) {
      this.socket.send(`<r xmlns='${NS.SM}'/>`);
      throw new Error('XMPP 未确认发送队列已达安全上限');
    }
    this.socket.send(xml);
    if (smCounted) {
      this.smOutbound = (this.smOutbound + 1) >>> 0;
      const match = xml.match(/^<(iq|message|presence)\b[^>]*\sid=['"]([^'"]+)['"]/);
      this.smUnacked.push({
        h: this.smOutbound,
        kind: match?.[1] || '',
        id: match?.[2] || '',
        xml,
        bytes: xmlBytes,
      });
      this.smUnackedBytes += xmlBytes;
      if (match?.[1] === 'message') this.socket.send(`<r xmlns='${NS.SM}'/>`);
    }
  }

  async sendIq(payload, { type = 'get', to = null, timeout = 12000, id = randomId('iq') } = {}) {
    const toAttribute = to ? ` to='${xmlEscape(to)}'` : '';
    const xml = `<iq xmlns='${NS.CLIENT}' type='${type}' id='${xmlEscape(id)}'${toAttribute}>${payload}</iq>`;
    const promise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('XMPP 请求超时'));
      }, timeout);
      this.pending.set(id, { resolve, reject, timer });
    });
    try {
      this.sendRaw(xml);
    } catch (error) {
      const pending = this.pending.get(id);
      if (pending) clearTimeout(pending.timer);
      this.pending.delete(id);
      throw error;
    }
    return promise;
  }

  async receive(text) {
    let root;
    try {
      root = parseXml(text);
    } catch (error) {
      this.emit('protocol-error', { error, raw: text });
      return;
    }

    if (root.localName === 'open') return;
    if (root.localName === 'features') return this.handleFeatures(root);
    if (root.localName === 'challenge' && root.namespaceURI === NS.SASL2) {
      return this.handleSasl2Challenge(root);
    }
    if (root.localName === 'success' && root.namespaceURI === NS.SASL2) {
      return this.handleSasl2Success(root);
    }
    if (root.localName === 'failure' && root.namespaceURI === NS.SASL2) {
      this.clearAuthenticationSecret();
      this.fastCredential = null;
      this.smResumeId = null;
      this.failConnect(new Error('用户名或密码错误，或者快速认证凭据已失效'));
      return;
    }
    if (root.localName === 'close') {
      this.socket?.close();
      return;
    }
    if (root.namespaceURI === NS.SM && root.localName === 'r') {
      if (this.smEnabled) this.socket?.send(`<a xmlns='${NS.SM}' h='${this.smInbound}'/>`);
      return;
    }
    if (root.namespaceURI === NS.SM && root.localName === 'a') {
      this.handleStreamAck(root.getAttribute('h'));
      return;
    }
    if (this.smEnabled && ['iq', 'message', 'presence'].includes(root.localName)) {
      this.smInbound = (this.smInbound + 1) >>> 0;
    }
    if (root.localName === 'iq') return this.handleIq(root);
    if (root.localName === 'message') return this.handleMessage(root, text);
    if (root.localName === 'presence') return this.handlePresence(root);
  }

  async handleFeatures(features) {
    if (this.phase === 'opening') {
      const authentication = child(features, 'authentication', NS.SASL2);
      if (!authentication) {
        this.clearAuthenticationSecret();
        this.failConnect(new Error('服务器不支持网页端要求的 SASL2 安全认证'));
        return;
      }
      const mechanisms = [...authentication.children]
        .filter((node) => node.localName === 'mechanism' && node.namespaceURI === NS.SASL2)
        .map((node) => node.textContent.trim());
      const fastMechanisms = [...(descendant(authentication, 'fast', NS.FAST)?.children || [])]
        .filter((node) => node.localName === 'mechanism' && node.namespaceURI === NS.FAST)
        .map((node) => node.textContent.trim());
      if (this.fastCredential) {
        if (!Number.isFinite(this.fastCredential.expiry) || this.fastCredential.expiry <= Date.now()) {
          this.fastCredential = null;
          if (!this.scramKey) {
            this.clearAuthenticationSecret();
            this.failConnect(new Error('快速认证凭据已过期，请重新输入密码'));
            return;
          }
        } else if (fastMechanisms.includes(this.fastCredential.mechanism)) {
          await this.beginFastAuthentication();
          return;
        }
      }
      if (!this.scramKey) {
        this.fastCredential = null;
        this.clearAuthenticationSecret();
        this.failConnect(new Error('快速认证不可用，请重新输入密码'));
        return;
      }
      if (!mechanisms.includes('SCRAM-SHA-256') || !fastMechanisms.includes('HT-SHA-256-NONE')) {
        this.clearAuthenticationSecret();
        this.failConnect(new Error('服务器未提供 SCRAM-SHA-256 和 FAST'));
        return;
      }
      this.beginScramAuthentication();
      return;
    }
    if (this.phase === 'sasl2-complete') {
      this.finishSasl2Session();
    }
  }

  authenticationExtensions({ requestToken = false } = {}) {
    const resume = this.smResumeId && this.jid
      ? `<resume xmlns='${NS.SM}' previd='${xmlEscape(this.smResumeId)}' h='${this.smInbound}'/>`
      : '';
    const bind = `<bind xmlns='${NS.BIND2}'><tag>Northstar-Web</tag><enable xmlns='${NS.CARBONS}'/><enable xmlns='${NS.SM}' resume='true'/><active xmlns='urn:xmpp:csi:0'/></bind>`;
    const token = requestToken
      ? `<request-token xmlns='${NS.FAST}' mechanism='HT-SHA-256-NONE'/>`
      : '';
    return `<user-agent xmlns='${NS.SASL2}' id='${xmlEscape(this.userAgentId)}'><software>Northstar Web</software></user-agent>${resume}${bind}${token}`;
  }

  startAuthenticationTimer() {
    clearTimeout(this.authenticationTimer);
    this.authenticationTimer = setTimeout(() => {
      this.clearAuthenticationSecret();
      this.failConnect(new Error('XMPP 认证超时'));
    }, 15000);
  }

  clearAuthenticationSecret() {
    this.scramKey = null;
    if (this.sasl2Context) {
      try {
        this.sasl2Context.expectedServerSignature?.fill?.(0);
      } catch {}
      this.sasl2Context.expectedServerSignature = null;
      this.sasl2Context = null;
    }
    clearTimeout(this.authenticationTimer);
    this.authenticationTimer = null;
  }

  beginScramAuthentication() {
    const nonce = bytesBase64(crypto.getRandomValues(new Uint8Array(24))).replaceAll('=', '');
    const clientFirstBare = `n=${saslName(this.username)},r=${nonce}`;
    const gs2Header = 'n,,';
    this.sasl2Context = {
      kind: 'scram',
      clientFirstBare,
      gs2Header,
      nonce,
      expectedServerSignature: null,
    };
    this.phase = 'authenticating-sasl2';
    this.startAuthenticationTimer();
    const initial = utf8Base64(`${gs2Header}${clientFirstBare}`);
    this.sendRaw(`<authenticate xmlns='${NS.SASL2}' mechanism='SCRAM-SHA-256'><initial-response>${initial}</initial-response>${this.authenticationExtensions({ requestToken: true })}</authenticate>`);
  }

  async beginFastAuthentication() {
    let tokenBytes = null;
    let initiator = null;
    let username = null;
    let response = null;
    let expected = null;
    try {
      tokenBytes = new TextEncoder().encode(this.fastCredential.token);
      initiator = await hmacSha256(tokenBytes, new TextEncoder().encode('Initiator'));
      username = new TextEncoder().encode(this.username);
      response = new Uint8Array(username.length + 1 + initiator.length);
      response.set(username);
      response.set(initiator, username.length + 1);
      expected = await hmacSha256(tokenBytes, new TextEncoder().encode('Responder'));
      this.sasl2Context = {
        kind: 'fast',
        expectedServerSignature: expected,
      };
      this.phase = 'authenticating-sasl2';
      this.startAuthenticationTimer();
      this.sendRaw(`<authenticate xmlns='${NS.SASL2}' mechanism='${this.fastCredential.mechanism}'><initial-response>${bytesBase64(response)}</initial-response>${this.authenticationExtensions()}<fast xmlns='${NS.FAST}'/></authenticate>`);
    } catch (error) {
      this.fastCredential = null;
      this.clearAuthenticationSecret();
      this.failConnect(error);
    } finally {
      tokenBytes?.fill?.(0);
      initiator?.fill?.(0);
      username?.fill?.(0);
      response?.fill?.(0);
    }
  }

  async handleSasl2Challenge(root) {
    const context = this.sasl2Context;
    if (this.phase !== 'authenticating-sasl2' || context?.kind !== 'scram'
      || protocolAttributes(root).length || [...root.children].length) {
      this.clearAuthenticationSecret();
      this.failConnect(new Error('服务器返回了无效的 SCRAM challenge'));
      return;
    }
    const scramKey = this.scramKey;
    this.scramKey = null;
    if (!scramKey) {
      this.clearAuthenticationSecret();
      this.failConnect(new Error('SCRAM 认证密钥不可用'));
      return;
    }
    let salt = null;
    let saltedPassword = null;
    let clientKey = null;
    let storedKey = null;
    let serverKey = null;
    let authBytes = null;
    let clientSignature = null;
    let proof = null;
    try {
      const serverFirst = parseScramServerFirst(root.textContent, context.nonce);
      const { r, s, i } = serverFirst;
      const iterations = Number(i);
      if (!Number.isSafeInteger(iterations) || iterations < 4096 || iterations > 10000000) {
        throw new Error('SCRAM 迭代次数超出安全范围');
      }
      salt = base64Bytes(s);
      if (salt.length < 16 || salt.length > 1024) throw new Error('SCRAM salt 长度错误');

      saltedPassword = await scramSaltedPassword(scramKey, salt, iterations);
      clientKey = await hmacSha256(saltedPassword, new TextEncoder().encode('Client Key'));
      storedKey = await sha256(clientKey);
      serverKey = await hmacSha256(saltedPassword, new TextEncoder().encode('Server Key'));

      const channelBinding = bytesBase64(new TextEncoder().encode(context.gs2Header));
      const clientFinalBare = `c=${channelBinding},r=${r}`;
      const authMessage = `${context.clientFirstBare},${serverFirst.raw},${clientFinalBare}`;
      authBytes = new TextEncoder().encode(authMessage);

      clientSignature = await hmacSha256(storedKey, authBytes);
      proof = clientKey.map((value, index) => value ^ clientSignature[index]);
      context.expectedServerSignature = await hmacSha256(serverKey, authBytes);

      this.sendRaw(`<response xmlns='${NS.SASL2}'>${utf8Base64(`${clientFinalBare},p=${bytesBase64(proof)}`)}</response>`);
    } catch (error) {
      this.clearAuthenticationSecret();
      this.failConnect(error);
    } finally {
      salt?.fill?.(0);
      saltedPassword?.fill?.(0);
      clientKey?.fill?.(0);
      storedKey?.fill?.(0);
      serverKey?.fill?.(0);
      authBytes?.fill?.(0);
      clientSignature?.fill?.(0);
      proof?.fill?.(0);
    }
  }

  handleSasl2Success(root) {
    const context = this.sasl2Context;
    if (this.phase !== 'authenticating-sasl2' || !context || protocolAttributes(root).length) {
      this.clearAuthenticationSecret();
      this.failConnect(new Error('服务器返回了无效的 SASL2 success'));
      return;
    }
    let serverProof = null;
    try {
      const additional = child(root, 'additional-data', NS.SASL2);
      if (!additional || [...additional.children].length || protocolAttributes(additional).length) {
        throw new Error('服务器没有提供认证签名');
      }
      serverProof = base64Bytes(additional.textContent);
      const expected = context.expectedServerSignature;
      if (context.kind === 'scram') {
        const serverFinal = new TextDecoder('utf-8', { fatal: true }).decode(serverProof);
        if (!serverFinal.startsWith('v=')
          || !constantTimeEqual(base64Bytes(serverFinal.slice(2)), expected)) {
          throw new Error('SCRAM 服务器签名验证失败');
        }
      } else if (!constantTimeEqual(serverProof, expected)) {
        throw new Error('FAST 服务器签名验证失败');
      }
      const authorization = child(root, 'authorization-identifier', NS.SASL2)?.textContent || '';
      if (!authorization || bareJid(authorization) !== `${this.username}@${this.domain}`) {
        throw new Error('服务器返回了不匹配的认证身份');
      }
      this.jid = authorization;
      this.resource = authorization.split('/').slice(1).join('/') || null;
      const issued = child(root, 'token', NS.FAST);
      if (issued) {
        const token = issued.getAttribute('token') || '';
        const expiry = Date.parse(issued.getAttribute('expiry') || '');
        if (!/^[A-Za-z0-9_-]{32,4096}$/.test(token) || !Number.isFinite(expiry) || expiry <= Date.now()) {
          throw new Error('服务器返回了无效的 FAST 凭据');
        }
        this.fastCredential = { mechanism: 'HT-SHA-256-NONE', token, expiry };
      }
      if (!this.fastCredential) throw new Error('服务器没有签发重连所需的 FAST 凭据');

      const resumed = child(root, 'resumed', NS.SM);
      const bound = child(root, 'bound', NS.BIND2);
      if (resumed) {
        this.applyInlineResumed(resumed);
      } else if (bound) {
        const enabled = child(bound, 'enabled', NS.SM);
        if (!enabled) throw new Error('服务器未启用内联流管理');
        this.applyInlineSmEnabled(enabled);
        this.lastConnectResumed = false;
      } else {
        throw new Error('服务器没有完成 Bind2 或流恢复');
      }
      this.clearAuthenticationSecret();
      this.sasl2Context = null;
      this.phase = 'sasl2-complete';
    } catch (error) {
      this.fastCredential = null;
      this.clearAuthenticationSecret();
      this.failConnect(error);
    } finally {
      serverProof?.fill?.(0);
    }
  }

  applyInlineSmEnabled(root) {
    const resumable = ['true', '1'].includes(root.getAttribute('resume'));
    const resumeId = root.getAttribute('id');
    if (protocolAttributes(root).some((attribute) => (
      attribute.namespaceURI || !['id', 'resume', 'max', 'location'].includes(attribute.localName)
    )) || [...root.children].length || root.textContent.trim()
      || !resumable || !/^[A-Za-z0-9_-]{43}$/.test(resumeId || '')) {
      throw new Error('服务器返回了无效的内联流管理响应');
    }
    this.smEnabled = true;
    this.smOutbound = 0;
    this.smInbound = 0;
    this.smServerAck = 0;
    this.smUnacked = [];
    this.smUnackedBytes = 0;
    this.smResumeId = resumeId;
  }

  applyInlineResumed(root) {
    const resumeId = root.getAttribute('previd') || '';
    const h = root.getAttribute('h') || '';
    this.smEnabled = true;
    if (resumeId !== this.smResumeId || !this.handleStreamAck(h)) {
      this.smEnabled = false;
      throw new Error('服务器返回了无效的内联流恢复响应');
    }
    for (const stanza of this.smUnacked) this.socket.send(stanza.xml);
    if (this.smUnacked.length) this.socket.send(`<r xmlns='${NS.SM}'/>`);
    this.lastConnectResumed = true;
  }

  finishSasl2Session() {
    this.phase = 'online';
    // An XEP-0198 resume continues the old stream state, including presence.
    // Sending a second initial presence here can reorder presence relative to
    // stanzas replayed by the server during the SASL2 inline resume.
    if (!this.lastConnectResumed) {
      this.sendRaw(`<presence xmlns='${NS.CLIENT}'><show>chat</show></presence>`);
    }
    this.resolveConnect?.(this.jid);
    this.resolveConnect = null;
    this.rejectConnect = null;
    this.emit('connected', {
      jid: this.jid,
      bareJid: bareJid(this.jid),
      resumed: this.lastConnectResumed,
    });
  }

  handleStreamAck(value) {
    if (!this.smEnabled || !/^(?:0|[1-9][0-9]*)$/.test(value || '')) return false;
    const acknowledged = Number(value);
    if (!Number.isSafeInteger(acknowledged) || acknowledged > 0xffffffff) return false;
    const count = (acknowledged - this.smServerAck + 0x100000000) % 0x100000000;
    if (count > this.smUnacked.length) {
      this.emit('protocol-error', { error: new Error('服务器返回了超出已发送范围的流确认') });
      return false;
    }
    this.smServerAck = acknowledged;
    for (const stanza of this.smUnacked.splice(0, count)) {
      this.smUnackedBytes = Math.max(0, this.smUnackedBytes - Number(stanza.bytes || 0));
      if (stanza.id) this.emit('stanza-acked', { ...stanza });
    }
    return true;
  }

  handleIq(iq) {
    const id = iq.getAttribute('id');
    const pending = id && this.pending.get(id);
    if (pending) {
      clearTimeout(pending.timer);
      this.pending.delete(id);
      if (iq.getAttribute('type') === 'error') pending.reject(xmppError(iq));
      else pending.resolve(iq);
      return;
    }
    const roster = child(iq, 'query', NS.ROSTER);
    if (iq.getAttribute('type') === 'set' && roster) {
      this.sendRaw(`<iq xmlns='${NS.CLIENT}' type='result' id='${xmlEscape(id || '')}'/>`);
      this.emit('roster-push', { items: parseRoster(roster) });
      return;
    }
    const blocked = child(iq, 'block', NS.BLOCKING);
    const unblocked = child(iq, 'unblock', NS.BLOCKING);
    if (iq.getAttribute('type') === 'set' && (blocked || unblocked)) {
      this.sendRaw(`<iq xmlns='${NS.CLIENT}' type='result' id='${xmlEscape(id || '')}'/>`);
      this.emit('blocking-change', {
        action: blocked ? 'block' : 'unblock',
        jids: [...(blocked || unblocked).children].filter((node) => node.localName === 'item').map((node) => bareJid(node.getAttribute('jid'))),
      });
    }
  }

  handleMessage(message, raw) {
    if (message.getAttribute('type') === 'error') {
      const id = message.getAttribute('id') || '';
      const errors = [...message.children]
        .filter((node) => node.localName === 'error' && node.namespaceURI === NS.CLIENT);
      if (!id || id.length > 128 || /[\u0000-\u001f\u007f]/.test(id) || errors.length !== 1) {
        this.emit('protocol-error', { error: new Error('Message error is missing a safe correlation id'), raw });
        return;
      }
      const errorNode = errors[0];
      const parsed = xmppError(message);
      const errorType = errorNode.getAttribute('type') || '';
      this.emit('message-error', {
        id,
        from: message.getAttribute('from') || '',
        to: message.getAttribute('to') || '',
        error: parsed,
        errorType,
        condition: parsed.condition,
        powRequired: Boolean(child(errorNode, 'pow-required', 'urn:northstar:pow:1')),
        proofChallengeId: child(message, 'pow', 'urn:northstar:pow:1')?.getAttribute('challenge') || null,
        raw,
      });
      return;
    }
    const event = child(message, 'event', NS.PUBSUB_EVENT);
    if (event) {
      this.emit('pep-event', { from: bareJid(message.getAttribute('from')), event, raw });
      return;
    }
    const mamResult = child(message, 'result', NS.MAM);
    if (mamResult) {
      const queryId = mamResult.getAttribute('queryid') || '';
      const archiveId = mamResult.getAttribute('id') || '';
      if (!this.mamQueries.has(queryId) || !archiveId || archiveId.length > 256) {
        this.emit('protocol-error', { error: new Error('拒绝了未经请求或缺少稳定 ID 的 MAM 结果'), raw });
        return;
      }
      const forwarded = child(mamResult, 'forwarded', NS.FORWARD);
      const forwardedChildren = [...(forwarded?.children || [])];
      const messages = forwardedChildren.filter((node) => node.localName === 'message' && node.namespaceURI === NS.CLIENT);
      const delays = forwardedChildren.filter((node) => node.localName === 'delay' && node.namespaceURI === NS.DELAY);
      if (!forwarded || messages.length !== 1 || delays.length > 1
        || forwardedChildren.length !== messages.length + delays.length) {
        this.emit('protocol-error', { error: new Error('MAM forwarded 结构无效'), raw });
        return;
      }
      this.emit('message', { element: messages[0], archived: true, timestamp: delays[0]?.getAttribute('stamp') || null, archiveId });
      return;
    }
    const carbon = child(message, 'sent', NS.CARBONS) || child(message, 'received', NS.CARBONS);
    if (carbon) {
      if (bareJid(message.getAttribute('from')) !== bareJid(this.jid)) {
        this.emit('protocol-error', { error: new Error('拒绝了来源不匹配的 Message Carbon'), raw });
        return;
      }
      const forwarded = child(carbon, 'forwarded', NS.FORWARD);
      const forwardedChildren = [...(forwarded?.children || [])];
      const messages = forwardedChildren.filter((node) => node.localName === 'message' && node.namespaceURI === NS.CLIENT);
      const delays = forwardedChildren.filter((node) => node.localName === 'delay' && node.namespaceURI === NS.DELAY);
      if (!forwarded || messages.length !== 1 || delays.length > 1
        || forwardedChildren.length !== messages.length + delays.length) {
        this.emit('protocol-error', { error: new Error('Message Carbon forwarded 结构无效'), raw });
        return;
      }
      const inner = messages[0];
      const own = bareJid(this.jid);
      if ((carbon.localName === 'sent' && bareJid(inner.getAttribute('from')) !== own)
        || (carbon.localName === 'received' && bareJid(inner.getAttribute('to')) !== own)) {
        this.emit('protocol-error', { error: new Error('Message Carbon 内层方向无效'), raw });
        return;
      }
      this.emit('message', { element: inner, archived: false, timestamp: delays[0]?.getAttribute('stamp') || null, carbon: carbon.localName, raw });
      return;
    }
    const delays = [...message.children]
      .filter((node) => node.localName === 'delay' && node.namespaceURI === NS.DELAY);
    if (delays.length > 1) {
      this.emit('protocol-error', { error: new Error('Message contains multiple delay timestamps'), raw });
      return;
    }
    const delayedAt = delays[0]?.getAttribute('stamp') || '';
    this.emit('message', {
      element: message,
      archived: false,
      timestamp: Number.isFinite(Date.parse(delayedAt)) ? delayedAt : null,
      raw,
    });
  }

  handlePresence(presence) {
    const from = presence.getAttribute('from') || '';
    const muc = child(presence, 'x', NS.MUC_USER);
    const item = muc && child(muc, 'item', NS.MUC_USER);
    this.emit('presence', {
      from,
      bareFrom: bareJid(from),
      type: presence.getAttribute('type') || 'available',
      show: child(presence, 'show')?.textContent || 'online',
      status: child(presence, 'status')?.textContent || '',
      muc: Boolean(muc),
      nick: from.includes('/') ? from.slice(from.indexOf('/') + 1) : '',
      realJid: bareJid(item?.getAttribute('jid') || ''),
      affiliation: item?.getAttribute('affiliation') || 'none',
      role: item?.getAttribute('role') || 'none',
      error: presence.getAttribute('type') === 'error' ? xmppError(presence) : null,
      statusCodes: [...(muc?.children || [])]
        .filter((node) => node.localName === 'status')
        .map((node) => node.getAttribute('code')),
    });
  }

  failConnect(error) {
    this.clearAuthenticationSecret();
    this.rejectConnect?.(error);
    this.resolveConnect = null;
    this.rejectConnect = null;
    this.emit('connection-error', { error });
    this.socket?.close();
  }

  rejectPending(error) {
    for (const { reject, timer } of this.pending.values()) {
      clearTimeout(timer);
      reject(error);
    }
    this.pending.clear();
    this.mamQueries.clear();
  }

  dropPreviousStream(error) {
    this.rejectPending(error);
    this.smEnabled = false;
    this.smResumeId = null;
    this.smOutbound = 0;
    this.smInbound = 0;
    this.smServerAck = 0;
    this.smUnacked = [];
    this.smUnackedBytes = 0;
    this.jid = null;
    this.resource = null;
  }

  closed() {
    const wasOnline = this.phase === 'online';
    const canResume = wasOnline && !this.intentionalClose && Boolean(this.smResumeId && this.jid);
    this.phase = 'closed';
    this.clearAuthenticationSecret();
    if (!canResume) this.dropPreviousStream(new Error('XMPP 连接已关闭'));
    this.smEnabled = false;
    this.connectPromise = null;
    if (this.rejectConnect) {
      const reject = this.rejectConnect;
      this.resolveConnect = null;
      this.rejectConnect = null;
      reject(new Error('XMPP 连接在认证完成前已关闭'));
    }
    if (wasOnline || !this.intentionalClose) this.emit('disconnected', { intentional: this.intentionalClose });
  }

  disconnect() {
    this.intentionalClose = true;
    this.clearAuthenticationSecret();
    this.fastCredential = null;
    this.smResumeId = null;
    try { this.sendRaw(`<presence xmlns='${NS.CLIENT}' type='unavailable'/>`); } catch {}
    try { this.sendRaw(`<close xmlns='${NS.FRAMING}'/>`); } catch {}
    this.socket?.close();
  }

  canResume() {
    return this.phase === 'closed' && Boolean(this.smResumeId && this.jid);
  }

  canReconnect() {
    return this.phase === 'closed' && Boolean(
      this.fastCredential && Number.isFinite(this.fastCredential.expiry) && this.fastCredential.expiry > Date.now()
    );
  }

  isStanzaPending(id) {
    return this.smEnabled && this.smUnacked.some((stanza) => stanza.id === id);
  }

  async getRoster() {
    const iq = await this.sendIq(`<query xmlns='${NS.ROSTER}'/>`);
    return parseRoster(child(iq, 'query', NS.ROSTER));
  }

  async getBlocklist() {
    const iq = await this.sendIq(`<blocklist xmlns='${NS.BLOCKING}'/>`);
    const blocklist = child(iq, 'blocklist', NS.BLOCKING);
    return [...(blocklist?.children || [])]
      .filter((node) => node.localName === 'item')
      .map((node) => bareJid(node.getAttribute('jid')));
  }

  block(jid) {
    return this.sendIq(`<block xmlns='${NS.BLOCKING}'><item jid='${xmlEscape(bareJid(jid))}'/></block>`, { type: 'set' });
  }

  unblock(jid) {
    return this.sendIq(`<unblock xmlns='${NS.BLOCKING}'><item jid='${xmlEscape(bareJid(jid))}'/></unblock>`, { type: 'set' });
  }

  setRosterItem(jid, name = '') {
    const nameAttribute = name ? ` name='${xmlEscape(name)}'` : '';
    return this.sendIq(`<query xmlns='${NS.ROSTER}'><item jid='${xmlEscape(bareJid(jid))}'${nameAttribute}/></query>`, { type: 'set' });
  }

  removeRosterItem(jid) {
    return this.sendIq(`<query xmlns='${NS.ROSTER}'><item jid='${xmlEscape(bareJid(jid))}' subscription='remove'/></query>`, { type: 'set' });
  }

  subscribe(jid) {
    this.sendRaw(`<presence xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(jid))}' type='subscribe'/>`);
  }

  approveSubscription(jid) {
    this.sendRaw(`<presence xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(jid))}' type='subscribed'/>`);
  }

  sendMessage(to, payload, id = randomId('msg')) {
    this.sendRaw(this.buildMessage(to, payload, id, 'chat'));
    return id;
  }

  buildMessage(to, payload, id, type = 'chat') {
    if (!['chat', 'groupchat'].includes(type)) throw new Error('Unsupported outbound message type');
    return `<message xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(to))}' type='${type}' id='${xmlEscape(id)}'>${payload}<origin-id xmlns='${NS.STANZA_ID}' id='${xmlEscape(id)}'/></message>`;
  }

  joinRoom(room, nick) {
    this.sendRaw(`<presence xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(room))}/${xmlEscape(nick)}'><x xmlns='${NS.MUC}'/></presence>`);
  }

  configureInstantRoom(room) {
    return this.sendIq(
      `<query xmlns='${NS.MUC_OWNER}'><x xmlns='${NS.X_DATA}' type='submit'/></query>`,
      { type: 'set', to: bareJid(room), timeout: 20000 },
    );
  }

  leaveRoom(room, nick) {
    this.sendRaw(`<presence xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(room))}/${xmlEscape(nick)}' type='unavailable'/>`);
  }

  sendGroupMessage(room, payload, id = randomId('group')) {
    this.sendRaw(this.buildMessage(room, payload, id, 'groupchat'));
    return id;
  }

  async getMucAffiliations(room, affiliation) {
    if (!['owner', 'admin', 'member'].includes(affiliation)) throw new Error('群聊成员类型无效');
    const iq = await this.sendIq(`<query xmlns='${NS.MUC_ADMIN}'><item affiliation='${affiliation}'/></query>`, {
      to: bareJid(room),
      timeout: 20000,
    });
    const query = child(iq, 'query', NS.MUC_ADMIN);
    const items = [...(query?.children || [])];
    if (items.length > 1000) throw new Error('群聊成员列表超过安全上限');
    return items.map((item) => {
      if (item.localName !== 'item' || item.namespaceURI !== NS.MUC_ADMIN) throw new Error('群聊成员列表包含未知元素');
      const jid = item.getAttribute('jid') || '';
      if (!jid || jid.includes('/') || bareJid(jid) === '') throw new Error('群聊成员列表包含无效 JID');
      return bareJid(jid);
    });
  }

  async getDiscoFeatures(jid) {
    const iq = await this.sendIq(`<query xmlns='${NS.DISCO_INFO}'/>`, {
      to: bareJid(jid),
      timeout: 20000,
    });
    const query = child(iq, 'query', NS.DISCO_INFO);
    if (!query) throw new Error('Service discovery response is missing disco#info');
    const features = new Set();
    for (const item of [...query.children]) {
      if (item.localName !== 'feature' || item.namespaceURI !== NS.DISCO_INFO) continue;
      const value = item.getAttribute('var') || '';
      if (!value || value.length > 1024) throw new Error('Service discovery returned an invalid feature');
      features.add(value);
    }
    return features;
  }

  async requestUploadSlot(filename, size, contentType = 'application/octet-stream') {
    if (typeof filename !== 'string' || !filename || [...filename].length > 255
      || !Number.isSafeInteger(Number(size)) || Number(size) < 0
      || typeof contentType !== 'string' || !contentType || contentType.length > 255) {
      throw new Error('Invalid HTTP upload slot request');
    }
    const iq = await this.sendIq(
      `<request xmlns='${NS.HTTP_UPLOAD}' filename='${xmlEscape(filename)}' size='${Number(size)}' content-type='${xmlEscape(contentType)}'/>`,
      { to: `upload.${this.domain}`, timeout: 20000 },
    );
    const slot = child(iq, 'slot', NS.HTTP_UPLOAD);
    const put = child(slot, 'put', NS.HTTP_UPLOAD);
    const get = child(slot, 'get', NS.HTTP_UPLOAD);
    if (!put?.getAttribute('url') || !get?.getAttribute('url')) throw new Error('上传服务返回了无效槽位');
    const headers = Object.create(null);
    const seenHeaders = new Set();
    const headerNodes = [...put.children].filter((item) => item.localName === 'header');
    if (headerNodes.length !== put.children.length) throw new Error('Upload service returned an unknown PUT child element');
    if (headerNodes.length > 32) throw new Error('Upload service returned too many headers');
    for (const node of headerNodes) {
      const name = node.getAttribute('name');
      const normalized = name?.toLowerCase() || '';
      if (node.namespaceURI !== NS.HTTP_UPLOAD
        || [...node.attributes].some((attribute) => (
          attribute.namespaceURI !== 'http://www.w3.org/2000/xmlns/'
          && (attribute.namespaceURI || attribute.localName !== 'name')
        ))
        || [...node.children].length
        || !name
        || name.length > 128
        || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)
        || seenHeaders.has(normalized)
        || /[\r\n]/.test(node.textContent)) throw new Error('Upload service returned an invalid header');
      seenHeaders.add(normalized);
      headers[name] = node.textContent;
    }
    return {
      put: { url: secureTransferUrl(put.getAttribute('url')), headers },
      get: { url: secureTransferUrl(get.getAttribute('url')) },
    };
  }

  getVCard(jid) {
    return this.sendIq(`<vCard xmlns='vcard-temp'/>`, { to: bareJid(jid) });
  }

  setVCard(payload) {
    return this.sendIq(payload, { type: 'set' });
  }

  sendChatState(to, state) {
    this.sendRaw(`<message xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(to))}' type='chat'><${state} xmlns='${NS.CHAT_STATES}'/><no-store xmlns='${NS.HINTS}'/></message>`);
  }

  async queryMam(withJid, max = 100) {
    const queryId = randomId('mam-query');
    const payload = `<query xmlns='${NS.MAM}' queryid='${queryId}'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>${NS.MAM}</value></field><field var='with'><value>${xmlEscape(bareJid(withJid))}</value></field></x><set xmlns='${NS.RSM}'><max>${Math.min(100, Math.max(1, max))}</max></set></query>`;
    this.mamQueries.set(queryId, { withJid: bareJid(withJid) });
    try {
      return await this.sendIq(payload, { type: 'set', id: queryId, timeout: 20000 });
    } finally {
      this.mamQueries.delete(queryId);
    }
  }

  async getPep(owner, node, itemId = null) {
    const item = itemId === null ? '' : `<item id='${xmlEscape(itemId)}'/>`;
    return this.sendIq(`<pubsub xmlns='${NS.PUBSUB}'><items node='${xmlEscape(node)}'>${item}</items></pubsub>`, { to: bareJid(owner) });
  }

  subscribePep(owner, node) {
    if (!this.jid) return Promise.reject(new Error('XMPP 尚未连接'));
    return this.sendIq(
      `<pubsub xmlns='${NS.PUBSUB}'><subscribe node='${xmlEscape(node)}' jid='${xmlEscape(bareJid(this.jid))}'/></pubsub>`,
      { to: bareJid(owner), type: 'set', timeout: 20000 },
    );
  }

  publishPep(node, itemId, payload, options = null) {
    const fields = [];
    if (options?.accessModel) fields.push(`<field var='pubsub#access_model'><value>${xmlEscape(options.accessModel)}</value></field>`);
    if (options?.maxItems) fields.push(`<field var='pubsub#max_items'><value>${xmlEscape(String(options.maxItems))}</value></field>`);
    const publishOptions = fields.length
      ? `<publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>${fields.join('')}</x></publish-options>`
      : '';
    return this.sendIq(`<pubsub xmlns='${NS.PUBSUB}'><publish node='${xmlEscape(node)}'><item id='${xmlEscape(itemId)}'>${payload}</item></publish>${publishOptions}</pubsub>`, { type: 'set', timeout: 20000 });
  }

  retractPep(node, itemId, notify = true) {
    return this.sendIq(`<pubsub xmlns='${NS.PUBSUB}'><retract node='${xmlEscape(node)}' notify='${notify ? 'true' : 'false'}'><item id='${xmlEscape(itemId)}'/></retract></pubsub>`, { type: 'set', timeout: 20000 });
  }
}

function parseRoster(query) {
  return [...(query?.children || [])]
    .filter((item) => item.localName === 'item')
    .map((item) => ({
      jid: bareJid(item.getAttribute('jid')),
      name: item.getAttribute('name') || '',
      subscription: item.getAttribute('subscription') || 'none',
      ask: item.getAttribute('ask') || null,
    }));
}
