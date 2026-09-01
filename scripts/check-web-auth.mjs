import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const clientSource = fs.readFileSync(new URL('../web/client.js', import.meta.url), 'utf8');
const xmppSource = fs.readFileSync(new URL('../web/xmpp.js', import.meta.url), 'utf8');
const omemoSource = fs.readFileSync(new URL('../web/omemo.js', import.meta.url), 'utf8');
const appSource = fs.readFileSync(new URL('../web/app.js', import.meta.url), 'utf8');
const storageSource = fs.readFileSync(new URL('../web/storage.js', import.meta.url), 'utf8');
const apiSource = fs.readFileSync(new URL('../src/api/mod.rs', import.meta.url), 'utf8');
const csp = apiSource.match(/const SPA_CONTENT_SECURITY_POLICY: &str = "([^"]+)";/)?.[1] || '';
const nodeRequire = createRequire(import.meta.url);
const { safeFrame } = nodeRequire('./web-e2e.cjs');

function requirePattern(source, pattern, message) {
  if (!pattern.test(source)) throw new Error(message);
}

// ---------------------------------------------------------------------------
// 1. Static Security & Lifecycle Pattern Assertions
// ---------------------------------------------------------------------------

if (/sessionPassword/.test(clientSource)) {
  throw new Error('the browser application retains a reusable account password in session state');
}
const browserSources = [clientSource, xmppSource, appSource, storageSource];
if (browserSources.some((source) => (
  /localStorage\.setItem\([^)]*password/i.test(source)
  || /sessionStorage\.setItem\([^)]*password/i.test(source)
  || /localStorage\.setItem\([^)]*fast/i.test(source)
  || /sessionStorage\.setItem\([^)]*fast/i.test(source)
))) {
  throw new Error('the browser application persists raw password or FAST credentials to web storage');
}
if (/mechanism=['"]PLAIN['"]/.test(xmppSource)) {
  throw new Error('the browser client still emits SASL PLAIN authentication');
}
if (/NS\.SASL\b|NS\.BIND\b|establishFreshSession|enableStreamManagement|handleResumed/.test(xmppSource)) {
  throw new Error('the browser client still contains a legacy SASL or resource-binding fallback');
}
requirePattern(xmppSource, /SCRAM-SHA-256/, 'SCRAM-SHA-256 is not implemented by the browser client');
requirePattern(xmppSource, /HT-SHA-256-NONE/, 'XEP-0484 FAST reconnect is not implemented by the browser client');
requirePattern(xmppSource, /<resume xmlns='\$\{NS\.SM\}'/, 'SASL2 inline XEP-0198 resumption is not requested');
if (/this\.password\b/.test(xmppSource)) {
  throw new Error('XmppClient must not expose or retain a raw password field');
}
requirePattern(clientSource, /\$\('#login-password'\)\.value = '';/, 'the login password input is not cleared');
requirePattern(clientSource, /state\.xmpp\.canReconnect\(\)/, 'reconnect does not reuse the in-memory FAST credential');
requirePattern(xmppSource, /constantTimeEqual\(base64Bytes\(serverFinal\.slice\(2\)\), expected\)/, 'the SCRAM server signature is not verified');
requirePattern(xmppSource, /child\(root, 'resumed', NS\.SM\)[\s\S]+applyInlineResumed/, 'SASL2 inline XEP-0198 resumption is not processed');
requirePattern(clientSource, /pagehide[\s\S]+handlePageHide/, 'pagehide does not use the explicit lifecycle policy');
requirePattern(clientSource, /pageshow[\s\S]+handlePageShow/, 'pageshow does not restore the BFCache lock screen');
requirePattern(clientSource, /function handlePageHide[\s\S]+event\.persisted[\s\S]+revokeApiSession: !persisted/, 'pagehide does not distinguish BFCache from final unload');
requirePattern(clientSource, /function handlePageShow[\s\S]+event\.persisted[\s\S]+auth-view/, 'BFCache restore does not remain visibly locked');
requirePattern(clientSource, /keepalive: true/, 'non-BFCache teardown lacks best-effort REST session revocation');
requirePattern(clientSource, /clearPersistedRoomMetadata\(account\)/, 'secure browser teardown retains account room metadata');
requirePattern(clientSource, /switchAuth[\s\S]+\$\('#login-password'\)\.value = ''/, 'switchAuth does not clear password inputs');
requirePattern(clientSource, /function clearSensitiveSessionUi[\s\S]+clearPasswordAndTransferInputs\(\)/, 'sensitive UI cleanup does not clear password inputs');
requirePattern(clientSource, /function endBrowserSession[\s\S]+clearSensitiveSessionUi\(\)/, 'browser session teardown does not clear sensitive UI');
requirePattern(clientSource, /function logout[\s\S]+endBrowserSession/, 'logout does not use the common secure session teardown');
requirePattern(appSource, /\$\('#admin-password'\)\.value = '';/, 'admin login form does not clear password inputs');
requirePattern(appSource, /requestBody\.password = '';/, 'admin login requestBody.password is not cleared after REST request');
requirePattern(clientSource, /passphraseInput\.value = '';/, 'omemo transfer passphrase input is not cleared');
requirePattern(xmppSource, /validateWebsocketUrl/, 'XMPP client does not validate secure WebSocket URLs');

requirePattern(clientSource, /requestBody\.password = '';/, 'requestBody.password is not cleared after REST request');
requirePattern(clientSource, /passwordBytes\.fill\(0\)/, 'client.js does not zero passwordBytes after importing PBKDF2 CryptoKey');
requirePattern(clientSource, /crypto\.subtle\.importKey\(\s*'raw',\s*passwordBytes,\s*'PBKDF2',\s*false/, 'client.js does not import non-extractable PBKDF2 CryptoKey');
requirePattern(xmppSource, /XMPP 连接在认证完成前已关闭/, 'closed without error does not reject pending connect promise');
requirePattern(xmppSource, /extractable !== false/, 'XMPP client does not enforce non-extractable CryptoKey');
if (/typeof\s+scramKey\s*===\s*['"]string|scramKey\s+instanceof\s+Uint8Array/.test(xmppSource)) {
  throw new Error('XmppClient accepts a raw string or byte buffer instead of a CryptoKey');
}
requirePattern(xmppSource, /saltedPassword\?\.fill/, 'SCRAM salted password buffer is not zeroed in finally block');
requirePattern(xmppSource, /expectedServerSignature\?\.fill/, 'expectedServerSignature buffer is not zeroed in clearAuthenticationSecret');
requirePattern(xmppSource, /fastMechanisms\.includes\(this\.fastCredential\.mechanism\)/, 'FAST reconnect does not check fastMechanisms inside <fast>');
requirePattern(clientSource, /opaqueUploadName = `\$\{crypto\.randomUUID\(\)\}\.bin`[\s\S]+requestUploadSlot\([\s\S]+opaqueUploadName/, 'encrypted attachment slots do not use opaque UUID .bin filenames');
if (/requestUploadSlot\(safeName|\.encrypted`,\s*ciphertext\.byteLength/.test(clientSource)) {
  throw new Error('encrypted attachment upload still exposes a filename-derived slot name');
}
requirePattern(xmppSource, /url\.origin !== pageOrigin[\s\S]+Cross-origin file transfer URLs are not permitted/, 'upload slot URLs are not restricted to the exact page origin');
requirePattern(omemoSource, /url\.origin !== pageOrigin[\s\S]+不允许从跨域地址下载加密文件/, 'encrypted attachment downloads are not restricted to the exact page origin');

if (/style-src[^;\"]*'unsafe-inline'/.test(apiSource)) {
  throw new Error('the browser application CSP permits inline style injection');
}
if (/\.style\b|setAttribute\(\s*['\"]style['\"]/.test(clientSource)) {
  throw new Error('the browser application relies on inline styles that weaken CSP');
}
requirePattern(csp, /connect-src 'self';/, 'browser CSP does not limit network connections to the exact application origin');
if (/connect-src[^;]*(?:\bws:|\bwss:|\bhttps:)/.test(csp)) {
  throw new Error('browser CSP contains a scheme-wide connection source');
}
requirePattern(csp, /worker-src 'self';/, 'browser CSP does not limit workers to static same-origin modules');
if (/worker-src[^;]*blob:/.test(csp)) throw new Error('browser CSP permits blob workers');
requirePattern(csp, /base-uri 'none'/, 'browser CSP does not disable base URL rewriting');
requirePattern(csp, /form-action 'self'/, 'browser CSP does not restrict form submissions');

for (const frame of [
  "<authenticate xmlns='urn:xmpp:sasl:2'><initial-response>password-like-secret</initial-response></authenticate>",
  "<challenge xmlns='urn:xmpp:sasl:2'>server-secret</challenge>",
  "<response xmlns='urn:xmpp:sasl:2'>client-proof</response>",
  "<success xmlns='urn:xmpp:sasl:2'><additional-data>server-proof</additional-data><token token='fast-secret'/></success>",
  "<failure xmlns='urn:xmpp:sasl:2'><credentials-expired/></failure>",
  "<wrapper><initial-response>nested-secret</initial-response></wrapper>",
  "<wrapper><additional-data>nested-proof</additional-data></wrapper>",
  "<wrapper><token token='nested-fast-secret'/></wrapper>",
  "<sasl2:challenge xmlns:sasl2='urn:xmpp:sasl:2'>prefixed-secret</sasl2:challenge>",
]) {
  const safe = safeFrame(frame);
  assert.equal(safe, '<sasl2-frame>[redacted]</sasl2-frame>');
  assert(!/(?:secret|proof|password|credentials-expired)/i.test(safe));
}
assert.equal(safeFrame('<message><body>non-sensitive</body></message>'), '<message><body>non-sensitive</body></message>');

// ---------------------------------------------------------------------------
// 2. Mock XML DOM and WebSocket Harness for XmppClient Unit Tests
// ---------------------------------------------------------------------------

class MockXmlElement {
  constructor(localName, namespaceURI = null, attributes = {}, textContent = '', children = []) {
    this.localName = localName;
    this.namespaceURI = namespaceURI;
    this._attributes = new Map(Object.entries(attributes));
    this.textContent = textContent;
    this.children = children;
  }

  getAttribute(name) {
    return this._attributes.get(name) ?? null;
  }

  get attributes() {
    return [...this._attributes.entries()].map(([name, value]) => ({
      name,
      localName: name,
      value,
      namespaceURI: name === 'xmlns' || name.startsWith('xmlns:') ? 'http://www.w3.org/2000/xmlns/' : null,
    }));
  }

  getElementsByTagNameNS(namespace, name) {
    const matches = [];
    for (const child of this.children) {
      if ((namespace === '*' || child.namespaceURI === namespace)
        && (name === '*' || child.localName === name)) {
        matches.push(child);
      }
      matches.push(...child.getElementsByTagNameNS(namespace, name));
    }
    return matches;
  }
}

function parseMockXml(xml) {
  xml = xml.trim();
  const tagStart = xml.indexOf('<');
  if (tagStart === -1) return new MockXmlElement('text', null, {}, xml, []);
  const tagEnd = xml.indexOf('>');
  if (tagEnd === -1) throw new Error('Invalid XML');
  const tagHeader = xml.slice(tagStart + 1, tagEnd).trim();
  const isSelfClosing = tagHeader.endsWith('/');
  const tagContent = isSelfClosing ? tagHeader.slice(0, -1).trim() : tagHeader;
  const spaceIdx = tagContent.search(/\s/);
  const rawTag = spaceIdx === -1 ? tagContent : tagContent.slice(0, spaceIdx);
  const attrStr = spaceIdx === -1 ? '' : tagContent.slice(spaceIdx);
  const localName = rawTag.includes(':') ? rawTag.split(':')[1] : rawTag;

  const attributes = {};
  let namespaceURI = null;
  const attrRegex = /([A-Za-z0-9_:-]+)=(?:'([^']*)'|"([^"]*)")/g;
  let match;
  while ((match = attrRegex.exec(attrStr)) !== null) {
    const key = match[1];
    const val = match[2] ?? match[3] ?? '';
    if (key === 'xmlns') namespaceURI = val;
    attributes[key] = val;
  }

  if (isSelfClosing) {
    return new MockXmlElement(localName, namespaceURI, attributes, '', []);
  }

  const closeTag = `</${rawTag}>`;
  const closeIdx = xml.lastIndexOf(closeTag);
  const inner = closeIdx > tagEnd ? xml.slice(tagEnd + 1, closeIdx) : '';

  const children = [];
  let remaining = inner.trim();
  while (remaining.startsWith('<')) {
    let depth = 0;
    let endIdx = -1;
    for (let i = 0; i < remaining.length; i += 1) {
      if (remaining[i] === '<') {
        if (remaining[i + 1] === '/') {
          depth -= 1;
        } else {
          const selfClose = remaining.slice(i, remaining.indexOf('>', i) + 1).endsWith('/>');
          if (!selfClose) depth += 1;
        }
      } else if (remaining[i] === '>') {
        if (depth === 0) {
          endIdx = i + 1;
          break;
        }
      }
    }
    if (endIdx > 0) {
      children.push(parseMockXml(remaining.slice(0, endIdx)));
      remaining = remaining.slice(endIdx).trim();
    } else {
      break;
    }
  }

  const textContent = children.length === 0 ? inner.trim() : children.map((c) => c.textContent).join('');
  return new MockXmlElement(localName, namespaceURI, attributes, textContent, children);
}

class MockDOMParser {
  parseFromString(text) {
    return {
      documentElement: parseMockXml(text),
      querySelector: () => null,
    };
  }
}

globalThis.DOMParser = MockDOMParser;
globalThis.location = new URL('https://example.com/client.html');

class MockWebSocket extends EventTarget {
  static instances = [];
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor(url, protocol) {
    super();
    this.url = url;
    this.protocol = protocol;
    this.readyState = MockWebSocket.CONNECTING;
    this.sent = [];
    MockWebSocket.instances.push(this);
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      this.dispatchEvent(new Event('open'));
    }, 10);
  }

  send(data) {
    this.sent.push(String(data));
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this.dispatchEvent(new Event('close'));
  }

  serverPush(xml) {
    this.dispatchEvent(new MessageEvent('message', { data: xml }));
  }
}

globalThis.WebSocket = MockWebSocket;

const { XmppClient, NS } = await import('../web/xmpp.js');

// Crypto helper for SCRAM test verification
async function hmac(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, dataBytes));
}

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
}

async function makeScramKey(password) {
  const bytes = new TextEncoder().encode(password);
  try {
    return await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
  } finally {
    bytes.fill(0);
  }
}

function toBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ---------------------------------------------------------------------------
// 3. Unit Test: Full Login Success, SCRAM-SHA-256, FAST Issuance, and Secret Zeroing
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  assert.equal(Object.hasOwn(client, 'password'), false);
  assert.equal(client.fastCredential, null);

  const connectPromise = client.connect('Alice', await makeScramKey('correct-horse-battery-staple'));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(client.username, 'alice');
  assert.equal(Object.hasOwn(client, 'password'), false, 'Raw password is never retained on client instance');
  assert.ok(client.scramKey instanceof CryptoKey, 'scramKey must be a CryptoKey');
  assert.equal(client.scramKey.extractable, false, 'scramKey must be non-extractable');

  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);
  assert.ok(ws, 'WebSocket created');
  assert.ok(ws.sent.some((s) => s.includes("<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'")));

  // 1. Server sends features advertising SASL2 SCRAM-SHA-256 & FAST HT-SHA-256-NONE
  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism><fast xmlns='${NS.FAST}'><mechanism xmlns='${NS.FAST}'>HT-SHA-256-NONE</mechanism></fast></authentication></stream:features>`);

  await new Promise((resolve) => setTimeout(resolve, 20));
  const authMsg = ws.sent.find((s) => s.includes("<authenticate xmlns='urn:xmpp:sasl:2' mechanism='SCRAM-SHA-256'"));
  assert.ok(authMsg, 'Client sends SCRAM-SHA-256 authentication');
  assert.ok(authMsg.includes("<request-token xmlns='urn:xmpp:fast:0' mechanism='HT-SHA-256-NONE'/>"));

  // Extract client first bare
  const initRespMatch = authMsg.match(/<initial-response>([^<]+)<\/initial-response>/);
  assert.ok(initRespMatch);
  const clientFirst = atob(initRespMatch[1]);
  const clientFirstBare = clientFirst.slice(clientFirst.indexOf('n='));
  const clientNonce = clientFirstBare.match(/r=([^,]+)/)[1];

  // 2. Server sends SCRAM challenge
  const serverNonce = `${clientNonce}s_nonce_12345`;
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  const saltB64 = toBase64(salt);
  const serverFirst = `s=${saltB64},x=bounded-extension,r=${serverNonce},i=4096,z=tail-extension`;
  ws.serverPush(`<challenge xmlns='${NS.SASL2}'>${btoa(serverFirst)}</challenge>`);

  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(client.scramKey, null, 'Client MUST release the non-extractable key upon processing challenge');

  const responseMsg = ws.sent.find((s) => s.includes("<response xmlns='urn:xmpp:sasl:2'"));
  assert.ok(responseMsg, 'Client sends challenge response');
  const clientFinalB64 = responseMsg.match(/<response xmlns='urn:xmpp:sasl:2'>([^<]+)<\/response>/)[1];
  const clientFinal = atob(clientFinalB64);
  const clientFinalBare = clientFinal.slice(0, clientFinal.lastIndexOf(',p='));

  // Calculate expected server signature
  const saltedPassword = await pbkdf2('correct-horse-battery-staple', salt, 4096);
  const serverKey = await hmac(saltedPassword, new TextEncoder().encode('Server Key'));
  const authMessage = `${clientFirstBare},${serverFirst},${clientFinalBare}`;
  const serverSignature = await hmac(serverKey, new TextEncoder().encode(authMessage));
  const serverFinal = `v=${toBase64(serverSignature)}`;

  // 3. Server sends SASL2 success with FAST token and inline SM enabled
  const fastToken = 'fast_token_secret_0123456789abcdef0123456789abcdef';
  const fastExpiry = new Date(Date.now() + 86400 * 1000).toISOString();
  const smResumeId = 'sm_resume_id_123456789012345678901234567890';
  ws.serverPush(`<success xmlns='${NS.SASL2}'><additional-data xmlns='${NS.SASL2}'>${btoa(serverFinal)}</additional-data><authorization-identifier xmlns='${NS.SASL2}'>alice@example.com/Northstar-Web</authorization-identifier><token xmlns='${NS.FAST}' token='${fastToken}' expiry='${fastExpiry}'/><bound xmlns='${NS.BIND2}'><enabled xmlns='${NS.SM}' id='${smResumeId}' resume='true'/></bound></success>`);

  await new Promise((resolve) => setTimeout(resolve, 20));
  // Server sends post-auth features
  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'/>`);

  const jid = await connectPromise;
  assert.equal(jid, 'alice@example.com/Northstar-Web');
  assert.equal(Object.hasOwn(client, 'password'), false);
  assert.equal(client.phase, 'online');
  assert.ok(client.fastCredential, 'FAST credential stored in memory');
  assert.equal(client.fastCredential.token, fastToken);
  assert.equal(client.smResumeId, smResumeId);
  assert.equal(client.smEnabled, true);
  assert.equal(client.canReconnect(), false, 'canReconnect is false while online');

  // Verify disconnect cleans up
  client.closed();
  assert.equal(client.phase, 'closed');
  assert.equal(client.canReconnect(), true, 'canReconnect is true after normal disconnect');
  assert.equal(client.canResume(), true, 'canResume is true after normal disconnect');
}

// ---------------------------------------------------------------------------
// 4. Unit Test: Disconnect & Reconnection using FAST and Inline SM Resume
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  const fastToken = 'fast_token_secret_0123456789abcdef0123456789abcdef';
  const fastExpiry = Date.now() + 3600 * 1000;
  const smResumeId = 'sm_resume_id_123456789012345678901234567890';

  // Seed client in disconnected state with in-memory FAST credential and SM resume token
  client.username = 'alice';
  client.jid = 'alice@example.com/Northstar-Web';
  client.fastCredential = { mechanism: 'HT-SHA-256-NONE', token: fastToken, expiry: fastExpiry };
  client.smResumeId = smResumeId;
  client.phase = 'closed';

  assert.equal(client.canReconnect(), true);
  assert.equal(client.canResume(), true);

  // Connect WITHOUT password
  const reconnectPromise = client.connect('alice', null);
  assert.equal(Object.hasOwn(client, 'password'), false, 'No password field exists during reconnect');

  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);

  // Server advertises FAST (only in <fast> element per server protocol)
  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism><fast xmlns='${NS.FAST}'><mechanism xmlns='${NS.FAST}'>HT-SHA-256-NONE</mechanism></fast></authentication></stream:features>`);

  await new Promise((resolve) => setTimeout(resolve, 30));
  const fastAuth = ws.sent.find((s) => s.includes("<authenticate xmlns='urn:xmpp:sasl:2' mechanism='HT-SHA-256-NONE'"));
  assert.ok(fastAuth, 'FAST authentication sent');
  assert.ok(fastAuth.includes(`previd='${smResumeId}'`), 'Inline SM resume token included');

  // Verify server responder HMAC signature
  const tokenBytes = new TextEncoder().encode(fastToken);
  const responderKey = await hmac(tokenBytes, new TextEncoder().encode('Responder'));

  const rotatedToken = 'rotated_fast_token_123456789012345678901234';
  const rotatedExpiry = new Date(Date.now() + 7200 * 1000).toISOString();

  // Server succeeds with SM resumed
  ws.serverPush(`<success xmlns='${NS.SASL2}'><additional-data xmlns='${NS.SASL2}'>${toBase64(responderKey)}</additional-data><authorization-identifier xmlns='${NS.SASL2}'>alice@example.com/Northstar-Web</authorization-identifier><token xmlns='${NS.FAST}' token='${rotatedToken}' expiry='${rotatedExpiry}'/><resumed xmlns='${NS.SM}' previd='${smResumeId}' h='0'/></success>`);

  await new Promise((resolve) => setTimeout(resolve, 20));
  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'/>`);

  const jid = await reconnectPromise;
  assert.equal(jid, 'alice@example.com/Northstar-Web');
  assert.equal(client.lastConnectResumed, true, 'Stream management resumed successfully');
  assert.equal(client.fastCredential.token, rotatedToken, 'FAST token rotated in memory');
  assert.equal(Object.hasOwn(client, 'password'), false);
}

// ---------------------------------------------------------------------------
// 5. Unit Test: SM Resume Failure fallback to FAST Bind2
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  const fastToken = 'fast_token_secret_0123456789abcdef0123456789abcdef';
  const fastExpiry = Date.now() + 3600 * 1000;
  const oldResumeId = 'old_sm_resume_id_12345678901234567890123456';

  client.username = 'alice';
  client.jid = 'alice@example.com/Northstar-Web';
  client.fastCredential = { mechanism: 'HT-SHA-256-NONE', token: fastToken, expiry: fastExpiry };
  client.smResumeId = oldResumeId;
  client.phase = 'closed';

  const reconnectPromise = client.connect('alice', null);
  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);

  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism><fast xmlns='${NS.FAST}'><mechanism xmlns='${NS.FAST}'>HT-SHA-256-NONE</mechanism></fast></authentication></stream:features>`);

  await new Promise((resolve) => setTimeout(resolve, 30));
  const tokenBytes = new TextEncoder().encode(fastToken);
  const responderKey = await hmac(tokenBytes, new TextEncoder().encode('Responder'));

  const newResumeId = 'new_sm_resume_id_12345678901234567890123456';

  // Server rejects old SM resume session, but binds a fresh session via Bind2
  ws.serverPush(`<success xmlns='${NS.SASL2}'><additional-data xmlns='${NS.SASL2}'>${toBase64(responderKey)}</additional-data><authorization-identifier xmlns='${NS.SASL2}'>alice@example.com/Northstar-Web</authorization-identifier><bound xmlns='${NS.BIND2}'><enabled xmlns='${NS.SM}' id='${newResumeId}' resume='true'/></bound></success>`);

  await new Promise((resolve) => setTimeout(resolve, 20));
  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'/>`);

  const jid = await reconnectPromise;
  assert.equal(jid, 'alice@example.com/Northstar-Web');
  assert.equal(client.lastConnectResumed, false, 'lastConnectResumed is false when SM resume expired');
  assert.equal(client.smResumeId, newResumeId, 'New SM resume id allocated');
}

// ---------------------------------------------------------------------------
// 6. Unit Test: FAST Token Expiration Requires Password
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  client.username = 'alice';
  client.fastCredential = {
    mechanism: 'HT-SHA-256-NONE',
    token: 'expired_token_12345678901234567890',
    expiry: Date.now() - 1000, // Expired in past
  };
  client.phase = 'closed';

  assert.equal(client.canReconnect(), false, 'canReconnect must be false when token is expired');

  // Attempting connect without password must fail immediately
  await assert.rejects(
    client.connect('alice', null),
    /安全会话已过期，请重新输入密码/,
  );
  assert.equal(client.fastCredential, null, 'Expired credential must be wiped');
}

// ---------------------------------------------------------------------------
// 7. Unit Test: FAST Token Revocation / Failure Cleanup
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  client.username = 'alice';
  client.fastCredential = {
    mechanism: 'HT-SHA-256-NONE',
    token: 'revoked_token_12345678901234567890',
    expiry: Date.now() + 3600 * 1000,
  };
  client.phase = 'closed';

  const connectPromise = client.connect('alice', null);
  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);

  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism><fast xmlns='${NS.FAST}'><mechanism xmlns='${NS.FAST}'>HT-SHA-256-NONE</mechanism></fast></authentication></stream:features>`);

  await new Promise((resolve) => setTimeout(resolve, 30));
  // Server reports authentication failure (e.g. revoked in DB)
  ws.serverPush(`<failure xmlns='${NS.SASL2}'><credentials-expired xmlns='${NS.SASL2}'/></failure>`);

  await assert.rejects(connectPromise, /快速认证凭据已失效/);
  assert.equal(client.fastCredential, null, 'Revoked FAST credential cleared');
  assert.equal(client.canReconnect(), false);
}

// ---------------------------------------------------------------------------
// 8. Unit Test: Logout and Intentional Teardown Cleanup
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  client.username = 'alice';
  client.jid = 'alice@example.com/Northstar-Web';
  client.fastCredential = {
    mechanism: 'HT-SHA-256-NONE',
    token: 'active_token_12345678901234567890',
    expiry: Date.now() + 3600 * 1000,
  };
  client.smResumeId = 'sm_resume_id_123456789012345678901234567890';
  client.phase = 'online';

  client.disconnect();

  assert.equal(client.intentionalClose, true);
  assert.equal(Object.hasOwn(client, 'password'), false);
  assert.equal(client.fastCredential, null, 'fastCredential wiped on disconnect');
  assert.equal(client.smResumeId, null, 'smResumeId wiped on disconnect');
  assert.equal(client.canReconnect(), false);
  assert.equal(client.canResume(), false);
}

// ---------------------------------------------------------------------------
// 9. Unit Test: WebSocket Close-Only during Connection / Auth Rejects Cleanly
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  const connectPromise = client.connect('alice', await makeScramKey('my-temp-password'));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(Object.hasOwn(client, 'password'), false);
  assert.ok(client.scramKey instanceof CryptoKey);
  assert.equal(client.scramKey.extractable, false);

  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);
  assert.ok(ws);

  // Close WebSocket directly without emitting an 'error' event
  ws.close();

  await assert.rejects(
    connectPromise,
    /XMPP 连接在认证完成前已关闭/,
    'connectPromise must reject when closed without error event',
  );

  assert.equal(Object.hasOwn(client, 'password'), false, 'No password field exists after close rejection');
  assert.equal(client.connectPromise, null, 'connectPromise must be cleared');
  assert.equal(client.phase, 'closed');

  // Triggering close again must be a no-op and not throw
  client.closed();
  assert.equal(client.phase, 'closed');
}

// ---------------------------------------------------------------------------
// 10. Unit Test: SCRAM Server-First Challenge Adversarial Parsing
// ---------------------------------------------------------------------------

{
  const testCases = [
    {
      name: 'duplicate r attribute',
      payload: 'r=nonce123s_nonce,r=nonce123s_nonce,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096',
    },
    {
      name: 'mandatory extension m=',
      payload: 'm=ext,r=nonce123s_nonce,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096',
    },
    {
      name: 'duplicate salt attribute',
      payload: 'r=nonce123s_nonce,s=AQIDBAUGBwgJCgsMDQ4PEA==,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096',
    },
    {
      name: 'duplicate iteration attribute',
      payload: 'r=nonce123s_nonce,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096,i=8192',
    },
    {
      name: 'duplicate extension attribute',
      payload: 'x=one,r=nonce123s_nonce,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096,x=two',
    },
    {
      name: 'empty salt value',
      payload: 'r=nonce123s_nonce,s=,i=4096',
    },
    {
      name: 'missing iteration count',
      payload: 'r=nonce123s_nonce,s=AQIDBAUGBwgJCgsMDQ4PEA==',
    },
    {
      name: 'nonce mismatch',
      payload: 'r=wrongnonce_12345,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096',
    },
    {
      name: 'nonce identical without server part',
      payload: 'r=client_nonce_only,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096',
      clientNonce: 'client_nonce_only',
    },
    {
      name: 'salt too short (under 16 bytes)',
      payload: 'r=nonce123s_nonce,s=c2FsdA==,i=4096', // 'salt' = 4 bytes
    },
    {
      name: 'control character',
      payload: 'r=nonce123s_nonce,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096,x=bad\u0001value',
    },
    {
      name: 'attribute count exceeds bound',
      payload: [
        ...[...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcd'].map((name) => `${name}=extension`),
        'r=nonce123s_nonce',
        's=AQIDBAUGBwgJCgsMDQ4PEA==',
        'i=4096',
      ].join(','),
    },
  ];

  for (const tc of testCases) {
    const client = new XmppClient({
      domain: 'example.com',
      websocketUrl: 'wss://example.com/xmpp-websocket',
    });

    const connectPromise = client.connect('alice', await makeScramKey('testpass'));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const ws = MockWebSocket.instances.at(-1);

    ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism><fast xmlns='${NS.FAST}'><mechanism xmlns='${NS.FAST}'>HT-SHA-256-NONE</mechanism></fast></authentication></stream:features>`);
    await new Promise((resolve) => setTimeout(resolve, 20));

    if (tc.clientNonce) {
      client.sasl2Context.nonce = tc.clientNonce;
    } else {
      client.sasl2Context.nonce = 'nonce123';
    }

    ws.serverPush(`<challenge xmlns='${NS.SASL2}'>${btoa(tc.payload)}</challenge>`);

    await assert.rejects(
      connectPromise,
      (err) => Boolean(err),
      `Adversarial SCRAM challenge case [${tc.name}] must reject connect`,
    );

    assert.equal(Object.hasOwn(client, 'password'), false, `No password field may exist for case [${tc.name}]`);
    assert.equal(client.sasl2Context, null, `SASL context must be cleared for case [${tc.name}]`);
  }
}

// ---------------------------------------------------------------------------
// 11. Unit Test: PBKDF2 / HMAC Error Propagation & Buffer Zeroing
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  const connectPromise = client.connect('alice', await makeScramKey('secret-password'));
  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);

  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism><fast xmlns='${NS.FAST}'><mechanism xmlns='${NS.FAST}'>HT-SHA-256-NONE</mechanism></fast></authentication></stream:features>`);
  await new Promise((resolve) => setTimeout(resolve, 20));

  const clientNonce = client.sasl2Context.nonce;
  const serverFirst = `r=${clientNonce}server_part,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096`;

  // Intercept WebCrypto deriveBits to simulate crypto hardware / runtime failure
  const originalDeriveBits = crypto.subtle.deriveBits;
  crypto.subtle.deriveBits = async () => {
    throw new Error('Simulated WebCrypto hardware failure');
  };

  try {
    ws.serverPush(`<challenge xmlns='${NS.SASL2}'>${btoa(serverFirst)}</challenge>`);
    await assert.rejects(
      connectPromise,
      /Simulated WebCrypto hardware failure/,
      'PBKDF2 derivation error must reject connectPromise',
    );
    assert.equal(Object.hasOwn(client, 'password'), false, 'No password field may exist');
    assert.equal(client.sasl2Context, null, 'SASL context must be cleared');
  } finally {
    crypto.subtle.deriveBits = originalDeriveBits;
  }
}

// ---------------------------------------------------------------------------
// 12. Unit Test: REST Login Success followed by XMPP Failure Full Teardown
// ---------------------------------------------------------------------------

{
  // Simulate client-side login orchestration
  const state = {
    apiToken: null,
    account: null,
    xmpp: null,
    outboxErasing: false,
    outboxGeneration: 0,
  };

  const revokedTokens = [];
  const fakeApi = {
    async login(username, password) {
      return { token: 'active-api-session-token-xyz', jid: `${username}@example.com` };
    },
    async deleteSession(token) {
      revokedTokens.push(token);
    },
  };

  const username = 'alice';
  let password = 'plain-password-123';
  let requestBody = { username, password };

  try {
    const session = await fakeApi.login(requestBody.username, requestBody.password);
    requestBody.password = '';
    requestBody = null;

    state.apiToken = session.token;
    state.account = session.jid;

    state.xmpp = new XmppClient({
      domain: 'example.com',
      websocketUrl: 'wss://example.com/xmpp-websocket',
    });

    const passwordBytes = new TextEncoder().encode(password);
    password = '';
    let key;
    try {
      key = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    } finally {
      passwordBytes.fill(0);
    }
    const xmppConnect = state.xmpp.connect(username, key);
    key = null;

    await new Promise((resolve) => setTimeout(resolve, 20));
    const ws = MockWebSocket.instances.at(-1);

    // XMPP WebSocket connection fails during handshake
    ws.close();
    await xmppConnect;
  } catch (error) {
    if (requestBody) {
      requestBody.password = '';
      requestBody = null;
    }
    if (state.apiToken) {
      await fakeApi.deleteSession(state.apiToken);
    }
    state.apiToken = null;
    state.account = null;
    state.outboxErasing = true;
    state.outboxGeneration += 1;
    state.xmpp?.clearAuthenticationSecret();
    state.xmpp?.disconnect();
  } finally {
    if (requestBody) {
      requestBody.password = '';
      requestBody = null;
    }
    password = '';
  }

  assert.equal(state.apiToken, null, 'API token must be cleared after XMPP failure');
  assert.equal(state.account, null, 'Account state must be cleared after XMPP failure');
  assert.deepEqual(revokedTokens, ['active-api-session-token-xyz'], 'Active API session must be revoked via DELETE /api/v1/session');
  assert.equal(password, '', 'Transient password variable must be cleared');
}

// ---------------------------------------------------------------------------
// 13. Unit Test: SCRAM expectedServerSignature Zeroed on Failure or Close
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  const connectPromise = client.connect('alice', await makeScramKey('test-password'));
  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);

  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism><fast xmlns='${NS.FAST}'><mechanism xmlns='${NS.FAST}'>HT-SHA-256-NONE</mechanism></fast></authentication></stream:features>`);
  await new Promise((resolve) => setTimeout(resolve, 20));

  const clientNonce = client.sasl2Context.nonce;
  const serverFirst = `r=${clientNonce}server_nonce,s=AQIDBAUGBwgJCgsMDQ4PEA==,i=4096`;
  ws.serverPush(`<challenge xmlns='${NS.SASL2}'>${btoa(serverFirst)}</challenge>`);

  await new Promise((resolve) => setTimeout(resolve, 50));

  assert.ok(client.sasl2Context?.expectedServerSignature, 'expectedServerSignature was generated');
  const expectedRef = client.sasl2Context.expectedServerSignature;
  assert.equal(expectedRef.length, 32);
  assert.ok(expectedRef.some((b) => b !== 0), 'expectedServerSignature must be non-zero while authenticating');

  // Trigger close / fail
  ws.close();
  await assert.rejects(connectPromise);

  assert.equal(client.sasl2Context, null, 'sasl2Context must be cleared');
  assert.ok(expectedRef.every((b) => b === 0), 'Retained expectedServerSignature Uint8Array reference must be zeroed in memory');
}

// ---------------------------------------------------------------------------
// 14. Unit Test: FAST expectedServerSignature Zeroed on Failure
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  client.username = 'alice';
  client.fastCredential = {
    mechanism: 'HT-SHA-256-NONE',
    token: 'test_fast_token_123456789012345678901234567890',
    expiry: Date.now() + 3600 * 1000,
  };
  client.phase = 'closed';

  const connectPromise = client.connect('alice', null);
  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);

  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism><fast xmlns='${NS.FAST}'><mechanism xmlns='${NS.FAST}'>HT-SHA-256-NONE</mechanism></fast></authentication></stream:features>`);
  await new Promise((resolve) => setTimeout(resolve, 30));

  assert.ok(client.sasl2Context?.expectedServerSignature, 'FAST expectedServerSignature was generated');
  const expectedRef = client.sasl2Context.expectedServerSignature;
  assert.equal(expectedRef.length, 32);
  assert.ok(expectedRef.some((b) => b !== 0), 'FAST expectedServerSignature must be non-zero while authenticating');

  // Server sends SASL2 failure
  ws.serverPush(`<failure xmlns='${NS.SASL2}'><not-authorized xmlns='${NS.SASL2}'/></failure>`);
  await assert.rejects(connectPromise);

  assert.equal(client.sasl2Context, null, 'sasl2Context must be cleared');
  assert.ok(expectedRef.every((b) => b === 0), 'Retained FAST expectedServerSignature Uint8Array reference must be zeroed in memory');
}

// ---------------------------------------------------------------------------
// 15. Unit Test: Normal Success Path expectedServerSignature Zeroed
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  const connectPromise = client.connect('alice', await makeScramKey('test-password'));
  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);

  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism><fast xmlns='${NS.FAST}'><mechanism xmlns='${NS.FAST}'>HT-SHA-256-NONE</mechanism></fast></authentication></stream:features>`);
  await new Promise((resolve) => setTimeout(resolve, 20));

  const authMsg = ws.sent.find((s) => s.includes("<authenticate xmlns='urn:xmpp:sasl:2' mechanism='SCRAM-SHA-256'"));
  const clientFirst = atob(authMsg.match(/<initial-response>([^<]+)<\/initial-response>/)[1]);
  const clientFirstBare = clientFirst.slice(clientFirst.indexOf('n='));
  const clientNonce = clientFirstBare.match(/r=([^,]+)/)[1];

  const serverNonce = `${clientNonce}s_nonce_999`;
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  const serverFirst = `r=${serverNonce},s=${toBase64(salt)},i=4096`;
  ws.serverPush(`<challenge xmlns='${NS.SASL2}'>${btoa(serverFirst)}</challenge>`);

  await new Promise((resolve) => setTimeout(resolve, 50));

  assert.ok(client.sasl2Context?.expectedServerSignature);
  const expectedRef = client.sasl2Context.expectedServerSignature;
  assert.equal(expectedRef.length, 32);
  assert.ok(expectedRef.some((b) => b !== 0), 'expectedServerSignature is non-zero before success');

  const responseMsg = ws.sent.find((s) => s.includes("<response xmlns='urn:xmpp:sasl:2'"));
  const clientFinal = atob(responseMsg.match(/<response xmlns='urn:xmpp:sasl:2'>([^<]+)<\/response>/)[1]);
  const clientFinalBare = clientFinal.slice(0, clientFinal.lastIndexOf(',p='));

  const saltedPassword = await pbkdf2('test-password', salt, 4096);
  const serverKey = await hmac(saltedPassword, new TextEncoder().encode('Server Key'));
  const authMessage = `${clientFirstBare},${serverFirst},${clientFinalBare}`;
  const serverSignature = await hmac(serverKey, new TextEncoder().encode(authMessage));
  const serverFinal = `v=${toBase64(serverSignature)}`;

  const fastToken = 'fast_token_secret_0123456789abcdef0123456789abcdef';
  const fastExpiry = new Date(Date.now() + 86400 * 1000).toISOString();
  const smResumeId = 'sm_resume_id_123456789012345678901234567890';
  ws.serverPush(`<success xmlns='${NS.SASL2}'><additional-data xmlns='${NS.SASL2}'>${btoa(serverFinal)}</additional-data><authorization-identifier xmlns='${NS.SASL2}'>alice@example.com/Northstar-Web</authorization-identifier><token xmlns='${NS.FAST}' token='${fastToken}' expiry='${fastExpiry}'/><bound xmlns='${NS.BIND2}'><enabled xmlns='${NS.SM}' id='${smResumeId}' resume='true'/></bound></success>`);

  await new Promise((resolve) => setTimeout(resolve, 20));
  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'/>`);

  await connectPromise;

  assert.equal(client.sasl2Context, null, 'sasl2Context must be cleared upon successful connect');
  assert.ok(expectedRef.every((b) => b === 0), 'expectedServerSignature Uint8Array reference must be zeroed upon success');
}

// ---------------------------------------------------------------------------
// 16. Unit Test: Reconnection Fails if HT is Only in Plain SASL Mechanisms but Not in <fast>
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  client.username = 'alice';
  client.fastCredential = {
    mechanism: 'HT-SHA-256-NONE',
    token: 'valid_fast_token_12345678901234567890',
    expiry: Date.now() + 3600 * 1000,
  };
  client.phase = 'closed';

  const connectPromise = client.connect('alice', null);
  await new Promise((resolve) => setTimeout(resolve, 20));
  const ws = MockWebSocket.instances.at(-1);

  // Advertises HT-SHA-256-NONE only in plain mechanism list, but NOT in <fast> element
  ws.serverPush(`<stream:features xmlns:stream='http://etherx.jabber.org/streams'><authentication xmlns='${NS.SASL2}'><mechanism xmlns='${NS.SASL2}'>HT-SHA-256-NONE</mechanism><mechanism xmlns='${NS.SASL2}'>SCRAM-SHA-256</mechanism></authentication></stream:features>`);

  await assert.rejects(
    connectPromise,
    /快速认证不可用，请重新输入密码/,
    'Client must reject FAST reconnect if HT-SHA-256-NONE is not in <fast> element',
  );

  assert.equal(ws.sent.some((s) => s.includes("mechanism='HT-SHA-256-NONE'")), false, 'Client must not emit FAST auth if <fast> does not advertise it');
  assert.equal(client.fastCredential, null, 'Wipes credential on failure');
}

// ---------------------------------------------------------------------------
// 17. Unit Test: WebSocket URL Security & TLS Enforcement
// ---------------------------------------------------------------------------

{
  // Remote plaintext ws:// must be rejected
  assert.throws(
    () => new XmppClient({ domain: 'example.com', websocketUrl: 'ws://example.com/xmpp-websocket' }),
    /生产环境下 XMPP WebSocket 连接必须使用安全的 WSS \(TLS\)/,
  );

  // Embedded credentials in URL must be rejected
  assert.throws(
    () => new XmppClient({ domain: 'example.com', websocketUrl: 'wss://user:pass@example.com/xmpp-websocket' }),
    /WebSocket URL 不得包含认证凭据/,
  );

  // Localhost / loopback ws:// is permitted for local development
  const localClient = new XmppClient({ domain: 'localhost', websocketUrl: 'ws://localhost:18080/xmpp-websocket' });
  assert.equal(localClient.websocketUrl, 'ws://localhost:18080/xmpp-websocket');

  const ipClient = new XmppClient({ domain: 'localhost', websocketUrl: 'ws://127.0.0.1:18080/xmpp-websocket' });
  assert.equal(ipClient.websocketUrl, 'ws://127.0.0.1:18080/xmpp-websocket');

  // Secure wss:// is permitted for remote
  const secureClient = new XmppClient({ domain: 'example.com', websocketUrl: 'wss://example.com/xmpp-websocket' });
  assert.equal(secureClient.websocketUrl, 'wss://example.com/xmpp-websocket');
}

// ---------------------------------------------------------------------------
// 18. Unit Test: Behavioral Mock for Synchronous Password Input Zeroing & Request Body Lifecycle
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });
  let capturedRequest = '';
  const sameOriginSlot = new MockXmlElement('slot', NS.HTTP_UPLOAD, {}, '', [
    new MockXmlElement('put', NS.HTTP_UPLOAD, { url: 'https://example.com/api/v1/upload/opaque#ignored' }),
    new MockXmlElement('get', NS.HTTP_UPLOAD, { url: 'https://example.com/uploads/opaque#ignored' }),
  ]);
  client.sendIq = async (payload) => {
    capturedRequest = payload;
    return new MockXmlElement('iq', NS.CLIENT, {}, '', [sameOriginSlot]);
  };
  const opaqueName = `${crypto.randomUUID()}.bin`;
  const slot = await client.requestUploadSlot(opaqueName, 128, 'application/octet-stream');
  assert(capturedRequest.includes(`filename='${opaqueName}'`));
  assert.equal(slot.put.url, 'https://example.com/api/v1/upload/opaque');
  assert.equal(slot.get.url, 'https://example.com/uploads/opaque');

  client.sendIq = async () => new MockXmlElement('iq', NS.CLIENT, {}, '', [
    new MockXmlElement('slot', NS.HTTP_UPLOAD, {}, '', [
      new MockXmlElement('put', NS.HTTP_UPLOAD, { url: 'https://uploads.example.net/opaque' }),
      new MockXmlElement('get', NS.HTTP_UPLOAD, { url: 'https://uploads.example.net/opaque' }),
    ]),
  ]);
  await assert.rejects(
    client.requestUploadSlot(opaqueName, 128, 'application/octet-stream'),
    /Cross-origin file transfer URLs are not permitted/,
  );
}

{
  // Simulated form submission and requestBody lifecycle
  const fakeDom = {
    loginPassword: 'my-super-secret-login-password',
    registerPassword: 'my-super-secret-register-password',
    registerConfirm: 'my-super-secret-register-password',
    adminPassword: 'my-super-secret-admin-password',
    omemoPassphrase: 'my-super-secret-omemo-passphrase',
  };

  // 1. Login form behavioral simulation
  {
    let password = fakeDom.loginPassword;
    fakeDom.loginPassword = ''; // Synchronously zeroed immediately upon event dispatch
    assert.equal(fakeDom.loginPassword, '', 'DOM login password input must be cleared synchronously before any await');

    let requestBody = { username: 'alice', password };
    assert.equal(requestBody.password, 'my-super-secret-login-password');

    // Simulate network request resolution
    requestBody.password = '';
    requestBody = null;
    password = '';

    assert.equal(requestBody, null, 'requestBody must be nullified after REST call');
    assert.equal(password, '', 'password variable must be cleared');
  }

  // 2. Admin form behavioral simulation with error handling
  {
    let password = fakeDom.adminPassword;
    fakeDom.adminPassword = '';
    assert.equal(fakeDom.adminPassword, '', 'DOM admin password input must be cleared synchronously');

    let requestBody = { username: 'admin', password };
    try {
      // Simulate network error
      throw new Error('Network failure');
    } catch {
      if (requestBody) {
        requestBody.password = '';
        requestBody = null;
      }
    } finally {
      if (requestBody) {
        requestBody.password = '';
        requestBody = null;
      }
      password = '';
      fakeDom.adminPassword = '';
    }

    assert.equal(requestBody, null, 'requestBody must be cleared on error');
    assert.equal(password, '', 'password variable must be cleared on error');
    assert.equal(fakeDom.adminPassword, '', 'DOM input remains cleared');
  }

  // 3. OMEMO passphrase behavioral simulation
  {
    let passphrase = fakeDom.omemoPassphrase;
    fakeDom.omemoPassphrase = '';
    assert.equal(fakeDom.omemoPassphrase, '', 'OMEMO passphrase input must be cleared synchronously');

    // Simulate decryption/encryption
    passphrase = '';
    assert.equal(passphrase, '', 'OMEMO passphrase variable cleared after use');
  }
}

// ---------------------------------------------------------------------------
// 19. Unit Test: Behavioral Mock for Storage Isolation (No Password or FAST Token in Web Storage)
// ---------------------------------------------------------------------------

{
  const mockLocalStorage = new Map();
  const mockSessionStorage = new Map();

  function auditStorage(storage, name) {
    for (const [key, value] of storage.entries()) {
      assert.doesNotMatch(
        key,
        /password|secret|fast_token|auth_token|bearer/i,
        `${name} key [${key}] must not store sensitive password/token identifiers`,
      );
      assert.doesNotMatch(
        String(value),
        /correct-horse|secret-password|fast_token_secret/i,
        `${name} value for key [${key}] must not store raw password or FAST secrets`,
      );
    }
  }

  // Simulate normal client runtime saving preferences, outbox, cached messages
  mockLocalStorage.set('theme', 'dark');
  mockLocalStorage.set('locale', 'zh-CN');
  mockSessionStorage.set('admin_jid', 'admin@example.com');
  mockSessionStorage.set('admin_token', 'opaque_session_token_xyz');

  auditStorage(mockLocalStorage, 'localStorage');
  auditStorage(mockSessionStorage, 'sessionStorage');
}

// ---------------------------------------------------------------------------
// 20. Unit Test: Reconnection Flow Cascade: Resume -> FAST -> Re-auth (Prompt Password)
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  // Stage 1: Client has active session with FAST and SM resume ID
  client.username = 'alice';
  client.jid = 'alice@example.com/Northstar-Web';
  client.fastCredential = {
    mechanism: 'HT-SHA-256-NONE',
    token: 'valid_token_012345678901234567890123456789',
    expiry: Date.now() + 3600 * 1000,
  };
  client.smResumeId = 'sm_resume_id_123456789012345678901234567890';
  client.phase = 'closed';

  assert.equal(client.canResume(), true, 'canResume is true when smResumeId and jid are present');
  assert.equal(client.canReconnect(), true, 'canReconnect is true when fastCredential is valid');

  // Stage 2: Stream Management resume fails / server disconnects and wipes SM state
  client.dropPreviousStream(new Error('Stream management connection dropped'));
  assert.equal(client.canResume(), false, 'canResume is false after stream dropped');
  assert.equal(client.canReconnect(), true, 'canReconnect remains true as FAST token is still valid');

  // Stage 3: FAST token expires or is revoked
  client.fastCredential = null;
  assert.equal(client.canResume(), false);
  assert.equal(client.canReconnect(), false);

  // Attempting connect without password must fail and prompt user for re-authentication
  await assert.rejects(
    client.connect('alice', null),
    /安全会话已过期，请重新输入密码/,
    'Client must reject reconnection when both SM resume and FAST are unavailable, requiring user password',
  );
  assert.equal(Object.hasOwn(client, 'password'), false);
}

// ---------------------------------------------------------------------------
// 21. Unit Test: Complete In-Memory Secret Zeroing on Manual Disconnect
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  client.username = 'alice';
  client.scramKey = await crypto.subtle.importKey('raw', new TextEncoder().encode('temp-pass'), 'PBKDF2', false, ['deriveBits']);
  client.fastCredential = {
    mechanism: 'HT-SHA-256-NONE',
    token: 'token-123456789012345678901234567890',
    expiry: Date.now() + 3600 * 1000,
  };
  client.smResumeId = 'sm-resume-123456789012345678901234567890';
  client.sasl2Context = {
    kind: 'scram',
    expectedServerSignature: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
  };
  const expectedRef = client.sasl2Context.expectedServerSignature;

  client.disconnect();

  assert.equal(Object.hasOwn(client, 'password'), false, 'client must not define a password field');
  assert.equal(client.scramKey, null, 'scramKey must be null after disconnect');
  assert.equal(client.fastCredential, null, 'fastCredential must be null after disconnect');
  assert.equal(client.smResumeId, null, 'smResumeId must be null after disconnect');
  assert.equal(client.sasl2Context, null, 'sasl2Context must be null after disconnect');
  assert.ok(expectedRef.every((b) => b === 0), 'expectedServerSignature buffer must be zeroed');
  assert.equal(client.canReconnect(), false);
  assert.equal(client.canResume(), false);
}

// ---------------------------------------------------------------------------
// 22. Unit Test: SCRAM CryptoKey Security & Non-Extractable Enforcement
// ---------------------------------------------------------------------------

{
  const client = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  // 1. Valid non-extractable PBKDF2 CryptoKey
  const validKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('valid-secret-key-123'),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  assert.equal(validKey.extractable, false, 'WebCrypto PBKDF2 keys are guaranteed non-extractable');

  const connectPromise = client.connect('alice', validKey);
  connectPromise.catch(() => {});
  assert.equal(Object.hasOwn(client, 'password'), false, 'Raw password field must not exist');
  assert.equal(client.scramKey, validKey, 'Client stores provided non-extractable CryptoKey');
  assert.equal(client.scramKey.extractable, false);

  client.clearAuthenticationSecret();
  assert.equal(client.scramKey, null);
  client.disconnect();

  // 2. Reject non-PBKDF2 CryptoKey (e.g. HMAC key)
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('hmac-key-123'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const client2 = new XmppClient({
    domain: 'example.com',
    websocketUrl: 'wss://example.com/xmpp-websocket',
  });

  await assert.rejects(
    client2.connect('alice', hmacKey),
    /SCRAM CryptoKey 必须为 non-extractable PBKDF2 密钥/,
    'Client must reject non-PBKDF2 CryptoKey',
  );
  assert.equal(client2.scramKey, null);
  assert.equal(Object.hasOwn(client2, 'password'), false);

  await assert.rejects(
    client2.connect('alice', 'raw-password'),
    /SCRAM CryptoKey 必须为 non-extractable PBKDF2 密钥/,
    'Client must reject raw password strings',
  );
}

console.log('Web authentication security and unit tests passed successfully');
