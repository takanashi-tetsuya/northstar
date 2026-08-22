export const NS = Object.freeze({
  CLIENT: 'jabber:client',
  FRAMING: 'urn:ietf:params:xml:ns:xmpp-framing',
  SASL: 'urn:ietf:params:xml:ns:xmpp-sasl',
  BIND: 'urn:ietf:params:xml:ns:xmpp-bind',
  ROSTER: 'jabber:iq:roster',
  REGISTER: 'jabber:iq:register',
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
  MUC_SENDER: 'urn:northstar:muc:sender:0',
  HTTP_UPLOAD: 'urn:xmpp:http:upload:0',
  AVATAR_DATA: 'urn:xmpp:avatar:data',
  AVATAR_METADATA: 'urn:xmpp:avatar:metadata',
  OMEMO2: 'urn:xmpp:omemo:2',
  OMEMO2_DEVICES: 'urn:xmpp:omemo:2:devices',
  OMEMO2_BUNDLES: 'urn:xmpp:omemo:2:bundles',
});

const parser = new DOMParser();

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

export function descendant(element, name, namespace) {
  return [...(element?.getElementsByTagNameNS(namespace || '*', name) || [])][0] || null;
}

export function randomId(prefix = 'n') {
  return `${prefix}-${crypto.randomUUID()}`;
}

function utf8Base64(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function xmppError(iq) {
  const error = child(iq, 'error');
  const condition = [...(error?.children || [])].find((node) => node.namespaceURI === 'urn:ietf:params:xml:ns:xmpp-stanzas');
  return new Error(condition?.localName || 'XMPP 请求失败');
}

export class XmppClient extends EventTarget {
  constructor({ domain, websocketUrl }) {
    super();
    this.domain = domain;
    this.websocketUrl = websocketUrl;
    this.socket = null;
    this.username = null;
    this.password = null;
    this.jid = null;
    this.resource = null;
    this.phase = 'idle';
    this.pending = new Map();
    this.connectPromise = null;
    this.intentionalClose = false;
  }

  emit(type, detail = {}) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  connect(username, password) {
    if (this.connectPromise) return this.connectPromise;
    this.username = username.toLowerCase();
    this.password = password;
    this.intentionalClose = false;
    this.phase = 'opening';
    this.connectPromise = new Promise((resolve, reject) => {
      this.resolveConnect = resolve;
      this.rejectConnect = reject;
      const socket = new WebSocket(this.websocketUrl, 'xmpp');
      this.socket = socket;
      socket.addEventListener('open', () => this.openStream());
      socket.addEventListener('message', (event) => this.receive(String(event.data)));
      socket.addEventListener('error', () => this.failConnect(new Error('无法连接 XMPP WebSocket')));
      socket.addEventListener('close', () => this.closed());
    });
    return this.connectPromise;
  }

  openStream() {
    this.sendRaw(`<open xmlns='${NS.FRAMING}' to='${xmlEscape(this.domain)}' version='1.0'/>`);
  }

  sendRaw(xml) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN) throw new Error('XMPP 尚未连接');
    this.socket.send(xml);
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
    this.sendRaw(xml);
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
    if (root.localName === 'success' && root.namespaceURI === NS.SASL) {
      this.phase = 'authenticated';
      this.openStream();
      return;
    }
    if (root.localName === 'failure' && root.namespaceURI === NS.SASL) {
      this.failConnect(new Error('用户名或密码错误'));
      return;
    }
    if (root.localName === 'close') {
      this.socket?.close();
      return;
    }
    if (root.localName === 'iq') return this.handleIq(root);
    if (root.localName === 'message') return this.handleMessage(root, text);
    if (root.localName === 'presence') return this.handlePresence(root);
  }

  async handleFeatures() {
    if (this.phase === 'opening') {
      this.phase = 'authenticating';
      const credentials = utf8Base64(`\u0000${this.username}\u0000${this.password}`);
      this.sendRaw(`<auth xmlns='${NS.SASL}' mechanism='PLAIN'>${credentials}</auth>`);
      return;
    }
    if (this.phase !== 'authenticated') return;
    try {
      this.resource = `northstar-${crypto.randomUUID().slice(0, 8)}`;
      const iq = await this.sendIq(`<bind xmlns='${NS.BIND}'><resource>${xmlEscape(this.resource)}</resource></bind>`, { type: 'set' });
      this.jid = descendant(iq, 'jid', NS.BIND)?.textContent || `${this.username}@${this.domain}/${this.resource}`;
      await this.sendIq(`<enable xmlns='${NS.CARBONS}'/>`, { type: 'set' });
      this.phase = 'online';
      this.password = null;
      this.sendRaw(`<presence xmlns='${NS.CLIENT}'><show>chat</show></presence>`);
      this.resolveConnect?.(this.jid);
      this.emit('connected', { jid: this.jid, bareJid: bareJid(this.jid) });
    } catch (error) {
      this.failConnect(error);
    }
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
    const event = child(message, 'event', NS.PUBSUB_EVENT);
    if (event) {
      this.emit('pep-event', { from: bareJid(message.getAttribute('from')), event, raw });
      return;
    }
    const mamResult = child(message, 'result', NS.MAM);
    if (mamResult) {
      const forwarded = child(mamResult, 'forwarded', NS.FORWARD);
      const inner = [...(forwarded?.children || [])].find((node) => node.localName === 'message');
      const delay = child(forwarded, 'delay', NS.DELAY);
      if (inner) this.emit('message', { element: inner, archived: true, timestamp: delay?.getAttribute('stamp') || null, archiveId: mamResult.getAttribute('id') });
      return;
    }
    const carbon = child(message, 'sent', NS.CARBONS) || child(message, 'received', NS.CARBONS);
    if (carbon) {
      const forwarded = child(carbon, 'forwarded', NS.FORWARD);
      const inner = [...(forwarded?.children || [])].find((node) => node.localName === 'message');
      if (inner) this.emit('message', { element: inner, archived: false, timestamp: null, carbon: carbon.localName, raw });
      return;
    }
    this.emit('message', { element: message, archived: false, timestamp: null, raw });
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
      statusCodes: [...(muc?.children || [])]
        .filter((node) => node.localName === 'status')
        .map((node) => node.getAttribute('code')),
    });
  }

  failConnect(error) {
    this.rejectConnect?.(error);
    this.resolveConnect = null;
    this.rejectConnect = null;
    this.emit('connection-error', { error });
    this.socket?.close();
  }

  closed() {
    const wasOnline = this.phase === 'online';
    this.phase = 'closed';
    this.password = null;
    for (const { reject, timer } of this.pending.values()) {
      clearTimeout(timer);
      reject(new Error('XMPP 连接已关闭'));
    }
    this.pending.clear();
    this.connectPromise = null;
    if (wasOnline || !this.intentionalClose) this.emit('disconnected', { intentional: this.intentionalClose });
  }

  disconnect() {
    this.intentionalClose = true;
    try { this.sendRaw(`<presence xmlns='${NS.CLIENT}' type='unavailable'/>`); } catch {}
    try { this.sendRaw(`<close xmlns='${NS.FRAMING}'/>`); } catch {}
    this.socket?.close();
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
    this.sendRaw(`<message xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(to))}' type='chat' id='${xmlEscape(id)}'>${payload}</message>`);
    return id;
  }

  joinRoom(room, nick) {
    this.sendRaw(`<presence xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(room))}/${xmlEscape(nick)}'><x xmlns='${NS.MUC}'/></presence>`);
  }

  leaveRoom(room, nick) {
    this.sendRaw(`<presence xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(room))}/${xmlEscape(nick)}' type='unavailable'/>`);
  }

  sendGroupMessage(room, payload, id = randomId('group')) {
    this.sendRaw(`<message xmlns='${NS.CLIENT}' to='${xmlEscape(bareJid(room))}' type='groupchat' id='${xmlEscape(id)}'>${payload}</message>`);
    return id;
  }

  async requestUploadSlot(filename, size, contentType = 'application/octet-stream') {
    const iq = await this.sendIq(
      `<request xmlns='${NS.HTTP_UPLOAD}' filename='${xmlEscape(filename)}' size='${Number(size)}' content-type='${xmlEscape(contentType)}'/>`,
      { to: `upload.${this.domain}`, timeout: 20000 },
    );
    const slot = child(iq, 'slot', NS.HTTP_UPLOAD);
    const put = child(slot, 'put', NS.HTTP_UPLOAD);
    const get = child(slot, 'get', NS.HTTP_UPLOAD);
    if (!put?.getAttribute('url') || !get?.getAttribute('url')) throw new Error('上传服务返回了无效槽位');
    const headers = {};
    for (const node of [...put.children].filter((item) => item.localName === 'header')) {
      const name = node.getAttribute('name');
      if (name) headers[name] = node.textContent;
    }
    return { put: { url: put.getAttribute('url'), headers }, get: { url: get.getAttribute('url') } };
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
    return this.sendIq(payload, { type: 'set', id: queryId, timeout: 20000 });
  }

  async getPep(owner, node, itemId = null) {
    const item = itemId === null ? '' : `<item id='${xmlEscape(itemId)}'/>`;
    return this.sendIq(`<pubsub xmlns='${NS.PUBSUB}'><items node='${xmlEscape(node)}'>${item}</items></pubsub>`, { to: bareJid(owner) });
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
