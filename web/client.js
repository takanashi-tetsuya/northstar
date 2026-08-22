import { XmppClient, NS, bareJid, child, localpart, randomId, xmlEscape } from './xmpp.js';
import { loadCachedMessages, saveCachedMessage } from './storage.js';
import { initializeI18n, translate } from './i18n.js?v=20260813-6';
import { acquireProof } from './pow.js?v=20260813-1';
import {
  AVATAR_EDITOR_SIZE,
  AvatarCropper,
  MAX_AVATAR_INPUT_BYTES,
  formatAvatarBytes,
} from './avatar-editor.js?v=20260813-1';

initializeI18n();

globalThis.__WASM_BASE__ = new URL('./crypto/', import.meta.url).href;
const { OmemoManager, isOmemoMessage } = await import('./omemo.js');

const $ = (selector) => document.querySelector(selector);
let avatarCropper = null;
let powQueue = Promise.resolve();
const state = {
  config: null,
  xmpp: null,
  omemo: null,
  account: null,
  apiToken: null,
  sessionPassword: null,
  selfProfile: {},
  contacts: new Map(),
  rooms: new Map(),
  presence: new Map(),
  messages: new Map(),
  hydratedPeers: new Set(),
  blocked: new Set(),
  selected: null,
  typingTimer: null,
  composingTimer: null,
  reconnectTimer: null,
  reconnectAttempts: 0,
  intentionalLogout: false,
  pendingMessages: [],
};

function websocketUrl(path) {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${location.host}${path}`;
}

function bytesToBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeAttachment(metadata) {
  return `northstar-file:v1:${bytesToBase64(new TextEncoder().encode(JSON.stringify(metadata)))}`;
}

function decodeAttachment(value) {
  if (!value.startsWith('northstar-file:v1:')) return null;
  try {
    const metadata = JSON.parse(new TextDecoder().decode(base64ToBytes(value.slice(18))));
    const url = new URL(metadata.url, location.origin);
    if (url.origin !== location.origin || !metadata.name || !metadata.key || !metadata.iv) return null;
    return { ...metadata, url: url.href };
  } catch {
    return null;
  }
}

function humanError(error) {
  const value = String(error?.message || error || '未知错误');
  const translations = {
    'not-authorized': '账号认证失败',
    'service-unavailable': '对方当前不可用',
    'remote-server-not-found': '暂不支持这个远程服务器',
    'item-not-found': '没有找到所需的加密资料',
    'feature-not-implemented': '服务器暂不支持这项操作',
    'conflict': '资源冲突，请重试',
  };
  return translate(translations[value] || value);
}

function setBusy(button, busy, label) {
  if (!button) return;
  if (busy) {
    button.dataset.originalLabel = button.textContent;
    button.textContent = label || '请稍候…';
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalLabel || button.textContent;
    button.disabled = false;
  }
}

function showMessage(element, text) {
  element.textContent = text;
  element.classList.toggle('hidden', !text);
}

function toast(message, { type = 'info', action = null } = {}) {
  const node = document.createElement('div');
  node.className = `toast ${type}`;
  const text = document.createElement('span');
  text.textContent = message;
  node.append(text);
  if (action) {
    node.classList.add('actionable');
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = action.label;
    button.addEventListener('click', async () => {
      try { await action.run(); node.remove(); } catch (error) { toast(humanError(error), { type: 'error' }); }
    });
    node.append(button);
  }
  $('#toast-region').append(node);
  if (!action) setTimeout(() => node.remove(), 5000);
}

function setConnection(mode, label) {
  const target = $('#connection-label');
  target.replaceChildren();
  const dot = document.createElement('i');
  dot.className = `presence ${mode}`;
  target.append(dot, label);
}

function paintAvatar(element, entity, fallback = 'N') {
  if (entity?.avatar) {
    element.style.backgroundImage = `url(${entity.avatar})`;
    element.classList.add('image');
    element.textContent = '';
  } else {
    element.style.backgroundImage = '';
    element.classList.remove('image');
    element.textContent = fallback;
  }
}

async function loadAvatar(jid, own) {
  const metadataIq = await state.xmpp.getPep(jid, NS.AVATAR_METADATA);
  const info = [...metadataIq.getElementsByTagName('info')][0];
  const id = info?.getAttribute('id');
  const type = info?.getAttribute('type') || 'image/png';
  if (!id || !type.startsWith('image/')) return;
  const dataIq = await state.xmpp.getPep(jid, NS.AVATAR_DATA, id);
  const data = [...dataIq.getElementsByTagName('data')][0]?.textContent?.trim();
  if (!data || data.length > 512 * 1024) return;
  const avatar = `data:${type};base64,${data}`;
  if (own) {
    state.selfProfile = { avatar };
    paintAvatar($('#self-avatar'), state.selfProfile, localpart(state.account).slice(0, 1) || 'N');
    paintAvatar($('#settings-avatar'), state.selfProfile, localpart(state.account).slice(0, 1) || 'N');
  } else {
    const contact = state.contacts.get(bareJid(jid));
    if (!contact) return;
    contact.avatar = avatar;
    renderConversations();
    if (state.selected === contact.jid) paintAvatar($('#peer-avatar'), contact, initials(contact));
  }
}

async function prepareAvatar(event) {
  const input = event.currentTarget;
  const file = input.files?.[0];
  if (!file) return;
  const supportedExtension = /\.(?:avif|bmp|dib|gif|heic|heif|ico|jfif|jpe?g|png|svg|tiff?|webp)$/i.test(file.name);
  if ((!file.type.startsWith('image/') && !supportedExtension) || file.size > MAX_AVATAR_INPUT_BYTES) {
    toast('请选择不超过 50 MiB 的图片文件', { type: 'error' });
    input.value = '';
    return;
  }
  setBusy($('#avatar-button'), true, '正在读取图片…');
  try {
    const dimensions = await avatarCropper.load(file);
    $('#avatar-zoom').value = '1';
    $('#avatar-zoom-value').textContent = '100%';
    $('#avatar-source-info').textContent = `${file.name} · ${formatAvatarBytes(file.size)} · ${dimensions.width} × ${dimensions.height}`;
    $('#avatar-output-info').textContent = '将输出为标准 JPEG，且小于 256 KiB';
    $('#avatar-editor-error').textContent = '';
    $('#avatar-editor-dialog').showModal();
  } catch (error) {
    toast(humanError(error), { type: 'error' });
  } finally {
    setBusy($('#avatar-button'), false);
    input.value = '';
  }
}

async function publishAvatarBlob(blob, dimension) {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', bytes));
  const id = [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  const type = blob.type || 'image/jpeg';
  const base64 = bytesToBase64(bytes);
  await state.xmpp.publishPep(NS.AVATAR_DATA, id, `<data xmlns='${NS.AVATAR_DATA}'>${base64}</data>`);
  await state.xmpp.publishPep(NS.AVATAR_METADATA, id, `<metadata xmlns='${NS.AVATAR_METADATA}'><info bytes='${blob.size}' height='${dimension}' id='${id}' type='${xmlEscape(type)}' width='${dimension}'/></metadata>`);
  await state.xmpp.setVCard(`<vCard xmlns='vcard-temp'><FN>${xmlEscape(localpart(state.account))}</FN><PHOTO><TYPE>${xmlEscape(type)}</TYPE><BINVAL>${base64}</BINVAL></PHOTO></vCard>`);
  const avatar = `data:${type};base64,${base64}`;
  state.selfProfile = { avatar };
  paintAvatar($('#self-avatar'), state.selfProfile, localpart(state.account).slice(0, 1) || 'N');
  paintAvatar($('#settings-avatar'), state.selfProfile, localpart(state.account).slice(0, 1) || 'N');
}

async function publishProcessedAvatar(event) {
  const button = event.currentTarget;
  $('#avatar-editor-error').textContent = '';
  setBusy(button, true, '正在压缩…');
  try {
    const result = await avatarCropper.exportAvatar();
    $('#avatar-output-info').textContent = `${result.dimension} × ${result.dimension} JPEG · ${formatAvatarBytes(result.blob.size)}`;
    await publishAvatarBlob(result.blob, result.dimension);
    $('#avatar-editor-dialog').close();
    toast('头像已在本地裁切、压缩并发布');
  } catch (error) {
    $('#avatar-editor-error').textContent = humanError(error);
  } finally {
    setBusy(button, false);
  }
}

function bindAvatarEditor() {
  const canvas = $('#avatar-crop-canvas');
  const zoom = $('#avatar-zoom');
  avatarCropper = new AvatarCropper(canvas);
  let pointerId = null;
  let previousX = 0;
  let previousY = 0;

  const updateZoom = (value) => {
    zoom.value = String(Math.min(4, Math.max(1, value)));
    avatarCropper.setZoom(zoom.value);
    $('#avatar-zoom-value').textContent = `${Math.round(Number(zoom.value) * 100)}%`;
  };
  zoom.addEventListener('input', () => updateZoom(Number(zoom.value)));
  canvas.addEventListener('wheel', (event) => {
    event.preventDefault();
    updateZoom(Number(zoom.value) + (event.deltaY < 0 ? .08 : -.08));
  }, { passive: false });
  canvas.addEventListener('pointerdown', (event) => {
    if (!avatarCropper.source) return;
    pointerId = event.pointerId;
    previousX = event.clientX;
    previousY = event.clientY;
    canvas.setPointerCapture(pointerId);
    canvas.classList.add('dragging');
  });
  canvas.addEventListener('pointermove', (event) => {
    if (event.pointerId !== pointerId) return;
    const ratio = AVATAR_EDITOR_SIZE / canvas.getBoundingClientRect().width;
    avatarCropper.moveBy((event.clientX - previousX) * ratio, (event.clientY - previousY) * ratio);
    previousX = event.clientX;
    previousY = event.clientY;
  });
  const endDrag = (event) => {
    if (event.pointerId !== pointerId) return;
    pointerId = null;
    canvas.classList.remove('dragging');
  };
  canvas.addEventListener('pointerup', endDrag);
  canvas.addEventListener('pointercancel', endDrag);
  $('#avatar-rotate-left').addEventListener('click', () => avatarCropper.rotate(-90));
  $('#avatar-rotate-right').addEventListener('click', () => avatarCropper.rotate(90));
  $('#avatar-reset').addEventListener('click', () => {
    avatarCropper.reset();
    updateZoom(1);
  });
  $('#avatar-save').addEventListener('click', publishProcessedAvatar);
  $('#avatar-editor-dialog').addEventListener('close', () => avatarCropper.clear());
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (state.apiToken) headers.set('Authorization', `Bearer ${state.apiToken}`);
  const response = await fetch(path, { ...options, headers, cache: 'no-store' });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) {
    const error = new Error(data?.error?.message || data?.message || text || `请求失败 (${response.status})`);
    error.status = response.status;
    error.details = data?.error?.details;
    throw error;
  }
  return data;
}

function updatePowStatus(selector, event) {
  const element = $(selector);
  if (!element) return;
  let message = '';
  if (event.phase === 'issued') {
    const { requirement } = event;
    message = `防滥用台阶 ${requirement.step} · 工作量 ${Number(requirement.work_factor).toLocaleString()} / 上限 ${Number(requirement.max_work_factor).toLocaleString()} · 冷却每 ${requirement.cooldown_seconds} 秒下降一级`;
  } else if (event.phase === 'waiting') {
    message = `发送过于频繁，硬等待 ${event.remaining} 秒。等待结束后再计算，避免堆积算力。`;
  } else if (event.phase === 'working') {
    const rate = event.elapsedMs > 250 ? Math.round(event.hashes / (event.elapsedMs / 1000)) : 0;
    message = `正在进行工作量证明… ${Number(event.hashes || 0).toLocaleString()} 次${rate ? ` · ${rate.toLocaleString()}/秒` : ''}`;
  } else if (event.phase === 'solved') {
    message = `工作量证明完成，用时 ${(event.elapsedMs / 1000).toFixed(1)} 秒。`;
  }
  element.textContent = translate(message);
  element.classList.toggle('hidden', !message);
}

const powXml = (proof) => proof
  ? `<pow xmlns='urn:northstar:pow:1' challenge='${xmlEscape(proof.challenge_id)}' nonce='${xmlEscape(proof.nonce)}'/>`
  : '';

function queuedProof(action, selector) {
  if (!state.config?.pow_max_work_factor) return Promise.resolve(null);
  const task = powQueue.then(() => acquireProof(request, action, (event) => updatePowStatus(selector, event)));
  powQueue = task.catch(() => {});
  return task;
}

async function initializePage() {
  bindInterface();
  try {
    state.config = await request('/api/v1/config');
    const suffix = `@${state.config.domain}`;
    $('#server-label').textContent = `连接到 ${state.config.domain}`;
    $('#login-domain').textContent = suffix;
    $('#register-domain').textContent = suffix;
    $('#group-domain').textContent = `@conference.${state.config.domain}`;
    if (!state.config.open_registration) {
      $('#register-tab').disabled = true;
      $('#register-tab').title = '服务器已关闭开放注册';
    }
    const antiAbuseAvailable = Boolean(state.config.pow_max_work_factor);
    $('#report-contact-button').classList.toggle('hidden', !antiAbuseAvailable);
    $('#report-history-button').disabled = !antiAbuseAvailable;
    if (!antiAbuseAvailable) $('#report-history-button').title = '服务器更新并重启后启用';
    const invitationField = $('#invitation-field');
    const invitationInput = $('#register-invitation');
    if (state.config.invitation_required) {
      invitationField.firstChild.textContent = '邀请码（必填）';
      invitationInput.required = true;
    }
  } catch (error) {
    showMessage($('#auth-error'), `无法读取服务器配置：${humanError(error)}`);
    $('#login-form button[type="submit"]').disabled = true;
  }
}

function bindInterface() {
  bindAvatarEditor();
  $('#login-tab').addEventListener('click', () => switchAuth('login'));
  $('#register-tab').addEventListener('click', () => switchAuth('register'));
  $('#login-form').addEventListener('submit', login);
  $('#register-form').addEventListener('submit', register);
  document.querySelectorAll('[data-reveal]').forEach((button) => button.addEventListener('click', () => {
    const input = document.getElementById(button.dataset.reveal);
    input.type = input.type === 'password' ? 'text' : 'password';
    button.textContent = input.type === 'password' ? '显示' : '隐藏';
  }));

  for (const button of [$('#add-contact-button'), $('#new-chat-button'), $('#empty-new-chat')]) {
    button.addEventListener('click', () => openContactDialog());
  }
  $('#new-group-button').addEventListener('click', openGroupDialog);
  $('#group-form').addEventListener('submit', joinGroup);
  $('#leave-room-button').addEventListener('click', leaveSelectedRoom);
  $('#contact-form').addEventListener('submit', saveContact);
  document.querySelectorAll('[data-close-dialog]').forEach((button) => button.addEventListener('click', () => {
    document.getElementById(button.dataset.closeDialog)?.close();
  }));
  $('#contact-search').addEventListener('input', renderConversations);
  $('#message-form').addEventListener('submit', sendMessage);
  $('#message-input').addEventListener('input', handleComposerInput);
  $('#message-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      $('#message-form').requestSubmit();
    }
  });
  $('#attachment-button').addEventListener('click', () => $('#attachment-input').click());
  $('#attachment-input').addEventListener('change', sendAttachment);
  $('#mobile-back').addEventListener('click', () => $('#chat-view').classList.remove('conversation-open'));
  $('#dismiss-security').addEventListener('click', () => $('#security-banner').classList.add('hidden'));
  $('#verify-button').addEventListener('click', () => openVerification(false));
  $('#refresh-devices').addEventListener('click', (event) => { event.preventDefault(); openVerification(true); });
  $('#settings-button').addEventListener('click', () => $('#settings-dialog').showModal());
  $('#avatar-button').addEventListener('click', () => $('#avatar-input').click());
  $('#avatar-input').addEventListener('change', prepareAvatar);
  $('#logout-button').addEventListener('click', (event) => { event.preventDefault(); logout(); });
  $('#contact-menu-button').addEventListener('click', openContactActions);
  $('#report-contact-button').addEventListener('click', openReportDialog);
  $('#report-form').addEventListener('submit', submitReport);
  $('#report-history-button').addEventListener('click', openReportHistory);
  $('#report-history-list').addEventListener('click', handleAppealClick);
  $('#toggle-block-button').addEventListener('click', toggleSelectedBlock);
  $('#remove-contact-button').addEventListener('click', removeSelectedContact);
  window.addEventListener('online', () => maybeReconnect());
  window.addEventListener('offline', () => setConnection('offline', '网络已断开'));
  window.addEventListener('beforeunload', () => state.xmpp?.disconnect());
  window.addEventListener('northstar:languagechange', () => {
    renderConversations();
    if (state.selected) {
      updatePeerPresence();
      updateBlockedState();
      renderMessages();
    }
  });
}

function switchAuth(mode) {
  const loginMode = mode === 'login';
  $('#login-tab').classList.toggle('active', loginMode);
  $('#register-tab').classList.toggle('active', !loginMode);
  $('#login-tab').setAttribute('aria-selected', String(loginMode));
  $('#register-tab').setAttribute('aria-selected', String(!loginMode));
  $('#login-form').classList.toggle('hidden', !loginMode);
  $('#register-form').classList.toggle('hidden', loginMode);
  $('#auth-title').textContent = loginMode ? '登录聊天' : '创建账号';
  showMessage($('#auth-error'), '');
  showMessage($('#auth-success'), '');
}

async function register(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const username = $('#register-username').value.trim().toLowerCase();
  const password = $('#register-password').value;
  if (password !== $('#register-confirm').value) {
    showMessage($('#auth-error'), '两次输入的密码不一致');
    return;
  }
  setBusy(button, true, '正在创建…');
  showMessage($('#auth-error'), '');
  try {
    const pow = await queuedProof('registration', '#auth-pow-status');
    await request('/api/v1/register', {
      method: 'POST',
      body: JSON.stringify({
        username,
        password,
        invitation_token: $('#register-invitation').value.trim() || null,
        pow,
      }),
    });
    switchAuth('login');
    $('#login-username').value = username;
    $('#login-password').value = password;
    showMessage($('#auth-success'), '账号已创建，可以立即登录。');
  } catch (error) {
    showMessage($('#auth-error'), humanError(error));
  } finally {
    setBusy(button, false);
    setTimeout(() => showMessage($('#auth-pow-status'), ''), 2500);
  }
}

async function login(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const username = $('#login-username').value.trim().toLowerCase();
  const password = $('#login-password').value;
  setBusy(button, true, '正在建立安全会话…');
  showMessage($('#auth-error'), '');
  state.intentionalLogout = false;
  try {
    const session = await request('/api/v1/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    state.apiToken = session.token;
    state.account = bareJid(session.jid);
    state.sessionPassword = password;
    await connectXmpp(username, password);
    await enterChat();
  } catch (error) {
    state.apiToken = null;
    state.account = null;
    state.sessionPassword = null;
    state.xmpp?.disconnect();
    showMessage($('#auth-error'), humanError(error));
  } finally {
    setBusy(button, false);
  }
}

async function connectXmpp(username, password) {
  const xmpp = new XmppClient({
    domain: state.config.domain,
    websocketUrl: websocketUrl(state.config.websocket_path || '/xmpp-websocket'),
  });
  state.xmpp = xmpp;
  if (state.omemo) state.omemo.xmpp = xmpp;
  bindXmppEvents(xmpp);
  setConnection('away', '正在连接');
  await xmpp.connect(username, password);
  setConnection('online', '在线 · OMEMO 初始化中');
}

function bindXmppEvents(xmpp) {
  xmpp.addEventListener('message', (event) => processMessage(event.detail));
  xmpp.addEventListener('presence', (event) => processPresence(event.detail));
  xmpp.addEventListener('roster-push', (event) => mergeRoster(event.detail.items));
  xmpp.addEventListener('pep-event', (event) => {
    state.omemo?.handlePepEvent(event.detail.from, event.detail.event);
    const avatarItems = child(event.detail.event, 'items', `${NS.PUBSUB}#event`);
    if (avatarItems?.getAttribute('node') === NS.AVATAR_METADATA) loadAvatar(event.detail.from, event.detail.from === state.account).catch(() => {});
    if (event.detail.from === state.selected) refreshSecurity(false);
  });
  xmpp.addEventListener('blocking-change', (event) => {
    if (event.detail.action === 'unblock' && event.detail.jids.length === 0) state.blocked.clear();
    for (const jid of event.detail.jids) {
      if (event.detail.action === 'block') state.blocked.add(jid);
      else state.blocked.delete(jid);
    }
    updateBlockedState();
    renderConversations();
  });
  xmpp.addEventListener('connection-error', (event) => toast(humanError(event.detail.error), { type: 'error' }));
  xmpp.addEventListener('disconnected', () => {
    if (xmpp !== state.xmpp || state.intentionalLogout) return;
    setConnection('offline', '连接已断开');
    scheduleReconnect();
  });
}

async function enterChat() {
  $('#auth-view').classList.add('hidden');
  $('#chat-view').classList.remove('hidden');
  $('#active-conversation').classList.add('hidden');
  $('#empty-state').classList.remove('hidden');
  $('#self-name').textContent = state.account;
  paintAvatar($('#self-avatar'), state.selfProfile, localpart(state.account).slice(0, 1) || 'N');
  paintAvatar($('#settings-avatar'), state.selfProfile, localpart(state.account).slice(0, 1) || 'N');

  const [roster, blocklist] = await Promise.all([
    state.xmpp.getRoster(),
    state.xmpp.getBlocklist(),
    request('/api/v1/me').catch(() => null),
  ]);
  mergeRoster(roster);
  state.blocked = new Set(blocklist);
  state.omemo = new OmemoManager(state.xmpp, state.account);
  const ownDevice = await state.omemo.initialize();
  $('#own-device-id').textContent = ownDevice.id;
  $('#own-fingerprint').textContent = ownDevice.fingerprint;
  setConnection('online', '在线 · OMEMO 已启用');
  loadAvatar(state.account, true).catch(() => {});
  for (const contact of state.contacts.values()) loadAvatar(contact.jid, false).catch(() => {});
  const queuedMessages = state.pendingMessages.splice(0);
  for (const message of queuedMessages) await processMessage(message);
  restoreRooms();
  for (const room of state.rooms.values()) state.xmpp.joinRoom(room.jid, room.nick);
  state.reconnectAttempts = 0;
  renderConversations();
}

function mergeRoster(items) {
  for (const item of items) {
    if (!item.jid) continue;
    if (item.subscription === 'remove') {
      state.contacts.delete(item.jid);
      continue;
    }
    const previous = state.contacts.get(item.jid) || {};
    state.contacts.set(item.jid, { ...previous, ...item, transient: false });
  }
  renderConversations();
  for (const item of items) if (item.jid && item.subscription !== 'remove') loadAvatar(item.jid, false).catch(() => {});
}

function ensureContact(jid, name = '') {
  jid = bareJid(jid);
  if (!jid || jid === state.account) return null;
  if (!state.contacts.has(jid)) state.contacts.set(jid, { jid, name, subscription: 'none', transient: true });
  return state.contacts.get(jid);
}

async function saveContact(event) {
  event.preventDefault();
  const jid = bareJid($('#contact-jid').value.trim());
  const name = $('#contact-name').value.trim();
  if (!jid.includes('@') || jid.split('@')[1] !== state.config.domain) {
    showMessage($('#contact-error'), `请输入 ${state.config.domain} 上的完整 XMPP 地址`);
    return;
  }
  if (jid === state.account) {
    showMessage($('#contact-error'), '不能把自己添加为联系人');
    return;
  }
  setBusy($('#save-contact'), true, '发送中…');
  try {
    await state.xmpp.setRosterItem(jid, name);
    state.xmpp.subscribe(jid);
    ensureContact(jid, name);
    state.contacts.set(jid, { ...state.contacts.get(jid), name, ask: 'subscribe', transient: false });
    $('#contact-dialog').close();
    renderConversations();
    await selectConversation(jid);
    toast('联系人请求已发送');
  } catch (error) {
    showMessage($('#contact-error'), humanError(error));
  } finally {
    setBusy($('#save-contact'), false);
  }
}

function openContactDialog() {
  showMessage($('#contact-error'), '');
  $('#contact-jid').value = '';
  $('#contact-name').value = '';
  $('#contact-dialog').showModal();
  setTimeout(() => $('#contact-jid').focus(), 30);
}

function roomStorageKey() {
  return `northstar:rooms:${state.account}`;
}

function persistRooms() {
  const rooms = [...state.rooms.values()].map(({ jid, name, nick }) => ({ jid, name, nick }));
  localStorage.setItem(roomStorageKey(), JSON.stringify(rooms));
}

function restoreRooms() {
  let rooms = [];
  try { rooms = JSON.parse(localStorage.getItem(roomStorageKey()) || '[]'); } catch {}
  for (const room of Array.isArray(rooms) ? rooms : []) {
    const jid = bareJid(room.jid);
    if (!jid.endsWith(`@conference.${state.config.domain}`) || !room.nick) continue;
    state.rooms.set(jid, { jid, name: room.name || localpart(jid), nick: room.nick, members: new Map(), joined: false, unread: 0, kind: 'group' });
  }
}

function openGroupDialog() {
  showMessage($('#group-error'), '');
  $('#group-room').value = '';
  $('#group-name').value = '';
  $('#group-nick').value = localpart(state.account);
  $('#group-dialog').showModal();
  setTimeout(() => $('#group-room').focus(), 30);
}

async function joinGroup(event) {
  event.preventDefault();
  const local = $('#group-room').value.trim().toLowerCase();
  const name = $('#group-name').value.trim();
  const nick = $('#group-nick').value.trim();
  if (!/^[a-z0-9_.-]{1,64}$/.test(local) || !nick || /[<>&/]/.test(nick)) {
    showMessage($('#group-error'), '房间名称或昵称格式不正确');
    return;
  }
  const jid = `${local}@conference.${state.config.domain}`;
  setBusy($('#join-group-button'), true, '加入中…');
  try {
    const room = state.rooms.get(jid) || { jid, members: new Map(), unread: 0, kind: 'group' };
    Object.assign(room, { name: name || room.name || local, nick, joined: false });
    state.rooms.set(jid, room);
    persistRooms();
    state.xmpp.joinRoom(jid, nick);
    $('#group-dialog').close();
    await selectConversation(jid);
  } catch (error) {
    showMessage($('#group-error'), humanError(error));
  } finally {
    setBusy($('#join-group-button'), false);
  }
}

function openRoomActions(room) {
  $('#room-actions-name').textContent = displayName(room);
  const list = $('#room-member-list');
  list.replaceChildren();
  for (const member of [...room.members.values()].sort((a, b) => a.nick.localeCompare(b.nick, 'zh-CN'))) {
    const card = document.createElement('section');
    card.className = 'member-card';
    const avatar = document.createElement('span');
    avatar.className = 'avatar';
    avatar.textContent = member.nick.slice(0, 1).toUpperCase();
    const copy = document.createElement('span');
    copy.className = 'member-copy';
    const nick = document.createElement('strong');
    nick.textContent = member.nick;
    const jid = document.createElement('span');
    jid.textContent = member.jid || '身份未公开';
    copy.append(nick, jid);
    const role = document.createElement('span');
    role.className = 'member-role';
    role.textContent = member.affiliation === 'owner' ? '房主' : member.role === 'moderator' ? '管理员' : '成员';
    card.append(avatar, copy, role);
    list.append(card);
  }
  if (!room.members.size) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = '尚未收到成员列表。';
    list.append(empty);
  }
  const dialog = $('#room-actions-dialog');
  if (!dialog.open) dialog.showModal();
}

async function leaveSelectedRoom() {
  const room = state.rooms.get(state.selected);
  if (!room) return;
  $('#room-actions-dialog').close();
  if (room.joined) state.xmpp.leaveRoom(room.jid, room.nick);
  state.rooms.delete(room.jid);
  persistRooms();
  state.selected = null;
  $('#active-conversation').classList.add('hidden');
  $('#empty-state').classList.remove('hidden');
  renderConversations();
}

async function removeSelectedContact() {
  if (!state.selected) return;
  const contact = state.contacts.get(state.selected);
  if (contact?.transient) return;
  if (!confirm(`从联系人中移除 ${displayName(contact)}？`)) return;
  try {
    $('#contact-actions-dialog').close();
    await state.xmpp.removeRosterItem(state.selected);
    state.contacts.delete(state.selected);
    state.selected = null;
    $('#active-conversation').classList.add('hidden');
    $('#empty-state').classList.remove('hidden');
    renderConversations();
  } catch (error) {
    toast(humanError(error), { type: 'error' });
  }
}

function openContactActions() {
  if (!state.selected) return;
  const room = state.rooms.get(state.selected);
  if (room) {
    openRoomActions(room);
    return;
  }
  const contact = state.contacts.get(state.selected);
  $('#contact-actions-name').textContent = displayName(contact);
  $('#toggle-block-button').textContent = state.blocked.has(state.selected) ? '解除屏蔽' : '屏蔽联系人';
  $('#remove-contact-button').disabled = Boolean(contact?.transient);
  $('#contact-actions-dialog').showModal();
}

function openReportDialog() {
  if (!state.selected || state.rooms.has(state.selected)) return;
  const messages = (state.messages.get(state.selected) || []).slice(-50).reverse();
  const list = $('#report-message-list');
  list.replaceChildren();
  for (const message of messages) {
    const label = document.createElement('label');
    label.className = 'evidence-item';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = message.id;
    checkbox.dataset.messageId = message.id;
    const copy = document.createElement('span');
    copy.className = 'evidence-copy';
    const metadata = document.createElement('span');
    metadata.textContent = `${message.outgoing ? '我' : displayName(state.contacts.get(state.selected))} · ${new Date(message.timestamp).toLocaleString()}`;
    const body = document.createElement('strong');
    body.dataset.userContent = '';
    body.textContent = message.body;
    copy.append(metadata, body);
    label.append(checkbox, copy);
    list.append(label);
  }
  if (!messages.length) {
    const empty = document.createElement('p');
    empty.className = 'modal-copy';
    empty.textContent = '当前没有可以提交的聊天记录。';
    list.append(empty);
  }
  $('#report-description').value = '';
  showMessage($('#report-error'), '');
  showMessage($('#report-pow-status'), '');
  $('#contact-actions-dialog').close();
  $('#report-dialog').showModal();
}

async function submitReport(event) {
  event.preventDefault();
  const button = $('#submit-report-button');
  const selectedIds = [...$('#report-message-list').querySelectorAll('input:checked')]
    .slice(0, 20)
    .map((input) => input.dataset.messageId);
  if (!selectedIds.length) {
    showMessage($('#report-error'), '请至少选择一条聊天记录。');
    return;
  }
  const messages = state.messages.get(state.selected) || [];
  const selected = selectedIds.map((id) => messages.find((message) => message.id === id)).filter(Boolean);
  setBusy(button, true, '正在计算…');
  showMessage($('#report-error'), '');
  try {
    const pow = await queuedProof('report', '#report-pow-status');
    await request('/api/v1/reports', {
      method: 'POST',
      body: JSON.stringify({
        reported_jid: state.selected,
        category: $('#report-category').value,
        description: $('#report-description').value.trim(),
        evidence: selected.map((message) => ({
          client_message_id: message.id,
          sender_jid: message.senderJid || (message.outgoing ? state.account : state.selected),
          sent_at: message.timestamp,
          body_text: message.body,
          encrypted: Boolean(message.encrypted),
        })),
        pow,
      }),
    });
    $('#report-dialog').close();
    toast('举报已提交，管理人员可以看到你选取的聊天记录。');
  } catch (error) {
    showMessage($('#report-error'), humanError(error));
  } finally {
    setBusy(button, false);
  }
}

const reportStatus = (status) => ({
  submitted: '已提交', reviewing: '处理中', actioned: '已采取措施', rejected: '未支持举报', closed: '已关闭',
  upheld: '申诉成立', denied: '申诉未成立',
})[status] || status;

async function openReportHistory() {
  $('#settings-dialog').close();
  if (!$('#report-history-dialog').open) $('#report-history-dialog').showModal();
  const list = $('#report-history-list');
  list.replaceChildren();
  const loading = document.createElement('p');
  loading.className = 'modal-copy';
  loading.textContent = '正在读取举报记录…';
  list.append(loading);
  showMessage($('#report-history-error'), '');
  try {
    const data = await request('/api/v1/reports');
    renderReportHistory(data.reports || []);
  } catch (error) {
    list.replaceChildren();
    showMessage($('#report-history-error'), humanError(error));
  }
}

function renderReportHistory(reports) {
  const list = $('#report-history-list');
  list.replaceChildren();
  for (const report of reports) {
    const card = document.createElement('section');
    card.className = 'report-card';
    const header = document.createElement('header');
    const title = document.createElement('strong');
    title.textContent = `${report.reported_jid} · ${report.category}`;
    const status = document.createElement('span');
    status.className = 'report-status';
    status.textContent = reportStatus(report.status);
    header.append(title, status);
    const created = document.createElement('p');
    created.textContent = `提交于 ${new Date(report.created_at).toLocaleString()} · ${report.evidence?.length || 0} 条证据`;
    card.append(header, created);
    if (report.resolution) {
      const resolution = document.createElement('p');
      const resolutionValue = document.createElement('span');
      resolutionValue.dataset.userContent = '';
      resolutionValue.textContent = report.resolution;
      resolution.append(document.createTextNode('处理结果：'), resolutionValue);
      card.append(resolution);
    }
    if (report.appeal) {
      const appeal = document.createElement('div');
      appeal.className = 'appeal-box';
      const reason = document.createElement('p');
      const reasonValue = document.createElement('span');
      reasonValue.dataset.userContent = '';
      reasonValue.textContent = report.appeal.reason;
      reason.append(document.createTextNode(`申诉（${reportStatus(report.appeal.status)}）：`), reasonValue);
      appeal.append(reason);
      if (report.appeal.resolution) {
        const result = document.createElement('p');
        const resultValue = document.createElement('span');
        resultValue.dataset.userContent = '';
        resultValue.textContent = report.appeal.resolution;
        result.append(document.createTextNode('申诉结果：'), resultValue);
        appeal.append(result);
      }
      card.append(appeal);
    } else if (['actioned', 'rejected', 'closed'].includes(report.status)) {
      const appeal = document.createElement('div');
      appeal.className = 'appeal-box';
      const textarea = document.createElement('textarea');
      textarea.rows = 3;
      textarea.maxLength = 4000;
      textarea.placeholder = '说明为什么对处理结果不满意（至少 20 个字符）';
      textarea.dataset.appealReason = report.id;
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondary-button';
      button.dataset.appealReport = report.id;
      button.textContent = '计算并提交申诉';
      appeal.append(textarea, button);
      card.append(appeal);
    }
    list.append(card);
  }
  if (!reports.length) {
    const empty = document.createElement('p');
    empty.className = 'modal-copy';
    empty.textContent = '你还没有提交过举报。';
    list.append(empty);
  }
}

async function handleAppealClick(event) {
  const button = event.target.closest('button[data-appeal-report]');
  if (!button) return;
  const reportId = button.dataset.appealReport;
  const reason = $(`textarea[data-appeal-reason="${reportId}"]`).value.trim();
  if (reason.length < 20) {
    showMessage($('#report-history-error'), '申诉理由至少需要 20 个字符。');
    return;
  }
  setBusy(button, true, '正在严格校验…');
  showMessage($('#report-history-error'), '');
  try {
    const pow = await queuedProof('appeal', '#appeal-pow-status');
    await request(`/api/v1/reports/${reportId}/appeals`, {
      method: 'POST',
      body: JSON.stringify({ reason, pow }),
    });
    toast('申诉已提交。');
    await openReportHistory();
  } catch (error) {
    showMessage($('#report-history-error'), humanError(error));
    setBusy(button, false);
  }
}

async function toggleSelectedBlock() {
  if (!state.selected) return;
  const jid = state.selected;
  const blocked = state.blocked.has(jid);
  setBusy($('#toggle-block-button'), true, blocked ? '解除中…' : '屏蔽中…');
  try {
    if (blocked) await state.xmpp.unblock(jid);
    else await state.xmpp.block(jid);
    if (blocked) state.blocked.delete(jid);
    else state.blocked.add(jid);
    $('#contact-actions-dialog').close();
    updateBlockedState();
    toast(blocked ? '已解除屏蔽' : '已屏蔽此联系人');
  } catch (error) {
    toast(humanError(error), { type: 'error' });
  } finally {
    setBusy($('#toggle-block-button'), false);
  }
}

function updateBlockedState() {
  const blocked = state.selected && state.blocked.has(state.selected);
  $('#message-input').disabled = Boolean(blocked);
  $('#send-button').disabled = Boolean(blocked);
  $('#message-input').placeholder = blocked ? '已屏蔽此联系人' : '输入消息';
  if (blocked) {
    $('#composer-mode').textContent = '联系人已屏蔽';
  } else if (state.omemo?.ready) {
    $('#composer-mode').textContent = 'OMEMO 端到端加密';
  }
}

function displayName(contact) {
  return contact?.name || localpart(contact?.jid || '') || contact?.jid || '未知联系人';
}

function initials(contact) {
  return displayName(contact).slice(0, 1).toUpperCase();
}

function lastMessage(jid) {
  const list = state.messages.get(jid) || [];
  return list[list.length - 1] || null;
}

function renderConversations() {
  const navigation = $('#conversation-list');
  const filter = $('#contact-search').value.trim().toLowerCase();
  const contacts = [...state.contacts.values(), ...state.rooms.values()]
    .filter((contact) => !filter || displayName(contact).toLowerCase().includes(filter) || contact.jid.includes(filter))
    .sort((left, right) => {
      const leftTime = lastMessage(left.jid)?.timestamp || '';
      const rightTime = lastMessage(right.jid)?.timestamp || '';
      return rightTime.localeCompare(leftTime) || displayName(left).localeCompare(displayName(right), 'zh-CN');
    });
  navigation.replaceChildren();
  for (const contact of contacts) {
    const message = lastMessage(contact.jid);
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `conversation-item${contact.kind === 'group' ? ' group' : ''}${contact.jid === state.selected ? ' active' : ''}`;
    button.dataset.jid = contact.jid;
    const avatar = document.createElement('span');
    avatar.className = 'avatar';
    paintAvatar(avatar, contact.kind === 'group' ? null : contact, contact.kind === 'group' ? '#' : initials(contact));
    const main = document.createElement('span');
    main.className = 'conversation-main';
    const line = document.createElement('span');
    line.className = 'conversation-line';
    const name = document.createElement('strong');
    name.textContent = displayName(contact);
    const time = document.createElement('time');
    time.textContent = message ? compactTime(message.timestamp) : '';
    line.append(name, time);
    const preview = document.createElement('span');
    preview.className = 'conversation-preview';
    if (message?.encrypted) {
      const lock = document.createElement('span');
      lock.className = 'mini-lock';
      lock.textContent = '◇';
      preview.append(lock);
    }
    const previewText = document.createElement('span');
    previewText.textContent = message?.body || (contact.kind === 'group' ? translate(`群聊 · ${contact.members.size} 人在线`) : contact.ask ? translate('联系人请求已发送') : contact.jid);
    preview.append(previewText);
    main.append(line, preview);
    button.append(avatar, main);
    if (contact.unread) {
      const badge = document.createElement('span');
      badge.className = 'unread-badge';
      badge.textContent = contact.unread > 9 ? '9+' : String(contact.unread);
      button.append(badge);
    }
    button.addEventListener('click', () => selectConversation(contact.jid));
    navigation.append(button);
  }
}

async function selectConversation(jid) {
  jid = bareJid(jid);
  const room = state.rooms.get(jid);
  const contact = room || ensureContact(jid);
  if (!contact) return;
  state.selected = jid;
  contact.unread = 0;
  $('#chat-view').classList.add('conversation-open');
  $('#empty-state').classList.add('hidden');
  $('#active-conversation').classList.remove('hidden');
  $('#peer-name').textContent = displayName(contact);
  paintAvatar($('#peer-avatar'), room ? null : contact, room ? '#' : initials(contact));
  updatePeerPresence();
  updateBlockedState();
  renderConversations();
  if (!state.hydratedPeers.has(jid)) {
    state.hydratedPeers.add(jid);
    const cached = await loadCachedMessages(state.account, jid);
    const current = state.messages.get(jid) || [];
    const merged = new Map(cached.map((message) => [message.id, message]));
    for (const message of current) merged.set(message.id, message);
    state.messages.set(jid, [...merged.values()].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)));
    renderMessages();
    if (!room) state.xmpp.queryMam(jid, 100).catch((error) => toast(`历史记录读取失败：${humanError(error)}`, { type: 'error' }));
  } else {
    renderMessages();
  }
  if (room && !room.joined) state.xmpp.joinRoom(room.jid, room.nick);
  refreshSecurity(false);
  $('#message-input').focus();
}

function updatePeerPresence() {
  if (!state.selected) return;
  const room = state.rooms.get(state.selected);
  if (room) {
    const status = $('#peer-status');
    status.dataset.memberCount = String(room.members.size);
    status.dataset.joined = String(room.joined);
    status.replaceChildren();
    const dot = document.createElement('i');
    dot.className = `presence ${room.joined ? 'online' : 'away'}`;
    status.append(dot, room.joined ? `${room.members.size} 人在线` : '正在加入群聊');
    return;
  }
  const presence = state.presence.get(state.selected) || { type: 'unavailable', show: 'offline' };
  const status = $('#peer-status');
  delete status.dataset.memberCount;
  delete status.dataset.joined;
  status.replaceChildren();
  const dot = document.createElement('i');
  const mode = presence.type === 'unavailable' ? 'offline' : presence.show === 'dnd' ? 'busy' : ['away', 'xa'].includes(presence.show) ? 'away' : 'online';
  dot.className = `presence ${mode}`;
  const labels = { offline: '离线', online: '在线', away: '离开', busy: '请勿打扰' };
  status.append(dot, presence.status || labels[mode]);
}

function processPresence(presence) {
  if (presence.muc) {
    const room = state.rooms.get(presence.bareFrom);
    if (!room || !presence.nick) return;
    if (presence.type === 'unavailable') room.members.delete(presence.nick);
    else room.members.set(presence.nick, {
      nick: presence.nick,
      jid: presence.realJid,
      affiliation: presence.affiliation,
      role: presence.role,
    });
    if (presence.statusCodes.includes('110')) room.joined = presence.type !== 'unavailable';
    if (state.selected === room.jid) {
      updatePeerPresence();
      refreshSecurity(false);
      if ($('#room-actions-dialog').open) openRoomActions(room);
    }
    renderConversations();
    return;
  }
  if (!presence.bareFrom || presence.bareFrom === state.account) return;
  if (presence.type === 'subscribe') {
    ensureContact(presence.bareFrom);
    toast(`${presence.bareFrom} 希望添加你为联系人`, {
      action: {
        label: '接受',
        run: async () => {
          await state.xmpp.setRosterItem(presence.bareFrom);
          state.xmpp.approveSubscription(presence.bareFrom);
          state.xmpp.subscribe(presence.bareFrom);
          const contact = ensureContact(presence.bareFrom);
          Object.assign(contact, { subscription: 'from', ask: 'subscribe', transient: false });
          renderConversations();
          toast('联系人请求已接受');
        },
      },
    });
    return;
  }
  if (['subscribed', 'unsubscribe', 'unsubscribed'].includes(presence.type)) return;
  state.presence.set(presence.bareFrom, presence);
  if (state.selected === presence.bareFrom) updatePeerPresence();
}

async function processMessage({ element, archived, timestamp, archiveId }) {
  if (!state.omemo?.ready) {
    state.pendingMessages.push({ element, archived, timestamp, archiveId });
    return;
  }
  const fromFull = element.getAttribute('from') || '';
  const from = bareJid(fromFull);
  const to = bareJid(element.getAttribute('to'));
  const room = element.getAttribute('type') === 'groupchat' ? state.rooms.get(from) : null;
  const senderNick = room && fromFull.includes('/') ? fromFull.slice(fromFull.indexOf('/') + 1) : '';
  const archivedSender = child(element, 'x', NS.MUC_SENDER)?.getAttribute('jid') || '';
  const senderJid = room?.members.get(senderNick)?.jid || bareJid(archivedSender);
  const outgoing = room ? senderJid === state.account || senderNick === room.nick : from === state.account;
  const peer = room ? room.jid : outgoing ? to : from;
  if (!peer || (!room && peer === state.account)) return;

  const chatState = [...element.children].find((node) => node.namespaceURI === NS.CHAT_STATES);
  if (chatState && !archived) {
    showTyping(peer, chatState.localName);
    if (![...element.children].some((node) => node.localName === 'body' || node.localName === 'encrypted')) return;
  }

  const receiptRequest = child(element, 'request', NS.RECEIPTS);
  const id = element.getAttribute('id') || archiveId || randomId('received');
  if (!room && receiptRequest && !outgoing && !archived) {
    state.xmpp.sendMessage(peer, `<received xmlns='${NS.RECEIPTS}' id='${xmlEscape(id)}'/><no-store xmlns='${NS.HINTS}'/>`, randomId('receipt'));
  }
  if (child(element, 'received', NS.RECEIPTS)) return;

  if (!room) ensureContact(peer);
  const list = state.messages.get(peer) || [];
  if (list.some((message) => message.id === id)) return;
  let body = '';
  let encrypted = false;
  let failed = false;
  if (isOmemoMessage(element)) {
    encrypted = true;
    try {
      body = await state.omemo.decrypt(element, room ? senderJid : from);
    } catch (error) {
      body = `[无法解密：${humanError(error)}]`;
      failed = true;
    }
  } else {
    body = child(element, 'body', NS.CLIENT)?.textContent || child(element, 'body')?.textContent || '';
    if (!body && room) {
      const subject = child(element, 'subject', NS.CLIENT)?.textContent || child(element, 'subject')?.textContent;
      if (subject) body = `群主题：${subject}`;
    }
  }
  if (!body) return;
  const attachment = decodeAttachment(body);
  if (attachment) body = `📎 ${attachment.name}`;
  const message = {
    id,
    body,
    encrypted,
    failed,
    outgoing,
    timestamp: timestamp || new Date().toISOString(),
    archived,
    senderNick,
    senderJid: room ? senderJid : outgoing ? state.account : from,
    attachment,
  };
  list.push(message);
  list.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  state.messages.set(peer, list);
  if (!failed) await saveCachedMessage(state.account, peer, message);
  if (state.selected !== peer && !outgoing && !archived) {
    const conversation = room || state.contacts.get(peer);
    conversation.unread = (conversation.unread || 0) + 1;
  }
  if (state.selected === peer) renderMessages();
  renderConversations();
}

async function sendMessage(event) {
  event.preventDefault();
  const input = $('#message-input');
  const body = input.value.trim();
  if (!body || !state.selected || state.blocked.has(state.selected)) return;
  setBusy($('#send-button'), true, '加密中…');
  try {
    const id = randomId('message');
    const room = state.rooms.get(state.selected);
    const recipients = room
      ? [...new Set([...room.members.values()].map((member) => member.jid).filter(Boolean))]
      : [];
    const encrypted = room
      ? await state.omemo.encryptGroup(recipients, body)
      : await state.omemo.encrypt(state.selected, body);
    const proof = await queuedProof('message', '#pow-status');
    if (room) state.xmpp.sendGroupMessage(state.selected, `${encrypted.xml}${powXml(proof)}`, id);
    else state.xmpp.sendMessage(state.selected, `${encrypted.xml}<request xmlns='${NS.RECEIPTS}'/>${powXml(proof)}`, id);
    const message = { id, body, encrypted: true, outgoing: true, failed: false, senderNick: room?.nick || '', senderJid: state.account, timestamp: new Date().toISOString(), archived: false };
    const list = state.messages.get(state.selected) || [];
    list.push(message);
    state.messages.set(state.selected, list);
    await saveCachedMessage(state.account, state.selected, message);
    input.value = '';
    resizeComposer();
    if (!room) state.xmpp.sendChatState(state.selected, 'active');
    renderMessages();
    renderConversations();
    if (encrypted.failures.length) toast(`${encrypted.failures.length} 个其他设备未收到消息`, { type: 'error' });
  } catch (error) {
    toast(`消息没有发送：${humanError(error)}`, { type: 'error' });
  } finally {
    setBusy($('#send-button'), false);
    setTimeout(() => showMessage($('#pow-status'), ''), 2500);
    input.focus();
  }
}

async function sendAttachment(event) {
  const input = event.currentTarget;
  const file = input.files?.[0];
  if (!file || !state.selected) return;
  if (file.size + 16 > state.config.upload_max_bytes) {
    toast(`文件不能超过 ${formatBytes(state.config.upload_max_bytes - 16)}`, { type: 'error' });
    input.value = '';
    return;
  }
  setBusy($('#attachment-button'), true, '加密上传中…');
  try {
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, await file.arrayBuffer()));
    const safeName = `${file.name.replace(/[\\/\x00-\x1f]/g, '_') || 'attachment'}.northstar`;
    const slot = await state.xmpp.requestUploadSlot(safeName, ciphertext.byteLength, 'application/octet-stream');
    const upload = await fetch(slot.put.url, {
      method: 'PUT',
      headers: { ...slot.put.headers, 'Content-Type': 'application/octet-stream' },
      body: ciphertext,
      credentials: 'omit',
    });
    if (!upload.ok) throw new Error(`加密文件上传失败 (${upload.status})`);
    const attachment = {
      url: slot.get.url,
      name: file.name,
      type: file.type || 'application/octet-stream',
      size: file.size,
      key: bytesToBase64(keyBytes),
      iv: bytesToBase64(iv),
    };
    const protectedPayload = encodeAttachment(attachment);
    const room = state.rooms.get(state.selected);
    const recipients = room
      ? [...new Set([...room.members.values()].map((member) => member.jid).filter(Boolean))]
      : [];
    const encrypted = room
      ? await state.omemo.encryptGroup(recipients, protectedPayload)
      : await state.omemo.encrypt(state.selected, protectedPayload);
    const proof = await queuedProof('message', '#pow-status');
    const id = randomId('attachment');
    if (room) state.xmpp.sendGroupMessage(state.selected, `${encrypted.xml}${powXml(proof)}`, id);
    else state.xmpp.sendMessage(state.selected, `${encrypted.xml}<request xmlns='${NS.RECEIPTS}'/>${powXml(proof)}`, id);
    const message = {
      id,
      body: `📎 ${attachment.name}`,
      attachment,
      encrypted: true,
      outgoing: true,
      failed: false,
      senderNick: room?.nick || '',
      senderJid: state.account,
      timestamp: new Date().toISOString(),
      archived: false,
    };
    const list = state.messages.get(state.selected) || [];
    list.push(message);
    state.messages.set(state.selected, list);
    await saveCachedMessage(state.account, state.selected, message);
    renderMessages();
    renderConversations();
    if (encrypted.failures.length) toast(`${encrypted.failures.length} 个设备未收到文件密钥`, { type: 'error' });
  } catch (error) {
    toast(`文件没有发送：${humanError(error)}`, { type: 'error' });
  } finally {
    setBusy($('#attachment-button'), false);
    setTimeout(() => showMessage($('#pow-status'), ''), 2500);
    input.value = '';
  }
}

async function downloadAttachment(attachment, button) {
  setBusy(button, true, '解密中…');
  try {
    const response = await fetch(attachment.url, { credentials: 'omit', cache: 'force-cache' });
    if (!response.ok) throw new Error(`文件下载失败 (${response.status})`);
    const key = await crypto.subtle.importKey('raw', base64ToBytes(attachment.key), 'AES-GCM', false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(attachment.iv) },
      key,
      await response.arrayBuffer(),
    );
    const url = URL.createObjectURL(new Blob([plaintext], { type: attachment.type }));
    const link = document.createElement('a');
    link.href = url;
    link.download = attachment.name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    toast(humanError(error), { type: 'error' });
  } finally {
    setBusy(button, false);
  }
}

function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}

function handleComposerInput() {
  resizeComposer();
  if (!state.selected || state.xmpp?.phase !== 'online') return;
  if (state.rooms.has(state.selected)) return;
  clearTimeout(state.composingTimer);
  state.xmpp.sendChatState(state.selected, 'composing');
  state.composingTimer = setTimeout(() => state.xmpp?.sendChatState(state.selected, 'paused'), 1800);
}

function resizeComposer() {
  const input = $('#message-input');
  input.style.height = 'auto';
  input.style.height = `${Math.min(input.scrollHeight, 160)}px`;
}

function showTyping(peer, mode) {
  if (peer !== state.selected) return;
  const indicator = $('#typing-indicator');
  clearTimeout(state.typingTimer);
  if (mode === 'composing') {
    indicator.textContent = `${displayName(state.contacts.get(peer))} 正在输入…`;
    indicator.classList.remove('hidden');
    state.typingTimer = setTimeout(() => indicator.classList.add('hidden'), 3000);
  } else {
    indicator.classList.add('hidden');
  }
}

function renderMessages() {
  const container = $('#message-list');
  const messages = state.messages.get(state.selected) || [];
  container.replaceChildren();
  let previousDay = '';
  for (const message of messages) {
    const day = new Date(message.timestamp).toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' });
    if (day !== previousDay) {
      const separator = document.createElement('div');
      separator.className = 'day-separator';
      separator.textContent = day;
      container.append(separator);
      previousDay = day;
    }
    const row = document.createElement('article');
    row.className = `message-row ${message.outgoing ? 'outgoing' : 'incoming'}`;
    const block = document.createElement('div');
    block.className = 'message-block';
    if (!message.outgoing && state.rooms.has(state.selected) && message.senderNick) {
      const sender = document.createElement('div');
      sender.className = 'message-sender';
      sender.textContent = message.senderNick;
      block.append(sender);
    }
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    if (message.attachment) {
      const card = document.createElement('div');
      card.className = 'attachment-card';
      const name = document.createElement('strong');
      name.textContent = `📎 ${message.attachment.name}`;
      const details = document.createElement('span');
      details.textContent = `${formatBytes(message.attachment.size)} · ${message.attachment.type}`;
      const download = document.createElement('button');
      download.type = 'button';
      download.className = 'attachment-download';
      download.textContent = '解密并下载';
      download.addEventListener('click', () => downloadAttachment(message.attachment, download));
      card.append(name, details, download);
      bubble.append(card);
    } else {
      bubble.textContent = message.body;
    }
    const meta = document.createElement('div');
    meta.className = 'message-meta';
    const time = document.createElement('time');
    time.textContent = new Date(message.timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    meta.append(time);
    const security = document.createElement('span');
    security.className = message.failed ? 'failed' : message.encrypted ? 'encrypted' : 'failed';
    security.textContent = message.failed ? '解密失败' : message.encrypted ? '◇ 端到端加密' : '未加密';
    meta.append(security);
    block.append(bubble, meta);
    row.append(block);
    container.append(row);
  }
  requestAnimationFrame(() => { container.scrollTop = container.scrollHeight; });
}

function encryptionPeers() {
  const room = state.rooms.get(state.selected);
  if (!room) return state.selected ? [state.selected] : [];
  return [...new Set([...room.members.values()]
    .map((member) => member.jid)
    .filter((jid) => jid && jid !== state.account))];
}

async function inspectConversationDevices(refresh) {
  const peers = encryptionPeers();
  if (!peers.length) throw new Error('群聊中还没有其他成员');
  const groups = await Promise.all(peers.map(async (jid) => {
    const devices = await state.omemo.inspectDevices(jid, refresh);
    return devices.map((device) => ({ ...device, jid }));
  }));
  return groups.flat();
}

async function refreshSecurity(refresh) {
  if (!state.selected || !state.omemo?.ready) return;
  const label = $('#security-label');
  const button = $('#verify-button');
  const composer = $('.composer-security');
  label.textContent = '检查中';
  try {
    const devices = await inspectConversationDevices(refresh);
    const usable = devices.filter((device) => device.fingerprint);
    if (!usable.length) throw new Error('未找到加密设备');
    label.textContent = `${usable.length} 台加密设备`;
    button.classList.remove('warning');
    composer.classList.remove('warning');
    $('#composer-mode').textContent = 'OMEMO 端到端加密';
    $('#security-banner strong').textContent = 'OMEMO 端到端加密已就绪';
    $('#security-banner span:not(.shield)').textContent = `已发现 ${usable.length} 台接收设备；服务器只能保存密文。`;
  } catch (error) {
    label.textContent = '无法加密';
    button.classList.add('warning');
    composer.classList.add('warning');
    $('#composer-mode').textContent = '暂时无法安全发送';
    $('#security-banner strong').textContent = '尚未建立加密会话';
    $('#security-banner span:not(.shield)').textContent = humanError(error);
  }
  if (state.blocked.has(state.selected)) $('#composer-mode').textContent = '联系人已屏蔽';
}

async function openVerification(refresh) {
  if (!state.selected) return;
  const list = $('#fingerprint-list');
  list.replaceChildren();
  const loading = document.createElement('div');
  loading.className = 'fingerprint-card';
  loading.textContent = '正在读取设备…';
  list.append(loading);
  if (!$('#verify-dialog').open) $('#verify-dialog').showModal();
  try {
    const devices = await inspectConversationDevices(refresh);
    list.replaceChildren();
    for (const device of devices) {
      const card = document.createElement('section');
      card.className = 'fingerprint-card';
      const header = document.createElement('header');
      const title = document.createElement('strong');
      title.textContent = `${device.jid} · 设备 ${device.id}`;
      const status = document.createElement('span');
      status.textContent = device.fingerprint
        ? (device.trustState === 'changed'
          ? '身份密钥已变化，已拒绝信任'
          : device.trustState === 'trusted'
            ? '与本地 TOFU 记录一致'
            : '首次使用即信任（TOFU）')
        : '不可用';
      header.append(title, status);
      const code = document.createElement('code');
      code.textContent = device.fingerprint || device.error || '无法读取指纹';
      card.append(header, code);
      list.append(card);
    }
    if (!devices.length) loading.textContent = '对方尚未发布 OMEMO 设备。';
    await refreshSecurity(refresh);
  } catch (error) {
    list.replaceChildren();
    const card = document.createElement('div');
    card.className = 'fingerprint-card';
    card.textContent = humanError(error);
    list.append(card);
  }
}

function compactTime(value) {
  const date = new Date(value);
  const today = new Date();
  if (date.toDateString() === today.toDateString()) return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
  return date.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' });
}

function scheduleReconnect() {
  if (state.intentionalLogout || !state.account || !state.sessionPassword || state.reconnectTimer) return;
  const delay = Math.min(30000, 1000 * 2 ** state.reconnectAttempts);
  state.reconnectAttempts += 1;
  state.reconnectTimer = setTimeout(() => {
    state.reconnectTimer = null;
    maybeReconnect();
  }, delay);
}

async function maybeReconnect() {
  if (state.intentionalLogout || !navigator.onLine || !state.account || !state.sessionPassword || state.xmpp?.phase === 'online') return;
  try {
    setConnection('away', '正在重新连接');
    await connectXmpp(localpart(state.account), state.sessionPassword);
    state.omemo.xmpp = state.xmpp;
    await state.omemo.publishBundle();
    await state.xmpp.getRoster().then(mergeRoster);
    state.blocked = new Set(await state.xmpp.getBlocklist());
    for (const room of state.rooms.values()) {
      room.joined = false;
      room.members.clear();
      state.xmpp.joinRoom(room.jid, room.nick);
    }
    updateBlockedState();
    setConnection('online', '在线 · OMEMO 已启用');
    state.reconnectAttempts = 0;
  } catch {
    scheduleReconnect();
  }
}

function logout() {
  state.intentionalLogout = true;
  clearTimeout(state.reconnectTimer);
  state.xmpp?.disconnect();
  state.apiToken = null;
  state.account = null;
  state.sessionPassword = null;
  state.omemo = null;
  state.contacts.clear();
  state.messages.clear();
  state.hydratedPeers.clear();
  state.blocked.clear();
  state.presence.clear();
  state.selected = null;
  $('#settings-dialog').close();
  if ($('#avatar-editor-dialog').open) $('#avatar-editor-dialog').close();
  $('#active-conversation').classList.add('hidden');
  $('#empty-state').classList.remove('hidden');
  $('#chat-view').classList.add('hidden');
  $('#auth-view').classList.remove('hidden');
  $('#login-password').value = '';
  showMessage($('#auth-success'), '已安全退出；本机 OMEMO 私钥仍保留在此浏览器中。');
}

initializePage();
