import { XmppClient, NS, bareJid, child, localpart, randomId, xmlEscape } from './xmpp.js';
import {
  deleteValue, getValue, loadCachedMessages, saveCachedMessage, setValue,
} from './storage.js';
import { currentLocale, initializeI18n, translate } from './i18n.js?v=20260813-6';
import { acquireProof, httpPowIntent, xmppPowIntent } from './pow.js?v=20260829-1';
import {
  AckSettlementWindow,
  messageErrorDisposition,
  OUTBOX_CAPACITY,
  OUTBOX_MAX_PAYLOAD_BYTES,
  OUTBOX_MAX_SERVER_RETRIES,
  OUTBOX_TTL_MS,
  prepareFreshProofAttempt,
} from './outbox-delivery.js?v=20260829-2';
import {
  AVATAR_EDITOR_SIZE,
  AvatarCropper,
  MAX_AVATAR_INPUT_BYTES,
  formatAvatarBytes,
} from './avatar-editor.js?v=20260826-2';
import {
  newOmemoTransferSecret,
  OMEMO_TRANSFER_MAX_BYTES,
} from './omemo-recovery.mjs';

initializeI18n();

globalThis.__WASM_BASE__ = new URL('./crypto/', import.meta.url).href;
const {
  OmemoManager,
  isOmemoMessage,
  buildEncryptedFileContent,
  validateEncryptedAttachmentUrl,
} = await import('./omemo.js?v=20260829-1');

const $ = (selector) => document.querySelector(selector);
let avatarCropper = null;
let powQueue = Promise.resolve();
const state = {
  config: null,
  xmpp: null,
  omemo: null,
  account: null,
  apiToken: null,
  selfProfile: {},
  contacts: new Map(),
  rooms: new Map(),
  presence: new Map(),
  messages: new Map(),
  hydratedPeers: new Set(),
  blocked: new Set(),
  selected: null,
  typingTimer: null,
  reconnectTimer: null,
  reconnectAttempts: 0,
  intentionalLogout: false,
  pendingMessages: [],
  encryptedOutbox: new Map(),
  outboxWriteChain: Promise.resolve(),
  outboxGeneration: 0,
  outboxAckWindow: new AckSettlementWindow(),
  outboxRetries: new Set(),
  outboxErasing: false,
  securityModes: new Map(),
  omemoTransferId: null,
  omemoTransferGeneration: null,
  omemoTransferPollTimer: null,
  omemoTransferWatchEpoch: 0,
  omemoTransferWatchInFlight: Promise.resolve(),
  omemoRecoveryTransition: false,
  omemoTransferAbortController: null,
  pageLifecycleLocked: false,
  lifecycleCleanup: Promise.resolve(),
};

function websocketUrl(path) {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${scheme}//${location.host}${path}`;
}

function outboxStorageKey() {
  return `encrypted-outbox:${state.account}`;
}

function persistEncryptedOutbox() {
  const account = state.account;
  if (!account) return Promise.resolve();
  const value = [...state.encryptedOutbox.values()];
  state.outboxWriteChain = state.outboxWriteChain
    .catch(() => {})
    .then(() => setValue('preferences', `encrypted-outbox:${account}`, value));
  return state.outboxWriteChain;
}

async function drainEncryptedOutboxWrites() {
  for (;;) {
    const pendingWrites = state.outboxWriteChain;
    await pendingWrites.catch(() => {});
    if (pendingWrites === state.outboxWriteChain) return;
  }
}

async function stageEncryptedOutbound(record) {
  if (state.outboxErasing) throw new Error('Encrypted outbox is being securely erased');
  const generation = state.outboxGeneration;
  if (typeof record?.payload !== 'string' || !record.payload
    || record.payload.length > OUTBOX_MAX_PAYLOAD_BYTES
    || /[^\x00-\x7f]/.test(record.payload)
    || !record.payload.includes(NS.OMEMO2)
    || /<body\b/i.test(record.payload)
    || (record.basePayload !== undefined
      && (typeof record.basePayload !== 'string'
        || !record.basePayload
        || record.basePayload.length > OUTBOX_MAX_PAYLOAD_BYTES
        || /[^\x00-\x7f]/.test(record.basePayload)
        || !record.basePayload.includes(NS.OMEMO2)
        || /<body\b/i.test(record.basePayload)))) {
    throw new Error('Encrypted outbox payload exceeds the safe local/server bound');
  }
  if (state.encryptedOutbox.size >= OUTBOX_CAPACITY && !state.encryptedOutbox.has(record.id)) {
    throw new Error('加密发件箱已满；请等待连接恢复后再发送');
  }
  const previous = state.encryptedOutbox.get(record.id);
  state.encryptedOutbox.set(record.id, {
    ...previous,
    ...record,
    createdAt: previous?.createdAt || record.createdAt || new Date().toISOString(),
  });
  try {
    await persistEncryptedOutbox();
  } catch (error) {
    // A logout/device-erasure fence owns the new generation. Never let an
    // older asynchronous write restore its in-memory record into that session.
    if (generation === state.outboxGeneration) {
      if (previous) state.encryptedOutbox.set(record.id, previous);
      else state.encryptedOutbox.delete(record.id);
    }
    throw error;
  }
}

async function acknowledgeEncryptedOutbound(id) {
  state.outboxAckWindow.forget(id);
  if (!state.encryptedOutbox.delete(id)) return;
  await persistEncryptedOutbox();
}

async function erasePersistentEncryptedOutbox(account) {
  state.outboxErasing = true;
  state.outboxGeneration += 1;
  state.outboxAckWindow.clear();
  state.outboxRetries.clear();
  await drainEncryptedOutboxWrites();
  state.encryptedOutbox.clear();
  await deleteValue('preferences', `encrypted-outbox:${account}`);
  state.outboxWriteChain = Promise.resolve();
}

function settleEncryptedOutbound(id, acknowledgedXml = null) {
  const record = state.encryptedOutbox.get(id);
  if (!record || record.deliveryState !== 'awaiting-ack') return;
  if (acknowledgedXml
    && state.xmpp.buildMessage(record.to, record.payload, record.id, record.type) !== acknowledgedXml) return;
  state.outboxAckWindow.recordAck(id, (settledId) => {
    acknowledgeEncryptedOutbound(settledId)
      .catch((error) => console.error('Failed to clear settled encrypted outbox item', error));
  });
}

async function loadEncryptedOutbox() {
  const records = await getValue('preferences', outboxStorageKey());
  const now = Date.now();
  state.encryptedOutbox = new Map((Array.isArray(records) ? records : [])
    .filter((record) => record
      && typeof record.id === 'string'
      && record.id.length > 0
      && record.id.length <= 128
      && typeof record.to === 'string'
      && record.to.length > 2
      && record.to.length <= 3071
      && record.to.includes('@')
      && ['chat', 'groupchat'].includes(record.type)
      && typeof record.payload === 'string'
      && record.payload.length > 0
      && record.payload.length <= OUTBOX_MAX_PAYLOAD_BYTES
      && !/[^\x00-\x7f]/.test(record.payload)
      && record.payload.includes(`xmlns='${NS.OMEMO2}'`)
      && !/<body\b/i.test(record.payload)
      && typeof record.basePayload === 'string'
      && record.basePayload.length > 0
      && record.basePayload.length <= OUTBOX_MAX_PAYLOAD_BYTES
      && !/[^\x00-\x7f]/.test(record.basePayload)
      && record.basePayload.includes(`xmlns='${NS.OMEMO2}'`)
      && !/<body\b/i.test(record.basePayload)
      && (record.powPending === undefined || typeof record.powPending === 'boolean')
      && (record.deliveryState === undefined
        || ['proof-pending', 'proof-ready', 'awaiting-ack', 'retry-pending', 'terminal'].includes(record.deliveryState))
      && (record.retryCount === undefined
        || (Number.isSafeInteger(record.retryCount)
          && record.retryCount >= 0
          && record.retryCount <= OUTBOX_MAX_SERVER_RETRIES + 1))
      && (record.proofChallengeId === undefined
        || record.proofChallengeId === null
        || (typeof record.proofChallengeId === 'string' && record.proofChallengeId.length <= 64))
      && Number.isFinite(Date.parse(record.createdAt))
      && Date.parse(record.createdAt) <= now + 5 * 60 * 1000)
    .slice(-OUTBOX_CAPACITY)
    .map((record) => [record.id, {
      ...record,
      deliveryState: record.deliveryState || 'retry-pending',
      retryCount: Number(record.retryCount || 0),
    }]));
}

async function replayEncryptedOutbox() {
  const expiry = Date.now() - OUTBOX_TTL_MS;
  let terminalCount = 0;
  for (const record of [...state.encryptedOutbox.values()]) {
    if (Date.parse(record.createdAt) < expiry) {
      state.encryptedOutbox.delete(record.id);
      continue;
    }
    if (record.deliveryState === 'terminal') {
      terminalCount += 1;
      continue;
    }
    if (state.xmpp.isStanzaPending(record.id)) continue;
    await retryEncryptedOutbound(record.id, { automatic: false });
  }
  await persistEncryptedOutbox();
  if (terminalCount) {
    toast(`${terminalCount} 条被服务器永久拒绝的密文仍保留在本机，且不会自动重试。`, { type: 'error' });
  }
}

async function sendDurableEncrypted(record) {
  const pending = { ...record, deliveryState: 'awaiting-ack' };
  await stageEncryptedOutbound(pending);
  state.outboxAckWindow.beginAttempt(record.id);
  if (record.type === 'groupchat') state.xmpp.sendGroupMessage(record.to, record.payload, record.id);
  else state.xmpp.sendMessage(record.to, record.payload, record.id);
  if (!state.xmpp.smEnabled) settleEncryptedOutbound(record.id);
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

async function sha256Base64(value) {
  return bytesToBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', value)));
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

function toast(message, { type = 'info', action = null, code = null } = {}) {
  const node = document.createElement('div');
  node.className = `toast ${type}`;
  if (code) node.dataset.code = code;
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
    const image = document.createElement('img');
    image.src = entity.avatar;
    image.alt = '';
    image.decoding = 'async';
    image.setAttribute('aria-hidden', 'true');
    element.replaceChildren(image);
    element.classList.add('image');
  } else {
    element.replaceChildren(document.createTextNode(fallback));
    element.classList.remove('image');
  }
}

async function loadAvatar(jid, own) {
  const metadataIq = await state.xmpp.getPep(jid, NS.AVATAR_METADATA);
  const infos = [...metadataIq.getElementsByTagName('info')];
  const info = infos.find((candidate) => !candidate.hasAttribute('url') && candidate.getAttribute('type') === 'image/png')
    || infos.find((candidate) => !candidate.hasAttribute('url') && candidate.getAttribute('type')?.startsWith('image/'));
  const id = info?.getAttribute('id');
  const type = info?.getAttribute('type') || 'image/png';
  if (!id || !type.startsWith('image/')) return;
  const dataIq = await state.xmpp.getPep(jid, NS.AVATAR_DATA, id);
  const data = [...dataIq.getElementsByTagName('data')][0]?.textContent?.replace(/\s/g, '');
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
    $('#avatar-output-info').textContent = '将输出为标准 PNG，且小于 256 KiB';
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
  const type = blob.type || 'image/png';
  const base64 = bytesToBase64(bytes);
  await state.xmpp.publishPep(NS.AVATAR_DATA, id, `<data xmlns='${NS.AVATAR_DATA}'>${base64}</data>`);
  await state.xmpp.publishPep(NS.AVATAR_METADATA, id, `<metadata xmlns='${NS.AVATAR_METADATA}'><info bytes='${blob.size}' height='${dimension}' id='${id}' type='${xmlEscape(type)}' width='${dimension}'/></metadata>`);
  // Northstar advertises XEP-0398 and projects the metadata publication to
  // vCard-temp atomically. A second full vCard SET here would erase unrelated
  // profile fields because XEP-0054 updates are whole-document replacements.
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
    $('#avatar-output-info').textContent = `${result.dimension} × ${result.dimension} PNG · ${formatAvatarBytes(result.blob.size)}`;
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

function newClientIdempotencyKey() {
  if (typeof crypto.randomUUID === 'function') return `web-client-${crypto.randomUUID()}`;
  const random = crypto.getRandomValues(new Uint8Array(24));
  return `web-client-${[...random].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

const API_RETRY_DELAYS_MS = [250, 750, 1750];
const API_RETRYABLE_STATUS = new Set([408, 500, 502, 503, 504]);

function apiRetryDelay(response, attempt) {
  const retryAfter = response?.headers?.get('Retry-After');
  if (retryAfter) {
    const seconds = Number(retryAfter);
    const milliseconds = Number.isFinite(seconds)
      ? seconds * 1000
      : Date.parse(retryAfter) - Date.now();
    if (Number.isFinite(milliseconds) && milliseconds >= 0) {
      // Keep automatic recovery bounded. A longer server lease is surfaced to
      // the user rather than leaving an apparently frozen browser request.
      return Math.min(Math.max(milliseconds, 100), 10_000);
    }
  }
  return API_RETRY_DELAYS_MS[attempt] ?? null;
}

function waitForApiRetry(milliseconds, signal) {
  if (signal?.aborted) return Promise.reject(signal.reason || new DOMException('Aborted', 'AbortError'));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, milliseconds);
    signal?.addEventListener('abort', () => {
      clearTimeout(timer);
      reject(signal.reason || new DOMException('Aborted', 'AbortError'));
    }, { once: true });
  });
}

async function request(path, options = {}) {
  const { idempotencyKey, omitAuthorization = false, ...requestOptions } = options;
  const headers = new Headers(requestOptions.headers || {});
  if (requestOptions.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (state.apiToken && !omitAuthorization) headers.set('Authorization', `Bearer ${state.apiToken}`);
  const method = String(requestOptions.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && !headers.has('Idempotency-Key')) {
    headers.set('Idempotency-Key', idempotencyKey || newClientIdempotencyKey());
  }
  // `headers` (including the generated Idempotency-Key) and the serialized
  // body are created once outside the loop. Every uncertain retry therefore
  // represents the exact same mutation to the server.
  for (let attempt = 0; ; attempt += 1) {
    let response;
    try {
      response = await fetch(path, { ...requestOptions, headers, cache: 'no-store' });
    } catch (error) {
      const delay = API_RETRY_DELAYS_MS[attempt];
      if (delay === undefined || requestOptions.signal?.aborted) throw error;
      await waitForApiRetry(delay, requestOptions.signal);
      continue;
    }
    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (response.ok) return data;

    const errorCode = data?.error?.code;
    const retryable = API_RETRYABLE_STATUS.has(response.status)
      || (response.status === 409 && errorCode === 'idempotency_in_progress');
    const delay = retryable ? apiRetryDelay(response, attempt) : null;
    if (delay !== null && attempt < API_RETRY_DELAYS_MS.length && !requestOptions.signal?.aborted) {
      await waitForApiRetry(delay, requestOptions.signal);
      continue;
    }
    const error = new Error(data?.error?.message || data?.message || text || `请求失败 (${response.status})`);
    error.status = response.status;
    error.code = errorCode;
    error.details = data?.error?.details;
    error.retryAfterSeconds = Number(response.headers.get('Retry-After')) || null;
    throw error;
  }
}

function updatePowStatus(selector, event) {
  const element = $(selector);
  if (!element) return;
  let message = '';
  if (event.phase === 'issued') {
    const { requirement } = event;
    message = `防滥用台阶 ${requirement.step} · 工作量 ${Number(requirement.work_factor).toLocaleString(currentLocale())} / 上限 ${Number(requirement.max_work_factor).toLocaleString(currentLocale())} · 冷却每 ${requirement.cooldown_seconds} 秒下降一级`;
  } else if (event.phase === 'waiting') {
    message = `发送过于频繁，硬等待 ${event.remaining} 秒。等待结束后再计算，避免堆积算力。`;
  } else if (event.phase === 'working') {
    const rate = event.elapsedMs > 250 ? Math.round(event.hashes / (event.elapsedMs / 1000)) : 0;
    message = `正在进行工作量证明… ${Number(event.hashes || 0).toLocaleString(currentLocale())} 次${rate ? ` · ${rate.toLocaleString(currentLocale())}/秒` : ''}`;
  } else if (event.phase === 'solved') {
    message = `工作量证明完成，用时 ${(event.elapsedMs / 1000).toFixed(1)} 秒。`;
  }
  element.textContent = translate(message);
  element.classList.toggle('hidden', !message);
}

const powXml = (proof) => proof
  ? `<pow xmlns='urn:northstar:pow:1' challenge='${xmlEscape(proof.challenge_id)}' nonce='${xmlEscape(proof.nonce)}'/>`
  : '';

function queuedProof(action, selector, context = {}) {
  if (!state.config?.pow_max_work_factor) return Promise.resolve(null);
  const task = powQueue.then(() => acquireProof(request, action, (event) => updatePowStatus(selector, event), context));
  powQueue = task.catch(() => {});
  return task;
}

async function queuedHttpProof(action, selector, path, body, identity = {}) {
  const intent = await httpPowIntent(path, body);
  return queuedProof(action, selector, { ...identity, intent });
}

async function queuedMessageProof(to, type, payload, id, selector = '#pow-status') {
  const baseRecord = {
    id, to, type, payload, basePayload: payload, powPending: true, deliveryState: 'proof-pending',
  };
  // Encryption may already have advanced a Double Ratchet (including a first
  // pre-key message). Persist that ciphertext before waiting or computing so
  // a failed/closed challenge cannot strand the session. Replays acquire a
  // fresh proof for these exact bytes and retain the same origin-id.
  await stageEncryptedOutbound(baseRecord);
  const canonicalStanza = state.xmpp.buildMessage(to, payload, id, type);
  const intent = await xmppPowIntent('/xmpp/message', canonicalStanza);
  const proof = await queuedProof('message', selector, { intent });
  await stageEncryptedOutbound({
    ...baseRecord,
    payload: `${payload}${powXml(proof)}`,
    powPending: false,
    proofChallengeId: proof?.challenge_id ? String(proof.challenge_id) : null,
    deliveryState: 'proof-ready',
  });
  return proof;
}

async function retryEncryptedOutbound(id, { automatic = true } = {}) {
  if (state.outboxRetries.has(id)) return;
  const current = state.encryptedOutbox.get(id);
  if (!current || current.deliveryState === 'terminal') return;
  if (Number(current.retryCount || 0) > OUTBOX_MAX_SERVER_RETRIES) return;
  if (!state.xmpp || state.intentionalLogout || state.xmpp.phase !== 'online') return;
  state.outboxRetries.add(id);
  try {
    const attempt = prepareFreshProofAttempt(current);
    await stageEncryptedOutbound(attempt);
    const proof = await queuedMessageProof(
      attempt.to,
      attempt.type,
      attempt.basePayload,
      attempt.id,
    );
    if (state.intentionalLogout || state.outboxErasing) return;
    await sendDurableEncrypted({
      ...attempt,
      payload: `${attempt.basePayload}${powXml(proof)}`,
      powPending: false,
    });
    if (automatic) toast('服务器要求重新验证；已用新的工作量证明重试保留的密文。');
  } catch (error) {
    const retained = state.encryptedOutbox.get(id);
    if (retained && retained.deliveryState !== 'terminal') {
      await stageEncryptedOutbound({
        ...retained,
        payload: retained.basePayload,
        powPending: true,
        deliveryState: 'retry-pending',
      }).catch(() => {});
    }
    console.warn('Deferred encrypted outbox retry until a fresh bound proof is available', error);
    toast(`${automatic ? '' : '重连后仍未能发送：'}密文仍保留在本机；取得新的工作量证明后会重试：${humanError(error)}`, { type: 'error' });
  } finally {
    state.outboxRetries.delete(id);
  }
}

async function handleEncryptedMessageError(detail) {
  const record = state.encryptedOutbox.get(detail.id);
  if (!record || bareJid(detail.from) !== bareJid(record.to)) return;
  if (detail.proofChallengeId && record.proofChallengeId
    && detail.proofChallengeId !== record.proofChallengeId) return;
  state.outboxAckWindow.recordError(detail.id);
  const disposition = messageErrorDisposition(detail, Number(record.retryCount || 0));
  const condition = detail.condition || 'unknown-error';
  const retained = {
    ...record,
    payload: record.basePayload,
    powPending: true,
    retryCount: disposition.retryCount,
    lastError: condition,
    deliveryState: disposition.kind === 'retry' ? 'retry-pending' : 'terminal',
  };
  await stageEncryptedOutbound(retained);
  if (disposition.kind === 'retry') {
    toast(`服务器暂未接受消息（${condition}）；原密文已保留，正在取得新的工作量证明。`, { type: 'error' });
    queueMicrotask(() => retryEncryptedOutbound(detail.id));
    return;
  }
  const reason = disposition.exhausted
    ? `已达到 ${OUTBOX_MAX_SERVER_RETRIES} 次自动重试上限`
    : '该错误不可安全自动重试';
  toast(`服务器拒绝了消息（${condition}）；密文已保留但不会继续自动发送：${reason}。`, { type: 'error' });
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
    const uploadAdmission = Boolean(state.config.capabilities?.upload_admission);
    $('#attachment-button').classList.toggle('hidden', !uploadAdmission);
    $('#attachment-button').disabled = !uploadAdmission;
    $('#attachment-input').disabled = !uploadAdmission;
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
  $('#verify-button').addEventListener('click', handleSecurityButton);
  $('#refresh-devices').addEventListener('click', (event) => { event.preventDefault(); openVerification(true); });
  $('#settings-button').addEventListener('click', () => $('#settings-dialog').showModal());
  $('#avatar-button').addEventListener('click', () => $('#avatar-input').click());
  $('#avatar-input').addEventListener('change', prepareAvatar);
  $('#logout-button').addEventListener('click', (event) => { event.preventDefault(); logout(); });
  $('#forget-omemo-device').addEventListener('click', forgetOmemoDevice);
  $('#export-omemo-device').addEventListener('click', exportOmemoDevice);
  $('#import-omemo-device').addEventListener('click', importOmemoDevice);
  $('#cancel-omemo-transfer').addEventListener('click', cancelPendingOmemoTransfer);
  $('#contact-menu-button').addEventListener('click', openContactActions);
  $('#report-contact-button').addEventListener('click', openReportDialog);
  $('#report-form').addEventListener('submit', submitReport);
  $('#report-history-button').addEventListener('click', openReportHistory);
  $('#report-history-list').addEventListener('click', handleAppealClick);
  $('#toggle-block-button').addEventListener('click', toggleSelectedBlock);
  $('#remove-contact-button').addEventListener('click', removeSelectedContact);
  window.addEventListener('online', () => maybeReconnect());
  window.addEventListener('offline', () => setConnection('offline', '网络已断开'));
  window.addEventListener('pagehide', handlePageHide);
  window.addEventListener('pageshow', handlePageShow);
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
  $('#login-password').value = '';
  $('#register-password').value = '';
  $('#register-confirm').value = '';
  showMessage($('#auth-error'), '');
  showMessage($('#auth-success'), '');
}

async function register(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const username = $('#register-username').value.trim().toLowerCase();
  let password = $('#register-password').value;
  const confirm = $('#register-confirm').value;
  $('#register-password').value = '';
  $('#register-confirm').value = '';
  if (password !== confirm) {
    password = '';
    showMessage($('#auth-error'), '两次输入的密码不一致');
    return;
  }
  setBusy(button, true, '正在创建…');
  showMessage($('#auth-error'), '');
  let requestBody = null;
  try {
    requestBody = {
      username,
      password,
      invitation_token: $('#register-invitation').value.trim() || null,
    };
    const pow = await queuedHttpProof(
      'registration', '#auth-pow-status', '/api/v1/register', requestBody,
    );
    await request('/api/v1/register', {
      method: 'POST',
      body: JSON.stringify({ ...requestBody, pow }),
    });
    requestBody.password = '';
    requestBody = null;
    password = '';
    switchAuth('login');
    $('#login-username').value = username;
    $('#register-password').value = '';
    $('#register-confirm').value = '';
    showMessage($('#auth-success'), '账号已创建，可以立即登录。');
  } catch (error) {
    if (requestBody) {
      requestBody.password = '';
      requestBody = null;
    }
    showMessage($('#auth-error'), humanError(error));
  } finally {
    if (requestBody) {
      requestBody.password = '';
      requestBody = null;
    }
    password = '';
    $('#register-password').value = '';
    $('#register-confirm').value = '';
    setBusy(button, false);
    setTimeout(() => showMessage($('#auth-pow-status'), ''), 2500);
  }
}

async function login(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const username = $('#login-username').value.trim().toLowerCase();
  let password = $('#login-password').value;
  $('#login-password').value = '';
  setBusy(button, true, '正在建立安全会话…');
  showMessage($('#auth-error'), '');
  state.intentionalLogout = false;
  state.pageLifecycleLocked = false;
  let requestBody = null;
  let scramKey = null;
  try {
    await state.lifecycleCleanup.catch(() => {});
    state.lifecycleCleanup = Promise.resolve();
    requestBody = { username, password };
    const pow = await queuedHttpProof(
      'login', '#auth-pow-status', '/api/v1/login', requestBody, { username },
    );
    const session = await request('/api/v1/login', { method: 'POST', body: JSON.stringify({ ...requestBody, pow }) });
    requestBody.password = '';
    requestBody = null;

    let passwordBytes = new TextEncoder().encode(password);
    password = '';
    try {
      scramKey = await crypto.subtle.importKey(
        'raw',
        passwordBytes,
        'PBKDF2',
        false,
        ['deriveBits'],
      );
    } finally {
      passwordBytes.fill(0);
      passwordBytes = null;
    }

    state.apiToken = session.token;
    state.account = bareJid(session.jid);
    await drainEncryptedOutboxWrites();
    state.outboxErasing = false;
    $('#login-password').value = '';
    await connectXmpp(username, scramKey);
    scramKey = null;
    await enterChat();
  } catch (error) {
    if (requestBody) {
      requestBody.password = '';
      requestBody = null;
    }
    scramKey = null;
    const failedOmemo = state.omemo;
    state.omemo = null;
    await failedOmemo?.destroy().catch((destroyError) => {
      console.error('Failed to tear down OMEMO after login initialization failure', destroyError);
    });
    if (state.apiToken) {
      await request('/api/v1/session', { method: 'DELETE' }).catch((logoutError) => {
        console.warn('Failed to revoke API session after login initialization failure', logoutError);
      });
    }
    state.apiToken = null;
    state.outboxErasing = true;
    state.outboxGeneration += 1;
    state.account = null;
    state.xmpp?.clearAuthenticationSecret();
    state.xmpp?.disconnect();
    $('#chat-view').classList.add('hidden');
    $('#auth-view').classList.remove('hidden');
    showMessage($('#auth-error'), humanError(error));
  } finally {
    if (requestBody) {
      requestBody.password = '';
      requestBody = null;
    }
    password = '';
    scramKey = null;
    $('#login-password').value = '';
    $('#register-password').value = '';
    $('#register-confirm').value = '';
    setBusy(button, false);
  }
}

async function connectXmpp(username, secret = null) {
  const requestedUrl = websocketUrl(state.config.websocket_path || '/xmpp-websocket');
  const reusable = state.xmpp?.domain === state.config.domain
    && state.xmpp.websocketUrl === requestedUrl
    && state.xmpp.username === username.toLowerCase()
    && state.xmpp.canReconnect();
  const xmpp = reusable ? state.xmpp : new XmppClient({
    domain: state.config.domain,
    websocketUrl: requestedUrl,
  });
  state.xmpp = xmpp;
  if (state.omemo) state.omemo.xmpp = xmpp;
  if (!reusable) bindXmppEvents(xmpp);
  setConnection('away', '正在连接');
  await xmpp.connect(username, secret);
  setConnection('online', '在线 · OMEMO 初始化中');
}

function bindXmppEvents(xmpp) {
  xmpp.addEventListener('message', (event) => processMessage(event.detail));
  xmpp.addEventListener('message-error', (event) => {
    handleEncryptedMessageError(event.detail)
      .catch((error) => console.error('Failed to retain rejected encrypted message', error));
  });
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
  xmpp.addEventListener('stanza-acked', (event) => {
    settleEncryptedOutbound(event.detail.id, event.detail.xml);
  });
  xmpp.addEventListener('disconnected', () => {
    if (xmpp !== state.xmpp || state.intentionalLogout) return;
    setConnection('offline', '连接已断开');
    scheduleReconnect();
  });
}

async function enterChat() {
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
  state.omemo = new OmemoManager(state.xmpp, state.account, {
    prepareOutbound: async ({ to, type, payload, id }) => (
      powXml(await queuedMessageProof(to, type, payload, id))
    ),
    sendEncrypted: sendDurableEncrypted,
    onRemoteRetired: async ({ account, deviceId, keyErasureComplete }) => {
      try {
        state.intentionalLogout = true;
        await erasePersistentEncryptedOutbox(account);
      } finally {
        logout({
          message: keyErasureComplete
            ? `OMEMO device ${deviceId} was removed by another authenticated account endpoint. Its local keys were erased.`
            : `OMEMO device ${deviceId} was removed remotely and disabled, but local key erasure did not complete. Clear this site's local data before using this browser again.`,
        });
      }
    },
    lookupRecoveryAuthority: () => request('/api/v1/me/omemo-recovery-authority'),
    lookupRecoveryTransfer: (transferId) => request(`/api/v1/me/omemo-recovery-transfers/${transferId}`),
    retryPendingRecoveryConsume: ({ transferId, packageSha256, consumerSecret }) => request(
      `/api/v1/me/omemo-recovery-transfers/${transferId}/consume`,
      {
        method: 'POST',
        body: JSON.stringify({
          package_sha256: packageSha256,
          consumer_secret: consumerSecret,
        }),
      },
    ),
    resolvePendingRecoveryTransfer: async ({
      transferId, consumerCommitment, generation, packageSha256,
    }) => {
      let transfer;
      try {
        transfer = await request(`/api/v1/me/omemo-recovery-transfers/${transferId}`);
      } catch (error) {
        if (error.status === 404) return 'invalid-destination';
        throw error;
      }
      if (transfer.state === 'consumed') {
        return transfer.consumer_commitment === consumerCommitment
          && transfer.generation === Number(generation)
          && String(transfer.package_sha256).toLowerCase() === packageSha256
          ? 'consumed'
          : 'invalid-destination';
      }
      if (['preparing', 'prepared'].includes(transfer.state)) return 'pending';
      return 'invalid-destination';
    },
    pollRecoveryTransfer: ({ transferId, pollSecret }) => request(
      `/api/v1/omemo-recovery-transfers/${transferId}/poll`,
      {
        method: 'POST',
        omitAuthorization: true,
        body: JSON.stringify({ poll_secret: pollSecret }),
      },
    ),
  });
  const ownDevice = await state.omemo.initialize();
  if (ownDevice.recoveryFrozen) {
    state.omemoTransferId = ownDevice.transferId;
    state.omemoTransferGeneration = ownDevice.generation ?? null;
    state.intentionalLogout = true;
    state.xmpp?.disconnect();
    $('#own-device-id').textContent = ownDevice.id;
    $('#own-fingerprint').textContent = ownDevice.fingerprint;
    $('#auth-view').classList.add('hidden');
    $('#chat-view').classList.remove('hidden');
    $('#cancel-omemo-transfer').classList.remove('hidden');
    setConnection('offline', 'OMEMO migration frozen · recovery actions available');
    omemoTransferStatus(ownDevice.transferState === 'locally-unallocated'
      ? 'A locally frozen transfer was found before server preparation completed. You may safely cancel it after the authenticated authority check.'
      : ownDevice.transferState === 'authority-advanced'
        ? 'Server recovery authority advanced for another transfer. This source remains locked and cannot be re-enabled; complete an authoritative retirement check before clearing local state.'
        : 'An unfinished OMEMO transfer was restored. This device remains frozen; you may continue observing it or cancel it.', 'error');
    watchPendingOmemoTransfer();
    return;
  }
  // Device retirement is an account-wide PEP mutation. The browser does not
  // advertise entity caps, so it must establish a durable explicit bare-JID
  // subscription before the encrypted session is considered ready. Without
  // it another authenticated endpoint could revoke this device without this
  // page promptly erasing its local key material.
  await state.xmpp.subscribePep(state.account, NS.OMEMO2_DEVICES);
  $('#own-device-id').textContent = ownDevice.id;
  $('#own-fingerprint').textContent = ownDevice.fingerprint;
  setConnection('online', '在线 · OMEMO 已启用');
  await loadEncryptedOutbox();
  await replayEncryptedOutbox();
  loadAvatar(state.account, true).catch(() => {});
  for (const contact of state.contacts.values()) {
    loadAvatar(contact.jid, false).catch(() => {});
    subscribeOmemoDeviceEvents(contact.jid);
    subscribeAvatarEvents(contact.jid);
  }
  const queuedMessages = state.pendingMessages.splice(0);
  for (const message of queuedMessages) await processMessage(message);
  restoreRooms();
  for (const room of state.rooms.values()) requestRoomJoin(room);
  $('#auth-view').classList.add('hidden');
  $('#chat-view').classList.remove('hidden');
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
    if (state.omemo?.ready) {
      subscribeOmemoDeviceEvents(item.jid);
      subscribeAvatarEvents(item.jid);
    }
  }
  renderConversations();
  for (const item of items) if (item.jid && item.subscription !== 'remove') loadAvatar(item.jid, false).catch(() => {});
}

function subscribeOmemoDeviceEvents(jid) {
  state.xmpp?.subscribePep(jid, NS.OMEMO2_DEVICES).catch((error) => {
    console.warn('OMEMO device-list subscription was not accepted; the client will refetch before sending', error);
  });
}

function subscribeAvatarEvents(jid) {
  state.xmpp?.subscribePep(jid, NS.AVATAR_METADATA).catch((error) => {
    console.warn('Avatar metadata subscription was not accepted; the client will refetch when the contact is opened', error);
  });
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
  $('#contact-jid').focus();
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
    state.rooms.set(jid, {
      jid,
      name: room.name || localpart(jid),
      nick: room.nick,
      members: new Map(),
      affiliates: new Map(),
      affiliatesReady: false,
      omemoRoomVerified: false,
      omemoRoomError: 'Room encryption context has not been verified yet',
      joined: false,
      joinState: 'idle',
      joinError: '',
      joinAttempt: 0,
      unread: 0,
      kind: 'group',
    });
  }
}

function openGroupDialog() {
  showMessage($('#group-error'), '');
  $('#group-room').value = '';
  $('#group-name').value = '';
  $('#group-nick').value = localpart(state.account);
  $('#group-dialog').showModal();
  $('#group-room').focus();
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
    const room = state.rooms.get(jid) || {
      jid,
      members: new Map(),
      affiliates: new Map(),
      affiliatesReady: false,
      omemoRoomVerified: false,
      omemoRoomError: 'Room encryption context has not been verified yet',
      joinState: 'idle',
      joinError: '',
      joinAttempt: 0,
      unread: 0,
      kind: 'group',
    };
    Object.assign(room, { name: name || room.name || local, nick, joined: false });
    state.rooms.set(jid, room);
    persistRooms();
    requestRoomJoin(room);
    $('#group-dialog').close();
    await selectConversation(jid);
  } catch (error) {
    showMessage($('#group-error'), humanError(error));
  } finally {
    setBusy($('#join-group-button'), false);
  }
}

function requestRoomJoin(room) {
  room.joinAttempt = Number(room.joinAttempt || 0) + 1;
  room.joinState = 'joining';
  room.joinError = '';
  room.joinErrorCondition = '';
  room.joined = false;
  room.affiliatesReady = false;
  room.omemoRoomVerified = false;
  state.xmpp.joinRoom(room.jid, room.nick);
  if (state.selected === room.jid) updatePeerPresence();
  renderConversations();
}

function failRoomJoin(room, error, attempt = room.joinAttempt) {
  if (attempt !== room.joinAttempt) return;
  room.joined = false;
  room.joinState = 'error';
  room.joinError = humanError(error);
  room.joinErrorCondition = String(error?.condition || error?.message || '');
  room.affiliatesReady = false;
  room.omemoRoomVerified = false;
  room.omemoRoomError = room.joinError;
  if (state.selected === room.jid) updatePeerPresence();
  renderConversations();
  toast(`无法加入 ${room.jid}：${room.joinError}`, { type: 'error' });
}

async function finishRoomJoin(room, presence) {
  const attempt = room.joinAttempt;
  if (room.joinCompletionAttempt === attempt) return;
  room.joinCompletionAttempt = attempt;
  if (presence.statusCodes.includes('201')) {
    room.joinState = 'configuring';
    room.joined = false;
    if (state.selected === room.jid) updatePeerPresence();
    try {
      await state.xmpp.configureInstantRoom(room.jid);
    } catch (error) {
      failRoomJoin(room, error, attempt);
      return;
    }
  }
  if (attempt !== room.joinAttempt) return;
  room.joined = true;
  room.joinState = 'joined';
  room.joinError = '';
  room.joinErrorCondition = '';
  if (state.selected === room.jid) updatePeerPresence();
  try {
    await refreshRoomAffiliations(room);
  } catch (error) {
    console.warn('MUC affiliation refresh failed', error);
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

async function refreshRoomAffiliations(room, { refreshUi = true } = {}) {
  if (!room?.joined) return;
  room.affiliatesReady = false;
  room.omemoRoomVerified = false;
  try {
    const [features, ...lists] = await Promise.all([
      state.xmpp.getDiscoFeatures(room.jid),
      ...['owner', 'admin', 'member'].map(async (affiliation) => ({
        affiliation,
        jids: await state.xmpp.getMucAffiliations(room.jid, affiliation),
      })),
    ]);
    if (!features.has('muc_nonanonymous')) {
      throw new Error('OMEMO group chats require a non-anonymous room');
    }
    const next = new Map();
    for (const result of lists) {
      for (const jid of result.jids) next.set(jid, result.affiliation);
    }
    room.affiliates = next;
    room.affiliatesReady = true;
    room.omemoRoomVerified = true;
    room.omemoRoomError = '';
  } catch (error) {
    room.omemoRoomError = `Could not obtain the complete owner, admin and member lists: ${humanError(error)}`;
    throw error;
  }
  if (refreshUi && state.selected === room.jid) await refreshSecurity(true);
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
  let reportableMessages = 0;
  for (const message of messages) {
    const label = document.createElement('label');
    label.className = 'evidence-item';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = message.id;
    checkbox.dataset.messageId = message.id;
    const reportable = Boolean(message.archiveId && !message.failed && message.body?.trim());
    checkbox.disabled = !reportable;
    if (reportable) reportableMessages += 1;
    const copy = document.createElement('span');
    copy.className = 'evidence-copy';
    const metadata = document.createElement('span');
    const unavailableReason = message.failed
      ? ' · 解密失败，不能作为可验证证据'
      : !message.archiveId ? ' · 尚未同步到历史记录'
        : !message.body?.trim() ? ' · 没有可提交的文本' : '';
    metadata.textContent = `${message.outgoing ? translate('我') : displayName(state.contacts.get(state.selected))} · ${new Date(message.timestamp).toLocaleString(currentLocale())}${unavailableReason}`;
    if (!reportable) label.title = message.archiveId
      ? '这条记录不能作为可验证证据。'
      : '请先同步历史记录，获取服务器签发的归档 ID。';
    const body = document.createElement('strong');
    body.dataset.userContent = '';
    body.textContent = message.body;
    copy.append(metadata, body);
    label.append(checkbox, copy);
    list.append(label);
  }
  if (!messages.length || !reportableMessages) {
    const empty = document.createElement('p');
    empty.className = 'modal-copy';
    empty.textContent = messages.length
      ? '当前没有已归档且可提交的聊天记录。请先同步历史记录后重试。'
      : '当前没有可以提交的聊天记录。';
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
  if (selected.length !== selectedIds.length
    || selected.some((message) => !message.archiveId || message.failed || !message.body?.trim())) {
    showMessage($('#report-error'), '所选记录尚未归档或无法验证，请同步历史记录后重新选择。');
    return;
  }
  setBusy(button, true, '正在计算…');
  showMessage($('#report-error'), '');
  try {
    const requestBody = {
      reported_jid: state.selected,
      category: $('#report-category').value,
      description: $('#report-description').value.trim(),
      evidence: selected.map((message) => ({
        archive_id: message.archiveId,
        client_message_id: message.clientMessageId || null,
        body_text: message.body,
      })),
    };
    const pow = await queuedHttpProof(
      'report', '#report-pow-status', '/api/v1/reports', requestBody,
    );
    await request('/api/v1/reports', {
      method: 'POST',
      body: JSON.stringify({ ...requestBody, pow }),
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
    created.textContent = `提交于 ${new Date(report.created_at).toLocaleString(currentLocale())} · ${report.evidence?.length || 0} 条证据`;
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
    const requestBody = { reason };
    const path = `/api/v1/reports/${reportId}/appeals`;
    const pow = await queuedHttpProof('appeal', '#appeal-pow-status', path, requestBody);
    await request(`/api/v1/reports/${reportId}/appeals`, {
      method: 'POST',
      body: JSON.stringify({ ...requestBody, pow }),
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
  if (room && !room.joined && (!room.joinState || room.joinState === 'idle')) requestRoomJoin(room);
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
    status.dataset.joinState = room.joinState || (room.joined ? 'joined' : 'joining');
    status.dataset.joinError = room.joinError || '';
    status.dataset.joinErrorCondition = room.joinErrorCondition || '';
    status.replaceChildren();
    const dot = document.createElement('i');
    dot.className = `presence ${room.joined ? 'online' : 'away'}`;
    if (room.joinState === 'error') {
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.dataset.roomJoinRetry = '';
      retry.textContent = '重试加入';
      retry.addEventListener('click', () => requestRoomJoin(room));
      status.append(dot, `Unable to join: ${room.joinError || 'XMPP request failed'} `, retry);
    } else {
      const pending = room.joinState === 'configuring' ? 'Configuring new room' : 'Joining group chat';
      status.append(dot, room.joined ? `${room.members.size} 人在线` : pending);
    }
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
  const room = state.rooms.get(presence.bareFrom);
  if (room) {
    if (presence.type === 'error') {
      failRoomJoin(room, presence.error || new Error('XMPP room join failed'));
      return;
    }
    if (!presence.muc || !presence.nick) return;
    if (presence.type === 'unavailable') room.members.delete(presence.nick);
    else room.members.set(presence.nick, {
      nick: presence.nick,
      jid: presence.realJid,
      affiliation: presence.affiliation,
      role: presence.role,
    });
    if (presence.realJid) {
      if (['owner', 'admin', 'member'].includes(presence.affiliation)) {
        room.affiliates.set(presence.realJid, presence.affiliation);
      } else if (['none', 'outcast'].includes(presence.affiliation)) {
        room.affiliates.delete(presence.realJid);
      }
    }
    if (presence.statusCodes.includes('110')) {
      if (presence.type === 'unavailable') {
        room.joined = false;
        room.joinState = 'idle';
      } else {
        finishRoomJoin(room, presence).catch((error) => failRoomJoin(room, error));
      }
    }
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

function scopedWireMessageId(sender, id) {
  return `wire:${bareJid(sender)}\0${id}`;
}

function clientMessageId(element) {
  const value = element.getAttribute('id') || '';
  return value && value.length <= 128 && !/[\u0000-\u001f\u007f]/.test(value) ? value : null;
}

function stableMessageId(element, { archiveId, peer, sender }) {
  const originIds = [...element.children]
    .filter((node) => node.localName === 'origin-id' && node.namespaceURI === NS.STANZA_ID)
    .map((node) => node.getAttribute('id') || '')
    .filter((id) => id && id.length <= 256);
  if (originIds.length === 1) return scopedWireMessageId(sender, originIds[0]);
  const stanzaIds = [...element.children]
    .filter((node) => node.localName === 'stanza-id' && node.namespaceURI === NS.STANZA_ID)
    .map((node) => ({ by: bareJid(node.getAttribute('by')), id: node.getAttribute('id') || '' }))
    .filter(({ by, id }) => by && id && id.length <= 256);
  if (stanzaIds.length) {
    stanzaIds.sort((left, right) => left.by.localeCompare(right.by) || left.id.localeCompare(right.id));
    return `sid:${stanzaIds[0].by}\0${stanzaIds[0].id}`;
  }
  if (archiveId) return `mam:${bareJid(peer)}\0${archiveId}`;
  const wireId = element.getAttribute('id') || randomId('received');
  return scopedWireMessageId(sender, wireId);
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

  const encryptedEnvelope = isOmemoMessage(element);
  const chatState = !encryptedEnvelope
    ? [...element.children].find((node) => node.namespaceURI === NS.CHAT_STATES)
    : null;
  if (chatState && !archived) {
    showTyping(peer, chatState.localName);
    if (![...element.children].some((node) => node.localName === 'body' || node.localName === 'encrypted')) return;
  }

  const receiptRequest = !encryptedEnvelope ? child(element, 'request', NS.RECEIPTS) : null;
  const receiptId = element.getAttribute('id') || '';
  const archivedClientMessageId = clientMessageId(element);
  const id = stableMessageId(element, { archiveId, peer, sender: room ? senderJid || from : from });
  if (!room && receiptRequest && !outgoing && !archived) {
    if (receiptId) state.xmpp.sendMessage(peer, `<received xmlns='${NS.RECEIPTS}' id='${xmlEscape(receiptId)}'/><no-store xmlns='${NS.HINTS}'/>`, randomId('receipt'));
  }
  if (!encryptedEnvelope && child(element, 'received', NS.RECEIPTS)) return;

  if (!room) ensureContact(peer);
  const list = state.messages.get(peer) || [];
  const duplicate = list.find((message) => message.id === id)
    || (archiveId && archivedClientMessageId
      ? list.find((message) => message.clientMessageId === archivedClientMessageId
        && message.outgoing === outgoing)
      : null);
  if (duplicate) {
    // MAM is authoritative only for immutable archive and client stanza IDs.
    // Never replace an already displayed/decrypted body, attachment, trust
    // decision or failure state when enriching a live/carbon duplicate.
    if (archiveId && !duplicate.archiveId) duplicate.archiveId = archiveId;
    if (archivedClientMessageId && !duplicate.clientMessageId) {
      duplicate.clientMessageId = archivedClientMessageId;
    }
    if (state.selected === peer) renderMessages();
    return;
  }
  let body = '';
  let encrypted = false;
  let authenticated = false;
  let failed = false;
  let attachment = null;
  if (encryptedEnvelope) {
    encrypted = true;
    try {
      if (room && (!senderJid || !senderJid.includes('@'))) {
        throw new Error('OMEMO group message has no authenticated real-JID sender mapping');
      }
      const decrypted = await state.omemo.decrypt(element, room ? senderJid : from, {
        roomJid: room?.jid || null,
        toJid: room ? room.jid : outgoing ? peer : state.account,
        stanzaTimestamp: timestamp,
      });
      body = decrypted.body;
      attachment = decrypted.attachment || null;
      authenticated = decrypted.authenticated && (decrypted.announced || archived);
      if (decrypted.chatState && !archived) showTyping(peer, decrypted.chatState);
      if (decrypted.receiptRequest && receiptId && !room && !outgoing && !archived) {
        sendEncryptedReceipt(peer, receiptId)
          .catch((error) => console.warn('Failed to send encrypted message receipt', error));
      }
      if (decrypted.optOut) {
        if (room) throw new Error('OMEMO plaintext opt-out is not valid for a group chat');
        if (!['verified', 'tofu'].includes(decrypted.trustState)) {
          throw new Error('Ignored an OMEMO plaintext opt-out from a device without a trust decision');
        }
        handleOmemoOptOut(peer, decrypted.optOut.reason);
      } else if (['verified', 'tofu'].includes(decrypted.trustState)
        && state.securityModes.has(peer)) {
        state.securityModes.delete(peer);
        if (state.selected === peer) refreshSecurity(false);
      }
      if (decrypted.needsReply && !room && !outgoing && !archived) {
        try {
          const reply = await state.omemo.encryptEmpty(peer, decrypted.senderDevice);
          state.xmpp.sendMessage(peer, reply, randomId('omemo-empty'));
        } catch (error) {
          console.warn('Failed to send OMEMO session acknowledgement/heartbeat', error);
        }
      }
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
  if (!body && !attachment) return;
  attachment ||= decodeAttachment(body);
  if (attachment) body = `📎 ${attachment.name}`;
  const message = {
    id,
    archiveId: archiveId || null,
    clientMessageId: archivedClientMessageId,
    body,
    encrypted,
    authenticated,
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

async function sendEncryptedReceipt(peer, receiptId) {
  await state.omemo.assertEncryptable(peer);
  const id = randomId('receipt');
  const encrypted = await state.omemo.encrypt(peer, '', {
    contentXml: `<received xmlns='${NS.RECEIPTS}' id='${xmlEscape(receiptId)}'/>`,
  });
  const proof = await queuedMessageProof(peer, 'chat', encrypted.xml, id);
  await sendDurableEncrypted({
    id,
    to: peer,
    type: 'chat',
    payload: `${encrypted.xml}${powXml(proof)}`,
  });
}

async function sendMessage(event) {
  event.preventDefault();
  const input = $('#message-input');
  const body = input.value.trim();
  if (!body || !state.selected || state.blocked.has(state.selected)) return;
  setBusy($('#send-button'), true, '加密中…');
  let staged = false;
  let outboundId = null;
  try {
    const id = randomId('message');
    outboundId = id;
    const room = state.rooms.get(state.selected);
    if (room) await refreshRoomAffiliations(room, { refreshUi: false });
    const securityMode = room ? 'omemo' : state.securityModes.get(state.selected) || 'omemo';
    if (securityMode === 'blocked-optout') {
      throw new Error('Sending is blocked until you reject the plaintext downgrade request and continue using OMEMO');
    }
    const recipients = room ? roomEncryptionPeers(room) : [];
    if (room) await state.omemo.assertGroupEncryptable(recipients, room.jid);
    else await state.omemo.assertEncryptable(state.selected);
    const encrypted = room
      ? await state.omemo.encryptGroup(recipients, body, room.jid)
      : await state.omemo.encrypt(state.selected, body, {
        contentXml: `<body xmlns='${NS.CLIENT}'>${xmlEscape(body)}</body><request xmlns='${NS.RECEIPTS}'/>`,
      });
    const proof = await queuedMessageProof(
      state.selected,
      room ? 'groupchat' : 'chat',
      encrypted.xml,
      id,
    );
    const payload = room
      ? `${encrypted.xml}${powXml(proof)}`
      : `${encrypted.xml}${powXml(proof)}`;
    await sendDurableEncrypted({
      id,
      to: state.selected,
      type: room ? 'groupchat' : 'chat',
      payload,
    });
    staged = true;
    const message = {
      id: scopedWireMessageId(state.account, id),
      archiveId: null,
      clientMessageId: id,
      body,
      encrypted: true,
      authenticated: true,
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
    input.value = '';
    resizeComposer();
    renderMessages();
    renderConversations();
    if (encrypted.failures.length) toast(`${encrypted.failures.length} 个其他设备未收到消息`, { type: 'error' });
  } catch (error) {
    staged ||= Boolean(outboundId && state.encryptedOutbox.has(outboundId));
    toast(staged
      ? `连接在发送时中断；密文已安全排队：${humanError(error)}`
      : `消息没有发送：${humanError(error)}`, {
      type: 'error',
      code: staged ? 'encrypted-outbox-staged' : 'send-failed-closed',
    });
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
  if (!state.config.capabilities?.upload_admission
      || !Number.isSafeInteger(state.config.upload_max_bytes)) {
    toast('服务器当前不接受新的文件上传。', { type: 'error' });
    input.value = '';
    return;
  }
  if (state.securityModes.get(state.selected) === 'blocked-optout') {
    toast('选择会话安全模式前无法发送。', { type: 'error' });
    input.value = '';
    return;
  }
  if (file.size + 16 > state.config.upload_max_bytes) {
    toast(`文件不能超过 ${formatBytes(state.config.upload_max_bytes - 16)}`, { type: 'error' });
    input.value = '';
    return;
  }
  setBusy($('#attachment-button'), true, '加密上传中…');
  let staged = false;
  let outboundId = null;
  try {
    const room = state.rooms.get(state.selected);
    if (room) await refreshRoomAffiliations(room, { refreshUi: false });
    const recipients = room ? roomEncryptionPeers(room) : [];
    if (room) await state.omemo.assertGroupEncryptable(recipients, room.jid);
    else await state.omemo.assertEncryptable(state.selected);
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const plaintextBytes = await file.arrayBuffer();
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintextBytes));
    // The upload service sees only an opaque storage identifier. The real
    // filename remains inside authenticated SCE/XEP-0447 metadata and is
    // therefore disclosed only to OMEMO recipients.
    const opaqueUploadName = `${crypto.randomUUID()}.bin`;
    const slot = await state.xmpp.requestUploadSlot(
      opaqueUploadName,
      ciphertext.byteLength,
      'application/octet-stream',
    );
    const upload = await fetch(slot.put.url, {
      method: 'PUT',
      headers: { ...slot.put.headers, 'Content-Type': 'application/octet-stream' },
      body: ciphertext,
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
    if (!upload.ok) throw new Error(`加密文件上传失败 (${upload.status})`);
    const attachment = {
      url: slot.get.url,
      id: crypto.randomUUID(),
      name: file.name,
      type: file.type || 'application/octet-stream',
      size: file.size,
      key: bytesToBase64(keyBytes),
      iv: bytesToBase64(iv),
      hash: await sha256Base64(plaintextBytes),
      encryptedHash: await sha256Base64(ciphertext),
    };
    const protectedPayload = buildEncryptedFileContent(attachment);
    const encrypted = room
      ? await state.omemo.encryptGroup(recipients, protectedPayload.body, room.jid, { contentXml: protectedPayload.contentXml })
      : await state.omemo.encrypt(state.selected, protectedPayload.body, {
        contentXml: `${protectedPayload.contentXml}<request xmlns='${NS.RECEIPTS}'/>`,
      });
    const id = randomId('attachment');
    outboundId = id;
    const proof = await queuedMessageProof(
      state.selected,
      room ? 'groupchat' : 'chat',
      encrypted.xml,
      id,
    );
    const payload = room
      ? `${encrypted.xml}${powXml(proof)}`
      : `${encrypted.xml}${powXml(proof)}`;
    await sendDurableEncrypted({
      id,
      to: state.selected,
      type: room ? 'groupchat' : 'chat',
      payload,
    });
    staged = true;
    const message = {
      id: scopedWireMessageId(state.account, id),
      archiveId: null,
      clientMessageId: id,
      body: `📎 ${attachment.name}`,
      attachment,
      encrypted: true,
      authenticated: true,
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
    staged ||= Boolean(outboundId && state.encryptedOutbox.has(outboundId));
    toast(staged
      ? `连接在发送时中断；加密文件消息已安全排队：${humanError(error)}`
      : `文件没有发送：${humanError(error)}`, { type: 'error' });
  } finally {
    setBusy($('#attachment-button'), false);
    setTimeout(() => showMessage($('#pow-status'), ''), 2500);
    input.value = '';
  }
}

async function readResponseLimited(response, maximum) {
  const declared = Number(response.headers.get('Content-Length'));
  if (Number.isFinite(declared) && declared > maximum) throw new Error('加密文件响应超过允许大小');
  if (!response.body?.getReader) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maximum) throw new Error('加密文件响应超过允许大小');
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > maximum) {
      await reader.cancel();
      throw new Error('加密文件响应超过允许大小');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function downloadAttachment(attachment, button) {
  const downloadLimit = state.config.upload_download_max_bytes;
  if (!state.config.capabilities?.upload_download || !Number.isSafeInteger(downloadLimit)) {
    toast('服务器当前不提供历史附件下载。', { type: 'error' });
    return;
  }
  setBusy(button, true, '解密中…');
  try {
    const response = await fetch(attachment.url, {
      credentials: 'omit',
      cache: 'force-cache',
      referrerPolicy: 'no-referrer',
      redirect: 'follow',
    });
    if (!response.ok) throw new Error(`文件下载失败 (${response.status})`);
    // Fetch exposes the final URL after redirects. Re-apply the exact same
    // origin policy used by the encrypted metadata parser before consuming a
    // single response byte; HTTPS alone is not an authorization boundary.
    validateEncryptedAttachmentUrl(response.url);
    const ciphertext = await readResponseLimited(response, downloadLimit);
    if (attachment.encryptedHash && await sha256Base64(ciphertext) !== attachment.encryptedHash) {
      throw new Error('加密文件密文完整性校验失败');
    }
    const key = await crypto.subtle.importKey('raw', base64ToBytes(attachment.key), 'AES-GCM', false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(attachment.iv) },
      key,
      ciphertext,
    );
    if (attachment.size !== null && plaintext.byteLength !== attachment.size) throw new Error('解密文件大小与声明不一致');
    if (attachment.hash && await sha256Base64(plaintext) !== attachment.hash) throw new Error('解密文件完整性校验失败');
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
  // Typing state is sensitive conversation metadata. The web client requires
  // OMEMO for outbound chats and never emits XEP-0085 state in plaintext.
  // SCE requires payload-bearing messages to be stored, so synthesizing an
  // encrypted typing stanza would also pollute MAM and advance ratchets for
  // ephemeral UI noise. Omit it until an interoperable encrypted profile is
  // standardized instead of silently leaking it outside SCE.
}

function resizeComposer() {
  const input = $('#message-input');
  input.rows = 1;
  const lineHeight = Number.parseFloat(getComputedStyle(input).lineHeight) || 21;
  const verticalPadding = Number.parseFloat(getComputedStyle(input).paddingTop)
    + Number.parseFloat(getComputedStyle(input).paddingBottom);
  const visualLines = Math.ceil(Math.max(0, input.scrollHeight - verticalPadding) / lineHeight);
  input.rows = Math.max(1, Math.min(6, visualLines));
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
    row.className = `message-row ${message.outgoing ? 'outgoing' : 'incoming'} ${message.encrypted && message.authenticated !== true ? 'unverified' : ''}`;
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
    security.className = message.failed || (message.encrypted && message.authenticated !== true)
      ? 'failed'
      : message.encrypted ? 'encrypted' : 'failed';
    security.textContent = message.failed
      ? '解密失败'
      : message.encrypted && message.authenticated !== true
        ? '◇ 已加密，但发送设备尚未验证'
        : message.encrypted ? '◇ 端到端加密' : '未加密';
    security.dataset.securityState = message.failed
      ? 'decryption-failed'
      : message.encrypted && message.authenticated !== true
        ? 'encrypted-unverified'
        : message.encrypted ? 'encrypted-authenticated' : 'plaintext';
    meta.append(security);
    block.append(bubble, meta);
    row.append(block);
    container.append(row);
  }
  requestAnimationFrame(() => { container.scrollTop = container.scrollHeight; });
}

function roomEncryptionPeers(room) {
  if (!room.joined) throw new Error('The room has not finished joining');
  if (!room.omemoRoomVerified || !room.affiliatesReady) {
    throw new Error(room.omemoRoomError || 'The complete OMEMO room recipient list is unavailable');
  }
  if ([...room.members.values()].some((member) => !member.jid)) {
    throw new Error('OMEMO group chats require every occupant to expose a real JID');
  }
  room.affiliates ||= new Map();
  return [...new Set([
    ...[...room.members.values()].map((member) => member.jid),
    ...room.affiliates.keys(),
  ].filter((jid) => jid && jid !== state.account))];
}

function encryptionPeers() {
  const room = state.rooms.get(state.selected);
  return room ? roomEncryptionPeers(room) : state.selected ? [state.selected] : [];
}

async function inspectConversationDevices(refresh) {
  const peers = encryptionPeers();
  if (!peers.length) throw new Error('群聊中还没有其他成员');
  const ownDevice = await state.omemo.getOwnDevice();
  const inspectionPeers = [...new Set([...peers, state.account])];
  const groups = await Promise.all(inspectionPeers.map(async (jid) => {
    const devices = await state.omemo.inspectDevices(jid, refresh);
    return devices
      .filter((device) => jid !== state.account || device.id !== ownDevice.id)
      .map((device) => ({ ...device, jid, own: jid === state.account }));
  }));
  return groups.flat();
}

async function refreshSecurity(refresh) {
  if (!state.selected || !state.omemo?.ready) return;
  const label = $('#security-label');
  const button = $('#verify-button');
  const composer = $('.composer-security');
  const banner = $('#security-banner');
  banner.dataset.securityState = 'checking';
  const securityMode = state.securityModes.get(state.selected);
  if (securityMode === 'blocked-optout') {
    banner.dataset.securityState = 'blocked-optout';
    label.textContent = '需要决定';
    button.classList.add('warning');
    composer.classList.add('warning');
    $('#composer-mode').textContent = '发送已阻止';
    $('#security-banner strong').textContent = '对方请求使用明文';
    $('#security-banner span:not(.shield)').textContent = 'Northstar 不允许降级为明文。选择此警告以拒绝请求并继续使用 OMEMO。';
    return;
  }
  label.textContent = '检查中';
  try {
    const devices = await inspectConversationDevices(refresh);
    const unresolved = devices.filter((device) => !device.fingerprint || !['verified', 'tofu', 'distrusted'].includes(device.trustState));
    if (unresolved.length) {
      banner.dataset.securityState = 'unresolved-devices';
      throw new Error('有设备尚未验证、身份已变化或公钥包不可用；请先检查设备指纹');
    }
    const usable = devices.filter((device) => device.fingerprint && ['verified', 'tofu'].includes(device.trustState));
    const peersWithoutTrustedDevices = encryptionPeers().filter(
      (peer) => !usable.some((device) => device.jid === peer),
    );
    if (peersWithoutTrustedDevices.length) {
      banner.dataset.securityState = 'no-trusted-recipient';
      throw new Error('至少一位参与者没有受信任的加密设备');
    }
    const distrusted = devices.filter((device) => device.trustState === 'distrusted').length;
    const tofu = devices.filter((device) => device.trustState === 'tofu').length;
    label.textContent = `${usable.length} 台加密设备`;
    button.classList.remove('warning');
    composer.classList.remove('warning');
    $('#composer-mode').textContent = 'OMEMO 端到端加密';
    $('#security-banner strong').textContent = 'OMEMO 端到端加密已就绪';
    $('#security-banner span:not(.shield)').textContent = tofu
      ? `将向 ${usable.length} 台设备加密；其中 ${tofu} 台通过 TOFU 接受，未经独立验证。`
      : distrusted
      ? `将向 ${usable.length} 台设备加密；已排除 ${distrusted} 台明确不信任的设备。`
      : `已发现 ${usable.length} 台接收设备；服务器只能保存密文。`;
    banner.dataset.securityState = 'ready';
  } catch (error) {
    if (banner.dataset.securityState === 'checking') banner.dataset.securityState = 'unavailable';
    label.textContent = '无法加密';
    button.classList.add('warning');
    composer.classList.add('warning');
    $('#composer-mode').textContent = '暂时无法安全发送';
    $('#security-banner strong').textContent = '尚未建立加密会话';
    $('#security-banner span:not(.shield)').textContent = humanError(error);
  }
  if (state.blocked.has(state.selected)) $('#composer-mode').textContent = '联系人已屏蔽';
}

let verificationOperation = Promise.resolve();

function openVerification(refresh) {
  const operation = verificationOperation
    .catch(() => {})
    .then(() => openVerificationLocked(refresh));
  verificationOperation = operation;
  return operation;
}

async function openVerificationLocked(refresh) {
  if (!state.selected) return;
  const list = $('#fingerprint-list');
  list.dataset.loading = 'true';
  const refreshButton = $('#refresh-devices');
  refreshButton.disabled = true;
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
      card.dataset.deviceId = String(device.id);
      card.dataset.jid = device.jid;
      card.dataset.trustState = device.fingerprint ? (device.trustState || 'undecided') : 'unavailable';
      const header = document.createElement('header');
      const title = document.createElement('strong');
      title.textContent = `${device.own ? translate('我的其他设备') : device.jid} · 设备 ${device.id}`;
      const status = document.createElement('span');
      status.textContent = device.fingerprint
        ? (device.trustState === 'changed'
          ? '身份密钥已变化，发送已暂停'
          : device.trustState === 'verified'
            ? '已通过可信渠道验证'
            : device.trustState === 'distrusted'
              ? '已明确标记为不信任'
              : device.trustState === 'tofu'
                ? '首次使用即信任（TOFU；未独立验证）'
                : '尚未做出信任决定')
        : '不可用';
      header.append(title, status);
      const code = document.createElement('code');
      code.textContent = device.fingerprint || device.error || '无法读取指纹';
      card.append(header, code);
      if (device.fingerprint && device.identityKey) {
        const actions = document.createElement('div');
        actions.className = 'fingerprint-actions';
        const addDecision = (label, decision, className = 'secondary-button') => {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = `${className} compact-button omemo-trust-${decision}`;
          button.textContent = label;
          button.addEventListener('click', async () => {
            button.disabled = true;
            try {
              await state.omemo.setDeviceTrust(device.jid, device.id, device.identityKey, decision);
              toast(decision === 'verified'
                ? '设备指纹已标记为通过可信渠道验证'
                : decision === 'distrusted'
                  ? '该设备已标记为不信任，后续消息不会加密给它'
                  : '已接受当前身份密钥，但仍建议通过可信渠道核对指纹');
              await openVerification(true);
            } catch (error) {
              toast(humanError(error), { type: 'error' });
              await openVerification(true);
            }
          });
          actions.append(button);
        };
        if (device.trustState !== 'verified') addDecision('核对无误，标记为已验证', 'verified', 'primary-button');
        if (device.trustState !== 'tofu') addDecision('首次使用即信任（未独立验证）', 'tofu');
        if (device.trustState !== 'distrusted') addDecision('不信任此设备', 'distrusted', 'danger-button');
        const reset = document.createElement('button');
        reset.type = 'button';
        reset.className = 'secondary-button compact-button omemo-session-reset';
        reset.textContent = '重置加密会话';
        reset.title = '仅在无法解密或设备恢复旧备份后使用；下次发送会建立新会话';
        reset.addEventListener('click', async () => {
          if (!confirm(translate(`确定替换 ${device.jid} · 设备 ${device.id} 的 OMEMO 会话吗？`))) return;
          reset.disabled = true;
          try {
            await state.omemo.resetSession(device.jid, device.id);
            toast('旧会话已移除；下次发送将重新建立加密会话');
          } catch (error) {
            toast(humanError(error), { type: 'error' });
          } finally {
            reset.disabled = false;
          }
        });
        actions.append(reset);
        if (device.own) {
          const retire = document.createElement('button');
          retire.type = 'button';
          retire.className = 'danger-button compact-button omemo-device-retire';
          retire.textContent = '从我的账户移除此设备';
          retire.addEventListener('click', async () => {
            if (!confirm(translate(`从账户移除 ${device.jid} · 设备 ${device.id}？该浏览器将不再收到新的加密消息。`))) return;
            retire.disabled = true;
            try {
              await state.omemo.retireOtherOwnDevice(device.id);
              toast('设备已移除并标记为不信任。');
              await openVerification(true);
            } catch (error) {
              toast(humanError(error), { type: 'error' });
              retire.disabled = false;
            }
          });
          actions.append(retire);
        }
        card.append(actions);
      }
      list.append(card);
    }
    if (!devices.length) {
      const empty = document.createElement('div');
      empty.className = 'fingerprint-card';
      empty.textContent = '对方尚未发布 OMEMO 设备。';
      list.append(empty);
    }
    await refreshSecurity(refresh);
  } catch (error) {
    list.replaceChildren();
    const card = document.createElement('div');
    card.className = 'fingerprint-card';
    card.textContent = humanError(error);
    list.append(card);
  } finally {
    list.dataset.loading = 'false';
    refreshButton.disabled = false;
  }
}

function handleOmemoOptOut(peer, reason) {
  state.securityModes.set(peer, 'blocked-optout');
  if (state.selected === peer) refreshSecurity(false);
  toast(reason
    ? `对方请求使用明文（${reason}）。Northstar 已阻止此降级请求。`
    : '对方请求使用明文。Northstar 已阻止此降级请求。', { type: 'error' });
}

function handleSecurityButton() {
  const mode = state.securityModes.get(state.selected);
  if (!mode) {
    openVerification(false);
    return;
  }
  if (!confirm(translate('继续使用 OMEMO 并拒绝降级为明文的请求？'))) return;
  state.securityModes.delete(state.selected);
  refreshSecurity(true);
}

function compactTime(value) {
  const date = new Date(value);
  const today = new Date();
  if (date.toDateString() === today.toDateString()) return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
  return date.toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' });
}

function scheduleReconnect() {
  if (state.intentionalLogout || !state.account || !state.xmpp?.canReconnect() || state.reconnectTimer) return;
  const delay = Math.min(30000, 1000 * 2 ** state.reconnectAttempts);
  state.reconnectAttempts += 1;
  state.reconnectTimer = setTimeout(() => {
    state.reconnectTimer = null;
    maybeReconnect();
  }, delay);
}

async function maybeReconnect() {
  if (state.intentionalLogout || !navigator.onLine || !state.account || !state.xmpp?.canReconnect() || state.xmpp?.phase === 'online') return;
  try {
    setConnection('away', '正在重新连接');
    await connectXmpp(localpart(state.account));
    state.omemo.xmpp = state.xmpp;
    await state.omemo.validateRecoveryAuthority();
    if (!state.xmpp.lastConnectResumed) {
      await state.omemo.publishBundle();
      await state.omemo.ensureDeviceAnnouncement();
      await state.xmpp.getRoster().then(mergeRoster);
      state.blocked = new Set(await state.xmpp.getBlocklist());
      for (const room of state.rooms.values()) {
        room.joined = false;
        room.members.clear();
        requestRoomJoin(room);
      }
    }
    await replayEncryptedOutbox();
    updateBlockedState();
    setConnection('online', '在线 · OMEMO 已启用');
    state.reconnectAttempts = 0;
  } catch (error) {
    if (!state.xmpp?.canReconnect()) {
      setConnection('offline', '安全会话已过期，请重新登录');
      toast('安全会话已过期，请重新输入密码登录', { type: 'error' });
      logout({ message: '安全会话已过期，请重新登录。' });
      return;
    }
    scheduleReconnect();
  }
}

async function forgetOmemoDevice(event) {
  event.preventDefault();
  if (!state.omemo?.ready) return;
  if (!confirm(translate('从账户移除此浏览器设备并永久删除其本地 OMEMO 密钥？加密历史记录无法恢复这些棘轮密钥。'))) return;
  const button = event.currentTarget;
  setBusy(button, true, '移除中…');
  try {
    const account = state.account;
    await state.omemo.retireAndEraseLocalState();
    await erasePersistentEncryptedOutbox(account);
    setBusy(button, false);
    logout({ message: '此浏览器设备及其本地 OMEMO 密钥已永久移除。' });
  } catch (error) {
    toast(`设备未能删除：${humanError(error)}`, { type: 'error' });
    setBusy(button, false);
  }
}

function omemoTransferStatus(message, type = 'info') {
  const element = $('#omemo-transfer-status');
  element.textContent = message;
  element.classList.toggle('hidden', !message);
  element.classList.toggle('error', type === 'error');
  element.classList.toggle('success', type === 'success');
}

function downloadLocalTransfer(serialized, transferId) {
  const blob = new Blob([serialized], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `northstar-omemo-${transferId}.northstar-omemo-transfer.json`;
  anchor.rel = 'noopener';
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

async function exportOmemoDevice(event) {
  event.preventDefault();
  const button = event.currentTarget;
  const passphraseInput = $('#omemo-transfer-passphrase');
  const confirmInput = $('#omemo-transfer-confirm');
  let passphrase = passphraseInput.value;
  const confirmValue = confirmInput.value;
  passphraseInput.value = '';
  confirmInput.value = '';
  if (passphrase !== confirmValue) {
    passphrase = '';
    omemoTransferStatus('两次输入的迁移口令不一致。', 'error');
    return;
  }
  if ([...passphrase].length < 12) {
    passphrase = '';
    omemoTransferStatus('请使用至少 12 个字符的独立迁移口令。', 'error');
    return;
  }
  const recovered = state.omemo?.getRecoverableSourceTransfer();
  let transferId = recovered?.transferId || crypto.randomUUID();
  let pollSecret = recovered?.pollSecret || newOmemoTransferSecret();
  const abortController = new AbortController();
  state.omemoTransferAbortController = abortController;
  let prepared = null;
  let sourceFrozen = false;
  let markerReplaced = false;
  let recoveryWatchPaused = false;
  setBusy(button, true, '正在派生密钥…');
  omemoTransferStatus('正在准备服务器无法解密的一次性迁移文件…');
  try {
    const own = await state.omemo.getOwnDevice();
    if (recovered) {
      sourceFrozen = true;
      if (recovered.generation !== null) {
        // The encrypted file is intentionally not retained by the browser.
        // Re-encrypting would create a different immutable digest for the old
        // prepared row. Revoke it, observe authority, then create a fresh row
        // while retaining the same account Web Lock and frozen ratchet.
        await pauseOmemoRecoveryWatch();
        recoveryWatchPaused = true;
        state.intentionalLogout = true;
        await request(`/api/v1/me/omemo-recovery-transfers/${transferId}`, { method: 'DELETE' });
        const oldTransferId = transferId;
        transferId = crypto.randomUUID();
        pollSecret = newOmemoTransferSecret();
        await state.omemo.replaceSourceRecoveryMarker(oldTransferId, transferId, pollSecret);
        markerReplaced = true;
        state.omemoTransferId = transferId;
        state.omemoTransferGeneration = null;
        // The watcher is resumed only after the replacement marker has been
        // durably sealed. A crash before this line leaves the old marker; a
        // crash after it leaves the new frozen marker.
        state.omemoRecoveryTransition = false;
        recoveryWatchPaused = false;
        watchPendingOmemoTransfer();
      }
      prepared = await request('/api/v1/me/omemo-recovery-transfers', {
          method: 'POST',
          body: JSON.stringify({
            transfer_id: transferId,
            source_device_id: own.id,
            poll_secret: pollSecret,
          }),
        });
      if (!['preparing', 'prepared'].includes(prepared.state)) {
        throw new Error('The recovered source transfer can no longer produce a package');
      }
    } else {
      const authorityBaseline = await request('/api/v1/me/omemo-recovery-authority');
      const baselineGeneration = Number(authorityBaseline.latest_consumed_generation || 0);
      if (!Number.isSafeInteger(baselineGeneration) || baselineGeneration < 0) {
        throw new Error('Server returned an invalid OMEMO recovery authority baseline');
      }
      await state.omemo.freezeDeviceTransfer(transferId, pollSecret, baselineGeneration);
      sourceFrozen = true;
      state.omemoTransferId = transferId;
      state.omemoTransferGeneration = null;
      state.intentionalLogout = true;
      state.xmpp?.disconnect();
      $('#cancel-omemo-transfer').classList.remove('hidden');
      setConnection('offline', '设备迁移待处理');
      prepared = await request('/api/v1/me/omemo-recovery-transfers', {
        method: 'POST',
        body: JSON.stringify({
          transfer_id: transferId,
          source_device_id: own.id,
          poll_secret: pollSecret,
        }),
      });
    }
    state.omemoTransferGeneration = Number(prepared.generation);
    const encrypted = await state.omemo.createDeviceTransfer(passphrase, prepared, pollSecret, {
      signal: abortController.signal,
    });
    passphrase = '';
    await request(`/api/v1/me/omemo-recovery-transfers/${transferId}`, {
      method: 'PUT',
      body: JSON.stringify({ package_sha256: encrypted.sha256 }),
    });
    downloadLocalTransfer(encrypted.serialized, transferId);
    $('#cancel-omemo-transfer').classList.remove('hidden');
    watchPendingOmemoTransfer();
    omemoTransferStatus('迁移文件已保存到本地。源设备现已冻结，以防棘轮状态分叉。请在七天内导入一次并删除该文件，或在此取消迁移。', 'success');
  } catch (error) {
    if (recoveryWatchPaused) {
      state.omemoRecoveryTransition = false;
      recoveryWatchPaused = false;
    }
    let revocationCertain = false;
    if (markerReplaced) {
      $('#cancel-omemo-transfer').classList.remove('hidden');
      watchPendingOmemoTransfer();
    } else if (sourceFrozen) {
      try {
        await request(`/api/v1/me/omemo-recovery-transfers/${transferId}`, { method: 'DELETE' });
        revocationCertain = true;
      } catch (revokeError) {
        revocationCertain = revokeError.status === 404;
      }
      if (revocationCertain) {
        await state.omemo?.cancelDeviceTransfer(transferId);
        state.omemoTransferId = null;
        state.omemoTransferGeneration = null;
        state.intentionalLogout = false;
        await maybeReconnect();
      } else {
        $('#cancel-omemo-transfer').classList.remove('hidden');
        watchPendingOmemoTransfer();
      }
    }
    omemoTransferStatus(revocationCertain || !sourceFrozen
      ? `迁移导出失败：${humanError(error)}`
      : `迁移导出结果尚不确定，源设备将保持冻结：${humanError(error)}`,
    'error');
  } finally {
    if (state.omemoTransferAbortController === abortController) {
      state.omemoTransferAbortController = null;
    }
    passphrase = '';
    passphraseInput.value = '';
    confirmInput.value = '';
    setBusy(button, false);
  }
}

function clearOmemoTransferWatch() {
  state.omemoTransferWatchEpoch += 1;
  clearTimeout(state.omemoTransferPollTimer);
  state.omemoTransferPollTimer = null;
}

async function pauseOmemoRecoveryWatch() {
  state.omemoRecoveryTransition = true;
  clearOmemoTransferWatch();
  await state.omemoTransferWatchInFlight.catch(() => {});
}

function recoveryWatchCurrent(epoch, transferId) {
  return !state.omemoRecoveryTransition
    && state.omemoTransferWatchEpoch === epoch
    && state.omemoTransferId === transferId
    && Boolean(state.omemo);
}

function watchPendingOmemoTransfer() {
  clearOmemoTransferWatch();
  if (!state.omemoTransferId || !state.omemo || state.omemoRecoveryTransition) return;
  const epoch = state.omemoTransferWatchEpoch;
  const transferId = state.omemoTransferId;
  state.omemoTransferPollTimer = setTimeout(() => {
    state.omemoTransferPollTimer = null;
    const run = (async () => {
      if (!recoveryWatchCurrent(epoch, transferId)) return;
      try {
        const recovery = await state.omemo.validateRecoveryAuthority(
          () => recoveryWatchCurrent(epoch, transferId),
        );
        if (!recoveryWatchCurrent(epoch, transferId)) return;
      if (recovery?.recoverable) {
        state.omemoTransferGeneration = recovery.generation ?? null;
        omemoTransferStatus(recovery.state === 'locally-unallocated'
          ? 'The source freeze is recoverable and no server transfer exists. You may cancel it safely.'
          : 'The OMEMO transfer remains frozen and recoverable. Continue on the destination or cancel it.', 'error');
        watchPendingOmemoTransfer();
        return;
      }
      if (!recoveryWatchCurrent(epoch, transferId)) return;
      clearOmemoTransferWatch();
      state.omemoTransferId = null;
      state.omemoTransferGeneration = null;
      state.intentionalLogout = false;
      $('#cancel-omemo-transfer').classList.add('hidden');
      omemoTransferStatus('迁移文件已不再有效，正在重新连接源设备。', 'success');
      if (state.omemoRecoveryTransition || state.omemoTransferWatchEpoch !== epoch + 1) return;
      await maybeReconnect();
      return;
      } catch (error) {
        console.warn('Pending OMEMO transfer authority check failed closed', error);
      }
      if (recoveryWatchCurrent(epoch, transferId)) watchPendingOmemoTransfer();
    })();
    const tracked = run.finally(() => {
      if (state.omemoTransferWatchInFlight === tracked) state.omemoTransferWatchInFlight = Promise.resolve();
    });
    state.omemoTransferWatchInFlight = tracked;
  }, 5000);
}

async function cancelPendingOmemoTransfer(event) {
  event.preventDefault();
  const button = event.currentTarget;
  const transferId = state.omemoTransferId;
  if (!transferId || !state.omemo) return;
  if (!confirm('永久取消此一次性迁移文件并重新启用源设备？')) return;
  state.omemoTransferAbortController?.abort();
  setBusy(button, true, '正在取消…');
  try {
    await request(`/api/v1/me/omemo-recovery-transfers/${transferId}`, { method: 'DELETE' })
      .catch((error) => {
        if (error.status !== 404) throw error;
      });
    const recovery = await state.omemo.validateRecoveryAuthority();
    if (recovery?.recoverable && !['locally-unallocated', 'preparing', 'prepared'].includes(recovery.state)) {
      throw new Error('Server authority did not confirm that the source transfer can be cancelled');
    }
    await state.omemo.cancelDeviceTransfer(transferId);
    clearOmemoTransferWatch();
    state.omemoTransferId = null;
    state.omemoTransferGeneration = null;
    state.intentionalLogout = false;
    button.classList.add('hidden');
    omemoTransferStatus('迁移文件已撤销。请删除已下载的文件；正在重新连接源设备。', 'success');
    await maybeReconnect();
  } catch (error) {
    omemoTransferStatus(`迁移取消失败：${humanError(error)}`, 'error');
    await state.omemo.validateRecoveryAuthority().catch(() => {});
  } finally {
    setBusy(button, false);
  }
}

async function importOmemoDevice(event) {
  event.preventDefault();
  const button = event.currentTarget;
  const fileInput = $('#omemo-transfer-file');
  const passphraseInput = $('#omemo-import-passphrase');
  const file = fileInput.files?.[0];
  if (!file) {
    passphraseInput.value = '';
    omemoTransferStatus('请先选择加密的迁移文件。', 'error');
    return;
  }
  if (file.size < 1 || file.size > OMEMO_TRANSFER_MAX_BYTES) {
    passphraseInput.value = '';
    omemoTransferStatus('迁移文件超过 44 MiB 安全上限。', 'error');
    return;
  }
  let passphrase = passphraseInput.value;
  const abortController = new AbortController();
  state.omemoTransferAbortController = abortController;
  passphraseInput.value = '';
  setBusy(button, true, '正在解密…');
  omemoTransferStatus('正在验证并解密本地迁移文件…');
  let imported = null;
  let installed = false;
  let replacementStarted = false;
  let consumerSecret = null;
  let consumerCommitment = null;
  try {
    imported = await state.omemo.decryptDeviceTransfer(await file.arrayBuffer(), passphrase, {
      signal: abortController.signal,
    });
    passphrase = '';
    const transfer = await request(`/api/v1/me/omemo-recovery-transfers/${imported.metadata.transfer_id}`);
    if (transfer.state !== 'prepared'
      || transfer.generation !== imported.metadata.generation
      || transfer.source_device_id !== imported.metadata.source_device_id
      || String(transfer.package_sha256).toLowerCase() !== imported.sha256) {
      throw new Error('服务器的一次性迁移记录与此文件不匹配');
    }
    if (!confirm('导入操作会将源 OMEMO 设备移入此浏览器，永久移除此浏览器当前的 OMEMO 设备，并要求重新验证所有联系人指纹。是否继续？')) {
      omemoTransferStatus('已取消导入；未更改任何本地设备。');
      return;
    }
    consumerSecret = newOmemoTransferSecret();
    state.intentionalLogout = true;
    await erasePersistentEncryptedOutbox(state.account);
    replacementStarted = true;
    ({ consumerCommitment } = await state.omemo.installDeviceTransfer(imported, consumerSecret));
    installed = true;
    try {
      await request(`/api/v1/me/omemo-recovery-transfers/${imported.metadata.transfer_id}/consume`, {
        method: 'POST',
        body: JSON.stringify({
          package_sha256: imported.sha256,
          consumer_secret: consumerSecret,
        }),
      });
    } catch (consumeError) {
      // A timeout after PostgreSQL commit is ambiguous. Never erase the only
      // destination copy until an authoritative read proves it did not win.
      let transferAfter = null;
      let authorityAfter;
      try {
        transferAfter = await request(`/api/v1/me/omemo-recovery-transfers/${imported.metadata.transfer_id}`)
          .catch((error) => {
            if (error.status === 404) return null;
            throw error;
          });
        authorityAfter = await request('/api/v1/me/omemo-recovery-authority');
      } catch {
        await state.omemo.markDeviceTransferPhase('consume-uncertain');
        fileInput.value = '';
        logout({ message: '迁移提交结果暂时无法确定。已保留加密的目标状态，但在验证服务器代际前将保持安全锁定。请勿重新启用源迁移文件。' });
        return;
      }
      const committed = (transferAfter?.state === 'consumed'
          && transferAfter.consumer_commitment === consumerCommitment
          && String(transferAfter.package_sha256).toLowerCase() === imported.sha256)
        || (Number(authorityAfter.latest_consumed_generation) === Number(imported.metadata.generation)
          && authorityAfter.latest_consumed_transfer_id === imported.metadata.transfer_id
          && authorityAfter.latest_consumer_commitment === consumerCommitment);
      if (!committed) throw consumeError;
    }
    await state.omemo.markDeviceTransferPhase('consumed-confirmed');
    fileInput.value = '';
    logout({ message: 'OMEMO 设备迁移已完成。请在此浏览器重新登录、删除迁移文件，并明确重新验证每个联系人设备。' });
  } catch (error) {
    let erasureFailed = false;
    if (replacementStarted || installed) {
      await state.omemo?.eraseInstalledDeviceTransfer().catch((erasureError) => {
        erasureFailed = true;
        console.error('OMEMO replacement cleanup remains journal-fenced', erasureError);
      });
    }
    if (state.intentionalLogout) {
      logout({ message: erasureFailed
        ? '迁移无法提交且本地删除未完成。替换日志将保持安全锁定；重试前请清除此站点的本地数据。'
        : '由于一次性迁移无法提交，目标设备已被删除。请重新登录以创建新设备；源迁移仍是权威状态。' });
    }
    omemoTransferStatus(`迁移导入失败：${humanError(error)}`, 'error');
  } finally {
    if (state.omemoTransferAbortController === abortController) {
      state.omemoTransferAbortController = null;
    }
    passphrase = '';
    passphraseInput.value = '';
    setBusy(button, false);
  }
}

function clearPasswordAndTransferInputs() {
  $('#login-password').value = '';
  $('#register-password').value = '';
  $('#register-confirm').value = '';
  $('#omemo-transfer-passphrase').value = '';
  $('#omemo-transfer-confirm').value = '';
  $('#omemo-import-passphrase').value = '';
  $('#omemo-transfer-file').value = '';
}

function clearSensitiveSessionUi() {
  clearPasswordAndTransferInputs();
  for (const selector of [
    '#login-username', '#register-username', '#register-invitation', '#contact-search',
    '#contact-jid', '#contact-name', '#group-room', '#group-name', '#group-nick',
    '#report-description', '#message-input', '#attachment-input', '#avatar-input',
  ]) {
    const element = $(selector);
    if (element) element.value = '';
  }
  for (const selector of [
    '#message-list', '#fingerprint-list', '#conversation-list', '#room-member-list',
    '#report-message-list', '#report-history-list',
  ]) {
    $(selector)?.replaceChildren();
  }
  for (const selector of [
    '#self-name', '#peer-name', '#peer-address', '#peer-status', '#room-actions-name',
    '#contact-actions-name', '#security-title', '#security-copy',
  ]) {
    const element = $(selector);
    if (element) element.textContent = '';
  }
  document.querySelectorAll('dialog[open]').forEach((dialog) => dialog.close());
  $('#toast-region')?.replaceChildren();
  paintAvatar($('#self-avatar'), null, 'N');
  paintAvatar($('#settings-avatar'), null, 'N');
  paintAvatar($('#peer-avatar'), null, 'N');
  avatarCropper?.clear();
}

function clearPersistedRoomMetadata(account) {
  if (!account) return;
  try {
    localStorage.removeItem(`northstar:rooms:${bareJid(account)}`);
  } catch (error) {
    console.warn('Failed to erase local room metadata', error);
  }
}

function revokeApiSessionKeepalive(token) {
  if (!token) return;
  fetch('/api/v1/session', {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${token}`,
      'Idempotency-Key': newClientIdempotencyKey(),
    },
    cache: 'no-store',
    credentials: 'omit',
    keepalive: true,
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  }).catch((error) => console.warn('Failed to revoke API session during browser teardown', error));
}

function endBrowserSession({
  message,
  revokeApiSession,
  lifecycleLocked = false,
} = {}) {
  const account = state.account;
  const apiToken = state.apiToken;
  const omemo = state.omemo;
  state.intentionalLogout = true;
  state.pageLifecycleLocked = lifecycleLocked;
  state.outboxErasing = true;
  state.outboxGeneration += 1;
  clearTimeout(state.reconnectTimer);
  state.omemoTransferAbortController?.abort();
  state.omemoTransferAbortController = null;
  state.xmpp?.disconnect();
  const previousCleanup = state.lifecycleCleanup;
  const currentCleanup = Promise.resolve(omemo?.destroy()).catch((error) => {
    console.error('Failed to flush OMEMO state during browser teardown', error);
  });
  state.lifecycleCleanup = Promise.allSettled([previousCleanup, currentCleanup]).then(() => {});
  if (revokeApiSession) revokeApiSessionKeepalive(apiToken);
  clearPersistedRoomMetadata(account);
  state.apiToken = null;
  state.account = null;
  state.omemo = null;
  state.xmpp = null;
  state.selfProfile = {};
  state.contacts.clear();
  state.rooms.clear();
  state.messages.clear();
  state.hydratedPeers.clear();
  state.blocked.clear();
  state.presence.clear();
  state.pendingMessages = [];
  state.outboxAckWindow.clear();
  state.outboxRetries.clear();
  state.encryptedOutbox.clear();
  state.securityModes.clear();
  clearOmemoTransferWatch();
  state.omemoTransferId = null;
  state.omemoTransferGeneration = null;
  state.selected = null;
  $('#active-conversation').classList.add('hidden');
  $('#empty-state').classList.remove('hidden');
  $('#chat-view').classList.add('hidden');
  $('#auth-view').classList.remove('hidden');
  clearSensitiveSessionUi();
  $('#own-device-id').textContent = '—';
  $('#own-fingerprint').textContent = '—';
  $('#cancel-omemo-transfer').classList.add('hidden');
  omemoTransferStatus('');
  showMessage($('#auth-success'), message || '安全会话已结束，请重新登录。');
}

function handlePageHide(event) {
  const persisted = Boolean(event.persisted);
  endBrowserSession({
    message: persisted
      ? '页面已进入浏览器返回缓存并安全锁定；返回后请重新登录。'
      : '页面会话已结束；服务器端会话撤销已尽力提交，超时策略仍会最终失效该会话。',
    revokeApiSession: !persisted,
    lifecycleLocked: persisted,
  });
}

function handlePageShow(event) {
  if (!event.persisted) return;
  clearSensitiveSessionUi();
  $('#chat-view').classList.add('hidden');
  $('#auth-view').classList.remove('hidden');
  showMessage($('#auth-success'), '页面已从浏览器返回缓存恢复，但安全会话仍保持锁定；请重新登录。');
}

function logout({ message = '已安全退出；加密封装的本机 OMEMO 状态仍保留在此浏览器中。' } = {}) {
  endBrowserSession({ message, revokeApiSession: true, lifecycleLocked: false });
}

initializePage();
