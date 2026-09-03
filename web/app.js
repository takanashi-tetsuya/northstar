import { currentLocale, initializeI18n, translate } from './i18n.js?v=20260813-6';

initializeI18n();

const $ = (selector) => document.querySelector(selector);
const state = {
  token: sessionStorage.getItem('admin_token'),
  jid: sessionStorage.getItem('admin_jid'),
  domain: location.hostname,
  publicConfig: null,
  runtime: null,
};
const esc = (value) => String(value).replace(/[&<>'"]/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
})[char]);

function newIdempotencyKey() {
  if (typeof crypto.randomUUID === 'function') return `web-admin-${crypto.randomUUID()}`;
  const random = crypto.getRandomValues(new Uint8Array(24));
  return `web-admin-${[...random].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
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

async function api(path, options = {}) {
  const { idempotencyKey, ...requestOptions } = options;
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const method = String(requestOptions.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && !headers['Idempotency-Key']) {
    headers['Idempotency-Key'] = idempotencyKey || newIdempotencyKey();
  }
  // Generate the key once, then reuse both it and the serialized request body
  // across bounded retries after an uncertain network/server result.
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
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = text; }
    if (response.ok) return body;

    const errorCode = body?.error?.code;
    const retryable = API_RETRYABLE_STATUS.has(response.status)
      || (response.status === 409 && errorCode === 'idempotency_in_progress');
    const delay = retryable ? apiRetryDelay(response, attempt) : null;
    if (delay !== null && attempt < API_RETRY_DELAYS_MS.length && !requestOptions.signal?.aborted) {
      await waitForApiRetry(delay, requestOptions.signal);
      continue;
    }
    const error = new Error(body?.error?.message || body || '请求失败');
    error.status = response.status;
    error.code = errorCode;
    error.retryAfterSeconds = Number(response.headers.get('Retry-After')) || null;
    throw error;
  }
}

async function checkServer() {
  try {
    const response = await fetch('/healthz', { cache: 'no-store' });
    if (!response.ok) throw new Error('unhealthy');
    $('#server-status').classList.add('online');
    $('#server-status').innerHTML = '<i></i> 服务在线';
  } catch {
    $('#server-status').classList.remove('online');
    $('#server-status').innerHTML = '<i></i> 服务离线';
  }
}

async function loadPublicConfig() {
  try {
    const config = await api('/api/v1/config');
    state.publicConfig = config;
    state.domain = config.domain;
    $('#domain-value').textContent = config.domain;
    const publicClient = config.capabilities?.web_client && config.public_url
      ? `${String(config.public_url).replace(/\/$/, '')}/client.html`
      : null;
    document.querySelectorAll('[data-public-client]').forEach((link) => {
      if (publicClient) {
        link.href = publicClient;
        link.removeAttribute('aria-disabled');
      } else {
        link.removeAttribute('href');
        link.setAttribute('aria-disabled', 'true');
      }
    });
  } catch {
    $('#domain-value').textContent = location.hostname;
  }
}

function showAdminSession() {
  const loggedIn = Boolean(state.token);
  $('#admin-login').classList.toggle('hidden', loggedIn);
  $('#admin-content').classList.toggle('hidden', !loggedIn);
  $('#admin-identity').textContent = state.jid ? `管理员：${state.jid}` : '';
}

async function loadAdmin() {
  if (!state.token) return;
  try {
    const [stats, users, publicConfig] = await Promise.all([
      api('/api/v1/admin/stats'),
      api('/api/v1/admin/users'),
      api('/api/v1/config'),
    ]);
    const invitationAvailable = Boolean(publicConfig.capabilities?.invitation_registration);
    const [reports, invitations] = await Promise.all([
      api('/api/v1/admin/reports').catch(() => null),
      invitationAvailable ? api('/api/v1/admin/invitations') : Promise.resolve(null),
    ]);
    const values = [
      ['账户', stats.users],
      ['在线会话', stats.online_sessions],
      ['密文归档', stats.archived_stanzas],
      ['离线队列', stats.offline_stanzas],
      ['群聊房间', stats.rooms],
      ['群聊在线成员', stats.room_occupants],
      ['已上传文件', stats.uploaded_files],
      ['推送订阅', stats.push_subscriptions],
      ['联邦投递', stats.federation_outbound_deliveries],
      ['联邦失败', stats.federation_failures],
      ['待处理举报', stats.pending_reports],
      ['待处理申诉', stats.pending_appeals],
      ['有效邀请码', stats.active_invitations],
      ['触发限制', stats.rate_limited_operations],
    ];
    $('#stats').innerHTML = values.filter(([, value]) => value !== undefined).map(([label, value]) =>
      `<div class="stat"><strong>${value}</strong><span>${label}</span></div>`).join('');
    state.publicConfig = publicConfig;
    state.runtime = {
      openRegistration: stats.registration_open === undefined
        ? Boolean(publicConfig.open_registration)
        : Boolean(stats.registration_open),
      islandMode: Boolean(stats.island_mode),
    };
    $('#registration-toggle').checked = state.runtime.openRegistration;
    $('#registration-toggle').disabled = Boolean(publicConfig.registration_dependency_locked);
    $('#registration-toggle').title = publicConfig.registration_dependency_locked
      ? 'Web client is disabled, so invitation-only registration is locked closed.'
      : '';
    $('#invitation-control').classList.toggle('hidden', !invitationAvailable);
    $('#island-toggle').checked = state.runtime.islandMode;
    $('#island-toggle').disabled = stats.island_mode === undefined;
    $('#users').innerHTML = users.users.map((user) => `<tr>
      <td><strong>${esc(user.username)}</strong></td>
      <td>${user.is_admin ? '管理员' : '用户'}</td>
      <td>${user.is_disabled ? '已停用' : '正常'}</td>
      <td>${new Date(user.created_at).toLocaleDateString(currentLocale())}</td>
      <td><button data-user="${user.id}" data-action="disabled" data-value="${!user.is_disabled}">${user.is_disabled ? '启用' : '停用'}</button><button data-user="${user.id}" data-action="admin" data-value="${!user.is_admin}">${user.is_admin ? '撤销管理' : '设为管理'}</button></td>
    </tr>`).join('');
    if (invitations) renderInvitations(invitations.invitations || [], invitations.required);
    if (reports) renderReports(reports.reports || []);
    else $('#reports').innerHTML = '<p class="admin-help">服务器更新并重启后启用举报队列。</p>';
    await Promise.all([
      loadSessions(),
      loadRooms(),
      loadOfflineStats(),
      loadOperations(),
    ]);
  } catch (error) {
    if (/authentication|required|unauthorized/i.test(error.message)) logoutAdmin();
    else $('#admin-error').textContent = error.message;
  }
}

function renderInvitations(invitations, required) {
  const header = `<p class="admin-help">${required ? '当前注册必须提供有效邀请码。' : '当前为开放注册；邀请码可选，启用 INVITATION_REQUIRED 后会强制使用。'}</p>`;
  const cards = invitations.map((invitation) => {
    const inactive = invitation.revoked_at || (invitation.expires_at && new Date(invitation.expires_at) <= new Date()) || invitation.use_count >= invitation.max_uses;
    return `<article class="admin-item">
      <header><strong>${esc(invitation.label)}</strong><span class="queue-status">${inactive ? '不可用' : '有效'}</span></header>
      <p>使用 ${invitation.use_count}/${invitation.max_uses} · ${invitation.expires_at ? `到期 ${new Date(invitation.expires_at).toLocaleString(currentLocale())}` : '永不过期'}</p>
      ${inactive ? '' : `<button type="button" data-revoke-invitation="${invitation.id}">撤销</button>`}
    </article>`;
  }).join('');
  $('#invitations').innerHTML = header + (cards || '<p class="admin-help">尚未创建邀请码。</p>');
}

function renderReports(reports) {
  $('#reports').innerHTML = reports.map((report) => {
    const evidence = (report.evidence || []).map((item) => `<blockquote><strong data-i18n-ignore>${esc(item.sender_jid)}</strong><time>${item.sent_at ? new Date(item.sent_at).toLocaleString(currentLocale()) : '时间未知'}</time><p data-i18n-ignore>${esc(item.body_text)}</p><small>${item.encrypted ? '由举报人从端到端加密会话中选择并解密提交' : '未加密消息'}</small></blockquote>`).join('');
    const appeal = report.appeal ? `<section class="appeal-review"><h4>申诉 · ${esc(report.appeal.status)}</h4><p data-i18n-ignore>${esc(report.appeal.reason)}</p>
      <label>申诉状态<select data-appeal-status="${report.appeal.id}"><option value="submitted" ${report.appeal.status === 'submitted' ? 'selected' : ''}>已提交</option><option value="reviewing" ${report.appeal.status === 'reviewing' ? 'selected' : ''}>处理中</option><option value="upheld" ${report.appeal.status === 'upheld' ? 'selected' : ''}>申诉成立</option><option value="denied" ${report.appeal.status === 'denied' ? 'selected' : ''}>申诉未成立</option></select></label>
      <label>申诉处理说明<textarea data-i18n-ignore data-appeal-resolution="${report.appeal.id}" maxlength="8000">${esc(report.appeal.resolution || '')}</textarea></label>
      <button type="button" class="primary" data-update-appeal="${report.appeal.id}">保存申诉处理</button></section>` : '';
    return `<article class="moderation-card">
      <header><div><strong>${esc(report.reported_jid)}</strong><span>举报人 ${esc(report.reporter_username)} · ${new Date(report.created_at).toLocaleString(currentLocale())}</span></div><span class="queue-status">${esc(report.category)} / ${esc(report.status)}</span></header>
      ${report.description ? `<p class="report-description" data-i18n-ignore>${esc(report.description)}</p>` : ''}
      <details><summary>查看 ${report.evidence?.length || 0} 条已提交记录</summary>${evidence}</details>
      <div class="moderation-controls">
        <label>举报状态<select data-report-status="${report.id}"><option value="submitted" ${report.status === 'submitted' ? 'selected' : ''}>已提交</option><option value="reviewing" ${report.status === 'reviewing' ? 'selected' : ''}>处理中</option><option value="actioned" ${report.status === 'actioned' ? 'selected' : ''}>已采取措施</option><option value="rejected" ${report.status === 'rejected' ? 'selected' : ''}>未支持举报</option><option value="closed" ${report.status === 'closed' ? 'selected' : ''}>已关闭</option></select></label>
        <label>处理说明<textarea data-i18n-ignore data-report-resolution="${report.id}" maxlength="8000">${esc(report.resolution || '')}</textarea></label>
        <button type="button" class="primary" data-update-report="${report.id}">保存处理结果</button>
      </div>${appeal}
    </article>`;
  }).join('') || '<p class="admin-help">当前没有举报。</p>';
}

function humanDuration(seconds) {
  const value = Math.max(0, Number(seconds) || 0);
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m`;
  return `${Math.floor(value)}s`;
}

function humanBytes(bytes) {
  let value = Math.max(0, Number(bytes) || 0);
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

async function loadSessions() {
  try {
    const data = await api('/api/v1/admin/sessions?limit=100');
    $('#sessions').innerHTML = (data.sessions || []).map((session) => `<article class="admin-item">
      <header><strong data-i18n-ignore>${esc(session.jid)}</strong><span class="queue-status">${esc(session.node)}</span></header>
      <p>${session.ip ? `IP ${esc(session.ip)} · ` : ''}${humanDuration(session.connected_duration_seconds)} · ${esc(session.resource)}</p>
      <button type="button" data-kick-session="${session.connection_id}" data-session-jid="${esc(session.jid)}">Disconnect</button>
    </article>`).join('') || '<p class="admin-help">No connected resources.</p>';
  } catch (error) {
    $('#sessions').innerHTML = `<p class="admin-help">${esc(error.message)}</p>`;
  }
}

async function loadRooms() {
  try {
    const data = await api('/api/v1/admin/muc_rooms?limit=100');
    $('#rooms').innerHTML = (data.rooms || []).map((room) => `<article class="admin-item">
      <header><strong data-i18n-ignore>${esc(room.title || room.localpart)}</strong><span class="queue-status">${room.current_occupants} online</span></header>
      <p data-i18n-ignore>${esc(room.localpart)}@conference.${esc(state.domain)} · ${room.non_anonymous ? 'non-anonymous' : 'semi-anonymous'} · ${room.persistent ? 'persistent' : 'temporary'}</p>
      <button type="button" data-destroy-room="${esc(room.localpart)}">Destroy</button>
    </article>`).join('') || '<p class="admin-help">No rooms exist.</p>';
  } catch (error) {
    $('#rooms').innerHTML = `<p class="admin-help">${esc(error.message)}</p>`;
  }
}

async function loadOfflineStats() {
  try {
    const data = await api('/api/v1/admin/offline_messages');
    $('#offline-stats').textContent = `${data.total_messages} queued messages · approximately ${humanBytes(data.estimated_bytes)}`;
    $('#clear-offline').disabled = Number(data.total_messages) === 0;
  } catch (error) {
    $('#offline-stats').textContent = error.message;
  }
}

function operationStatusLabel(operation) {
  const suffix = operation.error_code ? ` · ${operation.error_code}` : '';
  return `${operation.status}${suffix}`;
}

function renderOperations(operations) {
  $('#operations').innerHTML = operations.map((operation) => {
    const cancelable = ['pending', 'running'].includes(operation.status) && !operation.point_of_no_return_at;
    const reconcile = operation.status === 'indeterminate';
    return `<article class="moderation-card operation-card" data-operation-card="${operation.id}">
      <header><div><strong>${esc(operation.kind)}</strong><code data-i18n-ignore>${esc(operation.id)}</code></div><span class="queue-status">${esc(operationStatusLabel(operation))}</span></header>
      <p class="operation-meta">${operation.target ? `Target: ${esc(operation.target)} · ` : ''}attempt ${operation.attempts}/${operation.max_attempts} · created ${new Date(operation.created_at).toLocaleString(currentLocale())}</p>
      <div class="operation-actions">
        <button type="button" data-inspect-operation="${operation.id}">Inspect</button>
        ${cancelable ? `<button type="button" class="danger-action" data-cancel-operation="${operation.id}">Cancel</button>` : ''}
        ${reconcile ? `<button type="button" data-reconcile-operation="${operation.id}" data-reconcile-success="true">Mark succeeded</button><button type="button" class="danger-action" data-reconcile-operation="${operation.id}" data-reconcile-success="false">Mark failed</button>` : ''}
      </div>
      <div class="operation-detail hidden" data-operation-detail="${operation.id}"></div>
    </article>`;
  }).join('') || '<p class="admin-help">No durable operations have been recorded.</p>';
}

async function loadOperations() {
  try {
    const data = await api('/api/v1/admin/operations?limit=25');
    renderOperations(data.items || []);
  } catch (error) {
    $('#operations').innerHTML = `<p class="admin-help">${esc(error.message)}</p>`;
  }
}

async function inspectOperation(id) {
  const detail = $(`[data-operation-detail="${id}"]`);
  if (!detail) return;
  if (!detail.classList.contains('hidden')) {
    detail.classList.add('hidden');
    return;
  }
  detail.classList.remove('hidden');
  detail.textContent = '正在加载操作证据…';
  try {
    const operation = await api(`/api/v1/admin/operations/${id}`);
    const targetStatus = operation.status === 'indeterminate' ? 'indeterminate' : null;
    const targetQuery = new URLSearchParams({ limit: '25' });
    if (targetStatus) targetQuery.set('status', targetStatus);
    const targetPage = await api(`/api/v1/admin/operations/${id}/targets?${targetQuery}`);
    const targets = targetPage.items || [];
    const targetControls = targets.map((target) => `<article class="admin-item" data-target-card="${target.id}">
      <header><strong data-i18n-ignore>${esc(target.target_key)}</strong><span class="queue-status">${esc(target.status)}</span></header>
      <p>attempt ${target.attempts}/${target.max_attempts}${target.error_code ? ` · ${esc(target.error_code)}` : ''}</p>
      <div class="operation-actions"><button type="button" data-inspect-target="${target.id}" data-target-operation="${id}">Inspect target evidence</button>${target.status === 'indeterminate' ? `<button type="button" data-reconcile-target="${target.id}" data-target-operation="${id}" data-reconcile-success="true">Mark target succeeded</button><button type="button" class="danger-action" data-reconcile-target="${target.id}" data-target-operation="${id}" data-reconcile-success="false">Mark target failed</button>` : ''}</div>
      <div class="operation-target-detail hidden" data-target-detail="${target.id}"></div>
    </article>`).join('');
    const continuation = targetPage.next_cursor
      ? `<button type="button" class="secondary" data-more-targets="${id}" data-target-status="${targetStatus || ''}" data-target-cursor="${esc(targetPage.next_cursor)}">Load more targets</button>`
      : '';
    const targetDescription = targetStatus
      ? '<p class="admin-help">Only indeterminate targets are shown. Reconcile every target before reconciling the parent operation.</p>'
      : '';
    detail.innerHTML = `<pre data-i18n-ignore>${esc(JSON.stringify(operation, null, 2))}</pre>${targetDescription}${targetControls ? `<div class="admin-card-list" data-target-list="${id}">${targetControls}</div>${continuation}` : ''}`;
  } catch (error) {
    detail.textContent = error.message;
  }
}

async function inspectOperationTarget(operationId, targetId) {
  const detail = $(`[data-target-detail="${targetId}"]`);
  if (!detail) return;
  if (!detail.classList.contains('hidden')) {
    detail.classList.add('hidden');
    return;
  }
  detail.classList.remove('hidden');
  detail.textContent = 'Loading target evidence…';
  try {
    const target = await api(`/api/v1/admin/operations/${operationId}/targets/${targetId}`);
    detail.innerHTML = `<pre data-i18n-ignore>${esc(JSON.stringify(target, null, 2))}</pre>`;
  } catch (error) {
    detail.textContent = error.message;
  }
}

async function loadMoreOperationTargets(button) {
  const operationId = button.dataset.moreTargets;
  const query = new URLSearchParams({ limit: '25', cursor: button.dataset.targetCursor });
  if (button.dataset.targetStatus) query.set('status', button.dataset.targetStatus);
  const page = await api(`/api/v1/admin/operations/${operationId}/targets?${query}`);
  const list = $(`[data-target-list="${operationId}"]`);
  for (const target of page.items || []) {
    const wrapper = document.createElement('div');
    wrapper.innerHTML = `<article class="admin-item" data-target-card="${target.id}">
      <header><strong data-i18n-ignore>${esc(target.target_key)}</strong><span class="queue-status">${esc(target.status)}</span></header>
      <p>attempt ${target.attempts}/${target.max_attempts}${target.error_code ? ` · ${esc(target.error_code)}` : ''}</p>
      <div class="operation-actions"><button type="button" data-inspect-target="${target.id}" data-target-operation="${operationId}">Inspect target evidence</button>${target.status === 'indeterminate' ? `<button type="button" data-reconcile-target="${target.id}" data-target-operation="${operationId}" data-reconcile-success="true">Mark target succeeded</button><button type="button" class="danger-action" data-reconcile-target="${target.id}" data-target-operation="${operationId}" data-reconcile-success="false">Mark target failed</button>` : ''}</div>
      <div class="operation-target-detail hidden" data-target-detail="${target.id}"></div>
    </article>`;
    list?.append(wrapper.firstElementChild);
  }
  if (page.next_cursor) {
    button.dataset.targetCursor = page.next_cursor;
  } else {
    button.remove();
  }
}

async function reconcileOperation(id, succeeded) {
  const evidence = window.prompt(translate('请输入不含秘密的证据说明，解释结果如何得到验证：'));
  if (!evidence?.trim()) return;
  let errorCode = null;
  if (!succeeded) {
    errorCode = window.prompt(translate('请输入简短的机器可读失败代码（例如 operator_verified_failure）：'));
    if (!errorCode?.trim()) return;
  }
  await api(`/api/v1/admin/operations/${id}/reconcile`, {
    method: 'POST',
    body: JSON.stringify({
      succeeded,
      result: null,
      error_code: succeeded ? null : errorCode.trim(),
      evidence_note: evidence.trim(),
    }),
  });
}

async function reconcileOperationTarget(operationId, targetId, succeeded) {
  const evidence = window.prompt(translate('请输入不含秘密的证据说明，解释结果如何得到验证：'));
  if (!evidence?.trim()) return;
  let errorCode = null;
  if (!succeeded) {
    errorCode = window.prompt(translate('请输入简短的机器可读失败代码（例如 operator_verified_failure）：'));
    if (!errorCode?.trim()) return;
  }
  await api(`/api/v1/admin/operations/${operationId}/targets/${targetId}/reconcile`, {
    method: 'POST',
    body: JSON.stringify({
      succeeded,
      result: null,
      error_code: succeeded ? null : errorCode.trim(),
      evidence_note: evidence.trim(),
    }),
  });
}

async function revokeApiSession(token) {
  if (!token) return;
  const response = await fetch('/api/v1/session', {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
    cache: 'no-store',
    keepalive: true,
  });
  if (!response.ok && response.status !== 401) throw new Error('服务器端管理会话撤销失败');
}

async function logoutAdmin() {
  const token = state.token;
  state.token = null;
  state.jid = null;
  sessionStorage.removeItem('admin_token');
  sessionStorage.removeItem('admin_jid');
  showAdminSession();
  try {
    await revokeApiSession(token);
  } catch (error) {
    $('#admin-error').textContent = error.message;
  }
}

$('#admin-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#admin-error').textContent = '';
  const username = $('#admin-username').value;
  let password = $('#admin-password').value;
  $('#admin-password').value = '';
  let requestBody = null;
  try {
    requestBody = {
      username,
      password,
    };
    const session = await api('/api/v1/login', {
      method: 'POST',
      body: JSON.stringify(requestBody),
    });
    requestBody.password = '';
    requestBody = null;
    password = '';
    if (!session.is_admin) {
      await revokeApiSession(session.token);
      throw new Error('该账户没有管理员权限');
    }
    state.token = session.token;
    state.jid = session.jid;
    sessionStorage.setItem('admin_token', state.token);
    sessionStorage.setItem('admin_jid', state.jid);
    $('#admin-password').value = '';
    showAdminSession();
    await loadAdmin();
  } catch (error) {
    if (requestBody) {
      requestBody.password = '';
      requestBody = null;
    }
    $('#admin-error').textContent = error.message;
  } finally {
    if (requestBody) {
      requestBody.password = '';
      requestBody = null;
    }
    password = '';
    $('#admin-password').value = '';
  }
});

$('#users').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-user]');
  if (!button) return;
  button.disabled = true;
  try {
    await api(`/api/v1/admin/users/${button.dataset.user}`, {
      method: 'PATCH',
      body: JSON.stringify({ [button.dataset.action]: button.dataset.value === 'true' }),
    });
    await loadAdmin();
  } catch (error) {
    $('#admin-error').textContent = error.message;
    button.disabled = false;
  }
});

$('#invitation-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const created = await api('/api/v1/admin/invitations', {
      method: 'POST',
      body: JSON.stringify({
        label: $('#invitation-label').value.trim(),
        max_uses: Number($('#invitation-max-uses').value),
        expires_in_hours: $('#invitation-hours').value ? Number($('#invitation-hours').value) : null,
      }),
    });
    $('#invitation-token').textContent = `仅显示一次，请立即复制：${created.token}`;
    $('#invitation-token').classList.remove('hidden');
    await loadAdmin();
  } catch (error) {
    $('#admin-error').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$('#invitations').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-revoke-invitation]');
  if (!button) return;
  button.disabled = true;
  try {
    await api(`/api/v1/admin/invitations/${button.dataset.revokeInvitation}`, { method: 'DELETE' });
    await loadAdmin();
  } catch (error) {
    $('#admin-error').textContent = error.message;
    button.disabled = false;
  }
});

$('#reports').addEventListener('click', async (event) => {
  const reportButton = event.target.closest('button[data-update-report]');
  const appealButton = event.target.closest('button[data-update-appeal]');
  if (!reportButton && !appealButton) return;
  const button = reportButton || appealButton;
  button.disabled = true;
  try {
    if (reportButton) {
      const id = reportButton.dataset.updateReport;
      await api(`/api/v1/admin/reports/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: $(`[data-report-status="${id}"]`).value, resolution: $(`[data-report-resolution="${id}"]`).value.trim() }),
      });
    } else {
      const id = appealButton.dataset.updateAppeal;
      await api(`/api/v1/admin/appeals/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: $(`[data-appeal-status="${id}"]`).value, resolution: $(`[data-appeal-resolution="${id}"]`).value.trim() }),
      });
    }
    await loadAdmin();
  } catch (error) {
    $('#admin-error').textContent = error.message;
    button.disabled = false;
  }
});

$('#sessions').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-kick-session]');
  if (!button) return;
  const jid = button.dataset.sessionJid || 'this resource';
  if (!window.confirm(translate(`断开 ${jid}？客户端可能会自动重新连接。`))) return;
  button.disabled = true;
  try {
    await api(`/api/v1/admin/sessions/${button.dataset.kickSession}`, { method: 'DELETE' });
    await Promise.all([loadSessions(), loadOperations()]);
  } catch (error) {
    $('#admin-error').textContent = error.message;
    button.disabled = false;
  }
});

$('#rooms').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-destroy-room]');
  if (!button) return;
  const localpart = button.dataset.destroyRoom;
  if (!window.confirm(translate(`永久销毁 ${localpart}@conference.${state.domain}？所有参与者都将断开连接。`))) return;
  button.disabled = true;
  try {
    await api(`/api/v1/admin/muc_rooms/${encodeURIComponent(localpart)}`, { method: 'DELETE' });
    await Promise.all([loadRooms(), loadOperations()]);
  } catch (error) {
    $('#admin-error').textContent = error.message;
    button.disabled = false;
  }
});

$('#save-runtime-controls').addEventListener('click', async (event) => {
  if (!state.runtime) return;
  const button = event.currentTarget;
  const openRegistration = $('#registration-toggle').checked;
  const islandMode = $('#island-toggle').checked;
  button.disabled = true;
  $('#runtime-control-status').textContent = '正在应用已审计的运行时控制…';
  try {
    if (openRegistration !== state.runtime.openRegistration) {
      await api('/api/v1/admin/registration', {
        method: 'POST',
        body: JSON.stringify({ enabled: openRegistration }),
      });
    }
    if (!$('#island-toggle').disabled && islandMode !== state.runtime.islandMode) {
      await api('/api/v1/admin/island_mode', {
        method: 'POST',
        body: JSON.stringify({ enabled: islandMode }),
      });
    }
    $('#runtime-control-status').textContent = '运行时控制已接受。';
    await loadAdmin();
  } catch (error) {
    $('#runtime-control-status').textContent = error.message;
    $('#registration-toggle').checked = state.runtime.openRegistration;
    $('#island-toggle').checked = state.runtime.islandMode;
  } finally {
    button.disabled = false;
  }
});

$('#reload-tls').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  $('#runtime-control-status').textContent = '正在验证并重新加载 TLS 身份…';
  try {
    const result = await api('/api/v1/admin/tls/reload', { method: 'POST' });
    $('#runtime-control-status').textContent = result.not_after
      ? `TLS identity reloaded; certificate expires ${new Date(result.not_after).toLocaleString(currentLocale())}.`
      : 'TLS identity reload accepted.';
  } catch (error) {
    $('#runtime-control-status').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$('#panic-disconnect').addEventListener('click', async (event) => {
  if (!window.confirm(translate('断开所有活动客户端会话？这是紧急操作，所有客户端都可能重新连接。'))) return;
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api('/api/v1/admin/panic_disconnect', { method: 'POST' });
    $('#runtime-control-status').textContent = '紧急断开已排队。';
    await loadOperations();
  } catch (error) {
    $('#runtime-control-status').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$('#clear-offline').addEventListener('click', async (event) => {
  if (!window.confirm(translate('删除所有排队的离线消息？此操作无法撤销。'))) return;
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await api('/api/v1/admin/offline_messages', { method: 'DELETE' });
    $('#offline-stats').textContent = `已移除 ${result.removed || 0} 条排队消息。`;
    await loadOfflineStats();
  } catch (error) {
    $('#offline-stats').textContent = error.message;
    button.disabled = false;
  }
});

$('#broadcast-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = $('#broadcast-message').value.trim();
  if (!message || !window.confirm(translate('将此公告排队发送给所有账户？'))) return;
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  $('#broadcast-status').textContent = '正在将广播排队…';
  try {
    await api('/api/v1/admin/broadcast', {
      method: 'POST',
      body: JSON.stringify({ message }),
    });
    $('#broadcast-message').value = '';
    $('#broadcast-status').textContent = '广播操作已排队。';
    await loadOperations();
  } catch (error) {
    $('#broadcast-status').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$('#operations').addEventListener('click', async (event) => {
  const inspect = event.target.closest('button[data-inspect-operation]');
  const cancel = event.target.closest('button[data-cancel-operation]');
  const reconcile = event.target.closest('button[data-reconcile-operation]');
  const reconcileTarget = event.target.closest('button[data-reconcile-target]');
  const inspectTarget = event.target.closest('button[data-inspect-target]');
  const moreTargets = event.target.closest('button[data-more-targets]');
  const button = inspect || cancel || reconcile || reconcileTarget || inspectTarget || moreTargets;
  if (!button) return;
  button.disabled = true;
  try {
    if (inspect) {
      await inspectOperation(inspect.dataset.inspectOperation);
    } else if (cancel) {
      if (window.confirm(translate('请求取消此操作？'))) {
        await api(`/api/v1/admin/operations/${cancel.dataset.cancelOperation}/cancel`, { method: 'POST' });
        await loadOperations();
      }
    } else if (reconcile) {
      const succeeded = reconcile.dataset.reconcileSuccess === 'true';
      if (window.confirm(translate(`手动将此结果未定的操作标记为${translate(succeeded ? '成功' : '失败')}？请先验证外部证据。`))) {
        await reconcileOperation(reconcile.dataset.reconcileOperation, succeeded);
        await loadOperations();
      }
    } else if (reconcileTarget) {
      const succeeded = reconcileTarget.dataset.reconcileSuccess === 'true';
      if (window.confirm(translate(`手动将此结果未定的目标标记为${translate(succeeded ? '成功' : '失败')}？请先验证外部证据。`))) {
        await reconcileOperationTarget(reconcileTarget.dataset.targetOperation, reconcileTarget.dataset.reconcileTarget, succeeded);
        await loadOperations();
      }
    } else if (inspectTarget) {
      await inspectOperationTarget(inspectTarget.dataset.targetOperation, inspectTarget.dataset.inspectTarget);
    } else {
      await loadMoreOperationTargets(moreTargets);
    }
  } catch (error) {
    $('#admin-error').textContent = error.message;
  } finally {
    if (button.isConnected) button.disabled = false;
  }
});

$('#refresh-admin').addEventListener('click', loadAdmin);
$('#refresh-sessions').addEventListener('click', loadSessions);
$('#refresh-rooms').addEventListener('click', loadRooms);
$('#refresh-operations').addEventListener('click', loadOperations);
$('#operation-lookup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const id = $('#operation-lookup-id').value.trim();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const operation = await api(`/api/v1/admin/operations/${encodeURIComponent(id)}`);
    renderOperations([operation]);
    await inspectOperation(operation.id);
  } catch (error) {
    $('#operations').innerHTML = `<p class="admin-help">${esc(error.message)}</p>`;
  } finally {
    button.disabled = false;
  }
});
$('#admin-logout').addEventListener('click', () => { void logoutAdmin(); });
window.addEventListener('northstar:languagechange', () => {
  checkServer();
  showAdminSession();
  if (state.token) loadAdmin();
});

loadPublicConfig();
checkServer();
showAdminSession();
if (state.token) loadAdmin();
