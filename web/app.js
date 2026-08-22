import { currentLocale, initializeI18n } from './i18n.js?v=20260813-6';

initializeI18n();

const $ = (selector) => document.querySelector(selector);
const state = {
  token: sessionStorage.getItem('admin_token'),
  jid: sessionStorage.getItem('admin_jid'),
  domain: location.hostname,
};
const esc = (value) => String(value).replace(/[&<>'"]/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
})[char]);

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(path, { ...options, headers });
  const body = response.headers.get('content-type')?.includes('json')
    ? await response.json()
    : await response.text();
  if (!response.ok) throw new Error(body?.error?.message || body || '请求失败');
  return body;
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
    state.domain = config.domain;
    $('#domain-value').textContent = config.domain;
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
    const [stats, users] = await Promise.all([
      api('/api/v1/admin/stats'),
      api('/api/v1/admin/users'),
    ]);
    const [reports, invitations] = await Promise.all([
      api('/api/v1/admin/reports').catch(() => null),
      api('/api/v1/admin/invitations').catch(() => null),
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
    $('#users').innerHTML = users.users.map((user) => `<tr>
      <td><strong>${esc(user.username)}</strong></td>
      <td>${user.is_admin ? '管理员' : '用户'}</td>
      <td>${user.is_disabled ? '已停用' : '正常'}</td>
      <td>${new Date(user.created_at).toLocaleDateString(currentLocale())}</td>
      <td><button data-user="${user.id}" data-action="disabled" data-value="${!user.is_disabled}">${user.is_disabled ? '启用' : '停用'}</button><button data-user="${user.id}" data-action="admin" data-value="${!user.is_admin}">${user.is_admin ? '撤销管理' : '设为管理'}</button></td>
    </tr>`).join('');
    if (invitations) renderInvitations(invitations.invitations || [], invitations.required);
    else $('#invitations').innerHTML = '<p class="admin-help">服务器更新并重启后启用邀请码管理。</p>';
    if (reports) renderReports(reports.reports || []);
    else $('#reports').innerHTML = '<p class="admin-help">服务器更新并重启后启用举报队列。</p>';
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

function logoutAdmin() {
  state.token = null;
  state.jid = null;
  sessionStorage.removeItem('admin_token');
  sessionStorage.removeItem('admin_jid');
  showAdminSession();
}

$('#admin-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('#admin-error').textContent = '';
  try {
    const session = await api('/api/v1/login', {
      method: 'POST',
      body: JSON.stringify({
        username: $('#admin-username').value,
        password: $('#admin-password').value,
      }),
    });
    if (!session.is_admin) throw new Error('该账户没有管理员权限');
    state.token = session.token;
    state.jid = session.jid;
    sessionStorage.setItem('admin_token', state.token);
    sessionStorage.setItem('admin_jid', state.jid);
    $('#admin-password').value = '';
    showAdminSession();
    await loadAdmin();
  } catch (error) {
    $('#admin-error').textContent = error.message;
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

$('#refresh-admin').addEventListener('click', loadAdmin);
$('#admin-logout').addEventListener('click', logoutAdmin);
window.addEventListener('northstar:languagechange', () => {
  checkServer();
  showAdminSession();
  if (state.token) loadAdmin();
});

loadPublicConfig();
checkServer();
showAdminSession();
if (state.token) loadAdmin();
