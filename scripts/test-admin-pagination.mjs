import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { test } from 'node:test';

const source = fs.readFileSync(new URL('../web/app.js', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
const definitions = {
  users: ['users', 'users', 100], sessions: ['sessions', 'sessions', 100],
  rooms: ['muc_rooms', 'rooms', 100], reports: ['reports', 'reports', 25],
  invitations: ['invitations', 'invitations', 25], operations: ['operations', 'items', 25],
};
function fixture() {
  const elements = new Map();
  for (const [, id] of html.matchAll(/id="([^"]+)"/g)) elements.set(`#${id}`, {
    innerHTML: '', textContent: '', listeners: {},
    classList: { toggle() {}, add() {}, remove() {} },
    addEventListener(event, callback) { this.listeners[event] = callback; },
  });
  const element = (selector) => {
    assert.ok(elements.has(selector), `missing element ${selector}`);
    return elements.get(selector);
  };
  const calls = [];
  const reply = (body, status = 200) => ({ ok: status === 200, status, headers: new Headers(), text: async () => JSON.stringify(body) });
  const f = { element, calls, reply, intercept: null };
  const context = vm.createContext({
    document: { querySelector: element }, window: { addEventListener() {} },
    location: { hostname: 'example.test' }, sessionStorage: { getItem() { return null; }, removeItem() {} },
    initializeI18n() {}, currentLocale: () => 'en', translate: (value) => value,
    URLSearchParams, Date, crypto: { randomUUID: () => 'fixture' }, setTimeout, clearTimeout,
    fetch: async (path, options) => {
      calls.push(path);
      if (f.intercept) {
        const result = f.intercept(path, options);
        if (result) return result;
      }
      if (path === '/api/v1/admin/stats') return reply({ users: 101 });
      if (path === '/api/v1/config') return reply({ capabilities: { invitation_registration: true } });
      if (path === '/api/v1/admin/offline_messages') return reply({ total_messages: 0 });
      if (path === '/api/v1/session') return reply({});
      const url = new URL(path, 'https://example.test');
      const entry = Object.entries(definitions).find(([, [route]]) => url.pathname === `/api/v1/admin/${route}`);
      assert.ok(entry, path);
      const [name, [, key, limit]] = entry;
      assert.equal(url.searchParams.get('limit'), String(limit));
      const cursor = url.searchParams.get('cursor');
      assert.ok(cursor === null || cursor === `${name} &+?page=2`, 'cursor must round-trip without injection');
      const row = (i) => ({ id: `${name}-${i}`, username: `${name}-${i}`, jid: `${name}-${i}`, node: 'node',
        title: `${name}-${i}`, localpart: `${name}-${i}`, reported_jid: `${name}-${i}`, label: `${name}-${i}`,
        kind: `${name}-${i}`, created_at: '2026-09-29', max_uses: 10, use_count: 0, status: 'pending' });
      return reply({ [key]: cursor ? [row(limit)] : Array.from({ length: limit }, (_, i) => row(i)),
        next_cursor: cursor ? null : `${name} &+?page=2` });
    },
  });
  const body = source.replace(/^import .*\n/, '');
  vm.runInContext(body.slice(0, body.lastIndexOf('\nloadPublicConfig();')), context);
  f.run = (code) => vm.runInContext(code, context);
  f.run("state.token = 'test-only'");
  return f;
}

for (const [name, [, , limit]] of Object.entries(definitions)) {
  test(`${name}: bounded first page, reachable final row, previous page and refresh`, async () => {
    const f = fixture();
    await f.run('loadAdmin()');
    assert.equal(f.calls.length, 9, 'initial load must not fetch continuations automatically');
    assert.match(f.element(`#${name}`).innerHTML, new RegExp(`${name}-${limit - 1}`));
    assert.doesNotMatch(f.element(`#${name}`).innerHTML, new RegExp(`${name}-${limit}(?:[<" ])`));
    assert.match(f.element(`#${name}-pagination`).innerHTML, /More results are available/);
    await f.run(`changeAdminPage('${name}', 'next')`);
    assert.equal(f.calls.length, 10);
    assert.match(f.element(`#${name}`).innerHTML, new RegExp(`${name}-${limit}`));
    assert.match(f.element(`#${name}-pagination`).innerHTML, /No more results/);
    await f.run(`changeAdminPage('${name}', 'next')`);
    assert.equal(f.calls.length, 10, 'final page cannot issue another request');
    await f.run(`changeAdminPage('${name}', 'previous')`);
    assert.match(f.element(`#${name}`).innerHTML, new RegExp(`${name}-0`));
    await f.run(`loadAdminPage('${name}')`);
    assert.equal(f.run(`adminPages.get('${name}').history.length`), 0);
  });
}

test('failed continuation preserves current rows and retries the same cursor', async () => {
  const f = fixture();
  await f.run("loadAdminPage('users')");
  const before = f.element('#users').innerHTML;
  f.intercept = () => f.reply({ error: { message: '<failed>' } }, 400);
  await f.run("changeAdminPage('users', 'next')");
  assert.equal(f.element('#users').innerHTML, before);
  assert.match(f.element('#users-pagination').innerHTML, /&lt;failed&gt;/);
  const failedPath = f.calls.at(-1);
  f.intercept = null;
  await f.run("changeAdminPage('users', 'next')");
  assert.equal(f.calls.at(-1), failedPath);
  assert.match(f.element('#users').innerHTML, /users-100/);
});

test('double clicks, refresh and logout cannot apply an obsolete page', async () => {
  const f = fixture();
  await f.run("loadAdminPage('users')");
  let complete;
  f.intercept = () => new Promise((resolve) => { complete = resolve; });
  const pending = f.run("changeAdminPage('users', 'next')");
  await f.run("changeAdminPage('users', 'next')");
  assert.equal(f.calls.length, 2);
  f.intercept = null;
  await f.run("loadAdminPage('users')");
  complete(f.reply({ users: [{ username: 'obsolete' }], next_cursor: 'obsolete' }));
  await pending;
  assert.doesNotMatch(f.element('#users').innerHTML, /obsolete/);
  f.intercept = () => new Promise((resolve) => { complete = resolve; });
  const logoutPending = f.run("changeAdminPage('users', 'next')");
  f.intercept = null;
  await f.run('logoutAdmin()');
  complete(f.reply({ users: [{ username: 'after-logout' }] }));
  await logoutPending;
  assert.equal(f.element('#users').innerHTML, '');
  assert.equal(f.element('#users-pagination').innerHTML, '');
});

test('failed first page offers retry and pagination controls are wired', async () => {
  const f = fixture();
  f.intercept = () => f.reply({ error: { message: 'try again' } }, 400);
  await f.run("loadAdminPage('users')");
  assert.match(f.element('#users-pagination').innerHTML, /data-admin-direction="refresh"/);
  f.intercept = null;
  await f.run("changeAdminPage('users', 'refresh')");
  const button = { disabled: false, dataset: { adminDirection: 'next' } };
  f.element('#users-pagination').listeners.click({ target: { closest: () => button } });
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(f.element('#users').innerHTML, /users-100/);
});
