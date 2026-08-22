#!/usr/bin/env node
'use strict';

const { chromium } = require(
  process.env.NORTHSTAR_PLAYWRIGHT
    || 'C:/Users/Admin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright',
);

const baseUrl = process.argv[2] || process.env.NORTHSTAR_URL || 'http://127.0.0.1:18080';
const executablePath = process.env.NORTHSTAR_CHROME
  || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const password = 'web-e2e-password-123';
const suffix = Date.now().toString(36);
const alice = `web_alice_${suffix}`;
const bob = `web_bob_${suffix}`;
const room = `web-room-${suffix}`;

function check(condition, message) {
  if (!condition) throw new Error(message);
}

async function register(username) {
  let response;
  try {
    response = await fetch(`${baseUrl}/api/v1/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
  } catch (error) {
    const cause = error.cause?.message || error.cause?.code || 'unknown network error';
    throw new Error(`registration request could not reach ${baseUrl}: ${cause}`, { cause: error });
  }
  check(response.status === 201, `registration failed for ${username}: ${response.status} ${await response.text()}`);
}

async function login(page, username) {
  await page.goto(`${baseUrl}/client.html`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(
    () => document.querySelector('#login-domain')?.textContent !== '@…',
    null,
    { timeout: 30_000 },
  );
  await page.locator('#login-username').fill(username);
  await page.locator('#login-password').fill(password);
  await page.locator('#login-form button[type="submit"]').click();
  try {
    await page.locator('#chat-view:not(.hidden)').waitFor({ timeout: 45_000 });
  } catch (error) {
    const detail = await page.locator('#auth-error').textContent().catch(() => '');
    throw new Error(`web login did not complete for ${username}: ${detail || error.message}`);
  }
  await page.waitForFunction(
    () => document.querySelector('#connection-label .presence.online')
      && !['', '—'].includes(document.querySelector('#own-device-id')?.textContent?.trim()),
    null,
    { timeout: 45_000 },
  );
}

async function addContact(page, jid) {
  await page.locator('#add-contact-button').click();
  await page.locator('#contact-jid').fill(jid);
  await page.locator('#contact-name').fill('Web E2E peer');
  await page.locator('#save-contact').click();
  await page.locator('#contact-dialog').waitFor({ state: 'hidden' });
}

async function joinGroup(page, localpart, nick) {
  await page.locator('#new-group-button').click();
  await page.locator('#group-room').fill(localpart);
  await page.locator('#group-name').fill('Web E2E Group');
  await page.locator('#group-nick').fill(nick);
  check(await page.locator('#group-room').inputValue() === localpart, 'group room input changed before submission');
  check(await page.locator('#group-nick').inputValue() === nick, 'group nickname input changed before submission');
  await page.locator('#join-group-button').click();
  await page.locator('#group-dialog').waitFor({ state: 'hidden' });
  await page.locator(`.conversation-item[data-jid="${localpart}@conference.localhost"]`).waitFor();
}

async function sendText(page, text) {
  await page.locator('#message-input').fill(text);
  await page.locator('#send-button').click();
  await page.locator('.message-row.outgoing .message-bubble', { hasText: text }).waitFor({ timeout: 30_000 });
}

async function waitForGroupMemberCount(page, count) {
  await page.waitForFunction(
    (expected) => document.querySelector('#peer-status')?.dataset.memberCount === String(expected),
    count,
    { timeout: 20_000 },
  );
  await page.locator('#contact-menu-button').click();
  try {
    await page.waitForFunction(
      (expected) => document.querySelectorAll('#room-member-list .member-card').length === expected,
      count,
      { timeout: 20_000 },
    );
  } catch (error) {
    const state = await page.evaluate(() => ({
      status: document.querySelector('#peer-status')?.textContent?.trim(),
      members: [...document.querySelectorAll('#room-member-list .member-card')]
        .map((member) => member.textContent?.trim()),
    }));
    throw new Error(`group member list did not reach ${count}: ${JSON.stringify(state)}`, { cause: error });
  }
  await page.keyboard.press('Escape');
  await page.locator('#room-actions-dialog').waitFor({ state: 'hidden' });
}

async function main() {
  await Promise.all([register(alice), register(bob)]);
  const browser = await chromium.launch({ executablePath, headless: true, args: ['--no-sandbox'] });
  const failures = [];
  try {
    const aliceContext = await browser.newContext({ acceptDownloads: true });
    const aliceSecondContext = await browser.newContext({ acceptDownloads: true });
    const bobContext = await browser.newContext({ acceptDownloads: true });
    const alicePage = await aliceContext.newPage();
    const aliceSecondPage = await aliceSecondContext.newPage();
    const bobPage = await bobContext.newPage();
    for (const [name, page] of [['alice', alicePage], ['alice-second', aliceSecondPage], ['bob', bobPage]]) {
      page.on('pageerror', (error) => failures.push(`${name} page error: ${error.message}`));
      page.on('requestfailed', (request) => {
        if (['document', 'script', 'stylesheet', 'wasm'].includes(request.resourceType())) {
          failures.push(`${name} request failed: ${request.url()} ${request.failure()?.errorText}`);
        }
      });
    }

    // Two fresh resources intentionally initialize concurrently. XEP-0384
    // requires each resource to reannounce itself if the other's publication
    // overwrites the shared `current` device-list item.
    await Promise.all([login(alicePage, alice), login(aliceSecondPage, alice)]);
    await login(bobPage, bob);
    check(
      await alicePage.locator('#own-device-id').textContent()
        !== await aliceSecondPage.locator('#own-device-id').textContent(),
      'independent browser profiles reused an OMEMO device ID',
    );
    await addContact(alicePage, `${bob}@localhost`);
    const approval = bobPage.locator('.toast.actionable', { hasText: `${alice}@localhost` });
    await approval.waitFor({ timeout: 20_000 });
    await approval.locator('button').click();
    const reciprocalApproval = alicePage.locator('.toast.actionable', { hasText: `${bob}@localhost` });
    await reciprocalApproval.waitFor({ timeout: 20_000 });
    await reciprocalApproval.locator('button').click();

    const aliceConversation = bobPage.locator(`.conversation-item[data-jid="${alice}@localhost"]`);
    const bobConversationOnSecond = aliceSecondPage.locator(`.conversation-item[data-jid="${bob}@localhost"]`);
    await bobConversationOnSecond.waitFor({ timeout: 20_000 });
    await bobConversationOnSecond.click();
    await aliceConversation.waitFor({ timeout: 20_000 });
    await aliceConversation.click();
    await bobPage.locator('#verify-button').click();
    await bobPage.locator('#refresh-devices').click();
    await bobPage.waitForFunction(
      () => document.querySelectorAll('#fingerprint-list .fingerprint-card').length === 2,
      null,
      { timeout: 30_000 },
    );
    await bobPage.keyboard.press('Escape');
    await bobPage.locator('#verify-dialog').waitFor({ state: 'hidden' });

    const directMessage = `OMEMO direct ${suffix}`;
    await sendText(alicePage, directMessage);
    await bobPage.locator('.message-row.incoming .message-bubble', { hasText: directMessage }).waitFor({ timeout: 30_000 });
    check(await bobPage.locator('.message-row.incoming .message-meta .encrypted').count() > 0, 'direct message was not marked encrypted');
    await aliceSecondPage.locator('.message-row.outgoing .message-bubble', { hasText: directMessage }).waitFor({ timeout: 30_000 });

    const reply = `OMEMO reply ${suffix}`;
    await sendText(bobPage, reply);
    await alicePage.locator('.message-row.incoming .message-bubble', { hasText: reply }).waitFor({ timeout: 30_000 });
    await aliceSecondPage.locator('.message-row.incoming .message-bubble', { hasText: reply }).waitFor({ timeout: 30_000 });

    const attachmentBytes = Buffer.from(`Northstar encrypted attachment ${suffix}`, 'utf8');
    await alicePage.locator('#attachment-input').setInputFiles({
      name: 'northstar-e2e.txt',
      mimeType: 'text/plain',
      buffer: attachmentBytes,
    });
    const attachmentCard = bobPage.locator('.message-row.incoming .attachment-card', { hasText: 'northstar-e2e.txt' });
    await attachmentCard.waitFor({ timeout: 30_000 });
    const downloadPromise = bobPage.waitForEvent('download');
    await attachmentCard.locator('button').click();
    const download = await downloadPromise;
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    check(Buffer.concat(chunks).equals(attachmentBytes), 'downloaded attachment did not decrypt to its original bytes');

    await Promise.all([
      joinGroup(alicePage, room, 'Alice'),
      joinGroup(bobPage, room, 'Bob'),
    ]);
    await Promise.all([
      waitForGroupMemberCount(alicePage, 2),
      waitForGroupMemberCount(bobPage, 2),
    ]);
    const groupMessage = `OMEMO group ${suffix}`;
    await sendText(alicePage, groupMessage);
    await bobPage.locator('.message-row.incoming .message-bubble', { hasText: groupMessage }).waitFor({ timeout: 30_000 });

    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zf8sAAAAASUVORK5CYII=', 'base64');
    await alicePage.locator('#avatar-input').setInputFiles({ name: 'avatar.png', mimeType: 'image/png', buffer: png });
    await alicePage.locator('#avatar-editor-dialog').waitFor({ state: 'visible', timeout: 20_000 });
    await alicePage.locator('#avatar-save').click();
    await alicePage.locator('#avatar-editor-dialog').waitFor({ state: 'hidden', timeout: 30_000 });
    await alicePage.waitForFunction(() => document.querySelector('#self-avatar')?.style.backgroundImage.startsWith('url('), null, { timeout: 20_000 });

    const adminContext = await browser.newContext();
    const adminPage = await adminContext.newPage();
    adminPage.on('pageerror', (error) => failures.push(`admin page error: ${error.message}`));
    await adminPage.goto(baseUrl, { waitUntil: 'domcontentloaded' });
    await adminPage.locator('#admin-username').fill(process.env.NORTHSTAR_ADMIN_USER || 'admin_it');
    await adminPage.locator('#admin-password').fill(process.env.NORTHSTAR_ADMIN_PASSWORD || 'integration-admin-password-123');
    await adminPage.locator('#admin-form button[type="submit"]').click();
    await adminPage.locator('#admin-content:not(.hidden)').waitFor({ timeout: 20_000 });
    check(await adminPage.locator('#stats .stat').count() >= 10, 'administration dashboard did not render all operational counters');
    check(await adminPage.locator('#users tr').count() >= 3, 'administration user table did not load');

    const mobileContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const mobilePage = await mobileContext.newPage();
    await mobilePage.goto(`${baseUrl}/client.html`, { waitUntil: 'domcontentloaded' });
    const overflow = await mobilePage.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    check(overflow <= 1, `mobile login layout overflows horizontally by ${overflow}px`);

    check(failures.length === 0, failures.join('\n'));
    console.log('web-e2e: concurrent same-account OMEMO devices, multi-device direct delivery, group messages, encrypted upload/download, avatar, admin dashboard and mobile layout passed');
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
