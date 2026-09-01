#!/usr/bin/env node
'use strict';

const { createHash } = require('node:crypto');

const baseUrl = process.argv[2] || process.env.NORTHSTAR_URL || 'http://127.0.0.1:18080';
const executablePath = process.env.NORTHSTAR_CHROME
  || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const password = 'web-e2e-password-123';
const suffix = Date.now().toString(36);
const alice = `web_alice_${suffix}`;
const bob = `web_bob_${suffix}`;
const room = `web-room-${suffix}`;
const pageDiagnostics = new WeakMap();
const pageTransportCounters = new WeakMap();

function safeFrame(payload) {
  const text = String(payload || '');
  if (/<\s*(?:[A-Za-z_][\w.-]*:)?(?:authenticate|challenge|response|success|failure|token|initial-response|additional-data)\b/i.test(text)) {
    return '<sasl2-frame>[redacted]</sasl2-frame>';
  }
  return text.length > 2_000 ? `${text.slice(0, 2_000)}…[truncated]` : text;
}

function attachDiagnostics(name, page, failures) {
  const events = [];
  const remember = (event) => {
    events.push(event);
    if (events.length > 80) events.shift();
  };
  pageDiagnostics.set(page, events);
  const counters = { sentMessageFrames: 0, selfDeviceSubscriptions: 0, uploadSlotFilenames: [] };
  pageTransportCounters.set(page, counters);
  page.on('pageerror', (error) => {
    const event = `${name} page error: ${error.message}`;
    failures.push(event);
    remember(event);
  });
  page.on('console', (message) => {
    if (['error', 'warning'].includes(message.type())) remember(`${name} console ${message.type()}: ${message.text()}`);
  });
  page.on('requestfailed', (request) => {
    if (['document', 'script', 'stylesheet', 'wasm'].includes(request.resourceType())) {
      const event = `${name} request failed: ${request.url()} ${request.failure()?.errorText}`;
      failures.push(event);
      remember(event);
    }
  });
  page.on('websocket', (socket) => {
    remember(`${name} websocket opened: ${socket.url()}`);
    socket.on('framesent', (event) => {
      const payload = String(event.payload || '');
      if (/^<message\b/.test(payload)) counters.sentMessageFrames += 1;
      if (payload.includes("<subscribe node='urn:xmpp:omemo:2:devices'")
        && payload.match(/<iq\b[^>]*\bto='([^']+)'/)?.[1]
          === payload.match(/<subscribe\b[^>]*\bjid='([^']+)'/)?.[1]) {
        counters.selfDeviceSubscriptions += 1;
      }
      if (payload.includes("xmlns='urn:xmpp:http:upload:0'")) {
        const filename = payload.match(/<request\b[^>]*\bfilename='([^']+)'/)?.[1];
        if (filename) counters.uploadSlotFilenames.push(filename);
      }
      remember(`${name} WS > ${safeFrame(event.payload)}`);
    });
    socket.on('framereceived', (event) => remember(`${name} WS < ${safeFrame(event.payload)}`));
    socket.on('socketerror', (error) => remember(`${name} websocket error: ${error}`));
    socket.on('close', () => remember(`${name} websocket closed`));
  });
}

function check(condition, message) {
  if (!condition) throw new Error(message);
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function register(username) {
  const request = { username, password, invitation_token: null };
  const bodySha256 = createHash('sha256').update(canonicalJson(request)).digest('base64url');
  const challengeResponse = await fetch(`${baseUrl}/api/v1/anti-abuse/challenge`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      action: 'registration',
      intent: {
        version: 2,
        method: 'POST',
        path: '/api/v1/register',
        body_sha256: bodySha256,
      },
    }),
  });
  check(challengeResponse.status === 200, `could not obtain registration PoW: ${challengeResponse.status}`);
  const challenge = await challengeResponse.json();
  const waitSeconds = Math.max(
    Number(challenge.requirement.hard_wait_seconds || 0),
    Number(challenge.requirement.retry_after_seconds || 0),
  );
  if (waitSeconds > 0) await new Promise((resolve) => setTimeout(resolve, (waitSeconds * 1000) + 100));
  const factor = Math.max(1, Number(challenge.requirement.work_factor));
  const target = ((1n << 64n) - 1n) / BigInt(factor);
  let nonce = 0;
  for (;; nonce += 1) {
    const digest = createHash('sha256').update(challenge.prefix).update(String(nonce)).digest();
    if (digest.readBigUInt64BE(0) <= target) break;
  }
  let response;
  try {
    response = await fetch(`${baseUrl}/api/v1/register`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'idempotency-key': `web-e2e-register-${username}`,
      },
      body: JSON.stringify({
        ...request,
        pow: { challenge_id: challenge.challenge_id, nonce: String(nonce) },
      }),
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
    const diagnostics = pageDiagnostics.get(page) || [];
    throw new Error(
      `web login did not complete for ${username}: ${detail || error.message}\n${diagnostics.join('\n')}`,
    );
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

async function roomDiagnostics(page) {
  return page.evaluate(() => {
    const status = document.querySelector('#peer-status');
    const selected = document.querySelector('.conversation-item.active');
    return {
      status: status?.textContent?.trim(),
      statusData: status ? { ...status.dataset } : null,
      selected: selected?.dataset?.jid || null,
      roomTitle: document.querySelector('#peer-name')?.textContent?.trim(),
      retryVisible: Boolean(document.querySelector('[data-room-join-retry]')),
      toasts: [...document.querySelectorAll('.toast')].map((toast) => ({
        text: toast.textContent?.trim(),
        error: toast.classList.contains('error'),
      })),
    };
  });
}

async function waitForRoomJoinState(page, expected) {
  try {
    await page.waitForFunction(
      (value) => document.querySelector('#peer-status')?.dataset.joinState === value,
      expected,
      { timeout: 20_000 },
    );
  } catch (error) {
    throw new Error(
      `room join state did not reach ${expected}: ${JSON.stringify(await roomDiagnostics(page))}`,
      { cause: error },
    );
  }
}

async function holdInstantRoomConfiguration(page) {
  await page.evaluate(() => {
    const original = WebSocket.prototype.send;
    const pending = [];
    let released = false;
    WebSocket.prototype.send = function holdMucOwnerConfiguration(data) {
      if (!released && typeof data === 'string'
        && data.includes("http://jabber.org/protocol/muc#owner")
        && data.includes("type='submit'")) {
        pending.push([this, data]);
        document.documentElement.dataset.heldMucOwnerConfiguration = 'true';
        return;
      }
      return original.call(this, data);
    };
    globalThis.__northstarReleaseMucOwnerConfiguration = () => {
      if (released) return;
      released = true;
      WebSocket.prototype.send = original;
      for (const [socket, data] of pending.splice(0)) original.call(socket, data);
      document.documentElement.dataset.heldMucOwnerConfiguration = 'released';
    };
  });
}

async function releaseInstantRoomConfiguration(page) {
  await page.waitForFunction(
    () => document.documentElement.dataset.heldMucOwnerConfiguration === 'true',
    null,
    { timeout: 20_000 },
  );
  await page.evaluate(() => globalThis.__northstarReleaseMucOwnerConfiguration?.());
}

async function sendText(page, text) {
  await page.locator('#message-input').fill(text);
  await page.locator('#send-button').click();
  await page.locator('.message-row.outgoing .message-bubble', { hasText: text }).waitFor({ timeout: 30_000 });
}

async function waitForGroupMemberCount(page, count) {
  try {
    await page.waitForFunction(
      (expected) => document.querySelector('#peer-status')?.dataset.memberCount === String(expected),
      count,
      { timeout: 20_000 },
    );
  } catch (error) {
    throw new Error(
      `group status member count did not reach ${count}: ${JSON.stringify(await roomDiagnostics(page))}`,
      { cause: error },
    );
  }
  await page.locator('#contact-menu-button').click();
  try {
    await page.waitForFunction(
      (expected) => document.querySelectorAll('#room-member-list .member-card').length === expected,
      count,
      { timeout: 20_000 },
    );
  } catch (error) {
    const state = {
      ...await roomDiagnostics(page),
      members: await page.locator('#room-member-list .member-card').allTextContents(),
    };
    throw new Error(`group member list did not reach ${count}: ${JSON.stringify(state)}`, { cause: error });
  }
  await page.keyboard.press('Escape');
  await page.locator('#room-actions-dialog').waitFor({ state: 'hidden' });
}

async function waitForVerificationIdle(page) {
  await page.locator('#verify-dialog').waitFor({ state: 'visible', timeout: 30_000 });
  await page.waitForFunction(
    () => document.querySelector('#fingerprint-list')?.dataset.loading === 'false'
      && !document.querySelector('#refresh-devices')?.disabled,
    null,
    { timeout: 30_000 },
  );
}

async function verificationDiagnostics(page) {
  return page.evaluate(() => ({
    selectedPeer: document.querySelector('.conversation-item.active')?.getAttribute('data-jid') || null,
    dialogOpen: Boolean(document.querySelector('#verify-dialog')?.open),
    loading: document.querySelector('#fingerprint-list')?.dataset.loading || null,
    refreshDisabled: Boolean(document.querySelector('#refresh-devices')?.disabled),
    cards: [...document.querySelectorAll('#fingerprint-list .fingerprint-card')].map((card) => ({
      title: card.querySelector('strong')?.textContent?.trim() || null,
      status: card.querySelector('header span')?.textContent?.trim() || null,
      code: card.querySelector('code')?.textContent?.trim() || null,
      text: card.textContent?.trim() || null,
      actions: [...card.querySelectorAll('button')].map((button) => ({
        className: button.className,
        disabled: button.disabled,
        text: button.textContent?.trim(),
      })),
    })),
  }));
}

async function verifyAllVisibleOmemoDevices(page, expectedCount) {
  await page.locator('#verify-button').click();
  await waitForVerificationIdle(page);
  await page.locator('#refresh-devices').click();
  try {
    await waitForVerificationIdle(page);
    await page.waitForFunction(
      (expected) => document.querySelectorAll('#fingerprint-list .fingerprint-card').length === expected,
      expectedCount,
      { timeout: 30_000 },
    );
  } catch (error) {
    const diagnostics = await verificationDiagnostics(page);
    throw new Error(
      `OMEMO verification did not show exactly ${expectedCount} devices: ${JSON.stringify(diagnostics)}`,
      { cause: error },
    );
  }
  for (;;) {
    const verify = page.locator('#fingerprint-list .omemo-trust-verified').first();
    if (!await verify.count()) break;
    const before = await page.locator(
      '#fingerprint-list .fingerprint-card[data-trust-state="verified"]',
    ).count();
    await verify.click();
    await waitForVerificationIdle(page);
    await page.waitForFunction(
      ({ expected, verified }) => document.querySelectorAll(
        '#fingerprint-list .fingerprint-card',
      ).length === expected && document.querySelectorAll(
        '#fingerprint-list .fingerprint-card[data-trust-state="verified"]',
      ).length === verified,
      { expected: expectedCount, verified: before + 1 },
      { timeout: 30_000 },
    );
  }
  const verified = await page.locator(
    '#fingerprint-list .fingerprint-card[data-trust-state="verified"]',
  ).count();
  check(verified === expectedCount, `expected ${expectedCount} verified OMEMO devices, got ${verified}`);
}

async function acceptAllVisibleOmemoDevicesTofu(page, expectedCount) {
  await page.locator('#verify-button').click();
  await waitForVerificationIdle(page);
  await page.locator('#refresh-devices').click();
  await waitForVerificationIdle(page);
  await page.waitForFunction(
    (expected) => document.querySelectorAll('#fingerprint-list .fingerprint-card').length === expected,
    expectedCount,
    { timeout: 30_000 },
  );
  for (let index = 0; index < expectedCount; index += 1) {
    await page.locator('#fingerprint-list .omemo-trust-tofu').first().click();
    await waitForVerificationIdle(page);
    await page.waitForFunction(
      ({ expected, tofu }) => document.querySelectorAll(
        '#fingerprint-list .fingerprint-card',
      ).length === expected && document.querySelectorAll(
        '#fingerprint-list .fingerprint-card[data-trust-state="tofu"]',
      ).length === tofu,
      { expected: expectedCount, tofu: index + 1 },
      { timeout: 30_000 },
    );
  }
}

async function persistedEncryptedOutboxSummary(page) {
  return page.evaluate(async () => {
    const account = document.querySelector('#self-name')?.textContent?.trim() || '';
    const { getValue } = await import('/storage.js');
    const records = account ? await getValue('preferences', `encrypted-outbox:${account}`) : null;
    return {
      account,
      count: Array.isArray(records) ? records.length : 0,
      ids: Array.isArray(records) ? records.map((record) => record?.id).filter(Boolean) : [],
    };
  });
}

async function assertUnverifiedDevicesBlockSend(page, marker) {
  const messageFramesBefore = pageTransportCounters.get(page)?.sentMessageFrames || 0;
  const outboxBefore = await persistedEncryptedOutboxSummary(page);
  await page.evaluate(() => {
    globalThis.__northstarE2eComposerAbort?.abort();
    const controller = new AbortController();
    globalThis.__northstarE2eComposerAbort = controller;
    globalThis.__northstarE2eComposerTrace = { clicks: 0, submits: [] };
    document.querySelector('#send-button')?.addEventListener('click', () => {
      globalThis.__northstarE2eComposerTrace.clicks += 1;
    }, { capture: true, signal: controller.signal });
    document.querySelector('#message-form')?.addEventListener('submit', (event) => {
      const record = { defaultPrevented: event.defaultPrevented };
      globalThis.__northstarE2eComposerTrace.submits.push(record);
      // The product listener was registered during page bootstrap and runs
      // first on this same form. Preserve the page only when it failed to
      // prevent navigation; the recorded false value still fails the test.
      if (!event.defaultPrevented) event.preventDefault();
    }, { signal: controller.signal });
  });
  await page.locator('#message-input').fill(marker);
  const before = await page.evaluate(() => ({
    disabled: document.querySelector('#send-button')?.disabled,
    label: document.querySelector('#send-button')?.textContent?.trim(),
    input: document.querySelector('#message-input')?.value,
    formConnected: Boolean(document.querySelector('#message-form')?.isConnected),
    securityBanner: document.querySelector('#security-banner')?.textContent?.trim(),
    securityState: document.querySelector('#security-banner')?.dataset.securityState || null,
  }));
  check(before.input === marker && before.formConnected, `message composer was not ready: ${JSON.stringify(before)}`);
  if (before.disabled) {
    check(
      ['unresolved-devices', 'no-trusted-recipient'].includes(before.securityState),
      `disabled composer did not expose an explicit unresolved-device security state: ${JSON.stringify(before)}`,
    );
    check(
      (pageTransportCounters.get(page)?.sentMessageFrames || 0) === messageFramesBefore,
      'a disabled untrusted-device composer emitted an XMPP message frame',
    );
    check(
      await page.locator('.message-row.outgoing .message-bubble', { hasText: marker }).count() === 0,
      'a disabled untrusted-device composer created an outgoing message row',
    );
    const outboxAfter = await persistedEncryptedOutboxSummary(page);
    check(
      outboxAfter.count <= outboxBefore.count
        && outboxAfter.ids.every((id) => outboxBefore.ids.includes(id)),
      'a disabled untrusted-device composer staged an encrypted outbox record',
    );
    await page.locator('#message-input').fill('');
    return;
  }
  const errorToast = page.locator('.toast.error[data-code="send-failed-closed"]').last();
  await page.locator('#send-button').click();
  let toastText = '';
  let toastCode = '';
  try {
    await errorToast.waitFor({ timeout: 20_000 });
    toastText = await errorToast.textContent();
    toastCode = await errorToast.getAttribute('data-code');
    await page.waitForFunction(() => !document.querySelector('#send-button')?.disabled, null, { timeout: 20_000 });
  } catch (error) {
    const diagnostics = await page.evaluate((initial) => ({
      before: initial,
      sendButton: {
        disabled: document.querySelector('#send-button')?.disabled,
        label: document.querySelector('#send-button')?.textContent?.trim(),
      },
      toasts: [...document.querySelectorAll('.toast')].map((node) => node.textContent?.trim()),
      outgoing: [...document.querySelectorAll('.message-row.outgoing .message-bubble')]
        .map((node) => node.textContent?.trim()),
      securityBanner: document.querySelector('#security-banner')?.textContent?.trim(),
      selectedPeer: document.querySelector('#peer-jid')?.textContent?.trim(),
      composerTrace: globalThis.__northstarE2eComposerTrace,
    }), before);
    diagnostics.outbox = await persistedEncryptedOutboxSummary(page);
    diagnostics.sentMessageFrames = (pageTransportCounters.get(page)?.sentMessageFrames || 0)
      - messageFramesBefore;
    throw new Error(`unverified-device send did not fail closed: ${JSON.stringify(diagnostics)}`, { cause: error });
  }
  const composerTrace = await page.evaluate(() => globalThis.__northstarE2eComposerTrace);
  check(toastCode === 'send-failed-closed', `untrusted-device rejection lacked a semantic fail-closed error: ${toastText}`);
  check(
    composerTrace?.clicks === 1
      && composerTrace.submits.length === 1
      && composerTrace.submits[0].defaultPrevented === true,
    `message form did not enter exactly one prevented send handler: ${JSON.stringify(composerTrace)}`,
  );
  const messageFramesAfter = pageTransportCounters.get(page)?.sentMessageFrames || 0;
  const outboxAfter = await persistedEncryptedOutboxSummary(page);
  check(
    await page.locator('.message-row.outgoing .message-bubble', { hasText: marker }).count() === 0,
    'a TOFU device received an outbound OMEMO content key before verification',
  );
  check(
    messageFramesAfter === messageFramesBefore,
    'an XMPP message frame was emitted while an OMEMO device still lacked a trust decision',
  );
  check(
    outboxAfter.count <= outboxBefore.count
      && outboxAfter.ids.every((id) => outboxBefore.ids.includes(id)),
    'an encrypted outbox record was staged while an OMEMO device still lacked a trust decision',
  );
  await page.locator('#message-input').fill('');
}

async function main() {
  const { chromium } = require(
    process.env.NORTHSTAR_PLAYWRIGHT
      || 'C:/Users/Admin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright',
  );
  // Registration challenges are intentionally single-use per IP/action, so
  // parallel issuance would invalidate one challenge before it is submitted.
  await register(alice);
  await register(bob);
  const disableSandbox = process.env.NORTHSTAR_BROWSER_DISABLE_SANDBOX === 'true';
  if (disableSandbox) {
    console.warn('browser E2E is running with the Chrome sandbox explicitly disabled');
  }
  const browser = await chromium.launch({
    executablePath,
    headless: true,
    args: disableSandbox ? ['--no-sandbox'] : [],
  });
  const failures = [];
  try {
    const aliceContext = await browser.newContext({ acceptDownloads: true });
    const aliceSecondContext = await browser.newContext({ acceptDownloads: true });
    const bobContext = await browser.newContext({ acceptDownloads: true });
    const alicePage = await aliceContext.newPage();
    const aliceSecondPage = await aliceSecondContext.newPage();
    const bobPage = await bobContext.newPage();
    for (const [name, page] of [['alice', alicePage], ['alice-second', aliceSecondPage], ['bob', bobPage]]) {
      attachDiagnostics(name, page, failures);
    }

    // Two fresh resources intentionally initialize concurrently. XEP-0384
    // requires each resource to reannounce itself if the other's publication
    // overwrites the shared `current` device-list item.
    await Promise.all([login(alicePage, alice), login(aliceSecondPage, alice)]);
    await login(bobPage, bob);
    for (const page of [alicePage, aliceSecondPage, bobPage]) {
      check(
        pageTransportCounters.get(page)?.selfDeviceSubscriptions === 1,
        'OMEMO login did not establish exactly one explicit own-device PEP subscription before entering chat',
      );
    }
    const sealedOmemoState = await alicePage.evaluate(async (account) => {
      const { getValue } = await import('/storage.js');
      const record = await getValue('crypto', account);
      const wrappingKey = await getValue('preferences', `omemo-wrapping-key:${account}`);
      let exportRejected = false;
      try {
        await crypto.subtle.exportKey('raw', wrappingKey);
      } catch { exportRejected = true; }
      return {
        sealedVersion: record?.sealedVersion,
        hasCiphertext: typeof record?.ciphertext === 'string' && record.ciphertext.length > 32,
        leaksIdentityPair: Object.hasOwn(record || {}, 'identityKeyPair'),
        exportRejected,
      };
    }, `${alice}@localhost`);
    check(
      sealedOmemoState.sealedVersion === 1
        && sealedOmemoState.hasCiphertext
        && !sealedOmemoState.leaksIdentityPair
        && sealedOmemoState.exportRejected,
      'OMEMO private state was not sealed with a non-exportable browser key',
    );
    const strictOmemoParser = await alicePage.evaluate(async () => {
      const { OmemoManager, cryptoUtilities, buildEncryptedFileContent } = await import('/omemo.js?v=20260827-4');
      const documentFor = (xml) => new DOMParser().parseFromString(xml, 'application/xml');
      const valid = cryptoUtilities.parseDeviceList(
        documentFor("<devices xmlns='urn:xmpp:omemo:2'><device id='1' label='Phone' labelsig='ignored-until-verified'/><device id='2'/></devices>").documentElement,
      );
      let duplicateRejected = false;
      let unknownAttributeRejected = false;
      try {
        cryptoUtilities.parseDeviceList(
          documentFor("<devices xmlns='urn:xmpp:omemo:2'><device id='1'/><device id='1'/></devices>").documentElement,
        );
      } catch { duplicateRejected = true; }
      try {
        cryptoUtilities.parseDeviceList(
          documentFor("<devices xmlns='urn:xmpp:omemo:2' unsafe='true'><device id='1'/></devices>").documentElement,
        );
      } catch { unknownAttributeRejected = true; }
      const validEncrypted = cryptoUtilities.parseEncryptedElement(
        documentFor("<encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@localhost'><key rid='9' kex='true'>AQ==</key></keys></header></encrypted>").documentElement,
      );
      const key32 = btoa(String.fromCharCode(...new Uint8Array(32)));
      const signature64 = btoa(String.fromCharCode(...new Uint8Array(64)));
      const bundleXml = (count, signedKey = key32) => (
        "<bundle xmlns='urn:xmpp:omemo:2'>"
        + `<spk id='1'>${signedKey}</spk><spks>${signature64}</spks><ik>${key32}</ik><prekeys>`
        + Array.from({ length: count }, (_, index) => `<pk id='${index + 1}'>${key32}</pk>`).join('')
        + '</prekeys></bundle>'
      );
      const validBundlePrekeys = cryptoUtilities.parseBundleElement(
        documentFor(bundleXml(25)).documentElement,
        'bob@localhost',
        9,
      ).prekeys.length;
      let shortBundleRejected = false;
      let shortPublicKeyRejected = false;
      try {
        cryptoUtilities.parseBundleElement(
          documentFor(bundleXml(24)).documentElement,
          'bob@localhost',
          9,
        );
      } catch { shortBundleRejected = true; }
      try {
        cryptoUtilities.parseBundleElement(
          documentFor(bundleXml(25, 'AQID')).documentElement,
          'bob@localhost',
          9,
        );
      } catch { shortPublicKeyRejected = true; }
      let duplicateRecipientRejected = false;
      let invalidKexRejected = false;
      let reorderedEnvelopeRejected = false;
      let resourceRecipientRejected = false;
      try {
        cryptoUtilities.parseEncryptedElement(
          documentFor("<encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@localhost'><key rid='9'>AQ==</key><key rid='9'>Ag==</key></keys></header></encrypted>").documentElement,
        );
      } catch { duplicateRecipientRejected = true; }
      try {
        cryptoUtilities.parseEncryptedElement(
          documentFor("<encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@localhost'><key rid='9' kex='yes'>AQ==</key></keys></header></encrypted>").documentElement,
        );
      } catch { invalidKexRejected = true; }
      try {
        cryptoUtilities.parseEncryptedElement(
          documentFor("<encrypted xmlns='urn:xmpp:omemo:2'><payload>AQ==</payload><header sid='7'><keys jid='alice@localhost'><key rid='9'>AQ==</key></keys></header></encrypted>").documentElement,
        );
      } catch { reorderedEnvelopeRejected = true; }
      try {
        cryptoUtilities.parseEncryptedElement(
          documentFor("<encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@localhost/forged'><key rid='9'>AQ==</key></keys></header></encrypted>").documentElement,
        );
      } catch { resourceRecipientRejected = true; }
      const context = await cryptoUtilities.encryptEnvelope('context binding probe', {
        from: 'alice@localhost',
        to: 'room@conference.localhost',
      });
      const contextPlaintext = await cryptoUtilities.decryptEnvelope(
        context.keyAndTag,
        context.payload,
        { from: 'alice@localhost', to: 'room@conference.localhost', requireTo: true },
      );
      const rawSceEnvelope = async (xml) => {
        const contentKey = crypto.getRandomValues(new Uint8Array(32));
        const hkdfKey = await crypto.subtle.importKey('raw', contentKey, 'HKDF', false, ['deriveBits']);
        const bits = await crypto.subtle.deriveBits({
          name: 'HKDF',
          hash: 'SHA-256',
          salt: new Uint8Array(32),
          info: new TextEncoder().encode('OMEMO Payload'),
        }, hkdfKey, 640);
        const encryption = bits.slice(0, 32);
        const authentication = bits.slice(32, 64);
        const iv = bits.slice(64, 80);
        const aes = await crypto.subtle.importKey('raw', encryption, 'AES-CBC', false, ['encrypt']);
        const payloadBytes = await crypto.subtle.encrypt(
          { name: 'AES-CBC', iv }, aes, new TextEncoder().encode(xml),
        );
        const hmacKey = await crypto.subtle.importKey(
          'raw', authentication, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
        );
        const tag = (await crypto.subtle.sign('HMAC', hmacKey, payloadBytes)).slice(0, 16);
        const keyAndTag = new Uint8Array(48);
        keyAndTag.set(contentKey, 0);
        keyAndTag.set(new Uint8Array(tag), 32);
        const bytes = new Uint8Array(payloadBytes);
        let binary = '';
        for (let index = 0; index < bytes.length; index += 0x8000) {
          binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
        }
        return { keyAndTag: keyAndTag.buffer, payload: btoa(binary) };
      };
      const longPadding = await rawSceEnvelope(
        `<envelope xmlns='urn:xmpp:sce:1'><content><body xmlns='jabber:client'>long padding probe</body></content><rpad>${'x'.repeat(16_384)}</rpad><from jid='alice@localhost'/><to jid='bob@localhost'/></envelope>`,
      );
      const longPaddingPlaintext = await cryptoUtilities.decryptEnvelope(
        longPadding.keyAndTag,
        longPadding.payload,
        { from: 'alice@localhost', to: 'bob@localhost' },
      );
      const missingPadding = await rawSceEnvelope(
        "<envelope xmlns='urn:xmpp:sce:1'><content><body xmlns='jabber:client'>missing padding</body></content><from jid='alice@localhost'/><to jid='bob@localhost'/></envelope>",
      );
      let missingPaddingRejected = false;
      try {
        await cryptoUtilities.decryptEnvelope(
          missingPadding.keyAndTag,
          missingPadding.payload,
          { from: 'alice@localhost', to: 'bob@localhost' },
        );
      } catch { missingPaddingRejected = true; }
      let wrongRoomRejected = false;
      let groupToDirectRejected = false;
      let resourceAffixRejected = false;
      try {
        await cryptoUtilities.decryptEnvelope(
          context.keyAndTag,
          context.payload,
          { from: 'alice@localhost', to: 'other@conference.localhost', requireTo: true },
        );
      } catch { wrongRoomRejected = true; }
      try {
        await cryptoUtilities.decryptEnvelope(
          context.keyAndTag,
          context.payload,
          { from: 'alice@localhost', to: 'bob@localhost', requireTo: false },
        );
      } catch { groupToDirectRejected = true; }
      const resourceAffix = await rawSceEnvelope(
        "<envelope xmlns='urn:xmpp:sce:1'><content><body xmlns='jabber:client'>resource spoof</body></content><rpad>x</rpad><from jid='alice@localhost/forged'/><to jid='bob@localhost'/></envelope>",
      );
      try {
        await cryptoUtilities.decryptEnvelope(
          resourceAffix.keyAndTag,
          resourceAffix.payload,
          { from: 'alice@localhost', to: 'bob@localhost' },
        );
      } catch { resourceAffixRejected = true; }
      const zeros = btoa(String.fromCharCode(...new Uint8Array(32)));
      const encryptedFile = buildEncryptedFileContent({
        id: 'standard-file',
        url: 'http://127.0.0.1/test.encrypted',
        name: 'probe.txt',
        type: 'text/plain',
        size: 5,
        key: zeros,
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        hash: zeros,
        encryptedHash: zeros,
      });
      const fileDocument = documentFor(`<content xmlns='urn:xmpp:sce:1'>${encryptedFile.contentXml}</content>`);
      const parsedFile = cryptoUtilities.parseEncryptedFileSharing(
        [...fileDocument.documentElement.children].find((node) => node.localName === 'file-sharing'),
      );
      const trustContent = `<trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='bob@localhost'><trust>${zeros}</trust></key-owner></trust-message>`;
      const trustEnvelope = await cryptoUtilities.encryptEnvelope('', {
        from: 'alice@localhost',
        to: 'bob@localhost',
        timeStamp: '2026-08-26T00:00:00.000Z',
        contentXml: trustContent,
      });
      const parsedTrust = await cryptoUtilities.decryptEnvelope(
        trustEnvelope.keyAndTag,
        trustEnvelope.payload,
        {
          from: 'alice@localhost',
          to: 'bob@localhost',
          details: true,
          referenceTime: '2026-08-26T00:00:00.000Z',
        },
      );
      const receiptRequestEnvelope = await cryptoUtilities.encryptEnvelope('', {
        from: 'alice@localhost',
        contentXml: "<body xmlns='jabber:client'>receipt probe</body><request xmlns='urn:xmpp:receipts'/>",
      });
      const parsedReceiptRequest = await cryptoUtilities.decryptEnvelope(
        receiptRequestEnvelope.keyAndTag,
        receiptRequestEnvelope.payload,
        { from: 'alice@localhost', details: true },
      );
      const receiptResponseEnvelope = await cryptoUtilities.encryptEnvelope('', {
        from: 'bob@localhost',
        contentXml: "<received xmlns='urn:xmpp:receipts' id='receipt-probe'/>",
      });
      const parsedReceiptResponse = await cryptoUtilities.decryptEnvelope(
        receiptResponseEnvelope.keyAndTag,
        receiptResponseEnvelope.payload,
        { from: 'bob@localhost', details: true },
      );
      const encryptedChatStateEnvelope = await cryptoUtilities.encryptEnvelope('', {
        from: 'bob@localhost',
        contentXml: "<composing xmlns='http://jabber.org/protocol/chatstates'/>",
      });
      const parsedChatState = await cryptoUtilities.decryptEnvelope(
        encryptedChatStateEnvelope.keyAndTag,
        encryptedChatStateEnvelope.payload,
        { from: 'bob@localhost', details: true },
      );
      const manager = new OmemoManager({}, 'alice@localhost');
      manager.state = {
        lastTrustTimestamps: {},
        pendingTrustMessages: [],
        trustDecisions: {
          'bob@localhost.8': {
            identity: zeros,
            state: 'distrusted',
            updatedAt: '2026-08-25T00:00:00.000Z',
          },
        },
        identities: {},
        sessions: {},
      };
      manager.store = { persist: async () => {} };
      manager.fetchDeviceIds = async () => [8];
      manager.fetchBundle = async (jid, id) => ({ jid, id, identityKey: zeros });
      await manager.applyTrustMessage(
        'bob@localhost.7',
        new Date(Date.now() - 2000).toISOString(),
        [{ jid: 'mallory@localhost', entries: [{ identity: zeros, state: 'verified' }] }],
        true,
      );
      const thirdPartyTrustRejected = !manager.state.trustDecisions['mallory@localhost.8'];
      await manager.applyTrustMessage(
        'bob@localhost.7',
        new Date(Date.now() - 1000).toISOString(),
        [{ jid: 'bob@localhost', entries: [{ identity: zeros, state: 'verified' }] }],
        true,
      );
      const manualDistrustPreserved = manager.state.trustDecisions['bob@localhost.8'].state === 'distrusted';
      const sequence = [];
      await Promise.all([
        manager.withSessionOperation('bob@localhost.8', async () => {
          sequence.push('first-start');
          await new Promise((resolve) => setTimeout(resolve, 20));
          sequence.push('first-end');
        }),
        manager.withSessionOperation('bob@localhost.8', async () => sequence.push('second')),
      ]);
      return {
        valid,
        duplicateRejected,
        unknownAttributeRejected,
        validEncryptedSid: validEncrypted.senderDevice,
        validBundlePrekeys,
        shortBundleRejected,
        shortPublicKeyRejected,
        duplicateRecipientRejected,
        invalidKexRejected,
        reorderedEnvelopeRejected,
        resourceRecipientRejected,
        contextPlaintext,
        longPaddingPlaintext,
        missingPaddingRejected,
        wrongRoomRejected,
        groupToDirectRejected,
        resourceAffixRejected,
        standardFile: parsedFile.standard,
        standardFileName: parsedFile.name,
        trustOwner: parsedTrust.trustMessage?.[0]?.jid,
        trustStamp: parsedTrust.trustTimestamp,
        encryptedReceiptRequest: parsedReceiptRequest.receiptRequest,
        encryptedReceiptResponse: parsedReceiptResponse.receiptReceivedId,
        encryptedChatState: parsedChatState.chatState,
        thirdPartyTrustRejected,
        manualDistrustPreserved,
        sessionSequence: sequence.join(','),
      };
    });
    check(
      strictOmemoParser.valid.join(',') === '1,2'
        && strictOmemoParser.duplicateRejected
        && strictOmemoParser.unknownAttributeRejected
        && strictOmemoParser.validEncryptedSid === 7
        && strictOmemoParser.validBundlePrekeys === 25
        && strictOmemoParser.shortBundleRejected
        && strictOmemoParser.shortPublicKeyRejected
        && strictOmemoParser.duplicateRecipientRejected
        && strictOmemoParser.invalidKexRejected
        && strictOmemoParser.reorderedEnvelopeRejected
        && strictOmemoParser.resourceRecipientRejected
        && strictOmemoParser.contextPlaintext === 'context binding probe'
        && strictOmemoParser.longPaddingPlaintext === 'long padding probe'
        && strictOmemoParser.missingPaddingRejected
        && strictOmemoParser.wrongRoomRejected
        && strictOmemoParser.groupToDirectRejected
        && strictOmemoParser.resourceAffixRejected
        && strictOmemoParser.standardFile === 'XEP-0447/XEP-0448'
        && strictOmemoParser.standardFileName === 'probe.txt'
        && strictOmemoParser.trustOwner === 'bob@localhost'
        && strictOmemoParser.trustStamp === '2026-08-26T00:00:00.000Z'
        && strictOmemoParser.encryptedReceiptRequest
        && strictOmemoParser.encryptedReceiptResponse === 'receipt-probe'
        && strictOmemoParser.encryptedChatState === 'composing'
        && strictOmemoParser.thirdPartyTrustRejected
        && strictOmemoParser.manualDistrustPreserved
        && strictOmemoParser.sessionSequence === 'first-start,first-end,second',
      'strict OMEMO parser or SCE room-context binding accepted ambiguous input',
    );
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
    await assertUnverifiedDevicesBlockSend(bobPage, `TOFU block Bob ${suffix}`);
    await verifyAllVisibleOmemoDevices(bobPage, 2);
    check(
      await bobPage.locator('#fingerprint-list .fingerprint-card[data-trust-state="verified"]').count() === 2,
      'explicit OMEMO fingerprint verification was not persisted in the device list',
    );
    await bobPage.locator('#fingerprint-list .omemo-trust-distrusted').first().click();
    await waitForVerificationIdle(bobPage);
    await bobPage.locator('#fingerprint-list .fingerprint-card[data-trust-state="distrusted"]')
      .waitFor({ timeout: 30_000 });
    await bobPage.locator('#fingerprint-list .fingerprint-card[data-trust-state="distrusted"]')
      .locator('.omemo-trust-verified').click();
    await waitForVerificationIdle(bobPage);
    await bobPage.waitForFunction(
      () => document.querySelectorAll(
        '#fingerprint-list .fingerprint-card[data-trust-state="verified"]',
      ).length === 2,
      null,
      { timeout: 30_000 },
    );
    await bobPage.locator('#refresh-devices').click();
    await waitForVerificationIdle(bobPage);
    await bobPage.waitForFunction(
      () => document.querySelectorAll(
        '#fingerprint-list .fingerprint-card[data-trust-state="verified"]',
      ).length === 2,
      null,
      { timeout: 30_000 },
    );
    await bobPage.keyboard.press('Escape');
    await bobPage.locator('#verify-dialog').waitFor({ state: 'hidden' });

    const bobConversationOnAlice = alicePage.locator(`.conversation-item[data-jid="${bob}@localhost"]`);
    await bobConversationOnAlice.waitFor({ timeout: 20_000 });
    await bobConversationOnAlice.click();
    await assertUnverifiedDevicesBlockSend(alicePage, `TOFU block Alice ${suffix}`);
    // Alice explicitly accepts Bob and Alice's other browser profile using
    // TOFU. A freshly seen key was blocked above and is only eligible after
    // this user decision; it remains visibly distinct from verification.
    await acceptAllVisibleOmemoDevicesTofu(alicePage, 2);
    await alicePage.keyboard.press('Escape');
    await alicePage.locator('#verify-dialog').waitFor({ state: 'hidden' });

    const directMessage = `OMEMO direct ${suffix}`;
    await sendText(alicePage, directMessage);
    await bobPage.locator('.message-row.incoming .message-bubble', { hasText: directMessage }).waitFor({ timeout: 30_000 });
    check(await bobPage.locator('.message-row.incoming .message-meta .encrypted').count() > 0, 'direct message was not marked encrypted');
    await aliceSecondPage.locator('.message-row.outgoing .message-bubble', { hasText: directMessage }).waitFor({ timeout: 30_000 });

    const reply = `OMEMO reply ${suffix}`;
    await sendText(bobPage, reply);
    await alicePage.locator('.message-row.incoming .message-bubble', { hasText: reply }).waitFor({ timeout: 30_000 });
    const unverifiedReply = aliceSecondPage.locator('.message-row.incoming', { hasText: reply });
    await unverifiedReply.locator('.message-bubble').waitFor({ timeout: 30_000 });
    check(
      await unverifiedReply.locator(
        '.message-meta [data-security-state="encrypted-unverified"]',
      ).count() === 1,
      'incoming OMEMO from a TOFU device was presented as authenticated',
    );

    const attachmentBytes = Buffer.from(`Northstar encrypted attachment ${suffix}`, 'utf8');
    await alicePage.locator('#attachment-input').setInputFiles({
      name: 'northstar-e2e.txt',
      mimeType: 'text/plain',
      buffer: attachmentBytes,
    });
    const attachmentCard = bobPage.locator('.message-row.incoming .attachment-card', { hasText: 'northstar-e2e.txt' });
    await attachmentCard.waitFor({ timeout: 30_000 });
    const uploadSlotFilenames = pageTransportCounters.get(alicePage)?.uploadSlotFilenames || [];
    const uploadSlotFilename = uploadSlotFilenames.at(-1) || '';
    check(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.bin$/i.test(uploadSlotFilename),
      `encrypted upload disclosed a non-opaque slot filename: ${uploadSlotFilename || '[missing]'}`,
    );
    check(!uploadSlotFilename.includes('northstar-e2e'), 'encrypted upload disclosed the original filename in its slot IQ');
    const downloadPromise = bobPage.waitForEvent('download');
    await attachmentCard.locator('button').click();
    const download = await downloadPromise;
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    check(Buffer.concat(chunks).equals(attachmentBytes), 'downloaded attachment did not decrypt to its original bytes');

    // Hold the creator's instant-room form long enough to exercise the
    // XEP-0045 locked-room window deterministically. A non-owner is expected
    // to receive item-not-found until the owner submits the empty form.
    await holdInstantRoomConfiguration(alicePage);
    await joinGroup(alicePage, room, 'Alice');
    await waitForRoomJoinState(alicePage, 'configuring');
    await joinGroup(bobPage, room, 'Bob');
    await waitForRoomJoinState(bobPage, 'error');
    check(
      await bobPage.locator('#peer-status').getAttribute('data-join-error-condition') === 'item-not-found',
      `locked room did not fail closed with item-not-found: ${JSON.stringify(await roomDiagnostics(bobPage))}`,
    );
    check(
      await bobPage.locator('[data-room-join-retry]').count() === 1,
      'locked-room rejection did not expose an explicit retry action',
    );
    await releaseInstantRoomConfiguration(alicePage);
    await waitForRoomJoinState(alicePage, 'joined');
    await bobPage.locator('[data-room-join-retry]').click();
    await waitForRoomJoinState(bobPage, 'joined');
    await Promise.all([
      waitForGroupMemberCount(alicePage, 2),
      waitForGroupMemberCount(bobPage, 2),
    ]);
    const groupMessage = `OMEMO group ${suffix}`;
    await alicePage.waitForFunction(
      () => document.querySelector('#security-banner')?.dataset.securityState === 'ready',
      null,
      { timeout: 30_000 },
    );
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
    await adminPage.locator('#offline-stats').waitFor({ timeout: 20_000 });
    check(!/Loading/i.test(await adminPage.locator('#offline-stats').textContent()), 'administration offline queue did not load');
    check(await adminPage.locator('#sessions').count() === 1, 'administration session control panel is missing');
    check(await adminPage.locator('#rooms').count() === 1, 'administration room control panel is missing');
    check(await adminPage.locator('#operations').count() === 1, 'administration operation journal is missing');
    check(await adminPage.locator('#registration-toggle').isChecked(), 'administration runtime controls did not reflect open registration');
    check(await adminPage.locator('#reload-tls').isVisible(), 'administration TLS reload control is missing');
    check(await adminPage.locator('#panic-disconnect').isVisible(), 'administration emergency disconnect control is missing');
    const adminToken = await adminPage.evaluate(() => sessionStorage.getItem('admin_token'));
    check(Boolean(adminToken), 'administration bearer session was not established');
    const logoutResponse = adminPage.waitForResponse(
      (response) => response.url().endsWith('/api/v1/session') && response.request().method() === 'DELETE',
    );
    await adminPage.locator('#admin-logout').click();
    check((await logoutResponse).status() === 200, 'administration logout did not revoke the server session');
    const revokedStatus = await adminPage.evaluate(async (token) => {
      const response = await fetch('/api/v1/me', { headers: { Authorization: `Bearer ${token}` } });
      return response.status;
    }, adminToken);
    check(revokedStatus === 401, 'revoked administration bearer token remained usable');

    const mobileContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const mobilePage = await mobileContext.newPage();
    await mobilePage.goto(`${baseUrl}/client.html`, { waitUntil: 'domcontentloaded' });
    const overflow = await mobilePage.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    check(overflow <= 1, `mobile login layout overflows horizontally by ${overflow}px`);

    const removedDeviceId = await aliceSecondPage.locator('#own-device-id').textContent();
    await alicePage.locator('#verify-button').click();
    await alicePage.locator('#refresh-devices').click();
    const remoteDeviceCard = alicePage.locator('.fingerprint-card', { hasText: removedDeviceId })
      .filter({ has: alicePage.locator('.omemo-device-retire') });
    await remoteDeviceCard.waitFor({ timeout: 30_000 });
    alicePage.once('dialog', (dialog) => dialog.accept());
    await remoteDeviceCard.locator('.omemo-device-retire').click();
    await alicePage.waitForFunction(
      (deviceId) => ![...document.querySelectorAll('.fingerprint-card')]
        .some((card) => card.textContent.includes(deviceId)
          && card.querySelector('.omemo-device-retire')),
      removedDeviceId,
      { timeout: 30_000 },
    );
    await alicePage.keyboard.press('Escape');
    await alicePage.locator('#verify-dialog').waitFor({ state: 'hidden' });

    try {
      await aliceSecondPage.locator('#auth-view:not(.hidden)').waitFor({ timeout: 30_000 });
    } catch (error) {
      const diagnostics = await aliceSecondPage.evaluate(async (account) => {
        const { getValue } = await import('/storage.js');
        return {
          authHidden: document.querySelector('#auth-view')?.classList.contains('hidden'),
          chatHidden: document.querySelector('#chat-view')?.classList.contains('hidden'),
          ownDeviceId: document.querySelector('#own-device-id')?.textContent?.trim(),
          authSuccess: document.querySelector('#auth-success')?.textContent?.trim(),
          authError: document.querySelector('#auth-error')?.textContent?.trim(),
          cryptoPresent: await getValue('crypto', account) !== undefined,
          wrappingPresent: await getValue('preferences', `omemo-wrapping-key:${account}`) !== undefined,
          outboxPresent: await getValue('preferences', `encrypted-outbox:${account}`) !== undefined,
          toasts: [...document.querySelectorAll('.toast')].map((toast) => toast.textContent?.trim()),
        };
      }, `${alice}@localhost`);
      diagnostics.transport = pageDiagnostics.get(aliceSecondPage) || [];
      throw new Error(
        `remotely retired OMEMO endpoint did not fail closed: ${JSON.stringify(diagnostics)}`,
        { cause: error },
      );
    }
    const erased = await aliceSecondPage.evaluate(async (account) => {
      const { getValue } = await import('/storage.js');
      return {
        crypto: await getValue('crypto', account),
        wrapping: await getValue('preferences', `omemo-wrapping-key:${account}`),
        outbox: await getValue('preferences', `encrypted-outbox:${account}`),
        messageNodes: document.querySelector('#message-list')?.childElementCount,
      };
    }, `${alice}@localhost`);
    check(erased.crypto === undefined && erased.wrapping === undefined
      && erased.outbox === undefined && erased.messageNodes === 0,
    `remote retirement did not erase local OMEMO state for device ${removedDeviceId}`);

    await aliceConversation.click();
    const afterRevocation = `OMEMO after device revocation ${suffix}`;
    await sendText(bobPage, afterRevocation);
    await bobConversationOnAlice.click();
    await alicePage.locator('.message-row.incoming .message-bubble', { hasText: afterRevocation })
      .waitFor({ timeout: 30_000 });
    await aliceSecondPage.waitForTimeout(2_000);
    check(
      await aliceSecondPage.locator('.message-row.incoming .message-bubble', { hasText: afterRevocation }).count() === 0,
      `retired device ${removedDeviceId} still received a new OMEMO content key`,
    );

    await login(aliceSecondPage, alice);
    const replacementDeviceId = await aliceSecondPage.locator('#own-device-id').textContent();
    check(
      replacementDeviceId !== removedDeviceId,
      `fresh profile silently reused retired OMEMO device id ${removedDeviceId}`,
    );
    await bobConversationOnSecond.waitFor({ timeout: 20_000 });
    await bobConversationOnSecond.click();
    await assertUnverifiedDevicesBlockSend(aliceSecondPage, `Fresh device trust block ${suffix}`);

    const persistedRoomKey = `northstar:rooms:${alice}@localhost`;
    check(
      await alicePage.evaluate((key) => localStorage.getItem(key) !== null, persistedRoomKey),
      'room metadata fixture was not persisted before logout cleanup validation',
    );
    const logoutRevocation = alicePage.waitForRequest((request) => (
      request.url() === `${baseUrl}/api/v1/session` && request.method() === 'DELETE'
    ));
    await alicePage.locator('#logout-button').click();
    await logoutRevocation;
    await alicePage.locator('#auth-view:not(.hidden)').waitFor({ timeout: 10_000 });
    check(
      await alicePage.evaluate((key) => localStorage.getItem(key) === null, persistedRoomKey),
      'logout retained account-scoped room metadata',
    );

    await aliceSecondPage.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
      window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    });
    await aliceSecondPage.locator('#auth-view:not(.hidden)').waitFor({ timeout: 10_000 });
    const bfcacheLock = await aliceSecondPage.evaluate(() => ({
      loginPassword: document.querySelector('#login-password')?.value,
      registerPassword: document.querySelector('#register-password')?.value,
      messages: document.querySelector('#message-list')?.childElementCount,
      fingerprints: document.querySelector('#fingerprint-list')?.childElementCount,
      openDialogs: document.querySelectorAll('dialog[open]').length,
      reportDescription: document.querySelector('#report-description')?.value,
      chatHidden: document.querySelector('#chat-view')?.classList.contains('hidden'),
    }));
    check(
      bfcacheLock.loginPassword === ''
        && bfcacheLock.registerPassword === ''
        && bfcacheLock.messages === 0
        && bfcacheLock.fingerprints === 0
        && bfcacheLock.openDialogs === 0
        && bfcacheLock.reportDescription === ''
        && bfcacheLock.chatHidden,
      `BFCache restore did not remain locked with sensitive UI cleared: ${JSON.stringify(bfcacheLock)}`,
    );

    check(failures.length === 0, failures.join('\n'));
    console.log('web-e2e: concurrent/replaced OMEMO devices, explicit trust, remote revocation, multi-device direct delivery, group messages, encrypted upload/download, avatar, admin session revocation, dashboard and mobile layout passed');
  } finally {
    await browser.close();
  }
}

module.exports = { safeFrame };

if (require.main === module) {
  main().catch((error) => {
    console.error(error.stack || error);
    process.exitCode = 1;
  });
}
