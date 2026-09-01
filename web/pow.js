const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const scalarOrder = (left, right) => {
      const leftScalars = [...left];
      const rightScalars = [...right];
      for (let index = 0; index < Math.min(leftScalars.length, rightScalars.length); index += 1) {
        const difference = leftScalars[index].codePointAt(0) - rightScalars[index].codePointAt(0);
        if (difference) return difference;
      }
      return leftScalars.length - rightScalars.length;
    };
    return `{${Object.keys(value).sort(scalarOrder).map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('Unsupported proof-of-work intent value');
}

function base64Url(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

async function sha256Base64Url(value) {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

export async function httpPowIntent(path, body, method = 'POST') {
  if (!['POST', 'PATCH'].includes(method)) throw new Error('Unsupported HTTP proof-of-work method');
  return {
    version: 2,
    method,
    path,
    body_sha256: await sha256Base64Url(canonicalJson(body)),
  };
}

export async function xmppPowIntent(path, canonicalStanza) {
  return {
    version: 2,
    method: 'XMPP',
    path,
    body_sha256: await sha256Base64Url(canonicalStanza),
  };
}

async function waitForCooldown(seconds, update) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    const remaining = Math.max(1, Math.ceil((deadline - Date.now()) / 1000));
    update?.({ phase: 'waiting', remaining });
    await sleep(Math.min(1000, Math.max(100, deadline - Date.now())));
  }
  await sleep(150);
}

function solveChallenge(challenge, update) {
  const factor = Number(challenge.requirement.work_factor);
  if (factor <= 1) return Promise.resolve({ nonce: '0', hashes: 1, elapsedMs: 0 });
  return new Promise((resolve, reject) => {
    const worker = new Worker('/pow-worker.js?v=20260813-1');
    const timeout = setTimeout(() => {
      worker.terminate();
      reject(new Error('Proof-of-work calculation timed out'));
    }, Math.max(30_000, (Number(challenge.expires_in_seconds) + 5) * 1000));
    worker.addEventListener('message', (event) => {
      if (event.data.type === 'progress') update?.({ phase: 'working', ...event.data, factor });
      if (event.data.type !== 'solved') return;
      clearTimeout(timeout);
      worker.terminate();
      resolve(event.data);
    });
    worker.addEventListener('error', (event) => {
      clearTimeout(timeout);
      worker.terminate();
      reject(new Error(event.message || 'Proof-of-work worker failed'));
    });
    worker.postMessage({ prefix: challenge.prefix, workFactor: factor });
  });
}

export async function acquireProof(request, action, update, context = {}) {
  if (!context.intent) throw new Error('Proof-of-work v2 requires an operation intent');
  const challenge = await request('/api/v1/anti-abuse/challenge', {
    method: 'POST',
    body: JSON.stringify({ action, ...context }),
  });
  const requirement = challenge.requirement;
  const waitSeconds = Math.max(
    Number(requirement.hard_wait_seconds || 0),
    Number(requirement.retry_after_seconds || 0),
  );
  update?.({ phase: 'issued', requirement });
  if (waitSeconds > 0) await waitForCooldown(waitSeconds, update);
  update?.({ phase: 'working', hashes: 0, elapsedMs: 0, factor: Number(requirement.work_factor) });
  const result = await solveChallenge(challenge, update);
  update?.({ phase: 'solved', requirement, ...result });
  return {
    challenge_id: challenge.challenge_id,
    nonce: result.nonce,
  };
}
