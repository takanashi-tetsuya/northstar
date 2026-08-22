const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

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

export async function acquireProof(request, action, update) {
  const challenge = await request('/api/v1/anti-abuse/challenge', {
    method: 'POST',
    body: JSON.stringify({ action }),
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
