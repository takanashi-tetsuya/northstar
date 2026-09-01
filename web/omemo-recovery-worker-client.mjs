import {
  OMEMO_TRANSFER_MAX_BYTES,
  OMEMO_TRANSFER_MAX_STATE_BYTES,
} from './omemo-recovery.mjs';

const MIB = 1024 * 1024;
const WORKER_URL = new URL('./omemo-recovery-worker.mjs', import.meta.url);
const WORKER_DEADLINE_MS = 120_000;

export function omemoTransferMemoryBudget({
  deviceMemoryGiB = null,
  inputBytes = 0,
  operation,
}) {
  if (!['create', 'open'].includes(operation)
    || !Number.isSafeInteger(inputBytes) || inputBytes < 0
    || inputBytes > OMEMO_TRANSFER_MAX_BYTES) {
    throw new Error('OMEMO transfer memory budget input is invalid');
  }
  const reported = Number(deviceMemoryGiB);
  const available = Number.isFinite(reported) && reported > 0
    ? Math.floor(reported * 1024 * MIB * 0.2)
    : 256 * MIB;
  const budgetBytes = Math.min(512 * MIB, Math.max(128 * MIB, available));
  // Argon2id reserves 64 MiB. JSON/UTF-8/Base64, structured clone and AES-GCM
  // may coexist briefly, so use a deliberately conservative 4x expansion.
  const workingSetInput = operation === 'open' ? inputBytes : OMEMO_TRANSFER_MAX_STATE_BYTES;
  const requiredBytes = 96 * MIB + workingSetInput * 4;
  return Object.freeze({ allowed: requiredBytes <= budgetBytes, requiredBytes, budgetBytes });
}

function assertWorkerBudget(operation, inputBytes) {
  const estimate = omemoTransferMemoryBudget({
    deviceMemoryGiB: navigator.deviceMemory,
    inputBytes,
    operation,
  });
  if (!estimate.allowed) {
    throw new Error('This device does not report enough safe memory for the selected OMEMO transfer package.');
  }
}

function runRecoveryWorker(operation, payload, transfer = [], { signal, deadlineMs = WORKER_DEADLINE_MS } = {}) {
  if (typeof Worker !== 'function') {
    throw new Error('OMEMO device transfer requires a dedicated Web Worker in this browser.');
  }
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER_URL, { type: 'module', name: 'northstar-omemo-recovery' });
    let settled = false;
    let deadline;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      signal?.removeEventListener('abort', abort);
      worker.terminate();
      callback(value);
    };
    const abort = () => finish(reject, new DOMException('OMEMO device transfer was cancelled.', 'AbortError'));
    if (signal?.aborted) return abort();
    signal?.addEventListener('abort', abort, { once: true });
    deadline = setTimeout(() => finish(reject, new DOMException(
      'OMEMO device transfer exceeded its safety deadline.', 'TimeoutError',
    )), deadlineMs);
    worker.onmessage = ({ data }) => {
      if (data?.ok) finish(resolve, data.result);
      else finish(reject, new Error(data?.error || 'OMEMO transfer worker failed closed.'));
    };
    worker.onerror = () => finish(reject, new Error('OMEMO transfer worker crashed and was terminated.'));
    worker.onmessageerror = () => finish(reject, new Error('OMEMO transfer worker returned an invalid result.'));
    try {
      worker.postMessage({ operation, payload }, transfer);
    } catch (error) {
      finish(reject, error);
    }
  });
}

export function createOmemoTransferPackageInWorker({ metadata, state, passphrase, signal }) {
  assertWorkerBudget('create', 0);
  return runRecoveryWorker('create', { metadata, state, passphrase }, [], { signal });
}

export function openOmemoTransferPackageInWorker({
  packageBuffer, expectedAccount, passphrase, now = Date.now(), signal,
}) {
  if (!(packageBuffer instanceof ArrayBuffer)) throw new Error('OMEMO transfer package buffer is invalid');
  assertWorkerBudget('open', packageBuffer.byteLength);
  return runRecoveryWorker('open', {
    packageBuffer,
    expectedAccount,
    passphrase,
    now,
  }, [packageBuffer], { signal });
}
