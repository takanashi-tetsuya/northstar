export const OUTBOX_ACK_SETTLE_MS = 1500;
export const OUTBOX_MAX_SERVER_RETRIES = 4;
export const OUTBOX_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const OUTBOX_CAPACITY = 100;
export const OUTBOX_MAX_PAYLOAD_BYTES = 1_000_000;

const RETRYABLE_WAIT_CONDITIONS = new Set([
  'internal-server-error',
  'remote-server-timeout',
  'resource-constraint',
  'service-unavailable',
]);

export function messageErrorDisposition(detail, previousRetries = 0) {
  const attempts = Number.isSafeInteger(previousRetries) && previousRetries >= 0
    ? previousRetries
    : 0;
  const retryable = detail?.errorType === 'wait'
    && (detail?.powRequired === true || RETRYABLE_WAIT_CONDITIONS.has(detail?.condition));
  if (!retryable) return { kind: 'terminal', retryCount: attempts };
  const retryCount = attempts + 1;
  if (retryCount > OUTBOX_MAX_SERVER_RETRIES) {
    return { kind: 'terminal', retryCount, exhausted: true };
  }
  return { kind: 'retry', retryCount };
}

export function prepareFreshProofAttempt(record) {
  if (!record || typeof record.basePayload !== 'string' || !record.basePayload) {
    throw new Error('A ciphertext outbox retry requires the original pow-less payload');
  }
  return {
    ...record,
    payload: record.basePayload,
    powPending: true,
    proofChallengeId: null,
    deliveryState: 'proof-pending',
  };
}

/**
 * XEP-0198 acknowledges stream handling, not application success. Keep a
 * short ordered-error window before deleting ciphertext from the outbox.
 * A message error observed before or after the ACK cancels settlement.
 */
export class AckSettlementWindow {
  constructor({
    settleMs = OUTBOX_ACK_SETTLE_MS,
    schedule = (callback, delay) => setTimeout(callback, delay),
    cancel = (timer) => clearTimeout(timer),
  } = {}) {
    this.settleMs = settleMs;
    this.schedule = schedule;
    this.cancelTimer = cancel;
    this.timers = new Map();
    this.failedAttempts = new Set();
  }

  beginAttempt(id) {
    this.cancel(id);
    this.failedAttempts.delete(id);
  }

  recordError(id) {
    this.failedAttempts.add(id);
    this.cancel(id);
  }

  recordAck(id, settle) {
    if (this.failedAttempts.has(id)) return false;
    this.cancel(id);
    const timer = this.schedule(() => {
      this.timers.delete(id);
      if (!this.failedAttempts.has(id)) settle(id);
    }, this.settleMs);
    this.timers.set(id, timer);
    return true;
  }

  cancel(id) {
    const timer = this.timers.get(id);
    if (timer !== undefined) this.cancelTimer(timer);
    this.timers.delete(id);
  }

  forget(id) {
    this.cancel(id);
    this.failedAttempts.delete(id);
  }

  clear() {
    for (const id of this.timers.keys()) this.cancel(id);
    this.failedAttempts.clear();
  }
}
