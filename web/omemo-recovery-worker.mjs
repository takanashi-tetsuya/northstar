import {
  createOmemoTransferPackage,
  openOmemoTransferPackage,
} from './omemo-recovery.mjs';

await import('./crypto/hash-wasm-argon2.umd.min.js');

function safeError(error) {
  const message = typeof error?.message === 'string' ? error.message : 'OMEMO transfer failed closed.';
  return message.slice(0, 512);
}

self.onmessage = async ({ data }) => {
  const operation = data?.operation;
  const payload = data?.payload;
  if (!payload || typeof payload !== 'object') {
    self.postMessage({ ok: false, error: 'OMEMO transfer worker request is invalid.' });
    return;
  }
  try {
    if (typeof globalThis.hashwasm?.argon2id !== 'function') {
      throw new Error('The pinned Argon2id worker implementation is unavailable.');
    }
    if (operation === 'create') {
      const result = await createOmemoTransferPackage({
        metadata: payload.metadata,
        state: payload.state,
        passphrase: payload.passphrase,
        argon2id: globalThis.hashwasm.argon2id,
      });
      self.postMessage({
        ok: true,
        result: {
          serialized: result.serialized,
          sha256: result.sha256,
          metadata: result.metadata,
        },
      });
      return;
    }
    if (operation === 'open') {
      if (!(payload.packageBuffer instanceof ArrayBuffer)) {
        throw new Error('The OMEMO transfer package buffer is invalid.');
      }
      const input = new Uint8Array(payload.packageBuffer);
      const result = await openOmemoTransferPackage({
        serialized: input,
        expectedAccount: payload.expectedAccount,
        passphrase: payload.passphrase,
        argon2id: globalThis.hashwasm.argon2id,
        now: payload.now,
      });
      input.fill(0);
      self.postMessage({ ok: true, result }, [result.packageBytes.buffer]);
      return;
    }
    throw new Error('OMEMO transfer worker operation is unsupported.');
  } catch (error) {
    if (payload.packageBuffer instanceof ArrayBuffer && payload.packageBuffer.byteLength) {
      new Uint8Array(payload.packageBuffer).fill(0);
    }
    self.postMessage({ ok: false, error: safeError(error) });
  } finally {
    payload.passphrase = '';
    payload.state = null;
    payload.packageBuffer = null;
  }
};
