import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { encodeEd25519Pkcs8V2 } from './generate-cluster-signing-key.mjs';

function pair() {
  const keys = generateKeyPairSync('ed25519');
  return { ...keys,
    privateDer: keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
    publicDer: keys.publicKey.export({ format: 'der', type: 'spki' }),
  };
}

test('strict v2 contains the derived public component and signs with the same identity', () => {
  const keys = pair();
  const v2 = encodeEd25519Pkcs8V2(keys.privateDer, keys.publicDer);
  assert.equal(v2.length, 83);
  assert.equal(v2.subarray(0, 16).toString('hex'), '3051020101300506032b657004220420');
  assert.equal(v2.subarray(48, 51).toString('hex'), '812100');
  assert.deepEqual(v2.subarray(51), keys.publicDer.subarray(12));
  // Older Node/OpenSSL providers cannot import v2. Validate its explicit seed
  // and public fields while using the corresponding v1 container for signing;
  // the runtime's strict ring parser is exercised by the real cluster fixture.
  const v1 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), v2.subarray(16, 48)]);
  const imported = createPrivateKey({ key: v1, format: 'der', type: 'pkcs8' });
  const message = Buffer.from('Northstar cluster key generator interoperability');
  assert.ok(verify(null, message, keys.publicKey, sign(null, message, imported)));
  assert.deepEqual(createPublicKey(imported).export({ format: 'der', type: 'spki' }), keys.publicDer);
});

test('reject unsupported private/public encodings and mismatched key pairs', () => {
  const keys = pair();
  const badOid = Buffer.from(keys.privateDer);
  badOid[11] ^= 1;
  for (const invalid of [keys.privateDer.subarray(1), Buffer.concat([keys.privateDer, Buffer.from([0])]), badOid]) {
    assert.throws(() => encodeEd25519Pkcs8V2(invalid, keys.publicDer), /PrivateKeyInfo/);
  }
  const badPublic = Buffer.from(keys.publicDer);
  badPublic[8] ^= 1;
  for (const invalid of [keys.publicDer.subarray(1), badPublic]) {
    assert.throws(() => encodeEd25519Pkcs8V2(keys.privateDer, invalid), /SubjectPublicKeyInfo/);
  }
  assert.throws(() => encodeEd25519Pkcs8V2(keys.privateDer, pair().publicDer), /do not match/);
});

test('CLI preserves owner-only exclusive output and never prints private material', () => {
  const directory = mkdtempSync(join(tmpdir(), 'northstar-cluster-key-test-'));
  try {
    const privatePath = join(directory, 'private.b64');
    const publicPath = join(directory, 'public.b64');
    const opensslPath = join(directory, 'openssl.der');
    const script = fileURLToPath(new URL('./generate-cluster-signing-key.mjs', import.meta.url));
    const run = () => spawnSync(process.execPath, [script, privatePath, publicPath, opensslPath], { encoding: 'utf8' });
    const first = run();
    assert.equal(first.status, 0, first.stderr);
    const privateText = readFileSync(privatePath, 'utf8').trim();
    const publicText = readFileSync(publicPath, 'utf8').trim();
    assert.ok(!first.stdout.includes(privateText));
    assert.equal(Buffer.from(privateText, 'base64url').length, 83);
    assert.equal(Buffer.from(publicText, 'base64url').length, 32);
    const opensslDer = readFileSync(opensslPath);
    assert.equal(opensslDer.length, 48);
    const signer = createPrivateKey({ key: opensslDer, format: 'der', type: 'pkcs8' });
    const verifier = createPublicKey({ key: Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicText, 'base64url'),
    ]), format: 'der', type: 'spki' });
    const message = Buffer.from('fixture signer must match runtime public identity');
    assert.ok(verify(null, message, verifier, sign(null, message, signer)));
    if (process.platform !== 'win32') {
      for (const file of [privatePath, publicPath, opensslPath]) assert.equal(statSync(file).mode & 0o777, 0o600);
    }
    const second = run();
    assert.equal(second.status, 2);
    assert.match(second.stderr, /refusing to overwrite/);
    assert.equal(readFileSync(privatePath, 'utf8').trim(), privateText);
    assert.equal(readFileSync(publicPath, 'utf8').trim(), publicText);
    assert.deepEqual(readFileSync(opensslPath), opensslDer);
  } finally {
    for (const file of ['private.b64', 'public.b64', 'openssl.der']) rmSync(join(directory, file), { force: true });
    rmdirSync(directory);
  }
});

test('CLI rejects overlapping outputs and never overwrites an existing OpenSSL copy', () => {
  const directory = mkdtempSync(join(tmpdir(), 'northstar-cluster-key-collision-test-'));
  const files = ['private.b64', 'public.b64', 'openssl.der'].map((file) => join(directory, file));
  const script = fileURLToPath(new URL('./generate-cluster-signing-key.mjs', import.meta.url));
  const run = (paths) => spawnSync(process.execPath, [script, ...paths], { encoding: 'utf8' });
  try {
    for (const paths of [
      [files[0], files[0]], [files[0], files[1], files[0]], [files[0], files[1], files[1]],
    ]) {
      const result = run(paths);
      assert.equal(result.status, 2);
      assert.match(result.stderr, /paths must differ/);
      assert.ok(files.every((file) => !existsSync(file)));
    }
    const sentinel = Buffer.from('preexisting fixture key remains untouched');
    writeFileSync(files[2], sentinel, { flag: 'wx', mode: 0o600 });
    const result = run(files);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /refusing to overwrite/);
    assert.deepEqual(readFileSync(files[2]), sentinel);
  } finally {
    for (const file of files) rmSync(file, { force: true });
    rmdirSync(directory);
  }
});
