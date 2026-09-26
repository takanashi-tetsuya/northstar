import { createHash, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const archive = resolve(root, 'third_party/hash-wasm/hash-wasm-4.12.0.tgz');
const evidencePath = resolve(root, 'third_party/hash-wasm/npm-registry-signature-4.12.0.json');
const deployedPath = resolve(root, 'web/crypto/hash-wasm-argon2.umd.min.js');

// Pin the historical npm signing key independently of the captured registry response.
const expected = Object.freeze({
  package: 'hash-wasm',
  version: '4.12.0',
  tarballSha256: '1db32a125fb46177932ec8ac438d3cd8214ebdfaccb5d6611b657d88eb586f92',
  artifactSha256: 'dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094',
  registryReportedPublishedAt: '2024-11-19T19:01:58.186Z',
  keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
  spkiDerBase64: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
  keyExpires: '2025-01-29T00:00:00.000Z',
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function hash(algorithm, bytes, encoding = 'hex') {
  return createHash(algorithm).update(bytes).digest(encoding);
}

function base64(value, label) {
  invariant(typeof value === 'string' && /^[A-Za-z0-9+/]+={0,2}$/.test(value), `${label} is not base64`);
  const bytes = Buffer.from(value, 'base64');
  invariant(bytes.toString('base64') === value, `${label} has noncanonical base64 encoding`);
  return bytes;
}

function verifyEvidence(evidence, tarball, deployed, archiveArtifact, packageJson) {
  invariant(evidence.package === expected.package && evidence.version === expected.version,
    'npm package identity changed');
  invariant(evidence.metadataUrl === 'https://registry.npmjs.org/hash-wasm/4.12.0' &&
    evidence.packumentUrl === 'https://registry.npmjs.org/hash-wasm' &&
    evidence.tarballUrl === 'https://registry.npmjs.org/hash-wasm/-/hash-wasm-4.12.0.tgz',
  'npm registry location changed');
  invariant(evidence.registryReportedPublishedAt === expected.registryReportedPublishedAt &&
    Date.parse(evidence.registryReportedPublishedAt) < Date.parse(expected.keyExpires),
  'npm registry reports publication after the historical key expired');
  invariant(packageJson.name === expected.package && packageJson.version === expected.version,
    'vendored tarball has a different package identity');
  invariant(evidence.tarballSha256 === expected.tarballSha256 &&
    hash('sha256', tarball) === expected.tarballSha256,
  'vendored tarball SHA-256 differs from the pinned release');
  invariant(evidence.shasumSha1 === hash('sha1', tarball), 'npm SHA-1 differs from the tarball');
  invariant(evidence.integrity === `sha512-${hash('sha512', tarball, 'base64')}`,
    'npm SRI differs from the tarball');

  const key = evidence.signingKey;
  invariant(evidence.signature?.keyid === expected.keyid && key?.keyid === expected.keyid &&
    key.spkiDerBase64 === expected.spkiDerBase64 &&
    key.source === 'https://registry.npmjs.org/-/npm/v1/keys' &&
    key.keytype === 'ecdsa-sha2-nistp256' && key.scheme === 'ecdsa-sha2-nistp256' &&
    key.expires === expected.keyExpires,
  'npm registry signing key differs from the pinned historical key');
  const signedMessage = Buffer.from(`${expected.package}@${expected.version}:${evidence.integrity}`);
  invariant(verify('sha256', signedMessage, {
    key: base64(key.spkiDerBase64, 'npm public key'),
    format: 'der',
    type: 'spki',
  }, base64(evidence.signature.sig, 'npm signature')),
  'npm registry signature is invalid');

  invariant(hash('sha256', deployed) === expected.artifactSha256,
    'deployed Argon2 artifact differs from the pinned release');
  invariant(deployed.equals(archiveArtifact),
    'deployed Argon2 artifact differs from the signed npm tarball');
}

function archiveFiles(tarball) {
  invariant(hash('sha256', tarball) === expected.tarballSha256,
    'vendored tarball changed before parsing');
  const bytes = gunzipSync(tarball, { maxOutputLength: 4 * 1024 * 1024 });
  const wanted = new Set(['package/package.json', 'package/dist/argon2.umd.min.js']);
  const found = new Map();
  const paths = new Set();
  for (let offset = 0; offset + 512 <= bytes.length;) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const path = header.subarray(0, 100).toString('utf8').split('\0', 1)[0];
    const sizeText = header.subarray(124, 136).toString('ascii').split('\0', 1)[0].trim();
    invariant(/^[0-7]+$/.test(sizeText), `invalid tar entry size: ${path}`);
    const size = Number.parseInt(sizeText, 8);
    const dataStart = offset + 512;
    invariant(dataStart + size <= bytes.length, `truncated tar entry: ${path}`);
    if (header[156] === 0 || header[156] === 0x30) paths.add(path);
    if (wanted.has(path)) {
      invariant(!found.has(path) && (header[156] === 0 || header[156] === 0x30),
        `duplicate or non-file tar entry: ${path}`);
      found.set(path, Buffer.from(bytes.subarray(dataStart, dataStart + size)));
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  for (const path of wanted) invariant(found.has(path), `npm tarball lacks ${path}`);
  return { found, paths };
}

function requireReproducibleSourceBuild(paths) {
  const missing = [
    'package/wasm/argon2.wasm.json',
    'package/scripts/build.sh',
  ].filter((path) => !paths.has(path));
  if (!['package/package-lock.json', 'package/npm-shrinkwrap.json',
    'package/yarn.lock', 'package/pnpm-lock.yaml'].some((path) => paths.has(path))) {
    missing.push('a dependency lockfile');
  }
  invariant(missing.length === 0,
    `hash-wasm 4.12.0 source rebuild is unqualified: npm package lacks ${missing.join(', ')}`);
  throw new Error('hash-wasm 4.12.0 source rebuild is unqualified: two independent clean builds and toolchain evidence are missing');
}

function expectRejected(label, evidence, tarball, deployed, archiveArtifact, packageJson) {
  let rejected = false;
  try {
    verifyEvidence(evidence, tarball, deployed, archiveArtifact, packageJson);
  } catch {
    rejected = true;
  }
  invariant(rejected, `${label} passed provenance verification`);
}

const [evidenceBytes, tarball, deployed] = await Promise.all([
  readFile(evidencePath),
  readFile(archive),
  readFile(deployedPath),
]);
const evidence = JSON.parse(evidenceBytes.toString('utf8'));
const { found: files, paths } = archiveFiles(tarball);
const archiveArtifact = files.get('package/dist/argon2.umd.min.js');
const packageJson = JSON.parse(files.get('package/package.json').toString('utf8'));
verifyEvidence(evidence, tarball, deployed, archiveArtifact, packageJson);

if (process.argv.includes('--self-test')) {
  const badSignature = structuredClone(evidence);
  badSignature.signature.sig = `A${badSignature.signature.sig.slice(1)}`;
  expectRejected('modified npm signature', badSignature, tarball, deployed, archiveArtifact, packageJson);

  const badKey = structuredClone(evidence);
  badKey.signingKey.spkiDerBase64 = 'A'.repeat(expected.spkiDerBase64.length);
  expectRejected('substituted npm key', badKey, tarball, deployed, archiveArtifact, packageJson);

  const badDate = structuredClone(evidence);
  badDate.registryReportedPublishedAt = '2025-02-01T00:00:00.000Z';
  expectRejected('post-expiry publication date', badDate, tarball, deployed, archiveArtifact, packageJson);

  const badTarball = Buffer.from(tarball);
  badTarball[0] ^= 1;
  expectRejected('modified npm tarball', evidence, badTarball, deployed, archiveArtifact, packageJson);

  const badArtifact = Buffer.from(deployed);
  badArtifact[0] ^= 1;
  expectRejected('modified deployed artifact', evidence, tarball, badArtifact, archiveArtifact, packageJson);

  let missingSourceRejected = false;
  try {
    requireReproducibleSourceBuild(paths);
  } catch (error) {
    missingSourceRejected = String(error.message).includes('package/wasm/argon2.wasm.json') &&
      String(error.message).includes('package/scripts/build.sh') &&
      String(error.message).includes('a dependency lockfile');
  }
  invariant(missingSourceRejected, 'incomplete npm source passed reproducible-build qualification');

  let missingBuildEvidenceRejected = false;
  try {
    requireReproducibleSourceBuild(new Set([...paths,
      'package/wasm/argon2.wasm.json',
      'package/scripts/build.sh',
      'package/package-lock.json',
    ]));
  } catch (error) {
    missingBuildEvidenceRejected = String(error.message).includes('two independent clean builds');
  }
  invariant(missingBuildEvidenceRejected,
    'source files alone bypassed reproducible-build qualification');
}

if (process.argv.includes('--require-reproducible')) {
  requireReproducibleSourceBuild(paths);
} else {
  console.log('hash-wasm 4.12.0 historical npm signature and deployed Argon2 bytes verified; source rebuild remains unqualified');
}
