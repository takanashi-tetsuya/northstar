import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyLibomemoQualification } from './verify-libomemo-rebuild-qualification.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const expected = new Map([
  ['web/crypto/libomemo.js', '29848fa0791bc07f6982e7e86a5261a3226518f581aba268ec8b030a11e30385'],
  ['web/crypto/curve25519_compiled.wasm', '3a32503ade92ed2bf522d49d51106a227dadb39c2a7b08a1023c216c7eec1286'],
  ['web/crypto/LICENSE-GPL-3.0.txt', '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986'],
  ['third_party/libomemo.js/libomemo.js-v2.0.2-source.tar.gz', '952172631c2e16085420779b3ea039ce59a2ac0b1b20255ff16d1941d4226343'],
  ['web/crypto/hash-wasm-argon2.umd.min.js', 'dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094'],
  ['third_party/hash-wasm/hash-wasm-4.12.0.tgz', '1db32a125fb46177932ec8ac438d3cd8214ebdfaccb5d6611b657d88eb586f92'],
  ['third_party/hash-wasm/LICENSE', 'c14dea172f72f2714284a0ac2ab1b00b5352a01409d58255a46227ffc541debd'],
]);

for (const [path, wanted] of expected) {
  const bytes = await readFile(resolve(root, path));
  const actual = createHash('sha256').update(bytes).digest('hex');
  if (actual !== wanted) throw new Error(`${path}: expected SHA-256 ${wanted}, got ${actual}`);
}

const notice = await readFile(resolve(root, 'THIRD_PARTY_NOTICES.md'), 'utf8');
for (const marker of [
  'libomemo.js 2.0.2',
  'df3d34cab03306d34d6ed0bf8b3a3db152173bb4',
  'hash-wasm` 4.12.0',
  '373b796205ab55fb4a657374dad6ea589bf75815',
]) {
  if (!notice.includes(marker)) throw new Error(`THIRD_PARTY_NOTICES.md is missing ${marker}`);
}

const argonSbom = JSON.parse(await readFile(resolve(root, 'third_party/hash-wasm/SBOM.cdx.json'), 'utf8'));
if (argonSbom.bomFormat !== 'CycloneDX' || argonSbom.specVersion !== '1.6') {
  throw new Error('Argon2 browser SBOM is not CycloneDX 1.6');
}
const argonComponents = new Map(argonSbom.components.map((component) => [component['bom-ref'], component]));
const hashWasm = argonComponents.get('pkg:npm/hash-wasm@4.12.0');
const argonArtifact = argonComponents.get('northstar:web/crypto/hash-wasm-argon2.umd.min.js');
if (hashWasm?.purl !== 'pkg:npm/hash-wasm@4.12.0'
  || hashWasm?.licenses?.[0]?.license?.id !== 'MIT'
  || hashWasm?.hashes?.find((hash) => hash.alg === 'SHA-256')?.content
    !== expected.get('third_party/hash-wasm/hash-wasm-4.12.0.tgz')
  || argonArtifact?.hashes?.find((hash) => hash.alg === 'SHA-256')?.content
    !== expected.get('web/crypto/hash-wasm-argon2.umd.min.js')) {
  throw new Error('Argon2 browser SBOM does not match the CI allowlist');
}
if (!JSON.stringify(hashWasm).includes('373b796205ab55fb4a657374dad6ea589bf75815')
  || !JSON.stringify(hashWasm).includes('provenance-traced-not-reproducible')) {
  throw new Error('Argon2 browser SBOM lacks its exact provenance/rebuild boundary');
}

const sbom = JSON.parse(await readFile(resolve(root, 'third_party/libomemo.js/SBOM.cdx.json'), 'utf8'));
if (sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== '1.6') {
  throw new Error('browser cryptography SBOM is not CycloneDX 1.6');
}
const components = new Map(sbom.components.map((component) => [component['bom-ref'], component]));
const library = components.get('pkg:npm/libomemo.js@2.0.2');
const wasm = components.get('northstar:web/crypto/curve25519_compiled.wasm');
if (!library || library.version !== '2.0.2' || library.purl !== 'pkg:npm/libomemo.js@2.0.2') {
  throw new Error('SBOM does not pin libomemo.js 2.0.2');
}
for (const dependency of ['pkg:npm/protobufjs@8.6.4', 'pkg:npm/long@5.3.2']) {
  if (!components.has(dependency)) throw new Error(`SBOM is missing bundled runtime dependency ${dependency}`);
}
for (const [component, wanted] of [
  [library, expected.get('web/crypto/libomemo.js')],
  [wasm, expected.get('web/crypto/curve25519_compiled.wasm')],
]) {
  const recorded = component?.hashes?.find((hash) => hash.alg === 'SHA-256')?.content;
  if (recorded !== wanted) throw new Error('SBOM cryptographic artifact hash does not match the CI allowlist');
}
if (!JSON.stringify(library).includes('df3d34cab03306d34d6ed0bf8b3a3db152173bb4')) {
  throw new Error('SBOM does not identify the pinned upstream commit');
}

const qualification = await verifyLibomemoQualification();
if (qualification.reproducible) {
  throw new Error('libomemo 2.0.2 unexpectedly changed rebuild qualification without review');
}

console.log(
  'Pinned browser cryptography artifacts/source verified; 2.0.2 rebuild remains explicitly unqualified',
);
