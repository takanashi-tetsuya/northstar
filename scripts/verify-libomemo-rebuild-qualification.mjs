import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { collectLibomemoEvidence } from './audit-libomemo-source.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const qualificationPath = resolve(
  root,
  'third_party/libomemo.js/rebuild-qualification.json',
);
const CURRENT_EXCEPTION_VERSION = '2.0.2';
const CURRENT_EXCEPTION_HASHES = Object.freeze({
  source: '952172631c2e16085420779b3ea039ce59a2ac0b1b20255ff16d1941d4226343',
  javascript: '29848fa0791bc07f6982e7e86a5261a3226518f581aba268ec8b030a11e30385',
  wasm: '3a32503ade92ed2bf522d49d51106a227dadb39c2a7b08a1023c216c7eec1286',
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function hasText(values, fragment) {
  return values.some((value) => value.toLowerCase().includes(fragment.toLowerCase()));
}

function evidenceRecord(value, label) {
  invariant(value && typeof value === 'object' && !Array.isArray(value), `${label} is missing`);
  invariant(
    typeof value.path === 'string' &&
      value.path.length > 0 &&
      !value.path.startsWith('/') &&
      !value.path.includes('\\') &&
      !value.path.split('/').includes('..'),
    `${label} has an unsafe repository path`,
  );
  invariant(/^[0-9a-f]{64}$/.test(value.sha256), `${label} has no SHA-256 binding`);
  return value;
}

async function verifyEvidenceRecord(value, label) {
  const record = evidenceRecord(value, label);
  const bytes = await readFile(resolve(root, record.path));
  invariant(sha256(bytes) === record.sha256, `${label} bytes do not match qualification`);
  return bytes;
}

export function validateLibomemoQualification(qualification, evidence) {
  invariant(qualification.schemaVersion === 1, 'unknown libomemo rebuild qualification schema');
  invariant(
    qualification.component === `pkg:npm/libomemo.js@${qualification.release.version}`,
    'qualification component and release version disagree',
  );
  invariant(
    qualification.npmDistribution.url ===
      `https://registry.npmjs.org/libomemo.js/-/libomemo.js-${qualification.release.version}.tgz` &&
      /^[0-9a-f]{40}$/.test(qualification.npmDistribution.sha1),
    'official npm distribution record drifted',
  );
  invariant(
    qualification.release.commit === evidence.sourceArchive.globalPax.comment,
    'source archive PAX commit does not match the recorded release commit',
  );
  invariant(
    qualification.source.paxCommit === evidence.sourceArchive.globalPax.comment,
    'qualification does not bind the archive PAX commit',
  );
  invariant(
    qualification.source.sha256 === evidence.sourceArchive.sha256 &&
      qualification.source.archiveRoot === evidence.sourceArchive.root &&
      qualification.source.regularFileCount === evidence.sourceArchive.regularFileCount,
    'qualification source archive facts drifted',
  );
  invariant(
    evidence.package.name === 'libomemo.js' &&
      evidence.package.version === qualification.release.version &&
      evidence.package.lockRootVersion === qualification.release.version,
    'source package metadata does not match the qualified release',
  );
  for (const [field, actual] of [
    ['node', evidence.package.node],
    ['lockfileVersion', evidence.package.lockfileVersion],
    ['lockedPackageCount', evidence.package.lockedPackageCount],
    ['registryPackageCount', evidence.package.registryPackageCount],
    ['rollup', evidence.package.rollup],
    ['esbuild', evidence.package.esbuild],
    ['typescript', evidence.package.typescript],
    ['protobufjs', evidence.package.protobufjs],
  ]) {
    invariant(
      qualification.javascriptBuild[field] === actual,
      `qualified JavaScript build fact drifted: ${field}`,
    );
  }
  invariant(
    evidence.package.registryPackagesMissingIntegrity.length ===
      qualification.javascriptBuild.registryPackagesMissingIntegrity,
    'npm lockfile integrity coverage drifted',
  );
  invariant(
    evidence.package.registryPackagesMissingIntegrity.length === 0 &&
      evidence.package.nonRegistryResolvedPackages.length === 0,
    'npm lockfile contains an unverified or non-registry resolved package',
  );
  for (const [field, actual] of [
    ['packageJsonSha256', evidence.buildInputs.packageJsonSha256],
    ['packageLockSha256', evidence.buildInputs.packageLockSha256],
    ['rollupConfigSha256', evidence.buildInputs.rollupConfigSha256],
  ]) {
    invariant(
      qualification.javascriptBuild[field] === actual,
      `qualified JavaScript input drifted: ${field}`,
    );
  }
  invariant(
    qualification.wasmBuild.compileScriptSha256 === evidence.buildInputs.compileScriptSha256,
    'qualified native compile script drifted',
  );
  invariant(
    qualification.wasmBuild.archiveArtifactSha256 === evidence.wasm.sha256,
    'source-archive WASM artifact drifted',
  );
  invariant(
    JSON.stringify(qualification.wasmBuild.customSections) ===
      JSON.stringify(evidence.wasm.customSections) &&
      qualification.wasmBuild.producers === evidence.wasm.producers,
    'WASM custom-section/compiler evidence drifted',
  );
  invariant(
    evidence.buildArtifactIsPresentInSourceArchive,
    'expected prebuilt WASM is absent from the source archive',
  );

  const missing = qualification.missingEvidence;
  invariant(Array.isArray(missing) && missing.length >= 8, 'missing-evidence list is incomplete');
  for (const required of [
    'npm executable version',
    'npm tarball',
    'signed tag object',
    'Emscripten',
    'digest-pinned compiler image',
    'two independent clean source rebuilds',
    'in-toto or SLSA',
  ]) {
    invariant(hasText(missing, required), `missing-evidence list omits ${required}`);
  }

  if (qualification.release.status === 'provenance-traced-not-reproducible') {
    invariant(
      qualification.release.version === CURRENT_EXCEPTION_VERSION &&
        qualification.release.currentExceptionVersion === CURRENT_EXCEPTION_VERSION,
      'the provenance-only exception is restricted to libomemo.js 2.0.2',
    );
    invariant(
      qualification.source.sha256 === CURRENT_EXCEPTION_HASHES.source &&
        qualification.npmDistribution.sha256 === null &&
        qualification.rebuild.expectedOutputs['dist/libomemo.esm.min.js'] ===
          CURRENT_EXCEPTION_HASHES.javascript &&
        qualification.rebuild.expectedOutputs['dist/curve25519_compiled.wasm'] ===
          CURRENT_EXCEPTION_HASHES.wasm,
      'the provenance-only exception cannot be retargeted to different bytes',
    );
    invariant(!qualification.rebuild.qualified, 'unreproducible release marked qualified');
    for (const [label, value] of [
      ['npm version', qualification.javascriptBuild.npm],
      ['signed tag object', qualification.source.signedTagObject],
      ['tag signature', qualification.source.detachedSignature],
      ['signer fingerprint', qualification.source.signerFingerprint],
      ['npm tarball', qualification.npmDistribution.vendoredTarball],
      ['Emscripten version', qualification.wasmBuild.emscripten],
      ['LLVM version', qualification.wasmBuild.llvm],
      ['Binaryen version', qualification.wasmBuild.binaryen],
      ['builder image', qualification.rebuild.builderImage],
      ['builder platform', qualification.rebuild.builderPlatform],
      ['version probe command', qualification.rebuild.versionProbeCommand],
      ['build command', qualification.rebuild.buildCommand],
      ['locale', qualification.rebuild.locale],
      ['timezone', qualification.rebuild.timezone],
      ['SOURCE_DATE_EPOCH', qualification.rebuild.sourceDateEpoch],
      ['two-build evidence', qualification.rebuild.twoBuildEvidence],
    ]) {
      invariant(value === null, `${label} must remain null rather than being guessed`);
    }
    invariant(
      evidence.compilerVersionPins.emscripten.length === 0 &&
        evidence.compilerVersionPins.llvm.length === 0 &&
        evidence.compilerVersionPins.binaryen.length === 0 &&
        evidence.compilerVersionPins.digestPinnedBuilder.length === 0 &&
        evidence.wasm.producers === null,
      'new compiler evidence exists but qualification was not reviewed',
    );
    return { reproducible: false, status: qualification.release.status };
  }

  invariant(
    qualification.release.status === 'reproducible' && qualification.rebuild.qualified === true,
    'unknown or unqualified rebuild status',
  );
  invariant(
    /^[0-9a-f]{64}$/.test(qualification.npmDistribution.sha256),
    'a reproducible release requires the vendored npm tarball SHA-256',
  );
  invariant(
    typeof qualification.rebuild.builderPlatform === 'string' &&
      /^[a-z0-9]+\/[a-z0-9_]+(?:\/[a-z0-9_]+)?$/.test(qualification.rebuild.builderPlatform),
    'reproducible builds require one explicit OCI platform',
  );
  invariant(
    typeof qualification.rebuild.builderImage === 'string' &&
      /^[^\s@]+(?:\/[^\s@]+)*@sha256:[0-9a-f]{64}$/.test(
        qualification.rebuild.builderImage,
      ),
    'reproducible builds require a digest-pinned OCI builder image',
  );
  invariant(
    Array.isArray(qualification.rebuild.versionProbeCommand) &&
      qualification.rebuild.versionProbeCommand.length > 0 &&
      qualification.rebuild.versionProbeCommand.every(
        (argument) => typeof argument === 'string' && argument.length > 0,
      ),
    'reproducible build version probe must be an argument array',
  );
  invariant(
    qualification.rebuild.network === 'none' &&
      qualification.rebuild.independentBuildsRequired >= 2,
    'reproducible builds require two offline builder executions',
  );
  invariant(
    Array.isArray(qualification.rebuild.buildCommand) &&
      qualification.rebuild.buildCommand.length > 0 &&
      qualification.rebuild.buildCommand.every(
        (argument) => typeof argument === 'string' && argument.length > 0,
      ),
    'reproducible build command must be an argument array',
  );
  invariant(
    JSON.stringify(Object.keys(qualification.rebuild.expectedOutputs).sort()) ===
      JSON.stringify([
        'dist/curve25519_compiled.wasm',
        'dist/libomemo.esm.min.js',
      ]),
    'qualification must compare exactly the deployed JavaScript and WASM outputs',
  );
  for (const [label, value] of [
    ['npm', qualification.javascriptBuild.npm],
    ['Emscripten', qualification.wasmBuild.emscripten],
    ['LLVM', qualification.wasmBuild.llvm],
    ['Binaryen', qualification.wasmBuild.binaryen],
    ['builder signature', qualification.rebuild.builderImageSignature],
    ['signed tag object', qualification.source.signedTagObject],
    ['signer fingerprint', qualification.source.signerFingerprint],
    ['npm tarball', qualification.npmDistribution.vendoredTarball],
    ['in-toto provenance', qualification.rebuild.inTotoProvenance],
    ['two-build evidence', qualification.rebuild.twoBuildEvidence],
    ['locale', qualification.rebuild.locale],
    ['timezone', qualification.rebuild.timezone],
    ['SOURCE_DATE_EPOCH', qualification.rebuild.sourceDateEpoch],
  ]) {
    invariant(value !== null && value !== '', `reproducible qualification is missing ${label}`);
  }
  invariant(
    /^[0-9A-F]{40,64}$/i.test(qualification.source.signerFingerprint),
    'reproducible qualification requires a full signer fingerprint',
  );
  evidenceRecord(qualification.source.signedTagObject, 'signed tag object');
  evidenceRecord(qualification.source.detachedSignature, 'tag signature');
  evidenceRecord(qualification.source.signatureTrustRecord, 'signature trust record');
  evidenceRecord(qualification.npmDistribution.vendoredTarball, 'official npm tarball');
  evidenceRecord(qualification.npmDistribution.registryAttestation, 'npm registry attestation');
  evidenceRecord(qualification.rebuild.inTotoProvenance, 'in-toto provenance');
  evidenceRecord(qualification.rebuild.twoBuildEvidence, 'two-build evidence');
  invariant(
    qualification.rebuild.builderImageSignature &&
      typeof qualification.rebuild.builderImageSignature === 'object',
    'builder image signature evidence is missing',
  );
  evidenceRecord(qualification.rebuild.builderImageSignature.bundle, 'builder signature bundle');
  evidenceRecord(qualification.rebuild.builderImageSignature.publicKey, 'builder signature key');
  return { reproducible: true, status: qualification.release.status };
}

export async function verifyLibomemoQualification({ requireReproducible = false } = {}) {
  const [qualificationBytes, evidence, deployedJavascript, deployedWasm, sbomBytes] =
    await Promise.all([
      readFile(qualificationPath),
      collectLibomemoEvidence(),
      readFile(resolve(root, 'web/crypto/libomemo.js')),
      readFile(resolve(root, 'web/crypto/curve25519_compiled.wasm')),
      readFile(resolve(root, 'third_party/libomemo.js/SBOM.cdx.json')),
    ]);
  const qualification = JSON.parse(qualificationBytes.toString('utf8'));
  const result = validateLibomemoQualification(qualification, evidence);
  invariant(
    sha256(deployedJavascript) ===
      qualification.rebuild.expectedOutputs['dist/libomemo.esm.min.js'],
    'deployed libomemo JavaScript does not match the qualification record',
  );
  if (result.reproducible) {
    const npmTarball = await verifyEvidenceRecord(
      qualification.npmDistribution.vendoredTarball,
      'official npm tarball',
    );
    invariant(
      sha256(npmTarball) === qualification.npmDistribution.sha256,
      'vendored npm tarball differs from the recorded official distribution',
    );
    await Promise.all([
      verifyEvidenceRecord(qualification.source.signedTagObject, 'signed tag object'),
      verifyEvidenceRecord(qualification.source.detachedSignature, 'tag signature'),
      verifyEvidenceRecord(qualification.source.signatureTrustRecord, 'signature trust record'),
      verifyEvidenceRecord(
        qualification.npmDistribution.registryAttestation,
        'npm registry attestation',
      ),
      verifyEvidenceRecord(
        qualification.rebuild.builderImageSignature.bundle,
        'builder signature bundle',
      ),
      verifyEvidenceRecord(
        qualification.rebuild.builderImageSignature.publicKey,
        'builder signature key',
      ),
      verifyEvidenceRecord(qualification.rebuild.inTotoProvenance, 'in-toto provenance'),
      verifyEvidenceRecord(qualification.rebuild.twoBuildEvidence, 'two-build evidence'),
    ]);
  }
  invariant(
    sha256(deployedWasm) ===
      qualification.rebuild.expectedOutputs['dist/curve25519_compiled.wasm'] &&
      sha256(deployedWasm) === evidence.wasm.sha256,
    'deployed WASM does not match the qualification/source-archive artifact',
  );
  const sbom = JSON.parse(sbomBytes.toString('utf8'));
  const library = sbom.components?.find(
    (component) => component['bom-ref'] === qualification.component,
  );
  const properties = new Map(
    (library?.properties ?? []).map((property) => [property.name, property.value]),
  );
  invariant(
    properties.get('northstar:rebuild-qualification') === qualification.release.status,
    'SBOM does not carry the rebuild qualification status',
  );
  const sourceArchiveHash = properties.get('northstar:source-archive-sha256');
  const distribution = library?.externalReferences?.find(
    (reference) => reference.type === 'distribution',
  );
  const distributionSha1 = distribution?.hashes?.find(
    (hash) => hash.alg === 'SHA-1',
  )?.content;
  const distributionSha256 = distribution?.hashes?.find(
    (hash) => hash.alg === 'SHA-256',
  )?.content ?? null;
  invariant(
    sourceArchiveHash === qualification.source.sha256 &&
      distribution?.url === qualification.npmDistribution.url &&
      distributionSha1 === qualification.npmDistribution.sha1 &&
      distributionSha256 === qualification.npmDistribution.sha256,
    'SBOM source/npm distribution provenance does not match qualification',
  );
  invariant(
    properties.get('northstar:qualification-manifest-sha256') === sha256(qualificationBytes),
    'SBOM does not bind the qualification manifest',
  );
  if (requireReproducible && !result.reproducible) {
    throw new Error(
      'libomemo.js 2.0.2 is provenance-traced but not source-reproducible; qualification is fail-closed',
    );
  }
  return { ...result, evidence };
}

async function selfTest() {
  const qualification = JSON.parse(await readFile(qualificationPath, 'utf8'));
  const evidence = await collectLibomemoEvidence();
  const changedVersion = structuredClone(qualification);
  changedVersion.release.version = '2.0.3';
  changedVersion.component = 'pkg:npm/libomemo.js@2.0.3';
  let rejected = false;
  try {
    validateLibomemoQualification(changedVersion, {
      ...evidence,
      package: { ...evidence.package, version: '2.0.3', lockRootVersion: '2.0.3' },
    });
  } catch {
    rejected = true;
  }
  invariant(rejected, 'a new version bypassed the reproducible-build upgrade gate');
  const guessedCompiler = structuredClone(qualification);
  guessedCompiler.wasmBuild.emscripten = 'guessed-version';
  rejected = false;
  try {
    validateLibomemoQualification(guessedCompiler, evidence);
  } catch {
    rejected = true;
  }
  invariant(rejected, 'a guessed compiler version bypassed the qualification gate');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const requireReproducible = process.argv.includes('--require-reproducible');
  if (process.argv.includes('--self-test')) await selfTest();
  const result = await verifyLibomemoQualification({ requireReproducible });
  if (process.argv.includes('--ci') && result.reproducible) {
    const rebuild = spawnSync(
      process.execPath,
      [resolve(root, 'scripts/rebuild-libomemo-hermetic.mjs')],
      { cwd: root, stdio: 'inherit', windowsHide: true },
    );
    if (rebuild.error) throw rebuild.error;
    invariant(rebuild.status === 0, 'hermetic two-builder qualification failed');
  }
  console.log(
    result.reproducible
      ? 'libomemo source rebuild qualification verified'
      : 'libomemo 2.0.2 provenance verified; source rebuild remains explicitly unqualified',
  );
}
