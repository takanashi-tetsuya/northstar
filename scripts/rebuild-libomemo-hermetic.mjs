import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { verifyLibomemoQualification } from './verify-libomemo-rebuild-qualification.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const qualificationPath = resolve(
  root,
  'third_party/libomemo.js/rebuild-qualification.json',
);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function runDocker(arguments_, options = {}) {
  const result = spawnSync('docker', arguments_, {
    cwd: root,
    encoding: 'utf8',
    stdio: options.capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      options.capture
        ? `docker command failed: ${result.stderr.trim()}`
        : `docker command failed with status ${result.status}`,
    );
  }
  return result.stdout?.trim() ?? '';
}

function repositoryEvidencePath(record, label) {
  const path = resolve(root, record.path);
  invariant(path.startsWith(`${root}${sep}`), `${label} must remain inside the repository`);
  return path;
}

function verifyBuilderSignature(qualification) {
  const signature = qualification.rebuild.builderImageSignature;
  const result = spawnSync(
    'cosign',
    [
      'verify',
      '--offline',
      '--key',
      repositoryEvidencePath(signature.publicKey, 'builder signature key'),
      '--bundle',
      repositoryEvidencePath(signature.bundle, 'builder signature bundle'),
      qualification.rebuild.builderImage,
    ],
    { cwd: root, encoding: 'utf8', stdio: 'inherit', windowsHide: true },
  );
  if (result.error) throw result.error;
  invariant(result.status === 0, 'offline builder-image signature verification failed');
}

function containerBaseArgs(qualification) {
  return [
    'run',
    '--rm',
    '--pull=never',
    '--network=none',
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges',
    '--pids-limit=256',
    '--user=65532:65532',
    '--platform',
    qualification.rebuild.builderPlatform,
    '--env',
    `LANG=${qualification.rebuild.locale}`,
    '--env',
    `LC_ALL=${qualification.rebuild.locale}`,
    '--env',
    `TZ=${qualification.rebuild.timezone}`,
    '--env',
    `SOURCE_DATE_EPOCH=${qualification.rebuild.sourceDateEpoch}`,
  ];
}

async function compareOutput(qualification, first, second, output) {
  const [left, right, deployed] = await Promise.all([
    readFile(resolve(first, output)),
    readFile(resolve(second, output)),
    readFile(
      output.endsWith('libomemo.esm.min.js')
        ? resolve(root, 'web/crypto/libomemo.js')
        : resolve(root, 'web/crypto/curve25519_compiled.wasm'),
    ),
  ]);
  const expected = qualification.rebuild.expectedOutputs[output];
  invariant(sha256(left) === expected, `first clean build differs for ${output}`);
  invariant(sha256(right) === expected, `second clean build differs for ${output}`);
  invariant(left.equals(right), `independent builders are not byte-identical for ${output}`);
  invariant(left.equals(deployed), `source rebuild differs from deployed ${output}`);
  return { path: output, sha256: expected, bytes: left.length };
}

await verifyLibomemoQualification({ requireReproducible: true });
const qualification = JSON.parse(await readFile(qualificationPath, 'utf8'));
const sourceArchive = resolve(root, qualification.source.archive);
invariant(
  sourceArchive.startsWith(`${root}${sep}`),
  'qualified source archive must remain inside the repository',
);
const image = qualification.rebuild.builderImage;
verifyBuilderSignature(qualification);
const repoDigests = JSON.parse(
  runDocker(['image', 'inspect', '--format', '{{json .RepoDigests}}', image], {
    capture: true,
  }),
);
invariant(
  Array.isArray(repoDigests) && repoDigests.includes(image),
  'preloaded builder image does not expose the exact qualified digest',
);

const probe = runDocker(
  [
    ...containerBaseArgs(qualification),
    image,
    ...qualification.rebuild.versionProbeCommand,
  ],
  { capture: true },
);
const toolchain = JSON.parse(probe);
for (const [field, expected] of [
  ['node', qualification.javascriptBuild.node],
  ['npm', qualification.javascriptBuild.npm],
  ['emscripten', qualification.wasmBuild.emscripten],
  ['llvm', qualification.wasmBuild.llvm],
  ['binaryen', qualification.wasmBuild.binaryen],
]) {
  invariant(toolchain[field] === expected, `builder ${field} version differs from qualification`);
}

const temporary = await mkdtemp(resolve(tmpdir(), 'northstar-libomemo-rebuild-'));
const outputA = resolve(temporary, 'builder-a');
const outputB = resolve(temporary, 'builder-b');
try {
  for (const output of [outputA, outputB]) {
    await mkdir(output, { mode: 0o777 });
    await chmod(output, 0o777);
  }
  for (const output of [outputA, outputB]) {
    runDocker([
      ...containerBaseArgs(qualification),
      '--tmpfs',
      '/tmp:rw,noexec,nosuid,nodev,size=1g',
      '--mount',
      `type=bind,src=${sourceArchive},dst=/input/source.tar.gz,readonly`,
      '--mount',
      `type=bind,src=${output},dst=/out`,
      image,
      ...qualification.rebuild.buildCommand,
    ]);
  }
  const outputs = [];
  for (const output of Object.keys(qualification.rebuild.expectedOutputs).sort()) {
    invariant(
      !output.startsWith('/') && !output.split(/[\\/]/).includes('..'),
      `unsafe qualified output path: ${output}`,
    );
    outputs.push(await compareOutput(qualification, outputA, outputB, output));
  }
  console.log(
    JSON.stringify(
      {
        schemaVersion: 1,
        builderImage: image,
        builderPlatform: qualification.rebuild.builderPlatform,
        sourceArchiveSha256: qualification.source.sha256,
        toolchain,
        outputs,
        independentBuilds: 2,
        network: 'none',
      },
      null,
      2,
    ),
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}
