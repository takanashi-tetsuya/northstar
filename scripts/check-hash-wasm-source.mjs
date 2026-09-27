import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const sourcePath = join(root, 'third_party/hash-wasm/hash-wasm-4.12.0-source.tar.gz');
const npmPath = join(root, 'third_party/hash-wasm/hash-wasm-4.12.0.tgz');
const expected = Object.freeze({
  commit: '373b796205ab55fb4a657374dad6ea589bf75815',
  tree: '12ac3ceecea81077e6de47fa07f118d35608d787',
  sourceSha256: 'ae1a62afe48be3f1fdf355c8e349f5d5c7f1e469e47794718a72ec626df1cf71',
  npmSha256: '1db32a125fb46177932ec8ac438d3cd8214ebdfaccb5d6611b657d88eb586f92',
  sharedFiles: 64,
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function run(program, args, cwd) {
  return execFileSync(program, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

async function filesUnder(directory, prefix = '') {
  const files = new Map();
  for (const entry of await readdir(join(directory, prefix), { withFileTypes: true })) {
    if (entry.name === '.git') continue;
    const relative = join(prefix, entry.name);
    if (entry.isDirectory()) {
      for (const [path, bytes] of await filesUnder(directory, relative)) files.set(path, bytes);
    } else {
      invariant(entry.isFile(), `unexpected archive entry: ${relative}`);
      files.set(relative, await readFile(join(directory, relative)));
    }
  }
  return files;
}

async function verifySource(source, npm) {
  invariant(sha256(source) === expected.sourceSha256, 'hash-wasm source archive SHA-256 changed');
  invariant(sha256(npm) === expected.npmSha256, 'hash-wasm npm archive SHA-256 changed');

  const temporary = await mkdtemp(join(tmpdir(), 'northstar-hash-wasm-source-'));
  try {
    const sourceDir = join(temporary, 'source');
    const packageDir = join(temporary, 'npm');
    const pinnedSourcePath = join(temporary, 'source.tar.gz');
    const pinnedNpmPath = join(temporary, 'npm.tgz');
    await Promise.all([
      mkdir(sourceDir), mkdir(packageDir),
      writeFile(pinnedSourcePath, source), writeFile(pinnedNpmPath, npm),
    ]);
    run('tar', ['-xzf', pinnedSourcePath, '-C', sourceDir, '--no-same-owner'], temporary);
    run('tar', ['-xzf', pinnedNpmPath, '-C', packageDir, '--no-same-owner'], temporary);

    const sourceRoot = join(sourceDir, `Daninet-hash-wasm-${expected.commit.slice(0, 7)}`);
    invariant((await stat(sourceRoot)).isDirectory(), 'upstream source archive root changed');
    const sourceFiles = await filesUnder(sourceRoot);
    const packageFiles = await filesUnder(join(packageDir, 'package'));

    for (const path of ['package-lock.json', 'scripts/build.sh',
      'scripts/Dockerfile', 'scripts/Makefile-clang']) {
      invariant(sourceFiles.has(path), `upstream build input missing: ${path}`);
    }

    run('git', ['init', '-q'], sourceRoot);
    run('git', ['-c', 'core.autocrlf=false', 'add', '-f', '-A', '--', '.'], sourceRoot);
    invariant(run('git', ['write-tree'], sourceRoot) === expected.tree,
      `upstream source archive does not reproduce Git tree ${expected.tree}`);

    const shared = [...packageFiles].filter(([path]) => sourceFiles.has(path));
    invariant(shared.length === expected.sharedFiles,
      `npm package/source shared file count changed: ${shared.length}`);
    for (const [path, bytes] of shared) {
      invariant(bytes.equals(sourceFiles.get(path)), `npm package source differs from upstream: ${path}`);
    }
    for (const path of ['src/argon2.c', 'src/blake2b.c', 'src/hash-wasm.h',
      'lib/argon2.ts', 'lib/blake2b.ts', 'rollup.config.mjs', 'package.json']) {
      invariant(packageFiles.has(path) && sourceFiles.has(path), `required shared source missing: ${path}`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

const [source, npm] = await Promise.all([readFile(sourcePath), readFile(npmPath)]);
await verifySource(source, npm);

if (process.argv.includes('--self-test')) {
  const altered = Buffer.from(source);
  altered[0] ^= 1;
  let rejected = false;
  try { await verifySource(altered, npm); } catch { rejected = true; }
  invariant(rejected, 'modified source archive passed verification');
}

console.log('hash-wasm source Git tree and 64 npm/source files verified; generated JS/WASM source rebuild remains unqualified');
