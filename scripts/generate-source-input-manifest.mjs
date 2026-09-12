#!/usr/bin/env node

// Produce the reviewable source identity used by bounded candidate packages.
// The manifest is intentionally independent of Cargo's build cache: a file
// beneath any `target/` directory is never source input, even when historical
// repository state happened to track it. Paths are sorted by their UTF-8 byte
// representation, rather than locale-sensitive string collation.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const algorithm = 'sha256-utf8-lf-record-manifest-v2';

function normalizeRepositoryPath(value) {
  const normalized = value.replaceAll('\\', '/');
  if (!normalized || normalized.startsWith('/') || normalized.split('/').includes('..')) {
    throw new Error(`invalid repository-relative path: ${JSON.stringify(value)}`);
  }
  return normalized;
}

function isBuildOutputPath(relativePath) {
  return normalizeRepositoryPath(relativePath).split('/').includes('target');
}

function compareUtf8Path(left, right) {
  return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'));
}

function trackedPaths() {
  const output = execFileSync('git', ['ls-files', '-z'], {
    cwd: root,
    encoding: 'buffer',
  });
  return output
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .map(normalizeRepositoryPath);
}

function parseArguments(argumentsList) {
  const includes = [];
  let outputPath = null;
  let selfTest = false;
  for (let index = 0; index < argumentsList.length; index += 1) {
    const argument = argumentsList[index];
    if (argument === '--include') {
      const value = argumentsList[++index];
      if (!value) throw new Error('--include requires a repository-relative path');
      includes.push(normalizeRepositoryPath(value));
    } else if (argument === '--write') {
      const value = argumentsList[++index];
      if (!value) throw new Error('--write requires an output path');
      outputPath = path.resolve(root, value);
      if (!outputPath.startsWith(`${root}${path.sep}`)) {
        throw new Error('--write must stay beneath the repository root');
      }
    } else if (argument === '--self-test') {
      selfTest = true;
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  return { includes, outputPath, selfTest };
}

function sourceRecords(paths) {
  const records = [];
  for (const relativePath of [...new Set(paths)].sort(compareUtf8Path)) {
    if (isBuildOutputPath(relativePath)) continue;
    const absolutePath = path.resolve(root, relativePath);
    if (!absolutePath.startsWith(`${root}${path.sep}`)) {
      throw new Error(`path escapes repository root: ${relativePath}`);
    }
    const stat = fs.statSync(absolutePath);
    if (!stat.isFile()) throw new Error(`source input is not a regular file: ${relativePath}`);
    const bytes = fs.readFileSync(absolutePath);
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    records.push(`${relativePath}\tfile\t${bytes.length}\t${digest}`);
  }
  return records;
}

function renderManifest(records) {
  return [
    '# northstar-source-input-manifest-v2',
    `# algorithm: ${algorithm}`,
    '# path ordering: raw UTF-8 byte order',
    '# excluded: every repository path containing a target/ segment',
    '# record: path<TAB>file<TAB>byte-count<TAB>sha256',
    ...records,
    '',
  ].join('\n');
}

function fingerprint(records) {
  return crypto.createHash('sha256').update(`${records.join('\n')}\n`, 'utf8').digest('hex');
}

function runSelfTest() {
  const ordered = ['z.rs', 'a.rs', 'ä.rs'].sort(compareUtf8Path);
  if (ordered.join(',') !== 'a.rs,z.rs,ä.rs') {
    throw new Error(`UTF-8 byte ordering self-test failed: ${ordered.join(',')}`);
  }
  for (const pathUnderTarget of ['target/debug/x', 'crate/target/x', 'a/target/b/x']) {
    if (!isBuildOutputPath(pathUnderTarget)) {
      throw new Error(`target exclusion self-test failed: ${pathUnderTarget}`);
    }
  }
  if (isBuildOutputPath('crates/example/src/lib.rs')) {
    throw new Error('target exclusion self-test rejected a source path');
  }
  console.log('source-input manifest self-test passed');
}

const options = parseArguments(process.argv.slice(2));
if (options.selfTest) {
  if (options.includes.length > 0 || options.outputPath !== null) {
    throw new Error('--self-test cannot be combined with manifest output options');
  }
  runSelfTest();
  process.exit(0);
}

const records = sourceRecords([...trackedPaths(), ...options.includes]);
const manifest = renderManifest(records);
const result = {
  algorithm,
  fingerprint: fingerprint(records),
  records: records.length,
  excluded_build_output_paths: trackedPaths().filter(isBuildOutputPath).length,
};
if (options.outputPath !== null) {
  fs.mkdirSync(path.dirname(options.outputPath), { recursive: true });
  fs.writeFileSync(options.outputPath, manifest, 'utf8');
}
console.log(JSON.stringify(result));
