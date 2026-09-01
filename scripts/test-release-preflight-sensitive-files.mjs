import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanTrackedSensitiveFiles } from './check-tracked-sensitive-files.mjs';

function git(repository, args) {
  const result = spawnSync('git', ['-C', repository, ...args], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.equal(result.status, 0, `git ${args.join(' ')} failed: ${result.stderr}`);
}

function writeFixture(repository, relativePath, contents = 'synthetic fixture\n') {
  const destination = path.join(repository, ...relativePath.split('/'));
  mkdirSync(path.dirname(destination), { recursive: true });
  writeFileSync(destination, contents, { encoding: 'utf8' });
}

const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), 'northstar-sensitive-files-'));
const checkerScript = fileURLToPath(
  new URL('./check-tracked-sensitive-files.mjs', import.meta.url),
);
try {
  git(temporaryRoot, ['init', '--quiet']);

  const allowed = [
    '.env.example',
    '.env.production.example',
    'deploy/secrets/README.md',
    'deploy/secrets/runtime_database_url.example',
    'certs/trust/README.md',
    'scripts/fixtures/runtime_database_url.fixture',
    'scripts/fixtures/credentials.json.example',
  ];
  const denied = [
    'leak.pkcs8.b64',
    '.pgpass',
    'id_rsa',
    'id_ed25519',
    'snapshot.dump',
    'snapshot.sql.gz',
    'state.tfstate',
    '.npmrc',
    'credentials.json',
    'service-account.json',
    'runtime_database_url',
    'northstar_command_password',
    'command_database_url',
    'dummy_scram_secret',
    'backup_age_identity.txt',
  ];
  for (const relativePath of allowed) writeFixture(temporaryRoot, relativePath);
  for (const relativePath of denied) writeFixture(temporaryRoot, relativePath);
  writeFixture(
    temporaryRoot,
    'innocent-looking.txt',
    '-----BEGIN PRIVATE KEY-----\nsynthetic-not-a-real-key\n-----END PRIVATE KEY-----\n',
  );
  git(temporaryRoot, ['add', '--', '.']);

  const findings = scanTrackedSensitiveFiles(temporaryRoot);
  assert.equal(findings.skipped, false);
  assert.deepEqual(findings.sensitivePaths, denied.slice().sort());
  assert.deepEqual(findings.privateKeyPaths, ['innocent-looking.txt']);
  for (const relativePath of allowed) {
    assert(!findings.sensitivePaths.includes(relativePath), `template was rejected: ${relativePath}`);
  }

  const rejected = spawnSync(process.execPath, [checkerScript, temporaryRoot], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.equal(rejected.status, 1, 'tracked fake secrets did not fail the release gate');

  for (const relativePath of [...denied, 'innocent-looking.txt']) {
    rmSync(path.join(temporaryRoot, ...relativePath.split('/')));
  }
  git(temporaryRoot, ['add', '--all']);
  const allowedOnly = spawnSync(process.execPath, [checkerScript, temporaryRoot], {
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.equal(
    allowedOnly.status,
    0,
    `safe templates or README files were rejected: ${allowedOnly.stderr}`,
  );

  writeFixture(temporaryRoot, 'untracked-command-secret', 'synthetic secret\n');
  writeFixture(
    temporaryRoot,
    'untracked-private-material.txt',
    '-----BEGIN PRIVATE KEY-----\nsynthetic-not-a-real-key\n-----END PRIVATE KEY-----\n',
  );
  writeFixture(temporaryRoot, 'northstar_command_password', 'synthetic secret\n');
  const untrackedRejected = spawnSync(
    process.execPath,
    [checkerScript, '--include-untracked', temporaryRoot],
    { encoding: 'utf8', windowsHide: true },
  );
  assert.equal(untrackedRejected.status, 1, 'untracked release candidates were not scanned');
  assert.match(untrackedRejected.stderr, /northstar_command_password/);
  assert.match(untrackedRejected.stderr, /untracked-private-material\.txt/);
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}

console.log('Tracked sensitive-file release policy self-test passed');
