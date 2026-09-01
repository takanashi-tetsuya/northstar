import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

const PRIVATE_KEY_LINE =
  '^[[:space:]]*-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----[[:space:]]*$';

const SAFE_EXACT_PATHS = new Set([
  '.env.example',
  'deploy/secrets/README.md',
  'certs/trust/README.md',
]);

const NORTHSTAR_SECRET_BASENAMES = new Set([
  'postgres_bootstrap_password',
  'northstar_migrator_password',
  'northstar_runtime_password',
  'northstar_command_password',
  'northstar_backup_password',
  'migrator_database_url',
  'runtime_database_url',
  'command_database_url',
  'backup_database_url',
  'bootstrap_admin_password',
  'grafana_admin_password',
  'dialback_secret',
  'fast_token_secret',
  'dummy_scram_secret',
  'abuse_state_hmac_key',
  'abuse_state_hmac_previous_key',
  'api_control_secret',
  'api_control_previous_secret',
  'metrics_bearer_token',
  'prometheus_metrics_bearer_token',
  'turn_shared_secret',
  'upload_s3_secret_access_key',
  'backup_age_identity.txt',
]);

const SENSITIVE_BASENAMES = new Set([
  '.pgpass',
  '.pg_service.conf',
  '.netrc',
  '.npmrc',
  '.pypirc',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
  'kubeconfig',
  'credentials.json',
  'credentials.yaml',
  'credentials.yml',
  'secrets.json',
  'secrets.yaml',
  'secrets.yml',
  'client_secret.json',
  'client-secret.json',
  'service_account.json',
  'service-account.json',
  'application_default_credentials.json',
]);

const SENSITIVE_SUFFIXES = [
  '.pkcs8.b64',
  '.sql.gz',
  '.sql.bz2',
  '.sql.xz',
  '.tfstate.backup',
  '.key',
  '.pem',
  '.p12',
  '.pfx',
  '.jks',
  '.keystore',
  '.pkcs8',
  '.pk8',
  '.agekey',
  '.db',
  '.sqlite',
  '.sqlite3',
  '.dump',
  '.pgdump',
  '.backup',
  '.tfstate',
  '.secret',
  '.token',
  '.env',
];

function normalizeTrackedPath(value) {
  return value.replaceAll('\\', '/').replace(/^\.\//, '');
}

function isExplicitTemplate(relativePath) {
  if (SAFE_EXACT_PATHS.has(relativePath)) return true;
  if (/^\.env(?:\.[^/]+)*\.example$/i.test(relativePath)) return true;
  return /^(?:deploy\/secrets|scripts\/fixtures)\/.+\.(?:example|sample|template|fixture|testdata)$/i.test(
    relativePath,
  );
}

export function isSensitiveTrackedPath(value) {
  const relativePath = normalizeTrackedPath(value);
  if (isExplicitTemplate(relativePath)) return false;

  const lower = relativePath.toLowerCase();
  const segments = lower.split('/');
  const basename = segments.at(-1) ?? '';

  if (basename === '.env' || basename.startsWith('.env.')) return true;
  if (segments.includes('secrets') || segments.includes('certs')) return true;
  if (NORTHSTAR_SECRET_BASENAMES.has(basename)) return true;
  if (SENSITIVE_BASENAMES.has(basename)) return true;
  if (SENSITIVE_SUFFIXES.some((suffix) => basename.endsWith(suffix))) return true;
  if (/(?:^|[_-])(?:password|secret|token|database[_-]?url|private[_-]?key)$/.test(basename)) {
    return true;
  }
  if (/^(?:client[_-]?secret|service[_-]?account|credentials?)[^/]*\.(?:json|ya?ml)$/.test(basename)) {
    return true;
  }
  if (segments.includes('.aws') && basename === 'credentials') return true;
  if (segments.includes('.docker') && basename === 'config.json') return true;
  return false;
}

function git(repository, args) {
  return spawnSync('git', ['-C', repository, ...args], {
    encoding: null,
    windowsHide: true,
  });
}

function nulPaths(buffer) {
  if (!buffer || buffer.length === 0) return [];
  return buffer
    .toString('utf8')
    .split('\0')
    .filter((entry) => entry.length > 0)
    .map(normalizeTrackedPath);
}

export function scanTrackedSensitiveFiles(repository, { includeUntracked = false } = {}) {
  const root = path.resolve(repository);
  const worktree = git(root, ['rev-parse', '--is-inside-work-tree']);
  if (worktree.status !== 0) {
    return { skipped: true, sensitivePaths: [], privateKeyPaths: [] };
  }

  const tracked = git(root, ['ls-files', '-z']);
  if (tracked.status !== 0) {
    throw new Error(`git ls-files failed with status ${tracked.status}`);
  }
  const trackedPaths = nulPaths(tracked.stdout);
  let candidatePaths = trackedPaths;
  if (includeUntracked) {
    const untracked = git(root, ['ls-files', '--others', '--exclude-standard', '-z']);
    if (untracked.status !== 0) {
      throw new Error(`git ls-files for untracked candidates failed with status ${untracked.status}`);
    }
    candidatePaths = [...new Set([...trackedPaths, ...nulPaths(untracked.stdout)])].sort();
  }
  const sensitivePaths = candidatePaths.filter(isSensitiveTrackedPath).sort();

  const privateKeys = git(root, [
    'grep',
    '--cached',
    '-I',
    '-l',
    '-z',
    '-E',
    PRIVATE_KEY_LINE,
    '--',
    '.',
  ]);
  if (privateKeys.status !== 0 && privateKeys.status !== 1) {
    throw new Error(`git grep private-key scan failed with status ${privateKeys.status}`);
  }
  const privateKeyPathSet = new Set(privateKeys.status === 0 ? nulPaths(privateKeys.stdout) : []);
  if (includeUntracked) {
    const privateKeyPattern = /^\s*-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\s*$/m;
    for (const relativePath of candidatePaths) {
      const absolutePath = path.join(root, ...relativePath.split('/'));
      let metadata;
      try {
        metadata = fs.lstatSync(absolutePath);
      } catch {
        continue;
      }
      if (!metadata.isFile() || metadata.size > 16 * 1024 * 1024) continue;
      const contents = fs.readFileSync(absolutePath);
      if (contents.includes(0)) continue;
      if (privateKeyPattern.test(contents.toString('utf8'))) privateKeyPathSet.add(relativePath);
    }
  }
  const privateKeyPaths = [...privateKeyPathSet].sort();
  return { skipped: false, sensitivePaths, privateKeyPaths };
}

function printPaths(title, paths) {
  if (paths.length === 0) return;
  process.stderr.write(`${title}:\n`);
  for (const trackedPath of paths) process.stderr.write(`  ${JSON.stringify(trackedPath)}\n`);
}

function main() {
  const includeUntracked = process.argv.includes('--include-untracked');
  const positional = process.argv.slice(2).filter((argument) => argument !== '--include-untracked');
  const repository = positional[0] ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const findings = scanTrackedSensitiveFiles(repository, { includeUntracked });
  if (findings.skipped) {
    process.stderr.write('WARN: this directory is not a Git worktree; tracked-file checks were skipped\n');
    return;
  }
  printPaths('source control contains sensitive/runtime filenames', findings.sensitivePaths);
  printPaths('source control contains private-key material', findings.privateKeyPaths);
  if (findings.sensitivePaths.length > 0 || findings.privateKeyPaths.length > 0) {
    process.exitCode = 1;
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`tracked sensitive-file check failed: ${error.message}\n`);
    process.exitCode = 2;
  }
}
