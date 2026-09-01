import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const currentDocuments = [
  'README.md',
  'README.zh-TW.md',
  'CONTRIBUTING.md',
  'CHANGELOG.md',
  'SECURITY.md',
  'ARCHITECTURE.md',
  'XEP_MATRIX.md',
  'changelog/v0.2.md',
  'docs/README.md',
  'docs/ARCHITECTURE.md',
  'docs/KNOWN_ISSUES.md',
  'docs/PRODUCTION_OPERATIONS.md',
  'docs/DATABASE_ROLES.md',
  'docs/DEPLOYMENT_CAPACITY.md',
  'docs/OMEMO_DEVICE_TRANSFER.md',
  'docs/RELEASE_CHECKLIST.md',
  'docs/CLUSTERING.md',
  'docs/ABUSE_AND_MODERATION_PRODUCTION_AUDIT.md',
  'docs/DATA_LIFECYCLE.md',
  'docs/WEB_CRYPTO_SUPPLY_CHAIN.md',
  'docs/COMPONENT_PROTOCOL_EVIDENCE.md',
  'docs/SASL2_FAST_BIND2_EVIDENCE.md',
  'docs/LOCALIZATION.md',
  'docs/TRACEABILITY.md',
  'docs/archive/README.md',
  'monitoring/README.md',
  'monitoring/ALERTING_RUNBOOK.md',
];
const historicalDocuments = [
  'docs/archive/CHANGELOG.md',
  'docs/archive/KNOWN_ISSUES_RESOLUTION_PLAN_ZH.md',
  'docs/archive/NORTHSTAR_HANDOFF_REFERENCE_ZH.md',
  'docs/archive/V1.1_VALIDATION_REPORT_ZH.md',
  'docs/archive/SEVEN_TASK_IMPLEMENTATION_AND_VALIDATION_REPORT_ZH.md',
];

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

for (const relativePath of [...currentDocuments, ...historicalDocuments]) {
  if (!fs.existsSync(path.join(root, relativePath))) {
    throw new Error(`document traceability target is missing: ${relativePath}`);
  }
}

for (const relativePath of historicalDocuments) {
  const opening = read(relativePath).slice(0, 1_200).toLowerCase();
  if (!(opening.includes('histor') || opening.includes('历史')) || !opening.includes('当前')) {
    throw new Error(`${relativePath} is not clearly marked as a historical snapshot`);
  }
}

const cargoManifest = read('Cargo.toml');
const packageSection = cargoManifest.split(/^\[dependencies\]/m, 1)[0];
const packageVersion = packageSection.match(/^version = "([^"]+)"$/m)?.[1];
if (!packageVersion) throw new Error('Cargo.toml package version is missing');
const openApiVersion = read('docs/openapi.yaml').match(/^  version: ([^\s]+)$/m)?.[1];
if (openApiVersion !== packageVersion) {
  throw new Error(`OpenAPI version ${openApiVersion ?? 'missing'} does not match Cargo ${packageVersion}`);
}
for (const relativePath of [
  'Dockerfile',
  'deploy/backup.Dockerfile',
  'deploy/database-grants.Dockerfile',
]) {
  if (!read(relativePath).includes(`ARG NORTHSTAR_VERSION=${packageVersion}`)) {
    throw new Error(`${relativePath} OCI version does not match Cargo ${packageVersion}`);
  }
}
for (const [relativePath, marker] of [
  ['.env.example', `NORTHSTAR_VERSION=${packageVersion}`],
  ['docker-compose.yml', `NORTHSTAR_VERSION:-${packageVersion}`],
  ['changelog/v0.2.md', `**Package version:** \`${packageVersion}\``],
]) {
  if (!read(relativePath).includes(marker)) {
    throw new Error(`${relativePath} does not carry release version ${packageVersion}`);
  }
}
const pinnedToolchain = read('rust-toolchain.toml').match(/^channel = "([^"]+)"$/m)?.[1];
const minimumRust = packageSection.match(/^rust-version = "([^"]+)"$/m)?.[1];
if (!pinnedToolchain || !minimumRust || !pinnedToolchain.startsWith(`${minimumRust}.`)) {
  throw new Error('release toolchain must be a patch release of Cargo.toml rust-version');
}
if (!read('.github/workflows/ci.yml').includes(`toolchain: ${pinnedToolchain}`)) {
  throw new Error(`CI does not use the pinned Rust ${pinnedToolchain} release toolchain`);
}
const escapedPinnedToolchain = pinnedToolchain.replaceAll('.', '\\.');
const applicationDockerfile = read('Dockerfile');
if (
  !new RegExp(
    `^FROM rust:${escapedPinnedToolchain}-bookworm@sha256:[0-9a-f]{64} AS builder$`,
    'm',
  ).test(applicationDockerfile)
) {
  throw new Error(`Docker builder tag does not identify pinned Rust ${pinnedToolchain}`);
}
if (
  !applicationDockerfile.includes(
    `RUN rustc --version | grep -E '^rustc ${escapedPinnedToolchain} '`,
  )
) {
  throw new Error(`Docker build does not verify pinned Rust ${pinnedToolchain}`);
}

const staleStatements = new Map([
  [
    'README.md',
    [
      'Explicit XEP-0334 `no-store` is therefore declined for this reliability-required direct-message path',
    ],
  ],
  [
    'docs/KNOWN_ISSUES.md',
    [
      'Reliability-required direct messages carrying `no-store` are declined rather than silently persisted',
      'Generic PubSub is local to a Northstar deployment and is not federated by this cluster layer',
    ],
  ],
]);
for (const [relativePath, statements] of staleStatements) {
  const source = read(relativePath);
  for (const statement of statements) {
    if (source.includes(statement)) {
      throw new Error(`${relativePath} retains a superseded statement: ${statement}`);
    }
  }
}

const knownIssues = read('docs/KNOWN_ISSUES.md');
for (const phrase of [
  '`no-store`',
  'volatile',
  'PostgreSQL',
  'Cross-domain PubSub',
  '1,000-session',
  'key ID',
]) {
  if (!knownIssues.includes(phrase)) {
    throw new Error(`KNOWN_ISSUES.md is missing the current boundary phrase: ${phrase}`);
  }
}

const currentIssueIds = new Set();
for (const line of knownIssues.split(/\r?\n/)) {
  const match = line.match(/^\|\s*([A-Z][A-Z0-9-]+)\s*\|/);
  if (!match || match[1] === 'ID') continue;
  if (currentIssueIds.has(match[1])) {
    throw new Error(`duplicate current known-issue ID: ${match[1]}`);
  }
  currentIssueIds.add(match[1]);
}
if (currentIssueIds.size < 25) {
  throw new Error(`unexpectedly small current known-issue index: ${currentIssueIds.size} rows`);
}

const migrationFiles = fs
  .readdirSync(path.join(root, 'migrations'))
  .filter((name) => name.endsWith('.sql'))
  .sort();
const migrationVersions = new Set();
for (const name of migrationFiles) {
  const match = name.match(/^(\d{4})_[a-z0-9_]+\.sql$/);
  if (!match) throw new Error(`non-canonical migration filename: ${name}`);
  if (migrationVersions.has(match[1])) {
    throw new Error(`duplicate migration version in documentation gate: ${match[1]}`);
  }
  migrationVersions.add(match[1]);
}
const currentMigration = [...migrationVersions].sort().at(-1);
if (!currentMigration) throw new Error('documentation gate found no migrations');
for (const relativePath of [
  'docs/PRODUCTION_OPERATIONS.md',
  'docs/DATABASE_ROLES.md',
  'docs/RELEASE_CHECKLIST.md',
  'docs/TRACEABILITY.md',
]) {
  if (!read(relativePath).includes(currentMigration)) {
    throw new Error(`${relativePath} does not name current migration ${currentMigration}`);
  }
}

const architecture = read('docs/ARCHITECTURE.md').replace(/\s+/g, ' ');
const architectureBudget =
  '`AppState=9` public fields and, across the protocol tree (including inline protocol tests), ' +
  '`0 db authority references / 0 db domain-model references / 0 state.pool / 0 sqlx:: / 0 PgPool`';
if (!architecture.includes(architectureBudget)) {
  throw new Error('docs/ARCHITECTURE.md does not state the current 9/0/0/0/0/0 architecture budget');
}
if (!knownIssues.replace(/\s+/g, ' ').includes('`AppState=9 public fields`')) {
  throw new Error('KNOWN_ISSUES.md does not state the current AppState public-field count');
}

const matrix = read('XEP_MATRIX.md');
const allowedStatuses = new Set(['Core', 'Partial', 'Pass-through', 'Experimental']);
const seenStandards = new Set();
let matrixRows = 0;
for (const line of matrix.split(/\r?\n/)) {
  if (!/^\|\s*(?:RFC|XEP-)/.test(line)) continue;
  const cells = line
    .split('|')
    .slice(1, -1)
    .map((cell) => cell.trim());
  if (cells.length !== 3) throw new Error(`malformed XEP matrix row: ${line}`);
  const [standard, status, scope] = cells;
  if (seenStandards.has(standard)) throw new Error(`duplicate XEP matrix row: ${standard}`);
  if (!allowedStatuses.has(status)) throw new Error(`unknown XEP matrix status for ${standard}: ${status}`);
  if (scope.length < 40) throw new Error(`XEP matrix scope is too vague for ${standard}`);
  seenStandards.add(standard);
  matrixRows += 1;
}
if (matrixRows < 25) throw new Error(`unexpectedly small XEP matrix: ${matrixRows} rows`);

const traceability = read('docs/TRACEABILITY.md');
const allowedEvidenceStates = new Set([
  'Confirmed',
  'Planned',
  'Implemented',
  'Verified-local',
  'Verified-external',
  'Accepted-boundary',
  'Historical',
]);
const tracedIssues = new Map();
for (const line of traceability.split(/\r?\n/)) {
  const match = line.match(/^\|\s*([A-Z][A-Z0-9-]+)\s*\|\s*([A-Za-z-]+)\s*\|/);
  if (!match || match[1] === 'Issue') continue;
  const [, issueId, state] = match;
  if (tracedIssues.has(issueId)) throw new Error(`duplicate traceability issue: ${issueId}`);
  if (!allowedEvidenceStates.has(state)) {
    throw new Error(`invalid traceability state for ${issueId}: ${state}`);
  }
  if (['Implemented', 'Verified-local', 'Verified-external'].includes(state)) {
    if (!line.includes('../src/') && !line.includes('../scripts/')) {
      throw new Error(`implemented issue lacks code/test evidence: ${issueId}`);
    }
  }
  tracedIssues.set(issueId, state);
}
const tracedCoreStandards = new Set();
let inCoreEvidence = false;
for (const line of traceability.split(/\r?\n/)) {
  if (line === '## Core protocol evidence') {
    inCoreEvidence = true;
    continue;
  }
  if (inCoreEvidence && line.startsWith('## ')) break;
  if (!inCoreEvidence) continue;
  const match = line.match(/^\|\s*((?:RFC\s+\d+)|(?:XEP-\d+))\s*\|\s*(.+)\s*\|$/);
  if (!match || match[1] === 'Standard') continue;
  if (tracedCoreStandards.has(match[1])) {
    throw new Error(`duplicate Core protocol evidence row: ${match[1]}`);
  }
  if (!match[2].includes('../scripts/')) {
    throw new Error(`Core protocol evidence lacks a repository harness: ${match[1]}`);
  }
  tracedCoreStandards.add(match[1]);
}
for (const line of matrix.split(/\r?\n/)) {
  if (!/^\|\s*(?:RFC|XEP-)/.test(line)) continue;
  const cells = line.split('|').slice(1, -1).map((cell) => cell.trim());
  if (cells[1] === 'Core' && !tracedCoreStandards.has(cells[0])) {
    throw new Error(`Core protocol lacks traceability evidence: ${cells[0]}`);
  }
}
for (const standard of tracedCoreStandards) {
  const matrixLine = matrix
    .split(/\r?\n/)
    .find((line) => line.startsWith(`| ${standard} |`));
  if (!matrixLine || !matrixLine.includes('| Core |')) {
    throw new Error(`traceability lists a standard that is not currently Core: ${standard}`);
  }
}

function markdownFilesUnder(relativeDirectory) {
  const absoluteDirectory = path.join(root, relativeDirectory);
  const results = [];
  for (const entry of fs.readdirSync(absoluteDirectory, { withFileTypes: true })) {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) results.push(...markdownFilesUnder(relativePath));
    else if (entry.isFile() && entry.name.endsWith('.md')) results.push(relativePath);
  }
  return results;
}

const markdownDocuments = [
  'README.md',
  'README.zh-TW.md',
  'CONTRIBUTING.md',
  'ARCHITECTURE.md',
  'CHANGELOG.md',
  'SECURITY.md',
  'XEP_MATRIX.md',
  ...markdownFilesUnder('changelog'),
  ...markdownFilesUnder('docs'),
  'monitoring/README.md',
  'monitoring/ALERTING_RUNBOOK.md',
];
for (const relativePath of markdownDocuments) {
  const source = read(relativePath);
  for (const match of source.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    let target = match[1].trim().replace(/^<|>$/g, '');
    if (/^(?:https?:|mailto:|#)/i.test(target)) continue;
    target = target.split('#', 1)[0];
    if (target.length === 0) continue;
    const resolved = path.resolve(root, path.dirname(relativePath), decodeURIComponent(target));
    if (!fs.existsSync(resolved)) {
      throw new Error(`${relativePath} contains a broken local link: ${match[1]}`);
    }
  }
}

console.log(
  `Documentation consistency checks passed: ${matrixRows} protocol rows and ` +
    `${markdownDocuments.length} Markdown documents checked; ` +
    `${currentIssueIds.size} current known issues validated, ${tracedIssues.size} trace rows and ` +
    `${tracedCoreStandards.size} Core profiles traced; current migration ${currentMigration}`,
);
