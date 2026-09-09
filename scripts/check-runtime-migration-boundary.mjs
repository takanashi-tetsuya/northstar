import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scriptsDirectory = path.join(root, 'scripts');
const listeners = /\b(?:XMPP_BIND|XMPPS_BIND|HTTP_BIND|WEBSOCKET_BIND)=/;
const migratorCredential = /\bMIGRATOR_DATABASE_URL(?:_FILE)?=/;
const explicitMigration = /(?:^|\s)migrate(?:\s|$)/m;
const boundedLedgerRejection = 'northstar-runtime-migration-negative-precheck: immutable-ledger-drift';

function lineStarts(source) {
  const starts = [0];
  for (let index = source.indexOf('\n'); index !== -1; index = source.indexOf('\n', index + 1)) {
    starts.push(index + 1);
  }
  return starts;
}

// Shell functions configure their local runtime at definition time, but do not
// start it until a top-level call occurs. The fixtures use conventional
// unindented `name() {` / `}` delimiters; retaining offsets lets the policy
// compare actual invocations with migrations without pretending to be a full
// shell parser.
function shellFunctionRanges(source) {
  const ranges = [];
  const starts = lineStarts(source);
  let open = null;

  for (let line = 0; line < starts.length; line += 1) {
    const start = starts[line];
    const end = line + 1 < starts.length ? starts[line + 1] : source.length;
    const text = source.slice(start, end).replace(/\r?\n$/, '');
    if (!open) {
      const match = text.match(/^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{$/);
      if (match) open = { name: match[1], start };
      continue;
    }
    if (/^}$/.test(text)) {
      ranges.push({ ...open, end });
      open = null;
    }
  }
  return ranges;
}

function blankFunctionBodies(source, ranges) {
  // String offsets in JavaScript are UTF-16 code-unit offsets. split('') keeps
  // the same indexing model even when a fixture comment contains a surrogate
  // pair, unlike the Unicode-code-point iterator used by `[...source]`.
  const characters = source.split('');
  for (const range of ranges) {
    for (let index = range.start; index < range.end; index += 1) {
      if (characters[index] !== '\n') characters[index] = ' ';
    }
  }
  return characters.join('');
}

function matchOffsets(source, expression) {
  const matcher = new RegExp(
    expression.source,
    expression.flags.includes('g') ? expression.flags : `${expression.flags}g`,
  );
  const offsets = [];
  for (let match = matcher.exec(source); match; match = matcher.exec(source)) {
    offsets.push(match.index);
  }
  return offsets;
}

function runtimeStarts(source) {
  const ranges = shellFunctionRanges(source);
  const topLevel = blankFunctionBodies(source, ranges);
  const starts = matchOffsets(topLevel, listeners);

  for (const range of ranges) {
    const body = source.slice(range.start, range.end);
    if (!listeners.test(body) || !/\$binary\b/.test(body)) continue;
    const call = new RegExp(`^\\s*${range.name}(?:\\s|$)`, 'gm');
    for (const offset of matchOffsets(topLevel, call)) starts.push(offset);
  }
  return starts.sort((left, right) => left - right);
}

function hasBoundedLedgerNegativeProof(source, firstRuntime, firstMigration) {
  const marker = source.indexOf(boundedLedgerRejection);
  return marker >= 0
    && marker <= firstRuntime
    && firstRuntime < firstMigration
    && source.includes('[[ "$stale_status" != 0 ]]')
    && source.includes('[[ ! -e "$readiness_file" ]]')
    && source.includes("grep -Fq 'PostgreSQL migration ledger drifted:'");
}

function inspectRuntimeFixture(name, source) {
  const fixtureViolations = [];
  const startsNorthstar = /rust-xmpp-server/.test(source) && listeners.test(source);
  if (!startsNorthstar) return fixtureViolations;

  if (!migratorCredential.test(source)) {
    fixtureViolations.push(`${name}: missing an explicit MIGRATOR_DATABASE_URL or MIGRATOR_DATABASE_URL_FILE`);
  }
  if (!explicitMigration.test(source)) {
    fixtureViolations.push(`${name}: starts a runtime without an explicit migrate command`);
  }

  const migrations = matchOffsets(source, explicitMigration);
  const starts = runtimeStarts(source);
  if (migrations.length > 0 && starts.length > 0 && migrations[0] > starts[0]
    && !hasBoundedLedgerNegativeProof(source, starts[0], migrations[0])) {
    fixtureViolations.push(`${name}: starts a runtime before applying migrations`);
  }

  // The listener-stress parent may hand a runtime fixture a disposable,
  // already-migrated database copy. This is deliberately narrower than a
  // general migration bypass: both domain databases must be named, the
  // fixture must retain its ordinary explicit migrate path, and it must use
  // the cloned public schema rather than silently sharing the default test
  // database. Keep this contract visible to static review.
  const usesStressPreprovisioning = /\bNORTHSTAR_LISTENER_STRESS_DATABASE_[AB]\b/.test(source);
  if (usesStressPreprovisioning) {
    for (const required of [
      'NORTHSTAR_LISTENER_STRESS_DATABASE_A',
      'NORTHSTAR_LISTENER_STRESS_DATABASE_B',
      'fixture_preprovisioned=true',
      'schema_a=public',
      'schema_b=public',
    ]) {
      if (!source.includes(required)) {
        fixtureViolations.push(`${name}: listener-stress preprovisioning lacks ${required}`);
      }
    }
  }
  return fixtureViolations;
}

function selfTest() {
  const functionBodyBeforeMigration = `
start_runtime() {
  XMPP_BIND=127.0.0.1:0 "$binary"
}
MIGRATOR_DATABASE_URL_FILE=/run/secret "$binary" migrate
start_runtime
rust-xmpp-server
`;
  const directRuntimeBeforeMigration = `
MIGRATOR_DATABASE_URL_FILE=/run/secret
XMPP_BIND=127.0.0.1:0 "$binary"
"$binary" migrate
rust-xmpp-server
`;
  const boundedNegative = `
MIGRATOR_DATABASE_URL_FILE=/run/secret
# ${boundedLedgerRejection}
XMPP_BIND=127.0.0.1:0 "$binary"
[[ "$stale_status" != 0 ]]
[[ ! -e "$readiness_file" ]]
grep -Fq 'PostgreSQL migration ledger drifted:' "$runtime_log"
"$binary" migrate
rust-xmpp-server
`;
  const failures = [
    ['function-body-before-migration', functionBodyBeforeMigration, 0],
    ['direct-runtime-before-migration', directRuntimeBeforeMigration, 1],
    ['bounded-ledger-negative', boundedNegative, 0],
  ].filter(([, source, expected]) => inspectRuntimeFixture('self-test', source).length !== expected);
  if (failures.length > 0) {
    throw new Error(`runtime migration-boundary self-test failed: ${failures.map(([name]) => name).join(', ')}`);
  }
}

selfTest();

const violations = [];
for (const entry of fs.readdirSync(scriptsDirectory, { withFileTypes: true })) {
  if (!entry.isFile() || !entry.name.endsWith('.sh') || entry.name.startsWith('stop-')) continue;
  const file = path.join(scriptsDirectory, entry.name);
  violations.push(...inspectRuntimeFixture(entry.name, fs.readFileSync(file, 'utf8')));
}

if (violations.length > 0) {
  throw new Error(
    `runtime fixtures must establish an isolated migrated database state before startup:\n${violations.join('\n')}`,
  );
}

console.log('Runtime migration-boundary check passed: every server fixture migrates before startup or proves a bounded immutable-ledger rejection');
