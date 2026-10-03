import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifiedRuntimeInventory } from './check-architecture-boundaries.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const requiredFamilies = ['startup', 'c2s', 'direct', 'session', 'federation', 'muc', 'mix',
  'visibility', 'pubsub', 'upload', 'administration', 'cluster', 'workers', 'diagnostics', 'recovery', 'client'];
const levels = new Set(['static', 'deterministic_unit', 'isolated_db', 'wire', 'operator_only']);
function requireValue(ok, why) { if (!ok) throw new Error(`runtime experiments: ${why}`); }
function text(value, label) { requireValue(typeof value === 'string' && value.trim().length > 0, `${label} must be nonempty`); }
function nonempty(values, label) { requireValue(Array.isArray(values) && values.length > 0, `${label} must be nonempty`); }
function fields(value, allowed, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  requireValue(Object.keys(value).every(key => allowed.includes(key)), `${label} contains an unknown field`);
  requireValue(allowed.every(key => Object.hasOwn(value, key)), `${label} lacks a required field`);
}
export function readRuntimeExperiments() {
  return JSON.parse(fs.readFileSync(path.join(root, 'catalog/runtime-experiments.json'), 'utf8'));
}
export function verifyRuntimeExperiments(catalog, { inventory = verifiedRuntimeInventory,
  read = relative => fs.readFileSync(path.join(root, relative), 'utf8') } = {}) {
  fields(catalog, ['schema', 'purpose', 'required_families', 'families', 'executable_contract'], 'catalog');
  requireValue(catalog.schema === 'northstar-runtime-experiments-v2', 'unsupported schema');
  text(catalog.purpose, 'purpose');
  requireValue(JSON.stringify(catalog.required_families) === JSON.stringify(requiredFamilies), 'required-family list drift');
  nonempty(catalog.families, 'families');
  const owners = new Map(inventory.map(item => [item.id, item.owner]));
  requireValue(owners.size === inventory.length, 'verified inventory has duplicate IDs');
  const families = new Set(), identities = new Set(), experiments = new Set();
  function reference(value, label) {
    fields(value, ['path', 'anchor'], label);
    text(value.path, `${label} path`); text(value.anchor, `${label} anchor`);
    requireValue(!path.isAbsolute(value.path) && !value.path.split('/').some(part => !part || part === '.' || part === '..')
      && !value.path.includes('\\'), `${label} path escapes source tree`);
    let source;
    try { source = read(value.path); } catch { throw new Error(`runtime experiments: ${label} source unavailable`); }
    requireValue(source.split(value.anchor).length === 2, `${label} anchor missing or ambiguous`);
  }
  const contract = catalog.executable_contract;
  fields(contract, ['schema', 'model', 'scope', 'implementation', 'fixtures', 'input_schema', 'identity',
    'policy', 'policy_source', 'clock', 'normal_preflight', 'semantic_cuts', 'verdicts', 'budgets',
    'termination', 'provenance', 'cleanup', 'limitations', 'scenarios'], 'executable contract');
  requireValue(contract.schema === 'northstar-admission-scenario-v1' && contract.model === 'admission-fixture-v1',
    'unsupported executable contract/model');
  requireValue(contract.input_schema === '#/$defs/admissionScenario', 'missing executable input schema');
  for (const key of ['scope', 'identity', 'normal_preflight', 'termination', 'provenance', 'cleanup']) text(contract[key], key);
  requireValue(/model\/fixture/.test(contract.scope) && /not production-shared/.test(contract.scope), 'model scope must remain explicit');
  requireValue(/synthetic/.test(contract.identity) && /no production MAC/.test(contract.identity), 'synthetic identity boundary missing');
  for (const key of ['implementation', 'fixtures', 'policy_source']) reference(contract[key], `contract ${key}`);
  fields(contract.policy, ['actor_capacity', 'accepted_ttl_us', 'pending_ttl_us', 'lease_us'], 'contract policy');
  for (const [key, expected] of Object.entries({ actor_capacity: 4096, accepted_ttl_us: 21600000000,
    pending_ttl_us: 1800000000, lease_us: 60000000 })) {
    requireValue(Number.isSafeInteger(contract.policy[key]) && contract.policy[key] === expected, `contract ${key} policy drift`);
  }
  const policySource = read(contract.policy_source.path);
  for (const expression of [
    /MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER: i64 = 4_096;/,
    /MESSAGE_ADMISSION_LEASE:[\s\S]*?from_secs\(60\);/,
    /MESSAGE_ADMISSION_PENDING_TTL:[\s\S]*?from_secs\(30 \* 60\);/,
    /MESSAGE_ADMISSION_ACCEPTED_TTL:[\s\S]*?from_secs\(6 \* 60 \* 60\);/,
  ]) requireValue(expression.test(policySource), 'executable policy does not match production constants');
  fields(contract.clock, ['domain', 'unit', 'active', 'expired'], 'contract clock');
  requireValue(contract.clock.domain === 'sql_model' && contract.clock.unit === 'microsecond'
    && contract.clock.active === 'expires_at > now' && contract.clock.expired === 'expires_at <= now', 'SQL expiry/clock drift');
  for (const [key, expected] of Object.entries({
    semantic_cuts: ['none', 'before_effect_cancel', 'reservation_commit_unknown'],
    verdicts: ['Pass', 'InvariantViolation', 'InvalidScenario', 'EnvironmentInterrupted', 'Inconclusive', 'Cancelled'],
    budgets: ['domain_us', 'wall_ms', 'steps', 'events', 'evidence_bytes', 'memory_bytes', 'files'],
    scenarios: ['normal-mixed', 'capacity-4095-4096-4097', 'replay-payload-actor-conflict', 'ttl-before',
      'ttl-at', 'ttl-after', 'pending-lease-reclaim', 'late-finalize-source-semantics', 'late-finalize-4097-candidate', 'reservation-unknown', 'cancel-before-reservation'],
  })) requireValue(JSON.stringify(contract[key]) === JSON.stringify(expected), `contract ${key} drift`);
  nonempty(contract.limitations, 'contract limitations');
  contract.limitations.forEach(value => text(value, 'limitation'));
  const portableSchema = JSON.parse(read('catalog/runtime-experiments.schema.json'));
  requireValue(portableSchema.$defs?.admissionScenario?.additionalProperties === false,
    'portable executable schema must reject unknown fields');
  for (const family of catalog.families) {
    fields(family, ['id', 'title', 'production_owner', 'runtime_identities', 'invariants', 'boundaries',
      'faults', 'budgets', 'experiments', 'privacy', 'gaps'], 'family');
    requireValue(requiredFamilies.includes(family.id) && !families.has(family.id), 'unknown or duplicate family');
    families.add(family.id); text(family.title, 'title'); reference(family.production_owner, `${family.id} owner`);
    for (const list of ['invariants', 'faults', 'gaps']) {
      nonempty(family[list], `${family.id} ${list}`);
      family[list].forEach(value => text(value, list));
    }
    fields(family.boundaries, ['commit', 'handoff', 'completion'], 'boundaries');
    Object.values(family.boundaries).forEach(value => text(value, 'boundary'));
    fields(family.budgets, ['contract', 'source'], 'budgets');
    text(family.budgets.contract, 'budget contract'); reference(family.budgets.source, `${family.id} budget`);
    text(family.privacy, 'privacy');
    requireValue(Array.isArray(family.runtime_identities), 'identities must be an array');
    for (const identity of family.runtime_identities) {
      fields(identity, ['id', 'owner', 'coverage', 'interpretation'], 'identity');
      requireValue(owners.has(identity.id) && owners.get(identity.id) === identity.owner, 'unknown identity or changed owner');
      requireValue(!identities.has(identity.id), 'duplicate identity coverage'); identities.add(identity.id);
      requireValue(identity.coverage === 'static_boundary', 'runtime identity mapping cannot claim executed business proof');
      text(identity.interpretation, 'identity interpretation');
    }
    nonempty(family.experiments, `${family.id} experiments`);
    for (const experiment of family.experiments) {
      fields(experiment, ['id', 'level', 'status', 'command', 'test', 'assertions', 'artifacts', 'cleanup'], 'experiment');
      requireValue(/^[a-z][a-z0-9-]+$/.test(experiment.id) && !experiments.has(experiment.id), 'duplicate or invalid experiment ID');
      experiments.add(experiment.id);
      requireValue(levels.has(experiment.level), 'unknown evidence level');
      requireValue(experiment.status === 'declared', 'catalog is not a run result; evidence must be recorded separately');
      text(experiment.command, 'command'); reference(experiment.test, `${experiment.id} test`);
      const argv = experiment.command.split(/\s+/);
      if (argv[0] === 'cargo') {
        requireValue(argv.slice(0, 5).join(' ') === 'cargo test --locked --bin rust-xmpp-server' && argv.length === 6,
          'Cargo experiment must declare one explicit binary/selector');
        const selector = argv[5];
        const module = experiment.test.path.replace(/^src\//, '').replace(/\.rs$/, '')
          .replace(/_tests$/, '/tests').replaceAll('/', '::');
        const testName = /\bfn\s+([a-zA-Z_][a-zA-Z0-9_]*)\b/.exec(experiment.test.anchor)?.[1];
        const parts = selector.split('::'), leaf = parts.at(-1);
        const moduleSelector = selector.replace(/::tests$/, '');
        const selectsModule = module === selector || module.startsWith(`${selector}::`) || module.endsWith(`::${selector}`)
          || ((module === moduleSelector || module.endsWith(`::${moduleSelector}`)) && selector.endsWith('::tests'));
        const selectsFunction = testName && testName.includes(leaf) && (parts.length === 1
          || module === parts.slice(0, -1).join('::') || module.endsWith(`::${parts.slice(0, -1).join('::')}`));
        requireValue(selectsModule || selectsFunction, `${experiment.id} Cargo selector does not select referenced module/test`);
      } else {
        requireValue(['node', 'python3', 'bash'].includes(argv[0]) && /^scripts\/[a-zA-Z0-9_./-]+$/.test(argv[1])
          && !argv[1].split('/').includes('..'), 'script command must use an owned repository script');
        const testName = /\bfn\s+([a-zA-Z_][a-zA-Z0-9_]*)\b/.exec(experiment.test.anchor)?.[1];
        const selectsRustTest = experiment.test.path.endsWith('.rs') && testName && read(argv[1]).includes(`::${testName}`);
        requireValue(argv[1] === experiment.test.path || selectsRustTest,
          `${experiment.id} script command must execute its referenced test/fixture`);
      }
      for (const list of ['assertions', 'artifacts']) {
        nonempty(experiment[list], list); experiment[list].forEach(value => text(value, list));
      }
      text(experiment.cleanup, 'cleanup');
      if (experiment.level === 'isolated_db') requireValue(/db|database|family/.test(experiment.command), 'DB experiment lacks explicit fixture command');
      if (experiment.level === 'wire') requireValue(/wire|soak|integration|runtime/.test(experiment.command), 'wire experiment lacks explicit fixture command');
    }
  }
  requireValue(requiredFamilies.every(value => families.has(value)), 'missing required family');
  requireValue([...owners.keys()].every(value => identities.has(value)), 'unaccounted runtime identity');
  return { families: families.size, runtimeIdentities: identities.size, experiments: experiments.size,
    interpretation: 'Index validated; no experiment was executed by this validator.' };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(verifyRuntimeExperiments(readRuntimeExperiments()))); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
