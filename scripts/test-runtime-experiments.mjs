import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readRuntimeExperiments, verifyRuntimeExperiments } from './check-runtime-experiments.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const baseline = readRuntimeExperiments();
const clone = () => structuredClone(baseline);
test('complete production index has 16 families and 71 exact runtime identities', () => {
  const result = verifyRuntimeExperiments(clone());
  assert.equal(result.families, 16); assert.equal(result.runtimeIdentities, 71);
  assert.match(result.interpretation, /no experiment was executed/);
});
for (const [label, mutate] of [
  ['missing family', c => c.families.pop()],
  ['duplicate family', c => c.families.push(structuredClone(c.families[0]))],
  ['unknown family', c => c.families[0].id = 'invented'],
  ['self-declared smaller scope', c => c.required_families.pop()],
  ['unknown field', c => c.families[0].passed = true],
  ['missing ownership', c => delete c.families[0].production_owner],
  ['fake owner path', c => c.families[0].production_owner.path = 'src/not-present.rs'],
  ['stale owner anchor', c => c.families[0].production_owner.anchor = 'invented_source_anchor'],
  ['path traversal', c => c.families[0].production_owner.path = '../outside'],
  ['absolute source', c => c.families[0].production_owner.path = '/etc/passwd'],
  ['missing fault', c => c.families[0].faults = []],
  ['empty invariant', c => c.families[0].invariants = ['']],
  ['missing deadline ownership', c => c.families[0].budgets.contract = ''],
  ['stale budget anchor', c => c.families[0].budgets.source.anchor = 'old_budget'],
  ['missing completion boundary', c => delete c.families[0].boundaries.completion],
  ['missing privacy', c => c.families[0].privacy = ''],
  ['hidden gaps', c => c.families[0].gaps = []],
  ['stale command selector', c => c.families[0].experiments[0].command = 'cargo test --locked --bin rust-xmpp-server no_such_selector_exists'],
  ['wrong executable script', c => c.families.find(f => f.id === 'mix').experiments[0].command = 'bash scripts/muc-db-wsl.sh'],
  ['stale test selector', c => c.families[0].experiments[0].test.anchor = 'removed_test'],
  ['duplicate experiment', c => c.families[1].experiments[0].id = c.families[0].experiments[0].id],
  ['overclaimed execution', c => c.families[0].experiments[0].status = 'passed'],
  ['unknown evidence', c => c.families[0].experiments[0].level = 'production_proven'],
  ['missing measurable assertion', c => c.families[0].experiments[0].assertions = []],
  ['missing cleanup', c => c.families[0].experiments[0].cleanup = ''],
  ['missing command', c => c.families[0].experiments[0].command = ''],
  ['missing executable contract', c => delete c.executable_contract],
  ['unknown executable field', c => c.executable_contract.observed = true],
  ['unsupported model', c => c.executable_contract.model = 'production-proven'],
  ['changed capacity', c => c.executable_contract.policy.actor_capacity = 4097],
  ['boolean capacity', c => c.executable_contract.policy.actor_capacity = true],
  ['expiry comparator drift', c => c.executable_contract.clock.active = 'expires_at >= now'],
  ['missing cancellation verdict', c => c.executable_contract.verdicts.pop()],
  ['missing bounded evidence', c => c.executable_contract.budgets.splice(4, 1)],
  ['unknown fault cut', c => c.executable_contract.semantic_cuts.push('durable_commit_unknown')],
  ['missing concrete fixture', c => c.executable_contract.scenarios.pop()],
  ['overclaimed model scope', c => c.executable_contract.scope = 'production proven'],
  ['overclaimed identity mapping', c => c.executable_contract.identity = 'production MAC compatible'],
]) test(`rejects ${label}`, () => { const c = clone(); mutate(c); assert.throws(() => verifyRuntimeExperiments(c)); });
const identityFamily = c => c.families.find(f => f.runtime_identities.length);
for (const [label, mutate] of [
  ['unaccounted identity', f => f.runtime_identities.pop()],
  ['duplicate identity', f => f.runtime_identities.push(structuredClone(f.runtime_identities[0]))],
  ['invented identity', f => f.runtime_identities[0].id = 'worker:invented'],
  ['wrong identity owner', f => f.runtime_identities[0].owner = 'src/invented.rs'],
  ['overclaimed identity proof', f => f.runtime_identities[0].coverage = 'wire_passed'],
]) test(`rejects ${label}`, () => { const c = clone(); mutate(identityFamily(c)); assert.throws(() => verifyRuntimeExperiments(c)); });
test('rejects duplicate source anchor instead of guessing which owner applies', () => {
  const c = clone(), reference = c.families[0].production_owner;
  assert.throws(() => verifyRuntimeExperiments(c, { read: relative => fs.readFileSync(path.join(root, relative), 'utf8')
    + (relative === reference.path ? `\n${reference.anchor}\n` : '') }));
});

test('portable JSON schema keeps the same finite family and declaration vocabulary', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(root, 'catalog/runtime-experiments.schema.json'), 'utf8'));
  assert.deepEqual(schema.properties.required_families.const, baseline.required_families);
  assert.equal(schema.$defs.family.properties.experiments.items.properties.status.const, 'declared');
  assert.equal(schema.$defs.family.properties.runtime_identities.items.properties.coverage.const, 'static_boundary');
  assert.equal(schema.properties.schema.const, baseline.schema);
  assert.equal(schema.$defs.admissionScenario.additionalProperties, false);
  assert.equal(schema.$defs.admissionRow.additionalProperties, false);
  assert.equal(schema.$defs.admissionCommand.additionalProperties, false);
  assert.equal(schema.$defs.admissionCommand.properties.time_us.type, 'integer');
  assert.deepEqual(schema.properties.executable_contract.properties.scenarios.const, baseline.executable_contract.scenarios);
});

for (const [label, mutate] of [
  ['missing controlled contract', c => delete c.controlled_contract],
  ['unknown controlled field', c => c.controlled_contract.executed = true],
  ['wrong controlled adapter', c => c.controlled_contract.adapter = 'real_adapter'],
  ['wrong controlled binding', c => c.controlled_contract.binding_version = 'production-mac'],
  ['missing controlled fixture', c => c.controlled_contract.scenarios.pop()],
  ['missing controlled rejection', c => c.controlled_contract.rejection_scenarios.pop()],
  ['duplicate controlled fixture', c => c.controlled_contract.scenarios.push(c.controlled_contract.scenarios[0])],
  ['wrong controlled runner', c => c.controlled_contract.runner.anchor = 'not-an-executable-anchor'],
  ['controlled scope overclaim', c => c.controlled_contract.scope = 'SQL and wire qualified'],
]) test(`rejects ${label}`, () => { const c = clone(); mutate(c); assert.throws(() => verifyRuntimeExperiments(c)); });
test('controlled portable schema rejects unknown and omitted nullable fields', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(root, 'catalog/runtime-experiments.schema.json'), 'utf8'));
  for (const name of ['controlledAdmissionInput', 'controlledCommand', 'controlledCompletion', 'controlledGuard', 'controlledAdmissionOutput']) {
    assert.equal(schema.$defs[name].additionalProperties, false);
    assert.deepEqual([...schema.$defs[name].required].sort(), Object.keys(schema.$defs[name].properties).sort());
  }
  assert.equal(schema.$defs.controlledAdmissionInput.properties.budgets.properties.evidence_bytes.minimum, 2048);
  assert.equal(schema.$defs.controlledCommand.properties.generation.minimum, 0);
  assert.ok(schema.$defs.controlledCommand.required.includes('reconcile_of'));
  assert.deepEqual(schema.properties.controlled_contract.properties.scenarios.const, baseline.controlled_contract.scenarios);
});
