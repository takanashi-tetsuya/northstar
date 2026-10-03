import assert from 'node:assert/strict';
import test from 'node:test';
import { readAdmissionSources, verifyAdmissionBoundaries } from './check-admission-execution.mjs';

const sources = readAdmissionSources();

test('current production-shared admission source boundaries are present', () => {
  assert.equal(verifyAdmissionBoundaries(sources).real_adapter_qualification, false);
});

test('comments and literals do not acquire capabilities', () => {
  const execution = sources.execution + '\n// tokio::spawn AppState\nconst NOTE: &str = "Utc::now()";\n';
  assert.doesNotThrow(() => verifyAdmissionBoundaries({ ...sources, execution }));
});

const mutations = [
  ['ambient core I/O', 'execution', source => source + '\nfn leak() { std::fs::read("x"); }'],
  ['ambient core clock', 'transaction', source => source + '\nfn leak() { Utc::now(); }'],
  ['ambient core entropy', 'execution', source => source + '\nfn leak() { Uuid::new_v4(); }'],
  ['core AppState', 'execution', source => source + '\nfn leak(state: &AppState) {}'],
  ['unchecked request completion', 'execution', source => source.replace('expected.command != completion.effect.command', 'false')],
  ['unchecked transaction knowledge', 'execution', source => source.replace(/validate_knowledge\(\s*expected,\s*&completion\.knowledge,?\s*\)\?;/, '/* validate_knowledge(expected, &completion.knowledge)?; */')],
  ['unchecked result kind', 'execution', source => source.replace(/validate_result\(\s*expected,\s*&completion\.result,\s*&completion\.knowledge,?\s*\)\?;/, '/* validate_result(expected, &completion.result, &completion.knowledge)?; */')],
  ['service bypass', 'service', source => source.replace(/coordinator\s*\.complete\(\s*Completion/, 'legacy_complete(Completion')],
  ['duplicated begin decision', 'repository', source => source.replace('decision::decide_begin(', 'legacy_decide_begin(')],
  ['missing locked row fetch', 'repository', source => source.replace('.fetch_all(&mut *tx)', '.fetch_optional(&mut *tx)')],
  ['duplicated actor cap', 'repository', source => source.replace('decision::decide_actor_capacity(', 'legacy_decide_actor_capacity(')],
  ['duplicated shard cap', 'repository', source => source.replace('decision::decide_shard_reservation(', 'legacy_decide_shard_reservation(')],
  ['missing payload fence', 'transaction', source => source.replace('row.payload_mac.as_slice().ct_eq(&fence.payload_mac)', 'true')],
  ['accepted finalization policy change', 'transaction', source => source.replaceAll('row.state == RowState::Accepted', 'row.state == RowState::Pending')],
  ['invented expiry policy', 'transaction', source => source.replace('if row.lease_token != fence.lease_token {', 'if row.expires_at <= row.lease_expires_at { return FinalizeDecision::LostFence; }\n    if row.lease_token != fence.lease_token {')],
  ['fabricated service fence', 'service', source => source.replace('let acceptance = lease.acceptance();', 'let acceptance = fabricated();')],
  ['duplicated finalization decision', 'repository', source => source.replace('decision::decide_finalize(', 'legacy_decide_finalize(')],
  ['unscoped commit', 'repository', source => source + '\nasync fn bypass(tx: Transaction) { tx.commit().await; }'],
  ['lost guard-denial commit scope', 'repository', source => source.replaceAll('BeginCommitPurpose::GuardDenial', 'BeginCommitPurpose::NewReservation')],
  ['missing receipt observation', 'witness', source => source.replace('witness.received(receipt);', '')],
  ['await after commit before receipt', 'witness', source => source.replace('witness.received(receipt);', 'unrelated().await; witness.received(receipt);')],
  ['guard-only scope conflation', 'verification', source => source.replace('TransactionScope::GuardOnlyVerification', 'TransactionScope::AdmissionFinalize')],
  ['blocking actor row lock', 'actor', source => source.replace('FOR UPDATE NOWAIT', 'FOR UPDATE')],
  ['unbounded foreground cleanup', 'repository', source => source.replace('LIMIT 128 FOR UPDATE SKIP LOCKED', 'FOR UPDATE')],
];

for (const [name, field, mutate] of mutations) {
  test(`rejects ${name}`, () => {
    const changed = mutate(sources[field]);
    assert.notEqual(changed, sources[field], `mutation anchor disappeared: ${name}`);
    assert.throws(() => verifyAdmissionBoundaries({ ...sources, [field]: changed }), /admission boundary:/);
  });
}
