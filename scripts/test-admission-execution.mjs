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
  ['ambient retained lifecycle I/O', 'lifecycle', source => source + '\nfn leak() { std::fs::read("x"); }'],
  ['unchecked request completion', 'execution', source => source.replace('expected.command != actual.command', 'false')],
  ['completion supplies trusted knowledge', 'execution', source => source.replace('self.observed.as_ref() != Some(&completion.knowledge)', 'false')],
  ['unbound witness observation', 'execution', source => source.replace('validate_effect(expected, witness.effect())?;', '')],
  ['nonmonotone witness observation', 'execution', source => source.replace('!knowledge_advances(prior, witness.knowledge())', 'false')],
  ['changed prepared receipt', 'execution', source => source.replace('prepared.matches_receipt(&receipt)', 'true')],
  ['unchecked transaction knowledge', 'execution', source => source.replace(/validate_knowledge\(\s*expected,\s*&completion\.knowledge,?\s*\)\?;/, '/* validate_knowledge(expected, &completion.knowledge)?; */')],
  ['unchecked result kind', 'execution', source => source.replace(/validate_result\(\s*expected,\s*&completion\.result,\s*&completion\.knowledge,?\s*\)\?;/, '/* validate_result(expected, &completion.result, &completion.knowledge)?; */')],
  ['service bypass', 'service', source => source.replace(/coordinator\s*\.complete\(\s*Completion/, 'legacy_complete(Completion')],
  ['service omits independent observation', 'service', source => source.replace('coordinator.observe_witness(&observed)?;', '')],
  ['retained begin bypass', 'service', source => source.replace('retained.start(&begin_command(request)?)?;', '')],
  ['retained finalize bypass', 'service', source => source.replace('retained.start(&Command::Finalize(acceptance_fence(&acceptance)))?;', '')],
  ['retained completion bypass', 'service', source => source.replace('let outcome = retained.complete(completion)?;', 'let outcome = legacy_complete(completion)?;')],
  ['retained witness observation missing', 'lifecycle', source => source.replace('execution.coordinator.observe_witness(&execution.witness)?;', '')],
  ['retained request substitution', 'lifecycle', source => source.replace('execution.handle.effect.command != *command', 'false')],
  ['repeated effect invocation', 'lifecycle', source => source.replace('if execution.started {', 'if false {')],
  ['grant before actual completion', 'lifecycle', source => source.replace('execution.coordinator.state()', 'fabricated_state()')],
  ['commit after finished effect', 'lifecycle', source => source.replaceAll('if execution.coordinator.pending().is_none() {', 'if false {')],
  ['frame owner not retained', 'frame', source => source.replace('direct_operation: DirectOperationHandle::new(operation_id)', 'direct_operation: unrelated_owner()')],
  ['frame MUC slot omitted', 'frame', source => source.replace('muc_discussion: MucDiscussionSlot::default(),', '')],
  ['frame MUC slot replaced', 'frame', source => source.replace('muc_discussion: MucDiscussionSlot::default()', 'muc_discussion: unrelated_slot()')],
  ['async frame observation starts too late', 'frame', source => source.replace('pub(super) fn run<T>', 'pub(super) async fn run<T>')],
  ['child not destroyed before terminal', 'frame', source => source.replace('drop(self.child.take());', '')],
  ['protocol retained begin removed', 'messaging', source => source.replace('.begin_message_admission_retained(&request, &retained)', '.legacy_begin(&request, &retained)')],
  ['shared retained finalization removed', 'service', source => source.replace('.accept_message_admission_retained(&lease, &retained)', '.legacy_finalize(&lease, &retained)')],
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
  ['missing receipt observation', 'witness', source => source.replace('witness.received(prepared);', '')],
  ['await after commit before receipt', 'witness', source => source.replace('witness.received(prepared);', 'unrelated().await; witness.received(prepared);')],
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

function rejectsDirect(name, field, pattern, replacement) {
  test(`rejects ${name}`, () => {
    const source = sources[field];
    // messaging.rs has an existing test module before its production impl.
    // Its selected forwarding expressions must therefore be unique across
    // the whole file; truncating at that module would miss the real caller.
    const marker = field === 'messaging' ? null
      : /\n#\[cfg\(test\)\]\s*\n(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\b/.exec(source);
    const split = marker ? marker.index : source.length;
    const production = source.slice(0, split);
    assert.equal([...production.matchAll(pattern)].length, 1, 'direct continuation mutation must match exactly once in production source');
    const changed = production.replace(pattern, replacement) + source.slice(split);
    assert.notEqual(changed, source, 'direct continuation mutation must change source');
    assert.throws(() => verifyAdmissionBoundaries({ ...sources, [field]: changed }), /admission boundary:/);
  });
}
rejectsDirect('production frame reuses a fixed identity', 'frame',
  /Self::initialize\(transport, frame, Uuid::new_v4\(\)\)/g,
  'Self::initialize(transport, frame, Uuid::nil())');
rejectsDirect('production frame bypasses the shared initializer', 'frame',
  /Self::initialize\(transport, frame, Uuid::new_v4\(\)\)/g,
  'Self::unrelated_initialize(transport, frame, Uuid::new_v4())');
rejectsDirect('saved frame replaces its supplied identity', 'frame',
  /Self::initialize\(transport, frame, operation_id\)/g,
  'Self::initialize(transport, frame, Uuid::nil())');
rejectsDirect('saved frame constructor becomes production code', 'frame',
  /#\[cfg\(test\)\]\s+pub\(super\) fn for_saved_case/g,
  'pub(super) fn for_saved_case');
rejectsDirect('shared frame replaces the runtime sequence', 'frame',
  /sequence: NEXT_SEQUENCE\.fetch_add\(1, Ordering::Relaxed\)/g,
  'sequence: 1');
rejectsDirect('shared frame replaces the actual frame policy', 'frame',
  /policy: Policy::for_frame\(transport, frame\)/g,
  'policy: unrelated_policy()');
rejectsDirect('publicly replaceable applied result', 'directWorkflow',
  /actual: anyhow::Result<DirectPersonalMessageAdmission>,/g,
  'pub(crate) actual: anyhow::Result<DirectPersonalMessageAdmission>,');
rejectsDirect('clonable applied result and continuation', 'directWorkflow',
  /pub\(crate\) struct AppliedLocalDirect/g,
  '#[derive(Clone)]\npub(crate) struct AppliedLocalDirect');
rejectsDirect('second unbound applied-pair constructor', 'directWorkflow',
  /pub\(crate\) struct AppliedLocalDirect/g,
  "pub(crate) fn raw_applied<'a>(actual: anyhow::Result<DirectPersonalMessageAdmission>, continuation: LocalDirectContinuation<'a>) -> AppliedLocalDirect<'a> { AppliedLocalDirect { actual, continuation } }\npub(crate) struct AppliedLocalDirect");
rejectsDirect('applied-pair decomposition API', 'directWorkflow',
  /pub\(crate\) struct AppliedLocalDirect/g,
  "impl<'a> AppliedLocalDirect<'a> { pub(crate) fn into_parts(self) -> (anyhow::Result<DirectPersonalMessageAdmission>, LocalDirectContinuation<'a>) { (self.actual, self.continuation) } }\npub(crate) struct AppliedLocalDirect");
rejectsDirect('application bridge missing its actual observer', 'directWorkflow',
  /\.commit_direct\(\s*prepared\.command\(\),\s*prepared\.eligibility\(\),\s*Some\(&prepared\),?\s*\)/g,
  '.commit_direct(prepared.command(), prepared.eligibility(), None)');
rejectsDirect('application bridge discards receipt-aware error mapping', 'directWorkflow',
  /\.map_err\(super::direct_commit_error\)/g, '.map_err(legacy_direct_error)');
rejectsDirect('message service passes another preparation', 'messageService',
  /commit_prepared_application\(\s*&self\.personal,\s*prepared,?\s*\)/g,
  'commit_prepared_application(&self.personal, other_prepared)');
rejectsDirect('protocol finalizer loses the originating owner', 'messaging',
  /\|\| self\.message_operation\(\),/g, '|| None,');
rejectsDirect('shared finalizer consumes lease before retaining its handle', 'service',
  /(let retained = operation\(\)\.map\(\|operation\| operation\.finalize\(retained_lease\)\);)\s*(let lease = lease\.take\(\)\.expect\("lease checked above"\);)/g,
  '$2 $1');
rejectsDirect('protocol swaps the sealed application value', 'messaging',
  /(match continue_prepared_local_direct\(\s*)applied,/g, '$1other_applied,');
rejectsDirect('retained route bypasses the shared live continuation', 'messaging',
  /live\.route_with\(&\*self\.state, &targets\)/g, 'legacy_route(&*self.state, &targets)');
rejectsDirect('eager health read in shared continuation', 'directWorkflow',
  /(let AppliedLocalDirect\s*\{\s*actual,\s*continuation,?\s*\}\s*=\s*applied;)/g,
  '$1 let _ = route.direct_route_mode();');
rejectsDirect('stored continuation skips shared finalization', 'directWorkflow',
  /finalize_message_admission_with\(\s*admission,\s*lease,\s*if mode/g,
  'skip_finalization(admission, lease, if mode');
rejectsDirect('late route substitutes a different committed source', 'directWorkflow',
  /delivery: super::DirectRouteDelivery::Committed\(self\.source\(\)\),/g,
  'delivery: super::DirectRouteDelivery::Committed(other_source),');
rejectsDirect('late route disables its existing health gate', 'directWorkflow',
  /enforce_direct_health: true,/g, 'enforce_direct_health: false,');
