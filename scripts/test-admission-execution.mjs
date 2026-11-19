import assert from 'node:assert/strict';
import test from 'node:test';
import { readAdmissionSources, verifyAdmissionBoundaries } from './check-admission-execution.mjs';

const sources = readAdmissionSources();

test('current production-shared admission source boundaries are present', () => {
  assert.equal(verifyAdmissionBoundaries(sources).real_adapter_qualification, false);
});

test('comments and literals do not acquire capabilities', () => {
  const execution = sources.execution + '\n// tokio::spawn ServerNode\nconst NOTE: &str = "Utc::now()";\n';
  assert.doesNotThrow(() => verifyAdmissionBoundaries({ ...sources, execution }));
});

const mutations = [
  ['ambient core I/O', 'execution', source => source + '\nfn leak() { std::fs::read("x"); }'],
  ['ambient core clock', 'transaction', source => source + '\nfn leak() { Utc::now(); }'],
  ['ambient core entropy', 'execution', source => source + '\nfn leak() { Uuid::new_v4(); }'],
  ['core ServerNode', 'execution', source => source + '\nfn leak(state: &ServerNode) {}'],
  ['ambient retained lifecycle I/O', 'lifecycle', source => source + '\nfn leak() { std::fs::read("x"); }'],
  ['frame owner not retained', 'frame', source => source.replace('direct_operation: DirectOperationHandle::new(operation_id)', 'direct_operation: unrelated_owner()')],
  ['frame MUC slot omitted', 'frame', source => source.replace('muc_discussion: MucDiscussionSlot::default(),', '')],
  ['frame MUC slot replaced', 'frame', source => source.replace('muc_discussion: MucDiscussionSlot::default()', 'muc_discussion: unrelated_slot()')],
  ['frame MIX slot omitted', 'frame', source => source.replace('mix_foreground: MixForegroundSlot::default(),', '')],
  ['frame MIX slot replaced', 'frame', source => source.replace('mix_foreground: MixForegroundSlot::default()', 'mix_foreground: unrelated_slot()')],
  ['frame auth slot omitted', 'frame', source => source.replace('auth_receipt: std::sync::Mutex::new(None),', '')],
  ['frame auth slot replaced', 'frame', source => source.replace('auth_receipt: std::sync::Mutex::new(None)', 'auth_receipt: unrelated_slot()')],
  ['frame credential history omitted', 'frame', source => source.replace('credential_attempts: std::sync::Mutex::new(CredentialAttempts::default()),', '')],
  ['frame credential history replaced', 'frame', source => source.replace('credential_attempts: std::sync::Mutex::new(CredentialAttempts::default())', 'credential_attempts: unrelated_slot()')],
  ['unscoped commit', 'repository', source => source + '\nasync fn bypass(tx: Transaction) { tx.commit().await; }'],
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
    const marker = /\n#\[cfg\(test\)\]\s*\n(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\b/.exec(source);
    const split = marker ? marker.index : source.length;
    const production = source.slice(0, split);
    assert.equal([...production.matchAll(pattern)].length, 1, 'direct continuation mutation must match exactly once in production source');
    const changed = production.replace(pattern, replacement) + source.slice(split);
    assert.notEqual(changed, source, 'direct continuation mutation must change source');
    assert.throws(() => verifyAdmissionBoundaries({ ...sources, [field]: changed }), /admission boundary:/);
  });
}
rejectsDirect('saved frame replaces its supplied identity', 'frame',
  /Self::initialize\(transport, frame, operation_id\)/g,
  'Self::initialize(transport, frame, Uuid::nil())');
rejectsDirect('saved frame constructor becomes production code', 'frame',
  /#\[cfg\(any\(test, feature = "test-support"\)\)\]\s+pub fn for_saved_case/g,
  'pub fn for_saved_case');
rejectsDirect('shared frame replaces the runtime sequence', 'frame',
  /sequence: NEXT_SEQUENCE\.fetch_add\(1, Ordering::Relaxed\)/g,
  'sequence: 1');
rejectsDirect('shared frame replaces the actual frame policy', 'frame',
  /policy: Policy::for_frame\(transport, frame\)/g,
  'policy: unrelated_policy()');
rejectsDirect('publicly replaceable applied result', 'directWorkflow',
  /actual: anyhow::Result<DirectPersonalMessageAdmission>,/g,
  'pub actual: anyhow::Result<DirectPersonalMessageAdmission>,');
rejectsDirect('second unbound applied-pair constructor', 'directWorkflow',
  /pub struct AppliedLocalDirect/g,
  "pub(crate) fn raw_applied<'a>(actual: anyhow::Result<DirectPersonalMessageAdmission>, continuation: LocalDirectContinuation<'a>) -> AppliedLocalDirect<'a> { AppliedLocalDirect { actual, continuation } }\npub struct AppliedLocalDirect");
rejectsDirect('applied-pair decomposition API', 'directWorkflow',
  /pub struct AppliedLocalDirect/g,
  "impl<'a> AppliedLocalDirect<'a> { pub(crate) fn into_parts(self) -> (anyhow::Result<DirectPersonalMessageAdmission>, LocalDirectContinuation<'a>) { (self.actual, self.continuation) } }\npub struct AppliedLocalDirect");
