import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { verifyMixOutboxLifecycle } from './check-architecture-boundaries.mjs';

const baseline = fs.readFileSync(new URL('../src/xmpp/protocol/mix.rs', import.meta.url), 'utf8')
  .replace(/\r\n/g, '\n');

// Mutate one real production body in memory. No Rust fixture is compiled or
// written back, and every mutation executes the validator used by CI.
function replaceIn(source, declaration, before, after) {
  const start = source.indexOf(declaration);
  assert.ok(start >= 0, `missing mutation declaration: ${declaration}`);
  const end = source.indexOf('\n}\n', start);
  assert.ok(end > start, `missing mutation body end: ${declaration}`);
  const body = source.slice(start, end + 2);
  assert.equal(body.split(before).length, 2, `mutation must match once: ${before}`);
  return source.slice(0, start) + body.replace(before, after) + source.slice(end + 2);
}

function rejects(name, declaration, before, after, expected) {
  test(name, () => {
    const changed = replaceIn(baseline, declaration, before, after);
    assert.throws(() => verifyMixOutboxLifecycle(changed), expected);
  });
}

const claim = 'async fn drainable_mix_outbox_claim<';
const lane = 'async fn run_mix_outbox_lane(';
const join = 'async fn join_mix_outbox_lanes';
const start = 'pub(crate) fn start_mix_delivery_outbox(';
const admission = /claim admission/;
const freshToken = /independent hard token|independent hard token and receive/;

test('current production MIX lanes satisfy the full lifecycle gate', () => {
  verifyMixOutboxLifecycle(baseline);
});

test('whitespace and a trailing call comma do not change the claim contract', () => {
  const changed = replaceIn(baseline, claim,
    'cancellable_mix_outbox_turn(cancel, claim).await',
    'cancellable_mix_outbox_turn(\n\t cancel,\n claim,\n).await');
  verifyMixOutboxLifecycle(changed);
});

for (const [constant, seconds] of [
  ['MIX_OUTBOX_DRAIN_GRACE', 14],
  ['MIX_OUTBOX_UNCLAIMED_DB_TURN_DEADLINE', 5],
  ['MIX_OUTBOX_ATTEMPT_DEADLINE', 20],
]) {
  test(`reject changed ${constant} budget`, () => {
    const before = `const ${constant}: Duration = Duration::from_secs(${seconds});`;
    assert.equal(baseline.split(before).length, 2);
    assert.throws(() => verifyMixOutboxLifecycle(baseline.replace(before,
      `const ${constant}: Duration = Duration::from_secs(${seconds + 1});`)), /deadline/);
  });
}
rejects('stop must be tested before the claim is polled', claim,
  'if stop_claiming.is_cancelled()', 'if false', admission);
rejects('inverting stop cannot admit a new claim', claim,
  'if stop_claiming.is_cancelled()', 'if !stop_claiming.is_cancelled()', admission);
rejects('comments cannot stand in for executable stop admission', claim,
  'if stop_claiming.is_cancelled()', 'if false /* stop_claiming.is_cancelled() */', admission);
rejects('an admitted claim cannot race the parent stop token', claim,
  'cancellable_mix_outbox_turn(cancel, claim).await',
  'cancellable_mix_outbox_turn(stop_claiming, claim).await', admission);
rejects('an admitted claim cannot bypass its bounded hard-cancel turn', claim,
  'cancellable_mix_outbox_turn(cancel, claim).await', 'claim.await', admission);
rejects('stop checked only after database completion is too late', claim,
  'if stop_claiming.is_cancelled() {\n        return Ok(Vec::new());\n    }\n    cancellable_mix_outbox_turn(cancel, claim).await',
  'let result = cancellable_mix_outbox_turn(cancel, claim).await;\n    if stop_claiming.is_cancelled() { return Ok(Vec::new()); }\n    result', admission);
rejects('claim wrapper must retain the fixed five-second turn', 'async fn cancellable_mix_outbox_turn<',
  'MIX_OUTBOX_UNCLAIMED_DB_TURN_DEADLINE', 'MIX_OUTBOX_ATTEMPT_DEADLINE', /five-second/);
rejects('hard cancellation must remain the first bounded-turn branch', 'async fn bounded_mix_outbox_turn<',
  'biased;', '', /prioritize hard cancellation/);
rejects('bounded turn must retain its absolute deadline', 'async fn bounded_mix_outbox_turn<',
  'tokio::time::sleep_until(deadline)', 'std::future::pending::<()>()', /absolute deadline/);
for (const [name, before] of [
  ['delivery', 'let deliveries = drainable_mix_outbox_claim(\n                stop_claiming,'],
  ['PAM', 'MixOutboxQueue::PamResult => Ok(drainable_mix_outbox_claim(\n            stop_claiming,'],
]) {
  rejects(`${name} claim arm cannot bypass stop admission`, 'async fn claim_mix_outbox_work(',
    before, before.replace('drainable_mix_outbox_claim', 'unbounded_claim'), /independently bounded/);
}
test('two wrappers in delivery cannot conceal an unguarded PAM claim', () => {
  const directPam = replaceIn(baseline, 'async fn claim_mix_outbox_work(',
    'MixOutboxQueue::PamResult => Ok(drainable_mix_outbox_claim(\n            stop_claiming,\n            cancel,',
    'MixOutboxQueue::PamResult => Ok(cancellable_mix_outbox_turn(\n            cancel,');
  const nested = replaceIn(directPam, 'async fn claim_mix_outbox_work(',
    '                state\n                    .mix_service()\n                    .claim_mix_deliveries(claim_limit, 8 * 1024 * 1024),',
    '                drainable_mix_outbox_claim(stop_claiming, cancel, state.mix_service().claim_mix_deliveries(claim_limit, 8 * 1024 * 1024)),');
  assert.throws(() => verifyMixOutboxLifecycle(nested), /independently bounded/);
});
rejects('parent stop must close lane admission', lane,
  'stop_claiming.is_cancelled() || cancel.is_cancelled()', 'cancel.is_cancelled()', /lane admission/);
rejects('new claims require accepting state', lane,
  'if accepting\n            && claim_task.is_none()', 'if claim_task.is_none()', /new claims require/);
rejects('owned work must not inherit the parent stop token', lane,
  '                                        cancel.clone(),', '                                        stop_claiming.clone(),', /pending claims and work/);
rejects('stopping cannot discard an already-issued claim response', lane,
  'maintenance_task.take();', 'maintenance_task.take();\n            claim_task.take();', /retain claimed work/);
rejects('stopping cannot reset a claim handle before its result', lane,
  'maintenance_task.take();', 'maintenance_task.take();\n            claim_task = None;', /retain claimed work/);
rejects('claimed delivery must remain in the joint progress set', 'async fn next_mix_outbox_progress(',
  'in_flight.next()', 'std::future::pending()', /jointly polled/);
rejects('claim results cannot be awaited serially in the lane', lane,
  'let mut healthy_progress = false;',
  'let mut healthy_progress = false;\n        if let Some(claim) = claim_task.as_mut() { claim.await; }', /retain claimed work/);

for (const [finished, peer] of [['delivery', 'pam'], ['pam', 'delivery']]) {
  const guard = `if ${finished}_result.is_err() || !stop_claiming.is_cancelled()`;
  rejects(`${finished} completion cannot always hard-cancel its peer`, join,
    guard, 'if true', /must preserve a normal stopped peer/);
  rejects(`${finished} error must still cancel during parent shutdown`, join,
    guard, guard.replace(' || ', ' && '), /must preserve a normal stopped peer/);
  rejects(`${finished} result must await its draining peer`, join,
    `let ${peer}_result = ${peer}.await;`, `let ${peer}_result = Ok(());`, /join must cancel and drain|must preserve a normal stopped peer/);
}
rejects('hard token cannot be a parent child token', start,
  'let lane_cancel = tokio_util::sync::CancellationToken::new();',
  'let lane_cancel = cancel.child_token();', freshToken);
for (const [name, before] of [
  ['delivery', 'Arc::clone(&state),\n                    cancel.clone(),\n                    lane_cancel.clone(),'],
  ['PAM', 'state,\n                    cancel.clone(),\n                    lane_cancel.clone(),'],
]) {
  rejects(`${name} lane must receive distinct correctly ordered stop and hard tokens`, start,
    before, before.replace('cancel.clone(),\n                    lane_cancel.clone()',
      'lane_cancel.clone(),\n                    cancel.clone()'), /parent stop separately/);
}
test('supervisor retries cannot reuse a cancelled hard token', () => {
  const moved = replaceIn(baseline, start,
    'let lane_cancel = tokio_util::sync::CancellationToken::new();', '');
  const cloned = replaceIn(moved, start, 'let cancel = cancel.clone();',
    'let cancel = cancel.clone();\n            let lane_cancel = lane_cancel.clone();');
  const changed = replaceIn(cloned, start, 'let registry = Arc::clone(state.worker_registry());',
    'let lane_cancel = tokio_util::sync::CancellationToken::new();\n    let registry = Arc::clone(state.worker_registry());');
  assert.throws(() => verifyMixOutboxLifecycle(changed), /every supervised attempt/);
});
rejects('supervisor must enforce its registered drain grace', start,
  '        MIX_OUTBOX_DRAIN_GRACE,', '        Duration::from_secs(140),', /whole-worker drain/);
rejects('delivery cannot fall back to the PAM queue', 'async fn claim_mix_outbox_work(',
  '.claim_mix_deliveries(claim_limit, 8 * 1024 * 1024)',
  '.claim_pam_results(claim_limit)', /only their own durable work/);
rejects('PAM must retain its separate budget', start,
  '                    pam_budget,', '                    delivery_budget,', /without delivery\/PAM fallback/);
test('test-only copies cannot conceal a broken production claim helper', () => {
  const changed = replaceIn(baseline, claim, 'cancellable_mix_outbox_turn(cancel, claim).await', 'claim.await');
  const proof = baseline.slice(baseline.indexOf(claim), baseline.indexOf('\n}\n', baseline.indexOf(claim)) + 2);
  assert.throws(() => verifyMixOutboxLifecycle(changed + '\n#[cfg(test)]\nmod fake {\n' + proof + '\n}\n'), admission);
});
