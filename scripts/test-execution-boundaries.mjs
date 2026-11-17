import assert from 'node:assert/strict';
import test from 'node:test';
import { findRustItem, matchingRustBrace } from './lib/source-module.mjs';
import { readExecutionSources, verifyExecutionBoundaries, verifyRoomExecutionBoundaries, verifyMucDiscussionBoundaries, verifyMixForegroundBoundaries, verifyMixWorkerBoundaries, verifyNativeWriteBoundaries, verifySmOwnershipBoundaries, verifyBoshTransferBoundaries, verifyBoshResponseBoundaries, verifyBoshSelectionObservations, verifyRouteHelperBoundaries } from './check-execution-boundaries.mjs';

const baseline = readExecutionSources();
const CROSS_CRATE_TEST_ONLY = '#[cfg(any(test, feature = "test-support"))]';
function changed(file, before, after) {
  assert.equal(baseline[file].split(before).length, 2, `mutation must match exactly once: ${before}`);
  assert.notEqual(before, after, 'string mutation must not be a no-op');
  return { ...baseline, [file]: baseline[file].replace(before, after) };
}
function rejects(name, file, before, after, expected) {
  test(name, () => assert.throws(() => verifyExecutionBoundaries(changedMuc(file, before, after)), expected));
}

// A split module repeats an inherent impl header once per file; take the
// block that holds the given member.
function itemContaining(source, declaration, member) {
  const items = [];
  for (let start = source.indexOf(declaration); start >= 0; start = source.indexOf(declaration, start + 1)) {
    const close = matchingRustBrace(source, source.indexOf('{', start + declaration.length));
    items.push({ start, close, text: source.slice(start, close + 1) });
  }
  const containing = items.filter(item => item.text.includes(member));
  assert.equal(containing.length, 1, `exactly one ${declaration} must hold ${member}`);
  return containing[0];
}

test('current production execution owners satisfy the gate', () => verifyExecutionBoundaries(baseline));
for (const [name, declaration, member] of [
  ['authUsers', "pub async fn lock_auth_generation_observed<'a>("],
  ['authUsers', "pub async fn lock_auth_generation<'a>("],
  ['sasl2', 'impl<H: SessionHost> ProtocolSession<H>', 'payload.replace_envelope('],
]) {
  test(`${declaration} remains checked after the parent test-module boundary`, () => {
    const source = baseline[name];
    const item = member ? itemContaining(source, declaration, member) : findRustItem(source, declaration);
    const split = source.slice(0, item.start) + source.slice(item.close + 1) + '\nmod moved;\n' + item.text;
    verifyExecutionBoundaries({ ...baseline, [name]: split });
  });
}
test('comments and ordinary formatting are not executable authority', () => {
  verifyExecutionBoundaries(changed('frame', 'let result = future.await;',
    'let /* comment { } */ result =\n future . await;'));
});
rejects('comment cannot replace root credential forwarding', 'state',
  'self.session.sm_service.finalize_binding_observed(connection_id, user_id, expected_auth_generation, full_jid, self.config.capacity_session_lease_seconds, device_id, fast_plan, observation).await',
  '/* self.session.sm_service.finalize_binding_observed(connection_id, user_id, expected_auth_generation, full_jid, self.config.capacity_session_lease_seconds, device_id, fast_plan, observation).await */', /state forwarding/);
rejects('raw string cannot replace root credential forwarding', 'state',
  'self.session.sm_service.finalize_binding_observed(connection_id, user_id, expected_auth_generation, full_jid, self.config.capacity_session_lease_seconds, device_id, fast_plan, observation).await',
  'r###"self.session.sm_service.finalize_binding_observed(connection_id, user_id, expected_auth_generation, full_jid, self.config.capacity_session_lease_seconds, device_id, fast_plan, observation).await"###', /state forwarding/);
rejects('publication cannot fork a detached observer', 'frame',
  'let result = future.await;',
  'tokio::spawn(async {}); let result = future.await;', /without adding a deadline/);

rejects('frame observation must exist before child polling', 'frame',
  'pub fn run<T>(', 'pub async fn run<T>(', /production body/);
rejects('frame timer cannot start in the synchronous constructor', 'frame',
  'child: Some(Box::pin(async move {\n                tokio::time::timeout(budget, future).await\n            })),',
  'child: Some(Box::pin(tokio::time::timeout(budget, future))),', /first-poll timer/);
rejects('frame runner must remember a panic across an outer catch', 'frame',
  'this.poll_in_progress = true;', 'this.poll_in_progress = false;', /retain panic knowledge/);
rejects('normal pending must clear the panic marker', 'frame',
  'Poll::Pending => {\n                this.poll_in_progress = false;\n                return Poll::Pending;\n            }',
  'Poll::Pending => { return Poll::Pending; }', /retain panic knowledge/);
rejects('ready child destruction must precede clearing the panic marker', 'frame',
  'drop(this.child.take());\n        this.poll_in_progress = false;',
  'this.poll_in_progress = false;\n        drop(this.child.take());', /destroy the ready child/);
rejects('runner drop cannot omit child destruction', 'frame',
  'drop(self.child.take());', '', /destroy the child first/);
rejects('runner drop cannot forget a caught panic', 'frame',
  'if self.poll_in_progress {', 'if std::thread::panicking() {', /preserve a caught panic/);
rejects('inline classifier remains transport-specific', 'frame',
  'let inline = transport == ClientTransport::WebSocket && is_inline_auth(frame);',
  'let inline = is_inline_auth(frame);', /guarded WebSocket inline/);
rejects('BOSH ingress cannot bypass observed execution', 'bosh',
  'match self.protocol.process_frame(payload).await {',
  'match self.protocol.handle(payload).await {', /BOSH must enter/);
rejects('BOSH publication cannot bypass observed owner', 'bosh',
  '.publish_committed_authentication_and_route(owner)',
  '.publish_committed_authentication_and_route_inner(owner)', /auth BOSH continuation/);
rejects('BOSH unexposed response cannot publish authentication', 'boshResponse',
  'anyhow::ensure!(self.accepted, "BOSH authentication control was not exposed");',
  'anyhow::ensure!(true, "BOSH authentication control was not exposed");', /BOSH publication gate/);
rejects('BOSH publication failure cannot succeed', 'bosh',
  'Ok(ready) => ready,\n            Err(_) => return false',
  'Ok(ready) => ready,\n            Err(_) => return true', /BOSH must observe publication/);
rejects('BOSH cannot insert a suspension between exposure and publication', 'bosh',
  'let ready = match exposed',
  'tokio::task::yield_now().await;\n        let ready = match exposed', /BOSH must observe publication/);
rejects('BOSH activation marker cannot be hidden behind a dead condition', 'boshAction',
  'let item = if index == 0 {',
  'let item = if false {', /BOSH activation/);
rejects('BOSH publication cannot treat every accepted response as selected', 'boshResponse',
  'if self.auth_control_selected {',
  'if true {', /BOSH publication gate/);
rejects('BOSH publication callback failure cannot mint readiness', 'boshResponse',
  'anyhow::ensure!(publish(owners).await, "BOSH authentication publication failed");',
  'let _ = publish(owners).await;', /BOSH publication gate/);
rejects('BOSH plain compatibility finish cannot bypass auth publication', 'boshResponse',
  '!self.auth_control_selected,\n            "selected BOSH authentication control requires publication"',
  'true,\n            "selected BOSH authentication control requires publication"', /plain compatibility finish/);
rejects('BOSH item marker cannot become public mutable authority', 'outbound',
  '    bosh_auth_control: bool,',
  '    pub(crate) bosh_auth_control: bool,', /private item selection metadata/);
rejects('BOSH marker accessor cannot synthesize selected membership', 'outbound',
  'pub fn is_bosh_auth_control(&self) -> bool { self.bosh_auth_control }',
  'pub fn is_bosh_auth_control(&self) -> bool { true }', /private item selection metadata/);
rejects('BOSH cache cannot retain auth selection membership', 'bosh',
  'struct CachedResponse {',
  'struct CachedResponse {\n    auth_control_selected: bool,', /cache and replay/);
for (const owner of ['BoundResponse', 'ExposedResponse', 'PublicationReadyResponse']) {
  rejects(`BOSH ${owner} cannot derive Clone`, 'boshResponse',
    `pub struct ${owner} {`,
    `#[derive(Clone)]\npub struct ${owner} {`, /cannot derive or manually implement Clone or Copy/);
  rejects(`BOSH ${owner} cannot manually implement Clone`, 'boshResponse',
    `impl ${owner} {`,
    `impl Clone for ${owner} { fn clone(&self) -> Self { panic!("unreviewed clone") } }\nimpl ${owner} {`,
    /cannot derive or manually implement Clone or Copy/);
}
rejects('BOSH ready owner cannot derive Copy', 'boshResponse',
  'pub struct PublicationReadyResponse {',
  '#[derive(Copy)]\npub struct PublicationReadyResponse {', /cannot derive or manually implement Clone or Copy/);
rejects('BOSH exposed owner cannot manually implement Copy', 'boshResponse',
  'impl ExposedResponse {',
  'impl Copy for ExposedResponse {}\nimpl ExposedResponse {', /cannot derive or manually implement Clone or Copy/);
rejects('BOSH bound exposure must consume its owner', 'boshResponse',
  'pub fn expose(mut self, responders: Vec<Responder>)',
  'pub fn expose(&self, responders: Vec<Responder>)', /named consuming declaration heads/);
rejects('BOSH publication cannot borrow its exposed owner', 'boshResponse',
  'pub async fn publish_authentication<F: Future<Output = bool>>(\n        mut self,',
  'pub async fn publish_authentication<F: Future<Output = bool>>(\n        &self,', /named consuming declaration heads/);
rejects('BOSH ready bookkeeping must consume its owner', 'boshResponse',
  'impl PublicationReadyResponse {\n    pub fn finish(\n        self,',
  'impl PublicationReadyResponse {\n    pub fn finish(\n        &self,', /named consuming declaration heads/);
rejects('BOSH bound owner cannot expose mutable selected membership', 'boshResponse',
  '    bound: response::BoundResponse,\n    auth_control_selected: bool,',
  '    bound: response::BoundResponse,\n    pub auth_control_selected: bool,', /exact private field shape/);
rejects('BOSH ready owner cannot expose its inner continuation', 'boshResponse',
  'pub struct PublicationReadyResponse {\n    exposed: ExposedResponse',
  'pub struct PublicationReadyResponse {\n    pub exposed: ExposedResponse', /exact private field shape/);
rejects('BOSH ready owner cannot add an into_exposed escape', 'boshResponse',
  'impl PublicationReadyResponse {',
  'impl PublicationReadyResponse {\n    pub fn into_exposed(self) -> Result<ExposedResponse> { Ok(self.exposed) }',
  /closed inherent-method inventory/);
rejects('BOSH readiness cannot be constructed by an extra free function', 'boshResponse',
  'impl PublicationReadyResponse {',
  'fn extra_readiness(exposed: ExposedResponse) -> Result<PublicationReadyResponse> { Ok(PublicationReadyResponse { exposed }) }\nimpl PublicationReadyResponse {',
  /cannot add named construction sites/);
rejects('BOSH ready owner cannot hide a Self constructor inside finish', 'boshResponse',
  '        let ExposedResponse {',
  '        let _extra = |exposed| Self { exposed };\n        let ExposedResponse {', /cannot add Self-brace construction/);
rejects('BOSH acceptance accessor must remain test-only', 'boshResponse',
  `${CROSS_CRATE_TEST_ONLY}\n    pub fn any_accepted(&self)`,
  'pub fn any_accepted(&self)', /test-only compatibility methods/);
rejects('BOSH plain compatibility finish must remain test-only', 'boshResponse',
  `${CROSS_CRATE_TEST_ONLY}\n    pub fn finish(`,
  'pub fn finish(', /test-only compatibility methods/);

// Finite auth owner/adapter negatives reuse the same exact token-span helper.
rejects('auth receipt identity cannot become public substitution authority', 'authCredential',
  'publication_identity: Uuid,', 'pub publication_identity: Uuid,', /receipt instance identity must remain private/);
rejects('auth selection completion cannot ignore one selected owner', 'boshResponse',
  'observations.iter().all(|observation| observation.completed())',
  'observations.iter().any(|observation| observation.completed())', /BOSH publication gate/);
rejects('auth owner cannot publish its mutable receipt field', 'authOwner',
  'struct PendingPublication {\n    receipt: CredentialCommitReceipt,',
  'struct PendingPublication {\n    pub(crate) receipt: CredentialCommitReceipt,', /receipt, origin and effects private/);
rejects('auth holder cannot add a factory that takes before write', 'authOwner',
  'impl AuthControlHolder {',
  'impl AuthControlHolder { pub(crate) fn take_without_write(self) -> OwnedPublication { let pending = self.0.pending.lock().unwrap().pending.take().unwrap(); OwnedPublication { pending, holder: self, managed: false } }',
  /closed inherent-method inventory/);

rejects('auth holder join observation cannot become a production accessor', 'authOwner',
  `${CROSS_CRATE_TEST_ONLY} pub fn join_observation(&self) -> ControlJoinObservation { self.0.joins.clone() }`,
  'pub fn join_observation(&self) -> ControlJoinObservation { self.0.joins.clone() }', /test-only read-only clone/);
rejects('auth holder join observation cannot substitute unrelated joins', 'authOwner',
  'pub fn join_observation(&self) -> ControlJoinObservation { self.0.joins.clone() }',
  'pub fn join_observation(&self) -> ControlJoinObservation { other_joins.clone() }', /test-only read-only clone/);

for (const [file, name, derive] of [
  ['authFacts', 'CredentialAttemptJoin', 'Clone, Copy, Debug, Eq, PartialEq'],
  ['authFacts', 'CredentialJoins', 'Clone, Copy, Debug, Eq, PartialEq'],
  ['authFacts', 'PublicationJoins', 'Clone, Copy, Debug, Eq, PartialEq'],
  ['authOwner', 'ControlAssociation', 'Clone, Copy, Debug, Eq, PartialEq'],
  ['authOwner', 'ControlJoins', 'Clone, Copy, Debug, Default, Eq, PartialEq'],
]) {
  rejects(`auth ${name} facts cannot escape test configuration`, file,
    `${CROSS_CRATE_TEST_ONLY} #[derive(${derive})] pub struct ${name}`,
    `#[derive(${derive})] pub struct ${name}`, /test-only association facts/);
}
for (const [file, field, expected] of [
  ['authFacts', 'transferred_receipt: Option<Uuid>', /test-only and follow actual checked transfer/],
  ['authFacts', 'begun_receipt: Option<Uuid>', /test-only and follow actual publication acceptance/],
  ['authOwner', 'joins: ControlJoinObservation,', /test-only handoff cut/],
]) {
  rejects(`auth private ${field} cannot escape test configuration`, file,
    `${CROSS_CRATE_TEST_ONLY} ${field}`, field, expected);
}
rejects('auth credential joins cannot replace raw returned identity with constructed identity', 'authFacts',
  'returned_receipt: state.returned.as_ref().map(|(id, _)| *id)',
  'returned_receipt: state.constructed.as_ref().map(|(id, _)| *id)', /independently read actual constructed/);
rejects('auth credential joins cannot fabricate an observed transfer identity', 'authFacts',
  'state.transferred_receipt = Some(receipt.publication_identity());',
  'state.transferred_receipt = state.constructed.as_ref().map(|(id, _)| *id);', /follow actual checked transfer/);
rejects('auth publication joins cannot fabricate a begun receipt identity', 'authFacts',
  'state.begun_receipt = Some(receipt.publication_identity());',
  'state.begun_receipt = Some(state.receipt_id);', /follow actual publication acceptance/);
rejects('auth publication joins cannot erase their actual credential anchor', 'authFacts',
  'credential: state.credential.as_ref().map(|credential| credential.joins().owner)',
  'credential: None', /only an observed credential anchor/);
rejects('auth retained join reader cannot keep a holder alive', 'authOwner',
  'pub struct ControlJoinObservation(Arc<Mutex<ControlJoins>>);',
  'pub struct ControlJoinObservation(Arc<Holder>);', /retain only test facts/);
rejects('auth control joins cannot copy introduction into the transferred association', 'authOwner',
  'holder.0.joins.0.lock().unwrap().transferred = Some(control_association(&holder.0, &owner.pending));',
  'holder.0.joins.0.lock().unwrap().transferred = holder.0.joins.0.lock().unwrap().introduced;', /test-only handoff cut/);
rejects('auth control joins cannot replace the moved pending receipt with the earlier observation', 'authOwner',
  'receipt: pending.receipt.publication_identity()',
  'receipt: holder.observation.joins().receipt', /moved pending receipt independently/);
rejects('auth control joins cannot erase the actual frame association', 'authOwner',
  'frame: pending.origin.as_ref().map(FrameExecution::operation_id)',
  'frame: None', /actual holder and moved pending receipt/);

// Pre-receipt controls use the same exact-one token-span mutation helper.
rejects('credential FAST cannot lose its actual COMMIT observation', 'authDb',
  'match CredentialInvocation::commit(observation, tx.commit()).await {',
  'match tx.commit().await {', /actual transaction and construct/);
for (const [file, site] of [['authDb', 'FastExpired'], ['credentialSmDb', 'BindingReservationLost'],
  ['credentialSmDb', 'BindingStageMissing'], ['credentialSmDb', 'BindingFastExpired'],
  ['credentialSmDb', 'ResumeStageMissing'], ['credentialSmDb', 'ResumeClaimLost'],
  ['credentialSmDb', 'ResumeFastExpired'], ['credentialSmDb', 'ResumePrivacyMissing']]) {
  rejects(`credential ${site} cannot omit its actual rollback`, file,
    `CredentialInvocation::rollback(observation, CredentialRollbackSite::${site}, tx.rollback()).await`,
    'tx.rollback().await', /exact COMMIT and rollback inventory|ignored versus propagated rollback errors/);
}
rejects('credential binding state must retain configured lease policy', 'state',
  'self.session.sm_service.finalize_binding_observed(connection_id, user_id, expected_auth_generation, full_jid, self.config.capacity_session_lease_seconds, device_id, fast_plan, observation).await',
  'self.session.sm_service.finalize_binding_observed(connection_id, user_id, expected_auth_generation, full_jid, 99, device_id, fast_plan, observation).await', /actual lease and exact resume request/);

// Reuse the bounded token-span mutation helper for auth and room guards.
// Match the exact selected token span while tolerating whitespace and optional final commas;
// the production gate still masks comments/literals independently.
function changedMuc(file, before, after, expectedMatches = 1) {
  function dense(source) {
    let text = '';
    const offsets = [];
    for (let index = 0; index < source.length; index++) {
      if (/\s/.test(source[index])) continue;
      if (source[index] === ',') {
        let next = index + 1;
        while (next < source.length && /\s/.test(source[next])) next++;
        if (source[next] === ')' || source[next] === '}') continue;
      }
      offsets.push(index);
      text += source[index];
    }
    return { text, offsets };
  }
  const source = baseline[file];
  const indexed = dense(source);
  const needle = dense(before).text;
  const matches = [];
  for (let index = indexed.text.indexOf(needle); index >= 0; index = indexed.text.indexOf(needle, index + needle.length)) matches.push(index);
  assert.equal(matches.length, expectedMatches, `MUC mutation must match its exact token span: ${before}`);
  assert.notEqual(dense(before).text, dense(after).text, 'MUC mutation must not be a no-op');
  const start = indexed.offsets[matches[0]];
  const end = indexed.offsets[matches[0] + needle.length - 1] + 1;
  return { ...baseline, [file]: source.slice(0, start) + after + source.slice(end) };
}

test('current production room owners satisfy the gate', () => verifyRoomExecutionBoundaries(baseline));

function rejectsMixForeground(name, file, before, after, expected, matches = 1) {
  test(name, () => assert.throws(() => verifyMixForegroundBoundaries(
    changedMuc(file, before, after, matches)), expected));
}
test('current production MIX foreground satisfies its retained-owner gate', () => verifyMixForegroundBoundaries(baseline));
rejectsMixForeground('MIX configuration cannot be supplied by a caller claim', 'state',
  'config.domain.clone(), mix_message_content_identity,', 'claimed_domain(), mix_message_content_identity,', /actual runtime configuration/);
rejectsMixForeground('MIX raw Existing survives rollback suspension', 'mixDb',
  'request.observed_existing(foreground_existing(&existing))?; } transaction.rollback().await?;',
  '} transaction.rollback().await?;', /before both rollback awaits/, 2);
test('current MUC discussion source bridges retain accepted knowledge', () => verifyMucDiscussionBoundaries(baseline));
test('MUC service constructor remains checked with an unrelated impl block', () => {
  const mucService = baseline.mucService + '\nimpl<R: MucRepository> MucService<R> {\n    pub(crate) fn zz_probe(&self) {}\n}\n';
  verifyMucDiscussionBoundaries({ ...baseline, mucService });
});

test('native receive, write and settlement owners satisfy their source gate', () => verifyNativeWriteBoundaries(baseline));
function rejectsNativeWrite(name, file, pattern, replacement, expected) {
  test(name, () => {
    assert.equal([...baseline[file].matchAll(pattern)].length, 1, 'native mutation must match exactly once');
    const source = baseline[file].replace(pattern, replacement);
    assert.notEqual(source, baseline[file], 'native mutation must change source');
    assert.throws(() => verifyNativeWriteBoundaries({ ...baseline, [file]: source }), expected);
  });
}
rejectsNativeWrite('TCP lease cannot substitute another stanza', 'transport', /\|stanza\| send\(io, stanza\)/g, '|stanza| send(io, other_stanza)', /native TCP/);
rejectsNativeWrite('WS lease cannot substitute another stanza', 'transport', /Message::Text\(stanza\.to_owned\(\)\.into\(\)\)/g, 'Message::Text(other_stanza.to_owned().into())', /native WebSocket/);
rejectsNativeWrite('WS send cannot bypass the bounded helper', 'transport', /bounded_websocket_live_write\(socket\.send\(message\), cancellation\)/g, 'unbounded_write(socket.send(message), cancellation)', /WebSocket live writes/);
rejectsNativeWrite('WS write cannot lose actor-shutdown priority', 'transport', /_ = cancellation\.actor_shutdown\.cancelled\(\) => false,/g, '', /WebSocket live selection/);
rejectsNativeWrite('WS write cannot replace the existing timeout', 'transport', /tokio::time::timeout\(XMPP_WRITE_TIMEOUT, write\)/g, 'tokio::time::timeout(OTHER_TIMEOUT, write)', /WebSocket live selection/);
rejectsNativeWrite('lease writer must receive its original item body', 'nativeWrite', /writer\(&self\.item\.stanza\)/g, 'writer(other_stanza)', /actual writer truth/);
rejectsNativeWrite('lease cannot relabel a failed write as full', 'nativeWrite', /let truth = if actual\.is_ok\(\)/g, 'let truth = if true', /actual writer truth/);
rejectsNativeWrite('lease must propagate actual writer failure', 'nativeWrite', /\n\s*actual\?;/g, '\n        let _ = actual;', /actual writer truth/);
rejectsNativeWrite('written item must retain its full-write notification', 'nativeWrite', /self\.item\.confirm_transport_write\(\);/g, '', /native settlement/);
rejectsNativeWrite('written item must use the consuming ACK request', 'nativeWrite', /self\.written\.begin_ack\(\)/g, 'unreviewed_ack()', /native settlement/);
rejectsNativeWrite('C2S settlement cannot substitute its request', 'nativeWrite', /port\.acknowledge_c2s\(&request\)/g, 'port.acknowledge_c2s(&other_request)', /native c2s settlement/);
rejectsNativeWrite('MIX settlement cannot substitute its request', 'nativeWrite', /port\.acknowledge_mix\(&request\)/g, 'port.acknowledge_mix(&other_request)', /native mix settlement/);
rejectsNativeWrite('native Drop must destroy its child first', 'nativeWrite', /drop\(self\.child\.take\(\)\);/g, '', /destroy its child/);
rejectsNativeWrite('native poll must retain the panic marker', 'nativeWrite', /this\.poll_in_progress = true;/g, 'this.poll_in_progress = false;', /mark a panic boundary/);
rejectsNativeWrite('native ready poll must destroy its child first', 'nativeWrite', /drop\(this\.child\.take\(\)\);/g, '', /mark a panic boundary/);
rejectsNativeWrite('ACK commit helper cannot skip its actual commit', 'nativeCore', /commit\.await\.map_err\(CommitError::Repository\)\?;/g, 'drop(commit);', /bind preparation before COMMIT/);
rejectsNativeWrite('C2S transaction cannot bypass the observer', 'replayDb', /\bcommit_observed\(/g, 'unobserved_commit(', /actual C2S ACK transaction/);
rejectsNativeWrite('C2S absent row cannot be called a deletion', 'replayDb', /AckDisposition::AbsentUnclaimed/g, 'AckDisposition::Deleted', /checked deletion/);
rejectsNativeWrite('MIX transaction cannot bypass the observer', 'mixDb', /\bcommit_observed\(\s*transaction\.commit\(\),\s*observation,/g, 'unobserved_commit(transaction.commit(), observation,', /actual MIX ACK transaction/);
rejectsNativeWrite('MIX no-match cannot be called a deletion', 'mixDb', /AckDisposition::NoMatchingMix/g, 'AckDisposition::Deleted', /actual MIX ACK transaction/);

test('SM production ownership paths satisfy their source gate', () => verifySmOwnershipBoundaries(baseline));
test('SM comments cannot provide additional executable effects', () => {
  verifySmOwnershipBoundaries({ ...baseline, smOwner: `/* pool.begin(); request.no_persistence(); */\n${baseline.smOwner}` });
});
// Only an inline `mod tests { ... }` ends the production source in the
// mutation helpers below: a module read appends child files after the
// parent's bodyless `mod tests;` declaration.
function rejectsSm(name, file, method, pattern, replacement, expected) {
  test(name, () => {
    const testModule = baseline[file].search(/#\[cfg\(test\)\]\s*mod tests\s*\{/);
    const production = testModule < 0 ? baseline[file] : baseline[file].slice(0, testModule);
    const declaration = new RegExp(`\\bfn\\s+${method}\\b`, 'g');
    const matches = [...production.matchAll(declaration)];
    assert.equal(matches.length, 1, 'SM mutation must select one actual method');
    const start = matches[0].index;
    // These reviewed methods contain no nested function declarations. Keep
    // unrelated methods out of a targeted mutation without executing Rust.
    const following = /\n\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+/.exec(production.slice(start + matches[0][0].length));
    const end = following ? start + matches[0][0].length + following.index : production.length;
    const selected = baseline[file].slice(start, end);
    assert.equal([...selected.matchAll(pattern)].length, 1, 'SM mutation must match exactly once inside its selected method');
    const source = baseline[file].slice(0, start) + selected.replace(pattern, replacement) + baseline[file].slice(end);
    assert.notEqual(source, baseline[file], 'SM mutation must change source');
    assert.throws(() => verifySmOwnershipBoundaries({ ...baseline, [file]: source }), expected);
  });
}
rejectsSm('SM record entry cannot substitute its owner', 'protocol', 'record_outbound_item', /turn\.record_item\(item,\s*&observation\)/g, 'turn.record_item(item, &other_observation)', /record_outbound_item/);
rejectsSm('SM checkpoint entry cannot omit its child owner', 'protocol', 'checkpoint_sm', /sm_owner::SmTurnRunner::new/g, 'unobserved_runner', /checkpoint_sm/);
rejectsSm('SM ACK entry cannot substitute h', 'smProtocol', 'acknowledge', /turn\.acknowledge\(h,\s*&observation\)/g, 'turn.acknowledge(other_h, &observation)', /SM acknowledge/);
rejectsSm('SM item cannot substitute its body before recording', 'smOwner', 'record_item', /self\.record_source\(&item\.stanza,\s*item\.durable_source,\s*observation\)/g, 'self.record_source(other_stanza, item.durable_source, observation)', /real item/);
rejectsSm('SM item cannot discard its checkpoint failure', 'smOwner', 'record_item', /\.await\?;/g, '.await.ok();', /real item/);
rejectsSm('SM item cannot omit the ownership notification attempt', 'smOwner', 'record_item', /observation\.notification_attempted\(\);/g, '', /ownership notification/);
rejectsSm('SM record cannot stop advancing h', 'smOwner', 'record_source', /self\.sm\.outbound_h\.wrapping_add\(1\)/g, 'self.sm.outbound_h', /append before checkpoint/);
rejectsSm('SM record cannot restore after every checkpoint error', 'smOwner', 'record_source', /error\s*\.downcast_ref::<crate::outbound::DurableDeliverySuperseded>\(\)\s*\.is_some\(\)/g, 'true', /typed supersession/);
rejectsSm('SM record cannot omit its retained append fact', 'smOwner', 'record_source', /observation\.appended\(\);/g, '', /append before checkpoint/);
rejectsSm('SM record cannot omit typed restoration', 'smOwner', 'record_source', /self\.sm\.unacked\.pop_back\(\);/g, '', /typed supersession/);
rejectsSm('SM checkpoint cannot skip transient reservation', 'smOwner', 'checkpoint_in_turn', /self\s*\.port\s*\.reserve_snapshot\(live_bytes\)/g, 'unobserved_reservation()', /bind its snapshot/);
rejectsSm('SM checkpoint cannot expand its existing deadline', 'smOwner', 'checkpoint_in_turn', /Duration::from_secs\(5\)/g, 'Duration::from_secs(6)', /bind its snapshot/);
rejectsSm('SM checkpoint cannot apply an unvalidated return', 'smOwner', 'checkpoint_in_turn', /validate_checkpoint_return\(outcome\.updated,\s*&rotations\)/g, 'accept_unchecked_result(outcome.updated, &rotations)', /returned receipt/);
rejectsSm('SM ACK cannot replace actual counter arithmetic', 'smOwner', 'acknowledge', /northstar_xep_0198::acknowledgement_delta/g, 'invented_delta', /actual h arithmetic/);
rejectsSm('SM ACK cannot select another prefix', 'smOwner', 'acknowledge', /\.take\(delta\)/g, '.take(delta + 1)', /exact persisted cut/);
rejectsSm('SM ACK cannot erase separate batch authority', 'smOwner', 'acknowledge', /prepared\.request\(\)\.validate_batch_return\(\)\?;/g, '', /separate batch authority/);
rejectsSm('SM ACK cannot erase local h application evidence', 'smOwner', 'acknowledge', /observation\.ack_applied\(h\);/g, '', /local apply/);
rejectsSm('SM ACK cannot flatten capacity failure', 'smOwner', 'acknowledge', /result\?;/g, 'drop(result);', /fallible shrink/);
rejectsSm('SM prepared view cannot omit payload projection equality', 'smPrepared', 'validate_projection', /snapshot\s*==\s*SnapshotProjection::from\(self\.snapshot\)/g, 'true', /entire immutable projection/);
rejectsSm('SM prepared view cannot omit policy equality', 'smPrepared', 'validate_projection', /policy\s*==\s*self\.policy/g, 'true', /entire immutable projection/);
rejectsSm('SM COMMIT cannot skip its real future', 'smCore', 'commit_observed', /future\.await\.map_err\(CompletionError::Repository\)\?;/g, 'drop(future);', /commit_observed/);
rejectsSm('SM COMMIT cannot lose a known receipt', 'smCore', 'commit_observed', /permit\.received\(\);/g, '', /commit_observed/);
rejectsSm('SM rollback cannot claim success without awaiting it', 'smCore', 'rollback_observed', /future\.await\.map_err\(CompletionError::Repository\)\?;/g, 'drop(future);', /rollback_observed/);
rejectsSm('SM SQL cannot bypass its COMMIT observation', 'smDb', 'checkpoint_sm_session_and_acknowledge_observed', /sm_ownership::commit_observed/g, 'sm_ownership::unobserved_commit', /SQL checkpoint/);
rejectsSm('SM SQL cannot bypass its explicit rollback observation', 'smDb', 'checkpoint_sm_session_and_acknowledge_observed', /sm_ownership::rollback_observed/g, 'sm_ownership::unobserved_rollback', /SQL checkpoint/);
rejectsSm('SM empty batch cannot invent a transaction receipt', 'smDb', 'acknowledge_transport_sources_observed', /request\.no_persistence\(\)\?;/g, 'request.invented_receipt()?;', /unpersisted SQL ACK/);
rejectsSm('SM batch cannot bypass its COMMIT observation', 'smDb', 'acknowledge_transport_sources_observed', /sm_ownership::commit_observed/g, 'sm_ownership::unobserved_commit', /unpersisted SQL ACK/);
rejectsSm('SM runner cannot lose its panic marker', 'smOwner', 'poll', /this\.poll_in_progress\s*=\s*true;/g, 'this.poll_in_progress = false;', /panic marker/);
rejectsSm('SM typed error cannot erase independently known COMMIT', 'smOwner', 'record_source', /&&\s*observation\.may_restore_superseded\(\)/g, '', /typed supersession/);
rejectsSm('SM restoration cannot invert its no-COMMIT condition', 'smCore', 'may_restore_superseded', /state\.knowledge\s*==\s*Knowledge::NoCommitRequested/g, 'state.knowledge != Knowledge::NoCommitRequested', /independent active no-COMMIT/);

test('BOSH pending transfer and actual item owner satisfy their source gate', () => verifyBoshTransferBoundaries(baseline));
test('BOSH transfer comments do not supply executable receipt authority', () => {
  verifyBoshTransferBoundaries({ ...baseline, boshCore: `/* permit.received(); */\n${baseline.boshCore}` });
});
function rejectsBosh(name, file, pattern, replacement, expected) {
  test(name, () => {
    const testModule = baseline[file].search(/#\[cfg\(test\)\]\s*mod tests\s*\{/);
    const production = testModule < 0 ? baseline[file] : baseline[file].slice(0, testModule);
    assert.equal([...production.matchAll(pattern)].length, 1, 'BOSH mutation must match exactly once in production source');
    const source = production.replace(pattern, replacement) + baseline[file].slice(production.length);
    assert.notEqual(source, baseline[file], 'BOSH mutation must change source');
    assert.throws(() => verifyBoshTransferBoundaries({ ...baseline, [file]: source }), expected);
  });
}
rejectsBosh('BOSH cannot expand its existing backend timer', 'bosh', /const BOSH_BACKEND_OPERATION_TIMEOUT: Duration = Duration::from_secs\(5\);/g, 'const BOSH_BACKEND_OPERATION_TIMEOUT: Duration = Duration::from_secs(6);', /existing backend timeout/);
rejectsBosh('BOSH request cannot substitute another operation', 'bosh', /self\.accept_request\(\*request,\s*response,\s*&operation\)/g, 'self.accept_request(*request, response, &other_operation)', /Request must retain/);
rejectsBosh('BOSH outbound cannot substitute another operation', 'bosh', /self\.queue_outbound\(stanza,\s*&operation\)/g, 'self.queue_outbound(stanza, &other_operation)', /Outbound must retain/);
rejectsBosh('BOSH actor cannot replace its item at the shared helper', 'bosh', /ownership::record_and_push\(\s*&mut output,\s*item,/g, 'ownership::record_and_push(&mut output, other_item,', /same item/);
rejectsBosh('BOSH transfer errors cannot become record-side supersession', 'bosh', /Err\(ownership::RecordPushError::Record\(error\)\)\s*if superseded_bosh_message_id/g, 'Err(ownership::RecordPushError::Transfer { source, error }) if superseded_bosh_message_id', /record-only supersession/);
rejectsBosh('BOSH record port must see the original item', 'boshOwner', /record\s*\.record\(&item\)/g, 'record.record(&other_item)', /record its actual item/);
rejectsBosh('BOSH cannot clear source on the unowned branch', 'boshOwner', /if managed_by_sm\s*\{/g, 'if !managed_by_sm {', /clear SM-owned/);
rejectsBosh('BOSH SM transfer must clear the durable source', 'boshOwner', /item\.durable_source = None;/g, '', /clear SM-owned/);
rejectsBosh('BOSH SM transfer must clear the old MIX handoff', 'boshOwner', /item\.mix_handoff = None;/g, '', /clear SM-owned/);
rejectsBosh('BOSH transfer cannot skip its existing capacity precheck', 'boshOwner', /if !output\.can_push\(&item\)/g, 'if false', /own the original item/);
rejectsBosh('BOSH transfer cannot replace the prepared request', 'boshOwner', /port\.transfer\(&prepared\.request\)/g, 'port.transfer(&other_request)', /exact returned continuation/);
rejectsBosh('BOSH transfer cannot substitute its return', 'boshOwner', /prepared\.returned\(returned\)\?\.push\(output\)/g, 'prepared.returned(other_source)?.push(output)', /exact returned continuation/);
rejectsBosh('BOSH local continuation cannot skip receipt authority', 'boshOwner', /self\.transferred\.begin_local\(\)\?/g, 'invent_local_authority()', /exact source mutation/);
rejectsBosh('BOSH item cannot receive a different rotated source', 'boshOwner', /TransportOwnershipSource::Mix\(local\.current\(\)\)/g, 'TransportOwnershipSource::Mix(other_source)', /exact source mutation/);
rejectsBosh('BOSH handoff cannot name another session', 'boshOwner', /session_id: local\.session_id\(\),/g, 'session_id: other_session,', /notification attempt/);
rejectsBosh('BOSH cannot discard the actual FIFO result', 'boshOwner', /local\.queue_returned\(accepted\);/g, 'local.queue_returned(true);', /actual FIFO result/);
rejectsBosh('BOSH MIX service cannot replace the closed request', 'mixService', /self\.repository\.transfer_mix_delivery_to_bosh\(request\)/g, 'self.repository.transfer_mix_delivery_to_bosh(other_request)', /same closed request/);
rejectsBosh('BOSH repository cannot discard the closed request', 'mixRepository', /crate::mix::transfer_mix_delivery_to_bosh\(&self\.pool,\s*request\)/g, 'crate::mix::transfer_mix_delivery_to_bosh(&self.pool, other_request)', /same closed request/);
rejectsBosh('BOSH SQL cannot replace the bound source', 'mixDb', /(pub async fn transfer_mix_delivery_to_bosh\([\s\S]*?\{\s*request\.validate_for_io\(\)\?;\s*)let source = request\.source\(\);/g, '$1let source = other_source;', /closed inputs/);
rejectsBosh('BOSH SQL cannot replace the bound session', 'mixDb', /let session_id = request\.session_id\(\);/g, 'let session_id = other_session;', /closed inputs/);
rejectsBosh('BOSH SQL cannot bypass the COMMIT observer', 'mixDb', /bosh_ownership::transfer_commit_observed/g, 'bosh_ownership::unobserved_commit', /actual COMMIT receipt/);
rejectsBosh('BOSH commit helper must await its actual future', 'boshCore', /future\.await\.map_err\(CompletionError::Repository\)\?;/g, 'drop(future);', /COMMIT wrapper/);
rejectsBosh('BOSH commit helper cannot erase a known receipt', 'boshCore', /permit\.received\(\);/g, '', /COMMIT wrapper/);
rejectsBosh('BOSH return cannot substitute the observed source', 'boshCore', /transfer\.returned_source = Some\(current\);/g, 'transfer.returned_source = Some(other_source);', /actual return/);
rejectsBosh('BOSH return cannot fabricate receipt agreement', 'boshCore', /transfer\.return_matches_receipt\s*=\s*transfer\.knowledge == TransferKnowledge::ReceiptKnown\(current\);/g, 'transfer.return_matches_receipt = true;', /matching receipt authority/);
rejectsBosh('BOSH return cannot accept an unmatched receipt', 'boshCore', /if !transfer\.return_matches_receipt\s*\{/g, 'if false {', /matching receipt authority/);
rejectsBosh('BOSH Drop must destroy the child first', 'boshOwner', /drop\(self\.child\.take\(\)\);/g, '', /destroy its child/);
rejectsBosh('BOSH poll must preserve caught panic knowledge', 'boshOwner', /this\.poll_in_progress = true;/g, 'this.poll_in_progress = false;', /actual timeout\/return/);
rejectsBosh('BOSH poll must retain the actual keep-running result', 'boshOwner', /result\.as_ref\(\)\.ok\(\)\.copied\(\)/g, 'Some(true)', /keep_running/);

test('BOSH response ownership uses the actual production helpers', () => verifyBoshResponseBoundaries(baseline));
test('BOSH response comments cannot add receipt or exposure authority', () => {
  verifyBoshResponseBoundaries({ ...baseline, boshResponseCore: `/* permit.received();\n#[cfg(test)]\nmod tests */\n${baseline.boshResponseCore}` });
});
function rejectsBoshResponse(name, file, pattern, replacement, expected) {
  test(name, () => {
    const source = baseline[file];
    const marker = /\n#\[cfg\(test\)\]\s*\nmod tests\s*\{/.exec(source);
    const split = marker ? marker.index : source.length;
    const production = source.slice(0, split);
    assert.equal([...production.matchAll(pattern)].length, 1, 'BOSH response mutation must match exactly once in production source');
    const changedSource = production.replace(pattern, replacement) + source.slice(split);
    assert.notEqual(changedSource, source, 'BOSH response mutation must change source');
    assert.throws(() => verifyBoshResponseBoundaries({ ...baseline, [file]: changedSource }), expected);
  });
}
rejectsBoshResponse('response preparation cannot borrow another FIFO', 'bosh',
  /output: &mut self\.output,/g, 'output: &mut other_output,', /actual actor fields/);
rejectsBoshResponse('response cache predicate cannot include pause controls', 'bosh',
  /cache: cache && condition\.is_none\(\) && pending\.request\.pause\.is_none\(\),/g,
  'cache: cache && condition.is_none(),', /existing cache predicate/);
rejectsBoshResponse('cached replay cannot precede ACK validation', 'bosh',
  /if !valid_client_response_ack\(/g, 'if !unchecked_client_response_ack(', /validate client ACK/);
rejectsBoshResponse('fresh BOSH ACK cannot bypass the shared helper', 'bosh',
  /\.renew_and_apply_response_ack\(request\.ack, operation\)/g, '.apply_ack_without_renewal(request.ack, operation)', /key, shape/);
rejectsBoshResponse('actor ACK wrapper cannot bypass its production helper', 'bosh',
  /response_owner::renew_and_acknowledge\(/g, 'response_owner::unobserved_acknowledge(', /actor ACK wrapper/);
rejectsBoshResponse('actor pause wrapper cannot bypass the empty-control primitive', 'bosh',
  /response_owner::finish_empty_control\(/g, 'response_owner::unobserved_empty_control(', /actor pause wrapper/);
for (const method of ['bind_bosh_response_sources', 'renew_bosh_fences', 'acknowledge_bosh_responses']) {
  rejectsBoshResponse(`${method} port cannot replace its request`, 'boshResponse',
    new RegExp(`(self\\.service\\.${method}\\()request(\\))`, 'g'),
    '$1other_request$2', /ReplayPort must pass each exact request/);
}
rejectsBoshResponse('bind port cannot receive a replacement request', 'boshResponse',
  /port\.bind\(&request\)/g, 'port.bind(&other_request)', /bind selected sources/);
rejectsBoshResponse('bind return cannot replace actual membership', 'boshResponse',
  /request\.returned\(ownership\)/g, 'request.returned(other_ownership)', /actual returned membership/);
rejectsBoshResponse('typed bind errors cannot bypass restoration authority', 'boshResponse',
  /request\.supersession\(message_id\)/g, 'invent_restoration(message_id)', /independent pre-COMMIT authority/);
rejectsBoshResponse('restoration cannot use another transaction knowledge class', 'boshResponseCore',
  /(pub fn supersession[\s\S]*?attempt\.knowledge != )BindKnowledge::NoCommitRequested/g,
  '$1BindKnowledge::NotRequired', /cannot restore an entered or confirmed bind/);
rejectsBoshResponse('bind return cannot fabricate receipt agreement', 'boshResponseCore',
  /BindKnowledge::ReceiptKnown\(receipt\) => receipt == &ownership/g,
  'BindKnowledge::ReceiptKnown(receipt) => true', /matching receipt authority/);
rejectsBoshResponse('payload exposure cannot omit the matching receipt guard', 'boshResponseCore',
  /if !attempt\.return_matches \|\| attempt\.restored/g, 'if false', /checked bound continuation/);
rejectsBoshResponse('cache insertion cannot be recorded before the actual push', 'boshResponse',
  /(if metadata\.cache \{)([\s\S]*?)bookkeeping\.cached\(\);/g,
  '$1 bookkeeping.cached(); $2', /record insertion after the actual push/);
rejectsBoshResponse('cache cannot replace returned membership', 'boshResponse',
  /durable_ownership: ownership,/g, 'durable_ownership: other_ownership,', /same bytes, membership/);
rejectsBoshResponse('pause cannot turn into a terminal control', 'boshResponse',
  /operation\.observe_empty_control\(rid\)/g, 'operation.observe_terminal_control(rid)', /empty synchronous control/);
rejectsBoshResponse('cached renewal cannot target another RID', 'boshResponse',
  /operation\.begin_renew\(Some\(\(request\.rid, ownership\)\)\)/g,
  'operation.begin_renew(Some((other_rid, ownership)))', /exact renewal before payload exposure/);
rejectsBoshResponse('cached replay cannot apply a fresh ACK', 'boshResponse',
  /exposure\.updated\(\);/g, 'exposure.updated(); port.acknowledge(&other_request).await.unwrap();', /cannot apply a fresh ACK/);
rejectsBoshResponse('fresh ACK must retain the actual receipt-send result', 'boshResponse',
  /acknowledged\.receipt_sent\(accepted\);/g, 'acknowledged.receipt_sent(true);', /actual receipt sends/);
rejectsBoshResponse('fresh ACK cannot evict a different RID prefix', 'boshResponse',
  /cached\.rid <= acknowledged\.rid\(\)/g, 'cached.rid <= other_rid', /exact committed return/);
rejectsBoshResponse('BOSH bind service cannot retarget its closed request', 'replayService',
  /\.bind_bosh_response_sources\(request\)/g, '.bind_bosh_response_sources(other_request)', /service must forward/);
rejectsBoshResponse('BOSH renewal repository cannot retarget its closed request', 'replayRepository',
  /renew_bosh_transport_fences\(&self\.pool, request\)/g,
  'renew_bosh_transport_fences(&self.pool, other_request)', /repository must forward/);
rejectsBoshResponse('bind SQL cannot omit its independent COMMIT receipt', 'replayDb',
  /response::bind_commit_observed/g, 'response::unobserved_bind_commit', /independent membership receipt/);
rejectsBoshResponse('renewal SQL cannot replace expected cache membership', 'replayDb',
  /let expected_response = request\.expected\(\);/g, 'let expected_response = None;', /closed request inputs/);
rejectsBoshResponse('ACK SQL cannot fabricate its deletion count', 'replayDb',
  /let acknowledged = deleted_sources\.len\(\);/g, 'let acknowledged = 0;', /actual deletion facts/);
for (const kind of ['bind', 'renew', 'ack']) {
  rejectsBoshResponse(`${kind} response COMMIT cannot discard its receipt`, 'boshResponseCore',
    new RegExp(`(pub async fn ${kind}_commit_observed[\\s\\S]*?)permit\\.received\\(\\);`, 'g'),
    '$1', /response COMMIT wrappers/);
}

function rejectsMixWorker(name, file, before, after, expected, matches = 1) {
  test(name, () => assert.throws(() => verifyMixWorkerBoundaries(
    changedMuc(file, before, after, matches)), expected));
}

test('MIX worker production adapters and private permissions satisfy their gate', () => verifyMixWorkerBoundaries(baseline));
rejectsMixWorker('MIX shared worker port cannot grow a generic executor operation', 'mix',
  "trait ClaimedMixDeliveryPort: Clone + Send + Sync + 'static {",
  "trait ClaimedMixDeliveryPort: Clone + Send + Sync + 'static { fn execute(&self);", /port must contain only/);
test('MIX production port cannot retain an extra field', () => {
  assert.throws(() => verifyMixWorkerBoundaries(changed('mix',
    'struct MixOutboxDeliveryPort<C> {\n    pub context: Arc<C>,\n}',
    'struct MixOutboxDeliveryPort<C> {\n    pub context: Arc<C>,\n    retained: bool,\n}')),
  { message: 'execution boundary: MIX production port must retain only its existing context' });
});
test('MIX production port cannot substitute its context type', () => {
  assert.throws(() => verifyMixWorkerBoundaries(changed('mix',
    'struct MixOutboxDeliveryPort<C> {\n    pub context: Arc<C>,\n}',
    'struct MixOutboxDeliveryPort<C> {\n    pub context: Arc<()>,\n}')),
  { message: 'execution boundary: MIX production port must retain only its existing context' });
});
rejectsMixWorker('MIX attempt UUID equality cannot replace private invocation identity', 'mixWorkerCore',
  'fn same(&self, other: &Self) -> bool { Arc::ptr_eq(&self.0, &other.0) }',
  'fn same(&self, other: &Self) -> bool { self.row().source == other.row().source }', /private invocation identity/);

// The baseline is the untouched source read from disk, including the proposed
// Rust observer after an authorized integration. Do not synthesize a positive
// fixture by patching baseline source into the gate's expected contract.
test('untouched BOSH selection observer satisfies focused and complete production gates', () => {
  verifyBoshSelectionObservations(baseline);
  verifyExecutionBoundaries(baseline);
  verifyBoshResponseBoundaries(baseline);
});
function rejectsSelection(name, before, after, expected) {
  test(name, () => {
    const mutant = changedMuc('boshResponse', before, after);
    assert.throws(() => verifyBoshSelectionObservations(mutant), expected);
    assert.throws(() => verifyExecutionBoundaries(mutant));
    assert.throws(() => verifyBoshResponseBoundaries(mutant));
  });
}
for (const [name, declaration] of [
  ['capacity', 'const MAX_SELECTED_FACTS: usize = 4;'],
  ['status', '#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum SelectionReadStatus'],
  ['item snapshot', '#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct SelectedItemSnapshot'],
  ['response snapshot', '#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct SelectionSnapshot'],
  ['retained item', 'struct SelectedItemRead'],
  ['retained state', 'struct SelectionState'],
  ['handle', '#[derive(Clone)] pub struct SelectionObservation'],
  ['implementation', 'impl SelectionObservation'],
]) {
  rejectsSelection(`BOSH selection ${name} cannot escape test configuration`,
    `${CROSS_CRATE_TEST_ONLY} ${declaration}`, declaration, /exact test-only declaration/);
}
rejectsSelection('BOSH selection observation capacity cannot grow',
  'const MAX_SELECTED_FACTS: usize = 4;', 'const MAX_SELECTED_FACTS: usize = 5;', /exact test-only declaration/);
rejectsSelection('BOSH selection snapshot cannot retain an unbounded collection',
  'pub items: [Option<SelectedItemSnapshot>; MAX_SELECTED_FACTS]',
  'pub items: Vec<SelectedItemSnapshot>', /capacity|fact-only field shape/);
rejectsSelection('BOSH selection retained state cannot retain an unbounded collection',
  'status: SelectionReadStatus, items: [Option<SelectedItemRead>; MAX_SELECTED_FACTS]',
  'status: SelectionReadStatus, items: Vec<SelectedItemRead>', /capacity|fact-only field shape/);
rejectsSelection('BOSH selection capture cannot allocate an unbounded collection',
  'let items: [Option<SelectedItemRead>; MAX_SELECTED_FACTS] = std::array::from_fn(|ordinal|',
  'let items: Vec<SelectedItemRead> = selected.iter().map(|ordinal|', /capacity|final FIFO facts/);
rejectsSelection('BOSH selection status cannot lose its missing-association count',
  'Incomplete { omitted_items: usize, missing_auth_associations: usize, connection_changed: bool, }',
  'Incomplete { omitted_items: usize, connection_changed: bool, }', /fact-only field shape/);
rejectsSelection('BOSH selection status cannot lose its sticky connection-change fact',
  'Incomplete { omitted_items: usize, missing_auth_associations: usize, connection_changed: bool, }',
  'Incomplete { omitted_items: usize, missing_auth_associations: usize, }', /fact-only field shape/);
for (const [name, field] of [
  ['holder', 'Option<northstar_stream::auth_publication::AuthControlHolder>'],
  ['receipt', 'Option<northstar_auth_application::authentication::CredentialCommitReceipt>'],
  ['publication observation', 'Option<northstar_auth_application::authentication::publication::Observation>'],
  ['consuming owner', 'Option<northstar_stream::auth_publication::OwnedPublication>'],
  ['response bytes', 'Option<BoshHttpResponse>'],
]) {
  rejectsSelection(`BOSH selection retained item cannot extend ${name} lifetime`,
    'struct SelectedItemRead {', `struct SelectedItemRead { retained: ${field},`, /fact-only field shape/);
}
rejectsSelection('BOSH selection handle cannot retain actual holders',
  'pub struct SelectionObservation(Arc<std::sync::Mutex<SelectionState>>);',
  'pub struct SelectionObservation(Arc<Vec<northstar_stream::auth_publication::AuthControlHolder>>);', /exact test-only declaration/);
rejectsSelection('BOSH selection handle tuple field cannot become public',
  'pub struct SelectionObservation(Arc<std::sync::Mutex<SelectionState>>);',
  'pub struct SelectionObservation(pub Arc<std::sync::Mutex<SelectionState>>);', /exact test-only declaration/);
rejectsSelection('BOSH selection state cannot expose mutable facts',
  'struct SelectionState { session: uuid::Uuid,',
  'struct SelectionState { pub session: uuid::Uuid,', /fact-only field shape/);
rejectsSelection('BOSH selection snapshot cannot silently lose its digest field',
  'pub sha256: [u8; 32],', '', /fact-only field shape/);
rejectsSelection('BOSH selection snapshot cannot acquire unreviewed derives',
  '#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct SelectionSnapshot',
  '#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)] pub struct SelectionSnapshot', /exact test-only declaration/);
rejectsSelection('BOSH selection cannot add a mutable reset API',
  'impl SelectionObservation {',
  'impl SelectionObservation { pub fn reset(&self) { self.0.lock().unwrap().status = SelectionReadStatus::Complete; }', /closed capture/);
rejectsSelection('BOSH selection snapshots cannot acquire an authority conversion',
  'impl SelectionObservation {',
  'impl SelectionSnapshot { fn into_owner(self) -> OwnedPublication { panic!() } } impl SelectionObservation {', /exact test-only declaration|closed capture/);
rejectsSelection('BOSH selection capture cannot become a public constructor',
  'fn capture(selected: &VecDeque<OutboundItem>, operation: &Operation, metadata: Metadata) -> Self',
  'pub fn capture(selected: &VecDeque<OutboundItem>, operation: &Operation, metadata: Metadata) -> Self', /immutable fact-only snapshot declarations/);
rejectsSelection('BOSH selection capture cannot retain a borrowed queue lifetime',
  'fn capture(selected: &VecDeque<OutboundItem>, operation: &Operation, metadata: Metadata) -> Self',
  "fn capture<'a>(selected: &'a VecDeque<OutboundItem>, operation: &Operation, metadata: Metadata) -> Self", /immutable fact-only snapshot declarations/);
rejectsSelection('BOSH selection snapshot getter cannot return mutable state',
  'pub fn snapshot(&self) -> SelectionSnapshot',
  'pub fn snapshot(&mut self) -> &mut SelectionState', /immutable fact-only snapshot declarations/);
rejectsSelection('BOSH selection owner getter cannot escape test configuration',
  `${CROSS_CRATE_TEST_ONLY} pub fn selection_observation(&self) -> SelectionObservation`,
  'pub fn selection_observation(&self) -> SelectionObservation', /test-only and clone only/);
rejectsSelection('BOSH selection owner field cannot escape test configuration',
  `${CROSS_CRATE_TEST_ONLY} selection: SelectionObservation`, 'selection: SelectionObservation', /private test-only fact handle/);
rejectsSelection('BOSH selection owner getter cannot mutate its stored facts',
  'pub fn selection_observation(&self) -> SelectionObservation { self.selection.clone() }',
  'pub fn selection_observation(&self) -> SelectionObservation { self.selection.0.lock().unwrap().status = SelectionReadStatus::Complete; self.selection.clone() }', /test-only and clone only/);
rejectsSelection('BOSH selection owner getter cannot leak selected controls',
  'pub fn selection_observation(&self) -> SelectionObservation { self.selection.clone() }',
  'pub fn selection_observation(&self) -> &SelectedControls { &self.auth_controls }', /test-only and clone only/);
for (const [name, before, after] of [
  ['explicit overflow count', 'let omitted_items = selected.len().saturating_sub(MAX_SELECTED_FACTS);', 'let omitted_items = 0;'],
]) {
  rejectsSelection(`BOSH selection capture must retain ${name}`, before, after, /capacity|final FIFO facts/);
}
for (const [name, before, after] of [
  ['bound effect literal', 'bound_effects: state.bound_effects,', 'bound_effects: true,'],
  ['notification literal', 'notification_expected: state.notification_expected', 'notification_expected: false'],
  ['bound effect fixture', 'bound_effects: state.bound_effects,', 'bound_effects: expected_bound_effects,'],
  ['notification fixture', 'notification_expected: state.notification_expected', 'notification_expected: expected_notification'],
  ['bound effect receipt-kind inference', 'bound_effects: state.bound_effects,', 'bound_effects: state.snapshot.receipt == ReceiptKind::Binding,'],
  ['notification receipt-kind inference', 'notification_expected: state.notification_expected', 'notification_expected: state.snapshot.receipt == ReceiptKind::Resume'],
]) {
  rejects(`auth publication joins reject ${name}`, 'authFacts', before, after, /actual State effect intent/);
}
rejects('auth publication intent fields cannot retain an authoritative observation', 'authFacts',
  'pub bound_effects: bool, pub notification_expected: bool',
  'pub bound_effects: bool, pub notification_expected: bool, pub retained: Observation', /test-only association facts/);
rejects('auth publication joins preserve exact read-only derives', 'authFacts',
  '#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct PublicationJoins',
  '#[derive(Clone, Debug, Eq, PartialEq)] pub struct PublicationJoins', /exact test-only derives/);

test('auth publication joins reject a separate preceding derive attribute', () => {
  const mutant = changedMuc('authFacts',
    `${CROSS_CRATE_TEST_ONLY} #[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct PublicationJoins`,
    `#[derive(Default)] ${CROSS_CRATE_TEST_ONLY} #[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct PublicationJoins`);
  assert.throws(() => verifyExecutionBoundaries(mutant),
    { message: 'execution boundary: auth PublicationJoins must preserve its exact test-only derives' });
});

// Actual untouched production input, never a synthesized positive source fixture.
test('untouched route helpers satisfy focused and complete production gates', () => {
  verifyRouteHelperBoundaries(baseline);
  verifyExecutionBoundaries(baseline);
});
function rejectsRoute(name, file, before, after, complete = false, expectedMatches = 1) {
  test(name, () => {
    const mutant = changedMuc(file, before, after, expectedMatches);
    assert.throws(() => verifyRouteHelperBoundaries(mutant), /execution boundary: route helper/);
    if (complete) assert.throws(() => verifyExecutionBoundaries(mutant), /execution boundary: route helper/);
  });
}
rejectsRoute("route epoch helper cannot become test-only", "sessionTable",
  "pub fn publish_user_agent_epoch_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    key: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    user_agent_epoch: Option<i64>,\n) -> bool",
  "#[cfg(test)] pub fn publish_user_agent_epoch_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    key: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    user_agent_epoch: Option<i64>,\n) -> bool");
rejectsRoute("route activation helper cannot become test-only", "sessionTable",
  "pub fn activate_session_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    full_jid: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    disconnect: &CancellationToken,\n) -> bool",
  "#[cfg(test)] pub fn activate_session_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    full_jid: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    disconnect: &CancellationToken,\n) -> bool");
rejectsRoute("route caps helper cannot become test-only", "sessionTable",
  "pub fn session_mix_capability_in(\n    sessions: &DashMap<String, OnlineSession>,\n    caps_by_jid: &CapsResourceIndex,\n    pending_caps: &PendingCapsIndex,\n    full_jid: &str,\n) -> MixSessionCapability",
  "#[cfg(test)] pub fn session_mix_capability_in(\n    sessions: &DashMap<String, OnlineSession>,\n    caps_by_jid: &CapsResourceIndex,\n    pending_caps: &PendingCapsIndex,\n    full_jid: &str,\n) -> MixSessionCapability");
rejectsRoute("route epoch helper cannot be replaced by a test-module shadow", "sessionTable",
  "pub fn publish_user_agent_epoch_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    key: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    user_agent_epoch: Option<i64>,\n) -> bool {\n    let Some(mut session) = sessions.get_mut(key) else {\n        return false;\n    };\n    if session.connection_id != connection_id\n        || session.user_id != user_id\n        || session.auth_generation != auth_generation\n        || !Arc::ptr_eq(&session.lifecycle, lifecycle)\n        || session.disconnect.is_cancelled()\n        || session.lifecycle.load(Ordering::Acquire) != 0\n    {\n        return false;\n    }\n    session.user_agent_epoch = user_agent_epoch;\n    true\n}\n",
  "#[cfg(test)] mod shadow_route { pub fn publish_user_agent_epoch_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    key: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    user_agent_epoch: Option<i64>,\n) -> bool {\n    let Some(mut session) = sessions.get_mut(key) else {\n        return false;\n    };\n    if session.connection_id != connection_id\n        || session.user_id != user_id\n        || session.auth_generation != auth_generation\n        || !Arc::ptr_eq(&session.lifecycle, lifecycle)\n        || session.disconnect.is_cancelled()\n        || session.lifecycle.load(Ordering::Acquire) != 0\n    {\n        return false;\n    }\n    session.user_agent_epoch = user_agent_epoch;\n    true\n}\n }");
rejectsRoute("route epoch helper rejects duplicate test-module shadow", "sessionTable",
  "pub fn publish_user_agent_epoch_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    key: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    user_agent_epoch: Option<i64>,\n) -> bool {\n    let Some(mut session) = sessions.get_mut(key) else {\n        return false;\n    };\n    if session.connection_id != connection_id\n        || session.user_id != user_id\n        || session.auth_generation != auth_generation\n        || !Arc::ptr_eq(&session.lifecycle, lifecycle)\n        || session.disconnect.is_cancelled()\n        || session.lifecycle.load(Ordering::Acquire) != 0\n    {\n        return false;\n    }\n    session.user_agent_epoch = user_agent_epoch;\n    true\n}\n",
  "pub fn publish_user_agent_epoch_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    key: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    user_agent_epoch: Option<i64>,\n) -> bool {\n    let Some(mut session) = sessions.get_mut(key) else {\n        return false;\n    };\n    if session.connection_id != connection_id\n        || session.user_id != user_id\n        || session.auth_generation != auth_generation\n        || !Arc::ptr_eq(&session.lifecycle, lifecycle)\n        || session.disconnect.is_cancelled()\n        || session.lifecycle.load(Ordering::Acquire) != 0\n    {\n        return false;\n    }\n    session.user_agent_epoch = user_agent_epoch;\n    true\n}\n\n#[cfg(test)] mod shadow_route { pub fn publish_user_agent_epoch_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    key: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    user_agent_epoch: Option<i64>,\n) -> bool {\n    let Some(mut session) = sessions.get_mut(key) else {\n        return false;\n    };\n    if session.connection_id != connection_id\n        || session.user_id != user_id\n        || session.auth_generation != auth_generation\n        || !Arc::ptr_eq(&session.lifecycle, lifecycle)\n        || session.disconnect.is_cancelled()\n        || session.lifecycle.load(Ordering::Acquire) != 0\n    {\n        return false;\n    }\n    session.user_agent_epoch = user_agent_epoch;\n    true\n}\n }");
rejectsRoute("route epoch delegate cannot become test-only", "sessionTable",
  "pub fn publish_user_agent_epoch_if_current(\n        &self,\n        key: &str,\n        connection_id: uuid::Uuid,\n        user_id: uuid::Uuid,\n        auth_generation: i64,\n        lifecycle: &Arc<AtomicU8>,\n        user_agent_epoch: Option<i64>,\n    ) -> bool",
  "#[cfg(test)] pub fn publish_user_agent_epoch_if_current(\n        &self,\n        key: &str,\n        connection_id: uuid::Uuid,\n        user_id: uuid::Uuid,\n        auth_generation: i64,\n        lifecycle: &Arc<AtomicU8>,\n        user_agent_epoch: Option<i64>,\n    ) -> bool");
rejectsRoute("route activation delegate cannot become test-only", "sessionTable",
  "pub fn activate_session_if_current(\n        &self,\n        full_jid: &str,\n        connection_id: uuid::Uuid,\n        user_id: uuid::Uuid,\n        auth_generation: i64,\n        lifecycle: &Arc<AtomicU8>,\n        disconnect: &CancellationToken,\n    ) -> bool",
  "#[cfg(test)] pub fn activate_session_if_current(\n        &self,\n        full_jid: &str,\n        connection_id: uuid::Uuid,\n        user_id: uuid::Uuid,\n        auth_generation: i64,\n        lifecycle: &Arc<AtomicU8>,\n        disconnect: &CancellationToken,\n    ) -> bool");
rejectsRoute("route caps delegate cannot become test-only", "mixOutboxState",
  "fn session_mix_capability(&self, full_jid: &str) -> MixSessionCapability",
  "#[cfg(test)] fn session_mix_capability(&self, full_jid: &str) -> MixSessionCapability");
rejectsRoute("route CAPS delegate preserves the pending index", "mixOutboxState",
  "session_mix_capability_in(&self.sessions, &self.caps_by_jid, &self.pending_caps, full_jid)",
  "session_mix_capability_in(&self.sessions, &self.caps_by_jid, &other_pending_caps, full_jid)");
rejectsRoute("route CAPS delegate preserves the queried key", "mixOutboxState",
  "session_mix_capability_in(&self.sessions, &self.caps_by_jid, &self.pending_caps, full_jid)",
  "session_mix_capability_in(&self.sessions, &self.caps_by_jid, &self.pending_caps, other_jid)");
rejectsRoute("route activation must call the actual shared predicate", "sessionTable",
  "if !staged_route_activation_allowed(StagedRouteActivationCheck {\n        session: StagedRouteIdentity {\n            connection_id: session.connection_id,\n            user_id: session.user_id,\n            auth_generation: session.auth_generation,\n        },\n        expected: StagedRouteIdentity {\n            connection_id,\n            user_id,\n            auth_generation,\n        },\n        same_lifecycle: Arc::ptr_eq(&session.lifecycle, lifecycle),\n        lifecycle_state: session.lifecycle.load(Ordering::Acquire),\n        session_cancelled: session.disconnect.is_cancelled(),\n        owner_cancelled: disconnect.is_cancelled(),\n    }) {\n        return false;\n    }",
  "if false { return false; }", true);
rejectsRoute("route activation passes actual staged identity", "sessionTable",
  "session: StagedRouteIdentity { connection_id: session.connection_id, user_id: session.user_id, auth_generation: session.auth_generation, }",
  "session: StagedRouteIdentity { connection_id, user_id, auth_generation, }");
rejectsRoute("route activation passes actual lifecycle identity", "sessionTable",
  "same_lifecycle: Arc::ptr_eq(&session.lifecycle, lifecycle),",
  "same_lifecycle: true,");
rejectsRoute("route activation passes actual owner cancellation", "sessionTable",
  "owner_cancelled: disconnect.is_cancelled(), }) {",
  "owner_cancelled: false, }) {");
rejectsRoute("route activation retains its map write guard", "sessionTable",
  "pub fn activate_session_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    full_jid: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    disconnect: &CancellationToken,\n) -> bool {\n    let Some(session) = sessions.get_mut(full_jid) else {\n        return false;\n    };\n",
  "pub fn activate_session_if_current_in(\n    sessions: &DashMap<String, OnlineSession>,\n    full_jid: &str,\n    connection_id: uuid::Uuid,\n    user_id: uuid::Uuid,\n    auth_generation: i64,\n    lifecycle: &Arc<AtomicU8>,\n    disconnect: &CancellationToken,\n) -> bool {\n    let Some(session) = sessions.get(full_jid).map(|entry| entry.value().clone()) else {\n        return false;\n    };\n");
rejectsRoute("route activation must publish true before rechecking", "sessionTable",
  "session.routable.store(true, Ordering::Release); if session.lifecycle.load(Ordering::Acquire) != 0 || session.disconnect.is_cancelled() || disconnect.is_cancelled() { session.routable.store(false, Ordering::Release); return false; } true",
  " if session.lifecycle.load(Ordering::Acquire) != 0 || session.disconnect.is_cancelled() || disconnect.is_cancelled() { session.routable.store(false, Ordering::Release); return false; } true");
rejectsRoute("route activation rechecks the lifecycle after publication", "sessionTable",
  "session.routable.store(true, Ordering::Release); if session.lifecycle.load(Ordering::Acquire) != 0 || session.disconnect.is_cancelled() || disconnect.is_cancelled() { session.routable.store(false, Ordering::Release); return false; } true",
  "session.routable.store(true, Ordering::Release); if session.disconnect.is_cancelled() || disconnect.is_cancelled() { session.routable.store(false, Ordering::Release); return false; } true");
rejectsRoute("route activation rechecks the session token after publication", "sessionTable",
  "session.routable.store(true, Ordering::Release); if session.lifecycle.load(Ordering::Acquire) != 0 || session.disconnect.is_cancelled() || disconnect.is_cancelled() { session.routable.store(false, Ordering::Release); return false; } true",
  "session.routable.store(true, Ordering::Release); if session.lifecycle.load(Ordering::Acquire) != 0 || disconnect.is_cancelled() { session.routable.store(false, Ordering::Release); return false; } true");
rejectsRoute("route activation rechecks the owner token after publication", "sessionTable",
  "session.routable.store(true, Ordering::Release); if session.lifecycle.load(Ordering::Acquire) != 0 || session.disconnect.is_cancelled() || disconnect.is_cancelled() { session.routable.store(false, Ordering::Release); return false; } true",
  "session.routable.store(true, Ordering::Release); if session.lifecycle.load(Ordering::Acquire) != 0 || session.disconnect.is_cancelled() { session.routable.store(false, Ordering::Release); return false; } true");
rejectsRoute("route activation must roll back false on a failed recheck", "sessionTable",
  "session.routable.store(true, Ordering::Release); if session.lifecycle.load(Ordering::Acquire) != 0 || session.disconnect.is_cancelled() || disconnect.is_cancelled() { session.routable.store(false, Ordering::Release); return false; } true",
  "session.routable.store(true, Ordering::Release); if session.lifecycle.load(Ordering::Acquire) != 0 || session.disconnect.is_cancelled() || disconnect.is_cancelled() {  return false; } true");
