import assert from 'node:assert/strict';
import test from 'node:test';
import { findRustItem, matchingRustBrace } from './lib/source-module.mjs';
import { readExecutionSources, verifyExecutionBoundaries, verifyRoomExecutionBoundaries, verifyMucDiscussionBoundaries, verifyMixForegroundBoundaries, verifyMixWorkerBoundaries, verifyBoshSelectionObservations, verifyRouteHelperBoundaries } from './check-execution-boundaries.mjs';

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
rejects('BOSH ingress cannot bypass observed execution', 'bosh',
  'match self.protocol.process_frame(payload).await {',
  'match self.protocol.handle(payload).await {', /BOSH must enter/);
rejects('BOSH publication cannot bypass observed owner', 'bosh',
  '.publish_committed_authentication_and_route(owner)',
  '.publish_committed_authentication_and_route_inner(owner)', /auth BOSH continuation/);
rejects('BOSH publication failure cannot succeed', 'bosh',
  'Ok(ready) => ready,\n            Err(_) => return false',
  'Ok(ready) => ready,\n            Err(_) => return true', /BOSH must observe publication/);
rejects('BOSH cannot insert a suspension between exposure and publication', 'bosh',
  'let ready = match exposed',
  'tokio::task::yield_now().await;\n        let ready = match exposed', /BOSH must observe publication/);
rejects('BOSH activation marker cannot be hidden behind a dead condition', 'boshAction',
  'let item = if index == 0 {',
  'let item = if false {', /BOSH activation/);
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
});
function rejectsSelection(name, before, after, expected) {
  test(name, () => {
    const mutant = changedMuc('boshResponse', before, after);
    assert.throws(() => verifyBoshSelectionObservations(mutant), expected);
    assert.throws(() => verifyExecutionBoundaries(mutant));
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
