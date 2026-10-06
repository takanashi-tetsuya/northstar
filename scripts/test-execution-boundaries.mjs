import assert from 'node:assert/strict';
import test from 'node:test';
import { readExecutionSources, verifyExecutionBoundaries, verifyRoomExecutionBoundaries, verifyMucDiscussionBoundaries, verifyMixForegroundBoundaries, verifyMixWorkerBoundaries, verifyNativeAckService, verifyNativeWriteBoundaries, verifySmOwnershipBoundaries, verifyBoshTransferBoundaries, verifyBoshResponseBoundaries } from './check-execution-boundaries.mjs';

const baseline = readExecutionSources();
function changed(file, before, after) {
  assert.equal(baseline[file].split(before).length, 2, `mutation must match exactly once: ${before}`);
  assert.notEqual(before, after, 'string mutation must not be a no-op');
  return { ...baseline, [file]: baseline[file].replace(before, after) };
}
function rejects(name, file, before, after, expected) {
  test(name, () => assert.throws(() => verifyExecutionBoundaries(changedMuc(file, before, after)), expected));
}

test('current production execution owners satisfy the gate', () => verifyExecutionBoundaries(baseline));
test('comments and ordinary formatting are not executable authority', () => {
  verifyExecutionBoundaries(changed('frame', 'let result = future.await;',
    'let /* comment { } */ result =\n future . await;'));
});
rejects('native TCP ingress cannot bypass observed frame execution', 'transport',
  'let action = match session.process_frame(&frame).await {\n                        Ok(action) => action,',
  'let action = match session.handle(&frame).await {\n                        Ok(action) => action,', /drive_io/);
rejects('native WebSocket ingress cannot bypass observed frame execution', 'transport',
  'let action = match session.process_frame(&frame).await {\n                            Ok(action) => Ok(action),',
  'let action = match session.handle(&frame).await {\n                            Ok(action) => Ok(action),', /websocket_connection/);
rejects('activation must retain originating frame', 'protocol',
  'CredentialAttempt::new(self.frame_executions.auth_origin(), self.connection_id, kind)', 'CredentialAttempt::new(None, self.connection_id, kind)', /originating frame/);
rejects('comment cannot replace originating frame ownership', 'protocol',
  'CredentialAttempt::new(self.frame_executions.auth_origin(), self.connection_id, kind)',
  '/* CredentialAttempt::new(self.frame_executions.auth_origin(), self.connection_id, kind) */', /originating frame/);
rejects('raw string cannot replace originating frame ownership', 'protocol',
  'CredentialAttempt::new(self.frame_executions.auth_origin(), self.connection_id, kind)',
  'r###"CredentialAttempt::new(self.frame_executions.auth_origin(), self.connection_id, kind)"###', /originating frame/);
rejects('publication cannot bypass typed observation', 'protocol',
  '.observe_publication(future)',
  '.run(future)', /observed typed owner/);
rejects('publication cannot add a deadline', 'frame',
  'let result = future.await;',
  'let result = tokio::time::timeout(FRAME_BUDGET, future).await.unwrap();', /without adding a deadline/);
rejects('publication cannot fork a detached observer', 'frame',
  'let result = future.await;',
  'tokio::spawn(async {}); let result = future.await;', /without adding a deadline/);
rejects('frame budget cannot be expanded to hide a stall', 'frame',
  'const FRAME_BUDGET: Duration = Duration::from_secs(5);',
  'const FRAME_BUDGET: Duration = Duration::from_secs(6);', /reviewed budget/);
rejects('WebSocket inline budget cannot drift', 'frame',
  'const INLINE_AUTH_BUDGET: Duration = Duration::from_secs(8);',
  'const INLINE_AUTH_BUDGET: Duration = Duration::from_secs(9);', /reviewed budget/);
rejects('backend failure cannot be flattened to credential rejection', 'authOwner',
  'return PublicationResult::BackendFailure;', 'return PublicationResult::CredentialRejected;', /BackendFailure/);
rejects('integrity failure cannot be flattened to credential rejection', 'authOwner',
  'AuthenticationResult::Authenticated(_) | AuthenticationResult::IntegrityFailure => { port.rejected(PublicationResult::IntegrityRejected, None); return PublicationResult::IntegrityRejected; }',
  'AuthenticationResult::Authenticated(_) | AuthenticationResult::IntegrityFailure => { port.rejected(PublicationResult::CredentialRejected, None); return PublicationResult::CredentialRejected; }', /IntegrityRejected/);
rejects('credential fence loss cannot continue transport', 'authOwner',
  'return PublicationResult::CredentialRejected;', 'return PublicationResult::Completed;', /credential fence/);
rejects('missing principal cannot become successful publication', 'protocol',
  'self.session.authenticated.as_ref().is_none_or(|user| { user.id != route.user || user.auth_generation != route.generation })',
  'self.session.authenticated.as_ref().is_some_and(|user| { user.id != route.user || user.auth_generation != route.generation })', /missing principal/);
rejects('deferred replacement notification must remain visible', 'authOwner',
  'return PublicationResult::CompletedWithDeferredNotification;',
  'return PublicationResult::Completed;', /visibly deferred/);
rejects('deferred replacement notification cannot force a client retry', 'frame',
  'Self::Completed | Self::CompletedWithDeferredNotification',
  'Self::Completed', /only authoritative publication success/);
for (const [file, helper, end] of [
  ['tcp', 'tcp_record_and_send_auth(io, session, reply, holder, opening).await?', 'return Ok(TcpActionDisposition::Close);'],
  ['websocket', 'write_auth_control(socket, reply, holder, send_cancellation).await', 'return false;'],
]) {
  rejects(`${file} first write must succeed before activation`, file,
    `let Some(owner) = ${helper} else { ${end} };`,
    `let Some(owner) = ${helper} else { ${end} }; tokio::task::yield_now().await;`, /successful first\/control write/);
  rejects(`${file} resumed control must succeed before activation`, file,
    `let Some(owner) = ${helper.replace('reply', 'control')} else { ${end} };`,
    `let Some(owner) = ${helper.replace('reply', 'control')} else { ${end} }; tokio::task::yield_now().await;`, /successful first\/control write/);
  rejects(`${file} publication guard cannot be supplied by a comment`, file,
    `let Some(owner) = ${helper} else { ${end} };`,
    `/* let Some(owner) = ${helper} else { ${end} }; */`, /successful first\/control write/);
  rejects(`${file} rejected publication must close rather than continue`, file,
    `let Some(owner) = ${helper} else { ${end} }; if !session.publish_committed_authentication_and_route(owner).await { ${end} }`,
    `let Some(owner) = ${helper} else { ${end} }; if !session.publish_committed_authentication_and_route(owner).await { continue; }`, /successful first\/control write/);
}

// Runtime trace tests alone do not prevent an adapter/owner bypass.
rejects('inner credential publication cannot acquire a new five-second deadline', 'authOwner',
  'match port.publish(&invocation).await {',
  'match tokio::time::timeout(std::time::Duration::from_secs(5), port.publish(&invocation)).await.unwrap_or(AuthenticationResult::StaleGeneration) {',
  /auth consuming sequence/);
rejects('backend publication outcome cannot report completed', 'frame',
  'Self::BackendFailure => Outcome::BackendFailure,',
  'Self::BackendFailure => Outcome::Completed,', /result-to-outcome classification/);
rejects('frame runner cannot apply inline budget to every transport', 'frame',
  'let budget = self.0.policy.budget;',
  'let budget = INLINE_AUTH_BUDGET;', /transport-specific policy budget/);
rejects('frame observation must exist before child polling', 'frame',
  'pub(super) fn run<T>(', 'pub(super) async fn run<T>(', /production body/);
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
rejects('frame backend failure cannot become completed', 'frame',
  'this.observation.finish(Outcome::BackendFailure);',
  'this.observation.finish(Outcome::Completed);', /typed terminal result/);
rejects('frame timeout cannot become backend failure', 'frame',
  'this.observation.finish(Outcome::TimedOut);',
  'this.observation.finish(Outcome::BackendFailure);', /typed terminal result/);
rejects('runner drop cannot omit child destruction', 'frame',
  'drop(self.child.take());', '', /destroy the child first/);
rejects('runner drop cannot forget a caught panic', 'frame',
  'if self.poll_in_progress {', 'if std::thread::panicking() {', /preserve a caught panic/);
rejects('capture behind a dead condition is not originating ownership', 'protocol',
  'CredentialAttempt::new(self.frame_executions.auth_origin(), self.connection_id, kind)',
  'CredentialAttempt::new(if false { self.frame_executions.auth_origin() } else { None }, self.connection_id, kind)', /originating frame/);
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
rejects('BOSH exposure must reflect actual responder acceptance', 'boshResponse',
  'let accepted = responder.send(response).is_ok();',
  'let accepted = true; let _ = responder.send(response);', /actual responder acceptance/);
rejects('BOSH cannot insert a suspension between exposure and publication', 'bosh',
  'let ready = match exposed',
  'tokio::task::yield_now().await;\n        let ready = match exposed', /BOSH must observe publication/);
rejects('BOSH activation marker cannot be hidden behind a dead condition', 'boshAction',
  'let item = if index == 0 {',
  'let item = if false {', /BOSH activation/);
rejects('BOSH resume must honor the activation flag', 'bosh',
  'let control = if activate_route {',
  'let control = if false {', /BOSH resume/);
rejects('BOSH publication cannot treat every accepted response as selected', 'boshResponse',
  'if self.auth_control_selected {',
  'if true {', /BOSH publication gate/);
rejects('BOSH publication callback failure cannot mint readiness', 'boshResponse',
  'anyhow::ensure!(publish(owners).await, "BOSH authentication publication failed");',
  'let _ = publish(owners).await;', /BOSH publication gate/);
rejects('BOSH selected membership must use the final response items', 'boshResponse',
  'SelectedControls::new(selected.iter().map(|item| (item.stanza.as_str(), item.auth_publication())))',
  'SelectedControls::new(fields.output.iter().map(|item| (item.stanza.as_str(), item.auth_publication())))', /BOSH auth membership/);
rejects('BOSH exposure cannot discard selected membership', 'boshResponse',
  'auth_control_selected: self.auth_control_selected,',
  'auth_control_selected: false,', /actual responder acceptance/);
rejects('BOSH plain compatibility finish cannot bypass auth publication', 'boshResponse',
  '!self.auth_control_selected,\n            "selected BOSH authentication control requires publication"',
  'true,\n            "selected BOSH authentication control requires publication"', /plain compatibility finish/);
rejects('BOSH item marker cannot become public mutable authority', 'outbound',
  '    bosh_auth_control: bool,',
  '    pub(crate) bosh_auth_control: bool,', /private item selection metadata/);
rejects('BOSH marker accessor cannot synthesize selected membership', 'outbound',
  'pub(crate) fn is_bosh_auth_control(&self) -> bool { self.bosh_auth_control }',
  'pub(crate) fn is_bosh_auth_control(&self) -> bool { true }', /private item selection metadata/);
rejects('BOSH cache cannot retain auth selection membership', 'bosh',
  'struct CachedResponse {',
  'struct CachedResponse {\n    auth_control_selected: bool,', /cache and replay/);
for (const owner of ['BoundResponse', 'ExposedResponse', 'PublicationReadyResponse']) {
  rejects(`BOSH ${owner} cannot derive Clone`, 'boshResponse',
    `pub(super) struct ${owner} {`,
    `#[derive(Clone)]\npub(super) struct ${owner} {`, /cannot derive or manually implement Clone or Copy/);
  rejects(`BOSH ${owner} cannot manually implement Clone`, 'boshResponse',
    `impl ${owner} {`,
    `impl Clone for ${owner} { fn clone(&self) -> Self { panic!("unreviewed clone") } }\nimpl ${owner} {`,
    /cannot derive or manually implement Clone or Copy/);
}
rejects('BOSH ready owner cannot derive Copy', 'boshResponse',
  'pub(super) struct PublicationReadyResponse {',
  '#[derive(Copy)]\npub(super) struct PublicationReadyResponse {', /cannot derive or manually implement Clone or Copy/);
rejects('BOSH exposed owner cannot manually implement Copy', 'boshResponse',
  'impl ExposedResponse {',
  'impl Copy for ExposedResponse {}\nimpl ExposedResponse {', /cannot derive or manually implement Clone or Copy/);
rejects('BOSH bound exposure must consume its owner', 'boshResponse',
  'pub(super) fn expose(mut self, responders: Vec<Responder>)',
  'pub(super) fn expose(&self, responders: Vec<Responder>)', /named consuming declaration heads/);
rejects('BOSH publication cannot borrow its exposed owner', 'boshResponse',
  'pub(super) async fn publish_authentication<F: Future<Output = bool>>(\n        mut self,',
  'pub(super) async fn publish_authentication<F: Future<Output = bool>>(\n        &self,', /named consuming declaration heads/);
rejects('BOSH ready bookkeeping must consume its owner', 'boshResponse',
  'impl PublicationReadyResponse {\n    pub(super) fn finish(\n        self,',
  'impl PublicationReadyResponse {\n    pub(super) fn finish(\n        &self,', /named consuming declaration heads/);
rejects('BOSH bound owner cannot expose mutable selected membership', 'boshResponse',
  '    bound: response::BoundResponse,\n    auth_control_selected: bool,',
  '    bound: response::BoundResponse,\n    pub(super) auth_control_selected: bool,', /exact private field shape/);
rejects('BOSH ready owner cannot expose its inner continuation', 'boshResponse',
  'pub(super) struct PublicationReadyResponse {\n    exposed: ExposedResponse',
  'pub(super) struct PublicationReadyResponse {\n    pub(super) exposed: ExposedResponse', /exact private field shape/);
rejects('BOSH ready owner cannot add an into_exposed escape', 'boshResponse',
  'impl PublicationReadyResponse {',
  'impl PublicationReadyResponse {\n    pub(super) fn into_exposed(self) -> Result<ExposedResponse> { Ok(self.exposed) }',
  /closed inherent-method inventory/);
rejects('BOSH readiness cannot be constructed by an extra free function', 'boshResponse',
  'impl PublicationReadyResponse {',
  'fn extra_readiness(exposed: ExposedResponse) -> Result<PublicationReadyResponse> { Ok(PublicationReadyResponse { exposed }) }\nimpl PublicationReadyResponse {',
  /cannot add named construction sites/);
rejects('BOSH ready owner cannot hide a Self constructor inside finish', 'boshResponse',
  '        let ExposedResponse {',
  '        let _extra = |exposed| Self { exposed };\n        let ExposedResponse {', /cannot add Self-brace construction/);
rejects('BOSH acceptance accessor must remain test-only', 'boshResponse',
  '#[cfg(test)]\n    pub(super) fn any_accepted(&self)',
  'pub(super) fn any_accepted(&self)', /test-only compatibility methods/);
rejects('BOSH plain compatibility finish must remain test-only', 'boshResponse',
  '#[cfg(test)]\n    pub(super) fn finish(',
  'pub(super) fn finish(', /test-only compatibility methods/);

// Finite auth owner/adapter negatives reuse the same exact token-span helper.
rejects('auth receipt identity cannot become public substitution authority', 'authService',
  'publication_identity: Uuid,', 'pub publication_identity: Uuid,', /receipt instance identity must remain private/);
rejects('auth value-equal receipt cannot substitute its private instance', 'authFacts',
  'state.receipt_id == receipt.publication_identity() && state.receipt == ReceiptProjection::of(receipt)',
  'state.receipt == ReceiptProjection::of(receipt)', /actual receipt and successful control transport/);
rejects('auth invocation cannot begin before successful control transport', 'authFacts',
  'ensure!(matches!(state.snapshot.transport, Transport::Written | Transport::BoshAccepted { .. }), "auth publication requires successful control transport");',
  '', /actual receipt and successful control transport/);
rejects('auth service start cannot be repeated through another borrow', 'authFacts',
  'ensure!(!state.snapshot.service_started, "auth publication service already started");',
  '', /distinct one-use transitions/);
rejects('auth repository start cannot be repeated before pool begin', 'authFacts',
  'ensure!(state.snapshot.service_started && !state.snapshot.repository_started, "auth publication repository is not pending");',
  'ensure!(state.snapshot.service_started, "auth publication repository is not pending");', /distinct one-use transitions/);
rejects('auth actual return must pass the observed service', 'protocol',
  '.publish_credential_commit_observed(invocation).await',
  '.publish_credential_commit(invocation.receipt()).await', /actual observed service/);
rejects('auth frame registration cannot accept another origin', 'frame',
  'observation.snapshot().frame == Some(self.0.operation_id)',
  'true', /frame registration/);
rejects('auth completed handler cannot retire a sealed publication', 'authFacts',
  'if !state.snapshot.sealed && state.snapshot.terminal.is_none() {',
  'if state.snapshot.terminal.is_none() {', /independently owned/);
rejects('auth COMMIT knowledge cannot be recorded after the await', 'authFacts',
  'state.snapshot.publication = Knowledge::CommitCallEntered;',
  'state.snapshot.publication = Knowledge::BeforeCommit;', /COMMIT entry, receipt and return/);
rejects('auth SQL publication cannot replace the stored epoch with a hint', 'authDb',
  'invocation.commit(tx.commit(), published_epoch)',
  'invocation.commit(tx.commit(), receipt.staged_login_epoch().map(|stage| stage.epoch))', /actual transaction order/);
rejects('auth actual return cannot mint a matching receipt', 'authFacts',
  'state.snapshot.publication == Knowledge::ReceiptKnown(epoch)',
  'true', /return cannot synthesize/);
rejects('auth final control binding cannot ignore its digest', 'authOwner',
  'self.0.length == control.len() && self.0.digest == <[u8; 32]>::from(Sha256::digest(control.as_bytes()))',
  'self.0.length == control.len()', /control bytes must match/);
rejects('auth native alias cannot write before claiming the current holder', 'authOwner',
  'state.pending.is_some() && state.phase == HolderPhase::Recording',
  'state.pending.is_some()', /native write must claim/);
rejects('auth late transport observation cannot overwrite written facts', 'authFacts',
  'ensure!(allowed, "auth transport observation is late or out of order");',
  '', /transport observations must remain monotone/);
rejects('auth selected controls cannot skip duplicate IDs', 'authOwner',
  'ids.insert(holder.0.id) && pointers.insert(Arc::as_ptr(&holder.0) as usize)',
  'pointers.insert(Arc::as_ptr(&holder.0) as usize)', /reject duplicate IDs and aliases/);
rejects('auth selected controls cannot skip duplicate holder addresses', 'authOwner',
  'ids.insert(holder.0.id) && pointers.insert(Arc::as_ptr(&holder.0) as usize)',
  'ids.insert(holder.0.id)', /reject duplicate IDs and aliases/);
rejects('auth selected take cannot remove a holder during validation', 'authOwner',
  'let pending = pending.pending.as_ref().ok_or_else(|| anyhow::anyhow!("auth holder was already consumed"))?;',
  'let pending = pending.pending.take().ok_or_else(|| anyhow::anyhow!("auth holder was already consumed"))?;', /entire set before FIFO consumption/);
rejects('auth selected lock set cannot cross an await', 'authOwner',
  'drop(guards);\n        drop(sorted);',
  'tokio::task::yield_now().await; drop(guards); drop(sorted);', /locks cannot cross an await/);
rejects('auth selection completion cannot ignore one selected owner', 'boshResponse',
  'observations.iter().all(|observation| observation.completed())',
  'observations.iter().any(|observation| observation.completed())', /BOSH publication gate/);
rejects('auth bound caps publication cannot use latest session intent', 'authOwner',
  'port.caps(effects.caps.take()).await;',
  'port.caps(None).await;', /captured route, caps and notifier ordering/);
rejects('auth caps adapter cannot replace the captured connection', 'authCaps',
  'self.commit_caps_observation_for(presence, full_jid, intent.connection, &intent.gate, &intent.generation);',
  'self.commit_caps_observation_for(presence, full_jid, self.connection_id, &intent.gate, &intent.generation);', /captured presence, gate, generation/);
rejects('auth route adapter cannot use latest connection for captured activation', 'protocol',
  '&route.key, route.connection, route.user, route.generation, &route.lifecycle, &route.disconnect',
  '&route.key, self.session.connection_id, route.user, route.generation, &route.lifecycle, &route.disconnect', /captured activation/);
rejects('auth forged terminal marker cannot mint completed ownership', 'authFacts',
  'Some(Terminal::Completed) => self.successful_completion(false),',
  'Some(Terminal::Completed) => true,', /captured effect results/);
rejects('auth completion cannot flatten missing caps result', 'authFacts',
  '|| !effects.caps_entered || !effects.caps_returned',
  '|| !effects.caps_entered', /captured effect results/);
rejects('auth publication ready child must be destroyed before retirement', 'authOwner',
  'drop(this.child.take());\n                this.retirement.polling = false;',
  'this.retirement.polling = false; drop(this.child.take());', /destroy its child/);
rejects('auth retirement field cannot precede its child', 'authOwner',
  'struct PublicationRunner<F> { child: Option<Pin<Box<F>>>, retirement: PublicationRetirement }',
  'struct PublicationRunner<F> { retirement: PublicationRetirement, child: Option<Pin<Box<F>>> }', /retirement field guard/);
rejects('auth retirement cannot forget a caught poll panic', 'authOwner',
  'if self.polling || std::thread::panicking() { Terminal::Panicked } else { Terminal::Cancelled }',
  'if std::thread::panicking() { Terminal::Panicked } else { Terminal::Cancelled }', /retirement field guard/);
rejects('auth actual TCP record cannot start before exact byte validation', 'transport',
  'holder.validate_control(&stanza)?;',
  '', /TCP adapter must validate/);
rejects('auth inline resume cannot seal before final activation', 'sasl2',
  'payload.activate_route = true;\n                    self.seal_resume_authentication(&mut payload)?;',
  'self.seal_resume_authentication(&mut payload)?; payload.activate_route = true;', /inline resume must seal/);
for (const [file, owner] of [['authService', 'CredentialCommitReceipt'], ['authOwner', 'KnownCredentialOwner'],
  ['authOwner', 'OwnedPublication'], ['authOwner', 'SelectedControls']]) {
  rejects(`auth ${owner} cannot derive Clone`, file,
    `pub(crate) struct ${owner}`, `#[derive(Clone)] pub(crate) struct ${owner}`, /cannot derive or implement Clone or Copy/);
}
rejects('auth owner cannot publish its mutable receipt field', 'authOwner',
  'struct PendingPublication {\n    receipt: CredentialCommitReceipt,',
  'struct PendingPublication {\n    pub(crate) receipt: CredentialCommitReceipt,', /receipt, origin and effects private/);
rejects('auth holder cannot add a factory that takes before write', 'authOwner',
  'impl AuthControlHolder {',
  'impl AuthControlHolder { pub(crate) fn take_without_write(self) -> OwnedPublication { let pending = self.0.pending.lock().unwrap().pending.take().unwrap(); OwnedPublication { pending, holder: self, managed: false } }',
  /closed inherent-method inventory/);

// Pre-receipt controls use the same exact-one token-span mutation helper.
rejects('credential prepared owner cannot become Clone', 'authFacts',
  'pub(crate) struct PreparedCredential', '#[derive(Clone)] pub(crate) struct PreparedCredential', /cannot derive or implement Clone or Copy/);
rejects('credential receipt handoff cannot acquire the latest frame', 'protocol',
  'let owner = attempt.into_owner(receipt)?;', 'let owner = latest_attempt().into_owner(receipt)?;', /exact captured attempt/);
rejects('credential observed mode cannot downgrade after a missing witness', 'authOwner',
  '(Some(origin), Some(prepared)) => { KnownCredentialOwner::from_observed(receipt, origin, self.connection, &prepared) }',
  '(Some(origin), Some(prepared)) => Ok(KnownCredentialOwner::from_returned(receipt, Some(origin), self.connection))', /cannot downgrade/);
rejects('credential checked owner cannot skip independent transfer validation', 'authOwner',
  'let credential = prepared.transfer(&receipt, origin.operation_id(), connection).map_err(|_| CredentialHandoffIntegrity)?;',
  'let credential = prepared.observation();', /validate before creating/);
rejects('credential handoff cannot accept an equal replacement receipt', 'authFacts',
  'state.constructed.as_ref() == Some(&actual) && state.returned.as_ref() == Some(&actual)',
  'state.constructed.is_some() && state.returned.is_some()', /exact constructed\/returned instance/);
rejects('credential raw success cannot replace its independent witness', 'authFacts',
  'state.snapshot.return_matches && state.integrity', 'state.snapshot.returned.is_some()', /same-attempt witness/);
rejects('credential COMMIT cannot freeze after polling the driver', 'authFacts',
  'state.snapshot.commit = CredentialCall::Entered;', 'state.snapshot.commit = CredentialCall::Ok;', /freeze preparation/);
rejects('credential COMMIT acknowledgement cannot be inferred from entry', 'authFacts',
  'state.snapshot.commit = if result.is_ok() { CredentialCall::Ok } else { CredentialCall::Err };',
  'state.snapshot.commit = CredentialCall::Ok;', /acknowledge only the actual result/);
rejects('credential COMMIT cannot replace the frozen projection after await', 'authFacts',
  'if result.is_ok() { state.witness = state.prospective.take(); }',
  'if result.is_ok() { state.witness = fresh_witness(); }', /freeze preparation/);
rejects('credential true eligibility cannot flatten SQL false or missing', 'authFacts',
  'snapshot.eligibility != Eligibility::Returned(Some(true))', 'false', /true eligibility/);
rejects('credential stage projection cannot substitute another SQL operation', 'authFacts',
  'Some(stage.operation_id) == snapshot.stage_id', 'true', /original SQL stage/);
rejects('credential rollback cannot ignore its actual refusal site', 'authFacts',
  '&& site.permitted(snapshot)', '', /exact rollback sites/);
rejects('credential duplicate construction cannot replace its original receipt', 'authFacts',
  'if state.constructed.is_some() { state.integrity = false; return; }', '', /preserve first facts/);
rejects('credential repository errors cannot lose the original downcast identity', 'authFacts',
  'CommitError::Repository(error) => error.into()', 'CommitError::Repository(error) => anyhow::anyhow!("wrapper")', /original repository error identity/);
rejects('credential hidden helper begin cannot bypass observation', 'authUsers',
  'CredentialInvocation::begin(observation, pool.begin()).await.map_err(credential_error)?',
  'pool.begin().await?', /real begin\/query\/refusal rollback/);
rejects('credential hidden helper cannot collapse false into missing', 'authUsers',
  'if eligible != Some(true) {', 'if eligible.is_none() {', /None and false/);
rejects('credential hidden helper rollback cannot be inferred from Drop', 'authUsers',
  'CredentialInvocation::rollback(observation, CredentialRollbackSite::GenerationRefused, tx.rollback()).await.map_err(credential_error)?;',
  'drop(tx);', /real begin\/query\/refusal rollback/);
rejects('credential helper compatibility must explicitly remain unobserved', 'authUsers',
  'lock_auth_generation_observed(pool, user_id, expected_generation, None).await',
  'lock_auth_generation_observed(pool, user_id, expected_generation, current_observation()).await', /compatibility must share/);
rejects('credential generated stage identity must be recorded before SQL', 'authDb',
  'if let Some(observation) = observation { observation.stage_id(operation_id); }',
  '', /original generated ID before the query/);
rejects('credential staged SQL cannot generate a replacement identity', 'authDb',
  'connection_id, operation_id, LOGIN_EPOCH_STAGE_TTL_SECONDS',
  'connection_id, Uuid::new_v4(), LOGIN_EPOCH_STAGE_TTL_SECONDS', /original generated ID before the query/);
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
  'self.sm_service.finalize_binding_observed(connection_id, user_id, expected_auth_generation, full_jid, self.config.capacity_session_lease_seconds, device_id, fast_plan, observation).await',
  'self.sm_service.finalize_binding_observed(connection_id, user_id, expected_auth_generation, full_jid, 99, device_id, fast_plan, observation).await', /actual lease and exact resume request/);
rejects('credential fixed history cannot replace an earlier attempt', 'frame',
  'attempts.slots[kind.index()].is_none()', 'true', /original fixed-kind attempts/);
rejects('credential registration cannot reopen after retirement snapshot', 'frame',
  'attempts.closed = true;', 'attempts.closed = false;', /close registration and copy handles atomically/);
rejects('credential frame history cannot retain only the latest attempt', 'frame',
  'attempts.slots.clone()', 'latest_credential_only()', /close registration and copy handles atomically/);
rejects('credential contradictory returned success cannot fall through as ordinary Unknown', 'sasl2',
  '|| crate::xmpp::auth_publication::credential_handoff_failed(&error)', '', /contradictory returned success must close/);
rejects('credential resume Unknown cannot prohibit the existing fallback', 'sasl2',
  'if bind_plan.is_none() && !unbound_state_committed {',
  'if bind_plan.is_none() && !unbound_state_committed && !resume_was_unknown {', /existing separate fallback attempt/);

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

function rejectsRoom(name, file, before, after, expected) {
  test(name, () => assert.throws(() => verifyRoomExecutionBoundaries(
    ['muc', 'mucFanout'].includes(file) ? changedMuc(file, before, after) : changed(file, before, after)
  ), expected));
}
test('current production room owners satisfy the gate', () => verifyRoomExecutionBoundaries(baseline));
rejectsRoom('MUC policy observation cannot be removed', 'muc',
  'self.enter_frame_stage(Stage::MucPolicy);', '', /MUC message policy/);
rejectsRoom('MUC wait stage cannot be supplied by a comment', 'muc',
  'self.enter_frame_stage(Stage::MucGateWait);',
  '/* self.enter_frame_stage(Stage::MucGateWait); */', /MUC standalone gate wait/);
rejectsRoom('MUC authority observation cannot be removed', 'muc',
  'self.enter_frame_stage(Stage::MucAuthority);', '', /MUC standalone gate wait/);
for (const call of [
  'match self\n                .state\n                .muc_service()\n                .execute_muc_retraction(',
  'match service\n                    .set_local_cluster_subject(',
  'match service\n                .execute_muc_subject(',
]) {
  const gap = call.includes('set_local_cluster_subject') ? '\n                ' : '\n            ';
  rejectsRoom(`MUC admission hook cannot disappear before ${call.split('.').at(-1)}`, 'muc',
    'self.enter_frame_stage(Stage::MucAdmission);' + gap + call, call, /MUC admission stage/);
}
rejectsRoom('observed MUC admission must retain its frame stage', 'muc',
  'self.enter_frame_stage(Stage::MucAdmission);\n                let completion = self',
  'let completion = self', /MUC admission stage/);
rejectsRoom('legacy MUC admission must retain its frame stage', 'muc',
  'self.enter_frame_stage(Stage::MucAdmission);\n                self.state\n                    .muc_service()\n                    .execute_muc_discussion(',
  'self.state\n                    .muc_service()\n                    .execute_muc_discussion(', /MUC admission stage/);
rejectsRoom('MUC replay cannot become fresh live fanout', 'muc',
  'fanout_disposition = MucFanoutDisposition::Replay;',
  'fanout_disposition = MucFanoutDisposition::Accepted;', /MUC replay and accepted fanout/);
rejectsRoom('MUC message cannot bypass reviewed fanout owner', 'muc',
  'accepted.fanout(self).await?', 'unreviewed_fanout(self).await?', /MUC replay and accepted fanout/);
rejectsRoom('MUC fanout stage adapter cannot swap local and cluster meaning', 'muc',
  'MucFanoutStage::Cluster => Stage::MucClusterFanout,',
  'MucFanoutStage::Cluster => Stage::MucLocalFanout,', /MUC fanout adapter/);
rejectsRoom('MUC fanout cannot report effects for replay', 'mucFanout',
  'if disposition == MucFanoutDisposition::Replay {\n        return false;\n    }',
  'if disposition == MucFanoutDisposition::Replay {\n        return true;\n    }', /MUC fanout must skip replay/);
rejectsRoom('MUC fanout cannot move local stage before cluster publication', 'mucFanout',
  'port.enter(MucFanoutStage::Cluster);\n    port.publish_cluster().await;',
  'port.enter(MucFanoutStage::Local);\n    port.publish_cluster().await;', /MUC effects must preserve/);
rejectsRoom('C2S MIX cannot discard originating frame observation', 'mix',
  'Some(&self.frame_executions),', 'None,', /C2S MIX must attribute/);
rejectsRoom('MIX shared message owner cannot lose policy observation', 'mix',
  'observation.enter(Stage::MixPolicy);', '', /MIX shared owner/);
for (const call of ['retract_mix_message']) {
  const indentation = call === 'retract_mix_message' ? '        ' : '    ';
  const before = `if let Some(observation) = observation {\n${indentation}    observation.enter(Stage::MixAdmission);\n${indentation}}\n${indentation}let admission = state\n${indentation}    .mix_service()\n${indentation}    .${call}(`;
  const after = `let admission = state\n${indentation}    .mix_service()\n${indentation}    .${call}(`;
  rejectsRoom(`MIX ${call} must retain its admission hook`, 'mix', before, after, /MIX admission stage/);
}
test('MIX foreground admission must retain its admission hook', () => {
  assert.throws(() => verifyRoomExecutionBoundaries(changedMuc('mix',
    'if let Some(observation) = observation { observation.enter(Stage::MixAdmission); } let admission = if let Some(owner) = &foreground {',
    'let admission = if let Some(owner) = &foreground {')), /MIX admission stage/);
});

function rejectsMixForeground(name, file, before, after, expected, matches = 1) {
  test(name, () => assert.throws(() => verifyMixForegroundBoundaries(
    changedMuc(file, before, after, matches)), expected));
}
test('current production MIX foreground satisfies its retained-owner gate', () => verifyMixForegroundBoundaries(baseline));
rejectsMixForeground('MIX configuration cannot be supplied by a caller claim', 'state',
  'config.domain.clone(), mix_message_content_identity,', 'claimed_domain(), mix_message_content_identity,', /actual runtime configuration/);
rejectsMixForeground('MIX receiving domain keeps the existing subdomain policy', 'mixService',
  '&format!("mix.{configured_domain}")', '&format!("other.{configured_domain}")', /canonical mix subdomain/);
rejectsMixForeground('MIX configured domain cannot be supplied by a comment', 'mixService',
  'let configured_mix_domain = northstar_xmpp_types::prepare_domainpart(&format!("mix.{configured_domain}"))?;',
  '/* let configured_mix_domain = northstar_xmpp_types::prepare_domainpart(&format!("mix.{configured_domain}"))?; */ let configured_mix_domain = claimed_domain();', /canonical mix subdomain/);
rejectsMixForeground('MIX preparation cannot accept a self-consistent foreign domain', 'mixService',
  'if !ingress.matches_receiving_domain(&self.configured_mix_domain)', 'if false', /own receiving authority/);
rejectsMixForeground('MIX observed service cannot substitute claimed domain', 'mixService',
  'request, &self.configured_mix_domain, self.repository.store_mix_message_observed(',
  'request, claimed_domain(), self.repository.store_mix_message_observed(', /receiving domain and bound repository/);
rejectsMixForeground('MIX observed service retains the fair pre-pool guard', 'mixService',
  'let _admission = self.delivery_admission_guard().await; let completion = northstar_room_application::mix::admit_observed(',
  'let completion = northstar_room_application::mix::admit_observed(', /fair admission/);
rejectsMixForeground('MIX compatibility service retains the fair pre-pool guard', 'mixService',
  'let _admission = self.delivery_admission_guard().await; let result = self.repository.store_mix_message(',
  'let result = self.repository.store_mix_message(', /compatibility service/);
rejectsMixForeground('MIX equal UUIDs cannot replace private invocation identity', 'mixCore',
  'fn same_invocation(&self, other: &Self) -> bool { Arc::ptr_eq(&self.0, &other.0) }',
  'fn same_invocation(&self, other: &Self) -> bool { true }', /private allocation identity/);
rejectsMixForeground('MIX store input pointer cannot be substituted', 'mixCore',
  'Arc::ptr_eq(command, &self.command)', 'true', /immutable invocation input/);
rejectsMixForeground('MIX COMMIT receipt cannot follow an unrelated await', 'mixCore',
  'commit.await.map_err(CommitError::Commit)?; request.received(prepared)',
  'commit.await.map_err(CommitError::Commit)?; unrelated().await; request.received(prepared)', /without an intervening await/);
rejectsMixForeground('MIX actual entered fact cannot be replaced by equal values', 'mixCore',
  'Arc::ptr_eq(fact, &prepared.fact)', 'true', /exact active invocation/);
rejectsMixForeground('MIX contradictory returns remain diagnosable', 'mixCore',
  'state.snapshot.returned = Some(Returned::Admission(admission.clone()));',
  'drop(admission.clone());', /contradictory returns/);
rejectsMixForeground('MIX accepted return retains one audience', 'mixCore',
  'state.snapshot.returned = Some(Returned::AcceptedStored(id));',
  'state.snapshot.returned = Some(Returned::Admission(admission.clone()));', /matched Stored retains one audience/);
rejectsMixForeground('MIX wake is consumed before invocation', 'mixCore',
  'state.snapshot.wake = Wake::Invoked; } publish();',
  'publish(); state.snapshot.wake = Wake::Invoked; }', /consume before synchronous invocation/);
rejectsMixForeground('MIX observed SQL actor is obtained from its request', 'mixDb',
  'pool, command.channel_id, &command.actor, &command.item_id.to_string(),',
  'pool, command.channel_id, &forged_actor(), &command.item_id.to_string(),', /only from the bound request/);
rejectsMixForeground('MIX raw Existing survives rollback suspension', 'mixDb',
  'request.observed_existing(foreground_existing(&existing))?; } transaction.rollback().await?;',
  '} transaction.rollback().await?;', /before both rollback awaits/, 2);
rejectsMixForeground('MIX admission wraps its actual COMMIT', 'mixDb',
  'transaction.commit(), request, northstar_room_core::mix::Stored {',
  'fabricated_commit(), request, northstar_room_core::mix::Stored {', /actual COMMIT order/);
rejectsMixForeground('MIX projection retains actual delivery IDs', 'mixDb',
  'delivery_id: delivery_ids[recipient.jid.as_str()]', 'delivery_id: event_id', /actual IDs\/sequences/);
rejectsMixForeground('MIX projection retains returned sequence values', 'mixDb',
  'sequence: sequences[&recipient.jid]', 'sequence: 1', /actual IDs\/sequences/);
rejectsMixForeground('MIX empty audience does not invent an event', 'mixDb',
  'if recipients.is_empty() { return Ok(None); }', 'if false { return Ok(None); }', /no empty durable event/);
rejectsMixForeground('MIX preflight replay needs repository authentication', 'mixRepository',
  'request.authenticated(&raw, result)?;', '/* request.authenticated(&raw, result)?; */', /authenticated repository evidence/);
rejectsMixForeground('MIX SQL Existing cannot skip classification', 'mixRepository',
  'request.authenticated(&raw, classified)?;', '', /classified by the repository/);
rejectsMixForeground('MIX store authentication true branch keeps original replay identity', 'mixRepository',
  'let classified = if exact { MixBusinessReplay::Replay(existing.authoritative_id) } else { MixBusinessReplay::Conflict };',
  'let classified = if exact { MixBusinessReplay::Conflict } else { MixBusinessReplay::Conflict };', /store authentication must map/);
rejectsMixForeground('MIX store authentication false branch remains conflict', 'mixRepository',
  'let classified = if exact { MixBusinessReplay::Replay(existing.authoritative_id) } else { MixBusinessReplay::Conflict };',
  'let classified = if exact { MixBusinessReplay::Replay(existing.authoritative_id) } else { MixBusinessReplay::Replay(existing.authoritative_id) };', /store authentication must map/);
rejectsMixForeground('MIX store returned branch cannot contradict authenticated classification', 'mixRepository',
  'request.authenticated(&raw, classified)?; if exact { StoreEventOutcome::Replay(existing.authoritative_id) } else { StoreEventOutcome::Conflict }',
  'request.authenticated(&raw, classified)?; if exact { StoreEventOutcome::Replay(existing.authoritative_id) } else { StoreEventOutcome::Replay(existing.authoritative_id) }', /store authentication must map/);
rejectsMixForeground('MIX read authentication true branch keeps original replay identity', 'mixRepository',
  'let result = if existing.target_id.is_none() && authenticators.verifies(&existing.semantic_key_id, &existing.semantic_mac) { MixBusinessReplay::Replay(existing.authoritative_id) } else { MixBusinessReplay::Conflict };',
  'let result = if existing.target_id.is_none() && authenticators.verifies(&existing.semantic_key_id, &existing.semantic_mac) { MixBusinessReplay::Replay(Uuid::nil()) } else { MixBusinessReplay::Conflict };', /read authentication must map/);
rejectsMixForeground('MIX read authentication false branch remains conflict', 'mixRepository',
  'let result = if existing.target_id.is_none() && authenticators.verifies(&existing.semantic_key_id, &existing.semantic_mac) { MixBusinessReplay::Replay(existing.authoritative_id) } else { MixBusinessReplay::Conflict };',
  'let result = if existing.target_id.is_none() && authenticators.verifies(&existing.semantic_key_id, &existing.semantic_mac) { MixBusinessReplay::Replay(existing.authoritative_id) } else { MixBusinessReplay::Replay(existing.authoritative_id) };', /read authentication must map/);
rejectsMixForeground('MIX absent frames skip observed preparation', 'frame',
  'let prepared = prepare()?; execution.0.mix_foreground.register(&prepared).map(Some)',
  'execution.0.mix_foreground.register(&untrusted_prepared()).map(Some)', /true absence must skip preparation/);
rejectsMixForeground('MIX conflicting registration cannot be downgraded', 'mixSlot',
  'if !observation.is_for(prepared) { return Err(Rejected::Input); }',
  'if !observation.is_for(prepared) { return Ok(observation.clone()); }', /retired\/conflicting owners/);
rejectsMixForeground('MIX observed ingress cannot fall back after registration failure', 'mix',
  'frames.mix_foreground(|| { state.mix_service().prepare_mix_foreground(',
  'legacy_or_failed_registration(|| { state.mix_service().prepare_mix_foreground(', /contiguous unfiltered registration/);
rejectsMixForeground('MIX active frame cannot be filtered into legacy compatibility', 'mix',
  'if let Some(frames) = observation {',
  'if let Some(frames) = observation.filter(|_| false) {', /contiguous unfiltered registration/);
rejectsMixForeground('MIX active foreground cannot be shadowed into compatibility', 'mix',
  'let foreground = if retraction_target.is_none() {',
  'let observation = observation.filter(|_| false); let foreground = if retraction_target.is_none() {', /contiguous unfiltered registration/);
rejectsMixForeground('MIX replay selection cannot filter an active owner', 'mix',
  'let replay = if let Some(owner) = &foreground {',
  'let replay = if let Some(owner) = foreground.as_ref().filter(|_| false) {', /contiguous unfiltered registration/);
rejectsMixForeground('MIX store selection cannot filter an active owner', 'mix',
  'let admission = if let Some(owner) = &foreground {',
  'let admission = if let Some(owner) = foreground.as_ref().filter(|_| false) {', /contiguous unfiltered registration/);
rejectsMixForeground('MIX mutable membership cannot move before replay', 'mix',
  'let foreground = if retraction_target.is_none()',
  'let early = state.mix_service().mix_participant(channel.id, actor_bare).await?; let foreground = if retraction_target.is_none()',
  /mutable membership must follow/);
rejectsRoom('federated MIX cannot invent a C2S observation', 'mix',
  'process_channel_message(&state, &actor_bare, &actor_full, &raw, None).await?',
  'process_channel_message(&state, &actor_bare, &actor_full, &raw, Some(&SessionExecutions::default())).await?',
  /federated MIX/);
rejectsRoom('transferred MIX owner cannot acknowledge through old worker token', 'mix',
  'ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport => Ok(true),',
  'ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport => acknowledge().await,', /MIX settlement/);
rejectsRoom('worker-owned MIX result cannot skip acknowledgement', 'mix',
  'ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker => acknowledge().await,',
  'ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker => Ok(true),', /MIX settlement/);
rejectsMixWorker('MIX claimed delivery cannot bypass lazy settlement owner', 'mix',
  'completion.settlement(command, closed)?', 'unreviewed_settlement(command, closed)?', /MIX claimed delivery/);
test('MUC room guard cannot be released before accepted fanout', () => {
  const start = baseline.muc.indexOf('        let attempted = if let Some(accepted) = discussion_fanout {');
  const release = '        drop(local_authority_guard);';
  const end = baseline.muc.indexOf(release, start);
  assert.ok(start >= 0 && end > start);
  const before = baseline.muc.slice(start, end + release.length);
  const after = release + '\n' + before.slice(0, -release.length);
  assert.throws(() => verifyRoomExecutionBoundaries(changed('muc', before, after)), /before releasing the room guard/);
});

function rejectsMucDiscussion(name, file, before, after, expected) {
  test(name, () => assert.throws(() => verifyMucDiscussionBoundaries(changedMuc(file, before, after)), expected));
}
test('current MUC discussion source bridges retain accepted knowledge', () => verifyMucDiscussionBoundaries(baseline));
rejectsMucDiscussion('MUC prepared domain must come from receiving configuration', 'mucApplication',
  'discussion::PreparedDiscussion::new(command, self.configured_domain.clone())',
  'discussion::PreparedDiscussion::new(command, caller_domain())', /receiving application configuration/);
rejectsMucDiscussion('MUC request cannot validate its own foreign domain', 'mucCore',
  'self.observation.0.prepared.0.configured_domain == configured_domain',
  'true', /cannot authorize its own configured domain/);
rejectsMucDiscussion('MUC observed repository cannot start before domain refusal', 'mucApplication',
  'request.start().map_err(AdmissionError::Observation)?;', '', /before repository start/);
rejectsMucDiscussion('MUC repository must project input from the bound request', 'mucDb',
  'super::room::discussion_to_db(request.command()),',
  'unrelated_command(),', /projected from its bound request/);
rejectsMucDiscussion('MUC actual COMMIT entry cannot disappear', 'mucCore',
  'let prepared = request.enter_commit(outcome).map_err(CommitError::Observation)?;',
  'let prepared = fabricated_commit();', /actual entry and successful receipt/);
rejectsMucDiscussion('MUC receipt must precede any post-COMMIT suspension', 'mucCore',
  'request.received(prepared).map_err(CommitError::Observation)',
  'unrelated().await; request.received(prepared).map_err(CommitError::Observation)', /actual entry and successful receipt/);
rejectsMucDiscussion('MUC receipt token cannot cross invocations', 'mucCore',
  'if !self.observation.same_invocation(&prepared.observation) {',
  'if false {', /exact active invocation/);
rejectsMucDiscussion('MUC stored result cannot substitute another fresh identity', 'mucCore',
  'MucDiscussionAdmission::Stored(id) if id == self.command().id => {',
  'MucDiscussionAdmission::Stored(id) if true => {', /Stored must match fresh identity/);
rejectsMucDiscussion('MUC replay cannot infer original archive presence from the new request', 'mucCore',
  'MucDiscussionAdmission::Replay(_) if self.command().origin_id.is_some() => None,',
  'MucDiscussionAdmission::Replay(_) if self.command().origin_id.is_some() => Some(self.observation.0.prepared.requested_class()),', /Replay must keep original identity/);
rejectsMucDiscussion('MUC volatile acceptance cannot gain identity recovery', 'mucCore',
  '(false, false) => Self::Volatile',
  '(false, false) => Self::IdentityOnly', /archive and identity independence/);
rejectsMucDiscussion('MUC returned-only success cannot mint an observed permit', 'mucCore',
  'return Err(Rejected::MissingReceipt);',
  '/* receipt was not observed */', /returned-only success/);
test('MUC first fresh SQL COMMIT exit cannot bypass observation', () => {
  const before = 'commit_muc_discussion(transaction, request, MucDiscussionAdmission::Stored(message.id)).await';
  const sources = changedMuc('mucDb', before, 'legacy_commit(transaction).await', 2);
  assert.throws(() => verifyMucDiscussionBoundaries(sources), /all three existing COMMIT exits/);
});
rejectsMucDiscussion('MUC replay SQL COMMIT must observe its original ID', 'mucDb',
  'commit_muc_discussion(transaction, request, MucDiscussionAdmission::Replay(existing_id)).await',
  'commit_muc_discussion(transaction, request, MucDiscussionAdmission::Replay(message.id)).await', /all three existing COMMIT exits/);
rejectsMucDiscussion('MUC PostgreSQL repository cannot select legacy returned-only admission', 'mucRepository',
  'db::admit_muc_discussion_observed(&self.pool, request).await?',
  'db::admit_muc_discussion(&self.pool, discussion_to_db(request.command())).await?', /observed SQL entry/);
rejectsMucDiscussion('MUC service cannot skip the request-bound application', 'mucService',
  '.admit_discussion_observed(request)', '.legacy_discussion(request)', /request-bound application/);
rejectsMucDiscussion('MUC service constructor cannot substitute a different configured domain', 'mucService',
  'discussion_application: RoomApplication::new(repository.clone(), configured_domain.to_string())',
  'discussion_application: RoomApplication::new(repository.clone(), "evil.test")', /actual receiving configuration/);
rejectsMucDiscussion('MUC service preparation cannot select another application', 'mucService',
  'self.discussion_application.prepare_discussion(command)',
  'self.other_application.prepare_discussion(command)', /configured discussion application/);
rejectsMucDiscussion('MUC retired lazy slot cannot register another invocation', 'mucSlot',
  'if slot.terminal.is_some() {', 'if false {', /retired\/conflicting rejection/);
rejectsMucDiscussion('MUC conflicting slot cannot masquerade as an existing matching input', 'mucSlot',
  'if !observation.is_for(prepared) {', 'if false {', /retired\/conflicting rejection/);
rejectsMucDiscussion('MUC retired current frame cannot fall back to legacy absence', 'frame',
  'return Err(discussion::Rejected::Retired);', 'return Ok(None);', /legacy absence must remain distinct/);
rejectsMucDiscussion('MUC protocol accessor cannot swallow registration errors', 'protocol',
  'self.frame_executions.muc_discussion(prepared)',
  'Ok(self.frame_executions.muc_discussion(prepared).ok().flatten())', /propagate registration errors/);
rejectsMucDiscussion('MUC frame completion must retire its discussion slot', 'frame',
  'progress.muc_discussion.retire(muc_reason)', 'None', /frame retirement/);
rejectsMucDiscussion('MUC envelope cannot skip archive/live pairing', 'muc',
  'anyhow::ensure!(command.stanza == archive,', 'anyhow::ensure!(true,', /bind exact archive projection/);
rejectsMucDiscussion('MUC bound envelope cannot consume another invocation result', 'muc',
  'completion.into_fanout(&self.observation)?', 'completion.into_fanout(&other)?', /consume matching completion/);
rejectsMucDiscussion('MUC accepted envelope cannot substitute fanout payload', 'muc',
  'stanza: &live.stanza', 'stanza: &replacement', /cannot substitute live payload/);
rejectsRoom('MUC discussion registration failure cannot select legacy fallback', 'muc',
  'self.muc_discussion_operation(&prepared.prepared)?',
  'self.muc_discussion_operation(&prepared.prepared).ok().flatten()', /MUC discussion dispatch/);
rejectsRoom('MUC active frame cannot be filtered into legacy admission', 'muc',
  'if let Some(operation) = operation {',
  'if let Some(operation) = operation.filter(|_| false) {', /MUC discussion dispatch/);
rejectsRoom('MUC observed fanout cannot borrow a reusable permit', 'mucFanout',
  'let progress = permit.start()?;', 'let progress = permit.borrow();', /consume its permit/);
rejectsRoom('MUC acquired recipient order cannot be silently sorted', 'mucFanout',
  'let recipients = port.recipients();', 'let mut recipients = port.recipients(); recipients.sort();', /MUC effects must preserve/);
rejectsRoom('MUC pending endpoint cannot advance before its actual return', 'mucFanout',
  'let accepted = port.deliver(&recipient).await;', 'let accepted = true;', /MUC effects must preserve/);
rejectsMixWorker('MIX acknowledgement cannot substitute a different exact fence', 'mixDb',
  'remove_mix_delivery_tx(&mut transaction, source.delivery_id, source.lease_token)',
  'remove_mix_delivery_tx(&mut transaction, source.delivery_id, source.delivery_id)', /ACK must observe/);

test('native and compatibility MIX ACK share the reviewed database owner', () => verifyNativeAckService(baseline.mixService));
function rejectsNativeAck(name, declaration, before, after, expected) {
  test(name, () => {
    assert.equal(baseline.mixService.split(declaration).length - 1, 1);
    const start = baseline.mixService.indexOf(declaration);
    const end = baseline.mixService.indexOf('\n    }', start);
    assert.ok(end > start, 'reviewed service method boundary must exist');
    const method = baseline.mixService.slice(start, end + 6);
    assert.equal(method.split(before).length - 1, 1, 'mutation must match once within its service method');
    const source = baseline.mixService.slice(0, start) + method.replace(before, after) + baseline.mixService.slice(end + 6);
    assert.notEqual(source, baseline.mixService, 'mutation must change source');
    assert.throws(() => verifyNativeAckService(source), expected);
  });
}
const legacyAck = 'pub(crate) async fn acknowledge_mix_delivery(';
const nativeAck = 'pub(crate) async fn acknowledge_mix_socket_write(';
const sharedAck = 'async fn acknowledge_mix_delivery_inner(';
rejectsNativeAck('legacy MIX ACK cannot replace the exact delivery', legacyAck, 'delivery_id,', 'other_delivery,', /legacy MIX acknowledgement/);
rejectsNativeAck('legacy MIX ACK cannot replace the exact token', legacyAck, 'lease_token,', 'other_token,', /legacy MIX acknowledgement/);
rejectsNativeAck('legacy MIX ACK cannot invent an observation', legacyAck, 'None', 'Some(request)', /legacy MIX acknowledgement/);
rejectsNativeAck('native MIX ACK cannot reinterpret a C2S source', nativeAck, 'TransportOwnershipSource::Mix(source)', 'TransportOwnershipSource::C2s(source)', /native MIX acknowledgement/);
rejectsNativeAck('native MIX ACK cannot extract a different request', nativeAck, 'request.source()', 'other_request.source()', /native MIX acknowledgement/);
rejectsNativeAck('native MIX ACK cannot replace the exact token', nativeAck, 'source.lease_token', 'source.delivery_id', /native MIX acknowledgement/);
rejectsNativeAck('native MIX ACK cannot discard its observation', nativeAck, 'Some(request)', 'None', /native MIX acknowledgement/);
rejectsNativeAck('native MIX ACK cannot replace its observation', nativeAck, 'Some(request)', 'Some(other_request)', /native MIX acknowledgement/);
rejectsNativeAck('shared MIX ACK cannot bypass database admission', sharedAck, 'self.outbox_db_admission_guard().await', 'unbounded_permit()', /shared MIX acknowledgement/);
rejectsNativeAck('shared MIX ACK cannot omit the repository observation', sharedAck, 'lease_token, observation', 'lease_token, None', /shared MIX acknowledgement/);
rejectsNativeAck('shared MIX ACK cannot erase the repository failure', sharedAck, '.await?', '.await.unwrap_or(true)', /shared MIX acknowledgement/);
rejectsNativeAck('shared MIX ACK cannot wake after no-match', sharedAck, 'if result', 'if true', /shared MIX acknowledgement/);
rejectsNativeAck('shared MIX ACK cannot invert the wake condition', sharedAck, 'if result', 'if !result', /shared MIX acknowledgement/);
rejectsNativeAck('shared MIX ACK cannot wake twice', sharedAck, 'self.publish_delivery_local_commit();', 'self.publish_delivery_local_commit(); self.publish_delivery_local_commit();', /shared MIX acknowledgement/);
rejectsNativeAck('shared MIX ACK cannot fabricate success', sharedAck, 'Ok(result)', 'Ok(true)', /shared MIX acknowledgement/);

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
function rejectsSm(name, file, method, pattern, replacement, expected) {
  test(name, () => {
    const testModule = baseline[file].search(/#\[cfg\(test\)\]\s*mod tests\b/);
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
    const testModule = baseline[file].search(/#\[cfg\(test\)\]\s*mod tests\b/);
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
rejectsBosh('BOSH repository cannot discard the closed request', 'mixRepository', /db::mix::transfer_mix_delivery_to_bosh\(&self\.pool,\s*request\)/g, 'db::mix::transfer_mix_delivery_to_bosh(&self.pool, other_request)', /same closed request/);
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
    const marker = /\n#\[cfg\(test\)\]\s*\nmod tests\b/.exec(source);
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
rejectsMixWorker('MIX claim cannot accept value-equal substituted row storage', 'mixWorkerCore',
  'ClaimKnowledge::StatementReceipt(receipt) => Arc::ptr_eq(receipt, &rows)',
  'ClaimKnowledge::StatementReceipt(receipt) => receipt == &rows', /exact returned storage/);
rejectsMixWorker('MIX claim cannot erase a rejected actual return', 'mixWorkerCore',
  'state.returned = Some(ClaimReturned::Rejected(rows.clone()));', 'state.returned = None;', /exact returned storage/);
rejectsMixWorker('MIX claim cannot mint attempts for duplicate delivery rows', 'mixWorkerCore',
  'if rows.iter().map(|row| row.source.delivery_id).collect::<std::collections::BTreeSet<_>>().len() != rows.len()',
  'if false', /unique rows/);
rejectsMixWorker('MIX attempt UUID equality cannot replace private invocation identity', 'mixWorkerCore',
  'fn same(&self, other: &Self) -> bool { Arc::ptr_eq(&self.0, &other.0) }',
  'fn same(&self, other: &Self) -> bool { self.row().source == other.row().source }', /private invocation identity/);
rejectsMixWorker('MIX archive mismatch cannot reopen retry permission', 'mixWorkerCore',
  'if state.snapshot.archive.knowledge != ArchiveKnowledge::ReceiptKnown(result) { state.snapshot.aborted = true; return Err(Rejected::MissingReceipt); }',
  'if state.snapshot.archive.knowledge != ArchiveKnowledge::ReceiptKnown(result) { return Err(Rejected::MissingReceipt); }', /archive mismatch/);
rejectsMixWorker('MIX archive receipt alone cannot authorize routing before exact return', 'mixWorkerCore',
  '(ArchiveKnowledge::ReceiptKnown(known), Some(ArchiveReturned::Outcome(returned))) if known == returned',
  '(ArchiveKnowledge::ReceiptKnown(known), Some(ArchiveReturned::Outcome(returned))) if true', /matching receipt and returned/);
rejectsMixWorker('MIX contradictory local return cannot authorize another resource', 'mixWorkerCore',
  'if enqueued != requires_enqueue { state.snapshot.aborted = true; return Err(Rejected::Result); }',
  'if enqueued != requires_enqueue { return Err(Rejected::Result); }', /contradictory local returns/);
rejectsMixWorker('MIX renewal backend failure cannot reset into another renewal', 'mixWorkerCore',
  'renewal.returned = Some(RenewalReturned::Error); renewal.pending = false; state.snapshot.aborted = true;',
  'renewal.returned = Some(RenewalReturned::Error); renewal.pending = false;', /renewal error/);
rejectsMixWorker('MIX renewal false must retain unavailable lease knowledge', 'mixWorkerCore',
  'renewal.last_receipt = Some((self.ordinal, result)); if !result { state.snapshot.lease_lost = true; }',
  'renewal.last_receipt = Some((self.ordinal, result));', /false lease knowledge/);
rejectsMixWorker('MIX closed renewal scope cannot invent completion of a pending child', 'mixWorkerCore',
  'state.snapshot.renewal_scope_closed = true; Ok(RenewalScopeClosed { observation: self.clone() })',
  'state.snapshot.renewal.pending = false; state.snapshot.renewal_scope_closed = true; Ok(RenewalScopeClosed { observation: self.clone() })', /pending invocation knowledge/);
rejectsMixWorker('MIX settlement cannot start before renewal children are destroyed', 'mixWorkerCore',
  'if !state.snapshot.renewal_scope_closed { return Err(Rejected::Renewal); }',
  'if false { return Err(Rejected::Renewal); }', /closed renewal scope/);
rejectsMixWorker('MIX pending route cannot select ACK settlement', 'mixWorkerCore',
  'RouteResult::Pending => SettlementKind::Defer,',
  'RouteResult::Pending => SettlementKind::Ack,', /exclusive outcome kind/);
rejectsMixWorker('MIX settlement cannot silently substitute its returned receipt', 'mixWorkerCore',
  'settlement.knowledge != SettlementKnowledge::ReceiptKnown(result)',
  'false', /actual receipt and command/);
for (const [name, receipt] of [['archive', 'prepared'], ['settlement', 'prepared, result']]) {
  rejectsMixWorker(`MIX ${name} COMMIT cannot erase an independently observed receipt`, 'mixWorkerCore',
    `request.received(${receipt}).map_err(CommitError::Observation)`, 'Ok(())', /COMMIT wrappers/);
}
for (const name of ['Claim', 'Attempt']) {
  rejectsMixWorker(`MIX ${name} holder cannot retire before child destruction`, 'mixWorkerOwner',
    `impl Drop for ${name}Run { fn drop(&mut self) { drop(self.child.take());`,
    `impl Drop for ${name}Run { fn drop(&mut self) { self.retirement.finish(core::TerminalReason::Cancelled); drop(self.child.take());`, /field guard/);
  rejectsMixWorker(`MIX ${name} retirement must preserve caught poll panic`, 'mixWorkerOwner',
    `impl Drop for ${name}Retirement { fn drop(&mut self) { if !self.retired { self.finish(if self.polling || std::thread::panicking()`,
    `impl Drop for ${name}Retirement { fn drop(&mut self) { if !self.retired { self.finish(if std::thread::panicking()`, /field guard/);
}
rejectsMixWorker('MIX observed claim cannot be replaced by a raw DTO compatibility claim', 'mixWorker',
  'context.service().claim_mix_deliveries_observed(&request)',
  'context.service().claim_mix_deliveries(claim_limit, 8 * 1024 * 1024)', /bounded observed claim/);
rejectsMixWorker('MIX work cannot bypass its owning attempt holder', 'mixWorker',
  'let run = delivery.run(move |attempt, handle| { process_claimed_mix_delivery(context, attempt, handle, cancel) });',
  'let run = process_claimed_mix_delivery(context, delivery, handle, cancel);', /attempt holder/);
for (const [name, repository] of [
  ['claim_mix_deliveries_observed', 'claim_mix_deliveries_observed'],
  ['outbox_archive_mix_message_once_observed', 'archive_mix_message_once_observed'],
  ['renew_mix_delivery_lease_observed', 'renew_mix_delivery_lease_observed'],
  ['settle_mix_delivery_observed', 'settle_mix_delivery_observed'],
]) {
  rejectsMixWorker(`MIX ${name} must forward its own closed request`, 'mixService',
    `self.repository.${repository}(request).await`,
    `self.repository.${repository}(other_request).await`, /fair admission and exact request/);
}
rejectsMixWorker('MIX settlement cannot wake on ACK false', 'mixService',
  'SettlementResult::Ack(true) | SettlementResult::DeadLetter(true)',
  'SettlementResult::Ack(false) | SettlementResult::DeadLetter(true)', /wake must follow/);
rejectsMixWorker('MIX authorized empty claim cannot manufacture a mutating statement receipt', 'mixDb',
  'request.read_empty()?;', 'request.enter_statement()?;', /authorized read-empty/);
rejectsMixWorker('MIX successful CTE claim cannot lose its independent row receipt', 'mixDb',
  'request.received(entered.expect("observed claim entered its mutating statement"), rows.clone())?;',
  'drop(entered);', /actual autocommit statement receipt/);
rejectsMixWorker('MIX worker ACK false cannot be converted to a true receipt', 'mixDb',
  'northstar_delivery_core::mix_outbox::SettlementResult::Ack(removed)',
  'northstar_delivery_core::mix_outbox::SettlementResult::Ack(true)', /ACK must observe/);
rejectsMixWorker('MIX shared settlement cannot bypass the actual COMMIT observer', 'mixDb',
  'northstar_delivery_core::mix_outbox::settlement_commit_observed(transaction.commit(), request, result)',
  'unobserved_commit(transaction.commit(), request, result)', /shared settlement helper/);
rejectsMixWorker('MIX dead-letter NotMoved cannot report a moved receipt', 'mixDb',
  'northstar_delivery_core::mix_outbox::SettlementResult::DeadLetter(moved)',
  'northstar_delivery_core::mix_outbox::SettlementResult::DeadLetter(true)', /Moved and NotMoved/);
rejectsMixWorker('MIX retry LeaseLost cannot skip its actual COMMIT', 'mixDb',
  'commit_mix_worker_settlement(transaction, observation, northstar_delivery_core::mix_outbox::SettlementResult::Retry(MixDeliveryRetryOutcome::LeaseLost)).await?;',
  'drop(transaction);', /actual COMMIT for LeaseLost/);
rejectsMixWorker('MIX retry cannot replace the locked-row outcome in its receipt', 'mixDb',
  'northstar_delivery_core::mix_outbox::SettlementResult::Retry(outcome)',
  'northstar_delivery_core::mix_outbox::SettlementResult::Retry(MixDeliveryRetryOutcome::Retried)', /locked-row decisions/);
rejectsMixWorker('MIX renewal false cannot be upgraded to a positive receipt', 'mixDb',
  'request.received(entered.expect("observed renewal entered its statement"), renewed)?;',
  'request.received(entered.expect("observed renewal entered its statement"), true)?;', /autocommit boolean receipt/);
rejectsMixWorker('MIX defer false cannot be upgraded to a positive receipt', 'mixDb',
  'northstar_delivery_core::mix_outbox::SettlementResult::Defer(updated)',
  'northstar_delivery_core::mix_outbox::SettlementResult::Defer(true)', /autocommit boolean receipt/);
rejectsMixWorker('MIX retry cannot borrow a different claimed wake generation', 'mixDb',
  'retry_mix_delivery_inner(pool, source.delivery_id, source.lease_token, request.route_wake_generation(), error, Some(request)).await',
  'retry_mix_delivery_inner(pool, source.delivery_id, source.lease_token, other_generation, error, Some(request)).await', /generation and command/);
rejectsMixWorker('MIX personal archive Stored cannot bypass the actual COMMIT', 'mixArchive',
  'commit_mix_archive(transaction, observation, SourceArchiveAdmission::Stored(personal_archive_id)).await?;',
  'drop(transaction);', /Stored and authenticated original-ID Replay/);
rejectsMixWorker('MIX personal archive replay receipt must keep the original row ID', 'mixArchive',
  'commit_mix_archive(transaction, observation, SourceArchiveAdmission::Replay(existing_id)).await?;',
  'commit_mix_archive(transaction, observation, SourceArchiveAdmission::Replay(personal_archive_id)).await?;', /original-ID Replay/);
rejectsMixWorker('MIX route cannot force optional producer rows into always-archived messages', 'mix',
  'authoritative_stanza_id: row.authoritative_stanza_id, archive: row.archive,',
  'authoritative_stanza_id: row.authoritative_stanza_id, archive: true,', /optional-ID and archive shape/);
for (const effect of ['archive', 'local', 'cluster']) {
  const before = effect === 'archive' ? 'let admission = if let Some(owner) = observation {' :
    `let result = if let Some(owner) = observation { let request = owner.${effect}_request(`;
  const after = before.replace('= observation {', '= observation.filter(|_| false) {');
  rejectsMixWorker(`MIX active worker cannot filter out its observed ${effect} branch`, 'mix', before, after, /unfiltered bound/);
}
rejectsMixWorker('MIX local handoff cannot discard its pending disconnect guard', 'mix',
  'let mut pending = PendingMixLocalHandoff::new(sender.clone(), disconnect.clone());',
  'let mut pending = UnobservedHandoff::new(sender.clone(), disconnect.clone());', /pending-disconnect guard/);
rejectsMixWorker('MIX local enqueue cannot be recorded as typed ownership transfer', 'mix',
  'request.enqueued().map_err(MixLocalTransportFailure::Observation)?;',
  'request.returned(mix_worker::LocalResult::Transferred(mix_worker::TransferBoundary::ClusterSocketFenced)).map_err(MixLocalTransportFailure::Observation)?;', /pending-disconnect guard/);
rejectsMixWorker('MIX typed local receipt cannot defer consumption across another await', 'mix',
  'pending.mark_completed(); if let Some(request) = observation {',
  'pending.mark_completed(); std::future::pending::<()>().await; if let Some(request) = observation {', /immediately before any later await/);
rejectsMixWorker('MIX cluster result cannot return before transfer consumption', 'mix',
  'record_claimed_cluster_result(request, &result)?; result',
  'return result; record_claimed_cluster_result(request, &result)?;', /typed result before returning/);
rejectsMixWorker('MIX delivered boolean cannot authorize cluster transfer', 'mix',
  'Ok(receipt) if receipt.acknowledged => receipt.mix_handoff.map',
  'Ok(receipt) if receipt.delivered => receipt.mix_handoff.map', /acknowledged typed handoff/);
rejectsMixWorker('MIX settlement cannot close renewal scope before child destruction', 'mix',
  'let closed = handle.observation.close_renewal_scope()?;',
  'let closed = premature_scope;', /close renewal scope/);
rejectsMixWorker('MIX transferred route cannot select worker ACK', 'mix',
  'request.returned(mix_worker::RouteResult::Transferred)?.transferred(closed)?; return Ok(());',
  'let settlement = request.returned(mix_worker::RouteResult::CompletedByWorker)?.settlement(mix_worker::SettlementCommand::Ack, closed)?; return Ok(());', /consume transfer or lazily/);
for (const [kind, database, other] of [['Ack', 'acknowledge', 'defer'], ['Defer', 'defer', 'acknowledge'], ['Retry', 'retry', 'dead_letter'], ['DeadLetter', 'dead_letter', 'retry']]) {
  rejectsMixWorker(`MIX ${kind} repository cannot select another settlement`, 'mixRepository',
    `db::${database}_mix_delivery_worker_observed(&self.pool, request).await?`,
    `db::${other}_mix_delivery_worker_observed(&self.pool, request).await?`, /typed command and exact request/);
}
rejectsMixWorker('MIX claim projection cannot replace its actual lease token', 'mixDb',
  'source: crate::outbound::MixDelivery { delivery_id: delivery.delivery_id, lease_token: delivery.lease_token, },',
  'source: crate::outbound::MixDelivery { delivery_id: delivery.delivery_id, lease_token: other_token, },', /claimed attempt projection/);
rejectsMixWorker('MIX archive adapter cannot retarget a personal projection', 'mixArchive',
  'pool, command.personal_archive_id, command.owner_id, &command.channel_jid,',
  'pool, command.personal_archive_id, other_owner, &command.channel_jid,', /bound command/);
rejectsMixWorker('MIX archive repository cannot turn Replay into Stored', 'mixRepository',
  'db::SourceArchiveAdmission::Replay(id) => outbox::core::ArchiveResult::Replay(id)',
  'db::SourceArchiveAdmission::Replay(id) => outbox::core::ArchiveResult::Stored(id)', /same request/);
rejectsMixWorker('MIX pending route cannot change the existing defer delay policy', 'mix',
  'mix_worker::SettlementCommand::Defer { delay_seconds: MIX_DELIVERY_ROUTE_RECOVERY_DELAY_SECS }',
  'mix_worker::SettlementCommand::Defer { delay_seconds: 1 }', /actual route result/);
for (const [name, request, result] of [
  ['claim_mix_deliveries_observed', 'ClaimRequest', 'Vec<outbox::OwnedAttempt>'],
  ['outbox_archive_mix_message_once_observed', 'ArchiveRequest', 'outbox::core::ArchiveResult'],
  ['renew_mix_delivery_lease_observed', 'RenewalRequest', 'bool'],
  ['settle_mix_delivery_observed', 'SettlementRequest', 'outbox::core::SettlementResult'],
]) {
  const declaration = `pub(crate) async fn ${name}(&self, request: &outbox::core::${request}) -> Result<${result}> {`;
  rejectsMixWorker(`MIX ${name} cannot skip the fair outbox gate`, 'mixService',
    `${declaration} let _admission = self.outbox_db_admission_guard().await;`, declaration,
    /fair admission and exact request/);
}
