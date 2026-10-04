import assert from 'node:assert/strict';
import test from 'node:test';
import { readExecutionSources, verifyExecutionBoundaries, verifyRoomExecutionBoundaries, verifyNativeAckService, verifyNativeWriteBoundaries, verifySmOwnershipBoundaries } from './check-execution-boundaries.mjs';

const baseline = readExecutionSources();
function changed(file, before, after) {
  assert.equal(baseline[file].split(before).length, 2, `mutation must match exactly once: ${before}`);
  return { ...baseline, [file]: baseline[file].replace(before, after) };
}
function rejects(name, file, before, after, expected) {
  test(name, () => assert.throws(() => verifyExecutionBoundaries(changed(file, before, after)), expected));
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
  'self.frame_executions.defer_publication(execution);', 'drop(execution);', /originating frame/);
rejects('comment cannot replace originating frame ownership', 'protocol',
  'self.frame_executions.defer_publication(execution);',
  '/* self.frame_executions.defer_publication(execution); */', /originating frame/);
rejects('raw string cannot replace originating frame ownership', 'protocol',
  'self.frame_executions.defer_publication(execution);',
  'let ignored = r###"self.frame_executions.defer_publication(execution);"###;', /originating frame/);
rejects('publication cannot bypass typed observation', 'protocol',
  '.observe_publication(self.publish_committed_authentication_and_route_inner())',
  '.run(self.publish_committed_authentication_and_route_inner())', /observed typed owner/);
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
rejects('backend failure cannot be flattened to credential rejection', 'protocol',
  'return PublicationResult::BackendFailure;', 'return PublicationResult::CredentialRejected;', /BackendFailure/);
rejects('integrity failure cannot be flattened to credential rejection', 'protocol',
  'return PublicationResult::IntegrityRejected;', 'return PublicationResult::CredentialRejected;', /IntegrityRejected/);
rejects('credential fence loss cannot continue transport', 'protocol',
  'return PublicationResult::CredentialRejected;', 'return PublicationResult::Completed;', /credential fence/);
rejects('missing principal cannot become successful publication', 'protocol',
  'let Some(user) = self.authenticated.clone() else {\n            return PublicationResult::RouteRejected;\n        };',
  'let Some(user) = self.authenticated.clone() else {\n            return PublicationResult::Completed;\n        };', /missing principal/);
rejects('deferred replacement notification must remain visible', 'protocol',
  'return PublicationResult::CompletedWithDeferredNotification;',
  'return PublicationResult::Completed;', /visibly deferred/);
rejects('deferred replacement notification cannot force a client retry', 'frame',
  'Self::Completed | Self::CompletedWithDeferredNotification',
  'Self::Completed', /only authoritative publication success/);
for (const file of ['tcp', 'websocket']) {
  rejects(`${file} first write must succeed before activation`, file,
    'if index == 0 && !session.publish_committed_authentication_and_route().await {',
    'if !session.publish_committed_authentication_and_route().await && index == 0 {', /successful first\/control write/);
  rejects(`${file} resumed control must succeed before activation`, file,
    'if activate_route && !session.publish_committed_authentication_and_route().await {',
    'if !session.publish_committed_authentication_and_route().await && activate_route {', /successful first\/control write/);
  rejects(`${file} publication guard cannot be supplied by a comment`, file,
    'if index == 0 && !session.publish_committed_authentication_and_route().await {',
    '/* if index == 0 && !session.publish_committed_authentication_and_route().await */ if false {', /two observed publication continuations/);
}

// Concrete independent-review escapes. Keep these on the production validator:
// runtime trace tests alone do not prevent a later adapter/owner bypass.
rejects('inner credential publication cannot acquire a new five-second deadline', 'protocol',
  'match self\n                .state\n                .authentication_service()\n                .publish_credential_commit(&receipt)\n                .await',
  'match tokio::time::timeout(\n                std::time::Duration::from_secs(5),\n                self.state.authentication_service().publish_credential_commit(&receipt)\n            ).await.unwrap_or(crate::services::authentication::AuthenticationResult::StaleGeneration)',
  /inner credential publication/);
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
rejects('deferral behind a dead condition is not originating ownership', 'protocol',
  'self.frame_executions.defer_publication(execution);',
  'if false { self.frame_executions.defer_publication(execution); }', /reviewed live condition/);
rejects('TCP rejected publication must close rather than continue', 'tcp',
  'if index == 0 && !session.publish_committed_authentication_and_route().await {\n                    return Ok(TcpActionDisposition::Close);\n                }',
  'if index == 0 && !session.publish_committed_authentication_and_route().await {\n                    continue;\n                }', /successful first\/control write/);
rejects('WebSocket rejected publication must close rather than continue', 'websocket',
  'if index == 0 && !session.publish_committed_authentication_and_route().await {\n                    return false;\n                }',
  'if index == 0 && !session.publish_committed_authentication_and_route().await {\n                    continue;\n                }', /successful first\/control write/);
rejects('inline classifier remains transport-specific', 'frame',
  'let inline = transport == ClientTransport::WebSocket && is_inline_auth(frame);',
  'let inline = is_inline_auth(frame);', /guarded WebSocket inline/);
rejects('BOSH ingress cannot bypass observed execution', 'bosh',
  'match self.protocol.process_frame(payload).await {',
  'match self.protocol.handle(payload).await {', /BOSH must enter/);
rejects('BOSH publication cannot bypass observed owner', 'bosh',
  '.publish_committed_authentication_and_route()\n                .await',
  '.publish_committed_authentication_and_route_inner()\n                .await', /BOSH must observe publication/);
rejects('BOSH unexposed response cannot publish authentication', 'bosh',
  'if !exposed_to_transport {\n                return false;\n            }',
  'if false {\n                return false;\n            }', /BOSH must observe publication/);
rejects('BOSH publication failure cannot succeed', 'bosh',
  '.publish_committed_authentication_and_route()\n                .await\n            {\n                return false;',
  '.publish_committed_authentication_and_route()\n                .await\n            {\n                return true;', /BOSH must observe publication/);
rejects('BOSH exposure must reflect actual responder acceptance', 'bosh',
  'exposed_to_transport |= responder.send(response.clone()).is_ok();',
  'exposed_to_transport = true; let _ = responder.send(response.clone());', /BOSH must observe publication/);
rejects('BOSH activation marker cannot be hidden behind a dead condition', 'boshAction',
  'if index == 0 {\n                        self.auth_publication_pending = true;\n                    }',
  'if false {\n                        self.auth_publication_pending = true;\n                    }', /BOSH activation/);
rejects('BOSH resume must honor the activation flag', 'boshAction',
  'if activate_route {\n                    self.auth_publication_pending = true;\n                }',
  'if false {\n                    self.auth_publication_pending = true;\n                }', /BOSH resume/);


function rejectsRoom(name, file, before, after, expected) {
  test(name, () => assert.throws(() => verifyRoomExecutionBoundaries(changed(file, before, after)), expected));
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
  'let admission = self\n                .state\n                .muc_service()\n                .execute_muc_discussion(',
]) {
  const gap = call.includes('set_local_cluster_subject') ? '\n                ' : '\n            ';
  rejectsRoom(`MUC admission hook cannot disappear before ${call.split('.').at(-1)}`, 'muc',
    'self.enter_frame_stage(Stage::MucAdmission);' + gap + call, call, /MUC admission stage/);
}
rejectsRoom('MUC replay cannot become fresh live fanout', 'muc',
  'fanout_disposition = MucFanoutDisposition::Replay;',
  'fanout_disposition = MucFanoutDisposition::Accepted;', /MUC replay and accepted fanout/);
rejectsRoom('MUC message cannot bypass reviewed fanout owner', 'muc',
  'if !run_muc_fanout(', 'if !unreviewed_fanout(', /MUC replay and accepted fanout/);
rejectsRoom('MUC fanout stage adapter cannot swap local and cluster meaning', 'muc',
  'MucFanoutStage::Cluster => Stage::MucClusterFanout,',
  'MucFanoutStage::Cluster => Stage::MucLocalFanout,', /MUC fanout adapter/);
rejectsRoom('MUC fanout cannot report effects for replay', 'mucFanout',
  'if disposition == MucFanoutDisposition::Replay {\n        return false;\n    }',
  'if disposition == MucFanoutDisposition::Replay {\n        return true;\n    }', /MUC fanout must skip replay/);
rejectsRoom('MUC fanout cannot move local stage before cluster publication', 'mucFanout',
  'port.publish_cluster().await;\n    port.enter(MucFanoutStage::Local);',
  'port.enter(MucFanoutStage::Local);\n    port.publish_cluster().await;', /MUC fanout must skip replay/);
rejectsRoom('C2S MIX cannot discard originating frame observation', 'mix',
  'Some(&self.frame_executions),', 'None,', /C2S MIX must attribute/);
rejectsRoom('MIX shared message owner cannot lose policy observation', 'mix',
  'observation.enter(Stage::MixPolicy);', '', /MIX shared owner/);
for (const call of ['retract_mix_message', 'store_mix_message']) {
  const indentation = call === 'retract_mix_message' ? '        ' : '    ';
  const before = `if let Some(observation) = observation {\n${indentation}    observation.enter(Stage::MixAdmission);\n${indentation}}\n${indentation}let admission = state\n${indentation}    .mix_service()\n${indentation}    .${call}(`;
  const after = `let admission = state\n${indentation}    .mix_service()\n${indentation}    .${call}(`;
  rejectsRoom(`MIX ${call} must retain its admission hook`, 'mix', before, after, /MIX admission stage/);
}
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
rejectsRoom('MIX claimed delivery cannot bypass lazy settlement owner', 'mix',
  'finish_mix_delivery_owner(outcome, || {', 'unreviewed_delivery_owner(outcome, || {', /MIX claimed delivery/);
test('MUC room guard cannot be released before accepted fanout', () => {
  const start = baseline.muc.indexOf('        if !run_muc_fanout(');
  const release = '        drop(local_authority_guard);';
  const end = baseline.muc.indexOf(release, start);
  assert.ok(start >= 0 && end > start);
  const before = baseline.muc.slice(start, end + release.length);
  const after = release + '\n' + before.slice(0, -release.length);
  assert.throws(() => verifyRoomExecutionBoundaries(changed('muc', before, after)), /before releasing the room guard/);
});
rejectsRoom('MIX acknowledgement cannot substitute a different exact fence', 'mix',
  '.acknowledge_mix_delivery(delivery.delivery_id, delivery.lease_token),',
  '.acknowledge_mix_delivery(delivery.delivery_id, delivery.delivery_id),', /MIX claimed delivery/);

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
rejectsNativeWrite('MIX transaction cannot bypass the observer', 'mixDb', /\bcommit_observed\(/g, 'unobserved_commit(', /actual MIX ACK transaction/);
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
