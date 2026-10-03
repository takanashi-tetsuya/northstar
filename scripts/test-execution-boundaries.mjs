import assert from 'node:assert/strict';
import test from 'node:test';
import { readExecutionSources, verifyExecutionBoundaries, verifyRoomExecutionBoundaries } from './check-execution-boundaries.mjs';

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
  'match tokio::time::timeout(self.0.policy.budget, future).await {',
  'match tokio::time::timeout(INLINE_AUTH_BUDGET, future).await {', /transport-specific policy budget/);
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
