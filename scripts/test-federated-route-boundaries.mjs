import assert from 'node:assert/strict';
import test from 'node:test';
import { readFederatedRouteSources, verifyFederatedRouteBoundaries } from './check-federated-route-boundaries.mjs';

const baseline = readFederatedRouteSources();
function rejectsMutation(name, file, before, after, expected) {
  test(name, () => {
    assert.equal(baseline[file].split(before).length - 1, 1, `mutation fixture must match exactly once: ${before}`);
    const changed = { ...baseline, [file]: baseline[file].replace(before, after) };
    assert.notEqual(changed[file], baseline[file], 'mutation must change source');
    assert.throws(() => verifyFederatedRouteBoundaries(changed), expected);
  });
}

test('production federation caller and origin-specific adapter are wired', () => {
  assert.deepEqual(verifyFederatedRouteBoundaries(baseline), {
    caller: 'route_inbound_message', owner: 'route_federated', adapter: 'S2sDirectRoutePort',
  });
});
test('comments, literals and unrelated functions do not spoof caller wiring', () => {
  const missing = baseline.inbound.replace('DirectMessageRouter::route_federated(', 'DirectMessageRouter::route(');
  const decoys = '\n// DirectMessageRouter::route_federated(&S2sDirectRoutePort(state), request, history_committed);\n'
    + '/* outer /* nested */ DirectMessageRouter::route_federated(&S2sDirectRoutePort(state), request, history_committed); */\n'
    + 'const DECOY: &str = r##"DirectMessageRouter::route_federated(&S2sDirectRoutePort(state), request, history_committed);"##;\n'
    + 'fn unrelated() { DirectMessageRouter::route_federated(&S2sDirectRoutePort(state), request, history_committed); }';
  assert.throws(() => verifyFederatedRouteBoundaries({ ...baseline, inbound: missing + decoys }), /caller must invoke/);
});
test('irrelevant strings, nested comments and character braces are masked', () => {
  verifyFederatedRouteBoundaries({ ...baseline,
    adapter: baseline.adapter.replace('fn record_local_accept(&self, durable: bool) {',
      'fn record_local_accept(&self, durable: bool) {\n/* one /* two */ } */ let brace = \'}\'; let text = "personal_message_telemetry() }"; let raw = r#" } "#;'),
  });
});
test('an unrelated declaration cannot spoof the owned entry signature', () => {
  const before = ') -> Result<(), crate::outbound::RouteSendError> {';
  assert.equal(baseline.adapter.split(before).length - 1, 1);
  const changed = baseline.adapter.replace(before, ') -> Result<(), anyhow::Error> {')
    + '\nfn fake_fntry_local(&self, session: &Self::Session, enqueue: crate::outbound::RouteEnqueue,) -> Result<(), crate::outbound::RouteSendError> {}';
  assert.notEqual(changed, baseline.adapter);
  assert.throws(() => verifyFederatedRouteBoundaries({ ...baseline, adapter: changed }), /owned local enqueue and preserve its refusal type/);
});

rejectsMutation('adapter module cannot disappear', 'inbound', 'mod direct_route;', '// mod direct_route;', /module must stay registered/);
rejectsMutation('adapter import cannot disappear', 'inbound', 'use direct_route::S2sDirectRoutePort;', '// use direct_route::S2sDirectRoutePort;', /import its origin-specific adapter/);
rejectsMutation('caller cannot switch to C2S checkpoint policy', 'inbound', 'DirectMessageRouter::route_federated(', 'DirectMessageRouter::route(', /caller must invoke/);
rejectsMutation('caller cannot use unwrapped AppState', 'inbound', '&S2sDirectRoutePort(state)', '&state', /caller must invoke/);
rejectsMutation('caller cannot substitute a different state', 'inbound', '&S2sDirectRoutePort(state)', '&S2sDirectRoutePort(other_state)', /caller must invoke/);
rejectsMutation('caller cannot drop committed history', 'inbound', '        history_committed,\n    )\n    .await?;', '        false,\n    )\n    .await?;', /committed-history input/);
rejectsMutation('caller cannot disable direct health', 'inbound', 'enforce_direct_health: true,', 'enforce_direct_health: false,', /envelope, targets and health/);
rejectsMutation('caller must use approved targets', 'inbound', 'approved_targets: &targets,', 'approved_targets: &unfiltered_targets,', /envelope, targets and health/);
rejectsMutation('caller must use authoritative envelope', 'inbound', '            stanza: &annotated,\n            delivery,', '            stanza: raw,\n            delivery,', /envelope, targets and health/);
rejectsMutation('caller cannot resume inline enqueue', 'inbound', 'let outcome = DirectMessageRouter::route_federated(', 'target.sender.try_send(annotated.clone());\n    let outcome = DirectMessageRouter::route_federated(', /regained inline/);
rejectsMutation('caller cannot discard Carbon exclusion', 'inbound', 'DirectRouteOutcome::Routed { accepted_full_jid } => (true, accepted_full_jid)', 'DirectRouteOutcome::Routed { accepted_full_jid } => (true, None)', /retain the accepted resource/);
rejectsMutation('queue telemetry cannot switch to C2S', 'adapter', 'self.0.s2s_online_queue_telemetry().accepted(durable);', 'self.0.personal_message_telemetry().online_queue_result(true, durable);', /federation queue telemetry/);
rejectsMutation('queue telemetry cannot lose durable classification', 'adapter', '.accepted(durable);', '.accepted(false);', /federation queue telemetry/);
rejectsMutation('postaccept telemetry cannot switch to C2S', 'adapter', 'self.0.s2s_inbound_delivery_telemetry().post_accept_failed();', 'self.0.personal_message_telemetry().post_accept_failed();', /federation telemetry/);
rejectsMutation('comments cannot satisfy postaccept telemetry', 'adapter', 'self.0.s2s_inbound_delivery_telemetry().post_accept_failed();', '// self.0.s2s_inbound_delivery_telemetry().post_accept_failed();', /federation telemetry/);
rejectsMutation('additional C2S telemetry cannot be double counted', 'adapter', 'self.0.s2s_inbound_delivery_telemetry().post_accept_failed();', 'self.0.s2s_inbound_delivery_telemetry().post_accept_failed();\n self.0.personal_message_telemetry().post_accept_failed();', /must not record C2S/);
rejectsMutation('local adapter cannot substitute the owned item', 'adapter', 'OnlineRoutePort::try_local(self.0, session, enqueue)', 'OnlineRoutePort::try_local(self.0, session, other_enqueue)', /exact owned local enqueue/);
rejectsMutation('local adapter cannot clone the owned item', 'adapter', 'OnlineRoutePort::try_local(self.0, session, enqueue)', 'OnlineRoutePort::try_local(self.0, session, enqueue.clone())', /exact owned local enqueue/);
rejectsMutation('local adapter cannot substitute the session', 'adapter', 'OnlineRoutePort::try_local(self.0, session, enqueue)', 'OnlineRoutePort::try_local(self.0, other_session, enqueue)', /exact owned local enqueue/);
rejectsMutation('local adapter cannot erase the refused item', 'adapter', 'OnlineRoutePort::try_local(self.0, session, enqueue)', 'OnlineRoutePort::try_local(self.0, session, enqueue).map_err(|_| anyhow::anyhow!("refused"))', /exact owned local enqueue/);
rejectsMutation('local adapter cannot discard the refusal result', 'adapter', 'OnlineRoutePort::try_local(self.0, session, enqueue)', 'let _ = OnlineRoutePort::try_local(self.0, session, enqueue); Ok(())', /exact owned local enqueue/);
rejectsMutation('local adapter cannot drop before forwarding', 'adapter', 'OnlineRoutePort::try_local(self.0, session, enqueue)', 'drop(enqueue); OnlineRoutePort::try_local(self.0, session, replacement)', /exact owned local enqueue/);
rejectsMutation('local adapter cannot forward twice', 'adapter', 'OnlineRoutePort::try_local(self.0, session, enqueue)', 'OnlineRoutePort::try_local(self.0, session, enqueue); OnlineRoutePort::try_local(self.0, session, enqueue)', /exact owned local enqueue/);
rejectsMutation('local adapter must take ownership', 'adapter', 'enqueue: crate::outbound::RouteEnqueue,', 'enqueue: &crate::outbound::RouteEnqueue,', /owned local enqueue and preserve its refusal type/);
rejectsMutation('local adapter must retain the typed refusal', 'adapter', ') -> Result<(), crate::outbound::RouteSendError> {', ') -> Result<(), anyhow::Error> {', /owned local enqueue and preserve its refusal type/);
rejectsMutation('local adapter cannot add a second entry', 'adapter', '    fn try_local(', '    fn try_local(&self) {}\n    fn try_local(', /one owned local enqueue entry/);
rejectsMutation('fanout adapter cannot switch routing origins', 'adapter', '.route_s2s_message_to_available_remote_resources(jid, stanza, delivery)', '.route_personal_message_to_available_remote_resources(jid, stanza, delivery)', /federation remote adapter/);
rejectsMutation('primary adapter cannot switch routing origins', 'adapter', '.route_s2s_message_to_remote_primary(jid, stanza, delivery)', '.route_personal_message_to_remote_primary(jid, stanza, delivery)', /federation remote adapter/);
rejectsMutation('remote receipt cannot discard Carbon exclusion', 'adapter', 'accepted_full_jid: routed.accepted_full_jid,', 'accepted_full_jid: None,', /receipt must preserve/);
rejectsMutation('remote receipt cannot invent acceptance', 'adapter', 'delivered: routed.delivered,', 'delivered: true,', /receipt must preserve/);
rejectsMutation('rearm must preserve exact claim', 'adapter', 'DirectMessageRoutePort::rearm_direct_route(self.0, delivery).await;', 'DirectMessageRoutePort::rearm_direct_route(self.0, other_delivery).await;', /exact delivery claim/);

rejectsMutation('caller cannot discard committed delivery', 'inbound', '            delivery,\n            approved_targets:', '            delivery: DirectRouteDelivery::Volatile,\n            approved_targets:', /envelope, targets and health/);
rejectsMutation('caller cannot substitute another sender', 'inbound', '            sender: from,\n            recipient_id: recipient.id,', '            sender: other_sender,\n            recipient_id: recipient.id,', /envelope, targets and health/);
rejectsMutation('caller cannot substitute another recipient', 'inbound', '            recipient_id: recipient.id,\n            stanza: &annotated,', '            recipient_id: other_recipient.id,\n            stanza: &annotated,', /envelope, targets and health/);
