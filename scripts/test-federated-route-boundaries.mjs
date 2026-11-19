import assert from 'node:assert/strict';
import test from 'node:test';
import { readFederatedRouteSources, verifyFederatedRouteBoundaries } from './check-federated-route-boundaries.mjs';

const baseline = readFederatedRouteSources();
const hostQueueTelemetry = `northstar_federation_application::telemetry::OnlineQueueAcceptanceTelemetry::new(
            &self.metrics.online_queue_durable_acceptances_total,
            &self.metrics.online_queue_volatile_acceptances_total,
        )
        .accepted(durable);`;
const hostPostAcceptTelemetry = `northstar_federation_application::telemetry::InboundDeliveryTelemetry::new(
            &self.metrics.post_accept_side_effect_failures_total,
            &self.metrics.messages_routed_total,
        )
        .post_accept_failed();`;
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
    caller: 'route_inbound_message', owner: 'route_federated', adapter: 'FederatedDirectRoute',
  });
});
test('comments, literals and unrelated functions do not spoof caller wiring', () => {
  const missing = baseline.inbound.replace('        history_committed,\n    )\n    .await?;', '        false,\n    )\n    .await?;');
  const decoys = '\n// DirectMessageRouter::route_federated(&FederatedDirectRoute(state), request, history_committed);\n'
    + '/* outer /* nested */ DirectMessageRouter::route_federated(&FederatedDirectRoute(state), request, history_committed); */\n'
    + 'const DECOY: &str = r##"DirectMessageRouter::route_federated(&FederatedDirectRoute(state), request, history_committed);"##;\n'
    + 'fn unrelated() { DirectMessageRouter::route_federated(&FederatedDirectRoute(state), request, history_committed); }';
  assert.throws(() => verifyFederatedRouteBoundaries({ ...baseline, inbound: missing + decoys }), /committed-history input/);
});
test('irrelevant strings, nested comments and character braces are masked', () => {
  verifyFederatedRouteBoundaries({ ...baseline,
    adapter: baseline.adapter.replace('fn record_local_accept(&self, durable: bool) {',
      'fn record_local_accept(&self, durable: bool) {\n/* one /* two */ } */ let brace = \'}\'; let text = "personal_message_telemetry() }"; let raw = r#" } "#;'),
  });
});

rejectsMutation('caller cannot drop committed history', 'inbound', '        history_committed,\n    )\n    .await?;', '        false,\n    )\n    .await?;', /committed-history input/);
rejectsMutation('caller cannot resume inline enqueue', 'inbound', 'let outcome = DirectMessageRouter::route_federated(', 'target.sender.try_send(annotated.clone());\n    let outcome = DirectMessageRouter::route_federated(', /regained inline/);
rejectsMutation('queue telemetry cannot switch to C2S', 'adapter', 'self.0.record_s2s_online_accept(durable);', 'self.0.personal_message_telemetry().online_queue_result(true, durable);', /must not record C2S/);
rejectsMutation('host queue telemetry cannot switch to C2S', 'host', hostQueueTelemetry, 'self.personal_message_telemetry().online_queue_result(true, durable);', /federation queue telemetry/);
rejectsMutation('host queue telemetry cannot lose durable classification', 'host', '.accepted(durable);', '.accepted(false);', /federation queue telemetry/);
rejectsMutation('postaccept telemetry cannot switch to C2S', 'adapter', 'self.0.record_s2s_post_accept_failure();', 'self.0.personal_message_telemetry().post_accept_failed();', /must not record C2S/);
rejectsMutation('additional C2S telemetry cannot be double counted', 'adapter', 'self.0.record_s2s_post_accept_failure();', 'self.0.record_s2s_post_accept_failure();\n self.0.personal_message_telemetry().post_accept_failed();', /must not record C2S/);
rejectsMutation('host postaccept telemetry cannot switch to C2S', 'host', hostPostAcceptTelemetry, 'self.personal_message_telemetry().post_accept_failed();', /federation telemetry/);
rejectsMutation('host postaccept telemetry cannot be double counted', 'host', hostPostAcceptTelemetry, `${hostPostAcceptTelemetry}\n self.personal_message_telemetry().post_accept_failed();`, /federation telemetry/);
rejectsMutation('remote receipt cannot discard Carbon exclusion', 'host', 'accepted_full_jid: routed.accepted_full_jid,', 'accepted_full_jid: None,', /receipt must preserve/);
rejectsMutation('remote receipt cannot invent acceptance', 'host', 'delivered: routed.delivered,', 'delivered: true,', /receipt must preserve/);
