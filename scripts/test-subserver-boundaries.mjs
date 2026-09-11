import assert from 'node:assert/strict';
import test from 'node:test';
import { readSubserverSources, verifySubserverBoundaries } from './check-subserver-boundaries.mjs';

const baseline = readSubserverSources();

function rejectsMutation(name, file, before, after, expected) {
  test(name, () => {
    assert.ok(baseline[file].includes(before), `fixture mutation no longer matches: ${before}`);
    const changed = { ...baseline, [file]: baseline[file].replaceAll(before, after) };
    assert.throws(() => verifySubserverBoundaries(changed), expected);
  });
}

test('reviewed compositions have one role-qualified archive worker each', () => {
  assert.deepEqual(verifySubserverBoundaries(baseline), {
    maintenanceWorkers: ['archive-retention'], maintenanceObservers: ['maintenance-ownership'],
  });
});
test('comments and string descriptions do not grant core capabilities', () => {
  verifySubserverBoundaries({ ...baseline,
    subservers: `${baseline.subservers}\n// AppState and Keyring are forbidden\nconst DESCRIPTION: &str = "Config::from_env()";\n`,
  });
});

rejectsMutation('reject core state authority', 'subservers', 'use std::', 'use crate::state::AppState;\nuse std::', /core state/);
rejectsMutation('reject general configuration loading', 'subservers', 'config.validate()?;', 'Config::from_env()?;\nconfig.validate()?;', /general runtime config/);
rejectsMutation('reject expanding maintenance input secrets', 'subservers', 'struct MaintenanceConfig {', 'struct MaintenanceConfig {\n signing_key: String,', /capability inventory/);
rejectsMutation('reject expanding retention context authority', 'retention', 'struct RetentionContext {', 'struct RetentionContext {\n session_authority: usize,', /capability inventory/);
rejectsMutation('reject public maintenance bind', 'subservers', 'self.maintenance_bind.ip().is_loopback()', 'true', /reject public/);
rejectsMutation('reject kernel-selected production port', 'subservers', 'self.maintenance_bind.port() != 0', 'true', /reject public/);
rejectsMutation('recheck the actual health listener', 'subservers', 'listener.local_addr()?.ip().is_loopback()', 'true', /bounded local authority/);
rejectsMutation('reject unbounded health concurrency', 'subservers', 'Semaphore::new(16)', 'Semaphore::new(16000)', /bounded local authority/);
rejectsMutation('reject increased health header budget', 'subservers', '[0u8; 4096]', '[0u8; 65536]', /bounded local authority/);
rejectsMutation('reject increased request deadline', 'subservers', 'Duration::from_secs(2)', 'Duration::from_secs(200)', /bounded local authority/);
rejectsMutation('readiness requires a successful retention pass', 'subservers', 'retention_readiness.is_ready()', 'true', /bounded local authority/);
rejectsMutation('readiness also requires worker health', 'subservers', 'workers.readiness_error().is_none()', 'true', /bounded local authority/);
rejectsMutation('reap health connections on cancellation', 'subservers', 'connections.shutdown().await', 'drop(connections)', /bounded local authority/);
rejectsMutation('reject raw health error disclosure', 'subservers', 'let permits =', 'let detail = error.to_string();\nlet permits =', /failure details/);
rejectsMutation('keep runtime role attestation', 'subservers', 'db::attest_runtime_role(&pool)', 'skip_attestation(&pool)', /startup\/shutdown/);
rejectsMutation('close the exact advisory-lock session on early return', 'subservers', 'connection.close_on_drop()', 'connection.flush()', /physical session/);
rejectsMutation('probe the exact ownership connection', 'subservers', 'execute(&mut *ownership)', 'execute(&pool)', /exact-session loss detection/);
rejectsMutation('ownership observer stays critical', 'subservers', '.register_observer("maintenance-ownership", WorkerCriticality::Critical)', '.register_observer("maintenance-ownership", WorkerCriticality::Restartable)', /observer must remain critical/);
rejectsMutation('core cannot acquire embedded retention authority', 'subservers', 'self == Self::Standalone', 'self != Self::Maintenance', /only standalone/);
rejectsMutation('maintenance cannot load core dotenv', 'main', 'if arguments != ["serve", "maintenance"]', 'if true', /core .env/);
rejectsMutation('standalone claims ownership before state', 'main', 'claim_maintenance_on_connection(&mut runtime_control_connection)', 'skip_ownership(&mut runtime_control_connection)', /standalone must claim/);
rejectsMutation('maintenance worker inventory stays exact', 'subservers', '"archive-retention",', '"unreviewed-worker",', /declared retention worker/);
rejectsMutation('standalone peer restart keeps core-only role', 'cluster', '"$binary" serve core >"$redis_tmp/cluster-b.log"', '"$binary" serve standalone >"$redis_tmp/cluster-b.log"', /cluster startup\/restart/);
rejectsMutation('document residual authority and detection limit', 'responsibility', 'bounded overlap', 'exclusive fencing', /document lacks/);
rejectsMutation('document the actual maintenance watchdog', 'responsibility', '2 × retention interval + 60 s', 'none', /stale role-qualified worker semantics/);
rejectsMutation('idle control ticks cannot clear database errors', 'state', 'heartbeat.pulse();', 'heartbeat.ok();', /control health/);
rejectsMutation('control errors cannot be reported as healthy', 'state', 'heartbeat.error(error);', 'heartbeat.ok();', /control health/);
rejectsMutation('successful database reads are distinguished from idle ticks', 'state', 'else if observed_database {', 'else if true {', /control health/);
rejectsMutation('coordinator must use the reviewed error-preserving health report', 'state',
  'report_runtime_control_health(&heartbeat, observed_database, first_error);',
  'heartbeat.ok();', /control coordinator/);
rejectsMutation('instrumented settings reads still use the reserved connection', 'state',
  'db::runtime_control_snapshot(&mut connection, |phase| {',
  'db::runtime_control_snapshot(&state.pool, |phase| {', /exact reserved connection/);
rejectsMutation('control read instrumentation cannot silently drop its phase observation', 'state',
  'diagnostics.database_read(phase)',
  'drop(phase)', /exact reserved connection/);
rejectsMutation('control phase observation cannot report speculative success', 'state',
  'diagnostics.database_read(phase)',
  'heartbeat.ok(); diagnostics.database_read(phase)', /control coordinator/);
