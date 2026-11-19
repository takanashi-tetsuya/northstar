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

test('reviewed compositions have exact role-qualified maintenance workers', () => {
  assert.deepEqual(verifySubserverBoundaries(baseline), {
    maintenanceWorkers: ['archive-retention', 'pubsub-subscription-cleanup'], maintenanceObservers: ['maintenance-ownership'],
  });
});
test('comments and string descriptions do not grant core capabilities', () => {
  verifySubserverBoundaries({ ...baseline,
    subservers: `${baseline.subservers}\n// ServerNode and Keyring are forbidden\nconst DESCRIPTION: &str = "Config::from_env()";\n`,
  });
});

test('subscription cleanup authority after tests stays checked', () => {
  assert.throws(() => verifySubserverBoundaries({ ...baseline,
    subscriptionCleanup: `${baseline.subscriptionCleanup}\nuse crate::node::ServerNode;\n`,
  }), /narrow existing-pool/);
});

rejectsMutation('reject core state authority', 'subservers', 'use std::', 'use crate::node::ServerNode;\nuse std::', /core state/);
rejectsMutation('reject general configuration loading', 'maintenanceConfig', 'config.validate()?;', 'Config::from_env()?;\nconfig.validate()?;', /general runtime config/);
rejectsMutation('subscription cleanup cannot allocate another pool', 'subscriptionCleanup', 'use std::', 'use sqlx::postgres::PgPoolOptions;\nuse std::', /narrow existing-pool/);
rejectsMutation('physical cleanup cannot return to digest delivery', 'pubsubDelivery', 'let mut interval = tokio::time::interval(Duration::from_secs(1));', 'cleanup_expired_subscriptions(&state.pool, 1000).await;\nlet mut interval = tokio::time::interval(Duration::from_secs(1));', /delivery-worker/);
rejectsMutation('maintenance cleanup watchdog keeps its own budget', 'subservers', 'Some(northstar_pubsub_application::subscription_cleanup::MAX_SILENCE)', 'Some(Duration::from_secs(5))', /independent restart/);
rejectsMutation('keep runtime role attestation', 'subservers', 'northstar_postgres::role_attestation::attest_runtime_role(&pool)', 'skip_attestation(&pool)', /startup\/shutdown/);
rejectsMutation('close the exact advisory-lock session on early return', 'maintenanceOwnership', 'connection.close_on_drop()', 'connection.flush()', /physical session/);
rejectsMutation('probe the exact ownership connection', 'maintenanceOwnership', 'execute(&mut **connection)', 'execute(&pool)', /physical session/);
rejectsMutation('maintenance probes its reserved connection', 'maintenanceProcess', 'ownership.probe()', 'pool.probe()', /physical session/);
rejectsMutation('ownership adapter probes its reserved connection', 'maintenanceOwnership', 'probe_exact(&mut self.connection)', 'probe_exact(&mut self.pool)', /physical session/);
rejectsMutation('ownership observer stays critical', 'subservers', '.register_observer("maintenance-ownership", WorkerCriticality::Critical)', '.register_observer("maintenance-ownership", WorkerCriticality::Restartable)', /observer must remain critical/);
rejectsMutation('maintenance cannot load core dotenv', 'main', 'if arguments != ["serve", "maintenance"]', 'if true', /core .env/);
rejectsMutation('dotenv failures cannot be silently ignored', 'main', 'config::load_dotenv()?;', 'config::load_dotenv().ok();', /dotenv loading errors/);
rejectsMutation('dotenv precedes migrator configuration', 'main', 'install_crypto_provider()?;', 'let _ = run_migrations().await;\ninstall_crypto_provider()?;', /dotenv loading must precede/);
rejectsMutation('explicit dotenv disable cannot be bypassed', 'main', 'std::env::var("NORTHSTAR_DISABLE_DOTENV").as_deref() != Ok("true")', 'true', /explicit dotenv disable/);
rejectsMutation('standalone claims ownership before state', 'main', 'claim_maintenance_on_connection(&mut runtime_control_connection)', 'skip_ownership(&mut runtime_control_connection)', /standalone must claim/);
rejectsMutation('maintenance worker inventory stays exact', 'subservers', '"archive-retention",', '"unreviewed-worker",', /declared retention worker/);
rejectsMutation('standalone peer restart keeps core-only role', 'cluster', '"$binary" serve core >"$redis_tmp/cluster-b.log"', '"$binary" serve standalone >"$redis_tmp/cluster-b.log"', /cluster startup\/restart/);
rejectsMutation('document residual authority and detection limit', 'responsibility', 'bounded overlap', 'exclusive fencing', /document lacks/);
rejectsMutation('document the actual maintenance watchdog', 'responsibility', '2 × retention interval + 60 s', 'none', /stale role-qualified worker semantics/);
rejectsMutation('coordinator must use the reviewed error-preserving health report', 'runtimeControl',
  'report_runtime_control_health(&heartbeat, observed_database, first_error);',
  'heartbeat.ok();', /control coordinator/);
rejectsMutation('control phase observation cannot report speculative success', 'runtimeControl',
  'diagnostics.database_read(phase)',
  'heartbeat.ok(); diagnostics.database_read(phase)', /control coordinator/);
