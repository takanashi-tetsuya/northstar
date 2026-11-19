import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readProductionModule } from './lib/source-module.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = { main: 'src/main.rs', workerComposition: 'src/node/workers.rs', subservers: 'src/runtime/subservers.rs', maintenanceOwnership: 'crates/contexts/operations/northstar-operations-postgres/src/maintenance_ownership.rs',
  maintenanceProcess: 'crates/contexts/operations/northstar-operations-application/src/maintenance_process.rs',
  maintenanceConfig: 'crates/platform/northstar-config/src/maintenance.rs',
  maintenanceHealth: 'crates/edges/northstar-http/src/maintenance_health.rs',
  subscriptionCleanup: 'crates/contexts/pubsub/northstar-pubsub-application/src/subscription_cleanup.rs',
  pubsubProtocol: 'crates/contexts/pubsub/northstar-pubsub-xmpp/src/protocol_session.rs', pubsubDelivery: 'crates/contexts/pubsub/northstar-pubsub-xmpp/src/delivery.rs',
  pubsubAdapter: 'crates/contexts/pubsub/northstar-pubsub-xmpp/src/pubsub.rs',
  pubsubService: 'crates/contexts/pubsub/northstar-pubsub-application/src/service.rs',
  runtimeControl: 'crates/contexts/operations/northstar-operations-application/src/runtime_control_coordinator.rs',
  cluster: 'scripts/cluster-wsl.sh', responsibility: 'docs/PROGRAM_RESPONSIBILITIES.md' };

function requireBoundary(condition, message) {
  if (!condition) throw new Error(`subserver boundary: ${message}`);
}

// Preserve token offsets while masking comments and normal string literals.
function codeOnly(source) {
  return source.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\/|"(?:\\.|[^"\\])*"/g,
    (text) => text.replace(/[^\n]/g, ' '));
}

function body(source, declaration) {
  const start = source.indexOf(declaration);
  requireBoundary(start >= 0, `missing ${declaration}`);
  const code = codeOnly(source);
  const open = code.indexOf('{', start + declaration.length);
  let depth = 0;
  for (let index = open; index < code.length; index++) {
    if (code[index] === '{') depth++;
    if (code[index] === '}' && --depth === 0) return source.slice(open + 1, index);
  }
  throw new Error(`subserver boundary: unterminated ${declaration}`);
}

export function readSubserverSources() {
  // Worker composition, private health and PubSub are read as whole production modules.
  return Object.fromEntries(Object.entries(files).map(([name, file]) => [name,
    ['workerComposition', 'maintenanceHealth', 'pubsubProtocol', 'pubsubDelivery', 'pubsubAdapter', 'pubsubService'].includes(name)
      ? readProductionModule(file, { root }) : fs.readFileSync(path.join(root, file), 'utf8')]));
}

export function verifySubserverBoundaries({ main, workerComposition, subservers, maintenanceProcess, maintenanceConfig, maintenanceHealth, maintenanceOwnership, subscriptionCleanup, pubsubProtocol, pubsubDelivery, pubsubAdapter, pubsubService, runtimeControl, cluster, responsibility }) {
  const coordinator = body(runtimeControl, 'pub async fn run(');
  requireBoundary(coordinator.includes('let mut observed_database = false;') &&
    coordinator.includes('report_runtime_control_health(&heartbeat, observed_database, first_error);') &&
    !/heartbeat\.(?:ok|error)\(/.test(coordinator) &&
    [...coordinator.matchAll(/observed_database = true;/g)].length === 2,
  'control coordinator must report exactly its two actual database-read paths through the reviewed health function');
  const subserverCode = codeOnly(subservers) + codeOnly(maintenanceProcess) + codeOnly(maintenanceConfig) + codeOnly(maintenanceHealth);
  requireBoundary(!/\b(?:ServerNode|AbuseGuard|FederationRouter|ReloadableTlsConfig|Keyring|KeyRing)\b/.test(subserverCode),
    'maintenance cannot construct or import core state, routing or key authorities');
  requireBoundary(!/\bConfig\s*::\s*from_env\b|crate\s*::\s*(?:auth|abuse|node|s2s|xmpp|tls|storage)\s*::/.test(subserverCode),
    'maintenance cannot load the general runtime config or core capability modules');
  // Mask only the known test module and retain later production items.
  const testStart = subscriptionCleanup.indexOf('#[cfg(test)]');
  requireBoundary(testStart >= 0 && /^#\[cfg\(test\)\]\s*mod tests\s*\{/.test(subscriptionCleanup.slice(testStart)),
    'subscription cleanup test module boundary changed');
  const testBody = body(subscriptionCleanup.slice(testStart), 'mod tests');
  const testEnd = subscriptionCleanup.indexOf(testBody, testStart) + testBody.length + 1;
  const subscriptionProduction = subscriptionCleanup.slice(0, testStart) + subscriptionCleanup.slice(testEnd);
  const subscriptionCode = codeOnly(subscriptionProduction);
  requireBoundary(!/\b(?:ServerNode|Config|Keyring|KeyRing|FederationRouter|PgPoolOptions|PgConnection)\b|crate\s*::\s*(?:node|s2s|xmpp|auth)\s*::/.test(subscriptionCode),
    'subscription cleanup must retain its narrow existing-pool authority');
  requireBoundary(!/\bcleanup_expired_subscriptions\s*\(/.test(codeOnly(pubsubProtocol) + codeOnly(pubsubDelivery) + codeOnly(pubsubAdapter)
    + codeOnly(pubsubService)),
    'physical subscription cleanup cannot reacquire delivery-worker or shared-outbox authority');
  const run = body(subservers, 'async fn run_maintenance(');
  const monitor = body(maintenanceProcess, 'async fn supervise_maintenance<');
  const closeOwnership = body(maintenanceOwnership, 'async fn close(');
  const fromEnv = body(maintenanceConfig, 'pub fn from_env(');
  for (const marker of ['config.validate()?', 'northstar_postgres::role_attestation::attest_runtime_role(&pool)',
    'northstar_postgres::role_attestation::attest_development_database_is_loopback(&pool)', 'northstar_postgres::schema::verify_schema(&pool',
    'claim_maintenance(&pool)', '.max_connections(MAINTENANCE_POOL_MAX_CONNECTIONS)',
    '.min_connections(0)', 'ownership.close().await', 'self.connection.close().await?', 'pool.close().await',
    'workers.shutdown_and_join(', 'cancel.cancel()']) {
    const source = marker === 'config.validate()?' ? fromEnv
      : ['self.connection.close().await?', 'pool.close().await'].includes(marker) ? closeOwnership
      : ['ownership.close().await', 'workers.shutdown_and_join(', 'cancel.cancel()'].includes(marker) ? monitor : run;
    requireBoundary(source.replace(/\s+/g, '').includes(marker.replace(/\s+/g, '')), `maintenance startup/shutdown lost ${marker}`);
  }
  const claim = body(subservers, 'async fn claim_maintenance_on_connection(');
  const claimExact = body(maintenanceOwnership, 'async fn claim_exact(');
  const probeExact = body(maintenanceOwnership, 'async fn probe_exact(');
  requireBoundary(claim.includes('maintenance_ownership::claim_exact(connection).await') &&
    claimExact.includes('connection.close_on_drop()') && claimExact.includes('pg_try_advisory_lock(') &&
    claimExact.includes('current_database()') && claimExact.includes('current_schema()') &&
    claimExact.includes('.fetch_one(&mut **connection)') && claimExact.includes('ensure!(') &&
    monitor.includes('ownership.probe()') &&
    body(maintenanceOwnership, 'async fn probe(').includes('probe_exact(&mut self.connection)') &&
    probeExact.includes('SELECT 1') && probeExact.includes('.execute(&mut **connection)'),
  'all retention modes must claim the same schema-scoped physical session and close it on drop');

  const dispatch = body(main, 'if process_role == runtime::subservers::ProcessRole::Maintenance');
  requireBoundary(dispatch.includes('return runtime::subservers::run_maintenance().await') &&
    main.indexOf('if process_role == runtime::subservers::ProcessRole::Maintenance') < main.indexOf('Config::from_env()?'),
  'maintenance must exit the composition path before general Config and ServerNode assembly');
  const dotenv = main.indexOf('config::load_dotenv()?;');
  requireBoundary(dotenv >= 0, 'dotenv loading errors must propagate before mode-specific configuration');
  const startup = body(main, 'async fn run()');
  const startupDotenv = startup.indexOf('config::load_dotenv()?;');
  requireBoundary(startupDotenv >= 0 && ['identity_audit::maybe_run(', 'run_migrations().await', 'Config::from_env()?']
    .every((consumer) => startup.indexOf(consumer) > startupDotenv),
  'dotenv loading must precede every mode-specific configuration consumer');
  const dotenvGuard = main.slice(main.lastIndexOf('if arguments', dotenv), dotenv);
  requireBoundary(/if arguments\s*!=\s*\[\s*"serve",\s*"maintenance"\s*\]/.test(dotenvGuard),
    'maintenance must never import a core .env file');
  requireBoundary(dotenvGuard.includes('std::env::var("NORTHSTAR_DISABLE_DOTENV").as_deref() != Ok("true")'),
    'explicit dotenv disable must prevent importing a developer .env file');
  const ownership = body(main, 'if process_role.embeds_retention()');
  requireBoundary(ownership.includes('claim_maintenance_on_connection(&mut runtime_control_connection)') &&
    main.indexOf('claim_maintenance_on_connection(') < main.indexOf('let state = ServerNode::new('),
  'standalone must claim retention before state/listener activation on its existing control connection');
  const guardedRegistrations = [...workerComposition.matchAll(/if process_role\.embeds_retention\(\)/g)]
    .map((match) => body(workerComposition.slice(match.index), 'if process_role.embeds_retention()'));
  requireBoundary(guardedRegistrations.filter((block) => block.includes('"archive-retention"') &&
    block.includes('retention_worker::serve_context(')).length === 1, 'standalone retention worker must have one explicit role guard');
  requireBoundary(guardedRegistrations.filter((block) => block.includes('"pubsub-subscription-cleanup"') &&
    block.includes('subscription_cleanup::serve_context(')).length === 1 &&
    [...workerComposition.matchAll(/\.supervise\(\s*"pubsub-subscription-cleanup"/g)].length === 1,
  'standalone subscription cleanup must have one explicit role guard');
  const workers = [...subservers.matchAll(/\.supervise(?:_draining)?\(\s*"([^"]+)"/g)].map((match) => match[1]);
  requireBoundary(JSON.stringify(workers) === JSON.stringify(['archive-retention', 'pubsub-subscription-cleanup']),
    'maintenance may supervise only its declared retention worker');
  requireBoundary(/"archive-retention",\s*WorkerCriticality::Restartable,\s*WorkerMode::Continuous,\s*Some\(silence\)/.test(run),
    'maintenance retention must retain its restart/readiness/watchdog contract');
  requireBoundary(/"pubsub-subscription-cleanup",\s*WorkerCriticality::Restartable,\s*WorkerMode::Continuous,\s*Some\(northstar_pubsub_application::subscription_cleanup::MAX_SILENCE\)/.test(run) &&
    run.includes('subscription_cleanup::serve_context('),
    'maintenance subscription cleanup must retain its independent restart/readiness/watchdog contract');
  const observers = [...subservers.matchAll(/\.register_observer\(\s*"([^"]+)"/g)].map((match) => match[1]);
  requireBoundary(JSON.stringify(observers) === JSON.stringify(['maintenance-ownership']),
    'maintenance ownership health must have one explicit observer');
  requireBoundary(/\.register_observer\("maintenance-ownership",\s*WorkerCriticality::Critical\)/.test(run),
    'maintenance ownership observer must remain critical');
  requireBoundary(cluster.includes('"$binary" serve standalone >"$redis_tmp/cluster-a.log"') &&
    cluster.includes('"$binary" serve core >"$redis_tmp/cluster-b.log"'),
  'experimental cluster startup/restart must retain one archive owner and a core-only peer');
  for (const marker of ['`serve maintenance`', '`maintenance/archive-retention`', '`maintenance/pubsub-subscription-cleanup`', '`maintenance-ownership`',
    'bounded overlap', 'shared PostgreSQL runtime role']) {
    requireBoundary(responsibility.includes(marker), `responsibility document lacks ${marker}`);
  }
  for (const [name, markers] of [
    ['maintenance/archive-retention', ['`serve maintenance`', 'restartable / continuous', '2 × retention interval + 60 s', '| immediate |']],
    ['maintenance/pubsub-subscription-cleanup', ['`serve maintenance`', 'restartable / continuous', '110 s', '40 s', '60 s', '| immediate |']],
    ['maintenance-ownership', ['`serve maintenance`', 'critical health observer', '**no task/factory**', '5 s', '3 s']],
  ]) {
    const row = responsibility.split(/\r?\n/).find((line) => line.includes(`| \`${name}\` |`));
    requireBoundary(row && markers.every((marker) => row.includes(marker)), `stale role-qualified worker semantics: ${name}`);
  }
  return { maintenanceWorkers: workers, maintenanceObservers: observers };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    verifySubserverBoundaries(readSubserverSources());
    console.log('Subserver boundary checks passed: minimal maintenance inputs, loopback health, explicit role ownership and shared-role budget');
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
