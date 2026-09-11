import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = { main: 'src/main.rs', subservers: 'src/subservers.rs', retention: 'src/retention.rs',
  subscriptionCleanup: 'src/subscription_cleanup.rs',
  pubsubProtocol: 'src/xmpp/protocol/pubsub.rs', pubsubService: 'src/services/pubsub.rs',
  state: 'src/state.rs',
  cluster: 'scripts/cluster-wsl.sh', responsibility: 'docs/PROGRAM_RESPONSIBILITIES.md' };

function requireBoundary(condition, message) {
  if (!condition) throw new Error(`subserver boundary: ${message}`);
}

// Source-shape regression gate, not a proof of Rust semantics. Preserve offsets
// while masking comments and normal string literals for brace/token inspection.
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

function exactFields(source, declaration, expected) {
  const fields = [...codeOnly(body(source, declaration)).matchAll(/^\s*(?:pub(?:\(crate\))?\s+)?([a-z_]+)\s*:/gm)]
    .map((match) => match[1]).sort();
  requireBoundary(JSON.stringify(fields) === JSON.stringify([...expected].sort()), `${declaration} capability inventory changed`);
}

export function readSubserverSources() {
  return Object.fromEntries(Object.entries(files).map(([name, file]) => [name, fs.readFileSync(path.join(root, file), 'utf8')]));
}

export function verifySubserverBoundaries({ main, subservers, retention, subscriptionCleanup, pubsubProtocol, pubsubService, state, cluster, responsibility }) {
  // Alternate control ticks can legitimately perform no SQL. They must not
  // reset a lost advisory-lock session's consecutive database error count.
  const report = codeOnly(body(state, 'fn report_runtime_control_health(')).replace(/\s+/g, '');
  requireBoundary(report === 'ifletSome(error)=error{heartbeat.error(error);}elseifobserved_database{heartbeat.ok();}else{heartbeat.pulse();}',
    'control health must preserve errors on idle ticks and clear them only after successful database observation');
  const coordinator = body(state, 'fn start_runtime_control_refresh(');
  requireBoundary(coordinator.includes('let mut observed_database = false;') &&
    coordinator.includes('report_runtime_control_health(&heartbeat, observed_database, first_error);') &&
    !/heartbeat\.(?:ok|error)\(/.test(coordinator) &&
    [...coordinator.matchAll(/observed_database = true;/g)].length === 2,
  'control coordinator must report exactly its two actual database-read paths through the reviewed health function');
  for (const [declaration, query] of [
    ['if refresh_policy', /db::runtime_control_snapshot\(\s*&mut connection,\s*\|phase\|\s*\{\s*diagnostics\.database_read\(phase\)\s*\}\s*,?\)/],
    ['if state.config.enable_xmpp_service_control', /db::poll_admin_service_control\(\s*&mut connection\s*\)/],
  ]) {
    const read = body(coordinator, declaration);
    requireBoundary(read.includes('observed_database = true;') && query.test(codeOnly(read)),
      'control coordinator must tie health observation to a read of its exact reserved connection');
  }
  const subserverCode = codeOnly(subservers);
  requireBoundary(!/\b(?:AppState|AbuseGuard|FederationRouter|ReloadableTlsConfig|Keyring|KeyRing)\b/.test(subserverCode),
    'maintenance cannot construct or import core state, routing or key authorities');
  requireBoundary(!/\bConfig\s*::\s*from_env\b|crate\s*::\s*(?:auth|abuse|state|s2s|xmpp|tls|storage)\s*::/.test(subserverCode),
    'maintenance cannot load the general runtime config or core capability modules');
  exactFields(subservers, 'struct MaintenanceConfig', [
    'xmpp_domain', 'database_url', 'database_url_file', 'database_allow_unsafe_role_for_development',
    'maintenance_bind', 'mam_retention_days', 'muc_mam_retention_days', 'offline_message_ttl_days',
    'audit_log_retention_days', 'retention_cleanup_batch_size', 'retention_cleanup_interval_seconds',
  ]);
  exactFields(retention, 'struct RetentionContext', ['pool', 'policy', 'metrics', 'readiness']);
  exactFields(subscriptionCleanup, 'struct SubscriptionCleanupContext', ['pool', 'metrics', 'readiness']);
  // Mask only the known test module and retain later production items.
  const testStart = subscriptionCleanup.indexOf('#[cfg(test)]');
  requireBoundary(testStart >= 0 && /^#\[cfg\(test\)\]\s*mod tests\s*\{/.test(subscriptionCleanup.slice(testStart)),
    'subscription cleanup test module boundary changed');
  const testBody = body(subscriptionCleanup.slice(testStart), 'mod tests');
  const testEnd = subscriptionCleanup.indexOf(testBody, testStart) + testBody.length + 1;
  const subscriptionProduction = subscriptionCleanup.slice(0, testStart) + subscriptionCleanup.slice(testEnd);
  const subscriptionCode = codeOnly(subscriptionProduction);
  requireBoundary(!/\b(?:AppState|Config|Keyring|KeyRing|FederationRouter|PgPoolOptions|PgConnection)\b|crate\s*::\s*(?:state|s2s|xmpp|auth)\s*::/.test(subscriptionCode),
    'subscription cleanup must retain its narrow existing-pool authority');
  for (const [name, seconds] of [['CLEANUP_INTERVAL', 60], ['CLEANUP_BUDGET', 40], ['MAX_SILENCE', 110]]) {
    requireBoundary(new RegExp(`const ${name}: Duration = Duration::from_secs\\(${seconds}\\)`).test(subscriptionCode),
      `subscription cleanup lost its independent ${name} budget`);
  }
  requireBoundary(/const CLEANUP_BATCH_SIZE: i64 = 1_?000/.test(subscriptionCode),
    'subscription cleanup must retain its bounded batch size');
  requireBoundary(!/\bcleanup_expired_subscriptions\s*\(/.test(codeOnly(pubsubProtocol) + codeOnly(pubsubService)),
    'physical subscription cleanup cannot reacquire delivery-worker or shared-outbox authority');
  const cleanupPass = codeOnly(body(subscriptionProduction, 'async fn run_once_with'));
  requireBoundary(cleanupPass.includes('tokio::time::timeout_at(deadline, async { cleanup().await })') &&
    cleanupPass.includes('readiness.begin_pass()') && cleanupPass.includes('cancel.cancelled()'),
    'subscription cleanup must enforce a cancellation-aware total pass deadline before publishing health');
  requireBoundary(codeOnly(body(subscriptionProduction, 'async fn serve_with')).includes('Instant::now() + CLEANUP_BUDGET'),
    'subscription cleanup must apply its reviewed budget to each pass');
  exactFields(retention, 'struct RetentionPolicy', ['mam_retention_days', 'muc_mam_retention_days',
    'offline_message_ttl_days', 'audit_log_retention_days', 'retention_cleanup_batch_size', 'retention_cleanup_interval_seconds']);
  requireBoundary(/self\.maintenance_bind\.ip\(\)\.is_loopback\(\)/.test(subservers) &&
    /self\.maintenance_bind\.port\(\)\s*!=\s*0/.test(subservers), 'maintenance config must reject public or unowned binds');
  const health = body(subservers, 'async fn private_health(');
  for (const marker of ['listener.local_addr()?.ip().is_loopback()', 'Semaphore::new(16)',
    '[0u8; 4096]', 'Duration::from_secs(2)', 'connections.shutdown().await', 'workers.readiness_error().is_none()', 'retention_readiness.is_ready()', 'subscription_readiness.is_ready()']) {
    requireBoundary(health.replace(/\s+/g, '').includes(marker.replace(/\s+/g, '')), `private health lost bounded local authority: ${marker}`);
  }
  requireBoundary(!health.includes('error.to_string()'), 'private health cannot return internal failure details');
  const run = body(subservers, 'async fn run_maintenance(');
  for (const marker of ['config.validate()?', 'db::attest_runtime_role(&pool)',
    'db::attest_development_database_is_loopback(&pool)', 'db::verify_schema(&pool',
    'claim_maintenance(&pool)', '.max_connections(MAINTENANCE_POOL_MAX_CONNECTIONS)',
    '.min_connections(0)', 'ownership.close().await', 'pool.close().await',
    'workers.shutdown_and_join(', 'cancel.cancel()']) {
    requireBoundary(run.replace(/\s+/g, '').includes(marker.replace(/\s+/g, '')), `maintenance startup/shutdown lost ${marker}`);
  }
  requireBoundary(subservers.includes('DATABASE_MAX_CONNECTIONS_LIMIT - MAINTENANCE_POOL_MAX_CONNECTIONS'),
    'core capacity must derive from the shared runtime-role budget');
  const claim = body(subservers, 'async fn claim_maintenance_on_connection(');
  requireBoundary(claim.includes('connection.close_on_drop()') && claim.includes('pg_try_advisory_lock(') &&
    claim.includes('current_database()') && claim.includes('current_schema()') &&
    claim.includes('.fetch_one(&mut **connection)') && claim.includes('anyhow::ensure!('),
  'all retention modes must claim the same schema-scoped physical session and close it on drop');

  const dispatch = body(main, 'if process_role == subservers::ProcessRole::Maintenance');
  requireBoundary(dispatch.includes('return subservers::run_maintenance().await') &&
    main.indexOf('if process_role == subservers::ProcessRole::Maintenance') < main.indexOf('Config::from_env()?'),
  'maintenance must exit the composition path before general Config and AppState assembly');
  const dotenv = main.indexOf('dotenvy::dotenv()');
  const dotenvGuard = main.slice(main.lastIndexOf('if arguments', dotenv), dotenv);
  requireBoundary(/if arguments\s*!=\s*\[\s*"serve",\s*"maintenance"\s*\]/.test(dotenvGuard),
    'maintenance must never import a core .env file');
  requireBoundary(body(subservers, 'fn embeds_retention(').trim() === 'self == Self::Standalone',
    'only standalone may embed retention in the core composition');
  const ownership = body(main, 'if process_role.embeds_retention()');
  requireBoundary(ownership.includes('claim_maintenance_on_connection(&mut runtime_control_connection)') &&
    main.indexOf('claim_maintenance_on_connection(') < main.indexOf('let state = AppState::new('),
  'standalone must claim retention before state/listener activation on its existing control connection');
  const guardedRegistrations = [...main.matchAll(/if process_role\.embeds_retention\(\)/g)]
    .map((match) => body(main.slice(match.index), 'if process_role.embeds_retention()'));
  requireBoundary(guardedRegistrations.filter((block) => block.includes('"archive-retention"') &&
    block.includes('retention::serve(')).length === 1, 'standalone retention worker must have one explicit role guard');
  requireBoundary(guardedRegistrations.filter((block) => block.includes('"pubsub-subscription-cleanup"') &&
    block.includes('subscription_cleanup::serve_context(')).length === 1 &&
    [...main.matchAll(/\.supervise\(\s*"pubsub-subscription-cleanup"/g)].length === 1,
  'standalone subscription cleanup must have one explicit role guard');
  const workers = [...subservers.matchAll(/\.supervise(?:_draining)?\(\s*"([^"]+)"/g)].map((match) => match[1]);
  requireBoundary(JSON.stringify(workers) === JSON.stringify(['archive-retention', 'pubsub-subscription-cleanup']),
    'maintenance may supervise only its declared retention worker');
  requireBoundary(/"archive-retention",\s*WorkerCriticality::Restartable,\s*WorkerMode::Continuous,\s*Some\(silence\)/.test(run),
    'maintenance retention must retain its restart/readiness/watchdog contract');
  requireBoundary(/"pubsub-subscription-cleanup",\s*WorkerCriticality::Restartable,\s*WorkerMode::Continuous,\s*Some\((?:crate::)?subscription_cleanup::MAX_SILENCE\)/.test(run) &&
    run.includes('subscription_cleanup::serve_context('),
    'maintenance subscription cleanup must retain its independent restart/readiness/watchdog contract');
  const observers = [...subservers.matchAll(/\.register_observer\(\s*"([^"]+)"/g)].map((match) => match[1]);
  requireBoundary(JSON.stringify(observers) === JSON.stringify(['maintenance-ownership']),
    'maintenance ownership health must have one explicit observer');
  requireBoundary(/\.register_observer\("maintenance-ownership",\s*WorkerCriticality::Critical\)/.test(run),
    'maintenance ownership observer must remain critical');
  for (const marker of ['Duration::from_secs(5)', 'Duration::from_secs(3)',
    'sqlx::query("SELECT 1").execute(&mut *ownership)', 'if !matches!(probe, Ok(Ok(_)))',
    'break Err(anyhow::anyhow!("maintenance database ownership connection failed"))']) {
    requireBoundary(run.replace(/\s+/g, '').includes(marker.replace(/\s+/g, '')),
      `maintenance exact-session loss detection changed: ${marker}`);
  }
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
