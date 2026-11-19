import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readProductionModule, readRoleSplitFile, readModule, readModuleParts, rustItemBody } from './lib/source-module.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function structBody(source, declaration) {
  const start = source.indexOf(declaration);
  if (start < 0) throw new Error(`missing ${declaration}`);
  const open = source.indexOf('{', start + declaration.length);
  if (open < 0) throw new Error(`missing body for ${declaration}`);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    if (source[index] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, index);
    }
  }
  throw new Error(`unterminated body for ${declaration}`);
}

function countMatches(source, pattern) {
  return [...source.matchAll(pattern)].length;
}

// Mask complete cfg(test) items while preserving offsets and line breaks.
// Truncating at the first marker can silently hide production items declared
// later in the file. Test-only functions and imports can also appear between
// production items, so the aggregate security boundary uses this structural
// scanner rather than relying on source layout conventions.
function productionWithoutCfgTestModules(source, moduleName) {
  const ranges = [];
  const pattern = /^\s*#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]/gm;
  for (let match; (match = pattern.exec(source)) !== null; ) {
    const itemStart = pattern.lastIndex;
    const tail = source.slice(itemStart);
    const firstSemicolon = tail.indexOf(';');
    const firstOpening = tail.indexOf('{');
    const isUse = /^\s*(?:#\s*\[[^\]]+\]\s*)*(?:pub(?:\([^)]*\))?\s+)?use\b/s.test(tail);
    let end;
    if (firstSemicolon >= 0 && (isUse || firstOpening < 0 || firstSemicolon < firstOpening)) {
      end = itemStart + firstSemicolon + 1;
    } else if (firstOpening >= 0) {
      const opening = itemStart + firstOpening;
      const closing = matchingRustBrace(source, opening);
      if (closing < 0) throw new Error(`${moduleName} has an unterminated cfg(test) item`);
      end = closing + 1;
    } else {
      throw new Error(`${moduleName} has an unclassified cfg(test) item`);
    }
    ranges.push([match.index, end]);
    pattern.lastIndex = end;
  }
  let output = '';
  let cursor = 0;
  for (const [start, end] of ranges) {
    output += source.slice(cursor, start);
    output += source.slice(start, end).replace(/[^\r\n]/g, ' ');
    cursor = end;
  }
  return output + source.slice(cursor);
}

function matchingRustBrace(source, opening) {
  let depth = 1;
  let index = opening + 1;
  while (index < source.length) {
    if (source.startsWith('//', index)) {
      const newline = source.indexOf('\n', index + 2);
      index = newline < 0 ? source.length : newline + 1;
      continue;
    }
    if (source.startsWith('/*', index)) {
      let commentDepth = 1;
      index += 2;
      while (index < source.length && commentDepth > 0) {
        if (source.startsWith('/*', index)) {
          commentDepth += 1;
          index += 2;
        } else if (source.startsWith('*/', index)) {
          commentDepth -= 1;
          index += 2;
        } else index += 1;
      }
      continue;
    }
    const raw = /^(?:br|rb|r)(#+)?"/.exec(source.slice(index));
    if (raw) {
      const terminator = `"${raw[1] ?? ''}`;
      const closing = source.indexOf(terminator, index + raw[0].length);
      if (closing < 0) return -1;
      index = closing + terminator.length;
      continue;
    }
    const quoteOffset = source[index] === '"' ? 0 : source.startsWith('b"', index) ? 1 : -1;
    if (quoteOffset >= 0) {
      index += quoteOffset + 1;
      let escaped = false;
      while (index < source.length) {
        const character = source[index++];
        if (escaped) escaped = false;
        else if (character === '\\') escaped = true;
        else if (character === '"') break;
      }
      continue;
    }
    const charStart =
      source[index] === "'" ? index + 1 : source.startsWith("b'", index) ? index + 2 : -1;
    if (charStart >= 0 && charStart < source.length) {
      let cursor = charStart;
      if (source[cursor] === '\\') {
        cursor += 2;
        if (source[cursor - 1] === 'u' && source[cursor] === '{') {
          const brace = source.indexOf('}', cursor + 1);
          cursor = brace < 0 ? source.length : brace + 1;
        }
      } else {
        const scalar = source.codePointAt(cursor);
        cursor += scalar !== undefined && scalar > 0xffff ? 2 : 1;
      }
      if (source[cursor] === "'") {
        index = cursor + 1;
        continue;
      }
    }
    if (source[index] === '{') depth += 1;
    else if (source[index] === '}' && --depth === 0) return index;
    index += 1;
  }
  return -1;
}

function asyncFunctionSpans(source, moduleName) {
  const functions = [];
  const declaration =
    /^[\t ]*(?:pub(?:[\t ]*\([^\r\n)]*\))?[\t ]+)?async[\t ]+fn[\t ]+([A-Za-z_][A-Za-z0-9_]*)[\t ]*(?:<[^>{}]*>)?[\t ]*\(/gm;
  for (let match; (match = declaration.exec(source)) !== null; ) {
    const opening = source.indexOf('{', declaration.lastIndex);
    if (opening < 0) {
      throw new Error(`${moduleName} declares async fn ${match[1]} without a parseable body`);
    }
    const closing = matchingRustBrace(source, opening);
    if (closing < 0) {
      throw new Error(`${moduleName} has an unterminated async fn ${match[1]}`);
    }
    functions.push({ name: match[1], opening, closing });
    declaration.lastIndex = closing + 1;
  }
  return functions;
}

function functionBody(source, span) {
  return source.slice(span.opening + 1, span.closing);
}

function statementBeforeAwait(source, awaitOffset) {
  const boundary = Math.max(
    source.lastIndexOf(';', awaitOffset),
    source.lastIndexOf('{', awaitOffset),
    source.lastIndexOf('}', awaitOffset),
  );
  return source.slice(boundary + 1, awaitOffset);
}

function classifyDbDependencies(source, moduleName) {
  let authorityReferences = 0;
  let domainReferences = 0;

  for (const match of source.matchAll(/^\s*use\s+([^;]+);/gm)) {
    const authorityImport = match[1].match(/\bdb::([a-z_][A-Za-z0-9_]*)/);
    if (authorityImport) {
      throw new Error(
        `${moduleName} imports db authority ${authorityImport[1]} into local scope; ` +
          `use db::${authorityImport[1]} at every call site`,
      );
    }
    if (/\bdb::[A-Za-z_][A-Za-z0-9_]*\s+as\s+/.test(match[1])) {
      throw new Error(`${moduleName} aliases a db symbol and can evade the coupling gate`);
    }
  }

  // Rust naming makes this distinction mechanically reviewable: persistence
  // functions and submodules are lower_snake_case, while exported domain
  // models/enums are UpperCamelCase and constants are SCREAMING_SNAKE_CASE.
  // Keep counting reference sites (including inline test modules), as the old
  // aggregate gate did, but do not call a model match an exercise of database
  // authority.
  for (const match of source.matchAll(/\bdb::([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (/^[a-z_]/.test(match[1])) {
      authorityReferences += 1;
    } else {
      domainReferences += 1;
    }
  }

  // A grouped import has no identifier after `db::`, so account for each
  // imported domain symbol explicitly. More importantly, reject importing a
  // persistence function/submodule into local scope: otherwise changing
  // `db::write(...)` into `write(...)` would make the authority budget lie.
  for (const match of source.matchAll(/\bdb\s*::\s*\{([^{}]*)\}/gs)) {
    for (const rawItem of match[1].split(',')) {
      const item = rawItem.trim();
      if (item.length === 0 || item === 'self') continue;
      if (item === '*' || /\s+as\s+/.test(item)) {
        throw new Error(
          `${moduleName} aliases or glob-imports a db symbol; keep the dependency auditable`,
        );
      }
      const imported = item.match(/^([A-Za-z_][A-Za-z0-9_]*)$/);
      if (!imported) {
        throw new Error(`${moduleName} has an unclassified grouped db import: ${item}`);
      }
      if (/^[a-z_]/.test(imported[1])) {
        throw new Error(
          `${moduleName} imports db authority ${imported[1]} into local scope; use db::${imported[1]}`,
        );
      }
      domainReferences += 1;
    }
  }

  if (/\b(?:crate\s*::\s*)?db\s+as\s+[A-Za-z_][A-Za-z0-9_]*/.test(source)) {
    throw new Error(`${moduleName} aliases the db namespace and can evade the authority gate`);
  }
  if (/\bdb\s*::\s*\*/.test(source)) {
    throw new Error(`${moduleName} glob-imports the db namespace and can evade the authority gate`);
  }

  return { authorityReferences, domainReferences };
}

// whole production module (the file and its non-test child files); items are
// read by their unique declaration, so they keep being found after a split
const state = readProductionModule('src/node.rs', { root });
// crates/edges/northstar-cluster/src/lib.rs is read as its whole production module too (listener.rs,
// pool.rs and the files a split adds), with items read by unique declaration
const cluster = readProductionModule('crates/edges/northstar-cluster/src/lib.rs', { root });
const mainSource = read('src/main.rs');
const workerComposition = readProductionModule('src/node/workers.rs', { root });
const abuseWorkers = read('src/node/workers/abuse.rs');
const abuseAuthorityWorker = read('crates/contexts/operations/northstar-operations-application/src/abuse_authority_worker.rs');
const maintenanceWorkers = read('src/node/workers/maintenance.rs');
const clusterWorkers = read('src/node/workers/cluster.rs');
const responsibilityDocument = read('docs/PROGRAM_RESPONSIBILITIES.md');
const listenerStressDriver = read('scripts/listener-readiness-stress-wsl.sh');
const loopbackPostgresFixture = read('scripts/loopback-postgres-ci.sh');
const ciWorkflow = read('.github/workflows/ci.yml');
const appState = rustItemBody(state, 'pub struct ServerNode');
const httpModule = rustItemBody(read('src/node/modules/http.rs'), 'pub(in crate::node) struct HttpModule');
const publicFields = countMatches(appState, /^\s*pub\s+[A-Za-z_][A-Za-z0-9_]*\s*:/gm);
const cratePublicFields = countMatches(appState, /^\s*pub\(crate\)\s+[A-Za-z_][A-Za-z0-9_]*\s*:/gm);
const publicFieldNames = [
  ...appState.matchAll(/^\s*pub\s+([A-Za-z_][A-Za-z0-9_]*)\s*:/gm),
].map((match) => match[1]);

// Public capability counts may only decrease as service boundaries narrow.
// New work must use application services without raising these ceilings.
const MAX_APP_STATE_PUBLIC_FIELDS = 0;
const MAX_APP_STATE_CRATE_PUBLIC_FIELDS = 0;
const EXPECTED_APP_STATE_PUBLIC_CAPABILITIES = [];

if (publicFields > MAX_APP_STATE_PUBLIC_FIELDS) {
  throw new Error(
    `ServerNode public-field budget regressed: ${publicFields} > ${MAX_APP_STATE_PUBLIC_FIELDS}`,
  );
}
if (cratePublicFields > MAX_APP_STATE_CRATE_PUBLIC_FIELDS) {
  throw new Error(
    `ServerNode crate-public-field budget regressed: ${cratePublicFields} > ${MAX_APP_STATE_CRATE_PUBLIC_FIELDS}`,
  );
}
const actualPublicCapabilities = [...publicFieldNames].sort();
if (
  actualPublicCapabilities.length !== EXPECTED_APP_STATE_PUBLIC_CAPABILITIES.length ||
  actualPublicCapabilities.some(
    (name, index) => name !== EXPECTED_APP_STATE_PUBLIC_CAPABILITIES[index],
  )
) {
  throw new Error(
    'ServerNode public capability identity changed; extract a typed port or update the reviewed ' +
      `responsibility model instead of swapping fields under the count budget: ${actualPublicCapabilities.join(', ')}`,
  );
}
if (/\b(?:state|shutdown_state)\.pool\b/.test(mainSource + cluster)
    || !appState.includes('pool: PgPool,')) {
  throw new Error('process and cluster workers must use narrow state-owned database capabilities');
}
if (!rustItemBody(read('src/node/hosts/s2s_inbound.rs'), 'fn local_domain(').includes('&self.config.domain')
    || /\bstate\.config\.domain\b/.test(readProductionModule('crates/edges/northstar-s2s/src/inbound.rs', { root }))) {
  throw new Error('S2S ingress must receive only the validated local domain');
}
const clusterMessageResolver = rustItemBody(cluster, 'async fn resolve_node_message_delivery<');
if (!clusterMessageResolver.includes('verifier.resolve(request, stanza, target_jid).await?')
    || /sqlx::|\.fetch_(?:one|optional|all)\(/.test(clusterMessageResolver)
    || !readProductionModule('crates/edges/northstar-cluster/src/listener.rs', { root }).includes('message_policy.verifier()')
    || !read('src/node/adapters/cluster_listener_message.rs').includes('verifier: northstar_session_application::node_message_contract_verifier::NodeMessageContractVerifier::new(')
    || !read('src/node/adapters/cluster_listener_message.rs').includes('northstar_session_postgres::node_message_projection_repository::PostgresNodeMessageProjectionRepository::new(')) {
  throw new Error('inbound cluster message contracts must use the PostgreSQL projection verifier port');
}

for (const field of [
  'upload',
  'pubsub',
  'room',
  'roster',
  'abuse',
  'auth',
  'operations',
  'message',
  'federation',
  'archive',
  'session',
  'runtime',
  'tls_context',
]) {
  if (!new RegExp(`^\\s*${field}\\s*:`, 'm').test(appState)) {
    throw new Error(`ServerNode capability ${field} is no longer private or is missing`);
  }
  if (new RegExp(`^\\s*pub(?:\\(crate\\))?\\s+${field}\\s*:`, 'm').test(appState)) {
    throw new Error(`ServerNode capability ${field} became publicly accessible`);
  }
}
const sessionLiveState = structBody(read('src/node/modules/session.rs'), 'pub(in crate::node) struct SessionLiveState');
for (const field of [
  'bosh',
  'sessions',
  'caps_cache',
  'caps_by_jid',
  'pending_caps',
  'federated_caps_gates',
  'caps_effect_dispatcher',
  'client_admission',
  'connection_actors',
]) {
  if (!new RegExp(`^\\s*${field}\\s*:`, 'm').test(sessionLiveState)) {
    throw new Error(`ServerNode capability ${field} is no longer private or is missing`);
  }
  if (new RegExp(`^\\s*pub(?:\\(crate\\))?\\s+${field}\\s*:`, 'm').test(sessionLiveState)) {
    throw new Error(`ServerNode capability ${field} became publicly accessible`);
  }
}
const runtimeModuleSource = read('src/node/modules/runtime.rs');
const runtimeModule = structBody(runtimeModuleSource, 'pub(in crate::node) struct RuntimeModule');
for (const field of [
  'started_at',
  'process_started_at',
  'service_shutdown',
  'runtime_control_liveness',
  'workers',
]) {
  if (!new RegExp(`^\\s*${field}\\s*:`, 'm').test(runtimeModule)) {
    throw new Error(`ServerNode capability ${field} is no longer private or is missing`);
  }
  if (new RegExp(`^\\s*pub(?:\\(crate\\))?\\s+${field}\\s*:`, 'm').test(runtimeModule)) {
    throw new Error(`ServerNode capability ${field} became publicly accessible`);
  }
}
if (!/^\s*pub\(in crate::node\)\s+registration\s*:\s*northstar_auth_application::registration_availability::RegistrationAvailability\s*,/m.test(read('src/node/modules/auth.rs'))) {
  throw new Error('AuthModule registration availability must remain inside the node');
}
if (!/^\s*pub\(in crate::node\)\s+dialback_secret\s*:\s*Zeroizing<Vec<u8>>\s*,/m.test(read('src/node/modules/federation.rs'))) {
  throw new Error('FederationModule dialback_secret must remain inside the node and Zeroizing');
}
if (/^\s*(?:pub(?:\(crate\))?\s+)?fast_token_secret\s*:/m.test(appState)) {
  throw new Error('ServerNode must not retain the FAST derivation key after adapter construction');
}
const smAdapterBody = structBody(read('crates/contexts/workflows/northstar-workflows/src/sm_repository.rs'), 'pub struct PostgresSmRepository');
if (!/^\s*fast_token_secret\s*:\s*Arc<Zeroizing<Vec<u8>>>\s*,/m.test(smAdapterBody)) {
  throw new Error('SM repository FAST key must remain private Arc<Zeroizing<Vec<u8>>>');
}
const runtimeControlConnection = read('crates/contexts/operations/northstar-operations-postgres/src/runtime_control_connection.rs');
const runtimeControlPoolConstruction = rustItemBody(runtimeControlConnection, 'fn runtime_control_pool_options(');
for (const invariant of [
  'max_connections(SERVICE_CONTROL_POOL_MAX_CONNECTIONS)',
  'min_connections(SERVICE_CONTROL_POOL_MAX_CONNECTIONS)',
  'acquire_timeout(attempt_budget)',
  'northstar_postgres::role_attestation::pin_public_application_schema(options)',
]) {
  if (!runtimeControlPoolConstruction.includes(invariant)) {
    throw new Error(`runtime-control pool lost its isolated runtime-pool invariant: ${invariant}`);
  }
}
const runtimeControlRefresh = rustItemBody(state, 'fn start_runtime_control_refresh(');
const runtimeControlContext = read('crates/contexts/operations/northstar-operations-application/src/runtime_control_coordinator.rs');
const runtimeControlRun = structBody(runtimeControlContext, 'pub async fn run(');
if ((runtimeControlRefresh.match(/let\s+max_silence\s*=/g) ?? []).length !== 1
    || !/let max_silence = Duration::from_secs\(5\);/.test(runtimeControlRefresh)
    || !/"runtime-control-refresh",\s*northstar_runtime::workers::WorkerCriticality::Critical,\s*northstar_runtime::workers::WorkerMode::Continuous,\s*Some\(max_silence\),/s.test(runtimeControlRefresh)
    || !/RuntimeControlDiagnostics::new\(diagnostic_cancel,\s*max_silence\)/s.test(runtimeControlRun)
    || /\bArc<ServerNode>\b/.test(runtimeControlContext)
    || !runtimeControlRun.includes('Duration::from_millis(500)')
    || !runtimeControlRun.includes('self.connection.lock().await.take()')) {
  throw new Error('runtime-control diagnostics and supervision must share the unchanged five-second silence bound');
}
if (/fn start_runtime_(?:federation_policy|admin_setting)_refresh\(|fn start_service_control_watcher\(/.test(state)) {
  throw new Error('independent runtime control workers can contend for the one-connection control pool');
}
const runtimeControlReservation = rustItemBody(runtimeControlConnection, 'pub async fn reserve_runtime_control_connection(');
for (const invariant of [
  'runtime_control_pool_options(config, attempt_budget)',
  'let connect_options = runtime_control_connect_options(&config.database_url)?;',
  '.connect_with(connect_options.clone())',
  'RUNTIME_CONTROL_STARTUP_RETRY_BUDGET',
  'runtime_control_startup_connect(deadline,',
  'tokio::time::timeout_at(deadline,',
]) {
  if (!runtimeControlReservation.includes(invariant)) {
    throw new Error(`runtime-control startup reservation lost required invariant: ${invariant}`);
  }
}
if (!/runtime_control_pool\s*\.acquire\(\)\s*\.await/s.test(runtimeControlReservation)) {
  throw new Error('runtime-control startup reservation must retain its one dedicated connection');
}
if (!/pub async fn new\([\s\S]*?runtime_control_connection\s*:\s*PoolConnection<Postgres>/.test(state)) {
  throw new Error('ServerNode must receive the already-reserved runtime-control connection');
}
const terminalMain = structBody(mainSource, 'async fn main()');
if (terminalMain.replace(/\s+/g, '') !== 'northstar_telemetry::logging::report_result(run().await)') {
  throw new Error('main must report its final result through the bounded console owner');
}
const runtimeMain = structBody(mainSource, 'async fn run()');
if ([...runtimeMain.matchAll(/state\.start_workers\(&cancel, process_role\)/g)].length !== 1
    || /\.supervise(?:_draining)?\(/.test(runtimeMain)) {
  throw new Error('main must delegate supervised worker composition through exactly one startup call');
}
if (!abuseWorkers.includes('let authority_probe = abuse_key_authority_probe(state);')
    || !/tokio::time::timeout\(\s*ABUSE_KEY_AUTHORITY_QUERY_TIMEOUT,\s*authority_probe\.validate\(&authority_identity\)/s.test(abuseAuthorityWorker)
    || !maintenanceWorkers.includes('let bg_context = Arc::new(background_maintenance_context(state));')
    || /let authority_pool = state\.pool\.clone\(\)/.test(workerComposition)) {
  throw new Error('critical key guard and housekeeping must use narrow repository-backed capabilities');
}
if (!maintenanceWorkers.includes('retention_context(state)')
    || !maintenanceWorkers.includes('subscription_cleanup_context(state)')
    || /PostgresMaintenanceRepository::new\(state\.pool\.clone\(\)\)/.test(workerComposition)) {
  throw new Error('retention workers must receive separate state-owned repository contexts');
}
const mainRuntimeControlReservation = runtimeMain.indexOf('node::reserve_runtime_control_connection(&config).await?');
const mainPrimaryPoolConstruction = runtimeMain.indexOf('let pool_options = northstar_postgres::pool::options()');
if (mainRuntimeControlReservation < 0 || mainPrimaryPoolConstruction < 0
    || mainRuntimeControlReservation > mainPrimaryPoolConstruction) {
  throw new Error('main must reserve runtime-control authority before constructing the traffic pool');
}
if (!/Self::start_runtime_control_refresh\(\s*Arc::clone\(&state\),\s*runtime_control_connection,\s*worker_cancel,\s*\);/s.test(state)) {
  throw new Error('ServerNode must transfer the reserved connection to the coordinated runtime-control worker');
}
const serviceControlInstallation = rustItemBody(runtimeModuleSource, 'pub(in crate::node) fn install_service_shutdown(');
if (!/self\.service_shutdown\s*\.set\(cancel\)/s.test(serviceControlInstallation)) {
  throw new Error('XEP-0133 service control must install the shutdown authority before the coordinator polls it');
}
if (!responsibilityDocument.includes('| runtime control pool | `northstar_runtime` | exactly 1 reserved connection; at most 3 s per initial handshake within one absolute 15 s admission deadline, including jitter, role attestation and reservation |')) {
  throw new Error('program responsibility model must document the dedicated runtime control pool');
}
// whole production module (the file and its non-test child files)
const mixProtocol = readProductionModule('crates/contexts/room/northstar-mix-xmpp/src/lib.rs', { root });
const mixProtocolProduction = productionWithoutCfgTestModules(
  mixProtocol,
  'crates/contexts/room/northstar-mix-xmpp/src/lib.rs',
);
const commandPoolConstruction = rustItemBody(state, 'pub async fn new(');
// The upload storage pool is opened by UploadModule::start, called from ServerNode::new.
const uploadModuleStart = rustItemBody(state, 'pub(in crate::node) async fn start(');
for (const invariant of [
  'let auxiliary_pool_deadline = tokio::time::Instant::now() + AUXILIARY_POOL_STARTUP_BUDGET;',
  'startup_database_connect( auxiliary_pool_deadline, AUXILIARY_POOL_ACQUIRE_TIMEOUT, "XEP-0133 command",',
  'startup_database_connect( auxiliary_pool_deadline, AUXILIARY_POOL_ACQUIRE_TIMEOUT, "OMEMO recovery poll",',
  'tokio::time::timeout_at(auxiliary_pool_deadline,',
]) {
  if (!commandPoolConstruction.replace(/\s+/g, '').includes(invariant.replace(/\s+/g, ''))) {
    throw new Error(`auxiliary pools must share bounded startup admission: ${invariant}`);
  }
}
if (countMatches(commandPoolConstruction, /\.acquire_timeout\(AUXILIARY_POOL_ACQUIRE_TIMEOUT\)/g)
      + countMatches(uploadModuleStart, /\.acquire_timeout\(AUXILIARY_POOL_ACQUIRE_TIMEOUT\)/g) !== 3
    || !/const AUXILIARY_POOL_ACQUIRE_TIMEOUT:\s*Duration\s*=\s*Duration::from_secs\(2\)/.test(state)
    || !/const AUXILIARY_POOL_STARTUP_BUDGET:\s*Duration\s*=\s*Duration::from_secs\(15\)/.test(state)) {
  throw new Error('auxiliary pools retain a 2 s acquisition policy within a shared 15 s startup window');
}
const commandPoolModeMatch = structBody(
  commandPoolConstruction,
  'let command_pool = match config.admin_command_pool_mode',
);
if (
  countMatches(commandPoolModeMatch, /AdminCommandPoolMode\s*::\s*SharedUnsafeDevelopment/g) !== 1 ||
  !/AdminCommandPoolMode\s*::\s*SharedUnsafeDevelopment\s*=>\s*pool\s*\.\s*clone\s*\(\s*\)\s*,/.test(
    commandPoolModeMatch,
  )
) {
  throw new Error('unsafe development must mount the command service on the already-attested primary pool');
}
if (
  !/AdminCommandPoolMode\s*::\s*DedicatedProductionRole\s*=>\s*\{[\s\S]*?\.connect\s*\(\s*&config\s*\.\s*admin_command_database_url\s*\)[\s\S]*?attest_admin_command_role\s*\(\s*&command_pool\s*\)\s*\.\s*await\s*\?/.test(
    commandPoolModeMatch,
  )
) {
  throw new Error('production command mode must keep its separately attested command-role pool');
}
if (!mainSource.includes('Some("--storage-connection-budget")')
    || !uploadModuleStart.includes('StoragePoolMode::Disabled => None')
    || !uploadModuleStart.includes('StoragePoolMode::SharedUnsafeDevelopment => Some(pool.clone())')
    || !uploadModuleStart.includes('northstar_postgres::role_attestation::attest_storage_role(&storage_pool)')
    || !commandPoolConstruction.includes('UploadModule::start(&config, &pool).await?')) {
  throw new Error('storage pool must be absent when disabled and attested in production');
}
for (const invariant of [
  'load_runtime_connection_budget()',
  '"$binary" --runtime-connection-budget',
  'runtime_connections_per_child=$((database_max_connections + runtime_auxiliary_connections))',
  'readonly stress_child_count=$((pairs * 2))',
  'fixture_control_connections_per_pair=1',
  'required_fixture_connections=$((stress_child_count * runtime_connections_per_child + fixture_control_connections + observer_connections))',
  'observer_connections="${NORTHSTAR_LISTENER_STRESS_OBSERVER_CONNECTIONS:-0}"',
  'case "$observer_connections" in 0|1)',
  'publish_observer_round_map()',
  'assert_fixture_connection_capacity()',
  "SHOW max_connections;",
  'fixture_actual_max_connections >= required_fixture_connections',
  '10#$configured == fixture_actual_max_connections',
]) {
  if (!listenerStressDriver.includes(invariant)) {
    throw new Error(`listener stress capacity calculation is missing: ${invariant}`);
  }
}
if (!mainSource.includes('Some("--runtime-connection-budget")')) {
  throw new Error('the server no longer exposes its runtime connection budget manifest');
}
if (listenerStressDriver.includes('NORTHSTAR_LISTENER_STRESS_POSTGRES_HEADROOM')) {
  throw new Error('listener stress capacity must not rely on generic PostgreSQL headroom');
}
if (!/max_connections < 16 \|\| max_connections > 768/.test(loopbackPostgresFixture)) {
  throw new Error('loopback PostgreSQL fixture no longer admits the reviewed stress capacity');
}
if (
  countMatches(ciWorkflow, /NORTHSTAR_LOOPBACK_POSTGRES_MAX_CONNECTIONS: "672"/g) !== 2 ||
  !ciWorkflow.includes('NORTHSTAR_LOOPBACK_POSTGRES_MAX_CONNECTIONS: "32"') ||
  ciWorkflow.includes('NORTHSTAR_LISTENER_STRESS_POSTGRES_HEADROOM')
) {
  throw new Error('listener stress workflow no longer declares auditable smoke and full-matrix capacity budgets');
}

// Runtime secrets must be transferred exactly once from Config into their
// narrow owner. ServerNode deliberately keeps Config for non-secret policy, so
// leaving even an Option/Arc clone behind would make the secret reachable by
// every protocol handler through `state.config`.
const appStateNew = rustItemBody(state, 'pub async fn new(');
for (const field of [
  'bootstrap_admin_password',
  'turn_shared_secret',
  'dialback_secret',
  'fast_token_secret',
  'abuse_state_hmac_key',
  'abuse_state_hmac_previous_key',
  'redis_url',
]) {
  if (
    !new RegExp(
      `config\\s*\\.\\s*raw\\s*\\.\\s*${field}\\s*\\.\\s*take\\s*\\(`,
    ).test(appStateNew)
  ) {
    throw new Error(`ServerNode::new must take and consume config.raw.${field}`);
  }
}
for (const field of ['metrics_bearer_token', 'cluster_security']) {
  if (!new RegExp(`config\\s*\\.\\s*${field}\\s*\\.\\s*take\\s*\\(`).test(appStateNew)) {
    throw new Error(`ServerNode::new must take and consume config.${field}`);
  }
}
for (const operation of ['zeroize', 'clear']) {
  if (
    !new RegExp(
      `config\\s*\\.\\s*raw\\s*\\.\\s*database_url\\s*\\.\\s*${operation}\\s*\\(`,
    ).test(appStateNew)
  ) {
    throw new Error(`ServerNode::new must ${operation} config.raw.database_url after pool creation`);
  }
}
if (!/config\s*\.\s*take_component_credentials\s*\(/.test(appStateNew)) {
  throw new Error('ServerNode::new must take exclusive ownership of component credentials');
}
if (
  /^\s*pub(?:\(crate\))?\s+[A-Za-z_][A-Za-z0-9_]*(?:secret|token|credential|keyring)[A-Za-z0-9_]*\s*:/gim.test(
    `${appState}\n${httpModule}`,
  )
) {
  throw new Error('ServerNode exposes a runtime secret/token/credential capability as a field');
}
for (const field of ['metrics_bearer_token', 'web_admin_gateway_token']) {
  if (!new RegExp(`^\\s*${field}\\s*:\\s*Option<Arc<Zeroizing<String>>>\\s*,`, 'm').test(httpModule)) {
    throw new Error('ServerNode exposes a runtime secret/token/credential capability as a field');
  }
}

// The context ports' impls for the session and the context glue moved to the contexts' -xmpp crates. Each
// protocol_session.rs holds one "// From src/xmpp/protocol/<module>.rs." section per root module it came from; a
// protocol module is read together with its sections, and a module whose file left the root is its sections.
const sessionImplSections = new Map();
const contextsDirectory = path.join(root, 'crates', 'contexts');
for (const context of fs.readdirSync(contextsDirectory, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
  const contextDirectory = path.join(contextsDirectory, context.name);
  for (const crate of fs.readdirSync(contextDirectory, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
    const file = path.join(contextDirectory, crate.name, 'src', 'protocol_session.rs');
    if (!fs.existsSync(file)) continue;
    const parts = fs.readFileSync(file, 'utf8').split(/^\/\/ From src\/xmpp\/protocol\/([\w/]+)\.rs\.$/m);
    for (let index = 1; index < parts.length; index += 2) {
      const name = `${parts[index].split('/')[0]}.rs`;
      sessionImplSections.set(name, `${sessionImplSections.get(name) ?? ''}\n${parts[index + 1]}`);
    }
  }
}
function withSessionImpls(name, source) {
  return `${source}\n${sessionImplSections.get(name) ?? ''}`;
}

// The root's glue modules, northstar-stream's session modules and the sections of glue that has no file left;
// no module name has a file in both directories.
const protocolModulePaths = new Map([
  ...[...sessionImplSections.keys()].map((name) => [name, null]),
  ...['crates/edges/northstar-stream/src/protocol'].flatMap((directory) =>
    fs
      .readdirSync(path.join(root, directory))
      .filter((name) => name.endsWith('.rs'))
      .map((name) => [name, `${directory}/${name}`]),
  ),
]);
const protocolFiles = [...protocolModulePaths.keys()].sort();
function protocolModuleSource(name, readFile = (relative) => readProductionModule(relative, { root })) {
  const relative = protocolModulePaths.get(name);
  return withSessionImpls(name, relative ? readFile(relative) : '');
}

// Preserve single-file reads for unrelated modules in the mixed inventories below.
const productionProtocolModules = new Set([
  'pep.rs', 'pubsub.rs', 'messaging.rs', 'commands.rs', 'presence.rs', 'sasl2.rs',
]);
function readProtocolSource(name) {
  return productionProtocolModules.has(name) ? protocolModuleSource(name) : protocolModuleSource(name, read);
}

let protocolDbAuthorityReferences = 0;
let protocolDbDomainReferences = 0;
let protocolStatePoolReferences = 0;
let protocolSqlxReferences = 0;
let protocolPgPoolReferences = 0;
const perFile = [];
for (const name of protocolFiles) {
  // Each top-level protocol module is read with its non-test child files, so
  // code moved into `protocol/<name>/` keeps being counted.
  const source = protocolModuleSource(name);
  const productionSource = productionWithoutCfgTestModules(source, `${name} production`);
  const { authorityReferences, domainReferences } = classifyDbDependencies(
    productionSource,
    `${name} production`,
  );
  protocolStatePoolReferences += countMatches(
    productionSource,
    /\b(?:self\s*\.\s*)?state\s*\.\s*pool\b/g,
  );
  protocolSqlxReferences += countMatches(productionSource, /\bsqlx\s*::/g);
  protocolPgPoolReferences += countMatches(
    productionSource,
    /\b(?<!::)PgPool\b/g,
  );
  if (authorityReferences > 0 || domainReferences > 0) {
    protocolDbAuthorityReferences += authorityReferences;
    protocolDbDomainReferences += domainReferences;
    perFile.push({
      name,
      authorityReferences,
      domainReferences,
      lines: source.split(/\r?\n/).length - 1,
    });
  }
}

// A fully extracted protocol module legitimately disappears from `perFile`.
// Treat absence as the monotonic zero-coupling result instead of making the
// architecture gate fail when the boundary improves beyond its old baseline.
const mix = perFile.find(({ name }) => name === 'mix.rs') ?? {
  name: 'mix.rs',
  authorityReferences: 0,
  domainReferences: 0,
};

// MIX durable fan-out has one application-service admission boundary. Keep
// the complete producer set explicit: omitting one method would let normal
// same-process concurrency queue on PostgreSQL only after consuming PgPool
// connections, while calling the repository directly would bypass FIFO
// coordination altogether.
const mixProducerMappings = [
  ['destroy_mix_channel', 'destroy_mix_channel'],
  ['join_mix_channel', 'join_mix_channel'],
  ['expire_unrefreshed_mix_presence', 'expire_unrefreshed_mix_presence'],
  ['update_mix_subscriptions', 'update_mix_subscriptions'],
  ['set_mix_nick', 'set_mix_nick'],
  ['leave_mix_channel', 'leave_mix_channel'],
  ['store_mix_presence', 'store_mix_presence_with_policy'],
  ['ensure_mix_presence', 'store_mix_presence_with_policy'],
  ['store_mix_message', 'store_mix_message_inner'],
  ['store_mix_message_observed', 'store_mix_message_inner'],
  ['publish_mix_avatar', 'publish_mix_avatar'],
  ['retract_mix_avatar', 'retract_mix_avatar'],
  ['update_mix_info', 'update_mix_info'],
  ['update_mix_config', 'update_mix_config'],
  ['set_mix_access_entry', 'set_mix_access_entry'],
  ['register_mix_nick', 'register_mix_nick'],
  ['update_mix_participant_preference', 'update_mix_participant_preference'],
  ['retract_mix_message', 'retract_mix_message'],
  ['requeue_mix_delivery_dead_letter', 'requeue_mix_delivery_dead_letter'],
];
const mixProducerMethods = mixProducerMappings.map(([serviceMethod]) => serviceMethod);
if (new Set(mixProducerMethods).size !== mixProducerMethods.length) {
  throw new Error('MIX service producer mapping contains duplicate service methods');
}
const mixServiceSource = readProductionModule('crates/contexts/room/northstar-room-application/src/mix_service.rs', { root });
const mixServiceProduction = productionWithoutCfgTestModules(
  mixServiceSource,
  'crates/contexts/room/northstar-room-application/src/mix_service.rs',
);
const mixServiceDefinition = structBody(mixServiceProduction, 'pub struct MixService');
if (
  !/^\s*outbox_background_budget\s*:\s*usize\s*,?\s*$/m.test(mixServiceDefinition) ||
  !/^\s*outbox_db_admission\s*:\s*northstar_runtime\s*::\s*durable_outbox\s*::\s*DurableOutboxDatabaseAdmission\s*,?\s*$/m.test(
    mixServiceDefinition,
  ) ||
  /^\s*pub(?:\(crate\))?\s+outbox_(?:background_budget|db_admission)\s*:/m.test(
    mixServiceDefinition,
  )
) {
  throw new Error(
    'MixService must privately retain its typed outbox budget and application-owned DB admission capability',
  );
}
if (
  !/async\s+fn\s+outbox_db_admission_guard\s*\(\s*&self\s*\)\s*->\s*OwnedSemaphorePermit/.test(
    mixServiceProduction,
  ) ||
  /pub(?:\(crate\))?\s+async\s+fn\s+outbox_db_admission_guard\b/.test(mixServiceProduction)
) {
  throw new Error('MIX outbox DB permits must remain private OwnedSemaphorePermit capability tokens');
}
const stateOutboxAdmission = rustItemBody(state, 'pub struct ServerNode');
if (
  !/^\s*durable_outbox_database_admission\s*:\s*northstar_runtime\s*::\s*durable_outbox\s*::\s*DurableOutboxDatabaseAdmission\s*,?$/m.test(
    stateOutboxAdmission,
  ) ||
  /^\s*pub(?:\(crate\))?\s+durable_outbox_database_admission\s*:/m.test(stateOutboxAdmission)
) {
  throw new Error('ServerNode must privately own the shared durable-outbox database admission');
}
if (
  !/let\s+durable_outbox_database_admission\s*=\s*northstar_runtime\s*::\s*durable_outbox\s*::\s*DurableOutboxDatabaseAdmission\s*::\s*for_primary_pool\s*\(\s*config\s*\.\s*database_max_connections\s*,?\s*\)/s.test(
    state,
  ) ||
  !/PubSubService\s*::\s*new_with_durable_outbox_database_admission[\s\S]*?durable_outbox_database_admission\s*\.\s*clone\s*\(\s*\)/.test(
    state,
  ) ||
  !/MixService\s*::\s*new_with_outbox_database_admission[\s\S]*?durable_outbox_database_admission\s*\.\s*clone\s*\(\s*\)/.test(
    state,
  )
) {
  throw new Error('ServerNode must inject one durable-outbox admission into PubSub and MIX services');
}

// The only code that can hold this private owned permit is a reviewed service
// method below. Every awaited operation in such a method is either a short
// repository turn, another local admission lock, or one explicitly reviewed
// authority/enqueue turn that has no peer/socket I/O; this structurally
// excludes transport/federation delivery from the permit lifetime.
const mixOutboxDbMethods = new Map([
  ['reconcile_expired_remote_pam', 'reconcile_expired_remote_pam'],
  ['claim_pam_results', 'claim_pam_results'],
  ['renew_pam_result_lease', 'renew_pam_result_lease'],
  ['acknowledge_pam_result', 'acknowledge_pam_result'],
  ['defer_pam_result', 'defer_pam_result'],
  ['retry_pam_result', 'retry_pam_result'],
  ['prune_expired_pam_results', 'prune_expired_pam_results'],
  ['outbox_find_enabled_user', 'find_enabled_user'],
  ['outbox_is_blocked', 'is_blocked'],
  ['outbox_archive_mix_message_once', 'archive_mix_message_once'],
  ['outbox_archive_mix_message_once_observed', 'archive_mix_message_once_observed'],
  [
    'outbox_admit_federated_stanza',
    {
      description: 'FederationOutboxAdmission::admit durable outbox admission',
      callPattern:
        /\bfederation\s*\.\s*admit\s*\(\s*target_domain\s*,\s*stanza\s*\)\s*\.\s*await\b/,
      awaitPattern:
        /\bfederation\s*\.\s*admit\s*\(\s*target_domain\s*,\s*stanza\s*\)/,
    },
  ],
  ['claim_mix_deliveries', 'claim_mix_deliveries'],
  ['claim_mix_deliveries_observed', 'claim_mix_deliveries_observed'],
  ['maintain_mix_delivery_retention', 'maintain_mix_delivery_retention'],
  ['prune_expired_business_intents', 'prune_expired_business_intents'],
  ['prune_expired_federated_iq_results', 'prune_expired_federated_iq_results'],
  ['acknowledge_mix_delivery_inner', 'acknowledge_mix_delivery'],
  ['fence_mix_socket_write', 'fence_mix_socket_write'],
  ['transfer_mix_delivery_to_cluster', 'transfer_mix_delivery_to_cluster'],
  ['release_mix_cluster_delivery', 'release_mix_cluster_delivery'],
  ['transfer_mix_delivery_to_bosh', 'transfer_mix_delivery_to_bosh'],
  ['renew_mix_delivery_lease', 'renew_mix_delivery_lease'],
  ['renew_mix_delivery_lease_observed', 'renew_mix_delivery_lease_observed'],
  ['settle_mix_delivery_observed', 'settle_mix_delivery_observed'],
  ['dead_letter_mix_delivery', 'dead_letter_mix_delivery'],
  ['retry_mix_delivery', 'retry_mix_delivery'],
  ['defer_mix_delivery', 'defer_mix_delivery'],
  ['wake_mix_delivery_recipient', 'wake_mix_delivery_recipient'],
  ['mix_delivery_dead_letters', 'mix_delivery_dead_letters'],
  ['requeue_mix_delivery_dead_letter', 'requeue_mix_delivery_dead_letter'],
]);
function reviewedPermitManifestDetails(requiredMethods, observedOwners) {
  const unexpected = [...observedOwners.keys()]
    .filter((name) => !requiredMethods.has(name))
    .sort();
  const missing = [...requiredMethods.keys()]
    .filter((name) => !observedOwners.has(name))
    .sort();
  const repeated = [...observedOwners]
    .filter(([, count]) => count !== 1)
    .map(([name]) => name)
    .sort();
  return { unexpected, missing, repeated };
}

// A missing reviewed owner is a hard failure, not an invitation to expand the
// permit allowlist. Keep this small negative regression adjacent to the same
// helper used for the production source scan.
const permitManifestNegativeFixture = reviewedPermitManifestDetails(
  new Map([['required_turn', 'repository_turn']]),
  new Map(),
);
if (permitManifestNegativeFixture.missing.join(',') !== 'required_turn') {
  throw new Error('MIX outbox permit manifest self-test did not reject a missing reviewed owner');
}

const mixServiceFunctions = asyncFunctionSpans(mixServiceProduction, 'crates/contexts/room/northstar-room-application/src/mix_service.rs');
const mixOutboxDbPermitOwners = new Map();
const mixOutboxDbPermitCallPattern = /self\s*\.\s*outbox_db_admission_guard\s*\(\s*\)\s*\.\s*await/g;
for (let match; (match = mixOutboxDbPermitCallPattern.exec(mixServiceProduction)) !== null; ) {
  const owner = mixServiceFunctions.find(
    ({ opening, closing }) => opening < match.index && match.index < closing,
  );
  if (!owner) {
    let offset = match.index;
    for (const part of readModuleParts('crates/contexts/room/northstar-room-application/src/mix_service.rs', { root, includeTests: false })) {
      if (offset <= part.source.length) {
        const line = countMatches(part.source.slice(0, offset), /\n/g) + 1;
        throw new Error(`${part.path}:${line} acquires an outbox DB permit outside a service method`);
      }
      offset -= part.source.length + 1;
    }
  }
  mixOutboxDbPermitOwners.set(owner.name, (mixOutboxDbPermitOwners.get(owner.name) ?? 0) + 1);
}
const {
  unexpected: unexpectedMixOutboxDbPermitOwners,
  missing: missingMixOutboxDbPermitOwners,
  repeated: repeatedMixOutboxDbPermitOwners,
} = reviewedPermitManifestDetails(mixOutboxDbMethods, mixOutboxDbPermitOwners);
if (
  unexpectedMixOutboxDbPermitOwners.length > 0 ||
  missingMixOutboxDbPermitOwners.length > 0 ||
  repeatedMixOutboxDbPermitOwners.length > 0
) {
  const details = [];
  if (unexpectedMixOutboxDbPermitOwners.length > 0) {
    details.push(`unreviewed permit owners: ${unexpectedMixOutboxDbPermitOwners.join(', ')}`);
  }
  if (missingMixOutboxDbPermitOwners.length > 0) {
    details.push(`outbox methods without a permit: ${missingMixOutboxDbPermitOwners.join(', ')}`);
  }
  if (repeatedMixOutboxDbPermitOwners.length > 0) {
    details.push(`methods taking more than one permit: ${repeatedMixOutboxDbPermitOwners.join(', ')}`);
  }
  throw new Error(`MIX outbox DB admission manifest mismatch; ${details.join('; ')}`);
}
for (const [serviceMethod, repositoryMethod] of mixOutboxDbMethods) {
  const owner = mixServiceFunctions.find(({ name }) => name === serviceMethod);
  if (!owner) throw new Error(`missing MIX outbox DB service method ${serviceMethod}`);
  const body = functionBody(mixServiceProduction, owner);
  const reviewedTurn =
    typeof repositoryMethod === 'string'
      ? {
          description: `${repositoryMethod} repository turn`,
          callPattern: new RegExp(`self\\s*\\.\\s*repository\\s*\\.\\s*${repositoryMethod}\\s*\\(`),
          awaitPattern: new RegExp(`self\\s*\\.\\s*repository\\s*\\.\\s*${repositoryMethod}\\s*\\(`),
        }
      : repositoryMethod;
  if (!reviewedTurn.callPattern.test(body)) {
    throw new Error(
      `MIX outbox DB service method ${serviceMethod} must make its reviewed ${reviewedTurn.description}`,
    );
  }
  const awaitPattern = /\.\s*await\b/g;
  for (let awaited; (awaited = awaitPattern.exec(body)) !== null; ) {
    const statement = statementBeforeAwait(body, awaited.index);
    if (
      !/self\s*\.\s*outbox_db_admission_guard\s*\(\s*\)/.test(statement) &&
      !/self\s*\.\s*delivery_admission_guard\s*\(\s*\)/.test(statement) &&
      !/self\s*\.\s*pam_capacity_admission_guard\s*\(\s*\)/.test(statement) &&
      !reviewedTurn.awaitPattern.test(statement)
    ) {
      throw new Error(
        `MIX outbox DB service method ${serviceMethod} awaits unreviewed work while its DB permit may be held`,
      );
    }
  }
}
const channelStanzaDatabaseLane = structBody(
  mixProtocolProduction,
  'enum ChannelStanzaDatabaseLane',
);
for (const lane of ['LiveIngress', 'DurableOutbox']) {
  if (!new RegExp(`^\\s*${lane}\\s*,?\\s*$`, 'm').test(channelStanzaDatabaseLane)) {
    throw new Error(`MIX channel stanza database lanes must retain ${lane}`);
  }
}
const mixAdapterSource = readProductionModule('crates/contexts/room/northstar-room-postgres/src/mix_repository.rs', { root });
for (const [serviceMethod] of mixProducerMappings) {
  const adapter = structBody(mixAdapterSource, `async fn ${serviceMethod}(`);
  if (!adapter.includes(`crate::mix::${serviceMethod}(`)) {
    throw new Error(`MIX producer adapter ${serviceMethod} lost its reviewed atomic repository operation`);
  }
}

const mixRepositoryTransactionEntries = [
  'requeue_mix_delivery_dead_letter',
  'destroy_mix_channel',
  'join_mix_channel',
  'expire_unrefreshed_mix_presence',
  'update_mix_subscriptions',
  'set_mix_nick',
  'leave_mix_channel',
  'store_mix_presence_with_policy',
  'store_mix_message_inner',
  'publish_mix_avatar',
  'retract_mix_avatar',
  'update_mix_info',
  'update_mix_config',
  'set_mix_access_entry',
  'register_mix_nick',
  'update_mix_participant_preference',
  'retract_mix_message',
];
// whole production module (the file and its non-test child files)
const mixRepositorySource = readProductionModule('crates/contexts/room/northstar-room-postgres/src/mix.rs', { root });
const mixRepositoryProduction = productionWithoutCfgTestModules(
  mixRepositorySource,
  'crates/contexts/room/northstar-room-postgres/src/mix.rs',
);
const mixRepositoryFunctions = asyncFunctionSpans(mixRepositoryProduction, 'crates/contexts/room/northstar-room-postgres/src/mix.rs');
const actualMixRepositoryEntries = [];
const mixAdmissionPattern = /begin_mix_delivery_admission\(pool\)\.await\?/g;
for (let match; (match = mixAdmissionPattern.exec(mixRepositoryProduction)) !== null; ) {
  const owner = mixRepositoryFunctions.find(
    ({ opening, closing }) => opening < match.index && match.index < closing,
  );
  if (!owner) {
    const line = countMatches(mixRepositoryProduction.slice(0, match.index), /\n/g) + 1;
    throw new Error(
      `crates/contexts/room/northstar-room-postgres/src/mix.rs:${line} acquires the MIX delivery fence outside a parseable async function`,
    );
  }
  actualMixRepositoryEntries.push(owner.name);
}

const explicitMixRepositoryEntrySet = new Set(mixRepositoryTransactionEntries);
if (explicitMixRepositoryEntrySet.size !== mixRepositoryTransactionEntries.length) {
  throw new Error('MIX repository producer manifest contains duplicate entries');
}
const actualMixRepositoryEntrySet = new Set(actualMixRepositoryEntries);
const unlistedMixRepositoryEntries = [...actualMixRepositoryEntrySet]
  .filter((entry) => !explicitMixRepositoryEntrySet.has(entry))
  .sort();
const staleMixRepositoryEntries = [...explicitMixRepositoryEntrySet]
  .filter((entry) => !actualMixRepositoryEntrySet.has(entry))
  .sort();
if (unlistedMixRepositoryEntries.length > 0 || staleMixRepositoryEntries.length > 0) {
  const details = [];
  if (unlistedMixRepositoryEntries.length > 0) {
    details.push(`unlisted fenced producers: ${unlistedMixRepositoryEntries.join(', ')}`);
  }
  if (staleMixRepositoryEntries.length > 0) {
    details.push(`manifest entries without a delivery fence: ${staleMixRepositoryEntries.join(', ')}`);
  }
  throw new Error(`MIX repository producer manifest mismatch; ${details.join('; ')}`);
}

const mappedMixRepositoryEntries = new Set(
  mixProducerMappings.map(([, repositoryEntry]) => repositoryEntry),
);
const repositoryEntriesWithoutServiceMapping = [...explicitMixRepositoryEntrySet]
  .filter((entry) => !mappedMixRepositoryEntries.has(entry))
  .sort();
const serviceMappingsWithoutRepositoryEntry = [...mappedMixRepositoryEntries]
  .filter((entry) => !explicitMixRepositoryEntrySet.has(entry))
  .sort();
if (
  repositoryEntriesWithoutServiceMapping.length > 0 ||
  serviceMappingsWithoutRepositoryEntry.length > 0
) {
  const details = [];
  if (repositoryEntriesWithoutServiceMapping.length > 0) {
    details.push(
      `repository entries without service mapping: ${repositoryEntriesWithoutServiceMapping.join(', ')}`,
    );
  }
  if (serviceMappingsWithoutRepositoryEntry.length > 0) {
    details.push(
      `service mappings to unknown repository entries: ${serviceMappingsWithoutRepositoryEntry.join(', ')}`,
    );
  }
  throw new Error(`MIX service/repository producer mapping mismatch; ${details.join('; ')}`);
}

if (
  countMatches(
    mixRepositoryProduction,
    /SELECT northstar_mix_pam_operation_insert\(/g,
  ) !== 1
) {
  throw new Error(
    'MIX-PAM journal insertion must have one production capability caller after its durable outbox projection and pass the canonical account identity',
  );
}
if (
  mixRepositoryProduction.includes('pg_try_advisory_xact_lock(hashtextextended(\'mix-pam') ||
  mixRepositoryProduction.includes('INSERT INTO mix_pam_operations') ||
  mixRepositoryProduction.includes('DELETE FROM mix_pam_operations')
) {
  throw new Error(
    'production MIX-PAM code must use blocking owner-held insert/prune capabilities instead of try-lock, COUNT, or direct journal DML',
  );
}

// ARCH-SVC PubSub/PEP vertical slice (2026-08-29): the protocol layer now
// reaches persistence through a private PubSubService capability. Keep the
// reduced aggregate and both extracted-module baselines monotonic.
//
// The former 1,075-reference aggregate conflated authority with domain-model
// matching. Seven command-session references added on 2026-08-30 are all
// AdminCommand state/completion enum/DTO mappings; they did not add a database
// call. Independent ceilings keep that distinction honest. Grouped domain
// imports are expanded per symbol, so these numbers are intentionally not
// arithmetically comparable with the old raw `db::` token count.
//
// ARCH-SVC MIX vertical slice (2026-08-31): mix.rs no longer names any `db::`
// domain type — its 128 references moved behind MixService-owned DTOs with
// explicit repository mappings, so the aggregate ceiling drops by exactly 128
// and the per-file MIX budget is zero.
const MAX_PROTOCOL_DB_AUTHORITY_REFERENCES = 0;
const MAX_PROTOCOL_DB_DOMAIN_REFERENCES = 7;
const MAX_MIX_DB_DOMAIN_REFERENCES = 0;
const MAX_PUBSUB_DB_DOMAIN_REFERENCES = 0;
const MAX_PEP_DB_DOMAIN_REFERENCES = 0;
const MAX_MESSAGING_DB_DOMAIN_REFERENCES = 0;
const MAX_DISCOVERY_DB_DOMAIN_REFERENCES = 7;
if (protocolDbAuthorityReferences > MAX_PROTOCOL_DB_AUTHORITY_REFERENCES) {
  throw new Error(
    `protocol-layer db authority budget regressed: ${protocolDbAuthorityReferences} > ${MAX_PROTOCOL_DB_AUTHORITY_REFERENCES}`,
  );
}
if (protocolDbDomainReferences > MAX_PROTOCOL_DB_DOMAIN_REFERENCES) {
  throw new Error(
    `protocol-layer db domain-model coupling regressed: ${protocolDbDomainReferences} > ${MAX_PROTOCOL_DB_DOMAIN_REFERENCES}`,
  );
}
if (
  protocolStatePoolReferences !== 0 ||
  protocolSqlxReferences !== 0 ||
  protocolPgPoolReferences !== 0
) {
  throw new Error(
    `production protocol regained a raw PostgreSQL capability: ` +
      `state.pool=${protocolStatePoolReferences}, sqlx::=${protocolSqlxReferences}, ` +
      `PgPool=${protocolPgPoolReferences}`,
  );
}
if (mix.domainReferences > MAX_MIX_DB_DOMAIN_REFERENCES) {
  throw new Error(
    `mix.rs db domain-model coupling regressed: ${mix.domainReferences} > ${MAX_MIX_DB_DOMAIN_REFERENCES}`,
  );
}
const pubsub = perFile.find(({ name }) => name === 'pubsub.rs');
const pep = perFile.find(({ name }) => name === 'pep.rs');
const messaging = perFile.find(({ name }) => name === 'messaging.rs');
const discovery = perFile.find(({ name }) => name === 'discovery.rs');
// `perFile` intentionally contains only modules with at least one direct
// repository reference.  Treat an absent entry as the desired zero rather
// than making complete extraction fail the monotonic architecture gate.
const pubsubDbDomainReferences = pubsub?.domainReferences ?? 0;
const pepDbDomainReferences = pep?.domainReferences ?? 0;
const messagingDbDomainReferences = messaging?.domainReferences ?? 0;
const discoveryDbDomainReferences = discovery?.domainReferences ?? 0;
if (pubsubDbDomainReferences > MAX_PUBSUB_DB_DOMAIN_REFERENCES) {
  throw new Error(
    `pubsub.rs db domain-model coupling regressed: ${pubsubDbDomainReferences} > ${MAX_PUBSUB_DB_DOMAIN_REFERENCES}`,
  );
}
if (pepDbDomainReferences > MAX_PEP_DB_DOMAIN_REFERENCES) {
  throw new Error(
    `pep.rs db domain-model coupling regressed: ${pepDbDomainReferences} > ${MAX_PEP_DB_DOMAIN_REFERENCES}`,
  );
}
if (messagingDbDomainReferences > MAX_MESSAGING_DB_DOMAIN_REFERENCES) {
  throw new Error(
    `messaging.rs db domain-model coupling regressed: ${messagingDbDomainReferences} > ${MAX_MESSAGING_DB_DOMAIN_REFERENCES}`,
  );
}
if (discoveryDbDomainReferences > MAX_DISCOVERY_DB_DOMAIN_REFERENCES) {
  throw new Error(
    `discovery.rs db domain-model coupling regressed: ${discoveryDbDomainReferences} > ${MAX_DISCOVERY_DB_DOMAIN_REFERENCES}`,
  );
}

// ARCH-SVC PubSub/PEP semantic boundary: a zero authority count is necessary
// but not sufficient. Raw SQL or a locally wrapped PgPool would bypass the
// `db::function` classifier, so reject every persistence-capability spelling
// from these protocol modules. Alias and glob escapes are rejected above by
// classifyDbDependencies. Each module is read with its non-test child files.
for (const [name, serviceAccessor, source] of [
  ['pubsub.rs', 'pubsub_application_service',
    readProductionModule('crates/contexts/pubsub/northstar-pubsub-xmpp/src/pubsub.rs', { root })],
  ['pep.rs', 'pubsub_application_service', protocolModuleSource('pep.rs')],
  ['mix.rs', 'mix_service', readProductionModule('crates/contexts/room/northstar-mix-xmpp/src/lib.rs', { root })],
  ['mam.rs', 'mam_service', protocolModuleSource('mam.rs')],
  ['privacy.rs', 'privacy_service', protocolModuleSource('privacy.rs')],
  ['private.rs', 'private_storage_service', protocolModuleSource('private.rs')],
  ['replay.rs', 'replay_service', readProductionModule('crates/edges/northstar-stream/src/replay.rs', { root })],
  ['roster.rs', 'roster_service', protocolModuleSource('roster.rs')],
  ['vcard.rs', 'profile_service', protocolModuleSource('vcard.rs')],
]) {
  const dependency = classifyDbDependencies(source, name);
  if (dependency.authorityReferences !== 0) {
    throw new Error(`${name} must have exactly zero direct db authority references`);
  }
  for (const [description, pattern] of [
    ['ServerNode pool access', /\bstate\s*\.\s*pool\b/],
    ['a PostgreSQL pool type', /\b(?:sqlx\s*::\s*)?PgPool\b/],
    ['raw SQL execution', /\bsqlx\s*::/],
  ]) {
    if (pattern.test(source)) {
      throw new Error(`${name} bypasses its application service through ${description}`);
    }
  }
  if (name === 'replay.rs') {
    if (!/\bReplayService\s*</.test(source) || /\bServerNode\b/.test(source)) {
      throw new Error('replay.rs must receive a narrow ReplayService handle');
    }
    for (const caller of ['presence.rs', 'sasl2.rs', 'sm.rs']) {
      if (!/\.replay_service\s*\(\s*\)/.test(readProtocolSource(caller))) {
        throw new Error(`${caller} no longer obtains the replay service for deferred work`);
      }
    }
  } else if (!new RegExp(`\\.${serviceAccessor}\\s*\\(\\s*\\)`).test(source)) {
    throw new Error(`${name} no longer routes persistence through ${serviceAccessor}()`);
  }
}

const rosterServiceSource = read('crates/contexts/roster/northstar-roster-application/src/service.rs');
const rosterServiceBody = structBody(rosterServiceSource, 'pub struct RosterService');
if (!/^\s*repository\s*:\s*R\s*,?\s*$/m.test(rosterServiceBody)) {
  throw new Error('RosterService must receive its repository port');
}
for (const invariant of [
  'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY',
  'expected_auth_generation',
]) {
  if (!rosterServiceSource.includes(invariant) && !readProductionModule('crates/contexts/roster/northstar-roster-postgres/src/roster.rs', { root }).includes(invariant)) {
    throw new Error(`RosterService lost safety invariant: ${invariant}`);
  }
}

const replayServiceSource = read('crates/contexts/session/northstar-session-application/src/replay.rs');
const replayServiceBody = structBody(replayServiceSource, 'pub struct ReplayService');
if (!/^\s*repository\s*:\s*R\s*,?\s*$/m.test(replayServiceBody)) {
  throw new Error('ReplayService must receive its repository port');
}
const replayAdapterBody = structBody(
  read('crates/contexts/session/northstar-session-postgres/src/replay_repository.rs'), 'pub struct PostgresReplayRepository',
);
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(replayAdapterBody)) {
  throw new Error('Replay repository PostgreSQL capability must remain private');
}
const replayMigration = read('migrations/0103_offline_replay_leases.sql');
if (/\bpublic\s*\./i.test(replayMigration)) {
  throw new Error('offline replay lease migration must remain search_path/schema safe');
}
for (const invariant of [
  'CREATE TABLE offline_replay_leases',
  'recipient_id UUID PRIMARY KEY',
  'owner_token UUID NOT NULL UNIQUE',
  "expires_at >= renewed_at + INTERVAL '75 seconds'",
]) {
  if (!replayMigration.includes(invariant)) {
    throw new Error(`offline replay lease migration lost invariant: ${invariant}`);
  }
}
const replayResourceMigration = read('migrations/0122_offline_replay_resource_leases.sql');
if (/\bpublic\s*\./i.test(replayResourceMigration)) {
  throw new Error('resource-scoped replay migration must remain search_path/schema safe');
}
for (const invariant of [
  'ADD COLUMN resource VARCHAR(1023) NOT NULL',
  'PRIMARY KEY (recipient_id, resource)',
  'BEFORE UPDATE OF recipient_id, resource',
  'fence_offline_replay_lease_identity',
]) {
  if (!replayResourceMigration.includes(invariant)) {
    throw new Error(`resource-scoped replay migration lost invariant: ${invariant}`);
  }
}
const replayDbSource = readProductionModule('crates/contexts/session/northstar-session-postgres/src/replay.rs', { root }).replace(/\s+/g, ' ');
for (const invariant of [
  'OfflineReplayLeaseAcquire',
  'Some("40001")',
]) {
  if (!replayDbSource.includes(invariant)) {
    throw new Error(`offline replay database boundary lost invariant: ${invariant}`);
  }
}
const sasl2Source = readProductionModule('crates/edges/northstar-stream/src/protocol/sasl2.rs', { root });
// ARCH-SVC authentication vertical slice: protocol code owns SASL wire state
// only. The repository owns PostgreSQL and FAST authority; the service owns
// dummy-SCRAM derivation. A successful identity is structurally
// incapable of carrying password or SCRAM verifier fields.
const authenticationServiceSource = read('crates/contexts/auth/northstar-auth-application/src/authentication.rs');
const authenticationServiceBody = structBody(
  authenticationServiceSource,
  'pub struct AuthenticationService',
);
if (!/^\s*repository\s*:\s*R\s*,?\s*$/m.test(authenticationServiceBody)) {
  throw new Error('AuthenticationService must receive its repository port');
}
const authenticationAdapterBody = structBody(
  read('crates/contexts/auth/northstar-auth-postgres/src/authentication.rs'), 'pub struct PostgresAuthenticationRepository',
);
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(authenticationAdapterBody)) {
  throw new Error('Authentication repository PostgreSQL capability must remain private');
}
if (!/^\s*fast_token_secret\s*:\s*Arc<Zeroizing<Vec<u8>>>\s*,?\s*$/m.test(authenticationAdapterBody)) {
  throw new Error('Authentication repository FAST key must remain private Arc<Zeroizing<Vec<u8>>>');
}
if (!/^\s*dummy_scram_secret\s*:\s*Arc<Zeroizing<Vec<u8>>>\s*,?\s*$/m.test(authenticationServiceBody)) {
  throw new Error('AuthenticationService dummy SCRAM key must remain private Arc<Zeroizing<Vec<u8>>>');
}
if (/^\s*pub(?:\(crate\))?\s+(?:pool|fast_token_secret|dummy_scram_secret)\s*:/m.test(authenticationServiceBody)) {
  throw new Error('AuthenticationService exposed a PostgreSQL or authentication-key capability');
}
const authenticatedAccountBody = structBody(
  authenticationServiceSource,
  'pub struct AuthenticatedAccount',
);
for (const forbidden of [
  'password_hash',
  'scram_iterations',
  'scram_sha1_iterations',
  'stored_key',
  'server_key',
  'salt',
]) {
  if (new RegExp(`\\b${forbidden}\\b`).test(authenticatedAccountBody)) {
    throw new Error(`AuthenticatedAccount regained credential field ${forbidden}`);
  }
}
const legacyAuthProtocolSource = readRoleSplitFile('crates/edges/northstar-stream/src/protocol.rs', { root });
const protocolSessionBody = structBody(legacyAuthProtocolSource, 'pub struct ProtocolSession');
if (!/^\s*host\s*:\s*Arc<H>\s*,?\s*$/m.test(protocolSessionBody)) {
  throw new Error('ProtocolSession must keep its host private to its protocol implementation');
}
const smRuntimePolicyBody = structBody(legacyAuthProtocolSource, 'struct SmRuntimePolicy');
if (/\b(?:ServerNode|Arc)\b/.test(smRuntimePolicyBody)
    || !/\bsession\s*:\s*SmSessionPolicy\b/.test(smRuntimePolicyBody)
    || !/\bbuffer\s*:\s*SmBufferLimits\b/.test(smRuntimePolicyBody)
    || !/\bip_binding\s*:\s*String\b/.test(smRuntimePolicyBody)
    || !/\bsm_runtime_policy\s*:\s*SmRuntimePolicy\b/.test(protocolSessionBody)) {
  throw new Error('ProtocolSession SM safety policy must be a narrow owned snapshot');
}
const nativeTransportSource = read('crates/edges/northstar-c2s/src/lib.rs');
const backpressureGuard = structBody(nativeTransportSource, 'struct BackpressureDisconnectMetric');
if (/\bServerNode\b/.test(backpressureGuard)
    || !/\btelemetry\s*:\s*C2sBackpressureTelemetry\b/.test(backpressureGuard)) {
  throw new Error('TCP/WebSocket backpressure guard must hold only narrow telemetry');
}
const nativeTransportPolicy = structBody(nativeTransportSource, 'struct NativeTransportPolicy');
if (/\b(?:ServerNode|Arc)\b/.test(nativeTransportPolicy)
    || !/\bsm_lease_poll_interval\s*:\s*Duration\b/.test(nativeTransportPolicy)
    || !/\bbackpressure_telemetry\s*:\s*C2sBackpressureTelemetry\b/.test(nativeTransportPolicy)) {
  throw new Error('TCP/WebSocket transport policy must contain only immutable cadence and typed telemetry');
}
const driveIoDeclaration = nativeTransportSource.slice(
  nativeTransportSource.indexOf('async fn drive_io<S, P>'),
  nativeTransportSource.indexOf('async fn drive_io<S, P>') + 400,
);
if (!/transport_policy\s*:\s*&NativeTransportPolicy/.test(driveIoDeclaration)
    || /\bstate\s*:|\bServerNode\b/.test(driveIoDeclaration)
    || /\bstate\s*\./.test(structBody(nativeTransportSource, 'async fn drive_io<S, P>'))) {
  throw new Error('TCP transport loop must use NativeTransportPolicy, not global state');
}
for (const connection of [
  'async fn xmpps_tcp_connection',
  'async fn tcp_connection',
  'pub async fn websocket_connection',
]) {
  const body = structBody(nativeTransportSource, connection);
  const opening = 'let mut session = host.open_session(';
  const sessionCreated = body.indexOf(opening);
  if (sessionCreated < 0
      || /\bServerNode\b/.test(body)
      || /\bhost\s*\./.test(body.slice(sessionCreated + opening.length))) {
    throw new Error(`${connection} retains its host after opening the protocol session`);
  }
}
if (!/authenticated\s*:\s*\r?\n?\s*Option<northstar_auth_application::authentication::AuthenticatedAccount>/.test(legacyAuthProtocolSource)) {
  throw new Error('ProtocolSession must retain only the least-authority AuthenticatedAccount DTO');
}
for (const [name, source] of [
  ['protocol.rs', legacyAuthProtocolSource],
  ['sasl2.rs', sasl2Source],
]) {
  for (const authority of [
    'get_scram_credentials',
    'authenticate',
    'find_user',
    'find_user_by_id',
    'auth_generation_is_current',
    'archive_boundaries_visible',
    'authenticate_fast_token',
    'commit_fast_state_with_login_epoch',
  ]) {
    if (new RegExp(`\\bdb::${authority}\\s*\\(`).test(source)) {
      throw new Error(`${name} bypasses AuthenticationService via db::${authority}`);
    }
  }
  if (!/\.authentication_service\s*\(\s*\)/.test(source)) {
    throw new Error(`${name} no longer delegates authentication authority to AuthenticationService`);
  }
}
if (/\bstate\s*\.\s*pool\b/.test(sasl2Source)) {
  throw new Error('sasl2.rs regained direct ServerNode PostgreSQL authority');
}
const accountServiceSource = read('crates/contexts/auth/northstar-auth-application/src/account.rs');
const registrationAccountBody = structBody(
  accountServiceSource,
  'pub struct RegistrationAccount',
);
if (/(?:\bpassword_hash\b|\bscram_[A-Za-z0-9_]*|\bauth_generation\b|\bis_admin\b)/.test(registrationAccountBody)) {
  throw new Error('AccountService RegistrationAccount regained credential or authority fields');
}
const authCorePasswordSource = read('crates/contexts/auth/northstar-auth-core/src/password.rs');
const usersSource = readProductionModule('crates/contexts/auth/northstar-auth-postgres/src/users.rs', { root });
if (!/impl\s+std::fmt::Debug\s+for\s+PasswordCredentials\b/.test(authCorePasswordSource)
    || !/impl\s+std::fmt::Debug\s+for\s+PreparedLogin\b/.test(usersSource)) {
  throw new Error('credential containers require explicitly redacted Debug implementations');
}

// Federated MUC remains a large orchestration module with unrelated cluster
// transactions, so it cannot yet satisfy the whole-file PgPool prohibition
// above. Its MAM slice must nevertheless use the same authorized snapshot
// service as local XEP-0313: no room lookup, affiliation check, boundary read,
// cursor validation or archive page may be composed directly in the protocol
// handler. These checks apply to the whole production module (the file and its
// non-test child files).
const federatedMucSource = readProductionModule('crates/contexts/room/northstar-muc-xmpp/src/federated_muc.rs', { root });
if (!/\.execute_federated_mam_metadata\s*\(/.test(federatedMucSource)
  || !/self\s*\.archive\s*\.mam_service\s*\(\s*\)\s*\.execute_federated_mam_metadata\s*\(/.test(read('src/node/hosts/muc.rs'))) {
  throw new Error('federated_muc.rs no longer routes MAM authority through mam_service()');
}
const federatedIqHandler = rustItemBody(federatedMucSource, 'async fn federated_muc_iq_owned(');
const federatedMetadataCall = federatedIqHandler.indexOf('.execute_federated_mam_metadata(command)');
const federatedActorCheck = federatedIqHandler.indexOf('authenticated_remote_actor(authenticated_domain, from)');
const federatedBareActor = federatedIqHandler.indexOf('let actor_bare_jid = northstar_xmpp_types::jid::canonical_bare_key(&actor_full_jid)?;');
const federatedMetadataCommand = federatedIqHandler.indexOf('FederatedMamMetadataCommand::from_authenticated_actor(');
if (federatedMetadataCall < 0
  || federatedActorCheck < 0
  || federatedBareActor <= federatedActorCheck
  || federatedMetadataCommand <= federatedBareActor
  || federatedMetadataCall <= federatedMetadataCommand
  || !/room\.localpart\.clone\(\),\s*authenticated_domain,\s*&actor_full_jid,\s*joined,/.test(
    federatedIqHandler.slice(federatedMetadataCommand, federatedMetadataCall))
  || federatedIqHandler.includes('.authorized_federated_room_boundaries(')) {
  throw new Error('federated MAM metadata must use an authenticated actor and typed archive command');
}
const mamServiceSource = read('crates/contexts/archive/northstar-archive-application/src/service.rs');
const mamServiceBody = structBody(mamServiceSource, 'pub struct MamService');
if (!/^\s*repository\s*:\s*R\s*,?\s*$/m.test(mamServiceBody)) {
  throw new Error('MamService must receive its repository port');
}
// mix_muc.rs receives the MIX service from its callers instead of ServerNode.
for (const [name, accessor, forbiddenAuthority, route, path] of [
  ['mix_muc.rs', 'MixService', 'link_mix_muc_by_localpart', /\bmix\s*:\s*&MixService<R>[^]*?\bmix\s*\.\s*link_local_muc_mirror\s*\(/, 'crates/contexts/room/northstar-room-application/src/mix_muc.rs'],
  ['presence.rs', 'presence_service()', 'claim_admin_service_messages', /\.presence_service\s*\(\s*\)/],
  ['presence.rs', 'presence_service()', 'complete_admin_service_message_claim', /\.presence_service\s*\(\s*\)/],
  ['upload.rs', 'UploadSessionHost', 'create_upload_slot_bounded', /\.reserve_upload_slot\s*\(/],
  ['upload_session_host.rs', 'upload_service()', 'create_upload_slot_bounded', /\.upload_service\s*\(\s*\)/, 'src/node/hosts/upload_session.rs'],
]) {
  const production = productionWithoutCfgTestModules(
    path ? read(path) : readProtocolSource(name),
    `${name} production`,
  );
  if (new RegExp(`\\b(?:db|northstar_upload_postgres)\\s*::\\s*${forbiddenAuthority}\\b`).test(production)) {
    throw new Error(`${name} bypasses ${accessor} via db::${forbiddenAuthority}`);
  }
  if (!route.test(production)) {
    throw new Error(`${name} no longer routes persistence through ${accessor}`);
  }
}

const uploadServiceSource = read('crates/contexts/upload/northstar-upload-application/src/service.rs');
const uploadServiceBody = structBody(uploadServiceSource, 'pub struct UploadService');
if (!/^\s*repository\s*:\s*R\s*,?\s*$/m.test(uploadServiceBody)) {
  throw new Error('UploadService must receive its repository port');
}
for (const [name, source] of [
  ['RosterService', rosterServiceSource],
  ['UploadService', uploadServiceSource],
  ['PasskeyService', read('crates/contexts/auth/northstar-auth-application/src/passkeys.rs')],
  ['MessageService', read('crates/contexts/message/northstar-message-application/src/messaging.rs')],
  ['MamService', mamServiceSource],
  ['MucService', readProductionModule('crates/contexts/room/northstar-room-application/src/muc_service.rs', { root })],
  ['ProfileService', read('crates/contexts/pubsub/northstar-pubsub-application/src/profile.rs')],
  ['PubSubService', readProductionModule('crates/contexts/pubsub/northstar-pubsub-application/src/service.rs', { root })],
  ['BlockingService', read('crates/contexts/roster/northstar-roster-application/src/blocking.rs')],
  ['PrivacyService', read('crates/contexts/roster/northstar-roster-application/src/privacy.rs')],
  ['PresenceService', read('crates/contexts/roster/northstar-roster-application/src/presence.rs')],
  ['ReplayService', read('crates/contexts/session/northstar-session-application/src/replay.rs')],
  ['AccountService', accountServiceSource],
  ['AdminCommandService', read('crates/contexts/operations/northstar-operations-application/src/admin_commands.rs')],
  ['AuthenticationService', authenticationServiceSource],
  ['RetractionService', read('crates/contexts/message/northstar-message-application/src/retractions.rs')],
  ['SmService', read('crates/contexts/session/northstar-session-application/src/sm.rs')],
  ['MixService', mixServiceSource],
  ['PushService', read('crates/contexts/message/northstar-message-application/src/push.rs')],
  ['PrivateStorageService', read('crates/contexts/pubsub/northstar-pubsub-application/src/private_storage.rs')],
  ['RetentionContext', read('crates/contexts/operations/northstar-operations-application/src/retention_worker.rs')],
  ['SubscriptionCleanupContext', read('crates/contexts/pubsub/northstar-pubsub-application/src/subscription_cleanup.rs')],
  ['UploadMaintenanceContext', read('crates/contexts/upload/northstar-upload-application/src/worker.rs')],
  ['UploadMaintenanceRepository', read('crates/contexts/upload/northstar-upload-application/src/maintenance.rs')],
  ['CapacityMaintenanceService', read('crates/contexts/session/northstar-session-application/src/capacity_maintenance.rs')],
  ['CapacityMaintenanceContexts', read('crates/edges/northstar-stream/src/capacity_maintenance.rs')],
  ['CapacityMaintenanceWorkers', read('crates/edges/northstar-stream/src/capacity_maintenance.rs')],
  ['SmSuspensionContext', read('crates/edges/northstar-stream/src/session_cleanup/suspension.rs')],
  ['SmSuspensionRepository', read('crates/contexts/session/northstar-session-application/src/sm_suspension.rs')],
  ['ApiQueryService', read('crates/contexts/operations/northstar-operations-application/src/api_queries.rs')],
  ['ApiQueryContext', read('crates/edges/northstar-http/src/contexts/api_queries.rs')],
  ['HTTP entry and public discovery policies', read('crates/edges/northstar-http/src/contexts/http_policy.rs')],
  ['API mutation values', read('crates/contexts/operations/northstar-operations-core/src/api_mutations.rs')],
  ['ReportService', read('crates/contexts/operations/northstar-operations-application/src/reports.rs')],
  ['ReportContext', read('crates/edges/northstar-http/src/contexts/reports.rs')],
  ['AccountAdminServices', read('crates/contexts/auth/northstar-auth-application/src/account_admin.rs')],
  ['AccountAdminRuntime', read('crates/edges/northstar-stream/src/local_routes/admin_sessions.rs')],
  ['RegistrationAvailability', read('crates/contexts/auth/northstar-auth-application/src/registration_availability.rs')],
  ['OperationAdminService', read('crates/contexts/operations/northstar-operations-application/src/operations.rs')],
  ['AdminDispatchService', read('crates/contexts/operations/northstar-operations-application/src/admin_dispatch.rs')],
  ['GovernanceService', read('crates/contexts/operations/northstar-operations-application/src/governance.rs')],
  ['GovernanceContext', read('crates/edges/northstar-http/src/contexts/governance.rs')],
  ['MetricsSnapshotService', read('crates/contexts/operations/northstar-operations-application/src/metrics_snapshot.rs')],
  ['FederationOutboxService', read('crates/contexts/federation/northstar-federation-application/src/outbox.rs')],
  ['TlsContext', readProductionModule('crates/platform/northstar-security/src/tls.rs', { root })],
  ['UploadAdminService', read('crates/contexts/operations/northstar-operations-application/src/upload_admin.rs')],
  ['ReportModerationService', read('crates/contexts/operations/northstar-operations-application/src/report_moderation.rs')],
  ['InvitationAdminService', read('crates/contexts/auth/northstar-auth-application/src/invitation_admin.rs')],
  ['RetentionPolicyService', read('crates/contexts/operations/northstar-operations-application/src/retention_policy.rs')],
  ['RetentionPolicyContext', read('crates/edges/northstar-http/src/contexts/retention_policy.rs')],
  ['OmemoRecoveryService', read('crates/contexts/auth/northstar-auth-application/src/omemo_recovery.rs')],
  ['OmemoRecoveryPollContext', read('crates/edges/northstar-http/src/contexts/omemo_poll.rs')],
]) {
  const production = productionWithoutCfgTestModules(source, name);
  for (const [label, pattern] of [
    ['SQLx', /\bsqlx\s*::/],
    ['database pools', /\bPgPool\b/],
    ['concrete database adapters', /\bdb\b/],
    ['global state', /\bServerNode\b/],
  ]) {
    if (pattern.test(production)) throw new Error(`${name} regained ${label} authority`);
  }
}
for (const [path, name] of [
  ['crates/edges/northstar-http/src/operations.rs', 'list_operations'], ['crates/edges/northstar-http/src/operations.rs', 'get_operation'],
  ['crates/edges/northstar-http/src/operations.rs', 'list_targets'], ['crates/edges/northstar-http/src/operations.rs', 'get_target'],
  ['crates/edges/northstar-http/src/admin.rs', 'admin_stats'], ['crates/edges/northstar-http/src/admin.rs', 'admin_users'],
  ['crates/edges/northstar-http/src/admin.rs', 'admin_reports'], ['crates/edges/northstar-http/src/admin.rs', 'admin_invitations'],
  ['crates/edges/northstar-http/src/admin.rs', 'admin_sessions'], ['crates/edges/northstar-http/src/admin.rs', 'admin_offline_messages_stats'],
  ['crates/edges/northstar-http/src/admin.rs', 'admin_muc_rooms'], ['crates/edges/northstar-http/src/users.rs', 'history'],
  ['crates/edges/northstar-http/src/reports.rs', 'my_reports'], ['crates/edges/northstar-http/src/upload_admin.rs', 'admin_upload_dead_letters'],
]) {
  const body = structBody(read(path), `pub async fn ${name}<R: HttpRepositories>(`);
  const signature = read(path).slice(read(path).indexOf(`pub async fn ${name}<R: HttpRepositories>(`)).split(') ->')[0];
  if (!signature.includes('State<crate::contexts::ApiQueryContext<R>>')) {
    throw new Error(`${name} must receive the narrow REST query context`);
  }

  if (/\b(?:sqlx|db)\s*::|\.pool\b|begin_authorized_read/.test(body) || !body.includes('.api_query_service()')) {
    throw new Error(`${name} must use a complete authorized query port`);
  }
}
const adminSessionRoute = structBody(read('crates/edges/northstar-http/src/admin.rs'), 'pub async fn admin_sessions<R: HttpRepositories>(');
if (/\b(?:sort_unstable_by_key|retain|truncate)\b/.test(adminSessionRoute)) {
  throw new Error('administrator session page selection must belong to the application service');
}
if (/begin_authorized_read/.test(readRoleSplitFile('crates/edges/northstar-http/src/lib.rs', { root }))) {
  throw new Error('HTTP principals must not expose database read transactions');
}
const suspensionRecoverySource = productionWithoutCfgTestModules(
  read('crates/edges/northstar-stream/src/session_cleanup/recovery.rs'),
  'SM suspension recovery',
);
if (!suspensionRecoverySource.includes('SmSuspensionContext<R, C>') || /\bServerNode\b/.test(suspensionRecoverySource)) {
  throw new Error('SM suspension recovery must retain its narrow context');
}
for (const [path, names, context] of [
  ['crates/edges/northstar-http/src/operations.rs', ['cancel_operation', 'reconcile_operation', 'reconcile_target'], 'contexts::OperationAdminContext'],
  ['crates/edges/northstar-http/src/admin.rs', ['admin_update_report', 'admin_update_appeal'], 'contexts::ReportModerationContext'],
  ['crates/edges/northstar-http/src/admin.rs', ['admin_update_user', 'admin_clear_offline_messages'], 'contexts::AccountAdminContext'],
  ['crates/edges/northstar-http/src/admin.rs', ['admin_toggle_registration'], 'contexts::RegistrationAdminContext'],
  ['crates/edges/northstar-http/src/admin.rs', ['admin_kick_session'], 'contexts::SessionAdminContext'],
  ['crates/edges/northstar-http/src/upload_admin.rs', ['admin_retry_upload_dead_letter'], 'contexts::UploadAdminContext'],
  ['crates/edges/northstar-http/src/admin.rs', ['admin_create_invitation', 'admin_revoke_invitation'], 'contexts::InvitationAdminContext'],
  ['crates/edges/northstar-http/src/admin.rs', ['admin_tls_reload', 'admin_panic_disconnect', 'admin_toggle_island_mode', 'admin_destroy_muc_room', 'admin_broadcast'], 'contexts::AdminDispatchContext'],
  ['crates/edges/northstar-http/src/data_lifecycle.rs', ['get_my_retention', 'update_my_retention', 'get_muc_retention', 'update_muc_retention'], 'contexts::RetentionPolicyContext'],
]) {
  const source = read(path);
  for (const name of names) {
    const body = structBody(source, `pub async fn ${name}<R: HttpRepositories>(`);
    const signature = source.slice(source.indexOf(`pub async fn ${name}<R: HttpRepositories>(`)).split(') ->')[0];
    if (!signature.includes(`State<crate::${context}<R>>`) || /\b(?:sqlx|db|ServerNode)\b|\.pool\b/.test(body)) {
      throw new Error(`${name} must retain its command service and narrow context`);
    }
  }
}
const governanceApiSource = read('crates/edges/northstar-http/src/data_lifecycle.rs');
for (const name of ['list_legal_holds', 'create_legal_hold', 'release_legal_hold', 'export_legal_hold', 'export_audit']) {
  const body = structBody(governanceApiSource, `pub async fn ${name}<R: HttpRepositories>(`);
  const signature = governanceApiSource.slice(governanceApiSource.indexOf(`pub async fn ${name}<R: HttpRepositories>(`)).split(') ->')[0];
  if (!signature.includes('State<GovernanceContext<R>>') || /\b(?:sqlx|db|ServerNode)\b|\.pool\b/.test(body)) {
    throw new Error(`${name} must retain its governance use-case context`);
  }
}
const reportApiSource = productionWithoutCfgTestModules(read('crates/edges/northstar-http/src/reports.rs'), 'Reports HTTP');
for (const forbidden of [/\bdb\s*::/, /\bsqlx\s*::/, /\bPgPool\b/, /\.pool\b/]) {
  if (forbidden.test(reportApiSource)) throw new Error('Reports HTTP regained direct persistence authority');
}
if (!reportApiSource.includes('.report_service()') || /\bServerNode\b/.test(reportApiSource)) {
  throw new Error('Reports HTTP must use its service and narrow context');
}
const recoveryApiSource = productionWithoutCfgTestModules(read('crates/edges/northstar-http/src/omemo_recovery.rs'), 'OMEMO recovery HTTP');
for (const forbidden of [/\bdb\s*::/, /\bsqlx\s*::/, /\bPgPool\b/, /\.pool\b/]) {
  if (forbidden.test(recoveryApiSource)) throw new Error('OMEMO recovery HTTP regained direct persistence authority');
}
const recoveryPollBody = structBody(recoveryApiSource, 'pub async fn poll_omemo_recovery<R: HttpRepositories>(');
if (/\b(?:ServerNode|current_user)\b/.test(recoveryPollBody) || !recoveryPollBody.includes('.poll(')) {
  throw new Error('OMEMO polling must use its isolated completion capability');
}
const passkeyApiSource = productionWithoutCfgTestModules(read('crates/edges/northstar-http/src/passkeys.rs'), 'Passkeys HTTP');
for (const forbidden of [/\bdb\s*::/, /\bsqlx\s*::/, /\bstate\s*\.\s*pool\b/, /\.begin_authorized_read\s*\(/]) {
  if (forbidden.test(passkeyApiSource)) throw new Error('Passkeys HTTP regained direct persistence authority');
}
if (!passkeyApiSource.includes('State<PasskeyAccountHttpContext<R>>')
    || !passkeyApiSource.includes('State<PasskeyStartHttpContext<R>>')
    || !read('crates/edges/northstar-http/src/contexts/passkey_http.rs').includes('Arc<PasskeyService<R>>')) {
  throw new Error('Passkeys HTTP must use scoped application services');
}
const passkeyAccountContext = structBody(
  read('crates/edges/northstar-http/src/contexts/passkey_http.rs'),
  'pub struct PasskeyAccountHttpContext',
);
const passkeyStartContext = structBody(read('crates/edges/northstar-http/src/contexts/passkey_http.rs'), 'pub struct PasskeyStartHttpContext');
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(passkeyStartContext)
    || !/pub\(super\) async fn register_start<R: HttpRepositories>\(\s*State\(state\): State<PasskeyStartHttpContext<R>>/.test(passkeyApiSource)
    || !/pub\(super\) async fn login_start<R: HttpRepositories>\(\s*State\(state\): State<PasskeyStartHttpContext<R>>/.test(passkeyApiSource)) {
  throw new Error('Passkey challenge starts must use scoped abuse and credential authority');
}
const apiSessionHttpContext = structBody(read('crates/edges/northstar-http/src/contexts/api_session_http.rs'), 'pub struct ApiSessionHttpContext');
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(apiSessionHttpContext)
    || !/pub async fn logout<R: HttpRepositories>\(\s*State\(state\): State<ApiSessionHttpContext<R>>/.test(read('crates/edges/northstar-http/src/auth_routes.rs'))) {
  throw new Error('HTTP logout must use only its audited session command');
}
const registrationHttpContext = structBody(read('crates/edges/northstar-http/src/contexts/http_registration_endpoint.rs'), 'pub struct HttpRegistrationEndpointContext');
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(registrationHttpContext)
    || !/pub async fn register<R: HttpRepositories>\(\s*State\(context\): State<HttpRegistrationEndpointContext<R>>/.test(read('crates/edges/northstar-http/src/auth_routes.rs'))) {
  throw new Error('HTTP registration must use scoped account admission authority');
}
const challengeHttpContext = structBody(read('crates/edges/northstar-http/src/contexts/http_challenge_endpoint.rs'), 'pub struct HttpChallengeEndpointContext');
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(challengeHttpContext)
    || !/pub async fn anti_abuse_challenge<R: HttpRepositories>\(\s*State\(context\): State<HttpChallengeEndpointContext<R>>,\s*State\(queries\): State<crate::contexts::ApiQueryContext<R>>/.test(read('crates/edges/northstar-http/src/auth_routes.rs'))) {
  throw new Error('anti-abuse challenge issuance must use scoped HTTP authority');
}
const uploadDeleteContext = structBody(read('crates/edges/northstar-http/src/contexts/upload_http_delete.rs'), 'pub struct UploadHttpDeleteContext');
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(uploadDeleteContext)
    || !/pub async fn upload_delete<R: HttpRepositories>\(\s*State\(state\): State<UploadHttpDeleteContext<R>>,\s*State\(queries\): State<crate::contexts::ApiQueryContext<R>>/.test(read('crates/edges/northstar-http/src/upload.rs'))) {
  throw new Error('upload deletion must use scoped lifecycle and bearer authority');
}
const uploadReplayReadContext = structBody(read('crates/edges/northstar-http/src/contexts/upload_http_read.rs'), 'pub struct UploadHttpReplayReadContext');
const uploadWriteContext = structBody(read('crates/edges/northstar-http/src/contexts/upload_http_write.rs'), 'pub struct UploadHttpWriteContext');
const uploadApiSource = read('crates/edges/northstar-http/src/upload.rs');
if (/\b(?:ServerNode|ClusterManager|PgPool|UploadHttpReadContext)\b/.test(uploadReplayReadContext)
    || /\b(?:ServerNode|ClusterManager|PgPool)\b/.test(uploadWriteContext)
    || !/pub async fn upload_put<R: HttpRepositories>\(\s*State\(state\): State<UploadHttpWriteContext<R>>,\s*State\(replay_read\): State<UploadHttpReplayReadContext>/.test(uploadApiSource)
    || /State<Arc<ServerNode>>/.test(uploadApiSource)) {
  throw new Error('upload PUT and replay readback must use scoped, exact guarded authority');
}
const passwordChangeContext = structBody(read('crates/edges/northstar-http/src/contexts/password_change_http.rs'), 'pub struct PasswordChangeHttpContext');
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(passwordChangeContext)
    || !/pub async fn change_password<R: HttpRepositories>\(\s*State\(state\): State<PasswordChangeHttpContext<R>>/.test(read('crates/edges/northstar-http/src/users.rs'))) {
  throw new Error('password change admission must use scoped HTTP authority');
}
const accountGenerationTeardown = read('crates/contexts/auth/northstar-auth-xmpp/src/account_generation_teardown.rs');
const teardownSequence = structBody(accountGenerationTeardown, 'pub struct AccountGenerationTeardownSequence');
const accountGenerationTeardownAdapter = read('src/node/adapters/account_generation_teardown.rs');
const teardownAdapters = structBody(accountGenerationTeardownAdapter, 'pub(crate) struct AccountGenerationTeardownAdapters');
const accountTeardownRuntime = read('src/node/adapters/account_teardown_runtime.rs');
const fullTeardownContext = structBody(accountTeardownRuntime, 'pub(crate) struct AccountTeardownRuntime');
const accountTeardownFlow = structBody(read('crates/contexts/auth/northstar-auth-application/src/account_teardown.rs'), 'pub async fn disconnect_account(');
const accountTeardownPorts = read('crates/edges/northstar-http/src/contexts/account_teardown.rs');
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(teardownSequence)
    || /\b(?:ServerNode|ClusterManager|PgPool)\b/.test(teardownAdapters)
    || /\b(?:ServerNode|ClusterManager|PgPool)\b/.test(fullTeardownContext)
    || !teardownAdapters.includes('SmTeardownService<PostgresSmTeardownRepository>')
    || !fullTeardownContext.includes('SessionCleanupSmRevoker')
    || !fullTeardownContext.includes('AccountGenerationService<PostgresAccountGenerationRepository>')
    || !/routes\s*\.revoke\(/.test(accountGenerationTeardownAdapter)
    || !/notifier\s*\.send_account_generation_teardown\(/.test(accountGenerationTeardownAdapter)
    || !/self\.ports\s*\.revoke_local_routes\(/.test(accountGenerationTeardown)
    || !/self\.ports\s*\.revoke_durable_sm\(/.test(accountGenerationTeardown)
    || !/self\.ports\s*\.notify_cluster\(/.test(accountGenerationTeardown)
    || !/revoke_durable_sm\(\)\.await[\s\S]+notify_cluster\(\)\.await/.test(accountGenerationTeardown)
    || !/self\.routes\.revoke\([\s\S]+self\.sm\.revoke_user_with_teardown\(user_id\)\.await[\s\S]+self\.generation\.committed_generation\(user_id\)\.await[\s\S]+send_account_generation_teardown\(/.test(accountTeardownRuntime)
    || !/effects\.revoke_local_routes\(user_id, bare_account_jid\);[\s\S]+effects\.revoke_sm_sessions\(user_id\)\.await[\s\S]+effects\.committed_generation\(user_id\)\.await[\s\S]+\.notify_generation_teardown\(bare_account_jid, user_id, generation\)/.test(accountTeardownFlow)
    || !/pub\(super\) async fn remove<R: HttpRepositories>\(\s*State\(teardown\): State<AccountGenerationTeardownContext>/.test(passkeyApiSource)
    || !/pub async fn consume_omemo_recovery<R: HttpRepositories>\(\s*State\(context\): State<OmemoRecoveryHttpContext<R>>,\s*State\(teardown\): State<AccountGenerationTeardownContext>/.test(recoveryApiSource)
    || !/pub async fn change_password<R: HttpRepositories>\(\s*State\(state\): State<PasswordChangeHttpContext<R>>,\s*State\(teardown\): State<AccountTeardownContext>/.test(read('crates/edges/northstar-http/src/users.rs'))
    || /\b(?:ServerNode|ClusterManager|PgPool)\b|crate::node\b/.test(accountTeardownPorts)
    || !accountTeardownPorts.includes('teardown: Arc<dyn AccountSessionTeardown>')
    || !accountTeardownPorts.includes('teardown: Arc<dyn AccountGenerationTeardown>')
    || /State<Arc<ServerNode>>/.test(passkeyApiSource + recoveryApiSource + read('crates/edges/northstar-http/src/users.rs'))) {
  throw new Error('post-commit account teardown must use scoped HTTP contexts and ordered effects');
}
const smTeardownService = read('crates/contexts/session/northstar-session-application/src/sm_teardown.rs');
if (/\b(?:sqlx|PgPool|ServerNode|ClusterManager)\b/.test(smTeardownService.split('#[cfg(test)]')[0])
    || !smTeardownService.includes('render(snapshot).await?;')
    || !smTeardownService.includes('self.repository.finalize(lease).await?')
    || !smTeardownService.includes('batch.pending == 0')
    || !smTeardownService.includes('Duration::from_millis(25)')
    || !/self\.sm\s*\.revoke_before_generation\(/.test(accountGenerationTeardownAdapter)) {
  throw new Error('durable SM generation teardown must retain fenced claims and post-effect finalization');
}
const operationWorkerControl = read('src/node/adapters/operation_worker_control.rs');
const operationWorkerFields = structBody(operationWorkerControl, 'pub(crate) struct OperationWorkerControl');
const operationRuntime = read('crates/contexts/operations/northstar-operations-xmpp/src/operation_runtime.rs');
const operationRuntimeAdapters = read('src/node/adapters/operation_runtime_adapters.rs');
const operationRuntimeFields = structBody(operationRuntime, 'pub struct OperationWorkerRuntime');
const ordinaryRun = structBody(operationRuntime, 'async fn run_one<');
const ordinaryHeartbeat = structBody(operationRuntime, 'async fn lease_heartbeat<');
const ordinaryEffects = structBody(operationRuntime, 'async fn execute_effect(');
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(operationWorkerFields)
    || /\b(?:ServerNode|ClusterManager|PgPool)\b/.test(operationRuntimeFields)
    || /\bServerNode\b/.test(ordinaryRun + ordinaryHeartbeat + ordinaryEffects)
    || !operationWorkerControl.includes('claim_parent_with_targets')
    || !ordinaryRun.includes('.execute_after_commit(')
    || !ordinaryRun.includes('execute_effect(')
    || !ordinaryHeartbeat.includes('.renew_effect_leases(')
    || !operationRuntime.includes('session_effects: &impl OperationSessionEffects')
    || !operationRuntime.includes('control: Arc::new(control)')
    || !operationRuntimeAdapters.includes('RuntimeControl(self.operation_worker_control())')
    || !/pub async fn serve\(\s*runtime: OperationWorkerRuntime/.test(operationRuntime)) {
  throw new Error('ordinary operation claims and effects must retain scoped worker authority');
}
const disabledFactoryReset = structBody(read('crates/edges/northstar-http/src/admin.rs'), 'pub async fn admin_nuke(');
if (!/pub async fn admin_nuke\(\s*_actor: ApiAdmin/.test(read('crates/edges/northstar-http/src/admin.rs'))
    || /Arc<ServerNode>/.test(disabledFactoryReset)) {
  throw new Error('disabled factory reset must authenticate without broad application state');
}
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(passkeyAccountContext)
    || !/pub\(super\) async fn list<R: HttpRepositories>\(\s*State\(state\): State<PasskeyAccountHttpContext<R>>,\s*State\(queries\): State<crate::contexts::ApiQueryContext<R>>/s.test(passkeyApiSource)
    || !/pub\(super\) async fn register_finish<R: HttpRepositories>\(\s*State\(state\): State<PasskeyAccountHttpContext<R>>,\s*State\(queries\): State<crate::contexts::ApiQueryContext<R>>/s.test(passkeyApiSource)) {
  throw new Error('account Passkeys reads and registration completion must use scoped HTTP authority');
}
const omemoRecoveryApi = read('crates/edges/northstar-http/src/omemo_recovery.rs');
const omemoRecoveryContext = structBody(
  read('crates/edges/northstar-http/src/contexts/omemo_recovery_http.rs'),
  'pub struct OmemoRecoveryHttpContext',
);
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(omemoRecoveryContext)) {
  throw new Error('authenticated OMEMO recovery context gained broad application authority');
}
for (const handler of ['prepare_omemo_recovery', 'seal_omemo_recovery', 'get_omemo_recovery',
  'get_omemo_recovery_authority', 'revoke_omemo_recovery']) {
  if (!new RegExp(`pub async fn ${handler}<R: HttpRepositories>\\(\\s*State\\(context\\): State<OmemoRecoveryHttpContext<R>>`, 's').test(omemoRecoveryApi)) {
    throw new Error(`authenticated OMEMO recovery handler ${handler} regained broad state`);
  }
}
// ARCH-SVC local XEP-0045 boundary: protocol code owns XML/session routing,
// while all PostgreSQL reads, mutations and committed-outbox wake authority
// pass through MucService. Inline DB fixtures are structurally masked rather
// than hiding every item after the first cfg(test) marker. These checks apply
// to the whole production module (the file and its non-test child files), so
// code moved into a child file stays covered.
const mucProtocolSource = readProductionModule('crates/contexts/room/northstar-muc-xmpp/src/muc.rs', { root });
const mucProductionSource = productionWithoutCfgTestModules(
  mucProtocolSource,
  'muc.rs production',
);
if (/\b(?:self\.)?(?:state|host)\s*\.\s*cluster\b/.test(mucProductionSource)) {
  throw new Error('MUC protocol handlers must use purpose-specific state operations, not cluster authority');
}
const mucProductionDependencies = classifyDbDependencies(
  mucProductionSource,
  'muc.rs production',
);
if (mucProductionDependencies.authorityReferences !== 0) {
  throw new Error(
    `muc.rs production must have exactly zero direct db authority references, found ${mucProductionDependencies.authorityReferences}`,
  );
}
for (const [description, pattern] of [
  ['ServerNode pool access', /\b(?:self\.)?(?:state|host)\s*\.\s*pool\b/],
  ['a PostgreSQL pool type', /\b(?:sqlx\s*::\s*)?PgPool\b/],
  ['raw SQL execution', /\bsqlx\s*::/],
]) {
  if (pattern.test(mucProductionSource)) {
    throw new Error(`muc.rs production bypasses MucService through ${description}`);
  }
}
if (!/\.muc_service\s*\(\s*\)/.test(mucProductionSource)) {
  throw new Error('muc.rs no longer routes persistence through muc_service()');
}
if (!(/\.wake_committed_operation\s*\(\s*&self\.state\.cluster\s*,/.test(mucProductionSource)
    || /\.wake_committed_muc_operation\s*\(/.test(mucProductionSource))) {
  throw new Error('muc.rs no longer routes committed outbox wakes through MucService');
}
if (/\.wake_committed_muc_operation\s*\(\s*&self\.pool\b/.test(state)) {
  throw new Error('ServerNode runtime paths bypass MucService for committed MUC wakes');
}
if (!/async fn wake_committed_muc_operation\s*\([\s\S]*?self\s*\.room\s*\.muc_service\s*\(\s*\)\s*\.wake_committed_operation\s*\(\s*&self\.cluster\s*,\s*operation_id\s*\)/.test(read('src/node/hosts/muc.rs'))) {
  throw new Error('ServerNode committed MUC wake must delegate to MucService with cluster authority');
}
const operationRuntimeSource = productionWithoutCfgTestModules(
  read('crates/contexts/operations/northstar-operations-xmpp/src/operation_runtime.rs'),
  'operation_runtime.rs production',
);
if (/state\.pool|sqlx::Transaction|db::(?:operation_work_pending|claim_operation_in_tx|enqueue_operation_target_in_tx)\s*\(/.test(operationRuntimeSource)
    || !operationRuntimeSource.includes('.claim_parent_with_targets(')) {
  throw new Error('administrator operation worker must keep its initial claim and target writes behind the journal service');
}
const operationMucDestroyEffectsSource = read('src/node/adapters/operation_muc_destroy_effects.rs');
const committedMucWakeServiceSource = read('crates/contexts/room/northstar-room-application/src/operation_muc_wake.rs');
if (!/muc_destroy_effects\.notify_committed\(operation\.id\)\.await/.test(operationRuntimeSource)
    || !operationMucDestroyEffectsSource.includes('self.wake.notify(&self.publisher, operation_id).await')
    || !committedMucWakeServiceSource.includes('notify_committed_operation(self.repository.descriptor(operation_id), wake, operation_id)')) {
  throw new Error('operation worker must wake committed MUC effects through the typed post-commit port');
}
const mucServiceSource = readProductionModule('crates/contexts/room/northstar-room-application/src/muc_service.rs', { root });
const mucServiceBody = structBody(mucServiceSource, 'pub struct MucService');
if (!/^\s*repository\s*:\s*R\s*,?\s*$/m.test(mucServiceBody)) {
  throw new Error('MucService must receive its repository port');
}
if (!/enabled_local_account[\s\S]*crate::accounts::enabled_user_id/.test(readProductionModule('crates/contexts/room/northstar-room-postgres/src/room.rs', { root }))) {
  throw new Error('MucService no longer fails closed for disabled local routing targets');
}
const discoverySource = read('crates/edges/northstar-stream/src/protocol/discovery.rs');
for (const accessor of ['mix_service', 'muc_service', 'pubsub_service']) {
  if (!new RegExp(`\\.${accessor}\\s*\\(\\s*\\)`).test(discoverySource)) {
    throw new Error(`discovery.rs no longer routes authority through ${accessor}()`);
  }
}

// ARCH-SVC account/push boundary: resource binding remains a deliberately
// separate stateful session transaction, but XEP-0077 and XEP-0357 handlers
// must not regain direct persistence authority.
const miscSource = read('crates/edges/northstar-stream/src/protocol/misc.rs');
for (const authority of [
  'prepare_registration',
  'create_user_with_invitation_guarded_in_tx',
  'change_password_guarded_v2',
  'begin_account_deletion_quiesce_guarded_v2',
  'delete_user_with_roster_audited',
  'enable_push_subscription',
  'disable_push_subscriptions',
  'claim_push_deliveries',
  'complete_push_response',
]) {
  if (new RegExp(`\\b(?:db|northstar_\\w+(?:\\s*::\\s*\\w+)*?)\\s*::\\s*${authority}\\b`).test(miscSource)) {
    throw new Error(`misc.rs bypasses its account/push application service via ${authority}`);
  }
}
for (const accessor of ['account_service', 'push_service']) {
  if (!new RegExp(`\\.${accessor}\\s*\\(\\s*\\)`).test(miscSource)) {
    throw new Error(`misc.rs no longer routes account/push persistence through ${accessor}()`);
  }
}

const registrationHandler = structBody(read('crates/edges/northstar-http/src/auth_routes.rs'), 'pub async fn register<R: HttpRepositories>(');
if (!/\.service\(\)[\s\S]+\.register_http\(HttpRegistrationRequest/.test(registrationHandler)) {
  throw new Error('HTTP registration must enter the account service with a typed command');
}
if (/(?:\bstate\s*\.\s*pool\b|\bdb::(?:acquire_idempotency_in_tx|prepare_registration|create_user_with_invitation_guarded_in_tx_v2)\b|\btransaction\b|\bPgPool\b)/.test(registrationHandler)) {
  throw new Error('HTTP registration regained SQL, transaction or password-work authority');
}

// ARCH-SVC XEP-0050/XEP-0133 administrative boundary: inline DB fixtures
// intentionally remain below `#[cfg(test)]`, but every production command
// must delegate persistence, audit and command lifecycle authority to the
// private AdminCommandService. Keep protocol code limited to form parsing,
// in-memory routing effects and stanza construction.
const commandsSource = readProductionModule('crates/contexts/operations/northstar-operations-xmpp/src/commands.rs', { root });
const commandsProductionSource = productionWithoutCfgTestModules(
  commandsSource,
  'commands.rs production',
);
const commandsProductionDependencies = classifyDbDependencies(
  commandsProductionSource,
  'commands.rs production',
);
if (commandsProductionDependencies.authorityReferences !== 0) {
  throw new Error(
    `commands.rs production must have exactly zero direct db authority references, found ${commandsProductionDependencies.authorityReferences}`,
  );
}
for (const [description, pattern] of [
  ['ServerNode pool access', /\bstate\s*\.\s*pool\b/],
  ['a PostgreSQL pool type', /\b(?:sqlx\s*::\s*)?PgPool\b/],
  ['raw SQL execution', /\bsqlx\s*::/],
]) {
  if (pattern.test(commandsProductionSource)) {
    throw new Error(`commands.rs production bypasses AdminCommandService through ${description}`);
  }
}
if (!/\.command_service\s*\(\s*\)/.test(commandsProductionSource)) {
  throw new Error('commands.rs no longer routes persistence through command_service()');
}
// ARCH-SVC XEP-0424/XEP-0444 boundary: protocol code may parse a retraction
// and map its typed result, but tombstone ownership, replay identity, archive
// writes and the optional S2S outbox share one RetractionService transaction.
// Test fixtures below `#[cfg(test)]` may create isolated rows directly; the
// production handler must never regain a PostgreSQL capability or hide one
// behind an imported/aliased database function.
const retractionsSource = read('crates/contexts/message/northstar-message-xmpp/src/retractions.rs');
const retractionsProductionSource = productionWithoutCfgTestModules(
  retractionsSource,
  'retractions.rs production',
);
const retractionsProductionDependencies = classifyDbDependencies(
  retractionsProductionSource,
  'retractions.rs production',
);
if (retractionsProductionDependencies.authorityReferences !== 0) {
  throw new Error(
    `retractions.rs production must have exactly zero direct db authority references, found ${retractionsProductionDependencies.authorityReferences}`,
  );
}
for (const [description, pattern] of [
  ['ServerNode pool access', /\b(?:self\.)?(?:state|host)\s*\.\s*pool\b/],
  ['a PostgreSQL pool type', /\b(?:sqlx\s*::\s*)?PgPool\b/],
  ['raw SQL execution', /\bsqlx\s*::/],
]) {
  if (pattern.test(retractionsProductionSource)) {
    throw new Error(`retractions.rs production bypasses RetractionService through ${description}`);
  }
}
if (!/\.retraction_service\s*\(\s*\)/.test(retractionsProductionSource)) {
  throw new Error('retractions.rs no longer routes persistence through retraction_service()');
}
const retractionServiceSource = read('crates/contexts/message/northstar-message-application/src/retractions.rs');
const retractionServiceBody = structBody(
  retractionServiceSource,
  'pub struct RetractionService',
);
if (!/^\s*repository\s*:\s*R\s*,?\s*$/m.test(retractionServiceBody)) {
  throw new Error('RetractionService must receive its repository port');
}
const retractionRepositorySource = read('crates/contexts/workflows/northstar-workflows/src/retraction_repository.rs');
const retractionRepositoryBody = structBody(retractionRepositorySource, 'pub struct PostgresRetractionRepository');
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(retractionRepositoryBody)) {
  throw new Error('Retraction repository PostgreSQL capability must remain private');
}
const retractionIntentMigration = read('migrations/0102_personal_retraction_intents.sql');
if (/\bpublic\s*\./i.test(retractionIntentMigration)) {
  throw new Error('retraction intent migration must remain search_path/schema safe');
}
const retractionOwnerIdentityMigration = read(
  'migrations/0119_personal_retraction_owner_identity.sql',
);
if (/\bpublic\s*\./i.test(retractionOwnerIdentityMigration)) {
  throw new Error('retraction owner identity migration must remain search_path/schema safe');
}

// ARCH-SECRET Durable content identity (migration 0104): a personal-message
// or retraction replay tombstone must not become a second plaintext archive.
// Only AbuseGuard may derive purpose-bound subkeys from the mounted,
// rotatable anti-abuse key generations. Each application service receives a
// least-authority keyring for exactly one purpose; protocol handlers and DB
// repositories never receive either the source key or caller-selectable
// purpose authority.
const keyedContentMigration = read('migrations/0104_keyed_content_identity.sql');
if (/\bpublic\s*\./i.test(keyedContentMigration)) {
  throw new Error('keyed content identity migration must remain search_path/schema safe');
}
for (const invariant of [
  'DROP COLUMN payload_value',
  'payload_key_id VARCHAR(16)',
  'payload_mac BYTEA',
  'personal_message_admission_payload_evidence_check',
  'personal_message_admission_payload_key_idx',
  'payload_digest IS NOT NULL',
  'payload_key_id IS NOT NULL',
  'payload_mac IS NOT NULL',
  'semantic_key_id VARCHAR(16)',
  'semantic_mac BYTEA',
  'personal_retraction_intent_semantic_evidence_check',
  'personal_retraction_intent_semantic_key_idx',
  'semantic_sha256 IS NOT NULL',
  'semantic_sha512 IS NOT NULL',
  'semantic_length IS NOT NULL',
  'semantic_key_id IS NOT NULL',
  'semantic_mac IS NOT NULL',
]) {
  if (!keyedContentMigration.includes(invariant)) {
    throw new Error(`keyed content identity migration lost invariant: ${invariant}`);
  }
}
if (/\bADD\s+COLUMN\s+payload_value\b/i.test(keyedContentMigration)) {
  throw new Error('migration 0104 must irreversibly remove, never recreate, plaintext payload_value');
}
const historicalOwnershipFixture = read('scripts/migration-0056-db-wsl.sh');
for (const upgradeEvidence of [
  'payload_value is intentional here: this schema stops at migration 0055',
  'M0056-LEGACY-CONTENT-MARKER',
  '10#$version > 104',
  "column_name='payload_value'",
  '0104 accepted an all-empty personal-message evidence shape',
]) {
  if (!historicalOwnershipFixture.includes(upgradeEvidence)) {
    throw new Error(`0056 historical fixture lost its 0104 upgrade proof: ${upgradeEvidence}`);
  }
}
// reads the whole module including test-only child files
const archiveRepositorySource = `${readModule('tools/northstar-db-it/src/archive.rs', { root })}\n${readModule('crates/contexts/message/northstar-message-postgres/src/personal_history.rs', { root })}\n${readModule('crates/contexts/workflows/northstar-workflows/src/personal_history.rs', { root })}\n${read('crates/contexts/workflows/northstar-workflows/src/mam_room.rs')}\n${read('crates/contexts/workflows/northstar-workflows/src/mix_archive.rs')}`;
if (/\bpayload_value\b/.test(archiveRepositorySource)) {
  throw new Error('archive repository must not read, bind, or persist plaintext admission payload_value');
}
const personalHistoryIdentityBody = structBody(
  archiveRepositorySource,
  'pub struct PersonalHistoryIdentity',
);
if (/^\s*(?:pub\s+)?payload\s*:/m.test(personalHistoryIdentityBody)) {
  throw new Error('PersonalHistoryIdentity must carry authenticators, never plaintext payload');
}
const personalAdmissionInserts = [...archiveRepositorySource.matchAll(
  /INSERT\s+INTO\s+personal_message_admissions\s*\(([^)]*)\)/gsi,
)];
if (personalAdmissionInserts.length !== 1) {
  throw new Error(`archive repository must have one reviewed personal admission insert, found ${personalAdmissionInserts.length}`);
}
const personalAdmissionInsertColumns = personalAdmissionInserts[0][1];
for (const keyedColumn of ['payload_key_id', 'payload_mac']) {
  if (!new RegExp(`\\b${keyedColumn}\\b`).test(personalAdmissionInsertColumns)) {
    throw new Error(`new personal admission writes lost keyed column ${keyedColumn}`);
  }
}
if (/\b(?:payload_digest|payload_value)\b/.test(personalAdmissionInsertColumns)) {
  throw new Error('new personal admission writes must never use legacy/plaintext evidence columns');
}

const abuseSource = readProductionModule('crates/contexts/abuse/northstar-abuse-application/src/guard.rs', { root });
const abuseProductionSource = productionWithoutCfgTestModules(abuseSource, 'abuse.rs production');
if (/\bpub\s+async\s+fn\s+accept_message_admission\s*\(/.test(abuseProductionSource)) {
  throw new Error('message admission acceptance must remain behind its issued service/repository fence');
}
const contentIdentitySource = readProductionModule('crates/contexts/abuse/northstar-abuse-policy/src/content_identity.rs', { root });
for (const typeName of [
  'PersonalMessageContentKeyring',
  'PersonalRetractionContentKeyring',
]) {
  const body = structBody(contentIdentitySource, `pub struct ${typeName}`);
  if (/^\s*pub(?:\(crate\))?\s+(?:generations|keys|secret)\s*:/m.test(body)) {
    throw new Error(`${typeName} exposed its derived content key material`);
  }
}
const contentGenerationBody = structBody(abuseSource, 'fn content_identity_generations(');
if (!/\bpersistent_actor_key_candidates\s*\(\s*\)/.test(contentGenerationBody)) {
  throw new Error('durable content keys must derive only from authorized anti-abuse generations');
}
if (/\bapi_control\b|ApiControlKeyring/.test(contentGenerationBody)) {
  throw new Error('API control secrets must never be reused for durable content identity');
}
// The abuse context owns the purpose selector; its callers must not name it.
const sourceFilesNamingContentPurpose = [];
for (const directory of ['tools/northstar-test-harness/tests/saved_replay', 'crates/edges/northstar-stream/src/protocol', 'tools/northstar-db-it/src', 'crates/contexts']) {
  const pending = [path.join(root, directory)];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(full);
      else if (entry.isFile() && entry.name.endsWith('.rs')) {
        const relative = path.relative(root, full).replaceAll('\\', '/');
        if (relative.startsWith('crates/contexts/abuse/')) continue;
        const source = fs.readFileSync(full, 'utf8');
        if (/\bContentIdentityPurpose\b/.test(source)) {
          sourceFilesNamingContentPurpose.push(relative);
        }
      }
    }
  }
}
if (sourceFilesNamingContentPurpose.length > 0) {
  throw new Error(
    `application/DB/protocol code regained caller-selectable content purpose: ${sourceFilesNamingContentPurpose.join(', ')}`,
  );
}
const keyedMessageRepositorySource = read('crates/contexts/workflows/northstar-workflows/src/message_repository.rs');
for (const [serviceName, body, expectedKeyring] of [
  ['PostgresMessageRepository', structBody(keyedMessageRepositorySource, 'pub struct PostgresMessageRepository'), 'PersonalMessageContentKeyring'],
  ['RetractionService', retractionServiceBody, 'PersonalRetractionContentKeyring'],
]) {
  if (!new RegExp(`^\\s*content_identity\\s*:\\s*${expectedKeyring}\\s*,?\\s*$`, 'm').test(body)) {
    throw new Error(`${serviceName} must privately own only ${expectedKeyring}`);
  }
  if (/^\s*pub(?:\(crate\))?\s+content_identity\s*:/m.test(body)) {
    throw new Error(`${serviceName} exposed its content identity capability`);
  }
}
const keyedProtocolSource = protocolFiles
  .map((name) => readProtocolSource(name))
  .join('\n');
if (/\b(?:PersonalMessageContentKeyring|PersonalRetractionContentKeyring)\b/.test(keyedProtocolSource)) {
  throw new Error('protocol tree must not receive durable content-key capabilities');
}
const retractionProductionSource = productionWithoutCfgTestModules(
  retractionRepositorySource,
  'retractions repository production',
);
const retractionIntentInserts = [...retractionProductionSource.matchAll(
  /INSERT\s+INTO\s+personal_retraction_intents\s*\(([^)]*)\)/gsi,
)];
if (retractionIntentInserts.length !== 1) {
  throw new Error(`Retraction repository must have one reviewed intent insert, found ${retractionIntentInserts.length}`);
}
const retractionIntentInsertColumns = retractionIntentInserts[0][1];
if (/\b(?:semantic_sha256|semantic_sha512|semantic_length)\b/.test(retractionIntentInsertColumns)) {
  throw new Error('new retraction intent writes must never use legacy semantic evidence columns');
}

// ARCH-SVC runtime secret boundary. Protocol modules may request semantic
// operations from services/ServerNode methods, but must never name or traverse
// long-lived configuration material directly.
const protocolSource = protocolFiles
  .map((name) => readProtocolSource(name))
  .join('\n');
for (const credentialAccessor of [
  'component_authentication_credential',
  'component_connect_credentials',
]) {
  if (new RegExp(`\\b${credentialAccessor}\\s*\\(`).test(protocolSource)) {
    throw new Error(`protocol tree bypasses component transport boundary via ${credentialAccessor}`);
  }
}
for (const field of [
  'bootstrap_admin_password',
  'turn_shared_secret',
  'dialback_secret',
  'fast_token_secret',
  'dummy_scram_secret',
  'abuse_state_hmac_key',
  'abuse_state_hmac_previous_key',
  'redis_url',
  'metrics_bearer_token',
  'cluster_security',
  'database_url',
]) {
  const directField = new RegExp(
    `\\b(?:state\\s*\\.\\s*)?config(?:\\s*\\.\\s*raw)?\\s*\\.\\s*${field}\\b|` +
      `\\bstate\\s*\\.\\s*${field}\\b`,
  );
  if (directField.test(protocolSource)) {
    throw new Error(`protocol tree directly references runtime secret field ${field}`);
  }
}

const extdiscoProtocol = read('crates/contexts/message/northstar-message-xmpp/src/extdisco.rs');
if (!/\.extdisco_service\s*\(\s*\)/.test(extdiscoProtocol)) {
  throw new Error('extdisco.rs no longer delegates TURN credential authority to ExtDiscoService');
}
const extdiscoService = read('crates/contexts/message/northstar-message-application/src/extdisco.rs');
const extdiscoInner = structBody(extdiscoService, 'struct ExtDiscoInner');
if (!/^\s*turn_shared_secret\s*:\s*Option<Zeroizing<Vec<u8>>>\s*,/m.test(extdiscoInner)) {
  throw new Error('ExtDiscoService TURN key must remain a private Zeroizing byte buffer');
}
if (/^\s*pub(?:\(crate\))?\s+turn_shared_secret\s*:/m.test(extdiscoInner)) {
  throw new Error('ExtDiscoService exposed its long-lived TURN key');
}

const messageServiceSource = read('crates/contexts/message/northstar-message-application/src/messaging.rs');
const localRecipient = structBody(messageServiceSource, 'pub struct LocalRecipient');
for (const credentialField of [
  'password_hash',
  'scram_iterations',
  'scram_sha1_iterations',
  'auth_generation',
]) {
  if (new RegExp(`\\b${credentialField}\\b`).test(localRecipient)) {
    throw new Error(`LocalRecipient leaks authentication field ${credentialField}`);
  }
}
// XEP-0115 federated presence is observed by independent authenticated S2S
// tasks. Its ordering must come from one exact full-JID lifecycle authority,
// not TTLs, retries, or a cache-size heuristic. Keep acquisition in the
// inbound presence scope so ordinary presence routing and Caps/PEP effects
// commit in the same chosen cross-stream order. Participant RAII makes a
// waiter cancellation remove the registry entry without a background sweep.
const capsProtocolSource =
  read('crates/contexts/session/northstar-protocol-runtime/src/caps.rs') +
  read('crates/edges/northstar-stream/src/protocol/caps.rs') +
  read('crates/edges/northstar-stream/src/caps_effects.rs');
const s2sInboundSource = readProductionModule('crates/edges/northstar-s2s/src/inbound.rs', { root })
  + readProductionModule('crates/contexts/roster/northstar-roster-xmpp/src/federated_presence.rs', { root })
  + readProductionModule('crates/contexts/message/northstar-message-xmpp/src/federated_message.rs', { root });
if (/(?:db|northstar_message_postgres::\w+|northstar_workflows::\w+)::(?:store_offline_for_recipient|admit_personal_history)\s*\(/.test(s2sInboundSource)
    || !s2sInboundSource.includes('.store_offline(OfflineMessageAdmission {')
    || !s2sInboundSource.includes('.admit_history(&writes)')) {
  throw new Error('inbound S2S personal storage must use the message service');
}
const s2sOutboundSource = readProductionModule('crates/edges/northstar-s2s/src/outbound.rs', { root });
const componentsSource = readProductionModule('crates/edges/northstar-s2s/src/components.rs', { root });
const federationCoreSource = read('crates/contexts/federation/northstar-federation-core/src/lib.rs');
const federationComponents = read('crates/contexts/federation/northstar-federation-application/src/components.rs');
if (!federationCoreSource.includes('pub fn classify_hosted_domain(')
    || !federationCoreSource.includes('pub const fn accepts_s2s_stream_target(')
    || !federationComponents.includes('classify_hosted_domain(local_domain, target)')
    || !s2sInboundSource.includes('classify_hosted_domain(local_domain, target)')
    || !s2sInboundSource.includes('classify_hosted_domain(configured_domain, candidate)')
    || !s2sInboundSource.includes('HostedDomain::accepts_s2s_stream_target')) {
  throw new Error('component routes and S2S identity/stream admission must share the hosted-domain policy');
}
for (const invariant of [
  'struct FederatedCapsGateSlot',
  'struct FederatedCapsParticipant',
  'observation_id: uuid::Uuid',
  'pub async fn federated_caps_connection_closed',
]) {
  if (!capsProtocolSource.includes(invariant)) {
    throw new Error(`federated Caps lifecycle lost cancellation-safe invariant: ${invariant}`);
  }
}
for (const invariant of [
  'let federated_presence_epoch = if matches!(kind, "available" | "unavailable")',
  'Some(state.federated_caps_gates().lock(&full_jid).await)',
  'if let Some(resource_epoch) = federated_presence_epoch.as_ref()',
]) {
  if (!s2sInboundSource.includes(invariant)) {
    throw new Error(`S2S presence lost its federated Caps ordering proof: ${invariant}`);
  }
}
if (!/observe_federated_caps\(\s*state,\s*root,\s*from,\s*connection_id,\s*resource_epoch/s.test(s2sInboundSource)) {
  throw new Error('S2S Caps observation is no longer bound to the authenticated connection UUID');
}
for (const [name, source] of [
  ['inbound S2S', s2sInboundSource],
  ['outbound S2S', s2sOutboundSource],
  ['external component', componentsSource],
]) {
  if (!source.includes('federated_caps_connection_closed')) {
    throw new Error(`${name} teardown no longer retires exact connection-owned Caps observations`);
  }
}
if (/observe_federated_caps[\s\S]{0,500}federated_caps_gates\(\)\.lock/.test(capsProtocolSource)) {
  throw new Error('federated Caps gate must cover final presence routing, not be reacquired inside the observer');
}

// The observation table, not a periodic poll or bounded hint queue, owns
// pending work. Saturation requests a no-lost-wakeup reconstruction, while
// retry and IQ-correlation expiry use the exact earliest deadline.
if (/interval\s*\(\s*CAPS_EFFECT_RETRY_BASE\s*\)/.test(capsProtocolSource)) {
  throw new Error('Caps retry correctness regressed to fixed periodic reconstruction');
}
if (/\.take\(128\)/.test(capsProtocolSource + protocolModuleSource('pep.rs')
  + readProductionModule('crates/contexts/pubsub/northstar-pubsub-xmpp/src/pep.rs', { root }))) {
  throw new Error('Caps/PEP fan-out silently truncates a verified notify summary');
}
if (countMatches(capsProtocolSource, /self\.entries\.insert\(\s*full_jid,/g) < 2) {
  throw new Error('local and federated Caps observations must use atomic single-key replacement');
}
const commitCapsObservationWrapper = structBody(
  capsProtocolSource,
  'pub fn commit_caps_observation(',
);
if (
  commitCapsObservationWrapper.replace(/\s+/g, '').replace(/,\)/g, ')') !==
    'self.commit_caps_observation_for(presence,full_jid,self.connection_id,&self.presence.mix_presence_gate,&self.presence.caps_observation_generation);'
) {
  throw new Error('ordinary Caps observation must forward its exact connection, gate and generation');
}
const commitCapsObservation = structBody(
  capsProtocolSource,
  'fn commit_caps_observation_for(',
);
const localObservationInsert = commitCapsObservation.indexOf('.observe_local(');
const unavailableLocalRemoval = commitCapsObservation.lastIndexOf(
  '.remove_local_resource(&full_jid, connection)',
  localObservationInsert,
);
const unavailableBranch = commitCapsObservation.indexOf('if presence');
if (
  localObservationInsert < 0 ||
  unavailableLocalRemoval < unavailableBranch ||
  unavailableLocalRemoval > localObservationInsert
) {
  throw new Error('local available Caps replacement regained a remove-before-insert visibility gap');
}

// Responsibility documentation is part of the architecture boundary. Keep
// the exact long-lived task identities and domain-service accessors synchronized
// with the composition root so a renamed or newly introduced authority cannot
// become invisible to review merely because aggregate budgets still pass.
function assertExactUniqueInventory(label, actual, expected) {
  const counts = new Map();
  for (const item of actual) counts.set(item, (counts.get(item) ?? 0) + 1);
  const duplicates = [...counts].filter(([, count]) => count !== 1).map(([item]) => item);
  const missing = expected.filter((item) => !counts.has(item));
  const unexpected = [...counts.keys()].filter((item) => !expected.includes(item));
  if (duplicates.length > 0 || missing.length > 0 || unexpected.length > 0) {
    throw new Error(
      `${label} inventory mismatch; duplicate=${duplicates.join(',') || '-'} ` +
        `missing=${missing.join(',') || '-'} unexpected=${unexpected.join(',') || '-'}`,
    );
  }
}

const supervisedWorkerContracts = [
  { name: 'abuse-key-deployment-authority', criticality: 'Critical', mode: 'Continuous', watchdog: 'Some(ABUSE_KEY_AUTHORITY_POLL_INTERVAL.saturating_mul(2))', draining: false },
  { name: 'deployment-capacity-session-leases', criticality: 'Critical', mode: 'Continuous', watchdog: 'Some(capacity_interval.saturating_mul(2))', draining: false },
  { name: 'deployment-capacity-lease-reaper', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(120))', draining: false },
  { name: 'background-maintenance', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(180))', draining: false },
  { name: 'account-deletion-recovery', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(1_200))', draining: false },
  { name: 'upload-storage-reconciliation', criticality: 'Critical', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(600))', draining: false },
  { name: 'archive-retention', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(retention_max_silence)', draining: false },
  { name: 'pubsub-subscription-cleanup', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(northstar_pubsub_application::subscription_cleanup::MAX_SILENCE)', draining: false },
  { name: 'admin-session-cleanup', criticality: 'Critical', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(90))', draining: false },
  { name: 'redis-pubsub', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(45))', draining: false },
  { name: 'account-revocations', criticality: 'Critical', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(10))', draining: false },
  { name: 'cluster-maintenance', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(90))', draining: false },
  { name: 'standalone-muc-occupancy', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(45))', draining: false },
  { name: 'cluster-failure-policy', criticality: 'Critical', mode: 'Continuous', watchdog: 'Some(std::time::Duration::from_secs(15))', draining: false },
  { name: 'cluster-muc-outbox', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(Duration::from_secs(30))', draining: false },
  { name: 'locked-muc-expiry', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(Duration::from_secs(20))', draining: false },
  { name: 'runtime-control-refresh', criticality: 'Critical', mode: 'Continuous', watchdog: 'Some(max_silence)', draining: false },
  { name: 'sm-authority-listener', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(Duration::from_secs(15))', draining: false },
  { name: 'sm-suspension-recovery', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(Duration::from_secs(30))', draining: true },
  { name: 'caps-side-effects', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(Duration::from_secs(60))', draining: true },
  { name: 'mix-iq-relay-expiry', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(Duration::from_secs(10))', draining: false },
  { name: 'mix-delivery-outbox', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(Duration::from_secs(30))', draining: true },
  { name: 'mix-presence-recovery', criticality: 'Restartable', mode: 'OneShot', watchdog: 'Some(Duration::from_secs(90))', draining: false },
  { name: 'pubsub-digest-delivery', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(Duration::from_secs(5))', draining: false },
  { name: 'pubsub-event-outbox-delivery', criticality: 'Restartable', mode: 'Continuous', watchdog: 'Some(Duration::from_secs(30))', draining: false },
];
const supervisedWorkers = supervisedWorkerContracts.map(({ name }) => name);
const workerResponsibilityEvidence = {
  'abuse-key-deployment-authority': ['src/node/workers/abuse.rs', '`state/workers/abuse.rs`', '2 ×'],
  'deployment-capacity-session-leases': ['src/node/workers/session.rs', '`state/workers/session.rs`', '2 ×'],
  'deployment-capacity-lease-reaper': ['src/node/workers/session.rs', '`state/workers/session.rs`', '120 s'],
  'background-maintenance': ['src/node/workers/maintenance.rs', '`state/workers/maintenance.rs`', '180 s'],
  'account-deletion-recovery': ['src/node/workers/maintenance.rs', '`state/workers/maintenance.rs`', '1,200 s'],
  'upload-storage-reconciliation': ['src/node/workers/upload.rs', '`state/workers/upload.rs`', '600 s'],
  'archive-retention': ['src/node/workers/maintenance.rs', '`state/workers/maintenance.rs`', 'derived retention'],
  'pubsub-subscription-cleanup': ['src/node/workers/maintenance.rs', '`state/workers/maintenance.rs`, standalone only', '110 s'],
  'admin-session-cleanup': ['src/node/workers/operations.rs', '`state/workers/operations.rs`', '90 s'],
  'redis-pubsub': ['src/node/workers/cluster.rs', '`state/workers/cluster.rs`, cluster only', '45 s'],
  'account-revocations': ['src/node/workers/cluster.rs', '`state/workers/cluster.rs`, cluster only', '10 s'],
  'cluster-maintenance': ['src/node/workers/cluster.rs', '`state/workers/cluster.rs`, cluster only', '90 s'],
  'standalone-muc-occupancy': ['src/node/workers/cluster.rs', '`state/workers/cluster.rs`, standalone PostgreSQL MUC only', '45 s'],
  'cluster-failure-policy': ['src/node/workers/cluster.rs', '`state/workers/cluster.rs`, cluster only', '15 s'],
  'cluster-muc-outbox': ['crates/edges/northstar-cluster/src/lib.rs', 'unconditionally registered', '30 s'],
  'locked-muc-expiry': ['src/node.rs', '`ServerNode` MUC startup', '20 s'],
  'runtime-control-refresh': ['src/node.rs', 'process startup reserves the connection', '5 s'],
  'sm-authority-listener': ['crates/contexts/workflows/northstar-workflows/src/authority_listener.rs', 'ServerNode database listener startup', '15 s'],
  'sm-suspension-recovery': ['crates/edges/northstar-stream/src/session_cleanup/recovery.rs', 'session-cleanup service startup', '30 s'],
  'caps-side-effects': ['crates/edges/northstar-stream/src/caps_effects.rs', 'Caps subsystem startup', '60 s'],
  'mix-iq-relay-expiry': ['crates/contexts/room/northstar-mix-xmpp/src/lib.rs', 'MIX protocol capability startup', '10 s'],
  'mix-delivery-outbox': ['crates/contexts/room/northstar-mix-xmpp/src/worker.rs', 'MIX capability startup', '30 s'],
  'mix-presence-recovery': ['crates/contexts/room/northstar-mix-xmpp/src/lib.rs', 'MIX capability startup', '90 s'],
  'pubsub-digest-delivery': ['crates/contexts/pubsub/northstar-pubsub-xmpp/src/delivery.rs', 'PubSub capability startup', '5 s'],
  'pubsub-event-outbox-delivery': ['crates/contexts/pubsub/northstar-pubsub-xmpp/src/delivery.rs', 'PubSub capability startup', '30 s'],
};
const workerDocumentBehaviorEvidence = {
  'abuse-key-deployment-authority': ['first returned validation error/timeout'],
  'upload-storage-reconciliation': ['three consecutive DB/provider/backlog reports', 'waiting ticks only pulse'],
  'cluster-maintenance': ['authentication or user-agent login generation'],
  'standalone-muc-occupancy': ['90 s lease deadline', '128-actor batches'],
  'cluster-failure-policy': ['any terminal attempt or silence cancels'],
  'cluster-muc-outbox': ['in every mode', 'single-node PostgreSQL maintenance'],
  'sm-authority-listener': ['5 s liveness tick'],
  'pubsub-subscription-cleanup': ['60 s', '40 s', '1,000', 'delivery'],
};
const productionRustSources = [];
const pendingResponsibilitySources = [path.join(root, 'src'), path.join(root, 'crates')];
while (pendingResponsibilitySources.length > 0) {
  const current = pendingResponsibilitySources.pop();
  for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
    const full = path.join(current, entry.name);
    if (entry.isDirectory()) pendingResponsibilitySources.push(full);
    else if (entry.isFile() && entry.name.endsWith('.rs')) {
      const relative = path.relative(root, full).replaceAll('\\', '/');
      // Test modules (a `tests.rs`/`*_tests.rs` file, every file below a
      // `tests/` module directory, and crate integration tests) compile only
      // under #[cfg(test)] or as test targets. They are not production worker
      // registration sites.
      if (/(?:^|\/)(?:[^/]*_tests|tests)(?:\.rs$|\/)/.test(relative)) continue;
      productionRustSources.push({
        relative,
        source: productionWithoutCfgTestModules(fs.readFileSync(full, 'utf8'), relative),
      });
    }
  }
}
// Maintenance is an independently selected process role. Qualify only that
// reviewed composition root; a duplicate in any other source still fails.
const roleIdentity = (relative, name) => relative === 'src/runtime/subservers.rs' ? `maintenance/${name}` : name;
const composedWorkers = productionRustSources.flatMap(({ relative, source }) =>
  [...source.matchAll(/\.supervise(_draining)?\(\s*"([^"]+)"/g)]
    .map((match) => roleIdentity(relative, match[2])),
);
assertExactUniqueInventory('supervised-worker', composedWorkers, [...supervisedWorkers,
  'maintenance/archive-retention', 'maintenance/pubsub-subscription-cleanup']);
for (const contract of supervisedWorkerContracts) {
  const [expectedSource, documentedOwner, documentedWatchdog] =
    workerResponsibilityEvidence[contract.name] ?? [];
  const sourceEntry = productionRustSources.find(({ relative }) => relative === expectedSource);
  if (!sourceEntry) throw new Error(`missing reviewed worker owner source: ${expectedSource}`);
  const sourceRegistrations = [
    ...sourceEntry.source.matchAll(/\.supervise(_draining)?\(\s*"([^"]+)"/g),
  ].filter((match) => match[2] === contract.name);
  if (sourceRegistrations.length !== 1) {
    throw new Error(
      `worker ${contract.name} must have exactly one registration in ${expectedSource}`,
    );
  }
  const registration = sourceRegistrations[0];
  const nextRegistration = sourceEntry.source.indexOf('.supervise', registration.index + 1);
  const registrationEnd =
    nextRegistration < 0 ? registration.index + 2500 : Math.min(nextRegistration, registration.index + 2500);
  const tail = sourceEntry.source
    .slice(registration.index, registrationEnd)
    .replace(/\s+/g, ' ');
  const expectedCriticality = `WorkerCriticality::${contract.criticality}`;
  const expectedMode = `WorkerMode::${contract.mode}`;
  const expectedWatchdog = contract.watchdog.replace(/\s+/g, ' ');
  if (
    !tail.includes(expectedCriticality) ||
    !tail.includes(expectedMode) ||
    !tail.includes(expectedWatchdog) ||
    Boolean(registration[1]) !== contract.draining
  ) {
    throw new Error(
      `supervised-worker contract drift for ${contract.name}: expected ` +
        `${contract.criticality}/${contract.mode}/${contract.watchdog}/` +
        `${contract.draining ? 'draining' : 'immediate'}`,
    );
  }
  const documentRow = responsibilityDocument
    .split(/\r?\n/)
    .find((line) => line.includes(`| \`${contract.name}\` |`));
  const documentedMode = contract.mode === 'OneShot' ? 'one-shot' : 'continuous';
  if (
    !documentRow ||
    !documentRow.includes(documentedOwner) ||
    !documentRow.includes(documentedWatchdog) ||
    !documentRow.includes(`${contract.criticality.toLowerCase()} / ${documentedMode}`) ||
    (contract.watchdog === 'None' && !documentRow.includes('**none**')) ||
    (contract.draining && !documentRow.toLowerCase().includes('drain')) ||
    (!contract.draining && !documentRow.includes('| immediate |'))
  ) {
    throw new Error(`program responsibility model has stale worker semantics: ${contract.name}`);
  }
  for (const evidence of workerDocumentBehaviorEvidence[contract.name] ?? []) {
    if (!documentRow.includes(evidence)) {
      throw new Error(
        `program responsibility model omits ${contract.name} behavior evidence: ${evidence}`,
      );
    }
  }
}
const healthObservers = productionRustSources.flatMap(({ relative, source }) =>
  [...source.matchAll(/\.register_observer\(\s*"([^"]+)"/g)]
    .map((match) => roleIdentity(relative, match[1])),
);
assertExactUniqueInventory('health-observer', healthObservers,
  ['session-cleanup', 'maintenance/maintenance-ownership']);
const sessionCleanupRow = responsibilityDocument
  .split(/\r?\n/)
  .find((line) => line.includes('| `session-cleanup` |'));
if (
  !sessionCleanupRow ||
  !sessionCleanupRow.includes('**no task/factory**') ||
  !sessionCleanupRow.includes('| none |')
) {
  throw new Error('program responsibility model must identify session-cleanup as a taskless observer');
}
if (
  countMatches(state, /northstar_cluster::start_muc_outbox_delivery\(/g) !== 1 ||
  !cluster.includes('also runs in supported single-node')
) {
  throw new Error('cluster MUC PostgreSQL maintenance must remain unconditionally composed');
}
const clusterMucOutboxWorker = rustItemBody(cluster, 'async fn run_muc_outbox_delivery<A: ClusterAdapters>(');
const clusterMucOutboxContextSource = read('crates/edges/northstar-cluster/src/muc_outbox_worker.rs');
const clusterMucOutboxContext = structBody(
  clusterMucOutboxContextSource,
  'pub struct ClusterMucOutboxWorkerContext',
);
if (!clusterMucOutboxWorker.includes('let housekeeping = &context.housekeeping;')
    || !state.includes('state.cluster_muc_outbox_worker_context()')
    || /\b(?:ServerNode|ClusterManager|PgPool)\b/.test(clusterMucOutboxContext)
    || /(?:crate::db|northstar_room_postgres::cluster_muc)::(?:cleanup_cluster_muc_dead_letters|cleanup_cluster_muc_history|cluster_muc_outbox_snapshot)\s*\(/.test(clusterMucOutboxWorker)) {
  throw new Error('cluster MUC outbox housekeeping must use separate narrow repository operations');
}
const operationRuntimeOwnershipSource = read('crates/contexts/operations/northstar-operations-xmpp/src/operation_runtime.rs');
const mucDestroyServiceSource = read('crates/contexts/operations/northstar-operations-application/src/operation_muc_destroy.rs');
const mucDestroyEffect = structBody(mucDestroyServiceSource, 'pub struct MucDestroyEffect');
if (/\blocal_domain\b/.test(mucDestroyEffect)
    || !mucDestroyServiceSource.includes('jid.domainpart() == format!("conference.{}", self.local_domain)')
    || !state.includes('config.domain.clone(),')) {
  throw new Error('MUC destruction must validate the immutable service-owned local domain');
}
const operationWorkerControlSource = read('src/node/adapters/operation_worker_control.rs');
const operationSessionEffectsSource = read('src/node/adapters/operation_session_effects.rs');
if (!operationWorkerControlSource.replace(/\s+/g, '').includes('routes:northstar_operations_xmpp::operation_runtime::LocalBroadcastRoutes::new(std::sync::Arc::clone(self.session.live().sessions()),self.config.domain.clone(),self.cluster.node_id.clone(),).target_snapshot()')
    || !operationWorkerControlSource.includes('self.routes.target_seeds(operation)')
    || !/control\s*\.claim_parent_with_targets\(worker_id, LEASE_SECONDS\)/.test(operationRuntimeOwnershipSource)
    || !operationRuntimeOwnershipSource.includes('"admin.broadcast" => session_effects.send_broadcast_exact(payload)')
    || !operationSessionEffectsSource.includes('self.broadcast.send_exact(payload)')
    || /fn local_target_seeds\(\s*state:\s*&ServerNode/.test(operationRuntimeOwnershipSource)) {
  throw new Error('administrator broadcast must snapshot and deliver through its exact local-route capability');
}
if (!operationSessionEffectsSource.replace(/\s+/g, '').replace(/,\)/g, ')').includes('kick:northstar_operations_xmpp::operation_runtime::LocalSessionKickRoutes::new(std::sync::Arc::clone(self.session.live().sessions()))')
    || !operationRuntimeOwnershipSource.includes('session_effects.kick_exact(user_id, generation, connection_id)')
    || !operationSessionEffectsSource.includes('.kick_exact(user_id, auth_generation, connection_id)')
    || !operationRuntimeOwnershipSource.includes('session.connection_id == connection_id')
    || !operationRuntimeOwnershipSource.includes('session.auth_generation == auth_generation')) {
  throw new Error('administrator session kick must cancel only the exact committed route incarnation');
}
if (!operationSessionEffectsSource.replace(/\s+/g, '').replace(/,\)/g, ')').includes('generation_cleanup:northstar_operations_xmpp::operation_runtime::LocalGenerationCleanupRoutes::new(std::sync::Arc::clone(self.session.live().sessions()))')
    || !operationRuntimeOwnershipSource.includes('session_effects.cancel_exact_generation(user_id, generation)')
    || !operationSessionEffectsSource.includes('.cancel_exact_generation(user_id, auth_generation)')
    || !operationRuntimeOwnershipSource.includes('session.user_id == user_id && session.auth_generation == auth_generation')) {
  throw new Error('administrator account cleanup must cancel only the exact account generation');
}
const panicDisconnect = structBody(operationRuntimeOwnershipSource, 'async fn panic_disconnect_with<');
const panicEffectsSource = read('src/node/adapters/operation_panic_effects.rs');
const panicEffectsFields = structBody(panicEffectsSource, 'pub(crate) struct OperationPanicEffects');
if (/\b(?:ServerNode|ClusterManager|PgPool)\b/.test(panicEffectsFields)
    || !panicEffectsSource.includes('panic_disconnect_with(&self.routes, || self.sm.revoke_all_with_teardown()).await')
    || !/let disconnected = routes\.cancel_all\(\);\s*teardown\(\)\.await\?;/.test(panicDisconnect)) {
  throw new Error('emergency disconnect must cancel all local routes before durable SM teardown');
}
const loginEndpointSource = read('crates/edges/northstar-http/src/auth_routes.rs');
const loginEndpoint = structBody(loginEndpointSource, 'pub async fn login<R: HttpRepositories>(');
const loginContext = structBody(read('crates/edges/northstar-http/src/contexts/http_login_endpoint.rs'), 'pub struct HttpLoginEndpointContext');
if (!loginEndpointSource.includes('State(context): State<HttpLoginEndpointContext<R>>')
    || /\bstate\.(?:metrics|pool|config)\b/.test(loginEndpoint)
    || /\bServerNode\b|\bMetrics\b|PgPool/.test(loginContext)) {
  throw new Error('REST login must receive only its service, proxy policy and outcome counters');
}
const uploadSource = read('crates/edges/northstar-http/src/upload.rs');
const uploadGet = structBody(uploadSource, 'pub async fn upload_get<R: HttpRepositories>(');
const uploadReadContext = structBody(read('crates/edges/northstar-http/src/contexts/upload_http_read.rs'), 'pub struct UploadHttpReadContext');
if (!uploadSource.includes('State(state): State<UploadHttpReadContext<R>>')
    || !uploadGet.includes('let download_guard = state.acquire_download(client_ip)')
    || !uploadGet.includes('let _download_guard = download_guard;')
    || /\b(?:ServerNode|Metrics|PgPool)\b/.test(uploadReadContext)
    || !read('src/node/hosts/http.rs').includes('admission: self.upload.runtime.download_admission().cloned()')) {
  throw new Error('public upload GET must retain shared download admission and guarded read authority');
}
const capsEffectSource = read('crates/edges/northstar-stream/src/protocol/caps.rs');
const capsDispatchSource = read('crates/edges/northstar-stream/src/caps_effects.rs');
const capsDispatchWorker = capsDispatchSource.slice(capsDispatchSource.indexOf('pub(crate) struct CapsEffectRunGuard'));
if (/\bstate\.metrics\b|\bself\.(?:state|host)\.metrics\b|&(?:(?:northstar_telemetry::)?metrics::)?Metrics\b/.test(capsEffectSource)
    || !capsEffectSource.includes('state.caps_effect_telemetry()')
    || !capsDispatchSource.includes('pub(crate) struct CapsEffectRunGuard')
    || /\bmetrics\b/.test(capsDispatchWorker)
    || !capsDispatchWorker.includes('context.telemetry()')) {
  throw new Error('caps effect dispatch must receive only its admission and completion telemetry');
}
const passkeyFinishSource = read('crates/edges/northstar-http/src/passkeys.rs');
const passkeyFinishContext = structBody(read('crates/edges/northstar-http/src/contexts/passkey_login_finish.rs'), 'pub struct PasskeyLoginFinishContext');
if (!passkeyFinishSource.includes('State(state): State<PasskeyLoginFinishContext<R>>')
    || /\b(?:ServerNode|Metrics|PgPool)\b/.test(passkeyFinishContext)) {
  throw new Error('Passkey login completion must use its narrow service context');
}
const presenceProtocol = protocolModuleSource('presence.rs');
const presenceClusterRouting = read('crates/edges/northstar-cluster/src/presence_routing.rs');
const presenceDelivery = read('crates/contexts/roster/northstar-roster-xmpp/src/presence_delivery.rs');
if (/\bself\.(?:state|host)\s*\.metrics\b/.test(presenceProtocol)
    || /\b(?:self|host)\s*\.\s*metrics\b/.test(presenceDelivery)
    || /\.metrics\b/.test(presenceClusterRouting)
    || !presenceClusterRouting.includes("telemetry: &PresenceProbeTelemetry<'_>")
    || countMatches(presenceClusterRouting, /\btelemetry\.failed\(\)/g) !== 2) {
  throw new Error('cross-node presence replay failures must use their one-counter telemetry port');
}
// reads the whole module including test-only child files
const mucProtocol = readModule('crates/contexts/room/northstar-muc-xmpp/src/muc.rs', { root });
if (/\b(?:self\.)?(?:state|host)\s*\.metrics\b/.test(mucProtocol)
    || !mucProtocol.includes('state.muc_telemetry().post_commit_failure()')) {
  throw new Error('MUC authority and post-commit reporting must use its narrow telemetry port');
}
const mixOutboxContext = read('src/node/adapters/mix_outbox.rs');
const mixOutboxStart = structBody(mixProtocolProduction, 'pub fn start_mix_delivery_outbox(');
if (/\bstate\s*\.metrics\b/.test(mixProtocol)
    || !mixProtocol.includes('context.record_post_commit_failure()')
    || !mixOutboxContext.includes('MixPostCommitTelemetry::new(&self.delivery_failures, &self.post_accept_failures)')
    || !state.includes('Arc::new(state.mix_outbox_context())')
    || /\b(?:Arc<ServerNode>|PgPool|ClusterManager|Arc<Metrics>)\b/.test(mixOutboxContext)
    || /\bArc<ServerNode>\b/.test(mixOutboxStart)
    || !/self\s*\.\s*service\s*\.\s*outbox_lookup_cluster_nodes\s*\(/.test(mixOutboxContext)
    || !/self\s*\.\s*cluster_delivery\s*\.\s*send_mix\s*\(/.test(mixOutboxContext)) {
  throw new Error('MIX post-commit delivery must use its two-counter telemetry port');
}
const accountRecoverySource = read('crates/contexts/auth/northstar-auth-xmpp/src/account_deletion.rs');
const accountRecoveryTelemetry = structBody(accountRecoverySource, 'pub struct AccountDeletionRecoveryTelemetry');
if (/\.metrics\b/.test(accountRecoverySource)
    || /Arc<(?:(?:crate::)?(?:platform::)?metrics::)?Metrics>/.test(accountRecoveryTelemetry)
    || !accountRecoveryTelemetry.includes("success: &'a AtomicU64")
    || !accountRecoveryTelemetry.includes("failure: &'a AtomicU64")
    || !accountRecoveryTelemetry.includes("lease_loss: &'a AtomicU64")
    || countMatches(accountRecoverySource, /context\.telemetry\(\)\.succeeded\(\)/g) !== 1
    || countMatches(accountRecoverySource, /context\.telemetry\(\)\.failed\(\)/g) !== 1
    || countMatches(accountRecoverySource, /context\.telemetry\(\)\.lease_lost\(\)/g) !== 1) {
  throw new Error('account deletion recovery must use its three shared telemetry cells');
}
const readinessEndpointSource = read('crates/edges/northstar-http/src/system.rs');
const metricsEndpoint = structBody(readinessEndpointSource, 'pub struct MetricsEndpointState');
const metricsContextSource = read('crates/edges/northstar-http/src/contexts/metrics.rs');
const metricsContextProduction = productionWithoutCfgTestModules(metricsContextSource, 'metrics context production');
const metricsContext = structBody(metricsContextSource, 'pub struct MetricsContext');
const metricsServe = structBody(readRoleSplitFile('crates/edges/northstar-http/src/lib.rs', { root }), 'pub async fn serve_metrics<');
if (!metricsEndpoint.includes('context: MetricsContext')
    || /Arc<ServerNode>/.test(metricsEndpoint)
    || /\b(?:ServerNode|ClusterManager|TlsContext)\b|Arc<dyn Fn/.test(metricsContext)
    || !metricsContext.includes('cluster: Arc<dyn ClusterMetrics>')
    || !metricsContext.includes('tls: TlsMetricsProbe')
    || !metricsContext.includes('muc_occupant_count: MucOccupancyCountProbe')
    || !metricsContext.includes('sm: Arc<dyn SmRecoveryGauges>')
    || /\bServerNode\b|crate::node\b/.test(metricsContextProduction)
    || !metricsServe.includes('MetricsEndpointState::new(context)')
    || !readinessEndpointSource.includes('context.authorized(peer, metrics_bearer_candidate(headers))')) {
  throw new Error('private metrics endpoint must use a narrow live, read-only observability context');
}
const readinessEndpoint = structBody(readinessEndpointSource, 'pub struct ReadyEndpointState');
const readinessContext = rustItemBody(read('crates/edges/northstar-http/src/contexts/readiness.rs'), 'pub struct ReadinessContext');
if (!readinessEndpoint.includes('context: ReadinessContext')
    || /Arc<ServerNode>|(?:ServerNode|ClusterManager|WorkerRegistry|SmMemoryGovernor|UploadSafetyGate|ConnectionActorRegistry)\b/.test(readinessContext)
    || countMatches(readRoleSplitFile('crates/edges/northstar-http/src/lib.rs', { root }), /ReadyEndpointState::new\(state\.readiness_context\(\)\)/g) !== 2) {
  throw new Error('readiness listeners must receive only a narrow read-only runtime context');
}
const clusterSource = cluster;
const clusterMaintenance = rustItemBody(clusterSource, 'async fn maintenance_once<A: ClusterAdapters>(');
const clusterRedisMaintenance = rustItemBody(clusterSource, 'struct ClusterMaintenanceRedis');
const sessionRouteMaintenanceSource = read('crates/contexts/session/northstar-session-application/src/session_route_maintenance.rs');
const sessionRoutePort = structBody(sessionRouteMaintenanceSource, 'pub trait SessionRouteRenewalPort');
const sessionRouteService = structBody(sessionRouteMaintenanceSource, 'impl<P: SessionRouteRenewalPort> SessionRouteRenewalService<P>');
const sessionRouteRedisAdapter = rustItemBody(clusterSource, 'impl northstar_session_application::session_route_maintenance::SessionRouteRenewalPort');
const sessionRouteRelease = rustItemBody(clusterSource, 'async fn release_session_authority(');
const mucSoftStatePort = structBody(mucServiceSource, 'pub trait MucSoftStateProjectionPort');
const mucSoftStateService = structBody(mucServiceSource, 'impl<P: MucSoftStateProjectionPort> MucSoftStateProjectionService<P>');
const mucRedisAdapter = rustItemBody(clusterSource, 'impl MucSoftStateProjectionPort for &ClusterMaintenanceRedis');
if (/\bstate\.cluster\b/.test(clusterMaintenance)
    || /\b(?:signer|pubsub|publisher|delivery_route)\s*:/.test(clusterRedisMaintenance)
    || !sessionRoutePort.includes('fn renew_authority(')
    || !sessionRoutePort.includes('fn refresh_projection(')
    || !sessionRoutePort.includes('fn release_authority(')
    || !sessionRouteService.includes('.renew_authority(')
    || !sessionRouteService.includes('.refresh_projection(')
    || !sessionRouteService.includes('.release_authority(')
    || !sessionRouteRedisAdapter.includes('self.renew_session_authority(full_jid, connection_id)')
    || !sessionRouteRedisAdapter.includes('self.refresh_session_projection(full_jid, activity_age_seconds, connection_id)')
    || !sessionRouteRedisAdapter.includes('self.release_session_authority(full_jid, connection_id, token)')
    || !sessionRouteRelease.includes('} = token')
    || /self\.instance_epoch\.load\(/.test(sessionRouteRelease)
    || !clusterMaintenance.includes('context.session_routes.renew_all(sessions).await?')
    || /\bredis\s*\.\s*refresh_session\s*\(/.test(clusterMaintenance)
    || !clusterMaintenance.includes('MucSoftStateProjectionService::new(redis)')
    || !/\bsoft_state\s*\.\s*refresh\s*\(/.test(clusterMaintenance)
    || !/\bsoft_state\s*\.\s*reconcile_room\s*\(/.test(clusterMaintenance)
    || /\bredis\s*\.\s*(?:join_muc|register_muc_occupant|reconcile_muc_soft_state)\s*\(/.test(clusterMaintenance)
    || clusterMaintenance.indexOf('for chunk in unrenewed_muc.chunks(')
      > clusterMaintenance.indexOf('MucSoftStateProjectionService::new(redis)')
    || /\b(?:ClusterManager|ServerNode|redis::)\b/.test(mucSoftStatePort + mucSoftStateService)
    || !mucSoftStateService.includes('.join_room(room_jid)')
    || !mucSoftStateService.includes('.refresh_occupant(room_jid, nick, exact_occupant_json)')
    || !mucSoftStateService.includes('.reconcile_room(room_jid)')
    || !mucRedisAdapter.includes('self.join_muc(room_jid)')
    || !mucRedisAdapter.includes('self.register_muc_occupant(room_jid, nick, exact_occupant_json)')
    || !mucRedisAdapter.includes('self.reconcile_muc_soft_state(room_jid)')) {
  throw new Error('cluster lease maintenance must use scoped Redis projection authority');
}
const clusterListener = rustItemBody(readProductionModule('crates/edges/northstar-cluster/src/listener.rs', { root }), 'async fn listen_once<A: ClusterAdapters>(');
const clusterListenerTransport = rustItemBody(cluster, 'pub struct ClusterPubsubListenerTransport');
const clusterListenerSupervisor = rustItemBody(cluster, 'pub async fn run_pubsub_listener<A: ClusterAdapters>(');
if (/\b(?:ServerNode|ClusterManager|signer|pending_acks|replay)\s*:/.test(clusterListenerTransport)
    || /\bstate\.cluster\b/.test(clusterListenerSupervisor)) {
  throw new Error('PubSub listener setup and generation must use scoped transport authority');
}
const listenerDispatch = read('crates/edges/northstar-cluster/src/listener_dispatch.rs');
const listenerDispatchConstructor = read('src/node/adapters/cluster_listener_dispatch.rs');
if (clusterListener.includes('db::cluster_session_route_authority(')
    || !clusterListener.includes('dispatch.terminate_exact_session(')
    || !listenerDispatchConstructor.includes('SessionTerminationAuthorityService::new(')
    || !listenerDispatch.includes('fence_local_session_in(')) {
  throw new Error('signed session termination must re-read exact route authority through its service');
}
if (!clusterMaintenance.includes('.session_authority')
    || /(?:crate::)?db::(?:auth_states_for_users|user_agent_login_epochs)\s*\(/.test(clusterMaintenance)) {
  throw new Error('cluster credential maintenance must use the read-only session authority service');
}
if (/tokio::spawn\s*\(\s*admin_session_cleanup_heartbeat/.test(operationRuntimeOwnershipSource)) {
  throw new Error('administrator cleanup lease renewal must not be a detached Tokio task');
}
const clusterFailureSupervisor = rustItemBody(
  cluster,
  'pub async fn run_failure_supervisor<A: ClusterAdapters>(',
);
const clusterFailureContext = structBody(
  read('crates/edges/northstar-cluster/src/failure_supervisor_context.rs'),
  'pub struct ClusterFailureSupervisorContext',
);
const clusterFailureAuthority = rustItemBody(
  cluster,
  'pub struct ClusterFailureSupervisorAuthority',
);
if (!clusterFailureSupervisor.includes('context.replay_maintenance')
    || !clusterFailureSupervisor.includes('context.route_maintenance')
    || !clusterFailureSupervisor.includes('.cleanup_and_validate(4096)')
    || !clusterWorkers.includes('cluster_failure_supervisor_context(state)')
    || /ClusterManager|\bPgPool\b|\bServerNode\b/.test(clusterFailureContext)
    || /ClusterManager|\bPgPool\b/.test(clusterFailureAuthority)
    || /cluster_(?:session_route|replay)_maintenance_service\s*:/.test(appState)
    || /Arc<ServerNode>/.test(clusterFailureSupervisor)
    || /(?:crate::)?db::(?:cleanup_cluster_envelope_replays|validate_cluster_replay_capacity_authority)\s*\(/.test(clusterFailureSupervisor)) {
  throw new Error('cluster failure supervisor must own narrow authority and bounded maintenance services');
}
if (!clusterFailureSupervisor.includes('context.route_maintenance')
    || !clusterFailureSupervisor.includes('.cleanup_and_validate(4096)')
    || /(?:crate::)?db::(?:cleanup_cluster_session_routes|validate_cluster_session_route_authority)\s*\(/.test(clusterFailureSupervisor)) {
  throw new Error('cluster failure supervisor must clean and validate session routes through its bounded maintenance service');
}
const accountRevocationWorker = rustItemBody(
  cluster,
  'pub async fn run_account_revocations<',
);
if (!clusterWorkers.includes('account_revocation_worker_context(state)')
    || /Arc<ServerNode>|\bstate\./.test(accountRevocationWorker)
    || !accountRevocationWorker.includes('context.authority.identity()')
    || !accountRevocationWorker.includes('context.routes.revoke(')
    || !accountRevocationWorker.includes('context.routes.fence_all()')) {
  throw new Error('account revocation worker must use a narrow live-identity and fail-closed route context');
}
const c2sTelemetry = read('crates/contexts/session/northstar-session-application/src/telemetry.rs');
const c2sProtocol = readRoleSplitFile('crates/edges/northstar-stream/src/protocol.rs', { root });
const c2sDispatch = read('crates/edges/northstar-stream/src/protocol/dispatch.rs');
if (!read('crates/contexts/session/northstar-session-application/src/post_actions.rs')
      .includes('struct PostActionTelemetry')
    || !c2sTelemetry.includes('struct InboundStanzaTelemetry')
    || !read('crates/contexts/roster/northstar-roster-xmpp/src/session_host.rs')
      .includes('struct PostAcceptFailureTelemetry')
    || !c2sTelemetry.includes('struct PushSubscriptionTelemetry')
    || !c2sTelemetry.includes('struct PushDeliveryTelemetry')
    || !c2sTelemetry.includes('struct RegistrationTelemetry')
    || !c2sTelemetry.includes('struct AccountAbuseTelemetry')
    || !c2sTelemetry.includes('struct SessionBindTelemetry')
    || !c2sTelemetry.includes('struct SmSessionTelemetry')
    || !c2sTelemetry.includes('struct Sasl2AuthenticationTelemetry')
    || !c2sTelemetry.includes('struct C2sAuthenticationTelemetry')
    || !c2sTelemetry.includes('struct OutboundStanzaTelemetry')
    || !c2sTelemetry.includes('struct SessionDropFallbackTelemetry')
    || !read('crates/contexts/message/northstar-message-application/src/telemetry.rs').includes('struct PersonalMessageTelemetry')
    || !read('crates/contexts/room/northstar-room-core/src/telemetry.rs').includes('struct FederatedMucTelemetry')
    || /\b(?:ServerNode|Metrics|PgPool|C2sRuntimePorts)\b/.test(c2sTelemetry)
    || !c2sProtocol.includes('c2s_post_action_telemetry()')
    || /(?:self\.)?(?:state|host)\.metrics\.post_action_/.test(c2sProtocol)
    || !/pub async fn handle\(&mut self, xml: &str\) -> Result<Action> \{\s*self\.host\.inbound_stanza_telemetry\(\)\.received\(\);/.test(c2sDispatch)
    || /self\.(?:state|host)\.metrics\b/.test(c2sDispatch)
    || ['privacy.rs', 'blocking.rs', 'roster.rs'].some((name) =>
      /\b(?:self\.)?(?:state|host)\s*\.\s*metrics\b/.test(protocolModuleSource(name, read)))
    || /\b(?:self\.)?(?:state|host)\s*\.\s*metrics\b/.test(read('crates/edges/northstar-stream/src/protocol/ibr.rs'))
    || /\b(?:self\.)?(?:state|host)\s*\.\s*metrics\b/.test(read('crates/edges/northstar-stream/src/protocol/misc.rs'))
    || /\b(?:self\.)?(?:state|host)\s*\.\s*metrics\b/.test(read('crates/edges/northstar-stream/src/protocol/sm.rs'))
    || /\b(?:self\.)?(?:state|host)\s*\.\s*metrics\b/.test(readProductionModule('crates/edges/northstar-stream/src/protocol/sasl2.rs', { root }))
    || /\b(?:self\.)?(?:state|host)\s*\.\s*metrics\b/.test(c2sProtocol)
    || /(?:self\.)?(?:state|host)\.metrics\b/.test(readProductionModule('crates/contexts/message/northstar-message-xmpp/src/messaging.rs', { root }))
    || /(?:self\.)?(?:state|host)\.metrics\b/.test(federatedMucSource)) {
  throw new Error('C2S post-action supervision must use narrow telemetry without broad state or registry authority');
}
const componentTransport = readProductionModule('crates/edges/northstar-s2s/src/components.rs', { root });
if (!federationComponents.includes('struct ComponentTelemetry')
    || /\b(?:state|state_clone)\s*\.\s*metrics\b/.test(componentTransport)
    || !componentTransport.includes('component_telemetry().connection_failed()')
    || !componentTransport.includes('component_telemetry().outbox_written()')) {
  throw new Error('component transport must use only its typed connection and delivery telemetry');
}
const s2sTelemetry = read('crates/contexts/federation/northstar-federation-application/src/telemetry.rs');
if (!s2sTelemetry.includes('struct OnlineQueueAcceptanceTelemetry')
    || !s2sTelemetry.includes('struct InboundConnectionTelemetry')
    || !s2sTelemetry.includes('struct OutboundDispositionTelemetry')
    || /\b(?:ServerNode|Metrics|PgPool)\b/.test(s2sTelemetry)
    || /\b(?:state|state_clone)\s*\.\s*metrics\b/.test(s2sInboundSource)
    || /\b(?:state|state_clone)\s*\.\s*metrics\b/.test(readProductionModule('crates/edges/northstar-s2s/src/outbound.rs', { root }))) {
  throw new Error('S2S ingress and egress must use narrow telemetry cells');
}
for (const protocol of ['pep.rs', 'pubsub.rs']) {
  if (/\bstate\s*\.\s*metrics\b/.test(protocolModuleSource(protocol))) {
    throw new Error(`${protocol} must use a narrow telemetry capability`);
  }
}
const retentionContext = structBody(read('crates/contexts/operations/northstar-operations-application/src/retention_worker.rs'), 'pub struct RetentionContext');
if (!retentionContext.includes('counters: RetentionCounters')
    || retentionContext.includes('Arc<Metrics>')) {
  throw new Error('archive retention must carry only its operation counters');
}
const housekeepingContext = structBody(read('crates/contexts/operations/northstar-operations-application/src/background_housekeeping.rs'), 'pub struct BackgroundHousekeepingContext');
if (!housekeepingContext.includes('counters: BackgroundHousekeepingCounters')
    || housekeepingContext.includes('Arc<Metrics>')
    || /bg_state\.metrics\b/.test(workerComposition)) {
  throw new Error('background housekeeping must not retain the complete metrics registry');
}
const lockedMucExpiryWorker = rustItemBody(state, 'fn start_locked_muc_expiry(');
const lockedMucExpiryContext = read('crates/contexts/room/northstar-muc-xmpp/src/locked_room_expiry.rs');
if (!lockedMucExpiryWorker.includes('.locked_muc_expiry_context')
    || !lockedMucExpiryContext.includes('.expire_locked_rooms(')
    || /(?:db|muc)::delete_expired_locked_muc_rooms\s*\(/.test(lockedMucExpiryWorker)) {
  throw new Error('locked MUC expiry worker must commit through its repository service');
}
const mixPresenceRecovery = structBody(readProductionModule('crates/contexts/room/northstar-mix-xmpp/src/lib.rs', { root }), 'pub fn start_mix_presence_recovery(');
const mixPresenceContext = read('src/node/adapters/mix_presence_recovery.rs');
const verifiedMixPresence = structBody(readProductionModule('crates/contexts/room/northstar-mix-xmpp/src/lib.rs', { root }), 'async fn publish_verified_mix_presence_with(');
if (!state.includes('Arc::new(state.mix_presence_recovery_context())')
    || /\b(?:ServerNode|PgPool|ClusterManager)\b/.test(mixPresenceRecovery)
    || /\b(?:Arc<ServerNode>|PgPool|ClusterManager)\b/.test(mixPresenceContext)
    || !mixPresenceRecovery.includes('context.routes().local_epochs(')
    || !mixPresenceRecovery.includes('context.expire_unrefreshed(cutoff)')
    || !verifiedMixPresence.includes('context.routes().epoch_state(')
    || !mixPresenceContext.includes('self.policy.domain_allowed(')) {
  throw new Error('MIX presence recovery must use live route fences and narrow application effects');
}
const serviceTaskNames = [
  'XMPP',
  'XMPPS',
  'S2S',
  'S2S TLS',
  'external component',
  'durable operation worker',
  'HTTP',
  'Web administration',
  'metrics',
];
const composedServiceTasks = [
  ...mainSource.matchAll(/spawn_service_task\(\s*&mut service_tasks,\s*"([^"]+)"/g),
].map((match) => match[1]);
assertExactUniqueInventory('top-level service task', composedServiceTasks, serviceTaskNames);
for (const task of serviceTaskNames) {
  if (!mainSource.includes(`"${task}"`)) {
    throw new Error(`documented top-level service task is absent from main.rs: ${task}`);
  }
  if (!responsibilityDocument.includes(`\`${task}\``)) {
    throw new Error(`program responsibility model omits top-level service task: ${task}`);
  }
}
const moduleServiceAccessors = [
  'api_query_service',
  'api_session_service',
  'cluster_authority_service',
  'cluster_instance_release_service',
  'cluster_muc_occupancy_maintenance_service',
  'challenge_issue_service',
  'sasl_login_abuse_service',
  's2s_roster_authorization_service',
  's2s_outbox_dispatch_service',
  's2s_sm_outbox_service',
  'report_service',
  'omemo_recovery_service',
  'authentication_service',
  'account_service',
  'admin_command_service',
  'message_service',
  'message_admission_service',
  'retraction_service',
  'replay_service',
  'sm_service',
  'roster_service',
  'presence_service',
  'privacy_service',
  'blocking_service',
  'mam_service',
  'pubsub_service',
  'profile_service',
  'private_storage_service',
  'muc_service',
  'mix_service',
  'push_service',
  'upload_service',
  'extdisco_service',
];
if (!state.includes('let upload_service = config.upload_mode.keeps_storage_runtime().then(')) {
  throw new Error('upload service must exist while the drain-read-only GET and DELETE routes are mounted');
}
// ServerNode keeps composition and runtime handles; every inherent *_service
// method, regardless of visibility, belongs to its owning context module.
const appStateServiceAccessors = [...state.matchAll(/^\s*impl\s+ServerNode\s*\{/gm)].flatMap((block) => {
  const open = block.index + block[0].length - 1;
  return [...state.slice(open, matchingRustBrace(state, open))
    .matchAll(/\bfn\s+([a-z][a-z0-9_]*_service)\s*(?:<[^>{}]*>)?\s*\(/g)].map((match) => match[1]);
});
assertExactUniqueInventory('ServerNode service accessor', appStateServiceAccessors, []);

// Inventory only crate-private service accessors in inherent context module
// implementations. Host-trait methods keep their names and are not accessors.
const composedModuleServiceAccessors = productionRustSources
  .filter(({ relative }) => relative.startsWith('src/node/'))
  .flatMap(({ relative, source }) => [...source.matchAll(/^\s*impl\s+[A-Za-z][A-Za-z0-9_]*Module\s*\{/gm)]
    .flatMap((block) => {
      const open = block.index + block[0].length - 1;
      return [...source.slice(open, matchingRustBrace(source, open))
        .matchAll(/pub\(crate\)\s+fn\s+([a-z][a-z0-9_]*_service)\s*\(/g)]
        .map((match) => ({ name: match[1], owner: relative }));
    }));
const composedServiceAccessors = composedModuleServiceAccessors.map(({ name }) => name);
assertExactUniqueInventory('module service accessor', composedServiceAccessors, moduleServiceAccessors);
for (const accessor of moduleServiceAccessors) {
  if (!responsibilityDocument.includes(`\`${accessor}()\``)) {
    throw new Error(`program responsibility model omits module service accessor: ${accessor}`);
  }
}

const largestAuthority = [...perFile]
  .sort((left, right) => right.authorityReferences - left.authorityReferences)
  .slice(0, 5)
  .map(
    ({ name, authorityReferences, lines }) =>
      `${name}=${authorityReferences} authority refs/${lines} lines`,
  )
  .join(', ');
const largestDomain = [...perFile]
  .sort((left, right) => right.domainReferences - left.domainReferences)
  .slice(0, 5)
  .map(({ name, domainReferences }) => `${name}=${domainReferences} domain refs`)
  .join(', ');

console.log(
  `Architecture boundary budgets passed: ServerNode=${publicFields} public fields, ` +
    `protocol=${protocolDbAuthorityReferences} db authority refs / ` +
    `${protocolDbDomainReferences} db domain-model refs / ` +
    `${protocolStatePoolReferences} state.pool / ${protocolSqlxReferences} sqlx:: / ` +
    `${protocolPgPoolReferences} PgPool refs; authority: ${largestAuthority}; ` +
    `domain: ${largestDomain}`,
);

// The experiment index consumes the exact production inventory already checked
// above, never a second handwritten list of runtime authorities.
// SQLx 0.9, like 0.8, can return a connection to its pool inside the
// transaction of a cancelled BEGIN. Scanned production pools in src/ and
// crates/ start from options that close such a connection on release.
const poolOptionsSource = read('crates/platform/northstar-postgres/src/pool.rs');
const unguardedPools = productionRustSources
  .filter(({ relative }) => /^(?:src\/|crates\/(?:contexts|edges)\/|crates\/platform\/northstar-)/.test(relative))
  .filter(({ relative }) => relative !== 'crates/platform/northstar-postgres/src/pool.rs')
  // Modules compiled only for tests may build plain pools.
  .filter(({ relative }) => !/(?:^|\/)(?:test_support|\w+_test)\.rs$/.test(relative))
  .filter(({ source }) => /\bPgPoolOptions::new\(\)/.test(source))
  .map(({ relative }) => relative);
if (unguardedPools.length > 0
    || !poolOptionsSource.includes('PgPoolOptions::new().after_release(')
    || !poolOptionsSource.includes('"SELECT pg_catalog.statement_timestamp() = pg_catalog.transaction_timestamp()"')
    || !poolOptionsSource.includes('sqlx::raw_sql(')
    || !poolOptionsSource.includes('Ok(reusable)')) {
  throw new Error(`database pools must start from northstar_postgres::pool::options(): ${unguardedPools.join(', ')}`);
}

export const verifiedRuntimeInventory = [
  ...productionRustSources.flatMap(({ relative, source }) =>
    [...source.matchAll(/\.supervise(_draining)?\(\s*"([^"]+)"/g)].map((match) => ({
      id: `worker:${roleIdentity(relative, match[2])}`, kind: 'worker', owner: relative,
    }))),
  ...productionRustSources.flatMap(({ relative, source }) =>
    [...source.matchAll(/\.register_observer\(\s*"([^"]+)"/g)].map((match) => ({
      id: `observer:${roleIdentity(relative, match[1])}`, kind: 'observer', owner: relative,
    }))),
  ...composedServiceTasks.map((name) => ({ id: `task:${name}`, kind: 'task', owner: 'src/main.rs' })),
  ...composedModuleServiceAccessors.map(({ name, owner }) => ({ id: `service:${name}`, kind: 'service', owner })),
].sort((left, right) => left.id.localeCompare(right.id));
