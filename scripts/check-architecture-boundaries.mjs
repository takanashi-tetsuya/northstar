import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

const state = read('src/state.rs');
const configSource = read('src/config.rs');
const appState = structBody(state, 'pub struct AppState');
const publicFields = countMatches(appState, /^\s*pub\s+[A-Za-z_][A-Za-z0-9_]*\s*:/gm);
const cratePublicFields = countMatches(appState, /^\s*pub\(crate\)\s+[A-Za-z_][A-Za-z0-9_]*\s*:/gm);

// These ceilings capture the 2026-08-29 debt baseline. They are monotonic
// budgets, not a claim that the current architecture is sufficiently narrow.
// New work must use an application service instead of increasing either
// number; the ceilings should be lowered as vertical slices are extracted.
const MAX_APP_STATE_PUBLIC_FIELDS = 9;
const MAX_APP_STATE_CRATE_PUBLIC_FIELDS = 0;

if (publicFields > MAX_APP_STATE_PUBLIC_FIELDS) {
  throw new Error(
    `AppState public-field budget regressed: ${publicFields} > ${MAX_APP_STATE_PUBLIC_FIELDS}`,
  );
}
if (cratePublicFields > MAX_APP_STATE_CRATE_PUBLIC_FIELDS) {
  throw new Error(
    `AppState crate-public-field budget regressed: ${cratePublicFields} > ${MAX_APP_STATE_CRATE_PUBLIC_FIELDS}`,
  );
}

// The loaded configuration transiently contains database, cluster,
// component, TURN, FAST and anti-abuse credentials. It must be move-only so
// AppState::new can consume and scrub the sole configuration instance instead
// of leaving an unconstrained plaintext clone elsewhere in the process.
for (const typeName of ['RawConfig', 'Config']) {
  const declaration = new RegExp(
    `#\\s*\\[\\s*derive\\s*\\(([^)]*\\bClone\\b[^)]*)\\)\\s*\\]\\s*pub\\s+struct\\s+${typeName}\\b`,
    's',
  );
  if (declaration.test(configSource)) {
    throw new Error(`${typeName} must remain move-only because it transiently owns runtime secrets`);
  }
}

for (const field of [
  'api_control',
  'api_cursor',
  'upload_service',
  'upload_store',
  'message_service',
  'retraction_service',
  'pubsub_service',
  'mam_service',
  'mix_service',
  'presence_service',
  'replay_service',
  'privacy_service',
  'private_storage_service',
  'profile_service',
  'account_service',
  'authentication_service',
  'admin_command_service',
  'push_service',
  'extdisco_service',
  'component_credentials',
  'components',
  'bosh',
  's2s_dns_resolver',
  's2s_dnssec_resolver',
  'dialback_verifications',
  's2s_connections',
  's2s_connection_attempts',
  'component_connections',
  'started_at',
  'registration_closed',
  'federation_write_policy',
  's2s_connection_registry',
]) {
  if (!new RegExp(`^\\s*${field}\\s*:`, 'm').test(appState)) {
    throw new Error(`AppState capability ${field} is no longer private or is missing`);
  }
  if (new RegExp(`^\\s*pub(?:\\(crate\\))?\\s+${field}\\s*:`, 'm').test(appState)) {
    throw new Error(`AppState capability ${field} became publicly accessible`);
  }
}
if (!/^\s*dialback_secret\s*:\s*Zeroizing<Vec<u8>>\s*,/m.test(appState)) {
  throw new Error('AppState dialback_secret must remain private and Zeroizing');
}
if (!/^\s*fast_token_secret\s*:\s*Arc<Zeroizing<Vec<u8>>>\s*,/m.test(appState)) {
  throw new Error('AppState fast_token_secret must remain private Arc<Zeroizing<Vec<u8>>>');
}

// Runtime secrets must be transferred exactly once from Config into their
// narrow owner. AppState deliberately keeps Config for non-secret policy, so
// leaving even an Option/Arc clone behind would make the secret reachable by
// every protocol handler through `state.config`.
const appStateNew = structBody(state, 'pub async fn new(');
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
    throw new Error(`AppState::new must take and consume config.raw.${field}`);
  }
}
for (const field of ['metrics_bearer_token', 'cluster_security']) {
  if (!new RegExp(`config\\s*\\.\\s*${field}\\s*\\.\\s*take\\s*\\(`).test(appStateNew)) {
    throw new Error(`AppState::new must take and consume config.${field}`);
  }
}
for (const operation of ['zeroize', 'clear']) {
  if (
    !new RegExp(
      `config\\s*\\.\\s*raw\\s*\\.\\s*database_url\\s*\\.\\s*${operation}\\s*\\(`,
    ).test(appStateNew)
  ) {
    throw new Error(`AppState::new must ${operation} config.raw.database_url after pool creation`);
  }
}
if (!/std\s*::\s*mem\s*::\s*take\s*\(\s*&mut\s+config\s*\.\s*components\s*\)/.test(appStateNew)) {
  throw new Error('AppState::new must take exclusive ownership of component credentials');
}
for (const field of ['secret_value', 'secret_file']) {
  if (!new RegExp(`credential\\s*\\.\\s*${field}\\s*=\\s*None`).test(appStateNew)) {
    throw new Error(`AppState::new must remove component ${field} from shared Config metadata`);
  }
}
if (!/credential\s*\.\s*secret_sha256\s*\.\s*zeroize\s*\(/.test(appStateNew)) {
  throw new Error('AppState::new must zero the component verifier in shared Config metadata');
}
if (
  /^\s*pub(?:\(crate\))?\s+[A-Za-z_][A-Za-z0-9_]*(?:secret|token|credential|keyring)[A-Za-z0-9_]*\s*:/gim.test(
    appState,
  )
) {
  throw new Error('AppState exposes a runtime secret/token/credential capability as a field');
}

const protocolDirectory = path.join(root, 'src', 'xmpp', 'protocol');
const protocolFiles = fs
  .readdirSync(protocolDirectory)
  .filter((name) => name.endsWith('.rs'))
  .sort();

let protocolDbAuthorityReferences = 0;
let protocolDbDomainReferences = 0;
let protocolStatePoolReferences = 0;
let protocolSqlxReferences = 0;
let protocolPgPoolReferences = 0;
const perFile = [];
for (const name of protocolFiles) {
  const source = fs.readFileSync(path.join(protocolDirectory, name), 'utf8');
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
const MAX_MIX_DB_AUTHORITY_REFERENCES = 0;
const MAX_MIX_DB_DOMAIN_REFERENCES = 0;
const MAX_PUBSUB_DB_AUTHORITY_REFERENCES = 0;
const MAX_PUBSUB_DB_DOMAIN_REFERENCES = 0;
const MAX_PEP_DB_AUTHORITY_REFERENCES = 0;
const MAX_PEP_DB_DOMAIN_REFERENCES = 0;
const MAX_MESSAGING_DB_AUTHORITY_REFERENCES = 0;
const MAX_MESSAGING_DB_DOMAIN_REFERENCES = 0;
const MAX_DISCOVERY_DB_AUTHORITY_REFERENCES = 0;
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
if (mix.authorityReferences > MAX_MIX_DB_AUTHORITY_REFERENCES) {
  throw new Error(
    `mix.rs db authority budget regressed: ${mix.authorityReferences} > ${MAX_MIX_DB_AUTHORITY_REFERENCES}`,
  );
}
if (mix.authorityReferences !== 0) {
  throw new Error('mix.rs must have exactly zero direct db authority references');
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
const pubsubDbAuthorityReferences = pubsub?.authorityReferences ?? 0;
const pubsubDbDomainReferences = pubsub?.domainReferences ?? 0;
const pepDbAuthorityReferences = pep?.authorityReferences ?? 0;
const pepDbDomainReferences = pep?.domainReferences ?? 0;
const messagingDbAuthorityReferences = messaging?.authorityReferences ?? 0;
const messagingDbDomainReferences = messaging?.domainReferences ?? 0;
const discoveryDbAuthorityReferences = discovery?.authorityReferences ?? 0;
const discoveryDbDomainReferences = discovery?.domainReferences ?? 0;
if (pubsubDbAuthorityReferences > MAX_PUBSUB_DB_AUTHORITY_REFERENCES) {
  throw new Error(
    `pubsub.rs db authority budget regressed: ${pubsubDbAuthorityReferences} > ${MAX_PUBSUB_DB_AUTHORITY_REFERENCES}`,
  );
}
if (pubsubDbDomainReferences > MAX_PUBSUB_DB_DOMAIN_REFERENCES) {
  throw new Error(
    `pubsub.rs db domain-model coupling regressed: ${pubsubDbDomainReferences} > ${MAX_PUBSUB_DB_DOMAIN_REFERENCES}`,
  );
}
if (pepDbAuthorityReferences > MAX_PEP_DB_AUTHORITY_REFERENCES) {
  throw new Error(
    `pep.rs db authority budget regressed: ${pepDbAuthorityReferences} > ${MAX_PEP_DB_AUTHORITY_REFERENCES}`,
  );
}
if (pepDbDomainReferences > MAX_PEP_DB_DOMAIN_REFERENCES) {
  throw new Error(
    `pep.rs db domain-model coupling regressed: ${pepDbDomainReferences} > ${MAX_PEP_DB_DOMAIN_REFERENCES}`,
  );
}
if (messagingDbAuthorityReferences > MAX_MESSAGING_DB_AUTHORITY_REFERENCES) {
  throw new Error(
    `messaging.rs db authority budget regressed: ${messagingDbAuthorityReferences} > ${MAX_MESSAGING_DB_AUTHORITY_REFERENCES}`,
  );
}
if (messagingDbDomainReferences > MAX_MESSAGING_DB_DOMAIN_REFERENCES) {
  throw new Error(
    `messaging.rs db domain-model coupling regressed: ${messagingDbDomainReferences} > ${MAX_MESSAGING_DB_DOMAIN_REFERENCES}`,
  );
}
if (discoveryDbAuthorityReferences !== MAX_DISCOVERY_DB_AUTHORITY_REFERENCES) {
  throw new Error(
    `discovery.rs must have exactly zero db authority references, found ${discoveryDbAuthorityReferences}`,
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
// classifyDbDependencies.
for (const [name, serviceAccessor, source] of [
  ['pubsub.rs', 'pubsub_service', read('src/xmpp/protocol/pubsub.rs')],
  ['pep.rs', 'pubsub_service', read('src/xmpp/protocol/pep.rs')],
  ['mix.rs', 'mix_service', read('src/xmpp/protocol/mix.rs')],
  ['mam.rs', 'mam_service', read('src/xmpp/protocol/mam.rs')],
  ['privacy.rs', 'privacy_service', read('src/xmpp/protocol/privacy.rs')],
  ['private.rs', 'private_storage_service', read('src/xmpp/protocol/private.rs')],
  ['replay.rs', 'replay_service', read('src/xmpp/protocol/replay.rs')],
  ['roster.rs', 'roster_service', read('src/xmpp/protocol/roster.rs')],
  ['vcard.rs', 'profile_service', read('src/xmpp/protocol/vcard.rs')],
]) {
  const dependency = classifyDbDependencies(source, name);
  if (dependency.authorityReferences !== 0) {
    throw new Error(`${name} must have exactly zero direct db authority references`);
  }
  for (const [description, pattern] of [
    ['AppState pool access', /\bstate\s*\.\s*pool\b/],
    ['a PostgreSQL pool type', /\b(?:sqlx\s*::\s*)?PgPool\b/],
    ['raw SQL execution', /\bsqlx\s*::/],
  ]) {
    if (pattern.test(source)) {
      throw new Error(`${name} bypasses its application service through ${description}`);
    }
  }
  if (!new RegExp(`\\.${serviceAccessor}\\s*\\(\\s*\\)`).test(source)) {
    throw new Error(`${name} no longer routes persistence through ${serviceAccessor}()`);
  }
}

const rosterServiceSource = read('src/services/roster.rs');
const rosterServiceBody = structBody(rosterServiceSource, 'pub(crate) struct RosterService');
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(rosterServiceBody)) {
  throw new Error('RosterService PostgreSQL capability must remain a private PgPool field');
}
if (/^\s*pub(?:\(crate\))?\s+pool\s*:/m.test(rosterServiceBody)) {
  throw new Error('RosterService must not expose its PostgreSQL capability');
}
for (const invariant of [
  'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY',
  'expected_auth_generation',
  'MAX_BUFFERED_ROSTER_CHANGES',
  'RosterSyncState::Flushing',
]) {
  if (!rosterServiceSource.includes(invariant) && !read('src/db/roster.rs').includes(invariant)) {
    throw new Error(`RosterService lost safety invariant: ${invariant}`);
  }
}
const clusterRosterSource = read('src/cluster.rs');
for (const invariant of ['expected_user_id', 'roster_version', 'roster_annotated_stanza']) {
  if (!clusterRosterSource.includes(invariant)) {
    throw new Error(`cluster roster delivery lost identity/ordering field: ${invariant}`);
  }
}

// ARCH-SVC XEP-0160 replay boundary: only transport ordering/backpressure is
// allowed in protocol code. PostgreSQL account/page leases, policy snapshots
// and claim cleanup remain private to ReplayService. Bind 2 uses the same
// service path and may not resurrect the former pool-owning repository drain.
const replayProtocolSource = read('src/xmpp/protocol/replay.rs');
const replayDependencies = classifyDbDependencies(replayProtocolSource, 'replay.rs');
if (replayDependencies.authorityReferences !== 0) {
  throw new Error('replay.rs must have exactly zero direct db authority references');
}
for (const [description, pattern] of [
  ['AppState pool access', /\bstate\s*\.\s*pool\b/],
  ['a PostgreSQL pool type', /\b(?:sqlx\s*::\s*)?PgPool\b/],
  ['raw SQL execution', /\bsqlx\s*::/],
]) {
  if (pattern.test(replayProtocolSource)) {
    throw new Error(`replay.rs bypasses ReplayService through ${description}`);
  }
}
if (!/\.replay_service\s*\(\s*\)/.test(replayProtocolSource)) {
  throw new Error('replay.rs no longer routes persistence through replay_service()');
}
const replayServiceSource = read('src/services/replay.rs');
const replayServiceBody = structBody(replayServiceSource, 'pub(crate) struct ReplayService');
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(replayServiceBody)) {
  throw new Error('ReplayService PostgreSQL capability must remain a private PgPool field');
}
if (/^\s*pub(?:\(crate\))?\s+pool\s*:/m.test(replayServiceBody)) {
  throw new Error('ReplayService must not expose its PostgreSQL capability');
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
const replayDbSource = read('src/db/replay.rs').replace(/\s+/g, ' ');
for (const invariant of [
  'ON CONFLICT(recipient_id,resource)',
  'SET owner_token=EXCLUDED.owner_token',
]) {
  if (!replayDbSource.includes(invariant)) {
    throw new Error(`offline replay acquisition lost invariant: ${invariant}`);
  }
}
const resourceOwnerFence = 'WHERE recipient_id=$1 AND resource=$2 AND owner_token=$3';
if (replayDbSource.split(resourceOwnerFence).length - 1 < 3) {
  throw new Error('offline replay claim/renew/release lost its resource + owner-token fence');
}
for (const invariant of [
  'OfflineReplayLeaseAcquire',
  'BusyUntil(OfflineReplayBusyUntil)',
  'Some("40001")',
]) {
  if (!replayDbSource.includes(invariant)) {
    throw new Error(`offline replay database boundary lost invariant: ${invariant}`);
  }
}
for (const invariant of ['ReplayStartOutcome', 'ReplayStartOutcome::BusyUntil']) {
  if (!replayServiceSource.includes(invariant) && !replayProtocolSource.includes(invariant)) {
    throw new Error(`offline replay retry coordinator lost invariant: ${invariant}`);
  }
}
if (!replayProtocolSource.includes('REPLAY_RECOVERY_DEADLINE')) {
  throw new Error('offline replay busy retry lost its bounded recovery deadline');
}
const sasl2Source = read('src/xmpp/protocol/sasl2.rs');
for (const forbidden of [
  'deliver_bind2_offline',
  'deliver_offline_leased',
  'acquire_offline_replay_lease',
]) {
  if (new RegExp(`\\b(?:db\\s*::\\s*)?${forbidden}\\b`).test(sasl2Source)) {
    throw new Error(`sasl2.rs bypasses ReplayService via ${forbidden}`);
  }
}
if (!/super\s*::\s*replay\s*::\s*replay_bind2_offline\s*\(/.test(sasl2Source)) {
  throw new Error('SASL2 Bind 2 no longer delegates offline reconciliation to ReplayService');
}

// ARCH-SVC authentication vertical slice: protocol code owns SASL wire state
// only. PostgreSQL account/verifier authority and the independent FAST and
// dummy-SCRAM derivation keys stay
// inside AuthenticationService, whose successful result is structurally
// incapable of carrying password or SCRAM verifier fields.
const authenticationServiceSource = read('src/services/authentication.rs');
const authenticationServiceBody = structBody(
  authenticationServiceSource,
  'pub(crate) struct AuthenticationService',
);
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(authenticationServiceBody)) {
  throw new Error('AuthenticationService PostgreSQL capability must remain a private PgPool field');
}
if (!/^\s*fast_token_secret\s*:\s*Arc<Zeroizing<Vec<u8>>>\s*,?\s*$/m.test(authenticationServiceBody)) {
  throw new Error('AuthenticationService FAST key must remain private Arc<Zeroizing<Vec<u8>>>');
}
if (!/^\s*dummy_scram_secret\s*:\s*Arc<Zeroizing<Vec<u8>>>\s*,?\s*$/m.test(authenticationServiceBody)) {
  throw new Error('AuthenticationService dummy SCRAM key must remain private Arc<Zeroizing<Vec<u8>>>');
}
if (/^\s*pub(?:\(crate\))?\s+(?:pool|fast_token_secret|dummy_scram_secret)\s*:/m.test(authenticationServiceBody)) {
  throw new Error('AuthenticationService exposed a PostgreSQL or authentication-key capability');
}
const authenticatedAccountBody = structBody(
  authenticationServiceSource,
  'pub(crate) struct AuthenticatedAccount',
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
if (/AuthenticationResult\s*<\s*(?:crate::)?db::User\s*>/.test(authenticationServiceSource)) {
  throw new Error('AuthenticationService must never return the credential-bearing db::User DTO');
}
const legacyAuthProtocolSource = read('src/xmpp/protocol.rs');
if (!/authenticated\s*:\s*\r?\n?\s*Option<crate::services::authentication::AuthenticatedAccount>/.test(legacyAuthProtocolSource)) {
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
  throw new Error('sasl2.rs regained direct AppState PostgreSQL authority');
}
const accountServiceSource = read('src/services/account.rs');
if (/RegistrationOutcome[\s\S]*?Created\s*\(\s*db::User\s*\)/.test(accountServiceSource)) {
  throw new Error('AccountService registration result leaks the credential-bearing db::User DTO');
}
const registrationAccountBody = structBody(
  accountServiceSource,
  'pub(crate) struct RegistrationAccount',
);
if (/(?:\bpassword_hash\b|\bscram_[A-Za-z0-9_]*|\bauth_generation\b|\bis_admin\b)/.test(registrationAccountBody)) {
  throw new Error('AccountService RegistrationAccount regained credential or authority fields');
}
const authSource = read('src/auth.rs');
const usersSource = read('src/db/users.rs');
for (const [name, source, typeName] of [
  ['PasswordCredentials', authSource, 'PasswordCredentials'],
  ['PreparedScramUpgrade', usersSource, 'PreparedScramUpgrade'],
  ['PreparedLogin', usersSource, 'PreparedLogin'],
]) {
  if (!new RegExp(`impl\\s+Drop\\s+for\\s+${typeName}\\b`).test(source)) {
    throw new Error(`${name} must zeroize reusable credential material on Drop`);
  }
}
if (!/impl\s+std::fmt::Debug\s+for\s+PasswordCredentials\b/.test(authSource)
    || !/impl\s+std::fmt::Debug\s+for\s+PreparedLogin\b/.test(usersSource)) {
  throw new Error('credential containers require explicitly redacted Debug implementations');
}

// Federated MUC remains a large orchestration module with unrelated cluster
// transactions, so it cannot yet satisfy the whole-file PgPool prohibition
// above. Its MAM slice must nevertheless use the same authorized snapshot
// service as local XEP-0313: no room lookup, affiliation check, boundary read,
// cursor validation or archive page may be composed directly in the protocol
// handler.
const federatedMucSource = read('src/xmpp/protocol/federated_muc.rs');
for (const authority of [
  'authorize_mam_room',
  'authorize_federated_mam_room',
  'mam_room_archive_boundaries_authorized',
  'mam_room_archive_page_authorized',
  'mam_federated_room_archive_boundaries_authorized',
  'mam_federated_room_archive_page_authorized',
  'muc_archive_boundaries',
  'muc_archive_boundaries_visible',
  'mam_muc_archive_page',
  'mam_muc_archive_page_visible',
]) {
  if (new RegExp(`\\bdb\\s*::\\s*${authority}\\b`).test(federatedMucSource)) {
    throw new Error(
      `federated_muc.rs bypasses the authorized MAM snapshot via db::${authority}`,
    );
  }
}
if (!/\.mam_service\s*\(\s*\)/.test(federatedMucSource)) {
  throw new Error('federated_muc.rs no longer routes MAM authority through mam_service()');
}
for (const forbidden of [
  'enqueue_s2s_outbox_in_transaction',
  'mam_federated_room_archive_page_authorized_in_transaction',
]) {
  if (new RegExp(`\bdb\s*::\s*${forbidden}\b`).test(federatedMucSource)) {
    throw new Error(`federated_muc.rs regained transactional authority via db::${forbidden}`);
  }
}
const mamServiceSource = read('src/services/mam.rs');
const mamServiceBody = structBody(mamServiceSource, 'pub(crate) struct MamService');
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(mamServiceBody)
    || /^\s*pub(?:\(crate\))?\s+pool\s*:/m.test(mamServiceBody)) {
  throw new Error('MamService must retain a private PostgreSQL capability');
}
for (const invariant of [
  'mam_federated_room_archive_page_authorized_in_transaction',
  'enqueue_s2s_outbox_in_transaction',
  'transaction.commit().await?',
  'transaction.rollback().await?',
  'federation.wake_outbox()',
  'FederatedMamAdmissionOutcome::OutboxRejected',
]) {
  if (!mamServiceSource.includes(invariant)) {
    throw new Error(`MamService federated stream lost atomicity invariant: ${invariant}`);
  }
}
const archiveSource = read('src/db/archive.rs');
for (const invariant of [
  'WHERE localpart=$1 AND destroyed_at IS NULL\n          FOR SHARE',
  'pg_advisory_xact_lock(hashtextextended($1::TEXT, 29))',
  'muc_external_affiliations\n          WHERE room_id=$1 AND jid=$2 FOR SHARE',
]) {
  if (!archiveSource.includes(invariant)) {
    throw new Error(`federated MAM repository lost policy/identity lock: ${invariant}`);
  }
}

for (const [name, accessor, forbiddenAuthority] of [
  ['mix_muc.rs', 'mix_service', 'link_mix_muc_by_localpart'],
  ['presence.rs', 'presence_service', 'claim_admin_service_messages'],
  ['presence.rs', 'presence_service', 'complete_admin_service_message_claim'],
  ['upload.rs', 'upload_service', 'create_upload_slot_bounded'],
]) {
  const production = productionWithoutCfgTestModules(
    read(`src/xmpp/protocol/${name}`),
    `${name} production`,
  );
  if (new RegExp(`\bdb\s*::\s*${forbiddenAuthority}\b`).test(production)) {
    throw new Error(`${name} bypasses ${accessor}() via db::${forbiddenAuthority}`);
  }
  if (!new RegExp(`\.${accessor}\s*\(\s*\)`).test(production)) {
    throw new Error(`${name} no longer routes persistence through ${accessor}()`);
  }
}

const uploadServiceSource = read('src/services/upload.rs');
const uploadServiceBody = structBody(uploadServiceSource, 'pub(crate) struct UploadService');
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(uploadServiceBody)
    || /^\s*pub(?:\(crate\))?\s+pool\s*:/m.test(uploadServiceBody)) {
  throw new Error('UploadService must retain a private PostgreSQL capability');
}
// ARCH-SVC local XEP-0045 boundary: protocol code owns XML/session routing,
// while all PostgreSQL reads, mutations and committed-outbox wake authority
// pass through MucService. Inline DB fixtures are structurally masked rather
// than hiding every item after the first cfg(test) marker.
const mucProtocolSource = read('src/xmpp/protocol/muc.rs');
const mucProductionSource = productionWithoutCfgTestModules(
  mucProtocolSource,
  'muc.rs production',
);
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
  ['AppState pool access', /\b(?:self\.)?state\s*\.\s*pool\b/],
  ['a PostgreSQL pool type', /\b(?:sqlx\s*::\s*)?PgPool\b/],
  ['raw SQL execution', /\bsqlx\s*::/],
  ['the raw cluster MUC wake capability', /\.wake_committed_muc_operation\s*\(/],
]) {
  if (pattern.test(mucProductionSource)) {
    throw new Error(`muc.rs production bypasses MucService through ${description}`);
  }
}
if (!/\.muc_service\s*\(\s*\)/.test(mucProductionSource)) {
  throw new Error('muc.rs no longer routes persistence through muc_service()');
}
if (!/\.wake_committed_operation\s*\(\s*&self\.state\.cluster\s*,/.test(mucProductionSource)) {
  throw new Error('muc.rs no longer routes committed outbox wakes through MucService');
}
if (/\.wake_committed_muc_operation\s*\(\s*&self\.pool\b/.test(state)) {
  throw new Error('AppState runtime paths bypass MucService for committed MUC wakes');
}
const operationRuntimeSource = productionWithoutCfgTestModules(
  read('src/operation_runtime.rs'),
  'operation_runtime.rs production',
);
if (/\.wake_committed_muc_operation\s*\(/.test(operationRuntimeSource)
    || /\.wake_committed_operation\s*\(\s*&state\.pool\b/.test(operationRuntimeSource)) {
  throw new Error('operation_runtime.rs bypasses MucService for committed MUC wakes');
}
if (!/\.muc_service\s*\(\s*\)\s*\.wake_committed_operation\s*\(\s*&state\.cluster\s*,/.test(operationRuntimeSource)) {
  throw new Error('operation_runtime.rs no longer routes committed MUC wakes through MucService');
}
const mucServiceSource = read('src/services/muc.rs');
const mucServiceBody = structBody(mucServiceSource, 'pub(crate) struct MucService');
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(mucServiceBody)) {
  throw new Error('MucService PostgreSQL capability must remain a private PgPool field');
}
if (/^\s*pub(?:\(crate\))?\s+pool\s*:/m.test(mucServiceBody)) {
  throw new Error('MucService must not expose its PostgreSQL capability');
}
if (/find_user[\s\S]*Result<Option<\s*db::User\s*>>/.test(mucServiceSource)) {
  throw new Error('MucService leaks the credential-bearing db::User DTO');
}
if (!/enabled_local_account[\s\S]*db::enabled_user_id/.test(mucServiceSource)) {
  throw new Error('MucService no longer fails closed for disabled local routing targets');
}
if (!/find_enabled_user[\s\S]*?FROM users\s+WHERE username=\$1 AND NOT is_disabled/.test(usersSource)) {
  throw new Error('least-authority MUC account lookup must exclude disabled accounts in SQL');
}
for (const signature of mucServiceSource.matchAll(
  /pub\(crate\)\s+(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/gs,
)) {
  if (signature[1] !== 'new' && /\b(?:sqlx\s*::\s*)?PgPool\b/.test(signature[2])) {
    throw new Error('MucService must not accept a raw PostgreSQL capability');
  }
}

const discoverySource = read('src/xmpp/protocol/discovery.rs');
for (const [description, pattern] of [
  ['AppState pool access', /\b(?:self\.)?state\s*\.\s*pool\b/],
  ['a PostgreSQL pool type', /\b(?:sqlx\s*::\s*)?PgPool\b/],
  ['raw SQL execution', /\bsqlx\s*::/],
]) {
  if (pattern.test(discoverySource)) {
    throw new Error(`discovery.rs bypasses application services through ${description}`);
  }
}
for (const accessor of ['mix_service', 'muc_service', 'pubsub_service']) {
  if (!new RegExp(`\\.${accessor}\\s*\\(\\s*\\)`).test(discoverySource)) {
    throw new Error(`discovery.rs no longer routes authority through ${accessor}()`);
  }
}

// ARCH-SVC account/push boundary: resource binding remains a deliberately
// separate stateful session transaction, but XEP-0077 and XEP-0357 handlers
// must not regain direct persistence authority.
const miscSource = read('src/xmpp/protocol/misc.rs');
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
  if (new RegExp(`\\bdb\\s*::\\s*${authority}\\b`).test(miscSource)) {
    throw new Error(`misc.rs bypasses its account/push application service via ${authority}`);
  }
}
for (const accessor of ['account_service', 'push_service']) {
  if (!new RegExp(`\\.${accessor}\\s*\\(\\s*\\)`).test(miscSource)) {
    throw new Error(`misc.rs no longer routes account/push persistence through ${accessor}()`);
  }
}

// ARCH-SVC two-phase bind/resume boundary: protocol code may stage Redis and
// in-memory routes only while no PostgreSQL authorization transaction exists.
// Exact auth-generation, capacity/claim, FAST and privacy authority belongs to
// SmService's short phase-one/phase-two transactions.
const smProtocolSource = read('src/xmpp/protocol/sm.rs');
const smProductionSource = productionWithoutCfgTestModules(
  smProtocolSource,
  'sm.rs production',
);
const smProductionDependencies = classifyDbDependencies(
  smProductionSource,
  'sm.rs production',
);
if (smProductionDependencies.authorityReferences !== 0) {
  throw new Error(
    `sm.rs production must have exactly zero direct db authority references, found ${smProductionDependencies.authorityReferences}`,
  );
}
if (/\bstate\s*\.\s*pool\b/.test(smProductionSource)) {
  throw new Error('sm.rs production regained direct AppState PostgreSQL authority');
}
for (const [file, source] of [
  ['misc.rs', miscSource],
  ['sm.rs', smProtocolSource],
]) {
  for (const forbidden of [
    'lock_auth_generation',
    'commit_fast_in_transaction',
    'activate_claimed_sm_session_in_transaction',
    'transfer_claimed_sm_live_session_in_transaction',
    'set_active_privacy_list',
  ]) {
    if (new RegExp(`\\b(?:db\\s*::\\s*)?${forbidden}\\b`).test(source)) {
      throw new Error(
        `${file} regained a PostgreSQL bind/resume authority via ${forbidden}; external route awaits must remain outside DB transactions`,
      );
    }
  }
}
if (!/\.finalize_resource_binding\s*\(/.test(miscSource)) {
  throw new Error('misc.rs no longer uses the exact phase-two binding finalizer');
}
if (!/\.finalize_sm_resume\s*\(/.test(smProtocolSource)) {
  throw new Error('sm.rs no longer uses the atomic phase-two SM finalizer');
}

// ARCH-SVC XEP-0050/XEP-0133 administrative boundary: inline DB fixtures
// intentionally remain below `#[cfg(test)]`, but every production command
// must delegate persistence, audit and command lifecycle authority to the
// private AdminCommandService. Keep protocol code limited to form parsing,
// in-memory routing effects and stanza construction.
const commandsSource = read('src/xmpp/protocol/commands.rs');
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
  ['AppState pool access', /\bstate\s*\.\s*pool\b/],
  ['a PostgreSQL pool type', /\b(?:sqlx\s*::\s*)?PgPool\b/],
  ['raw SQL execution', /\bsqlx\s*::/],
]) {
  if (pattern.test(commandsProductionSource)) {
    throw new Error(`commands.rs production bypasses AdminCommandService through ${description}`);
  }
}
if (!/\.admin_command_service\s*\(\s*\)/.test(commandsProductionSource)) {
  throw new Error('commands.rs no longer routes persistence through admin_command_service()');
}
const adminCommandServiceSource = productionWithoutCfgTestModules(
  read('src/services/admin_commands.rs'),
  'admin_commands service',
);
const adminReadBoundary = structBody(
  adminCommandServiceSource,
  'impl AdminCommandService',
);
for (const required of [
  'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ',
  'auth_generation=$3',
  'is_admin AND NOT is_disabled',
  'FOR SHARE',
]) {
  if (!adminReadBoundary.includes(required)) {
    throw new Error(`AdminCommandService read authorization lost required boundary: ${required}`);
  }
}
for (const method of [
  'registered_account_count',
  'disabled_account_count',
  'registered_account_usernames',
  'disabled_account_usernames',
  'announcement_account_page',
  'administrator_usernames',
  'account_last_login',
  'account_roster',
  'account_statistics',
  'service_message_body',
  'federation_rule_domains',
]) {
  const declaration = `pub(crate) async fn ${method}`;
  const start = adminCommandServiceSource.indexOf(declaration);
  if (start < 0) throw new Error(`AdminCommandService lost sensitive read method ${method}`);
  const opening = adminCommandServiceSource.indexOf('{', start + declaration.length);
  const closing = matchingRustBrace(adminCommandServiceSource, opening);
  const body = adminCommandServiceSource.slice(opening + 1, closing);
  if (!body.includes('begin_authorized_read(actor)')) {
    throw new Error(`${method} no longer binds authorization and data to one transaction`);
  }
}
if (/db::roster\s*\(\s*&self\.pool/.test(adminReadBoundary)) {
  throw new Error('account_roster reopened the pool after administrative authorization');
}
if (!adminReadBoundary.includes('replace_federation_runtime_rules_command')) {
  throw new Error('federation rule replacement no longer returns its cache image atomically');
}

// ARCH-SVC XEP-0424/XEP-0444 boundary: protocol code may parse a retraction
// and map its typed result, but tombstone ownership, replay identity, archive
// writes and the optional S2S outbox share one RetractionService transaction.
// Test fixtures below `#[cfg(test)]` may create isolated rows directly; the
// production handler must never regain a PostgreSQL capability or hide one
// behind an imported/aliased database function.
const retractionsSource = read('src/xmpp/protocol/retractions.rs');
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
  ['AppState pool access', /\b(?:self\.)?state\s*\.\s*pool\b/],
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
const retractionServiceSource = read('src/services/retractions.rs');
const retractionServiceBody = structBody(
  retractionServiceSource,
  'pub(crate) struct RetractionService',
);
if (!/^\s*pool\s*:\s*PgPool\s*,?\s*$/m.test(retractionServiceBody)) {
  throw new Error('RetractionService PostgreSQL capability must remain a private PgPool field');
}
if (/^\s*pub(?:\(crate\))?\s+pool\s*:/m.test(retractionServiceBody)) {
  throw new Error('RetractionService must not expose its PostgreSQL capability');
}
for (const signature of retractionServiceSource.matchAll(
  /pub\(crate\)\s+(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)/gs,
)) {
  if (signature[1] !== 'new' && /\b(?:sqlx\s*::\s*)?PgPool\b/.test(signature[2])) {
    throw new Error('RetractionService must not accept a raw PostgreSQL capability');
  }
}
const retractionIntentMigration = read('migrations/0102_personal_retraction_intents.sql');
if (/\bpublic\s*\./i.test(retractionIntentMigration)) {
  throw new Error('retraction intent migration must remain search_path/schema safe');
}
for (const evidence of [
  'semantic_sha256',
  'semantic_sha512',
  'semantic_length',
  'owner_projection_sha256',
  'owner_projection_sha512',
  'owner_projection_length',
]) {
  if (!new RegExp(`\\b${evidence}\\b`).test(retractionIntentMigration)) {
    throw new Error(`retraction intent migration lost collision evidence ${evidence}`);
  }
}
if (/\b(?:semantic_value|payload_value|stanza)\s+(?:BYTEA|TEXT|VARCHAR)/i.test(retractionIntentMigration)) {
  throw new Error('retraction intent table must not persist plaintext semantic XML');
}
for (const projectionInvariant of [
  'CREATE TABLE personal_retraction_action_projections',
  'UNIQUE (intent_id, owner_id)',
  'ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED',
]) {
  if (!retractionIntentMigration.includes(projectionInvariant)) {
    throw new Error(`retraction projection snapshot lost invariant: ${projectionInvariant}`);
  }
}
const retractionOwnerIdentityMigration = read(
  'migrations/0119_personal_retraction_owner_identity.sql',
);
if (/\bpublic\s*\./i.test(retractionOwnerIdentityMigration)) {
  throw new Error('retraction owner identity migration must remain search_path/schema safe');
}
for (const ownerIdentityInvariant of [
  'owner_projection_key_id VARCHAR(16)',
  'owner_projection_mac BYTEA',
  'personal_retraction_intent_owner_evidence_check',
  'personal_retraction_intent_owner_key_idx',
  'DROP COLUMN peer_bare_jid',
  'message_archive_retraction_stanza_bucket_idx',
  'fence_personal_retraction_owner_identity',
]) {
  if (!retractionOwnerIdentityMigration.includes(ownerIdentityInvariant)) {
    throw new Error(
      `retraction owner identity migration lost invariant: ${ownerIdentityInvariant}`,
    );
  }
}
if (!/pg_catalog\.md5\s*\(\s*stanza_id\s*\)/.test(retractionOwnerIdentityMigration)) {
  throw new Error('retraction target index must use a bounded stanza-id bucket');
}
if (!/owner_projection_key_id\s*=\s*\$1/.test(read('src/db/abuse_keys.rs'))) {
  throw new Error('anti-abuse key retirement lost owner-topology references');
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
const archiveRepositorySource = read('src/db/archive.rs');
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

const abuseSource = read('src/abuse.rs');
for (const typeName of [
  'PersonalMessageContentKeyring',
  'PersonalRetractionContentKeyring',
]) {
  const body = structBody(abuseSource, `pub(crate) struct ${typeName}`);
  if (/^\s*pub(?:\(crate\))?\s+(?:generations|keys|secret)\s*:/m.test(body)) {
    throw new Error(`${typeName} exposed its derived content key material`);
  }
}
if (/pub(?:\(crate\))?\s+enum\s+ContentIdentityPurpose\b/.test(abuseSource)) {
  throw new Error('content identity purpose selection must remain private to AbuseGuard');
}
for (const requiredFactory of [
  'personal_message_content_keyring',
  'personal_retraction_content_keyring',
]) {
  if (!new RegExp(`fn\\s+${requiredFactory}\\s*\\(`).test(abuseSource)) {
    throw new Error(`AbuseGuard lost purpose-bound key derivation factory ${requiredFactory}`);
  }
}
const contentGenerationBody = structBody(abuseSource, 'fn content_identity_generations(');
if (!/\bpersistent_actor_key_candidates\s*\(\s*\)/.test(contentGenerationBody)) {
  throw new Error('durable content keys must derive only from authorized anti-abuse generations');
}
if (/\bapi_control\b|ApiControlKeyring/.test(contentGenerationBody)) {
  throw new Error('API control secrets must never be reused for durable content identity');
}
const sourceFilesNamingContentPurpose = [];
for (const directory of ['src/services', 'src/xmpp/protocol', 'src/db']) {
  const pending = [path.join(root, directory)];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(full);
      else if (entry.isFile() && entry.name.endsWith('.rs')) {
        const source = fs.readFileSync(full, 'utf8');
        if (/\bContentIdentityPurpose\b/.test(source)) {
          sourceFilesNamingContentPurpose.push(path.relative(root, full));
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
const keyedMessageServiceSource = read('src/services/messaging.rs');
for (const [serviceName, body, expectedKeyring] of [
  ['MessageService', structBody(keyedMessageServiceSource, 'pub(crate) struct MessageService'), 'PersonalMessageContentKeyring'],
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
  .map((name) => fs.readFileSync(path.join(protocolDirectory, name), 'utf8'))
  .join('\n');
if (/\b(?:PersonalMessageContentKeyring|PersonalRetractionContentKeyring)\b/.test(keyedProtocolSource)) {
  throw new Error('protocol tree must not receive durable content-key capabilities');
}
const retractionProductionSource = productionWithoutCfgTestModules(
  retractionServiceSource,
  'retractions service production',
);
const retractionIntentInserts = [...retractionProductionSource.matchAll(
  /INSERT\s+INTO\s+personal_retraction_intents\s*\(([^)]*)\)/gsi,
)];
if (retractionIntentInserts.length !== 1) {
  throw new Error(`RetractionService must have one reviewed intent insert, found ${retractionIntentInserts.length}`);
}
const retractionIntentInsertColumns = retractionIntentInserts[0][1];
for (const keyedColumn of ['semantic_key_id', 'semantic_mac']) {
  if (!new RegExp(`\\b${keyedColumn}\\b`).test(retractionIntentInsertColumns)) {
    throw new Error(`new retraction intent writes lost keyed column ${keyedColumn}`);
  }
}
if (/\b(?:semantic_sha256|semantic_sha512|semantic_length)\b/.test(retractionIntentInsertColumns)) {
  throw new Error('new retraction intent writes must never use legacy semantic evidence columns');
}
const abuseKeyRepositorySource = read('src/db/abuse_keys.rs');
for (const retirementReference of [
  'FROM personal_message_admissions',
  'WHERE payload_key_id=$1',
  'FROM personal_retraction_intents',
  'WHERE semantic_key_id=$1',
]) {
  if (!abuseKeyRepositorySource.includes(retirementReference)) {
    throw new Error(`anti-abuse key retirement fence lost content identity reference: ${retirementReference}`);
  }
}

// ARCH-SVC runtime secret boundary. Protocol modules may request semantic
// operations from services/AppState methods, but must never name or traverse
// long-lived configuration material directly.
const protocolSource = protocolFiles
  .map((name) => fs.readFileSync(path.join(protocolDirectory, name), 'utf8'))
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

const extdiscoProtocol = read('src/xmpp/protocol/extdisco.rs');
if (!/\.extdisco_service\s*\(\s*\)/.test(extdiscoProtocol)) {
  throw new Error('extdisco.rs no longer delegates TURN credential authority to ExtDiscoService');
}
const extdiscoService = read('src/services/extdisco.rs');
const extdiscoInner = structBody(extdiscoService, 'struct ExtDiscoInner');
if (!/^\s*turn_shared_secret\s*:\s*Option<Zeroizing<Vec<u8>>>\s*,/m.test(extdiscoInner)) {
  throw new Error('ExtDiscoService TURN key must remain a private Zeroizing byte buffer');
}
if (/^\s*pub(?:\(crate\))?\s+turn_shared_secret\s*:/m.test(extdiscoInner)) {
  throw new Error('ExtDiscoService exposed its long-lived TURN key');
}

// ARCH-SVC personal-message vertical slice (2026-08-30): routing code may
// import domain value types, but all PostgreSQL authority must pass through
// the private MessageService capability. This is a semantic boundary rather
// than only a repository-wide count budget.
const messagingSource = read('src/xmpp/protocol/messaging.rs');
if (/state\s*\.\s*pool/.test(messagingSource)) {
  throw new Error('messaging.rs regained direct AppState PostgreSQL authority');
}
for (const forbidden of [
  'admit_personal_history',
  'admit_outbound_personal_history',
  'store_offline_idempotent',
  'archive_allowed',
  'is_blocked_for_account',
  'privacy_denies',
  'find_user',
]) {
  if (new RegExp(`\\bdb::${forbidden}\\b`).test(messagingSource)) {
    throw new Error(`messaging.rs bypasses MessageService via db::${forbidden}`);
  }
}
const messageServiceSource = read('src/services/messaging.rs');
const localRecipient = structBody(messageServiceSource, 'pub(crate) struct LocalRecipient');
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
if (/Deliver\s*\(\s*db::User\s*\)/.test(messageServiceSource)) {
  throw new Error('MessageService leaks the persistence User credential model to routing code');
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
  `Architecture boundary budgets passed: AppState=${publicFields} public fields, ` +
    `protocol=${protocolDbAuthorityReferences} db authority refs / ` +
    `${protocolDbDomainReferences} db domain-model refs / ` +
    `${protocolStatePoolReferences} state.pool / ${protocolSqlxReferences} sqlx:: / ` +
    `${protocolPgPoolReferences} PgPool refs; authority: ${largestAuthority}; ` +
    `domain: ${largestDomain}`,
);
