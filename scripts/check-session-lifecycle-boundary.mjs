import fs from "node:fs";
import assert from "node:assert/strict";

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

function requireMatch(value, pattern, message) {
  if (!pattern.test(value)) throw new Error(message);
}

function verifyMucSmAssociationBoundary(source) {
  // Inspect only this production function, not its helper, tests, comments or
  // diagnostics. Preserve offsets while masking comments and string literals.
  const code = source.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\/|"(?:\\.|[^"\\])*"/g,
    (text) => text.replace(/[^\n]/g, " "));
  const start = code.search(/\bpub\s+async\s+fn\s+associate_local_muc_sm_session\s*\(/);
  if (start < 0) throw new Error("MUC SM association function is missing");
  const open = code.indexOf("{", start);
  let depth = 0;
  let body;
  for (let index = open; index < code.length; index++) {
    if (code[index] === "{") depth++;
    if (code[index] === "}" && --depth === 0) {
      body = code.slice(open + 1, index);
      break;
    }
  }
  if (body === undefined) throw new Error("MUC SM association function is unterminated");
  requireMatch(
    body,
    /\bfor\s*\([^{};]+\)\s+in\s+local_muc_membership_snapshots\s*\(\s*memberships\s*\)\s*\{/,
    "MUC SM association must iterate owned membership snapshots before backend awaits",
  );
}

const protocol = read("src/xmpp/protocol.rs");
const transport = read("src/xmpp/mod.rs");
const bosh = read("src/bosh.rs");
const replay = read("src/services/replay.rs");
const sasl2 = read("src/xmpp/protocol/sasl2.rs");
const state = read("src/state.rs");

verifyMucSmAssociationBoundary(state);
// Keep the production ownership boundary tied to the helper's runtime test.
// Cloning an iterator item alone still leaves its shard guard in the iterator.
const snapshotLoop = /for\s*\(\s*room_jid\s*,\s*membership\s*\)\s+in\s+local_muc_membership_snapshots\s*\(\s*memberships\s*\)\s*\{/;
requireMatch(state, snapshotLoop, "MUC SM association mutation fixture no longer matches");
for (const [name, replacement] of [
  ["live iterator", "for membership in memberships {"],
  ["cloned but uncollected iterator", "for (room_jid, membership) in memberships.iter().map(|entry| (entry.key().clone(), entry.value().clone())) {"],
  ["discarded snapshot", "let _ = local_muc_membership_snapshots(memberships); for membership in memberships {"],
  ["comment-only snapshot", "// for (room_jid, membership) in local_muc_membership_snapshots(memberships) {\nfor membership in memberships {"],
]) {
  assert.throws(
    () => verifyMucSmAssociationBoundary(state.replace(snapshotLoop, replacement)),
    /MUC SM association must iterate owned membership snapshots/,
    `MUC SM association boundary accepted ${name}`,
  );
}

const dropStart = protocol.indexOf("fn synchronous_drop_fallback");
const dropEnd = protocol.indexOf("#[cfg(test)]", dropStart);
if (dropStart < 0 || dropEnd < 0) throw new Error("ProtocolSession Drop block is missing");
const dropBody = protocol.slice(dropStart, dropEnd);
for (const forbidden of ["tokio::spawn", "db::", ".await", ".federation", ".cluster."]) {
  if (dropBody.includes(forbidden)) {
    throw new Error(`ProtocolSession Drop regained forbidden async authority: ${forbidden}`);
  }
}

requireMatch(
  protocol,
  /claim_session_cleanup[\s\S]*service\.quiesce\(plan\);[\s\S]*local_quiesced = true;[\s\S]*abort_and_drain/,
  "local ownership must be quiesced without an await before finalizer cancellation becomes safe",
);
requireMatch(
  protocol,
  /JoinSet<&'static str>[\s\S]*MAX_POST_ACTION_TASKS_PER_SESSION[\s\S]*abort_all\(\)[\s\S]*join_next\(\)/,
  "post-transport work must remain bounded, owned, aborted and drained",
);
requireMatch(
  protocol,
  /drop_requires_local_quiesce\(false, 1\)/,
  "the cancellation-after-cleanup-claim regression test is missing",
);

const nativeFinalizers =
  transport.match(/finish_protocol_session\(&mut session, transport\)(?:\.await)?/g) ?? [];
if (nativeFinalizers.length !== 3) {
  throw new Error(`expected exact TCP, Direct TLS and WebSocket finalizers; found ${nativeFinalizers.length}`);
}
requireMatch(
  transport,
  /async fn finish_protocol_session[\s\S]*AssertUnwindSafe\(session\.finalize\(\)\)\.catch_unwind\(\)\.await[\s\S]*resume_unwind/,
  "the shared native-transport finalizer must observe cleanup failures and panics",
);
requireMatch(
  bosh,
  /self\.manager\.remove\(&self\.session_key\);[\s\S]*release_bosh_fences[\s\S]*self\.protocol\.finalize\(\)\.await/,
  "BOSH actor exits must stop admission, release response fences and finalize exactly once",
);
if (transport.includes("crate::db::replay") || bosh.includes("crate::db::replay")) {
  throw new Error("C2S transports regained direct durable replay database authority");
}
for (const capability of [
  "fence_socket_write",
  "acknowledge_socket_write",
  "renew_bosh_fences",
  "acknowledge_bosh_responses",
  "bind_bosh_response",
  "release_bosh_fences",
]) {
  if (!replay.includes(`fn ${capability}`)) {
    throw new Error(`ReplayService is missing transport capability ${capability}`);
  }
}

// Authentication timing spans mutable SASL2 session work, but it only needs
// the histogram handle. A clone here would keep the entire AppState alive.
if (/self\.state\.clone\(\)|Arc::clone\(&self\.state\)/.test(sasl2)) {
  throw new Error("SASL2 session work regained an owned AppState clone");
}
const sasl2Timers = sasl2.match(/self\.state\.sasl2_authentication_timer\(\)/g) ?? [];
if (sasl2Timers.length !== 3) {
  throw new Error(`expected owned timers for SASL2 authenticate, response and abort; found ${sasl2Timers.length}`);
}
for (const entry of [
  "authenticate2(&mut self, root: Node<'_, '_>) -> Result<Action>",
  "sasl2_response(&mut self, root: Node<'_, '_>) -> Result<Action>",
  "sasl2_abort(&mut self, root: Node<'_, '_>) -> Action",
]) {
  const start = sasl2.indexOf(entry);
  if (start < 0) throw new Error(`SASL2 entry ${entry} is missing`);
  requireMatch(
    sasl2.slice(start + entry.length),
    /^\s*\{\s*let _authentication_timer = self\.state\.sasl2_authentication_timer\(\);/,
    `${entry} must start its owned timer before any early return`,
  );
}

const startTlsTransition = transport.indexOf("STARTTLS is a transport transition");
const tcpFinalize = transport.indexOf(
  "finish_protocol_session(&mut session, transport).await",
  startTlsTransition,
);
if (startTlsTransition < 0 || tcpFinalize < startTlsTransition) {
  throw new Error("STARTTLS must retain the same ProtocolSession until the upgraded transport exits");
}

console.log("session lifecycle and durable transport authority boundaries are intact");

// The frame runner is the production ingress, not an optional observer beside
// transport-specific handling. Behavioral timeout/cancellation tests live in
// frame_execution.rs; these mutation checks prevent adapter bypass drift.
function verifyFrameExecutionIngress(nativeSource, boshSource) {
  if (/\b(?:session|protocol)\.handle\s*\(/.test(nativeSource)
      || /\bprotocol\.handle\s*\(/.test(boshSource)) {
    throw new Error('C2S transports bypassed the owned frame execution boundary');
  }
  if ((nativeSource.match(/session\.process_frame\(&frame\)/g) ?? []).length !== 2
      || (boshSource.match(/self\.protocol\.process_frame\(payload\)/g) ?? []).length !== 1) {
    throw new Error('TCP, WebSocket and BOSH must all enter the canonical frame runner');
  }
}
verifyFrameExecutionIngress(transport, bosh);
for (const [nativeSource, boshSource] of [
  [transport.replace('session.process_frame(&frame)', 'session.handle(&frame)'), bosh],
  [transport, bosh.replace('self.protocol.process_frame(payload)', 'self.protocol.handle(payload)')],
]) {
  let rejected = false;
  try { verifyFrameExecutionIngress(nativeSource, boshSource); } catch { rejected = true; }
  if (!rejected) throw new Error('frame-runner bypass mutation was not rejected');
}
console.log('canonical frame ingress and bypass mutations are intact');
