import fs from "node:fs";
import assert from "node:assert/strict";
import { readProductionModule, readRoleSplitFile } from "./lib/source-module.mjs";

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
  const start = code.search(/\bpub\s+async\s+fn\s+associate_local_muc_sm_session\s*(?:<[^>{]*>)?\s*\(/);
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

const protocol = readRoleSplitFile("crates/edges/northstar-stream/src/protocol.rs");
const protocolTests = read("crates/edges/northstar-stream/src/protocol/legacy_sasl_wire_tests.rs");
const transport = read("crates/edges/northstar-c2s/src/lib.rs");
const bosh = readRoleSplitFile("crates/edges/northstar-bosh/src/lib.rs");
const replay = read("crates/contexts/session/northstar-session-application/src/replay.rs");
const sasl2 = readProductionModule("crates/edges/northstar-stream/src/protocol/sasl2.rs");
const resume = readProductionModule("crates/contexts/room/northstar-muc-xmpp/src/resume.rs");

verifyMucSmAssociationBoundary(resume);
// Keep the production ownership boundary tied to the helper's runtime test.
// Cloning an iterator item alone still leaves its shard guard in the iterator.
const snapshotLoop = /for\s*\(\s*room_jid\s*,\s*membership\s*\)\s+in\s+local_muc_membership_snapshots\s*\(\s*memberships\s*\)\s*\{/;
requireMatch(resume, snapshotLoop, "MUC SM association mutation fixture no longer matches");
for (const [name, replacement] of [
  ["live iterator", "for membership in memberships {"],
  ["cloned but uncollected iterator", "for (room_jid, membership) in memberships.iter().map(|entry| (entry.key().clone(), entry.value().clone())) {"],
  ["discarded snapshot", "let _ = local_muc_membership_snapshots(memberships); for membership in memberships {"],
  ["comment-only snapshot", "// for (room_jid, membership) in local_muc_membership_snapshots(memberships) {\nfor membership in memberships {"],
]) {
  assert.throws(
    () => verifyMucSmAssociationBoundary(resume.replace(snapshotLoop, replacement)),
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
  protocolTests,
  /drop_requires_local_quiesce\(false, 1\)/,
  "the cancellation-after-cleanup-claim regression test is missing",
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
// the histogram handle. A clone here would keep the entire ServerNode alive.
if (/self\.host\.clone\(\)|Arc::clone\(&self\.host\)/.test(sasl2)) {
  throw new Error("SASL2 session work regained an owned ServerNode clone");
}

console.log("session lifecycle and durable transport authority boundaries are intact");

// The frame runner is the production ingress, not an optional observer beside
// transport-specific handling. Behavioral timeout/cancellation tests live in
// frame_execution.rs; these mutation checks prevent adapter bypass drift.
function verifyFrameExecutionIngress(boshSource) {
  if (/\bprotocol\.handle\s*\(/.test(boshSource)) {
    throw new Error('BOSH bypassed the owned frame execution boundary');
  }
  if ((boshSource.match(/self\.protocol\.process_frame\(payload\)/g) ?? []).length !== 1) {
    throw new Error('BOSH must enter the canonical frame runner exactly once');
  }
}
verifyFrameExecutionIngress(bosh);
for (const boshSource of [
  bosh.replace('self.protocol.process_frame(payload)', 'self.protocol.handle(payload)'),
]) {
  let rejected = false;
  try { verifyFrameExecutionIngress(boshSource); } catch { rejected = true; }
  if (!rejected) throw new Error('frame-runner bypass mutation was not rejected');
}
console.log('canonical frame ingress and bypass mutations are intact');
