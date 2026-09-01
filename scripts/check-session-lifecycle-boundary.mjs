import fs from "node:fs";

function read(path) {
  return fs.readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

function requireMatch(value, pattern, message) {
  if (!pattern.test(value)) throw new Error(message);
}

const protocol = read("src/xmpp/protocol.rs");
const transport = read("src/xmpp/mod.rs");
const bosh = read("src/bosh.rs");
const replay = read("src/services/replay.rs");

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

const startTlsTransition = transport.indexOf("STARTTLS is a transport transition");
const tcpFinalize = transport.indexOf(
  "finish_protocol_session(&mut session, transport).await",
  startTlsTransition,
);
if (startTlsTransition < 0 || tcpFinalize < startTlsTransition) {
  throw new Error("STARTTLS must retain the same ProtocolSession until the upgraded transport exits");
}

console.log("session lifecycle and durable transport authority boundaries are intact");
