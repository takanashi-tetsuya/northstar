#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_literal() {
  local source_file="$1" literal="$2" contract="$3"
  if ! grep -Fq -- "$literal" "$source_file"; then
    echo "MUC cluster static contract is missing: $contract ($source_file: $literal)" >&2
    exit 1
  fi
}

# Fail before starting any runtime when the authoritative schema/source shape
# was accidentally weakened. These checks complement, but never replace, the
# disposable PostgreSQL and two-node fault scenarios below.
require_literal "$project_dir/migrations/0089_cluster_muc_authority.sql" \
  "terminal MUC occupancy cannot be revived" "terminal occupancy fence"
require_literal "$project_dir/migrations/0089_cluster_muc_authority.sql" \
  "cluster_muc_room_outbox_capacity_underflow" "outbox capacity underflow guard"
require_literal "$project_dir/migrations/0089_cluster_muc_authority.sql" \
  "muc_rooms_live_localpart_unique" "live-room uniqueness constraint"
require_literal "$project_dir/migrations/0089_cluster_muc_authority.sql" \
  "CHECK (event_id = operation_id)" "operation/event identity fence"
require_literal "$project_dir/migrations/0089_cluster_muc_authority.sql" \
  "northstar_purge_cluster_muc_history" "bounded history purge authority"
require_literal "$project_dir/migrations/0090_deployment_capacity_ledger.sql" \
  "northstar_muc_capacity_destroy_update" "room destruction capacity authority"
require_literal "$project_dir/migrations/0090_deployment_capacity_ledger.sql" \
  "northstar_capacity_lock_batch" "ordered capacity lock authority"
require_literal "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql" \
  "PRIMARY KEY(delivery_id,handoff_version)" "exact delivery handoff identity"
require_literal "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql" \
  "cluster MUC handoff destination is not authoritative" "handoff destination authority fence"
require_literal "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql" \
  "cluster MUC handoff has no exact authoritative history" "handoff history authority fence"
require_literal "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql" \
  "REVOKE ALL ON FUNCTION northstar_transfer_cluster_muc_outbox" "outbox mutation privilege revocation"
if grep -Fq -- "northstar.cluster_muc_resume_handoff" \
  "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql" \
  "$project_dir/src/db/cluster_muc.rs"; then
  echo "cluster MUC handoff must not trust a caller-controlled GUC" >&2
  exit 1
fi
require_literal "$project_dir/src/db/cluster_muc.rs" \
  'parent.claim_token=$4' "parent claim-token fence"
require_literal "$project_dir/src/db/cluster_muc.rs" \
  'lease_until>clock_timestamp()' "lease ownership predicate"
require_literal "$project_dir/migrations/0096_bosh_ack_ownership_bounds.sql" \
  "first_owned_at+INTERVAL '5 minutes'" "bounded first-owner interval"
require_literal "$project_dir/migrations/0095_cluster_replay_fence.sql" \
  "northstar_admit_cluster_envelope_replay" "cluster replay admission fence"
require_literal "$project_dir/migrations/0095_cluster_replay_fence.sql" \
  "existing.destination_instance_uuid<>p_destination_uuid" "destination instance replay fence"
require_literal "$project_dir/src/db/muc.rs" \
  "ON CONFLICT (localpart) WHERE destroyed_at IS NULL DO NOTHING" "live-room create idempotency"
require_literal "$project_dir/src/cluster.rs" \
  "executable MUC control rejected" "untrusted executable MUC control rejection"
require_literal "$project_dir/src/cluster.rs" \
  "cluster_muc_delivery_recipient_snapshot" "recipient snapshot authority"
require_literal "$project_dir/src/db/cluster_muc.rs" \
  "mutate_cluster_muc_registration" "membership mutation authority"
require_literal "$project_dir/src/db/cluster_muc.rs" \
  "grant_cluster_muc_invitation_in_tx" "invitation mutation authority"
require_literal "$project_dir/src/cluster.rs" \
  '"offline_affiliation"' "offline affiliation projection"

redis_dir="$(mktemp -d -t northstar-muc-redis-XXXXXX)"
chmod 700 "$redis_dir"
if [[ "$(stat -c '%a' "$redis_dir")" != "700" ]]; then
  echo "MUC Redis runtime directory must be private: $redis_dir" >&2
  exit 1
fi
redis_socket="$redis_dir/redis.sock"
redis_pid=""

cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "$redis_pid" ]] && kill -0 "$redis_pid" 2>/dev/null; then
    kill "$redis_pid"
    wait "$redis_pid" 2>/dev/null || true
  fi
  socket_remains=0
  if [[ -e "$redis_socket" || -L "$redis_socket" ]]; then
    socket_remains=1
    echo "MUC Redis socket remained after its owned process stopped: $redis_socket" >&2
    exit_code=1
  fi
  case "$redis_dir" in
    /tmp/northstar-muc-redis-*) rm -rf -- "$redis_dir" ;;
    *) echo "refusing to remove unexpected MUC Redis directory: $redis_dir" >&2; exit_code=1 ;;
  esac
  if [[ -e "$redis_dir" ]]; then
    echo "MUC Redis runtime directory remained after cleanup: $redis_dir" >&2
    exit_code=1
  fi
  echo "MUC Redis cleanup: socket_remains=$socket_remains"
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

redis-server \
  --port 0 \
  --unixsocket "$redis_socket" \
  --unixsocketperm 700 \
  --save '' \
  --appendonly no \
  --protected-mode yes \
  --dir "$redis_dir" \
  >"$redis_dir/redis.log" 2>&1 &
redis_pid="$!"

# Readiness is determined solely by a successful command over the exact
# private Unix socket.  The short polling interval only avoids a busy loop;
# there is no fixed startup delay that could mask a failed Redis child.
redis_ready=false
for _ in $(seq 1 50); do
  if redis-cli --socket "$redis_socket" ping >/dev/null 2>&1; then
    redis_ready=true
    break
  fi
  if ! kill -0 "$redis_pid" 2>/dev/null; then
    echo "MUC Redis exited before publishing its Unix socket" >&2
    tail -n 160 "$redis_dir/redis.log" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [[ "$redis_ready" != "true" ]]; then
  echo "MUC Redis did not become ready on its Unix socket" >&2
  tail -n 160 "$redis_dir/redis.log" >&2 || true
  exit 1
fi
[[ -S "$redis_socket" ]] || {
  echo "MUC Redis readiness succeeded without a Unix-domain socket: $redis_socket" >&2
  exit 1
}
if [[ "$(stat -c '%a' "$redis_socket")" != "700" ]]; then
  echo "MUC Redis socket permissions are not private: $redis_socket" >&2
  exit 1
fi

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi

# `redis+unix:///absolute/path` is the Rust redis client syntax accepted by
# Config's local Unix-socket transport validation.
export TEST_REDIS_URL="redis+unix://$redis_socket"
cargo test --locked --offline db::cluster_muc::tests:: -- --nocapture
cargo test --locked --offline \
  cluster::tests::redis_muc_nickname_and_voice_mutations_reject_conflicts_and_aba \
  -- --ignored --nocapture

echo "CLU-MUC static fences and pure state models passed; run scripts/cluster-wsl.sh for the disposable PostgreSQL/two-node Redis outage matrix"
