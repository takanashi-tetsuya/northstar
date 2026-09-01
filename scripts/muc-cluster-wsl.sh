#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Fail before starting any runtime when the authoritative schema/source shape
# was accidentally weakened. These checks complement, but never replace, the
# disposable PostgreSQL and two-node fault scenarios below.
grep -q "terminal MUC occupancy cannot be revived" \
  "$project_dir/migrations/0089_cluster_muc_authority.sql"
grep -q "cluster_muc_room_outbox_capacity_underflow" \
  "$project_dir/migrations/0089_cluster_muc_authority.sql"
grep -q "muc_rooms_live_localpart_unique" \
  "$project_dir/migrations/0089_cluster_muc_authority.sql"
grep -q "CHECK (event_id = operation_id)" \
  "$project_dir/migrations/0089_cluster_muc_authority.sql"
grep -q "northstar_purge_cluster_muc_history" \
  "$project_dir/migrations/0089_cluster_muc_authority.sql"
grep -q "northstar_muc_capacity_destroy_update" \
  "$project_dir/migrations/0090_deployment_capacity_ledger.sql"
grep -q "northstar_capacity_lock_batch" \
  "$project_dir/migrations/0090_deployment_capacity_ledger.sql"
grep -q "PRIMARY KEY(delivery_id,handoff_version)" \
  "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql"
grep -q "cluster MUC handoff destination is not authoritative" \
  "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql"
grep -q "cluster MUC handoff has no exact authoritative history" \
  "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql"
grep -q "REVOKE ALL ON FUNCTION northstar_transfer_cluster_muc_outbox" \
  "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql"
if grep -q "northstar.cluster_muc_resume_handoff" \
  "$project_dir/migrations/0094_cluster_muc_delivery_receipts.sql" \
  "$project_dir/src/db/cluster_muc.rs"; then
  echo "cluster MUC handoff must not trust a caller-controlled GUC" >&2
  exit 1
fi
grep -q "parent.claim_token=\$4" "$project_dir/src/db/cluster_muc.rs"
grep -q "lease_until>clock_timestamp()" "$project_dir/src/db/cluster_muc.rs"
grep -q "first_owned_at+INTERVAL '5 minutes'" \
  "$project_dir/migrations/0096_bosh_ack_ownership_bounds.sql"
grep -q "northstar_admit_cluster_envelope_replay" \
  "$project_dir/migrations/0095_cluster_replay_fence.sql"
grep -q "existing.destination_instance_uuid<>p_destination_uuid" \
  "$project_dir/migrations/0095_cluster_replay_fence.sql"
grep -q "ON CONFLICT (localpart) WHERE destroyed_at IS NULL DO NOTHING" \
  "$project_dir/src/db/muc.rs"
grep -q "lease_until>clock_timestamp()" \
  "$project_dir/src/db/cluster_muc.rs"
grep -q "protocol-v8 executable MUC control rejected" \
  "$project_dir/src/cluster.rs"
grep -q "cluster_muc_delivery_recipient_snapshot" \
  "$project_dir/src/cluster.rs"
grep -q "mutate_cluster_muc_registration" \
  "$project_dir/src/db/cluster_muc.rs"
grep -q "grant_cluster_muc_invitation_in_tx" \
  "$project_dir/src/db/cluster_muc.rs"
grep -q '"offline_affiliation"' \
  "$project_dir/src/cluster.rs"

redis_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
redis_dir="$(mktemp -d -t northstar-muc-redis-XXXXXX)"
redis_pid=""

cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "$redis_pid" ]] && kill -0 "$redis_pid" 2>/dev/null; then
    kill "$redis_pid"
    wait "$redis_pid" 2>/dev/null || true
  fi
  case "$redis_dir" in
    /tmp/northstar-muc-redis-*) rm -rf -- "$redis_dir" ;;
    *) echo "refusing to remove unexpected MUC Redis directory: $redis_dir" >&2; exit_code=1 ;;
  esac
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

redis-server \
  --bind 127.0.0.1 \
  --port "$redis_port" \
  --save '' \
  --appendonly no \
  --protected-mode yes \
  --dir "$redis_dir" \
  >"$redis_dir/redis.log" 2>&1 &
redis_pid="$!"

for _ in $(seq 1 50); do
  if redis-cli -h 127.0.0.1 -p "$redis_port" ping >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
redis-cli -h 127.0.0.1 -p "$redis_port" ping >/dev/null

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi

export TEST_REDIS_URL="redis://127.0.0.1:$redis_port/"
cargo test --locked --offline db::cluster_muc::tests:: -- --nocapture
cargo test --locked --offline \
  cluster::tests::redis_muc_nickname_and_voice_mutations_reject_conflicts_and_aba \
  -- --ignored --nocapture

echo "CLU-MUC static fences and pure state models passed; run scripts/cluster-wsl.sh for the disposable PostgreSQL/two-node Redis outage matrix"
