#!/usr/bin/env bash
set -euo pipefail
set +x

# Join the two isolated Northstar guests to one signed Redis control plane.
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
binary=$project_dir/target/debug/rust-xmpp-server
key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -x $binary && -f $key ]] || { echo 'candidate binary or lab SSH key missing' >&2; exit 2; }
bash "$project_dir/scripts/local-vm-lab-preflight.sh" >/dev/null

ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts")
lease_ip() {
  local vm=northstar-lab-$1 ip
  ip=$(virsh net-dhcp-leases northstar-lab |
    awk -v vm="$vm" '$6 == vm { split($5, parts, "/"); print parts[1] }')
  [[ $ip =~ ^192\.168\.197\.[0-9]+$ ]] || return 1
  printf '%s' "$ip"
}
a=lab@$(lease_ip ns-a)
b=lab@$(lease_ip ns-b)
infra=lab@$(lease_ip infra)

# Persist identity across reruns. A new key must not silently replace the
# PostgreSQL signing authority for a live node.
keys=/tmp/northstar-lab/cluster-keys
mkdir -p "$keys"
chmod 700 "$keys"
for node in ns-a ns-b; do
  private=$keys/$node.pkcs8.b64
  public=$keys/$node.public.b64
  if [[ ! -e $private && ! -e $public ]]; then
    remote=$a
    [[ $node == ns-b ]] && remote=$b
    if ssh "${ssh_opts[@]}" "$remote" \
      'test -e /home/lab/northstar/secrets/cluster-signing.pkcs8.b64'; then
      echo "host signing identity for $node is missing; refusing key rotation" >&2
      exit 1
    fi
    node "$project_dir/scripts/generate-cluster-signing-key.mjs" "$private" "$public" >/dev/null
  fi
  [[ -f $private && -f $public && ! -L $private && ! -L $public ]] || {
    echo "incomplete signing identity for $node" >&2
    exit 1
  }
done

bash "$project_dir/scripts/local-vm-lab-redis.sh"
bash "$project_dir/scripts/local-vm-lab-minio-bucket.sh"
authority=$(ssh "${ssh_opts[@]}" "$infra" \
  'sudo -u postgres psql -d xmpp --no-psqlrc -Atqc "SELECT storage_backend FROM upload_storage_authority WHERE singleton"')
[[ $authority == s3 ]] || { echo 'both nodes require committed S3 upload authority' >&2; exit 1; }

ssh "${ssh_opts[@]}" "$a" 'sudo systemctl stop northstar-lab.service'
ssh "${ssh_opts[@]}" "$b" 'sudo systemctl stop northstar-lab.service 2>/dev/null || true'
ssh "${ssh_opts[@]}" "$b" 'install -d -m 700 /home/lab/northstar/secrets'
ssh "${ssh_opts[@]}" "$infra" \
  'sudo tar -C /etc/northstar/secrets -cf - migrator_database_url runtime_database_url storage_database_url command_database_url dialback_secret fast_token_secret dummy_scram_secret abuse_state_hmac_key api_control_secret metrics_bearer_token' |
  ssh "${ssh_opts[@]}" "$b" \
    'umask 077; tar --no-same-owner -C /home/lab/northstar/secrets -xf -'
ssh "${ssh_opts[@]}" "$b" 'python3 - <<'"'"'PY'"'"'
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

for name in ("migrator", "runtime", "storage", "command"):
    path = Path("/home/lab/northstar/secrets") / f"{name}_database_url"
    parsed = urlsplit(path.read_text().strip())
    if parsed.hostname != "postgres" or parsed.query or parsed.fragment or not parsed.netloc.endswith(":5432"):
        raise SystemExit("unexpected lab database URL structure")
    credentials = parsed.netloc.rsplit("@", 1)[0]
    if credentials == parsed.netloc:
        raise SystemExit("missing database credentials")
    path.write_text(urlunsplit((parsed.scheme, f"{credentials}@infra.lab.test:5432",
        parsed.path, "sslmode=verify-full&sslrootcert=/etc/northstar-lab-pki/ca.pem", "")) + "\n")
    path.chmod(0o600)
PY'

# This guest serves the same XMPP domain, so it uses the lab domain's
# certificate. Its Redis client certificate remains guest-specific.
ssh "${ssh_opts[@]}" "$a" \
  'sudo tar -C /etc/northstar-lab-pki -cf - ns-a.pem ns-a.key' |
  ssh "${ssh_opts[@]}" "$b" 'sudo tar -C /etc/northstar-lab-pki -xf -'
ssh "${ssh_opts[@]}" "$b" \
  'sudo chown lab:lab /etc/northstar-lab-pki/ns-a.key; sudo chmod 640 /etc/northstar-lab-pki/ns-a.key; cat /etc/northstar-lab-pki/ns-a.pem /etc/northstar-lab-pki/ca.pem > /home/lab/northstar/fullchain.pem; chmod 644 /home/lab/northstar/fullchain.pem'

scp "${ssh_opts[@]}" "$binary" "$b:/home/lab/northstar/rust-xmpp-server"
ssh "${ssh_opts[@]}" "$a" \
  'sudo cat /etc/systemd/system/northstar-lab.service' |
  sed 's@serve standalone@serve core@' |
  ssh "${ssh_opts[@]}" "$b" \
    'sudo tee /etc/systemd/system/northstar-lab.service >/dev/null'

for entry in "ns-a $a" "ns-b $b"; do
  read -r node remote <<<"$entry"
  peer=ns-a
  [[ $node == ns-a ]] && peer=ns-b
  scp "${ssh_opts[@]}" "$keys/$node.pkcs8.b64" \
    "$remote:/home/lab/northstar/secrets/cluster-signing.pkcs8.b64"
  ssh "${ssh_opts[@]}" "$infra" \
    'sudo sh -c '"'"'printf "rediss://northstar:%s@infra.lab.test:6379/\n" "$(cat /etc/northstar-lab-redis/password)"'"'"'' |
    ssh "${ssh_opts[@]}" "$remote" \
      'umask 077; cat > /home/lab/northstar/secrets/redis-url'
  ssh "${ssh_opts[@]}" "$infra" 'sudo python3 - <<'"'"'PY'"'"'
import json
from pathlib import Path
root = Path("/etc/northstar-lab-minio")
print(json.dumps({"generation": 1, "access_key_id": (root / "access-key").read_text().strip(),
    "secret_access_key": (root / "secret-key").read_text().strip()}))
PY' | ssh "${ssh_opts[@]}" "$remote" \
    'umask 077; cat > /home/lab/northstar/secrets/s3-credentials.json'
  ssh "${ssh_opts[@]}" "$remote" \
    "umask 077; cp /etc/northstar-lab-pki/ca.pem /home/lab/northstar/secrets/redis-ca.pem; cp /etc/northstar-lab-pki/$node.pem /home/lab/northstar/secrets/redis-client.pem; cp /etc/northstar-lab-pki/$node.key /home/lab/northstar/secrets/redis-client.key; chmod 600 /home/lab/northstar/secrets/redis-*.pem /home/lab/northstar/secrets/redis-client.key"
  peer_public=$(tr -d '\r\n' <"$keys/$peer.public.b64")
  [[ $peer_public =~ ^[A-Za-z0-9_-]+$ ]] || exit 1
  printf '{"namespace":"ns-a.lab.test","nodes":[{"node_id":"%s","key_epoch":1,"current_public_key":"%s","allowed_kinds":["ack","direct_delivery","blocking_presence","presence_probe","session_teardown","account_generation_teardown","user_agent_replacement","sm_session_teardown","sm_muc_teardown","muc_broadcast","muc_private","muc_presence","muc_nickname_change","muc_role_change","muc_evict","muc_destroy","muc_operation_wake"]}]}\n' \
    "$peer" "$peer_public" |
    ssh "${ssh_opts[@]}" "$remote" \
      'umask 077; cat > /home/lab/northstar/secrets/cluster-peers.json'
  ssh "${ssh_opts[@]}" "$remote" "sudo bash -s -- '$node'" <<'GUEST'
set -euo pipefail
node=$1
mkdir -p /etc/systemd/system/northstar-lab.service.d
cat >/etc/systemd/system/northstar-lab.service.d/cluster.conf <<UNIT
[Service]
Environment=REDIS_URL_FILE=/home/lab/northstar/secrets/redis-url
Environment=REDIS_TLS_CA_CERT_PATH=/home/lab/northstar/secrets/redis-ca.pem
Environment=REDIS_TLS_CLIENT_CERT_PATH=/home/lab/northstar/secrets/redis-client.pem
Environment=REDIS_TLS_CLIENT_KEY_PATH=/home/lab/northstar/secrets/redis-client.key
Environment=CLUSTER_NODE_ID=$node
Environment=CLUSTER_SIGNING_PRIVATE_KEY_FILE=/home/lab/northstar/secrets/cluster-signing.pkcs8.b64
Environment=CLUSTER_PEER_KEYS_FILE=/home/lab/northstar/secrets/cluster-peers.json
Environment=CLUSTER_SIGNING_KEY_EPOCH=1
Environment=CLUSTER_FAILURE_POLICY=fail_closed
Environment=CLUSTER_SAFETY_LEASE_SECONDS=120
UNIT
systemctl daemon-reload
GUEST
done

for remote in "$a" "$b"; do
  ssh "${ssh_opts[@]}" "$remote" \
    'sudo systemctl restart northstar-lab.service; sleep 3; sudo systemctl is-active northstar-lab.service'
done
echo 'both Northstar lab nodes started with signed Redis control plane and shared S3 authority'
