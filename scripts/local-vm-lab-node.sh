#!/usr/bin/env bash
set -euo pipefail
set +x

# Rebuild the standalone Northstar node against the isolated lab database.
[[ $# -eq 1 && $1 == ns-a ]] || { echo "usage: $0 ns-a" >&2; exit 2; }
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
binary=$project_dir/target/debug/rust-xmpp-server
[[ -x $binary ]] || { echo "build the candidate binary first" >&2; exit 2; }
key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo "lab SSH key not found" >&2; exit 2; }
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts")
lease_ip() {
  local vm=northstar-lab-$1 ip
  ip=$(virsh net-dhcp-leases northstar-lab | awk -v vm="$vm" '$6 == vm { split($5, parts, "/"); print parts[1] }')
  [[ $ip =~ ^192\.168\.197\.[0-9]+$ ]] || return 1
  printf '%s' "$ip"
}
node_ip=$(lease_ip ns-a)
infra_ip=$(lease_ip infra)
node=lab@$node_ip
infra=lab@$infra_ip

ssh "${ssh_opts[@]}" "$node" 'sudo systemctl stop northstar-lab.service 2>/dev/null || true; install -d -m 700 /home/lab/northstar/secrets'

# Secret bytes cross only the isolated guest-to-guest SSH channel. The host
# never materializes them or passes them through a command-line argument.
ssh "${ssh_opts[@]}" "$infra" \
  'sudo tar -C /etc/northstar/secrets -cf - migrator_database_url runtime_database_url storage_database_url command_database_url dialback_secret fast_token_secret dummy_scram_secret abuse_state_hmac_key api_control_secret metrics_bearer_token' |
  ssh "${ssh_opts[@]}" "$node" \
    'umask 077; tar --no-same-owner -C /home/lab/northstar/secrets -xf -'

ssh "${ssh_opts[@]}" "$node" 'python3 - <<'"'"'PY'"'"'
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

directory = Path("/home/lab/northstar/secrets")
for name in ("migrator", "runtime", "storage", "command"):
    path = directory / f"{name}_database_url"
    parsed = urlsplit(path.read_text().strip())
    if parsed.hostname not in {"postgres", "infra.lab.test"}:
        raise SystemExit("unexpected lab database hostname")
    if parsed.query or parsed.fragment or not parsed.netloc.endswith(":5432"):
        raise SystemExit("unexpected lab database URL structure")
    credentials = parsed.netloc.rsplit("@", 1)[0]
    if credentials == parsed.netloc:
        raise SystemExit("missing database credentials")
    path.write_text(urlunsplit((parsed.scheme, f"{credentials}@infra.lab.test:5432",
        parsed.path, "sslmode=verify-full&sslrootcert=/etc/northstar-lab-pki/ca.pem", "")) + "\n")
    path.chmod(0o600)
PY'

scp "${ssh_opts[@]}" "$binary" "$node:/home/lab/northstar/rust-xmpp-server"
ssh "${ssh_opts[@]}" "$node" \
  'cat /etc/northstar-lab-pki/ns-a.pem /etc/northstar-lab-pki/ca.pem > /home/lab/northstar/fullchain.pem; chmod 644 /home/lab/northstar/fullchain.pem; NORTHSTAR_DISABLE_DOTENV=true XMPP_DOMAIN=ns-a.lab.test MIGRATOR_DATABASE_URL_FILE=/home/lab/northstar/secrets/migrator_database_url /home/lab/northstar/rust-xmpp-server migrate'

scp "${ssh_opts[@]}" "$project_dir/scripts/reconcile-database-grants.sh" \
  "$project_dir/scripts/run-postgres.py" "$infra:/home/lab/northstar-lab-db/scripts/"
scp "${ssh_opts[@]}" "$project_dir/deploy/postgres-init/lib/"*.sql \
  "$infra:/home/lab/northstar-lab-db/deploy/postgres-init/lib/"
ssh "${ssh_opts[@]}" "$infra" 'sudo bash -s' <<'GUEST'
set -euo pipefail
umask 077
url_file=$(mktemp /tmp/northstar-lab-migrator-url.XXXXXXXX)
grant_log=$(mktemp /tmp/northstar-lab-grants.XXXXXXXX)
trap 'rm -f "$url_file" "$grant_log"' EXIT
python3 - "$url_file" <<'PY'
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import sys

parsed = urlsplit(Path("/etc/northstar/secrets/migrator_database_url").read_text().strip())
if parsed.hostname != "postgres" or parsed.query or parsed.fragment:
    raise SystemExit("unexpected generated database URL structure")
credentials = parsed.netloc.rsplit("@", 1)[0]
Path(sys.argv[1]).write_text(urlunsplit((parsed.scheme, f"{credentials}@infra.lab.test:5432",
    parsed.path, "sslmode=verify-full&sslrootcert=/etc/northstar-lab-pki/ca.pem", "")) + "\n")
PY
if ! bash /home/lab/northstar-lab-db/scripts/reconcile-database-grants.sh \
  --database-url-file "$url_file" >"$grant_log" 2>&1; then
  tail -n 80 "$grant_log" >&2
  exit 1
fi
echo 'Northstar database grants reconciled.'
GUEST

ssh "${ssh_opts[@]}" "$node" 'sudo tee /etc/systemd/system/northstar-lab.service >/dev/null' <<'UNIT'
[Unit]
Description=Northstar isolated VM lab
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=lab
WorkingDirectory=/home/lab/northstar
Environment=NORTHSTAR_DISABLE_DOTENV=true
Environment=RUST_LOG=info
Environment=XMPP_DOMAIN=ns-a.lab.test
Environment=DATABASE_URL_FILE=/home/lab/northstar/secrets/runtime_database_url
Environment=ADMIN_COMMAND_DATABASE_URL_FILE=/home/lab/northstar/secrets/command_database_url
Environment=STORAGE_DATABASE_URL_FILE=/home/lab/northstar/secrets/storage_database_url
Environment=TLS_CERT_PATH=/home/lab/northstar/fullchain.pem
Environment=TLS_KEY_PATH=/etc/northstar-lab-pki/ns-a.key
Environment=FEDERATION_ALLOW_PRIVATE_IPS=true
Environment=FEDERATION_EXTRA_ROOT_CERT_PATH=/etc/northstar-lab-pki/ca.pem
Environment=DIALBACK_SECRET_FILE=/home/lab/northstar/secrets/dialback_secret
Environment=FAST_TOKEN_SECRET_FILE=/home/lab/northstar/secrets/fast_token_secret
Environment=DUMMY_SCRAM_SECRET_FILE=/home/lab/northstar/secrets/dummy_scram_secret
Environment=ABUSE_STATE_HMAC_KEY_FILE=/home/lab/northstar/secrets/abuse_state_hmac_key
Environment=API_CONTROL_SECRET_FILE=/home/lab/northstar/secrets/api_control_secret
Environment=METRICS_BEARER_TOKEN_FILE=/home/lab/northstar/secrets/metrics_bearer_token
Environment=DATABASE_MAX_CONNECTIONS=10
Environment=DATABASE_MIN_CONNECTIONS=2
ExecStart=/home/lab/northstar/rust-xmpp-server serve standalone
Restart=no
UNIT
ssh "${ssh_opts[@]}" "$node" \
  'sudo systemctl daemon-reload; sudo systemctl start northstar-lab.service; sleep 2; sudo systemctl is-active northstar-lab.service'
sha256sum "$binary"
