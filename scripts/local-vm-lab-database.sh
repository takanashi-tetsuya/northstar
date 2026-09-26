#!/usr/bin/env bash
set -euo pipefail

# Provision the disposable lab's PostgreSQL with the production role policy.
key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts")
infra_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-infra" { split($5, parts, "/"); print parts[1] }')
[[ $infra_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 1

remote=lab@"$infra_ip"
ssh "${ssh_opts[@]}" "$remote" 'mkdir -p /home/lab/northstar-lab-db/deploy/postgres-init/lib /home/lab/northstar-lab-db/scripts'
scp "${ssh_opts[@]}" scripts/create-production-secrets.sh "$remote:/home/lab/northstar-lab-db/scripts/"
scp "${ssh_opts[@]}" deploy/postgres-init/010-northstar-roles.sh \
  "$remote:/home/lab/northstar-lab-db/deploy/postgres-init/"
scp "${ssh_opts[@]}" deploy/postgres-init/lib/*.sql \
  "$remote:/home/lab/northstar-lab-db/deploy/postgres-init/lib/"

setup=$(mktemp)
trap 'rm -f "$setup"' EXIT
cat >"$setup" <<'GUEST'
#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
infra_ip=$1
[[ $infra_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 2

install -d -o root -g root -m 700 /etc/northstar
NORTHSTAR_SECRET_UID=$(id -u lab) \
NORTHSTAR_SECRET_GID=$(id -g lab) \
POSTGRES_SECRET_UID=$(id -u postgres) \
POSTGRES_SECRET_GID=$(id -g postgres) \
  sh /home/lab/northstar-lab-db/scripts/create-production-secrets.sh

# Debian's package cluster begins with the local postgres superuser. Import
# the generator's bootstrap credential without putting it in argv or output.
password_copy=/var/lib/postgresql/.northstar-lab-bootstrap-password
install -o postgres -g postgres -m 600 \
  /etc/northstar/secrets/postgres_bootstrap_password "$password_copy"
trap 'rm -f "$password_copy"' EXIT
if ! sudo -u postgres psql --no-psqlrc -Atqc \
  "SELECT 1 FROM pg_roles WHERE rolname='northstar_bootstrap'" | grep -qx 1; then
  sudo -u postgres psql --no-psqlrc -v ON_ERROR_STOP=1 <<'SQL'
SET password_encryption = 'scram-sha-256';
SELECT format(
  'CREATE ROLE northstar_bootstrap LOGIN SUPERUSER CREATEDB CREATEROLE PASSWORD %L',
  btrim(pg_read_file('/var/lib/postgresql/.northstar-lab-bootstrap-password'), E'\n\r')
) \gexec
SQL
fi
sudo -u postgres psql --no-psqlrc -v ON_ERROR_STOP=1 <<'SQL'
SET password_encryption = 'scram-sha-256';
SELECT format(
  'ALTER ROLE northstar_bootstrap PASSWORD %L',
  btrim(pg_read_file('/var/lib/postgresql/.northstar-lab-bootstrap-password'), E'\n\r')
) \gexec
SQL
if ! sudo -u postgres psql --no-psqlrc -Atqc \
  "SELECT 1 FROM pg_database WHERE datname='xmpp'" | grep -qx 1; then
  sudo -u postgres createdb --owner=northstar_bootstrap xmpp
fi
rm -f "$password_copy"
trap - EXIT

postgres_config=/etc/postgresql/17/main/conf.d/99-northstar-lab.conf
candidate_config=$(mktemp)
cat >"$candidate_config" <<CONF
listen_addresses = '127.0.0.1,$infra_ip'
ssl = on
ssl_cert_file = '/etc/northstar-lab-pki/infra.pem'
ssl_key_file = '/etc/northstar-lab-pki/infra.key'
password_encryption = 'scram-sha-256'
CONF
config_changed=false
if ! cmp -s "$candidate_config" "$postgres_config"; then
  install -m 644 "$candidate_config" "$postgres_config"
  config_changed=true
fi
rm -f "$candidate_config"
if ! grep -q '^hostssl[[:space:]]\+xmpp[[:space:]]\+all[[:space:]]\+192.168.197.0/24' \
  /etc/postgresql/17/main/pg_hba.conf; then
  sed -i '1i hostssl xmpp all 192.168.197.0/24 scram-sha-256' \
    /etc/postgresql/17/main/pg_hba.conf
fi
if ! grep -q '^hostssl[[:space:]]\+xmpp[[:space:]]\+northstar_bootstrap[[:space:]]\+127.0.0.1/32' \
  /etc/postgresql/17/main/pg_hba.conf; then
  sed -i '1i hostssl xmpp northstar_bootstrap 127.0.0.1/32 scram-sha-256' \
    /etc/postgresql/17/main/pg_hba.conf
fi
if [[ $config_changed == true ]]; then
  systemctl restart postgresql
else
  systemctl reload postgresql
fi
pg_isready -h 127.0.0.1 -p 5432

if [[ $(sudo -u postgres psql -d xmpp --no-psqlrc -Atqc \
  "SELECT pg_catalog.to_regclass('public._sqlx_migrations') IS NOT NULL") == t ]]; then
  for role in northstar_migrator northstar_runtime northstar_storage \
      northstar_commands northstar_backup; do
    [[ $(sudo -u postgres psql --no-psqlrc -Atqc \
      "SELECT 1 FROM pg_roles WHERE rolname='$role'") == 1 ]] || {
      echo "migrated lab database is missing role: $role" >&2
      exit 1
    }
  done
  echo 'existing migrated database and workload roles retained'
else
  POSTGRES_USER=northstar_bootstrap POSTGRES_DB=xmpp \
  PGHOST=infra.lab.test PGHOSTADDR="$infra_ip" PGSSLMODE=verify-full \
  PGSSLROOTCERT=/etc/northstar-lab-pki/ca.pem \
  POSTGRES_PASSWORD_FILE=/etc/northstar/secrets/postgres_bootstrap_password \
  NORTHSTAR_MIGRATOR_PASSWORD_FILE=/etc/northstar/secrets/northstar_migrator_password \
  NORTHSTAR_RUNTIME_PASSWORD_FILE=/etc/northstar/secrets/northstar_runtime_password \
  NORTHSTAR_STORAGE_PASSWORD_FILE=/etc/northstar/secrets/northstar_storage_password \
  NORTHSTAR_COMMAND_PASSWORD_FILE=/etc/northstar/secrets/northstar_command_password \
  NORTHSTAR_BACKUP_PASSWORD_FILE=/etc/northstar/secrets/northstar_backup_password \
    bash /home/lab/northstar-lab-db/deploy/postgres-init/010-northstar-roles.sh
fi

sudo -u postgres psql --no-psqlrc -Atqc \
  "SELECT rolname FROM pg_roles WHERE rolname LIKE 'northstar_%' ORDER BY rolname"
GUEST
scp "${ssh_opts[@]}" "$setup" "$remote:/tmp/northstar-lab-db-setup.sh"
ssh "${ssh_opts[@]}" "$remote" "set -e; sudo bash /tmp/northstar-lab-db-setup.sh '$infra_ip'; rm -f /tmp/northstar-lab-db-setup.sh"
