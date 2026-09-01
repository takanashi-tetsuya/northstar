#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

# These settings change protocol exposure, authentication, identity disclosure,
# trust validation, or durable-session limits.  A Compose deployment must not
# silently ignore a value that the documented .env surface invites operators to
# set. Optional STUN/TURN endpoints deliberately use YAML null pass-through so
# an absent endpoint remains an absent Option rather than an invalid empty URL.
required_mappings='ADMIN_ADDRESSES
ABUSE_ADDRESSES
SUPPORT_ADDRESSES
FEEDBACK_ADDRESSES
SALES_ADDRESSES
SECURITY_ADDRESSES
SCRAM_SHA1_ENABLED
DUMMY_SCRAM_SECRET_FILE
METRICS_BIND
WEBSOCKET_ALLOWED_ORIGINS
XEP_0487_IPS
XEP_0487_TTL_SECONDS
XEP_0487_PRIORITY
XEP_0487_WEIGHT
SM_LIVE_LEASE_SECONDS
SM_CLAIM_LEASE_SECONDS
SM_MAX_UNACKED_STANZAS
SM_MAX_UNACKED_BYTES
SM_MAX_SNAPSHOT_BYTES
SM_MEMORY_BUDGET_BYTES
SM_RECOVERY_MAX_BYTES
SM_RECOVERY_MAX_JOBS
SM_MAX_RESUMABLE_SESSIONS
SM_IP_BINDING
SM_REQUIRE_SAME_DEVICE
RESOURCE_BIND_TIMEOUT_SECONDS
C2S_CLIENT_TRUST_ROOT_CERT_PATH
C2S_CLIENT_CRL_PATH
FEDERATION_EXTRA_ROOT_CERT_PATH
FEDERATION_CRL_PATH
FEDERATION_DANE_MODE
STUN_SERVER
TURN_SERVER
TURN_SHARED_SECRET_FILE
TURN_CREDENTIALS_TTL_SECONDS
TURN_CREDENTIAL_REQUESTS_PER_MINUTE
UPLOAD_S3_CREDENTIAL_BUNDLE_FILE
UPLOAD_DOWNLOAD_MAX_CONCURRENT
UPLOAD_DOWNLOAD_MAX_PER_IP
UPLOAD_DOWNLOAD_READ_TIMEOUT_SECONDS
UPLOAD_DOWNLOAD_MAX_SECONDS
UPLOAD_STORAGE_MAX_PENDING_JOBS
UPLOAD_STORAGE_MAX_RETAINED_FILES
UPLOAD_STORAGE_MAX_RETAINED_BYTES
UPLOAD_RETENTION_SECONDS'

failures=0
for key in $required_mappings; do
    if ! grep -Eq "^[[:space:]]{6}${key}:" docker-compose.yml; then
        echo "docker-compose.yml does not map documented setting $key" >&2
        failures=$((failures + 1))
    fi
    if ! grep -Eq "^[[:space:]#]*${key}=" .env.example; then
        echo ".env.example does not document Compose setting $key" >&2
        failures=$((failures + 1))
    fi
done

# Every maintained runtime harness that exercises a stable FAST authority must
# supply a separately generated dummy-SCRAM authority as well. Keeping this in
# the release gate prevents a new harness from accidentally restoring the old
# shared-key or implicit-key behavior.
for script in $(grep -l 'FAST_TOKEN_SECRET_FILE' scripts/*.sh); do
    fast_bindings=$(grep -c 'FAST_TOKEN_SECRET_FILE' "$script")
    dummy_bindings=$(grep -c 'DUMMY_SCRAM_SECRET_FILE' "$script" || true)
    if [ "$fast_bindings" -ne "$dummy_bindings" ]; then
        echo "$script must supply one independent DUMMY_SCRAM_SECRET_FILE for every FAST_TOKEN_SECRET_FILE binding" >&2
        failures=$((failures + 1))
    fi
done

grep -Eq '^[[:space:]]+source:[[:space:]]+\./certs/trust$' docker-compose.yml \
    && grep -Eq '^[[:space:]]+target:[[:space:]]+/app/certs/trust$' docker-compose.yml \
    && grep -A1 -E '^[[:space:]]+target:[[:space:]]+/app/certs/trust$' docker-compose.yml \
        | grep -Eq '^[[:space:]]+read_only:[[:space:]]+true$' \
    || {
        echo "Compose must mount optional certs/trust material read-only at /app/certs/trust" >&2
        failures=$((failures + 1))
    }

service_block() {
    awk -v service="$1" '
      $0 == "  " service ":" { inside=1; next }
      inside && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
      inside { print }
    ' docker-compose.yml
}

postgres_block=$(service_block postgres)
migrate_block=$(service_block migrate)
xmpp_block=$(service_block xmpp)
backup_block=$(service_block backup)
restore_block=$(service_block restore)

grep -Fq 'NORTHSTAR_SECRET_DIR:-/etc/northstar/secrets' docker-compose.yml \
    && ! grep -Fq 'deploy/secrets/' docker-compose.yml \
    && ! grep -Fq 'deploy/secrets/' deploy/docker-compose.*.yml \
    || {
        echo "Compose runtime secrets must default to the external root-owned secret directory" >&2
        failures=$((failures + 1))
    }
if grep -Eq '^[A-Z0-9_]+_(SECRET|HOST)_FILE=/etc/northstar/secrets/' .env.example; then
    echo "individual .env secret paths must remain commented so NORTHSTAR_SECRET_DIR is authoritative" >&2
    failures=$((failures + 1))
fi

printf '%s\n' "$postgres_block" | grep -Fq 'POSTGRES_USER: northstar_bootstrap' \
    && printf '%s\n' "$postgres_block" | grep -Fq '/docker-entrypoint-initdb.d:ro' \
    || {
        echo "Compose PostgreSQL must use the dedicated bootstrap role and role initializer" >&2
        failures=$((failures + 1))
    }
printf '%s\n' "$migrate_block" | grep -Fq 'MIGRATOR_DATABASE_URL_FILE: /run/secrets/migrator_database_url' \
    && printf '%s\n' "$migrate_block" | grep -Fq 'entrypoint: ["/usr/local/bin/xmpp-server"]' \
    && printf '%s\n' "$migrate_block" | grep -Fq 'command: ["migrate"]' \
    && printf '%s\n' "$xmpp_block" | grep -Fq 'DATABASE_URL_FILE: /run/secrets/runtime_database_url' \
    && printf '%s\n' "$backup_block" | grep -Fq '/run/secrets/backup_database_url' \
    || {
        echo "Compose database capabilities are not split across migrate/runtime/backup" >&2
        failures=$((failures + 1))
    }
if printf '%s\n' "$xmpp_block" \
    | grep -Eq 'migrator_database_url|postgres_bootstrap_password|northstar_(migrator|runtime|backup)_password'; then
    echo "the long-lived XMPP service must not receive database owner/bootstrap material" >&2
    failures=$((failures + 1))
fi
if printf '%s\n' "$backup_block" | grep -Eq 'migrator_database_url|runtime_database_url'; then
    echo "the backup service must receive only the read-only backup database URL" >&2
    failures=$((failures + 1))
fi
printf '%s\n' "$backup_block" | grep -Fq 'BACKUP_SECURITY_POLICY: production' \
    && printf '%s\n' "$backup_block" | grep -Fq 'BACKUP_SIGNING_KEY_FILE: /run/secrets/backup_signing_key' \
    && printf '%s\n' "$backup_block" | grep -Fq 'BACKUP_AGE_RECIPIENT_FILE: /run/secrets/backup_age_recipients' \
    && printf '%s\n' "$backup_block" | grep -Fq 'BACKUP_SEQUENCE_STATE_FILE: /state/backup-sequence' \
    && printf '%s\n' "$restore_block" | grep -Fq 'BACKUP_ROLLBACK_STATE_FILE: /state/restore-floor' \
    || {
        echo "production Compose must make signed, age-encrypted, anti-rollback backup mandatory" >&2
        failures=$((failures + 1))
    }

[ "$failures" -eq 0 ] || exit 1
echo "Compose security and protocol configuration mappings are complete"
