#!/usr/bin/env bash
set -euo pipefail

# This fixture intentionally handles live random credentials.  Report only the
# failing source line: xtrace would disclose command substitutions containing
# those credentials, while a bare `set -e` exit is not actionable in CI.
trap 'status=$?; printf "secret security fixture failed at line %s\n" "$LINENO" >&2; exit "$status"' ERR

source_project="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d /tmp/northstar-secret-security.XXXXXX)"
cleanup() {
  case "$work_dir" in
    /tmp/northstar-secret-security.*) rm -rf -- "$work_dir" ;;
  esac
}
trap cleanup EXIT

test_project="$work_dir/project"
mkdir -p "$test_project/scripts"
cp "$source_project/scripts/create-production-secrets.sh" "$test_project/scripts/"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "secret security regression tests require root to verify container ownership" >&2
  exit 77
fi
secret_dir="$work_dir/runtime-secrets"
output=$(NORTHSTAR_SECRET_DIR="$secret_dir" sh "$test_project/scripts/create-production-secrets.sh" 2>&1)
[[ "$(stat -c '%a' "$secret_dir")" == 700 ]]
[[ "$(stat -c '%u:%g' "$secret_dir")" == 0:0 ]]
lock_file="$work_dir/.northstar-secrets.lock"
[[ -f "$lock_file" && ! -L "$lock_file" ]]
[[ "$(stat -c '%a' "$lock_file")" == 600 ]]
[[ "$(stat -c '%u:%g' "$lock_file")" == 0:0 ]]

secret_names='postgres_bootstrap_password northstar_migrator_password northstar_runtime_password northstar_command_password northstar_backup_password migrator_database_url runtime_database_url command_database_url backup_database_url bootstrap_admin_password grafana_admin_password dialback_secret fast_token_secret dummy_scram_secret abuse_state_hmac_key api_control_secret metrics_bearer_token prometheus_metrics_bearer_token backup_signing_ed25519.pem backup_signing_ed25519.pub.pem backup_age_recipients.txt backup_age_identity.txt'
for name in $secret_names; do
  path="$secret_dir/$name"
  [[ -f "$path" && ! -L "$path" ]]
  [[ "$(stat -c '%a' "$path")" == 600 ]]
  fragment=$(tr -d '\r\n' < "$path" | head -c 24)
  [[ -z "$fragment" || "$output" != *"$fragment"* ]]
done
for name in postgres_bootstrap_password northstar_migrator_password northstar_runtime_password northstar_command_password northstar_backup_password; do
  [[ "$(stat -c '%u:%g' "$secret_dir/$name")" == 70:70 ]]
done
[[ "$(stat -c '%u:%g' "$secret_dir/grafana_admin_password")" == 472:0 ]]
for name in migrator_database_url runtime_database_url command_database_url backup_database_url bootstrap_admin_password dialback_secret fast_token_secret dummy_scram_secret abuse_state_hmac_key api_control_secret metrics_bearer_token backup_signing_ed25519.pem backup_signing_ed25519.pub.pem backup_age_recipients.txt backup_age_identity.txt; do
  [[ "$(stat -c '%u:%g' "$secret_dir/$name")" == 10001:10001 ]]
done
[[ "$(stat -c '%u:%g' "$secret_dir/prometheus_metrics_bearer_token")" == 65534:65534 ]]
cmp -s "$secret_dir/metrics_bearer_token" "$secret_dir/prometheus_metrics_bearer_token"
for name in postgres_bootstrap_password northstar_migrator_password northstar_runtime_password northstar_command_password northstar_backup_password dialback_secret fast_token_secret dummy_scram_secret abuse_state_hmac_key api_control_secret metrics_bearer_token; do
  [[ "$(tr -d '\r\n' < "$secret_dir/$name")" =~ ^[0-9a-f]{64}$ ]]
done
command_password=$(tr -d '\r\n' < "$secret_dir/northstar_command_password")
[[ "$(tr -d '\r\n' < "$secret_dir/command_database_url")" \
    == "postgres://northstar_commands:${command_password}@postgres:5432/xmpp" ]]
unset command_password
for other in dialback_secret fast_token_secret dummy_scram_secret abuse_state_hmac_key; do
  ! cmp -s "$secret_dir/api_control_secret" "$secret_dir/$other"
done
for role in migrator runtime backup; do
  password=$(tr -d '\r\n' < "$secret_dir/northstar_${role}_password")
  [[ "$(tr -d '\r\n' < "$secret_dir/${role}_database_url")" \
      == "postgres://northstar_${role}:${password}@postgres:5432/xmpp" ]]
  unset password
done
probe="$work_dir/crypto-probe"
signature="$work_dir/crypto-probe.sig"
ciphertext="$work_dir/crypto-probe.age"
plaintext="$work_dir/crypto-probe.out"
printf '%s\n' northstar-secret-test > "$probe"
openssl pkeyutl -sign -rawin -inkey "$secret_dir/backup_signing_ed25519.pem" \
  -in "$probe" -out "$signature"
openssl pkeyutl -verify -rawin -pubin -inkey "$secret_dir/backup_signing_ed25519.pub.pem" \
  -in "$probe" -sigfile "$signature"
age -R "$secret_dir/backup_age_recipients.txt" -o "$ciphertext" "$probe"
age -d -i "$secret_dir/backup_age_identity.txt" -o "$plaintext" "$ciphertext"
cmp -s "$probe" "$plaintext"

trace_output=$(NORTHSTAR_SECRET_DIR="$secret_dir" sh -x "$test_project/scripts/create-production-secrets.sh" 2>&1)
for name in $secret_names; do
  fragment=$(tr -d '\r\n' < "$secret_dir/$name" | head -c 24)
  [[ -z "$fragment" || "$trace_output" != *"$fragment"* ]]
done

before=$(sha256sum "$secret_dir"/*)
second_output=$(NORTHSTAR_SECRET_DIR="$secret_dir" sh "$test_project/scripts/create-production-secrets.sh" 2>&1)
after=$(sha256sum "$secret_dir"/*)
[[ "$before" == "$after" ]]
[[ "$second_output" == *'none were changed'* ]]
[[ ! -e "$secret_dir/api_control_previous_secret" ]]

compose="$source_project/docker-compose.yml"
grep -Fq 'API_CONTROL_SECRET_FILE: /run/secrets/api_control_secret' "$compose"
grep -Fq 'DUMMY_SCRAM_SECRET_FILE: /run/secrets/dummy_scram_secret' "$compose"
grep -Fq 'NORTHSTAR_SECRET_DIR:-/etc/northstar/secrets}/dummy_scram_secret' "$compose"
grep -Fq 'NORTHSTAR_SECRET_DIR:-/etc/northstar/secrets}/api_control_secret' "$compose"
grep -Fq 'METRICS_BEARER_TOKEN_FILE: /run/secrets/metrics_bearer_token' "$compose"
grep -Fq 'NORTHSTAR_SECRET_DIR:-/etc/northstar/secrets}/metrics_bearer_token' "$compose"
grep -Fq 'METRICS_BIND: 0.0.0.0:9091' "$compose"
grep -Fq 'credentials_file: /run/secrets/prometheus_metrics_bearer_token' "$source_project/monitoring/prometheus.yml"
grep -Fq 'NORTHSTAR_SECRET_DIR:-/etc/northstar/secrets}/prometheus_metrics_bearer_token' "$compose"
grep -Fq 'targets: ["xmpp:9091"]' "$source_project/monitoring/prometheus.yml"
grep -Fq 'POSTGRES_USER: northstar_bootstrap' "$compose"
grep -Fq 'MIGRATOR_DATABASE_URL_FILE: /run/secrets/migrator_database_url' "$compose"
grep -Fq 'DATABASE_URL_FILE: /run/secrets/runtime_database_url' "$compose"
grep -Fq 'ADMIN_COMMAND_DATABASE_URL_FILE: /run/secrets/command_database_url' "$compose"
grep -Fq '/run/secrets/backup_database_url' "$compose"
grep -Fq 'BACKUP_SECURITY_POLICY: production' "$compose"
if awk '/^  xmpp:/{inside=1} inside && /^  [a-zA-Z0-9_-]+:/{if ($1 != "xmpp:") inside=0} inside{print}' "$compose" \
    | grep -Eq 'migrator_database_url|postgres_bootstrap_password|northstar_(migrator|runtime|backup)_password'; then
  echo "the long-lived XMPP service received a bootstrap or migrator capability" >&2
  exit 1
fi
if grep -Fq 'API_CONTROL_ALLOW_EPHEMERAL:' "$compose"; then
  echo "production Compose must not opt into an ephemeral API-control key" >&2
  exit 1
fi
if grep -Fq 'DUMMY_SCRAM_ALLOW_EPHEMERAL_FOR_DEVELOPMENT:' "$compose"; then
  echo "production Compose must not opt into an ephemeral dummy SCRAM key" >&2
  exit 1
fi
rotation="$source_project/deploy/docker-compose.api-control-key-rotation.yml"
grep -Fq 'API_CONTROL_PREVIOUS_SECRET_FILE: /run/secrets/api_control_previous_secret' "$rotation"
grep -Fq 'NORTHSTAR_SECRET_DIR:-/etc/northstar/secrets}/api_control_previous_secret' "$rotation"

attack_project="$work_dir/symlink-attack"
attack_secret_dir="$work_dir/symlink-attack-secrets"
mkdir -p "$attack_project/scripts" "$attack_secret_dir"
chmod 0700 "$attack_secret_dir"
cp "$source_project/scripts/create-production-secrets.sh" "$attack_project/scripts/"
target="$work_dir/do-not-overwrite"
printf 'sentinel\n' > "$target"
ln -s "$target" "$attack_secret_dir/postgres_bootstrap_password"
if NORTHSTAR_SECRET_DIR="$attack_secret_dir" \
    sh "$attack_project/scripts/create-production-secrets.sh" >"$work_dir/attack.log" 2>&1; then
  echo "secret generator followed an attacker-controlled symlink" >&2
  exit 1
fi
[[ "$(cat "$target")" == sentinel ]]
[[ "$(cat "$work_dir/attack.log")" != *sentinel* ]]

# Existing files are validated rather than silently blessed. Weak material,
# reused capabilities and multiple hard links must all fail closed.
weak_dir="$work_dir/weak-secrets"
cp -a "$secret_dir" "$weak_dir"
printf '%s\n' weak >"$weak_dir/fast_token_secret"
chmod 0600 "$weak_dir/fast_token_secret"
chown 10001:10001 "$weak_dir/fast_token_secret"
if NORTHSTAR_SECRET_DIR="$weak_dir" \
    sh "$test_project/scripts/create-production-secrets.sh" >"$work_dir/weak.log" 2>&1; then
  echo "secret generator accepted weak existing key material" >&2
  exit 1
fi

weak_dummy_dir="$work_dir/weak-dummy-secrets"
cp -a "$secret_dir" "$weak_dummy_dir"
printf '%s\n' weak >"$weak_dummy_dir/dummy_scram_secret"
chmod 0600 "$weak_dummy_dir/dummy_scram_secret"
chown 10001:10001 "$weak_dummy_dir/dummy_scram_secret"
if NORTHSTAR_SECRET_DIR="$weak_dummy_dir" \
    sh "$test_project/scripts/create-production-secrets.sh" >"$work_dir/weak-dummy.log" 2>&1; then
  echo "secret generator accepted weak existing dummy SCRAM key material" >&2
  exit 1
fi

reuse_dir="$work_dir/reused-secrets"
cp -a "$secret_dir" "$reuse_dir"
cp "$reuse_dir/fast_token_secret" "$reuse_dir/api_control_secret"
chmod 0600 "$reuse_dir/api_control_secret"
chown 10001:10001 "$reuse_dir/api_control_secret"
if NORTHSTAR_SECRET_DIR="$reuse_dir" \
    sh "$test_project/scripts/create-production-secrets.sh" >"$work_dir/reuse.log" 2>&1; then
  echo "secret generator accepted a reused independent capability" >&2
  exit 1
fi

reuse_dummy_dir="$work_dir/reused-dummy-secrets"
cp -a "$secret_dir" "$reuse_dummy_dir"
cp "$reuse_dummy_dir/fast_token_secret" "$reuse_dummy_dir/dummy_scram_secret"
chmod 0600 "$reuse_dummy_dir/dummy_scram_secret"
chown 10001:10001 "$reuse_dummy_dir/dummy_scram_secret"
if NORTHSTAR_SECRET_DIR="$reuse_dummy_dir" \
    sh "$test_project/scripts/create-production-secrets.sh" >"$work_dir/reuse-dummy.log" 2>&1; then
  echo "secret generator accepted reuse of the FAST key as dummy SCRAM authority" >&2
  exit 1
fi

hardlink_dir="$work_dir/hardlink-secrets"
mkdir -m 0700 "$hardlink_dir"
hardlink_target="$work_dir/hardlink-target"
printf '%064d\n' 0 >"$hardlink_target"
chmod 0600 "$hardlink_target"
ln "$hardlink_target" "$hardlink_dir/postgres_bootstrap_password"
if NORTHSTAR_SECRET_DIR="$hardlink_dir" \
    sh "$test_project/scripts/create-production-secrets.sh" >"$work_dir/hardlink.log" 2>&1; then
  echo "secret generator accepted a multiple-link secret" >&2
  exit 1
fi

untrusted_parent="$work_dir/untrusted-parent"
mkdir "$untrusted_parent"
chmod 0777 "$untrusted_parent"
if NORTHSTAR_SECRET_DIR="$untrusted_parent/secrets" \
    sh "$test_project/scripts/create-production-secrets.sh" >"$work_dir/parent.log" 2>&1; then
  echo "secret generator accepted a replaceable parent directory" >&2
  exit 1
fi
[[ ! -e "$untrusted_parent/secrets" ]]

# The generator must not create its parent before it can lock a trusted
# boundary. Deployment setup creates the root-owned parent explicitly.
missing_parent="$work_dir/missing-parent"
if NORTHSTAR_SECRET_DIR="$missing_parent/secrets" \
    sh "$test_project/scripts/create-production-secrets.sh" >"$work_dir/missing-parent.log" 2>&1; then
  echo "secret generator created an unlocked parent directory" >&2
  exit 1
fi
[[ ! -e "$missing_parent" ]]

stale_dir="$work_dir/stale-secrets"
cp -a "$secret_dir" "$stale_dir"
mkdir "$stale_dir/.backup-age.tmp.abandoned"
printf '%s\n' abandoned >"$stale_dir/.backup-age.tmp.abandoned/identity.txt"
if NORTHSTAR_SECRET_DIR="$stale_dir" \
    sh "$test_project/scripts/create-production-secrets.sh" >"$work_dir/stale.log" 2>&1; then
  echo "secret generator accepted stale temporary private material" >&2
  exit 1
fi

echo "secret generation security regression tests passed"
