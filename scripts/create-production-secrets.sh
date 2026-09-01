#!/usr/bin/env sh
set -eu
set +x

# Keep privileged secret generation outside the developer-owned source tree.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

secret_dir=${NORTHSTAR_SECRET_DIR:-/etc/northstar/secrets}
northstar_uid=${NORTHSTAR_SECRET_UID:-10001}
northstar_gid=${NORTHSTAR_SECRET_GID:-10001}
postgres_uid=${POSTGRES_SECRET_UID:-70}
postgres_gid=${POSTGRES_SECRET_GID:-70}
grafana_uid=${GRAFANA_SECRET_UID:-472}
grafana_gid=${GRAFANA_SECRET_GID:-0}
prometheus_uid=${PROMETHEUS_SECRET_UID:-65534}
prometheus_gid=${PROMETHEUS_SECRET_GID:-65534}

fail() {
    echo "production secret generation failed: $1" >&2
    exit 1
}

for identity in \
    "$northstar_uid" "$northstar_gid" \
    "$postgres_uid" "$postgres_gid" \
    "$grafana_uid" "$grafana_gid" \
    "$prometheus_uid" "$prometheus_gid"; do
    case "$identity" in
        ''|*[!0-9]*) fail "secret owner IDs must be unsigned decimal integers" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || {
    echo "production secrets have different container owners; run this script as root" >&2
    echo "the script never prints secret values" >&2
    exit 1
}

case "$secret_dir" in
    /*) ;;
    *) fail "NORTHSTAR_SECRET_DIR must be an absolute path" ;;
esac
case "$secret_dir" in
    /|*/|*/.|*/..|*/./*|*/../*|*//*)
        fail "NORTHSTAR_SECRET_DIR is not a canonical dedicated path"
        ;;
esac

for command in age age-keygen chmod chown cmp cp dirname flock grep id install \
    ln mktemp openssl python3 rm rmdir stat tr wc; do
    command -v "$command" >/dev/null 2>&1 \
        || fail "required production secret tool is missing: $command"
done

umask 077

# Every existing ancestor must be immune to replacement by an unprivileged
# account. A root-owned sticky directory (normally /tmp in tests) is accepted.
validate_trusted_chain() {
    python3 - "$1" <<'PY'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
    raise SystemExit("secret path must be absolute and canonical")
current = pathlib.Path("/")
for part in path.parts[1:]:
    current /= part
    try:
        info = os.lstat(current)
    except OSError as error:
        raise SystemExit(f"trusted secret ancestor is unavailable: {current}: {error}")
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"trusted secret ancestor is not a real directory: {current}")
    if info.st_uid != 0:
        raise SystemExit(f"trusted secret ancestor is not root-owned: {current}")
    if info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX):
        raise SystemExit(f"trusted secret ancestor is group/world writable: {current}")
PY
}

secret_parent=$(dirname -- "$secret_dir")
[ -d "$secret_parent" ] && [ ! -L "$secret_parent" ] \
    || fail "secret parent must be pre-created as a real root-owned directory"
validate_trusted_chain "$secret_parent"
[ "$(stat -c '%u:%g' "$secret_parent")" = 0:0 ] \
    || fail "secret parent must be owned by root:root"
[ "$(stat -c '%a' "$secret_parent")" = 700 ] \
    || fail "secret parent must have mode 0700"
secret_parent_identity=$(stat -Lc '%d:%i' "$secret_parent")

assert_secret_parent() {
    [ -d "$secret_parent" ] && [ ! -L "$secret_parent" ] \
        && [ "$(stat -Lc '%d:%i' "$secret_parent")" = "$secret_parent_identity" ] \
        && [ "$(stat -c '%u:%g' "$secret_parent")" = 0:0 ] \
        && [ "$(stat -c '%a' "$secret_parent")" = 700 ] \
        || fail "secret parent changed while the generator was running"
}

# The persistent parent lock is the generator's first write. The parent and
# every ancestor were verified before the file descriptor was opened, so root
# never creates a path below a directory another account can replace.
lock_file="$secret_parent/.northstar-secrets.lock"
if [ -e "$lock_file" ] || [ -L "$lock_file" ]; then
    [ -f "$lock_file" ] && [ ! -L "$lock_file" ] \
        && [ "$(stat -c '%u:%g' "$lock_file")" = 0:0 ] \
        && [ "$(stat -c '%a' "$lock_file")" = 600 ] \
        && [ "$(stat -c '%h' "$lock_file")" = 1 ] \
        || fail "secret generator lock is not a private root-owned single-link file"
fi
exec 9>>"$lock_file"
chmod 0600 "$lock_file"
[ "$(stat -Lc '%d:%i' "/proc/$$/fd/9")" = "$(stat -c '%d:%i' "$lock_file")" ] \
    || fail "secret generator lock inode changed while it was opened"
flock -n 9 || fail "another production secret generator is running"
assert_secret_parent

if [ ! -e "$secret_dir" ]; then
    install -d -m 0700 -o 0 -g 0 -- "$secret_dir"
fi
[ -d "$secret_dir" ] && [ ! -L "$secret_dir" ] \
    || fail "production secret path must be a real directory"
[ "$(stat -c '%u:%g' "$secret_dir")" = 0:0 ] \
    || fail "production secret directory must be owned by root:root"
[ "$(stat -c '%a' "$secret_dir")" = 700 ] \
    || fail "production secret directory must have mode 0700"
validate_trusted_chain "$secret_dir"

secret_dir_identity=$(stat -Lc '%d:%i' "$secret_dir")
assert_secret_boundary() {
    assert_secret_parent
    [ -d "$secret_dir" ] && [ ! -L "$secret_dir" ] \
        && [ "$(stat -Lc '%d:%i' "$secret_dir")" = "$secret_dir_identity" ] \
        && [ "$(stat -c '%u:%g' "$secret_dir")" = 0:0 ] \
        && [ "$(stat -c '%a' "$secret_dir")" = 700 ] \
        || fail "secret directory changed while the generator was running"
}

assert_secret_boundary

# Never leave temporary private-key, plaintext probe, or partially generated
# material behind after a tool error or signal. Every registered path is set by
# this script and must stay below the verified hidden namespace.
temporary=
key_work=
signing_private=
signing_public=
signing_probe=
signing_signature=
age_work=
age_raw_identity=
age_identity=
age_recipients=
age_probe=
age_ciphertext=
age_plaintext=
key_check=
private_check=
public_check=
probe=
signature=
ciphertext=
plaintext=
cleanup_temporary_material() {
    cleanup_status=$?
    trap - EXIT HUP INT TERM
    set +e
    for cleanup_path in \
        "$temporary" "$signing_private" "$signing_public" "$signing_probe" \
        "$signing_signature" "$age_raw_identity" "$age_identity" \
        "$age_recipients" "$age_probe" "$age_ciphertext" "$age_plaintext" \
        "$key_check" "$private_check" "$public_check" "$probe" "$signature" \
        "$ciphertext" "$plaintext"; do
        case "$cleanup_path" in
            "$secret_dir"/.*)
                [ ! -e "$cleanup_path" ] && [ ! -L "$cleanup_path" ] \
                    || rm -f -- "$cleanup_path"
                ;;
        esac
    done
    for cleanup_dir in "$age_work" "$key_work"; do
        case "$cleanup_dir" in
            "$secret_dir"/.*)
                [ ! -d "$cleanup_dir" ] || rmdir -- "$cleanup_dir"
                ;;
        esac
    done
    exit "$cleanup_status"
}
trap cleanup_temporary_material EXIT
trap 'exit 1' HUP INT TERM

secret_names="postgres_bootstrap_password northstar_migrator_password northstar_runtime_password northstar_command_password northstar_backup_password migrator_database_url runtime_database_url command_database_url backup_database_url bootstrap_admin_password grafana_admin_password dialback_secret fast_token_secret dummy_scram_secret abuse_state_hmac_key api_control_secret metrics_bearer_token prometheus_metrics_bearer_token backup_signing_ed25519.pem backup_signing_ed25519.pub.pem backup_age_recipients.txt backup_age_identity.txt"
optional_hex_names="api_control_previous_secret abuse_state_hmac_previous_key"

# A previous interrupted version may have left plaintext probes or private-key
# work directories. Do not guess whether they are safe to remove: stop before
# touching managed material and require an administrator to inspect and delete
# them inside the already protected boundary.
for stale_temporary in "$secret_dir"/.*.tmp.*; do
    if [ -e "$stale_temporary" ] || [ -L "$stale_temporary" ]; then
        fail "stale temporary secret material exists; inspect the protected secret directory"
    fi
done

expected_owner() {
    case "$1" in
        postgres_bootstrap_password|northstar_migrator_password|northstar_runtime_password|northstar_command_password|northstar_backup_password)
            printf '%s' "$postgres_uid:$postgres_gid" ;;
        grafana_admin_password) printf '%s' "$grafana_uid:$grafana_gid" ;;
        prometheus_metrics_bearer_token) printf '%s' "$prometheus_uid:$prometheus_gid" ;;
        *) printf '%s' "$northstar_uid:$northstar_gid" ;;
    esac
}

# Existing material is input, not something to bless by chmod/chown.
for secret in $secret_names $optional_hex_names; do
    path="$secret_dir/$secret"
    if [ -e "$path" ] || [ -L "$path" ]; then
        owner=$(expected_owner "$secret")
        [ -f "$path" ] && [ ! -L "$path" ] \
            && [ "$(stat -c '%h' "$path")" = 1 ] \
            && [ "$(stat -c '%a' "$path")" = 600 ] \
            || fail "existing secret is not a private regular single-link file: $secret"
        actual_owner=$(stat -c '%u:%g' "$path")
        [ "$actual_owner" = 0:0 ] || [ "$actual_owner" = "$owner" ] \
            || fail "existing secret has an unexpected owner: $secret"
    fi
done

created=""
create_random_hex() {
    name=$1
    bytes=$2
    destination="$secret_dir/$name"
    [ ! -e "$destination" ] || return 0
    assert_secret_boundary
    temporary=$(mktemp "$secret_dir/.${name}.tmp.XXXXXX")
    if ! openssl rand -hex "$bytes" >"$temporary"; then
        rm -f -- "$temporary"
        fail "failed to generate secret: $name"
    fi
    chmod 0600 "$temporary"
    if [ -e "$destination" ] || [ -L "$destination" ] \
        || ! ln "$temporary" "$destination"; then
        rm -f -- "$temporary"
        fail "secret appeared concurrently; refusing to overwrite: $name"
    fi
    rm -f -- "$temporary"
    created="$created $name"
}

create_database_url() {
    name=$1
    role=$2
    password_name=$3
    destination="$secret_dir/$name"
    [ ! -e "$destination" ] || return 0
    assert_secret_boundary
    temporary=$(mktemp "$secret_dir/.${name}.tmp.XXXXXX")
    {
        printf 'postgres://%s:' "$role"
        tr -d '\r\n' <"$secret_dir/$password_name"
        printf '@postgres:5432/xmpp\n'
    } >"$temporary"
    chmod 0600 "$temporary"
    if [ -e "$destination" ] || [ -L "$destination" ] \
        || ! ln "$temporary" "$destination"; then
        rm -f -- "$temporary"
        fail "database URL appeared concurrently; refusing to overwrite: $name"
    fi
    rm -f -- "$temporary"
    created="$created $name"
}

require_pair_state() {
    first=$1
    second=$2
    first_exists=false
    second_exists=false
    [ -e "$secret_dir/$first" ] && first_exists=true
    [ -e "$secret_dir/$second" ] && second_exists=true
    [ "$first_exists" = "$second_exists" ] \
        || fail "refusing to repair an incomplete cryptographic key pair: $first / $second"
}

publish_pair() {
    first_source=$1
    first_name=$2
    second_source=$3
    second_name=$4
    first_destination="$secret_dir/$first_name"
    second_destination="$secret_dir/$second_name"
    assert_secret_boundary
    if [ -e "$first_destination" ] || [ -L "$first_destination" ] \
        || [ -e "$second_destination" ] || [ -L "$second_destination" ]; then
        fail "cryptographic key pair appeared concurrently; refusing to overwrite"
    fi
    ln "$first_source" "$first_destination" \
        || fail "cryptographic key pair appeared concurrently; refusing to overwrite"
    if ! ln "$second_source" "$second_destination"; then
        rm -f -- "$first_destination"
        fail "cryptographic key pair appeared concurrently; refusing to leave a partial pair"
    fi
    created="$created $first_name $second_name"
}

create_random_hex postgres_bootstrap_password 32
create_random_hex northstar_migrator_password 32
create_random_hex northstar_runtime_password 32
create_random_hex northstar_command_password 32
create_random_hex northstar_backup_password 32
create_database_url migrator_database_url northstar_migrator northstar_migrator_password
create_database_url runtime_database_url northstar_runtime northstar_runtime_password
create_database_url command_database_url northstar_commands northstar_command_password
create_database_url backup_database_url northstar_backup northstar_backup_password

create_random_hex bootstrap_admin_password 48
create_random_hex grafana_admin_password 48
create_random_hex dialback_secret 32
create_random_hex fast_token_secret 32
create_random_hex dummy_scram_secret 32
create_random_hex abuse_state_hmac_key 32
create_random_hex api_control_secret 32
create_random_hex metrics_bearer_token 32
if [ ! -e "$secret_dir/prometheus_metrics_bearer_token" ]; then
    temporary=$(mktemp "$secret_dir/.prometheus_metrics_bearer_token.tmp.XXXXXX")
    cp -- "$secret_dir/metrics_bearer_token" "$temporary"
    chmod 0600 "$temporary"
    if ! ln "$temporary" "$secret_dir/prometheus_metrics_bearer_token"; then
        rm -f -- "$temporary"
        fail "metrics token copy appeared concurrently; refusing to overwrite"
    fi
    rm -f -- "$temporary"
    created="$created prometheus_metrics_bearer_token"
fi

require_pair_state backup_signing_ed25519.pem backup_signing_ed25519.pub.pem
if [ ! -e "$secret_dir/backup_signing_ed25519.pem" ]; then
    key_work=$(mktemp -d "$secret_dir/.backup-signing.tmp.XXXXXX")
    signing_private="$key_work/private.pem"
    signing_public="$key_work/public.pem"
    signing_probe="$key_work/probe"
    signing_signature="$key_work/probe.sig"
    openssl genpkey -algorithm ED25519 -out "$signing_private"
    openssl pkey -in "$signing_private" -pubout -out "$signing_public"
    printf '%s\n' northstar-backup-signing-self-test >"$signing_probe"
    openssl pkeyutl -sign -rawin -inkey "$signing_private" \
        -in "$signing_probe" -out "$signing_signature"
    openssl pkeyutl -verify -rawin -pubin -inkey "$signing_public" \
        -in "$signing_probe" -sigfile "$signing_signature" >/dev/null
    chmod 0600 "$signing_private" "$signing_public"
    publish_pair "$signing_private" backup_signing_ed25519.pem \
        "$signing_public" backup_signing_ed25519.pub.pem
    rm -f -- "$signing_signature" "$signing_probe" "$signing_public" "$signing_private"
    rmdir "$key_work"
fi

require_pair_state backup_age_identity.txt backup_age_recipients.txt
if [ ! -e "$secret_dir/backup_age_identity.txt" ]; then
    age_work=$(mktemp -d "$secret_dir/.backup-age.tmp.XXXXXX")
    age_raw_identity="$age_work/raw-identity.txt"
    age_identity="$age_work/identity.txt"
    age_recipients="$age_work/recipients.txt"
    age_probe="$age_work/probe"
    age_ciphertext="$age_work/probe.age"
    age_plaintext="$age_work/probe.out"
    age-keygen -o "$age_raw_identity" >/dev/null 2>&1
    LC_ALL=C grep -E '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$age_raw_identity" >"$age_identity"
    [ "$(wc -l <"$age_identity" | tr -d ' ')" = 1 ] \
        || fail "generated age identity is not one canonical native key"
    age-keygen -y "$age_identity" >"$age_recipients"
    printf '%s\n' northstar-backup-age-self-test >"$age_probe"
    age -R "$age_recipients" -o "$age_ciphertext" "$age_probe" >/dev/null 2>&1
    age -d -i "$age_identity" -o "$age_plaintext" "$age_ciphertext" >/dev/null 2>&1
    cmp -s "$age_probe" "$age_plaintext" \
        || fail "generated age identity failed its encryption self-test"
    chmod 0600 "$age_identity" "$age_recipients"
    publish_pair "$age_identity" backup_age_identity.txt \
        "$age_recipients" backup_age_recipients.txt
    rm -f -- "$age_plaintext" "$age_ciphertext" "$age_probe" \
        "$age_recipients" "$age_identity" "$age_raw_identity"
    rmdir "$age_work"
fi

validate_hex_secret() {
    name=$1
    digits=$2
    path="$secret_dir/$name"
    expected_size=$((digits + 1))
    [ "$(wc -c <"$path" | tr -d ' ')" = "$expected_size" ] \
        || fail "$name must contain exactly $digits lowercase hexadecimal characters and one newline"
    LC_ALL=C grep -Eq "^[0-9a-f]{$digits}$" "$path" \
        || fail "$name is not in the generated lowercase hexadecimal format"
    value=$(tr -d '\n' <"$path")
    printf '%s\n' "$value" | cmp -s - "$path" \
        || fail "$name must contain exactly one canonical line"
    unset value
}

for name in postgres_bootstrap_password northstar_migrator_password \
    northstar_runtime_password northstar_command_password northstar_backup_password dialback_secret \
    fast_token_secret dummy_scram_secret abuse_state_hmac_key api_control_secret \
    metrics_bearer_token prometheus_metrics_bearer_token; do
    validate_hex_secret "$name" 64
done
validate_hex_secret bootstrap_admin_password 96
validate_hex_secret grafana_admin_password 96
for name in $optional_hex_names; do
    [ ! -e "$secret_dir/$name" ] || validate_hex_secret "$name" 64
done

verify_database_url() {
    name=$1
    role=$2
    password_name=$3
    password=$(tr -d '\r\n' <"$secret_dir/$password_name")
    actual=$(tr -d '\r\n' <"$secret_dir/$name")
    expected="postgres://$role:${password}@postgres:5432/xmpp"
    [ "$actual" = "$expected" ] \
        || fail "$name does not match its role password and Compose endpoint"
    printf '%s\n' "$actual" | cmp -s - "$secret_dir/$name" \
        || fail "$name must contain exactly one canonical line"
    unset password actual expected
}
verify_database_url migrator_database_url northstar_migrator northstar_migrator_password
verify_database_url runtime_database_url northstar_runtime northstar_runtime_password
verify_database_url command_database_url northstar_commands northstar_command_password
verify_database_url backup_database_url northstar_backup northstar_backup_password

cmp -s "$secret_dir/metrics_bearer_token" "$secret_dir/prometheus_metrics_bearer_token" \
    || fail "Northstar and Prometheus metrics bearer-token files must contain the same value"

# Reuse between independent capabilities is rejected even for existing files.
distinct_names="postgres_bootstrap_password northstar_migrator_password northstar_runtime_password northstar_command_password northstar_backup_password bootstrap_admin_password grafana_admin_password dialback_secret fast_token_secret dummy_scram_secret abuse_state_hmac_key api_control_secret metrics_bearer_token"
for name in $optional_hex_names; do
    [ ! -e "$secret_dir/$name" ] || distinct_names="$distinct_names $name"
done
checked=""
for name in $distinct_names; do
    for previous in $checked; do
        ! cmp -s "$secret_dir/$name" "$secret_dir/$previous" \
            || fail "independent secrets must not reuse the same value: $name / $previous"
    done
    checked="$checked $name"
done

# Existing cryptographic material is never trusted merely because both names
# exist. Bound its size, derive public capabilities, and perform live pair tests.
for name in backup_signing_ed25519.pem backup_signing_ed25519.pub.pem \
    backup_age_identity.txt backup_age_recipients.txt; do
    size=$(wc -c <"$secret_dir/$name")
    [ "$size" -gt 0 ] && [ "$size" -le 16384 ] \
        || fail "$name is empty or unreasonably large"
done
openssl pkey -in "$secret_dir/backup_signing_ed25519.pem" -passin pass: \
    -text -noout 2>/dev/null | grep -q ED25519 \
    || fail "backup signing private key must be an unencrypted Ed25519 key"
openssl pkey -pubin -in "$secret_dir/backup_signing_ed25519.pub.pem" \
    -text_pub -noout 2>/dev/null | grep -q ED25519 \
    || fail "backup verification key must be an Ed25519 public key"

key_check=$(mktemp "$secret_dir/.backup-key-check.tmp.XXXXXX")
private_check=$(mktemp "$secret_dir/.backup-private-check.tmp.XXXXXX")
public_check=$(mktemp "$secret_dir/.backup-public-check.tmp.XXXXXX")
openssl pkey -in "$secret_dir/backup_signing_ed25519.pem" -out "$private_check"
cmp -s "$private_check" "$secret_dir/backup_signing_ed25519.pem" \
    || { rm -f -- "$key_check" "$private_check" "$public_check"; fail "backup signing private key is not canonical"; }
openssl pkey -pubin -in "$secret_dir/backup_signing_ed25519.pub.pem" -pubout -out "$public_check"
cmp -s "$public_check" "$secret_dir/backup_signing_ed25519.pub.pem" \
    || { rm -f -- "$key_check" "$private_check" "$public_check"; fail "backup verification key is not canonical"; }
openssl pkey -in "$secret_dir/backup_signing_ed25519.pem" -pubout -out "$key_check"
cmp -s "$key_check" "$secret_dir/backup_signing_ed25519.pub.pem" \
    || { rm -f -- "$key_check" "$private_check" "$public_check"; fail "backup signing private/public keys do not match"; }
age-keygen -y "$secret_dir/backup_age_identity.txt" >"$key_check"
cmp -s "$key_check" "$secret_dir/backup_age_recipients.txt" \
    || { rm -f -- "$key_check" "$private_check" "$public_check"; fail "backup age identity/recipient files do not match"; }
LC_ALL=C grep -Eq '^age1[0-9a-z]+$' "$secret_dir/backup_age_recipients.txt" \
    || { rm -f -- "$key_check" "$private_check" "$public_check"; fail "backup age recipients file is not canonical"; }
recipient=$(tr -d '\n' <"$secret_dir/backup_age_recipients.txt")
printf '%s\n' "$recipient" | cmp -s - "$secret_dir/backup_age_recipients.txt" \
    || { rm -f -- "$key_check" "$private_check" "$public_check"; fail "backup age recipients file must contain exactly one line"; }
unset recipient
identity_lines=$(LC_ALL=C grep -Ec '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$secret_dir/backup_age_identity.txt" || true)
[ "$identity_lines" = 1 ] \
    || { rm -f -- "$key_check" "$private_check" "$public_check"; fail "backup age identity must contain exactly one native identity"; }
identity=$(LC_ALL=C grep -E '^AGE-SECRET-KEY-1[0-9A-Z]+$' "$secret_dir/backup_age_identity.txt")
printf '%s\n' "$identity" | cmp -s - "$secret_dir/backup_age_identity.txt" \
    || { rm -f -- "$key_check" "$private_check" "$public_check"; fail "backup age identity file must contain exactly one canonical line"; }
unset identity

probe=$(mktemp "$secret_dir/.backup-pair-probe.tmp.XXXXXX")
signature=$(mktemp "$secret_dir/.backup-pair-signature.tmp.XXXXXX")
ciphertext=$(mktemp "$secret_dir/.backup-pair-ciphertext.tmp.XXXXXX")
plaintext=$(mktemp "$secret_dir/.backup-pair-plaintext.tmp.XXXXXX")
printf '%s\n' northstar-production-secret-pair-self-test >"$probe"
openssl pkeyutl -sign -rawin -inkey "$secret_dir/backup_signing_ed25519.pem" \
    -in "$probe" -out "$signature"
openssl pkeyutl -verify -rawin -pubin -inkey "$secret_dir/backup_signing_ed25519.pub.pem" \
    -in "$probe" -sigfile "$signature" >/dev/null
age -R "$secret_dir/backup_age_recipients.txt" -o "$ciphertext" "$probe" >/dev/null 2>&1
age -d -i "$secret_dir/backup_age_identity.txt" -o "$plaintext" "$ciphertext" >/dev/null 2>&1
cmp -s "$probe" "$plaintext" \
    || fail "backup age identity failed its encryption self-test"
rm -f -- "$plaintext" "$ciphertext" "$signature" "$probe" \
    "$key_check" "$private_check" "$public_check"

assert_secret_boundary
for secret in $secret_names; do
    [ -f "$secret_dir/$secret" ] && [ ! -L "$secret_dir/$secret" ] \
        && [ "$(stat -c '%h' "$secret_dir/$secret")" = 1 ] \
        || fail "secret changed before ownership publication: $secret"
    chmod 0600 "$secret_dir/$secret"
done

chown "$postgres_uid:$postgres_gid" \
    "$secret_dir/postgres_bootstrap_password" \
    "$secret_dir/northstar_migrator_password" \
    "$secret_dir/northstar_runtime_password" \
    "$secret_dir/northstar_command_password" \
    "$secret_dir/northstar_backup_password"
chown "$grafana_uid:$grafana_gid" "$secret_dir/grafana_admin_password"
chown "$prometheus_uid:$prometheus_gid" "$secret_dir/prometheus_metrics_bearer_token"
chown "$northstar_uid:$northstar_gid" \
    "$secret_dir/migrator_database_url" \
    "$secret_dir/runtime_database_url" \
    "$secret_dir/command_database_url" \
    "$secret_dir/backup_database_url" \
    "$secret_dir/bootstrap_admin_password" \
    "$secret_dir/dialback_secret" \
    "$secret_dir/fast_token_secret" \
    "$secret_dir/dummy_scram_secret" \
    "$secret_dir/abuse_state_hmac_key" \
    "$secret_dir/api_control_secret" \
    "$secret_dir/metrics_bearer_token" \
    "$secret_dir/backup_signing_ed25519.pem" \
    "$secret_dir/backup_signing_ed25519.pub.pem" \
    "$secret_dir/backup_age_recipients.txt" \
    "$secret_dir/backup_age_identity.txt"
for secret in $optional_hex_names; do
    if [ -e "$secret_dir/$secret" ]; then
        chmod 0600 "$secret_dir/$secret"
        chown "$northstar_uid:$northstar_gid" "$secret_dir/$secret"
    fi
done

assert_secret_boundary
for secret in $secret_names $optional_hex_names; do
    [ -e "$secret_dir/$secret" ] || continue
    [ "$(stat -c '%u:%g' "$secret_dir/$secret")" = "$(expected_owner "$secret")" ] \
        && [ "$(stat -c '%a' "$secret_dir/$secret")" = 600 ] \
        || fail "published secret owner or mode is incorrect: $secret"
done

if [ -n "$created" ]; then
    echo "created production secret files under $secret_dir:$created"
else
    echo "all production secret files under $secret_dir already exist and passed validation; none were changed"
fi
echo "secret values were not printed; protect backup lineage state separately"
