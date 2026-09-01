#!/usr/bin/env sh
set -eu
set +x

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

failures=0
fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

node scripts/test-release-preflight-sensitive-files.mjs \
    || fail "tracked sensitive-file policy self-test failed"
node scripts/check-tracked-sensitive-files.mjs --include-untracked \
    || fail "source control contains sensitive/runtime files"
node scripts/check-process-isolation.mjs \
    || fail "test tooling contains broad process termination that could stop unrelated applications"
node scripts/check-parser-fuzz-coverage.mjs \
    || fail "parser fuzz targets do not exercise their declared production parser boundaries"

sh scripts/check-migration-versions.sh \
    || fail "database migration version validation failed"
sh scripts/check-compose-config-mapping.sh \
    || fail "Compose security/protocol configuration mapping validation failed"
bash scripts/check-database-role-boundaries.sh \
    || fail "database role and secret-isolation validation failed"
sh scripts/test-log-security.sh \
    || fail "log permission and container rotation validation failed"
node scripts/check-architecture-boundaries.mjs \
    || fail "application-service architecture boundary validation failed"
node scripts/check-documentation-consistency.mjs \
    || fail "documentation and protocol traceability validation failed"
node scripts/check-outbound-xml-construction.mjs \
    || fail "outbound XML construction validation failed"
node scripts/verify-crypto-artifacts.mjs \
    || fail "browser cryptographic artifact provenance validation failed"
node scripts/verify-libomemo-rebuild-qualification.mjs --self-test --ci \
    || fail "browser cryptographic artifact provenance validation failed"
node scripts/verify-swagger-ui-artifacts.mjs \
    || fail "self-hosted Swagger UI artifact validation failed"
node scripts/check-abuse.mjs \
    || fail "anti-abuse browser invariants failed"
node scripts/check-avatar-editor.mjs \
    || fail "avatar editor invariants failed"
node scripts/check-omemo.mjs \
    || fail "OMEMO browser invariants failed"
node scripts/check-omemo-recovery.mjs \
    || fail "OMEMO one-time device-transfer invariants failed"
node scripts/check-outbox-delivery.mjs \
    || fail "browser encrypted-outbox settlement invariants failed"
node scripts/check-web-auth.mjs \
    || fail "browser authentication invariants failed"
node scripts/omemo-security-tests.mjs \
    || fail "OMEMO security behavior model failed"
node scripts/check-i18n.mjs \
    || fail "recommended-language localization inventory failed"
node scripts/check-locales.mjs \
    || fail "generated static language packs are incomplete"

cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit || fail "RustSec dependency audit failed"
else
    fail "cargo-audit is required for release preflight"
fi
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny --all-features --locked check || fail "dependency policy check failed"
else
    fail "cargo-deny is required for release preflight"
fi

grep -F 'license = "AGPL-3.0-only"' Cargo.toml >/dev/null \
    || fail "Cargo.toml license metadata is not AGPL-3.0-only"
grep -F 'GNU AFFERO GENERAL PUBLIC LICENSE' LICENSE >/dev/null \
    || fail "LICENSE is not the full GNU Affero GPL text"
grep -F 'repository = "https://github.com/takanashi-tetsuya/northstar"' Cargo.toml >/dev/null \
    || fail "Cargo.toml repository metadata is missing or incorrect"
package_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
[ -n "$package_version" ] || fail "Cargo.toml package version could not be read"
grep -F "channel = \"1.97.1\"" rust-toolchain.toml >/dev/null \
    || fail "rust-toolchain.toml does not pin the release toolchain"
release_toolchain=$(sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml)
[ -n "$release_toolchain" ] || fail "rust-toolchain.toml release channel could not be read"
release_toolchain_regex=$(printf '%s\n' "$release_toolchain" | sed 's/[.]/\\./g')
grep -E "^FROM rust:${release_toolchain}-bookworm@sha256:[0-9a-f]{64} AS builder$" Dockerfile >/dev/null \
    || fail "Dockerfile builder tag does not identify the pinned Rust $release_toolchain toolchain"
grep -F "RUN rustc --version | grep -E '^rustc ${release_toolchain_regex} '" Dockerfile >/dev/null \
    || fail "Dockerfile does not verify the pinned Rust $release_toolchain compiler"
for image_file in Dockerfile deploy/backup.Dockerfile deploy/database-grants.Dockerfile; do
    grep -F "ARG NORTHSTAR_VERSION=$package_version" "$image_file" >/dev/null \
        || fail "$image_file OCI version does not match Cargo.toml"
    grep -F 'org.opencontainers.image.licenses="AGPL-3.0-only"' "$image_file" >/dev/null \
        || fail "$image_file does not declare the project license"
    grep -F 'LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/northstar/' "$image_file" >/dev/null \
        || fail "$image_file does not install project license notices"
done
unpinned_actions=$(grep -ERn '^[[:space:]]*uses:[[:space:]]+[^@[:space:]]+@' .github/workflows \
    | grep -Ev '@[0-9a-f]{40}([[:space:]]*#.*)?$' || true)
[ -z "$unpinned_actions" ] \
    || fail "GitHub Actions must use a full immutable commit SHA:\n$unpinned_actions"
unpinned_build_images=$(grep -H '^FROM ' Dockerfile deploy/backup.Dockerfile deploy/database-grants.Dockerfile \
    | grep -Ev '@sha256:[0-9a-f]{64}([[:space:]]|$)' || true)
[ -z "$unpinned_build_images" ] \
    || fail "Dockerfile base images must use immutable sha256 digests:\n$unpinned_build_images"
unpinned_compose_images=$(grep -E '^[[:space:]]+image:' docker-compose.yml \
    | grep -Ev '@sha256:[0-9a-f]{64}([[:space:]]|$)' || true)
[ -z "$unpinned_compose_images" ] \
    || fail "Compose images must use immutable sha256 digests:\n$unpinned_compose_images"
unpinned_ci_images=$(grep -EH '^[[:space:]]+image:' .github/workflows/*.yml \
    | grep -Ev '@sha256:[0-9a-f]{64}([[:space:]]|$)' || true)
[ -z "$unpinned_ci_images" ] \
    || fail "CI service images must use immutable sha256 digests:\n$unpinned_ci_images"
mutable_rust_toolchains=$(grep -En 'rustup (toolchain install|default) stable|toolchain:[[:space:]]*stable' \
    .github/workflows/*.yml || true)
[ -z "$mutable_rust_toolchains" ] \
    || fail "CI Rust toolchains must use an explicit release:\n$mutable_rust_toolchains"

if [ "${1:-}" = "--production" ]; then
    [ -f .env ] || fail ".env is missing"
    domain=$(sed -n 's/^XMPP_DOMAIN=//p' .env | tail -n 1)
    public_url=$(sed -n 's/^PUBLIC_URL=//p' .env | tail -n 1)
    cert_path=$(sed -n 's/^TLS_CERT_HOST_PATH=//p' .env | tail -n 1)
    key_path=$(sed -n 's/^TLS_KEY_HOST_PATH=//p' .env | tail -n 1)
    cert_path=${cert_path:-certs/server.crt}
    key_path=${key_path:-certs/server.key}

    [ -n "$domain" ] && [ "$domain" != "localhost" ] || fail "XMPP_DOMAIN must be a public production domain"
    case "$public_url" in
        https://*) ;;
        *) fail "PUBLIC_URL must use HTTPS in production" ;;
    esac
    [ -f "$cert_path" ] || fail "production TLS certificate is missing"
    [ -f "$key_path" ] || fail "production TLS private key is missing"
    if [ -f "$cert_path" ] && [ -f "$key_path" ] && [ -n "$domain" ]; then
        sh scripts/verify-production-certificate.sh "$cert_path" "$key_path" "$domain" >/dev/null \
            || fail "strict production TLS certificate validation failed"
        [ "$(stat -c '%u:%g' "$key_path")" = "10001:10001" ] \
            || fail "the Compose TLS private key must be owned by UID/GID 10001:10001"
    fi

    secret_root=$(sed -n 's/^NORTHSTAR_SECRET_DIR=//p' .env | tail -n 1)
    secret_root=${secret_root:-/etc/northstar/secrets}
    case "$secret_root" in
        /*) ;;
        *) fail "NORTHSTAR_SECRET_DIR must be absolute" ;;
    esac
    case "$secret_root" in
        /|*/|*/.|*/..|*/./*|*/../*|*//*)
            fail "NORTHSTAR_SECRET_DIR must be a canonical dedicated path"
            ;;
    esac
    [ -d "$secret_root" ] && [ ! -L "$secret_root" ] \
        || fail "NORTHSTAR_SECRET_DIR must be a real directory"
    if [ -d "$secret_root" ] && [ ! -L "$secret_root" ]; then
        [ "$(stat -c '%u:%g' "$secret_root")" = 0:0 ] \
            || fail "NORTHSTAR_SECRET_DIR must be owned by root:root"
        [ "$(stat -c '%a' "$secret_root")" = 700 ] \
            || fail "NORTHSTAR_SECRET_DIR must have mode 0700"
    fi
    secret_parent=$(dirname -- "$secret_root")
    [ -d "$secret_parent" ] && [ ! -L "$secret_parent" ] \
        && [ "$(stat -c '%u:%g' "$secret_parent")" = 0:0 ] \
        && [ "$(stat -c '%a' "$secret_parent")" = 700 ] \
        || fail "the production secret parent must be a real root:root mode-0700 directory"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$secret_root" <<'PY' || fail "the production secret path has a linked, non-root, or replaceable ancestor"
import os
import pathlib
import stat
import sys

current = pathlib.Path("/")
for part in pathlib.Path(sys.argv[1]).parts[1:]:
    current /= part
    info = os.lstat(current)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise SystemExit(1)
    if info.st_uid != 0:
        raise SystemExit(1)
    if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
        raise SystemExit(1)
PY
    else
        fail "python3 is required to validate every production secret-path ancestor"
    fi

    postgres_bootstrap_secret_path=$(sed -n 's/^POSTGRES_BOOTSTRAP_PASSWORD_SECRET_FILE=//p' .env | tail -n 1)
    postgres_bootstrap_secret_path=${postgres_bootstrap_secret_path:-$secret_root/postgres_bootstrap_password}
    migrator_password_path=$(sed -n 's/^NORTHSTAR_MIGRATOR_PASSWORD_SECRET_FILE=//p' .env | tail -n 1)
    migrator_password_path=${migrator_password_path:-$secret_root/northstar_migrator_password}
    runtime_password_path=$(sed -n 's/^NORTHSTAR_RUNTIME_PASSWORD_SECRET_FILE=//p' .env | tail -n 1)
    runtime_password_path=${runtime_password_path:-$secret_root/northstar_runtime_password}
    command_password_path=$(sed -n 's/^NORTHSTAR_COMMAND_PASSWORD_SECRET_FILE=//p' .env | tail -n 1)
    command_password_path=${command_password_path:-$secret_root/northstar_command_password}
    backup_password_path=$(sed -n 's/^NORTHSTAR_BACKUP_PASSWORD_SECRET_FILE=//p' .env | tail -n 1)
    backup_password_path=${backup_password_path:-$secret_root/northstar_backup_password}
    migrator_database_url_path=$(sed -n 's/^MIGRATOR_DATABASE_URL_SECRET_FILE=//p' .env | tail -n 1)
    migrator_database_url_path=${migrator_database_url_path:-$secret_root/migrator_database_url}
    runtime_database_url_path=$(sed -n 's/^RUNTIME_DATABASE_URL_SECRET_FILE=//p' .env | tail -n 1)
    runtime_database_url_path=${runtime_database_url_path:-$secret_root/runtime_database_url}
    command_database_url_path=$(sed -n 's/^COMMAND_DATABASE_URL_SECRET_FILE=//p' .env | tail -n 1)
    command_database_url_path=${command_database_url_path:-$secret_root/command_database_url}
    backup_database_url_path=$(sed -n 's/^BACKUP_DATABASE_URL_SECRET_FILE=//p' .env | tail -n 1)
    backup_database_url_path=${backup_database_url_path:-$secret_root/backup_database_url}
    backup_signing_key_path=$(sed -n 's/^BACKUP_SIGNING_KEY_SECRET_FILE=//p' .env | tail -n 1)
    backup_signing_key_path=${backup_signing_key_path:-$secret_root/backup_signing_ed25519.pem}
    backup_verify_key_path=$(sed -n 's/^BACKUP_VERIFY_KEY_SECRET_FILE=//p' .env | tail -n 1)
    backup_verify_key_path=${backup_verify_key_path:-$secret_root/backup_signing_ed25519.pub.pem}
    backup_age_recipients_path=$(sed -n 's/^BACKUP_AGE_RECIPIENTS_SECRET_FILE=//p' .env | tail -n 1)
    backup_age_recipients_path=${backup_age_recipients_path:-$secret_root/backup_age_recipients.txt}
    backup_age_identity_path=$(sed -n 's/^BACKUP_AGE_IDENTITY_SECRET_FILE=//p' .env | tail -n 1)
    backup_age_identity_path=${backup_age_identity_path:-$secret_root/backup_age_identity.txt}
    fast_secret_path=$(sed -n 's/^FAST_TOKEN_SECRET_HOST_FILE=//p' .env | tail -n 1)
    fast_secret_path=${fast_secret_path:-$secret_root/fast_token_secret}
    dummy_scram_secret_path=$(sed -n 's/^DUMMY_SCRAM_SECRET_HOST_FILE=//p' .env | tail -n 1)
    dummy_scram_secret_path=${dummy_scram_secret_path:-$secret_root/dummy_scram_secret}
    abuse_secret_path=$(sed -n 's/^ABUSE_STATE_HMAC_KEY_HOST_FILE=//p' .env | tail -n 1)
    abuse_secret_path=${abuse_secret_path:-$secret_root/abuse_state_hmac_key}
    abuse_previous_secret_path=$(sed -n 's/^ABUSE_STATE_HMAC_PREVIOUS_KEY_HOST_FILE=//p' .env | tail -n 1)
    api_control_secret_path=$(sed -n 's/^API_CONTROL_SECRET_HOST_FILE=//p' .env | tail -n 1)
    api_control_secret_path=${api_control_secret_path:-$secret_root/api_control_secret}
    api_control_previous_secret_path=$(sed -n 's/^API_CONTROL_PREVIOUS_SECRET_HOST_FILE=//p' .env | tail -n 1)
    metrics_secret_path=$(sed -n 's/^METRICS_BEARER_TOKEN_HOST_FILE=//p' .env | tail -n 1)
    metrics_secret_path=${metrics_secret_path:-$secret_root/metrics_bearer_token}
    prometheus_metrics_secret_path=$(sed -n 's/^PROMETHEUS_METRICS_BEARER_TOKEN_HOST_FILE=//p' .env | tail -n 1)
    prometheus_metrics_secret_path=${prometheus_metrics_secret_path:-$secret_root/prometheus_metrics_bearer_token}
    dialback_secret_path=$(sed -n 's/^DIALBACK_SECRET_HOST_FILE=//p' .env | tail -n 1)
    dialback_secret_path=${dialback_secret_path:-$secret_root/dialback_secret}

    check_secret_file() {
        checked_path=$1
        checked_name=$2
        checked_owner=$3
        [ -s "$checked_path" ] || {
            fail "missing production secret: $checked_name"
            return
        }
        if [ ! -f "$checked_path" ] || [ -L "$checked_path" ]; then
            fail "$checked_name must be a regular non-symlink file"
            return
        fi
        [ "$(stat -c '%h' "$checked_path")" = "1" ] \
            || fail "$checked_name must have exactly one hard link"
        [ "$(stat -c '%a' "$checked_path")" = "600" ] \
            || fail "$checked_name must have mode 0600"
        [ "$(stat -c '%u:%g' "$checked_path")" = "$checked_owner" ] \
            || fail "$checked_name must be owned by UID/GID $checked_owner"
    }

    check_secret_file "$postgres_bootstrap_secret_path" postgres_bootstrap_password 70:70
    check_secret_file "$migrator_password_path" northstar_migrator_password 70:70
    check_secret_file "$runtime_password_path" northstar_runtime_password 70:70
    check_secret_file "$command_password_path" northstar_command_password 70:70
    check_secret_file "$backup_password_path" northstar_backup_password 70:70
    check_secret_file "$migrator_database_url_path" migrator_database_url 10001:10001
    check_secret_file "$runtime_database_url_path" runtime_database_url 10001:10001
    check_secret_file "$command_database_url_path" command_database_url 10001:10001
    check_secret_file "$backup_database_url_path" backup_database_url 10001:10001
    check_secret_file "$backup_signing_key_path" backup_signing_ed25519.pem 10001:10001
    check_secret_file "$backup_verify_key_path" backup_signing_ed25519.pub.pem 10001:10001
    check_secret_file "$backup_age_recipients_path" backup_age_recipients.txt 10001:10001
    check_secret_file "$backup_age_identity_path" backup_age_identity.txt 10001:10001
    check_secret_file "$fast_secret_path" fast_token_secret 10001:10001
    check_secret_file "$dummy_scram_secret_path" dummy_scram_secret 10001:10001
    check_secret_file "$abuse_secret_path" abuse_state_hmac_key 10001:10001
    check_secret_file "$api_control_secret_path" api_control_secret 10001:10001
    check_secret_file "$metrics_secret_path" metrics_bearer_token 10001:10001
    check_secret_file "$prometheus_metrics_secret_path" prometheus_metrics_bearer_token 65534:65534

    check_runtime_secret_material() {
        checked_path=$1
        checked_name=$2
        [ -s "$checked_path" ] || return
        python3 - "$checked_path" "$checked_name" <<'PY' || fail "$checked_name must contain 32 to 4096 UTF-8 bytes without NUL after trailing CR/LF removal"
import pathlib
import sys

value = pathlib.Path(sys.argv[1]).read_bytes().decode("utf-8").rstrip("\r\n")
encoded = value.encode("utf-8")
if not 32 <= len(encoded) <= 4096 or b"\x00" in encoded:
    raise SystemExit(1)
PY
    }
    check_runtime_secret_material "$fast_secret_path" fast_token_secret
    check_runtime_secret_material "$dummy_scram_secret_path" dummy_scram_secret
    runtime_secret_material_equal() {
        python3 - "$1" "$2" <<'PY'
import pathlib
import sys

def load(path):
    return pathlib.Path(path).read_bytes().decode("utf-8").rstrip("\r\n")

raise SystemExit(0 if load(sys.argv[1]) == load(sys.argv[2]) else 1)
PY
    }
    if [ -s "$metrics_secret_path" ] && [ -s "$prometheus_metrics_secret_path" ] \
        && ! cmp -s "$metrics_secret_path" "$prometheus_metrics_secret_path"; then
        fail "Northstar and Prometheus metrics bearer-token copies must match"
    fi
    if [ -n "$api_control_previous_secret_path" ]; then
        check_secret_file "$api_control_previous_secret_path" api_control_previous_secret 10001:10001
        if [ -s "$api_control_secret_path" ] && [ -s "$api_control_previous_secret_path" ] \
            && cmp -s "$api_control_secret_path" "$api_control_previous_secret_path"; then
            fail "api_control_previous_secret must differ from the current key"
        fi
    fi
    if [ -n "$abuse_previous_secret_path" ]; then
        check_secret_file "$abuse_previous_secret_path" abuse_state_hmac_previous_key 10001:10001
        if [ -s "$abuse_secret_path" ] && [ -s "$abuse_previous_secret_path" ] \
            && cmp -s "$abuse_secret_path" "$abuse_previous_secret_path"; then
            fail "abuse_state_hmac_previous_key must differ from the current key"
        fi
    fi
    if [ -s "$abuse_secret_path" ] && [ -s "$fast_secret_path" ] \
        && cmp -s "$abuse_secret_path" "$fast_secret_path"; then
        fail "abuse_state_hmac_key must not reuse fast_token_secret"
    fi
    if [ -s "$dummy_scram_secret_path" ] && [ -s "$fast_secret_path" ] \
        && runtime_secret_material_equal "$dummy_scram_secret_path" "$fast_secret_path"; then
        fail "dummy_scram_secret must not reuse fast_token_secret"
    fi
    if [ -s "$dummy_scram_secret_path" ] && [ -s "$abuse_secret_path" ] \
        && runtime_secret_material_equal "$dummy_scram_secret_path" "$abuse_secret_path"; then
        fail "dummy_scram_secret must not reuse abuse_state_hmac_key"
    fi
    if [ -s "$api_control_secret_path" ] && [ -s "$fast_secret_path" ] \
        && cmp -s "$api_control_secret_path" "$fast_secret_path"; then
        fail "api_control_secret must not reuse fast_token_secret"
    fi
    if [ -s "$dummy_scram_secret_path" ] && [ -s "$api_control_secret_path" ] \
        && runtime_secret_material_equal "$dummy_scram_secret_path" "$api_control_secret_path"; then
        fail "dummy_scram_secret must not reuse api_control_secret"
    fi
    if [ -s "$api_control_secret_path" ] && [ -s "$abuse_secret_path" ] \
        && cmp -s "$api_control_secret_path" "$abuse_secret_path"; then
        fail "api_control_secret must not reuse abuse_state_hmac_key"
    fi
    dialback_enabled=$(sed -n 's/^DIALBACK_ENABLED=//p' .env | tail -n 1)
    if [ "${dialback_enabled:-true}" != "false" ]; then
        check_secret_file "$dialback_secret_path" dialback_secret 10001:10001
        if [ -s "$abuse_secret_path" ] && [ -s "$dialback_secret_path" ] \
            && cmp -s "$abuse_secret_path" "$dialback_secret_path"; then
            fail "abuse_state_hmac_key must not reuse dialback_secret"
        fi
        if [ -s "$api_control_secret_path" ] && [ -s "$dialback_secret_path" ] \
            && cmp -s "$api_control_secret_path" "$dialback_secret_path"; then
            fail "api_control_secret must not reuse dialback_secret"
        fi
        if [ -s "$dummy_scram_secret_path" ] && [ -s "$dialback_secret_path" ] \
            && runtime_secret_material_equal "$dummy_scram_secret_path" "$dialback_secret_path"; then
            fail "dummy_scram_secret must not reuse dialback_secret"
        fi
    fi

    verify_role_url() {
        checked_url=$1
        checked_password=$2
        checked_role=$3
        checked_name=$4
        if [ -s "$checked_url" ] && [ -s "$checked_password" ]; then
            role_password=$(tr -d '\r\n' < "$checked_password")
            role_url=$(tr -d '\r\n' < "$checked_url")
            expected_role_url="postgres://$checked_role:${role_password}@postgres:5432/xmpp"
            [ "$role_url" = "$expected_role_url" ] \
                || fail "$checked_name does not match its role password and Compose endpoint"
            unset role_password role_url expected_role_url
        fi
    }
    verify_role_url "$migrator_database_url_path" "$migrator_password_path" northstar_migrator migrator_database_url
    verify_role_url "$runtime_database_url_path" "$runtime_password_path" northstar_runtime runtime_database_url
    verify_role_url "$command_database_url_path" "$command_password_path" northstar_commands command_database_url
    verify_role_url "$backup_database_url_path" "$backup_password_path" northstar_backup backup_database_url

    if [ -s "$backup_signing_key_path" ] && [ -s "$backup_verify_key_path" ]; then
        signing_probe=$(mktemp)
        signing_signature=$(mktemp)
        printf '%s\n' northstar-release-preflight > "$signing_probe"
        openssl pkeyutl -sign -rawin -inkey "$backup_signing_key_path" \
            -in "$signing_probe" -out "$signing_signature" >/dev/null 2>&1 \
            || fail "backup signing private key is not a usable Ed25519 key"
        openssl pkeyutl -verify -rawin -pubin -inkey "$backup_verify_key_path" \
            -in "$signing_probe" -sigfile "$signing_signature" >/dev/null 2>&1 \
            || fail "backup signing and verification keys do not match"
        rm -f -- "$signing_probe" "$signing_signature"
    fi
    if [ -s "$backup_age_recipients_path" ] && [ -s "$backup_age_identity_path" ]; then
        if ! command -v age >/dev/null 2>&1; then
            fail "age is required to validate the production backup encryption identity"
        else
            age_probe=$(mktemp)
            age_ciphertext=$(mktemp)
            age_plaintext=$(mktemp)
            printf '%s\n' northstar-release-preflight > "$age_probe"
            age -R "$backup_age_recipients_path" -o "$age_ciphertext" "$age_probe" >/dev/null 2>&1 \
                || fail "backup age recipients are invalid"
            age -d -i "$backup_age_identity_path" -o "$age_plaintext" "$age_ciphertext" >/dev/null 2>&1 \
                || fail "backup age identity cannot decrypt the configured recipients"
            cmp -s "$age_probe" "$age_plaintext" \
                || fail "backup age encryption self-test changed plaintext"
            rm -f -- "$age_probe" "$age_ciphertext" "$age_plaintext"
        fi
    fi

    if command -v docker >/dev/null 2>&1; then
        docker compose config --quiet
        docker run --rm --entrypoint /bin/promtool \
            -v "$project_dir/monitoring:/etc/northstar-monitoring:ro" \
            prom/prometheus:v3.12.0@sha256:69f5241418838263316593f7274a304b095c40bcf22e57272865da91bd60a8ac \
            check rules /etc/northstar-monitoring/alerts.yml \
            || fail "Prometheus alert-rule syntax validation failed"
        if [ -n "$abuse_previous_secret_path" ]; then
            docker compose -f docker-compose.yml \
                -f deploy/docker-compose.abuse-key-rotation.yml config --quiet
        fi
        if [ -n "$api_control_previous_secret_path" ]; then
            docker compose -f docker-compose.yml \
                -f deploy/docker-compose.api-control-key-rotation.yml config --quiet
        fi
    else
        fail "Docker is required for --production because this mode validates the Compose deployment profile"
    fi
fi

if [ "$failures" -ne 0 ]; then
    echo "release preflight failed with $failures problem(s)" >&2
    exit 1
fi

echo "release preflight passed"
