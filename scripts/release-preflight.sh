#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

failures=0
fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    tracked_sensitive=$(git ls-files \
        | grep -E '(^|/)(\.env($|\.)|secrets/|certs/)|\.(key|pem|p12|pfx|jks|keystore|db|sqlite3?)$' \
        | grep -Ev '^(\.env(\..*)?\.example|deploy/secrets/README\.md)$' \
        || true)
    [ -z "$tracked_sensitive" ] || fail "source control contains sensitive/runtime files:\n$tracked_sensitive"
    tracked_private_keys=$(git grep -Il -E 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' -- . || true)
    [ -z "$tracked_private_keys" ] || fail "source control contains private-key material:\n$tracked_private_keys"
else
    echo "WARN: this directory is not a Git worktree; tracked-file checks were skipped" >&2
fi

cargo fmt --all -- --check
cargo check --all-targets --locked
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings

grep -F 'license = "AGPL-3.0-only"' Cargo.toml >/dev/null \
    || fail "Cargo.toml license metadata is not AGPL-3.0-only"
grep -F 'GNU AFFERO GENERAL PUBLIC LICENSE' LICENSE >/dev/null \
    || fail "LICENSE is not the full GNU Affero GPL text"

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
        openssl x509 -in "$cert_path" -noout -checkend 2592000 >/dev/null \
            || fail "TLS certificate expires within 30 days"
        openssl x509 -in "$cert_path" -noout -checkhost "$domain" >/dev/null \
            || fail "TLS certificate SAN does not cover XMPP_DOMAIN"
        cert_key_hash=$(openssl x509 -in "$cert_path" -pubkey -noout | openssl sha256)
        private_key_hash=$(openssl pkey -in "$key_path" -pubout | openssl sha256)
        [ "$cert_key_hash" = "$private_key_hash" ] || fail "TLS certificate and private key do not match"
    fi

    for secret in postgres_password database_url; do
        secret_path="deploy/secrets/$secret"
        [ -s "$secret_path" ] || fail "missing production secret: $secret_path"
        if [ -e "$secret_path" ] && [ "$(stat -c '%a' "$secret_path")" != "600" ]; then
            fail "$secret_path must have mode 0600"
        fi
    done

    if command -v docker >/dev/null 2>&1; then
        docker compose config --quiet
    else
        echo "WARN: Docker is unavailable; Compose validation was skipped" >&2
    fi
fi

if [ "$failures" -ne 0 ]; then
    echo "release preflight failed with $failures problem(s)" >&2
    exit 1
fi

echo "release preflight passed"
