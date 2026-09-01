#!/usr/bin/env bash
set -euo pipefail

# This local WSL harness is deliberately pinned to the disposable `xmpp_test`
# database. It owns a cryptographically random schema, forces every sqlx
# connection into it, and removes it on success, failure, or interruption.
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PGPASSWORD="xmpp-test-password"
database_args=(--host 127.0.0.1 --username xmpp_test --dbname xmpp_test)
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test"
schema="api_pages_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$schema" =~ ^api_pages_[0-9a-f]{32}$ ]] || {
    echo "failed to create a safe schema name" >&2
    exit 1
}

created=0

cleanup() {
    if [[ "$created" == 1 ]]; then
        psql "${database_args[@]}" -v ON_ERROR_STOP=1 \
            -c "DROP SCHEMA IF EXISTS \"$schema\" CASCADE" >/dev/null
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

psql "${database_args[@]}" -v ON_ERROR_STOP=1 \
    -c "CREATE SCHEMA \"$schema\"" >/dev/null
created=1

# PGOPTIONS is interpreted by PostgreSQL when each connection is established;
# unlike a one-off SET, it therefore covers every connection in sqlx's pool.
export PGOPTIONS="-c search_path=$schema"
actual_schema="$(psql "${database_args[@]}" -v ON_ERROR_STOP=1 -Atqc 'SELECT current_schema()')"
[[ "$actual_schema" == "$schema" ]] || {
    echo "database connection did not enter the isolated schema" >&2
    exit 1
}

cd "$project_dir"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
    export PATH="$project_dir/.cargo-linux:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    export RUSTUP_HOME="$project_dir/.rustup-linux"
    export CARGO_HOME="$project_dir/.cargo-local"
    export CARGO_TARGET_DIR="$project_dir/target-wsl"
fi

test_name='db::api_pages::tests::postgres_keyset_pages_are_stable_isolated_and_indexed'
if ! test_output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture 2>&1)"; then
    printf '%s\n' "$test_output"
    exit 1
fi
printf '%s\n' "$test_output"
grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$test_output" || {
    echo "expected exactly one isolated api_pages PostgreSQL test to execute" >&2
    exit 1
}

cleanup
created=0
schema_remains="$(psql "${database_args[@]}" -v ON_ERROR_STOP=1 -Atqc \
    "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$schema')")"
[[ "$schema_remains" == "f" ]] || {
    echo "isolated api_pages schema was not removed" >&2
    exit 1
}
trap - EXIT
