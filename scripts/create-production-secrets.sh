#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
secret_dir="$project_dir/deploy/secrets"

umask 077
mkdir -p "$secret_dir"

created=""
if [ -e "$secret_dir/database_url" ] && [ ! -e "$secret_dir/postgres_password" ]; then
    echo "refusing to create a new PostgreSQL password beside an existing database_url secret" >&2
    exit 1
fi
if [ ! -e "$secret_dir/postgres_password" ]; then
    openssl rand -hex 32 > "$secret_dir/postgres_password"
    created="$created postgres_password"
fi
if [ ! -e "$secret_dir/database_url" ]; then
    {
        printf 'postgres://xmpp:'
        tr -d '\r\n' < "$secret_dir/postgres_password"
        printf '@postgres:5432/xmpp\n'
    } > "$secret_dir/database_url"
    created="$created database_url"
fi
if [ ! -e "$secret_dir/bootstrap_admin_password" ]; then
    openssl rand -base64 36 | tr -d '\r\n' > "$secret_dir/bootstrap_admin_password"
    printf '\n' >> "$secret_dir/bootstrap_admin_password"
    created="$created bootstrap_admin_password"
fi
if [ ! -e "$secret_dir/grafana_admin_password" ]; then
    openssl rand -base64 36 | tr -d '\r\n' > "$secret_dir/grafana_admin_password"
    printf '\n' >> "$secret_dir/grafana_admin_password"
    created="$created grafana_admin_password"
fi

chmod 600 \
    "$secret_dir/postgres_password" \
    "$secret_dir/database_url" \
    "$secret_dir/bootstrap_admin_password" \
    "$secret_dir/grafana_admin_password"

if [ -n "$created" ]; then
    echo "created production secret files under deploy/secrets:$created"
else
    echo "all production secret files already exist; none were changed"
fi
echo "secret values were not printed; copy required initial passwords through a secure local channel"
