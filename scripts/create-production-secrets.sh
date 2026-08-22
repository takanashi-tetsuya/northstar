#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
secret_dir="$project_dir/deploy/secrets"

umask 077
mkdir -p "$secret_dir"

for file in postgres_password database_url bootstrap_admin_password; do
    if [ -e "$secret_dir/$file" ]; then
        echo "refusing to overwrite existing secret: deploy/secrets/$file" >&2
        exit 1
    fi
done

openssl rand -hex 32 > "$secret_dir/postgres_password"
{
    printf 'postgres://xmpp:'
    tr -d '\r\n' < "$secret_dir/postgres_password"
    printf '@postgres:5432/xmpp\n'
} > "$secret_dir/database_url"
openssl rand -base64 36 | tr -d '\r\n' > "$secret_dir/bootstrap_admin_password"
printf '\n' >> "$secret_dir/bootstrap_admin_password"

chmod 600 \
    "$secret_dir/postgres_password" \
    "$secret_dir/database_url" \
    "$secret_dir/bootstrap_admin_password"

echo "created three production secret files under deploy/secrets with mode 0600"
echo "their values were not printed; copy the initial administrator password through a secure local channel"
