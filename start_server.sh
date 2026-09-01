#!/usr/bin/env sh
set -eu
umask 077

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"

# Development convenience wrapper only. Run the explicit migration command
# first; production must use the supervised deployment procedure.
[ -f .env ] || {
    echo "Missing .env; copy .env.development.example and configure its local database URLs." >&2
    exit 1
}
echo "Starting Northstar in the foreground. Press Ctrl-C for a graceful shutdown."
exec cargo run --locked
