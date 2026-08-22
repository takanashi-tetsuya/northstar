#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"

cargo build --locked
echo "Starting Northstar in the foreground. Press Ctrl-C for a graceful shutdown."
exec cargo run --locked
