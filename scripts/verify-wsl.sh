#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUSTUP_HOME="$project_dir/.rustup-linux"
export CARGO_HOME="$project_dir/.cargo-local"
export CARGO_TARGET_DIR="$project_dir/target-wsl"

cd "$project_dir"

case "${1:-all}" in
  fetch)
    cargo fetch --locked
    ;;
  fmt)
    cargo fmt --all -- --check
    ;;
  check)
    cargo check --all-targets --locked --offline
    ;;
  test)
    cargo test --locked --offline
    ;;
  clippy)
    cargo clippy --all-targets --locked --offline -- -D warnings
    ;;
  all)
    cargo fmt --all -- --check
    cargo check --all-targets --locked --offline
    cargo test --locked --offline
    cargo clippy --all-targets --locked --offline -- -D warnings
    ;;
  *)
    echo "usage: $0 [fetch|fmt|check|test|clippy|all]" >&2
    exit 2
    ;;
esac
