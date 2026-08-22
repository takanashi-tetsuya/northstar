#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pid_file="$project_dir/browser-server.pid"
expected_binary="$project_dir/target-wsl/debug/rust-xmpp-server"

if [[ -f "$pid_file" ]]; then
  server_pid="$(cat "$pid_file")"
  if [[ ! "$server_pid" =~ ^[0-9]+$ ]]; then
    echo "invalid browser-server.pid" >&2
    exit 1
  fi
  if kill -0 "$server_pid" 2>/dev/null; then
    actual_binary="$(readlink "/proc/$server_pid/exe" 2>/dev/null || true)"
    resolved_expected="$(readlink -f "$expected_binary")"
    if [[ "$actual_binary" != "$resolved_expected" && "$actual_binary" != "$resolved_expected (deleted)" ]]; then
      echo "refusing to stop PID $server_pid because it is not the browser test server" >&2
      exit 1
    fi
    kill "$server_pid"
    for _ in $(seq 1 50); do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$server_pid" 2>/dev/null; then
      echo "browser test server did not stop cleanly" >&2
      exit 1
    fi
  fi
  rm -f "$pid_file"
fi
