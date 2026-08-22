#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if ! /mnt/c/Windows/System32/curl.exe --version >/dev/null 2>&1; then
  echo "WSL Windows-program interop is unavailable; run scripts/release-runtime-validation.ps1 from PowerShell" >&2
  exit 2
fi

bash -n \
  build.sh \
  build_and_start.sh \
  start_server.sh \
  scripts/create-production-secrets.sh \
  scripts/release-preflight.sh \
  scripts/browser-e2e-server-wsl.sh \
  scripts/start-browser-test-wsl.sh \
  scripts/restart-browser-test-wsl.sh \
  scripts/stop-browser-test-wsl.sh

bash scripts/verify-wsl.sh all
bash scripts/integration-wsl.sh
bash scripts/federation-wsl.sh
bash scripts/load-1000-wsl.sh
bash scripts/browser-e2e-wsl.sh

echo "release runtime validation passed"
