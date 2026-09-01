#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if ! /mnt/c/Windows/System32/curl.exe --version >/dev/null 2>&1; then
  echo "WSL Windows-program interop is unavailable; run scripts/release-runtime-validation.ps1 from PowerShell" >&2
  exit 2
fi
if [[ "$(id -u)" -eq 0 ]]; then
  echo "run the release suite as an ordinary WSL user; only the isolated secret and XEP-0487 fixtures are elevated" >&2
  exit 2
fi

find . -maxdepth 1 -type f -name '*.sh' -exec bash -n {} +
find scripts -maxdepth 1 -type f -name '*.sh' -exec bash -n {} +
find scripts -maxdepth 1 -type f -name '*.py' -exec python3 -m py_compile {} +

bash scripts/test-certificate-security.sh
bash scripts/test-log-security.sh
if sudo -n true >/dev/null 2>&1; then
  sudo -n bash scripts/test-secret-security.sh
else
  echo "the isolated secret ownership fixture requires passwordless sudo; use the PowerShell wrapper if unavailable" >&2
  exit 2
fi
bash scripts/runtime-tls-test-wsl.sh
bash scripts/verify-wsl.sh all
bash scripts/parser-robustness-wsl.sh 30
bash scripts/database-role-boundary-wsl.sh
bash scripts/auth-admin-db-wsl.sh
bash scripts/admin-session-cleanup-db-wsl.sh
bash scripts/authentication-service-db-wsl.sh
bash scripts/abuse-reporting-db-wsl.sh
bash scripts/abuse-key-deployment-db-wsl.sh
bash scripts/message-pow-db-wsl.sh
bash scripts/api-operations-db-wsl.sh
bash scripts/api-pages-db-wsl.sh
bash scripts/migration-upgrade-wsl.sh
bash scripts/migration-0056-db-wsl.sh
bash scripts/rfc7622-identity-db-wsl.sh
bash scripts/identity-audit-db-wsl.sh
bash scripts/jid-identity-db-wsl.sh
bash scripts/authorization-jid-identity-db-wsl.sh
bash scripts/push-jid-identity-db-wsl.sh
bash scripts/push-delivery-db-wsl.sh
bash scripts/mix-jid-identity-db-wsl.sh
bash scripts/session-jid-identity-db-wsl.sh
bash scripts/profile-jid-identity-db-wsl.sh
bash scripts/roster-service-db-wsl.sh
bash scripts/mam-db-wsl.sh
bash scripts/mix-mam-db-wsl.sh
bash scripts/mix-family-db-wsl.sh
bash scripts/muc-db-wsl.sh
bash scripts/pie-db-wsl.sh
bash scripts/privacy-db-wsl.sh
bash scripts/offline-replay-db-wsl.sh
bash scripts/pubsub-db-wsl.sh
bash scripts/pubsub-outbox-db-wsl.sh
bash scripts/pubsub-wire-wsl.sh
bash scripts/retention-db-wsl.sh
bash scripts/sm-db-wsl.sh
bash scripts/s2s-db-wsl.sh
bash scripts/upload-db-wsl.sh
bash scripts/integration-wsl.sh
bash scripts/message-pow-wire-wsl.sh
bash scripts/profile-storage-runtime-wsl.sh
bash scripts/omemo-runtime-wsl.sh
bash scripts/moderation-runtime-wsl.sh
bash scripts/mix-runtime-wsl.sh
bash scripts/federation-wsl.sh
S2S_SASL_EXTERNAL_ENABLED=false bash scripts/federation-wsl.sh
bash scripts/mix-federation-runtime-wsl.sh
bash scripts/component-runtime-wsl.sh
bash scripts/muc-cluster-wsl.sh
bash scripts/cluster-wsl.sh
runtime_uid="$(id -u)"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" == "true" ]]; then
  xep0487_target_dir="${CARGO_TARGET_DIR:-$project_dir/target}"
else
  xep0487_target_dir="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi
sudo -n env \
  XEP0487_RUNTIME_UID="$runtime_uid" \
  CARGO_TARGET_DIR="$xep0487_target_dir" \
  NORTHSTAR_XEP0487_SKIP_BUILD=true \
  XMPP_TEST_OFFLINE="${XMPP_TEST_OFFLINE:-true}" \
  bash scripts/xep0487-runtime-wsl.sh
bash scripts/load-1000-wsl.sh
bash scripts/load-1000-production-wsl.sh
bash scripts/backup-restore-wsl.sh
node_exe="${NORTHSTAR_NODE_EXE:-/mnt/c/Users/Admin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe}"
if [[ ! -x "$node_exe" ]]; then
  echo "Windows Node.js runtime is required for the standalone OMEMO security suite" >&2
  exit 2
fi
"$node_exe" scripts/omemo-security-tests.mjs
bash scripts/browser-e2e-wsl.sh

echo "NOTE: production certificate/secret preflight is intentionally separate: run scripts/release-preflight.sh --production on the deployment host."
echo "NOTE: scripts/production-encryption-probe.sh is intentionally excluded because it inspects an operator-selected account in the production database."
echo "release runtime validation passed"
