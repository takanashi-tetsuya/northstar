#!/usr/bin/env bash
# Execute one N08 database card in a new private loopback PostgreSQL fixture
# and retain only a redacted control receipt. The card scripts own the actual
# migration/runtime assertions; this wrapper only provides bounded evidence.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

[[ $# -eq 2 && "$2" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
  echo "usage: $0 <R06|R07|R08> <run-id>" >&2
  exit 2
}
stage="$1"
run_id="$2"
case "$stage" in
  R06) card_script="scripts/n08-db01-wsl.sh"; card_name="db01" ;;
  R07) card_script="scripts/n08-r07-upgrade-wsl.sh"; card_name="db08-db03-db04" ;;
  R08) card_script="scripts/n08-r08-template-clone-wsl.sh"; card_name="db05" ;;
  *) echo "N08 database receipt refused an unplanned card" >&2; exit 2 ;;
esac

result_dir="$project_dir/logs/northstar-n08-2026-09-08/${stage,,}-${card_name}/runs/$run_id"
result_dir_resolved="$(realpath -m -- "$result_dir")"
case "$result_dir_resolved" in
  "$project_dir"/logs/northstar-n08-2026-09-08/r0*-*/runs/*) ;;
  *) echo "N08 database receipt resolved an unexpected output directory" >&2; exit 2 ;;
esac
mkdir -p -- "$result_dir_resolved"
chmod 700 -- "$result_dir_resolved"

raw_log="$result_dir_resolved/control.raw.log"
redacted_log="$result_dir_resolved/control.redacted.log"
status_file="$result_dir_resolved/status.tsv"
: >"$raw_log"
chmod 600 -- "$raw_log"

started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
XMPP_TEST_SYSTEM_TOOLCHAIN=true \
XMPP_TEST_OFFLINE=true \
CARGO_TARGET_DIR="$project_dir/target" \
NORTHSTAR_CI_DIAGNOSTICS_DIR="$result_dir_resolved/diagnostics" \
bash "$project_dir/scripts/private-loopback-postgres-wsl.sh" --max-connections 64 -- \
  bash "$project_dir/$card_script" >"$raw_log" 2>&1
status=$?
set -e
finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ! python3 "$project_dir/scripts/github_ci_summary.py" \
  --title "N08 $stage $card_name private PostgreSQL card" \
  --redacted-copy "$redacted_log" "$raw_log" >/dev/null 2>&1; then
  printf '%s\n' 'redaction_failed=true; raw control log retained mode=0600' >"$redacted_log"
fi
chmod 600 -- "$redacted_log"
raw_sha256="$(sha256sum "$raw_log" | awk '{print $1}')"
redacted_sha256="$(sha256sum "$redacted_log" | awk '{print $1}')"
printf 'stage\tcard\tstarted_utc\tfinished_utc\texit_status\traw_sha256\tredacted_sha256\n' >"$status_file"
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$stage" "$card_name" "$started" "$finished" "$status" "$raw_sha256" "$redacted_sha256" >>"$status_file"
chmod 600 -- "$status_file"
rm -f -- "$raw_log"
exit "$status"
