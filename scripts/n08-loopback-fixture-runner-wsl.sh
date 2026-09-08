#!/usr/bin/env bash
# Run one N08 loopback fixture outside a short-lived interactive WSL caller.
# This is deliberately narrow: it accepts only the four plan-approved
# federation/MIX 1x1 and 1x2 scenarios and delegates all database creation and
# cleanup to private-loopback-postgres-wsl.sh.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

usage() {
  echo "usage: $0 <R09|R10|R11|R12> <federation|mix-federation> <1|2> <run-id>" >&2
}

[[ $# -eq 4 ]] || { usage; exit 2; }
stage="$1"
fixture="$2"
pairs="$3"
run_id="$4"

case "$stage:$fixture:$pairs" in
  R09:federation:1|R10:mix-federation:1|R11:federation:2|R12:mix-federation:2) ;;
  *)
    echo "N08 runner refused an unplanned fixture combination" >&2
    usage
    exit 2
    ;;
esac
[[ "$run_id" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
  echo "N08 runner refused an invalid run identifier" >&2
  exit 2
}

result_dir="$project_dir/logs/northstar-n08-2026-09-08/${stage,,}-${fixture}-pairs-${pairs}/runs/$run_id"
result_dir_resolved="$(realpath -m -- "$result_dir")"
case "$result_dir_resolved" in
  "$project_dir"/logs/northstar-n08-2026-09-08/r*) ;;
  *)
    echo "N08 runner resolved an unexpected result directory" >&2
    exit 2
    ;;
esac
mkdir -p -- "$result_dir_resolved"
chmod 700 -- "$result_dir_resolved"

raw_log="$result_dir_resolved/control.raw.log"
redacted_log="$result_dir_resolved/control.redacted.log"
status_file="$result_dir_resolved/status.tsv"
: >"$raw_log"
chmod 600 -- "$raw_log"

start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
XMPP_TEST_SYSTEM_TOOLCHAIN=true \
XMPP_TEST_OFFLINE=true \
CARGO_TARGET_DIR="$project_dir/target" \
NORTHSTAR_CI_DIAGNOSTICS_DIR="$result_dir_resolved/diagnostics" \
bash "$project_dir/scripts/private-loopback-postgres-wsl.sh" \
  --with-listener-stress-role --max-connections 64 -- \
  bash "$project_dir/scripts/listener-readiness-stress-wsl.sh" \
    --mode regular --fixture "$fixture" --rounds 1 --pairs "$pairs" \
  >"$raw_log" 2>&1
status=$?
set -e
end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if ! python3 "$project_dir/scripts/github_ci_summary.py" \
  --title "N08 $stage $fixture ${pairs}x1 loopback fixture" \
  --redacted-copy "$redacted_log" "$raw_log" >/dev/null 2>&1; then
  printf '%s\n' 'redaction_failed=true; raw control log retained mode=0600' >"$redacted_log"
fi
chmod 600 -- "$redacted_log"
raw_sha256="$(sha256sum "$raw_log" | awk '{print $1}')"
redacted_sha256="$(sha256sum "$redacted_log" | awk '{print $1}')"
printf 'stage\tfixture\tpairs\tstarted_utc\tfinished_utc\texit_status\traw_sha256\tredacted_sha256\n' >"$status_file"
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$stage" "$fixture" "$pairs" "$start_utc" "$end_utc" "$status" "$raw_sha256" "$redacted_sha256" >>"$status_file"
chmod 600 -- "$status_file"

# The only raw file is created by this runner in a result directory it owns.
# The redacted copy and hash remain as the durable receipt.
rm -f -- "$raw_log"
exit "$status"
