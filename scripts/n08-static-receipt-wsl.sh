#!/usr/bin/env bash
# Produce one bounded, redacted R04 receipt for the current N08 candidate.
# It does not start a database, listener, container, or network fixture.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

[[ $# -eq 1 && "$1" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
  echo "usage: $0 <run-id>" >&2
  exit 2
}
run_id="$1"
result_dir="$project_dir/logs/northstar-n08-2026-09-08/r04-static/runs/$run_id"
result_dir_resolved="$(realpath -m -- "$result_dir")"
case "$result_dir_resolved" in
  "$project_dir"/logs/northstar-n08-2026-09-08/r04-static/runs/*) ;;
  *) echo "N08 static receipt resolved an unexpected output directory" >&2; exit 2 ;;
esac
mkdir -p -- "$result_dir_resolved"
chmod 700 -- "$result_dir_resolved"

results_file="$result_dir_resolved/results.tsv"
printf 'case_id\tstarted_utc\tfinished_utc\texit_status\tredacted_log\tredacted_sha256\n' >"$results_file"
chmod 600 -- "$results_file"

run_case() {
  local case_id="$1" raw_log redacted_log started finished status checksum
  shift
  raw_log="$result_dir_resolved/${case_id}.raw.log"
  redacted_log="$result_dir_resolved/${case_id}.redacted.log"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  set +e
  "$@" >"$raw_log" 2>&1
  status=$?
  set -e
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if ! python3 "$project_dir/scripts/github_ci_summary.py" \
    --title "N08 R04 $case_id" \
    --redacted-copy "$redacted_log" "$raw_log" >/dev/null 2>&1; then
    printf '%s\n' 'redaction_failed=true; raw log retained mode=0600' >"$redacted_log"
  fi
  chmod 600 -- "$raw_log" "$redacted_log"
  checksum="$(sha256sum "$redacted_log" | awk '{print $1}')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$case_id" "$started" "$finished" "$status" "$(basename "$redacted_log")" "$checksum" >>"$results_file"
  # This runner owns the raw file and retains only its reviewed redacted copy.
  rm -f -- "$raw_log"
  return "$status"
}

export XMPP_TEST_SYSTEM_TOOLCHAIN=true
export XMPP_TEST_OFFLINE=true
export CARGO_TARGET_DIR="$project_dir/target"

run_case fmt cargo fmt --all -- --check || exit $?
run_case check cargo check --workspace --all-targets --all-features --locked --offline || exit $?
run_case test-no-run cargo test --workspace --all-targets --all-features --locked --offline --no-run || exit $?
run_case clippy cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings || exit $?
run_case ci-supervisor bash scripts/test-github-ci-supervisor.sh || exit $?
run_case listener-worker bash scripts/test-listener-stress-worker.sh || exit $?

binary="$project_dir/target/debug/rust-xmpp-server"
[[ -f "$binary" && -x "$binary" ]] || {
  echo 'N08 static receipt did not find the current Linux executable' >&2
  exit 1
}
{
  printf 'rustc=%s\n' "$(rustc --version)"
  printf 'cargo=%s\n' "$(cargo --version)"
  printf 'binary=%s\n' "$binary"
  printf 'binary_size=%s\n' "$(stat -c '%s' "$binary")"
  printf 'binary_sha256=%s\n' "$(sha256sum "$binary" | awk '{print $1}')"
  printf 'features=workspace-all-features\n'
  printf 'profile=dev\n'
} >"$result_dir_resolved/build.tsv"
chmod 600 -- "$result_dir_resolved/build.tsv"
