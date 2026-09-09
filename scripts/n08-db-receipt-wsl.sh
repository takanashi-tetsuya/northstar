#!/usr/bin/env bash
# Execute one N08 database card in a private loopback PostgreSQL fixture and
# publish only a verified redacted control receipt. Raw output is retained
# locally when evidence generation fails; it is never replaced with a fake log.

set -Eeuo pipefail
set +x
umask 077

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

valid_exit_status() { [[ "$1" =~ ^[0-9]+$ ]]; }

read_private_status() {
  local path=$1
  local -a lines=()
  [[ -f "$path" && ! -L "$path" ]] || return 1
  mapfile -t lines <"$path"
  (( ${#lines[@]} == 1 )) && valid_exit_status "${lines[0]}" || return 1
  printf '%s\n' "${lines[0]}"
}

redact_control_log() {
  python3 "$project_dir/scripts/github_ci_summary.py" \
    --title "N08 $stage $card_name private PostgreSQL card" \
    --redacted-copy "$redacted_log" "$raw_log"
}

execute_fixture_command() {
  NORTHSTAR_PRIVATE_PG_CHILD_STATUS_FILE="$child_status_file" \
  NORTHSTAR_PRIVATE_PG_CLEANUP_STATUS_FILE="$fixture_cleanup_status_file" \
  XMPP_TEST_SYSTEM_TOOLCHAIN=true \
  XMPP_TEST_OFFLINE=true \
  CARGO_TARGET_DIR="$project_dir/target" \
  NORTHSTAR_CI_DIAGNOSTICS_DIR="$result_dir_resolved/diagnostics" \
  bash "$project_dir/scripts/private-loopback-postgres-wsl.sh" --max-connections 64 -- \
    bash "$project_dir/$card_script"
}

write_receipt_status() {
  local started=$1 finished=$2 fixture_status=$3 business_status=$4
  local redaction_status=$5 fixture_cleanup_status=$6 raw_cleanup_status=$7
  local wrapper_status=$8 raw_state=$9 redacted_state=${10} raw_hash=${11} redacted_hash=${12}
  printf '%s\n' \
    'stage	card	started_utc	finished_utc	fixture_exit_status	business_exit_status	redaction_exit_status	fixture_cleanup_exit_status	raw_cleanup_exit_status	wrapper_exit_status	raw_log_state	redacted_log_state	raw_sha256	redacted_sha256' \
    >"$status_file"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$stage" "$card_name" "$started" "$finished" "$fixture_status" \
    "$business_status" "$redaction_status" "$fixture_cleanup_status" \
    "$raw_cleanup_status" "$wrapper_status" "$raw_state" "$redacted_state" \
    "$raw_hash" "$redacted_hash" >>"$status_file"
  chmod 600 -- "$status_file"
}

run_receipt() {
  local started finished fixture_status business_status fixture_cleanup_status
  local redaction_status raw_cleanup_status wrapper_status raw_state redacted_state raw_hash redacted_hash
  : >"$raw_log"
  chmod 600 -- "$raw_log"
  rm -f -- "$redacted_log"
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if execute_fixture_command >"$raw_log" 2>&1; then fixture_status=0; else fixture_status=$?; fi
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  business_status="$(read_private_status "$child_status_file" 2>/dev/null || printf '%s' not-recorded)"
  fixture_cleanup_status="$(read_private_status "$fixture_cleanup_status_file" 2>/dev/null || printf '%s' not-recorded)"
  if redact_control_log >/dev/null 2>&1 && [[ -f "$redacted_log" && ! -L "$redacted_log" ]]; then
    redaction_status=0
    chmod 600 -- "$redacted_log"
    redacted_state=valid
    redacted_hash="$(sha256sum "$redacted_log" | awk '{print $1}')"
    raw_hash="$(sha256sum "$raw_log" | awk '{print $1}')"
    if rm -f -- "$raw_log"; then raw_cleanup_status=0; raw_state=removed_after_verified_redaction; else raw_cleanup_status=1; raw_state=retained_cleanup_failed; fi
  else
    redaction_status=$?
    (( redaction_status == 0 )) && redaction_status=1
    rm -f -- "$redacted_log" || true
    chmod 600 -- "$raw_log"
    raw_hash="$(sha256sum "$raw_log" | awk '{print $1}')"
    redacted_hash=not-generated
    raw_cleanup_status=not-applicable
    raw_state=retained_redaction_failed
    redacted_state=not-generated
  fi
  wrapper_status=$fixture_status
  # The receipt wrapper always supplies both status paths.  A missing or
  # failed child/fixture cleanup attestation cannot be reported as a complete
  # success even if the parent process happened to return zero.
  if [[ "$business_status" == not-recorded && "$wrapper_status" == 0 ]]; then
    wrapper_status=1
  fi
  if [[ "$fixture_cleanup_status" != 0 && "$wrapper_status" == 0 ]]; then
    if valid_exit_status "$fixture_cleanup_status"; then
      wrapper_status=$fixture_cleanup_status
    else
      wrapper_status=1
    fi
  fi
  if (( redaction_status != 0 && wrapper_status == 0 )); then wrapper_status=$redaction_status; fi
  if [[ "$raw_cleanup_status" == 1 && "$wrapper_status" == 0 ]]; then wrapper_status=1; fi
  write_receipt_status "$started" "$finished" "$fixture_status" "$business_status" \
    "$redaction_status" "$fixture_cleanup_status" "$raw_cleanup_status" \
    "$wrapper_status" "$raw_state" "$redacted_state" "$raw_hash" "$redacted_hash"
  return "$wrapper_status"
}

run_receipt_state_self_test() {
  local test_root='' case_name business_case redaction_case expected_status observed_status record_cleanup_status
  test_root="$(mktemp -d "${TMPDIR:-/tmp}/northstar-n08-db-receipt-self-test.XXXXXX")"
  (
    execute_fixture_command() {
      printf '%s\n' 'n08-sensitive-sentinel'
      printf '%s\n' "$business_case" >"$child_status_file"
      if [[ "$record_cleanup_status" == true ]]; then
        printf '%s\n' 0 >"$fixture_cleanup_status_file"
      fi
      return "$business_case"
    }
    redact_control_log() {
      if [[ "$redaction_case" == 0 ]]; then sed 's/n08-sensitive-sentinel/[redacted]/g' "$raw_log" >"$redacted_log"; else return "$redaction_case"; fi
    }
    for case_name in success redaction-failure business-failure both-fail missing-cleanup-status; do
      case "$case_name" in
        success) business_case=0; redaction_case=0; record_cleanup_status=true; expected_status=0 ;;
        redaction-failure) business_case=0; redaction_case=17; record_cleanup_status=true; expected_status=17 ;;
        business-failure) business_case=23; redaction_case=0; record_cleanup_status=true; expected_status=23 ;;
        both-fail) business_case=23; redaction_case=17; record_cleanup_status=true; expected_status=23 ;;
        missing-cleanup-status) business_case=0; redaction_case=0; record_cleanup_status=false; expected_status=1 ;;
      esac
      stage=TEST; card_name="$case_name"; result_dir_resolved="$test_root/$case_name"
      mkdir -p -- "$result_dir_resolved"
      raw_log="$result_dir_resolved/control.raw.log"; redacted_log="$result_dir_resolved/control.redacted.log"; status_file="$result_dir_resolved/status.tsv"
      child_status_file="$result_dir_resolved/private-fixture-child.status"; fixture_cleanup_status_file="$result_dir_resolved/private-fixture-cleanup.status"
      if run_receipt; then observed_status=0; else observed_status=$?; fi
      [[ "$observed_status" == "$expected_status" ]] || exit 1
      grep -Fq 'n08-sensitive-sentinel' "$status_file" && exit 1
      if [[ "$redaction_case" == 0 ]]; then
        [[ ! -e "$raw_log" && -f "$redacted_log" ]] || exit 1
        grep -Fq 'n08-sensitive-sentinel' "$redacted_log" && exit 1
      else
        [[ -f "$raw_log" && ! -e "$redacted_log" ]] || exit 1
        grep -Fq 'n08-sensitive-sentinel' "$raw_log" || exit 1
      fi
      # A successful negative grep above returns one; make the completed test
      # case itself successful rather than letting the loop leak that status.
      true
    done
  ) || { rm -rf -- "$test_root"; echo 'N08 database receipt state self-test failed' >&2; return 1; }
  rm -rf -- "$test_root"
  printf '%s\n' 'N08 database receipt state self-test passed'
}

if [[ "${1:-}" == '--self-test-receipt-state' ]]; then
  [[ $# -eq 1 ]] || { echo 'self-test accepts no additional arguments' >&2; exit 2; }
  run_receipt_state_self_test
  exit 0
fi

[[ $# -eq 2 && "$2" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || {
  echo "usage: $0 <R06|R07|R08> <run-id>" >&2
  exit 2
}
stage="$1"; run_id="$2"
case "$stage" in
  R06) card_script="scripts/n08-db01-wsl.sh"; card_name="db01" ;;
  R07) card_script="scripts/n08-r07-upgrade-wsl.sh"; card_name="db08-db03-db04" ;;
  R08) card_script="scripts/n08-r08-template-clone-wsl.sh"; card_name="db05" ;;
  *) echo 'N08 database receipt refused an unplanned card' >&2; exit 2 ;;
esac
result_dir="$project_dir/logs/northstar-n08-2026-09-08/${stage,,}-${card_name}/runs/$run_id"
result_dir_resolved="$(realpath -m -- "$result_dir")"
case "$result_dir_resolved" in
  "$project_dir"/logs/northstar-n08-2026-09-08/r0*-*/runs/*) ;;
  *) echo 'N08 database receipt resolved an unexpected output directory' >&2; exit 2 ;;
esac
mkdir -p -- "$result_dir_resolved"
chmod 700 -- "$result_dir_resolved"
raw_log="$result_dir_resolved/control.raw.log"; redacted_log="$result_dir_resolved/control.redacted.log"; status_file="$result_dir_resolved/status.tsv"
child_status_file="$result_dir_resolved/private-fixture-child.status"; fixture_cleanup_status_file="$result_dir_resolved/private-fixture-cleanup.status"
run_receipt
