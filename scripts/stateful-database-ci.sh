#!/usr/bin/env bash
# Execute one isolated database CI shard. The workflow gives every shard its
# own disposable loopback PostgreSQL fixture; each suite below creates its own
# schema/Redis namespace as required. A failed suite must not hide later
# suites: every declared suite emits exactly one terminal result record.
set -Eeuo pipefail

if (( $# != 1 )); then
  echo "usage: $0 <auth-identity|abuse-delivery|collaboration-storage|pubsub-federation>" >&2
  exit 2
fi

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

shard="$1"
declare -a suite_manifest=()

case "$shard" in
  auth-identity)
    suite_manifest=(
      'auth-admin|Auth/admin database|600|auth-admin-db-wsl.sh'
      'admin-session-cleanup|Admin session cleanup database|480|admin-session-cleanup-db-wsl.sh'
      'authentication-service|Authentication service database|600|authentication-service-db-wsl.sh'
      'api-operations|API operations database|600|api-operations-db-wsl.sh'
      'api-pages|API pages database|480|api-pages-db-wsl.sh'
      'migration-upgrade|Migration upgrade database|600|migration-upgrade-wsl.sh'
      'migration-0056-compatibility|Migration 0056 compatibility database|480|migration-0056-db-wsl.sh'
      'rfc7622-identity|RFC 7622 identity database|480|rfc7622-identity-db-wsl.sh'
      'identity-audit|Identity audit database|480|identity-audit-db-wsl.sh'
      'jid-identity|JID identity database|480|jid-identity-db-wsl.sh'
      'authorization-jid-identity|Authorization JID identity database|480|authorization-jid-identity-db-wsl.sh'
      'push-jid-identity|Push JID identity database|480|push-jid-identity-db-wsl.sh'
      'mix-jid-identity|MIX JID identity database|480|mix-jid-identity-db-wsl.sh'
      'session-jid-identity|Session JID identity database|480|session-jid-identity-db-wsl.sh'
      'profile-jid-identity|Profile JID identity database|480|profile-jid-identity-db-wsl.sh'
    )
    ;;
  abuse-delivery)
    suite_manifest=(
      'abuse-reporting|Abuse reporting database|600|abuse-reporting-db-wsl.sh'
      'abuse-key-deployment|Abuse key deployment database|480|abuse-key-deployment-db-wsl.sh'
      'message-pow|Message PoW database|600|message-pow-db-wsl.sh'
      'push-delivery|Push delivery database|480|push-delivery-db-wsl.sh'
      'offline-replay|Offline replay database|600|offline-replay-db-wsl.sh'
      'retention|Retention database|480|retention-db-wsl.sh'
      'stream-management|Stream Management database|600|sm-db-wsl.sh'
      's2s|S2S database|600|s2s-db-wsl.sh'
    )
    ;;
  collaboration-storage)
    suite_manifest=(
      'roster-service|Roster service database|480|roster-service-db-wsl.sh'
      'muc|MUC database|600|muc-db-wsl.sh'
      'pie|PIE database|480|pie-db-wsl.sh'
      'privacy|Privacy database|600|privacy-db-wsl.sh'
      'http-upload|HTTP Upload database|600|upload-db-wsl.sh'
      'muc-cluster|MUC cluster database|600|muc-cluster-wsl.sh'
    )
    ;;
  pubsub-federation)
    suite_manifest=(
      'pubsub|PubSub database|600|pubsub-db-wsl.sh'
      'pubsub-outbox|PubSub outbox database|600|pubsub-outbox-db-wsl.sh'
      'pubsub-wire|PubSub wire integration|600|pubsub-wire-wsl.sh'
    )
    ;;
  *)
    echo "unknown isolated database CI shard: $1" >&2
    exit 2
    ;;
esac

declare -A suite_reported=()
declare -a suite_ids=()
for entry in "${suite_manifest[@]}"; do
  IFS='|' read -r suite_id _ <<<"$entry"
  suite_ids+=("$suite_id")
done

failed_suite_count=0
current_suite_id=""

report_suite() {
  local suite_id="$1" result="$2" stage="$3" status="$4" blocked_by="${5:-}"
  if [[ -n "${suite_reported[$suite_id]+present}" ]]; then
    echo "duplicate terminal result for suite_id=$suite_id" >&2
    exit 70
  fi
  suite_reported["$suite_id"]="$result"
  if [[ -n "$blocked_by" ]]; then
    printf 'phase=database_suite_result shard=%s suite_id=%s result=%s stage=%s exit_status=%s blocked_by=%s\n' \
      "$shard" "$suite_id" "$result" "$stage" "$status" "$blocked_by"
  else
    printf 'phase=database_suite_result shard=%s suite_id=%s result=%s stage=%s exit_status=%s\n' \
      "$shard" "$suite_id" "$result" "$stage" "$status"
  fi
}

report_interrupted_suites() {
  local signal_name="$1" exit_status="$2" source="$3" suite_id
  trap - EXIT HUP INT TERM
  if [[ -n "$current_suite_id" && -z "${suite_reported[$current_suite_id]+present}" ]]; then
    report_suite "$current_suite_id" cancelled process-group-cancellation "$exit_status" "$source-$signal_name"
  fi
  for suite_id in "${suite_ids[@]}"; do
    if [[ -z "${suite_reported[$suite_id]+present}" ]]; then
      report_suite "$suite_id" not-run process-group-cancellation "$exit_status" "$source-$signal_name"
    fi
  done
  exit "$exit_status"
}
trap 'report_interrupted_suites HUP 129 parent-signal' HUP
trap 'report_interrupted_suites INT 130 parent-signal' INT
trap 'report_interrupted_suites TERM 143 parent-signal' TERM

cancellation_signal_name() {
  case "$1" in
    129) printf '%s\n' HUP ;;
    130) printf '%s\n' INT ;;
    143) printf '%s\n' TERM ;;
    *) return 1 ;;
  esac
}

run_suite() {
  local suite_id="$1" title="$2" timeout_seconds="$3" script="$4" status signal_name
  current_suite_id="$suite_id"
  printf 'phase=database_suite_started shard=%s suite_id=%s suite_title=%q timeout_seconds=%s\n' \
    "$shard" "$suite_id" "$title" "$timeout_seconds"
  if NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS="$timeout_seconds" \
    bash scripts/github-ci-run.sh "$title" bash "scripts/$script"; then
    status=0
  else
    status=$?
  fi
  if (( status == 0 )); then
    report_suite "$suite_id" passed command-completed "$status"
  elif (( status == 124 )); then
    failed_suite_count=$((failed_suite_count + 1))
    report_suite "$suite_id" timeout command-deadline "$status"
  elif signal_name="$(cancellation_signal_name "$status")"; then
    # An inner supervisor may have received a parent cancellation before this
    # shell did. Its signal exit status has the same lifecycle meaning as our
    # direct signal traps: do not run another suite after it.
    report_interrupted_suites "$signal_name" "$status" runner-exit-signal
  else
    failed_suite_count=$((failed_suite_count + 1))
    report_suite "$suite_id" failed command-exit "$status"
  fi
  current_suite_id=""
  return 0
}

for entry in "${suite_manifest[@]}"; do
  IFS='|' read -r suite_id title timeout_seconds script <<<"$entry"
  run_suite "$suite_id" "$title" "$timeout_seconds" "$script"
done

printf 'phase=database_shard_completed shard=%s passed=%s failed=%s total=%s\n' \
  "$shard" "$(( ${#suite_ids[@]} - failed_suite_count ))" "$failed_suite_count" "${#suite_ids[@]}"
if (( failed_suite_count > 0 )); then
  exit 1
fi
