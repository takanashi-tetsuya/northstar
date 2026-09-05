#!/usr/bin/env bash
# Execute one isolated database CI shard.  The workflow gives every shard its
# own disposable loopback PostgreSQL fixture; each script below creates its
# own schema/Redis namespace as required.  Keep the mapping explicit so a new
# persistence test cannot silently disappear from required CI coverage.
set -Eeuo pipefail

if (( $# != 1 )); then
  echo "usage: $0 <auth-identity|abuse-delivery|collaboration-storage|pubsub-federation>" >&2
  exit 2
fi

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"

shard="$1"

run_suite() {
  local title="$1" timeout_seconds="$2" script="$3"
  printf 'phase=database_suite_started shard=%s suite=%q timeout_seconds=%s\n' \
    "$shard" "$title" "$timeout_seconds"
  NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS="$timeout_seconds" \
    bash scripts/github-ci-run.sh "$title" bash "scripts/$script"
  printf 'phase=database_suite_completed suite=%q\n' "$title"
}

case "$shard" in
  auth-identity)
    run_suite 'Auth/admin database' 600 auth-admin-db-wsl.sh
    run_suite 'Admin session cleanup database' 480 admin-session-cleanup-db-wsl.sh
    run_suite 'Authentication service database' 600 authentication-service-db-wsl.sh
    run_suite 'API operations database' 600 api-operations-db-wsl.sh
    run_suite 'API pages database' 480 api-pages-db-wsl.sh
    run_suite 'Migration upgrade database' 600 migration-upgrade-wsl.sh
    run_suite 'Migration 0056 compatibility database' 480 migration-0056-db-wsl.sh
    run_suite 'RFC 7622 identity database' 480 rfc7622-identity-db-wsl.sh
    run_suite 'Identity audit database' 480 identity-audit-db-wsl.sh
    run_suite 'JID identity database' 480 jid-identity-db-wsl.sh
    run_suite 'Authorization JID identity database' 480 authorization-jid-identity-db-wsl.sh
    run_suite 'Push JID identity database' 480 push-jid-identity-db-wsl.sh
    run_suite 'MIX JID identity database' 480 mix-jid-identity-db-wsl.sh
    run_suite 'Session JID identity database' 480 session-jid-identity-db-wsl.sh
    run_suite 'Profile JID identity database' 480 profile-jid-identity-db-wsl.sh
    ;;
  abuse-delivery)
    run_suite 'Abuse reporting database' 600 abuse-reporting-db-wsl.sh
    run_suite 'Abuse key deployment database' 480 abuse-key-deployment-db-wsl.sh
    run_suite 'Message PoW database' 600 message-pow-db-wsl.sh
    run_suite 'Push delivery database' 480 push-delivery-db-wsl.sh
    run_suite 'Offline replay database' 600 offline-replay-db-wsl.sh
    run_suite 'Retention database' 480 retention-db-wsl.sh
    run_suite 'Stream Management database' 600 sm-db-wsl.sh
    run_suite 'S2S database' 600 s2s-db-wsl.sh
    ;;
  collaboration-storage)
    run_suite 'Roster service database' 480 roster-service-db-wsl.sh
    run_suite 'MUC database' 600 muc-db-wsl.sh
    run_suite 'PIE database' 480 pie-db-wsl.sh
    run_suite 'Privacy database' 600 privacy-db-wsl.sh
    run_suite 'HTTP Upload database' 600 upload-db-wsl.sh
    run_suite 'MUC cluster database' 600 muc-cluster-wsl.sh
    ;;
  pubsub-federation)
    run_suite 'PubSub database' 600 pubsub-db-wsl.sh
    run_suite 'PubSub outbox database' 600 pubsub-outbox-db-wsl.sh
    run_suite 'PubSub wire integration' 600 pubsub-wire-wsl.sh
    ;;
  *)
    echo "unknown isolated database CI shard: $1" >&2
    exit 2
    ;;
esac
