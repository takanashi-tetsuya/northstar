#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_abuse_reporting_it_" "abuse/reporting"

cd "$project_dir"
northstar_use_test_toolchain "$project_dir"
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema"

scope="${ABUSE_REPORTING_TEST_SCOPE:-all}"
if [[ "$scope" != "reports" && "$scope" != "atomic" && "$scope" != "legacy" ]]; then
  cargo test --locked --offline \
    abuse::tests::postgres_challenges_are_one_use_restart_safe_and_deidentified \
    -- --ignored --nocapture
  cargo test --locked --offline \
    abuse::tests::postgres_accepts_one_thousand_independent_actor_decisions \
    -- --ignored --nocapture
fi
if [[ "$scope" != "abuse" && "$scope" != "atomic" ]]; then
  cargo test --locked --offline \
    db::reports::tests::report_evidence_is_owned_peer_bound_atomic_and_moderation_is_serialized \
    -- --ignored --nocapture
fi
if [[ "$scope" != "abuse" && "$scope" != "legacy" ]]; then
  cargo test --locked --offline \
    db::reports::tests::report_and_appeal_transactions_are_idempotent_pow_atomic_and_serialized \
    -- --ignored --nocapture
fi
