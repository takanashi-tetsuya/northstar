#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_retention_it_" "retention"

cd "$project_dir"
northstar_use_test_toolchain "$project_dir"
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::retention::tests::bounded_concurrent_cleanup_is_restart_safe_and_preserves_evidence \
  -- --ignored --exact --nocapture
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::retention::tests::asymmetric_mam_retention_preserves_admission_until_the_last_projection_ends \
  -- --ignored --exact --nocapture
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::retention::tests::offline_retention_and_admin_clear_respect_sm_and_bosh_owners \
  -- --ignored --exact --nocapture
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::data_lifecycle::tests::postgres_hold_cleanup_delete_release_and_audit_invariants \
  -- --ignored --exact --nocapture
TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  subscription_cleanup::tests::postgres_cleanup_preserves_live_subscriptions_and_event_snapshots_and_is_bounded \
  -- --ignored --exact --nocapture
