#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_mix_mam_" "MIX MAM"

cd "$project_dir"
northstar_use_test_toolchain "$project_dir"

TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
  cargo test --locked --offline \
  db::mix::mam_integration_tests::mix_mam_snapshot_filters_cursors_and_metadata_are_consistent \
  -- --ignored --nocapture
