#!/usr/bin/env bash
set -euo pipefail

# S51 roster, presence and privacy suites (C6/C7 audit): blocklist
# revision journal, blocking presence audiences, privacy commands and
# leases, roster push order, subscription transitions, terminal and
# directed presence, visibility gates, pending subscription replay,
# presence decisions and projection, and the room/PubSub policy
# readers. Every test runs exactly once against one fully migrated
# isolated schema; tests that need their own schema create and remove
# it themselves.

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$project_dir/scripts/lib/isolated-test-schema.sh"
northstar_start_test_schema "northstar_roster_presence_" "roster presence"

cd "$project_dir"
northstar_use_test_toolchain "$project_dir"

run_exact_ignored() {
  local test_name="$1" output
  output="$(TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:${PGPORT:-5432}/xmpp_test?options=-csearch_path%3D$test_schema" \
    cargo test --locked --offline -p northstar-db-it "$test_name" \
    -- --ignored --exact --nocapture --test-threads=1 2>&1)" || {
    printf '%s\n' "$output"
    return 1
  }
  printf '%s\n' "$output"
  grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output" || {
    echo "expected exactly one ignored roster presence test to execute: $test_name" >&2
    return 1
  }
}

run_exact_ignored \
  operations::service_message_claim::disabled_account_cannot_handoff_service_message_claim

run_exact_ignored \
  operations::service_message_claim::expired_service_message_claim_cannot_handoff_after_reclaim

run_exact_ignored \
  operations::service_message_claim::password_change_cannot_handoff_service_message_claim

run_exact_ignored \
  operations::service_message_claim::service_message_claim_handoffs_and_completes_once

run_exact_ignored \
  pubsub::notification_admission::live_active_allow_overrides_default_deny_and_expired_selection_stays_expired

run_exact_ignored \
  pubsub::notification_admission::notification_policy_checks_current_roster_rules_and_auth_generation

run_exact_ignored \
  pubsub::notification_admission::pep_handoff_rechecks_blocks_and_never_delivers_to_a_recreated_account

run_exact_ignored \
  pubsub::notification_admission::profile_explicit_audience_uses_to_and_none_groups_without_implicit_delivery

run_exact_ignored \
  room::mix_preference_roster_lock::deleted_candidate_is_not_recreated_by_the_preference_write

run_exact_ignored \
  room::mix_preference_roster_lock::disabled_candidate_keeps_the_roster_mirror_without_a_push

run_exact_ignored \
  room::mix_preference_roster_lock::share_presence_waits_before_ordinary_roster_set_touches_the_same_item

run_exact_ignored \
  room::room_delivery_policy::decline_block_handover_stays_denied

run_exact_ignored \
  room::room_delivery_policy::mix_archive_live_policy_and_relay_follow_route_and_membership_changes

run_exact_ignored \
  room::room_delivery_policy::muc_policy_read_neither_waits_for_nor_renews_the_active_lease

run_exact_ignored \
  room::room_delivery_policy::muc_replay_history_and_presence_use_live_visible_peer_policy

run_exact_ignored \
  room::room_delivery_policy::remote_mix_relay_cannot_combine_joined_membership_with_a_later_unblock

run_exact_ignored \
  room::room_delivery_policy::suspended_muc_delivery_uses_the_sm_selection_and_room_blocks

run_exact_ignored \
  roster::blocking_presence::commit_samples_inbound_and_outbound_privacy_per_resource

run_exact_ignored \
  roster::blocking_presence::commit_uses_only_the_supplied_route_incarnations

run_exact_ignored \
  roster::blocking_presence::directed_revocation_is_confined_to_the_granting_source_and_exact_peer

run_exact_ignored \
  roster::blocking_presence::empty_delta_skips_roster_lock_and_stale_actor_is_unavailable

run_exact_ignored \
  roster::blocking_presence::quota_refusal_rolls_back_the_actual_delta

run_exact_ignored \
  roster::blocking_presence::residual_and_reverse_blocks_and_reblock_keep_presence_hidden

run_exact_ignored \
  roster::blocking_presence::strict_indexed_matching_agrees_with_scalar_patterns

run_exact_ignored \
  roster::blocking_presence::subscription_update_while_block_waits_is_in_the_committed_audience

run_exact_ignored \
  roster::blocklist_revisions::a_commit_failure_rolls_back_the_delta_counter_and_list

run_exact_ignored \
  roster::blocklist_revisions::block_mutations_fanned_out_in_inverse_order_are_delivered_in_revision_order

run_exact_ignored \
  roster::blocklist_revisions::journal_repairs_a_lost_final_push_without_another_mutation

run_exact_ignored \
  roster::blocklist_revisions::no_op_does_not_append_or_advance_the_counter

run_exact_ignored \
  roster::blocklist_revisions::recreated_account_has_an_independent_revision_journal

run_exact_ignored \
  roster::communication_policy::block_scope_and_account_precedence

run_exact_ignored \
  roster::communication_policy::mixed_batch_preserves_order_and_presence_masks

run_exact_ignored \
  roster::communication_policy::policy_read_leaves_lease_and_locks_untouched

run_exact_ignored \
  roster::communication_policy::policy_swap_uses_one_statement_snapshot

run_exact_ignored \
  roster::communication_policy::privacy_rules_and_selection_fallback

run_exact_ignored \
  roster::federated_inbound::blocked_federated_requester_probe_is_silent

run_exact_ignored \
  roster::federated_inbound::federated_owner_delivery_observes_a_block_committed_after_capture

run_exact_ignored \
  roster::federated_inbound::federated_subscribe_and_subscribed_keep_their_resource_audiences

run_exact_ignored \
  roster::presence_decisions::a_same_name_recreated_owner_cannot_supply_a_captured_probe

run_exact_ignored \
  roster::presence_decisions::broadcast_policy_swap_with_no_allowed_snapshot_never_leaks

run_exact_ignored \
  roster::presence_decisions::broadcast_uses_current_direction_and_enabled_account_incarnation

run_exact_ignored \
  roster::presence_decisions::probe_honors_exact_directed_authority_and_bilateral_blocks

run_exact_ignored \
  roster::presence_decisions::replay_checks_grant_again_after_recipient_capture

run_exact_ignored \
  roster::presence_projection::committed_avatar_is_projected_over_old_local_and_federated_probe_caches

run_exact_ignored \
  roster::presence_projection::nonnegative_priority_is_visible_before_its_database_replay_cutoff

run_exact_ignored \
  roster::privacy_commands::default_and_remove_observe_suspended_lease_and_sm_transfer

run_exact_ignored \
  roster::privacy_commands::default_and_remove_serialize_with_binding_publication_and_release

run_exact_ignored \
  roster::privacy_commands::named_get_is_one_snapshot_during_delete_recreate_and_edit

run_exact_ignored \
  roster::privacy_commands::overview_is_coherent_during_switch_delete_and_selection_expiry

run_exact_ignored \
  roster::privacy_commands::privacy_and_blocklist_gets_follow_one_account_snapshot_during_revocation

run_exact_ignored \
  roster::privacy_commands::privacy_writes_reject_an_actor_revoked_while_waiting_on_the_owner

run_exact_ignored \
  roster::privacy_commands::remote_active_selection_blocks_removal_and_expired_selection_uses_default

run_exact_ignored \
  roster::privacy_lease::activation_and_decline_publish_sm_and_lease_together_before_checkpoint

run_exact_ignored \
  roster::privacy_lease::expired_sm_reference_conflicts_and_expired_sm_policy_fails_closed

run_exact_ignored \
  roster::privacy_lease::renewal_uses_only_capacity_winners_and_rolls_back_on_privacy_failure

run_exact_ignored \
  roster::privacy_lease::renewal_waiting_on_a_selector_cannot_extend_it_after_expiry

run_exact_ignored \
  roster::privacy_lease::resume_rebuilds_only_the_new_selector_while_old_clear_and_reaper_overlap

run_exact_ignored \
  roster::roster_push_order::bounded_gap_returns_exact_versions_with_proven_get_annotations

run_exact_ignored \
  roster::roster_push_order::delayed_first_commit_is_covered_by_the_get_before_second_commit_is_flushed

run_exact_ignored \
  roster::roster_push_order::password_change_between_commit_and_delivery_keeps_original_push_authority

run_exact_ignored \
  roster::subscription_transitions::approval_duplicates_and_revocation_commit_typed_replies

run_exact_ignored \
  roster::subscription_transitions::component_subscription_uses_transactional_route_outbox

run_exact_ignored \
  roster::subscription_transitions::full_target_evidence_cannot_authorize_a_disabled_or_recreated_account

run_exact_ignored \
  roster::subscription_transitions::inbound_outbox_failure_rolls_back_approval_journal_pending_and_intent

run_exact_ignored \
  roster::subscription_transitions::removal_of_pending_only_remote_or_missing_item_does_not_cancel_request

run_exact_ignored \
  roster::subscription_transitions::removal_settles_disabled_mirror_in_both_directions

run_exact_ignored \
  roster::terminal_presence::live_capture_freezes_terminal_selector_and_recipient_policy

run_exact_ignored \
  roster::terminal_presence::rebind_during_directed_withdrawal_does_not_retarget_acceptance

run_exact_ignored \
  roster::terminal_presence::replacement_while_terminal_policy_is_waiting_cannot_inherit_a_grant

run_exact_ignored \
  roster::terminal_presence::sm_expiry_captures_directed_only_grants_from_an_unavailable_source

run_exact_ignored \
  roster::visibility_gates::a_captured_iq_decision_cannot_authorize_a_replacement_connection_or_generation

run_exact_ignored \
  roster::visibility_gates::carbon_and_ordinary_resource_policy_agree_on_active_default_and_block

run_exact_ignored \
  roster::visibility_gates::iq_visibility_cannot_combine_an_old_roster_grant_with_a_new_policy_allow

run_exact_ignored \
  roster::visibility_gates::ordinary_send_cannot_mix_block_and_privacy_during_default_edit_and_roster_change

run_exact_ignored \
  session::pending_replay::pending_handoff_rechecks_block_and_stored_stanza_edit

run_exact_ignored \
  session::pending_replay::pending_handoff_rechecks_cancellation_and_accepts_the_new_request

run_exact_ignored \
  session::pending_replay::pending_handoff_rechecks_requester_disablement_and_recreation

run_exact_ignored \
  session::pending_replay::pending_handoff_rechecks_selector_expiry_missing_lease_and_same_name_edit

run_exact_ignored \
  session::pending_replay::retry_serializes_with_cancel_and_approval_and_preserves_outbox_order
