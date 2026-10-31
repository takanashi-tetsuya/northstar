use super::{
    directed_presence_capacity_reached, directed_presence_target_is_outside_bare_scope,
    full_jid_probe_available_response, should_probe_contact_on_presence,
    should_resend_pending_outbound_subscription, stamped_subscription_presence,
    unsubscribed_probe_response,
};
use northstar_presence_core::{directed_recipient_matches, offline_replay_became_eligible};

#[test]
fn offline_replay_starts_on_first_nonnegative_available_priority() {
    assert!(!offline_replay_became_eligible(false, 0, true, -1));
    assert!(offline_replay_became_eligible(true, -1, true, 0));
    assert!(offline_replay_became_eligible(false, 0, true, 0));
    assert!(!offline_replay_became_eligible(true, 0, true, 5));
    assert!(!offline_replay_became_eligible(true, -1, false, 0));
}

#[test]
fn directed_presence_admission_matches_the_resume_snapshot_bound() {
    assert!(!directed_presence_capacity_reached(1_023, false));
    assert!(directed_presence_capacity_reached(1_024, false));
    assert!(!directed_presence_capacity_reached(1_024, true));
}

#[test]
fn roster_broadcast_scope_removes_bare_and_full_directed_targets() {
    assert!(!directed_presence_target_is_outside_bare_scope(
        "Alice@BÜCHER.example/Phone",
        "alice@bücher.example",
    ));
    assert!(directed_presence_target_is_outside_bare_scope(
        "bob@example.test/Phone",
        "alice@example.test",
    ));
    assert!(!directed_presence_target_is_outside_bare_scope(
        "not a jid",
        "alice@example.test",
    ));
}

#[test]
fn automatic_contact_probes_are_initial_presence_only() {
    assert!(should_probe_contact_on_presence(true, "to"));
    assert!(should_probe_contact_on_presence(true, "both"));
    assert!(!should_probe_contact_on_presence(false, "both"));
    assert!(!should_probe_contact_on_presence(true, "from"));
}

#[test]
fn pending_outbound_subscriptions_are_recovered_on_initial_presence_only() {
    assert!(should_resend_pending_outbound_subscription(
        true,
        Some("subscribe")
    ));
    assert!(!should_resend_pending_outbound_subscription(
        false,
        Some("subscribe")
    ));
    assert!(!should_resend_pending_outbound_subscription(true, None));
}

#[test]
fn directed_presence_authorization_is_bare_or_exact_resource_scoped() {
    assert!(directed_recipient_matches(
        "Alice@BÜCHER.example",
        "alice@bücher.example/Phone"
    ));
    assert!(directed_recipient_matches(
        "alice@example.test/Phone",
        "alice@example.test/Phone"
    ));
    assert!(!directed_recipient_matches(
        "alice@example.test/Phone",
        "alice@example.test/phone"
    ));
    assert!(!directed_recipient_matches(
        "alice@example.test/Phone",
        "alice@example.test/Tablet"
    ));
}

#[test]
fn subscription_stamping_uses_bare_jids_and_preserves_extensions() {
    let stamped = stamped_subscription_presence(
        "<presence to='bob@example.test/Tablet' type='subscribe'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>",
        "alice@example.test",
        "bob@example.test",
    );
    assert!(stamped.contains("from='alice@example.test'"));
    assert!(stamped.contains("to='bob@example.test'"));
    assert!(!stamped.contains("Tablet"));
    assert!(stamped.contains("<nick xmlns='http://jabber.org/protocol/nick'>Alice</nick>"));
}

#[test]
fn unauthorized_probe_response_does_not_expose_a_resource() {
    assert_eq!(
        unsubscribed_probe_response(
            "missing@example.test",
            "alice@example.test/Phone",
            Some("probe-1"),
        ),
        "<presence xmlns='jabber:client' from='missing@example.test' to='alice@example.test/Phone' type='unsubscribed' id='probe-1'/>"
    );
}

#[test]
fn full_jid_probe_response_exposes_only_availability() {
    let response = full_jid_probe_available_response(
        "romeo@example.test/Phone",
        "alice@example.test/Tablet",
        Some("presence-1"),
    );
    assert_eq!(
        response,
        "<presence xmlns='jabber:client' from='romeo@example.test/Phone' to='alice@example.test/Tablet' id='presence-1'/>"
    );
    assert!(!response.contains("<show>"));
    assert!(!response.contains("<status>"));
    assert!(!response.contains("<priority>"));
}
