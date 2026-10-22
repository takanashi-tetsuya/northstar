//! Capability-free RFC 6121 presence-session and directed-visibility policy.

#![forbid(unsafe_code)]

pub const MAX_DIRECTED_PRESENCE_RECIPIENTS: usize = 1_024;

pub fn should_resend_pending_subscription(first_available: bool, ask: Option<&str>) -> bool {
    first_available && ask == Some("subscribe")
}

pub fn directed_recipient_matches(authorized: &str, requester: &str) -> bool {
    let (Ok(authorized), Ok(requester)) = (
        northstar_xmpp_types::CanonicalJid::parse(authorized),
        northstar_xmpp_types::CanonicalJid::parse(requester),
    ) else {
        return false;
    };
    if authorized.resourcepart().is_some() {
        authorized == requester
    } else {
        authorized.bare() == requester.bare()
    }
}

pub const fn offline_replay_became_eligible(
    was_available: bool,
    previous_priority: i16,
    now_available: bool,
    priority: i16,
) -> bool {
    now_available && priority >= 0 && (!was_available || previous_priority < 0)
}

pub fn should_probe_contact_on_presence(first_available: bool, subscription: &str) -> bool {
    first_available && matches!(subscription, "to" | "both")
}

pub const fn directed_presence_capacity_reached(current: usize, already_present: bool) -> bool {
    !already_present && current >= MAX_DIRECTED_PRESENCE_RECIPIENTS
}

pub fn directed_presence_target_is_outside_bare_scope(target: &str, target_bare: &str) -> bool {
    let (Ok(target), Ok(target_bare)) = (
        northstar_xmpp_types::canonical_bare_key(target),
        northstar_xmpp_types::canonical_bare_key(target_bare),
    ) else {
        return false;
    };
    target != target_bare
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_replay_opens_only_on_a_new_nonnegative_available_epoch() {
        assert!(offline_replay_became_eligible(false, 0, true, 0));
        assert!(offline_replay_became_eligible(true, -1, true, 0));
        assert!(!offline_replay_became_eligible(true, 0, true, 5));
        assert!(!offline_replay_became_eligible(true, -1, false, 0));
    }

    #[test]
    fn directed_authority_is_resource_exact_or_bare_scoped() {
        assert!(directed_recipient_matches(
            "alice@example.test",
            "alice@example.test/phone"
        ));
        assert!(directed_recipient_matches(
            "alice@example.test/Phone",
            "alice@example.test/Phone"
        ));
        assert!(!directed_recipient_matches(
            "alice@example.test/Phone",
            "alice@example.test/phone"
        ));
    }

    #[test]
    fn directed_capacity_does_not_reject_an_existing_recipient() {
        assert!(directed_presence_capacity_reached(
            MAX_DIRECTED_PRESENCE_RECIPIENTS,
            false
        ));
        assert!(!directed_presence_capacity_reached(
            MAX_DIRECTED_PRESENCE_RECIPIENTS,
            true
        ));
    }

    #[test]
    fn probes_and_pending_requests_are_first_presence_only() {
        assert!(should_probe_contact_on_presence(true, "both"));
        assert!(!should_probe_contact_on_presence(false, "both"));
        assert!(should_resend_pending_subscription(true, Some("subscribe")));
        assert!(!should_resend_pending_subscription(
            false,
            Some("subscribe")
        ));
    }
}
