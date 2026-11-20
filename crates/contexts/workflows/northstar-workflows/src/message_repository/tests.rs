use super::*;
use northstar_message_postgres::personal_history::PersonalHistoryAdmission;

#[test]
fn durable_results_do_not_expose_repository_row_ids() {
    assert_eq!(
        map_history_outcome(
            PersonalHistoryAdmission::Stored(vec![Uuid::new_v4()]),
            MessagePostCommit::WakeFederationOutbox,
        ),
        DurableAdmissionOutcome::Stored {
            archive_written: true,
            post_commit: MessagePostCommit::WakeFederationOutbox,
        }
    );
    assert_eq!(
        map_history_outcome(
            PersonalHistoryAdmission::Replay(vec![]),
            MessagePostCommit::WakeFederationOutbox,
        ),
        DurableAdmissionOutcome::Replay
    );
}

#[test]
fn stored_delivery_can_have_no_written_archives() {
    let post_commit = MessagePostCommit::RouteLocalDelivery {
        delivery_id: Uuid::from_u128(1),
        recipient_id: Uuid::from_u128(2),
    };
    assert_eq!(
        map_history_outcome(PersonalHistoryAdmission::Stored(Vec::new()), post_commit),
        DurableAdmissionOutcome::Stored {
            archive_written: false,
            post_commit,
        }
    );
}

#[test]
fn only_explicit_full_normal_messages_receive_resource_affinity() {
    assert_eq!(
        durable_target_full_jid(
            "<message to='alice@example.test/Phone'><body>normal</body></message>"
        )
        .unwrap()
        .as_deref(),
        Some("alice@example.test/Phone")
    );
    for stanza in [
        "<message to='alice@example.test'><body>bare</body></message>",
        "<message type='chat' to='alice@example.test/Phone'><body>fallback</body></message>",
        "<message><body>implicit self</body></message>",
    ] {
        assert_eq!(durable_target_full_jid(stanza).unwrap(), None);
    }
}

#[test]
fn durable_recipient_authority_is_canonical_and_local() {
    assert!(
        validate_local_recipient_authority_for_domain("alice@example.test", "example.test").is_ok()
    );
    assert!(
        validate_local_recipient_authority_for_domain("alice@evil.test", "example.test").is_err()
    );
    assert!(
        validate_local_recipient_authority_for_domain("Alice@example.test", "example.test")
            .is_err()
    );
}
