use super::*;

#[test]
fn only_same_account_pep_bypasses_inbound_rules() {
    let account = Uuid::new_v4();
    let connection = Uuid::new_v4();
    let recipient = || NotificationRecipient {
        full_jid: "alice@example.test/phone",
        account_id: account,
        auth_generation: 3,
        connection_id: connection,
        active_list: Some("selected"),
    };
    for (source, self_delivery) in [
        (NotificationSource::PepPublisher("alice@example.test"), true),
        (NotificationSource::PepPublisher("alice@remote.test"), false),
        (NotificationSource::Service("pubsub.example.test"), false),
    ] {
        let (query, same_account) = source.policy(recipient()).unwrap();
        assert_eq!(query.account_id, account);
        assert_eq!(query.expected_auth_generation, Some(3));
        assert_eq!(
            query.subject,
            PolicySubject::Connection {
                connection_id: connection,
                expects_active: true,
            }
        );
        assert_eq!(query.kind, PrivacyStanzaKind::Message);
        assert_eq!(query.check_owner_block, !self_delivery);
        assert!(!query.check_peer_block);
        assert_eq!(same_account, self_delivery);
    }
}

#[test]
fn recipient_without_an_active_selection_requests_the_default_fallback() {
    let connection_id = Uuid::new_v4();
    let (query, _) = NotificationSource::PepPublisher("publisher@example.test")
        .policy(NotificationRecipient {
            full_jid: "alice@example.test/desktop",
            account_id: Uuid::new_v4(),
            auth_generation: 1,
            connection_id,
            active_list: None,
        })
        .unwrap();
    assert_eq!(
        query.subject,
        PolicySubject::Connection {
            connection_id,
            expects_active: false,
        }
    );
}
