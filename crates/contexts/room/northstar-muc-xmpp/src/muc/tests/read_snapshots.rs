use super::*;

#[test]
fn self_ping_uses_named_activity_command_only_for_own_nick() {
    futures::executor::block_on(async {
        let mut session = Session::new(Admission::Stored, false);
        session.host.clustered = true;
        assert!(refresh_muc_occupant_activity(&session, ROOM_JID, "Alice")
            .await
            .unwrap());
        assert!(!refresh_muc_occupant_activity(&session, ROOM_JID, "Other")
            .await
            .unwrap());
        assert_eq!(
            session.host.state.events(),
            [
                Event::Principal,
                Event::Validate,
                Event::Renew,
                Event::Principal,
                Event::Validate
            ]
        );
    });
}

#[test]
fn expired_owner_get_returns_item_not_found_without_a_command() {
    let xml = format!("<iq type='get' to='{ROOM_JID}' id='expired'><query xmlns='http://jabber.org/protocol/muc#owner'/></iq>");
    let document = roxmltree::Document::parse(&xml).unwrap();
    let session = Session::new(Admission::Stored, false);
    let action = futures::executor::block_on(owner::muc_owner_get(
        &session,
        "expired",
        document.root_element(),
    ))
    .unwrap();
    let MucAction::Send(reply) = action else {
        panic!("expected an IQ error")
    };
    assert_eq!(reply, iq_error_from("expired", ROOM_JID, "item-not-found"));
    assert_eq!(
        session.host.state.events(),
        [Event::User, Event::Principal, Event::Room]
    );
}
