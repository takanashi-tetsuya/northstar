use super::*;
use crate::muc::message::addressed::{send_addressed, AddressedDeliveryKind};
use northstar_room_core::occupancy::MucOccupantRoute;

fn bob_route() -> MucOccupantRoute {
    MucOccupantRoute {
        nick: "Bob".into(),
        full_jid: "bob@local.test/phone".into(),
        connection_id: CONNECTION_ID,
        cluster_epoch: OCCUPANT_EPOCH,
    }
}

#[test]
fn private_stanza_delivers_only_to_an_exact_local_recipient() {
    let session = Session::new(Admission::Stored, false);
    let route = bob_route();
    for candidate in [
        route.clone(),
        MucOccupantRoute {
            cluster_epoch: Uuid::from_u128(99),
            ..route.clone()
        },
        MucOccupantRoute {
            nick: "Missing".into(),
            ..route
        },
    ] {
        ready(send_addressed(
            &session.host,
            ROOM_JID,
            &candidate,
            "<message/>".into(),
            SENDER,
            AddressedDeliveryKind::Private {
                sender_nick: "Alice",
            },
            false,
        ))
        .unwrap();
    }
    let events = session.host.state.events();
    assert!(
        matches!(&events[..], [Event::Privacy, Event::Deliver(to, xml),
        Event::PrivateRoute(stale, false), Event::PrivateRoute(missing, false)]
        if to == "bob@local.test/phone" && xml == "<message/>"
            && stale.cluster_epoch == Uuid::from_u128(99) && missing.nick == "Missing")
    );
}

#[test]
fn decline_uses_the_room_for_local_blocking_without_an_occupant_sender() {
    let session = Session::new(Admission::Stored, false);
    let probe = "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline/></x></message>";
    ready(send_addressed(
        &session.host,
        ROOM_JID,
        &bob_route(),
        probe.into(),
        "invitee@local.test/Phone",
        AddressedDeliveryKind::Decline,
        false,
    ))
    .unwrap();
    assert!(
        matches!(&session.host.state.events()[..], [Event::Privacy, Event::Deliver(to, xml)]
        if to == "bob@local.test/phone" && xml == probe)
    );
}

#[test]
fn voice_form_keeps_the_real_requester_and_only_addresses_moderator_routes() {
    let session = Session::new(Admission::Stored, false);
    let requester = MucOccupantRoute {
        full_jid: SENDER.into(),
        nick: "Alice".into(),
        ..bob_route()
    };
    let remote = MucOccupantRoute {
        full_jid: REMOTE_SENDER.into(),
        nick: "Remote".into(),
        ..bob_route()
    };
    ready(crate::muc::message::voice_routes::deliver_voice_request(
        &session.host,
        ROOM_JID,
        &requester,
        vec![bob_route(), remote.clone()],
        false,
    ));
    let events = session.host.state.events();
    let [Event::PrivateRoute(published, true), Event::Privacy, Event::Deliver(to, xml)] =
        &events[..]
    else {
        panic!("unexpected voice routes: {events:?}");
    };
    assert_eq!(published, &remote);
    assert_eq!(to, "bob@local.test/phone");
    let document = roxmltree::Document::parse(xml).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("from"), Some(ROOM_JID));
    assert_eq!(root.attribute("to"), Some(to.as_str()));
    for (name, value) in [
        ("muc#jid", SENDER),
        ("muc#roomnick", "Alice"),
        ("muc#request_allow", "false"),
    ] {
        let field = root
            .descendants()
            .find(|node| node.attribute("var") == Some(name))
            .unwrap();
        assert_eq!(
            field.first_element_child().and_then(|node| node.text()),
            Some(value)
        );
    }
}
