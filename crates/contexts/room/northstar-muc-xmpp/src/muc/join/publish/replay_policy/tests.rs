use super::*;

#[test]
fn denied_peer_items_leave_the_self_presence_and_subject_in_order() {
    let mut replay = ReplayPolicy::default();
    replay.history(
        "room@conference.example.test",
        "<message><body>denied</body></message>",
        "private@example.test/Phone",
        "<message><body>denied</body></message>".into(),
    );
    let replies = render_replay(
        replay
            .items
            .into_iter()
            .zip([RoomDeliveryDecision::PrivacyDenies]),
        "<presence id='self'/>".into(),
        MucHistoryRequest::default(),
        "<message><subject/></message>".into(),
    );
    assert_eq!(
        replies,
        ["<presence id='self'/>", "<message><subject/></message>"]
    );
}

#[test]
fn anonymous_history_keeps_the_private_block_candidate_out_of_the_wire_stanza() {
    let stanza = "<message from='room@conference.example.test/Nick'><body>Hello</body></message>";
    let mut replay = ReplayPolicy::default();
    replay.history(
        "room@conference.example.test",
        stanza,
        "private@example.test/Phone",
        stanza.into(),
    );
    assert_eq!(
        replay.items[0].visible_peer,
        "room@conference.example.test/Nick"
    );
    assert_eq!(replay.items[0].real_peer, "private@example.test/Phone");
    let replies = render_replay(
        replay.items.into_iter().zip([RoomDeliveryDecision::Allow]),
        "<presence/>".into(),
        MucHistoryRequest::default(),
        "<message><subject/></message>".into(),
    );
    assert_eq!(replies[1], stanza);
}
