use super::*;

#[test]
fn stanza_kind_uses_the_translated_room_stanza() {
    for (name, kind) in [
        ("message", PrivacyStanzaKind::Message),
        ("presence", PrivacyStanzaKind::PresenceIn),
        ("iq", PrivacyStanzaKind::Iq),
    ] {
        let stanza = format!("<{name} from='room@conference.example.test/Nick'/>");
        let facts = stanza_policy_facts(&stanza).unwrap();
        assert_eq!(facts.visible_peer, "room@conference.example.test/Nick");
        assert_eq!(facts.kind, kind);
        assert!(facts.real_peer.is_none());
    }
}

#[test]
fn presence_item_jid_is_an_internal_block_candidate() {
    let facts = stanza_policy_facts(
        "<presence from='room@conference.example.test/Nick'>\
          <x xmlns='http://jabber.org/protocol/muc#user'><item jid='user@example.test/Phone'/></x>\
         </presence>",
    )
    .unwrap();
    assert_eq!(facts.visible_peer, "room@conference.example.test/Nick");
    assert_eq!(facts.real_peer.as_deref(), Some("user@example.test/Phone"));
}

#[test]
fn self_presence_and_room_errors_bypass_live_peer_checks() {
    assert!(stanza_policy_facts(
        "<presence from='room@conference.example.test/Nick'>\
          <x xmlns='http://jabber.org/protocol/muc#user'><status code='110'/></x>\
         </presence>",
    )
    .is_none());
    assert!(
        stanza_policy_facts("<message from='room@conference.example.test' type='error'/>",)
            .is_none()
    );
    assert!(stanza_policy_facts(
        "<presence from='room@conference.example.test/Nick' type='unavailable'>\
          <x xmlns='http://jabber.org/protocol/muc#user'><destroy/></x>\
         </presence>",
    )
    .is_none());
}
