use super::{canonical_local_muc_room, local_muc_room_jid};
use northstar_room_core::stanza::valid_muc_room;
use northstar_xmpp_types::{prepare_domainpart, CanonicalJid};

fn previous_local_muc_room(value: &str, expected_domain: &str) -> Option<(String, String)> {
    let room = CanonicalJid::parse_bare(value).ok()?;
    let expected_domain = prepare_domainpart(expected_domain).ok()?;
    let localpart = room.localpart()?;
    if room.domainpart() != expected_domain || !valid_muc_room(localpart) {
        return None;
    }
    Some((room.to_string(), localpart.to_owned()))
}

#[test]
fn local_room_jid_preserves_bare_address_validation_and_projection() {
    let service = "conference.example.test";
    let maximum_name = format!("{}@{service}", "a".repeat(255));
    let oversized_name = format!("{}@{service}", "a".repeat(256));
    for (value, expected_domain, accepted) in [
        ("Lobby@CONFERENCE.Example.Test", service, true),
        (
            "lobby@conference.example.test.",
            "CONFERENCE.EXAMPLE.TEST",
            true,
        ),
        (
            "lobby@conference.bücher.test",
            "conference.xn--bcher-kva.test",
            true,
        ),
        (
            "lobby@conference.xn--bcher-kva.test",
            "conference.bücher.test",
            true,
        ),
        (&maximum_name, service, true),
        (&oversized_name, service, false),
        ("bad name@conference.example.test", service, false),
        ("bad&name@conference.example.test", service, false),
        ("lobby@conference.example.test/Alice", service, false),
        ("lobby@conference.example.test/", service, false),
        ("@conference.example.test", service, false),
        (service, service, false),
        ("", service, false),
        ("lobby@conference.foreign.test", service, false),
        ("lobby@conference.example.test", "", false),
    ] {
        let previous = previous_local_muc_room(value, expected_domain);
        assert_eq!(
            previous.is_some(),
            accepted,
            "{value:?} at {expected_domain:?}"
        );
        let room = local_muc_room_jid(value, expected_domain);
        let projected = room.map(|room| {
            assert_eq!(room.as_str(), room.to_string());
            (room.to_string(), room.room_name().to_string())
        });
        assert_eq!(projected, previous, "{value:?} at {expected_domain:?}");
        assert_eq!(canonical_local_muc_room(value, expected_domain), previous);
    }
}
