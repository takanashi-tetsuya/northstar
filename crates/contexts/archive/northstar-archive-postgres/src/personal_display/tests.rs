use super::*;
use northstar_time::DateTime;

const CHANNEL: &str = "room@mix.remote.test";
const TARGET: Uuid = Uuid::from_u128(1);
const ACTION: Uuid = Uuid::from_u128(2);

fn source() -> (&'static str, Uuid, MixSourceRetraction) {
    (
        CHANNEL,
        TARGET,
        MixSourceRetraction {
            action_stanza_id: ACTION,
            retracted_at: DateTime::from_timestamp(0, 999_000_000).unwrap(),
        },
    )
}

#[test]
fn mix_source_display_uses_personal_tombstone_and_authoritative_ids() {
    let raw = format!("<message xmlns='jabber:client' from='{CHANNEL}/publisher' to='alice@local.test' type='groupchat' id='{TARGET}'><body>secret</body><encrypted xmlns='urn:xmpp:omemo:2'/><mix xmlns='urn:xmpp:mix:core:1'><nick>Publisher</nick></mix><stanza-id xmlns='urn:xmpp:sid:0' id='untrusted' by='other.test'/></message>");
    assert_eq!(
        resolve_personal_display(&raw, true, None, None),
        (raw.clone(), true)
    );
    let display = resolve_personal_display(&raw, true, Some(source()), None);
    let expected = format!("<message xmlns='jabber:client' from='{CHANNEL}/publisher' to='alice@local.test' type='groupchat' id='{TARGET}'><stanza-id xmlns='urn:xmpp:sid:0' id='{TARGET}' by='{CHANNEL}'/><retracted xmlns='urn:xmpp:message-retract:1' stamp='1970-01-01T00:00:00Z' id='{ACTION}'/></message>");
    assert_eq!(display, (expected, false));
    assert_eq!(
        resolve_personal_display(&display.0, false, Some(source()), None),
        display
    );
}

#[test]
fn mix_source_display_fails_closed_on_invalid_envelopes() {
    let expected = format!("<message xmlns='jabber:client' from='{CHANNEL}' type='groupchat' id='{TARGET}'><stanza-id xmlns='urn:xmpp:sid:0' id='{TARGET}' by='{CHANNEL}'/><retracted xmlns='urn:xmpp:message-retract:1' stamp='1970-01-01T00:00:00Z' id='{ACTION}'/></message>");
    for raw in [
        "<message><body>malformed".to_owned(),
        format!("<message from='other@mix.remote.test/actor' type='groupchat' id='{TARGET}'><body>secret</body></message>"),
        format!("<message from='{CHANNEL}/actor' type='groupchat' id='{ACTION}'><body>secret</body></message>"),
        format!("<message from='{CHANNEL}/actor' to='bad jid' type='groupchat' id='{TARGET}'><body>secret</body></message>"),
    ] {
        assert_eq!(
            resolve_personal_display(&raw, true, Some(source()), None),
            (expected.clone(), false)
        );
    }
}

#[test]
fn source_display_precedes_row_display_without_touching_raw_evidence() {
    let raw = "<message><encrypted xmlns='urn:xmpp:omemo:2'/></message>";
    let overlay = "<message><retracted xmlns='urn:xmpp:message-retract:1' id='local'/></message>";
    assert_eq!(
        resolve_personal_display(raw, true, Some(source()), Some(overlay)),
        resolve_personal_display(raw, true, Some(source()), None)
    );
    assert_eq!(
        resolve_personal_display(raw, true, None, Some(overlay)),
        (overlay.to_owned(), false)
    );
    assert_eq!(
        resolve_personal_display(raw, true, None, None),
        (raw.to_owned(), true)
    );
}
