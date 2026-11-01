//! The rules that need no database.

use super::*;

#[test]
fn durable_message_retries_keep_one_authoritative_identity() {
    let outbox_id = Uuid::from_u128(0x1234);
    let input = "<message from='Alice@Example.COM/Phone' to='bob@remote.test'><stanza-id xmlns='urn:xmpp:sid:0' by='alice@example.com' id='forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='mallory@example.com' id='same-domain-forged'/><stanza-id xmlns='urn:xmpp:sid:0' by='remote.test' id='peer-id'/><body>hello</body></message>";

    let first = durable_federation_stanza(input, outbox_id).unwrap();
    let retry = durable_federation_stanza(input, outbox_id).unwrap();
    assert_eq!(first, retry, "the same outbox row must retry identically");

    let document = roxmltree::Document::parse(&first).unwrap();
    let ids = document
        .root_element()
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:xmpp:sid:0")
                && child.tag_name().name() == "stanza-id"
        })
        .map(|child| {
            (
                child.attribute("by").unwrap().to_owned(),
                child.attribute("id").unwrap().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&("remote.test".to_owned(), "peer-id".to_owned())));
    assert!(ids.contains(&("alice@example.com".to_owned(), outbox_id.to_string())));
    assert!(!first.contains("forged"));
    assert!(!first.contains("same-domain-forged"));
}

#[test]
fn non_message_outbox_stanzas_are_not_rewritten() {
    let iq = "<iq from='alice@example.com' to='remote.test' type='get' id='one'/>";
    assert_eq!(
        durable_federation_stanza(iq, Uuid::from_u128(7)).unwrap(),
        iq
    );
}

#[test]
fn durable_messages_require_an_identity_authority() {
    let error = durable_federation_stanza("<message><body>hello</body></message>", Uuid::nil())
        .unwrap_err();
    assert!(error.to_string().contains("missing its from address"));
}

#[test]
fn retry_delay_is_bounded_exponential_with_jitter() {
    let id = Uuid::from_u128(0x1234);
    let one = retry_delay_seconds(1, 5, 3600, id);
    let two = retry_delay_seconds(2, 5, 3600, id);
    let ten = retry_delay_seconds(20, 5, 3600, id);
    assert!((5..=6).contains(&one));
    assert!((10..=12).contains(&two));
    assert!(two > one);
    assert_eq!(ten, 3600);
}

#[test]
fn utf8_error_truncation_does_not_split_a_character() {
    let error = "x".repeat(2047) + "界";
    let truncated = truncate_utf8(&error, 2048);
    assert_eq!(truncated.len(), 2047);
    assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
}
