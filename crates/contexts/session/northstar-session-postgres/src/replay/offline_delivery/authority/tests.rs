use super::*;

#[test]
fn unlinked_replay_requires_the_exact_recipient_stanza_id() {
    let recipient = "recipient@example.test";
    let id = Uuid::from_u128(20);
    let other = Uuid::from_u128(21);
    let recipient_sid = format!("<stanza-id xmlns='urn:xmpp:sid:0' by='{recipient}' id='{id}'/>");
    let foreign_sid =
        format!("<stanza-id xmlns='urn:xmpp:sid:0' by='sender@example.test' id='{id}'/>");
    for (children, expected_id, proven) in [
        (recipient_sid.clone(), id, true),
        (recipient_sid.clone(), other, false),
        (foreign_sid, id, false),
        (format!("{recipient_sid}{recipient_sid}"), id, false),
        (String::new(), id, false),
    ] {
        assert_eq!(
            wire_matches_projection(
                &format!("<message>{children}</message>"),
                recipient,
                expected_id
            ),
            proven
        );
    }
}
