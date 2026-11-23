use super::*;
use northstar_stream::transport::Action;

#[test]
fn direct_invitation_outcomes_preserve_delivery_and_stanza_errors() {
    let claim = Some(Uuid::from_u128(1));
    assert!(matches!(
        grant_delivery(
            DirectInvitationOutcome::Open { recipient: None },
            None,
            false
        ),
        Ok(GrantDelivery::Open)
    ));
    assert!(matches!(
        grant_delivery(DirectInvitationOutcome::Granted { live_claim_id: claim }, None, true),
        Ok(GrantDelivery::Granted { live_claim_id, wake_operation: true }) if live_claim_id == claim
    ));
    assert!(matches!(
        grant_delivery(DirectInvitationOutcome::Replay, None, false),
        Ok(GrantDelivery::Replay)
    ));
    let request =
        roxmltree::Document::parse("<message id='invite' to='target@local.test'/>").unwrap();
    for (refusal, kind, condition) in [
        (
            DirectInvitationRefusal::SenderBlocked,
            "cancel",
            "not-acceptable",
        ),
        (
            DirectInvitationRefusal::Unavailable,
            "cancel",
            "service-unavailable",
        ),
        (DirectInvitationRefusal::Forbidden, "auth", "forbidden"),
        (DirectInvitationRefusal::Stale, "cancel", "item-not-found"),
        (DirectInvitationRefusal::Conflict, "cancel", "conflict"),
        (
            DirectInvitationRefusal::Capacity,
            "wait",
            "resource-constraint",
        ),
    ] {
        let Err(mapped) = grant_delivery(DirectInvitationOutcome::Refused(refusal), None, false)
        else {
            panic!("a refused invitation returned a delivery intent");
        };
        let Action::Send(stanza) = refused(request.root_element(), mapped) else {
            panic!("a refused invitation did not produce a stanza error");
        };
        let reply = roxmltree::Document::parse(&stanza).unwrap();
        let error = reply
            .root_element()
            .children()
            .find(|node| node.has_tag_name("error"))
            .unwrap();
        assert_eq!(error.attribute("type"), Some(kind));
        assert!(error
            .children()
            .any(|node| node.has_tag_name(("urn:ietf:params:xml:ns:xmpp-stanzas", condition))));
        if refusal == DirectInvitationRefusal::SenderBlocked {
            assert!(error
                .children()
                .any(|node| node.has_tag_name(("urn:xmpp:blocking:errors", "blocked"))));
        }
    }
}
