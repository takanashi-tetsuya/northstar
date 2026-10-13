use super::*;
use roxmltree::Document;
use std::time::Duration;

#[test]
fn binding_failures_preserve_internal_cause_and_use_valid_wire_conditions() {
    assert_eq!(
        ResourceBindingFailure::CredentialsExpired.iq_condition(),
        "not-authorized"
    );
    assert_eq!(
        ResourceBindingFailure::CredentialsExpired.sasl_condition(),
        "credentials-expired"
    );
    assert_eq!(
        ResourceBindingFailure::CapacityExhausted.iq_condition(),
        "resource-constraint"
    );
    assert_eq!(
        ResourceBindingFailure::CapacityExhausted.sasl_condition(),
        "temporary-auth-failure"
    );
    assert_ne!(
        ResourceBindingFailure::Conflict,
        ResourceBindingFailure::CommittedRouteLost
    );
}

#[test]
fn test_legacy_register() {
    let xml = "<query xmlns='jabber:iq:register'><username>user1</username><password>pass1</password></query>";
    let doc = Document::parse(xml).unwrap();
    let res = parse_legacy_register(doc.root_element());
    assert_eq!(res, Ok(("user1".to_string(), "pass1".to_string())));

    let xml = "<query xmlns='jabber:iq:register'><username>user1</username><username>user2</username><password>pass1</password></query>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_legacy_register(doc.root_element()).is_err());

    let xml = "<query xmlns='jabber:iq:register'><username>user1</username><password>pass1</password><bad xmlns='other'/></query>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_legacy_register(doc.root_element()).is_err());

    let xml = "<query xmlns='jabber:iq:register'><username><value>user1</value></username><password>pass1</password></query>";
    let doc = Document::parse(xml).unwrap();
    assert!(parse_legacy_register(doc.root_element()).is_err());
}

#[test]
fn password_change_is_unambiguous() {
    let doc = Document::parse(
        "<query xmlns='jabber:iq:register'><username>alice</username><password>correct-horse</password></query>",
    )
    .unwrap();
    let (username, password, proof) = parse_password_change(doc.root_element(), "alice").unwrap();
    assert_eq!(username, "alice");
    assert_eq!(password, "correct-horse");
    assert!(proof.is_none());
    let doc = Document::parse(
        "<query xmlns='jabber:iq:register'><password>one</password><password>two</password></query>",
    )
    .unwrap();
    assert!(parse_password_change(doc.root_element(), "alice").is_err());
}

#[test]
fn account_removal_accepts_one_strict_bound_proof() {
    let doc = Document::parse(
        "<query xmlns='jabber:iq:register'><remove/><pow xmlns='urn:northstar:pow:1' challenge='018f25df-7fd1-7a36-8cef-112233445566' nonce='42'/></query>",
    )
    .unwrap();
    let proof = parse_account_remove(doc.root_element()).unwrap().unwrap();
    assert_eq!(proof.nonce, "42");

    let duplicate =
        Document::parse("<query xmlns='jabber:iq:register'><remove/><remove/></query>").unwrap();
    assert!(parse_account_remove(duplicate.root_element()).is_err());
}

#[test]
fn xep_0077_errors_include_legacy_and_modern_conditions() {
    for (condition, code) in [
        ("bad-request", "400"),
        ("not-authorized", "401"),
        ("not-acceptable", "406"),
        ("registration-required", "407"),
        ("conflict", "409"),
        ("service-unavailable", "503"),
    ] {
        let xml = iq_registration_error("reg1", condition);
        let document = Document::parse(&xml).unwrap();
        let error = document
            .root_element()
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == "error")
            .unwrap();
        assert_eq!(error.attribute("code"), Some(code));
        assert!(error.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == condition
                && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
        }));
    }
}

#[tokio::test]
async fn metered_registration_error_carries_a_parseable_bound_v2_challenge() {
    let guard = crate::abuse::AbuseGuard::new(crate::abuse::AbuseConfig {
        base_work_factor: 2,
        max_work_factor: 256,
        window: Duration::from_secs(300),
        cooldown_step: Duration::from_secs(30),
        max_wait: Duration::from_secs(8),
        message_free_burst: 5,
        approximate_max_device_seconds: 8,
    });
    let intent = PowIntent::xmpp_registration(
        "alice",
        "correct horse battery staple",
        Some("invite-token"),
    );
    let actors = vec!["ip:192.0.2.10".to_owned()];
    let challenge = guard
        .issue_v2(
            AbuseAction::Registration,
            "registration:192.0.2.10",
            &actors,
            &intent,
        )
        .await
        .unwrap();
    let xml = iq_registration_abuse_error(
        "registration-metered",
        &challenge.requirement,
        Some(&challenge),
    );
    let document = Document::parse(&xml).unwrap();
    let pow = document
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "pow-required"
                && node.tag_name().namespace() == Some("urn:northstar:pow:2")
        })
        .expect("v2 challenge element");
    assert_eq!(pow.attribute("version"), Some("2"));
    let challenge_id = challenge.challenge_id.to_string();
    assert_eq!(pow.attribute("challenge"), Some(challenge_id.as_str()));
    assert_eq!(pow.attribute("intent-method"), Some("XMPP"));
    assert_eq!(pow.attribute("intent-path"), Some("/xmpp/register"));
    assert!(pow
        .attribute("intent-body-sha256")
        .is_some_and(|digest| !digest.is_empty()));
    let ordinary = iq_registration_abuse_error("standard-client", &challenge.requirement, None);
    let document = Document::parse(&ordinary).unwrap();
    let error = document.root_element().first_element_child().unwrap();
    assert_eq!(error.attribute("type"), Some("wait"));
    let children = error
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0].tag_name().name(), "resource-constraint");
    assert_eq!(children[1].tag_name().name(), "text");
    assert!(children
        .iter()
        .all(|node| node.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")));
    assert!(children[1].text().unwrap().contains("300 seconds"));
}
