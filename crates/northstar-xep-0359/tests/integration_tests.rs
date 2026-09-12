#![forbid(unsafe_code)]

use northstar_xep_0359::{
    authoritative_deduplication_key, build_origin_id, build_referenced_stanza, build_stanza_id,
    origin_deduplication_key, parse_message, plan_authority_update, stanza_id_trust, validate_id,
    DeduplicationKey, ReferenceTrust, SidError, DESCRIPTOR, MAX_ID_BYTES, MAX_ID_ELEMENTS,
    NAMESPACE, XEP_ID,
};
use northstar_xep_core::{StanzaKind, XepId};
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Document;

fn parsed(xml: &str) -> Result<northstar_xep_0359::MessageIds<'static>, SidError> {
    let xml = Box::leak(xml.to_owned().into_boxed_str());
    let document = Box::leak(Box::new(Document::parse(xml).expect("valid fixture XML")));
    parse_message(document.root_element())
}

#[test]
fn parses_complete_direct_child_set() {
    let ids = parsed(
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='client-1'/><stanza-id xmlns='urn:xmpp:sid:0' id='account-1' by='Alice@Example.test'/><referenced-stanza xmlns='urn:xmpp:sid:0' id='room-1' by='room@conference.example.test'/></message>",
    )
    .unwrap();
    assert_eq!(ids.origin.unwrap().id.as_str(), "client-1");
    assert_eq!(ids.stanza_ids[0].id.as_str(), "account-1");
    assert_eq!(ids.stanza_ids[0].by.to_string(), "alice@example.test");
    assert_eq!(ids.references[0].id.as_str(), "room-1");
    assert_eq!(
        ids.references[0].by.as_ref().unwrap().to_string(),
        "room@conference.example.test"
    );
}

#[test]
fn referenced_stanza_allows_missing_by() {
    let ids = parsed("<message><referenced-stanza xmlns='urn:xmpp:sid:0' id='target'/></message>")
        .unwrap();
    assert!(ids.references[0].by.is_none());
}

#[test]
fn nested_sid_elements_are_not_top_level_claims() {
    let ids = parsed(
        "<message><forwarded xmlns='urn:xmpp:forward:0'><message><origin-id xmlns='urn:xmpp:sid:0' id='nested'/></message></forwarded></message>",
    )
    .unwrap();
    assert_eq!(ids, Default::default());
}

#[test]
fn unknown_sid_children_remain_forward_compatible() {
    let ids = parsed(
        "<message><future-id xmlns='urn:xmpp:sid:0' value='opaque'/><origin-id xmlns='urn:xmpp:sid:0' id='known'/></message>",
    )
    .unwrap();
    assert_eq!(ids.unknown_sid_children, 1);
    assert_eq!(ids.origin.unwrap().id.as_str(), "known");
}

#[test]
fn rejects_duplicate_origin() {
    let error = parsed(
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='one'/><origin-id xmlns='urn:xmpp:sid:0' id='two'/></message>",
    )
    .unwrap_err();
    assert_eq!(error, SidError::DuplicateOriginId);
}

#[test]
fn rejects_duplicate_canonical_issuer() {
    let error = parsed(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='two' by='alice@example.test'/></message>",
    )
    .unwrap_err();
    assert_eq!(
        error,
        SidError::DuplicateIssuer("alice@example.test".into())
    );
}

#[test]
fn resourcepart_case_remains_distinct() {
    let ids = parsed(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' id='upper' by='alice@example.test/Phone'/><stanza-id xmlns='urn:xmpp:sid:0' id='lower' by='alice@example.test/phone'/></message>",
    )
    .unwrap();
    assert_eq!(ids.stanza_ids.len(), 2);
}

#[test]
fn rejects_missing_attributes_and_invalid_issuer() {
    assert_eq!(
        parsed("<message><origin-id xmlns='urn:xmpp:sid:0'/></message>").unwrap_err(),
        SidError::MissingId
    );
    assert_eq!(
        parsed("<message><stanza-id xmlns='urn:xmpp:sid:0' id='one'/></message>").unwrap_err(),
        SidError::MissingBy
    );
    assert!(matches!(
        parsed("<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='bad jid'/></message>")
            .unwrap_err(),
        SidError::InvalidIssuer(_)
    ));
}

#[test]
fn rejects_origin_by_and_unexpected_attributes() {
    assert_eq!(
        parsed("<message><origin-id xmlns='urn:xmpp:sid:0' id='one' by='alice@example.test'/></message>")
            .unwrap_err(),
        SidError::OriginHasBy
    );
    assert_eq!(
        parsed("<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='alice@example.test' extra='x'/></message>")
            .unwrap_err(),
        SidError::UnexpectedAttribute
    );
}

#[test]
fn rejects_child_or_text_content() {
    for xml in [
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='one'>text</origin-id></message>",
        "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='alice@example.test'><x/></stanza-id></message>",
    ] {
        assert_eq!(parsed(xml).unwrap_err(), SidError::ElementHasContent);
    }
}

#[test]
fn validates_identifier_bounds_and_controls() {
    assert_eq!(validate_id("id").unwrap().as_str(), "id");
    assert!(validate_id("").is_err());
    assert!(validate_id("bad\nvalue").is_err());
    assert!(validate_id(&"x".repeat(MAX_ID_BYTES)).is_ok());
    assert!(validate_id(&"x".repeat(MAX_ID_BYTES + 1)).is_err());
}

#[test]
fn enforces_direct_element_count_bound() {
    let children = (0..=MAX_ID_ELEMENTS)
        .map(|index| format!("<referenced-stanza xmlns='urn:xmpp:sid:0' id='{index}'/>"))
        .collect::<String>();
    let error = parsed(&format!("<message>{children}</message>")).unwrap_err();
    assert_eq!(
        error,
        SidError::TooManyElements {
            limit: MAX_ID_ELEMENTS
        }
    );
}

#[test]
fn rejects_non_message_roots() {
    let document = Document::parse("<presence/>").unwrap();
    assert_eq!(
        parse_message(document.root_element()).unwrap_err(),
        SidError::NotMessage
    );
}

#[test]
fn builders_escape_and_round_trip() {
    let by = CanonicalJid::parse("Alice@Example.test").unwrap();
    let origin = build_origin_id("a&<'\"").unwrap();
    let stanza = build_stanza_id("server&1", &by).unwrap();
    let reference = build_referenced_stanza("target&1", Some(&by)).unwrap();
    let ids = parsed(&format!("<message>{origin}{stanza}{reference}</message>")).unwrap();
    assert_eq!(ids.origin.unwrap().id.as_str(), "a&<'\"");
    assert_eq!(ids.stanza_ids[0].id.as_str(), "server&1");
    assert_eq!(ids.stanza_ids[0].by.to_string(), "alice@example.test");
    assert_eq!(ids.references[0].id.as_str(), "target&1");
}

#[test]
fn authority_plan_removes_only_own_claims_and_preserves_origin() {
    let ids = parsed(
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='client'/><stanza-id xmlns='urn:xmpp:sid:0' id='forged' by='alice@example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote' by='remote.test'/></message>",
    )
    .unwrap();
    let authority = CanonicalJid::parse("Alice@Example.test").unwrap();
    let replacement = validate_id("authoritative").unwrap();
    let plan = plan_authority_update(&ids, authority.clone(), Some(replacement));
    assert_eq!(plan.assigning_entity, authority);
    assert_eq!(plan.remove_matching, 1);
    assert_eq!(plan.foreign_ids_preserved, 1);
    assert_eq!(plan.replacement.unwrap().as_str(), "authoritative");
    assert!(plan.preserve_origin);
}

#[test]
fn authority_plan_supports_required_delete_without_replacement() {
    let ids = parsed(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' id='forged' by='alice@example.test'/></message>",
    )
    .unwrap();
    let plan = plan_authority_update(
        &ids,
        CanonicalJid::parse("alice@example.test").unwrap(),
        None,
    );
    assert_eq!(plan.remove_matching, 1);
    assert!(plan.replacement.is_none());
}

#[test]
fn deduplication_keys_keep_origin_sender_scope_and_authority() {
    let sender = CanonicalJid::parse("alice@example.test").unwrap();
    let by = CanonicalJid::parse("room@conference.example.test").unwrap();
    let id = validate_id("same-text").unwrap();
    let origin = origin_deduplication_key(sender.clone(), id);
    let authoritative = authoritative_deduplication_key(by.clone(), id);
    assert_eq!(
        origin,
        DeduplicationKey::Origin {
            sender_scope: sender,
            id
        }
    );
    assert_eq!(authoritative, DeduplicationKey::Authoritative { by, id });
    assert_ne!(origin, authoritative);
}

#[test]
fn trust_requires_verified_assigning_entity_support() {
    assert_eq!(
        stanza_id_trust(false),
        ReferenceTrust::UnverifiedAssigningEntity
    );
    assert_eq!(
        stanza_id_trust(true),
        ReferenceTrust::VerifiedAssigningEntity
    );
    assert_ne!(
        ReferenceTrust::SpoofableOrigin,
        ReferenceTrust::VerifiedAssigningEntity
    );
}

#[test]
fn descriptor_matches_extension_contract() {
    assert_eq!(DESCRIPTOR.id, XEP_ID);
    assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
    assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
    assert_eq!(DESCRIPTOR.routes.len(), 3);
    assert!(DESCRIPTOR
        .routes
        .iter()
        .all(|route| route.stanza == StanzaKind::Message && route.namespace == NAMESPACE));
}
