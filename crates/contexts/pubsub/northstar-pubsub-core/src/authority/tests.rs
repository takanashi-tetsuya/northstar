use super::{PubSubAddress, PubSubBareJid, PubSubNodeId, PubSubNodeName};
use northstar_xmpp_types::jid::{canonical_bare_key, canonicalize, CanonicalJid};
use uuid::Uuid;

#[test]
fn address_matches_existing_canonical_jid_forms() {
    for (input, has_resource) in [
        ("ALIce@Example.TEST", false),
        ("ALIce@Example.TEST/Phone", true),
        ("PubSub.Example.TEST", false),
    ] {
        let address = PubSubAddress::parse(input).unwrap();
        let canonical = CanonicalJid::parse(input).unwrap();
        assert_eq!(address.canonical(), &canonical);
        assert_eq!(address, PubSubAddress::from_canonical(canonical));
        assert_eq!(address.to_string(), canonicalize(input).unwrap());
        assert_eq!(
            address.bare().to_string(),
            canonical_bare_key(input).unwrap()
        );
        assert_eq!(address.has_resource(), has_resource);
    }
}

#[test]
fn bare_jid_accepts_bare_addresses_and_rejects_resources() {
    let input = "ALIce@Example.TEST";
    let bare = PubSubBareJid::parse(input).unwrap();
    assert_eq!(bare.canonical(), &CanonicalJid::parse_bare(input).unwrap());
    assert_eq!(bare.to_string(), canonical_bare_key(input).unwrap());
    assert!(PubSubBareJid::parse("ALIce@Example.TEST/Phone").is_err());
}

#[test]
fn both_jid_types_reject_invalid_addresses() {
    for input in ["", "alice@", "@example.test", "alice@example.test/"] {
        assert!(PubSubAddress::parse(input).is_err());
        assert!(PubSubBareJid::parse(input).is_err());
    }
}

#[test]
fn node_name_rejects_blank_text_and_preserves_the_original() {
    assert!(PubSubNodeName::parse("").is_err());
    assert!(PubSubNodeName::parse("  ").is_err());
    let name = PubSubNodeName::parse(" a ").unwrap();
    assert_eq!(name.as_str(), " a ");
    assert_eq!(name.to_string(), " a ");
}

#[test]
fn node_id_round_trips_the_uuid_and_uses_its_display() {
    let uuid = Uuid::from_u128(42);
    let id = PubSubNodeId::new(uuid);
    assert_eq!(id.get(), uuid);
    assert_eq!(id.to_string(), uuid.to_string());
}
