use northstar_xmpp_types::{
    canonical_bare_key, canonical_session_key, canonicalize, canonicalize_bare, domain_to_ascii,
    prepare_domainpart, prepare_localpart, prepare_resourcepart, CanonicalJid,
};
use std::collections::HashSet;

#[test]
fn test_canonical_jid_full_accessors_and_display() {
    let jid = CanonicalJid::parse("ALICE@EXAMPLE.COM/Mobile").expect("valid full JID");
    assert_eq!(jid.localpart(), Some("alice"));
    assert_eq!(jid.domainpart(), "example.com");
    assert_eq!(jid.resourcepart(), Some("Mobile"));
    assert_eq!(jid.bare(), "alice@example.com");
    assert_eq!(jid.to_string(), "alice@example.com/Mobile");
}

#[test]
fn test_canonical_jid_bare_accessors_and_display() {
    let jid = CanonicalJid::parse("BOB@EXAMPLE.ORG").expect("valid bare JID");
    assert_eq!(jid.localpart(), Some("bob"));
    assert_eq!(jid.domainpart(), "example.org");
    assert_eq!(jid.resourcepart(), None);
    assert_eq!(jid.bare(), "bob@example.org");
    assert_eq!(jid.to_string(), "bob@example.org");

    let parsed_bare = CanonicalJid::parse_bare("BOB@EXAMPLE.ORG").expect("valid bare parse");
    assert_eq!(jid, parsed_bare);

    assert!(CanonicalJid::parse_bare("bob@example.org/res").is_err());
}

#[test]
fn test_canonical_jid_domain_only_accessors_and_display() {
    let jid = CanonicalJid::parse("CONFERENCE.EXAMPLE.COM").expect("valid domain JID");
    assert_eq!(jid.localpart(), None);
    assert_eq!(jid.domainpart(), "conference.example.com");
    assert_eq!(jid.resourcepart(), None);
    assert_eq!(jid.bare(), "conference.example.com");
    assert_eq!(jid.to_string(), "conference.example.com");

    let jid_with_res =
        CanonicalJid::parse("CONFERENCE.EXAMPLE.COM/moderator").expect("domain with res");
    assert_eq!(jid_with_res.localpart(), None);
    assert_eq!(jid_with_res.domainpart(), "conference.example.com");
    assert_eq!(jid_with_res.resourcepart(), Some("moderator"));
    assert_eq!(jid_with_res.bare(), "conference.example.com");
    assert_eq!(jid_with_res.to_string(), "conference.example.com/moderator");
}

#[test]
fn test_canonicalize_helpers() {
    assert_eq!(
        canonicalize("ALICE@EXAMPLE.COM/Work").unwrap(),
        "alice@example.com/Work"
    );
    assert_eq!(
        canonicalize_bare("ALICE@EXAMPLE.COM").unwrap(),
        "alice@example.com"
    );
    assert!(canonicalize_bare("alice@example.com/Work").is_err());
}

#[test]
fn test_hash_and_equality() {
    let jid1 = CanonicalJid::parse("user@domain.test/res").unwrap();
    let jid2 = CanonicalJid::parse("USER@DOMAIN.TEST/res").unwrap();
    let jid3 = CanonicalJid::parse("user@domain.test/RES").unwrap();

    assert_eq!(jid1, jid2);
    assert_ne!(jid1, jid3);

    let mut set = HashSet::new();
    set.insert(jid1);
    assert!(set.contains(&jid2));
    assert!(!set.contains(&jid3));
}

#[test]
fn test_canonical_bare_key_behavior() {
    assert_eq!(
        canonical_bare_key("User@Domain.Test/Phone").unwrap(),
        "user@domain.test"
    );
    assert_eq!(
        canonical_bare_key("User@Domain.Test").unwrap(),
        "user@domain.test"
    );
    assert_eq!(canonical_bare_key("DOMAIN.TEST").unwrap(), "domain.test");
    assert!(canonical_bare_key("").is_err());
}

#[test]
fn test_canonical_session_key_behavior() {
    assert_eq!(
        canonical_session_key("User@Domain.Test/Phone").unwrap(),
        "user@domain.test/Phone"
    );
    assert_eq!(
        canonical_session_key("Domain.Test/Bot").unwrap(),
        "domain.test/Bot"
    );
    assert!(canonical_session_key("User@Domain.Test").is_err());
    assert!(canonical_session_key("Domain.Test").is_err());
}

#[test]
fn test_domain_to_ascii_dns_names() {
    assert_eq!(
        domain_to_ascii("b\u{fc}cher.example").unwrap(),
        "xn--bcher-kva.example"
    );
    assert_eq!(domain_to_ascii("EXAMPLE.COM").unwrap(), "example.com");
    assert!(domain_to_ascii("[2001:db8::1]").is_err());
    assert!(domain_to_ascii("[::1]").is_err());
}

#[test]
fn test_ipv4_and_ipv6_domainparts() {
    assert_eq!(prepare_domainpart("127.0.0.1").unwrap(), "127.0.0.1");
    assert_eq!(prepare_domainpart("192.168.1.1").unwrap(), "192.168.1.1");
    assert_eq!(prepare_domainpart("[::1]").unwrap(), "[::1]");
    assert_eq!(
        prepare_domainpart("[2001:0db8::1]").unwrap(),
        "[2001:db8::1]"
    );
    assert_eq!(
        prepare_domainpart("[fe80::1%25eth0]").unwrap(),
        "[fe80::1%25eth0]"
    );

    assert!(prepare_domainpart("[fe80::1%eth0]").is_err());
    assert!(prepare_domainpart("[invalid_ipv6]").is_err());
    assert!(prepare_domainpart("[::1").is_err());
    assert!(prepare_domainpart("::1]").is_err());
}

#[test]
fn test_trailing_dot_stripping() {
    assert_eq!(prepare_domainpart("example.com.").unwrap(), "example.com");
    assert_eq!(
        prepare_domainpart("example.com\u{3002}").unwrap(),
        "example.com"
    );
    assert_eq!(
        prepare_domainpart("example.com\u{ff0e}").unwrap(),
        "example.com"
    );
    assert_eq!(
        prepare_domainpart("example.com\u{ff61}").unwrap(),
        "example.com"
    );
}

#[test]
fn test_octet_limits_rejection() {
    assert!(prepare_localpart("").is_err());
    assert!(prepare_resourcepart("").is_err());
    assert!(prepare_domainpart("").is_err());

    let exact_1023 = "a".repeat(1023);
    let over_1023 = "a".repeat(1024);

    assert!(prepare_localpart(&exact_1023).is_ok());
    assert!(prepare_localpart(&over_1023).is_err());

    assert!(prepare_resourcepart(&exact_1023).is_ok());
    assert!(prepare_resourcepart(&over_1023).is_err());

    assert!(prepare_domainpart(&exact_1023).is_err()); // IDNA label limit
}

#[test]
fn test_rfc7622_localpart_prohibited_characters() {
    let prohibited = ['"', '&', '\'', '/', ':', '<', '>', '@'];
    for &ch in &prohibited {
        assert!(prepare_localpart(&format!("user{ch}name")).is_err());
    }

    // Characters that are prohibited in localpart and cannot be parsed as separate parts
    let invalid_in_full_jid = ['"', '&', '\'', ':', '<', '>'];
    for &ch in &invalid_in_full_jid {
        assert!(CanonicalJid::parse(&format!("user{ch}name@example.com")).is_err());
    }
}

#[test]
fn test_rfc7622_delimiters_in_resourcepart() {
    // Delimiters / and @ are allowed in resourceparts per RFC 7622 section 3.1
    let jid = CanonicalJid::parse("user@example.com/res@1/res@2").unwrap();
    assert_eq!(jid.localpart(), Some("user"));
    assert_eq!(jid.domainpart(), "example.com");
    assert_eq!(jid.resourcepart(), Some("res@1/res@2"));
}
