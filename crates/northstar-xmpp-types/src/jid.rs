//! RFC 7622 JID parsing, preparation and canonical comparison.
//!
//! Component separators are located before applying any Unicode mapping, as
//! required by RFC 7622. Localparts and resourceparts use the maintained
//! PRECIS profiles from RFC 8265; domain names use IDNA/UTS #46 processing.

use anyhow::{Context, Result};
use precis_profiles::{
    precis_core::profile::PrecisFastInvocation, OpaqueString, UsernameCaseMapped,
};
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

const MAX_PART_OCTETS: usize = 1023;
const MAX_JID_OCTETS: usize = 3071;
const XMPP_LOCALPART_EXCLUSIONS: [char; 8] = ['"', '&', '\'', '/', ':', '<', '>', '@'];

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalJid {
    localpart: Option<String>,
    domainpart: String,
    resourcepart: Option<String>,
}

impl CanonicalJid {
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() || value.len() > MAX_JID_OCTETS {
            anyhow::bail!("JID must contain 1 to {MAX_JID_OCTETS} UTF-8 octets");
        }

        // RFC 7622 section 3.1 requires finding the separators before any
        // transformation that could decompose a character into '@' or '/'.
        let (address, resourcepart) = match value.split_once('/') {
            Some((address, resource)) => (address, Some(prepare_resourcepart(resource)?)),
            None => (value, None),
        };
        if address.is_empty() {
            anyhow::bail!("JID domainpart is empty");
        }

        let (localpart, domainpart) = match address.split_once('@') {
            Some((local, domain)) => (Some(prepare_localpart(local)?), domain),
            None => (None, address),
        };
        let domainpart = prepare_domainpart(domainpart)?;
        let jid = Self {
            localpart,
            domainpart,
            resourcepart,
        };
        if jid.to_string().len() > MAX_JID_OCTETS {
            anyhow::bail!("canonical JID exceeds {MAX_JID_OCTETS} UTF-8 octets");
        }
        Ok(jid)
    }

    pub fn parse_bare(value: &str) -> Result<Self> {
        let jid = Self::parse(value)?;
        if jid.resourcepart.is_some() {
            anyhow::bail!("bare JID must not have a resourcepart");
        }
        Ok(jid)
    }

    pub fn localpart(&self) -> Option<&str> {
        self.localpart.as_deref()
    }

    pub fn domainpart(&self) -> &str {
        &self.domainpart
    }

    pub fn resourcepart(&self) -> Option<&str> {
        self.resourcepart.as_deref()
    }

    pub fn bare(&self) -> String {
        match &self.localpart {
            Some(localpart) => format!("{localpart}@{}", self.domainpart),
            None => self.domainpart.clone(),
        }
    }

    /// Return the canonical bare form without reparsing a serialized JID.
    ///
    /// This is an infallible structural projection because `self` has already
    /// passed RFC 7622 preparation and only the resourcepart is discarded.
    pub fn to_bare(&self) -> Self {
        Self {
            localpart: self.localpart.clone(),
            domainpart: self.domainpart.clone(),
            resourcepart: None,
        }
    }
}

impl fmt::Display for CanonicalJid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(localpart) = &self.localpart {
            write!(formatter, "{localpart}@")?;
        }
        formatter.write_str(&self.domainpart)?;
        if let Some(resourcepart) = &self.resourcepart {
            write!(formatter, "/{resourcepart}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CanonicalJid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CanonicalJid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

pub fn prepare_localpart(value: &str) -> Result<String> {
    if value.is_empty() {
        anyhow::bail!("JID localpart is empty");
    }
    let prepared = UsernameCaseMapped::enforce(value)
        .context("JID localpart violates the UsernameCaseMapped PRECIS profile")?
        .into_owned();
    if prepared.is_empty() || prepared.len() > MAX_PART_OCTETS {
        anyhow::bail!("JID localpart must contain 1 to {MAX_PART_OCTETS} UTF-8 octets");
    }
    if prepared
        .chars()
        .any(|character| XMPP_LOCALPART_EXCLUSIONS.contains(&character))
    {
        anyhow::bail!("JID localpart contains an RFC 7622 excluded character");
    }
    Ok(prepared)
}

pub fn prepare_resourcepart(value: &str) -> Result<String> {
    if value.is_empty() {
        anyhow::bail!("JID resourcepart is empty");
    }
    let prepared = OpaqueString::enforce(value)
        .context("JID resourcepart violates the OpaqueString PRECIS profile")?
        .into_owned();
    if prepared.is_empty() || prepared.len() > MAX_PART_OCTETS {
        anyhow::bail!("JID resourcepart must contain 1 to {MAX_PART_OCTETS} UTF-8 octets");
    }
    Ok(prepared)
}

pub fn prepare_domainpart(value: &str) -> Result<String> {
    let value = strip_final_label_separator(value);
    if value.is_empty() {
        anyhow::bail!("JID domainpart is empty");
    }

    let prepared = if let Ok(ipv4) = value.parse::<Ipv4Addr>() {
        ipv4.to_string()
    } else if value.starts_with('[') || value.ends_with(']') {
        prepare_ip_literal(value)?
    } else {
        let ascii = idna::domain_to_ascii_strict(value)
            .map_err(|_| anyhow::anyhow!("JID domainpart is not a valid IDNA domain"))?
            .to_ascii_lowercase();
        let (unicode, result) = idna::domain_to_unicode(&ascii);
        result.map_err(|_| anyhow::anyhow!("JID domainpart is not a valid IDNA domain"))?;
        unicode
    };

    if prepared.is_empty() || prepared.len() > MAX_PART_OCTETS {
        anyhow::bail!("JID domainpart must contain 1 to {MAX_PART_OCTETS} UTF-8 octets");
    }
    Ok(prepared)
}

/// Convert an RFC 7622 U-label domain to the A-label used strictly at DNS and
/// TLS SNI boundaries. Stored and routed JIDs must use `prepare_domainpart`.
pub fn domain_to_ascii(value: &str) -> Result<String> {
    let prepared = prepare_domainpart(value)?;
    if prepared.starts_with('[') {
        anyhow::bail!("IP literals are not DNS names");
    }
    idna::domain_to_ascii_strict(&prepared)
        .map(|value| value.to_ascii_lowercase())
        .map_err(|_| anyhow::anyhow!("domain is not a valid DNS IDNA name"))
}

pub fn canonicalize(value: &str) -> Result<String> {
    CanonicalJid::parse(value).map(|jid| jid.to_string())
}

pub fn canonicalize_bare(value: &str) -> Result<String> {
    CanonicalJid::parse_bare(value).map(|jid| jid.to_string())
}

/// Match an XMPP address pattern at domain, bare-JID or exact full-JID scope.
/// Resourceparts remain case-sensitive because they use PRECIS OpaqueString.
pub fn jid_scope_matches(pattern: &str, candidate: &str) -> bool {
    let (Ok(pattern), Ok(candidate)) =
        (CanonicalJid::parse(pattern), CanonicalJid::parse(candidate))
    else {
        return false;
    };
    if pattern.resourcepart().is_some() {
        return pattern == candidate;
    }
    if pattern.localpart().is_some() {
        return pattern.bare() == candidate.bare();
    }
    pattern.domainpart() == candidate.domainpart()
}

/// Canonical key for an account, accepting either a bare or full input JID.
/// Localpart/domainpart are prepared while the resourcepart is deliberately
/// discarded.
pub fn canonical_bare_key(value: &str) -> Result<String> {
    CanonicalJid::parse(value).map(|jid| jid.bare())
}

/// Canonical key for one online resource. RFC 7622 applies a case-mapped
/// profile to the localpart but the OpaqueString profile to the resourcepart,
/// so callers must never lowercase the returned full JID.
pub fn canonical_session_key(value: &str) -> Result<String> {
    let jid = CanonicalJid::parse(value)?;
    if jid.resourcepart().is_none() {
        anyhow::bail!("session JID must contain a resourcepart");
    }
    Ok(jid.to_string())
}

fn strip_final_label_separator(value: &str) -> &str {
    value
        .strip_suffix(['.', '\u{3002}', '\u{ff0e}', '\u{ff61}'])
        .unwrap_or(value)
}

fn prepare_ip_literal(value: &str) -> Result<String> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .context("IPv6 JID domainparts must be enclosed in brackets")?;
    let (address, zone) = match inner.split_once("%25") {
        Some((address, zone)) => {
            validate_zone_identifier(zone)?;
            (address, Some(zone))
        }
        None => {
            if inner.contains('%') {
                anyhow::bail!("IPv6 zone identifiers must use RFC 6874 %25 escaping");
            }
            (inner, None)
        }
    };
    let address = address
        .parse::<Ipv6Addr>()
        .context("JID domainpart contains an invalid IPv6 address")?;
    Ok(match zone {
        Some(zone) => format!("[{address}%25{zone}]"),
        None => format!("[{address}]"),
    })
}

fn validate_zone_identifier(value: &str) -> Result<()> {
    if value.is_empty() {
        anyhow::bail!("IPv6 zone identifier is empty");
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            index += 1;
        } else if byte == b'%'
            && bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            index += 3;
        } else {
            anyhow::bail!("IPv6 zone identifier contains invalid RFC 6874 syntax");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_precis_and_idna_equivalents() {
        assert_eq!(
            canonicalize("A\u{30a}LICE@B\u{fc}CHER.Example./DeviceA\u{30a}").unwrap(),
            "\u{e5}lice@b\u{fc}cher.example/Device\u{c5}"
        );
        assert_eq!(
            canonicalize("\u{e5}lice@xn--bcher-kva.example/Device\u{c5}").unwrap(),
            "\u{e5}lice@b\u{fc}cher.example/Device\u{c5}"
        );
        assert_eq!(
            domain_to_ascii("B\u{fc}CHER.example").unwrap(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn parses_before_unicode_mapping_and_preserves_opaque_resources() {
        assert!(CanonicalJid::parse("alice@example.test/foo/bar@device").is_ok());
        assert_eq!(
            canonicalize("example.test./foo bar").unwrap(),
            "example.test/foo bar"
        );
    }

    #[test]
    fn session_keys_case_map_accounts_but_not_opaque_resources() {
        assert_eq!(
            canonical_session_key("ALICE@Example.test/Phone").unwrap(),
            "alice@example.test/Phone"
        );
        assert_ne!(
            canonical_session_key("alice@example.test/Phone").unwrap(),
            canonical_session_key("alice@example.test/phone").unwrap()
        );
        assert_eq!(
            canonical_bare_key("ALICE@Example.test/Phone").unwrap(),
            "alice@example.test"
        );
        assert!(canonical_session_key("alice@example.test").is_err());
    }

    #[test]
    fn bare_projection_is_infallible_and_preserves_canonical_identity() {
        let full = CanonicalJid::parse("ALICE@B\u{fc}CHER.example/Phone").unwrap();
        let bare = full.to_bare();
        assert_eq!(bare.to_string(), "alice@b\u{fc}cher.example");
        assert_eq!(bare.resourcepart(), None);
        assert_eq!(bare, bare.to_bare());
    }

    #[test]
    fn canonical_jids_have_a_stable_structural_order() {
        let mut jids = [
            CanonicalJid::parse("bob@example.test").unwrap(),
            CanonicalJid::parse("alice@example.test/phone").unwrap(),
            CanonicalJid::parse("alice@example.test/Phone").unwrap(),
            CanonicalJid::parse("alice@example.test").unwrap(),
        ];
        jids.sort();
        assert_eq!(
            jids.map(|jid| jid.to_string()),
            [
                "alice@example.test",
                "alice@example.test/Phone",
                "alice@example.test/phone",
                "bob@example.test",
            ]
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_revalidates_the_canonical_invariant() {
        let jid = CanonicalJid::parse("ALICE@B\u{fc}CHER.example/Phone").unwrap();
        let json = serde_json::to_string(&jid).unwrap();
        assert_eq!(json, "\"alice@b\u{fc}cher.example/Phone\"");
        assert_eq!(serde_json::from_str::<CanonicalJid>(&json).unwrap(), jid);
        assert!(serde_json::from_str::<CanonicalJid>("\"bad jid\"").is_err());
    }

    #[test]
    fn accepts_domain_only_and_ip_literal_jids() {
        assert_eq!(canonicalize_bare("EXAMPLE.test.").unwrap(), "example.test");
        assert_eq!(
            canonicalize_bare("[2001:0db8::1]").unwrap(),
            "[2001:db8::1]"
        );
        assert_eq!(
            canonicalize_bare("[fe80::1%25eth0]").unwrap(),
            "[fe80::1%25eth0]"
        );
    }

    #[test]
    fn rejects_malicious_or_disallowed_unicode() {
        for jid in [
            "ali\u{200b}ce@example.test",
            "alice\u{202e}@example.test",
            "\u{265a}@example.test",
            "\u{2163}@example.test",
            "alice@example..test",
            "alice@exa mple.test",
            "alice@example.test/\u{0007}",
        ] {
            assert!(CanonicalJid::parse(jid).is_err(), "accepted {jid:?}");
        }
    }

    #[test]
    fn enforces_octet_limits_after_mapping() {
        let maximum_localpart = format!("{}@x", "a".repeat(1023));
        let maximum_resource = format!("a@x/{}", "r".repeat(1023));
        assert!(CanonicalJid::parse(&maximum_localpart).is_ok());
        assert!(CanonicalJid::parse(&maximum_resource).is_ok());
        let oversized_localpart = format!("{}@example.test", "a".repeat(1024));
        let oversized_resource = format!("alice@example.test/{}", "a".repeat(1024));
        assert!(CanonicalJid::parse(&oversized_localpart).is_err());
        assert!(CanonicalJid::parse(&oversized_resource).is_err());
    }

    #[test]
    fn canonicalization_is_idempotent_for_adversarial_rfc7622_corpus() {
        // RFC 7622 section 3.1 parses the first '/' and first '@' in the
        // remaining address before applying any mapping.  The resourcepart
        // is opaque and can legitimately contain either separator.
        for input in [
            "ALICE@BüCHER.example./Phone",
            "example.test/foo/bar@device",
            "a.example/b@example.net",
            "Σ@example.test/♚",
            "example.test/resource with spaces",
            "[2001:0db8::1]/opaque@resource/child",
        ] {
            let once = canonicalize(input).unwrap_or_else(|error| {
                panic!("RFC 7622 corpus entry {input:?} was rejected: {error}")
            });
            assert_eq!(canonicalize(&once).unwrap(), once, "input {input:?}");
        }
        assert!(CanonicalJid::parse("a@b@example.test/resource").is_err());
        assert!(CanonicalJid::parse("@example.test/resource").is_err());
        assert!(CanonicalJid::parse("example.test/").is_err());
    }

    #[test]
    fn rejects_rfc_7622_localpart_exclusions() {
        for character in XMPP_LOCALPART_EXCLUSIONS {
            assert!(prepare_localpart(&format!("alice{character}")).is_err());
        }
    }

    #[test]
    fn scoped_matching_distinguishes_domain_bare_and_opaque_resource() {
        assert!(jid_scope_matches(
            "example.test",
            "alice@example.test/Phone"
        ));
        assert!(jid_scope_matches(
            "alice@example.test",
            "alice@example.test/Phone"
        ));
        assert!(jid_scope_matches(
            "alice@example.test/Phone",
            "alice@example.test/Phone"
        ));
        assert!(!jid_scope_matches(
            "alice@example.test/Phone",
            "alice@example.test/phone"
        ));
    }
}
