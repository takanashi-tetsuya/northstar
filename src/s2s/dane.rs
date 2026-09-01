//! DNSSEC-validated XMPP DANE policy (RFC 7712 section 5.1, RFC 7673).
//!
//! XMPP's DNA profile is intentionally narrower than generic TLSA: only
//! PKIX-EE (usage 1) and DANE-EE (usage 3) are accepted. Every lookup comes
//! from Hickory's local DNSSEC validator, and SRV, terminal address and TLSA
//! data are bound to the endpoint actually selected for the socket.

use anyhow::{Context, Result};
use hickory_resolver::{
    net::{DnsError, NetError},
    proto::{
        dnssec::Proof,
        op::ResponseCode,
        rr::{
            rdata::{
                tlsa::{CertUsage, Matching, Selector},
                TLSA,
            },
            RData, Record,
        },
    },
    TokioResolver,
};
use sha2::{Digest, Sha256, Sha512};
use std::{net::IpAddr, time::Duration};
use subtle::ConstantTimeEq;
use tokio_rustls::rustls::pki_types::CertificateDer;
use webpki::EndEntityCert;
use x509_parser::{parse_x509_certificate, public_key::PublicKey};

const DANE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_TLSA_RECORDS: usize = 32;
const MAX_SRV_RECORDS: usize = 128;
const MAX_RAW_ASSOCIATION_BYTES: usize = 64 * 1024;
const MAX_ADDRESS_RECORDS: usize = 32;
const MIN_RSA_BITS: usize = 2048;
const MIN_EC_BITS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DaneMode {
    Off,
    Opportunistic,
    Required,
}

impl DaneMode {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "opportunistic" => Ok(Self::Opportunistic),
            "required" => Ok(Self::Required),
            _ => anyhow::bail!("FEDERATION_DANE_MODE must be off, opportunistic, or required"),
        }
    }
}

/// The DNSSEC-authenticated SRV relationship that selected a federation
/// endpoint. RFC 7671 requires TLSA to be looked up at the SRV target and
/// selected port; authenticating TLSA while trusting an attacker-selected SRV
/// target would not authenticate the original XMPP service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaneSrvBinding {
    owner: String,
    target: String,
    port: u16,
}

impl DaneSrvBinding {
    pub(crate) fn new(service: &str, xmpp_domain: &str, target: &str, port: u16) -> Result<Self> {
        if !matches!(service, "_xmpp-server" | "_xmpps-server") {
            anyhow::bail!("DANE SRV service must be _xmpp-server or _xmpps-server");
        }
        if port == 0 {
            anyhow::bail!("DANE SRV port cannot be zero");
        }
        let domain = canonical_dns_host(xmpp_domain)?;
        let target = canonical_dns_host(target)?;
        Ok(Self {
            owner: format!("{service}._tcp.{domain}."),
            target,
            port,
        })
    }

    pub(crate) fn target(&self) -> &str {
        &self.target
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaneUsage {
    /// RFC 7712's service-certificate proof: PKIX validation is required in
    /// addition to the TLSA constraint (TLSA certificate usage 1).
    PkixEndEntity,
    /// RFC 7712's domain-issued proof (TLSA certificate usage 3).
    DaneEndEntity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaneSelector {
    FullCertificate,
    SubjectPublicKeyInfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaneMatching {
    Exact,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DaneAssociation {
    usage: DaneUsage,
    selector: DaneSelector,
    matching: DaneMatching,
    data: Vec<u8>,
}

impl DaneAssociation {
    fn from_tlsa(record: &TLSA) -> Result<Option<Self>> {
        let usage = match record.cert_usage {
            // RFC 7712 section 5.1 defines the XMPP DANE prooftype in terms
            // of PKIX-EE (1) and DANE-EE (3), not the generic TLSA usages 0/2.
            CertUsage::PkixEe => DaneUsage::PkixEndEntity,
            CertUsage::DaneEe => DaneUsage::DaneEndEntity,
            _ => return Ok(None),
        };
        let selector = match record.selector {
            Selector::Full => DaneSelector::FullCertificate,
            Selector::Spki => DaneSelector::SubjectPublicKeyInfo,
            _ => return Ok(None),
        };
        let matching = match record.matching {
            Matching::Raw => DaneMatching::Exact,
            Matching::Sha256 => DaneMatching::Sha256,
            Matching::Sha512 => DaneMatching::Sha512,
            _ => return Ok(None),
        };
        if record.cert_data.is_empty() || record.cert_data.len() > MAX_RAW_ASSOCIATION_BYTES {
            return Ok(None);
        }
        match matching {
            DaneMatching::Exact => {}
            DaneMatching::Sha256 if record.cert_data.len() == 32 => {}
            DaneMatching::Sha512 if record.cert_data.len() == 64 => {}
            DaneMatching::Sha256 | DaneMatching::Sha512 => return Ok(None),
        }
        Ok(Some(Self {
            usage,
            selector,
            matching,
            data: record.cert_data.clone(),
        }))
    }

    fn matches_certificate(&self, certificate: &CertificateDer<'_>) -> Result<bool> {
        match self.selector {
            DaneSelector::FullCertificate => Ok(self.matches_selected(certificate.as_ref())),
            DaneSelector::SubjectPublicKeyInfo => {
                let (remainder, parsed) = parse_x509_certificate(certificate.as_ref())
                    .map_err(|_| anyhow::anyhow!("DANE candidate certificate is malformed"))?;
                if !remainder.is_empty() {
                    anyhow::bail!("DANE candidate certificate contains trailing DER data");
                }
                Ok(self.matches_selected(parsed.public_key().raw))
            }
        }
    }

    fn matches_selected(&self, selected: &[u8]) -> bool {
        let candidate = match self.matching {
            DaneMatching::Exact => selected.to_vec(),
            DaneMatching::Sha256 => Sha256::digest(selected).to_vec(),
            DaneMatching::Sha512 => Sha512::digest(selected).to_vec(),
        };
        candidate.len() == self.data.len()
            && bool::from(candidate.as_slice().ct_eq(self.data.as_slice()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DanePolicy {
    owner: String,
    associations: Vec<DaneAssociation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DaneMatch {
    /// The TLSA constraint matched, but normal RFC 5280 path, time, EKU and
    /// XMPP reference-identity validation remains mandatory.
    PkixEndEntity,
    /// The TLSA constraint is the reference identity. RFC 7673 deliberately
    /// disables PKIX path, validity-time and DNS-name checks for this case.
    /// The rustls handshake must still prove possession of the parsed public
    /// key using one of Northstar's configured, non-legacy signature schemes.
    DaneEndEntity,
}

impl DanePolicy {
    pub(crate) fn owner(&self) -> &str {
        &self.owner
    }

    pub(crate) fn matching_credentials(
        &self,
        certificates: &[CertificateDer<'_>],
    ) -> Result<Vec<DaneMatch>> {
        let leaf = certificates
            .first()
            .context("DANE peer presented an empty certificate chain")?;
        validate_dane_leaf_structure(leaf)?;
        let mut matches = Vec::new();
        for association in &self.associations {
            match association.usage {
                DaneUsage::PkixEndEntity if association.matches_certificate(leaf)? => {
                    if !matches.contains(&DaneMatch::PkixEndEntity) {
                        matches.push(DaneMatch::PkixEndEntity);
                    }
                }
                DaneUsage::DaneEndEntity if association.matches_certificate(leaf)? => {
                    if !matches.contains(&DaneMatch::DaneEndEntity) {
                        matches.push(DaneMatch::DaneEndEntity);
                    }
                }
                DaneUsage::PkixEndEntity | DaneUsage::DaneEndEntity => {}
            }
        }
        Ok(matches)
    }
}

/// Look up an endpoint's TLSA policy using a locally validating resolver.
/// Only records carrying Hickory's `Proof::Secure` are consumed. A secure
/// positive RRset is authoritative even when all its records use unsupported
/// parameters: in that case the connection fails rather than downgrading to
/// PKIX. DNSSEC bogus/indeterminate responses are propagated as errors.
pub(crate) async fn lookup_dane_policy(
    resolver: &TokioResolver,
    mode: DaneMode,
    tls_host: &str,
    port: u16,
    selected_ip: IpAddr,
    srv_binding: Option<&DaneSrvBinding>,
) -> Result<Option<DanePolicy>> {
    if mode == DaneMode::Off {
        return Ok(None);
    }
    if port == 0 {
        anyhow::bail!("DANE TLS port cannot be zero");
    }
    let tls_host = canonical_dns_host(tls_host)?;
    let Some(binding) = srv_binding else {
        // RFC 7712 section 5.1 says an XMPP service without SRV records uses
        // the RFC 6120 fallback methods. It is not an XMPP DANE endpoint.
        return unavailable(mode, "no DNSSEC-authenticated XMPP SRV relationship exists");
    };
    if binding.target != tls_host || binding.port != port {
        anyhow::bail!("DANE SRV binding does not match the selected TLS endpoint");
    }
    if !secure_srv_binding(resolver, binding).await? {
        return unavailable(mode, "the selected SRV relationship is not DNSSEC secure");
    }
    if !secure_address_binding(resolver, &binding.target, selected_ip).await? {
        return unavailable(
            mode,
            "the selected SRV target address is not DNSSEC authenticated",
        );
    }

    let owner = format!("_{port}._tcp.{tls_host}.");
    let lookup =
        match tokio::time::timeout(DANE_LOOKUP_TIMEOUT, resolver.tlsa_lookup(owner.clone()))
            .await
            .with_context(|| format!("DNSSEC TLSA lookup timed out for {owner}"))?
        {
            Ok(lookup) => lookup,
            Err(error) if no_records(&error) => {
                return unavailable(mode, "no TLSA RRset was published");
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("DNSSEC TLSA validation failed for {owner}"));
            }
        };

    match secure_tlsa_associations(&owner, lookup.answers())? {
        SecureTlsa::Unavailable => unavailable(mode, "the TLSA RRset is not DNSSEC secure"),
        SecureTlsa::Policy(associations) => Ok(Some(DanePolicy {
            owner,
            associations,
        })),
    }
}

/// RFC 7673 requires the entire SRV-to-address delegation to be DNSSEC
/// authenticated. Hickory's locally validating resolver assigns `Secure` to
/// an address only after validating any CNAME/DNAME chain, so accepting the
/// selected address additionally binds the actual socket destination. We do
/// not trust an upstream AD bit or an address produced by the system resolver.
async fn secure_address_binding(
    resolver: &TokioResolver,
    target: &str,
    selected_ip: IpAddr,
) -> Result<bool> {
    let lookup = match selected_ip {
        IpAddr::V4(_) => {
            tokio::time::timeout(DANE_LOOKUP_TIMEOUT, resolver.ipv4_lookup(target.to_owned()))
                .await
                .with_context(|| format!("DNSSEC A lookup timed out for {target}"))?
                .map_err(anyhow::Error::from)
        }
        IpAddr::V6(_) => {
            tokio::time::timeout(DANE_LOOKUP_TIMEOUT, resolver.ipv6_lookup(target.to_owned()))
                .await
                .with_context(|| format!("DNSSEC AAAA lookup timed out for {target}"))?
                .map_err(anyhow::Error::from)
        }
    };
    let lookup = match lookup {
        Ok(lookup) => lookup,
        Err(error) => {
            let is_absent = error.downcast_ref::<NetError>().is_some_and(no_records);
            if is_absent {
                return Ok(false);
            }
            return Err(error).with_context(|| {
                format!("DNSSEC address validation failed for SRV target {target}")
            });
        }
    };
    secure_selected_address(lookup.answers(), selected_ip)
}

fn secure_selected_address(answers: &[Record], selected_ip: IpAddr) -> Result<bool> {
    let address_records = answers
        .iter()
        .filter(|record| matches!(record.data, RData::A(_) | RData::AAAA(_)))
        .collect::<Vec<_>>();
    if address_records.len() > MAX_ADDRESS_RECORDS {
        anyhow::bail!("DNSSEC address response exceeds its record limit");
    }
    if address_records.is_empty() {
        return Ok(false);
    }
    let proofs = address_records
        .iter()
        .map(|record| record.proof)
        .collect::<Vec<_>>();
    match uniform_proof(&proofs)? {
        Proof::Secure => {}
        Proof::Insecure => return Ok(false),
        Proof::Bogus | Proof::Indeterminate => {
            anyhow::bail!("SRV target address response is not cryptographically validated")
        }
    }
    uniform_record_owner(address_records.iter().copied())?;
    Ok(address_records.iter().any(|record| match record.data {
        RData::A(address) => selected_ip == IpAddr::V4(address.0),
        RData::AAAA(address) => selected_ip == IpAddr::V6(address.0),
        _ => false,
    }))
}

async fn secure_srv_binding(resolver: &TokioResolver, binding: &DaneSrvBinding) -> Result<bool> {
    let lookup = match tokio::time::timeout(
        DANE_LOOKUP_TIMEOUT,
        resolver.srv_lookup(binding.owner.clone()),
    )
    .await
    .with_context(|| format!("DNSSEC SRV lookup timed out for {}", binding.owner))?
    {
        Ok(lookup) => lookup,
        Err(error) if no_records(&error) => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("DNSSEC SRV validation failed for {}", binding.owner));
        }
    };
    let records = lookup
        .answers()
        .iter()
        .filter(|record| matches!(record.data, RData::SRV(_)))
        .collect::<Vec<_>>();
    if records.len() > MAX_SRV_RECORDS {
        anyhow::bail!("DNSSEC SRV response exceeds its record limit");
    }
    if records.is_empty() {
        return Ok(false);
    }
    let proofs = records
        .iter()
        .map(|record| record.proof)
        .collect::<Vec<_>>();
    match uniform_proof(&proofs)? {
        Proof::Secure => {}
        Proof::Insecure => return Ok(false),
        Proof::Bogus | Proof::Indeterminate => {
            anyhow::bail!("DNSSEC SRV response is not cryptographically validated")
        }
    }
    let mut exact = false;
    uniform_record_owner(records.iter().copied())?;
    for record in records {
        let RData::SRV(srv) = &record.data else {
            continue;
        };
        if srv.port == binding.port
            && canonical_dns_host(&srv.target.to_utf8())
                .is_ok_and(|target| target == binding.target)
        {
            exact = true;
        }
    }
    if !exact {
        anyhow::bail!("selected federation endpoint is absent from the secure SRV RRset");
    }
    Ok(true)
}

enum SecureTlsa {
    Unavailable,
    Policy(Vec<DaneAssociation>),
}

fn secure_tlsa_associations(_query_owner: &str, answers: &[Record]) -> Result<SecureTlsa> {
    let records = answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::TLSA(tlsa) => Some((record, tlsa)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if records.len() > MAX_TLSA_RECORDS {
        anyhow::bail!("DNSSEC TLSA response exceeds its record limit");
    }
    if records.is_empty() {
        return Ok(SecureTlsa::Unavailable);
    }
    let proofs = records
        .iter()
        .map(|(record, _)| record.proof)
        .collect::<Vec<_>>();
    match uniform_proof(&proofs)? {
        Proof::Secure => {}
        Proof::Insecure => return Ok(SecureTlsa::Unavailable),
        Proof::Bogus | Proof::Indeterminate => {
            anyhow::bail!("TLSA RRset is not cryptographically validated")
        }
    }
    let mut associations = Vec::new();
    // A DNSSEC-secure CNAME/DNAME chain may change the final RRset owner.
    // Hickory binds the returned, locally validated answer to the exact query;
    // requiring one uniform terminal owner prevents response splicing while
    // remaining compatible with RFC 7671 aliases.
    uniform_record_owner(records.iter().map(|(record, _)| *record))?;
    for (_, tlsa) in records {
        if let Some(association) = DaneAssociation::from_tlsa(tlsa)? {
            associations.push(association);
        }
    }
    if associations.is_empty() {
        anyhow::bail!("secure TLSA RRset contains no RFC 7712 PKIX-EE/DANE-EE association");
    }
    Ok(SecureTlsa::Policy(associations))
}

fn uniform_proof(proofs: &[Proof]) -> Result<Proof> {
    let first = proofs.first().copied().unwrap_or(Proof::Indeterminate);
    if proofs.iter().any(|proof| *proof != first) {
        anyhow::bail!("DNSSEC RRset contains inconsistent validation proofs");
    }
    Ok(first)
}

fn uniform_record_owner<'a>(records: impl IntoIterator<Item = &'a Record>) -> Result<()> {
    let mut records = records.into_iter();
    let Some(first) = records.next() else {
        return Ok(());
    };
    let owner = first.name.to_utf8();
    if records.any(|record| !dns_names_equal(&record.name.to_utf8(), &owner)) {
        anyhow::bail!("DNSSEC RRset contains inconsistent terminal owner names");
    }
    Ok(())
}

fn unavailable(mode: DaneMode, reason: &str) -> Result<Option<DanePolicy>> {
    match mode {
        DaneMode::Off | DaneMode::Opportunistic => Ok(None),
        DaneMode::Required => anyhow::bail!("DANE is required but {reason}"),
    }
}

fn no_records(error: &NetError) -> bool {
    matches!(
        error,
        NetError::Dns(DnsError::NoRecordsFound(no_records))
            if matches!(no_records.response_code, ResponseCode::NoError | ResponseCode::NXDomain)
    )
}

fn canonical_dns_host(value: &str) -> Result<String> {
    let prepared = crate::jid::prepare_domainpart(value.trim_end_matches('.'))
        .context("DANE host is not a valid RFC 7622 domain")?;
    crate::jid::domain_to_ascii(&prepared)
        .context("DANE host cannot be represented as an A-label")
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
}

fn dns_names_equal(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}

/// Parse the DANE-EE leaf before comparing even a full-certificate selector.
/// A raw byte-for-byte TLSA match must never turn malformed DER into a TLS
/// credential. Certificate time and DNS name are intentionally not checked:
/// RFC 7673 section 4.2 makes the DNSSEC-authenticated TLSA record the identity
/// and validity authority for usage 3.
fn validate_dane_leaf_structure(certificate: &CertificateDer<'_>) -> Result<()> {
    EndEntityCert::try_from(certificate)
        .context("DANE leaf is not a structurally valid end-entity certificate")?;
    let (remainder, parsed) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| anyhow::anyhow!("DANE leaf contains malformed X.509 DER"))?;
    if !remainder.is_empty() {
        anyhow::bail!("DANE leaf contains trailing DER data");
    }
    match parsed
        .public_key()
        .parsed()
        .context("DANE leaf contains an invalid subject public key")?
    {
        PublicKey::RSA(key)
            if key.key_size() >= MIN_RSA_BITS
                && key
                    .try_exponent()
                    .is_ok_and(|exponent| exponent >= 65_537 && exponent % 2 == 1) => {}
        PublicKey::EC(key) if key.key_size() >= MIN_EC_BITS => {}
        // x509-parser currently reports Ed25519 as Unknown. The exact OID and
        // 32-byte key constraint keep this narrow; rustls will still verify
        // the TLS CertificateVerify signature with its provider policy.
        PublicKey::Unknown(key)
            if parsed.public_key().algorithm.algorithm.to_id_string() == "1.3.101.112"
                && key.len() == 32 => {}
        _ => anyhow::bail!("DANE leaf uses an unsupported or weak public key"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::{Name, Record};
    use std::str::FromStr;

    fn tlsa_record(owner: &str, proof: Proof, tlsa: TLSA) -> Record {
        let mut record = Record::from_rdata(
            Name::from_str(owner).expect("test DNS name"),
            300,
            RData::TLSA(tlsa),
        );
        record.proof = proof;
        record
    }

    #[test]
    fn dane_mode_and_service_owner_are_strict_and_idna_canonical() {
        assert_eq!(
            DaneMode::parse("OPPORTUNISTIC").unwrap(),
            DaneMode::Opportunistic
        );
        assert!(DaneMode::parse("permissive").is_err());
        let binding = DaneSrvBinding::new(
            "_xmpps-server",
            "B\u{fc}CHER.example.",
            "TLS.B\u{fc}CHER.example.",
            5270,
        )
        .unwrap();
        assert_eq!(binding.owner, "_xmpps-server._tcp.xn--bcher-kva.example.");
        assert_eq!(binding.target, "tls.xn--bcher-kva.example");
        assert!(DaneSrvBinding::new("_https", "example.test", "tls.example.test", 443).is_err());
        assert!(
            DaneSrvBinding::new("_xmpp-server", "example.test", "tls.example.test", 0).is_err()
        );
    }

    #[test]
    fn association_matching_supports_exact_sha256_and_sha512() {
        let selected = b"certificate-or-spki-der";
        for (matching, data) in [
            (DaneMatching::Exact, selected.to_vec()),
            (DaneMatching::Sha256, Sha256::digest(selected).to_vec()),
            (DaneMatching::Sha512, Sha512::digest(selected).to_vec()),
        ] {
            let association = DaneAssociation {
                usage: DaneUsage::DaneEndEntity,
                selector: DaneSelector::FullCertificate,
                matching,
                data,
            };
            assert!(association.matches_selected(selected));
            assert!(!association.matches_selected(b"different"));
        }
    }

    #[test]
    fn only_uniform_secure_tlsa_rrsets_become_policy() {
        let owner = "_5269._tcp.example.test.";
        let tlsa = TLSA::new(
            CertUsage::DaneEe,
            Selector::Full,
            Matching::Sha256,
            vec![7; 32],
        );
        let secure = tlsa_record(owner, Proof::Secure, tlsa.clone());
        assert!(matches!(
            secure_tlsa_associations(owner, &[secure]),
            Ok(SecureTlsa::Policy(_))
        ));
        let insecure = tlsa_record(owner, Proof::Insecure, tlsa.clone());
        assert!(matches!(
            secure_tlsa_associations(owner, &[insecure]),
            Ok(SecureTlsa::Unavailable)
        ));
        let mixed = [
            tlsa_record(owner, Proof::Secure, tlsa.clone()),
            tlsa_record(owner, Proof::Insecure, tlsa),
        ];
        assert!(secure_tlsa_associations(owner, &mixed).is_err());

        // A locally validated CNAME/DNAME chain may legitimately produce a
        // different terminal owner, but one RRset cannot mix terminal owners.
        let alias = tlsa_record(
            "_5269._tcp.alias.example.test.",
            Proof::Secure,
            TLSA::new(
                CertUsage::DaneEe,
                Selector::Full,
                Matching::Sha256,
                vec![7; 32],
            ),
        );
        assert!(matches!(
            secure_tlsa_associations(owner, std::slice::from_ref(&alias)),
            Ok(SecureTlsa::Policy(_))
        ));
        let split_owner = [
            alias,
            tlsa_record(
                "_5269._tcp.other.example.test.",
                Proof::Secure,
                TLSA::new(
                    CertUsage::DaneEe,
                    Selector::Full,
                    Matching::Sha256,
                    vec![8; 32],
                ),
            ),
        ];
        assert!(secure_tlsa_associations(owner, &split_owner).is_err());
    }

    #[test]
    fn secure_unknown_or_malformed_tlsa_policy_fails_closed() {
        let owner = "_5269._tcp.example.test.";
        let unsupported = tlsa_record(
            owner,
            Proof::Secure,
            TLSA::new(
                CertUsage::DaneTa,
                Selector::Full,
                Matching::Sha256,
                vec![1; 32],
            ),
        );
        assert!(secure_tlsa_associations(owner, &[unsupported]).is_err());
        let malformed = tlsa_record(
            owner,
            Proof::Secure,
            TLSA::new(
                CertUsage::DaneEe,
                Selector::Full,
                Matching::Sha512,
                vec![2; 32],
            ),
        );
        assert!(secure_tlsa_associations(owner, &[malformed]).is_err());
        for proof in [Proof::Bogus, Proof::Indeterminate] {
            let invalid_proof = tlsa_record(
                owner,
                proof,
                TLSA::new(
                    CertUsage::DaneEe,
                    Selector::Full,
                    Matching::Sha256,
                    vec![3; 32],
                ),
            );
            assert!(secure_tlsa_associations(owner, &[invalid_proof]).is_err());
        }

        // RFC 7673 processes usable associations from the RRset; an unknown
        // record does not invalidate a simultaneously published XMPP record.
        let mixed = [
            tlsa_record(
                owner,
                Proof::Secure,
                TLSA::new(
                    CertUsage::DaneTa,
                    Selector::Full,
                    Matching::Sha256,
                    vec![1; 32],
                ),
            ),
            tlsa_record(
                owner,
                Proof::Secure,
                TLSA::new(
                    CertUsage::PkixEe,
                    Selector::Spki,
                    Matching::Sha512,
                    vec![2; 64],
                ),
            ),
        ];
        assert!(matches!(
            secure_tlsa_associations(owner, &mixed),
            Ok(SecureTlsa::Policy(associations)) if associations.len() == 1
        ));
    }

    #[test]
    fn malformed_leaf_cannot_become_a_dane_identity_by_raw_byte_match() {
        let leaf = CertificateDer::from(vec![1, 2, 3]);
        let policy = DanePolicy {
            owner: "_5269._tcp.example.test.".to_owned(),
            associations: vec![DaneAssociation {
                usage: DaneUsage::DaneEndEntity,
                selector: DaneSelector::FullCertificate,
                matching: DaneMatching::Exact,
                data: leaf.as_ref().to_vec(),
            }],
        };
        assert!(policy.matching_credentials(&[leaf]).is_err());
    }

    #[test]
    fn rfc_7712_accepts_only_pkix_ee_and_dane_ee_usages() {
        for (usage, expected) in [
            (CertUsage::PkixTa, false),
            (CertUsage::PkixEe, true),
            (CertUsage::DaneTa, false),
            (CertUsage::DaneEe, true),
        ] {
            let record = TLSA::new(usage, Selector::Full, Matching::Sha256, vec![9; 32]);
            assert_eq!(
                DaneAssociation::from_tlsa(&record).unwrap().is_some(),
                expected
            );
        }
        for (selector, expected) in [
            (Selector::Full, DaneSelector::FullCertificate),
            (Selector::Spki, DaneSelector::SubjectPublicKeyInfo),
        ] {
            for (matching, expected_matching, data) in [
                (Matching::Raw, DaneMatching::Exact, vec![9]),
                (Matching::Sha256, DaneMatching::Sha256, vec![9; 32]),
                (Matching::Sha512, DaneMatching::Sha512, vec![9; 64]),
            ] {
                let association = DaneAssociation::from_tlsa(&TLSA::new(
                    CertUsage::DaneEe,
                    selector,
                    matching,
                    data,
                ))
                .unwrap()
                .unwrap();
                assert_eq!(association.selector, expected);
                assert_eq!(association.matching, expected_matching);
            }
        }
    }

    #[test]
    fn selected_socket_address_must_be_in_a_uniformly_secure_rrset() {
        let name = Name::from_str("xmpp.example.test.").unwrap();
        let mut secure = Record::from_rdata(
            name.clone(),
            300,
            RData::A(hickory_resolver::proto::rr::rdata::A::new(192, 0, 2, 1)),
        );
        secure.proof = Proof::Secure;
        assert!(secure_selected_address(
            std::slice::from_ref(&secure),
            "192.0.2.1".parse().unwrap()
        )
        .unwrap());
        assert!(!secure_selected_address(&[secure], "192.0.2.2".parse().unwrap()).unwrap());

        let mut insecure = Record::from_rdata(
            name.clone(),
            300,
            RData::A(hickory_resolver::proto::rr::rdata::A::new(192, 0, 2, 1)),
        );
        insecure.proof = Proof::Insecure;
        assert!(!secure_selected_address(&[insecure], "192.0.2.1".parse().unwrap()).unwrap());

        let mut bogus = Record::from_rdata(
            name,
            300,
            RData::A(hickory_resolver::proto::rr::rdata::A::new(192, 0, 2, 1)),
        );
        bogus.proof = Proof::Bogus;
        assert!(secure_selected_address(&[bogus], "192.0.2.1".parse().unwrap()).is_err());

        let mut indeterminate = Record::from_rdata(
            Name::from_str("xmpp.example.test.").unwrap(),
            300,
            RData::A(hickory_resolver::proto::rr::rdata::A::new(192, 0, 2, 1)),
        );
        indeterminate.proof = Proof::Indeterminate;
        assert!(secure_selected_address(&[indeterminate], "192.0.2.1".parse().unwrap()).is_err());
    }

    #[test]
    fn tlsa_record_limit_is_enforced_before_policy_use() {
        let owner = "_5269._tcp.example.test.";
        let records = (0..=MAX_TLSA_RECORDS)
            .map(|_| {
                tlsa_record(
                    owner,
                    Proof::Secure,
                    TLSA::new(
                        CertUsage::DaneEe,
                        Selector::Full,
                        Matching::Sha256,
                        vec![3; 32],
                    ),
                )
            })
            .collect::<Vec<_>>();
        assert!(secure_tlsa_associations(owner, &records).is_err());
    }
}
