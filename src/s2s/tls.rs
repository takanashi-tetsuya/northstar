use crate::{
    jid::prepare_domainpart,
    s2s::dane::{DaneMatch, DanePolicy},
    state::AppState,
};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio_rustls::rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use x509_parser::{
    asn1_rs::{Any, Class, FromDer, Tag},
    extensions::GeneralName,
    parse_x509_certificate,
};

const ID_ON_XMPP_ADDR: &str = "1.3.6.1.5.5.7.8.5";
const ID_ON_DNS_SRV: &str = "1.3.6.1.5.5.7.8.7";
const XMPP_SERVER_SERVICE: &str = "_xmpp-server";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XmppCertificateIdentity {
    DnsId,
    SrvId,
    XmppAddr,
}

/// The TLS client verifier deliberately validates only PKIX here. XMPP's
/// reference identity is the stream `to` domain, not the host selected by an
/// SRV record, and RFC 6120 also permits SRV-ID and id-on-xmppAddr SANs that
/// rustls' HTTPS-style DNS verifier does not understand. Identity matching is
/// therefore performed immediately after the handshake by
/// `verify_peer_xmpp_identity` and before any post-TLS XML is sent.
#[derive(Debug)]
struct XmppPkixServerVerifier {
    roots: Arc<RootCertStore>,
    algorithms: WebPkiSupportedAlgorithms,
    public_key_pins: Vec<[u8; 32]>,
    dane_policy: Option<DanePolicy>,
    crls: Option<Arc<crate::crl::CrlSet>>,
}

impl XmppPkixServerVerifier {
    fn new(
        roots: Arc<RootCertStore>,
        public_key_pins: &[[u8; 32]],
        dane_policy: Option<&DanePolicy>,
        crls: Option<Arc<crate::crl::CrlSet>>,
    ) -> Self {
        Self {
            roots,
            algorithms: tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
            public_key_pins: public_key_pins.to_vec(),
            dane_policy: dane_policy.cloned(),
            crls,
        }
    }

    fn verify_pkix(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<(), RustlsError> {
        if let Some(crls) = &self.crls {
            return crls
                .verify_server_chain(
                    end_entity,
                    intermediates,
                    &self.roots,
                    now,
                    self.algorithms.all,
                )
                .map_err(|error| RustlsError::General(format!("{error:#}")));
        }
        let parsed = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )
    }
}

impl ServerCertVerifier for XmppPkixServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        if let Some(policy) = &self.dane_policy {
            let certificates = std::iter::once(end_entity.clone())
                .chain(intermediates.iter().cloned())
                .collect::<Vec<_>>();
            let matches = policy
                .matching_credentials(&certificates)
                .map_err(|error| RustlsError::General(format!("{error:#}")))?;
            if matches.contains(&DaneMatch::DaneEndEntity) {
                // RFC 7673 section 4.2: a DNSSEC-authenticated DANE-EE match
                // replaces PKIX path, time and name checks. The remainder of
                // this verifier still requires rustls to validate the TLS
                // CertificateVerify signature using the provider's schemes.
                return Ok(ServerCertVerified::assertion());
            }
            if matches.contains(&DaneMatch::PkixEndEntity) {
                return self
                    .verify_pkix(end_entity, intermediates, now)
                    .map(|()| ServerCertVerified::assertion());
            }
            return Err(RustlsError::General(format!(
                "peer certificate does not match secure TLSA policy {}",
                policy.owner()
            )));
        }
        let pkix = self.verify_pkix(end_entity, intermediates, now);
        if !pin_fallback_permitted(self.crls.is_some()) {
            // An XEP-0487 pin is an additional discovery credential, not an
            // escape hatch from an explicitly configured CA revocation
            // policy. In particular, CertRevoked (and fail-closed CRL
            // coverage/signature/freshness failures) must never be replaced
            // by a successful raw SPKI pin comparison.
            return pkix.map(|()| ServerCertVerified::assertion());
        }
        if pkix.is_ok() || pinned_certificate_valid(end_entity, &self.public_key_pins) {
            Ok(ServerCertVerified::assertion())
        } else {
            pkix.map(|()| ServerCertVerified::assertion())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn pin_fallback_permitted(crl_policy_configured: bool) -> bool {
    !crl_policy_configured
}

pub(crate) fn s2s_client_config(
    state: &AppState,
    direct_tls: bool,
    public_key_pins: &[[u8; 32]],
    dane_policy: Option<&DanePolicy>,
) -> Result<(Arc<tokio_rustls::rustls::ClientConfig>, u64)> {
    let material = state.tls.current();
    let mut config = if direct_tls {
        material.s2s_client_direct.as_ref().clone()
    } else {
        material.s2s_client_starttls.as_ref().clone()
    };
    // A resumed TLS connection may not carry a fresh Certificate message.
    // Disable resumption so post-handshake XMPP SAN verification always sees
    // the certificate that authenticated this exact connection.
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(XmppPkixServerVerifier::new(
            Arc::clone(&material.federation_roots),
            public_key_pins,
            dane_policy,
            material.federation_crls.clone(),
        )));
    Ok((Arc::new(config), material.generation))
}

fn pinned_certificate_valid(
    certificate: &CertificateDer<'_>,
    public_key_pins: &[[u8; 32]],
) -> bool {
    if public_key_pins.is_empty() {
        return false;
    }
    let Ok((remaining, parsed)) = parse_x509_certificate(certificate.as_ref()) else {
        return false;
    };
    if !remaining.is_empty() || !parsed.validity().is_valid() {
        return false;
    }
    let pin = Sha256::digest(parsed.public_key().raw);
    public_key_pins
        .iter()
        .any(|expected| bool::from(expected.ct_eq(pin.as_slice())))
}

pub(crate) fn peer_public_key_pin(certificate: &CertificateDer<'_>) -> Result<[u8; 32]> {
    let (remaining, parsed) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| anyhow::anyhow!("could not parse federation end-entity certificate"))?;
    if !remaining.is_empty() {
        anyhow::bail!("federation certificate contains trailing DER data");
    }
    Ok(Sha256::digest(parsed.public_key().raw).into())
}

pub(crate) fn s2s_server_config(
    state: &AppState,
    direct_tls: bool,
) -> Result<(Arc<tokio_rustls::rustls::ServerConfig>, u64)> {
    let material = state.tls.current();
    let config = if direct_tls {
        Arc::clone(&material.s2s_direct)
    } else {
        Arc::clone(&material.s2s_starttls)
    };
    Ok((config, material.generation))
}

/// A privacy-minimized HTTPS client for XEP-0487 discovery. Unlike an S2S
/// TLS connection it does not present Northstar's server certificate. Normal
/// WebPKI hostname verification authenticates every origin and redirect.
pub(crate) fn host_meta_https_client_config(
    state: &AppState,
) -> Result<Arc<tokio_rustls::rustls::ClientConfig>> {
    let material = state.tls.current();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let mut verifier = tokio_rustls::rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::clone(&material.federation_roots),
        Arc::clone(&provider),
    );
    if let Some(crls) = &material.federation_crls {
        verifier = verifier
            .with_crls(crls.encoded())
            .enforce_revocation_expiration();
    }
    let verifier = verifier
        .build()
        .context("could not build CRL-aware XEP-0487 HTTPS verifier")?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("could not select safe TLS versions for XEP-0487 HTTPS")?
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Validate only the certification path and client-auth usage. This is kept
/// separate from XMPP identity matching so callers cannot accidentally treat
/// an SRV target hostname as the authenticated XMPP domain.
pub(crate) fn verify_peer_certificate_chain(
    state: &AppState,
    certificates: &[CertificateDer<'static>],
) -> Result<bool> {
    let Some(end_entity) = certificates.first() else {
        return Ok(false);
    };
    let material = state.tls.current();
    let algorithms = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .signature_verification_algorithms;
    if let Some(crls) = &material.federation_crls {
        return Ok(crls
            .verify_client_chain(
                end_entity,
                &certificates[1..],
                &material.federation_roots,
                UnixTime::now(),
                algorithms.all,
            )
            .is_ok());
    }
    let end_entity = webpki::EndEntityCert::try_from(end_entity)
        .context("could not parse federation end-entity certificate")?;
    Ok(end_entity
        .verify_for_usage(
            algorithms.all,
            &material.federation_roots.roots,
            &certificates[1..],
            UnixTime::now(),
            webpki::KeyUsage::client_auth(),
            None,
            None,
        )
        .is_ok())
}

/// Match the XMPP reference domain against the leaf certificate SANs using
/// the identity types required/encouraged by RFC 6120 section 13.7:
/// DNS-ID, `_xmpp-server` SRV-ID, and id-on-xmppAddr. CN fallback is
/// intentionally not used.
pub(crate) fn verify_peer_xmpp_identity(
    certificate: &CertificateDer<'_>,
    domain: &str,
) -> Result<Option<XmppCertificateIdentity>> {
    let domain = prepare_domainpart(domain).context("invalid XMPP reference domain")?;
    let (remaining, certificate) = parse_x509_certificate(certificate.as_ref())
        .map_err(|_| anyhow::anyhow!("could not parse federation end-entity certificate"))?;
    if !remaining.is_empty() {
        anyhow::bail!("federation certificate contains trailing DER data");
    }
    let Some(san) = certificate
        .subject_alternative_name()
        .context("invalid federation subjectAltName extension")?
    else {
        return Ok(None);
    };

    for name in &san.value.general_names {
        match name {
            GeneralName::DNSName(presented) if dns_id_matches(presented, &domain) => {
                return Ok(Some(XmppCertificateIdentity::DnsId));
            }
            GeneralName::OtherName(oid, encoded) if oid.to_id_string() == ID_ON_DNS_SRV => {
                if decode_explicit_string(encoded, Tag::Ia5String)
                    .is_some_and(|presented| srv_id_matches(presented, &domain))
                {
                    return Ok(Some(XmppCertificateIdentity::SrvId));
                }
            }
            GeneralName::OtherName(oid, encoded)
                if oid.to_id_string() == ID_ON_XMPP_ADDR
                    && decode_explicit_string(encoded, Tag::Utf8String)
                        .is_some_and(|presented| xmpp_addr_matches(presented, &domain)) =>
            {
                return Ok(Some(XmppCertificateIdentity::XmppAddr));
            }
            _ => {}
        }
    }
    Ok(None)
}

pub(crate) fn verify_peer_domain(
    state: &AppState,
    certificates: &[CertificateDer<'static>],
    domain: &str,
) -> Result<Option<XmppCertificateIdentity>> {
    if !verify_peer_certificate_chain(state, certificates)? {
        return Ok(None);
    }
    let Some(end_entity) = certificates.first() else {
        return Ok(None);
    };
    verify_peer_xmpp_identity(end_entity, domain)
}

fn decode_explicit_string(encoded: &[u8], string_tag: Tag) -> Option<&str> {
    let (remaining, explicit) = Any::from_der(encoded).ok()?;
    if !remaining.is_empty()
        || explicit.class() != Class::ContextSpecific
        || explicit.tag() != Tag(0)
        || !explicit.header.constructed()
    {
        return None;
    }
    let (remaining, value) = Any::from_der(explicit.data).ok()?;
    if !remaining.is_empty()
        || value.class() != Class::Universal
        || value.tag() != string_tag
        || value.header.constructed()
    {
        return None;
    }
    std::str::from_utf8(value.data).ok()
}

fn dns_id_matches(presented: &str, reference: &str) -> bool {
    let Ok(reference) = prepare_domainpart(reference) else {
        return false;
    };
    if !presented.is_ascii()
        || reference.parse::<Ipv4Addr>().is_ok()
        || reference
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .is_some_and(|value| value.parse::<Ipv6Addr>().is_ok())
    {
        return false;
    }
    if let Some(suffix) = presented.strip_prefix("*.") {
        if suffix.contains('*') {
            return false;
        }
        let Ok(suffix) = prepare_domainpart(suffix) else {
            return false;
        };
        let Some(prefix) = reference.strip_suffix(&format!(".{suffix}")) else {
            return false;
        };
        !prefix.is_empty() && !prefix.contains('.')
    } else {
        !presented.contains('*')
            && prepare_domainpart(presented).is_ok_and(|presented| presented == reference)
    }
}

fn srv_id_matches(presented: &str, reference: &str) -> bool {
    if !presented.is_ascii() {
        return false;
    }
    let Some((service, domain)) = presented.split_once('.') else {
        return false;
    };
    service.eq_ignore_ascii_case(XMPP_SERVER_SERVICE) && dns_id_matches(domain, reference)
}

fn xmpp_addr_matches(presented: &str, reference: &str) -> bool {
    !presented.contains(['@', '/', '*'])
        && prepare_domainpart(presented).is_ok_and(|presented| presented == reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_crl_policy_cannot_be_bypassed_by_a_pin() {
        assert!(!pin_fallback_permitted(true));
        assert!(pin_fallback_permitted(false));
    }

    #[test]
    fn dns_id_matching_is_idna_aware_and_wildcards_match_one_label() {
        assert!(dns_id_matches(
            "xn--bcher-kva.example",
            "B\u{fc}CHER.Example."
        ));
        assert!(dns_id_matches("*.example.test", "chat.example.test"));
        assert!(!dns_id_matches("*.example.test", "example.test"));
        assert!(!dns_id_matches("*.example.test", "a.b.example.test"));
        assert!(!dns_id_matches("chat*.example.test", "chat1.example.test"));
        assert!(!dns_id_matches("*.*.example.test", "a.b.example.test"));
        assert!(!dns_id_matches("127.0.0.1", "127.0.0.1"));
        assert!(!dns_id_matches(
            "b\u{fc}cher.example",
            "b\u{fc}cher.example"
        ));
    }

    #[test]
    fn srv_id_requires_the_xmpp_server_service_and_reference_domain() {
        assert!(srv_id_matches(
            "_XMPP-SERVER.xn--bcher-kva.example",
            "b\u{fc}cher.example"
        ));
        assert!(srv_id_matches(
            "_xmpp-server.*.example.test",
            "chat.example.test"
        ));
        assert!(!srv_id_matches("_xmpp-client.example.test", "example.test"));
        assert!(!srv_id_matches("_xmpp-server.evil.test", "example.test"));
    }

    #[test]
    fn xmpp_addr_accepts_only_a_canonicalizable_domainpart() {
        assert!(xmpp_addr_matches("B\u{fc}CHER.example.", "bücher.example"));
        for invalid in [
            "alice@example.test",
            "example.test/resource",
            "*.example.test",
            "evil.test",
        ] {
            assert!(!xmpp_addr_matches(invalid, "example.test"));
        }
    }

    #[test]
    fn other_name_string_decoder_enforces_explicit_der_and_string_type() {
        let xmpp = b"\xa0\x0e\x0c\x0cexample.test";
        let srv = b"\xa0\x1b\x16\x19_xmpp-server.example.test";
        assert_eq!(
            decode_explicit_string(xmpp, Tag::Utf8String),
            Some("example.test")
        );
        assert_eq!(
            decode_explicit_string(srv, Tag::Ia5String),
            Some("_xmpp-server.example.test")
        );
        assert!(decode_explicit_string(xmpp, Tag::Ia5String).is_none());
        assert!(decode_explicit_string(&xmpp[1..], Tag::Utf8String).is_none());
        assert!(
            decode_explicit_string(b"\xa0\x0e\x0c\x0cexample.test\x00", Tag::Utf8String).is_none()
        );
    }

    #[test]
    #[ignore = "set TEST_XMPP_IDENTITY_CERT_PATH, TEST_XMPP_IDENTITY_DOMAIN, and TEST_XMPP_IDENTITY_KIND"]
    fn parses_a_real_x509_xmpp_identity_certificate() {
        use tokio_rustls::rustls::pki_types::pem::PemObject;

        let path = std::env::var("TEST_XMPP_IDENTITY_CERT_PATH").expect("certificate path");
        let domain = std::env::var("TEST_XMPP_IDENTITY_DOMAIN").expect("reference domain");
        let expected = match std::env::var("TEST_XMPP_IDENTITY_KIND")
            .expect("identity kind")
            .as_str()
        {
            "dns" => XmppCertificateIdentity::DnsId,
            "srv" => XmppCertificateIdentity::SrvId,
            "xmpp" => XmppCertificateIdentity::XmppAddr,
            other => panic!("unknown identity kind {other}"),
        };
        let certificate = CertificateDer::from_pem_file(path).expect("valid PEM certificate");
        assert_eq!(
            verify_peer_xmpp_identity(&certificate, &domain).unwrap(),
            Some(expected)
        );
        assert_eq!(
            verify_peer_xmpp_identity(&certificate, "wrong.example").unwrap(),
            None
        );
    }
}
