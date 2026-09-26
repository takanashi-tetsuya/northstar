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
    ocsp_staple_required: bool,
}

impl XmppPkixServerVerifier {
    fn new(
        roots: Arc<RootCertStore>,
        public_key_pins: &[[u8; 32]],
        dane_policy: Option<&DanePolicy>,
        crls: Option<Arc<crate::crl::CrlSet>>,
        ocsp_staple_required: bool,
    ) -> Self {
        Self {
            roots,
            algorithms: tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
            public_key_pins: public_key_pins.to_vec(),
            dane_policy: dane_policy.cloned(),
            crls,
            ocsp_staple_required,
        }
    }

    fn verify_pkix(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<(), RustlsError> {
        if let Some(crls) = &self.crls {
            crls.verify_server_chain(
                end_entity,
                intermediates,
                &self.roots,
                now,
                self.algorithms.all,
            )
            .map_err(|error| RustlsError::General(format!("{error:#}")))?;
        } else {
            let parsed = ParsedCertificate::try_from(end_entity)?;
            verify_server_cert_signed_by_trust_anchor(
                &parsed,
                &self.roots,
                intermediates,
                now,
                self.algorithms.all,
            )?;
        }
        if self.ocsp_staple_required {
            let chain = std::iter::once(end_entity.clone())
                .chain(intermediates.iter().cloned())
                .collect::<Vec<_>>();
            crate::ocsp::ValidatedOcspResponse::from_staple(ocsp_response, &chain).map_err(
                |error| RustlsError::General(format!("outbound OCSP staple: {error:#}")),
            )?;
        }
        Ok(())
    }
}

impl ServerCertVerifier for XmppPkixServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
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
                    .verify_pkix(end_entity, intermediates, ocsp_response, now)
                    .map(|()| ServerCertVerified::assertion());
            }
            return Err(RustlsError::General(format!(
                "peer certificate does not match secure TLSA policy {}",
                policy.owner()
            )));
        }
        let pkix = self.verify_pkix(end_entity, intermediates, ocsp_response, now);
        if !pin_fallback_permitted(self.crls.is_some() || self.ocsp_staple_required) {
            // An XEP-0487 pin is an additional discovery credential, not an
            // escape hatch from an explicitly configured CA revocation
            // policy. In particular, CertRevoked (and fail-closed CRL
            // coverage/signature/freshness failures, or a required OCSP
            // staple) must never be replaced by an SPKI pin comparison.
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

fn pin_fallback_permitted(revocation_policy_configured: bool) -> bool {
    !revocation_policy_configured
}

pub(crate) fn s2s_client_config(
    state: &AppState,
    direct_tls: bool,
    public_key_pins: &[[u8; 32]],
    dane_policy: Option<&DanePolicy>,
) -> Result<(Arc<tokio_rustls::rustls::ClientConfig>, u64)> {
    let material = state.tls_context().federation_snapshot();
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
            Arc::clone(&material.roots),
            public_key_pins,
            dane_policy,
            material.crls.clone(),
            state.s2s_ocsp_staple_required(),
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
    let material = state.tls_context().federation_snapshot();
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
    let material = state.tls_context().federation_snapshot();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let mut verifier = tokio_rustls::rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::clone(&material.roots),
        Arc::clone(&provider),
    );
    if let Some(crls) = &material.crls {
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
    let material = state.tls_context().federation_snapshot();
    let algorithms = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .signature_verification_algorithms;
    if let Some(crls) = &material.crls {
        return Ok(crls
            .verify_client_chain(
                end_entity,
                &certificates[1..],
                &material.roots,
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
            &material.roots.roots,
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
    #[ignore = "requires OCSP responses generated by scripts/test-ocsp-stapling.sh"]
    fn generated_outbound_ocsp_profile_checks_exact_status_and_pkix() {
        use std::{fs, path::PathBuf};

        let fixture = PathBuf::from(std::env::var("TEST_OCSP_FIXTURE_DIR").unwrap());
        let certificate = |name: &str| {
            CertificateDer::from(
                openssl::x509::X509::from_pem(&fs::read(fixture.join(name)).unwrap())
                    .unwrap()
                    .to_der()
                    .unwrap(),
            )
        };
        let leaf = certificate("leaf.crt");
        let issuer = certificate("root.crt");
        let mut roots = RootCertStore::empty();
        roots.add(issuer.clone()).unwrap();
        let roots = Arc::new(roots);
        let strict = XmppPkixServerVerifier::new(Arc::clone(&roots), &[], None, None, true);
        let normal = XmppPkixServerVerifier::new(roots, &[], None, None, false);
        let name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();
        let good = fs::read(fixture.join("good.der")).unwrap();
        assert!(strict
            .verify_server_cert(&leaf, std::slice::from_ref(&issuer), &name, &good, now)
            .is_ok());
        assert!(normal
            .verify_server_cert(&leaf, std::slice::from_ref(&issuer), &name, &[], now)
            .is_ok());
        assert!(strict
            .verify_server_cert(&leaf, std::slice::from_ref(&issuer), &name, &[], now)
            .is_err());
        assert!(strict
            .verify_server_cert(&leaf, &[], &name, &good, now)
            .is_err());
        let pin = peer_public_key_pin(&leaf).unwrap();
        let strict_pinned =
            XmppPkixServerVerifier::new(Arc::new(RootCertStore::empty()), &[pin], None, None, true);
        assert!(strict_pinned
            .verify_server_cert(&leaf, std::slice::from_ref(&issuer), &name, &good, now)
            .is_err());
        for response in [
            "too-long.der",
            "revoked.der",
            "unknown.der",
            "wrong-leaf.der",
            "wrong-issuer.der",
            "bad-signature.der",
            "no-next-update.der",
        ] {
            let der = fs::read(fixture.join(response)).unwrap();
            assert!(
                strict
                    .verify_server_cert(&leaf, std::slice::from_ref(&issuer), &name, &der, now)
                    .is_err(),
                "unexpectedly accepted {response}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires OCSP responses generated by scripts/test-ocsp-stapling.sh and loopback sockets"]
    async fn generated_outbound_ocsp_staple_is_required_on_tls12_and_tls13() {
        use crate::tls::{ReloadableTlsConfig, TlsPolicyFiles};
        use std::{fs, path::PathBuf};
        use tokio_rustls::{
            rustls::version::{TLS12, TLS13},
            TlsAcceptor, TlsConnector,
        };

        let fixture = PathBuf::from(std::env::var("TEST_OCSP_FIXTURE_DIR").unwrap());
        let issuer = CertificateDer::from(
            openssl::x509::X509::from_pem(&fs::read(fixture.join("root.crt")).unwrap())
                .unwrap()
                .to_der()
                .unwrap(),
        );
        let mut roots = RootCertStore::empty();
        roots.add(issuer).unwrap();
        let roots = Arc::new(roots);
        for version in [&TLS12, &TLS13] {
            for staple_present in [false, true] {
                let response_path = fixture.join("good.der");
                let server = ReloadableTlsConfig::new(
                    &fixture.join("chain.crt"),
                    &fixture.join("leaf.key"),
                    "localhost",
                    TlsPolicyFiles {
                        ocsp_response: staple_present.then_some(response_path.as_path()),
                        ..TlsPolicyFiles::default()
                    },
                )
                .unwrap();
                let acceptor = TlsAcceptor::from(Arc::clone(&server.current().c2s_starttls));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let provider =
                    Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
                let mut config = ClientConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_root_certificates(roots.as_ref().clone())
                    .with_no_client_auth();
                config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(XmppPkixServerVerifier::new(
                        Arc::clone(&roots),
                        &[],
                        None,
                        None,
                        true,
                    )));
                let connector = TlsConnector::from(Arc::new(config));
                let (client, _) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    tokio::join!(
                        async {
                            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
                            connector
                                .connect(ServerName::try_from("localhost").unwrap(), socket)
                                .await
                        },
                        async {
                            let (socket, _) = listener.accept().await.unwrap();
                            acceptor.accept(socket).await
                        }
                    )
                })
                .await
                .expect("outbound OCSP TLS handshake timed out");
                assert_eq!(
                    client.is_ok(),
                    staple_present,
                    "{version:?} staple={staple_present}: {client:?}"
                );
            }
        }
    }

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
