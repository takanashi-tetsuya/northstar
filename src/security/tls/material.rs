//! Construct trust stores, certificate verifiers, rustls configurations, and immutable TLS material.

use super::*;

pub(super) fn crypto_provider() -> Arc<tokio_rustls::rustls::crypto::CryptoProvider> {
    Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider())
}

pub(super) fn federation_root_store(extra_root_path: Option<&Path>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = extra_root_path {
        for certificate in certificate_chain(path)? {
            validate_extra_trust_anchor(certificate.as_ref())?;
            roots
                .add(certificate)
                .context("invalid extra federation trust root")?;
        }
    }
    Ok(roots)
}

pub(super) fn c2s_client_verifier(
    trust_root_path: Option<&Path>,
    crls: Option<&crate::security::crl::CrlSet>,
) -> Result<ClientVerifierAndRoots> {
    let Some(path) = trust_root_path else {
        return Ok((None, None));
    };
    let mut roots = RootCertStore::empty();
    for certificate in certificate_chain(path)? {
        validate_extra_trust_anchor(certificate.as_ref())?;
        roots
            .add(certificate)
            .context("invalid C2S client trust root")?;
    }
    if roots.is_empty() {
        anyhow::bail!("C2S client trust-root bundle is empty");
    }
    let roots = Arc::new(roots);
    let mut builder =
        WebPkiClientVerifier::builder_with_provider(Arc::clone(&roots), crypto_provider());
    if let Some(crls) = crls {
        builder = builder
            .with_crls(crls.encoded())
            .enforce_revocation_expiration();
    }
    let verifier = builder
        .allow_unauthenticated()
        .build()
        .context("could not build C2S client certificate verifier")?;
    Ok((Some(verifier), Some(roots)))
}

pub(super) fn crl_set(
    path: Option<&Path>,
    label: &str,
) -> Result<Option<Arc<crate::security::crl::CrlSet>>> {
    path.map(|path| {
        let bytes = read_stable_regular_file(path, label, MAX_CRL_FILE_BYTES, false)?;
        crate::security::crl::CrlSet::from_pem(&bytes, label).map(Arc::new)
    })
    .transpose()
}

pub(super) struct FreshOcspResolver {
    pub(super) key: Arc<CertifiedKey>,
    pub(super) response: Arc<crate::security::ocsp::ValidatedOcspResponse>,
}

impl std::fmt::Debug for FreshOcspResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("FreshOcspResolver").finish()
    }
}

impl ResolvesServerCert for FreshOcspResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.response.fresh_now().then(|| Arc::clone(&self.key))
    }
}

pub(super) fn server_config(
    chain: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
    ocsp: Option<&Arc<crate::security::ocsp::ValidatedOcspResponse>>,
    alpn: Option<&'static [u8]>,
) -> Result<Arc<ServerConfig>> {
    let builder = ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(TLS_VERSIONS)
        .context("configured TLS versions are not supported by the crypto provider")?;
    let builder = match client_verifier {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };
    let mut config = if let Some(ocsp) = ocsp {
        let mut certified_key =
            CertifiedKey::from_der(chain.to_vec(), key.clone_key(), builder.crypto_provider())
                .context("TLS certificate and private key do not match")?;
        certified_key.ocsp = Some(ocsp.der().to_vec());
        builder.with_cert_resolver(Arc::new(FreshOcspResolver {
            key: Arc::new(certified_key),
            response: Arc::clone(ocsp),
        }))
    } else {
        builder
            .with_single_cert(chain.to_vec(), key.clone_key())
            .context("TLS certificate and private key do not match")?
    };
    config.require_ems = true;
    if ocsp.is_some() {
        // A resumed TLS session can bypass certificate selection entirely.
        // Disable both server-side cache and TLS 1.3 tickets while strict
        // stapling is enabled, so every new connection crosses the expiry gate.
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
    }
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    Ok(Arc::new(config))
}

pub(super) fn client_config(
    chain: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    roots: RootCertStore,
    alpn: Option<&'static [u8]>,
) -> Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(TLS_VERSIONS)
        .context("configured TLS versions are not supported by the crypto provider")?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain.to_vec(), key.clone_key())
        .context("invalid S2S client certificate or private key")?;
    config.require_ems = true;
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    Ok(Arc::new(config))
}

pub(super) struct TlsMaterialInput<'a> {
    pub(super) cert_path: &'a Path,
    pub(super) key_path: &'a Path,
    pub(super) domain: &'a str,
    pub(super) extra_root_path: Option<&'a Path>,
    pub(super) c2s_client_trust_root_path: Option<&'a Path>,
    pub(super) federation_crl_path: Option<&'a Path>,
    pub(super) c2s_client_crl_path: Option<&'a Path>,
    pub(super) ocsp_response_path: Option<&'a Path>,
    pub(super) generation: u64,
}

pub(super) fn tls_material(input: TlsMaterialInput<'_>) -> Result<Arc<TlsMaterial>> {
    let TlsMaterialInput {
        cert_path,
        key_path,
        domain,
        extra_root_path,
        c2s_client_trust_root_path,
        federation_crl_path,
        c2s_client_crl_path,
        ocsp_response_path,
        generation,
    } = input;
    let development = development_certificate_domain(domain);
    let chain = certificate_chain(cert_path)?;
    let key = private_key(key_path, !development)?;
    if development {
        tracing::warn!(
            %domain,
            "development TLS trust policy is active; public-domain deployments require strict key permissions and a trusted certificate chain"
        );
    }
    let roots = federation_root_store(extra_root_path)?;
    let leaf_not_after_unix = validate_server_chain(&chain, domain, &roots)?;
    let tls_server_end_point = tls_server_end_point(
        chain
            .first()
            .expect("certificate_chain rejects an empty chain")
            .as_ref(),
    )?;
    let federation_crls = crl_set(federation_crl_path, "federation CRL file")?;
    let c2s_client_crls = crl_set(c2s_client_crl_path, "C2S client CRL file")?;
    let ocsp = ocsp_response_path
        .map(|path| {
            crate::security::ocsp::ValidatedOcspResponse::from_file(path, &chain).map(Arc::new)
        })
        .transpose()?;
    let s2s_verifier: Arc<dyn ClientCertVerifier> = Arc::new(PresentedServerCertificate::new());
    let (c2s_verifier, c2s_client_roots) =
        c2s_client_verifier(c2s_client_trust_root_path, c2s_client_crls.as_deref())?;

    Ok(Arc::new(TlsMaterial {
        c2s_starttls: server_config(&chain, &key, c2s_verifier.clone(), ocsp.as_ref(), None)?,
        c2s_direct: server_config(
            &chain,
            &key,
            c2s_verifier,
            ocsp.as_ref(),
            Some(b"xmpp-client"),
        )?,
        s2s_starttls: server_config(
            &chain,
            &key,
            Some(Arc::clone(&s2s_verifier)),
            ocsp.as_ref(),
            None,
        )?,
        s2s_direct: server_config(
            &chain,
            &key,
            Some(s2s_verifier),
            ocsp.as_ref(),
            Some(b"xmpp-server"),
        )?,
        s2s_client_starttls: client_config(&chain, &key, roots.clone(), None)?,
        s2s_client_direct: client_config(&chain, &key, roots.clone(), Some(b"xmpp-server"))?,
        federation_roots: Arc::new(roots),
        federation_crls,
        c2s_client_roots,
        c2s_client_crls,
        tls_server_end_point,
        leaf_not_after_unix,
        generation,
    }))
}

/// Accept the peer certificate during the TLS handshake without trusting it
/// as an XMPP identity. SASL EXTERNAL performs PKIX/domain verification after
/// the peer has asserted its XMPP domain. Keeping client certificates optional
/// preserves TLS-protected Dialback interoperability.
#[derive(Debug)]
pub(crate) struct PresentedServerCertificate {
    pub(super) algorithms: tokio_rustls::rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PresentedServerCertificate {
    pub(super) fn new() -> Self {
        Self {
            algorithms: tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for PresentedServerCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, tokio_rustls::rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
