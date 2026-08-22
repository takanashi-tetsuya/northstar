use crate::state::AppState;
use crate::tls::{certificate_chain, private_key};
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::RootCertStore;

use super::*;

pub(crate) fn s2s_client_config(
    state: &AppState,
) -> Result<Arc<tokio_rustls::rustls::ClientConfig>> {
    let roots = root_store(state)?;
    let chain = tls::certificate_chain(&state.config.tls_cert_path)?;
    let key = tls::private_key(&state.config.tls_key_path)?;
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .context("invalid S2S client certificate")?;
    Ok(Arc::new(config))
}

pub(crate) fn s2s_server_config(
    state: &AppState,
) -> Result<Arc<tokio_rustls::rustls::ServerConfig>> {
    let chain = tls::certificate_chain(&state.config.tls_cert_path)?;
    let key = tls::private_key(&state.config.tls_key_path)?;
    let verifier = Arc::new(PresentedServerCertificate::new());
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .context("invalid S2S server certificate")?;
    Ok(Arc::new(config))
}

pub(crate) fn root_store(state: &AppState) -> Result<RootCertStore> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = &state.config.federation_extra_root_cert_path {
        for certificate in tls::certificate_chain(path)? {
            roots
                .add(certificate)
                .context("invalid extra federation trust root")?;
        }
    }
    Ok(roots)
}

pub(crate) fn verify_peer_domain(
    state: &AppState,
    certificates: &[CertificateDer<'static>],
    domain: &str,
) -> Result<bool> {
    let Some(end_entity) = certificates.first() else {
        return Ok(false);
    };
    let verifier =
        tokio_rustls::rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store(state)?))
            .build()
            .context("could not build federation certificate verifier")?;
    let server_name = ServerName::try_from(domain.to_owned()).context("invalid peer domain")?;
    Ok(verifier
        .verify_server_cert(
            end_entity,
            &certificates[1..],
            &server_name,
            &[],
            UnixTime::now(),
        )
        .is_ok())
}

use tokio_rustls::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

#[derive(Debug)]
pub(crate) struct PresentedServerCertificate {
    algorithms: tokio_rustls::rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PresentedServerCertificate {
    pub(crate) fn new() -> Self {
        Self {
            algorithms: tokio_rustls::rustls::crypto::ring::default_provider()
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
    ) -> Result<ClientCertVerified, tokio_rustls::rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
