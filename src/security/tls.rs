use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio_rustls::rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ClientHello, NoServerSessionStorage, ResolvesServerCert, WebPkiClientVerifier,
    },
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    ClientConfig, RootCertStore, ServerConfig,
};
use x509_parser::{
    asn1_rs::{Any, Class, FromDer, Tag},
    extensions::GeneralName,
    prelude::{parse_x509_certificate, X509Version},
    public_key::PublicKey,
    signature_algorithm::SignatureAlgorithm,
};

mod certificates;
mod material;

use self::certificates::{
    decode_explicit_utf8_string, development_certificate_domain, parse_certificate,
    pem_begin_labels, private_key, read_stable_regular_file, tls_server_end_point,
    validate_extra_trust_anchor, validate_server_chain,
};
#[cfg(test)]
use self::certificates::{hashless_certificate_signature, signature_digest_oid};
use self::material::{crypto_provider, tls_material, TlsMaterialInput};

const ID_ON_XMPP_ADDR: &str = "1.3.6.1.5.5.7.8.5";

const MAX_CERTIFICATE_FILE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_FILE_BYTES: u64 = 128 * 1024;
const MAX_CRL_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CERTIFICATES_IN_CHAIN: usize = 8;
const TLS_VERSIONS: &[&tokio_rustls::rustls::SupportedProtocolVersion] = &[&TLS13, &TLS12];

type ClientVerifierAndRoots = (
    Option<Arc<dyn ClientCertVerifier>>,
    Option<Arc<RootCertStore>>,
);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum CertificateSessionKind {
    C2s,
    InboundS2s,
    OutboundS2s,
}

impl CertificateSessionKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::C2s => "c2s_external",
            Self::InboundS2s => "inbound_s2s_external",
            Self::OutboundS2s => "outbound_s2s_external",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RevokedCertificateSession {
    pub connection_id: uuid::Uuid,
    pub kind: CertificateSessionKind,
    pub certificate_issuer: String,
    pub certificate_serial: String,
    pub certificate_sha256: String,
    pub handshake_tls_generation: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CertificateSessionMetrics {
    pub active: u64,
    pub c2s_external: u64,
    pub inbound_s2s_external: u64,
    pub outbound_s2s_external: u64,
}

#[derive(Debug)]
pub(crate) struct TlsReloadOutcome {
    pub previous_generation: u64,
    pub generation: u64,
    pub evaluated_sessions: u64,
    pub sessions_without_applicable_crl: u64,
    pub inconclusive_rechecks: u64,
    pub active_sessions_after_signal: u64,
    pub drained_c2s_external: u64,
    pub drained_inbound_s2s_external: u64,
    pub drained_outbound_s2s_external: u64,
    pub drained_sessions: Vec<RevokedCertificateSession>,
}

impl TlsReloadOutcome {
    pub(crate) fn drained_total(&self) -> u64 {
        self.drained_c2s_external
            .saturating_add(self.drained_inbound_s2s_external)
            .saturating_add(self.drained_outbound_s2s_external)
    }
}

#[derive(Clone)]
struct CertificateSessionEntry {
    registration_id: uuid::Uuid,
    connection_id: uuid::Uuid,
    kind: CertificateSessionKind,
    peer_chain: Vec<CertificateDer<'static>>,
    certificate_issuer: String,
    certificate_serial: String,
    certificate_sha256: String,
    handshake_tls_generation: u64,
    authenticated_at: UnixTime,
    disconnect: tokio_util::sync::CancellationToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveRevocationDecision {
    NotApplicable,
    NotRevoked,
    ExplicitlyRevoked,
    Inconclusive,
}

struct RevocationSweep {
    evaluated: u64,
    without_applicable_crl: u64,
    inconclusive: u64,
    drained: Vec<RevokedCertificateSession>,
}

#[derive(Default)]
struct CertificateSessionRegistry {
    sessions: Mutex<HashMap<uuid::Uuid, CertificateSessionEntry>>,
}

impl CertificateSessionRegistry {
    fn register(
        self: &Arc<Self>,
        connection_id: uuid::Uuid,
        kind: CertificateSessionKind,
        peer_chain: Vec<CertificateDer<'static>>,
        handshake_tls_generation: u64,
        authenticated_at: UnixTime,
        disconnect: tokio_util::sync::CancellationToken,
    ) -> Result<CertificateSessionGuard> {
        anyhow::ensure!(
            !connection_id.is_nil(),
            "certificate session connection ID is nil"
        );
        anyhow::ensure!(
            !disconnect.is_cancelled(),
            "certificate-authenticated connection is already closing"
        );
        anyhow::ensure!(
            !peer_chain.is_empty() && peer_chain.len() <= MAX_CERTIFICATES_IN_CHAIN,
            "certificate-authenticated peer chain is empty or exceeds its certificate limit"
        );
        let peer_chain_bytes = peer_chain.iter().try_fold(0_u64, |total, certificate| {
            total.checked_add(certificate.as_ref().len() as u64)
        });
        anyhow::ensure!(
            peer_chain_bytes.is_some_and(|bytes| bytes <= MAX_CERTIFICATE_FILE_BYTES),
            "certificate-authenticated peer chain exceeds its encoded size limit"
        );
        let leaf = peer_chain
            .first()
            .context("certificate-authenticated session has no peer certificate")?;
        let certificate = parse_certificate(leaf.as_ref())?;
        let certificate_issuer = bounded_log_metadata(&certificate.issuer().to_string(), 1_024);
        let certificate_serial = bounded_log_metadata(&certificate.raw_serial_as_string(), 128);
        let certificate_sha256 = hex_lower(&Sha256::digest(leaf.as_ref()));
        let registration_id = uuid::Uuid::new_v4();
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        anyhow::ensure!(
            !sessions.contains_key(&connection_id),
            "certificate session connection ID is already registered"
        );
        sessions.insert(
            connection_id,
            CertificateSessionEntry {
                registration_id,
                connection_id,
                kind,
                peer_chain,
                certificate_issuer,
                certificate_serial,
                certificate_sha256,
                handshake_tls_generation,
                authenticated_at,
                disconnect,
            },
        );
        Ok(CertificateSessionGuard {
            registry: Arc::clone(self),
            connection_id,
            registration_id,
        })
    }

    fn unregister(&self, connection_id: uuid::Uuid, registration_id: uuid::Uuid) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if sessions
            .get(&connection_id)
            .is_some_and(|entry| entry.registration_id == registration_id)
        {
            sessions.remove(&connection_id);
        }
    }

    fn signal_snapshot_if_current(&self, snapshot: &CertificateSessionEntry) -> bool {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(current) = sessions.get(&snapshot.connection_id) else {
            return false;
        };
        if current.registration_id != snapshot.registration_id || current.disconnect.is_cancelled()
        {
            return false;
        }
        current.disconnect.cancel();
        true
    }

    fn metrics(&self) -> CertificateSessionMetrics {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut metrics = CertificateSessionMetrics {
            active: sessions.len().try_into().unwrap_or(u64::MAX),
            ..CertificateSessionMetrics::default()
        };
        for entry in sessions.values() {
            match entry.kind {
                CertificateSessionKind::C2s => {
                    metrics.c2s_external = metrics.c2s_external.saturating_add(1)
                }
                CertificateSessionKind::InboundS2s => {
                    metrics.inbound_s2s_external = metrics.inbound_s2s_external.saturating_add(1)
                }
                CertificateSessionKind::OutboundS2s => {
                    metrics.outbound_s2s_external = metrics.outbound_s2s_external.saturating_add(1)
                }
            }
        }
        metrics
    }

    fn drain_explicitly_revoked(&self, material: &TlsMaterial) -> RevocationSweep {
        // Chain validation is deliberately performed outside the registry
        // mutex. A 1000-session reload may require substantial public-key
        // work; holding a synchronous mutex across that work would block
        // unrelated connection teardown on Tokio workers.
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut sweep = RevocationSweep {
            evaluated: sessions.len().try_into().unwrap_or(u64::MAX),
            without_applicable_crl: 0,
            inconclusive: 0,
            drained: Vec::new(),
        };
        for entry in sessions {
            match material.revocation_decision(&entry) {
                LiveRevocationDecision::NotApplicable => {
                    sweep.without_applicable_crl = sweep.without_applicable_crl.saturating_add(1);
                }
                LiveRevocationDecision::NotRevoked => {}
                LiveRevocationDecision::Inconclusive => {
                    sweep.inconclusive = sweep.inconclusive.saturating_add(1);
                }
                LiveRevocationDecision::ExplicitlyRevoked if !entry.disconnect.is_cancelled() => {
                    // The connection may have closed while its chain was being
                    // evaluated. Re-check exact registration ownership under
                    // the mutex so an obsolete snapshot cannot be counted or
                    // affect a hypothetical reused connection UUID.
                    if !self.signal_snapshot_if_current(&entry) {
                        continue;
                    }
                    sweep.drained.push(RevokedCertificateSession {
                        connection_id: entry.connection_id,
                        kind: entry.kind,
                        certificate_issuer: entry.certificate_issuer.clone(),
                        certificate_serial: entry.certificate_serial.clone(),
                        certificate_sha256: entry.certificate_sha256.clone(),
                        handshake_tls_generation: entry.handshake_tls_generation,
                    });
                }
                LiveRevocationDecision::ExplicitlyRevoked => {}
            }
        }
        sweep
    }

    #[cfg(test)]
    fn cancel_matching(
        &self,
        mut matches: impl FnMut(&CertificateSessionEntry) -> bool,
    ) -> (u64, Vec<RevokedCertificateSession>) {
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let evaluated = sessions.len().try_into().unwrap_or(u64::MAX);
        let mut drained = Vec::new();
        for entry in sessions.values() {
            if entry.disconnect.is_cancelled() || !matches(entry) {
                continue;
            }
            entry.disconnect.cancel();
            drained.push(RevokedCertificateSession {
                connection_id: entry.connection_id,
                kind: entry.kind,
                certificate_issuer: entry.certificate_issuer.clone(),
                certificate_serial: entry.certificate_serial.clone(),
                certificate_sha256: entry.certificate_sha256.clone(),
                handshake_tls_generation: entry.handshake_tls_generation,
            });
        }
        (evaluated, drained)
    }
}

/// Exact registration ownership prevents a late Drop from unregistering a
/// hypothetical later connection which reused the same external ID.
pub(crate) struct CertificateSessionGuard {
    registry: Arc<CertificateSessionRegistry>,
    connection_id: uuid::Uuid,
    registration_id: uuid::Uuid,
}

impl Drop for CertificateSessionGuard {
    fn drop(&mut self) {
        self.registry
            .unregister(self.connection_id, self.registration_id);
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn bounded_log_metadata(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .flat_map(char::escape_default)
        .take(max_chars)
        .collect()
}

/// XEP-0368 requires the initiating entity to send the JID domain as SNI on
/// Direct TLS. STARTTLS has no equivalent TLS-layer name signal and therefore
/// must not call this helper.
pub(crate) fn direct_tls_sni_matches(presented: Option<&str>, expected_domain: &str) -> bool {
    matches!(
        (
            presented.and_then(|name| crate::jid::domain_to_ascii(name).ok()),
            crate::jid::domain_to_ascii(expected_domain),
        ),
        (Some(presented), Ok(expected)) if presented == expected
    )
}

pub fn certificate_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = read_stable_regular_file(
        path,
        "TLS certificate file",
        MAX_CERTIFICATE_FILE_BYTES,
        false,
    )?;
    let pem = std::str::from_utf8(&bytes).context("TLS certificate file is not UTF-8 PEM")?;
    let labels = pem_begin_labels(pem).collect::<Vec<_>>();
    if labels.is_empty() || labels.iter().any(|label| *label != "CERTIFICATE") {
        anyhow::bail!("TLS certificate file must contain only CERTIFICATE PEM blocks");
    }
    let chain = CertificateDer::pem_slice_iter(&bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid TLS certificate PEM")?;
    if chain.is_empty() || chain.len() != labels.len() {
        anyhow::bail!("TLS certificate file contains malformed or unsupported PEM blocks");
    }
    if chain.len() > MAX_CERTIFICATES_IN_CHAIN {
        anyhow::bail!("TLS certificate chain exceeds {MAX_CERTIFICATES_IN_CHAIN} certificates");
    }
    for (index, certificate) in chain.iter().enumerate() {
        if chain[..index]
            .iter()
            .any(|previous| previous.as_ref() == certificate.as_ref())
        {
            anyhow::bail!("TLS certificate chain contains a duplicate certificate");
        }
    }
    Ok(chain)
}

/// Extract C2S identities only from id-on-xmppAddr subjectAltName entries.
/// PKIX and clientAuth EKU validation have already happened in rustls; CN,
/// DNS-ID and unqualified localparts are intentionally never fallbacks.
pub(crate) fn c2s_client_xmpp_identities(
    certificates: &[CertificateDer<'_>],
    domain: &str,
) -> Result<Vec<String>> {
    let Some(leaf) = certificates.first() else {
        return Ok(Vec::new());
    };
    let certificate = parse_certificate(leaf.as_ref())?;
    let Some(san) = certificate
        .subject_alternative_name()
        .context("invalid C2S client subjectAltName extension")?
    else {
        return Ok(Vec::new());
    };
    let domain = crate::jid::prepare_domainpart(domain)?;
    let mut identities = Vec::new();
    for name in &san.value.general_names {
        let GeneralName::OtherName(oid, encoded) = name else {
            continue;
        };
        if oid.to_id_string() != ID_ON_XMPP_ADDR {
            continue;
        }
        let value = decode_explicit_utf8_string(encoded)
            .context("malformed id-on-xmppAddr C2S client identity")?;
        let jid = crate::jid::CanonicalJid::parse_bare(value)
            .context("invalid id-on-xmppAddr C2S client identity")?;
        if jid.domainpart() == domain && jid.localpart().is_some() {
            let canonical = jid.to_string();
            if !identities.contains(&canonical) {
                identities.push(canonical);
            }
        }
    }
    Ok(identities)
}

pub struct TlsMaterial {
    pub c2s_starttls: Arc<ServerConfig>,
    pub c2s_direct: Arc<ServerConfig>,
    pub s2s_starttls: Arc<ServerConfig>,
    pub s2s_direct: Arc<ServerConfig>,
    pub s2s_client_starttls: Arc<ClientConfig>,
    pub s2s_client_direct: Arc<ClientConfig>,
    pub federation_roots: Arc<RootCertStore>,
    pub federation_crls: Option<Arc<crate::security::crl::CrlSet>>,
    /// Retained solely for exact re-evaluation of already authenticated C2S
    /// EXTERNAL sessions after a local CRL snapshot changes.
    c2s_client_roots: Option<Arc<RootCertStore>>,
    c2s_client_crls: Option<Arc<crate::security::crl::CrlSet>>,
    /// RFC 5929 endpoint binding is absent for hashless certificate signature
    /// algorithms such as Ed25519.  TLS trust and every non-endpoint binding
    /// remain usable in that case.
    pub tls_server_end_point: Option<Vec<u8>>,
    pub leaf_not_after_unix: i64,
    pub generation: u64,
}

impl TlsMaterial {
    fn revocation_decision_with_role(
        crls: &crate::security::crl::CrlSet,
        roots: &RootCertStore,
        session: &CertificateSessionEntry,
        server_role: bool,
    ) -> LiveRevocationDecision {
        let Some(end_entity) = session.peer_chain.first() else {
            return LiveRevocationDecision::Inconclusive;
        };
        let intermediates = &session.peer_chain[1..];
        let algorithms = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms;
        let recheck = |time| {
            if server_role {
                crls.recheck_server_chain(end_entity, intermediates, roots, time, algorithms.all)
            } else {
                crls.recheck_client_chain(end_entity, intermediates, roots, time, algorithms.all)
            }
        };
        let now = UnixTime::now();
        let current = recheck(now);
        match current {
            crate::security::crl::RevocationRecheck::Valid => LiveRevocationDecision::NotRevoked,
            crate::security::crl::RevocationRecheck::ExplicitlyRevoked => {
                LiveRevocationDecision::ExplicitlyRevoked
            }
            crate::security::crl::RevocationRecheck::OtherValidationFailure
                if crls.is_fresh_at(now) =>
            {
                match recheck(session.authenticated_at) {
                    crate::security::crl::RevocationRecheck::Valid => {
                        LiveRevocationDecision::NotRevoked
                    }
                    crate::security::crl::RevocationRecheck::ExplicitlyRevoked => {
                        LiveRevocationDecision::ExplicitlyRevoked
                    }
                    crate::security::crl::RevocationRecheck::OtherValidationFailure => {
                        LiveRevocationDecision::Inconclusive
                    }
                }
            }
            crate::security::crl::RevocationRecheck::OtherValidationFailure => {
                LiveRevocationDecision::Inconclusive
            }
        }
    }

    fn revocation_decision(&self, session: &CertificateSessionEntry) -> LiveRevocationDecision {
        match session.kind {
            CertificateSessionKind::C2s => {
                let (Some(crls), Some(roots)) = (&self.c2s_client_crls, &self.c2s_client_roots)
                else {
                    return LiveRevocationDecision::NotApplicable;
                };
                Self::revocation_decision_with_role(crls.as_ref(), roots.as_ref(), session, false)
            }
            CertificateSessionKind::InboundS2s => {
                let Some(crls) = &self.federation_crls else {
                    return LiveRevocationDecision::NotApplicable;
                };
                Self::revocation_decision_with_role(
                    crls.as_ref(),
                    self.federation_roots.as_ref(),
                    session,
                    false,
                )
            }
            CertificateSessionKind::OutboundS2s => {
                let Some(crls) = &self.federation_crls else {
                    return LiveRevocationDecision::NotApplicable;
                };
                Self::revocation_decision_with_role(
                    crls.as_ref(),
                    self.federation_roots.as_ref(),
                    session,
                    true,
                )
            }
        }
    }
}

/// TLS-only authority shared by serving, federation and the reload worker.
/// Callers receive one immutable snapshot per handshake, never the mutable
/// reload manager or unrelated application state.
#[derive(Clone)]
pub(crate) struct TlsContext {
    reloadable: Arc<ReloadableTlsConfig>,
}

/// Metrics-only TLS view; no handshake material, private key, session
/// registration, or reload capability is available to the HTTP endpoint.
#[derive(Clone)]
pub(crate) struct TlsMetricsProbe {
    reloadable: Arc<ReloadableTlsConfig>,
}

impl TlsMetricsProbe {
    pub(crate) fn leaf_status(&self) -> (i64, u64) {
        let material = self.reloadable.current();
        (material.leaf_not_after_unix, material.generation)
    }

    pub(crate) fn certificate_session_metrics(&self) -> CertificateSessionMetrics {
        self.reloadable.certificate_session_metrics()
    }
}

pub(crate) struct C2sTlsSnapshot {
    pub server_config: Arc<ServerConfig>,
    pub tls_server_end_point: Option<Vec<u8>>,
    pub generation: u64,
}

pub(crate) struct FederationTlsSnapshot {
    pub s2s_starttls: Arc<ServerConfig>,
    pub s2s_direct: Arc<ServerConfig>,
    pub s2s_client_starttls: Arc<ClientConfig>,
    pub s2s_client_direct: Arc<ClientConfig>,
    pub roots: Arc<RootCertStore>,
    pub crls: Option<Arc<crate::security::crl::CrlSet>>,
    pub generation: u64,
}

impl TlsContext {
    pub(crate) fn new(reloadable: Arc<ReloadableTlsConfig>) -> Self {
        Self { reloadable }
    }

    pub(crate) fn metrics_probe(&self) -> TlsMetricsProbe {
        TlsMetricsProbe {
            reloadable: Arc::clone(&self.reloadable),
        }
    }

    pub(crate) fn c2s_snapshot(&self, direct_tls: bool) -> C2sTlsSnapshot {
        let material = self.reloadable.current();
        C2sTlsSnapshot {
            server_config: if direct_tls {
                Arc::clone(&material.c2s_direct)
            } else {
                Arc::clone(&material.c2s_starttls)
            },
            tls_server_end_point: material.tls_server_end_point.clone(),
            generation: material.generation,
        }
    }

    pub(crate) fn federation_snapshot(&self) -> FederationTlsSnapshot {
        let material = self.reloadable.current();
        FederationTlsSnapshot {
            s2s_starttls: Arc::clone(&material.s2s_starttls),
            s2s_direct: Arc::clone(&material.s2s_direct),
            s2s_client_starttls: Arc::clone(&material.s2s_client_starttls),
            s2s_client_direct: Arc::clone(&material.s2s_client_direct),
            roots: Arc::clone(&material.federation_roots),
            crls: material.federation_crls.clone(),
            generation: material.generation,
        }
    }

    pub(crate) fn register_certificate_session(
        &self,
        connection_id: uuid::Uuid,
        kind: CertificateSessionKind,
        peer_chain: Vec<CertificateDer<'static>>,
        handshake_tls_generation: u64,
        disconnect: tokio_util::sync::CancellationToken,
    ) -> Result<CertificateSessionGuard> {
        self.reloadable.register_certificate_session(
            connection_id,
            kind,
            peer_chain,
            handshake_tls_generation,
            disconnect,
        )
    }

    pub(crate) fn reload(&self) -> Result<TlsReloadOutcome> {
        self.reloadable.reload()
    }
}

pub struct ReloadableTlsConfig {
    material: ArcSwap<TlsMaterial>,
    cert_path: PathBuf,
    key_path: PathBuf,
    domain: String,
    extra_root_path: Option<PathBuf>,
    c2s_client_trust_root_path: Option<PathBuf>,
    federation_crl_path: Option<PathBuf>,
    c2s_client_crl_path: Option<PathBuf>,
    ocsp_response_path: Option<PathBuf>,
    reload_lock: Mutex<()>,
    activation_lock: Mutex<()>,
    certificate_sessions: Arc<CertificateSessionRegistry>,
}

#[derive(Default)]
pub struct TlsPolicyFiles<'a> {
    pub extra_root: Option<&'a Path>,
    pub c2s_client_trust_root: Option<&'a Path>,
    pub federation_crl: Option<&'a Path>,
    pub c2s_client_crl: Option<&'a Path>,
    pub ocsp_response: Option<&'a Path>,
}

impl ReloadableTlsConfig {
    pub fn new(
        cert_path: &Path,
        key_path: &Path,
        domain: &str,
        files: TlsPolicyFiles<'_>,
    ) -> Result<Arc<Self>> {
        let TlsPolicyFiles {
            extra_root: extra_root_path,
            c2s_client_trust_root: c2s_client_trust_root_path,
            federation_crl: federation_crl_path,
            c2s_client_crl: c2s_client_crl_path,
            ocsp_response: ocsp_response_path,
        } = files;
        let material = tls_material(TlsMaterialInput {
            cert_path,
            key_path,
            domain,
            extra_root_path,
            c2s_client_trust_root_path,
            federation_crl_path,
            c2s_client_crl_path,
            ocsp_response_path,
            generation: 1,
        })?;
        Ok(Arc::new(Self {
            material: ArcSwap::new(material),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            domain: domain.to_owned(),
            extra_root_path: extra_root_path.map(Path::to_path_buf),
            c2s_client_trust_root_path: c2s_client_trust_root_path.map(Path::to_path_buf),
            federation_crl_path: federation_crl_path.map(Path::to_path_buf),
            c2s_client_crl_path: c2s_client_crl_path.map(Path::to_path_buf),
            ocsp_response_path: ocsp_response_path.map(Path::to_path_buf),
            reload_lock: Mutex::new(()),
            activation_lock: Mutex::new(()),
            certificate_sessions: Arc::new(CertificateSessionRegistry::default()),
        }))
    }

    pub fn current(&self) -> Arc<TlsMaterial> {
        self.material.load_full()
    }

    pub(crate) fn certificate_session_metrics(&self) -> CertificateSessionMetrics {
        self.certificate_sessions.metrics()
    }

    pub(crate) fn register_certificate_session(
        self: &Arc<Self>,
        connection_id: uuid::Uuid,
        kind: CertificateSessionKind,
        peer_chain: Vec<CertificateDer<'static>>,
        handshake_tls_generation: u64,
        disconnect: tokio_util::sync::CancellationToken,
    ) -> Result<CertificateSessionGuard> {
        // Serialize only the activation/registration edge, never reload file
        // I/O or the later registry sweep. This closes the register-vs-reload
        // gap: a post-activation registration evaluates the new material for
        // itself, while pre-activation entries belong to the sweep.
        let _activation = self
            .activation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("TLS activation lock is poisoned"))?;
        let current = self.current();
        let authenticated_at = UnixTime::now();
        anyhow::ensure!(
            !peer_chain.is_empty(),
            "certificate-authenticated session has no peer certificate"
        );
        let probe = CertificateSessionEntry {
            registration_id: uuid::Uuid::nil(),
            connection_id,
            kind,
            peer_chain: peer_chain.clone(),
            certificate_issuer: String::new(),
            certificate_serial: String::new(),
            certificate_sha256: String::new(),
            handshake_tls_generation,
            authenticated_at,
            disconnect: disconnect.clone(),
        };
        anyhow::ensure!(
            current.revocation_decision(&probe) != LiveRevocationDecision::ExplicitlyRevoked,
            "peer certificate is explicitly revoked by the active CRL snapshot"
        );
        self.certificate_sessions.register(
            connection_id,
            kind,
            peer_chain,
            handshake_tls_generation,
            authenticated_at,
            disconnect,
        )
    }

    pub(crate) fn reload(&self) -> Result<TlsReloadOutcome> {
        let _guard = self
            .reload_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("TLS reload lock is poisoned"))?;
        let new_material = tls_material(TlsMaterialInput {
            cert_path: &self.cert_path,
            key_path: &self.key_path,
            domain: &self.domain,
            extra_root_path: self.extra_root_path.as_deref(),
            c2s_client_trust_root_path: self.c2s_client_trust_root_path.as_deref(),
            federation_crl_path: self.federation_crl_path.as_deref(),
            c2s_client_crl_path: self.c2s_client_crl_path.as_deref(),
            ocsp_response_path: self.ocsp_response_path.as_deref(),
            generation: self
                .current()
                .generation
                .checked_add(1)
                .context("TLS generation counter overflow")?,
        })?;
        let not_after = new_material.leaf_not_after_unix;
        let activation = self
            .activation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("TLS activation lock is poisoned"))?;
        let previous_generation = self.current().generation;
        let generation = new_material.generation;
        self.material.store(Arc::clone(&new_material));
        // Registration after this point observes and evaluates the new
        // snapshot itself, so it does not belong to the pre-activation sweep.
        // Release the edge lock before the public-key work below.
        drop(activation);
        let sweep = self
            .certificate_sessions
            .drain_explicitly_revoked(&new_material);
        let mut drained_c2s_external = 0_u64;
        let mut drained_inbound_s2s_external = 0_u64;
        let mut drained_outbound_s2s_external = 0_u64;
        for session in &sweep.drained {
            match session.kind {
                CertificateSessionKind::C2s => {
                    drained_c2s_external = drained_c2s_external.saturating_add(1)
                }
                CertificateSessionKind::InboundS2s => {
                    drained_inbound_s2s_external = drained_inbound_s2s_external.saturating_add(1)
                }
                CertificateSessionKind::OutboundS2s => {
                    drained_outbound_s2s_external = drained_outbound_s2s_external.saturating_add(1)
                }
            }
        }
        let active_sessions_after_signal = self.certificate_sessions.metrics().active;
        tracing::info!(
            not_after_unix = not_after,
            previous_generation,
            generation,
            evaluated_sessions = sweep.evaluated,
            sessions_without_applicable_crl = sweep.without_applicable_crl,
            inconclusive_rechecks = sweep.inconclusive,
            drained_sessions = sweep.drained.len(),
            "TLS material reloaded atomically and active certificate sessions re-evaluated"
        );
        Ok(TlsReloadOutcome {
            previous_generation,
            generation,
            evaluated_sessions: sweep.evaluated,
            sessions_without_applicable_crl: sweep.without_applicable_crl,
            inconclusive_rechecks: sweep.inconclusive,
            active_sessions_after_signal,
            drained_c2s_external,
            drained_inbound_s2s_external,
            drained_outbound_s2s_external,
            drained_sessions: sweep.drained,
        })
    }
}

#[cfg(test)]
mod tests;
