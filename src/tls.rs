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
        WebPkiClientVerifier,
    },
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

fn crypto_provider() -> Arc<tokio_rustls::rustls::crypto::CryptoProvider> {
    Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider())
}

fn read_stable_regular_file(
    path: &Path,
    label: &str,
    max_bytes: u64,
    enforce_private_permissions: bool,
) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        anyhow::bail!("{label} must be a regular file and not a symbolic link");
    }
    if before.len() == 0 || before.len() > max_bytes {
        anyhow::bail!("{label} is empty or exceeds its size limit");
    }
    if enforce_private_permissions {
        validate_private_file_permissions(&before, label)?;
    } else {
        validate_public_file_permissions(&before, label)?;
    }

    // Keep one descriptor from validation through the bounded read. On Unix,
    // O_NOFOLLOW also closes the lstat/open race instead of briefly following
    // an attacker-controlled replacement symlink.
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot open {label} {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("cannot inspect opened {label} {}", path.display()))?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > max_bytes {
        anyhow::bail!("{label} is not a regular file or exceeds its size limit");
    }
    validate_same_file(&before, &opened, label)?;
    if enforce_private_permissions {
        validate_private_file_permissions(&opened, label)?;
    } else {
        validate_public_file_permissions(&opened, label)?;
    }

    let capacity = usize::try_from(opened.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity.min(max_bytes as usize));
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {label} {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        anyhow::bail!("{label} is empty or exceeds its size limit");
    }

    let opened_after = file
        .metadata()
        .with_context(|| format!("cannot re-inspect opened {label} {}", path.display()))?;
    let path_after = fs::symlink_metadata(path)
        .with_context(|| format!("cannot re-inspect {label} {}", path.display()))?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || opened.len() != opened_after.len()
        || opened.modified().ok() != opened_after.modified().ok()
        || opened.len() != bytes.len() as u64
    {
        anyhow::bail!("{label} changed while it was being read; retry after atomic replacement");
    }
    validate_same_file(&opened, &opened_after, label)?;
    validate_same_file(&opened, &path_after, label)?;
    if enforce_private_permissions {
        validate_private_file_permissions(&opened_after, label)?;
        validate_private_file_permissions(&path_after, label)?;
    } else {
        validate_public_file_permissions(&opened_after, label)?;
        validate_public_file_permissions(&path_after, label)?;
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_same_file(before: &fs::Metadata, after: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        anyhow::bail!("{label} changed while it was being read; retry after atomic replacement");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_file(before: &fs::Metadata, after: &fs::Metadata, label: &str) -> Result<()> {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        anyhow::bail!("{label} changed while it was being read; retry after atomic replacement");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file_permissions(metadata: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o400 && mode != 0o600 {
        anyhow::bail!("{label} permissions must be exactly 0400 or 0600 (found {mode:04o})");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_public_file_permissions(metadata: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        anyhow::bail!("{label} must not be group/world writable (found {mode:04o})");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_permissions(_metadata: &fs::Metadata, _label: &str) -> Result<()> {
    // Windows ACLs do not map safely to Unix mode bits. The Linux production
    // preflight performs the authoritative 0400/0600 check.
    Ok(())
}

#[cfg(not(unix))]
fn validate_public_file_permissions(_metadata: &fs::Metadata, _label: &str) -> Result<()> {
    Ok(())
}

fn pem_begin_labels(pem: &str) -> impl Iterator<Item = &str> {
    pem.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("-----BEGIN ")
            .and_then(|line| line.strip_suffix("-----"))
    })
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

fn private_key(path: &Path, enforce_permissions: bool) -> Result<PrivateKeyDer<'static>> {
    let bytes = read_stable_regular_file(
        path,
        "TLS private key",
        MAX_PRIVATE_KEY_FILE_BYTES,
        enforce_permissions,
    )?;
    let pem = std::str::from_utf8(&bytes).context("TLS private key is not UTF-8 PEM")?;
    let labels = pem_begin_labels(pem).collect::<Vec<_>>();
    if labels.len() != 1
        || !matches!(
            labels[0],
            "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY"
        )
    {
        anyhow::bail!("TLS key file must contain exactly one unencrypted private-key PEM block");
    }
    PrivateKeyDer::from_pem_slice(&bytes).context("cannot decode TLS private key")
}

fn federation_root_store(extra_root_path: Option<&Path>) -> Result<RootCertStore> {
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

fn c2s_client_verifier(
    trust_root_path: Option<&Path>,
    crls: Option<&crate::crl::CrlSet>,
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

fn crl_set(path: Option<&Path>, label: &str) -> Result<Option<Arc<crate::crl::CrlSet>>> {
    path.map(|path| {
        let bytes = read_stable_regular_file(path, label, MAX_CRL_FILE_BYTES, false)?;
        crate::crl::CrlSet::from_pem(&bytes, label).map(Arc::new)
    })
    .transpose()
}

fn parse_certificate(der: &[u8]) -> Result<x509_parser::certificate::X509Certificate<'_>> {
    let (remainder, certificate) = parse_x509_certificate(der)
        .map_err(|error| anyhow::anyhow!("cannot parse X.509 certificate: {error}"))?;
    if !remainder.is_empty() {
        anyhow::bail!("X.509 certificate contains trailing DER data");
    }
    certificate
        .extensions_map()
        .context("X.509 certificate contains duplicate extensions")?;
    Ok(certificate)
}

fn decode_explicit_utf8_string(encoded: &[u8]) -> Option<&str> {
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
        || value.tag() != Tag::Utf8String
        || value.header.constructed()
    {
        return None;
    }
    std::str::from_utf8(value.data).ok()
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

fn validate_extra_trust_anchor(der: &[u8]) -> Result<()> {
    let certificate = parse_certificate(der)?;
    if certificate.version != X509Version::V3 || !certificate.validity().is_valid() {
        anyhow::bail!("extra federation trust root must be a currently valid X.509 v3 certificate");
    }
    let constraints = certificate
        .basic_constraints()
        .context("cannot parse extra trust-root basic constraints")?
        .context("extra federation trust root lacks basic constraints")?;
    if !constraints.value.ca {
        anyhow::bail!("extra federation trust root is not a CA certificate");
    }
    let usage = certificate
        .key_usage()
        .context("cannot parse extra trust-root key usage")?
        .context("extra federation trust root lacks key usage")?;
    if !usage.value.key_cert_sign() {
        anyhow::bail!("extra federation trust root cannot sign certificates");
    }
    Ok(())
}

fn development_certificate_domain(domain: &str) -> bool {
    domain == "localhost"
        || domain.ends_with(".localhost")
        || domain == "test"
        || domain.ends_with(".test")
        || domain == "invalid"
        || domain.ends_with(".invalid")
        || domain == "example"
        || domain.ends_with(".example")
        || matches!(domain, "example.com" | "example.net" | "example.org")
}

fn validate_leaf_profile(der: &[u8], permit_self_signed: bool) -> Result<i64> {
    let certificate = parse_certificate(der)?;
    if certificate.version != X509Version::V3 {
        anyhow::bail!("TLS leaf certificate must be X.509 version 3");
    }
    if !certificate.validity().is_valid() {
        anyhow::bail!("TLS leaf certificate is not currently valid");
    }
    if !permit_self_signed && certificate.subject() == certificate.issuer() {
        anyhow::bail!("a public-domain TLS leaf certificate must not be self-signed");
    }
    let constraints = certificate
        .basic_constraints()
        .context("cannot parse TLS leaf basic constraints")?
        .context("TLS leaf certificate lacks basic constraints")?;
    if constraints.value.ca {
        anyhow::bail!("TLS leaf certificate must declare CA:FALSE");
    }
    let usage = certificate
        .key_usage()
        .context("cannot parse TLS leaf key usage")?
        .context("TLS leaf certificate lacks key usage")?;
    if !usage.value.digital_signature() || usage.value.key_cert_sign() || usage.value.crl_sign() {
        anyhow::bail!("TLS leaf key usage must allow signatures and must not allow CA signing");
    }
    let extended = certificate
        .extended_key_usage()
        .context("cannot parse TLS leaf extended key usage")?
        .context("TLS leaf certificate lacks extended key usage")?;
    if !extended.value.server_auth && !extended.value.any {
        anyhow::bail!("TLS leaf certificate is not valid for server authentication");
    }
    certificate
        .subject_alternative_name()
        .context("cannot parse TLS leaf Subject Alternative Name")?
        .context("TLS leaf certificate lacks a Subject Alternative Name")?;

    let subject_public_key = certificate.public_key();
    let subject_algorithm = subject_public_key.algorithm.algorithm.to_id_string();
    match subject_public_key
        .parsed()
        .context("invalid TLS leaf public key")?
    {
        PublicKey::RSA(key) => {
            if key.key_size() < 3072 || key.try_exponent().unwrap_or_default() < 65_537 {
                anyhow::bail!("RSA TLS keys must be at least 3072 bits with a safe exponent");
            }
        }
        PublicKey::EC(key) if (256..=521).contains(&key.key_size()) => {}
        PublicKey::EC(_) => anyhow::bail!("elliptic-curve TLS keys must be 256 to 521 bits"),
        PublicKey::Unknown(key) if subject_algorithm == "1.3.101.112" && key.len() == 32 => {}
        _ => anyhow::bail!("TLS certificate public-key algorithm is unsupported"),
    }

    let signature_oid = certificate.signature_algorithm.algorithm.to_id_string();
    let digest_oid = certificate_signature_digest_oid(&certificate)?;
    if digest_oid
        .as_deref()
        .is_some_and(|oid| matches!(oid, "1.2.840.113549.2.5" | "1.3.14.3.2.26"))
    {
        anyhow::bail!("TLS certificate uses an MD5 or SHA-1 signature");
    }
    if signature_oid == "1.2.840.113549.1.1.2" {
        anyhow::bail!("TLS certificate uses an obsolete MD2 signature");
    }
    Ok(certificate.validity().not_after.timestamp())
}

fn validate_server_chain(
    chain: &[CertificateDer<'static>],
    domain: &str,
    public_roots: &RootCertStore,
) -> Result<i64> {
    let development = development_certificate_domain(domain);
    let not_after = validate_leaf_profile(
        chain
            .first()
            .context("TLS certificate chain is empty")?
            .as_ref(),
        development,
    )?;
    for certificate in &chain[1..] {
        let certificate = parse_certificate(certificate.as_ref())?;
        if !certificate.validity().is_valid() {
            anyhow::bail!("TLS certificate chain contains an expired or not-yet-valid certificate");
        }
    }

    let roots = if development {
        let mut roots = RootCertStore::empty();
        roots
            .add(
                chain
                    .last()
                    .expect("a validated TLS chain has a last certificate")
                    .clone(),
            )
            .context("development TLS trust anchor is invalid")?;
        roots
    } else {
        public_roots.clone()
    };
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crypto_provider())
        .build()
        .context("could not build local certificate verifier")?;
    let server_name =
        ServerName::try_from(crate::jid::domain_to_ascii(domain)?).context("invalid TLS domain")?;
    verifier
        .verify_server_cert(
            chain.first().expect("validated non-empty chain"),
            &chain[1..],
            &server_name,
            &[],
            UnixTime::now(),
        )
        .context("TLS certificate chain, domain, time, or server purpose is invalid")?;
    Ok(not_after)
}

fn server_config(
    chain: &[CertificateDer<'static>],
    key: &PrivateKeyDer<'static>,
    client_verifier: Option<Arc<dyn ClientCertVerifier>>,
    alpn: Option<&'static [u8]>,
) -> Result<Arc<ServerConfig>> {
    let builder = ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(TLS_VERSIONS)
        .context("configured TLS versions are not supported by the crypto provider")?;
    let mut config = match client_verifier {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    }
    .with_single_cert(chain.to_vec(), key.clone_key())
    .context("TLS certificate and private key do not match")?;
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    Ok(Arc::new(config))
}

fn client_config(
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
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    Ok(Arc::new(config))
}

struct TlsMaterialInput<'a> {
    cert_path: &'a Path,
    key_path: &'a Path,
    domain: &'a str,
    extra_root_path: Option<&'a Path>,
    c2s_client_trust_root_path: Option<&'a Path>,
    federation_crl_path: Option<&'a Path>,
    c2s_client_crl_path: Option<&'a Path>,
    generation: u64,
}

fn tls_material(input: TlsMaterialInput<'_>) -> Result<Arc<TlsMaterial>> {
    let TlsMaterialInput {
        cert_path,
        key_path,
        domain,
        extra_root_path,
        c2s_client_trust_root_path,
        federation_crl_path,
        c2s_client_crl_path,
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
    let s2s_verifier: Arc<dyn ClientCertVerifier> = Arc::new(PresentedServerCertificate::new());
    let (c2s_verifier, c2s_client_roots) =
        c2s_client_verifier(c2s_client_trust_root_path, c2s_client_crls.as_deref())?;

    Ok(Arc::new(TlsMaterial {
        c2s_starttls: server_config(&chain, &key, c2s_verifier.clone(), None)?,
        c2s_direct: server_config(&chain, &key, c2s_verifier, Some(b"xmpp-client"))?,
        s2s_starttls: server_config(&chain, &key, Some(Arc::clone(&s2s_verifier)), None)?,
        s2s_direct: server_config(&chain, &key, Some(s2s_verifier), Some(b"xmpp-server"))?,
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

pub struct TlsMaterial {
    pub c2s_starttls: Arc<ServerConfig>,
    pub c2s_direct: Arc<ServerConfig>,
    pub s2s_starttls: Arc<ServerConfig>,
    pub s2s_direct: Arc<ServerConfig>,
    pub s2s_client_starttls: Arc<ClientConfig>,
    pub s2s_client_direct: Arc<ClientConfig>,
    pub federation_roots: Arc<RootCertStore>,
    pub federation_crls: Option<Arc<crate::crl::CrlSet>>,
    /// Retained solely for exact re-evaluation of already authenticated C2S
    /// EXTERNAL sessions after a local CRL snapshot changes.
    c2s_client_roots: Option<Arc<RootCertStore>>,
    c2s_client_crls: Option<Arc<crate::crl::CrlSet>>,
    /// RFC 5929 endpoint binding is absent for hashless certificate signature
    /// algorithms such as Ed25519.  TLS trust and every non-endpoint binding
    /// remain usable in that case.
    pub tls_server_end_point: Option<Vec<u8>>,
    pub leaf_not_after_unix: i64,
    pub generation: u64,
}

impl TlsMaterial {
    fn revocation_decision_with_role(
        crls: &crate::crl::CrlSet,
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
            crate::crl::RevocationRecheck::Valid => LiveRevocationDecision::NotRevoked,
            crate::crl::RevocationRecheck::ExplicitlyRevoked => {
                LiveRevocationDecision::ExplicitlyRevoked
            }
            crate::crl::RevocationRecheck::OtherValidationFailure if crls.is_fresh_at(now) => {
                match recheck(session.authenticated_at) {
                    crate::crl::RevocationRecheck::Valid => LiveRevocationDecision::NotRevoked,
                    crate::crl::RevocationRecheck::ExplicitlyRevoked => {
                        LiveRevocationDecision::ExplicitlyRevoked
                    }
                    crate::crl::RevocationRecheck::OtherValidationFailure => {
                        LiveRevocationDecision::Inconclusive
                    }
                }
            }
            crate::crl::RevocationRecheck::OtherValidationFailure => {
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

pub struct ReloadableTlsConfig {
    material: ArcSwap<TlsMaterial>,
    cert_path: PathBuf,
    key_path: PathBuf,
    domain: String,
    extra_root_path: Option<PathBuf>,
    c2s_client_trust_root_path: Option<PathBuf>,
    federation_crl_path: Option<PathBuf>,
    c2s_client_crl_path: Option<PathBuf>,
    reload_lock: Mutex<()>,
    activation_lock: Mutex<()>,
    certificate_sessions: Arc<CertificateSessionRegistry>,
}

impl ReloadableTlsConfig {
    pub fn new(
        cert_path: &Path,
        key_path: &Path,
        domain: &str,
        extra_root_path: Option<&Path>,
        c2s_client_trust_root_path: Option<&Path>,
        federation_crl_path: Option<&Path>,
        c2s_client_crl_path: Option<&Path>,
    ) -> Result<Arc<Self>> {
        let material = tls_material(TlsMaterialInput {
            cert_path,
            key_path,
            domain,
            extra_root_path,
            c2s_client_trust_root_path,
            federation_crl_path,
            c2s_client_crl_path,
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

/// RFC 5929 tls-server-end-point: hash the exact DER leaf certificate with
/// the digest used by its signature algorithm, substituting SHA-256 for
/// legacy MD5/SHA-1 algorithms. Algorithms without exactly one underlying
/// hash (including Ed25519) deliberately have no tls-server-end-point value.
fn tls_server_end_point(der: &[u8]) -> Result<Option<Vec<u8>>> {
    let certificate = parse_certificate(der).context("cannot parse TLS leaf certificate")?;
    let Some(digest_oid) = certificate_signature_digest_oid(&certificate)? else {
        return Ok(None);
    };

    let digest = match digest_oid.as_str() {
        // RFC 5929 requires SHA-256 for MD5 and SHA-1 signatures.
        "1.2.840.113549.2.5" | "1.3.14.3.2.26" => Sha256::digest(der).to_vec(),
        "2.16.840.1.101.3.4.2.4" => Sha224::digest(der).to_vec(),
        "2.16.840.1.101.3.4.2.1" => Sha256::digest(der).to_vec(),
        "2.16.840.1.101.3.4.2.2" => Sha384::digest(der).to_vec(),
        "2.16.840.1.101.3.4.2.3" => Sha512::digest(der).to_vec(),
        _ => anyhow::bail!("unsupported certificate signature digest for tls-server-end-point"),
    };
    Ok(Some(digest))
}

fn certificate_signature_digest_oid(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<Option<String>> {
    let signature_oid = certificate.signature_algorithm.algorithm.to_id_string();
    if signature_oid == "1.2.840.113549.1.1.10" {
        match SignatureAlgorithm::try_from(&certificate.signature_algorithm)
            .context("cannot parse RSA-PSS certificate signature parameters")?
        {
            SignatureAlgorithm::RSASSA_PSS(parameters) => {
                Ok(Some(parameters.hash_algorithm_oid().to_id_string()))
            }
            _ => anyhow::bail!("invalid RSA-PSS certificate signature parameters"),
        }
    } else if hashless_certificate_signature(&signature_oid) {
        // Ed25519 and Ed448 sign the certificate directly and do not expose a
        // single digest algorithm for RFC 5929 tls-server-end-point.
        Ok(None)
    } else {
        signature_digest_oid(&signature_oid)
            .context("certificate signature algorithm has no supported RFC 5929 digest")
            .map(|oid| Some(oid.to_owned()))
    }
}

fn hashless_certificate_signature(signature_oid: &str) -> bool {
    matches!(signature_oid, "1.3.101.112" | "1.3.101.113")
}

fn signature_digest_oid(signature_oid: &str) -> Option<&'static str> {
    match signature_oid {
        // md2WithRSAEncryption, md5WithRSAEncryption, sha1WithRSAEncryption,
        // the historical OIW SHA-1/RSA OID, DSA/SHA-1 and ECDSA/SHA-1.
        "1.2.840.113549.1.1.2"
        | "1.2.840.113549.1.1.4"
        | "1.2.840.113549.1.1.5"
        | "1.3.14.3.2.29"
        | "1.2.840.10040.4.3"
        | "1.2.840.10045.4.1" => Some("1.3.14.3.2.26"),
        "1.2.840.113549.1.1.14" | "1.2.840.10045.4.3.1" | "2.16.840.1.101.3.4.3.1" => {
            Some("2.16.840.1.101.3.4.2.4")
        }
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" | "2.16.840.1.101.3.4.3.2" => {
            Some("2.16.840.1.101.3.4.2.1")
        }
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" | "2.16.840.1.101.3.4.3.3" => {
            Some("2.16.840.1.101.3.4.2.2")
        }
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" | "2.16.840.1.101.3.4.3.4" => {
            Some("2.16.840.1.101.3.4.2.3")
        }
        _ => None,
    }
}

/// Accept the peer certificate during the TLS handshake without trusting it
/// as an XMPP identity. SASL EXTERNAL performs PKIX/domain verification after
/// the peer has asserted its XMPP domain. Keeping client certificates optional
/// preserves TLS-protected Dialback interoperability.
#[derive(Debug)]
pub(crate) struct PresentedServerCertificate {
    algorithms: tokio_rustls::rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PresentedServerCertificate {
    fn new() -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_log_metadata_is_control_escaped_and_bounded() {
        assert_eq!(bounded_log_metadata("issuer\nname", 64), "issuer\\nname");
        assert_eq!(bounded_log_metadata("abcdef", 3), "abc");
    }

    fn test_certificate_session_entry(
        connection_id: uuid::Uuid,
        registration_id: uuid::Uuid,
        kind: CertificateSessionKind,
        disconnect: tokio_util::sync::CancellationToken,
    ) -> CertificateSessionEntry {
        CertificateSessionEntry {
            registration_id,
            connection_id,
            kind,
            peer_chain: Vec::new(),
            certificate_issuer: "CN=test issuer".into(),
            certificate_serial: "01".into(),
            certificate_sha256: "00".repeat(32),
            handshake_tls_generation: 7,
            authenticated_at: UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
            disconnect,
        }
    }

    #[test]
    fn certificate_session_registry_cancels_only_the_exact_match() {
        let registry = Arc::new(CertificateSessionRegistry::default());
        let first_connection = uuid::Uuid::new_v4();
        let second_connection = uuid::Uuid::new_v4();
        let first_registration = uuid::Uuid::new_v4();
        let second_registration = uuid::Uuid::new_v4();
        let first_disconnect = tokio_util::sync::CancellationToken::new();
        let second_disconnect = tokio_util::sync::CancellationToken::new();
        {
            let mut sessions = registry.sessions.lock().unwrap();
            sessions.insert(
                first_connection,
                test_certificate_session_entry(
                    first_connection,
                    first_registration,
                    CertificateSessionKind::C2s,
                    first_disconnect.clone(),
                ),
            );
            sessions.insert(
                second_connection,
                test_certificate_session_entry(
                    second_connection,
                    second_registration,
                    CertificateSessionKind::InboundS2s,
                    second_disconnect.clone(),
                ),
            );
        }
        let (evaluated, drained) = registry.cancel_matching(|entry| {
            entry.connection_id == first_connection && entry.registration_id == first_registration
        });
        assert_eq!(evaluated, 2);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].connection_id, first_connection);
        assert!(first_disconnect.is_cancelled());
        assert!(!second_disconnect.is_cancelled());
        assert_eq!(
            registry.metrics(),
            CertificateSessionMetrics {
                active: 2,
                c2s_external: 1,
                inbound_s2s_external: 1,
                outbound_s2s_external: 0,
            }
        );
        let (_, repeated) =
            registry.cancel_matching(|entry| entry.connection_id == first_connection);
        assert!(repeated.is_empty());
    }

    #[test]
    fn stale_certificate_session_guard_cannot_remove_reused_connection_id() {
        let registry = Arc::new(CertificateSessionRegistry::default());
        let connection_id = uuid::Uuid::new_v4();
        let old_registration = uuid::Uuid::new_v4();
        let replacement_registration = uuid::Uuid::new_v4();
        registry.sessions.lock().unwrap().insert(
            connection_id,
            test_certificate_session_entry(
                connection_id,
                replacement_registration,
                CertificateSessionKind::OutboundS2s,
                tokio_util::sync::CancellationToken::new(),
            ),
        );
        let stale_guard = CertificateSessionGuard {
            registry: Arc::clone(&registry),
            connection_id,
            registration_id: old_registration,
        };
        drop(stale_guard);
        assert_eq!(registry.metrics().active, 1);
        registry.unregister(connection_id, replacement_registration);
        assert_eq!(registry.metrics().active, 0);
    }

    #[test]
    fn stale_revocation_snapshot_cannot_cancel_reused_connection_id() {
        let registry = Arc::new(CertificateSessionRegistry::default());
        let connection_id = uuid::Uuid::new_v4();
        let stale = test_certificate_session_entry(
            connection_id,
            uuid::Uuid::new_v4(),
            CertificateSessionKind::InboundS2s,
            tokio_util::sync::CancellationToken::new(),
        );
        let replacement_disconnect = tokio_util::sync::CancellationToken::new();
        registry.sessions.lock().unwrap().insert(
            connection_id,
            test_certificate_session_entry(
                connection_id,
                uuid::Uuid::new_v4(),
                CertificateSessionKind::InboundS2s,
                replacement_disconnect.clone(),
            ),
        );

        assert!(!registry.signal_snapshot_if_current(&stale));
        assert!(!replacement_disconnect.is_cancelled());
    }

    #[test]
    fn direct_tls_sni_is_required_and_matches_the_prepared_xmpp_domain() {
        assert!(direct_tls_sni_matches(
            Some("B\u{fc}CHER.example."),
            "xn--bcher-kva.example"
        ));
        assert!(!direct_tls_sni_matches(None, "example.test"));
        assert!(!direct_tls_sni_matches(
            Some("other.example"),
            "example.test"
        ));
        assert!(!direct_tls_sni_matches(Some("bad domain"), "example.test"));
    }

    #[test]
    fn c2s_xmppaddr_decoder_requires_explicit_utf8_der() {
        let value = b"alice@example.test";
        let mut encoded = vec![0xa0, (value.len() + 2) as u8, 0x0c, value.len() as u8];
        encoded.extend_from_slice(value);
        assert_eq!(
            decode_explicit_utf8_string(&encoded),
            Some("alice@example.test")
        );
        encoded[2] = 0x16;
        assert!(decode_explicit_utf8_string(&encoded).is_none());
        assert!(decode_explicit_utf8_string(&encoded[1..]).is_none());
    }

    fn install_crypto_provider() {
        // The binary installs this before constructing AppState. Unit tests
        // enter TLS construction directly and can race each other, so an
        // already-installed identical process provider is also success.
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    #[test]
    fn development_certificate_exemption_is_reserved_name_only() {
        for domain in [
            "localhost",
            "conference.localhost",
            "alpha.test",
            "invalid",
            "service.example",
            "example.com",
        ] {
            assert!(development_certificate_domain(domain));
        }
        for domain in [
            "localhost.example.com",
            "test.example.net",
            "example.com.evil",
        ] {
            assert!(!development_certificate_domain(domain));
        }
    }

    #[test]
    fn unsupported_and_obsolete_signature_algorithms_are_not_silently_mapped() {
        assert_eq!(
            signature_digest_oid("1.2.840.113549.1.1.11"),
            Some("2.16.840.1.101.3.4.2.1")
        );
        assert_eq!(
            signature_digest_oid("1.2.840.113549.1.1.5"),
            Some("1.3.14.3.2.26")
        );
        assert_eq!(signature_digest_oid("1.3.101.112"), None);
        assert!(hashless_certificate_signature("1.3.101.112"));
        assert!(hashless_certificate_signature("1.3.101.113"));
        assert!(!hashless_certificate_signature("1.2.840.113549.1.1.11"));
    }

    #[test]
    fn pem_label_parser_never_treats_private_material_as_a_certificate() {
        let mixed = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n\
                     -----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n";
        assert_eq!(
            pem_begin_labels(mixed).collect::<Vec<_>>(),
            vec!["CERTIFICATE", "PRIVATE KEY"]
        );
    }

    #[test]
    #[ignore = "requires TEST_TLS_CERT_PATH and TEST_TLS_KEY_PATH generated outside the repository"]
    fn generated_identity_builds_every_profile_and_failed_reload_is_atomic() {
        install_crypto_provider();
        let source_certificate =
            PathBuf::from(std::env::var("TEST_TLS_CERT_PATH").expect("TEST_TLS_CERT_PATH"));
        let source_key =
            PathBuf::from(std::env::var("TEST_TLS_KEY_PATH").expect("TEST_TLS_KEY_PATH"));
        let directory =
            std::env::temp_dir().join(format!("northstar-tls-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let certificate = directory.join("server.crt");
        let key = directory.join("server.key");
        fs::copy(source_certificate, &certificate).unwrap();
        fs::copy(source_key, &key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let reloadable =
            ReloadableTlsConfig::new(&certificate, &key, "localhost", None, None, None, None)
                .unwrap();
        let initial = reloadable.current();
        assert!(initial
            .tls_server_end_point
            .as_ref()
            .is_some_and(|binding| !binding.is_empty()));
        assert!(initial.leaf_not_after_unix > 0);
        assert!(initial.c2s_starttls.alpn_protocols.is_empty());
        assert_eq!(
            initial.c2s_direct.alpn_protocols,
            vec![b"xmpp-client".to_vec()]
        );
        assert!(initial.s2s_starttls.alpn_protocols.is_empty());
        assert_eq!(
            initial.s2s_direct.alpn_protocols,
            vec![b"xmpp-server".to_vec()]
        );
        assert!(initial.s2s_client_starttls.alpn_protocols.is_empty());
        assert_eq!(
            initial.s2s_client_direct.alpn_protocols,
            vec![b"xmpp-server".to_vec()]
        );

        let original_key = fs::read(&key).unwrap();
        fs::write(&key, b"not a private key\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = reloadable.reload().unwrap_err().to_string();
        assert!(!error.contains("PRIVATE KEY"));
        assert!(Arc::ptr_eq(&initial, &reloadable.current()));

        fs::write(&key, original_key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        reloadable.reload().unwrap();
        assert!(!Arc::ptr_eq(&initial, &reloadable.current()));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "requires generated C2S client-certificate fixtures outside the repository"]
    fn generated_c2s_external_accepts_only_local_xmppaddr_sans_and_never_cn() {
        install_crypto_provider();
        let client_ca =
            PathBuf::from(std::env::var("TEST_C2S_CLIENT_CA_PATH").expect("C2S client CA path"));
        let valid = certificate_chain(Path::new(
            &std::env::var("TEST_C2S_CLIENT_CERT_PATH").expect("C2S client certificate"),
        ))
        .unwrap();
        let wrong_domain = certificate_chain(Path::new(
            &std::env::var("TEST_C2S_WRONG_DOMAIN_CERT_PATH")
                .expect("wrong-domain C2S client certificate"),
        ))
        .unwrap();
        let cn_only = certificate_chain(Path::new(
            &std::env::var("TEST_C2S_CN_ONLY_CERT_PATH").expect("CN-only C2S client certificate"),
        ))
        .unwrap();

        assert_eq!(
            c2s_client_xmpp_identities(&valid, "localhost").unwrap(),
            vec!["alice@localhost"]
        );
        assert!(c2s_client_xmpp_identities(&wrong_domain, "localhost")
            .unwrap()
            .is_empty());
        assert!(c2s_client_xmpp_identities(&cn_only, "localhost")
            .unwrap()
            .is_empty());

        let server_certificate = PathBuf::from(
            std::env::var("TEST_TLS_CERT_PATH").expect("development server certificate"),
        );
        let server_key =
            PathBuf::from(std::env::var("TEST_TLS_KEY_PATH").expect("development server key"));
        let material = ReloadableTlsConfig::new(
            &server_certificate,
            &server_key,
            "localhost",
            None,
            Some(&client_ca),
            None,
            None,
        )
        .unwrap()
        .current();
        assert!(material.c2s_starttls.alpn_protocols.is_empty());
        assert_eq!(
            material.c2s_direct.alpn_protocols,
            vec![b"xmpp-client".to_vec()]
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "requires a generated private-CA fixture outside the repository"]
    fn generated_public_identity_enforces_trust_domain_permissions_and_atomic_reload() {
        use std::os::unix::fs::PermissionsExt;

        install_crypto_provider();

        let source_certificate =
            PathBuf::from(std::env::var("TEST_PUBLIC_TLS_CERT_PATH").expect("public certificate"));
        let source_key =
            PathBuf::from(std::env::var("TEST_PUBLIC_TLS_KEY_PATH").expect("public key"));
        let trust_root =
            PathBuf::from(std::env::var("TEST_PUBLIC_TLS_CA_PATH").expect("private CA"));
        let domain = std::env::var("TEST_PUBLIC_TLS_DOMAIN").expect("public test domain");
        assert!(!development_certificate_domain(&domain));

        let directory =
            std::env::temp_dir().join(format!("northstar-public-tls-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let certificate = directory.join("server.crt");
        let key = directory.join("server.key");
        fs::copy(source_certificate, &certificate).unwrap();
        fs::copy(source_key, &key).unwrap();

        fs::set_permissions(&certificate, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(ReloadableTlsConfig::new(
            &certificate,
            &key,
            &domain,
            Some(&trust_root),
            None,
            None,
            None,
        )
        .is_err());
        fs::set_permissions(&certificate, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ReloadableTlsConfig::new(
            &certificate,
            &key,
            &domain,
            Some(&trust_root),
            None,
            None,
            None,
        )
        .is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            ReloadableTlsConfig::new(&certificate, &key, &domain, None, None, None, None).is_err()
        );
        assert!(ReloadableTlsConfig::new(
            &certificate,
            &key,
            "wrong.runtime.northstar.internal",
            Some(&trust_root),
            None,
            None,
            None,
        )
        .is_err());

        let reloadable = ReloadableTlsConfig::new(
            &certificate,
            &key,
            &domain,
            Some(&trust_root),
            None,
            None,
            None,
        )
        .unwrap();
        let initial = reloadable.current();
        let original_key = fs::read(&key).unwrap();
        fs::write(&key, b"invalid key fixture\n").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let error = reloadable.reload().unwrap_err().to_string();
        assert!(!error.contains("invalid key fixture"));
        assert!(Arc::ptr_eq(&initial, &reloadable.current()));

        fs::write(&key, original_key).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        reloadable.reload().unwrap();
        assert!(!Arc::ptr_eq(&initial, &reloadable.current()));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "requires generated CRL reload fixtures outside the repository"]
    fn generated_crl_reload_is_atomic_and_rolls_back_on_invalid_input() {
        install_crypto_provider();
        let certificate = PathBuf::from(
            std::env::var("TEST_TLS_RELOAD_CERT_PATH").expect("reload certificate path"),
        );
        let key = PathBuf::from(
            std::env::var("TEST_TLS_RELOAD_KEY_PATH").expect("reload private-key path"),
        );
        let root =
            PathBuf::from(std::env::var("TEST_TLS_RELOAD_ROOT_PATH").expect("reload root path"));
        let initial_crl =
            fs::read(std::env::var("TEST_TLS_RELOAD_CRL_PATH").expect("initial CRL path")).unwrap();
        let renewed_crl =
            fs::read(std::env::var("TEST_TLS_RELOAD_RENEWED_CRL_PATH").expect("renewed CRL path"))
                .unwrap();
        let reload_crl = certificate.with_file_name("reload-under-test.crl.pem");
        fs::write(&reload_crl, &initial_crl).unwrap();

        let reloadable = ReloadableTlsConfig::new(
            &certificate,
            &key,
            "server.example.test",
            Some(&root),
            None,
            Some(&reload_crl),
            None,
        )
        .unwrap();
        let initial = reloadable.current();
        assert!(initial.federation_crls.is_some());

        fs::write(&reload_crl, b"not a CRL\n").unwrap();
        assert!(reloadable.reload().is_err());
        assert!(Arc::ptr_eq(&initial, &reloadable.current()));

        fs::write(&reload_crl, renewed_crl).unwrap();
        reloadable.reload().unwrap();
        assert!(!Arc::ptr_eq(&initial, &reloadable.current()));
        assert!(reloadable.current().federation_crls.is_some());
        fs::remove_file(reload_crl).unwrap();
    }
}
