//! Read bounded certificate and key inputs, validate certificate policy, and derive certificate identities and endpoint digests.

use super::*;

pub(super) fn read_stable_regular_file(
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
pub(super) fn validate_same_file(
    before: &fs::Metadata,
    after: &fs::Metadata,
    label: &str,
) -> Result<()> {
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
pub(super) fn validate_same_file(
    before: &fs::Metadata,
    after: &fs::Metadata,
    label: &str,
) -> Result<()> {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        anyhow::bail!("{label} changed while it was being read; retry after atomic replacement");
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn validate_private_file_permissions(
    metadata: &fs::Metadata,
    label: &str,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o400 && mode != 0o600 {
        anyhow::bail!("{label} permissions must be exactly 0400 or 0600 (found {mode:04o})");
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn validate_public_file_permissions(metadata: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        anyhow::bail!("{label} must not be group/world writable (found {mode:04o})");
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn validate_private_file_permissions(
    _metadata: &fs::Metadata,
    _label: &str,
) -> Result<()> {
    // Windows ACLs do not map safely to Unix mode bits. The Linux production
    // preflight performs the authoritative 0400/0600 check.
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn validate_public_file_permissions(
    _metadata: &fs::Metadata,
    _label: &str,
) -> Result<()> {
    Ok(())
}

pub(super) fn pem_begin_labels(pem: &str) -> impl Iterator<Item = &str> {
    pem.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("-----BEGIN ")
            .and_then(|line| line.strip_suffix("-----"))
    })
}

pub(super) fn private_key(
    path: &Path,
    enforce_permissions: bool,
) -> Result<PrivateKeyDer<'static>> {
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

pub(super) fn parse_certificate(
    der: &[u8],
) -> Result<x509_parser::certificate::X509Certificate<'_>> {
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

pub(super) fn decode_explicit_utf8_string(encoded: &[u8]) -> Option<&str> {
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

pub(super) fn validate_extra_trust_anchor(der: &[u8]) -> Result<()> {
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

pub(super) fn development_certificate_domain(domain: &str) -> bool {
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

pub(super) fn validate_leaf_profile(der: &[u8], permit_self_signed: bool) -> Result<i64> {
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

pub(super) fn validate_server_chain(
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

/// RFC 5929 tls-server-end-point: hash the exact DER leaf certificate with
/// the digest used by its signature algorithm, substituting SHA-256 for
/// legacy MD5/SHA-1 algorithms. Algorithms without exactly one underlying
/// hash (including Ed25519) deliberately have no tls-server-end-point value.
pub(super) fn tls_server_end_point(der: &[u8]) -> Result<Option<Vec<u8>>> {
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

pub(super) fn certificate_signature_digest_oid(
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

pub(super) fn hashless_certificate_signature(signature_oid: &str) -> bool {
    matches!(signature_oid, "1.3.101.112" | "1.3.101.113")
}

pub(super) fn signature_digest_oid(signature_oid: &str) -> Option<&'static str> {
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
