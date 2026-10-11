use anyhow::{Context, Result};
use tokio_rustls::rustls::{
    pki_types::{
        pem::PemObject, CertificateDer, CertificateRevocationListDer,
        SignatureVerificationAlgorithm, UnixTime,
    },
    RootCertStore,
};
use webpki::{
    CertRevocationList, EndEntityCert, ExpirationPolicy, KeyUsage, OwnedCertRevocationList,
    RevocationCheckDepth, RevocationOptionsBuilder, UnknownStatusPolicy,
};

const MAX_CRLS: usize = 64;

#[derive(Clone, Copy)]
enum PeerRole {
    Server,
    Client,
}

/// Result of re-evaluating an already authenticated peer against a newly
/// loaded CRL snapshot.  Only the exact `CertRevoked` result is actionable:
/// expiry, a changed trust root, an incomplete chain, an inapplicable CRL or
/// any other validation failure must not turn a routine TLS reload into a
/// global connection kick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RevocationRecheck {
    Valid,
    ExplicitlyRevoked,
    OtherValidationFailure,
}

impl PeerRole {
    fn key_usage(self) -> KeyUsage {
        match self {
            Self::Server => KeyUsage::server_auth(),
            Self::Client => KeyUsage::client_auth(),
        }
    }
}

/// A startup/reload-parsed CRL set. Structural validity and required freshness
/// metadata are parsed while loading; signature, issuer authority, current
/// freshness and applicability can
/// only be established against a concrete peer chain and are therefore checked
/// by `verify_*_chain`. When present, that per-chain verification is
/// deliberately fail-closed: every non-root certificate in the built chain
/// must have an authoritative CRL, CRL signatures must validate, and nextUpdate
/// must not be expired. Northstar never downloads attacker-selected CRL URLs
/// from certificate extensions.
#[derive(Debug)]
pub(crate) struct CrlSet {
    encoded: Vec<CertificateRevocationListDer<'static>>,
    parsed: Vec<CertRevocationList<'static>>,
    fresh_until_unix: u64,
}

impl CrlSet {
    pub(crate) fn from_pem(bytes: &[u8], label: &str) -> Result<Self> {
        let pem =
            std::str::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8 PEM"))?;
        let labels = pem_begin_labels(pem).collect::<Vec<_>>();
        if labels.is_empty()
            || labels
                .iter()
                .any(|block| !matches!(*block, "X509 CRL" | "CRL"))
        {
            anyhow::bail!("{label} must contain only X509 CRL PEM blocks");
        }
        if labels.len() > MAX_CRLS {
            anyhow::bail!("{label} exceeds the limit of {MAX_CRLS} CRLs");
        }
        let encoded = CertificateRevocationListDer::pem_slice_iter(bytes)
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("{label} contains invalid CRL PEM"))?;
        if encoded.is_empty() || encoded.len() != labels.len() {
            anyhow::bail!("{label} contains malformed or unsupported PEM blocks");
        }
        let mut parsed = Vec::with_capacity(encoded.len());
        let mut issuer_names: Vec<Vec<u8>> = Vec::with_capacity(encoded.len());
        let mut fresh_until_unix = u64::MAX;
        for (index, crl) in encoded.iter().enumerate() {
            if encoded[..index]
                .iter()
                .any(|previous| previous.as_ref() == crl.as_ref())
            {
                anyhow::bail!("{label} contains a duplicate CRL");
            }
            parsed.push(CertRevocationList::from(
                OwnedCertRevocationList::from_der(crl.as_ref())
                    .with_context(|| format!("{label} contains an invalid RFC 5280 CRL"))?,
            ));
            let (remaining, inspected) = x509_parser::parse_x509_crl(crl.as_ref())
                .map_err(|error| anyhow::anyhow!("{label} contains an invalid CRL: {error}"))?;
            anyhow::ensure!(
                remaining.is_empty(),
                "{label} contains trailing CRL DER data"
            );
            let issuer_name = inspected.issuer().as_raw();
            anyhow::ensure!(
                !issuer_names
                    .iter()
                    .any(|previous| previous.as_slice() == issuer_name),
                "{label} contains multiple CRLs for one issuer; supply exactly one current full CRL per issuer"
            );
            issuer_names.push(issuer_name.to_vec());
            let next_update = inspected
                .next_update()
                .context("CRL nextUpdate is required by the fail-closed policy")?
                .timestamp();
            let next_update =
                u64::try_from(next_update).context("CRL nextUpdate predates the Unix epoch")?;
            fresh_until_unix = fresh_until_unix.min(next_update);
        }
        Ok(Self {
            encoded,
            parsed,
            fresh_until_unix,
        })
    }

    pub(crate) fn verify_server_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        roots: &RootCertStore,
        now: UnixTime,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
    ) -> Result<()> {
        self.verify_chain_result(
            end_entity,
            intermediates,
            roots,
            now,
            algorithms,
            PeerRole::Server,
        )
        .with_context(|| "server certificate path, EKU, or fail-closed CRL validation failed")
    }

    /// Apply the same fail-closed CRL policy to a certificate presented by a
    /// TLS client. This is used by inbound S2S SASL EXTERNAL (and, when the
    /// operator enables it, C2S EXTERNAL); validating a client credential as
    /// `serverAuth` would silently bypass its EKU boundary.
    pub(crate) fn verify_client_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        roots: &RootCertStore,
        now: UnixTime,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
    ) -> Result<()> {
        self.verify_chain_result(
            end_entity,
            intermediates,
            roots,
            now,
            algorithms,
            PeerRole::Client,
        )
        .with_context(|| "client certificate path, EKU, or fail-closed CRL validation failed")
    }

    pub(crate) fn recheck_server_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        roots: &RootCertStore,
        now: UnixTime,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
    ) -> RevocationRecheck {
        Self::classify(self.verify_chain_result(
            end_entity,
            intermediates,
            roots,
            now,
            algorithms,
            PeerRole::Server,
        ))
    }

    pub(crate) fn recheck_client_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        roots: &RootCertStore,
        now: UnixTime,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
    ) -> RevocationRecheck {
        Self::classify(self.verify_chain_result(
            end_entity,
            intermediates,
            roots,
            now,
            algorithms,
            PeerRole::Client,
        ))
    }

    pub(crate) fn is_fresh_at(&self, now: UnixTime) -> bool {
        now.as_secs() < self.fresh_until_unix
    }

    fn classify(result: std::result::Result<(), webpki::Error>) -> RevocationRecheck {
        match result {
            Ok(()) => RevocationRecheck::Valid,
            Err(webpki::Error::CertRevoked) => RevocationRecheck::ExplicitlyRevoked,
            Err(_) => RevocationRecheck::OtherValidationFailure,
        }
    }

    fn verify_chain_result(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        roots: &RootCertStore,
        now: UnixTime,
        algorithms: &[&dyn SignatureVerificationAlgorithm],
        peer_role: PeerRole,
    ) -> std::result::Result<(), webpki::Error> {
        let end_entity = EndEntityCert::try_from(end_entity)?;
        let crls = self.parsed.iter().collect::<Vec<_>>();
        let revocation = RevocationOptionsBuilder::new(&crls)
            .expect("CrlSet construction rejects an empty CRL bundle")
            .with_depth(RevocationCheckDepth::Chain)
            .with_status_policy(UnknownStatusPolicy::Deny)
            .with_expiration_policy(ExpirationPolicy::Enforce)
            .build();
        end_entity.verify_for_usage(
            algorithms,
            &roots.roots,
            intermediates,
            now,
            peer_role.key_usage(),
            Some(revocation),
            None,
        )?;
        Ok(())
    }

    /// rustls' stock client-certificate verifier accepts the encoded CRLs
    /// directly. Keeping the DER from the same startup/reload parse ensures
    /// the handshake verifier and Northstar's post-handshake XMPP verifier
    /// cannot accidentally use different revocation snapshots.
    pub(crate) fn encoded(&self) -> Vec<CertificateRevocationListDer<'static>> {
        self.encoded.clone()
    }
}

fn pem_begin_labels(pem: &str) -> impl Iterator<Item = &str> {
    pem.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("-----BEGIN ")
            .and_then(|line| line.strip_suffix("-----"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_explicit_revocation_classification_requires_a_drain() {
        assert_eq!(CrlSet::classify(Ok(())), RevocationRecheck::Valid);
        assert_eq!(
            CrlSet::classify(Err(webpki::Error::CertRevoked)),
            RevocationRecheck::ExplicitlyRevoked
        );
        assert_eq!(
            CrlSet::classify(Err(webpki::Error::UnknownIssuer)),
            RevocationRecheck::OtherValidationFailure
        );
    }

    #[test]
    fn crl_bundle_rejects_empty_mixed_and_malformed_pem() {
        assert!(CrlSet::from_pem(b"", "test CRL").is_err());
        assert!(CrlSet::from_pem(
            b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
            "test CRL"
        )
        .is_err());
        assert!(CrlSet::from_pem(
            b"-----BEGIN X509 CRL-----\nAA==\n-----END X509 CRL-----\n",
            "test CRL"
        )
        .is_err());
    }

    #[test]
    fn crl_bundle_limit_is_checked_before_der_parsing() {
        let mut pem = String::new();
        for _ in 0..=MAX_CRLS {
            pem.push_str("-----BEGIN X509 CRL-----\nAA==\n-----END X509 CRL-----\n");
        }
        let error = CrlSet::from_pem(pem.as_bytes(), "test CRL")
            .expect_err("oversized bundle must fail")
            .to_string();
        assert!(error.contains("exceeds the limit"));
    }

    #[test]
    #[ignore = "set TEST_CRL_PATH, TEST_CRL_ROOT_PATH, TEST_CRL_LEAF_PATH, TEST_CRL_ROLE, and TEST_CRL_EXPECT_VALID"]
    fn validates_generated_server_or_client_revocation_fixture() {
        let crl_path = std::env::var("TEST_CRL_PATH").expect("CRL fixture path");
        let root_path = std::env::var("TEST_CRL_ROOT_PATH").expect("root fixture path");
        let leaf_path = std::env::var("TEST_CRL_LEAF_PATH").expect("leaf fixture path");
        let role = std::env::var("TEST_CRL_ROLE").expect("server or client role");
        let expected = std::env::var("TEST_CRL_EXPECT_VALID")
            .expect("true or false expected validity")
            .parse::<bool>()
            .expect("boolean expected validity");

        let crls = CrlSet::from_pem(&std::fs::read(crl_path).unwrap(), "test CRL").unwrap();
        let root = CertificateDer::from_pem_file(root_path).unwrap();
        let leaf = CertificateDer::from_pem_file(leaf_path).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(root).unwrap();
        let algorithms = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms;
        let result = match role.as_str() {
            "server" => {
                crls.verify_server_chain(&leaf, &[], &roots, UnixTime::now(), algorithms.all)
            }
            "client" => {
                crls.verify_client_chain(&leaf, &[], &roots, UnixTime::now(), algorithms.all)
            }
            _ => panic!("TEST_CRL_ROLE must be server or client"),
        };
        assert_eq!(
            result.is_ok(),
            expected,
            "unexpected CRL result: {result:?}"
        );
    }
}
