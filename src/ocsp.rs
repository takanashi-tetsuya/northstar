//! Validation for an operator-supplied OCSP staple. No certificate-provided
//! URL is fetched; the signer and the leaf status are checked before use.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use openssl::{
    hash::MessageDigest,
    ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspResponse, OcspResponseStatus},
    stack::Stack,
    x509::{store::X509StoreBuilder, verify::X509VerifyFlags, X509},
};
use std::{fs, path::Path};
use tokio_rustls::rustls::pki_types::CertificateDer;

const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const MAX_STATUS_AGE_SECONDS: u32 = 7 * 24 * 60 * 60;

pub(crate) struct ValidatedOcspResponse {
    der: Vec<u8>,
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
}

fn response_time(value: &openssl::asn1::Asn1GeneralizedTimeRef) -> Result<DateTime<Utc>> {
    // OpenSSL prints a validated GeneralizedTime in this fixed GMT form. An
    // unexpected format is rejected instead of weakening the expiry gate.
    let printed = value.to_string();
    Ok(
        NaiveDateTime::parse_from_str(&printed, "%b %e %H:%M:%S %Y GMT")
            .context("OCSP response has an unparseable update time")?
            .and_utc(),
    )
}

impl ValidatedOcspResponse {
    pub(crate) fn from_file(path: &Path, chain: &[CertificateDer<'static>]) -> Result<Self> {
        let metadata = fs::metadata(path).context("could not inspect OCSP response file")?;
        anyhow::ensure!(
            metadata.is_file() && (1..=MAX_RESPONSE_BYTES).contains(&metadata.len()),
            "OCSP response must be a nonempty regular file within the size limit"
        );
        let der = fs::read(path).context("could not read OCSP response file")?;
        anyhow::ensure!(
            !der.is_empty() && der.len() as u64 <= MAX_RESPONSE_BYTES,
            "OCSP response exceeds its size limit"
        );
        Self::from_der(der, chain)
    }

    fn from_der(der: Vec<u8>, chain: &[CertificateDer<'static>]) -> Result<Self> {
        anyhow::ensure!(
            chain.len() >= 2,
            "OCSP stapling requires the leaf and its issuing certificate in the configured chain"
        );
        let leaf = X509::from_der(chain[0].as_ref()).context("invalid OCSP leaf certificate")?;
        let issuer =
            X509::from_der(chain[1].as_ref()).context("invalid OCSP issuer certificate")?;
        let response = OcspResponse::from_der(&der).context("invalid OCSP DER response")?;
        anyhow::ensure!(
            response
                .to_der()
                .context("could not re-encode OCSP response")?
                == der,
            "OCSP response has trailing or noncanonical data"
        );
        anyhow::ensure!(
            response.status() == OcspResponseStatus::SUCCESSFUL,
            "OCSP responder did not return a successful response"
        );
        let basic = response.basic().context("missing basic OCSP response")?;
        let mut untrusted = Stack::new().context("could not prepare OCSP certificate chain")?;
        untrusted
            .push(issuer.clone())
            .context("could not add OCSP issuer certificate")?;
        for cert in &chain[2..] {
            untrusted
                .push(X509::from_der(cert.as_ref())?)
                .context("invalid OCSP chain certificate")?;
        }
        let mut store = X509StoreBuilder::new().context("could not build OCSP issuer store")?;
        store
            .set_flags(X509VerifyFlags::PARTIAL_CHAIN)
            .context("could not require exact OCSP issuer trust")?;
        store
            .add_cert(issuer.clone())
            .context("could not trust the configured OCSP issuer")?;
        basic
            .verify(&untrusted, &store.build(), OcspFlag::empty())
            .context("OCSP response signature or responder authority is invalid")?;

        let mut selected = None;
        for digest in [MessageDigest::sha1(), MessageDigest::sha256()] {
            let id = OcspCertId::from_cert(digest, &leaf, &issuer)
                .context("could not identify OCSP leaf certificate")?;
            if let Some(status) = basic.find_status(&id) {
                anyhow::ensure!(
                    selected.is_none(),
                    "OCSP response contains multiple statuses for this leaf"
                );
                anyhow::ensure!(
                    status.status == OcspCertStatus::GOOD,
                    "OCSP response does not report good status for this leaf"
                );
                anyhow::ensure!(
                    status.next_update().is_some(),
                    "OCSP response has no bounded nextUpdate"
                );
                status
                    .check_validity(0, Some(MAX_STATUS_AGE_SECONDS))
                    .context("OCSP response is stale or not yet valid")?;
                let this_update = response_time(status.this_update)?;
                let next_update =
                    response_time(status.next_update().expect("nextUpdate was checked above"))?;
                anyhow::ensure!(
                    next_update > this_update
                        && next_update.signed_duration_since(this_update)
                            <= Duration::seconds(i64::from(MAX_STATUS_AGE_SECONDS)),
                    "OCSP response validity interval exceeds the seven-day limit"
                );
                selected = Some((this_update, next_update));
            }
        }
        let (this_update, next_update) =
            selected.context("OCSP response does not cover the configured leaf")?;
        let response = Self {
            der,
            this_update,
            next_update,
        };
        anyhow::ensure!(
            response.fresh_now(),
            "OCSP response is stale or not yet valid"
        );
        Ok(response)
    }

    pub(crate) fn der(&self) -> &[u8] {
        &self.der
    }

    /// Checked again at every new handshake, so an expired staple cannot be
    /// served indefinitely from a previously validated TLS snapshot.
    pub(crate) fn fresh_now(&self) -> bool {
        self.fresh_at(Utc::now())
    }

    fn fresh_at(&self, now: DateTime<Utc>) -> bool {
        self.this_update <= now && now < self.next_update
    }
}

#[cfg(test)]
mod tests {
    use super::ValidatedOcspResponse;
    use chrono::Duration;
    use std::{fs, path::PathBuf};
    use tokio_rustls::rustls::pki_types::CertificateDer;

    #[test]
    #[ignore = "requires OCSP responses generated by scripts/test-ocsp-stapling.sh"]
    fn generated_responses_require_exact_good_fresh_authorized_status() {
        let root = PathBuf::from(std::env::var("TEST_OCSP_FIXTURE_DIR").unwrap());
        let certificate = |name: &str| {
            let pem = fs::read(root.join(name)).unwrap();
            CertificateDer::from(
                openssl::x509::X509::from_pem(&pem)
                    .unwrap()
                    .to_der()
                    .unwrap(),
            )
        };
        let chain = vec![certificate("leaf.crt"), certificate("root.crt")];
        let good = ValidatedOcspResponse::from_file(&root.join("good.der"), &chain).unwrap();
        assert!(good.fresh_now());
        assert!(!good.fresh_at(good.this_update - Duration::seconds(1)));
        assert!(!good.fresh_at(good.next_update));
        for name in [
            "too-long.der",
            "revoked.der",
            "unknown.der",
            "wrong-leaf.der",
            "bad-signature.der",
            "no-next-update.der",
        ] {
            assert!(
                ValidatedOcspResponse::from_file(&root.join(name), &chain).is_err(),
                "unexpectedly accepted {name}"
            );
        }
        let mut trailing = good.der().to_vec();
        trailing.push(0);
        assert!(ValidatedOcspResponse::from_der(trailing, &chain).is_err());
        assert!(ValidatedOcspResponse::from_der(good.der().to_vec(), &chain[..1]).is_err());
    }
}
