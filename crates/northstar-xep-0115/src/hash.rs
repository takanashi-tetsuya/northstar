//! Supported hash algorithms and verification routines for XEP-0115.

use crate::canonical::generate_canonical_verification_string;
use crate::error::CapsError;
use crate::model::{CapsAdvertisement, CapsKey, CapsValidationResult, DiscoInfo};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha1::{Digest, Sha1};
use sha2::{Sha224, Sha256, Sha384, Sha512};
use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Supported cryptographic hash algorithms for XEP-0115 verification.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CapsHashAlgorithm {
    /// SHA-1 (required by XEP-0115 Section 5 for backward compatibility, deprecated).
    Sha1,
    /// SHA-256 (recommended for modern XMPP implementations).
    Sha256,
    /// SHA-512.
    Sha512,
    /// SHA-384.
    Sha384,
    /// SHA-224.
    Sha224,
    /// Unsupported or unrecognized algorithm.
    Other(String),
}

impl CapsHashAlgorithm {
    /// Parses an algorithm name from a wire attribute value.
    pub fn parse_name(name: &str) -> Self {
        let normalized = name.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "sha-1" | "sha1" => Self::Sha1,
            "sha-256" | "sha256" => Self::Sha256,
            "sha-512" | "sha512" => Self::Sha512,
            "sha-384" | "sha384" => Self::Sha384,
            "sha-224" | "sha224" => Self::Sha224,
            _ => Self::Other(normalized),
        }
    }

    /// Returns the standard canonical lowercase wire identifier for this algorithm.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sha1 => "sha-1",
            Self::Sha256 => "sha-256",
            Self::Sha512 => "sha-512",
            Self::Sha384 => "sha-384",
            Self::Sha224 => "sha-224",
            Self::Other(ref name) => name.as_str(),
        }
    }

    /// Returns `true` if this algorithm is natively supported for verification.
    pub const fn is_supported(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// Returns `true` if this algorithm is deprecated (e.g. SHA-1).
    pub const fn is_deprecated(&self) -> bool {
        matches!(self, Self::Sha1)
    }

    /// Computes the raw digest of `data` using this algorithm.
    pub fn digest(&self, data: &[u8]) -> Result<Vec<u8>, CapsError> {
        match self {
            Self::Sha1 => Ok(Sha1::digest(data).to_vec()),
            Self::Sha256 => Ok(Sha256::digest(data).to_vec()),
            Self::Sha512 => Ok(Sha512::digest(data).to_vec()),
            Self::Sha384 => Ok(Sha384::digest(data).to_vec()),
            Self::Sha224 => Ok(Sha224::digest(data).to_vec()),
            Self::Other(ref name) => Err(CapsError::UnsupportedHashAlgorithm(name.clone())),
        }
    }

    /// Computes the base64-encoded verification string hash for `canonical_string`.
    pub fn compute_ver(&self, canonical_string: &str) -> Result<String, CapsError> {
        let digest = self.digest(canonical_string.as_bytes())?;
        Ok(STANDARD.encode(digest))
    }

    /// Verifies whether `advertised_ver` matches the computed hash of `canonical_string`.
    pub fn verify(&self, canonical_string: &str, advertised_ver: &str) -> Result<bool, CapsError> {
        let computed = self.compute_ver(canonical_string)?;
        Ok(computed == advertised_ver)
    }
}

impl fmt::Display for CapsHashAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Verifies a presence `<c>` advertisement against caller-supplied `DiscoInfo`.
pub fn verify_caps_advertisement(
    advertisement: &CapsAdvertisement,
    disco: &DiscoInfo,
) -> CapsValidationResult {
    let Some(ref hash_str) = advertisement.hash else {
        return CapsValidationResult::LegacyWithoutHash;
    };

    let algorithm = CapsHashAlgorithm::parse_name(hash_str);
    if !algorithm.is_supported() {
        return CapsValidationResult::UnsupportedAlgorithm {
            algorithm: hash_str.clone(),
        };
    }

    let canonical_string = match generate_canonical_verification_string(disco) {
        Ok(s) => s,
        Err(err) => return CapsValidationResult::InvalidData(err),
    };

    let computed_ver = match algorithm.compute_ver(&canonical_string) {
        Ok(ver) => ver,
        Err(err) => return CapsValidationResult::InvalidData(err),
    };

    if computed_ver == advertisement.ver {
        let key = match CapsKey::new(algorithm.as_str(), &advertisement.node, &advertisement.ver) {
            Ok(k) => k,
            Err(err) => return CapsValidationResult::InvalidData(err),
        };
        CapsValidationResult::Valid {
            key,
            canonical_string,
        }
    } else {
        CapsValidationResult::Mismatch {
            expected: advertisement.ver.clone(),
            computed: computed_ver,
        }
    }
}

/// Generates the canonical verification string and computes the `ver` attribute value for given `DiscoInfo`.
pub fn compute_verification_string_and_ver(
    algorithm: &CapsHashAlgorithm,
    disco: &DiscoInfo,
) -> Result<(String, String), CapsError> {
    let canonical_string = generate_canonical_verification_string(disco)?;
    let ver = algorithm.compute_ver(&canonical_string)?;
    Ok((canonical_string, ver))
}
