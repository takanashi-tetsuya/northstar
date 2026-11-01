//! Purpose-separated keyrings that authenticate durable content identities.

use crate::{
    compute_content_identity_authenticators, ContentIdentityAuthenticators, ContentIdentityPurpose,
};
use std::sync::Arc;
use zeroize::Zeroizing;

/// One deployment key generation, derived for a single purpose.
pub struct ContentIdentityGeneration {
    pub key_id: String,
    pub key: Zeroizing<Vec<u8>>,
}

/// Least-authority capability for XEP-0369 channel message replay identities.
/// It cannot produce personal-message or MIX-retraction commitments even
/// though all generations originate from the same mounted deployment secret.
#[derive(Clone)]
pub struct MixMessageContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

impl MixMessageContentKeyring {
    pub fn new(generations: Arc<Vec<ContentIdentityGeneration>>) -> Self {
        Self { generations }
    }

    pub fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::MixMessage,
            canonical_payload,
        )
    }
}

/// Least-authority capability for XEP-0425 MIX retraction replay identities.
/// Keeping it distinct from channel-message identity prevents a compromised
/// service path from forging an authenticator for the other operation family.
#[derive(Clone)]
pub struct MixRetractionContentKeyring {
    generations: Arc<Vec<ContentIdentityGeneration>>,
}

impl MixRetractionContentKeyring {
    pub fn new(generations: Arc<Vec<ContentIdentityGeneration>>) -> Self {
        Self { generations }
    }

    pub fn authenticators(&self, canonical_payload: &[u8]) -> ContentIdentityAuthenticators {
        content_identity_authenticators(
            &self.generations,
            ContentIdentityPurpose::MixRetraction,
            canonical_payload,
        )
    }
}

pub fn content_identity_authenticators(
    generations: &[ContentIdentityGeneration],
    purpose: ContentIdentityPurpose,
    canonical_payload: &[u8],
) -> ContentIdentityAuthenticators {
    compute_content_identity_authenticators(
        generations
            .iter()
            .map(|generation| (generation.key_id.as_str(), generation.key.as_slice())),
        purpose,
        canonical_payload,
    )
}
