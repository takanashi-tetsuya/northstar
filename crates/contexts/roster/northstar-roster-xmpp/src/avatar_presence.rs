//! Per-account gate that orders cached avatar presence projections.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use tokio::sync::{Mutex, MutexGuard};

const STRIPE_COUNT: usize = 64;

/// Serializes the committed avatar lookup and local presence update for an account.
pub struct AvatarPresenceGate {
    stripes: [Mutex<()>; STRIPE_COUNT],
}

impl Default for AvatarPresenceGate {
    fn default() -> Self {
        Self {
            stripes: std::array::from_fn(|_| Mutex::new(())),
        }
    }
}

impl AvatarPresenceGate {
    /// `owner` is the account's JID; it is reduced to its canonical bare form, so a full
    /// or non-canonical spelling of the same account selects the same stripe.
    pub async fn lock(&self, owner: &str) -> MutexGuard<'_, ()> {
        let key = northstar_xmpp_types::jid::canonical_bare_key(owner)
            .unwrap_or_else(|_| owner.to_owned());
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        self.stripes[hasher.finish() as usize % STRIPE_COUNT]
            .lock()
            .await
    }
}
