//! Per-account gate that orders cached avatar presence projections.

use northstar_roster_application::presence::{PresenceRepository, PresenceService};
use northstar_xml_builder::rewrite::project_presence_avatar;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

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

pub(crate) async fn render_current_presence_avatar(
    service: &PresenceService<impl PresenceRepository>,
    owner_id: Uuid,
    cached: &str,
) -> Option<String> {
    let hash = service.avatar_hash(owner_id).await;
    project_presence_avatar(cached, hash.as_ref().map(|hash| hash.as_deref()).ok())
}

#[cfg(test)]
mod tests;
