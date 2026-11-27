use crate::AvatarPresenceGate;
use anyhow::Result;
use northstar_roster_application::presence::{PresenceRepository, PresenceService};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_xml_builder::rewrite::project_presence_avatar;
use std::future::Future;
use uuid::Uuid;

/// Refresh stored local presence with the owner's current vCard avatar hash.
pub async fn refresh_avatar_presence(
    gate: &AvatarPresenceGate,
    presence_service: &PresenceService<impl PresenceRepository>,
    owner_id: Uuid,
    owner_bare: &str,
    sessions: impl FnOnce() -> Vec<OnlineSession>,
) {
    if let Err(error) = refresh_avatar_presence_with_hash(
        gate,
        owner_bare,
        presence_service.avatar_hash(owner_id),
        sessions,
    )
    .await
    {
        tracing::warn!(?error, %owner_id, "could not refresh cached avatar presence");
    }
}

pub(super) async fn refresh_avatar_presence_with_hash(
    gate: &AvatarPresenceGate,
    owner_bare: &str,
    avatar_hash: impl Future<Output = Result<Option<String>>>,
    sessions: impl FnOnce() -> Vec<OnlineSession>,
) -> Result<()> {
    project_avatar_presence(gate, owner_bare, avatar_hash, |hash| {
        for session in sessions() {
            let mut last_presence = session
                .last_presence
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let refreshed = last_presence
                .as_deref()
                .and_then(|raw| project_presence_avatar(raw, hash.map(Some)));
            if let Some(refreshed) = refreshed {
                *last_presence = Some(refreshed);
            }
        }
    })
    .await
}

pub(super) async fn project_avatar_presence<T>(
    gate: &AvatarPresenceGate,
    owner_bare: &str,
    avatar_hash: impl Future<Output = Result<Option<String>>>,
    project: impl FnOnce(Option<&str>) -> T,
) -> Result<T> {
    // Poll the database read only after admission and retain the guard through the cache update.
    let _guard = gate.lock(owner_bare).await;
    let hash = avatar_hash.await?;
    Ok(project(hash.as_deref()))
}
