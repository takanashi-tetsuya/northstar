use anyhow::Result;
use northstar_xml_builder::rewrite::{project_presence_avatar, set_from};
use std::future::Future;

pub(crate) struct PreparedBroadcastPresence<A = super::BroadcastAudience> {
    pub(super) audience: A,
    pub(super) wire: String,
    pub(crate) cached: Option<String>,
}

pub(super) async fn prepare<A>(
    raw: &str,
    available: bool,
    from: &str,
    audience: impl Future<Output = Result<A>>,
    avatar_hash: impl Future<Output = Result<Option<String>>>,
) -> Result<PreparedBroadcastPresence<A>> {
    let audience = audience.await?;
    if !available {
        return Ok(PreparedBroadcastPresence {
            audience,
            wire: set_from(raw, from),
            cached: None,
        });
    }
    let hash = avatar_hash.await?;
    let wire = project_presence_avatar(raw, Some(hash.as_deref()))
        .ok_or_else(|| anyhow::anyhow!("broadcast presence could not be rendered"))?;
    let wire = set_from(&wire, from);
    let cached = if hash.is_some() {
        wire.clone()
    } else {
        let cached = project_presence_avatar(raw, None)
            .ok_or_else(|| anyhow::anyhow!("broadcast presence could not be cached"))?;
        set_from(&cached, from)
    };
    Ok(PreparedBroadcastPresence {
        audience,
        wire,
        cached: Some(cached),
    })
}

#[cfg(test)]
mod tests;
