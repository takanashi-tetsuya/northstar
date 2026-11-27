use anyhow::Result;
use northstar_roster_application::blocking::RosterEntry;
use northstar_xml_builder::rewrite::{project_presence_avatar, set_from};
use std::future::Future;

pub(crate) struct PreparedBroadcastPresence {
    pub(super) roster: Vec<RosterEntry>,
    pub(super) wire: String,
    pub(crate) cached: Option<String>,
}

pub(super) async fn prepare(
    raw: &str,
    available: bool,
    from: &str,
    roster: impl Future<Output = Result<Vec<RosterEntry>>>,
    avatar_hash: impl Future<Output = Result<Option<String>>>,
) -> Result<PreparedBroadcastPresence> {
    let roster = roster.await?;
    if !available {
        return Ok(PreparedBroadcastPresence {
            roster,
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
        roster,
        wire,
        cached: Some(cached),
    })
}

#[cfg(test)]
mod tests;
