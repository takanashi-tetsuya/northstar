use super::{cluster_roster_push_version, ListenerStep};
use northstar_stream::local_routes::session::OnlineSession;
use std::sync::atomic::Ordering;

pub(super) struct RosterPushOptions<'a> {
    pub(super) roster_version: Option<i64>,
    pub(super) roster_annotated_stanza: Option<&'a str>,
}

pub(super) fn validate_roster_push<'a>(
    json: &'a serde_json::Value,
    stanza: &str,
    roster_requested_only: bool,
    expected_user_id: Option<uuid::Uuid>,
) -> ListenerStep<RosterPushOptions<'a>> {
    let roster_version = match json.get("roster_version") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => value.as_i64(),
    };
    let roster_annotated_stanza = match json.get("roster_annotated_stanza") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value))
            if value.len() <= northstar_stream::MAX_XMPP_FRAME_BYTES
                && roxmltree::Document::parse(value).is_ok() =>
        {
            Some(value.as_str())
        }
        Some(_) => return ListenerStep::Continue,
    };
    if roster_requested_only && (expected_user_id.is_none() || roster_version.is_none()) {
        return ListenerStep::Continue;
    }
    if roster_requested_only {
        let Some(roster_version) = roster_version else {
            return ListenerStep::Continue;
        };
        if cluster_roster_push_version(stanza) != Some(roster_version)
            || roster_annotated_stanza
                .is_some_and(|value| cluster_roster_push_version(value) != Some(roster_version))
        {
            return ListenerStep::Continue;
        }
    }
    if !roster_requested_only && (roster_version.is_some() || roster_annotated_stanza.is_some()) {
        return ListenerStep::Continue;
    }
    ListenerStep::Next(RosterPushOptions {
        roster_version,
        roster_annotated_stanza,
    })
}

pub(super) fn roster_interest_missing(
    roster_requested_only: bool,
    session: &OnlineSession,
) -> bool {
    roster_requested_only && !session.roster_requested.load(Ordering::Acquire)
}
