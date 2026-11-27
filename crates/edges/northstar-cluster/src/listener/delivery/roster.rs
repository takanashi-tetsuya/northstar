use super::{DirectDeliveryOptions, ListenerStep};
use crate::ExactControlKind;
use northstar_roster_core::RosterPushDisposition;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_xml_builder::rewrite::set_to;
use std::sync::atomic::Ordering;

pub(super) struct RosterPushOptions<'a> {
    pub(super) roster_version: Option<i64>,
    pub(super) roster_annotated_stanza: Option<&'a str>,
}

pub(super) fn validate_roster_push<'a>(
    json: &'a serde_json::Value,
    document: Option<&roxmltree::Document<'_>>,
    roster_requested_only: bool,
) -> ListenerStep<RosterPushOptions<'a>> {
    if roster_requested_only
        || !json["roster_version"].is_null()
        || !json["roster_annotated_stanza"].is_null()
        || document.is_some_and(|document| {
            let root = document.root_element();
            root.tag_name().name() == "iq"
                && root.attribute("type") == Some("set")
                && root
                    .children()
                    .any(|node| node.has_tag_name(("jabber:iq:roster", "query")))
        })
    {
        return ListenerStep::Continue;
    }
    ListenerStep::Next(RosterPushOptions {
        roster_version: None,
        roster_annotated_stanza: None,
    })
}

pub(in crate::listener) fn handoff_roster_push(
    options: &DirectDeliveryOptions<'_>,
    session: &OnlineSession,
    jid: &str,
    stanza: &str,
) -> bool {
    let (Some(control), Some(version)) = (&options.exact_control, options.roster_version) else {
        return false;
    };
    if control.kind != ExactControlKind::RosterPush
        || control.account_id != session.user_id
        || control.auth_generation != session.auth_generation
        || control.expected_connections.get(jid) != Some(&session.connection_id)
        || !session.routable.load(Ordering::Acquire)
        || session.disconnect.is_cancelled()
    {
        return false;
    }
    let annotated = options
        .roster_annotated_stanza
        .map(|stanza| set_to(stanza, jid));
    match session.roster_sync.route(
        &session.roster_requested,
        &session.mix_roster_annotations,
        version,
        stanza.to_owned(),
        annotated,
        |stanza| !session.disconnect.is_cancelled() && session.sender.try_send(stanza).is_ok(),
    ) {
        RosterPushDisposition::Buffered
        | RosterPushDisposition::Covered
        | RosterPushDisposition::Delivered => true,
        RosterPushDisposition::NotInterested | RosterPushDisposition::Failed => false,
        RosterPushDisposition::Resync => {
            session.sender.disconnect_backpressured_transport();
            session.disconnect.cancel();
            false
        }
    }
}

pub(super) fn roster_interest_missing(
    roster_requested_only: bool,
    session: &OnlineSession,
) -> bool {
    roster_requested_only && !session.roster_requested.load(Ordering::Acquire)
}
