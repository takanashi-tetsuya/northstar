use super::{validate_roster_push, ListenerStep, RosterPushOptions};
use crate::{
    validate_exact_control, ExactControl, ExactControlKind, EXACT_CONTROL_DELIVERY_VERSION,
};
use roxmltree::Document;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

pub(super) fn is_exact_control_version(json: &Value) -> bool {
    json["protocol_version"].as_str() == Some(EXACT_CONTROL_DELIVERY_VERSION)
}

pub(super) fn validate_control_and_roster_push<'a>(
    json: &'a Value,
    target: &str,
    document: Option<&Document<'_>>,
    roster_requested_only: bool,
    (expected_user_id, expected_auth_generation): (Option<Uuid>, Option<i64>),
) -> ListenerStep<(RosterPushOptions<'a>, Option<ExactControl>)> {
    if !is_exact_control_version(json) {
        // Directed and broadcast C2S presence shared the old generic
        // delivery envelope. There is no safe way to route that envelope
        // while requiring exact recipients for directed/terminal effects.
        if document.is_some_and(|document| {
            let root = document.root_element();
            root.tag_name().name() == "presence"
                && root
                    .attribute("from")
                    .is_some_and(|from| from.contains('/'))
                && json["presence_subscription"].as_bool() != Some(true)
                && json["current_presence_replay"].as_bool() != Some(true)
        }) {
            return ListenerStep::Continue;
        }
        return match validate_roster_push(json, document, roster_requested_only) {
            ListenerStep::Next(roster) => ListenerStep::Next((roster, None)),
            ListenerStep::Continue => ListenerStep::Continue,
        };
    }
    let (Ok(control), Ok(routes), Some(document)) = (
        ExactControl::deserialize(&json["exact_control"]),
        BTreeMap::<String, Uuid>::deserialize(&json["expected_connections"]),
        document,
    ) else {
        return ListenerStep::Continue;
    };
    if expected_user_id != Some(control.account_id)
        || expected_auth_generation != Some(control.auth_generation)
        || routes != control.expected_connections
        || control.kind == ExactControlKind::BlockingPresence
        || !selectors_match(json, control.kind)
        || validate_exact_control(&control, target, document).is_err()
    {
        return ListenerStep::Continue;
    }
    let roster_version = control.roster_version;
    if !json["roster_version"].is_null()
        && json["roster_version"]
            .as_i64()
            .is_none_or(|version| Some(version) != roster_version)
    {
        return ListenerStep::Continue;
    }
    let roster_annotated_stanza = match json.get("roster_annotated_stanza") {
        None | Some(Value::Null) => None,
        Some(Value::String(value))
            if roster_version.is_some()
                && value.len() <= northstar_stream::MAX_XMPP_FRAME_BYTES
                && crate::cluster_roster_push_version(value) == roster_version =>
        {
            Some(value.as_str())
        }
        Some(_) => return ListenerStep::Continue,
    };
    ListenerStep::Next((
        RosterPushOptions {
            roster_version,
            roster_annotated_stanza,
        },
        Some(control),
    ))
}

pub(in super::super) fn retryable_presence_kind(kind: ExactControlKind) -> bool {
    matches!(
        kind,
        ExactControlKind::UnavailablePresence | ExactControlKind::TeardownUnavailable
    )
}

fn selectors_match(json: &Value, kind: ExactControlKind) -> bool {
    use ExactControlKind::*;

    [
        ("roster_requested_only", kind == RosterPush),
        ("blocklist_requested_only", kind == BlocklistPush),
        ("privacy_requested_only", kind == PrivacyPush),
        ("presence_subscription", kind == SubscriptionPresence),
        ("current_presence_replay", kind == CurrentPresenceReplay),
        ("carbons_only", false),
        ("mix_capable_only", false),
        ("transport_receipt_required", false),
        ("mix_transport_receipt_required", false),
    ]
    .into_iter()
    .all(|(field, expected)| match json.get(field) {
        None => !expected,
        Some(value) => value.as_bool() == Some(expected),
    }) && ["delivery", "carbon_muc_room", "carbon_muc_nick"]
        .into_iter()
        .all(|field| json[field].is_null())
}

#[cfg(test)]
impl<A: crate::ClusterAdapters> crate::listener_dispatch::ClusterListenerDispatch<A> {
    pub(crate) async fn test_exact_control_delivery(
        &self,
        admission: &crate::ClusterListenerAdmission,
        policy: &crate::ClusterListenerMessagePolicy<A>,
        mix_caps: &crate::listener_mix_caps::ClusterListenerMixCaps,
        json: &Value,
    ) -> Option<(usize, Option<String>)> {
        use super::super::{envelope::prepare_listener_command, presence, ListenerCommand};
        use super::{fan_out_direct_delivery, resolve_stanza_delivery, validate_direct_delivery};

        let ListenerStep::Next(ListenerCommand {
            target, mut turn, ..
        }) = prepare_listener_command(admission, json, crate::DELIVERY_CONTRACT_PROTOCOL_VERSION)
        else {
            return None;
        };
        let stanza = json["stanza"].as_str()?;
        let ListenerStep::Next((parsed_stanza, authority)) =
            presence::validate_stanza_presence(admission, policy, "node-b", json, target, stanza)
                .await
        else {
            return None;
        };
        let ListenerStep::Next((delivery, _)) = resolve_stanza_delivery(
            policy,
            json,
            target,
            stanza,
            &parsed_stanza,
            (false, false),
            &mut turn,
        )
        .await
        else {
            return None;
        };
        let ListenerStep::Next(options) =
            validate_direct_delivery(json, target, &parsed_stanza, authority, &delivery)
        else {
            return None;
        };
        fan_out_direct_delivery(
            self, policy, mix_caps, target, &delivery, &options, &mut turn,
        )
        .await;
        Some((turn.delivered, turn.accepted_full_jid))
    }
}
