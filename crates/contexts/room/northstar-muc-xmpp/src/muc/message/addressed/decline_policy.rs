use crate::ports::MucHost;
use anyhow::Result;
use northstar_room_application::room_delivery_policy::{
    PrivacyStanzaKind, RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomPolicyLiveSession,
    RoomPolicyRoute, RoomPolicySubject,
};
use uuid::Uuid;

pub(crate) struct DeclineRecipients<S> {
    pub(crate) sessions: Vec<S>,
    pub(crate) offline_allowed: bool,
}

pub(crate) async fn allowed_decline_sessions<H: MucHost>(
    host: &H,
    sessions: Vec<(String, H::Session)>,
    account_id: Uuid,
    recipient: &str,
    room: &str,
    sender: &str,
) -> Result<Option<DeclineRecipients<H::Session>>> {
    let account = RoomPolicyRoute {
        account_id,
        auth_generation: None,
        subject: RoomPolicySubject::AccountDefault,
    };
    let base = RoomDeliveryPolicyQuery {
        route: account,
        visible_peer: room,
        real_peer: Some(sender),
        kind: Some(PrivacyStanzaKind::Message),
        recipient_jid: recipient,
    };
    let candidates = sessions
        .into_iter()
        .filter_map(|(jid, target)| {
            let route = RoomPolicyLiveSession::room_policy_route(&target);
            (route.account_id == account_id).then_some((jid, target, route))
        })
        .collect::<Vec<_>>();
    let queries = std::iter::once(base)
        .chain(
            candidates
                .iter()
                .map(|(_, _, route)| RoomDeliveryPolicyQuery {
                    route: *route,
                    ..base
                }),
        )
        .collect::<Vec<_>>();
    let decisions = host.read_room_delivery_policies(&queries).await?;
    anyhow::ensure!(
        decisions.len() == queries.len(),
        "incomplete MUC decline policy"
    );
    let account_decision = decisions[0];
    if matches!(
        account_decision,
        RoomDeliveryDecision::Blocked | RoomDeliveryDecision::StaleRoute
    ) {
        return Ok(None);
    }
    let sessions = candidates
        .into_iter()
        .zip(decisions.into_iter().skip(1))
        .filter_map(|((jid, target, route), decision)| {
            (decision.allows()
                && host
                    .session_entries_for(&jid)
                    .iter()
                    .any(|(_, current)| RoomPolicyLiveSession::room_policy_route(current) == route))
            .then_some(target)
        })
        .collect();
    Ok(Some(DeclineRecipients {
        sessions,
        offline_allowed: account_decision.allows(),
    }))
}
