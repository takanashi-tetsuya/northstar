//! Send a direct stanza through the selected queue, receipt, or MIX handoff.

use super::delivery::DirectDeliveryOptions;
use super::*;
use crate::listener_dispatch::ClusterListenerDispatch;
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_stream::local_routes::session_table::LocalSessionTable;
use northstar_stream::{local_routes::session::OnlineSession, outbound};

pub(super) struct DirectDeliveryRecipient<'a> {
    pub(super) session: &'a OnlineSession,
    pub(super) jid: &'a str,
    pub(super) target: &'a str,
    pub(super) delivery: &'a String,
}

pub(super) enum DirectDeliverySend {
    Accepted(bool),
    StopFanout,
}

pub(super) async fn send_direct_delivery<A: ClusterAdapters>(
    message_policy: &ClusterListenerMessagePolicy<A>,
    dispatch: &ClusterListenerDispatch<A>,
    recipient: DirectDeliveryRecipient<'_>,
    options: &DirectDeliveryOptions<'_>,
    mix_delivery: Option<outbound::MixDelivery>,
    durable_delivery: Option<outbound::DurableDelivery>,
    mix_handoff: &mut Option<ClusterMixHandoff>,
) -> DirectDeliverySend {
    let DirectDeliveryRecipient {
        session,
        jid,
        target,
        delivery,
    } = recipient;
    let DirectDeliveryOptions {
        roster_requested_only,
        roster_version,
        roster_annotated_stanza,
        transport_receipt_required,
        mix_request_id,
        ..
    } = *options;
    let send_roster = |session: &OnlineSession| {
        let version = roster_version.expect("cluster roster shape validated before session fanout");
        let annotated = roster_annotated_stanza.map(|stanza| set_to(stanza, jid));
        match session.roster_sync.route(
            &session.roster_requested,
            &session.mix_roster_annotations,
            version,
            delivery.clone(),
            annotated,
        ) {
            northstar_roster_core::RosterPushDisposition::NotInterested => false,
            northstar_roster_core::RosterPushDisposition::Buffered => true,
            northstar_roster_core::RosterPushDisposition::Deliver(stanza) => {
                if session.sender.try_send(stanza).is_ok() {
                    true
                } else {
                    session.sender.disconnect_backpressured_transport();
                    session.disconnect.cancel();
                    false
                }
            }
            northstar_roster_core::RosterPushDisposition::Overflow => {
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                false
            }
        }
    };
    if options.expected_connections.is_some() || durable_delivery.is_some() {
        let route = ExactMessageRoute {
            full_jid: jid.to_owned(),
            account_id: session.user_id,
            auth_generation: session.auth_generation,
            connection_id: session.connection_id,
            node_id: None,
            priority: Some(session.priority.load(Ordering::Relaxed)),
            available: Some(session.available.load(Ordering::Relaxed)),
        };
        let table = LocalSessionTable::new(Arc::clone(&dispatch.account_routes.sessions));
        let accepted = table.with_exact_message_route(&route, |current| {
            if !options.priority_matches(target, current) {
                return false;
            }
            if roster_requested_only && options.exact_control.is_some() {
                return send_roster(current);
            }
            if let Some(durable) = durable_delivery {
                current
                    .sender
                    .try_send_durable(delivery.clone(), durable)
                    .is_ok()
            } else {
                current.sender.try_send(delivery.clone()).is_ok()
            }
        });
        return DirectDeliverySend::Accepted(accepted == Some(true));
    }
    let accepted = if roster_requested_only {
        send_roster(session)
    } else if let (Some(source), Some(request_id)) = (mix_delivery, mix_request_id) {
        return handoff_mix_delivery(
            message_policy,
            dispatch,
            &recipient,
            source,
            request_id,
            mix_handoff,
        )
        .await;
    } else if transport_receipt_required {
        let (receipt_tx, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
        match session
            .sender
            .try_send_with_transport_receipt(delivery.clone(), receipt_tx)
        {
            Ok(()) => {
                match tokio::time::timeout(DELIVERY_TRANSPORT_RECEIPT_TIMEOUT, receipt_rx.recv())
                    .await
                {
                    Ok(Some(())) => true,
                    Ok(None) => false,
                    Err(_) => {
                        session.sender.disconnect_backpressured_transport();
                        session.disconnect.cancel();
                        false
                    }
                }
            }
            Err(_) => {
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                false
            }
        }
    } else {
        session.sender.try_send(delivery.clone()).is_ok()
    };
    DirectDeliverySend::Accepted(accepted)
}

pub(super) async fn handoff_mix_delivery<A: ClusterAdapters>(
    message_policy: &ClusterListenerMessagePolicy<A>,
    dispatch: &ClusterListenerDispatch<A>,
    recipient: &DirectDeliveryRecipient<'_>,
    source: outbound::MixDelivery,
    request_id: uuid::Uuid,
    mix_handoff: &mut Option<ClusterMixHandoff>,
) -> DirectDeliverySend {
    let DirectDeliveryRecipient {
        session,
        delivery,
        jid,
        ..
    } = *recipient;
    let Ok(address) = northstar_room_core::mix::MixRealJid::parse(jid) else {
        return DirectDeliverySend::Accepted(false);
    };
    match message_policy
        .mix
        .outbox_claimed_recipient_account(source, &address)
        .await
    {
        Ok(Some(account_id)) if account_id == session.user_id => {}
        Ok(Some(_)) => return DirectDeliverySend::Accepted(false),
        Ok(None) => return DirectDeliverySend::StopFanout,
        Err(error) => {
            tracing::warn!(
                ?error,
                delivery_id = %source.delivery_id,
                "failed to verify remote MIX recipient account"
            );
            return DirectDeliverySend::StopFanout;
        }
    }
    // Rotate the signed source into this node's durable
    // fence before putting it on a local C2S output.  No
    // acknowledgement is emitted until that output has
    // itself transferred to its socket/SM/BOSH owner.
    let remote_source = match message_policy
        .transfer_mix_delivery(
            source,
            dispatch.node_id(),
            request_id,
            MIX_CLUSTER_HANDOFF_TTL_SECONDS,
        )
        .await
    {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!(
                ?error,
                delivery_id = %source.delivery_id,
                "failed to establish remote MIX ownership fence"
            );
            return DirectDeliverySend::StopFanout;
        }
    };
    let accepted = match try_send_cluster_mix_transport(
        &session.sender,
        &session.disconnect,
        delivery.clone(),
        remote_source,
    )
    .await
    {
        Ok(outbound::MixTransportCompletion::SocketFenced { .. }) => {
            *mix_handoff = Some(ClusterMixHandoff::SocketFenced);
            true
        }
        Ok(outbound::MixTransportCompletion::SmPersisted { .. }) => {
            *mix_handoff = Some(ClusterMixHandoff::SmPersisted);
            true
        }
        Ok(outbound::MixTransportCompletion::BoshPersisted { .. }) => {
            *mix_handoff = Some(ClusterMixHandoff::BoshPersisted);
            true
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                delivery_id = %remote_source.delivery_id,
                "remote MIX transport failed before durable ownership"
            );
            if let Err(release_error) = message_policy
                .release_mix_delivery(remote_source, dispatch.node_id(), request_id)
                .await
            {
                tracing::error!(
                    ?release_error,
                    delivery_id = %remote_source.delivery_id,
                    "failed to release unowned remote MIX hand-off"
                );
            }
            false
        }
    };
    DirectDeliverySend::Accepted(accepted)
}
