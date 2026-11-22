//! Build acknowledgements and publish them or queue their response batch.

use super::responses::{
    complete_listener_responses, publish_listener_ack, ListenerResponseContext,
};
use super::*;
use crate::listener_dispatch::ClusterListenerDispatch;
use northstar_security::cluster_bus::SignedClusterEnvelope;

pub(super) struct ListenerAckContext<'a, A: ClusterAdapters> {
    pub(super) admission: &'a Arc<ClusterListenerAdmission>,
    pub(super) security: &'a Arc<ClusterListenerSecurity>,
    pub(super) message_policy: &'a Arc<ClusterListenerMessagePolicy<A>>,
    pub(super) dispatch: &'a ClusterListenerDispatch<A>,
    pub(super) presence_sender: &'a Arc<ClusterNodeDelivery>,
}

pub(super) async fn acknowledge_listener_command<A: ClusterAdapters>(
    context: ListenerAckContext<'_, A>,
    (candidate_generation, rotation_epoch): (u64, u64),
    envelope: SignedClusterEnvelope,
    source_node: String,
    turn: ListenerTurn,
    continuations: &mut ListenerContinuations,
) -> Result<()> {
    let ListenerAckContext {
        admission,
        security,
        message_policy,
        dispatch,
        presence_sender,
    } = context;
    let ListenerTurn {
        delivered,
        accepted_full_jid,
        mix_supported,
        mix_unsupported,
        mix_unknown,
        mix_handoff,
        control_processed,
        control_outcome,
        acknowledged_delivery,
        responses,
    } = turn;
    let json = &envelope.payload;
    let ack = json["request_id"]
        .as_str()
        .filter(|request_id| uuid::Uuid::parse_str(request_id).is_ok())
        .zip(
            json["ack_nonce"]
                .as_str()
                .filter(|nonce| (32..=128).contains(&nonce.len())),
        )
        .map(|(request_id, nonce)| NodeDeliveryAck {
            request_id: request_id.to_owned(),
            nonce: nonce.to_owned(),
            node_id: dispatch.node_id().to_owned(),
            delivered,
            accepted_full_jid,
            mix_supported,
            mix_unsupported,
            mix_unknown,
            control_processed,
            control_outcome,
            delivery: acknowledged_delivery,
            mix_handoff,
        });
    let authority = ListenerCommandAuthority {
        generation: candidate_generation,
        rotation_epoch,
        envelope,
    };
    if responses.items.is_empty() {
        if let Some(ack) = ack {
            publish_listener_ack(admission, security, &source_node, ack, &authority).await?;
        }
    } else {
        // Only remote receipt waits leave the sequential command turn.
        // Both peers can therefore execute each other's leaf deliveries
        // even when they simultaneously handle presence probes.
        continuations.push(complete_listener_responses(
            ListenerResponseContext {
                admission: Arc::clone(admission),
                security: Arc::clone(security),
                message_policy: Arc::clone(message_policy),
                sender: Arc::clone(presence_sender),
            },
            authority,
            responses,
            source_node,
            ack,
        ))?;
    }
    Ok(())
}
