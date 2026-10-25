//! Manage bounded listener responses, continuations, authority validation, and acknowledgement completion.

use super::*;

#[derive(Default)]
pub(in crate::cluster) struct ListenerContinuations {
    pub(in crate::cluster) pending: VecDeque<BoxFuture<'static, Result<()>>>,
}

impl ListenerContinuations {
    pub(in crate::cluster) fn push(
        &mut self,
        work: impl std::future::Future<Output = Result<()>> + Send + 'static,
    ) -> Result<()> {
        anyhow::ensure!(
            self.pending.len() < MAX_LISTENER_CONTINUATIONS,
            "Redis listener response continuation capacity exceeded"
        );
        self.pending.push_back(work.boxed());
        Ok(())
    }

    pub(in crate::cluster) async fn next(&mut self) -> Option<Result<()>> {
        // Poll only the first response batch, preserving remote presence
        // transition order. Cancelling this wait leaves that batch in place.
        let result = self.pending.front_mut()?.await;
        self.pending.pop_front();
        Some(result)
    }
}

pub(in crate::cluster) struct ListenerResponse {
    pub(in crate::cluster) node_id: String,
    pub(in crate::cluster) recipient: String,
    pub(in crate::cluster) stanza: String,
    pub(in crate::cluster) presence_authority: Option<ClusterPresenceAuthority>,
}

#[derive(Default)]
pub(in crate::cluster) struct ListenerResponses {
    pub(in crate::cluster) items: Vec<ListenerResponse>,
    pub(in crate::cluster) bytes: usize,
}

impl ListenerResponses {
    pub(in crate::cluster) fn push(&mut self, response: ListenerResponse) -> Result<()> {
        let bytes = self
            .bytes
            .saturating_add(response.node_id.len())
            .saturating_add(response.recipient.len())
            .saturating_add(response.stanza.len());
        anyhow::ensure!(
            self.items.len() < MAX_PENDING_CLUSTER_ACKS && bytes <= MAX_CLUSTER_PAYLOAD_BYTES,
            "Redis listener response batch exceeded its count or byte budget"
        );
        self.items.push(response);
        self.bytes = bytes;
        Ok(())
    }
}

pub(in crate::cluster) struct ListenerCommandAuthority {
    pub(in crate::cluster) generation: u64,
    pub(in crate::cluster) rotation_epoch: u64,
    pub(in crate::cluster) envelope: northstar_security::cluster_bus::SignedClusterEnvelope,
}

impl ListenerCommandAuthority {
    pub(in crate::cluster) fn validate(
        &self,
        admission: &ClusterListenerAdmission,
        security: &ClusterListenerSecurity,
    ) -> Result<()> {
        admission.validate_generation(self.generation, self.rotation_epoch)?;
        // Recheck expiry and current source key/process authority after deferred
        // work. Replay admission already happened once in the reader.
        security.validate_verified_envelope(&self.envelope)?;
        Ok(())
    }
}

pub(in crate::cluster) fn validate_listener_generation_health(
    health: &ClusterHealth,
    generation: u64,
    rotation_epoch: u64,
) -> Result<()> {
    let _transition = health
        .failure_since
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    anyhow::ensure!(
        health.effective_state() != CLUSTER_SHUTDOWN_REQUIRED
            && !health.transition_pending()
            && health.listener_rotation_epoch.load(Ordering::Acquire) == rotation_epoch
            && health.listener_generation.load(Ordering::Acquire) == generation
            && !health.listener_requires_rotation(generation),
        "Redis listener response belongs to a retired listener generation"
    );
    Ok(())
}

pub(super) async fn publish_listener_ack(
    admission: &ClusterListenerAdmission,
    security: &ClusterListenerSecurity,
    source_node: &str,
    ack: NodeDeliveryAck,
    authority: &ListenerCommandAuthority,
) -> Result<()> {
    security
        .publish_ack(admission, source_node, ack, authority)
        .await
}

pub(super) struct ListenerResponseContext {
    pub(super) admission: Arc<ClusterListenerAdmission>,
    pub(super) security: Arc<ClusterListenerSecurity>,
    pub(super) message_policy: Arc<ClusterListenerMessagePolicy>,
    pub(super) sender: Arc<ClusterNodeDelivery>,
}

pub(super) async fn complete_listener_responses(
    context: ListenerResponseContext,
    authority: ListenerCommandAuthority,
    responses: ListenerResponses,
    source_node: String,
    mut ack: Option<NodeDeliveryAck>,
) -> Result<()> {
    for response in responses.items {
        authority.validate(&context.admission, &context.security)?;
        let result = if let Some(presence_authority) = response.presence_authority {
            context
                .sender
                .send_current_presence_replay(
                    &response.node_id,
                    &response.recipient,
                    &response.stanza,
                    presence_authority,
                )
                .await
        } else {
            context
                .sender
                .send_available_presence(&response.node_id, &response.recipient, &response.stanza)
                .await
        };
        match result {
            Ok(accepted) => {
                if let Some(ack) = &mut ack {
                    ack.delivered += usize::from(accepted);
                }
            }
            Err(error) => {
                if response.presence_authority.is_some() {
                    context.message_policy.presence_probe_failed();
                }
                return Err(error.context("cluster listener remote presence response failed"));
            }
        }
    }
    authority.validate(&context.admission, &context.security)?;
    if let Some(ack) = ack {
        publish_listener_ack(
            &context.admission,
            &context.security,
            &source_node,
            ack,
            &authority,
        )
        .await?;
    }
    Ok(())
}
