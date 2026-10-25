//! Node-addressed delivery: MIX hand-off, privacy and exclusion filters, and the node and unavailable delivery capabilities.

use super::*;

/// The remote cluster worker owns a concrete C2S route while awaiting a
/// typed MIX hand-off.  If the request task is cancelled or the driver drops
/// its completion channel, the route is torn down before an old queued item
/// can become visible after its database lease is released for retry.
pub(super) struct PendingClusterMixHandoff {
    pub(super) sender: crate::xmpp::outbound::OutboundSender,
    pub(super) disconnect: CancellationToken,
    pub(super) completed: bool,
}

impl PendingClusterMixHandoff {
    pub(super) fn new(
        sender: crate::xmpp::outbound::OutboundSender,
        disconnect: CancellationToken,
    ) -> Self {
        Self {
            sender,
            disconnect,
            completed: false,
        }
    }

    pub(super) fn mark_completed(&mut self) {
        self.completed = true;
    }
}

impl Drop for PendingClusterMixHandoff {
    fn drop(&mut self) {
        if !self.completed {
            self.sender.disconnect_backpressured_transport();
            self.disconnect.cancel();
        }
    }
}

/// Enqueue an exact remote MIX source and wait for a typed durable boundary.
/// There is intentionally no synthetic ownership timeout: a socket writer
/// fences the source before bytes, while SM and BOSH persist it.  Cancellation
/// closes only this route and leaves the database fence reclaimable.
pub(super) async fn try_send_cluster_mix_transport(
    sender: &crate::xmpp::outbound::OutboundSender,
    disconnect: &CancellationToken,
    stanza: String,
    source: crate::xmpp::outbound::MixDelivery,
) -> Result<crate::xmpp::outbound::MixTransportCompletion> {
    let receiver = match sender.try_send_durable_mix(stanza, source) {
        Ok(receiver) => receiver,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            sender.disconnect_backpressured_transport();
            disconnect.cancel();
            anyhow::bail!("remote MIX resource output queue is full");
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            sender.disconnect_backpressured_transport();
            disconnect.cancel();
            anyhow::bail!("remote MIX resource output queue is closed");
        }
    };
    let mut pending = PendingClusterMixHandoff::new(sender.clone(), disconnect.clone());
    let completion = receiver
        .await
        .context("remote MIX resource closed before durable hand-off")?;
    pending.mark_completed();
    Ok(completion)
}

/// Privacy lists are resource scoped, while both Carbon wrappers are addressed
/// between resources of the same account. The policy peer must therefore come
/// from the forwarded stanza: `from` for a received Carbon and `to` for a sent
/// Carbon. Looking only at the outer wrapper would turn every sent Carbon into
/// apparent self-traffic and bypass a deny rule on another cluster node.
pub(super) fn delivery_privacy_peer(
    document: &roxmltree::Document<'_>,
    carbons_only: bool,
) -> Option<(String, crate::db::PrivacyStanzaKind)> {
    let root = document.root_element();
    let kind = match root.tag_name().name() {
        "message" => crate::db::PrivacyStanzaKind::Message,
        "iq" => crate::db::PrivacyStanzaKind::Iq,
        "presence" => crate::db::PrivacyStanzaKind::PresenceIn,
        _ => return None,
    };
    let peer = if carbons_only {
        let mut wrappers = root.children().filter(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:xmpp:carbons:2")
                && matches!(child.tag_name().name(), "sent" | "received")
        });
        let wrapper = wrappers.next()?;
        if wrappers.next().is_some() {
            return None;
        }
        let mut forwarded_nodes = wrapper.children().filter(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:xmpp:forward:0")
                && child.tag_name().name() == "forwarded"
        });
        let forwarded = forwarded_nodes.next()?;
        if forwarded_nodes.next().is_some() {
            return None;
        }
        let mut messages = forwarded.children().filter(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("jabber:client")
                && child.tag_name().name() == "message"
        });
        let message = messages.next()?;
        if messages.next().is_some() {
            return None;
        }
        match wrapper.tag_name().name() {
            "received" => message.attribute("from"),
            "sent" => message.attribute("to"),
            _ => None,
        }
    } else {
        root.attribute("from")
    };
    northstar_xmpp_types::jid::canonicalize(peer?)
        .ok()
        .map(|peer| (peer, kind))
}

pub(super) fn delivery_exclusions(json: &serde_json::Value) -> HashSet<String> {
    if let Some(values) = json["exclude_jids"]
        .as_array()
        .filter(|values| values.len() <= MAX_DELIVERY_EXCLUSIONS)
    {
        let parsed = values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .and_then(|jid| northstar_xmpp_types::jid::canonical_session_key(jid).ok())
            })
            .collect::<Option<HashSet<_>>>();
        if let Some(parsed) = parsed {
            return parsed;
        }
    }
    json["exclude_jid"]
        .as_str()
        .and_then(|jid| northstar_xmpp_types::jid::canonical_session_key(jid).ok())
        .into_iter()
        .collect()
}

pub(super) fn delivery_carbon_muc_scope(
    json: &serde_json::Value,
) -> Result<Option<(String, String)>, ()> {
    match (
        json["carbon_muc_room"].as_str(),
        json["carbon_muc_nick"].as_str(),
    ) {
        (None, None) => Ok(None),
        (Some(room), Some(nick)) => Ok(Some((
            northstar_xmpp_types::jid::canonicalize_bare(room).map_err(|_| ())?,
            crate::services::xml_util::prepare_muc_nick(nick).map_err(|_| ())?,
        ))),
        _ => Err(()),
    }
}

/// Signed, acknowledged stanza delivery. This projection can neither mutate
/// session routes nor consume listener replay authority.
#[derive(Clone)]
pub(crate) struct ClusterNodeDelivery {
    pub(super) publisher: ClusterSignedPublisher,
    pub(super) pool: Option<Pool<RedisConnectionManager>>,
    pub(super) client: Option<redis::Client>,
    pub(super) health: Arc<ClusterHealth>,
    pub(super) pending_ack_slots: Arc<tokio::sync::Semaphore>,
    pub(super) pending_acks: Arc<dashmap::DashMap<String, PendingClusterAck>>,
}

#[derive(Clone)]
pub(crate) struct ClusterUnavailableDelivery {
    pub(super) routes: ClusterListenerPresenceRoutes,
    pub(super) sender: ClusterNodeDelivery,
}

impl ClusterUnavailableDelivery {
    /// Preserve PostgreSQL route order and require the signed delivery ACK
    /// before considering a cleanup unavailable notification complete.
    pub(crate) async fn send_unavailable_to_remote_nodes(
        &self,
        target_jid: &str,
        stanza: &str,
        exclude_jid: &str,
        bare_target: bool,
    ) -> Result<()> {
        for node_id in self.routes.lookup_nodes(target_jid).await? {
            if node_id == self.routes.node_id {
                continue;
            }
            let exclusions = [exclude_jid];
            let receipt = self
                .sender
                .send_to_node_receipt(
                    &node_id,
                    target_jid,
                    stanza,
                    NodeDeliveryOptions {
                        available_only: bare_target,
                        exclude_jids: &exclusions,
                        ..NodeDeliveryOptions::default()
                    },
                )
                .await?;
            anyhow::ensure!(
                receipt.acknowledged,
                "cluster presence delivery was not acknowledged"
            );
        }
        Ok(())
    }
}

impl ClusterNodeDelivery {
    pub(crate) async fn send_mix(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        source: Option<crate::xmpp::outbound::MixDelivery>,
    ) -> Result<NodeDeliveryReceipt> {
        self.send_to_node_receipt(
            node_id,
            target_jid,
            stanza,
            NodeDeliveryOptions {
                mix_capable_only: true,
                mix_transport_receipt_required: source.is_some(),
                mix_delivery: source,
                ..NodeDeliveryOptions::default()
            },
        )
        .await
    }

    pub(crate) async fn send_mix_exact_account(
        &self,
        node_id: &str,
        target_full_jid: &str,
        stanza: &str,
        expected_user_id: uuid::Uuid,
    ) -> Result<bool> {
        let target = northstar_xmpp_types::jid::CanonicalJid::parse(target_full_jid)?;
        anyhow::ensure!(
            target.resourcepart().is_some(),
            "exact cluster delivery requires a full JID"
        );
        let canonical_target = target.to_string();
        let document = roxmltree::Document::parse(stanza)
            .context("exact cluster delivery requires one valid XML stanza")?;
        let root = document.root_element();
        anyhow::ensure!(
            root.tag_name().name() == "iq"
                && root.tag_name().namespace() == Some("jabber:client")
                && matches!(root.attribute("type"), Some("result" | "error"))
                && root.attribute("id").is_some_and(|id| !id.is_empty())
                && root.attribute("to").is_some_and(|to| {
                    northstar_xmpp_types::jid::canonical_session_key(to)
                        .ok()
                        .as_deref()
                        == Some(canonical_target.as_str())
                }),
            "exact cluster delivery must be an IQ addressed to the target resource"
        );
        let receipt = self
            .send_to_node_receipt(
                node_id,
                target_full_jid,
                stanza,
                NodeDeliveryOptions {
                    expected_user_id: Some(expected_user_id),
                    transport_receipt_required: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?;
        anyhow::ensure!(
            receipt.acknowledged,
            "exact cluster delivery was not acknowledged"
        );
        Ok(receipt.delivered)
    }

    pub(crate) async fn send_pubsub_notification(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(node_id, target_jid, stanza, NodeDeliveryOptions::default())
            .await?
            .delivered)
    }

    pub(crate) async fn send_roster_push(
        &self,
        node_id: &str,
        target_jid: &str,
        expected_user_id: uuid::Uuid,
        roster_version: i64,
        stanza: &str,
        annotated_stanza: Option<&str>,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    roster_requested_only: true,
                    expected_user_id: Some(expected_user_id),
                    roster_version: Some(roster_version),
                    roster_annotated_stanza: annotated_stanza,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub(crate) async fn send_account_removal_presence(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(node_id, target_jid, stanza, NodeDeliveryOptions::default())
            .await?
            .delivered)
    }

    pub(crate) async fn send_available_presence(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub(crate) async fn send_current_presence_replay(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only: true,
                    expected_user_id: Some(authority.recipient_id),
                    expected_auth_generation: Some(authority.recipient_auth_generation),
                    presence_authority: Some(authority),
                    presence_delivery: Some(ClusterPresenceDelivery::CurrentReplay),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub(super) fn key(&self, suffix: String) -> String {
        self.publisher.key(suffix)
    }

    pub(super) fn admit(&self, operation: ClusterOperation) -> Result<()> {
        admit_health(&self.health, operation)
    }

    pub(super) fn note_incompatible_peer_version(&self, node_id: &str, observed: Option<&str>) {
        note_incompatible_peer_version(&self.health, node_id, observed);
    }

    pub(super) fn record_control_plane_failure(&self, error: &anyhow::Error) {
        self.publisher.record_control_plane_failure(error);
    }

    pub(super) fn register_pending_ack(
        &self,
        request_id: &str,
        source_node: &str,
        nonce: &str,
    ) -> Result<PendingAckRegistration> {
        register_pending_ack_in(
            &self.pending_ack_slots,
            &self.pending_acks,
            request_id,
            source_node,
            nonce,
        )
    }

    pub(super) async fn publish_signed(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        destination_node: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<i32> {
        self.publisher
            .publish_signed(conn, destination_node, channel, payload)
            .await
    }

    pub(super) async fn send_to_node_receipt(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        options: NodeDeliveryOptions<'_>,
    ) -> Result<NodeDeliveryReceipt> {
        anyhow::ensure!(
            !options.roster_requested_only
                || (options.expected_user_id.is_some() && options.roster_version.is_some()),
            "cluster roster delivery requires an exact account and version fence"
        );
        anyhow::ensure!(
            options.roster_annotated_stanza.is_none() || options.roster_requested_only,
            "annotated roster payload cannot be used for ordinary delivery"
        );
        anyhow::ensure!(
            options.presence_delivery.is_some() == options.presence_authority.is_some(),
            "cluster presence delivery requires one complete versioned authority"
        );
        if let Some(authority) = options.presence_authority {
            anyhow::ensure!(
                options.expected_user_id == Some(authority.recipient_id)
                    && options.expected_auth_generation
                        == Some(authority.recipient_auth_generation),
                "cluster presence recipient fence does not match its authority"
            );
        }
        if let Some(version) = options.roster_version {
            anyhow::ensure!(
                cluster_roster_push_version(stanza) == Some(version),
                "cluster roster payload version does not match its delivery fence"
            );
        }
        if let Some(annotated) = options.roster_annotated_stanza {
            anyhow::ensure!(
                annotated.len() <= crate::xmpp::MAX_XMPP_FRAME_BYTES,
                "annotated roster payload exceeds the stanza limit"
            );
            anyhow::ensure!(
                cluster_roster_push_version(annotated) == options.roster_version,
                "annotated cluster roster payload version does not match its delivery fence"
            );
        }
        if (self.health.transition_pending()
            || self.health.effective_state() == CLUSTER_DURABLE_DIRECT_ONLY)
            && (options.durable_delivery.is_some() || options.mix_delivery.is_some())
        {
            // The PostgreSQL row remains the only accepted projection. The
            // caller observes no live acceptance and leaves it for replay.
            return Ok(NodeDeliveryReceipt::default());
        }
        self.admit(
            if options.durable_delivery.is_some() || options.mix_delivery.is_some() {
                ClusterOperation::DurableDirect
            } else {
                ClusterOperation::VolatileDelivery
            },
        )?;
        let target_jid = northstar_xmpp_types::jid::canonicalize(target_jid)?;
        let delivery_contract = outbound_delivery_contract(
            stanza,
            &target_jid,
            options.durable_delivery,
            options.mix_delivery,
        )?;
        if options.exclude_jids.len() > MAX_DELIVERY_EXCLUSIONS {
            anyhow::bail!("too many cluster delivery exclusions");
        }
        let exclude_jids = options
            .exclude_jids
            .iter()
            .map(|jid| northstar_xmpp_types::jid::canonical_session_key(jid))
            .collect::<Result<Vec<_>>>()?;
        let carbon_muc_scope = options
            .carbon_muc_scope
            .map(|(room, nick)| {
                Ok::<_, anyhow::Error>((
                    northstar_xmpp_types::jid::canonicalize_bare(room)?,
                    crate::services::xml_util::prepare_muc_nick(nick)?,
                ))
            })
            .transpose()?;
        anyhow::ensure!(
            !(options.transport_receipt_required && options.mix_transport_receipt_required),
            "cluster delivery cannot combine exact-resource and MIX transport receipts"
        );
        if options.transport_receipt_required {
            anyhow::ensure!(
                delivery_contract.is_none()
                    && options.expected_user_id.is_some()
                    && northstar_xmpp_types::jid::CanonicalJid::parse(&target_jid)?
                        .resourcepart()
                        .is_some()
                    && !options.carbons_only
                    && !options.blocklist_requested_only
                    && !options.roster_requested_only
                    && !options.privacy_requested_only
                    && !options.mix_capable_only
                    && !options.primary
                    && !options.available_only
                    && !options.available_nonnegative_only
                    && exclude_jids.is_empty()
                    && carbon_muc_scope.is_none(),
                "transport-receipted cluster delivery requires one exact account resource"
            );
        }
        if options.mix_transport_receipt_required {
            anyhow::ensure!(
                matches!(
                    delivery_contract,
                    Some(NodeDeliveryContract::DurableMix { .. })
                ) && options.mix_capable_only
                    && northstar_xmpp_types::jid::CanonicalJid::parse(&target_jid)?
                        .resourcepart()
                        .is_none()
                    && !options.carbons_only
                    && !options.blocklist_requested_only
                    && !options.roster_requested_only
                    && !options.privacy_requested_only
                    && !options.primary
                    && !options.available_only
                    && !options.available_nonnegative_only
                    && options.expected_user_id.is_none()
                    && options.expected_auth_generation.is_none()
                    && options.roster_version.is_none()
                    && options.roster_annotated_stanza.is_none()
                    && exclude_jids.is_empty()
                    && carbon_muc_scope.is_none(),
                "MIX transport-receipted cluster delivery requires one exact bare-JID MIX source"
            );
        }
        let legacy_exclude_jid = exclude_jids.first();
        let (Some(pool), Some(_)) = (&self.pool, &self.client) else {
            return Ok(NodeDeliveryReceipt::default());
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let nonce = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let channel = self.key(format!("node:{node_id}"));
        let payload = serde_json::json!({
            "protocol_version": NODE_PROTOCOL_VERSION,
            "target": target_jid,
            "stanza": stanza,
            "delivery": delivery_contract,
            "carbons_only": options.carbons_only,
            "blocklist_requested_only": options.blocklist_requested_only,
            "roster_requested_only": options.roster_requested_only,
            "expected_user_id": options.expected_user_id,
            "expected_auth_generation": options.expected_auth_generation,
            "roster_version": options.roster_version,
            "roster_annotated_stanza": options.roster_annotated_stanza,
            "privacy_requested_only": options.privacy_requested_only,
            "mix_capable_only": options.mix_capable_only,
            "transport_receipt_required": options.transport_receipt_required,
            "mix_transport_receipt_required": options.mix_transport_receipt_required,
            "exclude_jid": legacy_exclude_jid,
            "exclude_jids": exclude_jids,
            "request_id": request_id,
            "ack_nonce": nonce,
            "primary_one_to_one": options.primary,
            "available_only": options.available_only,
            "available_nonnegative_only": options.available_nonnegative_only,
            "presence_authority_version": options
                .presence_authority
                .map(|_| PRESENCE_AUTHORITY_VERSION),
            "presence_owner_id": options.presence_authority.map(|value| value.owner_id),
            "presence_owner_auth_generation": options
                .presence_authority
                .map(|value| value.owner_auth_generation),
            "presence_recipient_id": options.presence_authority.map(|value| value.recipient_id),
            "presence_recipient_auth_generation": options
                .presence_authority
                .map(|value| value.recipient_auth_generation),
            "current_presence_replay": options.presence_delivery
                == Some(ClusterPresenceDelivery::CurrentReplay),
            "presence_subscription": options.presence_delivery
                == Some(ClusterPresenceDelivery::Subscription),
            "carbon_muc_room": carbon_muc_scope.as_ref().map(|scope| scope.0.as_str()),
            "carbon_muc_nick": carbon_muc_scope.as_ref().map(|scope| scope.1.as_str()),
        });
        let mut conn = pool.get().await?;
        let peer_version: Option<String> =
            conn.get(self.key(format!("node:{node_id}:alive"))).await?;
        if !supports_current_cluster_protocol(peer_version.as_deref()) {
            if peer_version.is_some() {
                self.note_incompatible_peer_version(node_id, peer_version.as_deref());
            }
            tracing::warn!(
                %node_id,
                peer_version = peer_version.as_deref().unwrap_or("missing"),
                "declined traffic for a peer without the authenticated current cluster protocol"
            );
            return Ok(NodeDeliveryReceipt::default());
        }
        // Older peers do not understand the MUC membership scope and would
        // fan the private-message Carbon to unrelated resources. Fail closed
        // during a rolling upgrade rather than weakening conversation
        // privacy; an ordinary Carbon remains backward compatible.
        if carbon_muc_scope.is_some() && !supports_control_ack(peer_version.as_deref()) {
            return Ok(NodeDeliveryReceipt::default());
        }
        if let Some(contract) = delivery_contract {
            if supports_delivery_contract(peer_version.as_deref()) {
                // The current peer will validate and echo the exact contract.
            } else if supports_legacy_delivery_inference(peer_version.as_deref()) {
                // Version 7 and older recover a durable fence from the
                // recipient-authoritative stanza-id. Only send traffic whose
                // explicit current-version contract is exactly representable by that old
                // algorithm. In particular, a volatile no-store stanza with
                // such an ID must wait for the rolling upgrade to finish.
                let identity =
                    crate::xmpp::outbound::recipient_delivery_identity(stanza, &target_jid);
                if !delivery_contract_compatible_with_peer(
                    peer_version.as_deref(),
                    contract,
                    identity,
                ) {
                    tracing::warn!(
                        %node_id,
                        "declined a message whose delivery contract is unsafe for a legacy cluster peer"
                    );
                    return Ok(NodeDeliveryReceipt::default());
                }
            } else {
                tracing::warn!(
                    %node_id,
                    peer_version = peer_version.as_deref().unwrap_or("missing"),
                    "declined a message for a cluster peer with an unsupported delivery protocol"
                );
                return Ok(NodeDeliveryReceipt::default());
            }
        }
        let require_correlated_ack = requires_correlated_ack(peer_version.as_deref());
        let require_delivery_contract =
            delivery_contract.is_some() && supports_delivery_contract(peer_version.as_deref());
        let mut acknowledgement = self.register_pending_ack(&request_id, node_id, &nonce)?;
        let result = async {
            let receivers = self
                .publish_signed(&mut conn, node_id, &channel, payload)
                .await?;
            drop(conn);
            if receivers == 0 {
                self.record_control_plane_failure(&anyhow::anyhow!(
                    "cluster delivery had no authoritative subscriber"
                ));
                return Ok(NodeDeliveryReceipt::default());
            }
            let deadline = tokio::time::Instant::now() + DELIVERY_ACK_TIMEOUT;
            loop {
                let Some(ack) = tokio::time::timeout_at(deadline, acknowledgement.recv())
                    .await
                    .ok()
                    .flatten()
                else {
                    self.record_control_plane_failure(&anyhow::anyhow!(
                        "cluster delivery acknowledgement timed out"
                    ));
                    return Ok(NodeDeliveryReceipt::default());
                };
                let Ok(ack_payload) = serde_json::to_string(&ack) else {
                    continue;
                };
                if let Some(receipt) = validated_delivery_ack(
                    &ack_payload,
                    DeliveryAckExpectation {
                        request_id: &request_id,
                        nonce: &nonce,
                        node_id,
                        target_jid: &target_jid,
                        primary: options.primary,
                        delivery: delivery_contract,
                        require_delivery_contract,
                        mix_capable_only: options.mix_capable_only,
                        transport_receipt_required: options.transport_receipt_required,
                        mix_transport_receipt_required: options.mix_transport_receipt_required,
                    },
                ) {
                    return Ok(receipt);
                }
                debug_assert!(require_correlated_ack);
            }
        }
        .await;
        result
    }
}
