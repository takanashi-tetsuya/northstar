//! Signed publication, correlated control sending, envelope verification and pending acknowledgements.

use super::*;

/// Shared signed command publication without listener replay, database, or
/// session-routing authority. Only cluster-owned projections use this signer.
#[derive(Clone)]
pub(super) struct ClusterSignedPublisher {
    pub(super) pool: Option<Pool<RedisConnectionManager>>,
    pub(super) namespace: String,
    pub(super) key_prefix: String,
    pub(super) node_id: String,
    pub(super) security: Option<Arc<northstar_security::cluster_bus::ClusterSecurityConfig>>,
    pub(super) connection_uuid: uuid::Uuid,
    pub(super) instance_epoch: Arc<AtomicI64>,
    pub(super) authorized_instances: Arc<dashmap::DashMap<String, AuthorizedClusterInstance>>,
    pub(super) health: Arc<ClusterHealth>,
    pub(super) listener_rotation: Arc<tokio::sync::Notify>,
    pub(super) failure_policy: Option<northstar_security::cluster_bus::ClusterFailurePolicy>,
    pub(super) publication_gate: Arc<tokio::sync::RwLock<()>>,
}

/// Bounded correlated control ACKs shared by the manager and teardown notifier.
/// It can publish authenticated controls but cannot discover or mutate routes.
#[derive(Clone)]
pub(super) struct ClusterCorrelatedControlSender {
    pub(super) publisher: ClusterSignedPublisher,
    pub(super) transport_ready: bool,
    pub(super) pending_ack_slots: Arc<tokio::sync::Semaphore>,
    pub(super) pending_acks: Arc<dashmap::DashMap<String, PendingClusterAck>>,
}

impl ClusterSignedPublisher {
    pub(super) fn is_enabled(&self) -> bool {
        self.pool.is_some()
    }

    pub(super) fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    pub(super) async fn active_muc_nodes(&self, room_jid: &str) -> Result<Vec<String>> {
        let Some(pool) = &self.pool else {
            return Ok(Vec::new());
        };
        let room = northstar_xmpp_types::jid::canonicalize_bare(room_jid)?;
        let mut conn = pool.get().await?;
        let key = self.key(format!("muc_nodes:{room}"));
        // Fan-out uses bounded live-node hints; full reconciliation belongs
        // to maintenance and explicit room reads. The peer limit includes one
        // extra slot for this process.
        let script = redis::Script::new(
            r#"
            if redis.call('scard', KEYS[1]) > tonumber(ARGV[2]) then
                return redis.error_reply('MUC routing node hint limit exceeded')
            end
            local nodes = redis.call('smembers', KEYS[1])
            for _, node in ipairs(nodes) do
                if #node == 0 or #node > tonumber(ARGV[3]) then
                    return redis.error_reply('MUC routing node hint has an invalid length')
                end
            end
            local active = {}
            local stale = {}
            for _, node in ipairs(nodes) do
                if redis.call('get', ARGV[1] .. node .. ':alive') then
                    table.insert(active, node)
                else
                    table.insert(stale, node)
                end
            end
            for _, node in ipairs(stale) do
                redis.call('srem', KEYS[1], node)
            end
            return active
            "#,
        );
        let mut nodes: Vec<String> = script
            .key(key)
            .arg(self.key("node:".to_owned()))
            .arg(northstar_security::cluster_bus::MAX_PEERS + 1)
            .arg(northstar_security::cluster_bus::MAX_NODE_ID_BYTES)
            .invoke_async(&mut *conn)
            .await?;
        nodes.sort_unstable();
        Ok(nodes)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn send_muc_presence_with_status(
        &self,
        room_jid: &str,
        occupant: &crate::services::muc::SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
        removal_status: Option<u16>,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let nodes = self.active_muc_nodes(room_jid).await?;
        let payload = serde_json::json!({
            "target": room_jid,
            "muc_presence": true,
            "occupant": occupant,
            "unavailable": unavailable,
            "created": created,
            "id": id,
            "removal_status": removal_status,
            "actor_nick": actor_nick,
            "reason": reason,
        });
        let mut conn = pool.get().await?;
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    pub(super) fn process_instance_token(&self) -> Result<String> {
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        anyhow::ensure!(epoch >= 1, "cluster process instance is not authoritative");
        Ok(format!("{}.{}", self.connection_uuid.simple(), epoch))
    }

    pub(super) fn process_alive_key(&self) -> Result<String> {
        Ok(self.key(format!(
            "node_instance:{}:{}:alive",
            self.node_id,
            self.process_instance_token()?
        )))
    }

    pub(super) fn sign_payload(
        &self,
        destination_node: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<String> {
        let security = self
            .security
            .as_ref()
            .context("cluster signer is not configured")?;
        let destination = self
            .authorized_instances
            .get(destination_node)
            .context("cluster destination process authority is unavailable")?;
        anyhow::ensure!(
            destination.valid_until > Instant::now() && destination.refresh_until > Instant::now(),
            "cluster destination process authority is stale"
        );
        let kind = northstar_security::cluster_bus::infer_kind(&payload)?;
        let envelope = northstar_security::cluster_bus::SignedClusterEnvelope::sign(
            &security.signer(),
            &self.namespace,
            &self.node_id,
            destination_node,
            destination.instance_uuid,
            destination.instance_epoch,
            &destination.signing_key_id,
            destination.signing_key_epoch,
            channel,
            kind,
            self.connection_uuid,
            self.instance_epoch.load(Ordering::Acquire),
            payload,
            chrono::Utc::now().timestamp(),
        )?;
        let encoded =
            serde_json::to_string(&envelope).context("could not encode signed cluster envelope")?;
        anyhow::ensure!(
            encoded.len() <= MAX_CLUSTER_PAYLOAD_BYTES,
            "cluster envelope exceeds the transport limit"
        );
        Ok(encoded)
    }

    pub(super) async fn publish_signed(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        destination_node: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<i32> {
        let _publication = self.publication_gate.read().await;
        admit_health(&self.health, ClusterOperation::VolatileDelivery)?;
        let encoded = self.sign_payload(destination_node, channel, payload)?;
        match conn.publish(channel, encoded).await {
            Ok(receivers) if receivers > 0 => Ok(receivers),
            Ok(_) => {
                let failure =
                    anyhow::anyhow!("signed cluster publish had no authoritative subscriber");
                self.record_control_plane_failure(&failure);
                Err(failure)
            }
            Err(error) => {
                let failure = anyhow::Error::new(error).context("signed cluster publish failed");
                self.record_control_plane_failure(&failure);
                Err(failure)
            }
        }
    }

    pub(super) fn record_control_plane_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.is_enabled(),
            self.failure_policy,
            ClusterFailureClass::RedisCommand,
            error,
        );
    }
}

impl ClusterCorrelatedControlSender {
    pub(super) async fn send_control_to_node(
        &self,
        node_id: &str,
        target: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let acknowledgement = self
            .send_control_to_node_ack(node_id, target, payload)
            .await?;
        anyhow::ensure!(
            acknowledgement.control_processed == Some(true),
            "cluster control was rejected by its authoritative receiver"
        );
        Ok(())
    }

    pub(super) async fn send_control_to_node_ack(
        &self,
        node_id: &str,
        target: &str,
        mut payload: serde_json::Value,
    ) -> Result<NodeDeliveryAck> {
        let Some(pool) = self
            .publisher
            .pool
            .as_ref()
            .filter(|_| self.transport_ready)
        else {
            anyhow::bail!("cluster control requested without an active cluster transport");
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let nonce = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let mut conn = pool.get().await?;
        let peer_version: Option<String> = conn
            .get(self.publisher.key(format!("node:{node_id}:alive")))
            .await?;
        if !supports_current_cluster_protocol(peer_version.as_deref()) {
            if peer_version.is_some() {
                note_incompatible_peer_version(
                    &self.publisher.health,
                    node_id,
                    peer_version.as_deref(),
                );
            }
            anyhow::bail!("cluster peer does not support authenticated current-version controls");
        }
        let Some(fields) = payload.as_object_mut() else {
            anyhow::bail!("cluster control payload is not an object");
        };
        anyhow::ensure!(
            fields.get("target").and_then(serde_json::Value::as_str) == Some(target),
            "cluster control target mismatch"
        );
        fields.insert("request_id".to_owned(), request_id.clone().into());
        fields.insert("ack_nonce".to_owned(), nonce.clone().into());
        fields.insert("protocol_version".to_owned(), NODE_PROTOCOL_VERSION.into());
        let channel = self.publisher.key(format!("node:{node_id}"));
        let mut acknowledgement = register_pending_ack_in(
            &self.pending_ack_slots,
            &self.pending_acks,
            &request_id,
            node_id,
            &nonce,
        )?;
        let result = async {
            let receivers = self
                .publisher
                .publish_signed(&mut conn, node_id, &channel, payload)
                .await?;
            // Keep only the bounded registration while the peer publishes its
            // ACK; the listener needs this pool to send that ACK.
            drop(conn);
            if receivers == 0 {
                let error = anyhow::anyhow!("cluster control had no subscriber");
                self.publisher.record_control_plane_failure(&error);
                return Err(error);
            }
            let deadline = tokio::time::Instant::now() + DELIVERY_ACK_TIMEOUT;
            loop {
                let Some(ack) = tokio::time::timeout_at(deadline, acknowledgement.recv())
                    .await
                    .ok()
                    .flatten()
                else {
                    let error = anyhow::anyhow!("cluster control acknowledgement timed out");
                    self.publisher.record_control_plane_failure(&error);
                    return Err(error);
                };
                if ack.control_processed.is_some() {
                    return Ok(ack);
                }
            }
        }
        .await;
        result
    }
}

pub(super) fn dispatch_pending_ack(
    pending_acks: &dashmap::DashMap<String, PendingClusterAck>,
    source_node: &str,
    payload: serde_json::Value,
) -> bool {
    let Ok(ack) = serde_json::from_value::<NodeDeliveryAck>(payload) else {
        return false;
    };
    let Some(pending) = pending_acks.get(&ack.request_id) else {
        return false;
    };
    if pending.source_node != source_node
        || pending.nonce != ack.nonce
        || pending.source_node != ack.node_id
    {
        return false;
    }
    pending.sender.try_send(ack).is_ok()
}

#[derive(Clone)]
pub(super) struct PendingClusterAck {
    pub(super) source_node: String,
    pub(super) nonce: String,
    pub(super) registration_id: uuid::Uuid,
    pub(super) sender: tokio::sync::mpsc::Sender<NodeDeliveryAck>,
}

pub(super) struct PendingAckRegistration {
    pub(super) request_id: String,
    pub(super) registration_id: uuid::Uuid,
    pub(super) entries: Arc<dashmap::DashMap<String, PendingClusterAck>>,
    pub(super) receiver: tokio::sync::mpsc::Receiver<NodeDeliveryAck>,
    pub(super) _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PendingAckRegistration {
    pub(super) async fn recv(&mut self) -> Option<NodeDeliveryAck> {
        self.receiver.recv().await
    }
}

impl Drop for PendingAckRegistration {
    fn drop(&mut self) {
        let registration_id = self.registration_id;
        self.entries.remove_if(&self.request_id, |_, pending| {
            pending.registration_id == registration_id
        });
    }
}

pub(super) fn register_pending_ack_in(
    slots: &Arc<tokio::sync::Semaphore>,
    entries: &Arc<dashmap::DashMap<String, PendingClusterAck>>,
    request_id: &str,
    source_node: &str,
    nonce: &str,
) -> Result<PendingAckRegistration> {
    let permit = Arc::clone(slots)
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("cluster acknowledgement capacity is exhausted"))?;
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let registration_id = uuid::Uuid::new_v4();
    match entries.entry(request_id.to_owned()) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(PendingClusterAck {
                source_node: source_node.to_owned(),
                nonce: nonce.to_owned(),
                registration_id,
                sender,
            });
        }
        dashmap::mapref::entry::Entry::Occupied(_) => {
            anyhow::bail!("cluster acknowledgement request ID collided");
        }
    }
    Ok(PendingAckRegistration {
        request_id: request_id.to_owned(),
        registration_id,
        entries: Arc::clone(entries),
        receiver,
        _permit: permit,
    })
}

impl ClusterManager {
    #[cfg(test)]
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

    #[cfg(test)]
    pub(super) fn dispatch_pending_ack(
        &self,
        source_node: &str,
        payload: serde_json::Value,
    ) -> bool {
        dispatch_pending_ack(&self.pending_acks, source_node, payload)
    }

    pub(super) async fn publish_signed(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        destination_node: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<i32> {
        self.signed_publisher()
            .publish_signed(conn, destination_node, channel, payload)
            .await
    }

    #[cfg(test)]
    pub(super) fn verify_signed_payload(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
    ) -> Result<northstar_security::cluster_bus::SignedClusterEnvelope> {
        self.verify_signed_payload_inner(raw, channel, expected_source, true)
    }

    #[cfg(test)]
    pub(super) fn verify_signed_payload_inner(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
        remember_replay: bool,
    ) -> Result<northstar_security::cluster_bus::SignedClusterEnvelope> {
        let envelope =
            self.listener_security()
                .verify_current_envelope(raw, channel, expected_source)?;
        if remember_replay {
            self.remember_envelope_replay(&envelope)?;
        }
        Ok(envelope)
    }

    #[cfg(test)]
    pub(super) fn remember_envelope_replay(
        &self,
        envelope: &northstar_security::cluster_bus::SignedClusterEnvelope,
    ) -> Result<()> {
        let replay_key = format!(
            "{}:{}:{}:{}",
            envelope.source_node,
            envelope.connection_epoch,
            envelope.connection_uuid,
            envelope.event_id
        );
        let now = chrono::Utc::now().timestamp();
        let accept_until = envelope
            .expires_at
            .saturating_add(northstar_security::cluster_bus::CLOCK_SKEW_SECONDS);
        self.remember_replay_key(replay_key, accept_until, now, MAX_REPLAY_ENTRIES)
    }

    #[cfg(test)]
    pub(super) fn remember_replay_key(
        &self,
        replay_key: String,
        accept_until: i64,
        now: i64,
        limit: usize,
    ) -> Result<()> {
        anyhow::ensure!(limit > 0, "cluster replay cache limit must be positive");
        // DashMap makes an individual entry operation atomic, but a separate
        // len-check followed by an insert is not an atomic capacity admission.
        // A signed peer can submit many envelopes concurrently, so serialize
        // expiry, capacity reservation and insertion under one short-lived
        // process-local gate. No await or external I/O occurs while held.
        let _admission = self
            .replay_cache_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("cluster replay cache admission gate was poisoned"))?;
        if let Some(existing) = self.replay_cache.get(&replay_key) {
            let still_accepted = *existing >= now;
            drop(existing);
            if still_accepted {
                self.health
                    .replay_rejections
                    .fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("cluster envelope replay rejected");
            }
            self.replay_cache.remove(&replay_key);
        }
        if self.replay_cache.len() >= limit
            && now > self.replay_cache_next_expiry.load(Ordering::Relaxed)
        {
            #[cfg(test)]
            self.replay_cache_sweeps.fetch_add(1, Ordering::Relaxed);
            let mut next_expiry = i64::MAX;
            self.replay_cache.retain(|_, accept_until| {
                let retained = *accept_until >= now;
                if retained {
                    next_expiry = next_expiry.min(*accept_until);
                }
                retained
            });
            self.replay_cache_next_expiry
                .store(next_expiry, Ordering::Relaxed);
        }
        anyhow::ensure!(
            self.replay_cache.len() < limit,
            "cluster replay cache is at capacity"
        );
        match self.replay_cache.entry(replay_key) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(accept_until);
                self.replay_cache_next_expiry
                    .fetch_min(accept_until, Ordering::Relaxed);
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                self.health
                    .replay_rejections
                    .fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("cluster envelope replay rejected");
            }
        }
        Ok(())
    }
}
