//! Session route registration and lookup, and node-addressed stanza sending.

use super::*;

impl ClusterManager {
    pub(super) async fn touch_node(&self) -> Result<()> {
        self.maintenance_redis().touch_node().await
    }

    pub async fn try_register_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        proof: crate::services::sm::SessionRouteClaimProof,
    ) -> Result<bool> {
        self.admit(ClusterOperation::NewBinding)?;
        let (full_jid, bare) = session_route_keys(full_jid)?;
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let owner_instance_epoch = self.instance_epoch.load(Ordering::Acquire);
        if !crate::db::claim_cluster_session_route(
            authority_pool,
            &self.namespace,
            &full_jid,
            &bare,
            &self.node_id,
            self.connection_uuid,
            owner_instance_epoch,
            connection_id,
            proof.into(),
            Duration::from_secs(SESSION_TTL_SECONDS),
        )
        .await?
        {
            return Ok(false);
        }
        let mut conn = pool.get().await?;
        let full_key = self.key(format!("session:{full_jid}"));
        let bare_key = self.key(format!("user_sessions:{bare}"));
        let activity_key = self.key("session_activity".to_owned());
        let instance_key = self.key(format!("session_instance:{full_jid}"));

        let script = redis::Script::new(
            r#"
            local owner = redis.call('get', KEYS[1])
            if owner and owner ~= ARGV[1] then
                local owner_alive = ARGV[3] .. ':node:' .. owner .. ':alive'
                if redis.call('exists', owner_alive) == 1 then return 0 end
            end
            redis.call('set', KEYS[1], ARGV[1], 'EX', ARGV[4])
            redis.call('set', KEYS[4], ARGV[6], 'EX', ARGV[4])
            redis.call('sadd', KEYS[2], ARGV[2])
            redis.call('expire', KEYS[2], ARGV[5])
            local now = redis.call('time')
            redis.call('zadd', KEYS[3], now[1], ARGV[2])
            return 1
            "#,
        );
        let reserved = script
            .key(&full_key)
            .key(&bare_key)
            .key(&activity_key)
            .key(&instance_key)
            .arg(&self.node_id)
            .arg(&full_jid)
            .arg(&self.key_prefix)
            .arg(SESSION_TTL_SECONDS)
            .arg(USER_SET_TTL_SECONDS)
            .arg(connection_id.to_string())
            .invoke_async::<i32>(&mut *conn)
            .await;
        match reserved {
            Ok(1) => Ok(true),
            Ok(_) => {
                let _ = crate::db::release_cluster_session_route(
                    authority_pool,
                    &self.namespace,
                    &full_jid,
                    &self.node_id,
                    self.connection_uuid,
                    owner_instance_epoch,
                    connection_id,
                )
                .await;
                Ok(false)
            }
            Err(error) => {
                let _ = crate::db::release_cluster_session_route(
                    authority_pool,
                    &self.namespace,
                    &full_jid,
                    &self.node_id,
                    self.connection_uuid,
                    owner_instance_epoch,
                    connection_id,
                )
                .await;
                Err(error.into())
            }
        }
    }

    pub async fn unregister_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> Result<()> {
        self.session_route_release()
            .release_exact_local_session_route(full_jid, connection_id)
            .await
    }

    pub async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let started = tokio::time::Instant::now();
        let result = self.listener_presence_routes().lookup_nodes(jid).await;
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis(),
            success = result.is_ok(),
            "Redis session-route lookup completed"
        );
        result
    }

    /// Enumerate canonical bare JIDs with at least one live Redis route.
    /// This is intentionally reserved for authenticated administrative
    /// statistics; normal stanza routing remains O(1) and never scans Redis.
    pub async fn online_bare_jids(&self) -> Result<std::collections::BTreeSet<String>> {
        let Some(pool) = &self.pool else {
            return Ok(std::collections::BTreeSet::new());
        };
        let mut conn = pool.get().await?;
        let prefix = self.key("user_sessions:".to_owned());
        let pattern = format!("{prefix}*");
        let mut cursor = 0u64;
        let mut online = std::collections::BTreeSet::new();
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(1000usize)
                .query_async(&mut *conn)
                .await?;
            for key in keys {
                let Some(candidate) = key.strip_prefix(&prefix) else {
                    continue;
                };
                let Ok(bare) = crate::jid::canonicalize_bare(candidate) else {
                    continue;
                };
                let full_jids: Vec<String> = conn.smembers(&key).await?;
                let mut live = false;
                for full_jid in full_jids {
                    let owner: Option<String> =
                        conn.get(self.key(format!("session:{full_jid}"))).await?;
                    if owner.is_some() {
                        live = true;
                    } else {
                        let _: usize = conn.srem(&key, &full_jid).await?;
                    }
                }
                if live {
                    online.insert(bare);
                }
            }
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        Ok(online)
    }

    pub async fn activity_bare_jids(
        &self,
        idle_seconds: u64,
        active: bool,
    ) -> Result<std::collections::BTreeSet<String>> {
        let Some(pool) = &self.pool else {
            return Ok(std::collections::BTreeSet::new());
        };
        let mut conn = pool.get().await?;
        let time: Vec<String> = redis::cmd("TIME").query_async(&mut *conn).await?;
        let now = time
            .first()
            .and_then(|value| value.parse::<i64>().ok())
            .context("Redis TIME response is invalid")?;
        let oldest = now.saturating_sub(SESSION_TTL_SECONDS as i64);
        let threshold = now.saturating_sub(idle_seconds as i64);
        let (minimum, maximum) = if active {
            (threshold.to_string(), "+inf".to_owned())
        } else {
            (oldest.to_string(), format!("({threshold}"))
        };
        let members: Vec<String> = redis::cmd("ZRANGEBYSCORE")
            .arg(self.key("session_activity".to_owned()))
            .arg(minimum)
            .arg(maximum)
            .query_async(&mut *conn)
            .await?;
        let mut users = std::collections::BTreeSet::new();
        for full_jid in members {
            let owner: Option<String> = conn.get(self.key(format!("session:{full_jid}"))).await?;
            if owner.is_none() {
                continue;
            }
            if let Ok(bare) = crate::jid::canonical_bare_key(&full_jid) {
                users.insert(bare);
            }
        }
        Ok(users)
    }

    pub async fn send_to_node(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        carbons_only: bool,
        exclude_jid: Option<&str>,
    ) -> Result<bool> {
        let exclude_jids = exclude_jid.into_iter().collect::<Vec<_>>();
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    carbons_only,
                    exclude_jids: &exclude_jids,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Route a bare-JID broadcast only to resources that have announced
    /// available presence with a non-negative priority.  RFC 6121 uses this
    /// delivery mode for headline messages; ordinary cluster broadcasts
    /// (roster pushes, Carbons, and directed traffic) must not inherit this
    /// filter.
    pub async fn send_to_node_available(
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
                    available_nonnegative_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Route a database-backed bare-JID message to every eligible resource
    /// while carrying the exact PostgreSQL acknowledgement fence across the
    /// cluster bus.
    pub async fn send_to_node_available_durable(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_nonnegative_only: true,
                    durable_delivery: Some(delivery),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Route presence to every available resource of a bare JID. Presence
    /// routing does not use message priority, so negative-priority resources
    /// remain eligible here (unlike headline-message routing above).
    pub async fn send_to_node_available_presence(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        self.send_to_node_available_presence_excluding(node_id, target_jid, stanza, None)
            .await
    }

    pub async fn send_to_node_available_presence_excluding(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        exclude_jid: Option<&str>,
    ) -> Result<bool> {
        let exclude_jids = exclude_jid.into_iter().collect::<Vec<_>>();
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only: true,
                    exclude_jids: &exclude_jids,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Ask the node that owns one or more resources of `owner` to replay
    /// those resources' current available presence to every available
    /// resource of `recipient`. This closes the RFC 6121 initial-presence
    /// probe gap when the contact and requester are attached to different
    /// application nodes.
    pub async fn request_presence_probe_from_node(
        &self,
        node_id: &str,
        owner: &str,
        recipient: &str,
        availability_only: bool,
        authority: ClusterPresenceAuthority,
    ) -> Result<()> {
        let owner = crate::jid::canonicalize(owner)?;
        let recipient = crate::jid::canonicalize(recipient)?;
        self.send_control_to_node(
            node_id,
            &owner,
            serde_json::json!({
                "target": owner,
                "presence_probe": true,
                "recipient": recipient,
                "availability_only": availability_only,
                "presence_authority_version": PRESENCE_AUTHORITY_VERSION,
                "presence_owner_id": authority.owner_id,
                "presence_owner_auth_generation": authority.owner_auth_generation,
                "presence_recipient_id": authority.recipient_id,
                "presence_recipient_auth_generation": authority.recipient_auth_generation,
            }),
        )
        .await
    }

    /// Deliver an XEP-0191 push only to resources that successfully requested
    /// their blocklist on this (possibly resumed) session.
    pub async fn send_to_node_blocklist(
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
                    blocklist_requested_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Deliver an XEP-0016 list-definition push only to resources that have
    /// requested privacy-list state during this logical (possibly resumed)
    /// session.
    pub async fn send_to_node_privacy(
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
                    privacy_requested_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Deliver a presence-subscription notification to available resources.
    /// RFC 6121 roster interest gates roster pushes, not subscription-related
    /// presence. Callers therefore normally pass `false`; the parameter is
    /// retained for rolling compatibility with older cluster senders.
    pub async fn send_to_node_presence_subscription(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        roster_requested_only: bool,
        authority: ClusterPresenceAuthority,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only: true,
                    roster_requested_only,
                    expected_user_id: Some(authority.recipient_id),
                    expected_auth_generation: Some(authority.recipient_auth_generation),
                    presence_authority: Some(authority),
                    presence_delivery: Some(ClusterPresenceDelivery::Subscription),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Ask another node that owns resources of `owner` to emit those exact
    /// resources' polite-blocking presence transition.
    pub async fn send_blocking_presence_change(
        &self,
        node_id: &str,
        owner: &str,
        targets: &[String],
        patterns: &[String],
        available: bool,
    ) -> Result<()> {
        let (Some(pool), _) = (&self.pool, &self.client) else {
            return Ok(());
        };
        let owner = crate::jid::canonicalize_bare(owner)?;
        if targets.len() > northstar_xep_0191::MAX_ITEMS
            || patterns.len() > northstar_xep_0191::MAX_ITEMS
        {
            anyhow::bail!("too many blocking presence targets");
        }
        let targets = targets
            .iter()
            .map(|target| crate::jid::canonicalize(target))
            .collect::<Result<Vec<_>>>()?;
        let patterns = patterns
            .iter()
            .map(|pattern| crate::jid::canonicalize(pattern))
            .collect::<Result<Vec<_>>>()?;
        let payload = serde_json::json!({
            "target": owner,
            "blocking_presence_change": true,
            "blocking_targets": targets,
            "blocking_patterns": patterns,
            "available": available,
        });
        let mut conn = pool.get().await?;
        let channel = self.key(format!("node:{node_id}"));
        let _ = self
            .publish_signed(&mut conn, node_id, &channel, payload)
            .await?;
        Ok(())
    }

    /// Route a Carbon to a peer node while excluding every exact canonical
    /// resource in `exclude_jids`. The first exclusion is also written to the
    /// legacy scalar field, so rolling-upgrade peers still exclude the primary
    /// receiving resource rather than echoing a Carbon to it.
    pub async fn send_to_node_excluding(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        carbons_only: bool,
        exclude_jids: &[&str],
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    carbons_only,
                    exclude_jids,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub async fn send_to_node_muc_carbons_excluding(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        exclude_jids: &[&str],
        room_jid: &str,
        nick: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    carbons_only: true,
                    exclude_jids,
                    carbon_muc_scope: Some((room_jid, nick)),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Route one primary one-to-one stanza and return the exact full-resource
    /// key that accepted it. A legacy peer can still report successful
    /// delivery without a key; callers must then suppress Carbons rather than
    /// guessing an exclusion.
    pub async fn send_to_node_primary(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<NodeDeliveryReceipt> {
        self.send_to_node_receipt(
            node_id,
            target_jid,
            stanza,
            NodeDeliveryOptions {
                primary: true,
                ..NodeDeliveryOptions::default()
            },
        )
        .await
    }

    /// Durable counterpart of [`Self::send_to_node_primary`]. The receiver
    /// verifies the exact spool row before attaching this fence to a socket.
    pub async fn send_to_node_primary_durable(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        delivery: crate::outbound::DurableDelivery,
    ) -> Result<NodeDeliveryReceipt> {
        self.send_to_node_receipt(
            node_id,
            target_jid,
            stanza,
            NodeDeliveryOptions {
                primary: true,
                durable_delivery: Some(delivery),
                ..NodeDeliveryOptions::default()
            },
        )
        .await
    }

    /// Revoke older live logins belonging to one XEP-0388 client
    /// installation. The PostgreSQL epoch makes delayed/replayed controls
    /// harmless to a later replacement login.
    pub async fn send_user_agent_replacement(
        &self,
        bare_jid: &str,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
        minimum_epoch: i64,
    ) -> Result<()> {
        anyhow::ensure!(minimum_epoch > 0, "invalid user-agent epoch");
        let bare_jid = crate::jid::canonicalize_bare(bare_jid)?;
        if self.pool.is_none() {
            return Ok(());
        }
        let nodes = self.lookup_nodes(&bare_jid).await?;
        let payload = serde_json::json!({
            "target": bare_jid,
            "user_agent_replacement": true,
            "user_id": user_id,
            "device_id": device_id,
            "minimum_epoch": minimum_epoch,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                self.send_control_to_node(&node_id, &bare_jid, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    /// Deliver an idempotent cluster control operation and wait until the
    /// addressed node confirms that it processed it. Redis Pub/Sub's publish
    /// return value only proves that a subscriber existed; without this
    /// correlated acknowledgement the durable teardown lease could be
    /// finalized while the remote node still retained live state.
    pub(super) async fn send_control_to_node(
        &self,
        node_id: &str,
        target: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        self.correlated_control_sender()
            .send_control_to_node(node_id, target, payload)
            .await
    }

    pub(super) async fn send_to_node_receipt(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        options: NodeDeliveryOptions<'_>,
    ) -> Result<NodeDeliveryReceipt> {
        self.node_delivery()
            .send_to_node_receipt(node_id, target_jid, stanza, options)
            .await
    }
}
