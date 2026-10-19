//! Cluster MUC outbox delivery: claim passes, policy snapshots, departure presence and event delivery.

use super::*;

pub(super) async fn run_muc_outbox_delivery(
    context: Arc<crate::state::cluster_muc_outbox_worker::ClusterMucOutboxWorkerContext>,
    cancel: CancellationToken,
    heartbeat: crate::platform::workers::WorkerHeartbeat,
) -> Result<()> {
    let mut poll = tokio::time::interval(Duration::from_secs(1));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut next_history_cleanup = Instant::now();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = poll.tick() => {},
            _ = context.signal.wait() => {},
        }
        {
            let _database_turn = context.database_turn().await;
            context.preclaim.prepare_pass(32, 256).await?;
        }
        let pass_started = Instant::now();
        'batches: for _ in 0..MUC_OUTBOX_MAX_BATCHES_PER_PASS {
            if cancel.is_cancelled() || pass_started.elapsed() >= MUC_OUTBOX_PASS_BUDGET {
                break;
            }
            let deliveries = {
                let _database_turn = context.database_turn().await;
                context
                    .claim
                    .claim_batch(
                        &context.signal.node_id,
                        MUC_OUTBOX_BATCH_SIZE,
                        Duration::from_secs(30),
                    )
                    .await?
            };
            if deliveries.is_empty() {
                break;
            }
            for delivery in deliveries {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                if pass_started.elapsed() >= MUC_OUTBOX_PASS_BUDGET {
                    break 'batches;
                }
                let outcome = tokio::time::timeout(
                    MUC_OUTBOX_DELIVERY_BUDGET,
                    deliver_cluster_muc_event(&context, &delivery),
                )
                .await
                .map_err(|_| anyhow::anyhow!("cluster MUC delivery exceeded its time budget"))
                .and_then(std::convert::identity);
                match outcome {
                    Ok(()) => {
                        let acknowledged = {
                            let _database_turn = context.database_turn().await;
                            context.settlement.acknowledge(&delivery).await?
                        };
                        anyhow::ensure!(
                            acknowledged == AckOutcome::Acknowledged,
                            "cluster MUC outbox ACK lost its exact claim lease"
                        );
                        context.record_delivery();
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            delivery_id=%delivery.delivery_id,
                            operation_id=%delivery.operation_id,
                            event_id=%delivery.event_id,
                            "cluster MUC audience delivery will retry with the same stable event ID"
                        );
                        {
                            let _database_turn = context.database_turn().await;
                            context
                                .settlement
                                .retry(&delivery, &error.to_string())
                                .await?;
                        }
                        context.record_retry();
                    }
                }
                heartbeat.ok();
            }
        }
        let housekeeping = &context.housekeeping;
        {
            let _database_turn = context.database_turn().await;
            housekeeping.purge_expired_dead_letters().await?;
        }
        if Instant::now() >= next_history_cleanup {
            // Ninety days is the bounded online idempotency/recovery horizon
            // for experimental clustered room-control events. Active legal
            // holds and outstanding delivery projections make the database
            // cleanup fail closed or skip the protected incarnation.
            {
                let _database_turn = context.database_turn().await;
                housekeeping.purge_history().await?;
            }
            next_history_cleanup = Instant::now() + Duration::from_secs(60);
        }
        let snapshot = {
            let _database_turn = context.database_turn().await;
            housekeeping.snapshot().await?
        };
        context.record_gauges(snapshot);
        heartbeat.ok();
    }
}

pub(super) struct ClusterMucPolicyRender<'a> {
    pub(super) endpoints:
        &'a crate::state::cluster_muc_delivery_endpoints::ClusterMucDeliveryEndpoints,
    pub(super) context: &'a crate::db::ClusterMucEventContext,
    pub(super) room_jid: &'a str,
    pub(super) recipient: &'a crate::state::MucOccupant,
    pub(super) event_id: &'a str,
    pub(super) change: &'a serde_json::Value,
    pub(super) configuration_change: bool,
    pub(super) stanzas: &'a mut Vec<String>,
}

pub(super) fn cluster_muc_policy_result(
    change: &serde_json::Value,
) -> Result<(
    crate::db::ClusterMucOccupancyTarget,
    crate::db::ClusterMucPolicySnapshot,
)> {
    let target: crate::db::ClusterMucOccupancyTarget =
        serde_json::from_value(change["target"].clone())
            .context("cluster MUC policy target tuple is invalid")?;
    let snapshot: crate::db::ClusterMucPolicySnapshot =
        serde_json::from_value(change["snapshot"].clone())
            .context("cluster MUC policy result snapshot is invalid")?;
    anyhow::ensure!(
        snapshot.room_id == target.room_id
            && snapshot.room_epoch == target.room_epoch
            && snapshot.occupant_incarnation == target.occupant_incarnation
            && snapshot.occupancy_epoch == target.occupancy_epoch
            && snapshot.full_jid == target.full_jid
            && snapshot.nick == target.nick
            && snapshot.connection_uuid == target.connection_uuid
            && snapshot.connection_epoch == target.connection_epoch,
        "cluster MUC policy snapshot is not exactly bound"
    );
    Ok((target, snapshot))
}

pub(super) fn validate_cluster_muc_admin_batch_details(
    details: &serde_json::Value,
    room_id: uuid::Uuid,
    room_epoch: uuid::Uuid,
) -> Result<&[serde_json::Value]> {
    let room_non_anonymous = details["non_anonymous"]
        .as_bool()
        .context("cluster MUC batch has no committed anonymity policy")?;
    let changes = details["changes"]
        .as_array()
        .context("cluster MUC batch has no ordered result snapshots")?;
    let request_change_count = details["request_change_count"]
        .as_u64()
        .context("cluster MUC batch has no committed request item count")?;
    anyhow::ensure!(
        (1..=63).contains(&request_change_count) && changes.len() <= 63,
        "cluster MUC batch exceeds the receipt ordinal limit"
    );
    for change in changes {
        match change["kind"].as_str() {
            Some("presence") => {
                let (target, snapshot) = cluster_muc_policy_result(change)?;
                anyhow::ensure!(
                    target.room_id == room_id && target.room_epoch == room_epoch,
                    "cluster MUC batch target belongs to another room incarnation"
                );
                anyhow::ensure!(
                    matches!(snapshot.state.as_str(), "active" | "suspended" | "revoked"),
                    "cluster MUC batch presence has an invalid result state"
                );
                let status = change["status"].as_u64();
                if matches!(snapshot.state.as_str(), "active" | "suspended") {
                    anyhow::ensure!(
                        change["status"].is_null(),
                        "cluster MUC batch active presence has a removal status"
                    );
                } else {
                    anyhow::ensure!(
                        matches!(status, Some(301 | 307 | 321)),
                        "cluster MUC batch removal has no valid status"
                    );
                }
            }
            Some("offline_affiliation") => {
                anyhow::ensure!(
                    room_non_anonymous,
                    "cluster MUC batch anonymous room has an offline JID notice"
                );
                let bare_jid = change["bare_jid"]
                    .as_str()
                    .context("cluster MUC batch offline target has no bare JID")?;
                anyhow::ensure!(
                    crate::jid::canonicalize_bare(bare_jid)? == bare_jid,
                    "cluster MUC batch offline target is not canonical"
                );
                let affiliation = change["affiliation"]
                    .as_str()
                    .context("cluster MUC batch offline target has no affiliation")?;
                anyhow::ensure!(
                    matches!(
                        affiliation,
                        "owner" | "admin" | "member" | "outcast" | "none"
                    ),
                    "cluster MUC batch offline affiliation is invalid"
                );
                anyhow::ensure!(
                    change["nick"].is_null() || change["nick"].is_string(),
                    "cluster MUC batch offline nickname is invalid"
                );
                anyhow::ensure!(
                    change["nick"].as_str().is_none_or(|nick| nick.len() <= 128),
                    "cluster MUC batch offline nickname is oversized"
                );
            }
            _ => anyhow::bail!("cluster MUC batch result kind is invalid"),
        }
        anyhow::ensure!(
            change["reason"].is_null() || change["reason"].is_string(),
            "cluster MUC batch reason is invalid"
        );
        anyhow::ensure!(
            change["reason"]
                .as_str()
                .is_none_or(|reason| reason.len() <= 4096),
            "cluster MUC batch reason is oversized"
        );
    }
    Ok(changes.as_slice())
}

pub(super) fn append_cluster_muc_policy_snapshot(render: ClusterMucPolicyRender<'_>) -> Result<()> {
    let ClusterMucPolicyRender {
        endpoints,
        context,
        room_jid,
        recipient,
        event_id,
        change,
        configuration_change,
        stanzas,
    } = render;
    let (_target, snapshot) = cluster_muc_policy_result(change)?;
    let room_non_anonymous = context.details["non_anonymous"]
        .as_bool()
        .unwrap_or(context.room_non_anonymous);
    let subject = crate::services::muc::SerializableMucOccupant {
        full_jid: snapshot.full_jid.clone(),
        room_jid: room_jid.to_owned(),
        nick: snapshot.nick.clone(),
        affiliation: snapshot.affiliation.clone(),
        role: snapshot.role.clone(),
        room_non_anonymous,
        occupant_id: crate::xmpp::xml_util::muc_occupant_id(
            &context.occupant_id_secret,
            &snapshot.bare_jid,
        ),
        cluster_epoch: snapshot.occupant_incarnation,
        connection_id: snapshot.connection_uuid,
        federated_domain: None,
        sm_session_id: snapshot.sm_session_id,
        payload: String::new(),
    };
    let subject_is_recipient = snapshot.full_jid == recipient.full_jid
        && snapshot.occupant_incarnation == recipient.cluster_epoch
        && snapshot.connection_uuid == recipient.connection_id;
    let terminal = !matches!(snapshot.state.as_str(), "active" | "suspended");
    if terminal {
        let fallback = if snapshot.affiliation == "outcast" {
            301
        } else if configuration_change {
            322
        } else {
            321
        };
        let status = change["status"]
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .or(Some(fallback));
        stanzas.push(crate::xmpp::xml_util::muc_presence_stanza_with_status(
            &subject,
            &recipient.full_jid,
            true,
            snapshot.full_jid == recipient.full_jid,
            false,
            Some(event_id),
            room_non_anonymous || subject_is_recipient || recipient.role == "moderator",
            status,
            None,
            change["reason"].as_str(),
        ));
        // The target's own durable delivery performs cache revocation. If a
        // different audience row removed it first, the target row would no
        // longer be able to deliver its required self-unavailable stanza.
        if subject_is_recipient {
            endpoints.revoke_exact_recipient(&subject);
        }
    } else {
        if subject_is_recipient {
            endpoints.apply_policy_projection_exact(&subject);
        }
        stanzas.push(crate::xmpp::xml_util::muc_presence_stanza(
            &subject,
            &recipient.full_jid,
            false,
            snapshot.full_jid == recipient.full_jid,
            false,
            Some(event_id),
            room_non_anonymous
                || snapshot.full_jid == recipient.full_jid
                || recipient.role == "moderator",
        ));
    }
    Ok(())
}

pub(super) fn render_cluster_muc_departure_presence(
    target: &crate::services::muc::SerializableMucOccupant,
    recipient: &crate::services::muc::SerializableMucOccupant,
    event_id: &str,
    room_non_anonymous: bool,
    operation_kind: &str,
    details: &serde_json::Value,
) -> Result<String> {
    let status = if operation_kind == "leave" {
        match details.get("status") {
            None => None,
            Some(value) => {
                anyhow::ensure!(value.as_u64() == Some(333), "invalid MUC leave status");
                Some(333)
            }
        }
    } else {
        None
    };
    let self_presence = target.full_jid == recipient.full_jid;
    Ok(crate::xmpp::xml_util::muc_presence_stanza_with_status(
        target,
        &recipient.full_jid,
        true,
        self_presence,
        false,
        Some(event_id),
        room_non_anonymous || recipient.role == "moderator",
        status,
        None,
        None,
    ))
}

pub(super) async fn deliver_cluster_muc_event(
    worker: &crate::state::cluster_muc_outbox_worker::ClusterMucOutboxWorkerContext,
    delivery: &crate::db::ClusterMucOutboxDelivery,
) -> Result<()> {
    let endpoints = &worker.endpoints;
    anyhow::ensure!(
        matches!(delivery.audience_kind.as_str(), "occupant" | "node_pull"),
        "cluster MUC outbox audience kind is unsupported"
    );
    let payload: serde_json::Value = serde_json::from_str(&delivery.payload)
        .context("cluster MUC outbox payload is invalid JSON")?;
    let canonical_digest = sha2::Sha256::digest(delivery.payload.as_bytes()).to_vec();
    anyhow::ensure!(
        canonical_digest == delivery.payload_digest,
        "cluster MUC outbox payload digest mismatch"
    );
    let operation_id = delivery.operation_id.to_string();
    let database_event_id = delivery.event_id.to_string();
    anyhow::ensure!(
        payload["operation_id"].as_str() == Some(operation_id.as_str())
            && payload["event_id"].as_str() == Some(database_event_id.as_str())
            && payload["event_sequence"].as_i64() == Some(delivery.event_sequence),
        "cluster MUC outbox payload identity is not exactly bound"
    );
    let context = {
        let _database_turn = worker.database_turn().await;
        worker
            .delivery_read
            .event_context(delivery.operation_id)
            .await?
            .context("cluster MUC outbox operation is missing")?
    };
    anyhow::ensure!(
        context.room_epoch == delivery.room_epoch,
        "cluster MUC outbox room epoch is stale"
    );
    anyhow::ensure!(
        context
            .actor_affiliation
            .as_deref()
            .is_none_or(|value| matches!(value, "owner" | "admin" | "member" | "outcast" | "none")),
        "cluster MUC operation contains an invalid actor affiliation"
    );
    let room_jid = format!("{}@conference.{}", context.room_localpart, worker.domain);
    let Some(recipient_nick) = delivery.recipient_nick.as_deref() else {
        // node_pull rows are wake hints only; the worker has completed the
        // authoritative PostgreSQL pull by reaching this point.
        return Ok(());
    };
    let cached_recipient = endpoints.cached_recipient(&room_jid, recipient_nick);
    let exact_cached = cached_recipient.as_ref().is_some_and(|recipient| {
        delivery.recipient_full_jid.as_deref() == Some(&recipient.full_jid)
            && delivery.recipient_occupant_incarnation == Some(recipient.cluster_epoch)
            && delivery.recipient_connection_uuid == Some(recipient.connection_id)
            && recipient.nick == recipient_nick
    });
    let mut recipient = if exact_cached {
        cached_recipient.expect("exact cached MUC recipient was checked")
    } else {
        // A terminal transition revokes the PG lease before its notification
        // is written to the socket. Reconstruct only an endpoint from the
        // immutable outbox audience tuple; never revive membership or trust a
        // Redis nickname cache. The stable event ID remains the retry key.
        let snapshot = {
            let _database_turn = worker.database_turn().await;
            worker.delivery_read.recipient_snapshot(delivery).await?
        };
        let Some(snapshot) = snapshot else {
            let audience_is_current = {
                let _database_turn = worker.database_turn().await;
                worker.delivery_read.audience_is_current(delivery).await?
            };
            if audience_is_current {
                anyhow::bail!("authoritative MUC audience snapshot disappeared");
            }
            return Ok(());
        };
        let room_non_anonymous = context.details["non_anonymous"]
            .as_bool()
            .unwrap_or(context.room_non_anonymous);
        endpoints
            .recipient_from_snapshot(
                &snapshot,
                &room_jid,
                room_non_anonymous,
                crate::xmpp::xml_util::muc_occupant_id(
                    &context.occupant_id_secret,
                    &snapshot.bare_jid,
                ),
            )
            .context("immutable MUC audience has no exact live, SM or federated endpoint")?
    };
    if context.operation_kind == "admin_batch" {
        // A later role change or SM handoff may alter the live endpoint, but
        // neither may change the visibility rules of this committed event.
        let original = if let Some(snapshot) = payload.get("original_audience") {
            serde_json::from_value::<crate::db::ClusterMucAudienceSnapshot>(snapshot.clone())
                .context("cluster MUC batch payload original audience is malformed")?
        } else {
            let _database_turn = worker.database_turn().await;
            worker
                .delivery_read
                .original_audience_snapshot(delivery)
                .await?
                .context("cluster MUC batch original audience is missing")?
        };
        anyhow::ensure!(
            original.room_id == delivery.room_id
                && original.room_epoch == delivery.room_epoch
                && original.full_jid == recipient.full_jid
                && original.nick == recipient.nick
                && original.occupant_incarnation == recipient.cluster_epoch
                && Some(original.occupancy_epoch) == delivery.recipient_occupancy_epoch
                && matches!(
                    original.role.as_str(),
                    "moderator" | "participant" | "visitor" | "none"
                )
                && matches!(
                    original.affiliation.as_str(),
                    "owner" | "admin" | "member" | "outcast" | "none"
                ),
            "cluster MUC batch original audience is not exactly bound"
        );
        recipient.role = original.role;
        recipient.affiliation = original.affiliation;
    }
    let recipient_serializable = crate::services::muc::SerializableMucOccupant::from(&recipient);
    let event_id = delivery.event_id.to_string();
    let target = context
        .target
        .as_ref()
        .map(|target| {
            anyhow::ensure!(
                target.occupancy_epoch >= 1 && target.connection_epoch >= 1,
                "cluster MUC target has invalid authority epochs"
            );
            Ok(crate::services::muc::SerializableMucOccupant {
                full_jid: target.full_jid.clone(),
                room_jid: room_jid.clone(),
                nick: target.nick.clone(),
                affiliation: target.affiliation.clone(),
                role: target.role.clone(),
                room_non_anonymous: context.room_non_anonymous,
                occupant_id: crate::xmpp::xml_util::muc_occupant_id(
                    &context.occupant_id_secret,
                    &target.bare_jid,
                ),
                cluster_epoch: target.occupant_incarnation,
                connection_id: target.connection_uuid,
                federated_domain: None,
                sm_session_id: None,
                payload: target.presence_payload.clone(),
            })
        })
        .transpose()?;
    let mut stanzas = Vec::with_capacity(2);
    match context.operation_kind.as_str() {
        "join" | "resume" | "role" => {
            let target = target.context("MUC join/resume/role event has no exact target")?;
            if context.operation_kind == "role" {
                endpoints.apply_role_projection_exact(&target);
            }
            let self_presence = target.full_jid == recipient.full_jid;
            stanzas.push(crate::xmpp::xml_util::muc_presence_stanza(
                &target,
                &recipient.full_jid,
                false,
                self_presence,
                false,
                Some(&event_id),
                context.room_non_anonymous || self_presence || recipient.role == "moderator",
            ));
        }
        "rename" => {
            let target = target.context("MUC rename event has no exact target")?;
            let old_nick = context.details["old_nick"]
                .as_str()
                .context("MUC rename event has no old nickname")?;
            let new_nick = context.details["new_nick"]
                .as_str()
                .context("MUC rename event has no new nickname")?;
            let mut old = target.clone();
            old.nick = old_nick.to_owned();
            stanzas.push(crate::xmpp::xml_util::muc_nickname_change_presence(
                &old,
                &recipient_serializable,
                new_nick,
                Some(&event_id),
            ));
            let self_presence = target.full_jid == recipient.full_jid;
            stanzas.push(crate::xmpp::xml_util::muc_presence_stanza(
                &target,
                &recipient.full_jid,
                false,
                self_presence,
                false,
                Some(&event_id),
                context.room_non_anonymous || self_presence || recipient.role == "moderator",
            ));
        }
        "leave" | "expire" | "account_delete" => {
            let target = target.context("MUC departure event has no exact target")?;
            let self_presence = target.full_jid == recipient.full_jid;
            stanzas.push(render_cluster_muc_departure_presence(
                &target,
                &recipient_serializable,
                &event_id,
                context.room_non_anonymous,
                &context.operation_kind,
                &context.details,
            )?);
            if self_presence {
                endpoints.revoke_exact_recipient(&target);
            }
        }
        "suspend" => {
            // XEP-0198 suspension retains membership until its PG lease
            // expires; it intentionally emits no transient unavailable.
        }
        "kick" | "ban" => {
            let target = target.context("MUC removal event has no exact target")?;
            let status = context.details["status"]
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .or(Some(if context.operation_kind == "ban" {
                    301
                } else {
                    307
                }));
            let reason = context.details["reason"].as_str();
            let actor_nick = context
                .actor_full_jid
                .as_deref()
                .and_then(|full| endpoints.actor_nick(&room_jid, full));
            let self_presence = target.full_jid == recipient.full_jid;
            stanzas.push(crate::xmpp::xml_util::muc_presence_stanza_with_status(
                &target,
                &recipient.full_jid,
                true,
                self_presence,
                false,
                Some(&event_id),
                true,
                status,
                actor_nick.as_deref(),
                reason,
            ));
            if self_presence {
                endpoints.revoke_exact_recipient(&target);
            }
        }
        "destroy" | "locked_expiry" => {
            let alternate = context.details["alternate_jid"].as_str();
            let reason = context.details["reason"].as_str();
            let stanza = crate::xmpp::xml_util::muc_destroy_presence(
                &recipient_serializable,
                alternate,
                reason,
            );
            stanzas.push(crate::xmpp::xml_util::set_root_attribute(
                &stanza, "id", &event_id,
            ));
        }
        "subject" => {
            let stanza = context.details["stanza"]
                .as_str()
                .context("cluster MUC subject event has no committed stanza")?;
            let stanza = crate::xmpp::xml_util::set_to(stanza, &recipient.full_jid);
            let stanza = crate::xmpp::xml_util::set_from(&stanza, &room_jid);
            stanzas.push(crate::xmpp::xml_util::add_stanza_id(
                &stanza,
                &room_jid,
                delivery.event_id,
            ));
        }
        "config" | "affiliation" => {
            let configuration_change = context.operation_kind == "config";
            let changes = context.details[if configuration_change {
                "affected"
            } else {
                "changes"
            }]
            .as_array()
            .context("cluster MUC policy event has no exact result snapshot array")?;
            for change in changes {
                append_cluster_muc_policy_snapshot(ClusterMucPolicyRender {
                    endpoints,
                    context: &context,
                    room_jid: &room_jid,
                    recipient: &recipient,
                    event_id: &event_id,
                    change,
                    configuration_change,
                    stanzas: &mut stanzas,
                })?;
            }
            if !configuration_change {
                if let Some(offline) = context.details["offline_affiliation"].as_object() {
                    let bare_jid = offline
                        .get("bare_jid")
                        .and_then(serde_json::Value::as_str)
                        .context("cluster MUC offline affiliation has no bare JID")?;
                    let affiliation = offline
                        .get("affiliation")
                        .and_then(serde_json::Value::as_str)
                        .context("cluster MUC offline affiliation has no affiliation")?;
                    let nick = offline.get("nick").and_then(serde_json::Value::as_str);
                    let reason = offline.get("reason").and_then(serde_json::Value::as_str);
                    let notice = crate::xmpp::protocol::muc::muc_offline_affiliation_change_notice(
                        &room_jid,
                        bare_jid,
                        affiliation,
                        nick,
                        reason,
                    );
                    let notice = crate::xmpp::xml_util::set_to(&notice, &recipient.full_jid);
                    stanzas.push(crate::xmpp::xml_util::set_root_attribute(
                        &notice, "id", &event_id,
                    ));
                }
            }
            if configuration_change {
                let extension = crate::xmpp::xml_builder::XmlElement::namespaced(
                    "x",
                    "http://jabber.org/protocol/muc#user",
                )
                .child(crate::xmpp::xml_builder::XmlElement::new("status").attr("code", "104"));
                stanzas.push(
                    crate::xmpp::xml_builder::XmlElement::namespaced("message", "jabber:client")
                        .attr("from", &room_jid)
                        .attr("to", &recipient.full_jid)
                        .attr("type", "groupchat")
                        .attr("id", &event_id)
                        .child(extension)
                        .finish(),
                );
            }
        }
        "admin_batch" => {
            anyhow::ensure!(target.is_none(), "cluster MUC batch has a singular target");
            // Validate every projection before the first cache mutation or
            // transport write. A corrupt later item cannot partially apply
            // an earlier item and then fail the whole delivery.
            let changes = validate_cluster_muc_admin_batch_details(
                &context.details,
                delivery.room_id,
                delivery.room_epoch,
            )?;
            for change in changes {
                match change["kind"].as_str() {
                    Some("presence") => {
                        append_cluster_muc_policy_snapshot(ClusterMucPolicyRender {
                            endpoints,
                            context: &context,
                            room_jid: &room_jid,
                            recipient: &recipient,
                            event_id: &event_id,
                            change,
                            configuration_change: false,
                            stanzas: &mut stanzas,
                        })?;
                    }
                    Some("offline_affiliation") => {
                        let bare_jid = change["bare_jid"].as_str().expect("batch was validated");
                        let affiliation =
                            change["affiliation"].as_str().expect("batch was validated");
                        let nick = change["nick"].as_str();
                        let reason = change["reason"].as_str();
                        let notice =
                            crate::xmpp::protocol::muc::muc_offline_affiliation_change_notice(
                                &room_jid,
                                bare_jid,
                                affiliation,
                                nick,
                                reason,
                            );
                        let notice = crate::xmpp::xml_util::set_to(&notice, &recipient.full_jid);
                        stanzas.push(crate::xmpp::xml_util::set_root_attribute(
                            &notice, "id", &event_id,
                        ));
                    }
                    _ => unreachable!("batch was validated"),
                }
            }
        }
        other => anyhow::bail!("unsupported cluster MUC event kind {other}"),
    }
    for (ordinal, stanza) in stanzas.into_iter().enumerate() {
        let ordinal =
            i32::try_from(ordinal).context("MUC event has too many stanza projections")?;
        let stable_item_id = format!("{}:{ordinal}", delivery.event_id);
        let stanza = if context.operation_kind == "admin_batch" {
            crate::xmpp::xml_util::set_root_attribute(&stanza, "id", &stable_item_id)
        } else {
            stanza
        };
        let completed = {
            let _database_turn = worker.database_turn().await;
            worker
                .delivery_item
                .completed(delivery.delivery_id, ordinal, &stable_item_id)
                .await?
        };
        if completed {
            continue;
        }
        anyhow::ensure!(
            worker
                .delivery
                .deliver_to_muc_occupant_with_receipt(&recipient, stanza, delivery,)
                .await?,
            "exact MUC audience transport did not reach a durable ownership/write boundary"
        );
        let completed = {
            let _database_turn = worker.database_turn().await;
            worker
                .delivery_item
                .complete_exact(delivery, ordinal, &stable_item_id)
                .await?
        };
        anyhow::ensure!(
            completed,
            "cluster MUC delivery item lost its stable ordinal identity"
        );
    }
    Ok(())
}
