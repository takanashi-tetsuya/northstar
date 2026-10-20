//! Channel stanza delivery to one participant, local or clustered, and its durable completion.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChannelStanzaDatabaseLane {
    /// A client-originated stanza uses the normal application pool without
    /// borrowing durable outbox capacity.
    LiveIngress,
    /// A previously claimed durable outbox row must limit every local
    /// recipient lookup, archive projection, cluster authority lookup, and
    /// S2S outbox admission to the service-owned database budget. Each permit
    /// is released before later transport or cluster-peer work, which may
    /// wait on external I/O.
    DurableOutbox,
}

pub(super) struct ChannelStanzaDelivery<'a> {
    /// Present only for a claimed durable outbox recipient.  It makes the
    /// bounded stage logs below correlate with the authoritative lease without
    /// logging stanza content or any client-supplied payload.
    pub(super) delivery_id: Option<Uuid>,
    /// The exact leased MIX recipient source for a durable outbox row. A
    /// source is deliberately absent for live ingress: only a claimed source
    /// may be transferred to a recoverable transport or acknowledged.
    pub(super) mix_source: Option<crate::xmpp::outbound::MixDelivery>,
    pub(super) channel_jid: &'a str,
    pub(super) recipient: &'a MixParticipant,
    pub(super) stanza: String,
    pub(super) authoritative_stanza_id: Option<Uuid>,
    pub(super) archive: bool,
    pub(super) encrypted: bool,
    pub(super) durable: bool,
    pub(super) database_lane: ChannelStanzaDatabaseLane,
}

/// The outcome that determines who may consume a claimed MIX recipient row.
/// Socket fencing, XEP-0198 and BOSH persistence transfer responsibility to a
/// typed transport owner. Federation outbox admission leaves final deletion
/// with the claiming worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChannelStanzaDeliveryOutcome {
    CompletedByClaimingWorker,
    TransferredToRecoverableTransport,
}

/// The successful route result selects the only remaining settlement owner.
/// Construct an acknowledgement future only while the worker still owns the
/// source. After a socket/SM/BOSH hand-off its old token must never be used for
/// acknowledgement, retry or dead-letter settlement.
#[allow(dead_code)] // Compatibility selector retained for the existing typed-owner controls.
pub(super) async fn finish_mix_delivery_owner<Acknowledge, Completion>(
    outcome: ChannelStanzaDeliveryOutcome,
    acknowledge: Acknowledge,
) -> Result<bool>
where
    Acknowledge: FnOnce() -> Completion,
    Completion: std::future::Future<Output = Result<bool>>,
{
    match outcome {
        ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker => acknowledge().await,
        ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport => Ok(true),
    }
}

pub(super) async fn deliver_channel_stanza(
    context: &MixOutboxContext,
    delivery: ChannelStanzaDelivery<'_>,
) -> Result<ChannelStanzaDeliveryOutcome> {
    deliver_channel_stanza_inner(context, delivery, None).await
}

pub(super) async fn deliver_claimed_channel_stanza(
    context: &MixOutboxContext,
    request: &mix_worker::RouteRequest,
) -> Result<ChannelStanzaDeliveryOutcome> {
    request.start()?;
    let row = request.row();
    let recipient = MixParticipant {
        participant_id: row.participant_id,
        jid: row.recipient_jid.clone(),
        nick: row.recipient_nick.clone(),
    };
    deliver_channel_stanza_inner(
        context,
        ChannelStanzaDelivery {
            delivery_id: Some(row.source.delivery_id),
            mix_source: Some(row.source),
            channel_jid: &row.channel_jid,
            recipient: &recipient,
            stanza: request.stanza().to_owned(),
            authoritative_stanza_id: row.authoritative_stanza_id,
            archive: row.archive,
            encrypted: row.encrypted,
            durable: true,
            database_lane: ChannelStanzaDatabaseLane::DurableOutbox,
        },
        Some(request),
    )
    .await
}

pub(super) async fn send_claimed_cluster_mix(
    context: &MixOutboxContext,
    request: &mix_worker::ClusterRequest,
) -> Result<crate::cluster::NodeDeliveryReceipt> {
    request.start()?;
    let result = context
        .send_cluster_mix(
            request.node(),
            request.recipient(),
            request.stanza(),
            Some(request.source()),
        )
        .await;
    record_claimed_cluster_result(request, &result)?;
    result
}

pub(super) fn record_claimed_cluster_result(
    request: &mix_worker::ClusterRequest,
    result: &Result<crate::cluster::NodeDeliveryReceipt>,
) -> Result<()> {
    let handoff = match result {
        Ok(receipt) if receipt.acknowledged => receipt.mix_handoff.map(|handoff| match handoff {
            crate::cluster::ClusterMixHandoff::SocketFenced => {
                mix_worker::TransferBoundary::ClusterSocketFenced
            }
            crate::cluster::ClusterMixHandoff::SmPersisted => {
                mix_worker::TransferBoundary::ClusterSmPersisted
            }
            crate::cluster::ClusterMixHandoff::BoshPersisted => {
                mix_worker::TransferBoundary::ClusterBoshPersisted
            }
        }),
        _ => None,
    };
    request.returned(handoff)?;
    Ok(())
}

pub(super) async fn deliver_channel_stanza_inner(
    context: &MixOutboxContext,
    delivery: ChannelStanzaDelivery<'_>,
    observation: Option<&mix_worker::RouteRequest>,
) -> Result<ChannelStanzaDeliveryOutcome> {
    let ChannelStanzaDelivery {
        delivery_id,
        mix_source,
        channel_jid,
        recipient,
        stanza,
        authoritative_stanza_id,
        archive,
        encrypted,
        durable,
        database_lane,
    } = delivery;
    let durable_source = match (durable, delivery_id, mix_source) {
        (true, Some(delivery_id), Some(source)) if source.delivery_id == delivery_id => {
            Some(source)
        }
        (true, _, _) => anyhow::bail!("durable MIX routing requires its exact claimed source"),
        (false, None, None) => None,
        (false, _, _) => anyhow::bail!("live MIX routing must not carry a durable source"),
    };
    let durable_delivery_id = durable_source.map(|source| source.delivery_id);
    if let Some(delivery_id) = durable_delivery_id {
        tracing::debug!(
            delivery_id = %delivery_id,
            channel = channel_jid,
            recipient = %recipient.jid,
            "MIX durable delivery entered recipient routing"
        );
    }
    let recipient_jid = match CanonicalJid::parse_bare(&recipient.jid) {
        Ok(jid) => jid,
        Err(error) => {
            record_mix_post_commit_failure(
                context,
                channel_jid,
                &recipient.jid,
                "invalid persisted recipient JID",
                &error,
            );
            if durable {
                return Err(permanent_mix_delivery_error(
                    "invalid-recipient",
                    error.to_string(),
                ));
            }
            return Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker);
        }
    };
    let domain = recipient_jid.domainpart();
    if same_jid_domain(domain, context.local_domain()) {
        let Some(username) = recipient_jid.localpart() else {
            return Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker);
        };
        if let Some(delivery_id) = durable_delivery_id {
            tracing::debug!(delivery_id = %delivery_id, "MIX durable delivery resolving local account");
        }
        let user = match database_lane {
            ChannelStanzaDatabaseLane::LiveIngress => {
                context.service().find_enabled_user(username).await
            }
            ChannelStanzaDatabaseLane::DurableOutbox => {
                context.service().outbox_find_enabled_user(username).await
            }
        };
        let user = match user {
            Ok(user) => user,
            Err(error) => {
                record_mix_post_commit_failure(
                    context,
                    channel_jid,
                    &recipient.jid,
                    "local account lookup",
                    &error,
                );
                if durable {
                    return Err(error);
                }
                return Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker);
            }
        };
        let Some(user) = user else {
            if durable {
                return Err(permanent_mix_delivery_error(
                    "account-unavailable",
                    "local MIX recipient no longer exists or is disabled",
                ));
            }
            return Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker);
        };
        // `recipient` is an immutable MIX Core participant/subscription
        // snapshot captured by the channel mutation transaction.  XEP-0405
        // PAM is only an optional account-side roster projection; requiring a
        // PAM row here silently dropped every event for a valid direct Core
        // join.  Account blocking remains a live, fail-closed privacy check.
        if let Some(delivery_id) = durable_delivery_id {
            tracing::debug!(delivery_id = %delivery_id, "MIX durable delivery evaluating recipient block policy");
        }
        let blocked = match database_lane {
            ChannelStanzaDatabaseLane::LiveIngress => {
                context.service().is_blocked(user.id, channel_jid).await
            }
            ChannelStanzaDatabaseLane::DurableOutbox => {
                context
                    .service()
                    .outbox_is_blocked(user.id, channel_jid)
                    .await
            }
        };
        let blocked = match blocked {
            Ok(blocked) => blocked,
            Err(error) => {
                record_mix_post_commit_failure(
                    context,
                    channel_jid,
                    &recipient.jid,
                    "blocking lookup",
                    &error,
                );
                if durable {
                    return Err(error);
                }
                return Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker);
            }
        };
        if blocked {
            if durable {
                return Err(permanent_mix_delivery_error(
                    "policy-cancelled",
                    "recipient currently blocks this MIX channel",
                ));
            }
            return Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker);
        }
        if archive {
            if let Some(delivery_id) = durable_delivery_id {
                tracing::debug!(delivery_id = %delivery_id, "MIX durable delivery writing personal archive projection");
            }
            let authoritative_stanza_id = authoritative_stanza_id
                .context("archived MIX delivery requires an authoritative stanza id")?;
            let archive_id = Uuid::new_v4();
            let client_stanza_id = authoritative_stanza_id.to_string();
            let admission = if let Some(owner) = observation {
                let request =
                    owner.archive_request(user.id, archive_id, Some(client_stanza_id.clone()))?;
                context
                    .service()
                    .outbox_archive_mix_message_once_observed(&request)
                    .await
                    .map(|result| match result {
                        mix_worker::ArchiveResult::Stored(id) => SourceArchiveAdmission::Stored(id),
                        mix_worker::ArchiveResult::Replay(id) => SourceArchiveAdmission::Replay(id),
                    })
            } else {
                match database_lane {
                    ChannelStanzaDatabaseLane::LiveIngress => {
                        context
                            .service()
                            .archive_mix_message_once(
                                archive_id,
                                user.id,
                                channel_jid,
                                authoritative_stanza_id,
                                &stanza,
                                encrypted,
                                Some(&client_stanza_id),
                            )
                            .await
                    }
                    ChannelStanzaDatabaseLane::DurableOutbox => {
                        context
                            .service()
                            .outbox_archive_mix_message_once(
                                archive_id,
                                user.id,
                                channel_jid,
                                authoritative_stanza_id,
                                &stanza,
                                encrypted,
                                Some(&client_stanza_id),
                            )
                            .await
                    }
                }
            };
            match admission {
                Ok(SourceArchiveAdmission::Stored(_)) => {}
                // The archive projection may have committed immediately
                // before a crash.  A durable outbox retry must continue to
                // live routing; the authoritative stanza-id makes the
                // resulting at-least-once transport delivery deduplicable.
                Ok(SourceArchiveAdmission::Replay(_)) => {}
                Err(error) => {
                    record_mix_post_commit_failure(
                        context,
                        channel_jid,
                        &recipient.jid,
                        "personal MAM archive",
                        &error,
                    );
                    if durable {
                        return Err(error);
                    }
                    return Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker);
                }
            }
        }
        let mut local_targets = context.session_entries_for(&recipient.jid);
        // One leased recipient row may cross exactly one local transport.
        // Sorting makes the choice deterministic across the hash-map-backed
        // live-route registry; a source transferred to SM/BOSH or written to
        // a socket must never also be queued to a second resource.
        local_targets.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        if let Some(delivery_id) = durable_delivery_id {
            tracing::debug!(delivery_id = %delivery_id, target_count = local_targets.len(), "MIX durable delivery evaluating local sessions");
        }
        let mut had_deliverable_target = false;
        let mut had_unknown_target = false;
        let mut had_route_target = !local_targets.is_empty();
        let mut cluster_delivery_failed = false;
        let mut accepted = false;
        let mut transferred_to_recoverable_transport = false;
        for (jid, session) in &local_targets {
            match context.session_mix_capability(jid) {
                MixSessionCapability::Supported => {
                    had_deliverable_target = true;
                    if durable {
                        let source = durable_source.expect("durable source was validated above");
                        let result = if let Some(owner) = observation {
                            let request = owner.local_request(jid.clone())?;
                            try_send_local_durable_mix_observed(
                                &session.sender,
                                &session.disconnect,
                                &request,
                            )
                            .await
                        } else {
                            try_send_local_durable_mix(
                                &session.sender,
                                &session.disconnect,
                                stanza.clone(),
                                source,
                            )
                            .await
                        };
                        match result {
                            Ok(
                                crate::xmpp::outbound::MixTransportCompletion::SocketFenced {
                                    ..
                                }
                                | crate::xmpp::outbound::MixTransportCompletion::SmPersisted {
                                    ..
                                }
                                | crate::xmpp::outbound::MixTransportCompletion::BoshPersisted {
                                    ..
                                },
                            ) => {
                                accepted = true;
                                transferred_to_recoverable_transport = true;
                                break;
                            }
                            Err(error) => {
                                record_mix_post_commit_failure(
                                    context,
                                    channel_jid,
                                    jid,
                                    "local session durable transport hand-off",
                                    &error,
                                );
                            }
                        }
                    } else if let Err(error) = session.sender.try_send(stanza.clone()) {
                        record_mix_post_commit_failure(
                            context,
                            channel_jid,
                            jid,
                            "local session queue",
                            &error,
                        );
                    }
                }
                MixSessionCapability::Unsupported => {}
                MixSessionCapability::Unknown => had_unknown_target = true,
            }
        }
        if durable && transferred_to_recoverable_transport {
            return Ok(ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport);
        }
        if durable && accepted {
            return Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker);
        }
        if let Some(delivery_id) = durable_delivery_id {
            tracing::debug!(delivery_id = %delivery_id, "MIX durable delivery resolving cluster authorities");
        }
        let nodes = match database_lane {
            ChannelStanzaDatabaseLane::LiveIngress => context.lookup_nodes(&recipient.jid).await,
            ChannelStanzaDatabaseLane::DurableOutbox => {
                context.outbox_lookup_cluster_nodes(&recipient.jid).await
            }
        };
        let nodes = match nodes {
            Ok(nodes) => nodes,
            Err(error) => {
                record_mix_post_commit_failure(
                    context,
                    channel_jid,
                    &recipient.jid,
                    "cluster recipient lookup",
                    &error,
                );
                if durable {
                    return Err(error);
                }
                return Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker);
            }
        };
        for node_id in nodes {
            had_route_target = true;
            let result = if let Some(owner) = observation {
                let request = owner.cluster_request(node_id.clone())?;
                send_claimed_cluster_mix(context, &request).await
            } else {
                context
                    .send_cluster_mix(&node_id, &recipient.jid, &stanza, durable_source)
                    .await
            };
            match result {
                Ok(receipt) => {
                    if receipt.acknowledged {
                        // A v13 peer returns a typed hand-off only after
                        // the source moved to its socket/SM/BOSH owner.
                        // The original worker must then stop using its
                        // old lease instead of deleting it or retrying it.
                        if durable && receipt.mix_handoff.is_some() {
                            accepted = true;
                            transferred_to_recoverable_transport = true;
                            break;
                        } else {
                            accepted |= receipt.delivered;
                        }
                        had_deliverable_target |= receipt.mix_supported > 0;
                        had_unknown_target |= receipt.mix_unknown > 0;
                    } else {
                        cluster_delivery_failed = true;
                    }
                }
                Err(error) => {
                    cluster_delivery_failed = true;
                    record_mix_post_commit_failure(
                        context,
                        channel_jid,
                        &recipient.jid,
                        "cluster queue",
                        &error,
                    );
                }
            }
        }
        // A remote v13 receipt names a durable boundary reached with the
        // rotated source lease. The originating claimant must stop here: the
        // original token is invalid and neither acknowledgement nor retry may
        // race the remote socket/SM/BOSH owner.
        if durable && transferred_to_recoverable_transport {
            return Ok(ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport);
        }
        if durable {
            let availability = if had_deliverable_target {
                DurableMixRouteAvailability::Deliverable
            } else if had_unknown_target {
                DurableMixRouteAvailability::UnknownCapability
            } else if had_route_target {
                DurableMixRouteAvailability::Unsupported
            } else {
                DurableMixRouteAvailability::NoTarget
            };
            match classify_durable_mix_route(
                archive,
                accepted,
                availability,
                cluster_delivery_failed,
            ) {
                DurableMixRouteDisposition::Accepted => {}
                // A route may become eligible after the recipient connects or
                // finishes XEP-0115 verification.  Keep the ordered durable
                // row; expiry is the terminal boundary, never an arbitrary
                // capability-discovery age.
                DurableMixRouteDisposition::Park => {
                    return Err(MixDeliveryRoutePending.into());
                }
                DurableMixRouteDisposition::RetryCluster => {
                    anyhow::bail!("cluster MIX capability delivery failed");
                }
                DurableMixRouteDisposition::RetryDeliverable => {
                    anyhow::bail!("no online MIX resource accepted durable delivery");
                }
            }
        }
    } else if !context.federation_domain_allowed(domain) {
        if durable {
            return Err(permanent_mix_delivery_error(
                "policy-cancelled",
                "recipient federation domain is no longer allowed",
            ));
        }
    } else {
        if let Some(delivery_id) = durable_delivery_id {
            tracing::debug!(delivery_id = %delivery_id, target_domain = domain, "MIX durable delivery admitting federation outbox projection");
        }
        let admitted = match database_lane {
            ChannelStanzaDatabaseLane::LiveIngress => {
                context.federation_outbox().send(domain, stanza, None).await
            }
            ChannelStanzaDatabaseLane::DurableOutbox => {
                context
                    .service()
                    .outbox_admit_federated_stanza(context.federation_outbox(), domain, stanza)
                    .await
            }
        };
        if !admitted {
            record_mix_post_commit_failure(
                context,
                channel_jid,
                &recipient.jid,
                "federation queue rejected stanza",
                &"not accepted",
            );
            if durable {
                anyhow::bail!("federated MIX delivery was not admitted");
            }
        }
    }
    Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker)
}

pub(super) fn addressed_mix_delivery(template: &str, recipient: &str) -> Result<String> {
    let stanza = crate::services::xml_util::set_to(template, recipient);
    let document = Document::parse(&stanza).context("invalid durable MIX stanza template")?;
    anyhow::ensure!(
        document.root_element().attribute("to") == Some(recipient),
        "durable MIX stanza could not be addressed"
    );
    Ok(stanza)
}
