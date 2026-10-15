//! Native, replacement and original saved-case runs.

use super::*;

pub(super) async fn run_native(
    input: NativeInput<'_>,
    recorder: &mut sm::Recorder,
    receivers: &mut ItemReceivers,
    mix_handoffs: &mut Vec<wire::MixHandoff>,
) -> Result<(wire::NativeEvidence, bool, bool)> {
    use crate::xmpp::direct_delivery::{DirectWriteLease, NativeWriteRunner};
    let NativeInput {
        case,
        frame_id,
        plan,
        item,
        row,
        sequence,
    } = input;
    // The receiving callback has been polled; this independent observation is
    // retained before the child prepare/write/ACK future receives a first poll.
    let observation = northstar_delivery_core::native_write::Observation::new(item.durable_source);
    let log = Arc::new(NativeLog {
        observation: observation.clone(),
        sequence: sequence.clone(),
        prefixes: Mutex::new(vec![]),
        writes: Mutex::new(vec![]),
        flushes: Mutex::new(vec![]),
        acks: Mutex::new(vec![]),
        ack_pending: AtomicBool::new(false),
    });
    let sm_pending = recorder.pending_marker();
    let mut port = NativePort {
        spec: plan.native,
        connection_id: plan.connection_id.0,
        row,
        log: log.clone(),
        recorder,
        replacement: plan.replacement.clone(),
    };
    let mut writer = ScriptedWriter {
        script: plan.write,
        accepted: 0,
        log: log.clone(),
    };
    let child = async {
        let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
        log.prefix();
        receivers.observe_mix(&sequence, mix_handoffs);
        let written = lease
            .write(|stanza| crate::xmpp::send(&mut writer, stanza))
            .await?;
        written.settle_with(&port).await;
        Ok::<_, anyhow::Error>(())
    };
    let mut runner = Box::pin(NativeWriteRunner::new(observation.clone(), child));
    let dropped = matches!(&case.drive, wire::Drive::DropNativeAckCommit { frame_id: target } | wire::Drive::DropSmCheckpointCommit { frame_id: target } if *target == frame_id);
    let mut actual = futures::poll!(&mut runner);
    let mut polls = vec![sequence.lock().unwrap().polled(&actual)];
    if let Some(control) = &plan.replacement {
        if plan.connection_id.0 == control.old_connection {
            anyhow::ensure!(
                actual.is_pending() && control.waiting.load(Ordering::SeqCst),
                "old native authority-read gate was not reached"
            );
            control.replace_and_dequeue(&item.stanza)?;
            control.release_old()?;
            actual = futures::poll!(&mut runner);
            polls.push(sequence.lock().unwrap().polled(&actual));
        }
    }
    let failed = matches!(&actual, std::task::Poll::Ready(Err(_)));
    if dropped {
        let entered = match case.drive {
            wire::Drive::DropNativeAckCommit { .. } => log.ack_pending.load(Ordering::SeqCst),
            wire::Drive::DropSmCheckpointCommit { .. } => sm_pending.load(Ordering::SeqCst),
            _ => false,
        };
        anyhow::ensure!(
            actual.is_pending() && entered,
            "native selected drop cut was not reached"
        );
    } else {
        anyhow::ensure!(actual.is_ready(), "unexpected pending native owner");
    }
    drop(runner);
    port.recorder.capture_retired();
    log.prefix();
    receivers.observe_mix(&sequence, mix_handoffs);
    let ownership_receipts = receivers.observe_ownership(&sequence);
    let state = native_state(&observation);
    let evidence = wire::NativeEvidence {
        frame_id,
        connection_id: plan.connection_id,
        state,
        write_calls: log.writes.lock().unwrap().clone(),
        flush_calls: log.flushes.lock().unwrap().clone(),
        ack_calls: log.acks.lock().unwrap().clone(),
        ownership_receipts,
        write_receipts: vec![],
        prefixes: log.prefixes.lock().unwrap().clone(),
        polls,
    };
    Ok((evidence, dropped, failed))
}

pub(super) async fn run_replacement(
    case: &wire::Case,
    frame_id: wire::Id,
    item: OutboundItem,
    row: Arc<Mutex<Option<DurableDelivery>>>,
    sequence: Sequence,
) -> Result<wire::RecipientEvidence> {
    let wire::RecipientOwner::NativeReplacement {
        initial_row,
        old,
        replacement,
        ..
    } = &case.recipient_owner
    else {
        anyhow::bail!("replacement owner input missing");
    };
    anyhow::ensure!(
        *row.lock().unwrap() == initial_row.actual().c2s(),
        "initial replacement row differs from actual direct COMMIT history"
    );
    let old_source = old
        .fence
        .returned_source
        .actual()
        .c2s()
        .context("old native fence family")?;
    let new_source = replacement
        .fence
        .returned_source
        .actual()
        .c2s()
        .context("replacement native fence family")?;
    let control = Arc::new(ReplacementControl::new(
        row.clone(),
        old.connection_id.0,
        replacement.connection_id.0,
        old_source,
        new_source,
        sequence.clone(),
    ));
    let mut old_recorder = sm::Recorder::new(old.connection_id.0, None, &[], sequence.clone())?;
    let mut old_receivers = ItemReceivers::default();
    let mut handoffs = vec![];
    let (old_evidence, dropped, failed) = run_native(
        NativeInput {
            case,
            frame_id,
            plan: NativePlan {
                connection_id: old.connection_id,
                native: Some(old),
                write: &old.write,
                replacement: Some(control.clone()),
            },
            item,
            row: row.clone(),
            sequence: sequence.clone(),
        },
        &mut old_recorder,
        &mut old_receivers,
        &mut handoffs,
    )
    .await?;
    anyhow::ensure!(
        !dropped && !failed,
        "old native write failed outside the declared ACK authority rejection"
    );
    let (replacement_item, replacement_dequeued) = control
        .dequeued
        .lock()
        .unwrap()
        .take()
        .context("replacement channel handoff missing")?;
    let mut new_recorder =
        sm::Recorder::new(replacement.connection_id.0, None, &[], sequence.clone())?;
    let mut new_receivers = ItemReceivers::default();
    let (replacement_evidence, dropped, failed) = run_native(
        NativeInput {
            case,
            frame_id,
            plan: NativePlan {
                connection_id: replacement.connection_id,
                native: Some(replacement),
                write: &replacement.write,
                replacement: Some(control.clone()),
            },
            item: replacement_item,
            row: row.clone(),
            sequence,
        },
        &mut new_recorder,
        &mut new_receivers,
        &mut handoffs,
    )
    .await?;
    anyhow::ensure!(
        !dropped && !failed && handoffs.is_empty(),
        "replacement native write did not complete"
    );
    let row_events = control.events.lock().unwrap().clone();
    let row_after = row
        .lock()
        .unwrap()
        .map(|source| TransportOwnershipSource::C2s(source).into());
    Ok(wire::RecipientEvidence::NativeReplacement {
        old: Box::new(old_evidence),
        replacement: Box::new(replacement_evidence),
        row_events,
        row_after,
        replacement_dequeued,
    })
}

pub(super) struct OriginalRun {
    pub(super) evidence: wire::OriginalEvidence,
    pub(super) target: Option<OutboundItem>,
    pub(super) row: Arc<Mutex<Option<DurableDelivery>>>,
    pub(super) cancelled: bool,
}

pub(super) async fn run_original(
    case: &wire::Case,
    index: usize,
    sequence: Sequence,
) -> Result<OriginalRun> {
    use crate::services::messaging::direct_workflow::commit_prepared_application;
    use crate::xmpp::{frame_execution::FrameExecution, protocol::ClientTransport};
    let original = &case.originals[index];
    let ids = &case.identities.originals[index];
    let policy = &case.policy[index];
    let route_plan = &case.route[index];
    let frame =
        FrameExecution::for_saved_case(ClientTransport::Tcp, &original.xml, original.frame_id.0);
    let owner = frame.direct_operation();
    let log = Arc::new(FrameLog {
        owner: owner.clone(),
        sequence,
        prefixes: Mutex::new(vec![]),
        route: Mutex::new(wire::RouteEvidence::default()),
        routing: AtomicBool::new(false),
        direct_pending: AtomicBool::new(false),
        rearm_pending: AtomicBool::new(false),
    });
    let row = Arc::new(Mutex::new(None));
    let admission = MessageAdmissionService::new(AdmissionPort {
        plan: &case.admission[index],
        log: log.clone(),
    });
    let app = MessageApplication::new(DirectPort {
        plan: &case.direct_repository[index],
        log: log.clone(),
        row: row.clone(),
    });
    let port = RoutePort {
        plan: route_plan,
        clustered: policy.clustered,
        log: log.clone(),
        health: Mutex::new(route_plan.health_modes.iter().copied().collect()),
        remote: Mutex::new(route_plan.remote_primary_returns.iter().copied().collect()),
    };
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let mut prefill_receivers = Vec::new();
    if let Some(wire::Item::Plain {
        xml,
        transport_receipt,
    }) = route_plan.prefill.get()
    {
        let item = if *transport_receipt {
            let (receipt, receiver) = tokio::sync::mpsc::unbounded_channel();
            prefill_receivers.push(receiver);
            OutboundItem::with_transport_receipt(xml.clone(), receipt)
        } else {
            OutboundItem::plain(xml.clone())
        };
        sender
            .try_send(item)
            .map_err(|_| anyhow::anyhow!("failed empty controlled queue prefill"))?;
    }
    let sender = OutboundSender::new(sender);
    let targets = route_plan
        .targets
        .iter()
        .map(|target| (target.jid.clone(), sender.clone()))
        .collect::<Vec<_>>();
    let mut projection = None;
    let mut prepared_evidence = None;
    let mut continuation = None;
    let child = async {
        let document = roxmltree::Document::parse(&original.xml)?;
        let root = document.root_element();
        let source = OriginalDirectMessage::capture(
            root,
            case.identities.actor_id.0,
            &original.sender_full,
            &original.target,
            &original.xml,
        );
        let mut lease = None;
        if let Some(payload) = source.rated_payload() {
            let request = MessageAdmissionRequest {
                actor_id: source.actor_id,
                account_bare: bare_jid(source.sender),
                normalized_target: source.target,
                origin_id: source.origin_id.as_deref(),
                normalized_payload: payload,
                pow_intent_payload: source.routed_raw,
                subject: "message",
                actors: &[],
                proof: None,
            };
            let retained = owner.begin(&request)?;
            frame.enter(Stage::MessageAdmission);
            let MessageAdmissionStart::Proceed {
                lease: returned, ..
            } = admission
                .begin_message_admission_retained(&request, &retained)
                .await?
            else {
                anyhow::bail!("unexpected controlled admission result");
            };
            lease = returned;
            log.prefix();
        }
        let local = source.project_local(
            LocalProjectionAuthority {
                recipient_id: case.identities.recipient_id.0,
                recipient_bare: &policy.recipient_bare,
                sender_stable_id: ids.sender_stable_id.0,
                recipient_stable_id: ids.recipient_stable_id.0,
                domain: &policy.domain,
            },
            policy.encrypted,
            None,
        );
        let eligibility =
            direct_spool_eligibility(policy.degraded_spool_eligible, policy.spool_privacy_permits);
        let applied = {
            let delayed = local.delayed(
                chrono::DateTime::parse_from_rfc3339(&original.at_utc)?.with_timezone(&chrono::Utc),
                LocalArchivePolicy {
                    sender_enabled: policy.sender_archive,
                    recipient_enabled: policy.recipient_archive,
                },
            );
            let mut archives = Vec::with_capacity(2);
            if policy.sender_archive {
                archives.push(ArchiveWrite {
                    id: ids.sender_stable_id.0,
                    owner_id: source.actor_id,
                    peer_jid: source.target,
                    stanza: &local.sender_archive_stanza,
                    encrypted: local.encrypted,
                    stanza_id: source.stanza_id,
                });
            }
            if policy.recipient_archive && case.identities.recipient_id.0 != source.actor_id {
                archives.push(ArchiveWrite {
                    id: ids.recipient_stable_id.0,
                    owner_id: case.identities.recipient_id.0,
                    peer_jid: source.sender,
                    stanza: &local.recipient_archive_stanza,
                    encrypted: local.encrypted,
                    stanza_id: source.stanza_id,
                });
            }
            let identity = source.origin_id.as_deref().map(|value| MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: bare_jid(source.sender),
                actor_scope: bare_jid(source.sender),
                target_scope: bare_jid(source.target),
                value,
                payload: &local.rewritten,
            });
            let command = ValidatedPersonalMessage {
                local_actor_id: Some(source.actor_id),
                identity,
                archives: &archives,
                destination: PersonalMessageDestination::Local(LocalDelivery {
                    delivery_id: ids.recipient_stable_id.0,
                    recipient_id: case.identities.recipient_id.0,
                    recipient_bare_jid: &policy.recipient_bare,
                    sender_jid: source.sender,
                    stanza: &delayed.stanza,
                    encrypted: local.encrypted,
                    mam_backed: policy.recipient_archive,
                }),
            };
            projection = Some(wire::Projection {
                message_type: source.message_type.to_owned(),
                origin_id: source.origin_id.clone(),
                rated: source.rated_payload().is_some(),
                normalized_payload: source.rated_payload().map(str::to_owned),
                live_xml: local.recipient_delivery.clone(),
                stored_xml: delayed.stanza.clone(),
                archives: command
                    .archives
                    .iter()
                    .map(|archive| wire::ArchiveEvidence {
                        archive_id: wire::Id(archive.id),
                        owner_id: wire::Id(archive.owner_id),
                        peer_jid: archive.peer_jid.to_owned(),
                        stanza_id: archive.stanza_id.map(str::to_owned),
                        encrypted: archive.encrypted,
                        xml: archive.stanza.to_owned(),
                    })
                    .collect(),
            });
            let PersonalMessageDestination::Local(destination) = command.destination else {
                unreachable!()
            };
            prepared_evidence = Some(wire::PreparedEvidence {
                actor_id: wire::Id(command.local_actor_id.expect("local actor")),
                recipient_id: wire::Id(destination.recipient_id),
                delivery_id: wire::Id(destination.delivery_id),
                eligibility: match eligibility {
                    DirectSpoolEligibility::Eligible => "Eligible",
                    DirectSpoolEligibility::LiveOnly => "LiveOnly",
                },
                encrypted: destination.encrypted,
                mam_backed: destination.mam_backed,
                archive_ids: command
                    .archives
                    .iter()
                    .map(|archive| wire::Id(archive.id))
                    .collect(),
                identity: command.identity.map(|identity| wire::IdentityEvidence {
                    authority: "LocalOrigin",
                    actor_scope_raw: identity.actor_scope_raw.to_owned(),
                    actor_scope: identity.actor_scope.to_owned(),
                    target_scope: identity.target_scope.to_owned(),
                    value: identity.value.to_owned(),
                    payload: identity.payload.to_owned(),
                }),
            });
            let prepared = delayed.bind(owner.clone(), command, eligibility)?;
            frame.enter(Stage::MessageAdmission);
            commit_prepared_application(&app, prepared).await
        };
        // The delayed command and archives have ended. The actual application
        // pair retains only the production continuation's immutable live view.
        log.prefix();
        match continue_prepared_local_direct(applied, &mut lease, &admission, &port, || {
            frame.enter(Stage::MessageFollowup)
        })
        .await
        {
            ContinuedLocalDirect::Accepted => {
                continuation = Some(wire::Continuation {
                    kind: "Accepted",
                    error_type: None,
                    error_condition: None,
                })
            }
            ContinuedLocalDirect::Reject(error) => {
                let (kind, condition) = error.stanza_error();
                continuation = Some(wire::Continuation {
                    kind: "Reject",
                    error_type: Some(kind),
                    error_condition: Some(condition),
                });
            }
            ContinuedLocalDirect::Live(live) => {
                continuation = Some(wire::Continuation {
                    kind: "Live",
                    error_type: None,
                    error_condition: None,
                });
                frame.enter(Stage::MessageRouting);
                log.routing.store(true, Ordering::SeqCst);
                live.route_with(&port, &targets)
                    .await
                    .map_err(|_| anyhow::anyhow!("prepared controlled route failed"))?;
            }
        }
        Ok(())
    };
    let mut runner = Box::pin(frame.run(child));
    let cancelled = matches!(&case.drive, wire::Drive::DropDirectCommit { frame_id } | wire::Drive::DropRearm { frame_id } if *frame_id == original.frame_id);
    let actual = futures::poll!(&mut runner);
    let polls = vec![log.sequence.lock().unwrap().polled(&actual)];
    if cancelled {
        let reached = match &case.drive {
            wire::Drive::DropDirectCommit { .. } => log.direct_pending.load(Ordering::SeqCst),
            wire::Drive::DropRearm { .. } => log.rearm_pending.load(Ordering::SeqCst),
            _ => false,
        };
        anyhow::ensure!(
            actual.is_pending() && reached,
            "declared sender drop cut was not reached"
        );
        drop(runner);
    } else {
        // Every controlled non-cut port is immediately ready. An unexpected
        // pending state is a fixture failure, not a hidden unbounded wait.
        drop(runner);
        match actual {
            std::task::Poll::Ready(Ok(())) => {}
            std::task::Poll::Ready(Err(_)) => anyhow::bail!("controlled frame failed"),
            std::task::Poll::Pending => anyhow::bail!("unexpected pending controlled frame"),
        }
    }
    log.prefix();
    let state = original_state(&owner);
    let mut target = None;
    if state
        .handoff
        .as_ref()
        .is_some_and(|handoff| handoff.local_accepted)
    {
        let item = receiver
            .try_recv()
            .map_err(|_| anyhow::anyhow!("accepted queue item missing"))?;
        anyhow::ensure!(
            item.c2s_delivery().is_some_and(|source| source.recipient_id
                == case.identities.recipient_id.0
                && source.message_id == ids.recipient_stable_id.0),
            "accepted target item identity mismatch"
        );
        let seq = next(&log.sequence);
        log.route.lock().unwrap().dequeued.push(wire::Dequeue {
            seq,
            source: item.durable_source.map(Into::into),
            xml: item.stanza.clone(),
        });
        target = Some(item);
    }
    // Inventory consumes the remaining real receiver only after producer and
    // target-dequeue work ended. This cleanup is never a delivery observation.
    while let Ok(item) = receiver.try_recv() {
        log.route.lock().unwrap().queue_remaining.push(wire::Slot {
            xml: item.stanza,
            source: item.durable_source.map(Into::into),
        });
    }
    let mut route = log.route.lock().unwrap().clone();
    route.backpressure_disconnected = sender.backpressure_disconnect().is_cancelled();
    route.handoff = state.handoff;
    let prefixes = log.prefixes.lock().unwrap().clone();
    // A prefilled P does not acquire a synthetic delivery receipt on cleanup.
    for mut receiver in prefill_receivers {
        anyhow::ensure!(
            !matches!(receiver.try_recv(), Ok(())),
            "prefill cleanup acknowledged an item"
        );
    }
    Ok(OriginalRun {
        evidence: wire::OriginalEvidence {
            frame_id: original.frame_id,
            projection,
            prepared: prepared_evidence,
            begin: state.begin,
            finalize: state.finalize,
            direct: state.direct,
            continuation,
            route,
            terminal: state.terminal,
            prefixes,
            polls,
        },
        target,
        row,
        cancelled,
    })
}
