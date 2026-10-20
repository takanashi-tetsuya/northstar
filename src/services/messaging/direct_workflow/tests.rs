use super::*;
use northstar_message_application::direct_lifecycle::{DirectOutcomeClass, TerminalReason};
use northstar_message_core::LocalDelivery;

fn prepared() -> (DirectOperationHandle, PreparedLocalDirect<'static, 'static>) {
    let owner = DirectOperationHandle::new(Uuid::new_v4());
    let command = ValidatedPersonalMessage {
        local_actor_id: Some(Uuid::from_u128(1)),
        identity: None,
        archives: &[],
        destination: PersonalMessageDestination::Local(LocalDelivery {
            delivery_id: Uuid::from_u128(2),
            recipient_id: Uuid::from_u128(3),
            recipient_bare_jid: "bob@example.test",
            sender_jid: "alice@example.test/device",
            stanza: "private-stored-stanza",
            encrypted: false,
            mam_backed: false,
        }),
    };
    let prepared = PreparedLocalDirect::bind(
        owner.clone(),
        LocalPreparation {
            actor_id: Uuid::from_u128(1),
            sender_bare: "alice@example.test",
            sender_full: "alice@example.test/device",
            target_bare: "bob@example.test",
            target_full: "bob@example.test",
            message_type: "chat",
            live_stanza: "private-live-stanza",
            origin_id: None,
            identity_payload: "private-identity-stanza",
            stored_stanza: "private-stored-stanza",
            admission: PreparationAdmission::NoAdmissionRequired,
        },
        command,
        DirectSpoolEligibility::Eligible,
        LiveDirectBinding {
            sender: "alice@example.test/device",
            target: "bob@example.test",
            target_bare: "bob@example.test",
            message_type: "chat",
            stanza: "private-live-stanza",
            recipient_id: Uuid::from_u128(3),
        },
    )
    .unwrap();
    (owner, prepared)
}
fn stored() -> TransactionOutcome {
    TransactionOutcome::Stored {
        recipient_id: Uuid::from_u128(3),
        delivery_id: Uuid::from_u128(2),
        archive_ids: vec![],
        live_claim_id: Some(Uuid::from_u128(2)),
    }
}

#[tokio::test]
async fn real_commit_wrapper_preserves_every_cancellation_cut_in_outer_owner() {
    for cut in 0..4 {
        let (owner, prepared) = prepared();
        let mut future = Box::pin(async {
            prepared
                .start(prepared.command(), prepared.eligibility())
                .unwrap();
            if cut == 1 {
                std::future::pending::<()>().await;
            }
            commit_observed(
                async {
                    if cut == 2 {
                        std::future::pending::<()>().await;
                    }
                    Ok::<(), anyhow::Error>(())
                },
                &prepared,
                stored(),
                DirectPostCommitMode::Live,
            )
            .await
            .unwrap();
            std::future::pending::<()>().await;
        });
        if cut != 0 {
            assert!(futures::poll!(&mut future).is_pending());
        }
        drop(future);
        drop(prepared);
        let snapshot = owner.snapshot().direct.unwrap();
        assert_eq!(snapshot.started, cut != 0);
        assert!(matches!(
            (&snapshot.knowledge, cut),
            (Knowledge::NoCommitRequested, 0 | 1)
                | (Knowledge::CommitCallEntered(_), 2)
                | (Knowledge::ReceiptKnown(_), 3)
        ));
        assert_eq!(snapshot.outcome, None);
        let summary = owner.retire(TerminalReason::Cancelled).direct.unwrap();
        assert_eq!(
            summary.confirmed_outcome,
            (cut == 3).then_some(DirectOutcomeClass::Stored)
        );
        assert_eq!(summary.returned_mode, None);
    }
}

#[test]
fn prepared_command_is_immutable_at_the_actual_application_observer_entry() {
    let (owner, prepared) = prepared();
    let mut changed = *prepared.command();
    let PersonalMessageDestination::Local(mut destination) = changed.destination else {
        unreachable!()
    };
    destination.stanza = "substituted stored payload";
    changed.destination = PersonalMessageDestination::Local(destination);
    let before = owner.snapshot();
    assert_eq!(
        prepared.start(&changed, prepared.eligibility()),
        Err(Rejected::Command)
    );
    assert_eq!(owner.snapshot(), before);
    prepared
        .start(prepared.command(), prepared.eligibility())
        .unwrap();
    assert_eq!(
        prepared.start(prepared.command(), prepared.eligibility()),
        Err(Rejected::AlreadyStarted)
    );
    assert!(!format!("{prepared:?}").contains("private-"));
}

#[tokio::test]
async fn known_transaction_outcome_survives_mapping_error_without_fabricating_mode_or_delivery() {
    for fact in [
        stored(),
        TransactionOutcome::Replay {
            archive_ids: vec![Uuid::from_u128(99)],
        },
        TransactionOutcome::AccountUnavailable,
    ] {
        let (owner, prepared) = prepared();
        prepared
            .start(prepared.command(), prepared.eligibility())
            .unwrap();
        commit_observed(
            async { Ok::<(), anyhow::Error>(()) },
            &prepared,
            fact.clone(),
            DirectPostCommitMode::Live,
        )
        .await
        .unwrap();
        let outcome = prepared.complete(None).unwrap();
        let error = continuation_error(
            anyhow::anyhow!("injected continuation failure"),
            Some(outcome),
        );
        assert_eq!(preserved_transaction(&error), Some(&fact));
        assert_eq!(
            owner
                .retire(TerminalReason::Completed)
                .direct
                .unwrap()
                .returned_mode,
            None
        );
    }
}

fn complete_stored(prepared: &PreparedLocalDirect<'_, '_>, mode: Option<DirectPostCommitMode>) {
    use northstar_message_core::{MessageCommit, MessagePostCommit};
    prepared
        .start(prepared.command(), prepared.eligibility())
        .unwrap();
    let transaction = prepared
        .prepare(stored(), DirectPostCommitMode::Live)
        .unwrap();
    prepared.received(transaction).unwrap();
    prepared
        .complete(mode.map(|mode| DirectPersonalMessageAdmission {
            commit: MessageCommit::Stored {
                archive_written: false,
                post_commit: MessagePostCommit::RouteLocalDelivery {
                    recipient_id: Uuid::from_u128(3),
                    delivery_id: Uuid::from_u128(2),
                },
            },
            mode,
            live_claim_id: Some(Uuid::from_u128(2)),
        }))
        .unwrap();
}
fn route_request<S>(targets: &[(String, S)]) -> super::super::DirectRouteRequest<'_, S> {
    super::super::DirectRouteRequest {
        message_type: "chat",
        target: super::super::DirectRouteTarget::Bare("bob@example.test"),
        sender: "alice@example.test/device",
        recipient_id: Uuid::from_u128(3),
        stanza: "private-live-stanza",
        delivery: super::super::DirectRouteDelivery::Committed(
            northstar_delivery_core::DurableDelivery {
                recipient_id: Uuid::from_u128(3),
                message_id: Uuid::from_u128(2),
                claim_id: Some(Uuid::from_u128(2)),
            },
        ),
        approved_targets: targets,
        enforce_direct_health: true,
    }
}
fn handoff() -> (DirectOperationHandle, PreparedDirectHandoff<'static>) {
    let (owner, prepared) = prepared();
    complete_stored(&prepared, Some(DirectPostCommitMode::Live));
    let PreparedHandoffNext::Route(handoff) = prepared
        .into_continuation()
        .after_finalize(|| DirectPostCommitMode::Live)
        .unwrap()
    else {
        unreachable!()
    };
    (owner, handoff)
}

#[test]
fn retained_continuation_keeps_the_actual_mode_read_short_circuit() {
    for returned in [
        None,
        Some(DirectPostCommitMode::SpoolOnly),
        Some(DirectPostCommitMode::Live),
    ] {
        let (_, prepared) = prepared();
        complete_stored(&prepared, returned);
        let reads = std::cell::Cell::new(0);
        let next = prepared
            .into_continuation()
            .after_finalize(|| {
                reads.set(reads.get() + 1);
                DirectPostCommitMode::Live
            })
            .unwrap();
        assert_eq!(
            reads.get(),
            usize::from(returned == Some(DirectPostCommitMode::Live))
        );
        assert_eq!(
            matches!(next, PreparedHandoffNext::Route(_)),
            returned == Some(DirectPostCommitMode::Live)
        );
    }
}

#[test]
fn actual_prepared_router_binding_rejects_changed_live_authority_before_consumption() {
    for mutation in 0..8 {
        let (owner, handoff) = handoff();
        let before = owner.snapshot();
        let mut request = route_request::<()>(&[]);
        match mutation {
            0 => request.sender = "mallory@example.test/device",
            1 => request.recipient_id = Uuid::from_u128(99),
            2 => request.stanza = "changed live payload",
            3 => request.target = super::super::DirectRouteTarget::Bare("mallory@example.test"),
            4 => {
                request.target = super::super::DirectRouteTarget::Full {
                    jid: "bob@example.test",
                    bare: "mallory@example.test",
                }
            }
            5 => {
                request.target = super::super::DirectRouteTarget::Full {
                    jid: "bob@example.test",
                    bare: "bob@example.test",
                }
            }
            6 => request.enforce_direct_health = false,
            _ => request.message_type = "headline",
        }
        assert!(handoff.bind_route(&request).is_err());
        assert_eq!(owner.snapshot(), before);
    }
    let (owner, handoff) = handoff();
    let (item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
    assert_eq!(item.stanza, "private-live-stanza");
    assert!(owner.snapshot().reservation.is_none());
    assert_eq!(witness.snapshot().source, item.c2s_delivery().unwrap());
}

#[test]
fn real_enqueue_gate_refuses_wrong_source_and_same_ids_changed_payload_without_sending() {
    use crate::xmpp::outbound::{OutboundItem, OutboundSender, RouteEnqueue};
    for changed_source in [true, false] {
        let (_, handoff) = handoff();
        let (mut item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
        let source = item.c2s_delivery().unwrap();
        let permit = witness.local_permit(source).unwrap();
        if changed_source {
            item = OutboundItem::durable(
                item.stanza,
                northstar_delivery_core::DurableDelivery {
                    message_id: Uuid::from_u128(99),
                    ..source
                },
            );
        } else {
            item.stanza = "changed private payload".into();
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let sender = OutboundSender::new(tx);
        let rejected = RouteEnqueue::bind(item, Some(permit), "private-live-stanza").unwrap_err();
        assert!(!format!("{rejected:?}").contains("private"));
        assert!(!witness.snapshot().local_accepted);
        assert_eq!(
            witness.snapshot().local_call,
            northstar_message_application::direct_handoff::LocalKnowledge::NotRequested
        );
        assert!(witness.local_permit(source).is_ok());
        assert!(rx.try_recv().is_err());
        assert!(!sender.backpressure_disconnect().is_cancelled());
    }
}

#[test]
fn actual_full_and_closed_refusals_preserve_item_channels_and_disconnect_order() {
    use crate::xmpp::outbound::{OutboundSender, RouteEnqueue};
    use northstar_message_application::direct_handoff::Refusal;
    for closed in [false, true] {
        let (_, handoff) = handoff();
        let (mut item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
        let source = item.c2s_delivery().unwrap();
        let (receipt, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
        item.transport_receipt = Some(receipt);
        let address = item.stanza.as_ptr();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let sender = OutboundSender::new(tx);
        if closed {
            rx.close();
        } else {
            sender.try_send("occupied".into()).unwrap();
        }
        let enqueue = RouteEnqueue::bind(
            item,
            Some(witness.local_permit(source).unwrap()),
            "private-live-stanza",
        )
        .unwrap();
        let refused = sender.try_send_route_item(enqueue).unwrap_err();
        let item = match refused {
            crate::xmpp::outbound::RouteSendError::Full(item) => {
                assert!(!closed);
                assert!(sender.backpressure_disconnect().is_cancelled());
                item
            }
            crate::xmpp::outbound::RouteSendError::Closed(item) => {
                assert!(closed);
                item
            }
            crate::xmpp::outbound::RouteSendError::Binding(_) => panic!("valid item rejected"),
        };
        assert_eq!(item.stanza.as_ptr(), address);
        assert_eq!(item.c2s_delivery(), Some(source));
        assert_eq!(
            witness.snapshot().last_local_refusal,
            Some(if closed {
                Refusal::Closed
            } else {
                Refusal::Full
            })
        );
        assert!(receipt_rx.try_recv().is_err());
        let (tx, mut accepted_rx) = tokio::sync::mpsc::channel(1);
        let next = OutboundSender::new(tx);
        next.try_send_route_item(
            RouteEnqueue::bind(
                item,
                Some(witness.local_permit(source).unwrap()),
                "private-live-stanza",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(witness.snapshot().local_accepted);
        let received = accepted_rx.try_recv().unwrap();
        assert_eq!(received.stanza.as_ptr(), address);
        received.confirm_transport_ownership();
        assert_eq!(receipt_rx.try_recv(), Ok(()));
    }
}

struct RealQueuePort {
    owner: DirectOperationHandle,
    events: std::sync::Mutex<Vec<&'static str>>,
    pending_rearm: bool,
}
impl super::super::OnlineRoutePort for RealQueuePort {
    type Session = crate::xmpp::outbound::OutboundSender;
    fn try_local(
        &self,
        session: &Self::Session,
        enqueue: crate::xmpp::outbound::RouteEnqueue,
    ) -> Result<(), crate::xmpp::outbound::RouteSendError> {
        self.events.lock().unwrap().push("enqueue");
        session.try_send_route_item(enqueue)
    }
    fn record_local_accept(&self, _: bool) {
        assert!(self.owner.snapshot().handoff.unwrap().local_accepted);
        self.events.lock().unwrap().push("accepted");
    }
    async fn route_available_remote(
        &self,
        _: &str,
        _: &str,
        _: Option<northstar_delivery_core::DurableDelivery>,
    ) -> bool {
        false
    }
    async fn route_remote_primary(
        &self,
        _: &str,
        _: &str,
        _: Option<northstar_delivery_core::DurableDelivery>,
    ) -> super::super::OnlineRouteResult {
        self.events.lock().unwrap().push("remote");
        super::super::OnlineRouteResult::default()
    }
}
impl super::super::FullJidFallbackPort for RealQueuePort {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, Self::Session)> {
        vec![]
    }
    fn available_priority(&self, _: &Self::Session) -> Option<i16> {
        Some(0)
    }
    fn priority(&self, _: &Self::Session) -> i16 {
        0
    }
    async fn privacy_allows_fallback(&self, _: &Self::Session, _: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
    fn post_accept_failed(&self) {
        self.events.lock().unwrap().push("failed");
    }
}
impl super::super::DirectMessageRoutePort for RealQueuePort {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        self.events.lock().unwrap().push("health");
        DirectPostCommitMode::Live
    }
    fn clustered_direct_routes(&self) -> bool {
        true
    }
    async fn rearm_direct_route(&self, _: northstar_delivery_core::DurableDelivery) {
        self.events.lock().unwrap().push("rearm");
        if self.pending_rearm {
            std::future::pending::<()>().await;
        }
    }
}

#[tokio::test]
async fn real_router_sender_queue_fact_survives_a_later_outer_continuation_cancel() {
    let (owner, handoff) = handoff();
    let port = RealQueuePort {
        owner: owner.clone(),
        events: Default::default(),
        pending_rearm: false,
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let targets = [(
        "bob@example.test/device".into(),
        crate::xmpp::outbound::OutboundSender::new(tx),
    )];
    let mut future = Box::pin(async {
        let outcome = super::super::DirectMessageRouter::route_prepared(
            &port,
            route_request(&targets),
            handoff,
        )
        .await
        .unwrap();
        assert!(matches!(
            outcome,
            super::super::DirectRouteOutcome::Routed { .. }
        ));
        // Controlled outer-followup suspension, after the real router has
        // returned; the local-success router itself need not suspend.
        std::future::pending::<()>().await;
    });
    assert!(futures::poll!(&mut future).is_pending());
    drop(future);
    let summary = owner.retire(TerminalReason::Cancelled);
    assert!(summary.handoff.unwrap().local_accepted);
    assert_eq!(
        summary.handoff.unwrap().route_end,
        northstar_message_application::direct_handoff::RouteEnd::Returned
    );
    let item = rx.try_recv().unwrap();
    assert_eq!(item.stanza, "private-live-stanza");
    assert_eq!(
        item.c2s_delivery().unwrap().claim_id,
        Some(Uuid::from_u128(2))
    );
    assert_eq!(
        *port.events.lock().unwrap(),
        ["health", "enqueue", "accepted", "health"]
    );
}

#[tokio::test]
async fn real_router_rearm_entry_survives_cancellation_without_claiming_release() {
    let (owner, handoff) = handoff();
    let port = RealQueuePort {
        owner: owner.clone(),
        events: Default::default(),
        pending_rearm: true,
    };
    let mut future = Box::pin(super::super::DirectMessageRouter::route_prepared(
        &port,
        route_request(&[]),
        handoff,
    ));
    assert!(futures::poll!(&mut future).is_pending());
    drop(future);
    let snapshot = owner.snapshot().handoff.unwrap();
    assert_eq!(
        snapshot.rearm,
        northstar_message_application::direct_handoff::RearmKnowledge::CallEntered
    );
    assert_eq!(
        snapshot.route_end,
        northstar_message_application::direct_handoff::RouteEnd::Dropped
    );
    assert!(snapshot.prior_remote_uncertain);
    assert!(!snapshot.local_accepted);
    assert_eq!(*port.events.lock().unwrap(), ["health", "remote", "rearm"]);
}

#[test]
fn refused_item_is_rechecked_against_the_original_live_projection_before_retry() {
    let (owner, handoff) = handoff();
    let (item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
    let port = RealQueuePort {
        owner: owner.clone(),
        events: Default::default(),
        pending_rearm: false,
    };
    let mut payload =
        super::super::RoutePayload::prepared("private-live-stanza", item, witness.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let sender = crate::xmpp::outbound::OutboundSender::new(tx);
    rx.close();
    assert!(!payload.enqueue(&port, &sender));
    let before = owner.snapshot();
    // Deliberately corrupt only the refused value in this controlled test;
    // production keeps this value private between attempts.
    payload.item.as_mut().unwrap().stanza = "same IDs, substituted payload".into();
    let (tx, mut accepted_rx) = tokio::sync::mpsc::channel(1);
    let next = crate::xmpp::outbound::OutboundSender::new(tx);
    assert!(!payload.enqueue(&port, &next));
    assert!(payload.binding_rejected);
    assert_eq!(owner.snapshot(), before);
    assert!(accepted_rx.try_recv().is_err());
    assert_eq!(*port.events.lock().unwrap(), ["enqueue"]);
}

#[test]
fn live_preparation_comparison_rejects_substituted_projection_before_direct_effect() {
    for mutation in 0..5 {
        let (_, template) = prepared();
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let mut live = LiveDirectBinding {
            sender: "alice@example.test/device",
            target: "bob@example.test",
            target_bare: "bob@example.test",
            message_type: "chat",
            stanza: "private-live-stanza",
            recipient_id: Uuid::from_u128(3),
        };
        match mutation {
            0 => live.sender = "mallory@example.test/device",
            1 => live.target = "bob@example.test/other",
            2 => live.recipient_id = Uuid::from_u128(99),
            3 => live.stanza = "substituted-live-stanza",
            _ => live.target_bare = "mallory@example.test",
        }
        let before = owner.snapshot();
        let result = PreparedLocalDirect::bind(
            owner.clone(),
            LocalPreparation {
                actor_id: Uuid::from_u128(1),
                sender_bare: "alice@example.test",
                sender_full: "alice@example.test/device",
                target_bare: "bob@example.test",
                target_full: "bob@example.test",
                message_type: "chat",
                live_stanza: "private-live-stanza",
                origin_id: None,
                identity_payload: "private-identity-stanza",
                stored_stanza: "private-stored-stanza",
                admission: PreparationAdmission::NoAdmissionRequired,
            },
            *template.command(),
            DirectSpoolEligibility::Eligible,
            live,
        );
        assert!(result.is_err());
        assert_eq!(owner.snapshot(), before);
    }
}

#[test]
fn held_enqueue_permit_cannot_start_after_frame_retirement() {
    use crate::xmpp::outbound::{OutboundSender, RouteEnqueue, RouteSendError};
    let (owner, handoff) = handoff();
    let (item, witness) = handoff.bind_route(&route_request::<()>(&[])).unwrap();
    let permit = witness.local_permit(item.c2s_delivery().unwrap()).unwrap();
    let enqueue = RouteEnqueue::bind(item, Some(permit), "private-live-stanza").unwrap();
    owner.retire(TerminalReason::Cancelled);
    let before = owner.snapshot();
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let sender = OutboundSender::new(tx);
    assert!(matches!(
        sender.try_send_route_item(enqueue),
        Err(RouteSendError::Binding(_))
    ));
    assert_eq!(owner.snapshot(), before);
    assert!(rx.try_recv().is_err());
}
