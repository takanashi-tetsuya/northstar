use super::*;
use crate::services::message_admission::{
    witness::AdmissionWitness, MessageAdmissionRepository, MessageAdmissionService,
};
use northstar_abuse_policy::{
    admission_execution::{Effect, ReconcileResult},
    admission_transaction::FinalizeDecision,
};
use uuid::Uuid;

pub(super) const FRAME_MESSAGE: &str = "<message type='chat'/>";

struct MemoryGuard;
impl MessageAdmissionRepository for MemoryGuard {
    async fn begin(
        &self,
        _: &MessageAdmissionRequest<'_>,
        _: &AdmissionWitness,
    ) -> Result<MessageAdmissionStart> {
        Ok(MessageAdmissionStart::Proceed {
            lease: None,
            requirement: crate::security::abuse::WorkRequirement {
                action: "message".into(),
                step: 0,
                work_factor: 1,
                max_work_factor: 1,
                hard_wait_seconds: 0,
                retry_after_seconds: 0,
                cooldown_seconds: 0,
                approximate_max_device_seconds: 0,
                notice: String::new(),
            },
        })
    }
    async fn accept(
        &self,
        _: &crate::security::abuse::MessageAdmissionAcceptance<'_>,
        _: &AdmissionWitness,
    ) -> Result<FinalizeDecision> {
        panic!("preparation does not finalize")
    }
    async fn reconcile(&self, _: &Effect) -> Result<ReconcileResult> {
        panic!("preparation does not reconcile")
    }
}

async fn owner(source: &OriginalDirectMessage<'_>) -> DirectOperationHandle {
    let owner = DirectOperationHandle::new(Uuid::new_v4());
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
        let effect = owner.begin(&request).unwrap();
        MessageAdmissionService::new(MemoryGuard)
            .begin_message_admission_retained(&request, &effect)
            .await
            .unwrap();
    }
    owner
}

fn command<'a>(
    local: &'a LocalOriginalProjection<'_, '_>,
    delayed: &'a DelayedLocalProjection<'_, '_, '_>,
) -> ValidatedPersonalMessage<'a> {
    let source = local.source;
    ValidatedPersonalMessage {
        local_actor_id: Some(source.actor_id),
        archives: &[],
        identity: source.origin_id.as_deref().map(|origin| MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: bare_jid(source.sender),
            actor_scope: bare_jid(source.sender),
            target_scope: bare_jid(source.target),
            value: origin,
            payload: &local.rewritten,
        }),
        destination: PersonalMessageDestination::Local(LocalDelivery {
            delivery_id: local.authority.recipient_stable_id,
            recipient_id: local.authority.recipient_id,
            recipient_bare_jid: local.authority.recipient_bare,
            sender_jid: source.sender,
            stanza: &delayed.stanza,
            encrypted: local.encrypted,
            mam_backed: delayed.archive_policy.recipient_enabled,
        }),
    }
}

fn authority(target: &str, own: bool) -> LocalProjectionAuthority<'_> {
    LocalProjectionAuthority {
        recipient_id: Uuid::from_u128(if own { 1 } else { 2 }),
        recipient_bare: bare_jid(target),
        sender_stable_id: Uuid::from_u128(10),
        recipient_stable_id: Uuid::from_u128(if own { 10 } else { 20 }),
        domain: "example.test",
    }
}

#[tokio::test]
async fn preparation_preserves_full_bare_delayed_live_self_and_unrated_controls() {
    for (raw, target, own, rated) in [
        ("<message to='bob@EXAMPLE.test/phone'><body>hello</body><origin-id xmlns='urn:xmpp:sid:0' id='origin'/></message>", "bob@example.test/phone", false, true),
        ("<message to='bob@example.test'><store xmlns='urn:xmpp:hints'/></message>", "bob@example.test", false, false),
        ("<message to='alice@example.test'><body>self</body></message>", "alice@example.test", true, true),
    ] {
        let document = roxmltree::Document::parse(raw).unwrap();
        let source = OriginalDirectMessage::capture(document.root_element(), Uuid::from_u128(1), "alice@example.test/device", target, raw);
        assert_eq!(source.rated_payload().is_some(), rated);
        let owner = owner(&source).await;
        let local = source.project_local(authority(target, own), false, None);
        let delayed = local.delayed(chrono::DateTime::from_timestamp(100, 0).unwrap(), LocalArchivePolicy::default());
        assert_ne!(delayed.stanza, local.recipient_delivery);
        if own { assert_eq!(local.sender_archive, local.recipient_delivery); }
        let command = command(&local, &delayed);
        if let Some(identity) = command.identity {
            assert_eq!(identity.target_scope, bare_jid(target));
            assert_ne!(identity.payload, source.rated_payload().unwrap());
        }
        let prepared = delayed.bind(owner.clone(), command, DirectSpoolEligibility::Eligible).unwrap();
        assert_eq!(*prepared.command(), command);
        assert_eq!(owner.snapshot().reservation.is_some(), rated);
        assert!(owner.snapshot().direct.is_some());
    }
}

#[tokio::test]
async fn independently_changed_actor_origin_full_target_or_source_payload_cannot_reuse_admission() {
    let raw = "<message to='bob@example.test/phone'><body>hello</body><origin-id xmlns='urn:xmpp:sid:0' id='origin'/></message>";
    let document = roxmltree::Document::parse(raw).unwrap();
    let original = OriginalDirectMessage::capture(
        document.root_element(),
        Uuid::from_u128(1),
        "alice@example.test/device",
        "bob@example.test/phone",
        raw,
    );
    for field in 0..4 {
        let owner = owner(&original).await;
        let changed_raw = match field {
            1 => raw.replace("id='origin'", "id='other'"),
            2 => raw.replace("/phone", "/other"),
            3 => raw.replace("hello", "changed"),
            _ => raw.to_owned(),
        };
        let document = roxmltree::Document::parse(&changed_raw).unwrap();
        let target = if field == 2 {
            "bob@example.test/other"
        } else {
            "bob@example.test/phone"
        };
        let changed = OriginalDirectMessage::capture(
            document.root_element(),
            Uuid::from_u128(if field == 0 { 99 } else { 1 }),
            "alice@example.test/device",
            target,
            &changed_raw,
        );
        let local = changed.project_local(authority(target, false), false, None);
        let delayed = local.delayed(
            chrono::DateTime::from_timestamp(100, 0).unwrap(),
            LocalArchivePolicy::default(),
        );
        let before = owner.snapshot();
        assert!(delayed
            .bind(
                owner.clone(),
                command(&local, &delayed),
                DirectSpoolEligibility::Eligible
            )
            .is_err());
        assert_eq!(owner.snapshot(), before);
    }
}

#[tokio::test]
async fn changed_prepared_identity_payload_or_stored_projection_is_rejected_before_effect_issue() {
    let raw = "<message to='bob@example.test'><body>hello</body><origin-id xmlns='urn:xmpp:sid:0' id='origin'/></message>";
    let document = roxmltree::Document::parse(raw).unwrap();
    let source = OriginalDirectMessage::capture(
        document.root_element(),
        Uuid::from_u128(1),
        "alice@example.test/device",
        "bob@example.test",
        raw,
    );
    let local = source.project_local(authority(source.target, false), false, None);
    let delayed = local.delayed(
        chrono::DateTime::from_timestamp(100, 0).unwrap(),
        LocalArchivePolicy::default(),
    );
    for field in 0..3 {
        let owner = owner(&source).await;
        let before = owner.snapshot();
        let mut changed = command(&local, &delayed);
        match field {
            0 => changed.identity.as_mut().unwrap().payload = "changed source payload",
            1 => changed.identity.as_mut().unwrap().value = "other-origin",
            2 => {
                let PersonalMessageDestination::Local(mut destination) = changed.destination else {
                    unreachable!()
                };
                destination.stanza = "changed stored projection";
                changed.destination = PersonalMessageDestination::Local(destination);
            }
            _ => unreachable!(),
        }
        assert!(delayed
            .bind(owner.clone(), changed, DirectSpoolEligibility::Eligible)
            .is_err());
        assert_eq!(owner.snapshot(), before);
    }
}

#[tokio::test]
async fn valid_unrated_frame_does_not_acquire_the_rated_normalized_payload_limit() {
    let prefix = "<message to='bob@example.test'><store xmlns='urn:xmpp:hints'/><!--";
    let suffix = "--></message>";
    let raw = format!(
        "{prefix}{}{suffix}",
        "x".repeat(1_048_576 - prefix.len() - suffix.len())
    );
    let document = roxmltree::Document::parse(&raw).unwrap();
    let source = OriginalDirectMessage::capture(
        document.root_element(),
        Uuid::from_u128(1),
        "alice@example.test/device",
        "bob@example.test",
        &raw,
    );
    assert!(source.rated_payload().is_none());
    let owner = owner(&source).await;
    let local = source.project_local(authority(source.target, false), false, None);
    let delayed = local.delayed(
        chrono::DateTime::from_timestamp(100, 0).unwrap(),
        LocalArchivePolicy::default(),
    );
    assert!(delayed.stanza.len() > 1_048_576);
    delayed
        .bind(
            owner.clone(),
            command(&local, &delayed),
            DirectSpoolEligibility::Eligible,
        )
        .unwrap();
    assert!(owner.snapshot().reservation.is_none());
}

#[tokio::test]
async fn exact_policy_projection_set_and_mam_flag_reject_missing_duplicate_or_changed_views() {
    for own in [false, true] {
        let target = if own {
            "alice@example.test"
        } else {
            "bob@example.test"
        };
        let raw = format!("<message to='{target}'><body>hello</body></message>");
        let document = roxmltree::Document::parse(&raw).unwrap();
        let source = OriginalDirectMessage::capture(
            document.root_element(),
            Uuid::from_u128(1),
            "alice@example.test/device",
            target,
            &raw,
        );
        let local = source.project_local(authority(target, own), false, None);
        for (sender_enabled, recipient_enabled) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let delayed = local.delayed(
                chrono::DateTime::from_timestamp(100, 0).unwrap(),
                LocalArchivePolicy {
                    sender_enabled,
                    recipient_enabled,
                },
            );
            let sender = ArchiveWrite {
                id: local.authority.sender_stable_id,
                owner_id: source.actor_id,
                peer_jid: target,
                stanza: &local.sender_archive_stanza,
                encrypted: false,
                stanza_id: None,
            };
            let recipient = ArchiveWrite {
                id: local.authority.recipient_stable_id,
                owner_id: local.authority.recipient_id,
                peer_jid: source.sender,
                stanza: &local.recipient_archive_stanza,
                encrypted: false,
                stanza_id: None,
            };
            let mut writes = Vec::new();
            if sender_enabled {
                writes.push(sender.clone());
            }
            if recipient_enabled && !own {
                writes.push(recipient);
            }
            let mut valid = command(&local, &delayed);
            valid.archives = &writes;
            let owner = owner(&source).await;
            let before = owner.snapshot();
            if !writes.is_empty() {
                let mut missing = valid;
                missing.archives = &[];
                assert!(delayed
                    .bind(owner.clone(), missing, DirectSpoolEligibility::Eligible)
                    .is_err());
            }
            let duplicated = vec![sender.clone(), sender];
            let mut duplicate = valid;
            duplicate.archives = &duplicated;
            assert!(delayed
                .bind(owner.clone(), duplicate, DirectSpoolEligibility::Eligible)
                .is_err());
            let mut changed_mam = valid;
            let PersonalMessageDestination::Local(mut destination) = changed_mam.destination else {
                unreachable!()
            };
            destination.mam_backed = !recipient_enabled;
            changed_mam.destination = PersonalMessageDestination::Local(destination);
            assert!(delayed
                .bind(owner.clone(), changed_mam, DirectSpoolEligibility::Eligible)
                .is_err());
            assert_eq!(owner.snapshot(), before);
            let prepared = delayed
                .bind(owner, valid, DirectSpoolEligibility::Eligible)
                .unwrap();
            assert_eq!(
                prepared.command().archives.len(),
                usize::from(sender_enabled) + usize::from(recipient_enabled && !own)
            );
            let PersonalMessageDestination::Local(destination) = prepared.command().destination
            else {
                unreachable!()
            };
            assert_eq!(destination.mam_backed, recipient_enabled);
        }
    }
}

struct PreparedQueue;
impl crate::services::messaging::OnlineRoutePort for PreparedQueue {
    type Session = crate::xmpp::outbound::OutboundSender;
    fn try_local(
        &self,
        session: &Self::Session,
        item: crate::xmpp::outbound::RouteEnqueue,
    ) -> std::result::Result<(), crate::xmpp::outbound::RouteSendError> {
        session.try_send_route_item(item)
    }
    fn record_local_accept(&self, _: bool) {}
    async fn route_available_remote(
        &self,
        _: &str,
        _: &str,
        _: Option<crate::xmpp::outbound::DurableDelivery>,
    ) -> bool {
        panic!("valid prepared target is local")
    }
    async fn route_remote_primary(
        &self,
        _: &str,
        _: &str,
        _: Option<crate::xmpp::outbound::DurableDelivery>,
    ) -> crate::services::messaging::OnlineRouteResult {
        panic!("valid prepared target is local")
    }
}
impl crate::services::messaging::FullJidFallbackPort for PreparedQueue {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, Self::Session)> {
        panic!("binding must reject changed fallback before routing")
    }
    fn available_priority(&self, _: &Self::Session) -> Option<i16> {
        Some(0)
    }
    fn priority(&self, _: &Self::Session) -> i16 {
        0
    }
    async fn privacy_allows_fallback(&self, _: &Self::Session, _: &str) -> Result<bool> {
        Ok(true)
    }
    fn post_accept_failed(&self) {}
}
impl crate::services::messaging::DirectMessageRoutePort for PreparedQueue {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        DirectPostCommitMode::Live
    }
    fn clustered_direct_routes(&self) -> bool {
        true
    }
    async fn rearm_direct_route(&self, _: crate::xmpp::outbound::DurableDelivery) {
        panic!("accepted queue is never rearmed")
    }
}

#[tokio::test]
async fn actual_original_to_router_preserves_live_payload_after_delayed_command_drops() {
    use northstar_message_application::direct_commit::DirectCommitObserver;
    for (raw, target, own) in [
        (
            "<message type='chat' to='bob@example.test/phone'><body>hello</body></message>",
            "bob@example.test/phone",
            false,
        ),
        (
            "<message to='bob@example.test'><store xmlns='urn:xmpp:hints'/></message>",
            "bob@example.test",
            false,
        ),
        (
            "<message to='alice@example.test'><body>self</body></message>",
            "alice@example.test",
            true,
        ),
    ] {
        let document = roxmltree::Document::parse(raw).unwrap();
        let original = OriginalDirectMessage::capture(
            document.root_element(),
            Uuid::from_u128(1),
            "alice@example.test/device",
            target,
            raw,
        );
        let local = original.project_local(authority(target, own), false, None);
        for mutation in 0..5 {
            let owner = owner(&original).await;
            let continuation = {
                let delayed = local.delayed(
                    chrono::DateTime::from_timestamp(100, 0).unwrap(),
                    LocalArchivePolicy::default(),
                );
                let prepared = delayed
                    .bind(
                        owner.clone(),
                        command(&local, &delayed),
                        DirectSpoolEligibility::Eligible,
                    )
                    .unwrap();
                prepared
                    .start(prepared.command(), prepared.eligibility())
                    .unwrap();
                let transaction = prepared
                    .prepare(
                        TransactionOutcome::Stored {
                            recipient_id: local.authority.recipient_id,
                            delivery_id: local.authority.recipient_stable_id,
                            archive_ids: vec![],
                            live_claim_id: Some(local.authority.recipient_stable_id),
                        },
                        DirectPostCommitMode::Live,
                    )
                    .unwrap();
                prepared.received(transaction).unwrap();
                prepared
                    .complete(Some(
                        crate::services::messaging::DirectPersonalMessageAdmission {
                            commit: DurableAdmissionOutcome::Stored {
                                archive_written: false,
                                post_commit: MessagePostCommit::RouteLocalDelivery {
                                    recipient_id: local.authority.recipient_id,
                                    delivery_id: local.authority.recipient_stable_id,
                                },
                            },
                            mode: DirectPostCommitMode::Live,
                            live_claim_id: Some(local.authority.recipient_stable_id),
                        },
                    ))
                    .unwrap();
                prepared.into_continuation()
            };
            // The actual stored-command buffers have ended, while the
            // private live projection remains bound through queue entry.
            let PreparedHandoffNext::Route(handoff) = continuation
                .after_finalize(|| DirectPostCommitMode::Live)
                .unwrap()
            else {
                unreachable!()
            };
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let targets = [(
                target.to_owned(),
                crate::xmpp::outbound::OutboundSender::new(tx),
            )];
            let mut request = DirectRouteRequest {
                message_type: original.message_type,
                target: if target == bare_jid(target) {
                    DirectRouteTarget::Bare(target)
                } else {
                    DirectRouteTarget::Full {
                        jid: target,
                        bare: bare_jid(target),
                    }
                },
                sender: original.sender,
                recipient_id: local.authority.recipient_id,
                stanza: &local.recipient_delivery,
                delivery: DirectRouteDelivery::Committed(crate::xmpp::outbound::DurableDelivery {
                    recipient_id: local.authority.recipient_id,
                    message_id: local.authority.recipient_stable_id,
                    claim_id: Some(local.authority.recipient_stable_id),
                }),
                approved_targets: &targets,
                enforce_direct_health: true,
            };
            match mutation {
                1 => {
                    request.target = DirectRouteTarget::Full {
                        jid: target,
                        bare: "unrelated@example.test",
                    }
                }
                2 => {
                    request.target = if target == bare_jid(target) {
                        DirectRouteTarget::Full {
                            jid: target,
                            bare: target,
                        }
                    } else {
                        DirectRouteTarget::Bare(target)
                    }
                }
                3 => request.stanza = "substituted live payload",
                4 => request.enforce_direct_health = false,
                _ => {}
            }
            let outcome = DirectMessageRouter::route_prepared(&PreparedQueue, request, handoff)
                .await
                .unwrap();
            if mutation == 0 {
                assert!(matches!(outcome, DirectRouteOutcome::Routed { .. }));
                let item = rx.try_recv().unwrap();
                assert_eq!(item.stanza, local.recipient_delivery);
                assert_eq!(
                    item.c2s_delivery().unwrap().recipient_id,
                    local.authority.recipient_id
                );
                assert!(owner.snapshot().handoff.unwrap().local_accepted);
            } else {
                assert!(matches!(
                    outcome,
                    DirectRouteOutcome::AcceptedForRecovery { .. }
                ));
                assert!(rx.try_recv().is_err());
                assert!(!owner.snapshot().handoff.unwrap().local_accepted);
            }
        }
    }
}
