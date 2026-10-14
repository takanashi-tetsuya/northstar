use super::super::{
    DirectMessageRoutePort, DirectRouteOutcome, FullJidFallbackPort, OnlineRoutePort,
    OnlineRouteResult,
};
use super::*;
use crate::{
    security::abuse::{MessageAdmissionLease, MessageAdmissionStart},
    services::message_admission::continuation_fixture::{
        self as admission_fixture, Admission, Events, FinalizeCut,
    },
    xmpp::outbound::{DurableDelivery, OutboundSender, RouteEnqueue, RouteSendError},
};
use northstar_message_application::{
    direct_lifecycle::{OriginalAdmission, TerminalReason},
    MessageApplication, PersonalMessageCommitRepository,
};
use northstar_message_core::{LocalDelivery, MessageIdentity};
use std::{
    io::Write,
    sync::{Arc, Mutex},
};

const LIVE: &str = "<message id='live'><body>private live</body></message>";
const UNRATED_LIVE: &str = "<message id='live' type='chat' from='alice@example.test/device' to='bob@example.test'><store xmlns='urn:xmpp:hints'/></message>";
fn live_for(mode: Admission) -> &'static str {
    if mode == Admission::NotRated {
        UNRATED_LIVE
    } else {
        LIVE
    }
}
type AdmissionService = MessageAdmissionService<admission_fixture::Repository>;
async fn admit(
    owner: &DirectOperationHandle,
    mode: Admission,
    cut: FinalizeCut,
    events: Events,
) -> (AdmissionService, Option<MessageAdmissionLease>) {
    let service = MessageAdmissionService::new(admission_fixture::Repository {
        admission: mode,
        cut,
        events,
    });
    let lease = if mode == Admission::NotRated {
        None
    } else {
        let request = admission_fixture::request();
        let retained = owner.begin(&request).unwrap();
        let MessageAdmissionStart::Proceed { lease, .. } = service
            .begin_message_admission_retained(&request, &retained)
            .await
            .unwrap()
        else {
            panic!("fixture admission rejected");
        };
        lease
    };
    (service, lease)
}
fn prepared<'command>(
    owner: &DirectOperationHandle,
    mode: Admission,
    stored: &'command str,
) -> PreparedLocalDirect<'command, 'static> {
    let request = admission_fixture::request();
    let live = live_for(mode);
    let parsed = roxmltree::Document::parse(live).unwrap();
    assert_eq!(
        crate::xmpp::xml_util::is_abuse_rated_message(parsed.root_element()),
        mode != Admission::NotRated,
    );
    let command = ValidatedPersonalMessage {
        local_actor_id: Some(request.actor_id),
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: request.account_bare,
            actor_scope: request.account_bare,
            target_scope: "bob@example.test",
            value: "origin",
            payload: "private-identity-stanza",
        }),
        archives: &[],
        destination: PersonalMessageDestination::Local(LocalDelivery {
            delivery_id: Uuid::from_u128(2),
            recipient_id: Uuid::from_u128(5),
            recipient_bare_jid: "bob@example.test",
            sender_jid: "alice@example.test/device",
            stanza: stored,
            encrypted: false,
            mam_backed: false,
        }),
    };
    PreparedLocalDirect::bind(
        owner.clone(),
        LocalPreparation {
            actor_id: request.actor_id,
            sender_bare: request.account_bare,
            sender_full: "alice@example.test/device",
            target_bare: "bob@example.test",
            target_full: request.normalized_target,
            message_type: "chat",
            live_stanza: live,
            origin_id: request.origin_id,
            identity_payload: "private-identity-stanza",
            stored_stanza: stored,
            admission: if mode == Admission::NotRated {
                PreparationAdmission::NoAdmissionRequired
            } else {
                PreparationAdmission::Rated(OriginalAdmission {
                    actor_id: request.actor_id,
                    account_bare: request.account_bare,
                    normalized_target: request.normalized_target,
                    origin_id: request.origin_id,
                    normalized_payload: request.normalized_payload,
                })
            },
        },
        command,
        DirectSpoolEligibility::Eligible,
        LiveDirectBinding {
            sender: "alice@example.test/device",
            target: "bob@example.test",
            target_bare: "bob@example.test",
            message_type: "chat",
            stanza: live,
            recipient_id: Uuid::from_u128(5),
        },
    )
    .unwrap()
}
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum DirectCut {
    #[default]
    Success,
    PreCommitError,
    CommitError,
    CommitPending,
    AfterReceiptError,
}
#[derive(Clone, Copy, Default)]
enum Outcome {
    #[default]
    Stored,
    Replay,
    Unavailable,
}
struct Repository {
    cut: DirectCut,
    outcome: Outcome,
    admitted: DirectPostCommitMode,
    returned: DirectPostCommitMode,
    events: Events,
}
impl Repository {
    fn stored(events: Events) -> Self {
        Self {
            cut: DirectCut::Success,
            outcome: Outcome::Stored,
            admitted: DirectPostCommitMode::Live,
            returned: DirectPostCommitMode::Live,
            events,
        }
    }
}
impl PersonalMessageCommitRepository for Repository {
    type Error = anyhow::Error;
    async fn commit<'a>(
        &'a self,
        _: &'a ValidatedPersonalMessage<'a>,
    ) -> anyhow::Result<MessageCommit> {
        panic!("prepared application used legacy commit");
    }
}
impl DirectCommitRepository for Repository {
    type Error = anyhow::Error;
    async fn commit_direct<'a>(
        &'a self,
        command: &'a ValidatedPersonalMessage<'a>,
        _: DirectSpoolEligibility,
        observer: Option<&'a dyn DirectCommitObserver>,
    ) -> anyhow::Result<DirectPersonalMessageAdmission> {
        self.events.lock().unwrap().push("direct");
        if self.cut == DirectCut::PreCommitError {
            anyhow::bail!("controlled pre-COMMIT direct error");
        }
        let PersonalMessageDestination::Local(destination) = command.destination else {
            panic!("wrong destination");
        };
        let claim = (self.admitted == DirectPostCommitMode::Live
            && matches!(self.outcome, Outcome::Stored))
        .then_some(destination.delivery_id);
        let fact = match self.outcome {
            Outcome::Stored => TransactionOutcome::Stored {
                recipient_id: destination.recipient_id,
                delivery_id: destination.delivery_id,
                archive_ids: command.archives.iter().map(|write| write.id).collect(),
                live_claim_id: claim,
            },
            Outcome::Replay => TransactionOutcome::Replay {
                archive_ids: vec![Uuid::from_u128(909)],
            },
            Outcome::Unavailable => TransactionOutcome::AccountUnavailable,
        };
        // Actual MessageApplication has already started the observer. Only
        // the same production COMMIT wrapper records these controlled cuts.
        commit_observed(
            async {
                self.events.lock().unwrap().push("direct_commit");
                if self.cut == DirectCut::CommitPending {
                    std::future::pending::<()>().await;
                }
                if self.cut == DirectCut::CommitError {
                    anyhow::bail!("controlled direct COMMIT reply loss");
                }
                Ok::<_, anyhow::Error>(())
            },
            observer.expect("prepared observer"),
            fact,
            self.admitted,
        )
        .await?;
        self.events.lock().unwrap().push("direct_receipt");
        if self.cut == DirectCut::AfterReceiptError {
            anyhow::bail!("controlled post-receipt mapping error");
        }
        Ok(DirectPersonalMessageAdmission {
            commit: match self.outcome {
                Outcome::Stored => MessageCommit::Stored {
                    archive_written: !command.archives.is_empty(),
                    post_commit: MessagePostCommit::RouteLocalDelivery {
                        delivery_id: destination.delivery_id,
                        recipient_id: destination.recipient_id,
                    },
                },
                Outcome::Replay => MessageCommit::Replay,
                Outcome::Unavailable => MessageCommit::AccountUnavailable,
            },
            mode: self.returned,
            live_claim_id: claim,
        })
    }
}
struct Port {
    owner: DirectOperationHandle,
    mode: DirectPostCommitMode,
    events: Events,
    rearmed: Mutex<Vec<DurableDelivery>>,
}
impl Port {
    fn new(owner: &DirectOperationHandle, events: Events) -> Self {
        Self {
            owner: owner.clone(),
            mode: DirectPostCommitMode::Live,
            events,
            rearmed: Mutex::new(vec![]),
        }
    }
}
impl OnlineRoutePort for Port {
    type Session = OutboundSender;
    fn try_local(&self, session: &Self::Session, item: RouteEnqueue) -> Result<(), RouteSendError> {
        self.events.lock().unwrap().push("enqueue");
        session.try_send_route_item(item)
    }
    fn record_local_accept(&self, _: bool) {
        assert!(self.owner.snapshot().handoff.unwrap().local_accepted);
        self.events.lock().unwrap().push("accepted");
    }
    async fn route_available_remote(&self, _: &str, _: &str, _: Option<DurableDelivery>) -> bool {
        self.events.lock().unwrap().push("remote");
        false
    }
    async fn route_remote_primary(
        &self,
        _: &str,
        _: &str,
        _: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.events.lock().unwrap().push("remote");
        OnlineRouteResult::default()
    }
}
impl FullJidFallbackPort for Port {
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
impl DirectMessageRoutePort for Port {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        self.events.lock().unwrap().push("health");
        self.mode
    }
    fn clustered_direct_routes(&self) -> bool {
        true
    }
    async fn rearm_direct_route(&self, source: DurableDelivery) {
        self.events.lock().unwrap().push("rearm");
        self.rearmed.lock().unwrap().push(source);
    }
}
fn count(events: &Events, name: &str) -> usize {
    events
        .lock()
        .unwrap()
        .iter()
        .filter(|value| **value == name)
        .count()
}
fn followup(owner: &DirectOperationHandle, events: &Events) {
    let snapshot = owner.snapshot();
    assert!(snapshot.finalization.is_some());
    assert!(!snapshot.finalization.unwrap().effect_started);
    events.lock().unwrap().push("followup");
}
#[derive(Clone, Default)]
struct Trace(Arc<Mutex<Vec<u8>>>);
impl Write for Trace {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Trace {
    fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let trace = Self::default();
        let writer = trace.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .json()
            .with_ansi(false)
            .with_target(true)
            .with_env_filter("off,rust_xmpp_server::xmpp::protocol::messaging=debug")
            .with_writer(move || writer.clone())
            .finish();
        (trace, tracing::subscriber::set_default(subscriber))
    }
    fn events(&self) -> Vec<serde_json::Value> {
        std::str::from_utf8(&self.0.lock().unwrap())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn assert_finalize_warning(&self, label: &str) {
        let events = self.events();
        let warnings = events
            .iter()
            .filter(|event| {
                event["fields"]["message"]
                    == "accepted message PoW admission could not be finalized"
            })
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0]["target"],
            "rust_xmpp_server::xmpp::protocol::messaging"
        );
        assert_eq!(warnings[0]["level"], "WARN");
        assert_eq!(warnings[0]["fields"]["route"], label);
    }
}

#[tokio::test]
async fn stored_live_finalizes_before_returning_one_use_route() {
    for mode in [
        Admission::Reserved,
        Admission::GuardOnly,
        Admission::NotRated,
    ] {
        let (trace, _guard) = Trace::install();
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = admit(&owner, mode, FinalizeCut::Success, events.clone()).await;
        let begin = owner.snapshot().reservation;
        events.lock().unwrap().clear();
        let app = MessageApplication::new(Repository::stored(events.clone()));
        let delayed = String::from("<message><delay xmlns='urn:xmpp:delay'/></message>");
        let applied = commit_prepared_application(&app, prepared(&owner, mode, &delayed)).await;
        drop(delayed); // The opaque pair retains only the original live view.
        let port = Port::new(&owner, events.clone());
        let next = continue_prepared_local_direct(applied, &mut lease, &service, &port, || {
            followup(&owner, &events)
        })
        .await;
        let ContinuedLocalDirect::Live(live) = next else {
            panic!("stored live result did not produce route");
        };
        assert!(!live.archive_written());
        assert_eq!(live.source().message_id, Uuid::from_u128(2));
        assert!(lease.is_none());
        assert_eq!(owner.snapshot().reservation, begin);
        assert_eq!(
            count(&events, "followup"),
            usize::from(mode == Admission::Reserved)
        );
        assert_eq!(
            count(&events, "accept"),
            usize::from(mode == Admission::Reserved)
        );
        assert_eq!(count(&events, "health"), 1);
        assert_eq!(count(&events, "enqueue"), 0);
        if mode == Admission::Reserved {
            assert_eq!(
                *events.lock().unwrap(),
                [
                    "direct",
                    "direct_commit",
                    "direct_receipt",
                    "followup",
                    "accept",
                    "finalize_commit",
                    "finalize_receipt",
                    "health"
                ]
            );
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let targets = [(
            "bob@example.test/device".to_owned(),
            OutboundSender::new(tx),
        )];
        assert!(rx.try_recv().is_err());
        assert!(matches!(
            live.route_with(&port, &targets).await.unwrap(),
            DirectRouteOutcome::Routed { .. }
        ));
        let item = rx.try_recv().unwrap();
        assert_eq!(item.stanza, live_for(mode));
        assert_eq!(
            item.c2s_delivery().unwrap().claim_id,
            Some(Uuid::from_u128(2))
        );
        assert_eq!(count(&events, "enqueue"), 1);
        assert_eq!(count(&events, "failed"), 0);
        let debug = trace.events();
        let event = debug
            .iter()
            .find(|event| {
                event["fields"]["message"] == "committed durable C2S delivery before route attempt"
            })
            .unwrap();
        assert_eq!(
            event["target"],
            "rust_xmpp_server::xmpp::protocol::messaging"
        );
        assert_eq!(
            event["fields"]["recipient_id"],
            Uuid::from_u128(5).to_string()
        );
        assert_eq!(
            event["fields"]["message_id"],
            Uuid::from_u128(2).to_string()
        );
        assert_eq!(event["fields"]["target"], "bob@example.test");
    }
}

#[tokio::test]
async fn spooled_and_degraded_modes_keep_distinct_health_and_rearm_short_circuits() {
    for case in 0..3 {
        let (trace, _guard) = Trace::install();
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = admit(
            &owner,
            Admission::Reserved,
            FinalizeCut::PreCommitError,
            events.clone(),
        )
        .await;
        let app = MessageApplication::new(Repository {
            admitted: if case == 0 {
                DirectPostCommitMode::SpoolOnly
            } else {
                DirectPostCommitMode::Live
            },
            returned: if case < 2 {
                DirectPostCommitMode::SpoolOnly
            } else {
                DirectPostCommitMode::Live
            },
            ..Repository::stored(events.clone())
        });
        let applied =
            commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                .await;
        let mut port = Port::new(&owner, events.clone());
        port.mode = DirectPostCommitMode::SpoolOnly;
        assert!(matches!(
            continue_prepared_local_direct(applied, &mut lease, &service, &port, || followup(
                &owner, &events
            ))
            .await,
            ContinuedLocalDirect::Accepted
        ));
        assert_eq!(count(&events, "health"), usize::from(case == 2));
        assert_eq!(count(&events, "rearm"), usize::from(case != 0));
        assert_eq!(count(&events, "enqueue"), 0);
        assert_eq!(count(&events, "failed"), 1);
        trace.assert_finalize_warning(if case < 2 {
            "local-durable-c2s-spooled"
        } else {
            "local-durable-c2s"
        });
        let snapshot = owner.snapshot();
        assert!(snapshot.finalization.is_some());
        assert_eq!(
            snapshot.handoff.unwrap().rearm,
            if case == 0 {
                northstar_message_application::direct_handoff::RearmKnowledge::NotRequested
            } else {
                northstar_message_application::direct_handoff::RearmKnowledge::CallReturned
            }
        );
    }
}

#[tokio::test]
async fn returned_finalize_error_continues_but_pending_finalize_blocks() {
    for cut in [
        FinalizeCut::PreCommitError,
        FinalizeCut::CommitError,
        FinalizeCut::AfterReceiptError,
        FinalizeCut::PendingBeforeCommit,
        FinalizeCut::PendingCommit,
    ] {
        let (trace, _guard) = Trace::install();
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = admit(&owner, Admission::Reserved, cut, events.clone()).await;
        let app = MessageApplication::new(Repository::stored(events.clone()));
        let applied =
            commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                .await;
        let before = owner.snapshot();
        let port = Port::new(&owner, events.clone());
        let pending = matches!(
            cut,
            FinalizeCut::PendingBeforeCommit | FinalizeCut::PendingCommit
        );
        let mut future = Box::pin(continue_prepared_local_direct(
            applied,
            &mut lease,
            &service,
            &port,
            || followup(&owner, &events),
        ));
        let result = futures::poll!(&mut future);
        if pending {
            assert!(result.is_pending());
        } else {
            assert!(matches!(
                result,
                std::task::Poll::Ready(ContinuedLocalDirect::Live(_))
            ));
        }
        drop(future);
        assert!(lease.is_none());
        assert_eq!(count(&events, "followup"), 1);
        assert_eq!(count(&events, "accept"), 1);
        assert_eq!(count(&events, "health"), usize::from(!pending));
        assert_eq!(count(&events, "failed"), usize::from(!pending));
        assert_eq!(count(&events, "enqueue"), 0);
        assert_eq!(count(&events, "rearm"), 0);
        let after = owner.snapshot();
        assert_eq!(after.reservation, before.reservation);
        assert_eq!(after.direct, before.direct);
        use northstar_abuse_policy::admission_execution::Knowledge as AdmissionKnowledge;
        let finalization = after.finalization.unwrap();
        assert!(match cut {
            FinalizeCut::PreCommitError | FinalizeCut::PendingBeforeCommit => matches!(
                finalization.witness.knowledge(),
                AdmissionKnowledge::NoCommitRequested
            ),
            FinalizeCut::CommitError | FinalizeCut::PendingCommit => matches!(
                finalization.witness.knowledge(),
                AdmissionKnowledge::CommitCallEntered(_)
            ),
            FinalizeCut::AfterReceiptError => matches!(
                finalization.witness.knowledge(),
                AdmissionKnowledge::ReceiptKnown(_)
            ),
            FinalizeCut::Success => unreachable!(),
        });
        if !pending {
            trace.assert_finalize_warning("local-durable-c2s");
        }
    }
}

#[tokio::test]
async fn replay_results_finalize_without_live_authority() {
    for cut in [DirectCut::Success, DirectCut::AfterReceiptError] {
        let (trace, _guard) = Trace::install();
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let other = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = admit(
            &owner,
            Admission::Reserved,
            FinalizeCut::PreCommitError,
            events.clone(),
        )
        .await;
        let (_other_service, other_lease) = admit(
            &other,
            Admission::Reserved,
            FinalizeCut::Success,
            Events::default(),
        )
        .await;
        let _other_prepared = prepared(&other, Admission::Reserved, "other-delayed");
        let untouched = other.snapshot();
        let app = MessageApplication::new(Repository {
            cut,
            outcome: Outcome::Replay,
            ..Repository::stored(events.clone())
        });
        let applied =
            commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                .await;
        let port = Port::new(&owner, events.clone());
        assert!(matches!(
            continue_prepared_local_direct(applied, &mut lease, &service, &port, || followup(
                &owner, &events
            ))
            .await,
            ContinuedLocalDirect::Accepted
        ));
        assert!(lease.is_none());
        assert!(other_lease.is_some());
        assert_eq!(other.snapshot(), untouched);
        assert_eq!(count(&events, "health"), 0);
        assert_eq!(count(&events, "rearm"), 0);
        assert_eq!(count(&events, "enqueue"), 0);
        assert_eq!(count(&events, "failed"), 1);
        trace.assert_finalize_warning(if cut == DirectCut::Success {
            "local-durable-c2s-replay"
        } else {
            "local-durable-c2s-replay-continuation-unknown"
        });
        let snapshot = owner.snapshot();
        assert!(snapshot.handoff.is_none());
        let direct = snapshot.direct.unwrap();
        let Knowledge::ReceiptKnown(receipt) = &direct.knowledge else {
            panic!("Replay receipt lost");
        };
        assert_eq!(
            receipt.prepared.outcome,
            TransactionOutcome::Replay {
                archive_ids: vec![Uuid::from_u128(909)]
            }
        );
    }
}

#[tokio::test]
async fn unavailable_results_leave_finalization_and_route_untouched() {
    for cut in [DirectCut::Success, DirectCut::AfterReceiptError] {
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let other = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = admit(
            &owner,
            Admission::Reserved,
            FinalizeCut::Success,
            events.clone(),
        )
        .await;
        let (_other_service, other_lease) = admit(
            &other,
            Admission::Reserved,
            FinalizeCut::Success,
            Events::default(),
        )
        .await;
        let _other_prepared = prepared(&other, Admission::Reserved, "other-delayed");
        let untouched = other.snapshot();
        let app = MessageApplication::new(Repository {
            cut,
            outcome: Outcome::Unavailable,
            ..Repository::stored(events.clone())
        });
        let applied =
            commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                .await;
        let port = Port::new(&owner, events.clone());
        let ContinuedLocalDirect::Reject(error) =
            continue_prepared_local_direct(applied, &mut lease, &service, &port, || {
                followup(&owner, &events)
            })
            .await
        else {
            panic!("unavailable result accepted");
        };
        assert_eq!(error.stanza_error(), ("cancel", "service-unavailable"));
        assert!(lease.is_some());
        assert!(other_lease.is_some());
        assert_eq!(other.snapshot(), untouched);
        for event in ["followup", "accept", "health", "enqueue", "rearm", "failed"] {
            assert_eq!(count(&events, event), 0);
        }
        let snapshot = owner.snapshot();
        assert!(snapshot.finalization.is_none());
        assert!(snapshot.handoff.is_none());
    }
}

#[tokio::test]
async fn stored_receipt_without_returned_mode_recovers_without_health() {
    let (trace, _guard) = Trace::install();
    let owner = DirectOperationHandle::new(Uuid::new_v4());
    let events = Events::default();
    let (service, mut lease) = admit(
        &owner,
        Admission::Reserved,
        FinalizeCut::PreCommitError,
        events.clone(),
    )
    .await;
    let app = MessageApplication::new(Repository {
        cut: DirectCut::AfterReceiptError,
        ..Repository::stored(events.clone())
    });
    let applied =
        commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed")).await;
    let port = Port::new(&owner, events.clone());
    assert!(matches!(
        continue_prepared_local_direct(applied, &mut lease, &service, &port, || followup(
            &owner, &events
        ))
        .await,
        ContinuedLocalDirect::Accepted
    ));
    assert!(lease.is_none());
    assert_eq!(count(&events, "failed"), 2);
    assert_eq!(count(&events, "health"), 0);
    assert_eq!(count(&events, "rearm"), 1);
    assert_eq!(count(&events, "enqueue"), 0);
    trace.assert_finalize_warning("local-durable-c2s-continuation-unknown");
    assert_eq!(
        port.rearmed.lock().unwrap().as_slice(),
        [DurableDelivery {
            recipient_id: Uuid::from_u128(5),
            message_id: Uuid::from_u128(2),
            claim_id: Some(Uuid::from_u128(2))
        }]
    );
    assert!(matches!(
        owner.snapshot().direct.unwrap().outcome,
        Some(ExecutionOutcome::ReceiptPreserved(_))
    ));
}

#[tokio::test]
async fn unconfirmed_errors_keep_precommit_and_commit_unknown_separate() {
    for cut in [DirectCut::PreCommitError, DirectCut::CommitError] {
        let (trace, _guard) = Trace::install();
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = admit(
            &owner,
            Admission::Reserved,
            FinalizeCut::Success,
            events.clone(),
        )
        .await;
        let app = MessageApplication::new(Repository {
            cut,
            ..Repository::stored(events.clone())
        });
        let applied =
            commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                .await;
        let port = Port::new(&owner, events.clone());
        let ContinuedLocalDirect::Reject(error) =
            continue_prepared_local_direct(applied, &mut lease, &service, &port, || {
                followup(&owner, &events)
            })
            .await
        else {
            panic!("unconfirmed error accepted");
        };
        assert_eq!(error.stanza_error(), ("wait", "resource-constraint"));
        assert!(lease.is_some());
        for event in ["followup", "accept", "health", "enqueue", "rearm", "failed"] {
            assert_eq!(count(&events, event), 0);
        }
        let snapshot = owner.snapshot();
        assert!(snapshot.finalization.is_none());
        assert!(snapshot.handoff.is_none());
        let direct = snapshot.direct.unwrap();
        assert!(matches!(
            (&direct.knowledge, cut),
            (Knowledge::NoCommitRequested, DirectCut::PreCommitError)
                | (Knowledge::CommitCallEntered(_), DirectCut::CommitError)
        ));
        let warnings = trace.events();
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0]["target"],
            "rust_xmpp_server::xmpp::protocol::messaging"
        );
        assert_eq!(
            warnings[0]["fields"]["message"],
            "local history/C2S admission did not return a confirmed result"
        );
    }
    let events = Events::default();
    let child_events = events.clone();
    let pair_returned = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let child_returned = pair_returned.clone();
    let (owner, runner) = crate::xmpp::protocol::ProtocolSession::retained_direct_frame_for_test(
        move |owner| async move {
            let (service, mut lease) = admit(
                &owner,
                Admission::Reserved,
                FinalizeCut::Success,
                child_events.clone(),
            )
            .await;
            let app = MessageApplication::new(Repository {
                cut: DirectCut::CommitPending,
                ..Repository::stored(child_events.clone())
            });
            let applied =
                commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed"))
                    .await;
            child_returned.store(true, std::sync::atomic::Ordering::SeqCst);
            let port = Port::new(&owner, child_events.clone());
            let _ = continue_prepared_local_direct(applied, &mut lease, &service, &port, || {
                followup(&owner, &child_events)
            })
            .await;
            Ok(())
        },
    );
    assert!(owner.snapshot().direct.is_none());
    let mut runner = Box::pin(runner);
    assert!(futures::poll!(&mut runner).is_pending());
    drop(runner);
    let snapshot = owner.snapshot();
    assert_eq!(snapshot.terminal, Some(TerminalReason::Cancelled));
    assert!(matches!(
        snapshot.direct.unwrap().knowledge,
        Knowledge::CommitCallEntered(_)
    ));
    assert!(snapshot
        .reservation
        .unwrap()
        .has_durable_reservation_receipt());
    assert!(snapshot.finalization.is_none());
    assert!(snapshot.handoff.is_none());
    assert!(!pair_returned.load(std::sync::atomic::Ordering::SeqCst));
    for event in ["followup", "accept", "health", "enqueue", "rearm"] {
        assert_eq!(count(&events, event), 0);
    }
}

#[tokio::test]
async fn finalization_orders_missing_invalid_and_unretained_leases() {
    for case in 0..4 {
        let (trace, _guard) = Trace::install();
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let events = Events::default();
        let (service, mut lease) = if case == 1 || case == 2 {
            admit(
                &owner,
                Admission::Reserved,
                FinalizeCut::Success,
                events.clone(),
            )
            .await
        } else {
            (
                MessageAdmissionService::new(admission_fixture::Repository {
                    admission: Admission::NotRated,
                    cut: FinalizeCut::Success,
                    events: events.clone(),
                }),
                (case == 3).then(|| admission_fixture::lease(3)),
            )
        };
        if case == 1 {
            lease = Some(admission_fixture::lease(99));
        }
        events.lock().unwrap().clear();
        finalize_message_admission_with(
            &service,
            &mut lease,
            "fixture-finalize",
            || {
                events.lock().unwrap().push("lookup");
                (case != 3).then(|| owner.clone())
            },
            || {
                if case == 2 {
                    followup(&owner, &events);
                } else {
                    assert!(owner.snapshot().finalization.is_none());
                    events.lock().unwrap().push("followup");
                }
            },
            || events.lock().unwrap().push("failed"),
        )
        .await;
        assert!(lease.is_none());
        match case {
            0 => assert!(events.lock().unwrap().is_empty()),
            1 => {
                assert_eq!(*events.lock().unwrap(), ["lookup", "followup", "failed"]);
                trace.assert_finalize_warning("fixture-finalize");
            }
            _ => assert_eq!(
                *events.lock().unwrap(),
                [
                    "lookup",
                    "followup",
                    "accept",
                    "finalize_commit",
                    "finalize_receipt"
                ]
            ),
        }
        if case != 1 {
            assert!(trace.events().is_empty());
        }
        assert_eq!(owner.snapshot().finalization.is_some(), case == 2);
    }
}

#[tokio::test]
async fn continuation_rejection_never_turns_known_storage_into_live_route() {
    let (trace, _guard) = Trace::install();
    let owner = DirectOperationHandle::new(Uuid::new_v4());
    let events = Events::default();
    let (service, mut lease) = admit(
        &owner,
        Admission::Reserved,
        FinalizeCut::Success,
        events.clone(),
    )
    .await;
    let app = MessageApplication::new(Repository::stored(events.clone()));
    let applied =
        commit_prepared_application(&app, prepared(&owner, Admission::Reserved, "delayed")).await;
    // Complete the actual shared finalization, then retire the original
    // owner. No forged result or changed handoff fact supplies this cut.
    finalize_message_admission_with(
        &service,
        &mut lease,
        "fixture-finalize",
        || Some(owner.clone()),
        || followup(&owner, &events),
        || events.lock().unwrap().push("failed"),
    )
    .await;
    owner.retire(TerminalReason::Cancelled);
    let before = owner.snapshot();
    let port = Port::new(&owner, events.clone());
    assert!(matches!(
        continue_prepared_local_direct(applied, &mut lease, &service, &port, || panic!(
            "missing lease entered followup"
        ))
        .await,
        ContinuedLocalDirect::Accepted
    ));
    assert_eq!(owner.snapshot(), before);
    assert_eq!(count(&events, "failed"), 1);
    assert_eq!(count(&events, "accept"), 1);
    for event in ["health", "enqueue", "rearm"] {
        assert_eq!(count(&events, event), 0);
    }
    assert!(matches!(
        before.direct.unwrap().knowledge,
        Knowledge::ReceiptKnown(_)
    ));
    let trace = trace.events();
    let warning = trace
        .iter()
        .find(|event| {
            event["fields"]["message"]
                == "stored direct handoff could not be issued; row remains recoverable"
        })
        .unwrap();
    assert_eq!(
        warning["target"],
        "rust_xmpp_server::xmpp::protocol::messaging"
    );
}

#[tokio::test]
async fn defensive_stored_shape_retains_existing_internal_error() {
    let owner = DirectOperationHandle::new(Uuid::new_v4());
    let events = Events::default();
    let (service, mut lease) = admit(
        &owner,
        Admission::Reserved,
        FinalizeCut::Success,
        events.clone(),
    )
    .await;
    let continuation = prepared(&owner, Admission::Reserved, "delayed").into_continuation();
    let before = owner.snapshot();
    // Deliberately synthetic module-private defensive input. No public pair
    // constructor or application-composition claim is introduced here.
    let malformed = AppliedLocalDirect {
        actual: Ok(DirectPersonalMessageAdmission {
            commit: MessageCommit::Stored {
                archive_written: true,
                post_commit: MessagePostCommit::WakeFederationOutbox,
            },
            mode: DirectPostCommitMode::Live,
            live_claim_id: None,
        }),
        continuation,
    };
    let port = Port::new(&owner, events.clone());
    let ContinuedLocalDirect::Reject(error) =
        continue_prepared_local_direct(malformed, &mut lease, &service, &port, || {
            panic!("malformed stored result finalized")
        })
        .await
    else {
        panic!("malformed stored result accepted");
    };
    assert_eq!(error.stanza_error(), ("wait", "internal-server-error"));
    assert!(lease.is_some());
    assert_eq!(owner.snapshot(), before);
    for event in ["followup", "accept", "health", "enqueue", "rearm", "failed"] {
        assert_eq!(count(&events, event), 0);
    }
}
