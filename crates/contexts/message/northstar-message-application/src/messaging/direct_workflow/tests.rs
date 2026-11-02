//! Module-private defensive input for the applied pair. The workflow tests that
//! drive the real queue stay beside it in the root crate.
use super::*;
use crate::direct_lifecycle::OriginalAdmission;
use crate::message_admission::continuation_fixture::{
    self as admission_fixture, Admission, Events, FinalizeCut,
};
use crate::messaging::{
    DirectMessageRoutePort, FullJidFallbackPort, OnlineRoutePort, OnlineRouteResult,
};
use crate::test_queue::TestItem;
use northstar_abuse_policy::message_admission::MessageAdmissionStart;
use northstar_delivery_core::DurableDelivery;
use northstar_message_core::route_item::{RouteEnqueue, RouteSendError};
use northstar_message_core::{LocalDelivery, MessageIdentity};

const LIVE: &str = "<message id='live'><body>private live</body></message>";

fn prepared<'command>(
    owner: &DirectOperationHandle,
    stored: &'command str,
) -> PreparedLocalDirect<'command, 'static> {
    let request = admission_fixture::request();
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
            live_stanza: LIVE,
            origin_id: request.origin_id,
            identity_payload: "private-identity-stanza",
            stored_stanza: stored,
            admission: PreparationAdmission::Rated(OriginalAdmission {
                actor_id: request.actor_id,
                account_bare: request.account_bare,
                normalized_target: request.normalized_target,
                origin_id: request.origin_id,
                normalized_payload: request.normalized_payload,
            }),
        },
        command,
        DirectSpoolEligibility::Eligible,
        LiveDirectBinding {
            sender: "alice@example.test/device",
            target: "bob@example.test",
            target_bare: "bob@example.test",
            message_type: "chat",
            stanza: LIVE,
            recipient_id: Uuid::from_u128(5),
        },
    )
    .unwrap()
}

/// Records every call. The test requires that none of them is made.
struct Port(Events);
impl OnlineRoutePort for Port {
    type Item = TestItem;
    type Session = ();
    fn try_local(&self, _: &(), _: RouteEnqueue<TestItem>) -> Result<(), RouteSendError<TestItem>> {
        self.0.lock().unwrap().push("enqueue");
        Ok(())
    }
    fn record_local_accept(&self, _: bool) {
        self.0.lock().unwrap().push("accepted");
    }
    async fn route_available_remote(&self, _: &str, _: &str, _: Option<DurableDelivery>) -> bool {
        self.0.lock().unwrap().push("remote");
        false
    }
    async fn route_remote_primary(
        &self,
        _: &str,
        _: &str,
        _: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.0.lock().unwrap().push("remote");
        OnlineRouteResult::default()
    }
}
impl FullJidFallbackPort for Port {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, ())> {
        vec![]
    }
    fn available_priority(&self, _: &()) -> Option<i16> {
        Some(0)
    }
    fn priority(&self, _: &()) -> i16 {
        0
    }
    async fn privacy_allows_fallback(&self, _: &(), _: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
    fn post_accept_failed(&self) {
        self.0.lock().unwrap().push("failed");
    }
}
impl DirectMessageRoutePort for Port {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        self.0.lock().unwrap().push("health");
        DirectPostCommitMode::Live
    }
    fn clustered_direct_routes(&self) -> bool {
        true
    }
    async fn rearm_direct_route(&self, _: DurableDelivery) {
        self.0.lock().unwrap().push("rearm");
    }
}

#[tokio::test]
async fn defensive_stored_shape_retains_existing_internal_error() {
    let owner = DirectOperationHandle::new(Uuid::new_v4());
    let events = Events::default();
    let service = MessageAdmissionService::new(admission_fixture::Repository {
        admission: Admission::Reserved,
        cut: FinalizeCut::Success,
        events: events.clone(),
    });
    let request = admission_fixture::request();
    let retained = owner.begin(&request).unwrap();
    let MessageAdmissionStart::Proceed { mut lease, .. } = service
        .begin_message_admission_retained(&request, &retained)
        .await
        .unwrap()
    else {
        panic!("fixture admission rejected");
    };
    let continuation = prepared(&owner, "delayed").into_continuation();
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
    let port = Port(events.clone());
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
        assert!(!events.lock().unwrap().contains(&event));
    }
}
