use super::*;
use crate::discussion::{FanoutStage, KnowledgeClass, Request};
use crate::muc_service::*;
use std::sync::atomic::Ordering;

#[derive(Clone)]
struct Repository {
    inner: Arc<fixture::Repository>,
    address: Arc<Mutex<Option<usize>>>,
    commands: Arc<Mutex<Vec<MucDiscussion>>>,
}

impl Repository {
    fn new(cut: fixture::Cut) -> Self {
        Self {
            inner: Arc::new(fixture::Repository::new(cut)),
            address: Arc::new(Mutex::new(None)),
            commands: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl MucDiscussionRepository for Repository {
    type Error = anyhow::Error;

    fn admit_discussion<'a>(&'a self, _: &'a MucDiscussion) -> RepositoryFuture<'a, Self::Error> {
        panic!("observed service must use its bound request");
    }

    fn admit_discussion_observed<'a>(
        &'a self,
        request: &'a Request,
    ) -> RepositoryFuture<'a, Self::Error> {
        Box::pin(async move {
            assert_eq!(
                *self.address.lock().unwrap(),
                Some(std::ptr::from_ref(request) as usize)
            );
            self.commands
                .lock()
                .unwrap()
                .push(request.command().clone());
            self.inner.admit_discussion_observed(request).await
        })
    }
}

macro_rules! unused_ports {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $result:ty;)*) => {
        $(#[allow(clippy::too_many_arguments)]
        async fn $name(&self, $($arg: $ty),*) -> Result<$result> {
            $(let _ = $arg;)*
            panic!("unused MUC repository port: {}", stringify!($name));
        })*
    };
}

impl MucRepository for Repository {
    unused_ports! {
        local_room_snapshot(localpart: &str) -> Option<MucRoom>;
        local_affiliation(room_id: Uuid, user_id: Uuid) -> Option<String>;
        federated_affiliation(room_id: Uuid, bare_jid: &str) -> Option<String>;
        enabled_local_account(username: &str) -> Option<MucLocalAccount>;
        is_blocked_for_account(owner_id: Uuid, owner_bare_jid: &str, candidate: &str) -> bool;
        blocked_jids(user_id: Uuid) -> Vec<String>;
        store_local_muc_offline(configured_domain: &str, recipient_id: Uuid, sender_jid: &str, stanza: &str, encrypted: bool, policy: OfflineStorePolicy) -> OfflineStoreOutcome;
        local_message_by_id(room_id: Uuid, message_id: Uuid) -> Option<MucMessage>;
        local_history_since(room_id: Uuid, limit: i64, since: Option<DateTime<Utc>>) -> Vec<MucMessage>;
        delete_expired_locked_room(room_id: Uuid) -> bool;
        delete_temporary_room(room_id: Uuid, room_epoch: Uuid, config_version: i64) -> bool;
        local_reserved_nick(room_id: Uuid, user_id: Uuid) -> Option<String>;
        local_nick_reserved_for_other(room_id: Uuid, user_id: Uuid, nick: &str) -> bool;
        federated_reserved_nick(room_id: Uuid, bare_jid: &str) -> Option<String>;
        federated_nick_reserved_for_other(room_id: Uuid, bare_jid: &str, nick: &str) -> bool;
        get_or_create_local_room(localpart: &str, creator_id: Uuid, creator_full_jid: &str) -> (MucRoom, bool);
        get_or_create_federated_room(localpart: &str, creator_full_jid: &str) -> (MucRoom, bool);
        public_room_page(after: Option<&str>, before: Option<Option<&str>>, max: i64) -> Option<MucDiscoPage>;
        register_local_member(room_id: Uuid, user_id: Uuid, nick: &str) -> MucRegistrationOutcome;
        unregister_local_member(room_id: Uuid, user_id: Uuid) -> bool;
        register_federated_member(room_id: Uuid, bare_jid: &str, nick: &str) -> MucRegistrationOutcome;
        unregister_federated_member(room_id: Uuid, bare_jid: &str) -> bool;
        mutate_local_cluster_registration(operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, expected_config_version: i64, principal: &ClusterMucPrincipal, actor_full_jid: &str, reserved_nick: Option<&str>) -> ClusterMucRegistrationOutcome;
        admit_local_invite_command(configured_domain: &str, id: Uuid, room_id: Uuid, recipient_id: Uuid, sender_jid: &str, stanza: &str, encrypted: bool, policy: OfflineStorePolicy, cluster_authority: Option<&ClusterMucInviteAuthority>) -> DurableMucInviteOutcome;
        admit_federated_invite_command(room_id: Uuid, invitee_bare_jid: &str, target_domain: &str, stanza: &str, bounce_to: Option<&str>, policy: FederatedInvitePolicy, cluster_authority: Option<&ClusterMucInviteAuthority>) -> bool;
        set_local_subject(mutation: MucSubjectMutation<'_>, archive: bool, authority: MucActorAuthority) -> MucSubjectOutcome;
        set_local_cluster_subject(operation_id: Uuid, expected_room_epoch: Uuid, expected_config_version: i64, actor: &ClusterMucOccupancyTarget, mutation: MucSubjectMutation<'_>, archive: bool) -> ClusterMucTransitionOutcome;
        retract_local_message_and_archive_action(mutation: MucRetractionMutation<'_>) -> MucRetractionOutcome;
        update_local_legacy_config(room_id: Uuid, actor_full_jid: &str, config: MucConfigUpdate<'_>) -> MucConfigurationOutcome;
        cancel_locked_room(room_id: Uuid, actor_full_jid: &str) -> bool;
        delete_room(room_id: Uuid) -> ();
        set_local_legacy_affiliations_batch(room_id: Uuid, changes: &[MucAffiliationChange]) -> MucAffiliationBatchOutcome;
        local_affiliations(room_id: Uuid, affiliation: &str) -> Vec<String>;
        federated_affiliations(room_id: Uuid, affiliation: &str) -> Vec<String>;
        authorized_admin_role_list(configured_domain: &str, room_id: Uuid, expected_room_epoch: Uuid, user_id: Uuid, actor_scope: &str, asserted_local_role: &str, actor_target: Option<&ClusterMucOccupancyTarget>, clustered: bool, requested_role: &str) -> MucAdminSnapshot<MucAdminRoleList>;
        authorized_admin_affiliation_list(configured_domain: &str, room_id: Uuid, expected_room_epoch: Uuid, user_id: Uuid, actor_scope: &str, requested_affiliation: &str) -> MucAdminSnapshot<Vec<MucAdminAffiliationEntry>>;
        claim_local_cluster_occupancy(request: ClusterMucJoin<'_>) -> ClusterMucJoinOutcome;
        renew_local_cluster_occupancy(target: &ClusterMucOccupancyTarget, owner_node_id: &str, lease: Duration) -> bool;
        refresh_local_cluster_presence(target: &ClusterMucOccupancyTarget, owner_node_id: &str, presence_payload: &str, lease: Duration) -> bool;
        transition_local_cluster_occupancy(operation_id: Uuid, target: &ClusterMucOccupancyTarget, transition: &str, owner_node_id: &str, new_connection_uuid: Option<Uuid>, new_connection_epoch: Option<i64>, sm_session_id: Option<Uuid>, lease: Duration) -> ClusterMucTransitionOutcome;
        rebind_federated_cluster_occupancy(operation_id: Uuid, target: &ClusterMucOccupancyTarget, owner_node_id: &str, authenticated_domain: &str, new_connection_uuid: Uuid, lease: Duration) -> ClusterMucTransitionOutcome;
        disconnect_local_cluster_occupancy(operation_id: Uuid, target: &ClusterMucOccupancyTarget, owner_node_id: &str) -> ClusterMucTransitionOutcome;
        rename_local_cluster_occupancy(operation_id: Uuid, target: &ClusterMucOccupancyTarget, owner_node_id: &str, new_nick: &str) -> ClusterMucTransitionOutcome;
        update_local_cluster_config(operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, expected_config_version: i64, actor_target: &ClusterMucOccupancyTarget, principal: &ClusterMucPrincipal, actor_full_jid: &str, config: MucConfigUpdate<'_>) -> ClusterMucConfigurationOutcome;
        apply_local_cluster_affiliations_batch(operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, expected_config_version: i64, actor_target: &ClusterMucOccupancyTarget, actor: &ClusterMucPrincipal, actor_full_jid: &str, changes: &[MucAffiliationChange]) -> MucAffiliationBatchOutcome;
        apply_local_cluster_admin_batch(operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, expected_config_version: i64, actor_target: Option<&ClusterMucOccupancyTarget>, actor: &ClusterMucPrincipal, actor_full_jid: &str, local_domain: &str, changes: &[MucAdminBatchChange]) -> MucAdminBatchOutcome;
        kick_local_cluster_occupancy(operation_id: Uuid, actor: &ClusterMucOccupancyTarget, target: &ClusterMucOccupancyTarget, reason: Option<&str>) -> ClusterMucTransitionOutcome;
        change_local_cluster_role(operation_id: Uuid, actor: &ClusterMucOccupancyTarget, target: &ClusterMucOccupancyTarget, new_role: &str, reason: Option<&str>) -> ClusterMucTransitionOutcome;
        destroy_local_cluster_room(operation_id: Uuid, room_id: Uuid, expected_room_epoch: Uuid, actor: Option<&ClusterMucOccupancyTarget>, authorization_source: &str, actor_jid: Option<&str>, alternate_jid: Option<&str>, reason: Option<&str>) -> ClusterMucTransitionOutcome;
        local_cluster_occupancy_target(room_id: Uuid, occupant_incarnation: Uuid, connection_uuid: Uuid) -> Option<ClusterMucOccupancyTarget>;
        local_cluster_occupancy_target_by_nick(room_id: Uuid, expected_room_epoch: Uuid, nick: &str) -> Option<ClusterMucOccupancyTarget>;
        exact_local_cluster_occupancy_snapshot(target: &ClusterMucOccupancyTarget) -> Option<ClusterMucOccupancy>;
        suspended_local_cluster_occupancy(room_id: Uuid, room_epoch: Uuid, sm_session_id: Uuid, full_jid: &str, nick: &str) -> Option<ClusterMucOccupancy>;
        associate_local_cluster_sm_session(target: &ClusterMucOccupancyTarget, owner_node_id: &str, sm_session_id: Uuid) -> bool;
        cluster_room_is_empty(room_id: Uuid) -> bool;
        committed_wake(operation_id: Uuid) -> Option<ClusterMucWakeDescriptor>;
    }
}

#[tokio::test]
async fn discussion_service_preserves_receiving_authority() {
    crate::discussion::assert_commit_fact_cannot_be_substituted();
    let repository = Repository::new(fixture::Cut::Return);
    let service = MucService::new(repository.clone(), "configured.test");
    let foreign_application = RoomApplication::new(repository.clone(), "evil.test");
    let mut input = fixture::command(true, true);
    input.actor_scope = "alice@configured.test".into();
    input.sender_jid = "alice@configured.test/phone".into();
    input.authority.actor_scope.clone_from(&input.actor_scope);
    input.authority.full_jid.clone_from(&input.sender_jid);
    input.authority.principal = MucActorPrincipal::Local {
        user_id: Uuid::from_u128(14),
        local_domain: "configured.test".into(),
    };
    let mut foreign = input.clone();
    foreign.actor_scope = "alice@evil.test".into();
    foreign.sender_jid = "alice@evil.test/phone".into();
    foreign
        .authority
        .actor_scope
        .clone_from(&foreign.actor_scope);
    foreign.authority.full_jid.clone_from(&foreign.sender_jid);
    foreign.authority.principal = MucActorPrincipal::Local {
        user_id: Uuid::from_u128(14),
        local_domain: "evil.test".into(),
    };
    for (label, prepared) in [
        (
            "foreign preparation of local command",
            foreign_application.prepare_discussion(input.clone()),
        ),
        (
            "foreign command prepared by receiver",
            service.prepare_muc_discussion(foreign.clone()),
        ),
        (
            "self consistent foreign preparation",
            foreign_application.prepare_discussion(foreign),
        ),
    ] {
        let owner = Observation::new(prepared);
        let request = owner.request().unwrap();
        let completion = service
            .execute_muc_discussion_observed(&request)
            .await
            .unwrap();
        assert_eq!(
            completion.outcome(),
            MucDiscussionAdmission::Unauthorized,
            "{label}"
        );
        assert!(completion.into_fanout(&owner).unwrap().is_none(), "{label}");
        assert!(!owner.snapshot().repository_started, "{label}");
        assert_eq!(
            owner.snapshot().summary().knowledge,
            KnowledgeClass::NoCommitRequested,
            "{label}"
        );
        assert!(repository.commands.lock().unwrap().is_empty(), "{label}");
        assert_eq!(repository.inner.calls.load(Ordering::Relaxed), 0, "{label}");
    }
    let prepared = service.prepare_muc_discussion(input.clone());
    let slot = MucDiscussionSlot::default();
    let owner = slot.register(&prepared).unwrap();
    let same = slot.register(&prepared).unwrap();
    let before = owner.snapshot();
    assert!(
        matches!(
            slot.register(&service.prepare_muc_discussion(input.clone())),
            Err(Rejected::Input)
        ),
        "conflicting preparation"
    );
    assert_eq!(owner.snapshot(), before);
    let request = owner.request().unwrap();
    assert!(
        matches!(same.request(), Err(Rejected::RequestAlreadyIssued)),
        "same registered owner"
    );
    *repository.address.lock().unwrap() = Some(std::ptr::from_ref(&request) as usize);
    let mut work = Box::pin(service.execute_muc_discussion_observed(&request));
    let std::task::Poll::Ready(result) = futures::poll!(&mut work) else {
        panic!("successful commit must return with its receipt")
    };
    let completion = result.unwrap();
    drop(work);
    assert_eq!(
        completion.outcome(),
        MucDiscussionAdmission::Stored(input.id),
        "configured receiver"
    );
    assert_eq!(
        *repository.commands.lock().unwrap(),
        [input.clone()],
        "configured receiver"
    );
    assert_eq!(repository.inner.calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        owner.snapshot().summary().knowledge,
        KnowledgeClass::ReceiptKnown
    );
    assert!(completion.into_fanout(&owner).unwrap().is_some());
    assert_eq!(owner.snapshot().fanout.stage, FanoutStage::Ready);
    assert!(
        service
            .execute_muc_discussion_observed(&request)
            .await
            .is_err(),
        "no duplicate repository entry"
    );
    assert_eq!(repository.inner.calls.load(Ordering::Relaxed), 1);
    let retired = slot.retire(TerminalReason::Cancelled).unwrap();
    assert!(
        matches!(slot.register(&prepared), Err(Rejected::Retired)),
        "retired slot"
    );
    assert_eq!(slot.retire(TerminalReason::Completed), Some(retired));
    let empty = MucDiscussionSlot::default();
    assert!(empty.retire(TerminalReason::Cancelled).is_none());
    assert!(
        matches!(empty.register(&prepared), Err(Rejected::Retired)),
        "retired empty slot"
    );
    let directly_retired = MucDiscussionSlot::default();
    directly_retired
        .register(&prepared)
        .unwrap()
        .retire(TerminalReason::Cancelled);
    assert!(
        matches!(directly_retired.register(&prepared), Err(Rejected::Retired)),
        "retired observation"
    );

    for (label, cut, knowledge) in [
        (
            "during commit",
            fixture::Cut::DuringCommit,
            KnowledgeClass::CommitCallEntered,
        ),
        (
            "after receipt",
            fixture::Cut::AfterReceipt,
            KnowledgeClass::ReceiptKnown,
        ),
    ] {
        let repository = Repository::new(cut);
        let service = MucService::new(repository.clone(), "configured.test");
        let owner = Observation::new(service.prepare_muc_discussion(input.clone()));
        let request = owner.request().unwrap();
        *repository.address.lock().unwrap() = Some(std::ptr::from_ref(&request) as usize);
        let mut work = Box::pin(service.execute_muc_discussion_observed(&request));
        assert!(futures::poll!(&mut work).is_pending(), "{label}");
        assert_eq!(owner.snapshot().summary().knowledge, knowledge, "{label}");
        assert_eq!(
            owner.snapshot().fanout.stage,
            FanoutStage::Unavailable,
            "{label}"
        );
        assert_eq!(
            *repository.commands.lock().unwrap(),
            [input.clone()],
            "{label}"
        );
        drop(work);
        assert_eq!(
            owner.retire(TerminalReason::Cancelled).knowledge,
            knowledge,
            "{label}"
        );
    }
}
