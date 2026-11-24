use super::*;
use northstar_session_application::replay::{
    AuthorizedReplayPage, RecoveryGuardReleaseFuture, RecoveryReplayAuthorizationGuard,
    RecoveryReplayGuardPort, ReplayDisposition, ReplayMessage, ReplayPolicyVersion,
    ReplayPreparation,
};
use std::sync::Mutex;

pub(super) const CLAIM_TOKEN: Uuid = Uuid::from_u128(800);

pub(super) struct AuthorityCut {
    route: Arc<Mutex<ReplayRoute>>,
    generation: bool,
}

struct TestGuard;

impl RecoveryReplayGuardPort for TestGuard {
    fn release(self: Box<Self>) -> RecoveryGuardReleaseFuture {
        Box::pin(async { Ok(()) })
    }
}

impl ReplayAuthorityRepository for ReplayRepositoryFake {
    async fn claim_current_page(
        &self,
        session: &ReplaySession,
        authority: ReplayPageAuthority<'_>,
        bind2: bool,
        ttl: i64,
    ) -> Result<AuthorizedReplayClaim> {
        {
            let mut calls = self.0.lock().unwrap();
            if let Some(cut) = &calls.authority_cut {
                assert_eq!(session.route(), &*cut.route.lock().unwrap());
                assert!((authority.is_current)());
                calls.page_claims += 1;
                assert_eq!(calls.page_claims, 1);
                return Ok(AuthorizedReplayClaim::Claimed(AuthorizedReplayPage {
                    claim_token: CLAIM_TOKEN,
                    policy_version: ReplayPolicyVersion("before-cut".to_owned()),
                    messages: (1..=3)
                        .map(|id| {
                            (
                                ReplayMessage {
                                    id: Uuid::from_u128(id),
                                    stanza: format!("<message id='{id}'/>"),
                                },
                                ReplayDisposition::Deliver,
                            )
                        })
                        .collect(),
                }));
            }
        }
        assert!(matches!(
            self.claim_page(session, authority.active_privacy_list, bind2, ttl)
                .await?,
            ReplayPageOutcome::Empty
        ));
        Ok(AuthorizedReplayClaim::Empty)
    }

    async fn prepare_current_message(
        &self,
        session: &ReplaySession,
        request: ReplayMessageAuthority<'_>,
    ) -> Result<ReplayPreparation> {
        let calls = self.0.lock().unwrap();
        let cut = calls
            .authority_cut
            .as_ref()
            .expect("test claim must have authority");
        assert!((request.route.is_current)());
        assert_eq!(request.claim_token, CLAIM_TOKEN);
        assert_eq!(request.policy_version.0, "before-cut");
        if request.message_id == Uuid::from_u128(2) {
            let mut route = cut.route.lock().unwrap();
            assert_eq!(session.route(), &*route);
            if cut.generation {
                route.auth_generation += 1;
                return Ok(ReplayPreparation::StaleRoute);
            }
            route.connection_id = Uuid::new_v4();
        }
        Ok(ReplayPreparation::Ready(
            RecoveryReplayAuthorizationGuard::new(TestGuard),
        ))
    }
}

#[tokio::test]
async fn all_replay_entries_release_only_the_suffix_after_authority_changes() {
    for entry in ["login", "priority", "bind2", "resume", "recovery"] {
        for generation in [false, true] {
            let expected = replay_route(Uuid::from_u128(901), "alice@example.test/Phone");
            let live_route = Arc::new(Mutex::new(expected.clone()));
            let calls = Arc::new(Mutex::new(ReplayCalls {
                authority_cut: Some(AuthorityCut {
                    route: live_route.clone(),
                    generation,
                }),
                ..ReplayCalls::default()
            }));
            let current = expected.clone();
            let target = ReplayTarget::new(
                expected,
                Arc::default(),
                Arc::new(move || *live_route.lock().unwrap() == current),
            );
            let service =
                ReplayService::new(ReplayRepositoryFake(calls.clone()), "example.test", 30);
            let (queue, mut receiver) = mpsc::channel(3);
            let outbound = crate::outbound::OutboundSender::new(queue);
            let available = Arc::new(AtomicBool::new(true));
            let epoch = Arc::new(AtomicU64::new(1));
            let cutoff = Utc::now();
            match entry {
                "login" => {
                    replay_newly_available_resource(
                        service,
                        outbound,
                        target,
                        "alice@example.test".to_owned(),
                        false,
                        true,
                        available,
                        epoch,
                        1,
                        Some(cutoff),
                    )
                    .await
                }
                "priority" => {
                    replay_newly_nonnegative_resource(
                        service, outbound, target, available, epoch, 1, cutoff,
                    )
                    .await
                }
                "bind2" => replay_bind2_offline(service, outbound, target).await,
                "resume" => {
                    replay_resumed_offline(service, outbound, target, available, epoch, 1).await
                }
                "recovery" => assert!(
                    !replay_after_cluster_reconciliation(
                        service, outbound, target, false, available, epoch, 1, cutoff
                    )
                    .await
                ),
                _ => unreachable!(),
            }
            let first = receiver.try_recv().unwrap();
            let delivered = first.c2s_delivery().unwrap();
            assert_eq!(delivered.message_id, Uuid::from_u128(1), "{entry}");
            assert_eq!(delivered.claim_id, Some(CLAIM_TOKEN), "{entry}");
            assert!(
                receiver.try_recv().is_err(),
                "{entry} sent to a stale route"
            );
            let calls = calls.lock().unwrap();
            assert_eq!(
                calls.released_suffix,
                [Uuid::from_u128(2), Uuid::from_u128(3)],
                "{entry}"
            );
            assert_eq!(calls.releases, 1, "{entry}");
        }
    }
}
