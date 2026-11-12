//! Credential owners, controls and a fake publication port for tests of authentication publication, here and
//! in the transports.

use super::*;
use northstar_auth_application::authentication::{BindingPublication, StagedLoginEpoch};
use std::{sync::atomic::Ordering, task::Waker};

pub fn fixture_control(control: &str, connection: Uuid) -> (AuthControlHolder, Observation) {
    let owner = KnownCredentialOwner::from_returned(
        CredentialCommitReceipt::new(None, None, None),
        None,
        connection,
    );
    let observation = owner.observation().clone();
    let holder = owner
        .seal(
            control,
            CapturedEffects {
                route: RouteIntent::Unbound,
                caps: None,
                notification: None,
            },
        )
        .unwrap();
    (holder, observation)
}
pub fn fixture_bound_control(
    control: &str,
    connection: Uuid,
    notify: bool,
) -> (AuthControlHolder, Observation) {
    let user = Uuid::from_u128(303);
    let device = Uuid::from_u128(304);
    let receipt = CredentialCommitReceipt::new(
        None,
        Some(StagedLoginEpoch {
            operation_id: Uuid::from_u128(301),
            connection_id: connection,
            user_id: user,
            device_id: device,
            auth_generation: 2,
            epoch: 999,
        }),
        Some(BindingPublication {
            connection_id: connection,
            user_id: user,
            full_jid: "fixture@example.test/captured".to_owned(),
            lease_seconds: 120,
        }),
    );
    let owner = KnownCredentialOwner::from_returned(receipt, None, connection);
    let observation = owner.observation().clone();
    let holder = owner
        .seal(control, fixture_bound_effects(connection, notify))
        .unwrap();
    (holder, observation)
}
pub(crate) fn fixture_bound_effects(connection: Uuid, notify: bool) -> CapturedEffects {
    let user = Uuid::from_u128(303);
    let device = Uuid::from_u128(304);
    let route = BoundRoute {
        key: "fixture@example.test/captured".to_owned(),
        user,
        generation: 2,
        connection,
        lifecycle: Arc::new(AtomicU8::new(0)),
        disconnect: CancellationToken::new(),
    };
    let caps = CapsIntent {
        presence: "<presence/>".to_owned(),
        key: route.key.clone(),
        connection,
        gate: Arc::new(tokio::sync::Mutex::new(())),
        generation: Arc::new(AtomicU64::new(9)),
    };
    let notification = notify.then(|| NotificationIntent {
        account: "fixture@example.test".to_owned(),
        user,
        device,
        excluded_key: route.key.clone(),
    });
    CapturedEffects {
        route: RouteIntent::Bound(route),
        caps: Some(caps),
        notification,
    }
}
#[derive(Clone, Copy, Default)]
pub enum Cut {
    #[default]
    Success,
    BeforeCommit,
    CommitPending,
    CommitError,
    BareSuccess,
    WrongReturn,
    RouteRejected,
    CapsPending,
    NotifyError,
}
pub struct FakePort {
    pub connection: Uuid,
    pub cut: Cut,
    pub events: Vec<&'static str>,
    pub routes: Vec<String>,
    pub caps_generation: Option<u64>,
    pub notification: Option<(String, Uuid, Uuid, String, i64)>,
}
impl FakePort {
    pub fn new(connection: Uuid, cut: Cut) -> Self {
        Self {
            connection,
            cut,
            events: Vec::new(),
            routes: Vec::new(),
            caps_generation: None,
            notification: None,
        }
    }
}
impl PublicationPort for FakePort {
    fn connection(&self) -> Uuid {
        self.connection
    }
    async fn publish(&mut self, invocation: &Invocation<'_>) -> AuthenticationResult<Option<i64>> {
        self.events.push("service");
        invocation.enter_service().unwrap();
        let result = if matches!(self.cut, Cut::BeforeCommit) {
            AuthenticationResult::BackendFailure(anyhow::anyhow!("controlled pre-COMMIT failure"))
        } else if invocation.receipt().staged_login_epoch().is_none()
            && invocation.receipt().binding_publication().is_none()
        {
            invocation.not_required().unwrap();
            AuthenticationResult::Authenticated(None)
        } else {
            invocation.enter_repository().unwrap();
            self.events.push("repository");
            if matches!(self.cut, Cut::BareSuccess) {
                AuthenticationResult::Authenticated(Some(7))
            } else {
                let cut = self.cut;
                let committed = invocation
                    .commit(
                        async {
                            if matches!(cut, Cut::CommitPending) {
                                std::future::pending::<()>().await;
                            }
                            if matches!(cut, Cut::CommitError) {
                                return Err(std::io::Error::other("controlled COMMIT reply loss"));
                            }
                            Ok(())
                        },
                        Some(7),
                    )
                    .await;
                match committed {
                    Ok(()) => AuthenticationResult::Authenticated(Some(
                        if matches!(cut, Cut::WrongReturn) {
                            8
                        } else {
                            7
                        },
                    )),
                    Err(error) => AuthenticationResult::BackendFailure(error.into()),
                }
            }
        };
        // Preserve the actual fake adapter return even when it mismatches;
        // the shared production sequence must reject it before effects.
        let _ = invocation.returned(&result);
        result
    }
    fn epoch_and_mapping(&mut self, route: &BoundRoute, epoch: Option<i64>) -> bool {
        self.events.push("route");
        self.routes.push(route.key.clone());
        assert_eq!(route.connection, self.connection);
        assert_eq!(route.user, Uuid::from_u128(303));
        assert_eq!(route.generation, 2);
        assert_eq!(epoch, Some(7));
        !matches!(self.cut, Cut::RouteRejected)
    }
    fn activate(&mut self, route: &BoundRoute) -> bool {
        self.events.push("activate");
        assert_eq!(route.key, "fixture@example.test/captured");
        true
    }
    async fn caps(&mut self, intent: Option<CapsIntent>) {
        self.events.push("caps");
        let caps = intent.expect("captured resume caps intent");
        assert_eq!(caps.key, "fixture@example.test/captured");
        assert_eq!(caps.connection, self.connection);
        assert_eq!(caps.presence, "<presence/>");
        self.caps_generation = Some(caps.generation.load(Ordering::Acquire));
        if matches!(self.cut, Cut::CapsPending) {
            std::future::pending::<()>().await;
        }
    }
    fn notify_local(&mut self, intent: &NotificationIntent, epoch: i64) {
        self.events.push("local_notification");
        self.notification = Some((
            intent.account.clone(),
            intent.user,
            intent.device,
            intent.excluded_key.clone(),
            epoch,
        ));
    }
    async fn notify_remote(&mut self, _: &NotificationIntent, _: i64) -> Result<()> {
        self.events.push("remote_notification");
        if matches!(self.cut, Cut::NotifyError) {
            anyhow::bail!("controlled notification failure");
        }
        Ok(())
    }
    fn rejected(&mut self, _: PublicationResult, _: Option<&anyhow::Error>) {
        self.events.push("rejected");
    }
    fn notification_deferred(&mut self, _: &anyhow::Error) {
        self.events.push("deferred");
    }
}
pub async fn publish_unbound_fixture(owners: Vec<OwnedPublication>) -> bool {
    for owner in owners {
        let mut port = FakePort::new(owner.connection(), Cut::Success);
        if !owner.publish(&mut port).await.transport_succeeded() {
            return false;
        }
        assert_eq!(port.events, ["service"]);
    }
    true
}
pub fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
