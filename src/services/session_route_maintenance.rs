//! Exact clustered session-route renewal after PostgreSQL instance validation.

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// PostgreSQL owns the route. Redis holds only its disposable projection.
/// All methods must use the same full JID and connection UUID fence.
pub(crate) trait SessionRouteRenewalPort: Send + Sync {
    fn renew_authority(
        &self,
        full_jid: &str,
        connection_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<SessionRouteAuthorityToken>>> + Send;
    fn refresh_projection(
        &self,
        full_jid: &str,
        activity_age_seconds: u64,
        connection_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn release_authority(
        &self,
        full_jid: &str,
        connection_id: Uuid,
        token: SessionRouteAuthorityToken,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// The exact PostgreSQL instance epoch captured before renewal. Compensation
/// must reuse it even if the process epoch changes before the Redis result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionRouteAuthorityToken {
    NoCluster,
    Exact { owner_instance_epoch: i64 },
}

pub(crate) struct SessionRouteLease {
    pub(crate) full_jid: String,
    pub(crate) activity_age_seconds: u64,
    pub(crate) connection_id: Uuid,
    pub(crate) disconnect: CancellationToken,
}

pub(crate) struct SessionRouteRenewalService<P> {
    port: P,
}

impl<P: SessionRouteRenewalPort> SessionRouteRenewalService<P> {
    pub(crate) fn new(port: P) -> Self {
        Self { port }
    }

    /// Authority renewal precedes projection. A rejected projection releases
    /// the exact authority claim; an unavailable projection does the same best-
    /// effort compensation and stops the pass for the supervisor to fence
    /// readiness. A lost exact route cancels only its local stream.
    pub(crate) async fn renew_all(&self, leases: Vec<SessionRouteLease>) -> Result<()> {
        for lease in leases {
            let Some(authority_token) = self
                .port
                .renew_authority(&lease.full_jid, lease.connection_id)
                .await?
            else {
                cancel_lost_route(&lease);
                continue;
            };
            match self
                .port
                .refresh_projection(
                    &lease.full_jid,
                    lease.activity_age_seconds,
                    lease.connection_id,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    let _ = self
                        .port
                        .release_authority(&lease.full_jid, lease.connection_id, authority_token)
                        .await;
                    cancel_lost_route(&lease);
                }
                Err(error) => {
                    let _ = self
                        .port
                        .release_authority(&lease.full_jid, lease.connection_id, authority_token)
                        .await;
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}

fn cancel_lost_route(lease: &SessionRouteLease) {
    tracing::warn!(
        full_jid = %lease.full_jid,
        connection_id = %lease.connection_id,
        "disconnecting local session that lost its cluster routing lease"
    );
    lease.disconnect.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Authority(Uuid),
        Projection(Uuid),
        Release(Uuid, SessionRouteAuthorityToken),
    }

    struct FaultPort {
        authority: Mutex<VecDeque<Result<Option<SessionRouteAuthorityToken>>>>,
        projection: Mutex<VecDeque<Result<bool>>>,
        release: Mutex<VecDeque<Result<()>>>,
        calls: Mutex<Vec<Call>>,
    }

    impl SessionRouteRenewalPort for &FaultPort {
        async fn renew_authority(
            &self,
            full_jid: &str,
            connection_id: Uuid,
        ) -> Result<Option<SessionRouteAuthorityToken>> {
            assert_eq!(full_jid, format!("alice@local.test/{connection_id}"));
            self.calls
                .lock()
                .unwrap()
                .push(Call::Authority(connection_id));
            self.authority
                .lock()
                .unwrap()
                .pop_front()
                .expect("injected authority reply")
        }

        async fn refresh_projection(
            &self,
            full_jid: &str,
            activity_age_seconds: u64,
            connection_id: Uuid,
        ) -> Result<bool> {
            assert_eq!(full_jid, format!("alice@local.test/{connection_id}"));
            assert_eq!(activity_age_seconds, 7);
            self.calls
                .lock()
                .unwrap()
                .push(Call::Projection(connection_id));
            self.projection
                .lock()
                .unwrap()
                .pop_front()
                .expect("injected projection reply")
        }

        async fn release_authority(
            &self,
            full_jid: &str,
            connection_id: Uuid,
            token: SessionRouteAuthorityToken,
        ) -> Result<()> {
            assert_eq!(full_jid, format!("alice@local.test/{connection_id}"));
            self.calls
                .lock()
                .unwrap()
                .push(Call::Release(connection_id, token));
            self.release
                .lock()
                .unwrap()
                .pop_front()
                .expect("injected release reply")
        }
    }

    fn lease(connection_id: Uuid, disconnect: CancellationToken) -> SessionRouteLease {
        SessionRouteLease {
            full_jid: format!("alice@local.test/{connection_id}"),
            activity_age_seconds: 7,
            connection_id,
            disconnect,
        }
    }

    fn token(owner_instance_epoch: i64) -> SessionRouteAuthorityToken {
        SessionRouteAuthorityToken::Exact {
            owner_instance_epoch,
        }
    }

    #[tokio::test]
    async fn lost_postgres_authority_cancels_exact_route_without_redis_write() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let first_cancel = CancellationToken::new();
        let second_cancel = CancellationToken::new();
        let port = FaultPort {
            authority: Mutex::new(VecDeque::from([Ok(None), Ok(Some(token(17)))])),
            projection: Mutex::new(VecDeque::from([Ok(true)])),
            release: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
        };

        SessionRouteRenewalService::new(&port)
            .renew_all(vec![
                lease(first, first_cancel.clone()),
                lease(second, second_cancel.clone()),
            ])
            .await
            .unwrap();

        assert!(first_cancel.is_cancelled());
        assert!(!second_cancel.is_cancelled());
        assert_eq!(
            *port.calls.lock().unwrap(),
            vec![
                Call::Authority(first),
                Call::Authority(second),
                Call::Projection(second)
            ]
        );
    }

    #[tokio::test]
    async fn rejected_redis_projection_releases_authority_and_cancels_exact_route() {
        let connection_id = Uuid::new_v4();
        let disconnect = CancellationToken::new();
        let port = FaultPort {
            authority: Mutex::new(VecDeque::from([Ok(Some(token(41)))])),
            projection: Mutex::new(VecDeque::from([Ok(false)])),
            release: Mutex::new(VecDeque::from([Ok(())])),
            calls: Mutex::new(Vec::new()),
        };

        SessionRouteRenewalService::new(&port)
            .renew_all(vec![lease(connection_id, disconnect.clone())])
            .await
            .unwrap();

        assert!(disconnect.is_cancelled());
        assert_eq!(
            *port.calls.lock().unwrap(),
            vec![
                Call::Authority(connection_id),
                Call::Projection(connection_id),
                Call::Release(connection_id, token(41))
            ]
        );
    }

    #[tokio::test]
    async fn redis_outage_compensates_and_stops_pass_until_retry() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let third = Uuid::new_v4();
        let second_cancel = CancellationToken::new();
        let third_cancel = CancellationToken::new();
        let port = FaultPort {
            authority: Mutex::new(VecDeque::from([
                Ok(Some(token(100))),
                Ok(Some(token(101))),
                Ok(Some(token(102))),
                Ok(Some(token(103))),
                Ok(Some(token(104))),
            ])),
            projection: Mutex::new(VecDeque::from([
                Ok(true),
                Err(anyhow::anyhow!("injected Redis outage")),
                Ok(true),
                Ok(true),
                Ok(true),
            ])),
            release: Mutex::new(VecDeque::from([Ok(())])),
            calls: Mutex::new(Vec::new()),
        };
        let service = SessionRouteRenewalService::new(&port);

        let error = service
            .renew_all(vec![
                lease(first, CancellationToken::new()),
                lease(second, second_cancel.clone()),
                lease(third, third_cancel.clone()),
            ])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("injected Redis outage"));
        assert!(!second_cancel.is_cancelled());
        assert!(!third_cancel.is_cancelled());
        assert_eq!(
            *port.calls.lock().unwrap(),
            vec![
                Call::Authority(first),
                Call::Projection(first),
                Call::Authority(second),
                Call::Projection(second),
                Call::Release(second, token(101))
            ]
        );

        service
            .renew_all(vec![
                lease(first, CancellationToken::new()),
                lease(second, second_cancel.clone()),
                lease(third, third_cancel.clone()),
            ])
            .await
            .unwrap();
        assert_eq!(port.calls.lock().unwrap().len(), 11);
        assert!(!second_cancel.is_cancelled());
        assert!(!third_cancel.is_cancelled());
    }
}
