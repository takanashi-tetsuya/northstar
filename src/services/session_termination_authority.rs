//! Exact PostgreSQL route authority for a signed remote session termination.
//! The listener retains ownership of the local connection fence and ACK.

use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionRouteAuthority {
    pub(crate) owner_node_id: String,
    pub(crate) owner_instance_uuid: Uuid,
    pub(crate) owner_instance_epoch: i64,
    pub(crate) connection_uuid: Uuid,
}

pub(crate) struct LocalClusterInstance {
    pub(crate) node_id: String,
    pub(crate) instance_uuid: Uuid,
    pub(crate) instance_epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionTerminationAuthority {
    Absent,
    WrongOwner,
    Authorized,
}

pub(crate) trait SessionTerminationAuthorityRepository: Send + Sync {
    fn route_authority(
        &self,
        namespace: &str,
        full_jid: &str,
    ) -> impl Future<Output = Result<Option<SessionRouteAuthority>>> + Send;
}

pub(crate) struct SessionTerminationAuthorityService<R> {
    repository: R,
}

impl<R: SessionTerminationAuthorityRepository> SessionTerminationAuthorityService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Read the durable route first, then snapshot the local owner. The owner
    /// snapshot runs after the database await, matching the listener's former
    /// ordering if a process instance changes while the read is pending.
    pub(crate) async fn authorize(
        &self,
        namespace: &str,
        full_jid: &str,
        expected_connection: Uuid,
        local_instance: impl FnOnce() -> LocalClusterInstance + Send,
    ) -> Result<SessionTerminationAuthority> {
        let Some(route) = self.repository.route_authority(namespace, full_jid).await? else {
            return Ok(SessionTerminationAuthority::Absent);
        };
        if route.connection_uuid != expected_connection {
            return Ok(SessionTerminationAuthority::Absent);
        }
        let local = local_instance();
        if route.owner_node_id != local.node_id
            || route.owner_instance_uuid != local.instance_uuid
            || route.owner_instance_epoch != local.instance_epoch
        {
            return Ok(SessionTerminationAuthority::WrongOwner);
        }
        Ok(SessionTerminationAuthority::Authorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    struct StubRepository {
        route: Option<SessionRouteAuthority>,
        fail: bool,
        reads: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl SessionTerminationAuthorityRepository for StubRepository {
        async fn route_authority(
            &self,
            namespace: &str,
            full_jid: &str,
        ) -> Result<Option<SessionRouteAuthority>> {
            self.reads
                .lock()
                .unwrap()
                .push((namespace.to_owned(), full_jid.to_owned()));
            if self.fail {
                anyhow::bail!("route authority unavailable");
            }
            Ok(self.route.clone())
        }
    }

    fn local() -> LocalClusterInstance {
        LocalClusterInstance {
            node_id: "node-a".into(),
            instance_uuid: Uuid::from_u128(1),
            instance_epoch: 7,
        }
    }

    fn route(connection_uuid: Uuid) -> SessionRouteAuthority {
        SessionRouteAuthority {
            owner_node_id: "node-a".into(),
            owner_instance_uuid: Uuid::from_u128(1),
            owner_instance_epoch: 7,
            connection_uuid,
        }
    }

    #[tokio::test]
    async fn only_exact_route_and_owner_authorize_local_termination() {
        let connection = Uuid::from_u128(2);
        let reads = Arc::new(Mutex::new(Vec::new()));
        let local_reads = Arc::new(AtomicUsize::new(0));
        let cases = [
            (None, SessionTerminationAuthority::Absent),
            (
                Some(route(Uuid::from_u128(3))),
                SessionTerminationAuthority::Absent,
            ),
            (
                Some(SessionRouteAuthority {
                    owner_node_id: "node-b".into(),
                    ..route(connection)
                }),
                SessionTerminationAuthority::WrongOwner,
            ),
            (
                Some(SessionRouteAuthority {
                    owner_instance_uuid: Uuid::from_u128(4),
                    ..route(connection)
                }),
                SessionTerminationAuthority::WrongOwner,
            ),
            (
                Some(SessionRouteAuthority {
                    owner_instance_epoch: 8,
                    ..route(connection)
                }),
                SessionTerminationAuthority::WrongOwner,
            ),
            (
                Some(route(connection)),
                SessionTerminationAuthority::Authorized,
            ),
        ];
        for (index, (route, expected)) in cases.into_iter().enumerate() {
            let service = SessionTerminationAuthorityService::new(StubRepository {
                route,
                fail: false,
                reads: Arc::clone(&reads),
            });
            let completed_reads = Arc::clone(&reads);
            let owner_reads = Arc::clone(&local_reads);
            assert_eq!(
                service
                    .authorize(
                        "example.test",
                        "alice@example.test/a",
                        connection,
                        move || {
                            assert_eq!(completed_reads.lock().unwrap().len(), index + 1);
                            owner_reads.fetch_add(1, Ordering::Relaxed);
                            local()
                        }
                    )
                    .await
                    .unwrap(),
                expected
            );
        }
        assert_eq!(reads.lock().unwrap().len(), 6);
        assert_eq!(local_reads.load(Ordering::Relaxed), 4);
        assert!(reads
            .lock()
            .unwrap()
            .iter()
            .all(|(namespace, jid)| namespace == "example.test" && jid == "alice@example.test/a"));
    }

    #[tokio::test]
    async fn read_error_never_grants_authority_or_reads_local_identity() {
        let service = SessionTerminationAuthorityService::new(StubRepository {
            route: Some(route(Uuid::from_u128(2))),
            fail: true,
            reads: Arc::new(Mutex::new(Vec::new())),
        });
        assert!(service
            .authorize(
                "example.test",
                "alice@example.test/a",
                Uuid::from_u128(2),
                || { panic!("local owner must not be read after a failed authority query") }
            )
            .await
            .is_err());
    }
}
