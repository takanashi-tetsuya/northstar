//! Read-only credential authority for the cluster maintenance safety sweep.
//! Local route cancellation remains with the cluster worker, between the two
//! database reads within the existing maintenance budget.

use anyhow::Result;
use std::{collections::HashMap, future::Future};
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) struct SessionAuthoritySnapshot {
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) device_id: Option<Uuid>,
    pub(crate) device_epoch: Option<i64>,
}

#[derive(Clone, Copy)]
pub(crate) struct AccountAuthState {
    pub(crate) auth_generation: i64,
    pub(crate) is_disabled: bool,
}

pub(crate) trait SessionAuthoritySweepRepository: Send + Sync {
    fn auth_states_for_users(
        &self,
        user_ids: &[Uuid],
    ) -> impl Future<Output = Result<HashMap<Uuid, AccountAuthState>>> + Send;

    fn user_agent_login_epochs(
        &self,
        agents: &[(Uuid, Uuid)],
    ) -> impl Future<Output = Result<HashMap<(Uuid, Uuid), i64>>> + Send;
}

pub(crate) struct SessionAuthoritySweepService<R> {
    repository: R,
}

impl<R: SessionAuthoritySweepRepository> SessionAuthoritySweepService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    /// A missing or disabled account, or any generation mismatch, revokes the
    /// local route. Preserve the input order so callers can fence exact routes.
    pub(crate) async fn stale_generations(
        &self,
        sessions: &[SessionAuthoritySnapshot],
    ) -> Result<Vec<bool>> {
        let mut user_ids = sessions
            .iter()
            .map(|session| session.user_id)
            .collect::<Vec<_>>();
        user_ids.sort_unstable();
        user_ids.dedup();
        let states = self.repository.auth_states_for_users(&user_ids).await?;
        Ok(sessions
            .iter()
            .map(|session| {
                states.get(&session.user_id).is_none_or(|state| {
                    state.is_disabled || state.auth_generation != session.auth_generation
                })
            })
            .collect())
    }

    /// Only sessions carrying both a device ID and an epoch are checked. A
    /// missing durable epoch revokes the route; a newer local epoch is valid.
    pub(crate) async fn stale_device_epochs(
        &self,
        sessions: &[SessionAuthoritySnapshot],
    ) -> Result<Vec<bool>> {
        let mut agents = sessions
            .iter()
            .filter_map(|session| {
                session
                    .device_id
                    .zip(session.device_epoch)
                    .map(|(device_id, _)| (session.user_id, device_id))
            })
            .collect::<Vec<_>>();
        agents.sort_unstable();
        agents.dedup();
        let epochs = self.repository.user_agent_login_epochs(&agents).await?;
        Ok(sessions
            .iter()
            .map(|session| {
                session
                    .device_id
                    .zip(session.device_epoch)
                    .is_some_and(|(device_id, epoch)| {
                        epochs
                            .get(&(session.user_id, device_id))
                            .is_none_or(|current| epoch < *current)
                    })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct StubRepository {
        users: HashMap<Uuid, AccountAuthState>,
        agents: HashMap<(Uuid, Uuid), i64>,
        reads: Arc<Mutex<Vec<String>>>,
    }

    impl SessionAuthoritySweepRepository for StubRepository {
        async fn auth_states_for_users(
            &self,
            user_ids: &[Uuid],
        ) -> Result<HashMap<Uuid, AccountAuthState>> {
            self.reads
                .lock()
                .unwrap()
                .push(format!("users:{user_ids:?}"));
            Ok(self.users.clone())
        }

        async fn user_agent_login_epochs(
            &self,
            agents: &[(Uuid, Uuid)],
        ) -> Result<HashMap<(Uuid, Uuid), i64>> {
            self.reads
                .lock()
                .unwrap()
                .push(format!("agents:{agents:?}"));
            Ok(self.agents.clone())
        }
    }

    #[tokio::test]
    async fn missing_disabled_and_replaced_authorities_fence_only_matching_routes() {
        let active = Uuid::from_u128(1);
        let disabled = Uuid::from_u128(2);
        let missing = Uuid::from_u128(3);
        let device = Uuid::from_u128(4);
        let other_device = Uuid::from_u128(5);
        let reads = Arc::new(Mutex::new(Vec::new()));
        let service = SessionAuthoritySweepService::new(StubRepository {
            users: HashMap::from([
                (
                    active,
                    AccountAuthState {
                        auth_generation: 7,
                        is_disabled: false,
                    },
                ),
                (
                    disabled,
                    AccountAuthState {
                        auth_generation: 7,
                        is_disabled: true,
                    },
                ),
            ]),
            agents: HashMap::from([((active, device), 9), ((active, other_device), 8)]),
            reads: Arc::clone(&reads),
        });
        let sessions = [
            SessionAuthoritySnapshot {
                user_id: active,
                auth_generation: 7,
                device_id: Some(device),
                device_epoch: Some(8),
            },
            SessionAuthoritySnapshot {
                user_id: active,
                auth_generation: 6,
                device_id: Some(other_device),
                device_epoch: Some(9),
            },
            SessionAuthoritySnapshot {
                user_id: disabled,
                auth_generation: 7,
                device_id: None,
                device_epoch: None,
            },
            SessionAuthoritySnapshot {
                user_id: missing,
                auth_generation: 7,
                device_id: Some(device),
                device_epoch: Some(1),
            },
            SessionAuthoritySnapshot {
                user_id: active,
                auth_generation: 7,
                device_id: Some(other_device),
                device_epoch: Some(8),
            },
            SessionAuthoritySnapshot {
                user_id: active,
                auth_generation: 7,
                device_id: Some(device),
                device_epoch: None,
            },
        ];
        assert_eq!(
            service.stale_generations(&sessions).await.unwrap(),
            [false, true, true, true, false, false]
        );
        assert_eq!(
            service.stale_device_epochs(&sessions).await.unwrap(),
            [true, false, false, true, false, false]
        );
        let reads = reads.lock().unwrap();
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0], format!("users:{:?}", [active, disabled, missing]));
        assert_eq!(
            reads[1],
            format!(
                "agents:{:?}",
                [(active, device), (active, other_device), (missing, device)]
            )
        );
    }
}
