//! Roster commands and per-resource push ordering.
//!
//! The repository owns authorization and atomic persistence. RosterSyncGate
//! handles the initial-result/push race without retaining a database connection.
//! Safety Invariants: MAX_BUFFERED_ROSTER_CHANGES, RosterSyncState::Flushing

use crate::{
    validate_roster_get_command, validate_roster_remove_command, validate_roster_upsert_command,
    RosterGetCommand, RosterRemoveCommand, RosterRepository, RosterUpsertCommand,
};
use anyhow::Result;
use northstar_roster_core::{
    RosterAuthorization, RosterChange, RosterReadSnapshot, RosterRemovalTransition,
};

#[derive(Clone)]
pub struct RosterService<R> {
    repository: R,
}

impl<R: RosterRepository<Error = anyhow::Error>> RosterService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn execute_roster_get(
        &self,
        command: RosterGetCommand,
    ) -> Result<RosterAuthorization<RosterReadSnapshot>> {
        if validate_roster_get_command(&command).is_err() {
            return Ok(RosterAuthorization::Unauthorized);
        }
        self.repository.get_roster(&command).await
    }

    pub async fn execute_roster_upsert(
        &self,
        command: RosterUpsertCommand,
    ) -> Result<RosterAuthorization<RosterChange>> {
        if validate_roster_upsert_command(&command).is_err() {
            return Ok(RosterAuthorization::Unauthorized);
        }
        self.repository.upsert_item(&command).await
    }

    pub async fn execute_roster_remove(
        &self,
        command: RosterRemoveCommand<'_>,
    ) -> Result<RosterAuthorization<Option<RosterRemovalTransition>>> {
        if validate_roster_remove_command(&command).is_err() {
            return Ok(RosterAuthorization::Unauthorized);
        }
        self.repository.remove_item(&command).await
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DenyingRepository {
        calls: std::sync::atomic::AtomicUsize,
        failed: AtomicBool,
        owner: uuid::Uuid,
    }

    impl DenyingRepository {
        fn reject<T>(
            &self,
            owner: uuid::Uuid,
            generation: i64,
        ) -> anyhow::Result<RosterAuthorization<T>> {
            assert_eq!(owner, self.owner);
            assert_eq!(generation, 7);
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.failed.load(Ordering::SeqCst) {
                anyhow::bail!("repository unavailable");
            }
            Ok(RosterAuthorization::Unauthorized)
        }
    }

    impl RosterRepository for DenyingRepository {
        type Error = anyhow::Error;

        async fn get_roster(
            &self,
            command: &RosterGetCommand,
        ) -> anyhow::Result<RosterAuthorization<RosterReadSnapshot>> {
            self.reject(command.owner_id, command.expected_auth_generation)
        }

        async fn upsert_item(
            &self,
            command: &RosterUpsertCommand,
        ) -> anyhow::Result<RosterAuthorization<RosterChange>> {
            self.reject(command.owner_id, command.expected_auth_generation)
        }

        async fn remove_item(
            &self,
            command: &RosterRemoveCommand<'_>,
        ) -> anyhow::Result<RosterAuthorization<Option<RosterRemovalTransition>>> {
            let RosterRemovalRoute::Remote {
                target_domain,
                policy,
                ..
            } = command.route
            else {
                panic!("expected remote notification in the same command");
            };
            assert_eq!(target_domain, "remote.test");
            assert_eq!(policy.max_rows, 20);
            self.reject(command.owner_id, command.expected_auth_generation)
        }
    }

    #[tokio::test]
    async fn repository_denials_and_failures_preserve_authority() {
        let owner = uuid::Uuid::new_v4();
        let service = super::RosterService::new(DenyingRepository {
            calls: std::sync::atomic::AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            owner,
        });
        let get = RosterGetCommand {
            owner_id: owner,
            expected_auth_generation: 7,
            requested_version: Some(-1),
            annotations_requested: false,
        };
        assert_eq!(
            service.execute_roster_get(get.clone()).await.unwrap(),
            RosterAuthorization::Unauthorized
        );
        assert_eq!(service.repository.calls.load(Ordering::SeqCst), 0);
        let get = RosterGetCommand {
            requested_version: None,
            ..get
        };
        assert_eq!(
            service.execute_roster_get(get.clone()).await.unwrap(),
            RosterAuthorization::Unauthorized
        );
        let upsert = RosterUpsertCommand {
            owner_id: owner,
            expected_auth_generation: 7,
            jid: "bob@remote.test".into(),
            name: None,
            groups: vec![],
        };
        assert_eq!(
            service.execute_roster_upsert(upsert.clone()).await.unwrap(),
            RosterAuthorization::Unauthorized
        );
        let remove = RosterRemoveCommand {
            owner_id: owner,
            expected_auth_generation: 7,
            jid: "bob@remote.test",
            route: RosterRemovalRoute::Remote {
                target_domain: "remote.test",
                unsubscribe_stanza: "<presence/>",
                unsubscribed_stanza: "<presence/>",
                bounce_to: None,
                policy: S2sOutboxPolicy {
                    ttl_seconds: 60,
                    max_rows: 20,
                    max_bytes: 10240,
                    max_per_domain: 10,
                },
            },
        };
        assert_eq!(
            service.execute_roster_remove(remove).await.unwrap(),
            RosterAuthorization::Unauthorized
        );
        service.repository.failed.store(true, Ordering::SeqCst);
        assert_eq!(
            service
                .execute_roster_get(get)
                .await
                .unwrap_err()
                .to_string(),
            "repository unavailable"
        );
        assert_eq!(
            service
                .execute_roster_upsert(upsert)
                .await
                .unwrap_err()
                .to_string(),
            "repository unavailable"
        );
        assert_eq!(
            service
                .execute_roster_remove(remove)
                .await
                .unwrap_err()
                .to_string(),
            "repository unavailable"
        );
        assert_eq!(service.repository.calls.load(Ordering::SeqCst), 6);
    }
}
