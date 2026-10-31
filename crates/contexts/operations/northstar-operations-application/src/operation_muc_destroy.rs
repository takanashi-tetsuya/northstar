//! Validated administrator room-destroy effect and its atomic repository port.

use anyhow::{Context, Result};
use serde_json::Value;
use uuid::Uuid;

pub struct MucDestroyEffect<'a> {
    pub operation_id: Uuid,
    pub request_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub payload: &'a Value,
}

pub struct ValidatedMucDestroy<'a> {
    pub operation_id: Uuid,
    pub request_id: Uuid,
    pub actor_id: Uuid,
    pub room_jid: &'a str,
    pub localpart: &'a str,
    pub alternate_jid: Option<&'a str>,
    pub reason: Option<&'a str>,
}

pub struct MucDestroyCommit {
    pub room_jid: String,
    pub destroyed: bool,
    /// Occupancies captured by the committed room incarnation before it was
    /// tombstoned. A later room with the same JID has different identities.
    pub audience: Vec<MucDestroyAudience>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucDestroyAudience {
    pub full_jid: String,
    pub nick: String,
    pub occupant_incarnation: Uuid,
    pub connection_id: Uuid,
}

pub trait MucDestroyRepository: Send + Sync {
    fn commit(
        &self,
        command: ValidatedMucDestroy<'_>,
    ) -> impl std::future::Future<Output = Result<MucDestroyCommit>> + Send;
}

#[derive(Clone)]
pub struct MucDestroyService<R> {
    repository: R,
    local_domain: String,
}

impl<R: MucDestroyRepository> MucDestroyService<R> {
    pub fn new(repository: R, local_domain: String) -> Self {
        Self {
            repository,
            local_domain,
        }
    }

    pub async fn execute(&self, effect: MucDestroyEffect<'_>) -> Result<MucDestroyCommit> {
        let room_jid = effect
            .payload
            .get("room_jid")
            .and_then(Value::as_str)
            .context("room JID is missing")?;
        let jid = northstar_xmpp_types::jid::CanonicalJid::parse(room_jid)
            .context("room JID is invalid")?;
        anyhow::ensure!(jid.resourcepart().is_none(), "room JID must be bare");
        let localpart = jid.localpart().context("room JID has no localpart")?;
        anyhow::ensure!(
            jid.domainpart() == format!("conference.{}", self.local_domain),
            "room JID is outside this MUC service"
        );
        let actor_id = effect
            .actor_id
            .context("admin MUC destroy operation has no actor")?;
        self.repository
            .commit(ValidatedMucDestroy {
                operation_id: effect.operation_id,
                request_id: effect.request_id,
                actor_id,
                room_jid,
                localpart,
                alternate_jid: effect.payload.get("alternate_jid").and_then(Value::as_str),
                reason: effect.payload.get("reason").and_then(Value::as_str),
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingRepository(Arc<Mutex<Vec<String>>>);

    impl MucDestroyRepository for RecordingRepository {
        async fn commit(&self, command: ValidatedMucDestroy<'_>) -> Result<MucDestroyCommit> {
            self.0.lock().unwrap().push(command.room_jid.to_owned());
            Ok(MucDestroyCommit {
                room_jid: command.room_jid.to_owned(),
                destroyed: true,
                audience: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn rejects_foreign_or_resource_room_before_reaching_repository() {
        let repository = RecordingRepository::default();
        let service = MucDestroyService::new(repository.clone(), "example.test".into());
        let operation_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        for room_jid in [
            "room@conference.other.test",
            "room@conference.example.test/resource",
            "room@example.test",
        ] {
            assert!(service
                .execute(MucDestroyEffect {
                    operation_id,
                    request_id,
                    actor_id: Some(Uuid::new_v4()),
                    payload: &serde_json::json!({
                        "room_jid":room_jid,
                        "local_domain":"other.test"
                    }),
                })
                .await
                .is_err());
        }
        assert!(repository.0.lock().unwrap().is_empty());
        let outcome = service
            .execute(MucDestroyEffect {
                operation_id,
                request_id,
                actor_id: Some(Uuid::new_v4()),
                payload: &serde_json::json!({
                    "room_jid":"room@conference.example.test",
                    "local_domain":"other.test"
                }),
            })
            .await
            .unwrap();
        assert!(outcome.destroyed);
        assert_eq!(
            repository.0.lock().unwrap()[0],
            "room@conference.example.test"
        );
    }
}
