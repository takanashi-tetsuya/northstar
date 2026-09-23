//! Validated administrator room-destroy effect and its atomic repository port.

use anyhow::{Context, Result};
use serde_json::Value;
use uuid::Uuid;

pub(crate) struct MucDestroyEffect<'a> {
    pub(crate) operation_id: Uuid,
    pub(crate) request_id: Uuid,
    pub(crate) actor_id: Option<Uuid>,
    pub(crate) payload: &'a Value,
}

pub(crate) struct ValidatedMucDestroy<'a> {
    pub(crate) operation_id: Uuid,
    pub(crate) request_id: Uuid,
    pub(crate) actor_id: Uuid,
    pub(crate) room_jid: &'a str,
    pub(crate) localpart: &'a str,
    pub(crate) alternate_jid: Option<&'a str>,
    pub(crate) reason: Option<&'a str>,
}

pub(crate) struct MucDestroyCommit {
    pub(crate) room_jid: String,
    pub(crate) destroyed: bool,
}

pub(crate) trait MucDestroyRepository: Send + Sync {
    fn commit(
        &self,
        command: ValidatedMucDestroy<'_>,
    ) -> impl std::future::Future<Output = Result<MucDestroyCommit>> + Send;
}

#[derive(Clone)]
pub(crate) struct MucDestroyService<R> {
    repository: R,
    local_domain: String,
}

impl<R: MucDestroyRepository> MucDestroyService<R> {
    pub(crate) fn new(repository: R, local_domain: String) -> Self {
        Self {
            repository,
            local_domain,
        }
    }

    pub(crate) async fn execute(&self, effect: MucDestroyEffect<'_>) -> Result<MucDestroyCommit> {
        let room_jid = effect
            .payload
            .get("room_jid")
            .and_then(Value::as_str)
            .context("room JID is missing")?;
        let jid = crate::jid::CanonicalJid::parse(room_jid).context("room JID is invalid")?;
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
