//! Consume committed account revocations under one immutable cluster-instance
//! identity. Local routes must be revoked before their exact revisions are
//! acknowledged, so an interrupted batch remains safe to replay.

use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountRevocationConsumerIdentity {
    pub(crate) domain: String,
    pub(crate) node_id: String,
    pub(crate) instance_uuid: Uuid,
    pub(crate) instance_epoch: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct AccountRevocationEvent {
    pub(crate) user_id: Uuid,
    pub(crate) username: String,
    pub(crate) before_generation: i64,
    pub(crate) account_deleted: bool,
    pub(crate) revision: Uuid,
}

pub(crate) trait AccountRevocationRepository: Send + Sync {
    fn pending(
        &self,
        identity: &AccountRevocationConsumerIdentity,
    ) -> impl Future<Output = Result<Vec<AccountRevocationEvent>>> + Send;

    fn acknowledge(
        &self,
        identity: &AccountRevocationConsumerIdentity,
        revisions: &[Uuid],
    ) -> impl Future<Output = Result<()>> + Send;

    fn cleanup(&self) -> impl Future<Output = Result<()>> + Send;
}

pub(crate) struct AccountRevocationConsumerService<R> {
    repository: R,
}

impl<R: AccountRevocationRepository> AccountRevocationConsumerService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn cleanup(&self) -> Result<()> {
        self.repository.cleanup().await
    }

    /// Return true when a full batch may have left more work in the queue.
    /// The caller's existing timeout bounds read, local revocation and ACK.
    pub(crate) async fn consume_batch(
        &self,
        identity: &AccountRevocationConsumerIdentity,
        mut revoke_local: impl FnMut(Uuid, &str, Option<i64>),
    ) -> Result<bool> {
        let events = self.repository.pending(identity).await?;
        let mut revisions = Vec::with_capacity(events.len());
        for event in events {
            let bare_jid = format!("{}@{}", event.username, identity.domain);
            revoke_local(
                event.user_id,
                &bare_jid,
                (!event.account_deleted).then_some(event.before_generation),
            );
            revisions.push(event.revision);
        }
        if !revisions.is_empty() {
            self.repository.acknowledge(identity, &revisions).await?;
        }
        Ok(revisions.len() == 256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Trace {
        steps: Mutex<Vec<String>>,
        identities: Mutex<Vec<AccountRevocationConsumerIdentity>>,
        acknowledged: Mutex<Vec<Uuid>>,
    }

    struct StubRepository {
        trace: Arc<Trace>,
        events: Vec<AccountRevocationEvent>,
        read_fails: bool,
    }

    impl AccountRevocationRepository for StubRepository {
        async fn pending(
            &self,
            identity: &AccountRevocationConsumerIdentity,
        ) -> Result<Vec<AccountRevocationEvent>> {
            self.trace.steps.lock().unwrap().push("read".into());
            self.trace.identities.lock().unwrap().push(identity.clone());
            if self.read_fails {
                anyhow::bail!("authority unavailable");
            }
            Ok(self.events.clone())
        }

        async fn acknowledge(
            &self,
            identity: &AccountRevocationConsumerIdentity,
            revisions: &[Uuid],
        ) -> Result<()> {
            self.trace.steps.lock().unwrap().push("ack".into());
            self.trace.identities.lock().unwrap().push(identity.clone());
            *self.trace.acknowledged.lock().unwrap() = revisions.to_vec();
            Ok(())
        }

        async fn cleanup(&self) -> Result<()> {
            Ok(())
        }
    }

    fn identity() -> AccountRevocationConsumerIdentity {
        AccountRevocationConsumerIdentity {
            domain: "example.test".into(),
            node_id: "node-a".into(),
            instance_uuid: Uuid::from_u128(1),
            instance_epoch: 42,
        }
    }

    fn event(number: u128, deleted: bool) -> AccountRevocationEvent {
        AccountRevocationEvent {
            user_id: Uuid::from_u128(number + 1000),
            username: format!("user{number}"),
            before_generation: 7,
            account_deleted: deleted,
            revision: Uuid::from_u128(number + 2000),
        }
    }

    #[tokio::test]
    async fn revokes_every_route_before_ack_with_the_same_identity() {
        let trace = Arc::new(Trace::default());
        let events = vec![event(1, false), event(2, true)];
        let service = AccountRevocationConsumerService::new(StubRepository {
            trace: Arc::clone(&trace),
            events: events.clone(),
            read_fails: false,
        });
        let identity = identity();
        let mut revoked = Vec::new();
        let more = service
            .consume_batch(&identity, |user, jid, generation| {
                trace.steps.lock().unwrap().push("revoke".into());
                revoked.push((user, jid.to_owned(), generation));
            })
            .await
            .unwrap();

        assert!(!more);
        assert_eq!(
            revoked,
            vec![
                (events[0].user_id, "user1@example.test".into(), Some(7)),
                (events[1].user_id, "user2@example.test".into(), None),
            ]
        );
        assert_eq!(
            *trace.steps.lock().unwrap(),
            ["read", "revoke", "revoke", "ack"]
        );
        assert_eq!(
            *trace.identities.lock().unwrap(),
            [identity.clone(), identity]
        );
        assert_eq!(
            *trace.acknowledged.lock().unwrap(),
            vec![events[0].revision, events[1].revision]
        );
    }

    #[tokio::test]
    async fn full_batch_requests_continuation_only_after_ack() {
        let trace = Arc::new(Trace::default());
        let service = AccountRevocationConsumerService::new(StubRepository {
            trace: Arc::clone(&trace),
            events: (0..256).map(|number| event(number, false)).collect(),
            read_fails: false,
        });
        assert!(service
            .consume_batch(&identity(), |_, _, _| {
                trace.steps.lock().unwrap().push("revoke".into());
            })
            .await
            .unwrap());
        let steps = trace.steps.lock().unwrap();
        assert_eq!(steps.len(), 258);
        assert_eq!(steps.last().unwrap(), "ack");
        assert_eq!(trace.acknowledged.lock().unwrap().len(), 256);
    }

    #[tokio::test]
    async fn failed_read_does_not_revoke_or_ack() {
        let trace = Arc::new(Trace::default());
        let service = AccountRevocationConsumerService::new(StubRepository {
            trace: Arc::clone(&trace),
            events: vec![event(1, false)],
            read_fails: true,
        });
        assert!(service
            .consume_batch(&identity(), |_, _, _| panic!("unexpected revocation"))
            .await
            .is_err());
        assert_eq!(*trace.steps.lock().unwrap(), ["read"]);
        assert!(trace.acknowledged.lock().unwrap().is_empty());
    }
}
