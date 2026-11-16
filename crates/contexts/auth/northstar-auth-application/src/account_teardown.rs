//! Read the committed authorization generation before cross-node teardown.

use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

/// Effects of a committed credential change that replaces every session of the account.
pub trait AccountTeardownEffects: Send + Sync {
    fn revoke_local_routes(&self, user_id: Uuid, bare_account_jid: &str);
    fn revoke_sm_sessions(&self, user_id: Uuid) -> impl Future<Output = Result<usize>> + Send;
    fn committed_generation(&self, user_id: Uuid) -> impl Future<Output = Result<i64>> + Send;
    fn notify_generation_teardown(
        &self,
        bare_account_jid: &str,
        user_id: Uuid,
        generation: i64,
    ) -> impl Future<Output = Result<()>> + Send;
}

pub async fn disconnect_account(
    effects: &impl AccountTeardownEffects,
    user_id: Uuid,
    bare_account_jid: &str,
) {
    effects.revoke_local_routes(user_id, bare_account_jid);
    if let Err(error) = effects.revoke_sm_sessions(user_id).await {
        tracing::error!(?error, %user_id, "failed to revoke durable SM sessions");
    }
    // Credentials are already committed. A read failure leaves the
    // periodic generation sweep responsible for cross-node teardown.
    let generation = match effects.committed_generation(user_id).await {
        Ok(generation) => generation,
        Err(error) => {
            tracing::error!(?error, %user_id, "could not load the post-mutation auth generation");
            return;
        }
    };
    if let Err(error) = effects
        .notify_generation_teardown(bare_account_jid, user_id, generation)
        .await
    {
        tracing::error!(
            ?error,
            %user_id,
            auth_generation = generation,
            "cross-node account revocation was not acknowledged; maintenance will retry"
        );
    }
}

pub trait AccountGenerationRepository: Send + Sync {
    fn generation(&self, user_id: Uuid) -> impl Future<Output = Result<Option<i64>>> + Send;
}

pub struct AccountGenerationService<R> {
    repository: R,
}

impl<R: AccountGenerationRepository> AccountGenerationService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn committed_generation(&self, user_id: Uuid) -> Result<i64> {
        Ok(self
            .repository
            .generation(user_id)
            .await?
            .unwrap_or(i64::MAX))
    }
}

/// The outcome of the XEP-0077 account deletion commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalizeAccountDeletion {
    Deleted,
    Missing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const ACCOUNT_JID: &str = "alice@example.test";
    const USER_ID: Uuid = Uuid::from_u128(42);

    #[derive(Debug, PartialEq)]
    enum Call {
        Local(Uuid, String),
        Sm(Uuid),
        Generation(Uuid),
        Notify(String, Uuid, i64),
    }

    #[derive(Clone, Copy)]
    enum Failure {
        Sm,
        Generation,
        Notification,
    }

    struct RecordingEffects {
        calls: Mutex<Vec<Call>>,
        failure: Option<Failure>,
    }

    impl AccountTeardownEffects for RecordingEffects {
        fn revoke_local_routes(&self, user_id: Uuid, bare_account_jid: &str) {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Local(user_id, bare_account_jid.to_owned()));
        }

        async fn revoke_sm_sessions(&self, user_id: Uuid) -> Result<usize> {
            self.calls.lock().unwrap().push(Call::Sm(user_id));
            if matches!(self.failure, Some(Failure::Sm)) {
                anyhow::bail!("SM revocation failed");
            }
            Ok(2)
        }

        async fn committed_generation(&self, user_id: Uuid) -> Result<i64> {
            self.calls.lock().unwrap().push(Call::Generation(user_id));
            if matches!(self.failure, Some(Failure::Generation)) {
                anyhow::bail!("generation read failed");
            }
            Ok(73)
        }

        async fn notify_generation_teardown(
            &self,
            bare_account_jid: &str,
            user_id: Uuid,
            generation: i64,
        ) -> Result<()> {
            self.calls.lock().unwrap().push(Call::Notify(
                bare_account_jid.to_owned(),
                user_id,
                generation,
            ));
            if matches!(self.failure, Some(Failure::Notification)) {
                anyhow::bail!("notification failed");
            }
            Ok(())
        }
    }

    async fn recorded_disconnect(failure: Option<Failure>) -> Vec<Call> {
        let effects = RecordingEffects {
            calls: Mutex::new(Vec::new()),
            failure,
        };
        disconnect_account(&effects, USER_ID, ACCOUNT_JID).await;
        effects.calls.into_inner().unwrap()
    }

    fn all_calls() -> Vec<Call> {
        vec![
            Call::Local(USER_ID, ACCOUNT_JID.to_owned()),
            Call::Sm(USER_ID),
            Call::Generation(USER_ID),
            Call::Notify(ACCOUNT_JID.to_owned(), USER_ID, 73),
        ]
    }

    #[tokio::test]
    async fn disconnect_account_runs_effects_in_order_with_committed_generation() {
        assert_eq!(recorded_disconnect(None).await, all_calls());
    }

    #[tokio::test]
    async fn disconnect_account_continues_after_sm_revoke_error() {
        assert_eq!(recorded_disconnect(Some(Failure::Sm)).await, all_calls());
    }

    #[tokio::test]
    async fn disconnect_account_stops_before_notification_on_generation_error() {
        assert_eq!(
            recorded_disconnect(Some(Failure::Generation)).await,
            all_calls()[..3]
        );
    }

    #[tokio::test]
    async fn disconnect_account_returns_normally_after_notification_error() {
        assert_eq!(
            recorded_disconnect(Some(Failure::Notification)).await,
            all_calls()
        );
    }

    struct Stub(Option<i64>);

    impl AccountGenerationRepository for Stub {
        async fn generation(&self, _user_id: Uuid) -> Result<Option<i64>> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn deleted_account_uses_full_revocation_fence() {
        let service = AccountGenerationService::new(Stub(None));
        assert_eq!(
            service.committed_generation(Uuid::new_v4()).await.unwrap(),
            i64::MAX
        );
    }
}
