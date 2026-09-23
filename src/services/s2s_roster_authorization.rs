//! Roster visibility for authenticated inbound federation stanzas.
//! Directed-presence grants remain process-local and are checked by the
//! inbound router after this persisted subscription read.

use anyhow::Result;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FederatedRosterSubscription {
    From,
    Both,
    Other,
}

pub(crate) trait FederatedRosterRepository: Send + Sync {
    async fn subscription_for(
        &self,
        recipient_id: Uuid,
        requester_bare: &str,
    ) -> Result<Option<FederatedRosterSubscription>>;
}

pub(crate) struct FederatedRosterAuthorizationService<R> {
    repository: R,
}

impl<R: FederatedRosterRepository> FederatedRosterAuthorizationService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn allows_presence(
        &self,
        recipient_id: Uuid,
        requester_bare: &str,
    ) -> Result<bool> {
        Ok(matches!(
            self.repository
                .subscription_for(recipient_id, requester_bare)
                .await?,
            Some(FederatedRosterSubscription::From | FederatedRosterSubscription::Both)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubRepository {
        subscription: Option<FederatedRosterSubscription>,
        fail: bool,
    }

    impl FederatedRosterRepository for StubRepository {
        async fn subscription_for(
            &self,
            recipient_id: Uuid,
            requester_bare: &str,
        ) -> Result<Option<FederatedRosterSubscription>> {
            assert_eq!(recipient_id, Uuid::from_u128(7));
            assert_eq!(requester_bare, "remote@example.test");
            if self.fail {
                anyhow::bail!("roster read failed");
            }
            Ok(self.subscription)
        }
    }

    #[tokio::test]
    async fn only_inbound_or_mutual_subscription_grants_roster_visibility() {
        for (subscription, visible) in [
            (Some(FederatedRosterSubscription::From), true),
            (Some(FederatedRosterSubscription::Both), true),
            (Some(FederatedRosterSubscription::Other), false),
            (None, false),
        ] {
            let service = FederatedRosterAuthorizationService::new(StubRepository {
                subscription,
                fail: false,
            });
            assert_eq!(
                service
                    .allows_presence(Uuid::from_u128(7), "remote@example.test")
                    .await
                    .unwrap(),
                visible
            );
        }
    }

    #[tokio::test]
    async fn roster_lookup_error_is_not_converted_to_denial() {
        let service = FederatedRosterAuthorizationService::new(StubRepository {
            subscription: None,
            fail: true,
        });
        assert!(service
            .allows_presence(Uuid::from_u128(7), "remote@example.test")
            .await
            .is_err());
    }
}
