use super::*;
use northstar_roster_application::subscription_retry::SubscriptionRetryIdentity;
use northstar_roster_core::RosterActor;
use uuid::Uuid;

const FROM: &str = "alice@example.test";
const TO: &str = "bob@example.test";
const MINIMAL: &str =
    "<presence xmlns='jabber:client' from='alice@example.test' to='bob@example.test' type='subscribe'/>";
const IDENTITY: SubscriptionRetryIdentity = SubscriptionRetryIdentity {
    roster_updated_at_micros: 157,
    roster_version: Some(7),
    local_created_at_micros: Some(156),
};

struct RetryRepository(SubscriptionRetryAdmission);

impl SubscriptionRetryRepository for RetryRepository {
    async fn pending_retry_identity(
        &self,
        request: SubscriptionRetryRequest<'_>,
    ) -> Result<Option<SubscriptionRetryIdentity>> {
        assert_eq!(request.contact, TO);
        Ok(Some(IDENTITY))
    }

    async fn retry_outbound_subscription(
        &self,
        _: SubscriptionRetryRequest<'_>,
        identity: SubscriptionRetryIdentity,
        stanza: &str,
    ) -> Result<SubscriptionRetryAdmission> {
        assert_eq!(identity, IDENTITY);
        assert_eq!(stanza, MINIMAL);
        Ok(self.0)
    }
}

#[tokio::test]
async fn retry_preserves_the_admission_outcome_and_minimal_subscribe() {
    let actor = RosterActor {
        account_id: Uuid::from_u128(1),
        auth_generation: 3,
        connection_id: Uuid::from_u128(2),
        full_jid: format!("{FROM}/phone"),
    };
    let contact = PresenceAccount {
        id: Uuid::from_u128(3),
        auth_generation: 4,
        username: "bob".to_owned(),
    };
    for expected in [
        SubscriptionRetryAdmission::Stale,
        SubscriptionRetryAdmission::Local {
            created_at_micros: 156,
        },
    ] {
        let request = SubscriptionRetryRequest {
            actor: &actor,
            contact: TO,
            expects_active: false,
            target: SubscriptionRetryTarget::Local(&contact),
        };
        let (admission, stanza) =
            admit_subscription_retry(&RetryRepository(expected), request, FROM)
                .await
                .unwrap();
        assert_eq!(admission, expected);
        assert_eq!(stanza, MINIMAL);
    }
}
