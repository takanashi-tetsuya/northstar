use northstar_xmpp_types::jid::CanonicalJid;
use uuid::Uuid;

/// The account incarnation a durable message write must still match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActorGenerationFence {
    pub account_id: Uuid,
    pub auth_generation: i64,
}

/// The authenticated account and bound resource that sent a client message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedMessageActor {
    pub account_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub full_jid: CanonicalJid,
}

impl AuthenticatedMessageActor {
    pub fn fence(&self) -> ActorGenerationFence {
        ActorGenerationFence {
            account_id: self.account_id,
            auth_generation: self.auth_generation,
        }
    }

    pub fn bare_jid(&self) -> String {
        self.full_jid.bare()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> AuthenticatedMessageActor {
        AuthenticatedMessageActor {
            account_id: Uuid::from_u128(1),
            auth_generation: 7,
            connection_id: Uuid::from_u128(2),
            full_jid: CanonicalJid::parse("Alice@EXAMPLE.test/Laptop").unwrap(),
        }
    }

    #[test]
    fn fence_uses_the_authenticated_account_incarnation() {
        assert_eq!(
            actor().fence(),
            ActorGenerationFence {
                account_id: Uuid::from_u128(1),
                auth_generation: 7,
            },
        );
    }

    #[test]
    fn bare_jid_projects_the_canonical_account_address() {
        assert_eq!(actor().bare_jid(), "alice@example.test");
    }
}
