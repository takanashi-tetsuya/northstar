use northstar_roster_core::RosterActor;
use uuid::Uuid;

pub(super) fn bound_actor(
    account: Option<(Uuid, i64)>,
    connection_id: Uuid,
    full_jid: Option<&str>,
) -> Option<RosterActor> {
    let (account_id, auth_generation) = account?;
    Some(RosterActor {
        account_id,
        auth_generation,
        connection_id,
        full_jid: full_jid?.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{bound_actor, RosterActor, Uuid};

    #[test]
    fn actor_carries_the_authenticated_account_and_bound_connection() {
        let account_id = Uuid::from_u128(17);
        let auth_generation = 8;
        let connection_id = Uuid::from_u128(21);
        let full_jid = "alice@example.test/Phone/Work";

        assert_eq!(
            bound_actor(
                Some((account_id, auth_generation)),
                connection_id,
                Some(full_jid),
            ),
            Some(RosterActor {
                account_id,
                auth_generation,
                connection_id,
                full_jid: full_jid.to_owned(),
            }),
        );
        assert_eq!(bound_actor(None, connection_id, Some(full_jid)), None);
        assert_eq!(
            bound_actor(Some((account_id, auth_generation)), connection_id, None),
            None,
        );
    }
}
