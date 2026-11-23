use super::*;

const USER_ID: Uuid = Uuid::from_u128(1);
const LOCAL_DOMAIN: &str = "local.test";
const ACTOR: &str = "alice@local.test";
const SENDER: &str = "alice@local.test/Phone";

fn local(domain: &str) -> MucActorPrincipal {
    MucActorPrincipal::Local {
        user_id: USER_ID,
        local_domain: domain.to_owned(),
    }
}

fn federated(bare_jid: &str, domain: &str) -> MucActorPrincipal {
    MucActorPrincipal::Federated {
        bare_jid: bare_jid.to_owned(),
        authenticated_domain: domain.to_owned(),
    }
}

fn authority(actor_scope: &str, full_jid: &str, principal: MucActorPrincipal) -> MucActorAuthority {
    MucActorAuthority {
        clustered: false,
        expected_room_epoch: Uuid::from_u128(2),
        principal,
        actor_scope: actor_scope.to_owned(),
        full_jid: full_jid.to_owned(),
        nick: "Alice/Phone".to_owned(),
        occupant_incarnation: Uuid::from_u128(3),
        connection_uuid: Uuid::from_u128(4),
        expected_role: "none".to_owned(),
        expected_affiliation: "none".to_owned(),
        cluster_target: None,
    }
}

fn previous_matches_authenticated_scope(
    authority: &MucActorAuthority,
    configured_domain: &str,
) -> bool {
    let Ok(actor) = CanonicalJid::parse(&authority.actor_scope) else {
        return false;
    };
    if actor.resourcepart().is_some() || actor.to_string() != authority.actor_scope {
        return false;
    }
    let Ok(full) = CanonicalJid::parse(&authority.full_jid) else {
        return false;
    };
    if full.resourcepart().is_none()
        || full.to_string() != authority.full_jid
        || full.bare() != authority.actor_scope
    {
        return false;
    }
    match &authority.principal {
        MucActorPrincipal::Local { local_domain, .. } => {
            let (Ok(local_domain), Ok(configured_domain)) = (
                prepare_domainpart(local_domain),
                prepare_domainpart(configured_domain),
            ) else {
                return false;
            };
            local_domain == configured_domain && actor.domainpart() == local_domain
        }
        MucActorPrincipal::Federated {
            bare_jid,
            authenticated_domain,
        } => {
            let Ok(principal) = CanonicalJid::parse(bare_jid) else {
                return false;
            };
            let Ok(authenticated_domain) = prepare_domainpart(authenticated_domain) else {
                return false;
            };
            principal.resourcepart().is_none()
                && principal.to_string() == *bare_jid
                && principal.bare() == authority.actor_scope
                && principal.domainpart() == authenticated_domain
        }
    }
}

#[test]
fn verified_actor_preserves_authenticated_scope_checks() {
    for (actor, sender, local_domain, configured_domain, accepted) in [
        (ACTOR, SENDER, LOCAL_DOMAIN, LOCAL_DOMAIN, true),
        (ACTOR, SENDER, "LOCAL.TEST.", "LOCAL.TEST", true),
        (ACTOR, SENDER, "foreign.test", LOCAL_DOMAIN, false),
        (ACTOR, SENDER, LOCAL_DOMAIN, "foreign.test", false),
        (ACTOR, SENDER, LOCAL_DOMAIN, "", false),
        (ACTOR, SENDER, "", LOCAL_DOMAIN, false),
        (
            "Alice@local.test",
            SENDER,
            LOCAL_DOMAIN,
            LOCAL_DOMAIN,
            false,
        ),
        (
            ACTOR,
            "alice@LOCAL.TEST/Phone",
            LOCAL_DOMAIN,
            LOCAL_DOMAIN,
            false,
        ),
        (SENDER, SENDER, LOCAL_DOMAIN, LOCAL_DOMAIN, false),
        (ACTOR, ACTOR, LOCAL_DOMAIN, LOCAL_DOMAIN, false),
        (
            ACTOR,
            "alice@local.test/",
            LOCAL_DOMAIN,
            LOCAL_DOMAIN,
            false,
        ),
        ("", SENDER, LOCAL_DOMAIN, LOCAL_DOMAIN, false),
        (ACTOR, "", LOCAL_DOMAIN, LOCAL_DOMAIN, false),
        (
            ACTOR,
            "bob@local.test/Phone",
            LOCAL_DOMAIN,
            LOCAL_DOMAIN,
            false,
        ),
        (
            LOCAL_DOMAIN,
            "local.test/Phone",
            LOCAL_DOMAIN,
            LOCAL_DOMAIN,
            true,
        ),
        (
            "alice@foreign.test",
            "alice@foreign.test/Phone",
            LOCAL_DOMAIN,
            LOCAL_DOMAIN,
            false,
        ),
    ] {
        let authority = authority(actor, sender, local(local_domain));
        if let Some(principal) = assert_scope_case(&authority, configured_domain, accepted) {
            assert_eq!(
                principal,
                VerifiedMucPrincipal::Local {
                    user_id: USER_ID,
                    local_domain: LOCAL_DOMAIN.to_owned(),
                }
            );
        }
    }

    let remote_actor = "alice@bücher.test";
    let remote_sender = "alice@bücher.test/Phone";
    for (principal, domain, accepted) in [
        (remote_actor, "XN--BCHER-KVA.TEST", true),
        (remote_actor, "foreign.test", false),
        ("alice@xn--bcher-kva.test", "bücher.test", false),
        (remote_sender, "bücher.test", false),
        ("bob@bücher.test", "bücher.test", false),
        ("", "bücher.test", false),
        (remote_actor, "", false),
    ] {
        let authority = authority(remote_actor, remote_sender, federated(principal, domain));
        if let Some(VerifiedMucPrincipal::Federated {
            bare_jid,
            authenticated_domain,
        }) = assert_scope_case(&authority, "", accepted)
        {
            assert_eq!(bare_jid.to_string(), remote_actor);
            assert_eq!(authenticated_domain, "bücher.test");
        } else {
            assert!(
                !accepted,
                "expected a federated principal for {authority:?}"
            );
        }
    }
}

fn assert_scope_case(
    authority: &MucActorAuthority,
    configured_domain: &str,
    accepted: bool,
) -> Option<VerifiedMucPrincipal> {
    let previous = previous_matches_authenticated_scope(authority, configured_domain);
    assert_eq!(previous, accepted, "{authority:?} at {configured_domain:?}");
    assert_eq!(
        authority.matches_authenticated_scope(configured_domain),
        previous
    );
    let verified = authority.verified(configured_domain);
    assert_eq!(
        verified.is_some(),
        previous,
        "{authority:?} at {configured_domain:?}"
    );
    let verified = verified?;
    assert_eq!(verified.actor_scope.to_string(), authority.actor_scope);
    assert_eq!(verified.full_jid.to_string(), authority.full_jid);
    assert_eq!(verified.nick.as_str(), authority.nick);
    assert_eq!(verified.nick.to_string(), authority.nick);
    assert_eq!(verified.expected_role.as_str(), authority.expected_role);
    assert_eq!(
        verified.expected_affiliation.as_str(),
        authority.expected_affiliation
    );
    Some(verified.principal)
}

#[test]
fn verified_actor_checks_policy_and_nickname_beyond_scope() {
    for (nick, role, affiliation) in [
        ("", "participant", "member"),
        ("Alice\n", "participant", "member"),
        ("Alice", "Participant", "member"),
        ("Alice", "participant", ""),
    ] {
        let mut authority = authority(ACTOR, SENDER, local(LOCAL_DOMAIN));
        authority.nick = nick.to_owned();
        authority.expected_role = role.to_owned();
        authority.expected_affiliation = affiliation.to_owned();
        assert!(previous_matches_authenticated_scope(
            &authority,
            LOCAL_DOMAIN
        ));
        assert!(authority.matches_authenticated_scope(LOCAL_DOMAIN));
        assert!(authority.verified(LOCAL_DOMAIN).is_none());
    }
}

#[test]
fn occupancy_transition_names_round_trip_and_reject_other_spellings() {
    for (transition, name) in [
        (MucOccupancyTransition::Suspend, "suspend"),
        (MucOccupancyTransition::Resume, "resume"),
        (MucOccupancyTransition::Rebind, "rebind"),
        (MucOccupancyTransition::Leave, "leave"),
    ] {
        assert_eq!(transition.as_str(), name);
        assert_eq!(MucOccupancyTransition::parse(name), Some(transition));
    }
    for name in ["", "join", "Resume", " resume", "leave ", "suspended"] {
        assert_eq!(MucOccupancyTransition::parse(name), None);
    }
}

#[test]
fn exact_target_accessors_preserve_serialized_address_strings() {
    let mut target = ClusterMucOccupancyTarget {
        room_id: Uuid::from_u128(1),
        room_epoch: Uuid::from_u128(2),
        occupant_incarnation: Uuid::from_u128(3),
        occupancy_epoch: 1,
        full_jid: SENDER.to_owned(),
        nick: "Alice/Phone".to_owned(),
        connection_uuid: Uuid::from_u128(4),
        connection_epoch: 1,
    };
    assert_eq!(target.occupant_nick().unwrap().to_string(), target.nick);
    assert_eq!(target.full_jid().unwrap().to_string(), target.full_jid);

    target.full_jid = ACTOR.to_owned();
    assert_eq!(target.full_jid().unwrap().to_string(), ACTOR);

    target.full_jid = "Alice@LOCAL.TEST/Phone".to_owned();
    let stored = serde_json::to_string(&target).unwrap();
    assert_eq!(target.full_jid().unwrap().to_string(), SENDER);
    assert_eq!(serde_json::to_string(&target).unwrap(), stored);
    assert_eq!(
        serde_json::from_str::<ClusterMucOccupancyTarget>(&stored).unwrap(),
        target
    );

    target.full_jid.clear();
    target.nick.clear();
    assert!(target.full_jid().is_err());
    assert!(target.occupant_nick().is_err());
}
