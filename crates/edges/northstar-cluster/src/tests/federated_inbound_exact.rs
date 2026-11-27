use super::*;
use crate::listener::test_federated_presence_control;
use crate::presence_routing::{FederatedPresenceOwner, FederatedPresenceRequest};
use northstar_roster_core::PresenceAccount;
use northstar_session_application::replay::ReplayService;
use northstar_session_postgres::replay_repository::PostgresReplayRepository;
use northstar_stream::local_routes::session_table::LocalSessionTable;
use serde_json::json;

const PEER: &str = "remote.test";
const SENDER: &str = "alice@remote.test/Tablet";
const PRESENCE: &str =
    "<presence xmlns='jabber:client' from='alice@remote.test/Tablet' to='bob@example.test'/>";

fn payload(kind: ExactControlKind, stanza: &str) -> serde_json::Value {
    let request = FederatedPresenceRequest {
        target: TARGET,
        sender: SENDER,
        stanza,
        remote_peer: PEER,
        kind,
        pending_created_at_micros: None,
    };
    let account = PresenceAccount {
        id: ORIGINAL,
        auth_generation: 1,
        username: "bob".to_owned(),
    };
    let control = request.control(&account, [(ORIGINAL_JID.to_owned(), ORIGINAL)].into());
    let mut json = request.payload(&control);
    json["protocol_version"] = json!(EXACT_CONTROL_DELIVERY_VERSION);
    json
}

fn unused_replay() -> ReplayService<PostgresReplayRepository> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgresql://unused@localhost/unused")
        .unwrap();
    ReplayService::new(PostgresReplayRepository::new(pool), "example.test", 30)
}

fn owner<'a>(
    fixture: &'a DirectDeliveryFixture,
    replay: &'a ReplayService<PostgresReplayRepository>,
) -> FederatedPresenceOwner<'a, UnusedPorts, PostgresReplayRepository, UnusedPorts> {
    FederatedPresenceOwner::new(
        LocalSessionTable::new(Arc::clone(&fixture.mix_caps.sessions)),
        &fixture.policy.presence,
        replay,
        &UnusedPorts,
        &fixture.policy.local_domain,
    )
}

#[tokio::test]
async fn federated_controls_reject_legacy_forms_and_carry_the_verified_peer() {
    let fixture = DirectDeliveryFixture::new();
    let mut recipient = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    let replay = unused_replay();
    let owner = owner(&fixture, &replay);
    for (kind, stanza) in [
        (ExactControlKind::FederatedInboundPresence, PRESENCE),
        (ExactControlKind::CurrentPresenceReplay, PRESENCE),
        (
            ExactControlKind::ProbeResponse,
            "<presence type='probe' from='alice@remote.test/Tablet' to='bob@example.test'/>",
        ),
    ] {
        let mut request = payload(kind, stanza);
        assert_eq!(request["exact_control"]["remote_peer"], PEER);
        request["protocol_version"] = json!(NODE_PROTOCOL_VERSION);
        assert!(test_federated_presence_control(&owner, &request)
            .await
            .is_err());
        request["protocol_version"] = json!(EXACT_CONTROL_DELIVERY_VERSION);
        request["exact_control"]["remote_peer"] = json!("spoofer.test");
        assert!(test_federated_presence_control(&owner, &request)
            .await
            .is_err());
    }
    assert!(recipient.try_recv().is_err());
}

#[tokio::test]
async fn federated_delivery_pins_the_account_generation_and_connection() {
    let fixture = DirectDeliveryFixture::new();
    let mut recipient = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    let mut sibling = fixture.add_session(RECREATED_JID, ORIGINAL, 0);
    let replay = unused_replay();
    let owner = owner(&fixture, &replay);
    let mut request = payload(ExactControlKind::FederatedInboundPresence, PRESENCE);
    assert_eq!(
        test_federated_presence_control(&owner, &request)
            .await
            .unwrap()
            .delivered,
        1
    );
    assert_eq!(recipient.try_recv().unwrap().stanza, PRESENCE);

    request["exact_control"]["auth_generation"] = json!(2);
    assert_eq!(
        test_federated_presence_control(&owner, &request)
            .await
            .unwrap()
            .delivered,
        0
    );
    request["exact_control"]["auth_generation"] = json!(1);
    request["exact_control"]["expected_connections"][ORIGINAL_JID] = json!(RECREATED);
    assert_eq!(
        test_federated_presence_control(&owner, &request)
            .await
            .unwrap()
            .delivered,
        0
    );
    assert!(recipient.try_recv().is_err());
    assert!(sibling.try_recv().is_err());
}
