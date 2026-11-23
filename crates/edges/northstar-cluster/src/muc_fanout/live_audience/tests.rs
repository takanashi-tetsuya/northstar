use super::*;
use uuid::Uuid;

#[test]
fn exact_broadcast_splits_at_the_route_limit_without_losing_routes() {
    let routes: Vec<_> = (1..=MUC_ROUTE_ENVELOPE_LIMIT + 1)
        .map(|index| MucOccupantRoute {
            nick: format!("nick-{index}"),
            full_jid: format!("user-{index}@example.test/phone"),
            connection_id: Uuid::from_u128(index as u128),
            cluster_epoch: Uuid::from_u128(1),
        })
        .collect();
    let borrowed: Vec<_> = routes.iter().collect();
    let room = "room@conference.example.test";
    let sender = "alice@example.test/phone";
    let payloads: Vec<_> =
        exact_broadcast_payloads(room, "<message/>", Some(sender), &borrowed).collect();
    assert_eq!(payloads.len(), 2);
    assert_eq!(
        payloads[0]["audience"].as_array().unwrap().len(),
        MUC_ROUTE_ENVELOPE_LIMIT
    );
    assert_eq!(payloads[1]["audience"].as_array().unwrap().len(), 1);
    let mut decoded = Vec::new();
    for payload in payloads {
        assert_eq!(
            payload["envelope_version"],
            MUC_EXACT_ROUTE_ENVELOPE_VERSION
        );
        assert_eq!(payload["target"], room);
        assert_eq!(payload["stanza"], "<message/>");
        assert_eq!(payload["real_sender"], sender);
        decoded.extend(
            serde_json::from_value::<Vec<MucOccupantRoute>>(payload["audience"].clone()).unwrap(),
        );
    }
    assert_eq!(decoded, routes);
}
