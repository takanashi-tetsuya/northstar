use super::*;
use northstar_room_application::room_delivery_policy::{
    RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomDeliveryPolicyReader, RoomPolicySubject,
};

impl RoomDeliveryPolicyReader for Ports {
    async fn read_room_delivery_policies(
        &self,
        queries: &[RoomDeliveryPolicyQuery<'_>],
    ) -> Result<Vec<RoomDeliveryDecision>> {
        let [query] = queries else {
            panic!("expected an exact MUC recipient");
        };
        let mut peers = vec![query.visible_peer.to_owned()];
        peers.extend(query.real_peer.map(str::to_owned));
        assert!(self
            .blocked_local_accounts("example.test", &[query.recipient_jid.to_owned()], &peers)
            .await?
            .is_empty());
        let RoomPolicySubject::Connection { id, expects_active } = query.route.subject else {
            panic!("expected an exact connection");
        };
        assert!(!expects_active);
        assert!(
            self.privacy_allows_session(
                query.route.account_id,
                id,
                None,
                query.visible_peer,
                query.kind.expect("expected a stanza mask"),
            )
            .await?
        );
        Ok(vec![RoomDeliveryDecision::Allow])
    }
}
