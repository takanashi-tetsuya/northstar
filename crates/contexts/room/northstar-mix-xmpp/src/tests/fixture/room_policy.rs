use super::*;
use northstar_room_application::room_delivery_policy::{
    RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomPolicyLiveSession, RoomPolicyRoute,
    RoomPolicySubject,
};

impl RoomPolicyLiveSession for LocalSession {
    fn room_policy_route(&self) -> RoomPolicyRoute {
        RoomPolicyRoute {
            account_id: self.user_id(),
            auth_generation: Some(0),
            subject: RoomPolicySubject::Connection {
                id: Uuid::from_u128(84),
                expects_active: false,
            },
        }
    }
}

impl crate::ports::MixChannelPolicyReader for Context {
    fn channel_policy_route_is_current(&self, full_jid: &str, sampled: RoomPolicyRoute) -> bool {
        self.state
            .sessions
            .lock()
            .unwrap()
            .iter()
            .any(|(jid, session)| jid == full_jid && session.room_policy_route() == sampled)
    }

    async fn read_channel_delivery_policies(
        &self,
        queries: &[RoomDeliveryPolicyQuery<'_>],
        lane: ChannelStanzaDatabaseLane,
    ) -> Result<Vec<RoomDeliveryDecision>> {
        if let [query] = queries {
            if query.kind.is_none() {
                let owner_id = query.route.account_id;
                let blocked = match lane {
                    ChannelStanzaDatabaseLane::LiveIngress => {
                        self.service
                            .is_blocked(owner_id, query.visible_peer)
                            .await?
                    }
                    ChannelStanzaDatabaseLane::DurableOutbox => {
                        self.service
                            .outbox_is_blocked(owner_id, query.visible_peer)
                            .await?
                    }
                };
                if blocked {
                    return Ok(vec![RoomDeliveryDecision::Blocked]);
                }
            }
        }
        Ok(vec![RoomDeliveryDecision::Allow; queries.len()])
    }
}
