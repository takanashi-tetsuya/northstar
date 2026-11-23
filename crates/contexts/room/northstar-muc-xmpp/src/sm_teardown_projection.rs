//! Resolve an exact suspended MUC occupant before its committed teardown.

use dashmap::DashMap;
use northstar_room_application::sm_teardown_muc::{SmTeardownMucRepository, SmTeardownMucService};
use northstar_room_core::occupancy::{MucOccupantEndpoint, SerializableMucOccupant};
use northstar_room_core::MucTimeSources;
use northstar_stream::local_routes::muc::MucOccupant;
use northstar_xmpp_types::jid_text::{bare_jid, localpart};
use std::sync::Arc;
use uuid::Uuid;

pub struct SmTeardownMucProjection<R> {
    service: SmTeardownMucService<R>,
    occupants: Arc<DashMap<String, MucOccupant>>,
    time_sources: MucTimeSources,
}

impl<R: SmTeardownMucRepository> SmTeardownMucProjection<R> {
    pub fn new(
        service: SmTeardownMucService<R>,
        occupants: Arc<DashMap<String, MucOccupant>>,
    ) -> Self {
        Self::new_with_time_sources(service, occupants, MucTimeSources::default())
    }

    pub fn new_with_time_sources(
        service: SmTeardownMucService<R>,
        occupants: Arc<DashMap<String, MucOccupant>>,
        time_sources: MucTimeSources,
    ) -> Self {
        Self {
            service,
            occupants,
            time_sources,
        }
    }

    pub async fn occupant(
        &self,
        sm_session_id: Uuid,
        user_id: Uuid,
        full_jid: &str,
        room_jid: &str,
        nick: &str,
    ) -> anyhow::Result<SerializableMucOccupant> {
        if let Some(occupant) =
            self.cached_suspended_occupant(sm_session_id, full_jid, room_jid, nick)
        {
            return Ok(occupant);
        }
        let projection = self
            .service
            .occupant_projection(localpart(room_jid), user_id, bare_jid(full_jid))
            .await?;
        Ok(SerializableMucOccupant {
            full_jid: full_jid.to_owned(),
            room_jid: room_jid.to_owned(),
            nick: nick.to_owned(),
            affiliation: projection.affiliation,
            role: projection.role.to_owned(),
            room_non_anonymous: projection.room_non_anonymous,
            occupant_id: projection.occupant_id,
            cluster_epoch: self.time_sources.new_uuid(),
            connection_id: Uuid::nil(),
            federated_domain: None,
            sm_session_id: Some(sm_session_id),
            payload: String::new(),
        })
    }

    fn cached_suspended_occupant(
        &self,
        sm_session_id: Uuid,
        full_jid: &str,
        room_jid: &str,
        nick: &str,
    ) -> Option<SerializableMucOccupant> {
        let key = northstar_room_core::stanza::muc_occupant_key(room_jid, nick);
        self.occupants
            .get(&key)
            .filter(|occupant| {
                occupant.full_jid == full_jid
                    && occupant.room_jid == room_jid
                    && occupant.nick == nick
                    && !occupant.cluster_epoch.is_nil()
                    && !occupant.connection_id.is_nil()
                    && matches!(
                        &occupant.endpoint,
                        MucOccupantEndpoint::Suspended(endpoint)
                            if endpoint.sm_session_id == sm_session_id
                    )
            })
            .map(|occupant| SerializableMucOccupant::from(&*occupant))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_room_application::muc_service::{CommittedRoomRetirement, MucRoomIncarnation};
    use northstar_room_application::sm_teardown_muc::SmTeardownMucRoom;
    use northstar_room_core::occupancy::MucOccupantRoute;
    use northstar_stream::local_routes::muc::SuspendedMucEndpoint;
    use std::collections::HashSet;

    struct StubRepository {
        expect_lookup: bool,
        room_id: Uuid,
        user_id: Uuid,
    }

    impl SmTeardownMucRepository for StubRepository {
        async fn room(&self, localpart: &str) -> anyhow::Result<Option<SmTeardownMucRoom>> {
            assert!(self.expect_lookup);
            assert_eq!(localpart, "room");
            Ok(Some(SmTeardownMucRoom {
                id: self.room_id,
                room_epoch: Uuid::new_v4(),
                config_version: 1,
                non_anonymous: false,
                occupant_id_secret: b"room-secret".to_vec(),
            }))
        }

        async fn affiliation(
            &self,
            room_id: Uuid,
            user_id: Uuid,
        ) -> anyhow::Result<Option<String>> {
            assert_eq!(room_id, self.room_id);
            assert_eq!(user_id, self.user_id);
            Ok(Some("owner".to_owned()))
        }

        async fn blocked_local_audience(
            &self,
            _local_domain: &str,
            _occupant_jids: &[String],
            _stanza_senders: &[String],
        ) -> anyhow::Result<HashSet<String>> {
            panic!("unexpected blocked audience lookup");
        }

        async fn delete_temporary_room(
            &self,
            _room: MucRoomIncarnation,
        ) -> anyhow::Result<Option<CommittedRoomRetirement>> {
            panic!("unexpected temporary room deletion");
        }

        async fn departed_room(
            &self,
            _localpart: &str,
            _route: &MucOccupantRoute,
            _sm_session_id: Uuid,
        ) -> anyhow::Result<Option<MucRoomIncarnation>> {
            panic!("unexpected departed room lookup");
        }

        async fn departure_observers(
            &self,
            _room: MucRoomIncarnation,
            _departed_nick: &str,
        ) -> anyhow::Result<Vec<MucOccupantRoute>> {
            panic!("unexpected departure observer lookup");
        }
    }

    fn suspended_occupant(sm_session_id: Uuid) -> MucOccupant {
        MucOccupant {
            full_jid: "alice@example.test/Phone".to_owned(),
            room_jid: "room@muc.example.test".to_owned(),
            nick: "Alice".to_owned(),
            endpoint: MucOccupantEndpoint::Suspended(Arc::new(
                SuspendedMucEndpoint::new_collecting(sm_session_id, 0, 0),
            )),
            affiliation: "member".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: true,
            occupant_id: "cached-occupant-id".to_owned(),
            cluster_epoch: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            sm_session_id: Some(sm_session_id),
            payload: "cached-payload".to_owned(),
        }
    }

    #[test]
    fn exact_suspended_cache_hit_skips_projection() {
        futures::executor::block_on(async {
            let sm_session_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let occupant = suspended_occupant(sm_session_id);
            let occupants = Arc::new(DashMap::new());
            occupants.insert(
                northstar_room_core::stanza::muc_occupant_key(&occupant.room_jid, &occupant.nick),
                occupant.clone(),
            );
            let projection = SmTeardownMucProjection::new(
                SmTeardownMucService::new(StubRepository {
                    expect_lookup: false,
                    room_id: Uuid::new_v4(),
                    user_id,
                }),
                occupants,
            );
            let result = projection
                .occupant(
                    sm_session_id,
                    user_id,
                    &occupant.full_jid,
                    &occupant.room_jid,
                    &occupant.nick,
                )
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(&result).unwrap(),
                serde_json::to_value(SerializableMucOccupant::from(&occupant)).unwrap()
            );
        });
    }

    #[test]
    fn suspended_cache_requires_exact_identity_and_endpoint() {
        let sm_session_id = Uuid::new_v4();
        let occupant = suspended_occupant(sm_session_id);
        let key = northstar_room_core::stanza::muc_occupant_key(&occupant.room_jid, &occupant.nick);
        let occupants = Arc::new(DashMap::new());
        let projection = SmTeardownMucProjection::new(
            SmTeardownMucService::new(StubRepository {
                expect_lookup: false,
                room_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
            }),
            Arc::clone(&occupants),
        );
        for mismatch in 0..8 {
            let mut cached = occupant.clone();
            match mismatch {
                0 => cached.full_jid = "alice@example.test/Other".to_owned(),
                1 => cached.room_jid = "other@muc.example.test".to_owned(),
                2 => cached.nick = "Other".to_owned(),
                3 => cached.cluster_epoch = Uuid::nil(),
                4 => cached.connection_id = Uuid::nil(),
                5 => {
                    cached.endpoint = MucOccupantEndpoint::Suspended(Arc::new(
                        SuspendedMucEndpoint::new_collecting(Uuid::new_v4(), 0, 0),
                    ));
                }
                6 => {
                    cached.endpoint = MucOccupantEndpoint::Federated {
                        authenticated_domain: "example.test".to_owned(),
                        connection_id: cached.connection_id,
                    };
                }
                _ => {
                    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
                    cached.endpoint = MucOccupantEndpoint::Local(
                        northstar_stream::outbound::OutboundSender::new(sender),
                    );
                }
            }
            occupants.insert(key.clone(), cached);
            assert!(
                projection
                    .cached_suspended_occupant(
                        sm_session_id,
                        &occupant.full_jid,
                        &occupant.room_jid,
                        &occupant.nick,
                    )
                    .is_none(),
                "accepted cache mismatch {mismatch}"
            );
        }
    }

    #[test]
    fn cache_miss_projects_occupant_with_fresh_epoch_and_nil_connection() {
        futures::executor::block_on(async {
            let sm_session_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();
            let projection = SmTeardownMucProjection::new(
                SmTeardownMucService::new(StubRepository {
                    expect_lookup: true,
                    room_id: Uuid::new_v4(),
                    user_id,
                }),
                Arc::new(DashMap::new()),
            );
            let mut epochs = HashSet::new();
            for _ in 0..2 {
                let result = projection
                    .occupant(
                        sm_session_id,
                        user_id,
                        "alice@example.test/Phone",
                        "room@muc.example.test",
                        "Alice",
                    )
                    .await
                    .unwrap();
                assert_eq!(result.full_jid, "alice@example.test/Phone");
                assert_eq!(result.room_jid, "room@muc.example.test");
                assert_eq!(result.nick, "Alice");
                assert_eq!(result.affiliation, "owner");
                assert_eq!(result.role, "moderator");
                assert!(!result.room_non_anonymous);
                assert_eq!(
                    result.occupant_id,
                    northstar_room_core::stanza::muc_occupant_id(
                        b"room-secret",
                        "alice@example.test",
                    )
                );
                assert!(!result.cluster_epoch.is_nil());
                assert!(epochs.insert(result.cluster_epoch));
                assert!(result.connection_id.is_nil());
                assert_eq!(result.sm_session_id, Some(sm_session_id));
                assert_eq!(result.federated_domain, None);
                assert!(result.payload.is_empty());
            }
        });
    }
}
