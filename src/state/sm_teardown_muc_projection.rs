//! Resolve an exact suspended MUC occupant before its committed teardown.

use super::{
    bare_jid, localpart, AppState, MucOccupant, MucOccupantEndpoint, SerializableMucOccupant,
};
use crate::{
    db::sm_teardown_muc_repository::PostgresSmTeardownMucRepository,
    services::sm_teardown_muc::SmTeardownMucService,
};
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

pub(super) struct SmTeardownMucProjection {
    service: SmTeardownMucService<PostgresSmTeardownMucRepository>,
    occupants: Arc<DashMap<String, MucOccupant>>,
}

impl AppState {
    pub(super) fn sm_teardown_muc_projection(&self) -> SmTeardownMucProjection {
        SmTeardownMucProjection {
            service: self.sm_teardown_muc_service(),
            occupants: Arc::clone(&self.muc_occupants),
        }
    }
}

impl SmTeardownMucProjection {
    pub(super) async fn occupant(
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
            cluster_epoch: Uuid::new_v4(),
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
        let key = crate::xmpp::xml_util::muc_occupant_key(room_jid, nick);
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
