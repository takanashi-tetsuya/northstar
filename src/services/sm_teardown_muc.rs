//! PostgreSQL projections needed after an exact SM-owned MUC route is fenced.

use anyhow::Result;
use std::{collections::HashSet, future::Future};
use uuid::Uuid;

pub(crate) struct SmTeardownMucRoom {
    pub(crate) id: Uuid,
    pub(crate) room_epoch: Uuid,
    pub(crate) config_version: i64,
    pub(crate) non_anonymous: bool,
    pub(crate) occupant_id_secret: Vec<u8>,
}

pub(crate) struct SmTeardownMucOccupantProjection {
    pub(crate) affiliation: String,
    pub(crate) role: &'static str,
    pub(crate) room_non_anonymous: bool,
    pub(crate) occupant_id: String,
}

pub(crate) trait SmTeardownMucRepository: Send + Sync {
    fn room(
        &self,
        localpart: &str,
    ) -> impl Future<Output = Result<Option<SmTeardownMucRoom>>> + Send;

    fn affiliation(
        &self,
        room_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Option<String>>> + Send;

    fn blocked_local_audience(
        &self,
        local_domain: &str,
        occupant_jids: &[String],
        stanza_senders: &[String],
    ) -> impl Future<Output = Result<HashSet<String>>> + Send;

    fn delete_temporary_room(
        &self,
        room_id: Uuid,
        room_epoch: Uuid,
        config_version: i64,
    ) -> impl Future<Output = Result<bool>> + Send;
}

#[derive(Clone)]
pub(crate) struct SmTeardownMucService<R> {
    repository: R,
}

impl<R: SmTeardownMucRepository> SmTeardownMucService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn occupant_projection(
        &self,
        room_localpart: &str,
        user_id: Uuid,
        actor_bare_jid: &str,
    ) -> Result<SmTeardownMucOccupantProjection> {
        let room = self.repository.room(room_localpart).await?;
        let affiliation = if let Some(room) = &room {
            self.repository
                .affiliation(room.id, user_id)
                .await?
                .unwrap_or_else(|| "none".to_owned())
        } else {
            "none".to_owned()
        };
        let role = if matches!(affiliation.as_str(), "owner" | "admin") {
            "moderator"
        } else {
            "participant"
        };
        Ok(SmTeardownMucOccupantProjection {
            affiliation,
            role,
            room_non_anonymous: room.as_ref().is_none_or(|room| room.non_anonymous),
            occupant_id: room
                .as_ref()
                .map(|room| {
                    crate::xmpp::xml_util::muc_occupant_id(&room.occupant_id_secret, actor_bare_jid)
                })
                .unwrap_or_default(),
        })
    }

    pub(crate) async fn blocked_local_audience(
        &self,
        local_domain: &str,
        occupant_jids: &[String],
        stanza_senders: &[String],
    ) -> Result<HashSet<String>> {
        self.repository
            .blocked_local_audience(local_domain, occupant_jids, stanza_senders)
            .await
    }

    pub(crate) async fn retire_empty_temporary_room(&self, room_localpart: &str) -> Result<bool> {
        let Some(room) = self.repository.room(room_localpart).await? else {
            return Ok(false);
        };
        self.repository
            .delete_temporary_room(room.id, room.room_epoch, room.config_version)
            .await
    }
}
