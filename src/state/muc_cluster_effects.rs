//! Cluster publication commands used after MUC persistence has committed.

use super::{AppState, SerializableMucOccupant};
use anyhow::Result;

pub(crate) struct MucPresencePublication<'a> {
    pub(crate) room: &'a str,
    pub(crate) occupant: &'a SerializableMucOccupant,
    pub(crate) unavailable: bool,
    pub(crate) created: bool,
    pub(crate) removal_status: Option<u16>,
    pub(crate) actor_nick: Option<&'a str>,
    pub(crate) reason: Option<&'a str>,
}

impl AppState {
    pub(crate) async fn publish_muc_cluster_stanza(
        &self,
        room: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        match real_sender {
            Some(sender) => self.cluster.send_to_muc_from(room, stanza, sender).await,
            None => self.cluster.send_to_muc(room, stanza).await,
        }
    }

    pub(crate) async fn evict_cluster_muc_occupant(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        self.cluster
            .evict_muc_occupant(occupant, status, actor_nick, reason)
            .await
            .map(|_| ())
    }

    pub(crate) async fn leave_cluster_muc_room(&self, room: &str) -> Result<()> {
        self.cluster.leave_muc(room).await
    }

    pub(crate) async fn register_cluster_muc_occupant(
        &self,
        room: &str,
        nick: &str,
        json: &str,
    ) -> Result<()> {
        self.cluster
            .register_muc_occupant(room, nick, json)
            .await
            .map(|_| ())
    }

    pub(crate) async fn publish_muc_cluster_presence(
        &self,
        publication: MucPresencePublication<'_>,
    ) -> Result<()> {
        self.cluster
            .send_muc_presence_with_status(
                publication.room,
                publication.occupant,
                publication.unavailable,
                publication.created,
                None,
                publication.removal_status,
                publication.actor_nick,
                publication.reason,
            )
            .await
    }
}
