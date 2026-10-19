//! Occupant records shared by the room service, the MUC protocol adapters and cluster replication.

/// The process-local identity needed to remove one occupancy without touching
/// a connection that later reused its room nickname.
#[derive(Clone, Copy)]
pub(crate) struct LocalMucOccupantIdentity<'a> {
    pub room_jid: &'a str,
    pub nick: &'a str,
    pub full_jid: &'a str,
    pub connection_id: uuid::Uuid,
    pub cluster_epoch: uuid::Uuid,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SerializableMucOccupant {
    pub full_jid: String,
    pub room_jid: String,
    pub nick: String,
    pub affiliation: String,
    pub role: String,
    pub room_non_anonymous: bool,
    #[serde(default)]
    pub occupant_id: String,
    #[serde(default)]
    pub cluster_epoch: uuid::Uuid,
    #[serde(default)]
    pub connection_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federated_domain: Option<String>,
    /// Internal cluster ownership epoch for a suspended XEP-0198 actor. It is
    /// never rendered into an XMPP stanza.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sm_session_id: Option<uuid::Uuid>,
    pub payload: String,
}

impl<'a> From<&'a SerializableMucOccupant> for LocalMucOccupantIdentity<'a> {
    fn from(occupant: &'a SerializableMucOccupant) -> Self {
        Self {
            room_jid: &occupant.room_jid,
            nick: &occupant.nick,
            full_jid: &occupant.full_jid,
            connection_id: occupant.connection_id,
            cluster_epoch: occupant.cluster_epoch,
        }
    }
}
