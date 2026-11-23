use anyhow::Result;
use northstar_room_application::mix_service::HostedDiscoView;
use northstar_room_core::mix::{
    MixAccessModel, MixAdministratorRetractionRights, MixChannelAddress, MixChannelId, MixRole,
};
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{postgres::PgRow, PgPool, Row};

pub(crate) async fn hosted_disco(
    pool: &PgPool,
    address: &MixChannelAddress,
    actor: &CanonicalJid,
) -> Result<Option<HostedDiscoView>> {
    fetch_discovery(pool, Some(address), None, actor)
        .await?
        .map(|row| {
            let (actor_admitted, visible_to_actor) = discovery_admission(&row);
            Ok(HostedDiscoView {
                channel_id: MixChannelId::new(row.get("id")),
                address: address.clone(),
                name: row.get("name"),
                revision: row.get("revision"),
                discoverable: row.get("discoverable"),
                access_model: MixAccessModel::parse(row.get("access_model"))?,
                actor_admitted,
                visible_to_actor,
                actor_role: row
                    .get::<Option<&str>, _>("actor_role")
                    .map(MixRole::parse)
                    .transpose()?,
                allow_user_message_retraction: row.get("allow_user_message_retraction"),
                administrator_retraction_rights: MixAdministratorRetractionRights::parse(
                    row.get("administrator_retraction_rights"),
                )?,
                allow_private_messages: row.get("allow_private_messages"),
                muc_room_id: row.get("muc_room_id"),
            })
        })
        .transpose()
}

pub(super) async fn fetch_discovery(
    pool: &PgPool,
    address: Option<&MixChannelAddress>,
    channel_id: Option<&MixChannelId>,
    actor: &CanonicalJid,
) -> Result<Option<PgRow>> {
    anyhow::ensure!(
        actor.resourcepart().is_none(),
        "MIX disco requester must be a bare JID or authenticated domain"
    );
    let row = sqlx::query(
        "SELECT c.id, c.name, c.revision, c.discoverable, c.access_model,
            c.allow_user_message_retraction, c.administrator_retraction_rights,
            c.allow_private_messages, cr.role AS actor_role,
            (SELECT r.id FROM mix_muc_mirrors mm JOIN muc_rooms r ON r.id = mm.muc_room_id
             WHERE mm.mix_channel_id = c.id AND r.destroyed_at IS NULL
               AND r.localpart = c.localpart) AS muc_room_id,
            EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = c.id AND jid = $2) AS participant,
            EXISTS(SELECT 1 FROM mix_banned WHERE channel_id = c.id AND jid_pattern IN ($2, $3)) AS banned,
            EXISTS(SELECT 1 FROM mix_allowed WHERE channel_id = c.id AND jid_pattern IN ($2, $3)) AS allowed
         FROM mix_channels c
         LEFT JOIN mix_channel_roles cr ON cr.channel_id = c.id AND cr.jid = $2
         WHERE ($1::uuid IS NOT NULL AND c.id = $1)
            OR (c.service_domain = $4 AND c.localpart = $5)",
    )
    .bind(channel_id.map(MixChannelId::as_uuid))
    .bind(actor.bare())
    .bind(actor.domainpart())
    .bind(address.map(MixChannelAddress::domain))
    .bind(address.map(MixChannelAddress::localpart))
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub(super) fn discovery_admission(row: &PgRow) -> (bool, bool) {
    let privileged = row.get::<Option<&str>, _>("actor_role").is_some();
    let participant = row.get::<bool, _>("participant");
    let admitted = (privileged || !row.get::<bool, _>("banned"))
        && (row.get::<&str, _>("access_model") == "open"
            || participant
            || privileged
            || row.get::<bool, _>("allowed"));
    let visible = admitted && (row.get::<bool, _>("discoverable") || participant || privileged);
    (admitted, visible)
}
