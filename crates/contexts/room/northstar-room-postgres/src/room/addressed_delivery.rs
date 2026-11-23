use super::{PostgresMucRepository, RoomEffects};
use anyhow::Result;
use northstar_room_application::muc_service::{
    MucAddressedActor, MucAddressedDeliveryRepository, MucAddressedOutcome, MucAddressedRequest,
};
use northstar_room_core::{occupancy::MucOccupantRoute, stanza::muc_occupant_id};
use sqlx::PgPool;

impl<E: RoomEffects> MucAddressedDeliveryRepository for PostgresMucRepository<E> {
    async fn muc_addressed_authority(
        &self,
        room_localpart: &str,
        request: MucAddressedRequest<'_>,
    ) -> Result<MucAddressedOutcome> {
        muc_addressed_authority(&self.pool, room_localpart, request).await
    }

    async fn current_muc_moderators(
        &self,
        room_localpart: &str,
        candidates: &[MucOccupantRoute],
    ) -> Result<Vec<MucOccupantRoute>> {
        current_muc_moderators(&self.pool, room_localpart, candidates).await
    }
}

type RouteJson = sqlx::types::Json<MucOccupantRoute>;
type RoutesJson = sqlx::types::Json<Vec<MucOccupantRoute>>;

#[derive(sqlx::FromRow)]
struct AuthorityRow {
    actor: Option<RouteJson>,
    actor_bare: Option<String>,
    actor_matches: Option<bool>,
    actor_allowed: Option<bool>,
    actor_visitor: Option<bool>,
    moderated: bool,
    allow_private_messages: bool,
    occupant_id_secret: Option<Vec<u8>>,
    target: Option<RouteJson>,
    moderators: RoutesJson,
}

pub async fn muc_addressed_authority(
    pool: &PgPool,
    room_localpart: &str,
    request: MucAddressedRequest<'_>,
) -> Result<MucAddressedOutcome> {
    let (actor, nick, voice) = match request {
        MucAddressedRequest::Private { actor, nick } => (Some(actor), Some(nick), false),
        MucAddressedRequest::Decline { nick } => (None, nick, false),
        MucAddressedRequest::Voice { actor } => (Some(actor), None, true),
    };
    let (full_jid, account_id, connection_id, authenticated_domain, occupant_incarnation) =
        match actor {
            Some(MucAddressedActor::Local {
                account_id,
                full_jid,
                connection_id,
                occupant_incarnation,
            }) => (
                Some(full_jid),
                Some(account_id),
                Some(connection_id),
                None,
                Some(occupant_incarnation),
            ),
            Some(MucAddressedActor::Federated {
                authenticated_domain,
                full_jid,
            }) => (Some(full_jid), None, None, Some(authenticated_domain), None),
            None => (None, None, None, None, None),
        };
    let row = sqlx::query_as::<_, AuthorityRow>(
        "WITH room AS (
             SELECT id,room_epoch,moderated,members_only,allow_private_messages,occupant_id_secret
               FROM muc_rooms WHERE localpart=$1 AND destroyed_at IS NULL
         ), live AS NOT MATERIALIZED (
             SELECT o.*, jsonb_build_object('nick',o.nick,'full_jid',o.full_jid,
                        'connection_id',o.connection_uuid,'cluster_epoch',o.occupant_incarnation) AS route
               FROM room r JOIN cluster_muc_occupancies o
                 ON o.room_id=r.id AND o.room_epoch=r.room_epoch
              WHERE o.state IN ('active','suspended') AND o.lease_until>statement_timestamp()
         )
         SELECT a.route AS actor,a.bare_jid AS actor_bare,
                CASE WHEN $3::uuid IS NOT NULL THEN
                    a.identity_kind='local' AND a.local_user_id=$3 AND a.connection_uuid=$4::uuid
                        AND a.occupant_incarnation=$8::uuid
                ELSE a.identity_kind='federated' AND a.authenticated_domain=$5 END AS actor_matches,
                COALESCE(f.affiliation,'none')<>'outcast'
                    AND (NOT r.members_only OR COALESCE(f.affiliation,'none')<>'none')
                    AS actor_allowed,
                a.role='visitor' AS actor_visitor,r.moderated,r.allow_private_messages,
                r.occupant_id_secret,
                (SELECT route FROM live WHERE nick=$6) AS target,
                CASE WHEN $7 THEN COALESCE((SELECT jsonb_agg(route ORDER BY nick)
                     FROM live WHERE role='moderator'),'[]'::jsonb) ELSE '[]'::jsonb END AS moderators
           FROM room r LEFT JOIN live a ON a.full_jid=$2 AND a.state='active'
           LEFT JOIN muc_affiliations f ON f.room_id=r.id AND f.user_id=$3",
    )
    .bind(room_localpart)
    .bind(full_jid)
    .bind(account_id)
    .bind(connection_id)
    .bind(authenticated_domain)
    .bind(nick)
    .bind(voice)
    .bind(occupant_incarnation)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(if actor.is_some() {
            MucAddressedOutcome::NotJoined
        } else {
            MucAddressedOutcome::MissingRoom
        });
    };
    let target = row
        .target
        .map(|route| route.0)
        .filter(MucOccupantRoute::is_exact);
    if actor.is_none() {
        return Ok(MucAddressedOutcome::Decline { target });
    }
    let Some(sender) = row
        .actor
        .map(|route| route.0)
        .filter(MucOccupantRoute::is_exact)
    else {
        return Ok(MucAddressedOutcome::NotJoined);
    };
    if row.actor_matches != Some(true) {
        return Ok(if authenticated_domain.is_some() {
            MucAddressedOutcome::NotAuthorized
        } else {
            MucAddressedOutcome::NotJoined
        });
    }
    if (account_id.is_some() && row.actor_allowed != Some(true))
        || if voice {
            !row.moderated || row.actor_visitor != Some(true)
        } else {
            !row.allow_private_messages
        }
    {
        return Ok(MucAddressedOutcome::Forbidden);
    }
    if voice {
        return Ok(MucAddressedOutcome::Voice {
            requester: sender,
            moderators: row
                .moderators
                .0
                .into_iter()
                .filter(MucOccupantRoute::is_exact)
                .collect(),
        });
    }
    let secret = row
        .occupant_id_secret
        .ok_or_else(|| anyhow::anyhow!("live MUC occupancy has no occupant ID secret"))?;
    let bare = row
        .actor_bare
        .ok_or_else(|| anyhow::anyhow!("live MUC occupancy has no bare JID"))?;
    Ok(MucAddressedOutcome::Private {
        sender_nick: sender.nick,
        sender_occupant_id: muc_occupant_id(&secret, &bare),
        target,
    })
}

pub async fn current_muc_moderators(
    pool: &PgPool,
    room_localpart: &str,
    candidates: &[MucOccupantRoute],
) -> Result<Vec<MucOccupantRoute>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_scalar::<_, RouteJson>(
        "SELECT jsonb_build_object('nick',c.nick,'full_jid',c.full_jid,
                    'connection_id',c.connection_id,'cluster_epoch',c.cluster_epoch)
           FROM jsonb_to_recordset($2) AS c(nick text,full_jid text,connection_id uuid,cluster_epoch uuid)
           JOIN muc_rooms r ON r.localpart=$1 AND r.destroyed_at IS NULL
           JOIN cluster_muc_occupancies o ON o.room_id=r.id AND o.room_epoch=r.room_epoch
                AND o.occupant_incarnation=c.cluster_epoch AND o.connection_uuid=c.connection_id
                AND o.full_jid=c.full_jid AND o.nick=c.nick
          WHERE o.role='moderator' AND o.state IN ('active','suspended')
            AND o.lease_until>statement_timestamp()",
    )
    .bind(room_localpart)
    .bind(sqlx::types::Json(candidates))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| row.0)
        .filter(MucOccupantRoute::is_exact)
        .collect())
}
