use super::*;
use crate::muc::{read_muc_room, LIVE_MUC_ROOM};
use northstar_room_core::occupancy::MucOccupantRoute;
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{AssertSqlSafe, PgConnection, Postgres, Row, Transaction};

const EXACT_ACTIVE_ACTOR: &str =
    "SELECT actor.role,actor.affiliation,actor.local_user_id,actor.bare_jid
    FROM cluster_muc_occupancies AS actor
    JOIN room ON room.id=actor.room_id AND room.room_epoch=actor.room_epoch
    WHERE actor.occupant_incarnation=$2 AND actor.connection_uuid=$3
      AND actor.full_jid=$4 AND actor.nick=$5 AND actor.owner_node_id=$6
      AND actor.authenticated_domain IS NOT DISTINCT FROM $7::text
      AND actor.state='active' AND actor.lease_until > transaction_timestamp()";

pub(crate) async fn begin_read(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

fn visible(view: &MucRoomRead, full_jid: Option<&str>, federated: bool) -> bool {
    !view.room.is_locked()
        || (view.room.configuration_owner_jid.as_deref() == full_jid
            && (!federated || !view.configuration_expired))
}

async fn affiliation_and_reservation(
    transaction: &mut PgConnection,
    room_id: Uuid,
    principal: MucReadPrincipal<'_>,
) -> Result<(String, Option<String>)> {
    let row = match principal {
        MucReadPrincipal::Local { user_id, .. } => sqlx::query(
            "SELECT affiliation,reserved_nick FROM muc_affiliations WHERE room_id=$1 AND user_id=$2",
        )
        .bind(room_id)
        .bind(user_id)
        .fetch_optional(transaction)
        .await?,
        MucReadPrincipal::Federated { bare_jid, .. } => sqlx::query(
            "SELECT affiliation,reserved_nick FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2",
        )
        .bind(room_id)
        .bind(bare_jid)
        .fetch_optional(transaction)
        .await?,
    };
    Ok(row.map_or_else(
        || ("none".to_owned(), None),
        |row| (row.get("affiliation"), row.get("reserved_nick")),
    ))
}

async fn exact_actor(
    transaction: &mut PgConnection,
    room: &MucRoom,
    proof: MucOccupancyProof<'_>,
) -> Result<Option<sqlx::postgres::PgRow>> {
    if !proof.route.is_exact() {
        return Ok(None);
    }
    Ok(sqlx::query(AssertSqlSafe(format!(
        "WITH room AS (SELECT $1::uuid AS id,$8::uuid AS room_epoch) {EXACT_ACTIVE_ACTOR}"
    )))
    .bind(room.id)
    .bind(proof.route.cluster_epoch)
    .bind(proof.route.connection_id)
    .bind(&proof.route.full_jid)
    .bind(&proof.route.nick)
    .bind(proof.node_id)
    .bind(proof.authenticated_domain)
    .bind(room.room_epoch)
    .fetch_optional(transaction)
    .await?)
}

pub(crate) async fn enabled_local_viewer(
    transaction: &mut PgConnection,
    user_id: Uuid,
    bare_jid: &str,
    local_domain: &str,
) -> Result<bool> {
    let actor = CanonicalJid::parse_bare(bare_jid)?;
    let local_domain = northstar_xmpp_types::jid::prepare_domainpart(local_domain)?;
    if actor.domainpart() != local_domain || actor.to_string() != bare_jid {
        return Ok(false);
    }
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND username=$2 AND NOT is_disabled)",
    )
    .bind(user_id)
    .bind(actor.localpart().unwrap_or_default())
    .fetch_one(transaction)
    .await?)
}

async fn management_authority(
    transaction: &mut PgConnection,
    room: &MucRoom,
    viewer: MucManagementViewer<'_>,
    local_domain: &str,
) -> Result<Option<(String, String)>> {
    let (bare_jid, user_id, domain) = match viewer.principal {
        MucReadPrincipal::Local { user_id, bare_jid } => {
            if !enabled_local_viewer(transaction, user_id, bare_jid, local_domain).await? {
                return Ok(None);
            }
            (bare_jid, Some(user_id), None)
        }
        MucReadPrincipal::Federated { bare_jid, domain } => {
            if viewer.occupancy.is_none() {
                return Ok(None);
            }
            (bare_jid, None, Some(domain))
        }
    };
    if northstar_xmpp_types::jid::canonical_bare_key(viewer.full_jid)? != bare_jid {
        return Ok(None);
    }
    let (affiliation, _) =
        affiliation_and_reservation(transaction, room.id, viewer.principal).await?;
    let role = if let Some(proof) = viewer.occupancy {
        if proof.route.full_jid != viewer.full_jid || proof.authenticated_domain != domain {
            return Ok(None);
        }
        let Some(actor) = exact_actor(transaction, room, proof).await? else {
            return Ok(None);
        };
        if actor.get::<String, _>("bare_jid") != bare_jid
            || actor.get::<Option<Uuid>, _>("local_user_id") != user_id
            || actor.get::<String, _>("affiliation") != affiliation
        {
            return Ok(None);
        }
        actor.get("role")
    } else {
        "none".to_owned()
    };
    Ok(Some((affiliation, role)))
}

pub(crate) async fn role_entries(
    transaction: &mut PgConnection,
    room_id: Uuid,
    room_epoch: Uuid,
    role: &str,
) -> Result<Vec<crate::muc::MucAdminRoleEntry>> {
    Ok(sqlx::query(
        "SELECT nick,role,bare_jid FROM cluster_muc_occupancies
          WHERE room_id=$1 AND room_epoch=$2 AND role=$3
            AND state IN ('active','suspended') AND lease_until > transaction_timestamp()
          ORDER BY nick,occupancy_epoch",
    )
    .bind(room_id)
    .bind(room_epoch)
    .bind(role)
    .fetch_all(transaction)
    .await?
    .into_iter()
    .map(|row| crate::muc::MucAdminRoleEntry {
        nick: row.get("nick"),
        role: row.get("role"),
        bare_jid: row.get("bare_jid"),
    })
    .collect())
}

pub(crate) fn affiliation_list_allowed(
    affiliation: &str,
    requested: &str,
    members_only: bool,
    non_anonymous: bool,
) -> bool {
    matches!(requested, "owner" | "admin" | "member" | "outcast")
        && (matches!(affiliation, "owner" | "admin")
            || (affiliation == "member" && members_only && non_anonymous && requested != "outcast"))
}

pub(crate) async fn affiliation_entries(
    transaction: &mut PgConnection,
    room_id: Uuid,
    requested: &str,
    local_domain: &str,
) -> Result<Vec<crate::muc::MucAdminAffiliationEntry>> {
    Ok(sqlx::query(
        "SELECT address,is_local FROM (
            SELECT users.username AS address,true AS is_local FROM muc_affiliations affiliation
              JOIN users ON users.id=affiliation.user_id
             WHERE affiliation.room_id=$1 AND affiliation.affiliation=$2
            UNION ALL
            SELECT jid,false FROM muc_external_affiliations WHERE room_id=$1 AND affiliation=$2
         ) AS entries ORDER BY is_local DESC,address",
    )
    .bind(room_id)
    .bind(requested)
    .fetch_all(transaction)
    .await?
    .into_iter()
    .map(|row| {
        let address: String = row.get("address");
        crate::muc::MucAdminAffiliationEntry {
            bare_jid: if row.get("is_local") {
                format!("{address}@{local_domain}")
            } else {
                address
            },
            affiliation: requested.to_owned(),
        }
    })
    .collect())
}

impl<E: RoomEffects> MucReadRepository for PostgresMucRepository<E> {
    async fn read_room(&self, localpart: &str) -> Result<Option<MucRoomRead>> {
        read_muc_room(&self.pool, localpart).await
    }

    async fn room_view(
        &self,
        localpart: &str,
        viewer: MucRoomViewer<'_>,
        kind: MucRoomViewKind,
    ) -> Result<MucRoomView> {
        let mut transaction = begin_read(&self.pool).await?;
        let Some(view) = read_muc_room(&mut *transaction, localpart).await? else {
            return Ok(MucRoomView::Missing);
        };
        if (viewer.federated || kind != MucRoomViewKind::Registration)
            && !visible(&view, viewer.full_jid, viewer.federated)
        {
            return Ok(MucRoomView::Missing);
        }
        let room = &view.room;
        let mut nicks = Vec::new();
        let mut reserved_nick = None;
        let mut mirror_linked = false;
        match kind {
            MucRoomViewKind::Items => {
                if viewer.federated {
                    let Some(proof) = viewer.occupancy else {
                        return Ok(MucRoomView::Unauthorized);
                    };
                    if proof.authenticated_domain.is_none()
                        || Some(proof.route.full_jid.as_str()) != viewer.full_jid
                        || exact_actor(&mut transaction, room, proof).await?.is_none()
                    {
                        return Ok(MucRoomView::Unauthorized);
                    }
                }
                #[cfg(any(test, feature = "test-support"))]
                crate::muc::maybe_pause_muc_authorization_for_test("room_items_snapshot").await;
                nicks = sqlx::query_scalar(
                    "SELECT nick FROM cluster_muc_occupancies WHERE room_id=$1 AND room_epoch=$2
                      AND state IN ('active','suspended') AND lease_until > transaction_timestamp()
                      ORDER BY nick COLLATE \"C\"",
                )
                .bind(room.id)
                .bind(room.room_epoch)
                .fetch_all(&mut *transaction)
                .await?;
            }
            MucRoomViewKind::Registration if !room.allow_registration => {}
            MucRoomViewKind::Registration | MucRoomViewKind::ReservedNick => {
                if kind == MucRoomViewKind::Registration {
                    #[cfg(any(test, feature = "test-support"))]
                    crate::muc::maybe_pause_muc_authorization_for_test("registration_snapshot")
                        .await;
                }
                if let Some(principal) = viewer.principal {
                    reserved_nick =
                        affiliation_and_reservation(&mut transaction, room.id, principal)
                            .await?
                            .1;
                }
            }
            MucRoomViewKind::Info {
                include_mirror: true,
            } => {
                mirror_linked = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM mix_muc_mirrors mm
                      JOIN mix_channels channel ON channel.id=mm.mix_channel_id
                     WHERE mm.muc_room_id=$1 AND channel.localpart=$2)",
                )
                .bind(room.id)
                .bind(&room.localpart)
                .fetch_one(&mut *transaction)
                .await?;
            }
            MucRoomViewKind::Info {
                include_mirror: false,
            } => {}
        }
        transaction.commit().await?;
        Ok(MucRoomView::Found {
            room: Box::new(view),
            reserved_nick,
            mirror_linked,
            nicks,
        })
    }

    async fn owner_form(
        &self,
        localpart: &str,
        viewer: MucManagementViewer<'_>,
        local_domain: &str,
    ) -> Result<MucAdminSnapshot<MucRoomRead>> {
        let mut transaction = begin_read(&self.pool).await?;
        #[cfg(any(test, feature = "test-support"))]
        crate::muc::maybe_pause_muc_authorization_for_test("owner_form_snapshot").await;
        let Some(view) = read_muc_room(&mut *transaction, localpart).await? else {
            return Ok(MucAdminSnapshot::Stale);
        };
        if view.configuration_expired {
            return Ok(MucAdminSnapshot::Stale);
        }
        let federated = matches!(viewer.principal, MucReadPrincipal::Federated { .. });
        if !visible(&view, Some(viewer.full_jid), federated) {
            return Ok(if federated {
                MucAdminSnapshot::Stale
            } else {
                MucAdminSnapshot::Unauthorized
            });
        }
        let authorized = management_authority(&mut transaction, &view.room, viewer, local_domain)
            .await?
            .is_some_and(|(affiliation, _)| affiliation == "owner");
        transaction.commit().await?;
        Ok(if authorized {
            MucAdminSnapshot::Authorized(view)
        } else {
            MucAdminSnapshot::Unauthorized
        })
    }

    async fn admin_list(
        &self,
        localpart: &str,
        viewer: MucManagementViewer<'_>,
        local_domain: &str,
        kind: MucAdminListKind<'_>,
    ) -> Result<MucAdminSnapshot<MucAdminList>> {
        let mut transaction = begin_read(&self.pool).await?;
        #[cfg(any(test, feature = "test-support"))]
        if matches!(viewer.principal, MucReadPrincipal::Federated { .. }) {
            crate::muc::maybe_pause_muc_authorization_for_test("federated_admin_snapshot").await;
        }
        let Some(view) = read_muc_room(&mut *transaction, localpart).await? else {
            return Ok(MucAdminSnapshot::Stale);
        };
        let federated = matches!(viewer.principal, MucReadPrincipal::Federated { .. });
        if (federated && !visible(&view, Some(viewer.full_jid), true))
            || (!federated && view.room.is_locked() && !matches!(kind, MucAdminListKind::Invalid))
        {
            return Ok(MucAdminSnapshot::Stale);
        }
        if !federated && matches!(kind, MucAdminListKind::Invalid) {
            return Ok(MucAdminSnapshot::Authorized(MucAdminList::Invalid));
        }
        let room = &view.room;
        let Some((affiliation, role)) =
            management_authority(&mut transaction, room, viewer, local_domain).await?
        else {
            return Ok(MucAdminSnapshot::Unauthorized);
        };
        let list = match kind {
            MucAdminListKind::Invalid => MucAdminList::Invalid,
            MucAdminListKind::Role(requested)
                if affiliation != "outcast"
                    && (role == "moderator"
                        || matches!(affiliation.as_str(), "owner" | "admin")) =>
            {
                MucAdminList::Roles(
                    crate::muc::MucAdminRoleList {
                        requester_role: role,
                        non_anonymous: room.non_anonymous,
                        entries: role_entries(
                            &mut transaction,
                            room.id,
                            room.room_epoch,
                            requested,
                        )
                        .await?,
                    }
                    .into(),
                )
            }
            MucAdminListKind::Affiliation(requested)
                if affiliation_list_allowed(
                    &affiliation,
                    requested,
                    room.members_only,
                    room.non_anonymous,
                ) =>
            {
                MucAdminList::Affiliations(
                    affiliation_entries(&mut transaction, room.id, requested, local_domain)
                        .await?
                        .into_iter()
                        .map(|entry| MucAdminAffiliationEntry {
                            bare_jid: entry.bare_jid,
                            affiliation: entry.affiliation,
                        })
                        .collect(),
                )
            }
            _ => return Ok(MucAdminSnapshot::Unauthorized),
        };
        transaction.commit().await?;
        Ok(MucAdminSnapshot::Authorized(list))
    }

    async fn occupant_iq(
        &self,
        localpart: &str,
        sender: Option<MucOccupancyProof<'_>>,
        target_nick: &str,
        node_id: &str,
        federated_viewer: Option<&str>,
    ) -> Result<MucOccupantIqView> {
        let sender = sender.filter(|proof| proof.route.is_exact());
        let row = sqlx::query(AssertSqlSafe(format!(
            "WITH room AS ({LIVE_MUC_ROOM})
             SELECT EXISTS({EXACT_ACTIVE_ACTOR}) AS sender_proved,
                    target.nick,target.full_jid,target.connection_uuid,target.occupant_incarnation
               FROM room LEFT JOIN cluster_muc_occupancies AS target
                 ON target.room_id=room.id AND target.room_epoch=room.room_epoch
                AND target.nick=$8 AND target.owner_node_id=$9
                AND target.state IN ('active','suspended') AND target.lease_until > transaction_timestamp()
              WHERE $10::text IS NULL OR room.configuration_state='active'
                 OR (room.configuration_owner_jid=$10 AND NOT room.configuration_expired)"
        )))
        .bind(localpart)
        .bind(sender.map(|proof| proof.route.cluster_epoch))
        .bind(sender.map(|proof| proof.route.connection_id))
        .bind(sender.map(|proof| proof.route.full_jid.as_str()))
        .bind(sender.map(|proof| proof.route.nick.as_str()))
        .bind(sender.map(|proof| proof.node_id))
        .bind(sender.and_then(|proof| proof.authenticated_domain))
        .bind(target_nick)
        .bind(node_id)
        .bind(federated_viewer)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(MucOccupantIqView {
                room_visible: false,
                sender: None,
                target: None,
            });
        };
        let sender = sender
            .filter(|_| row.get("sender_proved"))
            .map(|proof| proof.route.clone());
        let target = row
            .get::<Option<String>, _>("nick")
            .map(|nick| MucOccupantRoute {
                nick,
                full_jid: row.get("full_jid"),
                connection_id: row.get("connection_uuid"),
                cluster_epoch: row.get("occupant_incarnation"),
            });
        Ok(MucOccupantIqView {
            room_visible: true,
            sender,
            target,
        })
    }

    async fn refresh_muc_occupant_activity(
        &self,
        localpart: &str,
        proof: MucOccupancyProof<'_>,
    ) -> Result<Option<MucOccupantRoute>> {
        if !proof.route.is_exact() {
            return Ok(None);
        }
        let refreshed: Option<bool> = sqlx::query_scalar(
            "UPDATE cluster_muc_occupancies AS occupant
                SET lease_until=clock_timestamp() + interval '90 seconds', updated_at=clock_timestamp()
               FROM muc_rooms AS room
              WHERE room.localpart=$1 AND room.destroyed_at IS NULL
                AND room.id=occupant.room_id AND room.room_epoch=occupant.room_epoch
                AND occupant.occupant_incarnation=$2 AND occupant.connection_uuid=$3
                AND occupant.full_jid=$4 AND occupant.nick=$5 AND occupant.owner_node_id=$6
                AND occupant.authenticated_domain IS NOT DISTINCT FROM $7::text
                AND occupant.state='active' AND occupant.lease_until > clock_timestamp()
                AND ($7::text IS NULL OR room.configuration_state='active'
                    OR (room.configuration_owner_jid=$4 AND room.configuration_expires_at > clock_timestamp()))
              RETURNING true",
        )
        .bind(localpart)
        .bind(proof.route.cluster_epoch)
        .bind(proof.route.connection_id)
        .bind(&proof.route.full_jid)
        .bind(&proof.route.nick)
        .bind(proof.node_id)
        .bind(proof.authenticated_domain)
        .fetch_optional(&self.pool)
        .await?;
        Ok(refreshed.map(|_| proof.route.clone()))
    }
}
