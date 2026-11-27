use super::list_commands::{
    commit_list_removal, remove_list_in_transaction, replace_list_in_transaction,
    set_default_in_transaction, validate_replacement, RemovePrivacyListOutcome,
    ReplacePrivacyListOutcome,
};
use super::query::{read_privacy_list, read_privacy_overview, stored_list_name};
use super::PostgresPrivacyRepository;
use anyhow::Result;
use northstar_roster_application::privacy::commands::{
    ActorOutcome, PolicyCommandRepository, PrivacyListName, PrivacyOverviewSnapshot, TopologyProof,
    TopologyResource,
};
use northstar_roster_application::privacy::{
    PrivacyItem, PrivacyListMutationOutcome, PrivacySelectionOutcome,
};
use northstar_roster_core::RosterActor;
use sqlx::{Postgres, Row, Transaction};

impl PolicyCommandRepository for PostgresPrivacyRepository {
    async fn read_privacy_overview(
        &self,
        actor: &RosterActor,
    ) -> Result<ActorOutcome<PrivacyOverviewSnapshot>> {
        read_privacy_overview(&self.pool, actor).await
    }

    async fn read_privacy_list(
        &self,
        actor: &RosterActor,
        name: &PrivacyListName,
    ) -> Result<ActorOutcome<Option<Vec<PrivacyItem>>>> {
        read_privacy_list(&self.pool, actor, name).await
    }

    async fn read_blocklist(&self, actor: &RosterActor) -> Result<ActorOutcome<Vec<String>>> {
        let rows = sqlx::query_scalar::<_, Option<String>>(
            "SELECT blocked.blocked_jid FROM users owner \
             LEFT JOIN blocked_jids blocked ON blocked.owner_id=owner.id \
             WHERE owner.id=$1 AND NOT owner.is_disabled AND owner.auth_generation=$2 \
             ORDER BY blocked.blocked_jid",
        )
        .bind(actor.account_id)
        .bind(actor.auth_generation)
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(ActorOutcome::Stale);
        }
        Ok(ActorOutcome::Current(rows.into_iter().flatten().collect()))
    }

    async fn replace_privacy_list(
        &self,
        actor: &RosterActor,
        name: &PrivacyListName,
        items: &[PrivacyItem],
    ) -> Result<ActorOutcome<PrivacyListMutationOutcome>> {
        let mut tx = self.pool.begin().await?;
        if !lock_actor(&mut tx, actor).await? {
            tx.rollback().await?;
            return Ok(ActorOutcome::Stale);
        }
        validate_replacement(items)?;
        let outcome =
            replace_list_in_transaction(&mut tx, actor.account_id, name.as_str(), items).await?;
        Ok(ActorOutcome::Current(match outcome {
            ReplacePrivacyListOutcome::Stored => {
                tx.commit().await?;
                PrivacyListMutationOutcome::Stored
            }
            ReplacePrivacyListOutcome::TooManyLists => {
                tx.rollback().await?;
                PrivacyListMutationOutcome::QuotaExceeded
            }
        }))
    }

    async fn select_default_privacy_list(
        &self,
        actor: &RosterActor,
        name: Option<&PrivacyListName>,
    ) -> Result<ActorOutcome<(PrivacySelectionOutcome, TopologyProof)>> {
        let mut tx = self.pool.begin().await?;
        if !lock_actor(&mut tx, actor).await? {
            tx.rollback().await?;
            return Ok(ActorOutcome::Stale);
        }
        let proof = read_topology(&mut tx, actor).await?;
        let outcome = if !proof.other_resources.is_empty() {
            tx.rollback().await?;
            PrivacySelectionOutcome::Conflict
        } else if set_default_in_transaction(
            &mut tx,
            actor.account_id,
            name.map(PrivacyListName::as_str),
        )
        .await?
        {
            tx.commit().await?;
            PrivacySelectionOutcome::Updated
        } else {
            tx.rollback().await?;
            PrivacySelectionOutcome::Missing
        };
        Ok(ActorOutcome::Current((outcome, proof)))
    }

    async fn remove_privacy_list(
        &self,
        actor: &RosterActor,
        name: &PrivacyListName,
    ) -> Result<ActorOutcome<(PrivacyListMutationOutcome, TopologyProof)>> {
        let mut tx = self.pool.begin().await?;
        if !lock_actor(&mut tx, actor).await? {
            tx.rollback().await?;
            return Ok(ActorOutcome::Stale);
        }
        let proof = read_topology(&mut tx, actor).await?;
        let outcome = if proof
            .other_resources
            .iter()
            .any(|resource| resource.effective_list.as_ref() == Some(name))
        {
            RemovePrivacyListOutcome::Conflict
        } else {
            remove_list_in_transaction(&mut tx, actor.account_id, name.as_str()).await?
        };
        let outcome = if outcome == RemovePrivacyListOutcome::Conflict {
            tx.rollback().await?;
            outcome
        } else if commit_list_removal(tx).await? {
            outcome
        } else {
            RemovePrivacyListOutcome::Conflict
        };
        let outcome = match outcome {
            RemovePrivacyListOutcome::Conflict => PrivacyListMutationOutcome::Conflict,
            RemovePrivacyListOutcome::Removed => PrivacyListMutationOutcome::Removed,
            RemovePrivacyListOutcome::Missing => PrivacyListMutationOutcome::Missing,
        };
        Ok(ActorOutcome::Current((outcome, proof)))
    }
}

async fn lock_actor(tx: &mut Transaction<'_, Postgres>, actor: &RosterActor) -> Result<bool> {
    let owner: Option<(i64, bool)> = sqlx::query_as(
        "SELECT auth_generation, is_disabled FROM northstar_lock_user_rows_update(ARRAY[$1::uuid])",
    )
    .bind(actor.account_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(owner == Some((actor.auth_generation, false)))
}

async fn read_topology(
    tx: &mut Transaction<'_, Postgres>,
    actor: &RosterActor,
) -> Result<TopologyProof> {
    // Reservations take a conflicting owner lock before inserting a lease.
    // Read the rows without locking them: publication and SM handoff can
    // update a lease, and release can delete it, but all live rows count.
    let rows = sqlx::query(
        "WITH sampled AS MATERIALIZED (SELECT clock_timestamp() AS instant) \
         SELECT lease.connection_id, COALESCE(active.list_name, defaults.list_name) AS effective_list \
         FROM deployment_session_leases lease CROSS JOIN sampled \
         LEFT JOIN privacy_active_sessions active ON active.owner_id=lease.user_id \
             AND active.connection_id=lease.connection_id AND active.expires_at>sampled.instant \
         LEFT JOIN privacy_default_lists defaults ON defaults.owner_id=lease.user_id \
         WHERE lease.user_id=$1 AND lease.connection_id<>$2 AND lease.lease_until>sampled.instant \
         ORDER BY lease.connection_id",
    )
    .bind(actor.account_id)
    .bind(actor.connection_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut other_resources = Vec::with_capacity(rows.len());
    for row in &rows {
        other_resources.push(TopologyResource {
            connection_id: row.try_get("connection_id")?,
            effective_list: stored_list_name(row, "effective_list")?,
        });
    }
    Ok(TopologyProof { other_resources })
}
