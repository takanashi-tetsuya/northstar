use super::WorkflowRosterEffects;
use anyhow::Result;
use northstar_roster_core::RosterGap;
use northstar_roster_postgres::roster::RosterGapAnnotationProof;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

impl RosterGapAnnotationProof for WorkflowRosterEffects {
    async fn annotations_proven(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        gap: RosterGap,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT NOT EXISTS (
                SELECT 1 FROM roster_change_log log JOIN mix_pam_memberships pam
                  ON pam.user_id=log.owner_id AND pam.channel_jid=log.contact_jid
                WHERE log.owner_id=$1 AND log.version>$2 AND log.version<=$3 AND NOT log.removed
                  AND (pam.xmin <> log.xmin OR pam.updated_at <> log.changed_at)
             )",
        )
        .bind(owner_id)
        .bind(gap.after.0)
        .bind(gap.through.0)
        .fetch_one(&mut **transaction)
        .await?)
    }
}
