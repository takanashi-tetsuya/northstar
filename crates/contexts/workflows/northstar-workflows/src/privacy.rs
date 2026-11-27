//! The privacy check of a session that the session context's tables identify. It reads the session through an SQL
//! function of the session context, so it cannot live in the roster adapter.

use anyhow::Result;
use northstar_roster_postgres::privacy::{privacy_denies_in_snapshot, PrivacyStanzaKind};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

async fn sm_privacy_state(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<Option<(Uuid, Option<String>)>> {
    Ok(
        sqlx::query_as("SELECT * FROM northstar_sm_privacy_state($1)")
            .bind(session_id)
            .fetch_optional(&mut **tx)
            .await?,
    )
}

pub(crate) async fn sm_privacy_state_exists(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<bool> {
    Ok(sm_privacy_state(tx, session_id).await?.is_some())
}

pub async fn privacy_denies_for_sm_session(
    pool: &PgPool,
    session_id: Uuid,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<Option<bool>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await?;
    let denied = match sm_privacy_state(&mut tx, session_id).await? {
        Some((user_id, active)) => {
            privacy_denies_in_snapshot(&mut tx, user_id, active.as_deref(), candidate, kind).await?
        }
        None => true,
    };
    tx.commit().await?;
    Ok(Some(denied))
}
