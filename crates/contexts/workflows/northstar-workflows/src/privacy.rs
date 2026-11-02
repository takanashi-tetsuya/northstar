//! The privacy check of a session that the session context's tables identify. It reads the session through an SQL
//! function of the session context, so it cannot live in the roster adapter.

use anyhow::Result;
use northstar_roster_postgres::privacy::{privacy_denies, PrivacyStanzaKind};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub async fn privacy_denies_for_sm_session(
    pool: &PgPool,
    session_id: Uuid,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<Option<bool>> {
    let row = sqlx::query("SELECT * FROM northstar_sm_privacy_state($1)")
        .bind(session_id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let user_id: Uuid = row.get("user_id");
    let active: Option<String> = row.get("active_privacy_list");
    privacy_denies(pool, user_id, active.as_deref(), candidate, kind)
        .await
        .map(Some)
}
