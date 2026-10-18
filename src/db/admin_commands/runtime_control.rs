//! Persists service messages, runtime policy projections, and scheduled service controls.

use super::*;

pub async fn set_admin_service_message_command(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    kind: &str,
    body: Option<&str>,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(kind, "motd" | "welcome"),
        "invalid service message kind"
    );
    Ok(sqlx::query_scalar(
        "SELECT northstar_admin_command_set_service_message(
          $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(kind)
    .bind(body)
    .bind(fence.result_payload)
    .fetch_one(pool)
    .await?)
}

pub async fn record_admin_announcement_command(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    recipients: usize,
    bytes: usize,
) -> Result<bool> {
    let recipients = i32::try_from(recipients).context("announcement recipient count overflow")?;
    let bytes = i32::try_from(bytes).context("announcement size overflow")?;
    Ok(sqlx::query_scalar(
        "SELECT northstar_admin_command_record_announcement(
          $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(recipients)
    .bind(bytes)
    .bind(fence.result_payload)
    .fetch_one(pool)
    .await?)
}

/// Lease service messages for one account.  A socket/process failure before
/// enqueue confirmation leaves an expiring lease rather than a false
/// delivered marker, so a later initial presence can retry.  Completion is a
/// separate connection-incarnation-bound update below; delivery is therefore
/// at-least-once across the unavoidable queue/DB crash boundary.
pub async fn claim_admin_service_messages(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<ClaimedAdminServiceMessage>> {
    let mut tx = pool.begin().await?;
    let rows = sqlx::query("SELECT kind,body,revision FROM admin_service_messages ORDER BY kind")
        .fetch_all(&mut *tx)
        .await?;
    let mut claimed = Vec::new();
    let delivery_date: chrono::NaiveDate = sqlx::query_scalar("SELECT CURRENT_DATE")
        .fetch_one(&mut *tx)
        .await?;
    for row in rows {
        let kind: String = row.get("kind");
        let body: String = row.get("body");
        let revision: Uuid = row.get("revision");
        let message_date = if kind == "motd" {
            delivery_date
        } else {
            chrono::NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("fixed welcome delivery date is valid")
        };
        let claim_id = Uuid::new_v4();
        let leased = if kind == "welcome" {
            // The partial welcome index intentionally means once per account,
            // not once per edited revision.  Only an expired, never-completed
            // first delivery may be reclaimed.
            let existing = sqlx::query(
                "SELECT delivered_at IS NULL
                        AND claim_expires_at <= clock_timestamp() AS claimable
                 FROM admin_service_message_deliveries
                 WHERE kind='welcome' AND user_id=$1 FOR UPDATE",
            )
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
            match existing {
                None => {
                    sqlx::query(
                        "INSERT INTO admin_service_message_deliveries
                         (kind,revision,user_id,delivery_date,delivered_at,claim_id,claim_expires_at)
                         VALUES('welcome',$1,$2,$3,NULL,$4,clock_timestamp()+INTERVAL '30 seconds')",
                    )
                    .bind(revision)
                    .bind(user_id)
                    .bind(message_date)
                    .bind(claim_id)
                    .execute(&mut *tx)
                    .await?;
                    true
                }
                Some(existing) if existing.get::<bool, _>("claimable") => {
                    sqlx::query(
                        "UPDATE admin_service_message_deliveries
                         SET revision=$2,claim_id=$3,
                             claim_expires_at=clock_timestamp()+INTERVAL '30 seconds'
                         WHERE kind='welcome' AND user_id=$1",
                    )
                    .bind(user_id)
                    .bind(revision)
                    .bind(claim_id)
                    .execute(&mut *tx)
                    .await?;
                    true
                }
                _ => false,
            }
        } else {
            sqlx::query(
                "INSERT INTO admin_service_message_deliveries
                 (kind,revision,user_id,delivery_date,delivered_at,claim_id,claim_expires_at)
                 VALUES($1,$2,$3,$4,NULL,$5,clock_timestamp()+INTERVAL '30 seconds')
                 ON CONFLICT(kind,revision,user_id,delivery_date) DO UPDATE
                 SET claim_id=EXCLUDED.claim_id,
                     claim_expires_at=clock_timestamp()+INTERVAL '30 seconds'
                 WHERE admin_service_message_deliveries.delivered_at IS NULL
                   AND admin_service_message_deliveries.claim_expires_at <= clock_timestamp()
                 RETURNING TRUE",
            )
            .bind(&kind)
            .bind(revision)
            .bind(user_id)
            .bind(message_date)
            .bind(claim_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some()
        };
        if leased {
            claimed.push(ClaimedAdminServiceMessage {
                kind,
                body,
                revision,
                delivery_date: message_date,
                claim_id,
            });
        }
    }
    // Keep the delivery ledger bounded without a table-wide blocking delete.
    sqlx::query(
        "DELETE FROM admin_service_message_deliveries WHERE (kind,revision,user_id,delivery_date) IN (
             SELECT kind,revision,user_id,delivery_date FROM admin_service_message_deliveries
             WHERE kind='motd'
               AND COALESCE(delivered_at,claim_expires_at) < clock_timestamp()-INTERVAL '90 days'
             ORDER BY COALESCE(delivered_at,claim_expires_at) LIMIT 1000
         )",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(claimed)
}

pub async fn complete_admin_service_message_claim(
    pool: &PgPool,
    user_id: Uuid,
    claim: &ClaimedAdminServiceMessage,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE admin_service_message_deliveries
         SET delivered_at=clock_timestamp(),claim_id=NULL,claim_expires_at=NULL
         WHERE kind=$1 AND revision=$2 AND user_id=$3 AND delivery_date=$4
           AND claim_id=$5 AND delivered_at IS NULL",
    )
    .bind(&claim.kind)
    .bind(claim.revision)
    .bind(user_id)
    .bind(claim.delivery_date)
    .bind(claim.claim_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub(super) fn federation_runtime_rules_from_rows(
    rows: Vec<sqlx::postgres::PgRow>,
) -> (Vec<String>, Vec<String>) {
    let mut blacklist = Vec::new();
    let mut whitelist = Vec::new();
    for row in rows {
        let kind: String = row.get("kind");
        let domain: String = row.get("domain");
        if kind == "blacklist" {
            blacklist.push(domain);
        } else {
            whitelist.push(domain);
        }
    }
    (blacklist, whitelist)
}

pub async fn federation_runtime_rules(pool: &PgPool) -> Result<(Vec<String>, Vec<String>)> {
    let rows = sqlx::query("SELECT kind,domain FROM federation_runtime_rules ORDER BY kind,domain")
        .fetch_all(pool)
        .await?;
    Ok(federation_runtime_rules_from_rows(rows))
}

pub async fn replace_federation_runtime_rules_command(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    kind: &str,
    domains: &[String],
) -> Result<Option<(Vec<String>, Vec<String>)>> {
    anyhow::ensure!(
        matches!(kind, "blacklist" | "whitelist"),
        "invalid rule kind"
    );
    anyhow::ensure!(domains.len() <= 1000, "too many federation rules");
    let row = sqlx::query(
        "SELECT blacklist,whitelist
           FROM northstar_admin_command_replace_federation_rules(
             $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(kind)
    .bind(domains)
    .bind(fence.result_payload)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| (row.get("blacklist"), row.get("whitelist"))))
}

/// PostgreSQL's clock anchors this process against future durable service
/// controls, independently of the host's wall clock.
pub async fn admin_service_control_startup_time(
    pool: &PgPool,
) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await?)
}

pub async fn initialize_admin_runtime_settings(
    pool: &PgPool,
    island_mode: bool,
    registration_closed: bool,
    registration_must_remain_closed: bool,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO admin_runtime_settings(key,enabled)
         VALUES('island_mode',$1),('registration_closed',$2)
         ON CONFLICT(key) DO UPDATE
            SET enabled=TRUE,
                revision=admin_runtime_settings.revision+1,
                updated_at=clock_timestamp()
          WHERE $3
            AND EXCLUDED.key='registration_closed'
            AND NOT admin_runtime_settings.enabled",
    )
    .bind(island_mode)
    .bind(registration_closed)
    .bind(registration_must_remain_closed)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(super) fn admin_runtime_settings_from_rows(
    rows: Vec<sqlx::postgres::PgRow>,
) -> Result<(bool, bool)> {
    let mut island_mode = None;
    let mut registration_closed = None;
    for row in rows {
        match row.get::<String, _>("key").as_str() {
            "island_mode" => island_mode = Some(row.get("enabled")),
            "registration_closed" => registration_closed = Some(row.get("enabled")),
            _ => {}
        }
    }
    Ok((
        island_mode.context("island_mode runtime setting is missing")?,
        registration_closed.context("registration_closed runtime setting is missing")?,
    ))
}

pub async fn admin_runtime_settings(pool: &PgPool) -> Result<(bool, bool)> {
    let rows = sqlx::query("SELECT key,enabled FROM admin_runtime_settings ORDER BY key")
        .fetch_all(pool)
        .await?;
    admin_runtime_settings_from_rows(rows)
}

/// Read the complete runtime control-plane projection over the caller's
/// already-reserved connection. This deliberately avoids a second pool
/// acquisition between administration and federation observations. One SQL
/// statement gives both projections the same MVCC snapshot and avoids a
/// second network/scheduler round trip on every policy refresh.
/// The observer records only which fixed read is in flight; it performs no I/O.
pub(crate) async fn runtime_control_snapshot(
    connection: &mut PgConnection,
    mut read_phase: impl FnMut(RuntimeControlReadPhase),
) -> Result<(bool, bool, Vec<String>, Vec<String>)> {
    read_phase(RuntimeControlReadPhase::Snapshot);
    let rows = sqlx::query(
        "SELECT key,enabled,NULL::text AS kind,NULL::text AS domain
           FROM admin_runtime_settings
         UNION ALL
         SELECT NULL::text,NULL::boolean,kind,domain FROM federation_runtime_rules
         ORDER BY key,kind,domain",
    )
    .fetch_all(&mut *connection)
    .await?;
    let (settings, rules): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|row| row.get::<Option<String>, _>("key").is_some());
    let (island_mode, registration_closed) = admin_runtime_settings_from_rows(settings)?;
    let (blacklist, whitelist) = federation_runtime_rules_from_rows(rules);
    Ok((island_mode, registration_closed, blacklist, whitelist))
}

pub async fn set_admin_runtime_setting_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    key: &str,
    enabled: bool,
    request_id: Option<Uuid>,
) -> Result<()> {
    anyhow::ensure!(
        matches!(key, "island_mode" | "registration_closed"),
        "invalid runtime setting"
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("northstar:admin-runtime-setting:{key}"))
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO admin_runtime_settings(key,enabled,updated_by)
         VALUES($1,$2,$3)
         ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled,
             revision=admin_runtime_settings.revision+1,
             updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()",
    )
    .bind(key)
    .bind(enabled)
    .bind(actor_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'admin.runtime_setting.set',$2,$3,$4)",
    )
    .bind(actor_id)
    .bind(key)
    .bind(serde_json::json!({"enabled":enabled,"source":"rest"}))
    .bind(request_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn apply_admin_service_control_command(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    action: &str,
    delay_seconds: i64,
    announcement: Option<&str>,
    cancel: bool,
) -> Result<Option<Uuid>> {
    let delay_seconds = i32::try_from(delay_seconds).context("service delay overflow")?;
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT northstar_admin_command_service_control(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(action)
    .bind(delay_seconds)
    .bind(announcement)
    .bind(cancel)
    .bind(fence.result_payload)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Return an active control generation, atomically advancing it to `fired`
/// when its PostgreSQL-clock deadline has arrived.  Every node polls this row;
/// only processes whose start time predates `fired_at` act on it.
pub async fn poll_admin_service_control(
    connection: &mut PgConnection,
) -> Result<Option<DurableServiceControl>> {
    tokio::time::timeout(SERVICE_CONTROL_POLL_TIMEOUT, async {
        let mut transaction = connection.begin().await?;
        sqlx::query("SELECT pg_catalog.set_config('lock_timeout',$1,TRUE)")
            .bind(SERVICE_CONTROL_LOCK_TIMEOUT)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SELECT pg_catalog.set_config('statement_timeout',$1,TRUE)")
            .bind(SERVICE_CONTROL_STATEMENT_TIMEOUT)
            .execute(&mut *transaction)
            .await?;
        let row = sqlx::query(
            "SELECT generation,action,execute_at,fired_at,expires_at
               FROM northstar_admin_service_control_poll()",
        )
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok::<_, anyhow::Error>(row.map(|row| service_control_from_row(&row)))
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "durable service-control poll exceeded {} ms",
            SERVICE_CONTROL_POLL_TIMEOUT.as_millis()
        )
    })?
}

pub(super) fn service_control_from_row(row: &sqlx::postgres::PgRow) -> DurableServiceControl {
    DurableServiceControl {
        generation: row.get("generation"),
        action: row.get("action"),
        execute_at: row.get("execute_at"),
        fired_at: row.get("fired_at"),
        expires_at: row.get("expires_at"),
    }
}
