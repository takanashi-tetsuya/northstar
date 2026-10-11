//! MIX MAM archive queries and boundaries.

use super::*;

pub(super) async fn mix_mam_blocked_patterns(
    transaction: &mut Transaction<'_, Postgres>,
    viewer_id: Option<Uuid>,
) -> Result<Vec<MamBlockedPattern>> {
    let Some(viewer_id) = viewer_id else {
        return Ok(Vec::new());
    };
    let patterns = sqlx::query_scalar::<_, String>(
        "SELECT blocked_jid FROM blocked_jids WHERE owner_id=$1 ORDER BY blocked_jid",
    )
    .bind(viewer_id)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(classify_mam_blocked_jids(
        patterns,
        MamBlockedIdentitySource::BarePublisher,
    ))
}

pub(super) fn push_mix_mam_archive_base(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    channel_id: Uuid,
    blocked_patterns: &[MamBlockedPattern],
) {
    query_builder
        .push(" WHERE channel_id = ")
        .push_bind(channel_id)
        .push(" AND node = ")
        .push_bind(NODE_MESSAGES);
    for pattern in blocked_patterns {
        match pattern {
            MamBlockedPattern::Full(_) => {}
            MamBlockedPattern::Bare(value) => {
                query_builder
                    .push(" AND publisher_jid <> ")
                    .push_bind(value.clone());
            }
            MamBlockedPattern::Domain(value) => {
                query_builder
                    .push(" AND CASE WHEN position('@' in publisher_jid) > 0 THEN split_part(publisher_jid, '@', 2) ELSE publisher_jid END <> ")
                    .push_bind(value.clone());
            }
        }
    }
}

pub(super) fn push_mix_mam_scope(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    channel_id: Uuid,
    query: &super::super::MamArchiveQuery,
    blocked_patterns: &[MamBlockedPattern],
    after_point: Option<(DateTime<Utc>, Uuid)>,
    before_point: Option<(DateTime<Utc>, Uuid)>,
) {
    push_mix_mam_archive_base(query_builder, channel_id, blocked_patterns);
    if let Some(with_jid) = &query.with_jid {
        query_builder
            .push(" AND publisher_jid = ")
            .push_bind(with_jid.clone());
    }
    if let Some(start) = query.start {
        query_builder.push(" AND created_at >= ").push_bind(start);
    }
    if let Some(end) = query.end {
        query_builder.push(" AND created_at <= ").push_bind(end);
    }
    if let Some((created_at, id)) = after_point {
        query_builder
            .push(" AND (created_at, authoritative_id) > (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    if let Some((created_at, id)) = before_point {
        query_builder
            .push(" AND (created_at, authoritative_id) < (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    if !query.ids.is_empty() {
        query_builder
            .push(" AND authoritative_id = ANY(")
            .push_bind(query.ids.clone())
            .push(")");
    }
}

/// Query a MIX channel's mandatory messages archive using one repeatable-read
/// snapshot. Cursor validation, the result count, page rows and first index
/// therefore cannot disagree if retention runs concurrently.
pub(super) async fn mix_mam_page_for(
    pool: &PgPool,
    channel_id: Uuid,
    viewer_id: Option<Uuid>,
    actor: Option<&str>,
    query: &super::super::MamArchiveQuery,
) -> Result<MixReadOutcome<MixMamPage>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    if let Some(actor) = actor {
        match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, NODE_MESSAGES).await?
        {
            MixReadOutcome::Found(channel) => {
                if !mix_mam_peer_filter_allowed(&channel.jid_visibility, query.with_jid.is_some()) {
                    transaction.rollback().await?;
                    return Ok(MixReadOutcome::Unauthorized);
                }
            }
            MixReadOutcome::Unauthorized => {
                transaction.rollback().await?;
                return Ok(MixReadOutcome::Unauthorized);
            }
            MixReadOutcome::NotFound => {
                transaction.rollback().await?;
                return Ok(MixReadOutcome::NotFound);
            }
        }
    }
    let blocked_patterns = mix_mam_blocked_patterns(&mut transaction, viewer_id).await?;

    // Item IDs must match the form filters. Form/RSM cursors need only be
    // visible in the channel's base scope, independently of those filters.
    let requested_ids = query
        .ids
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !requested_ids.is_empty() {
        let mut builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM mix_events");
        push_mix_mam_scope(
            &mut builder,
            channel_id,
            query,
            &blocked_patterns,
            None,
            None,
        );
        builder
            .push(" AND authoritative_id = ANY(")
            .push_bind(requested_ids.clone())
            .push(")");
        let found: i64 = builder
            .build_query_scalar()
            .fetch_one(&mut *transaction)
            .await?;
        if found != requested_ids.len() as i64 {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }
    let referenced_ids = mam_referenced_ids(query);
    let mut visible_points = std::collections::HashMap::with_capacity(referenced_ids.len());
    if !referenced_ids.is_empty() {
        let mut builder =
            QueryBuilder::<Postgres>::new("SELECT authoritative_id, created_at FROM mix_events");
        push_mix_mam_archive_base(&mut builder, channel_id, &blocked_patterns);
        builder
            .push(" AND authoritative_id = ANY(")
            .push_bind(referenced_ids)
            .push(")");
        for row in builder.build().fetch_all(&mut *transaction).await? {
            visible_points.insert(row.try_get("authoritative_id")?, row.try_get("created_at")?);
        }
    }
    let Some(resolved) = resolve_mam_query(query, &visible_points) else {
        transaction.rollback().await?;
        return Ok(MixReadOutcome::NotFound);
    };
    let form_after = resolved.plan.count_bounds.after;
    let form_before = resolved.plan.count_bounds.before;

    let mut count_builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM mix_events");
    push_mix_mam_scope(
        &mut count_builder,
        channel_id,
        query,
        &blocked_patterns,
        form_after,
        form_before,
    );
    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(&mut *transaction)
        .await?;

    let max = query.max.clamp(0, MAX_MAM_PAGE_SIZE);
    let window = resolved.plan.page_window(resolved.page, max);
    let mut page_builder = QueryBuilder::<Postgres>::new(
        "SELECT authoritative_id AS id, item_id, payload, created_at FROM mix_events",
    );
    push_mix_mam_scope(
        &mut page_builder,
        channel_id,
        query,
        &blocked_patterns,
        window.after,
        window.before,
    );
    page_builder.push(if window.descending {
        " ORDER BY created_at DESC, authoritative_id DESC LIMIT "
    } else {
        " ORDER BY created_at ASC, authoritative_id ASC LIMIT "
    });
    page_builder.push_bind(window.fetch_limit);
    if let Some(index) = window.offset {
        page_builder.push(" OFFSET ").push_bind(index);
    }
    let rows = page_builder.build().fetch_all(&mut *transaction).await?;
    let (events, complete) = finish_mam_page(
        rows.iter()
            .map(|row| MixEvent {
                id: row.get("id"),
                item_id: row.get("item_id"),
                payload: row.get("payload"),
                created_at: row.get("created_at"),
            })
            .collect(),
        max,
        window.descending,
    );

    let first_index = if let Some(first) = events.first() {
        let mut index_builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM mix_events");
        push_mix_mam_scope(
            &mut index_builder,
            channel_id,
            query,
            &blocked_patterns,
            form_after,
            form_before,
        );
        index_builder
            .push(" AND (created_at, authoritative_id) < (")
            .push_bind(first.created_at)
            .push(", ")
            .push_bind(first.id)
            .push(")");
        index_builder
            .build_query_scalar()
            .fetch_one(&mut *transaction)
            .await?
    } else {
        0
    };
    transaction.commit().await?;
    Ok(MixReadOutcome::Found(MixMamPage {
        events,
        total,
        first_index,
        complete,
    }))
}

#[cfg(test)]
pub async fn mix_mam_page(
    pool: &PgPool,
    channel_id: Uuid,
    query: &super::super::MamArchiveQuery,
) -> Result<Option<MixMamPage>> {
    Ok(
        match mix_mam_page_for(pool, channel_id, None, None, query).await? {
            MixReadOutcome::Found(page) => Some(page),
            MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => None,
        },
    )
}

#[cfg(test)]
pub async fn mix_mam_page_visible(
    pool: &PgPool,
    channel_id: Uuid,
    viewer_id: Uuid,
    query: &super::super::MamArchiveQuery,
) -> Result<Option<MixMamPage>> {
    Ok(
        match mix_mam_page_for(pool, channel_id, Some(viewer_id), None, query).await? {
            MixReadOutcome::Found(page) => Some(page),
            MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => None,
        },
    )
}

pub async fn authorized_mix_mam_page(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    viewer_id: Option<Uuid>,
    query: &super::super::MamArchiveQuery,
) -> Result<MixReadOutcome<MixMamPage>> {
    mix_mam_page_for(pool, channel_id, viewer_id, Some(actor), query).await
}

#[cfg(test)]
pub async fn mix_mam_boundaries(
    pool: &PgPool,
    channel_id: Uuid,
) -> Result<(
    Option<super::super::ArchiveBoundary>,
    Option<super::super::ArchiveBoundary>,
)> {
    let first = sqlx::query(
        "SELECT authoritative_id AS id, created_at FROM mix_events
         WHERE channel_id = $1 AND node = $2
         ORDER BY created_at ASC, authoritative_id ASC LIMIT 1",
    )
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .fetch_optional(pool)
    .await?;
    let last = sqlx::query(
        "SELECT authoritative_id AS id, created_at FROM mix_events
         WHERE channel_id = $1 AND node = $2
         ORDER BY created_at DESC, authoritative_id DESC LIMIT 1",
    )
    .bind(channel_id)
    .bind(NODE_MESSAGES)
    .fetch_optional(pool)
    .await?;
    let convert = |row: sqlx::postgres::PgRow| super::super::ArchiveBoundary {
        id: row.get("id"),
        created_at: row.get("created_at"),
    };
    Ok((first.map(convert), last.map(convert)))
}

pub async fn authorized_mix_mam_boundaries(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    viewer_id: Option<Uuid>,
) -> Result<
    MixReadOutcome<(
        Option<super::super::ArchiveBoundary>,
        Option<super::super::ArchiveBoundary>,
    )>,
> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    match authorize_mix_node_read_tx(&mut transaction, channel_id, actor, NODE_MESSAGES).await? {
        MixReadOutcome::Found(_) => {}
        MixReadOutcome::Unauthorized => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::Unauthorized);
        }
        MixReadOutcome::NotFound => {
            transaction.rollback().await?;
            return Ok(MixReadOutcome::NotFound);
        }
    }
    let blocked_patterns = mix_mam_blocked_patterns(&mut transaction, viewer_id).await?;
    let mut first_builder =
        QueryBuilder::<Postgres>::new("SELECT authoritative_id AS id,created_at FROM mix_events");
    push_mix_mam_archive_base(&mut first_builder, channel_id, &blocked_patterns);
    first_builder.push(" ORDER BY created_at ASC,authoritative_id ASC LIMIT 1");
    let first = first_builder
        .build()
        .fetch_optional(&mut *transaction)
        .await?;
    let mut last_builder =
        QueryBuilder::<Postgres>::new("SELECT authoritative_id AS id,created_at FROM mix_events");
    push_mix_mam_archive_base(&mut last_builder, channel_id, &blocked_patterns);
    last_builder.push(" ORDER BY created_at DESC,authoritative_id DESC LIMIT 1");
    let last = last_builder
        .build()
        .fetch_optional(&mut *transaction)
        .await?;
    let convert = |row: sqlx::postgres::PgRow| super::super::ArchiveBoundary {
        id: row.get("id"),
        created_at: row.get("created_at"),
    };
    transaction.commit().await?;
    Ok(MixReadOutcome::Found((
        first.map(convert),
        last.map(convert),
    )))
}
