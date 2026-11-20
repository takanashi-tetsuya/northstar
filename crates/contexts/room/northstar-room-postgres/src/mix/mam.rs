//! MIX MAM archive queries and boundaries.

use super::*;

async fn mix_mam_blocked_patterns(
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

fn push_mix_mam_archive_base(
    query_builder: &mut QueryBuilder<Postgres>,
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

fn push_mix_mam_scope(
    query_builder: &mut QueryBuilder<Postgres>,
    channel_id: Uuid,
    query: &northstar_archive_core::MamArchiveQuery,
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

fn push_mix_mam_reference_scope(
    builder: &mut QueryBuilder<Postgres>,
    channel_id: Uuid,
    blocked_patterns: &[MamBlockedPattern],
    referenced_ids: Vec<Uuid>,
) {
    push_mix_mam_archive_base(builder, channel_id, blocked_patterns);
    builder
        .push(" AND authoritative_id = ANY(")
        .push_bind(referenced_ids)
        .push(")");
}

pub(crate) async fn mix_mam_page_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    viewer_id: Option<Uuid>,
    query: &northstar_archive_core::MamArchiveQuery,
) -> Result<Option<MixMamPage>> {
    let blocked_patterns = mix_mam_blocked_patterns(transaction, viewer_id).await?;
    // Resolve requested IDs and cursors in the visible base before filtering.
    let referenced_ids = mam_referenced_ids(query);
    let mut visible_points = std::collections::HashMap::with_capacity(referenced_ids.len());
    if !referenced_ids.is_empty() {
        let mut builder =
            QueryBuilder::<Postgres>::new("SELECT authoritative_id, created_at FROM mix_events");
        push_mix_mam_reference_scope(&mut builder, channel_id, &blocked_patterns, referenced_ids);
        for row in builder.build().fetch_all(&mut **transaction).await? {
            visible_points.insert(row.try_get("authoritative_id")?, row.try_get("created_at")?);
        }
    }
    let Some(resolved) = resolve_mam_query(query, &visible_points) else {
        return Ok(None);
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
        .fetch_one(&mut **transaction)
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
    let rows = page_builder.build().fetch_all(&mut **transaction).await?;
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
            .fetch_one(&mut **transaction)
            .await?
    } else {
        0
    };
    Ok(Some(MixMamPage {
        events,
        total,
        first_index,
        complete,
    }))
}

pub(crate) async fn mix_mam_boundaries_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    viewer_id: Option<Uuid>,
) -> Result<(
    Option<northstar_archive_core::ArchiveBoundary>,
    Option<northstar_archive_core::ArchiveBoundary>,
)> {
    let blocked_patterns = mix_mam_blocked_patterns(transaction, viewer_id).await?;
    let mut first_builder =
        QueryBuilder::<Postgres>::new("SELECT authoritative_id AS id,created_at FROM mix_events");
    push_mix_mam_archive_base(&mut first_builder, channel_id, &blocked_patterns);
    first_builder.push(" ORDER BY created_at ASC,authoritative_id ASC LIMIT 1");
    let first = first_builder
        .build()
        .fetch_optional(&mut **transaction)
        .await?;
    let mut last_builder =
        QueryBuilder::<Postgres>::new("SELECT authoritative_id AS id,created_at FROM mix_events");
    push_mix_mam_archive_base(&mut last_builder, channel_id, &blocked_patterns);
    last_builder.push(" ORDER BY created_at DESC,authoritative_id DESC LIMIT 1");
    let last = last_builder
        .build()
        .fetch_optional(&mut **transaction)
        .await?;
    let convert = |row: sqlx::postgres::PgRow| northstar_archive_core::ArchiveBoundary {
        id: row.get("id"),
        created_at: row.get("created_at"),
    };
    Ok((first.map(convert), last.map(convert)))
}

#[cfg(any(test, feature = "test-support"))]
async fn mix_mam_test_snapshot(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn mix_mam_page(
    pool: &PgPool,
    channel_id: Uuid,
    query: &northstar_archive_core::MamArchiveQuery,
) -> Result<Option<MixMamPage>> {
    let mut transaction = mix_mam_test_snapshot(pool).await?;
    let page = mix_mam_page_tx(&mut transaction, channel_id, None, query).await?;
    transaction.commit().await?;
    Ok(page)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn mix_mam_page_visible(
    pool: &PgPool,
    channel_id: Uuid,
    viewer_id: Uuid,
    query: &northstar_archive_core::MamArchiveQuery,
) -> Result<Option<MixMamPage>> {
    let mut transaction = mix_mam_test_snapshot(pool).await?;
    let page = mix_mam_page_tx(&mut transaction, channel_id, Some(viewer_id), query).await?;
    transaction.commit().await?;
    Ok(page)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn mix_mam_boundaries(
    pool: &PgPool,
    channel_id: Uuid,
) -> Result<(
    Option<northstar_archive_core::ArchiveBoundary>,
    Option<northstar_archive_core::ArchiveBoundary>,
)> {
    let mut transaction = mix_mam_test_snapshot(pool).await?;
    let boundaries = mix_mam_boundaries_tx(&mut transaction, channel_id, None).await?;
    transaction.commit().await?;
    Ok(boundaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_archive_core::{MamArchiveQuery, MamRsmPage};

    #[test]
    fn mix_mam_reference_scope_applies_blocks_before_form_filters() {
        let channel_id = Uuid::from_u128(1);
        let visible = Uuid::from_u128(2);
        let blocked = Uuid::from_u128(3);
        let stamp = DateTime::from_timestamp(1_000, 0).unwrap();
        let blocks = [MamBlockedPattern::Bare("blocked@example.test".into())];
        let mut query = MamArchiveQuery {
            with_jid: Some("publisher@example.test/resource".into()),
            start: Some(DateTime::from_timestamp(2_000, 0).unwrap()),
            end: None,
            before_id: None,
            after_id: None,
            ids: vec![visible, visible],
            page: MamRsmPage::First,
            max: 10,
        };
        assert_eq!(mam_referenced_ids(&query), vec![visible]);
        let mut references = QueryBuilder::<Postgres>::new("SELECT id FROM mix_events");
        push_mix_mam_reference_scope(
            &mut references,
            channel_id,
            &blocks,
            mam_referenced_ids(&query),
        );
        assert_eq!(
            references.sql().as_str(),
            "SELECT id FROM mix_events WHERE channel_id = $1 AND node = $2 AND publisher_jid <> $3 AND authoritative_id = ANY($4)"
        );
        let visible_points = std::collections::HashMap::from([(visible, stamp)]);
        assert!(resolve_mam_query(&query, &visible_points).is_some());

        let mut selection = QueryBuilder::<Postgres>::new("SELECT id FROM mix_events");
        push_mix_mam_scope(&mut selection, channel_id, &query, &blocks, None, None);
        assert_eq!(
            selection.sql().as_str(),
            "SELECT id FROM mix_events WHERE channel_id = $1 AND node = $2 AND publisher_jid <> $3 AND publisher_jid = $4 AND created_at >= $5 AND authoritative_id = ANY($6)"
        );
        query.ids.push(blocked);
        assert!(resolve_mam_query(&query, &visible_points).is_none());
    }
}
