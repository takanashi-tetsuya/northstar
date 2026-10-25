//! MAM archive sources, visibility filters, boundaries and page queries.

use super::*;

#[derive(Clone, Copy)]
pub enum MamArchiveSource {
    User(Uuid),
    Muc(Uuid),
}

impl MamArchiveSource {
    pub fn table(self) -> &'static str {
        match self {
            Self::User(_) => "message_archive",
            Self::Muc(_) => "muc_messages",
        }
    }

    pub fn owner_column(self) -> &'static str {
        match self {
            Self::User(_) => "owner_id",
            Self::Muc(_) => "room_id",
        }
    }

    pub fn owner_id(self) -> Uuid {
        match self {
            Self::User(id) | Self::Muc(id) => id,
        }
    }

    pub fn select_columns(self) -> &'static str {
        match self {
            Self::User(_) => {
                "id, peer_full_jid AS peer_jid, stanza, encrypted, stanza_id, created_at"
            }
            // MUC stanza_id is an authoritative UUID rather than the
            // personal archive's optional client id. Expose no client id
            // through the shared row type instead of conflating the two.
            Self::Muc(_) => {
                "id, sender_jid AS peer_jid, stanza, encrypted, NULL::TEXT AS stanza_id, created_at"
            }
        }
    }

    pub fn visible_full_identity(self) -> &'static str {
        match self {
            Self::User(_) => "peer_full_jid",
            // A full-JID block is resource-specific. New rows retain a bare
            // actor_scope for bare/domain matching, while sender_jid preserves
            // the originating resource for this exact comparison.
            Self::Muc(_) => "sender_jid",
        }
    }

    pub fn visible_bare_identity(self) -> &'static str {
        match self {
            Self::User(_) => "peer_jid",
            Self::Muc(_) => "split_part(COALESCE(actor_scope, sender_jid), '/', 1)",
        }
    }

    pub fn visible_domain_identity(self) -> &'static str {
        match self {
            Self::User(_) => {
                "CASE WHEN position('@' in peer_jid) > 0 THEN split_part(peer_jid, '@', 2) ELSE peer_jid END"
            }
            Self::Muc(_) => {
                "CASE WHEN position('@' in split_part(COALESCE(actor_scope, sender_jid), '/', 1)) > 0 THEN split_part(split_part(COALESCE(actor_scope, sender_jid), '/', 1), '@', 2) ELSE split_part(COALESCE(actor_scope, sender_jid), '/', 1) END"
            }
        }
    }
}

pub async fn mam_blocked_patterns(
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
        MamBlockedIdentitySource::ResourceAware,
    ))
}

pub fn push_mam_visibility(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    source: MamArchiveSource,
    blocked_patterns: &[MamBlockedPattern],
) {
    for pattern in blocked_patterns {
        query_builder.push(" AND ");
        match pattern {
            MamBlockedPattern::Full(value) => query_builder
                .push(source.visible_full_identity())
                .push(" <> ")
                .push_bind(value.clone()),
            MamBlockedPattern::Bare(value) => query_builder
                .push(source.visible_bare_identity())
                .push(" <> ")
                .push_bind(value.clone()),
            MamBlockedPattern::Domain(value) => query_builder
                .push(source.visible_domain_identity())
                .push(" <> ")
                .push_bind(value.clone()),
        };
    }
}

pub async fn archive_boundaries_for(
    pool: &PgPool,
    source: MamArchiveSource,
    viewer_id: Option<Uuid>,
) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let boundaries =
        archive_boundaries_for_in_transaction(&mut transaction, source, viewer_id).await?;
    transaction.commit().await?;
    Ok(boundaries)
}

pub async fn archive_boundaries_for_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    source: MamArchiveSource,
    viewer_id: Option<Uuid>,
) -> Result<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
    let blocked_patterns = mam_blocked_patterns(transaction, viewer_id).await?;

    let boundary = |descending: bool| {
        let mut builder = QueryBuilder::<Postgres>::new("SELECT id, created_at FROM ");
        builder
            .push(source.table())
            .push(" WHERE ")
            .push(source.owner_column())
            .push(" = ")
            .push_bind(source.owner_id());
        push_mam_visibility(&mut builder, source, &blocked_patterns);
        builder.push(if descending {
            " ORDER BY created_at DESC, id DESC LIMIT 1"
        } else {
            " ORDER BY created_at ASC, id ASC LIMIT 1"
        });
        builder
    };
    let first = boundary(false)
        .build()
        .fetch_optional(&mut **transaction)
        .await?;
    let last = boundary(true)
        .build()
        .fetch_optional(&mut **transaction)
        .await?;
    let convert = |row: sqlx::postgres::PgRow| ArchiveBoundary {
        id: row.get("id"),
        created_at: row.get("created_at"),
    };
    Ok((first.map(convert), last.map(convert)))
}

pub fn push_mam_archive_base(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    source: MamArchiveSource,
    blocked_patterns: &[MamBlockedPattern],
) {
    query_builder
        .push(" WHERE ")
        .push(source.owner_column())
        .push(" = ")
        .push_bind(source.owner_id());
    push_mam_visibility(query_builder, source, blocked_patterns);
}

pub fn push_mam_scope(
    query_builder: &mut QueryBuilder<'_, Postgres>,
    source: MamArchiveSource,
    query: &MamArchiveQuery,
    blocked_patterns: &[MamBlockedPattern],
    bounds: MamQueryBounds,
) {
    push_mam_archive_base(query_builder, source, blocked_patterns);
    if let Some(with_jid) = &query.with_jid {
        let full = with_jid.contains('/');
        if full {
            query_builder.push(" AND ");
            match source {
                MamArchiveSource::User(_) => query_builder.push("peer_full_jid"),
                MamArchiveSource::Muc(_) => query_builder.push("sender_jid"),
            };
            query_builder.push(" = ").push_bind(with_jid.clone());
        } else {
            query_builder.push(" AND ");
            match source {
                MamArchiveSource::User(_) => query_builder.push("peer_jid"),
                MamArchiveSource::Muc(_) => query_builder.push("split_part(sender_jid, '/', 1)"),
            };
            query_builder.push(" = ").push_bind(with_jid.clone());
        }
    }
    if let Some(start) = query.start {
        query_builder.push(" AND created_at >= ").push_bind(start);
    }
    if let Some(end) = query.end {
        query_builder.push(" AND created_at <= ").push_bind(end);
    }
    if let Some((created_at, id)) = bounds.after {
        query_builder
            .push(" AND (created_at, id) > (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    if let Some((created_at, id)) = bounds.before {
        query_builder
            .push(" AND (created_at, id) < (")
            .push_bind(created_at)
            .push(", ")
            .push_bind(id)
            .push(")");
    }
    if !query.ids.is_empty() {
        query_builder
            .push(" AND id = ANY(")
            .push_bind(query.ids.clone())
            .push(")");
    }
}

pub async fn mam_archive_page_for(
    pool: &PgPool,
    source: MamArchiveSource,
    viewer_id: Option<Uuid>,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let page =
        mam_archive_page_for_in_transaction(&mut transaction, source, viewer_id, query).await?;
    transaction.commit().await?;
    Ok(page)
}

pub async fn mam_archive_page_for_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    source: MamArchiveSource,
    viewer_id: Option<Uuid>,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    let blocked_patterns = mam_blocked_patterns(transaction, viewer_id).await?;

    // Resolve all referenced UIDs against the same visible archive scope.
    // The cursor itself need not match the form's independent filters.
    let requested_ids = mam_referenced_ids(query);
    let mut visible_points = HashMap::with_capacity(requested_ids.len());
    if !requested_ids.is_empty() {
        let mut builder = QueryBuilder::<Postgres>::new("SELECT id, created_at FROM ");
        builder.push(source.table());
        push_mam_archive_base(&mut builder, source, &blocked_patterns);
        builder
            .push(" AND id = ANY(")
            .push_bind(requested_ids)
            .push(")");
        for row in builder.build().fetch_all(&mut **transaction).await? {
            visible_points.insert(row.try_get("id")?, row.try_get("created_at")?);
        }
    }
    let Some(resolved) = resolve_mam_query(query, &visible_points) else {
        return Ok(None);
    };
    let plan = resolved.plan;
    let mut count_builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ");
    count_builder.push(source.table());
    push_mam_scope(
        &mut count_builder,
        source,
        query,
        &blocked_patterns,
        plan.count_bounds,
    );
    let total: i64 = count_builder
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await?;

    let max = query.max.clamp(0, MAX_MAM_PAGE_SIZE);
    let page = plan.page_window(resolved.page, max);

    let mut page_builder = QueryBuilder::<Postgres>::new("SELECT ");
    page_builder
        .push(source.select_columns())
        .push(" FROM ")
        .push(source.table());
    push_mam_scope(
        &mut page_builder,
        source,
        query,
        &blocked_patterns,
        page.bounds(),
    );
    page_builder.push(if page.descending {
        " ORDER BY created_at DESC, id DESC LIMIT "
    } else {
        " ORDER BY created_at ASC, id ASC LIMIT "
    });
    page_builder.push_bind(page.fetch_limit);
    if let Some(index) = page.offset {
        page_builder.push(" OFFSET ").push_bind(index);
    }
    let fetched = page_builder.build().fetch_all(&mut **transaction).await?;
    let (rows, complete) = finish_mam_page(
        fetched.iter().map(archive_from_row).collect(),
        max,
        page.descending,
    );

    let first_index = if let Some(first) = rows.first() {
        let mut index_builder = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ");
        index_builder.push(source.table());
        push_mam_scope(
            &mut index_builder,
            source,
            query,
            &blocked_patterns,
            plan.count_bounds,
        );
        index_builder
            .push(" AND (created_at, id) < (")
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
    Ok(Some(ArchivePage {
        rows,
        total,
        first_index,
        complete,
    }))
}

pub async fn mam_user_archive_page(
    pool: &PgPool,
    owner_id: Uuid,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    mam_archive_page_for(
        pool,
        MamArchiveSource::User(owner_id),
        Some(owner_id),
        query,
    )
    .await
}

/// Personal MAM page inside a caller-owned exact-bearer authorization
/// transaction. The API layer keeps the account and session rows locked from
/// its authorization check through this repeatable archive snapshot.
pub async fn mam_user_archive_page_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    owner_id: Uuid,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    mam_archive_page_for_in_transaction(
        transaction,
        MamArchiveSource::User(owner_id),
        Some(owner_id),
        query,
    )
    .await
}

/// MUC MAM with XEP-0191 visibility applied inside the same repeatable-read
/// snapshot as cursor validation, count, index and page selection.
#[cfg(any(test, feature = "test-support"))]
pub async fn mam_muc_archive_page_visible(
    pool: &PgPool,
    room_id: Uuid,
    viewer_id: Uuid,
    query: &MamArchiveQuery,
) -> Result<Option<ArchivePage>> {
    mam_archive_page_for(pool, MamArchiveSource::Muc(room_id), Some(viewer_id), query).await
}

pub fn archive_from_row(row: &sqlx::postgres::PgRow) -> ArchiveRow {
    ArchiveRow {
        id: row.get("id"),
        peer_jid: row.get("peer_jid"),
        stanza: row.get("stanza"),
        encrypted: row.get("encrypted"),
        stanza_id: row.get("stanza_id"),
        created_at: row.get("created_at"),
    }
}
