//! Structural, ownership and composite identity findings.

use super::*;

pub(super) async fn structural_findings(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
) -> Result<Vec<Finding>> {
    struct Check {
        table: &'static str,
        field: &'static str,
        required: &'static [&'static str],
        query: &'static str,
        explanation: &'static str,
    }
    const CHECKS: &[Check] = &[
        Check {
            table: "mix_channels",
            field: "contacts",
            required: &["contacts"],
            query: "SELECT ctid::text AS locator FROM mix_channels t
                    WHERE jsonb_typeof(t.contacts) IS DISTINCT FROM 'array'
                       OR EXISTS (
                         SELECT 1 FROM jsonb_array_elements(
                           CASE WHEN jsonb_typeof(t.contacts)='array' THEN t.contacts ELSE '[]'::jsonb END
                         ) value WHERE jsonb_typeof(value) IS DISTINCT FROM 'string'
                       ) ORDER BY ctid",
            explanation: "contacts must be a JSON array containing only string JIDs",
        },
        Check {
            table: "sm_resume_sessions",
            field: "joined_rooms",
            required: &["joined_rooms"],
            query: "SELECT ctid::text AS locator FROM sm_resume_sessions t
                    WHERE jsonb_typeof(t.joined_rooms) IS DISTINCT FROM 'array'
                       OR EXISTS (
                         SELECT 1 FROM jsonb_array_elements(
                           CASE WHEN jsonb_typeof(t.joined_rooms)='array' THEN t.joined_rooms ELSE '[]'::jsonb END
                         ) value
                         WHERE jsonb_typeof(value) IS DISTINCT FROM 'object'
                            OR jsonb_typeof(value->'room_jid') IS DISTINCT FROM 'string'
                       ) ORDER BY ctid",
            explanation: "joined_rooms must be a JSON array of objects with a string room_jid",
        },
        Check {
            table: "sm_resume_sessions",
            field: "directed_presence",
            required: &["directed_presence"],
            query: "SELECT ctid::text AS locator FROM sm_resume_sessions t
                    WHERE jsonb_typeof(t.directed_presence) IS DISTINCT FROM 'array'
                       OR EXISTS (
                         SELECT 1 FROM jsonb_array_elements(
                           CASE WHEN jsonb_typeof(t.directed_presence)='array' THEN t.directed_presence ELSE '[]'::jsonb END
                         ) value WHERE jsonb_typeof(value) IS DISTINCT FROM 'string'
                       ) ORDER BY ctid",
            explanation: "directed_presence must be a JSON array containing only string JIDs",
        },
    ];
    let mut findings = Vec::new();
    for check in CHECKS {
        if !schema.has(check.table, check.required) {
            continue;
        }
        for row in sqlx::query(check.query)
            .fetch_all(&mut **transaction)
            .await?
        {
            let locator: String = row.try_get("locator")?;
            findings.push(Finding {
                code: "invalid_identity_container",
                table: check.table.to_owned(),
                field: check.field.to_owned(),
                locator: format!("{}@{}", check.table, locator),
                canonicalizer: "container-shape",
                scope: None,
                original: None,
                canonical: None,
                related_locations: Vec::new(),
                reference_edge_ids: Vec::new(),
                explanation: check.explanation.to_owned(),
                recommendation: "Repair the container shape on an isolated copy before changing any nested identity values; never discard unknown membership state automatically.".to_owned(),
            });
        }
    }
    Ok(findings)
}

pub(super) async fn ownership_and_composite_findings(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
    domain: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    if schema.has("users", &["id", "username"])
        && schema.has(
            "sm_resume_sessions",
            &["id", "user_id", "full_jid", "resource"],
        )
    {
        let rows = sqlx::query(
            "SELECT s.ctid::text AS locator,u.username,s.full_jid,s.resource
             FROM sm_resume_sessions s JOIN users u ON u.id=s.user_id ORDER BY s.ctid",
        )
        .fetch_all(&mut **transaction)
        .await?;
        for row in rows {
            let locator: String = row.try_get("locator")?;
            let username: String = row.try_get("username")?;
            let full: String = row.try_get("full_jid")?;
            let resource: String = row.try_get("resource")?;
            let Ok(canonical_full) = crate::jid::canonical_session_key(&full) else {
                continue;
            };
            let Ok(parsed) = crate::jid::CanonicalJid::parse(&canonical_full) else {
                continue;
            };
            let expected_bare = crate::jid::canonicalize_bare(&format!("{username}@{domain}"));
            if expected_bare
                .as_deref()
                .is_ok_and(|expected| expected != parsed.bare())
            {
                findings.push(semantic_finding(
                    reporter,
                    SemanticFinding {
                        table: "sm_resume_sessions",
                        field: "full_jid",
                        locator: &locator,
                        original: &full,
                        code: "session_ownership_mismatch",
                        explanation: "the session full JID does not belong to the referenced users.username at the configured XMPP domain",
                        edges: &["sm-session-owner"],
                    },
                ));
            }
            if crate::jid::prepare_resourcepart(&resource).ok().as_deref() != parsed.resourcepart()
            {
                findings.push(semantic_finding(
                    reporter,
                    SemanticFinding {
                        table: "sm_resume_sessions",
                        field: "resource",
                        locator: &locator,
                        original: &resource,
                        code: "session_resource_mismatch",
                        explanation: "the prepared resource column does not equal the resourcepart of full_jid",
                        edges: &["sm-session-owner"],
                    },
                ));
            }
        }
    }
    if schema.has("users", &["id", "username"])
        && schema.has("admin_command_sessions", &["owner_id", "owner_full_jid"])
    {
        let rows = sqlx::query(
            "SELECT s.ctid::text AS locator,u.username,s.owner_full_jid
             FROM admin_command_sessions s JOIN users u ON u.id=s.owner_id ORDER BY s.ctid",
        )
        .fetch_all(&mut **transaction)
        .await?;
        for row in rows {
            let locator: String = row.try_get("locator")?;
            let username: String = row.try_get("username")?;
            let full: String = row.try_get("owner_full_jid")?;
            let expected = crate::jid::canonicalize_bare(&format!("{username}@{domain}"));
            let actual = crate::jid::canonical_bare_key(&full);
            if matches!((&expected, &actual), (Ok(expected), Ok(actual)) if expected != actual) {
                findings.push(semantic_finding(
                    reporter,
                    SemanticFinding {
                        table: "admin_command_sessions",
                        field: "owner_full_jid",
                        locator: &locator,
                        original: &full,
                        code: "session_ownership_mismatch",
                        explanation:
                            "the admin command full JID does not belong to the referenced account",
                        edges: &["admin-session-owner"],
                    },
                ));
            }
        }
    }
    findings.extend(mix_channel_collisions(transaction, schema, reporter).await?);
    findings.extend(mix_registered_nick_collisions(transaction, schema, reporter).await?);
    findings.extend(message_archive_invariants(transaction, schema, reporter).await?);
    findings.extend(personal_admission_collisions(transaction, schema, reporter).await?);
    findings.extend(muc_origin_invariants(transaction, schema, reporter).await?);
    findings.extend(mix_participant_invariants(transaction, schema, reporter).await?);
    findings.extend(mix_channel_owner_invariants(transaction, schema, reporter).await?);
    findings.extend(muc_destroy_invariants(transaction, schema, reporter, domain).await?);
    Ok(findings)
}

pub(super) struct SemanticFinding<'a> {
    pub(super) table: &'a str,
    pub(super) field: &'a str,
    pub(super) locator: &'a str,
    pub(super) original: &'a str,
    pub(super) code: &'static str,
    pub(super) explanation: &'a str,
    pub(super) edges: &'a [&'a str],
}

pub(super) fn semantic_finding(reporter: &Reporter, input: SemanticFinding<'_>) -> Finding {
    Finding {
        code: input.code,
        table: input.table.to_owned(),
        field: input.field.to_owned(),
        locator: format!("{}@{}", input.table, input.locator),
        canonicalizer: "cross-column-identity-invariant",
        scope: None,
        original: Some(reporter.value(input.original)),
        canonical: None,
        related_locations: Vec::new(),
        reference_edge_ids: input
            .edges
            .iter()
            .map(|edge| (*edge).to_owned())
            .collect(),
        explanation: input.explanation.to_owned(),
        recommendation: "Verify the owning principal and repair every linked session row together on an isolated copy; stale bearer/session records should be revoked rather than reassigned by guesswork.".to_owned(),
    }
}

pub(super) async fn mix_channel_collisions(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has("mix_channels", &["service_domain", "localpart"]) {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,service_domain,localpart FROM mix_channels ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut keys: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let service: String = row.try_get("service_domain")?;
        let local: String = row.try_get("localpart")?;
        if let (Ok(service), Ok(local)) = (
            crate::jid::prepare_domainpart(&service),
            crate::jid::prepare_localpart(&local),
        ) {
            keys.entry((service, local)).or_default().push((
                locator,
                format!(
                    "{}@{}",
                    row.try_get::<String, _>("localpart")?,
                    row.try_get::<String, _>("service_domain")?
                ),
            ));
        }
    }
    Ok(composite_collision_findings(
        reporter,
        "mix_channels",
        "service_domain+localpart",
        keys,
        "MIX channel addresses collide after localpart PRECIS and service-domain IDNA preparation",
        &["mix-channel-address"],
    ))
}

pub(super) async fn mix_registered_nick_collisions(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has("mix_registered_nicks", &["service_domain", "jid", "nick"]) {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,service_domain,jid,nick FROM mix_registered_nicks ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut owner_keys: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    let mut nick_keys: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let original_service: String = row.try_get("service_domain")?;
        let original_jid: String = row.try_get("jid")?;
        let nick: String = row.try_get("nick")?;
        if let (Ok(service), Ok(jid)) = (
            crate::jid::prepare_domainpart(&original_service),
            IdentityKind::UserBare.canonicalize(&original_jid),
        ) {
            owner_keys
                .entry((service.clone(), jid))
                .or_default()
                .push((locator.clone(), original_jid));
            nick_keys
                .entry((service, nick.clone()))
                .or_default()
                .push((locator, nick));
        }
    }
    let mut findings = composite_collision_findings(
        reporter,
        "mix_registered_nicks",
        "service_domain+jid",
        owner_keys,
        "registered MIX ownership collides after service-domain/JID canonicalization",
        &["mix-registered-nick-owner"],
    );
    findings.extend(composite_collision_findings(
        reporter,
        "mix_registered_nicks",
        "service_domain+nick",
        nick_keys,
        "the same MIX nickname would have multiple owners after service-domain canonicalization",
        &["mix-registered-nick-owner"],
    ));
    Ok(findings)
}

pub(super) fn composite_collision_findings(
    reporter: &Reporter,
    table: &str,
    field: &str,
    keys: BTreeMap<(String, String), Vec<(String, String)>>,
    explanation: &str,
    edges: &[&str],
) -> Vec<Finding> {
    keys.into_iter()
        .filter_map(|((left, right), rows)| {
            if rows.len() < 2 {
                return None;
            }
            let (locator, original) = &rows[0];
            Some(Finding {
                code: "precis_canonical_collision",
                table: table.to_owned(),
                field: field.to_owned(),
                locator: format!("{table}@{locator}"),
                canonicalizer: "composite-canonical-key",
                scope: Some(reporter.value(&left)),
                original: Some(reporter.value(original)),
                canonical: Some(reporter.value(&format!("{right}@{left}"))),
                related_locations: rows
                    .iter()
                    .skip(1)
                    .map(|(locator, _)| format!("{table}@{locator}"))
                    .collect(),
                reference_edge_ids: edges.iter().map(|edge| (*edge).to_owned()).collect(),
                explanation: explanation.to_owned(),
                recommendation: "Choose the authoritative principal/address manually and repair all referenced rows in one reviewed transaction; never select a winner automatically.".to_owned(),
            })
        })
        .collect()
}
