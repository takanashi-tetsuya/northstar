//! Cross-table identity invariants for archives, admissions, MUC and MIX.

use super::*;

pub(super) struct InvariantFinding<'a> {
    pub(super) table: &'a str,
    pub(super) field: &'a str,
    pub(super) locator: &'a str,
    pub(super) original: Option<&'a str>,
    pub(super) canonical: Option<&'a str>,
    pub(super) code: &'static str,
    pub(super) explanation: &'a str,
    pub(super) edges: &'a [&'a str],
    pub(super) related_locations: Vec<String>,
}

pub(super) fn invariant_finding(reporter: &Reporter, input: InvariantFinding<'_>) -> Finding {
    Finding {
        code: input.code,
        table: input.table.to_owned(),
        field: input.field.to_owned(),
        locator: format!("{}@{}", input.table, input.locator),
        canonicalizer: "cross-row-identity-invariant",
        scope: None,
        original: input.original.map(|value| reporter.value(value)),
        canonical: input.canonical.map(|value| reporter.value(value)),
        related_locations: input.related_locations,
        reference_edge_ids: input
            .edges
            .iter()
            .map(|edge| (*edge).to_owned())
            .collect(),
        explanation: input.explanation.to_owned(),
        recommendation: "Resolve the authoritative identity and repair the complete referenced graph in one reviewed transaction on an isolated database copy; never merge automatically.".to_owned(),
    }
}

pub(super) async fn message_archive_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "message_archive",
        &[
            "owner_id",
            "peer_jid",
            "peer_full_jid",
            "source_by",
            "source_stanza_id",
        ],
    ) {
        return Ok(Vec::new());
    }
    struct SourceRow {
        locator: String,
        original: String,
    }
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,owner_id::text AS owner_id,peer_jid,peer_full_jid,
                source_by,source_stanza_id::text AS source_stanza_id
         FROM message_archive ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    let mut source_keys: BTreeMap<(String, String, String), Vec<SourceRow>> = BTreeMap::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let owner: String = row.try_get("owner_id")?;
        let peer: String = row.try_get("peer_jid")?;
        let peer_full: String = row.try_get("peer_full_jid")?;
        if let (Ok(peer_key), Ok(full_key)) = (
            crate::jid::canonical_bare_key(&peer),
            crate::jid::canonical_bare_key(&peer_full),
        ) {
            if peer_key != full_key {
                findings.push(invariant_finding(
                    reporter,
                    InvariantFinding {
                        table: "message_archive",
                        field: "peer_jid+peer_full_jid",
                        locator: &locator,
                        original: Some(&peer),
                        canonical: Some(&full_key),
                        code: "archive_peer_mismatch",
                        explanation: "peer_jid and the barepart of peer_full_jid identify different principals",
                        edges: &["account-principal"],
                        related_locations: Vec::new(),
                    },
                ));
            }
        }
        let source: Option<String> = row.try_get("source_by")?;
        let source_id: Option<String> = row.try_get("source_stanza_id")?;
        if let (Some(source), Some(source_id)) = (source, source_id) {
            if let Ok(canonical) = crate::jid::canonicalize_bare(&source) {
                source_keys
                    .entry((owner.clone(), canonical, source_id))
                    .or_default()
                    .push(SourceRow {
                        locator,
                        original: source,
                    });
            }
        }
    }
    for rows in source_keys.into_values().filter(|rows| rows.len() > 1) {
        findings.push(invariant_finding(
            reporter,
            InvariantFinding {
                table: "message_archive",
                field: "source_by+source_stanza_id",
                locator: &rows[0].locator,
                original: Some(&rows[0].original),
                canonical: None,
                code: "precis_canonical_collision",
                explanation:
                    "multiple archive rows would claim the same canonical stanza-id authority",
                edges: &["account-principal"],
                related_locations: rows
                    .iter()
                    .skip(1)
                    .map(|row| format!("message_archive@{}", row.locator))
                    .collect(),
            },
        ));
    }
    Ok(findings)
}

pub(super) async fn personal_admission_collisions(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "personal_message_admissions",
        &[
            "identity_kind",
            "actor_scope",
            "target_scope",
            "identity_digest",
        ],
    ) {
        return Ok(Vec::new());
    }
    struct AdmissionRow {
        locator: String,
        actor: String,
        canonical_actor: String,
        canonical_target: String,
    }
    type AdmissionKey = (String, String, String, Vec<u8>);
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,identity_kind,actor_scope,target_scope,identity_digest
         FROM personal_message_admissions ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut keys: BTreeMap<AdmissionKey, Vec<AdmissionRow>> = BTreeMap::new();
    for row in rows {
        let actor: String = row.try_get("actor_scope")?;
        let target: String = row.try_get("target_scope")?;
        if let (Ok(canonical_actor), Ok(canonical_target)) = (
            crate::jid::canonicalize(&actor),
            crate::jid::canonicalize(&target),
        ) {
            let kind: String = row.try_get("identity_kind")?;
            let digest: Vec<u8> = row.try_get("identity_digest")?;
            keys.entry((
                kind,
                canonical_actor.clone(),
                canonical_target.clone(),
                digest,
            ))
            .or_default()
            .push(AdmissionRow {
                locator: row.try_get("locator")?,
                actor,
                canonical_actor,
                canonical_target,
            });
        }
    }
    Ok(keys
        .into_values()
        .filter(|rows| rows.len() > 1)
        .map(|rows| {
            invariant_finding(
                reporter,
                InvariantFinding {
                    table: "personal_message_admissions",
                    field: "identity_kind+actor_scope+target_scope+identity_digest",
                    locator: &rows[0].locator,
                    original: Some(&rows[0].actor),
                    canonical: Some(&format!(
                        "{} -> {}",
                        rows[0].canonical_actor, rows[0].canonical_target
                    )),
                    code: "precis_canonical_collision",
                    explanation:
                        "multiple admission rows become the same canonical idempotency identity",
                    edges: &["personal-admission-projections"],
                    related_locations: rows
                        .iter()
                        .skip(1)
                        .map(|row| format!("personal_message_admissions@{}", row.locator))
                        .collect(),
                },
            )
        })
        .collect())
}

pub(super) fn muc_origin_digest(actor_scope: &str, origin_id: &str) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"northstar:muc-origin-id:v1\0");
    digest.update((actor_scope.len() as u32).to_be_bytes());
    digest.update(actor_scope.as_bytes());
    digest.update((origin_id.len() as u32).to_be_bytes());
    digest.update(origin_id.as_bytes());
    digest.finalize().to_vec()
}

pub(super) async fn muc_origin_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "muc_origin_admissions",
        &[
            "room_id",
            "origin_digest",
            "actor_scope",
            "origin_id",
            "stanza_id",
        ],
    ) {
        return Ok(Vec::new());
    }
    struct Admission {
        locator: String,
        stanza: String,
        actor: String,
        origin: String,
        canonical_actor: String,
        canonical_digest: Vec<u8>,
    }
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,room_id::text AS room_id,origin_digest,
                actor_scope,origin_id,stanza_id::text AS stanza_id
         FROM muc_origin_admissions ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    let mut keys: BTreeMap<(String, Vec<u8>), Vec<Admission>> = BTreeMap::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let actor: String = row.try_get("actor_scope")?;
        let origin: String = row.try_get("origin_id")?;
        let stored_digest: Vec<u8> = row.try_get("origin_digest")?;
        if let Ok(canonical_actor) = crate::jid::canonicalize_bare(&actor) {
            let canonical_digest = muc_origin_digest(&canonical_actor, &origin);
            if stored_digest != canonical_digest {
                findings.push(invariant_finding(
                    reporter,
                    InvariantFinding {
                        table: "muc_origin_admissions",
                        field: "origin_digest",
                        locator: &locator,
                        original: Some(&actor),
                        canonical: Some(&canonical_actor),
                        code: "derived_identity_mismatch",
                        explanation: "origin_digest is not derived from the canonical actor_scope and origin_id",
                        edges: &["muc-origin-admission-message"],
                        related_locations: Vec::new(),
                    },
                ));
            }
            keys.entry((row.try_get("room_id")?, canonical_digest.clone()))
                .or_default()
                .push(Admission {
                    locator,
                    stanza: row.try_get("stanza_id")?,
                    actor,
                    origin,
                    canonical_actor,
                    canonical_digest,
                });
        }
    }
    for rows in keys.values().filter(|rows| rows.len() > 1) {
        findings.push(invariant_finding(
            reporter,
            InvariantFinding {
                table: "muc_origin_admissions",
                field: "room_id+origin_digest",
                locator: &rows[0].locator,
                original: Some(&rows[0].actor),
                canonical: Some(&rows[0].canonical_actor),
                code: "precis_canonical_collision",
                explanation: "multiple MUC admissions become the same canonical origin identity",
                edges: &["muc-origin-admission-message"],
                related_locations: rows
                    .iter()
                    .skip(1)
                    .map(|row| format!("muc_origin_admissions@{}", row.locator))
                    .collect(),
            },
        ));
    }

    if schema.has(
        "muc_messages",
        &["id", "room_id", "actor_scope", "origin_id", "origin_digest"],
    ) {
        let remaining_migration_complete = if schema.has(
            "jid_identity_migrations",
            &["migration", "canonicalizer_version"],
        ) {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                   SELECT 1 FROM jid_identity_migrations
                   WHERE migration='remaining-identity-metadata-rfc7622-ulabel-v2'
                     AND canonicalizer_version=2
                 )",
            )
            .fetch_one(&mut **transaction)
            .await?
        } else {
            false
        };
        let admissions = keys
            .into_iter()
            .flat_map(|((room, _), rows)| {
                rows.into_iter().map(move |row| {
                    (
                        room.clone(),
                        row.stanza,
                        row.canonical_actor,
                        row.origin,
                        row.canonical_digest,
                    )
                })
            })
            .collect::<HashSet<_>>();
        let messages = sqlx::query(
            "SELECT ctid::text AS locator,id::text AS id,room_id::text AS room_id,
                    actor_scope,origin_id,origin_digest
             FROM muc_messages ORDER BY ctid",
        )
        .fetch_all(&mut **transaction)
        .await?;
        for row in messages {
            let locator: String = row.try_get("locator")?;
            let actor: Option<String> = row.try_get("actor_scope")?;
            let origin: Option<String> = row.try_get("origin_id")?;
            let digest: Option<Vec<u8>> = row.try_get("origin_digest")?;
            match (actor, origin, digest) {
                (None, None, None) | (Some(_), None, None) => {}
                (Some(actor), Some(origin), Some(stored)) => {
                    if let Ok(canonical_actor) = crate::jid::canonicalize_bare(&actor) {
                        let expected = muc_origin_digest(&canonical_actor, &origin);
                        let key = (
                            row.try_get::<String, _>("room_id")?,
                            row.try_get::<String, _>("id")?,
                            canonical_actor.clone(),
                            origin.clone(),
                            expected.clone(),
                        );
                        if stored != expected
                            || (!remaining_migration_complete && !admissions.contains(&key))
                        {
                            findings.push(invariant_finding(
                                reporter,
                                InvariantFinding {
                                    table: "muc_messages",
                                    field: "actor_scope+origin_digest",
                                    locator: &locator,
                                    original: Some(&actor),
                                    canonical: Some(&canonical_actor),
                                    code: "origin_admission_mismatch",
                                    explanation: "message origin metadata has no exact canonical durable admission",
                                    edges: &["muc-origin-admission-message"],
                                    related_locations: Vec::new(),
                                },
                            ));
                        }
                    }
                }
                (actor, _, _) => findings.push(invariant_finding(
                    reporter,
                    InvariantFinding {
                        table: "muc_messages",
                        field: "actor_scope+origin_id+origin_digest",
                        locator: &locator,
                        original: actor.as_deref(),
                        canonical: None,
                        code: "incomplete_origin_identity",
                        explanation: "message contains an incomplete origin identity tuple",
                        edges: &["muc-origin-admission-message"],
                        related_locations: Vec::new(),
                    },
                )),
            }
        }
    }
    Ok(findings)
}

pub(super) async fn mix_participant_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "mix_participant_identities",
        &["channel_id", "participant_id", "jid"],
    ) || !schema.has("mix_participants", &["channel_id", "participant_id", "jid"])
    {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT p.ctid::text AS locator,p.jid AS participant_jid,i.jid AS identity_jid,
                (i.participant_id IS NOT NULL) AS parent_present
         FROM mix_participants p
         LEFT JOIN mix_participant_identities i
           ON i.channel_id=p.channel_id AND i.participant_id=p.participant_id
         ORDER BY p.ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let participant: String = row.try_get("participant_jid")?;
        let identity: Option<String> = row.try_get("identity_jid")?;
        let mismatch = match identity.as_deref() {
            Some(identity) => match (
                IdentityKind::UserBare.canonicalize(&participant),
                IdentityKind::UserBare.canonicalize(identity),
            ) {
                (Ok(left), Ok(right)) => left != right,
                _ => false,
            },
            None => true,
        };
        if mismatch {
            findings.push(invariant_finding(
                reporter,
                InvariantFinding {
                    table: "mix_participants",
                    field: "jid+participant_id",
                    locator: &locator,
                    original: Some(&participant),
                    canonical: identity.as_deref(),
                    code: "participant_identity_mismatch",
                    explanation: "active MIX participant does not have an exact stable participant identity parent after canonicalization",
                    edges: &["mix-participant-identity"],
                    related_locations: Vec::new(),
                },
            ));
        }
    }
    Ok(findings)
}

pub(super) async fn mix_channel_owner_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has("mix_channels", &["id", "creator_jid"])
        || !schema.has("mix_channel_roles", &["channel_id", "jid", "role"])
    {
        return Ok(Vec::new());
    }
    let roles = sqlx::query(
        "SELECT channel_id::text AS channel_id,jid FROM mix_channel_roles
         WHERE role='owner' ORDER BY channel_id,jid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut canonical_roles = HashSet::new();
    for row in roles {
        let channel: String = row.try_get("channel_id")?;
        let jid: String = row.try_get("jid")?;
        if let Ok(jid) = IdentityKind::UserBare.canonicalize(&jid) {
            canonical_roles.insert((channel, jid));
        }
    }
    let channels = sqlx::query(
        "SELECT ctid::text AS locator,id::text AS channel_id,creator_jid
         FROM mix_channels ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    for row in channels {
        let locator: String = row.try_get("locator")?;
        let channel: String = row.try_get("channel_id")?;
        let creator: String = row.try_get("creator_jid")?;
        if let Ok(canonical) = IdentityKind::UserBare.canonicalize(&creator) {
            if !canonical_roles.contains(&(channel, canonical.clone())) {
                findings.push(invariant_finding(
                    reporter,
                    InvariantFinding {
                        table: "mix_channels",
                        field: "creator_jid",
                        locator: &locator,
                        original: Some(&creator),
                        canonical: Some(&canonical),
                        code: "mix_creator_owner_role_missing",
                        explanation: "the canonical channel creator has no canonical owner role",
                        edges: &["mix-channel-creator-role"],
                        related_locations: Vec::new(),
                    },
                ));
            }
        }
    }
    Ok(findings)
}

pub(super) async fn muc_destroy_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
    domain: &str,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "api_muc_destroy_intents",
        &["room_jid", "localpart", "operation_id"],
    ) || !schema.has("api_operation_journal", &["id", "kind", "target"])
    {
        return Ok(Vec::new());
    }
    let conference = crate::jid::prepare_domainpart(&format!("conference.{domain}"))?;
    let rows = sqlx::query(
        "SELECT i.ctid::text AS locator,i.room_jid,i.localpart,o.kind,o.target
         FROM api_muc_destroy_intents i
         LEFT JOIN api_operation_journal o ON o.id=i.operation_id ORDER BY i.ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let room: String = row.try_get("room_jid")?;
        let local: String = row.try_get("localpart")?;
        let kind: Option<String> = row.try_get("kind")?;
        let target: Option<String> = row.try_get("target")?;
        let valid = crate::jid::CanonicalJid::parse_bare(&room)
            .ok()
            .and_then(|jid| {
                let prepared_local = crate::jid::prepare_localpart(&local).ok()?;
                Some(
                    jid.localpart() == Some(prepared_local.as_str())
                        && jid.domainpart() == conference
                        && kind.as_deref() == Some("admin.muc_destroy")
                        && target.as_deref() == Some(jid.to_string().as_str()),
                )
            })
            .unwrap_or(false);
        if !valid {
            findings.push(invariant_finding(
                reporter,
                InvariantFinding {
                    table: "api_muc_destroy_intents",
                    field: "room_jid+localpart+operation_id",
                    locator: &locator,
                    original: Some(&room),
                    canonical: None,
                    code: "muc_destroy_identity_mismatch",
                    explanation: "destroy tombstone address, configured conference service and immutable operation kind/target disagree",
                    edges: &["muc-destroy-operation"],
                    related_locations: Vec::new(),
                },
            ));
        }
    }
    Ok(findings)
}
