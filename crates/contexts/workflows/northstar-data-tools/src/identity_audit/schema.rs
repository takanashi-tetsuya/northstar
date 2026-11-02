//! Schema discovery, marker reporting, scan specifications and the identity reference graph.

use super::*;

pub(super) async fn load_schema(transaction: &mut Transaction<'_, Postgres>) -> Result<SchemaMap> {
    let schema = sqlx::query_scalar::<_, String>("SELECT current_schema()::text")
        .fetch_one(&mut **transaction)
        .await?;
    // pg_catalog is intentional: information_schema hides tables for which the
    // audit role lacks privileges and could turn a permission mistake into a
    // false "old schema / clean" result.  Catalog discovery sees the table;
    // the subsequent SELECT then fails closed if the role cannot read it.
    let rows = sqlx::query(
        "SELECT c.relname AS table_name,a.attname AS column_name
         FROM pg_class c
         JOIN pg_namespace n ON n.oid=c.relnamespace
         JOIN pg_attribute a ON a.attrelid=c.oid
         WHERE n.nspname=current_schema()
           AND c.relkind IN ('r','p')
           AND a.attnum > 0 AND NOT a.attisdropped
         ORDER BY c.relname,a.attnum",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut tables = HashMap::<String, HashSet<String>>::new();
    for row in rows {
        let table: String = row.try_get("table_name")?;
        let column: String = row.try_get("column_name")?;
        tables.entry(table).or_default().insert(column);
    }
    Ok(SchemaMap { schema, tables })
}

pub(super) async fn load_schema_report(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<SchemaReport> {
    let (applied_sqlx_migrations, latest_sqlx_migration) =
        if schema.has("_sqlx_migrations", &["version", "success"]) {
            let row = sqlx::query(
                "SELECT COUNT(*) FILTER (WHERE success) AS applied,
                    MAX(version) FILTER (WHERE success) AS latest
             FROM _sqlx_migrations",
            )
            .fetch_one(&mut **transaction)
            .await?;
            (row.try_get("applied")?, row.try_get("latest")?)
        } else {
            (None, None)
        };
    let identity_markers = if schema.has(
        "jid_identity_migrations",
        &[
            "migration",
            "canonicalizer_version",
            "transformed_rows",
            "completed_at",
        ],
    ) {
        sqlx::query(
            "SELECT migration,canonicalizer_version,transformed_rows,completed_at
             FROM jid_identity_migrations ORDER BY migration",
        )
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| {
            let marker: String = row.try_get("migration")?;
            let (marker_kind, domain_scope) = marker_description(&marker, reporter);
            Ok(MarkerReport {
                marker_kind,
                domain_scope,
                canonicalizer_version: row.try_get("canonicalizer_version")?,
                transformed_rows: row.try_get("transformed_rows")?,
                completed_at: row.try_get("completed_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?
    } else {
        Vec::new()
    };
    Ok(SchemaReport {
        current_schema: schema.schema.clone(),
        applied_sqlx_migrations,
        latest_sqlx_migration,
        identity_markers,
    })
}

pub(super) fn marker_description(
    marker: &str,
    reporter: &Reporter,
) -> (String, Option<SensitiveValue>) {
    const KNOWN: &[&str] = &[
        "pubsub-pep-rfc7622-ulabel-v2",
        "authorization-keys-rfc7622-ulabel-v2",
        "push-keys-rfc7622-ulabel-v2",
        "mix-keys-rfc7622-ulabel-v2",
        "profile-pep-item-jids-rfc7622-ulabel-v2",
        "remaining-identity-metadata-rfc7622-ulabel-v2",
    ];
    const SESSION: &str = "session-authorization-rfc7622-ulabel-v2:";
    if KNOWN.contains(&marker) {
        (marker.to_owned(), None)
    } else if let Some(domain) = marker.strip_prefix(SESSION) {
        (
            "session-authorization-rfc7622-ulabel-v2".to_owned(),
            Some(reporter.value(domain)),
        )
    } else {
        (
            "unrecognized-identity-migration-marker".to_owned(),
            Some(reporter.value(marker)),
        )
    }
}

pub(super) fn scan_specs() -> Vec<ScanSpec> {
    use IdentityKind as K;
    use ScanSource::{Column, Query};
    const NONE: &[&str] = &[];
    const USER: &[&str] = &["account-principal"];
    const PUBSUB_NODE: &[&str] = &["pubsub-node-owner"];
    const PEP_NODE: &[&str] = &["pep-node-owner"];
    const PUSH: &[&str] = &["push-attempt-subscription"];
    const MIX_CHANNEL: &[&str] = &["mix-channel-address"];
    const MIX_PARTICIPANT: &[&str] = &["mix-participant-identity"];
    const SM: &[&str] = &["sm-session-owner", "sm-resume-stanzas"];
    const ADMIN: &[&str] = &["admin-session-owner"];
    const MUC_INTENT: &[&str] = &["muc-destroy-operation"];
    const PROFILE: &[&str] = &["profile-pep-item-payload-root"];

    vec![
        ScanSpec { table: "users", field: "username", required_columns: &["username"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Localpart, collision_namespace: Some("account-username"), reference_edges: USER, remediation: "Resolve the account principal and every users(id) reference together; never merge two accounts automatically." },
        ScanSpec { table: "roster_items", field: "contact_jid", required_columns: &["owner_id", "contact_jid"], source: Column { scope_sql: "t.owner_id::text", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: Some("roster-contact"), reference_edges: USER, remediation: "Repair the owner-scoped roster key and its change-log history together." },
        ScanSpec { table: "roster_change_log", field: "contact_jid", required_columns: &["owner_id", "version", "contact_jid"], source: Column { scope_sql: "t.owner_id::text || ':' || t.version::text", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: USER, remediation: "Rewrite the historical contact identity only after its live roster principal is resolved." },
        ScanSpec { table: "blocked_jids", field: "blocked_jid", required_columns: &["owner_id", "blocked_jid"], source: Column { scope_sql: "t.owner_id::text", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: Some("blocked-jid"), reference_edges: USER, remediation: "Preserve the owner's deny policy and deduplicate only after confirming equivalent principals/resources." },
        ScanSpec { table: "federated_presence_pending", field: "from_jid", required_columns: &["recipient_id", "from_jid"], source: Column { scope_sql: "t.recipient_id::text", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: Some("pending-presence"), reference_edges: USER, remediation: "Resolve the sender principal before deduplicating pending subscription state." },
        ScanSpec { table: "mam_preference_jids", field: "jid", required_columns: &["user_id", "jid"], source: Column { scope_sql: "t.user_id::text", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: Some("mam-preference"), reference_edges: USER, remediation: "Review conflicting always/never archive policies before consolidating their keys." },
        ScanSpec { table: "muc_external_affiliations", field: "jid", required_columns: &["room_id", "jid"], source: Column { scope_sql: "t.room_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("muc-external-affiliation"), reference_edges: &["muc-room-affiliation"], remediation: "Resolve room affiliation authority manually; conflicting affiliations must not be combined by precedence guesswork." },
        ScanSpec { table: "federation_runtime_rules", field: "domain", required_columns: &["kind", "domain"], source: Column { scope_sql: "t.kind", predicate_sql: "TRUE" }, kind: K::Domain, collision_namespace: Some("federation-runtime-rule"), reference_edges: NONE, remediation: "Review allow/deny policy for the canonical domain and keep one explicit rule." },

        ScanSpec { table: "pubsub_nodes", field: "creator_jid", required_columns: &["creator_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: PUBSUB_NODE, remediation: "Repair creator attribution together with node affiliations; a resourcepart is discarded only after review." },
        ScanSpec { table: "pubsub_nodes", field: "children_association_whitelist", required_columns: &["children_association_whitelist"], source: Query("SELECT t.ctid::text || '/array/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.identity AS value FROM pubsub_nodes t CROSS JOIN LATERAL unnest(t.children_association_whitelist) WITH ORDINALITY AS value(identity,ordinality) ORDER BY t.ctid,value.ordinality"), kind: K::BareKey, collision_namespace: Some("pubsub-child-whitelist"), reference_edges: PUBSUB_NODE, remediation: "Remove only the explicitly reviewed duplicate whitelist member and preserve collection policy." },
        ScanSpec { table: "pubsub_items", field: "publisher_jid", required_columns: &["publisher_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: PUBSUB_NODE, remediation: "Repair publisher attribution without changing the item XML payload." },
        ScanSpec { table: "pubsub_affiliations", field: "jid", required_columns: &["node_id", "jid"], source: Column { scope_sql: "t.node_id::text", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: Some("pubsub-affiliation"), reference_edges: PUBSUB_NODE, remediation: "Resolve conflicting node affiliations explicitly before changing the key." },
        ScanSpec { table: "pubsub_subscriptions", field: "jid", required_columns: &["node_id", "jid"], source: Column { scope_sql: "t.node_id::text", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: Some("pubsub-subscription"), reference_edges: PUBSUB_NODE, remediation: "Resolve subscription ownership and subid state before deduplicating." },
        ScanSpec { table: "pubsub_digest_queue", field: "subscriber_jid", required_columns: &["subscriber_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: &["pubsub-digest-subscription"], remediation: "Repair the queue recipient consistently with its subscription; do not inspect or rewrite event XML in this audit." },
        ScanSpec { table: "pep_nodes", field: "access_whitelist", required_columns: &["access_whitelist"], source: Query("SELECT t.ctid::text || '/array/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.identity AS value FROM pep_nodes t CROSS JOIN LATERAL unnest(t.access_whitelist) WITH ORDINALITY AS value(identity,ordinality) ORDER BY t.ctid,value.ordinality"), kind: K::BareKey, collision_namespace: Some("pep-access-whitelist"), reference_edges: PEP_NODE, remediation: "Review and deduplicate the owner/node access policy explicitly." },
        ScanSpec { table: "pep_subscriptions", field: "subscriber_jid", required_columns: &["owner_id", "node", "subscriber_jid"], source: Column { scope_sql: "t.owner_id::text || ':' || t.node", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: Some("pep-subscription"), reference_edges: PEP_NODE, remediation: "Resolve full-JID subscriber/subid ownership without collapsing case-sensitive resourceparts." },

        ScanSpec { table: "push_subscriptions", field: "service_jid", required_columns: &["user_id", "service_jid", "node"], source: Column { scope_sql: "t.user_id::text || ':' || COALESCE(t.node,'')", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: Some("push-subscription"), reference_edges: PUSH, remediation: "Rewrite the parent subscription and all delivery attempts atomically after resolving any duplicate service." },
        ScanSpec { table: "push_delivery_attempts", field: "service_jid", required_columns: &["user_id", "service_jid", "node"], source: Column { scope_sql: "t.user_id::text || ':' || COALESCE(t.node,'')", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: PUSH, remediation: "Keep the attempt key identical to its parent push subscription." },

        ScanSpec { table: "mix_channels", field: "service_domain", required_columns: &["service_domain"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Domain, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair service_domain together with localpart and every channel reference." },
        ScanSpec { table: "mix_channels", field: "localpart", required_columns: &["localpart"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Localpart, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair localpart together with service_domain and every channel reference." },
        ScanSpec { table: "mix_channels", field: "creator_jid", required_columns: &["creator_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: None, reference_edges: &["mix-channel-creator-role"], remediation: "Ensure the canonical creator still has the channel owner role." },
        ScanSpec { table: "mix_channels", field: "contacts", required_columns: &["contacts"], source: Query("SELECT t.ctid::text || '/json/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.identity #>> '{}' AS value FROM mix_channels t CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(t.contacts)='array' THEN t.contacts ELSE '[]'::jsonb END) WITH ORDINALITY AS value(identity,ordinality) WHERE jsonb_typeof(value.identity)='string' ORDER BY t.ctid,value.ordinality"), kind: K::UserBare, collision_namespace: Some("mix-channel-contact"), reference_edges: MIX_CHANNEL, remediation: "Remove only reviewed duplicate contacts and preserve contact ordering intentionally." },
        ScanSpec { table: "mix_participant_identities", field: "jid", required_columns: &["channel_id", "jid"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-participant-identity"), reference_edges: MIX_PARTICIPANT, remediation: "Resolve the stable participant ID and active participant row as one graph." },
        ScanSpec { table: "mix_participants", field: "jid", required_columns: &["channel_id", "jid"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-active-participant"), reference_edges: MIX_PARTICIPANT, remediation: "Keep the active participant's JID and stable identity parent consistent." },
        ScanSpec { table: "mix_channel_roles", field: "jid", required_columns: &["channel_id", "jid"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-channel-role"), reference_edges: &["mix-channel-creator-role"], remediation: "Resolve owner/administrator authorization explicitly before consolidating keys." },
        ScanSpec { table: "mix_allowed", field: "jid_pattern", required_columns: &["channel_id", "jid_pattern"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::AccessPattern, collision_namespace: Some("mix-access-policy"), reference_edges: MIX_CHANNEL, remediation: "Choose one allow/ban outcome explicitly; a canonical identity cannot remain in both lists." },
        ScanSpec { table: "mix_banned", field: "jid_pattern", required_columns: &["channel_id", "jid_pattern"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::AccessPattern, collision_namespace: Some("mix-access-policy"), reference_edges: MIX_CHANNEL, remediation: "Choose one allow/ban outcome explicitly; a canonical identity cannot remain in both lists." },
        ScanSpec { table: "mix_allowed", field: "added_by", required_columns: &["added_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair historical policy attribution only after confirming the actor principal." },
        ScanSpec { table: "mix_banned", field: "added_by", required_columns: &["added_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair historical policy attribution only after confirming the actor principal." },
        ScanSpec { table: "mix_pam_memberships", field: "channel_jid", required_columns: &["user_id", "channel_jid"], source: Column { scope_sql: "t.user_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-pam-membership"), reference_edges: USER, remediation: "Resolve the account's channel membership and pending request state before deduplicating." },
        ScanSpec { table: "mix_pam_memberships", field: "requester_full_jid", required_columns: &["requester_full_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::SessionFull, collision_namespace: None, reference_edges: USER, remediation: "Revoke an unowned or malformed pending requester session instead of reassigning it." },
        ScanSpec { table: "mix_registered_nicks", field: "service_domain", required_columns: &["service_domain"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Domain, collision_namespace: None, reference_edges: &["mix-registered-nick-owner"], remediation: "Repair the service scope together with JID and nickname uniqueness." },
        ScanSpec { table: "mix_registered_nicks", field: "jid", required_columns: &["service_domain", "jid"], source: Column { scope_sql: "t.service_domain", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-registered-jid"), reference_edges: &["mix-registered-nick-owner"], remediation: "Resolve the registered nickname owner explicitly." },
        ScanSpec { table: "mix_invitations", field: "inviter_jid", required_columns: &["inviter_jid", "consumed_at", "expires_at"], source: Column { scope_sql: "''", predicate_sql: "t.consumed_at IS NULL AND t.expires_at > clock_timestamp()" }, kind: K::UserBare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair or revoke the active invitation; never expose or regenerate its token." },
        ScanSpec { table: "mix_invitations", field: "invitee_jid", required_columns: &["invitee_jid", "consumed_at", "expires_at"], source: Column { scope_sql: "''", predicate_sql: "t.consumed_at IS NULL AND t.expires_at > clock_timestamp()" }, kind: K::UserBare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair or revoke the active invitation; never expose or regenerate its token." },

        ScanSpec { table: "pep_items", field: "item_id", required_columns: &["owner_id", "node", "item_id"], source: Column { scope_sql: "t.owner_id::text || ':' || t.node", predicate_sql: "t.node IN ('urn:xmpp:bookmarks:1','urn:xmpp:contacts')" }, kind: K::UserBare, collision_namespace: Some("profile-pep-item"), reference_edges: PROFILE, remediation: "Use the dedicated profile ItemID repair on an isolated copy so the key and XML root id change atomically; this audit intentionally does not read payload XML." },
        ScanSpec { table: "sm_resume_sessions", field: "full_jid", required_columns: &["user_id", "full_jid"], source: Column { scope_sql: "t.user_id::text", predicate_sql: "TRUE" }, kind: K::SessionFull, collision_namespace: Some("sm-session-full-jid"), reference_edges: SM, remediation: "Resolve ownership and revoke stale colliding sessions rather than merging bearer state." },
        ScanSpec { table: "sm_resume_sessions", field: "resource", required_columns: &["resource"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Resource, collision_namespace: None, reference_edges: SM, remediation: "Keep the resource exactly equal to the full_jid resourcepart; resourceparts are case-sensitive." },
        ScanSpec { table: "sm_resume_sessions", field: "joined_rooms", required_columns: &["joined_rooms"], source: Query("SELECT t.ctid::text || '/joined/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.membership->>'room_jid' AS value FROM sm_resume_sessions t CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(t.joined_rooms)='array' THEN t.joined_rooms ELSE '[]'::jsonb END) WITH ORDINALITY AS value(membership,ordinality) WHERE jsonb_typeof(value.membership)='object' AND jsonb_typeof(value.membership->'room_jid')='string' ORDER BY t.ctid,value.ordinality"), kind: K::UserBare, collision_namespace: Some("sm-joined-room"), reference_edges: SM, remediation: "Resolve duplicate room membership state within the suspended session before rewriting JSON." },
        ScanSpec { table: "sm_resume_sessions", field: "directed_presence", required_columns: &["directed_presence"], source: Query("SELECT t.ctid::text || '/directed/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.identity #>> '{}' AS value FROM sm_resume_sessions t CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(t.directed_presence)='array' THEN t.directed_presence ELSE '[]'::jsonb END) WITH ORDINALITY AS value(identity,ordinality) WHERE jsonb_typeof(value.identity)='string' ORDER BY t.ctid,value.ordinality"), kind: K::Full, collision_namespace: Some("sm-directed-presence"), reference_edges: SM, remediation: "Resolve duplicate directed-presence targets within the suspended session before rewriting JSON." },
        ScanSpec { table: "admin_command_sessions", field: "owner_full_jid", required_columns: &["owner_id", "owner_full_jid"], source: Column { scope_sql: "t.owner_id::text", predicate_sql: "TRUE" }, kind: K::SessionFull, collision_namespace: None, reference_edges: ADMIN, remediation: "Revoke a malformed/unowned command session; never transfer privileged session state automatically." },
        ScanSpec { table: "api_muc_destroy_intents", field: "room_jid", required_columns: &["room_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("muc-destroy-room"), reference_edges: MUC_INTENT, remediation: "Repair the tombstone and immutable operation target together using a reviewed control-plane procedure." },
        ScanSpec { table: "api_muc_destroy_intents", field: "localpart", required_columns: &["localpart"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Localpart, collision_namespace: Some("muc-destroy-localpart"), reference_edges: MUC_INTENT, remediation: "Keep localpart equal to room_jid localpart and the configured conference service." },

        ScanSpec { table: "offline_messages", field: "sender_jid", required_columns: &["sender_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: USER, remediation: "Repair only sender identity metadata; this audit never reads or rewrites the stanza." },
        ScanSpec { table: "message_archive", field: "peer_jid", required_columns: &["peer_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: USER, remediation: "Repair archive identity metadata without reading or rewriting archived stanza content." },
        ScanSpec { table: "message_archive", field: "peer_full_jid", required_columns: &["peer_full_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: USER, remediation: "Keep peer_full_jid's bare key consistent with peer_jid while preserving an opaque resourcepart." },
        ScanSpec { table: "message_archive", field: "source_by", required_columns: &["source_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: USER, remediation: "Resolve the stanza-id authority before changing archive metadata; never inspect content in this tool." },
        ScanSpec { table: "personal_message_admissions", field: "actor_scope", required_columns: &["actor_scope"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["personal-admission-projections"], remediation: "Repair actor/target scopes and every durable projection as one admission identity; never inspect content commitments." },
        ScanSpec { table: "personal_message_admissions", field: "target_scope", required_columns: &["target_scope"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["personal-admission-projections"], remediation: "Repair actor/target scopes and every durable projection as one admission identity; never inspect content commitments." },
        ScanSpec { table: "muc_origin_admissions", field: "actor_scope", required_columns: &["actor_scope"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: &["muc-origin-admission-message"], remediation: "Recompute the admission digest using the reviewed origin-id procedure; never guess which colliding event survives." },
        ScanSpec { table: "muc_rooms", field: "subject_set_by", required_columns: &["subject_set_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: &["muc-room-affiliation"], remediation: "Repair subject attribution independently of subject text." },
        ScanSpec { table: "muc_rooms", field: "configuration_owner_jid", required_columns: &["configuration_owner_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["muc-room-affiliation"], remediation: "Verify configuration authority against current room ownership before changing it." },
        ScanSpec { table: "muc_messages", field: "sender_jid", required_columns: &["sender_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["muc-origin-admission-message"], remediation: "Repair sender metadata without reading or rewriting the archived stanza." },
        ScanSpec { table: "muc_messages", field: "actor_scope", required_columns: &["actor_scope"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: &["muc-origin-admission-message"], remediation: "Keep actor scope and origin admission digest consistent." },
        ScanSpec { table: "abuse_reports", field: "reported_jid", required_columns: &["reported_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: &["abuse-report-evidence"], remediation: "Repair only the reported principal metadata; descriptions and evidence content are deliberately outside this audit." },
        ScanSpec { table: "abuse_report_evidence", field: "sender_jid", required_columns: &["sender_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["abuse-report-evidence"], remediation: "Repair only sender metadata; body_text is deliberately not read." },
        ScanSpec { table: "s2s_outbox", field: "target_domain", required_columns: &["target_domain", "dedupe_hash"], source: Column { scope_sql: "encode(t.dedupe_hash,'hex')", predicate_sql: "TRUE" }, kind: K::Domain, collision_namespace: Some("s2s-target-dedupe"), reference_edges: NONE, remediation: "Resolve canonical target/dedupe collisions before rewriting; stanza content is deliberately not read." },
        ScanSpec { table: "s2s_outbox", field: "bounce_to", required_columns: &["bounce_to"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: NONE, remediation: "Repair the bounce identity without reading or rewriting the queued stanza." },
        ScanSpec { table: "privacy_list_items", field: "match_value", required_columns: &["match_type", "match_value"], source: Column { scope_sql: "''", predicate_sql: "t.match_type='jid'" }, kind: K::Full, collision_namespace: None, reference_edges: USER, remediation: "Review privacy-list first-match semantics before changing a JID match value." },
        ScanSpec { table: "mix_events", field: "publisher_jid", required_columns: &["publisher_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair publisher metadata only; event payload is deliberately not read." },
        ScanSpec { table: "mix_events", field: "source_full_jid", required_columns: &["node", "source_full_jid"], source: Column { scope_sql: "''", predicate_sql: "t.node='urn:xmpp:mix:nodes:presence'" }, kind: K::SessionFull, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Preserve the case-sensitive resourcepart in historical presence attribution." },
        ScanSpec { table: "mix_events", field: "item_id", required_columns: &["channel_id", "node", "item_id"], source: Column { scope_sql: "t.channel_id::text || ':' || t.node", predicate_sql: "t.node IN ('urn:xmpp:mix:nodes:allowed','urn:xmpp:mix:nodes:banned')" }, kind: K::AccessPattern, collision_namespace: Some("mix-event-policy-item"), reference_edges: MIX_CHANNEL, remediation: "Repair the event key only with a payload-aware procedure; payload is deliberately not read by this audit." },
        ScanSpec { table: "mix_events", field: "item_id", required_columns: &["channel_id", "node", "item_id"], source: Column { scope_sql: "t.channel_id::text || ':' || t.node", predicate_sql: "t.node='urn:xmpp:mix:nodes:presence'" }, kind: K::SessionFull, collision_namespace: Some("mix-event-presence-item"), reference_edges: MIX_CHANNEL, remediation: "Repair the event key only with a payload-aware procedure; resourceparts remain case-sensitive." },
        ScanSpec { table: "mix_muc_mirrors", field: "created_by", required_columns: &["created_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: &["mix-muc-mirror"], remediation: "Verify the mirror creator against MUC/MIX ownership before changing attribution." },
    ]
}

pub(super) async fn load_reference_graph(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    specs: &[ScanSpec],
) -> Result<Vec<ReferenceEdge>> {
    let audited = specs.iter().map(|spec| spec.table).collect::<HashSet<_>>();
    let mut edges = Vec::new();
    let rows = sqlx::query(
        "SELECT c.conname,
                c.conrelid::regclass::text AS source_table,
                c.confrelid::regclass::text AS target_table,
                pg_get_constraintdef(c.oid,false) AS definition
         FROM pg_constraint c
         JOIN pg_namespace n ON n.oid=c.connamespace
         WHERE c.contype='f' AND n.nspname=current_schema()
         ORDER BY source_table,c.conname",
    )
    .fetch_all(&mut **transaction)
    .await?;
    for row in rows {
        let source: String = row.try_get("source_table")?;
        let target: String = row.try_get("target_table")?;
        let source_name = source
            .rsplit('.')
            .next()
            .unwrap_or(&source)
            .trim_matches('"');
        let target_name = target
            .rsplit('.')
            .next()
            .unwrap_or(&target)
            .trim_matches('"');
        if !audited.contains(source_name) && !audited.contains(target_name) {
            continue;
        }
        let name: String = row.try_get("conname")?;
        edges.push(ReferenceEdge {
            id: format!("fk:{source_name}:{name}"),
            kind: "database-foreign-key",
            source,
            target,
            relationship: row.try_get("definition")?,
            row_data_inspected: false,
        });
    }

    struct StaticEdge {
        id: &'static str,
        source_table: &'static str,
        target_table: &'static str,
        source: &'static str,
        target: &'static str,
        relationship: &'static str,
    }
    const STATIC: &[StaticEdge] = &[
        StaticEdge { id: "account-principal", source_table: "users", target_table: "roster_items", source: "users.username + configured XMPP domain", target: "account-owned identity-bearing rows", relationship: "users.id foreign keys and reconstructed bare JID define the account principal" },
        StaticEdge { id: "pubsub-node-owner", source_table: "pubsub_nodes", target_table: "pubsub_affiliations", source: "pubsub_nodes.creator_jid", target: "pubsub_affiliations/subscriptions/items", relationship: "creator, authorization keys, subscriptions and item attribution share one node identity graph" },
        StaticEdge { id: "pubsub-digest-subscription", source_table: "pubsub_digest_queue", target_table: "pubsub_subscriptions", source: "pubsub_digest_queue.subscription_node_id + subscriber_jid", target: "pubsub_subscriptions.node_id + jid", relationship: "semantic queue recipient must remain the canonical subscription recipient; queue XML is not inspected" },
        StaticEdge { id: "pep-node-owner", source_table: "pep_nodes", target_table: "pep_subscriptions", source: "pep_nodes(owner_id,node)", target: "pep_subscriptions and access_whitelist", relationship: "PEP access and subscriber identities are owner/node scoped" },
        StaticEdge { id: "push-attempt-subscription", source_table: "push_delivery_attempts", target_table: "push_subscriptions", source: "push_delivery_attempts(user_id,service_jid,node)", target: "push_subscriptions(user_id,service_jid,node)", relationship: "delivery attempt is a composite foreign-key child of the push subscription" },
        StaticEdge { id: "mix-channel-address", source_table: "mix_channels", target_table: "mix_participants", source: "mix_channels(service_domain,localpart)", target: "all channel_id children and address-derived protocol state", relationship: "MIX channel address is a composite canonical key; every channel_id child follows it" },
        StaticEdge { id: "mix-channel-creator-role", source_table: "mix_channels", target_table: "mix_channel_roles", source: "mix_channels.creator_jid", target: "mix_channel_roles jid where role=owner", relationship: "the canonical channel creator must retain an owner role" },
        StaticEdge { id: "mix-participant-identity", source_table: "mix_participants", target_table: "mix_participant_identities", source: "mix_participants(channel_id,jid,participant_id)", target: "mix_participant_identities(channel_id,jid,participant_id)", relationship: "active participant must match the stable participant identity in both JID and participant ID" },
        StaticEdge { id: "mix-registered-nick-owner", source_table: "mix_registered_nicks", target_table: "mix_channels", source: "mix_registered_nicks(service_domain,jid,nick)", target: "MIX service scope", relationship: "both canonical owner JID and nickname are unique within canonical service_domain" },
        StaticEdge { id: "sm-session-owner", source_table: "sm_resume_sessions", target_table: "users", source: "sm_resume_sessions(user_id,full_jid,resource)", target: "users(id,username) + configured XMPP domain", relationship: "full JID barepart belongs to the referenced account and resource equals its opaque resourcepart" },
        StaticEdge { id: "sm-resume-stanzas", source_table: "sm_resume_stanzas", target_table: "sm_resume_sessions", source: "sm_resume_stanzas.session_id", target: "sm_resume_sessions.id", relationship: "queued stanzas follow a session, but stanza bytes are never inspected by this audit" },
        StaticEdge { id: "admin-session-owner", source_table: "admin_command_sessions", target_table: "users", source: "admin_command_sessions(owner_id,owner_full_jid)", target: "users(id,username) + configured XMPP domain", relationship: "privileged command session full JID must belong to its owner account" },
        StaticEdge { id: "muc-destroy-operation", source_table: "api_muc_destroy_intents", target_table: "api_operation_journal", source: "api_muc_destroy_intents(operation_id,room_jid,localpart)", target: "api_operation_journal(id,kind,target)", relationship: "destroy tombstone address and immutable operation target agree; operation payload is deliberately not inspected" },
        StaticEdge { id: "profile-pep-item-payload-root", source_table: "pep_items", target_table: "pep_items", source: "profile pep_items.item_id", target: "root id attribute in the same row payload", relationship: "key and XML root id must change atomically in a dedicated content-aware repair; payload is deliberately not inspected" },
        StaticEdge { id: "personal-admission-projections", source_table: "personal_message_admissions", target_table: "message_archive", source: "personal_message_admissions identity tuple", target: "archive/offline/S2S/durable delivery projection IDs", relationship: "admission identity and all recoverable projections form one idempotency graph" },
        StaticEdge { id: "muc-origin-admission-message", source_table: "muc_origin_admissions", target_table: "muc_messages", source: "canonical actor_scope + origin_id digest", target: "muc_messages origin_digest/actor_scope", relationship: "canonical actor changes require digest recomputation and atomic admission/message repair" },
        StaticEdge { id: "muc-room-affiliation", source_table: "muc_rooms", target_table: "muc_external_affiliations", source: "MUC room identity and attribution", target: "local/external affiliation authorization", relationship: "room attribution must remain consistent with owner/admin/member authority" },
        StaticEdge { id: "abuse-report-evidence", source_table: "abuse_reports", target_table: "abuse_report_evidence", source: "abuse_reports.reported_jid", target: "abuse_report_evidence.sender_jid", relationship: "identity metadata is linked by report_id; descriptions and evidence body are never inspected" },
        StaticEdge { id: "mix-muc-mirror", source_table: "mix_muc_mirrors", target_table: "mix_channels", source: "mix_muc_mirrors(created_by,mix_channel_id,muc_room_id)", target: "MIX channel and MUC room ownership", relationship: "mirror creator attribution crosses the MIX/MUC identity graph" },
    ];
    for edge in STATIC {
        if schema.tables.contains_key(edge.source_table)
            || schema.tables.contains_key(edge.target_table)
        {
            edges.push(ReferenceEdge {
                id: edge.id.to_owned(),
                kind: "semantic-identity-edge",
                source: edge.source.to_owned(),
                target: edge.target.to_owned(),
                relationship: edge.relationship.to_owned(),
                row_data_inspected: false,
            });
        }
    }
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(edges)
}
