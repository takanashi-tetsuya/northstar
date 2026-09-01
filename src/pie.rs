//! XEP-0227 Portable Import/Export (PIE) operator tooling.
//!
//! This module is intentionally an offline control-plane tool.  It does not
//! expose user archives over HTTP or XMPP and it never exports plaintext
//! passwords.  Import is one serializable transaction, including its audit
//! record; `--dry-run` executes the same database writes and then rolls back.

use crate::{auth, config::Config, jid};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use roxmltree::{Document, Node};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

const PIE_NS: &str = "urn:xmpp:pie:0";
const SCRAM_NS: &str = "urn:xmpp:pie:0#scram";
const MAM_PIE_NS: &str = "urn:xmpp:pie:0#mam";
const XINCLUDE_NS: &str = "http://www.w3.org/2001/XInclude";
const ROSTER_NS: &str = "jabber:iq:roster";
const PRIVATE_NS: &str = "jabber:iq:private";
const PRIVACY_NS: &str = "jabber:iq:privacy";
const PUBSUB_NS: &str = "http://jabber.org/protocol/pubsub";
const PUBSUB_OWNER_NS: &str = "http://jabber.org/protocol/pubsub#owner";
const CLIENT_NS: &str = "jabber:client";
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 4_096;
const MAX_INCLUDE_DEPTH: usize = 8;
const MAX_XML_DEPTH: usize = 64;
const MAX_XML_NODES: usize = 2_000_000;
const MAX_USERS: usize = 10_000;
const MAX_ITEMS: usize = 250_000;
const MAX_STANZA_BYTES: usize = 1024 * 1024;
const SCRAM_ONLY_PASSWORD_HASH: &str = "!northstar-pie-scram-only";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConflictPolicy {
    Fail,
    Skip,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnknownPolicy {
    Warn,
    Fail,
}

#[derive(Debug)]
enum Command {
    Export { output: PathBuf, include_mam: bool },
    Import(ImportOptions),
}

#[derive(Debug)]
struct ImportOptions {
    input: PathBuf,
    root: Option<PathBuf>,
    dry_run: bool,
    conflict: ConflictPolicy,
    unknown: UnknownPolicy,
    allow_plaintext_passwords: bool,
}

struct ImportRuntime<'a> {
    domain: &'a str,
    scram_iterations: u32,
}

#[derive(Default)]
struct LoadBudget {
    total_bytes: u64,
    files: usize,
    nodes: usize,
    users: usize,
    items: usize,
    seen: BTreeSet<PathBuf>,
}

#[derive(Default)]
struct ImportDocument {
    users: Vec<PieUser>,
    warnings: Vec<String>,
}

#[derive(Default)]
struct PieUser {
    username: String,
    plaintext_password: Option<String>,
    scram: Option<ScramCredential>,
    roster: Vec<RosterItem>,
    offline: Vec<OfflineMessage>,
    private_xml: Vec<PrivateXml>,
    vcard: Option<String>,
    blocked: Vec<String>,
    pending: Vec<PendingPresence>,
    pep_nodes: BTreeMap<String, PepNode>,
    archive: Vec<ArchiveItem>,
}

struct ScramCredential {
    iterations: u32,
    salt: Vec<u8>,
    stored_key: Vec<u8>,
    server_key: Vec<u8>,
}

struct RosterItem {
    jid: String,
    name: Option<String>,
    subscription: String,
    ask: Option<String>,
    groups: Vec<String>,
    approved: bool,
}

struct OfflineMessage {
    sender: String,
    stanza: String,
    /// Derived from the validated stanza, never accepted as an independent
    /// PIE field.
    target_resource: Option<String>,
    encrypted: bool,
    created_at: Option<DateTime<Utc>>,
}

struct PrivateXml {
    name: String,
    namespace: String,
    xml: String,
}

struct PendingPresence {
    from: String,
    stanza: String,
}

struct PepNode {
    access_model: String,
    max_items: i32,
    persist_items: bool,
    send_last: String,
    deliver_notifications: bool,
    roster_groups_allowed: Vec<String>,
    access_whitelist: Vec<String>,
    subscriptions: Vec<PepSubscription>,
    items: Vec<PepItem>,
}

impl Default for PepNode {
    fn default() -> Self {
        Self {
            access_model: "presence".to_owned(),
            max_items: 100,
            persist_items: true,
            send_last: "on_sub".to_owned(),
            deliver_notifications: true,
            roster_groups_allowed: Vec::new(),
            access_whitelist: Vec::new(),
            subscriptions: Vec::new(),
            items: Vec::new(),
        }
    }
}

struct PepSubscription {
    jid: String,
    subid: String,
    state: String,
}

struct PepItem {
    id: String,
    payload: String,
}

struct ArchiveItem {
    result_id: String,
    peer_jid: String,
    peer_full_jid: String,
    stanza: String,
    encrypted: bool,
    created_at: DateTime<Utc>,
}

struct PreparedUser {
    data: PieUser,
    password_hash: String,
    scram: ScramCredential,
}

struct StagedUser {
    id: Uuid,
    data: PieUser,
}

pub async fn run(config: &Config, arguments: &[String]) -> Result<()> {
    let command = parse_command(arguments)?;
    let import_uses_migrator = matches!(&command, Command::Import(_))
        && !config.database_allow_unsafe_role_for_development;
    let database_url = if import_uses_migrator {
        let value = std::env::var("MIGRATOR_DATABASE_URL").ok();
        let file = std::env::var_os("MIGRATOR_DATABASE_URL_FILE").map(PathBuf::from);
        anyhow::ensure!(
            value.is_none() || file.is_none(),
            "set only one of MIGRATOR_DATABASE_URL and MIGRATOR_DATABASE_URL_FILE for PIE import"
        );
        zeroize::Zeroizing::new(match (value, file) {
            (Some(value), None) if !value.trim().is_empty() => value,
            (None, Some(path)) => {
                crate::config::read_secret_file(&path, "MIGRATOR_DATABASE_URL_FILE")?
            }
            _ => anyhow::bail!(
                "production PIE import requires MIGRATOR_DATABASE_URL_FILE (preferred) or MIGRATOR_DATABASE_URL"
            ),
        })
    } else {
        zeroize::Zeroizing::new(config.database_url.clone())
    };
    let pool_options = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database_max_connections.clamp(1, 8));
    let pool_options = if config.database_allow_unsafe_role_for_development {
        pool_options
    } else {
        crate::db::pin_public_application_schema(pool_options)
    };
    let pool = pool_options
        .connect(database_url.as_str())
        .await
        .context("PIE could not connect to PostgreSQL")?;
    if config.database_allow_unsafe_role_for_development {
        crate::db::attest_development_database_is_loopback(&pool).await?;
    } else if import_uses_migrator {
        crate::db::attest_migrator_role(&pool).await?;
    } else {
        crate::db::attest_runtime_role(&pool).await?;
    }
    assert_schema_ready(&pool).await?;
    match command {
        Command::Export {
            output,
            include_mam,
        } => export(&pool, &config.domain, &output, include_mam).await,
        Command::Import(options) => {
            import(
                &pool,
                &ImportRuntime {
                    domain: &config.domain,
                    scram_iterations: config.scram_iterations,
                },
                &options,
            )
            .await
        }
    }
}

fn parse_command(arguments: &[String]) -> Result<Command> {
    let Some(action) = arguments.first().map(String::as_str) else {
        bail!(usage());
    };
    let mut output = None;
    let mut input = None;
    let mut root = None;
    let mut dry_run = false;
    let mut include_mam = true;
    let mut conflict = ConflictPolicy::Fail;
    let mut unknown = UnknownPolicy::Warn;
    let mut allow_plaintext_passwords = false;
    let mut index = 1;
    while index < arguments.len() {
        let option = arguments[index].as_str();
        index += 1;
        let value = |index: &mut usize| -> Result<String> {
            let value = arguments
                .get(*index)
                .with_context(|| format!("{option} requires a value"))?
                .clone();
            *index += 1;
            Ok(value)
        };
        match option {
            "--output" => output = Some(PathBuf::from(value(&mut index)?)),
            "--input" => input = Some(PathBuf::from(value(&mut index)?)),
            "--root" => root = Some(PathBuf::from(value(&mut index)?)),
            "--dry-run" => dry_run = true,
            "--exclude-mam" => include_mam = false,
            "--allow-plaintext-passwords" => allow_plaintext_passwords = true,
            "--conflict" => {
                conflict = match value(&mut index)?.as_str() {
                    "fail" => ConflictPolicy::Fail,
                    "skip" => ConflictPolicy::Skip,
                    "replace" => ConflictPolicy::Replace,
                    other => bail!("invalid conflict policy {other:?}; use fail, skip, or replace"),
                }
            }
            "--unknown" => {
                unknown = match value(&mut index)?.as_str() {
                    "warn" => UnknownPolicy::Warn,
                    "fail" => UnknownPolicy::Fail,
                    other => bail!("invalid unknown-data policy {other:?}; use warn or fail"),
                }
            }
            "--help" | "-h" => bail!(usage()),
            other => bail!("unknown PIE option {other:?}\n{}", usage()),
        }
    }
    match action {
        "export" => {
            let output = output.context("PIE export requires --output PATH")?;
            if input.is_some()
                || root.is_some()
                || dry_run
                || conflict != ConflictPolicy::Fail
                || unknown != UnknownPolicy::Warn
                || allow_plaintext_passwords
            {
                bail!("an import-only option was supplied to PIE export");
            }
            Ok(Command::Export {
                output,
                include_mam,
            })
        }
        "import" => {
            let input = input.context("PIE import requires --input PATH")?;
            if output.is_some() || !include_mam {
                bail!("an export-only option was supplied to PIE import");
            }
            Ok(Command::Import(ImportOptions {
                input,
                root,
                dry_run,
                conflict,
                unknown,
                allow_plaintext_passwords,
            }))
        }
        other => bail!("unknown PIE action {other:?}\n{}", usage()),
    }
}

fn usage() -> &'static str {
    "usage:\n  rust-xmpp-server pie export --output PATH [--exclude-mam]\n  rust-xmpp-server pie import --input PATH [--root DIR] [--dry-run] [--conflict fail|skip|replace] [--unknown warn|fail] [--allow-plaintext-passwords]\n\nRun PIE import while Northstar is stopped. Export creates a new owner-only file and never writes plaintext passwords. Encrypt exported files with an external, authenticated encryption tool before transport or long-term storage."
}

async fn assert_schema_ready(pool: &PgPool) -> Result<()> {
    let version: Option<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE success ORDER BY version DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("PIE requires a migrated Northstar database")?;
    if version.unwrap_or_default() < 51 {
        bail!("PIE requires the current Northstar schema; run the server migration first");
    }
    Ok(())
}

async fn export(
    pool: &PgPool,
    configured_domain: &str,
    output: &Path,
    include_mam: bool,
) -> Result<()> {
    let domain = jid::prepare_domainpart(configured_domain)?;
    let users = sqlx::query(
        "SELECT id,username,scram_sha256_salt,scram_sha256_iterations,
                scram_sha256_stored_key,scram_sha256_server_key
           FROM users ORDER BY username LIMIT $1",
    )
    .bind((MAX_USERS + 1) as i64)
    .fetch_all(pool)
    .await?;
    if users.len() > MAX_USERS {
        bail!("PIE export exceeds the {MAX_USERS} user safety limit");
    }
    let mut xml = String::with_capacity(64 * 1024);
    xml.push_str("<?xml version='1.0' encoding='UTF-8'?>\n");
    xml.push_str("<server-data xmlns='urn:xmpp:pie:0'>\n");
    xml.push_str(&format!("  <host jid='{}'>\n", attr_escape(&domain)));
    let mut item_count = 0_usize;
    let user_count = users.len();
    let mut auth_omissions = Vec::new();
    for row in users {
        let user_id: Uuid = row.get("id");
        let username: String = row.get("username");
        xml.push_str(&format!("    <user name='{}'>\n", attr_escape(&username)));
        let scram = (
            row.get::<Option<Vec<u8>>, _>("scram_sha256_salt"),
            row.get::<Option<i32>, _>("scram_sha256_iterations"),
            row.get::<Option<Vec<u8>>, _>("scram_sha256_stored_key"),
            row.get::<Option<Vec<u8>>, _>("scram_sha256_server_key"),
        );
        match scram {
            (Some(salt), Some(iterations), Some(stored), Some(server))
                if (auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS)
                    .contains(&(iterations as u32))
                    && !salt.is_empty()
                    && stored.len() == 32
                    && server.len() == 32 =>
            {
                xml.push_str("      <scram-credentials xmlns='urn:xmpp:pie:0#scram' mechanism='SCRAM-SHA-256'>\n");
                xml.push_str(&format!("        <iter-count>{iterations}</iter-count>\n"));
                xml.push_str(&format!("        <salt>{}</salt>\n", BASE64.encode(salt)));
                xml.push_str(&format!(
                    "        <server-key>{}</server-key>\n",
                    BASE64.encode(server)
                ));
                xml.push_str(&format!(
                    "        <stored-key>{}</stored-key>\n",
                    BASE64.encode(stored)
                ));
                xml.push_str("      </scram-credentials>\n");
            }
            _ => auth_omissions.push(username.clone()),
        }
        export_roster(pool, user_id, &mut xml, &mut item_count).await?;
        export_offline(pool, user_id, &mut xml, &mut item_count).await?;
        export_private(pool, user_id, &mut xml, &mut item_count).await?;
        export_vcard(pool, user_id, &mut xml, &mut item_count).await?;
        export_blocklist(pool, user_id, &mut xml, &mut item_count).await?;
        export_pending(pool, user_id, &domain, &mut xml, &mut item_count).await?;
        export_pep(pool, user_id, &mut xml, &mut item_count).await?;
        if include_mam {
            export_mam(pool, user_id, &mut xml, &mut item_count).await?;
        }
        xml.push_str("    </user>\n");
        enforce_items(item_count)?;
        if xml.len() > MAX_TOTAL_BYTES as usize {
            bail!(
                "PIE export exceeds the {} MiB output safety limit",
                MAX_TOTAL_BYTES / 1024 / 1024
            );
        }
    }
    xml.push_str("  </host>\n</server-data>\n");
    validate_xml_document(&xml, "generated PIE export")?;
    write_secret_file(output, xml.as_bytes())?;
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details)
         VALUES(NULL,'operator.pie.export',$1,$2)",
    )
    .bind(
        output
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("[non-utf8]"),
    )
    .bind(serde_json::json!({
        "domain":domain,
        "users": user_count,
        "items": item_count,
        "mam_included":include_mam,
        "credential_omissions":auth_omissions.len()
    }))
    .execute(pool)
    .await
    .context("PIE export file was written, but its database audit record failed")?;
    for username in auth_omissions {
        eprintln!(
            "warning: {username}@{domain} had no valid portable SCRAM-SHA-256 verifier; the exported account cannot authenticate after import until an operator resets its password"
        );
    }
    eprintln!(
        "PIE export created {} with owner-only creation semantics; apply external authenticated encryption before transport or long-term storage",
        output.display()
    );
    Ok(())
}

async fn export_roster(
    pool: &PgPool,
    user_id: Uuid,
    xml: &mut String,
    count: &mut usize,
) -> Result<()> {
    let rows = sqlx::query("SELECT contact_jid,display_name,subscription,ask,groups,approved FROM roster_items WHERE owner_id=$1 ORDER BY contact_jid")
        .bind(user_id).fetch_all(pool).await?;
    if rows.is_empty() {
        return Ok(());
    }
    xml.push_str("      <query xmlns='jabber:iq:roster'>\n");
    for row in rows {
        *count += 1;
        let jid: String = row.get("contact_jid");
        let name: Option<String> = row.get("display_name");
        let subscription: String = row.get("subscription");
        let ask: Option<String> = row.get("ask");
        let approved: bool = row.get("approved");
        let groups: Vec<String> = serde_json::from_value(row.get("groups"))?;
        xml.push_str(&format!(
            "        <item jid='{}' subscription='{}'",
            attr_escape(&jid),
            attr_escape(&subscription)
        ));
        if let Some(name) = name {
            xml.push_str(&format!(" name='{}'", attr_escape(&name)));
        }
        if let Some(ask) = ask {
            xml.push_str(&format!(" ask='{}'", attr_escape(&ask)));
        }
        if approved {
            xml.push_str(" approved='true'");
        }
        if groups.is_empty() {
            xml.push_str("/>\n");
        } else {
            xml.push_str(">\n");
            for group in groups {
                xml.push_str(&format!(
                    "          <group>{}</group>\n",
                    text_escape(&group)
                ));
            }
            xml.push_str("        </item>\n");
        }
    }
    xml.push_str("      </query>\n");
    Ok(())
}

async fn export_offline(
    pool: &PgPool,
    user_id: Uuid,
    xml: &mut String,
    count: &mut usize,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT stanza FROM offline_messages WHERE recipient_id=$1 ORDER BY created_at,id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(());
    }
    xml.push_str("      <offline-messages>\n");
    for row in rows {
        *count += 1;
        let stanza: String = row.get("stanza");
        validate_client_message_fragment(&stanza, "stored offline message")?;
        xml.push_str("        ");
        xml.push_str(&stanza);
        xml.push('\n');
    }
    xml.push_str("      </offline-messages>\n");
    Ok(())
}

async fn export_private(
    pool: &PgPool,
    user_id: Uuid,
    xml: &mut String,
    count: &mut usize,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT xml_data FROM private_xml WHERE user_id=$1 ORDER BY element_ns,element_name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(());
    }
    xml.push_str("      <query xmlns='jabber:iq:private'>\n");
    for row in rows {
        *count += 1;
        let data: String = row.get("xml_data");
        validate_xml_fragment(&data, "stored private XML")?;
        xml.push_str("        ");
        xml.push_str(&data);
        xml.push('\n');
    }
    xml.push_str("      </query>\n");
    Ok(())
}

async fn export_vcard(
    pool: &PgPool,
    user_id: Uuid,
    xml: &mut String,
    count: &mut usize,
) -> Result<()> {
    let payload: Option<String> = sqlx::query_scalar("SELECT payload FROM vcards WHERE user_id=$1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    if let Some(payload) = payload {
        *count += 1;
        validate_xml_fragment(&payload, "stored vCard")?;
        bound_xml(&payload, "stored vCard")?;
        let document = Document::parse(&payload)?;
        let root = document.root_element();
        if root.tag_name().name() != "vCard" || root.tag_name().namespace() != Some("vcard-temp") {
            bail!("stored vCard does not use the vcard-temp root element");
        }
        xml.push_str("      ");
        xml.push_str(&payload);
        xml.push('\n');
    }
    Ok(())
}

async fn export_blocklist(
    pool: &PgPool,
    user_id: Uuid,
    xml: &mut String,
    count: &mut usize,
) -> Result<()> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT blocked_jid FROM blocked_jids WHERE owner_id=$1 ORDER BY blocked_jid",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(());
    }
    xml.push_str("      <query xmlns='jabber:iq:privacy'><default name='northstar-blocklist'/><list name='northstar-blocklist'>\n");
    for (index, blocked) in rows.into_iter().enumerate() {
        *count += 1;
        xml.push_str(&format!(
            "        <item type='jid' value='{}' action='deny' order='{}'/>\n",
            attr_escape(&blocked),
            index + 1
        ));
    }
    xml.push_str("        <item action='allow' order='2147483647'/>\n      </list></query>\n");
    Ok(())
}

async fn export_pending(
    pool: &PgPool,
    user_id: Uuid,
    domain: &str,
    xml: &mut String,
    count: &mut usize,
) -> Result<()> {
    let local = sqlx::query("SELECT u.username,p.stanza,p.created_at FROM pending_presence_subscriptions p JOIN users u ON u.id=p.requester_id WHERE p.recipient_id=$1 ORDER BY p.created_at,u.username")
        .bind(user_id).fetch_all(pool).await?;
    let remote = sqlx::query("SELECT from_jid,stanza,created_at FROM federated_presence_pending WHERE recipient_id=$1 ORDER BY created_at,from_jid")
        .bind(user_id).fetch_all(pool).await?;
    for row in local {
        *count += 1;
        let from = format!("{}@{domain}", row.get::<String, _>("username"));
        let stanza: Option<String> = row.get("stanza");
        append_pending_presence(xml, &from, stanza.as_deref())?;
    }
    for row in remote {
        *count += 1;
        let from: String = row.get("from_jid");
        let stanza: Option<String> = row.get("stanza");
        append_pending_presence(xml, &from, stanza.as_deref())?;
    }
    Ok(())
}

fn append_pending_presence(xml: &mut String, from: &str, stanza: Option<&str>) -> Result<()> {
    if let Some(stanza) = stanza {
        validate_xml_fragment(stanza, "stored pending presence")?;
        xml.push_str("      ");
        xml.push_str(stanza);
        xml.push('\n');
    } else {
        xml.push_str(&format!(
            "      <presence xmlns='jabber:client' type='subscribe' from='{}'/>\n",
            attr_escape(from)
        ));
    }
    Ok(())
}

async fn export_pep(
    pool: &PgPool,
    user_id: Uuid,
    xml: &mut String,
    count: &mut usize,
) -> Result<()> {
    let nodes = sqlx::query("SELECT node,access_model,max_items,persist_items,send_last_published_item,deliver_notifications,roster_groups_allowed,access_whitelist FROM pep_nodes WHERE owner_id=$1 ORDER BY node")
        .bind(user_id).fetch_all(pool).await?;
    if nodes.is_empty() {
        return Ok(());
    }
    xml.push_str("      <pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>\n");
    for row in &nodes {
        *count += 1;
        let node: String = row.get("node");
        xml.push_str(&format!(
            "        <configure node='{}'><x xmlns='jabber:x:data' type='submit'>",
            attr_escape(&node)
        ));
        xml.push_str("<field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#node_config</value></field>");
        push_form(
            &mut *xml,
            "pubsub#access_model",
            &row.get::<String, _>("access_model"),
        );
        push_form(
            &mut *xml,
            "pubsub#max_items",
            &row.get::<i32, _>("max_items").to_string(),
        );
        push_form(
            &mut *xml,
            "pubsub#persist_items",
            bool_text(row.get("persist_items")),
        );
        push_form(
            &mut *xml,
            "pubsub#send_last_published_item",
            &row.get::<String, _>("send_last_published_item"),
        );
        push_form(
            &mut *xml,
            "pubsub#deliver_notifications",
            bool_text(row.get("deliver_notifications")),
        );
        push_form_values(
            &mut *xml,
            "pubsub#roster_groups_allowed",
            &row.get::<Vec<String>, _>("roster_groups_allowed"),
        );
        push_form_values(
            &mut *xml,
            "northstar#access_whitelist",
            &row.get::<Vec<String>, _>("access_whitelist"),
        );
        xml.push_str("</x></configure>\n");
        let subscriptions = sqlx::query("SELECT subscriber_jid,subid,state FROM pep_subscriptions WHERE owner_id=$1 AND node=$2 ORDER BY subscriber_jid")
            .bind(user_id).bind(&node).fetch_all(pool).await?;
        if !subscriptions.is_empty() {
            xml.push_str(&format!(
                "        <subscriptions node='{}'>\n",
                attr_escape(&node)
            ));
            for subscription in subscriptions {
                *count += 1;
                xml.push_str(&format!(
                    "          <subscription jid='{}' subscription='{}' subid='{}'/>\n",
                    attr_escape(&subscription.get::<String, _>("subscriber_jid")),
                    attr_escape(&subscription.get::<String, _>("state")),
                    attr_escape(&subscription.get::<String, _>("subid"))
                ));
            }
            xml.push_str("        </subscriptions>\n");
        }
    }
    xml.push_str("      </pubsub>\n      <pubsub xmlns='http://jabber.org/protocol/pubsub'>\n");
    for row in nodes {
        let node: String = row.get("node");
        let items = sqlx::query("SELECT item_id,payload FROM pep_items WHERE owner_id=$1 AND node=$2 ORDER BY updated_at,item_id")
            .bind(user_id).bind(&node).fetch_all(pool).await?;
        xml.push_str(&format!("        <items node='{}'>\n", attr_escape(&node)));
        for item in items {
            *count += 1;
            let payload: String = item.get("payload");
            validate_xml_fragment(&payload, "stored PEP payload")?;
            xml.push_str(&format!(
                "          <item id='{}'>{}</item>\n",
                attr_escape(&item.get::<String, _>("item_id")),
                payload
            ));
        }
        xml.push_str("        </items>\n");
    }
    xml.push_str("      </pubsub>\n");
    Ok(())
}

async fn export_mam(
    pool: &PgPool,
    user_id: Uuid,
    xml: &mut String,
    count: &mut usize,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT id,stanza,created_at FROM message_archive WHERE owner_id=$1 ORDER BY created_at,id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    if rows.is_empty() {
        return Ok(());
    }
    xml.push_str("      <archive xmlns='urn:xmpp:pie:0#mam'>\n");
    for row in rows {
        *count += 1;
        let stanza: String = row.get("stanza");
        validate_client_message_fragment(&stanza, "stored MAM stanza")?;
        let id: Uuid = row.get("id");
        let stamp: DateTime<Utc> = row.get("created_at");
        xml.push_str(&format!("        <result xmlns='urn:xmpp:mam:2' id='{id}'><forwarded xmlns='urn:xmpp:forward:0'><delay xmlns='urn:xmpp:delay' stamp='{}'/>{}</forwarded></result>\n", stamp.to_rfc3339(), stanza));
    }
    xml.push_str("      </archive>\n");
    Ok(())
}

async fn import(pool: &PgPool, runtime: &ImportRuntime<'_>, options: &ImportOptions) -> Result<()> {
    let domain = jid::prepare_domainpart(runtime.domain)?;
    let root = secure_root(&options.input, options.root.as_deref())?;
    let input = secure_existing_path(&root, &options.input)?;
    let mut budget = LoadBudget::default();
    let mut document = ImportDocument::default();
    load_server_document(&root, &input, 0, &domain, &mut budget, &mut document)?;
    if document.users.is_empty() {
        bail!("PIE import contains no users for {domain}");
    }
    document
        .users
        .sort_by(|left, right| left.username.cmp(&right.username));
    for window in document.users.windows(2) {
        if window[0].username == window[1].username {
            bail!("PIE contains duplicate user {:?}", window[0].username);
        }
    }
    if options.unknown == UnknownPolicy::Fail && !document.warnings.is_empty() {
        bail!(
            "PIE contains unsupported data:\n{}",
            document.warnings.join("\n")
        );
    }
    for warning in &document.warnings {
        eprintln!("warning: {warning}");
    }
    let mut prepared = Vec::with_capacity(document.users.len());
    for user in document.users {
        prepared.push(prepare_user(
            user,
            runtime.scram_iterations,
            options.allow_plaintext_passwords,
        )?);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await?;
    if options.conflict == ConflictPolicy::Replace {
        // Replacement cascades through upload_slots. Match online account
        // deletion's global-capacity -> domain/user lock order and reject
        // contention quickly instead of occupying a pool connection behind
        // storage admission.
        sqlx::query("SET LOCAL lock_timeout='50ms'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT northstar_upload_capacity_lock()")
            .fetch_one(&mut *tx)
            .await
            .context("upload storage capacity busy; retry PIE replacement")?;
    }
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 227))")
        .bind(&domain)
        .execute(&mut *tx)
        .await?;
    let mut staged = Vec::with_capacity(prepared.len());
    let mut skipped = 0_u64;
    for user in prepared {
        match stage_user_identity(&mut tx, user, options.conflict).await? {
            Some(user) => staged.push(user),
            None => skipped += 1,
        }
    }
    // Every identity exists before dependent state is restored. This makes
    // local pending-presence restoration independent of username sort order.
    for user in &mut staged {
        import_user_data(&mut tx, &domain, user).await?;
    }
    let imported = staged.len() as u64;
    sqlx::query("INSERT INTO audit_log(actor_id,action,target,details) VALUES(NULL,'operator.pie.import',$1,$2)")
        .bind(&domain)
        .bind(serde_json::json!({
            "source":input.file_name().and_then(|name| name.to_str()).unwrap_or("[non-utf8]"),
            "dry_run":options.dry_run,
            "conflict":format!("{:?}", options.conflict).to_ascii_lowercase(),
            "imported":imported,
            "skipped":skipped,
            "warnings":document.warnings.len()
        }))
        .execute(&mut *tx).await?;
    if options.dry_run {
        tx.rollback().await?;
        eprintln!(
            "PIE dry-run validated {imported} user(s), skipped {skipped}, and rolled back every database change"
        );
    } else {
        tx.commit().await?;
        eprintln!("PIE import committed {imported} user(s); skipped {skipped}");
    }
    Ok(())
}

fn prepare_user(user: PieUser, iterations: u32, allow_plaintext: bool) -> Result<PreparedUser> {
    if let Some(password) = user.plaintext_password.as_deref() {
        if !allow_plaintext {
            bail!(
                "PIE user {:?} contains a plaintext password; explicit --allow-plaintext-passwords is required",
                user.username
            );
        }
        let credentials =
            auth::hash_password(password, true, iterations, false).with_context(|| {
                format!(
                    "invalid plaintext password for PIE user {:?}",
                    user.username
                )
            })?;
        let (password_hash, iterations, salt, stored_key, server_key) =
            credentials.into_sha256_parts();
        return Ok(PreparedUser {
            data: user,
            password_hash,
            scram: ScramCredential {
                iterations,
                salt,
                stored_key,
                server_key,
            },
        });
    }
    let scram = user.scram.as_ref().context(format!(
        "PIE user {:?} has neither an allowed plaintext password nor SCRAM-SHA-256 credentials",
        user.username
    ))?;
    Ok(PreparedUser {
        password_hash: SCRAM_ONLY_PASSWORD_HASH.to_owned(),
        scram: ScramCredential {
            iterations: scram.iterations,
            salt: scram.salt.clone(),
            stored_key: scram.stored_key.clone(),
            server_key: scram.server_key.clone(),
        },
        data: user,
    })
}

async fn stage_user_identity(
    tx: &mut Transaction<'_, Postgres>,
    user: PreparedUser,
    conflict: ConflictPolicy,
) -> Result<Option<StagedUser>> {
    let existing = sqlx::query("SELECT id,is_admin FROM users WHERE username=$1 FOR UPDATE")
        .bind(&user.data.username)
        .fetch_optional(&mut **tx)
        .await?;
    if let Some(existing) = existing {
        let existing_id: Uuid = existing.get("id");
        match conflict {
            ConflictPolicy::Fail => bail!("PIE user {:?} already exists", user.data.username),
            ConflictPolicy::Skip => return Ok(None),
            ConflictPolicy::Replace => {
                if existing.get::<bool, _>("is_admin") {
                    bail!(
                        "PIE refuses to replace administrator {:?}; server roles are outside XEP-0227",
                        user.data.username
                    );
                }
                sqlx::query("DELETE FROM users WHERE id=$1")
                    .bind(existing_id)
                    .execute(&mut **tx)
                    .await?;
            }
        }
    }
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash,scram_sha256_salt,scram_sha256_iterations,scram_sha256_stored_key,scram_sha256_server_key) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(user_id).bind(&user.data.username).bind(user.password_hash)
        .bind(user.scram.salt).bind(user.scram.iterations as i32)
        .bind(user.scram.stored_key).bind(user.scram.server_key)
        .execute(&mut **tx).await?;
    Ok(Some(StagedUser {
        id: user_id,
        data: user.data,
    }))
}

async fn import_user_data(
    tx: &mut Transaction<'_, Postgres>,
    domain: &str,
    user: &mut StagedUser,
) -> Result<()> {
    let user_id = user.id;
    for item in std::mem::take(&mut user.data.roster) {
        sqlx::query("INSERT INTO roster_items(owner_id,contact_jid,display_name,subscription,ask,groups,approved) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(user_id).bind(item.jid).bind(item.name).bind(item.subscription).bind(item.ask)
            .bind(serde_json::to_value(item.groups)?).bind(item.approved).execute(&mut **tx).await?;
    }
    if !user.data.offline.is_empty() {
        // Share the same queue-snapshot gate as live C2S/MUC delivery. The
        // administrator's exclusive clear operation must have a precise
        // before/after boundary even while an XEP-0227 import is committing.
        sqlx::query("SELECT pg_advisory_xact_lock_shared(5645368709120102)")
            .execute(&mut **tx)
            .await?;
    }
    for message in std::mem::take(&mut user.data.offline) {
        sqlx::query("INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,target_resource,encrypted,created_at) VALUES($1,$2,$3,$4,$5,$6,COALESCE($7,clock_timestamp()))")
            .bind(Uuid::new_v4()).bind(user_id).bind(message.sender).bind(message.stanza)
            .bind(message.target_resource).bind(message.encrypted).bind(message.created_at)
            .execute(&mut **tx).await?;
    }
    for private in std::mem::take(&mut user.data.private_xml) {
        sqlx::query(
            "INSERT INTO private_xml(user_id,element_name,element_ns,xml_data) VALUES($1,$2,$3,$4)",
        )
        .bind(user_id)
        .bind(private.name)
        .bind(private.namespace)
        .bind(private.xml)
        .execute(&mut **tx)
        .await?;
    }
    if let Some(vcard) = user.data.vcard.take() {
        sqlx::query("INSERT INTO vcards(user_id,payload) VALUES($1,$2)")
            .bind(user_id)
            .bind(vcard)
            .execute(&mut **tx)
            .await?;
    }
    for blocked in std::mem::take(&mut user.data.blocked) {
        sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
            .bind(user_id)
            .bind(blocked)
            .execute(&mut **tx)
            .await?;
    }
    for pending in std::mem::take(&mut user.data.pending) {
        let parsed = jid::CanonicalJid::parse(&pending.from)?;
        if parsed.domainpart() == domain {
            let requester = parsed
                .localpart()
                .context("local pending subscription has no localpart")?;
            let requester_id: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM users WHERE username=$1")
                    .bind(requester)
                    .fetch_optional(&mut **tx)
                    .await?;
            if let Some(requester_id) = requester_id {
                if requester_id != user_id {
                    sqlx::query("INSERT INTO pending_presence_subscriptions(requester_id,recipient_id,stanza) VALUES($1,$2,$3) ON CONFLICT(requester_id,recipient_id) DO UPDATE SET stanza=EXCLUDED.stanza")
                        .bind(requester_id).bind(user_id).bind(pending.stanza).execute(&mut **tx).await?;
                }
            } else {
                sqlx::query("INSERT INTO federated_presence_pending(recipient_id,from_jid,stanza) VALUES($1,$2,$3) ON CONFLICT(recipient_id,from_jid) DO UPDATE SET stanza=EXCLUDED.stanza")
                    .bind(user_id).bind(pending.from).bind(pending.stanza).execute(&mut **tx).await?;
            }
        } else {
            sqlx::query("INSERT INTO federated_presence_pending(recipient_id,from_jid,stanza) VALUES($1,$2,$3) ON CONFLICT(recipient_id,from_jid) DO UPDATE SET stanza=EXCLUDED.stanza")
                .bind(user_id).bind(pending.from).bind(pending.stanza).execute(&mut **tx).await?;
        }
    }
    for (node_name, node) in std::mem::take(&mut user.data.pep_nodes) {
        sqlx::query("INSERT INTO pep_nodes(owner_id,node,access_model,max_items,persist_items,send_last_published_item,deliver_notifications,roster_groups_allowed,access_whitelist) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(user_id).bind(&node_name).bind(node.access_model).bind(node.max_items)
            .bind(node.persist_items).bind(node.send_last).bind(node.deliver_notifications)
            .bind(node.roster_groups_allowed).bind(node.access_whitelist).execute(&mut **tx).await?;
        for subscription in node.subscriptions {
            sqlx::query("INSERT INTO pep_subscriptions(owner_id,node,subscriber_jid,subid,state) VALUES($1,$2,$3,$4,$5)")
                .bind(user_id).bind(&node_name).bind(subscription.jid).bind(subscription.subid).bind(subscription.state).execute(&mut **tx).await?;
        }
        for item in node.items {
            sqlx::query("INSERT INTO pep_items(owner_id,node,item_id,payload) VALUES($1,$2,$3,$4)")
                .bind(user_id)
                .bind(&node_name)
                .bind(item.id)
                .bind(item.payload)
                .execute(&mut **tx)
                .await?;
        }
    }
    for item in std::mem::take(&mut user.data.archive) {
        sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(Uuid::new_v4()).bind(user_id).bind(item.peer_jid).bind(item.peer_full_jid)
            .bind(item.stanza).bind(item.encrypted).bind(item.result_id).bind(item.created_at).execute(&mut **tx).await?;
    }
    Ok(())
}

fn secure_root(input: &Path, root: Option<&Path>) -> Result<PathBuf> {
    let requested = root.map(Path::to_path_buf).unwrap_or_else(|| {
        input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    if fs::symlink_metadata(&requested)?.file_type().is_symlink() {
        bail!("PIE security root must not be a symlink");
    }
    requested
        .canonicalize()
        .context("could not resolve PIE security root")
}

fn secure_existing_path(root: &Path, requested: &Path) -> Result<PathBuf> {
    let candidate = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()?.join(requested)
    };
    if !candidate.starts_with(root) {
        bail!("PIE input path must be lexically below the configured security root");
    }
    // Inspect the path exactly as supplied before canonicalization. Once a
    // symlink has been canonicalized its identity is lost, so checking only
    // the resolved path would silently accept a link whose target remains
    // inside the security root.
    reject_symlink_components(root, &candidate)?;
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("could not resolve {}", candidate.display()))?;
    if !canonical.starts_with(root) {
        bail!("PIE input escapes the configured security root");
    }
    if !canonical.is_file() {
        bail!("PIE input is not a regular file");
    }
    Ok(canonical)
}

fn reject_symlink_components(root: &Path, path: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .context("path escaped security root")?;
    if relative.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        bail!("PIE path contains a non-local path component");
    }
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current)?.file_type().is_symlink() {
            bail!("PIE refuses symlink path component {}", current.display());
        }
    }
    Ok(())
}

fn resolve_include(root: &Path, parent: &Path, href: &str) -> Result<PathBuf> {
    if href.is_empty() || href.contains(['?', '#', '\\']) || href.contains("://") {
        bail!("unsafe XInclude href {href:?}");
    }
    let decoded = percent_decode(href)?;
    let relative = Path::new(&decoded);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("XInclude href must be a relative URI below the security root");
    }
    let candidate = parent
        .parent()
        .context("XInclude parent has no directory")?
        .join(relative);
    if !candidate.starts_with(root) {
        bail!("XInclude {href:?} escapes the security root");
    }
    // Check the unresolved candidate. Canonicalization follows symlinks and
    // therefore cannot be used to prove that the original include path was
    // link-free.
    reject_symlink_components(root, &candidate)?;
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("could not resolve XInclude {href:?}"))?;
    if !canonical.starts_with(root) {
        bail!("XInclude {href:?} escapes the security root");
    }
    if !canonical.is_file() {
        bail!("XInclude {href:?} is not a regular file");
    }
    Ok(canonical)
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = *bytes.get(index + 1).context("truncated percent escape")?;
            let lo = *bytes.get(index + 2).context("truncated percent escape")?;
            decoded.push((hex(hi)? << 4) | hex(lo)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let value = String::from_utf8(decoded).context("XInclude href is not UTF-8")?;
    if value.contains('\0') {
        bail!("XInclude href contains NUL");
    }
    Ok(value)
}

fn hex(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => bail!("invalid percent escape"),
    }
}

fn read_xml(path: &Path, budget: &mut LoadBudget) -> Result<String> {
    if budget.files >= MAX_FILES {
        bail!("PIE exceeds the {MAX_FILES} file limit");
    }
    if !budget.seen.insert(path.to_path_buf()) {
        bail!(
            "PIE contains an XInclude cycle or duplicate include: {}",
            path.display()
        );
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_FILE_BYTES {
        bail!(
            "PIE file {} exceeds {} MiB",
            path.display(),
            MAX_FILE_BYTES / 1024 / 1024
        );
    }
    budget.total_bytes = budget
        .total_bytes
        .checked_add(metadata.len())
        .context("PIE byte counter overflow")?;
    if budget.total_bytes > MAX_TOTAL_BYTES {
        bail!(
            "PIE input exceeds {} MiB total",
            MAX_TOTAL_BYTES / 1024 / 1024
        );
    }
    budget.files += 1;
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        bail!("PIE file grew beyond its size limit while reading");
    }
    let xml = String::from_utf8(bytes).context("PIE XML is not UTF-8")?;
    reject_dtd(&xml)?;
    Ok(xml)
}

fn load_server_document(
    root: &Path,
    path: &Path,
    depth: usize,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    include_depth(depth)?;
    let xml = read_xml(path, budget)?;
    let document = parse_bounded(&xml, path, budget)?;
    let root_node = document.root_element();
    if root_node.tag_name().name() != "server-data"
        || root_node.tag_name().namespace() != Some(PIE_NS)
    {
        bail!("PIE root must be server-data in {PIE_NS}");
    }
    for child in element_children(root_node)? {
        if is_include(child) {
            let include = parse_include(root, path, child)?;
            load_host_document(root, &include, depth + 1, domain, budget, output)?;
        } else if child.tag_name().name() == "host" && child.tag_name().namespace() == Some(PIE_NS)
        {
            parse_host(root, path, child, depth, domain, budget, output)?;
        } else {
            unsupported(
                output,
                format!(
                    "unsupported server-data child {{{}}}{}",
                    child.tag_name().namespace().unwrap_or(""),
                    child.tag_name().name()
                ),
            );
        }
    }
    Ok(())
}

fn load_host_document(
    root: &Path,
    path: &Path,
    depth: usize,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    include_depth(depth)?;
    let xml = read_xml(path, budget)?;
    let document = parse_bounded(&xml, path, budget)?;
    let node = document.root_element();
    if node.tag_name().name() != "host" || node.tag_name().namespace() != Some(PIE_NS) {
        bail!("server-data XInclude must resolve to one PIE host element");
    }
    parse_host(root, path, node, depth, domain, budget, output)
}

fn parse_host(
    root: &Path,
    path: &Path,
    node: Node<'_, '_>,
    depth: usize,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    only_attributes(node, &["jid"])?;
    let host = node.attribute("jid").context("PIE host is missing jid")?;
    let parsed = jid::CanonicalJid::parse_bare(host)?;
    if parsed.localpart().is_some() || parsed.domainpart() != domain {
        bail!("PIE host {host:?} does not exactly match configured domain {domain:?}");
    }
    for child in element_children(node)? {
        if is_include(child) {
            let include = parse_include(root, path, child)?;
            load_user_document(root, &include, depth + 1, domain, budget, output)?;
        } else if child.tag_name().name() == "user" && child.tag_name().namespace() == Some(PIE_NS)
        {
            push_user(child, domain, budget, output)?;
        } else {
            unsupported(
                output,
                format!(
                    "unsupported host child {{{}}}{}",
                    child.tag_name().namespace().unwrap_or(""),
                    child.tag_name().name()
                ),
            );
        }
    }
    Ok(())
}

fn load_user_document(
    _root: &Path,
    path: &Path,
    depth: usize,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    include_depth(depth)?;
    let xml = read_xml(path, budget)?;
    let document = parse_bounded(&xml, path, budget)?;
    let node = document.root_element();
    if node.tag_name().name() != "user" || node.tag_name().namespace() != Some(PIE_NS) {
        bail!("host XInclude must resolve to one PIE user element");
    }
    push_user(node, domain, budget, output)
}

fn push_user(
    node: Node<'_, '_>,
    domain: &str,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    budget.users += 1;
    if budget.users > MAX_USERS {
        bail!("PIE exceeds the {MAX_USERS} user limit");
    }
    only_attributes(node, &["name", "password"])?;
    let raw_name = node.attribute("name").context("PIE user is missing name")?;
    let username = auth::normalize_username(raw_name)?;
    if username != raw_name {
        bail!("PIE user name {raw_name:?} is not canonical");
    }
    let mut user = PieUser {
        username,
        plaintext_password: node.attribute("password").map(ToOwned::to_owned),
        ..Default::default()
    };
    let account_username = user.username.clone();
    for child in element_children(node)? {
        match (
            child.tag_name().namespace().unwrap_or(""),
            child.tag_name().name(),
        ) {
            (SCRAM_NS, "scram-credentials") => parse_scram(child, &mut user, output)?,
            (ROSTER_NS, "query") => parse_roster(child, &mut user, budget)?,
            (PIE_NS, "offline-messages") => parse_offline(
                child,
                &format!("{account_username}@{domain}"),
                &mut user,
                budget,
            )?,
            (PRIVATE_NS, "query") => parse_private(child, &mut user, budget)?,
            ("vcard-temp", "vCard") => {
                item(budget)?;
                if user.vcard.replace(node_to_xml(child)).is_some() {
                    bail!("duplicate vCard for PIE user");
                }
            }
            (PRIVACY_NS, "query") => parse_privacy(child, &mut user, budget, output)?,
            (CLIENT_NS, "presence") => parse_pending(child, domain, &mut user, budget)?,
            (PUBSUB_OWNER_NS, "pubsub") => parse_pep_owner(child, &mut user, budget, output)?,
            (PUBSUB_NS, "pubsub") => parse_pep_items(child, &mut user, budget)?,
            (MAM_PIE_NS, "archive") => {
                parse_archive(child, &account_username, domain, &mut user, budget)?
            }
            (XINCLUDE_NS, "include") => unsupported(
                output,
                "XInclude below a user is opaque user data and was not processed".to_owned(),
            ),
            (namespace, name) => unsupported(
                output,
                format!("unsupported user child {{{namespace}}}{name}"),
            ),
        }
    }
    output.users.push(user);
    Ok(())
}

fn parse_scram(node: Node<'_, '_>, user: &mut PieUser, output: &mut ImportDocument) -> Result<()> {
    only_attributes(node, &["mechanism"])?;
    let mechanism = node
        .attribute("mechanism")
        .context("SCRAM credentials missing mechanism")?;
    if mechanism != "SCRAM-SHA-256" {
        unsupported(
            output,
            format!("SCRAM mechanism {mechanism:?} is not supported by Northstar"),
        );
        return Ok(());
    }
    if user.scram.is_some() {
        bail!("duplicate SCRAM-SHA-256 credentials");
    }
    let values = exact_text_children(
        node,
        &["iter-count", "salt", "server-key", "stored-key"],
        SCRAM_NS,
    )?;
    let iteration_text = values
        .get("iter-count")
        .context("SCRAM iter-count missing")?;
    if iteration_text.starts_with('0') || !iteration_text.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid SCRAM iter-count syntax");
    }
    let iterations: u32 = iteration_text.parse()?;
    if !(auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS).contains(&iterations) {
        bail!("SCRAM iteration count is outside Northstar's safe bounds");
    }
    let salt = decode_b64(
        values.get("salt").context("SCRAM salt missing")?,
        16,
        1024,
        "SCRAM salt",
    )?;
    let stored_key = decode_b64(
        values
            .get("stored-key")
            .context("SCRAM stored-key missing")?,
        32,
        32,
        "SCRAM stored-key",
    )?;
    let server_key = decode_b64(
        values
            .get("server-key")
            .context("SCRAM server-key missing")?,
        32,
        32,
        "SCRAM server-key",
    )?;
    user.scram = Some(ScramCredential {
        iterations,
        salt,
        stored_key,
        server_key,
    });
    Ok(())
}

fn parse_roster(node: Node<'_, '_>, user: &mut PieUser, budget: &mut LoadBudget) -> Result<()> {
    only_attributes(node, &[])?;
    for child in element_children(node)? {
        if child.tag_name().namespace() != Some(ROSTER_NS) || child.tag_name().name() != "item" {
            bail!("roster query contains a non-item element");
        }
        item(budget)?;
        only_attributes(child, &["jid", "name", "subscription", "ask", "approved"])?;
        let contact =
            jid::canonicalize_bare(child.attribute("jid").context("roster item missing jid")?)?;
        let subscription = child.attribute("subscription").unwrap_or("none");
        if !matches!(subscription, "none" | "to" | "from" | "both") {
            bail!("invalid roster subscription");
        }
        let ask = child.attribute("ask").map(ToOwned::to_owned);
        if ask.as_deref().is_some_and(|value| value != "subscribe") {
            bail!("invalid roster ask value");
        }
        let approved = match child.attribute("approved") {
            None | Some("false") | Some("0") => false,
            Some("true") | Some("1") => true,
            Some(_) => bail!("invalid roster approved value"),
        };
        let mut groups = Vec::new();
        for group in element_children(child)? {
            if group.tag_name().namespace() != Some(ROSTER_NS)
                || group.tag_name().name() != "group"
                || group.attributes().len() != 0
                || group.children().any(|n| n.is_element())
            {
                bail!("invalid roster group");
            }
            let value = group.text().unwrap_or("").to_owned();
            if value.len() > 1024 {
                bail!("roster group exceeds 1024 bytes");
            }
            groups.push(value);
        }
        groups.sort();
        groups.dedup();
        user.roster.push(RosterItem {
            jid: contact,
            name: child.attribute("name").map(ToOwned::to_owned),
            subscription: subscription.to_owned(),
            ask,
            groups,
            approved,
        });
    }
    Ok(())
}

fn parse_offline(
    node: Node<'_, '_>,
    account: &str,
    user: &mut PieUser,
    budget: &mut LoadBudget,
) -> Result<()> {
    only_attributes(node, &[])?;
    for message in element_children(node)? {
        item(budget)?;
        validate_message_node(message)?;
        let raw_recipient = message
            .attribute("to")
            .context("offline message missing to")?;
        let recipient = jid::CanonicalJid::parse(raw_recipient)?;
        if recipient.to_string() != raw_recipient {
            bail!("offline message recipient must already be canonical");
        }
        if recipient.bare() != account {
            bail!("offline message is addressed to another account");
        }
        let target_resource = if message.attribute("type").unwrap_or("normal") == "normal" {
            recipient.resourcepart().map(str::to_owned)
        } else {
            None
        };
        let sender = jid::canonicalize(
            message
                .attribute("from")
                .context("offline message missing from")?,
        )?;
        let stanza = node_to_xml(message);
        bound_xml(&stanza, "offline stanza")?;
        user.offline.push(OfflineMessage {
            sender,
            encrypted: stanza_is_encrypted(message),
            created_at: delay_stamp(message)?,
            stanza,
            target_resource,
        });
    }
    Ok(())
}

fn parse_private(node: Node<'_, '_>, user: &mut PieUser, budget: &mut LoadBudget) -> Result<()> {
    only_attributes(node, &[])?;
    for child in element_children(node)? {
        item(budget)?;
        let namespace = child
            .tag_name()
            .namespace()
            .context("private XML child must have a namespace")?
            .to_owned();
        if namespace == PRIVATE_NS {
            bail!("private XML child must use its own namespace");
        }
        let xml = node_to_xml(child);
        bound_xml(&xml, "private XML item")?;
        user.private_xml.push(PrivateXml {
            name: child.tag_name().name().to_owned(),
            namespace,
            xml,
        });
    }
    Ok(())
}

fn parse_privacy(
    node: Node<'_, '_>,
    user: &mut PieUser,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    only_attributes(node, &[])?;
    let children = element_children(node)?;
    let defaults: Vec<_> = children
        .iter()
        .copied()
        .filter(|child| {
            child.tag_name().namespace() == Some(PRIVACY_NS) && child.tag_name().name() == "default"
        })
        .collect();
    if defaults.len() > 1 {
        bail!("privacy query contains duplicate default selections");
    }
    let selected = defaults
        .first()
        .and_then(|child| child.attribute("name"))
        .map(ToOwned::to_owned);
    for child in children {
        if child.tag_name().namespace() != Some(PRIVACY_NS) {
            bail!("privacy query contains foreign child");
        }
        match child.tag_name().name() {
            "default" => {
                only_attributes(child, &["name"])?;
            }
            "active" => unsupported(
                output,
                "XEP-0016 active privacy-list state is session-specific and was ignored".to_owned(),
            ),
            "list" => {
                only_attributes(child, &["name"])?;
                let name = child
                    .attribute("name")
                    .context("privacy list missing name")?;
                if selected.as_deref().is_some_and(|selected| selected != name)
                    && name != "northstar-blocklist"
                {
                    unsupported(
                        output,
                        format!(
                            "privacy list {name:?} is not the selected Northstar blocklist and was ignored"
                        ),
                    );
                    continue;
                }
                for entry in element_children(child)? {
                    item(budget)?;
                    only_attributes(entry, &["type", "value", "action", "order"])?;
                    if entry.tag_name().name() != "item"
                        || entry.tag_name().namespace() != Some(PRIVACY_NS)
                    {
                        bail!("privacy list contains a non-item element");
                    }
                    let action = entry
                        .attribute("action")
                        .context("privacy item missing action")?;
                    if action == "allow"
                        && entry.attribute("type").is_none()
                        && !entry.children().any(|n| n.is_element())
                    {
                        continue;
                    }
                    if action != "deny"
                        || entry.attribute("type") != Some("jid")
                        || entry.children().any(|n| n.is_element())
                    {
                        unsupported(
                            output,
                            "a privacy-list rule cannot be represented by XEP-0191 and was ignored"
                                .to_owned(),
                        );
                        continue;
                    }
                    user.blocked.push(jid::canonicalize(
                        entry
                            .attribute("value")
                            .context("privacy JID rule missing value")?,
                    )?);
                }
            }
            other => unsupported(output, format!("privacy child {other:?} was ignored")),
        }
    }
    user.blocked.sort();
    user.blocked.dedup();
    Ok(())
}

fn parse_pending(
    node: Node<'_, '_>,
    domain: &str,
    user: &mut PieUser,
    budget: &mut LoadBudget,
) -> Result<()> {
    item(budget)?;
    validate_message_like_attributes(node)?;
    if node.attribute("type") != Some("subscribe") {
        bail!("PIE pending presence must have type='subscribe'");
    }
    let from = jid::canonicalize_bare(
        node.attribute("from")
            .context("pending presence missing from")?,
    )?;
    if let Some(to) = node.attribute("to") {
        let expected = format!("{}@{domain}", user.username);
        if jid::canonical_bare_key(to)? != expected {
            bail!("pending presence is addressed to another account");
        }
    }
    let stanza = node_to_xml(node);
    bound_xml(&stanza, "pending presence")?;
    user.pending.push(PendingPresence { from, stanza });
    Ok(())
}

fn parse_pep_owner(
    node: Node<'_, '_>,
    user: &mut PieUser,
    budget: &mut LoadBudget,
    output: &mut ImportDocument,
) -> Result<()> {
    only_attributes(node, &[])?;
    let children = element_children(node)?;
    // XEP-0227 does not assign semantic meaning to sibling ordering. Build
    // node configurations before applying subscriptions even when an export
    // places <subscriptions/> first.
    for child in children.iter().copied().filter(|child| {
        child.tag_name().namespace() == Some(PUBSUB_OWNER_NS)
            && child.tag_name().name() == "configure"
    }) {
        match child.tag_name().name() {
            "configure" if child.tag_name().namespace() == Some(PUBSUB_OWNER_NS) => {
                item(budget)?;
                only_attributes(child, &["node"])?;
                let name = bounded_identifier(
                    child
                        .attribute("node")
                        .context("PEP configure missing node")?,
                    1024,
                    "PEP node",
                )?;
                if user.pep_nodes.contains_key(&name) {
                    bail!("duplicate PEP node configuration {name:?}");
                }
                let form = element_children(child)?;
                let [form] = form.as_slice() else {
                    bail!("PEP configure must contain exactly one data form");
                };
                let fields = parse_form(*form)?;
                let mut config = PepNode::default();
                if let Some(value) = first(&fields, "pubsub#access_model") {
                    config.access_model = value.to_owned();
                }
                if !matches!(
                    config.access_model.as_str(),
                    "open" | "presence" | "roster" | "whitelist"
                ) {
                    bail!("unsupported PEP access model");
                }
                if let Some(value) = first(&fields, "pubsub#max_items") {
                    config.max_items = value.parse()?;
                }
                if !(1..=100).contains(&config.max_items) {
                    bail!("PEP max_items exceeds Northstar bounds");
                }
                if let Some(value) = first(&fields, "pubsub#persist_items") {
                    config.persist_items = parse_bool(value)?;
                }
                if let Some(value) = first(&fields, "pubsub#send_last_published_item") {
                    config.send_last = value.to_owned();
                }
                if !matches!(
                    config.send_last.as_str(),
                    "never" | "on_sub" | "on_sub_and_presence"
                ) {
                    bail!("invalid PEP send_last_published_item");
                }
                if let Some(value) = first(&fields, "pubsub#deliver_notifications") {
                    config.deliver_notifications = parse_bool(value)?;
                }
                config.roster_groups_allowed = fields
                    .get("pubsub#roster_groups_allowed")
                    .cloned()
                    .unwrap_or_default();
                config.access_whitelist = fields
                    .get("northstar#access_whitelist")
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|value| jid::canonicalize_bare(&value))
                    .collect::<Result<_>>()?;
                for key in fields.keys() {
                    if !matches!(
                        key.as_str(),
                        "FORM_TYPE"
                            | "pubsub#access_model"
                            | "pubsub#max_items"
                            | "pubsub#persist_items"
                            | "pubsub#send_last_published_item"
                            | "pubsub#deliver_notifications"
                            | "pubsub#roster_groups_allowed"
                            | "northstar#access_whitelist"
                    ) {
                        unsupported(
                            output,
                            format!(
                                "PEP configuration field {key:?} is not persisted by Northstar"
                            ),
                        );
                    }
                }
                user.pep_nodes.insert(name, config);
            }
            _ => unreachable!("configure-only first pass"),
        }
    }
    for child in children.into_iter().filter(|child| {
        !(child.tag_name().namespace() == Some(PUBSUB_OWNER_NS)
            && child.tag_name().name() == "configure")
    }) {
        match child.tag_name().name() {
            "subscriptions" if child.tag_name().namespace() == Some(PUBSUB_OWNER_NS) => {
                only_attributes(child, &["node"])?;
                let name = child
                    .attribute("node")
                    .context("PEP subscriptions missing node")?
                    .to_owned();
                let config = user
                    .pep_nodes
                    .get_mut(&name)
                    .context("PEP subscriptions lack node configuration")?;
                for subscription in element_children(child)? {
                    item(budget)?;
                    only_attributes(subscription, &["jid", "subscription", "subid"])?;
                    let state = subscription
                        .attribute("subscription")
                        .unwrap_or("subscribed");
                    if !matches!(state, "subscribed" | "pending") {
                        unsupported(
                            output,
                            format!("PEP subscription state {state:?} was ignored"),
                        );
                        continue;
                    }
                    let subscriber = jid::canonicalize(
                        subscription
                            .attribute("jid")
                            .context("PEP subscription missing jid")?,
                    )?;
                    let subid = subscription
                        .attribute("subid")
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| Uuid::new_v4().to_string());
                    bounded_identifier(&subid, 128, "PEP subid")?;
                    config.subscriptions.push(PepSubscription {
                        jid: subscriber,
                        subid,
                        state: state.to_owned(),
                    });
                }
            }
            "affiliations" if child.tag_name().namespace() == Some(PUBSUB_OWNER_NS) => {
                unsupported(output, "PEP affiliations other than Northstar's implicit owner/access-whitelist model were ignored".to_owned());
            }
            other => unsupported(output, format!("unsupported PEP owner element {other:?}")),
        }
    }
    Ok(())
}

fn parse_pep_items(node: Node<'_, '_>, user: &mut PieUser, budget: &mut LoadBudget) -> Result<()> {
    only_attributes(node, &[])?;
    for items in element_children(node)? {
        if items.tag_name().namespace() != Some(PUBSUB_NS) || items.tag_name().name() != "items" {
            bail!("PEP pubsub contains non-items child");
        }
        only_attributes(items, &["node"])?;
        let name = items.attribute("node").context("PEP items missing node")?;
        let config = user
            .pep_nodes
            .get_mut(name)
            .context("PEP items have no corresponding node configuration")?;
        for entry in element_children(items)? {
            item(budget)?;
            if entry.tag_name().namespace() != Some(PUBSUB_NS) || entry.tag_name().name() != "item"
            {
                bail!("PEP items contains non-item child");
            }
            only_attributes(entry, &["id", "publisher"])?;
            let id = bounded_identifier(
                entry.attribute("id").context("PEP item missing id")?,
                1024,
                "PEP item id",
            )?;
            let children = element_children(entry)?;
            let [payload] = children.as_slice() else {
                bail!("Northstar PEP item import requires exactly one payload element");
            };
            let payload = node_to_xml(*payload);
            bound_xml(&payload, "PEP payload")?;
            config.items.push(PepItem { id, payload });
        }
        if config.items.len() > config.max_items as usize {
            bail!("PEP node {name:?} contains more items than max_items");
        }
    }
    Ok(())
}

fn parse_archive(
    node: Node<'_, '_>,
    username: &str,
    domain: &str,
    user: &mut PieUser,
    budget: &mut LoadBudget,
) -> Result<()> {
    only_attributes(node, &[])?;
    let account = format!("{username}@{domain}");
    let mut previous = None;
    for result in element_children(node)? {
        item(budget)?;
        if result.tag_name().namespace() != Some("urn:xmpp:mam:2")
            || result.tag_name().name() != "result"
        {
            bail!("PIE MAM archive contains a non-result element");
        }
        only_attributes(result, &["id", "queryid"])?;
        let result_id = bounded_identifier(
            result.attribute("id").context("MAM result missing id")?,
            1024,
            "MAM result id",
        )?;
        let forwarded = element_children(result)?;
        let [forwarded] = forwarded.as_slice() else {
            bail!("MAM result must contain exactly one forwarded element");
        };
        if forwarded.tag_name().namespace() != Some("urn:xmpp:forward:0")
            || forwarded.tag_name().name() != "forwarded"
        {
            bail!("MAM result child is not forwarded");
        }
        let children = element_children(*forwarded)?;
        let delay = children
            .iter()
            .find(|child| {
                child.tag_name().namespace() == Some("urn:xmpp:delay")
                    && child.tag_name().name() == "delay"
            })
            .context("MAM forwarded element missing delay")?;
        only_attributes(*delay, &["stamp", "from"])?;
        let created_at = DateTime::parse_from_rfc3339(
            delay
                .attribute("stamp")
                .context("MAM delay missing stamp")?,
        )?
        .with_timezone(&Utc);
        if previous.is_some_and(|previous| created_at < previous) {
            bail!("MAM results are not in chronological order");
        }
        previous = Some(created_at);
        let message = children
            .iter()
            .find(|child| {
                child.tag_name().namespace() == Some(CLIENT_NS)
                    && child.tag_name().name() == "message"
            })
            .context("MAM forwarded element missing jabber:client message")?;
        validate_message_node(*message)?;
        let from_full = message
            .attribute("from")
            .map(jid::canonicalize)
            .transpose()?;
        let to_full = message.attribute("to").map(jid::canonicalize).transpose()?;
        let from_bare = from_full
            .as_deref()
            .map(jid::canonical_bare_key)
            .transpose()?;
        let to_bare = to_full
            .as_deref()
            .map(jid::canonical_bare_key)
            .transpose()?;
        let peer_full_jid = if from_bare.as_deref() == Some(&account) {
            to_full.context("outgoing MAM message missing to")?
        } else if to_bare.as_deref() == Some(&account) {
            from_full.context("incoming MAM message missing from")?
        } else {
            bail!("MAM message does not belong to imported account");
        };
        let peer_jid = jid::canonical_bare_key(&peer_full_jid)?;
        let stanza = node_to_xml(*message);
        bound_xml(&stanza, "MAM stanza")?;
        user.archive.push(ArchiveItem {
            result_id,
            peer_jid,
            peer_full_jid,
            encrypted: stanza_is_encrypted(*message),
            stanza,
            created_at,
        });
    }
    Ok(())
}

fn parse_include(root: &Path, parent: &Path, node: Node<'_, '_>) -> Result<PathBuf> {
    only_attributes(node, &["href"])?;
    if node.attribute("parse").is_some() || node.attribute("xpointer").is_some() {
        bail!("PIE only supports XInclude without parse or xpointer");
    }
    if node
        .children()
        .any(|child| child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        bail!("XInclude fallback/content is not supported");
    }
    resolve_include(
        root,
        parent,
        node.attribute("href").context("XInclude missing href")?,
    )
}

fn parse_bounded<'a>(xml: &'a str, path: &Path, budget: &mut LoadBudget) -> Result<Document<'a>> {
    let document =
        Document::parse(xml).with_context(|| format!("malformed XML in {}", path.display()))?;
    let mut local_nodes = 0_usize;
    let mut max_depth = 0_usize;
    for node in document.descendants() {
        local_nodes += 1;
        let depth = node.ancestors().count();
        max_depth = max_depth.max(depth);
    }
    if max_depth > MAX_XML_DEPTH {
        bail!("PIE XML nesting exceeds {MAX_XML_DEPTH}");
    }
    budget.nodes = budget
        .nodes
        .checked_add(local_nodes)
        .context("PIE node counter overflow")?;
    if budget.nodes > MAX_XML_NODES {
        bail!("PIE exceeds the {MAX_XML_NODES} XML-node limit");
    }
    Ok(document)
}

fn reject_dtd(xml: &str) -> Result<()> {
    let upper = xml.to_ascii_uppercase();
    if upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY") {
        bail!("PIE rejects DTD and entity declarations");
    }
    Ok(())
}

fn validate_xml_document(xml: &str, label: &str) -> Result<()> {
    reject_dtd(xml)?;
    Document::parse(xml).with_context(|| format!("{label} is not well-formed XML"))?;
    Ok(())
}

fn validate_xml_fragment(xml: &str, label: &str) -> Result<()> {
    bound_xml(xml, label)?;
    validate_xml_document(xml, label)
}

fn validate_client_message_fragment(xml: &str, label: &str) -> Result<()> {
    validate_xml_fragment(xml, label)?;
    let document = Document::parse(xml)?;
    validate_message_node(document.root_element())
}

fn bound_xml(xml: &str, label: &str) -> Result<()> {
    if xml.is_empty() || xml.len() > MAX_STANZA_BYTES {
        bail!("{label} must contain 1 to {MAX_STANZA_BYTES} bytes");
    }
    Ok(())
}

fn element_children<'a, 'input>(node: Node<'a, 'input>) -> Result<Vec<Node<'a, 'input>>> {
    if node.children().any(|child| {
        !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
    }) {
        bail!("unexpected character data below {}", node.tag_name().name());
    }
    Ok(node.children().filter(Node::is_element).collect())
}

fn only_attributes(node: Node<'_, '_>, allowed: &[&str]) -> Result<()> {
    for attribute in node.attributes() {
        if !allowed.contains(&attribute.name()) {
            bail!(
                "unexpected attribute {:?} on {}",
                attribute.name(),
                node.tag_name().name()
            );
        }
    }
    Ok(())
}

fn is_include(node: Node<'_, '_>) -> bool {
    node.tag_name().name() == "include" && node.tag_name().namespace() == Some(XINCLUDE_NS)
}

fn include_depth(depth: usize) -> Result<()> {
    if depth > MAX_INCLUDE_DEPTH {
        bail!("PIE XInclude depth exceeds {MAX_INCLUDE_DEPTH}");
    }
    Ok(())
}

fn item(budget: &mut LoadBudget) -> Result<()> {
    budget.items += 1;
    enforce_items(budget.items)
}

fn enforce_items(items: usize) -> Result<()> {
    if items > MAX_ITEMS {
        bail!("PIE exceeds the {MAX_ITEMS} item limit");
    }
    Ok(())
}

fn unsupported(output: &mut ImportDocument, message: String) {
    if !output.warnings.contains(&message) {
        output.warnings.push(message);
    }
}

fn decode_b64(value: &str, min: usize, max: usize, label: &str) -> Result<Vec<u8>> {
    let decoded = BASE64
        .decode(value)
        .with_context(|| format!("invalid base64 in {label}"))?;
    if !(min..=max).contains(&decoded.len()) {
        bail!("{label} decoded length is outside {min}..={max}");
    }
    Ok(decoded)
}

fn exact_text_children(
    node: Node<'_, '_>,
    expected: &[&str],
    namespace: &str,
) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for child in element_children(node)? {
        if child.tag_name().namespace() != Some(namespace)
            || !expected.contains(&child.tag_name().name())
            || child.attributes().len() != 0
            || child.children().any(|n| n.is_element())
        {
            bail!("invalid child in {}", node.tag_name().name());
        }
        if values
            .insert(
                child.tag_name().name().to_owned(),
                child.text().unwrap_or("").to_owned(),
            )
            .is_some()
        {
            bail!("duplicate child {}", child.tag_name().name());
        }
    }
    if values.len() != expected.len() {
        bail!("{} is missing a required child", node.tag_name().name());
    }
    Ok(values)
}

fn bounded_identifier(value: &str, max: usize, label: &str) -> Result<String> {
    if value.is_empty() || value.len() > max {
        bail!("{label} must contain 1 to {max} bytes");
    }
    Ok(value.to_owned())
}

fn validate_message_node(node: Node<'_, '_>) -> Result<()> {
    if node.tag_name().name() != "message" || node.tag_name().namespace() != Some(CLIENT_NS) {
        bail!("expected a jabber:client message");
    }
    validate_message_like_attributes(node)
}

fn validate_message_like_attributes(node: Node<'_, '_>) -> Result<()> {
    for attribute in node.attributes() {
        if !matches!(attribute.name(), "from" | "to" | "type" | "id" | "lang") {
            bail!("unexpected stanza attribute {:?}", attribute.name());
        }
    }
    Ok(())
}

fn delay_stamp(node: Node<'_, '_>) -> Result<Option<DateTime<Utc>>> {
    node.descendants()
        .find(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:xmpp:delay")
                && child.tag_name().name() == "delay"
        })
        .and_then(|delay| delay.attribute("stamp"))
        .map(|stamp| {
            DateTime::parse_from_rfc3339(stamp)
                .map(|stamp| stamp.with_timezone(&Utc))
                .map_err(Into::into)
        })
        .transpose()
}

fn stanza_is_encrypted(node: Node<'_, '_>) -> bool {
    node.children().filter(Node::is_element).any(|child| {
        matches!(
            child.tag_name().namespace(),
            Some("urn:xmpp:omemo:2") | Some("eu.siacs.conversations.axolotl")
        )
    })
}

fn parse_form(node: Node<'_, '_>) -> Result<BTreeMap<String, Vec<String>>> {
    if node.tag_name().namespace() != Some("jabber:x:data")
        || node.tag_name().name() != "x"
        || !matches!(node.attribute("type"), Some("form" | "submit" | "result"))
    {
        bail!("invalid PEP configuration data form");
    }
    let mut output = BTreeMap::new();
    for field in element_children(node)? {
        if field.tag_name().namespace() != Some("jabber:x:data")
            || field.tag_name().name() != "field"
        {
            bail!("data form contains non-field child");
        }
        let var = field
            .attribute("var")
            .context("data-form field missing var")?
            .to_owned();
        if output.contains_key(&var) {
            bail!("duplicate data-form field {var:?}");
        }
        let mut values = Vec::new();
        for value in element_children(field)? {
            if value.tag_name().namespace() != Some("jabber:x:data")
                || value.tag_name().name() != "value"
                || value.children().any(|n| n.is_element())
            {
                bail!("invalid data-form value");
            }
            values.push(value.text().unwrap_or("").to_owned());
        }
        output.insert(var, values);
    }
    Ok(output)
}

fn first<'a>(fields: &'a BTreeMap<String, Vec<String>>, key: &str) -> Option<&'a str> {
    fields
        .get(key)
        .and_then(|values| values.first())
        .map(String::as_str)
}

fn parse_bool(value: &str) -> Result<bool> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => bail!("invalid XML boolean {value:?}"),
    }
}

fn push_form(xml: &mut String, name: &str, value: &str) {
    xml.push_str(&format!(
        "<field var='{}'><value>{}</value></field>",
        attr_escape(name),
        text_escape(value)
    ));
}

fn push_form_values(xml: &mut String, name: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    xml.push_str(&format!("<field var='{}'>", attr_escape(name)));
    for value in values {
        xml.push_str(&format!("<value>{}</value>", text_escape(value)));
    }
    xml.push_str("</field>");
}

fn bool_text(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn node_to_xml(node: Node<'_, '_>) -> String {
    let mut output = String::new();
    serialize_node(node, &mut output);
    output
}

fn serialize_node(node: Node<'_, '_>, output: &mut String) {
    if node.is_text() {
        output.push_str(&text_escape(node.text().unwrap_or("")));
        return;
    }
    if !node.is_element() {
        return;
    }
    output.push('<');
    output.push_str(node.tag_name().name());
    if let Some(namespace) = node.tag_name().namespace() {
        output.push_str(&format!(" xmlns='{}'", attr_escape(namespace)));
    }
    let mut namespaced_index = 0;
    for attribute in node.attributes() {
        let name = match attribute.namespace() {
            None => attribute.name().to_owned(),
            Some("http://www.w3.org/XML/1998/namespace") => format!("xml:{}", attribute.name()),
            Some(namespace) => {
                let prefix = format!("ns{namespaced_index}");
                namespaced_index += 1;
                output.push_str(&format!(" xmlns:{prefix}='{}'", attr_escape(namespace)));
                format!("{prefix}:{}", attribute.name())
            }
        };
        output.push_str(&format!(" {name}='{}'", attr_escape(attribute.value())));
    }
    let children: Vec<_> = node
        .children()
        .filter(|child| child.is_element() || child.is_text())
        .collect();
    if children.is_empty() {
        output.push_str("/>");
        return;
    }
    output.push('>');
    for child in children {
        serialize_node(child, output);
    }
    output.push_str("</");
    output.push_str(node.tag_name().name());
    output.push('>');
}

fn text_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn attr_escape(value: &str) -> String {
    text_escape(value)
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
}

fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    if contents.len() > MAX_TOTAL_BYTES as usize {
        bail!("PIE output exceeds the safety limit");
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("refusing to overwrite PIE output {}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!("PIE output permissions are {mode:o}, expected 600");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTree(PathBuf);

    impl TestTree {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("northstar-pie-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn portable_scram() -> &'static str {
        "<scram-credentials xmlns='urn:xmpp:pie:0#scram' mechanism='SCRAM-SHA-256'><iter-count>4096</iter-count><salt>QUFBQUFBQUFBQUFBQUFBQQ==</salt><server-key>QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=</server-key><stored-key>QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=</stored-key></scram-credentials>"
    }

    #[test]
    fn command_defaults_are_safe() {
        let command =
            parse_command(&["import".into(), "--input".into(), "data.xml".into()]).unwrap();
        assert!(matches!(
            command,
            Command::Import(ImportOptions {
                dry_run: false,
                conflict: ConflictPolicy::Fail,
                unknown: UnknownPolicy::Warn,
                allow_plaintext_passwords: false,
                ..
            })
        ));
        assert!(parse_command(&[
            "export".into(),
            "--output".into(),
            "data.xml".into(),
            "--dry-run".into()
        ])
        .is_err());
    }

    #[test]
    fn include_uri_rejects_traversal_urls_and_bad_escapes() {
        for value in [
            "../secret.xml",
            "%2e%2e/secret.xml",
            "/etc/passwd",
            "https://example.test/a",
            "C:%5csecret",
            "a.xml?x",
            "a.xml#x",
            "%zz",
        ] {
            let decoded = percent_decode(value);
            if let Ok(decoded) = decoded {
                let path = Path::new(&decoded);
                assert!(
                    path.is_absolute()
                        || decoded.contains("://")
                        || decoded.contains(['?', '#', '\\'])
                        || path.components().any(|component| matches!(
                            component,
                            Component::ParentDir | Component::RootDir | Component::Prefix(_)
                        )),
                    "unexpectedly safe: {value}"
                );
            }
        }
    }

    #[test]
    fn dtd_and_entity_documents_are_rejected() {
        assert!(reject_dtd("<!DOCTYPE x [<!ENTITY e 'boom'>]><x>&e;</x>").is_err());
        assert!(reject_dtd("<server-data xmlns='urn:xmpp:pie:0'/>").is_ok());
    }

    #[test]
    fn serializer_makes_inherited_namespaces_self_contained() {
        let document = Document::parse(
            "<item xmlns='urn:test'><payload xml:lang='en'>a&amp;b</payload></item>",
        )
        .unwrap();
        let payload = document
            .descendants()
            .find(|node| node.tag_name().name() == "payload")
            .unwrap();
        assert_eq!(
            node_to_xml(payload),
            "<payload xmlns='urn:test' xml:lang='en'>a&amp;b</payload>"
        );
    }

    #[test]
    fn scram_parser_rejects_weak_or_ambiguous_credentials() {
        let weak = Document::parse("<scram-credentials xmlns='urn:xmpp:pie:0#scram' mechanism='SCRAM-SHA-256'><iter-count>1</iter-count><salt>QUFBQUFBQUFBQUFBQUFBQQ==</salt><server-key>QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=</server-key><stored-key>QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=</stored-key></scram-credentials>").unwrap();
        let mut user = PieUser::default();
        let mut output = ImportDocument::default();
        assert!(parse_scram(weak.root_element(), &mut user, &mut output).is_err());
    }

    #[test]
    fn privacy_and_pep_sibling_order_does_not_change_import_meaning() {
        let xml = format!(
            "<user xmlns='{PIE_NS}' name='alice'>{}
             <query xmlns='{PRIVACY_NS}'>
               <list name='chosen'><item type='jid' value='blocked@example.test' action='deny' order='1'/></list>
               <default name='chosen'/>
             </query>
             <pubsub xmlns='{PUBSUB_OWNER_NS}'>
               <subscriptions node='urn:test:ordered'><subscription jid='bob@example.test' subscription='subscribed' subid='s1'/></subscriptions>
               <configure node='urn:test:ordered'><x xmlns='jabber:x:data' type='submit'>
                 <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field>
                 <field var='pubsub#access_model'><value>whitelist</value></field>
               </x></configure>
             </pubsub>
             </user>",
            portable_scram()
        );
        let document = Document::parse(&xml).unwrap();
        let mut budget = LoadBudget::default();
        let mut output = ImportDocument::default();
        push_user(
            document.root_element(),
            "example.test",
            &mut budget,
            &mut output,
        )
        .unwrap();
        let user = &output.users[0];
        assert_eq!(user.blocked, ["blocked@example.test"]);
        assert_eq!(user.pep_nodes["urn:test:ordered"].subscriptions.len(), 1);
    }

    #[test]
    fn identity_import_preserves_resources_and_bares_presence_subscriptions() {
        let offline_xml = format!(
            "<offline-messages><message xmlns='{CLIENT_NS}' from='ALICE@B\u{fc}CHER.Example./Phone' to='owner@example.test'/></offline-messages>"
        );
        let offline = Document::parse(&offline_xml).unwrap();
        let mut user = PieUser {
            username: "owner".to_owned(),
            ..PieUser::default()
        };
        let mut budget = LoadBudget::default();
        parse_offline(
            offline.root_element(),
            "owner@example.test",
            &mut user,
            &mut budget,
        )
        .unwrap();
        assert_eq!(user.offline[0].sender, "alice@bücher.example/Phone");
        assert_eq!(user.offline[0].target_resource, None);

        let full_normal_xml = format!(
            "<offline-messages><message xmlns='{CLIENT_NS}' from='alice@remote.test/Phone' to='owner@example.test/Target'/></offline-messages>"
        );
        let full_normal = Document::parse(&full_normal_xml).unwrap();
        parse_offline(
            full_normal.root_element(),
            "owner@example.test",
            &mut user,
            &mut budget,
        )
        .unwrap();
        assert_eq!(user.offline[1].target_resource.as_deref(), Some("Target"));

        let full_chat_xml = format!(
            "<offline-messages><message xmlns='{CLIENT_NS}' type='chat' from='alice@remote.test/Phone' to='owner@example.test/Fallback'/></offline-messages>"
        );
        let full_chat = Document::parse(&full_chat_xml).unwrap();
        parse_offline(
            full_chat.root_element(),
            "owner@example.test",
            &mut user,
            &mut budget,
        )
        .unwrap();
        assert_eq!(user.offline[2].target_resource, None);

        for rejected in [
            format!(
                "<offline-messages><message xmlns='{CLIENT_NS}' from='alice@remote.test' to='OWNER@example.test/Target'/></offline-messages>"
            ),
            format!(
                "<offline-messages><message xmlns='{CLIENT_NS}' from='alice@remote.test' to='owner@evil.test/Target'/></offline-messages>"
            ),
        ] {
            let rejected = Document::parse(&rejected).unwrap();
            assert!(
                parse_offline(
                    rejected.root_element(),
                    "owner@example.test",
                    &mut user,
                    &mut budget,
                )
                .is_err()
            );
        }

        let privacy_xml = format!(
            "<query xmlns='{PRIVACY_NS}'><default name='northstar-blocklist'/><list name='northstar-blocklist'><item type='jid' value='ALICE@B\u{fc}CHER.Example./Phone' action='deny' order='1'/></list></query>"
        );
        let privacy = Document::parse(&privacy_xml).unwrap();
        let mut output = ImportDocument::default();
        parse_privacy(privacy.root_element(), &mut user, &mut budget, &mut output).unwrap();
        assert_eq!(user.blocked, ["alice@bücher.example/Phone"]);

        let pending_xml = format!(
            "<presence xmlns='{CLIENT_NS}' type='subscribe' from='BOB@B\u{fc}CHER.Example.' to='owner@example.test'/>",
        );
        let pending = Document::parse(&pending_xml).unwrap();
        parse_pending(
            pending.root_element(),
            "example.test",
            &mut user,
            &mut budget,
        )
        .unwrap();
        assert_eq!(user.pending[0].from, "bob@bücher.example");

        let invalid_xml = format!(
            "<presence xmlns='{CLIENT_NS}' type='subscribe' from='bob@example.test/Phone' to='owner@example.test'/>",
        );
        let invalid = Document::parse(&invalid_xml).unwrap();
        assert!(parse_pending(
            invalid.root_element(),
            "example.test",
            &mut user,
            &mut budget,
        )
        .is_err());
    }

    #[test]
    fn standard_relative_xinclude_layout_loads_host_and_user() {
        let tree = TestTree::new();
        let users = tree.0.join("example.test");
        fs::create_dir(&users).unwrap();
        fs::write(
            tree.0.join("main.xml"),
            "<server-data xmlns='urn:xmpp:pie:0' xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include href='example.test.xml'/></server-data>",
        )
        .unwrap();
        fs::write(
            tree.0.join("example.test.xml"),
            "<host xmlns='urn:xmpp:pie:0' xmlns:xi='http://www.w3.org/2001/XInclude' jid='example.test'><xi:include href='example.test/alice.xml'/></host>",
        )
        .unwrap();
        fs::write(
            users.join("alice.xml"),
            format!(
                "<user xmlns='urn:xmpp:pie:0' name='alice'>{}</user>",
                portable_scram()
            ),
        )
        .unwrap();
        let mut budget = LoadBudget::default();
        let mut output = ImportDocument::default();
        load_server_document(
            &tree.0.canonicalize().unwrap(),
            &tree.0.join("main.xml").canonicalize().unwrap(),
            0,
            "example.test",
            &mut budget,
            &mut output,
        )
        .unwrap();
        assert_eq!(output.users.len(), 1);
        assert_eq!(output.users[0].username, "alice");
        assert!(output.users[0].scram.is_some());
        assert_eq!(budget.files, 3);
    }

    #[test]
    fn xinclude_cannot_escape_the_security_root() {
        let tree = TestTree::new();
        let root = tree.0.join("root");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("main.xml"),
            "<server-data xmlns='urn:xmpp:pie:0' xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include href='../outside.xml'/></server-data>",
        )
        .unwrap();
        fs::write(
            tree.0.join("outside.xml"),
            "<host xmlns='urn:xmpp:pie:0' jid='example.test'/>",
        )
        .unwrap();
        let mut budget = LoadBudget::default();
        let mut output = ImportDocument::default();
        let error = load_server_document(
            &root.canonicalize().unwrap(),
            &root.join("main.xml").canonicalize().unwrap(),
            0,
            "example.test",
            &mut budget,
            &mut output,
        )
        .unwrap_err();
        assert!(error.to_string().contains("relative URI"));
    }

    #[test]
    fn duplicate_include_and_resource_counters_fail_closed() {
        let tree = TestTree::new();
        fs::write(
            tree.0.join("host.xml"),
            "<host xmlns='urn:xmpp:pie:0' jid='example.test'/>",
        )
        .unwrap();
        fs::write(
            tree.0.join("main.xml"),
            "<server-data xmlns='urn:xmpp:pie:0' xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include href='host.xml'/><xi:include href='host.xml'/></server-data>",
        )
        .unwrap();
        let mut budget = LoadBudget::default();
        let mut output = ImportDocument::default();
        assert!(load_server_document(
            &tree.0.canonicalize().unwrap(),
            &tree.0.join("main.xml").canonicalize().unwrap(),
            0,
            "example.test",
            &mut budget,
            &mut output,
        )
        .unwrap_err()
        .to_string()
        .contains("duplicate include"));
        let mut budget = LoadBudget {
            items: MAX_ITEMS,
            ..Default::default()
        };
        assert!(item(&mut budget).is_err());
        assert!(include_depth(MAX_INCLUDE_DEPTH + 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn xinclude_refuses_symlinks_even_when_the_target_stays_inside_root() {
        use std::os::unix::fs::symlink;
        let tree = TestTree::new();
        let root = tree.0.canonicalize().unwrap();
        fs::write(
            tree.0.join("host.xml"),
            "<host xmlns='urn:xmpp:pie:0' jid='example.test'/>",
        )
        .unwrap();
        symlink(tree.0.join("host.xml"), tree.0.join("alias.xml")).unwrap();
        let input_error = secure_existing_path(&root, &tree.0.join("alias.xml")).unwrap_err();
        assert!(input_error.to_string().contains("symlink"));
        let error = resolve_include(&root, &tree.0.join("main.xml"), "alias.xml").unwrap_err();
        assert!(error.to_string().contains("symlink"));
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL schema"]
    async fn portable_data_roundtrip_conflicts_and_rollback_are_atomic() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL schema");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let alice = crate::db::create_user(
            &pool,
            "alice",
            "alice-portable-password",
            false,
            false,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let bob = crate::db::create_user(
            &pool,
            "bob",
            "bob-portable-password",
            false,
            false,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO roster_items(owner_id,contact_jid,display_name,subscription,groups,approved) VALUES($1,'bob@example.test','Bob','both','[\"Friends\",\"Trusted\"]'::jsonb,TRUE)")
            .bind(alice.id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted) VALUES($1,$2,'alice@example.test',$3,TRUE)")
            .bind(Uuid::new_v4()).bind(bob.id)
            .bind("<message xmlns='jabber:client' from='alice@example.test/phone' to='bob@example.test' type='chat'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='1'/><payload>YQ==</payload></encrypted></message>")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO private_xml(user_id,element_name,element_ns,xml_data) VALUES($1,'prefs','urn:test:prefs',$2)")
            .bind(alice.id).bind("<prefs xmlns='urn:test:prefs'><theme>dark</theme></prefs>").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO vcards(user_id,payload) VALUES($1,$2)")
            .bind(alice.id)
            .bind("<vCard xmlns='vcard-temp'><FN>Alice</FN></vCard>")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,'spam@example.net')")
            .bind(alice.id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO pending_presence_subscriptions(requester_id,recipient_id,stanza) VALUES($1,$2,$3)")
            .bind(alice.id).bind(bob.id)
            .bind("<presence xmlns='jabber:client' type='subscribe' from='alice@example.test' to='bob@example.test'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO pep_nodes(owner_id,node,access_model,max_items,persist_items,send_last_published_item,deliver_notifications,roster_groups_allowed,access_whitelist) VALUES($1,'urn:test:pep','whitelist',10,TRUE,'on_sub',TRUE,ARRAY['Friends','Trusted'],ARRAY['bob@example.test','carol@example.net'])")
            .bind(alice.id).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO pep_subscriptions(owner_id,node,subscriber_jid,subid,state) VALUES($1,'urn:test:pep','bob@example.test',$2,'subscribed')")
            .bind(alice.id).bind(Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO pep_items(owner_id,node,item_id,payload) VALUES($1,'urn:test:pep','current',$2)")
            .bind(alice.id).bind("<status xmlns='urn:test:status'>ready</status>").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id) VALUES($1,$2,'bob@example.test','bob@example.test',$3,TRUE,'origin-1')")
            .bind(Uuid::new_v4()).bind(alice.id)
            .bind("<message xmlns='jabber:client' from='alice@example.test/phone' to='bob@example.test' type='chat' id='origin-1'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='1'/><payload>Yg==</payload></encrypted></message>")
            .execute(&pool).await.unwrap();
        let expected_scram =
            crate::db::get_scram_credentials(&pool, "alice", crate::auth::ScramAlgorithm::Sha256)
                .await
                .unwrap()
                .unwrap();
        let tree = TestTree::new();
        let output = tree.0.join("portable.xml");
        export(&pool, "example.test", &output, true).await.unwrap();
        let exported = fs::read_to_string(&output).unwrap();
        assert!(!exported.contains("password="));
        assert!(exported.contains("urn:xmpp:pie:0#scram"));
        assert!(exported.contains("pubsub#roster_groups_allowed"));
        sqlx::query("DELETE FROM users")
            .execute(&pool)
            .await
            .unwrap();
        let runtime = ImportRuntime {
            domain: "example.test",
            scram_iterations: auth::MIN_SCRAM_ITERATIONS,
        };
        let mut options = ImportOptions {
            input: output.clone(),
            root: Some(tree.0.clone()),
            dry_run: true,
            conflict: ConflictPolicy::Fail,
            unknown: UnknownPolicy::Warn,
            allow_plaintext_passwords: false,
        };
        import(&pool, &runtime, &options).await.unwrap();
        let users_after_dry_run: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users_after_dry_run, 0);
        options.dry_run = false;
        import(&pool, &runtime, &options).await.unwrap();
        let restored_alice = crate::db::find_user(&pool, "alice").await.unwrap().unwrap();
        let restored_bob = crate::db::find_user(&pool, "bob").await.unwrap().unwrap();
        let restored_scram =
            crate::db::get_scram_credentials(&pool, "alice", crate::auth::ScramAlgorithm::Sha256)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(restored_scram.iterations, expected_scram.iterations);
        assert_eq!(restored_scram.salt, expected_scram.salt);
        assert_eq!(restored_scram.stored_key, expected_scram.stored_key);
        assert_eq!(restored_scram.server_key, expected_scram.server_key);
        for (table, expected) in [
            ("roster_items", 1_i64),
            ("offline_messages", 1),
            ("private_xml", 1),
            ("vcards", 1),
            ("blocked_jids", 1),
            ("pending_presence_subscriptions", 1),
            ("federated_presence_pending", 0),
            ("pep_nodes", 1),
            ("pep_subscriptions", 1),
            ("pep_items", 1),
            ("message_archive", 1),
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(count, expected, "unexpected row count for {table}");
        }
        options.conflict = ConflictPolicy::Skip;
        import(&pool, &runtime, &options).await.unwrap();
        assert_eq!(
            crate::db::find_user(&pool, "alice")
                .await
                .unwrap()
                .unwrap()
                .id,
            restored_alice.id
        );
        assert_eq!(
            crate::db::find_user(&pool, "bob")
                .await
                .unwrap()
                .unwrap()
                .id,
            restored_bob.id
        );
        options.conflict = ConflictPolicy::Replace;
        import(&pool, &runtime, &options).await.unwrap();
        assert_ne!(
            crate::db::find_user(&pool, "alice")
                .await
                .unwrap()
                .unwrap()
                .id,
            restored_alice.id
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pending_presence_subscriptions")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );

        let existing = crate::db::create_user(
            &pool,
            "zrollback",
            "rollback-existing-password",
            false,
            false,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let rollback_file = tree.0.join("rollback.xml");
        fs::write(
            &rollback_file,
            format!("<server-data xmlns='urn:xmpp:pie:0'><host jid='example.test'><user name='arollback'>{0}</user><user name='zrollback'>{0}</user></host></server-data>", portable_scram()),
        ).unwrap();
        options.input = rollback_file;
        options.conflict = ConflictPolicy::Fail;
        assert!(import(&pool, &runtime, &options).await.is_err());
        assert!(crate::db::find_user(&pool, "arollback")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            crate::db::find_user(&pool, "zrollback")
                .await
                .unwrap()
                .unwrap()
                .id,
            existing.id
        );
    }
}
