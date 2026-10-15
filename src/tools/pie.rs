//! XEP-0227 Portable Import/Export (PIE) operator tooling.
//!
//! This module is intentionally an offline control-plane tool.  It does not
//! expose user archives over HTTP or XMPP and it never exports plaintext
//! passwords.  Import is one serializable transaction, including its audit
//! record; `--dry-run` executes the same database writes and then rolls back.

use crate::{auth, db, jid, platform::config::Config};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use roxmltree::{Document, Node};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

mod export_data;
mod import_loading;
mod import_payloads;

use self::export_data::export;
use self::import_loading::import;
#[cfg(test)]
use self::import_loading::{
    load_server_document, percent_decode, push_user, resolve_include, secure_existing_path,
};
use self::import_payloads::{
    parse_archive, parse_offline, parse_pending, parse_pep_items, parse_pep_owner, parse_privacy,
    parse_private, parse_roster, parse_scram,
};

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
pub(crate) enum ConflictPolicy {
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
pub(crate) struct PieUser {
    pub(crate) username: String,
    plaintext_password: Option<String>,
    scram: Option<ScramCredential>,
    pub(crate) roster: Vec<RosterItem>,
    pub(crate) offline: Vec<OfflineMessage>,
    pub(crate) private_xml: Vec<PrivateXml>,
    pub(crate) vcard: Option<String>,
    pub(crate) blocked: Vec<String>,
    pub(crate) pending: Vec<PendingPresence>,
    pub(crate) pep_nodes: BTreeMap<String, PepNode>,
    pub(crate) archive: Vec<ArchiveItem>,
}

pub(crate) struct ScramCredential {
    pub(crate) iterations: u32,
    pub(crate) salt: Vec<u8>,
    pub(crate) stored_key: Vec<u8>,
    pub(crate) server_key: Vec<u8>,
}

pub(crate) struct RosterItem {
    pub(crate) jid: String,
    pub(crate) name: Option<String>,
    pub(crate) subscription: String,
    pub(crate) ask: Option<String>,
    pub(crate) groups: Vec<String>,
    pub(crate) approved: bool,
}

pub(crate) struct OfflineMessage {
    pub(crate) sender: String,
    pub(crate) stanza: String,
    /// Derived from the validated stanza, never accepted as an independent
    /// PIE field.
    pub(crate) target_resource: Option<String>,
    pub(crate) encrypted: bool,
    pub(crate) created_at: Option<DateTime<Utc>>,
}

pub(crate) struct PrivateXml {
    pub(crate) name: String,
    pub(crate) namespace: String,
    pub(crate) xml: String,
}

pub(crate) struct PendingPresence {
    pub(crate) from: String,
    pub(crate) stanza: String,
}

pub(crate) struct PepNode {
    pub(crate) access_model: String,
    pub(crate) max_items: i32,
    pub(crate) persist_items: bool,
    pub(crate) send_last: String,
    pub(crate) deliver_notifications: bool,
    pub(crate) roster_groups_allowed: Vec<String>,
    pub(crate) access_whitelist: Vec<String>,
    pub(crate) subscriptions: Vec<PepSubscription>,
    pub(crate) items: Vec<PepItem>,
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

pub(crate) struct PepSubscription {
    pub(crate) jid: String,
    pub(crate) subid: String,
    pub(crate) state: String,
}

pub(crate) struct PepItem {
    pub(crate) id: String,
    pub(crate) payload: String,
}

pub(crate) struct ArchiveItem {
    pub(crate) result_id: String,
    pub(crate) peer_jid: String,
    pub(crate) peer_full_jid: String,
    pub(crate) stanza: String,
    pub(crate) encrypted: bool,
    pub(crate) created_at: DateTime<Utc>,
}

pub(crate) struct PreparedUser {
    pub(crate) data: PieUser,
    pub(crate) password_hash: String,
    pub(crate) scram: ScramCredential,
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
                crate::platform::config::read_secret_file(&path, "MIGRATOR_DATABASE_URL_FILE")?
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

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(test)]
pub(crate) const MODULE_SOURCE: &[(&str, &str)] = &[
    ("pie", include_str!("pie.rs")),
    ("export_data", include_str!("pie/export_data.rs")),
    ("import_loading", include_str!("pie/import_loading.rs")),
    ("import_payloads", include_str!("pie/import_payloads.rs")),
];

#[cfg(test)]
pub(crate) fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod module_source_tests;
