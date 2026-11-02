//! Export account data from PostgreSQL into validated portable XML.

use super::*;

pub(super) async fn export(
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

pub(super) async fn export_roster(
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

pub(super) async fn export_offline(
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

pub(super) async fn export_private(
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

pub(super) async fn export_vcard(
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

pub(super) async fn export_blocklist(
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

pub(super) async fn export_pending(
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

pub(super) fn append_pending_presence(
    xml: &mut String,
    from: &str,
    stanza: Option<&str>,
) -> Result<()> {
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

pub(super) async fn export_pep(
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

pub(super) async fn export_mam(
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
