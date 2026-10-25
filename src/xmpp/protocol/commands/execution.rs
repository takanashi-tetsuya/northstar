//! Execute administrative commands and perform their account-target and announcement-routing operations.

use super::*;

pub(super) async fn execute_count_command(
    session: &ProtocolSession,
    actor: &AdminActor,
    node: &str,
) -> Result<String> {
    let (field, value) = match node {
        ONLINE_COUNT => {
            let users = online_bare_jids(session).await?;
            ("onlineusersnum", users.len().to_string())
        }
        REGISTERED_COUNT => {
            let users = session
                .state
                .admin_command_service()
                .registered_account_count(actor)
                .await?
                .unwrap_or_default();
            ("registeredusersnum", users.to_string())
        }
        DISABLED_COUNT => {
            let users = session
                .state
                .admin_command_service()
                .disabled_account_count(actor)
                .await?
                .unwrap_or_default();
            ("disabledusersnum", users.to_string())
        }
        ACTIVE_COUNT | IDLE_COUNT => {
            let (active, idle) = activity_bare_jids(session).await?;
            if node == ACTIVE_COUNT {
                ("activeusersnum", active.len().to_string())
            } else {
                ("idleusersnum", idle.len().to_string())
            }
        }
        _ => unreachable!("only count commands reach execute_count_command"),
    };
    Ok(XmlElement::namespaced("x", DATA_NS)
        .attr("type", "result")
        .child(form_type_field())
        .child(
            XmlElement::new("field")
                .attr("var", field)
                .child(XmlElement::new("value").text(value)),
        )
        .finish())
}

pub(super) async fn execute_list_command(
    session: &ProtocolSession,
    actor: &AdminActor,
    node: &str,
    max_items: usize,
    offset: usize,
) -> Result<String> {
    let (field, values) = match node {
        ONLINE_LIST => (
            "onlineuserjids",
            online_bare_jids(session)
                .await?
                .into_iter()
                .skip(offset)
                .take(max_items)
                .collect::<Vec<_>>(),
        ),
        REGISTERED_LIST => (
            "registereduserjids",
            session
                .state
                .admin_command_service()
                .registered_account_usernames(actor, max_items as i64, offset as i64)
                .await?
                .unwrap_or_default()
                .into_iter()
                .map(|username| local_account_jid(&username, session.state.local_domain()))
                .collect::<Result<Vec<_>>>()?,
        ),
        DISABLED_LIST => {
            let rows = session
                .state
                .admin_command_service()
                .disabled_account_usernames(actor, max_items as i64, offset as i64)
                .await?
                .unwrap_or_default();
            (
                "disableduserjids",
                rows.into_iter()
                    .map(|username| local_account_jid(&username, session.state.local_domain()))
                    .collect::<Result<Vec<_>>>()?,
            )
        }
        ACTIVE_LIST | IDLE_LIST => {
            let (active, idle) = activity_bare_jids(session).await?;
            (
                if node == ACTIVE_LIST {
                    "activeuserjids"
                } else {
                    "idleuserjids"
                },
                if node == ACTIVE_LIST { active } else { idle }
                    .into_iter()
                    .skip(offset)
                    .take(max_items)
                    .collect::<Vec<_>>(),
            )
        }
        _ => unreachable!("only list commands reach execute_list_command"),
    };
    let mut result_values = XmlElement::new("field").attr("var", field);
    for jid in values {
        result_values.push_child(XmlElement::new("value").text(jid));
    }
    Ok(XmlElement::namespaced("x", DATA_NS)
        .attr("type", "result")
        .child(form_type_field())
        .child(result_values)
        .finish())
}

pub(super) async fn execute_form_command(
    session: &ProtocolSession,
    actor: &AdminActor,
    claim: &crate::services::admin_commands::AdminExecutionClaim,
    node: &str,
    submission: Submission,
) -> Result<Option<String>> {
    if is_list_command(node) {
        let max_items = submission
            .one("max_items")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| (1..=MAX_LIST_ITEMS).contains(value));
        let offset = submission
            .one("start")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value <= 1_000_000);
        return match (max_items, offset) {
            (Some(max_items), Some(offset)) => {
                execute_list_command(session, actor, node, max_items, offset)
                    .await
                    .map(Some)
            }
            _ => Ok(None),
        };
    }

    match node {
        ADD_USER => {
            let Some(username) = local_account_username(
                submission.one("accountjid").ok(),
                session.state.local_domain(),
            ) else {
                return Ok(None);
            };
            let password = submission.one("password").ok();
            let verify = submission.one("password-verify").ok();
            let (Some(password), Some(verify)) = (password, verify) else {
                return Ok(None);
            };
            if password != verify {
                return Ok(None);
            }
            let payload = empty_result();
            if !session
                .state
                .admin_command_service()
                .renew_execution(actor, claim, node)
                .await?
            {
                return Ok(None);
            }
            let scram_policy = session.state.admin_scram_policy();
            if !matches!(
                session
                    .state
                    .admin_command_service()
                    .create_account(
                        actor,
                        claim,
                        node,
                        &username,
                        password,
                        scram_policy.iterations,
                        scram_policy.sha1_enabled,
                        &payload,
                    )
                    .await?,
                CreateAccountOutcome::Created
            ) {
                return Ok(None);
            }
            Ok(Some(payload))
        }
        DELETE_USER | DISABLE_USER | REENABLE_USER | END_USER_SESSION => {
            let values = submission.many("accountjids").ok();
            let Some(values) = values.filter(|values| !values.is_empty()) else {
                return Ok(None);
            };
            let mut targets = Vec::with_capacity(values.len());
            for value in values {
                let (username, exact_full) = if node == END_USER_SESSION {
                    let Ok(jid) = northstar_xmpp_types::jid::CanonicalJid::parse(value.trim())
                    else {
                        return Ok(None);
                    };
                    if jid.domainpart() != session.state.local_domain() || jid.localpart().is_none()
                    {
                        return Ok(None);
                    }
                    let Ok(username) = northstar_auth_core::normalize_username(
                        jid.localpart().expect("localpart checked"),
                    ) else {
                        return Ok(None);
                    };
                    (username, jid.resourcepart().is_some().then_some(jid))
                } else {
                    let Some(username) =
                        local_account_username(Some(value), session.state.local_domain())
                    else {
                        return Ok(None);
                    };
                    (username, None)
                };
                targets.push(AccountCommandTarget {
                    username,
                    exact_full_jid: exact_full,
                });
            }
            let action = match node {
                DELETE_USER => AccountCommandAction::Delete,
                DISABLE_USER => AccountCommandAction::Disable,
                REENABLE_USER => AccountCommandAction::Reenable,
                END_USER_SESSION => AccountCommandAction::EndSessions,
                _ => unreachable!(),
            };
            let payload = empty_result();
            let outcome = session
                .state
                .admin_command_service()
                .mutate_accounts(
                    actor,
                    claim,
                    node,
                    &targets,
                    action,
                    session.state.local_domain(),
                    &payload,
                )
                .await?;
            match outcome {
                AccountMutationOutcome::Applied => {}
                AccountMutationOutcome::Retryable => return Err(AdminCommandRetryable.into()),
                AccountMutationOutcome::Unauthorized
                | AccountMutationOutcome::TargetChanged
                | AccountMutationOutcome::SelfMutation
                | AccountMutationOutcome::LastAdministrator => return Ok(None),
            }
            Ok(Some(payload))
        }
        CHANGE_USER_PASSWORD => {
            let Some(username) = local_account_username(
                submission.one("accountjid").ok(),
                session.state.local_domain(),
            ) else {
                return Ok(None);
            };
            let Ok(password) = submission.one("password") else {
                return Ok(None);
            };
            let payload = empty_result();
            if !session
                .state
                .admin_command_service()
                .renew_execution(actor, claim, node)
                .await?
            {
                return Ok(None);
            }
            let scram_policy = session.state.admin_scram_policy();
            let outcome = session
                .state
                .admin_command_service()
                .reset_account_password(
                    actor,
                    claim,
                    node,
                    &username,
                    password,
                    scram_policy.iterations,
                    scram_policy.sha1_enabled,
                    session.state.local_domain(),
                    &payload,
                )
                .await?;
            if outcome != AdminWriteOutcome::Applied {
                return Ok(None);
            }
            Ok(Some(payload))
        }
        GET_USER_ROSTER | GET_USER_LAST_LOGIN => {
            let Some(values) = submission
                .many("accountjids")
                .ok()
                .filter(|values| values.len() == 1)
            else {
                return Ok(None);
            };
            let Some(username) = local_account_username(
                values.first().map(String::as_str),
                session.state.local_domain(),
            ) else {
                return Ok(None);
            };
            if node == GET_USER_LAST_LOGIN {
                let Some(target) = session
                    .state
                    .admin_command_service()
                    .account_last_login(actor, &username)
                    .await?
                else {
                    return Ok(None);
                };
                let account = local_account_jid(&target.username, session.state.local_domain())?;
                let value = target
                    .last_login_at
                    .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_default();
                return Ok(Some(
                    XmlElement::namespaced("x", DATA_NS)
                        .attr("type", "result")
                        .child(form_type_field())
                        .child(result_field("accountjids", account))
                        .child(result_field("lastlogin", value))
                        .finish(),
                ));
            }
            let Some(roster) = session
                .state
                .admin_command_service()
                .account_roster(actor, &username)
                .await?
            else {
                return Ok(None);
            };
            let account =
                local_account_jid(&roster.account.username, session.state.local_domain())?;
            let mut query = XmlElement::namespaced("query", "jabber:iq:roster");
            for (jid, name, subscription, ask) in roster.items {
                query.push_child(
                    XmlElement::new("item")
                        .attr("jid", jid)
                        .optional_attr("name", name)
                        .attr("subscription", subscription)
                        .optional_attr("ask", ask),
                );
            }
            Ok(Some(
                XmlElement::namespaced("x", DATA_NS)
                    .attr("type", "result")
                    .child(form_type_field())
                    .child(result_field("accountjids", account))
                    .child(query)
                    .finish(),
            ))
        }
        USER_STATS => {
            let Some(username) = local_account_username(
                submission.one("accountjid").ok(),
                session.state.local_domain(),
            ) else {
                return Ok(None);
            };
            let Some(stats) = session
                .state
                .admin_command_service()
                .account_statistics(actor, &username)
                .await?
            else {
                return Ok(None);
            };
            Ok(Some(
                XmlElement::namespaced("x", DATA_NS)
                    .attr("type", "result")
                    .child(form_type_field())
                    .child(result_field(
                        "accountjid",
                        local_account_jid(&stats.account.username, session.state.local_domain())?,
                    ))
                    .child(result_field("rostersize", stats.roster_size.to_string()))
                    .child(result_field(
                        "archivedstanzas",
                        stats.archived_stanzas.to_string(),
                    ))
                    .child(result_field(
                        "offlinestanzas",
                        stats.offline_stanzas.to_string(),
                    ))
                    .finish(),
            ))
        }
        EDIT_ADMIN => {
            let values = submission.many("adminjids").ok();
            let Some(values) = values.filter(|values| !values.is_empty()) else {
                return Ok(None);
            };
            let mut usernames = Vec::with_capacity(values.len());
            for value in values {
                let Some(username) =
                    local_account_username(Some(value), session.state.local_domain())
                else {
                    return Ok(None);
                };
                usernames.push(username);
            }
            let payload = empty_result();
            if session
                .state
                .admin_command_service()
                .replace_administrators(actor, claim, node, &usernames, &payload)
                .await?
                != AdminWriteOutcome::Applied
            {
                return Ok(None);
            }
            Ok(Some(payload))
        }
        ANNOUNCE => {
            let Some(body) = joined_text_field(&submission, "announcement") else {
                return Ok(None);
            };
            let recipients = online_bare_jids(session).await?.len();
            let payload = XmlElement::namespaced("x", DATA_NS)
                .attr("type", "result")
                .child(form_type_field())
                .child(result_field("onlineusersnum", recipients.to_string()))
                .finish();
            if session
                .state
                .admin_command_service()
                .record_announcement(actor, claim, node, recipients, body.len(), &payload)
                .await?
                != AdminWriteOutcome::Applied
            {
                return Ok(None);
            }
            let _ = send_announcement(session, actor, &body).await?;
            Ok(Some(payload))
        }
        SET_MOTD | EDIT_MOTD | SET_WELCOME => {
            let (kind, field_name) = if node == SET_WELCOME {
                ("welcome", "welcome")
            } else {
                ("motd", "motd")
            };
            let Some(body) = joined_text_field(&submission, field_name) else {
                return Ok(None);
            };
            let payload = empty_result();
            if session
                .state
                .admin_command_service()
                .set_service_message(actor, claim, node, kind, Some(&body), &payload)
                .await?
                != AdminWriteOutcome::Applied
            {
                return Ok(None);
            }
            Ok(Some(payload))
        }
        DELETE_MOTD | DELETE_WELCOME => {
            if !matches!(submission.one("confirm"), Ok("1" | "true")) {
                return Ok(None);
            }
            let kind = if node == DELETE_MOTD {
                "motd"
            } else {
                "welcome"
            };
            let payload = empty_result();
            if session
                .state
                .admin_command_service()
                .set_service_message(actor, claim, node, kind, None, &payload)
                .await?
                != AdminWriteOutcome::Applied
            {
                return Ok(None);
            }
            Ok(Some(payload))
        }
        EDIT_BLACKLIST | EDIT_WHITELIST => {
            let (kind, variable) = if node == EDIT_BLACKLIST {
                ("blacklist", "blacklistjids")
            } else {
                ("whitelist", "whitelistjids")
            };
            let Ok(values) = submission.many(variable) else {
                return Ok(None);
            };
            let mut entities = BTreeSet::new();
            for value in values {
                let Ok(jid) = northstar_xmpp_types::jid::CanonicalJid::parse(value.trim()) else {
                    return Ok(None);
                };
                entities.insert(jid.to_string());
            }
            let entities = entities.into_iter().collect::<Vec<_>>();
            let payload = empty_result();
            let Some(rules) = session
                .state
                .admin_command_service()
                .replace_federation_rules(actor, claim, node, kind, &entities, &payload)
                .await?
            else {
                return Ok(None);
            };
            session
                .state
                .replace_runtime_federation_cache(rules.blacklist, rules.whitelist);
            Ok(Some(payload))
        }
        RESTART | SHUTDOWN => {
            let Ok(confirm) = submission.one("confirm") else {
                return Ok(None);
            };
            if confirm == "CANCEL" {
                let payload = empty_result();
                if session
                    .state
                    .admin_command_service()
                    .cancel_service_control(
                        actor,
                        claim,
                        node,
                        if node == RESTART {
                            "restart"
                        } else {
                            "shutdown"
                        },
                        &payload,
                    )
                    .await?
                    != AdminWriteOutcome::Applied
                {
                    return Ok(None);
                }
                return Ok(Some(payload));
            }
            let expected = format!(
                "{} {}",
                if node == RESTART {
                    "RESTART"
                } else {
                    "SHUTDOWN"
                },
                session.state.local_domain(),
            );
            if confirm != expected {
                return Ok(None);
            }
            let Some(delay) = submission
                .one("delay")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|delay| (5..=3600).contains(delay))
            else {
                return Ok(None);
            };
            let announcement = submission
                .many("announcement")
                .ok()
                .map(|values| values.join("\n"))
                .filter(|value| !value.trim().is_empty() && value.len() <= 65_536);
            let payload = empty_result();
            let scheduled = session
                .state
                .admin_command_service()
                .schedule_service_control(
                    actor,
                    claim,
                    node,
                    if node == RESTART {
                        "restart"
                    } else {
                        "shutdown"
                    },
                    delay as i64,
                    announcement.as_deref(),
                    &payload,
                )
                .await?;
            if scheduled != AdminWriteOutcome::Applied {
                return Ok(None);
            }
            if let Some(announcement) = announcement {
                let _ = send_announcement(session, actor, &announcement).await?;
            }
            Ok(Some(payload))
        }
        _ => unreachable!("all advertised form commands are implemented"),
    }
}

pub(super) fn local_account_username(value: Option<&str>, domain: &str) -> Option<String> {
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(value?.trim()).ok()?;
    if jid.domainpart() != domain || jid.resourcepart().is_some() {
        return None;
    }
    northstar_auth_core::normalize_username(jid.localpart()?).ok()
}

pub(super) fn local_account_jid(username: &str, domain: &str) -> Result<String> {
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&format!("{username}@{domain}"))?;
    anyhow::ensure!(
        jid.localpart() == Some(username) && jid.domainpart() == domain,
        "local account identity changed during JID preparation"
    );
    Ok(jid.to_string())
}

pub(super) fn empty_result() -> String {
    XmlElement::namespaced("x", DATA_NS)
        .attr("type", "result")
        .child(form_type_field())
        .finish()
}

pub(super) fn joined_text_field(submission: &Submission, name: &str) -> Option<String> {
    let body = submission.many(name).ok()?.join("\n");
    (!body.trim().is_empty() && body.len() <= 65_536).then_some(body)
}

pub(super) async fn send_announcement(
    session: &ProtocolSession,
    actor: &AdminActor,
    body: &str,
) -> Result<usize> {
    let stanza = XmlElement::namespaced("message", "jabber:client")
        .attr("from", session.state.local_domain())
        .attr("type", "headline")
        .attr("id", uuid::Uuid::new_v4())
        .child(XmlElement::new("body").text(body.to_owned()))
        .finish();
    // Keep only the bounded local-session identity set in memory. Cluster
    // accounts are traversed once in a keyset-paginated database snapshot and
    // counted as each page is released, so a 100k-account announcement cannot
    // grow a second 100k-entry recipient set in this protocol task.
    let local_recipients = session.state.send_local_announcement(&stanza);
    let mut recipient_count = local_recipients.len();
    if session.state.admin_remote_announcement_enabled() {
        let mut cursor = None;
        loop {
            let page = session
                .state
                .admin_command_service()
                .announcement_account_page(actor, cursor.as_ref())
                .await?
                .ok_or_else(|| anyhow::anyhow!("administrator authorization changed"))?;
            for username in page.usernames {
                let bare = local_account_jid(&username, session.state.local_domain())?;
                let delivered_remotely = session
                    .state
                    .send_remote_announcement_to_account(&bare, &stanza)
                    .await?;
                if delivered_remotely && !local_recipients.contains(&bare) {
                    recipient_count += 1;
                }
            }
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(recipient_count)
}

pub(super) async fn online_bare_jids(session: &ProtocolSession) -> Result<BTreeSet<String>> {
    session.state.admin_online_bare_jids().await
}

pub(super) async fn activity_bare_jids(
    session: &ProtocolSession,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    session.state.admin_activity_bare_jids().await
}
