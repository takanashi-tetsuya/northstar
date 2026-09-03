use crate::{
    services::admin_commands::{
        AccountCommandAction, AccountCommandTarget, AccountMutationOutcome, AdminActor,
        AdminCommandRetryable, AdminWriteOutcome, CommandExecutionOutcome, CommandSessionOutcome,
        CreateAccountOutcome, ExecutionReleaseOutcome,
    },
    xmpp::protocol::{Action, ProtocolSession},
    xmpp::xml_builder::XmlElement,
};
use anyhow::Result;
use roxmltree::Node;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

const COMMANDS_NS: &str = "http://jabber.org/protocol/commands";
const DATA_NS: &str = "jabber:x:data";
const ADMIN_FORM_TYPE: &str = "http://jabber.org/protocol/admin";
const ONLINE_COUNT: &str = "http://jabber.org/protocol/admin#get-online-users-num";
const ONLINE_LIST: &str = "http://jabber.org/protocol/admin#get-online-users-list";
const REGISTERED_COUNT: &str = "http://jabber.org/protocol/admin#get-registered-users-num";
const REGISTERED_LIST: &str = "http://jabber.org/protocol/admin#get-registered-users-list";
const DISABLED_COUNT: &str = "http://jabber.org/protocol/admin#get-disabled-users-num";
const DISABLED_LIST: &str = "http://jabber.org/protocol/admin#get-disabled-users-list";
const ACTIVE_COUNT: &str = "http://jabber.org/protocol/admin#get-active-users-num";
const IDLE_COUNT: &str = "http://jabber.org/protocol/admin#get-idle-users-num";
const ACTIVE_LIST: &str = "http://jabber.org/protocol/admin#get-active-users";
const IDLE_LIST: &str = "http://jabber.org/protocol/admin#get-idle-users";
const ADD_USER: &str = "http://jabber.org/protocol/admin#add-user";
const DELETE_USER: &str = "http://jabber.org/protocol/admin#delete-user";
const DISABLE_USER: &str = "http://jabber.org/protocol/admin#disable-user";
const REENABLE_USER: &str = "http://jabber.org/protocol/admin#reenable-user";
const END_USER_SESSION: &str = "http://jabber.org/protocol/admin#end-user-session";
const CHANGE_USER_PASSWORD: &str = "http://jabber.org/protocol/admin#change-user-password";
const GET_USER_ROSTER: &str = "http://jabber.org/protocol/admin#get-user-roster";
const GET_USER_LAST_LOGIN: &str = "http://jabber.org/protocol/admin#get-user-lastlogin";
const USER_STATS: &str = "http://jabber.org/protocol/admin#user-stats";
const EDIT_ADMIN: &str = "http://jabber.org/protocol/admin#edit-admin";
const ANNOUNCE: &str = "http://jabber.org/protocol/admin#announce";
const SET_MOTD: &str = "http://jabber.org/protocol/admin#set-motd";
const EDIT_MOTD: &str = "http://jabber.org/protocol/admin#edit-motd";
const DELETE_MOTD: &str = "http://jabber.org/protocol/admin#delete-motd";
const SET_WELCOME: &str = "http://jabber.org/protocol/admin#set-welcome";
const DELETE_WELCOME: &str = "http://jabber.org/protocol/admin#delete-welcome";
const EDIT_BLACKLIST: &str = "http://jabber.org/protocol/admin#edit-blacklist";
const EDIT_WHITELIST: &str = "http://jabber.org/protocol/admin#edit-whitelist";
const RESTART: &str = "http://jabber.org/protocol/admin#restart";
const SHUTDOWN: &str = "http://jabber.org/protocol/admin#shutdown";
const MAX_LIST_ITEMS: usize = 200;
const MAX_ACCOUNT_ITEMS: usize = 200;

const COMMANDS: &[&str] = &[
    ADD_USER,
    DELETE_USER,
    DISABLE_USER,
    REENABLE_USER,
    END_USER_SESSION,
    CHANGE_USER_PASSWORD,
    GET_USER_ROSTER,
    GET_USER_LAST_LOGIN,
    USER_STATS,
    EDIT_ADMIN,
    ANNOUNCE,
    SET_MOTD,
    EDIT_MOTD,
    DELETE_MOTD,
    SET_WELCOME,
    DELETE_WELCOME,
    EDIT_BLACKLIST,
    EDIT_WHITELIST,
    RESTART,
    SHUTDOWN,
    REGISTERED_COUNT,
    DISABLED_COUNT,
    ONLINE_COUNT,
    ACTIVE_COUNT,
    IDLE_COUNT,
    REGISTERED_LIST,
    DISABLED_LIST,
    ONLINE_LIST,
    ACTIVE_LIST,
    IDLE_LIST,
];

pub(crate) fn is_command(node: &str) -> bool {
    COMMANDS.contains(&node)
}

fn is_list_command(node: &str) -> bool {
    matches!(
        node,
        ONLINE_LIST | REGISTERED_LIST | DISABLED_LIST | ACTIVE_LIST | IDLE_LIST
    )
}

fn is_count_command(node: &str) -> bool {
    matches!(
        node,
        ONLINE_COUNT | REGISTERED_COUNT | DISABLED_COUNT | ACTIVE_COUNT | IDLE_COUNT
    )
}

fn is_read_form_command(node: &str) -> bool {
    is_list_command(node) || matches!(node, GET_USER_ROSTER | GET_USER_LAST_LOGIN | USER_STATS)
}

fn valid_command_bearer(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn command_name(node: &str) -> &'static str {
    match node {
        ONLINE_COUNT => "Get Number of Online Users",
        ONLINE_LIST => "Get List of Online Users",
        REGISTERED_COUNT => "Get Number of Registered Users",
        REGISTERED_LIST => "Get List of Registered Users",
        DISABLED_COUNT => "Get Number of Disabled Users",
        DISABLED_LIST => "Get List of Disabled Users",
        ACTIVE_COUNT => "Get Number of Active Users",
        IDLE_COUNT => "Get Number of Idle Users",
        ACTIVE_LIST => "Get List of Active Users",
        IDLE_LIST => "Get List of Idle Users",
        ADD_USER => "Add User",
        DELETE_USER => "Delete User",
        DISABLE_USER => "Disable User",
        REENABLE_USER => "Re-Enable User",
        END_USER_SESSION => "End User Session",
        CHANGE_USER_PASSWORD => "Change User Password",
        GET_USER_ROSTER => "Get User Roster",
        GET_USER_LAST_LOGIN => "Get User Last Login Time",
        USER_STATS => "Get User Statistics",
        EDIT_ADMIN => "Edit Administrator List",
        ANNOUNCE => "Send Announcement to Active Users",
        SET_MOTD => "Set Message of the Day",
        EDIT_MOTD => "Edit Message of the Day",
        DELETE_MOTD => "Delete Message of the Day",
        SET_WELCOME => "Set Welcome Message",
        DELETE_WELCOME => "Delete Welcome Message",
        EDIT_BLACKLIST => "Edit Federation Blacklist",
        EDIT_WHITELIST => "Edit Federation Whitelist",
        RESTART => "Restart Service",
        SHUTDOWN => "Shut Down Service",
        _ => "Unknown Command",
    }
}

fn command_enabled(session: &ProtocolSession, node: &str) -> bool {
    !matches!(node, RESTART | SHUTDOWN)
        || (session.state.config.enable_xmpp_service_control
            && session.state.service_control_available())
}

async fn current_admin(session: &ProtocolSession) -> Result<Option<AdminActor>> {
    let Some(cached) = session.authenticated.as_ref() else {
        return Ok(None);
    };
    let cached = AdminActor::new(cached.id, cached.username.clone(), cached.auth_generation);
    session
        .state
        .admin_command_service()
        .current_admin(&cached)
        .await
}

pub(crate) async fn available_to(session: &ProtocolSession) -> Result<bool> {
    Ok(current_admin(session).await?.is_some())
}

pub(crate) async fn disco_info(
    session: &ProtocolSession,
    id: &str,
    responder: &str,
    node: &str,
) -> Result<Option<String>> {
    if current_admin(session).await?.is_none() || !command_enabled(session, node) {
        return Ok(None);
    }
    if node == COMMANDS_NS {
        let query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
            .attr("node", COMMANDS_NS)
            .child(
                XmlElement::new("identity")
                    .attr("category", "automation")
                    .attr("type", "command-list")
                    .attr("name", "Service Administration"),
            )
            .child(XmlElement::new("feature").attr("var", COMMANDS_NS))
            .child(XmlElement::new("feature").attr("var", DATA_NS));
        return Ok(Some(iq_result_from(id, responder, query)));
    }
    if is_command(node) {
        let query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
            .attr("node", node)
            .child(
                XmlElement::new("identity")
                    .attr("category", "automation")
                    .attr("type", "command-node")
                    .attr("name", command_name(node)),
            )
            .child(XmlElement::new("feature").attr("var", COMMANDS_NS))
            .child(XmlElement::new("feature").attr("var", DATA_NS));
        return Ok(Some(iq_result_from(id, responder, query)));
    }
    Ok(None)
}

pub(crate) async fn disco_items(
    session: &ProtocolSession,
    id: &str,
    responder: &str,
    node: &str,
) -> Result<Option<String>> {
    if node != COMMANDS_NS || current_admin(session).await?.is_none() {
        return Ok(None);
    }
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items")
        .attr("node", COMMANDS_NS);
    for command in COMMANDS
        .iter()
        .copied()
        .filter(|command| command_enabled(session, command))
    {
        query.push_child(
            XmlElement::new("item")
                .attr("jid", responder)
                .attr("node", command)
                .attr("name", command_name(command)),
        );
    }
    Ok(Some(iq_result_from(id, responder, query)))
}

pub(crate) async fn handle(
    session: &ProtocolSession,
    id: &str,
    root: Node<'_, '_>,
    command: Node<'_, '_>,
) -> Result<Action> {
    let responder = &session.state.config.domain;
    let node = command.attribute("node").unwrap_or_default();
    let Some(actor) = current_admin(session).await? else {
        return Ok(Action::Send(command_error(
            id,
            responder,
            node,
            "forbidden",
            "auth",
            None,
        )));
    };
    if session.full_jid.is_none() {
        return Ok(Action::Send(command_error(
            id,
            responder,
            node,
            "forbidden",
            "cancel",
            None,
        )));
    }
    if root.attribute("to").is_some_and(|to| {
        !crate::jid::CanonicalJid::parse_bare(to)
            .is_ok_and(|target| target.localpart().is_none() && target.domainpart() == responder)
    }) {
        return Ok(Action::Send(command_error(
            id,
            responder,
            node,
            "item-not-found",
            "cancel",
            None,
        )));
    }
    if !is_command(node) || !command_enabled(session, node) {
        return Ok(Action::Send(command_error(
            id,
            responder,
            node,
            "item-not-found",
            "cancel",
            None,
        )));
    }
    // XEP-0050 requires recipients to ignore a requester-supplied `status`.
    if command.attributes().any(|attribute| {
        attribute.namespace().is_none()
            && !matches!(attribute.name(), "node" | "action" | "sessionid" | "status")
    }) {
        return Ok(Action::Send(command_error(
            id,
            responder,
            node,
            "bad-request",
            "modify",
            Some("bad-payload"),
        )));
    }

    let action = command.attribute("action").unwrap_or("execute");
    if !matches!(action, "execute" | "cancel" | "prev" | "next" | "complete") {
        return Ok(Action::Send(command_error(
            id,
            responder,
            node,
            "bad-request",
            "modify",
            Some("malformed-action"),
        )));
    }
    let owner = session.full_jid.as_deref().unwrap_or_default();
    let session_id = command.attribute("sessionid");

    if action == "cancel" {
        let Some(session_id) = session_id else {
            return Ok(Action::Send(command_error(
                id,
                responder,
                node,
                "bad-request",
                "modify",
                Some("bad-sessionid"),
            )));
        };
        if !valid_command_bearer(session_id) {
            return Ok(Action::Send(command_error(
                id,
                responder,
                node,
                "bad-request",
                "modify",
                Some("bad-sessionid"),
            )));
        }
        let state = session
            .state
            .admin_command_service()
            .finish_session(session_id, &actor, owner, node, "canceled")
            .await?;
        return Ok(Action::Send(match state {
            CommandSessionOutcome::Finished => {
                command_result(id, responder, node, session_id, "canceled", "")
            }
            CommandSessionOutcome::Expired => command_error(
                id,
                responder,
                node,
                "not-allowed",
                "cancel",
                Some("session-expired"),
            ),
            CommandSessionOutcome::Invalid => command_error(
                id,
                responder,
                node,
                "bad-request",
                "modify",
                Some("bad-sessionid"),
            ),
        }));
    }

    match session_id {
        None => {
            if action != "execute" {
                return Ok(Action::Send(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-action"),
                )));
            }
            if command.children().any(|child| child.is_element()) {
                return Ok(Action::Send(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-payload"),
                )));
            }
            if !is_count_command(node) {
                let Some(session_id) = session
                    .state
                    .admin_command_service()
                    .create_session(&actor, owner, &session.state.config.domain, node, "form")
                    .await?
                else {
                    return Ok(Action::Send(command_error(
                        id,
                        responder,
                        node,
                        "resource-constraint",
                        "wait",
                        None,
                    )));
                };
                Ok(Action::Send(command_result(
                    id,
                    responder,
                    node,
                    session_id.as_str(),
                    "executing",
                    &request_form(session, &actor, node).await?,
                )))
            } else {
                let Some(session_id) = session
                    .state
                    .admin_command_service()
                    .create_session(
                        &actor,
                        owner,
                        &session.state.config.domain,
                        node,
                        "executing",
                    )
                    .await?
                else {
                    return Ok(Action::Send(command_error(
                        id,
                        responder,
                        node,
                        "resource-constraint",
                        "wait",
                        None,
                    )));
                };
                let payload = execute_count_command(session, &actor, node).await?;
                let finished = session
                    .state
                    .admin_command_service()
                    .complete_count_session(session_id.as_str(), &actor, owner, node, &payload)
                    .await?;
                if finished != CommandSessionOutcome::Finished {
                    return Ok(Action::Send(command_error(
                        id,
                        responder,
                        node,
                        "forbidden",
                        "auth",
                        None,
                    )));
                }
                Ok(Action::Send(command_result(
                    id,
                    responder,
                    node,
                    session_id.as_str(),
                    "completed",
                    &payload,
                )))
            }
        }
        Some(session_id) => {
            if !valid_command_bearer(session_id) {
                return Ok(Action::Send(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-sessionid"),
                )));
            }
            if is_count_command(node) || !matches!(action, "execute" | "complete") {
                return Ok(Action::Send(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-action"),
                )));
            }
            let submission = match parse_submission(command, node) {
                Ok(value) => value,
                Err(()) => {
                    return Ok(Action::Send(command_error(
                        id,
                        responder,
                        node,
                        "bad-request",
                        "modify",
                        Some("bad-payload"),
                    )));
                }
            };
            let target_digest = command_target_digest(node, &submission);
            let claim = match session
                .state
                .admin_command_service()
                .begin_execution(session_id, &actor, owner, node, &target_digest)
                .await?
            {
                CommandExecutionOutcome::Started(claim) => claim,
                CommandExecutionOutcome::Completed(payload) => {
                    return Ok(Action::Send(command_result(
                        id,
                        responder,
                        node,
                        session_id,
                        "completed",
                        &payload,
                    )));
                }
                CommandExecutionOutcome::Busy => {
                    return Ok(Action::Send(command_error(
                        id,
                        responder,
                        node,
                        "resource-constraint",
                        "wait",
                        None,
                    )));
                }
                CommandExecutionOutcome::Expired => {
                    return Ok(Action::Send(command_error(
                        id,
                        responder,
                        node,
                        "not-allowed",
                        "cancel",
                        Some("session-expired"),
                    )));
                }
                CommandExecutionOutcome::Invalid => {
                    return Ok(Action::Send(command_error(
                        id,
                        responder,
                        node,
                        "bad-request",
                        "modify",
                        Some("bad-sessionid"),
                    )));
                }
            };
            let command_execution =
                execute_form_command(session, &actor, &claim, node, submission).await;
            if command_execution
                .as_ref()
                .is_err_and(crate::password_work::is_overloaded)
            {
                if session
                    .state
                    .admin_command_service()
                    .release_execution(&actor, &claim, node)
                    .await?
                    != ExecutionReleaseOutcome::Released
                {
                    return Ok(Action::Send(command_error(
                        id, responder, node, "conflict", "cancel", None,
                    )));
                }
                return Ok(Action::Send(command_error(
                    id,
                    responder,
                    node,
                    "resource-constraint",
                    "wait",
                    None,
                )));
            }
            if command_execution
                .as_ref()
                .is_err_and(|error| error.downcast_ref::<AdminCommandRetryable>().is_some())
            {
                let _ = session
                    .state
                    .admin_command_service()
                    .release_execution(&actor, &claim, node)
                    .await?;
                return Ok(Action::Send(command_error(
                    id,
                    responder,
                    node,
                    "resource-constraint",
                    "wait",
                    None,
                )));
            }
            let Some(payload) = command_execution? else {
                if session
                    .state
                    .admin_command_service()
                    .release_execution(&actor, &claim, node)
                    .await?
                    != ExecutionReleaseOutcome::Released
                {
                    return Ok(Action::Send(command_error(
                        id, responder, node, "conflict", "cancel", None,
                    )));
                }
                return Ok(Action::Send(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-payload"),
                )));
            };
            if is_read_form_command(node)
                && session
                    .state
                    .admin_command_service()
                    .complete_read_execution(&actor, &claim, node, &payload)
                    .await?
                    != AdminWriteOutcome::Applied
            {
                return Ok(Action::Send(command_error(
                    id,
                    responder,
                    node,
                    "forbidden",
                    "auth",
                    None,
                )));
            }
            Ok(Action::Send(command_result(
                id,
                responder,
                node,
                session_id,
                "completed",
                &payload,
            )))
        }
    }
}

fn form_type_field() -> XmlElement {
    XmlElement::new("field")
        .attr("var", "FORM_TYPE")
        .attr("type", "hidden")
        .child(XmlElement::new("value").text(ADMIN_FORM_TYPE))
}

fn result_field(variable: &str, value: impl Into<String>) -> XmlElement {
    XmlElement::new("field")
        .attr("var", variable)
        .child(XmlElement::new("value").text(value))
}

async fn execute_count_command(
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

async fn execute_list_command(
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
                .map(|username| local_account_jid(&username, &session.state.config.domain))
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
                    .map(|username| local_account_jid(&username, &session.state.config.domain))
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

async fn execute_form_command(
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
                &session.state.config.domain,
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
                        session.state.config.scram_iterations,
                        session.state.config.scram_sha1_enabled,
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
                    let Ok(jid) = crate::jid::CanonicalJid::parse(value.trim()) else {
                        return Ok(None);
                    };
                    if jid.domainpart() != session.state.config.domain || jid.localpart().is_none()
                    {
                        return Ok(None);
                    }
                    let Ok(username) = crate::auth::normalize_username(
                        jid.localpart().expect("localpart checked"),
                    ) else {
                        return Ok(None);
                    };
                    (username, jid.resourcepart().is_some().then_some(jid))
                } else {
                    let Some(username) =
                        local_account_username(Some(value), &session.state.config.domain)
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
                    &session.state.config.domain,
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
                &session.state.config.domain,
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
            let outcome = session
                .state
                .admin_command_service()
                .reset_account_password(
                    actor,
                    claim,
                    node,
                    &username,
                    password,
                    session.state.config.scram_iterations,
                    session.state.config.scram_sha1_enabled,
                    &session.state.config.domain,
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
                &session.state.config.domain,
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
                let account = local_account_jid(&target.username, &session.state.config.domain)?;
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
                local_account_jid(&roster.account.username, &session.state.config.domain)?;
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
                &session.state.config.domain,
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
                        local_account_jid(&stats.account.username, &session.state.config.domain)?,
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
                    local_account_username(Some(value), &session.state.config.domain)
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
                let Ok(jid) = crate::jid::CanonicalJid::parse(value.trim()) else {
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
                session.state.config.domain,
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

fn local_account_username(value: Option<&str>, domain: &str) -> Option<String> {
    let jid = crate::jid::CanonicalJid::parse_bare(value?.trim()).ok()?;
    if jid.domainpart() != domain || jid.resourcepart().is_some() {
        return None;
    }
    crate::auth::normalize_username(jid.localpart()?).ok()
}

fn local_account_jid(username: &str, domain: &str) -> Result<String> {
    let jid = crate::jid::CanonicalJid::parse_bare(&format!("{username}@{domain}"))?;
    anyhow::ensure!(
        jid.localpart() == Some(username) && jid.domainpart() == domain,
        "local account identity changed during JID preparation"
    );
    Ok(jid.to_string())
}

fn empty_result() -> String {
    XmlElement::namespaced("x", DATA_NS)
        .attr("type", "result")
        .child(form_type_field())
        .finish()
}

fn joined_text_field(submission: &Submission, name: &str) -> Option<String> {
    let body = submission.many(name).ok()?.join("\n");
    (!body.trim().is_empty() && body.len() <= 65_536).then_some(body)
}

async fn send_announcement(
    session: &ProtocolSession,
    actor: &AdminActor,
    body: &str,
) -> Result<usize> {
    let stanza = XmlElement::namespaced("message", "jabber:client")
        .attr("from", &session.state.config.domain)
        .attr("type", "headline")
        .attr("id", uuid::Uuid::new_v4())
        .child(XmlElement::new("body").text(body.to_owned()))
        .finish();
    // Keep only the bounded local-session identity set in memory. Cluster
    // accounts are traversed once in a keyset-paginated database snapshot and
    // counted as each page is released, so a 100k-account announcement cannot
    // grow a second 100k-entry recipient set in this protocol task.
    let mut local_recipients = BTreeSet::new();
    for entry in session.state.sessions.iter() {
        if entry
            .value()
            .routable
            .load(std::sync::atomic::Ordering::Acquire)
            && entry
                .value()
                .available
                .load(std::sync::atomic::Ordering::Acquire)
            && entry
                .value()
                .priority
                .load(std::sync::atomic::Ordering::Acquire)
                >= 0
            && entry.value().sender.try_send(stanza.clone()).is_ok()
        {
            if let Ok(bare) = crate::jid::canonical_bare_key(entry.key()) {
                local_recipients.insert(bare);
            }
        }
    }
    let mut recipient_count = local_recipients.len();
    if session.state.cluster.is_enabled() {
        let mut cursor = None;
        loop {
            let page = session
                .state
                .admin_command_service()
                .announcement_account_page(actor, cursor.as_ref())
                .await?
                .ok_or_else(|| anyhow::anyhow!("administrator authorization changed"))?;
            for username in page.usernames {
                let bare = local_account_jid(&username, &session.state.config.domain)?;
                let mut delivered_remotely = false;
                for node_id in session.state.cluster.lookup_nodes(&bare).await? {
                    if node_id != session.state.cluster.node_id
                        && session
                            .state
                            .cluster
                            .send_to_node_available(&node_id, &bare, &stanza)
                            .await?
                    {
                        delivered_remotely = true;
                    }
                }
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

async fn online_bare_jids(session: &ProtocolSession) -> Result<BTreeSet<String>> {
    let mut users = session
        .state
        .sessions
        .iter()
        .filter(|entry| entry.routable.load(std::sync::atomic::Ordering::Acquire))
        .filter_map(|entry| crate::jid::canonical_bare_key(entry.key()).ok())
        .collect::<BTreeSet<_>>();
    users.extend(session.state.cluster.online_bare_jids().await?);
    Ok(users)
}

async fn activity_bare_jids(
    session: &ProtocolSession,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let idle_after = std::time::Duration::from_secs(session.state.config.admin_idle_seconds);
    let mut online = BTreeSet::new();
    let mut active = BTreeSet::new();
    for entry in session.state.sessions.iter() {
        if !entry.routable.load(std::sync::atomic::Ordering::Acquire) {
            continue;
        }
        let Ok(bare) = crate::jid::canonical_bare_key(entry.key()) else {
            continue;
        };
        online.insert(bare.clone());
        if entry
            .last_activity
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .elapsed()
            < idle_after
        {
            active.insert(bare);
        }
    }
    let cluster_active = session
        .state
        .cluster
        .activity_bare_jids(session.state.config.admin_idle_seconds, true)
        .await?;
    let cluster_idle = session
        .state
        .cluster
        .activity_bare_jids(session.state.config.admin_idle_seconds, false)
        .await?;
    active.extend(cluster_active);
    online.extend(active.iter().cloned());
    online.extend(cluster_idle);
    let idle = online.difference(&active).cloned().collect();
    Ok((active, idle))
}

async fn request_form(session: &ProtocolSession, actor: &AdminActor, node: &str) -> Result<String> {
    if is_list_command(node) {
        return Ok(list_request_form(node));
    }
    let fields = match node {
        ADD_USER => vec![
            field("accountjid", "jid-single", "The account JID", true, &[]),
            field("password", "text-private", "Password", true, &[]),
            field(
                "password-verify",
                "text-private",
                "Verify password",
                true,
                &[],
            ),
        ],
        DELETE_USER | DISABLE_USER | REENABLE_USER | END_USER_SESSION | GET_USER_ROSTER
        | GET_USER_LAST_LOGIN => vec![field("accountjids", "jid-multi", "Account JIDs", true, &[])],
        CHANGE_USER_PASSWORD => vec![
            field("accountjid", "jid-single", "The account JID", true, &[]),
            field("password", "text-private", "New password", true, &[]),
        ],
        USER_STATS => vec![field(
            "accountjid",
            "jid-single",
            "The account JID",
            true,
            &[],
        )],
        EDIT_ADMIN => {
            let rows = session
                .state
                .admin_command_service()
                .administrator_usernames(actor)
                .await?
                .ok_or_else(|| anyhow::anyhow!("administrator authorization changed"))?;
            anyhow::ensure!(
                !rows.truncated,
                "administrator list exceeds the XEP-0133 form bound"
            );
            let values = rows
                .usernames
                .iter()
                .map(|username| local_account_jid(username, &session.state.config.domain))
                .collect::<Result<Vec<_>>>()?;
            vec![field(
                "adminjids",
                "jid-multi",
                "Administrator JIDs",
                true,
                &values,
            )]
        }
        RESTART | SHUTDOWN => {
            let phrase = format!(
                "{} {}",
                if node == RESTART {
                    "RESTART"
                } else {
                    "SHUTDOWN"
                },
                session.state.config.domain,
            );
            vec![
                field(
                    "confirm",
                    "text-single",
                    &format!("Type {phrase}, or CANCEL to cancel a pending operation"),
                    true,
                    &[],
                ),
                field(
                    "delay",
                    "text-single",
                    "Delay in seconds (5-3600)",
                    true,
                    &["30".to_owned()],
                ),
                field(
                    "announcement",
                    "text-multi",
                    "Optional announcement",
                    false,
                    &[String::new()],
                ),
            ]
        }
        ANNOUNCE => vec![field(
            "announcement",
            "text-multi",
            "Announcement",
            true,
            &[],
        )],
        SET_MOTD | EDIT_MOTD => {
            let current = session
                .state
                .admin_command_service()
                .service_message_body(actor, "motd")
                .await?
                .into_iter()
                .collect::<Vec<_>>();
            vec![field(
                "motd",
                "text-multi",
                "Message of the day",
                true,
                &current,
            )]
        }
        SET_WELCOME => {
            let current = session
                .state
                .admin_command_service()
                .service_message_body(actor, "welcome")
                .await?
                .into_iter()
                .collect::<Vec<_>>();
            vec![field(
                "welcome",
                "text-multi",
                "Welcome message",
                true,
                &current,
            )]
        }
        DELETE_MOTD | DELETE_WELCOME => vec![field(
            "confirm",
            "boolean",
            "Confirm deletion",
            true,
            &["0".to_owned()],
        )],
        EDIT_BLACKLIST | EDIT_WHITELIST => {
            let (kind, variable) = if node == EDIT_BLACKLIST {
                ("blacklist", "blacklistjids")
            } else {
                ("whitelist", "whitelistjids")
            };
            let current = session
                .state
                .admin_command_service()
                .federation_rule_domains(actor, kind)
                .await?
                .ok_or_else(|| anyhow::anyhow!("administrator authorization changed"))?;
            vec![field(
                variable,
                "jid-multi",
                "Federation entities",
                false,
                &current,
            )]
        }
        _ => unreachable!("all interactive commands have a form"),
    };
    let mut form = XmlElement::namespaced("x", DATA_NS)
        .attr("type", "form")
        .child(XmlElement::new("title").text(command_name(node)))
        .child(XmlElement::new("instructions").text("Complete this administrative operation."))
        .child(form_type_field());
    for field in fields {
        form.push_child(field);
    }
    Ok(command_form_fragment(form))
}

fn field(var: &str, kind: &str, label: &str, required: bool, values: &[String]) -> XmlElement {
    let mut field = XmlElement::new("field")
        .attr("var", var)
        .attr("type", kind)
        .attr("label", label);
    for value in values {
        field.push_child(XmlElement::new("value").text(value.clone()));
    }
    if required {
        field.push_child(XmlElement::new("required"));
    }
    field
}

fn command_form_fragment(form: XmlElement) -> String {
    XmlElement::new("northstar-fragment")
        .child(
            XmlElement::new("actions")
                .attr("execute", "complete")
                .child(XmlElement::new("complete")),
        )
        .child(form)
        .finish_children()
}

fn list_request_form(node: &str) -> String {
    let subject = match node {
        ONLINE_LIST => "online users",
        DISABLED_LIST => "disabled users",
        ACTIVE_LIST => "active users",
        IDLE_LIST => "idle users",
        _ => "registered users",
    };
    let mut maximum = XmlElement::new("field")
        .attr("var", "max_items")
        .attr("type", "list-single")
        .attr("label", "Maximum number of items to show")
        .child(XmlElement::new("value").text("100"));
    for value in [25, 50, 75, 100, 150, 200] {
        maximum.push_child(
            XmlElement::new("option")
                .attr("label", value)
                .child(XmlElement::new("value").text(value.to_string())),
        );
    }
    let form = XmlElement::namespaced("x", DATA_NS)
        .attr("type", "form")
        .child(XmlElement::new("title").text(command_name(node)))
        .child(XmlElement::new("instructions").text(format!("Select a bounded page of {subject}.")))
        .child(form_type_field())
        .child(maximum)
        .child(
            XmlElement::new("field")
                .attr("var", "start")
                .attr("type", "text-single")
                .attr("label", "Zero-based page offset")
                .child(XmlElement::new("value").text("0")),
        );
    command_form_fragment(form)
}

#[derive(Debug, Eq, PartialEq)]
struct Submission {
    fields: HashMap<String, Vec<String>>,
}

impl Submission {
    fn one(&self, name: &str) -> std::result::Result<&str, ()> {
        let values = self.fields.get(name).ok_or(())?;
        let [value] = values.as_slice() else {
            return Err(());
        };
        Ok(value)
    }

    fn many(&self, name: &str) -> std::result::Result<&[String], ()> {
        self.fields.get(name).map(Vec::as_slice).ok_or(())
    }
}

/// Bind a claim to the exact canonical form submission. The database stores
/// only an owner-keyed HMAC of this digest, so passwords and low-entropy form
/// values do not leave a dictionary-testable durable hash behind.
fn command_target_digest(node: &str, submission: &Submission) -> [u8; 32] {
    fn append(digest: &mut Sha256, value: &[u8]) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }

    let mut digest = Sha256::new();
    digest.update(b"northstar-admin-command-target-v2\0");
    append(&mut digest, node.as_bytes());
    let mut fields = submission.fields.iter().collect::<Vec<_>>();
    fields.sort_unstable_by(|left, right| left.0.cmp(right.0));
    for (name, values) in fields {
        append(&mut digest, name.as_bytes());
        digest.update((values.len() as u64).to_be_bytes());
        for value in values {
            append(&mut digest, value.as_bytes());
        }
    }
    digest.finalize().into()
}

fn expected_fields(node: &str) -> &'static [&'static str] {
    match node {
        ONLINE_LIST | REGISTERED_LIST | DISABLED_LIST | ACTIVE_LIST | IDLE_LIST => {
            &["max_items", "start"]
        }
        ADD_USER => &["accountjid", "password", "password-verify"],
        CHANGE_USER_PASSWORD => &["accountjid", "password"],
        USER_STATS => &["accountjid"],
        EDIT_ADMIN => &["adminjids"],
        ANNOUNCE => &["announcement"],
        SET_MOTD | EDIT_MOTD => &["motd"],
        SET_WELCOME => &["welcome"],
        DELETE_MOTD | DELETE_WELCOME => &["confirm"],
        EDIT_BLACKLIST => &["blacklistjids"],
        EDIT_WHITELIST => &["whitelistjids"],
        RESTART | SHUTDOWN => &["confirm", "delay", "announcement"],
        DELETE_USER | DISABLE_USER | REENABLE_USER | END_USER_SESSION | GET_USER_ROSTER
        | GET_USER_LAST_LOGIN => &["accountjids"],
        _ => &[],
    }
}

fn parse_submission(command: Node<'_, '_>, node: &str) -> std::result::Result<Submission, ()> {
    let elements = command
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    let [form] = elements.as_slice() else {
        return Err(());
    };
    if form.tag_name().name() != "x"
        || form.tag_name().namespace() != Some(DATA_NS)
        || form.attribute("type") != Some("submit")
        || form
            .attributes()
            .any(|attribute| attribute.namespace().is_none() && attribute.name() != "type")
        || form
            .children()
            .any(|child| child.is_text() && !child.text().unwrap_or_default().trim().is_empty())
    {
        return Err(());
    }
    let expected = expected_fields(node);
    let mut fields = HashMap::<String, Vec<String>>::new();
    for field in form.children().filter(|child| child.is_element()) {
        if field.tag_name().name() != "field" || field.tag_name().namespace() != Some(DATA_NS) {
            return Err(());
        }
        let variable = field.attribute("var").ok_or(())?;
        if field.attributes().any(|attribute| {
            attribute.namespace().is_none() && !matches!(attribute.name(), "var" | "type")
        }) || (variable != "FORM_TYPE" && !expected.contains(&variable))
            || fields.contains_key(variable)
            || field
                .children()
                .any(|child| child.is_text() && !child.text().unwrap_or_default().trim().is_empty())
        {
            return Err(());
        }
        let values = field
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        if (values.is_empty()
            && !(matches!(node, EDIT_BLACKLIST | EDIT_WHITELIST) && variable != "FORM_TYPE"))
            || values.len() > MAX_ACCOUNT_ITEMS
            || values.iter().any(|value| {
                value.tag_name().name() != "value"
                    || value.tag_name().namespace() != Some(DATA_NS)
                    || value.attributes().len() != 0
                    || value.children().any(|child| child.is_element())
            })
        {
            return Err(());
        }
        let values = values
            .into_iter()
            .map(|value| value.text().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        fields.insert(variable.to_owned(), values);
    }
    if fields.get("FORM_TYPE").map(Vec::as_slice) != Some(&[ADMIN_FORM_TYPE.to_owned()][..])
        || expected.iter().any(|field| !fields.contains_key(*field))
        || fields.len() != expected.len() + 1
    {
        return Err(());
    }
    Ok(Submission { fields })
}

fn command_result(
    id: &str,
    from: &str,
    node: &str,
    session_id: &str,
    status: &str,
    payload: &str,
) -> String {
    let mut command = XmlElement::namespaced("command", COMMANDS_NS)
        .attr("node", node)
        .attr("sessionid", session_id)
        .attr("status", status);
    if !payload.is_empty() {
        if let Err(error) = command.push_validated_fragment(payload) {
            tracing::error!(?error, %node, "stored command result contains malformed XML");
            return command_error(id, from, node, "internal-server-error", "wait", None);
        }
    }
    iq_result_from(id, from, command)
}

fn iq_result_from(id: &str, from: &str, payload: XmlElement) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "result")
        .attr("from", from)
        .attr("id", id)
        .child(payload)
        .finish()
}

fn command_error(
    id: &str,
    from: &str,
    node: &str,
    condition: &str,
    error_type: &str,
    command_condition: Option<&str>,
) -> String {
    let stanza_condition = XmlElement::dynamic(condition)
        .expect("XMPP stanza error condition must be a valid QName")
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    let mut error = XmlElement::new("error")
        .attr("type", error_type)
        .child(stanza_condition);
    if let Some(command_condition) = command_condition {
        error.push_child(
            XmlElement::dynamic(command_condition)
                .expect("XEP-0050 command error condition must be a valid QName")
                .attr("xmlns", COMMANDS_NS),
        );
    }
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("id", id)
        .child(XmlElement::namespaced("command", COMMANDS_NS).attr("node", node))
        .child(error)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use roxmltree::Document;

    #[test]
    fn uses_the_registered_xep_0133_nodes() {
        assert!(is_command(ONLINE_COUNT));
        assert!(is_command(ONLINE_LIST));
        assert!(is_command(REGISTERED_COUNT));
        assert!(is_command(REGISTERED_LIST));
        assert!(is_command(ADD_USER));
        assert!(is_command(EDIT_ADMIN));
        assert!(!is_command(
            "http://jabber.org/protocol/admin#get-user-password"
        ));
        assert!(!is_command(
            "http://jabber.org/protocol/admin#get-online-users"
        ));
    }

    #[test]
    fn command_bearers_are_opaque_fixed_size_values() {
        assert!(valid_command_bearer(&"A1".repeat(32)));
        assert!(!valid_command_bearer(&"A1".repeat(31)));
        assert!(!valid_command_bearer(&format!("{}-", "A".repeat(63))));
    }

    #[test]
    fn command_target_digest_is_field_order_independent_but_value_order_sensitive() {
        let first = Submission {
            fields: HashMap::from([
                (
                    "accountjids".to_owned(),
                    vec!["a@example.test".to_owned(), "b@example.test".to_owned()],
                ),
                ("confirm".to_owned(), vec!["1".to_owned()]),
            ]),
        };
        let reordered_fields = Submission {
            fields: HashMap::from([
                ("confirm".to_owned(), vec!["1".to_owned()]),
                (
                    "accountjids".to_owned(),
                    vec!["a@example.test".to_owned(), "b@example.test".to_owned()],
                ),
            ]),
        };
        let reordered_values = Submission {
            fields: HashMap::from([
                ("confirm".to_owned(), vec!["1".to_owned()]),
                (
                    "accountjids".to_owned(),
                    vec!["b@example.test".to_owned(), "a@example.test".to_owned()],
                ),
            ]),
        };
        assert_eq!(
            command_target_digest(DELETE_USER, &first),
            command_target_digest(DELETE_USER, &reordered_fields)
        );
        assert_ne!(
            command_target_digest(DELETE_USER, &first),
            command_target_digest(DELETE_USER, &reordered_values)
        );
        assert_ne!(
            command_target_digest(DELETE_USER, &first),
            command_target_digest(DISABLE_USER, &first)
        );
    }

    #[test]
    fn parses_a_bounded_list_submission_and_rejects_duplicate_fields() {
        let good_xml = format!(
            "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='max_items'><value>150</value></field><field var='start'><value>25</value></field></x></command>"
        );
        let good = Document::parse(&good_xml).unwrap();
        let parsed = parse_submission(good.root_element(), REGISTERED_LIST).unwrap();
        assert_eq!(parsed.one("max_items"), Ok("150"));
        assert_eq!(parsed.one("start"), Ok("25"));

        let duplicate_xml = format!(
            "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='max_items'><value>25</value></field><field var='max_items'><value>50</value></field><field var='start'><value>0</value></field></x></command>"
        );
        let duplicate = Document::parse(&duplicate_xml).unwrap();
        assert_eq!(
            parse_submission(duplicate.root_element(), REGISTERED_LIST),
            Err(())
        );
    }

    #[test]
    fn rejects_wrong_form_namespaces_unknown_fields_and_oversized_lists() {
        for xml in [
            format!(
                "<command xmlns='{COMMANDS_NS}'><x xmlns='urn:wrong' type='submit'/></command>"
            ),
            format!(
                "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='unknown'><value>1</value></field><field var='max_items'><value>25</value></field><field var='start'><value>0</value></field></x></command>"
            ),
            format!(
                "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='max_items'><value>201</value></field><field var='start'><value>0</value></field></x></command>"
            ),
        ] {
            let document = Document::parse(&xml).unwrap();
            let parsed = parse_submission(document.root_element(), REGISTERED_LIST);
            if let Ok(parsed) = parsed {
                assert!(
                    parsed
                        .one("max_items")
                        .ok()
                        .and_then(|value| value.parse::<usize>().ok())
                        .is_none_or(|value| !(1..=MAX_LIST_ITEMS).contains(&value))
                );
            }
        }
    }

    #[test]
    fn command_errors_use_xep_0050_error_types_and_escape_input() {
        let error = command_error(
            "id'1",
            "example.test",
            "node&x",
            "bad-request",
            "modify",
            Some("bad-sessionid"),
        );
        assert!(error.contains("type='modify'"));
        assert!(error.contains("<bad-sessionid xmlns='http://jabber.org/protocol/commands'/"));
        assert!(error.contains("id='id&apos;1'"));
        assert!(error.contains("node='node&amp;x'"));
        Document::parse(&error).unwrap();
    }

    #[test]
    fn command_output_builder_contains_hostile_runtime_values() {
        let hostile = "x'&<injected xmlns='urn:evil'/>\r\n🙂";
        let result = command_result(hostile, hostile, hostile, hostile, hostile, "");
        let document = Document::parse(&result).unwrap();
        let iq = document.root_element();
        let command = iq.children().find(|child| child.is_element()).unwrap();
        assert_eq!(iq.attribute("id"), Some(hostile));
        assert_eq!(iq.attribute("from"), Some(hostile));
        assert_eq!(command.attribute("node"), Some(hostile));
        assert_eq!(command.attribute("sessionid"), Some(hostile));
        assert_eq!(command.attribute("status"), Some(hostile));
        assert_eq!(
            document
                .descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "injected")
                .count(),
            0
        );

        let field = field(
            "runtime",
            "text-single",
            hostile,
            true,
            &[hostile.to_owned()],
        );
        let field_xml = field.finish();
        let document = Document::parse(&field_xml).unwrap();
        let field = document.root_element();
        assert_eq!(field.attribute("label"), Some(hostile));
        assert_eq!(
            field
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "value")
                .and_then(|node| node.text()),
            Some(hostile)
        );
    }

    #[test]
    fn malformed_cached_command_payload_fails_closed_without_panicking() {
        let result = command_result(
            "request-id",
            "example.test",
            REGISTERED_LIST,
            "session-id",
            "completed",
            "<x><broken></x>",
        );
        let document = Document::parse(&result).unwrap();
        let iq = document.root_element();
        assert_eq!(iq.attribute("type"), Some("error"));
        assert!(document.descendants().any(|node| {
            node.is_element()
                && node.tag_name().name() == "internal-server-error"
                && node.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
        }));
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_command_sessions_are_cross_node_atomic() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let admin = uuid::Uuid::new_v4();
        let username = "cmd";
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',TRUE)",
        )
        .bind(admin)
        .bind(username)
        .execute(&pool)
        .await
        .unwrap();
        let owner = "cmd@example.test/Console";
        let command = db::create_admin_command_session(
            &pool,
            admin,
            owner,
            "example.test",
            0,
            REGISTERED_LIST,
            "form",
        )
        .await
        .unwrap()
        .unwrap();

        let first_pool = pool.clone();
        let second_pool = pool.clone();
        let first_bearer = command.to_string();
        let second_bearer = command.to_string();
        let first = tokio::spawn(async move {
            crate::db::finish_admin_command_session(
                &first_pool,
                &first_bearer,
                admin,
                owner,
                0,
                REGISTERED_LIST,
                "canceled",
            )
            .await
            .unwrap()
        });
        let second = tokio::spawn(async move {
            crate::db::finish_admin_command_session(
                &second_pool,
                &second_bearer,
                admin,
                owner,
                0,
                REGISTERED_LIST,
                "canceled",
            )
            .await
            .unwrap()
        });
        let outcomes = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|state| **state == crate::db::AdminCommandSessionState::Finished)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|state| **state == crate::db::AdminCommandSessionState::Invalid)
                .count(),
            1
        );

        let demoted = db::create_admin_command_session(
            &pool,
            admin,
            owner,
            "example.test",
            0,
            ONLINE_LIST,
            "form",
        )
        .await
        .unwrap()
        .unwrap();
        sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            crate::db::finish_admin_command_session(
                &pool,
                demoted.as_str(),
                admin,
                owner,
                0,
                ONLINE_LIST,
                "canceled",
            )
            .await
            .unwrap(),
            crate::db::AdminCommandSessionState::Invalid
        );
        sqlx::query("UPDATE users SET is_admin=TRUE WHERE id=$1")
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();

        let expired = db::create_admin_command_session(
            &pool,
            admin,
            owner,
            "example.test",
            0,
            ONLINE_LIST,
            "form",
        )
        .await
        .unwrap()
        .unwrap();
        sqlx::query(
            "UPDATE admin_command_sessions
                SET expires_at=NOW()-INTERVAL '1 second'
              WHERE owner_id=$1 AND node=$2 AND completed_at IS NULL",
        )
        .bind(admin)
        .bind(ONLINE_LIST)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            crate::db::finish_admin_command_session(
                &pool,
                expired.as_str(),
                admin,
                owner,
                0,
                ONLINE_LIST,
                "canceled",
            )
            .await
            .unwrap(),
            crate::db::AdminCommandSessionState::Expired
        );

        let execution = db::create_admin_command_session(
            &pool,
            admin,
            owner,
            "example.test",
            0,
            REGISTERED_LIST,
            "form",
        )
        .await
        .unwrap()
        .unwrap();
        let digest = Sha256::digest(b"validated-request").to_vec();
        let first_pool = pool.clone();
        let second_pool = pool.clone();
        let first_bearer = execution.to_string();
        let second_bearer = execution.to_string();
        let first_digest = digest.clone();
        let second_digest = digest.clone();
        let first = tokio::spawn(async move {
            crate::db::begin_admin_command_execution(
                &first_pool,
                &first_bearer,
                admin,
                owner,
                0,
                REGISTERED_LIST,
                &first_digest,
            )
            .await
            .unwrap()
        });
        let second = tokio::spawn(async move {
            crate::db::begin_admin_command_execution(
                &second_pool,
                &second_bearer,
                admin,
                owner,
                0,
                REGISTERED_LIST,
                &second_digest,
            )
            .await
            .unwrap()
        });
        let outcomes = [first.await.unwrap(), second.await.unwrap()];
        let mut claim = None;
        let mut busy = 0;
        for outcome in outcomes {
            match outcome {
                crate::db::AdminCommandExecutionState::Started(started) => claim = Some(started),
                crate::db::AdminCommandExecutionState::Busy => busy += 1,
                other => panic!("unexpected concurrent execution state: {other:?}"),
            }
        }
        let claim = claim.expect("one concurrent claimant must win");
        assert_eq!(busy, 1);
        // A semantic validation failure releases only its own incarnation and
        // leaves the XEP-0050 session reusable.
        assert!(crate::db::release_admin_command_execution(
            &pool,
            claim.token.as_str(),
            admin,
            username,
            0,
            REGISTERED_LIST,
            &digest,
        )
        .await
        .unwrap());
        let claim = match crate::db::begin_admin_command_execution(
            &pool,
            execution.as_str(),
            admin,
            owner,
            0,
            REGISTERED_LIST,
            &digest,
        )
        .await
        .unwrap()
        {
            crate::db::AdminCommandExecutionState::Started(claim) => claim,
            other => panic!("unexpected execution state: {other:?}"),
        };
        let payload = "<x xmlns='jabber:x:data' type='result'/>";
        assert!(crate::db::complete_admin_command_read_execution(
            &pool,
            claim.token.as_str(),
            admin,
            username,
            0,
            REGISTERED_LIST,
            &digest,
            payload,
        )
        .await
        .unwrap());
        assert_eq!(
            crate::db::begin_admin_command_execution(
                &pool,
                execution.as_str(),
                admin,
                owner,
                0,
                REGISTERED_LIST,
                &digest,
            )
            .await
            .unwrap(),
            crate::db::AdminCommandExecutionState::Completed(payload.to_owned())
        );
        let different_digest = Sha256::digest(b"different-request").to_vec();
        assert_eq!(
            crate::db::begin_admin_command_execution(
                &pool,
                execution.as_str(),
                admin,
                owner,
                0,
                REGISTERED_LIST,
                &different_digest,
            )
            .await
            .unwrap(),
            crate::db::AdminCommandExecutionState::Invalid
        );

        let member = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',FALSE)",
        )
        .bind(member)
        .bind(format!("member-{}", &member.simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();
        db::replace_admins(&pool, admin, &[admin, member])
            .await
            .unwrap();
        assert!(
            db::find_user_by_id(&pool, member)
                .await
                .unwrap()
                .unwrap()
                .is_admin
        );

        db::set_admin_service_message(&pool, admin, 0, "welcome", Some("Welcome"))
            .await
            .unwrap();
        db::set_admin_service_message(&pool, admin, 0, "motd", Some("Daily"))
            .await
            .unwrap();
        let first_pool = pool.clone();
        let second_pool = pool.clone();
        let first = tokio::spawn(async move {
            db::claim_admin_service_messages(&first_pool, member)
                .await
                .unwrap()
        });
        let second = tokio::spawn(async move {
            db::claim_admin_service_messages(&second_pool, member)
                .await
                .unwrap()
        });
        let mut claims = first.await.unwrap();
        claims.extend(second.await.unwrap());
        let mut claimed = claims
            .iter()
            .map(|claim| (claim.kind.clone(), claim.body.clone()))
            .collect::<Vec<_>>();
        claimed.sort();
        assert_eq!(
            claimed,
            vec![
                ("motd".to_owned(), "Daily".to_owned()),
                ("welcome".to_owned(), "Welcome".to_owned())
            ]
        );
        assert!(db::claim_admin_service_messages(&pool, member)
            .await
            .unwrap()
            .is_empty());
        let motd_claim = claims.iter().find(|claim| claim.kind == "motd").unwrap();
        sqlx::query(
            "UPDATE admin_service_message_deliveries
             SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE claim_id=$1",
        )
        .bind(motd_claim.claim_id)
        .execute(&pool)
        .await
        .unwrap();
        let reclaimed = db::claim_admin_service_messages(&pool, member)
            .await
            .unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(reclaimed[0].kind, "motd");
        assert!(
            db::complete_admin_service_message_claim(&pool, member, &reclaimed[0])
                .await
                .unwrap()
        );
        let welcome_claim = claims.iter().find(|claim| claim.kind == "welcome").unwrap();
        assert!(
            db::complete_admin_service_message_claim(&pool, member, welcome_claim)
                .await
                .unwrap()
        );
        db::set_admin_service_message(&pool, admin, 0, "welcome", None)
            .await
            .unwrap();
        db::set_admin_service_message(&pool, admin, 0, "welcome", Some("New welcome"))
            .await
            .unwrap();
        assert!(db::claim_admin_service_messages(&pool, member)
            .await
            .unwrap()
            .is_empty());
        db::set_admin_service_message(&pool, admin, 0, "motd", Some("Corrected"))
            .await
            .unwrap();
        let corrected = db::claim_admin_service_messages(&pool, member)
            .await
            .unwrap()
            .into_iter()
            .map(|claim| (claim.kind, claim.body))
            .collect::<Vec<_>>();
        assert_eq!(corrected, vec![("motd".to_owned(), "Corrected".to_owned())]);

        db::initialize_admin_runtime_settings(&pool, false, false, false)
            .await
            .unwrap();
        assert_eq!(
            db::admin_runtime_settings(&pool).await.unwrap(),
            (false, false)
        );
        assert!(
            db::set_admin_runtime_setting(&pool, admin, 0, "registration_closed", true,)
                .await
                .unwrap()
        );
        let observer_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        assert_eq!(
            db::admin_runtime_settings(&observer_pool).await.unwrap(),
            (false, true)
        );

        let mut entities = vec![
            "blocked.example".to_owned(),
            "alice@remote.example".to_owned(),
            "bob@remote.example/Phone".to_owned(),
        ];
        entities.sort();
        assert!(
            db::replace_federation_runtime_rules(&pool, admin, 0, "blacklist", &entities,)
                .await
                .unwrap()
        );
        assert_eq!(
            db::federation_runtime_rules(&observer_pool)
                .await
                .unwrap()
                .0,
            entities
        );

        let scheduled =
            db::schedule_admin_service_control(&pool, admin, 0, "restart", 5, Some("Maintenance"))
                .await
                .unwrap()
                .unwrap();
        assert!(
            db::schedule_admin_service_control(&observer_pool, admin, 0, "shutdown", 5, None,)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db::cancel_admin_service_control(&observer_pool, admin, 0)
                .await
                .unwrap(),
            Some(scheduled.generation)
        );
        let scheduled =
            db::schedule_admin_service_control(&observer_pool, admin, 0, "shutdown", 5, None)
                .await
                .unwrap()
                .unwrap();
        sqlx::query(
            "UPDATE admin_service_control SET execute_at=clock_timestamp()-INTERVAL '1 second'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let fired = db::poll_admin_service_control(&pool)
            .await
            .unwrap()
            .unwrap();
        let observed = db::poll_admin_service_control(&observer_pool)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fired.generation, scheduled.generation);
        assert_eq!(observed.generation, scheduled.generation);
        assert_eq!(fired.fired_at, observed.fired_at);
        assert!(
            db::schedule_admin_service_control(&pool, admin, 0, "restart", 5, None,)
                .await
                .unwrap()
                .is_none()
        );
        assert!(db::cancel_admin_service_control(&pool, admin, 0)
            .await
            .unwrap()
            .is_none());

        let before = db::find_user_by_id(&pool, member)
            .await
            .unwrap()
            .unwrap()
            .auth_generation;
        assert!(db::end_user_sessions(&pool, admin, member).await.unwrap());
        assert_eq!(
            db::find_user_by_id(&pool, member)
                .await
                .unwrap()
                .unwrap()
                .auth_generation,
            before + 1
        );
    }
}
