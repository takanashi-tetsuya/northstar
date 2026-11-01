use anyhow::Result;
use northstar_operations_application::admin_commands::{
    AccountCommandAction, AccountCommandTarget, AccountMutationOutcome, AdminActor,
    AdminCommandRepository, AdminCommandRetryable, AdminCommandService, AdminScramPolicy,
    AdminWriteOutcome, CommandExecutionOutcome, CommandSessionOutcome, CreateAccountOutcome,
    ExecutionReleaseOutcome,
};
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};

mod execution;
mod forms;

use self::execution::{execute_count_command, execute_form_command, local_account_jid};
#[cfg(test)]
use self::forms::field;
use self::forms::{
    command_error, command_result, form_type_field, iq_result_from, parse_submission, request_form,
    result_field,
};

/// What a client session provides to the administrative command handlers.
pub trait CommandSession: Sync {
    /// The command service, over the repository the composition root binds.
    fn command_service(&self) -> &AdminCommandService<impl AdminCommandRepository>;
    /// The account the session authenticated as. Every command rechecks it against the database.
    fn command_cached_admin(&self) -> Option<AdminActor>;
    /// The session's bound full JID, or `None` before resource binding.
    fn command_full_jid(&self) -> Option<&str>;
    /// The server's local domain.
    fn command_local_domain(&self) -> &str;
    /// The verifier policy of accounts the commands create or update.
    fn command_scram_policy(&self) -> AdminScramPolicy;
    /// Whether the restart and shutdown commands are configured and can take effect.
    fn command_service_control_available(&self) -> bool;
    /// Sends `stanza` to the eligible local sessions and returns the delivered account identities.
    fn command_send_local_announcement(&self, stanza: &str) -> BTreeSet<String>;
    /// Whether announcements also reach accounts through the durable offline path.
    fn command_remote_announcement_enabled(&self) -> bool;
    /// Replaces this node's cached federation rules after a committed edit.
    fn command_replace_federation_rules(&self, blacklist: Vec<String>, whitelist: Vec<String>);
    /// Sends `stanza` to `bare` on the other nodes, returning whether any session took it.
    fn command_send_remote_announcement(
        &self,
        bare: &str,
        stanza: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    /// The bare JIDs online anywhere in the cluster.
    fn command_online_bare_jids(
        &self,
    ) -> impl std::future::Future<Output = Result<BTreeSet<String>>> + Send;
    /// The active and the idle bare JIDs of the cluster.
    fn command_activity_bare_jids(
        &self,
    ) -> impl std::future::Future<Output = Result<(BTreeSet<String>, BTreeSet<String>)>> + Send;
}

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

pub fn is_command(node: &str) -> bool {
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

fn command_enabled(session: &impl CommandSession, node: &str) -> bool {
    !matches!(node, RESTART | SHUTDOWN) || (session.command_service_control_available())
}

async fn current_admin(session: &impl CommandSession) -> Result<Option<AdminActor>> {
    let Some(cached) = session.command_cached_admin() else {
        return Ok(None);
    };
    session.command_service().current_admin(&cached).await
}

pub async fn available_to(session: &impl CommandSession) -> Result<bool> {
    Ok(current_admin(session).await?.is_some())
}

pub async fn disco_info(
    session: &impl CommandSession,
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

pub async fn disco_items(
    session: &impl CommandSession,
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

pub async fn handle(
    session: &impl CommandSession,
    id: &str,
    root: Node<'_, '_>,
    command: Node<'_, '_>,
) -> Result<String> {
    let responder = session.command_local_domain();
    let node = command.attribute("node").unwrap_or_default();
    let Some(actor) = current_admin(session).await? else {
        return Ok(command_error(
            id,
            responder,
            node,
            "forbidden",
            "auth",
            None,
        ));
    };
    if session.command_full_jid().is_none() {
        return Ok(command_error(
            id,
            responder,
            node,
            "forbidden",
            "cancel",
            None,
        ));
    }
    if root.attribute("to").is_some_and(|to| {
        !northstar_xmpp_types::jid::CanonicalJid::parse_bare(to)
            .is_ok_and(|target| target.localpart().is_none() && target.domainpart() == responder)
    }) {
        return Ok(command_error(
            id,
            responder,
            node,
            "item-not-found",
            "cancel",
            None,
        ));
    }
    if !is_command(node) || !command_enabled(session, node) {
        return Ok(command_error(
            id,
            responder,
            node,
            "item-not-found",
            "cancel",
            None,
        ));
    }
    // XEP-0050 requires recipients to ignore a requester-supplied `status`.
    if command.attributes().any(|attribute| {
        attribute.namespace().is_none()
            && !matches!(attribute.name(), "node" | "action" | "sessionid" | "status")
    }) {
        return Ok(command_error(
            id,
            responder,
            node,
            "bad-request",
            "modify",
            Some("bad-payload"),
        ));
    }

    let action = command.attribute("action").unwrap_or("execute");
    if !matches!(action, "execute" | "cancel" | "prev" | "next" | "complete") {
        return Ok(command_error(
            id,
            responder,
            node,
            "bad-request",
            "modify",
            Some("malformed-action"),
        ));
    }
    let owner = session.command_full_jid().unwrap_or_default();
    let session_id = command.attribute("sessionid");

    if action == "cancel" {
        let Some(session_id) = session_id else {
            return Ok(command_error(
                id,
                responder,
                node,
                "bad-request",
                "modify",
                Some("bad-sessionid"),
            ));
        };
        if !valid_command_bearer(session_id) {
            return Ok(command_error(
                id,
                responder,
                node,
                "bad-request",
                "modify",
                Some("bad-sessionid"),
            ));
        }
        let state = session
            .command_service()
            .finish_session(session_id, &actor, owner, node, "canceled")
            .await?;
        return Ok(match state {
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
        });
    }

    match session_id {
        None => {
            if action != "execute" {
                return Ok(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-action"),
                ));
            }
            if command.children().any(|child| child.is_element()) {
                return Ok(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-payload"),
                ));
            }
            if !is_count_command(node) {
                let Some(session_id) = session
                    .command_service()
                    .create_session(&actor, owner, session.command_local_domain(), node, "form")
                    .await?
                else {
                    return Ok(command_error(
                        id,
                        responder,
                        node,
                        "resource-constraint",
                        "wait",
                        None,
                    ));
                };
                Ok(command_result(
                    id,
                    responder,
                    node,
                    session_id.as_str(),
                    "executing",
                    &request_form(session, &actor, node).await?,
                ))
            } else {
                let Some(session_id) = session
                    .command_service()
                    .create_session(
                        &actor,
                        owner,
                        session.command_local_domain(),
                        node,
                        "executing",
                    )
                    .await?
                else {
                    return Ok(command_error(
                        id,
                        responder,
                        node,
                        "resource-constraint",
                        "wait",
                        None,
                    ));
                };
                let payload = execute_count_command(session, &actor, node).await?;
                let finished = session
                    .command_service()
                    .complete_count_session(session_id.as_str(), &actor, owner, node, &payload)
                    .await?;
                if finished != CommandSessionOutcome::Finished {
                    return Ok(command_error(
                        id,
                        responder,
                        node,
                        "forbidden",
                        "auth",
                        None,
                    ));
                }
                Ok(command_result(
                    id,
                    responder,
                    node,
                    session_id.as_str(),
                    "completed",
                    &payload,
                ))
            }
        }
        Some(session_id) => {
            if !valid_command_bearer(session_id) {
                return Ok(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-sessionid"),
                ));
            }
            if is_count_command(node) || !matches!(action, "execute" | "complete") {
                return Ok(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-action"),
                ));
            }
            let submission = match parse_submission(command, node) {
                Ok(value) => value,
                Err(()) => {
                    return Ok(command_error(
                        id,
                        responder,
                        node,
                        "bad-request",
                        "modify",
                        Some("bad-payload"),
                    ));
                }
            };
            let target_digest = command_target_digest(node, &submission);
            let claim = match session
                .command_service()
                .begin_execution(session_id, &actor, owner, node, &target_digest)
                .await?
            {
                CommandExecutionOutcome::Started(claim) => claim,
                CommandExecutionOutcome::Completed(payload) => {
                    return Ok(command_result(
                        id,
                        responder,
                        node,
                        session_id,
                        "completed",
                        &payload,
                    ));
                }
                CommandExecutionOutcome::Busy => {
                    return Ok(command_error(
                        id,
                        responder,
                        node,
                        "resource-constraint",
                        "wait",
                        None,
                    ));
                }
                CommandExecutionOutcome::Expired => {
                    return Ok(command_error(
                        id,
                        responder,
                        node,
                        "not-allowed",
                        "cancel",
                        Some("session-expired"),
                    ));
                }
                CommandExecutionOutcome::Invalid => {
                    return Ok(command_error(
                        id,
                        responder,
                        node,
                        "bad-request",
                        "modify",
                        Some("bad-sessionid"),
                    ));
                }
            };
            let command_execution =
                execute_form_command(session, &actor, &claim, node, submission).await;
            if command_execution
                .as_ref()
                .is_err_and(northstar_security::password_work::is_overloaded)
            {
                if session
                    .command_service()
                    .release_execution(&actor, &claim, node)
                    .await?
                    != ExecutionReleaseOutcome::Released
                {
                    return Ok(command_error(
                        id, responder, node, "conflict", "cancel", None,
                    ));
                }
                return Ok(command_error(
                    id,
                    responder,
                    node,
                    "resource-constraint",
                    "wait",
                    None,
                ));
            }
            if command_execution
                .as_ref()
                .is_err_and(|error| error.downcast_ref::<AdminCommandRetryable>().is_some())
            {
                let _ = session
                    .command_service()
                    .release_execution(&actor, &claim, node)
                    .await?;
                return Ok(command_error(
                    id,
                    responder,
                    node,
                    "resource-constraint",
                    "wait",
                    None,
                ));
            }
            let Some(payload) = command_execution? else {
                if session
                    .command_service()
                    .release_execution(&actor, &claim, node)
                    .await?
                    != ExecutionReleaseOutcome::Released
                {
                    return Ok(command_error(
                        id, responder, node, "conflict", "cancel", None,
                    ));
                }
                return Ok(command_error(
                    id,
                    responder,
                    node,
                    "bad-request",
                    "modify",
                    Some("bad-payload"),
                ));
            };
            if is_read_form_command(node)
                && session
                    .command_service()
                    .complete_read_execution(&actor, &claim, node, &payload)
                    .await?
                    != AdminWriteOutcome::Applied
            {
                return Ok(command_error(
                    id,
                    responder,
                    node,
                    "forbidden",
                    "auth",
                    None,
                ));
            }
            Ok(command_result(
                id,
                responder,
                node,
                session_id,
                "completed",
                &payload,
            ))
        }
    }
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

#[cfg(test)]
mod tests;
