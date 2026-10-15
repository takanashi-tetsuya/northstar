//! Construct administrative forms, validate submissions, and render command IQ results and errors.

use super::*;

pub(super) fn form_type_field() -> XmlElement {
    XmlElement::new("field")
        .attr("var", "FORM_TYPE")
        .attr("type", "hidden")
        .child(XmlElement::new("value").text(ADMIN_FORM_TYPE))
}

pub(super) fn result_field(variable: &str, value: impl Into<String>) -> XmlElement {
    XmlElement::new("field")
        .attr("var", variable)
        .child(XmlElement::new("value").text(value))
}

pub(super) async fn request_form(
    session: &ProtocolSession,
    actor: &AdminActor,
    node: &str,
) -> Result<String> {
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
                .map(|username| local_account_jid(username, session.state.local_domain()))
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
                session.state.local_domain(),
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

pub(super) fn field(
    var: &str,
    kind: &str,
    label: &str,
    required: bool,
    values: &[String],
) -> XmlElement {
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

pub(super) fn command_form_fragment(form: XmlElement) -> String {
    XmlElement::new("northstar-fragment")
        .child(
            XmlElement::new("actions")
                .attr("execute", "complete")
                .child(XmlElement::new("complete")),
        )
        .child(form)
        .finish_children()
}

pub(super) fn list_request_form(node: &str) -> String {
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

pub(super) fn expected_fields(node: &str) -> &'static [&'static str] {
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

pub(super) fn parse_submission(
    command: Node<'_, '_>,
    node: &str,
) -> std::result::Result<Submission, ()> {
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

pub(super) fn command_result(
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

pub(super) fn iq_result_from(id: &str, from: &str, payload: XmlElement) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "result")
        .attr("from", from)
        .attr("id", id)
        .child(payload)
        .finish()
}

pub(super) fn command_error(
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
