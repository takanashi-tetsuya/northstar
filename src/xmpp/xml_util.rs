use crate::abuse::WorkRequirement;
use crate::state::{attr_escape, bare_jid, jid_domain, xml_escape};
use roxmltree::{Document, Node};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn child_text<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
}

pub(crate) fn mam_field<'a, 'input>(query: Node<'a, 'input>, name: &str) -> Option<&'a str> {
    query
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.attribute("var") == Some(name)
        })
        .and_then(|node| child_text(node, "value"))
}

pub(crate) fn xdata_field<'a, 'input>(form: Node<'a, 'input>, name: &str) -> Option<&'a str> {
    form.children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some("jabber:x:data")
                && node.attribute("var") == Some(name)
        })
        .and_then(|node| child_text(node, "value"))
}

pub(crate) fn xdata_bool(form: Node<'_, '_>, name: &str) -> std::result::Result<Option<bool>, ()> {
    match xdata_field(form, name) {
        None => Ok(None),
        Some("1" | "true") => Ok(Some(true)),
        Some("0" | "false") => Ok(Some(false)),
        Some(_) => Err(()),
    }
}

pub(crate) fn bool_value(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

pub(crate) fn blocking_items(
    node: Node<'_, '_>,
    own_full_jid: Option<&str>,
) -> Option<Vec<String>> {
    let mut items = Vec::new();
    for item in node.children().filter(|child| child.is_element()) {
        if item.tag_name().name() != "item"
            || item.tag_name().namespace() != Some("urn:xmpp:blocking")
        {
            return None;
        }
        let jid = item.attribute("jid")?.trim().to_ascii_lowercase();
        if jid.is_empty()
            || jid.len() > 3071
            || jid.chars().any(char::is_whitespace)
            || own_full_jid.is_some_and(|own| bare_jid(own).eq_ignore_ascii_case(bare_jid(&jid)))
        {
            return None;
        }
        items.push(jid);
    }
    Some(items)
}

pub(crate) fn rsm_value<'a, 'input>(
    query: Node<'a, 'input>,
    name: &str,
) -> Option<Option<&'a str>> {
    query
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == name
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/rsm")
        })
        .map(|node| node.text().filter(|value| !value.is_empty()))
}

pub(crate) fn mam_form() -> &'static str {
    "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with' type='jid-single'/><field var='start' type='text-single'/><field var='end' type='text-single'/></x></query>"
}

pub(crate) fn should_carbon(root: Node<'_, '_>) -> bool {
    matches!(
        root.attribute("type").unwrap_or("normal"),
        "chat" | "normal"
    ) && !root.descendants().any(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some("urn:xmpp:carbons:2")
            && matches!(node.tag_name().name(), "private" | "sent" | "received")
    })
}

pub(crate) fn carbon_message(kind: &str, from: &str, to: &str, forwarded: &str) -> String {
    format!(
        "<message xmlns='jabber:client' from='{}' to='{}' type='chat'><{} xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'>{}</forwarded></{}></message>",
        attr_escape(from),
        attr_escape(to),
        kind,
        forwarded,
        kind
    )
}

pub(crate) fn is_counted_stanza(stanza: &str) -> bool {
    let stanza = stanza.trim_start();
    stanza.starts_with("<iq") || stanza.starts_with("<message") || stanza.starts_with("<presence")
}

pub(crate) fn sm_failed(condition: &str) -> String {
    format!(
        "<failed xmlns='urn:xmpp:sm:3'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>",
        condition
    )
}

pub(crate) fn valid_resource(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value
            .chars()
            .any(|c| matches!(c, '<' | '>' | '&' | '/' | '\0'))
}

pub(crate) fn valid_muc_room(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.chars().any(|c| {
            c.is_whitespace() || matches!(c, '"' | '&' | '\'' | '/' | ':' | '<' | '>' | '@' | '\0')
        })
}

pub(crate) fn valid_muc_nick(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value
            .chars()
            .any(|c| matches!(c, '<' | '>' | '&' | '/' | '\0'))
}

pub(crate) fn valid_upload_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\'))
}

pub(crate) fn valid_content_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.is_ascii()
        && value.contains('/')
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

pub(crate) fn valid_push_jid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 3071
        && jid_domain(value).is_some()
        && !value
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '<' | '>' | '&'))
}

pub(crate) fn muc_occupant_key(room_jid: &str, nick: &str) -> String {
    format!(
        "{}/{}",
        room_jid.to_ascii_lowercase(),
        nick.to_ascii_lowercase()
    )
}

pub(crate) fn muc_presence_stanza(
    occupant: &crate::state::MucOccupant,
    to: &str,
    unavailable: bool,
    self_presence: bool,
    created: bool,
    id: Option<&str>,
    disclose_real_jid: bool,
) -> String {
    let kind = if unavailable {
        " type='unavailable'"
    } else {
        ""
    };
    let id_attr = match id {
        Some(i) => format!(" id='{}'", attr_escape(i)),
        None => "".to_string(),
    };
    let mut statuses = String::new();
    if self_presence && occupant.room_non_anonymous {
        statuses.push_str("<status code='100'/>");
    }
    if self_presence {
        statuses.push_str("<status code='110'/>");
    }
    if created {
        statuses.push_str("<status code='201'/>");
    }
    let jid = if disclose_real_jid {
        format!(" jid='{}'", attr_escape(&occupant.full_jid))
    } else {
        String::new()
    };
    let res = format!(
        "<presence xmlns='jabber:client' from='{}/{}' to='{}'{}{}>\
         <x xmlns='http://jabber.org/protocol/muc#user'>\
         <item affiliation='{}' role='{}'{}/>{}\
         </x>{}</presence>",
        attr_escape(&occupant.room_jid),
        attr_escape(&occupant.nick),
        attr_escape(to),
        id_attr,
        kind,
        attr_escape(&occupant.affiliation),
        if unavailable { "none" } else { &occupant.role },
        jid,
        statuses,
        if unavailable { "" } else { &occupant.payload }
    );
    tracing::debug!(room=%occupant.room_jid, to=%to, "MUC routing presence");
    res
}

pub(crate) fn muc_destroy_presence(
    occupant: &crate::state::MucOccupant,
    alternate: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut destroy = String::from("<destroy");
    if let Some(alternate) = alternate {
        destroy.push_str(&format!(" jid='{}'", attr_escape(alternate)));
    }
    destroy.push('>');
    if let Some(reason) = reason {
        destroy.push_str(&format!("<reason>{}</reason>", xml_escape(reason)));
    }
    destroy.push_str("</destroy>");
    format!(
        "<presence xmlns='jabber:client' from='{}/{}' to='{}' type='unavailable'><x xmlns='http://jabber.org/protocol/muc#user'><item affiliation='none' role='none'/>{}</x></presence>",
        attr_escape(&occupant.room_jid),
        attr_escape(&occupant.nick),
        attr_escape(&occupant.full_jid),
        destroy,
    )
}

pub(crate) fn add_delay(stanza: &str, created_at: chrono::DateTime<chrono::Utc>) -> String {
    let Some(closing) = stanza.rfind("</message>") else {
        return stanza.to_owned();
    };
    let mut delayed = stanza.to_owned();
    delayed.insert_str(
        closing,
        &format!(
            "<delay xmlns='urn:xmpp:delay' stamp='{}'/>",
            created_at.format("%Y-%m-%dT%H:%M:%SZ")
        ),
    );
    delayed
}

pub(crate) fn add_muc_sender(stanza: &str, sender_jid: &str) -> String {
    let Some(closing) = stanza.rfind("</message>") else {
        return stanza.to_owned();
    };
    let mut annotated = stanza.to_owned();
    annotated.insert_str(
        closing,
        &format!(
            "<x xmlns='urn:northstar:muc:sender:0' jid='{}'/>",
            attr_escape(bare_jid(sender_jid))
        ),
    );
    annotated
}

pub(crate) fn add_subscription(current: &str, direction: &str) -> String {
    match (current, direction) {
        ("none", "to") => "to",
        ("none", "from") => "from",
        ("to", "from") | ("from", "to") => "both",
        ("both", _) => "both",
        (value, _) => value,
    }
    .to_owned()
}

pub(crate) fn remove_subscription(current: &str, direction: &str) -> String {
    match (current, direction) {
        ("both", "to") => "from",
        ("both", "from") => "to",
        ("to", "to") | ("from", "from") => "none",
        (value, _) => value,
    }
    .to_owned()
}

pub(crate) fn stream_id() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

pub(crate) fn iq_result(id: &str, payload: &str) -> String {
    format!(
        "<iq xmlns='jabber:client' type='result' id='{}'>{}</iq>",
        attr_escape(id),
        payload
    )
}

pub(crate) fn iq_result_from(id: &str, from: &str, payload: &str) -> String {
    format!(
        "<iq xmlns='jabber:client' type='result' from='{}' id='{}'>{}</iq>",
        attr_escape(from),
        attr_escape(id),
        payload
    )
}

pub(crate) fn iq_error(id: &str, condition: &str) -> String {
    format!("<iq xmlns='jabber:client' type='error' id='{}'><error type='cancel'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>", attr_escape(id), condition)
}

pub(crate) fn iq_error_from(id: &str, from: &str, condition: &str) -> String {
    format!("<iq xmlns='jabber:client' type='error' from='{}' id='{}'><error type='cancel'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>", attr_escape(from), attr_escape(id), condition)
}

pub(crate) fn iq_abuse_error(id: &str, requirement: &WorkRequirement) -> String {
    format!(
        "<iq xmlns='jabber:client' type='error' id='{}'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><pow-required xmlns='urn:northstar:pow:1' step='{}' work-factor='{}' max-work-factor='{}' retry-after='{}' cooldown='{}' max-device-seconds='{}'/></error></iq>",
        attr_escape(id),
        requirement.step,
        requirement.work_factor,
        requirement.max_work_factor,
        requirement.hard_wait_seconds.max(requirement.retry_after_seconds),
        requirement.cooldown_seconds,
        requirement.approximate_max_device_seconds,
    )
}

pub(crate) fn failure(ns: &str, condition: &str) -> String {
    format!("<failure xmlns='{}'><{}/></failure>", ns, condition)
}

pub(crate) fn stream_error(condition: &str) -> String {
    format!(
        "<stream:error><{} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>",
        condition
    )
}

pub(crate) fn stanza_error(root: Node<'_, '_>, error_type: &str, condition: &str) -> String {
    format!("<{} xmlns='jabber:client' type='error' id='{}'><error type='{}'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></{}>", root.tag_name().name(), attr_escape(root.attribute("id").unwrap_or_default()), error_type, condition, root.tag_name().name())
}

pub(crate) fn blocked_stanza_error(root: Node<'_, '_>) -> String {
    format!("<{} xmlns='jabber:client' type='error' id='{}'><error type='cancel'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><blocked xmlns='urn:xmpp:blocking:errors'/></error></{}>", root.tag_name().name(), attr_escape(root.attribute("id").unwrap_or_default()), root.tag_name().name())
}

pub(crate) fn abuse_stanza_error(root: Node<'_, '_>, requirement: &WorkRequirement) -> String {
    format!(
        "<{} xmlns='jabber:client' type='error' id='{}'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><pow-required xmlns='urn:northstar:pow:1' step='{}' work-factor='{}' max-work-factor='{}' retry-after='{}' cooldown='{}' max-device-seconds='{}'/></error></{}>",
        root.tag_name().name(),
        attr_escape(root.attribute("id").unwrap_or_default()),
        requirement.step,
        requirement.work_factor,
        requirement.max_work_factor,
        requirement.hard_wait_seconds.max(requirement.retry_after_seconds),
        requirement.cooldown_seconds,
        requirement.approximate_max_device_seconds,
        root.tag_name().name(),
    )
}

pub(crate) fn strip_pow_element(raw: &str) -> String {
    let Ok(document) = Document::parse(raw) else {
        return raw.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "pow"
                && node.tag_name().namespace() == Some("urn:northstar:pow:1")
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    if ranges.is_empty() {
        return raw.to_owned();
    }
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut cleaned = raw.to_owned();
    for range in ranges {
        cleaned.replace_range(range, "");
    }
    cleaned
}

pub(crate) fn is_abuse_rated_message(root: Node<'_, '_>) -> bool {
    is_encrypted(root)
        || root.children().any(|node| {
            node.is_element()
                && matches!(node.tag_name().name(), "body" | "subject")
                && matches!(node.tag_name().namespace(), None | Some("jabber:client"))
        })
}

pub(crate) fn is_encrypted(root: Node<'_, '_>) -> bool {
    root.descendants().any(|node| is_encryption_node(node))
}

pub(crate) fn is_encryption_node(node: Node<'_, '_>) -> bool {
    node.is_element()
        && matches!(
            node.tag_name().namespace(),
            Some("eu.siacs.conversations.axolotl" | "urn:xmpp:omemo:2")
        )
}

pub(crate) fn set_from(raw: &str, from: &str) -> String {
    let Some(end) = raw.find('>') else {
        return raw.to_owned();
    };
    let head = &raw[..end];
    let cleaned = if let Some(start) = head.find(" from='") {
        let after = start + 7;
        head[after..]
            .find('\'')
            .map(|finish| format!("{}{}", &head[..start], &head[after + finish + 1..]))
            .unwrap_or_else(|| head.to_owned())
    } else if let Some(start) = head.find(" from=\"") {
        let after = start + 7;
        head[after..]
            .find('"')
            .map(|finish| format!("{}{}", &head[..start], &head[after + finish + 1..]))
            .unwrap_or_else(|| head.to_owned())
    } else {
        head.to_owned()
    };
    let namespace = if cleaned.contains(" xmlns=") {
        ""
    } else {
        " xmlns='jabber:client'"
    };
    if let Some(prefix) = cleaned.strip_suffix('/') {
        format!(
            "{}{} from='{}'/>{}",
            prefix,
            namespace,
            attr_escape(from),
            &raw[end + 1..]
        )
    } else {
        format!(
            "{}{} from='{}'>{}",
            cleaned,
            namespace,
            attr_escape(from),
            &raw[end + 1..]
        )
    }
}

pub(crate) fn set_to(raw: &str, to: &str) -> String {
    let Some(end) = raw.find('>') else {
        return raw.to_owned();
    };
    let head = &raw[..end];
    let cleaned = if let Some(start) = head.find(" to='") {
        let after = start + 5;
        head[after..]
            .find('\'')
            .map(|finish| format!("{}{}", &head[..start], &head[after + finish + 1..]))
            .unwrap_or_else(|| head.to_owned())
    } else if let Some(start) = head.find(" to=\"") {
        let after = start + 5;
        head[after..]
            .find('"')
            .map(|finish| format!("{}{}", &head[..start], &head[after + finish + 1..]))
            .unwrap_or_else(|| head.to_owned())
    } else {
        head.to_owned()
    };
    if let Some(prefix) = cleaned.strip_suffix('/') {
        format!("{} to='{}'/>{}", prefix, attr_escape(to), &raw[end + 1..])
    } else {
        format!("{} to='{}'>{}", cleaned, attr_escape(to), &raw[end + 1..])
    }
}

pub(crate) fn encrypted_archive_stanza(stanza: &str) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let mut ranges: Vec<_> = document
        .root_element()
        .children()
        .filter(|node| node.is_element() && !is_encryption_node(*node))
        .map(|node| node.range())
        .collect();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut safe = stanza.to_owned();
    for range in ranges {
        safe.replace_range(range, "");
    }
    if let Some(closing) = safe.rfind("</message>") {
        safe.insert_str(
            closing,
            "<body>This message is end-to-end encrypted.</body>",
        );
    }
    safe
}

pub(crate) fn has_no_store_hint(root: Node<'_, '_>) -> bool {
    root.children().any(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some("urn:xmpp:hints")
            && matches!(node.tag_name().name(), "no-store" | "no-permanent-store")
    })
}
