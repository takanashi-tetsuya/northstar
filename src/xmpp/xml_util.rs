use crate::abuse::WorkRequirement;
use crate::state::{attr_escape, bare_jid};
use crate::xmpp::xml_builder::{ValidatedXmlFragment, XmlElement};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use roxmltree::{Document, Node};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Unicode bidi embeddings, overrides, isolates and their terminators can
/// reorder neighbouring UI text without being visible themselves. They are
/// not needed to store ordinary RTL scripts (Arabic/Hebrew characters remain
/// valid), so profile fields reject these formatting controls at ingress.
pub(crate) fn contains_unsafe_bidi_controls(value: &str) -> bool {
    value
        .chars()
        .any(|character| matches!(character as u32, 0x202a..=0x202e | 0x2066..=0x2069))
}

pub(crate) fn xml_subtree_contains_unsafe_bidi_controls(node: Node<'_, '_>) -> bool {
    node.descendants().any(|descendant| {
        descendant.text().is_some_and(contains_unsafe_bidi_controls)
            || descendant
                .attributes()
                .any(|attribute| contains_unsafe_bidi_controls(attribute.value()))
    })
}

pub(crate) fn child_text<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<&'a str> {
    let parent_namespace = node.tag_name().namespace();
    node.children()
        .find(|n| {
            n.is_element()
                && n.tag_name().name() == name
                && (n.tag_name().namespace() == parent_namespace
                    // TCP stanzas are parsed without their surrounding
                    // `jabber:client` stream declaration. Treat a redundant
                    // explicit declaration as the inherited core namespace,
                    // while never confusing an extension with a core field.
                    || (parent_namespace.is_none()
                        && n.tag_name().namespace() == Some("jabber:client")))
        })
        .and_then(|n| n.text())
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

pub(crate) fn xdata_value_field(
    variable: &'static str,
    kind: &'static str,
    value: impl ToString,
) -> XmlElement {
    XmlElement::new("field")
        .attr("var", variable)
        .attr("type", kind)
        .child(XmlElement::new("value").text(value.to_string()))
}

pub(crate) fn strict_xdata_submit(
    form: Node<'_, '_>,
    expected_form_type: &str,
    allowed_fields: &[&str],
) -> std::result::Result<HashMap<String, String>, ()> {
    if form.tag_name().name() != "x"
        || form.tag_name().namespace() != Some("jabber:x:data")
        || form.attribute("type") != Some("submit")
        || form
            .attributes()
            .any(|attribute| attribute.name() != "type")
        || form.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err(());
    }
    let mut values = HashMap::new();
    for field in form.children().filter(|child| child.is_element()) {
        if field.tag_name().name() != "field"
            || field.tag_name().namespace() != Some("jabber:x:data")
        {
            return Err(());
        }
        let variable = field.attribute("var").ok_or(())?;
        if variable.is_empty()
            || variable.len() > 256
            || field
                .attributes()
                .any(|attribute| !matches!(attribute.name(), "var" | "type" | "label"))
            || field.children().any(|child| {
                !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
            })
        {
            return Err(());
        }
        let children = field
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        if children.len() != 1
            || children[0].tag_name().name() != "value"
            || children[0].tag_name().namespace() != Some("jabber:x:data")
            || children[0].attributes().len() != 0
            || children[0].children().any(|child| child.is_element())
        {
            return Err(());
        }
        let value = children[0]
            .children()
            .filter_map(|child| child.text())
            .collect::<String>();
        if value.len() > 4_096 {
            return Err(());
        }
        // XEP-0004 ignores unknown fields; validate their shape and size first
        // so they remain subject to the same input limits.
        if variable != "FORM_TYPE" && !allowed_fields.contains(&variable) {
            continue;
        }
        if values.insert(variable.to_owned(), value).is_some() {
            return Err(());
        }
    }
    if values.get("FORM_TYPE").map(String::as_str) != Some(expected_form_type)
        || form
            .children()
            .find(|child| {
                child.is_element()
                    && child.tag_name().name() == "field"
                    && child.attribute("var") == Some("FORM_TYPE")
            })
            .and_then(|field| field.attribute("type"))
            != Some("hidden")
    {
        return Err(());
    }
    Ok(values)
}

pub(crate) fn bool_value(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

/// Validate the RFC 5646/BCP 47 well-formed syntax used by `xml:lang`.
/// Registry membership is intentionally not required: private-use and future
/// registered subtags remain valid, while malformed/duplicate extensions and
/// variants are rejected.
pub(crate) fn valid_language_tag(value: &str) -> bool {
    crate::xmpp::stanza_validation::valid_language_tag(value)
}

pub(crate) fn mam_extended_form() -> &'static str {
    static FORM: LazyLock<String> = LazyLock::new(|| {
        let mut form = XmlElement::namespaced("x", "jabber:x:data").attr("type", "form");
        form.push_child(xdata_value_field("FORM_TYPE", "hidden", "urn:xmpp:mam:2"));
        for (variable, kind) in [
            ("with", "jid-single"),
            ("start", "text-single"),
            ("end", "text-single"),
            ("before-id", "text-single"),
            ("after-id", "text-single"),
        ] {
            form.push_child(
                XmlElement::new("field")
                    .attr("var", variable)
                    .attr("type", kind),
            );
        }
        form.push_child(
            XmlElement::new("field")
                .attr("var", "ids")
                .attr("type", "list-multi")
                .child(
                    XmlElement::namespaced("validate", "http://jabber.org/protocol/xdata-validate")
                        .attr("datatype", "xs:string")
                        .child(XmlElement::new("open")),
                ),
        );
        XmlElement::namespaced("query", "urn:xmpp:mam:2")
            .child(form)
            .finish()
    });
    FORM.as_str()
}

/// Reject a client-provided Carbon wrapper.  A server must be the only entity
/// that can assert `<sent/>` or `<received/>`; forwarding such a wrapper would
/// recreate the impersonation class behind CVE-2017-5589 and can also create
/// Carbon loops between resources.
pub(crate) fn validate_no_client_carbon(root: Node<'_, '_>) -> Result<(), &'static str> {
    if root.descendants().any(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some("urn:xmpp:carbons:2")
            && matches!(node.tag_name().name(), "sent" | "received")
    }) {
        return Err("not-allowed");
    }
    Ok(())
}

/// Apply the complete, transport-independent validation boundary for a
/// routed message. Keeping this ordering in one place prevents C2S, S2S,
/// federated MUC and federated MIX from accepting different archive/copy
/// controls merely because they entered through different transports.
pub(crate) fn validate_routed_message(
    root: Node<'_, '_>,
    extensions: &crate::xmpp::extensions::ExtensionRuntime,
) -> Result<(), &'static str> {
    validate_enabled_message_extensions(root, extensions)?;
    validate_delivery_receipts(root)?;
    validate_modern_message_payloads(root)?;
    validate_no_client_carbon(root)
}

/// Fail closed before interpreting an optional message extension. A disabled
/// XEP is absent from service discovery and every transport-facing route; an
/// endpoint cannot bypass that decision by sending the namespace over S2S,
/// federated MUC or federated MIX instead of C2S.
fn validate_enabled_message_extensions(
    root: Node<'_, '_>,
    extensions: &crate::xmpp::extensions::ExtensionRuntime,
) -> Result<(), &'static str> {
    for (id, namespace) in [
        (northstar_xep_0085::XEP_ID, northstar_xep_0085::NAMESPACE),
        (northstar_xep_0184::XEP_ID, northstar_xep_0184::NAMESPACE),
        (northstar_xep_0308::XEP_ID, northstar_xep_0308::NAMESPACE),
        (northstar_xep_0333::XEP_ID, northstar_xep_0333::NAMESPACE),
        (northstar_xep_0359::XEP_ID, northstar_xep_0359::NAMESPACE),
        (northstar_xep_0380::XEP_ID, northstar_xep_0380::NAMESPACE),
        (northstar_xep_0444::XEP_ID, northstar_xep_0444::NAMESPACE),
        (northstar_xep_0461::XEP_ID, northstar_xep_0461::NAMESPACE),
    ] {
        if !extensions.enabled(id)
            && root
                .children()
                .any(|node| node.is_element() && node.tag_name().namespace() == Some(namespace))
        {
            return Err("feature-not-implemented");
        }
    }
    Ok(())
}

pub(crate) fn should_carbon(root: Node<'_, '_>) -> bool {
    northstar_xep_0280::should_copy(root)
}

pub(crate) fn carbon_message(kind: &str, from: &str, to: &str, forwarded: &str) -> Option<String> {
    // The XEP-0280 wrapper name is protocol state, never caller-controlled
    // XML. Keep the legacy string-shaped API temporarily, but collapse it to
    // the only two legal element names before it reaches the serializer. This
    // makes an accidental future call with an untrusted value non-injectable.
    let direction = if kind == "sent" {
        northstar_xep_0280::Direction::Sent
    } else if kind == "received" {
        northstar_xep_0280::Direction::Received
    } else {
        return None;
    };
    // A stanza received on a TCP stream is allowed to inherit
    // `jabber:client` from the stream root, so its standalone serialization
    // does not necessarily contain an xmlns attribute. Once that stanza is
    // nested below XEP-0297 <forwarded/>, however, it would inherit
    // `urn:xmpp:forward:0` and stop being a client <message/>. Standards
    // clients (including Gajim) correctly ignore such a malformed Carbon.
    // Make the namespace boundary explicit before embedding the stanza; the
    // same conversion also turns an S2S `jabber:server` root into the C2S
    // namespace expected by the receiving resource.
    let forwarded = set_client_namespace(forwarded);
    northstar_xep_0280::build_carbon(direction, from, to, &forwarded).ok()
}

pub(crate) fn is_counted_stanza(stanza: &str) -> bool {
    let stanza = stanza.trim_start();
    stanza.starts_with("<iq") || stanza.starts_with("<message") || stanza.starts_with("<presence")
}

pub(crate) fn sm_failed(condition: &str) -> String {
    northstar_xep_0198::build_failed_str(condition)
}

pub(crate) fn valid_muc_room(value: &str) -> bool {
    northstar_xep_0045::is_valid_room_name(value)
}

pub(crate) fn valid_muc_nick(value: &str) -> bool {
    northstar_xep_0045::is_valid_occupant_nick(value)
}

/// MUC occupants use the room JID resourcepart as their nickname. RFC 7622
/// therefore requires the case-preserving PRECIS OpaqueString profile; a
/// nickname must never pass through UsernameCaseMapped or ASCII lowercase.
pub(crate) fn prepare_muc_nick(value: &str) -> anyhow::Result<String> {
    northstar_xep_0045::OccupantNick::parse(value)
        .map(|nick| nick.to_string())
        .map_err(anyhow::Error::from)
}

/// Validate and prepare an RFC 7622 bare JID.
pub(crate) fn valid_bare_jid(value: &str) -> bool {
    crate::jid::CanonicalJid::parse_bare(value).is_ok()
}

pub(crate) fn muc_occupant_key(room_jid: &str, nick: &str) -> String {
    northstar_xep_0045::occupant_key(room_jid, nick).unwrap_or_else(|_| {
        let room_jid =
            crate::jid::canonicalize_bare(room_jid).unwrap_or_else(|_| room_jid.to_owned());
        let nick = prepare_muc_nick(nick).unwrap_or_else(|_| nick.to_owned());
        format!("{room_jid}/{nick}")
    })
}

pub(crate) fn muc_presence_stanza(
    occupant: &crate::state::SerializableMucOccupant,
    to: &str,
    unavailable: bool,
    self_presence: bool,
    created: bool,
    id: Option<&str>,
    disclose_real_jid: bool,
) -> String {
    muc_presence_stanza_with_status(
        occupant,
        to,
        unavailable,
        self_presence,
        created,
        id,
        disclose_real_jid,
        None,
        None,
        None,
    )
}

pub(crate) fn muc_nickname_change_presence(
    occupant: &crate::state::SerializableMucOccupant,
    recipient: &crate::state::SerializableMucOccupant,
    new_nick: &str,
    id: Option<&str>,
) -> String {
    let self_presence = occupant.full_jid == recipient.full_jid;
    let disclose_real_jid =
        occupant.room_non_anonymous || self_presence || recipient.role == "moderator";
    let item = XmlElement::new("item")
        .attr("affiliation", &occupant.affiliation)
        .attr("role", &occupant.role)
        .attr("nick", new_nick)
        .optional_attr(
            "jid",
            disclose_real_jid.then_some(occupant.full_jid.as_str()),
        );
    let mut muc_user = XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
        .child(item)
        .child(XmlElement::new("status").attr("code", 303));
    if self_presence {
        muc_user.push_child(XmlElement::new("status").attr("code", 110));
    }
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", format!("{}/{}", occupant.room_jid, occupant.nick))
        .attr("to", &recipient.full_jid)
        .attr("type", "unavailable")
        .optional_attr("id", id)
        .child(muc_user)
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &occupant.occupant_id),
        )
        .finish()
}

pub(crate) fn add_muc_user_status(stanza: &str, code: u16) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let Some(extension) = document.root_element().children().find(|node| {
        node.is_element()
            && node.tag_name().name() == "x"
            && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
    }) else {
        return stanza.to_owned();
    };
    let status = if extension.default_namespace() == Some("http://jabber.org/protocol/muc#user") {
        XmlElement::new("status")
    } else {
        // A prefixed MUC extension does not establish a default namespace for
        // an unprefixed child inserted into it.
        XmlElement::namespaced("status", "http://jabber.org/protocol/muc#user")
    }
    .attr("code", code);
    append_element_child(stanza, extension.range(), &status).unwrap_or_else(|| stanza.to_owned())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn muc_presence_stanza_with_status(
    occupant: &crate::state::SerializableMucOccupant,
    to: &str,
    unavailable: bool,
    self_presence: bool,
    created: bool,
    id: Option<&str>,
    disclose_real_jid: bool,
    removal_status: Option<u16>,
    actor_nick: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut muc_user = XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user");
    let mut item = XmlElement::new("item")
        .attr("affiliation", &occupant.affiliation)
        .attr("role", if unavailable { "none" } else { &occupant.role })
        .optional_attr(
            "jid",
            disclose_real_jid.then_some(occupant.full_jid.as_str()),
        );
    if let Some(actor_nick) = actor_nick {
        item.push_child(XmlElement::new("actor").attr("nick", actor_nick));
    }
    if let Some(reason) = reason {
        item.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    muc_user.push_child(item);
    if self_presence && occupant.room_non_anonymous {
        muc_user.push_child(XmlElement::new("status").attr("code", 100));
    }
    if self_presence {
        muc_user.push_child(XmlElement::new("status").attr("code", 110));
    }
    if created {
        muc_user.push_child(XmlElement::new("status").attr("code", 201));
    }
    if let Some(code) = removal_status {
        muc_user.push_child(XmlElement::new("status").attr("code", code));
    }
    let mut presence = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", format!("{}/{}", occupant.room_jid, occupant.nick))
        .attr("to", to)
        .optional_attr("id", id)
        .optional_attr("type", unavailable.then_some("unavailable"))
        .child(muc_user)
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &occupant.occupant_id),
        );
    if !unavailable && !occupant.payload.is_empty() {
        if let Err(error) = presence.push_validated_fragment(&occupant.payload) {
            tracing::warn!(
                ?error,
                room = %occupant.room_jid,
                "discarded invalid stored MUC presence payload"
            );
        }
    }
    let res = presence.finish();
    tracing::debug!(room=%occupant.room_jid, to=%to, "MUC routing presence");
    res
}

pub(crate) fn muc_destroy_presence(
    occupant: &crate::state::SerializableMucOccupant,
    alternate: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut destroy = XmlElement::new("destroy").optional_attr("jid", alternate);
    if let Some(reason) = reason {
        destroy.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    let muc_user = XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
        .child(
            XmlElement::new("item")
                .attr("affiliation", "none")
                .attr("role", "none"),
        )
        .child(destroy);
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", format!("{}/{}", occupant.room_jid, occupant.nick))
        .attr("to", &occupant.full_jid)
        .attr("type", "unavailable")
        .child(muc_user)
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &occupant.occupant_id),
        )
        .finish()
}

/// XEP-0421 pseudonym scoped to one room. HMAC-SHA-256 provides a stable,
/// non-guessable value without correlating the same account across rooms.
pub(crate) fn muc_occupant_id(room_secret: &[u8], user_bare_jid: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(room_secret)
        .expect("HMAC accepts XEP-0421 room secrets of any length");
    let user_bare_jid = crate::jid::canonical_bare_key(user_bare_jid)
        .unwrap_or_else(|_| bare_jid(user_bare_jid).to_owned());
    mac.update(user_bare_jid.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Replace any client-supplied occupant-id with the authoritative room value.
pub(crate) fn set_muc_occupant_id(stanza: &str, occupant_id: &str) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "occupant-id"
                && node.tag_name().namespace() == Some("urn:xmpp:occupant-id:0")
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut authoritative = stanza.to_owned();
    for range in ranges {
        authoritative.replace_range(range, "");
    }
    append_root_element(
        &authoritative,
        &XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0").attr("id", occupant_id),
    )
    .unwrap_or(authoritative)
}

pub(crate) fn muc_stanza_error(
    root: Node<'_, '_>,
    recipient: &str,
    error_type: &str,
    condition: &str,
) -> String {
    let from = root.attribute("to").unwrap_or_default();
    let stanza_name = match root.tag_name().name() {
        "iq" => "iq",
        "message" => "message",
        "presence" => "presence",
        _ => "message",
    };
    let mut reply = XmlElement::new(stanza_name)
        .attr("xmlns", "jabber:client")
        .attr("from", from)
        .attr("to", recipient)
        .attr("type", "error")
        .attr("id", root.attribute("id").unwrap_or_default());
    if stanza_name == "presence" {
        reply.push_child(XmlElement::namespaced(
            "x",
            "http://jabber.org/protocol/muc",
        ));
    }
    reply
        .child(
            XmlElement::new("error")
                .attr("by", bare_jid(from))
                .attr("type", error_type)
                .child(stanza_condition_element(condition)),
        )
        .finish()
}

pub(crate) fn add_delay_from(
    stanza: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    from: Option<&str>,
) -> String {
    let mut delayed = stanza.to_owned();
    if let Ok(document) = Document::parse(stanza) {
        let mut ranges = document
            .root_element()
            .children()
            .filter(|child| {
                child.is_element()
                    && child.tag_name().name() == "delay"
                    && child.tag_name().namespace() == Some("urn:xmpp:delay")
            })
            .map(|child| child.range())
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
        for range in ranges {
            delayed.replace_range(range, "");
        }
    }
    let delay = XmlElement::namespaced("delay", "urn:xmpp:delay")
        .optional_attr("from", from)
        .attr("stamp", created_at.format("%Y-%m-%dT%H:%M:%SZ"));
    append_root_element(&delayed, &delay).unwrap_or_else(|| stanza.to_owned())
}

/// Remove direct XEP-0203 assertions that the current transport cannot
/// authenticate. Nested delays inside a `<forwarded/>` payload are opaque
/// extension data and are intentionally left alone. A C2S client has no
/// authority to assert a server delay, while an S2S peer may assert one only
/// from the exact domain authenticated on that stream.
pub(crate) fn strip_untrusted_direct_delays(stanza: &str, trusted_domain: Option<&str>) -> String {
    let trusted_domain =
        trusted_domain.and_then(|domain| crate::jid::prepare_domainpart(domain).ok());
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let direct_delays = document
        .root_element()
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "delay"
                && child.tag_name().namespace() == Some("urn:xmpp:delay")
        })
        .collect::<Vec<_>>();
    if direct_delays.is_empty() {
        return stanza.to_owned();
    }
    // XEP-0203 requires one and only one direct delay marker. Preserve that
    // marker only when the authenticated S2S hop can vouch for its source and
    // the timestamp uses XEP-0082's UTC (`Z`) profile. Natural-language reason
    // text is permitted by XEP-0203 and remains bounded here.
    let keep_single = direct_delays.len() == 1
        && direct_delays[0].attributes().all(|attribute| {
            attribute.namespace().is_none() && matches!(attribute.name(), "from" | "stamp")
        })
        && direct_delays[0].attribute("stamp").is_some_and(|stamp| {
            stamp.len() <= 64
                && stamp.ends_with('Z')
                && chrono::DateTime::parse_from_rfc3339(stamp)
                    .is_ok_and(|stamp| stamp.offset().local_minus_utc() == 0)
        })
        && !direct_delays[0].children().any(|node| node.is_element())
        && direct_delays[0]
            .text()
            .is_none_or(|text| text.len() <= 4_096)
        && trusted_domain.as_ref().is_some_and(|trusted| {
            direct_delays[0]
                .attribute("from")
                .map(|from| {
                    crate::jid::CanonicalJid::parse(from)
                        .is_ok_and(|from| from.domainpart() == trusted)
                })
                // `from` is only RECOMMENDED, not required. The authenticated
                // S2S domain is still authoritative for an omitted source.
                .unwrap_or(true)
        });
    if keep_single {
        return stanza.to_owned();
    }
    let mut ranges = direct_delays
        .into_iter()
        .map(|child| child.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut sanitized = stanza.to_owned();
    for range in ranges {
        sanitized.replace_range(range, "");
    }
    sanitized
}

pub(crate) fn add_muc_sender(stanza: &str, sender_jid: &str) -> String {
    append_root_element(
        stanza,
        &XmlElement::namespaced("x", "urn:northstar:muc:sender:0")
            .attr("jid", bare_jid(sender_jid)),
    )
    .unwrap_or_else(|| stanza.to_owned())
}

/// Produce the message payload embedded in a MUC MAM result. XEP-0313
/// requires no `to`, requires the occupant JID in `from`, and forbids trusting
/// a pre-existing MUC user extension. Real JIDs are added only when room
/// anonymity policy permits the querying user to see them.
pub(crate) fn mam_muc_stanza(stanza: &str, sender_jid: &str, reveal_real_jid: bool) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && matches!(
                    node.tag_name().namespace(),
                    Some("http://jabber.org/protocol/muc#user" | "urn:northstar:muc:sender:0")
                )
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut result = stanza.to_owned();
    for range in ranges {
        result.replace_range(range, "");
    }
    result = remove_root_attribute(&result, "to");
    if reveal_real_jid {
        let extension = XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
            .child(XmlElement::new("item").attr("jid", sender_jid));
        result = append_root_element(&result, &extension).unwrap_or(result);
    }
    result
}

fn remove_root_attribute(raw: &str, name: &str) -> String {
    if Document::parse(raw).is_err() {
        return raw.to_owned();
    }
    let Some(opening) = parse_root_opening(raw) else {
        return raw.to_owned();
    };
    let mut rewritten = raw.to_owned();
    let mut removals = opening
        .attributes
        .iter()
        .filter(|attribute| attribute.name == name)
        .map(|attribute| attribute.removal_start..attribute.end)
        .collect::<Vec<_>>();
    removals.sort_by_key(|range| std::cmp::Reverse(range.start));
    for range in removals {
        rewritten.replace_range(range, "");
    }
    rewritten
}

pub(crate) fn stream_id() -> u128 {
    // RFC 6120 requires every stream identifier to be unique, including the
    // new stream opened after STARTTLS. Wall-clock timestamps can repeat when
    // connections open within one clock tick or the system clock is adjusted;
    // a CSPRNG-backed UUID avoids both failure modes.
    uuid::Uuid::new_v4().as_u128()
}

pub(crate) fn iq_result(id: &str, payload: &str) -> String {
    let result = XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "result")
        .attr("id", id);
    match result.validated_fragment(payload) {
        Ok(result) => result.finish(),
        Err(error) => {
            tracing::error!(?error, "refused to emit malformed IQ result payload");
            iq_error(id, "internal-server-error")
        }
    }
}

pub(crate) fn iq_result_from(id: &str, from: &str, payload: &str) -> String {
    let result = XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "result")
        .attr("from", from)
        .attr("id", id);
    match result.validated_fragment(payload) {
        Ok(result) => result.finish(),
        Err(error) => {
            tracing::error!(
                ?error,
                "refused to emit malformed addressed IQ result payload"
            );
            iq_error_from(id, from, "internal-server-error")
        }
    }
}

pub(crate) fn iq_result_to(id: &str, from: &str, to: &str, payload: &str) -> String {
    let mut result = XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "result")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id);
    if result.push_validated_fragment(payload).is_err() {
        return iq_error_to(id, from, to, "wait", "internal-server-error");
    }
    result.finish()
}

pub(crate) fn iq_error(id: &str, condition: &str) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("type", stanza_error_type(condition))
                .child(stanza_condition_element(condition)),
        )
        .finish()
}

pub(crate) fn iq_error_from(id: &str, from: &str, condition: &str) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("type", stanza_error_type(condition))
                .child(stanza_condition_element(condition)),
        )
        .finish()
}

pub(crate) fn iq_error_to(
    id: &str,
    from: &str,
    to: &str,
    error_type: &str,
    condition: &str,
) -> String {
    let condition = XmlElement::dynamic(condition)
        .unwrap_or_else(|_| XmlElement::new("undefined-condition"))
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("type", error_type)
                .child(condition),
        )
        .finish()
}

fn stanza_condition_name(condition: &str) -> &'static str {
    match condition {
        "bad-request" => "bad-request",
        "conflict" => "conflict",
        "feature-not-implemented" => "feature-not-implemented",
        "forbidden" => "forbidden",
        "gone" => "gone",
        "internal-server-error" => "internal-server-error",
        "item-not-found" => "item-not-found",
        "jid-malformed" => "jid-malformed",
        "not-acceptable" => "not-acceptable",
        "not-allowed" => "not-allowed",
        "not-authorized" => "not-authorized",
        "policy-violation" => "policy-violation",
        "recipient-unavailable" => "recipient-unavailable",
        "redirect" => "redirect",
        "registration-required" => "registration-required",
        "remote-server-not-found" => "remote-server-not-found",
        "remote-server-timeout" => "remote-server-timeout",
        "resource-constraint" => "resource-constraint",
        "service-unavailable" => "service-unavailable",
        "subscription-required" => "subscription-required",
        "unexpected-request" => "unexpected-request",
        _ => "undefined-condition",
    }
}

fn stanza_condition_element(condition: &str) -> XmlElement {
    XmlElement::new(stanza_condition_name(condition))
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas")
}

pub(crate) fn stanza_error_type(condition: &str) -> &'static str {
    match condition {
        "forbidden" | "not-authorized" | "registration-required" | "subscription-required" => {
            "auth"
        }
        "bad-request" | "jid-malformed" | "not-acceptable" | "policy-violation" | "redirect" => {
            "modify"
        }
        "internal-server-error"
        | "recipient-unavailable"
        | "remote-server-timeout"
        | "resource-constraint"
        | "unexpected-request" => "wait",
        _ => "cancel",
    }
}

pub(crate) fn failure(ns: &str, condition: &str) -> String {
    XmlElement::new("failure")
        .attr("xmlns", ns)
        .child(XmlElement::new(sasl_failure_condition_name(condition)))
        .finish()
}

pub(crate) fn stream_error(condition: &str) -> String {
    XmlElement::new("stream:error")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .child(
            XmlElement::new(stream_error_condition_name(condition))
                .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-streams"),
        )
        .finish()
}

pub(crate) fn stanza_error(root: Node<'_, '_>, error_type: &str, condition: &str) -> String {
    let error = XmlElement::namespaced("error", "jabber:client")
        .attr("type", error_type)
        .child(stanza_condition_element(condition))
        .finish();
    reflected_stanza_error(root, &error)
}

fn sasl_failure_condition_name(condition: &str) -> &'static str {
    match condition {
        "aborted" => "aborted",
        "account-disabled" => "account-disabled",
        "credentials-expired" => "credentials-expired",
        "encryption-required" => "encryption-required",
        "incorrect-encoding" => "incorrect-encoding",
        "invalid-authzid" => "invalid-authzid",
        "invalid-mechanism" => "invalid-mechanism",
        "malformed-request" => "malformed-request",
        "mechanism-too-weak" => "mechanism-too-weak",
        "not-authorized" => "not-authorized",
        "temporary-auth-failure" => "temporary-auth-failure",
        _ => "temporary-auth-failure",
    }
}

fn stream_error_condition_name(condition: &str) -> &'static str {
    match condition {
        "bad-format" => "bad-format",
        "bad-namespace-prefix" => "bad-namespace-prefix",
        "conflict" => "conflict",
        "connection-timeout" => "connection-timeout",
        "host-gone" => "host-gone",
        "host-unknown" => "host-unknown",
        "improper-addressing" => "improper-addressing",
        "internal-server-error" => "internal-server-error",
        "invalid-from" => "invalid-from",
        "invalid-namespace" => "invalid-namespace",
        "invalid-xml" => "invalid-xml",
        "not-authorized" => "not-authorized",
        "not-well-formed" => "not-well-formed",
        "policy-violation" => "policy-violation",
        "remote-connection-failed" => "remote-connection-failed",
        "reset" => "reset",
        "resource-constraint" => "resource-constraint",
        "restricted-xml" => "restricted-xml",
        "see-other-host" => "see-other-host",
        "system-shutdown" => "system-shutdown",
        "unsupported-encoding" => "unsupported-encoding",
        "unsupported-feature" => "unsupported-feature",
        "unsupported-stanza-type" => "unsupported-stanza-type",
        "unsupported-version" => "unsupported-version",
        _ => "undefined-condition",
    }
}

pub(crate) fn blocked_stanza_error(root: Node<'_, '_>) -> String {
    let error = XmlElement::namespaced("error", "jabber:client")
        .attr("type", "cancel")
        .child(stanza_condition_element("not-acceptable"))
        .child(XmlElement::namespaced(
            "blocked",
            "urn:xmpp:blocking:errors",
        ))
        .finish();
    reflected_stanza_error(root, &error)
}

pub(crate) fn abuse_stanza_error(root: Node<'_, '_>, requirement: &WorkRequirement) -> String {
    let error = XmlElement::namespaced("error", "jabber:client")
        .attr("type", "wait")
        .child(stanza_condition_element("resource-constraint"))
        .child(
            XmlElement::namespaced("pow-required", "urn:northstar:pow:1")
                .attr("step", requirement.step)
                .attr("work-factor", requirement.work_factor)
                .attr("max-work-factor", requirement.max_work_factor)
                .attr(
                    "retry-after",
                    requirement
                        .hard_wait_seconds
                        .max(requirement.retry_after_seconds),
                )
                .attr("cooldown", requirement.cooldown_seconds)
                .attr(
                    "max-device-seconds",
                    requirement.approximate_max_device_seconds,
                ),
        )
        .finish();
    reflected_stanza_error(root, &error)
}

pub(crate) fn reflected_stanza_error(root: Node<'_, '_>, error: &str) -> String {
    let document = root.document();
    let input = document.input_text();
    let range = root.range();
    let Some(raw) = input.get(range.clone()) else {
        return String::new();
    };
    let original_from = root.attribute("from").map(str::to_owned);
    let original_to = root.attribute("to").map(str::to_owned);
    let mut reflected = raw.to_owned();
    let mut old_errors = root
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "error"
                && child.tag_name().namespace() == root.tag_name().namespace()
        })
        .map(|child| {
            let child = child.range();
            child.start - range.start..child.end - range.start
        })
        .collect::<Vec<_>>();
    old_errors.sort_by_key(|child| std::cmp::Reverse(child.start));
    for old_error in old_errors {
        reflected.replace_range(old_error, "");
    }
    // XEP-0077 explicitly discourages reflecting password-change payloads in
    // errors. Apply the same defensive rule to data-form secrets (including
    // invitation tokens and administrator password forms) so the generic RFC
    // error reflector cannot echo credentials into client/UI diagnostic logs.
    let mut sensitive = root
        .descendants()
        .filter_map(|node| {
            if !node.is_element() {
                return None;
            }
            let replacement = if node.tag_name().name() == "password"
                && node.tag_name().namespace() == Some("jabber:iq:register")
            {
                Some(XmlElement::namespaced("password", "jabber:iq:register").finish())
            } else if node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some("jabber:x:data")
                && node.attribute("var").is_some_and(|variable| {
                    matches!(
                        variable,
                        "password"
                            | "password-verify"
                            | "old_password"
                            | "urn:northstar:invite:token"
                    )
                })
            {
                Some(
                    XmlElement::namespaced("field", "jabber:x:data")
                        .attr("var", node.attribute("var").unwrap_or_default())
                        .finish(),
                )
            } else {
                None
            }?;
            let child = node.range();
            Some((
                child.start - range.start..child.end - range.start,
                replacement,
            ))
        })
        .collect::<Vec<_>>();
    sensitive.sort_by_key(|(child, _)| std::cmp::Reverse(child.start));
    for (child, replacement) in sensitive {
        reflected.replace_range(child, &replacement);
    }
    reflected = remove_root_attribute(&reflected, "type");
    reflected = remove_root_attribute(&reflected, "from");
    reflected = remove_root_attribute(&reflected, "to");
    reflected = set_root_attribute(&reflected, "type", "error");
    if let Some(from) = original_to {
        reflected = set_root_attribute(&reflected, "from", &from);
    }
    if let Some(to) = original_from {
        reflected = set_root_attribute(&reflected, "to", &to);
    }
    append_root_validated_fragment(&reflected, error).unwrap_or(reflected)
}

/// Turn a handler-generated IQ error into the RFC 6120 reflected form. This
/// preserves the original request payload and swaps its addressing while
/// retaining any standard or application-specific error extensions.
pub(crate) fn reflect_iq_error_response(request: Node<'_, '_>, response: &str) -> Option<String> {
    let document = Document::parse(response).ok()?;
    let response_root = document.root_element();
    if response_root.tag_name().name() != "iq" || response_root.attribute("type") != Some("error") {
        return None;
    }
    let error = response_root.children().find(|child| {
        child.is_element()
            && child.tag_name().name() == "error"
            && child.tag_name().namespace() == response_root.tag_name().namespace()
    })?;
    let error = document.input_text().get(error.range())?;
    let mut reflected = reflected_stanza_error(request, error);
    // A handler can be the authoritative service entity for an implicitly
    // addressed IQ (Carbons controls are answered by the account bare JID,
    // for example). Preserve those explicit server-selected addresses while
    // still reflecting the request payload and error extension. Responses
    // without explicit addressing retain the ordinary RFC swap above.
    if let Some(from) = response_root.attribute("from") {
        reflected = remove_root_attribute(&reflected, "from");
        reflected = set_root_attribute(&reflected, "from", from);
    }
    if let Some(to) = response_root.attribute("to") {
        reflected = remove_root_attribute(&reflected, "to");
        reflected = set_root_attribute(&reflected, "to", to);
    }
    Some(reflected)
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

pub(crate) fn add_stanza_id(stanza: &str, by: &str, id: uuid::Uuid) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let Ok(canonical_by) = crate::jid::CanonicalJid::parse(by) else {
        return stanza.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "stanza-id"
                && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
                && northstar_xep_0359::parse_stanza_id(*node)
                    .is_ok_and(|existing| existing.by == canonical_by)
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut annotated = stanza.to_owned();
    for range in ranges {
        annotated.replace_range(range, "");
    }
    let Ok(extension) = northstar_xep_0359::build_stanza_id(&id.to_string(), &canonical_by) else {
        return annotated;
    };
    append_root_validated_fragment(&annotated, &extension).unwrap_or(annotated)
}

/// Remove every XEP-0359 authority assertion for a domain controlled by this
/// server. A client or remote peer must not be able to avoid deduplication by
/// adding a second, forged local-account issuer next to the server's ID.
/// Foreign-domain IDs are preserved as forwarded provenance.
pub(crate) fn strip_stanza_ids_by_domain(stanza: &str, domain: &str) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let Ok(domain) = crate::jid::prepare_domainpart(domain) else {
        return stanza.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "stanza-id"
                && node.tag_name().namespace() == Some(northstar_xep_0359::NAMESPACE)
                && northstar_xep_0359::parse_stanza_id(*node)
                    .is_ok_and(|stanza_id| stanza_id.by.domainpart() == domain)
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut cleaned = stanza.to_owned();
    for range in ranges {
        cleaned.replace_range(range, "");
    }
    cleaned
}

pub(crate) fn is_abuse_rated_message(root: Node<'_, '_>) -> bool {
    is_encrypted(root)
        || root.children().any(|node| {
            node.is_element()
                && ((matches!(node.tag_name().name(), "body" | "subject")
                    && matches!(node.tag_name().namespace(), None | Some("jabber:client")))
                    || matches!(
                        (node.tag_name().namespace(), node.tag_name().name()),
                        (Some("urn:xmpp:reactions:0"), "reactions")
                            | (Some("urn:xmpp:sfs:0"), "file-sharing")
                            | (Some("urn:xmpp:chat-markers:0"), "markable" | "displayed")
                            | (Some("http://jabber.org/protocol/chatstates"), _)
                            | (Some("urn:xmpp:message-retract:1"), "retract")
                            | (Some("urn:xmpp:message-correct:0"), "replace")
                            | (Some("urn:xmpp:reply:0"), "reply")
                            | (Some("urn:xmpp:eme:0"), "encryption")
                            | (Some("urn:xmpp:stickers:0"), "sticker")
                            | (Some("urn:xmpp:tm:1"), "trust-message")
                            | (Some("urn:xmpp:jingle-message:0"), _)
                    ))
        })
}

/// Validate XEP-0184 wire invariants without generating a receipt on behalf of
/// a client. A receipt is an end-to-end client assertion; the server only
/// validates and routes it.
pub(crate) fn validate_delivery_receipts(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0184::parse_message(root)
        .map(|_| ())
        .map_err(|_| "bad-request")
}

/// Validate message-extension wire shapes before routing and archiving.
/// Rendering and decryption belong to the client.
pub(crate) fn validate_modern_message_payloads(root: Node<'_, '_>) -> Result<(), &'static str> {
    validate_processing_hints(root)?;
    validate_private_carbon_marker(root)?;
    validate_stanza_ids(root)?;
    crate::xmpp::protocol::jingle::validate_jmi_message(root)?;
    validate_chat_states(root)?;
    validate_omemo2_envelope(root)?;
    validate_explicit_encryption(root)?;
    validate_fallbacks(root)?;
    validate_correction(root)?;
    validate_displayed_marker(root)?;
    validate_no_client_tombstone(root)?;
    validate_reactions(root)?;
    validate_reply(root)?;
    validate_file_sharing(root)?;
    validate_sticker(root)?;
    validate_trust_message(root)?;
    Ok(())
}

/// Validate the server-visible XEP-0449 v0.2.0 marker. Sticker media is
/// carried by XEP-0447, while sticker-pack payloads remain ordinary bounded
/// PubSub items. Encrypted markers are intentionally opaque to the server.
fn validate_sticker(root: Node<'_, '_>) -> Result<(), &'static str> {
    const STICKERS: &str = "urn:xmpp:stickers:0";
    let stickers = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "sticker"
                && node.tag_name().namespace() == Some(STICKERS)
        })
        .collect::<Vec<_>>();
    if stickers.is_empty() {
        return Ok(());
    }
    if stickers.len() != 1 {
        return Err("bad-request");
    }

    let sticker = stickers[0];
    if sticker.children().any(|child| child.is_element())
        || has_non_whitespace_text(sticker)
        || sticker.attributes().any(|attribute| {
            attribute.namespace().is_some() || !matches!(attribute.name(), "pack" | "jid" | "node")
        })
    {
        return Err("bad-request");
    }

    let pack = sticker.attribute("pack");
    let jid = sticker.attribute("jid");
    let node = sticker.attribute("node");
    for value in [pack, node].into_iter().flatten() {
        if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err("bad-request");
        }
    }
    if jid.is_some() != node.is_some() || (jid.is_some() && pack.is_none()) {
        return Err("bad-request");
    }
    if jid.is_some_and(|value| crate::jid::CanonicalJid::parse_bare(value).is_err()) {
        return Err("jid-malformed");
    }

    // Section 4.1 defines the marker as metadata for a stateless file share,
    // not as a free-standing chat signal. A single share keeps the association
    // unambiguous and mirrors the one-file wire shape in the specification.
    let shares = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "file-sharing"
                && node.tag_name().namespace() == Some("urn:xmpp:sfs:0")
        })
        .count();
    if shares != 1 {
        return Err("bad-request");
    }
    Ok(())
}

/// Validate a plaintext, server-visible XEP-0434 v0.6.0 trust message. A
/// trust message encrypted through XEP-0420/OMEMO is ciphertext at this
/// boundary and deliberately remains opaque. Signature verification and the
/// XEP-0450 policy decision belong to endpoints, not the routing server.
fn validate_trust_message(root: Node<'_, '_>) -> Result<(), &'static str> {
    const TRUST_MESSAGES: &str = "urn:xmpp:tm:1";
    const MAX_TRUST_OWNERS: usize = 1_024;
    const MAX_TRUST_ENTRIES_PER_OWNER: usize = 1_024;
    const MAX_TRUST_ENTRIES: usize = 8_192;
    const MAX_KEY_IDENTIFIER_BYTES: usize = 64 * 1024;

    let messages = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "trust-message"
                && node.tag_name().namespace() == Some(TRUST_MESSAGES)
        })
        .collect::<Vec<_>>();
    if messages.is_empty() {
        return Ok(());
    }
    if messages.len() != 1 {
        return Err("bad-request");
    }
    let message = messages[0];
    if message.range().len() > 2 * 1024 * 1024 {
        return Err("resource-constraint");
    }
    if has_non_whitespace_text(message)
        || message.attributes().any(|attribute| {
            attribute.namespace().is_some() || !matches!(attribute.name(), "usage" | "encryption")
        })
    {
        return Err("bad-request");
    }
    for required in ["usage", "encryption"] {
        let value = message.attribute(required).ok_or("bad-request")?;
        if value.is_empty()
            || value.len() > 1_024
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err("bad-request");
        }
    }

    let owners = message
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if owners.is_empty() {
        return Err("bad-request");
    }
    if owners.len() > MAX_TRUST_OWNERS {
        return Err("resource-constraint");
    }
    let mut owner_jids = HashSet::new();
    let mut total_entries = 0usize;
    for owner in owners {
        if owner.tag_name().name() != "key-owner"
            || owner.tag_name().namespace() != Some(TRUST_MESSAGES)
            || has_non_whitespace_text(owner)
            || owner
                .attributes()
                .any(|attribute| attribute.namespace().is_some() || attribute.name() != "jid")
        {
            return Err("bad-request");
        }
        let owner_jid = owner
            .attribute("jid")
            .ok_or("bad-request")
            .and_then(|value| {
                crate::jid::CanonicalJid::parse_bare(value).map_err(|_| "jid-malformed")
            })?;
        if !owner_jids.insert(owner_jid.to_string()) {
            return Err("bad-request");
        }

        let actions = owner
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        if actions.is_empty() {
            return Err("bad-request");
        }
        if actions.len() > MAX_TRUST_ENTRIES_PER_OWNER {
            return Err("resource-constraint");
        }
        total_entries = total_entries
            .checked_add(actions.len())
            .ok_or("resource-constraint")?;
        if total_entries > MAX_TRUST_ENTRIES {
            return Err("resource-constraint");
        }

        let mut key_identifiers = HashSet::new();
        for action in actions {
            if action.tag_name().namespace() != Some(TRUST_MESSAGES)
                || !matches!(action.tag_name().name(), "trust" | "distrust")
                || action.attributes().len() != 0
                || action.children().any(|node| node.is_element())
            {
                return Err("bad-request");
            }
            let encoded = action.text().unwrap_or_default();
            if encoded.len()
                > MAX_KEY_IDENTIFIER_BYTES
                    .saturating_mul(2)
                    .saturating_add(16)
            {
                return Err("resource-constraint");
            }
            if !valid_omemo_base64(encoded, MAX_KEY_IDENTIFIER_BYTES) {
                return Err("bad-request");
            }
            let compact = encoded
                .chars()
                .filter(|character| !character.is_ascii_whitespace())
                .collect::<String>();
            if !key_identifiers.insert(compact) {
                return Err("bad-request");
            }
        }
    }
    Ok(())
}

const OMEMO2: &str = "urn:xmpp:omemo:2";
const SCE: &str = "urn:xmpp:sce:1";
const MAX_OMEMO2_ENCRYPTED_BYTES: usize = 2 * 1024 * 1024;
const MAX_OMEMO2_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_OMEMO2_KEY_BYTES: usize = 64 * 1024;
const MAX_OMEMO2_KEY_GROUPS: usize = 1024;
const MAX_OMEMO2_KEYS_PER_GROUP: usize = 1024;
const MAX_OMEMO2_TOTAL_KEYS: usize = 8192;

/// Validate the server-visible OMEMO 2 transport envelope without inspecting
/// or attempting to decrypt its SCE payload. This shared C2S/S2S boundary
/// keeps malformed recipient maps out of durable MAM/offline storage and
/// prevents a purported encrypted stanza from carrying a plaintext fallback.
fn validate_omemo2_envelope(root: Node<'_, '_>) -> Result<(), &'static str> {
    if root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "envelope"
            && node.tag_name().namespace() == Some(SCE)
    }) {
        // XEP-0420 forbids an unencrypted envelope as a direct stanza child.
        return Err("not-allowed");
    }

    let encrypted = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "encrypted"
                && node.tag_name().namespace() == Some(OMEMO2)
        })
        .collect::<Vec<_>>();
    if encrypted.is_empty() {
        return Ok(());
    }
    if encrypted.len() != 1 {
        return Err("bad-request");
    }
    let encrypted = encrypted[0];
    if encrypted.range().len() > MAX_OMEMO2_ENCRYPTED_BYTES {
        return Err("resource-constraint");
    }
    if encrypted.attributes().len() != 0 || has_non_whitespace_text(encrypted) {
        return Err("bad-request");
    }

    // OMEMO 2 uses SCE. A plaintext body/subject/thread, attachment or OOB URL
    // next to the ciphertext is a downgrade/leak, not a fallback.
    if root.children().any(|node| is_omemo2_plaintext_leak(&node)) {
        return Err("not-acceptable");
    }

    let children = encrypted
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if children.iter().any(|node| {
        node.tag_name().namespace() != Some(OMEMO2)
            || !matches!(node.tag_name().name(), "header" | "payload")
    }) {
        return Err("bad-request");
    }
    let headers = children
        .iter()
        .filter(|node| node.tag_name().name() == "header")
        .copied()
        .collect::<Vec<_>>();
    let payloads = children
        .iter()
        .filter(|node| node.tag_name().name() == "payload")
        .copied()
        .collect::<Vec<_>>();
    if headers.len() != 1
        || payloads.len() > 1
        || children.first().map(|node| node.tag_name().name()) != Some("header")
        || payloads
            .first()
            .is_some_and(|_| children.get(1).map(|node| node.tag_name().name()) != Some("payload"))
    {
        return Err("bad-request");
    }

    let header = headers[0];
    if header
        .attributes()
        .any(|attribute| attribute.namespace().is_some() || attribute.name() != "sid")
        || header
            .attribute("sid")
            .and_then(parse_omemo_positive_i31)
            .is_none()
        || has_non_whitespace_text(header)
    {
        return Err("bad-request");
    }

    let groups = header
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if groups.is_empty() || groups.len() > MAX_OMEMO2_KEY_GROUPS {
        return Err("resource-constraint");
    }
    let mut recipient_jids = HashSet::new();
    let mut total_keys = 0usize;
    for group in groups {
        if group.tag_name().name() != "keys"
            || group.tag_name().namespace() != Some(OMEMO2)
            || group
                .attributes()
                .any(|attribute| attribute.namespace().is_some() || attribute.name() != "jid")
            || has_non_whitespace_text(group)
        {
            return Err("bad-request");
        }
        let recipient = group
            .attribute("jid")
            .ok_or("bad-request")
            .and_then(|jid| {
                crate::jid::CanonicalJid::parse_bare(jid).map_err(|_| "jid-malformed")
            })?;
        if recipient.localpart().is_none() || !recipient_jids.insert(recipient.to_string()) {
            return Err("bad-request");
        }

        let keys = group
            .children()
            .filter(Node::is_element)
            .collect::<Vec<_>>();
        if keys.is_empty() || keys.len() > MAX_OMEMO2_KEYS_PER_GROUP {
            return Err("resource-constraint");
        }
        total_keys = total_keys
            .checked_add(keys.len())
            .ok_or("resource-constraint")?;
        if total_keys > MAX_OMEMO2_TOTAL_KEYS {
            return Err("resource-constraint");
        }
        let mut device_ids = HashSet::new();
        for key in keys {
            if key.tag_name().name() != "key"
                || key.tag_name().namespace() != Some(OMEMO2)
                || key.children().any(|node| node.is_element())
                || key.attributes().any(|attribute| {
                    attribute.namespace().is_some() || !matches!(attribute.name(), "rid" | "kex")
                })
            {
                return Err("bad-request");
            }
            let rid = key
                .attribute("rid")
                .and_then(parse_omemo_positive_i31)
                .ok_or("bad-request")?;
            if !device_ids.insert(rid)
                || key
                    .attribute("kex")
                    .is_some_and(|value| !matches!(value, "true" | "false" | "1" | "0"))
                || !valid_omemo_base64(key.text().unwrap_or_default(), MAX_OMEMO2_KEY_BYTES)
            {
                return Err("bad-request");
            }
        }
    }

    if let Some(payload) = payloads.first() {
        if payload.attributes().len() != 0
            || payload.children().any(|node| node.is_element())
            || !valid_omemo_base64(payload.text().unwrap_or_default(), MAX_OMEMO2_PAYLOAD_BYTES)
        {
            return Err("bad-request");
        }
        let store = root
            .children()
            .filter(|node| {
                node.is_element() && node.tag_name().namespace() == Some("urn:xmpp:hints")
            })
            .filter(|node| node.tag_name().name() == "store")
            .count();
        if store != 1 {
            // XEP-0420 requires this structural hint because an SCE payload
            // has no plaintext body. Other XEP-0334 hints are an independent
            // storage-policy decision: in particular, `no-store` may override
            // persistence while an already authenticated live route still
            // carries the ciphertext.
            return Err("not-acceptable");
        }
    }

    if root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "encryption"
            && node.tag_name().namespace() == Some("urn:xmpp:eme:0")
            && node.attribute("namespace") != Some(OMEMO2)
    }) {
        return Err("bad-request");
    }
    Ok(())
}

fn is_omemo2_plaintext_leak(node: &Node<'_, '_>) -> bool {
    if !node.is_element() {
        return false;
    }
    let namespace = node.tag_name().namespace().unwrap_or_default();
    let name = node.tag_name().name();
    (matches!(namespace, "" | "jabber:client") && matches!(name, "body" | "subject" | "thread"))
        || (namespace == "jabber:x:oob" && name == "x")
        || (namespace == "urn:xmpp:sfs:0" && name == "file-sharing")
        || (namespace == OMEMO2 && name == "opt-out")
}

fn has_non_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(Node::is_text)
        .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
}

fn parse_omemo_positive_i31(value: &str) -> Option<u32> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value <= i32::MAX as u32)
}

fn valid_omemo_base64(value: &str, max_decoded: usize) -> bool {
    if value.is_empty() || value.len() > max_decoded.saturating_mul(2).saturating_add(16) {
        return false;
    }
    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    !compact.is_empty()
        && BASE64
            .decode(compact)
            .is_ok_and(|decoded| !decoded.is_empty() && decoded.len() <= max_decoded)
}

fn validate_stanza_ids(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0359::parse_message(root)
        .map(|_| ())
        .map_err(|error| match error {
            northstar_xep_0359::SidError::InvalidIssuer(_) => "jid-malformed",
            _ => "bad-request",
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MessageStoragePolicy {
    pub(crate) temporary: bool,
    pub(crate) permanent: bool,
}

/// Preserve XEP-0334 hints when a service has to rebuild a routed message
/// (for example, when a MUC service rewrites an invitation). Callers validate
/// the original stanza before using this fragment.
pub(crate) fn processing_hints_fragment(root: Node<'_, '_>, raw: &str) -> String {
    root.children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some("urn:xmpp:hints"))
        .map(|node| {
            let range = node.range();
            &raw[range.start..range.end]
        })
        .collect()
}

/// Parse XEP-0334 processing hints as a bounded, privacy-preserving policy.
/// The server never treats extension-namespace lookalikes or payload-bearing
/// hints as policy. XEP-0334 defines these elements as hints and does not make
/// combinations a stanza error, so overlapping storage hints use a fixed
/// order independent of child order: `no-store`, `no-permanent-store`, then
/// `store`.
pub(crate) fn message_storage_policy(
    root: Node<'_, '_>,
) -> Result<MessageStoragePolicy, &'static str> {
    // XEP-0334 section 3 requires intermediaries to ignore processing hints
    // attached to error messages. Error stanzas are never eligible for
    // offline or permanent storage, so do not parse (or reject) hint-shaped
    // children on this branch.
    if root.attribute("type") == Some("error") {
        return Ok(MessageStoragePolicy {
            temporary: false,
            permanent: false,
        });
    }
    let mut store = false;
    let mut no_store = false;
    let mut no_permanent_store = false;
    let mut seen = HashSet::new();
    for hint in root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some("urn:xmpp:hints"))
    {
        let name = hint.tag_name().name();
        if !matches!(
            name,
            "store" | "no-store" | "no-permanent-store" | "no-copy"
        ) {
            // XEP-0334 explicitly permits future hints. Preserve them as
            // opaque data, but apply a small structural bound below.
            if hint.attributes().len() > 16
                || hint.descendants().filter(|node| node.is_element()).count() > 64
                || hint.range().len() > 65_536
            {
                return Err("resource-constraint");
            }
            continue;
        }
        if !seen.insert(name)
            || hint.attributes().len() != 0
            || hint.children().any(|child| child.is_element())
            || hint.text().is_some_and(|text| !text.trim().is_empty())
        {
            return Err("bad-request");
        }
        match name {
            "store" => store = true,
            "no-store" => no_store = true,
            "no-permanent-store" => no_permanent_store = true,
            // XEP-0334 says senders MUST only place this hint on messages to
            // full JIDs.  It also explicitly says the hint does not override
            // RFC 6121 bare-JID fan-out.  An intermediary therefore validates
            // the empty element but ignores its copy semantics unless `to`
            // is a valid full JID; rejecting the whole message would turn a
            // sender-side hint error into avoidable message loss.
            "no-copy" => {}
            _ => unreachable!(),
        }
    }
    if no_store {
        return Ok(MessageStoragePolicy {
            temporary: false,
            permanent: false,
        });
    }
    if no_permanent_store {
        return Ok(MessageStoragePolicy {
            temporary: true,
            permanent: false,
        });
    }
    if store {
        return Ok(MessageStoragePolicy {
            temporary: true,
            permanent: true,
        });
    }

    // Pure chat states and delivery receipts are transient by default.
    let mut found_signal = false;
    for node in root.children().filter(|node| node.is_element()) {
        let namespace = node.tag_name().namespace().unwrap_or_default();
        let name = node.tag_name().name();
        let is_signal = (namespace == "http://jabber.org/protocol/chatstates"
            && matches!(
                name,
                "active" | "composing" | "paused" | "inactive" | "gone"
            ))
            || (namespace == "urn:xmpp:receipts" && name == "received")
            || (namespace == "urn:xmpp:chat-markers:0" && matches!(name, "markable" | "displayed"));
        let is_signal_metadata = namespace == "urn:xmpp:hints"
            || (matches!(namespace, "" | "jabber:client") && name == "thread")
            || namespace == "urn:xmpp:sid:0"
            || (namespace == "urn:northstar:pow:1" && name == "pow");
        if is_signal || is_signal_metadata {
            found_signal |= is_signal;
            continue;
        }
        return Ok(MessageStoragePolicy {
            temporary: true,
            permanent: true,
        });
    }
    Ok(MessageStoragePolicy {
        temporary: !found_signal,
        permanent: !found_signal,
    })
}

fn validate_processing_hints(root: Node<'_, '_>) -> Result<(), &'static str> {
    message_storage_policy(root).map(|_| ())
}

fn validate_private_carbon_marker(root: Node<'_, '_>) -> Result<(), &'static str> {
    let markers = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "private"
                && node.tag_name().namespace() == Some("urn:xmpp:carbons:2")
        })
        .collect::<Vec<_>>();
    if markers.len() > 1 {
        return Err("bad-request");
    }
    if markers.first().is_some_and(|marker| {
        marker.attributes().len() != 0
            || marker.children().any(|child| child.is_element())
            || marker.text().is_some_and(|text| !text.trim().is_empty())
    }) {
        return Err("bad-request");
    }
    Ok(())
}

fn valid_message_reference(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        !value.is_empty()
            && value.len() <= 1_024
            && !value.chars().any(|character| character.is_control())
    })
}

fn validate_chat_states(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0085::parse_message(root)
        .map(|_| ())
        .map_err(|_| "bad-request")
}

fn validate_explicit_encryption(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0380::parse_message(root)
        .map(|_| ())
        .map_err(|_| "bad-request")
}

fn validate_fallbacks(root: Node<'_, '_>) -> Result<(), &'static str> {
    let message_texts = |name: &str| {
        root.children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == name
                    && matches!(node.tag_name().namespace(), None | Some("jabber:client"))
            })
            .map(|node| node.text().unwrap_or_default().chars().count())
            .collect::<Vec<_>>()
    };

    for fallback in root.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "fallback"
            && node.tag_name().namespace() == Some("urn:xmpp:fallback:0")
    }) {
        if fallback
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "for")
        {
            return Err("bad-request");
        }
        let namespace = fallback.attribute("for").ok_or("bad-request")?;
        if namespace.is_empty()
            || namespace.len() > 1_024
            || namespace.chars().any(char::is_control)
            || fallback.text().is_some_and(|text| !text.trim().is_empty())
        {
            return Err("bad-request");
        }

        let mut body_seen = false;
        for region in fallback.children().filter(|child| child.is_element()) {
            let name = region.tag_name().name();
            if region.tag_name().namespace() != Some("urn:xmpp:fallback:0")
                || !matches!(name, "subject" | "body")
                || (name == "subject" && body_seen)
                || region.children().any(|child| child.is_element())
                || region.text().is_some_and(|text| !text.trim().is_empty())
                || region.attributes().any(|attribute| {
                    attribute.namespace().is_some() || !matches!(attribute.name(), "start" | "end")
                })
            {
                return Err("bad-request");
            }
            body_seen |= name == "body";

            let (start, end) = match (region.attribute("start"), region.attribute("end")) {
                (None, None) => continue,
                (Some(start), Some(end)) => (
                    start.parse::<u32>().map_err(|_| "bad-request")? as usize,
                    end.parse::<u32>().map_err(|_| "bad-request")? as usize,
                ),
                _ => return Err("bad-request"),
            };
            let lengths = message_texts(name);
            if start > end || lengths.is_empty() || lengths.into_iter().any(|length| end > length) {
                return Err("bad-request");
            }
        }
    }
    Ok(())
}

fn validate_correction(root: Node<'_, '_>) -> Result<(), &'static str> {
    let Some(_) = northstar_xep_0308::parse_message(root).map_err(|_| "bad-request")? else {
        return Ok(());
    };
    // A correction resends the complete logical content. A naked control is
    // ambiguous archive spam; encrypted replacements remain inside E2EE.
    if !root.children().any(|node| {
        node.is_element()
            && ((matches!(node.tag_name().name(), "body" | "subject")
                && matches!(node.tag_name().namespace(), None | Some("jabber:client")))
                || is_encryption_node(node))
    }) {
        return Err("bad-request");
    }
    if root.children().any(is_non_messaging_correction_payload) {
        return Err("not-allowed");
    }
    Ok(())
}

fn is_non_messaging_correction_payload(node: Node<'_, '_>) -> bool {
    if !node.is_element() {
        return false;
    }
    matches!(
        (node.tag_name().namespace(), node.tag_name().name()),
        (Some("jabber:x:roster"), "x")
            | (Some("http://jabber.org/protocol/pubsub#event"), "event")
            | (Some("urn:xmpp:jingle-message:0"), _)
            | (Some("urn:xmpp:call-invites:0"), _)
            | (Some("urn:xmpp:chat-markers:0"), "displayed")
            | (Some("urn:xmpp:receipts"), "received")
            | (Some("urn:xmpp:reactions:0"), "reactions")
            | (Some("urn:xmpp:message-retract:1"), "retract" | "retracted")
    )
}

fn validate_displayed_marker(root: Node<'_, '_>) -> Result<(), &'static str> {
    let marker = northstar_xep_0333::parse_message(root).map_err(|_| "bad-request")?;
    if matches!(marker, Some(northstar_xep_0333::ChatMarker::Markable))
        && !valid_message_reference(root.attribute("id"))
    {
        return Err("bad-request");
    }
    Ok(())
}

fn validate_no_client_tombstone(root: Node<'_, '_>) -> Result<(), &'static str> {
    if root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "retracted"
            && node.tag_name().namespace() == Some("urn:xmpp:message-retract:1")
    }) {
        // `<retracted/>` is an archive-service tombstone representation. A
        // live endpoint requests retraction with `<retract/>` instead.
        return Err("not-allowed");
    }
    Ok(())
}

fn validate_reactions(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0444::parse_message(root)
        .map(|_| ())
        .map_err(|_| "not-acceptable")
}

fn validate_reply(root: Node<'_, '_>) -> Result<(), &'static str> {
    if let Some(reply) = northstar_xep_0461::parse_message(root).map_err(|_| "bad-request")? {
        // Canonical JID parsing is a server identity policy, deliberately kept
        // outside the capability-free wire crate.
        if crate::jid::CanonicalJid::parse(reply.to()).is_err() {
            return Err("bad-request");
        }
    }
    Ok(())
}

fn validate_file_sharing(root: Node<'_, '_>) -> Result<(), &'static str> {
    let shares = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "file-sharing"
                && node.tag_name().namespace() == Some("urn:xmpp:sfs:0")
        })
        .collect::<Vec<_>>();
    if shares.len() > 16 {
        return Err("resource-constraint");
    }
    let multiple = shares.len() > 1;
    let mut ids = HashSet::new();
    for share in shares {
        if share
            .attributes()
            .any(|attribute| !matches!(attribute.name(), "id" | "disposition"))
            || share
                .attribute("disposition")
                .is_some_and(|value| !matches!(value, "attachment" | "inline"))
        {
            return Err("bad-request");
        }
        if multiple {
            let id = share
                .attribute("id")
                .filter(|id| valid_message_reference(Some(id)));
            if id.is_none() || !ids.insert(id.unwrap()) {
                return Err("bad-request");
            }
        }
        if share.range().len() > 262_144
            || share.descendants().filter(|node| node.is_element()).count() > 256
            || share
                .children()
                .filter(|node| node.is_text())
                .any(|node| node.text().is_some_and(|text| !text.trim().is_empty()))
        {
            return Err("resource-constraint");
        }
        let file_nodes = share
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "file"
                    && node.tag_name().namespace() == Some("urn:xmpp:file:metadata:0")
            })
            .collect::<Vec<_>>();
        let sources = share
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "sources"
                    && node.tag_name().namespace() == Some("urn:xmpp:sfs:0")
            })
            .count();
        if file_nodes.len() != 1 || sources > 1 {
            return Err("bad-request");
        }
        validate_file_metadata(file_nodes[0])?;
    }
    Ok(())
}

fn validate_file_metadata(file: Node<'_, '_>) -> Result<(), &'static str> {
    if file.attributes().len() != 0
        || file.range().len() > 131_072
        || file.descendants().filter(|node| node.is_element()).count() > 128
        || file
            .children()
            .filter(|node| node.is_text())
            .any(|node| node.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err("resource-constraint");
    }

    let mut singletons = HashSet::new();
    let mut descriptions = HashSet::new();
    let mut hash_count = 0usize;
    let mut thumbnail_count = 0usize;
    for child in file.children().filter(|node| node.is_element()) {
        let namespace = child.tag_name().namespace().unwrap_or_default();
        let name = child.tag_name().name();
        match (namespace, name) {
            ("urn:xmpp:file:metadata:0", "date") => {
                validate_file_scalar(child, 64)?;
                if !singletons.insert(name)
                    || chrono::DateTime::parse_from_rfc3339(child.text().unwrap_or_default())
                        .is_err()
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:file:metadata:0", "media-type") => {
                validate_file_scalar(child, 255)?;
                let value = child.text().unwrap_or_default();
                if !singletons.insert(name)
                    || value.split_once('/').is_none_or(|(top, sub)| {
                        top.is_empty()
                            || sub.is_empty()
                            || value.chars().any(|character| {
                                character.is_control() || character.is_whitespace()
                            })
                    })
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:file:metadata:0", "name") => {
                validate_file_scalar(child, 1_024)?;
                let value = child.text().unwrap_or_default();
                if !singletons.insert(name)
                    || value.is_empty()
                    || value.chars().any(char::is_control)
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:file:metadata:0", "size")
            | ("urn:xmpp:file:metadata:0", "width")
            | ("urn:xmpp:file:metadata:0", "height")
            | ("urn:xmpp:file:metadata:0", "length") => {
                validate_file_scalar(child, 32)?;
                if !singletons.insert(name)
                    || child.text().unwrap_or_default().parse::<u64>().is_err()
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:file:metadata:0", "desc") => {
                if child.children().any(|nested| nested.is_element())
                    || child.text().is_some_and(|text| {
                        text.len() > 8_192 || text.chars().any(char::is_control)
                    })
                {
                    return Err("bad-request");
                }
                let language = child
                    .attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
                    .unwrap_or_default();
                if child.attributes().any(|attribute| {
                    attribute.namespace() != Some("http://www.w3.org/XML/1998/namespace")
                        || attribute.name() != "lang"
                }) || !descriptions.insert(language)
                    || (!language.is_empty() && !valid_language_tag(language))
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:hashes:2", "hash") => {
                hash_count += 1;
                let algorithm = child.attribute("algo").unwrap_or_default();
                let encoded = child.text().unwrap_or_default();
                if hash_count > 32
                    || child.children().any(|nested| nested.is_element())
                    || algorithm.is_empty()
                    || algorithm.len() > 64
                    || algorithm
                        .chars()
                        .any(|character| !character.is_ascii_alphanumeric() && character != '-')
                    || child
                        .attributes()
                        .any(|attribute| attribute.name() != "algo")
                    || encoded.is_empty()
                    || encoded.len() > 1_024
                    || encoded.chars().any(|character| {
                        !character.is_ascii_alphanumeric()
                            && !matches!(character, '+' | '/' | '=' | '-' | '_')
                    })
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:thumbs:1", "thumbnail") => {
                thumbnail_count += 1;
                if thumbnail_count > 16
                    || child.range().len() > 8_192
                    || child.descendants().filter(|node| node.is_element()).count() > 16
                {
                    return Err("resource-constraint");
                }
                // XEP-0264 has several transport profiles. Keep thumbnails
                // opaque for clients, but reject unbounded or control-bearing
                // metadata rather than claiming to render it.
                if child.attributes().any(|attribute| {
                    attribute.value().len() > 4_096
                        || attribute.value().chars().any(char::is_control)
                }) {
                    return Err("bad-request");
                }
            }
            _ => {
                // XEP-0446 is a client data format and intentionally
                // extensible. Preserve unknown metadata transparently while
                // enforcing an aggregate resource ceiling.
                if child.range().len() > 65_536
                    || child.descendants().filter(|node| node.is_element()).count() > 64
                    || child.attributes().any(|attribute| {
                        attribute.value().len() > 4_096
                            || attribute.value().chars().any(char::is_control)
                    })
                {
                    return Err("resource-constraint");
                }
            }
        }
    }
    Ok(())
}

fn validate_file_scalar(node: Node<'_, '_>, limit: usize) -> Result<(), &'static str> {
    if node.attributes().len() != 0
        || node.children().any(|child| child.is_element())
        || node
            .text()
            .is_none_or(|text| text.is_empty() || text.len() > limit)
    {
        return Err("bad-request");
    }
    Ok(())
}

pub(crate) fn is_encrypted(root: Node<'_, '_>) -> bool {
    root.children().any(is_encryption_node)
}

pub(crate) fn is_encryption_node(node: Node<'_, '_>) -> bool {
    node.is_element()
        && matches!(
            node.tag_name().namespace(),
            Some(
                "eu.siacs.conversations.axolotl"
                    | "urn:xmpp:omemo:1"
                    | "urn:xmpp:omemo:2"
                    | "urn:xmpp:openpgp:0"
                    | "jabber:x:encrypted"
            )
        )
}

pub(crate) fn set_from(raw: &str, from: &str) -> String {
    rewrite_root_attribute(raw, "from", from, true)
}

pub(crate) fn set_to(raw: &str, to: &str) -> String {
    rewrite_root_attribute(raw, "to", to, false)
}

/// Rebinds the root element's namespace prefix (or default namespace) to the
/// client stanza namespace while preserving the serialized payload. This is
/// used at the authenticated S2S-to-C2S boundary, where forwarding an
/// explicit `jabber:server` root would make the stanza foreign to clients.
pub(crate) fn set_client_namespace(raw: &str) -> String {
    let Ok(document) = Document::parse(raw) else {
        return raw.to_owned();
    };
    let root = document.root_element();
    if root.tag_name().namespace() == Some("jabber:client") {
        return raw.to_owned();
    }
    let Some(opening) = parse_root_opening(raw) else {
        return raw.to_owned();
    };
    let namespace_attribute = opening.element_name.split_once(':').map_or_else(
        || "xmlns".to_owned(),
        |(prefix, _)| format!("xmlns:{prefix}"),
    );
    let mut rewritten = raw.to_owned();
    let mut removals = opening
        .attributes
        .iter()
        .filter(|attribute| attribute.name == namespace_attribute)
        .map(|attribute| attribute.removal_start..attribute.end)
        .collect::<Vec<_>>();
    removals.sort_by_key(|range| std::cmp::Reverse(range.start));
    for range in removals {
        rewritten.replace_range(range, "");
    }
    let Some(opening) = parse_root_opening(&rewritten) else {
        return raw.to_owned();
    };
    rewritten.insert_str(
        opening.insertion,
        &format!(" {namespace_attribute}='jabber:client'"),
    );
    rewritten
}

#[derive(Debug)]
struct RootOpeningAttribute {
    name: String,
    value: String,
    /// Includes the XML whitespace immediately preceding this attribute so
    /// removing it cannot concatenate the neighbouring attributes.
    removal_start: usize,
    end: usize,
}

#[derive(Debug)]
struct RootOpening {
    element_name: String,
    insertion: usize,
    attributes: Vec<RootOpeningAttribute>,
}

fn rewrite_root_attribute(
    raw: &str,
    name: &str,
    value: &str,
    ensure_client_namespace: bool,
) -> String {
    let Ok(document) = Document::parse(raw) else {
        return raw.to_owned();
    };
    let root = document.root_element();
    let Some(opening) = parse_root_opening(raw) else {
        return raw.to_owned();
    };

    let mut rewritten = raw.to_owned();
    let mut removals = opening
        .attributes
        .iter()
        .filter(|attribute| attribute.name == name)
        .map(|attribute| attribute.removal_start..attribute.end)
        .collect::<Vec<_>>();
    removals.sort_by_key(|range| std::cmp::Reverse(range.start));
    for range in removals {
        rewritten.replace_range(range, "");
    }

    // Attribute removal changes byte offsets, so locate the safe insertion
    // point again. The document was already validated and only complete
    // attributes were removed above.
    let Some(opening) = parse_root_opening(&rewritten) else {
        return raw.to_owned();
    };
    let namespace = if ensure_client_namespace && root.lookup_namespace_uri(None).is_none() {
        " xmlns='jabber:client'"
    } else {
        ""
    };
    rewritten.insert_str(
        opening.insertion,
        &format!("{namespace} {name}='{}'", attr_escape(value)),
    );
    rewritten
}

pub(crate) fn set_root_attribute(raw: &str, name: &str, value: &str) -> String {
    rewrite_root_attribute(raw, name, value, false)
}

fn append_root_element(raw: &str, child: &XmlElement) -> Option<String> {
    append_root_validated_fragment(raw, &child.finish())
}

fn append_root_validated_fragment(raw: &str, child: &str) -> Option<String> {
    // `raw` is commonly a stanza restored from durable storage. Validate it
    // under the same size/depth/node/attribute and restricted-XML policy as
    // the child before performing the lexical-preservation splice.
    ValidatedXmlFragment::parse(raw).ok()?;
    let child = ValidatedXmlFragment::parse(child).ok()?;
    let document = Document::parse(raw).ok()?;
    append_validated_child_to_range(raw, document.root_element().range(), child.as_str())
}

fn append_element_child(
    raw: &str,
    element_range: std::ops::Range<usize>,
    child: &XmlElement,
) -> Option<String> {
    ValidatedXmlFragment::parse(raw).ok()?;
    let child = ValidatedXmlFragment::parse(&child.finish()).ok()?;
    append_validated_child_to_range(raw, element_range, child.as_str())
}

fn append_validated_child_to_range(
    raw: &str,
    element_range: std::ops::Range<usize>,
    child: &str,
) -> Option<String> {
    let element = raw.get(element_range.clone())?;
    let opening = parse_root_opening(element)?;
    let mut rewritten = raw.to_owned();
    if element.as_bytes().get(opening.insertion) == Some(&b'/') {
        let closing = XmlElement::dynamic(&opening.element_name).ok()?.close();
        let insertion = element_range.start.checked_add(opening.insertion)?;
        rewritten.replace_range(insertion..insertion + 2, &format!(">{child}{closing}"));
        return Some(rewritten);
    }
    let closing = element.rfind("</")?;
    rewritten.insert_str(element_range.start.checked_add(closing)?, child);
    Some(rewritten)
}

/// Locate only attributes on the document's root start tag. This is a lexical
/// preservation pass performed after a real XML parse; it deliberately never
/// searches payload text or nested elements.
fn parse_root_opening(raw: &str) -> Option<RootOpening> {
    let bytes = raw.as_bytes();
    let mut cursor = raw.len() - raw.trim_start().len();
    if bytes.get(cursor) != Some(&b'<') {
        return None;
    }
    cursor += 1;
    if matches!(bytes.get(cursor), Some(b'!' | b'?' | b'/')) {
        return None;
    }
    let element_start = cursor;
    while let Some(byte) = bytes.get(cursor) {
        if byte.is_ascii_whitespace() || matches!(byte, b'>' | b'/') {
            break;
        }
        cursor += 1;
    }
    let element_name = raw.get(element_start..cursor)?.to_owned();

    let mut attributes = Vec::new();
    loop {
        let whitespace_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        match bytes.get(cursor) {
            Some(b'>') => {
                return Some(RootOpening {
                    element_name,
                    insertion: cursor,
                    attributes,
                });
            }
            Some(b'/') if bytes.get(cursor + 1) == Some(&b'>') => {
                return Some(RootOpening {
                    element_name,
                    insertion: cursor,
                    attributes,
                });
            }
            None => return None,
            _ => {}
        }

        let name_start = cursor;
        while let Some(byte) = bytes.get(cursor) {
            if byte.is_ascii_whitespace() || matches!(byte, b'=' | b'>' | b'/') {
                break;
            }
            cursor += 1;
        }
        let attribute_name = raw.get(name_start..cursor)?.to_owned();
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            return None;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let quote = *bytes.get(cursor)?;
        if quote != b'\'' && quote != b'"' {
            return None;
        }
        cursor += 1;
        let value_start = cursor;
        while bytes.get(cursor).copied() != Some(quote) {
            cursor += 1;
            if cursor >= bytes.len() {
                return None;
            }
        }
        cursor += 1;
        attributes.push(RootOpeningAttribute {
            name: attribute_name,
            value: raw.get(value_start..cursor - 1)?.to_owned(),
            removal_start: whitespace_start,
            end: cursor,
        });
    }
}

/// A TCP stanza with no namespace declaration inherits `jabber:client` from
/// the surrounding stream. An explicit empty default namespace is different:
/// it resets that inherited namespace and therefore cannot be a core stanza.
pub(crate) fn root_resets_default_namespace(raw: &str) -> bool {
    parse_root_opening(raw).is_some_and(|opening| {
        opening
            .attributes
            .iter()
            .any(|attribute| attribute.name == "xmlns" && attribute.value.is_empty())
    })
}

pub(crate) fn encrypted_archive_stanza(stanza: &str) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let mut ranges: Vec<_> = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && !is_encryption_node(*node)
                && !is_safe_encrypted_archive_metadata(*node)
        })
        .map(|node| node.range())
        .collect();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut safe = stanza.to_owned();
    for range in ranges {
        safe.replace_range(range, "");
    }
    // XEP-0420 0.5.0 forbids a fallback body on SCE messages. Preserve the
    // historical generic fallback only for older encryption formats.
    if document.root_element().children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "encrypted"
            && node.tag_name().namespace() == Some(OMEMO2)
    }) {
        safe
    } else {
        append_root_element(
            &safe,
            &XmlElement::namespaced("body", "jabber:client")
                .text("This message is end-to-end encrypted."),
        )
        .unwrap_or(safe)
    }
}

/// Build the encrypted archive projection for a XEP-0424 retraction without
/// exposing the generic root-fragment insertion primitive outside this
/// serializer module. The runtime target is escaped by the typed builder and
/// callers are expected to have applied the protocol length/control checks.
pub(crate) fn encrypted_retraction_archive_stanza(stanza: &str, target_id: &str) -> String {
    let safe = encrypted_archive_stanza(stanza);
    let retract = XmlElement::namespaced("retract", "urn:xmpp:message-retract:1")
        .attr("id", target_id)
        .finish();
    append_root_validated_fragment(&safe, &retract).unwrap_or(safe)
}

fn is_safe_encrypted_archive_metadata(node: Node<'_, '_>) -> bool {
    matches!(
        (node.tag_name().namespace(), node.tag_name().name()),
        (
            Some("urn:xmpp:sid:0"),
            "origin-id" | "stanza-id" | "referenced-stanza"
        ) | (Some("urn:xmpp:eme:0"), "encryption")
            // OMEMO 2 payload messages require the explicit XEP-0334 store
            // hint.  Preserve it in the encrypted projection so a MUC/MAM
            // replay remains a valid stanza when it crosses an S2S boundary
            // and is validated again by the recipient server.
            | (Some("urn:xmpp:hints"), "store")
            | (Some("urn:xmpp:message-correct:0"), "replace")
            | (Some("urn:xmpp:reply:0"), "reply")
            | (Some("urn:xmpp:chat-markers:0"), "markable")
            | (Some("urn:xmpp:receipts"), "request")
    )
}

pub(crate) fn has_no_store_hint(root: Node<'_, '_>) -> bool {
    message_storage_policy(root)
        .map(|policy| !policy.permanent)
        .unwrap_or(true)
}

/// Return whether the sender explicitly requested XEP-0334 `no-store`.
///
/// This is intentionally different from [`has_no_store_hint`]: delivery
/// receipts and chat-state notifications are transient *by default*, but
/// that default must not be mistaken for an explicit prohibition on a
/// volatile online delivery.
pub(crate) fn has_explicit_no_store_hint(root: Node<'_, '_>) -> bool {
    root.attribute("type") != Some("error")
        && root.children().any(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some("urn:xmpp:hints")
                && node.tag_name().name() == "no-store"
        })
}

pub(crate) fn offline_storage_permitted(root: Node<'_, '_>) -> bool {
    message_storage_policy(root)
        .map(|policy| policy.temporary)
        .unwrap_or(false)
}

/// XEP-0313 archives accepted messages, never generated/rejected error
/// stanzas. Processing hints on an error are ignored per XEP-0334, so a
/// malicious `<store/>` cannot force a bounce into somebody's archive.
pub(crate) fn mam_storage_eligible(root: Node<'_, '_>) -> bool {
    root.attribute("type") != Some("error")
        && message_storage_policy(root)
            .map(|policy| policy.permanent)
            .unwrap_or(false)
}

#[cfg(test)]
#[path = "xml_util_tests.rs"]
mod tests;

pub(crate) fn inject_vcard_avatar_hash(
    raw: &str,
    _node: Node<'_, '_>,
    hash: Option<&str>,
) -> String {
    let Ok(document) = Document::parse(raw) else {
        return raw.to_owned();
    };
    let node = document.root_element();
    let updates = node
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "x"
                && child.tag_name().namespace() == Some("vcard-temp:x:update")
        })
        .collect::<Vec<_>>();
    // XEP-0398 preserves the sender's explicit empty-photo opt-out only when
    // it is an unambiguous, schema-shaped update. A second update, attributes,
    // extra elements or a second photo must not let a client smuggle a forged
    // hash past the server-authoritative conversion.
    if let [update] = updates.as_slice() {
        let elements = update
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        let explicit_empty = update.attributes().len() == 0
            && update
                .children()
                .filter(|child| child.is_text())
                .all(|child| child.text().is_none_or(|text| text.trim().is_empty()))
            && matches!(elements.as_slice(), [photo]
                if photo.tag_name().name() == "photo"
                    && photo.tag_name().namespace() == Some("vcard-temp:x:update")
                    && photo.attributes().len() == 0
                    && !photo.children().any(|child| child.is_element())
                    && photo.text().is_none_or(|text| text.trim().is_empty()));
        if explicit_empty {
            return raw.to_owned();
        }
    }
    let mut x_ranges = updates
        .iter()
        .map(|child| child.range())
        .collect::<Vec<_>>();

    let mut photo = XmlElement::new("photo");
    if let Some(hash) = hash {
        photo = photo.text(hash.to_owned());
    }
    let extension = XmlElement::namespaced("x", "vcard-temp:x:update").child(photo);

    let Some(first) = x_ranges.first().cloned() else {
        return append_root_element(raw, &extension).unwrap_or_else(|| raw.to_owned());
    };
    if ValidatedXmlFragment::parse(raw).is_err() {
        return raw.to_owned();
    }
    x_ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let extension = extension.finish();
    let mut rewritten = raw.to_owned();
    for range in x_ranges {
        rewritten.replace_range(range.clone(), if range == first { &extension } else { "" });
    }
    rewritten
}

#[cfg(test)]
#[path = "xml_util_vcard_presence_tests.rs"]
mod vcard_presence_tests;

#[cfg(test)]
#[path = "xml_util_strict_xdata_tests.rs"]
mod strict_xdata_tests;
