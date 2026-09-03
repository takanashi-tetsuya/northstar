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
        // XEP-0004 requires receivers to ignore unknown submitted fields. We
        // still validate their bounded wire shape above so an ignored field
        // cannot become an XML-smuggling or memory-amplification primitive.
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

/// Validate bounded, unambiguous wire shapes for server-visible modern
/// message extensions. Northstar routes and archives these end-to-end client
/// payloads; it does not pretend to render or decrypt them.
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
mod tests {
    use super::{
        add_delay_from, add_muc_user_status, add_stanza_id, blocked_stanza_error, carbon_message,
        child_text, failure, has_no_store_hint, iq_error, iq_result, is_abuse_rated_message,
        mam_muc_stanza, mam_storage_eligible, message_storage_policy, muc_occupant_id,
        muc_occupant_key, muc_presence_stanza_with_status, offline_storage_permitted,
        prepare_muc_nick, reflect_iq_error_response, set_from, set_muc_occupant_id, set_to,
        should_carbon, stanza_error, stanza_error_type, stream_error, stream_id,
        strip_stanza_ids_by_domain, strip_untrusted_direct_delays, valid_bare_jid,
        valid_language_tag, valid_muc_nick, validate_delivery_receipts,
        validate_modern_message_payloads, validate_no_client_carbon, validate_routed_message,
        BASE64, MAX_OMEMO2_PAYLOAD_BYTES,
    };
    use base64::Engine;
    use roxmltree::Document;

    fn transient(xml: &str) -> bool {
        let document = Document::parse(xml).expect("test message must be valid XML");
        has_no_store_hint(document.root_element())
    }

    #[test]
    fn disabled_message_extensions_fail_closed_at_the_shared_ingress_boundary() {
        let disabled = crate::xmpp::extensions::ExtensionRuntime::resolve(
            crate::xmpp::extensions::ExtensionSwitches {
                xep_0016: true,
                xep_0045: true,
                xep_0059: true,
                xep_0060: true,
                xep_0085: false,
                xep_0092: true,
                xep_0115: true,
                xep_0184: false,
                xep_0191: true,
                xep_0198: true,
                xep_0199: true,
                xep_0202: true,
                xep_0215: true,
                xep_0280: true,
                xep_0313: true,
                xep_0352: true,
                xep_0357: true,
                xep_0359: false,
                xep_0363: true,
                xep_0308: false,
                xep_0333: false,
                xep_0380: false,
                xep_0444: false,
                xep_0461: false,
            },
        );
        for xml in [
            "<message><active xmlns='http://jabber.org/protocol/chatstates'/></message>",
            "<message id='m1'><request xmlns='urn:xmpp:receipts'/></message>",
            "<message><body>updated</body><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
            "<message id='m2'><markable xmlns='urn:xmpp:chat-markers:0'/></message>",
            "<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/></message>",
            "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>yes</reaction></reactions></message>",
            "<message><origin-id xmlns='urn:xmpp:sid:0' id='m1'/></message>",
            "<message><reply xmlns='urn:xmpp:reply:0' to='alice@example.test' id='m1'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                validate_routed_message(document.root_element(), &disabled),
                Err("feature-not-implemented"),
                "{xml}"
            );
        }
    }

    #[test]
    fn enabled_message_extensions_delegate_wire_validation_to_their_crates() {
        let enabled = crate::xmpp::extensions::ExtensionRuntime::resolve(
            crate::xmpp::extensions::ExtensionSwitches::default(),
        );
        let malformed = Document::parse(
            "<message><reply xmlns='urn:xmpp:reply:0' to='not a jid' id='m1'/></message>",
        )
        .unwrap();
        assert_eq!(
            validate_routed_message(malformed.root_element(), &enabled),
            Err("bad-request")
        );
    }

    #[test]
    fn stream_identifiers_are_csprng_unique() {
        let first = stream_id();
        let second = stream_id();
        assert_ne!(first, second);
        assert_ne!(first, 0);
        assert_ne!(second, 0);
    }

    #[test]
    fn common_error_builders_escape_values_and_whitelist_condition_elements() {
        let iq = iq_error("id' /><injected/>", "bad-request/><injected");
        let document = Document::parse(&iq).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("id"), Some("id' /><injected/>"));
        assert_eq!(
            root.descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "injected")
                .count(),
            0
        );
        assert!(root.descendants().any(|node| {
            node.is_element()
                && node.tag_name().name() == "undefined-condition"
                && node.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
        }));

        let stream = stream_error("policy-violation/><injected");
        let document = Document::parse(&stream).unwrap();
        assert!(document
            .descendants()
            .any(|node| node.is_element() && node.tag_name().name() == "undefined-condition"));

        let sasl = failure(
            "urn:ietf:params:xml:ns:xmpp-sasl' injected='true",
            "not-authorized/><injected",
        );
        let document = Document::parse(&sasl).unwrap();
        let root = document.root_element();
        assert_eq!(
            root.attribute("xmlns"),
            // Namespace declarations are not ordinary attributes in
            // roxmltree; lookup proves the escaped runtime URI stayed one
            // namespace value rather than becoming markup.
            None
        );
        assert_eq!(
            root.lookup_namespace_uri(None),
            Some("urn:ietf:params:xml:ns:xmpp-sasl' injected='true")
        );
        assert!(root.descendants().any(|node| {
            node.is_element() && node.tag_name().name() == "temporary-auth-failure"
        }));
    }

    #[test]
    fn iq_result_raw_payload_crosses_the_validated_fragment_boundary() {
        let valid = iq_result(
            "result-1",
            "<query xmlns='urn:example:query'><value>safe</value></query>",
        );
        let document = Document::parse(&valid).unwrap();
        assert_eq!(document.root_element().attribute("type"), Some("result"));
        assert!(valid.contains("urn:example:query"));

        let rejected = iq_result("result-2", "</iq><injected/>");
        let document = Document::parse(&rejected).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("type"), Some("error"));
        assert!(root.descendants().any(|node| {
            node.is_element() && node.tag_name().name() == "internal-server-error"
        }));
        assert!(!rejected.contains("<injected"));
    }

    #[test]
    fn child_text_respects_protocol_namespaces() {
        let document = Document::parse(
            "<presence><priority xmlns='urn:evil'>127</priority><priority xmlns='jabber:client'>5</priority></presence>",
        )
        .unwrap();
        assert_eq!(child_text(document.root_element(), "priority"), Some("5"));

        let document = Document::parse(
            "<field xmlns='jabber:x:data'><value xmlns='urn:evil'>bad</value><value>good</value></field>",
        )
        .unwrap();
        assert_eq!(child_text(document.root_element(), "value"), Some("good"));
    }

    #[test]
    fn standalone_chat_signals_are_transient() {
        assert!(transient(
            "<message><composing xmlns='http://jabber.org/protocol/chatstates'/></message>"
        ));
        assert!(transient(
            "<message><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>"
        ));
        assert!(transient(
            "<message><thread>chat-1</thread><composing xmlns='http://jabber.org/protocol/chatstates'/><origin-id xmlns='urn:xmpp:sid:0' id='state-1'/></message>"
        ));
    }

    #[test]
    fn offline_delay_is_server_asserted_and_utc() {
        let stamp = chrono::DateTime::parse_from_rfc3339("2026-08-25T12:34:56Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let delayed = add_delay_from(
            "<message><body>queued</body></message>",
            stamp,
            Some("example.test"),
        );
        assert!(delayed.contains(
            "<delay xmlns='urn:xmpp:delay' from='example.test' stamp='2026-08-25T12:34:56Z'/>"
        ));

        let forged = "<message><delay xmlns='urn:xmpp:delay' from='mallory.test' stamp='1999-01-01T00:00:00Z'/><body>queued</body></message>";
        let delayed = add_delay_from(forged, stamp, Some("example.test"));
        assert_eq!(delayed.matches("urn:xmpp:delay").count(), 1);
        assert!(!delayed.contains("mallory.test"));
    }

    #[test]
    fn direct_delay_requires_the_current_transport_authority() {
        let stanza = "<message><body>x</body><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='2024-01-01T00:00:00Z'/><forwarded xmlns='urn:xmpp:forward:0'><delay xmlns='urn:xmpp:delay' from='archive.remote.test' stamp='2023-01-01T00:00:00Z'/></forwarded></message>";
        let c2s = strip_untrusted_direct_delays(stanza, None);
        assert!(!c2s.contains("from='remote.test'"));
        assert!(c2s.contains("from='archive.remote.test'"));

        let s2s = strip_untrusted_direct_delays(stanza, Some("REMOTE.TEST"));
        assert!(s2s.contains("from='remote.test'"));
        assert!(s2s.contains("from='archive.remote.test'"));

        let forged = "<message><delay xmlns='urn:xmpp:delay' from='local.test' stamp='2024-01-01T00:00:00Z'/><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='not-a-date'/></message>";
        let sanitized = strip_untrusted_direct_delays(forged, Some("remote.test"));
        assert!(!sanitized.contains("<delay"));

        let reason = "<message><delay xmlns='urn:xmpp:delay' stamp='2024-01-01T00:00:00.123Z'>Offline Storage</delay></message>";
        assert_eq!(
            strip_untrusted_direct_delays(reason, Some("remote.test")),
            reason
        );

        let offset = "<message><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='2024-01-01T01:00:00+01:00'/></message>";
        assert!(!strip_untrusted_direct_delays(offset, Some("remote.test")).contains("<delay"));

        let duplicate = "<message><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='2024-01-01T00:00:00Z'/><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='2024-01-02T00:00:00Z'/></message>";
        assert!(!strip_untrusted_direct_delays(duplicate, Some("remote.test")).contains("<delay"));
    }

    #[test]
    fn root_address_rewriting_ignores_markup_like_attribute_values() {
        let raw = "<message xmlns = \"jabber:client\" note=\"from='mallory' and >\" from = \"mallory@example.test/phone\"><body>to='victim'</body></message>";
        let rewritten = set_to(
            &set_from(raw, "alice@example.test/Phone"),
            "bob@example.test",
        );
        let document = Document::parse(&rewritten).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("from"), Some("alice@example.test/Phone"));
        assert_eq!(root.attribute("to"), Some("bob@example.test"));
        assert_eq!(root.attribute("note"), Some("from='mallory' and >"));
        assert_eq!(
            root.children()
                .find(|child| child.is_element())
                .and_then(|body| body.text()),
            Some("to='victim'")
        );
        assert_eq!(rewritten.matches(" from=").count(), 1);
        assert_eq!(rewritten.matches(" to=").count(), 1);
    }

    #[test]
    fn source_rewriting_adds_the_inherited_client_namespace_once() {
        let rewritten = set_from("<message to='bob@example.test'/>", "alice@example.test/a");
        let document = Document::parse(&rewritten).unwrap();
        let root = document.root_element();
        assert_eq!(root.tag_name().namespace(), Some("jabber:client"));
        assert_eq!(rewritten.matches("xmlns='jabber:client'").count(), 1);
        assert!(rewritten.ends_with("/>"));
    }

    #[test]
    fn authoritative_extensions_support_prefixed_and_self_closing_roots() {
        let id = uuid::Uuid::nil();
        let annotated = add_stanza_id(
            "<c:message xmlns:c='jabber:client' note='a>b'/>",
            "example.test",
            id,
        );
        let document = Document::parse(&annotated).unwrap();
        let root = document.root_element();
        assert_eq!(root.tag_name().name(), "message");
        assert_eq!(root.attribute("note"), Some("a>b"));
        assert!(root.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "stanza-id"
                && child.tag_name().namespace() == Some("urn:xmpp:sid:0")
        }));

        let delayed = add_delay_from(
            "<c:message xmlns:c='jabber:client'><c:body>queued</c:body></c:message>",
            chrono::DateTime::parse_from_rfc3339("2026-08-25T12:34:56Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            Some("example.test"),
        );
        let document = Document::parse(&delayed).unwrap();
        assert!(document.root_element().children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "delay"
                && child.tag_name().namespace() == Some("urn:xmpp:delay")
        }));
    }

    #[test]
    fn stanza_errors_reflect_payload_namespaces_and_swap_addresses() {
        let input = "<c:message xmlns:c='jabber:client' xmlns:e='urn:example' type='chat' id='m1' from='alice@example.test/A' to='bob@example.test'><c:body>hello</c:body><e:payload value='1'/></c:message>";
        let document = Document::parse(input).unwrap();
        let error = stanza_error(document.root_element(), "cancel", "service-unavailable");
        let document = Document::parse(&error).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("type"), Some("error"));
        assert_eq!(root.attribute("from"), Some("bob@example.test"));
        assert_eq!(root.attribute("to"), Some("alice@example.test/A"));
        assert!(root.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "payload"
                && child.tag_name().namespace() == Some("urn:example")
        }));
        let error_node = root
            .children()
            .find(|child| child.is_element() && child.tag_name().name() == "error")
            .unwrap();
        assert_eq!(error_node.tag_name().namespace(), Some("jabber:client"));
        assert_eq!(error_node.attribute("type"), Some("cancel"));

        let blocked = blocked_stanza_error(document.root_element());
        let document = Document::parse(&blocked).unwrap();
        assert_eq!(
            document
                .descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "error")
                .count(),
            1
        );
    }

    #[test]
    fn iq_errors_reflect_the_request_and_use_rfc_error_types() {
        let request = Document::parse(
            "<iq xmlns='jabber:client' type='get' id='q1' from='alice@example.test/A' to='pubsub.example.test'><query xmlns='urn:example'/></iq>",
        )
        .unwrap();
        let reflected = reflect_iq_error_response(
            request.root_element(),
            "<iq xmlns='jabber:client' type='error' id='q1'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><retry xmlns='urn:example' seconds='3'/></error></iq>",
        )
        .unwrap();
        let document = Document::parse(&reflected).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("type"), Some("error"));
        assert_eq!(root.attribute("from"), Some("pubsub.example.test"));
        assert_eq!(root.attribute("to"), Some("alice@example.test/A"));
        assert!(root.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "query"
                && child.tag_name().namespace() == Some("urn:example")
        }));
        assert!(root.descendants().any(|child| {
            child.is_element()
                && child.tag_name().name() == "retry"
                && child.tag_name().namespace() == Some("urn:example")
        }));
        assert_eq!(stanza_error_type("not-authorized"), "auth");
        assert_eq!(stanza_error_type("bad-request"), "modify");
        assert_eq!(stanza_error_type("remote-server-timeout"), "wait");
        assert_eq!(stanza_error_type("item-not-found"), "cancel");

        let implicit = Document::parse(
            "<iq xmlns='jabber:client' type='set' id='c1' from='alice@example.test/A'><enable xmlns='urn:xmpp:carbons:2' unexpected='true'/></iq>",
        )
        .unwrap();
        let addressed = reflect_iq_error_response(
            implicit.root_element(),
            "<iq xmlns='jabber:client' type='error' id='c1' from='alice@example.test' to='alice@example.test/A'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
        )
        .unwrap();
        let addressed = Document::parse(&addressed).unwrap();
        assert_eq!(
            addressed.root_element().attribute("from"),
            Some("alice@example.test")
        );
        assert_eq!(
            addressed.root_element().attribute("to"),
            Some("alice@example.test/A")
        );
    }

    #[test]
    fn reflected_errors_never_echo_registration_or_form_secrets() {
        let request = Document::parse(
            "<iq xmlns='jabber:client' type='set' id='pw1' from='alice@example.test/A'><query xmlns='jabber:iq:register'><username>alice</username><password>new-secret</password><x xmlns='jabber:x:data' type='submit'><field var='urn:northstar:invite:token'><value>invite-secret</value></field></x></query></iq>",
        )
        .unwrap();
        let reflected = reflect_iq_error_response(
            request.root_element(),
            "<iq xmlns='jabber:client' type='error' id='pw1'><error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
        )
        .unwrap();
        assert!(!reflected.contains("new-secret"));
        assert!(!reflected.contains("invite-secret"));
        let document = Document::parse(&reflected).unwrap();
        let password = document
            .descendants()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "password"
                    && node.tag_name().namespace() == Some("jabber:iq:register")
            })
            .unwrap();
        assert!(password.text().is_none());
    }

    #[test]
    fn stanza_ids_are_well_formed_and_unique_per_canonical_issuer() {
        for valid in [
            "<message><origin-id xmlns='urn:xmpp:sid:0' id='client-1'/><stanza-id xmlns='urn:xmpp:sid:0' id='server-1' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote-1' by='remote.test'/><referenced-stanza xmlns='urn:xmpp:sid:0' id='older' by='room@conference.example.test'/></message>",
            "<message><stanza-id xmlns='urn:xmpp:sid:0' id='upper' by='alice@example.test/Phone'/><stanza-id xmlns='urn:xmpp:sid:0' id='lower' by='alice@example.test/phone'/></message>",
        ] {
            let document = Document::parse(valid).unwrap();
            assert_eq!(validate_modern_message_payloads(document.root_element()), Ok(()));
        }
        for invalid in [
            "<message><origin-id xmlns='urn:xmpp:sid:0'/></message>",
            "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one'/></message>",
            "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='bad jid'/></message>",
            "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='two' by='alice@example.test'/></message>",
            "<message><origin-id xmlns='urn:xmpp:sid:0' id='one'>text</origin-id></message>",
            "<message><origin-id xmlns='urn:xmpp:sid:0' id='one'/><origin-id xmlns='urn:xmpp:sid:0' id='two'/></message>",
            "<message><referenced-stanza xmlns='urn:xmpp:sid:0' id='one'><child/></referenced-stanza></message>",
        ] {
            let document = Document::parse(invalid).unwrap();
            assert!(validate_modern_message_payloads(document.root_element()).is_err());
        }
    }

    #[test]
    fn stickers_require_one_bounded_stateless_file_share() {
        for valid in [
            "<message><sticker xmlns='urn:xmpp:stickers:0'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><media-type>image/png</media-type><size>1</size></file><sources><url-data xmlns='http://jabber.org/protocol/url-data' target='https://files.example/sticker.png'/></sources></file-sharing></message>",
            "<message><sticker xmlns='urn:xmpp:stickers:0' pack='EpRv28DHHzFrE4zd+xaNpVb4' jid='pubsub.example.test' node='urn:xmpp:stickers:0'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><media-type>image/webp</media-type></file></file-sharing></message>",
        ] {
            let document = Document::parse(valid).unwrap();
            let root = document.root_element();
            assert_eq!(validate_modern_message_payloads(root), Ok(()), "{valid}");
            assert!(is_abuse_rated_message(root));
        }
        for (invalid, condition) in [
            ("<message><sticker xmlns='urn:xmpp:stickers:0'/></message>", "bad-request"),
            ("<message><sticker xmlns='urn:xmpp:stickers:0'>not empty</sticker><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "bad-request"),
            ("<message><sticker xmlns='urn:xmpp:stickers:0' pack='p' node='n'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "bad-request"),
            ("<message><sticker xmlns='urn:xmpp:stickers:0' pack='p' jid='bad jid' node='n'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "jid-malformed"),
            ("<message><sticker xmlns='urn:xmpp:stickers:0'/><sticker xmlns='urn:xmpp:stickers:0'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "bad-request"),
            ("<message><sticker xmlns='urn:xmpp:stickers:0'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "bad-request"),
        ] {
            let document = Document::parse(invalid).unwrap();
            assert_eq!(
                validate_modern_message_payloads(document.root_element()),
                Err(condition),
                "{invalid}"
            );
        }
    }

    #[test]
    fn plaintext_trust_messages_are_bounded_and_unambiguous() {
        let valid = "<message type='chat'><store xmlns='urn:xmpp:hints'/><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='Alice@Example.test'><trust>aFABnX7Q/rbTgjBySYzrT2FsYCVYb49mbca5yB734KQ=</trust></key-owner><key-owner jid='bob@example.test'><distrust>tCP1CI3pqSTVGzFYFyPYUMfMZ9Ck/msmfD0wH/VtJBM=</distrust></key-owner></trust-message></message>";
        let document = Document::parse(valid).unwrap();
        assert_eq!(
            validate_modern_message_payloads(document.root_element()),
            Ok(())
        );
        assert!(is_abuse_rated_message(document.root_element()));

        for (invalid, condition) in [
            ("<message><trust-message xmlns='urn:xmpp:tm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'><trust>AQIDBA==</trust></key-owner></trust-message></message>", "bad-request"),
            ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test/phone'><trust>AQIDBA==</trust></key-owner></trust-message></message>", "jid-malformed"),
            ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'/></trust-message></message>", "bad-request"),
            ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'><trust>not base64!</trust></key-owner></trust-message></message>", "bad-request"),
            ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='Alice@Example.test'><trust>AQIDBA==</trust></key-owner><key-owner jid='alice@example.test'><distrust>BQYHCA==</distrust></key-owner></trust-message></message>", "bad-request"),
            ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'><trust>AQIDBA==</trust><distrust>AQIDBA==</distrust></key-owner></trust-message></message>", "bad-request"),
            ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><unknown/></trust-message></message>", "bad-request"),
            ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'><trust>AQIDBA==</trust></key-owner></trust-message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='bob@example.test'><trust>BQYHCA==</trust></key-owner></trust-message></message>", "bad-request"),
        ] {
            let document = Document::parse(invalid).unwrap();
            assert_eq!(
                validate_modern_message_payloads(document.root_element()),
                Err(condition),
                "{invalid}"
            );
        }
    }

    #[test]
    fn language_tags_follow_bcp47_structure() {
        for valid in [
            "en",
            "en-US",
            "zh-Hant-TW",
            "de-CH-1901",
            "sl-rozaj-biske-1994",
            "en-a-myext-x-private",
            "x-klingon",
            "i-default",
        ] {
            assert!(valid_language_tag(valid), "rejected {valid}");
        }
        for invalid in [
            "",
            "e",
            "en--US",
            "en-abcdefghi",
            "en-a",
            "en-a-test-a-again",
            "de-1901-1901",
            "x",
            "en-工具",
        ] {
            assert!(!valid_language_tag(invalid), "accepted {invalid}");
        }
    }

    #[test]
    fn error_messages_never_enter_mam_even_with_store_hint() {
        let document = Document::parse(
            "<message type='error'><store xmlns='urn:xmpp:hints'/><error type='cancel'/></message>",
        )
        .unwrap();
        assert!(!mam_storage_eligible(document.root_element()));
    }

    #[test]
    fn processing_hints_on_error_messages_are_ignored() {
        let document = Document::parse(
            "<message type='error'><no-copy xmlns='urn:xmpp:hints'>malformed-but-ignored</no-copy><body>original IM payload</body><error type='cancel'/></message>",
        )
        .unwrap();
        let root = document.root_element();
        assert_eq!(
            message_storage_policy(root).unwrap(),
            super::MessageStoragePolicy {
                temporary: false,
                permanent: false,
            }
        );
        assert!(should_carbon(root));
        assert!(super::validate_processing_hints(root).is_ok());
    }

    #[test]
    fn service_rewrites_preserve_processing_hints_verbatim() {
        let raw = "<message><x/><no-store xmlns='urn:xmpp:hints'/><future xmlns='urn:xmpp:hints' opaque='yes'/></message>";
        let document = Document::parse(raw).unwrap();
        assert_eq!(
            super::processing_hints_fragment(document.root_element(), raw),
            "<no-store xmlns='urn:xmpp:hints'/><future xmlns='urn:xmpp:hints' opaque='yes'/>"
        );
    }

    #[test]
    fn jingle_message_signalling_is_abuse_rated() {
        let document = Document::parse(
            "<message type='chat'><ringing xmlns='urn:xmpp:jingle-message:0' id='call-1'/><store xmlns='urn:xmpp:hints'/></message>",
        )
        .unwrap();
        assert!(is_abuse_rated_message(document.root_element()));
    }

    #[test]
    fn chat_signal_with_other_payload_remains_persistent() {
        assert!(!transient(
            "<message><active xmlns='http://jabber.org/protocol/chatstates'/><request xmlns='urn:xmpp:receipts'/></message>"
        ));
        assert!(!transient(
            "<message><body>hello</body><markable xmlns='urn:xmpp:chat-markers:0'/></message>"
        ));
    }

    #[test]
    fn carbon_rules_select_only_im_traffic_and_honor_suppression() {
        for xml in [
            "<message type='chat'/>",
            // XEP-0334 limits <no-copy/> to messages addressed to a full
            // JID.  On an unaddressed stanza the server ignores the hint
            // instead of suppressing RFC 6121 / XEP-0280 delivery.
            "<message type='chat'><no-copy xmlns='urn:xmpp:hints'/></message>",
            "<message><body>hello</body></message>",
            "<message><received xmlns='urn:xmpp:receipts' id='m1'/></message>",
            "<message><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>",
            "<message><x xmlns='jabber:x:conference' jid='room@conference.example.test'/></message>",
            "<message><x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@example.test'/></x></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(should_carbon(document.root_element()), "{xml}");
        }
        for xml in [
            "<message/>",
            "<message type='groupchat'><body>room</body></message>",
            "<message type='headline'><body>news</body></message>",
            "<message type='chat'><private xmlns='urn:xmpp:carbons:2'/></message>",
            "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>👍</reaction></reactions></message>",
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='m1'/></message>",
            "<message><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
            "<message><reply xmlns='urn:xmpp:reply:0' id='m1'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(!should_carbon(document.root_element()), "{xml}");
        }
    }

    #[test]
    fn carbon_rules_include_eligible_error_replies() {
        let eligible = Document::parse(
            "<message type='error'><body>original IM payload</body><error type='cancel'/></message>",
        )
        .unwrap();
        assert!(should_carbon(eligible.root_element()));
        let ineligible =
            Document::parse("<message type='error'><error type='cancel'/></message>").unwrap();
        assert!(!should_carbon(ineligible.root_element()));
    }

    #[test]
    fn clients_cannot_assert_or_nest_server_carbon_wrappers() {
        for xml in [
            "<message><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message/></forwarded></sent></message>",
            "<message><x><received xmlns='urn:xmpp:carbons:2'/></x></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                validate_no_client_carbon(document.root_element()),
                Err("not-allowed")
            );
        }
    }

    #[test]
    fn carbon_wrapper_preserves_type_and_server_addressing() {
        let wrapped = carbon_message(
            "received",
            "alice@example.test",
            "alice@example.test/tablet",
            "<message xmlns='jabber:client' from='bob@example.net/phone' to='alice@example.test' type='chat'><body>hi</body></message>",
        )
        .unwrap();
        let document = Document::parse(&wrapped).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("type"), Some("chat"));
        assert_eq!(root.attribute("from"), Some("alice@example.test"));
        assert_eq!(root.attribute("to"), Some("alice@example.test/tablet"));
        assert_eq!(
            root.descendants()
                .filter(|node| node.is_element()
                    && node.tag_name().name() == "forwarded"
                    && node.tag_name().namespace() == Some("urn:xmpp:forward:0"))
                .count(),
            1
        );

        let forwarded_message = root
            .descendants()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "forwarded"
                    && node.tag_name().namespace() == Some("urn:xmpp:forward:0")
            })
            .unwrap()
            .children()
            .find(|node| node.is_element())
            .unwrap();
        assert_eq!(forwarded_message.tag_name().name(), "message");
        assert_eq!(
            forwarded_message.tag_name().namespace(),
            Some("jabber:client")
        );
        assert_eq!(
            forwarded_message
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "body")
                .unwrap()
                .tag_name()
                .namespace(),
            Some("jabber:client")
        );
    }

    #[test]
    fn carbon_wrapper_rejects_dynamic_element_name_injection() {
        assert!(carbon_message(
            "received></received><injected",
            "alice@example.test",
            "alice@example.test/tablet",
            "<message xmlns='jabber:client' type='chat'><body>hi</body></message>",
        )
        .is_none());
    }

    #[test]
    fn carbon_wrapper_suppresses_invalid_or_restricted_forwarded_fragments() {
        for forwarded in [
            "<message><body></message>",
            "<message><!-- restricted --><body>hi</body></message>",
            "<message><unbound:payload/></message>",
        ] {
            assert!(carbon_message(
                "received",
                "alice@example.test",
                "alice@example.test/tablet",
                forwarded,
            )
            .is_none());
        }
    }

    #[test]
    fn carbon_wrapper_restores_the_inherited_client_namespace() {
        for forwarded in [
            "<message from='bob@example.net/phone' to='alice@example.test' type='chat'><body>stream inherited</body></message>",
            "<message xmlns='jabber:server' from='bob@example.net/phone' to='alice@example.test' type='chat'><body>federated</body></message>",
        ] {
            let wrapped = carbon_message(
                "received",
                "alice@example.test",
                "alice@example.test/tablet",
                forwarded,
            )
            .unwrap();
            let document = Document::parse(&wrapped).unwrap();
            let forwarded = document
                .descendants()
                .find(|node| {
                    node.is_element()
                        && node.tag_name().name() == "forwarded"
                        && node.tag_name().namespace() == Some("urn:xmpp:forward:0")
                })
                .unwrap();
            let message = forwarded
                .children()
                .find(|node| node.is_element())
                .unwrap();
            assert_eq!(message.tag_name().namespace(), Some("jabber:client"));
            let body = message
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "body")
                .unwrap();
            assert_eq!(body.tag_name().namespace(), Some("jabber:client"));
        }
    }

    #[test]
    fn muc_mam_payload_never_trusts_archived_identity_extensions() {
        let archived = "<message xmlns='jabber:client' from='room@conference.example.test/nick' to='alice@example.test/phone'><body>hi</body><x xmlns='http://jabber.org/protocol/muc#user'><item jid='forged@example.test'/></x><x xmlns='urn:northstar:muc:sender:0' jid='forged@example.test'/></message>";
        let hidden = mam_muc_stanza(archived, "real@example.test/phone", false);
        assert!(!hidden.contains(" to="));
        assert!(!hidden.contains("forged@example.test"));
        assert!(!hidden.contains("real@example.test"));

        let revealed = mam_muc_stanza(archived, "real@example.test/phone", true);
        assert!(!revealed.contains("forged@example.test"));
        assert!(revealed.contains("<item jid='real@example.test/phone'/>"));
        assert_eq!(
            revealed
                .matches("http://jabber.org/protocol/muc#user")
                .count(),
            1
        );
    }

    #[test]
    fn explicit_no_store_always_wins() {
        assert!(transient(
            "<message><body>secret</body><no-store xmlns='urn:xmpp:hints'/></message>"
        ));
    }

    #[test]
    fn explicit_store_keeps_a_standalone_chat_signal() {
        assert!(!transient(
            "<message><active xmlns='http://jabber.org/protocol/chatstates'/><store xmlns='urn:xmpp:hints'/></message>"
        ));
        assert!(!transient(
            "<message><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/><store xmlns='urn:xmpp:hints'/></message>"
        ));
    }

    #[test]
    fn no_permanent_store_keeps_temporary_offline_recovery_only() {
        let document = Document::parse(
            "<message to='bob@example.test'><body>temporary</body><no-permanent-store xmlns='urn:xmpp:hints'/></message>",
        )
        .unwrap();
        let root = document.root_element();
        assert!(offline_storage_permitted(root));
        assert!(!mam_storage_eligible(root));
        assert_eq!(
            message_storage_policy(root).unwrap(),
            super::MessageStoragePolicy {
                temporary: true,
                permanent: false,
            }
        );
    }

    #[test]
    fn processing_hints_are_empty_and_unique() {
        for invalid in [
            "<message to='bob@example.test'><store xmlns='urn:xmpp:hints'/><store xmlns='urn:xmpp:hints'/></message>",
            "<message to='bob@example.test'><no-store xmlns='urn:xmpp:hints'>yes</no-store></message>",
            "<message to='bob@example.test/phone'><private xmlns='urn:xmpp:carbons:2'/><private xmlns='urn:xmpp:carbons:2'/></message>",
        ] {
            assert!(!modern_payload_valid(invalid), "{invalid}");
        }
        assert!(modern_payload_valid(
            "<message to='bob@example.test/phone'><no-copy xmlns='urn:xmpp:hints'/></message>"
        ));
        assert!(modern_payload_valid(
            "<message to='bob@example.test'><no-copy xmlns='urn:xmpp:hints'/></message>"
        ));
        let bare = Document::parse(
            "<message to='bob@example.test'><body>fan out</body><no-copy xmlns='urn:xmpp:hints'/></message>",
        )
        .unwrap();
        assert!(should_carbon(bare.root_element()));
        let full = Document::parse(
            "<message to='bob@example.test/phone'><body>single target</body><no-copy xmlns='urn:xmpp:hints'/></message>",
        )
        .unwrap();
        assert!(!should_carbon(full.root_element()));
    }

    #[test]
    fn overlapping_storage_hints_use_privacy_preserving_precedence() {
        for (xml, expected) in [
            (
                "<message><store xmlns='urn:xmpp:hints'/><no-permanent-store xmlns='urn:xmpp:hints'/></message>",
                super::MessageStoragePolicy {
                    temporary: true,
                    permanent: false,
                },
            ),
            (
                "<message><store xmlns='urn:xmpp:hints'/><no-permanent-store xmlns='urn:xmpp:hints'/><no-store xmlns='urn:xmpp:hints'/></message>",
                super::MessageStoragePolicy {
                    temporary: false,
                    permanent: false,
                },
            ),
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                message_storage_policy(document.root_element()).unwrap(),
                expected,
                "{xml}"
            );
        }
    }

    #[test]
    fn delivery_receipts_require_unambiguous_ids() {
        let valid =
            Document::parse("<message id='m1'><request xmlns='urn:xmpp:receipts'/></message>")
                .unwrap();
        assert!(validate_delivery_receipts(valid.root_element()).is_ok());
        assert!(transient(
            "<message><received xmlns='urn:xmpp:receipts' id='m1'/></message>"
        ));

        for invalid in [
            "<message><request xmlns='urn:xmpp:receipts'/></message>",
            "<message><received xmlns='urn:xmpp:receipts'/></message>",
            "<message id='m1'><request xmlns='urn:xmpp:receipts'/><received xmlns='urn:xmpp:receipts' id='m0'/></message>",
            "<message id='m1'><received xmlns='urn:xmpp:receipts' evil:id='m0' xmlns:evil='urn:evil'/></message>",
        ] {
            let document = Document::parse(invalid).unwrap();
            assert!(validate_delivery_receipts(document.root_element()).is_err());
        }
    }

    fn modern_payload_valid(xml: &str) -> bool {
        let document = Document::parse(xml).expect("test message must be XML");
        validate_modern_message_payloads(document.root_element()).is_ok()
    }

    #[test]
    fn modern_message_extensions_accept_current_wire_shapes() {
        for xml in [
            "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
            "<message id='m2'><body>fixed</body><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
            "<message id='m1'><markable xmlns='urn:xmpp:chat-markers:0'/></message>",
            "<message><received xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>",
            "<message><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>",
            "<message><acknowledged xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>",
            "<message><openpgp xmlns='urn:xmpp:openpgp:0'/><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:openpgp:0'/></message>",
            "<message><body>🧛🏾 &amp; ok</body><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:reply:0'><body start='0' end='7'/></fallback></message>",
            "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>👍</reaction></reactions></message>",
            "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>👍</reaction><reaction>👍</reaction></reactions></message>",
            "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'/></message>",
            "<message><reply xmlns='urn:xmpp:reply:0' id='m1' to='alice@example.test/phone'/></message>",
            "<message><file-sharing xmlns='urn:xmpp:sfs:0' disposition='attachment'><file xmlns='urn:xmpp:file:metadata:0'><name>a.txt</name></file></file-sharing></message>",
        ] {
            assert!(modern_payload_valid(xml), "{xml}");
        }
    }

    #[test]
    fn encrypted_archive_preserves_ciphertext_and_eme_but_not_fallback_text() {
        for (namespace, payload) in [
            (
                "urn:xmpp:omemo:1",
                "<encrypted xmlns='urn:xmpp:omemo:1'><payload>cipher</payload></encrypted>",
            ),
            (
                "urn:xmpp:openpgp:0",
                "<openpgp xmlns='urn:xmpp:openpgp:0'>cipher</openpgp>",
            ),
            (
                "jabber:x:encrypted",
                "<x xmlns='jabber:x:encrypted'>cipher</x>",
            ),
        ] {
            let stanza = format!(
                "<message><body>plaintext fallback</body>{payload}<encryption xmlns='urn:xmpp:eme:0' namespace='{namespace}'/><origin-id xmlns='urn:xmpp:sid:0' id='m1'/><replace xmlns='urn:xmpp:message-correct:0' id='old'/><reply xmlns='urn:xmpp:reply:0' id='parent'/><markable xmlns='urn:xmpp:chat-markers:0'/><request xmlns='urn:xmpp:receipts'/><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:reply:0'/></message>"
            );
            let document = Document::parse(&stanza).unwrap();
            assert!(super::is_encrypted(document.root_element()), "{namespace}");
            let archived = super::encrypted_archive_stanza(&stanza);
            assert!(archived.contains("cipher"), "{namespace}");
            assert!(archived.contains("urn:xmpp:eme:0"), "{namespace}");
            assert!(archived.contains("urn:xmpp:sid:0"), "{namespace}");
            assert!(
                archived.contains("urn:xmpp:message-correct:0"),
                "{namespace}"
            );
            assert!(archived.contains("urn:xmpp:reply:0"), "{namespace}");
            assert!(archived.contains("urn:xmpp:chat-markers:0"), "{namespace}");
            assert!(archived.contains("urn:xmpp:receipts"), "{namespace}");
            assert!(!archived.contains("urn:xmpp:fallback:0"), "{namespace}");
            assert!(!archived.contains("plaintext fallback"), "{namespace}");
            assert!(archived.contains("This message is end-to-end encrypted."));
        }

        let nested = Document::parse(
            "<message><wrapper xmlns='urn:example'><encrypted xmlns='urn:xmpp:omemo:2'/></wrapper></message>",
        )
        .unwrap();
        assert!(!super::is_encrypted(nested.root_element()));

        // XEP-0380 is only an informational assertion.  It is abuse-rated,
        // but cannot by itself satisfy an encrypted-archive policy.
        let marker_only = Document::parse(
            "<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/></message>",
        )
        .unwrap();
        assert!(!super::is_encrypted(marker_only.root_element()));
        assert!(super::is_abuse_rated_message(marker_only.root_element()));

        let omemo2 = "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/><store xmlns='urn:xmpp:hints'/></message>";
        let archived = super::encrypted_archive_stanza(omemo2);
        assert!(archived.contains("urn:xmpp:omemo:2"));
        assert!(archived.contains("<payload>Ag==</payload>"));
        assert!(archived.contains("<store xmlns='urn:xmpp:hints'/>"));
        assert!(!archived.contains("<body"));
        assert!(!archived.contains("This message is end-to-end encrypted."));
        assert!(modern_payload_valid(&archived));
    }

    #[test]
    fn omemo2_transport_shape_is_bounded_and_rejects_plaintext_downgrades() {
        let valid = "<message type='chat'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9' kex='true'>AQ==</key></keys><keys jid='bob@bücher.example'><key rid='10'>Ag==</key></keys></header><payload>Aw==</payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' name='OMEMO'/><store xmlns='urn:xmpp:hints'/></message>";
        assert!(modern_payload_valid(valid));
        let empty = "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/><no-store xmlns='urn:xmpp:hints'/></message>";
        assert!(modern_payload_valid(empty));

        for invalid in [
            "<message><envelope xmlns='urn:xmpp:sce:1'><content/></envelope></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><body>plaintext downgrade</body></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><file-sharing xmlns='urn:xmpp:sfs:0'/></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='0'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test/device'><key rid='9'>AQ==</key></keys></header></encrypted></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys><keys jid='ALICE@example.test'><key rid='10'>Ag==</key></keys></header></encrypted></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key><key rid='9'>Ag==</key></keys></header></encrypted></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9' kex='yes'>AQ==</key></keys></header></encrypted></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>not-base64!</key></keys></header></encrypted></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload/></encrypted></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><payload>Ag==</payload><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted><store xmlns='urn:xmpp:hints'/></message>",
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted><encrypted xmlns='urn:xmpp:omemo:2'><header sid='8'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted></message>",
        ] {
            assert!(!modern_payload_valid(invalid), "{invalid}");
        }

        let oversized_payload = BASE64.encode(vec![0_u8; MAX_OMEMO2_PAYLOAD_BYTES + 1]);
        let oversized = format!(
            "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>{oversized_payload}</payload></encrypted><store xmlns='urn:xmpp:hints'/></message>"
        );
        assert!(!modern_payload_valid(&oversized));
    }

    #[test]
    fn omemo2_payload_store_requirement_does_not_override_no_store_policy() {
        let no_store = "<message type='chat'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/><store xmlns='urn:xmpp:hints'/><no-store xmlns='urn:xmpp:hints'/></message>";
        let document = Document::parse(no_store).unwrap();
        let root = document.root_element();

        assert_eq!(validate_modern_message_payloads(root), Ok(()));
        assert_eq!(
            message_storage_policy(root),
            Ok(super::MessageStoragePolicy {
                temporary: false,
                permanent: false,
            })
        );
        assert!(!offline_storage_permitted(root));
        assert!(!mam_storage_eligible(root));

        let missing_store = "<message type='chat'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/><no-store xmlns='urn:xmpp:hints'/></message>";
        let document = Document::parse(missing_store).unwrap();
        assert_eq!(
            validate_modern_message_payloads(document.root_element()),
            Err("not-acceptable")
        );
    }

    #[test]
    fn modern_message_extensions_reject_ambiguous_or_unbounded_controls() {
        for xml in [
            "<message><active xmlns='http://jabber.org/protocol/chatstates'/><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
            "<message><typing xmlns='http://jabber.org/protocol/chatstates'/></message>",
            "<message><encryption xmlns='urn:xmpp:eme:0'/></message>",
            "<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' evil:name='spoof' xmlns:evil='urn:evil'/></message>",
            "<message><body>🧛🏾</body><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:reply:0'><body start='0' end='9'/></fallback></message>",
            "<message><body>reply</body><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:reply:0'><body start='4'/></fallback></message>",
            "<message><body>reply</body><fallback xmlns='urn:xmpp:fallback:0'><body/></fallback></message>",
            "<message><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
            "<message><body>not a correction</body><received xmlns='urn:xmpp:receipts' id='delivery'/><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
            "<message><body>not a correction</body><propose xmlns='urn:xmpp:jingle-message:0' id='call'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/></propose><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
            "<message id='m1'><markable xmlns='urn:xmpp:chat-markers:0'/><displayed xmlns='urn:xmpp:chat-markers:0' id='m0'/></message>",
            "<message><retracted xmlns='urn:xmpp:message-retract:1' id='server-only'/></message>",
            "<message><reply xmlns='urn:xmpp:reply:0' id='m1' evil:to='alice@example.test' xmlns:evil='urn:evil'/></message>",
            "<message><reply xmlns='urn:xmpp:reply:0' id='m1' to='bad@@example.test'/></message>",
            "<message><file-sharing xmlns='urn:xmpp:sfs:0'/></message>",
            "<message><file-sharing xmlns='urn:xmpp:sfs:0' id='same'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing><file-sharing xmlns='urn:xmpp:sfs:0' id='same'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>",
            "<message><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><size>-1</size></file></file-sharing></message>",
            "<message><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><name>a</name><name>b</name></file></file-sharing></message>",
            "<message><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><date>not-a-date</date></file></file-sharing></message>",
        ] {
            assert!(!modern_payload_valid(xml), "{xml}");
        }
    }

    #[test]
    fn bare_jid_validation_rejects_resources_and_malformed_addresses() {
        assert!(valid_bare_jid("alice@example.test"));
        assert!(valid_bare_jid("用户@例子.测试"));
        assert!(valid_bare_jid("example.test"));
        assert!(!valid_bare_jid("@example.test"));
        assert!(!valid_bare_jid("alice@"));
        assert!(!valid_bare_jid("alice@example.test/resource"));
        assert!(!valid_bare_jid("alice@@example.test"));
        assert!(!valid_bare_jid("ali ce@example.test"));
    }

    #[test]
    fn stable_id_replaces_spoofed_issuer_and_preserves_origin() {
        let id = uuid::Uuid::parse_str("de305d54-75b4-431b-adb2-eb6b9e546013").unwrap();
        let annotated = add_stanza_id(
            "<message><origin-id xmlns='urn:xmpp:sid:0' id='client'/><stanza-id xmlns='urn:xmpp:sid:0' id='spoofed' by='alice@example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote' by='remote.test'/></message>",
            "alice@example.test",
            id,
        );
        assert!(annotated.contains("id='client'"));
        assert!(annotated.contains("id='remote'"));
        assert!(!annotated.contains("spoofed"));
        assert!(annotated.contains(&id.to_string()));
        assert_eq!(annotated.matches("by='alice@example.test'").count(), 1);
    }

    #[test]
    fn stable_id_can_be_removed_without_disclosing_the_senders_archive_id() {
        let cleaned = strip_stanza_ids_by_domain(
            "<message><origin-id xmlns='urn:xmpp:sid:0' id='client'/><stanza-id xmlns='urn:xmpp:sid:0' id='spoofed' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote' by='remote.test'/></message>",
            "example.test",
        );
        assert!(cleaned.contains("id='client'"));
        assert!(cleaned.contains("id='remote'"));
        assert!(!cleaned.contains("spoofed"));
        assert!(!cleaned.contains("by='Alice@Example.test'"));
    }

    #[test]
    fn local_domain_identity_sanitization_removes_every_forged_account() {
        let cleaned = strip_stanza_ids_by_domain(
            "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='alice@example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='two' by='Mallory@EXAMPLE.TEST'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote' by='remote.test'/></message>",
            "example.test",
        );
        assert!(!cleaned.contains("id='one'"));
        assert!(!cleaned.contains("id='two'"));
        assert!(cleaned.contains("id='remote'"));
    }

    #[test]
    fn occupant_ids_are_stable_and_scoped_to_a_room_secret() {
        let first = muc_occupant_id(&[7_u8; 32], "Alice@Example.test/phone");
        assert_eq!(
            first,
            muc_occupant_id(&[7_u8; 32], "alice@example.test/laptop")
        );
        assert_ne!(first, muc_occupant_id(&[8_u8; 32], "alice@example.test"));
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn authoritative_occupant_id_replaces_client_spoofing() {
        let stanza = set_muc_occupant_id(
            "<message><body>hello</body><occupant-id xmlns='urn:xmpp:occupant-id:0' id='spoofed'/></message>",
            "authoritative",
        );
        assert!(!stanza.contains("spoofed"));
        assert!(stanza.contains("id='authoritative'"));
        assert_eq!(stanza.matches("urn:xmpp:occupant-id:0").count(), 1);
    }

    #[test]
    fn muc_removal_presence_carries_self_kick_and_occupant_identity() {
        let occupant = crate::state::SerializableMucOccupant {
            full_jid: "alice@example.test/phone".to_owned(),
            room_jid: "room@conference.example.test".to_owned(),
            nick: "alice".to_owned(),
            affiliation: "member".to_owned(),
            role: "none".to_owned(),
            room_non_anonymous: false,
            occupant_id: "opaque-id".to_owned(),
            cluster_epoch: uuid::Uuid::new_v4(),
            connection_id: uuid::Uuid::new_v4(),
            federated_domain: None,
            sm_session_id: None,
            payload: String::new(),
        };
        let stanza = muc_presence_stanza_with_status(
            &occupant,
            &occupant.full_jid,
            true,
            true,
            false,
            Some("leave-1"),
            true,
            Some(307),
            Some("moderator"),
            Some("flooding"),
        );
        assert!(stanza.contains("<status code='110'/><status code='307'/>"));
        assert!(stanza.contains("<actor nick='moderator'/><reason>flooding</reason>"));
        assert!(stanza.contains("id='opaque-id'"));
    }

    #[test]
    fn muc_status_insertion_handles_prefixed_self_closing_extensions() {
        let input = "<c:presence xmlns:c='jabber:client'><m:x xmlns:m='http://jabber.org/protocol/muc#user'/></c:presence>";
        let stanza = add_muc_user_status(input, 170);
        let document = Document::parse(&stanza).unwrap();
        let status = document
            .descendants()
            .find(|node| node.is_element() && node.tag_name().name() == "status")
            .unwrap();
        assert_eq!(
            status.tag_name().namespace(),
            Some("http://jabber.org/protocol/muc#user")
        );
        assert_eq!(status.attribute("code"), Some("170"));
        assert_eq!(
            document
                .descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "status")
                .count(),
            1
        );
    }

    #[test]
    fn muc_occupant_keys_preserve_precis_opaque_nickname_case() {
        let upper = muc_occupant_key("ROOM@Conference.Example.test", "Nick");
        let lower = muc_occupant_key("room@conference.example.test", "nick");
        assert_eq!(upper, "room@conference.example.test/Nick");
        assert_eq!(lower, "room@conference.example.test/nick");
        assert_ne!(upper, lower);
    }

    #[test]
    fn muc_nickname_preparation_normalizes_without_trimming_or_case_mapping() {
        assert_eq!(prepare_muc_nick("A\u{30a}").unwrap(), "\u{c5}");
        assert_eq!(prepare_muc_nick(" Nick ").unwrap(), " Nick ");
        assert_ne!(
            prepare_muc_nick("Nick").unwrap(),
            prepare_muc_nick("nick").unwrap()
        );
        assert!(!valid_muc_nick(""));
        assert!(!valid_muc_nick("bad\u{0007}nick"));
    }
}

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
mod vcard_presence_tests {
    use super::*;

    #[test]
    fn test_inject_vcard_avatar_hash() {
        let raw = "<presence from='a' to='b'><x xmlns='vcard-temp:x:update'><photo>forged</photo></x></presence>";
        let doc = roxmltree::Document::parse(raw).unwrap();
        let replaced = inject_vcard_avatar_hash(raw, doc.root_element(), Some("real"));
        assert!(replaced.contains("<photo>real</photo>"));
        assert!(!replaced.contains("forged"));
    }

    #[test]
    fn explicit_empty_photo_is_not_overwritten() {
        let raw = "<presence><x xmlns='vcard-temp:x:update'><photo/></x></presence>";
        let doc = roxmltree::Document::parse(raw).unwrap();
        assert_eq!(
            inject_vcard_avatar_hash(raw, doc.root_element(), Some("stored")),
            raw
        );

        let ambiguous =
            "<presence><x xmlns='vcard-temp:x:update'><photo/><photo>forged</photo></x></presence>";
        let doc = roxmltree::Document::parse(ambiguous).unwrap();
        let replaced = inject_vcard_avatar_hash(ambiguous, doc.root_element(), Some("stored"));
        assert_eq!(replaced.matches("vcard-temp:x:update").count(), 1);
        assert!(replaced.contains("<photo>stored</photo>"));
        assert!(!replaced.contains("forged"));

        let duplicate = "<presence><x xmlns='vcard-temp:x:update'><photo/></x><x xmlns='vcard-temp:x:update'><photo>forged</photo></x></presence>";
        let doc = roxmltree::Document::parse(duplicate).unwrap();
        let replaced = inject_vcard_avatar_hash(duplicate, doc.root_element(), Some("stored"));
        assert_eq!(replaced.matches("vcard-temp:x:update").count(), 1);
        assert!(!replaced.contains("forged"));
    }

    #[test]
    fn avatar_hash_is_text_and_prefixed_empty_presence_is_expanded_safely() {
        let raw = "<c:presence xmlns:c='jabber:client'/>";
        let document = roxmltree::Document::parse(raw).unwrap();
        let attack = "hash</photo><injected xmlns='urn:evil'/>";
        let replaced = inject_vcard_avatar_hash(raw, document.root_element(), Some(attack));
        let document = roxmltree::Document::parse(&replaced).unwrap();
        let root = document.root_element();
        assert_eq!(root.tag_name().namespace(), Some("jabber:client"));
        assert!(document
            .descendants()
            .all(|node| !node.is_element() || node.tag_name().name() != "injected"));
        let photo = document
            .descendants()
            .find(|node| node.is_element() && node.tag_name().name() == "photo")
            .unwrap();
        assert_eq!(photo.tag_name().namespace(), Some("vcard-temp:x:update"));
        assert_eq!(photo.text(), Some(attack));
    }
}

#[cfg(test)]
mod strict_xdata_tests {
    use super::*;

    #[test]
    fn test_strict_xdata_submit() {
        let allowed = &["username", "password"];

        // Valid form
        let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='username'><value>user1</value></field></x>";
        let doc = roxmltree::Document::parse(xml).unwrap();
        let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
        assert!(res.is_ok());

        // Adjacent text/CDATA nodes are concatenated, never silently
        // truncated to the first XML text node.
        let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='username'><value>us<![CDATA[er1]]></value></field></x>";
        let doc = roxmltree::Document::parse(xml).unwrap();
        let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
        assert_eq!(
            res.unwrap().get("username").map(String::as_str),
            Some("user1")
        );

        // Wrong FORM_TYPE
        let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>wrong</value></field><field var='username'><value>user1</value></field></x>";
        let doc = roxmltree::Document::parse(xml).unwrap();
        let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
        assert!(res.is_err());

        // Multivalue
        let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='username'><value>user1</value><value>user2</value></field></x>";
        let doc = roxmltree::Document::parse(xml).unwrap();
        let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
        assert!(res.is_err());

        // Duplicate field
        let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='username'><value>user1</value></field><field var='username'><value>user2</value></field></x>";
        let doc = roxmltree::Document::parse(xml).unwrap();
        let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
        assert!(res.is_err());

        // XEP-0004 requires unknown submitted fields to be ignored.
        let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><field var='unknown'><value>user1</value></field></x>";
        let doc = roxmltree::Document::parse(xml).unwrap();
        let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
        assert!(res.is_ok_and(|values| !values.contains_key("unknown")));

        // Mixed namespace
        let xml = "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>jabber:iq:register</value></field><bad xmlns='other'/></x>";
        let doc = roxmltree::Document::parse(xml).unwrap();
        let res = strict_xdata_submit(doc.root_element(), "jabber:iq:register", allowed);
        assert!(res.is_err());
    }
}
