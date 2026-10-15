use crate::security::abuse::WorkRequirement;
use crate::state::{attr_escape, bare_jid};
use crate::xmpp::xml_builder::{ValidatedXmlFragment, XmlElement};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use roxmltree::{Document, Node};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

mod message_validation;
mod muc;
mod stanza_rewrite;

use self::message_validation::{
    validate_chat_states, validate_correction, validate_displayed_marker,
    validate_explicit_encryption, validate_fallbacks, validate_file_sharing,
    validate_no_client_tombstone, validate_omemo2_envelope, validate_private_carbon_marker,
    validate_processing_hints, validate_reactions, validate_reply, validate_stanza_ids,
    validate_sticker, validate_trust_message,
};
pub(crate) use self::muc::{
    add_muc_sender, add_muc_user_status, mam_muc_stanza, muc_destroy_presence,
    muc_nickname_change_presence, muc_occupant_id, muc_occupant_key, muc_presence_stanza,
    muc_presence_stanza_with_status, muc_stanza_error, prepare_muc_nick, set_muc_occupant_id,
    valid_muc_nick, valid_muc_room,
};
use self::stanza_rewrite::{
    append_element_child, append_root_element, append_root_validated_fragment,
    remove_root_attribute,
};
pub(crate) use self::stanza_rewrite::{
    inject_vcard_avatar_hash, root_resets_default_namespace, set_client_namespace, set_from,
    set_root_attribute, set_to,
};

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

/// Validate and prepare an RFC 7622 bare JID.
pub(crate) fn valid_bare_jid(value: &str) -> bool {
    crate::jid::CanonicalJid::parse_bare(value).is_ok()
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

const OMEMO2: &str = "urn:xmpp:omemo:2";
const SCE: &str = "urn:xmpp:sce:1";
const MAX_OMEMO2_ENCRYPTED_BYTES: usize = 2 * 1024 * 1024;
const MAX_OMEMO2_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_OMEMO2_KEY_BYTES: usize = 64 * 1024;
const MAX_OMEMO2_KEY_GROUPS: usize = 1024;
const MAX_OMEMO2_KEYS_PER_GROUP: usize = 1024;
const MAX_OMEMO2_TOTAL_KEYS: usize = 8192;

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

#[cfg(test)]
#[path = "xml_util_vcard_presence_tests.rs"]
mod vcard_presence_tests;

#[cfg(test)]
#[path = "xml_util_strict_xdata_tests.rs"]
mod strict_xdata_tests;
