//! RFC 6120 IQ replies and stanza error conditions. An unknown condition becomes
//! `undefined-condition`; a payload that is not a well-formed fragment becomes an
//! `internal-server-error` reply instead of malformed output.

use crate::rewrite::{append_root_validated_fragment, remove_root_attribute, set_root_attribute};
use crate::XmlElement;
use roxmltree::Node;

pub fn iq_result(id: &str, payload: &str) -> String {
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

pub fn iq_result_from(id: &str, from: &str, payload: &str) -> String {
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

pub fn iq_result_to(id: &str, from: &str, to: &str, payload: &str) -> String {
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

pub fn iq_error(id: &str, condition: &str) -> String {
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

pub fn iq_error_from(id: &str, from: &str, condition: &str) -> String {
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

pub fn iq_error_to(id: &str, from: &str, to: &str, error_type: &str, condition: &str) -> String {
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

pub fn stanza_condition_element(condition: &str) -> XmlElement {
    XmlElement::new(stanza_condition_name(condition))
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas")
}

pub fn stanza_error_type(condition: &str) -> &'static str {
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

/// The text of the first child `name` of `node`, in the namespace of `node`.
pub fn child_text<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<&'a str> {
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

/// The RFC 6120 error reply to `root`, with the given type and condition.
pub fn stanza_error(root: Node<'_, '_>, error_type: &str, condition: &str) -> String {
    let error = XmlElement::namespaced("error", "jabber:client")
        .attr("type", error_type)
        .child(stanza_condition_element(condition))
        .finish();
    reflected_stanza_error(root, &error)
}

/// The XEP-0191 error reply to a stanza addressed to a blocked entity.
pub fn blocked_stanza_error(root: Node<'_, '_>) -> String {
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

/// `root` turned back to its sender with the `error` element, without any credential it carried.
pub fn reflected_stanza_error(root: Node<'_, '_>, error: &str) -> String {
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
