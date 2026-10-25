//! RFC 6120 IQ replies and stanza error conditions. An unknown condition becomes
//! `undefined-condition`; a payload that is not a well-formed fragment becomes an
//! `internal-server-error` reply instead of malformed output.

use crate::XmlElement;

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
