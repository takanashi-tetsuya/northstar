//! Stream-level elements of RFC 6120 and SASL failures.

use crate::XmlElement;

pub fn is_counted_stanza(stanza: &str) -> bool {
    let stanza = stanza.trim_start();
    stanza.starts_with("<iq") || stanza.starts_with("<message") || stanza.starts_with("<presence")
}

pub fn stream_id() -> u128 {
    // RFC 6120 requires every stream identifier to be unique, including the
    // new stream opened after STARTTLS. Wall-clock timestamps can repeat when
    // connections open within one clock tick or the system clock is adjusted;
    // a CSPRNG-backed UUID avoids both failure modes.
    uuid::Uuid::new_v4().as_u128()
}

pub fn failure(ns: &str, condition: &str) -> String {
    XmlElement::new("failure")
        .attr("xmlns", ns)
        .child(XmlElement::new(sasl_failure_condition_name(condition)))
        .finish()
}

pub fn stream_error(condition: &str) -> String {
    XmlElement::new("stream:error")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .child(
            XmlElement::new(stream_error_condition_name(condition))
                .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-streams"),
        )
        .finish()
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
