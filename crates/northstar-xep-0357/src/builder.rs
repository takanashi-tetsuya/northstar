//! Safe XML builders for XEP-0357 Push Notifications IQ payloads and notification stanzas.

use crate::constants::{XMLNS_CLIENT, XMLNS_PUBSUB, XMLNS_PUSH, XMLNS_STANZAS};
use crate::error::PushError;
use crate::subscription::PublishOptions;
use crate::summary::PushSummary;
use crate::xml::{escape_xml_attr, XmlElement};

/// Build an `<enable xmlns='urn:xmpp:push:0'>` element XML string.
pub fn build_enable(
    service_jid: &str,
    node: Option<&str>,
    options: Option<&PublishOptions>,
) -> String {
    let mut el = XmlElement::namespaced("enable", XMLNS_PUSH).attr("jid", service_jid);
    if let Some(n) = node {
        if !n.is_empty() {
            el = el.attr("node", n);
        }
    }
    if let Some(opts) = options {
        el.push_raw_fragment(opts.to_xml());
    }
    el.finish()
}

/// Build a `<disable xmlns='urn:xmpp:push:0'>` element XML string.
pub fn build_disable(service_jid: &str, node: Option<&str>) -> String {
    let mut el = XmlElement::namespaced("disable", XMLNS_PUSH).attr("jid", service_jid);
    if let Some(n) = node {
        if !n.is_empty() {
            el = el.attr("node", n);
        }
    }
    el.finish()
}

/// Build a complete push notification IQ-set stanza XML string.
///
/// Produces:
/// ```xml
/// <iq xmlns='jabber:client' type='set' from='server.example' to='push.example.test' id='push-xxx'>
///   <pubsub xmlns='http://jabber.org/protocol/pubsub'>
///     <publish node='device-1'>
///       <item>
///         <notification xmlns='urn:xmpp:push:0'>
///           <x xmlns='jabber:x:data' type='form'>...</x>
///         </notification>
///       </item>
///     </publish>
///     <publish-options>...</publish-options>
///   </pubsub>
/// </iq>
/// ```
pub fn build_notification_iq(
    from_domain: &str,
    to_service: &str,
    request_id: &str,
    node: Option<&str>,
    summary: &PushSummary,
    publish_options_xml: Option<&str>,
) -> Result<String, PushError> {
    let notification_xml = summary.to_notification_xml();

    let mut publish = XmlElement::new("publish");
    if let Some(n) = node {
        if !n.is_empty() {
            publish = publish.attr("node", n);
        }
    }
    publish.push_child(XmlElement::new("item").raw_fragment(notification_xml));

    let mut pubsub = XmlElement::namespaced("pubsub", XMLNS_PUBSUB).child(publish);

    if let Some(opts_xml) = publish_options_xml {
        let options_el = XmlElement::new("publish-options");
        let options_el = options_el.validated_fragment(opts_xml).map_err(|_| {
            PushError::InvalidPublishOptions("malformed publish-options XML fragment".to_owned())
        })?;
        pubsub.push_child(options_el);
    }

    let iq = XmlElement::namespaced("iq", XMLNS_CLIENT)
        .attr("type", "set")
        .attr("from", from_domain)
        .attr("to", to_service)
        .attr("id", request_id)
        .child(pubsub);

    Ok(iq.finish())
}

/// Build an IQ result response XML string addressed from `responder` to `to_jid`.
pub fn build_iq_result(id: &str, responder: &str, to_jid: &str) -> String {
    let mut out = String::with_capacity(128);
    out.push_str("<iq type='result' from='");
    escape_xml_attr(&mut out, responder);
    out.push_str("' to='");
    escape_xml_attr(&mut out, to_jid);
    out.push_str("' id='");
    escape_xml_attr(&mut out, id);
    out.push_str("'/>");
    out
}

/// Build an IQ error response XML string from a [`PushError`].
pub fn build_iq_error(id: &str, responder: &str, to_jid: &str, error: &PushError) -> String {
    let err_type = error.stanza_error_type();
    let condition = error.as_stanza_error_condition();
    let mut out = String::with_capacity(256);
    out.push_str("<iq type='error' from='");
    escape_xml_attr(&mut out, responder);
    out.push_str("' to='");
    escape_xml_attr(&mut out, to_jid);
    out.push_str("' id='");
    escape_xml_attr(&mut out, id);
    out.push_str("'><error type='");
    escape_xml_attr(&mut out, err_type);
    out.push_str("'><");
    out.push_str(condition);
    out.push_str(" xmlns='");
    out.push_str(XMLNS_STANZAS);
    out.push_str("'/></error></iq>");
    out
}

/// Build an xdata field element for the push summary form.
pub fn build_xdata_value_field(
    var: &str,
    field_type: &str,
    value: impl std::fmt::Display,
) -> XmlElement {
    XmlElement::new("field")
        .attr("var", var)
        .attr("type", field_type)
        .child(XmlElement::new("value").text(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_enable_with_node() {
        let xml = build_enable("push.example.test", Some("device-1"), None);
        assert!(xml.contains("jid='push.example.test'"));
        assert!(xml.contains("node='device-1'"));
        assert!(xml.starts_with("<enable"));
        assert!(xml.ends_with("/>"));
    }

    #[test]
    fn build_enable_without_node() {
        let xml = build_enable("push.example.test", None, None);
        assert!(xml.contains("jid='push.example.test'"));
        assert!(!xml.contains("node="));
    }

    #[test]
    fn build_disable_service_wide() {
        let xml = build_disable("push.example.test", None);
        assert!(xml.contains("jid='push.example.test'"));
        assert!(!xml.contains("node="));
        assert!(xml.ends_with("/>"));
    }

    #[test]
    fn build_disable_with_node() {
        let xml = build_disable("push.example.test", Some("device-1"));
        assert!(xml.contains("node='device-1'"));
    }

    #[test]
    fn build_notification_iq_structure() {
        let summary = PushSummary::new()
            .with_message_count(3)
            .with_pending_subscription_count(1);
        let xml = build_notification_iq(
            "server.example",
            "push.example.test",
            "push-123",
            Some("device-1"),
            &summary,
            None,
        )
        .unwrap();
        assert!(xml.contains("type='set'"));
        assert!(xml.contains("from='server.example'"));
        assert!(xml.contains("to='push.example.test'"));
        assert!(xml.contains("id='push-123'"));
        assert!(xml.contains("node='device-1'"));
        assert!(xml.contains("<notification"));
        assert!(xml.contains("urn:xmpp:push:0"));
        assert!(xml.contains("message-count"));
    }

    #[test]
    fn build_iq_result_escapes() {
        let xml = build_iq_result("1", "alice@example.test", "bob@example.test");
        assert!(xml.contains("type='result'"));
        assert!(xml.contains("id='1'"));
    }

    #[test]
    fn build_iq_error_structure() {
        let err = PushError::BadRequest("test".to_owned());
        let xml = build_iq_error("1", "server.example", "alice@example.test", &err);
        assert!(xml.contains("type='error'"));
        assert!(xml.contains("bad-request"));
        assert!(xml.contains(XMLNS_STANZAS));
    }
}
