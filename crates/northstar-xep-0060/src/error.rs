//! XEP-0060 and RFC 6120 protocol errors and XML stanza error mappings.

use crate::constants::{NS_PUBSUB_ERRORS, NS_STANZAS};
use crate::xml::XmlElement;
use std::fmt;

/// RFC 6120 stanza error type categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StanzaErrorType {
    Auth,
    Modify,
    Wait,
    Cancel,
}

impl StanzaErrorType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Modify => "modify",
            Self::Wait => "wait",
            Self::Cancel => "cancel",
        }
    }
}

impl fmt::Display for StanzaErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Map an RFC 6120 error condition to its standard error type.
pub const fn stanza_error_type_for_condition(condition: &str) -> StanzaErrorType {
    match condition.as_bytes() {
        b"forbidden" | b"not-authorized" | b"payment-required" => StanzaErrorType::Auth,
        b"bad-request" | b"gone" | b"jid-malformed" | b"not-acceptable" | b"redirect" => {
            StanzaErrorType::Modify
        }
        b"policy-violation" | b"resource-constraint" | b"service-unavailable" => {
            StanzaErrorType::Wait
        }
        _ => StanzaErrorType::Cancel,
    }
}

/// An auditable XEP-0060 error with optional application-specific error condition,
/// unsupported feature token, or redirection URI.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub struct PubSubError {
    pub condition: &'static str,
    pub pubsub_condition: Option<&'static str>,
    pub feature: Option<&'static str>,
    pub redirect: Option<String>,
}

impl fmt::Display for PubSubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PubSubError(condition: {}", self.condition)?;
        if let Some(sub) = self.pubsub_condition {
            write!(f, ", pubsub_condition: {sub}")?;
        }
        if let Some(feat) = self.feature {
            write!(f, ", feature: {feat}")?;
        }
        if let Some(ref redir) = self.redirect {
            write!(f, ", redirect: {redir}")?;
        }
        write!(f, ")")
    }
}

impl PubSubError {
    pub const fn new(condition: &'static str, pubsub_condition: &'static str) -> Self {
        Self {
            condition,
            pubsub_condition: Some(pubsub_condition),
            feature: None,
            redirect: None,
        }
    }

    pub const fn simple(condition: &'static str) -> Self {
        Self {
            condition,
            pubsub_condition: None,
            feature: None,
            redirect: None,
        }
    }

    pub const fn unsupported(feature: &'static str) -> Self {
        Self {
            condition: "feature-not-implemented",
            pubsub_condition: Some("unsupported"),
            feature: Some(feature),
            redirect: None,
        }
    }

    pub fn moved(uri: impl Into<String>) -> Self {
        Self {
            condition: "gone",
            pubsub_condition: None,
            feature: None,
            redirect: Some(uri.into()),
        }
    }

    pub const fn bad_request() -> Self {
        Self::simple("bad-request")
    }

    pub const fn forbidden() -> Self {
        Self::simple("forbidden")
    }

    pub const fn item_not_found() -> Self {
        Self::simple("item-not-found")
    }

    pub const fn conflict() -> Self {
        Self::simple("conflict")
    }

    pub const fn not_acceptable() -> Self {
        Self::simple("not-acceptable")
    }

    pub const fn not_allowed() -> Self {
        Self::simple("not-allowed")
    }

    pub const fn resource_constraint() -> Self {
        Self::simple("resource-constraint")
    }

    pub const fn policy_violation() -> Self {
        Self::simple("policy-violation")
    }

    pub const fn unexpected_request() -> Self {
        Self::simple("unexpected-request")
    }

    pub const fn stanza_error_type(&self) -> StanzaErrorType {
        stanza_error_type_for_condition(self.condition)
    }

    /// Returns the stanza error type string and inner XML payload for this error.
    pub fn error_payload(&self) -> (&'static str, String) {
        let type_str = self.stanza_error_type().as_str();
        let extra = self
            .pubsub_condition
            .map(|specific| {
                let mut el = match XmlElement::dynamic(specific) {
                    Ok(e) => e.attr("xmlns", NS_PUBSUB_ERRORS),
                    Err(_) => XmlElement::namespaced("undefined-condition", NS_STANZAS),
                };
                if let Some(feat) = self.feature {
                    el = el.attr("feature", feat);
                }
                el.finish()
            })
            .unwrap_or_default();
        (type_str, extra)
    }

    /// Build an `<error type='...'>...</error>` element for this error.
    pub fn to_error_element(&self) -> XmlElement {
        let mut condition_element = match XmlElement::dynamic(self.condition) {
            Ok(e) => e.attr("xmlns", NS_STANZAS),
            Err(_) => XmlElement::namespaced("undefined-condition", NS_STANZAS),
        };
        if let Some(ref uri) = self.redirect {
            condition_element = condition_element.text(uri.clone());
        }

        let mut stanza_error = XmlElement::new("error")
            .attr("type", self.stanza_error_type().as_str())
            .child(condition_element);

        if let Some(specific) = self.pubsub_condition {
            let mut specific_element = match XmlElement::dynamic(specific) {
                Ok(e) => e.attr("xmlns", NS_PUBSUB_ERRORS),
                Err(_) => XmlElement::namespaced("undefined-condition", NS_STANZAS),
            };
            if let Some(feat) = self.feature {
                specific_element = specific_element.attr("feature", feat);
            }
            stanza_error = stanza_error.child(specific_element);
        }

        stanza_error
    }
}

/// Map a node configuration form error condition into an appropriate [`PubSubError`].
pub fn node_config_parse_error(condition: &'static str) -> PubSubError {
    if condition == "unsupported-access-model" {
        PubSubError::new("not-acceptable", "unsupported-access-model")
    } else {
        PubSubError::simple(condition)
    }
}

/// Helper for invalid subscription options form error.
pub const fn invalid_subscription_options() -> PubSubError {
    PubSubError::new("bad-request", "invalid-options")
}

/// Build a complete `<iq type='error' ...>` response for client-to-server dispatch.
pub fn build_iq_error(id: &str, from: &str, error: &PubSubError) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("id", id)
        .child(error.to_error_element())
        .finish()
}

/// Build a complete `<iq type='error' ...>` response for server-to-server dispatch.
pub fn build_s2s_iq_error(id: &str, from: &str, to: &str, error: &PubSubError) -> String {
    XmlElement::namespaced("iq", "jabber:server")
        .attr("type", "error")
        .attr("id", id)
        .attr("from", from)
        .attr("to", to)
        .child(error.to_error_element())
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn maps_stanza_error_types_correctly() {
        assert_eq!(
            stanza_error_type_for_condition("forbidden"),
            StanzaErrorType::Auth
        );
        assert_eq!(
            stanza_error_type_for_condition("bad-request"),
            StanzaErrorType::Modify
        );
        assert_eq!(
            stanza_error_type_for_condition("policy-violation"),
            StanzaErrorType::Wait
        );
        assert_eq!(
            stanza_error_type_for_condition("item-not-found"),
            StanzaErrorType::Cancel
        );
    }

    #[test]
    fn renders_simple_and_extended_iq_errors() {
        let err = PubSubError::unsupported("publish");
        let xml = build_iq_error("iq1", "pubsub.example.com", &err);
        let doc = Document::parse(&xml).unwrap();
        let root = doc.root_element();
        assert_eq!(root.attribute("type"), Some("error"));
        assert_eq!(root.attribute("id"), Some("iq1"));
        let error_el = root
            .children()
            .find(|c| c.tag_name().name() == "error")
            .unwrap();
        assert_eq!(error_el.attribute("type"), Some("cancel"));
        let specific = error_el
            .children()
            .find(|c| c.tag_name().name() == "unsupported")
            .unwrap();
        assert_eq!(specific.tag_name().namespace(), Some(NS_PUBSUB_ERRORS));
        assert_eq!(specific.attribute("feature"), Some("publish"));
    }

    #[test]
    fn renders_redirect_with_uri_text() {
        let err = PubSubError::moved("xmpp:pubsub.other.org?;node=new");
        let xml = build_iq_error("iq2", "pubsub.example.com", &err);
        let doc = Document::parse(&xml).unwrap();
        let gone = doc
            .descendants()
            .find(|c| c.tag_name().name() == "gone")
            .unwrap();
        assert_eq!(gone.tag_name().namespace(), Some(NS_STANZAS));
        assert_eq!(gone.text(), Some("xmpp:pubsub.other.org?;node=new"));
    }
}
