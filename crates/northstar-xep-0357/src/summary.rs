//! Strict parsing, validation, and XML generation for `urn:xmpp:push:summary` data forms.

use crate::constants::{MAX_FORM_FIELDS, MAX_VALUE_BYTES, XMLNS_DATA, XMLNS_PUSH, XMLNS_SUMMARY};
use crate::error::PushError;
use crate::xml::XmlElement;
use northstar_xmpp_types::CanonicalJid;
use roxmltree::Node;
use std::collections::HashSet;

/// Parsed typed representation of an XEP-0357 push notification summary (`urn:xmpp:push:summary`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PushSummary {
    /// Number of unread or offline messages for the recipient.
    pub message_count: Option<u64>,
    /// Number of pending presence subscription requests for the recipient.
    pub pending_subscription_count: Option<u64>,
    /// JID of the sender of the triggering message (only when authorized by disclosure policy).
    pub last_message_sender: Option<CanonicalJid>,
    /// Body snippet of the triggering message (only when authorized by disclosure policy).
    pub last_message_body: Option<String>,
    /// Additional extension fields in the summary form.
    pub additional_fields: Vec<(String, String)>,
}

impl PushSummary {
    /// Create an empty summary.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set message count.
    pub fn with_message_count(mut self, count: u64) -> Self {
        self.message_count = Some(count);
        self
    }

    /// Set pending presence subscription count.
    pub fn with_pending_subscription_count(mut self, count: u64) -> Self {
        self.pending_subscription_count = Some(count);
        self
    }

    /// Set last message sender.
    pub fn with_last_message_sender(mut self, sender: CanonicalJid) -> Self {
        self.last_message_sender = Some(sender);
        self
    }

    /// Set last message body snippet.
    pub fn with_last_message_body(mut self, body: impl Into<String>) -> Self {
        self.last_message_body = Some(body.into());
        self
    }

    /// Add an additional field.
    pub fn with_additional_field(
        mut self,
        var: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.additional_fields.push((var.into(), value.into()));
        self
    }

    /// Parse a summary from an `<x xmlns='jabber:x:data' type='form'>` XML node.
    pub fn parse(form: Node<'_, '_>) -> Result<Self, PushError> {
        if form.tag_name().name() != "x" {
            return Err(PushError::UnexpectedTagName {
                expected: "x",
                actual: form.tag_name().name().to_owned(),
            });
        }
        if form.tag_name().namespace() != Some(XMLNS_DATA) {
            return Err(PushError::UnexpectedNamespace {
                expected: XMLNS_DATA,
                actual: form.tag_name().namespace().unwrap_or("").to_owned(),
            });
        }
        if form.attribute("type") != Some("form") {
            return Err(PushError::InvalidSummary(
                "summary x data form type must be 'form'".to_owned(),
            ));
        }

        let field_nodes: Vec<_> = form.children().filter(|c| c.is_element()).collect();
        if field_nodes.is_empty() {
            return Err(PushError::InvalidSummary(
                "summary data form contains no fields".to_owned(),
            ));
        }
        if field_nodes.len() > MAX_FORM_FIELDS {
            return Err(PushError::InvalidSummary(format!(
                "summary field count {} exceeds maximum {}",
                field_nodes.len(),
                MAX_FORM_FIELDS
            )));
        }

        let mut seen = HashSet::new();
        let mut form_type_found = false;
        let mut message_count = None;
        let mut pending_subscription_count = None;
        let mut last_message_sender = None;
        let mut last_message_body = None;
        let mut additional_fields = Vec::new();

        for field_node in field_nodes {
            if field_node.tag_name().name() != "field"
                || field_node.tag_name().namespace() != Some(XMLNS_DATA)
            {
                return Err(PushError::InvalidSummary(
                    "expected <field xmlns='jabber:x:data'> in summary form".to_owned(),
                ));
            }

            let var = field_node.attribute("var").ok_or_else(|| {
                PushError::InvalidSummary("field is missing 'var' attribute".to_owned())
            })?;

            if !seen.insert(var.to_owned()) {
                return Err(PushError::InvalidSummary(format!(
                    "duplicate field var '{var}' in summary form"
                )));
            }

            let value_nodes: Vec<_> = field_node
                .children()
                .filter(|c| c.is_element() && c.tag_name().name() == "value")
                .collect();
            let first_val = value_nodes.first().and_then(|v| v.text()).unwrap_or("");

            match var {
                "FORM_TYPE" => {
                    if first_val.trim() != XMLNS_SUMMARY {
                        return Err(PushError::InvalidSummary(format!(
                            "FORM_TYPE must be '{XMLNS_SUMMARY}', got '{first_val}'"
                        )));
                    }
                    form_type_found = true;
                }
                "message-count" => {
                    let count = first_val.trim().parse::<u64>().map_err(|_| {
                        PushError::InvalidSummary(format!(
                            "invalid non-negative integer for message-count: '{first_val}'"
                        ))
                    })?;
                    message_count = Some(count);
                }
                "pending-subscription-count" => {
                    let count = first_val.trim().parse::<u64>().map_err(|_| {
                        PushError::InvalidSummary(format!(
                            "invalid non-negative integer for pending-subscription-count: '{first_val}'"
                        ))
                    })?;
                    pending_subscription_count = Some(count);
                }
                "last-message-sender" => {
                    let jid = CanonicalJid::parse(first_val.trim()).map_err(|e| {
                        PushError::JidMalformed(format!(
                            "invalid JID for last-message-sender '{first_val}': {e}"
                        ))
                    })?;
                    last_message_sender = Some(jid);
                }
                "last-message-body" => {
                    if first_val.len() > MAX_VALUE_BYTES {
                        return Err(PushError::InvalidSummary(format!(
                            "last-message-body byte length {} exceeds maximum {}",
                            first_val.len(),
                            MAX_VALUE_BYTES
                        )));
                    }
                    last_message_body = Some(first_val.to_owned());
                }
                other => {
                    additional_fields.push((other.to_owned(), first_val.to_owned()));
                }
            }
        }

        if !form_type_found {
            return Err(PushError::InvalidSummary(
                "summary form is missing FORM_TYPE field".to_owned(),
            ));
        }

        Ok(Self {
            message_count,
            pending_subscription_count,
            last_message_sender,
            last_message_body,
            additional_fields,
        })
    }

    /// Parse a summary from an XML string.
    pub fn parse_xml(xml: &str) -> Result<Self, PushError> {
        let doc =
            roxmltree::Document::parse(xml).map_err(|e| PushError::XmlParse(e.to_string()))?;
        Self::parse(doc.root_element())
    }

    /// Parse a `<notification xmlns='urn:xmpp:push:0'>` container node and extract the inner summary.
    pub fn parse_notification(notification_node: Node<'_, '_>) -> Result<Self, PushError> {
        if notification_node.tag_name().name() != "notification" {
            return Err(PushError::UnexpectedTagName {
                expected: "notification",
                actual: notification_node.tag_name().name().to_owned(),
            });
        }
        if notification_node.tag_name().namespace() != Some(XMLNS_PUSH) {
            return Err(PushError::UnexpectedNamespace {
                expected: XMLNS_PUSH,
                actual: notification_node
                    .tag_name()
                    .namespace()
                    .unwrap_or("")
                    .to_owned(),
            });
        }

        let form_node = notification_node
            .children()
            .find(|c| c.is_element() && c.tag_name().name() == "x")
            .ok_or_else(|| {
                PushError::InvalidSummary(
                    "notification element is missing inner <x> form".to_owned(),
                )
            })?;

        Self::parse(form_node)
    }

    /// Serialize summary to an `<x xmlns='jabber:x:data' type='form'>` element XML string.
    pub fn to_data_form_xml(&self) -> String {
        let mut form = XmlElement::namespaced("x", XMLNS_DATA).attr("type", "form");

        // FORM_TYPE hidden field
        form.push_child(
            XmlElement::new("field")
                .attr("var", "FORM_TYPE")
                .attr("type", "hidden")
                .child(XmlElement::new("value").text(XMLNS_SUMMARY)),
        );

        if let Some(count) = self.message_count {
            form.push_child(
                XmlElement::new("field")
                    .attr("var", "message-count")
                    .attr("type", "text-single")
                    .child(XmlElement::new("value").text(count)),
            );
        }

        if let Some(count) = self.pending_subscription_count {
            form.push_child(
                XmlElement::new("field")
                    .attr("var", "pending-subscription-count")
                    .attr("type", "text-single")
                    .child(XmlElement::new("value").text(count)),
            );
        }

        if let Some(ref sender) = self.last_message_sender {
            form.push_child(
                XmlElement::new("field")
                    .attr("var", "last-message-sender")
                    .attr("type", "jid-single")
                    .child(XmlElement::new("value").text(sender.to_string())),
            );
        }

        if let Some(ref body) = self.last_message_body {
            form.push_child(
                XmlElement::new("field")
                    .attr("var", "last-message-body")
                    .attr("type", "text-single")
                    .child(XmlElement::new("value").text(body)),
            );
        }

        for (var, val) in &self.additional_fields {
            form.push_child(
                XmlElement::new("field")
                    .attr("var", var)
                    .attr("type", "text-single")
                    .child(XmlElement::new("value").text(val)),
            );
        }

        form.finish()
    }

    /// Serialize summary wrapped inside `<notification xmlns='urn:xmpp:push:0'>`.
    pub fn to_notification_xml(&self) -> String {
        let form_xml = self.to_data_form_xml();
        let mut notification = XmlElement::namespaced("notification", XMLNS_PUSH);
        notification.push_raw_fragment(form_xml);
        notification.finish()
    }
}
