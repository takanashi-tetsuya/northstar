//! XEP-0388 requests and the wire forms of their outcomes.

use anyhow::Result;
use northstar_auth_core as auth;
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use uuid::{Uuid, Variant};
use zeroize::Zeroizing;

mod parsing;

pub use self::parsing::*;

pub const SASL2_NS: &str = "urn:xmpp:sasl:2";
pub const BIND2_NS: &str = "urn:xmpp:bind:0";
pub const FAST_NS: &str = "urn:xmpp:fast:0";

#[derive(Clone, Debug, Default)]
pub struct Bind2Request {
    pub tag: Option<String>,
    pub carbons: bool,
    pub sm: Option<SmInlineRequest>,
    pub csi_active: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct SmInlineRequest {
    pub resume: bool,
    pub max: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct FastRequest {
    /// XEP-0484 requires a monotonically increasing count only for TLS 0-RTT.
    /// Northstar does not advertise or accept early data, so ordinary FAST
    /// clients may omit it. A supplied value is still enforced atomically.
    pub count: Option<i64>,
    pub invalidate: bool,
}

pub struct SmResumeRequest {
    pub previd: Zeroizing<String>,
    pub h: u32,
}

pub struct Sasl2Request {
    pub mechanism: String,
    pub initial_response: Option<Zeroizing<String>>,
    pub user_agent_id: Option<Uuid>,
    pub bind: Option<Bind2Request>,
    pub request_token: Option<String>,
    pub fast: Option<FastRequest>,
    pub resume: Option<SmResumeRequest>,
}

pub struct Sasl2Context {
    pub request: Sasl2Request,
    pub fast_should_rotate: bool,
    pub awaiting_initial_response: bool,
    pub fast_token_id: Option<Uuid>,
    pub fast_token_was_new: bool,
    pub fast_invalidate: bool,
    pub authenticated_generation: Option<i64>,
    pub inherited_fast_chain:
        Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
}

impl std::fmt::Debug for SmResumeRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmResumeRequest")
            .field("previd", &"[REDACTED]")
            .field("h", &self.h)
            .finish()
    }
}

impl std::fmt::Debug for Sasl2Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sasl2Request")
            .field("mechanism", &self.mechanism)
            .field(
                "initial_response",
                &self.initial_response.as_ref().map(|_| "[REDACTED]"),
            )
            .field("user_agent_id", &self.user_agent_id)
            .field("bind", &self.bind)
            .field("request_token", &self.request_token)
            .field("fast", &self.fast)
            .field("resume", &self.resume)
            .finish()
    }
}

impl std::fmt::Debug for Sasl2Context {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sasl2Context")
            .field("request", &self.request)
            .field("fast_should_rotate", &self.fast_should_rotate)
            .field("awaiting_initial_response", &self.awaiting_initial_response)
            .field("fast_token_id", &self.fast_token_id.map(|_| "[REDACTED]"))
            .field("fast_token_was_new", &self.fast_token_was_new)
            .field("fast_invalidate", &self.fast_invalidate)
            .field("authenticated_generation", &self.authenticated_generation)
            .field("inherited_fast_chain", &self.inherited_fast_chain)
            .finish()
    }
}

/// Test-only access to the production success builder, with no bearer or
/// additional-data extension admitted by the closed Stage4 profile.
#[cfg(any(test, feature = "test-support"))]
pub fn stage4_saved_success_xml(authorization_identifier: &str) -> Result<String> {
    sasl2_success_xml(None, authorization_identifier, &[])
}

pub fn failure_xml(condition: &str, text: Option<&str>) -> String {
    let condition = XmlElement::dynamic(condition)
        .expect("SASL error condition must be a valid QName")
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-sasl");
    let mut failure = XmlElement::namespaced("failure", SASL2_NS).child(condition);
    if let Some(text) = text {
        failure.push_child(XmlElement::new("text").text(text.to_owned()));
    }
    failure.finish()
}

pub fn fast_token_xml(
    issued: &northstar_auth_application::authentication::IssuedFastToken,
) -> String {
    XmlElement::namespaced("token", FAST_NS)
        .attr(
            "expiry",
            issued
                .expires_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )
        .attr("token", issued.token.as_str())
        .finish()
}

pub fn sasl2_success_xml(
    additional_data: Option<&[u8]>,
    authorization_identifier: &str,
    extension_fragments: &[&str],
) -> Result<String> {
    use base64::Engine;

    let mut success = XmlElement::namespaced("success", SASL2_NS);
    if let Some(data) = additional_data.filter(|data| !data.is_empty()) {
        success.push_child(
            XmlElement::new("additional-data")
                .text(base64::engine::general_purpose::STANDARD.encode(data)),
        );
    }
    success.push_child(
        XmlElement::new("authorization-identifier").text(authorization_identifier.to_owned()),
    );
    for fragment in extension_fragments
        .iter()
        .copied()
        .filter(|fragment| !fragment.is_empty())
    {
        success.push_validated_fragment(fragment)?;
    }
    Ok(success.finish())
}

pub fn inline_resume_envelope_reservation_bytes(
    additional_data: Option<&[u8]>,
    authorization_identifier: &str,
    resumed_control: &str,
    token_xml: &str,
    features: &String,
) -> Option<usize> {
    // XML text escaping expands one UTF-8 byte by at most six bytes. Standard
    // Base64 is exactly four bytes per three-byte block. The fixed allowance
    // covers element names/namespaces and String growth; multiplying the
    // serialized upper bound by four also dominates allocator capacity
    // rounding before the actual capacity is verified by ResumePayload.
    let encoded = match additional_data.filter(|data| !data.is_empty()) {
        Some(data) => data.len().checked_add(2)?.checked_div(3)?.checked_mul(4)?,
        None => 0,
    };
    let serialized_upper = 4_096usize
        .checked_add(authorization_identifier.len().checked_mul(6)?)?
        .checked_add(encoded)?
        .checked_add(resumed_control.len())?
        .checked_add(token_xml.len())?;
    serialized_upper
        .checked_mul(4)?
        .checked_add(std::mem::size_of::<String>())?
        .checked_add(features.capacity())
}

#[cfg(test)]
mod tests;
