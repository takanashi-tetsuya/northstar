//! Strict, bounded parsing of direct XEP-0359 message children.

use crate::constants::{MAX_ID_BYTES, MAX_ID_ELEMENTS, NAMESPACE};
use crate::error::SidError;
use crate::model::{MessageIds, OriginId, ReferencedStanza, StableId, StanzaId};
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Node;
use std::collections::HashSet;

pub fn validate_id(value: &str) -> Result<StableId<'_>, SidError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        return Err(SidError::InvalidId {
            limit: MAX_ID_BYTES,
        });
    }
    Ok(StableId::new_validated(value))
}

fn validate_empty_content(node: Node<'_, '_>) -> Result<(), SidError> {
    if node.children().any(|child| child.is_element())
        || node.text().is_some_and(|text| !text.trim().is_empty())
    {
        return Err(SidError::ElementHasContent);
    }
    Ok(())
}

fn validate_attributes(node: Node<'_, '_>, allowed: &[&str]) -> Result<(), SidError> {
    if node
        .attributes()
        .any(|attribute| attribute.namespace().is_some() || !allowed.contains(&attribute.name()))
    {
        return Err(SidError::UnexpectedAttribute);
    }
    Ok(())
}

fn parse_issuer(raw: &str) -> Result<CanonicalJid, SidError> {
    CanonicalJid::parse(raw).map_err(|_| SidError::InvalidIssuer(raw.to_owned()))
}

pub fn parse_origin_id<'a, 'input>(node: Node<'a, 'input>) -> Result<OriginId<'a>, SidError> {
    ensure_element(node, "origin-id")?;
    validate_empty_content(node)?;
    if node.attribute("by").is_some() {
        return Err(SidError::OriginHasBy);
    }
    validate_attributes(node, &["id"])?;
    let id = validate_id(node.attribute("id").ok_or(SidError::MissingId)?)?;
    Ok(OriginId { id })
}

pub fn parse_stanza_id<'a, 'input>(node: Node<'a, 'input>) -> Result<StanzaId<'a>, SidError> {
    ensure_element(node, "stanza-id")?;
    validate_empty_content(node)?;
    validate_attributes(node, &["id", "by"])?;
    let id = validate_id(node.attribute("id").ok_or(SidError::MissingId)?)?;
    let raw_by = node.attribute("by").ok_or(SidError::MissingBy)?;
    Ok(StanzaId {
        id,
        by: parse_issuer(raw_by)?,
    })
}

pub fn parse_referenced_stanza<'a, 'input>(
    node: Node<'a, 'input>,
) -> Result<ReferencedStanza<'a>, SidError> {
    ensure_element(node, "referenced-stanza")?;
    validate_empty_content(node)?;
    validate_attributes(node, &["id", "by"])?;
    let id = validate_id(node.attribute("id").ok_or(SidError::MissingId)?)?;
    let by = node.attribute("by").map(parse_issuer).transpose()?;
    Ok(ReferencedStanza { id, by })
}

fn ensure_element(node: Node<'_, '_>, expected: &str) -> Result<(), SidError> {
    if !node.is_element()
        || node.tag_name().namespace() != Some(NAMESPACE)
        || node.tag_name().name() != expected
    {
        let found = if node.is_element() {
            node.tag_name().name().to_owned()
        } else {
            "#non-element".to_owned()
        };
        return Err(SidError::UnexpectedElement(found));
    }
    Ok(())
}

pub fn parse_message<'a, 'input>(root: Node<'a, 'input>) -> Result<MessageIds<'a>, SidError> {
    if !root.is_element() || root.tag_name().name() != "message" {
        return Err(SidError::NotMessage);
    }

    let sid_children = root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
        .collect::<Vec<_>>();
    if sid_children.len() > MAX_ID_ELEMENTS {
        return Err(SidError::TooManyElements {
            limit: MAX_ID_ELEMENTS,
        });
    }

    let mut result = MessageIds::default();
    let mut issuers = HashSet::new();
    for child in sid_children {
        match child.tag_name().name() {
            "origin-id" => {
                if result.origin.is_some() {
                    return Err(SidError::DuplicateOriginId);
                }
                result.origin = Some(parse_origin_id(child)?);
            }
            "stanza-id" => {
                let stanza_id = parse_stanza_id(child)?;
                let issuer = stanza_id.by.to_string();
                if !issuers.insert(issuer.clone()) {
                    return Err(SidError::DuplicateIssuer(issuer));
                }
                result.stanza_ids.push(stanza_id);
            }
            "referenced-stanza" => result.references.push(parse_referenced_stanza(child)?),
            _ => result.unknown_sid_children += 1,
        }
    }
    Ok(result)
}
