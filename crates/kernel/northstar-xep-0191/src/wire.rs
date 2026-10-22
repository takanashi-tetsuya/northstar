//! Strict and bounded parsing of XEP-0191 command payloads.

use crate::constants::{MAX_ITEMS, NAMESPACE};
use crate::error::BlockingError;
use crate::model::{BlockPattern, BlockingCommand, BlockingMutation, BlockingSnapshot};
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Node;
use std::collections::HashSet;

pub fn parse_blocklist(node: Node<'_, '_>) -> Result<BlockingCommand, BlockingError> {
    ensure_command(node, "blocklist")?;
    ensure_empty_command(node)?;
    Ok(BlockingCommand::GetBlocklist)
}

/// Parse the payload of a successful blocklist query.
pub fn parse_blocklist_result(node: Node<'_, '_>) -> Result<BlockingSnapshot, BlockingError> {
    ensure_command(node, "blocklist")?;
    parse_items(node).map(BlockingSnapshot::new)
}

pub fn parse_block(node: Node<'_, '_>) -> Result<BlockingCommand, BlockingError> {
    ensure_command(node, "block")?;
    let items = parse_items(node)?;
    if items.is_empty() {
        return Err(BlockingError::EmptyBlock);
    }
    Ok(BlockingCommand::Mutate(BlockingMutation::Block(items)))
}

pub fn parse_unblock(node: Node<'_, '_>) -> Result<BlockingCommand, BlockingError> {
    ensure_command(node, "unblock")?;
    let items = parse_items(node)?;
    if items.is_empty() {
        Ok(BlockingCommand::Mutate(BlockingMutation::UnblockAll))
    } else {
        Ok(BlockingCommand::Mutate(BlockingMutation::Unblock(items)))
    }
}

pub fn parse_iq(root: Node<'_, '_>) -> Result<BlockingCommand, BlockingError> {
    if !root.is_element() || root.tag_name().name() != "iq" {
        return Err(BlockingError::NotIq);
    }
    if root.attribute("to").is_some() {
        return Err(BlockingError::ExplicitIqTarget);
    }
    let payloads = root
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if payloads.len() != 1 {
        return Err(BlockingError::AmbiguousIqPayload);
    }
    if payloads[0].tag_name().namespace() != Some(NAMESPACE) {
        return Err(BlockingError::AmbiguousIqPayload);
    }
    match (root.attribute("type"), payloads[0].tag_name().name()) {
        (Some("get"), "blocklist") => parse_blocklist(payloads[0]),
        (Some("set"), "block") => parse_block(payloads[0]),
        (Some("set"), "unblock") => parse_unblock(payloads[0]),
        _ => Err(BlockingError::WrongIqType),
    }
}

fn ensure_command(node: Node<'_, '_>, name: &str) -> Result<(), BlockingError> {
    if !node.is_element()
        || node.tag_name().namespace() != Some(NAMESPACE)
        || node.tag_name().name() != name
    {
        let found = if node.is_element() {
            node.tag_name().name().to_owned()
        } else {
            "#non-element".to_owned()
        };
        return Err(BlockingError::UnexpectedElement(found));
    }
    Ok(())
}

fn ensure_empty_command(node: Node<'_, '_>) -> Result<(), BlockingError> {
    if node.attributes().len() != 0
        || node.children().any(|child| {
            child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err(BlockingError::InvalidCommandShape);
    }
    Ok(())
}

fn parse_items(node: Node<'_, '_>) -> Result<Vec<BlockPattern>, BlockingError> {
    if node.attributes().len() != 0
        || node.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err(BlockingError::InvalidCommandShape);
    }

    let children = node
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if children.len() > MAX_ITEMS {
        return Err(BlockingError::TooManyItems { limit: MAX_ITEMS });
    }

    let mut seen = HashSet::with_capacity(children.len());
    let mut items = Vec::with_capacity(children.len());
    for item in children {
        if item.tag_name().name() != "item" || item.tag_name().namespace() != Some(NAMESPACE) {
            return Err(BlockingError::UnexpectedChild);
        }
        if item.attributes().len() != 1
            || item
                .attributes()
                .any(|attribute| attribute.namespace().is_some() || attribute.name() != "jid")
            || item.children().next().is_some()
        {
            return Err(BlockingError::InvalidItemShape);
        }
        let raw = item.attribute("jid").unwrap_or_default();
        let jid =
            CanonicalJid::parse(raw).map_err(|_| BlockingError::InvalidJid(raw.to_owned()))?;
        let canonical = jid.to_string();
        if seen.insert(canonical) {
            items.push(BlockPattern::new(jid));
        }
    }
    Ok(items)
}
