//! PEP form values and configuration decisions shared by ingress and storage.

use crate::{default_pep_node_config, PepNodeConfig, PEP_MAX_ITEMS};

use pep_nodes::*;

/// PEP node names that carry node-specific form and payload rules.
pub mod pep_nodes {
    pub const OMEMO_DEVICES: &str = "urn:xmpp:omemo:2:devices";
    pub const OMEMO_BUNDLES: &str = "urn:xmpp:omemo:2:bundles";
    pub const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
    pub const AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";
    pub const VCARD4: &str = "urn:xmpp:vcard4";
    pub const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
    pub const CONTACTS: &str = "urn:xmpp:contacts";
    pub const LEGACY_BOOKMARKS: &str = "storage:bookmarks";
}

/// Only fields supplied by a submitted form.
#[derive(Debug, Default)]
pub struct PepConfigPatch {
    pub access_model: Option<String>,
    pub max_items: Option<PepMaxItems>,
    pub persist_items: Option<bool>,
    pub send_last_published_item: Option<String>,
    pub deliver_notifications: Option<bool>,
    pub roster_groups_allowed: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepMaxItems {
    Max,
    Count(i64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PepFormRejection;

#[derive(Debug)]
pub struct PepRequestedConfig {
    pub config: PepNodeConfig,
    pub explicit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepPublishConfigRejection {
    PreconditionNotMet,
    MaxItemsExceeded,
}

/// Validate submitted values and leave omitted fields at their base values.
pub fn apply_pep_config_patch(
    base: &PepNodeConfig,
    patch: &PepConfigPatch,
) -> Result<PepNodeConfig, PepFormRejection> {
    let mut config = base.clone();
    if let Some(value) = &patch.access_model {
        if !matches!(value.as_str(), "open" | "presence" | "roster" | "whitelist") {
            return Err(PepFormRejection);
        }
        config.access_model.clone_from(value);
    }
    if let Some(value) = patch.max_items {
        config.max_items = match value {
            PepMaxItems::Max => PEP_MAX_ITEMS,
            PepMaxItems::Count(count) => i32::try_from(count)
                .ok()
                .filter(|count| (1..=PEP_MAX_ITEMS).contains(count))
                .ok_or(PepFormRejection)?,
        };
    }
    if let Some(value) = patch.persist_items {
        config.persist_items = value;
    }
    if let Some(value) = &patch.send_last_published_item {
        if !matches!(value.as_str(), "never" | "on_sub" | "on_sub_and_presence") {
            return Err(PepFormRejection);
        }
        config.send_last_published_item.clone_from(value);
    }
    if let Some(value) = patch.deliver_notifications {
        config.deliver_notifications = value;
    }
    if let Some(values) = &patch.roster_groups_allowed {
        if !(1..=100).contains(&values.len())
            || values.iter().any(|value| !(1..=128).contains(&value.len()))
        {
            return Err(PepFormRejection);
        }
        config.roster_groups_allowed.clone_from(values);
    }
    Ok(config)
}

/// Validate the special-node requirements for explicit publish options.
pub fn pep_publish_options_policy(
    node: &str,
    config: &PepNodeConfig,
) -> Result<(), PepFormRejection> {
    validate_public_nodes(node, config)?;
    if matches!(node, BOOKMARKS2 | CONTACTS | LEGACY_BOOKMARKS)
        && (config.access_model != "whitelist"
            || !config.persist_items
            || config.send_last_published_item != "never")
    {
        return Err(PepFormRejection);
    }
    Ok(())
}

/// Validate the special-node requirements for an owner configuration change.
pub fn pep_owner_config_policy(node: &str, config: &PepNodeConfig) -> Result<(), PepFormRejection> {
    validate_public_nodes(node, config)?;
    if matches!(node, BOOKMARKS2 | CONTACTS | LEGACY_BOOKMARKS)
        && config.access_model != "whitelist"
    {
        return Err(PepFormRejection);
    }
    Ok(())
}

fn validate_public_nodes(node: &str, config: &PepNodeConfig) -> Result<(), PepFormRejection> {
    let max_items = match node {
        OMEMO_DEVICES | AVATAR_METADATA | VCARD4 => Some(1),
        OMEMO_BUNDLES => Some(PEP_MAX_ITEMS),
        AVATAR_DATA => None,
        _ => return Ok(()),
    };
    if config.access_model != "open"
        || !config.persist_items
        || max_items.is_some_and(|max| config.max_items != max)
    {
        return Err(PepFormRejection);
    }
    Ok(())
}

/// Resolve publish options from node defaults and record whether a form was supplied.
pub fn requested_pep_publish_config(
    node: &str,
    patch: Option<&PepConfigPatch>,
) -> Result<PepRequestedConfig, PepFormRejection> {
    let defaults = default_pep_node_config(node);
    let Some(patch) = patch else {
        return Ok(PepRequestedConfig {
            config: defaults,
            explicit: false,
        });
    };
    let config = apply_pep_config_patch(&defaults, patch)?;
    pep_publish_options_policy(node, &config)?;
    Ok(PepRequestedConfig {
        config,
        explicit: true,
    })
}

/// Check explicit preconditions before the limit of the effective configuration.
pub fn pep_publish_config_decision(
    requested: &PepNodeConfig,
    explicit: bool,
    actual: Option<&PepNodeConfig>,
    item_count: usize,
) -> Option<PepPublishConfigRejection> {
    if explicit && actual.is_some_and(|config| config != requested) {
        return Some(PepPublishConfigRejection::PreconditionNotMet);
    }
    (item_count > actual.unwrap_or(requested).max_items as usize)
        .then_some(PepPublishConfigRejection::MaxItemsExceeded)
}

#[cfg(test)]
mod tests;
