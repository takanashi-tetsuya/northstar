//! XEP-0045 Section 10 Room Configuration Form Domain Types, XML Form Generation, and Submission Parsing.

#![forbid(unsafe_code)]

use crate::xml::XmlElement;
use roxmltree::Node;
use std::fmt;
use thiserror::Error;

pub const FORM_TYPE_ROOMCONFIG: &str = "http://jabber.org/protocol/muc#roomconfig";
pub const MAX_ROOM_TITLE_BYTES: usize = 255;
pub const MAX_ROOM_DESC_BYTES: usize = 4096;
pub const MIN_MAX_OCCUPANTS: u32 = 2;
pub const MAX_MAX_OCCUPANTS: u32 = 1000;
pub const DEFAULT_MAX_OCCUPANTS: u32 = 50;

/// Error encountered while parsing or validating a MUC room configuration form.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FormError {
    /// Form is missing required `FORM_TYPE` or contains an unexpected namespace.
    #[error("invalid or missing FORM_TYPE in room configuration form")]
    InvalidFormType,

    /// Form submission type attribute is invalid (must be 'submit', 'form', or omitted).
    #[error("invalid form type attribute")]
    InvalidFormSubmissionType,

    /// Duplicate field variable declared in the submission.
    #[error("duplicate field '{0}' in form submission")]
    DuplicateField(String),

    /// Room title exceeds length bounds (max 255 bytes).
    #[error("room title exceeds 255 bytes limit")]
    TitleTooLong,

    /// Room description exceeds length bounds (max 4096 bytes).
    #[error("room description exceeds 4096 bytes limit")]
    DescriptionTooLong,

    /// Max occupants value is outside acceptable range (2..=1000).
    #[error("max occupants value must be between {MIN_MAX_OCCUPANTS} and {MAX_MAX_OCCUPANTS}")]
    MaxOccupantsOutOfRange,

    /// Boolean field value could not be parsed.
    #[error("invalid boolean value for field '{0}'")]
    InvalidBoolean(String),

    /// Invalid value for whois field (must be 'anyone' or 'moderators').
    #[error("invalid value for muc#roomconfig_whois (expected 'anyone' or 'moderators')")]
    InvalidWhois,

    /// Invalid value for allowpm field (must be 'anyone' or 'none').
    #[error("invalid value for muc#roomconfig_allowpm (expected 'anyone' or 'none')")]
    InvalidAllowPm,

    /// Missing password secret when room is set to password-protected.
    #[error("password-protected room requires a non-empty room secret")]
    MissingPasswordSecret,
}

/// Private message routing policy within a MUC room.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PrivateMessagePolicy {
    /// Anyone can send private messages to other occupants.
    Anyone,
    /// Private messaging through the room is disabled.
    None,
}

impl PrivateMessagePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anyone => "anyone",
            Self::None => "none",
        }
    }

    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "anyone" => Some(Self::Anyone),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Anyone)
    }
}

impl fmt::Display for PrivateMessagePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Strongly typed MUC room configuration parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RoomConfig {
    /// Human-readable title of the room (`muc#roomconfig_roomname`).
    pub title: Option<String>,
    /// Natural language description of the room (`muc#roomconfig_roomdesc`).
    pub description: Option<String>,
    /// Whether the room is persistent after all occupants leave (`muc#roomconfig_persistentroom`).
    pub persistent: bool,
    /// Whether only members/admins/owners can enter (`muc#roomconfig_membersonly`).
    pub members_only: bool,
    /// Whether the room is listed in service discovery directories (`muc#roomconfig_publicroom`).
    pub public: bool,
    /// Whether voice is required to send messages (`muc#roomconfig_moderatedroom`).
    pub moderated: bool,
    /// Whether occupant real bare/full JIDs are visible to anyone (`whois == anyone`).
    pub non_anonymous: bool,
    /// Maximum number of concurrent occupants (`muc#roomconfig_maxusers`).
    pub max_occupants: u32,
    /// Whether a password is required to enter (`muc#roomconfig_passwordprotectedroom`).
    pub password_protected: bool,
    /// Cleartext password supplied during creation/configuration (`muc#roomconfig_roomsecret`).
    pub room_secret: Option<String>,
    /// Whether any occupant may change the subject (`muc#roomconfig_changesubject`).
    pub allow_subject_change: bool,
    /// Whether occupants may invite others (`muc#roomconfig_allowinvites`).
    pub allow_invites: bool,
    /// Private messaging policy (`muc#roomconfig_allowpm`).
    pub allow_private_messages: PrivateMessagePolicy,
    /// Whether message history logging is active (`muc#roomconfig_enablelogging`).
    pub logging_enabled: bool,
    /// Whether users may register nicknames with the room (`muc#roomconfig_allowregister`).
    pub allow_registration: bool,
}

impl Default for RoomConfig {
    fn default() -> Self {
        Self {
            title: None,
            description: None,
            persistent: false,
            members_only: false,
            public: true,
            moderated: false,
            non_anonymous: true,
            max_occupants: DEFAULT_MAX_OCCUPANTS,
            password_protected: false,
            room_secret: None,
            allow_subject_change: true,
            allow_invites: false,
            allow_private_messages: PrivateMessagePolicy::Anyone,
            logging_enabled: true,
            allow_registration: false,
        }
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn xdata_value_field(
    variable: &'static str,
    kind: &'static str,
    value: impl ToString,
) -> XmlElement {
    XmlElement::new("field")
        .attr("var", variable)
        .attr("type", kind)
        .child(XmlElement::new("value").text(value.to_string()).finish())
}

fn xdata_option(value: &'static str, label: Option<&'static str>) -> XmlElement {
    XmlElement::new("option")
        .optional_attr("label", label)
        .child(XmlElement::new("value").text(value).finish())
}

/// Build the XEP-0045 Room Configuration Data Form (`<x xmlns='jabber:x:data' type='form'>`).
pub fn build_room_configuration_form(config: &RoomConfig, fallback_room_name: &str) -> String {
    let whois_value = if config.non_anonymous {
        "anyone"
    } else {
        "moderators"
    };
    let whois_field = xdata_value_field("muc#roomconfig_whois", "list-single", whois_value)
        .child(xdata_option("anyone", Some("Anyone")).finish())
        .child(xdata_option("moderators", Some("Moderators only")).finish())
        .finish();

    let allow_pm_field = xdata_value_field(
        "muc#roomconfig_allowpm",
        "list-single",
        config.allow_private_messages.as_str(),
    )
    .child(xdata_option("anyone", None).finish())
    .child(xdata_option("none", None).finish())
    .finish();

    let mut max_users_field = xdata_value_field(
        "muc#roomconfig_maxusers",
        "list-single",
        config.max_occupants,
    );
    for val in ["10", "20", "50", "100", "500", "1000"] {
        max_users_field.push_child(xdata_option(val, None).finish());
    }

    let form = XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "form")
        .child(XmlElement::new("title").text("Room configuration").finish())
        .child(xdata_value_field("FORM_TYPE", "hidden", FORM_TYPE_ROOMCONFIG).finish())
        .child(
            xdata_value_field(
                "muc#roomconfig_roomname",
                "text-single",
                config.title.as_deref().unwrap_or(fallback_room_name),
            )
            .finish(),
        )
        .child(
            xdata_value_field(
                "muc#roomconfig_roomdesc",
                "text-single",
                config.description.as_deref().unwrap_or_default(),
            )
            .finish(),
        )
        .child(
            xdata_value_field(
                "muc#roomconfig_persistentroom",
                "boolean",
                bool_str(config.persistent),
            )
            .finish(),
        )
        .child(
            xdata_value_field(
                "muc#roomconfig_membersonly",
                "boolean",
                bool_str(config.members_only),
            )
            .finish(),
        )
        .child(
            xdata_value_field(
                "muc#roomconfig_publicroom",
                "boolean",
                bool_str(config.public),
            )
            .finish(),
        )
        .child(
            xdata_value_field(
                "muc#roomconfig_moderatedroom",
                "boolean",
                bool_str(config.moderated),
            )
            .finish(),
        )
        .child(
            xdata_value_field(
                "muc#roomconfig_changesubject",
                "boolean",
                bool_str(config.allow_subject_change),
            )
            .finish(),
        )
        .child(
            xdata_value_field(
                "muc#roomconfig_allowinvites",
                "boolean",
                bool_str(config.allow_invites),
            )
            .finish(),
        )
        .child(allow_pm_field)
        .child(
            xdata_value_field(
                "muc#roomconfig_enablelogging",
                "boolean",
                bool_str(config.logging_enabled),
            )
            .finish(),
        )
        .child(
            xdata_value_field(
                "muc#roomconfig_allowregister",
                "boolean",
                bool_str(config.allow_registration),
            )
            .finish(),
        )
        .child(whois_field)
        .child(max_users_field.finish())
        .child(
            xdata_value_field(
                "muc#roomconfig_passwordprotectedroom",
                "boolean",
                bool_str(config.password_protected),
            )
            .finish(),
        )
        .child(
            xdata_value_field(
                "muc#roomconfig_roomsecret",
                "text-private",
                config.room_secret.as_deref().unwrap_or_default(),
            )
            .finish(),
        )
        .finish();

    XmlElement::namespaced("query", "http://jabber.org/protocol/muc#owner")
        .child(form)
        .finish()
}

fn parse_bool(value: &str, field_name: &str) -> Result<bool, FormError> {
    match value.trim() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(FormError::InvalidBoolean(field_name.to_owned())),
    }
}

/// Parse and validate a submitted XEP-0045 Room Configuration Data Form.
///
/// Fields not present in the submitted form retain their values from `base_config`.
pub fn parse_room_configuration_submit(
    form_node: Node<'_, '_>,
    base_config: &RoomConfig,
) -> Result<RoomConfig, FormError> {
    if form_node.tag_name().name() != "x"
        || form_node.tag_name().namespace() != Some("jabber:x:data")
    {
        return Err(FormError::InvalidFormType);
    }
    if !matches!(
        form_node.attribute("type"),
        None | Some("submit") | Some("form")
    ) {
        return Err(FormError::InvalidFormSubmissionType);
    }

    let mut seen_fields = std::collections::HashSet::new();
    let mut field_values = std::collections::HashMap::new();

    for field in form_node
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "field")
    {
        let Some(var) = field.attribute("var") else {
            continue;
        };
        if !seen_fields.insert(var) {
            return Err(FormError::DuplicateField(var.to_owned()));
        }
        let val = field
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "value")
            .and_then(|n| n.text())
            .unwrap_or_default();
        field_values.insert(var, val);
    }

    if let Some(form_type) = field_values.get("FORM_TYPE") {
        if *form_type != FORM_TYPE_ROOMCONFIG {
            return Err(FormError::InvalidFormType);
        }
    }

    let mut result = base_config.clone();

    if let Some(title_val) = field_values.get("muc#roomconfig_roomname") {
        let trimmed = title_val.trim();
        if trimmed.len() > MAX_ROOM_TITLE_BYTES {
            return Err(FormError::TitleTooLong);
        }
        result.title = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        };
    }

    if let Some(desc_val) = field_values.get("muc#roomconfig_roomdesc") {
        let trimmed = desc_val.trim();
        if trimmed.len() > MAX_ROOM_DESC_BYTES {
            return Err(FormError::DescriptionTooLong);
        }
        result.description = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        };
    }

    if let Some(val) = field_values.get("muc#roomconfig_persistentroom") {
        result.persistent = parse_bool(val, "muc#roomconfig_persistentroom")?;
    }
    if let Some(val) = field_values.get("muc#roomconfig_membersonly") {
        result.members_only = parse_bool(val, "muc#roomconfig_membersonly")?;
    }
    if let Some(val) = field_values.get("muc#roomconfig_publicroom") {
        result.public = parse_bool(val, "muc#roomconfig_publicroom")?;
    }
    if let Some(val) = field_values.get("muc#roomconfig_moderatedroom") {
        result.moderated = parse_bool(val, "muc#roomconfig_moderatedroom")?;
    }
    if let Some(val) = field_values.get("muc#roomconfig_changesubject") {
        result.allow_subject_change = parse_bool(val, "muc#roomconfig_changesubject")?;
    }
    if let Some(val) = field_values.get("muc#roomconfig_allowinvites") {
        result.allow_invites = parse_bool(val, "muc#roomconfig_allowinvites")?;
    }
    if let Some(val) = field_values.get("muc#roomconfig_enablelogging") {
        result.logging_enabled = parse_bool(val, "muc#roomconfig_enablelogging")?;
    }
    if let Some(val) = field_values.get("muc#roomconfig_allowregister") {
        result.allow_registration = parse_bool(val, "muc#roomconfig_allowregister")?;
    }

    if let Some(val) = field_values.get("muc#roomconfig_whois") {
        match *val {
            "anyone" => result.non_anonymous = true,
            "moderators" => result.non_anonymous = false,
            _ => return Err(FormError::InvalidWhois),
        }
    }

    if let Some(val) = field_values.get("muc#roomconfig_allowpm") {
        match *val {
            "anyone" => result.allow_private_messages = PrivateMessagePolicy::Anyone,
            "none" => result.allow_private_messages = PrivateMessagePolicy::None,
            _ => return Err(FormError::InvalidAllowPm),
        }
    }

    if let Some(val) = field_values.get("muc#roomconfig_maxusers") {
        match val.trim().parse::<u32>() {
            Ok(count) if (MIN_MAX_OCCUPANTS..=MAX_MAX_OCCUPANTS).contains(&count) => {
                result.max_occupants = count;
            }
            _ => return Err(FormError::MaxOccupantsOutOfRange),
        }
    }

    if let Some(val) = field_values.get("muc#roomconfig_passwordprotectedroom") {
        result.password_protected = parse_bool(val, "muc#roomconfig_passwordprotectedroom")?;
    }

    if let Some(val) = field_values.get("muc#roomconfig_roomsecret") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            result.room_secret = Some(trimmed.to_owned());
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn test_build_and_parse_form_roundtrip() {
        let initial_config = RoomConfig {
            title: Some("My Super Room".to_owned()),
            description: Some("Discussion about protocol separation".to_owned()),
            persistent: true,
            members_only: true,
            public: false,
            moderated: true,
            non_anonymous: false,
            max_occupants: 100,
            password_protected: true,
            room_secret: Some("secret123".to_owned()),
            allow_subject_change: false,
            allow_invites: true,
            allow_private_messages: PrivateMessagePolicy::None,
            logging_enabled: false,
            allow_registration: true,
        };

        let xml = build_room_configuration_form(&initial_config, "super-room");
        assert!(xml.contains("http://jabber.org/protocol/muc#owner"));
        assert!(xml.contains("http://jabber.org/protocol/muc#roomconfig"));

        let doc = Document::parse(&xml).unwrap();
        let query_node = doc.root_element();
        let form_node = query_node
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "x")
            .unwrap();

        let parsed = parse_room_configuration_submit(form_node, &RoomConfig::default()).unwrap();
        assert_eq!(parsed.title, Some("My Super Room".to_owned()));
        assert_eq!(
            parsed.description,
            Some("Discussion about protocol separation".to_owned())
        );
        assert!(parsed.persistent);
        assert!(parsed.members_only);
        assert!(!parsed.public);
        assert!(parsed.moderated);
        assert!(!parsed.non_anonymous);
        assert_eq!(parsed.max_occupants, 100);
        assert!(parsed.password_protected);
        assert_eq!(parsed.room_secret, Some("secret123".to_owned()));
        assert!(!parsed.allow_subject_change);
        assert!(parsed.allow_invites);
        assert_eq!(parsed.allow_private_messages, PrivateMessagePolicy::None);
        assert!(!parsed.logging_enabled);
        assert!(parsed.allow_registration);
    }

    #[test]
    fn test_validation_bounds() {
        let long_title = "a".repeat(256);
        let xml = format!(
            "<x xmlns='jabber:x:data' type='submit'>\
                <field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>\
                <field var='muc#roomconfig_roomname'><value>{long_title}</value></field>\
            </x>"
        );
        let doc = Document::parse(&xml).unwrap();
        assert_eq!(
            parse_room_configuration_submit(doc.root_element(), &RoomConfig::default()),
            Err(FormError::TitleTooLong)
        );

        let invalid_max = "<x xmlns='jabber:x:data' type='submit'>\
            <field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>\
            <field var='muc#roomconfig_maxusers'><value>1001</value></field>\
        </x>";
        let doc = Document::parse(invalid_max).unwrap();
        assert_eq!(
            parse_room_configuration_submit(doc.root_element(), &RoomConfig::default()),
            Err(FormError::MaxOccupantsOutOfRange)
        );
    }
}
