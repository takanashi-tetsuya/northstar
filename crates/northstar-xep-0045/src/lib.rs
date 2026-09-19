//! Capability-free XEP-0045 Multi-User Chat protocol types, permission evaluation, validation, and XML builders.
//!
//! This crate contains transport-neutral, capability-free domain models and pure
//! logic for XEP-0045 Multi-User Chat (MUC). It deliberately has no runtime,
//! database, Redis, network, HTTP, or global state dependencies.

#![forbid(unsafe_code)]

pub mod address;
pub mod admin;
pub mod affiliation;
pub mod form;
pub mod message;
pub mod permissions;
pub mod presence;
pub mod role;
pub mod status_code;
pub mod transitions;
pub mod xml;

pub use address::{
    is_valid_occupant_nick, is_valid_room_name, occupant_key, AddressError, MucOccupantJid,
    MucRoomJid, OccupantNick, RoomName, MAX_OCCUPANT_NICK_BYTES, MAX_ROOM_NAME_BYTES,
};
pub use admin::{
    build_admin_query_result, build_owner_destroy, build_voice_approval_form,
    build_voice_request_form, parse_admin_query, parse_owner_destroy, parse_voice_form, AdminError,
    AdminItem, AdminQuery, OwnerDestroy, VoiceForm, XMLNS_MUC_ADMIN, XMLNS_MUC_OWNER,
    XMLNS_MUC_REQUEST,
};
pub use affiliation::{Affiliation, AffiliationError};
pub use form::{
    build_room_configuration_form, parse_room_configuration_submit, FormError,
    PrivateMessagePolicy, RoomConfig, DEFAULT_MAX_OCCUPANTS, FORM_TYPE_ROOMCONFIG,
    MAX_MAX_OCCUPANTS, MAX_ROOM_DESC_BYTES, MAX_ROOM_TITLE_BYTES, MIN_MAX_OCCUPANTS,
};
pub use message::{
    apply_history_bounds, build_invitation_decline_message, build_mediated_invite_message,
    build_subject_message, parse_history_request, parse_invitation_decline, parse_mediated_invites,
    parse_subject_command, InvitationDecline, MediatedInvite, MessageError, MucHistoryRequest,
    DEFAULT_HISTORY_MAX_STANZAS, MAX_HISTORY_CHARS_BOUND, MAX_HISTORY_STANZA_BOUND, XMLNS_MUC,
    XMLNS_MUC_USER,
};
pub use permissions::{
    evaluate_affiliation_list_access, evaluate_discussion_message, evaluate_invitation,
    evaluate_role_list_access, evaluate_room_configuration_access, evaluate_room_join,
    evaluate_subject_change, should_broadcast_offline_affiliation_change, PermissionDecision,
    PermissionDeniedReason,
};
pub use presence::{
    build_destroy_presence, build_muc_presence, build_nick_change_presence,
    build_offline_affiliation_notice, is_allowed_muc_presence_payload_namespace,
    parse_muc_join_request, parse_muc_user_presence, MucDestroyPayload, MucJoinRequest,
    MucUserItem, MucUserPresencePayload, PresenceError,
};
pub use role::{Role, RoleError};
pub use status_code::StatusCode;
pub use transitions::{
    compute_affiliation_change_transition, compute_join_transition, compute_nick_change_transition,
    compute_role_change_transition, evaluate_room_policy_update, AffiliationChangeOutcome,
    JoinOutcome, NickChangeOutcome, OccupantSnapshot, RoleChangeOutcome, RoomPolicyUpdateDiff,
};
pub use xml::{escape_xml_attr, escape_xml_text, XmlElement};

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

/// XEP-0045 numeric extension identity.
pub const XEP_ID: XepId = XepId::new(45);

/// Static ExtensionDescriptor for XEP-0045 Multi-User Chat.
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Multi-User Chat",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[
        "http://jabber.org/protocol/muc",
        "http://jabber.org/protocol/muc#user",
        "http://jabber.org/protocol/muc#admin",
        "http://jabber.org/protocol/muc#owner",
        "http://jabber.org/protocol/muc#roomconfig",
        "muc_nonanonymous",
        "muc_semianonymous",
        "muc_open",
        "muc_membersonly",
        "muc_moderated",
        "muc_unmoderated",
        "muc_passwordprotected",
        "muc_unsecured",
        "muc_persistent",
        "muc_temporary",
        "muc_public",
        "muc_hidden",
    ],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::Presence,
            namespace: "http://jabber.org/protocol/muc",
            local_name: "x",
        },
        StanzaRoute {
            stanza: StanzaKind::Presence,
            namespace: "http://jabber.org/protocol/muc#user",
            local_name: "x",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: "http://jabber.org/protocol/muc#user",
            local_name: "x",
        },
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: "http://jabber.org/protocol/muc#admin",
            local_name: "query",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: "http://jabber.org/protocol/muc#admin",
            local_name: "query",
        },
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: "http://jabber.org/protocol/muc#owner",
            local_name: "query",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: "http://jabber.org/protocol/muc#owner",
            local_name: "query",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_descriptor() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Multi-User Chat");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert!(DESCRIPTOR.conflicts.is_empty());
        assert_eq!(DESCRIPTOR.routes.len(), 7);
    }
}
