//! Test-only fixed direct-message input/evidence boundary. This is not an
//! executor, an oracle, a product policy, or a public server entry point.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
};
use uuid::Uuid;

pub(crate) const CASE_SCHEMA: &str = "northstar-direct-case-v1";
pub(crate) const EVIDENCE_SCHEMA: &str = "northstar-direct-evidence-v1";
pub(crate) const ADAPTER_CONTRACT: &str = "local-direct-controlled-v1";
pub(crate) const ENTRY: &str = "xmpp::protocol::messaging::saved_case::replay_saved_case";
pub(crate) const MAX_INPUT: usize = 64 * 1024;
pub(crate) const MAX_FRAME: usize = 128 * 1024;
pub(crate) const MAX_FACTS: usize = 256;

// Named-field input objects must not accept serde's positional array form.
// The local Fields derive still owns duplicate/unknown-field detection. Each
// nested concrete struct re-enters this map-only visitor, including when an
// internally tagged enum delegates through serde's ContentDeserializer.
macro_rules! strict_object {
    (pub(crate) struct $name:ident { $(pub(crate) $field:ident: $kind:ty),* $(,)? }) => {
        #[derive(Clone, Serialize)]
        pub(crate) struct $name { $(pub(crate) $field: $kind),* }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Fields { $($field: $kind),* }
                struct ObjectVisitor;
                impl<'de> serde::de::Visitor<'de> for ObjectVisitor {
                    type Value = $name;
                    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { formatter.write_str(concat!("a named ", stringify!($name), " object")) }
                    fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                        let fields = Fields::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                        Ok($name { $($field: fields.$field),* })
                    }
                }
                deserializer.deserialize_map(ObjectVisitor)
            }
        }
    };
}

// Simple wire enums are JSON strings only. Serde's default enum decoder also
// accepts externally tagged object syntax, which this closed interface forbids.
macro_rules! string_enum {
    (pub(crate) enum $name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Eq, PartialEq, Serialize)]
        pub(crate) enum $name { $($variant),+ }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                match value.as_str() {
                    $(stringify!($variant) => Ok(Self::$variant),)+
                    _ => Err(serde::de::Error::unknown_variant(&value, &[$(stringify!($variant)),+])),
                }
            }
        }
    };
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Id(pub(crate) Uuid);
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let id = Uuid::parse_str(&text).map_err(serde::de::Error::custom)?;
        if id.to_string() != text {
            return Err(serde::de::Error::custom("noncanonical UUID"));
        }
        Ok(Self(id))
    }
}

/// Required JSON field, either a value or explicit null. This intentionally
/// is not Option, whose derived missing-field behavior would hide omissions.
#[derive(Clone, Serialize)]
#[serde(untagged)]
pub(crate) enum Nullable<T> {
    Value(T),
    Null(()),
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RequiredNullable<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for RequiredNullable<T> {
            type Value = Nullable<T>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a required value or explicit null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(Nullable::Null(()))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::StrDeserializer::<E>::new(value))
                    .map(Nullable::Value)
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::StringDeserializer::<E>::new(value))
                    .map(Nullable::Value)
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::U64Deserializer::<E>::new(value))
                    .map(Nullable::Value)
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::I64Deserializer::<E>::new(value))
                    .map(Nullable::Value)
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::BoolDeserializer::<E>::new(value))
                    .map(Nullable::Value)
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(Nullable::Value)
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                sequence: S,
            ) -> Result<Self::Value, S::Error> {
                T::deserialize(serde::de::value::SeqAccessDeserializer::new(sequence))
                    .map(Nullable::Value)
            }
        }
        // deserialize_any rejects a missing field. Forwarding directly to T
        // retains its duplicate/unknown-field error, without a Value map or
        // untagged intermediate swallowing that error into a generic variant.
        deserializer.deserialize_any(RequiredNullable(std::marker::PhantomData))
    }
}
impl<T> Nullable<T> {
    pub(crate) fn get(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Null(()) => None,
        }
    }
}

string_enum! { pub(crate) enum Mode { Live, SpoolOnly } }
impl Mode {
    pub(crate) fn actual(self) -> northstar_message_core::DirectPostCommitMode {
        match self {
            Self::Live => northstar_message_core::DirectPostCommitMode::Live,
            Self::SpoolOnly => northstar_message_core::DirectPostCommitMode::SpoolOnly,
        }
    }
}
string_enum! { pub(crate) enum CommitCut { Complete, Pending, Error } }
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Source {
    C2s {
        recipient_id: Id,
        message_id: Id,
        claim_id: Nullable<Id>,
    },
    Mix {
        delivery_id: Id,
        lease_token: Id,
    },
}
impl Source {
    pub(crate) fn actual(&self) -> northstar_delivery_core::TransportOwnershipSource {
        match self {
            Self::C2s {
                recipient_id,
                message_id,
                claim_id,
            } => northstar_delivery_core::TransportOwnershipSource::C2s(
                northstar_delivery_core::DurableDelivery {
                    recipient_id: recipient_id.0,
                    message_id: message_id.0,
                    claim_id: claim_id.get().map(|id| id.0),
                },
            ),
            Self::Mix {
                delivery_id,
                lease_token,
            } => northstar_delivery_core::TransportOwnershipSource::Mix(
                northstar_delivery_core::MixDelivery {
                    delivery_id: delivery_id.0,
                    lease_token: lease_token.0,
                },
            ),
        }
    }
}
impl From<northstar_delivery_core::TransportOwnershipSource> for Source {
    fn from(source: northstar_delivery_core::TransportOwnershipSource) -> Self {
        match source {
            northstar_delivery_core::TransportOwnershipSource::C2s(source) => Self::C2s {
                recipient_id: Id(source.recipient_id),
                message_id: Id(source.message_id),
                claim_id: source
                    .claim_id
                    .map_or(Nullable::Null(()), |id| Nullable::Value(Id(id))),
            },
            northstar_delivery_core::TransportOwnershipSource::Mix(source) => Self::Mix {
                delivery_id: Id(source.delivery_id),
                lease_token: Id(source.lease_token),
            },
        }
    }
}
strict_object! { pub(crate) struct Rotation { pub(crate) previous: Source, pub(crate) current: Source } }
strict_object! { pub(crate) struct Membership { pub(crate) c2s_message_ids: Vec<Id>, pub(crate) mix_delivery_ids: Vec<Id> } }
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum DeletedSource {
    C2s { recipient_id: Id, message_id: Id },
    Mix { delivery_id: Id, lease_token: Id },
}
strict_object! { pub(crate) struct OriginalIds { pub(crate) frame_id: Id, pub(crate) sender_stable_id: Id, pub(crate) recipient_stable_id: Id } }
strict_object! { pub(crate) struct Identities {
    pub(crate) actor_id: Id, pub(crate) recipient_id: Id, pub(crate) originals: Vec<OriginalIds>,
    pub(crate) connection_id: Nullable<Id>, pub(crate) sm_session_id: Nullable<Id>, pub(crate) bosh_session_id: Nullable<Id>, pub(crate) native_claim_id: Nullable<Id>,
    pub(crate) mix_delivery_id: Nullable<Id>, pub(crate) mix_old_token: Nullable<Id>, pub(crate) mix_new_token: Nullable<Id>,
    pub(crate) replacement_connection_id: Nullable<Id>, pub(crate) replacement_claim_id: Nullable<Id>,
} }
strict_object! { pub(crate) struct Original { pub(crate) frame_id: Id, pub(crate) xml: String, pub(crate) sender_full: String, pub(crate) target: String, pub(crate) at_utc: String } }
strict_object! { pub(crate) struct Policy {
    pub(crate) frame_id: Id, pub(crate) domain: String, pub(crate) recipient_bare: String,
    pub(crate) encrypted: bool, pub(crate) sender_archive: bool, pub(crate) recipient_archive: bool,
    pub(crate) clustered: bool, pub(crate) degraded_spool_eligible: bool, pub(crate) spool_privacy_permits: bool,
} }
strict_object! { pub(crate) struct Fence { pub(crate) admission_key_hex: String, pub(crate) payload_mac_hex: String, pub(crate) lease_token: Id, pub(crate) dedupe_digest_hex: String } }
strict_object! { pub(crate) struct Requirement {
    pub(crate) action: String, pub(crate) step: u32, pub(crate) work_factor: u64, pub(crate) max_work_factor: u64,
    pub(crate) hard_wait_seconds: u64, pub(crate) retry_after_seconds: u64, pub(crate) cooldown_seconds: u64,
    pub(crate) approximate_max_device_seconds: u64, pub(crate) notice: String,
} }
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Admission {
    NotRated {
        frame_id: Id,
    },
    Reserved {
        frame_id: Id,
        fence: Fence,
        requirement: Requirement,
        begin_commit: CommitCut,
        finalize_commit: CommitCut,
    },
}
impl Admission {
    pub(crate) fn frame_id(&self) -> Id {
        match self {
            Self::NotRated { frame_id } | Self::Reserved { frame_id, .. } => *frame_id,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Transaction {
    Stored {
        recipient_id: Id,
        delivery_id: Id,
        archive_ids: Vec<Id>,
        live_claim_id: Nullable<Id>,
    },
    Replay {
        archive_ids: Vec<Id>,
    },
    AccountUnavailable {},
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Completion {
    Return { mode: Mode },
    ErrorAfterReceipt {},
}
strict_object! { pub(crate) struct DirectRepository { pub(crate) frame_id: Id, pub(crate) transaction: Transaction, pub(crate) admitted_mode: Mode, pub(crate) commit: CommitCut, pub(crate) completion: Completion } }
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Item {
    Plain {
        xml: String,
        transport_receipt: bool,
    },
    Mix {
        xml: String,
        source: Source,
    },
}
string_enum! { pub(crate) enum Queue { Empty, PrefilledPlain } }
string_enum! { pub(crate) enum Rearm { Return, Pending } }
strict_object! { pub(crate) struct Target { pub(crate) jid: String, pub(crate) connection_id: Id } }
strict_object! { pub(crate) struct Route {
    pub(crate) frame_id: Id, pub(crate) initial_queue: Queue, pub(crate) prefill: Nullable<Item>, pub(crate) targets: Vec<Target>,
    pub(crate) health_modes: Vec<Mode>, pub(crate) remote_primary_returns: Vec<bool>, pub(crate) rearm: Rearm,
} }
string_enum! { pub(crate) enum Flush { Ok, Error } }
strict_object! { pub(crate) struct WriteScript { pub(crate) chunk_limit: u32, pub(crate) fail_after_accepted_bytes: Nullable<u32>, pub(crate) flush: Flush } }
strict_object! { pub(crate) struct NativeFence { pub(crate) returned_source: Source } }
string_enum! { pub(crate) enum NativeDisposition { Deleted } }
strict_object! { pub(crate) struct NativeAck { pub(crate) commit: CommitCut, pub(crate) disposition: NativeDisposition } }
strict_object! { pub(crate) struct NativeSpec { pub(crate) connection_id: Id, pub(crate) fence: NativeFence, pub(crate) write: WriteScript, pub(crate) ack: NativeAck } }
strict_object! { pub(crate) struct Governor { pub(crate) max_bytes: u32, pub(crate) max_recovery_bytes: u32, pub(crate) max_recovery_jobs: u32, pub(crate) max_snapshot_bytes: u32 } }
strict_object! { pub(crate) struct SmConfig {
    pub(crate) session_id: Nullable<Id>, pub(crate) enabled: bool, pub(crate) resume_allowed: bool,
    pub(crate) inbound_h: u32, pub(crate) outbound_h: u32, pub(crate) acked_h: u32,
    pub(crate) resume_timeout_seconds: u64, pub(crate) live_lease_seconds: u64, pub(crate) claim_lease_seconds: u64,
    pub(crate) require_same_device: bool, pub(crate) max_per_account: u32, pub(crate) max_global: u32,
    pub(crate) max_unacked_stanzas: u32, pub(crate) max_unacked_bytes: u32, pub(crate) max_snapshot_bytes: u32,
    pub(crate) ip_binding: String, pub(crate) peer_ip: String, pub(crate) governor: Governor,
} }
strict_object! { pub(crate) struct CheckpointReply { pub(crate) commit: CommitCut, pub(crate) updated: bool, pub(crate) rotations: Vec<Rotation> } }
strict_object! { pub(crate) struct SmAck { pub(crate) h: u32, pub(crate) reply: CheckpointReply } }
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum BoshRecording {
    Disabled {},
    PersistedSm {
        connection_id: Id,
        config: SmConfig,
        record_replies: Vec<CheckpointReply>,
    },
}
strict_object! { pub(crate) struct MixTransfer { pub(crate) commit: CommitCut, pub(crate) returned_source: Source } }
strict_object! { pub(crate) struct Bind { pub(crate) commit: CommitCut, pub(crate) returned_membership: Membership } }
string_enum! { pub(crate) enum Responder { Open, Dropped } }
strict_object! { pub(crate) struct CachedReplay { pub(crate) request_xml: String, pub(crate) renewal: CommitCut, pub(crate) responder: Responder } }
strict_object! { pub(crate) struct FreshAck { pub(crate) request_xml: String, pub(crate) renewal: CommitCut, pub(crate) ack_commit: CommitCut, pub(crate) deleted: Vec<DeletedSource> } }
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum RecipientOwner {
    None {},
    Native {
        frame_id: Id,
        native: NativeSpec,
    },
    Sm {
        frame_id: Id,
        connection_id: Id,
        config: SmConfig,
        extra_items: Vec<Item>,
        record_replies: Vec<CheckpointReply>,
        write: WriteScript,
        ack: Nullable<SmAck>,
    },
    Bosh {
        frame_id: Id,
        session_id: Id,
        ttl_seconds: u64,
        max_output_stanzas: u32,
        max_output_bytes: u32,
        max_response_bytes: u32,
        content_type: String,
        received_rid: u64,
        governor: Governor,
        extra_items: Vec<Item>,
        recording: Box<BoshRecording>,
        mix_transfer: Nullable<MixTransfer>,
        request_xml: String,
        initial_renewal: CommitCut,
        bind: Nullable<Bind>,
        responders: Vec<Responder>,
        cached_replay: Nullable<CachedReplay>,
        fresh_ack: Nullable<FreshAck>,
    },
    NativeReplacement {
        frame_id: Id,
        initial_row: Source,
        old: NativeSpec,
        replacement: NativeSpec,
        replacement_claim_id: Id,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum Drive {
    Complete {},
    DropDirectCommit { frame_id: Id },
    DropRearm { frame_id: Id },
    DropNativeAckCommit { frame_id: Id },
    DropSmCheckpointCommit { frame_id: Id },
    DropBoshBindCommit { frame_id: Id },
    ReplaceBeforeOldAckRead { frame_id: Id },
}
strict_object! { pub(crate) struct Case {
    pub(crate) schema: String, pub(crate) case_id: String, pub(crate) adapter_contract: String,
    pub(crate) identities: Identities, pub(crate) originals: Vec<Original>, pub(crate) policy: Vec<Policy>,
    pub(crate) admission: Vec<Admission>, pub(crate) direct_repository: Vec<DirectRepository>, pub(crate) route: Vec<Route>,
    pub(crate) recipient_owner: RecipientOwner, pub(crate) drive: Drive,
} }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum Rejection {
    DuplicateKey,
    UnknownField,
    IdentityBinding,
    InvalidSchema,
    Malformed,
    Limit,
    UnsupportedOwner,
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub(crate) fn unhex(value: &str) -> Result<Vec<u8>, Rejection> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Rejection::Malformed);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| Rejection::Malformed)?,
                16,
            )
            .map_err(|_| Rejection::Malformed)
        })
        .collect()
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex(&sha2::Sha256::digest(bytes))
}
pub(crate) fn read_input() -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut bytes)?;
    // Never label a truncated prefix hash as the complete input identity.
    // Oversized input is outside this profile, not a structured saved case.
    anyhow::ensure!(bytes.len() <= MAX_INPUT, "saved direct input cap exceeded");
    Ok(bytes)
}
pub(crate) fn decode(bytes: &[u8]) -> Result<Case, Rejection> {
    if bytes.len() > MAX_INPUT {
        return Err(Rejection::Limit);
    }
    // Concrete derives retain duplicate-key and unknown-field errors at every
    // level. No permissive Value map can discard duplicate keys first.
    let case: Case = serde_json::from_slice(bytes).map_err(|error| {
        let message = error.to_string();
        if message.starts_with("duplicate field") {
            Rejection::DuplicateKey
        } else if message.starts_with("unknown field") {
            Rejection::UnknownField
        } else {
            Rejection::Malformed
        }
    })?;
    case.validate()?;
    Ok(case)
}
impl Case {
    pub(crate) fn validate(&self) -> Result<(), Rejection> {
        if self.schema != CASE_SCHEMA || self.adapter_contract != ADAPTER_CONTRACT {
            return Err(Rejection::InvalidSchema);
        }
        let count = self.originals.len();
        if !(1..=2).contains(&count)
            || self.case_id.is_empty()
            || self.case_id.len() > 64
            || [
                self.identities.originals.len(),
                self.policy.len(),
                self.admission.len(),
                self.direct_repository.len(),
                self.route.len(),
            ]
            .iter()
            .any(|length| *length != count)
        {
            return Err(Rejection::Limit);
        }
        let mut ids = BTreeSet::new();
        let mut xml_bytes = 0usize;
        let mut items = count;
        for index in 0..count {
            let original = &self.originals[index];
            let identity = &self.identities.originals[index];
            let policy = &self.policy[index];
            let direct = &self.direct_repository[index];
            let route = &self.route[index];
            if [
                identity.frame_id,
                policy.frame_id,
                self.admission[index].frame_id(),
                direct.frame_id,
                route.frame_id,
            ]
            .iter()
            .any(|id| *id != original.frame_id)
                || !ids.insert(identity.frame_id)
                || !ids.insert(identity.sender_stable_id)
                || !ids.insert(identity.recipient_stable_id)
            {
                return Err(Rejection::IdentityBinding);
            }
            xml_bytes = xml_bytes
                .checked_add(original.xml.len())
                .ok_or(Rejection::Limit)?;
            if original.xml.len() > 4096
                || original.sender_full.len() > 1024
                || original.target.len() > 1024
                || policy.domain.len() > 256
                || policy.recipient_bare.len() > 1024
                || chrono::DateTime::parse_from_rfc3339(&original.at_utc).is_err()
            {
                return Err(Rejection::Limit);
            }
            let parsed =
                roxmltree::Document::parse(&original.xml).map_err(|_| Rejection::Malformed)?;
            let root = parsed.root_element();
            if root.tag_name().name() != "message"
                || root
                    .attribute("to")
                    .unwrap_or(crate::state::bare_jid(&original.sender_full))
                    != original.target
                || crate::state::bare_jid(&original.target) != policy.recipient_bare
            {
                return Err(Rejection::IdentityBinding);
            }
            if crate::xmpp::xml_util::is_abuse_rated_message(root)
                != matches!(self.admission[index], Admission::Reserved { .. })
                || crate::xmpp::xml_util::is_encrypted(root) != policy.encrypted
            {
                return Err(Rejection::IdentityBinding);
            }
            if let Admission::Reserved {
                fence,
                requirement,
                begin_commit,
                finalize_commit,
                ..
            } = &self.admission[index]
            {
                if *begin_commit != CommitCut::Complete || *finalize_commit == CommitCut::Pending {
                    return Err(Rejection::IdentityBinding);
                }
                if [
                    unhex(&fence.admission_key_hex)?.len(),
                    unhex(&fence.payload_mac_hex)?.len(),
                    unhex(&fence.dedupe_digest_hex)?.len(),
                ] != [32; 3]
                    || requirement.action != "message"
                    || requirement.notice.len() > 1024
                {
                    return Err(Rejection::Limit);
                }
            }
            if let Transaction::Stored {
                recipient_id,
                delivery_id,
                archive_ids,
                live_claim_id,
            } = &direct.transaction
            {
                let mut expected = Vec::new();
                if policy.sender_archive {
                    expected.push(identity.sender_stable_id);
                }
                if policy.recipient_archive
                    && self.identities.actor_id != self.identities.recipient_id
                {
                    expected.push(identity.recipient_stable_id);
                }
                if *recipient_id != self.identities.recipient_id
                    || *delivery_id != identity.recipient_stable_id
                    || *archive_ids != expected
                    || live_claim_id
                        .get()
                        .is_some_and(|claim| *claim != *delivery_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            let drop_direct = matches!(&self.drive, Drive::DropDirectCommit { frame_id } if *frame_id == original.frame_id);
            let drop_rearm = matches!(&self.drive, Drive::DropRearm { frame_id } if *frame_id == original.frame_id);
            if (direct.commit == CommitCut::Pending) != drop_direct
                || (route.rearm == Rearm::Pending) != drop_rearm
            {
                return Err(Rejection::IdentityBinding);
            }
            if direct.admitted_mode == Mode::SpoolOnly
                && !(policy.degraded_spool_eligible && policy.spool_privacy_permits)
            {
                return Err(Rejection::IdentityBinding);
            }
            if route.targets.len() > 4
                || route.health_modes.len() > 16
                || route.remote_primary_returns.len() > 4
                || (route.initial_queue == Queue::PrefilledPlain) != route.prefill.get().is_some()
            {
                return Err(Rejection::Limit);
            }
            for target in &route.targets {
                if crate::state::bare_jid(&target.jid) != policy.recipient_bare
                    || Some(&target.connection_id) != self.identities.connection_id.get()
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            if let Some(item) = route.prefill.get() {
                items += 1;
                let Item::Plain { xml, .. } = item else {
                    return Err(Rejection::IdentityBinding);
                };
                xml_bytes += xml.len();
                if xml.len() > 4096 {
                    return Err(Rejection::Limit);
                }
            }
        }
        if xml_bytes > 16384 || items > 4 {
            return Err(Rejection::Limit);
        }
        match &self.recipient_owner {
            RecipientOwner::None {} => {}
            RecipientOwner::Native { frame_id, native } => {
                let index = self
                    .originals
                    .iter()
                    .position(|original| original.frame_id == *frame_id)
                    .ok_or(Rejection::IdentityBinding)?;
                let Source::C2s {
                    recipient_id,
                    message_id,
                    claim_id,
                } = &native.fence.returned_source
                else {
                    return Err(Rejection::IdentityBinding);
                };
                if Some(&native.connection_id) != self.identities.connection_id.get()
                    || *recipient_id != self.identities.recipient_id
                    || *message_id != self.identities.originals[index].recipient_stable_id
                    || claim_id.get() != self.identities.native_claim_id.get()
                    || claim_id.get().is_none()
                {
                    return Err(Rejection::IdentityBinding);
                }
                let drop_ack = matches!(&self.drive, Drive::DropNativeAckCommit { frame_id: target } if *target == *frame_id);
                if (native.ack.commit == CommitCut::Pending) != drop_ack {
                    return Err(Rejection::IdentityBinding);
                }
                if native.write.chunk_limit == 0
                    || native.write.chunk_limit > 4096
                    || native
                        .write
                        .fail_after_accepted_bytes
                        .get()
                        .is_some_and(|bytes| *bytes != 1)
                {
                    return Err(Rejection::Limit);
                }
            }
            RecipientOwner::Sm {
                frame_id,
                connection_id,
                config,
                extra_items,
                record_replies,
                write,
                ack,
            } => {
                if !self
                    .originals
                    .iter()
                    .any(|original| original.frame_id == *frame_id)
                    || Some(connection_id) != self.identities.connection_id.get()
                    || config.session_id.get() != self.identities.sm_session_id.get()
                    || config.session_id.get().is_none()
                    || !config.enabled
                    || !config.resume_allowed
                    || config.outbound_h != config.acked_h
                    || self.identities.native_claim_id.get().is_some()
                    || config.peer_ip.parse::<std::net::IpAddr>().is_err()
                {
                    return Err(Rejection::IdentityBinding);
                }
                if extra_items.len() > 3
                    || items + extra_items.len() > 4
                    || record_replies.len() != 1 + extra_items.len()
                    || config.governor.max_bytes < config.governor.max_snapshot_bytes
                    || config.governor.max_recovery_bytes < config.governor.max_snapshot_bytes
                    || config.governor.max_recovery_jobs == 0
                    || config.governor.max_snapshot_bytes == 0
                    || write.chunk_limit == 0
                    || write.chunk_limit > 4096
                    || write
                        .fail_after_accepted_bytes
                        .get()
                        .is_some_and(|bytes| *bytes != 1)
                {
                    return Err(Rejection::Limit);
                }
                let mut mix = None;
                for item in extra_items {
                    let xml = match item {
                        Item::Plain { xml, .. } => xml,
                        Item::Mix { xml, source } => {
                            let Source::Mix {
                                delivery_id,
                                lease_token,
                            } = source
                            else {
                                return Err(Rejection::IdentityBinding);
                            };
                            if mix.is_some()
                                || Some(delivery_id) != self.identities.mix_delivery_id.get()
                                || Some(lease_token) != self.identities.mix_old_token.get()
                                || self.identities.mix_new_token.get().is_none()
                            {
                                return Err(Rejection::IdentityBinding);
                            }
                            mix = Some(source.actual());
                            xml
                        }
                    };
                    xml_bytes += xml.len();
                    if xml.len() > 4096 || roxmltree::Document::parse(xml).is_err() {
                        return Err(Rejection::Limit);
                    }
                }
                if xml_bytes > 16384 {
                    return Err(Rejection::Limit);
                }
                if mix.is_none()
                    && [
                        self.identities.mix_delivery_id.get(),
                        self.identities.mix_old_token.get(),
                        self.identities.mix_new_token.get(),
                    ]
                    .iter()
                    .any(Option::is_some)
                {
                    return Err(Rejection::IdentityBinding);
                }
                let drop_sm = matches!(&self.drive, Drive::DropSmCheckpointCommit { frame_id: target } if target == frame_id);
                for (index, reply) in record_replies.iter().enumerate() {
                    if !reply.updated
                        || (reply.commit == CommitCut::Pending) != (drop_sm && index == 0)
                    {
                        return Err(Rejection::IdentityBinding);
                    }
                    let newly_entering = index
                        .checked_sub(1)
                        .and_then(|index| extra_items.get(index))
                        .and_then(|item| match item {
                            Item::Mix { source, .. } => Some(source.actual()),
                            Item::Plain { .. } => None,
                        });
                    if let Some(previous) = newly_entering {
                        if reply.rotations.len() != 1 {
                            return Err(Rejection::IdentityBinding);
                        }
                        let rotation = &reply.rotations[0];
                        let Source::Mix {
                            delivery_id,
                            lease_token,
                        } = &rotation.current
                        else {
                            return Err(Rejection::IdentityBinding);
                        };
                        if rotation.previous.actual() != previous
                            || Some(delivery_id) != self.identities.mix_delivery_id.get()
                            || Some(lease_token) != self.identities.mix_new_token.get()
                        {
                            return Err(Rejection::IdentityBinding);
                        }
                    } else if !reply.rotations.is_empty() {
                        return Err(Rejection::IdentityBinding);
                    }
                }
                if drop_sm && ack.get().is_some() {
                    return Err(Rejection::IdentityBinding);
                }
                if let Some(ack) = ack.get() {
                    // Existing SM-owned MIX suffixes retain their last returned
                    // token. This profile has no re-rotation-on-ACK scenario.
                    if !ack.reply.updated
                        || ack.reply.commit != CommitCut::Complete
                        || !ack.reply.rotations.is_empty()
                    {
                        return Err(Rejection::IdentityBinding);
                    }
                }
            }
            RecipientOwner::NativeReplacement {
                frame_id,
                initial_row,
                old,
                replacement,
                replacement_claim_id,
            } => {
                if self.originals.len() != 1
                    || self.originals[0].frame_id != *frame_id
                    || !matches!(&self.drive, Drive::ReplaceBeforeOldAckRead { frame_id: target } if target == frame_id)
                    || Some(&old.connection_id) != self.identities.connection_id.get()
                    || Some(&replacement.connection_id)
                        != self.identities.replacement_connection_id.get()
                    || Some(replacement_claim_id) != self.identities.replacement_claim_id.get()
                    || old.connection_id == replacement.connection_id
                {
                    return Err(Rejection::IdentityBinding);
                }
                let Transaction::Stored {
                    recipient_id,
                    delivery_id,
                    live_claim_id,
                    ..
                } = &self.direct_repository[0].transaction
                else {
                    return Err(Rejection::IdentityBinding);
                };
                let expected_initial = northstar_delivery_core::TransportOwnershipSource::C2s(
                    northstar_delivery_core::DurableDelivery {
                        recipient_id: recipient_id.0,
                        message_id: delivery_id.0,
                        claim_id: live_claim_id.get().map(|id| id.0),
                    },
                );
                if initial_row.actual() != expected_initial
                    || !self.policy[0].clustered
                    || live_claim_id.get() != Some(delivery_id)
                    || self.direct_repository[0].admitted_mode != Mode::Live
                    || self.direct_repository[0].commit != CommitCut::Complete
                    || !matches!(
                        self.direct_repository[0].completion,
                        Completion::Return { mode: Mode::Live }
                    )
                {
                    return Err(Rejection::IdentityBinding);
                }
                for (native, claim) in [
                    (old, self.identities.native_claim_id.get()),
                    (replacement, Some(replacement_claim_id)),
                ] {
                    let Source::C2s {
                        recipient_id: returned_recipient,
                        message_id,
                        claim_id,
                    } = &native.fence.returned_source
                    else {
                        return Err(Rejection::IdentityBinding);
                    };
                    if returned_recipient != recipient_id
                        || message_id != delivery_id
                        || claim_id.get() != claim
                        || claim.is_none()
                        || native.ack.commit != CommitCut::Complete
                        || native.write.flush != Flush::Ok
                        || native.write.fail_after_accepted_bytes.get().is_some()
                    {
                        return Err(Rejection::IdentityBinding);
                    }
                    if native.write.chunk_limit == 0 || native.write.chunk_limit > 4096 {
                        return Err(Rejection::Limit);
                    }
                }
                if self.identities.native_claim_id.get() == Some(replacement_claim_id) {
                    return Err(Rejection::IdentityBinding);
                }
            }
            RecipientOwner::Bosh { .. } => {
                crate::bosh::validate_saved_case(self, items, xml_bytes)?
            }
        }
        if (!matches!(self.recipient_owner, RecipientOwner::Bosh { .. })
            && self.identities.bosh_session_id.get().is_some())
            || (!matches!(
                self.recipient_owner,
                RecipientOwner::NativeReplacement { .. }
            ) && [
                self.identities.replacement_connection_id.get(),
                self.identities.replacement_claim_id.get(),
            ]
            .iter()
            .any(Option::is_some))
            || (!matches!(
                self.recipient_owner,
                RecipientOwner::Sm { .. } | RecipientOwner::Bosh { .. }
            ) && [
                self.identities.sm_session_id.get(),
                self.identities.mix_delivery_id.get(),
                self.identities.mix_old_token.get(),
                self.identities.mix_new_token.get(),
            ]
            .iter()
            .any(Option::is_some))
        {
            return Err(Rejection::IdentityBinding);
        }
        if matches!(self.recipient_owner, RecipientOwner::None {})
            && self.identities.native_claim_id.get().is_some()
        {
            return Err(Rejection::IdentityBinding);
        }
        match &self.drive {
            Drive::Complete {} => {}
            Drive::DropDirectCommit { frame_id }
            | Drive::DropRearm { frame_id }
            | Drive::DropNativeAckCommit { frame_id } => {
                if !self
                    .originals
                    .iter()
                    .any(|original| original.frame_id == *frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
                if matches!(self.drive, Drive::DropNativeAckCommit { .. })
                    && !matches!(&self.recipient_owner, RecipientOwner::Native { frame_id: owner_frame, .. } if owner_frame == frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            Drive::DropSmCheckpointCommit { frame_id } => {
                if !matches!(&self.recipient_owner, RecipientOwner::Sm { frame_id: owner, .. } if owner == frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            Drive::ReplaceBeforeOldAckRead { frame_id } => {
                if !matches!(&self.recipient_owner, RecipientOwner::NativeReplacement { frame_id: owner, .. } if owner == frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            Drive::DropBoshBindCommit { frame_id } => {
                if !matches!(&self.recipient_owner, RecipientOwner::Bosh { frame_id: owner, .. } if owner == frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
        }
        Ok(())
    }
}

// These wire types describe actual observations, never expected verdicts. In
// particular, writer/flush facts and the owner's permission remain independent.
#[derive(Serialize)]
pub(crate) struct Envelope {
    pub(crate) schema: &'static str,
    pub(crate) entry: &'static str,
    pub(crate) input_sha256: String,
    pub(crate) rejection: Option<RejectedInput>,
    pub(crate) execution: Option<Execution>,
    pub(crate) originals: Vec<OriginalEvidence>,
    pub(crate) recipient: Option<RecipientEvidence>,
}
#[derive(Serialize)]
pub(crate) struct RejectedInput {
    pub(crate) class: &'static str,
    pub(crate) reason: Rejection,
}
#[derive(Clone, Copy, Serialize)]
pub(crate) enum Execution {
    Complete,
    Cancelled,
}
impl Envelope {
    pub(crate) fn rejected(input: &[u8], reason: Rejection) -> Self {
        Self {
            schema: EVIDENCE_SCHEMA,
            entry: ENTRY,
            input_sha256: digest(input),
            rejection: Some(RejectedInput {
                class: "InvalidScenario",
                reason,
            }),
            execution: None,
            originals: vec![],
            recipient: None,
        }
    }
}
pub(crate) fn emit(envelope: &Envelope) -> anyhow::Result<()> {
    let payload = serde_json::to_vec(envelope)?;
    anyhow::ensure!(
        payload.len() <= MAX_FRAME,
        "direct evidence frame cap exceeded"
    );
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\x1eNORTHSTAR_DIRECT_CASE_V1 {}", payload.len())?;
    stdout.write_all(&payload)?;
    stdout.write_all(b"\n\x1eEND\n")?;
    stdout.flush()?;
    Ok(())
}
#[derive(Clone, Serialize)]
pub(crate) struct Correlation {
    pub(crate) operation_id: Id,
    pub(crate) effect: u64,
    pub(crate) generation: u64,
    pub(crate) attempt: u64,
}
impl From<northstar_abuse_policy::admission_execution::Correlation> for Correlation {
    fn from(value: northstar_abuse_policy::admission_execution::Correlation) -> Self {
        Self {
            operation_id: Id(value.operation),
            effect: value.effect,
            generation: value.generation,
            attempt: u64::from(value.attempt),
        }
    }
}
#[derive(Clone, Serialize)]
pub(crate) struct FenceEvidence {
    pub(crate) admission_key_hex: String,
    pub(crate) payload_mac_hex: String,
    pub(crate) lease_token: Id,
}
impl From<&northstar_abuse_policy::admission_transaction::AdmissionFence> for FenceEvidence {
    fn from(value: &northstar_abuse_policy::admission_transaction::AdmissionFence) -> Self {
        Self {
            admission_key_hex: hex(&value.admission_key),
            payload_mac_hex: hex(&value.payload_mac),
            lease_token: Id(value.lease_token),
        }
    }
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum AdmissionFact {
    Reserved {
        fence: FenceEvidence,
    },
    Finalized {
        fence: FenceEvidence,
        result: &'static str,
    },
}
#[derive(Clone, Serialize)]
pub(crate) struct AdmissionCommit {
    pub(crate) correlation: Correlation,
    pub(crate) scope: &'static str,
    pub(crate) fact: AdmissionFact,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum AdmissionKnowledge {
    NoCommitRequested,
    CommitCallEntered { prepared: AdmissionCommit },
    ReceiptKnown { receipt: AdmissionCommit },
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum AdmissionReturned {
    Proceed { fence: FenceEvidence },
    AcceptPending,
    Error,
}
#[derive(Clone, Serialize)]
pub(crate) struct AdmissionEvidence {
    pub(crate) correlation: Correlation,
    pub(crate) started: bool,
    pub(crate) knowledge: AdmissionKnowledge,
    pub(crate) returned: Option<AdmissionReturned>,
}
#[derive(Clone, Serialize)]
pub(crate) struct DirectPrepared {
    pub(crate) correlation: Correlation,
    pub(crate) transaction: Transaction,
    pub(crate) admitted_mode: Mode,
}
#[derive(Clone, Serialize)]
pub(crate) struct DirectReceipt {
    pub(crate) prepared: DirectPrepared,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum DirectKnowledge {
    NoCommitRequested,
    CommitCallEntered { prepared: DirectPrepared },
    ReceiptKnown { receipt: DirectReceipt },
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum CommitResult {
    Stored {
        archive_written: bool,
        recipient_id: Id,
        delivery_id: Id,
    },
    Replay,
    AccountUnavailable,
}
#[derive(Clone, Serialize)]
pub(crate) struct DirectReturned {
    pub(crate) commit: CommitResult,
    pub(crate) mode: Mode,
    pub(crate) live_claim_id: Option<Id>,
}
#[derive(Clone, Serialize)]
pub(crate) struct DirectEvidence {
    pub(crate) correlation: Correlation,
    pub(crate) started: bool,
    pub(crate) knowledge: DirectKnowledge,
    pub(crate) returned: Option<DirectReturned>,
    pub(crate) preserved_transaction: Option<Transaction>,
    pub(crate) application_error: bool,
}
#[derive(Clone, Serialize)]
pub(crate) struct ArchiveEvidence {
    pub(crate) archive_id: Id,
    pub(crate) owner_id: Id,
    pub(crate) peer_jid: String,
    pub(crate) stanza_id: Option<String>,
    pub(crate) encrypted: bool,
    pub(crate) xml: String,
}
#[derive(Clone, Serialize)]
pub(crate) struct Projection {
    pub(crate) message_type: String,
    pub(crate) origin_id: Option<String>,
    pub(crate) rated: bool,
    pub(crate) normalized_payload: Option<String>,
    pub(crate) live_xml: String,
    pub(crate) stored_xml: String,
    pub(crate) archives: Vec<ArchiveEvidence>,
}
#[derive(Clone, Serialize)]
pub(crate) struct IdentityEvidence {
    pub(crate) authority: &'static str,
    pub(crate) actor_scope_raw: String,
    pub(crate) actor_scope: String,
    pub(crate) target_scope: String,
    pub(crate) value: String,
    pub(crate) payload: String,
}
#[derive(Clone, Serialize)]
pub(crate) struct PreparedEvidence {
    pub(crate) actor_id: Id,
    pub(crate) recipient_id: Id,
    pub(crate) delivery_id: Id,
    pub(crate) eligibility: &'static str,
    pub(crate) encrypted: bool,
    pub(crate) mam_backed: bool,
    pub(crate) archive_ids: Vec<Id>,
    pub(crate) identity: Option<IdentityEvidence>,
}
#[derive(Clone, Serialize)]
pub(crate) struct Continuation {
    pub(crate) kind: &'static str,
    pub(crate) error_type: Option<&'static str>,
    pub(crate) error_condition: Option<&'static str>,
}
#[derive(Clone, Serialize)]
pub(crate) struct Handoff {
    pub(crate) correlation: Correlation,
    pub(crate) source: Source,
    pub(crate) local_call: &'static str,
    pub(crate) local_accepted: bool,
    pub(crate) last_local_refusal: Option<&'static str>,
    pub(crate) remote: &'static str,
    pub(crate) prior_remote_uncertain: bool,
    pub(crate) rearm: &'static str,
    pub(crate) route_end: &'static str,
    pub(crate) retired: bool,
}
#[derive(Clone, Serialize)]
pub(crate) struct OriginalState {
    pub(crate) begin: Option<AdmissionEvidence>,
    pub(crate) finalize: Option<AdmissionEvidence>,
    pub(crate) direct: Option<DirectEvidence>,
    pub(crate) handoff: Option<Handoff>,
    pub(crate) terminal: Option<&'static str>,
}
#[derive(Clone, Serialize)]
pub(crate) struct OriginalPrefix {
    pub(crate) seq: u32,
    pub(crate) state: OriginalState,
}
#[derive(Clone, Serialize)]
pub(crate) struct Slot {
    pub(crate) xml: String,
    pub(crate) source: Option<Source>,
}
#[derive(Clone, Serialize)]
pub(crate) struct HealthRead {
    pub(crate) seq: u32,
    pub(crate) phase: &'static str,
    pub(crate) mode: Mode,
}
#[derive(Clone, Serialize)]
pub(crate) struct Enqueue {
    pub(crate) seq: u32,
    pub(crate) source: Source,
    pub(crate) xml: String,
    pub(crate) result: &'static str,
}
#[derive(Clone, Serialize)]
pub(crate) struct Dequeue {
    pub(crate) seq: u32,
    pub(crate) source: Option<Source>,
    pub(crate) xml: String,
}
#[derive(Clone, Serialize)]
pub(crate) struct RemoteCall {
    pub(crate) seq: u32,
    pub(crate) source: Source,
    pub(crate) returned: Option<bool>,
}
#[derive(Clone, Serialize)]
pub(crate) struct RearmCall {
    pub(crate) seq: u32,
    pub(crate) source: Source,
    pub(crate) returned: bool,
}
#[derive(Clone, Default, Serialize)]
pub(crate) struct RouteEvidence {
    pub(crate) health_reads: Vec<HealthRead>,
    pub(crate) enqueue: Vec<Enqueue>,
    pub(crate) dequeued: Vec<Dequeue>,
    pub(crate) queue_remaining: Vec<Slot>,
    pub(crate) backpressure_disconnected: bool,
    pub(crate) remote_calls: Vec<RemoteCall>,
    pub(crate) rearm_calls: Vec<RearmCall>,
    pub(crate) handoff: Option<Handoff>,
}
#[derive(Serialize)]
pub(crate) struct OriginalEvidence {
    pub(crate) frame_id: Id,
    pub(crate) projection: Option<Projection>,
    pub(crate) prepared: Option<PreparedEvidence>,
    pub(crate) begin: Option<AdmissionEvidence>,
    pub(crate) finalize: Option<AdmissionEvidence>,
    pub(crate) direct: Option<DirectEvidence>,
    pub(crate) continuation: Option<Continuation>,
    pub(crate) route: RouteEvidence,
    pub(crate) terminal: Option<&'static str>,
    pub(crate) prefixes: Vec<OriginalPrefix>,
    pub(crate) polls: Vec<DriverPoll>,
}
#[derive(Clone, Serialize)]
pub(crate) struct NativeFact {
    pub(crate) source: Source,
    pub(crate) disposition: &'static str,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum NativeAckKnowledge {
    NotRequested,
    NoCommitRequested,
    CommitCallEntered { fact: NativeFact },
    ReceiptKnown { fact: NativeFact },
}
#[derive(Clone, Serialize)]
pub(crate) struct NativeState {
    pub(crate) original: Option<Source>,
    pub(crate) preparation: &'static str,
    pub(crate) managed_by_sm: Option<bool>,
    pub(crate) fence_entered: bool,
    pub(crate) returned_fence: Option<Source>,
    pub(crate) writer_entered: bool,
    pub(crate) writer_result: Option<&'static str>,
    pub(crate) write_decision: Option<&'static str>,
    pub(crate) ack: NativeAckKnowledge,
    pub(crate) ack_returned: Option<bool>,
    pub(crate) terminal: Option<&'static str>,
}
#[derive(Clone, Serialize)]
pub(crate) struct NativePrefix {
    pub(crate) seq: u32,
    pub(crate) state: NativeState,
}
#[derive(Clone, Serialize)]
pub(crate) struct WriteCall {
    pub(crate) seq: u32,
    pub(crate) offered_len: u32,
    pub(crate) offered_sha256: String,
    pub(crate) accepted_bytes_hex: String,
    pub(crate) result: &'static str,
}
#[derive(Clone, Serialize)]
pub(crate) struct FlushCall {
    pub(crate) seq: u32,
    pub(crate) result: &'static str,
}
#[derive(Clone, Serialize)]
pub(crate) struct AckCall {
    pub(crate) seq: u32,
    pub(crate) source: Source,
    pub(crate) returned: Option<bool>,
}
#[derive(Clone, Serialize)]
pub(crate) struct ReceiptObservation {
    pub(crate) seq: u32,
    pub(crate) result: &'static str,
}
#[derive(Serialize)]
pub(crate) struct NativeEvidence {
    pub(crate) frame_id: Id,
    pub(crate) connection_id: Id,
    #[serde(flatten)]
    pub(crate) state: NativeState,
    pub(crate) write_calls: Vec<WriteCall>,
    pub(crate) flush_calls: Vec<FlushCall>,
    pub(crate) ack_calls: Vec<AckCall>,
    pub(crate) ownership_receipts: Vec<ReceiptObservation>,
    pub(crate) write_receipts: Vec<ReceiptObservation>,
    pub(crate) prefixes: Vec<NativePrefix>,
    pub(crate) polls: Vec<DriverPoll>,
}
#[derive(Serialize)]
#[serde(tag = "kind")]
pub(crate) enum RecipientEvidence {
    None,
    Native {
        native: Box<NativeEvidence>,
    },
    Sm {
        native_writes: Vec<NativeEvidence>,
        sm_turns: Vec<SmEvidence>,
        fifo_after: Vec<Slot>,
        outbound_h: u32,
        acked_h: u32,
        mix_handoffs: Vec<MixHandoff>,
    },
    Bosh {
        bosh: Box<BoshEvidence>,
        sm_turns: Vec<SmEvidence>,
        sm_fifo_after: Vec<Slot>,
        sm_outbound_h: Option<u32>,
        sm_acked_h: Option<u32>,
    },
    NativeReplacement {
        old: Box<NativeEvidence>,
        replacement: Box<NativeEvidence>,
        row_events: Vec<RowEvent>,
        row_after: Option<Source>,
        replacement_dequeued: Dequeue,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum RowEvent {
    Replace {
        seq: u32,
        recipient_id: Id,
        message_id: Id,
        before_claim_id: Id,
        after_claim_id: Id,
    },
    AuthorityRead {
        seq: u32,
        source: Source,
        current_claim_id: Option<Id>,
        matches: bool,
    },
    Delete {
        seq: u32,
        source: Source,
    },
}

#[derive(Clone, Serialize)]
pub(crate) struct DriverPoll {
    pub(crate) seq: u32,
    pub(crate) result: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum SmPurpose {
    Record,
    Checkpoint,
    Acknowledge { h: u32 },
}
#[derive(Clone, Serialize)]
pub(crate) struct SmScope {
    pub(crate) purpose: SmPurpose,
    pub(crate) session_id: Option<Id>,
    pub(crate) connection_id: Id,
    pub(crate) inbound_h: u32,
    pub(crate) outbound_h: u32,
    pub(crate) acked_h: u32,
    pub(crate) queued: u32,
}
#[derive(Clone, Serialize)]
pub(crate) struct SmBinding {
    pub(crate) session_id: Option<Id>,
    pub(crate) connection_id: Id,
    pub(crate) inbound_h: u32,
    pub(crate) outbound_h: u32,
    pub(crate) acked_h: u32,
    pub(crate) whole: Vec<Option<Source>>,
    pub(crate) acknowledged: Vec<Option<Source>>,
    pub(crate) remaining: Vec<Option<Source>>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum SmHDecision {
    NotRequested,
    Invalid,
    Prefix { count: u32 },
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum SmFact {
    Checkpoint {
        rotations: Vec<Rotation>,
        settled: Vec<Source>,
    },
    UnpersistedAck {
        deleted: Vec<Source>,
        absent_unclaimed: Vec<Source>,
    },
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum SmKnowledge {
    NotRequested,
    NoCommitRequested,
    NoPersistence,
    RollbackCallEntered,
    RollbackKnown,
    CommitCallEntered { fact: SmFact },
    ReceiptKnown { fact: SmFact },
}
#[derive(Clone, Serialize)]
pub(crate) struct SmState {
    pub(crate) scope: SmScope,
    pub(crate) binding: Option<SmBinding>,
    pub(crate) h_decision: SmHDecision,
    pub(crate) knowledge: SmKnowledge,
    pub(crate) appended: bool,
    pub(crate) restored: bool,
    pub(crate) ownership_applied: bool,
    pub(crate) acknowledged_h_applied: Option<u32>,
    pub(crate) notification_attempted: bool,
    pub(crate) capacity_completed: Option<bool>,
    pub(crate) returned_updated: Option<bool>,
    pub(crate) returned_error: bool,
    pub(crate) record_managed_by_sm: Option<bool>,
    pub(crate) terminal: Option<&'static str>,
}
#[derive(Clone, Serialize)]
pub(crate) struct SmPrefix {
    pub(crate) seq: u32,
    pub(crate) state: SmState,
}
#[derive(Serialize)]
pub(crate) struct SmEvidence {
    #[serde(flatten)]
    pub(crate) state: SmState,
    pub(crate) prefixes: Vec<SmPrefix>,
    pub(crate) polls: Vec<DriverPoll>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum MixHandoffResult {
    SmPersisted { session_id: Id },
    BoshPersisted { session_id: Id },
    SocketFenced { connection_id: Id },
    Empty,
    Closed,
}
#[derive(Clone, Serialize)]
pub(crate) struct MixHandoff {
    pub(crate) seq: u32,
    pub(crate) delivery_id: Id,
    pub(crate) result: MixHandoffResult,
}

#[derive(Clone, Serialize)]
pub(crate) struct BoshScope {
    pub(crate) session_id: Id,
    pub(crate) ttl_seconds: u64,
    pub(crate) kind: &'static str,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum BoshTransferKnowledge {
    NoCommitRequested,
    CommitCallEntered { source: Source },
    ReceiptKnown { source: Source },
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshTransferSnapshot {
    pub(crate) source: Source,
    pub(crate) knowledge: BoshTransferKnowledge,
    pub(crate) returned_source: Option<Source>,
    pub(crate) return_matches_receipt: bool,
    pub(crate) local_entered: bool,
    pub(crate) source_applied: bool,
    pub(crate) notification_attempted: bool,
    pub(crate) queue_accepted: Option<bool>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum BoshBindKnowledge {
    NotRequired,
    NoCommitRequested,
    CommitCallEntered { membership: Membership },
    ReceiptKnown { membership: Membership },
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshBindAttempt {
    pub(crate) selected_end: Option<u32>,
    pub(crate) selected_len: u32,
    pub(crate) sources: Option<Vec<Source>>,
    pub(crate) knowledge: BoshBindKnowledge,
    pub(crate) returned: Option<Membership>,
    pub(crate) return_matches: bool,
    pub(crate) superseded_message: Option<Id>,
    pub(crate) restored: bool,
    pub(crate) restore_matches: bool,
    pub(crate) removed_indices: Vec<u32>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshResponseSnapshot {
    pub(crate) rid: u64,
    pub(crate) kind: &'static str,
    pub(crate) lineage: Vec<Option<Source>>,
    pub(crate) removed: Vec<bool>,
    pub(crate) attempts: Vec<BoshBindAttempt>,
    pub(crate) construction_restored: u32,
    pub(crate) exposure_entered: bool,
    pub(crate) responder_calls: u32,
    pub(crate) accepted_responders: u32,
    pub(crate) refused_responders: u32,
    pub(crate) control_calls: u32,
    pub(crate) control_accepted: u32,
    pub(crate) control_refused: u32,
    pub(crate) empty_cache_evictions: u32,
    pub(crate) bookkeeping: bool,
    pub(crate) cached: bool,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshExpected {
    pub(crate) rid: u64,
    pub(crate) membership: Membership,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshRenewSnapshot {
    pub(crate) expected: Option<BoshExpected>,
    pub(crate) knowledge: &'static str,
    pub(crate) returned: bool,
    pub(crate) return_matches: bool,
    pub(crate) ack_issued: bool,
    pub(crate) replay_calls: u32,
    pub(crate) replay_accepted: u32,
    pub(crate) replay_refused: u32,
    pub(crate) replay_bookkeeping: bool,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshAckSnapshot {
    pub(crate) rid: u64,
    pub(crate) knowledge: &'static str,
    pub(crate) deleted: Option<Vec<DeletedSource>>,
    pub(crate) returned: bool,
    pub(crate) return_matches: bool,
    pub(crate) cache_evictions: u32,
    pub(crate) receipt_calls: u32,
    pub(crate) receipts_sent: u32,
    pub(crate) receipts_refused: u32,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshState {
    pub(crate) scope: BoshScope,
    pub(crate) transfers: Vec<BoshTransferSnapshot>,
    pub(crate) responses: Vec<BoshResponseSnapshot>,
    pub(crate) renewals: Vec<BoshRenewSnapshot>,
    pub(crate) acknowledgements: Vec<BoshAckSnapshot>,
    pub(crate) terminal: Option<&'static str>,
    pub(crate) keep_running: Option<bool>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum BoshAssociation {
    Outbound {
        item_index: u32,
        item: Slot,
    },
    Request {
        phase: &'static str,
        rid: u64,
        ack: Option<u64>,
        sid: Option<String>,
        fingerprint_hex: String,
    },
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshPrefix {
    pub(crate) seq: u32,
    pub(crate) state: BoshState,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshOwnerEvidence {
    pub(crate) owner_index: u32,
    pub(crate) association: BoshAssociation,
    #[serde(flatten)]
    pub(crate) state: BoshState,
    pub(crate) prefixes: Vec<BoshPrefix>,
    pub(crate) polls: Vec<DriverPoll>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshTransferCall {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) source: Source,
    pub(crate) returned_source: Option<Source>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshBindCall {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) rid: u64,
    pub(crate) sources: Vec<Source>,
    pub(crate) returned_membership: Option<Membership>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshRenewCall {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) expected: Option<BoshExpected>,
    pub(crate) returned: Option<bool>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshAckCall {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) rid: u64,
    pub(crate) returned: Option<bool>,
}
#[derive(Clone, Serialize)]
#[serde(tag = "kind")]
pub(crate) enum BoshResponseResult {
    Received { body_hex: String },
    Empty,
    Closed,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshResponseReceiver {
    pub(crate) seq: u32,
    pub(crate) owner_index: u32,
    pub(crate) rid: u64,
    pub(crate) phase: &'static str,
    pub(crate) receiver_index: u32,
    pub(crate) result: BoshResponseResult,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshCacheEntry {
    pub(crate) rid: u64,
    pub(crate) fingerprint_hex: String,
    pub(crate) membership: Membership,
    pub(crate) body_hex: String,
    pub(crate) response_bytes: u32,
    pub(crate) replays: u32,
    pub(crate) transport_receipt_count: u32,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshCacheHistory {
    pub(crate) seq: u32,
    pub(crate) entries: Vec<BoshCacheEntry>,
}
#[derive(Clone, Serialize)]
pub(crate) struct BoshTransportReceipt {
    pub(crate) seq: u32,
    pub(crate) item_index: u32,
    pub(crate) result: &'static str,
}
#[derive(Default, Serialize)]
pub(crate) struct BoshEvidence {
    pub(crate) owners: Vec<BoshOwnerEvidence>,
    pub(crate) transfer_calls: Vec<BoshTransferCall>,
    pub(crate) bind_calls: Vec<BoshBindCall>,
    pub(crate) renew_calls: Vec<BoshRenewCall>,
    pub(crate) ack_calls: Vec<BoshAckCall>,
    pub(crate) response_receivers: Vec<BoshResponseReceiver>,
    pub(crate) cache_history: Vec<BoshCacheHistory>,
    pub(crate) fifo_after: Vec<Slot>,
    pub(crate) output_bytes: u32,
    pub(crate) highest_responded: u64,
    pub(crate) mix_handoffs: Vec<MixHandoff>,
    pub(crate) transport_receipts: Vec<BoshTransportReceipt>,
}

/// One bounded observation counter across the case. It records call order;
/// it neither advances futures nor supplies permissions or domain verdicts.
#[derive(Default)]
pub(crate) struct Sequence {
    observations: u32,
    polls: u32,
}
impl Sequence {
    pub(crate) fn next(&mut self) -> u32 {
        assert!(
            (self.observations as usize) < MAX_FACTS,
            "direct observation cap exceeded"
        );
        self.observations += 1;
        self.observations
    }
    pub(crate) fn polled<T>(&mut self, actual: &std::task::Poll<T>) -> DriverPoll {
        assert!(self.polls < 64, "direct driver poll cap exceeded");
        self.polls += 1;
        DriverPoll {
            seq: self.next(),
            result: if actual.is_ready() {
                "Ready"
            } else {
                "Pending"
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Parser-only regressions. These construct no frame, port, runtime owner,
    // application or writer and do not alias the ignored saved-case workload.
    fn error<T: for<'de> Deserialize<'de>>(input: &str) -> String {
        match serde_json::from_str::<T>(input) {
            Ok(_) => panic!("invalid input was accepted"),
            Err(error) => error.to_string(),
        }
    }
    #[test]
    fn empty_tagged_variants_reject_unknown_and_duplicate_keys() {
        assert!(
            error::<RecipientOwner>(r#"{"kind":"None","extra":1}"#).starts_with("unknown field")
        );
        assert!(error::<Drive>(r#"{"kind":"Complete","extra":1}"#).starts_with("unknown field"));
        assert!(
            error::<Transaction>(r#"{"kind":"AccountUnavailable","extra":1}"#)
                .starts_with("unknown field")
        );
        assert!(
            error::<Completion>(r#"{"kind":"ErrorAfterReceipt","extra":1}"#)
                .starts_with("unknown field")
        );
        assert!(
            error::<BoshRecording>(r#"{"kind":"Disabled","extra":1}"#).starts_with("unknown field")
        );
        assert!(error::<RecipientOwner>(r#"{"kind":"None","kind":"None"}"#)
            .starts_with("duplicate field"));
        assert!(serde_json::from_str::<RecipientOwner>(r#"{"kind":"None"}"#).is_ok());
        assert!(serde_json::from_str::<Drive>(r#"{"kind":"Complete"}"#).is_ok());
    }
    #[test]
    fn named_objects_reject_root_and_nested_positional_arrays() {
        assert!(serde_json::from_str::<Case>("[]").is_err());
        assert!(serde_json::from_str::<Original>(
            r#"["00000000-0000-0000-0000-000000000001","x","a","b","c"]"#
        )
        .is_err());
        assert!(serde_json::from_str::<NativeSpec>(r#"{"connection_id":"00000000-0000-0000-0000-000000000003","fence":[],"write":{"chunk_limit":2,"fail_after_accepted_bytes":null,"flush":"Ok"},"ack":{"commit":"Complete","disposition":"Deleted"}}"#).is_err());
        assert!(serde_json::from_str::<RecipientOwner>(
            r#"{"kind":"Native","frame_id":"00000000-0000-0000-0000-000000000001","native":[]}"#
        )
        .is_err());
    }
    #[test]
    fn required_nullable_keeps_null_distinct_from_missing_and_preserves_nested_errors() {
        assert!(serde_json::from_str::<WriteScript>(
            r#"{"chunk_limit":2,"fail_after_accepted_bytes":null,"flush":"Ok"}"#
        )
        .is_ok());
        assert!(error::<WriteScript>(r#"{"chunk_limit":2,"flush":"Ok"}"#).contains("missing field"));
        assert!(error::<Nullable<WriteScript>>(
            r#"{"chunk_limit":2,"chunk_limit":3,"fail_after_accepted_bytes":null,"flush":"Ok"}"#
        )
        .starts_with("duplicate field"));
        assert!(error::<Nullable<WriteScript>>(
            r#"{"chunk_limit":2,"fail_after_accepted_bytes":null,"flush":"Ok","extra":0}"#
        )
        .starts_with("unknown field"));
        assert!(serde_json::from_str::<Nullable<WriteScript>>("[]").is_err());
        assert!(serde_json::from_str::<WriteScript>(
            r#"{"chunk_limit":2,"fail_after_accepted_bytes":false,"flush":"Ok"}"#
        )
        .is_err());
    }
    #[test]
    fn simple_enums_reject_object_forms_at_nested_boundaries() {
        assert!(serde_json::from_str::<Mode>(r#"{"Live":null}"#).is_err());
        assert!(serde_json::from_str::<CommitCut>(r#"{"Complete":null}"#).is_err());
        assert!(serde_json::from_str::<Queue>(r#"{"Empty":null}"#).is_err());
        assert!(serde_json::from_str::<Rearm>(r#"{"Return":null}"#).is_err());
        assert!(serde_json::from_str::<Flush>(r#"{"Ok":null}"#).is_err());
        assert!(serde_json::from_str::<NativeDisposition>(r#"{"Deleted":null}"#).is_err());
        assert!(serde_json::from_str::<Responder>(r#"{"Open":null}"#).is_err());
        assert!(serde_json::from_str::<WriteScript>(
            r#"{"chunk_limit":2,"fail_after_accepted_bytes":null,"flush":{"Ok":null}}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<Completion>(r#"{"kind":"Return","mode":{"Live":null}}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<NativeAck>(
            r#"{"commit":{"Complete":null},"disposition":"Deleted"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Mode>(r#""Live""#).is_ok());
        assert!(serde_json::from_str::<CommitCut>(r#""Complete""#).is_ok());
    }

    #[test]
    fn canonical_primitives_reject_uuid_aliases_nonintegers_and_bad_hex() {
        assert!(serde_json::from_str::<Id>(r#""00000000000000000000000000000001""#).is_err());
        assert!(serde_json::from_str::<Id>(r#""00000000-0000-0000-0000-00000000000A""#).is_err());
        for input in [
            r#"{"chunk_limit":2.0,"fail_after_accepted_bytes":null,"flush":"Ok"}"#,
            r#"{"chunk_limit":true,"fail_after_accepted_bytes":null,"flush":"Ok"}"#,
            r#"{"chunk_limit":-1,"fail_after_accepted_bytes":null,"flush":"Ok"}"#,
        ] {
            assert!(serde_json::from_str::<WriteScript>(input).is_err());
        }
        assert_eq!(unhex("00af").unwrap(), vec![0, 175]);
        for value in ["0", "AF", "0g"] {
            assert!(unhex(value).is_err());
        }
    }
}
