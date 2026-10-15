//! Test-only fixed direct-message input/evidence boundary. This is not an
//! executor, an oracle, a product policy, or a public server entry point.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
};
use uuid::Uuid;

mod case;
mod delivery_evidence;
mod evidence;

pub(crate) use self::delivery_evidence::{
    BoshAckCall, BoshAckSnapshot, BoshAssociation, BoshBindAttempt, BoshBindCall,
    BoshBindKnowledge, BoshCacheEntry, BoshCacheHistory, BoshEvidence, BoshExpected,
    BoshOwnerEvidence, BoshPrefix, BoshRenewCall, BoshRenewSnapshot, BoshResponseReceiver,
    BoshResponseResult, BoshResponseSnapshot, BoshScope, BoshState, BoshTransferCall,
    BoshTransferKnowledge, BoshTransferSnapshot, BoshTransportReceipt, DriverPoll, MixHandoff,
    MixHandoffResult, RecipientEvidence, RowEvent, Sequence, SmBinding, SmEvidence, SmFact,
    SmHDecision, SmKnowledge, SmPrefix, SmPurpose, SmScope, SmState,
};
pub(crate) use self::evidence::{
    emit, AckCall, AdmissionCommit, AdmissionEvidence, AdmissionFact, AdmissionKnowledge,
    AdmissionReturned, ArchiveEvidence, CommitResult, Continuation, Dequeue, DirectEvidence,
    DirectKnowledge, DirectPrepared, DirectReceipt, DirectReturned, Enqueue, Envelope, Execution,
    FlushCall, Handoff, HealthRead, IdentityEvidence, NativeAckKnowledge, NativeEvidence,
    NativeFact, NativePrefix, NativeState, OriginalEvidence, OriginalPrefix, OriginalState,
    PreparedEvidence, Projection, RearmCall, ReceiptObservation, RemoteCall, RouteEvidence, Slot,
    WriteCall,
};

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

#[cfg(test)]
mod tests;
