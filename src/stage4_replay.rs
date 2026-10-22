//! Closed test-only Stage4 input, factual evidence and finite composition dispatcher.
//! Captures actual owner observations; semantic verdicts belong to an independent reader.
//! Production protocol entry points are not selected through this module.
#![cfg(test)]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};
use uuid::Uuid;

// Driving is a separate test-only helper; no dispatcher/entry is defined here.
#[cfg(test)]
mod compact;
pub(crate) mod driver;

pub(crate) fn encode_compact_frame(envelope: &Envelope) -> Result<Vec<u8>, Loss> {
    compact::encode(envelope)
}

pub(crate) fn decode_compact_frame(frame: &[u8]) -> Result<Envelope, Rejection> {
    compact::decode(frame)
}

pub(crate) const CASE_SCHEMA: &str = "northstar-stage4-composition-case-v1";
pub(crate) const EVIDENCE_SCHEMA: &str = "northstar-stage4-composition-evidence-v1";
pub(crate) const ADAPTER_CONTRACT: &str = "local-stage4-composition-controlled-v1";
// Reserved contract spelling. This slice deliberately does not define the entry.
pub(crate) const ENTRY: &str = "stage4_replay::replay_saved_case";
pub(crate) const FRAME_TAG: &str = "NORTHSTAR_STAGE4_COMPOSITION_V1";
pub(crate) const MAX_INPUT: usize = 64 * 1024;
pub(crate) const MAX_FRAME: usize = 128 * 1024;
pub(crate) const MAX_FACTS: usize = 256;
pub(crate) const MAX_POLLS: usize = 64;
pub(crate) const MAX_IDENTITIES: usize = 64;
pub(crate) const MAX_OPAQUE: usize = 16;
pub(crate) const MAX_OWNER_SNAPSHOTS: usize = 16;
pub(crate) const RESPONSE_BYTES: u32 = 16384;
pub(crate) const OUTPUT_BYTES: u32 = 65536;
pub(crate) const MAX_STANZA: usize = 4096;
pub(crate) const MAX_NONPADDING: usize = 16384;
// Finite synthetic service-input bound, not a production lease-policy claim.
pub(crate) const MAX_BINDING_LEASE_SECONDS: u64 = 3600;

// Each nested named record re-enters deserialize_map. No Value conversion can
// erase duplicate keys. The generic form shares data shapes, not domain owners.
macro_rules! object {
    ($name:ident { $($field:ident: $kind:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        pub(crate) struct $name { $(pub(crate) $field: $kind),* }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)] #[serde(deny_unknown_fields)]
                struct Fields { $($field: $kind),* }
                struct Visitor;
                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = $name;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!("a named ", stringify!($name), " object")) }
                    fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<$name, M::Error> {
                        let _fields = Fields::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                        Ok($name { $($field: _fields.$field),* })
                    }
                }
                d.deserialize_map(Visitor)
            }
        }
        impl Walk for $name {
            fn walk(&mut self, _c: &mut LabelContext<'_>, _locus: Introduction) -> Result<(), Loss> {
                $(self.$field.walk(_c, field_locus(stringify!($field)))?;)* Ok(())
            }
        }
    };
}
macro_rules! data_object {
    ($name:ident<$i:ident> { $($field:ident: $kind:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        pub(crate) struct $name<$i> { $(pub(crate) $field: $kind),* }
        impl<'de, $i: Deserialize<'de>> Deserialize<'de> for $name<$i> {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)] #[serde(deny_unknown_fields)]
                struct Fields<$i> { $($field: $kind),* }
                struct Visitor<$i>(std::marker::PhantomData<$i>);
                impl<'de, $i: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<$i> {
                    type Value = $name<$i>;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!("a named ", stringify!($name), " object")) }
                    fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                        let fields = Fields::<$i>::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                        Ok($name { $($field: fields.$field),* })
                    }
                }
                d.deserialize_map(Visitor(std::marker::PhantomData))
            }
        }
        impl<$i: Walk> Walk for $name<$i> {
            fn walk(&mut self, c: &mut LabelContext<'_>, _locus: Introduction) -> Result<(), Loss> {
                $(self.$field.walk(c, field_locus(stringify!($field)))?;)* Ok(())
            }
        }
    };
}
macro_rules! strings {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
        pub(crate) enum $name { $($variant),+ }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let value = String::deserialize(d)?;
                match value.as_str() { $(stringify!($variant) => Ok(Self::$variant),)+ _ => Err(serde::de::Error::unknown_variant(&value, &[$(stringify!($variant)),+])) }
            }
        }
        impl Walk for $name { fn walk(&mut self, _: &mut LabelContext<'_>, _: Introduction) -> Result<(), Loss> { Ok(()) } }
    };
}
// Enforce String on every sum's own tag before derive sees it. This also
// matters beneath serde's ContentDeserializer, whose identifier method accepts
// integer variant indexes. The wrapper streams keys and leaves duplicates for
// the deriving visitor; data is never collapsed into a serde_json::Value map.
struct StringTagMap<M> {
    inner: M,
    tag: bool,
}
impl<M> StringTagMap<M> {
    fn new(inner: M) -> Self {
        Self { inner, tag: false }
    }
}
impl<'de, M: serde::de::MapAccess<'de>> serde::de::MapAccess<'de> for StringTagMap<M> {
    type Error = M::Error;
    fn next_key_seed<K: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        match self.inner.next_key::<String>()? {
            None => Ok(None),
            Some(key) => {
                self.tag = key == "kind";
                seed.deserialize(serde::de::value::StringDeserializer::<M::Error>::new(key))
                    .map(Some)
            }
        }
    }
    fn next_value_seed<V: serde::de::DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        if self.tag {
            let tag = self.inner.next_value::<String>()?;
            seed.deserialize(serde::de::value::StringDeserializer::<M::Error>::new(tag))
        } else {
            self.inner.next_value_seed(seed)
        }
    }
    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}
// Adjacently tagged sums always have an explicit named-record data value,
// including Empty. Empty variants therefore reject both omitted data and extras.
// Optional invocation metadata is scoped to the wire enum and its decode enum.
// Unmarked invocations retain the default lint policy.
macro_rules! sum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident($kind:ty)),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(tag = "kind", content = "data", deny_unknown_fields)]
        pub(crate) enum $name { $($variant($kind)),+ }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                // Internally tagged named variants use an identifier visitor
                // for kind. Adjacent-tag derive would accept {"V":null} tags.
                $(#[$meta])*
                #[derive(Deserialize)] #[serde(tag = "kind", deny_unknown_fields)]
                enum Fields { $($variant { data: $kind }),+ }
                struct Visitor;
                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = $name;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!("a tagged ", stringify!($name), " object")) }
                    fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                        match Fields::deserialize(serde::de::value::MapAccessDeserializer::new(StringTagMap::new(map)))? { $(Fields::$variant { data } => Ok($name::$variant(data))),+ }
                    }
                }
                d.deserialize_map(Visitor)
            }
        }
        impl Walk for $name { fn walk(&mut self, c: &mut LabelContext<'_>, l: Introduction) -> Result<(), Loss> { match self { $(Self::$variant(x) => x.walk(c, l)),+ } } }
    };
}
macro_rules! data_sum {
    ($(#[$meta:meta])* $name:ident<$i:ident> { $($variant:ident($kind:ty)),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(tag = "kind", content = "data", deny_unknown_fields)]
        pub(crate) enum $name<$i> { $($variant($kind)),+ }
        impl<'de, $i: Deserialize<'de>> Deserialize<'de> for $name<$i> {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                $(#[$meta])*
                #[derive(Deserialize)] #[serde(tag = "kind", deny_unknown_fields)]
                enum Fields<$i> { $($variant { data: $kind }),+ }
                struct Visitor<$i>(std::marker::PhantomData<$i>);
                impl<'de, $i: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<$i> {
                    type Value = $name<$i>;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(concat!("a tagged ", stringify!($name), " object")) }
                    fn visit_map<M: serde::de::MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                        match Fields::<$i>::deserialize(serde::de::value::MapAccessDeserializer::new(StringTagMap::new(map)))? { $(Fields::$variant { data } => Ok($name::$variant(data))),+ }
                    }
                }
                d.deserialize_map(Visitor(std::marker::PhantomData))
            }
        }
        impl<$i: Walk> Walk for $name<$i> { fn walk(&mut self, c: &mut LabelContext<'_>, l: Introduction) -> Result<(), Loss> { match self { $(Self::$variant(x) => x.walk(c, l)),+ } } }
    };
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Text<const N: usize>(String);
impl<const N: usize> Text<N> {
    pub(crate) fn new(s: impl Into<String>) -> Result<Self, Rejection> {
        let s = s.into();
        if s.len() > N || s.contains('\0') {
            return Err(Rejection::Bound);
        }
        Ok(Self(s))
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de, const N: usize> Deserialize<'de> for Text<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Hex<const N: usize>(String);
impl<const N: usize> Hex<N> {
    pub(crate) fn new(s: String) -> Result<Self, Rejection> {
        if s.len() != N * 2
            || !s
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Rejection::Encoding);
        }
        Ok(Self(s))
    }
    pub(crate) fn of(bytes: &[u8]) -> Result<Self, Rejection> {
        Self::new(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
}
impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Bytes<const N: usize>(String);
impl<const N: usize> Bytes<N> {
    pub(crate) fn new(s: String) -> Result<Self, Rejection> {
        if s.len() > N * 2
            || !s.len().is_multiple_of(2)
            || !s
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Rejection::Encoding);
        }
        Ok(Self(s))
    }
    pub(crate) fn of(bytes: &[u8]) -> Result<Self, Rejection> {
        Self::new(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
    pub(crate) fn as_hex(&self) -> &str {
        &self.0
    }
}
impl<'de, const N: usize> Deserialize<'de> for Bytes<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct List<T, const N: usize>(Vec<T>);
impl<T, const N: usize> List<T, N> {
    pub(crate) fn new(values: Vec<T>) -> Result<Self, Rejection> {
        if values.len() > N {
            Err(Rejection::Bound)
        } else {
            Ok(Self(values))
        }
    }
    pub(crate) fn as_slice(&self) -> &[T] {
        &self.0
    }
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for List<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Visitor<T, N> {
            type Value = List<T, N>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "at most {N} entries")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while values.len() < N {
                    match a.next_element()? {
                        Some(v) => values.push(v),
                        None => return Ok(List(values)),
                    }
                }
                if a.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("array cap exceeded"));
                }
                Ok(List(values))
            }
        }
        d.deserialize_seq(Visitor(std::marker::PhantomData))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Id(pub(crate) Uuid);
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let u = Uuid::parse_str(&s).map_err(serde::de::Error::custom)?;
        if u.to_string() != s {
            return Err(serde::de::Error::custom("noncanonical UUID"));
        }
        Ok(Self(u))
    }
}
// A missing field is not null. Forward directly rather than through Value or
// an untagged deserialization trial, which could obscure duplicate-key errors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub(crate) enum Nullable<T> {
    Value(T),
    Null(()),
}
impl<T> Nullable<T> {
    pub(crate) fn get(&self) -> Option<&T> {
        match self {
            Self::Value(v) => Some(v),
            Self::Null(()) => None,
        }
    }
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Visitor<T> {
            type Value = Nullable<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("required value or explicit null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(Nullable::Null(()))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::BoolDeserializer::<E>::new(v)).map(Nullable::Value)
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::U64Deserializer::<E>::new(v)).map(Nullable::Value)
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::I64Deserializer::<E>::new(v)).map(Nullable::Value)
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::StrDeserializer::<E>::new(v)).map(Nullable::Value)
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                T::deserialize(serde::de::value::StringDeserializer::<E>::new(v))
                    .map(Nullable::Value)
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                v: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(v)).map(Nullable::Value)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                v: A,
            ) -> Result<Self::Value, A::Error> {
                T::deserialize(serde::de::value::SeqAccessDeserializer::new(v)).map(Nullable::Value)
            }
        }
        d.deserialize_any(Visitor(std::marker::PhantomData))
    }
}
type Short = Text<256>;
type Jid = Text<1024>;
type Stanza = Text<MAX_STANZA>;
type Sha256 = Hex<32>;
object!(Empty {});
strings!(Rejection {
    TooLarge,
    Json,
    Schema,
    Bound,
    Encoding,
    Relationship,
    Unsupported
});
impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Rejection {}
strings!(CommitCut {
    Complete,
    Pending,
    Error
});
strings!(TransportKind { Tcp, Bosh });
strings!(CredentialKind {
    Binding,
    UnboundFast
});
strings!(FlushReply { Ok, Error });
strings!(Responder { Open, Dropped });
strings!(EndpointCut { Return, Pending });
strings!(MucDrive {
    Complete,
    DropCommit,
    DropSecondEndpoint
});
strings!(AuthDrive {
    Complete,
    DropPublicationCommit
});
// Only initial active routes are supplied. Later raw lifecycle observations
// remain actual output facts; state 2 is SupersededBySm, not "Closed".
strings!(Lifecycle { Active });
strings!(CapabilityFeature { MixCore, MixPam });
object!(Frame {
    frame_id: Id,
    connection_id: Id,
    transport: TransportKind,
    input: Stanza
});
object!(WriteScript { chunk_limit: u32, fail_after_accepted_bytes: Nullable<u32>, flush: FlushReply });
data_object!(MixSource<I> { delivery_id: I, lease_token: I });
data_object!(C2sSource<I> { recipient_id: I, message_id: I, claim_id: Nullable<I> });
data_sum!(Source<I> { C2s(C2sSource<I>), Mix(MixSource<I>) });
data_object!(Membership<I> { c2s_message_ids: List<I, 2>, mix_delivery_ids: List<I, 1> });
object!(Governor {
    max_bytes: u32,
    max_recovery_bytes: u32,
    max_recovery_jobs: u32,
    max_snapshot_bytes: u32
});
object!(PlainNative {
    connection_id: Id,
    write: WriteScript
});
object!(DurableNative { connection_id: Id, write: WriteScript, returned_fence: MixSource<Id>, ack_commit: CommitCut });
object!(BoshReply { commit: CommitCut, membership: Membership<Id> });
object!(BoshTransferReply { commit: CommitCut, returned_source: MixSource<Id> });
object!(BoshRequest { rid: u64, fingerprint: Sha256, request_xml: Stanza, content_type: Short, responders: List<Responder, 2> });
object!(BoshSessionInput {
    connection_id: Id,
    session_id: Id,
    ttl_seconds: u64,
    max_response_bytes: u32,
    max_output_bytes: u32,
    governor: Governor,
    response: BoshRequest,
    bind: BoshReply
});
object!(BoshAckInput { request: BoshRequest, acknowledged_rid: u64, renewal: CommitCut, commit: CommitCut, deleted: MixSource<Id> });
object!(MixBoshTransport { session: BoshSessionInput, transfer: BoshTransferReply, ack: Nullable<BoshAckInput> });
// Only the accepted local, nonclustered authority shape is selectable. Every
// field of the actual authority is retained; cluster_target must be null here.
data_object!(ClusterTarget<I> { room_id: I, room_epoch: I, occupant_incarnation: I, occupancy_epoch: i64, full_jid: Jid, nick: Short, connection_uuid: I, connection_epoch: i64 });
data_object!(LocalPrincipal<I> { user_id: I, local_domain: Short });
object!(FederatedPrincipal {
    bare_jid: Jid,
    authenticated_domain: Short
});
data_sum!(MucPrincipal<I> { Local(LocalPrincipal<I>), Federated(FederatedPrincipal) });
data_object!(Authority<I> { clustered: bool, expected_room_epoch: I, principal: MucPrincipal<I>, actor_scope: Jid, full_jid: Jid, nick: Short, occupant_incarnation: I, connection_uuid: I, expected_role: Short, expected_affiliation: Short, cluster_target: Nullable<ClusterTarget<I>> });
data_object!(MucCommand<I> { id: I, room_id: I, actor_scope: Jid, origin_id: Nullable<Short>, sender_jid: Jid, nick: Short, stanza: Stanza, encrypted: bool, archive: bool, retention_days: i64, authority: Authority<I> });
object!(AdmissionFenceInput { admission_key: Hex<32>, payload_mac: Hex<32>, lease_token: Id, dedupe_digest: Hex<32> });
object!(AdmissionRequirement {
    action: Short,
    step: u32,
    work_factor: u64,
    max_work_factor: u64,
    hard_wait_seconds: u64,
    retry_after_seconds: u64,
    cooldown_seconds: u64,
    approximate_max_device_seconds: u64,
    notice: Short
});
object!(RatedAdmission {
    fence: AdmissionFenceInput,
    requirement: AdmissionRequirement,
    begin_commit: CommitCut,
    finalize_commit: CommitCut
});
object!(MucRepository { original_id: Nullable<Id>, commit: CommitCut });
object!(RecipientInput {
    user_id: Id,
    full_jid: Jid,
    connection_id: Id,
    blocked: bool,
    endpoint: EndpointCut
});
object!(MucInput { frame: Frame, configured_domain: Short, command: MucCommand<Id>, admission: RatedAdmission, repository: MucRepository, recipients: List<RecipientInput, 2>, native: Nullable<PlainNative>, drive: MucDrive });

// Input includes construction inputs and literal public XML, never a receipt,
// control identity, bearer, owner capability, expected return or verdict.
object!(BoundControlInput {
    iq_id: Short,
    full_jid: Jid,
    xml: Stanza
});
object!(UnboundControlInput {
    authorization_identifier: Jid,
    xml: Stanza
});
sum!(ControlInput { Binding(BoundControlInput), UnboundFast(UnboundControlInput) });
// PreparedCredential::binding and BindingPublication use a u64 duration.
// This is neither an identity nor a reservation/receipt capability.
object!(BindingInput {
    resource: Short,
    lease_seconds: u64,
    full_jid: Jid
});
// Explicit supplied stage hint, independent of the later publication epoch.
// StagedLoginEpoch.operation_id remains generated and observed, never an input.
object!(CredentialPreparationInput { generation_allowed: bool, binding_reserved: bool, stage_present: bool, stage_epoch: Nullable<i64>, commit: CommitCut });
object!(EpochReply { epoch: Nullable<i64> });
sum!(PublicationReply { NoSql(Empty), Committed(EpochReply), BackendError(Empty), CommitPending(EpochReply) });
object!(AuthInput { frame: Frame, user_id: Id, auth_generation: i64, device_id: Nullable<Id>, ordinal: u8, credential_kind: CredentialKind, binding: Nullable<BindingInput>, preparation: CredentialPreparationInput, control: ControlInput, publication: PublicationReply, notification_expected: bool });
object!(ReplayIdentityInput { client_id: Short, canonical_semantics: Bytes<4096> });
data_object!(MixIngress<I> { channel_id: I, channel_jid: Jid, actor_bare: Jid, actor_full: Jid, children: Stanza, encrypted: bool, identity: Nullable<ReplayIdentityInput> });
data_object!(MixStoreCommand<I> { channel_id: I, actor: Jid, item_id: I, payload: Stanza, identity: Nullable<ReplayIdentityInput>, delivery_payload: Stanza, visible_jid: Nullable<Jid>, encrypted: bool });
data_object!(Participant<I> { participant_id: I, jid: Jid, nick: Nullable<Short> });
data_object!(RecipientProjection<I> { participant: Participant<I>, delivery_id: I, sequence: i64 });
data_object!(DeliveryProjection<I> { event_id: I, channel_id: I, channel_jid: Jid, stanza_template: Stanza, authoritative_stanza_id: Nullable<I>, archive: bool, encrypted: bool, recipients: List<RecipientProjection<I>, 2> });
data_object!(Stored<I> { authoritative_id: I, storage_id: I, channel_id: I, channel_jid: Jid, projection: Nullable<DeliveryProjection<I>> });
data_object!(Existing<I> { authoritative_id: I, semantic_key_id: Short, semantic_mac: Bytes<64>, target_id: Nullable<I> });
object!(FreshForeground { frame: Frame, configured_domain: Short, ingress: MixIngress<Id>, command: MixStoreCommand<Id>, stored: Stored<Id>, commit: CommitCut });
object!(ReplayForeground { frame: Frame, configured_domain: Short, ingress: MixIngress<Id>, existing: Existing<Id>, original_id: Id });
data_object!(DeliveryRow<I> { source: MixSource<I>, event_id: I, channel_id: I, channel_jid: Jid, participant_id: I, recipient_jid: Jid, recipient_nick: Nullable<Short>, stanza: Stanza, authoritative_stanza_id: Nullable<I>, archive: bool, encrypted: bool, attempt_count: i32, route_wake_generation: i64 });
object!(FreshProjectionOrigin {
    foreground_frame: Id,
    recipient_ordinal: u8,
    declared_delivery_id: Id
});
sum!(ClaimOrigin { FreshProjection(FreshProjectionOrigin), InitialDurableRow(DeliveryRow<Id>) });
object!(ArchiveReplayInput {
    original_archive_id: Id
});
sum!(ArchiveReply { StoreCandidate(Empty), Replay(ArchiveReplayInput) });
object!(ArchiveInput {
    reply: ArchiveReply,
    commit: CommitCut
});
object!(ClaimInput {
    limit: i64,
    max_bytes: i64,
    lease_token: Id,
    attempt_count: i32,
    route_wake_generation: i64,
    commit: CommitCut
});
object!(ActivatedRoute { frame_id: Id });
sum!(RouteProvenance { InitiallyPublished(Empty), ActivatedByAuth(ActivatedRoute) });
object!(CapsInput { connection_id: Id, generation: u64, verified_features: List<CapabilityFeature, 2> });
object!(RouteInput {
    full_jid: Jid,
    user_id: Id,
    connection_id: Id,
    auth_generation: i64,
    routable: bool,
    disconnected: bool,
    lifecycle: Lifecycle,
    caps: CapsInput,
    provenance: RouteProvenance
});
object!(RouteEnvironment { enabled_account_id: Id, privacy_blocked: bool, targets: List<RouteInput, 2>, queue_capacity: u8 });
object!(WorkerAttemptInput {
    claim: ClaimInput,
    archive: ArchiveInput,
    route: RouteEnvironment
});
object!(WorkerInput {
    origin: ClaimOrigin,
    attempt: WorkerAttemptInput
});
object!(FreshMixNativeInput {
    auth: AuthInput,
    auth_native: PlainNative,
    foreground: FreshForeground,
    worker: WorkerInput,
    delivery_native: DurableNative
});
object!(ReplayMixBoshLane {
    foreground: ReplayForeground,
    worker: WorkerInput,
    transport: MixBoshTransport
});
// P is a single literal tied to U and a frozen wrapper. There is no command,
// repeat count, arbitrary padding alphabet or user-selected selector program.
object!(FixedAuthPadding { presence_xml: Text<16384>, features_xml: Stanza });
object!(QueuedAuthLane {
    unbound: AuthInput,
    bound: AuthInput,
    session: BoshSessionInput,
    padding: FixedAuthPadding
});
object!(ReplayMixQueuedAuth {
    mix: ReplayMixBoshLane,
    auth: QueuedAuthLane
});
object!(RecoveryInput {
    worker: WorkerInput,
    replacement: WorkerAttemptInput,
    native: DurableNative
});
object!(DeferInput {
    worker: WorkerInput,
    settlement_commit: CommitCut,
    updated: bool
});
object!(NativeAuthInput {
    auth: AuthInput,
    native: PlainNative,
    drive: AuthDrive
});
object!(IndependentMixLane {
    worker: WorkerInput,
    transport: MixBoshTransport
});
object!(BoshAuthLane {
    bound: AuthInput,
    session: BoshSessionInput,
    drive: AuthDrive
});
// S11/S13 have the identical auth subtree. Null mix is the only structural
// deletion. A descriptive case_id can be identical across these literal files.
object!(BoshAuthInput { mix: Nullable<IndependentMixLane>, auth: BoshAuthLane });
sum!(
    #[expect(
        clippy::large_enum_variant,
        reason = "Finite test-only composition DTOs retain inline representation; measured memory fit remains required"
    )]
    Composition { Muc(MucInput), AuthThenMixNative(FreshMixNativeInput), ReplayMixQueuedAuth(ReplayMixQueuedAuth), MixRecoveryNative(RecoveryInput), MixDefer(DeferInput), NativeAuth(NativeAuthInput), BoshAuth(BoshAuthInput) }
);
object!(Case { schema: Text<64>, case_id: Text<64>, adapter_contract: Text<64>, composition: Composition });

pub(crate) struct ValidatedCase {
    case: Case,
    fixed_ids: BTreeSet<Uuid>,
    input_sha256: Sha256,
}
impl ValidatedCase {
    pub(crate) fn case(&self) -> &Case {
        &self.case
    }
}
pub(crate) fn read_input(reader: impl Read) -> Result<Vec<u8>, Rejection> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Rejection::Encoding)?;
    if bytes.len() > MAX_INPUT {
        return Err(Rejection::TooLarge);
    }
    Ok(bytes)
}
pub(crate) fn decode(bytes: &[u8]) -> Result<ValidatedCase, Rejection> {
    if bytes.len() > MAX_INPUT {
        return Err(Rejection::TooLarge);
    }
    let case: Case = serde_json::from_slice(bytes).map_err(|_| Rejection::Json)?;
    case.validate()?;
    case.validate_actors()?;
    let mut input = case.clone();
    let mut labels = IdentityMap::default();
    input
        .walk(
            &mut LabelContext {
                identities: &mut labels,
                seq: 0,
            },
            Introduction::UnexpectedObservedIdentity,
        )
        .map_err(|_| Rejection::Bound)?;
    let frame_limit = if matches!(case.composition, Composition::ReplayMixQueuedAuth(_)) {
        3
    } else {
        2
    };
    require(
        labels.input_frames.len() <= frame_limit
            && labels.input_connections.len() <= 2
            && labels.input_sessions.len() <= 2,
    )?;
    require(case.nonpadding_bytes() <= MAX_NONPADDING)?;
    Ok(ValidatedCase {
        case,
        fixed_ids: labels.fixed,
        input_sha256: sha256(bytes),
    })
}
fn require(value: bool) -> Result<(), Rejection> {
    if value {
        Ok(())
    } else {
        Err(Rejection::Relationship)
    }
}
fn full_jid(value: &Jid) -> Result<String, Rejection> {
    let jid = northstar_xmpp_types::CanonicalJid::parse(value.as_str())
        .map_err(|_| Rejection::Encoding)?;
    require(
        jid.localpart().is_some()
            && jid.resourcepart().is_some()
            && jid.to_string() == value.as_str(),
    )?;
    Ok(jid.bare().to_owned())
}
fn bare_jid(value: &Jid) -> Result<(), Rejection> {
    let jid = northstar_xmpp_types::CanonicalJid::parse(value.as_str())
        .map_err(|_| Rejection::Encoding)?;
    require(
        jid.localpart().is_some()
            && jid.resourcepart().is_none()
            && jid.to_string() == value.as_str(),
    )
}
fn xml(value: &str) -> Result<roxmltree::Document<'_>, Rejection> {
    roxmltree::Document::parse(value).map_err(|_| Rejection::Encoding)
}
fn write_plan(plan: &WriteScript, item_len: usize) -> Result<(), Rejection> {
    require(plan.chunk_limit > 0 && plan.chunk_limit as usize <= MAX_STANZA)?;
    let calls = item_len.div_ceil(plan.chunk_limit as usize);
    // All saved native paths require real successful write/flush. Failure
    // scripts remain outside this finite inventory's input language.
    require(
        calls <= 32
            && plan.fail_after_accepted_bytes.get().is_none()
            && plan.flush == FlushReply::Ok,
    )
}
fn auth_xml(auth: &AuthInput) -> &str {
    match &auth.control {
        ControlInput::Binding(c) => c.xml.as_str(),
        ControlInput::UnboundFast(c) => c.xml.as_str(),
    }
}
fn validate_auth(
    auth: &AuthInput,
    kind: CredentialKind,
    transport: TransportKind,
) -> Result<(), Rejection> {
    // The finite auth bridge does not capture NotificationIntent. Reject that
    // requested scope here, before owners, so rejected-envelope validation and
    // the adapter agree. Never silently clear it or infer it from an epoch.
    if auth.notification_expected {
        return Err(Rejection::Unsupported);
    }
    // Every saved auth frame owns exactly one actual credential invocation.
    // The frame assigns ordinal zero even when another frame owns a control.
    require(
        auth.credential_kind == kind
            && auth.frame.transport == transport
            && auth.ordinal == 0
            && auth.auth_generation >= 0,
    )?;
    require(auth.preparation.generation_allowed && auth.preparation.commit == CommitCut::Complete)?;
    require(auth.preparation.stage_epoch.get().is_some() == auth.preparation.stage_present)?;
    // db/authentication.rs:144–170 derives Some(epoch) only from a staged login;
    // lines 196–205 pass that presence through COMMIT and the returned result.
    // Validate supplied reply shape only. No epoch value is matched to a hint,
    // and actual returned observation values remain independently retained.
    match &auth.publication {
        PublicationReply::Committed(reply) | PublicationReply::CommitPending(reply) => {
            require(reply.epoch.get().is_some() == auth.preparation.stage_present)?
        }
        _ => {}
    }
    xml(auth.frame.input.as_str())?;
    let doc = xml(auth_xml(auth))?;
    let root = doc.root_element();
    match (&auth.control, kind, auth.binding.get()) {
        (ControlInput::Binding(c), CredentialKind::Binding, Some(binding)) => {
            full_jid(&c.full_jid)?;
            require(
                c.full_jid == binding.full_jid
                    && !binding.resource.as_str().is_empty()
                    && (1..=MAX_BINDING_LEASE_SECONDS).contains(&binding.lease_seconds),
            )?;
            require(
                c.full_jid
                    .as_str()
                    .rsplit_once('/')
                    .is_some_and(|(_, r)| r == binding.resource.as_str()),
            )?;
            require(
                auth.preparation.binding_reserved
                    && auth.preparation.stage_present == auth.device_id.get().is_some(),
            )?;
            // None means actual stage_returned(Ok(None)), Stage::Absent and no
            // stage operation ID. Some requests a reply matched to the actual
            // invocation's device/user/connection/generation and newly generated
            // stage operation ID; it never supplies a stage identity as authority.
            require(
                root.tag_name().name() == "iq"
                    && root.tag_name().namespace() == Some("jabber:client")
                    && root.attributes().len() == 2
                    && root.attribute("id") == Some(c.iq_id.as_str())
                    && root.attribute("type") == Some("result"),
            )?;
            let children: Vec<_> = root.children().filter(|n| n.is_element()).collect();
            require(
                children.len() == 1
                    && children[0].tag_name().name() == "bind"
                    && children[0].tag_name().namespace()
                        == Some("urn:ietf:params:xml:ns:xmpp-bind")
                    && children[0].attributes().len() == 0,
            )?;
            let jids: Vec<_> = children[0].children().filter(|n| n.is_element()).collect();
            require(
                jids.len() == 1
                    && jids[0].tag_name().name() == "jid"
                    && jids[0].tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-bind")
                    && jids[0].attributes().len() == 0
                    && jids[0].children().all(|n| n.is_text())
                    && jids[0].text() == Some(c.full_jid.as_str()),
            )?;
        }
        (ControlInput::UnboundFast(c), CredentialKind::UnboundFast, None) => {
            bare_jid(&c.authorization_identifier)?;
            // The saved U path is the narrower no-device/no-stage/no-bearer
            // NoSQL path. Other FAST stage shapes remain outside this grammar.
            require(
                auth.device_id.get().is_none()
                    && !auth.preparation.binding_reserved
                    && !auth.preparation.stage_present
                    && !auth.notification_expected,
            )?;
            require(
                root.tag_name().name() == "success"
                    && root.tag_name().namespace() == Some("urn:xmpp:sasl:2")
                    && root.attributes().len() == 0,
            )?;
            let children: Vec<_> = root.children().filter(|n| n.is_element()).collect();
            require(
                children.len() == 1
                    && children[0].tag_name().name() == "authorization-identifier"
                    && children[0].tag_name().namespace() == Some("urn:xmpp:sasl:2")
                    && children[0].attributes().len() == 0
                    && children[0].children().all(|n| n.is_text())
                    && children[0].text() == Some(c.authorization_identifier.as_str()),
            )?;
            require(matches!(auth.publication, PublicationReply::NoSql(_)))?;
        }
        _ => return Err(Rejection::Relationship),
    }
    // These controlled paths never issue a bearer or include token extensions.
    require(!auth_xml(auth).contains("<token") && !auth_xml(auth).contains("<additional-data"))
}
fn validate_request(request: &BoshRequest, session: Id) -> Result<(), Rejection> {
    require(request.rid > 0 && request.responders.as_slice().contains(&Responder::Open))?;
    require(request.fingerprint == sha256(request.request_xml.as_str().as_bytes()))?;
    let doc = xml(request.request_xml.as_str())?;
    let body = doc.root_element();
    require(
        body.tag_name().name() == "body"
            && body.tag_name().namespace() == Some("http://jabber.org/protocol/httpbind"),
    )?;
    require(body.attribute("rid").and_then(|v| v.parse::<u64>().ok()) == Some(request.rid))?;
    require(body.attribute("sid") == Some(session.0.to_string().as_str()))
}
fn validate_session(session: &BoshSessionInput) -> Result<(), Rejection> {
    require(
        session.max_response_bytes == RESPONSE_BYTES
            && session.max_output_bytes == OUTPUT_BYTES
            && session.ttl_seconds > 0
            && session.ttl_seconds <= 3600,
    )?;
    require(
        session.governor.max_bytes >= OUTPUT_BYTES
            && session.governor.max_bytes <= 1024 * 1024
            && session.governor.max_recovery_bytes <= 1024 * 1024
            && session.governor.max_recovery_jobs <= 2
            && session.governor.max_snapshot_bytes <= 1024 * 1024,
    )?;
    // Actual SmMemoryGovernor::new constructor relationships.
    require(
        session.governor.max_recovery_jobs > 0
            && session.governor.max_bytes >= session.governor.max_snapshot_bytes
            && session.governor.max_recovery_bytes >= session.governor.max_snapshot_bytes,
    )?;
    require(session.bind.commit == CommitCut::Complete)?;
    validate_request(&session.response, session.session_id)
}
fn validate_route(route: &RouteEnvironment) -> Result<(), Rejection> {
    require((1..=2).contains(&route.queue_capacity))?;
    let mut keys = BTreeSet::new();
    for entry in route.targets.as_slice() {
        full_jid(&entry.full_jid)?;
        require(
            keys.insert(entry.full_jid.as_str())
                && entry.user_id == route.enabled_account_id
                && entry.auth_generation >= 0,
        )?;
        require(entry.caps.connection_id == entry.connection_id)?;
        let unique: BTreeSet<_> = entry.caps.verified_features.as_slice().iter().collect();
        require(unique.len() == entry.caps.verified_features.len())?;
        match &entry.provenance {
            RouteProvenance::InitiallyPublished(_) => require(entry.routable)?,
            RouteProvenance::ActivatedByAuth(_) => require(!entry.routable)?,
        }
    }
    Ok(())
}
fn validate_worker(worker: &WorkerInput) -> Result<(), Rejection> {
    validate_attempt(&worker.attempt)?;
    if let ClaimOrigin::InitialDurableRow(row) = &worker.origin {
        bare_jid(&row.channel_jid)?;
        bare_jid(&row.recipient_jid)?;
        xml(row.stanza.as_str())?;
        require(
            row.source.lease_token == worker.attempt.claim.lease_token
                && row.attempt_count == worker.attempt.claim.attempt_count
                && row.route_wake_generation == worker.attempt.claim.route_wake_generation,
        )?;
        require(row.archive && row.authoritative_stanza_id.get().is_some())?;
        for target in worker.attempt.route.targets.as_slice() {
            require(full_jid(&target.full_jid)? == row.recipient_jid.as_str())?;
        }
    }
    Ok(())
}
fn validate_attempt(attempt: &WorkerAttemptInput) -> Result<(), Rejection> {
    require(
        attempt.claim.limit == 1
            && attempt.claim.max_bytes > 0
            && attempt.claim.max_bytes <= MAX_STANZA as i64
            && attempt.claim.attempt_count >= 0
            && attempt.claim.route_wake_generation >= 0,
    )?;
    require(
        attempt.claim.commit == CommitCut::Complete
            && attempt.archive.commit == CommitCut::Complete,
    )?;
    validate_route(&attempt.route)
}
fn delivered_environment(environment: &RouteEnvironment) -> Result<(), Rejection> {
    require(!environment.privacy_blocked && environment.targets.len() == 1)?;
    let target = &environment.targets.as_slice()[0];
    require(
        !target.disconnected
            && target.lifecycle == Lifecycle::Active
            && !target.caps.verified_features.is_empty(),
    )
}
fn validate_mix_transport(
    worker: &WorkerInput,
    transport: &MixBoshTransport,
    with_ack: bool,
) -> Result<(), Rejection> {
    validate_session(&transport.session)?;
    delivered_environment(&worker.attempt.route)?;
    require(
        transport.transfer.commit == CommitCut::Complete
            && transport.session.bind.commit == CommitCut::Complete,
    )?;
    let delivery = match &worker.origin {
        ClaimOrigin::FreshProjection(p) => p.declared_delivery_id,
        ClaimOrigin::InitialDurableRow(r) => r.source.delivery_id,
    };
    require(transport.transfer.returned_source.delivery_id == delivery)?;
    require(
        transport.session.bind.membership.c2s_message_ids.is_empty()
            && transport
                .session
                .bind
                .membership
                .mix_delivery_ids
                .as_slice()
                == [delivery],
    )?;
    require(
        worker
            .attempt
            .route
            .targets
            .as_slice()
            .iter()
            .any(|r| r.connection_id == transport.session.connection_id),
    )?;
    require(transport.ack.get().is_some() == with_ack)?;
    if let Some(ack) = transport.ack.get() {
        validate_request(&ack.request, transport.session.session_id)?;
        require(
            ack.acknowledged_rid == transport.session.response.rid
                && ack.request.rid > ack.acknowledged_rid
                && ack.deleted == transport.transfer.returned_source,
        )?;
        let doc = xml(ack.request.request_xml.as_str())?;
        require(
            doc.root_element()
                .attribute("ack")
                .and_then(|v| v.parse::<u64>().ok())
                == Some(ack.acknowledged_rid),
        )?;
        require(ack.commit == CommitCut::Complete && ack.renewal == CommitCut::Complete)?;
    }
    Ok(())
}
const P_OPEN: &str = "<presence><status>";
const P_CLOSE: &str = "</status></presence>";
const FIXED_FEATURES: &str = "<stream:features xmlns:stream=\"http://etherx.jabber.org/streams\"/>";
fn validate_padding(
    padding: &FixedAuthPadding,
    unbound: &AuthInput,
    bound: &AuthInput,
) -> Result<(), Rejection> {
    let u = auth_xml(unbound).len();
    let b = auth_xml(bound).len();
    let target = (RESPONSE_BYTES as usize)
        .checked_sub(256 + u)
        .ok_or(Rejection::Bound)?;
    let count = target
        .checked_sub(P_OPEN.len() + P_CLOSE.len())
        .ok_or(Rejection::Bound)?;
    let p = padding.presence_xml.as_str();
    require(p.len() == target && p.starts_with(P_OPEN) && p.ends_with(P_CLOSE))?;
    require(
        p[P_OPEN.len()..p.len() - P_CLOSE.len()]
            .bytes()
            .all(|x| x == b'x')
            && count <= 16384,
    )?;
    require(
        padding.features_xml.as_str() == FIXED_FEATURES
            && b + 256 <= RESPONSE_BYTES as usize
            && u + 256 <= RESPONSE_BYTES as usize,
    )
}
fn validate_muc(muc: &MucInput) -> Result<(), Rejection> {
    let c = &muc.command;
    let a = &c.authority;
    let MucPrincipal::Local(principal) = &a.principal else {
        return Err(Rejection::Unsupported);
    };
    require(
        muc.frame.transport == TransportKind::Tcp
            && c.retention_days >= 0
            && c.retention_days <= 3650,
    )?;
    require(
        !a.clustered
            && a.cluster_target.get().is_none()
            && a.connection_uuid == muc.frame.connection_id,
    )?;
    require(
        c.actor_scope == a.actor_scope
            && c.sender_jid == a.full_jid
            && c.nick == a.nick
            && principal.local_domain == muc.configured_domain,
    )?;
    bare_jid(&c.actor_scope)?;
    require(full_jid(&c.sender_jid)? == c.actor_scope.as_str())?;
    require(
        northstar_xmpp_types::CanonicalJid::parse(c.actor_scope.as_str())
            .map_err(|_| Rejection::Encoding)?
            .domainpart()
            == muc.configured_domain.as_str(),
    )?;
    xml(c.stanza.as_str())?;
    require(
        muc.admission.begin_commit == CommitCut::Complete
            && muc.admission.finalize_commit == CommitCut::Complete,
    )?;
    for recipient in muc.recipients.as_slice() {
        full_jid(&recipient.full_jid)?;
        require(!recipient.blocked)?;
    }
    match (
        &muc.repository.original_id,
        muc.repository.commit,
        muc.drive,
    ) {
        (Nullable::Null(()), CommitCut::Complete, MucDrive::Complete) => {
            require(
                c.archive
                    && c.origin_id.get().is_some()
                    && muc.recipients.len() == 1
                    && muc.recipients.as_slice()[0].endpoint == EndpointCut::Return,
            )?;
            let native = muc.native.get().ok_or(Rejection::Relationship)?;
            require(native.connection_id == muc.recipients.as_slice()[0].connection_id)?;
            write_plan(&native.write, c.stanza.as_str().len())?;
        }
        (Nullable::Value(_), CommitCut::Complete, MucDrive::Complete) => require(
            c.origin_id.get().is_some() && muc.recipients.is_empty() && muc.native.get().is_none(),
        )?,
        (Nullable::Null(()), CommitCut::Complete, MucDrive::DropSecondEndpoint) => {
            require(
                !c.archive
                    && c.origin_id.get().is_none()
                    && muc.recipients.len() == 2
                    && muc.native.get().is_none(),
            )?;
            require(
                muc.recipients.as_slice()[0].endpoint == EndpointCut::Return
                    && muc.recipients.as_slice()[1].endpoint == EndpointCut::Pending,
            )?;
        }
        (Nullable::Null(()), CommitCut::Pending, MucDrive::DropCommit) => {
            require(muc.recipients.is_empty() && muc.native.get().is_none())?
        }
        _ => return Err(Rejection::Unsupported),
    }
    Ok(())
}
fn validate_auth_drive(auth: &AuthInput, drive: AuthDrive) -> Result<(), Rejection> {
    require(matches!(
        (&auth.publication, drive),
        (PublicationReply::BackendError(_), AuthDrive::Complete)
            | (
                PublicationReply::CommitPending(_),
                AuthDrive::DropPublicationCommit
            )
    ))
}
fn independent_lanes(
    m: &MixBoshTransport,
    a: &BoshSessionInput,
    worker: &WorkerInput,
    bound: &AuthInput,
) -> Result<(), Rejection> {
    require(
        m.session.connection_id != a.connection_id
            && m.session.session_id != a.session_id
            && m.session.response.rid != a.response.rid,
    )?;
    let binding = bound.binding.get().ok_or(Rejection::Relationship)?;
    full_jid(&binding.full_jid)?;
    for r in worker.attempt.route.targets.as_slice() {
        require(
            r.full_jid != binding.full_jid
                && r.connection_id != a.connection_id
                && matches!(r.provenance, RouteProvenance::InitiallyPublished(_)),
        )?;
    }
    Ok(())
}
// Count canonical account actors, not room/participant IDs, sessions, devices,
// archive candidates or repeated copies of the same account's fixed identity.
// Account UUID and canonical bare-JID aliases must agree where both are supplied.
#[derive(Default)]
struct ActorBudget {
    bare: BTreeSet<String>,
    by_id: BTreeMap<Id, String>,
    by_bare: BTreeMap<String, Id>,
}
impl ActorBudget {
    fn bare(&mut self, bare: &Jid) -> Result<(), Rejection> {
        bare_jid(bare)?;
        self.bare.insert(bare.as_str().to_owned());
        require(self.bare.len() <= 2)
    }
    fn bind(&mut self, id: Id, bare: &Jid) -> Result<(), Rejection> {
        self.bare(bare)?;
        require(
            self.by_id
                .get(&id)
                .is_none_or(|existing| existing == bare.as_str()),
        )?;
        require(
            self.by_bare
                .get(bare.as_str())
                .is_none_or(|existing| *existing == id),
        )?;
        self.by_id.insert(id, bare.as_str().to_owned());
        self.by_bare.insert(bare.as_str().to_owned(), id);
        Ok(())
    }
    fn full(&mut self, id: Id, full: &Jid) -> Result<(), Rejection> {
        self.bind(id, &Text::new(full_jid(full)?)?)
    }
    fn auth(&mut self, auth: &AuthInput) -> Result<(), Rejection> {
        match &auth.control {
            ControlInput::Binding(c) => self.full(auth.user_id, &c.full_jid),
            ControlInput::UnboundFast(c) => self.bind(auth.user_id, &c.authorization_identifier),
        }
    }
    fn route(&mut self, route: &RouteEnvironment) -> Result<(), Rejection> {
        for target in route.targets.as_slice() {
            self.full(target.user_id, &target.full_jid)?;
        }
        Ok(())
    }
    fn worker(&mut self, worker: &WorkerInput) -> Result<(), Rejection> {
        if let ClaimOrigin::InitialDurableRow(row) = &worker.origin {
            self.bind(worker.attempt.route.enabled_account_id, &row.recipient_jid)?;
        }
        self.route(&worker.attempt.route)
    }
}
impl Case {
    fn validate_actors(&self) -> Result<(), Rejection> {
        let mut actors = ActorBudget::default();
        match &self.composition {
            Composition::Muc(c) => {
                let MucPrincipal::Local(principal) = &c.command.authority.principal else {
                    return Err(Rejection::Unsupported);
                };
                actors.bind(principal.user_id, &c.command.actor_scope)?;
                for r in c.recipients.as_slice() {
                    actors.full(r.user_id, &r.full_jid)?;
                }
            }
            Composition::AuthThenMixNative(c) => {
                actors.auth(&c.auth)?;
                actors.bare(&c.foreground.ingress.actor_bare)?;
                actors.worker(&c.worker)?;
                if let Some(p) = c.foreground.stored.projection.get() {
                    for r in p.recipients.as_slice() {
                        actors.bare(&r.participant.jid)?;
                    }
                }
            }
            Composition::ReplayMixQueuedAuth(c) => {
                actors.auth(&c.auth.unbound)?;
                actors.auth(&c.auth.bound)?;
                actors.bare(&c.mix.foreground.ingress.actor_bare)?;
                actors.worker(&c.mix.worker)?;
            }
            Composition::MixRecoveryNative(c) => {
                actors.worker(&c.worker)?;
                actors.route(&c.replacement.route)?;
                if let ClaimOrigin::InitialDurableRow(row) = &c.worker.origin {
                    actors.bind(c.replacement.route.enabled_account_id, &row.recipient_jid)?;
                }
            }
            Composition::MixDefer(c) => actors.worker(&c.worker)?,
            Composition::NativeAuth(c) => actors.auth(&c.auth)?,
            Composition::BoshAuth(c) => {
                actors.auth(&c.auth.bound)?;
                if let Some(m) = c.mix.get() {
                    actors.worker(&m.worker)?;
                }
            }
        }
        Ok(())
    }
    // Count distinct *logical supplied occurrences*, not unique strings and
    // not repeated copies of one item's bytes in command/projection/frame data.
    // These finite recipes each have a fixed number of logical message/control
    // occurrences. Equal bytes at two endpoints or in U/B still count twice.
    fn nonpadding_bytes(&self) -> usize {
        let initial = |w: &WorkerInput| match &w.origin {
            ClaimOrigin::InitialDurableRow(r) => r.stanza.as_str().len(),
            ClaimOrigin::FreshProjection(_) => 0,
        };
        match &self.composition {
            Composition::Muc(m) => m.command.stanza.as_str().len() * m.recipients.len().max(1),
            Composition::AuthThenMixNative(c) => {
                auth_xml(&c.auth).len()
                    + c.foreground
                        .stored
                        .projection
                        .get()
                        .map_or(0, |p| p.stanza_template.as_str().len() * p.recipients.len())
            }
            Composition::ReplayMixQueuedAuth(c) => {
                initial(&c.mix.worker)
                    + auth_xml(&c.auth.unbound).len()
                    + auth_xml(&c.auth.bound).len()
                    + c.auth.padding.features_xml.as_str().len()
            }
            Composition::MixRecoveryNative(c) => initial(&c.worker) * 2,
            Composition::MixDefer(c) => initial(&c.worker),
            Composition::NativeAuth(c) => auth_xml(&c.auth).len(),
            Composition::BoshAuth(c) => {
                auth_xml(&c.auth.bound).len() + c.mix.get().map_or(0, |m| initial(&m.worker))
            }
        }
    }
    fn validate(&self) -> Result<(), Rejection> {
        require(
            self.schema.as_str() == CASE_SCHEMA
                && self.adapter_contract.as_str() == ADAPTER_CONTRACT,
        )
        .map_err(|_| Rejection::Schema)?;
        require(!self.case_id.as_str().is_empty() && self.case_id.as_str().is_ascii())?;
        // Descriptive identity is intentionally never matched, parsed or used
        // to choose behavior. Each closed recipe carries its own domain inputs.
        match &self.composition {
            Composition::Muc(muc) => validate_muc(muc)?,
            Composition::AuthThenMixNative(c) => {
                validate_auth(&c.auth, CredentialKind::Binding, TransportKind::Tcp)?;
                require(matches!(c.auth.publication, PublicationReply::Committed(_)))?;
                require(
                    c.auth.frame.connection_id == c.auth_native.connection_id
                        && c.auth.frame.frame_id != c.foreground.frame.frame_id,
                )?;
                write_plan(&c.auth_native.write, auth_xml(&c.auth).len())?;
                validate_worker(&c.worker)?;
                delivered_environment(&c.worker.attempt.route)?;
                require(
                    matches!(
                        c.worker.attempt.archive.reply,
                        ArchiveReply::StoreCandidate(_)
                    ) && c.delivery_native.ack_commit == CommitCut::Complete,
                )?;
                let ClaimOrigin::FreshProjection(origin) = &c.worker.origin else {
                    return Err(Rejection::Relationship);
                };
                require(
                    origin.foreground_frame == c.foreground.frame.frame_id
                        && c.foreground.commit == CommitCut::Complete,
                )?;
                let stored = &c.foreground.stored;
                let command = &c.foreground.command;
                let ingress = &c.foreground.ingress;
                require(
                    c.foreground.frame.transport == TransportKind::Tcp
                        && stored.authoritative_id == command.item_id
                        && stored.channel_id == ingress.channel_id
                        && command.channel_id == ingress.channel_id
                        && stored.channel_jid == ingress.channel_jid,
                )?;
                require(
                    command.actor == ingress.actor_bare
                        && command.identity == ingress.identity
                        && command.delivery_payload == ingress.children
                        && command.encrypted == ingress.encrypted,
                )?;
                require(
                    command
                        .visible_jid
                        .get()
                        .is_none_or(|jid| jid == &ingress.actor_bare),
                )?;
                require(full_jid(&ingress.actor_full)? == ingress.actor_bare.as_str())?;
                bare_jid(&ingress.channel_jid)?;
                require(
                    northstar_xmpp_types::CanonicalJid::parse(ingress.channel_jid.as_str())
                        .map_err(|_| Rejection::Encoding)?
                        .domainpart()
                        == c.foreground.configured_domain.as_str(),
                )?;
                let projection = stored.projection.get().ok_or(Rejection::Relationship)?;
                // One outstanding delivery source. No second independently
                // supplied fresh row is possible in this input variant.
                require(
                    projection.recipients.len() == 1
                        && origin.recipient_ordinal == 0
                        && projection.recipients.as_slice()[0].delivery_id
                            == origin.declared_delivery_id,
                )?;
                require(
                    projection.event_id == stored.authoritative_id
                        && projection.channel_id == stored.channel_id
                        && projection.channel_jid == stored.channel_jid
                        && projection.authoritative_stanza_id.get()
                            == Some(&stored.authoritative_id)
                        && projection.archive
                        && projection.encrypted == command.encrypted
                        && projection.recipients.as_slice()[0].sequence > 0,
                )?;
                require(!projection.stanza_template.as_str().is_empty())?;
                require(
                    c.delivery_native.returned_fence.delivery_id == origin.declared_delivery_id,
                )?;
                require(c.worker.attempt.route.targets.len() == 1)?;
                let route = &c.worker.attempt.route.targets.as_slice()[0];
                bare_jid(&projection.recipients.as_slice()[0].participant.jid)?;
                require(
                    full_jid(&route.full_jid)?
                        == projection.recipients.as_slice()[0].participant.jid.as_str(),
                )?;
                require(
                    route.connection_id == c.auth.frame.connection_id
                        && route.connection_id == c.delivery_native.connection_id
                        && route.user_id == c.auth.user_id
                        && route.auth_generation == c.auth.auth_generation,
                )?;
                require(
                    matches!(&route.provenance, RouteProvenance::ActivatedByAuth(a) if a.frame_id == c.auth.frame.frame_id),
                )?;
                require(
                    c.auth
                        .binding
                        .get()
                        .is_some_and(|b| b.full_jid == route.full_jid),
                )?;
                write_plan(
                    &c.delivery_native.write,
                    projection.stanza_template.as_str().len(),
                )?;
            }
            Composition::ReplayMixQueuedAuth(c) => {
                validate_auth(
                    &c.auth.unbound,
                    CredentialKind::UnboundFast,
                    TransportKind::Bosh,
                )?;
                validate_auth(&c.auth.bound, CredentialKind::Binding, TransportKind::Bosh)?;
                validate_session(&c.auth.session)?;
                validate_worker(&c.mix.worker)?;
                validate_mix_transport(&c.mix.worker, &c.mix.transport, true)?;
                independent_lanes(
                    &c.mix.transport,
                    &c.auth.session,
                    &c.mix.worker,
                    &c.auth.bound,
                )?;
                require(
                    c.auth.unbound.frame.connection_id == c.auth.session.connection_id
                        && c.auth.bound.frame.connection_id == c.auth.session.connection_id,
                )?;
                require(
                    c.auth.unbound.frame.frame_id != c.auth.bound.frame.frame_id
                        && c.mix.foreground.frame.frame_id != c.auth.unbound.frame.frame_id
                        && c.mix.foreground.frame.frame_id != c.auth.bound.frame.frame_id,
                )?;
                require(
                    c.auth.session.bind.membership.c2s_message_ids.is_empty()
                        && c.auth.session.bind.membership.mix_delivery_ids.is_empty(),
                )?;
                validate_padding(&c.auth.padding, &c.auth.unbound, &c.auth.bound)?;
                let ClaimOrigin::InitialDurableRow(row) = &c.mix.worker.origin else {
                    return Err(Rejection::Relationship);
                };
                require(matches!(
                    c.mix.worker.attempt.archive.reply,
                    ArchiveReply::Replay(_)
                ))?;
                require(
                    row.event_id == c.mix.foreground.original_id
                        && row.authoritative_stanza_id.get() == Some(&c.mix.foreground.original_id)
                        && c.mix.foreground.existing.authoritative_id
                            == c.mix.foreground.original_id
                        && c.mix.foreground.ingress.identity.get().is_some(),
                )?;
                require(
                    row.channel_id == c.mix.foreground.ingress.channel_id
                        && row.channel_jid == c.mix.foreground.ingress.channel_jid,
                )?;
                bare_jid(&c.mix.foreground.ingress.actor_bare)?;
                require(
                    full_jid(&c.mix.foreground.ingress.actor_full)?
                        == c.mix.foreground.ingress.actor_bare.as_str(),
                )?;
                require(
                    northstar_xmpp_types::CanonicalJid::parse(row.channel_jid.as_str())
                        .map_err(|_| Rejection::Encoding)?
                        .domainpart()
                        == c.mix.foreground.configured_domain.as_str(),
                )?;
            }
            Composition::MixRecoveryNative(c) => {
                validate_worker(&c.worker)?;
                validate_attempt(&c.replacement)?;
                delivered_environment(&c.worker.attempt.route)?;
                delivered_environment(&c.replacement.route)?;
                require(
                    matches!(c.worker.origin, ClaimOrigin::InitialDurableRow(_))
                        && c.worker.attempt.claim.lease_token != c.replacement.claim.lease_token,
                )?;
                let (ArchiveReply::Replay(first), ArchiveReply::Replay(replacement)) = (
                    &c.worker.attempt.archive.reply,
                    &c.replacement.archive.reply,
                ) else {
                    return Err(Rejection::Relationship);
                };
                require(first.original_archive_id == replacement.original_archive_id)?;
                let old_route = &c.worker.attempt.route.targets.as_slice()[0];
                let new_route = &c.replacement.route.targets.as_slice()[0];
                require(
                    matches!(old_route.provenance, RouteProvenance::InitiallyPublished(_))
                        && old_route.routable
                        && matches!(new_route.provenance, RouteProvenance::InitiallyPublished(_))
                        && new_route.routable
                        && old_route.connection_id != new_route.connection_id,
                )?;
                // Actual PendingMixLocalHandoff::drop cancels the old sender and
                // disconnect token. Recovery must create an independent queue,
                // lifecycle and cancellation token for new_route, retaining the
                // old cancelled objects as evidence; never clear or relabel them.
                let ClaimOrigin::InitialDurableRow(row) = &c.worker.origin else {
                    unreachable!()
                };
                require(c.native.returned_fence.delivery_id == row.source.delivery_id)?;
                require(
                    c.replacement
                        .route
                        .targets
                        .as_slice()
                        .iter()
                        .any(|r| r.connection_id == c.native.connection_id),
                )?;
                for target in c.replacement.route.targets.as_slice() {
                    require(full_jid(&target.full_jid)? == row.recipient_jid.as_str())?;
                }
                require(c.native.ack_commit == CommitCut::Complete)?;
                write_plan(&c.native.write, row.stanza.as_str().len())?;
            }
            Composition::MixDefer(c) => {
                validate_worker(&c.worker)?;
                require(
                    matches!(c.worker.origin, ClaimOrigin::InitialDurableRow(_))
                        && c.worker.attempt.route.targets.is_empty()
                        && !c.worker.attempt.route.privacy_blocked
                        && c.settlement_commit == CommitCut::Complete
                        && c.updated,
                )?;
                // There is no renewal start, timer, or interval in the grammar.
            }
            Composition::NativeAuth(c) => {
                validate_auth(&c.auth, CredentialKind::Binding, TransportKind::Tcp)?;
                validate_auth_drive(&c.auth, c.drive)?;
                require(c.native.connection_id == c.auth.frame.connection_id)?;
                write_plan(&c.native.write, auth_xml(&c.auth).len())?;
            }
            Composition::BoshAuth(c) => {
                validate_auth(&c.auth.bound, CredentialKind::Binding, TransportKind::Bosh)?;
                validate_auth_drive(&c.auth.bound, c.auth.drive)?;
                validate_session(&c.auth.session)?;
                require(
                    c.auth.session.connection_id == c.auth.bound.frame.connection_id
                        && auth_xml(&c.auth.bound).len() + 256 <= RESPONSE_BYTES as usize,
                )?;
                require(
                    c.auth.session.bind.membership.c2s_message_ids.is_empty()
                        && c.auth.session.bind.membership.mix_delivery_ids.is_empty(),
                )?;
                if let Some(mix) = c.mix.get() {
                    validate_worker(&mix.worker)?;
                    require(
                        matches!(mix.worker.origin, ClaimOrigin::InitialDurableRow(_))
                            && matches!(
                                mix.worker.attempt.archive.reply,
                                ArchiveReply::StoreCandidate(_)
                            ),
                    )?;
                    validate_mix_transport(&mix.worker, &mix.transport, false)?;
                    independent_lanes(&mix.transport, &c.auth.session, &mix.worker, &c.auth.bound)?;
                } else {
                    require(c.auth.drive == AuthDrive::Complete)?;
                }
            }
        }
        Ok(())
    }
}

// ---- Capability-free actual observation records ----
// Missing observations are explicit nulls. These records have no Pass,
// InvariantViolation, Complete(control), expected count, or fixture verdict.
strings!(Cut {
    Introduction,
    PortEntry,
    PortReturn,
    BeforePoll,
    AfterPoll,
    ChildDrop,
    AfterRunnerDrop,
    BeforePublish,
    AfterPublish,
    BeforeFinish,
    AfterFinish,
    BeforeTeardown,
    AfterTeardown
});
strings!(OwnerTerminal {
    Completed,
    BackendFailure,
    TimedOut,
    Cancelled,
    Panicked
});
strings!(CallTerminal {
    Returned,
    TimedOut,
    Cancelled,
    Panicked
});
strings!(HandlerReturn {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Panicked
});
strings!(FrameOutcome {
    Pending,
    Completed,
    BackendFailure,
    TimedOut,
    Cancelled,
    Panicked,
    IntegrityRejected,
    CredentialRejected,
    RouteRejected,
    CompletedWithDeferredNotification
});
strings!(FrameStage {
    Validation,
    Handler,
    SmCheckpoint,
    AuthPublication,
    CapsPublication,
    ReplacementNotification,
    MessagePolicy,
    MessageAdmission,
    MessageRouting,
    MessageFollowup,
    MucPolicy,
    MucGateWait,
    MucAuthority,
    MucAdmission,
    MucClusterFanout,
    MucLocalFanout,
    MixPolicy,
    MixAdmission
});
strings!(AcceptanceClass {
    ArchiveAndIdentity,
    ArchiveOnly,
    IdentityOnly,
    Volatile
});
strings!(FanoutStage {
    Unavailable,
    Ready,
    Started,
    ClusterEntered,
    ClusterReturned,
    PrivacyEntered,
    Delivering,
    Completed
});
strings!(EffectScope {
    NewReservation,
    Reclaim,
    ReplayRead,
    PendingRequirement,
    GuardDenial,
    AdmissionFinalize,
    GuardOnlyVerification
});
strings!(FinalizeSuccess {
    PendingAccepted,
    AlreadyAccepted
});
strings!(GuardDecision { Allowed, Denied });
data_object!(OneId<I> { id: I });
object!(BoolValue { value: bool });
object!(CountValue { count: u32 });
object!(EpochValue { epoch: Nullable<i64> });
object!(RidValue { rid: u64 });
data_object!(Correlation<I> { operation_id: I, effect: u64, generation: u64, attempt: u64 });
data_object!(FenceEvidence<I> { admission_key: Sha256, payload_mac: Sha256, lease_token: I });
data_object!(FinalizedFact<I> { fence: FenceEvidence<I>, result: FinalizeSuccess });
data_sum!(AdmissionFact<I> { Reserved(FenceEvidence<I>), ReplayAccepted(Empty), InProgress(Empty), Denied(Empty), Finalized(FinalizedFact<I>), GuardOnly(GuardValue) });
object!(GuardValue {
    decision: GuardDecision
});
data_object!(AdmissionCommit<I> { correlation: Correlation<I>, scope: EffectScope, fact: AdmissionFact<I> });
data_sum!(AdmissionKnowledge<I> { NoCommitRequested(Empty), CommitCallEntered(AdmissionCommit<I>), ReceiptKnown(AdmissionCommit<I>) });
data_sum!(AdmissionReturned<I> { Proceed(FenceEvidence<I>), AcceptPending(Empty), Error(Empty) });
data_object!(AdmissionEvidence<I> { correlation: Correlation<I>, started: bool, knowledge: AdmissionKnowledge<I>, returned: Nullable<AdmissionReturned<I>> });
data_object!(FrameCapture<I> { frame: I, cut: Cut, stage: Nullable<FrameStage>, outcome: Nullable<FrameOutcome>, admission_begin: Nullable<AdmissionEvidence<I>>, admission_finalize: Nullable<AdmissionEvidence<I>> });
data_sum!(MucOutcome<I> { Stored(OneId<I>), Replay(OneId<I>), Unauthorized(Empty), Stale(Empty) });
data_object!(MucCommitFact<I> { outcome: MucOutcome<I>, fresh_class: Nullable<AcceptanceClass> });
data_sum!(MucKnowledge<I> { NoCommitRequested(Empty), CommitCallEntered(MucCommitFact<I>), ReceiptKnown(MucCommitFact<I>) });
data_sum!(MucReturned<I> { Outcome(MucOutcome<I>), Error(Empty) });
object!(FanoutPrefix { stage: FanoutStage, recipients: Nullable<u32>, next_recipient: u32, endpoint_pending: bool, blocked: u32, accepted: u32, rejected: u32 });
data_object!(MucSnapshot<I> { request_issued: bool, repository_started: bool, knowledge: MucKnowledge<I>, returned: Nullable<MucReturned<I>>, fanout: FanoutPrefix, terminal: Nullable<OwnerTerminal> });
data_object!(MucCapture<I> { frame: I, cut: Cut, command: Nullable<MucCommand<I>>, requested_class: Nullable<AcceptanceClass>, snapshot: MucSnapshot<I> });
data_object!(RecipientObservation<I> { user_id: I, full_jid: Jid, connection_id: I });
data_object!(MucRecipients<I> { frame: I, recipients: List<RecipientObservation<I>, 2> });
data_object!(MucEndpoint<I> { frame: I, ordinal: u8, recipient: RecipientObservation<I>, privacy_returned: Nullable<bool>, entered: bool, returned: Nullable<bool>, queued_item: Nullable<QueueItem<I>> });
data_sum!(
    #[expect(
        clippy::large_enum_variant,
        reason = "Finite test-only MUC facts retain inline representation; measured memory fit remains required"
    )]
    MucFact<I> { Snapshot(MucCapture<I>), Recipients(MucRecipients<I>), Endpoint(MucEndpoint<I>) }
);

data_sum!(MixReplay<I> { Miss(Empty), Replay(OneId<I>), Conflict(Empty) });
data_sum!(MixOutcome<I> { Stored(OneId<I>), Replay(OneId<I>), NotParticipant(Empty), Conflict(Empty), TooLarge(Empty) });
data_object!(MixAdmission<I> { outcome: MixOutcome<I>, recipients: List<Participant<I>, 2> });
data_object!(ExistingKnowledge<I> { raw: Nullable<Existing<I>>, authenticated: Nullable<MixReplay<I>> });
data_sum!(ReadReturned<I> { Outcome(MixReplay<I>), Error(Empty) });
data_object!(ReadKnowledge<I> { issued: bool, started: bool, miss: bool, existing: ExistingKnowledge<I>, returned: Nullable<ReadReturned<I>> });
data_sum!(ForegroundKnowledge<I> { NoCommitRequested(Empty), CommitCallEntered(Stored<I>), ReceiptKnown(Stored<I>) });
data_sum!(ForegroundReturned<I> { AcceptedStored(OneId<I>), Admission(MixAdmission<I>), Error(Empty) });
strings!(Wake {
    Unavailable,
    Ready,
    Invoked
});
data_object!(ForegroundSnapshot<I> { replay: ReadKnowledge<I>, request_issued: bool, repository_started: bool, existing: ExistingKnowledge<I>, knowledge: ForegroundKnowledge<I>, returned: Nullable<ForegroundReturned<I>>, wake: Wake, terminal: Nullable<OwnerTerminal> });
data_object!(ForegroundCapture<I> { frame: I, cut: Cut, ingress: MixIngress<I>, command: Nullable<MixStoreCommand<I>>, snapshot: ForegroundSnapshot<I> });
data_object!(ProjectionRowJoin<I> { foreground_frame: I, recipient_ordinal: u8, stored_authoritative_id: I, row_slot: u8, actual_row: DeliveryRow<I> });
data_object!(InitialRowLoaded<I> { input_row_ordinal: u8, row_slot: u8, actual_row: DeliveryRow<I> });
data_sum!(
    #[expect(
        clippy::large_enum_variant,
        reason = "Finite test-only foreground facts retain inline representation; measured memory fit remains required"
    )]
    ForegroundFact<I> { Snapshot(ForegroundCapture<I>), ProjectionRow(ProjectionRowJoin<I>), InitialRow(InitialRowLoaded<I>) }
);
object!(ClaimCommand {
    limit: i64,
    max_bytes: i64
});
data_object!(Rows<I> { rows: List<DeliveryRow<I>, 1> });
data_sum!(ClaimKnowledge<I> { NoStatementEntered(Empty), ReadEmpty(Empty), AutocommitStatementEntered(Empty), StatementReceipt(Rows<I>) });
data_sum!(ClaimReturned<I> { Accepted(CountValue), Rejected(Rows<I>), Error(Empty) });
data_object!(ClaimSnapshot<I> { issued: bool, started: bool, knowledge: ClaimKnowledge<I>, returned: Nullable<ClaimReturned<I>>, terminal: Nullable<OwnerTerminal> });
data_object!(ClaimCapture<I> { claim_ordinal: u8, cut: Cut, command: ClaimCommand, snapshot: ClaimSnapshot<I> });
data_object!(ClaimAttemptJoin<I> { claim_ordinal: u8, row_ordinal: u8, attempt_ordinal: u8, source: MixSource<I>, row: DeliveryRow<I>, same_retained_row: Nullable<bool> });
data_sum!(ClaimFact<I> { Snapshot(ClaimCapture<I>), Attempt(ClaimAttemptJoin<I>) });

data_object!(ArchiveCommand<I> { personal_archive_id: I, owner_id: I, channel_jid: Jid, authoritative_stanza_id: I, stanza: Stanza, encrypted: bool, client_stanza_id: Nullable<Short> });
data_sum!(ArchiveResult<I> { Stored(OneId<I>), Replay(OneId<I>) });
data_sum!(ArchiveKnowledge<I> { NoCommitEntered(Empty), CommitCallEntered(ArchiveResult<I>), ReceiptKnown(ArchiveResult<I>) });
data_sum!(ArchiveReturned<I> { Outcome(ArchiveResult<I>), Error(Empty) });
data_object!(ArchiveSnapshot<I> { issued: bool, started: bool, knowledge: ArchiveKnowledge<I>, returned: Nullable<ArchiveReturned<I>> });
data_sum!(TransferBoundary<I> { SocketFenced(OneId<I>), SmPersisted(OneId<I>), BoshPersisted(OneId<I>), ClusterSocketFenced(Empty), ClusterSmPersisted(Empty), ClusterBoshPersisted(Empty) });
data_sum!(LocalResult<I> { QueueFull(Empty), QueueClosed(Empty), HandoffClosed(Empty), Transferred(TransferBoundary<I>) });
data_object!(LocalPrefix<I> { target: Jid, started: bool, enqueued: bool, returned: Nullable<LocalResult<I>> });
data_object!(ClusterPrefix<I> { node: Short, started: bool, returned: bool, handoff: Nullable<TransferBoundary<I>> });
data_object!(TransferFact<I> { target: Jid, boundary: TransferBoundary<I> });
strings!(RoutePhase {
    Unprepared,
    Prepared,
    Started,
    Returned
});
strings!(RouteResult {
    CompletedByWorker,
    Transferred,
    Pending,
    Permanent,
    Retry,
    Cancelled
});
strings!(RetryResult {
    LeaseLost,
    Retried,
    RouteWokenAtAttemptLimit,
    DeadLettered
});
strings!(SettlementKind {
    Ack,
    Defer,
    Retry,
    DeadLetter
});
object!(RetryValue { value: RetryResult });
sum!(SettlementResult { Ack(BoolValue), Defer(BoolValue), Retry(RetryValue), DeadLetter(BoolValue) });
sum!(SettlementKnowledge { NotEntered(Empty), CommitCallEntered(SettlementResult), AutocommitStatementEntered(Empty), ReceiptKnown(SettlementResult) });
sum!(SettlementReturned { Outcome(SettlementResult), Error(Empty) });
object!(SettlementSnapshot { kind: SettlementKind, started: bool, knowledge: SettlementKnowledge, returned: Nullable<SettlementReturned> });
sum!(RenewalKnowledge { NotEntered(Empty), AutocommitStatementEntered(Empty), StatementReceipt(BoolValue) });
sum!(RenewalReturned { Outcome(BoolValue), Error(Empty) });
object!(RenewalReceipt {
    ordinal: u64,
    value: bool
});
object!(RenewalSnapshot { issued: u64, started: bool, pending: bool, knowledge: RenewalKnowledge, returned: Nullable<RenewalReturned>, last_receipt: Nullable<RenewalReceipt> });
data_object!(WorkerSnapshot<I> { route: RoutePhase, route_returned: Nullable<RouteResult>, archive: ArchiveSnapshot<I>, local: List<LocalPrefix<I>, 2>, cluster: List<ClusterPrefix<I>, 2>, transfer: Nullable<TransferFact<I>>, lease_lost: bool, aborted: bool, renewal_scope_closed: bool, renewal: RenewalSnapshot, settlement: Nullable<SettlementSnapshot>, terminal: Nullable<OwnerTerminal> });
data_object!(WorkerCapture<I> { attempt_ordinal: u8, cut: Cut, row: DeliveryRow<I>, route_stanza: Nullable<Stanza>, snapshot: WorkerSnapshot<I> });
data_object!(ArchiveCall<I> { attempt_ordinal: u8, command: ArchiveCommand<I>, returned: Nullable<ArchiveReturned<I>> });
strings!(MixCapability {
    Supported,
    Unsupported,
    Unknown
});
data_object!(LocalCapsEpoch<I> { connection_id: I, generation: u64 });
data_object!(FederatedCapsOwner<I> { connection_id: I, observation_id: I });
data_sum!(CapsOwner<I> { Local(LocalCapsEpoch<I>), Federated(FederatedCapsOwner<I>) });
object!(CapsKey {
    algorithm: Short,
    node: Short,
    version: Short
});
object!(NotifyRange {
    start: u32,
    end: u32
});
object!(VerifiedCapsSummary { mix_core: bool, mix_pam: bool, notify_storage: Text<4096>, notify_ranges: List<NotifyRange, 2> });
data_object!(CapsObservation<I> { owner: CapsOwner<I>, key: Nullable<CapsKey>, summary: Nullable<VerifiedCapsSummary> });
data_object!(RouteSession<I> { full_jid: Jid, connection_id: I, user_id: I, auth_generation: i64, user_agent_epoch: Nullable<i64>, caps_observation_generation: u64, routable: bool, disconnected: bool, lifecycle: u8 });
data_sum!(RouteLookupOwner<I> { Auth(OneId<I>), Worker(MixItemOwner) });
data_object!(RouteLookup<I> { owner: RouteLookupOwner<I>, lookup_key: Jid, entries: List<RouteSession<I>, 2> });
data_object!(RouteCandidate<I> { attempt_ordinal: u8, lookup_key: Jid, full_jid: Jid, connection_id: I, user_id: I, auth_generation: i64, caps_observation_generation: u64, routable: bool, disconnected: bool, lifecycle: u8, caps_before: Nullable<CapsObservation<I>>, caps_after: Nullable<CapsObservation<I>>, capability: MixCapability, pending_caps_count_before: u32, pending_caps_count_after: u32 });
data_object!(QueueItem<I> { item_ordinal: u8, connection_id: I, source: Nullable<Source<I>>, stanza: Text<16384>, auth_control: Nullable<I> });
data_object!(LocalQueueJoin<I> { attempt_ordinal: u8, target: Jid, item: QueueItem<I> });
data_sum!(HandoffResult<I> { Received(TransferBoundary<I>), Empty(Empty), Closed(Empty) });
data_object!(TypedHandoff<I> { attempt_ordinal: u8, item_ordinal: u8, source: MixSource<I>, received: HandoffResult<I> });
data_object!(RouteChildDrop<I> { attempt_ordinal: u8, disconnected: bool, snapshot: WorkerSnapshot<I> });
object!(DeferCommand { delay_seconds: i64 });
object!(RetryCommand { error: Short });
object!(DeadLetterCommand {
    reason: Short,
    error: Short
});
sum!(SettlementCommand { Ack(Empty), Defer(DeferCommand), Retry(RetryCommand), DeadLetter(DeadLetterCommand) });
data_object!(SettlementCall<I> { attempt_ordinal: u8, source: MixSource<I>, kind: SettlementKind, command: SettlementCommand, attempt_count: i32, route_wake_generation: i64, at_entry: WorkerSnapshot<I>, returned: Nullable<SettlementReturned> });
// Actual service-call observations. Capture entry with returned=null, then a
// separate later return fact only when that call actually returns. Account
// absence, backend error, privacy false and an unreturned call stay distinct.
// These are output facts, never inputs or reconstructed fixture effects.
data_object!(AccountIdentity<I> { id: I, username: Text<1024> });
data_sum!(AccountReturned<I> { Found(AccountIdentity<I>), Absent(Empty), Error(Empty) });
data_object!(AccountCall<I> { attempt_ordinal: u8, username: Text<1024>, returned: Nullable<AccountReturned<I>> });
sum!(PrivacyReturned { Outcome(BoolValue), Error(Empty) });
data_object!(PrivacyCall<I> { attempt_ordinal: u8, owner_id: I, candidate: Text<1024>, returned: Nullable<PrivacyReturned> });
data_sum!(WorkerFact<I> { Snapshot(WorkerCapture<I>), Archive(ArchiveCall<I>), Lookup(RouteLookup<I>), Candidate(RouteCandidate<I>), LocalQueue(LocalQueueJoin<I>), Handoff(TypedHandoff<I>), ChildDrop(RouteChildDrop<I>), Settlement(SettlementCall<I>), Account(AccountCall<I>), Privacy(PrivacyCall<I>) });

// These field sets mirror the integrated observed-auth API, including raw
// returned/constructed/transferred/begun identities separately. Historical
// holder transfer's publication projection never substitutes for LivePublication.
strings!(CredentialCall {
    NotEntered,
    Entered,
    Ok,
    Err
});
sum!(Eligibility { NotEntered(Empty), Entered(Empty), Returned(NullableBool), Err(Empty) });
object!(NullableBool { value: Nullable<bool> });
strings!(PreparationResult {
    NotEntered,
    Entered,
    Present,
    Absent,
    Err
});
strings!(CredentialRollbackSite {
    GenerationRefused,
    FastExpired,
    BindingReservationLost,
    BindingStageMissing,
    BindingFastExpired,
    ResumeStageMissing,
    ResumeClaimLost,
    ResumeFastExpired,
    ResumePrivacyMissing
});
object!(CredentialRollback {
    site: CredentialRollbackSite,
    call: CredentialCall
});
strings!(CredentialReturned {
    Authenticated,
    UnknownCredentials,
    Disabled,
    StaleGeneration,
    ExpiredCredentials,
    ReplayedCredentials,
    IntegrityFailure,
    BackendFailure,
    BindingCommitted,
    BindingCredentialsExpired,
    BindingReservationLost,
    ResumeCommitted,
    ResumeCredentialsExpired,
    ResumeClaimLost,
    ResumePrivacySelectionMissing,
    Error
});
strings!(ObservedCredentialKind {
    Binding,
    UnboundFast,
    Resume
});
strings!(CredentialTerminal {
    Returned,
    Cancelled,
    Panicked
});
data_object!(CredentialAttemptJoin<I> { attempt: I, frame: I, connection: I, ordinal: u8, kind: ObservedCredentialKind });
data_object!(CredentialJoins<I> { owner: CredentialAttemptJoin<I>, constructed_receipt: Nullable<I>, returned_receipt: Nullable<I>, transferred_receipt: Nullable<I> });
data_object!(CredentialSnapshot<I> { attempt: I, frame: I, connection: I, ordinal: u8, kind: ObservedCredentialKind, service_started: bool, repository_started: bool, begin: CredentialCall, eligibility: Eligibility, transaction_returned: bool, preparation: [PreparationResult; 5], stage_id: Nullable<I>, rollback: Nullable<CredentialRollback>, commit: CredentialCall, receipt_constructed: bool, returned: Nullable<CredentialReturned>, return_matches: bool, transferred: bool, handler: Nullable<HandlerReturn>, call_terminal: Nullable<CredentialTerminal>, integrity_failure: bool });
data_object!(CredentialCapture<I> { cut: Cut, snapshot: CredentialSnapshot<I>, joins: Nullable<CredentialJoins<I>> });
sum!(AuthTransport { NotStarted(Empty), Recording(Empty), WriteEntered(Empty), Written(Empty), BoshExposureEntered(RidValue), BoshAccepted(RidValue), BoshRefused(RidValue) });
sum!(PublicationKnowledge { NotStarted(Empty), NotRequired(Empty), BeforeCommit(Empty), CommitCallEntered(Empty), ReceiptKnown(EpochValue) });
strings!(PublicationRollback {
    NotRequested,
    CallEntered,
    Returned,
    Failed
});
sum!(PublicationReturned { Authenticated(EpochValue), UnknownCredentials(Empty), Disabled(Empty), StaleGeneration(Empty), ExpiredCredentials(Empty), ReplayedCredentials(Empty), IntegrityFailure(Empty), BackendFailure(Empty) });
strings!(PublicationTerminal {
    Completed,
    DeferredNotification,
    Failed,
    Cancelled,
    Panicked,
    Abandoned,
    ExposedNotAttempted
});
object!(PublicationEffects { unbound: bool, epoch_applied: bool, route_mapping: Nullable<bool>, route_activation: Nullable<bool>, caps_entered: bool, caps_returned: bool, notification_entered: bool, notification_returned: Nullable<bool> });
data_object!(PublicationSnapshot<I> { control: I, frame: Nullable<I>, handler: Nullable<HandlerReturn>, sealed: bool, transport: AuthTransport, publication: PublicationKnowledge, service_started: bool, repository_started: bool, rollback: PublicationRollback, returned: Nullable<PublicationReturned>, return_matches: bool, effects: PublicationEffects, terminal: Nullable<PublicationTerminal> });
data_object!(PublicationJoins<I> { control: I, frame: Nullable<I>, receipt: I, credential: Nullable<CredentialAttemptJoin<I>>, begun_receipt: Nullable<I>, bound_effects: bool, notification_expected: bool });
data_object!(ControlAssociation<I> { control: I, connection: I, frame: Nullable<I>, receipt: I, length: u32, digest: Sha256, publication: PublicationJoins<I> });
data_object!(ControlJoins<I> { introduced: Nullable<ControlAssociation<I>>, transferred: Nullable<ControlAssociation<I>> });
data_object!(ControlCapture<I> { cut: Cut, actual_xml: Nullable<Stanza>, holder: Nullable<ControlJoins<I>> });
data_object!(LivePublication<I> { cut: Cut, snapshot: PublicationSnapshot<I>, joins: Nullable<PublicationJoins<I>> });
data_object!(PublicationCallback<I> { connection: I, session: Nullable<I>, rid: Nullable<u64>, invoked_owners: List<ControlAssociation<I>, 2>, returned: Nullable<bool> });
data_sum!(ControlFact<I> { Holder(ControlCapture<I>), LivePublication(LivePublication<I>), Callback(PublicationCallback<I>) });

strings!(NativePreparation {
    NotStarted,
    Recording,
    FenceCallEntered,
    Prepared,
    Superseded,
    Failed
});
strings!(WriterResult { FullWrite, Failed });
strings!(WriteDecision { Withhold, Written });
strings!(AckDisposition {
    Deleted,
    AbsentUnclaimed,
    NoMatchingMix
});
strings!(IoResult { Ok, Error, Pending });
data_object!(NativeAckFact<I> { source: Source<I>, disposition: AckDisposition });
data_sum!(NativeAckKnowledge<I> { NotRequested(Empty), NoCommitRequested(Empty), CommitCallEntered(NativeAckFact<I>), ReceiptKnown(NativeAckFact<I>) });
data_object!(NativeSnapshot<I> { original: Nullable<Source<I>>, preparation: NativePreparation, managed_by_sm: Nullable<bool>, fence_entered: bool, returned_fence: Nullable<Source<I>>, writer_entered: bool, writer_result: Nullable<WriterResult>, write_decision: Nullable<WriteDecision>, ack: NativeAckKnowledge<I>, ack_returned: Nullable<bool>, terminal: Nullable<CallTerminal> });
data_object!(MucItemOwner<I> { frame: I, recipient_ordinal: u8 });
object!(MixItemOwner {
    attempt_ordinal: u8
});
data_object!(AuthItemOwner<I> { frame: I, control: I });
data_sum!(ItemOwner<I> { Muc(MucItemOwner<I>), Mix(MixItemOwner), Auth(AuthItemOwner<I>) });
data_object!(NativeCapture<I> { connection: I, item_ordinal: u8, owner: ItemOwner<I>, cut: Cut, snapshot: Nullable<NativeSnapshot<I>> });
object!(WriteCall { item_ordinal: u8, offered_len: u32, offered_sha256: Sha256, accepted_bytes_hex: Bytes<4096>, result: IoResult });
object!(FlushCall {
    item_ordinal: u8,
    result: IoResult
});
data_object!(NativeDequeue<I> { owner: ItemOwner<I>, item: QueueItem<I> });
data_object!(NativeAckCall<I> { item_ordinal: u8, source: Source<I>, returned: Nullable<bool> });
strings!(ReceiptResult {
    Accepted,
    Refused,
    Empty,
    Closed
});
object!(NativeReceipt {
    item_ordinal: u8,
    result: ReceiptResult
});
data_sum!(NativeFact<I> { Snapshot(NativeCapture<I>), Dequeue(NativeDequeue<I>), Write(WriteCall), Flush(FlushCall), Ack(NativeAckCall<I>), OwnershipReceipt(NativeReceipt), WriteReceipt(NativeReceipt) });

strings!(BoshOperationKind {
    Request,
    Outbound,
    HeldResponse
});
strings!(BoshResponseKind {
    Payload,
    TerminalControl,
    EmptyControl
});
strings!(TransactionKnowledge {
    NoCommitRequested,
    CommitCallEntered,
    ReceiptKnown
});
data_object!(BoshScope<I> { session_id: I, ttl_seconds: u64, kind: BoshOperationKind });
data_sum!(BoshTransferKnowledge<I> { NoCommitRequested(Empty), CommitCallEntered(MixSource<I>), ReceiptKnown(MixSource<I>) });
data_object!(BoshTransferSnapshot<I> { source: MixSource<I>, knowledge: BoshTransferKnowledge<I>, returned_source: Nullable<MixSource<I>>, return_matches_receipt: bool, local_entered: bool, source_applied: bool, notification_attempted: bool, queue_accepted: Nullable<bool> });
data_sum!(BoshBindKnowledge<I> { NotRequired(Empty), NoCommitRequested(Empty), CommitCallEntered(Membership<I>), ReceiptKnown(Membership<I>) });
data_object!(BoshBindAttempt<I> { selected_end: Nullable<u32>, selected_len: u32, sources: Nullable<List<Source<I>, 4>>, knowledge: BoshBindKnowledge<I>, returned: Nullable<Membership<I>>, return_matches: bool, superseded_message: Nullable<I>, restored: bool, restore_matches: bool, removed_indices: List<u32, 4> });
data_object!(BoshResponseSnapshot<I> { rid: u64, kind: BoshResponseKind, lineage: List<Nullable<Source<I>>, 4>, removed: List<bool, 4>, attempts: List<BoshBindAttempt<I>, 4>, construction_restored: u32, exposure_entered: bool, responder_calls: u32, accepted_responders: u32, refused_responders: u32, control_calls: u32, control_accepted: u32, control_refused: u32, empty_cache_evictions: u32, bookkeeping: bool, cached: bool });
data_object!(BoshExpected<I> { rid: u64, membership: Membership<I> });
data_object!(BoshRenewSnapshot<I> { expected: Nullable<BoshExpected<I>>, knowledge: TransactionKnowledge, returned: bool, return_matches: bool, ack_issued: bool, replay_calls: u32, replay_accepted: u32, replay_refused: u32, replay_bookkeeping: bool });
data_object!(DeletedC2s<I> { recipient_id: I, message_id: I });
data_sum!(DeletedSource<I> { C2s(DeletedC2s<I>), Mix(MixSource<I>) });
data_object!(BoshAckSnapshot<I> { rid: u64, knowledge: TransactionKnowledge, deleted: Nullable<List<DeletedSource<I>, 1>>, returned: bool, return_matches: bool, cache_evictions: u32, receipt_calls: u32, receipts_sent: u32, receipts_refused: u32 });
data_object!(BoshSnapshot<I> { scope: BoshScope<I>, transfers: List<BoshTransferSnapshot<I>, 1>, responses: List<BoshResponseSnapshot<I>, 2>, renewals: List<BoshRenewSnapshot<I>, 1>, acknowledgements: List<BoshAckSnapshot<I>, 1>, terminal: Nullable<CallTerminal>, keep_running: Nullable<bool> });
data_object!(BoshRequestAssociation<I> { session: I, connection: Nullable<I>, rid: u64, ack: Nullable<u64>, sid: Nullable<Short>, fingerprint: Sha256, request_xml: Stanza });
data_sum!(BoshAssociation<I> { Outbound(QueueItem<I>), Request(BoshRequestAssociation<I>) });
data_object!(BoshCapture<I> { owner_ordinal: u8, association: BoshAssociation<I>, cut: Cut, snapshot: BoshSnapshot<I> });
object!(IncompleteSelection {
    omitted_items: u32,
    missing_auth_associations: u32,
    connection_changed: bool
});
sum!(SelectionStatus { Complete(Empty), Incomplete(IncompleteSelection) });
data_object!(SelectedItem<I> { ordinal: u32, source: Nullable<Source<I>>, utf8_length: u32, sha256: Sha256, auth_marker: bool, sealed_association: Nullable<ControlAssociation<I>>, holder_joins: Nullable<ControlJoins<I>> });
// Fixed four slots mirror the real observer, retaining absent slots as null.
// Complete means this read has no omitted selection facts, never ready to cache.
data_object!(SelectionSnapshot<I> { session: I, rid: u64, fingerprint: Sha256, first_validated_connection: Nullable<I>, validated_connection: Nullable<I>, selected_count: u32, status: SelectionStatus, items: [Nullable<SelectedItem<I>>; 4] });
data_object!(SelectionCapture<I> { cut: Cut, selection: SelectionSnapshot<I> });
data_object!(BoshTransferCall<I> { owner_ordinal: u8, source: MixSource<I>, returned_source: Nullable<MixSource<I>> });
data_object!(BoshBindCall<I> { owner_ordinal: u8, rid: u64, sources: List<Source<I>, 4>, returned_membership: Nullable<Membership<I>> });
data_object!(BoshRenewCall<I> { owner_ordinal: u8, expected: Nullable<BoshExpected<I>>, returned: Nullable<bool> });
object!(BoshAckCall { owner_ordinal: u8, rid: u64, returned: Nullable<bool> });
object!(BodyBytes { body_hex: Bytes<16384> });
sum!(ResponseResult { Received(BodyBytes), Empty(Empty), Closed(Empty) });
data_object!(BoshResponseReceiver<I> { session: I, connection: Nullable<I>, owner_ordinal: u8, rid: u64, receiver_ordinal: u8, result: ResponseResult });
data_object!(CacheEntry<I> { rid: u64, fingerprint: Sha256, membership: Membership<I>, body_hex: Bytes<16384>, response_bytes: u32, replays: u32, transport_receipt_count: u32 });
data_object!(CacheCapture<I> { session: I, connection: I, cut: Cut, entries: List<CacheEntry<I>, 2> });
data_object!(BoshQueueCapture<I> { session: I, connection: I, cut: Cut, fifo: List<QueueItem<I>, 4>, output_bytes: u32, highest_responded: u64 });
data_object!(BoshTransportReceipt<I> { session: I, item_ordinal: u8, result: ReceiptResult });
data_sum!(
    #[expect(
        clippy::large_enum_variant,
        reason = "Finite test-only BOSH facts retain inline representation; measured memory fit remains required"
    )]
    BoshFact<I> { Snapshot(BoshCapture<I>), Selection(SelectionCapture<I>), Transfer(BoshTransferCall<I>), Bind(BoshBindCall<I>), Renew(BoshRenewCall<I>), Ack(BoshAckCall), Receiver(BoshResponseReceiver<I>), Cache(CacheCapture<I>), Queue(BoshQueueCapture<I>), TransportReceipt(BoshTransportReceipt<I>) }
);
strings!(PollResult { Pending, Ready });
strings!(DriverOwner {
    Muc,
    Foreground,
    Claim,
    Worker,
    Credential,
    Native,
    Publication,
    Bosh
});
object!(DriverPoll {
    owner: DriverOwner,
    owner_ordinal: u8,
    result: PollResult
});

// These are internal construction/metadata errors, never input rejections for
// an already decoded case. They must stay outside real owner futures/results.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DriverConfigurationError {
    OwnerOrdinal,
    ItemOrdinal,
    AdmittedCalls,
    MissingResourceStop,
    EnvelopeEncoding,
}
impl std::fmt::Display for DriverConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Stage4 driver configuration: {self:?}")
    }
}
impl std::error::Error for DriverConfigurationError {}

/// A validated data label, not a permit or a poll charge. Reusing it never
/// resets a budget. Only reserve_owner_poll admits the next actual owner poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PollSite {
    owner: DriverOwner,
    owner_ordinal: u8,
}
impl PollSite {
    pub(crate) fn new(
        owner: DriverOwner,
        owner_ordinal: u8,
    ) -> Result<Self, DriverConfigurationError> {
        let limit = match owner {
            DriverOwner::Muc | DriverOwner::Foreground => 3, // frame slots
            DriverOwner::Claim
            | DriverOwner::Worker
            | DriverOwner::Credential
            | DriverOwner::Publication => 2,
            DriverOwner::Native => 5, // case-local item slots, not per-transport
            DriverOwner::Bosh => 4,   // MIX transfer, two data responses, one ACK
        };
        if owner_ordinal >= limit {
            return Err(DriverConfigurationError::OwnerOrdinal);
        }
        Ok(Self {
            owner,
            owner_ordinal,
        })
    }
    pub(crate) fn owner(self) -> DriverOwner {
        self.owner
    }
    pub(crate) fn owner_ordinal(self) -> u8 {
        self.owner_ordinal
    }
}
object!(DriverResourceStop {
    owner: DriverOwner,
    owner_ordinal: u8,
    admitted_calls: u8
});
object!(NativeResourceStop {
    item_ordinal: u8,
    admitted_calls: u8
});
sum!(ResourceStop { DriverPoll(DriverResourceStop), NativeWrite(NativeResourceStop), NativeFlush(NativeResourceStop) });
impl ResourceStop {
    pub(crate) fn validate(&self) -> Result<(), DriverConfigurationError> {
        match self {
            Self::DriverPoll(stop) => {
                PollSite::new(stop.owner, stop.owner_ordinal)?;
                if stop.admitted_calls as usize != MAX_POLLS {
                    return Err(DriverConfigurationError::AdmittedCalls);
                }
            }
            Self::NativeWrite(stop) | Self::NativeFlush(stop) => {
                if stop.item_ordinal >= 5 {
                    return Err(DriverConfigurationError::ItemOrdinal);
                }
                let limit = if matches!(self, Self::NativeWrite(_)) {
                    32
                } else {
                    1
                };
                if stop.admitted_calls > limit {
                    return Err(DriverConfigurationError::AdmittedCalls);
                }
            }
        }
        Ok(())
    }
}
/// A resource cut outside domain results. Intentionally no Error impl: an
/// accidental `?` must not turn it into an anyhow/FrameFailure/backend result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BudgetStop {
    pub(crate) resource_stop: ResourceStop,
}

// ---- Case-local sequence and identity graph ----
strings!(Introduction {
    Frame,
    Connection,
    Session,
    CredentialAttempt,
    ConstructedReceipt,
    ReturnedReceipt,
    TransferredReceipt,
    BegunReceipt,
    ControlIdentity,
    ReceiptAssociation,
    ArchiveCandidate,
    StageIdentity,
    SourceIdentity,
    UnexpectedObservedIdentity
});
strings!(Loss {
    FactOverflow,
    PollOverflow,
    IdentityOverflow,
    OpaqueOverflow,
    OwnerSnapshotOverflow,
    FrameOverflow,
    UnlabeledIdentity,
    EncodedIdentityAtCapture,
    NoncanonicalIdentity,
    NoncontiguousSequence,
    MissingObservation,
    EncodingFailure
});
object!(FixedIdentity { uuid: Id });
object!(OpaqueIdentity { ordinal: u8 });
sum!(IdentityLabel { Fixed(FixedIdentity), Opaque(OpaqueIdentity) });
// IdentityLabel is a wire identity, not an authority or an owner handle.
// Ord uses the explicit variant/identity only; it never controls record order.
impl Ord for IdentityLabel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Fixed(a), Self::Fixed(b)) => a.uuid.cmp(&b.uuid),
            (Self::Opaque(a), Self::Opaque(b)) => a.ordinal.cmp(&b.ordinal),
            (Self::Fixed(_), Self::Opaque(_)) => std::cmp::Ordering::Less,
            (Self::Opaque(_), Self::Fixed(_)) => std::cmp::Ordering::Greater,
        }
    }
}
impl PartialOrd for IdentityLabel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceId {
    Raw(Uuid),
    Encoded(IdentityLabel),
}
impl EvidenceId {
    /// Only pass a UUID read from the actual observation being captured. This
    /// function does not fall back to any expected/input identity for None.
    pub(crate) fn observed(raw: Uuid) -> Self {
        Self::Raw(raw)
    }
}
impl Serialize for EvidenceId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Encoded(label) => label.serialize(s),
            Self::Raw(_) => Err(serde::ser::Error::custom("raw identity was not captured")),
        }
    }
}
impl<'de> Deserialize<'de> for EvidenceId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        IdentityLabel::deserialize(d).map(Self::Encoded)
    }
}
object!(IdentityIntroduction {
    label: IdentityLabel,
    first_seq: u32,
    locus: Introduction
});
#[derive(Clone, Default)]
struct IdentityMap {
    fixed: BTreeSet<Uuid>,
    labels: BTreeMap<Uuid, IdentityLabel>,
    seen_encoded: BTreeSet<IdentityLabel>,
    introductions: Vec<IdentityIntroduction>,
    opaque: u8,
    input_frames: BTreeSet<Uuid>,
    input_connections: BTreeSet<Uuid>,
    input_sessions: BTreeSet<Uuid>,
    reading_wire: bool,
}
impl IdentityMap {
    fn anchor(&mut self, id: Uuid, locus: Introduction) -> Result<(), Loss> {
        if !self.fixed.contains(&id) && self.fixed.len() == MAX_IDENTITIES {
            return Err(Loss::IdentityOverflow);
        }
        self.fixed.insert(id);
        match locus {
            Introduction::Frame => {
                self.input_frames.insert(id);
            }
            Introduction::Connection => {
                self.input_connections.insert(id);
            }
            Introduction::Session => {
                self.input_sessions.insert(id);
            }
            _ => {}
        }
        Ok(())
    }
    fn observe(&mut self, id: Uuid, seq: u32, locus: Introduction) -> Result<IdentityLabel, Loss> {
        if let Some(label) = self.labels.get(&id) {
            return Ok(label.clone());
        }
        // The total bound includes unused input-fixed identities too.
        let label = if self.fixed.contains(&id) {
            IdentityLabel::Fixed(FixedIdentity { uuid: Id(id) })
        } else {
            if self.fixed.len() + self.opaque as usize >= MAX_IDENTITIES {
                return Err(Loss::IdentityOverflow);
            }
            if self.opaque as usize >= MAX_OPAQUE {
                return Err(Loss::OpaqueOverflow);
            }
            self.opaque += 1;
            IdentityLabel::Opaque(OpaqueIdentity {
                ordinal: self.opaque,
            })
        };
        self.labels.insert(id, label.clone());
        self.introductions.push(IdentityIntroduction {
            label: label.clone(),
            first_seq: seq,
            locus,
        });
        Ok(label)
    }
    fn observe_encoded(
        &mut self,
        label: &IdentityLabel,
        seq: u32,
        locus: Introduction,
    ) -> Result<(), Loss> {
        if self.seen_encoded.contains(label) {
            return Ok(());
        }
        match label {
            IdentityLabel::Fixed(f) => {
                if !self.fixed.contains(&f.uuid.0) {
                    return Err(Loss::NoncanonicalIdentity);
                }
            }
            IdentityLabel::Opaque(o) => {
                if o.ordinal as usize > MAX_OPAQUE || o.ordinal != self.opaque + 1 {
                    return Err(Loss::NoncanonicalIdentity);
                }
                if self.fixed.len() + self.opaque as usize >= MAX_IDENTITIES {
                    return Err(Loss::IdentityOverflow);
                }
                self.opaque += 1;
            }
        }
        self.seen_encoded.insert(label.clone());
        self.introductions.push(IdentityIntroduction {
            label: label.clone(),
            first_seq: seq,
            locus,
        });
        Ok(())
    }
}
struct LabelContext<'a> {
    identities: &'a mut IdentityMap,
    seq: u32,
}
trait Walk {
    fn walk(&mut self, c: &mut LabelContext<'_>, locus: Introduction) -> Result<(), Loss>;
}
fn field_locus(field: &str) -> Introduction {
    match field {
        "frame" | "frame_id" | "foreground_frame" => Introduction::Frame,
        "connection"
        | "connection_id"
        | "connection_uuid"
        | "caps_connection"
        | "first_validated_connection"
        | "validated_connection" => Introduction::Connection,
        "session" | "session_id" => Introduction::Session,
        "attempt" => Introduction::CredentialAttempt,
        "constructed_receipt" => Introduction::ConstructedReceipt,
        "returned_receipt" => Introduction::ReturnedReceipt,
        "transferred_receipt" => Introduction::TransferredReceipt,
        "begun_receipt" => Introduction::BegunReceipt,
        // Publication observations already have this identity before sealing.
        // Only the actual snapshot's sealed field says whether sealing occurred.
        "control" | "auth_control" => Introduction::ControlIdentity,
        "receipt" => Introduction::ReceiptAssociation,
        "personal_archive_id" => Introduction::ArchiveCandidate,
        "stage_id" => Introduction::StageIdentity,
        "delivery_id" | "lease_token" | "message_id" | "claim_id" => Introduction::SourceIdentity,
        _ => Introduction::UnexpectedObservedIdentity,
    }
}
impl Walk for Id {
    fn walk(&mut self, c: &mut LabelContext<'_>, locus: Introduction) -> Result<(), Loss> {
        if c.seq != 0 {
            return Err(Loss::UnlabeledIdentity);
        }
        c.identities.anchor(self.0, locus)
    }
}
impl Walk for EvidenceId {
    fn walk(&mut self, c: &mut LabelContext<'_>, locus: Introduction) -> Result<(), Loss> {
        match self {
            Self::Raw(raw) if !c.identities.reading_wire => {
                let label = c.identities.observe(*raw, c.seq, locus)?;
                *self = Self::Encoded(label);
                Ok(())
            }
            Self::Encoded(label) if c.identities.reading_wire => {
                c.identities.observe_encoded(label, c.seq, locus)
            }
            Self::Raw(_) => Err(Loss::UnlabeledIdentity),
            Self::Encoded(_) => Err(Loss::EncodedIdentityAtCapture),
        }
    }
}
impl<T: Walk> Walk for Nullable<T> {
    fn walk(&mut self, c: &mut LabelContext<'_>, l: Introduction) -> Result<(), Loss> {
        if let Self::Value(v) = self {
            v.walk(c, l)?;
        }
        Ok(())
    }
}
impl<T: Walk, const N: usize> Walk for List<T, N> {
    fn walk(&mut self, c: &mut LabelContext<'_>, l: Introduction) -> Result<(), Loss> {
        for v in &mut self.0 {
            v.walk(c, l)?;
        }
        Ok(())
    }
}
impl<T: Walk, const N: usize> Walk for [T; N] {
    fn walk(&mut self, c: &mut LabelContext<'_>, l: Introduction) -> Result<(), Loss> {
        for v in self {
            v.walk(c, l)?;
        }
        Ok(())
    }
}
impl<const N: usize> Walk for Text<N> {
    fn walk(&mut self, _: &mut LabelContext<'_>, _: Introduction) -> Result<(), Loss> {
        Ok(())
    }
}
impl<const N: usize> Walk for Hex<N> {
    fn walk(&mut self, _: &mut LabelContext<'_>, _: Introduction) -> Result<(), Loss> {
        Ok(())
    }
}
impl<const N: usize> Walk for Bytes<N> {
    fn walk(&mut self, _: &mut LabelContext<'_>, _: Introduction) -> Result<(), Loss> {
        Ok(())
    }
}
macro_rules! scalar_walk { ($($t:ty),+) => { $(impl Walk for $t { fn walk(&mut self, _: &mut LabelContext<'_>, _: Introduction) -> Result<(), Loss> { Ok(()) } })+ }; }
scalar_walk!(bool, u8, u32, u64, i32, i64);

// This sum is exclusively the output observation vocabulary. It is not
// accepted by Case and has no commands, callbacks, or execution semantics.
sum!(
    #[expect(
        clippy::large_enum_variant,
        reason = "Finite test-only factual DTOs retain inline representation; measured memory fit remains required"
    )]
    Fact { Frame(FrameCapture<EvidenceId>), Muc(MucFact<EvidenceId>), Foreground(ForegroundFact<EvidenceId>), Claim(ClaimFact<EvidenceId>), Worker(WorkerFact<EvidenceId>), Credential(CredentialCapture<EvidenceId>), Control(ControlFact<EvidenceId>), Native(NativeFact<EvidenceId>), Bosh(BoshFact<EvidenceId>), Driver(DriverPoll) }
);
object!(Captured {
    seq: u32,
    fact: Fact
});
strings!(Execution {
    Complete,
    Cancelled,
    Failed
});
sum!(ObservationStatus { Complete(Empty), Lost(LostObservation) });
object!(LostObservation {
    reason: Loss,
    after_seq: u32
});
object!(Envelope { schema: Text<64>, entry: Text<128>, input_sha256: Sha256, rejection: Nullable<Rejection>, execution: Nullable<Execution>, resource_stop: Nullable<ResourceStop>, identity_map: List<IdentityIntroduction, MAX_IDENTITIES>, facts: List<Captured, MAX_FACTS>, observation_status: ObservationStatus });

#[derive(Default)]
// polls bounds retained Driver facts only, never actual owner admission.
pub(crate) struct Sequence {
    observations: u32,
    polls: u32,
}
impl Sequence {
    fn available(&self, poll: bool) -> Result<u32, Loss> {
        if self.observations as usize >= MAX_FACTS {
            return Err(Loss::FactOverflow);
        }
        if poll && self.polls as usize >= MAX_POLLS {
            return Err(Loss::PollOverflow);
        }
        Ok(self.observations + 1)
    }
    fn committed(&mut self, poll: bool) {
        self.observations += 1;
        if poll {
            self.polls += 1;
        }
    }
}
pub(crate) struct Recorder {
    input_sha256: Sha256,
    identities: IdentityMap,
    sequence: Sequence,
    facts: Vec<Captured>,
    snapshot_counts: BTreeMap<(u8, String), usize>,
    io_counts: BTreeMap<(u8, u8), usize>,
    loss: Option<Loss>,
    // Independent of retained facts and sticky semantic observation loss.
    // Never derived from Sequence.polls or charged again after recording.
    admitted_owner_polls: u8,
    resource_stop: Option<ResourceStop>,
}
impl Recorder {
    pub(crate) fn new(validated: &ValidatedCase) -> Self {
        Self {
            input_sha256: validated.input_sha256.clone(),
            identities: IdentityMap {
                fixed: validated.fixed_ids.clone(),
                ..IdentityMap::default()
            },
            sequence: Sequence::default(),
            facts: Vec::new(),
            snapshot_counts: BTreeMap::new(),
            io_counts: BTreeMap::new(),
            loss: None,
            admitted_owner_polls: 0,
            resource_stop: None,
        }
    }
    pub(crate) fn admitted_owner_polls(&self) -> u8 {
        self.admitted_owner_polls
    }
    pub(crate) fn resource_stop(&self) -> Option<&ResourceStop> {
        self.resource_stop.as_ref()
    }
    /// Reserve immediately before the declared owner's actual Future::poll,
    /// regardless of semantic capture loss. The 65th reservation never succeeds.
    pub(crate) fn reserve_owner_poll(&mut self, site: PollSite) -> Result<(), BudgetStop> {
        if let Some(stop) = &self.resource_stop {
            return Err(BudgetStop {
                resource_stop: stop.clone(),
            });
        }
        if self.admitted_owner_polls as usize == MAX_POLLS {
            let stop = ResourceStop::DriverPoll(DriverResourceStop {
                owner: site.owner,
                owner_ordinal: site.owner_ordinal,
                admitted_calls: self.admitted_owner_polls,
            });
            self.resource_stop = Some(stop.clone());
            return Err(BudgetStop {
                resource_stop: stop,
            });
        }
        self.admitted_owner_polls += 1;
        Ok(())
    }
    /// Writers own their independent counters/preflight. Latching valid bounded
    /// actual stop metadata never records a fact or changes the original loss.
    pub(crate) fn latch_resource_stop(
        &mut self,
        stop: ResourceStop,
    ) -> Result<BudgetStop, DriverConfigurationError> {
        if let Some(first) = &self.resource_stop {
            return Ok(BudgetStop {
                resource_stop: first.clone(),
            });
        }
        stop.validate()?;
        if let ResourceStop::DriverPoll(driver) = &stop {
            if driver.admitted_calls != self.admitted_owner_polls {
                return Err(DriverConfigurationError::AdmittedCalls);
            }
        }
        self.resource_stop = Some(stop.clone());
        Ok(BudgetStop {
            resource_stop: stop,
        })
    }
    /// Call exactly where the snapshot, return, or destructor is observed.
    /// There is no API for supplying a timestamp or filling an inferred event.
    pub(crate) fn capture(&mut self, mut fact: Fact) -> Result<u32, Loss> {
        if let Some(loss) = self.loss {
            return Err(loss);
        }
        let result = (|| {
            let poll = matches!(fact, Fact::Driver(_));
            let seq = self.sequence.available(poll)?;
            let key = snapshot_key(&fact);
            if let Some(key) = &key {
                if self.snapshot_counts.get(key).copied().unwrap_or(0) == MAX_OWNER_SNAPSHOTS {
                    return Err(Loss::OwnerSnapshotOverflow);
                }
            }
            let io_key = match &fact {
                Fact::Native(NativeFact::Write(x)) => Some(((0, x.item_ordinal), 32)),
                Fact::Native(NativeFact::Flush(x)) => Some(((1, x.item_ordinal), 1)),
                _ => None,
            };
            if let Some((key, limit)) = io_key {
                if self.io_counts.get(&key).copied().unwrap_or(0) == limit {
                    return Err(Loss::FactOverflow);
                }
            }
            // Label allocation is transactional with insertion: failure leaves
            // the retained prefix contiguous and does not leak a reserved ID.
            let mut identities = self.identities.clone();
            fact.walk(
                &mut LabelContext {
                    identities: &mut identities,
                    seq,
                },
                Introduction::UnexpectedObservedIdentity,
            )?;
            self.facts.push(Captured { seq, fact });
            self.identities = identities;
            self.sequence.committed(poll);
            if let Some(key) = key {
                *self.snapshot_counts.entry(key).or_default() += 1;
            }
            if let Some((key, _)) = io_key {
                *self.io_counts.entry(key).or_default() += 1;
            }
            Ok(seq)
        })();
        if let Err(loss) = result {
            self.loss = Some(loss);
        }
        result
    }
    pub(crate) fn polled<T>(
        &mut self,
        owner: DriverOwner,
        owner_ordinal: u8,
        actual: &std::task::Poll<T>,
    ) -> Result<u32, Loss> {
        // Retained observation only. This does not authorize or recharge a poll.
        if PollSite::new(owner, owner_ordinal).is_err() {
            return Err(*self.loss.get_or_insert(Loss::EncodingFailure));
        }
        self.capture(Fact::Driver(DriverPoll {
            owner,
            owner_ordinal,
            result: if actual.is_ready() {
                PollResult::Ready
            } else {
                PollResult::Pending
            },
        }))
    }
    pub(crate) fn missing_observation(&mut self) {
        self.loss.get_or_insert(Loss::MissingObservation);
    }
    pub(crate) fn finish(self, execution: Execution) -> Result<Envelope, Rejection> {
        let execution = if self.resource_stop.is_some() {
            Nullable::Null(())
        } else {
            Nullable::Value(execution)
        };
        self.finish_inner(execution)
    }
    /// After the caller drops the retained future, finish a resource cut
    /// without inventing a domain Execution or erasing an earlier loss.
    pub(crate) fn finish_resource_stopped(self) -> Result<Envelope, DriverConfigurationError> {
        if self.resource_stop.is_none() {
            return Err(DriverConfigurationError::MissingResourceStop);
        }
        self.finish_inner(Nullable::Null(()))
            .map_err(|_| DriverConfigurationError::EnvelopeEncoding)
    }
    fn finish_inner(self, execution: Nullable<Execution>) -> Result<Envelope, Rejection> {
        Ok(Envelope {
            schema: Text::new(EVIDENCE_SCHEMA)?,
            entry: Text::new(ENTRY)?,
            input_sha256: self.input_sha256,
            rejection: Nullable::Null(()),
            execution,
            resource_stop: self
                .resource_stop
                .map_or(Nullable::Null(()), Nullable::Value),
            identity_map: List::new(self.identities.introductions)?,
            facts: List::new(self.facts)?,
            observation_status: match self.loss {
                None => ObservationStatus::Complete(Empty {}),
                Some(reason) => ObservationStatus::Lost(LostObservation {
                    reason,
                    after_seq: self.sequence.observations,
                }),
            },
        })
    }
}
fn snapshot_key(fact: &Fact) -> Option<(u8, String)> {
    match fact {
        Fact::Frame(x) => Some((0, format!("{:?}", x.frame))),
        Fact::Muc(MucFact::Snapshot(x)) => Some((1, format!("{:?}", x.frame))),
        Fact::Foreground(ForegroundFact::Snapshot(x)) => Some((2, format!("{:?}", x.frame))),
        Fact::Claim(ClaimFact::Snapshot(x)) => Some((3, x.claim_ordinal.to_string())),
        Fact::Worker(WorkerFact::Snapshot(x)) => Some((4, x.attempt_ordinal.to_string())),
        Fact::Worker(WorkerFact::ChildDrop(x)) => Some((4, x.attempt_ordinal.to_string())),
        Fact::Worker(WorkerFact::Settlement(x)) => Some((4, x.attempt_ordinal.to_string())),
        Fact::Credential(x) => Some((5, format!("{:?}", x.snapshot.attempt))),
        Fact::Control(ControlFact::LivePublication(x)) => {
            Some((6, format!("{:?}", x.snapshot.control)))
        }
        Fact::Control(ControlFact::Holder(x)) => x
            .holder
            .get()
            .and_then(|h| h.introduced.get())
            .map(|a| (7, format!("{:?}", a.control))),
        Fact::Native(NativeFact::Snapshot(x)) => Some((8, x.item_ordinal.to_string())),
        Fact::Bosh(BoshFact::Snapshot(x)) => Some((9, x.owner_ordinal.to_string())),
        Fact::Bosh(BoshFact::Selection(x)) => {
            Some((10, format!("{:?}/{}", x.selection.session, x.selection.rid)))
        }
        _ => None,
    }
}
pub(crate) fn sha256(bytes: &[u8]) -> Sha256 {
    use sha2::Digest;
    Hex(sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
impl Envelope {
    pub(crate) fn rejected(input: &[u8], rejection: Rejection) -> Result<Self, Rejection> {
        if input.len() > MAX_INPUT {
            return Err(Rejection::TooLarge);
        }
        Ok(Self {
            schema: Text::new(EVIDENCE_SCHEMA)?,
            entry: Text::new(ENTRY)?,
            input_sha256: sha256(input),
            rejection: Nullable::Value(rejection),
            execution: Nullable::Null(()),
            resource_stop: Nullable::Null(()),
            identity_map: List::new(vec![])?,
            facts: List::new(vec![])?,
            observation_status: ObservationStatus::Complete(Empty {}),
        })
    }
}
struct CappedWriter {
    bytes: Vec<u8>,
    overflow: bool,
}
impl std::io::Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_FRAME.saturating_sub(self.bytes.len()) {
            self.overflow = true;
            return Err(std::io::Error::other("Stage4 evidence cap"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode_frame(envelope: &Envelope) -> Result<Vec<u8>, Loss> {
    let mut payload = CappedWriter {
        bytes: Vec::new(),
        overflow: false,
    };
    if serde_json::to_writer(&mut payload, envelope).is_err() {
        return Err(if payload.overflow {
            Loss::FrameOverflow
        } else {
            Loss::EncodingFailure
        });
    }
    let header = format!("\x1e{FRAME_TAG} {}\n", payload.bytes.len());
    let trailer = b"\n\x1eEND\n";
    if header.len() + payload.bytes.len() + trailer.len() > MAX_FRAME {
        return Err(Loss::FrameOverflow);
    }
    let mut frame = header.into_bytes();
    frame.extend(payload.bytes);
    frame.extend_from_slice(trailer);
    Ok(frame)
}
pub(crate) fn decode_frame(frame: &[u8]) -> Result<Envelope, Rejection> {
    if frame.len() > MAX_FRAME {
        return Err(Rejection::TooLarge);
    }
    let newline = frame
        .iter()
        .position(|b| *b == b'\n')
        .ok_or(Rejection::Encoding)?;
    let header = std::str::from_utf8(&frame[..newline]).map_err(|_| Rejection::Encoding)?;
    let count = header
        .strip_prefix(&format!("\x1e{FRAME_TAG} "))
        .ok_or(Rejection::Schema)?;
    require(
        !count.is_empty()
            && count.bytes().all(|c| c.is_ascii_digit())
            && (count == "0" || !count.starts_with('0')),
    )?;
    let count: usize = count.parse().map_err(|_| Rejection::Bound)?;
    let end = (newline + 1).checked_add(count).ok_or(Rejection::Bound)?;
    require(end <= frame.len() && &frame[end..] == b"\n\x1eEND\n")?;
    let envelope: Envelope =
        serde_json::from_slice(&frame[newline + 1..end]).map_err(|_| Rejection::Json)?;
    require(envelope.schema.as_str() == EVIDENCE_SCHEMA && envelope.entry.as_str() == ENTRY)
        .map_err(|_| Rejection::Schema)?;
    let canonical = serde_json::to_vec(&envelope).map_err(|_| Rejection::Encoding)?;
    if canonical.as_slice() != &frame[newline + 1..end] {
        return Err(Rejection::Encoding);
    }
    Ok(envelope)
}
/// Structural encoding/identity validation only. Unsafe but well-typed domain
/// histories are retained for the independent semantic oracle, not rejected here.
pub(crate) fn validate_envelope(
    envelope: &Envelope,
    input: &[u8],
    case: Option<&ValidatedCase>,
) -> Result<(), Loss> {
    if envelope.input_sha256 != sha256(input) {
        return Err(Loss::EncodingFailure);
    }
    if let Some(reason) = envelope.rejection.get() {
        if envelope.execution.get().is_some()
            || envelope.resource_stop.get().is_some()
            || !envelope.facts.is_empty()
            || !envelope.identity_map.is_empty()
            || case.is_some()
        {
            return Err(Loss::EncodingFailure);
        }
        if decode(input).err().as_ref() != Some(reason)
            || !matches!(envelope.observation_status, ObservationStatus::Complete(_))
        {
            return Err(Loss::EncodingFailure);
        }
        return Ok(());
    }
    let case = case.ok_or(Loss::EncodingFailure)?;
    if case.input_sha256 != sha256(input) {
        return Err(Loss::EncodingFailure);
    }
    match envelope.resource_stop.get() {
        Some(stop) => {
            stop.validate().map_err(|_| Loss::EncodingFailure)?;
            if envelope.execution.get().is_some() {
                return Err(Loss::EncodingFailure);
            }
        }
        None => {
            if envelope.execution.get().is_none() {
                return Err(Loss::EncodingFailure);
            }
        }
    }
    // A valid resource_stop means incomplete/nonqualifying, before fixture
    // matching. This structural function does not qualify anything, including
    // a mutant (whose intentional qualified=false alone is not this distinction).
    let mut map = IdentityMap {
        fixed: case.fixed_ids.clone(),
        reading_wire: true,
        ..IdentityMap::default()
    };
    let mut counts = BTreeMap::new();
    let mut io_counts = BTreeMap::new();
    let mut polls = 0;
    for (index, record) in envelope.facts.as_slice().iter().enumerate() {
        if record.seq != index as u32 + 1 {
            return Err(Loss::NoncontiguousSequence);
        }
        if let Fact::Driver(poll) = &record.fact {
            PollSite::new(poll.owner, poll.owner_ordinal).map_err(|_| Loss::EncodingFailure)?;
            polls += 1;
            if polls > MAX_POLLS {
                return Err(Loss::PollOverflow);
            }
        }
        if let Some(key) = snapshot_key(&record.fact) {
            let n = counts.entry(key).or_insert(0);
            *n += 1;
            if *n > MAX_OWNER_SNAPSHOTS {
                return Err(Loss::OwnerSnapshotOverflow);
            }
        }
        let io_key = match &record.fact {
            Fact::Native(NativeFact::Write(x)) => Some(((0, x.item_ordinal), 32)),
            Fact::Native(NativeFact::Flush(x)) => Some(((1, x.item_ordinal), 1)),
            _ => None,
        };
        if let Some((key, limit)) = io_key {
            let n = io_counts.entry(key).or_insert(0);
            *n += 1;
            if *n > limit {
                return Err(Loss::FactOverflow);
            }
        }
        let mut fact = record.fact.clone();
        fact.walk(
            &mut LabelContext {
                identities: &mut map,
                seq: record.seq,
            },
            Introduction::UnexpectedObservedIdentity,
        )?;
    }
    if map.introductions.as_slice() != envelope.identity_map.as_slice() {
        return Err(Loss::NoncanonicalIdentity);
    }
    if let ObservationStatus::Lost(lost) = &envelope.observation_status {
        if lost.after_seq != envelope.facts.len() as u32 {
            return Err(Loss::NoncontiguousSequence);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

// ---- Finite test-only composition dispatcher ----
// The closed schema and its separate driver retain bounded data and polling.
// Each recipe composes actual owners over finite supplied replies.
// This extension is not an oracle or fixture matcher.
// Process-level execution uses the separate bounded ignored entry below.
mod saved_dispatcher {
    use super::*;
    use crate::bosh::stage4_saved as bosh;
    use crate::xmpp::auth_publication::stage4_saved as auth;
    use crate::xmpp::outbound::{OutboundItem, RouteEnqueue};
    use crate::xmpp::protocol::mix::stage4_saved as mix;
    use crate::xmpp::stage4_native as native;
    use anyhow::{anyhow, bail, ensure, Context, Result};
    use std::{
        sync::{Arc, Mutex},
        task::Poll,
    };
    use tokio::sync::mpsc;

    type Capture = driver::Capture;

    // Root-only exits. Neither variant is a domain future's output, and this
    // enum intentionally has no Error implementation. BudgetStop never enters
    // anyhow, FrameFailure, a bool callback or a synthetic transport result.
    #[derive(Debug)]
    enum DispatchExit {
        Failed(anyhow::Error),
        Resource(BudgetStop),
    }
    type DispatchResult<T> = std::result::Result<T, DispatchExit>;
    impl From<anyhow::Error> for DispatchExit {
        fn from(error: anyhow::Error) -> Self {
            Self::Failed(error)
        }
    }
    fn driven<T>(actual: std::result::Result<Result<T>, BudgetStop>) -> DispatchResult<T> {
        match actual {
            Ok(result) => result.map_err(DispatchExit::Failed),
            Err(stop) => Err(DispatchExit::Resource(stop)),
        }
    }
    fn require_driver(condition: bool, message: &str) -> Result<()> {
        ensure!(condition, "{message}");
        Ok(())
    }

    // Role-checked data labels prepared before any real owner. These arrays do
    // not own budgets, authorize work, reset state, or encode commands. Exactly
    // the actual introduced item/operation ordinal indexes its immutable label.
    struct Sites {
        native: [native::NativeSite; 5],
        bosh: [bosh::BoshSite; 4],
        credential: [auth::CredentialSite; 2],
        publication: auth::PublicationSite,
        claim: [mix::ClaimSites; 2],
        foreground: mix::ForegroundSite,
    }
    impl Sites {
        fn new(case: &ValidatedCase) -> Result<Self> {
            let sites = Self {
                native: [
                    native::NativeSite::new(0)?,
                    native::NativeSite::new(1)?,
                    native::NativeSite::new(2)?,
                    native::NativeSite::new(3)?,
                    native::NativeSite::new(4)?,
                ],
                bosh: [
                    bosh::BoshSite::new(0)?,
                    bosh::BoshSite::new(1)?,
                    bosh::BoshSite::new(2)?,
                    bosh::BoshSite::new(3)?,
                ],
                credential: [auth::CredentialSite::new(0)?, auth::CredentialSite::new(1)?],
                publication: auth::PublicationSite::new(0)?,
                claim: [mix::ClaimSites::new(0)?, mix::ClaimSites::new(1)?],
                foreground: mix::ForegroundSite::new(0)?,
            };
            let check = |ordinal: usize, script: &WriteScript| {
                require_driver(
                    native::preparation_valid(sites.native[ordinal], script),
                    "invalid native site/script preparation",
                )
            };
            match &case.case().composition {
                Composition::Muc(input) => {
                    if let Some(plan) = input.native.get() {
                        check(0, &plan.write)?;
                    }
                }
                Composition::AuthThenMixNative(input) => {
                    check(0, &input.auth_native.write)?;
                    check(1, &input.delivery_native.write)?;
                }
                Composition::MixRecoveryNative(input) => check(1, &input.native.write)?,
                Composition::NativeAuth(input) => check(0, &input.native.write)?,
                Composition::ReplayMixQueuedAuth(_)
                | Composition::MixDefer(_)
                | Composition::BoshAuth(_) => {}
            }
            Ok(sites)
        }
    }

    // These are topology bounds, not JSON-selected execution commands. Ordinals
    // describe actual item/operation introductions in this one case. No counter
    // is persisted, used as authority, or included in the literal case input.
    #[derive(Default)]
    struct Ordinals {
        items: u8,
        bosh_operations: u8,
        credentials: u8,
    }
    impl Ordinals {
        fn item(&mut self) -> Result<u8> {
            Self::take(&mut self.items, 5, "logical output item")
        }
        fn bosh(&mut self) -> Result<u8> {
            Self::take(&mut self.bosh_operations, 4, "BOSH operation")
        }
        fn credential(&mut self) -> Result<u8> {
            Self::take(&mut self.credentials, 2, "credential invocation")
        }
        fn take(next: &mut u8, cap: u8, name: &str) -> Result<u8> {
            ensure!(*next < cap, "finite {name} introduction cap");
            let ordinal = *next;
            *next += 1;
            Ok(ordinal)
        }
    }
    fn lost(recorder: &Capture) {
        driver::lost(recorder);
    }

    // WorkerRun owns the reserve-before-poll call for its contained AttemptRun.
    // Root does not meter or emit a duplicate wrapper poll. Pending is retained
    // only for the actual queue handoff cut, then the same worker is resumed.
    async fn worker_pending(run: &mut mix::WorkerRun) -> DispatchResult<()> {
        match futures::poll!(std::pin::Pin::new(run)) {
            Poll::Pending => Ok(()),
            Poll::Ready(Err(stop)) => Err(DispatchExit::Resource(stop)),
            Poll::Ready(Ok(Err(error))) => Err(DispatchExit::Failed(error)),
            Poll::Ready(Ok(Ok(()))) => Err(DispatchExit::Failed(anyhow!(
                "worker returned before retained local handoff"
            ))),
        }
    }
    async fn worker_returned(run: &mut mix::WorkerRun) -> DispatchResult<()> {
        // Every real AttemptRun repoll is charged by WorkerRun. No extra poll,
        // scheduled retry loop, or new transport completion is supplied here.
        driven(run.await)
    }
    fn auth_lookup(routes: &mix::RouteMap, route: &mix::RouteHandle, read: &auth::AuthRead) {
        routes.capture_lookup(
            RouteLookupOwner::Auth(OneId {
                id: EvidenceId::observed(read.frame_id()),
            }),
            route.full_jid(),
        );
    }
    fn initial_input(worker: &WorkerInput) -> Result<&DeliveryRow<Id>> {
        match &worker.origin {
            ClaimOrigin::InitialDurableRow(row) => Ok(row),
            ClaimOrigin::FreshProjection(_) => {
                bail!("initial-row recipe received projection origin")
            }
        }
    }
    fn initial_bridge(worker: &WorkerInput, recorder: &Capture) -> Result<mix::Bridge> {
        // The only domain source for an initial durable row is its explicit
        // canonical channel JID. No saved hidden domain or replacement row.
        let channel =
            northstar_xmpp_types::CanonicalJid::parse(initial_input(worker)?.channel_jid.as_str())?;
        mix::Bridge::new(channel.domainpart(), recorder.clone())
    }
    fn install_target(
        routes: &mix::RouteMap,
        input: &RouteEnvironment,
    ) -> Result<(mix::RouteHandle, mpsc::Receiver<OutboundItem>)> {
        let [target] = input.targets.as_slice() else {
            bail!("finite delivered environment requires one target")
        };
        routes.install(target, input.queue_capacity)
    }
    fn enqueue_auth(
        route: &mix::RouteHandle,
        queue: &mut mpsc::Receiver<OutboundItem>,
        item: OutboundItem,
    ) -> Result<OutboundItem> {
        // Clone only bytes for the existing bind gate. Never clone the actual
        // item, auth holder, durable permit, or transport completion sender.
        let actual_bytes = item.stanza.clone();
        let enqueue = RouteEnqueue::bind(item, None, &actual_bytes)
            .map_err(|_| anyhow!("actual auth item failed route binding"))?;
        route
            .sender()
            .try_send_route_item(enqueue)
            .map_err(|_| anyhow!("actual auth queue refused item"))?;
        queue
            .try_recv()
            .map_err(|_| anyhow!("actual auth queue item absent"))
    }
    async fn build_auth(
        input: &AuthInput,
        route: Option<mix::RouteHandle>,
        ordinals: &mut Ordinals,
        recorder: &Capture,
        sites: &Sites,
    ) -> DispatchResult<(OutboundItem, auth::AuthRead, auth::Publisher)> {
        let ordinal = ordinals.credential()?;
        let built = driven(
            auth::build(
                input,
                route,
                recorder.clone(),
                sites.credential[usize::from(ordinal)],
            )
            .await,
        )?;
        let (item, read, publisher) = built.split();
        // No spawned work exists. build's metered owner has returned/dropped,
        // the single driver stack is paused and read clones have no mutator.
        read.capture_frame_quiescent(Cut::AfterRunnerDrop);
        Ok((item, read, publisher))
    }
    fn publication_execution(
        returned: Option<bool>,
        dropped: bool,
        drive: AuthDrive,
        recorder: &Capture,
    ) -> Execution {
        match (returned, dropped, drive) {
            // A handled backend error is an observed return, not an adapter
            // failure. The independent reader judges its effects and fixture.
            (Some(_), false, _) => Execution::Complete,
            (None, true, AuthDrive::DropPublicationCommit) => Execution::Cancelled,
            _ => {
                lost(recorder);
                Execution::Failed
            }
        }
    }
    async fn native_auth(
        input: &NativeAuthInput,
        recorder: &Capture,
        ordinals: &mut Ordinals,
        sites: &Sites,
    ) -> DispatchResult<Execution> {
        let routes = mix::RouteMap::new(recorder.clone());
        let (route, mut queue) = routes.install_auth(&input.auth, 1)?;
        let (item, read, mut publisher) =
            build_auth(&input.auth, Some(route.clone()), ordinals, recorder, sites).await?;
        auth_lookup(&routes, &route, &read);
        let item = enqueue_auth(&route, &mut queue, item)?;
        let ordinal = ordinals.item()?;
        let owner = driven(
            native::write_auth(
                item,
                route.connection_id(),
                sites.native[usize::from(ordinal)],
                input.native.write.clone(),
                recorder.clone(),
            )
            .await,
        )?;
        let actual = driven(
            auth::publish_native(
                owner,
                &read,
                &mut publisher,
                input.drive,
                recorder,
                sites.publication,
            )
            .await,
        )?;
        auth_lookup(&routes, &route, &read);
        Ok(publication_execution(
            actual.returned,
            actual.dropped,
            input.drive,
            recorder,
        ))
    }
    async fn auth_then_mix(
        input: &FreshMixNativeInput,
        recorder: &Capture,
        ordinals: &mut Ordinals,
        sites: &Sites,
    ) -> DispatchResult<Execution> {
        let routes = mix::RouteMap::new(recorder.clone());
        let (route, mut queue) = install_target(&routes, &input.worker.attempt.route)?;
        let (item, read, mut publisher) =
            build_auth(&input.auth, Some(route.clone()), ordinals, recorder, sites).await?;
        auth_lookup(&routes, &route, &read);
        let item = enqueue_auth(&route, &mut queue, item)?;
        let auth_ordinal = ordinals.item()?;
        let owner = driven(
            native::write_auth(
                item,
                route.connection_id(),
                sites.native[usize::from(auth_ordinal)],
                input.auth_native.write.clone(),
                recorder.clone(),
            )
            .await,
        )?;
        let actual = driven(
            auth::publish_native(
                owner,
                &read,
                &mut publisher,
                AuthDrive::Complete,
                recorder,
                sites.publication,
            )
            .await,
        )?;
        auth_lookup(&routes, &route, &read);
        // Continue only after the real publication continuation returned. No
        // fixture field can activate the route; real lookup/worker policy below
        // still decides whether this same retained session is eligible.
        require_driver(
            !actual.dropped && actual.returned == Some(true),
            "auth continuation did not complete before MIX",
        )?;
        let bridge = mix::Bridge::new(
            input.foreground.configured_domain.as_str(),
            recorder.clone(),
        )?;
        let ClaimOrigin::FreshProjection(origin) = &input.worker.origin else {
            return Err(DispatchExit::Failed(anyhow!("fresh recipe origin missing")));
        };
        let row = driven(
            bridge
                .fresh(
                    &input.foreground,
                    origin,
                    &input.worker.attempt.claim,
                    sites.foreground,
                )
                .await,
        )?;
        let mut worker = driven(
            bridge
                .claim(row, &input.worker.attempt, sites.claim[0], routes.clone())
                .await,
        )?;
        worker_pending(&mut worker).await?;
        let item = queue
            .try_recv()
            .context("actual fresh MIX queue item absent")?;
        let ordinal = ordinals.item()?;
        worker.record_dequeued(&route, ordinal, &item);
        bridge.supply_native(&input.delivery_native)?;
        let service = bridge.service();
        driven(
            native::write_item(
                item,
                route.connection_id(),
                sites.native[usize::from(ordinal)],
                ItemOwner::Mix(MixItemOwner { attempt_ordinal: 0 }),
                input.delivery_native.write.clone(),
                Some(&service),
                recorder.clone(),
            )
            .await,
        )?;
        worker_returned(&mut worker).await?;
        drop(worker);
        Ok(Execution::Complete)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Finite lane keeps owner, input, transport, route, queue, recorder, ordinal and poll-site dependencies explicit"
    )]
    async fn mix_bosh_lane(
        bridge: &mix::Bridge,
        worker_input: &WorkerInput,
        transport: &MixBoshTransport,
        routes: &mix::RouteMap,
        route: &mix::RouteHandle,
        queue: &mut mpsc::Receiver<OutboundItem>,
        recorder: &Capture,
        ordinals: &mut Ordinals,
        sites: &Sites,
    ) -> DispatchResult<bosh::Session> {
        let row = bridge.initial_row(initial_input(worker_input)?)?;
        let mut worker = driven(
            bridge
                .claim(row, &worker_input.attempt, sites.claim[0], routes.clone())
                .await,
        )?;
        worker_pending(&mut worker).await?;
        let item = queue
            .try_recv()
            .context("actual independent MIX queue item absent")?;
        let item_ordinal = ordinals.item()?;
        worker.record_dequeued(route, item_ordinal, &item);
        bridge.supply_bosh_transfer(&transport.transfer)?;
        let service = bridge.service();
        let mut session = bosh::Session::new(transport.session.clone(), recorder.clone())?;
        let transfer_ordinal = ordinals.bosh()?;
        let accepted = driven(
            session
                .push_mix(
                    item,
                    item_ordinal,
                    sites.bosh[usize::from(transfer_ordinal)],
                    &service,
                )
                .await,
        )?;
        require_driver(
            accepted,
            "actual independent MIX BOSH FIFO refused transfer",
        )?;
        // Only actual ServiceTransfer/record_and_push can signal the typed
        // BoshPersisted completion consumed by this still-live worker.
        worker_returned(&mut worker).await?;
        drop(worker);
        let response_ordinal = ordinals.bosh()?;
        let response = driven(
            session
                .respond(
                    sites.bosh[usize::from(response_ordinal)],
                    AuthDrive::Complete,
                )
                .await,
        )?;
        require_driver(
            !response.dropped && response.returned == Some(true),
            "independent MIX response did not complete before auth lane",
        )?;
        Ok(session)
    }
    async fn queued_auth(
        input: &ReplayMixQueuedAuth,
        recorder: &Capture,
        ordinals: &mut Ordinals,
        sites: &Sites,
    ) -> DispatchResult<Execution> {
        let routes = mix::RouteMap::new(recorder.clone());
        let (m_route, mut m_queue) = install_target(&routes, &input.mix.worker.attempt.route)?;
        // A exists while M performs actual lookup, but remains staged. The two
        // rows retain distinct queues, connection IDs, lifecycle and tokens.
        let (a_route, a_queue) = routes.install_auth(&input.auth.bound, 1)?;
        let bridge = mix::Bridge::new(
            input.mix.foreground.configured_domain.as_str(),
            recorder.clone(),
        )?;
        let _actual_replay_id =
            driven(bridge.replay(&input.mix.foreground, sites.foreground).await)?;
        let mut m = mix_bosh_lane(
            &bridge,
            &input.mix.worker,
            &input.mix.transport,
            &routes,
            &m_route,
            &mut m_queue,
            recorder,
            ordinals,
            sites,
        )
        .await?;
        let (u_item, u_read, u_publish) =
            build_auth(&input.auth.unbound, None, ordinals, recorder, sites).await?;
        let (b_item, b_read, b_publish) = build_auth(
            &input.auth.bound,
            Some(a_route.clone()),
            ordinals,
            recorder,
            sites,
        )
        .await?;
        auth_lookup(&routes, &a_route, &b_read);
        let mut a = bosh::Session::new(input.auth.session.clone(), recorder.clone())?;
        // All four exact supplied items exist before real selection. P/F are
        // the explicitly supplied fixed helper output, not handler evidence.
        a.push_plain(
            input.auth.padding.presence_xml.as_str().to_owned(),
            ordinals.item()?,
        )?;
        a.push_auth(u_item, u_read.clone(), u_publish, ordinals.item()?)?;
        a.push_plain(
            input.auth.padding.features_xml.as_str().to_owned(),
            ordinals.item()?,
        )?;
        a.push_auth(b_item, b_read.clone(), b_publish, ordinals.item()?)?;
        let response_ordinal = ordinals.bosh()?;
        let actual = driven(
            a.respond(
                sites.bosh[usize::from(response_ordinal)],
                AuthDrive::Complete,
            )
            .await,
        )?;
        auth_lookup(&routes, &a_route, &b_read);
        // No selection/callback/expected-count assertion here. Actual P/U and
        // remaining F/B, or any contradiction, are preserved for the reader.
        let result = publication_execution(
            actual.returned,
            actual.dropped,
            AuthDrive::Complete,
            recorder,
        );
        let ack = input
            .mix
            .transport
            .ack
            .get()
            .context("validated M ACK absent")?;
        let ack_ordinal = ordinals.bosh()?;
        driven(
            m.acknowledge(ack, sites.bosh[usize::from(ack_ordinal)])
                .await,
        )?;
        // ACK is actual renew/ACK plus a separate empty Payload response.
        // No EmptyControl, new logical item/frame, or fabricated callback.
        a.teardown()?;
        u_read.capture_frame_quiescent(Cut::AfterTeardown);
        b_read.capture_frame_quiescent(Cut::AfterTeardown);
        m.teardown()?;
        drop(a_queue);
        Ok(result)
    }
    async fn recovery(
        input: &RecoveryInput,
        recorder: &Capture,
        ordinals: &mut Ordinals,
        sites: &Sites,
    ) -> DispatchResult<Execution> {
        let bridge = initial_bridge(&input.worker, recorder)?;
        let original = bridge.initial_row(initial_input(&input.worker)?)?;
        let old_routes = mix::RouteMap::new(recorder.clone());
        let (old_route, mut old_queue) = install_target(&old_routes, &input.worker.attempt.route)?;
        let mut first = driven(
            bridge
                .claim(
                    original.clone(),
                    &input.worker.attempt,
                    sites.claim[0],
                    old_routes.clone(),
                )
                .await,
        )?;
        worker_pending(&mut first).await?;
        let old_item = old_queue
            .try_recv()
            .context("actual old queue item absent")?;
        first.record_dequeued(&old_route, ordinals.item()?, &old_item);
        let old_read = first.observation();
        // This is eligibility for the requested driver cut, not a settlement
        // policy or safety verdict. Observation-only join loss cannot supply
        // that eligibility: inspect the real still-live local request state.
        let actual_cut = old_read.snapshot();
        require_driver(
            actual_cut
                .local
                .last()
                .is_some_and(|local| local.started && local.enqueued && local.returned.is_none())
                && old_item.mix_delivery() == Some(old_read.row().source),
            "old drop did not reach its actual pending local handoff",
        )?;
        // Pending was genuinely returned by this WorkerRun, with its actual
        // item retained and local result absent. Drop the future, not input.
        drop(first);
        let new_routes = mix::RouteMap::new(recorder.clone());
        let (new_route, mut new_queue) = install_target(&new_routes, &input.replacement.route)?;
        let row = bridge.replacement_row(&original, &input.replacement.claim)?;
        let mut second = driven(
            bridge
                .claim(row, &input.replacement, sites.claim[1], new_routes.clone())
                .await,
        )?;
        worker_pending(&mut second).await?;
        let item = new_queue
            .try_recv()
            .context("actual replacement queue item absent")?;
        let ordinal = ordinals.item()?;
        second.record_dequeued(&new_route, ordinal, &item);
        bridge.supply_native(&input.native)?;
        let service = bridge.service();
        driven(
            native::write_item(
                item,
                new_route.connection_id(),
                sites.native[usize::from(ordinal)],
                ItemOwner::Mix(MixItemOwner { attempt_ordinal: 1 }),
                input.native.write.clone(),
                Some(&service),
                recorder.clone(),
            )
            .await,
        )?;
        worker_returned(&mut second).await?;
        drop(second);
        // Keep every old association and the unconsumed old transport item
        // through replacement completion. Never clear or retarget cancellation.
        drop(old_item);
        drop(old_read);
        drop(old_queue);
        drop(old_route);
        drop(old_routes);
        Ok(Execution::Complete)
    }
    async fn defer(
        input: &DeferInput,
        recorder: &Capture,
        sites: &Sites,
    ) -> DispatchResult<Execution> {
        let bridge = initial_bridge(&input.worker, recorder)?;
        let row = bridge.initial_row(initial_input(&input.worker)?)?;
        bridge.supply_defer(input.settlement_commit, input.updated)?;
        let routes = mix::RouteMap::new(recorder.clone());
        let mut worker = driven(
            bridge
                .claim(row, &input.worker.attempt, sites.claim[0], routes)
                .await,
        )?;
        // Actual shared route/classifier destroys its route scope, closes the
        // renewal scope, then settles Defer. Nothing drives a ten-second timer.
        worker_returned(&mut worker).await?;
        drop(worker);
        Ok(Execution::Complete)
    }
    async fn bosh_auth(
        input: &BoshAuthInput,
        recorder: &Capture,
        ordinals: &mut Ordinals,
        sites: &Sites,
    ) -> DispatchResult<Execution> {
        let routes = mix::RouteMap::new(recorder.clone());
        let (a_route, a_queue) = routes.install_auth(&input.auth.bound, 1)?;
        // M is an optional, wholly independent initial-row subtree. A never
        // receives its item/source. This exact structural branch permits the
        // same reduced literal bytes in baseline S13 and mutant M2/M3.
        let mut retained_m = None;
        if let Some(m) = input.mix.get() {
            let (route, mut queue) = install_target(&routes, &m.worker.attempt.route)?;
            let bridge = initial_bridge(&m.worker, recorder)?;
            let session = mix_bosh_lane(
                &bridge,
                &m.worker,
                &m.transport,
                &routes,
                &route,
                &mut queue,
                recorder,
                ordinals,
                sites,
            )
            .await?;
            retained_m = Some((session, route, queue, bridge));
        }
        // Complete M's actual response before constructing/starting A response.
        let (item, read, publisher) = build_auth(
            &input.auth.bound,
            Some(a_route.clone()),
            ordinals,
            recorder,
            sites,
        )
        .await?;
        auth_lookup(&routes, &a_route, &read);
        let mut a = bosh::Session::new(input.auth.session.clone(), recorder.clone())?;
        a.push_auth(item, read.clone(), publisher, ordinals.item()?)?;
        let response_ordinal = ordinals.bosh()?;
        let actual = driven(
            a.respond(sites.bosh[usize::from(response_ordinal)], input.auth.drive)
                .await,
        )?;
        auth_lookup(&routes, &a_route, &read);
        let result =
            publication_execution(actual.returned, actual.dropped, input.auth.drive, recorder);
        // Baseline error and mutant skipped callback are both emitted as actual
        // observations. Never assert callback count, BackendFailure or no-cache
        // here. The later independent safety reader owns the causal verdict.
        a.teardown()?;
        read.capture_frame_quiescent(Cut::AfterTeardown);
        if let Some((m, route, queue, bridge)) = retained_m {
            m.teardown()?;
            drop(queue);
            drop(route);
            drop(bridge);
        }
        drop(a_queue);
        Ok(result)
    }

    async fn dispatch(
        case: &ValidatedCase,
        recorder: &Capture,
        sites: &Sites,
    ) -> DispatchResult<Execution> {
        let mut ordinals = Ordinals::default();
        match &case.case().composition {
            Composition::Muc(input) => {
                crate::xmpp::protocol::muc::saved_stage4::run(input.clone(), recorder.clone())
                    .await
                    .map_err(DispatchExit::Resource)
            }
            Composition::AuthThenMixNative(input) => {
                auth_then_mix(input, recorder, &mut ordinals, sites).await
            }
            Composition::ReplayMixQueuedAuth(input) => {
                queued_auth(input, recorder, &mut ordinals, sites).await
            }
            Composition::MixRecoveryNative(input) => {
                recovery(input, recorder, &mut ordinals, sites).await
            }
            Composition::MixDefer(input) => defer(input, recorder, sites).await,
            Composition::NativeAuth(input) => {
                native_auth(input, recorder, &mut ordinals, sites).await
            }
            Composition::BoshAuth(input) => bosh_auth(input, recorder, &mut ordinals, sites).await,
        }
    }
    fn finish_capture(recorder: Capture, result: DispatchResult<Execution>) -> Result<Envelope> {
        // dispatch has exited: every stack-owned future/item/route/publisher
        // has already returned or been dropped. No root owner alias escapes.
        let owned = Arc::try_unwrap(recorder)
            .map_err(|_| anyhow!("dispatcher retained a recorder owner after teardown"))?;
        let mut recorder = match owned.into_inner() {
            Ok(recorder) => recorder,
            Err(poisoned) => {
                let mut recorder = poisoned.into_inner();
                recorder.missing_observation();
                recorder
            }
        };
        if let Err(DispatchExit::Resource(stop)) = &result {
            // Stop metadata must already have been latched by actual admission
            // or the writer's real counter/preflight. Root never fabricates it.
            require_driver(
                recorder.resource_stop() == Some(&stop.resource_stop),
                "returned resource stop differs from first actual latch",
            )?;
        }
        if recorder.resource_stop().is_some() {
            return Ok(recorder.finish_resource_stopped()?);
        }
        match result {
            Ok(execution) => Ok(recorder.finish(execution)?),
            Err(DispatchExit::Failed(_actual_error)) => {
                recorder.missing_observation();
                Ok(recorder.finish(Execution::Failed)?)
            }
            Err(DispatchExit::Resource(_)) => {
                Err(anyhow!("resource stop returned without retained metadata"))
            }
        }
    }
    pub(super) async fn run_bytes(input: &[u8]) -> Result<Envelope> {
        // The closed schema is the sole input-validation/rejection authority, including
        // unsupported notification intent. Invalid inputs create no owner.
        let case = match decode(input) {
            Ok(case) => case,
            Err(reason) => return Ok(Envelope::rejected(input, reason)?),
        };
        let sites = Sites::new(&case)?; // labels/scripts validated before owners
        let recorder = Arc::new(Mutex::new(Recorder::new(&case)));
        // Supervisor retains the complete five-second process/stdio budget.
        // Normal nested service/Publisher callbacks are never extra poll sites.
        let result = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dispatch(&case, &recorder, &sites),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(DispatchExit::Failed(anyhow!("finite dispatcher timed out"))),
        };
        finish_capture(recorder, result)
    }

    #[cfg(test)]
    mod dispatcher_controls {
        use super::*;
        use crate::xmpp::auth_publication::stage4_saved::ordinary as fixtures;

        // Bounded ordinary programmatic inputs using actual public builders in
        // the peer ordinary fixture. These are not frozen saved literal bytes,
        // expected evidence, record/replay output, or process-start contracts.
        fn native_case(drop_commit: bool) -> Case {
            let publication = if drop_commit {
                PublicationReply::CommitPending(EpochReply {
                    epoch: Nullable::Null(()),
                })
            } else {
                PublicationReply::BackendError(Empty {})
            };
            let auth = fixtures::bound(TransportKind::Tcp, publication);
            Case {
                schema: fixtures::text(CASE_SCHEMA),
                case_id: fixtures::text("ordinary-dispatch"),
                adapter_contract: fixtures::text(ADAPTER_CONTRACT),
                composition: Composition::NativeAuth(NativeAuthInput {
                    native: PlainNative {
                        connection_id: auth.frame.connection_id,
                        write: fixtures::write_ok(),
                    },
                    auth,
                    drive: if drop_commit {
                        AuthDrive::DropPublicationCommit
                    } else {
                        AuthDrive::Complete
                    },
                }),
            }
        }
        async fn ordinary(case: &Case) -> Envelope {
            run_bytes(&serde_json::to_vec(case).unwrap()).await.unwrap()
        }
        fn complete_observations(envelope: &Envelope) {
            assert!(matches!(
                envelope.observation_status,
                ObservationStatus::Complete(_)
            ));
        }

        #[tokio::test]
        async fn rejected_duplicate_positional_and_relationship_inputs_have_no_owner_facts() {
            let case = native_case(false);
            let original = serde_json::to_string(&case).unwrap();
            let duplicate =
                format!("{{\"schema\":\"{CASE_SCHEMA}\",{}", &original[1..]).into_bytes();
            let mut positional = serde_json::to_value(&case).unwrap();
            positional["composition"]["data"]["auth"]["frame"] = serde_json::json!([]);
            let mut relationship = case.clone();
            let Composition::NativeAuth(input) = &mut relationship.composition else {
                unreachable!()
            };
            input.native.connection_id = fixtures::fixed(99);
            for (input, reason) in [
                (duplicate, Rejection::Json),
                (serde_json::to_vec(&positional).unwrap(), Rejection::Json),
                (
                    serde_json::to_vec(&relationship).unwrap(),
                    Rejection::Relationship,
                ),
            ] {
                let envelope = run_bytes(&input).await.unwrap();
                assert_eq!(envelope.rejection.get(), Some(&reason));
                assert!(envelope.execution.get().is_none());
                assert!(envelope.facts.is_empty());
                assert!(envelope.identity_map.is_empty());
                validate_envelope(&envelope, &input, None).unwrap();
            }
        }
        #[tokio::test]
        async fn unsupported_notification_is_rejected_before_any_owner_is_created() {
            let mut case = native_case(false);
            let Composition::NativeAuth(input) = &mut case.composition else {
                unreachable!()
            };
            input.auth.notification_expected = true;
            let envelope = ordinary(&case).await;
            assert_eq!(envelope.rejection.get(), Some(&Rejection::Unsupported));
            assert!(envelope.execution.get().is_none());
            assert!(envelope.facts.is_empty());
            assert!(envelope.identity_map.is_empty());
            let bytes = serde_json::to_vec(&case).unwrap();
            validate_envelope(&envelope, &bytes, None).unwrap();
            assert!(envelope.resource_stop.get().is_none());
        }
        #[tokio::test]
        async fn descriptive_case_id_does_not_select_dispatch_or_observed_behavior() {
            let first_case = native_case(false);
            let mut second_case = first_case.clone();
            second_case.case_id = fixtures::text("any-other-description");
            let first = ordinary(&first_case).await;
            let second = ordinary(&second_case).await;
            complete_observations(&first);
            complete_observations(&second);
            assert_ne!(first.input_sha256, second.input_sha256);
            assert_eq!(first.execution, second.execution);
            assert_eq!(first.facts, second.facts);
            assert_eq!(first.identity_map, second.identity_map);
        }
        #[tokio::test]
        async fn native_handled_error_and_actual_pending_drop_keep_distinct_executions() {
            for dropped in [false, true] {
                let envelope = ordinary(&native_case(dropped)).await;
                complete_observations(&envelope);
                assert_eq!(
                    envelope.execution.get(),
                    Some(&if dropped {
                        Execution::Cancelled
                    } else {
                        Execution::Complete
                    })
                );
                if dropped {
                    assert!(
                        envelope
                            .facts
                            .as_slice()
                            .iter()
                            .any(|record| matches!(&record.fact, Fact::Driver(p)
                        if p.owner == DriverOwner::Publication && p.result == PollResult::Pending))
                    );
                    assert!(envelope.facts.as_slice().iter().any(|record| matches!(&record.fact,
                        Fact::Control(ControlFact::LivePublication(p)) if p.cut == Cut::AfterRunnerDrop
                        && matches!(p.snapshot.publication, PublicationKnowledge::CommitCallEntered(_))
                        && p.snapshot.terminal.get() == Some(&PublicationTerminal::Cancelled))));
                } else {
                    assert!(envelope.facts.as_slice().iter().any(|record| matches!(&record.fact,
                        Fact::Control(ControlFact::LivePublication(p))
                        if matches!(p.snapshot.returned.get(), Some(PublicationReturned::BackendFailure(_))))));
                }
            }
        }
        #[tokio::test]
        async fn reduced_bosh_backend_error_retains_selected_exposure_and_no_cache() {
            let case = Case {
                schema: fixtures::text(CASE_SCHEMA),
                case_id: fixtures::text("ordinary-reduced-auth"),
                adapter_contract: fixtures::text(ADAPTER_CONTRACT),
                composition: Composition::BoshAuth(BoshAuthInput {
                    mix: Nullable::Null(()),
                    auth: BoshAuthLane {
                        bound: fixtures::bound(
                            TransportKind::Bosh,
                            PublicationReply::BackendError(Empty {}),
                        ),
                        session: fixtures::session(2, 3, 22),
                        drive: AuthDrive::Complete,
                    },
                }),
            };
            let envelope = ordinary(&case).await;
            complete_observations(&envelope);
            assert_eq!(envelope.execution.get(), Some(&Execution::Complete));
            assert!(envelope.facts.as_slice().iter().any(|record| matches!(&record.fact,
                Fact::Bosh(BoshFact::Selection(s)) if s.cut == Cut::BeforePublish && s.selection.selected_count == 1)));
            assert!(envelope.facts.as_slice().iter().any(|record| matches!(&record.fact,
                Fact::Bosh(BoshFact::Snapshot(s)) if s.snapshot.responses.as_slice().iter().any(|r| r.exposure_entered && r.accepted_responders == 1))));
            assert!(envelope
                .facts
                .as_slice()
                .iter()
                .all(|record| match &record.fact {
                    Fact::Bosh(BoshFact::Cache(cache)) => cache.entries.is_empty(),
                    _ => true,
                }));
        }
        #[tokio::test]
        async fn sticky_loss_preserves_native_behavior_without_duplicate_owner_charges() {
            let case = decode(&serde_json::to_vec(&native_case(false)).unwrap()).unwrap();
            let sites = Sites::new(&case).unwrap();
            let recorder = Arc::new(Mutex::new(Recorder::new(&case)));
            driver::lost(&recorder);
            let result = dispatch(&case, &recorder, &sites).await;
            assert!(matches!(result, Ok(Execution::Complete)));
            // Credential frame, native write and standalone publication, once
            // each. The nested bool callback/service calls are not extra sites.
            assert_eq!(recorder.lock().unwrap().admitted_owner_polls(), 3);
            assert!(driver::resource_stop(&recorder).is_none());
            let envelope = finish_capture(recorder, result).unwrap();
            assert_eq!(envelope.execution.get(), Some(&Execution::Complete));
            assert!(envelope.resource_stop.get().is_none());
            assert!(matches!(
                envelope.observation_status,
                ObservationStatus::Lost(_)
            ));
        }
        #[tokio::test]
        async fn global_cut_before_planned_publication_drop_is_resource_metadata() {
            for sticky_loss in [false, true] {
                let bytes = serde_json::to_vec(&native_case(true)).unwrap();
                let case = decode(&bytes).unwrap();
                let sites = Sites::new(&case).unwrap();
                let recorder = Arc::new(Mutex::new(Recorder::new(&case)));
                if sticky_loss {
                    driver::lost(&recorder);
                }
                // Ordinary-only priming uses actual ready futures and the exact
                // shared admission helper. No counter is reset or fixture field
                // added, and the saved entry never has this path.
                let site = PollSite::new(DriverOwner::Worker, 0).unwrap();
                for _ in 0..62 {
                    let mut ready = Box::pin(std::future::ready(()));
                    let actual = std::future::poll_fn(|cx| {
                        Poll::Ready(driver::poll_once(&recorder, site, ready.as_mut(), cx))
                    })
                    .await;
                    assert!(matches!(actual, Ok(Poll::Ready(()))));
                }
                let result = dispatch(&case, &recorder, &sites).await;
                assert!(
                    matches!(&result, Err(DispatchExit::Resource(BudgetStop { resource_stop: ResourceStop::DriverPoll(stop) }))
                    if stop.owner == DriverOwner::Publication && stop.owner_ordinal == 0 && stop.admitted_calls == 64)
                );
                assert_eq!(recorder.lock().unwrap().admitted_owner_polls(), 64);
                // dispatch has dropped the native OwnedPublication/publisher/read/
                // route/queue scopes. A planned Drop input cannot label this cutoff
                // Cancelled or Failed, and a safety mutant cannot qualify through it.
                let envelope = finish_capture(recorder, result).unwrap();
                assert!(envelope.execution.get().is_none() && envelope.rejection.get().is_none());
                assert!(matches!(
                    envelope.resource_stop.get(),
                    Some(ResourceStop::DriverPoll(_))
                ));
                validate_envelope(&envelope, &bytes, Some(&case)).unwrap();
                assert!(!envelope
                    .facts
                    .as_slice()
                    .iter()
                    .any(|record| matches!(&record.fact, Fact::Control(ControlFact::Callback(_)))));
                if sticky_loss {
                    assert!(matches!(
                        envelope.observation_status,
                        ObservationStatus::Lost(_)
                    ));
                }
            }
        }
    }
}

// Exact fixed process/file boundary follows only Stage3's reviewed ignored
// fd0-entry pattern. No Stage3 backend, schema, verdict or receipt is reused.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires the separately reviewed fixed Stage4 saved-composition profile; reads one JSON input from fd0"]
async fn replay_saved_case() -> anyhow::Result<()> {
    use std::io::Write;
    let input = read_input(std::io::stdin().lock())?;
    let envelope = saved_dispatcher::run_bytes(&input).await?;
    // Serialize completely inside the unchanged cap before writing any byte.
    // Overflow is an explicit process failure, never truncated evidence or a
    // replacement success frame. Input/process occurrence IDs stay out-of-band.
    let frame = encode_compact_frame(&envelope)
        .map_err(|loss| anyhow::anyhow!("Stage4 frame encoding loss: {loss:?}"))?;
    let mut output = std::io::stdout().lock();
    output.write_all(&frame)?;
    output.flush()?;
    Ok(())
}

// Ordinary in-process composition measurement only. This one test evaluates
// the actual dispatcher on frozen bytes; it is not a parser-only control or a
// saved-entry/profile process. No execution or measurement has yet occurred.
#[tokio::test(flavor = "current_thread")]
async fn measure_frozen_compositions_in_process() -> anyhow::Result<()> {
    use std::{
        io::Write,
        time::{Duration, Instant},
    };
    const RECORD_TAG: &str = "NORTHSTAR_STAGE4_ORDINARY_MEASUREMENT_V1";
    const CASES: usize = 16;
    const RECORD_CAP: usize = 512;
    // Sixteen existing <=128KiB frames, two <=512B records per case,
    // one <=512B BEGIN and one <=512B terminal END or STOP record.
    // Exactly 2,114,560 maximum bytes from this test, including delimiters.
    const OUTPUT_CAP: usize = CASES * (MAX_FRAME + 2 * RECORD_CAP) + 2 * RECORD_CAP;
    const CASE_LIMIT: Duration = Duration::from_secs(5);
    const INPUTS: [(&str, &[u8]); CASES] = [
        ("S01", include_bytes!("stage4_replay/fixtures/S01.json")),
        ("S02", include_bytes!("stage4_replay/fixtures/S02.json")),
        ("S03", include_bytes!("stage4_replay/fixtures/S03.json")),
        ("S04", include_bytes!("stage4_replay/fixtures/S04.json")),
        ("S05", include_bytes!("stage4_replay/fixtures/S05.json")),
        ("S06", include_bytes!("stage4_replay/fixtures/S06.json")),
        ("S07", include_bytes!("stage4_replay/fixtures/S07.json")),
        ("S08", include_bytes!("stage4_replay/fixtures/S08.json")),
        ("S09", include_bytes!("stage4_replay/fixtures/S09.json")),
        ("S10", include_bytes!("stage4_replay/fixtures/S10.json")),
        ("S11", include_bytes!("stage4_replay/fixtures/S11.json")),
        ("S12", include_bytes!("stage4_replay/fixtures/S12.json")),
        ("S13", include_bytes!("stage4_replay/fixtures/S13.json")),
        ("S14", include_bytes!("stage4_replay/fixtures/S14.json")),
        ("S15", include_bytes!("stage4_replay/fixtures/S15.json")),
        ("S16", include_bytes!("stage4_replay/fixtures/S16.json")),
    ];
    fn emit(
        emitted: &mut usize,
        header: &str,
        frame: Option<&[u8]>,
        trailer: &str,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            header.len() <= RECORD_CAP && trailer.len() <= RECORD_CAP,
            "ordinary measurement record cap"
        );
        let frame = frame.unwrap_or_default();
        anyhow::ensure!(frame.len() <= MAX_FRAME, "ordinary measurement frame cap");
        let next = emitted
            .checked_add(header.len())
            .and_then(|n| n.checked_add(frame.len()))
            .and_then(|n| n.checked_add(trailer.len()))
            .ok_or_else(|| anyhow::anyhow!("ordinary measurement output overflow"))?;
        anyhow::ensure!(next <= OUTPUT_CAP, "ordinary measurement total output cap");
        // No lock spans evaluation/await. Keep each complete case block intact
        // against other Rust stdout users; unrelated log records may occur only
        // between blocks. An IO failure is terminal; never retry a whole block.
        let mut output = std::io::stdout().lock();
        output.write_all(header.as_bytes())?;
        output.write_all(frame)?;
        output.write_all(trailer.as_bytes())?;
        output.flush()?;
        *emitted = next;
        Ok(())
    }
    let mut emitted = 0usize;
    let mut attempts = 0usize;
    let mut envelopes = 0usize;
    let mut frames = 0usize;
    let mut decoded = 0usize;
    let mut rejected = 0usize;
    let mut facts_total = 0usize;
    let mut retained_polls_total = 0usize;
    let mut frame_bytes_total = 0usize;
    let begin = format!("\x1e{RECORD_TAG} BEGIN cases=16 frame_cap={MAX_FRAME} record_cap={RECORD_CAP} output_cap={OUTPUT_CAP} elapsed_scope=dispatcher_encode_decode_compare\n");
    emit(&mut emitted, &begin, None, "")?;
    for (position, (label, input)) in INPUTS.into_iter().enumerate() {
        attempts += 1;
        let index = position + 1;
        let input_hash = sha256(input);
        let started = Instant::now();
        // Sole actual evaluation call. No ignored fd0 entry, fixture decoder
        // substitute, environment selector, external process, retry or new
        // owner/clock framework. Existing driver/native budgets stay in force.
        let actual = saved_dispatcher::run_bytes(input).await;
        let envelope = match actual {
            Ok(envelope) => envelope,
            Err(_actual_error) => {
                let elapsed = started.elapsed();
                let header = format!("\x1e{RECORD_TAG} CASE index={index} label={label} input_sha256={} input_bytes={} elapsed_ns={} facts=unavailable retained_polls=unavailable encoded_bytes=0 frame_bytes=0 frame_status=unavailable wire_roundtrip=not_run wire_error=none run_error=true\n", input_hash.0, input.len(), elapsed.as_nanos());
                let trailer = format!("\x1e{RECORD_TAG} END_CASE index={index}\n");
                emit(&mut emitted, &header, None, &trailer)?;
                let stop = format!("\x1e{RECORD_TAG} STOP index={index} cause=run_error attempts={attempts} envelopes={envelopes} frames={frames} emitted_before_terminal={emitted}\n");
                emit(&mut emitted, &stop, None, "")?;
                anyhow::bail!(
                    "ordinary composition measurement stopped; actual run_error record emitted"
                );
            }
        };
        envelopes += 1;
        if envelope.rejection.get().is_some() {
            rejected += 1;
        } else {
            decoded += 1;
        }
        let facts = envelope.facts.len();
        let retained_polls = envelope
            .facts
            .as_slice()
            .iter()
            .filter(|record| matches!(record.fact, Fact::Driver(_)))
            .count();
        let mut writes = [0usize; 5];
        let mut flushes = [0usize; 5];
        let mut io_label_out_of_bound = false;
        for record in envelope.facts.as_slice() {
            match &record.fact {
                Fact::Native(NativeFact::Write(call)) => {
                    match writes.get_mut(usize::from(call.item_ordinal)) {
                        Some(count) => *count += 1,
                        None => io_label_out_of_bound = true,
                    }
                }
                Fact::Native(NativeFact::Flush(call)) => {
                    match flushes.get_mut(usize::from(call.item_ordinal)) {
                        Some(count) => *count += 1,
                        None => io_label_out_of_bound = true,
                    }
                }
                _ => {}
            }
        }
        let max_item_writes = writes.into_iter().max().unwrap_or(0);
        let max_item_flushes = flushes.into_iter().max().unwrap_or(0);
        facts_total += facts;
        retained_polls_total += retained_polls;
        // Encode once with the existing complete-frame cap even when the
        // envelope already reports loss/resource stop. Keep that actual frame
        // if available. Never encode a truncated/replacement success envelope.
        let encoded = encode_compact_frame(&envelope);
        // One captured Envelope, one encoded frame, one bounded decode and
        // exact paired canonical comparison. No second dispatcher/owner run.
        let (wire_roundtrip, wire_error) = match &encoded {
            Ok(frame) => match compact::verify_frame_roundtrip(&envelope, frame) {
                Ok(()) => ("verified", "none".to_owned()),
                Err(compact::RoundtripFailure::Decode(reason)) => {
                    ("failed", format!("decode_{reason:?}"))
                }
                Err(compact::RoundtripFailure::Compare(reason)) => {
                    ("failed", format!("compare_{reason:?}"))
                }
            },
            Err(_) => ("not_run", "none".to_owned()),
        };
        let elapsed = started.elapsed();
        let (candidate_frame, frame_status) = match &encoded {
            Ok(frame) => (Some(frame.as_slice()), "encoded".to_owned()),
            Err(loss) => (None, format!("{loss:?}")),
        };
        let encoded_bytes = candidate_frame.map_or(0, |bytes| bytes.len());
        // Withhold a frame that fails its same-capture gate. Its actual
        // successful encoding length/status remains visible in the receipt.
        let frame = if wire_roundtrip == "verified" {
            candidate_frame
        } else {
            None
        };
        let frame_bytes = frame.map_or(0, |bytes| bytes.len());
        if frame.is_some() {
            frames += 1;
            frame_bytes_total += frame_bytes;
        }
        let loss = match &envelope.observation_status {
            ObservationStatus::Complete(_) => "none".to_owned(),
            ObservationStatus::Lost(observed) => format!("{:?}", observed.reason),
        };
        let resource = match envelope.resource_stop.get() {
            None => "none".to_owned(),
            Some(ResourceStop::DriverPoll(stop)) => format!(
                "DriverPoll:{:?}:{}:{}",
                stop.owner, stop.owner_ordinal, stop.admitted_calls
            ),
            Some(ResourceStop::NativeWrite(stop)) => {
                format!("NativeWrite:{}:{}", stop.item_ordinal, stop.admitted_calls)
            }
            Some(ResourceStop::NativeFlush(stop)) => {
                format!("NativeFlush:{}:{}", stop.item_ordinal, stop.admitted_calls)
            }
        };
        let rejection = envelope
            .rejection
            .get()
            .map_or("none".to_owned(), |value| format!("{value:?}"));
        let execution = envelope
            .execution
            .get()
            .map_or("none".to_owned(), |value| format!("{value:?}"));
        let header = format!("\x1e{RECORD_TAG} CASE index={index} label={label} input_sha256={} input_bytes={} elapsed_ns={} facts={facts} retained_polls={retained_polls} max_item_writes={max_item_writes} max_item_flushes={max_item_flushes} encoded_bytes={encoded_bytes} frame_bytes={frame_bytes} frame_status={frame_status} wire_roundtrip={wire_roundtrip} wire_error={wire_error} rejection={rejection} execution={execution} loss={loss} resource={resource}\n", input_hash.0, input.len(), elapsed.as_nanos());
        let trailer = format!("\x1e{RECORD_TAG} END_CASE index={index}\n");
        emit(&mut emitted, &header, frame, &trailer)?;
        // Resource/loss checks are measurement qualification gates, not a Rust
        // domain safety oracle or expected fixture outcome. Complete/Cancelled
        // and real input-rejection envelopes remain factual data for the later
        // independent reader. Its invariant verdict cannot be inferred here.
        let stop_cause = if wire_roundtrip == "failed" {
            Some("wire_roundtrip")
        } else if envelope.resource_stop.get().is_some() {
            Some("resource_stop")
        } else if matches!(envelope.observation_status, ObservationStatus::Lost(_)) {
            Some("observation_loss")
        } else if envelope.execution.get() == Some(&Execution::Failed) {
            Some("execution_failed")
        } else if elapsed > CASE_LIMIT {
            Some("case_time")
        } else if input.len() > MAX_INPUT
            || facts > MAX_FACTS
            || retained_polls > MAX_POLLS
            || io_label_out_of_bound
            || max_item_writes > 32
            || max_item_flushes > 1
        {
            Some("retained_count_bound")
        } else if encoded.is_err() {
            Some("frame_encoding")
        } else {
            None
        };
        if let Some(cause) = stop_cause {
            let stop = format!("\x1e{RECORD_TAG} STOP index={index} cause={cause} attempts={attempts} envelopes={envelopes} frames={frames} decoded={decoded} rejected={rejected} facts={facts_total} retained_polls={retained_polls_total} frame_bytes={frame_bytes_total} emitted_before_terminal={emitted}\n");
            emit(&mut emitted, &stop, None, "")?;
            anyhow::bail!(
                "ordinary composition measurement stopped; actual frame or compact counts emitted"
            );
        }
    }
    let end = format!("\x1e{RECORD_TAG} END attempts={attempts} envelopes={envelopes} frames={frames} decoded={decoded} rejected={rejected} facts={facts_total} retained_polls={retained_polls_total} frame_bytes={frame_bytes_total} emitted_before_terminal={emitted}\n");
    emit(&mut emitted, &end, None, "")?;
    Ok(())
}

// Separate opt-in diagnostic, not one of the original 353 ordinary tests and
// not the saved fd0 entry/profile. No expected envelope or altered owner path.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires separate release of the fixed S06 serialization diagnostic"]
async fn diagnose_frozen_s06_serialization() -> anyhow::Result<()> {
    use std::{
        io::Write,
        time::{Duration, Instant},
    };
    const TAG: &str = "NORTHSTAR_STAGE4_S06_SERIALIZATION_DIAGNOSTIC_V1";
    const VALUE_CAP: usize = 4 * 1024 * 1024;
    const WORK_BYTES_CAP: usize = 8 * 1024 * 1024;
    const WRITE_CALLS_CAP: usize = 262144;
    const REPORT_CAP: usize = 16 * 1024;
    const LINE_CAP: usize = 512;
    const ELAPSED_CAP: Duration = Duration::from_secs(5);
    const INPUT: &[u8] = include_bytes!("stage4_replay/fixtures/S06.json");
    const LEAVES: [&str; 41] = [
        "Frame",
        "Muc.Snapshot",
        "Muc.Recipients",
        "Muc.Endpoint",
        "Foreground.Snapshot",
        "Foreground.ProjectionRow",
        "Foreground.InitialRow",
        "Claim.Snapshot",
        "Claim.Attempt",
        "Worker.Snapshot",
        "Worker.Archive",
        "Worker.Lookup",
        "Worker.Candidate",
        "Worker.LocalQueue",
        "Worker.Handoff",
        "Worker.ChildDrop",
        "Worker.Settlement",
        "Worker.Account",
        "Worker.Privacy",
        "Credential",
        "Control.Holder",
        "Control.LivePublication",
        "Control.Callback",
        "Native.Snapshot",
        "Native.Dequeue",
        "Native.Write",
        "Native.Flush",
        "Native.Ack",
        "Native.OwnershipReceipt",
        "Native.WriteReceipt",
        "Bosh.Snapshot",
        "Bosh.Selection",
        "Bosh.Transfer",
        "Bosh.Bind",
        "Bosh.Renew",
        "Bosh.Ack",
        "Bosh.Receiver",
        "Bosh.Cache",
        "Bosh.Queue",
        "Bosh.TransportReceipt",
        "Driver",
    ];
    fn leaf(fact: &Fact) -> usize {
        match fact {
            Fact::Frame(_) => 0,
            Fact::Muc(value) => match value {
                MucFact::Snapshot(_) => 1,
                MucFact::Recipients(_) => 2,
                MucFact::Endpoint(_) => 3,
            },
            Fact::Foreground(value) => match value {
                ForegroundFact::Snapshot(_) => 4,
                ForegroundFact::ProjectionRow(_) => 5,
                ForegroundFact::InitialRow(_) => 6,
            },
            Fact::Claim(value) => match value {
                ClaimFact::Snapshot(_) => 7,
                ClaimFact::Attempt(_) => 8,
            },
            Fact::Worker(value) => match value {
                WorkerFact::Snapshot(_) => 9,
                WorkerFact::Archive(_) => 10,
                WorkerFact::Lookup(_) => 11,
                WorkerFact::Candidate(_) => 12,
                WorkerFact::LocalQueue(_) => 13,
                WorkerFact::Handoff(_) => 14,
                WorkerFact::ChildDrop(_) => 15,
                WorkerFact::Settlement(_) => 16,
                WorkerFact::Account(_) => 17,
                WorkerFact::Privacy(_) => 18,
            },
            Fact::Credential(_) => 19,
            Fact::Control(value) => match value {
                ControlFact::Holder(_) => 20,
                ControlFact::LivePublication(_) => 21,
                ControlFact::Callback(_) => 22,
            },
            Fact::Native(value) => match value {
                NativeFact::Snapshot(_) => 23,
                NativeFact::Dequeue(_) => 24,
                NativeFact::Write(_) => 25,
                NativeFact::Flush(_) => 26,
                NativeFact::Ack(_) => 27,
                NativeFact::OwnershipReceipt(_) => 28,
                NativeFact::WriteReceipt(_) => 29,
            },
            Fact::Bosh(value) => match value {
                BoshFact::Snapshot(_) => 30,
                BoshFact::Selection(_) => 31,
                BoshFact::Transfer(_) => 32,
                BoshFact::Bind(_) => 33,
                BoshFact::Renew(_) => 34,
                BoshFact::Ack(_) => 35,
                BoshFact::Receiver(_) => 36,
                BoshFact::Cache(_) => 37,
                BoshFact::Queue(_) => 38,
                BoshFact::TransportReceipt(_) => 39,
            },
            Fact::Driver(_) => 40,
        }
    }
    struct Budget {
        started: Instant,
        bytes: usize,
        calls: usize,
        accepted_calls: usize,
        stop: &'static str,
    }
    struct CountingWriter<'a> {
        budget: &'a mut Budget,
        bytes: usize,
        status: &'static str,
    }
    impl Write for CountingWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            // Include the terminal rejected callback in attempted calls. The
            // final available call slot is reserved for a truthful stop.
            self.budget.calls += 1;
            if self.budget.started.elapsed() > ELAPSED_CAP {
                self.status = "elapsed_limit";
            } else if self.budget.calls >= WRITE_CALLS_CAP {
                self.status = "write_calls_limit";
            } else {
                let value_next = self.bytes.checked_add(bytes.len());
                let work_next = self.budget.bytes.checked_add(bytes.len());
                if !value_next.is_some_and(|n| n <= VALUE_CAP) {
                    self.status = "value_bytes_limit";
                } else if !work_next.is_some_and(|n| n <= WORK_BYTES_CAP) {
                    self.status = "work_bytes_limit";
                } else {
                    self.bytes = value_next.expect("checked value byte count");
                    self.budget.bytes = work_next.expect("checked work byte count");
                    self.budget.accepted_calls += 1;
                    return Ok(bytes.len());
                }
            }
            self.budget.stop = self.status;
            Err(std::io::Error::other(self.status))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    struct Count {
        accepted_bytes: usize,
        status: &'static str,
    }
    impl Count {
        fn exact(&self) -> Option<usize> {
            (self.status == "complete").then_some(self.accepted_bytes)
        }
    }
    fn count_json<T: Serialize + ?Sized>(value: &T, budget: &mut Budget) -> Count {
        if budget.stop != "complete" {
            return Count {
                accepted_bytes: 0,
                status: budget.stop,
            };
        }
        let mut writer = CountingWriter {
            budget,
            bytes: 0,
            status: "complete",
        };
        if serde_json::to_writer(&mut writer, value).is_err() && writer.status == "complete" {
            writer.status = "encoding_failure";
            writer.budget.stop = writer.status;
        }
        Count {
            accepted_bytes: writer.bytes,
            status: writer.status,
        }
    }
    #[derive(Clone, Copy, Default)]
    struct Bucket {
        records: usize,
        measured_records: usize,
        measured_bytes: usize,
        max_measured_record_bytes: usize,
    }
    fn line(report: &mut Vec<u8>, content: String) -> anyhow::Result<()> {
        let next = report.len().checked_add(content.len());
        anyhow::ensure!(
            content.len() <= LINE_CAP && next.is_some_and(|n| n <= REPORT_CAP),
            "S06 diagnostic report cap"
        );
        report.extend_from_slice(content.as_bytes());
        Ok(())
    }
    let input_hash = sha256(INPUT);
    anyhow::ensure!(
        INPUT.len() == 22911
            && input_hash.0 == "c609da10e108c0d5023f4b102d31b73e4d39de534703b915ad40e53cefb2d150",
        "S06 diagnostic frozen input mismatch"
    );
    let mut report = Vec::new();
    let mut budget = Budget {
        started: Instant::now(),
        bytes: 0,
        calls: 0,
        accepted_calls: 0,
        stop: "complete",
    };
    // Exactly one real dispatch. No other case, expected DTO, retry or fd0 path.
    let envelope = match saved_dispatcher::run_bytes(INPUT).await {
        Ok(envelope) => envelope,
        Err(_) => {
            line(
                &mut report,
                format!(
                    "\x1e{TAG} STOP label=S06 run_error=true input_sha256={} elapsed_ns={}\n",
                    input_hash.0,
                    budget.started.elapsed().as_nanos()
                ),
            )?;
            let mut output = std::io::stdout().lock();
            output.write_all(&report)?;
            output.flush()?;
            anyhow::bail!("S06 diagnostic actual dispatcher error; no envelope measured");
        }
    };
    // Existing bounded encoder is called unchanged once, and its bytes dropped.
    // The uncapped representation is never buffered, retained or emitted.
    let (encoding_status, encoded_bytes) = match encode_frame(&envelope) {
        Ok(frame) => ("encoded".to_owned(), Some(frame.len())),
        Err(loss) => (format!("{loss:?}"), None),
    };
    let payload = count_json(&envelope, &mut budget);
    let identities = count_json(&envelope.identity_map, &mut budget);
    let fact_list = count_json(&envelope.facts, &mut budget);
    let mut buckets = [Bucket::default(); LEAVES.len()];
    let mut records_status = "complete";
    let mut partial_record_bytes = None;
    anyhow::ensure!(
        envelope.facts.len() <= MAX_FACTS,
        "S06 diagnostic fact bound"
    );
    for record in envelope.facts.as_slice() {
        let bucket = &mut buckets[leaf(&record.fact)];
        bucket.records += 1;
        // After the first incomplete record, preserve counts but admit no more
        // serialization work. Complete-record subtotals are explicitly partial.
        if records_status == "complete" {
            let count = count_json(record, &mut budget);
            if let Some(bytes) = count.exact() {
                bucket.measured_records += 1;
                bucket.measured_bytes = bucket
                    .measured_bytes
                    .checked_add(bytes)
                    .ok_or_else(|| anyhow::anyhow!("S06 diagnostic bucket count overflow"))?;
                bucket.max_measured_record_bytes = bucket.max_measured_record_bytes.max(bytes);
            } else {
                records_status = count.status;
                partial_record_bytes = Some(count.accepted_bytes);
            }
        }
    }
    let records_count = buckets.iter().map(|b| b.records).sum::<usize>();
    let measured_count = buckets.iter().map(|b| b.measured_records).sum::<usize>();
    let measured_bytes = buckets
        .iter()
        .try_fold(0usize, |sum, b| sum.checked_add(b.measured_bytes));
    let separators = envelope.facts.len().saturating_sub(1);
    let record_sum_array_bytes = (records_status == "complete")
        .then_some(())
        .and(measured_bytes)
        .and_then(|n| n.checked_add(separators))
        .and_then(|n| n.checked_add(2));
    let facts_array_bytes = fact_list.exact();
    // Residual includes all named envelope fields and punctuation except the
    // complete facts array and identity-map value, counted separately above.
    let residual_bytes = payload
        .exact()
        .zip(facts_array_bytes)
        .zip(identities.exact())
        .and_then(|((p, f), i)| p.checked_sub(f)?.checked_sub(i));
    let reconciled = records_count == envelope.facts.len()
        && measured_count == records_count
        && record_sum_array_bytes.is_some()
        && record_sum_array_bytes == facts_array_bytes
        && residual_bytes
            .zip(facts_array_bytes)
            .zip(identities.exact())
            .and_then(|((r, f), i)| r.checked_add(f)?.checked_add(i))
            == payload.exact()
        && payload.exact().is_some();
    let whole_frame_bytes = payload.exact().and_then(|n| {
        let header_bytes = format!("\x1e{FRAME_TAG} {n}\n").len();
        n.checked_add(header_bytes)?
            .checked_add(b"\n\x1eEND\n".len())
    });
    let encoding_agrees = match encoding_status.as_str() {
        "encoded" => whole_frame_bytes.is_some() && whole_frame_bytes == encoded_bytes,
        "FrameOverflow" => whole_frame_bytes.is_some_and(|n| n > MAX_FRAME),
        _ => false,
    };
    line(&mut report, format!("\x1e{TAG} BEGIN label=S06 input_sha256={} input_bytes={} frame_cap={} report_cap={} line_cap={}\n", input_hash.0, INPUT.len(), MAX_FRAME, REPORT_CAP, LINE_CAP))?;
    line(&mut report, format!("\x1e{TAG} BUDGET value_bytes_cap={VALUE_CAP} work_bytes_cap={WORK_BYTES_CAP} write_calls_cap={WRITE_CALLS_CAP} elapsed_cap_ns={} elapsed_scope=dispatcher_encode_and_diagnostic\n", ELAPSED_CAP.as_nanos()))?;
    line(
        &mut report,
        format!(
            "\x1e{TAG} STATE rejection={:?} execution={:?} observation={:?} resource={:?}\n",
            envelope.rejection.get(),
            envelope.execution.get(),
            envelope.observation_status,
            envelope.resource_stop.get()
        ),
    )?;
    line(&mut report, format!("\x1e{TAG} ENCODING status={encoding_status} emitted_frame_bytes=0 bounded_encoded_bytes={encoded_bytes:?} exact_payload_bytes={:?} payload_accepted_bytes={} payload_status={} exact_whole_frame_bytes={whole_frame_bytes:?} encoding_agrees={encoding_agrees}\n", payload.exact(), payload.accepted_bytes, payload.status))?;
    line(&mut report, format!("\x1e{TAG} PARTS facts={} measured_facts={measured_count} records_status={records_status} partial_record_accepted_bytes={partial_record_bytes:?} complete_record_subtotal={measured_bytes:?} exact_facts_array_bytes={facts_array_bytes:?} separators={separators} exact_identity_map_bytes={:?} identity_status={} exact_residual_bytes={residual_bytes:?} reconciled={reconciled}\n", records_count, identities.exact(), identities.status))?;
    line(&mut report, format!("\x1e{TAG} FACT_LIST status={} accepted_bytes={} record_sum_array_bytes={record_sum_array_bytes:?} retained_polls={}\n", fact_list.status, fact_list.accepted_bytes, buckets[40].records))?;
    for (name, bucket) in LEAVES.iter().zip(buckets) {
        let exact = bucket.records == bucket.measured_records;
        line(&mut report, format!("\x1e{TAG} BUCKET leaf={name} records={} measured_records={} complete_record_subtotal={} max_complete_record_bytes={} exact={exact}\n", bucket.records, bucket.measured_records, bucket.measured_bytes, bucket.max_measured_record_bytes))?;
    }
    let elapsed = budget.started.elapsed();
    // Diagnostic completion is counting/reconciliation qualification only;
    // STATE and ENCODING remain authoritative, including any loss or overflow.
    let diagnostic_complete = reconciled && encoding_agrees && elapsed <= ELAPSED_CAP;
    let report_bytes_before_end = report.len();
    line(&mut report, format!("\x1e{TAG} END diagnostic_complete={diagnostic_complete} elapsed_ns={} counted_accepted_bytes={} attempted_write_calls={} accepted_write_calls={} report_bytes_before_end={report_bytes_before_end}\n", elapsed.as_nanos(), budget.bytes, budget.calls, budget.accepted_calls))?;
    let mut output = std::io::stdout().lock();
    output.write_all(&report)?;
    output.flush()?;
    anyhow::ensure!(
        diagnostic_complete,
        "S06 diagnostic incomplete; bounded factual summary emitted"
    );
    Ok(())
}
