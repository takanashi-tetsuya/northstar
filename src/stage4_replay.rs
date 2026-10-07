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
mod tests {
    use super::*;

    // Ordinary parser/identity controls only. These are not saved S13 bytes,
    // owner-composition positives, an expected envelope, or evidence of a run.
    const AUTH_REQUEST: &str = "<body xmlns='http://jabber.org/protocol/httpbind' rid='22' sid='00000000-0000-0000-0000-000000000003'/>";
    fn reduced_bytes() -> Vec<u8> {
        r#"{"schema":"northstar-stage4-composition-case-v1","case_id":"bosh-bound-error","adapter_contract":"local-stage4-composition-controlled-v1","composition":{"kind":"BoshAuth","data":{"mix":null,"auth":{"bound":{"frame":{"frame_id":"00000000-0000-0000-0000-000000000001","connection_id":"00000000-0000-0000-0000-000000000002","transport":"Bosh","input":"<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>r</resource></bind></iq>"},"user_id":"00000000-0000-0000-0000-000000000004","auth_generation":1,"device_id":null,"ordinal":0,"credential_kind":"Binding","binding":{"resource":"r","lease_seconds":60,"full_jid":"u@example.test/r"},"preparation":{"generation_allowed":true,"binding_reserved":true,"stage_present":false,"stage_epoch":null,"commit":"Complete"},"control":{"kind":"Binding","data":{"iq_id":"b1","full_jid":"u@example.test/r","xml":"<iq xmlns='jabber:client' id='b1' type='result'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>u@example.test/r</jid></bind></iq>"}},"publication":{"kind":"BackendError","data":{}},"notification_expected":false},"session":{"connection_id":"00000000-0000-0000-0000-000000000002","session_id":"00000000-0000-0000-0000-000000000003","ttl_seconds":60,"max_response_bytes":16384,"max_output_bytes":65536,"governor":{"max_bytes":65536,"max_recovery_bytes":65536,"max_recovery_jobs":2,"max_snapshot_bytes":65536},"response":{"rid":22,"fingerprint":"FP","request_xml":"<body xmlns='http://jabber.org/protocol/httpbind' rid='22' sid='00000000-0000-0000-0000-000000000003'/>","content_type":"text/xml; charset=utf-8","responders":["Open"]},"bind":{"commit":"Complete","membership":{"c2s_message_ids":[],"mix_delivery_ids":[]}}},"drive":"Complete"}}}}"#.replace("\"FP\"", &format!("\"{}\"", sha256(AUTH_REQUEST.as_bytes()).0)).into_bytes()
    }
    const MIX_REQUEST: &str = "<body xmlns='http://jabber.org/protocol/httpbind' rid='11' sid='00000000-0000-0000-0000-000000000008'/>";
    fn independent_mix() -> IndependentMixLane {
        let raw = r#"{"worker":{"origin":{"kind":"InitialDurableRow","data":{"source":{"delivery_id":"00000000-0000-0000-0000-00000000000c","lease_token":"00000000-0000-0000-0000-00000000000d"},"event_id":"00000000-0000-0000-0000-000000000009","channel_id":"00000000-0000-0000-0000-00000000000a","channel_jid":"c@mix.example.test","participant_id":"00000000-0000-0000-0000-00000000000b","recipient_jid":"u@example.test","recipient_nick":null,"stanza":"<message/>","authoritative_stanza_id":"00000000-0000-0000-0000-000000000009","archive":true,"encrypted":false,"attempt_count":0,"route_wake_generation":1}},"attempt":{"claim":{"limit":1,"max_bytes":4096,"lease_token":"00000000-0000-0000-0000-00000000000d","attempt_count":0,"route_wake_generation":1,"commit":"Complete"},"archive":{"reply":{"kind":"StoreCandidate","data":{}},"commit":"Complete"},"route":{"enabled_account_id":"00000000-0000-0000-0000-000000000004","privacy_blocked":false,"targets":[{"full_jid":"u@example.test/m","user_id":"00000000-0000-0000-0000-000000000004","connection_id":"00000000-0000-0000-0000-000000000007","auth_generation":1,"routable":true,"disconnected":false,"lifecycle":"Active","caps":{"connection_id":"00000000-0000-0000-0000-000000000007","generation":1,"verified_features":["MixCore"]},"provenance":{"kind":"InitiallyPublished","data":{}}}],"queue_capacity":1}}},"transport":{"session":{"connection_id":"00000000-0000-0000-0000-000000000007","session_id":"00000000-0000-0000-0000-000000000008","ttl_seconds":60,"max_response_bytes":16384,"max_output_bytes":65536,"governor":{"max_bytes":65536,"max_recovery_bytes":65536,"max_recovery_jobs":2,"max_snapshot_bytes":65536},"response":{"rid":11,"fingerprint":"FP","request_xml":"<body xmlns='http://jabber.org/protocol/httpbind' rid='11' sid='00000000-0000-0000-0000-000000000008'/>","content_type":"text/xml; charset=utf-8","responders":["Open"]},"bind":{"commit":"Complete","membership":{"c2s_message_ids":[],"mix_delivery_ids":["00000000-0000-0000-0000-00000000000c"]}}},"transfer":{"commit":"Complete","returned_source":{"delivery_id":"00000000-0000-0000-0000-00000000000c","lease_token":"00000000-0000-0000-0000-00000000000e"}},"ack":null}}"#.replace("\"FP\"", &format!("\"{}\"", sha256(MIX_REQUEST.as_bytes()).0));
        serde_json::from_str(&raw).unwrap()
    }
    pub(super) fn input_case() -> ValidatedCase {
        decode(&reduced_bytes()).unwrap()
    }
    fn id(n: u128) -> EvidenceId {
        EvidenceId::observed(Uuid::from_u128(n))
    }
    fn credential(attempt: u128, constructed: Option<u128>, returned: Option<u128>) -> Fact {
        let nullable = |n: Option<u128>| n.map_or(Nullable::Null(()), |n| Nullable::Value(id(n)));
        Fact::Credential(CredentialCapture {
            cut: Cut::Introduction,
            snapshot: CredentialSnapshot {
                attempt: id(attempt),
                frame: id(1),
                connection: id(2),
                ordinal: 0,
                kind: ObservedCredentialKind::Binding,
                service_started: false,
                repository_started: false,
                begin: CredentialCall::NotEntered,
                eligibility: Eligibility::NotEntered(Empty {}),
                transaction_returned: false,
                preparation: [PreparationResult::NotEntered; 5],
                stage_id: Nullable::Null(()),
                rollback: Nullable::Null(()),
                commit: CredentialCall::NotEntered,
                receipt_constructed: constructed.is_some(),
                returned: Nullable::Null(()),
                return_matches: false,
                transferred: false,
                handler: Nullable::Null(()),
                call_terminal: Nullable::Null(()),
                integrity_failure: false,
            },
            joins: Nullable::Value(CredentialJoins {
                owner: CredentialAttemptJoin {
                    attempt: id(attempt),
                    frame: id(1),
                    connection: id(2),
                    ordinal: 0,
                    kind: ObservedCredentialKind::Binding,
                },
                constructed_receipt: nullable(constructed),
                returned_receipt: nullable(returned),
                transferred_receipt: Nullable::Null(()),
            }),
        })
    }
    fn recorded(attempt: u128, receipt: u128) -> Envelope {
        let c = input_case();
        let mut recorder = Recorder::new(&c);
        recorder
            .capture(credential(attempt, Some(receipt), None))
            .unwrap();
        recorder
            .capture(credential(attempt, Some(receipt), Some(receipt)))
            .unwrap();
        recorder.finish(Execution::Complete).unwrap()
    }
    fn control_holder(transferred_receipt: Option<u128>) -> Fact {
        let association = |receipt| ControlAssociation {
            control: id(100),
            connection: id(2),
            frame: Nullable::Value(id(1)),
            receipt: id(receipt),
            length: 4,
            digest: sha256(b"test"),
            publication: PublicationJoins {
                control: id(100),
                frame: Nullable::Value(id(1)),
                receipt: id(receipt),
                credential: Nullable::Value(CredentialAttemptJoin {
                    attempt: id(300),
                    frame: id(1),
                    connection: id(2),
                    ordinal: 0,
                    kind: ObservedCredentialKind::Binding,
                }),
                begun_receipt: Nullable::Null(()),
                bound_effects: true,
                notification_expected: false,
            },
        };
        Fact::Control(ControlFact::Holder(ControlCapture {
            cut: Cut::Introduction,
            actual_xml: Nullable::Null(()),
            holder: Nullable::Value(ControlJoins {
                introduced: Nullable::Value(association(200)),
                transferred: transferred_receipt.map_or(Nullable::Null(()), |receipt| {
                    Nullable::Value(association(receipt))
                }),
            }),
        }))
    }
    fn is_opaque(id: &EvidenceId, expected: u8) -> bool {
        matches!(id, EvidenceId::Encoded(IdentityLabel::Opaque(o)) if o.ordinal == expected)
    }

    fn fixed(n: u128) -> Id {
        Id(Uuid::from_u128(n))
    }
    fn text<const N: usize>(value: &str) -> Text<N> {
        Text::new(value).unwrap()
    }
    fn list<T, const N: usize>(values: Vec<T>) -> List<T, N> {
        List::new(values).unwrap()
    }
    fn write_ok() -> WriteScript {
        WriteScript {
            chunk_limit: 4096,
            fail_after_accepted_bytes: Nullable::Null(()),
            flush: FlushReply::Ok,
        }
    }
    fn auth_input(transport: TransportKind, publication: PublicationReply) -> AuthInput {
        let c = input_case();
        let Composition::BoshAuth(b) = c.case.composition else {
            unreachable!()
        };
        let mut auth = b.auth.bound;
        auth.frame.transport = transport;
        auth.publication = publication;
        auth
    }
    fn parser_case(composition: Composition) -> Case {
        Case {
            schema: text(CASE_SCHEMA),
            case_id: text("ordinary-parser-input"),
            adapter_contract: text(ADAPTER_CONTRACT),
            composition,
        }
    }
    fn auth_bosh_case(mix: bool, cancel: bool) -> Case {
        let mut c = input_case().case;
        let Composition::BoshAuth(b) = &mut c.composition else {
            unreachable!()
        };
        if mix {
            b.mix = Nullable::Value(independent_mix());
        }
        if cancel {
            b.auth.bound.publication = PublicationReply::CommitPending(EpochReply {
                epoch: Nullable::Null(()),
            });
            b.auth.drive = AuthDrive::DropPublicationCommit;
        }
        c
    }
    fn native_auth_case(cancel: bool) -> Case {
        let publication = if cancel {
            PublicationReply::CommitPending(EpochReply {
                epoch: Nullable::Null(()),
            })
        } else {
            PublicationReply::BackendError(Empty {})
        };
        parser_case(Composition::NativeAuth(NativeAuthInput {
            auth: auth_input(TransportKind::Tcp, publication),
            native: PlainNative {
                connection_id: fixed(2),
                write: write_ok(),
            },
            drive: if cancel {
                AuthDrive::DropPublicationCommit
            } else {
                AuthDrive::Complete
            },
        }))
    }
    fn muc_case(cut: MucDrive, replay: bool) -> Case {
        let stanza =
            text("<message xmlns='jabber:client' type='groupchat'><body>hi</body></message>");
        let mut recipients = vec![RecipientInput {
            user_id: fixed(4),
            full_jid: text("a@example.test/one"),
            connection_id: fixed(2),
            blocked: false,
            endpoint: EndpointCut::Return,
        }];
        if cut == MucDrive::DropSecondEndpoint {
            recipients.push(RecipientInput {
                user_id: fixed(6),
                full_jid: text("b@example.test/two"),
                connection_id: fixed(7),
                blocked: false,
                endpoint: EndpointCut::Pending,
            });
        }
        if replay || cut == MucDrive::DropCommit {
            recipients.clear();
        }
        parser_case(Composition::Muc(MucInput {
            frame: Frame {
                frame_id: fixed(1),
                connection_id: fixed(2),
                transport: TransportKind::Tcp,
                input: stanza.clone(),
            },
            configured_domain: text("example.test"),
            command: MucCommand {
                id: fixed(63),
                room_id: fixed(60),
                actor_scope: text("a@example.test"),
                origin_id: if cut == MucDrive::DropSecondEndpoint {
                    Nullable::Null(())
                } else {
                    Nullable::Value(text("origin"))
                },
                sender_jid: text("a@example.test/one"),
                nick: text("a"),
                stanza,
                encrypted: false,
                archive: cut != MucDrive::DropSecondEndpoint,
                retention_days: 7,
                authority: Authority {
                    clustered: false,
                    expected_room_epoch: fixed(61),
                    principal: MucPrincipal::Local(LocalPrincipal {
                        user_id: fixed(4),
                        local_domain: text("example.test"),
                    }),
                    actor_scope: text("a@example.test"),
                    full_jid: text("a@example.test/one"),
                    nick: text("a"),
                    occupant_incarnation: fixed(62),
                    connection_uuid: fixed(2),
                    expected_role: text("participant"),
                    expected_affiliation: text("member"),
                    cluster_target: Nullable::Null(()),
                },
            },
            admission: RatedAdmission {
                fence: AdmissionFenceInput {
                    admission_key: Hex::of(&[0; 32]).unwrap(),
                    payload_mac: Hex::of(&[1; 32]).unwrap(),
                    lease_token: fixed(64),
                    dedupe_digest: Hex::of(&[2; 32]).unwrap(),
                },
                requirement: AdmissionRequirement {
                    action: text("message"),
                    step: 0,
                    work_factor: 1,
                    max_work_factor: 1,
                    hard_wait_seconds: 0,
                    retry_after_seconds: 0,
                    cooldown_seconds: 0,
                    approximate_max_device_seconds: 0,
                    notice: text("synthetic"),
                },
                begin_commit: CommitCut::Complete,
                finalize_commit: CommitCut::Complete,
            },
            repository: MucRepository {
                original_id: if replay {
                    Nullable::Value(fixed(65))
                } else {
                    Nullable::Null(())
                },
                commit: if cut == MucDrive::DropCommit {
                    CommitCut::Pending
                } else {
                    CommitCut::Complete
                },
            },
            recipients: list(recipients),
            native: if !replay && cut == MucDrive::Complete {
                Nullable::Value(PlainNative {
                    connection_id: fixed(2),
                    write: write_ok(),
                })
            } else {
                Nullable::Null(())
            },
            drive: cut,
        }))
    }
    fn fresh_mix_native_case() -> Case {
        let auth = auth_input(
            TransportKind::Tcp,
            PublicationReply::Committed(EpochReply {
                epoch: Nullable::Null(()),
            }),
        );
        let mut worker = independent_mix().worker;
        worker.origin = ClaimOrigin::FreshProjection(FreshProjectionOrigin {
            foreground_frame: fixed(66),
            recipient_ordinal: 0,
            declared_delivery_id: fixed(12),
        });
        let route = &mut worker.attempt.route.targets.0[0];
        route.full_jid = text("u@example.test/r");
        route.connection_id = fixed(2);
        route.caps.connection_id = fixed(2);
        route.routable = false;
        route.provenance = RouteProvenance::ActivatedByAuth(ActivatedRoute { frame_id: fixed(1) });
        parser_case(Composition::AuthThenMixNative(FreshMixNativeInput {
            auth,
            auth_native: PlainNative {
                connection_id: fixed(2),
                write: write_ok(),
            },
            foreground: FreshForeground {
                frame: Frame {
                    frame_id: fixed(66),
                    connection_id: fixed(7),
                    transport: TransportKind::Tcp,
                    input: text("<message><body>hi</body></message>"),
                },
                configured_domain: text("mix.example.test"),
                ingress: MixIngress {
                    channel_id: fixed(10),
                    channel_jid: text("c@mix.example.test"),
                    actor_bare: text("b@example.test"),
                    actor_full: text("b@example.test/two"),
                    children: text("<body>hi</body>"),
                    encrypted: false,
                    identity: Nullable::Null(()),
                },
                command: MixStoreCommand {
                    channel_id: fixed(10),
                    actor: text("b@example.test"),
                    item_id: fixed(9),
                    payload: text("<item/>"),
                    identity: Nullable::Null(()),
                    delivery_payload: text("<body>hi</body>"),
                    visible_jid: Nullable::Null(()),
                    encrypted: false,
                },
                stored: Stored {
                    authoritative_id: fixed(9),
                    storage_id: fixed(70),
                    channel_id: fixed(10),
                    channel_jid: text("c@mix.example.test"),
                    projection: Nullable::Value(DeliveryProjection {
                        event_id: fixed(9),
                        channel_id: fixed(10),
                        channel_jid: text("c@mix.example.test"),
                        stanza_template: text("<message/>"),
                        authoritative_stanza_id: Nullable::Value(fixed(9)),
                        archive: true,
                        encrypted: false,
                        recipients: list(vec![RecipientProjection {
                            participant: Participant {
                                participant_id: fixed(11),
                                jid: text("u@example.test"),
                                nick: Nullable::Null(()),
                            },
                            delivery_id: fixed(12),
                            sequence: 1,
                        }]),
                    }),
                },
                commit: CommitCut::Complete,
            },
            worker,
            delivery_native: DurableNative {
                connection_id: fixed(2),
                write: write_ok(),
                returned_fence: MixSource {
                    delivery_id: fixed(12),
                    lease_token: fixed(14),
                },
                ack_commit: CommitCut::Complete,
            },
        }))
    }
    fn replay_queued_auth_case() -> Case {
        let c = input_case();
        let Composition::BoshAuth(a) = c.case.composition else {
            unreachable!()
        };
        let bound = a.auth.bound;
        let session = a.auth.session;
        let mut unbound = bound.clone();
        unbound.frame.frame_id = fixed(30);
        unbound.frame.input = text("<authenticate xmlns='urn:xmpp:sasl:2'/>");
        unbound.credential_kind = CredentialKind::UnboundFast;
        unbound.binding = Nullable::Null(());
        unbound.preparation.binding_reserved = false;
        unbound.control = ControlInput::UnboundFast(UnboundControlInput { authorization_identifier: text("u@example.test"), xml: text("<success xmlns='urn:xmpp:sasl:2'><authorization-identifier>u@example.test</authorization-identifier></success>") });
        unbound.publication = PublicationReply::NoSql(Empty {});
        let count =
            RESPONSE_BYTES as usize - 256 - auth_xml(&unbound).len() - P_OPEN.len() - P_CLOSE.len();
        let padding = FixedAuthPadding {
            presence_xml: Text::new(format!("{P_OPEN}{}{P_CLOSE}", "x".repeat(count))).unwrap(),
            features_xml: text(FIXED_FEATURES),
        };
        let mut mix = independent_mix();
        mix.worker.attempt.archive.reply = ArchiveReply::Replay(ArchiveReplayInput {
            original_archive_id: fixed(50),
        });
        let request_xml = "<body xmlns='http://jabber.org/protocol/httpbind' rid='12' ack='11' sid='00000000-0000-0000-0000-000000000008'/>";
        mix.transport.ack = Nullable::Value(BoshAckInput {
            request: BoshRequest {
                rid: 12,
                fingerprint: sha256(request_xml.as_bytes()),
                request_xml: text(request_xml),
                content_type: text("text/xml; charset=utf-8"),
                responders: list(vec![Responder::Open]),
            },
            acknowledged_rid: 11,
            renewal: CommitCut::Complete,
            commit: CommitCut::Complete,
            deleted: mix.transport.transfer.returned_source.clone(),
        });
        parser_case(Composition::ReplayMixQueuedAuth(ReplayMixQueuedAuth {
            mix: ReplayMixBoshLane {
                foreground: ReplayForeground {
                    frame: Frame {
                        frame_id: fixed(31),
                        connection_id: fixed(7),
                        transport: TransportKind::Bosh,
                        input: text("<message><body>hi</body></message>"),
                    },
                    configured_domain: text("mix.example.test"),
                    ingress: MixIngress {
                        channel_id: fixed(10),
                        channel_jid: text("c@mix.example.test"),
                        actor_bare: text("u@example.test"),
                        actor_full: text("u@example.test/m"),
                        children: text("<body>hi</body>"),
                        encrypted: false,
                        identity: Nullable::Value(ReplayIdentityInput {
                            client_id: text("replay"),
                            canonical_semantics: Bytes::of(b"<body>hi</body>").unwrap(),
                        }),
                    },
                    existing: Existing {
                        authoritative_id: fixed(9),
                        semantic_key_id: text("synthetic-v1"),
                        semantic_mac: Bytes::of(&[0; 32]).unwrap(),
                        target_id: Nullable::Null(()),
                    },
                    original_id: fixed(9),
                },
                worker: mix.worker,
                transport: mix.transport,
            },
            auth: QueuedAuthLane {
                unbound,
                bound,
                session,
                padding,
            },
        }))
    }
    fn recovery_case() -> Case {
        let mut worker = independent_mix().worker;
        worker.attempt.archive.reply = ArchiveReply::Replay(ArchiveReplayInput {
            original_archive_id: fixed(50),
        });
        let mut replacement = worker.attempt.clone();
        replacement.claim.lease_token = fixed(15);
        replacement.claim.attempt_count = 1;
        replacement.route.targets.0[0].connection_id = fixed(2);
        replacement.route.targets.0[0].caps.connection_id = fixed(2);
        replacement.route.targets.0[0].full_jid = text("u@example.test/r");
        parser_case(Composition::MixRecoveryNative(RecoveryInput {
            worker,
            replacement,
            native: DurableNative {
                connection_id: fixed(2),
                write: write_ok(),
                returned_fence: MixSource {
                    delivery_id: fixed(12),
                    lease_token: fixed(14),
                },
                ack_commit: CommitCut::Complete,
            },
        }))
    }
    fn defer_case() -> Case {
        let mut worker = independent_mix().worker;
        worker.attempt.route.targets = list(vec![]);
        parser_case(Composition::MixDefer(DeferInput {
            worker,
            settlement_commit: CommitCut::Complete,
            updated: true,
        }))
    }
    fn decoded_positive(case: Case) {
        let bytes = serde_json::to_vec(&case).unwrap();
        let parsed = decode(&bytes).unwrap();
        assert_eq!(parsed.case, case);
    }
    fn live_anchor(
        control: u128,
        receipt: u128,
        attempt: u128,
        frame: u128,
        kind: ObservedCredentialKind,
    ) -> Fact {
        Fact::Control(ControlFact::LivePublication(LivePublication {
            cut: Cut::Introduction,
            snapshot: PublicationSnapshot {
                control: id(control),
                frame: Nullable::Value(id(frame)),
                handler: Nullable::Null(()),
                sealed: false,
                transport: AuthTransport::NotStarted(Empty {}),
                publication: PublicationKnowledge::NotStarted(Empty {}),
                service_started: false,
                repository_started: false,
                rollback: PublicationRollback::NotRequested,
                returned: Nullable::Null(()),
                return_matches: false,
                effects: PublicationEffects {
                    unbound: false,
                    epoch_applied: false,
                    route_mapping: Nullable::Null(()),
                    route_activation: Nullable::Null(()),
                    caps_entered: false,
                    caps_returned: false,
                    notification_entered: false,
                    notification_returned: Nullable::Null(()),
                },
                terminal: Nullable::Null(()),
            },
            joins: Nullable::Value(PublicationJoins {
                control: id(control),
                frame: Nullable::Value(id(frame)),
                receipt: id(receipt),
                credential: Nullable::Value(CredentialAttemptJoin {
                    attempt: id(attempt),
                    frame: id(frame),
                    connection: id(2),
                    ordinal: 0,
                    kind,
                }),
                begun_receipt: Nullable::Null(()),
                bound_effects: false,
                notification_expected: false,
            }),
        }))
    }
    fn credential_at(
        attempt: u128,
        receipt: u128,
        returned: u128,
        frame: u128,
        kind: ObservedCredentialKind,
    ) -> Fact {
        let mut fact = credential(attempt, Some(receipt), Some(returned));
        let Fact::Credential(c) = &mut fact else {
            unreachable!()
        };
        c.snapshot.frame = id(frame);
        c.snapshot.kind = kind;
        let Nullable::Value(joins) = &mut c.joins else {
            unreachable!()
        };
        joins.owner.frame = id(frame);
        joins.owner.kind = kind;
        fact
    }

    #[test]
    fn decode_s01_muc_stored_native() {
        decoded_positive(muc_case(MucDrive::Complete, false));
    }
    #[test]
    fn decode_s02_muc_replay_without_fanout() {
        decoded_positive(muc_case(MucDrive::Complete, true));
    }
    #[test]
    fn decode_s03_muc_volatile_second_endpoint_drop() {
        decoded_positive(muc_case(MucDrive::DropSecondEndpoint, false));
    }
    #[test]
    fn decode_s04_muc_commit_pending_drop() {
        decoded_positive(muc_case(MucDrive::DropCommit, false));
    }
    #[test]
    fn decode_s05_auth_fresh_mix_native() {
        decoded_positive(fresh_mix_native_case());
    }
    #[test]
    fn decode_s06_independent_replay_and_queued_auth() {
        decoded_positive(replay_queued_auth_case());
    }
    #[test]
    fn decode_s07_recovery_distinct_initially_published_connections() {
        decoded_positive(recovery_case());
    }
    #[test]
    fn decode_s08_archive_pending_defer() {
        decoded_positive(defer_case());
    }
    #[test]
    fn decode_s09_native_auth_backend_error() {
        decoded_positive(native_auth_case(false));
    }
    #[test]
    fn decode_s10_native_auth_publication_pending_drop() {
        decoded_positive(native_auth_case(true));
    }
    #[test]
    fn decode_s11_bosh_auth_error_with_independent_mix() {
        decoded_positive(auth_bosh_case(true, false));
    }
    #[test]
    fn decode_s12_bosh_auth_pending_drop_with_independent_mix() {
        decoded_positive(auth_bosh_case(true, true));
    }
    #[test]
    fn decode_s13_reduced_bosh_auth_error() {
        decoded_positive(auth_bosh_case(false, false));
    }

    #[test]
    fn binding_stage_device_presence_matches_actual_preparation_contract() {
        let absent = auth_bosh_case(false, false);
        decoded_positive(absent.clone());
        let mut present = absent.clone();
        let Composition::BoshAuth(c) = &mut present.composition else {
            unreachable!()
        };
        c.auth.bound.device_id = Nullable::Value(fixed(80));
        c.auth.bound.preparation.stage_present = true;
        c.auth.bound.preparation.stage_epoch = Nullable::Value(73);
        decoded_positive(present.clone());
        for (mut case, stage_present) in [(absent, true), (present, false)] {
            let Composition::BoshAuth(c) = &mut case.composition else {
                unreachable!()
            };
            c.auth.bound.preparation.stage_present = stage_present;
            c.auth.bound.preparation.stage_epoch = if stage_present {
                Nullable::Value(73)
            } else {
                Nullable::Null(())
            };
            assert!(matches!(
                decode(&serde_json::to_vec(&case).unwrap()),
                Err(Rejection::Relationship)
            ));
        }
    }

    #[test]
    fn committed_epoch_presence_must_agree_with_prepared_stage() {
        for stage_present in [false, true] {
            let mut case = fresh_mix_native_case();
            let Composition::AuthThenMixNative(c) = &mut case.composition else {
                unreachable!()
            };
            c.auth.preparation.stage_present = stage_present;
            c.auth.preparation.stage_epoch = if stage_present {
                Nullable::Value(73)
            } else {
                Nullable::Null(())
            };
            c.auth.device_id = if stage_present {
                Nullable::Value(fixed(80))
            } else {
                Nullable::Null(())
            };
            c.auth.publication = PublicationReply::Committed(EpochReply {
                epoch: if stage_present {
                    Nullable::Null(())
                } else {
                    Nullable::Value(41)
                },
            });
            assert!(matches!(
                decode(&serde_json::to_vec(&case).unwrap()),
                Err(Rejection::Relationship)
            ));
        }
        // Only presence is constrained, never an expected numeric epoch hint.
        for epoch in [i64::MIN, 0, i64::MAX] {
            let mut case = fresh_mix_native_case();
            let Composition::AuthThenMixNative(c) = &mut case.composition else {
                unreachable!()
            };
            c.auth.preparation.stage_present = true;
            c.auth.preparation.stage_epoch = Nullable::Value(73);
            c.auth.device_id = Nullable::Value(fixed(80));
            c.auth.publication = PublicationReply::Committed(EpochReply {
                epoch: Nullable::Value(epoch),
            });
            decoded_positive(case);
        }
    }

    #[test]
    fn pending_commit_epoch_presence_must_agree_with_prepared_stage() {
        for stage_present in [false, true] {
            let mut case = auth_bosh_case(true, true);
            let Composition::BoshAuth(c) = &mut case.composition else {
                unreachable!()
            };
            c.auth.bound.preparation.stage_present = stage_present;
            c.auth.bound.preparation.stage_epoch = if stage_present {
                Nullable::Value(73)
            } else {
                Nullable::Null(())
            };
            c.auth.bound.device_id = if stage_present {
                Nullable::Value(fixed(80))
            } else {
                Nullable::Null(())
            };
            c.auth.bound.publication = PublicationReply::CommitPending(EpochReply {
                epoch: if stage_present {
                    Nullable::Null(())
                } else {
                    Nullable::Value(41)
                },
            });
            assert!(matches!(
                decode(&serde_json::to_vec(&case).unwrap()),
                Err(Rejection::Relationship)
            ));
        }
        for epoch in [i64::MIN, 0, i64::MAX] {
            let mut case = auth_bosh_case(true, true);
            let Composition::BoshAuth(c) = &mut case.composition else {
                unreachable!()
            };
            c.auth.bound.preparation.stage_present = true;
            c.auth.bound.preparation.stage_epoch = Nullable::Value(73);
            c.auth.bound.device_id = Nullable::Value(fixed(80));
            c.auth.bound.publication = PublicationReply::CommitPending(EpochReply {
                epoch: Nullable::Value(epoch),
            });
            decoded_positive(case);
        }
    }

    #[test]
    fn explicit_stage_hint_and_later_publication_epoch_may_differ() {
        for pending in [false, true] {
            let mut case = if pending {
                auth_bosh_case(true, true)
            } else {
                fresh_mix_native_case()
            };
            let auth = match &mut case.composition {
                Composition::AuthThenMixNative(c) => &mut c.auth,
                Composition::BoshAuth(c) => &mut c.auth.bound,
                _ => unreachable!(),
            };
            auth.device_id = Nullable::Value(fixed(80));
            auth.preparation.stage_present = true;
            // Both are explicit supplied data. The publication's real returned
            // epoch is independent of the earlier stage hint, never repaired.
            auth.preparation.stage_epoch = Nullable::Value(73);
            auth.publication = if pending {
                PublicationReply::CommitPending(EpochReply {
                    epoch: Nullable::Value(9001),
                })
            } else {
                PublicationReply::Committed(EpochReply {
                    epoch: Nullable::Value(9001),
                })
            };
            let parsed = decode(&serde_json::to_vec(&case).unwrap()).unwrap();
            let auth = match &parsed.case.composition {
                Composition::AuthThenMixNative(c) => &c.auth,
                Composition::BoshAuth(c) => &c.auth.bound,
                _ => unreachable!(),
            };
            let reply = match &auth.publication {
                PublicationReply::Committed(r) | PublicationReply::CommitPending(r) => r,
                _ => unreachable!(),
            };
            assert_eq!(auth.preparation.stage_epoch.get(), Some(&73));
            assert_eq!(reply.epoch.get(), Some(&9001));
            assert_ne!(auth.preparation.stage_epoch, reply.epoch);
        }
    }

    #[test]
    fn explicit_stage_epoch_presence_must_match_stage_present() {
        for stage_present in [false, true] {
            let mut case = auth_bosh_case(false, false);
            let Composition::BoshAuth(c) = &mut case.composition else {
                unreachable!()
            };
            c.auth.bound.device_id = if stage_present {
                Nullable::Value(fixed(80))
            } else {
                Nullable::Null(())
            };
            c.auth.bound.preparation.stage_present = stage_present;
            c.auth.bound.preparation.stage_epoch = if stage_present {
                Nullable::Null(())
            } else {
                Nullable::Value(73)
            };
            assert!(matches!(
                decode(&serde_json::to_vec(&case).unwrap()),
                Err(Rejection::Relationship)
            ));
        }
    }

    #[test]
    fn stage_epoch_is_required_nullable_i64_and_accepts_no_operation_id_input() {
        let absent = r#"{"generation_allowed":true,"binding_reserved":true,"stage_present":false,"stage_epoch":null,"commit":"Complete"}"#;
        let parsed: CredentialPreparationInput = serde_json::from_str(absent).unwrap();
        assert!(parsed.stage_epoch.get().is_none());
        assert!(serde_json::from_str::<CredentialPreparationInput>(
            &absent.replace(",\"stage_epoch\":null", "")
        )
        .is_err());
        let extra = absent.replacen(
            '{',
            "{\"stage_operation_id\":\"00000000-0000-0000-0000-000000000001\",",
            1,
        );
        assert!(serde_json::from_str::<CredentialPreparationInput>(&extra).is_err());
        for valid in [i64::MIN, 0, i64::MAX] {
            let raw = absent
                .replace("\"stage_present\":false", "\"stage_present\":true")
                .replace("\"stage_epoch\":null", &format!("\"stage_epoch\":{valid}"));
            assert_eq!(
                serde_json::from_str::<CredentialPreparationInput>(&raw)
                    .unwrap()
                    .stage_epoch
                    .get(),
                Some(&valid)
            );
        }
        for invalid in [
            "true",
            "\"73\"",
            "73.0",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            assert!(
                serde_json::from_str::<CredentialPreparationInput>(&absent.replace(
                    "\"stage_epoch\":null",
                    &format!("\"stage_epoch\":{invalid}")
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn notification_intent_is_unsupported_before_owners_and_matches_rejection_envelope() {
        let rejected = |case: Case| {
            let input = serde_json::to_vec(&case).unwrap();
            assert!(matches!(decode(&input), Err(Rejection::Unsupported)));
            let envelope = Envelope::rejected(&input, Rejection::Unsupported).unwrap();
            assert!(
                envelope.facts.is_empty()
                    && envelope.identity_map.is_empty()
                    && envelope.execution.get().is_none()
            );
            assert_eq!(envelope.input_sha256, sha256(&input));
            validate_envelope(&envelope, &input, None).unwrap();
        };
        for mut case in [
            fresh_mix_native_case(),
            native_auth_case(false),
            native_auth_case(true),
            auth_bosh_case(true, false),
            auth_bosh_case(true, true),
            auth_bosh_case(false, false),
        ] {
            let auth = match &mut case.composition {
                Composition::AuthThenMixNative(c) => &mut c.auth,
                Composition::NativeAuth(c) => &mut c.auth,
                Composition::BoshAuth(c) => &mut c.auth.bound,
                _ => unreachable!(),
            };
            auth.notification_expected = true;
            rejected(case);
        }
        for unbound in [false, true] {
            let mut case = replay_queued_auth_case();
            let Composition::ReplayMixQueuedAuth(c) = &mut case.composition else {
                unreachable!()
            };
            if unbound {
                c.auth.unbound.notification_expected = true;
            } else {
                c.auth.bound.notification_expected = true;
            }
            rejected(case);
        }
    }

    #[test]
    fn false_notification_intent_preserves_all_thirteen_positive_meanings() {
        for case in [
            muc_case(MucDrive::Complete, false),
            muc_case(MucDrive::Complete, true),
            muc_case(MucDrive::DropSecondEndpoint, false),
            muc_case(MucDrive::DropCommit, false),
            fresh_mix_native_case(),
            replay_queued_auth_case(),
            recovery_case(),
            defer_case(),
            native_auth_case(false),
            native_auth_case(true),
            auth_bosh_case(true, false),
            auth_bosh_case(true, true),
            auth_bosh_case(false, false),
        ] {
            decoded_positive(case);
        }
    }

    #[test]
    fn no_notification_intent_with_some_epoch_remains_a_valid_component_input() {
        let mut case = fresh_mix_native_case();
        let Composition::AuthThenMixNative(c) = &mut case.composition else {
            unreachable!()
        };
        assert!(!c.auth.notification_expected);
        c.auth.device_id = Nullable::Value(fixed(80));
        c.auth.preparation.stage_present = true;
        c.auth.preparation.stage_epoch = Nullable::Value(73);
        c.auth.publication = PublicationReply::Committed(EpochReply {
            epoch: Nullable::Value(9001),
        });
        let parsed = decode(&serde_json::to_vec(&case).unwrap()).unwrap();
        let Composition::AuthThenMixNative(c) = &parsed.case.composition else {
            unreachable!()
        };
        assert!(!c.auth.notification_expected);
        assert!(matches!(
            c.auth.publication,
            PublicationReply::Committed(EpochReply {
                epoch: Nullable::Value(9001)
            })
        ));
        // publish_owned needs both a captured intent and Some authenticated
        // epoch. This controlled None-intent component input is not evidence
        // of full ProtocolSession notification-intent capture correspondence.
    }

    #[test]
    fn admitted_owner_reservations_survive_sticky_loss_without_recharge() {
        let mut r = Recorder::new(&input_case());
        let site = PollSite::new(DriverOwner::Worker, 1).unwrap();
        r.reserve_owner_poll(site).unwrap();
        r.polled(
            site.owner(),
            site.owner_ordinal(),
            &std::task::Poll::<()>::Pending,
        )
        .unwrap();
        assert_eq!(r.admitted_owner_polls(), 1);
        assert_eq!(r.sequence.polls, 1);
        r.missing_observation();
        for expected in 2..=64 {
            r.reserve_owner_poll(site).unwrap();
            assert_eq!(
                r.polled(
                    site.owner(),
                    site.owner_ordinal(),
                    &std::task::Poll::<()>::Pending
                ),
                Err(Loss::MissingObservation)
            );
            assert_eq!(r.admitted_owner_polls(), expected);
        }
        assert_eq!(r.sequence.polls, 1);
        let stop = r.reserve_owner_poll(site).unwrap_err();
        assert_eq!(r.admitted_owner_polls(), 64);
        assert_eq!(
            stop.resource_stop,
            ResourceStop::DriverPoll(DriverResourceStop {
                owner: DriverOwner::Worker,
                owner_ordinal: 1,
                admitted_calls: 64
            })
        );
        assert_eq!(
            r.reserve_owner_poll(PollSite::new(DriverOwner::Muc, 0).unwrap()),
            Err(stop)
        );
        let e = r.finish_resource_stopped().unwrap();
        assert!(e.execution.get().is_none());
        assert!(e.resource_stop.get().is_some());
        assert_eq!(e.facts.len(), 1);
        assert!(matches!(
            e.observation_status,
            ObservationStatus::Lost(LostObservation {
                reason: Loss::MissingObservation,
                after_seq: 1
            })
        ));
    }

    #[test]
    fn first_valid_resource_stop_is_immutable_and_invalid_metadata_is_internal() {
        let mut r = Recorder::new(&input_case());
        assert_eq!(
            r.latch_resource_stop(ResourceStop::DriverPoll(DriverResourceStop {
                owner: DriverOwner::Worker,
                owner_ordinal: 0,
                admitted_calls: 64
            })),
            Err(DriverConfigurationError::AdmittedCalls)
        );
        let invalid = ResourceStop::NativeWrite(NativeResourceStop {
            item_ordinal: 5,
            admitted_calls: 0,
        });
        assert_eq!(
            r.latch_resource_stop(invalid.clone()),
            Err(DriverConfigurationError::ItemOrdinal)
        );
        assert!(r.resource_stop().is_none());
        assert!(r.loss.is_none());
        let first = ResourceStop::NativeWrite(NativeResourceStop {
            item_ordinal: 4,
            admitted_calls: 0,
        });
        let stopped = r.latch_resource_stop(first.clone()).unwrap();
        assert_eq!(
            r.latch_resource_stop(ResourceStop::NativeFlush(NativeResourceStop {
                item_ordinal: 1,
                admitted_calls: 1
            }))
            .unwrap(),
            stopped
        );
        assert_eq!(r.latch_resource_stop(invalid).unwrap(), stopped);
        assert_eq!(r.resource_stop(), Some(&first));
        assert_eq!(r.admitted_owner_polls(), 0);
        assert_eq!(
            r.reserve_owner_poll(PollSite::new(DriverOwner::Native, 4).unwrap()),
            Err(stopped)
        );
        assert_eq!(r.admitted_owner_polls(), 0);
        let e = r.finish(Execution::Complete).unwrap();
        assert!(e.rejection.get().is_none());
        assert!(e.execution.get().is_none());
        assert_eq!(e.resource_stop.get(), Some(&first));
    }

    #[test]
    fn original_lost_prefix_and_later_resource_stop_are_both_retained() {
        let input = reduced_bytes();
        let validated = decode(&input).unwrap();
        let mut r = Recorder::new(&validated);
        r.capture(credential(100, Some(200), None)).unwrap();
        let prefix = r.facts.clone();
        r.missing_observation();
        let stop = ResourceStop::NativeWrite(NativeResourceStop {
            item_ordinal: 0,
            admitted_calls: 32,
        });
        r.latch_resource_stop(stop.clone()).unwrap();
        assert_eq!(
            r.capture(credential(100, Some(200), Some(200))),
            Err(Loss::MissingObservation)
        );
        let e = r.finish_resource_stopped().unwrap();
        assert_eq!(e.facts.as_slice(), prefix.as_slice());
        assert_eq!(e.resource_stop.get(), Some(&stop));
        assert!(matches!(
            e.observation_status,
            ObservationStatus::Lost(LostObservation {
                reason: Loss::MissingObservation,
                after_seq: 1
            })
        ));
        validate_envelope(&e, &input, Some(&validated)).unwrap();
        let encoded = encode_frame(&e).unwrap();
        assert_eq!(decode_frame(&encoded).unwrap(), e);
    }

    #[test]
    fn envelope_requires_exact_rejected_normal_and_resource_stopped_nullability() {
        let input = reduced_bytes();
        let validated = decode(&input).unwrap();
        let normal = Recorder::new(&validated)
            .finish(Execution::Complete)
            .unwrap();
        validate_envelope(&normal, &input, Some(&validated)).unwrap();
        let mut missing_execution = normal.clone();
        missing_execution.execution = Nullable::Null(());
        assert_eq!(
            validate_envelope(&missing_execution, &input, Some(&validated)),
            Err(Loss::EncodingFailure)
        );
        let mut r = Recorder::new(&validated);
        r.latch_resource_stop(ResourceStop::NativeFlush(NativeResourceStop {
            item_ordinal: 4,
            admitted_calls: 1,
        }))
        .unwrap();
        let stopped = r.finish_resource_stopped().unwrap();
        validate_envelope(&stopped, &input, Some(&validated)).unwrap();
        let mut false_execution = stopped.clone();
        false_execution.execution = Nullable::Value(Execution::Cancelled);
        assert_eq!(
            validate_envelope(&false_execution, &input, Some(&validated)),
            Err(Loss::EncodingFailure)
        );
        let bad_input = b"{}";
        let mut rejected = Envelope::rejected(bad_input, Rejection::Json).unwrap();
        validate_envelope(&rejected, bad_input, None).unwrap();
        rejected.resource_stop = stopped.resource_stop.clone();
        assert_eq!(
            validate_envelope(&rejected, bad_input, None),
            Err(Loss::EncodingFailure)
        );
        assert_eq!(
            Recorder::new(&validated)
                .finish_resource_stopped()
                .unwrap_err(),
            DriverConfigurationError::MissingResourceStop
        );
    }

    #[test]
    fn resource_stop_field_is_required_nullable_and_discriminator_is_closed() {
        let e = Recorder::new(&input_case())
            .finish(Execution::Complete)
            .unwrap();
        let raw = serde_json::to_string(&e).unwrap();
        assert!(raw.contains("\"resource_stop\":null"));
        assert!(
            serde_json::from_str::<Envelope>(&raw.replace(",\"resource_stop\":null", "")).is_err()
        );
        for raw in [
            r#"{"kind":"NativeBytes","data":{"item_ordinal":0,"admitted_calls":0}}"#,
            r#"{"kind":"NativeWrite","data":{"item_ordinal":0,"admitted_calls":0,"text":"extra"}}"#,
            r#"{"kind":"DriverPoll","data":{"owner":"Worker","owner_ordinal":0,"admitted_calls":64,"time":1}}"#,
        ] {
            assert!(serde_json::from_str::<ResourceStop>(raw).is_err());
        }
    }

    #[test]
    fn resource_stop_and_poll_site_bounds_match_fixed_owner_scopes() {
        for (owner, maximum) in [
            (DriverOwner::Muc, 2),
            (DriverOwner::Foreground, 2),
            (DriverOwner::Claim, 1),
            (DriverOwner::Worker, 1),
            (DriverOwner::Credential, 1),
            (DriverOwner::Publication, 1),
            (DriverOwner::Native, 4),
            (DriverOwner::Bosh, 3),
        ] {
            PollSite::new(owner, maximum).unwrap();
            assert_eq!(
                PollSite::new(owner, maximum + 1),
                Err(DriverConfigurationError::OwnerOrdinal)
            );
            ResourceStop::DriverPoll(DriverResourceStop {
                owner,
                owner_ordinal: maximum,
                admitted_calls: 64,
            })
            .validate()
            .unwrap();
        }
        for count in [0, 63, 65] {
            assert_eq!(
                ResourceStop::DriverPoll(DriverResourceStop {
                    owner: DriverOwner::Worker,
                    owner_ordinal: 0,
                    admitted_calls: count
                })
                .validate(),
                Err(DriverConfigurationError::AdmittedCalls)
            );
        }
        for count in [0, 17, 32] {
            ResourceStop::NativeWrite(NativeResourceStop {
                item_ordinal: 4,
                admitted_calls: count,
            })
            .validate()
            .unwrap();
        }
        for count in [0, 1] {
            ResourceStop::NativeFlush(NativeResourceStop {
                item_ordinal: 4,
                admitted_calls: count,
            })
            .validate()
            .unwrap();
        }
        assert_eq!(
            ResourceStop::NativeWrite(NativeResourceStop {
                item_ordinal: 4,
                admitted_calls: 33
            })
            .validate(),
            Err(DriverConfigurationError::AdmittedCalls)
        );
        assert_eq!(
            ResourceStop::NativeFlush(NativeResourceStop {
                item_ordinal: 4,
                admitted_calls: 2
            })
            .validate(),
            Err(DriverConfigurationError::AdmittedCalls)
        );
        assert_eq!(
            ResourceStop::NativeFlush(NativeResourceStop {
                item_ordinal: 5,
                admitted_calls: 0
            })
            .validate(),
            Err(DriverConfigurationError::ItemOrdinal)
        );
    }

    #[test]
    fn envelope_validator_rejects_out_of_bound_resource_metadata() {
        let input = reduced_bytes();
        let validated = decode(&input).unwrap();
        for stop in [
            ResourceStop::DriverPoll(DriverResourceStop {
                owner: DriverOwner::Claim,
                owner_ordinal: 2,
                admitted_calls: 64,
            }),
            ResourceStop::DriverPoll(DriverResourceStop {
                owner: DriverOwner::Claim,
                owner_ordinal: 0,
                admitted_calls: 63,
            }),
            ResourceStop::NativeWrite(NativeResourceStop {
                item_ordinal: 0,
                admitted_calls: 33,
            }),
            ResourceStop::NativeFlush(NativeResourceStop {
                item_ordinal: 0,
                admitted_calls: 2,
            }),
        ] {
            let mut envelope = Recorder::new(&validated)
                .finish(Execution::Complete)
                .unwrap();
            envelope.execution = Nullable::Null(());
            envelope.resource_stop = Nullable::Value(stop);
            assert_eq!(
                validate_envelope(&envelope, &input, Some(&validated)),
                Err(Loss::EncodingFailure)
            );
        }
    }

    #[test]
    fn binding_lease_duration_has_exact_bounds_and_unsigned_integer_type() {
        for lease in [1, MAX_BINDING_LEASE_SECONDS] {
            let mut case = auth_bosh_case(false, false);
            let Composition::BoshAuth(c) = &mut case.composition else {
                unreachable!()
            };
            let Nullable::Value(binding) = &mut c.auth.bound.binding else {
                unreachable!()
            };
            binding.lease_seconds = lease;
            decoded_positive(case);
        }
        for lease in [0, MAX_BINDING_LEASE_SECONDS + 1, u64::MAX] {
            let mut case = auth_bosh_case(false, false);
            let Composition::BoshAuth(c) = &mut case.composition else {
                unreachable!()
            };
            let Nullable::Value(binding) = &mut c.auth.bound.binding else {
                unreachable!()
            };
            binding.lease_seconds = lease;
            assert!(decode(&serde_json::to_vec(&case).unwrap()).is_err());
        }
        for lease in [
            "true",
            "-1",
            "60.0",
            "18446744073709551616",
            "\"00000000-0000-0000-0000-000000000005\"",
        ] {
            let raw = format!("{{\"resource\":\"r\",\"lease_seconds\":{lease},\"full_jid\":\"u@example.test/r\"}}");
            assert!(serde_json::from_str::<BindingInput>(&raw).is_err());
        }
    }

    #[test]
    fn recovery_rejects_unpublished_same_connection_or_changed_archive_original() {
        for change in 0..7 {
            let mut case = recovery_case();
            let Composition::MixRecoveryNative(c) = &mut case.composition else {
                unreachable!()
            };
            match change {
                0 => c.worker.attempt.archive.reply = ArchiveReply::StoreCandidate(Empty {}),
                1 => c.replacement.archive.reply = ArchiveReply::StoreCandidate(Empty {}),
                2 => {
                    c.replacement.archive.reply = ArchiveReply::Replay(ArchiveReplayInput {
                        original_archive_id: fixed(51),
                    })
                }
                3 => {
                    c.replacement.route.targets.0[0].connection_id = fixed(7);
                    c.replacement.route.targets.0[0].caps.connection_id = fixed(7);
                    c.native.connection_id = fixed(7);
                }
                4 => {
                    c.worker.attempt.route.targets.0[0].provenance =
                        RouteProvenance::ActivatedByAuth(ActivatedRoute { frame_id: fixed(1) });
                    c.worker.attempt.route.targets.0[0].routable = false;
                }
                5 => {
                    c.replacement.route.targets.0[0].provenance =
                        RouteProvenance::ActivatedByAuth(ActivatedRoute { frame_id: fixed(1) });
                    c.replacement.route.targets.0[0].routable = false;
                }
                _ => c.replacement.route.targets.0[0].routable = false,
            }
            assert!(decode(&serde_json::to_vec(&case).unwrap()).is_err());
        }
    }

    #[test]
    fn defer_rejects_privacy_block_before_archive_path() {
        let mut case = defer_case();
        let Composition::MixDefer(c) = &mut case.composition else {
            unreachable!()
        };
        c.worker.attempt.route.privacy_blocked = true;
        assert!(matches!(
            decode(&serde_json::to_vec(&case).unwrap()),
            Err(Rejection::Relationship)
        ));
    }

    #[test]
    fn fresh_mix_requires_visible_actor_and_nonempty_projection() {
        let mut visible = fresh_mix_native_case();
        let Composition::AuthThenMixNative(c) = &mut visible.composition else {
            unreachable!()
        };
        c.foreground.command.visible_jid = Nullable::Value(c.foreground.ingress.actor_bare.clone());
        decoded_positive(visible);
        for empty in [false, true] {
            let mut case = fresh_mix_native_case();
            let Composition::AuthThenMixNative(c) = &mut case.composition else {
                unreachable!()
            };
            if empty {
                let Nullable::Value(p) = &mut c.foreground.stored.projection else {
                    unreachable!()
                };
                p.stanza_template = text("");
            } else {
                c.foreground.command.visible_jid = Nullable::Value(text("different@example.test"));
            }
            assert!(matches!(
                decode(&serde_json::to_vec(&case).unwrap()),
                Err(Rejection::Relationship)
            ));
        }
    }

    #[test]
    fn finite_recipe_actor_budget_rejects_third_distinct_actor() {
        let mut case = muc_case(MucDrive::DropSecondEndpoint, false);
        let Composition::Muc(c) = &mut case.composition else {
            unreachable!()
        };
        c.command.actor_scope = text("third@example.test");
        c.command.sender_jid = text("third@example.test/one");
        c.command.authority.actor_scope = c.command.actor_scope.clone();
        c.command.authority.full_jid = c.command.sender_jid.clone();
        let MucPrincipal::Local(p) = &mut c.command.authority.principal else {
            unreachable!()
        };
        p.user_id = fixed(80);
        // All pre-existing recipe relationships remain meaningful; only the
        // extra canonical account actor exceeds the finite two-actor scope.
        case.validate().unwrap();
        assert!(matches!(
            decode(&serde_json::to_vec(&case).unwrap()),
            Err(Rejection::Relationship)
        ));
    }

    #[test]
    fn bosh_governor_input_enforces_actual_constructor_constraints() {
        for change in 0..3 {
            let mut case = auth_bosh_case(false, false);
            let Composition::BoshAuth(c) = &mut case.composition else {
                unreachable!()
            };
            let g = &mut c.auth.session.governor;
            match change {
                0 => g.max_recovery_jobs = 0,
                1 => {
                    g.max_snapshot_bytes = 65537;
                    g.max_recovery_bytes = 65537;
                }
                _ => g.max_recovery_bytes = 65535,
            }
            assert!(matches!(
                decode(&serde_json::to_vec(&case).unwrap()),
                Err(Rejection::Relationship)
            ));
        }
    }

    #[test]
    fn publication_callback_preserves_actual_boolean_and_absent_return() {
        for returned in ["true", "false", "null"] {
            let raw = format!("{{\"connection\":\"00000000-0000-0000-0000-000000000002\",\"session\":null,\"rid\":null,\"invoked_owners\":[],\"returned\":{returned}}}");
            assert!(serde_json::from_str::<PublicationCallback<Id>>(&raw).is_ok());
        }
        let raw = r#"{"connection":"00000000-0000-0000-0000-000000000002","session":null,"rid":null,"invoked_owners":[],"returned":"Completed"}"#;
        assert!(serde_json::from_str::<PublicationCallback<Id>>(raw).is_err());
    }

    #[test]
    fn actual_preseal_publication_capture_uses_phase_neutral_control_identity() {
        use crate::services::authentication::{publication as actual, CredentialCommitReceipt};
        let receipt = CredentialCommitReceipt::new(None, None, None);
        let observed = actual::Observation::returned_receipt(&receipt, Some(Uuid::from_u128(1)));
        let s = observed.snapshot();
        let j = observed.joins();
        // This ordinary control deliberately captures a genuine newly created
        // observation before any seal. Unexpected noninitial states stop the
        // test rather than being replaced by a fixture's expected state.
        let transport = match s.transport {
            actual::Transport::NotStarted => AuthTransport::NotStarted(Empty {}),
            _ => panic!("not a pre-seal constructor snapshot"),
        };
        let publication = match s.publication {
            actual::Knowledge::NotStarted => PublicationKnowledge::NotStarted(Empty {}),
            _ => panic!("not initial publication knowledge"),
        };
        let rollback = match s.rollback {
            actual::Rollback::NotRequested => PublicationRollback::NotRequested,
            _ => panic!("unexpected rollback"),
        };
        let nullable_bool = |v: Option<bool>| v.map_or(Nullable::Null(()), Nullable::Value);
        let nullable_id = |v: Option<Uuid>| {
            v.map_or(Nullable::Null(()), |v| {
                Nullable::Value(EvidenceId::observed(v))
            })
        };
        let fact = Fact::Control(ControlFact::LivePublication(LivePublication {
            cut: Cut::Introduction,
            snapshot: PublicationSnapshot {
                control: EvidenceId::observed(s.control),
                frame: nullable_id(s.frame),
                handler: s
                    .handler
                    .map_or(Nullable::Null(()), |_| panic!("unexpected handler return")),
                sealed: s.sealed,
                transport,
                publication,
                service_started: s.service_started,
                repository_started: s.repository_started,
                rollback,
                returned: s.returned.map_or(Nullable::Null(()), |_| {
                    panic!("unexpected publication return")
                }),
                return_matches: s.return_matches,
                effects: PublicationEffects {
                    unbound: s.effects.unbound,
                    epoch_applied: s.effects.epoch_applied,
                    route_mapping: nullable_bool(s.effects.route_mapping),
                    route_activation: nullable_bool(s.effects.route_activation),
                    caps_entered: s.effects.caps_entered,
                    caps_returned: s.effects.caps_returned,
                    notification_entered: s.effects.notification_entered,
                    notification_returned: nullable_bool(s.effects.notification_returned),
                },
                terminal: s
                    .terminal
                    .map_or(Nullable::Null(()), |_| panic!("unexpected terminal")),
            },
            joins: Nullable::Value(PublicationJoins {
                control: EvidenceId::observed(j.control),
                frame: nullable_id(j.frame),
                receipt: EvidenceId::observed(j.receipt),
                credential: j.credential.map_or(Nullable::Null(()), |_| {
                    panic!("unexpected credential attachment")
                }),
                begun_receipt: nullable_id(j.begun_receipt),
                bound_effects: j.bound_effects,
                notification_expected: j.notification_expected,
            }),
        }));
        assert!(!s.sealed);
        let mut recorder = Recorder::new(&input_case());
        recorder.capture(fact).unwrap();
        let e = recorder.finish(Execution::Complete).unwrap();
        let Fact::Control(ControlFact::LivePublication(capture)) = &e.facts.0[0].fact else {
            unreachable!()
        };
        assert!(!capture.snapshot.sealed);
        let EvidenceId::Encoded(control) = &capture.snapshot.control else {
            unreachable!()
        };
        assert_eq!(
            e.identity_map
                .0
                .iter()
                .find(|i| &i.label == control)
                .unwrap()
                .locus,
            Introduction::ControlIdentity
        );
    }

    #[test]
    fn prior_completed_frame_outcome_does_not_complete_pending_publication() {
        let input = reduced_bytes();
        let parsed = decode(&input).unwrap();
        let mut r = Recorder::new(&parsed);
        r.capture(Fact::Frame(FrameCapture {
            frame: id(1),
            cut: Cut::AfterPoll,
            stage: Nullable::Value(FrameStage::AuthPublication),
            outcome: Nullable::Value(FrameOutcome::Completed),
            admission_begin: Nullable::Null(()),
            admission_finalize: Nullable::Null(()),
        }))
        .unwrap();
        let mut live = live_anchor(100, 200, 300, 1, ObservedCredentialKind::Binding);
        let Fact::Control(ControlFact::LivePublication(p)) = &mut live else {
            unreachable!()
        };
        p.cut = Cut::AfterPoll;
        p.snapshot.publication = PublicationKnowledge::CommitCallEntered(Empty {});
        r.capture(live).unwrap();
        let e = r.finish(Execution::Cancelled).unwrap();
        validate_envelope(&e, &input, Some(&parsed)).unwrap();
        let Fact::Frame(frame) = &e.facts.0[0].fact else {
            unreachable!()
        };
        assert_eq!(frame.outcome.get(), Some(&FrameOutcome::Completed));
        let Fact::Control(ControlFact::LivePublication(p)) = &e.facts.0[1].fact else {
            unreachable!()
        };
        assert!(matches!(
            p.snapshot.publication,
            PublicationKnowledge::CommitCallEntered(_)
        ));
        assert!(p.snapshot.terminal.get().is_none());
        // Structural preservation only. The separate actual accessor control
        // establishes this combination's runtime origin; it is not run here.
    }

    #[test]
    fn existing_receipt_reassignment_preserves_original_live_publication_anchors() {
        let parsed = decode(&serde_json::to_vec(&replay_queued_auth_case()).unwrap()).unwrap();
        let build = |returned| {
            let mut r = Recorder::new(&parsed);
            r.capture(credential_at(
                300,
                200,
                200,
                1,
                ObservedCredentialKind::Binding,
            ))
            .unwrap();
            r.capture(credential_at(
                301,
                201,
                201,
                30,
                ObservedCredentialKind::UnboundFast,
            ))
            .unwrap();
            r.capture(live_anchor(
                100,
                200,
                300,
                1,
                ObservedCredentialKind::Binding,
            ))
            .unwrap();
            r.capture(live_anchor(
                101,
                201,
                301,
                30,
                ObservedCredentialKind::UnboundFast,
            ))
            .unwrap();
            r.capture(credential_at(
                300,
                200,
                returned,
                1,
                ObservedCredentialKind::Binding,
            ))
            .unwrap();
            r.finish(Execution::Complete).unwrap()
        };
        let original = build(200);
        let changed = build(201);
        assert_eq!(original.identity_map, changed.identity_map);
        assert_eq!(&original.facts.0[..4], &changed.facts.0[..4]);
        let Fact::Credential(c) = &changed.facts.0[4].fact else {
            unreachable!()
        };
        let joins = c.joins.get().unwrap();
        let Fact::Control(ControlFact::LivePublication(a)) = &changed.facts.0[2].fact else {
            unreachable!()
        };
        let Fact::Control(ControlFact::LivePublication(b)) = &changed.facts.0[3].fact else {
            unreachable!()
        };
        assert_eq!(
            joins.constructed_receipt.get(),
            Some(&a.joins.get().unwrap().receipt)
        );
        assert_eq!(
            joins.returned_receipt.get(),
            Some(&b.joins.get().unwrap().receipt)
        );
        assert_ne!(joins.constructed_receipt, joins.returned_receipt);
        assert_ne!(
            encode_frame(&original).unwrap(),
            encode_frame(&changed).unwrap()
        );
    }

    #[test]
    fn existing_control_receipt_swap_preserves_original_live_publication_anchors() {
        let parsed = decode(&serde_json::to_vec(&replay_queued_auth_case()).unwrap()).unwrap();
        let build = |receipt| {
            let mut r = Recorder::new(&parsed);
            r.capture(live_anchor(
                100,
                200,
                300,
                1,
                ObservedCredentialKind::Binding,
            ))
            .unwrap();
            r.capture(live_anchor(
                101,
                201,
                301,
                30,
                ObservedCredentialKind::UnboundFast,
            ))
            .unwrap();
            r.capture(control_holder(None)).unwrap();
            r.capture(control_holder(Some(receipt))).unwrap();
            r.finish(Execution::Complete).unwrap()
        };
        let original = build(200);
        let changed = build(201);
        assert_eq!(original.identity_map, changed.identity_map);
        assert_eq!(&original.facts.0[..3], &changed.facts.0[..3]);
        let Fact::Control(ControlFact::Holder(last)) = &changed.facts.0[3].fact else {
            unreachable!()
        };
        let joins = last.holder.get().unwrap();
        let Fact::Control(ControlFact::LivePublication(a)) = &changed.facts.0[0].fact else {
            unreachable!()
        };
        let Fact::Control(ControlFact::LivePublication(b)) = &changed.facts.0[1].fact else {
            unreachable!()
        };
        assert_eq!(
            joins.introduced.get().unwrap().receipt,
            a.joins.get().unwrap().receipt
        );
        assert_eq!(
            joins.transferred.get().unwrap().receipt,
            b.joins.get().unwrap().receipt
        );
        assert_ne!(
            joins.introduced.get().unwrap().receipt,
            joins.transferred.get().unwrap().receipt
        );
        assert_ne!(
            encode_frame(&original).unwrap(),
            encode_frame(&changed).unwrap()
        );
    }

    #[test]
    fn transferred_receipt_only_swap_retains_historical_publication_receipt() {
        let parsed = decode(&serde_json::to_vec(&replay_queued_auth_case()).unwrap()).unwrap();
        let mut r = Recorder::new(&parsed);
        r.capture(live_anchor(
            100,
            200,
            300,
            1,
            ObservedCredentialKind::Binding,
        ))
        .unwrap();
        r.capture(live_anchor(
            101,
            201,
            301,
            30,
            ObservedCredentialKind::UnboundFast,
        ))
        .unwrap();
        r.capture(control_holder(None)).unwrap();
        let mut second_holder = control_holder(None);
        let Fact::Control(ControlFact::Holder(second)) = &mut second_holder else {
            unreachable!()
        };
        let Nullable::Value(joins) = &mut second.holder else {
            unreachable!()
        };
        let Nullable::Value(introduction) = &mut joins.introduced else {
            unreachable!()
        };
        introduction.control = id(101);
        introduction.frame = Nullable::Value(id(30));
        introduction.receipt = id(201);
        introduction.publication.control = id(101);
        introduction.publication.frame = Nullable::Value(id(30));
        introduction.publication.receipt = id(201);
        introduction.publication.bound_effects = false;
        let Nullable::Value(owner) = &mut introduction.publication.credential else {
            unreachable!()
        };
        owner.attempt = id(301);
        owner.frame = id(30);
        owner.kind = ObservedCredentialKind::UnboundFast;
        r.capture(second_holder).unwrap();
        r.capture(control_holder(Some(200))).unwrap();
        let original = r.finish(Execution::Complete).unwrap();
        let mut changed = original.clone();
        // Receipt 201 already has its own unchanged live publication anchor.
        let Fact::Control(ControlFact::LivePublication(second)) = &original.facts.0[1].fact else {
            unreachable!()
        };
        let introduced_201 = second.joins.get().unwrap().receipt.clone();
        let Fact::Control(ControlFact::Holder(last)) = &mut changed.facts.0[4].fact else {
            unreachable!()
        };
        let Nullable::Value(holder) = &mut last.holder else {
            unreachable!()
        };
        let Nullable::Value(transferred) = &mut holder.transferred else {
            unreachable!()
        };
        let historical_200 = transferred.publication.receipt.clone();
        // The one and only negative edit models the private swap shape. Unlike
        // control_holder(Some(201)), this does not rewrite the nested historical
        // publication association to make the reassignment look consistent.
        transferred.receipt = introduced_201.clone();
        assert_eq!(transferred.publication.receipt, historical_200);
        assert_ne!(transferred.receipt, transferred.publication.receipt);
        assert_eq!(original.identity_map, changed.identity_map);
        assert_eq!(&original.facts.0[..4], &changed.facts.0[..4]);
        validate_envelope(
            &changed,
            &serde_json::to_vec(&replay_queued_auth_case()).unwrap(),
            Some(&parsed),
        )
        .unwrap();
        assert_ne!(
            encode_frame(&original).unwrap(),
            encode_frame(&changed).unwrap()
        );
        // Reverse exactly that field and recover the complete original facts.
        let Fact::Control(ControlFact::Holder(last)) = &mut changed.facts.0[4].fact else {
            unreachable!()
        };
        let Nullable::Value(holder) = &mut last.holder else {
            unreachable!()
        };
        let Nullable::Value(transferred) = &mut holder.transferred else {
            unreachable!()
        };
        transferred.receipt = historical_200;
        assert_eq!(changed, original);
    }

    #[test]
    fn account_call_distinguishes_entry_found_absent_and_error() {
        let mut encodings = BTreeSet::new();
        for returned in [
            "null",
            r#"{"kind":"Found","data":{"id":"00000000-0000-0000-0000-000000000385","username":"actual-name"}}"#,
            r#"{"kind":"Absent","data":{}}"#,
            r#"{"kind":"Error","data":{}}"#,
        ] {
            let raw = format!(
                "{{\"attempt_ordinal\":0,\"username\":\"requested-name\",\"returned\":{returned}}}"
            );
            let call: AccountCall<Id> = serde_json::from_str(&raw).unwrap();
            let encoded = serde_json::to_vec(&call).unwrap();
            assert_eq!(
                serde_json::from_slice::<AccountCall<Id>>(&encoded).unwrap(),
                call
            );
            encodings.insert(encoded);
        }
        assert_eq!(encodings.len(), 4);
        assert!(serde_json::from_str::<AccountCall<Id>>(
            r#"{"attempt_ordinal":0,"username":"requested-name"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<AccountReturned<Id>>(
            r#"{"kind":"Error","data":{"diagnostic":"backend text"}}"#
        )
        .is_err());
    }

    #[test]
    fn privacy_call_distinguishes_entry_true_false_and_error() {
        let mut encodings = BTreeSet::new();
        for returned in [
            "null",
            r#"{"kind":"Outcome","data":{"value":true}}"#,
            r#"{"kind":"Outcome","data":{"value":false}}"#,
            r#"{"kind":"Error","data":{}}"#,
        ] {
            let raw = format!("{{\"attempt_ordinal\":0,\"owner_id\":\"00000000-0000-0000-0000-000000000385\",\"candidate\":\"c@mix.example.test\",\"returned\":{returned}}}");
            let call: PrivacyCall<Id> = serde_json::from_str(&raw).unwrap();
            let encoded = serde_json::to_vec(&call).unwrap();
            assert_eq!(
                serde_json::from_slice::<PrivacyCall<Id>>(&encoded).unwrap(),
                call
            );
            encodings.insert(encoded);
        }
        assert_eq!(encodings.len(), 4);
        assert!(serde_json::from_str::<PrivacyReturned>(
            r#"{"kind":"Outcome","data":{"value":0}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<PrivacyReturned>(
            r#"{"kind":"Error","data":{"diagnostic":"backend text"}}"#
        )
        .is_err());
    }

    #[test]
    fn account_privacy_strings_are_bounded_to_1024_utf8_bytes() {
        let accepted = "x".repeat(1024);
        let rejected = "x".repeat(1025);
        for (value, valid) in [(&accepted, true), (&rejected, false)] {
            let account =
                format!("{{\"attempt_ordinal\":0,\"username\":\"{value}\",\"returned\":null}}");
            let identity = format!(
                "{{\"id\":\"00000000-0000-0000-0000-000000000385\",\"username\":\"{value}\"}}"
            );
            let privacy = format!("{{\"attempt_ordinal\":0,\"owner_id\":\"00000000-0000-0000-0000-000000000385\",\"candidate\":\"{value}\",\"returned\":null}}");
            assert_eq!(
                serde_json::from_str::<AccountCall<Id>>(&account).is_ok(),
                valid
            );
            assert_eq!(
                serde_json::from_str::<AccountIdentity<Id>>(&identity).is_ok(),
                valid
            );
            assert_eq!(
                serde_json::from_str::<PrivacyCall<Id>>(&privacy).is_ok(),
                valid
            );
        }
        assert!(Text::<1024>::new("é".repeat(512)).is_ok());
        assert!(Text::<1024>::new("é".repeat(513)).is_err());
    }

    #[test]
    fn account_return_identity_is_captured_and_reused_as_actual_privacy_argument() {
        let input = serde_json::to_vec(&recovery_case()).unwrap();
        let parsed = decode(&input).unwrap();
        // Actual service-result data type, deliberately different from the
        // supplied account ID/name. This ordinary data control does not run
        // either service or infer a successful account lookup from the input.
        let actual = crate::services::mix::MixAccount {
            id: Uuid::from_u128(901),
            username: "actual-name".to_owned(),
        };
        let requested = "requested-name";
        let candidate = "c@mix.example.test";
        let mut r = Recorder::new(&parsed);
        r.capture(Fact::Worker(WorkerFact::Account(AccountCall {
            attempt_ordinal: 0,
            username: text(requested),
            returned: Nullable::Null(()),
        })))
        .unwrap();
        r.capture(Fact::Worker(WorkerFact::Account(AccountCall {
            attempt_ordinal: 0,
            username: text(requested),
            returned: Nullable::Value(AccountReturned::Found(AccountIdentity {
                id: EvidenceId::observed(actual.id),
                username: text(&actual.username),
            })),
        })))
        .unwrap();
        r.capture(Fact::Worker(WorkerFact::Privacy(PrivacyCall {
            attempt_ordinal: 0,
            owner_id: EvidenceId::observed(actual.id),
            candidate: text(candidate),
            returned: Nullable::Null(()),
        })))
        .unwrap();
        r.capture(Fact::Worker(WorkerFact::Privacy(PrivacyCall {
            attempt_ordinal: 0,
            owner_id: EvidenceId::observed(actual.id),
            candidate: text(candidate),
            returned: Nullable::Value(PrivacyReturned::Outcome(BoolValue { value: false })),
        })))
        .unwrap();
        let e = r.finish(Execution::Complete).unwrap();
        validate_envelope(&e, &input, Some(&parsed)).unwrap();
        let Fact::Worker(WorkerFact::Account(entry)) = &e.facts.0[0].fact else {
            unreachable!()
        };
        assert!(entry.returned.get().is_none());
        let Fact::Worker(WorkerFact::Account(returned)) = &e.facts.0[1].fact else {
            unreachable!()
        };
        let Some(AccountReturned::Found(found)) = returned.returned.get() else {
            unreachable!()
        };
        assert_eq!(returned.username.as_str(), requested);
        assert_eq!(found.username.as_str(), actual.username);
        assert!(is_opaque(&found.id, 1));
        let Fact::Worker(WorkerFact::Privacy(privacy_entry)) = &e.facts.0[2].fact else {
            unreachable!()
        };
        let Fact::Worker(WorkerFact::Privacy(privacy_return)) = &e.facts.0[3].fact else {
            unreachable!()
        };
        assert_eq!(found.id, privacy_entry.owner_id);
        assert_eq!(found.id, privacy_return.owner_id);
        assert!(privacy_entry.returned.get().is_none());
        assert!(matches!(
            privacy_return.returned.get(),
            Some(PrivacyReturned::Outcome(BoolValue { value: false }))
        ));
        assert_eq!(e.identity_map.len(), 1);
        assert_eq!(e.identity_map.0[0].first_seq, 2);
        assert_eq!(
            e.facts.0.iter().map(|f| f.seq).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn bytes_hex_accessor_round_trips_without_repairing_invalid_encoding() {
        let raw = [0, 1, 127, 128, 255];
        let value = Bytes::<5>::of(&raw).unwrap();
        assert_eq!(value.as_hex(), "00017f80ff");
        let decoded: Vec<u8> = value
            .as_hex()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(decoded, raw);
        let round_trip: Bytes<5> =
            serde_json::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(round_trip.as_hex(), value.as_hex());
        assert_eq!(Bytes::<0>::of(&[]).unwrap().as_hex(), "");
        for invalid in ["00017F80ff", "00017f80f", "00017g80ff", "00017f80ff00"] {
            assert!(Bytes::<5>::new(invalid.to_owned()).is_err());
        }
        assert!(Bytes::<4>::of(&raw).is_err());
    }

    #[test]
    fn account_privacy_records_consume_the_existing_case_fact_budget() {
        let mut r = Recorder::new(&input_case());
        for index in 0..MAX_FACTS {
            let fact = if index % 2 == 0 {
                Fact::Worker(WorkerFact::Account(AccountCall {
                    attempt_ordinal: 0,
                    username: text("u"),
                    returned: Nullable::Null(()),
                }))
            } else {
                Fact::Worker(WorkerFact::Privacy(PrivacyCall {
                    attempt_ordinal: 0,
                    owner_id: id(4),
                    candidate: text("c@mix.example.test"),
                    returned: Nullable::Null(()),
                }))
            };
            assert_eq!(r.capture(fact).unwrap(), index as u32 + 1);
        }
        let extra = Fact::Worker(WorkerFact::Account(AccountCall {
            attempt_ordinal: 0,
            username: text("u"),
            returned: Nullable::Value(AccountReturned::Error(Empty {})),
        }));
        assert_eq!(r.capture(extra), Err(Loss::FactOverflow));
        let e = r.finish(Execution::Failed).unwrap();
        assert_eq!(e.facts.len(), MAX_FACTS);
        assert!(matches!(
            e.observation_status,
            ObservationStatus::Lost(LostObservation {
                reason: Loss::FactOverflow,
                after_seq: 256
            })
        ));
    }

    #[test]
    fn parser_accepts_closed_auth_input_without_owner_construction() {
        assert!(decode(&reduced_bytes()).is_ok());
    }

    #[test]
    fn parser_rejects_duplicate_and_unknown_top_level_fields() {
        let input = String::from_utf8(reduced_bytes()).unwrap();
        let duplicate = input.replacen("\"case_id\":", "\"case_id\":\"duplicate\",\"case_id\":", 1);
        assert!(matches!(decode(duplicate.as_bytes()), Err(Rejection::Json)));
        let extra = input.replacen('{', "{\"artifact\":\"mutant\",", 1);
        assert!(matches!(decode(extra.as_bytes()), Err(Rejection::Json)));
    }

    #[test]
    fn parser_rejects_duplicates_inside_required_nullable_objects() {
        assert!(serde_json::from_str::<Nullable<BindingInput>>(
            r#"{"resource":"r","resource":"s","lease_seconds":60,"full_jid":"u@example.test/r"}"#
        )
        .is_err());
    }

    #[test]
    fn parser_requires_named_records_even_under_tagged_sums() {
        assert!(serde_json::from_str::<EpochValue>("[null]").is_err());
        assert!(
            serde_json::from_str::<PublicationReply>(r#"{"kind":"Committed","data":[null]}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<PublicationReply>(r#"["Committed",{"epoch":null}]"#).is_err()
        );
        assert!(serde_json::from_str::<PublicationReply>(
            r#"{"kind":"BackendError","data":{"extra":true}}"#
        )
        .is_err());
    }

    #[test]
    fn parser_rejects_duplicate_tag_and_missing_empty_payload() {
        assert!(serde_json::from_str::<PublicationReply>(
            r#"{"kind":"NoSql","kind":"BackendError","data":{}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<PublicationReply>(r#"{"kind":"BackendError"}"#).is_err());
    }

    #[test]
    fn parser_rejects_object_and_numeric_tags_at_every_depth_and_key_order() {
        for bad in [r#"{"NoSql":null}"#, "0", "true", "null"] {
            for input in [
                format!("{{\"kind\":{bad},\"data\":{{}}}}"),
                format!("{{\"data\":{{}},\"kind\":{bad}}}"),
            ] {
                assert!(serde_json::from_str::<PublicationReply>(&input).is_err());
            }
        }
        // Exercise the actual Content-buffered nested-sum path. Variant index
        // 3 would otherwise select the payload-free ClusterSocketFenced value.
        for data in [
            r#"{"kind":3,"data":{}}"#,
            r#"{"data":{},"kind":3}"#,
            r#"{"kind":{"ClusterSocketFenced":null},"data":{}}"#,
        ] {
            let input = format!("{{\"kind\":\"Transferred\",\"data\":{data}}}");
            assert!(serde_json::from_str::<LocalResult<Id>>(&input).is_err());
        }
        assert!(serde_json::from_str::<LocalResult<Id>>(
            r#"{"kind":"Transferred","data":{"kind":"ClusterSocketFenced","data":{}}}"#
        )
        .is_ok());
        assert!(serde_json::from_str::<ArchiveReturned<Id>>(r#"{"kind":"Outcome","data":{"kind":"Stored","data":{"id":"00000000-0000-0000-0000-000000000001"}}}"#).is_ok());
        assert!(serde_json::from_str::<ArchiveReturned<Id>>(r#"{"kind":"Outcome","data":{"kind":0,"data":{"id":"00000000-0000-0000-0000-000000000001"}}}"#).is_err());
    }

    #[test]
    fn parser_accepts_reordered_sum_fields_without_erasing_duplicates() {
        assert!(
            serde_json::from_str::<PublicationReply>(r#"{"data":{},"kind":"BackendError"}"#)
                .is_ok()
        );
        assert!(serde_json::from_str::<PublicationReply>(
            r#"{"data":{"epoch":1,"epoch":2},"kind":"Committed"}"#
        )
        .is_err());
    }

    #[test]
    fn parser_requires_explicit_nullable_fields() {
        assert!(serde_json::from_str::<EpochValue>(r#"{"epoch":null}"#).is_ok());
        assert!(serde_json::from_str::<EpochValue>("{}").is_err());
    }

    #[test]
    fn parser_accepts_only_string_enum_encoding() {
        assert!(serde_json::from_str::<CommitCut>(r#""Complete""#).is_ok());
        assert!(serde_json::from_str::<CommitCut>(r#"{"Complete":null}"#).is_err());
        assert!(serde_json::from_str::<CommitCut>(r#""Completed""#).is_err());
    }

    #[test]
    fn parser_rejects_noncanonical_uuid_and_hex() {
        for value in [
            "0000000000000000000000000000000abc",
            "00000000-0000-0000-0000-000000000ABC",
            "{00000000-0000-0000-0000-000000000abc}",
        ] {
            assert!(serde_json::from_str::<Id>(&format!("\"{value}\"")).is_err());
        }
        assert!(serde_json::from_str::<Hex<1>>(r#""AF""#).is_err());
        assert!(serde_json::from_str::<Bytes<2>>(r#""abc""#).is_err());
        assert!(serde_json::from_str::<Bytes<2>>(r#""00ff00""#).is_err());
    }

    #[test]
    fn parser_rejects_boolean_float_negative_and_overflow_integer() {
        for n in ["true", "1.0", "-1", "4294967296"] {
            assert!(serde_json::from_str::<CountValue>(&format!("{{\"count\":{n}}}")).is_err());
        }
    }

    #[test]
    fn parser_enforces_string_array_and_input_caps() {
        assert!(serde_json::from_str::<Text<2>>(r#""abc""#).is_err());
        assert!(serde_json::from_str::<List<u8, 2>>("[1,2,3]").is_err());
        assert!(matches!(
            decode(&vec![b' '; MAX_INPUT + 1]),
            Err(Rejection::TooLarge)
        ));
        assert!(matches!(
            read_input(std::io::Cursor::new(vec![b' '; MAX_INPUT + 1])),
            Err(Rejection::TooLarge)
        ));
    }

    #[test]
    fn parser_rejects_trailing_value_and_foreign_contract() {
        let mut bytes = reduced_bytes();
        bytes.extend_from_slice(b" {}");
        assert!(matches!(decode(&bytes), Err(Rejection::Json)));
        let input = String::from_utf8(reduced_bytes())
            .unwrap()
            .replace(CASE_SCHEMA, "northstar-direct-case-v1");
        assert!(matches!(decode(input.as_bytes()), Err(Rejection::Schema)));
    }

    #[test]
    fn relationship_rejection_precedes_owner_work() {
        let mut case: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
        let Composition::BoshAuth(c) = &mut case.composition else {
            unreachable!()
        };
        c.auth.session.connection_id = Id(Uuid::from_u128(6));
        let bytes = serde_json::to_vec(&case).unwrap();
        assert!(matches!(decode(&bytes), Err(Rejection::Relationship)));
        let envelope = Envelope::rejected(&bytes, Rejection::Relationship).unwrap();
        assert!(
            envelope.facts.is_empty()
                && envelope.identity_map.is_empty()
                && envelope.execution.get().is_none()
        );
        validate_envelope(&envelope, &bytes, None).unwrap();
    }

    #[test]
    fn auth_parser_rejects_wrong_namespace_nested_leaf_and_nonzero_frame_ordinal() {
        let parsed = input_case();
        let Composition::BoshAuth(c) = &parsed.case.composition else {
            unreachable!()
        };
        for replacement in [
            "<jid xmlns='wrong'>u@example.test/r</jid>",
            "<jid>u@example.test/r<z:token xmlns:z='secrets'>x</z:token></jid>",
        ] {
            let mut bound = c.auth.bound.clone();
            let ControlInput::Binding(control) = &mut bound.control else {
                unreachable!()
            };
            control.xml.0 = control
                .xml
                .0
                .replace("<jid>u@example.test/r</jid>", replacement);
            assert!(validate_auth(&bound, CredentialKind::Binding, TransportKind::Bosh).is_err());
        }
        let mut bound = c.auth.bound.clone();
        bound.ordinal = 1;
        assert!(validate_auth(&bound, CredentialKind::Binding, TransportKind::Bosh).is_err());
    }

    #[test]
    fn worker_parser_rejects_declared_recipient_route_disagreement() {
        let mut mix = independent_mix();
        mix.worker.attempt.route.targets.0[0].full_jid =
            Text::new("someone-else@example.test/m").unwrap();
        assert!(validate_worker(&mix.worker).is_err());
    }

    #[test]
    fn case_id_does_not_select_behavior_or_artifact() {
        let mut a: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
        let composition = a.composition.clone();
        a.case_id = Text::new("M3-is-only-descriptive").unwrap();
        let b = decode(&serde_json::to_vec(&a).unwrap()).unwrap();
        assert_eq!(b.case.composition, composition);
    }

    #[test]
    fn full_to_reduced_deletes_only_independent_mix_subtree() {
        let mut full: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
        let Composition::BoshAuth(c) = &mut full.composition else {
            unreachable!()
        };
        let auth_bytes = serde_json::to_vec(&c.auth).unwrap();
        c.mix = Nullable::Value(independent_mix());
        let full_bytes = serde_json::to_vec(&full).unwrap();
        assert!(decode(&full_bytes).is_ok());
        let mut reduced = full.clone();
        let Composition::BoshAuth(c) = &mut reduced.composition else {
            unreachable!()
        };
        c.mix = Nullable::Null(());
        assert_eq!(serde_json::to_vec(&c.auth).unwrap(), auth_bytes);
        assert_eq!(full.case_id, reduced.case_id);
        let baseline = serde_json::to_vec(&reduced).unwrap();
        let m2 = baseline.clone();
        let m3 = baseline.clone();
        assert_eq!(baseline, m2);
        assert_eq!(m2, m3);
        assert_eq!(sha256(&baseline), sha256(&m3));
        assert!(decode(&baseline).is_ok());
    }

    #[test]
    fn independent_lanes_reject_connection_session_and_canonical_key_collision() {
        for change in 0..3 {
            let mut case: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
            let Composition::BoshAuth(c) = &mut case.composition else {
                unreachable!()
            };
            let mut mix = independent_mix();
            match change {
                0 => mix.transport.session.connection_id = c.auth.session.connection_id,
                1 => mix.transport.session.session_id = c.auth.session.session_id,
                _ => {
                    mix.worker.attempt.route.targets.0[0].full_jid =
                        c.auth.bound.binding.get().unwrap().full_jid.clone()
                }
            }
            c.mix = Nullable::Value(mix);
            assert!(decode(&serde_json::to_vec(&case).unwrap()).is_err());
        }
    }

    #[test]
    fn fixed_padding_accepts_only_frozen_geometry() {
        let parsed = input_case();
        let Composition::BoshAuth(c) = &parsed.case.composition else {
            unreachable!()
        };
        let b = c.auth.bound.clone();
        let mut u = b.clone();
        u.control = ControlInput::UnboundFast(UnboundControlInput { authorization_identifier: Text::new("u@example.test").unwrap(), xml: Text::new("<success xmlns='urn:xmpp:sasl:2'><authorization-identifier>u@example.test</authorization-identifier></success>").unwrap() });
        let count =
            RESPONSE_BYTES as usize - 256 - auth_xml(&u).len() - P_OPEN.len() - P_CLOSE.len();
        let mut padding = FixedAuthPadding {
            presence_xml: Text::new(format!("{P_OPEN}{}{P_CLOSE}", "x".repeat(count))).unwrap(),
            features_xml: Text::new(FIXED_FEATURES).unwrap(),
        };
        validate_padding(&padding, &u, &b).unwrap();
        padding.presence_xml.0 = padding.presence_xml.0.replacen('x', "y", 1);
        assert!(validate_padding(&padding, &u, &b).is_err());
    }

    #[test]
    fn identity_repeated_across_roles_has_one_label() {
        let mut r = Recorder::new(&input_case());
        r.capture(credential(100, Some(100), Some(100))).unwrap();
        let e = r.finish(Execution::Complete).unwrap();
        let Fact::Credential(c) = &e.facts.0[0].fact else {
            unreachable!()
        };
        let joins = c.joins.get().unwrap();
        assert_eq!(
            c.snapshot.attempt,
            joins.constructed_receipt.get().unwrap().clone()
        );
        assert_eq!(joins.constructed_receipt, joins.returned_receipt);
        assert_eq!(
            e.identity_map
                .0
                .iter()
                .filter(|i| matches!(i.label, IdentityLabel::Opaque(_)))
                .count(),
            1
        );
    }

    #[test]
    fn identity_distinct_raw_values_do_not_collapse() {
        let e = recorded(100, 200);
        let Fact::Credential(c) = &e.facts.0[0].fact else {
            unreachable!()
        };
        assert!(is_opaque(&c.snapshot.attempt, 1));
        assert!(is_opaque(
            c.joins.get().unwrap().constructed_receipt.get().unwrap(),
            2
        ));
    }

    #[test]
    fn identity_fixed_generated_collision_remains_actual_equality() {
        let e = recorded(1, 200);
        let Fact::Credential(c) = &e.facts.0[0].fact else {
            unreachable!()
        };
        assert_eq!(c.snapshot.attempt, c.snapshot.frame);
        assert!(matches!(
            c.snapshot.attempt,
            EvidenceId::Encoded(IdentityLabel::Fixed(_))
        ));
    }

    #[test]
    fn identity_global_opaque_renaming_is_canonical_equivalence() {
        assert_eq!(
            encode_frame(&recorded(100, 200)).unwrap(),
            encode_frame(&recorded(101, 201)).unwrap()
        );
    }

    #[test]
    fn deleting_independent_mix_can_shift_opaque_ordinals_but_retains_auth_anchors() {
        let mut full: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
        let Composition::BoshAuth(c) = &mut full.composition else {
            unreachable!()
        };
        c.mix = Nullable::Value(independent_mix());
        let full = decode(&serde_json::to_vec(&full).unwrap()).unwrap();
        let mut recorder = Recorder::new(&full);
        recorder
            .capture(Fact::Worker(WorkerFact::Archive(ArchiveCall {
                attempt_ordinal: 0,
                command: ArchiveCommand {
                    personal_archive_id: id(999),
                    owner_id: id(4),
                    channel_jid: Text::new("c@mix.example.test").unwrap(),
                    authoritative_stanza_id: id(9),
                    stanza: Text::new("<message/>").unwrap(),
                    encrypted: false,
                    client_stanza_id: Nullable::Null(()),
                },
                returned: Nullable::Null(()),
            })))
            .unwrap();
        recorder.capture(credential(100, Some(200), None)).unwrap();
        let full = recorder.finish(Execution::Complete).unwrap();
        let reduced = recorded(100, 200);
        let Fact::Credential(a) = &full.facts.0[1].fact else {
            unreachable!()
        };
        let Fact::Credential(b) = &reduced.facts.0[0].fact else {
            unreachable!()
        };
        assert_eq!(a.snapshot.frame, b.snapshot.frame);
        assert_eq!(a.snapshot.connection, b.snapshot.connection);
        assert!(is_opaque(&a.snapshot.attempt, 2));
        assert!(is_opaque(&b.snapshot.attempt, 1));
        assert_eq!(full.facts.0[1].seq, 2);
        assert_eq!(reduced.facts.0[0].seq, 1);
        // The independent shrink reader must compare anchored retained graphs,
        // never demand identical first-seen numbers across these different inputs.
    }

    #[test]
    fn identity_post_introduction_receipt_reassignment_stays_visible() {
        let c = input_case();
        let mut r = Recorder::new(&c);
        r.capture(credential(100, Some(200), None)).unwrap();
        r.capture(credential(100, Some(200), Some(201))).unwrap();
        let changed = r.finish(Execution::Complete).unwrap();
        let Fact::Credential(last) = &changed.facts.0[1].fact else {
            unreachable!()
        };
        let joins = last.joins.get().unwrap();
        assert_ne!(joins.constructed_receipt, joins.returned_receipt);
        assert!(is_opaque(joins.returned_receipt.get().unwrap(), 3));
        assert_ne!(
            encode_frame(&changed).unwrap(),
            encode_frame(&recorded(100, 200)).unwrap()
        );
        // This slice preserves the violating graph. The separate independent
        // semantic oracle, not this encoder, must reject the actual bad join.
    }

    #[test]
    fn identity_post_introduction_control_association_reassignment_stays_visible() {
        let mut original = Recorder::new(&input_case());
        original.capture(control_holder(None)).unwrap();
        original.capture(control_holder(Some(200))).unwrap();
        let mut changed = Recorder::new(&input_case());
        changed.capture(control_holder(None)).unwrap();
        changed.capture(control_holder(Some(201))).unwrap();
        let e = changed.finish(Execution::Complete).unwrap();
        let Fact::Control(ControlFact::Holder(last)) = &e.facts.0[1].fact else {
            unreachable!()
        };
        let holder = last.holder.get().unwrap();
        assert_ne!(
            holder.introduced.get().unwrap().receipt,
            holder.transferred.get().unwrap().receipt
        );
        assert_eq!(
            holder.introduced.get().unwrap().control,
            holder.transferred.get().unwrap().control
        );
        assert_ne!(
            encode_frame(&e).unwrap(),
            encode_frame(&original.finish(Execution::Complete).unwrap()).unwrap()
        );
    }

    #[test]
    fn identity_missing_receipt_is_not_synthesized_or_reserved() {
        let mut r = Recorder::new(&input_case());
        r.capture(credential(100, None, None)).unwrap();
        let e = r.finish(Execution::Complete).unwrap();
        let Fact::Credential(c) = &e.facts.0[0].fact else {
            unreachable!()
        };
        assert!(c.joins.get().unwrap().constructed_receipt.get().is_none());
        assert_eq!(
            e.identity_map
                .0
                .iter()
                .filter(|i| matches!(i.label, IdentityLabel::Opaque(_)))
                .count(),
            1
        );
    }

    #[test]
    fn identity_overflow_keeps_contiguous_prefix_and_explicit_loss() {
        let mut r = Recorder::new(&input_case());
        for n in 0..8 {
            r.capture(credential(100 + n, Some(200 + n), None)).unwrap();
        }
        assert_eq!(
            r.capture(credential(108, Some(208), None)),
            Err(Loss::OpaqueOverflow)
        );
        let e = r.finish(Execution::Failed).unwrap();
        assert_eq!(e.facts.len(), 8);
        assert!(matches!(
            e.observation_status,
            ObservationStatus::Lost(LostObservation {
                reason: Loss::OpaqueOverflow,
                after_seq: 8
            })
        ));
        assert_eq!(
            e.identity_map
                .0
                .iter()
                .filter(|i| matches!(i.label, IdentityLabel::Opaque(_)))
                .count(),
            MAX_OPAQUE
        );
    }

    #[test]
    fn identity_total_cap_includes_unused_fixed_anchors() {
        let mut m = IdentityMap::default();
        for n in 1..=64 {
            m.anchor(Uuid::from_u128(n), Introduction::UnexpectedObservedIdentity)
                .unwrap();
        }
        assert_eq!(
            m.observe(Uuid::from_u128(65), 1, Introduction::CredentialAttempt),
            Err(Loss::IdentityOverflow)
        );
        assert!(matches!(
            m.observe(Uuid::from_u128(1), 1, Introduction::CredentialAttempt),
            Ok(IdentityLabel::Fixed(_))
        ));
    }

    #[test]
    fn raw_generated_uuid_cannot_escape_without_capture() {
        assert!(serde_json::to_vec(&credential(100, Some(200), None)).is_err());
    }

    #[test]
    fn sequence_fact_poll_and_snapshot_bounds_are_explicit() {
        let mut sequence = Sequence::default();
        for n in 1..=MAX_FACTS {
            assert_eq!(sequence.available(false).unwrap(), n as u32);
            sequence.committed(false);
        }
        assert_eq!(sequence.available(false), Err(Loss::FactOverflow));
        let mut r = Recorder::new(&input_case());
        for _ in 0..MAX_POLLS {
            r.polled(DriverOwner::Publication, 0, &std::task::Poll::<()>::Pending)
                .unwrap();
        }
        assert_eq!(
            r.polled(DriverOwner::Publication, 0, &std::task::Poll::Ready(())),
            Err(Loss::PollOverflow)
        );
        let mut r = Recorder::new(&input_case());
        for _ in 0..MAX_OWNER_SNAPSHOTS {
            r.capture(credential(100, Some(200), None)).unwrap();
        }
        assert_eq!(
            r.capture(credential(100, Some(200), None)),
            Err(Loss::OwnerSnapshotOverflow)
        );
    }

    #[test]
    fn framing_round_trip_preserves_full_canonical_envelope() {
        let input = reduced_bytes();
        let c = decode(&input).unwrap();
        let e = recorded(100, 200);
        let bytes = encode_frame(&e).unwrap();
        let reread = decode_frame(&bytes).unwrap();
        validate_envelope(&reread, &input, Some(&c)).unwrap();
        assert_eq!(encode_frame(&reread).unwrap(), bytes);
    }

    #[test]
    fn framing_rejects_foreign_tag_length_trailing_and_oversize() {
        let frame = encode_frame(&recorded(100, 200)).unwrap();
        let foreign = String::from_utf8(frame.clone())
            .unwrap()
            .replace(FRAME_TAG, "NORTHSTAR_DIRECT_CASE_V1");
        assert!(decode_frame(foreign.as_bytes()).is_err());
        let mut trailing = frame.clone();
        trailing.extend_from_slice(b"x");
        assert!(decode_frame(&trailing).is_err());
        let mut truncated = frame;
        truncated.pop();
        assert!(decode_frame(&truncated).is_err());
        assert!(matches!(
            decode_frame(&vec![0; MAX_FRAME + 1]),
            Err(Rejection::TooLarge)
        ));
    }

    #[test]
    fn framing_rejects_noncanonical_json_even_with_correct_length() {
        let e = recorded(100, 200);
        let payload = String::from_utf8(serde_json::to_vec(&e).unwrap())
            .unwrap()
            .replacen("\"schema\":", "\"schema\" :", 1);
        let frame = format!("\x1e{FRAME_TAG} {}\n{payload}\n\x1eEND\n", payload.len());
        assert!(matches!(
            decode_frame(frame.as_bytes()),
            Err(Rejection::Encoding)
        ));
    }

    #[test]
    fn graph_reader_rejects_duplicate_sequence_or_forged_first_seen_locus() {
        let c = input_case();
        let input = reduced_bytes();
        let mut e = recorded(100, 200);
        e.facts.0[1].seq = 1;
        assert_eq!(
            validate_envelope(&e, &input, Some(&c)),
            Err(Loss::NoncontiguousSequence)
        );
        let mut e = recorded(100, 200);
        e.identity_map.0[0].locus = Introduction::ArchiveCandidate;
        assert_eq!(
            validate_envelope(&e, &input, Some(&c)),
            Err(Loss::NoncanonicalIdentity)
        );
    }

    #[test]
    fn graph_reader_mirrors_per_item_io_bounds() {
        let input = reduced_bytes();
        let c = decode(&input).unwrap();
        let mut r = Recorder::new(&c);
        r.capture(Fact::Native(NativeFact::Flush(FlushCall {
            item_ordinal: 0,
            result: IoResult::Ok,
        })))
        .unwrap();
        let mut e = r.finish(Execution::Complete).unwrap();
        let mut duplicate = e.facts.0[0].clone();
        duplicate.seq = 2;
        e.facts.0.push(duplicate);
        assert_eq!(
            validate_envelope(&e, &input, Some(&c)),
            Err(Loss::FactOverflow)
        );
        let mut r = Recorder::new(&c);
        for _ in 0..32 {
            r.capture(Fact::Native(NativeFact::Write(WriteCall {
                item_ordinal: 0,
                offered_len: 1,
                offered_sha256: sha256(b"x"),
                accepted_bytes_hex: Bytes::of(b"x").unwrap(),
                result: IoResult::Ok,
            })))
            .unwrap();
        }
        let mut e = r.finish(Execution::Complete).unwrap();
        let mut extra = e.facts.0[0].clone();
        extra.seq = 33;
        e.facts.0.push(extra);
        assert_eq!(
            validate_envelope(&e, &input, Some(&c)),
            Err(Loss::FactOverflow)
        );
    }

    #[test]
    fn graph_reader_rejects_unanchored_fixed_and_noncanonical_opaque_labels() {
        let c = input_case();
        let input = reduced_bytes();
        for replacement in [
            IdentityLabel::Fixed(FixedIdentity {
                uuid: Id(Uuid::from_u128(999)),
            }),
            IdentityLabel::Opaque(OpaqueIdentity { ordinal: 9 }),
        ] {
            let mut e = recorded(100, 200);
            let Fact::Credential(first) = &mut e.facts.0[0].fact else {
                unreachable!()
            };
            first.snapshot.attempt = EvidenceId::Encoded(replacement);
            assert_eq!(
                validate_envelope(&e, &input, Some(&c)),
                Err(Loss::NoncanonicalIdentity)
            );
        }
    }

    #[test]
    fn selected_complete_is_independent_of_missing_live_publication() {
        let selected: SelectionStatus =
            serde_json::from_str(r#"{"kind":"Complete","data":{}}"#).unwrap();
        let not_started: PublicationKnowledge =
            serde_json::from_str(r#"{"kind":"NotStarted","data":{}}"#).unwrap();
        assert!(matches!(selected, SelectionStatus::Complete(_)));
        assert!(matches!(not_started, PublicationKnowledge::NotStarted(_)));
        // They are deliberately different types. No conversion to a domain
        // completion decision exists, and missing joins remain representable.
        assert!(
            serde_json::from_str::<PublicationKnowledge>(r#"{"kind":"Complete","data":{}}"#)
                .is_err()
        );
    }

    #[test]
    fn frame_cap_includes_actual_encoded_observations_without_truncation() {
        let mut r = Recorder::new(&input_case());
        for n in 0..4 {
            r.capture(Fact::Bosh(BoshFact::Receiver(BoshResponseReceiver {
                session: id(3),
                connection: Nullable::Value(id(2)),
                owner_ordinal: 0,
                rid: 22,
                receiver_ordinal: n,
                result: ResponseResult::Received(BodyBytes {
                    body_hex: Bytes::of(&vec![b'x'; 16384]).unwrap(),
                }),
            })))
            .unwrap();
        }
        let e = r.finish(Execution::Complete).unwrap();
        assert_eq!(encode_frame(&e), Err(Loss::FrameOverflow));
        assert_eq!(e.facts.len(), 4);
    }

    #[test]
    fn replay_canonical_semantics_accepts_exact_nul_and_non_utf8_bytes() {
        let mut case = replay_queued_auth_case();
        let Composition::ReplayMixQueuedAuth(c) = &mut case.composition else {
            unreachable!()
        };
        let bytes = [
            0, 0, 0, 0, 0, 0, 0, 7, b'm', b'e', b's', b's', b'a', b'g', b'e', 0x80, 0xff,
        ];
        c.mix.foreground.ingress.identity = Nullable::Value(ReplayIdentityInput {
            client_id: text("binary-replay"),
            canonical_semantics: Bytes::of(&bytes).unwrap(),
        });
        let raw = serde_json::to_vec(&case).unwrap();
        let decoded = decode(&raw).unwrap();
        assert_eq!(decoded.case(), &case);
        let Composition::ReplayMixQueuedAuth(c) = &decoded.case().composition else {
            unreachable!()
        };
        assert_eq!(
            c.mix
                .foreground
                .ingress
                .identity
                .get()
                .unwrap()
                .canonical_semantics
                .as_hex(),
            "00000000000000076d65737361676580ff"
        );
        assert_eq!(
            Bytes::<4096>::of(&vec![0; 4096]).unwrap().as_hex().len(),
            8192
        );
    }

    #[test]
    fn replay_canonical_semantics_rejects_malformed_hex_without_repair() {
        let baseline = serde_json::to_value(replay_queued_auth_case()).unwrap();
        let pointer = "/composition/data/mix/foreground/ingress/identity/canonical_semantics";
        assert!(baseline.pointer(pointer).unwrap().is_string());
        for invalid in [
            "0".to_owned(),
            "AF".to_owned(),
            "0g".to_owned(),
            "00 ".to_owned(),
            "\0".to_owned(),
            "00".repeat(4097),
        ] {
            let mut changed = baseline.clone();
            *changed.pointer_mut(pointer).unwrap() = serde_json::Value::String(invalid);
            assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        assert!(decode(&serde_json::to_vec(&baseline).unwrap()).is_ok());
    }
}

// ---- Finite test-only composition dispatcher ----
// The closed schema and its separate driver retain bounded data and polling.
// Each recipe composes actual owners over finite supplied replies.
// This extension is not an oracle or fixture matcher.
// Process-level execution uses the separate bounded ignored entry below.
mod saved_dispatcher {
    use super::*;
    use crate::bosh::stage4_saved as bosh;
    use crate::outbound::{OutboundItem, RouteEnqueue};
    use crate::xmpp::auth_publication::stage4_saved as auth;
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
