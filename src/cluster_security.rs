//! Application-layer authentication for the experimental Redis cluster bus.
//!
//! Redis TLS protects a connection to Redis; it does not authenticate the
//! process which authored a Pub/Sub value.  This module therefore signs an
//! exact, short-lived envelope for every node command and acknowledgement.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};
use zeroize::Zeroizing;

pub const SIGNED_PROTOCOL_VERSION: u16 = 8;
const ENVELOPE_LIFETIME_SECONDS: i64 = 10;
pub(crate) const CLOCK_SKEW_SECONDS: i64 = 5;
const MAX_PEERS: usize = 128;
const MAX_ALLOWED_KINDS: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClusterFailurePolicy {
    FailClosed,
    DurableDirectOnly,
}

impl ClusterFailurePolicy {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "fail_closed" => Ok(Self::FailClosed),
            "durable_direct_only" => Ok(Self::DurableDirectOnly),
            _ => anyhow::bail!("CLUSTER_FAILURE_POLICY must be fail_closed or durable_direct_only"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterCommandKind {
    Ack,
    DirectDelivery,
    BlockingPresence,
    PresenceProbe,
    SessionTeardown,
    AccountGenerationTeardown,
    UserAgentReplacement,
    SmSessionTeardown,
    SmMucTeardown,
    MucBroadcast,
    MucPrivate,
    MucPresence,
    MucNicknameChange,
    MucRoleChange,
    MucEvict,
    MucDestroy,
    /// Authenticated hint that a node should pull an immutable MUC operation
    /// and its audience-specific deliveries from PostgreSQL.  The wire value
    /// never contains an executable room mutation.
    MucOperationWake,
}

#[derive(Clone)]
pub struct ClusterSecurityConfig {
    pub node_id: String,
    pub key_epoch: i64,
    pub current_key_id: String,
    pub current_public_key_sha256: String,
    pub previous_key_id: Option<String>,
    pub previous_public_key_sha256: Option<String>,
    pub staged_next_key_id: Option<String>,
    pub staged_next_public_key_sha256: Option<String>,
    pub failure_policy: ClusterFailurePolicy,
    pub safety_lease_seconds: u64,
    signer: Arc<ClusterSigner>,
    peers: Arc<HashMap<String, PeerVerifier>>,
}

impl ClusterSecurityConfig {
    pub fn signer(&self) -> Arc<ClusterSigner> {
        Arc::clone(&self.signer)
    }

    pub fn peers(&self) -> Arc<HashMap<String, PeerVerifier>> {
        Arc::clone(&self.peers)
    }

    pub fn peer_node_ids(&self) -> Vec<String> {
        let mut nodes = self.peers.keys().cloned().collect::<Vec<_>>();
        nodes.sort();
        nodes
    }

    pub fn peer_key_authorities(&self) -> Vec<crate::db::ExpectedClusterPeerKey> {
        let mut peers = self
            .peers
            .values()
            .map(|peer| crate::db::ExpectedClusterPeerKey {
                node_id: peer.node_id.clone(),
                epoch: peer.key_epoch,
                current_key_id: peer.current.key_id.clone(),
                current_public_key_sha256: public_key_digest(&peer.current.public_key),
                previous_key_id: peer.previous.as_ref().map(|key| key.key_id.clone()),
                previous_public_key_sha256: peer
                    .previous
                    .as_ref()
                    .map(|key| public_key_digest(&key.public_key)),
                staged_next_key_id: peer.staged_next.as_ref().map(|key| key.key_id.clone()),
                staged_next_public_key_sha256: peer
                    .staged_next
                    .as_ref()
                    .map(|key| public_key_digest(&key.public_key)),
            })
            .collect::<Vec<_>>();
        peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        peers
    }
}

pub struct ClusterSigner {
    pkcs8: Zeroizing<Vec<u8>>,
    pub key_id: String,
    pub key_epoch: i64,
}

impl ClusterSigner {
    fn sign(&self, bytes: &[u8]) -> Result<String> {
        let pair = Ed25519KeyPair::from_pkcs8(self.pkcs8.as_slice())
            .map_err(|_| anyhow::anyhow!("cluster Ed25519 private key is invalid"))?;
        Ok(URL_SAFE_NO_PAD.encode(pair.sign(bytes).as_ref()))
    }
}

#[derive(Clone)]
pub struct PeerVerifier {
    pub node_id: String,
    pub key_epoch: i64,
    current: VerificationKey,
    previous: Option<VerificationKey>,
    staged_next: Option<VerificationKey>,
    allowed_kinds: HashSet<ClusterCommandKind>,
}

#[derive(Clone)]
struct VerificationKey {
    key_id: String,
    public_key: [u8; 32],
}

impl PeerVerifier {
    fn key(&self, key_id: &str, epoch: i64) -> Option<&[u8; 32]> {
        if epoch == self.key_epoch && self.current.key_id == key_id {
            return Some(&self.current.public_key);
        }
        if let Some(key) = self
            .staged_next
            .as_ref()
            .filter(|key| epoch == self.key_epoch.saturating_add(1) && key.key_id == key_id)
        {
            // This is cryptographic verification only. ClusterManager must
            // subsequently require PostgreSQL current/previous key authority
            // and an exact process-instance lease, so a prepared key cannot
            // execute a command before activation.
            return Some(&key.public_key);
        }
        self.previous
            .as_ref()
            .filter(|key| self.key_epoch > 1 && epoch == self.key_epoch - 1 && key.key_id == key_id)
            .map(|key| &key.public_key)
    }

    fn permits(&self, kind: ClusterCommandKind) -> bool {
        self.allowed_kinds.contains(&kind)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerDocument {
    namespace: String,
    nodes: Vec<PeerEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerEntry {
    node_id: String,
    key_epoch: i64,
    current_public_key: String,
    #[serde(default)]
    previous_public_key: Option<String>,
    #[serde(default)]
    staged_next_public_key: Option<String>,
    allowed_kinds: Vec<ClusterCommandKind>,
}

pub struct ClusterSecurityConfiguration<'a> {
    pub namespace: &'a str,
    pub node_id: Option<&'a str>,
    pub private_key_file: Option<&'a Path>,
    pub previous_public_key_file: Option<&'a Path>,
    pub staged_next_public_key_file: Option<&'a Path>,
    pub peer_keys_file: Option<&'a Path>,
    pub key_epoch: i64,
    pub failure_policy: &'a str,
    pub safety_lease_seconds: u64,
}

pub fn load_configuration(
    configuration: ClusterSecurityConfiguration<'_>,
) -> Result<ClusterSecurityConfig> {
    let ClusterSecurityConfiguration {
        namespace,
        node_id,
        private_key_file,
        previous_public_key_file,
        staged_next_public_key_file,
        peer_keys_file,
        key_epoch,
        failure_policy,
        safety_lease_seconds,
    } = configuration;
    let node_id = node_id.context("REDIS_URL requires CLUSTER_NODE_ID")?;
    validate_node_id(node_id)?;
    anyhow::ensure!(
        key_epoch >= 1,
        "CLUSTER_SIGNING_KEY_EPOCH must be at least 1"
    );
    anyhow::ensure!(
        (90..=3_600).contains(&safety_lease_seconds),
        "CLUSTER_SAFETY_LEASE_SECONDS must be between 90 and 3600"
    );
    let failure_policy = ClusterFailurePolicy::parse(failure_policy)?;
    let private_key_file =
        private_key_file.context("REDIS_URL requires CLUSTER_SIGNING_PRIVATE_KEY_FILE")?;
    let peer_keys_file = peer_keys_file.context("REDIS_URL requires CLUSTER_PEER_KEYS_FILE")?;

    // The secret-file helper returns an owned String.  Wrap it before doing
    // any fallible decode/parse work so every error path wipes the base64
    // private key rather than leaving a second ordinary heap allocation.
    let encoded = Zeroizing::new(crate::config::read_secret_file(
        private_key_file,
        "CLUSTER_SIGNING_PRIVATE_KEY_FILE",
    )?);
    let mut decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .context("CLUSTER_SIGNING_PRIVATE_KEY_FILE must contain base64url PKCS#8")?,
    );
    let pair = Ed25519KeyPair::from_pkcs8(decoded.as_slice())
        .map_err(|_| anyhow::anyhow!("CLUSTER_SIGNING_PRIVATE_KEY_FILE is not Ed25519 PKCS#8"))?;
    let public_key: [u8; 32] = pair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| anyhow::anyhow!("cluster Ed25519 public key has an invalid length"))?;
    let current_key_id = key_id(&public_key);
    let current_public_key_sha256 = public_key_digest(&public_key);
    let previous_public = previous_public_key_file
        .map(|path| read_public_key(path, "CLUSTER_SIGNING_PREVIOUS_PUBLIC_KEY_FILE"))
        .transpose()?;
    let previous_key_id = previous_public.as_ref().map(key_id);
    let previous_public_key_sha256 = previous_public.as_ref().map(public_key_digest);
    anyhow::ensure!(
        previous_key_id.as_ref() != Some(&current_key_id),
        "cluster previous signing key must differ from the current key"
    );
    let staged_next_public = staged_next_public_key_file
        .map(|path| read_public_key(path, "CLUSTER_SIGNING_STAGED_NEXT_PUBLIC_KEY_FILE"))
        .transpose()?;
    let staged_next_key_id = staged_next_public.as_ref().map(key_id);
    let staged_next_public_key_sha256 = staged_next_public.as_ref().map(public_key_digest);
    anyhow::ensure!(
        staged_next_key_id.as_ref() != Some(&current_key_id)
            && staged_next_key_id != previous_key_id,
        "cluster staged-next key must differ from current and previous keys"
    );

    let peers = load_peers(peer_keys_file, namespace, node_id)?;
    let signer = Arc::new(ClusterSigner {
        pkcs8: std::mem::take(&mut decoded),
        key_id: current_key_id.clone(),
        key_epoch,
    });
    Ok(ClusterSecurityConfig {
        node_id: node_id.to_owned(),
        key_epoch,
        current_key_id,
        current_public_key_sha256,
        previous_key_id,
        previous_public_key_sha256,
        staged_next_key_id,
        staged_next_public_key_sha256,
        failure_policy,
        safety_lease_seconds,
        signer,
        peers: Arc::new(peers),
    })
}

fn load_peers(
    path: &Path,
    namespace: &str,
    local_node: &str,
) -> Result<HashMap<String, PeerVerifier>> {
    let metadata =
        std::fs::symlink_metadata(path).context("cannot inspect CLUSTER_PEER_KEYS_FILE")?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 1024 * 1024,
        "CLUSTER_PEER_KEYS_FILE must be a non-symlink regular file no larger than 1 MiB"
    );
    let raw = std::fs::read_to_string(path).context("cannot read CLUSTER_PEER_KEYS_FILE")?;
    let document: PeerDocument =
        serde_json::from_str(&raw).context("CLUSTER_PEER_KEYS_FILE is invalid JSON")?;
    anyhow::ensure!(
        document.namespace == namespace,
        "CLUSTER_PEER_KEYS_FILE namespace does not match XMPP_DOMAIN"
    );
    anyhow::ensure!(
        !document.nodes.is_empty() && document.nodes.len() <= MAX_PEERS,
        "CLUSTER_PEER_KEYS_FILE must contain 1..={MAX_PEERS} nodes"
    );
    let mut peers = HashMap::with_capacity(document.nodes.len());
    for entry in document.nodes {
        validate_node_id(&entry.node_id)?;
        anyhow::ensure!(
            entry.node_id != local_node,
            "peer allowlist must not contain the local node"
        );
        anyhow::ensure!(entry.key_epoch >= 1, "peer key_epoch must be at least 1");
        anyhow::ensure!(
            !entry.allowed_kinds.is_empty() && entry.allowed_kinds.len() <= MAX_ALLOWED_KINDS,
            "every cluster peer needs a bounded, non-empty allowed_kinds ACL"
        );
        let allowed_kinds = entry.allowed_kinds.into_iter().collect::<HashSet<_>>();
        let current_public_key = decode_public_key(&entry.current_public_key)
            .context("peer current_public_key is invalid")?;
        let current = VerificationKey {
            key_id: key_id(&current_public_key),
            public_key: current_public_key,
        };
        let previous = entry
            .previous_public_key
            .as_deref()
            .map(decode_public_key)
            .transpose()
            .context("peer previous_public_key is invalid")?
            .map(|public_key| VerificationKey {
                key_id: key_id(&public_key),
                public_key,
            });
        let staged_next = entry
            .staged_next_public_key
            .as_deref()
            .map(decode_public_key)
            .transpose()
            .context("peer staged_next_public_key is invalid")?
            .map(|public_key| VerificationKey {
                key_id: key_id(&public_key),
                public_key,
            });
        anyhow::ensure!(
            previous
                .as_ref()
                .is_none_or(|key| key.key_id != current.key_id),
            "peer previous key must differ from its current key"
        );
        anyhow::ensure!(
            staged_next.as_ref().is_none_or(|key| {
                key.key_id != current.key_id
                    && previous.as_ref().is_none_or(|old| old.key_id != key.key_id)
            }),
            "peer staged-next key must differ from current and previous keys"
        );
        let node_id = entry.node_id.clone();
        anyhow::ensure!(
            peers
                .insert(
                    node_id.clone(),
                    PeerVerifier {
                        node_id,
                        key_epoch: entry.key_epoch,
                        current,
                        previous,
                        staged_next,
                        allowed_kinds,
                    },
                )
                .is_none(),
            "CLUSTER_PEER_KEYS_FILE contains a duplicate node_id"
        );
    }
    Ok(peers)
}

fn read_public_key(path: &Path, variable: &str) -> Result<[u8; 32]> {
    let value = crate::config::read_secret_file(path, variable)?;
    decode_public_key(value.trim())
}

fn decode_public_key(value: &str) -> Result<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .context("Ed25519 public key must be unpadded base64url")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must contain exactly 32 bytes"))
}

fn validate_node_id(node_id: &str) -> Result<()> {
    anyhow::ensure!(
        (1..=128).contains(&node_id.len())
            && node_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "cluster node IDs must contain 1..=128 ASCII letters, digits, '.', '_' or '-'"
    );
    Ok(())
}

fn key_id(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(&Sha256::digest(public_key)[..12])
}

fn public_key_digest(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedClusterEnvelope {
    pub version: u16,
    pub namespace: String,
    pub source_node: String,
    pub destination_node: String,
    pub destination_connection_uuid: uuid::Uuid,
    pub destination_connection_epoch: i64,
    pub destination_key_id: String,
    pub destination_key_epoch: i64,
    pub channel: String,
    pub kind: ClusterCommandKind,
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub payload_sha256: String,
    pub key_id: String,
    pub key_epoch: i64,
    pub connection_uuid: uuid::Uuid,
    pub connection_epoch: i64,
    pub payload: Value,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedEnvelope<'a> {
    version: u16,
    namespace: &'a str,
    source_node: &'a str,
    destination_node: &'a str,
    destination_connection_uuid: uuid::Uuid,
    destination_connection_epoch: i64,
    destination_key_id: &'a str,
    destination_key_epoch: i64,
    channel: &'a str,
    kind: ClusterCommandKind,
    event_id: &'a str,
    request_id: Option<&'a str>,
    issued_at: i64,
    expires_at: i64,
    payload_sha256: &'a str,
    key_id: &'a str,
    key_epoch: i64,
    connection_uuid: uuid::Uuid,
    connection_epoch: i64,
    payload: &'a Value,
}

impl SignedClusterEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        signer: &ClusterSigner,
        namespace: &str,
        source_node: &str,
        destination_node: &str,
        destination_connection_uuid: uuid::Uuid,
        destination_connection_epoch: i64,
        destination_key_id: &str,
        destination_key_epoch: i64,
        channel: &str,
        kind: ClusterCommandKind,
        connection_uuid: uuid::Uuid,
        connection_epoch: i64,
        payload: Value,
        now: i64,
    ) -> Result<Self> {
        validate_node_id(source_node)?;
        validate_node_id(destination_node)?;
        anyhow::ensure!(
            !destination_connection_uuid.is_nil()
                && destination_connection_epoch >= 1
                && !destination_key_id.is_empty()
                && destination_key_epoch >= 1,
            "cluster destination process identity is invalid"
        );
        let request_id = payload
            .get("request_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(id) = request_id.as_deref() {
            anyhow::ensure!(
                uuid::Uuid::parse_str(id).is_ok(),
                "cluster request_id is invalid"
            );
        }
        let event_id = request_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let payload_sha256 = payload_digest(&payload)?;
        let mut envelope = Self {
            version: SIGNED_PROTOCOL_VERSION,
            namespace: namespace.to_owned(),
            source_node: source_node.to_owned(),
            destination_node: destination_node.to_owned(),
            destination_connection_uuid,
            destination_connection_epoch,
            destination_key_id: destination_key_id.to_owned(),
            destination_key_epoch,
            channel: channel.to_owned(),
            kind,
            event_id,
            request_id,
            issued_at: now,
            expires_at: now.saturating_add(ENVELOPE_LIFETIME_SECONDS),
            payload_sha256,
            key_id: signer.key_id.clone(),
            key_epoch: signer.key_epoch,
            connection_uuid,
            connection_epoch,
            payload,
            signature: String::new(),
        };
        envelope.signature = signer.sign(&envelope.signing_bytes()?)?;
        Ok(envelope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        namespace: &str,
        destination_node: &str,
        channel: &str,
        expected_source: Option<&str>,
        peers: &HashMap<String, PeerVerifier>,
        now: i64,
    ) -> Result<()> {
        anyhow::ensure!(
            self.version == SIGNED_PROTOCOL_VERSION,
            "unsupported signed cluster protocol version"
        );
        anyhow::ensure!(self.namespace == namespace, "cluster namespace mismatch");
        anyhow::ensure!(
            self.destination_node == destination_node,
            "cluster destination mismatch"
        );
        anyhow::ensure!(self.channel == channel, "cluster channel mismatch");
        if let Some(expected_source) = expected_source {
            anyhow::ensure!(
                self.source_node == expected_source,
                "cluster source mismatch"
            );
        }
        anyhow::ensure!(
            self.expires_at > self.issued_at
                && self.expires_at.saturating_sub(self.issued_at) <= ENVELOPE_LIFETIME_SECONDS
                && self.issued_at <= now.saturating_add(CLOCK_SKEW_SECONDS)
                && self.expires_at >= now.saturating_sub(CLOCK_SKEW_SECONDS),
            "cluster envelope is outside its validity window"
        );
        anyhow::ensure!(
            uuid::Uuid::parse_str(&self.event_id).is_ok(),
            "cluster event ID is invalid"
        );
        anyhow::ensure!(
            !self.connection_uuid.is_nil() && self.connection_epoch >= 1,
            "cluster process instance identity is invalid"
        );
        anyhow::ensure!(
            !self.destination_connection_uuid.is_nil()
                && self.destination_connection_epoch >= 1
                && !self.destination_key_id.is_empty()
                && self.destination_key_epoch >= 1,
            "cluster destination process identity is invalid"
        );
        anyhow::ensure!(
            self.request_id
                .as_deref()
                .is_none_or(|id| id == self.event_id && uuid::Uuid::parse_str(id).is_ok()),
            "cluster request ID is not exactly bound to its event ID"
        );
        anyhow::ensure!(
            payload_digest(&self.payload)? == self.payload_sha256,
            "cluster payload digest mismatch"
        );
        anyhow::ensure!(
            infer_kind(&self.payload)? == self.kind,
            "cluster command kind does not match its payload"
        );
        let peer = peers
            .get(&self.source_node)
            .context("cluster source node is not allowlisted")?;
        anyhow::ensure!(
            peer.node_id == self.source_node,
            "cluster peer identity mismatch"
        );
        anyhow::ensure!(
            peer.permits(self.kind),
            "cluster peer ACL rejected this command kind"
        );
        let public_key = peer
            .key(&self.key_id, self.key_epoch)
            .context("cluster signing key ID or epoch is not authorized")?;
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .context("cluster signature is not base64url")?;
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(&self.signing_bytes()?, &signature)
            .map_err(|_| anyhow::anyhow!("cluster Ed25519 signature verification failed"))?;
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&UnsignedEnvelope {
            version: self.version,
            namespace: &self.namespace,
            source_node: &self.source_node,
            destination_node: &self.destination_node,
            destination_connection_uuid: self.destination_connection_uuid,
            destination_connection_epoch: self.destination_connection_epoch,
            destination_key_id: &self.destination_key_id,
            destination_key_epoch: self.destination_key_epoch,
            channel: &self.channel,
            kind: self.kind,
            event_id: &self.event_id,
            request_id: self.request_id.as_deref(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            payload_sha256: &self.payload_sha256,
            key_id: &self.key_id,
            key_epoch: self.key_epoch,
            connection_uuid: self.connection_uuid,
            connection_epoch: self.connection_epoch,
            payload: &self.payload,
        })
        .context("could not serialize canonical cluster envelope")
    }
}

pub fn infer_kind(payload: &Value) -> Result<ClusterCommandKind> {
    let object = payload
        .as_object()
        .context("cluster command payload must be an object")?;
    let flagged = |name: &str| object.get(name).and_then(Value::as_bool) == Some(true);
    let candidates = [
        (
            flagged("blocking_presence_change"),
            ClusterCommandKind::BlockingPresence,
        ),
        (flagged("presence_probe"), ClusterCommandKind::PresenceProbe),
        (
            flagged("session_termination"),
            ClusterCommandKind::SessionTeardown,
        ),
        (
            flagged("account_generation_teardown"),
            ClusterCommandKind::AccountGenerationTeardown,
        ),
        (
            flagged("user_agent_replacement"),
            ClusterCommandKind::UserAgentReplacement,
        ),
        (
            flagged("sm_session_teardown"),
            ClusterCommandKind::SmSessionTeardown,
        ),
        (
            flagged("sm_muc_teardown"),
            ClusterCommandKind::SmMucTeardown,
        ),
        (flagged("muc_broadcast"), ClusterCommandKind::MucBroadcast),
        (flagged("muc_private"), ClusterCommandKind::MucPrivate),
        (flagged("muc_presence"), ClusterCommandKind::MucPresence),
        (
            flagged("muc_nickname_change"),
            ClusterCommandKind::MucNicknameChange,
        ),
        (
            flagged("muc_role_change"),
            ClusterCommandKind::MucRoleChange,
        ),
        (flagged("muc_evict"), ClusterCommandKind::MucEvict),
        (flagged("muc_destroy"), ClusterCommandKind::MucDestroy),
        (
            flagged("muc_operation_wake"),
            ClusterCommandKind::MucOperationWake,
        ),
    ];
    let mut kinds = candidates
        .into_iter()
        .filter_map(|(present, kind)| present.then_some(kind));
    if let Some(kind) = kinds.next() {
        anyhow::ensure!(
            kinds.next().is_none(),
            "cluster payload has multiple command kinds"
        );
        return Ok(kind);
    }
    if object.contains_key("delivered") && object.contains_key("nonce") {
        return Ok(ClusterCommandKind::Ack);
    }
    if object.contains_key("stanza") {
        return Ok(ClusterCommandKind::DirectDelivery);
    }
    anyhow::bail!("cluster payload has no recognized command kind")
}

fn payload_digest(payload: &Value) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(
        serde_json::to_vec(payload).context("could not serialize cluster payload")?,
    )))
}

#[cfg(test)]
pub(crate) fn test_configuration_pair(
    _namespace: &str,
) -> (Arc<ClusterSecurityConfig>, Arc<ClusterSecurityConfig>) {
    use ring::rand::SystemRandom;
    let allowed_kinds = HashSet::from([
        ClusterCommandKind::Ack,
        ClusterCommandKind::DirectDelivery,
        ClusterCommandKind::BlockingPresence,
        ClusterCommandKind::PresenceProbe,
        ClusterCommandKind::SessionTeardown,
        ClusterCommandKind::AccountGenerationTeardown,
        ClusterCommandKind::UserAgentReplacement,
        ClusterCommandKind::SmSessionTeardown,
        ClusterCommandKind::SmMucTeardown,
        ClusterCommandKind::MucBroadcast,
        ClusterCommandKind::MucPrivate,
        ClusterCommandKind::MucPresence,
        ClusterCommandKind::MucNicknameChange,
        ClusterCommandKind::MucRoleChange,
        ClusterCommandKind::MucEvict,
        ClusterCommandKind::MucDestroy,
        ClusterCommandKind::MucOperationWake,
    ]);
    let make_signer = || {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
        let signer = Arc::new(ClusterSigner {
            pkcs8: Zeroizing::new(pkcs8.as_ref().to_vec()),
            key_id: key_id(&public),
            key_epoch: 1,
        });
        (signer, public)
    };
    let (first_signer, first_public) = make_signer();
    let (second_signer, second_public) = make_signer();
    let make_config = |node_id: &str,
                       signer: Arc<ClusterSigner>,
                       public: [u8; 32],
                       peer_id: &str,
                       peer_public: [u8; 32]| {
        let current_key_id = key_id(&public);
        Arc::new(ClusterSecurityConfig {
            node_id: node_id.into(),
            key_epoch: 1,
            current_key_id: current_key_id.clone(),
            current_public_key_sha256: public_key_digest(&public),
            previous_key_id: None,
            previous_public_key_sha256: None,
            staged_next_key_id: None,
            staged_next_public_key_sha256: None,
            failure_policy: ClusterFailurePolicy::FailClosed,
            safety_lease_seconds: 120,
            signer,
            peers: Arc::new(HashMap::from([(
                peer_id.into(),
                PeerVerifier {
                    node_id: peer_id.into(),
                    key_epoch: 1,
                    current: VerificationKey {
                        key_id: key_id(&peer_public),
                        public_key: peer_public,
                    },
                    previous: None,
                    staged_next: None,
                    allowed_kinds: allowed_kinds.clone(),
                },
            )])),
        })
    };
    (
        make_config(
            "test-node-a",
            first_signer,
            first_public,
            "test-node-b",
            second_public,
        ),
        make_config(
            "test-node-b",
            second_signer,
            second_public,
            "test-node-a",
            first_public,
        ),
    )
}

#[cfg(test)]
pub(crate) fn test_prepared_staged_pair(
    _namespace: &str,
) -> (
    Arc<ClusterSecurityConfig>,
    Arc<ClusterSecurityConfig>,
    String,
) {
    use ring::rand::SystemRandom;
    let make_key = |epoch| {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
        (
            Arc::new(ClusterSigner {
                pkcs8: Zeroizing::new(pkcs8.as_ref().to_vec()),
                key_id: key_id(&public),
                key_epoch: epoch,
            }),
            public,
        )
    };
    let (_old_signer, old_public) = make_key(1);
    let (staged_signer, staged_public) = make_key(2);
    let (receiver_signer, receiver_public) = make_key(1);
    let allowed_kinds =
        HashSet::from([ClusterCommandKind::DirectDelivery, ClusterCommandKind::Ack]);
    let sender = Arc::new(ClusterSecurityConfig {
        node_id: "test-node-a".into(),
        key_epoch: 2,
        current_key_id: key_id(&staged_public),
        current_public_key_sha256: public_key_digest(&staged_public),
        previous_key_id: Some(key_id(&old_public)),
        previous_public_key_sha256: Some(public_key_digest(&old_public)),
        staged_next_key_id: None,
        staged_next_public_key_sha256: None,
        failure_policy: ClusterFailurePolicy::FailClosed,
        safety_lease_seconds: 120,
        signer: staged_signer,
        peers: Arc::new(HashMap::from([(
            "test-node-b".into(),
            PeerVerifier {
                node_id: "test-node-b".into(),
                key_epoch: 1,
                current: VerificationKey {
                    key_id: key_id(&receiver_public),
                    public_key: receiver_public,
                },
                previous: None,
                staged_next: None,
                allowed_kinds: allowed_kinds.clone(),
            },
        )])),
    });
    let receiver = Arc::new(ClusterSecurityConfig {
        node_id: "test-node-b".into(),
        key_epoch: 1,
        current_key_id: key_id(&receiver_public),
        current_public_key_sha256: public_key_digest(&receiver_public),
        previous_key_id: None,
        previous_public_key_sha256: None,
        staged_next_key_id: None,
        staged_next_public_key_sha256: None,
        failure_policy: ClusterFailurePolicy::FailClosed,
        safety_lease_seconds: 120,
        signer: receiver_signer,
        peers: Arc::new(HashMap::from([(
            "test-node-a".into(),
            PeerVerifier {
                node_id: "test-node-a".into(),
                key_epoch: 1,
                current: VerificationKey {
                    key_id: key_id(&old_public),
                    public_key: old_public,
                },
                previous: None,
                staged_next: Some(VerificationKey {
                    key_id: key_id(&staged_public),
                    public_key: staged_public,
                }),
                allowed_kinds,
            },
        )])),
    });
    (sender, receiver, key_id(&old_public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    fn fixture() -> (Arc<ClusterSigner>, HashMap<String, PeerVerifier>) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
        let signer = Arc::new(ClusterSigner {
            pkcs8: Zeroizing::new(pkcs8.as_ref().to_vec()),
            key_id: key_id(&public_key),
            key_epoch: 3,
        });
        let peers = HashMap::from([(
            "node-a".to_owned(),
            PeerVerifier {
                node_id: "node-a".to_owned(),
                key_epoch: 3,
                current: VerificationKey {
                    key_id: signer.key_id.clone(),
                    public_key,
                },
                previous: None,
                staged_next: None,
                allowed_kinds: HashSet::from([
                    ClusterCommandKind::DirectDelivery,
                    ClusterCommandKind::Ack,
                ]),
            },
        )]);
        (signer, peers)
    }

    #[test]
    fn envelope_binds_every_routing_dimension_and_rejects_tampering() {
        let (signer, peers) = fixture();
        let payload = serde_json::json!({
            "target": "alice@example.test",
            "stanza": "<message/>",
            "request_id": "55319f1b-8eb6-486d-bef2-f28382fc7f96",
        });
        let envelope = SignedClusterEnvelope::sign(
            &signer,
            "example.test",
            "node-a",
            "node-b",
            uuid::Uuid::new_v4(),
            3,
            "receiver-key",
            2,
            "northstar:example.test:node:node-b",
            ClusterCommandKind::DirectDelivery,
            uuid::Uuid::new_v4(),
            9,
            payload,
            1_000,
        )
        .unwrap();
        envelope
            .verify(
                "example.test",
                "node-b",
                "northstar:example.test:node:node-b",
                Some("node-a"),
                &peers,
                1_001,
            )
            .unwrap();
        for mutation in [
            "namespace",
            "destination",
            "destination_instance",
            "destination_key",
            "channel",
            "payload",
            "epoch",
        ] {
            let mut changed = envelope.clone();
            match mutation {
                "namespace" => changed.namespace = "other.test".into(),
                "destination" => changed.destination_node = "node-c".into(),
                "destination_instance" => changed.destination_connection_epoch += 1,
                "destination_key" => changed.destination_key_epoch += 1,
                "channel" => changed.channel.push_str(":wrong"),
                "payload" => changed.payload["target"] = "mallory@example.test".into(),
                "epoch" => changed.key_epoch += 1,
                _ => unreachable!(),
            }
            assert!(changed
                .verify(
                    "example.test",
                    "node-b",
                    "northstar:example.test:node:node-b",
                    Some("node-a"),
                    &peers,
                    1_001,
                )
                .is_err());
        }
    }

    #[test]
    fn expired_wrong_kind_and_non_allowlisted_source_fail_closed() {
        let (signer, peers) = fixture();
        let envelope = SignedClusterEnvelope::sign(
            &signer,
            "example.test",
            "node-a",
            "node-b",
            uuid::Uuid::new_v4(),
            3,
            "receiver-key",
            2,
            "channel",
            ClusterCommandKind::DirectDelivery,
            uuid::Uuid::new_v4(),
            9,
            serde_json::json!({"target":"a@example.test","stanza":"<message/>"}),
            1_000,
        )
        .unwrap();
        assert!(envelope
            .verify("example.test", "node-b", "channel", None, &peers, 1_020)
            .is_err());
        let mut wrong_kind = envelope.clone();
        wrong_kind.kind = ClusterCommandKind::MucDestroy;
        assert!(wrong_kind
            .verify("example.test", "node-b", "channel", None, &peers, 1_001)
            .is_err());
        let mut unknown = envelope;
        unknown.source_node = "unknown".into();
        assert!(unknown
            .verify("example.test", "node-b", "channel", None, &peers, 1_001)
            .is_err());
    }

    #[test]
    fn previous_key_accepts_only_the_immediately_preceding_key_epoch() {
        let rng = SystemRandom::new();
        let old_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let old_pair = Ed25519KeyPair::from_pkcs8(old_pkcs8.as_ref()).unwrap();
        let old_public: [u8; 32] = old_pair.public_key().as_ref().try_into().unwrap();
        let new_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let new_pair = Ed25519KeyPair::from_pkcs8(new_pkcs8.as_ref()).unwrap();
        let new_public: [u8; 32] = new_pair.public_key().as_ref().try_into().unwrap();
        let old_signer = ClusterSigner {
            pkcs8: Zeroizing::new(old_pkcs8.as_ref().to_vec()),
            key_id: key_id(&old_public),
            key_epoch: 4,
        };
        let peers = HashMap::from([(
            "node-a".to_owned(),
            PeerVerifier {
                node_id: "node-a".to_owned(),
                key_epoch: 5,
                current: VerificationKey {
                    key_id: key_id(&new_public),
                    public_key: new_public,
                },
                previous: Some(VerificationKey {
                    key_id: key_id(&old_public),
                    public_key: old_public,
                }),
                staged_next: None,
                allowed_kinds: HashSet::from([ClusterCommandKind::DirectDelivery]),
            },
        )]);
        let envelope = SignedClusterEnvelope::sign(
            &old_signer,
            "example.test",
            "node-a",
            "node-b",
            uuid::Uuid::new_v4(),
            3,
            "receiver-key",
            2,
            "channel",
            ClusterCommandKind::DirectDelivery,
            uuid::Uuid::new_v4(),
            11,
            serde_json::json!({"target":"a@example.test","stanza":"<message/>"}),
            1_000,
        )
        .unwrap();
        envelope
            .verify("example.test", "node-b", "channel", None, &peers, 1_001)
            .unwrap();

        let mut skipped_generation = envelope;
        skipped_generation.key_epoch = 3;
        assert!(skipped_generation
            .verify("example.test", "node-b", "channel", None, &peers, 1_001)
            .is_err());
    }

    #[test]
    fn staged_next_key_may_verify_cryptographically_but_needs_pg_activation() {
        let rng = SystemRandom::new();
        let current_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let current_pair = Ed25519KeyPair::from_pkcs8(current_pkcs8.as_ref()).unwrap();
        let current_public: [u8; 32] = current_pair.public_key().as_ref().try_into().unwrap();
        let staged_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let staged_pair = Ed25519KeyPair::from_pkcs8(staged_pkcs8.as_ref()).unwrap();
        let staged_public: [u8; 32] = staged_pair.public_key().as_ref().try_into().unwrap();
        let staged_signer = ClusterSigner {
            pkcs8: Zeroizing::new(staged_pkcs8.as_ref().to_vec()),
            key_id: key_id(&staged_public),
            key_epoch: 8,
        };
        let peers = HashMap::from([(
            "node-a".to_owned(),
            PeerVerifier {
                node_id: "node-a".to_owned(),
                key_epoch: 7,
                current: VerificationKey {
                    key_id: key_id(&current_public),
                    public_key: current_public,
                },
                previous: None,
                staged_next: Some(VerificationKey {
                    key_id: key_id(&staged_public),
                    public_key: staged_public,
                }),
                allowed_kinds: HashSet::from([ClusterCommandKind::DirectDelivery]),
            },
        )]);
        let envelope = SignedClusterEnvelope::sign(
            &staged_signer,
            "example.test",
            "node-a",
            "node-b",
            uuid::Uuid::new_v4(),
            3,
            "receiver-key",
            2,
            "channel",
            ClusterCommandKind::DirectDelivery,
            uuid::Uuid::new_v4(),
            3,
            serde_json::json!({"target":"a@example.test","stanza":"<message/>"}),
            1_000,
        )
        .unwrap();
        assert!(envelope
            .verify("example.test", "node-b", "channel", None, &peers, 1_001)
            .is_ok());
    }
}
