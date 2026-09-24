//! Application boundary for XEP-0424/XEP-0444 personal message retractions.
//!
//! The protocol layer validates the incoming XML shape and supplies an
//! authenticated sender plus bounded owner projections. This service owns the
//! validation and keyed content commitments. The repository commits original
//! tombstones, action archives and local or federated delivery together.

use crate::{
    abuse::{ContentIdentityAuthenticators, PersonalRetractionContentKeyring},
    xmpp::xml_builder::XmlElement,
};
use anyhow::{Context, Result};
pub(crate) use northstar_message_core::ArchiveProjection as ArchiveWrite;

use roxmltree::{Document, Node};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

const NS_RETRACT: &str = "urn:xmpp:message-retract:1";
const NS_STANZA_ID: &str = "urn:xmpp:sid:0";
const NS_NORTHSTAR_POW: &str = "urn:northstar:pow:1";
const RETRACTION_LOCK_DOMAIN: &[u8] = b"northstar/retraction-action-lock/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerProjection<'a> {
    pub(crate) owner_id: Uuid,
    pub(crate) peer_jid: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetractionCommand<'a> {
    pub(crate) target_id: &'a str,
    pub(crate) action_id: &'a str,
    /// Exact accepted message element. The service canonicalizes semantic XML
    /// and excludes only transport metadata plus the consumed local PoW
    /// envelope.
    pub(crate) semantic_payload: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FederationOutboxPolicy {
    pub(crate) ttl_seconds: u64,
    pub(crate) max_rows: i64,
    pub(crate) max_bytes: i64,
    pub(crate) max_per_domain: i64,
}

impl From<northstar_federation_core::S2sOutboxPolicy> for FederationOutboxPolicy {
    fn from(value: northstar_federation_core::S2sOutboxPolicy) -> Self {
        Self {
            ttl_seconds: value.ttl_seconds,
            max_rows: value.max_rows,
            max_bytes: value.max_bytes,
            max_per_domain: value.max_per_domain,
        }
    }
}

impl From<FederationOutboxPolicy> for northstar_federation_core::S2sOutboxPolicy {
    fn from(value: FederationOutboxPolicy) -> Self {
        Self {
            ttl_seconds: value.ttl_seconds,
            max_rows: value.max_rows,
            max_bytes: value.max_bytes,
            max_per_domain: value.max_per_domain,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutboundProjection<'a> {
    pub(crate) target_domain: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) bounce_to: Option<&'a str>,
    pub(crate) policy: FederationOutboxPolicy,
}

/// One recoverable local-delivery projection owned by the retraction
/// transaction. The protocol may fan the committed row into an online queue,
/// but the same row remains the offline fallback until a transport ACKs it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeliveryProjection<'a> {
    pub(crate) id: Uuid,
    pub(crate) recipient_id: Uuid,
    /// Present for an authenticated local C2S actor and absent for S2S input.
    pub(crate) local_actor_id: Option<Uuid>,
    pub(crate) sender_jid: &'a str,
    pub(crate) stanza: &'a str,
    pub(crate) encrypted: bool,
    pub(crate) max_messages: i64,
    pub(crate) max_bytes: i64,
    pub(crate) ttl_days: i64,
    pub(crate) mam_backed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct PersonalRetractionInvocation<'a> {
    pub(crate) owners: &'a [OwnerProjection<'a>],
    pub(crate) sender_jid: &'a str,
    pub(crate) command: RetractionCommand<'a>,
    pub(crate) action_writes: &'a [ArchiveWrite<'a>],
    pub(crate) delivery: Option<DeliveryProjection<'a>>,
    pub(crate) outbound: Option<OutboundProjection<'a>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetractionOutcome {
    Applied { tombstones: usize },
    Replay,
    Conflict,
    Forbidden,
    AccountUnavailable,
    CapacityExceeded,
}

/// A bounded retraction whose identities, archive projections and commitments
/// have been validated before persistence borrows a connection.
pub(crate) struct PreparedRetraction<'a> {
    pub(crate) command: &'a RetractionCommand<'a>,
    pub(crate) command_encrypted: bool,
    pub(crate) canonical_sender: String,
    pub(crate) configured_domain: String,
    pub(crate) canonical_semantics: Vec<u8>,
    pub(crate) normalized_owners: Vec<NormalizedOwner>,
    pub(crate) normalized_writes: Vec<NormalizedWrite<'a>>,
    pub(crate) normalized_delivery: Option<NormalizedDelivery<'a>>,
    pub(crate) normalized_outbound: Option<NormalizedOutbound<'a>>,
    pub(crate) action_digest: [u8; 32],
    pub(crate) semantic_sha256: Vec<u8>,
    pub(crate) semantic_sha512: Vec<u8>,
    pub(crate) semantic_length: i64,
    pub(crate) semantic_authenticators: ContentIdentityAuthenticators,
    pub(crate) owner_projection_sha256: Vec<u8>,
    pub(crate) owner_projection_sha512: Vec<u8>,
    pub(crate) owner_projection_length: i64,
    pub(crate) owner_authenticators: ContentIdentityAuthenticators,
    pub(crate) delivery_authenticators: Option<ContentIdentityAuthenticators>,
}

pub(crate) trait RetractionRepository: Send + Sync {
    fn apply_prepared(
        &self,
        prepared: PreparedRetraction<'_>,
    ) -> impl std::future::Future<Output = Result<RetractionOutcome>> + Send;
}

#[derive(Clone)]
pub(crate) struct RetractionService<R> {
    repository: R,
    content_identity: PersonalRetractionContentKeyring,
    configured_domain: String,
}

pub(crate) struct NormalizedOwner {
    pub(crate) owner_id: Uuid,
    pub(crate) peer_bare_jid: String,
}

pub(crate) struct NormalizedWrite<'a> {
    pub(crate) write: &'a ArchiveWrite<'a>,
    pub(crate) peer_bare_jid: String,
    pub(crate) peer_full_jid: String,
}

pub(crate) struct NormalizedDelivery<'a> {
    pub(crate) projection: &'a DeliveryProjection<'a>,
    pub(crate) sender_full_jid: String,
    pub(crate) sender_bare_jid: String,
    pub(crate) recipient_bare_jid: String,
    pub(crate) target_full_jid: Option<String>,
    pub(crate) commitment: Vec<u8>,
}

pub(crate) struct NormalizedOutbound<'a> {
    pub(crate) projection: &'a OutboundProjection<'a>,
    pub(crate) target_domain: String,
    pub(crate) recipient_bare_jid: String,
}

pub(crate) enum TargetClassification {
    OwnedOriginal(String),
    SameTombstone,
    ConflictingTombstone,
    ForeignOriginal,
    Irrelevant,
}

impl<R: RetractionRepository> RetractionService<R> {
    pub(crate) fn new(
        repository: R,
        content_identity: PersonalRetractionContentKeyring,
        configured_domain: impl Into<String>,
    ) -> Self {
        Self {
            repository,
            content_identity,
            configured_domain: configured_domain.into(),
        }
    }

    pub(crate) async fn apply(
        &self,
        owners: &[OwnerProjection<'_>],
        sender_jid: &str,
        command: &RetractionCommand<'_>,
        action_writes: &[ArchiveWrite<'_>],
        outbound: Option<&OutboundProjection<'_>>,
    ) -> Result<RetractionOutcome> {
        self.apply_with_delivery(owners, sender_jid, command, action_writes, None, outbound)
            .await
    }

    pub(crate) async fn apply_with_delivery(
        &self,
        owners: &[OwnerProjection<'_>],
        sender_jid: &str,
        command: &RetractionCommand<'_>,
        action_writes: &[ArchiveWrite<'_>],
        delivery: Option<&DeliveryProjection<'_>>,
        outbound: Option<&OutboundProjection<'_>>,
    ) -> Result<RetractionOutcome> {
        anyhow::ensure!(
            !owners.is_empty() && owners.len() <= 2 && action_writes.len() <= 2,
            "personal retraction exceeds owner projection bound"
        );
        validate_stable_id(command.target_id, "retraction target id")?;
        validate_stable_id(command.action_id, "retraction action id")?;
        anyhow::ensure!(
            !command.semantic_payload.is_empty() && command.semantic_payload.len() <= 1_048_576,
            "retraction semantic payload must contain 1 byte to 1 MiB"
        );

        let canonical_sender = crate::jid::canonical_bare_key(sender_jid)?;
        let mut normalized_owners = Vec::with_capacity(owners.len());
        let mut owner_ids = HashSet::new();
        for owner in owners {
            anyhow::ensure!(
                owner_ids.insert(owner.owner_id),
                "personal retraction contains duplicate archive owners"
            );
            normalized_owners.push(NormalizedOwner {
                owner_id: owner.owner_id,
                peer_bare_jid: crate::jid::canonical_bare_key(owner.peer_jid)?,
            });
        }
        normalized_owners.sort_by_key(|owner| owner.owner_id);

        let canonical_semantics = canonical_retraction_semantics(
            command.semantic_payload,
            &canonical_sender,
            command.action_id,
            command.target_id,
        )?;
        let command_document = Document::parse(command.semantic_payload)
            .context("retraction command is invalid XML")?;
        let command_encrypted =
            crate::xmpp::xml_util::is_encrypted(command_document.root_element());
        let configured_domain = crate::jid::prepare_domainpart(&self.configured_domain)?;
        anyhow::ensure!(
            delivery.is_none() || outbound.is_none(),
            "one retraction cannot request local C2S and S2S delivery projections"
        );
        let normalized_delivery = delivery
            .map(|delivery| {
                normalize_delivery_projection(
                    delivery,
                    &canonical_sender,
                    &configured_domain,
                    command,
                )
            })
            .transpose()?;
        let normalized_outbound = outbound
            .map(|outbound| {
                normalize_outbound_projection(
                    outbound,
                    &canonical_sender,
                    &configured_domain,
                    &canonical_semantics,
                    command,
                )
            })
            .transpose()?;
        let delivery_authenticators = normalized_delivery
            .as_ref()
            .map(|delivery| self.content_identity.authenticators(&delivery.commitment));
        let semantic_sha256 = Sha256::digest(&canonical_semantics).to_vec();
        let semantic_sha512 = Sha512::digest(&canonical_semantics).to_vec();
        let semantic_length = i64::try_from(canonical_semantics.len())?;
        let semantic_authenticators = self.content_identity.authenticators(&canonical_semantics);
        let action_digest = bounded_action_digest(command.action_id);
        let mut normalized_writes = Vec::with_capacity(action_writes.len());
        let mut write_owners = HashSet::new();
        let mut write_ids = HashSet::new();
        for write in action_writes {
            anyhow::ensure!(
                write_owners.insert(write.owner_id),
                "personal retraction contains duplicate action archive owners"
            );
            anyhow::ensure!(
                write_ids.insert(write.id),
                "personal retraction contains duplicate action archive ids"
            );
            anyhow::ensure!(
                write.stanza_id == Some(command.action_id),
                "action archive stable id does not match the retraction action id"
            );
            anyhow::ensure!(
                !write.stanza.is_empty() && write.stanza.len() <= 1_048_576,
                "retraction action archive must contain 1 byte to 1 MiB"
            );
            let peer_full_jid = crate::jid::canonicalize(write.peer_jid)?;
            let peer_bare_jid = crate::jid::canonical_bare_key(&peer_full_jid)?;
            anyhow::ensure!(
                normalized_owners.iter().any(|owner| {
                    owner.owner_id == write.owner_id && owner.peer_bare_jid == peer_bare_jid
                }),
                "retraction action archive does not belong to an authorized owner projection"
            );
            let write_semantics = canonical_retraction_semantics(
                write.stanza,
                &canonical_sender,
                command.action_id,
                command.target_id,
            )?;
            let write_document = Document::parse(write.stanza)
                .context("retraction action archive is invalid XML")?;
            anyhow::ensure!(
                crate::xmpp::xml_util::is_encrypted(write_document.root_element())
                    == write.encrypted,
                "retraction action archive encryption flag does not match stanza"
            );
            anyhow::ensure!(
                write.encrypted == command_encrypted,
                "retraction action archive encryption flag differs from authenticated action"
            );
            let expected_write_semantics = if write.encrypted {
                let sanitized = crate::xmpp::xml_util::encrypted_retraction_archive_stanza(
                    command.semantic_payload,
                    command.target_id,
                );
                canonical_retraction_semantics(
                    &sanitized,
                    &canonical_sender,
                    command.action_id,
                    command.target_id,
                )?
            } else {
                canonical_semantics.clone()
            };
            anyhow::ensure!(
                write_semantics == expected_write_semantics,
                "retraction action archive content differs from authenticated action"
            );
            normalized_writes.push(NormalizedWrite {
                write,
                peer_bare_jid,
                peer_full_jid,
            });
        }
        if let Some(delivery) = normalized_delivery.as_ref() {
            let recipient_action_archived = normalized_writes
                .iter()
                .any(|write| write.write.owner_id == delivery.projection.recipient_id);
            anyhow::ensure!(
                recipient_action_archived == delivery.projection.mam_backed,
                "retraction delivery MAM flag does not match recipient action projection"
            );
        }
        let owner_projection_value = canonical_owner_projection(&normalized_owners);
        let owner_projection_sha256 = Sha256::digest(&owner_projection_value).to_vec();
        let owner_projection_sha512 = Sha512::digest(&owner_projection_value).to_vec();
        let owner_projection_length = i64::try_from(owner_projection_value.len())?;
        let owner_authenticators = self
            .content_identity
            .authenticators(&owner_projection_value);

        self.repository
            .apply_prepared(PreparedRetraction {
                command,
                command_encrypted,
                canonical_sender,
                configured_domain,
                canonical_semantics,
                normalized_owners,
                normalized_writes,
                normalized_delivery,
                normalized_outbound,
                action_digest,
                semantic_sha256,
                semantic_sha512,
                semantic_length,
                semantic_authenticators,
                owner_projection_sha256,
                owner_projection_sha512,
                owner_projection_length,
                owner_authenticators,
                delivery_authenticators,
            })
            .await
    }
}

fn normalize_delivery_projection<'a>(
    delivery: &'a DeliveryProjection<'a>,
    canonical_sender: &str,
    configured_domain: &str,
    command: &RetractionCommand<'_>,
) -> Result<NormalizedDelivery<'a>> {
    anyhow::ensure!(
        !delivery.stanza.is_empty() && delivery.stanza.len() <= 1_048_576,
        "retraction delivery stanza must contain 1 byte to 1 MiB"
    );
    anyhow::ensure!(
        delivery.max_messages > 0 && delivery.max_bytes > 0 && delivery.ttl_days >= 0,
        "retraction delivery policy is invalid"
    );
    let sender_full = crate::jid::canonicalize(delivery.sender_jid)?;
    let sender_bare_jid = crate::jid::canonical_bare_key(&sender_full)?;
    anyhow::ensure!(
        sender_bare_jid == canonical_sender,
        "retraction delivery sender does not match authenticated sender"
    );
    let document =
        Document::parse(delivery.stanza).context("retraction delivery is invalid XML")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "retraction delivery is not a message"
    );
    let stanza_from = root
        .attribute("from")
        .context("retraction delivery is missing from")?;
    anyhow::ensure!(
        crate::jid::canonical_bare_key(stanza_from)? == canonical_sender,
        "retraction delivery from does not match authenticated sender"
    );
    // RFC 6120 section 10.3.1 gives a locally authenticated C2S message
    // without `to` the effective destination of the sender's bare JID. Keep
    // that routing value separate from the XML: section 8.1.1.1 forbids the
    // server from rewriting a client stanza's `to` while delivering it. S2S
    // stanzas, in contrast, are required to carry an explicit destination.
    let recipient_full_jid = match root.attribute("to") {
        Some(to) => crate::jid::canonicalize(to)?,
        None if delivery.local_actor_id.is_some() => canonical_sender.to_owned(),
        None => anyhow::bail!("federated retraction delivery is missing to"),
    };
    let recipient_jid = crate::jid::CanonicalJid::parse(&recipient_full_jid)?;
    anyhow::ensure!(
        recipient_jid.localpart().is_some() && recipient_jid.domainpart() == configured_domain,
        "retraction C2S delivery target is not a local account"
    );
    let recipient_bare_jid = recipient_jid.bare().to_string();
    let expected_target_full_jid = (root.attribute("to").is_some()
        && root.attribute("type").unwrap_or("normal") == "normal"
        && recipient_jid.resourcepart().is_some())
    .then(|| recipient_full_jid.clone());
    anyhow::ensure!(
        crate::xmpp::xml_util::is_encrypted(root) == delivery.encrypted,
        "retraction delivery encryption flag does not match stanza"
    );
    let delivery_semantics = canonical_retraction_transport_semantics(
        delivery.stanza,
        canonical_sender,
        command.action_id,
        command.target_id,
    )?;
    let command_semantics = canonical_retraction_transport_semantics(
        command.semantic_payload,
        canonical_sender,
        command.action_id,
        command.target_id,
    )?;
    anyhow::ensure!(
        delivery_semantics == command_semantics,
        "retraction delivery content differs from the authenticated action"
    );

    let mut commitment = b"northstar/retraction-c2s-projection/v1\0".to_vec();
    append_bytes_component(&mut commitment, delivery.recipient_id.as_bytes());
    match delivery.local_actor_id {
        Some(actor_id) => {
            commitment.push(1);
            append_bytes_component(&mut commitment, actor_id.as_bytes());
        }
        None => commitment.push(0),
    }
    append_component(&mut commitment, &sender_bare_jid);
    // Resource affinity is an immutable part of a normal full-JID delivery,
    // including authenticated S2S input. Bare and chat-fallback projections
    // remain account scoped and deliberately commit only the bare recipient.
    let committed_recipient = expected_target_full_jid
        .as_deref()
        .unwrap_or(recipient_bare_jid.as_str());
    append_component(&mut commitment, committed_recipient);
    commitment.push(u8::from(delivery.encrypted));
    commitment.push(u8::from(delivery.mam_backed));
    commitment.extend_from_slice(&delivery.max_messages.to_be_bytes());
    commitment.extend_from_slice(&delivery.max_bytes.to_be_bytes());
    commitment.extend_from_slice(&delivery.ttl_days.to_be_bytes());
    append_bytes_component(&mut commitment, &delivery_semantics);

    Ok(NormalizedDelivery {
        projection: delivery,
        sender_full_jid: sender_full,
        sender_bare_jid,
        recipient_bare_jid,
        target_full_jid: expected_target_full_jid,
        commitment,
    })
}

fn normalize_outbound_projection<'a>(
    outbound: &'a OutboundProjection<'a>,
    canonical_sender: &str,
    configured_domain: &str,
    canonical_command_semantics: &[u8],
    command: &RetractionCommand<'_>,
) -> Result<NormalizedOutbound<'a>> {
    let target_domain = crate::jid::prepare_domainpart(outbound.target_domain)?;
    anyhow::ensure!(
        target_domain != configured_domain,
        "retraction outbox target must be a remote domain"
    );
    let document = Document::parse(outbound.stanza).context("retraction outbox is invalid XML")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "retraction outbox is not a message"
    );
    anyhow::ensure!(
        root.attribute("from")
            .is_some_and(|from| crate::jid::canonical_bare_key(from).ok().as_deref()
                == Some(canonical_sender)),
        "retraction outbox from does not match authenticated sender"
    );
    let recipient = crate::jid::CanonicalJid::parse(
        root.attribute("to")
            .context("retraction outbox is missing to")?,
    )?;
    anyhow::ensure!(
        recipient.localpart().is_some() && recipient.domainpart() == target_domain,
        "retraction outbox target domain does not match stanza to"
    );
    if let Some(bounce_to) = outbound.bounce_to {
        anyhow::ensure!(
            crate::jid::canonical_bare_key(bounce_to)? == canonical_sender,
            "retraction outbox bounce authority does not belong to sender"
        );
    }
    let outbound_semantics = canonical_retraction_semantics(
        outbound.stanza,
        canonical_sender,
        command.action_id,
        command.target_id,
    )?;
    anyhow::ensure!(
        outbound_semantics == canonical_command_semantics,
        "retraction outbox content differs from the authenticated action"
    );
    Ok(NormalizedOutbound {
        projection: outbound,
        target_domain,
        // Personal retraction identity is deliberately account scoped. The
        // first committed outbox row retains the original full `to`, but an
        // exact retry from/to another resource of the same accounts is a
        // replay and never creates a second projection.
        recipient_bare_jid: recipient.bare().to_string(),
    })
}

pub(crate) fn validate_owner_authority(
    owners: &[NormalizedOwner],
    account_bares: &HashMap<Uuid, String>,
    canonical_sender: &str,
    configured_domain: &str,
    delivery: Option<&NormalizedDelivery<'_>>,
    outbound: Option<&NormalizedOutbound<'_>>,
) -> Result<()> {
    anyhow::ensure!(
        owners
            .iter()
            .all(|owner| account_bares.contains_key(&owner.owner_id)),
        "retraction owner UUID is not an enabled local account"
    );
    let sender = crate::jid::CanonicalJid::parse_bare(canonical_sender)?;
    let sender_is_local = sender.domainpart() == configured_domain;
    let sender_owner = account_bares
        .iter()
        .find_map(|(id, bare)| (bare == canonical_sender).then_some(*id));

    let mut expected = HashMap::<Uuid, String>::new();
    if let Some(delivery) = delivery {
        let projection = delivery.projection;
        anyhow::ensure!(
            account_bares.get(&projection.recipient_id) == Some(&delivery.recipient_bare_jid),
            "retraction delivery recipient UUID does not match stanza to"
        );
        if let Some(local_actor_id) = projection.local_actor_id {
            anyhow::ensure!(
                sender_is_local
                    && account_bares.get(&local_actor_id).map(String::as_str)
                        == Some(canonical_sender),
                "retraction local actor UUID does not match authenticated sender"
            );
            expected.insert(local_actor_id, delivery.recipient_bare_jid.clone());
            if let Some(previous) =
                expected.insert(projection.recipient_id, delivery.sender_bare_jid.clone())
            {
                anyhow::ensure!(
                    previous == delivery.sender_bare_jid,
                    "self-delivery owner projection is inconsistent"
                );
            }
        } else {
            anyhow::ensure!(
                !sender_is_local,
                "a local retraction sender requires an authenticated local actor UUID"
            );
            expected.insert(projection.recipient_id, delivery.sender_bare_jid.clone());
        }
    } else if let Some(outbound) = outbound {
        let sender_owner =
            sender_owner.context("outbound retraction sender is not a local owner")?;
        anyhow::ensure!(sender_is_local, "outbound retraction sender is not local");
        expected.insert(sender_owner, outbound.recipient_bare_jid.clone());
    } else {
        let sender_owner = sender_owner.context("retraction sender is not a local owner")?;
        anyhow::ensure!(
            sender_is_local,
            "unprojected retraction sender is not local"
        );
        if owners.len() == 1 {
            expected.insert(sender_owner, owners[0].peer_bare_jid.clone());
        } else {
            let recipient_owner = owners
                .iter()
                .find(|owner| owner.owner_id != sender_owner)
                .context("two-owner retraction omitted its recipient owner")?;
            let recipient_bare = account_bares
                .get(&recipient_owner.owner_id)
                .context("retraction recipient owner account disappeared")?;
            expected.insert(sender_owner, recipient_bare.clone());
            expected.insert(recipient_owner.owner_id, canonical_sender.to_owned());
        }
    }

    anyhow::ensure!(
        owners.len() == expected.len()
            && owners
                .iter()
                .all(|owner| { expected.get(&owner.owner_id) == Some(&owner.peer_bare_jid) }),
        "retraction owner projection is not derived from authenticated principals"
    );
    Ok(())
}

fn validate_stable_id(value: &str, label: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= 1_024 && !value.chars().any(char::is_control),
        "{label} must contain 1 to 1024 non-control bytes"
    );
    Ok(())
}

fn bounded_action_digest(action_id: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"northstar/retraction-action-identity/v1\0");
    update_digest_component(&mut digest, action_id);
    digest.finalize().into()
}

pub(crate) fn retraction_lock_key(sender: &str, action_id: &str) -> i64 {
    let mut digest = Sha256::new();
    digest.update(RETRACTION_LOCK_DOMAIN);
    update_digest_component(&mut digest, sender);
    update_digest_component(&mut digest, action_id);
    let bytes: [u8; 8] = digest.finalize()[..8]
        .try_into()
        .expect("SHA-256 prefix has a fixed length");
    i64::from_be_bytes(bytes)
}

fn canonical_owner_projection(owners: &[NormalizedOwner]) -> Vec<u8> {
    let mut value = b"northstar/retraction-owner-projection/v1\0".to_vec();
    for owner in owners {
        append_bytes_component(&mut value, owner.owner_id.as_bytes());
        append_component(&mut value, &owner.peer_bare_jid);
    }
    value
}

pub(crate) fn canonical_retraction_semantics(
    stanza: &str,
    sender: &str,
    expected_action_id: &str,
    expected_target_id: &str,
) -> Result<Vec<u8>> {
    canonical_retraction_semantics_inner(stanza, sender, expected_action_id, expected_target_id)
}

/// Named transport entry point for the transient-delivery commitment. It uses
/// the same semantic exclusions as durable action identity: server stanza IDs,
/// delay metadata and the locally consumed PoW envelope never change the
/// account-scoped action.
fn canonical_retraction_transport_semantics(
    stanza: &str,
    sender: &str,
    expected_action_id: &str,
    expected_target_id: &str,
) -> Result<Vec<u8>> {
    canonical_retraction_semantics_inner(stanza, sender, expected_action_id, expected_target_id)
}

fn canonical_retraction_semantics_inner(
    stanza: &str,
    sender: &str,
    expected_action_id: &str,
    expected_target_id: &str,
) -> Result<Vec<u8>> {
    let document = Document::parse(stanza).context("retraction action archive is invalid XML")?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "retraction action is not a message"
    );
    anyhow::ensure!(
        root.attribute("id") == Some(expected_action_id),
        "retraction action message id changed"
    );
    if let Some(from) = root.attribute("from") {
        anyhow::ensure!(
            crate::jid::canonical_bare_key(from).ok().as_deref() == Some(sender),
            "retraction action sender changed"
        );
    }
    let mut retracts = root.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "retract"
            && node.tag_name().namespace() == Some(NS_RETRACT)
    });
    let retract = retracts
        .next()
        .context("retraction action lost its retract element")?;
    anyhow::ensure!(
        retracts.next().is_none() && retract.attribute("id") == Some(expected_target_id),
        "retraction action target changed"
    );

    let mut value = b"northstar/retraction-intent/v1\0".to_vec();
    append_component(&mut value, sender);
    append_component(&mut value, expected_action_id);
    append_component(&mut value, expected_target_id);

    let mut root_attributes = root
        .attributes()
        .filter(|attribute| !matches!(attribute.name(), "from" | "to" | "id"))
        .collect::<Vec<_>>();
    root_attributes.sort_by_key(|attribute| {
        (
            attribute.namespace().unwrap_or_default(),
            attribute.name(),
            attribute.value(),
        )
    });
    for attribute in root_attributes {
        append_component(&mut value, attribute.namespace().unwrap_or_default());
        append_component(&mut value, attribute.name());
        append_component(&mut value, attribute.value());
    }
    for child in root.children() {
        if child == retract
            || (child.is_element()
                && child.tag_name().name() == "stanza-id"
                && child.tag_name().namespace() == Some(NS_STANZA_ID))
            || (child.is_element()
                && child.tag_name().name() == "pow"
                && child.tag_name().namespace() == Some(NS_NORTHSTAR_POW))
            || (child.is_element()
                && child.tag_name().name() == "delay"
                && child.tag_name().namespace() == Some("urn:xmpp:delay"))
        {
            continue;
        }
        append_semantic_node(&mut value, child);
    }
    anyhow::ensure!(
        !value.is_empty() && value.len() <= 2_097_152,
        "canonical retraction semantics exceed the durable evidence bound"
    );
    Ok(value)
}

fn append_semantic_node(value: &mut Vec<u8>, node: Node<'_, '_>) {
    if node.is_text() {
        let text = node.text().unwrap_or_default();
        if !text.trim().is_empty() {
            value.extend_from_slice(b"text\0");
            append_component(value, text);
        }
        return;
    }
    if !node.is_element() {
        return;
    }
    value.extend_from_slice(b"element\0");
    append_component(
        value,
        canonical_client_namespace(node.tag_name().namespace()),
    );
    append_component(value, node.tag_name().name());
    let mut attributes = node.attributes().collect::<Vec<_>>();
    attributes.sort_by_key(|attribute| {
        (
            attribute.namespace().unwrap_or_default(),
            attribute.name(),
            attribute.value(),
        )
    });
    for attribute in attributes {
        append_component(value, attribute.namespace().unwrap_or_default());
        append_component(value, attribute.name());
        append_component(value, attribute.value());
    }
    for child in node.children() {
        append_semantic_node(value, child);
    }
    value.extend_from_slice(b"/element\0");
}

fn canonical_client_namespace(namespace: Option<&str>) -> &str {
    match namespace {
        None | Some("jabber:client") | Some("jabber:server") => "",
        Some(namespace) => namespace,
    }
}

fn append_component(value: &mut Vec<u8>, component: &str) {
    append_bytes_component(value, component.as_bytes());
}

fn append_bytes_component(value: &mut Vec<u8>, component: &[u8]) {
    value.extend_from_slice(&(component.len() as u64).to_be_bytes());
    value.extend_from_slice(component);
}

fn update_digest_component(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

pub(crate) fn classify_target(
    stanza: &str,
    sender: &str,
    action_id: &str,
) -> Result<TargetClassification> {
    let document = match Document::parse(stanza) {
        Ok(document) => document,
        Err(_) => return Ok(TargetClassification::Irrelevant),
    };
    let root = document.root_element();
    if root.tag_name().name() != "message" {
        return Ok(TargetClassification::Irrelevant);
    }
    if let Some(retracted) = root.children().find(|node| {
        node.is_element()
            && node.tag_name().name() == "retracted"
            && node.tag_name().namespace() == Some(NS_RETRACT)
    }) {
        return Ok(if retracted.attribute("id") == Some(action_id) {
            TargetClassification::SameTombstone
        } else {
            TargetClassification::ConflictingTombstone
        });
    }
    if !root
        .attribute("from")
        .is_some_and(|from| crate::jid::canonical_bare_key(from).ok().as_deref() == Some(sender))
    {
        return Ok(TargetClassification::ForeignOriginal);
    }
    if !retractable_message(root) {
        return Ok(TargetClassification::Irrelevant);
    }
    Ok(TargetClassification::OwnedOriginal(tombstone_message(
        root, action_id,
    )))
}

pub(crate) fn retractable_message(root: Node<'_, '_>) -> bool {
    if root.attribute("type") == Some("error")
        || root.children().any(|node| {
            node.is_element()
                && matches!(
                    (node.tag_name().namespace(), node.tag_name().name()),
                    (Some("jabber:x:roster"), "x")
                        | (Some("http://jabber.org/protocol/pubsub#event"), "event")
                        | (Some("urn:xmpp:jingle-message:0"), _)
                        | (Some("urn:xmpp:call-invites:0"), _)
                        | (Some("urn:xmpp:receipts"), "received")
                        | (Some("urn:xmpp:chat-markers:0"), "displayed")
                        | (Some("urn:xmpp:reactions:0"), "reactions")
                        | (Some(NS_RETRACT), "retract" | "retracted")
                )
        })
    {
        return false;
    }

    root.children().any(|node| {
        node.is_element()
            && (((matches!(node.tag_name().name(), "body" | "subject")
                && matches!(node.tag_name().namespace(), None | Some("jabber:client")))
                && node.text().is_some_and(|text| !text.is_empty()))
                || crate::xmpp::xml_util::is_encryption_node(node)
                || matches!(
                    (node.tag_name().namespace(), node.tag_name().name()),
                    (Some("urn:xmpp:sfs:0"), "file-sharing")
                        | (Some("jabber:x:oob"), "x")
                        | (Some("http://jabber.org/protocol/xhtml-im"), "html")
                ))
    })
}

pub(crate) fn tombstone_message(original: Node<'_, '_>, retraction_id: &str) -> String {
    let mut message = XmlElement::namespaced("message", "jabber:client");
    for attribute in ["from", "to", "type", "id"] {
        if let Some(value) = original.attribute(attribute) {
            message = message.attr(attribute, value);
        }
    }
    // A tombstone replaces user content, not the server-assigned identity of
    // the archived item.  Retaining structurally valid direct stanza IDs keeps
    // XEP-0313 result IDs and XEP-0359 references stable after a retraction.
    // Rebuild the elements through the typed serializer instead of copying raw
    // XML from durable storage; malformed, nested, or extension-bearing claims
    // are deliberately discarded.
    for stanza_id in original.children().filter_map(|node| {
        if !node.is_element()
            || node.tag_name().namespace() != Some(NS_STANZA_ID)
            || node.tag_name().name() != "stanza-id"
            || node.attributes().len() != 2
            || node
                .attributes()
                .any(|attribute| !matches!(attribute.name(), "id" | "by"))
            || node.children().any(|child| {
                child.is_element()
                    || child.is_comment()
                    || child.is_pi()
                    || child.text().is_some_and(|text| !text.trim().is_empty())
            })
        {
            return None;
        }
        let id = node.attribute("id")?;
        let by = node.attribute("by")?;
        if validate_stable_id(id, "archived stanza id").is_err()
            || crate::jid::CanonicalJid::parse(by).is_err()
        {
            return None;
        }
        Some(
            XmlElement::namespaced("stanza-id", NS_STANZA_ID)
                .attr("id", id)
                .attr("by", by),
        )
    }) {
        message.push_child(stanza_id);
    }
    let stamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    message
        .child(
            XmlElement::namespaced("retracted", NS_RETRACT)
                .attr("stamp", stamp)
                .attr("id", retraction_id),
        )
        .finish()
}

#[cfg(test)]
#[path = "retractions_tests.rs"]
mod tests;
