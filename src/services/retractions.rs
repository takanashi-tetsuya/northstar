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
mod tests {
    use super::*;
    use crate::db;
    use sqlx::PgPool;

    #[tokio::test]
    async fn validation_precedes_persistence_and_repository_failure_remains_an_error() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct UnavailableRepository(AtomicUsize);
        impl RetractionRepository for UnavailableRepository {
            async fn apply_prepared(
                &self,
                prepared: PreparedRetraction<'_>,
            ) -> Result<RetractionOutcome> {
                self.0.fetch_add(1, Ordering::SeqCst);
                assert_eq!(prepared.canonical_sender, "alice@local.test");
                assert_eq!(prepared.normalized_owners.len(), 1);
                assert_eq!(
                    prepared.normalized_owners[0].peer_bare_jid,
                    "bob@remote.test"
                );
                let primary = prepared.semantic_authenticators.primary();
                assert!(crate::abuse::test_personal_retraction_content_keyring()
                    .authenticators(&prepared.canonical_semantics)
                    .verifies(primary.key_id(), primary.mac()));
                anyhow::bail!("injected repository unavailable")
            }
        }

        let service = RetractionService::new(
            UnavailableRepository(AtomicUsize::new(0)),
            crate::abuse::test_personal_retraction_content_keyring(),
            "local.test",
        );
        let command = RetractionCommand {
            target_id: "original",
            action_id: "action",
            semantic_payload: "<message from='alice@local.test/Phone' to='bob@remote.test' id='action'><retract xmlns='urn:xmpp:message-retract:1' id='original'/></message>",
        };
        let owners = [OwnerProjection {
            owner_id: Uuid::new_v4(),
            peer_jid: "bob@remote.test/Tablet",
        }];
        assert!(service
            .apply(&[], "alice@local.test/Phone", &command, &[], None)
            .await
            .is_err());
        let invalid = RetractionCommand {
            target_id: "mismatch",
            ..command
        };
        assert!(service
            .apply(&owners, "alice@local.test/Phone", &invalid, &[], None)
            .await
            .is_err());
        assert_eq!(service.repository.0.load(Ordering::SeqCst), 0);
        let error = service
            .apply(&owners, "alice@local.test/Phone", &command, &[], None)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "injected repository unavailable");
        assert_eq!(service.repository.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn owner_lookup_uses_peer_and_stanza_buckets_with_exists_collision_probe() {
        let migration =
            include_str!("../../migrations/0119_personal_retraction_owner_identity.sql");
        let source = include_str!("../db/retractions.rs");
        assert!(migration.contains("pg_catalog.md5(peer_jid)"));
        assert!(migration.contains("pg_catalog.md5(stanza_id)"));
        assert!(source.contains("pg_catalog.md5(peer_jid)=pg_catalog.md5($2::TEXT)"));
        assert!(source.contains("SELECT EXISTS("));
        assert!(!source.contains("SELECT COUNT(*) FROM message_archive\n                  WHERE owner_id=$1\n                    AND pg_catalog.md5(stanza_id)"));
    }

    #[test]
    fn tombstone_preserves_only_structurally_valid_direct_stanza_ids() {
        let document = Document::parse(
            "<message xmlns='jabber:client' from='alice@example.test/Phone' to='alice@example.test' id='original'>\
             <body>secret</body>\
             <stanza-id xmlns='urn:xmpp:sid:0' id='account-id' by='alice@example.test'/>\
             <stanza-id xmlns='urn:xmpp:sid:0' id='remote-id' by='remote.test'></stanza-id>\
             <stanza-id xmlns='urn:xmpp:sid:0' id='extra-id' by='remote.test' extra='1'/>\
             <wrapper><stanza-id xmlns='urn:xmpp:sid:0' id='nested-id' by='alice@example.test'/></wrapper>\
             <stanza-id xmlns='urn:xmpp:sid:0' id='invalid-by' by='not a jid'/>\
             </message>",
        )
        .unwrap();

        let tombstone = tombstone_message(document.root_element(), "retraction-id");
        let tombstone_document = Document::parse(&tombstone).unwrap();
        let root = tombstone_document.root_element();
        let stanza_ids = root
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(NS_STANZA_ID)
                    && node.tag_name().name() == "stanza-id"
            })
            .map(|node| {
                (
                    node.attribute("id").unwrap().to_owned(),
                    node.attribute("by").unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            stanza_ids,
            vec![
                ("account-id".to_owned(), "alice@example.test".to_owned()),
                ("remote-id".to_owned(), "remote.test".to_owned()),
            ]
        );
        assert!(!tombstone.contains("secret"));
        assert!(!tombstone.contains("extra-id"));
        assert!(!tombstone.contains("nested-id"));
        assert!(!tombstone.contains("invalid-by"));
        assert!(root.children().any(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(NS_RETRACT)
                && node.tag_name().name() == "retracted"
                && node.attribute("id") == Some("retraction-id")
        }));
    }

    async fn isolated_pool() -> (PgPool, PgPool, String) {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to the xmpp_test PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("retraction_service_test_{}", Uuid::new_v4().simple());
        eprintln!("isolated_schema={schema}");
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        (admin, pool, schema)
    }

    async fn archive_original(pool: &PgPool, owner_id: Uuid, id: Uuid, stable_id: &str) {
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'bob@local.test','bob@local.test/Phone',$3,FALSE,$4)",
        )
        .bind(id)
        .bind(owner_id)
        .bind(format!(
            "<message from='alice@local.test/Laptop' to='bob@local.test/Phone' id='{stable_id}'><body>must remain private</body></message>"
        ))
        .bind(stable_id)
        .execute(pool)
        .await
        .unwrap();
    }

    fn action_write<'a>(
        id: Uuid,
        owner_id: Uuid,
        stanza: &'a str,
        action_id: &'a str,
    ) -> ArchiveWrite<'a> {
        ArchiveWrite {
            id,
            owner_id,
            peer_jid: "bob@local.test/Phone",
            stanza,
            encrypted: false,
            stanza_id: Some(action_id),
        }
    }

    #[test]
    fn advisory_lock_uses_a_domain_separated_digest_of_the_complete_identity() {
        let first = retraction_lock_key("alice@example.test", "action-1");
        assert_eq!(first, retraction_lock_key("alice@example.test", "action-1"));
        assert_ne!(first, retraction_lock_key("alice@example.test", "action-2"));
        assert_ne!(
            first,
            retraction_lock_key("mallory@example.test", "action-1")
        );
    }

    #[test]
    fn validates_stable_id_bounds_and_control_characters() {
        assert!(validate_stable_id("normal-id-123", "test id").is_ok());
        assert!(validate_stable_id("", "empty id").is_err());
        let too_long = "a".repeat(1025);
        assert!(validate_stable_id(&too_long, "long id").is_err());
        let exact_max = "a".repeat(1024);
        assert!(validate_stable_id(&exact_max, "max id").is_ok());
        assert!(validate_stable_id("has\nnewline", "control char id").is_err());
        assert!(validate_stable_id("has\0null", "null byte id").is_err());
        assert!(validate_stable_id("has\ttab", "tab char id").is_err());
    }

    #[test]
    fn bounded_action_digest_is_deterministic_and_separated() {
        let d1 = bounded_action_digest("action-1");
        let d2 = bounded_action_digest("action-1");
        let d3 = bounded_action_digest("action-2");
        assert_eq!(d1, d2);
        assert_ne!(d1, d3);
    }

    #[test]
    fn canonical_retraction_semantics_excludes_transport_metadata_and_consumed_pow() {
        let first = "<message from='alice@example.test/Phone' id='action'><body>removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target'/><pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000001' nonce='one'/></message>";
        let retry = "<message from='alice@example.test/Tablet' id='action'><body>removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target'/><delay xmlns='urn:xmpp:delay' from='example.test' stamp='2026-08-31T00:00:00Z'/><pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000002' nonce='two'/></message>";
        let changed = "<message from='alice@example.test/Phone' id='action'><body>different</body><retract xmlns='urn:xmpp:message-retract:1' id='target'/><pow xmlns='urn:northstar:pow:1' challenge='00000000-0000-0000-0000-000000000003' nonce='three'/></message>";
        let canonical = |stanza| {
            canonical_retraction_semantics(stanza, "alice@example.test", "action", "target")
                .unwrap()
        };
        assert_eq!(canonical(first), canonical(retry));
        assert_ne!(canonical(first), canonical(changed));
    }

    #[test]
    fn canonical_owner_projection_formats_and_sorts() {
        let o1 = NormalizedOwner {
            owner_id: Uuid::nil(),
            peer_bare_jid: "bob@example.com".to_owned(),
        };
        let p1 = canonical_owner_projection(&[o1]);
        assert!(!p1.is_empty());
        assert!(p1.starts_with(b"northstar/retraction-owner-projection/v1\0"));
    }

    #[test]
    fn federation_outbox_policy_conversions() {
        let p1 = FederationOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 50,
            max_bytes: 100_000,
            max_per_domain: 20,
        };
        let db_policy: northstar_federation_core::S2sOutboxPolicy = p1.into();
        assert_eq!(db_policy.ttl_seconds, 300);
        assert_eq!(db_policy.max_rows, 50);
        assert_eq!(db_policy.max_bytes, 100_000);
        assert_eq!(db_policy.max_per_domain, 20);
        let p2: FederationOutboxPolicy = db_policy.into();
        assert_eq!(p1, p2);
    }

    #[test]
    fn c2s_missing_to_uses_effective_self_recipient_without_rewriting_xml() {
        let actor_id = Uuid::new_v4();
        let stanza = "<message from='alice@local.test/Phone' id='self-action'><retract xmlns='urn:xmpp:message-retract:1' id='self-target'/></message>";
        let command = RetractionCommand {
            target_id: "self-target",
            action_id: "self-action",
            semantic_payload: stanza,
        };
        let local = DeliveryProjection {
            id: Uuid::new_v4(),
            recipient_id: actor_id,
            local_actor_id: Some(actor_id),
            sender_jid: "alice@local.test/Phone",
            stanza,
            encrypted: false,
            max_messages: 100,
            max_bytes: 1_000_000,
            ttl_days: 30,
            mam_backed: false,
        };
        let normalized =
            normalize_delivery_projection(&local, "alice@local.test", "local.test", &command)
                .unwrap();
        assert_eq!(normalized.recipient_bare_jid, "alice@local.test");
        assert!(normalized.projection.stanza.contains("id='self-action'"));
        assert!(!normalized.projection.stanza.contains(" to="));

        let explicit_stanza = "<message from='alice@local.test/Phone' to='alice@local.test' id='self-action'><retract xmlns='urn:xmpp:message-retract:1' id='self-target'/></message>";
        let explicit = DeliveryProjection {
            stanza: explicit_stanza,
            ..local
        };
        let explicit_normalized =
            normalize_delivery_projection(&explicit, "alice@local.test", "local.test", &command)
                .unwrap();
        assert_eq!(normalized.commitment, explicit_normalized.commitment);

        let explicit_resource_stanza = "<message from='alice@local.test/Phone' to='alice@local.test/Tablet' id='self-action'><retract xmlns='urn:xmpp:message-retract:1' id='self-target'/></message>";
        let explicit_resource = DeliveryProjection {
            stanza: explicit_resource_stanza,
            ..local
        };
        let explicit_resource_normalized = normalize_delivery_projection(
            &explicit_resource,
            "alice@local.test",
            "local.test",
            &command,
        )
        .unwrap();
        assert_ne!(
            normalized.commitment,
            explicit_resource_normalized.commitment
        );

        let federated_stanza = "<message from='alice@remote.test/Phone' id='self-action'><retract xmlns='urn:xmpp:message-retract:1' id='self-target'/></message>";
        let federated_command = RetractionCommand {
            semantic_payload: federated_stanza,
            ..command
        };
        let federated = DeliveryProjection {
            local_actor_id: None,
            sender_jid: "alice@remote.test/Phone",
            stanza: federated_stanza,
            ..local
        };
        assert!(normalize_delivery_projection(
            &federated,
            "alice@remote.test",
            "local.test",
            &federated_command,
        )
        .is_err());
    }

    #[test]
    fn inbound_s2s_full_normal_delivery_identity_binds_the_exact_resource() {
        let recipient_id = Uuid::new_v4();
        let phone_stanza = "<message from='alice@remote.test/Phone' to='bob@local.test/Phone' id='remote-action'><retract xmlns='urn:xmpp:message-retract:1' id='remote-target'/></message>";
        let tablet_stanza = "<message from='alice@remote.test/Tablet' to='bob@local.test/Tablet' id='remote-action'><retract xmlns='urn:xmpp:message-retract:1' id='remote-target'/></message>";
        let phone_command = RetractionCommand {
            target_id: "remote-target",
            action_id: "remote-action",
            semantic_payload: phone_stanza,
        };
        let tablet_command = RetractionCommand {
            semantic_payload: tablet_stanza,
            ..phone_command
        };
        let phone = DeliveryProjection {
            id: Uuid::new_v4(),
            recipient_id,
            local_actor_id: None,
            sender_jid: "alice@remote.test/Phone",
            stanza: phone_stanza,
            encrypted: false,
            max_messages: 100,
            max_bytes: 1_000_000,
            ttl_days: 30,
            mam_backed: false,
        };
        let tablet = DeliveryProjection {
            id: Uuid::new_v4(),
            sender_jid: "alice@remote.test/Tablet",
            stanza: tablet_stanza,
            ..phone
        };
        let phone = normalize_delivery_projection(
            &phone,
            "alice@remote.test",
            "local.test",
            &phone_command,
        )
        .unwrap();
        let tablet = normalize_delivery_projection(
            &tablet,
            "alice@remote.test",
            "local.test",
            &tablet_command,
        )
        .unwrap();
        assert_eq!(phone.recipient_bare_jid, "bob@local.test");
        assert_eq!(
            phone.target_full_jid.as_deref(),
            Some("bob@local.test/Phone")
        );
        assert_eq!(
            tablet.target_full_jid.as_deref(),
            Some("bob@local.test/Tablet")
        );
        assert_ne!(phone.commitment, tablet.commitment);
    }

    #[test]
    fn outbound_projection_rejects_a_configured_local_target() {
        let command = RetractionCommand {
            target_id: "target",
            action_id: "action",
            semantic_payload: "<message from='alice@local.test/Phone' to='bob@local.test' id='action'><retract xmlns='urn:xmpp:message-retract:1' id='target'/></message>",
        };
        let semantics = canonical_retraction_semantics(
            command.semantic_payload,
            "alice@local.test",
            command.action_id,
            command.target_id,
        )
        .unwrap();
        let outbound = OutboundProjection {
            target_domain: "local.test",
            stanza: command.semantic_payload,
            bounce_to: Some("alice@local.test/Phone"),
            policy: FederationOutboxPolicy {
                ttl_seconds: 300,
                max_rows: 50,
                max_bytes: 100_000,
                max_per_domain: 20,
            },
        };
        assert!(normalize_outbound_projection(
            &outbound,
            "alice@local.test",
            "local.test",
            &semantics,
            &command,
        )
        .is_err());

        let domain_command = RetractionCommand {
            semantic_payload: "<message from='alice@local.test/Phone' to='remote.test' id='action'><retract xmlns='urn:xmpp:message-retract:1' id='target'/></message>",
            ..command
        };
        let domain_semantics = canonical_retraction_semantics(
            domain_command.semantic_payload,
            "alice@local.test",
            domain_command.action_id,
            domain_command.target_id,
        )
        .unwrap();
        let domain_outbound = OutboundProjection {
            target_domain: "remote.test",
            stanza: domain_command.semantic_payload,
            ..outbound
        };
        assert!(normalize_outbound_projection(
            &domain_outbound,
            "alice@local.test",
            "local.test",
            &domain_semantics,
            &domain_command,
        )
        .is_err());
    }

    #[test]
    fn personal_retraction_invocation_dto_contract() {
        let owner_id = Uuid::new_v4();
        let owners = [OwnerProjection {
            owner_id,
            peer_jid: "bob@example.com",
        }];
        let cmd = RetractionCommand {
            target_id: "target-1",
            action_id: "action-1",
            semantic_payload: "<message id='action-1'><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
        };
        let writes = [ArchiveWrite {
            id: Uuid::new_v4(),
            owner_id,
            peer_jid: "bob@example.com",
            stanza: "<message id='action-1'><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
            encrypted: false,
            stanza_id: Some("action-1"),
        }];
        let invocation = PersonalRetractionInvocation {
            owners: &owners,
            sender_jid: "alice@example.com",
            command: cmd,
            action_writes: &writes,
            delivery: None,
            outbound: None,
        };
        assert_eq!(invocation.owners.len(), 1);
        assert_eq!(invocation.sender_jid, "alice@example.com");
        assert_eq!(invocation.command.target_id, "target-1");
        assert_eq!(invocation.action_writes.len(), 1);
        assert!(invocation.delivery.is_none());
        assert!(invocation.outbound.is_none());
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn c2s_projection_is_atomic_idempotent_and_retains_replay_intent() {
        let (admin, pool, schema) = isolated_pool().await;
        let owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'alice','test')")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();
        let other_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'bob','test')")
            .bind(other_id)
            .execute(&pool)
            .await
            .unwrap();
        let service = RetractionService::new(
            crate::db::retractions::PostgresRetractionRepository::new(pool.clone()),
            crate::abuse::test_personal_retraction_content_keyring(),
            "local.test",
        );
        let owners = [OwnerProjection {
            owner_id,
            peer_jid: "alice@local.test/Phone",
        }];

        let target_row = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'alice@local.test','alice@local.test/Phone',$3,FALSE,'delivery-target')",
        )
        .bind(target_row)
        .bind(owner_id)
        .bind("<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='delivery-target'><body>must remain private</body></message>")
        .execute(&pool)
        .await
        .unwrap();
        let action = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='delivery-action'><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>";
        let command = RetractionCommand {
            target_id: "delivery-target",
            action_id: "delivery-action",
            semantic_payload: action,
        };
        let action_rows = [ArchiveWrite {
            id: Uuid::new_v4(),
            owner_id,
            peer_jid: "alice@local.test/Phone",
            stanza: action,
            encrypted: false,
            stanza_id: Some(command.action_id),
        }];
        let delivery_id = Uuid::new_v4();
        let delivery = DeliveryProjection {
            id: delivery_id,
            recipient_id: owner_id,
            local_actor_id: Some(owner_id),
            sender_jid: "alice@local.test/Laptop",
            stanza: action,
            encrypted: false,
            max_messages: 100,
            max_bytes: 1_000_000,
            ttl_days: 30,
            mam_backed: true,
        };
        assert_eq!(
            service
                .apply_with_delivery(
                    &owners,
                    "alice@local.test/Laptop",
                    &command,
                    &action_rows,
                    Some(&delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Applied { tombstones: 1 }
        );
        let committed: (i64, i64, i64, bool, Option<Uuid>) = sqlx::query_as(
            "SELECT
               (SELECT COUNT(*) FROM message_archive WHERE id=$1 AND stanza LIKE '%retracted%'),
               (SELECT COUNT(*) FROM message_archive WHERE stanza_id='delivery-action'),
               (SELECT COUNT(*) FROM offline_messages WHERE id=$2),
               intent.c2s_delivery_requested,intent.c2s_delivery_id
             FROM personal_retraction_intents intent
             WHERE intent.action_id='delivery-action'",
        )
        .bind(target_row)
        .bind(delivery_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(committed, (1, 1, 1, true, Some(delivery_id)));
        assert!(sqlx::query(
            "UPDATE personal_retraction_intents
                SET c2s_projection_mac=decode(repeat('aa',32),'hex')
              WHERE action_id='delivery-action'",
        )
        .execute(&pool)
        .await
        .is_err());
        assert!(sqlx::query(
            "UPDATE personal_retraction_intents
                SET owner_projection_mac=decode(repeat('bb',32),'hex')
              WHERE action_id='delivery-action'",
        )
        .execute(&pool)
        .await
        .is_err());

        let replay_delivery = DeliveryProjection {
            id: Uuid::new_v4(),
            ..delivery
        };
        assert_eq!(
            service
                .apply_with_delivery(
                    &owners,
                    "alice@local.test/Other",
                    &command,
                    &action_rows,
                    Some(&replay_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Replay
        );
        let delivery_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(delivery_count, 1, "exact replay must not fan out twice");
        let changed_action_archive = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='delivery-action'><body>changed fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>";
        sqlx::query(
            "UPDATE message_archive SET stanza=$1
              WHERE owner_id=$2 AND stanza_id='delivery-action'",
        )
        .bind(changed_action_archive)
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            service
                .apply_with_delivery(
                    &owners,
                    "alice@local.test/Other",
                    &command,
                    &action_rows,
                    Some(&replay_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Conflict,
            "a syntactically valid but changed action archive must fail closed"
        );
        sqlx::query(
            "UPDATE message_archive SET stanza=$1
              WHERE owner_id=$2 AND stanza_id='delivery-action'",
        )
        .bind(action)
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE message_archive SET encrypted=TRUE
              WHERE owner_id=$1 AND stanza_id='delivery-action'",
        )
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            service
                .apply_with_delivery(
                    &owners,
                    "alice@local.test/Other",
                    &command,
                    &action_rows,
                    Some(&replay_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Conflict,
            "the stored encrypted flag must agree with both XML and authenticated action"
        );
        sqlx::query(
            "UPDATE message_archive SET encrypted=FALSE
              WHERE owner_id=$1 AND stanza_id='delivery-action'",
        )
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
        let changed_recipient_stanza = "<message from='alice@local.test/Laptop' to='alice@local.test/Tablet' id='delivery-action'><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>";
        let changed_recipient_delivery = DeliveryProjection {
            id: Uuid::new_v4(),
            stanza: changed_recipient_stanza,
            ..delivery
        };
        assert_eq!(
            service
                .apply_with_delivery(
                    &owners,
                    "alice@local.test/Laptop",
                    &command,
                    &action_rows,
                    Some(&changed_recipient_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Conflict,
            "changing the canonical delivery target must conflict before fanout"
        );
        let swapped_owners = [
            OwnerProjection {
                owner_id,
                peer_jid: "bob@local.test/Phone",
            },
            OwnerProjection {
                owner_id: other_id,
                peer_jid: "alice@local.test/Laptop",
            },
        ];
        let swapped_stanza = "<message from='alice@local.test/Laptop' to='bob@local.test/Phone' id='delivery-action'><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>";
        let swapped_delivery = DeliveryProjection {
            id: Uuid::new_v4(),
            recipient_id: other_id,
            local_actor_id: Some(owner_id),
            stanza: swapped_stanza,
            mam_backed: false,
            ..delivery
        };
        assert_eq!(
            service
                .apply_with_delivery(
                    &swapped_owners,
                    "alice@local.test/Laptop",
                    &command,
                    &[],
                    Some(&swapped_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Conflict,
            "a retry cannot swap the recipient owner projection"
        );
        let forged_owners = [OwnerProjection {
            owner_id,
            peer_jid: "mallory@local.test/Phone",
        }];
        assert!(service
            .apply_with_delivery(
                &forged_owners,
                "alice@local.test/Laptop",
                &command,
                &[],
                Some(&replay_delivery),
                None,
            )
            .await
            .is_err());
        let missing_owner_delivery = DeliveryProjection {
            id: Uuid::new_v4(),
            recipient_id: Uuid::new_v4(),
            mam_backed: false,
            ..delivery
        };
        assert_eq!(
            service
                .apply_with_delivery(
                    &owners,
                    "alice@local.test/Laptop",
                    &command,
                    &[],
                    Some(&missing_owner_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::AccountUnavailable
        );
        let changed = RetractionCommand {
            semantic_payload: "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='delivery-action'><body>changed</body><retract xmlns='urn:xmpp:message-retract:1' id='delivery-target'/></message>",
            ..command
        };
        let changed_payload_rows = [ArchiveWrite {
            stanza: changed.semantic_payload,
            ..action_rows[0]
        }];
        let changed_payload_delivery = DeliveryProjection {
            id: Uuid::new_v4(),
            stanza: changed.semantic_payload,
            ..delivery
        };
        assert_eq!(
            service
                .apply_with_delivery(
                    &owners,
                    "alice@local.test/Laptop",
                    &changed,
                    &changed_payload_rows,
                    Some(&changed_payload_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Conflict
        );

        sqlx::query(
            "UPDATE personal_retraction_intents
                SET expires_at=clock_timestamp()-INTERVAL '1 day'
              WHERE action_id='delivery-action'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            db::purge_expired_retraction_intents(&pool, 10)
                .await
                .unwrap(),
            0
        );
        sqlx::query("DELETE FROM offline_messages WHERE id=$1")
            .bind(delivery_id)
            .execute(&pool)
            .await
            .unwrap();
        let cleared: (bool, Option<Uuid>) = sqlx::query_as(
            "SELECT c2s_delivery_requested,c2s_delivery_id
               FROM personal_retraction_intents WHERE action_id='delivery-action'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(cleared, (true, None));
        assert_eq!(
            db::purge_expired_retraction_intents(&pool, 10)
                .await
                .unwrap(),
            1
        );

        let capacity_target = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'alice@local.test','alice@local.test/Phone',$3,FALSE,'capacity-target')",
        )
        .bind(capacity_target)
        .bind(owner_id)
        .bind("<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='capacity-target'><body>must remain private</body></message>")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,mam_backed)
             VALUES($1,$2,'seed@local.test','<message/>',FALSE,FALSE)",
        )
        .bind(Uuid::new_v4())
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
        let capacity_action = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='capacity-action'><retract xmlns='urn:xmpp:message-retract:1' id='capacity-target'/></message>";
        let capacity_command = RetractionCommand {
            target_id: "capacity-target",
            action_id: "capacity-action",
            semantic_payload: capacity_action,
        };
        let capacity_delivery = DeliveryProjection {
            id: Uuid::new_v4(),
            recipient_id: owner_id,
            local_actor_id: Some(owner_id),
            sender_jid: "alice@local.test/Laptop",
            stanza: capacity_action,
            encrypted: false,
            max_messages: 1,
            max_bytes: 1_000_000,
            ttl_days: 30,
            mam_backed: false,
        };
        assert_eq!(
            service
                .apply_with_delivery(
                    &owners,
                    "alice@local.test/Laptop",
                    &capacity_command,
                    &[],
                    Some(&capacity_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::CapacityExceeded
        );
        let capacity_rollback: (String, i64) = sqlx::query_as(
            "SELECT
               (SELECT stanza FROM message_archive WHERE id=$1),
               (SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id='capacity-action')",
        )
        .bind(capacity_target)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(capacity_rollback.0.contains("must remain private"));
        assert_eq!(capacity_rollback.1, 0);

        let forbidden_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'alice@local.test','alice@local.test/Phone',$3,FALSE,'foreign-target')",
        )
        .bind(forbidden_id)
        .bind(owner_id)
        .bind("<message from='mallory@local.test/Phone' id='foreign-target'><body>foreign</body></message>")
        .execute(&pool)
        .await
        .unwrap();
        let forbidden_action = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='forbidden-action'><retract xmlns='urn:xmpp:message-retract:1' id='foreign-target'/></message>";
        let forbidden_command = RetractionCommand {
            target_id: "foreign-target",
            action_id: "forbidden-action",
            semantic_payload: forbidden_action,
        };
        let forbidden_delivery = DeliveryProjection {
            id: Uuid::new_v4(),
            stanza: forbidden_action,
            max_messages: 100,
            ..capacity_delivery
        };
        assert_eq!(
            service
                .apply_with_delivery(
                    &owners,
                    "alice@local.test/Laptop",
                    &forbidden_command,
                    &[],
                    Some(&forbidden_delivery),
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Forbidden
        );
        let forbidden_projection: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(forbidden_delivery.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(forbidden_projection, 0);

        sqlx::query("DELETE FROM offline_messages")
            .execute(&pool)
            .await
            .unwrap();
        let failure_target = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'alice@local.test','alice@local.test/Phone',$3,FALSE,'failure-target')",
        )
        .bind(failure_target)
        .bind(owner_id)
        .bind("<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='failure-target'><body>must remain private</body></message>")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE FUNCTION reject_retraction_delivery() RETURNS TRIGGER AS $$
             BEGIN RAISE EXCEPTION 'injected delivery failure'; END
             $$ LANGUAGE plpgsql",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_retraction_delivery AFTER INSERT ON offline_messages
             FOR EACH ROW EXECUTE FUNCTION reject_retraction_delivery()",
        )
        .execute(&pool)
        .await
        .unwrap();
        let failure_action = "<message from='alice@local.test/Laptop' to='alice@local.test/Phone' id='failure-action'><retract xmlns='urn:xmpp:message-retract:1' id='failure-target'/></message>";
        let failure_command = RetractionCommand {
            target_id: "failure-target",
            action_id: "failure-action",
            semantic_payload: failure_action,
        };
        let failure_delivery = DeliveryProjection {
            id: Uuid::new_v4(),
            stanza: failure_action,
            max_messages: 100,
            ..capacity_delivery
        };
        assert!(service
            .apply_with_delivery(
                &owners,
                "alice@local.test/Laptop",
                &failure_command,
                &[],
                Some(&failure_delivery),
                None,
            )
            .await
            .is_err());
        let failure_rollback: (String, i64, i64) = sqlx::query_as(
            "SELECT
               (SELECT stanza FROM message_archive WHERE id=$1),
               (SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id='failure-action'),
               (SELECT COUNT(*) FROM offline_messages WHERE id=$2)",
        )
        .bind(failure_target)
        .bind(failure_delivery.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(failure_rollback.0.contains("must remain private"));
        assert_eq!((failure_rollback.1, failure_rollback.2), (0, 0));

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn exact_replay_conflict_and_outbox_failure_are_atomic() {
        let (admin, pool, schema) = isolated_pool().await;
        let owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'alice','test')")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();

        let service = RetractionService::new(
            crate::db::retractions::PostgresRetractionRepository::new(pool.clone()),
            crate::abuse::test_personal_retraction_content_keyring(),
            "local.test",
        );
        let owners = [OwnerProjection {
            owner_id,
            peer_jid: "bob@local.test/Phone",
        }];
        let outbound_owners = [OwnerProjection {
            owner_id,
            peer_jid: "bob@remote.test/Phone",
        }];
        let target_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'bob@remote.test','bob@remote.test/Phone',$3,FALSE,'target-1')",
        )
        .bind(target_id)
        .bind(owner_id)
        .bind("<message from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='target-1'><body>must remain private</body></message>")
        .execute(&pool)
        .await
        .unwrap();

        let accepted = "<message from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>";
        let archived = "<message xmlns='jabber:client' from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/><stanza-id xmlns='urn:xmpp:sid:0' by='local.test' id='server-one'/></message>";
        let command = RetractionCommand {
            target_id: "target-1",
            action_id: "action-1",
            semantic_payload: accepted,
        };
        let writes = [ArchiveWrite {
            id: Uuid::new_v4(),
            owner_id,
            peer_jid: "bob@remote.test/Phone",
            stanza: archived,
            encrypted: false,
            stanza_id: Some(command.action_id),
        }];
        let outbox = OutboundProjection {
            target_domain: "remote.test",
            stanza: "<message from='alice@local.test' to='bob@remote.test' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
            bounce_to: Some("alice@local.test/Laptop"),
            policy: FederationOutboxPolicy {
                ttl_seconds: 300,
                max_rows: 100,
                max_bytes: 1_000_000,
                max_per_domain: 100,
            },
        };
        assert_eq!(
            service
                .apply(
                    &outbound_owners,
                    "alice@local.test/Laptop",
                    &command,
                    &writes,
                    Some(&outbox),
                )
                .await
                .unwrap(),
            RetractionOutcome::Applied { tombstones: 1 }
        );

        assert_eq!(
            service
                .apply(
                    &outbound_owners,
                    "alice@local.test/Laptop",
                    &command,
                    &[],
                    Some(&outbox),
                )
                .await
                .unwrap(),
            RetractionOutcome::Replay,
            "disabling MAM after admission must not change replay identity"
        );

        let replay_archive = "<message xmlns='jabber:client' from='alice@local.test/Other' to='bob@remote.test/Tablet' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/><stanza-id xmlns='urn:xmpp:sid:0' by='local.test' id='server-two'/></message>";
        let replay_writes = [ArchiveWrite {
            id: Uuid::new_v4(),
            owner_id,
            peer_jid: "bob@remote.test/Tablet",
            stanza: replay_archive,
            encrypted: false,
            stanza_id: Some(command.action_id),
        }];
        assert_eq!(
            service
                .apply(
                    &outbound_owners,
                    "alice@local.test/Other",
                    &command,
                    &replay_writes,
                    Some(&outbox),
                )
                .await
                .unwrap(),
            RetractionOutcome::Replay
        );
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT
               (SELECT COUNT(*) FROM message_archive WHERE owner_id=$1 AND stanza_id='action-1'),
               (SELECT COUNT(*) FROM s2s_outbox)",
        )
        .bind(owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            counts,
            (1, 1),
            "exact replay must not duplicate projections"
        );

        let changed_payload = RetractionCommand {
            semantic_payload: "<message from='alice@local.test/Laptop' id='action-1'><body>changed fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
            ..command
        };
        let changed_payload_outbox = OutboundProjection {
            stanza: "<message from='alice@local.test' to='bob@remote.test' id='action-1'><body>changed fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>",
            ..outbox
        };
        assert_eq!(
            service
                .apply(
                    &outbound_owners,
                    "alice@local.test/Laptop",
                    &changed_payload,
                    &[],
                    Some(&changed_payload_outbox),
                )
                .await
                .unwrap(),
            RetractionOutcome::Conflict
        );
        let changed_target = RetractionCommand {
            target_id: "different-target",
            semantic_payload: "<message from='alice@local.test/Laptop' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='different-target'/></message>",
            ..command
        };
        let changed_target_outbox = OutboundProjection {
            stanza: "<message from='alice@local.test' to='bob@remote.test' id='action-1'><body>message removed</body><retract xmlns='urn:xmpp:message-retract:1' id='different-target'/></message>",
            ..outbox
        };
        assert_eq!(
            service
                .apply(
                    &outbound_owners,
                    "alice@local.test/Laptop",
                    &changed_target,
                    &[],
                    Some(&changed_target_outbox),
                )
                .await
                .unwrap(),
            RetractionOutcome::Conflict
        );

        // Archiving may be disabled by policy. The independent intent row is
        // still the replay authority, so a tombstone never has to stand in for
        // the omitted action archive.
        let zero_target_id = Uuid::new_v4();
        archive_original(&pool, owner_id, zero_target_id, "zero-target").await;
        let zero_action = "<message from='alice@local.test/Laptop' id='zero-action'><body>private fallback must not be stored</body><retract xmlns='urn:xmpp:message-retract:1' id='zero-target'/></message>";
        let zero_command = RetractionCommand {
            target_id: "zero-target",
            action_id: "zero-action",
            semantic_payload: zero_action,
        };
        assert_eq!(
            service
                .apply(&owners, "alice@local.test/Laptop", &zero_command, &[], None,)
                .await
                .unwrap(),
            RetractionOutcome::Applied { tombstones: 1 }
        );
        // Emulate a row created by 0102 before keyed commitments existed.
        // The first exact replay must upgrade it and commit that upgrade even
        // though no message/outbox projection is added.
        let legacy_zero_semantic = canonical_retraction_semantics(
            zero_action,
            "alice@local.test",
            zero_command.action_id,
            zero_command.target_id,
        )
        .unwrap();
        sqlx::query(
            "UPDATE personal_retraction_intents
                SET semantic_key_id=NULL,semantic_mac=NULL,
                    semantic_sha256=$2,semantic_sha512=$3,semantic_length=$4
              WHERE action_id=$1",
        )
        .bind(zero_command.action_id)
        .bind(Sha256::digest(&legacy_zero_semantic).to_vec())
        .bind(Sha512::digest(&legacy_zero_semantic).to_vec())
        .bind(i64::try_from(legacy_zero_semantic.len()).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        let newly_enabled_write = [action_write(
            Uuid::new_v4(),
            owner_id,
            zero_action,
            zero_command.action_id,
        )];
        assert_eq!(
            service
                .apply(
                    &owners,
                    "alice@local.test/Laptop",
                    &zero_command,
                    &newly_enabled_write,
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Replay,
            "enabling MAM after a zero-write admission must not add a projection"
        );
        type RetractionEvidenceColumns = (
            Option<String>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<i64>,
        );
        let upgraded_zero_evidence: RetractionEvidenceColumns = sqlx::query_as(
            "SELECT semantic_key_id,semantic_mac,semantic_sha256,semantic_sha512,semantic_length
               FROM personal_retraction_intents WHERE action_id='zero-action'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(upgraded_zero_evidence.0.is_some());
        assert_eq!(
            upgraded_zero_evidence.1.as_deref().map(<[u8]>::len),
            Some(32)
        );
        assert_eq!(
            (
                upgraded_zero_evidence.2,
                upgraded_zero_evidence.3,
                upgraded_zero_evidence.4
            ),
            (None, None, None),
            "legacy unkeyed evidence must be irreversibly removed after upgrade"
        );

        // Rows created before 0119 cannot be proactively re-keyed without
        // recovering peer topology. An authorized exact replay supplies that
        // topology and performs the only owner-identity transition permitted
        // by the immutable database fence.
        let legacy_owner_action = "<message from='alice@local.test/Laptop' id='legacy-owner-action'><retract xmlns='urn:xmpp:message-retract:1' id='legacy-owner-target'/></message>";
        let legacy_owner_command = RetractionCommand {
            target_id: "legacy-owner-target",
            action_id: "legacy-owner-action",
            semantic_payload: legacy_owner_action,
        };
        let legacy_owner_semantics = canonical_retraction_semantics(
            legacy_owner_action,
            "alice@local.test",
            legacy_owner_command.action_id,
            legacy_owner_command.target_id,
        )
        .unwrap();
        let semantic_authenticators = service
            .content_identity
            .authenticators(&legacy_owner_semantics);
        let semantic_primary = semantic_authenticators.primary();
        let normalized_legacy_owners = [NormalizedOwner {
            owner_id,
            peer_bare_jid: "bob@local.test".to_owned(),
        }];
        let legacy_owner_value = canonical_owner_projection(&normalized_legacy_owners);
        let legacy_owner_intent_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO personal_retraction_intents(
                 id,sender_bare_jid,action_id,action_digest,target_id,
                 semantic_key_id,semantic_mac,
                 owner_projection_sha256,owner_projection_sha512,
                 owner_projection_length,outbound_requested)
             VALUES($1,'alice@local.test',$2,$3,$4,$5,$6,$7,$8,$9,FALSE)",
        )
        .bind(legacy_owner_intent_id)
        .bind(legacy_owner_command.action_id)
        .bind(bounded_action_digest(legacy_owner_command.action_id).to_vec())
        .bind(legacy_owner_command.target_id)
        .bind(semantic_primary.key_id())
        .bind(semantic_primary.mac().as_slice())
        .bind(Sha256::digest(&legacy_owner_value).to_vec())
        .bind(Sha512::digest(&legacy_owner_value).to_vec())
        .bind(i64::try_from(legacy_owner_value.len()).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            service
                .apply(
                    &owners,
                    "alice@local.test/Other",
                    &legacy_owner_command,
                    &[],
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Replay
        );
        type OwnerEvidenceColumns = (
            Option<String>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<i64>,
        );
        let upgraded_owner_evidence: OwnerEvidenceColumns = sqlx::query_as(
            "SELECT owner_projection_key_id,owner_projection_mac,
                    owner_projection_sha256,owner_projection_sha512,
                    owner_projection_length
               FROM personal_retraction_intents WHERE id=$1",
        )
        .bind(legacy_owner_intent_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(upgraded_owner_evidence.0.is_some());
        assert_eq!(
            upgraded_owner_evidence.1.as_deref().map(<[u8]>::len),
            Some(32)
        );
        assert_eq!(
            (
                upgraded_owner_evidence.2,
                upgraded_owner_evidence.3,
                upgraded_owner_evidence.4
            ),
            (None, None, None)
        );
        let unexpected_zero_projection: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM message_archive WHERE owner_id=$1 AND stanza_id='zero-action'",
        )
        .bind(owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unexpected_zero_projection, 0);
        let zero_replay = RetractionCommand {
            semantic_payload: "<message from='alice@local.test/Other' id='zero-action'><body>private fallback must not be stored</body><retract xmlns='urn:xmpp:message-retract:1' id='zero-target'/><stanza-id xmlns='urn:xmpp:sid:0' by='local.test' id='ignored-server-id'/></message>",
            ..zero_command
        };
        assert_eq!(
            service
                .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
                .await
                .unwrap(),
            RetractionOutcome::Replay
        );
        let zero_changed_payload = RetractionCommand {
            semantic_payload: "<message from='alice@local.test/Laptop' id='zero-action'><body>changed private fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='zero-target'/></message>",
            ..zero_command
        };
        assert_eq!(
            service
                .apply(
                    &owners,
                    "alice@local.test/Laptop",
                    &zero_changed_payload,
                    &[],
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Conflict
        );
        let zero_changed_target = RetractionCommand {
            target_id: "changed-zero-target",
            semantic_payload: "<message from='alice@local.test/Laptop' id='zero-action'><body>private fallback must not be stored</body><retract xmlns='urn:xmpp:message-retract:1' id='changed-zero-target'/></message>",
            ..zero_command
        };
        assert_eq!(
            service
                .apply(
                    &owners,
                    "alice@local.test/Laptop",
                    &zero_changed_target,
                    &[],
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Conflict
        );
        sqlx::query(
            "UPDATE personal_retraction_intents
                SET semantic_mac=decode(repeat('cc',32),'hex')
              WHERE action_id='zero-action'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            service
                .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
                .await
                .unwrap(),
            RetractionOutcome::Conflict,
            "a known key ID with a changed semantic MAC must fail closed"
        );
        sqlx::query(
            "UPDATE personal_retraction_intents
                SET semantic_key_id=NULL,semantic_mac=NULL,
                    semantic_sha256=$2,semantic_sha512=$3,semantic_length=$4
              WHERE action_id=$1",
        )
        .bind(zero_command.action_id)
        .bind(Sha256::digest(&legacy_zero_semantic).to_vec())
        .bind(Sha512::digest(&legacy_zero_semantic).to_vec())
        .bind(i64::try_from(legacy_zero_semantic.len()).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            service
                .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
                .await
                .unwrap(),
            RetractionOutcome::Replay
        );
        sqlx::query(
            "UPDATE personal_retraction_intents
                SET semantic_key_id='BBBBBBBBBBBBBBBB'
              WHERE action_id='zero-action'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            service
                .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
                .await
                .unwrap(),
            RetractionOutcome::Conflict,
            "an unknown content-key generation must fail closed"
        );
        assert!(
            sqlx::query(
                "UPDATE personal_retraction_intents
                SET semantic_key_id=NULL,semantic_sha256=NULL
              WHERE action_id='zero-action'",
            )
            .execute(&pool)
            .await
            .is_err(),
            "partial retraction evidence must fail the database constraint"
        );
        sqlx::query(
            "UPDATE personal_retraction_intents
                SET semantic_key_id=NULL,semantic_mac=NULL,
                    semantic_sha256=$2,semantic_sha512=$3,semantic_length=$4
              WHERE action_id=$1",
        )
        .bind(zero_command.action_id)
        .bind(Sha256::digest(&legacy_zero_semantic).to_vec())
        .bind(Sha512::digest(&legacy_zero_semantic).to_vec())
        .bind(i64::try_from(legacy_zero_semantic.len()).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            service
                .apply(&owners, "alice@local.test/Other", &zero_replay, &[], None,)
                .await
                .unwrap(),
            RetractionOutcome::Replay
        );
        let plaintext_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns
              WHERE table_schema=current_schema()
                AND table_name='personal_retraction_intents'
                AND column_name IN ('semantic_value','payload_value','stanza')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            plaintext_columns, 0,
            "intent evidence must never retain fallback XML"
        );
        let plaintext_row_marker: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM personal_retraction_intents AS intent
              WHERE row_to_json(intent)::TEXT LIKE '%private fallback must not be stored%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            plaintext_row_marker, 0,
            "a database dump of retraction intents must not contain fallback plaintext"
        );
        sqlx::query(
            "UPDATE personal_retraction_intents
                SET expires_at=clock_timestamp()-INTERVAL '1 day'
              WHERE action_id IN ('action-1','zero-action')",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            db::purge_expired_retraction_intents(&pool, 10)
                .await
                .unwrap(),
            1
        );
        let retained_outbox_intent: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id='action-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            retained_outbox_intent, 1,
            "expiry must not delete evidence while its durable outbox is pending"
        );

        // A two-owner replay is complete only when every expected action
        // archive projection exists. One surviving projection is a conflict,
        // never a successful replay.
        let second_owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'bob','test')")
            .bind(second_owner_id)
            .execute(&pool)
            .await
            .unwrap();
        let partial_targets = [Uuid::new_v4(), Uuid::new_v4()];
        for (id, owner, peer, full_peer) in [
            (
                partial_targets[0],
                owner_id,
                "bob@local.test",
                "bob@local.test/Phone",
            ),
            (
                partial_targets[1],
                second_owner_id,
                "alice@local.test",
                "alice@local.test/Laptop",
            ),
        ] {
            sqlx::query(
                "INSERT INTO message_archive
                 (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
                 VALUES($1,$2,$3,$4,$5,FALSE,'partial-target')",
            )
            .bind(id)
            .bind(owner)
            .bind(peer)
            .bind(full_peer)
            .bind("<message from='alice@local.test/Laptop' to='bob@local.test/Phone' id='partial-target'><body>two copies</body></message>")
            .execute(&pool)
            .await
            .unwrap();
        }
        let partial_owners = [
            OwnerProjection {
                owner_id,
                peer_jid: "bob@local.test/Phone",
            },
            OwnerProjection {
                owner_id: second_owner_id,
                peer_jid: "alice@local.test/Laptop",
            },
        ];
        let partial_action = "<message from='alice@local.test/Laptop' id='partial-action'><retract xmlns='urn:xmpp:message-retract:1' id='partial-target'/></message>";
        let partial_command = RetractionCommand {
            target_id: "partial-target",
            action_id: "partial-action",
            semantic_payload: partial_action,
        };
        let partial_action_ids = [Uuid::new_v4(), Uuid::new_v4()];
        let partial_writes = [
            ArchiveWrite {
                id: partial_action_ids[0],
                owner_id,
                peer_jid: "bob@local.test/Phone",
                stanza: partial_action,
                encrypted: false,
                stanza_id: Some("partial-action"),
            },
            ArchiveWrite {
                id: partial_action_ids[1],
                owner_id: second_owner_id,
                peer_jid: "alice@local.test/Laptop",
                stanza: partial_action,
                encrypted: false,
                stanza_id: Some("partial-action"),
            },
        ];
        assert_eq!(
            service
                .apply(
                    &partial_owners,
                    "alice@local.test/Laptop",
                    &partial_command,
                    &partial_writes,
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Applied { tombstones: 2 }
        );
        assert_eq!(
            service
                .apply(
                    &partial_owners,
                    "alice@local.test/Laptop",
                    &partial_command,
                    &[],
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Replay,
            "a two-write admission remains a replay after the current plan changes to zero"
        );
        sqlx::query("DELETE FROM message_archive WHERE id=$1")
            .bind(partial_action_ids[1])
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            service
                .apply(
                    &partial_owners,
                    "alice@local.test/Laptop",
                    &partial_command,
                    &[],
                    None,
                )
                .await
                .unwrap(),
            RetractionOutcome::Replay,
            "legitimate MAM retention may clear archive_id without changing the keyed replay plan"
        );

        let rollback_target_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'bob@remote.test','bob@remote.test/Phone',$3,FALSE,'rollback-target')",
        )
        .bind(rollback_target_id)
        .bind(owner_id)
        .bind("<message from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='rollback-target'><body>must remain private</body></message>")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE FUNCTION reject_retraction_outbox() RETURNS TRIGGER AS $$
             BEGIN RAISE EXCEPTION 'injected outbox failure'; END
             $$ LANGUAGE plpgsql",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_retraction_outbox
             AFTER INSERT ON s2s_outbox
             FOR EACH ROW EXECUTE FUNCTION reject_retraction_outbox()",
        )
        .execute(&pool)
        .await
        .unwrap();
        let rollback_action = "<message from='alice@local.test/Laptop' to='bob@remote.test/Phone' id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-target'/></message>";
        let rollback_command = RetractionCommand {
            target_id: "rollback-target",
            action_id: "rollback-action",
            semantic_payload: rollback_action,
        };
        let rollback_writes = [ArchiveWrite {
            id: Uuid::new_v4(),
            owner_id,
            peer_jid: "bob@remote.test/Phone",
            stanza: rollback_action,
            encrypted: false,
            stanza_id: Some(rollback_command.action_id),
        }];
        let rollback_outbox = OutboundProjection {
            stanza: "<message from='alice@local.test' to='bob@remote.test' id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-target'/></message>",
            ..outbox
        };
        assert!(service
            .apply(
                &outbound_owners,
                "alice@local.test/Laptop",
                &rollback_command,
                &rollback_writes,
                Some(&rollback_outbox),
            )
            .await
            .is_err());
        let rollback_stanza: String =
            sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=$1")
                .bind(rollback_target_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(rollback_stanza.contains("must remain private"));
        let rollback_counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT
               (SELECT COUNT(*) FROM message_archive WHERE owner_id=$1 AND stanza_id='rollback-action'),
               (SELECT COUNT(*) FROM s2s_outbox),
               (SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id='rollback-action')",
        )
        .bind(owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            rollback_counts,
            (0, 1, 0),
            "failed transaction must preserve the original and roll back intent/action/outbox projections"
        );

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }
}
