//! The projections one validated original yields for its archives and its live delivery.

use super::*;

/// One validated original. Rating is selected here by the existing predicate;
/// callers cannot manufacture a no-admission branch by supplying a boolean.
pub struct OriginalDirectMessage<'a> {
    pub actor_id: uuid::Uuid,
    pub sender: &'a str,
    pub target: &'a str,
    pub message_type: &'a str,
    pub routed_raw: &'a str,
    pub origin_id: Option<String>,
    pub stanza_id: Option<&'a str>,
    pub admission: OriginalAdmissionKind,
}

pub enum OriginalAdmissionKind {
    Rated(String),
    NoAdmissionRequired,
}

impl<'a> OriginalDirectMessage<'a> {
    pub fn capture(
        root: Node<'a, '_>,
        actor_id: uuid::Uuid,
        sender: &'a str,
        target: &'a str,
        routed_raw: &'a str,
    ) -> Self {
        let admission = if is_abuse_rated_message(root) {
            OriginalAdmissionKind::Rated(set_root_attribute(
                &set_from(routed_raw, bare_jid(sender)),
                "to",
                target,
            ))
        } else {
            OriginalAdmissionKind::NoAdmissionRequired
        };
        Self {
            actor_id,
            sender,
            target,
            message_type: root.attribute("type").unwrap_or("normal"),
            routed_raw,
            origin_id: direct_origin_id(root),
            stanza_id: root.attribute("id"),
            admission,
        }
    }
    pub fn rated_payload(&self) -> Option<&str> {
        match &self.admission {
            OriginalAdmissionKind::Rated(payload) => Some(payload),
            OriginalAdmissionKind::NoAdmissionRequired => None,
        }
    }
    pub fn project_local<'b>(
        &'b self,
        authority: LocalProjectionAuthority<'b>,
        encrypted: bool,
        retraction: Option<&str>,
    ) -> LocalOriginalProjection<'a, 'b> {
        // These transformations stay at their original local preparation point,
        // after generated stanza IDs and before the original policy awaits.
        let rewritten = set_from(self.routed_raw, self.sender);
        let routed = strip_stanza_ids_by_domain(&rewritten, authority.domain);
        let sender_archive = add_stanza_id(
            &rewritten,
            bare_jid(self.sender),
            authority.sender_stable_id,
        );
        let recipient_delivery = if authority.recipient_id == self.actor_id {
            sender_archive.clone()
        } else {
            add_stanza_id(
                &routed,
                authority.recipient_bare,
                authority.recipient_stable_id,
            )
        };
        let archive = |stanza: &str| {
            if encrypted {
                if let Some(target) = retraction {
                    encrypted_retraction_archive_stanza(stanza, target)
                } else {
                    encrypted_archive_stanza(stanza)
                }
            } else {
                stanza.to_owned()
            }
        };
        let sender_archive_stanza = archive(&sender_archive);
        let recipient_archive_stanza = archive(&recipient_delivery);
        LocalOriginalProjection {
            source: self,
            authority,
            encrypted,
            rewritten,
            sender_archive,
            recipient_delivery,
            sender_archive_stanza,
            recipient_archive_stanza,
        }
    }
}

pub struct LocalProjectionAuthority<'a> {
    pub recipient_id: uuid::Uuid,
    pub recipient_bare: &'a str,
    pub sender_stable_id: uuid::Uuid,
    pub recipient_stable_id: uuid::Uuid,
    pub domain: &'a str,
}

pub struct LocalOriginalProjection<'source, 'a> {
    pub source: &'a OriginalDirectMessage<'source>,
    pub authority: LocalProjectionAuthority<'a>,
    pub encrypted: bool,
    pub rewritten: String,
    pub sender_archive: String,
    pub recipient_delivery: String,
    pub sender_archive_stanza: String,
    pub recipient_archive_stanza: String,
}

pub struct DelayedLocalProjection<'source, 'local, 'a> {
    pub local: &'a LocalOriginalProjection<'source, 'local>,
    pub stanza: String,
    pub archive_policy: LocalArchivePolicy,
}

#[derive(Clone, Copy, Default)]
pub struct LocalArchivePolicy {
    pub sender_enabled: bool,
    pub recipient_enabled: bool,
}

impl<'source, 'local> LocalOriginalProjection<'source, 'local> {
    pub fn delayed(
        &self,
        at: chrono::DateTime<chrono::Utc>,
        archive_policy: LocalArchivePolicy,
    ) -> DelayedLocalProjection<'source, 'local, '_> {
        DelayedLocalProjection {
            local: self,
            stanza: add_delay_from(&self.recipient_delivery, at, Some(self.authority.domain)),
            archive_policy,
        }
    }
}

impl<'source, 'local, 'live> DelayedLocalProjection<'source, 'local, 'live> {
    pub fn bind<'a>(
        &self,
        owner: DirectOperationHandle,
        command: ValidatedPersonalMessage<'a>,
        eligibility: DirectSpoolEligibility,
    ) -> Result<PreparedLocalDirect<'a, 'live>> {
        let source = self.local.source;
        let authority = &self.local.authority;
        let PersonalMessageDestination::Local(destination) = command.destination else {
            anyhow::bail!("prepared direct is not local");
        };
        anyhow::ensure!(
            destination.recipient_id == authority.recipient_id
                && destination.delivery_id == authority.recipient_stable_id
                && destination.encrypted == self.local.encrypted
                && destination.mam_backed == self.archive_policy.recipient_enabled,
            "prepared direct destination mismatch"
        );
        let expected_owners = [
            self.archive_policy
                .sender_enabled
                .then_some(source.actor_id),
            (self.archive_policy.recipient_enabled && authority.recipient_id != source.actor_id)
                .then_some(authority.recipient_id),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        anyhow::ensure!(
            command.archives.len() == expected_owners.len(),
            "prepared direct archive set mismatch"
        );
        for (projection, expected_owner) in command.archives.iter().zip(expected_owners) {
            anyhow::ensure!(
                projection.owner_id == expected_owner,
                "prepared direct archive order/owner mismatch"
            );
            let (id, peer, stanza) = if projection.owner_id == source.actor_id {
                (
                    authority.sender_stable_id,
                    source.target,
                    self.local.sender_archive_stanza.as_str(),
                )
            } else if projection.owner_id == authority.recipient_id {
                (
                    authority.recipient_stable_id,
                    source.sender,
                    self.local.recipient_archive_stanza.as_str(),
                )
            } else {
                anyhow::bail!("prepared direct archive owner mismatch");
            };
            anyhow::ensure!(
                projection.id == id
                    && projection.peer_jid == peer
                    && projection.stanza == stanza
                    && projection.encrypted == self.local.encrypted
                    && projection.stanza_id == source.stanza_id,
                "prepared direct archive projection mismatch"
            );
        }
        let admission = match &source.admission {
            OriginalAdmissionKind::Rated(payload) => {
                PreparationAdmission::Rated(OriginalAdmission {
                    actor_id: source.actor_id,
                    account_bare: bare_jid(source.sender),
                    normalized_target: source.target,
                    origin_id: source.origin_id.as_deref(),
                    normalized_payload: payload,
                })
            }
            OriginalAdmissionKind::NoAdmissionRequired => PreparationAdmission::NoAdmissionRequired,
        };
        PreparedLocalDirect::bind(
            owner,
            LocalPreparation {
                actor_id: source.actor_id,
                sender_bare: bare_jid(source.sender),
                sender_full: source.sender,
                target_bare: bare_jid(source.target),
                target_full: source.target,
                message_type: source.message_type,
                live_stanza: &self.local.recipient_delivery,
                origin_id: source.origin_id.as_deref(),
                identity_payload: &self.local.rewritten,
                stored_stanza: &self.stanza,
                admission,
            },
            command,
            eligibility,
            LiveDirectBinding {
                sender: source.sender,
                target: source.target,
                target_bare: bare_jid(source.target),
                message_type: source.message_type,
                stanza: &self.local.recipient_delivery,
                recipient_id: authority.recipient_id,
            },
        )
    }
}

pub fn direct_spool_eligibility(
    stanza_eligible: bool,
    account_default_privacy_permits: bool,
) -> DirectSpoolEligibility {
    if stanza_eligible && account_default_privacy_permits {
        DirectSpoolEligibility::Eligible
    } else {
        DirectSpoolEligibility::LiveOnly
    }
}
