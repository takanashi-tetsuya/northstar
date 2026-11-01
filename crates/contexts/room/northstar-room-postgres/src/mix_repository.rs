//! PostgreSQL adapter for MIX membership, mutations and durable delivery.
use crate::effects::RoomEffects;
use anyhow::Result;
use chrono::{DateTime, Utc};
use northstar_room_application::mix_service::*;
use sqlx::PgPool;
use uuid::Uuid;

mod repository_impl;
#[derive(Clone)]
pub struct PostgresMixRepository<E> {
    pool: PgPool,
    effects: E,
}
impl<E: RoomEffects> PostgresMixRepository<E> {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            effects: E::default(),
        }
    }
}

impl From<crate::mix::MixPresenceProbeTarget> for MixPresenceProbeTarget {
    fn from(target: crate::mix::MixPresenceProbeTarget) -> Self {
        Self {
            channel_jid: target.channel_jid,
            participant_jid: target.participant_jid,
        }
    }
}
fn mam_query_db(query: &MamArchiveQuery) -> northstar_archive_core::MamArchiveQuery {
    northstar_archive_core::MamArchiveQuery {
        with_jid: query.with_jid.clone(),
        start: query.start,
        end: query.end,
        before_id: query.before_id,
        after_id: query.after_id,
        ids: query.ids.clone(),
        page: match query.page {
            MamRsmPage::First => northstar_archive_core::MamRsmPage::First,
            MamRsmPage::Last => northstar_archive_core::MamRsmPage::Last,
            MamRsmPage::Before(id) => northstar_archive_core::MamRsmPage::Before(id),
            MamRsmPage::After(id) => northstar_archive_core::MamRsmPage::After(id),
            MamRsmPage::Index(index) => northstar_archive_core::MamRsmPage::Index(index),
        },
        max: query.max,
    }
}
fn map_mix_muc_link_outcome(outcome: crate::mix_muc::LinkMixMucOutcome) -> MixMucLinkOutcome {
    match outcome {
        crate::mix_muc::LinkMixMucOutcome::Linked => MixMucLinkOutcome::Linked,
        crate::mix_muc::LinkMixMucOutcome::AlreadyLinked => MixMucLinkOutcome::AlreadyLinked,
        crate::mix_muc::LinkMixMucOutcome::MissingCounterpart => {
            MixMucLinkOutcome::MissingCounterpart
        }
        crate::mix_muc::LinkMixMucOutcome::NotCommonOwner => MixMucLinkOutcome::NotCommonOwner,
        crate::mix_muc::LinkMixMucOutcome::Conflict => MixMucLinkOutcome::Conflict,
    }
}

// ---------------------------------------------------------------------------
// Explicit repository <-> boundary translations. Every MIX DTO crossing into
// the protocol layer passes through exactly one of these functions; field
// names mirror the repository row so each mapping is reviewable by diff.
// ---------------------------------------------------------------------------

fn event(event: crate::mix::MixEvent) -> MixEvent {
    MixEvent {
        id: event.id,
        item_id: event.item_id,
        payload: event.payload,
        created_at: event.created_at,
    }
}

fn mutation_admission(admission: crate::mix::MixMutationAdmission) -> MixMutationAdmission {
    MixMutationAdmission {
        channel: admission.channel,
        node: admission.node,
        item_id: admission.item_id,
        payload: admission.payload,
        recipients: admission.recipients,
    }
}

fn retract_mix_message_admission(
    admission: crate::mix::RetractMixMessageAdmission,
    existing_outcome: impl FnOnce(&crate::mix::MixIntentEvidence) -> RetractMixMessageOutcome,
) -> RetractMixMessageAdmission {
    let outcome = match &admission.outcome {
        crate::mix::RetractMixMessageOutcome::Existing(existing) => existing_outcome(existing),
        crate::mix::RetractMixMessageOutcome::Retracted => RetractMixMessageOutcome::Retracted,
        crate::mix::RetractMixMessageOutcome::NotFound => RetractMixMessageOutcome::NotFound,
        crate::mix::RetractMixMessageOutcome::Forbidden => RetractMixMessageOutcome::Forbidden,
    };
    RetractMixMessageAdmission {
        outcome,
        recipients: admission.recipients,
    }
}

fn presence_item(item: crate::mix::MixPresenceItem) -> MixPresenceItem {
    MixPresenceItem {
        item_id: item.item_id,
        payload: item.payload,
        source_full_jid: item.source_full_jid,
    }
}

fn pam_membership(membership: crate::mix::PamMembership) -> PamMembership {
    PamMembership {
        id: membership.id,
        user_id: membership.user_id,
        channel_jid: membership.channel_jid,
        participant_id: membership.participant_id,
        state: membership.state,
        request_id: membership.request_id,
        client_request_id: membership.client_request_id,
        requester_full_jid: membership.requester_full_jid,
        subscriptions: membership.subscriptions,
    }
}

fn map_pam_replay(replay: crate::mix::PamOperationReplay) -> PamOperationReplay {
    match replay {
        crate::mix::PamOperationReplay::Miss => PamOperationReplay::Miss,
        crate::mix::PamOperationReplay::Pending => PamOperationReplay::Pending,
        crate::mix::PamOperationReplay::Replay(response) => PamOperationReplay::Replay(response),
        crate::mix::PamOperationReplay::Conflict => PamOperationReplay::Conflict,
    }
}

fn map_pam_completion(
    outcome: crate::mix::RemotePamCompletionOutcome,
) -> RemotePamCompletionOutcome {
    fn completion(value: crate::mix::RemotePamCompletion) -> RemotePamCompletion {
        RemotePamCompletion {
            response_xml: value.response_xml,
            membership: value.membership.map(pam_membership),
            applied: value.applied,
            roster_removed: value.roster_removed,
        }
    }
    match outcome {
        crate::mix::RemotePamCompletionOutcome::Applied(value) => {
            RemotePamCompletionOutcome::Applied(completion(value))
        }
        crate::mix::RemotePamCompletionOutcome::Replay(value) => {
            RemotePamCompletionOutcome::Replay(completion(value))
        }
        crate::mix::RemotePamCompletionOutcome::Conflict => RemotePamCompletionOutcome::Conflict,
        crate::mix::RemotePamCompletionOutcome::Missing => RemotePamCompletionOutcome::Missing,
    }
}

fn boundary(boundary: northstar_archive_core::ArchiveBoundary) -> ArchiveBoundary {
    ArchiveBoundary {
        id: boundary.id,
        created_at: boundary.created_at,
    }
}

fn mix_muc_mirror(mirror: crate::mix_muc::MixMucMirror) -> MixMucMirror {
    MixMucMirror {
        mix_channel_id: mirror.mix_channel_id,
        muc_room_id: mirror.muc_room_id,
        localpart: mirror.localpart,
        mix_domain: mirror.mix_domain,
    }
}

fn mam_page(page: crate::mix::MixMamPage) -> MixMamPage {
    MixMamPage {
        events: page.events.into_iter().map(event).collect(),
        total: page.total,
        first_index: page.first_index,
        complete: page.complete,
    }
}

fn create_outcome(outcome: crate::mix::CreateChannelOutcome) -> CreateChannelOutcome {
    match outcome {
        crate::mix::CreateChannelOutcome::Created(id) => CreateChannelOutcome::Created(id),
        crate::mix::CreateChannelOutcome::Conflict => CreateChannelOutcome::Conflict,
        crate::mix::CreateChannelOutcome::QuotaExceeded => CreateChannelOutcome::QuotaExceeded,
    }
}

fn store_event_outcome(outcome: crate::mix::StoreEventOutcome) -> StoreEventOutcome {
    match outcome {
        crate::mix::StoreEventOutcome::Stored(id) => StoreEventOutcome::Stored(id),
        crate::mix::StoreEventOutcome::Existing(_) => {
            unreachable!("existing MIX identity is resolved by the service keyring")
        }
        crate::mix::StoreEventOutcome::NotParticipant => StoreEventOutcome::NotParticipant,
        crate::mix::StoreEventOutcome::Conflict => StoreEventOutcome::Conflict,
        crate::mix::StoreEventOutcome::TooLarge => StoreEventOutcome::TooLarge,
    }
}

fn join_outcome(outcome: crate::mix::JoinChannelOutcome) -> JoinChannelOutcome {
    match outcome {
        crate::mix::JoinChannelOutcome::Joined {
            participant,
            preference,
            subscriptions,
            newly_joined,
            roster_change,
        } => JoinChannelOutcome::Joined {
            participant,
            preference,
            subscriptions,
            newly_joined,
            roster_change,
        },
        crate::mix::JoinChannelOutcome::Banned => JoinChannelOutcome::Banned,
        crate::mix::JoinChannelOutcome::NotAllowed => JoinChannelOutcome::NotAllowed,
        crate::mix::JoinChannelOutcome::Full => JoinChannelOutcome::Full,
        crate::mix::JoinChannelOutcome::MissingNick => JoinChannelOutcome::MissingNick,
        crate::mix::JoinChannelOutcome::NickConflict => JoinChannelOutcome::NickConflict,
    }
}

fn presence_outcome(outcome: crate::mix::PresenceOutcome) -> PresenceOutcome {
    match outcome {
        crate::mix::PresenceOutcome::Published => PresenceOutcome::Published,
        crate::mix::PresenceOutcome::Retracted => PresenceOutcome::Retracted,
        crate::mix::PresenceOutcome::Unchanged => PresenceOutcome::Unchanged,
        crate::mix::PresenceOutcome::NotSharing => PresenceOutcome::NotSharing,
        crate::mix::PresenceOutcome::NotParticipant => PresenceOutcome::NotParticipant,
    }
}

fn access_change_outcome(outcome: crate::mix::AccessChangeOutcome) -> AccessChangeOutcome {
    AccessChangeOutcome {
        removed_participants: outcome.removed_participants,
        removed_local_users: outcome.removed_local_users,
        removed_presence: outcome
            .removed_presence
            .into_iter()
            .map(|(participant, items)| {
                (participant, items.into_iter().map(presence_item).collect())
            })
            .collect(),
    }
}

impl From<&MixInvitationProof> for crate::mix::MixInvitationProof {
    fn from(proof: &MixInvitationProof) -> Self {
        crate::mix::MixInvitationProof {
            inviter_jid: proof.inviter_jid.clone(),
            invitee_jid: proof.invitee_jid.clone(),
            channel_jid: proof.channel_jid.clone(),
            token: proof.token.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
