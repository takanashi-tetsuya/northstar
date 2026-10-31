//! PostgreSQL adapter for MIX membership, mutations and durable delivery.
use crate::{db, services::mix::*};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

mod repository_impl;
#[derive(Clone)]
pub(crate) struct PostgresMixRepository {
    pool: PgPool,
}
impl PostgresMixRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
#[cfg(test)]
impl MixService<PostgresMixRepository> {
    pub(crate) fn new_with_test_keyrings(pool: PgPool) -> Self {
        Self::new(
            PostgresMixRepository::new(pool),
            northstar_abuse_application::guard::test_mix_message_content_keyring(),
            northstar_abuse_application::guard::test_mix_retraction_content_keyring(),
            32,
            "public".to_owned(),
        )
        .expect("test MIX service schema is valid")
    }
}

impl From<db::MixPresenceProbeTarget> for MixPresenceProbeTarget {
    fn from(target: db::MixPresenceProbeTarget) -> Self {
        Self {
            channel_jid: target.channel_jid,
            participant_jid: target.participant_jid,
        }
    }
}
impl From<db::MamArchiveQuery> for MamArchiveQuery {
    fn from(query: db::MamArchiveQuery) -> Self {
        Self {
            with_jid: query.with_jid,
            start: query.start,
            end: query.end,
            before_id: query.before_id,
            after_id: query.after_id,
            ids: query.ids,
            page: match query.page {
                db::MamRsmPage::First => MamRsmPage::First,
                db::MamRsmPage::Last => MamRsmPage::Last,
                db::MamRsmPage::Before(id) => MamRsmPage::Before(id),
                db::MamRsmPage::After(id) => MamRsmPage::After(id),
                db::MamRsmPage::Index(index) => MamRsmPage::Index(index),
            },
            max: query.max,
        }
    }
}
fn mam_query_db(query: &MamArchiveQuery) -> db::MamArchiveQuery {
    db::MamArchiveQuery {
        with_jid: query.with_jid.clone(),
        start: query.start,
        end: query.end,
        before_id: query.before_id,
        after_id: query.after_id,
        ids: query.ids.clone(),
        page: match query.page {
            MamRsmPage::First => db::MamRsmPage::First,
            MamRsmPage::Last => db::MamRsmPage::Last,
            MamRsmPage::Before(id) => db::MamRsmPage::Before(id),
            MamRsmPage::After(id) => db::MamRsmPage::After(id),
            MamRsmPage::Index(index) => db::MamRsmPage::Index(index),
        },
        max: query.max,
    }
}
fn map_mix_muc_link_outcome(outcome: db::LinkMixMucOutcome) -> MixMucLinkOutcome {
    match outcome {
        db::LinkMixMucOutcome::Linked => MixMucLinkOutcome::Linked,
        db::LinkMixMucOutcome::AlreadyLinked => MixMucLinkOutcome::AlreadyLinked,
        db::LinkMixMucOutcome::MissingCounterpart => MixMucLinkOutcome::MissingCounterpart,
        db::LinkMixMucOutcome::NotCommonOwner => MixMucLinkOutcome::NotCommonOwner,
        db::LinkMixMucOutcome::Conflict => MixMucLinkOutcome::Conflict,
    }
}

// ---------------------------------------------------------------------------
// Explicit repository <-> boundary translations. Every MIX DTO crossing into
// the protocol layer passes through exactly one of these functions; field
// names mirror the repository row so each mapping is reviewable by diff.
// ---------------------------------------------------------------------------

fn event(event: db::MixEvent) -> MixEvent {
    MixEvent {
        id: event.id,
        item_id: event.item_id,
        payload: event.payload,
        created_at: event.created_at,
    }
}

fn mutation_admission(admission: db::MixMutationAdmission) -> MixMutationAdmission {
    MixMutationAdmission {
        channel: admission.channel,
        node: admission.node,
        item_id: admission.item_id,
        payload: admission.payload,
        recipients: admission.recipients,
    }
}

fn retract_mix_message_admission(
    admission: db::RetractMixMessageAdmission,
    existing_outcome: impl FnOnce(&db::MixIntentEvidence) -> RetractMixMessageOutcome,
) -> RetractMixMessageAdmission {
    let outcome = match &admission.outcome {
        db::RetractMixMessageOutcome::Existing(existing) => existing_outcome(existing),
        db::RetractMixMessageOutcome::Retracted => RetractMixMessageOutcome::Retracted,
        db::RetractMixMessageOutcome::NotFound => RetractMixMessageOutcome::NotFound,
        db::RetractMixMessageOutcome::Forbidden => RetractMixMessageOutcome::Forbidden,
    };
    RetractMixMessageAdmission {
        outcome,
        recipients: admission.recipients,
    }
}

fn presence_item(item: db::MixPresenceItem) -> MixPresenceItem {
    MixPresenceItem {
        item_id: item.item_id,
        payload: item.payload,
        source_full_jid: item.source_full_jid,
    }
}

fn pam_membership(membership: db::PamMembership) -> PamMembership {
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

fn map_pam_replay(replay: db::PamOperationReplay) -> PamOperationReplay {
    match replay {
        db::PamOperationReplay::Miss => PamOperationReplay::Miss,
        db::PamOperationReplay::Pending => PamOperationReplay::Pending,
        db::PamOperationReplay::Replay(response) => PamOperationReplay::Replay(response),
        db::PamOperationReplay::Conflict => PamOperationReplay::Conflict,
    }
}

fn map_pam_completion(outcome: db::RemotePamCompletionOutcome) -> RemotePamCompletionOutcome {
    fn completion(value: db::RemotePamCompletion) -> RemotePamCompletion {
        RemotePamCompletion {
            response_xml: value.response_xml,
            membership: value.membership.map(pam_membership),
            applied: value.applied,
            roster_removed: value.roster_removed,
        }
    }
    match outcome {
        db::RemotePamCompletionOutcome::Applied(value) => {
            RemotePamCompletionOutcome::Applied(completion(value))
        }
        db::RemotePamCompletionOutcome::Replay(value) => {
            RemotePamCompletionOutcome::Replay(completion(value))
        }
        db::RemotePamCompletionOutcome::Conflict => RemotePamCompletionOutcome::Conflict,
        db::RemotePamCompletionOutcome::Missing => RemotePamCompletionOutcome::Missing,
    }
}

fn boundary(boundary: db::ArchiveBoundary) -> ArchiveBoundary {
    ArchiveBoundary {
        id: boundary.id,
        created_at: boundary.created_at,
    }
}

fn mix_muc_mirror(mirror: db::MixMucMirror) -> MixMucMirror {
    MixMucMirror {
        mix_channel_id: mirror.mix_channel_id,
        muc_room_id: mirror.muc_room_id,
        localpart: mirror.localpart,
        mix_domain: mirror.mix_domain,
    }
}

fn mam_page(page: db::MixMamPage) -> MixMamPage {
    MixMamPage {
        events: page.events.into_iter().map(event).collect(),
        total: page.total,
        first_index: page.first_index,
        complete: page.complete,
    }
}

fn create_outcome(outcome: db::CreateChannelOutcome) -> CreateChannelOutcome {
    match outcome {
        db::CreateChannelOutcome::Created(id) => CreateChannelOutcome::Created(id),
        db::CreateChannelOutcome::Conflict => CreateChannelOutcome::Conflict,
        db::CreateChannelOutcome::QuotaExceeded => CreateChannelOutcome::QuotaExceeded,
    }
}

fn store_event_outcome(outcome: db::StoreEventOutcome) -> StoreEventOutcome {
    match outcome {
        db::StoreEventOutcome::Stored(id) => StoreEventOutcome::Stored(id),
        db::StoreEventOutcome::Existing(_) => {
            unreachable!("existing MIX identity is resolved by the service keyring")
        }
        db::StoreEventOutcome::NotParticipant => StoreEventOutcome::NotParticipant,
        db::StoreEventOutcome::Conflict => StoreEventOutcome::Conflict,
        db::StoreEventOutcome::TooLarge => StoreEventOutcome::TooLarge,
    }
}

fn join_outcome(outcome: db::JoinChannelOutcome) -> JoinChannelOutcome {
    match outcome {
        db::JoinChannelOutcome::Joined {
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
        db::JoinChannelOutcome::Banned => JoinChannelOutcome::Banned,
        db::JoinChannelOutcome::NotAllowed => JoinChannelOutcome::NotAllowed,
        db::JoinChannelOutcome::Full => JoinChannelOutcome::Full,
        db::JoinChannelOutcome::MissingNick => JoinChannelOutcome::MissingNick,
        db::JoinChannelOutcome::NickConflict => JoinChannelOutcome::NickConflict,
    }
}

fn presence_outcome(outcome: db::PresenceOutcome) -> PresenceOutcome {
    match outcome {
        db::PresenceOutcome::Published => PresenceOutcome::Published,
        db::PresenceOutcome::Retracted => PresenceOutcome::Retracted,
        db::PresenceOutcome::Unchanged => PresenceOutcome::Unchanged,
        db::PresenceOutcome::NotSharing => PresenceOutcome::NotSharing,
        db::PresenceOutcome::NotParticipant => PresenceOutcome::NotParticipant,
    }
}

fn access_change_outcome(outcome: db::AccessChangeOutcome) -> AccessChangeOutcome {
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

impl From<&MixInvitationProof> for db::MixInvitationProof {
    fn from(proof: &MixInvitationProof) -> Self {
        db::MixInvitationProof {
            inviter_jid: proof.inviter_jid.clone(),
            invitee_jid: proof.invitee_jid.clone(),
            channel_jid: proof.channel_jid.clone(),
            token: proof.token.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
