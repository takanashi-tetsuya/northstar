use super::*;
use northstar_room_core::mix::{
    MixChannelAddress, MixChannelId, MixParticipantId, MixParticipantNick, MixRealJid,
    MixStableParticipantId,
};
use northstar_roster_core::RosterChange;

mod remote_join;

pub use self::remote_join::RemotePamJoinOptions;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedMixRosterDelta {
    pub account: MixAccount,
    pub version: i64,
    pub change: RosterChange,
    pub participant_annotation: Option<MixParticipantId>,
}

impl CommittedMixRosterDelta {
    pub fn new(
        account: MixAccount,
        change: RosterChange,
        participant_annotation: Option<MixParticipantId>,
    ) -> Self {
        Self {
            account,
            version: change.version,
            participant_annotation: if change.removed {
                None
            } else {
                participant_annotation
            },
            change,
        }
    }
}

#[derive(Debug)]
pub struct CommittedMixChange<T> {
    pub outcome: T,
    pub roster: Vec<CommittedMixRosterDelta>,
}

#[derive(Debug)]
pub enum HostedMixOutcome<T> {
    Present(T),
    MissingChannel,
}

impl<T> HostedMixOutcome<T> {
    pub fn classify(result: Result<T>) -> Result<Self> {
        match result {
            Ok(value) => Ok(Self::Present(value)),
            Err(error) if error.downcast_ref() == Some(&HostedMixRefusal::MissingChannel) => {
                Ok(Self::MissingChannel)
            }
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedMixRefusal {
    MissingChannel,
    AccountChanged,
    RemoteJoinOptionsNotHonoured,
}

impl std::fmt::Display for HostedMixRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MissingChannel => "MIX channel no longer exists",
            Self::AccountChanged => "MIX-PAM account no longer belongs to authenticated actor",
            Self::RemoteJoinOptionsNotHonoured => {
                "malformed federated MIX join result: requested ANON options not honoured"
            }
        })
    }
}

impl std::error::Error for HostedMixRefusal {}

pub struct RemotePamJoinEvidence<'a> {
    pub participant: &'a MixStableParticipantId,
    pub subscriptions: &'a [String],
    pub nick: Option<&'a MixParticipantNick>,
    pub anonymous_profile: bool,
    pub preference: Option<&'a MixParticipantPreference>,
}

pub struct RemotePamResponse<'a> {
    pub authenticated_domain: &'a str,
    pub channel: &'a MixChannelAddress,
    pub recipient: &'a MixRealJid,
    pub request_id: &'a str,
    pub digest: &'a [u8; 32],
}

pub trait MixPamProjectionRepository: Sync {
    fn destroy_mix_channel_committed(
        &self,
        channel: &MixChannelId,
        actor: &MixRealJid,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<CommittedMixChange<bool>>> + Send
    where
        Self: MixRepository,
    {
        async move {
            Ok(CommittedMixChange {
                outcome: self
                    .destroy_mix_channel(channel.as_uuid(), actor.as_str(), federated)
                    .await?,
                roster: Vec::new(),
            })
        }
    }

    fn leave_mix_channel_committed(
        &self,
        channel: &MixChannelId,
        actor: &MixRealJid,
        pam_user: Option<Uuid>,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<CommittedMixChange<Option<LeaveMixOutcome>>>> + Send
    where
        Self: MixRepository,
    {
        async move {
            Ok(CommittedMixChange {
                outcome: self
                    .leave_mix_channel(channel.as_uuid(), actor.as_str(), pam_user, federated)
                    .await?,
                roster: Vec::new(),
            })
        }
    }

    fn set_mix_access_entry_committed(
        &self,
        channel: &MixChannelId,
        actor: &MixRealJid,
        pattern: &str,
        list: MixAccessList,
        operation: MixAccessEntryOperation<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> impl std::future::Future<Output = Result<CommittedMixChange<Option<AccessChangeOutcome>>>> + Send
    where
        Self: MixRepository,
    {
        async move {
            Ok(CommittedMixChange {
                outcome: self
                    .set_mix_access_entry(
                        MixAccessEntryUpdate {
                            channel_id: channel.as_uuid(),
                            actor: actor.as_str(),
                            pattern,
                            list,
                            operation,
                        },
                        federated,
                    )
                    .await?,
                roster: Vec::new(),
            })
        }
    }

    fn complete_remote_pam_success_committed(
        &self,
        response: RemotePamResponse<'_>,
        join: Option<RemotePamJoinEvidence<'_>>,
    ) -> impl std::future::Future<Output = Result<CommittedMixChange<RemotePamCompletionOutcome>>> + Send
    where
        Self: MixRepository,
    {
        async move {
            Ok(CommittedMixChange {
                outcome: self
                    .complete_remote_pam_success(
                        response.authenticated_domain,
                        response.channel.as_str(),
                        response.recipient.as_str(),
                        response.request_id,
                        response.digest,
                        join.map(|join| RemotePamJoin {
                            participant_id: join.participant.as_str(),
                            subscriptions: join.subscriptions,
                            nick: join.nick.map(MixParticipantNick::as_str),
                        }),
                    )
                    .await?,
                roster: Vec::new(),
            })
        }
    }
}

impl<R: MixRepository + MixPamProjectionRepository> MixService<R> {
    pub async fn join_hosted_mix_committed(
        &self,
        channel: &MixChannelId,
        request: JoinMixRequest,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<HostedMixOutcome<CommittedMixChange<JoinChannelOutcome>>> {
        let actor = MixRealJid::parse(&request.actor_jid)?;
        let user_id = request.pam_user_id;
        let HostedMixOutcome::Present(outcome) = HostedMixOutcome::classify(
            self.join_mix_channel(channel.as_uuid(), request, federated)
                .await,
        )?
        else {
            return Ok(HostedMixOutcome::MissingChannel);
        };
        let roster = match (&outcome, user_id) {
            (
                JoinChannelOutcome::Joined {
                    participant,
                    roster_change: Some(change),
                    ..
                },
                Some(id),
            ) => {
                let username = actor
                    .as_str()
                    .split_once('@')
                    .expect("typed MIX real JID")
                    .0;
                vec![CommittedMixRosterDelta::new(
                    MixAccount {
                        id,
                        username: username.to_owned(),
                    },
                    change.as_ref().clone(),
                    Some(MixParticipantId::Local(
                        northstar_room_core::mix::MixLocalParticipantId::new(
                            participant.participant_id,
                        ),
                    )),
                )]
            }
            _ => Vec::new(),
        };
        Ok(HostedMixOutcome::Present(CommittedMixChange {
            outcome,
            roster,
        }))
    }

    pub async fn destroy_mix_channel_committed(
        &self,
        channel: &MixChannelId,
        actor: &MixRealJid,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<HostedMixOutcome<CommittedMixChange<bool>>> {
        let _admission = self.delivery_admission_guard().await;
        HostedMixOutcome::classify(
            self.repository
                .destroy_mix_channel_committed(channel, actor, federated)
                .await,
        )
    }

    pub async fn leave_mix_channel_committed(
        &self,
        channel: &MixChannelId,
        actor: &MixRealJid,
        pam_user: Option<Uuid>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<HostedMixOutcome<CommittedMixChange<Option<LeaveMixOutcome>>>> {
        let _admission = self.delivery_admission_guard().await;
        HostedMixOutcome::classify(
            self.repository
                .leave_mix_channel_committed(channel, actor, pam_user, federated)
                .await,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn set_mix_access_entry_committed(
        &self,
        channel: &MixChannelId,
        actor: &MixRealJid,
        pattern: &str,
        list: MixAccessList,
        operation: MixAccessEntryOperation<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<CommittedMixChange<Option<AccessChangeOutcome>>> {
        let _admission = self.delivery_admission_guard().await;
        self.repository
            .set_mix_access_entry_committed(channel, actor, pattern, list, operation, federated)
            .await
    }

    pub async fn complete_remote_pam_success_committed(
        &self,
        response: RemotePamResponse<'_>,
        join: Option<RemotePamJoinEvidence<'_>>,
    ) -> Result<CommittedMixChange<RemotePamCompletionOutcome>> {
        self.repository
            .complete_remote_pam_success_committed(response, join)
            .await
    }
}
