//! One lazy frame-owned discussion slot. Absence is selected by the session,
//! never by converting retired/conflicting registration into a legacy path.

use super::{DiscussionCommit, MucRepository, MucService, RetractionCommit};
pub use crate::discussion::{Observation, PreparedDiscussion, Rejected, Summary, TerminalReason};
use crate::{
    validate_muc_retraction_command, MucDiscussion, MucDiscussionAdmission, MucRetractionCommand,
    MucRetractionMutation, MucRetractionOutcome,
};
use std::sync::Mutex;

impl<R: MucRepository> MucService<R> {
    pub async fn execute_muc_live_discussion(
        &self,
        command: &MucDiscussion,
    ) -> anyhow::Result<DiscussionCommit> {
        if !command.authority_is_consistent(&self.configured_domain) {
            return Ok(DiscussionCommit {
                outcome: MucDiscussionAdmission::Unauthorized,
                audience: None,
            });
        }
        self.repository.admit_live_discussion(command).await
    }

    pub async fn execute_muc_live_retraction(
        &self,
        command: MucRetractionCommand<'_>,
    ) -> anyhow::Result<RetractionCommit> {
        if validate_muc_retraction_command(&command).is_err() {
            return Ok(RetractionCommit {
                outcome: MucRetractionOutcome::Unauthorized,
                audience: None,
            });
        }
        self.commit_live_retraction(command.mutation).await
    }

    pub async fn commit_live_retraction(
        &self,
        mutation: MucRetractionMutation<'_>,
    ) -> anyhow::Result<RetractionCommit> {
        if !mutation
            .authority
            .matches_authenticated_scope(&self.configured_domain)
        {
            return Ok(RetractionCommit {
                outcome: MucRetractionOutcome::Unauthorized,
                audience: None,
            });
        }
        self.repository.commit_live_retraction(mutation).await
    }
}

#[derive(Default)]
struct SlotState {
    observation: Option<Observation>,
    terminal: Option<TerminalReason>,
}

#[derive(Default)]
pub struct MucDiscussionSlot(Mutex<SlotState>);

impl MucDiscussionSlot {
    pub fn register(&self, prepared: &PreparedDiscussion) -> Result<Observation, Rejected> {
        let mut slot = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if slot.terminal.is_some() {
            return Err(Rejected::Retired);
        }
        if let Some(observation) = &slot.observation {
            if observation.snapshot().terminal.is_some() {
                return Err(Rejected::Retired);
            }
            if !observation.is_for(prepared) {
                return Err(Rejected::Input);
            }
            return Ok(observation.clone());
        }
        let observation = Observation::new(prepared.clone());
        slot.observation = Some(observation.clone());
        Ok(observation)
    }

    pub fn retire(&self, reason: TerminalReason) -> Option<Summary> {
        let mut slot = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let reason = *slot.terminal.get_or_insert(reason);
        slot.observation
            .as_ref()
            .map(|observation| observation.retire(reason))
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod fixture {
    use crate::{discussion::*, MucDiscussionRepository, RepositoryFuture, RoomApplication};
    use northstar_room_core::{
        MucActorAuthority, MucActorPrincipal, MucDiscussion, MucDiscussionAdmission, MucRoom,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use uuid::Uuid;

    #[derive(Clone, Copy)]
    pub enum Cut {
        Return,
        BeforeCommit,
        DuringCommit,
        AfterReceipt,
        PanicAfterReceipt,
        FailAfterReceipt,
    }

    pub struct Repository {
        pub cut: Cut,
        pub outcome: Option<MucDiscussionAdmission>,
        pub calls: Arc<AtomicUsize>,
    }

    impl Repository {
        pub fn new(cut: Cut) -> Self {
            Self {
                cut,
                outcome: None,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl MucDiscussionRepository for Repository {
        type Error = anyhow::Error;

        fn admit_discussion<'a>(
            &'a self,
            command: &'a MucDiscussion,
        ) -> RepositoryFuture<'a, Self::Error> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(self.outcome.unwrap_or(MucDiscussionAdmission::Stored {
                    id: command.id,
                    archived: command.archive_eligible,
                }))
            })
        }

        fn admit_discussion_observed<'a>(
            &'a self,
            request: &'a Request,
        ) -> RepositoryFuture<'a, Self::Error> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                if matches!(self.cut, Cut::BeforeCommit) {
                    std::future::pending::<()>().await;
                }
                let command = request.command();
                let outcome = self.outcome.unwrap_or(MucDiscussionAdmission::Stored {
                    id: command.id,
                    archived: command.archive_eligible,
                });
                commit_observed(
                    async {
                        if matches!(self.cut, Cut::DuringCommit) {
                            std::future::pending::<()>().await;
                        }
                        Ok::<(), anyhow::Error>(())
                    },
                    request,
                    outcome,
                )
                .await
                .map_err(|error| match error {
                    CommitError::Observation(error) => anyhow::Error::from(error),
                    CommitError::Commit(error) => error,
                })?;
                match self.cut {
                    Cut::AfterReceipt => std::future::pending::<()>().await,
                    Cut::PanicAfterReceipt => {
                        std::panic::panic_any("MUC receipt-before-return panic")
                    }
                    Cut::FailAfterReceipt => anyhow::bail!("MUC receipt-before-return error"),
                    _ => {}
                }
                Ok(outcome)
            })
        }
    }

    pub fn application(cut: Cut) -> RoomApplication<Repository> {
        RoomApplication::new(Repository::new(cut), "local.test")
    }

    pub fn command(archive: bool, identity: bool) -> MucDiscussion {
        MucDiscussion {
            id: Uuid::from_u128(11),
            room_id: Uuid::from_u128(12),
            actor_scope: "alice@local.test".to_owned(),
            origin_id: identity.then(|| "muc-origin".to_owned()),
            sender_jid: "alice@local.test/phone".to_owned(),
            nick: "Alice".to_owned(),
            stanza: "<message/>".to_owned(),
            encrypted: false,
            archive_eligible: archive,
            unarchived_stanza_bytes: None,
            retention_days: 0,
            authority: MucActorAuthority {
                clustered: false,
                expected_room_epoch: Uuid::from_u128(13),
                principal: MucActorPrincipal::Local {
                    user_id: Uuid::from_u128(14),
                    local_domain: "local.test".to_owned(),
                },
                actor_scope: "alice@local.test".to_owned(),
                full_jid: "alice@local.test/phone".to_owned(),
                nick: "Alice".to_owned(),
                occupant_incarnation: Uuid::from_u128(15),
                connection_uuid: Uuid::from_u128(16),
                expected_role: "participant".to_owned(),
                expected_affiliation: "member".to_owned(),
                cluster_target: None,
            },
        }
    }

    pub fn room() -> MucRoom {
        MucRoom {
            id: Uuid::from_u128(12),
            room_epoch: Uuid::from_u128(13),
            config_version: 1,
            localpart: "room".to_owned(),
            title: None,
            description: None,
            persistent: false,
            members_only: false,
            public: false,
            moderated: false,
            non_anonymous: false,
            max_occupants: 10,
            subject: None,
            subject_changed_at: None,
            allow_subject_change: false,
            allow_invites: false,
            allow_private_messages: false,
            logging_enabled: true,
            allow_registration: false,
            password_hash: None,
            occupant_id_secret: Vec::new(),
            configuration_owner_jid: None,
            configuration_expires_at: None,
        }
    }

    pub fn live_input() -> (MucDiscussion, String, String) {
        let mut command = command(true, true);
        let room_jid = "room@conference.local.test".to_owned();
        let stanza = northstar_xep_0359::add_stanza_id(
            "<message xmlns='jabber:client' from='room@conference.local.test/Alice' to='room@conference.local.test' type='groupchat'><body>hello</body></message>",
            &room_jid,
            command.id,
        );
        command.stanza = stanza.clone();
        (command, room_jid, stanza)
    }

    pub async fn accepted() -> (Observation, Completion) {
        let application = application(Cut::Return);
        let observation = Observation::new(application.prepare_discussion(command(true, true)));
        let request = observation.request().unwrap();
        let completion = application
            .admit_discussion_observed(&request)
            .await
            .unwrap();
        (observation, completion)
    }
}

#[cfg(test)]
mod tests;
