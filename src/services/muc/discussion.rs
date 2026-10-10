//! One lazy frame-owned discussion slot. Absence is selected by the session,
//! never by converting retired/conflicting registration into a legacy path.

pub(crate) use northstar_room_application::discussion::{
    Observation, PreparedDiscussion, Rejected, Summary, TerminalReason,
};
use std::sync::Mutex;

#[derive(Default)]
struct SlotState {
    observation: Option<Observation>,
    terminal: Option<TerminalReason>,
}

#[derive(Default)]
pub(crate) struct MucDiscussionSlot(Mutex<SlotState>);

impl MucDiscussionSlot {
    pub(crate) fn register(&self, prepared: &PreparedDiscussion) -> Result<Observation, Rejected> {
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

    pub(crate) fn retire(&self, reason: TerminalReason) -> Option<Summary> {
        let mut slot = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let reason = *slot.terminal.get_or_insert(reason);
        slot.observation
            .as_ref()
            .map(|observation| observation.retire(reason))
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    use northstar_room_application::{
        discussion::*, MucDiscussionRepository, RepositoryFuture, RoomApplication,
    };
    use northstar_room_core::{
        MucActorAuthority, MucActorPrincipal, MucDiscussion, MucDiscussionAdmission, MucRoom,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use uuid::Uuid;

    #[derive(Clone, Copy)]
    pub(crate) enum Cut {
        Return,
        BeforeCommit,
        DuringCommit,
        AfterReceipt,
        PanicAfterReceipt,
        FailAfterReceipt,
    }

    pub(crate) struct Repository {
        pub(crate) cut: Cut,
        pub(crate) outcome: Option<MucDiscussionAdmission>,
        pub(crate) calls: Arc<AtomicUsize>,
    }

    impl Repository {
        pub(crate) fn new(cut: Cut) -> Self {
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
                Ok(self
                    .outcome
                    .unwrap_or(MucDiscussionAdmission::Stored(command.id)))
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
                let outcome = self
                    .outcome
                    .unwrap_or(MucDiscussionAdmission::Stored(request.command().id));
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

    pub(crate) fn application(cut: Cut) -> RoomApplication<Repository> {
        RoomApplication::new(Repository::new(cut), "local.test")
    }

    pub(crate) fn command(archive: bool, identity: bool) -> MucDiscussion {
        MucDiscussion {
            id: Uuid::from_u128(11),
            room_id: Uuid::from_u128(12),
            actor_scope: "alice@local.test".to_owned(),
            origin_id: identity.then(|| "muc-origin".to_owned()),
            sender_jid: "alice@local.test/phone".to_owned(),
            nick: "Alice".to_owned(),
            stanza: "<message/>".to_owned(),
            encrypted: false,
            archive,
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

    pub(crate) fn room() -> MucRoom {
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

    pub(crate) fn live_input() -> (MucDiscussion, String, String) {
        let mut command = command(true, true);
        let room_jid = "room@conference.local.test".to_owned();
        let stanza = crate::xmpp::xml_util::add_stanza_id(
            "<message xmlns='jabber:client' from='room@conference.local.test/Alice' to='room@conference.local.test' type='groupchat'><body>hello</body></message>",
            &room_jid,
            command.id,
        );
        command.stanza = stanza.clone();
        (command, room_jid, stanza)
    }

    pub(crate) async fn accepted() -> (Observation, Completion) {
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
