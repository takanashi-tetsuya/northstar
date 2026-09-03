//! Capability-injected room application boundary.

#![forbid(unsafe_code)]

use northstar_room_core::{
    MucActorAuthority, MucAffiliationBatchOutcome, MucAffiliationBatchWrite, MucConfigurationOutcome,
    MucConfigurationWrite, MucDiscussion, MucDiscussionAdmission, MucRegistrationOutcome,
    MucRegistrationTarget, MucRegistrationWrite, MucRetractionMutation, MucRetractionOutcome,
    MucSubjectMutation, MucSubjectOutcome,
};
use std::{collections::VecDeque, future::Future, pin::Pin};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucSubjectCommand<'a> {
    pub mutation: MucSubjectMutation<'a>,
    pub archive: bool,
    pub authority: MucActorAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MucSubjectResult {
    pub outcome: MucSubjectOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucSubjectValidationError {
    EmptySenderJid,
    EmptyNick,
    SubjectTooLong,
    EmptyStanza,
}

pub fn validate_muc_subject_command(cmd: &MucSubjectCommand<'_>) -> Result<(), MucSubjectValidationError> {
    if cmd.mutation.sender_jid.trim().is_empty() {
        return Err(MucSubjectValidationError::EmptySenderJid);
    }
    if cmd.mutation.nick.trim().is_empty() {
        return Err(MucSubjectValidationError::EmptyNick);
    }
    if cmd.mutation.subject.len() > 10_000 {
        return Err(MucSubjectValidationError::SubjectTooLong);
    }
    if cmd.mutation.stanza.trim().is_empty() {
        return Err(MucSubjectValidationError::EmptyStanza);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucRetractionCommand<'a> {
    pub mutation: MucRetractionMutation<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MucRetractionResult {
    pub outcome: MucRetractionOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucRetractionValidationError {
    EmptySenderJid,
    EmptyNick,
    EmptyTombstone,
    EmptyActionStanza,
}

pub fn validate_muc_retraction_command(cmd: &MucRetractionCommand<'_>) -> Result<(), MucRetractionValidationError> {
    if cmd.mutation.sender_jid.trim().is_empty() {
        return Err(MucRetractionValidationError::EmptySenderJid);
    }
    if cmd.mutation.nick.trim().is_empty() {
        return Err(MucRetractionValidationError::EmptyNick);
    }
    if cmd.mutation.tombstone.trim().is_empty() {
        return Err(MucRetractionValidationError::EmptyTombstone);
    }
    if cmd.mutation.action_stanza.trim().is_empty() {
        return Err(MucRetractionValidationError::EmptyActionStanza);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucAffiliationBatchCommand<'a> {
    pub write: MucAffiliationBatchWrite<'a>,
}

impl<'a> From<MucAffiliationBatchWrite<'a>> for MucAffiliationBatchCommand<'a> {
    fn from(write: MucAffiliationBatchWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MucAffiliationBatchResult {
    pub outcome: MucAffiliationBatchOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucAffiliationBatchValidationError {
    EmptyChanges,
    TooManyChanges,
}

pub fn validate_muc_affiliation_batch_command(cmd: &MucAffiliationBatchCommand<'_>) -> Result<(), MucAffiliationBatchValidationError> {
    if cmd.write.changes.is_empty() {
        return Err(MucAffiliationBatchValidationError::EmptyChanges);
    }
    if cmd.write.changes.len() > 1000 {
        return Err(MucAffiliationBatchValidationError::TooManyChanges);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucConfigurationCommand<'a> {
    pub write: MucConfigurationWrite<'a>,
}

impl<'a> From<MucConfigurationWrite<'a>> for MucConfigurationCommand<'a> {
    fn from(write: MucConfigurationWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MucConfigurationResult {
    pub outcome: MucConfigurationOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucConfigurationValidationError {
    EmptyActorJid,
    TitleTooLong,
    DescriptionTooLong,
    InvalidMaxOccupants,
}

pub fn validate_muc_configuration_command(cmd: &MucConfigurationCommand<'_>) -> Result<(), MucConfigurationValidationError> {
    if cmd.write.actor_full_jid.trim().is_empty() {
        return Err(MucConfigurationValidationError::EmptyActorJid);
    }
    if let Some(title) = cmd.write.config.title {
        if title.len() > 1000 {
            return Err(MucConfigurationValidationError::TitleTooLong);
        }
    }
    if let Some(desc) = cmd.write.config.description {
        if desc.len() > 10_000 {
            return Err(MucConfigurationValidationError::DescriptionTooLong);
        }
    }
    if cmd.write.config.max_occupants < 0 || cmd.write.config.max_occupants > 100_000 {
        return Err(MucConfigurationValidationError::InvalidMaxOccupants);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MucRegistrationCommand<'a> {
    pub write: MucRegistrationWrite<'a>,
}

impl<'a> From<MucRegistrationWrite<'a>> for MucRegistrationCommand<'a> {
    fn from(write: MucRegistrationWrite<'a>) -> Self {
        Self { write }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MucRegistrationResult {
    pub outcome: MucRegistrationOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MucRegistrationValidationError {
    EmptyNick,
    NickTooLong,
    EmptyBareJid,
}

pub fn validate_muc_registration_command(cmd: &MucRegistrationCommand<'_>) -> Result<(), MucRegistrationValidationError> {
    if cmd.write.nick.trim().is_empty() {
        return Err(MucRegistrationValidationError::EmptyNick);
    }
    if cmd.write.nick.len() > 256 {
        return Err(MucRegistrationValidationError::NickTooLong);
    }
    if let MucRegistrationTarget::Federated { bare_jid } = cmd.write.target {
        if bare_jid.trim().is_empty() {
            return Err(MucRegistrationValidationError::EmptyBareJid);
        }
    }
    Ok(())
}


/// Request-owned ordered side effects produced only after a room transaction
/// commits. Admission is bounded before execution and sealing prevents a late
/// caller from appending work while effects are running.
#[derive(Debug)]
pub struct PostCommitPlan<T, const CAPACITY: usize> {
    effects: VecDeque<T>,
    sealed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostCommitAdmissionError {
    Full,
    Sealed,
}

impl<T, const CAPACITY: usize> Default for PostCommitPlan<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const CAPACITY: usize> PostCommitPlan<T, CAPACITY> {
    pub fn new() -> Self {
        Self {
            effects: VecDeque::with_capacity(CAPACITY),
            sealed: false,
        }
    }

    pub fn try_push(&mut self, effect: T) -> Result<(), PostCommitAdmissionError> {
        if self.sealed {
            return Err(PostCommitAdmissionError::Sealed);
        }
        if self.effects.len() >= CAPACITY {
            return Err(PostCommitAdmissionError::Full);
        }
        self.effects.push_back(effect);
        Ok(())
    }

    pub fn seal(&mut self) {
        self.sealed = true;
    }

    pub async fn run<E, Execute, ExecuteFuture, OnFailure>(
        mut self,
        mut execute: Execute,
        mut on_failure: OnFailure,
    ) where
        Execute: FnMut(T) -> ExecuteFuture,
        ExecuteFuture: Future<Output = Result<(), E>>,
        OnFailure: FnMut(E),
    {
        self.seal();
        while let Some(effect) = self.effects.pop_front() {
            if let Err(error) = execute(effect).await {
                on_failure(error);
            }
        }
    }
}

pub type RepositoryFuture<'a, E> =
    Pin<Box<dyn Future<Output = Result<MucDiscussionAdmission, E>> + Send + 'a>>;

pub trait MucDiscussionRepository: Send + Sync {
    type Error;

    fn admit_discussion<'a>(
        &'a self,
        command: &'a MucDiscussion,
    ) -> RepositoryFuture<'a, Self::Error>;
}

#[derive(Clone)]
pub struct RoomApplication<R> {
    repository: R,
    configured_domain: String,
}

impl<R> RoomApplication<R>
where
    R: MucDiscussionRepository,
{
    pub fn new(repository: R, configured_domain: impl Into<String>) -> Self {
        Self {
            repository,
            configured_domain: configured_domain.into(),
        }
    }

    pub async fn admit_discussion(
        &self,
        command: &MucDiscussion,
    ) -> Result<MucDiscussionAdmission, R::Error> {
        if !command.authority_is_consistent(&self.configured_domain) {
            return Ok(MucDiscussionAdmission::Unauthorized);
        }
        self.repository.admit_discussion(command).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_room_core::{MucActorAuthority, MucActorPrincipal};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::task::{Context, Poll, Waker};
    use uuid::Uuid;

    struct Repository {
        calls: Arc<AtomicUsize>,
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    impl MucDiscussionRepository for Repository {
        type Error = ();

        fn admit_discussion<'a>(
            &'a self,
            command: &'a MucDiscussion,
        ) -> RepositoryFuture<'a, Self::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move { Ok(MucDiscussionAdmission::Stored(command.id)) })
        }
    }

    fn command(domain: &str) -> MucDiscussion {
        let bare = format!("alice@{domain}");
        let full = format!("{bare}/phone");
        MucDiscussion {
            id: Uuid::from_u128(1),
            room_id: Uuid::from_u128(2),
            actor_scope: bare.clone(),
            origin_id: None,
            sender_jid: full.clone(),
            nick: "Alice".to_owned(),
            stanza: "<message/>".to_owned(),
            encrypted: false,
            archive: true,
            retention_days: 0,
            authority: MucActorAuthority {
                clustered: false,
                expected_room_epoch: Uuid::from_u128(3),
                principal: MucActorPrincipal::Local {
                    user_id: Uuid::from_u128(4),
                    local_domain: domain.to_owned(),
                },
                actor_scope: bare,
                full_jid: full,
                nick: "Alice".to_owned(),
                occupant_incarnation: Uuid::from_u128(5),
                connection_uuid: Uuid::from_u128(6),
                expected_role: "participant".to_owned(),
                expected_affiliation: "member".to_owned(),
                cluster_target: None,
            },
        }
    }

    #[test]
    fn malformed_authority_never_reaches_the_repository() {
        let calls = Arc::new(AtomicUsize::new(0));
        let application = RoomApplication::new(
            Repository {
                calls: Arc::clone(&calls),
            },
            "local.test",
        );
        let result = block_on(application.admit_discussion(&command("evil.test"))).unwrap();
        assert_eq!(result, MucDiscussionAdmission::Unauthorized);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn valid_authority_invokes_one_repository_operation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let application = RoomApplication::new(
            Repository {
                calls: Arc::clone(&calls),
            },
            "local.test",
        );
        let result = block_on(application.admit_discussion(&command("local.test"))).unwrap();
        assert_eq!(result, MucDiscussionAdmission::Stored(Uuid::from_u128(1)));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn post_commit_plan_is_bounded_and_sealed() {
        let mut plan = PostCommitPlan::<u8, 1>::new();
        assert_eq!(plan.try_push(1), Ok(()));
        assert_eq!(plan.try_push(2), Err(PostCommitAdmissionError::Full));
        plan.seal();
        assert_eq!(plan.try_push(3), Err(PostCommitAdmissionError::Sealed));
    }

    #[test]
    fn post_commit_plan_preserves_order_across_failures() {
        let mut plan = PostCommitPlan::<u8, 3>::new();
        plan.try_push(1).unwrap();
        plan.try_push(2).unwrap();
        plan.try_push(3).unwrap();
        let observed = std::cell::RefCell::new(Vec::new());
        let failures = std::cell::RefCell::new(Vec::new());
        block_on(plan.run(
            |value| {
                observed.borrow_mut().push(value);
                async move {
                    if value == 2 {
                        Err(value)
                    } else {
                        Ok(())
                    }
                }
            },
            |error| failures.borrow_mut().push(error),
        ));
        assert_eq!(*observed.borrow(), vec![1, 2, 3]);
        assert_eq!(*failures.borrow(), vec![2]);
    }

    #[test]
    fn subject_command_validation() {
        let auth = MucActorAuthority {
            clustered: false,
            expected_room_epoch: Uuid::nil(),
            principal: MucActorPrincipal::Local {
                user_id: Uuid::nil(),
                local_domain: "example.com".to_string(),
            },
            actor_scope: "user@example.com".to_string(),
            full_jid: "user@example.com/res".to_string(),
            nick: "User".to_string(),
            occupant_incarnation: Uuid::nil(),
            connection_uuid: Uuid::nil(),
            expected_role: "participant".to_string(),
            expected_affiliation: "member".to_string(),
            cluster_target: None,
        };
        let valid_cmd = MucSubjectCommand {
            mutation: MucSubjectMutation {
                stanza_id: Uuid::new_v4(),
                room_id: Uuid::new_v4(),
                actor_scope: "user@example.com",
                sender_jid: "user@example.com/res",
                nick: "User",
                subject: "Meeting Topics",
                stanza: "<message/>",
                encrypted: false,
            },
            archive: true,
            authority: auth.clone(),
        };
        assert!(validate_muc_subject_command(&valid_cmd).is_ok());

        let mut invalid_cmd = valid_cmd.clone();
        invalid_cmd.mutation.sender_jid = "  ";
        assert_eq!(
            validate_muc_subject_command(&invalid_cmd),
            Err(MucSubjectValidationError::EmptySenderJid)
        );

        let mut invalid_cmd = valid_cmd.clone();
        invalid_cmd.mutation.nick = "";
        assert_eq!(
            validate_muc_subject_command(&invalid_cmd),
            Err(MucSubjectValidationError::EmptyNick)
        );

        let mut invalid_cmd = valid_cmd;
        invalid_cmd.mutation.stanza = "   ";
        assert_eq!(
            validate_muc_subject_command(&invalid_cmd),
            Err(MucSubjectValidationError::EmptyStanza)
        );
    }

    #[test]
    fn retraction_and_registration_command_validation() {
        let auth = MucActorAuthority {
            clustered: false,
            expected_room_epoch: Uuid::nil(),
            principal: MucActorPrincipal::Local {
                user_id: Uuid::nil(),
                local_domain: "example.com".to_string(),
            },
            actor_scope: "user@example.com".to_string(),
            full_jid: "user@example.com/res".to_string(),
            nick: "User".to_string(),
            occupant_incarnation: Uuid::nil(),
            connection_uuid: Uuid::nil(),
            expected_role: "participant".to_string(),
            expected_affiliation: "member".to_string(),
            cluster_target: None,
        };
        let retract_cmd = MucRetractionCommand {
            mutation: MucRetractionMutation {
                action_id: Uuid::new_v4(),
                room_id: Uuid::new_v4(),
                target_id: Uuid::new_v4(),
                expected_stanza: "<message/>",
                actor_scope: "user@example.com",
                sender_jid: "user@example.com/res",
                nick: "User",
                tombstone: "<apply-to/>",
                action_stanza: "<message/>",
                reason: Some("moderation"),
                kind: northstar_room_core::MucRetractionKind::Moderator,
                authority: auth,
            },
        };
        assert!(validate_muc_retraction_command(&retract_cmd).is_ok());

        let reg_cmd = MucRegistrationCommand::from(MucRegistrationWrite {
            room_id: Uuid::new_v4(),
            target: MucRegistrationTarget::Local { user_id: Uuid::new_v4() },
            nick: "RegisteredNick",
        });
        assert!(validate_muc_registration_command(&reg_cmd).is_ok());

        let empty_nick_cmd = MucRegistrationCommand::from(MucRegistrationWrite {
            room_id: Uuid::new_v4(),
            target: MucRegistrationTarget::Local { user_id: Uuid::new_v4() },
            nick: "   ",
        });
        assert_eq!(
            validate_muc_registration_command(&empty_nick_cmd),
            Err(MucRegistrationValidationError::EmptyNick)
        );
    }

    #[test]
    fn affiliation_batch_command_validation() {
        let empty_cmd = MucAffiliationBatchCommand::from(MucAffiliationBatchWrite {
            room_id: Uuid::new_v4(),
            changes: &[],
        });
        assert_eq!(
            validate_muc_affiliation_batch_command(&empty_cmd),
            Err(MucAffiliationBatchValidationError::EmptyChanges)
        );

        let changes = vec![northstar_room_core::MucAffiliationChange {
            target: northstar_room_core::MucAffiliationTarget::LocalUsername("bob".to_string()),
            affiliation: "member".to_string(),
        }];
        let valid_cmd = MucAffiliationBatchCommand::from(MucAffiliationBatchWrite {
            room_id: Uuid::new_v4(),
            changes: &changes,
        });
        assert!(validate_muc_affiliation_batch_command(&valid_cmd).is_ok());
    }
}
