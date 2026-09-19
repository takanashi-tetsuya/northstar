//! Personal-message application orchestration over an injected commit port.
//!
//! This crate validates cross-adapter authority invariants before any storage
//! implementation can run. It intentionally knows nothing about PostgreSQL,
//! sockets, XML, global server state or post-commit providers.

use northstar_message_core::{
    IdentityAuthority, MessageCommit, PersonalMessageDestination, ValidatedPersonalMessage,
};
use std::future::Future;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidMessageCommand {
    FederationActorMissing,
    FederationActorMismatch,
    FederationIdentityNotLocal,
    LocalIdentityNotLocal,
    InboundIdentityNotRemote,
}

/// Persistence port for the single authoritative personal-message commit.
/// The implementation must atomically commit every projection present in the
/// command or return an error without a partial user-visible admission.
pub trait PersonalMessageCommitRepository {
    type Error;

    fn commit<'a>(
        &'a self,
        command: &'a ValidatedPersonalMessage<'a>,
    ) -> impl Future<Output = Result<MessageCommit, Self::Error>> + Send + 'a;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitError<E> {
    Invalid(InvalidMessageCommand),
    Repository(E),
}

#[derive(Clone)]
pub struct MessageApplication<R> {
    repository: R,
}

impl<R> MessageApplication<R>
where
    R: PersonalMessageCommitRepository,
{
    pub const fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn commit(
        &self,
        command: &ValidatedPersonalMessage<'_>,
    ) -> Result<MessageCommit, CommitError<R::Error>> {
        validate_authority(command).map_err(CommitError::Invalid)?;
        self.repository
            .commit(command)
            .await
            .map_err(CommitError::Repository)
    }
}

pub fn validate_authority(
    command: &ValidatedPersonalMessage<'_>,
) -> Result<(), InvalidMessageCommand> {
    match command.destination {
        PersonalMessageDestination::Federation(destination) => {
            let Some(actor) = command.local_actor_id else {
                return Err(InvalidMessageCommand::FederationActorMissing);
            };
            if actor != destination.local_actor_id {
                return Err(InvalidMessageCommand::FederationActorMismatch);
            }
            if command
                .identity
                .is_some_and(|identity| identity.authority != IdentityAuthority::LocalOrigin)
            {
                return Err(InvalidMessageCommand::FederationIdentityNotLocal);
            }
        }
        PersonalMessageDestination::Local(_) if command.local_actor_id.is_some() => {
            if command
                .identity
                .is_some_and(|identity| identity.authority != IdentityAuthority::LocalOrigin)
            {
                return Err(InvalidMessageCommand::LocalIdentityNotLocal);
            }
        }
        PersonalMessageDestination::Local(_) => {
            if command.identity.is_some_and(|identity| {
                identity.authority != IdentityAuthority::AuthenticatedRemoteStanza
            }) {
                return Err(InvalidMessageCommand::InboundIdentityNotRemote);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_message_core::{
        FederationDelivery, FederationOutboxLimits, LocalDelivery, MessageIdentity,
        MessagePostCommit,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    struct RecordingRepository {
        calls: AtomicUsize,
    }

    impl PersonalMessageCommitRepository for RecordingRepository {
        type Error = ();

        async fn commit<'a>(
            &'a self,
            _command: &'a ValidatedPersonalMessage<'a>,
        ) -> Result<MessageCommit, Self::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(MessageCommit::Stored {
                archive_written: false,
                post_commit: MessagePostCommit::RouteLocalDelivery {
                    delivery_id: Uuid::nil(),
                    recipient_id: Uuid::nil(),
                },
            })
        }
    }

    fn local_delivery() -> LocalDelivery<'static> {
        LocalDelivery {
            delivery_id: Uuid::nil(),
            recipient_id: Uuid::nil(),
            recipient_bare_jid: "alice@example.test",
            sender_jid: "bob@remote.test/device",
            stanza: "<message/>",
            encrypted: false,
            mam_backed: false,
        }
    }

    fn identity(authority: IdentityAuthority) -> MessageIdentity<'static> {
        MessageIdentity {
            authority,
            actor_scope_raw: "bob@remote.test",
            actor_scope: "bob@remote.test",
            target_scope: "alice@example.test",
            value: "message-1",
            payload: "<message/>",
        }
    }

    #[test]
    fn federation_actor_is_required_even_without_an_origin_id() {
        let command = ValidatedPersonalMessage {
            local_actor_id: None,
            identity: None,
            archives: &[],
            destination: PersonalMessageDestination::Federation(FederationDelivery {
                local_actor_id: Uuid::nil(),
                target_domain: "remote.test",
                stanza: "<message/>",
                bounce_to: None,
                limits: FederationOutboxLimits {
                    ttl_seconds: 1,
                    max_rows: 1,
                    max_bytes: 1,
                    max_per_domain: 1,
                },
            }),
        };
        assert_eq!(
            validate_authority(&command),
            Err(InvalidMessageCommand::FederationActorMissing)
        );
    }

    #[test]
    fn local_and_remote_identity_namespaces_cannot_cross() {
        let local_actor = ValidatedPersonalMessage {
            local_actor_id: Some(Uuid::nil()),
            identity: Some(identity(IdentityAuthority::AuthenticatedRemoteStanza)),
            archives: &[],
            destination: PersonalMessageDestination::Local(local_delivery()),
        };
        assert_eq!(
            validate_authority(&local_actor),
            Err(InvalidMessageCommand::LocalIdentityNotLocal)
        );

        let remote_actor = ValidatedPersonalMessage {
            local_actor_id: None,
            identity: Some(identity(IdentityAuthority::LocalOrigin)),
            archives: &[],
            destination: PersonalMessageDestination::Local(local_delivery()),
        };
        assert_eq!(
            validate_authority(&remote_actor),
            Err(InvalidMessageCommand::InboundIdentityNotRemote)
        );
    }

    #[tokio::test]
    async fn invalid_commands_never_reach_the_repository() {
        let application = MessageApplication::new(RecordingRepository {
            calls: AtomicUsize::new(0),
        });
        let command = ValidatedPersonalMessage {
            local_actor_id: Some(Uuid::nil()),
            identity: Some(identity(IdentityAuthority::AuthenticatedRemoteStanza)),
            archives: &[],
            destination: PersonalMessageDestination::Local(local_delivery()),
        };
        assert!(matches!(
            application.commit(&command).await,
            Err(CommitError::Invalid(_))
        ));
        assert_eq!(application.repository.calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn valid_commands_are_committed_once() {
        let application = MessageApplication::new(RecordingRepository {
            calls: AtomicUsize::new(0),
        });
        let command = ValidatedPersonalMessage {
            local_actor_id: None,
            identity: Some(identity(IdentityAuthority::AuthenticatedRemoteStanza)),
            archives: &[],
            destination: PersonalMessageDestination::Local(local_delivery()),
        };
        assert!(matches!(
            application.commit(&command).await,
            Ok(MessageCommit::Stored { .. })
        ));
        assert_eq!(application.repository.calls.load(Ordering::Relaxed), 1);
    }
}
