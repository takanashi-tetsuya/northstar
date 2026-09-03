//! Capability-injected XMPP session application boundaries, signals, and typed commands.

#![forbid(unsafe_code)]

pub use northstar_session_core::*;
use std::sync::Arc;
use tokio::sync::watch;
use uuid::Uuid;

/// Lossless lifecycle signal for one exact local route incarnation.
///
/// The sender retains the terminal state, so a waiter which subscribes after
/// the compare-and-remove has committed still observes `Removed`. Binding the
/// signal to the connection UUID prevents a full-JID ABA replacement from
/// satisfying a waiter for the previous transport.
#[derive(Debug)]
pub struct RouteIncarnationSignal {
    connection_id: Uuid,
    removed: watch::Sender<bool>,
}

impl RouteIncarnationSignal {
    pub fn new(connection_id: Uuid) -> Arc<Self> {
        let (removed, _) = watch::channel(false);
        Arc::new(Self {
            connection_id,
            removed,
        })
    }

    pub fn connection_id(&self) -> Uuid {
        self.connection_id
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.removed.subscribe()
    }

    pub fn publish_removed(&self) {
        self.removed.send_replace(true);
    }
}

/// Typed command for requesting resource binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionBindCommand {
    pub username: String,
    pub domain: String,
    pub requested_resource: Option<String>,
    pub connection_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionCommandValidationError {
    EmptyUsername,
    EmptyDomain,
    ResourceTooLong,
    InvalidResourceCharacters,
}

/// Pure validation of a session bind command.
pub fn validate_session_bind_command(
    command: &SessionBindCommand,
) -> Result<(), SessionCommandValidationError> {
    if command.username.trim().is_empty() {
        return Err(SessionCommandValidationError::EmptyUsername);
    }
    if command.domain.trim().is_empty() {
        return Err(SessionCommandValidationError::EmptyDomain);
    }
    if let Some(res) = &command.requested_resource {
        if res.is_empty() || res.len() > 1023 {
            return Err(SessionCommandValidationError::ResourceTooLong);
        }
        if res.contains('\0') || res.contains('/') || res.contains('\\') {
            return Err(SessionCommandValidationError::InvalidResourceCharacters);
        }
    }
    Ok(())
}

/// Durable account identity captured for session quiescing and cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCleanupAccount {
    pub user_id: Uuid,
    pub username: String,
    pub auth_generation: i64,
}

impl SessionCleanupAccount {
    pub fn new(user_id: Uuid, username: String, auth_generation: i64) -> Self {
        Self {
            user_id,
            username,
            auth_generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_incarnation_signal_flow() {
        let cid = Uuid::new_v4();
        let signal = RouteIncarnationSignal::new(cid);
        assert_eq!(signal.connection_id(), cid);

        let rx = signal.subscribe();
        assert!(!*rx.borrow());

        signal.publish_removed();
        assert!(*rx.borrow());

        // Late subscriber observes terminal state
        let late_rx = signal.subscribe();
        assert!(*late_rx.borrow());
    }

    #[test]
    fn session_bind_command_validation() {
        let cid = Uuid::new_v4();
        let valid = SessionBindCommand {
            username: "alice".to_string(),
            domain: "example.org".to_string(),
            requested_resource: Some("mobile".to_string()),
            connection_id: cid,
        };
        assert!(validate_session_bind_command(&valid).is_ok());

        let invalid_user = SessionBindCommand {
            username: "".to_string(),
            domain: "example.org".to_string(),
            requested_resource: None,
            connection_id: cid,
        };
        assert_eq!(
            validate_session_bind_command(&invalid_user),
            Err(SessionCommandValidationError::EmptyUsername)
        );

        let invalid_res = SessionBindCommand {
            username: "alice".to_string(),
            domain: "example.org".to_string(),
            requested_resource: Some("bad/resource".to_string()),
            connection_id: cid,
        };
        assert_eq!(
            validate_session_bind_command(&invalid_res),
            Err(SessionCommandValidationError::InvalidResourceCharacters)
        );
    }
}
