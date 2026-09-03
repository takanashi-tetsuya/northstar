//! Capability-injected XMPP S2S federation application boundaries, envelopes, and typed commands.

#![forbid(unsafe_code)]

pub use northstar_federation_core::*;
use uuid::Uuid;

/// In-flight federation transport envelope.
#[derive(Debug)]
pub struct FederationEnvelope {
    pub outbox_id: Uuid,
    pub lock_token: Uuid,
    pub attempt_count: i32,
    pub target_domain: String,
    pub bounce_to: Option<String>,
    pub stanza: String,
    pub delivery_mode: FederationDeliveryMode,
    volatile_completion: Option<tokio::sync::oneshot::Sender<()>>,
    volatile_deadline: Option<tokio::time::Instant>,
}

impl FederationEnvelope {
    pub fn new(
        outbox_id: Uuid,
        lock_token: Uuid,
        attempt_count: i32,
        target_domain: String,
        bounce_to: Option<String>,
        stanza: String,
        delivery_mode: FederationDeliveryMode,
    ) -> Self {
        Self {
            outbox_id,
            lock_token,
            attempt_count,
            target_domain,
            bounce_to,
            stanza,
            delivery_mode,
            volatile_completion: None,
            volatile_deadline: None,
        }
    }

    pub fn volatile(
        target_domain: String,
        stanza: String,
        deadline: tokio::time::Instant,
    ) -> (Self, tokio::sync::oneshot::Receiver<()>) {
        let (completion, receiver) = tokio::sync::oneshot::channel();
        (
            Self {
                outbox_id: Uuid::nil(),
                lock_token: Uuid::nil(),
                attempt_count: 0,
                target_domain,
                bounce_to: None,
                stanza,
                delivery_mode: FederationDeliveryMode::Volatile,
                volatile_completion: Some(completion),
                volatile_deadline: Some(deadline),
            },
            receiver,
        )
    }

    pub fn is_durable(&self) -> bool {
        self.delivery_mode == FederationDeliveryMode::DurableOutbox
    }

    pub fn complete_volatile_delivery(&mut self) {
        if let Some(completion) = self.volatile_completion.take() {
            let _ = completion.send(());
        }
    }

    pub fn volatile_write_budget(&self) -> Option<std::time::Duration> {
        if self.is_durable() {
            return None;
        }
        if self
            .volatile_completion
            .as_ref()
            .is_none_or(tokio::sync::oneshot::Sender::is_closed)
        {
            return Some(std::time::Duration::ZERO);
        }
        Some(
            self.volatile_deadline
                .and_then(|deadline| deadline.checked_duration_since(tokio::time::Instant::now()))
                .unwrap_or_default(),
        )
    }
}

impl From<S2sOutboxItem> for FederationEnvelope {
    fn from(item: S2sOutboxItem) -> Self {
        Self {
            outbox_id: item.id,
            lock_token: item.lock_token,
            attempt_count: item.attempt_count,
            target_domain: item.target_domain,
            bounce_to: item.bounce_to,
            stanza: item.stanza,
            delivery_mode: FederationDeliveryMode::DurableOutbox,
            volatile_completion: None,
            volatile_deadline: None,
        }
    }
}

/// Typed command for enqueuing an outbound federated stanza.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationSendCommand {
    pub target_domain: String,
    pub stanza: String,
    pub bounce_to: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationCommandValidationError {
    EmptyTargetDomain,
    EmptyStanza,
    StanzaTooLarge,
}

/// Pure validation of a federation send command.
pub fn validate_federation_send_command(
    command: &FederationSendCommand,
    max_stanza_bytes: usize,
) -> Result<(), FederationCommandValidationError> {
    if command.target_domain.trim().is_empty() {
        return Err(FederationCommandValidationError::EmptyTargetDomain);
    }
    if command.stanza.trim().is_empty() {
        return Err(FederationCommandValidationError::EmptyStanza);
    }
    if !validate_s2s_stanza_size(command.stanza.len(), max_stanza_bytes) {
        return Err(FederationCommandValidationError::StanzaTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_durable_and_volatile_modes() {
        let item = S2sOutboxItem {
            id: Uuid::new_v4(),
            target_domain: "remote.org".to_string(),
            bounce_to: None,
            stanza: "<message/>".to_string(),
            attempt_count: 1,
            lock_token: Uuid::new_v4(),
        };
        let envelope = FederationEnvelope::from(item);
        assert!(envelope.is_durable());
        assert_eq!(envelope.volatile_write_budget(), None);

        let (mut vol, mut rx) = FederationEnvelope::volatile(
            "remote.org".to_string(),
            "<presence/>".to_string(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        assert!(!vol.is_durable());
        assert!(vol.volatile_write_budget().is_some());
        vol.complete_volatile_delivery();
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn federation_send_command_validation() {
        let cmd = FederationSendCommand {
            target_domain: "remote.example".to_string(),
            stanza: "<message to='remote.example'/>".to_string(),
            bounce_to: None,
        };
        assert!(validate_federation_send_command(&cmd, 1024).is_ok());

        let empty_domain = FederationSendCommand {
            target_domain: "".to_string(),
            stanza: "<message/>".to_string(),
            bounce_to: None,
        };
        assert_eq!(
            validate_federation_send_command(&empty_domain, 1024),
            Err(FederationCommandValidationError::EmptyTargetDomain)
        );

        let oversize = FederationSendCommand {
            target_domain: "remote.example".to_string(),
            stanza: "x".repeat(2000),
            bounce_to: None,
        };
        assert_eq!(
            validate_federation_send_command(&oversize, 1024),
            Err(FederationCommandValidationError::StanzaTooLarge)
        );
    }
}
