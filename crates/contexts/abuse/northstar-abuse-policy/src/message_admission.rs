//! The contract between the abuse guard that issues a message admission and its callers.

use crate::admission_transaction::AdmissionFence;
use crate::{GuardError, MessageAdmissionRequest, MessageDedupeIdentity, WorkRequirement};
use uuid::Uuid;

#[derive(Debug)]
pub struct AbuseStateBusy;

impl std::fmt::Display for AbuseStateBusy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("anti-abuse actor state is busy; retry later")
    }
}

impl std::error::Error for AbuseStateBusy {}

pub fn is_abuse_state_busy(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AbuseStateBusy>().is_some()
}

pub fn validate_message_admission_request(
    request: &MessageAdmissionRequest<'_>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.actor_id != Uuid::nil(),
        "message admission actor must not be nil"
    );
    anyhow::ensure!(
        northstar_xmpp_types::jid::canonical_bare_key(request.account_bare)
            .is_ok_and(|value| value == request.account_bare),
        "message admission account must be a canonical bare JID"
    );
    anyhow::ensure!(
        northstar_xmpp_types::jid::canonicalize(request.normalized_target)
            .is_ok_and(|value| value == request.normalized_target),
        "message admission target must already be canonical"
    );
    anyhow::ensure!(
        !request.normalized_payload.is_empty() && request.normalized_payload.len() <= 1_048_576,
        "message admission payload must contain 1 byte to 1 MiB"
    );
    anyhow::ensure!(
        !request.pow_intent_payload.is_empty() && request.pow_intent_payload.len() <= 1_048_576,
        "message PoW intent payload must contain 1 byte to 1 MiB"
    );
    if let Some(origin_id) = request.origin_id {
        anyhow::ensure!(
            !origin_id.is_empty()
                && origin_id.len() <= 1_024
                && !origin_id.chars().any(char::is_control),
            "message origin-id must contain 1 to 1024 non-control bytes"
        );
    }

    Ok(())
}

#[derive(Clone)]
pub struct MessageAdmissionLease {
    admission_key: Vec<u8>,
    payload_mac: Vec<u8>,
    lease_token: Uuid,
    pub offline_dedupe: MessageDedupeIdentity,
}

/// The exact admission fence handed to the database after message delivery.
/// Only a lease issued by the guard can construct this view.
pub struct MessageAdmissionAcceptance<'a> {
    admission_key: &'a [u8],
    payload_mac: &'a [u8],
    lease_token: Uuid,
}

pub fn acceptance_fence(acceptance: &MessageAdmissionAcceptance<'_>) -> AdmissionFence {
    AdmissionFence {
        admission_key: acceptance.admission_key().to_vec(),
        payload_mac: acceptance.payload_mac().to_vec(),
        lease_token: acceptance.lease_token(),
    }
}

#[derive(Debug)]
pub enum MessageAdmissionStart {
    Proceed {
        lease: Option<MessageAdmissionLease>,
        requirement: WorkRequirement,
    },
    ReplayAccepted,
    InProgress {
        requirement: WorkRequirement,
    },
    Denied(GuardError),
    Conflict,
    CapacityLimited,
}

impl std::fmt::Debug for MessageAdmissionLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MessageAdmissionLease { authority: [redacted] }")
    }
}

impl MessageAdmissionLease {
    pub fn new(
        admission_key: Vec<u8>,
        payload_mac: Vec<u8>,
        lease_token: Uuid,
        offline_dedupe: MessageDedupeIdentity,
    ) -> Self {
        Self {
            admission_key,
            payload_mac,
            lease_token,
            offline_dedupe,
        }
    }

    pub fn acceptance(&self) -> MessageAdmissionAcceptance<'_> {
        MessageAdmissionAcceptance {
            admission_key: &self.admission_key,
            payload_mac: &self.payload_mac,
            lease_token: self.lease_token,
        }
    }
}

impl MessageAdmissionAcceptance<'_> {
    pub fn admission_key(&self) -> &[u8] {
        self.admission_key
    }

    pub fn payload_mac(&self) -> &[u8] {
        self.payload_mac
    }

    pub fn lease_token(&self) -> Uuid {
        self.lease_token
    }
}

#[cfg(any(test, feature = "test-support"))]
impl MessageAdmissionLease {
    pub fn admission_key(&self) -> &[u8] {
        &self.admission_key
    }
}
