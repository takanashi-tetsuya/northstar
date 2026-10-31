//! What a credential commit leaves behind for the frame that requested it.

use chrono::{DateTime, Utc};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct IssuedFastToken {
    pub token: Zeroizing<String>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for IssuedFastToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedFastToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StagedLoginEpoch {
    pub operation_id: Uuid,
    pub connection_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub auth_generation: i64,
    pub epoch: i64,
}

impl std::fmt::Debug for StagedLoginEpoch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedLoginEpoch")
            .field("operation_id", &self.operation_id)
            .field("connection_id", &self.connection_id)
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("auth_generation", &self.auth_generation)
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// Durable proof that FAST side effects committed. The issued bearer can be
/// consumed exactly once for the SASL2 success XML; the staged login epoch is
/// published only by the transport-success callback.
pub struct CredentialCommitReceipt {
    publication_identity: Uuid,
    issued_fast: Option<IssuedFastToken>,
    staged_login_epoch: Option<StagedLoginEpoch>,
    binding_publication: Option<BindingPublication>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BindingPublication {
    pub connection_id: Uuid,
    pub user_id: Uuid,
    pub full_jid: String,
    pub lease_seconds: u64,
}

impl std::fmt::Debug for BindingPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BindingPublication")
            .field("connection_id", &self.connection_id)
            .field("user_id", &self.user_id)
            .field("full_jid", &self.full_jid)
            .field("lease_seconds", &self.lease_seconds)
            .finish()
    }
}

impl std::fmt::Debug for CredentialCommitReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialCommitReceipt")
            .field(
                "issued_fast",
                &self.issued_fast.as_ref().map(|_| "[REDACTED]"),
            )
            .field("staged_login_epoch", &self.staged_login_epoch)
            .field("binding_publication", &self.binding_publication)
            .finish()
    }
}

impl CredentialCommitReceipt {
    pub fn publication_identity(&self) -> Uuid {
        self.publication_identity
    }
    pub fn staged_login_epoch(&self) -> Option<StagedLoginEpoch> {
        self.staged_login_epoch
    }
    pub fn binding_publication(&self) -> Option<&BindingPublication> {
        self.binding_publication.as_ref()
    }

    pub fn new(
        issued_fast: Option<IssuedFastToken>,
        staged_login_epoch: Option<StagedLoginEpoch>,
        binding_publication: Option<BindingPublication>,
    ) -> Self {
        Self {
            publication_identity: Uuid::new_v4(),
            issued_fast,
            staged_login_epoch,
            binding_publication,
        }
    }

    pub fn take_issued_fast(&mut self) -> Option<IssuedFastToken> {
        self.issued_fast.take()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FastTokenIssue {
    pub device_id: Uuid,
    pub mechanism: String,
    pub ttl_days: i64,
    pub strong_reauth_max_days: i64,
    pub inherited_chain: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FastCommitPlan {
    pub token_id: Option<Uuid>,
    pub token_was_new: bool,
    pub invalidate: bool,
    pub issue: Option<FastTokenIssue>,
}
