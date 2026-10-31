//! What binding and XEP-0198 resume finalization ask for and return.

use northstar_auth_core::credential::{CredentialCommitReceipt, FastCommitPlan};
use northstar_delivery_core::SmUnackedStanza;
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug)]
pub struct ActivatedSmSession {
    pub outbound_h: u32,
    pub unacked: Vec<SmUnackedStanza>,
}

#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Finalization returns the actual credential receipt by value without another allocation"
)]
pub enum BindingFinalizationOutcome {
    Committed { receipt: CredentialCommitReceipt },
    CredentialsExpired,
    ReservationLost,
}

pub struct SmResumeFinalizationRequest<'a> {
    pub session_id: Uuid,
    pub claim_token: Uuid,
    pub connection_id: Uuid,
    pub user_id: Uuid,
    pub expected_auth_generation: i64,
    pub client_h: u32,
    pub acknowledged_count: usize,
    pub peer_ip: IpAddr,
    pub user_agent_id: Option<Uuid>,
    pub active_privacy_list: Option<&'a str>,
    pub ttl_seconds: u64,
    pub live_lease_seconds: u64,
    pub max_stanzas: usize,
    pub max_bytes: usize,
    pub fast_plan: Option<&'a FastCommitPlan>,
}

#[derive(Debug)]
pub struct SmResumeFinalizationCommit {
    pub activated: ActivatedSmSession,
    pub receipt: CredentialCommitReceipt,
}

#[derive(Debug)]
pub enum SmResumeFinalizationOutcome {
    Committed(Box<SmResumeFinalizationCommit>),
    CredentialsExpired,
    ClaimLost,
    PrivacySelectionMissing,
}
