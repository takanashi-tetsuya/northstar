use crate::abuse::PowProof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct RegistrationRequest {
    pub username: String,
    pub password: String,
    pub invitation_token: Option<String>,
    pub pow: Option<PowProof>,
}

#[derive(Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub pow: Option<PowProof>,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub token: String,
    pub jid: String,
    pub is_admin: bool,
}

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub action: String,
}

#[derive(Deserialize)]
pub struct PasswordChange {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub r#with: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Deserialize)]
pub struct EvidenceItem {
    pub client_message_id: Option<String>,
    pub sender_jid: String,
    pub sent_at: Option<DateTime<Utc>>,
    pub body_text: String,
    pub encrypted: Option<bool>,
}

#[derive(Deserialize)]
pub struct ReportRequest {
    pub reported_jid: String,
    pub category: String,
    pub evidence: Vec<EvidenceItem>,
    pub description: Option<String>,
    pub pow: Option<PowProof>,
}

#[derive(Deserialize)]
pub struct AppealRequest {
    pub reason: String,
    pub pow: Option<PowProof>,
}

#[derive(Deserialize)]
pub struct UserPatch {
    pub disabled: Option<bool>,
    pub admin: Option<bool>,
}

#[derive(Deserialize)]
pub struct ModerationPatch {
    pub status: String,
    pub resolution: Option<String>,
}

#[derive(Deserialize)]
pub struct InvitationRequest {
    pub label: String,
    pub max_uses: Option<i32>,
    pub expires_in_hours: Option<i32>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Page {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}
