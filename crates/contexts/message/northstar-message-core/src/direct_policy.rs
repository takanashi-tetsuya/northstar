use uuid::Uuid;

/// The exact connection and whether losing its active selector must deny.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivacySelection {
    pub connection_id: Uuid,
    pub expects_active: bool,
}

/// Routing facts captured before admission; policy itself is read at commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectMessagePolicy<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub sender: Option<PrivacySelection>,
    pub recipient_sessions: &'a [PrivacySelection],
    pub remote_recipient_route: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectPolicyDenial {
    ActorUnavailable,
    OutboundBlock,
    OutboundPrivacy,
    RecipientBlock,
    RecipientPrivacy,
    DegradedSpool,
}

impl std::fmt::Display for DirectPolicyDenial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "direct message policy denied: {self:?}")
    }
}

impl std::error::Error for DirectPolicyDenial {}
