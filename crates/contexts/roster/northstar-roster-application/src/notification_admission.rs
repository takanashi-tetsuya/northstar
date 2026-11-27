//! Final recipient admission for PubSub and PEP notifications.

use crate::{CommunicationPolicyQuery, PolicyDirection, PolicySubject};
use anyhow::Result;
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub enum NotificationSource<'a> {
    Service(&'a str),
    PepPublisher(&'a str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationHandoff {
    Accepted,
    Suppressed,
    Retry,
}

pub struct NotificationRecipient<'a> {
    pub full_jid: &'a str,
    pub account_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub active_list: Option<&'a str>,
}

pub trait NotificationAdmission: Send + Sync {
    /// Sample the recipient's account, blocklist and selected message policy together.
    fn authorize_notification(
        &self,
        recipient: NotificationRecipient<'_>,
        source: NotificationSource<'_>,
    ) -> impl Future<Output = Result<bool>> + Send;
}

impl NotificationSource<'_> {
    pub fn policy(
        self,
        recipient: NotificationRecipient<'_>,
    ) -> Result<(CommunicationPolicyQuery, bool)> {
        let route = CanonicalJid::parse(recipient.full_jid)?;
        anyhow::ensure!(
            route.resourcepart().is_some(),
            "notification requires a full route"
        );
        let (peer, same_account) = match self {
            Self::Service(jid) => (CanonicalJid::parse(jid)?, false),
            Self::PepPublisher(jid) => {
                let peer = CanonicalJid::parse_bare(jid)?;
                let same_account = route.bare() == peer.to_string();
                (peer, same_account)
            }
        };
        Ok((
            CommunicationPolicyQuery {
                account_id: recipient.account_id,
                expected_auth_generation: Some(recipient.auth_generation),
                subject: PolicySubject::Connection {
                    connection_id: recipient.connection_id,
                    expects_active: recipient.active_list.is_some(),
                },
                peer: peer.to_string(),
                kind: PrivacyStanzaKind::Message,
                direction: PolicyDirection::Inbound,
                check_owner_block: !same_account,
                check_peer_block: false,
            },
            same_account,
        ))
    }
}

#[cfg(test)]
mod tests;
