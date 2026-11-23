use crate::mix::{MixChannelAddress, MixChannelId, MixParticipantId};
use northstar_xmpp_types::jid::CanonicalJid;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayReturnRoute {
    Local {
        jid: CanonicalJid,
        account: Uuid,
        auth_generation: i64,
        connection: Uuid,
    },
    Federated(CanonicalJid),
}

impl RelayReturnRoute {
    pub fn jid(&self) -> &CanonicalJid {
        match self {
            Self::Local { jid, .. } | Self::Federated(jid) => jid,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayPamIncarnation {
    pub membership: Uuid,
    pub participant: Option<MixParticipantId>,
}

#[derive(Clone, Debug)]
pub struct RelayReturnAuthority {
    pub exact_route: RelayReturnRoute,
    pub channel: MixChannelAddress,
    pub channel_incarnation: Option<MixChannelId>,
    pub pam_incarnation: Option<RelayPamIncarnation>,
}

impl RelayReturnAuthority {
    pub fn matches_channel(&self, current: Option<MixChannelId>) -> bool {
        self.channel_incarnation == current
    }

    pub fn accepts_pam(&self, current: Option<&RelayPamIncarnation>) -> bool {
        current.is_none() || self.pam_incarnation.as_ref() == current
    }
}
