//! Checked MIX addresses, identities and text policies.

use anyhow::{Context, Result};
use northstar_xmpp_types::jid::{
    prepare_domainpart, prepare_localpart, prepare_resourcepart, CanonicalJid,
};
use std::fmt;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MixChannelAddress {
    bare: String,
    localpart_len: usize,
}

impl MixChannelAddress {
    pub fn parse(value: &str) -> Result<Self> {
        let jid = CanonicalJid::parse_bare(value)?;
        let localpart = jid
            .localpart()
            .context("MIX channel JID requires a localpart")?;
        Ok(Self {
            bare: jid.bare(),
            localpart_len: localpart.len(),
        })
    }

    pub fn prepare_service_domain(value: &str) -> Result<String> {
        prepare_domainpart(value)
    }

    pub fn prepare_channel_localpart(value: &str) -> Result<String> {
        let prepared = prepare_localpart(value)?;
        anyhow::ensure!(prepared.len() <= 1023, "MIX channel localpart is too large");
        Ok(prepared)
    }

    pub fn localpart(&self) -> &str {
        &self.bare[..self.localpart_len]
    }

    pub fn domain(&self) -> &str {
        &self.bare[self.localpart_len + 1..]
    }

    pub fn as_str(&self) -> &str {
        &self.bare
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MixRealJid(String);

impl MixRealJid {
    /// Validates the entire input JID, then projects it to the account's bare JID.
    pub fn parse(value: &str) -> Result<Self> {
        let jid = CanonicalJid::parse(value)?;
        anyhow::ensure!(
            jid.localpart().is_some(),
            "MIX participants require a user bare JID"
        );
        Ok(Self(jid.bare()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MixParticipantNick(String);

impl MixParticipantNick {
    pub fn parse(value: &str) -> Result<Self> {
        prepare_resourcepart(value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! uuid_identity {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Hash)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new(value: Uuid) -> Self {
                Self(value)
            }

            pub fn parse(value: &str) -> Result<Self, uuid::Error> {
                Uuid::parse_str(value).map(Self)
            }

            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }
    };
}

uuid_identity!(MixChannelId);
uuid_identity!(MixLocalParticipantId);

macro_rules! text_policy {
    ($name:ident, $error:literal, { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn parse(value: &str) -> Result<Self> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => anyhow::bail!($error),
                }
            }

            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value),+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

text_policy!(MixPamState, "invalid MIX PAM membership state", {
    PendingJoin => "pending_join",
    Joined => "joined",
    PendingLeave => "pending_leave",
});
text_policy!(MixRole, "invalid MIX role", {
    Owner => "owner",
    Administrator => "administrator",
    Participant => "participant",
});
text_policy!(MixJidVisibility, "invalid JID visibility", {
    Visible => "visible",
    Maybe => "maybe",
    Hidden => "hidden",
});
text_policy!(MixAccessModel, "invalid access model", {
    Open => "open",
    Allowlist => "allowlist",
});
text_policy!(MixAdministratorRetractionRights, "invalid MIX retraction rights", {
    Nobody => "nobody",
    Administrators => "administrators",
    Owners => "owners",
});
text_policy!(MixJidVisibilityPreference, "invalid MIX JID visibility preference", {
    Default => "default",
    Never => "never",
    Always => "always",
    PreferNot => "prefer not",
});
text_policy!(MixAllowBlock, "invalid MIX participant preference", {
    Allow => "allow",
    Block => "block",
});
text_policy!(MixPamOperation, "invalid MIX PAM operation", {
    Join => "join",
    Leave => "leave",
});
text_policy!(MixPamOperationState, "invalid MIX PAM operation state", {
    Pending => "pending",
    Terminal => "terminal",
    Reconciliation => "reconciliation",
});

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MixStableParticipantId(String);

impl MixStableParticipantId {
    pub fn parse(value: &str) -> Result<Self> {
        anyhow::ensure!(
            !value.is_empty()
                && value.len() <= 1023
                && !value.contains('@')
                && !value.contains('/')
                && !value.contains('#'),
            "invalid MIX stable participant id"
        );
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum MixParticipantId {
    Local(MixLocalParticipantId),
    Remote(MixStableParticipantId),
}

impl MixParticipantId {
    pub fn parse_local(value: &str) -> Result<Self, uuid::Error> {
        MixLocalParticipantId::parse(value).map(Self::Local)
    }

    pub fn parse_remote(value: &str) -> Result<Self> {
        MixStableParticipantId::parse(value).map(Self::Remote)
    }
}

impl fmt::Display for MixParticipantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(id) => fmt::Display::fmt(id, formatter),
            Self::Remote(id) => fmt::Display::fmt(id, formatter),
        }
    }
}

/// A participant JID using the first '#' in the localpart as the separator.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MixRelayAddress {
    channel: MixChannelAddress,
    participant_id: MixParticipantId,
    resource: Option<String>,
    encoded: String,
}

impl MixRelayAddress {
    /// Encodes a typed participant reference with an optional prepared resource.
    pub fn new(
        channel: MixChannelAddress,
        participant_id: MixParticipantId,
        resource: Option<&str>,
    ) -> Result<Self> {
        let encoded_localpart = format!("{participant_id}#{}", channel.localpart());
        let bare = CanonicalJid::parse_bare(&format!("{encoded_localpart}@{}", channel.domain()))?;
        anyhow::ensure!(
            bare.localpart() == Some(encoded_localpart.as_str()),
            "MIX stable participant id is not a canonical JID localpart prefix"
        );
        let jid = match resource {
            Some(resource) => CanonicalJid::parse(&format!("{bare}/{resource}"))?,
            None => bare,
        };
        Ok(Self {
            channel,
            participant_id,
            resource: jid.resourcepart().map(str::to_owned),
            encoded: jid.to_string(),
        })
    }

    /// String boundary for the legacy encoder. Validate the ID before the channel.
    pub fn encode(channel: &str, participant_id: &str, resource: Option<&str>) -> Result<Self> {
        let participant_id = MixParticipantId::parse_remote(participant_id)?;
        Self::new(MixChannelAddress::parse(channel)?, participant_id, resource)
    }

    /// Decodes a bare or full reference, preserving the opaque participant ID.
    pub fn parse(value: &str) -> Result<Self> {
        Self::decode(value, CanonicalJid::parse)
    }

    pub fn parse_bare(value: &str) -> Result<Self> {
        Self::decode(value, CanonicalJid::parse_bare)
    }

    /// Checks a bare reference against the expected bare JID. A service-only
    /// expected JID is valid syntax and fails the channel comparison.
    pub fn parse_bare_for_channel(value: &str, channel: &str) -> Result<Self> {
        let address = Self::parse_bare(value)?;
        let channel = CanonicalJid::parse_bare(channel)?;
        anyhow::ensure!(
            address.channel.as_str() == channel.to_string(),
            "encoded MIX participant JID has the wrong channel"
        );
        Ok(address)
    }

    /// Interprets a reference in a known local scope, retaining its wire spelling.
    pub fn parse_local(value: &str) -> Result<Self> {
        let mut address = Self::parse(value)?;
        let MixParticipantId::Remote(id) = &address.participant_id else {
            unreachable!("wire decoding preserves the opaque ID")
        };
        address.participant_id = MixParticipantId::parse_local(id.as_str())?;
        Ok(address)
    }

    fn decode(value: &str, parse_jid: fn(&str) -> Result<CanonicalJid>) -> Result<Self> {
        let raw_localpart = value
            .split_once('@')
            .map(|(localpart, _)| localpart)
            .context("encoded MIX participant JID requires a localpart")?;
        let encoded = parse_jid(value)?;
        anyhow::ensure!(
            encoded.localpart() == Some(raw_localpart),
            "encoded MIX participant JID is not in canonical localpart form"
        );
        let (participant_id, channel_localpart) = raw_localpart
            .split_once('#')
            .context("encoded MIX participant JID is missing its channel")?;
        let participant_id = MixParticipantId::parse_remote(participant_id)?;
        let channel =
            MixChannelAddress::parse(&format!("{channel_localpart}@{}", encoded.domainpart()))?;
        Ok(Self {
            channel,
            participant_id,
            resource: encoded.resourcepart().map(str::to_owned),
            encoded: encoded.to_string(),
        })
    }

    pub fn channel(&self) -> &MixChannelAddress {
        &self.channel
    }

    pub fn participant_id(&self) -> &MixParticipantId {
        &self.participant_id
    }

    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

macro_rules! display_as_str {
    ($($name:ident),+ $(,)?) => {
        $(
            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(self.as_str())
                }
            }
        )+
    };
}

display_as_str!(
    MixChannelAddress,
    MixRealJid,
    MixParticipantNick,
    MixStableParticipantId,
    MixRelayAddress,
);

#[cfg(test)]
mod tests;
