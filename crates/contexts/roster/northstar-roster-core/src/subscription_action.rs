/// An RFC 6121 subscription presence stanza type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SubscriptionAction {
    Subscribe,
    Subscribed,
    Unsubscribe,
    Unsubscribed,
}

impl SubscriptionAction {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "subscribe" => Some(Self::Subscribe),
            "subscribed" => Some(Self::Subscribed),
            "unsubscribe" => Some(Self::Unsubscribe),
            "unsubscribed" => Some(Self::Unsubscribed),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subscribe => "subscribe",
            Self::Subscribed => "subscribed",
            Self::Unsubscribe => "unsubscribe",
            Self::Unsubscribed => "unsubscribed",
        }
    }
}

/// The command or federation direction of a subscription action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SubscriptionOrigin {
    LocalCommand,
    InboundRemote,
    OutboundRemote,
}

#[cfg(test)]
mod tests {
    use super::SubscriptionAction;

    #[test]
    fn subscription_action_round_trips_wire_spellings() {
        for (action, spelling) in [
            (SubscriptionAction::Subscribe, "subscribe"),
            (SubscriptionAction::Subscribed, "subscribed"),
            (SubscriptionAction::Unsubscribe, "unsubscribe"),
            (SubscriptionAction::Unsubscribed, "unsubscribed"),
        ] {
            assert_eq!(action.as_str(), spelling);
            assert_eq!(SubscriptionAction::parse(spelling), Some(action));
        }
    }

    #[test]
    fn subscription_action_rejects_other_spellings() {
        for spelling in [
            "",
            "Subscribe",
            "subscribe ",
            "available",
            "unavailable",
            "probe",
            "error",
        ] {
            assert_eq!(SubscriptionAction::parse(spelling), None);
        }
    }
}
