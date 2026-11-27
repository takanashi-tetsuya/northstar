use super::{AskType, LocalPresenceEffect, SubscriptionAction, SubscriptionType};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionReply {
    Subscribed,
    Unsubscribed,
}

impl SubscriptionReply {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subscribed => "subscribed",
            Self::Unsubscribed => "unsubscribed",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PendingSubscriptionChange {
    #[default]
    Keep,
    Insert,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionFacts<'a> {
    direction: Result<SubscriptionType, &'a str>,
    ask: Result<AskType, &'a str>,
    approved: bool,
}

impl<'a> SubscriptionFacts<'a> {
    pub fn from_row(subscription: &'a str, ask: Option<&'a str>, approved: bool) -> Self {
        Self {
            direction: SubscriptionType::parse(subscription).ok_or(subscription),
            ask: match ask {
                None => Ok(AskType::None),
                Some("subscribe") => Ok(AskType::Subscribe),
                Some(legacy) => Err(legacy),
            },
            approved,
        }
    }

    pub fn subscription(self) -> &'a str {
        match self.direction {
            Ok(direction) => direction.as_str(),
            Err(legacy) => legacy,
        }
    }

    pub fn ask(self) -> Option<&'a str> {
        match self.ask {
            Ok(ask) => ask.as_str(),
            Err(legacy) => Some(legacy),
        }
    }

    pub fn approved(self) -> bool {
        self.approved
    }

    fn permits_to(self) -> bool {
        matches!(
            self.direction,
            Ok(SubscriptionType::To | SubscriptionType::Both)
        )
    }

    fn permits_from(self) -> bool {
        matches!(
            self.direction,
            Ok(SubscriptionType::From | SubscriptionType::Both)
        )
    }

    fn grant(&mut self, direction: SubscriptionType) {
        use SubscriptionType::{Both, From, None, To};
        self.direction = Ok(match (self.direction, direction) {
            (Ok(None), To) | (Ok(To), To) => To,
            (Ok(None), From) | (Ok(From), From) => From,
            (Ok(To), From) | (Ok(From), To) | (Ok(Both), _) => Both,
            _ => None,
        });
    }

    fn revoke(&mut self, direction: SubscriptionType) {
        use SubscriptionType::{Both, From, None, To};
        self.direction = Ok(match (self.direction, direction) {
            (Ok(Both | To), From) => To,
            (Ok(Both | From), To) => From,
            _ => None,
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalSubscriptionDecision<'a> {
    pub actor: SubscriptionFacts<'a>,
    pub target: SubscriptionFacts<'a>,
    pub journal_actor: bool,
    pub journal_target: bool,
    pub pending_outbound: PendingSubscriptionChange,
    pub pending_inbound: PendingSubscriptionChange,
    pub effect: LocalPresenceEffect,
}

pub fn local_subscription_transition<'a>(
    actor: SubscriptionFacts<'a>,
    target: SubscriptionFacts<'a>,
    pending_outbound: bool,
    pending_inbound: bool,
    action: SubscriptionAction,
) -> LocalSubscriptionDecision<'a> {
    use LocalPresenceEffect::{AutoApproved, Forward, Suppressed};
    use PendingSubscriptionChange::{Delete, Insert, Keep};
    use SubscriptionAction::{Subscribe, Subscribed, Unsubscribe, Unsubscribed};
    use SubscriptionType::{From, To};

    let mut next = LocalSubscriptionDecision {
        actor,
        target,
        journal_actor: false,
        journal_target: false,
        pending_outbound: Keep,
        pending_inbound: Keep,
        effect: Suppressed,
    };
    match action {
        Subscribe if target.approved => {
            next.actor.grant(To);
            next.actor.ask = Ok(AskType::None);
            next.target.grant(From);
            next.target.approved = false;
            next.pending_outbound = Delete;
            next.effect = AutoApproved;
        }
        Subscribe if actor.permits_to() || pending_outbound => {}
        Subscribe => {
            next.actor.ask = Ok(AskType::Subscribe);
            next.pending_outbound = Insert;
            next.effect = Forward;
        }
        Subscribed if pending_inbound => {
            next.actor.grant(From);
            next.actor.approved = false;
            next.target.grant(To);
            next.target.ask = Ok(AskType::None);
            next.pending_inbound = Delete;
            next.effect = Forward;
        }
        Subscribed if !actor.permits_from() => next.actor.approved = true,
        Subscribed => {}
        Unsubscribe => {
            next.actor.revoke(To);
            next.actor.ask = Ok(AskType::None);
            next.target.revoke(From);
            next.pending_outbound = Delete;
            next.effect = Forward;
        }
        Unsubscribed => {
            next.actor.revoke(From);
            next.actor.approved = false;
            next.pending_inbound = Delete;
            if pending_inbound || actor.permits_from() {
                next.target.revoke(To);
                next.target.ask = Ok(AskType::None);
                next.effect = Forward;
            }
        }
    }
    next.journal_actor = next.actor != actor;
    next.journal_target = next.target != target;
    next
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteSubscriptionDecision<'a> {
    pub facts: SubscriptionFacts<'a>,
    pub journal: bool,
    pub pending: PendingSubscriptionChange,
    pub forward: bool,
    pub auto_reply: Option<SubscriptionReply>,
    pub send_unavailable: bool,
}

impl<'a> RemoteSubscriptionDecision<'a> {
    fn unchanged(facts: SubscriptionFacts<'a>) -> Self {
        Self {
            facts,
            journal: false,
            pending: PendingSubscriptionChange::Keep,
            forward: false,
            auto_reply: None,
            send_unavailable: false,
        }
    }
}

pub fn inbound_subscription_transition(
    facts: SubscriptionFacts<'_>,
    pending: bool,
    action: SubscriptionAction,
) -> RemoteSubscriptionDecision<'_> {
    use PendingSubscriptionChange::{Delete, Insert};
    use SubscriptionAction::{Subscribe, Subscribed, Unsubscribe, Unsubscribed};
    use SubscriptionType::{From, None as NoDirection, To};

    let mut next = RemoteSubscriptionDecision::unchanged(facts);
    match action {
        Subscribe if facts.approved => {
            next.facts.grant(From);
            next.facts.approved = false;
            next.pending = Delete;
            next.auto_reply = Some(SubscriptionReply::Subscribed);
        }
        Subscribe if facts.permits_from() => next.auto_reply = Some(SubscriptionReply::Subscribed),
        Subscribe if !pending => {
            next.pending = Insert;
            next.forward = true;
        }
        Subscribed
            if facts.ask == Ok(AskType::Subscribe)
                && matches!(facts.direction, Ok(NoDirection | From)) =>
        {
            next.facts.grant(To);
            next.facts.ask = Ok(AskType::None);
            next.forward = true;
        }
        Unsubscribe => {
            next.auto_reply = Some(SubscriptionReply::Unsubscribed);
            if pending || facts.permits_from() {
                next.facts.revoke(From);
                next.facts.approved = false;
                next.pending = Delete;
                next.forward = true;
                next.send_unavailable = facts.permits_from();
            }
        }
        Unsubscribed if facts.ask == Ok(AskType::Subscribe) || facts.permits_to() => {
            next.facts.revoke(To);
            next.facts.ask = Ok(AskType::None);
            next.forward = true;
        }
        Subscribe | Subscribed | Unsubscribed => {}
    }
    next.journal = next.facts != facts;
    next
}

pub fn outbound_subscription_transition(
    facts: SubscriptionFacts<'_>,
    pending: bool,
    action: SubscriptionAction,
) -> RemoteSubscriptionDecision<'_> {
    use PendingSubscriptionChange::Delete;
    use SubscriptionAction::{Subscribe, Subscribed, Unsubscribe, Unsubscribed};
    use SubscriptionType::{From, None as NoDirection, To};

    let mut next = RemoteSubscriptionDecision::unchanged(facts);
    match action {
        Subscribe => {
            if matches!(facts.direction, Ok(NoDirection | From)) {
                next.facts.ask = Ok(AskType::Subscribe);
            }
            next.forward = true;
        }
        Subscribed if pending => {
            next.facts.grant(From);
            next.facts.approved = false;
            next.pending = Delete;
            next.forward = true;
        }
        Subscribed if !facts.permits_from() => next.facts.approved = true,
        Subscribed => {}
        Unsubscribe => {
            next.facts.revoke(To);
            next.facts.ask = Ok(AskType::None);
            next.forward = true;
        }
        Unsubscribed => {
            next.facts.revoke(From);
            next.facts.approved = false;
            next.pending = Delete;
            next.forward = pending || facts.permits_from();
        }
    }
    next.journal = next.facts != facts;
    next
}

#[cfg(test)]
mod tests;
