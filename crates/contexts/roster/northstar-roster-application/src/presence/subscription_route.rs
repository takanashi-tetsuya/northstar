#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionRoute {
    Hosted,
    Component,
    Federated,
}

impl SubscriptionRoute {
    pub fn resolve(
        local_domain: &str,
        target_domain: &str,
        hosted_service: bool,
        configured_component: bool,
    ) -> Self {
        if local_domain == target_domain || hosted_service {
            Self::Hosted
        } else if configured_component {
            Self::Component
        } else {
            Self::Federated
        }
    }
}
