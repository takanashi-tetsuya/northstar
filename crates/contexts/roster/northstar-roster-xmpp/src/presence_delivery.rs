//! Presence fan-out for the presence handlers: delivery to the local sessions of an account and routing to the
//! other cluster nodes, over the node's [`crate::PresenceDeliveryHost`].

mod current;
mod directed;
mod subscription;

pub use self::current::{
    account_has_available_resource, answer_full_presence_probe, send_current_availability,
    send_current_availability_exact,
};
pub use self::directed::{
    deliver_directed_presence, deliver_directed_unavailable, directed_presence_recipient,
};
pub use self::subscription::{
    deliver_contact_presence, deliver_subscription_approval, deliver_subscription_presence,
    echo_account_presence,
};
