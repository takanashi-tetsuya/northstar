//! PostgreSQL adapter of the pubsub context: PubSub nodes, items, subscriptions, affiliations, collections and
//! digests, PEP nodes and items, vCards, private XML storage and the PubSub event outbox. It writes only its own
//! tables; it reads and locks `users` rows, whose writes belong to the auth context.

#![forbid(unsafe_code)]

mod conversions;
mod outbox;
mod pep;
mod pep_snapshot;
mod private;
mod pubsub;
mod rendering;
pub mod subscription_cleanup;
mod vcard;

pub use outbox::*;
pub use pep::*;
pub use pep_snapshot::*;
pub use private::*;
pub use pubsub::*;
pub use vcard::*;
