//! PostgreSQL adapter of the pubsub context: PubSub nodes, items, subscriptions, affiliations, collections and
//! digests, PEP nodes and items, vCards, private XML storage and the PubSub event outbox. It writes only its own
//! tables; it reads and locks `users` rows, whose writes belong to the auth context.

#![forbid(unsafe_code)]

mod conversions;
mod outbox;
mod pep;
mod private;
mod pubsub;
mod rendering;
mod vcard;

pub use outbox::*;
pub use pep::*;
pub use private::*;
pub use pubsub::*;
pub use vcard::*;
