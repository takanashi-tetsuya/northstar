//! PostgreSQL adapter of the roster context: roster items and their change log, presence subscriptions, blocking and
//! privacy lists. It writes only its own tables; it reads and locks `users` rows, whose writes belong to the auth
//! context. What a roster transaction changes elsewhere goes through [`RosterTransactionEffects`].

#![forbid(unsafe_code)]

mod effects;
pub mod federated_roster;
pub mod privacy;
pub mod roster;

pub use effects::RosterTransactionEffects;
