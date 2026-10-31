//! The anti-abuse application layer: the guard that decides proof-of-work, rate
//! and message admission, and the narrow login and challenge services on top of
//! it. Persistence is behind the ports here; `northstar-abuse-postgres` implements them.

pub mod challenge;
pub mod guard;
pub mod login;
