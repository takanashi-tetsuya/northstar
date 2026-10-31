//! PostgreSQL persistence of anti-abuse state: actor windows, challenges, message admissions and
//! the key deployment authority. Other contexts' tables stay behind `effects`.

mod actor_state;
pub mod challenge;
mod challenge_cleanup;
mod challenge_issuance;
mod commit;
pub mod effects;
pub mod keys;
pub mod login;
pub mod message_admission;
pub mod persistence;
pub mod transaction;
mod verification;
