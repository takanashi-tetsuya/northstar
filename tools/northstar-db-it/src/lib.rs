//! PostgreSQL integration tests of the context repositories and services.
//!
//! Every suite needs the whole schema (all migrations plus the identity data migrations in
//! northstar-workflows) and several cross context boundaries, so they live in this tooling crate rather
//! than next to one context. Tests that need a database are `#[ignore]`d and run by the
//! scripts/*-db-wsl.sh suites against an isolated schema (`-p northstar-db-it`).
#![cfg(test)]

mod abuse;
mod archive;
mod auth;
mod message;
mod operations;
mod pubsub;
mod room;
mod roster;
mod session;
mod support;
mod time_codec;
mod upload;
