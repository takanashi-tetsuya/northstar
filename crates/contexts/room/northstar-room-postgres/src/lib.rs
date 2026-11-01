//! PostgreSQL persistence of the room context. Functions take the caller's transaction where a use case spans
//! contexts, and steps in other contexts' tables go through [`effects::RoomEffects`].

#![forbid(unsafe_code)]

pub mod accounts;
pub mod cluster_muc;
pub mod cluster_muc_delivery_item_repository;
pub mod cluster_muc_delivery_read_repository;
pub mod cluster_muc_outbox_claim_repository;
pub mod cluster_muc_outbox_housekeeping_repository;
pub mod cluster_muc_outbox_preclaim_repository;
pub mod cluster_muc_outbox_settlement_repository;
pub mod cluster_muc_receipt_claim_repository;
pub mod effects;
pub mod locked_muc_expiry_repository;
pub mod mam_authorization;
pub mod mix;
pub mod mix_identity;
pub mod mix_muc;
pub mod mix_repository;
pub mod muc;
pub mod operation_muc_wake_repository;
pub mod room;
