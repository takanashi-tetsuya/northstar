//! The steps of a roster transaction that touch other contexts' tables.

use anyhow::Result;
use northstar_roster_application::S2sOutboxPolicy;
use sqlx::{Postgres, Transaction};
use std::collections::HashMap;
use std::future::Future;
use uuid::Uuid;

/// Each step runs inside the caller's transaction, at the point the roster code reaches it, so
/// locks are taken in one order and a failure rolls back the roster change with it. The composition
/// root implements this port over the contexts that own those tables.
pub trait RosterTransactionEffects: Send + Sync {
    /// Cancels the owner's PEP subscriptions held by `contact_jid` that the owner's roster no
    /// longer allows.
    ///
    /// XEP-0163 section 7.1 requires a PEP service to cancel explicit subscriptions when a presence
    /// subscription or roster group change removes the subscriber's access. Keeping this in the
    /// roster transaction prevents a committed roster state from retaining stale durable
    /// authorization.
    fn cancel_inaccessible_pep_subscriptions(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        contact_jid: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Enqueues one stanza on the durable federation outbox.
    fn enqueue_federated_stanza(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: S2sOutboxPolicy,
    ) -> impl Future<Output = Result<()>> + Send;

    /// The participant id of each MIX channel the owner joined through its account, by channel JID.
    fn mix_participants(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
    ) -> impl Future<Output = Result<HashMap<String, String>>> + Send;
}
