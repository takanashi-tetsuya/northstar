//! The cluster's PostgreSQL authority as the cluster edge sees it: the node's one live process slot, the replay
//! ledger of signed envelopes, and the routes that record which node, process and connection own a full JID. The
//! composition root installs one store once the database pool exists. Redis only carries commands; it never decides
//! ownership.

use crate::session_termination_authority::SessionRouteAuthority;
use anyhow::Result;
use northstar_security::{cluster_bus::SignedClusterEnvelope, cluster_keys::ClusterNodeInstance};
use northstar_session_core::SessionRouteClaimProof;
use std::{future::Future, pin::Pin, time::Duration};
use uuid::Uuid;

/// A store call's future. The cluster holds the store as a trait object, so its futures are boxed.
pub type ClusterStoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// The exact owner of one cluster session route: the node, the process instance that claimed it, and the
/// connection inside that process.
#[derive(Clone, Copy, Debug)]
pub struct ClusterSessionRouteOwner<'a> {
    pub namespace: &'a str,
    pub full_jid: &'a str,
    pub owner_node_id: &'a str,
    pub owner_instance_uuid: Uuid,
    pub owner_instance_epoch: i64,
    pub connection_uuid: Uuid,
}

pub trait ClusterSessionStore: Send + Sync {
    /// Claims the node ID's one live process slot. A still-live different instance is never pre-empted.
    #[allow(clippy::too_many_arguments)]
    fn claim_node_instance<'a>(
        &'a self,
        namespace: &'a str,
        node_id: &'a str,
        instance_uuid: Uuid,
        signing_key_id: &'a str,
        signing_key_epoch: i64,
        lease: Duration,
    ) -> ClusterStoreFuture<'a, ClusterNodeInstance>;

    /// Records a verified envelope in the replay ledger. `false` means the envelope was already admitted.
    fn admit_envelope_replay<'a>(
        &'a self,
        namespace: &'a str,
        envelope: &'a SignedClusterEnvelope,
    ) -> ClusterStoreFuture<'a, bool>;

    /// Whether a replay admission error is the source's validation rejection rather than lost authority.
    fn is_replay_validation_rejection(&self, error: &anyhow::Error) -> bool;

    /// Claims the route for `owner`. `false` means another live owner holds it.
    fn claim_session_route<'a>(
        &'a self,
        owner: ClusterSessionRouteOwner<'a>,
        bare_jid: &'a str,
        proof: SessionRouteClaimProof,
        lease: Duration,
    ) -> ClusterStoreFuture<'a, bool>;

    /// Extends the route's lease. `false` means `owner` no longer holds it.
    fn refresh_session_route<'a>(
        &'a self,
        owner: ClusterSessionRouteOwner<'a>,
        lease: Duration,
    ) -> ClusterStoreFuture<'a, bool>;

    /// Releases the route if `owner` still holds it exactly.
    fn release_session_route<'a>(
        &'a self,
        owner: ClusterSessionRouteOwner<'a>,
    ) -> ClusterStoreFuture<'a, bool>;

    fn session_route_authority<'a>(
        &'a self,
        namespace: &'a str,
        full_jid: &'a str,
    ) -> ClusterStoreFuture<'a, Option<SessionRouteAuthority>>;

    fn session_nodes_for_bare<'a>(
        &'a self,
        namespace: &'a str,
        bare_jid: &'a str,
    ) -> ClusterStoreFuture<'a, Vec<String>>;
}
