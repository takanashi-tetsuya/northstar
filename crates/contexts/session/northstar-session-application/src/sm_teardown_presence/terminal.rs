use anyhow::{ensure, Result};
use northstar_xmpp_types::jid::{canonicalize, CanonicalJid};
use serde::{Deserialize, Serialize};
use std::future::Future;
use uuid::Uuid;

/// A local directed grant records the transport that actually accepted it.
/// The SM array keeps legacy and external address strings readable.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DirectedGrant {
    pub scope: String,
    pub route: TerminalRoute,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TerminalRoute {
    pub full_jid: String,
    pub account_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub node_id: Option<String>,
}

impl TerminalRoute {
    /// A grant can be restored on a different node from the one that recorded
    /// it. The connection identity remains the fence in either perspective.
    pub fn same_transport(&self, other: &Self) -> bool {
        self.connection_id == other.connection_id
            && self.account_id == other.account_id
            && self.auth_generation == other.auth_generation
            && self.full_jid == other.full_jid
    }
}

impl DirectedGrant {
    pub fn encode(&self) -> String {
        format!(
            "\u{1}{}",
            serde_json::to_string(self).expect("serializable directed grant")
        )
    }

    pub fn decode(value: &str) -> Result<Option<Self>> {
        let Some(encoded) = value.strip_prefix('\u{1}') else {
            return Ok(None);
        };
        let grant: Self = serde_json::from_str(encoded)?;
        let scope = CanonicalJid::parse(&grant.scope)?;
        let route = CanonicalJid::parse(&grant.route.full_jid)?;
        ensure!(
            scope.to_string() == grant.scope
                && route.to_string() == grant.route.full_jid
                && route.resourcepart().is_some()
                && route.bare() == scope.bare()
                && (scope.resourcepart().is_none() || scope == route)
                && !grant.route.account_id.is_nil()
                && !grant.route.connection_id.is_nil()
                && grant.route.auth_generation >= 0
                && grant
                    .route
                    .node_id
                    .as_ref()
                    .is_none_or(|node| !node.is_empty() && node.len() <= 128),
            "invalid exact SM directed grant"
        );
        Ok(Some(grant))
    }

    pub fn canonicalize_entry(value: &str) -> Result<String> {
        match Self::decode(value)? {
            Some(grant) => Ok(grant.encode()),
            None => canonicalize(value),
        }
    }
}

#[derive(Clone, Copy)]
pub enum TerminalOwner {
    Live {
        auth_generation: i64,
        connection_id: Uuid,
    },
    Suspended {
        session_id: Uuid,
        deadline: std::time::Instant,
    },
}

pub struct TerminalPresenceRequest<'a> {
    pub owner_id: Uuid,
    pub owner: TerminalOwner,
    pub full_jid: &'a str,
    pub active_privacy_list: Option<&'a str>,
    pub available: bool,
    pub directed: &'a [String],
    pub local_domain: &'a str,
}

#[derive(Clone, Serialize)]
pub struct TerminalRouteCandidate {
    pub route: TerminalRoute,
    pub expects_active: bool,
    pub available: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TerminalPresenceTarget {
    Route { route: TerminalRoute, scope: String },
    External(String),
}

pub enum ExactPresenceAcceptance {
    Accepted,
    Gone,
    Retry,
    Unknown,
}

pub struct TerminalPresenceAudience {
    pub source: TerminalRoute,
    pub targets: Vec<TerminalPresenceTarget>,
    pub deadline: Option<std::time::Instant>,
}

pub trait TerminalPresenceRepository: Send + Sync {
    fn capture_terminal_presence(
        &self,
        request: &TerminalPresenceRequest<'_>,
        routes: &[TerminalRouteCandidate],
    ) -> impl Future<Output = Result<Option<TerminalPresenceAudience>>> + Send;
}

impl<R: TerminalPresenceRepository> super::SmTeardownPresenceService<R> {
    pub async fn capture_terminal_presence(
        &self,
        request: &TerminalPresenceRequest<'_>,
        routes: &[TerminalRouteCandidate],
    ) -> Result<Option<TerminalPresenceAudience>> {
        self.repository
            .capture_terminal_presence(request, routes)
            .await
    }
}
