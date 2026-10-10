//! Test-only construction of the exact map/queue objects shared by auth and MIX.
//! No AppState, SQL, workers, discovery or transport is constructed here.
use super::{driver, map, observed, Recorder};
use crate::{
    outbound::{OutboundItem, OutboundSender},
    stage4_replay as wire,
    state::{self, OnlineSession},
};
use anyhow::{ensure, Result};
use dashmap::DashMap;
use northstar_protocol_runtime::caps::{
    CapsKey, CapsResourceIndex, PendingCapsIndex, VerifiedCapsSummary,
};
use northstar_session_core::LocalCapsEpoch;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    Arc,
};
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct Inner {
    sessions: DashMap<String, OnlineSession>,
    caps: CapsResourceIndex,
    pending: PendingCapsIndex,
    recorder: Recorder,
}
#[derive(Clone)]
pub(crate) struct RouteMap(Arc<Inner>);
#[derive(Clone)]
pub(crate) struct RouteHandle {
    map: RouteMap,
    key: String,
    // This retained value aliases the actual sender/atomics/token inserted in
    // the map; replacement cannot retarget an old holder's lifecycle.
    original: OnlineSession,
}
impl RouteMap {
    pub(crate) fn new(recorder: Recorder) -> Self {
        Self(Arc::new(Inner {
            sessions: DashMap::new(),
            caps: CapsResourceIndex::new(),
            pending: PendingCapsIndex::new(),
            recorder,
        }))
    }
    pub(crate) fn install(
        &self,
        input: &wire::RouteInput,
        capacity: u8,
    ) -> Result<(RouteHandle, mpsc::Receiver<OutboundItem>)> {
        self.install_row(input, capacity, true)
    }
    pub(crate) fn install_auth(
        &self,
        input: &wire::AuthInput,
        capacity: u8,
    ) -> Result<(RouteHandle, mpsc::Receiver<OutboundItem>)> {
        let binding = input
            .binding
            .get()
            .ok_or_else(|| anyhow::anyhow!("bound route requires binding input"))?;
        let route = wire::RouteInput {
            full_jid: binding.full_jid.clone(),
            user_id: input.user_id,
            connection_id: input.frame.connection_id,
            auth_generation: input.auth_generation,
            routable: false,
            disconnected: false,
            lifecycle: wire::Lifecycle::Active,
            caps: wire::CapsInput {
                connection_id: input.frame.connection_id,
                generation: 0,
                verified_features: wire::List::new(Vec::new())?,
            },
            provenance: wire::RouteProvenance::ActivatedByAuth(wire::ActivatedRoute {
                frame_id: input.frame.frame_id,
            }),
        };
        self.install_row(&route, capacity, false)
    }
    fn install_row(
        &self,
        input: &wire::RouteInput,
        capacity: u8,
        supplied_caps: bool,
    ) -> Result<(RouteHandle, mpsc::Receiver<OutboundItem>)> {
        ensure!((1..=2).contains(&capacity), "route queue cap");
        ensure!(self.0.sessions.len() < 2, "route count cap");
        let key = crate::jid::canonical_session_key(input.full_jid.as_str())?;
        ensure!(key == input.full_jid.as_str(), "noncanonical route key");
        ensure!(
            !self.0.sessions.contains_key(&key),
            "route would overwrite another lane"
        );
        ensure!(
            self.0
                .sessions
                .iter()
                .all(|s| s.connection_id != input.connection_id.0),
            "connection would alias another lane"
        );
        let (sender, receiver) = mpsc::channel(usize::from(capacity));
        let now = Instant::now();
        let session = OnlineSession {
            user_id: input.user_id.0,
            auth_generation: input.auth_generation,
            user_agent_epoch: None,
            connection_id: input.connection_id.0,
            route_incarnation: state::RouteIncarnationSignal::new(input.connection_id.0),
            lifecycle: Arc::new(AtomicU8::new(0)),
            metrics_counted: Arc::default(),
            routable: Arc::new(AtomicBool::new(input.routable)),
            sender: OutboundSender::new(sender),
            available: Arc::default(),
            availability_generation: Arc::default(),
            post_actions: crate::xmpp::protocol::PostActionHandle::default(),
            recovery_replay_inflight_epoch: Arc::default(),
            recovery_replay_completed_epoch: Arc::default(),
            bind2_mam_catchup: false,
            mix_presence_gate: Arc::default(),
            mix_presence_fallback_suppressed: Arc::default(),
            caps_observation_generation: Arc::new(AtomicU64::new(input.caps.generation)),
            carbons: Arc::default(),
            priority: Arc::default(),
            show: Arc::default(),
            blocklist_requested: Arc::default(),
            roster_requested: Arc::default(),
            roster_sync: Arc::default(),
            mix_roster_annotations: Arc::default(),
            privacy_active: Arc::default(),
            privacy_requested: Arc::default(),
            directed_presence: Arc::default(),
            last_presence: Arc::default(),
            ip: None,
            resource: key
                .rsplit_once('/')
                .ok_or_else(|| anyhow::anyhow!("missing resource"))?
                .1
                .to_owned(),
            user_agent_id: None,
            sm_session_id: Arc::default(),
            muc_memberships: Arc::default(),
            connected_at: now,
            last_activity: Arc::new(std::sync::RwLock::new(now)),
            disconnect: CancellationToken::new(),
        };
        if input.disconnected {
            session.disconnect.cancel();
        }
        self.0.sessions.insert(key.clone(), session.clone());
        // Supplied verified environment is installed once, never repaired after
        // a stale-epoch eviction. Auth activation later uses this same row.
        if supplied_caps {
            self.0.caps.observe_local(
                key.clone(),
                LocalCapsEpoch {
                    connection_id: input.caps.connection_id.0,
                    generation: input.caps.generation,
                },
                Some(CapsKey {
                    algorithm: "sha-1".into(),
                    node: "stage4-supplied-caps".into(),
                    version: "supplied-v1".into(),
                }),
                Some(Arc::new(VerifiedCapsSummary::new(
                    input
                        .caps
                        .verified_features
                        .as_slice()
                        .contains(&wire::CapabilityFeature::MixCore),
                    input
                        .caps
                        .verified_features
                        .as_slice()
                        .contains(&wire::CapabilityFeature::MixPam),
                    String::new(),
                    Vec::new(),
                ))),
                now,
            );
        }
        Ok((
            RouteHandle {
                map: self.clone(),
                key,
                original: session,
            },
            receiver,
        ))
    }
    pub(crate) fn capture_lookup(
        &self,
        owner: wire::RouteLookupOwner<wire::EvidenceId>,
        key: &str,
    ) {
        let _ = self.lookup(owner, key);
    }
    pub(super) fn lookup(
        &self,
        owner: wire::RouteLookupOwner<wire::EvidenceId>,
        key: &str,
    ) -> Vec<(String, OnlineSession)> {
        let entries = state::session_entries_for_in(&self.0.sessions, key);
        observed(&self.0.recorder, || {
            Ok(wire::Fact::Worker(wire::WorkerFact::Lookup(
                wire::RouteLookup {
                    owner,
                    lookup_key: wire::Text::new(key)?,
                    entries: wire::List::new(
                        entries
                            .iter()
                            .map(|(k, s)| map::route_session(k, s))
                            .collect::<Result<Vec<_>>>()?,
                    )?,
                },
            )))
        });
        entries
    }
    pub(super) fn classify(
        &self,
        attempt: u8,
        lookup_key: &str,
        full_jid: &str,
        session: &OnlineSession,
    ) -> super::super::MixSessionCapability {
        let before = self.0.caps.snapshot(full_jid);
        let pending_before = self.0.pending.len();
        let capability = state::mix_outbox::session_mix_capability_in(
            &self.0.sessions,
            &self.0.caps,
            &self.0.pending,
            full_jid,
        );
        let after = self.0.caps.snapshot(full_jid);
        observed(&self.0.recorder, || {
            Ok(wire::Fact::Worker(wire::WorkerFact::Candidate(
                wire::RouteCandidate {
                    attempt_ordinal: attempt,
                    lookup_key: wire::Text::new(lookup_key)?,
                    full_jid: wire::Text::new(full_jid)?,
                    connection_id: map::id(session.connection_id),
                    user_id: map::id(session.user_id),
                    auth_generation: session.auth_generation,
                    caps_observation_generation: session
                        .caps_observation_generation
                        .load(Ordering::Acquire),
                    routable: session.routable.load(Ordering::Acquire),
                    disconnected: session.disconnect.is_cancelled(),
                    lifecycle: session.lifecycle.load(Ordering::Acquire),
                    caps_before: map::optional(before.as_ref().map(map::caps).transpose()?),
                    caps_after: map::optional(after.as_ref().map(map::caps).transpose()?),
                    capability: match capability {
                        super::super::MixSessionCapability::Supported => {
                            wire::MixCapability::Supported
                        }
                        super::super::MixSessionCapability::Unsupported => {
                            wire::MixCapability::Unsupported
                        }
                        super::super::MixSessionCapability::Unknown => wire::MixCapability::Unknown,
                    },
                    pending_caps_count_before: u32::try_from(pending_before)?,
                    pending_caps_count_after: u32::try_from(self.0.pending.len())?,
                },
            )))
        });
        capability
    }
}
impl RouteHandle {
    pub(crate) fn full_jid(&self) -> &str {
        &self.key
    }
    pub(crate) fn connection_id(&self) -> Uuid {
        self.original.connection_id
    }
    pub(crate) fn user_id(&self) -> Uuid {
        self.original.user_id
    }
    pub(crate) fn auth_generation(&self) -> i64 {
        self.original.auth_generation
    }
    pub(crate) fn lifecycle(&self) -> Arc<AtomicU8> {
        self.original.lifecycle.clone()
    }
    pub(crate) fn sender(&self) -> OutboundSender {
        self.original.sender.clone()
    }
    pub(crate) fn disconnect(&self) -> CancellationToken {
        self.original.disconnect.clone()
    }
    pub(crate) fn snapshot(&self) -> Option<Option<wire::RouteSession<wire::EvidenceId>>> {
        driver::project(&self.map.0.recorder, || {
            self.map
                .0
                .sessions
                .get(&self.key)
                .map(|s| map::route_session(&self.key, &s))
                .transpose()
        })
    }
    pub(crate) fn epoch_and_mapping(&self, epoch: Option<i64>) -> bool {
        state::publish_user_agent_epoch_if_current_in(
            &self.map.0.sessions,
            &self.key,
            self.original.connection_id,
            self.original.user_id,
            self.original.auth_generation,
            &self.original.lifecycle,
            epoch,
        )
    }
    pub(crate) fn activate(&self) -> bool {
        state::activate_session_if_current_in(
            &self.map.0.sessions,
            &self.key,
            self.original.connection_id,
            self.original.user_id,
            self.original.auth_generation,
            &self.original.lifecycle,
            &self.original.disconnect,
        )
    }
}
