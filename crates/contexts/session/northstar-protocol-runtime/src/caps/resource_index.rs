use super::{
    CapsEffectJob, CapsEffects, CapsKey, CapsObservation, CapsObservationOwner,
    CapsObservationSnapshot, CapsVerification, CapsVerificationCommit, PendingCaps,
    VerifiedCapsSummary, CAPS_EFFECT_RETRY_BASE, CAPS_EFFECT_RETRY_MAX,
    EFFECT_AUTOMATIC_PEP_LAST_ITEMS, EFFECT_DISCO_QUERY, EFFECT_EXPLICIT_PEP_LAST_ITEMS,
    EFFECT_VERIFIED_MIX_PRESENCE, MAX_CAPS_OBSERVATION_SUMMARY_BYTES, MAX_FEDERATED_CAPS_RESOURCES,
    MAX_FEDERATED_CAPS_RESOURCES_PER_DOMAIN,
};
use dashmap::DashMap;
use northstar_session_core::LocalCapsEpoch;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct CapsResourceAdmission {
    pub federated: usize,
    pub federated_per_domain: HashMap<String, usize>,
    pub summary_bytes: usize,
}

pub struct CapsResourceIndex {
    pub entries: DashMap<String, CapsObservation>,
    pub admission: Mutex<CapsResourceAdmission>,
    pub max_federated: usize,
    pub max_federated_per_domain: usize,
    pub max_summary_bytes: usize,
}

impl Default for CapsResourceIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsResourceIndex {
    pub fn new() -> Self {
        Self::with_limits(
            MAX_FEDERATED_CAPS_RESOURCES,
            MAX_FEDERATED_CAPS_RESOURCES_PER_DOMAIN,
        )
    }

    pub fn with_limits(max_federated: usize, max_federated_per_domain: usize) -> Self {
        Self::with_budgets(
            max_federated,
            max_federated_per_domain,
            MAX_CAPS_OBSERVATION_SUMMARY_BYTES,
        )
    }

    pub fn with_budgets(
        max_federated: usize,
        max_federated_per_domain: usize,
        max_summary_bytes: usize,
    ) -> Self {
        assert!(
            max_federated > 0,
            "federated caps capacity must be positive"
        );
        assert!(
            max_federated_per_domain > 0 && max_federated_per_domain <= max_federated,
            "federated caps per-domain capacity must fit the global capacity"
        );
        assert!(
            max_summary_bytes > 0,
            "caps observation summary budget must be positive"
        );
        Self {
            entries: DashMap::new(),
            admission: Mutex::new(CapsResourceAdmission::default()),
            max_federated,
            max_federated_per_domain,
            max_summary_bytes,
        }
    }

    pub fn observe_local(
        &self,
        full_jid: String,
        epoch: LocalCapsEpoch,
        key: Option<CapsKey>,
        cached: Option<Arc<VerifiedCapsSummary>>,
        now: Instant,
    ) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (previous_summary_bytes, previous_summary) =
            self.entries.get(&full_jid).map_or((0, None), |entry| {
                let summary = (entry.key.as_ref() == key.as_ref())
                    .then(|| match &entry.verification {
                        CapsVerification::Verified(summary) => Some(Arc::clone(summary)),
                        _ => None,
                    })
                    .flatten();
                (entry.summary_bytes, summary)
            });
        let cached = admit_observation_summary(
            &admission,
            previous_summary_bytes,
            cached.or(previous_summary),
            self.max_summary_bytes,
        );
        let summary_bytes = cached
            .as_deref()
            .map_or(0, VerifiedCapsSummary::resident_charge);
        if let Some(previous) = self.entries.insert(
            full_jid,
            new_caps_observation(CapsObservationOwner::Local(epoch), key, cached, None, now),
        ) {
            release_observation_admission(&mut admission, &previous);
        }
        admission.summary_bytes += summary_bytes;
    }

    pub fn observe_federated(
        &self,
        full_jid: String,
        connection_id: uuid::Uuid,
        domain: String,
        key: Option<CapsKey>,
        cached: Option<Arc<VerifiedCapsSummary>>,
        now: Instant,
    ) -> Option<CapsObservationOwner> {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous_domain = self
            .entries
            .get(&full_jid)
            .and_then(|entry| entry.federated_domain.clone());
        let adds_federated = previous_domain.is_none();
        let changes_domain = previous_domain
            .as_deref()
            .is_some_and(|previous| previous != domain);
        let domain_count = admission
            .federated_per_domain
            .get(&domain)
            .copied()
            .unwrap_or(0);
        if (adds_federated && admission.federated >= self.max_federated)
            || ((adds_federated || changes_domain) && domain_count >= self.max_federated_per_domain)
        {
            return None;
        }
        let (previous_summary_bytes, previous_summary) =
            self.entries.get(&full_jid).map_or((0, None), |entry| {
                let summary = (entry.key.as_ref() == key.as_ref())
                    .then(|| match &entry.verification {
                        CapsVerification::Verified(summary) => Some(Arc::clone(summary)),
                        _ => None,
                    })
                    .flatten();
                (entry.summary_bytes, summary)
            });
        let cached = admit_observation_summary(
            &admission,
            previous_summary_bytes,
            cached.or(previous_summary),
            self.max_summary_bytes,
        );
        let summary_bytes = cached
            .as_deref()
            .map_or(0, VerifiedCapsSummary::resident_charge);
        let owner = CapsObservationOwner::Federated {
            connection_id,
            observation_id: uuid::Uuid::new_v4(),
        };
        let previous = self.entries.insert(
            full_jid,
            new_caps_observation(owner, key, cached, Some(domain.clone()), now),
        );
        if let Some(previous) = previous.as_ref() {
            release_observation_admission(&mut admission, previous);
        }
        admission.summary_bytes += summary_bytes;
        admission.federated += 1;
        *admission.federated_per_domain.entry(domain).or_default() += 1;
        Some(owner)
    }

    pub fn owner(&self, full_jid: &str) -> Option<CapsObservationOwner> {
        self.entries.get(full_jid).map(|entry| entry.owner)
    }

    pub fn summary(&self, full_jid: &str) -> Option<Arc<VerifiedCapsSummary>> {
        let mut entry = self.entries.get_mut(full_jid)?;
        entry.touched_at = Instant::now();
        match &entry.verification {
            CapsVerification::Verified(summary) => Some(Arc::clone(summary)),
            _ => None,
        }
    }

    pub fn snapshot(&self, full_jid: &str) -> Option<CapsObservationSnapshot> {
        let mut entry = self.entries.get_mut(full_jid)?;
        entry.touched_at = Instant::now();
        Some(CapsObservationSnapshot {
            owner: entry.owner,
            key: entry.key.clone(),
            summary: match &entry.verification {
                CapsVerification::Verified(summary) => Some(Arc::clone(summary)),
                _ => None,
            },
        })
    }

    pub fn interested_resources_for_bare(&self, bare: &str, node: &str) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|entry| {
                let matches_bare = northstar_xmpp_types::canonical_bare_key(entry.key())
                    .is_ok_and(|candidate| candidate == bare);
                let interested = matches!(&entry.verification,
                    CapsVerification::Verified(summary) if summary.wants_node(node));
                (matches_bare && interested).then(|| entry.key().clone())
            })
            .collect()
    }

    pub fn current_owner(&self, full_jid: &str, owner: CapsObservationOwner) -> bool {
        self.entries
            .get(full_jid)
            .is_some_and(|entry| entry.owner == owner)
    }

    pub fn begin_query(
        &self,
        full_jid: &str,
        owner: CapsObservationOwner,
        key: &CapsKey,
        id: String,
    ) -> bool {
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return false;
        };
        if entry.owner != owner || entry.key.as_ref() != Some(key) {
            return false;
        }
        if !matches!(entry.verification, CapsVerification::NeedsDisco) {
            return false;
        }
        entry.verification = CapsVerification::Querying { id };
        true
    }

    pub fn mark_query_failed(&self, full_jid: &str, owner: CapsObservationOwner, id: &str) {
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return;
        };
        if entry.owner == owner
            && matches!(&entry.verification, CapsVerification::Querying { id: current, .. } if current == id)
        {
            entry.verification = CapsVerification::NeedsDisco;
        }
    }

    pub fn mark_verified(
        &self,
        full_jid: &str,
        owner: CapsObservationOwner,
        key: &CapsKey,
        id: &str,
        summary: Arc<VerifiedCapsSummary>,
    ) -> CapsVerificationCommit {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return CapsVerificationCommit::Stale;
        };
        if entry.owner != owner
            || entry.key.as_ref() != Some(key)
            || !matches!(&entry.verification, CapsVerification::Querying { id: current, .. } if current == id)
        {
            return CapsVerificationCommit::Stale;
        }
        if !try_install_verified_summary(
            &mut admission,
            &mut entry,
            summary,
            self.max_summary_bytes,
        ) {
            entry.verification = CapsVerification::NeedsDisco;
            entry.pending_effects |= EFFECT_DISCO_QUERY;
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.retry_at = Instant::now() + caps_retry_delay(entry.consecutive_failures);
            return CapsVerificationCommit::ResourceLimited;
        }
        entry.pending_effects &= !EFFECT_DISCO_QUERY;
        entry.retry_at = Instant::now();
        entry.consecutive_failures = 0;
        CapsVerificationCommit::Applied
    }

    pub fn mark_cached_verified(
        &self,
        full_jid: &str,
        owner: CapsObservationOwner,
        key: &CapsKey,
        summary: Arc<VerifiedCapsSummary>,
    ) -> CapsVerificationCommit {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return CapsVerificationCommit::Stale;
        };
        if entry.owner != owner
            || entry.key.as_ref() != Some(key)
            || !matches!(entry.verification, CapsVerification::NeedsDisco)
        {
            return CapsVerificationCommit::Stale;
        }
        if !try_install_verified_summary(
            &mut admission,
            &mut entry,
            summary,
            self.max_summary_bytes,
        ) {
            return CapsVerificationCommit::ResourceLimited;
        }
        entry.pending_effects &= !EFFECT_DISCO_QUERY;
        entry.retry_at = Instant::now();
        entry.consecutive_failures = 0;
        CapsVerificationCommit::Applied
    }

    pub fn mark_invalid(
        &self,
        full_jid: &str,
        owner: CapsObservationOwner,
        key: &CapsKey,
        id: &str,
    ) {
        let Some(mut entry) = self.entries.get_mut(full_jid) else {
            return;
        };
        if entry.owner == owner
            && entry.key.as_ref() == Some(key)
            && matches!(&entry.verification, CapsVerification::Querying { id: current, .. } if current == id)
        {
            entry.verification = CapsVerification::Invalid;
            entry.pending_effects &= !EFFECT_DISCO_QUERY;
        }
    }

    pub fn rearm_expired(&self, id: &str, pending: &PendingCaps, now: Instant) -> bool {
        let Some(mut entry) = self.entries.get_mut(&pending.full_jid) else {
            return false;
        };
        if entry.owner != pending.owner || entry.key.as_ref() != Some(&pending.key) {
            return false;
        }
        if !matches!(&entry.verification, CapsVerification::Querying { id: current, .. } if current == id)
        {
            return false;
        }
        entry.verification = CapsVerification::NeedsDisco;
        entry.pending_effects |= EFFECT_DISCO_QUERY;
        entry.retry_at = now;
        true
    }

    pub fn claim_effects(&self, full_jid: &str, now: Instant) -> Option<CapsEffectJob> {
        let mut entry = self.entries.get_mut(full_jid)?;
        if entry.pending_effects == 0 || entry.running_effects != 0 || entry.retry_at > now {
            return None;
        }
        let effects = CapsEffects(entry.pending_effects);
        entry.pending_effects = 0;
        entry.running_effects = effects.0;
        Some(CapsEffectJob {
            full_jid: full_jid.to_owned(),
            owner: entry.owner,
            key: entry.key.clone(),
            effects,
            queued_at: entry.touched_at.min(now),
        })
    }

    pub fn complete_effects(&self, job: &CapsEffectJob, failed: CapsEffects, now: Instant) -> bool {
        let Some(mut entry) = self.entries.get_mut(&job.full_jid) else {
            return false;
        };
        if entry.owner != job.owner {
            return false;
        }
        entry.running_effects &= !job.effects.0;
        if !failed.is_empty() {
            entry.pending_effects |= failed.0;
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
            entry.retry_at = now + caps_retry_delay(entry.consecutive_failures);
        } else {
            entry.consecutive_failures = 0;
            entry.retry_at = now;
        }
        entry.pending_effects != 0 && entry.running_effects == 0 && entry.retry_at <= now
    }

    pub fn recover_interrupted(&self, now: Instant) {
        for mut entry in self.entries.iter_mut() {
            if entry.running_effects != 0 {
                entry.pending_effects |= entry.running_effects;
                entry.running_effects = 0;
                entry.retry_at = now;
            }
        }
    }

    pub fn ready_observations(&self, now: Instant) -> Vec<(String, bool)> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.pending_effects != 0 && entry.running_effects == 0 && entry.retry_at <= now
            })
            .map(|entry| (entry.key().clone(), entry.owner.is_local()))
            .collect()
    }

    pub fn next_retry_deadline(&self, now: Instant) -> Option<Instant> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.pending_effects != 0 && entry.running_effects == 0 && entry.retry_at > now
            })
            .map(|entry| entry.retry_at)
            .min()
    }

    pub fn federated_resources_for_connection(&self, connection_id: uuid::Uuid) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.owner.federated_connection() == Some(connection_id))
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn remove_federated_resource_if_connection(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> bool {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = self.entries.remove_if(full_jid, |_, observation| {
            observation.owner.federated_connection() == Some(connection_id)
        });
        if let Some((_, observation)) = removed {
            release_observation_admission(&mut admission, &observation);
            true
        } else {
            false
        }
    }

    pub fn remove_local_resource(&self, full_jid: &str, connection_id: uuid::Uuid) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = self.entries.remove_if(full_jid, |_, observation| {
            matches!(observation.owner, CapsObservationOwner::Local(epoch) if epoch.connection_id == connection_id)
        });
        if let Some((_, observation)) = removed {
            release_observation_admission(&mut admission, &observation);
        }
    }

    pub fn remove_local_epoch(&self, full_jid: &str, epoch: LocalCapsEpoch) {
        let mut admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = self.entries.remove_if(full_jid, |_, observation| {
            observation.owner == CapsObservationOwner::Local(epoch)
        });
        if let Some((_, observation)) = removed {
            release_observation_admission(&mut admission, &observation);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn federated_counts(&self, domain: &str) -> (usize, usize) {
        let admission = self
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            admission.federated,
            admission
                .federated_per_domain
                .get(domain)
                .copied()
                .unwrap_or(0),
        )
    }

    pub fn summary_bytes(&self) -> usize {
        self.admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .summary_bytes
    }
}

fn release_observation_admission(
    admission: &mut CapsResourceAdmission,
    observation: &CapsObservation,
) {
    admission.summary_bytes = admission
        .summary_bytes
        .checked_sub(observation.summary_bytes)
        .expect("caps observation summary counter underflow");
    let Some(domain) = observation.federated_domain.as_deref() else {
        return;
    };
    admission.federated = admission
        .federated
        .checked_sub(1)
        .expect("federated caps admission counter underflow");
    let remove_domain = {
        let count = admission
            .federated_per_domain
            .get_mut(domain)
            .expect("federated caps domain counter missing");
        *count = count
            .checked_sub(1)
            .expect("federated caps domain counter underflow");
        *count == 0
    };
    if remove_domain {
        admission.federated_per_domain.remove(domain);
    }
}

fn admit_observation_summary(
    admission: &CapsResourceAdmission,
    replaced_summary_bytes: usize,
    summary: Option<Arc<VerifiedCapsSummary>>,
    max_summary_bytes: usize,
) -> Option<Arc<VerifiedCapsSummary>> {
    let summary = summary?;
    let charge = summary.resident_charge();
    let bytes_after_replacement = admission
        .summary_bytes
        .checked_sub(replaced_summary_bytes)
        .expect("caps replacement summary counter underflow")
        .saturating_add(charge);
    (charge <= max_summary_bytes && bytes_after_replacement <= max_summary_bytes).then_some(summary)
}

fn try_install_verified_summary(
    admission: &mut CapsResourceAdmission,
    entry: &mut CapsObservation,
    summary: Arc<VerifiedCapsSummary>,
    max_summary_bytes: usize,
) -> bool {
    let charge = summary.resident_charge();
    let bytes_after_install = admission
        .summary_bytes
        .checked_sub(entry.summary_bytes)
        .expect("caps observation summary counter underflow")
        .saturating_add(charge);
    if charge > max_summary_bytes || bytes_after_install > max_summary_bytes {
        return false;
    }
    let mut effects = EFFECT_AUTOMATIC_PEP_LAST_ITEMS;
    if entry.owner.is_local()
        && (summary.has_feature("urn:xmpp:mix:core:1") || summary.has_feature("urn:xmpp:mix:pam:2"))
    {
        effects |= EFFECT_VERIFIED_MIX_PRESENCE;
    }
    admission.summary_bytes = bytes_after_install;
    entry.summary_bytes = charge;
    entry.verification = CapsVerification::Verified(summary);
    entry.pending_effects |= effects;
    true
}

fn new_caps_observation(
    owner: CapsObservationOwner,
    key: Option<CapsKey>,
    cached: Option<Arc<VerifiedCapsSummary>>,
    federated_domain: Option<String>,
    now: Instant,
) -> CapsObservation {
    let (verification, mut pending_effects) = match (key.as_ref(), cached) {
        (None, _) => (
            CapsVerification::NoAdvertisement,
            EFFECT_EXPLICIT_PEP_LAST_ITEMS,
        ),
        (Some(_), Some(summary)) => {
            let mut effects = EFFECT_EXPLICIT_PEP_LAST_ITEMS | EFFECT_AUTOMATIC_PEP_LAST_ITEMS;
            if owner.is_local()
                && (summary.has_feature("urn:xmpp:mix:core:1")
                    || summary.has_feature("urn:xmpp:mix:pam:2"))
            {
                effects |= EFFECT_VERIFIED_MIX_PRESENCE;
            }
            (CapsVerification::Verified(summary), effects)
        }
        (Some(_), None) => (
            CapsVerification::NeedsDisco,
            EFFECT_EXPLICIT_PEP_LAST_ITEMS | EFFECT_DISCO_QUERY,
        ),
    };
    if !owner.is_local() {
        pending_effects &= !EFFECT_VERIFIED_MIX_PRESENCE;
    }
    let summary_bytes = match &verification {
        CapsVerification::Verified(summary) => summary.resident_charge(),
        _ => 0,
    };
    CapsObservation {
        owner,
        key,
        verification,
        pending_effects,
        running_effects: 0,
        retry_at: now,
        consecutive_failures: 0,
        touched_at: now,
        federated_domain,
        summary_bytes,
    }
}

pub fn caps_retry_delay(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(7);
    CAPS_EFFECT_RETRY_BASE
        .saturating_mul(1_u32 << shift)
        .min(CAPS_EFFECT_RETRY_MAX)
}
