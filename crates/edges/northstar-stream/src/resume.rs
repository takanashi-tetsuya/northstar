//! The XEP-0198 resume payload a protocol session hands its transport. The capacity leases it holds keep the
//! process SM memory governor charged until the transport has written, queued or discarded the payload.

use anyhow::{Context, Result};
use std::{collections::VecDeque, sync::Arc};

/// Transport-owned XEP-0198 replay payload. The capacity leases are acquired
/// before the replay strings are cloned and remain attached until a transport
/// has written, queued for ordered HTTP delivery, or discarded the complete
/// action. This prevents many simultaneous resumes from bypassing the process
/// SM memory governor with an otherwise short-lived `Vec<String>` clone.
pub struct ResumePayload {
    pub control: String,
    /// Ordered nonzas which must follow the resume control before any replayed
    /// stanza. SASL2 uses this for the mandatory post-success stream features.
    post_control: Vec<String>,
    replay: Vec<String>,
    pub activate_route: bool,
    pub auth_publication: Option<crate::auth_publication::AuthControlHolder>,
    transient_capacity: Vec<northstar_session_application::sm_capacity::SmCapacityLease>,
}

pub struct ResumeTransportParts {
    pub control: String,
    pub post_control: Vec<String>,
    pub replay: Vec<String>,
    pub activate_route: bool,
    pub auth_publication: Option<crate::auth_publication::AuthControlHolder>,
    pub transient_capacity: Vec<northstar_session_application::sm_capacity::SmCapacityLease>,
}

impl ResumePayload {
    pub fn from_sm_unacked(
        governor: &Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>,
        control: String,
        post_control: Vec<String>,
        replay_source: &VecDeque<crate::outbound::SmUnackedStanza>,
        activate_route: bool,
    ) -> Result<Self> {
        let requested_bytes = resume_payload_requested_bytes(
            &control,
            &post_control,
            replay_source.iter().map(|entry| entry.stanza.len()),
            replay_source.len(),
        )
        .context("XEP-0198 transport replay allocation overflow")?;
        let transient_capacity = governor
            .try_reserve_transient(requested_bytes)
            .context("XEP-0198 transport replay memory capacity reached")?;

        // Allocate every clone only after the complete process reservation.
        // Explicit capacities make the preflight and actual resident charge
        // identical rather than relying on `collect` growth heuristics.
        let mut replay = Vec::with_capacity(replay_source.len());
        for entry in replay_source {
            let mut stanza = String::with_capacity(entry.stanza.len());
            stanza.push_str(&entry.stanza);
            replay.push(stanza);
        }
        let actual_bytes = resume_payload_actual_bytes(&control, &post_control, &replay)
            .context("XEP-0198 transport replay allocation overflow")?;
        anyhow::ensure!(
            actual_bytes <= requested_bytes,
            "XEP-0198 transport replay allocation exceeded its reservation"
        );
        Ok(Self {
            control,
            post_control,
            replay,
            activate_route,
            auth_publication: None,
            transient_capacity,
        })
    }

    pub fn control(&self) -> &str {
        &self.control
    }

    pub fn replace_envelope(
        &mut self,
        control: String,
        post_control: Vec<String>,
        reserved_bytes: usize,
        mut capacity: Vec<northstar_session_application::sm_capacity::SmCapacityLease>,
    ) -> Result<()> {
        anyhow::ensure!(
            self.auth_publication.is_none(),
            "cannot replace a sealed authentication envelope"
        );
        let actual = control
            .capacity()
            .checked_add(
                post_control
                    .capacity()
                    .checked_mul(std::mem::size_of::<String>())
                    .context("SASL2 resume post-control allocation overflow")?,
            )
            .and_then(|bytes| {
                post_control
                    .iter()
                    .try_fold(bytes, |bytes, stanza| bytes.checked_add(stanza.capacity()))
            })
            .context("SASL2 resume transport envelope allocation overflow")?;
        anyhow::ensure!(
            actual <= reserved_bytes,
            "SASL2 resume transport envelope exceeded its reservation"
        );
        self.control = control;
        self.post_control = post_control;
        self.transient_capacity.append(&mut capacity);
        Ok(())
    }

    pub fn into_transport_parts(self) -> ResumeTransportParts {
        ResumeTransportParts {
            control: self.control,
            post_control: self.post_control,
            replay: self.replay,
            activate_route: self.activate_route,
            auth_publication: self.auth_publication,
            transient_capacity: self.transient_capacity,
        }
    }
}

fn resume_payload_requested_bytes(
    control: &String,
    post_control: &Vec<String>,
    mut replay_lengths: impl Iterator<Item = usize>,
    replay_count: usize,
) -> Option<usize> {
    let bytes = control.capacity().checked_add(
        post_control
            .capacity()
            .checked_mul(std::mem::size_of::<String>())?,
    )?;
    let bytes = post_control
        .iter()
        .try_fold(bytes, |bytes, stanza| bytes.checked_add(stanza.capacity()))?;
    let bytes = bytes.checked_add(replay_count.checked_mul(std::mem::size_of::<String>())?)?;
    replay_lengths.try_fold(bytes, usize::checked_add)
}

fn resume_payload_actual_bytes(
    control: &String,
    post_control: &Vec<String>,
    replay: &Vec<String>,
) -> Option<usize> {
    let bytes = control
        .capacity()
        .checked_add(
            post_control
                .capacity()
                .checked_mul(std::mem::size_of::<String>())?,
        )?
        .checked_add(
            replay
                .capacity()
                .checked_mul(std::mem::size_of::<String>())?,
        )?;
    let bytes = post_control
        .iter()
        .chain(replay)
        .try_fold(bytes, |bytes, stanza| bytes.checked_add(stanza.capacity()))?;
    Some(bytes)
}
