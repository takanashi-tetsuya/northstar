mod enable;
mod resume;

use super::{Action, ProtocolSession};
use crate::protocol::SessionHost;
use anyhow::Result;
use northstar_xep_0198::build_failed_str as sm_failed;
use roxmltree::Node;
use sha2::{Digest, Sha256};

#[cfg(test)]
use self::resume::{
    claim_sm_route_lifecycle, lock_mix_presence_gate_for_claim, muc_resume_failure_stanza,
    stage_muc_replay_suffix, validated_sm_session_key, wait_for_exact_route_removal,
    ClaimBoundWaitAbort, RouteRemovalWait, SmRouteTakeover,
};
#[cfg(test)]
use crate::local_routes::session_table::matching_sm_route;
#[cfg(test)]
use northstar_xep_0198::{
    acknowledgement_delta, resumability_allowed, resumed_offline_replay_eligible,
};

fn sm_resume_token_hash(emitted_bearer: &str) -> [u8; 32] {
    Sha256::digest(emitted_bearer.as_bytes()).into()
}

impl<H: SessionHost> ProtocolSession<H> {
    pub(crate) async fn stream_management(&mut self, root: Node<'_, '_>) -> Result<Action> {
        match root.tag_name().name() {
            "enable" => {
                let request = match northstar_xep_0198::parse_enable(root) {
                    Ok(request) if request.max.is_none() || request.resume => request,
                    Ok(_) | Err(_) => return Ok(Action::Send(sm_failed("bad-request"))),
                };
                Ok(Action::Send(
                    self.enable_sm_inline(request.resume, request.max.map(u64::from))
                        .await
                        .unwrap_or_else(sm_failed),
                ))
            }
            "r" if self.sm.enabled => {
                if northstar_xep_0198::parse_r(root).is_err() {
                    return Ok(Action::Send(sm_failed("bad-request")));
                }
                Ok(Action::Send(northstar_xep_0198::build_a(self.sm.inbound_h)))
            }
            "a" if self.sm.enabled => {
                let h = match northstar_xep_0198::parse_a(root) {
                    Ok(answer) => answer.h.get(),
                    Err(_) => {
                        return Ok(Action::Send(sm_failed("bad-request")));
                    }
                };
                if !self.acknowledge(h).await? {
                    self.sm.resume_allowed = false;
                    if let Some(id) = self.sm.db_id.take() {
                        // Preserve and durably lease the availability/MUC
                        // snapshot until teardown completes. A direct DELETE
                        // here creates a process-crash window with permanent
                        // ghost presence or occupants.
                        self.host.revoke_sm_session_with_teardown(id).await?;
                        *self
                            .sm
                            .session_id_shared
                            .write()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
                    }
                    return Ok(Action::CloseWith(
                        northstar_xep_0198::build_handled_count_too_high_stream_error(
                            h,
                            self.sm.outbound_h,
                        ),
                    ));
                }
                Ok(Action::None)
            }
            "resume" => self.resume(root).await,
            _ => Ok(Action::Send(sm_failed("unexpected-request"))),
        }
    }
}

impl<H: SessionHost> ProtocolSession<H> {
    pub(crate) async fn acknowledge(&mut self, h: u32) -> Result<bool> {
        let mut turn = self.sm_transport_turn();
        let observation =
            turn.start(northstar_delivery_core::sm_ownership::Purpose::Acknowledge { h });
        super::sm_owner::SmTurnRunner::new(observation.clone(), async move {
            let result = turn.acknowledge(h, &observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await
    }

    pub(crate) fn reset_sm(&mut self) {
        self.sm.enabled = false;
        self.presence.resumed_caps_presence = None;
        self.sm.db_id = None;
        *self
            .sm
            .session_id_shared
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.sm.resume_allowed = false;
        self.sm.resume_timeout_seconds = 0;
        self.sm.inbound_h = 0;
        self.sm.outbound_h = 0;
        self.sm.acked_h = 0;
        self.sm.unacked.clear();
        self.sm.capacity = None;
    }
}

#[cfg(test)]
mod tests;
