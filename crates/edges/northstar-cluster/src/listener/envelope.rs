//! Verify signed listener envelopes and classify their command payloads.

use super::*;
use northstar_security::cluster_bus::SignedClusterEnvelope;

pub(super) struct VerifiedListenerEnvelope {
    pub(super) envelope: SignedClusterEnvelope,
    pub(super) source_node: String,
    pub(super) protocol_version: u16,
}

pub(super) async fn verify_listener_envelope(
    security: &ClusterListenerSecurity,
    admission: &ClusterListenerAdmission,
    payload: &str,
    channel: &str,
    (candidate_generation, rotation_epoch): (u64, u64),
) -> Result<ListenerStep<VerifiedListenerEnvelope>> {
    let envelope = match security
        .verify_signed_payload_persisted(payload, channel, None)
        .await
    {
        Ok(envelope) => envelope,
        Err(error) => {
            admission.note_authentication_failure(&error);
            return Ok(ListenerStep::Continue);
        }
    };
    let protocol_version = envelope.version;
    let envelope_kind = envelope.kind;
    let source_node = envelope.source_node.clone();
    admission.validate_generation(candidate_generation, rotation_epoch)?;
    if envelope_kind == northstar_security::cluster_bus::ClusterCommandKind::Ack {
        if !admission.dispatch_pending_ack(&source_node, envelope.payload) {
            admission.note_authentication_failure(&anyhow::anyhow!(
                "cluster acknowledgement had no exact pending request"
            ));
        }
        return Ok(ListenerStep::Continue);
    }
    Ok(ListenerStep::Next(VerifiedListenerEnvelope {
        envelope,
        source_node,
        protocol_version,
    }))
}

pub(super) struct ListenerCommandFlags {
    pub(super) is_muc: bool,
    pub(super) is_muc_presence: bool,
    pub(super) is_muc_nickname_change: bool,
    pub(super) is_muc_role_change: bool,
    pub(super) is_muc_evict: bool,
    pub(super) is_muc_destroy: bool,
    pub(super) is_muc_operation_wake: bool,
    pub(super) is_muc_private: bool,
    pub(super) is_sm_muc_teardown: bool,
    pub(super) is_sm_session_teardown: bool,
    pub(super) is_account_generation_teardown: bool,
    pub(super) is_user_agent_replacement: bool,
    pub(super) is_session_termination: bool,
    pub(super) is_blocking_presence_change: bool,
    pub(super) is_presence_probe: bool,
}

pub(super) struct ListenerCommand<'a> {
    pub(super) target: &'a str,
    pub(super) turn: ListenerTurn,
    pub(super) flags: ListenerCommandFlags,
}

pub(super) fn prepare_listener_command<'a>(
    admission: &ClusterListenerAdmission,
    json: &'a serde_json::Value,
    protocol_version: u16,
) -> ListenerStep<ListenerCommand<'a>> {
    let Some(target) = json["target"].as_str() else {
        return ListenerStep::Continue;
    };
    let delivered = 0usize;
    let accepted_full_jid = None;
    let mix_supported = 0usize;
    let mix_unsupported = 0usize;
    let mix_unknown = 0usize;
    let mix_handoff = None;
    let control_processed = None;
    let control_outcome = None;
    let acknowledged_delivery = None;
    let responses = ListenerResponses::default();
    let is_muc = json["muc_broadcast"].as_bool().unwrap_or(false);
    let is_muc_presence = json["muc_presence"].as_bool().unwrap_or(false);
    let is_muc_nickname_change = json["muc_nickname_change"].as_bool().unwrap_or(false);
    let is_muc_role_change = json["muc_role_change"].as_bool().unwrap_or(false);
    let is_muc_evict = json["muc_evict"].as_bool().unwrap_or(false);
    let is_muc_destroy = json["muc_destroy"].as_bool().unwrap_or(false);
    let is_muc_operation_wake = json["muc_operation_wake"].as_bool().unwrap_or(false);
    let is_muc_private = json["muc_private"].as_bool().unwrap_or(false);
    let is_sm_muc_teardown = json["sm_muc_teardown"].as_bool().unwrap_or(false);
    let is_sm_session_teardown = json["sm_session_teardown"].as_bool().unwrap_or(false);
    let is_account_generation_teardown = json["account_generation_teardown"]
        .as_bool()
        .unwrap_or(false);
    let is_user_agent_replacement = json["user_agent_replacement"].as_bool().unwrap_or(false);
    let is_session_termination = json["session_termination"].as_bool().unwrap_or(false);
    let is_blocking_presence_change = json["blocking_presence_change"].as_bool().unwrap_or(false);
    let is_presence_probe = json["presence_probe"].as_bool().unwrap_or(false);

    if protocol_version >= northstar_security::cluster_bus::SIGNED_PROTOCOL_VERSION
        && (is_muc_nickname_change || is_muc_role_change || is_muc_evict || is_muc_destroy)
    {
        // Protocol-v9 MUC controls are wake-only. A signed Redis payload
        // is authenticated transport data, not authorization to execute
        // a mutation; peers must commit/pull the PG operation instead.
        admission.note_authentication_failure(&anyhow::anyhow!(
            "protocol-v9 executable MUC control rejected"
        ));
        return ListenerStep::Continue;
    }
    ListenerStep::Next(ListenerCommand {
        target,
        turn: ListenerTurn {
            delivered,
            accepted_full_jid,
            mix_supported,
            mix_unsupported,
            mix_unknown,
            mix_handoff,
            control_processed,
            control_outcome,
            acknowledged_delivery,
            responses,
        },
        flags: ListenerCommandFlags {
            is_muc,
            is_muc_presence,
            is_muc_nickname_change,
            is_muc_role_change,
            is_muc_evict,
            is_muc_destroy,
            is_muc_operation_wake,
            is_muc_private,
            is_sm_muc_teardown,
            is_sm_session_teardown,
            is_account_generation_teardown,
            is_user_agent_replacement,
            is_session_termination,
            is_blocking_presence_change,
            is_presence_probe,
        },
    })
}
