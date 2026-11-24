use super::*;
use northstar_message_application::messaging::LocalRecipient;
use std::ops::ControlFlow::{Break, Continue};

pub(super) struct LocalTargets<H: FullJidFallbackPort> {
    pub(super) spool_only_now: bool,
    pub(super) targets: Vec<(String, H::Session)>,
    pub(super) default_privacy_for_spool: Option<Result<bool>>,
    pub(super) spool_privacy_permits: bool,
}

#[expect(
    clippy::too_many_arguments,
    reason = "retain the local routing policy inputs at the existing decision point"
)]
pub(super) async fn select<S: MessageSession>(
    state: &S::Host,
    root: Node<'_, '_>,
    local_direct: bool,
    degraded_spool_eligible: bool,
    to: &str,
    bare_target: bool,
    message_type: &str,
    from: &str,
    recipient: &LocalRecipient,
) -> Result<ControlFlow<S::Action, LocalTargets<S::Host>>> {
    let spool_only_now = if local_direct {
        match state.message_service().direct_mode() {
            DirectPostCommitMode::Live => false,
            DirectPostCommitMode::SpoolOnly if degraded_spool_eligible => true,
            DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected => {
                return Ok(Break(message_error(root, "wait", "service-unavailable")));
            }
        }
    } else {
        false
    };
    // The degraded destination is the PostgreSQL recipient spool. Redis
    // session discovery cannot establish a live route in this mode.
    let mut targets = if spool_only_now {
        Vec::new()
    } else {
        state.fallback_sessions(to)
    };
    if bare_target {
        targets.retain(|(_, target)| state.available_priority(target).is_some());
        if message_type != "headline" {
            targets.sort_by(|(left_jid, left), (right_jid, right)| {
                state
                    .priority(right)
                    .cmp(&state.priority(left))
                    .then_with(|| left_jid.cmp(right_jid))
            });
        }
    }
    let unfiltered_local_targets = targets.len();
    let mut privacy_allowed_targets = Vec::with_capacity(targets.len());
    for target in targets {
        if state.privacy_allows_fallback(&target.1, from).await? {
            privacy_allowed_targets.push(target);
        }
    }
    let targets = privacy_allowed_targets;
    if unfiltered_local_targets > 0 && targets.is_empty() {
        return Ok(Break(message_error(root, "cancel", "service-unavailable")));
    }
    let remote_route_exists = if spool_only_now {
        false
    } else {
        state.personal_message_remote_resource_exists(to).await
    };
    // A live resource's active privacy list may override the account
    // default. If mode changes to SpoolOnly inside the PG transaction,
    // however, the delivery becomes account-scoped. Read that default
    // even when a live resource exists so the transaction can be marked
    // LiveOnly when an account spool would violate recipient privacy.
    let mut default_privacy_for_spool = if degraded_spool_eligible {
        Some(
            state
                .message_service()
                .default_recipient_privacy_denies(recipient.id, from)
                .await,
        )
    } else {
        None
    };
    let spool_privacy_permits = matches!(&default_privacy_for_spool, Some(Ok(false)));
    if targets.is_empty() && !remote_route_exists {
        let default_denies = match default_privacy_for_spool.take() {
            Some(result) => result?,
            None => {
                state
                    .message_service()
                    .default_recipient_privacy_denies(recipient.id, from)
                    .await?
            }
        };
        if default_denies {
            return Ok(Break(message_error(root, "cancel", "service-unavailable")));
        }
    }
    Ok(Continue(LocalTargets {
        spool_only_now,
        targets,
        default_privacy_for_spool,
        spool_privacy_permits,
    }))
}
