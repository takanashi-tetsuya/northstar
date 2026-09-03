use crate::config::AbuseConfig;
use crate::cooldown::penalty_cooldown_interval;
use crate::model::{AbuseAction, WorkRequirement};

/// Internal policy envelope detailing free burst allowance and base work factor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    pub free_burst: usize,
    pub base_work: u64,
}

/// Computes the action-specific policy parameters.
pub fn policy(action: AbuseAction, base_work: u64, message_free_burst: usize) -> Policy {
    match action {
        AbuseAction::Registration => Policy {
            free_burst: 1,
            base_work,
        },
        AbuseAction::Message => Policy {
            free_burst: message_free_burst,
            base_work,
        },
        AbuseAction::Report => Policy {
            free_burst: 0,
            base_work: base_work.saturating_mul(2),
        },
        AbuseAction::Appeal => Policy {
            free_burst: 0,
            base_work: base_work.saturating_mul(8),
        },
        AbuseAction::Login => Policy {
            free_burst: 5,
            base_work,
        },
        AbuseAction::PasswordChange => Policy {
            free_burst: 3,
            base_work: base_work.saturating_mul(4),
        },
    }
}

/// Calculate current rate-limiting escalation step from event count and free burst.
pub fn step_from_events(event_count: usize, free_burst: usize) -> u32 {
    let next_event = event_count.saturating_add(1);
    next_event.saturating_sub(free_burst) as u32
}

/// Computes quadratic PoW work factor scaled by exponential failure penalties.
///
/// Formula: work = base_work * (step^2) * (2^penalty), bounded by max_work_factor.
/// Step 0 or base 0 returns 1 (no PoW required).
pub fn calculate_work_factor(base_work: u64, step: u32, penalty: u32, max_work_factor: u64) -> u64 {
    if step == 0 || base_work == 0 {
        return 1;
    }
    let squared = u64::from(step).saturating_mul(u64::from(step));
    let penalty_multiplier = 1_u64.checked_shl(penalty.min(20)).unwrap_or(u64::MAX);
    base_work
        .saturating_mul(squared)
        .saturating_mul(penalty_multiplier)
        .clamp(1, max_work_factor)
}

/// Computes the hard waiting delay in seconds.
///
/// Stepped progression:
/// - step 0..=3: 0s
/// - step 4..=7: 2s
/// - step 8..=11: 10s
/// - step 12..=15: 30s
/// - step 16+: 120s
///
/// For Appeal actions, a minimum strict baseline of 15s is enforced.
/// Multiplied by 2^(penalty.min(8)).
pub fn hard_wait_seconds(action: AbuseAction, step: u32, penalty: u32) -> u64 {
    let base: u64 = match step {
        0..=3 => 0,
        4..=7 => 2,
        8..=11 => 10,
        12..=15 => 30,
        _ => 120,
    };
    let strict: u64 = match action {
        AbuseAction::Appeal => 15,
        _ => 0,
    };
    let multiplier = 1_u64.checked_shl(penalty.min(8)).unwrap_or(u64::MAX);
    base.max(strict).saturating_mul(multiplier)
}

/// Standard client notice string explaining rate limits and PoW semantics.
pub const ABUSE_NOTICE: &str = "Work rises in quadratic steps, has an operator-calibrated fixed maximum, and falls one penalty level at a time after activity stops. The advertised cooldown is the interval for the current penalty level; each higher level takes twice as long. Standards-only XMPP clients use the free burst and retry cooldown instead of PoW.";

/// Constructs a complete `WorkRequirement` envelope.
pub fn build_requirement(
    action: AbuseAction,
    policy: Policy,
    event_count: usize,
    penalty: u32,
    retry_after: u64,
    config: &AbuseConfig,
) -> WorkRequirement {
    let step = step_from_events(event_count, policy.free_burst);
    let work_factor =
        calculate_work_factor(policy.base_work, step, penalty, config.max_work_factor);
    let hard_wait = hard_wait_seconds(action, step, penalty)
        .min(config.max_wait.as_secs())
        .max(retry_after);

    let cooldown_seconds = if penalty == 0 {
        config.window.as_secs()
    } else {
        penalty_cooldown_interval(config.cooldown_step, penalty).as_secs()
    };

    WorkRequirement {
        action: action.as_str().to_owned(),
        step,
        work_factor,
        max_work_factor: config.max_work_factor,
        hard_wait_seconds: hard_wait,
        retry_after_seconds: retry_after,
        cooldown_seconds,
        approximate_max_device_seconds: config.approximate_max_device_seconds,
        notice: ABUSE_NOTICE.to_owned(),
    }
}

/// Verifies whether a prefetched challenge for an outgoing message stanza
/// remains sufficiently strict to satisfy the live requirement at consumption time.
///
/// Message challenges can be prepared in advance during normal client operation.
/// A prefetched challenge is accepted if no new retry cooldown has been activated
/// and its advertised work factor and hard delay are both at least as strict as
/// the current requirement.
pub fn prefetched_message_challenge_remains_sufficient(
    action: AbuseAction,
    challenge: &WorkRequirement,
    current: &WorkRequirement,
) -> bool {
    action == AbuseAction::Message
        && current.retry_after_seconds == 0
        && challenge.work_factor >= current.work_factor
        && challenge.hard_wait_seconds >= current.hard_wait_seconds
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> AbuseConfig {
        AbuseConfig {
            base_work_factor: 100,
            max_work_factor: 10_000,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        }
    }

    #[test]
    fn message_escalates_quadratically_after_free_burst() {
        let config = test_config();
        let p = policy(
            AbuseAction::Message,
            config.base_work_factor,
            config.message_free_burst,
        );
        assert_eq!(p.free_burst, 6);
        assert_eq!(p.base_work, 100);

        // 0..6 events (within free burst)
        for count in 0..6 {
            let req = build_requirement(AbuseAction::Message, p, count, 0, 0, &config);
            assert_eq!(req.step, 0);
            assert_eq!(req.work_factor, 1);
            assert_eq!(req.hard_wait_seconds, 0);
        }

        // Event 6 -> 7th event -> step 1
        let req1 = build_requirement(AbuseAction::Message, p, 6, 0, 0, &config);
        assert_eq!(req1.step, 1);
        assert_eq!(req1.work_factor, 100); // 100 * 1^2

        // Event 7 -> 8th event -> step 2
        let req2 = build_requirement(AbuseAction::Message, p, 7, 0, 0, &config);
        assert_eq!(req2.step, 2);
        assert_eq!(req2.work_factor, 400); // 100 * 2^2

        // Event 8 -> 9th event -> step 3
        let req3 = build_requirement(AbuseAction::Message, p, 8, 0, 0, &config);
        assert_eq!(req3.step, 3);
        assert_eq!(req3.work_factor, 900); // 100 * 3^2
    }

    #[test]
    fn hard_wait_step_thresholds() {
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 0, 0), 0);
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 3, 0), 0);
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 4, 0), 2);
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 7, 0), 2);
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 8, 0), 10);
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 11, 0), 10);
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 12, 0), 30);
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 15, 0), 30);
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 16, 0), 120);

        // Appeal baseline minimum is 15s
        assert_eq!(hard_wait_seconds(AbuseAction::Appeal, 0, 0), 15);
        assert_eq!(hard_wait_seconds(AbuseAction::Appeal, 4, 0), 15);
        assert_eq!(hard_wait_seconds(AbuseAction::Appeal, 12, 0), 30);
        assert_eq!(hard_wait_seconds(AbuseAction::Appeal, 16, 0), 120);

        // Penalty scaling: 1 << min(penalty, 8)
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 4, 1), 4); // 2 * 2^1
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 4, 2), 8); // 2 * 2^2
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 4, 8), 512); // 2 * 2^8
        assert_eq!(hard_wait_seconds(AbuseAction::Message, 4, 20), 512); // capped at 2^8
    }

    #[test]
    fn saturating_arithmetic_prevents_overflow() {
        let config = test_config();
        let p = policy(
            AbuseAction::Report,
            config.base_work_factor,
            config.message_free_burst,
        );

        let req = build_requirement(
            AbuseAction::Report,
            p,
            usize::MAX,
            u32::MAX,
            u64::MAX,
            &config,
        );
        assert_eq!(req.work_factor, config.max_work_factor);
        assert_eq!(req.hard_wait_seconds, u64::MAX); // max(hard_wait.min(max_wait), retry_after)
    }

    #[test]
    fn prefetched_message_challenge_sufficiency_checks() {
        let req_free = WorkRequirement {
            action: "message".to_owned(),
            step: 0,
            work_factor: 1,
            max_work_factor: 10_000,
            hard_wait_seconds: 0,
            retry_after_seconds: 0,
            cooldown_seconds: 60,
            approximate_max_device_seconds: 8,
            notice: String::new(),
        };

        let req_step1 = WorkRequirement {
            action: "message".to_owned(),
            step: 1,
            work_factor: 100,
            max_work_factor: 10_000,
            hard_wait_seconds: 0,
            retry_after_seconds: 0,
            cooldown_seconds: 60,
            approximate_max_device_seconds: 8,
            notice: String::new(),
        };

        let req_with_retry = WorkRequirement {
            retry_after_seconds: 5,
            ..req_step1.clone()
        };

        // Strict challenge matches or exceeds live requirement
        assert!(prefetched_message_challenge_remains_sufficient(
            AbuseAction::Message,
            &req_step1,
            &req_free
        ));

        // Cheaper challenge fails when live requirement has stepped up
        assert!(!prefetched_message_challenge_remains_sufficient(
            AbuseAction::Message,
            &req_free,
            &req_step1
        ));

        // Active retry cooldown on caller denies prefetched challenge
        assert!(!prefetched_message_challenge_remains_sufficient(
            AbuseAction::Message,
            &req_step1,
            &req_with_retry
        ));

        // Non-message actions do not permit prefetched relaxed sufficiency
        assert!(!prefetched_message_challenge_remains_sufficient(
            AbuseAction::Report,
            &req_step1,
            &req_free
        ));
    }
}
