use std::time::Duration;

use crate::config::AbuseConfig;
use crate::model::MAX_PENALTY_LEVEL;

/// Calculate the exponential cooldown interval for a given penalty level.
///
/// Level 0 returns base (1x), level 1 returns 2x, level 2 returns 4x, ...,
/// capped at level 10 (1024x).
pub fn penalty_cooldown_interval(base: Duration, level: u32) -> Duration {
    base.saturating_mul(1_u32 << level.min(MAX_PENALTY_LEVEL))
}

/// Calculate the decayed penalty level and total consumed cooldown duration
/// after an elapsed duration of inactivity.
pub fn decayed_penalty(
    mut level: u32,
    elapsed: Duration,
    cooldown_step: Duration,
) -> (u32, Duration) {
    if cooldown_step.is_zero() || level == 0 {
        return (level, Duration::ZERO);
    }
    let mut consumed = Duration::ZERO;
    while level > 0 {
        let interval = penalty_cooldown_interval(cooldown_step, level);
        if elapsed.saturating_sub(consumed) < interval {
            break;
        }
        consumed = consumed.saturating_add(interval);
        level -= 1;
    }
    (level, consumed)
}

/// Computes the complete geometric decay horizon needed to cool from
/// the maximum penalty level (10) down to 0.
///
/// Total horizon = sum_{level=1}^{10} (cooldown_step * 2^level) = cooldown_step * 2046.
pub fn max_penalty_decay_horizon(cooldown_step: Duration) -> Duration {
    (1..=MAX_PENALTY_LEVEL).fold(Duration::ZERO, |total, level| {
        total.saturating_add(penalty_cooldown_interval(cooldown_step, level))
    })
}

/// Calculate new penalty level and exponential hard wait duration on failure.
pub fn punish_penalty_and_wait(current_penalty: u32, max_wait: Duration) -> (u32, Duration) {
    let new_penalty = current_penalty.saturating_add(1).min(MAX_PENALTY_LEVEL);
    let wait_secs = 2_u64
        .saturating_pow(new_penalty.min(9))
        .min(max_wait.as_secs());
    (new_penalty, Duration::from_secs(wait_secs))
}

/// Computes the minimum required key rotation overlap window.
///
/// Ensures that before an old HMAC key is retired, all active challenges,
/// message admissions, offline dedupe tombstones, and penalty history have expired.
pub fn minimum_key_rotation_overlap(
    config: &AbuseConfig,
    message_admission_accepted_ttl: Duration,
    offline_message_replay_grace: Duration,
) -> Duration {
    config
        .window
        .max(config.max_wait)
        .max(config.max_wait.saturating_add(Duration::from_secs(30)))
        .max(max_penalty_decay_horizon(config.cooldown_step))
        .max(message_admission_accepted_ttl)
        .max(offline_message_replay_grace)
}

/// Trims sliding-window event timestamps older than `now - window`.
///
/// Bounded to a maximum of 4,096 entries to protect storage and memory
/// against runaway event floods.
pub fn trim_event_timestamps_utc(
    events: &mut Vec<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
    window: Duration,
) {
    let window_secs = i64::try_from(window.as_secs()).unwrap_or(i64::MAX);
    let cutoff = now - chrono::Duration::seconds(window_secs);
    events.retain(|event| *event >= cutoff && *event <= now);
    if events.len() > 4_096 {
        events.drain(..events.len() - 4_096);
    }
}

/// Decays penalty level using injected UTC timestamps.
pub fn decay_penalty_level_utc(
    penalty_level: u32,
    last_activity: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    cooldown_step: Duration,
) -> (u32, chrono::DateTime<chrono::Utc>) {
    if penalty_level == 0 || cooldown_step.is_zero() {
        return (penalty_level, last_activity);
    }
    let elapsed_secs = now
        .signed_duration_since(last_activity)
        .num_seconds()
        .max(0) as u64;
    let (level, consumed) = decayed_penalty(
        penalty_level,
        Duration::from_secs(elapsed_secs),
        cooldown_step,
    );
    let consumed_secs = i64::try_from(consumed.as_secs()).unwrap_or(i64::MAX);
    let updated_activity = last_activity + chrono::Duration::seconds(consumed_secs);
    (level, updated_activity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn penalty_cooldown_interval_doubles_each_level() {
        let base = Duration::from_secs(10);
        assert_eq!(penalty_cooldown_interval(base, 0), Duration::from_secs(10));
        assert_eq!(penalty_cooldown_interval(base, 1), Duration::from_secs(20));
        assert_eq!(penalty_cooldown_interval(base, 2), Duration::from_secs(40));
        assert_eq!(penalty_cooldown_interval(base, 3), Duration::from_secs(80));
        assert_eq!(
            penalty_cooldown_interval(base, 10),
            Duration::from_secs(10240)
        );
        assert_eq!(
            penalty_cooldown_interval(base, 20),
            Duration::from_secs(10240)
        );
    }

    #[test]
    fn geometric_penalty_decay_progression() {
        let step = Duration::from_secs(30);
        // Level 3 requires interval(3) = 30 * 8 = 240s to drop to level 2
        assert_eq!(
            decayed_penalty(3, Duration::from_secs(239), step),
            (3, Duration::ZERO)
        );
        assert_eq!(
            decayed_penalty(3, Duration::from_secs(240), step),
            (2, Duration::from_secs(240))
        );
        // Level 2 requires interval(2) = 30 * 4 = 120s additional (total 360s) to drop to level 1
        assert_eq!(
            decayed_penalty(3, Duration::from_secs(360), step),
            (1, Duration::from_secs(360))
        );
        // Level 1 requires interval(1) = 30 * 2 = 60s additional (total 420s) to drop to level 0
        assert_eq!(
            decayed_penalty(3, Duration::from_secs(420), step),
            (0, Duration::from_secs(420))
        );
        // Extra time past level 0 does not consume further
        assert_eq!(
            decayed_penalty(3, Duration::from_secs(1000), step),
            (0, Duration::from_secs(420))
        );
    }

    #[test]
    fn max_decay_horizon_exact_multiple() {
        let step = Duration::from_secs(1);
        // sum_{l=1}^{10} 2^l = 2 + 4 + 8 + 16 + 32 + 64 + 128 + 256 + 512 + 1024 = 2046
        assert_eq!(max_penalty_decay_horizon(step), Duration::from_secs(2046));
    }

    #[test]
    fn punish_penalty_progression_and_wait_cap() {
        let max_wait = Duration::from_secs(300);
        let (p1, w1) = punish_penalty_and_wait(0, max_wait);
        assert_eq!(p1, 1);
        assert_eq!(w1, Duration::from_secs(2)); // 2^1

        let (p2, w2) = punish_penalty_and_wait(1, max_wait);
        assert_eq!(p2, 2);
        assert_eq!(w2, Duration::from_secs(4)); // 2^2

        let (p9, w9) = punish_penalty_and_wait(8, max_wait);
        assert_eq!(p9, 9);
        assert_eq!(w9, Duration::from_secs(300)); // 2^9 = 512 capped at 300

        let (p10, w10) = punish_penalty_and_wait(9, max_wait);
        assert_eq!(p10, 10);
        assert_eq!(w10, Duration::from_secs(300)); // 2^9 = 512 capped at 300
    }

    #[test]
    fn trim_event_timestamps_retains_only_window_and_bounds_size() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-02T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let window = Duration::from_secs(60);
        let mut events = vec![
            now - chrono::Duration::seconds(100),
            now - chrono::Duration::seconds(50),
            now - chrono::Duration::seconds(10),
            now + chrono::Duration::seconds(5), // Future timestamp dropped
        ];
        trim_event_timestamps_utc(&mut events, now, window);
        assert_eq!(events.len(), 2);
    }
}
