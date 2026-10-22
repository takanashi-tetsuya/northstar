use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

use crate::cooldown::max_penalty_decay_horizon;

/// Configuration for anti-abuse rate-limiting, work escalation, and cooldown decays.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AbuseConfig {
    /// Base work factor multiplier applied at step 1. Must be > 0.
    pub base_work_factor: u64,
    /// Absolute ceiling on computational work difficulty. Must be >= base_work_factor.
    pub max_work_factor: u64,
    /// Sliding window duration for counting unpenalized event occurrences.
    pub window: Duration,
    /// Base duration step for exponential penalty cooldown (level 1 = step * 2).
    pub cooldown_step: Duration,
    /// Maximum hard delay clamp enforced across all actions.
    pub max_wait: Duration,
    /// Number of free messages allowed in the sliding window before PoW/delay escalates.
    pub message_free_burst: usize,
    /// Approximate device compute seconds notice advertised to clients.
    pub approximate_max_device_seconds: u64,
}

/// Errors occurring when validating an `AbuseConfig`.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ConfigError {
    #[error("base_work_factor must be positive, got {0}")]
    ZeroBaseWorkFactor(u64),
    #[error("max_work_factor ({max}) must be greater than or equal to base_work_factor ({base})")]
    MaxWorkFactorLessThanBase { base: u64, max: u64 },
    #[error("max_work_factor ({0}) exceeds maximum safe calculation bound ({1})")]
    MaxWorkFactorTooLarge(u64, u64),
    #[error("window duration must be positive")]
    ZeroWindow,
    #[error("window duration ({0:?}) exceeds maximum safe horizon (365 days)")]
    WindowTooLarge(Duration),
    #[error("cooldown_step duration must be positive")]
    ZeroCooldownStep,
    #[error(
        "cooldown_step duration ({0:?}) causes geometric decay horizon calculation to overflow"
    )]
    CooldownStepOverflow(Duration),
    #[error("max_wait duration must be positive")]
    ZeroMaxWait,
    #[error("max_wait duration ({0:?}) exceeds maximum safe horizon (365 days)")]
    MaxWaitTooLarge(Duration),
    #[error("approximate_max_device_seconds must be positive and <= 3600, got {0}")]
    InvalidDeviceSeconds(u64),
    #[error("message_free_burst must be between {min} and {max}, got {actual}")]
    InvalidFreeBurst {
        actual: usize,
        min: usize,
        max: usize,
    },
}

impl AbuseConfig {
    pub const DEFAULT_BASE_WORK_FACTOR: u64 = 100;
    pub const DEFAULT_MAX_WORK_FACTOR: u64 = 10_000;
    pub const DEFAULT_WINDOW_SECS: u64 = 60;
    pub const DEFAULT_COOLDOWN_STEP_SECS: u64 = 60;
    pub const DEFAULT_MAX_WAIT_SECS: u64 = 900;
    pub const DEFAULT_MESSAGE_FREE_BURST: usize = 6;
    pub const DEFAULT_APPROXIMATE_DEVICE_SECONDS: u64 = 8;

    /// Maximum safe max_work_factor to ensure `u64::MAX / work_factor` calculation
    /// never suffers from zero-division or numerical precision loss.
    pub const MAX_SAFE_WORK_FACTOR: u64 = u64::MAX / 2;

    /// Maximum duration allowed for individual interval configuration (365 days).
    pub const MAX_SAFE_INTERVAL: Duration = Duration::from_secs(365 * 24 * 60 * 60);

    pub fn builder() -> AbuseConfigBuilder {
        AbuseConfigBuilder::default()
    }

    /// Validates all configuration parameters and bounds.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.base_work_factor == 0 {
            return Err(ConfigError::ZeroBaseWorkFactor(0));
        }
        if self.max_work_factor < self.base_work_factor {
            return Err(ConfigError::MaxWorkFactorLessThanBase {
                base: self.base_work_factor,
                max: self.max_work_factor,
            });
        }
        if self.max_work_factor > Self::MAX_SAFE_WORK_FACTOR {
            return Err(ConfigError::MaxWorkFactorTooLarge(
                self.max_work_factor,
                Self::MAX_SAFE_WORK_FACTOR,
            ));
        }
        if self.window.is_zero() {
            return Err(ConfigError::ZeroWindow);
        }
        if self.window > Self::MAX_SAFE_INTERVAL {
            return Err(ConfigError::WindowTooLarge(self.window));
        }
        if self.cooldown_step.is_zero() {
            return Err(ConfigError::ZeroCooldownStep);
        }
        if self.cooldown_step > Self::MAX_SAFE_INTERVAL {
            return Err(ConfigError::CooldownStepOverflow(self.cooldown_step));
        }
        // Test that the geometric decay horizon does not overflow Duration::MAX
        let horizon = max_penalty_decay_horizon(self.cooldown_step);
        if horizon == Duration::MAX {
            return Err(ConfigError::CooldownStepOverflow(self.cooldown_step));
        }
        if self.max_wait.is_zero() {
            return Err(ConfigError::ZeroMaxWait);
        }
        if self.max_wait > Self::MAX_SAFE_INTERVAL {
            return Err(ConfigError::MaxWaitTooLarge(self.max_wait));
        }
        if self.approximate_max_device_seconds == 0 || self.approximate_max_device_seconds > 3600 {
            return Err(ConfigError::InvalidDeviceSeconds(
                self.approximate_max_device_seconds,
            ));
        }
        if self.message_free_burst == 0 || self.message_free_burst > 100_000 {
            return Err(ConfigError::InvalidFreeBurst {
                actual: self.message_free_burst,
                min: 1,
                max: 100_000,
            });
        }
        Ok(())
    }
}

/// Builder for `AbuseConfig` with secure defaults.
#[derive(Clone, Debug)]
pub struct AbuseConfigBuilder {
    base_work_factor: u64,
    max_work_factor: u64,
    window: Duration,
    cooldown_step: Duration,
    max_wait: Duration,
    message_free_burst: usize,
    approximate_max_device_seconds: u64,
}

impl Default for AbuseConfigBuilder {
    fn default() -> Self {
        Self {
            base_work_factor: AbuseConfig::DEFAULT_BASE_WORK_FACTOR,
            max_work_factor: AbuseConfig::DEFAULT_MAX_WORK_FACTOR,
            window: Duration::from_secs(AbuseConfig::DEFAULT_WINDOW_SECS),
            cooldown_step: Duration::from_secs(AbuseConfig::DEFAULT_COOLDOWN_STEP_SECS),
            max_wait: Duration::from_secs(AbuseConfig::DEFAULT_MAX_WAIT_SECS),
            message_free_burst: AbuseConfig::DEFAULT_MESSAGE_FREE_BURST,
            approximate_max_device_seconds: AbuseConfig::DEFAULT_APPROXIMATE_DEVICE_SECONDS,
        }
    }
}

impl AbuseConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn base_work_factor(mut self, factor: u64) -> Self {
        self.base_work_factor = factor;
        self
    }

    pub fn max_work_factor(mut self, factor: u64) -> Self {
        self.max_work_factor = factor;
        self
    }

    pub fn window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    pub fn cooldown_step(mut self, step: Duration) -> Self {
        self.cooldown_step = step;
        self
    }

    pub fn max_wait(mut self, max_wait: Duration) -> Self {
        self.max_wait = max_wait;
        self
    }

    pub fn message_free_burst(mut self, burst: usize) -> Self {
        self.message_free_burst = burst;
        self
    }

    pub fn approximate_max_device_seconds(mut self, seconds: u64) -> Self {
        self.approximate_max_device_seconds = seconds;
        self
    }

    pub fn build(self) -> Result<AbuseConfig, ConfigError> {
        let config = AbuseConfig {
            base_work_factor: self.base_work_factor,
            max_work_factor: self.max_work_factor,
            window: self.window,
            cooldown_step: self.cooldown_step,
            max_wait: self.max_wait,
            message_free_burst: self.message_free_burst,
            approximate_max_device_seconds: self.approximate_max_device_seconds,
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = AbuseConfig::builder().build().unwrap();
        assert_eq!(config.base_work_factor, 100);
        assert_eq!(config.max_work_factor, 10_000);
        assert_eq!(config.window, Duration::from_secs(60));
        assert_eq!(config.cooldown_step, Duration::from_secs(60));
        assert_eq!(config.max_wait, Duration::from_secs(900));
        assert_eq!(config.message_free_burst, 6);
        assert_eq!(config.approximate_max_device_seconds, 8);
    }

    #[test]
    fn rejects_zero_or_inverted_work_factors() {
        assert!(matches!(
            AbuseConfig::builder().base_work_factor(0).build(),
            Err(ConfigError::ZeroBaseWorkFactor(0))
        ));

        assert!(matches!(
            AbuseConfig::builder()
                .base_work_factor(500)
                .max_work_factor(100)
                .build(),
            Err(ConfigError::MaxWorkFactorLessThanBase {
                base: 500,
                max: 100
            })
        ));

        assert!(matches!(
            AbuseConfig::builder().max_work_factor(u64::MAX).build(),
            Err(ConfigError::MaxWorkFactorTooLarge(..))
        ));
    }

    #[test]
    fn rejects_zero_or_excessive_intervals() {
        assert!(matches!(
            AbuseConfig::builder().window(Duration::ZERO).build(),
            Err(ConfigError::ZeroWindow)
        ));

        assert!(matches!(
            AbuseConfig::builder().cooldown_step(Duration::ZERO).build(),
            Err(ConfigError::ZeroCooldownStep)
        ));

        assert!(matches!(
            AbuseConfig::builder().max_wait(Duration::ZERO).build(),
            Err(ConfigError::ZeroMaxWait)
        ));

        assert!(matches!(
            AbuseConfig::builder()
                .window(Duration::from_secs(366 * 24 * 60 * 60))
                .build(),
            Err(ConfigError::WindowTooLarge(_))
        ));
    }

    #[test]
    fn rejects_invalid_burst_and_device_seconds() {
        assert!(matches!(
            AbuseConfig::builder().message_free_burst(0).build(),
            Err(ConfigError::InvalidFreeBurst { .. })
        ));

        assert!(matches!(
            AbuseConfig::builder()
                .approximate_max_device_seconds(0)
                .build(),
            Err(ConfigError::InvalidDeviceSeconds(0))
        ));

        assert!(matches!(
            AbuseConfig::builder()
                .approximate_max_device_seconds(3601)
                .build(),
            Err(ConfigError::InvalidDeviceSeconds(3601))
        ));
    }
}
