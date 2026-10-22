#![forbid(unsafe_code)]

//! Enable and resume negotiation policies, eligibility evaluation, and network binding checks.

use std::net::IpAddr;

use crate::wire::EnableElement;

/// Server configuration parameters for XEP-0198 negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EnableConfig {
    /// Maximum allowed resumption timeout in seconds.
    pub server_max_timeout_seconds: u32,
    /// Whether stream resumption is globally allowed by server policy.
    pub allow_resumption: bool,
    /// Whether strict device continuity (XEP-0388 / stable user-agent ID) is required for resumption.
    pub require_same_device: bool,
}

impl Default for EnableConfig {
    fn default() -> Self {
        Self {
            server_max_timeout_seconds: 300,
            allow_resumption: true,
            require_same_device: false,
        }
    }
}

/// The result of an `<enable/>` negotiation decision.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NegotiatedEnable {
    /// Whether resumption was granted for this stream.
    pub resume: bool,
    /// The negotiated resumption timeout in seconds.
    pub timeout_seconds: u32,
    /// Optional redirection/reconnection location URI provided by the server.
    pub location: Option<String>,
}

/// Evaluates whether resumption can be granted based on the client request,
/// server strict same-device policy, and whether a stable device identifier exists.
///
/// XEP-0388 supplies a stable user-agent UUID, while legacy SASL has no
/// standard way to prove device continuity. Under the strict policy,
/// negotiate ordinary stream management for an unidentifiable legacy client
/// instead of issuing a bearer token that claim authority must later reject.
pub const fn resumability_allowed(
    requested_resume: bool,
    require_same_device: bool,
    has_device_id: bool,
) -> bool {
    requested_resume && (!require_same_device || has_device_id)
}

/// Evaluates pure enable negotiation between client request and server config.
pub fn negotiate_enable(
    client_request: &EnableElement,
    config: &EnableConfig,
    has_device_id: bool,
) -> NegotiatedEnable {
    let resume = config.allow_resumption
        && resumability_allowed(
            client_request.resume,
            config.require_same_device,
            has_device_id,
        );

    let server_max = config.server_max_timeout_seconds.max(1);
    let timeout_seconds = if resume {
        client_request
            .max
            .unwrap_or(server_max)
            .min(server_max)
            .max(1)
    } else {
        server_max
    };

    NegotiatedEnable {
        resume,
        timeout_seconds,
        location: None,
    }
}

/// Determines whether a resumed session is eligible for deferred offline message replay.
///
/// A resumed stream keeps its RFC 6121 availability and priority.
/// XEP-0160 must not drain the account queue into an unavailable or
/// negative-priority resource merely because XEP-0198 resumed it.
pub const fn resumed_offline_replay_eligible(available: bool, priority: i16) -> bool {
    available && priority >= 0
}

/// IP address binding policy for session resumption verification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpBindingPolicy {
    /// No IP address restriction on resumption.
    #[default]
    None,
    /// Claimant IP must match the original connection IP exactly.
    Exact,
    /// Claimant IP must be in the same /24 IPv4 subnet or /64 IPv6 prefix.
    Subnet,
}

impl IpBindingPolicy {
    /// Parses an IP binding policy string ("none", "exact", "subnet").
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "exact" => Some(Self::Exact),
            "subnet" => Some(Self::Subnet),
            _ => None,
        }
    }

    /// Returns the canonical configuration string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Exact => "exact",
            Self::Subnet => "subnet",
        }
    }
}

/// Pure evaluation of whether a claimant IP matches the expected session IP under policy.
pub fn peer_ip_matches(policy: IpBindingPolicy, expected: IpAddr, actual: IpAddr) -> bool {
    match policy {
        IpBindingPolicy::None => true,
        IpBindingPolicy::Exact => expected == actual,
        IpBindingPolicy::Subnet => match (expected, actual) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                (u32::from(a) & 0xffff_ff00) == (u32::from(b) & 0xffff_ff00)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let a_bytes = a.octets();
                let b_bytes = b.octets();
                a_bytes[0..8] == b_bytes[0..8]
            }
            _ => false,
        },
    }
}

/// Evaluates whether stored device identifier matches claimant device identifier under policy.
pub fn same_device_matches(
    stored_device: Option<&str>,
    claimant_device: Option<&str>,
    require_same_device: bool,
) -> bool {
    if !require_same_device {
        return true;
    }
    match (stored_device, claimant_device) {
        (Some(stored), Some(claimant)) => stored == claimant,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resumability_allowed_decision_table() {
        // (requested, require_same_device, has_device)
        assert!(resumability_allowed(true, false, false));
        assert!(resumability_allowed(true, false, true));
        assert!(resumability_allowed(true, true, true));
        assert!(!resumability_allowed(true, true, false));
        assert!(!resumability_allowed(false, false, true));
        assert!(!resumability_allowed(false, true, true));
    }

    #[test]
    fn negotiate_enable_scenarios() {
        let config = EnableConfig {
            server_max_timeout_seconds: 300,
            allow_resumption: true,
            require_same_device: false,
        };

        // Client requests resume with max 60
        let req = EnableElement {
            resume: true,
            max: Some(60),
            location: None,
        };
        let outcome = negotiate_enable(&req, &config, false);
        assert!(outcome.resume);
        assert_eq!(outcome.timeout_seconds, 60);

        // Client requests max 600, capped at server max 300
        let req = EnableElement {
            resume: true,
            max: Some(600),
            location: None,
        };
        let outcome = negotiate_enable(&req, &config, false);
        assert!(outcome.resume);
        assert_eq!(outcome.timeout_seconds, 300);

        // Non-resumable enable
        let req = EnableElement {
            resume: false,
            max: None,
            location: None,
        };
        let outcome = negotiate_enable(&req, &config, false);
        assert!(!outcome.resume);
        assert_eq!(outcome.timeout_seconds, 300);
    }

    #[test]
    fn offline_replay_eligibility() {
        assert!(resumed_offline_replay_eligible(true, 0));
        assert!(resumed_offline_replay_eligible(true, 10));
        assert!(!resumed_offline_replay_eligible(true, -1));
        assert!(!resumed_offline_replay_eligible(false, 10));
        assert!(!resumed_offline_replay_eligible(false, -1));
    }

    #[test]
    fn ip_binding_matching() {
        let ip1: IpAddr = "192.168.1.50".parse().unwrap();
        let ip1_same_subnet: IpAddr = "192.168.1.99".parse().unwrap();
        let ip1_diff_subnet: IpAddr = "192.168.2.50".parse().unwrap();

        assert!(peer_ip_matches(IpBindingPolicy::None, ip1, ip1_diff_subnet));
        assert!(peer_ip_matches(IpBindingPolicy::Exact, ip1, ip1));
        assert!(!peer_ip_matches(
            IpBindingPolicy::Exact,
            ip1,
            ip1_same_subnet
        ));
        assert!(peer_ip_matches(
            IpBindingPolicy::Subnet,
            ip1,
            ip1_same_subnet
        ));
        assert!(!peer_ip_matches(
            IpBindingPolicy::Subnet,
            ip1,
            ip1_diff_subnet
        ));

        let v6_1: IpAddr = "2001:db8:abcd:0012::1".parse().unwrap();
        let v6_same_prefix: IpAddr = "2001:db8:abcd:0012::beef".parse().unwrap();
        let v6_diff_prefix: IpAddr = "2001:db8:abcd:0034::1".parse().unwrap();

        assert!(peer_ip_matches(IpBindingPolicy::Exact, v6_1, v6_1));
        assert!(peer_ip_matches(
            IpBindingPolicy::Subnet,
            v6_1,
            v6_same_prefix
        ));
        assert!(!peer_ip_matches(
            IpBindingPolicy::Subnet,
            v6_1,
            v6_diff_prefix
        ));
    }

    #[test]
    fn same_device_matching() {
        assert!(same_device_matches(Some("dev-1"), Some("dev-1"), true));
        assert!(!same_device_matches(Some("dev-1"), Some("dev-2"), true));
        assert!(!same_device_matches(Some("dev-1"), None, true));
        assert!(!same_device_matches(None, Some("dev-1"), true));
        assert!(same_device_matches(Some("dev-1"), Some("dev-2"), false));
    }
}
