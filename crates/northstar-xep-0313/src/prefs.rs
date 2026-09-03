//! Archive preference models, normalization, and capability-free visibility decisions.

use crate::constants::MAX_PREFS_JIDS;
use crate::error::MamError;
use northstar_xmpp_types::{canonicalize, CanonicalJid};
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

/// Default archiving policy for messages when no explicit JID rule matches.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DefaultPolicy {
    /// Archive all messages by default.
    #[default]
    Always,
    /// Never archive messages by default.
    Never,
    /// Only archive messages for contacts present in the user's roster.
    Roster,
}

impl DefaultPolicy {
    /// Return the wire representation string for this policy.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Never => "never",
            Self::Roster => "roster",
        }
    }
}

impl FromStr for DefaultPolicy {
    type Err = MamError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            "roster" => Ok(Self::Roster),
            _ => Err(MamError::BadRequest("invalid default preference policy")),
        }
    }
}

impl fmt::Display for DefaultPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A normalized, validated set of user archiving preferences.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MamPreferences {
    /// Default policy when no explicit JID rule matches.
    pub default_policy: DefaultPolicy,
    /// List of canonical JIDs whose messages are always archived.
    pub always: Vec<String>,
    /// List of canonical JIDs whose messages are never archived.
    pub never: Vec<String>,
}

impl Default for MamPreferences {
    fn default() -> Self {
        Self {
            default_policy: DefaultPolicy::Always,
            always: Vec::new(),
            never: Vec::new(),
        }
    }
}

impl MamPreferences {
    /// Construct and validate a [`MamPreferences`] object with canonicalization and disjointness checks.
    pub fn new(
        default_policy: DefaultPolicy,
        always: Vec<String>,
        never: Vec<String>,
    ) -> Result<Self, MamError> {
        let mut canonical_always = Vec::with_capacity(always.len());
        let mut canonical_never = Vec::with_capacity(never.len());
        let mut seen = HashSet::new();

        for jid in always {
            let canon = canonicalize(&jid)
                .map_err(|_| MamError::JidMalformed("malformed JID in always list"))?;
            if !seen.insert(canon.clone()) {
                return Err(MamError::BadRequest("duplicate JID in preference lists"));
            }
            canonical_always.push(canon);
        }

        for jid in never {
            let canon = canonicalize(&jid)
                .map_err(|_| MamError::JidMalformed("malformed JID in never list"))?;
            if !seen.insert(canon.clone()) {
                return Err(MamError::BadRequest("duplicate JID in preference lists"));
            }
            canonical_never.push(canon);
        }

        if seen.len() > MAX_PREFS_JIDS {
            return Err(MamError::ResourceConstraint(
                "too many JIDs in preference lists",
            ));
        }

        Ok(Self {
            default_policy,
            always: canonical_always,
            never: canonical_never,
        })
    }
}

/// Pure, capability-free preference decision evaluating whether a message with a peer should be archived.
///
/// Priority rules:
/// 1. Exact full JID match in `always` -> `true`
/// 2. Exact full JID match in `never` -> `false`
/// 3. Bare JID match in `always` (for bare rules) -> `true`
/// 4. Bare JID match in `never` (for bare rules) -> `false`
/// 5. Default policy:
///    - `Always` -> `true`
///    - `Never` -> `false`
///    - `Roster` -> `is_in_roster`
pub fn evaluate_preference(
    prefs: &MamPreferences,
    peer_jid: &str,
    is_in_roster: bool,
) -> Result<bool, MamError> {
    let canonical_peer =
        CanonicalJid::parse(peer_jid).map_err(|_| MamError::JidMalformed("malformed peer JID"))?;
    Ok(evaluate_preference_with_canonical(
        prefs,
        &canonical_peer,
        is_in_roster,
    ))
}

/// Pure preference evaluation when [`CanonicalJid`] is already available.
pub fn evaluate_preference_with_canonical(
    prefs: &MamPreferences,
    peer: &CanonicalJid,
    is_in_roster: bool,
) -> bool {
    let full = peer.to_string();
    let bare = peer.bare();

    // 1. Exact full JID rule
    if prefs.always.iter().any(|j| j == &full) {
        return true;
    }
    if prefs.never.iter().any(|j| j == &full) {
        return false;
    }

    // 2. Bare JID rule (for rules that contain no resource)
    if prefs.always.iter().any(|j| j == &bare) {
        return true;
    }
    if prefs.never.iter().any(|j| j == &bare) {
        return false;
    }

    // 3. Default policy
    match prefs.default_policy {
        DefaultPolicy::Always => true,
        DefaultPolicy::Never => false,
        DefaultPolicy::Roster => is_in_roster,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferences_evaluation_priority() {
        let prefs = MamPreferences::new(
            DefaultPolicy::Roster,
            vec![
                "alice@example.test/Phone".to_owned(),
                "bob@example.test".to_owned(),
            ],
            vec![
                "alice@example.test".to_owned(),
                "charlie@example.test".to_owned(),
            ],
        )
        .unwrap();

        // Exact full JID match in always overrides bare JID in never
        assert!(evaluate_preference(&prefs, "alice@example.test/Phone", false).unwrap());

        // Other resource of Alice matches bare JID in never
        assert!(!evaluate_preference(&prefs, "alice@example.test/Desktop", true).unwrap());

        // Bob bare match in always
        assert!(evaluate_preference(&prefs, "bob@example.test/Mobile", false).unwrap());

        // Charlie bare match in never
        assert!(!evaluate_preference(&prefs, "charlie@example.test/Work", true).unwrap());

        // Default roster policy for unmatched peer
        assert!(evaluate_preference(&prefs, "dan@example.test/Home", true).unwrap());
        assert!(!evaluate_preference(&prefs, "dan@example.test/Home", false).unwrap());
    }

    #[test]
    fn rejects_duplicate_or_invalid_jids() {
        assert!(MamPreferences::new(
            DefaultPolicy::Always,
            vec!["a@example.test".to_owned()],
            vec!["A@example.test".to_owned()],
        )
        .is_err());

        assert!(MamPreferences::new(
            DefaultPolicy::Always,
            vec!["invalid jid".to_owned()],
            vec![],
        )
        .is_err());
    }
}
