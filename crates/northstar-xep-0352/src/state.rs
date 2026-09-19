#![forbid(unsafe_code)]

//! Deterministic state management for XEP-0352 Client State Indication.

use crate::wire::CsiIndication;
use std::fmt;

/// The client CSI state.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CsiState {
    /// Active state: the client is actively engaged and all stanzas should be delivered immediately.
    #[default]
    Active,
    /// Inactive state: the client is idle/backgrounded; non-critical traffic may be deferred/coalesced.
    Inactive,
}

impl CsiState {
    /// Returns the string representation of the state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
        }
    }

    /// Whether this state is active.
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether this state is inactive.
    pub const fn is_inactive(self) -> bool {
        matches!(self, Self::Inactive)
    }

    /// Converts a [`CsiIndication`] to its target [`CsiState`].
    pub const fn from_indication(indication: CsiIndication) -> Self {
        match indication {
            CsiIndication::Active => Self::Active,
            CsiIndication::Inactive => Self::Inactive,
        }
    }
}

impl fmt::Display for CsiState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of applying a state transition to a CSI state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TransitionOutcome {
    /// The state changed from one value to another.
    Changed { from: CsiState, to: CsiState },
    /// The indication was a duplicate / idempotent request and state was unchanged.
    Unchanged { state: CsiState },
}

impl TransitionOutcome {
    /// Returns `true` if the state was changed.
    pub const fn is_changed(self) -> bool {
        matches!(self, Self::Changed { .. })
    }

    /// Returns `true` if the transition is an activation (Inactive -> Active).
    pub const fn is_activation(self) -> bool {
        matches!(
            self,
            Self::Changed {
                from: CsiState::Inactive,
                to: CsiState::Active
            }
        )
    }

    /// Returns `true` if the transition is an inactivation (Active -> Inactive).
    pub const fn is_inactivation(self) -> bool {
        matches!(
            self,
            Self::Changed {
                from: CsiState::Active,
                to: CsiState::Inactive
            }
        )
    }

    /// Returns `true` if this transition was a duplicate (no state change).
    pub const fn is_duplicate(self) -> bool {
        matches!(self, Self::Unchanged { .. })
    }

    /// Returns the resulting current state after this transition.
    pub const fn current_state(self) -> CsiState {
        match self {
            Self::Changed { to, .. } => to,
            Self::Unchanged { state } => state,
        }
    }
}

/// Deterministic, capability-free state tracker for a CSI session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CsiStateMachine {
    current_state: CsiState,
    transition_count: u64,
}

impl Default for CsiStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl CsiStateMachine {
    /// Creates a new CSI state machine initialized to the default `Active` state.
    pub const fn new() -> Self {
        Self {
            current_state: CsiState::Active,
            transition_count: 0,
        }
    }

    /// Creates a state machine initialized to a specific state (e.g., set via SASL2 Bind).
    pub const fn with_initial_state(initial: CsiState) -> Self {
        Self {
            current_state: initial,
            transition_count: 0,
        }
    }

    /// Returns the current CSI state.
    pub const fn state(&self) -> CsiState {
        self.current_state
    }

    /// Returns `true` if the stream is currently active.
    pub const fn is_active(&self) -> bool {
        self.current_state.is_active()
    }

    /// Returns `true` if the stream is currently inactive.
    pub const fn is_inactive(&self) -> bool {
        self.current_state.is_inactive()
    }

    /// Returns the total number of actual state changes applied.
    pub const fn transition_count(&self) -> u64 {
        self.transition_count
    }

    /// Apply a wire indication to transition the state.
    pub fn apply_indication(&mut self, indication: CsiIndication) -> TransitionOutcome {
        let target = CsiState::from_indication(indication);
        let from = self.current_state;
        if from == target {
            TransitionOutcome::Unchanged { state: from }
        } else {
            self.current_state = target;
            self.transition_count = self.transition_count.saturating_add(1);
            TransitionOutcome::Changed { from, to: target }
        }
    }

    /// Explicitly transition to active state.
    pub fn set_active(&mut self) -> TransitionOutcome {
        self.apply_indication(CsiIndication::Active)
    }

    /// Explicitly transition to inactive state.
    pub fn set_inactive(&mut self) -> TransitionOutcome {
        self.apply_indication(CsiIndication::Inactive)
    }

    /// Resets the state machine back to default active state with zero transitions.
    pub fn reset(&mut self) {
        self.current_state = CsiState::Active;
        self.transition_count = 0;
    }
}
