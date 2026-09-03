//! Capability-injected roster application boundary, typed commands,
//! validation rules, and in-memory push synchronization.

#![forbid(unsafe_code)]

pub use northstar_roster_core::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use uuid::Uuid;

/// Upper limit on buffered committed pushes during a single initial roster sync.
pub const MAX_BUFFERED_ROSTER_CHANGES: usize = 512;

/// Typed command for fetching a roster snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterGetCommand {
    pub owner_id: Uuid,
    pub expected_auth_generation: i64,
    pub requested_version: Option<i64>,
    pub annotations_requested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterGetValidationError {
    InvalidVersion,
}

pub fn validate_roster_get_command(cmd: &RosterGetCommand) -> Result<(), RosterGetValidationError> {
    if let Some(version) = cmd.requested_version {
        if version < 0 {
            return Err(RosterGetValidationError::InvalidVersion);
        }
    }
    Ok(())
}

/// Typed command for adding or updating a roster item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterUpsertCommand {
    pub owner_id: Uuid,
    pub expected_auth_generation: i64,
    pub jid: String,
    pub name: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterUpsertValidationError {
    EmptyJid,
    InvalidJid,
    NameTooLong,
    TooManyGroups,
    GroupTooLong,
}

pub fn validate_roster_upsert_command(
    cmd: &RosterUpsertCommand,
) -> Result<(), RosterUpsertValidationError> {
    if cmd.jid.trim().is_empty() {
        return Err(RosterUpsertValidationError::EmptyJid);
    }
    if northstar_xmpp_types::CanonicalJid::parse_bare(&cmd.jid).is_err() {
        return Err(RosterUpsertValidationError::InvalidJid);
    }
    if let Some(name) = &cmd.name {
        if name.len() > 1024 {
            return Err(RosterUpsertValidationError::NameTooLong);
        }
    }
    if cmd.groups.len() > 128 {
        return Err(RosterUpsertValidationError::TooManyGroups);
    }
    for group in &cmd.groups {
        if group.len() > 1024 {
            return Err(RosterUpsertValidationError::GroupTooLong);
        }
    }
    Ok(())
}

/// Outbox policy for remote federation notifications upon roster removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteRemovalPolicy {
    pub ttl_seconds: u64,
    pub max_rows: i64,
    pub max_bytes: i64,
    pub max_per_domain: i64,
}

/// Delivery route target for roster item removal stanzas.
#[derive(Clone, Copy, Debug)]
pub enum RosterRemovalRoute<'a> {
    Local {
        owner_jid: &'a str,
        contact_username: Option<&'a str>,
    },
    Remote {
        target_domain: &'a str,
        unsubscribe_stanza: &'a str,
        unsubscribed_stanza: &'a str,
        bounce_to: Option<&'a str>,
        policy: RemoteRemovalPolicy,
    },
}

/// Typed command for removing a contact from a user's roster.
#[derive(Clone, Copy, Debug)]
pub struct RosterRemoveCommand<'a> {
    pub owner_id: Uuid,
    pub expected_auth_generation: i64,
    pub jid: &'a str,
    pub route: RosterRemovalRoute<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosterRemoveValidationError {
    EmptyJid,
    InvalidJid,
}

pub fn validate_roster_remove_command(
    cmd: &RosterRemoveCommand<'_>,
) -> Result<(), RosterRemoveValidationError> {
    if cmd.jid.trim().is_empty() {
        return Err(RosterRemoveValidationError::EmptyJid);
    }
    if northstar_xmpp_types::CanonicalJid::parse_bare(cmd.jid).is_err() {
        return Err(RosterRemoveValidationError::InvalidJid);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RosterSyncPermit {
    pub generation: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum BeginRosterSyncError {
    AlreadySynchronizing,
    Failed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RosterPushDisposition {
    NotInterested,
    Deliver(String),
    Buffered,
    Overflow,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RosterFlushBatch {
    Batch(Vec<(i64, String)>),
    Complete,
    Superseded,
    Failed,
}

#[derive(Debug)]
pub enum RosterSyncState {
    Idle,
    Synchronizing {
        generation: u64,
        buffered: BTreeMap<i64, String>,
    },
    Flushing {
        generation: u64,
        buffered: BTreeMap<i64, String>,
    },
    Failed,
}

/// In-memory ordering fence shared by `ProtocolSession` and its published
/// `OnlineSession`. Database snapshots remain short; only already-rendered
/// committed pushes are buffered while the IQ result enters the transport.
#[derive(Debug)]
pub struct RosterSyncGate {
    generation: AtomicU64,
    state: Mutex<RosterSyncState>,
}

impl Default for RosterSyncGate {
    fn default() -> Self {
        Self {
            generation: AtomicU64::new(0),
            state: Mutex::new(RosterSyncState::Idle),
        }
    }
}

impl RosterSyncGate {
    pub fn begin(
        &self,
        roster_requested: &AtomicBool,
        mix_annotations: &AtomicBool,
        annotations_requested: bool,
    ) -> std::result::Result<RosterSyncPermit, BeginRosterSyncError> {
        self.begin_with_hook(
            roster_requested,
            mix_annotations,
            annotations_requested,
            || {},
        )
    }

    pub fn begin_with_hook<F>(
        &self,
        roster_requested: &AtomicBool,
        mix_annotations: &AtomicBool,
        annotations_requested: bool,
        after_gate_entry: F,
    ) -> std::result::Result<RosterSyncPermit, BeginRosterSyncError>
    where
        F: FnOnce(),
    {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *state {
            RosterSyncState::Idle => {}
            RosterSyncState::Failed => return Err(BeginRosterSyncError::Failed),
            RosterSyncState::Synchronizing { .. } | RosterSyncState::Flushing { .. } => {
                return Err(BeginRosterSyncError::AlreadySynchronizing);
            }
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        *state = RosterSyncState::Synchronizing {
            generation,
            buffered: BTreeMap::new(),
        };
        after_gate_entry();
        mix_annotations.store(annotations_requested, Ordering::Release);
        roster_requested.store(true, Ordering::Release);
        Ok(RosterSyncPermit { generation })
    }

    pub fn route(
        &self,
        roster_requested: &AtomicBool,
        mix_annotations: &AtomicBool,
        version: i64,
        plain_stanza: String,
        annotated_stanza: Option<String>,
    ) -> RosterPushDisposition {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !roster_requested.load(Ordering::Acquire) {
            return RosterPushDisposition::NotInterested;
        }
        let stanza = if mix_annotations.load(Ordering::Acquire) {
            annotated_stanza.unwrap_or(plain_stanza)
        } else {
            plain_stanza
        };
        match &mut *state {
            RosterSyncState::Idle => RosterPushDisposition::Deliver(stanza),
            RosterSyncState::Synchronizing { buffered, .. }
            | RosterSyncState::Flushing { buffered, .. } => {
                if buffered.contains_key(&version) {
                    return RosterPushDisposition::Buffered;
                }
                if buffered.len() >= MAX_BUFFERED_ROSTER_CHANGES {
                    *state = RosterSyncState::Failed;
                    return RosterPushDisposition::Overflow;
                }
                buffered.insert(version, stanza);
                RosterPushDisposition::Buffered
            }
            RosterSyncState::Failed => RosterPushDisposition::Overflow,
        }
    }

    pub fn start_flush(
        &self,
        permit: RosterSyncPermit,
        snapshot_version: i64,
    ) -> RosterFlushBatch {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prior = std::mem::replace(&mut *state, RosterSyncState::Failed);
        let (generation, mut buffered) = match prior {
            RosterSyncState::Synchronizing {
                generation,
                buffered,
            } if generation == permit.generation => (generation, buffered),
            RosterSyncState::Failed => return RosterFlushBatch::Failed,
            prior => {
                *state = prior;
                return RosterFlushBatch::Superseded;
            }
        };
        buffered.retain(|version, _| *version > snapshot_version);
        *state = RosterSyncState::Flushing {
            generation,
            buffered,
        };
        self.next_batch_locked(&mut state, permit)
    }

    pub fn next_flush_batch(&self, permit: RosterSyncPermit) -> RosterFlushBatch {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.next_batch_locked(&mut state, permit)
    }

    fn next_batch_locked(
        &self,
        state: &mut RosterSyncState,
        permit: RosterSyncPermit,
    ) -> RosterFlushBatch {
        match state {
            RosterSyncState::Flushing {
                generation,
                buffered,
            } if *generation == permit.generation => {
                if buffered.is_empty() {
                    *state = RosterSyncState::Idle;
                    RosterFlushBatch::Complete
                } else {
                    RosterFlushBatch::Batch(std::mem::take(buffered).into_iter().collect())
                }
            }
            RosterSyncState::Failed => RosterFlushBatch::Failed,
            _ => RosterFlushBatch::Superseded,
        }
    }

    pub fn fail(&self, permit: RosterSyncPermit) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let matches = match &*state {
            RosterSyncState::Synchronizing { generation, .. }
            | RosterSyncState::Flushing { generation, .. } => *generation == permit.generation,
            RosterSyncState::Idle | RosterSyncState::Failed => false,
        };
        if matches {
            *state = RosterSyncState::Failed;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_validation() {
        let valid_get = RosterGetCommand {
            owner_id: Uuid::new_v4(),
            expected_auth_generation: 1,
            requested_version: Some(5),
            annotations_requested: false,
        };
        assert!(validate_roster_get_command(&valid_get).is_ok());

        let invalid_get = RosterGetCommand {
            owner_id: Uuid::new_v4(),
            expected_auth_generation: 1,
            requested_version: Some(-1),
            annotations_requested: false,
        };
        assert_eq!(
            validate_roster_get_command(&invalid_get),
            Err(RosterGetValidationError::InvalidVersion)
        );

        let valid_upsert = RosterUpsertCommand {
            owner_id: Uuid::new_v4(),
            expected_auth_generation: 1,
            jid: "contact@example.test".to_string(),
            name: Some("Friend".to_string()),
            groups: vec!["Friends".to_string()],
        };
        assert!(validate_roster_upsert_command(&valid_upsert).is_ok());

        let mut invalid_upsert = valid_upsert.clone();
        invalid_upsert.jid = "not a jid".to_string();
        assert_eq!(
            validate_roster_upsert_command(&invalid_upsert),
            Err(RosterUpsertValidationError::InvalidJid)
        );

        let valid_remove = RosterRemoveCommand {
            owner_id: Uuid::new_v4(),
            expected_auth_generation: 1,
            jid: "contact@example.test",
            route: RosterRemovalRoute::Local {
                owner_jid: "user@example.test",
                contact_username: Some("contact"),
            },
        };
        assert!(validate_roster_remove_command(&valid_remove).is_ok());
    }

    #[test]
    fn synchronization_buffers_orders_and_atomically_exits() {
        let gate = RosterSyncGate::default();
        let requested = AtomicBool::new(false);
        let annotations = AtomicBool::new(false);
        let permit = gate.begin(&requested, &annotations, true).unwrap();
        assert!(requested.load(Ordering::Acquire));
        assert!(annotations.load(Ordering::Acquire));
        assert_eq!(
            gate.route(&requested, &annotations, 13, "v13".to_owned(), None),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.route(&requested, &annotations, 12, "v12".to_owned(), None),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.start_flush(permit, 11),
            RosterFlushBatch::Batch(vec![(12, "v12".to_owned()), (13, "v13".to_owned())])
        );
        assert_eq!(
            gate.route(&requested, &annotations, 14, "v14".to_owned(), None),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.next_flush_batch(permit),
            RosterFlushBatch::Batch(vec![(14, "v14".to_owned())])
        );
        assert_eq!(gate.next_flush_batch(permit), RosterFlushBatch::Complete);
        assert_eq!(
            gate.route(&requested, &annotations, 15, "v15".to_owned(), None),
            RosterPushDisposition::Deliver("v15".to_owned())
        );
    }
}
