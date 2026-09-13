//! Process-wide fail-closed authority for upload object I/O.
//!
//! PostgreSQL is authoritative for both the physical namespace generation and
//! the trigger-maintained capacity ledger.  A worker-local health flag is not
//! sufficient: HTTP handlers, startup reconciliation and RAII cleanup can all
//! touch the same object store.  This gate gives every path one generation-
//! bound decision and wakes in-flight asynchronous operations when that
//! decision is invalidated.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, RwLock},
};

use tokio::sync::watch;

pub(crate) use northstar_upload_core::{
    UploadAuthorityGeneration, UploadIoClass, UploadSafetyState,
};

#[derive(Clone, Debug)]
struct UploadSafetySnapshot {
    state: UploadSafetyState,
    generation: Option<UploadAuthorityGeneration>,
    revision: u64,
    reason: Arc<str>,
}

impl UploadSafetySnapshot {
    fn permits(&self, class: UploadIoClass) -> bool {
        match self.state {
            UploadSafetyState::Disabled => false,
            UploadSafetyState::Healthy => true,
            UploadSafetyState::RecoveryDraining => !matches!(class, UploadIoClass::NewWrite),
            // A capacity proof failure does not make a committed locator
            // ambiguous, so existing immutable downloads may finish.  Every
            // mutation remains frozen until the exact authority is re-proved.
            UploadSafetyState::CapacityAuthorityUnsafe | UploadSafetyState::LedgerMismatch => {
                matches!(class, UploadIoClass::Read)
            }
            UploadSafetyState::Unproven | UploadSafetyState::NamespaceUnsafe => false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("upload object I/O is unavailable: {reason}")]
pub(crate) struct UploadSafetyError {
    reason: Arc<str>,
}

#[derive(Clone)]
pub(crate) struct UploadSafetyGate {
    snapshot: Arc<RwLock<UploadSafetySnapshot>>,
    changes: watch::Sender<u64>,
}

impl UploadSafetyGate {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_initial_state(
            UploadSafetyState::Unproven,
            "upload authority has not been proved",
        )
    }

    pub(crate) fn disabled() -> Arc<Self> {
        Self::with_initial_state(UploadSafetyState::Disabled, "upload capability is disabled")
    }

    fn with_initial_state(state: UploadSafetyState, reason: &'static str) -> Arc<Self> {
        let (changes, _) = watch::channel(0_u64);
        Arc::new(Self {
            snapshot: Arc::new(RwLock::new(UploadSafetySnapshot {
                state,
                generation: None,
                revision: 0,
                reason: Arc::from(reason),
            })),
            changes,
        })
    }

    pub(crate) fn state(&self) -> UploadSafetyState {
        self.snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .state
    }

    pub(crate) fn metric_code(&self) -> u64 {
        match self.state() {
            UploadSafetyState::Disabled => 6,
            UploadSafetyState::Healthy => 0,
            UploadSafetyState::RecoveryDraining => 1,
            UploadSafetyState::Unproven => 2,
            UploadSafetyState::NamespaceUnsafe => 3,
            UploadSafetyState::CapacityAuthorityUnsafe => 4,
            UploadSafetyState::LedgerMismatch => 5,
        }
    }

    pub(crate) fn generation(&self) -> Option<UploadAuthorityGeneration> {
        self.snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generation
    }

    pub(crate) fn establish(&self, generation: UploadAuthorityGeneration, recovery_draining: bool) {
        self.transition(
            if recovery_draining {
                UploadSafetyState::RecoveryDraining
            } else {
                UploadSafetyState::Healthy
            },
            Some(generation),
            if recovery_draining {
                "upload recovery capacity is draining"
            } else {
                "upload authority is healthy"
            },
        );
    }

    pub(crate) fn mark_namespace_unsafe(&self, reason: impl Into<Arc<str>>) {
        self.transition(UploadSafetyState::NamespaceUnsafe, None, reason);
    }

    pub(crate) fn mark_capacity_authority_unsafe(&self, reason: impl Into<Arc<str>>) {
        let generation = self.generation();
        self.transition(
            UploadSafetyState::CapacityAuthorityUnsafe,
            generation,
            reason,
        );
    }

    pub(crate) fn mark_ledger_mismatch(&self, reason: impl Into<Arc<str>>) {
        let generation = self.generation();
        self.transition(UploadSafetyState::LedgerMismatch, generation, reason);
    }

    fn transition(
        &self,
        state: UploadSafetyState,
        generation: Option<UploadAuthorityGeneration>,
        reason: impl Into<Arc<str>>,
    ) {
        let reason = reason.into();
        let revision = {
            let mut current = self
                .snapshot
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if current.state == UploadSafetyState::Disabled && state != UploadSafetyState::Disabled
            {
                return;
            }
            if current.state == UploadSafetyState::NamespaceUnsafe
                && state != UploadSafetyState::NamespaceUnsafe
            {
                // A namespace mismatch is process-terminal.  Only a restart
                // after an offline migration may establish a new generation.
                return;
            }
            if current.state == state
                && current.generation == generation
                && current.reason.as_ref() == reason.as_ref()
            {
                return;
            }
            current.state = state;
            current.generation = generation;
            current.revision = current.revision.saturating_add(1);
            current.reason = reason;
            current.revision
        };
        self.changes.send_replace(revision);
    }

    pub(crate) fn permit(
        self: &Arc<Self>,
        class: UploadIoClass,
    ) -> Result<UploadIoPermit, UploadSafetyError> {
        let snapshot = self
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if !snapshot.permits(class) {
            return Err(UploadSafetyError {
                reason: snapshot.reason,
            });
        }
        let generation = snapshot.generation.ok_or_else(|| UploadSafetyError {
            reason: Arc::from("upload authority generation is absent"),
        })?;
        Ok(UploadIoPermit {
            gate: Arc::clone(self),
            class,
            generation,
            revision: snapshot.revision,
            changes: self.changes.subscribe(),
        })
    }

    pub(crate) fn permits_generation(
        &self,
        class: UploadIoClass,
        generation: UploadAuthorityGeneration,
    ) -> bool {
        let snapshot = self
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshot.permits(class) && snapshot.generation == Some(generation)
    }

    pub(crate) fn invalidation_future(
        self: &Arc<Self>,
        class: UploadIoClass,
        generation: UploadAuthorityGeneration,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let gate = Arc::clone(self);
        let mut changes = self.changes.subscribe();
        Box::pin(async move {
            loop {
                if !gate.permits_generation(class, generation) {
                    return;
                }
                if changes.changed().await.is_err() {
                    return;
                }
            }
        })
    }
}

pub(crate) struct UploadIoPermit {
    gate: Arc<UploadSafetyGate>,
    class: UploadIoClass,
    generation: UploadAuthorityGeneration,
    revision: u64,
    changes: watch::Receiver<u64>,
}

impl UploadIoPermit {
    pub(crate) fn generation(&self) -> UploadAuthorityGeneration {
        self.generation
    }

    pub(crate) fn ensure_current(&self) -> Result<(), UploadSafetyError> {
        let snapshot = self
            .gate
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if snapshot.revision == self.revision
            && snapshot.generation == Some(self.generation)
            && snapshot.permits(self.class)
        {
            Ok(())
        } else {
            Err(UploadSafetyError {
                reason: snapshot.reason.clone(),
            })
        }
    }

    pub(crate) fn authority_changed_error(&self) -> UploadSafetyError {
        let snapshot = self
            .gate
            .snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        UploadSafetyError {
            reason: snapshot.reason.clone(),
        }
    }

    pub(crate) async fn invalidated(&mut self) {
        loop {
            if self.ensure_current().is_err() {
                return;
            }
            if self.changes.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_draining_rejects_only_new_physical_writes() {
        let gate = UploadSafetyGate::new();
        let generation = UploadAuthorityGeneration {
            namespace: 7,
            capacity_policy: 11,
        };
        gate.establish(generation, true);
        assert!(gate.permit(UploadIoClass::Read).is_ok());
        assert!(gate.permit(UploadIoClass::Promotion).is_ok());
        assert!(gate.permit(UploadIoClass::Recovery).is_ok());
        assert!(gate.permit(UploadIoClass::CredentialRefresh).is_ok());
        assert!(gate.permit(UploadIoClass::NewWrite).is_err());
    }

    #[test]
    fn disabled_is_ready_but_permanently_denies_every_io_class() {
        let gate = UploadSafetyGate::disabled();
        for class in [
            UploadIoClass::Read,
            UploadIoClass::NewWrite,
            UploadIoClass::Promotion,
            UploadIoClass::Recovery,
            UploadIoClass::CredentialRefresh,
        ] {
            assert!(gate.permit(class).is_err());
        }
        gate.establish(
            UploadAuthorityGeneration {
                namespace: 1,
                capacity_policy: 1,
            },
            false,
        );
        assert_eq!(gate.state(), UploadSafetyState::Disabled);
    }

    #[tokio::test]
    async fn generation_change_invalidates_an_in_flight_permit() {
        let gate = UploadSafetyGate::new();
        let generation = UploadAuthorityGeneration {
            namespace: 3,
            capacity_policy: 5,
        };
        gate.establish(generation, false);
        let mut permit = gate.permit(UploadIoClass::Promotion).unwrap();
        gate.mark_ledger_mismatch("injected mismatch");
        tokio::time::timeout(std::time::Duration::from_millis(50), permit.invalidated())
            .await
            .unwrap();
        assert!(permit.ensure_current().is_err());
    }

    #[test]
    fn namespace_unsafe_is_terminal_for_the_process() {
        let gate = UploadSafetyGate::new();
        let generation = UploadAuthorityGeneration {
            namespace: 1,
            capacity_policy: 1,
        };
        gate.establish(generation, false);
        gate.mark_namespace_unsafe("changed bucket");
        gate.establish(generation, false);
        assert_eq!(gate.state(), UploadSafetyState::NamespaceUnsafe);
        assert!(gate.permit(UploadIoClass::Read).is_err());
    }
}
