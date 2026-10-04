//! Private, synchronous preparation binding and retained direct SQL witness.
//! Buffers stay with the original protocol preparation; this module parses no
//! XML and owns no AppState, clock, SQL, socket, task, or retry capability.
use crate::services::message_admission::witness::DirectOperationHandle;
use northstar_message_application::{direct_commit::*, direct_lifecycle::PreparationAdmission};
use northstar_message_core::{
    DirectPersonalMessageAdmission, DirectPostCommitMode, DirectSpoolEligibility,
    IdentityAuthority, PersonalMessageDestination, ValidatedPersonalMessage,
};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
#[error("direct transaction committed but its continuation did not complete")]
struct DirectContinuationError {
    receipt: Receipt,
    #[source]
    source: anyhow::Error,
}

pub(super) fn continuation_error(
    error: anyhow::Error,
    outcome: Option<ExecutionOutcome>,
) -> anyhow::Error {
    match outcome {
        Some(ExecutionOutcome::ReceiptPreserved(receipt)) => DirectContinuationError {
            receipt,
            source: error,
        }
        .into(),
        _ => error,
    }
}

pub(crate) fn preserved_transaction(error: &anyhow::Error) -> Option<&TransactionOutcome> {
    error
        .downcast_ref::<DirectContinuationError>()
        .map(|error| &error.receipt.prepared.outcome)
}

/// Actual purpose-specific views derived by OriginalDirectMessage. These are
/// private runtime inputs, never caller-supplied fingerprints or preparation IDs.
pub(crate) struct LocalPreparation<'a> {
    pub(crate) actor_id: Uuid,
    pub(crate) sender_bare: &'a str,
    pub(crate) sender_full: &'a str,
    pub(crate) target_bare: &'a str,
    pub(crate) origin_id: Option<&'a str>,
    pub(crate) identity_payload: &'a str,
    pub(crate) stored_stanza: &'a str,
    pub(crate) admission: PreparationAdmission<'a>,
}

pub(crate) struct PreparedLocalDirect<'a> {
    owner: DirectOperationHandle,
    effect: DirectEffect,
    command: ValidatedPersonalMessage<'a>,
    eligibility: DirectSpoolEligibility,
}

impl std::fmt::Debug for PreparedLocalDirect<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedLocalDirect { authority: [redacted] }")
    }
}

impl<'a> PreparedLocalDirect<'a> {
    pub(crate) fn bind(
        owner: DirectOperationHandle,
        original: LocalPreparation<'_>,
        command: ValidatedPersonalMessage<'a>,
        eligibility: DirectSpoolEligibility,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            command.local_actor_id == Some(original.actor_id),
            "direct preparation actor mismatch"
        );
        let PersonalMessageDestination::Local(destination) = command.destination else {
            anyhow::bail!("direct preparation requires local destination");
        };
        anyhow::ensure!(
            destination.sender_jid == original.sender_full
                && destination.recipient_bare_jid == original.target_bare,
            "direct preparation source/target mismatch"
        );
        anyhow::ensure!(
            destination.stanza == original.stored_stanza,
            "direct preparation stored projection mismatch"
        );
        match (command.identity, original.origin_id) {
            (Some(identity), Some(origin)) => anyhow::ensure!(
                identity.authority == IdentityAuthority::LocalOrigin
                    && identity.actor_scope_raw == original.sender_bare
                    && identity.actor_scope == original.sender_bare
                    && identity.target_scope == original.target_bare
                    && identity.value == origin
                    && identity.payload == original.identity_payload,
                "direct preparation identity/payload mismatch"
            ),
            (None, None) => {}
            _ => anyhow::bail!("direct preparation origin identity mismatch"),
        }
        anyhow::ensure!(
            command
                .archives
                .iter()
                .all(|projection| projection.owner_id == original.actor_id
                    || projection.owner_id == destination.recipient_id),
            "direct preparation archive owner mismatch"
        );
        let facts = DirectCommandFacts::for_local(&command, eligibility)?;
        let effect = owner.prepare_direct(original.admission, facts)?;
        Ok(Self {
            owner,
            effect,
            command,
            eligibility,
        })
    }

    pub(crate) fn command(&self) -> &ValidatedPersonalMessage<'a> {
        &self.command
    }
    pub(crate) fn eligibility(&self) -> DirectSpoolEligibility {
        self.eligibility
    }
}

impl DirectCommitObserver for PreparedLocalDirect<'_> {
    fn start(
        &self,
        command: &ValidatedPersonalMessage<'_>,
        eligibility: DirectSpoolEligibility,
    ) -> Result<(), Rejected> {
        // Equality is between the same prepared purpose-specific command, not
        // between its intentionally different admission/live/stored projections.
        if *command != self.command || eligibility != self.eligibility {
            return Err(Rejected::Command);
        }
        self.owner.start_direct(&self.effect)
    }
    fn prepare(
        &self,
        outcome: TransactionOutcome,
        admitted_mode: DirectPostCommitMode,
    ) -> Result<PreparedCommit, Rejected> {
        let prepared = PreparedCommit {
            correlation: self.effect.correlation(),
            outcome,
            admitted_mode,
        };
        self.owner
            .prepare_direct_commit(&self.effect, prepared.clone())?;
        Ok(prepared)
    }
    fn received(&self, prepared: PreparedCommit) -> Result<(), Rejected> {
        self.owner.receive_direct_commit(&self.effect, prepared)
    }
    fn complete(
        &self,
        result: Option<DirectPersonalMessageAdmission>,
    ) -> Result<ExecutionOutcome, Rejected> {
        self.owner.complete_direct(&self.effect, result)
    }
}

/// The real archive caller supplies transaction.commit(); fake-port tests can
/// choose each cut without executing SQL. A call boundary is not a DB receipt.
pub(crate) async fn commit_observed<E>(
    commit: impl std::future::Future<Output = Result<(), E>>,
    observer: &dyn DirectCommitObserver,
    outcome: TransactionOutcome,
    admitted_mode: DirectPostCommitMode,
) -> anyhow::Result<()>
where
    E: Into<anyhow::Error>,
{
    let prepared = observer.prepare(outcome, admitted_mode)?;
    commit.await.map_err(Into::into)?;
    // No await, mode read, logging or result mapping before the receipt.
    observer.received(prepared)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_message_application::direct_lifecycle::{DirectOutcomeClass, TerminalReason};
    use northstar_message_core::LocalDelivery;

    fn prepared() -> (DirectOperationHandle, PreparedLocalDirect<'static>) {
        let owner = DirectOperationHandle::new(Uuid::new_v4());
        let command = ValidatedPersonalMessage {
            local_actor_id: Some(Uuid::from_u128(1)),
            identity: None,
            archives: &[],
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: Uuid::from_u128(2),
                recipient_id: Uuid::from_u128(3),
                recipient_bare_jid: "bob@example.test",
                sender_jid: "alice@example.test/device",
                stanza: "private-stored-stanza",
                encrypted: false,
                mam_backed: false,
            }),
        };
        let prepared = PreparedLocalDirect::bind(
            owner.clone(),
            LocalPreparation {
                actor_id: Uuid::from_u128(1),
                sender_bare: "alice@example.test",
                sender_full: "alice@example.test/device",
                target_bare: "bob@example.test",
                origin_id: None,
                identity_payload: "private-identity-stanza",
                stored_stanza: "private-stored-stanza",
                admission: PreparationAdmission::NoAdmissionRequired,
            },
            command,
            DirectSpoolEligibility::Eligible,
        )
        .unwrap();
        (owner, prepared)
    }
    fn stored() -> TransactionOutcome {
        TransactionOutcome::Stored {
            recipient_id: Uuid::from_u128(3),
            delivery_id: Uuid::from_u128(2),
            archive_ids: vec![],
            live_claim_id: Some(Uuid::from_u128(2)),
        }
    }

    #[tokio::test]
    async fn real_commit_wrapper_preserves_every_cancellation_cut_in_outer_owner() {
        for cut in 0..4 {
            let (owner, prepared) = prepared();
            let mut future = Box::pin(async {
                prepared
                    .start(prepared.command(), prepared.eligibility())
                    .unwrap();
                if cut == 1 {
                    std::future::pending::<()>().await;
                }
                commit_observed(
                    async {
                        if cut == 2 {
                            std::future::pending::<()>().await;
                        }
                        Ok::<(), anyhow::Error>(())
                    },
                    &prepared,
                    stored(),
                    DirectPostCommitMode::Live,
                )
                .await
                .unwrap();
                std::future::pending::<()>().await;
            });
            if cut != 0 {
                assert!(futures::poll!(&mut future).is_pending());
            }
            drop(future);
            drop(prepared);
            let snapshot = owner.snapshot().direct.unwrap();
            assert_eq!(snapshot.started, cut != 0);
            assert!(matches!(
                (&snapshot.knowledge, cut),
                (Knowledge::NoCommitRequested, 0 | 1)
                    | (Knowledge::CommitCallEntered(_), 2)
                    | (Knowledge::ReceiptKnown(_), 3)
            ));
            assert_eq!(snapshot.outcome, None);
            let summary = owner.retire(TerminalReason::Cancelled).direct.unwrap();
            assert_eq!(
                summary.confirmed_outcome,
                (cut == 3).then_some(DirectOutcomeClass::Stored)
            );
            assert_eq!(summary.returned_mode, None);
        }
    }

    #[test]
    fn prepared_command_is_immutable_at_the_actual_application_observer_entry() {
        let (owner, prepared) = prepared();
        let mut changed = *prepared.command();
        let PersonalMessageDestination::Local(mut destination) = changed.destination else {
            unreachable!()
        };
        destination.stanza = "substituted stored payload";
        changed.destination = PersonalMessageDestination::Local(destination);
        let before = owner.snapshot();
        assert_eq!(
            prepared.start(&changed, prepared.eligibility()),
            Err(Rejected::Command)
        );
        assert_eq!(owner.snapshot(), before);
        prepared
            .start(prepared.command(), prepared.eligibility())
            .unwrap();
        assert_eq!(
            prepared.start(prepared.command(), prepared.eligibility()),
            Err(Rejected::AlreadyStarted)
        );
        assert!(!format!("{prepared:?}").contains("private-"));
    }

    #[tokio::test]
    async fn known_transaction_outcome_survives_mapping_error_without_fabricating_mode_or_delivery()
    {
        for fact in [
            stored(),
            TransactionOutcome::Replay {
                archive_ids: vec![Uuid::from_u128(99)],
            },
            TransactionOutcome::AccountUnavailable,
        ] {
            let (owner, prepared) = prepared();
            prepared
                .start(prepared.command(), prepared.eligibility())
                .unwrap();
            commit_observed(
                async { Ok::<(), anyhow::Error>(()) },
                &prepared,
                fact.clone(),
                DirectPostCommitMode::Live,
            )
            .await
            .unwrap();
            let outcome = prepared.complete(None).unwrap();
            let error = continuation_error(
                anyhow::anyhow!("injected continuation failure"),
                Some(outcome),
            );
            assert_eq!(preserved_transaction(&error), Some(&fact));
            assert_eq!(
                owner
                    .retire(TerminalReason::Completed)
                    .direct
                    .unwrap()
                    .returned_mode,
                None
            );
        }
    }
}
