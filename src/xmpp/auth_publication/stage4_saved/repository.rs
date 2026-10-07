//! Finite repository replies only. No SQL, executor, timer or bearer issue.
use super::*;
use crate::auth;
use crate::services::authentication::publication::{
    self as observation, CredentialInvocation, CredentialPreparation, PreparationResult,
};
use crate::services::authentication::*;
use crate::services::sm::*;
use northstar_archive_core::ArchiveBoundary;

/// One supplied repository COMMIT child, with no timer or task. Its destructor
/// observes this child's actual lifetime, not the lifetime of the whole actor.
struct PublicationCommit {
    cut: wire::CommitCut,
    read: Option<observation::Observation>,
    recorder: Capture,
}
impl Future for PublicationCommit {
    type Output = std::io::Result<()>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        match self.cut {
            wire::CommitCut::Complete => Poll::Ready(Ok(())),
            wire::CommitCut::Pending => Poll::Pending,
            wire::CommitCut::Error => Poll::Ready(Err(std::io::Error::other(
                "supplied publication COMMIT error",
            ))),
        }
    }
}
impl Drop for PublicationCommit {
    fn drop(&mut self) {
        // Observation access itself can panic on a poisoned production read
        // cell. Contain it so instrumentation cannot turn Cancelled into
        // Panicked. Recover the recorder solely to retain explicit loss.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let read = self.read.as_ref().ok_or(())?;
            let fact = facts::publication(read, wire::Cut::ChildDrop);
            let mut recorder = self.recorder.lock().map_err(|_| ())?;
            recorder.capture(fact).map(|_| ()).map_err(|_| ())
        }));
        if !matches!(result, Ok(Ok(()))) {
            match self.recorder.lock() {
                Ok(mut recorder) => recorder.missing_observation(),
                Err(poisoned) => poisoned.into_inner().missing_observation(),
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct Repository {
    pub(super) input: wire::AuthInput,
    pub(super) credential: observation::CredentialObservation,
    pub(super) publication: Option<observation::Observation>,
    pub(super) recorder: Capture,
}
impl Repository {
    fn credential_cut(&self, cut: wire::Cut) {
        facts::emit(&self.recorder, facts::credential(&self.credential, cut))
    }
    fn publication_cut(&self, cut: wire::Cut) {
        let Some(read) = &self.publication else {
            facts::lost(&self.recorder);
            return;
        };
        facts::emit(&self.recorder, facts::publication(read, cut))
    }
    fn unsupported(&self) -> anyhow::Error {
        facts::lost(&self.recorder);
        anyhow::anyhow!("repository operation outside finite auth bridge")
    }
    fn publication_commit(&self, cut: wire::CommitCut) -> PublicationCommit {
        if self.publication.is_none() {
            facts::lost(&self.recorder);
        }
        PublicationCommit {
            cut,
            read: self.publication.clone(),
            recorder: self.recorder.clone(),
        }
    }
    async fn begin(&self, invocation: &CredentialInvocation<'_>) -> Result<()> {
        self.credential_cut(wire::Cut::PortEntry);
        CredentialInvocation::begin(
            Some(invocation),
            std::future::ready(Ok::<(), std::io::Error>(())),
        )
        .await
        .map_err(observation::credential_error)?;
        CredentialInvocation::eligibility(
            Some(invocation),
            std::future::ready(Ok::<_, std::io::Error>(Some(
                self.input.preparation.generation_allowed,
            ))),
        )
        .await
        .map_err(observation::credential_error)?;
        // The closed validated input only admits the positive generation reply.
        ensure!(
            self.input.preparation.generation_allowed,
            "unsupported refused generation input"
        );
        invocation.transaction_returned();
        Ok(())
    }
    fn stage(
        &self,
        invocation: &CredentialInvocation<'_>,
        connection: Uuid,
        user: Uuid,
        generation: i64,
        device: Option<Uuid>,
    ) -> Result<Option<StagedLoginEpoch>> {
        invocation.preparation_entered(CredentialPreparation::Stage);
        // stage_epoch is explicit supplied
        // repository data, independent of PublicationReply's later epoch.
        let stage = match device {
            Some(device_id) if self.input.preparation.stage_present => {
                let epoch = *self
                    .input
                    .preparation
                    .stage_epoch
                    .get()
                    .ok_or_else(|| anyhow::anyhow!("stage epoch reply absent"))?;
                let operation_id = Uuid::new_v4();
                invocation.stage_id(operation_id);
                Some(StagedLoginEpoch {
                    operation_id,
                    connection_id: connection,
                    user_id: user,
                    device_id,
                    auth_generation: generation,
                    epoch,
                })
            }
            None if !self.input.preparation.stage_present
                && self.input.preparation.stage_epoch.get().is_none() =>
            {
                None
            }
            _ => anyhow::bail!("stage reply does not match finite credential input"),
        };
        invocation.stage_returned(&Ok(stage));
        Ok(stage)
    }
    async fn commit(&self, invocation: &CredentialInvocation<'_>) -> Result<()> {
        CredentialInvocation::commit(
            Some(invocation),
            supplied_commit(self.input.preparation.commit),
        )
        .await
        .map_err(observation::credential_error)
    }
}
pub(crate) async fn supplied_commit(cut: wire::CommitCut) -> std::io::Result<()> {
    match cut {
        wire::CommitCut::Complete => Ok(()),
        wire::CommitCut::Error => Err(std::io::Error::other("supplied repository COMMIT error")),
        wire::CommitCut::Pending => std::future::pending().await,
    }
}
impl AuthenticationRepository for Repository {
    async fn scram_credentials(
        &self,
        _: &str,
        _: auth::ScramAlgorithm,
    ) -> AuthenticationResult<ScramCredentialSet> {
        AuthenticationResult::BackendFailure(self.unsupported())
    }
    async fn authenticate_plain(
        &self,
        _: &str,
        _: &str,
        _: AuthenticationPolicy,
    ) -> AuthenticationResult<AuthenticatedAccount> {
        AuthenticationResult::BackendFailure(self.unsupported())
    }
    async fn account_by_id(&self, _: Uuid) -> Result<Option<LoadedAccount>> {
        Err(self.unsupported())
    }
    async fn account_by_username(&self, _: &str) -> Result<Option<LoadedAccount>> {
        Err(self.unsupported())
    }
    async fn generation_state(&self, _: AuthenticationFence) -> AuthenticationResult<()> {
        AuthenticationResult::BackendFailure(self.unsupported())
    }
    async fn bind2_archive_boundaries(
        &self,
        _: Uuid,
        _: i64,
    ) -> AuthenticationResult<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
        AuthenticationResult::BackendFailure(self.unsupported())
    }
    async fn authenticate_fast(
        &self,
        _: FastProofRequest<'_>,
    ) -> AuthenticationResult<FastAuthenticationSuccess> {
        AuthenticationResult::BackendFailure(self.unsupported())
    }
    async fn commit_fast_with_login_epoch(
        &self,
        _: Uuid,
        _: i64,
        _: &FastCommitPlan,
        _: Option<Uuid>,
        _: Uuid,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        AuthenticationResult::BackendFailure(self.unsupported())
    }
    async fn commit_fast_with_login_epoch_observed(
        &self,
        user: Uuid,
        generation: i64,
        plan: &FastCommitPlan,
        device: Option<Uuid>,
        connection: Uuid,
        invocation: &CredentialInvocation<'_>,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        let result: Result<CredentialCommitReceipt> = async {
            invocation.enter_fast(user, generation, plan, device, connection)?;
            self.begin(invocation).await?;
            let stage = self.stage(invocation, connection, user, generation, device)?;
            invocation.preparation_entered(CredentialPreparation::Fast);
            // The accepted U path carries the actual empty FastCommitPlan:
            // successful preparation does not issue a bearer.
            ensure!(
                plan == &FastCommitPlan::default(),
                "saved U cannot issue a bearer"
            );
            invocation
                .preparation_returned(CredentialPreparation::Fast, PreparationResult::Present);
            self.commit(invocation).await?;
            let receipt = CredentialCommitReceipt::new(None, stage, None);
            invocation.constructed(&receipt);
            self.credential_cut(wire::Cut::PortReturn);
            Ok(receipt)
        }
        .await;
        match result {
            Ok(receipt) => AuthenticationResult::Authenticated(receipt),
            Err(error) => AuthenticationResult::BackendFailure(error),
        }
    }
    async fn publish_credential_commit(
        &self,
        _: &CredentialCommitReceipt,
    ) -> AuthenticationResult<Option<i64>> {
        AuthenticationResult::BackendFailure(self.unsupported())
    }
    async fn publish_credential_commit_observed(
        &self,
        invocation: &observation::Invocation<'_>,
    ) -> AuthenticationResult<Option<i64>> {
        let result: Result<Option<i64>> = async {
            invocation.enter_repository()?;
            self.publication_cut(wire::Cut::PortEntry);
            let epoch = match &self.input.publication {
                wire::PublicationReply::Committed(reply) => {
                    let epoch = reply.epoch.get().copied();
                    invocation
                        .commit(self.publication_commit(wire::CommitCut::Complete), epoch)
                        .await
                        .map_err(observation::credential_error)?;
                    epoch
                }
                wire::PublicationReply::CommitPending(reply) => {
                    let epoch = reply.epoch.get().copied();
                    invocation
                        .commit(self.publication_commit(wire::CommitCut::Pending), epoch)
                        .await
                        .map_err(observation::credential_error)?;
                    epoch
                }
                wire::PublicationReply::BackendError(_) => {
                    anyhow::bail!("supplied publication backend error before COMMIT")
                }
                wire::PublicationReply::NoSql(_) => return Err(self.unsupported()),
            };
            Ok(epoch)
        }
        .await;
        self.publication_cut(wire::Cut::PortReturn);
        match result {
            Ok(epoch) => AuthenticationResult::Authenticated(epoch),
            Err(error) => AuthenticationResult::BackendFailure(error),
        }
    }
}
impl SmRepository for Repository {
    async fn revoke_session(&self, _: Uuid) -> Result<()> {
        Err(self.unsupported())
    }
    async fn create_session(
        &self,
        _: SmSessionCreationRequest<'_>,
    ) -> Result<SmSessionCreationOutcome> {
        Err(self.unsupported())
    }
    async fn claim_resume(
        &self,
        _: SmResumeClaimRequest<'_>,
        _: SmIpPolicy,
    ) -> Result<SmResumeClaimOutcome> {
        Err(self.unsupported())
    }
    async fn checkpoint_session(
        &self,
        _: Uuid,
        _: Uuid,
        _: &SmSessionSnapshot,
        _: u64,
        _: u64,
        _: usize,
        _: usize,
        _: Option<&ownership::PreparedCheckpoint<'_>>,
    ) -> Result<SmCheckpointOutcome> {
        Err(self.unsupported())
    }
    async fn remove_live_muc_memberships(
        &self,
        _: Uuid,
        _: Uuid,
        _: &[SmMucMembership],
    ) -> Result<bool> {
        Err(self.unsupported())
    }
    async fn checkpoint_and_acknowledge(
        &self,
        _: Uuid,
        _: Uuid,
        _: &SmSessionSnapshot,
        _: &[crate::outbound::SmUnackedStanza],
        _: u64,
        _: u64,
        _: usize,
        _: usize,
        _: Option<&ownership::PreparedCheckpoint<'_>>,
    ) -> Result<SmCheckpointOutcome> {
        Err(self.unsupported())
    }
    async fn acknowledge_delivery_batch(
        &self,
        _: &[crate::outbound::TransportOwnershipSource],
        _: Option<&ownership::PreparedBatch<'_>>,
    ) -> Result<()> {
        Err(self.unsupported())
    }
    async fn reserve_binding(
        &self,
        _: Uuid,
        _: Uuid,
        _: i64,
        _: &str,
        _: u64,
    ) -> Result<BindingReservationOutcome> {
        Err(self.unsupported())
    }
    async fn finalize_binding(
        &self,
        _: Uuid,
        _: Uuid,
        _: i64,
        _: &str,
        _: u64,
        _: Option<Uuid>,
        _: Option<&FastCommitPlan>,
    ) -> Result<BindingFinalizationOutcome> {
        Err(self.unsupported())
    }
    async fn finalize_resume(
        &self,
        _: SmResumeFinalizationRequest<'_>,
    ) -> Result<SmResumeFinalizationOutcome> {
        Err(self.unsupported())
    }
    async fn finalize_binding_observed(
        &self,
        connection: Uuid,
        user: Uuid,
        generation: i64,
        key: &str,
        lease: u64,
        device: Option<Uuid>,
        fast: Option<&FastCommitPlan>,
        invocation: &CredentialInvocation<'_>,
    ) -> Result<BindingFinalizationOutcome> {
        invocation.enter_binding(connection, user, generation, key, lease, device, fast)?;
        self.begin(invocation).await?;
        ensure!(fast.is_none(), "saved B cannot issue a bearer");
        invocation.preparation_entered(CredentialPreparation::Binding);
        let reserved = self.input.preparation.binding_reserved;
        invocation.preparation_returned(
            CredentialPreparation::Binding,
            if reserved {
                PreparationResult::Present
            } else {
                PreparationResult::Absent
            },
        );
        ensure!(reserved, "unsupported refused reservation input");
        let stage = self.stage(invocation, connection, user, generation, device)?;
        self.commit(invocation).await?;
        let receipt = CredentialCommitReceipt::new(
            None,
            stage,
            Some(BindingPublication {
                connection_id: connection,
                user_id: user,
                full_jid: key.to_owned(),
                lease_seconds: lease,
            }),
        );
        invocation.constructed(&receipt);
        self.credential_cut(wire::Cut::PortReturn);
        Ok(BindingFinalizationOutcome::Committed { receipt })
    }
    async fn finalize_resume_observed(
        &self,
        _: SmResumeFinalizationRequest<'_>,
        _: &CredentialInvocation<'_>,
    ) -> Result<SmResumeFinalizationOutcome> {
        Err(self.unsupported())
    }
    async fn release_claim(&self, _: Uuid, _: Uuid) -> Result<()> {
        Err(self.unsupported())
    }
    async fn release_live_session(&self, _: Uuid) -> Result<bool> {
        Err(self.unsupported())
    }
    async fn suspend_exact_session(
        &self,
        _: Uuid,
        _: Uuid,
        _: Uuid,
        _: i64,
        _: &SmSessionSnapshot,
        _: u64,
        _: usize,
        _: usize,
    ) -> Result<bool> {
        Err(self.unsupported())
    }
}

#[cfg(test)]
mod drop_controls {
    use super::super::ordinary;
    use super::*;
    use crate::xmpp::protocol::mix::stage4_saved::RouteMap;

    #[tokio::test]
    async fn commit_child_drop_preserves_cancelled_with_poisoned_recorder() {
        let recorder = ordinary::recorder();
        let input = ordinary::bound(
            wire::TransportKind::Tcp,
            wire::PublicationReply::CommitPending(wire::EpochReply {
                epoch: wire::Nullable::Null(()),
            }),
        );
        let routes = RouteMap::new(recorder.clone());
        let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
        let (item, read, mut publisher) = super::super::build(
            &input,
            Some(route.clone()),
            recorder.clone(),
            ordinary::credential_site(0),
        )
        .await
        .unwrap()
        .unwrap()
        .split();
        let owner = crate::xmpp::stage4_native::write_auth(
            item,
            route.connection_id(),
            ordinary::native_site(0),
            ordinary::write_ok(),
            recorder.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        let mut future = Box::pin(publisher.publish(vec![owner], None, None, &recorder));
        assert!(futures::poll!(future.as_mut()).is_pending());
        assert_eq!(
            read.live_snapshot().publication,
            observation::Knowledge::CommitCallEntered
        );
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = recorder.lock().unwrap();
            panic!("ordinary recorder poison injection");
        }));
        assert!(poisoned.is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(future))).is_ok());
        assert_eq!(
            read.live_snapshot().terminal,
            Some(observation::Terminal::Cancelled)
        );
        assert!(matches!(
            ordinary::drain(&recorder).observation_status,
            wire::ObservationStatus::Lost(_)
        ));
    }
    #[tokio::test]
    async fn commit_child_drop_preserves_existing_capture_loss_and_cancelled_terminal() {
        let recorder = ordinary::recorder();
        let input = ordinary::bound(
            wire::TransportKind::Tcp,
            wire::PublicationReply::CommitPending(wire::EpochReply {
                epoch: wire::Nullable::Null(()),
            }),
        );
        let routes = RouteMap::new(recorder.clone());
        let (route, _receiver) = routes.install_auth(&input, 1).unwrap();
        let (item, read, mut publisher) = super::super::build(
            &input,
            Some(route.clone()),
            recorder.clone(),
            ordinary::credential_site(0),
        )
        .await
        .unwrap()
        .unwrap()
        .split();
        let owner = crate::xmpp::stage4_native::write_auth(
            item,
            route.connection_id(),
            ordinary::native_site(0),
            ordinary::write_ok(),
            recorder.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        let mut future = Box::pin(publisher.publish(vec![owner], None, None, &recorder));
        assert!(futures::poll!(future.as_mut()).is_pending());
        {
            let mut recorder = recorder.lock().unwrap();
            recorder.missing_observation();
        }
        drop(future);
        assert_eq!(
            read.live_snapshot().terminal,
            Some(observation::Terminal::Cancelled)
        );
        assert!(matches!(
            ordinary::drain(&recorder).observation_status,
            wire::ObservationStatus::Lost(wire::LostObservation {
                reason: wire::Loss::MissingObservation,
                ..
            })
        ));
    }
}
