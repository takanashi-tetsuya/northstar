use crate::account_deletion::{self, AccountDeletionRecoveryContext, AccountDeletionRecoveryPorts};
use anyhow::Result;
use northstar_auth_application::account::{
    AccountPolicy, AccountRepository, AccountService, DeletionQuiesceOutcome,
    DeletionQuiesceRequest, DeletionRecoveryJob, HttpRegistrationOutcome, HttpRegistrationRequest,
    PasswordChangeOutcome, PasswordChangeRequest, RegistrationGuardOutcome,
    RegistrationGuardRequest, RegistrationOutcome, RegistrationRequest, RemovedAccount,
};
use northstar_roster_core::RosterChange;
use northstar_runtime::workers::{WorkerCriticality, WorkerMode, WorkerRegistry};
use northstar_security::password_work::PasswordWorkReservation;
use northstar_telemetry::metrics::Metrics;
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::time::Duration;
use tokio::sync::{oneshot, Notify};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Claim(i64, i64),
    Revoke(Uuid),
    Delete(Uuid),
    Disconnect(Uuid, String),
    Release {
        user_id: Uuid,
        username: String,
        token: Uuid,
        attempts: i32,
        error_code: String,
    },
}

impl Call {
    fn release(job: &DeletionRecoveryJob) -> Self {
        Self::Release {
            user_id: job.user_id,
            username: job.username.clone(),
            token: job.claim_token(),
            attempts: job.attempts(),
            error_code: "finalization-failed".into(),
        }
    }
}

#[derive(Clone, Copy)]
enum Failure {
    None,
    Revoke,
    Delete,
}

struct Recording {
    calls: Mutex<Vec<Call>>,
    jobs: Mutex<Option<Vec<DeletionRecoveryJob>>>,
    failure: Failure,
    release_matches: bool,
    finished: Notify,
}

struct Repository(Arc<Recording>);

impl AccountRepository for Repository {
    async fn register_http(
        &self,
        _: HttpRegistrationRequest<'_>,
        _: AccountPolicy,
    ) -> Result<HttpRegistrationOutcome> {
        panic!("unexpected HTTP registration")
    }

    async fn verify_registration_guard(
        &self,
        _: RegistrationGuardRequest<'_>,
    ) -> Result<RegistrationGuardOutcome> {
        panic!("unexpected registration guard")
    }

    async fn register(
        &self,
        _: RegistrationRequest<'_>,
        _: AccountPolicy,
        _: PasswordWorkReservation,
    ) -> Result<RegistrationOutcome> {
        panic!("unexpected registration")
    }

    async fn change_password(
        &self,
        _: PasswordChangeRequest<'_>,
        _: AccountPolicy,
    ) -> Result<PasswordChangeOutcome> {
        panic!("unexpected password change")
    }

    async fn quiesce_for_deletion(
        &self,
        _: DeletionQuiesceRequest<'_>,
    ) -> Result<DeletionQuiesceOutcome> {
        panic!("recovery must finish an already quiesced account")
    }

    async fn delete_quiesced(&self, user_id: Uuid) -> Result<Option<RemovedAccount>> {
        self.0.calls.lock().unwrap().push(Call::Delete(user_id));
        if matches!(self.0.failure, Failure::Delete) {
            anyhow::bail!("fixture deletion failed");
        }
        Ok(Some(RemovedAccount {
            roster: Vec::new(),
            reverse_roster_changes: Vec::new(),
        }))
    }

    async fn claim_deletion_recovery(
        &self,
        limit: i64,
        lease_seconds: i64,
    ) -> Result<Vec<DeletionRecoveryJob>> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(Call::Claim(limit, lease_seconds));
        Ok(self
            .0
            .jobs
            .lock()
            .unwrap()
            .take()
            .expect("one recovery turn"))
    }

    async fn release_deletion_recovery(
        &self,
        job: &DeletionRecoveryJob,
        error_code: &str,
    ) -> Result<bool> {
        self.0.calls.lock().unwrap().push(Call::Release {
            user_id: job.user_id,
            username: job.username.clone(),
            token: job.claim_token(),
            attempts: job.attempts(),
            error_code: error_code.to_owned(),
        });
        self.0.finished.notify_one();
        Ok(self.0.release_matches)
    }
}

struct Ports(Arc<Recording>);

impl AccountDeletionRecoveryPorts for Ports {
    async fn revoke_sm(&self, user_id: Uuid) -> Result<usize> {
        self.0.calls.lock().unwrap().push(Call::Revoke(user_id));
        if matches!(self.0.failure, Failure::Revoke) {
            anyhow::bail!("fixture SM revocation failed");
        }
        Ok(3)
    }

    async fn deliver_roster_change(&self, _: Uuid, _: &str, _: &RosterChange) -> Result<()> {
        panic!("fixture has no reverse roster changes")
    }

    fn deliver_local_presence(&self, _: &str, _: &str) {
        panic!("fixture has no roster contacts")
    }

    async fn remote_nodes(&self, _: &str) -> Result<Vec<String>> {
        panic!("fixture has no roster contacts")
    }

    async fn send_account_removal_presence(&self, _: &str, _: &str, _: &str) -> Result<bool> {
        panic!("fixture has no roster contacts")
    }

    fn federation_domain_allowed(&self, _: &str) -> bool {
        panic!("fixture has no roster contacts")
    }

    async fn send_federation_presence(&self, _: &str, _: String, _: &str) -> bool {
        panic!("fixture has no roster contacts")
    }

    async fn disconnect_account(&self, user_id: Uuid, bare_jid: &str) {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(Call::Disconnect(user_id, bare_jid.to_owned()));
        self.0.finished.notify_one();
    }
}

fn job() -> DeletionRecoveryJob {
    DeletionRecoveryJob::from_lease(
        Uuid::from_u128(0x5821),
        "recovery-user".into(),
        Uuid::from_u128(0x5822),
        7,
    )
}

fn fixture(
    failure: Failure,
    release_matches: bool,
) -> (
    Arc<AccountDeletionRecoveryContext<Repository, Ports>>,
    Arc<Recording>,
    Arc<Metrics>,
) {
    let recording = Arc::new(Recording {
        calls: Mutex::new(Vec::new()),
        jobs: Mutex::new(Some(vec![job()])),
        failure,
        release_matches,
        finished: Notify::new(),
    });
    let metrics = Arc::new(Metrics::default());
    let context = Arc::new(AccountDeletionRecoveryContext::new(
        AccountService::new(Repository(Arc::clone(&recording)), false, 60, 8192, false),
        Ports(Arc::clone(&recording)),
        Arc::clone(&metrics),
        "example.test".into(),
    ));
    (context, recording, metrics)
}

#[tokio::test]
async fn recovery_context_forwards_claim_budget_and_complete_release_job() {
    for (label, release_matches) in [("matching lease", true), ("lost lease", false)] {
        let (context, recording, _) = fixture(Failure::None, release_matches);
        let jobs = context.claim().await.unwrap();
        assert_eq!(jobs.len(), 1, "{label}");
        let expected = job();
        assert_eq!(jobs[0].user_id, expected.user_id, "{label}");
        assert_eq!(jobs[0].username, expected.username, "{label}");
        assert_eq!(jobs[0].claim_token(), expected.claim_token(), "{label}");
        assert_eq!(jobs[0].attempts(), expected.attempts(), "{label}");
        assert_eq!(
            context.release(&jobs[0]).await.unwrap(),
            release_matches,
            "{label}"
        );
        assert_eq!(
            *recording.calls.lock().unwrap(),
            [Call::Claim(16, 900), Call::release(&expected)],
            "{label}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn recovery_revokes_before_deleting_and_releases_failed_jobs() {
    for (label, failure, release_matches) in [
        ("successful recovery", Failure::None, true),
        ("SM failure", Failure::Revoke, true),
        ("delete failure", Failure::Delete, true),
        ("lost release lease", Failure::Revoke, false),
    ] {
        let (context, recording, metrics) = fixture(failure, release_matches);
        let registry = WorkerRegistry::new();
        let supervisor_cancel = CancellationToken::new();
        let runner_cancel = CancellationToken::new();
        let (result_tx, result_rx) = oneshot::channel();
        let result_tx = Mutex::new(Some(result_tx));
        registry.supervise(
            "recording-account-recovery",
            WorkerCriticality::Restartable,
            WorkerMode::OneShot,
            None,
            supervisor_cancel.clone(),
            {
                let runner_cancel = runner_cancel.clone();
                move |heartbeat| {
                    let context = Arc::clone(&context);
                    let runner_cancel = runner_cancel.clone();
                    let result_tx = result_tx.lock().unwrap().take().expect("no restart");
                    async move {
                        let result =
                            account_deletion::serve(context, runner_cancel, heartbeat).await;
                        assert!(result_tx.send(result).is_ok(), "runner result receiver");
                        Ok(())
                    }
                }
            },
        );
        tokio::time::timeout(Duration::from_secs(1), recording.finished.notified())
            .await
            .expect("recovery did not finish its first job");
        runner_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), result_rx)
            .await
            .expect("recovery did not observe cancellation")
            .unwrap()
            .unwrap();
        let shutdown = registry
            .shutdown_and_join(&supervisor_cancel, Duration::from_secs(1))
            .await;
        assert!(shutdown.is_clean(), "{label}: {shutdown:?}");

        let job = job();
        let mut expected = vec![Call::Claim(16, 900), Call::Revoke(job.user_id)];
        if !matches!(failure, Failure::Revoke) {
            expected.push(Call::Delete(job.user_id));
        }
        let failed = !matches!(failure, Failure::None);
        if failed {
            expected.push(Call::release(&job));
        } else {
            expected.push(Call::Disconnect(
                job.user_id,
                "recovery-user@example.test".into(),
            ));
        }
        assert_eq!(*recording.calls.lock().unwrap(), expected, "{label}");
        assert_eq!(
            metrics
                .account_deletion_recovery_success_total
                .load(Ordering::Relaxed),
            u64::from(!failed),
            "{label}"
        );
        assert_eq!(
            metrics
                .account_deletion_recovery_failures_total
                .load(Ordering::Relaxed),
            u64::from(failed),
            "{label}"
        );
        assert_eq!(
            metrics
                .account_deletion_recovery_lease_losses_total
                .load(Ordering::Relaxed),
            u64::from(failed && !release_matches),
            "{label}"
        );
    }
}
