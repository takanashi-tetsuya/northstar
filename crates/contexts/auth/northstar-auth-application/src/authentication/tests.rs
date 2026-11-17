use super::*;
use publication::{CredentialInvocation, CredentialKind, CredentialPreparation, PreparationResult};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reply {
    Success,
    Unknown,
    Disabled,
    Stale,
    Expired,
    Replayed,
    Integrity,
    Backend,
}
impl Reply {
    fn result<T>(self, value: T) -> AuthenticationResult<T> {
        match self {
            Self::Success => AuthenticationResult::Authenticated(value),
            Self::Unknown => AuthenticationResult::UnknownCredentials,
            Self::Disabled => AuthenticationResult::Disabled,
            Self::Stale => AuthenticationResult::StaleGeneration,
            Self::Expired => AuthenticationResult::ExpiredCredentials,
            Self::Replayed => AuthenticationResult::ReplayedCredentials,
            Self::Integrity => AuthenticationResult::IntegrityFailure,
            Self::Backend => AuthenticationResult::BackendFailure(anyhow::Error::new(
                std::io::Error::other("repository sentinel"),
            )),
        }
    }
    fn check<T>(self, result: &AuthenticationResult<T>, label: &str) {
        let actual = match result {
            AuthenticationResult::Authenticated(_) => Self::Success,
            AuthenticationResult::UnknownCredentials => Self::Unknown,
            AuthenticationResult::Disabled => Self::Disabled,
            AuthenticationResult::StaleGeneration => Self::Stale,
            AuthenticationResult::ExpiredCredentials => Self::Expired,
            AuthenticationResult::ReplayedCredentials => Self::Replayed,
            AuthenticationResult::IntegrityFailure => Self::Integrity,
            AuthenticationResult::BackendFailure(error) => {
                assert_eq!(
                    error.to_string(),
                    "repository sentinel",
                    "{label}: raw error text"
                );
                assert_eq!(
                    error.downcast_ref::<std::io::Error>().unwrap().to_string(),
                    "repository sentinel",
                    "{label}: original backend error"
                );
                Self::Backend
            }
        };
        assert_eq!(actual, self, "{label}: raw result");
    }
    fn publication_return(self, epoch: Option<i64>) -> publication::Returned {
        use publication::Returned;
        match self {
            Self::Success => Returned::Authenticated(epoch),
            Self::Unknown => Returned::UnknownCredentials,
            Self::Disabled => Returned::Disabled,
            Self::Stale => Returned::StaleGeneration,
            Self::Expired => Returned::ExpiredCredentials,
            Self::Replayed => Returned::ReplayedCredentials,
            Self::Integrity => Returned::IntegrityFailure,
            Self::Backend => Returned::BackendFailure,
        }
    }
    fn credential_return(self) -> publication::CredentialReturned {
        use publication::CredentialReturned;
        match self {
            Self::Success => CredentialReturned::Authenticated,
            Self::Unknown => CredentialReturned::UnknownCredentials,
            Self::Disabled => CredentialReturned::Disabled,
            Self::Stale => CredentialReturned::StaleGeneration,
            Self::Expired => CredentialReturned::ExpiredCredentials,
            Self::Replayed => CredentialReturned::ReplayedCredentials,
            Self::Integrity => CredentialReturned::IntegrityFailure,
            Self::Backend => CredentialReturned::BackendFailure,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Call {
    Publish(Uuid, Option<StagedLoginEpoch>, Option<BindingPublication>),
    Fast {
        observed: bool,
        user: Uuid,
        generation: i64,
        plan: FastCommitPlan,
        device: Option<Uuid>,
        connection: Uuid,
    },
}
struct Repository {
    reply: Reply,
    stored_epoch: Option<i64>,
    returned_epoch: Option<i64>,
    commit: bool,
    contradict_receipt: bool,
    publication: Option<publication::Observation>,
    credential: Option<publication::CredentialObservation>,
    calls: Mutex<Vec<Call>>,
    returned_receipt: Mutex<Option<Uuid>>,
}
impl Repository {
    fn new(reply: Reply) -> Self {
        Self {
            reply,
            stored_epoch: Some(41),
            returned_epoch: Some(41),
            commit: true,
            contradict_receipt: false,
            publication: None,
            credential: None,
            calls: Mutex::default(),
            returned_receipt: Mutex::default(),
        }
    }
    fn return_receipt(
        &self,
        receipt: CredentialCommitReceipt,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        *self.returned_receipt.lock().unwrap() = Some(receipt.publication_identity());
        self.reply.result(receipt)
    }
}
impl AuthenticationRepository for Repository {
    async fn scram_credentials(
        &self,
        _: &str,
        _: auth::ScramAlgorithm,
    ) -> AuthenticationResult<ScramCredentialSet> {
        panic!("unexpected SCRAM lookup")
    }
    async fn authenticate_plain(
        &self,
        _: &str,
        _: &str,
        _: AuthenticationPolicy,
    ) -> AuthenticationResult<AuthenticatedAccount> {
        panic!("unexpected PLAIN authentication")
    }
    async fn account_by_id(&self, _: Uuid) -> anyhow::Result<Option<LoadedAccount>> {
        panic!("unexpected account lookup")
    }
    async fn account_by_username(&self, _: &str) -> anyhow::Result<Option<LoadedAccount>> {
        panic!("unexpected account lookup")
    }
    async fn generation_state(&self, _: AuthenticationFence) -> AuthenticationResult<()> {
        panic!("unexpected generation lookup")
    }
    async fn bind2_archive_boundaries(
        &self,
        _: Uuid,
        _: i64,
    ) -> AuthenticationResult<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
        panic!("unexpected archive lookup")
    }
    async fn authenticate_fast(
        &self,
        _: FastProofRequest<'_>,
    ) -> AuthenticationResult<FastAuthenticationSuccess> {
        panic!("unexpected FAST proof")
    }
    async fn commit_fast_with_login_epoch(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        plan: &FastCommitPlan,
        device_id: Option<Uuid>,
        connection_id: Uuid,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        self.calls.lock().unwrap().push(Call::Fast {
            observed: false,
            user: user_id,
            generation: expected_auth_generation,
            plan: plan.clone(),
            device: device_id,
            connection: connection_id,
        });
        self.return_receipt(fast_receipt())
    }
    async fn commit_fast_with_login_epoch_observed(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        plan: &FastCommitPlan,
        device_id: Option<Uuid>,
        connection_id: Uuid,
        invocation: &CredentialInvocation<'_>,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        let observation = self.credential.as_ref().unwrap();
        let before = observation.snapshot();
        assert!(
            before.service_started,
            "FAST service entered before repository"
        );
        assert!(!before.repository_started, "repository enters once");
        assert_eq!(before.returned, None, "raw return not yet observed");
        invocation
            .enter_fast(
                user_id,
                expected_auth_generation,
                plan,
                device_id,
                connection_id,
            )
            .unwrap();
        self.calls.lock().unwrap().push(Call::Fast {
            observed: true,
            user: user_id,
            generation: expected_auth_generation,
            plan: plan.clone(),
            device: device_id,
            connection: connection_id,
        });
        if self.reply != Reply::Success {
            return self.return_receipt(CredentialCommitReceipt::new(None, None, None));
        }
        CredentialInvocation::begin(Some(invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
        CredentialInvocation::eligibility(
            Some(invocation),
            std::future::ready(Ok::<_, ()>(Some(true))),
        )
        .await
        .unwrap();
        invocation.transaction_returned();
        invocation.preparation_entered(CredentialPreparation::Stage);
        invocation.stage_id(stage().operation_id);
        invocation.stage_returned(&Ok(Some(stage())));
        invocation.preparation_entered(CredentialPreparation::Fast);
        invocation.preparation_returned(CredentialPreparation::Fast, PreparationResult::Present);
        CredentialInvocation::commit(Some(invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
        let receipt = fast_receipt();
        invocation.constructed(&receipt);
        self.return_receipt(if self.contradict_receipt {
            // Equal data is still a different receipt instance.
            fast_receipt()
        } else {
            receipt
        })
    }
    async fn publish_credential_commit(
        &self,
        _: &CredentialCommitReceipt,
    ) -> AuthenticationResult<Option<i64>> {
        panic!("observed publication must not use receipt-only compatibility")
    }
    async fn publish_credential_commit_observed(
        &self,
        invocation: &publication::Invocation<'_>,
    ) -> AuthenticationResult<Option<i64>> {
        let before = self.publication.as_ref().unwrap().snapshot();
        assert!(
            before.service_started,
            "publication service entered before repository"
        );
        assert!(!before.repository_started, "repository enters once");
        assert_eq!(before.returned, None, "raw return not yet observed");
        invocation.enter_repository().unwrap();
        let receipt = invocation.receipt();
        self.calls.lock().unwrap().push(Call::Publish(
            receipt.publication_identity(),
            receipt.staged_login_epoch(),
            receipt.binding_publication().cloned(),
        ));
        if self.commit {
            invocation
                .commit(std::future::ready(Ok::<(), ()>(())), self.stored_epoch)
                .await
                .unwrap();
        }
        self.reply.result(self.returned_epoch)
    }
}

fn stage() -> StagedLoginEpoch {
    StagedLoginEpoch {
        operation_id: Uuid::from_u128(1),
        connection_id: Uuid::from_u128(2),
        user_id: Uuid::from_u128(3),
        device_id: Uuid::from_u128(4),
        auth_generation: 17,
        epoch: 999,
    }
}
fn fast_receipt() -> CredentialCommitReceipt {
    CredentialCommitReceipt::new(
        Some(IssuedFastToken {
            token: Zeroizing::new("FAST-returned-bearer-sentinel".to_owned()),
            expires_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }),
        Some(stage()),
        None,
    )
}
fn service(repository: Repository) -> AuthenticationService<Repository> {
    AuthenticationService::new(
        repository,
        Arc::new(Zeroizing::new(vec![7; 32])),
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
}
fn written(receipt: &CredentialCommitReceipt) -> publication::Observation {
    let observation = publication::Observation::returned_receipt(receipt, Some(Uuid::from_u128(5)));
    observation
        .sealed(receipt.binding_publication().is_some(), false)
        .unwrap();
    for transport in [
        publication::Transport::Recording,
        publication::Transport::WriteEntered,
        publication::Transport::Written,
    ] {
        observation.transport(transport).unwrap();
    }
    observation
}

#[tokio::test]
async fn observed_services_preserve_repository_results_and_reject_publication_mismatch() {
    use publication::Knowledge;
    for (label, staged, bound, stored, returned, commit, reply) in [
        (
            "unbound needs no SQL",
            false,
            false,
            None,
            None,
            false,
            Reply::Success,
        ),
        (
            "stored epoch beats receipt hint",
            true,
            false,
            Some(41),
            Some(41),
            true,
            Reply::Success,
        ),
        (
            "binding alone needs SQL",
            false,
            true,
            None,
            None,
            true,
            Reply::Success,
        ),
        (
            "staged binding preserves both",
            true,
            true,
            Some(41),
            Some(41),
            true,
            Reply::Success,
        ),
        (
            "contradictory epoch",
            true,
            false,
            Some(41),
            Some(999),
            true,
            Reply::Success,
        ),
        (
            "unwitnessed success",
            true,
            false,
            None,
            Some(41),
            false,
            Reply::Success,
        ),
        (
            "unknown credentials",
            true,
            false,
            None,
            None,
            false,
            Reply::Unknown,
        ),
        (
            "disabled account",
            true,
            false,
            None,
            None,
            false,
            Reply::Disabled,
        ),
        (
            "stale generation",
            true,
            false,
            None,
            None,
            false,
            Reply::Stale,
        ),
        (
            "expired credentials",
            true,
            false,
            None,
            None,
            false,
            Reply::Expired,
        ),
        (
            "replayed credentials",
            true,
            false,
            None,
            None,
            false,
            Reply::Replayed,
        ),
        (
            "repository integrity failure",
            true,
            false,
            None,
            None,
            false,
            Reply::Integrity,
        ),
        (
            "backend error identity",
            true,
            false,
            None,
            None,
            false,
            Reply::Backend,
        ),
    ] {
        let binding = bound.then(|| BindingPublication {
            connection_id: stage().connection_id,
            user_id: stage().user_id,
            full_jid: "alice@example.test/device".to_owned(),
            lease_seconds: 61,
        });
        let receipt = CredentialCommitReceipt::new(
            Some(IssuedFastToken {
                token: Zeroizing::new("publication-bearer-sentinel".to_owned()),
                expires_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            }),
            staged.then(stage),
            binding.clone(),
        );
        let observation = written(&receipt);
        let invocation = observation.begin(&receipt).unwrap();
        let mut repository = Repository::new(reply);
        repository.publication = Some(observation.clone());
        repository.stored_epoch = stored;
        repository.returned_epoch = returned;
        repository.commit = commit;
        let service = service(repository);
        let result = service
            .publish_credential_commit_observed(&invocation)
            .await;
        let matches =
            reply != Reply::Success || (!staged && !bound) || (commit && stored == returned);
        (if matches { reply } else { Reply::Integrity }).check(&result, label);
        if let AuthenticationResult::Authenticated(epoch) = result {
            assert_eq!(epoch, returned, "{label}: exact epoch returned");
        }
        let snapshot = observation.snapshot();
        assert!(snapshot.service_started, "{label}: service entry");
        assert_eq!(
            snapshot.repository_started,
            staged || bound,
            "{label}: SQL selection"
        );
        assert_eq!(
            snapshot.returned,
            Some(reply.publication_return(returned)),
            "{label}: actual raw return observed"
        );
        assert_eq!(
            snapshot.return_matches, matches,
            "{label}: return integrity"
        );
        assert_eq!(
            snapshot.publication,
            if !staged && !bound {
                Knowledge::NotRequired
            } else if commit {
                Knowledge::ReceiptKnown(stored)
            } else {
                Knowledge::BeforeCommit
            },
            "{label}: commit knowledge"
        );
        let expected = if staged || bound {
            vec![Call::Publish(
                receipt.publication_identity(),
                staged.then(stage),
                binding,
            )]
        } else {
            vec![]
        };
        assert_eq!(
            *service.repository.calls.lock().unwrap(),
            expected,
            "{label}: exact publication input"
        );
        Reply::Integrity.check(
            &service
                .publish_credential_commit_observed(&invocation)
                .await,
            label,
        );
        assert_eq!(
            *service.repository.calls.lock().unwrap(),
            expected,
            "{label}: duplicate cannot fall back"
        );
        assert_eq!(
            observation.snapshot(),
            snapshot,
            "{label}: duplicate preserves original observation"
        );
    }

    for (label, reply) in [
        ("FAST exact receipt", Reply::Success),
        ("FAST unknown credentials", Reply::Unknown),
        ("FAST disabled", Reply::Disabled),
        ("FAST stale generation", Reply::Stale),
        ("FAST expired", Reply::Expired),
        ("FAST replayed", Reply::Replayed),
        ("FAST integrity failure", Reply::Integrity),
        ("FAST backend error identity", Reply::Backend),
    ] {
        for (mode, observed, contradict) in [
            ("entry compatibility", false, false),
            ("observed return", true, false),
            ("contradictory receipt", true, true),
        ] {
            let prepared = publication::PreparedCredential::new(
                Uuid::from_u128(5),
                stage().connection_id,
                0,
                CredentialKind::UnboundFast,
            );
            let observation = prepared.observation();
            let plan = FastCommitPlan {
                token_id: Some(Uuid::from_u128(6)),
                token_was_new: true,
                invalidate: true,
                issue: Some(FastTokenIssue {
                    device_id: stage().device_id,
                    mechanism: "HT-SHA-256-NONE".to_owned(),
                    ttl_days: 9,
                    strong_reauth_max_days: 3,
                    inherited_chain: Some((
                        chrono::DateTime::from_timestamp(1_600_000_000, 0).unwrap(),
                        chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                    )),
                }),
            };
            let mut repository = Repository::new(reply);
            repository.credential = Some(observation.clone());
            repository.contradict_receipt = contradict;
            let service = service(repository);
            let result = service
                .commit_fast_with_login_epoch_observed(
                    stage().user_id,
                    stage().auth_generation,
                    &plan,
                    Some(stage().device_id),
                    stage().connection_id,
                    observed.then_some(&prepared),
                )
                .await;
            reply.check(&result, label);
            assert_eq!(
                *service.repository.calls.lock().unwrap(),
                vec![Call::Fast {
                    observed,
                    user: stage().user_id,
                    generation: stage().auth_generation,
                    plan: plan.clone(),
                    device: Some(stage().device_id),
                    connection: stage().connection_id,
                }],
                "{label}/{mode}: original command and selected entry"
            );
            let snapshot = observation.snapshot();
            assert_eq!(
                snapshot.service_started, observed,
                "{label}/{mode}: service entry"
            );
            assert_eq!(
                snapshot.repository_started, observed,
                "{label}/{mode}: repository entry"
            );
            assert_eq!(
                snapshot.returned,
                observed.then(|| reply.credential_return()),
                "{label}/{mode}: raw return recorded"
            );
            if let AuthenticationResult::Authenticated(mut receipt) = result {
                assert_eq!(
                    Some(receipt.publication_identity()),
                    *service.repository.returned_receipt.lock().unwrap(),
                    "{label}/{mode}: exact returned instance"
                );
                assert_eq!(
                    receipt.staged_login_epoch(),
                    Some(stage()),
                    "{label}/{mode}: receipt fields"
                );
                assert_eq!(
                    receipt.binding_publication(),
                    None,
                    "{label}/{mode}: unbound receipt"
                );
                let issued = receipt
                    .take_issued_fast()
                    .expect("raw returned FAST bearer");
                assert_eq!(
                    issued.token.as_str(),
                    "FAST-returned-bearer-sentinel",
                    "{label}/{mode}: original bearer"
                );
                assert_eq!(
                    issued.expires_at,
                    chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                    "{label}/{mode}: original bearer expiry"
                );
                if observed {
                    assert_eq!(
                        snapshot.return_matches, !contradict,
                        "{label}/{mode}: identity checked"
                    );
                    assert_eq!(
                        prepared
                            .transfer(&receipt, Uuid::from_u128(5), stage().connection_id)
                            .is_ok(),
                        !contradict,
                        "{label}/{mode}: mismatch cannot become compatibility"
                    );
                }
            }
            if observed {
                Reply::Integrity.check(
                    &service
                        .commit_fast_with_login_epoch_observed(
                            stage().user_id,
                            stage().auth_generation,
                            &plan,
                            Some(stage().device_id),
                            stage().connection_id,
                            Some(&prepared),
                        )
                        .await,
                    label,
                );
                assert_eq!(
                    service.repository.calls.lock().unwrap().len(),
                    1,
                    "{label}/{mode}: duplicate does not use compatibility"
                );
            }
        }
    }
    let prepared = publication::PreparedCredential::new(
        Uuid::from_u128(5),
        stage().connection_id,
        0,
        CredentialKind::Binding,
    );
    let service = service(Repository::new(Reply::Success));
    Reply::Integrity.check(
        &service
            .commit_fast_with_login_epoch_observed(
                stage().user_id,
                stage().auth_generation,
                &FastCommitPlan::default(),
                Some(stage().device_id),
                stage().connection_id,
                Some(&prepared),
            )
            .await,
        "wrong prepared kind",
    );
    assert!(
        service.repository.calls.lock().unwrap().is_empty(),
        "wrong prepared kind: no repository or compatibility call"
    );
}
