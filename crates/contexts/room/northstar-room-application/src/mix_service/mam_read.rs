//! Authorized MIX archive reads and durable federated replies.

use super::*;

#[derive(Debug)]
pub struct MixMamReadCommand {
    pub target: MixMamReadTarget,
    pub actor: MixMamReadActor,
    pub operation: MixMamReadOperation,
}

#[derive(Debug)]
pub struct MixMamReadTarget {
    pub service_domain: String,
    pub localpart: String,
}

#[derive(Debug)]
pub enum MixMamReadActor {
    Local {
        account_id: Uuid,
        username: String,
        auth_generation: i64,
        local_domain: String,
    },
    Federated {
        bare_jid: String,
    },
}

#[derive(Debug)]
pub enum MixMamReadOperation {
    /// Empty form requests and authorization before reporting a parse error.
    Form,
    Metadata,
    Query(MamArchiveQuery),
}

#[derive(Debug)]
pub enum MixMamReadOutcome {
    MissingChannel,
    NotAuthorized {
        channel_jid: String,
    },
    StaleAccount,
    Authorized {
        channel_jid: String,
        result: MixMamReadResult,
    },
}

#[derive(Debug)]
pub enum MixMamReadResult {
    Form,
    Boundaries(Option<ArchiveBoundary>, Option<ArchiveBoundary>),
    Page(MixMamPage),
    MissingReference,
}

#[derive(Debug)]
pub enum MixMamAdmissionOutcome {
    Queued,
    OutboxRejected(anyhow::Error),
}

pub trait MixMamReadRepository: Send + Sync {
    /// Resolve the session's account incarnation and read its visible archive.
    fn read_mix_mam(
        &self,
        command: MixMamReadCommand,
    ) -> impl std::future::Future<Output = Result<MixMamReadOutcome>> + Send;

    /// Resolve the authenticated federated actor and commit the rendered batch
    /// while holding channel authority.
    fn admit_federated_mix_mam(
        &self,
        command: MixMamReadCommand,
        target_domain: &str,
        policy: S2sOutboxPolicy,
        render: impl FnOnce(MixMamReadOutcome) -> Result<Vec<String>> + Send,
    ) -> impl std::future::Future<Output = Result<MixMamAdmissionOutcome>> + Send;
}

impl<R: MixRepository> MixService<R> {
    pub async fn read_mix_mam(&self, command: MixMamReadCommand) -> Result<MixMamReadOutcome> {
        self.repository.read_mix_mam(command).await
    }

    pub async fn admit_federated_mix_mam(
        &self,
        command: MixMamReadCommand,
        target_domain: &str,
        policy: S2sOutboxPolicy,
        render: impl FnOnce(MixMamReadOutcome) -> Result<Vec<String>> + Send,
    ) -> Result<MixMamAdmissionOutcome> {
        self.repository
            .admit_federated_mix_mam(command, target_domain, policy, render)
            .await
    }
}
