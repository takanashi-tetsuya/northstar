//! Actual ReplayService delegation over finite supplied repository receipts.
use super::*;
use crate::outbound::DurableDelivery;
use crate::services::replay::*;
use chrono::{DateTime, Utc};
use northstar_delivery_core::bosh_ownership::response::{
    self as response, AckRequest, BindRequest, DeletedSource, RenewRequest,
};
use std::sync::Mutex;
#[derive(Clone)]
pub(super) struct Repository {
    pub(super) session: Uuid,
    pub(super) ordinal: u8,
    pub(super) bind: wire::BoshReply,
    pub(super) ack: Option<wire::BoshAckInput>,
    pub(super) recorder: Capture,
    pub(super) used: Arc<Mutex<[bool; 3]>>,
}
impl Repository {
    fn entered(&self, slot: usize, session: Uuid) -> Result<()> {
        ensure!(session == self.session, "BOSH repository session mismatch");
        let mut used = self.used.lock().unwrap();
        ensure!(!used[slot], "finite BOSH repository call repeated");
        used[slot] = true;
        Ok(())
    }
    fn unsupported(&self) -> anyhow::Error {
        observed::lost(&self.recorder);
        anyhow::anyhow!("repository operation outside finite BOSH bridge")
    }
}
impl ReplayLeaseRepository for Repository {
    async fn username(&self, _: Uuid) -> Result<Option<String>> {
        Err(self.unsupported())
    }
    async fn acquire_lease(
        &self,
        _: Uuid,
        _: &str,
        _: Uuid,
        _: Option<DateTime<Utc>>,
        _: i64,
    ) -> Result<OfflineReplayLeaseAcquire> {
        Err(self.unsupported())
    }
}
impl ReplayRepository for Repository {
    async fn claim_page(
        &self,
        _: &ReplaySession,
        _: Option<&str>,
        _: bool,
        _: i64,
    ) -> Result<ReplayPageOutcome> {
        Err(self.unsupported())
    }
    async fn renew_before_send(&self, _: &ReplaySession, _: Uuid, _: &[Uuid]) -> Result<bool> {
        Err(self.unsupported())
    }
    async fn release_unsent(&self, _: &ReplaySession, _: Uuid, _: &[Uuid]) -> Result<u64> {
        Err(self.unsupported())
    }
    async fn finish(&self, _: &ReplaySession) -> Result<bool> {
        Err(self.unsupported())
    }
    async fn pending_presence_page(
        &self,
        _: Uuid,
        _: &str,
        _: Option<&str>,
        _: Option<&PendingPresenceCursor>,
        _: &str,
    ) -> Result<PendingPresencePage> {
        Err(self.unsupported())
    }
    async fn fence_socket_write(&self, _: DurableDelivery) -> Result<DurableDelivery> {
        Err(self.unsupported())
    }
    async fn acknowledge_socket_write(
        &self,
        _: DurableDelivery,
        _: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> Result<()> {
        Err(self.unsupported())
    }
    async fn renew_bosh_fences(&self, request: &RenewRequest) -> Result<()> {
        self.entered(1, request.session_id())?;
        request.validate_for_io()?;
        let ack = self.ack.as_ref().ok_or_else(|| self.unsupported())?;
        let emit = |returned| {
            observed::observe(&self.recorder, || {
                Ok(wire::Fact::Bosh(wire::BoshFact::Renew(
                    wire::BoshRenewCall {
                        owner_ordinal: self.ordinal,
                        expected: facts::expected(request.expected())?,
                        returned: observed::nullable(returned),
                    },
                )))
            });
        };
        emit(None);
        let result = response::renew_commit_observed(commit(ack.renewal), request).await;
        emit(Some(result.is_ok()));
        result.map_err(|e| anyhow::anyhow!("supplied BOSH renewal: {e:?}"))
    }
    async fn acknowledge_bosh_responses(&self, request: &AckRequest) -> Result<()> {
        self.entered(2, request.session_id())?;
        request.validate_for_io()?;
        let ack = self.ack.as_ref().ok_or_else(|| self.unsupported())?;
        ensure!(
            request.rid() == ack.acknowledged_rid,
            "ACK request differs from finite repository reply"
        );
        let emit = |returned| {
            observed::emit(
                &self.recorder,
                wire::Fact::Bosh(wire::BoshFact::Ack(wire::BoshAckCall {
                    owner_ordinal: self.ordinal,
                    rid: request.rid(),
                    returned: observed::nullable(returned),
                })),
            )
        };
        emit(None);
        let deleted = crate::outbound::MixDelivery {
            delivery_id: ack.deleted.delivery_id.0,
            lease_token: ack.deleted.lease_token.0,
        };
        let result = response::ack_commit_observed(
            commit(ack.commit),
            request,
            vec![DeletedSource::Mix(deleted)],
        )
        .await;
        emit(Some(result.is_ok()));
        result.map_err(|e| anyhow::anyhow!("supplied BOSH ACK: {e:?}"))
    }
    async fn bind_bosh_response_sources(
        &self,
        request: &BindRequest,
    ) -> Result<BoshResponseOwnership> {
        self.entered(0, request.session_id())?;
        request.validate_for_io()?;
        let emit = |returned_membership| {
            observed::observe(&self.recorder, || {
                Ok(wire::Fact::Bosh(wire::BoshFact::Bind(wire::BoshBindCall {
                    owner_ordinal: self.ordinal,
                    rid: request.rid(),
                    sources: wire::List::new(
                        request
                            .sources()
                            .iter()
                            .copied()
                            .map(observed::source)
                            .collect(),
                    )?,
                    returned_membership,
                })))
            });
        };
        emit(wire::Nullable::Null(()));
        // Membership is the independently supplied repository result. The
        // production bound continuation validates it against actual selection.
        let membership = BoshResponseOwnership {
            c2s_message_ids: self
                .bind
                .membership
                .c2s_message_ids
                .as_slice()
                .iter()
                .map(|id| id.0)
                .collect(),
            mix_delivery_ids: self
                .bind
                .membership
                .mix_delivery_ids
                .as_slice()
                .iter()
                .map(|id| id.0)
                .collect(),
        };
        response::bind_commit_observed(commit(self.bind.commit), request, membership.clone())
            .await
            .map_err(|e| anyhow::anyhow!("supplied BOSH binding: {e:?}"))?;
        if let Some(projected) =
            observed::project(&self.recorder, || facts::membership(&membership))
        {
            emit(wire::Nullable::Value(projected));
        }
        Ok(membership)
    }
    async fn release_bosh_fences(&self, _: Uuid) -> Result<()> {
        Err(self.unsupported())
    }
}
async fn commit(cut: wire::CommitCut) -> std::io::Result<()> {
    match cut {
        wire::CommitCut::Complete => Ok(()),
        wire::CommitCut::Pending => std::future::pending().await,
        wire::CommitCut::Error => Err(std::io::Error::other("supplied BOSH COMMIT error")),
    }
}
