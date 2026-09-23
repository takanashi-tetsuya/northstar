//! The only rated-message admission authority exposed to XMPP routing.
//! Beginning consumes proof and reserves a durable lease before routing;
//! accepting fences that lease only after a route has accepted the message.
use crate::abuse::{MessageAdmissionLease, MessageAdmissionRequest, MessageAdmissionStart};
use anyhow::Result;

pub(crate) trait MessageAdmissionRepository: Send + Sync {
    fn begin(
        &self,
        request: &MessageAdmissionRequest<'_>,
    ) -> impl std::future::Future<Output = Result<MessageAdmissionStart>> + Send;

    fn accept(
        &self,
        lease: &MessageAdmissionLease,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Clone)]
pub(crate) struct MessageAdmissionService<R> {
    repository: R,
}

impl<R: MessageAdmissionRepository> MessageAdmissionService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn begin_message_admission(
        &self,
        request: &MessageAdmissionRequest<'_>,
    ) -> Result<MessageAdmissionStart> {
        self.repository.begin(request).await
    }

    pub(crate) async fn accept_message_admission(
        &self,
        lease: &MessageAdmissionLease,
    ) -> Result<()> {
        self.repository.accept(lease).await
    }
}
