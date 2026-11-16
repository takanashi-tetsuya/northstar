//! `ServerNode` methods for suspended SM MUC endpoints that need the cluster or the SM suspension context; the
//! endpoint predicates, pause/resume transitions and buffer operations are in northstar-stream's
//! `local_routes::suspended_muc`.

use crate::node::*;

impl ServerNode {
    pub async fn mark_suspended_muc_durable(
        &self,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    ) -> bool {
        self.sm_suspension_context()
            .mark_suspended_muc_durable(endpoints)
            .await
    }

    pub async fn seal_suspended_muc_endpoints(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        self.sm_suspension_context()
            .seal_suspended_muc_endpoints(endpoints)
            .await
    }
}
