//! Construct TLS reload authority for committed administrator operations.

use crate::node::ServerNode;
use northstar_operations_application::tls_reload::OperationTlsReloadEffects;
use std::sync::Arc;

impl ServerNode {
    pub(crate) fn operation_tls_reload_effects(&self) -> OperationTlsReloadEffects {
        OperationTlsReloadEffects::new(self.tls_context.clone(), Arc::clone(&self.metrics))
    }
}
