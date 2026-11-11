//! BOSH records each response item through the session's stream management before the item joins a response.

use super::{ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_bosh::RecordPort;
use northstar_stream::outbound::OutboundItem;

impl<H: SessionHost> RecordPort for ProtocolSession<H> {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.record_outbound_item(item).await
    }
}
