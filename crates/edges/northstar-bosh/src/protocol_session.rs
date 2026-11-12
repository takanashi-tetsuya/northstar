//! BOSH records each response item through the session's stream management before the item joins a response.

use crate::RecordPort;
use anyhow::Result;
use northstar_stream::outbound::OutboundItem;
use northstar_stream::protocol::{ProtocolSession, SessionHost};

impl<H: SessionHost> RecordPort for ProtocolSession<H> {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.record_outbound_item(item).await
    }
}
