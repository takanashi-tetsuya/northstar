//! Protocol tests and Stage 4 harnesses of the root's `ProtocolSession<ServerNode>`. The session core and the
//! client IQ route table are in `northstar_stream::protocol`.

pub(crate) mod federated_muc;
pub(crate) mod messaging;
pub(crate) mod mix;
pub(crate) mod muc;

pub(crate) use northstar_stream::protocol::*;
