//! The root's context glue over [`ClientSession`]. The session core and client IQ route table are in
//! `northstar_stream::protocol`.

pub(crate) mod federated_muc;
pub(crate) mod messaging;
pub(crate) mod mix;
pub(crate) mod muc;

use crate::state::AppState;
pub(crate) use northstar_stream::protocol::*;
use northstar_stream::transport::Action;

/// The protocol session of the root's own host.
pub(crate) type ClientSession = ProtocolSession<AppState>;
