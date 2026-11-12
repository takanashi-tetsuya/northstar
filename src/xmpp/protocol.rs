//! The root's half of the client protocol session: the context glue over [`ClientSession`] and the client
//! IQ route table. The session core is `northstar_stream::protocol`.

pub(crate) mod discovery;
pub(crate) mod federated_muc;
pub(crate) mod iq_routes;
pub(crate) mod messaging;
pub(crate) mod mix;
pub(crate) mod muc;

use crate::state::AppState;
pub(crate) use northstar_stream::protocol::*;
use northstar_stream::transport::Action;

/// The protocol session of the root's own host.
pub(crate) type ClientSession = ProtocolSession<AppState>;
