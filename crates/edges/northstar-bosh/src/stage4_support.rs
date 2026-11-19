//! What northstar-test-harness's saved_replay integration target drives BOSH through: the response owner,
//! the ownership runner and the request and response values it replays. Compiled for tests and the
//! `test-support` feature only.

pub mod ownership {
    pub use crate::ownership::{
        record_and_push, OperationRunner, Output, RecordPort, RecordPushError, ServiceTransfer,
        TransferPort,
    };
}

pub mod response_owner {
    pub use crate::response_owner::*;
}

pub use crate::ownership::sm_record_composition;
pub use crate::request_policy::{parse_body, valid_client_response_ack};
pub use crate::{BoshHttpResponse, BoshRequest, CachedResponse, BOSH_BACKEND_OPERATION_TIMEOUT};
