use super::{Port, RecordingRoute};
use crate::messaging::ExactMessageRoutePort;

impl ExactMessageRoutePort for Port {}
impl ExactMessageRoutePort for RecordingRoute {}
