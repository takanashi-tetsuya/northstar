use super::RoutePort;
use northstar_message_application::messaging::ExactMessageRoutePort;

impl ExactMessageRoutePort for RoutePort<'_> {}
