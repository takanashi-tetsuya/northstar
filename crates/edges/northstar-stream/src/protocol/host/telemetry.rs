/// Telemetry recorded by protocol sessions.
pub trait SessionTelemetryHost: Send + Sync + 'static {
    /// See `ServerNode::c2s_authentication_telemetry`.
    fn c2s_authentication_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::C2sAuthenticationTelemetry<'_>;
    /// See `ServerNode::c2s_post_action_telemetry`.
    fn c2s_post_action_telemetry(
        &self,
    ) -> northstar_session_application::post_actions::PostActionTelemetry<'_>;
    /// See `ServerNode::outbound_stanza_telemetry`.
    fn outbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::OutboundStanzaTelemetry<'_>;
    /// See `ServerNode::push_subscription_telemetry`.
    fn push_subscription_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::PushSubscriptionTelemetry<'_>;
    /// See `ServerNode::record_bosh_session_closed`.
    fn record_bosh_session_closed(&self);
    /// See `ServerNode::record_c2s_backpressure_disconnect`.
    fn record_c2s_backpressure_disconnect(&self);
    /// See `ServerNode::registration_telemetry`.
    fn registration_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::RegistrationTelemetry<'_>;
    /// See `ServerNode::sasl2_authentication_telemetry`.
    fn sasl2_authentication_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::Sasl2AuthenticationTelemetry<'_>;
    /// See `ServerNode::sasl2_authentication_timer`.
    fn sasl2_authentication_timer(&self) -> northstar_telemetry::metrics::OwnedDurationTimer;
    /// See `ServerNode::session_bind_telemetry`.
    fn session_bind_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionBindTelemetry<'_>;
    /// See `ServerNode::session_drop_fallback_telemetry`.
    fn session_drop_fallback_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SessionDropFallbackTelemetry<'_>;
    /// See `ServerNode::sm_session_telemetry`.
    fn sm_session_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::SmSessionTelemetry<'_>;
    /// See `ServerNode::caps_effect_telemetry`.
    fn caps_effect_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::CapsEffectTelemetry<'_>;
    /// See `ServerNode::push_delivery_telemetry`.
    fn push_delivery_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::PushDeliveryTelemetry<'_>;
    /// See `ServerNode::inbound_stanza_telemetry`.
    fn inbound_stanza_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::InboundStanzaTelemetry<'_>;
    /// See `ServerNode::account_abuse_telemetry`.
    fn account_abuse_telemetry(
        &self,
    ) -> northstar_session_application::telemetry::AccountAbuseTelemetry<'_>;
}
