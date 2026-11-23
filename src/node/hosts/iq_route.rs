//! The node's context handler bindings for the stream-owned client IQ table.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_archive_xmpp::MamHandlers;
use northstar_message_xmpp::ExtDiscoHandlers;
use northstar_muc_xmpp::MucHandlers;
use northstar_pubsub_xmpp::{PepHandlers, PrivateXmlHandlers, PubSubHandlers, VCardHandlers};
use northstar_roster_xmpp::{BlockingHandlers, PrivacyHandlers, RosterHandlers};
use northstar_stream::protocol::dispatch::route::ClientIqRoute;
use northstar_stream::protocol::iq_routes::{build_routes, IqRouteHost};
use northstar_stream::protocol::ProtocolSession;
use northstar_stream::transport::Action;
use northstar_stream::{IqRequest, IqRouter};
use northstar_upload_xmpp::UploadHandlers;
use std::sync::LazyLock;

pub(in crate::node) static IQ_ROUTES: LazyLock<IqRouter<ClientIqRoute<ServerNode>>> =
    LazyLock::new(build_routes::<ServerNode>);

impl IqRouteHost for ServerNode {
    fn muc_time_sources(&self) -> &northstar_room_core::MucTimeSources {
        northstar_muc_xmpp::ports::MucHost::muc_time_sources(self)
    }

    fn xmpp_version_includes_os(&self) -> bool {
        self.config.xep_0092_include_os
    }

    fn server_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn is_local_muc_room(value: &str, expected_domain: &str) -> bool {
        northstar_muc_xmpp::muc::canonical_local_muc_room(value, expected_domain).is_some()
    }

    async fn command(session: &ProtocolSession<Self>, request: IqRequest<'_>) -> Result<Action> {
        northstar_operations_xmpp::commands::handle(
            session,
            request.id,
            request.stanza,
            request.payload,
        )
        .await
        .map(Action::Send)
    }

    async fn roster_get(
        session: &mut ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .roster_get(request.id, request.stanza, request.payload)
            .await
    }

    async fn roster_set(session: &ProtocolSession<Self>, request: IqRequest<'_>) -> Result<Action> {
        session
            .roster_set(request.id, request.stanza, request.payload)
            .await
    }

    async fn muc_owner_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session.muc_owner_get(request.id, request.stanza).await
    }

    async fn muc_owner_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .muc_owner_set(request.id, request.stanza, request.payload)
            .await
    }

    async fn muc_admin_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .muc_admin_get(request.id, request.stanza, request.payload)
            .await
    }

    async fn muc_admin_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .muc_admin_set(request.id, request.stanza, request.payload)
            .await
    }

    async fn muc_moderate(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .muc_moderate(request.id, request.stanza, request.payload)
            .await
    }

    async fn vcard_get(session: &ProtocolSession<Self>, request: IqRequest<'_>) -> Result<Action> {
        session.vcard_get(request.id, request.stanza).await
    }

    async fn vcard_set(session: &ProtocolSession<Self>, request: IqRequest<'_>) -> Result<Action> {
        session
            .vcard_set(request.id, request.stanza, request.payload, request.raw)
            .await
    }

    async fn private_get(
        session: &mut ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .private_get(request.id, request.stanza.attribute("to"), request.payload)
            .await
    }

    async fn private_set(
        session: &mut ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .private_set(
                request.id,
                request.stanza.attribute("to"),
                request.payload,
                request.raw,
            )
            .await
    }

    async fn privacy_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .privacy_get(request.id, request.stanza, request.payload)
            .await
    }

    async fn privacy_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .privacy_set(request.id, request.stanza, request.payload)
            .await
    }

    fn external_services(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session.external_services(request.id, request.stanza, request.payload)
    }

    fn external_credentials(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session.external_credentials(request.id, request.stanza, request.payload)
    }

    async fn mam_query_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .mam(request.id, request.payload, request.stanza.attribute("to"))
            .await
    }

    async fn mam_query_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .mam_query_form(request.id, request.stanza.attribute("to"), request.payload)
            .await
    }

    async fn mam_metadata(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .mam_metadata(request.id, request.stanza.attribute("to"), request.payload)
            .await
    }

    async fn mam_prefs_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .mam_preferences_get(request.id, request.stanza.attribute("to"), request.payload)
            .await
    }

    async fn mam_prefs_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .mam_preferences_set(request.id, request.stanza.attribute("to"), request.payload)
            .await
    }

    async fn blocklist(session: &ProtocolSession<Self>, request: IqRequest<'_>) -> Result<Action> {
        session
            .blocklist(request.id, request.stanza, request.payload)
            .await
    }

    async fn block(session: &ProtocolSession<Self>, request: IqRequest<'_>) -> Result<Action> {
        session
            .block(request.id, request.stanza, request.payload)
            .await
    }

    async fn unblock(session: &ProtocolSession<Self>, request: IqRequest<'_>) -> Result<Action> {
        session
            .unblock(request.id, request.stanza, request.payload)
            .await
    }

    async fn http_upload_slot(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .http_upload_slot(request.id, request.stanza.attribute("to"), request.payload)
            .await
    }

    async fn pubsub_iq_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .pubsub_iq_set_with_optional_to(
                request.id,
                request.payload,
                request.stanza.attribute("to"),
            )
            .await
    }

    async fn pep_publish(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .pep_publish(request.id, request.stanza, request.payload, request.raw)
            .await
    }

    async fn pubsub_iq_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session.pubsub_iq_get(request.id, request.payload).await
    }

    async fn pep_get(session: &ProtocolSession<Self>, request: IqRequest<'_>) -> Result<Action> {
        session
            .pep_get(request.id, request.stanza, request.payload)
            .await
    }

    async fn muc_register_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session.muc_register_get(request.id, request.stanza).await
    }

    async fn muc_register_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .muc_register_set(request.id, request.stanza, request.payload)
            .await
    }

    async fn pubsub_owner_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session.pubsub_owner_set(request.id, request.payload).await
    }

    async fn pep_owner_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .pep_owner_set(request.id, request.stanza, request.payload)
            .await
    }

    async fn pubsub_owner_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session.pubsub_owner_get(request.id, request.payload).await
    }

    async fn pep_owner_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action> {
        session
            .pep_owner_get(request.id, request.stanza, request.payload)
            .await
    }
}
