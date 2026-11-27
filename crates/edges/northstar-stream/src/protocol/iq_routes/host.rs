//! Context handler bindings needed by the client IQ route table.

use super::super::discovery::DiscoveryHost;
use super::super::ProtocolSession;
use crate::transport::Action;
use crate::IqRequest;
use anyhow::Result;
use std::future::Future;

/// The context adapters the route table cannot call directly because those
/// adapters depend on stream. Routing decisions stay in this crate.
pub trait IqRouteHost: DiscoveryHost {
    fn muc_time_sources(&self) -> &northstar_room_core::MucTimeSources;
    fn xmpp_version_includes_os(&self) -> bool;
    fn server_version(&self) -> &str;
    fn is_local_muc_room(value: &str, expected_domain: &str) -> bool;

    fn command(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn roster_get(
        session: &mut ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn roster_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn muc_owner_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn muc_owner_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn muc_admin_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn muc_admin_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn muc_moderate(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn vcard_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn vcard_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn private_get(
        session: &mut ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn private_set(
        session: &mut ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn privacy_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn privacy_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn external_services(session: &ProtocolSession<Self>, request: IqRequest<'_>)
        -> Result<Action>;

    fn external_credentials(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> Result<Action>;

    fn mam_query_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn mam_query_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn mam_metadata(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn mam_prefs_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn mam_prefs_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn blocklist(
        session: &mut ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn block(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn unblock(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn http_upload_slot(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn pubsub_iq_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn pep_publish(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn pubsub_iq_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn pep_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn muc_register_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn muc_register_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn pubsub_owner_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn pep_owner_set(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn pubsub_owner_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;

    fn pep_owner_get(
        session: &ProtocolSession<Self>,
        request: IqRequest<'_>,
    ) -> impl Future<Output = Result<Action>> + Send;
}
