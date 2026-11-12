//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`.

use crate::vcard::VCardSession;
use crate::PubSubSessionHost;
use anyhow::Result;
use northstar_pubsub_application::private_storage::{
    PrivateStorageRepository, PrivateStorageService,
};
use northstar_pubsub_application::profile::ProfileAudienceSnapshot;
use northstar_pubsub_application::profile::{ProfileRepository, ProfileService};
use northstar_pubsub_application::PubSubService;
use northstar_pubsub_core::PepAudienceSnapshot;
use northstar_pubsub_core::{PepQuotas, PubSubAccount};
use northstar_stream::protocol::{ProtocolSession, SessionHost};

// From src/xmpp/protocol/pep.rs.
impl<H: SessionHost + PubSubSessionHost> crate::pep::PepSession for ProtocolSession<H> {
    fn pep_account(&self) -> Option<PubSubAccount> {
        self.authenticated.as_ref().map(|user| PubSubAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn pep_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn pep_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn pep_local_domain(&self) -> &str {
        self.host().pubsub_local_domain()
    }

    fn pep_quotas(&self) -> PepQuotas {
        self.host().pep_account_quotas()
    }

    fn pep_pubsub_service(&self) -> &PubSubService<impl crate::PubSubRepositories> {
        self.host().pubsub_application_service()
    }

    fn pep_profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        self.host().profile_service()
    }

    fn pep_audience_routing(&self) -> &impl crate::pep::PepAudienceRouting {
        &**self.host()
    }

    fn pep_record_published(&self, count: u64) {
        self.host().pep_record_published(count);
    }

    fn pep_record_retracted(&self, count: u64) {
        self.host().pep_record_retracted(count);
    }

    fn pep_record_retrieved(&self) {
        self.host().pep_record_retrieved();
    }

    fn pep_refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        self.host().refresh_avatar_presence(owner_bare, hash);
    }
}

// From src/xmpp/protocol/private.rs.
impl<H: SessionHost + PubSubSessionHost> crate::private_xml::PrivateXmlSession
    for ProtocolSession<H>
{
    fn private_account(&self) -> Option<northstar_pubsub_core::PubSubAccount> {
        self.authenticated
            .as_ref()
            .map(|user| northstar_pubsub_core::PubSubAccount {
                id: user.id,
                username: user.username.clone(),
                auth_generation: user.auth_generation,
            })
    }

    fn private_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn private_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn private_local_domain(&self) -> &str {
        self.host().pubsub_local_domain()
    }

    fn private_storage_service(&self) -> &PrivateStorageService<impl PrivateStorageRepository> {
        self.host().private_storage_service()
    }

    fn private_pubsub_service(&self) -> &PubSubService<impl crate::PubSubRepositories> {
        self.host().pubsub_application_service()
    }

    fn private_pep_audience_messages(
        &self,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &PepAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        crate::pep::pep_audience_messages(&**self.host(), publisher_full_jid, node, event, audience)
    }
}

// From src/xmpp/protocol/vcard.rs.
impl<H: SessionHost + PubSubSessionHost> VCardSession for ProtocolSession<H> {
    fn vcard_account(&self) -> Option<PubSubAccount> {
        self.authenticated.as_ref().map(|user| PubSubAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        })
    }

    fn vcard_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn vcard_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn vcard_local_domain(&self) -> &str {
        self.host().pubsub_local_domain()
    }

    fn vcard_pep_quotas(&self) -> PepQuotas {
        self.host().pep_account_quotas()
    }

    fn vcard_profile_service(&self) -> &ProfileService<impl ProfileRepository> {
        self.host().profile_service()
    }

    fn vcard_profile_audience_messages(
        &self,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &ProfileAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        crate::pep::profile_audience_messages(
            &**self.host(),
            publisher_full_jid,
            node,
            event,
            audience,
        )
    }

    fn vcard_refresh_avatar_presence(&self, owner_bare: &str, hash: Option<&str>) {
        self.host().refresh_avatar_presence(owner_bare, hash);
    }
}
