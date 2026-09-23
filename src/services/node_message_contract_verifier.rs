//! Verify an inbound cluster message against its authoritative delivery source.

use anyhow::{Context, Result};
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestedNodeMessageProjection {
    Volatile,
    DurableC2s {
        recipient_id: Uuid,
        message_id: Uuid,
    },
    DurableMix {
        delivery_id: Uuid,
        lease_token: Uuid,
    },
    LegacyInference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VerifiedNodeMessageProjection {
    Volatile,
    Durable(crate::outbound::DurableDelivery),
    Mix(crate::outbound::MixDelivery),
}

pub(crate) struct MixDeliveryProjection {
    pub(crate) recipient_jid: String,
    pub(crate) stanza_template: String,
    pub(crate) lease_active: bool,
    pub(crate) event_active: bool,
}

pub(crate) trait NodeMessageProjectionRepository: Send + Sync {
    fn durable_c2s_stanza(
        &self,
        recipient_id: Uuid,
        message_id: Uuid,
    ) -> impl Future<Output = Result<Option<String>>> + Send;

    fn durable_mix_projection(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> impl Future<Output = Result<Option<MixDeliveryProjection>>> + Send;

    fn legacy_c2s_projection(
        &self,
        message_id: Uuid,
    ) -> impl Future<Output = Result<Option<(Uuid, String)>>> + Send;
}

pub(crate) struct NodeMessageContractVerifier<R> {
    repository: R,
}

impl<R: NodeMessageProjectionRepository> NodeMessageContractVerifier<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn resolve(
        &self,
        request: RequestedNodeMessageProjection,
        stanza: &str,
        target_jid: &str,
    ) -> Result<VerifiedNodeMessageProjection> {
        use crate::outbound::{recipient_delivery_identity, RecipientDeliveryIdentity};

        match request {
            RequestedNodeMessageProjection::Volatile => Ok(VerifiedNodeMessageProjection::Volatile),
            RequestedNodeMessageProjection::DurableC2s {
                recipient_id,
                message_id,
            } => {
                anyhow::ensure!(
                    !matches!(
                        recipient_delivery_identity(stanza, target_jid),
                        RecipientDeliveryIdentity::Missing | RecipientDeliveryIdentity::Invalid
                    ),
                    "durable cluster message lacks an unambiguous recipient stanza-id"
                );
                let stored_stanza = self
                    .repository
                    .durable_c2s_stanza(recipient_id, message_id)
                    .await
                    .context("failed to verify clustered durable C2S projection")?
                    .context("cluster durable delivery projection is missing")?;
                anyhow::ensure!(
                    durable_projection_matches(&stored_stanza, stanza),
                    "cluster durable delivery payload does not match its PostgreSQL projection"
                );
                Ok(VerifiedNodeMessageProjection::Durable(
                    crate::outbound::DurableDelivery {
                        recipient_id,
                        message_id,
                        claim_id: None,
                    },
                ))
            }
            RequestedNodeMessageProjection::DurableMix {
                delivery_id,
                lease_token,
            } => {
                anyhow::ensure!(
                    crate::jid::CanonicalJid::parse(target_jid)?
                        .resourcepart()
                        .is_none(),
                    "durable cluster MIX delivery requires a bare target"
                );
                let projection = self
                    .repository
                    .durable_mix_projection(delivery_id, lease_token)
                    .await
                    .context("failed to verify clustered durable MIX projection")?
                    .context("cluster durable MIX delivery projection is missing")?;
                anyhow::ensure!(
                    projection.lease_active && projection.event_active,
                    "cluster durable MIX delivery source is no longer active"
                );
                anyhow::ensure!(
                    crate::jid::canonicalize_bare(&projection.recipient_jid)?
                        == crate::jid::canonicalize_bare(target_jid)?,
                    "cluster durable MIX recipient does not match the target"
                );
                anyhow::ensure!(
                    crate::xmpp::xml_util::set_to(&projection.stanza_template, target_jid)
                        == stanza,
                    "cluster durable MIX payload does not match its PostgreSQL projection"
                );
                Ok(VerifiedNodeMessageProjection::Mix(
                    crate::outbound::MixDelivery {
                        delivery_id,
                        lease_token,
                    },
                ))
            }
            RequestedNodeMessageProjection::LegacyInference => {
                let message_id = match recipient_delivery_identity(stanza, target_jid) {
                    RecipientDeliveryIdentity::Missing => {
                        return Ok(VerifiedNodeMessageProjection::Volatile);
                    }
                    RecipientDeliveryIdentity::Exact(message_id) => message_id,
                    RecipientDeliveryIdentity::Invalid => {
                        anyhow::bail!("legacy cluster delivery identity is ambiguous")
                    }
                };
                let (recipient_id, stored_stanza) = self
                    .repository
                    .legacy_c2s_projection(message_id)
                    .await
                    .context("failed to verify legacy clustered C2S projection")?
                    .context("legacy cluster durable delivery projection is missing")?;
                anyhow::ensure!(
                    durable_projection_matches(&stored_stanza, stanza),
                    "legacy cluster durable delivery payload does not match its PostgreSQL projection"
                );
                Ok(VerifiedNodeMessageProjection::Durable(
                    crate::outbound::DurableDelivery {
                        recipient_id,
                        message_id,
                        claim_id: None,
                    },
                ))
            }
        }
    }
}

pub(crate) fn durable_projection_matches(stored_stanza: &str, routed_stanza: &str) -> bool {
    // Durable rows add a direct server delay marker before routing. Only
    // direct delays may differ; the remaining XML bytes must match exactly.
    crate::xmpp::xml_util::strip_untrusted_direct_delays(stored_stanza, None) == routed_stanza
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct StubRepository {
        calls: Mutex<Vec<&'static str>>,
        c2s: Option<String>,
        mix: Option<MixDeliveryProjection>,
        legacy: Option<(Uuid, String)>,
    }

    impl StubRepository {
        fn empty() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                c2s: None,
                mix: None,
                legacy: None,
            }
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl NodeMessageProjectionRepository for &StubRepository {
        async fn durable_c2s_stanza(
            &self,
            _recipient_id: Uuid,
            _message_id: Uuid,
        ) -> Result<Option<String>> {
            self.calls.lock().unwrap().push("c2s");
            Ok(self.c2s.clone())
        }

        async fn durable_mix_projection(
            &self,
            _delivery_id: Uuid,
            _lease_token: Uuid,
        ) -> Result<Option<MixDeliveryProjection>> {
            self.calls.lock().unwrap().push("mix");
            Ok(self.mix.as_ref().map(|source| MixDeliveryProjection {
                recipient_jid: source.recipient_jid.clone(),
                stanza_template: source.stanza_template.clone(),
                lease_active: source.lease_active,
                event_active: source.event_active,
            }))
        }

        async fn legacy_c2s_projection(&self, _message_id: Uuid) -> Result<Option<(Uuid, String)>> {
            self.calls.lock().unwrap().push("legacy");
            Ok(self.legacy.clone())
        }
    }

    fn stanza(message_id: Uuid) -> String {
        format!(
            "<message to='bob@example.test'><stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.test' id='{message_id}'/><body>hello</body></message>"
        )
    }

    #[tokio::test]
    async fn volatile_and_legacy_without_an_identity_do_not_query_postgres() {
        let repository = StubRepository::empty();
        let verifier = NodeMessageContractVerifier::new(&repository);
        assert_eq!(
            verifier
                .resolve(RequestedNodeMessageProjection::Volatile, "", "")
                .await
                .unwrap(),
            VerifiedNodeMessageProjection::Volatile
        );
        assert_eq!(
            verifier
                .resolve(
                    RequestedNodeMessageProjection::LegacyInference,
                    "<message><body>hello</body></message>",
                    "bob@example.test",
                )
                .await
                .unwrap(),
            VerifiedNodeMessageProjection::Volatile
        );
        assert!(repository.calls().is_empty());
    }

    #[tokio::test]
    async fn invalid_identity_and_full_jid_mix_target_fail_before_database_access() {
        let repository = StubRepository::empty();
        let verifier = NodeMessageContractVerifier::new(&repository);
        let message_id = Uuid::from_u128(1);
        assert!(verifier
            .resolve(
                RequestedNodeMessageProjection::DurableC2s {
                    recipient_id: Uuid::from_u128(2),
                    message_id,
                },
                "<message/>",
                "bob@example.test",
            )
            .await
            .is_err());
        assert!(verifier
            .resolve(
                RequestedNodeMessageProjection::LegacyInference,
                "<message><stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.test' id='bad'/></message>",
                "bob@example.test",
            )
            .await
            .is_err());
        assert!(verifier
            .resolve(
                RequestedNodeMessageProjection::DurableMix {
                    delivery_id: Uuid::from_u128(3),
                    lease_token: Uuid::from_u128(4),
                },
                "<message/>",
                "bob@example.test/Phone",
            )
            .await
            .is_err());
        assert!(repository.calls().is_empty());
    }

    #[tokio::test]
    async fn c2s_requires_the_exact_spooled_payload_after_direct_delay_removal() {
        let message_id = Uuid::from_u128(5);
        let recipient_id = Uuid::from_u128(6);
        let routed = stanza(message_id);
        let stored = crate::xmpp::xml_util::add_delay_from(
            &routed,
            chrono::Utc::now(),
            Some("example.test"),
        );
        let repository = StubRepository {
            c2s: Some(stored),
            ..StubRepository::empty()
        };
        let verifier = NodeMessageContractVerifier::new(&repository);
        assert_eq!(
            verifier
                .resolve(
                    RequestedNodeMessageProjection::DurableC2s {
                        recipient_id,
                        message_id,
                    },
                    &routed,
                    "bob@example.test",
                )
                .await
                .unwrap(),
            VerifiedNodeMessageProjection::Durable(crate::outbound::DurableDelivery {
                recipient_id,
                message_id,
                claim_id: None,
            })
        );
        assert!(verifier
            .resolve(
                RequestedNodeMessageProjection::DurableC2s {
                    recipient_id,
                    message_id,
                },
                &routed.replace("hello", "tampered"),
                "bob@example.test",
            )
            .await
            .is_err());
        assert_eq!(repository.calls(), vec!["c2s", "c2s"]);
    }

    #[tokio::test]
    async fn mix_rejects_expired_lease_and_wrong_recipient_or_payload() {
        let delivery_id = Uuid::from_u128(7);
        let lease_token = Uuid::from_u128(8);
        let request = RequestedNodeMessageProjection::DurableMix {
            delivery_id,
            lease_token,
        };
        let template = "<message to='placeholder@example.test'><body>hello</body></message>";
        let routed = crate::xmpp::xml_util::set_to(template, "bob@example.test");
        let repository = StubRepository {
            mix: Some(MixDeliveryProjection {
                recipient_jid: "bob@example.test".to_owned(),
                stanza_template: template.to_owned(),
                lease_active: false,
                event_active: true,
            }),
            ..StubRepository::empty()
        };
        let verifier = NodeMessageContractVerifier::new(&repository);
        assert!(verifier
            .resolve(request, &routed, "bob@example.test")
            .await
            .is_err());

        let repository = StubRepository {
            mix: Some(MixDeliveryProjection {
                recipient_jid: "mallory@example.test".to_owned(),
                stanza_template: template.to_owned(),
                lease_active: true,
                event_active: true,
            }),
            ..StubRepository::empty()
        };
        let verifier = NodeMessageContractVerifier::new(&repository);
        assert!(verifier
            .resolve(request, &routed, "bob@example.test")
            .await
            .is_err());

        let repository = StubRepository {
            mix: Some(MixDeliveryProjection {
                recipient_jid: "bob@example.test".to_owned(),
                stanza_template: template.to_owned(),
                lease_active: true,
                event_active: true,
            }),
            ..StubRepository::empty()
        };
        let verifier = NodeMessageContractVerifier::new(&repository);
        assert_eq!(
            verifier
                .resolve(request, &routed, "bob@example.test")
                .await
                .unwrap(),
            VerifiedNodeMessageProjection::Mix(crate::outbound::MixDelivery {
                delivery_id,
                lease_token,
            })
        );
        assert!(verifier
            .resolve(
                request,
                &routed.replace("hello", "tampered"),
                "bob@example.test",
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn legacy_identity_requires_a_matching_stored_projection() {
        let message_id = Uuid::from_u128(9);
        let recipient_id = Uuid::from_u128(10);
        let routed = stanza(message_id);
        let repository = StubRepository {
            legacy: Some((recipient_id, routed.clone())),
            ..StubRepository::empty()
        };
        let verifier = NodeMessageContractVerifier::new(&repository);
        assert_eq!(
            verifier
                .resolve(
                    RequestedNodeMessageProjection::LegacyInference,
                    &routed,
                    "bob@example.test",
                )
                .await
                .unwrap(),
            VerifiedNodeMessageProjection::Durable(crate::outbound::DurableDelivery {
                recipient_id,
                message_id,
                claim_id: None,
            })
        );
        assert_eq!(repository.calls(), vec!["legacy"]);
    }
}
