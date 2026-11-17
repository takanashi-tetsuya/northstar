//! Push notification IQ construction and routing.

use northstar_message_application::push::{
    PushDelivery, PushNotificationCounts, PushNotificationRouter, PushRepository, PushService,
};
use std::future::Future;

pub async fn dispatch_push_notification<R: PushRepository>(
    enabled: bool,
    push_service: &PushService<R>,
    recipient_id: uuid::Uuid,
    router: &impl PushNotificationRouter,
) -> anyhow::Result<()> {
    if !enabled {
        return Ok(());
    }
    push_service
        .dispatch_after_commit(recipient_id, router)
        .await
}

/// Where a push notification can go, bound by the composition root.
pub trait PushNotificationRoutes: Send + Sync {
    fn local_domain(&self) -> &str;
    fn deliver_local(
        &self,
        service_jid: &str,
        notification: &str,
    ) -> impl Future<Output = bool> + Send;
    fn route_cluster(
        &self,
        service_jid: &str,
        notification: &str,
    ) -> impl Future<Output = bool> + Send;
    fn remote_domain_allowed(&self, domain: &str) -> bool;
    fn send_federation(
        &self,
        domain: &str,
        notification: String,
    ) -> impl Future<Output = bool> + Send;
}

pub async fn route_push_notification(
    routes: &impl PushNotificationRoutes,
    delivery: &PushDelivery,
    counts: PushNotificationCounts,
) -> anyhow::Result<bool> {
    let request_id = format!("push-{}", delivery.request_id);
    let summary = northstar_xep_0357::PushSummary::new()
        .with_message_count(counts.message_count as u64)
        .with_pending_subscription_count(counts.pending_subscription_count as u64);
    let notification = northstar_xep_0357::build_notification_iq(
        routes.local_domain(),
        &delivery.service_jid,
        &request_id,
        (!delivery.node.is_empty()).then_some(delivery.node.as_str()),
        &summary,
        delivery.options.as_deref(),
    )?;
    let mut delivered = false;
    let service = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&delivery.service_jid).ok();
    if service
        .as_ref()
        .is_some_and(|jid| jid.domainpart() == routes.local_domain())
    {
        delivered = routes
            .deliver_local(&delivery.service_jid, &notification)
            .await;
        if !delivered {
            delivered = routes
                .route_cluster(&delivery.service_jid, &notification)
                .await;
        }
    } else if let Some(domain) = service.as_ref().map(|jid| jid.domainpart()) {
        if routes.remote_domain_allowed(domain) {
            delivered = routes.send_federation(domain, notification.clone()).await;
        }
    }
    Ok(delivered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_message_application::push::{
        PushBatch, PushEnableOutcome, PushResponseKind, PushResponseOutcome,
    };
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    struct FakePushRepository {
        calls: Arc<Mutex<Vec<&'static str>>>,
        claim_fails: bool,
    }

    impl PushRepository for FakePushRepository {
        async fn enable(
            &self,
            _: Uuid,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> anyhow::Result<PushEnableOutcome> {
            unreachable!()
        }

        async fn disable(&self, _: Uuid, _: &str, _: Option<&str>) -> anyhow::Result<u64> {
            unreachable!()
        }

        async fn claim_batch(&self, user_id: Uuid) -> anyhow::Result<PushBatch> {
            assert_eq!(user_id, Uuid::from_u128(545));
            self.calls.lock().unwrap().push("claim");
            if self.claim_fails {
                anyhow::bail!("claim failed");
            }
            Ok(PushBatch {
                message_count: 7,
                pending_subscription_count: 3,
                deliveries: vec![delivery("push@example.test")],
            })
        }

        async fn mark_unroutable(&self, _: Uuid) -> anyhow::Result<()> {
            unreachable!()
        }

        async fn complete_response(
            &self,
            _: Uuid,
            _: &str,
            _: PushResponseKind,
        ) -> anyhow::Result<PushResponseOutcome> {
            unreachable!()
        }

        async fn disable_from_service(&self, _: &str, _: &str, _: &str) -> anyhow::Result<bool> {
            unreachable!()
        }
    }

    struct RecordingPushRouter {
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl PushNotificationRouter for RecordingPushRouter {
        async fn route(
            &self,
            delivery: &PushDelivery,
            counts: PushNotificationCounts,
        ) -> anyhow::Result<bool> {
            assert_eq!(delivery.request_id, Uuid::from_u128(523));
            assert_eq!(delivery.service_jid, "push@example.test");
            assert_eq!(counts.message_count, 7);
            assert_eq!(counts.pending_subscription_count, 3);
            self.calls.lock().unwrap().push("route");
            Ok(true)
        }

        fn routed(&self) {
            self.calls.lock().unwrap().push("routed");
        }

        fn failed(&self) {
            unreachable!()
        }

        fn attempted(&self) {
            self.calls.lock().unwrap().push("attempted");
        }
    }

    #[tokio::test]
    async fn disabled_push_dispatches_nothing() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let service = PushService::new(FakePushRepository {
            calls: Arc::clone(&calls),
            claim_fails: true,
        });
        let router = RecordingPushRouter {
            calls: Arc::clone(&calls),
        };

        dispatch_push_notification(false, &service, Uuid::from_u128(545), &router)
            .await
            .unwrap();
        assert!(calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn enabled_push_dispatches_once() {
        for claim_fails in [false, true] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let service = PushService::new(FakePushRepository {
                calls: Arc::clone(&calls),
                claim_fails,
            });
            let router = RecordingPushRouter {
                calls: Arc::clone(&calls),
            };

            let result =
                dispatch_push_notification(true, &service, Uuid::from_u128(545), &router).await;
            if claim_fails {
                assert_eq!(result.unwrap_err().to_string(), "claim failed");
                assert_eq!(*calls.lock().unwrap(), vec!["claim"]);
            } else {
                result.unwrap();
                assert_eq!(
                    *calls.lock().unwrap(),
                    vec!["claim", "route", "routed", "attempted"]
                );
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum Call {
        Local(String, String),
        Cluster(String, String),
        Policy(String),
        Federation(String, String),
    }

    #[derive(Default)]
    struct FakeRoutes {
        calls: Mutex<Vec<Call>>,
        local_delivered: bool,
        cluster_delivered: bool,
        remote_allowed: bool,
        federation_delivered: bool,
    }

    impl PushNotificationRoutes for FakeRoutes {
        fn local_domain(&self) -> &str {
            "example.test"
        }

        async fn deliver_local(&self, service_jid: &str, notification: &str) -> bool {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Local(service_jid.to_owned(), notification.to_owned()));
            self.local_delivered
        }

        async fn route_cluster(&self, service_jid: &str, notification: &str) -> bool {
            self.calls.lock().unwrap().push(Call::Cluster(
                service_jid.to_owned(),
                notification.to_owned(),
            ));
            self.cluster_delivered
        }

        fn remote_domain_allowed(&self, domain: &str) -> bool {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Policy(domain.to_owned()));
            self.remote_allowed
        }

        async fn send_federation(&self, domain: &str, notification: String) -> bool {
            self.calls
                .lock()
                .unwrap()
                .push(Call::Federation(domain.to_owned(), notification));
            self.federation_delivered
        }
    }

    fn delivery(service_jid: &str) -> PushDelivery {
        PushDelivery {
            request_id: Uuid::from_u128(523),
            service_jid: service_jid.to_owned(),
            node: String::new(),
            options: None,
        }
    }

    fn counts() -> PushNotificationCounts {
        PushNotificationCounts {
            message_count: 7,
            pending_subscription_count: 3,
        }
    }

    fn notification(delivery: &PushDelivery, node: Option<&str>) -> String {
        let summary = northstar_xep_0357::PushSummary::new()
            .with_message_count(7)
            .with_pending_subscription_count(3);
        northstar_xep_0357::build_notification_iq(
            "example.test",
            &delivery.service_jid,
            &format!("push-{}", delivery.request_id),
            node,
            &summary,
            delivery.options.as_deref(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn local_domain_service_delivered_locally() {
        let routes = FakeRoutes {
            local_delivered: true,
            ..FakeRoutes::default()
        };
        let delivery = delivery("push@example.test");

        assert!(route_push_notification(&routes, &delivery, counts())
            .await
            .unwrap());
        assert_eq!(
            *routes.calls.lock().unwrap(),
            vec![Call::Local(
                delivery.service_jid.clone(),
                notification(&delivery, None),
            )]
        );
    }

    #[tokio::test]
    async fn local_miss_routes_cluster_once_and_returns_result() {
        for result in [false, true] {
            let routes = FakeRoutes {
                cluster_delivered: result,
                ..FakeRoutes::default()
            };
            let delivery = delivery("push@example.test");
            let expected = notification(&delivery, None);

            assert_eq!(
                route_push_notification(&routes, &delivery, counts())
                    .await
                    .unwrap(),
                result
            );
            assert_eq!(
                *routes.calls.lock().unwrap(),
                vec![
                    Call::Local(delivery.service_jid.clone(), expected.clone()),
                    Call::Cluster(delivery.service_jid.clone(), expected),
                ]
            );
        }
    }

    #[tokio::test]
    async fn remote_domain_allowed_sends_federation_once() {
        for result in [false, true] {
            let routes = FakeRoutes {
                remote_allowed: true,
                federation_delivered: result,
                ..FakeRoutes::default()
            };
            let delivery = delivery("push@remote.test");

            assert_eq!(
                route_push_notification(&routes, &delivery, counts())
                    .await
                    .unwrap(),
                result
            );
            assert_eq!(
                *routes.calls.lock().unwrap(),
                vec![
                    Call::Policy("remote.test".to_owned()),
                    Call::Federation("remote.test".to_owned(), notification(&delivery, None)),
                ]
            );
        }
    }

    #[tokio::test]
    async fn remote_domain_denied_does_not_send() {
        let routes = FakeRoutes::default();
        let delivery = delivery("push@remote.test");

        assert!(!route_push_notification(&routes, &delivery, counts())
            .await
            .unwrap());
        assert_eq!(
            *routes.calls.lock().unwrap(),
            vec![Call::Policy("remote.test".to_owned())]
        );
    }

    #[tokio::test]
    async fn invalid_bare_service_jid_does_not_route() {
        for service_jid in ["", "push@example.test/resource", "push@@example.test"] {
            let routes = FakeRoutes::default();
            let delivery = delivery(service_jid);

            assert!(!route_push_notification(&routes, &delivery, counts())
                .await
                .unwrap());
            assert!(routes.calls.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn notification_matches_builder_for_empty_and_nonempty_nodes() {
        for node in [None, Some("device<&'\"")] {
            for options in [
                None,
                Some("<x xmlns='jabber:x:data' type='submit'><field var='secret'><value>a&amp;b</value></field></x>"),
            ] {
                let routes = FakeRoutes {
                    local_delivered: true,
                    ..FakeRoutes::default()
                };
                let mut delivery = delivery("push@example.test");
                delivery.node = node.unwrap_or_default().to_owned();
                delivery.options = options.map(str::to_owned);

                assert!(route_push_notification(&routes, &delivery, counts())
                    .await
                    .unwrap());
                assert_eq!(
                    *routes.calls.lock().unwrap(),
                    vec![Call::Local(
                        delivery.service_jid.clone(),
                        notification(&delivery, node),
                    )]
                );
            }
        }
    }

    #[tokio::test]
    async fn invalid_publish_options_fail_before_routing() {
        let routes = FakeRoutes::default();
        let mut delivery = delivery("push@example.test");
        delivery.options = Some("<x>".to_owned());

        let error = route_push_notification(&routes, &delivery, counts())
            .await
            .unwrap_err();
        let expected = northstar_xep_0357::build_notification_iq(
            "example.test",
            &delivery.service_jid,
            &format!("push-{}", delivery.request_id),
            None,
            &northstar_xep_0357::PushSummary::new(),
            delivery.options.as_deref(),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), expected.to_string());
        assert!(routes.calls.lock().unwrap().is_empty());
    }
}
