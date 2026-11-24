use super::*;

const FIXED_SECRET: &str = "fixed coturn test secret";
const FIXED_EPOCH: i64 = 1_700_000_000;

fn configured_service(secret: Option<&str>, limit: usize) -> ExtDiscoService {
    ExtDiscoService::new(
        "example.test".to_owned(),
        Some(("stun.example.test".to_owned(), 3478)),
        Some(("turn.example.test".to_owned(), 3478)),
        secret.map(str::to_owned),
        3_600,
        limit,
    )
}

fn scope<'a>(username: &'a str, full_jid: &'a str) -> ExtDiscoRequestScope<'a> {
    ExtDiscoRequestScope {
        username: Some(username),
        full_jid: Some(full_jid),
        iq_type: Some("get"),
        target: Some("EXAMPLE.test"),
    }
}

fn selector(port: Option<u16>, transport: Option<&str>) -> ServiceIdentity {
    ServiceIdentity {
        host: ServiceHost::parse("TURN.Example.test.").unwrap(),
        service_type: ServiceToken::parse_service_type("turn").unwrap(),
        port: port.and_then(NonZeroU16::new),
        transport: transport.map(|value| ServiceToken::parse_transport(value).unwrap()),
    }
}

fn issue(
    service: &ExtDiscoService,
    scope: ExtDiscoRequestScope<'_>,
    peer_ip: &str,
    selectors: Vec<ServiceIdentity>,
    monotonic: Instant,
) -> ExtDiscoIssuance {
    service
        .issue_credentials(
            ExtDiscoCommand {
                scope,
                request: Some(CredentialsRequest {
                    services: selectors,
                }),
                peer_ip: peer_ip.parse().unwrap(),
            },
            IssuanceTime {
                unix_seconds: FIXED_EPOCH,
                monotonic,
            },
        )
        .unwrap()
}

#[test]
fn list_services_filters_in_configuration_order_without_charging() {
    let service = configured_service(Some(FIXED_SECRET), 1);
    for (filter, expected) in [
        (
            None,
            &[("stun", "udp"), ("turn", "udp"), ("turn", "tcp")][..],
        ),
        (Some("turn"), &[("turn", "udp"), ("turn", "tcp")][..]),
        (Some("unknown"), &[][..]),
    ] {
        let result = service
            .list_services(ExtDiscoQuery {
                scope: scope("alice", "alice@example.test/device"),
                request: Some(ServicesRequest {
                    service_type: filter
                        .map(|value| ServiceToken::parse_service_type(value).unwrap()),
                }),
            })
            .unwrap();
        let ExtDiscoServices::Listed {
            service_type,
            services,
        } = result
        else {
            panic!("expected a service listing");
        };
        assert_eq!(service_type.as_ref().map(ServiceToken::as_str), filter);
        let types_and_transports: Vec<_> = services
            .iter()
            .map(|record| {
                (
                    record.identity.service_type.as_str(),
                    record.identity.transport.as_ref().unwrap().as_str(),
                )
            })
            .collect();
        assert_eq!(types_and_transports.as_slice(), expected);
        for record in services {
            assert_eq!(
                record.restricted,
                record.identity.service_type.as_str() == "turn"
            );
        }
    }
    assert_eq!(service.inner.rate_window_checks.load(Ordering::Relaxed), 0);
}

#[test]
fn unrestricted_and_unmatched_commands_do_not_charge() {
    let now = Instant::now();
    for (secret, requested) in [
        (None, selector(None, None)),
        (Some(FIXED_SECRET), selector(Some(5349), None)),
        (Some(FIXED_SECRET), selector(Some(3478), Some("tls"))),
    ] {
        let service = configured_service(secret, 1);
        assert!(matches!(
            issue(
                &service,
                scope("alice", "alice@example.test/device"),
                "192.0.2.10",
                vec![requested],
                now,
            ),
            ExtDiscoIssuance::Rejected(ExtDiscoRejection::Unavailable)
        ));
        assert_eq!(service.inner.rate_window_checks.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn issue_credentials_deduplicates_sorted_matches_and_uses_fixed_coturn_credentials() {
    let service = configured_service(Some(FIXED_SECRET), 1);
    let result = issue(
        &service,
        scope("alice", "alice@example.test/device"),
        "192.0.2.10",
        vec![selector(Some(3478), Some("udp")), selector(None, None)],
        Instant::now(),
    );
    let ExtDiscoIssuance::Issued(services) = result else {
        panic!("expected issued credentials");
    };
    assert_eq!(services.len(), 2);
    for (record, expected_transport) in services.iter().zip(["tcp", "udp"]) {
        assert_eq!(
            record.service.identity.transport.as_ref().unwrap().as_str(),
            expected_transport
        );
        assert_eq!(
            record.credentials.username,
            "1700003600:PcwKKYEJqqyGL6SsCoS6IOpkh_X9zWCnrryq35ohCuw"
        );
        assert_eq!(record.credentials.expires, "2023-11-14T23:13:20Z");
    }
    let payload = northstar_xep_0215::build_credentials_result(&services).unwrap();
    assert_eq!(
        payload
            .matches("password='IB5q1aH6qYkelQcy9pZek0tG3wg='")
            .count(),
        2
    );
    assert_eq!(service.inner.rate_window_checks.load(Ordering::Relaxed), 2);
}

#[test]
fn account_window_is_charged_before_ip_and_resets_on_monotonic_time() {
    let start = Instant::now();
    let service = configured_service(Some(FIXED_SECRET), 1);
    let request = |scope, peer_ip, monotonic| {
        issue(
            &service,
            scope,
            peer_ip,
            vec![selector(None, None)],
            monotonic,
        )
    };
    let alice = || scope("alice", "alice@example.test/device");
    let bob = || scope("bob", "bob@example.test/device");
    let carol = || scope("carol", "carol@example.test/device");
    let shared_ip = "192.0.2.10";
    let other_ip = "192.0.2.20";

    assert!(matches!(
        request(alice(), shared_ip, start),
        ExtDiscoIssuance::Issued(_)
    ));
    assert!(matches!(
        request(bob(), shared_ip, start),
        ExtDiscoIssuance::Rejected(ExtDiscoRejection::RateLimited)
    ));
    assert!(matches!(
        request(
            scope("bob", "bob@example.test/another-device"),
            other_ip,
            start
        ),
        ExtDiscoIssuance::Rejected(ExtDiscoRejection::RateLimited)
    ));
    assert!(matches!(
        request(carol(), other_ip, start),
        ExtDiscoIssuance::Issued(_)
    ));
    assert!(matches!(
        request(bob(), shared_ip, start + CREDENTIAL_RATE_WINDOW),
        ExtDiscoIssuance::Issued(_)
    ));
}
