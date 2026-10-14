use super::*;

fn record(priority: u16, weight: u16, target: &str) -> SrvRecord {
    SrvRecord {
        priority,
        weight,
        port: 5269,
        target: target.to_owned(),
    }
}

#[test]
fn host_meta_cache_capacity_admission_is_linearizable() {
    let cache = dashmap::DashMap::new();
    let admission = Mutex::new(BoundedCacheAdmission::default());
    let workers = 64;
    let limit = 16;
    let now = Instant::now();
    let expiry = now + Duration::from_secs(60);
    let barrier = std::sync::Barrier::new(workers);
    let accepted = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for index in 0..workers {
            let cache = &cache;
            let admission = &admission;
            let barrier = &barrier;
            handles.push(scope.spawn(move || {
                barrier.wait();
                bounded_cache_insert_with_limit(
                    cache,
                    admission,
                    format!("peer-{index}.example"),
                    (index, expiry),
                    limit,
                    now,
                    |entry| entry.1,
                )
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("cache admission worker"))
            .filter(|accepted| *accepted)
            .count()
    });

    assert_eq!(accepted, limit);
    assert_eq!(cache.len(), limit);
}

#[test]
fn expired_host_meta_entries_release_capacity() {
    let cache = dashmap::DashMap::new();
    let admission = Mutex::new(BoundedCacheAdmission::default());
    let now = Instant::now();
    let expired_at = now + Duration::from_millis(1);
    assert!(bounded_cache_insert_with_limit(
        &cache,
        &admission,
        "expired.example".to_owned(),
        (1_u8, expired_at),
        1,
        now,
        |entry| entry.1,
    ));
    assert!(bounded_cache_insert_with_limit(
        &cache,
        &admission,
        "fresh.example".to_owned(),
        (2_u8, expired_at + Duration::from_secs(60)),
        1,
        expired_at + Duration::from_millis(1),
        |entry| entry.1,
    ));
    assert!(!cache.contains_key("expired.example"));
    assert_eq!(cache.get("fresh.example").map(|entry| entry.0), Some(2));
}

#[test]
fn full_host_meta_cache_does_not_rescan_before_the_earliest_ttl() {
    let cache = dashmap::DashMap::new();
    let admission = Mutex::new(BoundedCacheAdmission::default());
    let now = Instant::now();
    let resident_expiry = now + Duration::from_secs(60);
    assert!(bounded_cache_insert_with_limit(
        &cache,
        &admission,
        "resident.example".to_owned(),
        resident_expiry,
        1,
        now,
        |expiry| *expiry,
    ));
    for index in 0..128 {
        assert!(!bounded_cache_insert_with_limit(
            &cache,
            &admission,
            format!("rejected-{index}.example"),
            resident_expiry + Duration::from_secs(60),
            1,
            now,
            |expiry| *expiry,
        ));
    }
    assert_eq!(
        admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sweeps,
        0
    );
    assert!(bounded_cache_insert_with_limit(
        &cache,
        &admission,
        "replacement.example".to_owned(),
        resident_expiry + Duration::from_secs(60),
        1,
        resident_expiry + Duration::from_millis(1),
        |expiry| *expiry,
    ));
    assert_eq!(
        admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sweeps,
        1
    );
}

#[test]
fn srv_order_never_crosses_priority_groups() {
    for _ in 0..100 {
        let ordered = weighted_srv_order(vec![
            record(20, 100, "late.example."),
            record(10, 0, "first-a.example."),
            record(10, 50, "first-b.example."),
        ]);
        assert_eq!(ordered[0].priority, 10);
        assert_eq!(ordered[1].priority, 10);
        assert_eq!(ordered[2].priority, 20);
    }
}

#[test]
fn zero_weight_group_still_returns_every_record() {
    let ordered = weighted_srv_order(vec![
        record(10, 0, "a.example."),
        record(10, 0, "b.example."),
        record(10, 0, "c.example."),
    ]);
    assert_eq!(ordered.len(), 3);
}

#[test]
fn dual_stack_candidates_are_interleaved_without_dropping_either_family() {
    let ordered = interleave_ip_families([
        "2001:4860:4860::8888".parse().unwrap(),
        "2001:4860:4860::8844".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        "8.8.4.4".parse().unwrap(),
    ]);
    assert_eq!(ordered.len(), 4);
    assert!(ordered[0].is_ipv6());
    assert!(ordered[1].is_ipv4());
    assert!(ordered[2].is_ipv6());
    assert!(ordered[3].is_ipv4());

    let ipv4_first = interleave_ip_families([
        "8.8.8.8".parse().unwrap(),
        "2001:4860:4860::8888".parse().unwrap(),
    ]);
    assert!(ipv4_first[0].is_ipv4());
    assert!(ipv4_first[1].is_ipv6());
}

#[test]
fn ssrf_filter_rejects_private_special_and_mapped_addresses() {
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "169.254.1.1",
        "192.0.2.1",
        "198.18.0.1",
        "203.0.113.1",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fec0::1",
        "fe80::1",
        "::127.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::1",
        "2002:7f00:1::",
        "2001:db8::1",
        "3fff::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(!is_public_ip(ip.parse().unwrap()), "accepted {ip}");
    }
    assert!(is_public_ip("8.8.8.8".parse().unwrap()));
    assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
}

#[test]
fn xep_0487_document_is_authoritative_bounded_and_delegates_exactly() {
    let document = br#"{
            "xmpp":{"ttl":300,"public-key-pins-sha-256":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]},
            "links":[
                {"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,
                 "ips":["8.8.8.8"],"priority":10,"weight":50,"sni":"Xmpp.Example."},
                {"rel":"urn:xmpp:alt-connections:websocket","href":"wss://ignored.example/ws"}
            ]
        }"#;
    let parsed = parse_xep_0487_document(false, document).unwrap();
    let HostMetaDiscovery::Authoritative {
        ttl_seconds,
        endpoints,
    } = parsed
    else {
        panic!("XEP-0487 marker was not authoritative");
    };
    assert_eq!(ttl_seconds, 300);
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].address, "8.8.8.8:5270".parse().unwrap());
    assert_eq!(endpoints[0].tls_server_name, "xmpp.example");
    assert!(endpoints[0].direct_tls);
    assert!(endpoints[0].delegated_identity);
    assert_eq!(endpoints[0].public_key_pins, vec![[0; 32]]);
    assert_eq!(endpoints[0].selection_group, 10);

    assert_eq!(
        parse_xep_0487_document(false, br#"{"links":[]}"#).unwrap(),
        HostMetaDiscovery::Legacy
    );
    let no_s2s =
        parse_xep_0487_document(false, br#"{"xmpp":{"ttl":30},"links":[{"rel":"ignored"}]}"#)
            .unwrap();
    assert!(matches!(
        no_s2s,
        HostMetaDiscovery::Authoritative { endpoints, .. } if endpoints.is_empty()
    ));
}

#[test]
fn xep_0487_rejects_unsafe_or_ambiguous_connection_metadata() {
    for invalid in [
        br#"{"xmpp":{},"links":[]}"#.as_slice(),
        br#"{"xmpp":{"ttl":0},"links":[]}"#.as_slice(),
        br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,"ips":[],"priority":0,"weight":0,"sni":"example.org"}]}"#.as_slice(),
        br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,"ips":["not-an-ip"],"priority":0,"weight":0,"sni":"example.org"}]}"#.as_slice(),
        br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,"ips":["127.0.0.1"],"priority":0,"weight":0,"sni":"example.org"}]}"#.as_slice(),
        br#"{"xmpp":{"ttl":30,"public-key-pins-sha-256":["AA=="]},"links":[]}"#.as_slice(),
        br#"{"xmpp":{"ttl":30},"xmpp":{"ttl":60},"links":[]}"#.as_slice(),
        br#"{"xmpp":{"ttl":30,"ttl":60},"links":[]}"#.as_slice(),
        br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","rel":"ignored","port":5270,"ips":["8.8.8.8"],"priority":0,"weight":0,"sni":"example.org"}]}"#.as_slice(),
    ] {
        assert!(
            parse_xep_0487_document(false, invalid).is_err(),
            "accepted {}",
            String::from_utf8_lossy(invalid)
        );
    }
    let authoritative_error =
        parse_xep_0487_document(false, br#"{"xmpp":{"ttl":30,"ttl":60},"links":[]}"#).unwrap_err();
    assert!(
        authoritative_error
            .downcast_ref::<AuthoritativeHostMetaError>()
            .is_some(),
        "an explicit xmpp marker must not downgrade to legacy DNS discovery"
    );
    let private_test = br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,"ips":["127.0.0.1"],"priority":0,"weight":0,"sni":"localhost"}]}"#;
    assert!(parse_xep_0487_document(true, private_test).is_ok());
}

#[test]
fn host_meta_http_parser_enforces_framing_and_decodes_chunks() {
    let response = parse_http_response(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/jrd+json\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
    )
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"test");
    assert_eq!(
        response.content_type.as_deref(),
        Some("application/jrd+json")
    );

    for invalid in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            .as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nbody".as_slice(),
        b"HTTP/1.1 200 OK\r\n folded: value\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\ntoo-long".as_slice(),
    ] {
        assert!(parse_http_response(invalid).is_err());
    }
}

#[test]
fn host_meta_redirects_remain_https_bounded_and_loop_trackable() {
    let current = HttpsLocation {
        host: "example.org".to_owned(),
        port: 443,
        path_and_query: HOST_META_PATH.to_owned(),
    };
    assert_eq!(
        parse_https_redirect(&current, "/metadata.json").unwrap(),
        HttpsLocation {
            host: "example.org".to_owned(),
            port: 443,
            path_and_query: "/metadata.json".to_owned(),
        }
    );
    assert_eq!(
        parse_https_redirect(&current, "https://Meta.Example:8443/host.json?q=1").unwrap(),
        HttpsLocation {
            host: "meta.example".to_owned(),
            port: 8443,
            path_and_query: "/host.json?q=1".to_owned(),
        }
    );
    for invalid in [
        "http://example.org/metadata",
        "https://user@example.org/metadata",
        "https://127.0.0.1/metadata",
        "https://example.org:0/metadata",
    ] {
        assert!(parse_https_redirect(&current, invalid).is_err());
    }
}
