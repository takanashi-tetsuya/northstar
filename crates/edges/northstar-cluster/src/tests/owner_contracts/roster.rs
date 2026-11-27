use super::*;
use northstar_roster_core::RosterVersion;
use std::collections::BTreeMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

// A recording RESP endpoint exercises the real Redis adapter without an
// installed Redis service or environment variables. It accepts only the
// handshake, primary check, version read and publication used by this route.
async fn line(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(
            bytes.len() <= 128,
            "RESP length line exceeded the fixture bound"
        );
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return String::from_utf8(bytes).unwrap();
        }
    }
}

async fn command(stream: &mut TcpStream) -> Vec<String> {
    assert_eq!(stream.read_u8().await.unwrap(), b'*');
    let count: usize = line(stream).await.parse().unwrap();
    assert!(count <= 16);
    let mut arguments = Vec::with_capacity(count);
    for _ in 0..count {
        assert_eq!(stream.read_u8().await.unwrap(), b'$');
        let length: usize = line(stream).await.parse().unwrap();
        assert!(length <= MAX_CLUSTER_PAYLOAD_BYTES);
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(
            stream.read_u16().await.unwrap(),
            u16::from_be_bytes(*b"\r\n")
        );
        arguments.push(String::from_utf8(bytes).unwrap());
    }
    arguments
}

#[tokio::test]
async fn roster_push_keeps_original_user_version_and_annotation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client =
        redis::Client::open(format!("redis://{}/", listener.local_addr().unwrap())).unwrap();
    let (first_security, second_security) =
        northstar_security::cluster_bus::test_configuration_pair("roster-owner.test");
    let mut first = verification_manager("roster-owner.test", first_security);
    let mut second = verification_manager("roster-owner.test", second_security);
    first.connection_uuid = Uuid::from_u128(41);
    second.connection_uuid = Uuid::from_u128(42);
    first.pool = Some(
        cluster_pool_builder()
            .max_size(1)
            .build_unchecked(RedisConnectionManager {
                client: client.clone(),
            }),
    );
    first.client = Some(client);
    seed_test_peer_authority(&first, &second);
    seed_test_peer_authority(&second, &first);
    let expected_user = Uuid::from_u128(43);
    let plain = "<iq xmlns='jabber:client' type='set' id='original'><query xmlns='jabber:iq:roster' ver='42'><item jid='room@mix.example.test'/></query></iq>";
    let annotated = "<iq xmlns='jabber:client' type='set' id='original'><query xmlns='jabber:iq:roster' ver='42'><item jid='room@mix.example.test'><channel xmlns='urn:xmpp:mix:roster:0' participant-id='original-participant'/></item></query></iq>";
    let sender = first.node_delivery();
    let connection = Uuid::from_u128(45);
    let routes = BTreeMap::from([("alice@example.test/Phone".to_owned(), connection)]);
    let (finished, finish) = oneshot::channel();
    let send = async {
        let result = sender
            .send_roster_push(
                &second.node_id,
                "alice@example.test",
                (expected_user, 7),
                &routes,
                RosterVersion(42),
                (plain, Some(annotated)),
            )
            .await;
        finished.send(()).unwrap();
        result
    };
    let receive = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut substantive = Vec::new();
        loop {
            let args = command(&mut stream).await;
            match args[0].as_str() {
                "CLIENT" | "SELECT" => stream.write_all(b"+OK\r\n").await.unwrap(),
                "PING" => stream.write_all(b"+PONG\r\n").await.unwrap(),
                "ROLE" => stream
                    .write_all(b"*3\r\n$6\r\nmaster\r\n:0\r\n*0\r\n")
                    .await
                    .unwrap(),
                "GET" => {
                    assert_eq!(
                        args,
                        [
                            "GET".to_owned(),
                            first.key(format!("node:{}:alive", second.node_id))
                        ]
                    );
                    substantive.push("version");
                    stream.write_all(b"$2\r\n13\r\n").await.unwrap();
                }
                "PUBLISH" => {
                    assert_eq!(args.len(), 3);
                    assert_eq!(args[1], second.key(format!("node:{}", second.node_id)));
                    let envelope = second
                        .verify_signed_payload_inner(
                            &args[2],
                            &args[1],
                            Some(&first.node_id),
                            false,
                        )
                        .unwrap();
                    let payload = &envelope.payload;
                    assert_eq!(
                        payload["expected_user_id"],
                        serde_json::json!(expected_user)
                    );
                    assert_ne!(
                        payload["expected_user_id"],
                        serde_json::json!(Uuid::from_u128(44)),
                        "a recreated account cannot replace the original recipient"
                    );
                    assert_eq!(payload["roster_version"], 42);
                    assert_eq!(payload["protocol_version"], "15");
                    assert_eq!(payload["expected_auth_generation"], 7);
                    assert_eq!(payload["exact_control"]["kind"], "roster_push");
                    assert_eq!(payload["expected_connections"], serde_json::json!(routes));
                    assert_eq!(payload["roster_requested_only"], true);
                    assert_eq!(payload["target"], "alice@example.test");
                    assert_eq!(payload["stanza"], plain);
                    assert_eq!(payload["roster_annotated_stanza"], annotated);
                    substantive.push("publish");
                    stream.write_all(b":1\r\n").await.unwrap();
                    assert!(first.dispatch_pending_ack(
                        &second.node_id,
                        serde_json::json!({
                            "request_id": payload["request_id"], "nonce": payload["ack_nonce"],
                            "node_id": second.node_id, "delivered": 1,
                            "accepted_full_jid": "alice@example.test/Phone",
                        })
                    ));
                    finish.await.unwrap();
                    return substantive;
                }
                other => panic!("unexpected Redis command {other}"),
            }
        }
    };
    let (sent, calls) = tokio::join!(send, receive);
    assert!(sent.unwrap());
    assert_eq!(calls, ["version", "publish"]);
    assert!(first.pending_acks.is_empty());
    assert_eq!(
        first.pending_ack_slots.available_permits(),
        MAX_PENDING_CLUSTER_ACKS
    );
}
