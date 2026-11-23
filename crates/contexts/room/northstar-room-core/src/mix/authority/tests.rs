use super::*;

fn outcome<T>(result: Result<T>) -> Result<T, String> {
    result.map_err(|error| format!("{error:#}"))
}

#[test]
fn channel_addresses_preserve_component_and_bare_jid_preparation() {
    for (input, localpart, domain) in [
        ("room@mix.example", "room", "mix.example"),
        ("ROOM#Side@MIX.EXAMPLE.", "room#side", "mix.example"),
        ("A\u{30a}@xn--bcher-kva.example", "å", "bücher.example"),
        ("room@[2001:0db8::1]", "room", "[2001:db8::1]"),
    ] {
        let address = MixChannelAddress::parse(input).unwrap();
        assert_eq!(address.localpart(), localpart);
        assert_eq!(address.domain(), domain);
        assert_eq!(address.as_str(), format!("{localpart}@{domain}"));
        assert_eq!(MixChannelAddress::parse(address.as_str()).unwrap(), address);
    }
    for input in [
        "",
        "mix.example",
        "@mix.example",
        "r@mix.example/x",
        "r@a..test",
    ] {
        let legacy = CanonicalJid::parse_bare(input).and_then(|jid| {
            jid.localpart()
                .context("MIX channel JID requires a localpart")?;
            Ok(jid.to_string())
        });
        assert!(legacy.is_err(), "{input:?}");
        assert_eq!(
            outcome(MixChannelAddress::parse(input).map(|address| address.to_string())),
            outcome(legacy),
            "{input:?}"
        );
    }
    for input in [
        "MIX.EXAMPLE.",
        "xn--bcher-kva.example",
        "[2001:0db8::1]",
        "",
        "a..test",
    ] {
        assert_eq!(
            outcome(MixChannelAddress::prepare_service_domain(input)),
            outcome(prepare_domainpart(input))
        );
    }
    let oversized = "a".repeat(1024);
    for input in [
        "ROOM",
        "A\u{30a}",
        "r#side",
        "r@side",
        "",
        oversized.as_str(),
    ] {
        let legacy = prepare_localpart(input).and_then(|prepared| {
            anyhow::ensure!(prepared.len() <= 1023, "MIX channel localpart is too large");
            Ok(prepared)
        });
        assert_eq!(
            outcome(MixChannelAddress::prepare_channel_localpart(input)),
            outcome(legacy)
        );
    }
}

#[test]
fn real_jids_validate_full_inputs_before_discarding_resources() {
    for (input, expected) in [
        ("alice@example.test", Some("alice@example.test")),
        (
            "A\u{30a}LICE@xn--bcher-kva.example./Phone/@Desk",
            Some("ålice@bücher.example"),
        ),
        ("alice@example.test/", None),
        ("alice@example.test/\u{7}", None),
        ("example.test/Phone", None),
        ("@example.test", None),
        ("", None),
    ] {
        let legacy = CanonicalJid::parse(input).and_then(|jid| {
            anyhow::ensure!(
                jid.localpart().is_some(),
                "MIX participants require a user bare JID"
            );
            Ok(jid.bare())
        });
        let parsed = MixRealJid::parse(input);
        assert_eq!(parsed.as_ref().ok().map(MixRealJid::as_str), expected);
        if let Ok(jid) = &parsed {
            assert_eq!(&MixRealJid::parse(jid.as_str()).unwrap(), jid);
        }
        assert_eq!(outcome(parsed.map(|jid| jid.to_string())), outcome(legacy));
    }
}

#[test]
fn nick_preparation_preserves_case_and_spaces() {
    let oversized = "a".repeat(1024);
    for (input, expected) in [
        ("Nick", Some("Nick")),
        ("nick", Some("nick")),
        (" A ", Some(" A ")),
        ("A\u{30a}", Some("Å")),
        ("", None),
        ("bad\u{7}nick", None),
        (oversized.as_str(), None),
    ] {
        let parsed = MixParticipantNick::parse(input);
        assert_eq!(
            parsed.as_ref().ok().map(MixParticipantNick::as_str),
            expected
        );
        if let Ok(nick) = &parsed {
            assert_eq!(&MixParticipantNick::parse(nick.as_str()).unwrap(), nick);
        }
        assert_eq!(
            outcome(parsed.map(|nick| nick.to_string())),
            outcome(prepare_resourcepart(input))
        );
    }
}

#[test]
fn uuid_identities_normalize_and_keep_local_and_remote_ids_distinct() {
    let uuid = Uuid::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
    let canonical = "00112233-4455-6677-8899-aabbccddeeff";
    let channel = MixChannelId::new(uuid);
    let local = MixLocalParticipantId::new(uuid);
    for input in [canonical, "00112233445566778899AABBCCDDEEFF"] {
        assert_eq!(MixChannelId::parse(input).unwrap(), channel);
        assert_eq!(MixLocalParticipantId::parse(input).unwrap(), local);
    }
    assert_eq!(channel.to_string(), canonical);
    assert_eq!(local.to_string(), canonical);
    assert_eq!(channel.as_uuid(), uuid);
    assert_eq!(local.as_uuid(), uuid);
    for invalid in ["", "not-a-uuid", "00112233-4455-6677-8899-aabbccddeefg"] {
        assert!(MixChannelId::parse(invalid).is_err());
        assert!(MixLocalParticipantId::parse(invalid).is_err());
        assert!(MixParticipantId::parse_local(invalid).is_err());
    }

    let local = MixParticipantId::Local(local);
    let remote = MixParticipantId::parse_remote(canonical).unwrap();
    assert_eq!(local.to_string(), remote.to_string());
    assert_ne!(local, remote);
    assert_eq!(
        MixParticipantId::parse_local(&local.to_string()).unwrap(),
        local
    );
    assert_eq!(
        MixParticipantId::parse_remote(&remote.to_string()).unwrap(),
        remote
    );
}

#[test]
fn policy_values_accept_exact_stored_spellings() {
    macro_rules! assert_policy {
        ($type:ident, $extra_invalid:literal, $($variant:ident => $stored:literal),+ $(,)?) => {
            $(
                let value = $type::$variant;
                assert_eq!(value.as_str(), $stored);
                assert_eq!(value.to_string(), $stored);
                assert_eq!($type::parse(value.as_str()).unwrap(), value);
                assert!($type::parse(&$stored.to_ascii_uppercase()).is_err());
                assert!($type::parse(concat!($stored, " ")).is_err());
            )+
            assert!($type::parse("").is_err());
            assert!($type::parse($extra_invalid).is_err());
        };
    }
    assert_policy!(
        MixPamState, "pending",
        PendingJoin => "pending_join", Joined => "joined", PendingLeave => "pending_leave",
    );
    assert_policy!(
        MixRole, "admin",
        Owner => "owner", Administrator => "administrator", Participant => "participant",
    );
    assert_policy!(
        MixJidVisibility, "always", Visible => "visible", Maybe => "maybe", Hidden => "hidden",
    );
    assert_policy!(MixAccessModel, "closed", Open => "open", Allowlist => "allowlist");
    assert_policy!(
        MixAdministratorRetractionRights, "owner",
        Nobody => "nobody", Administrators => "administrators", Owners => "owners",
    );
    assert_policy!(
        MixJidVisibilityPreference, "prefer_not",
        Default => "default", Never => "never", Always => "always", PreferNot => "prefer not",
    );
    assert_policy!(MixAllowBlock, "default", Allow => "allow", Block => "block");
    assert_policy!(MixPamOperation, "joined", Join => "join", Leave => "leave");
    assert_policy!(
        MixPamOperationState, "pending_join",
        Pending => "pending", Terminal => "terminal", Reconciliation => "reconciliation",
    );
}

fn legacy_valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1023
        && !value.contains('@')
        && !value.contains('/')
        && !value.contains('#')
}

#[test]
fn remote_ids_are_opaque_with_an_octet_limit_and_three_delimiters() {
    let longest = format!("{}a", "α".repeat(511));
    let oversized = "α".repeat(512);
    for (input, accepted) in [
        ("not-a-uuid", true),
        ("αβγ", true),
        ("UPPER", true),
        ("A\u{30a}", true),
        (" \u{7} ", true),
        (longest.as_str(), true),
        (oversized.as_str(), false),
        ("", false),
        ("id#channel", false),
        ("id@example.test", false),
        ("id/resource", false),
    ] {
        let parsed = MixStableParticipantId::parse(input);
        assert_eq!(parsed.is_ok(), accepted, "{input:?}");
        assert_eq!(parsed.is_ok(), legacy_valid_id(input), "{input:?}");
        assert_eq!(MixParticipantId::parse_remote(input).is_ok(), accepted);
        if let Ok(id) = parsed {
            assert_eq!(id.as_str(), input);
            assert_eq!(MixStableParticipantId::parse(id.as_str()).unwrap(), id);
        }
    }
}

// Frozen string algorithms serve as an oracle without a dependency on the adapters.
fn legacy_encode(channel: &str, id: &str, resource: Option<&str>) -> Result<String> {
    anyhow::ensure!(legacy_valid_id(id), "invalid MIX stable participant id");
    let channel = CanonicalJid::parse_bare(channel)?;
    let localpart = channel
        .localpart()
        .context("MIX channel JID requires a localpart")?;
    let encoded_localpart = format!("{id}#{localpart}");
    let bare = CanonicalJid::parse_bare(&format!("{encoded_localpart}@{}", channel.domainpart()))?;
    anyhow::ensure!(
        bare.localpart() == Some(encoded_localpart.as_str()),
        "MIX stable participant id is not a canonical JID localpart prefix"
    );
    match resource {
        Some(resource) => northstar_xmpp_types::jid::canonicalize(&format!("{bare}/{resource}")),
        None => Ok(bare.to_string()),
    }
}

fn legacy_decode(value: &str) -> Result<(String, String)> {
    let raw_localpart = value
        .split_once('@')
        .map(|(part, _)| part)
        .context("encoded MIX participant JID requires a localpart")?;
    let encoded = CanonicalJid::parse_bare(value)?;
    anyhow::ensure!(
        encoded.localpart() == Some(raw_localpart),
        "encoded MIX participant JID is not in canonical localpart form"
    );
    let (id, channel) = encoded
        .localpart()
        .and_then(|part| part.split_once('#'))
        .context("encoded MIX participant JID is missing its channel")?;
    anyhow::ensure!(legacy_valid_id(id), "invalid MIX stable participant id");
    let channel = CanonicalJid::parse_bare(&format!("{channel}@{}", encoded.domainpart()))?;
    Ok((id.to_owned(), channel.to_string()))
}

#[test]
fn relay_encoders_preserve_legacy_bytes_and_error_order() {
    let long_id = "a".repeat(1019);
    let oversized_id = "a".repeat(1023);
    for (channel, id, resource) in [
        ("ROOM#Side@MIX.REMOTE.TEST.", "opaque", None),
        ("ROOM@MIX.REMOTE.TEST", "opaque", Some("A\u{30a}/Desk@Home")),
        ("r@mix.remote.test", "not-a-uuid", None),
        ("r@mix.remote.test", "αβγ", None),
        ("r@mix.remote.test", "UPPER", Some("")),
        ("r@mix.remote.test", "A\u{30a}", None),
        ("r@mix.remote.test", "id#channel", None),
        ("r@mix.remote.test", "id@example.test", None),
        ("r@mix.remote.test", "id/resource", None),
        ("r@mix.remote.test", "opaque", Some("")),
        ("r@mix.remote.test", "opaque", Some("\u{7}")),
        ("r@mix.remote.test/r", "opaque", None),
        ("mix.remote.test", "opaque", None),
        ("", "", Some("")),
        ("abc@mix.remote.test", long_id.as_str(), None),
        ("r@mix.remote.test", oversized_id.as_str(), None),
    ] {
        let parsed = MixRelayAddress::encode(channel, id, resource);
        if let Ok(address) = &parsed {
            assert_eq!(&MixRelayAddress::parse(address.as_str()).unwrap(), address);
        }
        assert_eq!(
            outcome(parsed.map(|address| address.to_string())),
            outcome(legacy_encode(channel, id, resource)),
            "{channel:?} {id:?} {resource:?}"
        );
    }
}

#[test]
fn relay_decoders_preserve_legacy_first_separator_and_channel_matching() {
    for input in [
        "opaque#room@mix.remote.test",
        "opaque#room#side@MIX.REMOTE.TEST.",
        "not-a-uuid#room@mix.remote.test",
        "αβγ#room@mix.remote.test",
        "UPPER#room@mix.remote.test",
        "#room@mix.remote.test",
        "opaque#@mix.remote.test",
        "opaque@mix.remote.test",
        "opaque#room@mix.remote.test/Desk",
        "mix.remote.test",
    ] {
        let result = MixRelayAddress::parse_bare(input);
        if let Ok(address) = &result {
            assert_eq!(
                &MixRelayAddress::parse_bare(address.as_str()).unwrap(),
                address
            );
            assert_eq!(address.resource(), None);
        }
        assert_eq!(
            outcome(result.map(|address| (
                address.participant_id().to_string(),
                address.channel().to_string(),
            ))),
            outcome(legacy_decode(input)),
            "{input:?}"
        );
        for expected in [
            "ROOM@MIX.REMOTE.TEST.",
            "room#side@mix.remote.test",
            "mix.remote.test",
            "room@mix.remote.test/Desk",
        ] {
            let legacy = legacy_decode(input).and_then(|(id, channel)| {
                let expected = CanonicalJid::parse_bare(expected)?;
                anyhow::ensure!(
                    channel == expected.to_string(),
                    "encoded MIX participant JID has the wrong channel"
                );
                Ok(id)
            });
            assert_eq!(
                outcome(
                    MixRelayAddress::parse_bare_for_channel(input, expected)
                        .map(|address| address.participant_id().to_string())
                ),
                outcome(legacy),
                "{input:?} {expected:?}"
            );
        }
    }
    let address = MixRelayAddress::parse_bare("opaque#room#side@MIX.REMOTE.TEST.").unwrap();
    assert_eq!(address.channel().as_str(), "room#side@mix.remote.test");
    assert_eq!(address.participant_id().to_string(), "opaque");
}

#[test]
fn full_relay_round_trips_resource_and_explicit_local_scope() {
    let channel = MixChannelAddress::parse("ROOM@MIX.REMOTE.TEST").unwrap();
    let participant = MixParticipantId::Local(MixLocalParticipantId::new(Uuid::from_u128(1)));
    let address = MixRelayAddress::new(channel, participant, Some("A\u{30a}/Desk@Home")).unwrap();
    assert_eq!(address.resource(), Some("Å/Desk@Home"));
    assert_eq!(
        address.as_str(),
        "00000000-0000-0000-0000-000000000001#room@mix.remote.test/Å/Desk@Home"
    );
    assert_eq!(
        MixRelayAddress::parse_local(address.as_str()).unwrap(),
        address
    );
    assert!(matches!(
        MixRelayAddress::parse(address.as_str())
            .unwrap()
            .participant_id(),
        MixParticipantId::Remote(_)
    ));
    assert!(MixRelayAddress::parse_local("opaque#room@mix.remote.test").is_err());
    let unhyphenated = "00000000000000000000000000000001#room@mix.remote.test";
    let decoded = MixRelayAddress::parse_local(unhyphenated).unwrap();
    assert_eq!(decoded.participant_id(), address.participant_id());
    assert_eq!(decoded.as_str(), unhyphenated);
}
