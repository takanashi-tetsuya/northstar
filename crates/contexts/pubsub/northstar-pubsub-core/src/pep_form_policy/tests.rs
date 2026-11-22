use super::*;

#[test]
fn patch_applies_each_field_and_preserves_unsubmitted_values() {
    let mut base = default_pep_node_config("example");
    base.access_whitelist = vec!["reader@example.test".to_owned()];
    let patch = PepConfigPatch {
        access_model: Some("roster".to_owned()),
        max_items: Some(PepMaxItems::Count(1)),
        persist_items: Some(false),
        send_last_published_item: Some("on_sub".to_owned()),
        deliver_notifications: Some(false),
        roster_groups_allowed: Some(vec!["Friends".to_owned(), "Work".to_owned()]),
    };
    let config = apply_pep_config_patch(&base, &patch).unwrap();
    assert_eq!(
        config,
        PepNodeConfig {
            access_model: "roster".to_owned(),
            max_items: 1,
            persist_items: false,
            send_last_published_item: "on_sub".to_owned(),
            deliver_notifications: false,
            roster_groups_allowed: vec!["Friends".to_owned(), "Work".to_owned()],
            access_whitelist: base.access_whitelist.clone(),
        }
    );
    assert_eq!(
        apply_pep_config_patch(&config, &PepConfigPatch::default()).unwrap(),
        config
    );
}

#[test]
fn patch_rejects_invalid_values_and_accepts_the_boundaries() {
    let base = default_pep_node_config("example");
    for patch in [
        PepConfigPatch {
            access_model: Some("authorize".to_owned()),
            ..Default::default()
        },
        PepConfigPatch {
            send_last_published_item: Some("sometimes".to_owned()),
            ..Default::default()
        },
    ] {
        assert_eq!(apply_pep_config_patch(&base, &patch), Err(PepFormRejection));
    }
    for count in [i64::MIN, -1, 0, i64::from(PEP_MAX_ITEMS) + 1, i64::MAX] {
        let patch = PepConfigPatch {
            max_items: Some(PepMaxItems::Count(count)),
            ..Default::default()
        };
        assert_eq!(apply_pep_config_patch(&base, &patch), Err(PepFormRejection));
    }
    for max in [
        PepMaxItems::Max,
        PepMaxItems::Count(i64::from(PEP_MAX_ITEMS)),
    ] {
        let patch = PepConfigPatch {
            max_items: Some(max),
            ..Default::default()
        };
        assert_eq!(
            apply_pep_config_patch(&base, &patch).unwrap().max_items,
            PEP_MAX_ITEMS
        );
    }
    for groups in [
        vec![],
        vec![String::new()],
        vec!["é".repeat(64) + "a"],
        vec!["group".to_owned(); 101],
    ] {
        let patch = PepConfigPatch {
            roster_groups_allowed: Some(groups),
            ..Default::default()
        };
        assert_eq!(apply_pep_config_patch(&base, &patch), Err(PepFormRejection));
    }
    let groups = vec!["é".repeat(64); 100];
    let patch = PepConfigPatch {
        roster_groups_allowed: Some(groups.clone()),
        ..Default::default()
    };
    assert_eq!(
        apply_pep_config_patch(&base, &patch)
            .unwrap()
            .roster_groups_allowed,
        groups
    );
}

#[test]
fn public_nodes_require_open_persistent_configs_and_node_specific_limits() {
    type Policy = fn(&str, &PepNodeConfig) -> Result<(), PepFormRejection>;
    let policies: [Policy; 2] = [pep_publish_options_policy, pep_owner_config_policy];
    for (node, changed_limit_allowed) in [
        (OMEMO_DEVICES, false),
        (OMEMO_BUNDLES, false),
        (AVATAR_DATA, true),
        (AVATAR_METADATA, false),
        (VCARD4, false),
    ] {
        let defaults = default_pep_node_config(node);
        let closed = PepNodeConfig {
            access_model: "presence".to_owned(),
            ..defaults.clone()
        };
        let transient = PepNodeConfig {
            persist_items: false,
            ..defaults.clone()
        };
        let changed_limit = PepNodeConfig {
            max_items: 2,
            ..defaults.clone()
        };
        for policy in policies {
            assert_eq!(policy(node, &defaults), Ok(()), "{node}");
            assert_eq!(policy(node, &closed), Err(PepFormRejection), "{node}");
            assert_eq!(policy(node, &transient), Err(PepFormRejection), "{node}");
            assert_eq!(
                policy(node, &changed_limit).is_ok(),
                changed_limit_allowed,
                "{node}"
            );
        }
    }
    for node in [
        "example",
        "eu.siacs.conversations.axolotl.devicelist",
        "eu.siacs.conversations.axolotl.bundles:1",
    ] {
        let generic = default_pep_node_config("example");
        assert_eq!(pep_publish_options_policy(node, &generic), Ok(()));
        assert_eq!(pep_owner_config_policy(node, &generic), Ok(()));
    }
}

#[test]
fn private_nodes_have_distinct_owner_and_publish_requirements() {
    for node in [BOOKMARKS2, CONTACTS, LEGACY_BOOKMARKS] {
        let defaults = default_pep_node_config(node);
        assert_eq!(pep_owner_config_policy(node, &defaults), Ok(()));
        assert_eq!(pep_publish_options_policy(node, &defaults), Ok(()));

        let public = PepNodeConfig {
            access_model: "open".to_owned(),
            ..defaults.clone()
        };
        assert_eq!(
            pep_owner_config_policy(node, &public),
            Err(PepFormRejection)
        );
        assert_eq!(
            pep_publish_options_policy(node, &public),
            Err(PepFormRejection)
        );

        for owner_only in [
            PepNodeConfig {
                persist_items: false,
                ..defaults.clone()
            },
            PepNodeConfig {
                send_last_published_item: "on_sub".to_owned(),
                ..defaults
            },
        ] {
            assert_eq!(pep_owner_config_policy(node, &owner_only), Ok(()));
            assert_eq!(
                pep_publish_options_policy(node, &owner_only),
                Err(PepFormRejection)
            );
        }
    }
}

#[test]
fn publish_request_distinguishes_implicit_defaults_from_explicit_options() {
    let defaults = requested_pep_publish_config(OMEMO_DEVICES, None).unwrap();
    assert!(!defaults.explicit);
    assert_eq!(defaults.config, default_pep_node_config(OMEMO_DEVICES));

    let explicit =
        requested_pep_publish_config(OMEMO_DEVICES, Some(&PepConfigPatch::default())).unwrap();
    assert!(explicit.explicit);
    assert_eq!(explicit.config, defaults.config);

    let patch = PepConfigPatch {
        max_items: Some(PepMaxItems::Count(2)),
        ..Default::default()
    };
    assert_eq!(
        requested_pep_publish_config(OMEMO_DEVICES, Some(&patch)).unwrap_err(),
        PepFormRejection
    );
    assert_eq!(
        requested_pep_publish_config("example", Some(&patch))
            .unwrap()
            .config
            .max_items,
        2
    );
}

#[test]
fn publish_decision_checks_explicit_preconditions_before_the_effective_limit() {
    use PepPublishConfigRejection::{MaxItemsExceeded, PreconditionNotMet};

    let requested = default_pep_node_config(OMEMO_DEVICES);
    let actual = PepNodeConfig {
        max_items: 2,
        ..requested.clone()
    };
    for count in [0, 3] {
        assert_eq!(
            pep_publish_config_decision(&requested, true, Some(&actual), count),
            Some(PreconditionNotMet)
        );
    }
    assert_eq!(
        pep_publish_config_decision(&requested, false, Some(&actual), 2),
        None
    );
    assert_eq!(
        pep_publish_config_decision(&requested, false, Some(&actual), 3),
        Some(MaxItemsExceeded)
    );
    assert_eq!(
        pep_publish_config_decision(&requested, true, Some(&requested), 2),
        Some(MaxItemsExceeded)
    );
    for explicit in [false, true] {
        assert_eq!(
            pep_publish_config_decision(&requested, explicit, None, 1),
            None
        );
        assert_eq!(
            pep_publish_config_decision(&requested, explicit, None, 2),
            Some(MaxItemsExceeded)
        );
    }
}
