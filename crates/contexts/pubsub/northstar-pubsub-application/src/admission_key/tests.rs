use super::PubSubAdmissionKey;
use crate::{is_pubsub_mutation_busy, PubSubMutationAdmission};
use northstar_pubsub_core::{PubSubAddress, PubSubBareJid, PubSubNodeId, PubSubNodeName};
use northstar_xmpp_types::jid::{canonical_bare_key, canonicalize};
use std::borrow::Cow;
use std::time::Duration;
use uuid::Uuid;

#[test]
fn all_key_variants_use_existing_admission_text() {
    let uuid = Uuid::from_u128(42);
    let full_jid = "ALIce@Example.TEST/Phone";
    let bare_jid = "ALIce@Example.TEST";
    let address = PubSubAddress::parse(full_jid).unwrap();
    let bare = PubSubBareJid::parse(bare_jid).unwrap();
    let node_name = PubSubNodeName::parse(" a ").unwrap();
    let node_key = PubSubAdmissionKey::NodeId(PubSubNodeId::new(uuid));
    let owner_key = PubSubAdmissionKey::Owner(uuid);

    assert!(matches!(
        PubSubAdmissionKey::Text(full_jid).compat_text(),
        Cow::Borrowed(text) if text == full_jid
    ));
    assert!(matches!(
        PubSubAdmissionKey::NodeName(&node_name).compat_text(),
        Cow::Borrowed(" a ")
    ));
    assert_eq!(node_key.compat_text().as_ref(), uuid.to_string());
    assert_eq!(owner_key.compat_text(), node_key.compat_text());
    assert_eq!(
        PubSubAdmissionKey::Address(&address).compat_text().as_ref(),
        canonicalize(full_jid).unwrap(),
    );
    assert_eq!(
        PubSubAdmissionKey::Bare(&bare).compat_text().as_ref(),
        canonical_bare_key(bare_jid).unwrap(),
    );
}

#[tokio::test(start_paused = true)]
async fn address_key_contends_with_its_canonical_text() {
    let input = "ALIce@Example.TEST/Phone";
    let address = PubSubAddress::parse(input).unwrap();
    assert_shared_stripe(
        PubSubAdmissionKey::Address(&address),
        &canonicalize(input).unwrap(),
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn node_id_key_contends_with_its_uuid_text() {
    let uuid = Uuid::from_u128(42);
    let id = PubSubNodeId::new(uuid);
    assert_shared_stripe(PubSubAdmissionKey::NodeId(id), &uuid.to_string()).await;
}

async fn assert_shared_stripe(key: PubSubAdmissionKey<'_>, text: &str) {
    let admission = PubSubMutationAdmission::new(4);
    let wait = Duration::from_millis(20);
    let permit = admission
        .acquire_keys_with_timeout(&[key], false, wait)
        .await
        .unwrap();
    let error = admission
        .acquire_with_timeout(&[text], false, wait)
        .await
        .unwrap_err();
    assert!(is_pubsub_mutation_busy(&error));
    drop(permit);

    admission
        .acquire_with_timeout(&[text], false, wait)
        .await
        .unwrap();
}
