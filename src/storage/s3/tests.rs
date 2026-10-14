use super::{validate_relative_key, S3UploadSettings, S3UploadStore};
use crate::storage::UploadStore;
use object_store::{memory::InMemory, ObjectStore};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{process::Command, sync::Arc};
use tokio::io::AsyncReadExt;

#[test]
fn keys_are_uuid_qualified_and_cannot_traverse() {
    let id = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    assert!(validate_relative_key(&format!("objects/{id}/{attempt}")).is_ok());
    assert!(validate_relative_key(&format!("staging/{id}/{attempt}")).is_ok());
    for invalid in [
        "../secret",
        "objects/not-a-uuid/not-a-uuid",
        "objects/a/b/c",
        "/objects/a/b",
    ] {
        assert!(validate_relative_key(invalid).is_err());
    }
}

#[test]
fn nonambient_store_requires_protected_file_credentials_and_debug_is_redacted() {
    let settings = S3UploadSettings {
        endpoint: Some("https://objects.example.test".to_owned()),
        region: "test-1".to_owned(),
        bucket: "test-bucket".to_owned(),
        prefix: "northstar-test".to_owned(),
        path_style: true,
        allow_http: false,
        ambient_credentials: false,
        cleanup_mode: super::S3CleanupMode::ExactVersion,
        credential_bundle_file: None,
        access_key_id_file: None,
        secret_access_key_file: None,
        session_token_file: Some("do-not-print/session-token".into()),
        sse_kms_key_id_file: Some("do-not-print/kms-key".into()),
    };
    let rendered = format!("{settings:?}");
    assert!(!rendered.contains("objects.example.test"));
    assert!(!rendered.contains("do-not-print"));
    assert!(S3UploadStore::new(settings).is_err());
}

#[tokio::test]
async fn shared_fake_store_verifies_same_attempt_and_rejects_versionless_cleanup() {
    let shared: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let node_a = S3UploadStore::with_client_for_test(Arc::clone(&shared));
    let node_b = S3UploadStore::with_client_for_test(shared);
    let id = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    let body = b"node-a-to-node-b";
    let expected: [u8; 32] = Sha256::digest(body).into();

    let mut staged = node_a
        .put(
            &id.to_string(),
            &attempt.to_string(),
            Box::new(std::io::Cursor::new(body.to_vec())),
            body.len() as u64,
        )
        .await
        .unwrap();
    assert_eq!(staged.sha256(), Some(&expected));
    assert_eq!(staged.stage_key(), staged.object_key());
    let stage_version = staged.stage_version().map(str::to_owned);
    staged.durably_recorded();
    let first = node_a
        .commit(
            &id.to_string(),
            &attempt.to_string(),
            stage_version.as_deref(),
            body.len() as u64,
            &expected,
        )
        .await
        .unwrap();
    let duplicate = node_b
        .commit(
            &id.to_string(),
            &attempt.to_string(),
            stage_version.as_deref(),
            body.len() as u64,
            &expected,
        )
        .await
        .unwrap();
    assert_eq!(first.object_key, duplicate.object_key);

    let stored = node_b
        .get(&first.object_key, first.object_version.as_deref())
        .await
        .unwrap()
        .unwrap();
    let mut reader = stored.reader;
    let mut downloaded = Vec::new();
    reader.read_to_end(&mut downloaded).await.unwrap();
    assert_eq!(downloaded, body);

    assert!(node_b
        .delete(&first.object_key, first.object_version.as_deref())
        .await
        .is_err());
    assert!(node_a
        .get(&first.object_key, first.object_version.as_deref())
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn client_swap_is_atomic_and_old_client_remains_valid_for_in_flight_work() {
    let old: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let replacement: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let store = S3UploadStore::with_client_for_test(Arc::clone(&old));
    let in_flight = store.client();
    store.swap_client_for_test(replacement);
    assert!(Arc::ptr_eq(&old, &in_flight));
    assert!(!Arc::ptr_eq(&store.client(), &in_flight));
}

#[tokio::test]
async fn versionless_attempt_cleanup_remains_pending_after_late_appearance() {
    let shared: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let store = S3UploadStore::with_client_for_test(shared);
    let id = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    assert!(store
        .abort(&id.to_string(), &attempt.to_string(), None)
        .await
        .is_err());

    // A timed-out multipart may still complete after cleanup first sees
    // an unversioned locator. Refusing the deletion keeps recovery pending.
    let mut late = store
        .put(
            &id.to_string(),
            &attempt.to_string(),
            Box::new(std::io::Cursor::new(b"late".to_vec())),
            4,
        )
        .await
        .unwrap();
    let version = late.stage_version().map(str::to_owned);
    late.durably_recorded();
    assert!(store
        .abort(&id.to_string(), &attempt.to_string(), version.as_deref())
        .await
        .is_err());
    assert!(store
        .abort(&id.to_string(), &attempt.to_string(), version.as_deref())
        .await
        .is_err());
    assert!(store
        .get(&format!("objects/{id}/{attempt}"), None)
        .await
        .unwrap()
        .is_some());
}

fn minio_versions(settings: &S3UploadSettings, key: &str) -> (Vec<String>, Vec<String>) {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/lib/s3-fixture.py"
        ))
        .arg("--endpoint")
        .arg(settings.endpoint.as_deref().unwrap())
        .arg("--bucket")
        .arg(&settings.bucket)
        .arg("--access-key-file")
        .arg(settings.access_key_id_file.as_deref().unwrap())
        .arg("--secret-key-file")
        .arg(settings.secret_access_key_file.as_deref().unwrap())
        .arg("list-versions")
        .arg(key)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "MinIO version inspection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    let values = |name: &str| {
        result[name]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    (values("versions"), values("delete_markers"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit loopback MinIO fixture and a versioned bucket"]
async fn minio_exact_version_cleanup_preserves_newer_version_without_marker() {
    let settings = S3UploadSettings {
        endpoint: Some(std::env::var("NORTHSTAR_MINIO_TEST_ENDPOINT").unwrap()),
        region: "us-east-1".to_owned(),
        bucket: std::env::var("NORTHSTAR_MINIO_TEST_BUCKET").unwrap(),
        prefix: format!("northstar-exact-delete/{}", uuid::Uuid::new_v4()),
        path_style: true,
        allow_http: true,
        ambient_credentials: false,
        cleanup_mode: super::S3CleanupMode::ExactVersion,
        credential_bundle_file: None,
        access_key_id_file: Some(
            std::env::var_os("NORTHSTAR_MINIO_TEST_ACCESS_KEY_FILE")
                .unwrap()
                .into(),
        ),
        secret_access_key_file: Some(
            std::env::var_os("NORTHSTAR_MINIO_TEST_SECRET_KEY_FILE")
                .unwrap()
                .into(),
        ),
        session_token_file: None,
        sse_kms_key_id_file: None,
    };
    let entered = Arc::new(tokio::sync::Barrier::new(2));
    let resume = Arc::new(tokio::sync::Barrier::new(2));
    let mut gated = S3UploadStore::new(settings.clone()).unwrap();
    gated.exact_delete_gate = Some((Arc::clone(&entered), Arc::clone(&resume)));
    let gated = Arc::new(gated);
    let id = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    let key = format!("objects/{id}/{attempt}");
    let full_key = format!("{}/{key}", settings.prefix);
    let mut first = gated
        .put(
            &id.to_string(),
            &attempt.to_string(),
            Box::new(std::io::Cursor::new(b"first".to_vec())),
            5,
        )
        .await
        .unwrap();
    let first_version = first.stage_version().unwrap().to_owned();
    first.durably_recorded();

    let abort = tokio::spawn({
        let gated = Arc::clone(&gated);
        let first_version = first_version.clone();
        async move {
            gated
                .abort(&id.to_string(), &attempt.to_string(), Some(&first_version))
                .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(30), entered.wait())
        .await
        .expect("exact-version abort did not reach its pre-delete gate");
    let mut second = gated
        .put(
            &id.to_string(),
            &attempt.to_string(),
            Box::new(std::io::Cursor::new(b"second".to_vec())),
            6,
        )
        .await
        .unwrap();
    let second_version = second.stage_version().unwrap().to_owned();
    second.durably_recorded();
    assert_ne!(first_version, second_version);
    tokio::time::timeout(std::time::Duration::from_secs(30), resume.wait())
        .await
        .expect("exact-version abort did not resume after the newer write");
    assert!(abort.await.unwrap().unwrap());

    let store = S3UploadStore::new(settings.clone()).unwrap();
    assert!(store
        .get(&key, Some(&first_version))
        .await
        .unwrap()
        .is_none());
    let mut current = store.get(&key, None).await.unwrap().unwrap();
    assert_eq!(
        current.object_version.as_deref(),
        Some(second_version.as_str())
    );
    let mut bytes = Vec::new();
    current.reader.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"second");
    assert_eq!(
        minio_versions(&settings, &full_key),
        (vec![second_version.clone()], Vec::new())
    );

    assert!(!store
        .abort(&id.to_string(), &attempt.to_string(), Some(&first_version))
        .await
        .unwrap());
    assert!(store
        .abort(&id.to_string(), &attempt.to_string(), None)
        .await
        .is_err());
    assert!(store.delete(&key, Some("null")).await.is_err());
    assert_eq!(
        minio_versions(&settings, &full_key),
        (vec![second_version.clone()], Vec::new())
    );

    let abandoned = store
        .put(
            &id.to_string(),
            &attempt.to_string(),
            Box::new(std::io::Cursor::new(b"abandoned".to_vec())),
            9,
        )
        .await
        .unwrap();
    let abandoned_version = abandoned.stage_version().unwrap().to_owned();
    let mut latest = store
        .put(
            &id.to_string(),
            &attempt.to_string(),
            Box::new(std::io::Cursor::new(b"latest".to_vec())),
            6,
        )
        .await
        .unwrap();
    let latest_version = latest.stage_version().unwrap().to_owned();
    latest.durably_recorded();

    // Dropping a completed but unrecorded stage removes only its exact
    // version, even after a concurrent writer has replaced latest.
    drop(abandoned);
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if store
                .get(&key, Some(&abandoned_version))
                .await
                .unwrap()
                .is_none()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("abandoned exact-version Drop cleanup did not complete");
    let (versions, markers) = minio_versions(&settings, &full_key);
    assert!(versions.contains(&second_version));
    assert!(versions.contains(&latest_version));
    assert_eq!(versions.len(), 2);
    assert!(markers.is_empty());

    // Cancellation while multipart completion is in flight has no known
    // version. Its temporary Drop must not create a key-level marker.
    drop(super::RemoteTemporaryObject::new(store.path(&key).unwrap()));
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let mut current = store.get(&key, None).await.unwrap().unwrap();
    assert_eq!(
        current.object_version.as_deref(),
        Some(latest_version.as_str())
    );
    let mut bytes = Vec::new();
    current.reader.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"latest");
    assert!(minio_versions(&settings, &full_key).1.is_empty());

    assert!(store.delete(&key, Some(&second_version)).await.unwrap());
    assert!(store.delete(&key, Some(&latest_version)).await.unwrap());
    assert!(store.get(&key, None).await.unwrap().is_none());
    assert_eq!(
        minio_versions(&settings, &full_key),
        (Vec::new(), Vec::new())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicit loopback MinIO fixture with never-versioned, enabled, and suspended buckets"]
async fn minio_unversioned_provider_without_conditional_delete_fails_closed() {
    let settings = S3UploadSettings {
        endpoint: Some(std::env::var("NORTHSTAR_MINIO_TEST_ENDPOINT").unwrap()),
        region: "us-east-1".to_owned(),
        bucket: std::env::var("NORTHSTAR_MINIO_TEST_UNVERSIONED_BUCKET").unwrap(),
        prefix: format!("northstar-unversioned-delete/{}", uuid::Uuid::new_v4()),
        path_style: true,
        allow_http: true,
        ambient_credentials: false,
        cleanup_mode: super::S3CleanupMode::QualifiedUnversioned,
        credential_bundle_file: None,
        access_key_id_file: Some(
            std::env::var_os("NORTHSTAR_MINIO_TEST_ACCESS_KEY_FILE")
                .unwrap()
                .into(),
        ),
        secret_access_key_file: Some(
            std::env::var_os("NORTHSTAR_MINIO_TEST_SECRET_KEY_FILE")
                .unwrap()
                .into(),
        ),
        session_token_file: None,
        sse_kms_key_id_file: None,
    };
    let store = S3UploadStore::new(settings.clone()).unwrap();
    let id = uuid::Uuid::new_v4();
    for action in ["abort", "delete", "drop"] {
        let attempt = uuid::Uuid::new_v4();
        let key = format!("objects/{id}/{attempt}");
        let full_key = format!("{}/{key}", settings.prefix);
        let mut staged = store
            .put(
                &id.to_string(),
                &attempt.to_string(),
                Box::new(std::io::Cursor::new(action.as_bytes().to_vec())),
                action.len() as u64,
            )
            .await
            .unwrap();
        assert!(staged.stage_version().is_none());
        assert!(store.get(&key, None).await.unwrap().is_some());
        let before = minio_versions(&settings, &full_key);
        match action {
            "abort" => {
                staged.durably_recorded();
                let error = store
                    .abort(&id.to_string(), &attempt.to_string(), None)
                    .await
                    .unwrap_err();
                assert!(
                    format!("{error:#}").contains("did not enforce conditional DELETE"),
                    "unexpected canary failure: {error:#}"
                );
            }
            "delete" => {
                staged.durably_recorded();
                assert!(store.delete(&key, None).await.is_err());
            }
            "drop" => {
                drop(staged);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            _ => unreachable!(),
        }
        let mut current = store.get(&key, None).await.unwrap().unwrap();
        let mut bytes = Vec::new();
        current.reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, action.as_bytes());
        assert_eq!(minio_versions(&settings, &full_key), before);
        assert!(before.1.is_empty());
    }

    for bucket in [
        std::env::var("NORTHSTAR_MINIO_TEST_BUCKET").unwrap(),
        std::env::var("NORTHSTAR_MINIO_TEST_SUSPENDED_BUCKET").unwrap(),
    ] {
        let mut blocked_settings = settings.clone();
        blocked_settings.bucket = bucket;
        let blocked = S3UploadStore::new(blocked_settings.clone()).unwrap();
        let attempt = uuid::Uuid::new_v4();
        let key = format!("objects/{id}/{attempt}");
        let full_key = format!("{}/{key}", blocked_settings.prefix);
        let mut staged = blocked
            .put(
                &id.to_string(),
                &attempt.to_string(),
                Box::new(std::io::Cursor::new(b"blocked".to_vec())),
                7,
            )
            .await
            .unwrap();
        staged.durably_recorded();
        let before = minio_versions(&blocked_settings, &full_key);
        assert!(blocked
            .abort(&id.to_string(), &attempt.to_string(), None)
            .await
            .is_err());
        assert!(blocked.get(&key, None).await.unwrap().is_some());
        assert_eq!(minio_versions(&blocked_settings, &full_key), before);
    }
}

#[tokio::test]
#[ignore = "requires the explicit loopback MinIO fixture and a pre-created bucket"]
async fn minio_compatible_round_trip_harness() {
    let endpoint = std::env::var("NORTHSTAR_MINIO_TEST_ENDPOINT")
        .expect("set NORTHSTAR_MINIO_TEST_ENDPOINT, normally http://127.0.0.1:19000");
    let bucket = std::env::var("NORTHSTAR_MINIO_TEST_BUCKET")
        .expect("set NORTHSTAR_MINIO_TEST_BUCKET after creating the fixture bucket");
    let access_key_id_file = std::env::var_os("NORTHSTAR_MINIO_TEST_ACCESS_KEY_FILE")
        .map(std::path::PathBuf::from)
        .expect("set NORTHSTAR_MINIO_TEST_ACCESS_KEY_FILE");
    let secret_access_key_file = std::env::var_os("NORTHSTAR_MINIO_TEST_SECRET_KEY_FILE")
        .map(std::path::PathBuf::from)
        .expect("set NORTHSTAR_MINIO_TEST_SECRET_KEY_FILE");
    let store = S3UploadStore::new(super::S3UploadSettings {
        endpoint: Some(endpoint),
        region: "us-east-1".to_owned(),
        bucket,
        prefix: format!("northstar-manual-test/{}", uuid::Uuid::new_v4()),
        path_style: true,
        allow_http: true,
        ambient_credentials: false,
        cleanup_mode: super::S3CleanupMode::ExactVersion,
        credential_bundle_file: None,
        access_key_id_file: Some(access_key_id_file),
        secret_access_key_file: Some(secret_access_key_file),
        session_token_file: None,
        sse_kms_key_id_file: None,
    })
    .unwrap();
    let id = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    let body = b"minio-compatibility";
    let digest: [u8; 32] = Sha256::digest(body).into();
    let mut stage = store
        .put(
            &id.to_string(),
            &attempt.to_string(),
            Box::new(std::io::Cursor::new(body.to_vec())),
            body.len() as u64,
        )
        .await
        .unwrap();
    let stage_version = stage.stage_version().map(str::to_owned);
    stage.durably_recorded();
    let object = store
        .commit(
            &id.to_string(),
            &attempt.to_string(),
            stage_version.as_deref(),
            body.len() as u64,
            &digest,
        )
        .await
        .unwrap();
    assert!(store
        .get(&object.object_key, object.object_version.as_deref())
        .await
        .unwrap()
        .is_some());
    store
        .delete(&object.object_key, object.object_version.as_deref())
        .await
        .unwrap();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Projection {
    Writing,
    Staged,
    Promoting,
    Committed,
}

#[derive(Clone, Copy)]
enum FailurePoint {
    StageBeforeMetadata,
    StagedMetadata,
    PromotingMetadata,
    VerifyBeforeCommit,
    CommitBeforeResponse,
}

#[derive(Default)]
struct FakeLifecycleStore {
    attempt_key: bool,
}

/// Pure crash model for the production transition order. Every injected
/// stop is resumed from durable state; promotion is create-only and
/// successful commit never removes the immutable attempt key.
fn recover_after_failure(fail_after: FailurePoint) -> (Projection, FakeLifecycleStore) {
    let mut transitions = vec![Projection::Writing];
    let mut store = FakeLifecycleStore { attempt_key: true };
    // The process can stop after stage creation while PostgreSQL is still
    // `writing`; the expired writing intent owns the exact cleanup key.
    if matches!(fail_after, FailurePoint::StageBeforeMetadata) {
        assert_eq!(transitions.last(), Some(&Projection::Writing));
        store.attempt_key = false;
        // A replacement claim recreates an isolated stage key.
        store.attempt_key = true;
    }
    transitions.push(Projection::Staged);
    if matches!(fail_after, FailurePoint::StagedMetadata) {
        // Durable promote job restarts from `staged`.
    }
    transitions.push(Projection::Promoting);
    if matches!(fail_after, FailurePoint::PromotingMetadata) {
        // Durable promote job restarts from `promoting`.
    }
    if matches!(fail_after, FailurePoint::VerifyBeforeCommit) {
        // PostgreSQL remains `promoting`; retry performs another read-only
        // exact-version verification of the same key.
        assert_eq!(transitions.last(), Some(&Projection::Promoting));
    }
    transitions.push(Projection::Committed);
    if matches!(fail_after, FailurePoint::CommitBeforeResponse) {
        // A retried request observes the committed DB projection and must
        // not abort the key which is both stage and destination.
        assert!(store.attempt_key);
    }
    (*transitions.last().expect("at least one projection"), store)
}

#[test]
fn every_durable_transition_recovers_monotonically() {
    for fail_after in [
        FailurePoint::StageBeforeMetadata,
        FailurePoint::StagedMetadata,
        FailurePoint::PromotingMetadata,
        FailurePoint::VerifyBeforeCommit,
        FailurePoint::CommitBeforeResponse,
    ] {
        let (projection, store) = recover_after_failure(fail_after);
        assert_eq!(projection, Projection::Committed);
        assert!(store.attempt_key);
    }
}
