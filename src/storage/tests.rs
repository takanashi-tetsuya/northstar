use super::{
    push_startup_staging_attempt, GuardedUploadStore, LocalUploadStore, UploadAuthorityGeneration,
    UploadSafetyGate, UploadStore, MAX_STARTUP_STAGING_ATTEMPTS,
};
use sha2::Digest;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

struct FailingReader;

impl AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::other("intentional read failure")))
    }
}

fn test_root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("northstar-upload-store-{}", uuid::Uuid::new_v4()))
}

#[tokio::test]
async fn short_and_oversized_writes_leave_no_object_or_partial() {
    for (body, expected) in [(b"abc".as_slice(), 4_u64), (b"abcde".as_slice(), 4_u64)] {
        let root = test_root();
        let id = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        let store = LocalUploadStore::new(root.clone());
        let written = store
            .put(
                &id.to_string(),
                &attempt.to_string(),
                Box::new(std::io::Cursor::new(body.to_vec())),
                expected,
            )
            .await
            .unwrap();
        assert_ne!(written.bytes_written(), expected);
        assert!(!tokio::fs::try_exists(root.join(id.to_string()))
            .await
            .unwrap());
        assert!(
            !tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
                .await
                .unwrap()
        );
        if tokio::fs::try_exists(&root).await.unwrap() {
            tokio::fs::remove_dir_all(root).await.unwrap();
        }
    }
}

#[tokio::test]
async fn exact_write_is_committed_and_readable_without_partial() {
    let root = test_root();
    let id = uuid::Uuid::new_v4();
    let key = id.to_string();
    let attempt = uuid::Uuid::new_v4().to_string();
    let store = LocalUploadStore::new(root.clone());
    let mut staged = store
        .put(
            &key,
            &attempt,
            Box::new(std::io::Cursor::new(b"test".to_vec())),
            4,
        )
        .await
        .unwrap();
    assert_eq!(staged.bytes_written(), 4);
    assert!(
        tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
            .await
            .unwrap()
    );
    assert!(store.get(&key, None).await.unwrap().is_none());
    let digest: [u8; 32] = sha2::Sha256::digest(b"test").into();
    let promoted = store
        .commit(&key, &attempt, None, 4, &digest)
        .await
        .unwrap();
    let duplicate = store
        .commit(&key, &attempt, None, 4, &digest)
        .await
        .unwrap();
    assert_eq!(promoted, duplicate);
    staged.durably_recorded();
    assert!(
        tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
            .await
            .unwrap()
    );
    assert!(store.abort(&key, &attempt, None).await.unwrap());
    assert!(
        !tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
            .await
            .unwrap()
    );
    let stored = store
        .get(&promoted.object_key, None)
        .await
        .unwrap()
        .unwrap();
    let mut reader = stored.reader;
    let mut body = Vec::new();
    reader.read_to_end(&mut body).await.unwrap();
    assert_eq!(stored.size, 4);
    assert_eq!(body, b"test");
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn dropping_an_unpromoted_exact_stage_removes_only_that_attempt() {
    let root = test_root();
    let id = uuid::Uuid::new_v4();
    let stale_attempt = uuid::Uuid::new_v4();
    let replacement_attempt = uuid::Uuid::new_v4();
    let store = LocalUploadStore::new(root.clone());

    let stale = store
        .put(
            &id.to_string(),
            &stale_attempt.to_string(),
            Box::new(std::io::Cursor::new(b"old!".to_vec())),
            4,
        )
        .await
        .unwrap();
    let replacement = store
        .put(
            &id.to_string(),
            &replacement_attempt.to_string(),
            Box::new(std::io::Cursor::new(b"new!".to_vec())),
            4,
        )
        .await
        .unwrap();

    drop(stale);
    assert!(
        !tokio::fs::try_exists(root.join(format!("{id}.{stale_attempt}.part")))
            .await
            .unwrap()
    );
    assert!(
        tokio::fs::try_exists(root.join(format!("{id}.{replacement_attempt}.part")))
            .await
            .unwrap()
    );
    drop(replacement);
    assert!(
        !tokio::fs::try_exists(root.join(format!("{id}.{replacement_attempt}.part")))
            .await
            .unwrap()
    );
    assert!(store.get(&id.to_string(), None).await.unwrap().is_none());

    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn startup_scan_and_cleanup_target_only_well_formed_abandoned_stages() {
    let root = test_root();
    tokio::fs::create_dir_all(&root).await.unwrap();
    let object = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    let owned = root.join(format!("{object}.{attempt}.part"));
    let operator_file = root.join("operator-data.part");
    let malformed = root.join(format!("{object}.not-a-uuid.part"));
    tokio::fs::write(&owned, b"abandoned").await.unwrap();
    tokio::fs::write(&operator_file, b"keep").await.unwrap();
    tokio::fs::write(&malformed, b"keep").await.unwrap();

    let store = LocalUploadStore::new(root.clone());
    assert_eq!(
        store.staging_attempts().await.unwrap(),
        vec![(object, attempt)]
    );
    assert!(store
        .abort(&object.to_string(), &attempt.to_string(), None)
        .await
        .unwrap());
    assert!(!tokio::fs::try_exists(owned).await.unwrap());
    assert!(tokio::fs::try_exists(operator_file).await.unwrap());
    assert!(tokio::fs::try_exists(malformed).await.unwrap());

    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[test]
fn startup_scan_rejects_stage_overflow_before_growing_the_result() {
    let object = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    let mut attempts = vec![(object, attempt); MAX_STARTUP_STAGING_ATTEMPTS];
    assert!(push_startup_staging_attempt(&mut attempts, object, attempt).is_err());
    assert_eq!(attempts.len(), MAX_STARTUP_STAGING_ATTEMPTS);
}

#[tokio::test]
async fn guarded_stage_drop_quarantines_bytes_after_generation_invalidation() {
    let root = test_root();
    let gate = UploadSafetyGate::new();
    let generation = UploadAuthorityGeneration {
        namespace: 17,
        capacity_policy: 23,
    };
    gate.establish(generation, false);
    let local = Arc::new(LocalUploadStore::new(root.clone()).with_safety_gate(Arc::clone(&gate)));
    let guarded = GuardedUploadStore::new(local, Arc::clone(&gate));
    let object = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    let staged = guarded
        .put(
            &object.to_string(),
            &attempt.to_string(),
            Box::new(std::io::Cursor::new(b"safe".to_vec())),
            4,
        )
        .await
        .unwrap();
    let path = root.join(format!("{object}.{attempt}.part"));
    assert!(tokio::fs::try_exists(&path).await.unwrap());
    gate.mark_ledger_mismatch("injected post-write mismatch");
    drop(staged);
    assert!(tokio::fs::try_exists(&path).await.unwrap());
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn stream_failure_removes_partial() {
    let root = test_root();
    let id = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    let store = LocalUploadStore::new(root.clone());
    assert!(store
        .put(
            &id.to_string(),
            &attempt.to_string(),
            Box::new(FailingReader),
            4,
        )
        .await
        .is_err());
    assert!(!tokio::fs::try_exists(root.join(id.to_string()))
        .await
        .unwrap());
    assert!(
        !tokio::fs::try_exists(root.join(format!("{id}.{attempt}.part")))
            .await
            .unwrap()
    );
    if tokio::fs::try_exists(&root).await.unwrap() {
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_write_removes_partial_and_is_not_gettable() {
    let root = test_root();
    let id = uuid::Uuid::new_v4();
    let key = id.to_string();
    let attempt = uuid::Uuid::new_v4().to_string();
    let store = Arc::new(LocalUploadStore::new(root.clone()));
    let (mut writer, reader) = tokio::io::duplex(64);
    writer.write_all(b"partial").await.unwrap();

    let task_store = store.clone();
    let task_key = key.clone();
    let task_attempt = attempt.clone();
    let task = tokio::spawn(async move {
        task_store
            .put(&task_key, &task_attempt, Box::new(reader), 1024)
            .await
            .unwrap()
    });
    let partial = root.join(format!("{id}.{attempt}.part"));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !tokio::fs::try_exists(&partial).await.unwrap() {
            assert!(!task.is_finished(), "upload ended before staging began");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("upload did not create its staging file");
    assert!(store.get(&key, None).await.unwrap().is_none());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!tokio::fs::try_exists(&partial).await.unwrap());
    assert!(store.get(&key, None).await.unwrap().is_none());

    drop(writer);
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn delete_removes_final_and_partial_but_rejects_non_uuid_keys() {
    let root = test_root();
    tokio::fs::create_dir_all(&root).await.unwrap();
    let id = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    tokio::fs::write(root.join(id.to_string()), b"object")
        .await
        .unwrap();
    tokio::fs::write(root.join(format!("{id}.{attempt}.part")), b"partial")
        .await
        .unwrap();
    let store = LocalUploadStore::new(root.clone());
    assert!(store.delete(&id.to_string(), None).await.unwrap());
    assert!(!store.delete(&id.to_string(), None).await.unwrap());
    assert!(store.get("../operator-secret", None).await.is_err());
    assert!(store.delete("../operator-secret", None).await.is_err());
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn clear_removes_only_owned_uuid_objects() {
    let root = test_root();
    tokio::fs::create_dir_all(root.join("operator-directory"))
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4();
    let attempt = uuid::Uuid::new_v4();
    tokio::fs::write(root.join(id.to_string()), b"object")
        .await
        .unwrap();
    tokio::fs::write(root.join(format!("{id}.{attempt}.part")), b"partial")
        .await
        .unwrap();
    tokio::fs::write(root.join("keep.txt"), b"operator data")
        .await
        .unwrap();

    let store = LocalUploadStore::new(root.clone());
    assert_eq!(store.clear().await.unwrap(), 2);
    assert!(tokio::fs::try_exists(root.join("keep.txt")).await.unwrap());
    assert!(tokio::fs::try_exists(root.join("operator-directory"))
        .await
        .unwrap());

    tokio::fs::remove_dir_all(root).await.unwrap();
}
