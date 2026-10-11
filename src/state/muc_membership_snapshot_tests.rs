//! Tests of local MUC membership snapshots.

use super::{local_muc_membership_snapshots, JoinedMucMembership};
use dashmap::DashMap;
use uuid::Uuid;

#[tokio::test(flavor = "current_thread")]
async fn muc_sm_association_snapshot_releases_membership_guards_before_backend_await() {
    let memberships = DashMap::new();
    let room = "room@conference.example.test".to_owned();
    let original = JoinedMucMembership::new("Alice".to_owned(), Uuid::new_v4());
    memberships.insert(room.clone(), original.clone());

    // The old loop retained a shard read guard even after cloning or
    // dropping its yielded entry. Probe nonblockingly so this regression
    // can demonstrate the failure without deadlocking the test runner.
    {
        let mut live = memberships.iter();
        let entry = live.next().expect("one membership");
        drop(entry);
        assert!(memberships.try_get_mut(&room).is_locked());
    }

    let (resume, backend) = tokio::sync::oneshot::channel::<()>();
    let association = async {
        let mut owned = local_muc_membership_snapshots(&memberships).into_iter();
        let current = owned.next().expect("one owned membership");
        backend.await.expect("backend released");
        assert!(owned.next().is_none());
        current
    };
    tokio::pin!(association);
    assert!(futures::poll!(&mut association).is_pending());

    // Revocation/rejoin can take the membership's write lock while the
    // association future and its iterator are suspended on this worker.
    let replacement = JoinedMucMembership::new("Alice".to_owned(), Uuid::new_v4());
    {
        let mut current = memberships
            .try_get_mut(&room)
            .try_unwrap()
            .expect("association must release all membership guards before I/O");
        *current = replacement.clone();
    }
    resume.send(()).expect("association is pending");
    assert_eq!(association.await, (room.clone(), original));
    assert_eq!(memberships.get(&room).unwrap().value(), &replacement);
}
