use super::*;

#[tokio::test]
async fn temporary_cleanup_forwards_the_departed_incarnation() {
    let departed = MucRoomIncarnation {
        room_id: Uuid::from_u128(1),
        room_epoch: Uuid::from_u128(2),
    };
    let replacement = MucRoomIncarnation {
        room_id: Uuid::from_u128(3),
        room_epoch: Uuid::from_u128(4),
    };
    let installed = std::cell::Cell::new(departed);
    let installed_after = &installed;
    let removed = retire_departed_room(
        async {
            let resolved = installed.get();
            installed.set(replacement);
            Ok(Some(resolved))
        },
        |target| async move {
            assert_eq!(target, departed);
            assert_eq!(installed_after.get(), replacement);
            Ok(None)
        },
    )
    .await
    .unwrap();
    assert!(removed.is_none());
    assert_eq!(installed.get(), replacement);
}

#[tokio::test]
async fn temporary_cleanup_never_falls_back_to_a_room_address() {
    let removed = retire_departed_room(std::future::ready(Ok(None)), |_| async {
        panic!("a departure without an exact room must not retire anything")
    })
    .await
    .unwrap();
    assert!(removed.is_none());
}
