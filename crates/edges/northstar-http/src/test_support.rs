//! Coordination between tests that run in parallel in this crate's unit-test binary.

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Orders child processes against tests that prove the kernel released one of their sockets.
///
/// Spawning a child copies every open descriptor of this test binary into the child, and the
/// child holds them until its `exec` closes the close-on-exec ones. A socket that another test
/// drops inside that window stays open in the child: a dropped listener keeps completing
/// handshakes into its backlog, and a dropped stream sends no FIN. A test that asserts such a
/// close holds a shared guard from before it opens those sockets until its assertion; a test
/// that spawns holds the exclusive guard until every child it spawned has exited. No child can
/// then hold a copy of a socket whose close a test asserts.
static CHILD_PROCESS_FENCE: RwLock<()> = RwLock::const_new(());

/// Held from before a test opens the sockets whose close it asserts until that assertion.
pub(crate) async fn socket_close_guard() -> RwLockReadGuard<'static, ()> {
    CHILD_PROCESS_FENCE.read().await
}

/// Held from before a test spawns a child process until every child it spawned has exited.
pub(crate) async fn child_process_guard() -> RwLockWriteGuard<'static, ()> {
    CHILD_PROCESS_FENCE.write().await
}
