use super::prepare;
use northstar_stream::local_routes::session::test_online_session;
use std::sync::atomic::Ordering;
use tokio::sync::oneshot;
use uuid::Uuid;

#[tokio::test]
async fn a_paused_projection_failure_leaves_the_old_probe_snapshot() {
    for (fail_roster, was_available) in [(true, true), (false, true), (true, false), (false, false)]
    {
        let (route, _receiver) = test_online_session(Uuid::new_v4(), 0, Uuid::new_v4(), "phone", 1);
        let old = "<presence id='old'/>".to_owned();
        let old_snapshot = was_available.then_some(Some(old));
        *route.last_presence.write().unwrap() = old_snapshot.clone().flatten();
        route.priority.store(-1, Ordering::Relaxed);
        route.available.store(was_available, Ordering::Release);
        let (entered, reached) = oneshot::channel();
        let (release, blocked) = oneshot::channel();
        let pause = async move {
            entered.send(()).unwrap();
            blocked.await.unwrap();
            anyhow::anyhow!("projection unavailable")
        };
        let pending = tokio::spawn(async move {
            let mut pause = std::pin::pin!(pause);
            let (roster_pause, hash_pause) = if fail_roster {
                (Some(pause.as_mut()), None)
            } else {
                (None, Some(pause.as_mut()))
            };
            prepare(
                "<presence id='new'><priority>9</priority></presence>",
                true,
                "alice@example.test/phone",
                async move {
                    match roster_pause {
                        Some(pause) => Err(pause.await),
                        None => Ok(()),
                    }
                },
                async move {
                    match hash_pause {
                        Some(pause) => Err(pause.await),
                        None => panic!("hash read after a failed roster read"),
                    }
                },
            )
            .await
        });
        reached.await.unwrap();
        assert_eq!(route.presence_route_state(), (was_available, -1));
        assert_eq!(route.current_presence(), old_snapshot);
        release.send(()).unwrap();
        assert!(pending.await.unwrap().is_err());
        assert_eq!(route.presence_route_state(), (was_available, -1));
        assert_eq!(route.current_presence(), old_snapshot);
    }
}
