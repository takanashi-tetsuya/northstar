//! Set up the Redis subscription and handle each selected listener input.

use super::*;
use northstar_runtime::workers::WorkerHeartbeat;
use northstar_telemetry::metrics::DurationTimer;

pub(super) struct ListenerSubscription<'a> {
    pub(super) redis_setup_timer: Option<DurationTimer<'a>>,
    pub(super) pubsub_conn: redis::aio::PubSub,
    pub(super) channel: String,
    pub(super) probe_channel: String,
}

pub(super) async fn subscribe_listener<'a, A: ClusterAdapters>(
    client: &redis::Client,
    transport: &ClusterPubsubListenerTransport,
    message_policy: &'a ClusterListenerMessagePolicy<A>,
) -> Result<ListenerSubscription<'a>> {
    let redis_setup_timer = Some(message_policy.start_redis_setup_timer());
    let mut pubsub_conn = open_pubsub(client).await?;
    let channel = transport.key(format!("node:{}", transport.node_id));
    let probe_channel = transport.key(format!(
        "listener_probe:{}:{}:{}",
        transport.node_id,
        transport.connection_uuid,
        transport.instance_epoch.load(Ordering::Acquire)
    ));
    subscribe_pubsub(&mut pubsub_conn, &channel).await?;
    subscribe_pubsub(&mut pubsub_conn, &probe_channel).await?;
    Ok(ListenerSubscription {
        redis_setup_timer,
        pubsub_conn,
        channel,
        probe_channel,
    })
}

pub(super) type ListenerProbe = (String, tokio::time::Instant, bool);

pub(super) async fn start_listener_probe(
    transport: &ClusterPubsubListenerTransport,
    probe_channel: &str,
) -> Result<(Option<ListenerProbe>, tokio::time::Interval)> {
    let initial_probe = uuid::Uuid::new_v4().to_string();
    publish_listener_probe(transport, probe_channel, &initial_probe).await?;
    let pending_probe = Some((
        initial_probe,
        tokio::time::Instant::now() + REDIS_CONNECT_TIMEOUT,
        true,
    ));
    let mut liveness = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(15),
        Duration::from_secs(15),
    );
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    Ok((pending_probe, liveness))
}

pub(super) enum ListenerInput {
    ProbeDue,
    ProbeTimedOut,
    Message(Option<redis::Msg>),
    ResponseComplete(Option<Result<()>>),
}

pub(super) struct ListenerInputContext<'a, 'metrics> {
    pub(super) transport: &'a ClusterPubsubListenerTransport,
    pub(super) probe_channel: &'a str,
    pub(super) channel: &'a str,
    pub(super) pending_probe: &'a mut Option<ListenerProbe>,
    pub(super) redis_setup_timer: &'a mut Option<DurationTimer<'metrics>>,
    pub(super) heartbeat: &'a WorkerHeartbeat,
}

pub(super) enum ReceivedListenerInput {
    Payload(String),
    Continue,
    Return(Result<()>),
}

pub(super) async fn receive_listener_payload(
    input: ListenerInput,
    context: ListenerInputContext<'_, '_>,
    (candidate_generation, rotation_epoch): (u64, u64),
) -> Result<ReceivedListenerInput> {
    let ListenerInputContext {
        transport,
        probe_channel,
        channel,
        pending_probe,
        redis_setup_timer,
        heartbeat,
    } = context;
    let message = match input {
        ListenerInput::ResponseComplete(result) => {
            result.context("Redis listener response set ended unexpectedly")??;
            return Ok(ReceivedListenerInput::Continue);
        }
        ListenerInput::ProbeDue => {
            anyhow::ensure!(
                pending_probe.is_none(),
                "Redis PubSub self-loop probe remained outstanding"
            );
            let token = uuid::Uuid::new_v4().to_string();
            publish_listener_probe(transport, probe_channel, &token).await?;
            *pending_probe = Some((
                token,
                tokio::time::Instant::now() + REDIS_CONNECT_TIMEOUT,
                false,
            ));
            return Ok(ReceivedListenerInput::Continue);
        }
        ListenerInput::ProbeTimedOut => {
            anyhow::bail!("Redis PubSub publish/subscription self-loop timed out")
        }
        ListenerInput::Message(message) => message,
    };
    let Some(message) = message else {
        return Ok(ReceivedListenerInput::Return(Ok(())));
    };
    let received_channel = message.get_channel_name().to_owned();
    let Ok(payload) = message.get_payload::<String>() else {
        return Ok(ReceivedListenerInput::Continue);
    };
    if received_channel == probe_channel {
        if pending_probe
            .as_ref()
            .is_some_and(|(token, _, _)| token == &payload)
        {
            let (_, _, establishing) = pending_probe.take().expect("probe was present");
            if establishing {
                transport.confirm_generation(candidate_generation, rotation_epoch)?;
                drop(redis_setup_timer.take());
            }
            heartbeat.ok();
        }
        return Ok(ReceivedListenerInput::Continue);
    }
    anyhow::ensure!(
        received_channel == channel,
        "Redis PubSub listener received an unexpected channel"
    );
    if pending_probe
        .as_ref()
        .is_some_and(|(_, _, establishing)| *establishing)
    {
        // Do not consume signature replay records or execute node commands
        // until this subscription has proved its own publish/receive path.
        // Durable deliveries remain eligible for their normal retry.
        return Ok(ReceivedListenerInput::Continue);
    }
    Ok(ReceivedListenerInput::Payload(payload))
}
