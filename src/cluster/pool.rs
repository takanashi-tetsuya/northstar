use super::{
    ClusterPubsubListenerTransport, CLUSTER_REDIS_POOL_MAX_SIZE, REDIS_CONNECT_TIMEOUT,
    REDIS_IO_TIMEOUT,
};
use anyhow::{Context, Result};
use bb8::Pool;
use redis::AsyncCommands;

#[derive(Clone, Debug)]
pub(super) struct RedisConnectionManager {
    pub(super) client: redis::Client,
}

impl bb8::ManageConnection for RedisConnectionManager {
    type Connection = redis::aio::MultiplexedConnection;
    type Error = redis::RedisError;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        let config = redis::AsyncConnectionConfig::new()
            .set_connection_timeout(Some(REDIS_CONNECT_TIMEOUT))
            .set_response_timeout(Some(REDIS_IO_TIMEOUT));
        self.client
            .get_multiplexed_async_connection_with_config(&config)
            .await
    }

    async fn is_valid(
        &self,
        connection: &mut Self::Connection,
    ) -> std::result::Result<(), Self::Error> {
        let pong: String = redis::cmd("PING").query_async(connection).await?;
        if pong == "PONG" {
            Ok(())
        } else {
            Err((
                redis::ErrorKind::Extension,
                "Redis PING returned an invalid response",
            )
                .into())
        }
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}

pub(super) fn cluster_pool_builder<M: bb8::ManageConnection>() -> bb8::Builder<M> {
    Pool::<M>::builder()
        .max_size(CLUSTER_REDIS_POOL_MAX_SIZE)
        .connection_timeout(REDIS_IO_TIMEOUT)
        .retry_connection(false)
}

pub(super) async fn open_pubsub(client: &redis::Client) -> Result<redis::aio::PubSub> {
    tokio::time::timeout(REDIS_CONNECT_TIMEOUT, client.get_async_pubsub())
        .await
        .context("Redis PubSub connection timed out")?
        .context("failed to connect Redis PubSub")
}

pub(super) async fn subscribe_pubsub(pubsub: &mut redis::aio::PubSub, channel: &str) -> Result<()> {
    tokio::time::timeout(REDIS_IO_TIMEOUT, pubsub.subscribe(channel))
        .await
        .context("Redis PubSub subscription timed out")?
        .context("failed to subscribe Redis PubSub")
}

pub(super) async fn publish_listener_probe(
    transport: &ClusterPubsubListenerTransport,
    channel: &str,
    token: &str,
) -> Result<()> {
    let pool = transport
        .pool
        .as_ref()
        .context("Redis listener probe started without a configured pool")?;
    let mut connection = pool.get().await?;
    let receivers: usize =
        tokio::time::timeout(REDIS_IO_TIMEOUT, connection.publish(channel, token))
            .await
            .context("Redis listener self-loop publish timed out")??;
    anyhow::ensure!(receivers > 0, "Redis listener self-loop had no subscriber");
    Ok(())
}
