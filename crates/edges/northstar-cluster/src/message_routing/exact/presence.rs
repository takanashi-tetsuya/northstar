use crate::delivery_contract::session_route_keys;
use crate::{ClusterManager, Pool, RedisConnectionManager, SESSION_TTL_SECONDS};
use anyhow::Result;
use northstar_message_application::messaging::ExactMessageRoute;
use uuid::Uuid;

impl ClusterManager {
    pub async fn publish_route_presence(
        &self,
        full_jid: &str,
        connection_id: Uuid,
        available: bool,
        priority: i16,
        seq: u64,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let (full_jid, _) = session_route_keys(full_jid)?;
        let mut conn = pool.get().await?;
        let script = redis::Script::new(
            r#"
            if redis.call('get', KEYS[1]) ~= ARGV[1] or redis.call('get', KEYS[2]) ~= ARGV[2] then
                return 0
            end
            local current = redis.call('get', KEYS[3])
            if current then
                local instance, seq = string.match(current, '^([^|]+)|[01]|%-?%d+|(%d+)$')
                if instance == ARGV[2] and (#seq > #ARGV[5] or (#seq == #ARGV[5] and seq >= ARGV[5])) then
                    return 0
                end
            end
            redis.call('set', KEYS[3], ARGV[2] .. '|' .. ARGV[3] .. '|' .. ARGV[4] .. '|' .. ARGV[5], 'EX', ARGV[6])
            return 1
            "#,
        );
        let _: i32 = script
            .key(self.key(format!("session:{full_jid}")))
            .key(self.key(format!("session_instance:{full_jid}")))
            .key(self.key(format!("session_presence:{full_jid}")))
            .arg(&self.node_id)
            .arg(connection_id.to_string())
            .arg(u8::from(available))
            .arg(priority)
            .arg(seq)
            .arg(SESSION_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(())
    }

    pub(super) async fn read_remote_route_presence(
        &self,
        pool: &Pool<RedisConnectionManager>,
        routes: &mut [ExactMessageRoute],
    ) -> Result<()> {
        if routes.is_empty() {
            return Ok(());
        }
        let keys: Vec<_> = routes
            .iter()
            .map(|route| self.key(format!("session_presence:{}", route.full_jid)))
            .collect();
        // One pipelined GET per key: the runtime Redis ACL grants GET but
        // not MGET, and every record is checked against its own connection.
        let mut pipe = redis::pipe();
        for key in &keys {
            pipe.get(key);
        }
        let mut conn = pool.get().await?;
        let records: Vec<Option<String>> = pipe.query_async(&mut *conn).await?;
        for (route, record) in routes.iter_mut().zip(records) {
            if let Some((available, priority)) = record
                .as_deref()
                .and_then(|record| exact_presence(record, route.connection_id))
            {
                route.priority = Some(priority);
                route.available = Some(available);
            }
        }
        Ok(())
    }
}

fn exact_presence(record: &str, connection_id: Uuid) -> Option<(bool, i16)> {
    let mut fields = record.split('|');
    if fields.next()?.parse::<Uuid>().ok()? != connection_id {
        return None;
    }
    let available = match fields.next()? {
        "0" => false,
        "1" => true,
        _ => return None,
    };
    let priority = fields.next()?.parse().ok()?;
    fields.next()?.parse::<u64>().ok()?;
    fields.next().is_none().then_some((available, priority))
}

#[cfg(test)]
#[path = "../../tests/route_presence_redis.rs"]
mod tests;
