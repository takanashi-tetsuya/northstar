-- Durable route-wake fencing for ordered MIX delivery.
--
-- A verified local MIX resource can become available after a worker has
-- claimed the recipient head but before that worker parks it for lack of a
-- route.  A process-local wake alone cannot close that race: another process
-- can own the lease, and an UPDATE which clears that lease can otherwise
-- overwrite the newly available route with its recovery delay.
--
-- Keep the marker on the exact current recipient projection rather than on a
-- process-local broker or a shared sequence row.  Claim, route wake, defer,
-- and retry all serialize on this one recipient row, preserving the existing
-- per-recipient ordering and avoiding a new sequence-authority lock order.

ALTER TABLE mix_delivery_recipients
    ADD COLUMN route_wake_generation BIGINT NOT NULL DEFAULT 0
    CHECK (route_wake_generation >= 0);

-- The existing 0133 helper emits only the installation schema.  A route wake
-- that reaches a leased head must also notify other processes, even though it
-- does not make that row immediately claimable until its lease is released.
-- Row-level firing avoids producing a notification for a no-op wake against a
-- recipient with no durable head.
CREATE TRIGGER mix_delivery_recipients_route_wake
AFTER UPDATE OF route_wake_generation ON mix_delivery_recipients
FOR EACH ROW
WHEN (OLD.route_wake_generation IS DISTINCT FROM NEW.route_wake_generation)
EXECUTE FUNCTION northstar_mix_delivery_notify();

COMMENT ON COLUMN mix_delivery_recipients.route_wake_generation IS
    'Durable route-wake epoch captured at claim; a later wake defeats defer/retry backoff for this ordered recipient head';
COMMENT ON TRIGGER mix_delivery_recipients_route_wake ON mix_delivery_recipients IS
    'Commit-ordered schema-only wake for a durable MIX route-wake epoch change';
