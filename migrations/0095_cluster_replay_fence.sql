CREATE TABLE cluster_signed_envelope_replays (
 namespace TEXT NOT NULL, source_node TEXT NOT NULL, source_instance_uuid UUID NOT NULL,
 source_instance_epoch BIGINT NOT NULL, source_key_id TEXT NOT NULL, source_key_epoch BIGINT NOT NULL,
 destination_node TEXT NOT NULL, destination_instance_uuid UUID NOT NULL,
 destination_instance_epoch BIGINT NOT NULL, destination_key_id TEXT NOT NULL,
 destination_key_epoch BIGINT NOT NULL, event_id UUID NOT NULL,
 channel_sha256 BYTEA NOT NULL CHECK(octet_length(channel_sha256)=32),
 payload_sha256 TEXT NOT NULL CHECK(octet_length(payload_sha256) BETWEEN 16 AND 128),
 expires_at TIMESTAMPTZ NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(namespace,source_node,source_instance_uuid,source_instance_epoch,
 destination_node,destination_instance_uuid,destination_instance_epoch,event_id),
 UNIQUE(namespace,source_node,source_instance_uuid,source_instance_epoch,destination_node,event_id)
);
CREATE INDEX cluster_signed_envelope_replays_expiry_idx ON cluster_signed_envelope_replays(expires_at,event_id);

CREATE FUNCTION northstar_admit_cluster_envelope_replay(
 p_namespace TEXT,p_source_node TEXT,p_source_uuid UUID,p_source_epoch BIGINT,
 p_source_key_id TEXT,p_source_key_epoch BIGINT,p_destination_node TEXT,
 p_destination_uuid UUID,p_destination_epoch BIGINT,p_destination_key_id TEXT,
 p_destination_key_epoch BIGINT,p_event_id UUID,p_channel_sha256 BYTEA,
 p_payload_sha256 TEXT,p_expires_at TIMESTAMPTZ) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE existing cluster_signed_envelope_replays%ROWTYPE;
BEGIN
 IF p_expires_at<=clock_timestamp()-INTERVAL '5 seconds' OR p_expires_at>clock_timestamp()+INTERVAL '30 seconds' THEN
  RAISE EXCEPTION 'cluster replay validity window rejected';
 END IF;
 PERFORM 1 FROM cluster_node_instances i
   WHERE i.xmpp_domain=p_namespace AND i.node_id=p_source_node
    AND i.instance_uuid=p_source_uuid AND i.instance_epoch=p_source_epoch
    AND i.signing_key_id=p_source_key_id AND i.signing_key_epoch=p_source_key_epoch
    AND i.lease_until>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'cluster replay source instance is not authoritative';
 END IF;
 PERFORM 1 FROM cluster_node_instances i
   WHERE i.xmpp_domain=p_namespace AND i.node_id=p_destination_node
    AND i.instance_uuid=p_destination_uuid AND i.instance_epoch=p_destination_epoch
    AND i.signing_key_id=p_destination_key_id AND i.signing_key_epoch=p_destination_key_epoch
    AND i.lease_until>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'cluster replay destination instance is not authoritative';
 END IF;
 INSERT INTO cluster_signed_envelope_replays VALUES(
  p_namespace,p_source_node,p_source_uuid,p_source_epoch,p_source_key_id,p_source_key_epoch,
  p_destination_node,p_destination_uuid,p_destination_epoch,p_destination_key_id,
  p_destination_key_epoch,p_event_id,p_channel_sha256,p_payload_sha256,p_expires_at,clock_timestamp())
 ON CONFLICT DO NOTHING;
 IF FOUND THEN RETURN TRUE; END IF;
 SELECT * INTO existing FROM cluster_signed_envelope_replays
  WHERE namespace=p_namespace AND source_node=p_source_node AND source_instance_uuid=p_source_uuid
   AND source_instance_epoch=p_source_epoch AND destination_node=p_destination_node
   AND event_id=p_event_id FOR UPDATE;
 IF existing.payload_sha256<>p_payload_sha256 OR existing.channel_sha256<>p_channel_sha256
    OR existing.source_key_id<>p_source_key_id OR existing.source_key_epoch<>p_source_key_epoch
    OR existing.destination_instance_uuid<>p_destination_uuid
    OR existing.destination_instance_epoch<>p_destination_epoch
    OR existing.destination_key_id<>p_destination_key_id OR existing.destination_key_epoch<>p_destination_key_epoch THEN
  RAISE EXCEPTION 'cluster replay identity conflict';
 END IF;
 RETURN FALSE;
END $$;

CREATE FUNCTION northstar_cleanup_cluster_envelope_replays(p_limit INTEGER) RETURNS BIGINT LANGUAGE SQL AS $$
WITH expired AS MATERIALIZED (
 SELECT namespace,source_node,source_instance_uuid,source_instance_epoch,destination_node,
        destination_instance_uuid,destination_instance_epoch,event_id
 FROM cluster_signed_envelope_replays WHERE expires_at<clock_timestamp()-INTERVAL '30 seconds'
 ORDER BY expires_at,event_id LIMIT LEAST(GREATEST(p_limit,1),10000) FOR UPDATE SKIP LOCKED
), removed AS (
 DELETE FROM cluster_signed_envelope_replays r USING expired e
 WHERE (r.namespace,r.source_node,r.source_instance_uuid,r.source_instance_epoch,r.destination_node,
        r.destination_instance_uuid,r.destination_instance_epoch,r.event_id)=
       (e.namespace,e.source_node,e.source_instance_uuid,e.source_instance_epoch,e.destination_node,
        e.destination_instance_uuid,e.destination_instance_epoch,e.event_id) RETURNING 1)
SELECT COUNT(*) FROM removed
$$;
