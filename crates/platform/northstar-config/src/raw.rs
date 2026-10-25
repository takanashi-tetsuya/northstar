//! Raw configuration as deserialized from the environment, with its serde defaults by name.

use super::*;

#[derive(Deserialize)]
pub struct RawConfig {
    #[serde(default = "default_domain")]
    pub xmpp_domain: String,

    #[serde(default = "default_server_name")]
    pub server_name: String,

    #[serde(default)]
    pub admin_addresses: Vec<String>,
    #[serde(default)]
    pub abuse_addresses: Vec<String>,
    #[serde(default)]
    pub support_addresses: Vec<String>,
    #[serde(default)]
    pub feedback_addresses: Vec<String>,
    #[serde(default)]
    pub sales_addresses: Vec<String>,
    #[serde(default)]
    pub security_addresses: Vec<String>,

    #[serde(default)]
    pub database_url: String,

    pub database_url_file: Option<PathBuf>,

    /// Dedicated no-table-access login used only to mint and manage opaque
    /// XEP-0133 command sessions. It must not be the runtime or migrator URL.
    #[serde(default)]
    pub admin_command_database_url: String,
    pub admin_command_database_url_file: Option<PathBuf>,

    /// Dedicated upload persistence credential; disabled mode never opens it.
    #[serde(default)]
    pub storage_database_url: String,
    pub storage_database_url_file: Option<PathBuf>,

    /// Optional Redis endpoint for the experimental multi-node routing layer.
    /// A normal single-node deployment does not require Redis.
    pub redis_url: Option<String>,
    pub redis_url_file: Option<PathBuf>,
    /// Optional private PKIX root and mTLS identity for a `rediss://` control
    /// plane. The client certificate and key must be configured together.
    pub redis_tls_ca_cert_path: Option<PathBuf>,
    pub redis_tls_client_cert_path: Option<PathBuf>,
    pub redis_tls_client_key_path: Option<PathBuf>,
    /// Stable operator-assigned cluster identity. Redis-enabled nodes must
    /// also mount an Ed25519 private key and an exact peer ACL document.
    pub cluster_node_id: Option<String>,
    pub cluster_signing_private_key_file: Option<PathBuf>,
    pub cluster_signing_previous_public_key_file: Option<PathBuf>,
    pub cluster_signing_staged_next_public_key_file: Option<PathBuf>,
    pub cluster_peer_keys_file: Option<PathBuf>,
    #[serde(default = "default_cluster_signing_key_epoch")]
    pub cluster_signing_key_epoch: i64,
    #[serde(default = "default_cluster_failure_policy")]
    pub cluster_failure_policy: String,
    #[serde(default = "default_cluster_safety_lease_seconds")]
    pub cluster_safety_lease_seconds: u64,

    #[serde(default = "default_db_max_connections")]
    pub database_max_connections: u32,

    pub stun_server: Option<String>,
    pub turn_server: Option<String>,
    pub turn_shared_secret: Option<String>,
    pub turn_shared_secret_file: Option<PathBuf>,
    #[serde(default = "default_turn_credentials_ttl")]
    pub turn_credentials_ttl_seconds: u64,
    #[serde(default = "default_turn_credential_requests_per_minute")]
    pub turn_credential_requests_per_minute: usize,

    #[serde(default = "default_db_min_connections")]
    pub database_min_connections: u32,

    /// Explicit escape hatch for an owner-backed local developer database.
    /// It is rejected unless every listener is loopback, Redis is absent or
    /// uses a local endpoint, and the domain is a reserved localhost/test name.
    #[serde(default)]
    pub database_allow_unsafe_role_for_development: bool,

    #[serde(default = "default_scram_iterations")]
    pub scram_iterations: u32,

    /// Explicit compatibility switch for the obsolete SCRAM-SHA-1 family.
    /// SHA-256 remains advertised first and is always enabled.
    #[serde(default)]
    pub scram_sha1_enabled: bool,

    /// XEP-0484 token derivation key. Prefer FAST_TOKEN_SECRET_FILE in
    /// production so the key never appears in the process environment.
    pub fast_token_secret: Option<String>,
    pub fast_token_secret_file: Option<PathBuf>,
    /// Development-only opt-in for a process-local FAST key. It is accepted
    /// only for a single-node, loopback, reserved-domain setup.
    #[serde(default)]
    pub fast_token_allow_ephemeral_for_development: bool,
    /// Deployment-keyed dummy SCRAM material must not share the FAST root
    /// key: independent rotation prevents a before/after account oracle.
    /// There is deliberately no inline environment-value alternative.
    pub dummy_scram_secret_file: Option<PathBuf>,
    /// Development-only opt-in for an independent process-local dummy SCRAM
    /// key. It has the same single-node/loopback/reserved-domain fence as the
    /// FAST development exception, but is enabled separately.
    #[serde(default)]
    pub dummy_scram_allow_ephemeral_for_development: bool,
    /// Stable HMAC key for de-identifying durable anti-abuse actors. Keep this
    /// separate from FAST token rotation. During rotation configure the old
    /// value as `ABUSE_STATE_HMAC_PREVIOUS_KEY(_FILE)` through the fixed
    /// 30-day tombstone floor and until every live durable old-key reference
    /// has drained.
    pub abuse_state_hmac_key: Option<String>,
    pub abuse_state_hmac_key_file: Option<PathBuf>,
    pub abuse_state_hmac_previous_key: Option<String>,
    pub abuse_state_hmac_previous_key_file: Option<PathBuf>,
    /// Monotonic deployment generation. Increment exactly once when the
    /// current key changes; a rollout with current=new and previous=old opens
    /// the PostgreSQL-authorized overlap for that next epoch.
    #[serde(default = "default_abuse_state_hmac_key_epoch")]
    pub abuse_state_hmac_key_epoch: i64,
    /// Second rotation phase. Enable with both current and previous mounted
    /// only after every node has adopted the overlap keyset. PostgreSQL then
    /// fences old-generation nodes and starts the safe retirement horizon.
    #[serde(default)]
    pub abuse_state_hmac_retire_previous: bool,
    /// Development-only opt-in for a process-local anti-abuse actor key. It is
    /// accepted only for a single-node loopback test deployment.
    #[serde(default)]
    pub abuse_state_allow_ephemeral: bool,
    /// Mounted control-plane key material. There is deliberately no direct
    /// environment-value alternative: replay encryption and idempotency HMAC
    /// keys must come from a permission-checked secret file.
    pub api_control_secret_file: Option<PathBuf>,
    pub api_control_previous_secret_file: Option<PathBuf>,
    /// Development-only opt-in for a process-local idempotency/replay key.
    /// It is rejected with Redis or a non-test/non-loopback deployment.
    #[serde(default)]
    pub api_control_allow_ephemeral: bool,
    #[serde(default = "default_fast_token_ttl")]
    pub fast_token_ttl_days: i64,
    #[serde(default = "default_fast_token_rotation")]
    pub fast_token_rotation_days: i64,
    /// Absolute lifetime of a FAST credential chain before a password/SCRAM
    /// authentication is required again. Rotations inherit, rather than
    /// reset, this deadline.
    #[serde(default = "default_fast_strong_reauth")]
    pub fast_strong_reauth_max_days: i64,

    #[serde(default = "default_sm_resume_timeout")]
    pub sm_resume_timeout_seconds: u64,

    /// Short database lease used to distinguish a live connection from a
    /// process that crashed before it could mark the stream resumable.
    #[serde(default = "default_sm_live_lease")]
    pub sm_live_lease_seconds: u64,
    #[serde(default = "default_sm_claim_lease")]
    pub sm_claim_lease_seconds: u64,
    #[serde(default = "default_sm_max_unacked_stanzas")]
    pub sm_max_unacked_stanzas: usize,
    #[serde(default = "default_sm_max_unacked_bytes")]
    pub sm_max_unacked_bytes: usize,
    /// Complete in-process XEP-0198 snapshot bound, including replay XML and
    /// all resource-scoped metadata retained for exact resume.
    #[serde(default = "default_sm_max_snapshot_bytes")]
    pub sm_max_snapshot_bytes: usize,
    /// Hard process-wide reservation for live and materialized resume state.
    /// Live streams grow an actual-byte lease before retaining more replay
    /// data; a cross-process resume temporarily reserves one maximum snapshot
    /// before the database claim and then shrinks to its measured size.
    #[serde(default = "default_sm_memory_budget_bytes")]
    pub sm_memory_budget_bytes: usize,
    /// Capacity reserved specifically for recovery-queue snapshot ownership.
    #[serde(default = "default_sm_recovery_max_bytes")]
    pub sm_recovery_max_bytes: usize,
    #[serde(default = "default_sm_recovery_max_jobs")]
    pub sm_recovery_max_jobs: usize,
    #[serde(default = "default_sm_max_resumable_sessions")]
    pub sm_max_resumable_sessions: usize,
    #[serde(default = "default_sm_ip_binding")]
    pub sm_ip_binding: String,
    #[serde(default = "default_true")]
    pub sm_require_same_device: bool,

    #[serde(default = "default_offline_message_ttl")]
    pub offline_message_ttl_days: i64,

    /// Upper bound for personal XEP-0313 history. Zero disables automated
    /// deletion; it never means immediate deletion.
    #[serde(default = "default_mam_retention_days")]
    pub mam_retention_days: i64,

    /// Upper bound for room XEP-0313 history. Zero disables automated
    /// deletion; it never means immediate deletion.
    #[serde(default = "default_muc_mam_retention_days")]
    pub muc_mam_retention_days: i64,

    #[serde(default = "default_retention_cleanup_batch_size")]
    pub retention_cleanup_batch_size: i64,

    #[serde(default = "default_retention_cleanup_interval")]
    pub retention_cleanup_interval_seconds: u64,

    /// Resolved reports and their copied evidence are removed after this many
    /// days. Pending reports/appeals are never removed. Zero disables the
    /// automated moderation purge for deployments with a legal hold.
    #[serde(default = "default_moderation_retention_days")]
    pub moderation_retention_days: i64,

    /// Insert-only administrative audit history is removed only through the
    /// bounded database cleanup gate after this many days. Unlike content
    /// retention, zero is not accepted: the audit policy must be explicit and
    /// finite so that privacy-sensitive operational metadata cannot grow
    /// forever.
    #[serde(default = "default_audit_log_retention_days")]
    pub audit_log_retention_days: i64,

    #[serde(default = "default_offline_max_messages")]
    pub offline_max_messages_per_account: i64,

    #[serde(default = "default_offline_max_bytes")]
    pub offline_max_bytes_per_account: i64,

    #[serde(default = "default_xmpp_bind")]
    pub xmpp_bind: SocketAddr,

    #[serde(default = "default_xmpps_bind")]
    pub xmpps_bind: SocketAddr,

    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,

    /// Explicitly enables nonce-bound, child-owned listener readiness records
    /// for hermetic test fixtures. It is rejected outside loopback reserved
    /// domains and is never enabled by a production default.
    #[serde(default)]
    pub test_listener_activation: bool,
    pub test_readiness_file: Option<PathBuf>,
    pub test_readiness_nonce: Option<String>,

    /// Public HTTP capability switches. Routes for disabled capabilities are
    /// not installed at all; handlers therefore cannot be reached through an
    /// alternate path or an accidental static-file fallback.
    #[serde(default = "default_true")]
    pub rest_api_enabled: bool,
    #[serde(default = "default_true")]
    pub websocket_enabled: bool,
    #[serde(default = "default_true")]
    pub web_client_enabled: bool,
    #[serde(default = "default_upload_mode")]
    pub upload_mode: UploadMode,

    /// The administration application and its API have a dedicated listener.
    /// It is loopback-only by default. A non-loopback bind must sit behind a
    /// trusted HTTPS proxy which injects the mounted gateway credential.
    #[serde(default = "default_true")]
    pub web_admin_enabled: bool,
    #[serde(default = "default_web_admin_bind")]
    pub web_admin_bind: SocketAddr,
    pub web_admin_gateway_token_file: Option<PathBuf>,

    /// Dedicated observability listener. It is intentionally separate from
    /// the public HTTP/WebSocket listener so database-backed collection cannot
    /// be exposed accidentally by a custom reverse proxy.
    #[serde(default = "default_metrics_bind")]
    pub metrics_bind: SocketAddr,
    /// Optional bearer credential for the metrics listener. A non-loopback
    /// metrics bind is rejected unless this protected file is configured.
    pub metrics_bearer_token_file: Option<PathBuf>,

    /// Enables XEP-0124/XEP-0206 on `/http-bind` and `/bosh`. Production
    /// clients are accepted only when the HTTP request is known to have
    /// arrived through HTTPS at a trusted reverse proxy.
    #[serde(default = "default_false")]
    pub bosh_enabled: bool,
    #[serde(default = "default_bosh_max_sessions")]
    pub bosh_max_sessions: usize,
    #[serde(default = "default_bosh_max_body_reads")]
    pub bosh_max_concurrent_body_reads: usize,
    #[serde(default = "default_bosh_body_read_timeout")]
    pub bosh_body_read_timeout_seconds: u64,
    #[serde(default = "default_bosh_max_wait")]
    pub bosh_max_wait_seconds: u64,
    #[serde(default = "default_bosh_inactivity")]
    pub bosh_inactivity_seconds: u64,
    #[serde(default = "default_bosh_polling")]
    pub bosh_polling_seconds: u64,
    #[serde(default = "default_bosh_max_pause")]
    pub bosh_max_pause_seconds: u64,
    #[serde(default = "default_bosh_max_request_bytes")]
    pub bosh_max_request_bytes: usize,
    #[serde(default = "default_bosh_max_response_bytes")]
    pub bosh_max_response_bytes: usize,
    #[serde(default = "default_bosh_max_stanzas")]
    pub bosh_max_stanzas_per_request: usize,
    #[serde(default = "default_bosh_output_stanzas")]
    pub bosh_max_output_stanzas: usize,
    #[serde(default = "default_bosh_output_bytes")]
    pub bosh_max_output_bytes: usize,

    #[serde(default = "default_tls_cert_path")]
    pub tls_cert_path: PathBuf,

    #[serde(default = "default_tls_key_path")]
    pub tls_key_path: PathBuf,

    /// Pre-fetched DER OCSP response for the configured server certificate.
    /// When present, an expired response closes new TLS handshakes until reload.
    pub tls_ocsp_response_path: Option<PathBuf>,

    /// Dedicated PKIX roots for optional C2S client-certificate
    /// authentication. System/federation roots are intentionally not reused.
    pub c2s_client_trust_root_cert_path: Option<PathBuf>,

    /// Optional local CRLs for C2S client-certificate authentication. When
    /// configured, revocation status is fail-closed for the complete path.
    pub c2s_client_crl_path: Option<PathBuf>,

    #[serde(default = "default_true")]
    pub open_registration: bool,

    #[serde(default = "default_true")]
    pub require_encrypted_archive: bool,

    #[serde(default = "default_registration_rate")]
    pub registration_rate_per_hour: u32,

    #[serde(default = "default_false")]
    pub invitation_required: bool,

    #[serde(default = "default_pow_base")]
    pub pow_base_work_factor: u64,

    #[serde(default = "default_pow_max")]
    pub pow_max_work_factor: u64,

    #[serde(default = "default_message_free_burst")]
    pub abuse_message_free_burst: usize,

    #[serde(default = "default_pow_max_device_seconds")]
    pub pow_max_device_seconds: u64,

    /// Optional RFC 3339 UTC deadline for accepting legacy challenges which
    /// are not bound to method/path/body. Unset means v2-only. This is a
    /// migration deadline, not a permanent compatibility switch.
    pub pow_v1_compatibility_until: Option<String>,

    #[serde(default = "default_abuse_window")]
    pub abuse_window_seconds: u64,

    #[serde(default = "default_abuse_cooldown")]
    pub abuse_cooldown_seconds: u64,

    #[serde(default = "default_abuse_wait")]
    pub abuse_max_wait_seconds: u64,

    #[serde(default = "default_trusted_ips")]
    pub trusted_proxy_ips: String,

    #[serde(default = "default_session_ttl")]
    pub session_ttl_hours: i64,

    #[serde(default = "default_max_client_connections")]
    pub max_client_connections: usize,

    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,

    #[serde(default = "default_max_sessions_per_account")]
    pub max_sessions_per_account: usize,

    /// Monotonic PostgreSQL authority epoch for deployment-wide resource
    /// ceilings. Every node must present the same values at one epoch; changing
    /// a ceiling requires incrementing this value exactly once for the rollout.
    #[serde(default = "default_deployment_capacity_epoch")]
    pub deployment_capacity_epoch: i64,

    #[serde(default = "default_max_accounts_total")]
    pub max_accounts_total: i64,

    #[serde(default = "default_max_muc_rooms_total")]
    pub max_muc_rooms_total: i64,

    #[serde(default = "default_max_muc_rooms_per_owner")]
    pub max_muc_rooms_per_owner: i64,

    #[serde(default = "default_max_live_sessions_total")]
    pub max_live_sessions_total: i64,

    /// PostgreSQL lease for a committed live binding. Missing heartbeats never
    /// lower a counter directly: maintenance first deletes the expired
    /// authoritative lease, whose trigger releases the exact shard allocation.
    #[serde(default = "default_capacity_session_lease")]
    pub capacity_session_lease_seconds: u64,

    #[serde(default = "default_capacity_session_heartbeat")]
    pub capacity_session_heartbeat_seconds: u64,

    #[serde(default = "default_unauthenticated_timeout")]
    pub unauthenticated_timeout_seconds: u64,

    /// Maximum time after successful SASL for a legacy/unbound stream to bind
    /// a resource. SASL2 Bind 2 and successful inline SM resume are already
    /// bound and therefore never enter this deadline state.
    #[serde(default = "default_resource_bind_timeout")]
    pub resource_bind_timeout_seconds: u64,

    #[serde(default = "default_pubsub_max_nodes_per_owner")]
    pub pubsub_max_nodes_per_owner: i64,

    #[serde(default = "default_pep_max_nodes_per_account")]
    pub pep_max_nodes_per_account: i64,

    #[serde(default = "default_pubsub_max_storage_per_owner")]
    pub pubsub_max_storage_bytes_per_owner: i64,

    #[serde(default = "default_pep_max_storage_per_account")]
    pub pep_max_storage_bytes_per_account: i64,

    /// Enables the Deferred XEP-0408 partial-mirror discovery model. The
    /// default remains false: MUC and MIX are independent services unless an
    /// operator deliberately opts into linking same-owner entities.
    #[serde(default = "default_false")]
    pub mix_muc_mirror_enabled: bool,

    pub bootstrap_admin_username: Option<String>,
    pub bootstrap_admin_password: Option<String>,
    pub bootstrap_admin_password_file: Option<PathBuf>,

    /// Enables XEP-0133 restart/shutdown commands.  Kept separate from the
    /// HTTP factory-reset switch and disabled by default.
    #[serde(default = "default_false")]
    pub enable_xmpp_service_control: bool,

    /// XEP-0133 active/idle boundary based on the last accepted client stanza.
    #[serde(default = "default_admin_idle_seconds")]
    pub admin_idle_seconds: u64,

    pub public_url: Option<String>,

    /// Additional browser origins allowed to open the XMPP WebSocket. The
    /// origin derived from PUBLIC_URL is always implicit; native clients that
    /// omit Origin are unaffected.
    #[serde(default)]
    pub websocket_allowed_origins: String,

    /// Explicit public addresses for XEP-0487. The experimental host-meta v2
    /// marker is emitted only when this list is non-empty, because every
    /// advertised link is required to contain at least one literal IP.
    #[serde(default)]
    pub xep_0487_ips: String,

    #[serde(default = "default_xep_0487_ttl")]
    pub xep_0487_ttl_seconds: u64,

    #[serde(default = "default_xep_0487_priority")]
    pub xep_0487_priority: u16,

    #[serde(default = "default_xep_0487_weight")]
    pub xep_0487_weight: u16,

    /// Independently compiled, runtime-resolved XEP modules. Defaults preserve
    /// the protocol surface from releases before modularization.
    #[serde(default = "default_true")]
    pub xep_0016_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0045_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0059_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0085_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0092_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0115_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0060_enabled: bool,
    /// XEP-0092 requires an operator choice before disclosing the host OS.
    /// This defaults to the historical behavior for upgrade compatibility.
    #[serde(default = "default_true")]
    pub xep_0092_include_os: bool,
    #[serde(default = "default_true")]
    pub xep_0184_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0191_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0198_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0199_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0202_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0215_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0280_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0313_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0352_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0357_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0359_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0363_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0308_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0333_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0380_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0444_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0461_enabled: bool,

    #[serde(default = "default_upload_dir")]
    pub upload_dir: PathBuf,

    /// `local` is the secure single-node baseline. `s3` uses the maintained
    /// object_store AWS client and immutable attempt-qualified keys.
    #[serde(default = "default_upload_storage_backend")]
    pub upload_storage_backend: String,
    pub upload_s3_endpoint: Option<String>,
    #[serde(default = "default_upload_s3_region")]
    pub upload_s3_region: String,
    pub upload_s3_bucket: Option<String>,
    #[serde(default = "default_upload_s3_cleanup_mode")]
    pub upload_s3_cleanup_mode: String,
    #[serde(default = "default_upload_s3_prefix")]
    pub upload_s3_prefix: String,
    #[serde(default)]
    pub upload_s3_path_style: bool,
    #[serde(default)]
    pub upload_s3_allow_http: bool,
    #[serde(default = "default_upload_s3_credential_mode")]
    pub upload_s3_credential_mode: String,
    pub upload_s3_credential_bundle_file: Option<PathBuf>,
    pub upload_s3_access_key_id_file: Option<PathBuf>,
    pub upload_s3_secret_access_key_file: Option<PathBuf>,
    pub upload_s3_session_token_file: Option<PathBuf>,
    pub upload_s3_sse_kms_key_id_file: Option<PathBuf>,

    #[serde(default = "default_upload_max")]
    pub upload_max_bytes: u64,
    /// Independent immutable-read ceiling. It may be raised for historical
    /// objects without reopening slot admission in drain-read-only mode.
    #[serde(default = "default_upload_download_max_bytes")]
    pub upload_download_max_bytes: u64,

    #[serde(default = "default_upload_max_files_per_user")]
    pub upload_max_files_per_user: i64,

    #[serde(default = "default_upload_max_bytes_per_user")]
    pub upload_max_bytes_per_user: i64,

    #[serde(default = "default_upload_download_concurrency")]
    pub upload_download_max_concurrent: usize,

    #[serde(default = "default_upload_download_per_ip")]
    pub upload_download_max_per_ip: usize,

    #[serde(default = "default_upload_download_read_timeout")]
    pub upload_download_read_timeout_seconds: u64,

    #[serde(default = "default_upload_download_max_seconds")]
    pub upload_download_max_seconds: u64,

    #[serde(default = "default_upload_storage_max_pending_jobs")]
    pub upload_storage_max_pending_jobs: i64,

    #[serde(default = "default_upload_storage_max_retained_files")]
    pub upload_storage_max_retained_files: i64,

    #[serde(default = "default_upload_storage_max_retained_bytes")]
    pub upload_storage_max_retained_bytes: i64,

    #[serde(default = "default_upload_retention_seconds")]
    pub upload_retention_seconds: u64,

    #[serde(default = "default_s2s_bind")]
    pub s2s_bind: SocketAddr,

    #[serde(default = "default_s2s_tls_bind")]
    pub s2s_tls_bind: SocketAddr,

    #[serde(default = "default_max_s2s_connections")]
    pub max_s2s_connections: usize,

    #[serde(default = "default_component_bind")]
    pub component_bind: SocketAddr,

    #[serde(default = "default_false")]
    pub components_enabled: bool,

    pub components_config_file: Option<PathBuf>,

    #[serde(default = "default_max_component_connections")]
    pub max_component_connections: usize,

    #[serde(default = "default_component_handshake_timeout")]
    pub component_handshake_timeout_seconds: u64,

    #[serde(default = "default_component_queue_capacity")]
    pub component_queue_capacity: usize,

    /// Maximum lifetime of a stanza waiting for a remote federation peer.
    #[serde(default = "default_s2s_outbox_ttl")]
    pub s2s_outbox_ttl_seconds: u64,

    #[serde(default = "default_s2s_outbox_max_rows")]
    pub s2s_outbox_max_rows: i64,

    #[serde(default = "default_s2s_outbox_max_bytes")]
    pub s2s_outbox_max_bytes: i64,

    #[serde(default = "default_s2s_outbox_max_per_domain")]
    pub s2s_outbox_max_per_domain: i64,

    #[serde(default = "default_s2s_outbox_retry_base")]
    pub s2s_outbox_retry_base_seconds: u64,

    #[serde(default = "default_s2s_outbox_retry_max")]
    pub s2s_outbox_retry_max_seconds: u64,

    #[serde(default = "default_s2s_outbox_max_attempts")]
    pub s2s_outbox_max_attempts: i32,

    #[serde(default = "default_s2s_outbox_claim_batch")]
    pub s2s_outbox_claim_batch: i64,

    #[serde(default = "default_s2s_outbox_lease")]
    pub s2s_outbox_lease_seconds: u64,

    #[serde(default = "default_true")]
    pub federation_enabled: bool,

    /// Prefer certificate-authenticated SASL EXTERNAL for S2S. This switch is
    /// primarily useful for interoperability tests and legacy deployments.
    #[serde(default = "default_true")]
    pub s2s_sasl_external_enabled: bool,

    /// Enable TLS-protected, callback-verified XEP-0220 as a compatibility
    /// fallback when SASL EXTERNAL is unavailable.
    #[serde(default = "default_true")]
    pub dialback_enabled: bool,

    pub dialback_secret: Option<String>,
    pub dialback_secret_file: Option<PathBuf>,

    #[serde(default)]
    pub federation_allowlist: String,

    #[serde(default)]
    pub federation_denylist: String,

    #[serde(default = "default_false")]
    pub federation_allow_private_ips: bool,

    #[serde(default)]
    pub federation_dns_overrides: String,

    pub federation_extra_root_cert_path: Option<PathBuf>,

    /// Local RFC 5280 CRLs used by outbound and inbound certificate-
    /// authenticated federation, and by XEP-0487 HTTPS discovery.
    pub federation_crl_path: Option<PathBuf>,

    /// Require a fresh, verified OCSP staple for outbound PKIX-authenticated
    /// S2S handshakes. DANE-EE keeps its independent DNSSEC trust policy.
    #[serde(default = "default_false")]
    pub federation_ocsp_staple_required: bool,

    /// RFC 7712 DNSSEC/DANE policy: off, opportunistic, or required.
    #[serde(default = "default_federation_dane_mode")]
    pub federation_dane_mode: String,

    /// Explicit lab.test DNSKEY trust anchor for isolated required-DANE tests.
    /// Ordinary federation always uses the resolver's default root anchors.
    pub federation_dnssec_lab_trust_anchor_path: Option<PathBuf>,

    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,

    #[serde(default = "default_log_rotation")]
    pub log_rotation: String,

    #[serde(default = "default_log_format")]
    pub log_format: String,

    #[serde(default = "default_log_retention")]
    pub log_retention_files: usize,
}
