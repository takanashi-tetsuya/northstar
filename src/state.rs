use crate::s2s::FederationEnvelope;
use crate::{
    abuse::{AbuseConfig, AbuseGuard},
    config::Config,
    db,
    metrics::Metrics,
    s2s::FederationRouter,
    storage::{LocalUploadStore, UploadStore},
};
use anyhow::Context;
use dashmap::DashMap;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicI16},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct OnlineSession {
    pub sender: mpsc::Sender<String>,
    pub available: Arc<AtomicBool>,
    pub carbons: Arc<AtomicBool>,
    pub priority: Arc<AtomicI16>,
    pub blocklist_requested: Arc<AtomicBool>,
}

pub struct ResumableSession {
    pub user: db::User,
    pub full_jid: String,
    pub available: Arc<AtomicBool>,
    pub carbons: Arc<AtomicBool>,
    pub priority: Arc<AtomicI16>,
    pub blocklist_requested: Arc<AtomicBool>,
    pub inbound_h: u32,
    pub outbound_h: u32,
    pub acked_h: u32,
    pub unacked: VecDeque<String>,
    pub expires_at: Instant,
}

#[derive(Clone)]
pub struct MucOccupant {
    pub full_jid: String,
    pub room_jid: String,
    pub nick: String,
    pub sender: mpsc::Sender<String>,
    pub affiliation: String,
    pub role: String,
    pub room_non_anonymous: bool,
    pub payload: String,
}

pub struct AppState {
    pub config: Config,
    pub pool: PgPool,
    pub sessions: DashMap<String, OnlineSession>,
    pub resumable_sessions: DashMap<String, ResumableSession>,
    pub muc_occupants: DashMap<String, MucOccupant>,
    pub metrics: Metrics,
    pub upload_store: Arc<dyn UploadStore>,
    pub federation: FederationRouter,
    pub s2s_outbound_connections: DashMap<String, mpsc::Sender<FederationEnvelope>>,
    pub s2s_dns_cache: DashMap<String, (SocketAddr, Instant)>,
    pub abuse: AbuseGuard,
    pub started_at: Instant,
    pub tls: std::sync::Arc<crate::tls::ReloadableTlsConfig>,
}

impl AppState {
    pub fn new(
        config: Config,
        pool: PgPool,
        federation: FederationRouter,
    ) -> anyhow::Result<Arc<Self>> {
        let upload_store = Arc::new(LocalUploadStore::new(config.upload_dir.clone()));
        let abuse = AbuseGuard::new(AbuseConfig {
            base_work_factor: config.pow_base_work_factor,
            max_work_factor: config.pow_max_work_factor,
            window: Duration::from_secs(config.abuse_window_seconds),
            cooldown_step: Duration::from_secs(config.abuse_cooldown_seconds),
            max_wait: Duration::from_secs(config.abuse_max_wait_seconds),
        });
        let tls = crate::tls::ReloadableTlsConfig::new(&config.tls_cert_path, &config.tls_key_path)
            .context("failed to load TLS certificate and key")?;
        Ok(Arc::new(Self {
            config,
            pool,
            sessions: DashMap::new(),
            resumable_sessions: DashMap::new(),
            muc_occupants: DashMap::new(),
            metrics: Metrics::default(),
            upload_store,
            federation,
            s2s_outbound_connections: DashMap::new(),
            s2s_dns_cache: DashMap::new(),
            abuse,
            started_at: Instant::now(),
            tls,
        }))
    }

    pub fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        if jid.contains('/') {
            return self
                .sessions
                .get(&jid.to_ascii_lowercase())
                .map(|entry| vec![entry.value().clone()])
                .unwrap_or_default();
        }
        let bare = bare_jid(jid).to_ascii_lowercase();
        self.sessions
            .iter()
            .filter(|entry| bare_jid(entry.key()) == bare.as_str())
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        if jid.contains('/') {
            return self
                .sessions
                .get(&jid.to_ascii_lowercase())
                .map(|entry| vec![(entry.key().clone(), entry.value().clone())])
                .unwrap_or_default();
        }
        let bare = bare_jid(jid).to_ascii_lowercase();
        self.sessions
            .iter()
            .filter(|entry| bare_jid(entry.key()) == bare.as_str())
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub fn muc_occupants_for(&self, room_jid: &str) -> Vec<(String, MucOccupant)> {
        let room_jid = room_jid.to_ascii_lowercase();
        self.muc_occupants
            .iter()
            .filter(|entry| entry.value().room_jid.eq_ignore_ascii_case(&room_jid))
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }
}

pub fn bare_jid(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}

pub fn localpart(jid: &str) -> &str {
    bare_jid(jid).split('@').next().unwrap_or(jid)
}

pub fn jid_domain(jid: &str) -> Option<&str> {
    bare_jid(jid).split_once('@').map(|(_, domain)| domain)
}

pub fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn attr_escape(value: &str) -> String {
    xml_escape(value)
}
