use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_rustls::rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};

pub fn certificate_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let chain: Vec<_> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("cannot open TLS certificate {}", path.display()))?
        .collect::<std::result::Result<_, _>>()
        .context("invalid TLS certificate")?;
    if chain.is_empty() {
        anyhow::bail!("TLS certificate chain is empty");
    }
    Ok(chain)
}

pub fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("cannot open or decode TLS key {}", path.display()))
}

pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let chain = certificate_chain(cert_path)?;
    let key = private_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("TLS certificate/key mismatch")?;
    Ok(Arc::new(config))
}

pub struct ReloadableTlsConfig {
    config: ArcSwap<ServerConfig>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl ReloadableTlsConfig {
    pub fn new(cert_path: &Path, key_path: &Path) -> Result<Arc<Self>> {
        let config = server_config(cert_path, key_path)?;
        Ok(Arc::new(Self {
            config: ArcSwap::new(config),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
        }))
    }

    pub fn current(&self) -> Arc<ServerConfig> {
        self.config.load_full()
    }

    pub fn reload(&self) -> Result<()> {
        let new_config = server_config(&self.cert_path, &self.key_path)?;
        self.config.store(new_config);
        tracing::info!("TLS certificate reloaded successfully");
        Ok(())
    }
}
