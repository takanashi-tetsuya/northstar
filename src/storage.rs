use anyhow::{Context, Result};
use std::{future::Future, path::PathBuf, pin::Pin};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait UploadStore: Send + Sync {
    fn put<'a>(
        &'a self,
        key: &'a str,
        stream: Box<dyn AsyncRead + Send + Unpin + 'a>,
        max_size: u64,
    ) -> StoreFuture<'a, u64>;

    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> StoreFuture<'a, Option<(Box<dyn AsyncRead + Send + Unpin + 'static>, u64)>>;

    fn delete<'a>(&'a self, key: &'a str) -> StoreFuture<'a, bool>;
}

pub struct LocalUploadStore {
    root: PathBuf,
}

impl LocalUploadStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }
}

impl UploadStore for LocalUploadStore {
    fn put<'a>(
        &'a self,
        key: &'a str,
        stream: Box<dyn AsyncRead + Send + Unpin + 'a>,
        max_size: u64,
    ) -> StoreFuture<'a, u64> {
        Box::pin(async move {
            tokio::fs::create_dir_all(&self.root)
                .await
                .with_context(|| {
                    format!("could not create upload directory {}", self.root.display())
                })?;
            let path = self.path(key);
            let temporary = path.with_extension("part");
            let mut file = tokio::fs::File::create(&temporary)
                .await
                .with_context(|| format!("could not create upload file {}", temporary.display()))?;
            let mut limited_stream = stream.take(max_size.saturating_add(1));
            let bytes_written = tokio::io::copy(&mut limited_stream, &mut file)
                .await
                .with_context(|| format!("could not write upload {}", temporary.display()))?;
            file.flush().await?;
            drop(file);
            if bytes_written != max_size {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Ok(bytes_written);
            }
            tokio::fs::rename(&temporary, &path)
                .await
                .with_context(|| format!("could not commit upload {}", path.display()))?;
            Ok(bytes_written)
        })
    }

    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> StoreFuture<'a, Option<(Box<dyn AsyncRead + Send + Unpin + 'static>, u64)>> {
        Box::pin(async move {
            match tokio::fs::File::open(self.path(key)).await {
                Ok(file) => {
                    let metadata = file.metadata().await?;
                    let size = metadata.len();
                    Ok(Some((
                        Box::new(file) as Box<dyn AsyncRead + Send + Unpin + 'static>,
                        size,
                    )))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            }
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> StoreFuture<'a, bool> {
        Box::pin(async move {
            match tokio::fs::remove_file(self.path(key)).await {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error.into()),
            }
        })
    }
}
