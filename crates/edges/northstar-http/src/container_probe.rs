//! The container healthcheck: a literal-address probe that requires `/readyz` to answer 200.

use anyhow::{Context, Result};

pub async fn container_healthcheck(address: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let address: std::net::SocketAddr = address
        .parse()
        .context("healthcheck address must be a literal IP:PORT")?;
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(address),
    )
    .await
    .context("healthcheck connection timed out")?
    .context("healthcheck connection failed")?;
    stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .context("healthcheck request failed")?;
    let response = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut response = Vec::with_capacity(128);
        let mut chunk = [0_u8; 128];
        loop {
            let bytes = stream
                .read(&mut chunk)
                .await
                .context("healthcheck response failed")?;
            if bytes == 0 {
                anyhow::bail!("healthcheck response ended before the HTTP status line");
            }
            response.extend_from_slice(&chunk[..bytes]);
            if response.windows(2).any(|bytes| bytes == b"\r\n") {
                return Ok::<_, anyhow::Error>(response);
            }
            if response.len() >= 512 {
                anyhow::bail!("healthcheck HTTP status line is too long");
            }
        }
    })
    .await
    .context("healthcheck response timed out")??;
    if response.starts_with(b"HTTP/1.1 200 ") || response.starts_with(b"HTTP/1.0 200 ") {
        Ok(())
    } else {
        anyhow::bail!("readiness endpoint did not return HTTP 200")
    }
}

#[cfg(test)]
mod tests {
    use super::container_healthcheck;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn endpoint(status: &'static str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 256];
            let bytes = stream.read(&mut request).await.unwrap();
            assert!(request[..bytes].starts_with(b"GET /readyz HTTP/1.1\r\n"));
            stream
                .write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .await
                .unwrap();
        });
        (address, task)
    }

    #[tokio::test]
    async fn container_probe_requires_the_readiness_endpoint_to_return_exactly_200() {
        let (address, server) = endpoint("200 OK").await;
        container_healthcheck(&address.to_string()).await.unwrap();
        server.await.unwrap();

        let (address, server) = endpoint("503 Service Unavailable").await;
        assert!(container_healthcheck(&address.to_string()).await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn container_probe_rejects_hostnames_and_malformed_addresses() {
        assert!(container_healthcheck("localhost:8080").await.is_err());
        assert!(container_healthcheck("127.0.0.1").await.is_err());
    }
}
