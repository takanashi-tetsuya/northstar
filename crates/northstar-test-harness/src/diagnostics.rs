use anyhow::{bail, Result};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Check if a local TCP port is accepting connections.
pub fn is_port_listening(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok()
}

/// Wait until a TCP port begins listening, or return error on timeout.
pub fn wait_for_port(port: u16, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if is_port_listening(port) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("timed out waiting for port {port} to begin listening");
}

/// Wait until a TCP port stops listening, or return error on timeout.
pub fn wait_for_port_closed(port: u16, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if !is_port_listening(port) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("timed out waiting for port {port} to close");
}
