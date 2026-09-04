use anyhow::{bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, TcpListener as StdTcpListener};

/// A pre-bound TCP listener that holds a socket open until handoff,
/// avoiding the port-stealing/reuse race condition.
#[derive(Debug)]
pub struct PreboundListener {
    listener: StdTcpListener,
    addr: SocketAddr,
}

impl PreboundListener {
    /// Bind a pre-bound listener on a specified address with SO_REUSEADDR.
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let domain = if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .context("failed to create socket")?;

        socket
            .set_reuse_address(true)
            .context("failed to set SO_REUSEADDR")?;
        #[cfg(unix)]
        {
            let _ = socket.set_reuse_port(true);
        }
        socket
            .set_nonblocking(true)
            .context("failed to set nonblocking")?;
        socket
            .bind(&addr.into())
            .with_context(|| format!("failed to bind listener to {addr}"))?;
        socket
            .listen(128)
            .with_context(|| format!("failed to listen on {addr}"))?;

        let listener: StdTcpListener = socket.into();
        let bound_addr = listener
            .local_addr()
            .context("failed to query bound socket local address")?;

        Ok(Self {
            listener,
            addr: bound_addr,
        })
    }

    /// Bind on an ephemeral loopback port (127.0.0.1:0).
    pub fn bind_ephemeral() -> Result<Self> {
        Self::bind("127.0.0.1:0".parse().unwrap())
    }

    /// Bound socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Bound port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Convert into a standard library `TcpListener`.
    pub fn into_std(self) -> StdTcpListener {
        self.listener
    }

    /// Convert into a Tokio async `TcpListener`.
    pub fn into_tokio(self) -> Result<tokio::net::TcpListener> {
        tokio::net::TcpListener::from_std(self.listener)
            .context("failed to convert std::net::TcpListener to tokio::net::TcpListener")
    }
}

/// Disjoint, non-overlapping port range for isolated test suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub min_port: u16,
    pub max_port: u16,
}

impl PortRange {
    pub const INTEGRATION: Self = Self {
        min_port: 34000,
        max_port: 35999,
    };
    pub const MIX_FEDERATION: Self = Self {
        min_port: 36000,
        max_port: 37999,
    };
    pub const FEDERATION: Self = Self {
        min_port: 38000,
        max_port: 39999,
    };
    pub const XEP0487: Self = Self {
        min_port: 40000,
        max_port: 41999,
    };

    pub const fn new(min_port: u16, max_port: u16) -> Self {
        Self { min_port, max_port }
    }

    /// Allocate `count` unique available pre-bound listeners within this range.
    pub fn allocate_listeners(&self, count: usize) -> Result<Vec<PreboundListener>> {
        let mut listeners = Vec::with_capacity(count);
        let span = self.max_port - self.min_port + 1;
        if (count as u16) > span {
            bail!("requested {count} ports but range only spans {span} ports");
        }

        // Deterministic pseudo-random offset based on current timestamp
        let offset = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            % span as u128) as u16;

        for i in 0..span {
            let port = self.min_port + ((offset + i) % span);
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            if let Ok(listener) = PreboundListener::bind(addr) {
                listeners.push(listener);
                if listeners.len() == count {
                    return Ok(listeners);
                }
            }
        }

        bail!(
            "could only allocate {} of {count} requested ports in range {}-{}",
            listeners.len(),
            self.min_port,
            self.max_port
        );
    }
}
