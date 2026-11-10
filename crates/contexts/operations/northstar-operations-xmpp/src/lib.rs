//! XMPP adapter of the operations context: XEP-0050 ad-hoc commands and XEP-0133 service administration.

pub mod commands;

pub use self::session_host::OperationsSessionHost;

mod session_host;
