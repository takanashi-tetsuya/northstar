//! Identity Authority microservice binary entry point.
//!
//! Defined per `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, Section 5).

use foundation_service_runtime::{ServiceConfig, ServiceRuntime};
use service_identity::IdentityService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServiceConfig::new("identity", 50051);
    let runtime = ServiceRuntime::new(config.clone());

    println!(
        "Starting Northstar Identity Authority microservice on {}:{}",
        config.host, config.port
    );

    let domain = std::env::var("XMPP_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let _identity = IdentityService::new(domain);
    println!("Identity Service initialized with SCRAM-SHA-256 credentials authority.");

    runtime.wait_for_shutdown_signal().await;
    println!("Identity Service shutdown gracefully.");
    Ok(())
}
