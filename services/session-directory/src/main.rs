//! Session Directory microservice binary entry point.
//!
//! Defined per `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, Section 5).

use foundation_service_runtime::{ServiceConfig, ServiceRuntime};
use service_session_directory::SessionDirectoryService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServiceConfig::new("session-directory", 50052);
    let runtime = ServiceRuntime::new(config.clone());

    println!(
        "Starting Northstar Session Directory microservice on {}:{}",
        config.host, config.port
    );

    let _session_dir = SessionDirectoryService::new();
    println!("Session Directory initialized with persistent epoch fencing authority.");

    runtime.wait_for_shutdown_signal().await;
    println!("Session Directory shutdown gracefully.");
    Ok(())
}
