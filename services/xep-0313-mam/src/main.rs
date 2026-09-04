//! XEP-0313 MAM Archive microservice binary entry point.
//!
//! Defined per `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, Section 5).

use foundation_service_runtime::{ServiceConfig, ServiceRuntime};
use service_xep_0313_mam::MamService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServiceConfig::new("xep-0313-mam", 50055);
    let runtime = ServiceRuntime::new(config.clone());

    println!(
        "Starting Northstar XEP-0313 MAM Archive microservice on {}:{}",
        config.host, config.port
    );

    let _mam = MamService::new();
    println!("XEP-0313 MAM Archive initialized: exclusive archive storage, Consumer Inbox deduplication, and RSM cursor pagination.");

    runtime.wait_for_shutdown_signal().await;
    println!("XEP-0313 MAM Archive shutdown gracefully.");
    Ok(())
}
