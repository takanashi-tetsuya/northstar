//! Delivery Router microservice binary entry point.
//!
//! Defined per `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, Section 5).

use foundation_service_runtime::{ServiceConfig, ServiceRuntime};
use service_delivery_router::DeliveryRouterService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServiceConfig::new("delivery-router", 50054);
    let runtime = ServiceRuntime::new(config.clone());

    println!(
        "Starting Northstar Delivery Router on {}:{}",
        config.host, config.port
    );

    let _router = DeliveryRouterService::new();
    println!("Delivery Router initialized: Consumer Inbox deduplication, online streaming to Edge, offline spool fallback.");

    runtime.wait_for_shutdown_signal().await;
    println!("Delivery Router shutdown gracefully.");
    Ok(())
}
