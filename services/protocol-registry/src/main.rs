//! Protocol Registry microservice binary entry point.
//!
//! Defined per `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, Section 5).

use foundation_contracts::adapters::registry::GetRouteSnapshotRequest;
use foundation_service_runtime::{ServiceConfig, ServiceProfile, ServiceRuntime};
use service_protocol_registry::RegistryService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServiceConfig::load(
        "protocol-registry",
        50050,
        ServiceProfile::from_environment(),
    )?;
    let runtime = ServiceRuntime::new(config.clone());

    println!(
        "Starting Northstar Protocol Registry microservice on {}:{}",
        config.host, config.port
    );

    let registry = RegistryService::new().with_default_routes();
    let snapshot = registry.get_route_snapshot(GetRouteSnapshotRequest {
        since_version: 0,
        trace: None,
    });
    println!(
        "Protocol Registry initialized. Snapshot version: {}, routes count: {}",
        snapshot.snapshot_version,
        snapshot.routes.len()
    );

    runtime.wait_for_shutdown_signal().await;
    println!("Protocol Registry shutdown gracefully.");
    Ok(())
}
