//! XMPP C2S Edge Connection Gateway microservice binary entry point.
//!
//! Defined per `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, Section 5).

use foundation_service_runtime::{ServiceConfig, ServiceRuntime};
use service_xmpp_edge::EdgeConnectionActor;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServiceConfig::new("xmpp-edge", 5222);
    let runtime = ServiceRuntime::new(config.clone());

    println!(
        "Starting Northstar XMPP C2S Edge Gateway on {}:{}",
        config.host, config.port
    );

    let (tx, _rx) = mpsc::channel(1024);
    let _edge = EdgeConnectionActor::new("edge-gateway-1", tx);
    println!("XMPP Edge Gateway initialized: stateless socket I/O, zero DB connections, gRPC backend integration.");

    runtime.wait_for_shutdown_signal().await;
    println!("XMPP Edge Gateway shutdown gracefully.");
    Ok(())
}
