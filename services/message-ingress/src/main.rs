//! Message Ingress Authority microservice binary entry point.
//!
//! Defined per `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, Section 5).

use foundation_service_runtime::{ServiceConfig, ServiceProfile, ServiceRuntime};
use service_message_ingress::MessageIngressService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServiceConfig::load("message-ingress", 50053, ServiceProfile::from_environment())?;
    let runtime = ServiceRuntime::new(config.clone());

    println!(
        "Starting Northstar Message Ingress Authority on {}:{}",
        config.host, config.port
    );

    let _ingress = MessageIngressService::new();
    println!("Message Ingress initialized: canonical JID authority, UUIDv7 monotonic sequence, and Outbox staging.");

    runtime.wait_for_shutdown_signal().await;
    println!("Message Ingress shutdown gracefully.");
    Ok(())
}
