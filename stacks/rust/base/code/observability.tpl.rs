// File: observability.tpl.rs
// Purpose: OpenTelemetry tracing setup using tracing + opentelemetry crates
// Generated for: {{PROJECT_NAME}}

use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_telemetry(service_name: &str, otlp_endpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint),
        )
        .with_trace_config(
            sdktrace::config().with_resource(Resource::new(vec![
                opentelemetry::KeyValue::new(SERVICE_NAME, service_name.to_string()),
            ])),
        )
        .install_batch(runtime::Tokio)?;

    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(telemetry_layer)
        .init();

    Ok(())
}

pub fn shutdown_telemetry() {
    global::shutdown_tracer_provider();
}

// Example usage with tracing macros
pub async fn example_traced_operation() {
    use tracing::{info, instrument};

    #[instrument]
    async fn inner_operation() {
        info!("Executing inner operation");
    }

    inner_operation().await;
}

// Usage:
// #[tokio::main]
// async fn main() {
//     init_telemetry("my-service", "http://localhost:4317").unwrap();
//     // ... app logic ...
//     shutdown_telemetry();
// }
