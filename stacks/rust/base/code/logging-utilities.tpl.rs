// File: logging-utilities.tpl.rs
// Purpose: Structured logging setup using 'tracing'
// Generated for: {{PROJECT_NAME}}

use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use std::str::FromStr;
use anyhow::{Context, Result};

pub struct Logger;

impl Logger {
    /// Initializes the global tracing subscriber
    pub fn init(log_level: Option<&str>) -> Result<()> {
        let level = log_level
            .map(|l| Level::from_str(l).unwrap_or(Level::INFO))
            .unwrap_or(Level::INFO);

        let subscriber = FmtSubscriber::builder()
            .with_max_level(level)
            .with_thread_ids(true)
            .with_target(false)
            .with_file(true)
            .with_line_number(true)
            // Use JSON formatting in production for better parsing
            // .json() 
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .context("Failed to set global default subscriber")?;

        info!("Logging initialized at level: {}", level);
        Ok(())
    }
}

pub fn example_logging() {
    use tracing::{error, warn, info, debug, trace};

    // Standard log levels
    error!("Something went wrong");
    warn!("Watch out");
    info!("System status: normal");
    debug!("Debugging info");
    trace!("Low level trace");

    // Structured logging fields
    info!(
        user_id = 42,
        action = "login",
        success = true,
        "User logged in successfully"
    );
}
