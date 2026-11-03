//! Vaultlock HTTP API — Axum-based modular monolith server.

pub mod auth;
pub mod config;
pub mod error;
pub mod health;
pub mod middleware;
pub mod router;
pub mod state;

pub use config::Config;
pub use state::AppState;
