pub mod http;

use crate::domain::EnergyPayload;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug)]
pub enum PublishError {
    Network(String),
    UnexpectedStatus(u16),
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(msg) => write!(f, "Erreur réseau: {}", msg),
            Self::UnexpectedStatus(code) => write!(f, "Statut HTTP inattendu: {}", code),
        }
    }
}

impl std::error::Error for PublishError {}

/// Trait définissant le contrat de publication des métriques de télémétrie
pub trait TelemetryPublisher: Send + Sync {
    fn publish<'a>(&'a self, payload: &'a EnergyPayload) -> BoxFuture<'a, Result<(), PublishError>>;
}
