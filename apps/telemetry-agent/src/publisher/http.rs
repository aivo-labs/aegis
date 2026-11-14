use super::{BoxFuture, PublishError, TelemetryPublisher};
use crate::domain::EnergyPayload;
use reqwest::Client;
use std::time::Duration;

/// Client HTTP pour l'ingestion vers l'API Symfony / Aegis Gate
pub struct HttpTelemetryPublisher {
    client: Client,
    endpoint_url: String,
    api_key: String,
}

impl HttpTelemetryPublisher {
    pub fn new(endpoint_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            endpoint_url: endpoint_url.into(),
            api_key: api_key.into(),
        }
    }

    pub fn with_client(
        client: Client,
        endpoint_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            client,
            endpoint_url: endpoint_url.into(),
            api_key: api_key.into(),
        }
    }
}

impl TelemetryPublisher for HttpTelemetryPublisher {
    fn publish<'a>(&'a self, payload: &'a EnergyPayload) -> BoxFuture<'a, Result<(), PublishError>> {
        Box::pin(async move {
            let res = self
                .client
                .post(&self.endpoint_url)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .json(payload)
                .send()
                .await
                .map_err(|e| PublishError::Network(e.to_string()))?;

            let status = res.status();
            if status.is_success() || status.as_u16() == 201 {
                Ok(())
            } else {
                Err(PublishError::UnexpectedStatus(status.as_u16()))
            }
        })
    }
}
