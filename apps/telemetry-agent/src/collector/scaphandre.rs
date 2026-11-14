use super::{BoxFuture, PowerSensor, SensorContext};
use regex::Regex;
use reqwest::Client;
use std::time::Duration;

/// Capteur Prometheus interrogeant la sonde locale Scaphandre
pub struct ScaphandreSensor {
    client: Client,
    metrics_url: String,
    regex: Regex,
}

impl ScaphandreSensor {
    pub fn new(metrics_url: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new());

        let regex = Regex::new(r"scaphandre_host_power_microwatts\s+([0-9\.]+)")
            .expect("Regex Scaphandre valide");

        Self {
            client,
            metrics_url: metrics_url.into(),
            regex,
        }
    }

    /// Parse le texte des métriques Prometheus pour extraire la puissance en Watts
    pub fn parse_metrics_text(regex: &Regex, body: &str) -> Option<f64> {
        let caps = regex.captures(body)?;
        let val_str = caps.get(1)?.as_str();
        let microwatts: f64 = val_str.parse().ok()?;
        Some(microwatts / 1_000_000.0)
    }
}

impl PowerSensor for ScaphandreSensor {
    fn name(&self) -> &'static str {
        "SCAPHANDRE_PROMETHEUS"
    }

    fn read_power<'a>(&'a mut self, _ctx: &'a SensorContext) -> BoxFuture<'a, Option<f64>> {
        Box::pin(async move {
            let res = self.client.get(&self.metrics_url).send().await.ok()?;
            let text = res.text().await.ok()?;
            Self::parse_metrics_text(&self.regex, &text)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scaphandre_metrics() {
        let regex = Regex::new(r"scaphandre_host_power_microwatts\s+([0-9\.]+)").unwrap();
        let sample = r#"
# HELP scaphandre_host_power_microwatts Power consumed by the whole host in microwatts
# TYPE scaphandre_host_power_microwatts gauge
scaphandre_host_power_microwatts 45500000.0
# HELP scaphandre_process_power_consumption_microwatts
"#;
        let watts = ScaphandreSensor::parse_metrics_text(&regex, sample);
        assert_eq!(watts, Some(45.5));
    }

    #[test]
    fn test_parse_missing_metric() {
        let regex = Regex::new(r"scaphandre_host_power_microwatts\s+([0-9\.]+)").unwrap();
        let sample = "other_metric 12345\n";
        assert_eq!(ScaphandreSensor::parse_metrics_text(&regex, sample), None);
    }
}
