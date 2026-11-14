use crate::collector::composite::CompositePowerSensor;
use crate::collector::{CpuCollector, SensorContext};
use crate::config::AgentConfig;
use crate::domain::EnergyPayload;
use crate::publisher::TelemetryPublisher;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Démon de télémétrie orchestrant la boucle de mesure et publication
pub struct TelemetryDaemon {
    pub config: AgentConfig,
    pub cpu_collector: Box<dyn CpuCollector>,
    pub sensor: CompositePowerSensor,
    pub publisher: Box<dyn TelemetryPublisher>,
}

impl TelemetryDaemon {
    pub fn new(
        config: AgentConfig,
        cpu_collector: Box<dyn CpuCollector>,
        sensor: CompositePowerSensor,
        publisher: Box<dyn TelemetryPublisher>,
    ) -> Self {
        Self {
            config,
            cpu_collector,
            sensor,
            publisher,
        }
    }

    /// Exécute un cycle unitaire de mesure et de publication (parfaitement testable)
    pub async fn tick(
        &mut self,
        elapsed_secs: f64,
    ) -> Result<EnergyPayload, Box<dyn std::error::Error + Send + Sync>> {
        let cpu_usage = self.cpu_collector.get_usage_percent();

        let ctx = SensorContext {
            cpu_usage_percent: cpu_usage,
            elapsed_secs,
        };

        let (power_watts, engine_source) = self.sensor.read_measurement(&ctx).await;

        let payload = EnergyPayload::new(
            &self.config.tenant_id,
            &self.config.server_id,
            power_watts,
            cpu_usage,
            elapsed_secs,
        );

        match self.publisher.publish(&payload).await {
            Ok(()) => {
                println!(
                    "✅ [Ingest OK] Total: {:.2}W ({}) | CPU: {:.1}% | Delta Joules: {:.2}J",
                    payload.power_watts,
                    engine_source,
                    payload.cpu_usage_percent,
                    payload.energy_joules_delta
                );
            }
            Err(e) => {
                eprintln!("⚠️ [Ingest Warning] {}", e);
            }
        }

        Ok(payload)
    }

    /// Démarre la boucle infinie d'échantillonnage de la sonde
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("🚀 [Aegis Gate] Agent de Télémétrie Énergétique (Rust v0.1.0)");
        println!(
            "📍 Client ID: {} | Server ID: {}",
            self.config.tenant_id, self.config.server_id
        );
        println!("⚡ Target Scaphandre: {}", self.config.scaphandre_url);
        println!("🔗 Target API Endpoint: {}", self.config.gate_api_url);

        let mut last_tick = Instant::now();

        loop {
            let elapsed_secs = last_tick.elapsed().as_secs_f64();
            last_tick = Instant::now();

            let _ = self.tick(elapsed_secs).await;

            sleep(Duration::from_secs(self.config.poll_interval_secs)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::PowerSensor;
    use crate::collector::BoxFuture;
    use crate::publisher::PublishError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct MockCpu(f64);
    impl CpuCollector for MockCpu {
        fn get_usage_percent(&self) -> f64 {
            self.0
        }
    }

    struct MockPower(f64);
    impl PowerSensor for MockPower {
        fn name(&self) -> &'static str {
            "MOCK_TEST"
        }
        fn read_power<'a>(&'a mut self, _ctx: &'a SensorContext) -> BoxFuture<'a, Option<f64>> {
            let val = self.0;
            Box::pin(async move { Some(val) })
        }
    }

    struct MockPublisher {
        calls: Arc<AtomicUsize>,
    }
    impl TelemetryPublisher for MockPublisher {
        fn publish<'a>(&'a self, _payload: &'a EnergyPayload) -> BoxFuture<'a, Result<(), PublishError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn test_daemon_tick() {
        let calls = Arc::new(AtomicUsize::new(0));
        let publisher = Box::new(MockPublisher {
            calls: Arc::clone(&calls),
        });
        let cpu = Box::new(MockCpu(40.0));
        let composite = CompositePowerSensor::new(vec![Box::new(MockPower(50.0))]);

        let mut daemon = TelemetryDaemon::new(
            AgentConfig::default(),
            cpu,
            composite,
            publisher,
        );

        let payload = daemon.tick(2.0).await.expect("tick should succeed");

        assert_eq!(payload.power_watts, 50.0);
        assert_eq!(payload.cpu_usage_percent, 40.0);
        assert_eq!(payload.energy_joules_delta, 100.0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
