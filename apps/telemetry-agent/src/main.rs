use aegis_telemetry_agent::collector::composite::CompositePowerSensor;
use aegis_telemetry_agent::collector::cpu::ProcStatCpuCollector;
use aegis_telemetry_agent::config::AgentConfig;
use aegis_telemetry_agent::daemon::TelemetryDaemon;
use aegis_telemetry_agent::publisher::http::HttpTelemetryPublisher;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = AgentConfig::from_env();

    let cpu_collector = Box::new(ProcStatCpuCollector::default());
    let sensor = CompositePowerSensor::standard(config.rapl_paths.clone(), &config.scaphandre_url);
    let publisher = Box::new(HttpTelemetryPublisher::new(
        &config.gate_api_url,
        &config.api_key,
    ));

    let mut daemon = TelemetryDaemon::new(config, cpu_collector, sensor, publisher);
    daemon.start().await
}
