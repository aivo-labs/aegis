use serde::{Deserialize, Serialize};

/// Structure du payload de télémétrie énergétique transmis à l'API Aegis Gate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnergyPayload {
    pub tenant_id: String,
    pub server_id: String,
    pub power_watts: f64,
    pub cpu_power_watts: f64,
    pub memory_power_watts: f64,
    pub cpu_usage_percent: f64,
    pub energy_joules_delta: f64,
}

impl EnergyPayload {
    /// Crée un nouveau payload en appliquant la ventilation CPU (70%) et Mémoire (30%)
    pub fn new(
        tenant_id: impl Into<String>,
        server_id: impl Into<String>,
        power_watts: f64,
        cpu_usage_percent: f64,
        elapsed_secs: f64,
    ) -> Self {
        let cpu_power_watts = power_watts * 0.70;
        let memory_power_watts = power_watts * 0.30;
        let energy_joules_delta = power_watts * elapsed_secs;

        Self {
            tenant_id: tenant_id.into(),
            server_id: server_id.into(),
            power_watts,
            cpu_power_watts,
            memory_power_watts,
            cpu_usage_percent,
            energy_joules_delta,
        }
    }
}

/// Résultat d'une mesure de puissance par un capteur
#[derive(Debug, Clone, PartialEq)]
pub struct PowerReading {
    pub power_watts: f64,
    pub source: &'static str,
}

impl PowerReading {
    pub fn new(power_watts: f64, source: &'static str) -> Self {
        Self { power_watts, source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_energy_payload_calculation() {
        let payload = EnergyPayload::new("tenant-1", "srv-1", 100.0, 50.0, 2.0);

        assert_eq!(payload.tenant_id, "tenant-1");
        assert_eq!(payload.server_id, "srv-1");
        assert_eq!(payload.power_watts, 100.0);
        assert_eq!(payload.cpu_power_watts, 70.0);
        assert_eq!(payload.memory_power_watts, 30.0);
        assert_eq!(payload.cpu_usage_percent, 50.0);
        assert_eq!(payload.energy_joules_delta, 200.0);
    }
}
