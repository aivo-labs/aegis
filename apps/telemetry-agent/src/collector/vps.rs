use super::{BoxFuture, PowerSensor, SensorContext};

/// Estimateur de puissance énergétique pour VPS virtualisés (KVM / QEMU / VMware)
/// Calibré sur un TDP serveur standard (idle 12W, max 48W)
pub struct VpsEstimatorSensor {
    pub idle_watts: f64,
    pub max_watts: f64,
}

impl Default for VpsEstimatorSensor {
    fn default() -> Self {
        Self {
            idle_watts: 12.0,
            max_watts: 48.0,
        }
    }
}

impl VpsEstimatorSensor {
    pub fn new(idle_watts: f64, max_watts: f64) -> Self {
        Self {
            idle_watts,
            max_watts,
        }
    }

    /// Estime la puissance en fonction de la charge CPU [0.0, 100.0]%
    pub fn estimate(&self, cpu_usage_percent: f64) -> f64 {
        let clamped = cpu_usage_percent.clamp(0.0, 100.0);
        self.idle_watts + ((self.max_watts - self.idle_watts) * (clamped / 100.0))
    }
}

impl PowerSensor for VpsEstimatorSensor {
    fn name(&self) -> &'static str {
        "VPS_KVM_CPU_ESTIMATION"
    }

    fn read_power<'a>(&'a mut self, ctx: &'a SensorContext) -> BoxFuture<'a, Option<f64>> {
        let watts = self.estimate(ctx.cpu_usage_percent);
        Box::pin(async move { Some(watts) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vps_estimator_idle() {
        let sensor = VpsEstimatorSensor::default();
        let watts = sensor.estimate(0.0);
        assert_eq!(watts, 12.0);
    }

    #[test]
    fn test_vps_estimator_half_load() {
        let sensor = VpsEstimatorSensor::default();
        let watts = sensor.estimate(50.0);
        assert_eq!(watts, 30.0);
    }

    #[test]
    fn test_vps_estimator_full_load() {
        let sensor = VpsEstimatorSensor::default();
        let watts = sensor.estimate(100.0);
        assert_eq!(watts, 48.0);
    }

    #[test]
    fn test_vps_estimator_clamped_extremes() {
        let sensor = VpsEstimatorSensor::default();
        assert_eq!(sensor.estimate(-10.0), 12.0);
        assert_eq!(sensor.estimate(150.0), 48.0);
    }
}
