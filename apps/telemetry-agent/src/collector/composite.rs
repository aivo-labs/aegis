use super::{
    rapl::RaplSensor, scaphandre::ScaphandreSensor, vps::VpsEstimatorSensor, PowerSensor,
    SensorContext,
};

/// Capteur composite orchestrant la chaîne de fallback :
/// 1. Lecture directe des registres Intel/AMD RAPL physiques
/// 2. Sonde Scaphandre Prometheus
/// 3. Fallback d'estimation dynamique VPS calibré sur la charge CPU
pub struct CompositePowerSensor {
    sensors: Vec<Box<dyn PowerSensor>>,
}

impl CompositePowerSensor {
    pub fn new(sensors: Vec<Box<dyn PowerSensor>>) -> Self {
        Self { sensors }
    }

    /// Construit la chaîne de sondes standard Aegis
    pub fn standard(rapl_paths: Vec<String>, scaphandre_url: &str) -> Self {
        let sensors: Vec<Box<dyn PowerSensor>> = vec![
            Box::new(RaplSensor::new(rapl_paths)),
            Box::new(ScaphandreSensor::new(scaphandre_url)),
            Box::new(VpsEstimatorSensor::default()),
        ];
        Self::new(sensors)
    }

    /// Évalue séquentiellement les sondes et renvoie la première mesure valide avec sa source
    pub async fn read_measurement(&mut self, ctx: &SensorContext) -> (f64, &'static str) {
        for sensor in &mut self.sensors {
            if let Some(watts) = sensor.read_power(ctx).await {
                return (watts, sensor.name());
            }
        }

        // Fallback ultime de sécurité
        (12.0, "FALLBACK_STATIC")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::BoxFuture;

    struct MockFailingSensor;
    impl PowerSensor for MockFailingSensor {
        fn name(&self) -> &'static str {
            "MOCK_FAILING"
        }
        fn read_power<'a>(&'a mut self, _ctx: &'a SensorContext) -> BoxFuture<'a, Option<f64>> {
            Box::pin(async { None })
        }
    }

    struct MockPassingSensor(f64);
    impl PowerSensor for MockPassingSensor {
        fn name(&self) -> &'static str {
            "MOCK_PASSING"
        }
        fn read_power<'a>(&'a mut self, _ctx: &'a SensorContext) -> BoxFuture<'a, Option<f64>> {
            let val = self.0;
            Box::pin(async move { Some(val) })
        }
    }

    #[tokio::test]
    async fn test_composite_fallback_to_second_sensor() {
        let sensors: Vec<Box<dyn PowerSensor>> = vec![
            Box::new(MockFailingSensor),
            Box::new(MockPassingSensor(42.5)),
        ];
        let mut composite = CompositePowerSensor::new(sensors);
        let ctx = SensorContext {
            cpu_usage_percent: 25.0,
            elapsed_secs: 2.0,
        };

        let (watts, source) = composite.read_measurement(&ctx).await;
        assert_eq!(watts, 42.5);
        assert_eq!(source, "MOCK_PASSING");
    }

    #[tokio::test]
    async fn test_composite_all_failing_fallback() {
        let sensors: Vec<Box<dyn PowerSensor>> = vec![
            Box::new(MockFailingSensor),
            Box::new(MockFailingSensor),
        ];
        let mut composite = CompositePowerSensor::new(sensors);
        let ctx = SensorContext {
            cpu_usage_percent: 0.0,
            elapsed_secs: 1.0,
        };

        let (watts, source) = composite.read_measurement(&ctx).await;
        assert_eq!(watts, 12.0);
        assert_eq!(source, "FALLBACK_STATIC");
    }
}
