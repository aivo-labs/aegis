pub mod composite;
pub mod cpu;
pub mod process_spawn;
pub mod rapl;
pub mod scaphandre;
pub mod vps;

use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Contexte transmis aux capteurs pour leur mesure
#[derive(Debug, Clone)]
pub struct SensorContext {
    pub cpu_usage_percent: f64,
    pub elapsed_secs: f64,
}

/// Trait définissant un capteur de puissance énergétique (Interface Segregation & Dependency Inversion)
pub trait PowerSensor: Send + Sync {
    /// Nom identifiant la source matérielle ou logicielle du capteur
    fn name(&self) -> &'static str;

    /// Effectue une lecture de la puissance instantanée en Watts
    fn read_power<'a>(&'a mut self, ctx: &'a SensorContext) -> BoxFuture<'a, Option<f64>>;
}

/// Trait définissant un collecteur de métriques CPU système
pub trait CpuCollector: Send + Sync {
    /// Mesure le pourcentage d'utilisation CPU global
    fn get_usage_percent(&self) -> f64;
}
