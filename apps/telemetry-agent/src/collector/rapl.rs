use super::{BoxFuture, PowerSensor, SensorContext};
use std::fs;

/// Capteur matériel direct basé sur les registres Intel/AMD RAPL (Running Average Power Limit)
pub struct RaplSensor {
    paths: Vec<String>,
    last_rapl_uj: Option<u64>,
}

impl Default for RaplSensor {
    fn default() -> Self {
        Self {
            paths: vec![
                "/host/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj".to_string(),
                "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj".to_string(),
            ],
            last_rapl_uj: None,
        }
    }
}

impl RaplSensor {
    pub fn new(paths: Vec<String>) -> Self {
        Self {
            paths,
            last_rapl_uj: None,
        }
    }

    /// Extrait la valeur brute en microjoules (µJ) depuis le premier chemin lisible
    pub fn read_energy_uj(&self) -> Option<u64> {
        for path in &self.paths {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(val) = content.trim().parse::<u64>() {
                    return Some(val);
                }
            }
        }
        None
    }

    /// Calcule la puissance en Watts à partir d'un échantillon µJ et du temps écoulé
    pub fn calculate_power_watts(&mut self, current_uj: u64, elapsed_secs: f64) -> Option<f64> {
        let prev_uj = self.last_rapl_uj?;
        self.last_rapl_uj = Some(current_uj);

        if current_uj >= prev_uj && elapsed_secs > 0.0 {
            let delta_joules = (current_uj - prev_uj) as f64 / 1_000_000.0;
            let watts = delta_joules / elapsed_secs;
            Some(watts)
        } else {
            None
        }
    }
}

impl PowerSensor for RaplSensor {
    fn name(&self) -> &'static str {
        "RAPL_HARDWARE_DIRECT"
    }

    fn read_power<'a>(&'a mut self, ctx: &'a SensorContext) -> BoxFuture<'a, Option<f64>> {
        Box::pin(async move {
            let current_uj = match self.read_energy_uj() {
                Some(uj) => uj,
                None => return None,
            };

            if self.last_rapl_uj.is_none() {
                self.last_rapl_uj = Some(current_uj);
                return None;
            }

            self.calculate_power_watts(current_uj, ctx.elapsed_secs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rapl_calculation() {
        let mut sensor = RaplSensor::new(vec![]);
        sensor.last_rapl_uj = Some(10_000_000); // 10 Joules

        // Après 2 secondes, compteur à 130_000_000 µJ (+120 Joules) -> 60 W
        let watts = sensor.calculate_power_watts(130_000_000, 2.0);
        assert_eq!(watts, Some(60.0));
        assert_eq!(sensor.last_rapl_uj, Some(130_000_000));
    }

    #[test]
    fn test_rapl_counter_wrap_or_reset() {
        let mut sensor = RaplSensor::new(vec![]);
        sensor.last_rapl_uj = Some(50_000_000);

        // Compteur inférieur (reset machine ou overflow)
        let watts = sensor.calculate_power_watts(10_000_000, 2.0);
        assert_eq!(watts, None);
        assert_eq!(sensor.last_rapl_uj, Some(10_000_000));
    }
}
