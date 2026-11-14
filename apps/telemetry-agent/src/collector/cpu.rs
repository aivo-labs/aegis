use super::CpuCollector;
use std::fs;
use std::thread;
use std::time::Duration;

/// Collecteur de charge CPU basé sur les jiffies de /proc/stat
pub struct ProcStatCpuCollector {
    paths: Vec<String>,
    sample_delay: Duration,
    default_usage: f64,
}

impl Default for ProcStatCpuCollector {
    fn default() -> Self {
        Self {
            paths: vec![
                "/host/proc/stat".to_string(),
                "/proc/stat".to_string(),
            ],
            sample_delay: Duration::from_millis(200),
            default_usage: 15.0,
        }
    }
}

impl ProcStatCpuCollector {
    pub fn new(paths: Vec<String>, sample_delay: Duration, default_usage: f64) -> Self {
        Self {
            paths,
            sample_delay,
            default_usage,
        }
    }

    /// Parse une ligne `cpu ...` pour en extraire (busy_jiffies, total_jiffies)
    pub fn parse_cpu_line(line: &str) -> Option<(u64, u64)> {
        let mut parts = line.split_whitespace();
        let header = parts.next()?;
        if !header.starts_with("cpu") {
            return None;
        }

        let user: u64 = parts.next()?.parse().ok()?;
        let nice: u64 = parts.next()?.parse().ok()?;
        let system: u64 = parts.next()?.parse().ok()?;
        let idle: u64 = parts.next()?.parse().ok()?;
        let iowait: u64 = parts.next()?.parse().ok()?;
        let irq: u64 = parts.next()?.parse().ok()?;
        let softirq: u64 = parts.next()?.parse().ok()?;

        let total_idle = idle + iowait;
        let total_busy = user + nice + system + irq + softirq;
        let total = total_idle + total_busy;

        Some((total_busy, total))
    }

    fn read_stat_sample(&self) -> Option<(u64, u64)> {
        for path in &self.paths {
            if let Ok(content) = fs::read_to_string(path) {
                if let Some(first_line) = content.lines().next() {
                    if let Some(sample) = Self::parse_cpu_line(first_line) {
                        return Some(sample);
                    }
                }
            }
        }
        None
    }
}

impl CpuCollector for ProcStatCpuCollector {
    fn get_usage_percent(&self) -> f64 {
        if let Some((busy1, total1)) = self.read_stat_sample() {
            thread::sleep(self.sample_delay);
            if let Some((busy2, total2)) = self.read_stat_sample() {
                let total_delta = total2.saturating_sub(total1) as f64;
                let busy_delta = busy2.saturating_sub(busy1) as f64;

                if total_delta > 0.0 {
                    let percent = (busy_delta / total_delta) * 100.0;
                    return percent.clamp(0.0, 100.0);
                }
            }
        }

        self.default_usage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpu_line_valid() {
        let line = "cpu  2255 34 2290 22625 31 0 10 0 0 0";
        let parsed = ProcStatCpuCollector::parse_cpu_line(line);
        assert!(parsed.is_some());
        let (busy, total) = parsed.unwrap();
        // busy = 2255 + 34 + 2290 + 0 + 10 = 4589
        // idle = 22625 + 31 = 22656
        // total = 27245
        assert_eq!(busy, 4589);
        assert_eq!(total, 27245);
    }

    #[test]
    fn test_parse_cpu_line_invalid() {
        let line = "intr 11234 56 78";
        assert!(ProcStatCpuCollector::parse_cpu_line(line).is_none());
    }
}
