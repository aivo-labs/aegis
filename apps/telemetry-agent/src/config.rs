use std::env;

/// Configuration de l'agent de télémétrie Aegis
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub tenant_id: String,
    pub server_id: String,
    pub scaphandre_url: String,
    pub gate_api_url: String,
    pub api_key: String,
    pub poll_interval_secs: u64,
    pub rapl_paths: Vec<String>,
    pub proc_stat_paths: Vec<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            tenant_id: "00000000-0000-0000-0000-000000000001".to_string(),
            server_id: "vps-aivo-01".to_string(),
            scaphandre_url: "http://localhost:8080/metrics".to_string(),
            gate_api_url: "http://localhost:8080/api/v1/gate/telemetry/energy".to_string(),
            api_key: "dev_secret_key_aivo".to_string(),
            poll_interval_secs: 5,
            rapl_paths: vec![
                "/host/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj".to_string(),
                "/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj".to_string(),
            ],
            proc_stat_paths: vec![
                "/host/proc/stat".to_string(),
                "/proc/stat".to_string(),
            ],
        }
    }
}

impl AgentConfig {
    /// Charge la configuration depuis les variables d'environnement
    pub fn from_env() -> Self {
        let default = Self::default();

        let tenant_id = env::var("AEGIS_TENANT_ID").unwrap_or(default.tenant_id);
        let server_id = env::var("AEGIS_SERVER_ID").unwrap_or_else(|_| {
            hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or(default.server_id)
        });
        let scaphandre_url = env::var("SCAPHANDRE_URL").unwrap_or(default.scaphandre_url);
        let gate_api_url = env::var("AEGIS_GATE_API_URL").unwrap_or(default.gate_api_url);
        let api_key = env::var("AEGIS_GATE_API_KEY").unwrap_or(default.api_key);
        let poll_interval_secs: u64 = env::var("POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default.poll_interval_secs);

        Self {
            tenant_id,
            server_id,
            scaphandre_url,
            gate_api_url,
            api_key,
            poll_interval_secs,
            rapl_paths: default.rapl_paths,
            proc_stat_paths: default.proc_stat_paths,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert_eq!(config.poll_interval_secs, 5);
        assert!(!config.rapl_paths.is_empty());
        assert!(!config.proc_stat_paths.is_empty());
        assert_eq!(config.tenant_id, "00000000-0000-0000-0000-000000000001");
    }
}
