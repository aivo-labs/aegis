use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Verrou n°4 (P1) : Surveillance Anti-Spawn de Shell côté Hôte (/proc)
/// Détecte en temps réel lorsqu'un worker web (php-fpm, nginx, apache2, node, java)
/// engendre un processus enfant de type shell ou binaire d'exfiltration (/bin/sh, bash, nc, curl, python).

const WEB_WORKER_COMMS: &[&str] = &[
    "php-fpm",
    "php-cgi",
    "php",
    "nginx",
    "apache2",
    "httpd",
    "node",
    "java",
    "caddy",
    "gunicorn",
    "uvicorn",
];

const SUSPICIOUS_CHILD_COMMS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ash",
    "ksh",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "python",
    "python3",
    "perl",
    "ruby",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuspiciousSpawnEvent {
    pub child_pid: u32,
    pub child_comm: String,
    pub parent_pid: u32,
    pub parent_comm: String,
    pub cmdline: String,
    pub threat_type: String,
}

#[derive(Debug, Clone)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub cmdline: String,
}

pub fn is_web_worker(comm: &str) -> bool {
    let lower = comm.trim().to_lowercase();
    WEB_WORKER_COMMS
        .iter()
        .any(|w| lower == *w || lower.starts_with(&format!("{w}:")) || lower.starts_with(&format!("{w}-")))
}

pub fn is_suspicious_shell_child(comm: &str) -> bool {
    let lower = comm.trim().to_lowercase();
    SUSPICIOUS_CHILD_COMMS.iter().any(|s| lower == *s)
}

/// Parse une ligne /proc/<pid>/stat de la forme : "1234 (php-fpm) S 1000 ..."
pub fn parse_proc_stat_line(stat_content: &str) -> Option<(u32, u32, String)> {
    let open_paren = stat_content.find('(')?;
    let close_paren = stat_content.rfind(')')?;
    if close_paren <= open_paren {
        return None;
    }

    let pid_str = stat_content[..open_paren].trim();
    let pid: u32 = pid_str.parse().ok()?;
    let comm = stat_content[open_paren + 1..close_paren].trim().to_string();

    let after_paren = stat_content[close_paren + 1..].trim();
    let mut parts = after_paren.split_whitespace();
    let _state = parts.next()?;
    let ppid_str = parts.next()?;
    let ppid: u32 = ppid_str.parse().ok()?;

    Some((pid, ppid, comm))
}

/// Évalue un instantané d'arbre de processus et retourne les spawns suspects (worker web -> shell)
pub fn evaluate_process_tree(entries: &[ProcEntry]) -> Vec<SuspiciousSpawnEvent> {
    let mut by_pid: HashMap<u32, &ProcEntry> = HashMap::with_capacity(entries.len());
    for entry in entries {
        by_pid.insert(entry.pid, entry);
    }

    let mut alerts = Vec::new();
    for entry in entries {
        if is_suspicious_shell_child(&entry.comm) {
            if let Some(parent) = by_pid.get(&entry.ppid) {
                if is_web_worker(&parent.comm) {
                    alerts.push(SuspiciousSpawnEvent {
                        child_pid: entry.pid,
                        child_comm: entry.comm.clone(),
                        parent_pid: parent.pid,
                        parent_comm: parent.comm.clone(),
                        cmdline: entry.cmdline.clone(),
                        threat_type: "HOST_SHELL_SPAWN_DETECTED".to_string(),
                    });
                }
            }
        }
    }

    alerts
}

/// Scanne /host/proc ou /proc à la recherche de processus shells enfants de serveurs web
pub fn scan_proc_for_shell_spawns(proc_paths: &[&str]) -> Vec<SuspiciousSpawnEvent> {
    let mut root_dir: Option<&Path> = None;
    for candidate in proc_paths {
        let p = Path::new(candidate);
        if p.exists() && p.is_dir() {
            root_dir = Some(p);
            break;
        }
    }

    let Some(proc_root) = root_dir else {
        return Vec::new();
    };

    let Ok(read_dir) = fs::read_dir(proc_root) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    for dir_entry in read_dir.flatten() {
        let file_name = dir_entry.file_name();
        let name_str = file_name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let stat_path = dir_entry.path().join("stat");
        let Ok(stat_raw) = fs::read_to_string(&stat_path) else {
            continue;
        };

        if let Some((pid, ppid, comm)) = parse_proc_stat_line(&stat_raw) {
            let cmdline_path = dir_entry.path().join("cmdline");
            let cmdline = fs::read(cmdline_path)
                .map(|bytes| {
                    bytes
                        .split(|b| *b == 0)
                        .filter(|s| !s.is_empty())
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_else(|_| comm.clone());

            entries.push(ProcEntry {
                pid,
                ppid,
                comm,
                cmdline,
            });
        }
    }

    evaluate_process_tree(&entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_stat_line() {
        let line = "4120 (php-fpm8.2) S 1024 4120 4120 0 -1 4194560 120 0 0 0 1 0 0 0 20 0 1 0";
        let parsed = parse_proc_stat_line(line).expect("should parse stat line");
        assert_eq!(parsed.0, 4120);
        assert_eq!(parsed.1, 1024);
        assert_eq!(parsed.2, "php-fpm8.2");
    }

    #[test]
    fn test_detects_web_worker_spawning_shell() {
        let tree = vec![
            ProcEntry {
                pid: 1,
                ppid: 0,
                comm: "systemd".to_string(),
                cmdline: "/sbin/init".to_string(),
            },
            ProcEntry {
                pid: 1200,
                ppid: 1,
                comm: "php-fpm".to_string(),
                cmdline: "php-fpm: pool www".to_string(),
            },
            ProcEntry {
                pid: 1337,
                ppid: 1200,
                comm: "sh".to_string(),
                cmdline: "/bin/sh -c id; cat /etc/passwd".to_string(),
            },
            ProcEntry {
                pid: 2000,
                ppid: 1,
                comm: "sshd".to_string(),
                cmdline: "sshd: admin@pts/0".to_string(),
            },
            ProcEntry {
                pid: 2001,
                ppid: 2000,
                comm: "bash".to_string(),
                cmdline: "-bash".to_string(),
            },
        ];

        let alerts = evaluate_process_tree(&tree);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].child_pid, 1337);
        assert_eq!(alerts[0].child_comm, "sh");
        assert_eq!(alerts[0].parent_pid, 1200);
        assert_eq!(alerts[0].parent_comm, "php-fpm");
        assert_eq!(alerts[0].threat_type, "HOST_SHELL_SPAWN_DETECTED");
    }
}
