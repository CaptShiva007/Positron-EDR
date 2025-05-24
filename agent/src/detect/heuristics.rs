use sysinfo::PidExt;

use crate::telemetry::{
    file::FileInfo, network::ConnectionInfo, process::ProcessInfo, registry::RegistryEntry,
};

#[derive(Debug)]
pub enum HeuristicAlert {
    SuspiciousProcess { pid: u32, reason: String },
    SuspiciousFile { path: String, reason: String },
    SuspiciousNetwork { pid: u32, reason: String },
    SuspiciousRegistry { key: String, reason: String },
}

pub fn analyze_processes(processes: &[ProcessInfo]) -> Vec<HeuristicAlert> {
    let mut alerts = Vec::new();

    for proc in processes {
        if proc.is_lolbin && proc.cpu_usage > 10.0 {
            alerts.push(HeuristicAlert::SuspiciousProcess {
                pid: proc.pid.as_u32(),
                reason: format!("LOLBin '{}' using high CPU", proc.name),
            });
        }

        if proc.user.to_lowercase() != "system" && proc.name.to_lowercase().contains("svchost") {
            alerts.push(HeuristicAlert::SuspiciousProcess {
                pid: proc.pid.as_u32(),
                reason: "Non-SYSTEM svchost process".to_string(),
            });
        }

        if let Some(hash) = &proc.hash {
            if hash.starts_with("0000") {
                alerts.push(HeuristicAlert::SuspiciousProcess { 
                    pid: proc.pid.as_u32(), 
                    reason: "Unusual hash prefix".to_string() 
                });
            }
        }
    }
    alerts
}

pub fn analyze_files(files: &[FileInfo]) -> Vec<HeuristicAlert> {
    files.iter().filter_map(|file| {
        if file.is_hidden && file.is_executable {
            Some(HeuristicAlert::SuspiciousFile { 
                path: file.path.to_string_lossy(), 
                reason: "Hidden Executable".to_string(),
            })
        } else {
            None
        }
    }).collect()
}

pub fn analyze_network(conns: &[ConnectionInfo]) -> Vec<HeuristicAlert> {
    conns.iter().filter_map(|conn| {
        if conn.remote_port == 4444 || conn.remote_port == 1337 {
            Some(HeuristicAlert::SuspiciousNetwork { 
                pid: conn.pid, 
                reason: format!("Connected to suspicious port[s]: {}", conn.remote_port), 
            })
        } else {
            None
        }
    }).collect()
}

pub fn analyze_registry(entries: &[RegistryEntry]) -> Vec<HeuristicAlert> {
    entries.iter().filter_map(|entry| {
        if entry.key.to_lowercase().contains("run") && entry.value.to_lowercase().contains("temp") {
            Some(HeuristicAlert::SuspiciousRegistry {
                key: entry.key.clone(), 
                reason: "Suspicious autorun in temp".to_string(), 
            })
        } else {
            None
        }
    }).collect()
}