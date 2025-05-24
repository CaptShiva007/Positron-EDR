use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use sysinfo::PidExt;
use std::time::SystemTime;

#[derive(Debug, Serialize, Deserialize)]
pub struct NormalizedFile{
    pub path: String,
    pub is_hidden: bool,
    pub is_executable: bool,
    pub last_modified: Option<u64>,
    pub size: u64,
    pub sha256: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NormalizedNetworkConn {
    pub local_address: String,
    pub remote_address: String,
    pub protocol: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NormalizedProcess {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: String,
    pub status: String,
    pub cpu_usage: f32,
    pub memory: u64,
    pub user: String,
    pub hash: Option<String>,
    pub is_lolbin: bool
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NormalizedRegistry {
    pub key_path: String,
    pub value_name: String,
    pub data: String,
    pub value_type: String
}

pub fn normalize_files(files: Vec<crate::telemetry::file::FileInfo>) -> Vec<NormalizedFile> {
    files.into_iter().map(|f| NormalizedFile {
        path: f.path.display().to_string(),
        is_hidden: f.is_hidden,
        is_executable: f.is_executable,
        last_modified: f.last_modified
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
        size: f.size,
        sha256: f.sha256
    }).collect()
}

pub fn normalize_network(conns: Vec<crate::telemetry::network::ConnectionInfo>) -> Vec<NormalizedNetworkConn> {
    conns.into_iter().map(|c| NormalizedNetworkConn {
        local_address: c.local_addr,
        remote_address: c.remote_addr,
        protocol: c.protocol,
        pid: c.pid,
        process_name: c.process_name,
    }).collect()
}

pub fn normalize_processes(procs: Vec<crate::telemetry::process::ProcessInfo>) -> Vec<NormalizedProcess> {
    procs.into_iter().map(|p| NormalizedProcess {
        pid: p.pid.as_u32(),
        ppid: p.ppid.map(|pp| pp.as_u32()),
        name: p.name,
        exe: p.exe,
        status: p.status,
        cpu_usage: p.cpu_usage,
        memory: p.memory,
        user: p.user,
        hash: p.hash,
        is_lolbin: p.is_lolbin,
    }).collect()
}

fn normalize_registry(reg_entries: Vec<crate::telemetry::registry::RegistryEntry>) -> Vec<NormalizedRegistry> {
    reg_entries.into_iter().map(|r| NormalizedRegistry {
        key_path: r.key_path,
        value_name: r.value_name,
        data: r.data,
        value_type: r.value_type
    }).collect()
}