use sysinfo::{Pid, ProcessExt, System, SystemExt};
use users::{get_user_by_uid, get_current_uid};
use std::fs::File;
use std::io::{Read};
use sha2::{Sha256, Digest};

#[derive(Debug)]
pub struct ProcessInfo{
    pub pid: Pid,
    pub ppid: Option<Pid>,
    pub name: String,
    pub exe: String,
    pub status: String,
    pub cpu_usage: f32,
    pub memory: u64,
    pub user: String,
    pub hash: Option<String>,
    pub is_lolbin: bool,
}

pub fn get_running_processes() -> Vec<ProcessInfo> {
    let mut system = System::new_all();
    system.refresh_all();

    let mut process_list = Vec::new();

    for (pid, proc) in system.processes() {
        let exe_path = proc.exe().display().to_string();
        
        let user = match get_current_uid() {
            uid => get_user_by_uid(uid)
                    .map(|u| u.name().to_string_lossy().into_owned())
                    .unwrap_or_else(|| "Unknown".to_string()),
        };

        let hash = calculate_sha256(proc.exe().to_str().unwrap_or_default());

        let is_lolbin = is_suspicious_lolbin(proc.name());

        let process_info = ProcessInfo {
            pid: *pid,
            ppid: proc.parent(),
            name: proc.name().to_string(),
            exe: exe_path,
            status: format!("{:?}", proc.status()),
            cpu_usage: proc.cpu_usage(),
            memory: proc.memory(),
            user,
            hash,
            is_lolbin
        };

        process_list.push(process_info);
    }
    process_list
}

fn calculate_sha256(path: &str) -> Option<String>{
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 4096];

    loop {
        let bytes_read = file.read(&mut buffer).ok()?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Some(hex::encode(hasher.finalize()))
}

fn is_suspicious_lolbin(name: &str) -> bool {
    let lolbins = [
        "powershell", "cmd", "wscript", "cscript", "rundll32", "mshta",
        "wmic", "regsvr32", "bitsadmin", "schtasks", "certutil"
    ];

    lolbins.iter().any(|&bin| name.to_lowercase().contains(bin))
}

pub fn monitor_process() {
    let processes = get_running_processes();
    for proc in processes {
        println!(
            "PID: {} | Name: {} | Path: {} | Status: {} | CPU: {:.2}% | Memory: {} KB",
            proc.pid, proc.name, proc.exe, proc.status, proc.cpu_usage, proc.memory
        );
    }
}