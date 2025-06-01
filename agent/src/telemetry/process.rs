use sysinfo::{Pid, PidExt, ProcessExt, System, SystemExt};
use winapi::um::sysinfoapi::ComputerNameDnsDomain;
use core::hash;
use std::fs::File;
use std::io::Read;
use sha2::{Sha256, Digest};

#[cfg(target_family = "unix")]
use users::get_user_by_uid;

#[cfg(target_family = "windows")]
use windows::{
    core::PWSTR,
    Win32::Foundation::{CloseHandle, HANDLE},
    Win32::Security::{
        GetTokenInformation, LookupAccountSidW, OpenProcessToken, TokenUser, TOKEN_QUERY, TOKEN_USER
    },
    Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION}
};

#[derive(Debug)]
pub struct ProcessInfo {
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

pub fn get_running_process() -> Vec<ProcessInfo> {
    let mut system = System::new_all();
    system.refresh_all();

    let known_lolbins = vec![
        "rundll32.exe", "regsvr32.exe", "powershell.exe", "wmic.exe", "certutil.exe",
        "mshta.exe", "cmd.exe", "cscript.exe", "wscript.exe"
    ];

    let mut process_list = Vec::new();

    for (pid, proc) in system.processes() {
        let exe_path = proc.exe().display().to_string();
        let user = get_process_user(proc);
        let name = proc.name().to_string();
        let hash = compute_sha256(&exe_path);
        let is_lolbin = known_lolbins.iter().any(|&bin| bin.eq_ignore_ascii_case(proc.name()));

        process_list.push(ProcessInfo {
            pid: *pid,
            ppid: proc.parent(),
            name,
            exe: exe_path,
            status: proc.status().to_string(),
            cpu_usage: proc.cpu_usage(),
            memory: proc.memory(),
            user,
            hash,
            is_lolbin
        });
    }
    process_list
}

//unix get_process_user
#[cfg(target_family = "unix")]
fn get_process_user(proc: &sysinfo::Process) -> String {
    match proc.user_id() {
        Some(uid) => get_user_by_uid(uid)
            .map(|u| u.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| "Unknown".to_string()),
        None => "Unknown".to_string(),
    }
}

#[cfg(windows)]
fn get_process_user(proc: &sysinfo::Process) -> String {
    use std::ptr::null_mut;
    use sysinfo::PidExt;
    use windows::core::PWSTR;

    let pid = proc.pid().as_u32();

    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if process_handle.is_invalid() {
            return "Unknown".to_string();
        }

        let mut token_handle: HANDLE = HANDLE(0);
        if !OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle).as_bool() {
            CloseHandle(process_handle);
            return "Unknown".to_string();
        }

        let mut buffer = vec![0u8; 1024];
        let mut return_length = 0u32;

        if !GetTokenInformation(token_handle, 
            TokenUser, 
            Some(buffer.as_mut_ptr() as *mut _), 
            buffer.len() as u32, 
        &mut return_length).as_bool() 
        
        {
            CloseHandle(token_handle);
            CloseHandle(process_handle);
            return "Unknown".to_string();
        }

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let sid_ptr = token_user.User.Sid;

        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain = [0u16; 256];
        let mut domain_len = domain.len() as u32;
        let mut sid_type = 0;

        if !LookupAccountSidW(
            None, 
            sid_ptr, 
            Some(&mut name), 
            &mut name_len, 
            Some(&mut domain), 
            &mut domain_len, 
        &mut sid_type).as_bool() 
        {
            CloseHandle(token_handle);
            CloseHandle(process_handle);
            return "Unknown".to_string();    
        }

        CloseHandle(token_handle);
        CloseHandle(process_handle);

        let username = String::from_utf16_lossy(&name[..name_len as usize]);
        let domainname = String::from_utf16_lossy(&domain[..domain_len as usize]);
        format!("{}\\{}, domainname, username")
    }
}

fn compute_sha256(path: &str) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];

    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

pub fn monitor_process() {
    let processes = get_running_process();
    for proc in processes {
        println!(
            "PID: {:<5} | PPID: {:<5} | {:<20} | CPU: {:>5.2}% | Mem: {:>6} KB | User: {:<20} | LoLBin: {:<5} | Hash: {}",
            proc.pid,
            proc.ppid.map_or(0, |ppid| ppid.as_u32()),
            proc.name,
            proc.cpu_usage,
            proc.memory,
            proc.user,
            proc.is_lolbin,
            proc.hash.unwrap_or_else(|| "N/A".to_string())
        );
    }
}