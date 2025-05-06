use sysinfo::{Pid, ProcessExt, System, SystemExt};

pub struct ProcessInfo{
    pub pid: Pid,
    pub name: String,
    pub exe: String,
    pub status: String,
    pub cpu_usage: f32,
    pub memory: u64,
}

pub fn get_running_processes() -> Vec<ProcessInfo> {
    let mut system = System::new_all();
    system.refresh_all();

    let mut process_list = Vec::new();

    for (pid, proc) in system.processes() {
        let process_info = ProcessInfo{
            pid: *pid,
            name: proc.name().to_string(),
            exe: proc.exe().display().to_string(),
            status: format!("{:?}", proc.status()),
            cpu_usage: proc.cpu_usage(),
            memory: proc.memory(),
        };

        process_list.push(process_info);
    }

    process_list
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