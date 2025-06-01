use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use std::net::IpAddr;
use std::fs::File;
use std::io::{self, Write};
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConnectionInfo {
    pub protocol: String,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub pid: Option<u32>,
    pub process_name: Option<String>
}

pub fn get_active_connections() -> Vec<ConnectionInfo> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let mut system = System::new_all();
    system.refresh_processes();

    let Ok(sockets) = get_sockets_info(af_flags, proto_flags) else {
        return vec![];
    };

    sockets.par_iter().filter_map(|socket| {
        let pid = socket.associated_pids.first().copied();
        let process_name = pid
            .and_then(|pid| system.process(sysinfo::Pid::from_u32(pid)))
            .map(|proc| proc.name().to_string());

        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => Some(ConnectionInfo {
                protocol: "TCP".to_string(),
                local_addr: tcp.local_addr.ip(),
                local_port: tcp.local_port.port(),
                remote_addr: Some(tcp.remote_addr.ip()),
                remote_port: Some(tcp.remote_port.port()),
                pid,
                process_name,
            }),
            ProtocolSocketInfo::Udp(udp) => Some(ConnectionInfo {
                protocol: "UDP".to_string(),
                local_addr: udp.local_addr.ip(),
                local_port: udp.local_port.port(),
                remote_addr: None,
                remote_port: None,
                pid,
                process_name
            }),
        }
    }).collect()
}

pub fn get_filtered_connections(protocol_filter: Option<&str>, pid_filter: Option<u32>) -> Vec<ConnectionInfo> {
    get_active_connections()
        .into_iter()
        .filter(|conn| {
            protocol_filter.map_or(true, |proto| conn.protocol.eq_ignore_ascii_case(proto)) &&
            pid_filter.map_or(true, |pid| conn.pid == Some(pid))
        })
        .collect()
}

pub fn print_connections(conns: &[ConnectionInfo]) {
    for conn in conns {
        println!(
            "[{}] {}:{} -> {}:{} | PID: {} | Process: {}",
            conn.protocol,
            conn.local_addr,
            conn.local_port,
            conn.remote_addr.unwrap_or(IpAddr::from([0,0,0,0])),
            conn.remote_port.unwrap_or(0),
            conn.pid.map_or("Unknown".to_string(), |p| p.to_string()),
            conn.process_name.clone().unwrap_or_else(|| "Unknown".to_string())
        );
    }
}

pub fn export_to_json(conns: &[ConnectionInfo], filename: &str) -> io::Result<()> {
    let file = File::create(filename)?;
    serde_json::to_writer_pretty(file, &conns)?;
    Ok(())
}

pub fn collect_network_telemetry(export_to: Option<&str>, filter_protocol: Option<&str>, filter_pid: Option<u32>) {
    let conns = get_filtered_connections(filter_protocol, filter_pid);

    match export_to {
        Some(path) => {
            if let Err(e) = export_to_json(&conns, path) {
                eprintln!("Failed to export connections: {}", e);
            } else {
                println!("Connections exported to {}", path);
            }
        }
        None => print_connections(&conns),
    }
}
