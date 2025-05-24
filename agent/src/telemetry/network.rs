use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo,
};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use std::net::IpAddr;

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

    let mut connections = Vec::new();

    if let Ok(sockets) = get_sockets_info(af_flags, proto_flags) {
        for socket in sockets {
            let pid = socket.associated_pids.first().copied();
            let process_name = pid
                .and_then(|pid| system.process(sysinfo::Pid::from_u32(pid)))
                .map(|proc| proc.name().to_string());

            let conn = match socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => ConnectionInfo {
                    protocol: "TCP".to_string(),
                    local_addr: tcp.local_addr.ip(),
                    local_port: tcp.local_port.port(),
                    remote_addr: Some(tcp.remote_addr.ip()),
                    remote_port: Some(tcp.remote_port.port()),
                    pid,
                    process_name,
                },
                ProtocolSocketInfo::Udp(udp) => ConnectionInfo {
                    protocol: "UDP".to_string(),
                    local_addr: udp.local_addr.ip(),
                    local_port: udp.local_port.port(),
                    remote_addr: None,
                    remote_port: None,
                    pid,
                    process_name
                },
            };
            connections.push(conn);
        }
    }
    connections
}

pub fn monitor_network() {
    let conns = get_active_connections();
    for conn in conns {
        println!(
            "[{}] {}:{} -> {}:{} | PID: {} | Process: {}",
            conn.protocol,
            conn.local_addr,
            conn.local_port,
            conn.remote_addr.unwrap_or(IpAddr::from([0, 0, 0, 0])),
            conn.remote_port.unwrap_or(0),
            conn.pid.map_or("Unknown".to_string(), |p| p.to_string()),
            conn.process_name.unwrap_or_else(|| "Unknown".to_string())
        );
    }
}