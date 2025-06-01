#[cfg(target_family = "windows")]
use std::collections::HashMap;
#[cfg(target_family = "windows")]
use winreg::enums::*;
#[cfg(target_family = "windows")]
use winreg::RegKey;

#[derive(Debug)]
pub struct RegistryEntry {
    pub hive: String,
    pub path: String,
    pub key: String,
    pub value: String,
}

#[cfg(target_family = "windows")]
pub fn read_registry_keys() -> Vec<RegistryEntry> {
    let mut entries = Vec::new();

    let registry_targets: Vec<(&str, HKEY, &str)> = vec![
        (
            "HKEY_CURRENT_USER",
            HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ),
        (
            "HKEY_LOCAL_MACHINE",
            HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ),
    ];

    for (hive_name, hive_key, subkey_path) in registry_targets {
        let hive = RegKey::predef(hive_key);
        match hive.open_subkey(subkey_path) {
            Ok(subkey) => {
                for item in subkey.enum_values().flatten() {
                    entries.push(RegistryEntry {
                        hive: hive_name.to_string(),
                        path: subkey_path.to_string(),
                        key: item.0,
                        value: item.1.to_string(),
                    });
                }
            }
            Err(e) => {
                eprintln!("Failed to open {}\\{}: {}", hive_name, subkey_path, e);
            }
        }
    }

    entries
}

#[cfg(target_family = "windows")]
pub fn monitor_registry() {
    let entries = read_registry_keys();

    if entries.is_empty() {
        println!("No registry autoruns found.");
    } else {
        for entry in entries {
            println!(
                "Hive: {:<20} | Path: {:<55} | Key: {:<20} | Value: {}",
                entry.hive, entry.path, entry.key, entry.value
            );
        }
    }
}

#[cfg(target_family = "unix")]
pub fn monitor_registry() {
    println!("Registry monitoring is not supported on this platform.");
}