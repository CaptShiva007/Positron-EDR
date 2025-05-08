#[cfg(target_family = "windows")]
use std::collections::HashMap;
#[cfg(target_family = "windows")]
use winreg::enums::*;
#[cfg(target_family = "windows")]
use winreg::RegKey;

#[cfg(target_family = "windows")]

#[derive(Debug)]
pub struct RegistryEntry {
    pub path: String,
    pub key: String,
    pub value: String,
}

#[cfg(target_family = "windows")]
pub fn read_registry_keys() -> Vec<RegistryEntry>{
    let mut entries = Vec::new();

    let hives: HashMap<&str, RegKey> = HashMap::from([
        ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", RegKey::predef(HKEY_CURRENT_USER)),
        ("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", RegKey::predef(HKEY_LOCAL_MACHINE)),
    ]);

    for (full_path, hive) in hives {
        if let Some((_, subkey_path)) = full_path.split_once('\\') {
            if let Ok(subkey) = hive.open_subkey(subkey_path) {
                for item in subkey.enum_values().flatten() {
                    entries.push(RegistryEntry {
                        path: full_path.to_string(),
                        key: item.0,
                        value: item.1.to_string(),
                    });
                }
            }
        }
    }
    entries
}

#[cfg(target_family = "windows")]
pub fn monitor_registry() {
    let entries = read_registry_keys();
    for entry in entries{
        println!(
            "Path: {} | Key: {} | Value: {}",
            entry.path, entry.key, entry.value
        );
    }
}

#[cfg(target_family = "unix")]
pub fn monitor_registry() {
    println!("Registry monitoring is not supported on this platform.")
}