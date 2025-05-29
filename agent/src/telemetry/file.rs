use std::fs::{self, Metadata};
use std::io::Read;
use std::{io, path};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, Duration};
use sha2::{Sha256, Digest};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub is_hidden: bool,
    pub is_executable: bool,
    pub last_modified: Option<SystemTime>,
    pub size: u64,
    pub sha256: Option<String>,
    pub entropy: Option<f64>,
}

#[cfg(target_family = "windows")]
fn is_hidden(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    use winapi::um::winnt::FILE_ATTRIBUTE_HIDDEN;

    if let Ok(metadata) = fs::metadata(path) {
        let attrs = metadata.file_attributes();
        (attrs & FILE_ATTRIBUTE_HIDDEN) !=0
    } else {
        false
    }
}

//is_hidden for unix
#[cfg(target_family = "unix")]
fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().starts_with("."))
        .unwrap_or(false)
}

#[cfg(target_family = "windows")]
fn is_executable_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("exe") | Some("bat") | Some("ps1") | Some("dll")
    )
}

//is_executable_file for unix
#[cfg(target_family = "unix")]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = fs::metadata(path) {
        let permissions = metadata.permissions();
        (permissions.mode() & 0o111) != 0
    } else {
        false
    }
}

fn compute_sha256(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(format!("{:x}", hasher.finalize()))
}

fn calculate_entropy(path: &Path) -> Option<f64> {
    let mut buffer = Vec::new();
    let mut file = fs::File::open(path).ok()?;
    file.read_to_end(&mut buffer).ok()?;

    let mut freq = [0usize; 256];
    for byte in &buffer {
        freq[*byte as usize] += 1;
    }

    let total = buffer.len() as f64;
    if total == 0.0 {
        return None;
    }

    let entropy = freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &count|{
        let p = count as f64/total;
        acc - p * p.log2()
    });

    Some(entropy)
}

pub fn collect_file_telemetry<P: AsRef<Path>>(root: P, max_age: Duration) -> io::Result<Vec<FileInfo>> {
    let mut suspicious_files = Vec::new();

    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();

        if path.is_file() {
            let metadata = fs::metadata(path)?;
            let modified_time = metadata.modified().ok();

            let is_recent  = modified_time
                .and_then(|t| SystemTime::now()
                .checked_sub(max_age).map(|cutoff| t>= cutoff))
                .unwrap_or(false);

            let is_hidden = is_hidden(path);
            let is_exec = is_executable_file(path);

            if is_recent || is_hidden || is_exec {
                suspicious_files.push(FileInfo{
                    path: path.to_path_buf(),
                    is_hidden,
                    is_executable: is_exec,
                    last_modified: modified_time,
                    size: metadata.len(),
                    sha256: compute_sha256(path),
                    entropy: calculate_entropy(path),
                });
            }
        }
    }
    Ok(suspicious_files)
}