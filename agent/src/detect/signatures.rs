use yara::{Compiler, Rules, Scanner};
use std::fs;
use std::path::Path;
use crate::telemetry::file::FileInfo;

#[derive(Debug)]
pub struct SignatureMatch {
    pub file_path: String,
    pub rule_name: String,
    pub tags: Vec<String>,
    pub meta: Vec<(String, String)>
}

pub fn compile_rules_from_dir<P: AsRef<Path>>(dir: P) -> Result<Rules, yara::Error> {
    let mut compiler = Compiler::new()?;

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map(|ext| ext == "yar").unwrap_or(false) {
            compiler.add_rules_file(&path)?;
        }
    }
    compiler.compile_rules()
}

pub fn scan_files_with_rules(files: &[FileInfo], rules: &Rules) -> Vec<SignatureMatch> {
    let mut matches = Vec::new();
    let mut scanner = rules.scanner().unwrap();

    for file in files {
        if let Ok(buffer) = fs::read(&file.path) {
            scanner = scanner.clear();
            if let Ok(results) = scanner.scan_mem(&buffer) {
                for rule in results.iter() {
                    matches.push(SignatureMatch{
                        file_path: file.path.to_string_lossy().to_string(),
                        rule_name: rule.identifier.to_string(),
                        tags: rule.tags.clone(),
                        meta: rule
                            .metadatas
                            .iter()
                            .map(|(k, v)| (k.clone(), v.to_string()))
                            .collect(), 
                    });
                }
            }
        }
    }
    matches
}