use crate::types::{AnalysisConfig, SecurityIssue};
use crate::core::engine::DetectionEngine;
use std::path::{Path, PathBuf};
use move_binary_format::CompiledModule;
use std::collections::HashMap;

pub struct SuiSecurityAnalyzer {
    config: AnalysisConfig,
    engine: DetectionEngine,
}

#[derive(Debug, Default)]
pub struct AnalysisReport {
    pub issues: Vec<SecurityIssue>,
    pub stats: HashMap<String, String>,
}

pub struct ScanResult {
    pub reports: HashMap<PathBuf, AnalysisReport>,
}

impl SuiSecurityAnalyzer {
    pub fn new(config: AnalysisConfig) -> Self {
        Self {
            config,
            engine: DetectionEngine::new(),
        }
    }

    pub fn enable_detectors(&mut self, detectors: &[&str]) {
        // TODO: Implement enable logic in engine/registry
    }

    pub fn disable_detectors(&mut self, detectors: &[String]) { // Changed signature to match likely usage
         // TODO: Implement disable logic in engine/registry
    }
    
    pub async fn analyze_module(&mut self, module_bytes: &[u8]) -> Result<AnalysisReport, anyhow::Error> {
        let module = CompiledModule::deserialize_with_defaults(module_bytes)?;
        let result = self.engine.analyze_module(&module, &self.config).await;
        
        Ok(AnalysisReport {
            issues: result.issues,
            stats: HashMap::new(), // Populate if needed
        })
    }
    
    pub async fn analyze_directory(&mut self, path: &Path, _parallel: bool) -> Result<AnalysisReport, anyhow::Error> {
        // Simple implementation: walk directory, find .mv files
        let mut all_issues = Vec::new();
        
        for entry in walkdir::WalkDir::new(path) {
            let entry = entry?;
            let path_str = entry.path().to_string_lossy();
            
            // Skip dependencies
            if path_str.contains("/dependencies/") || path_str.contains("\\dependencies\\") {
                continue;
            }

            if entry.path().extension().map_or(false, |e| e == "mv") {
                let bytes = std::fs::read(entry.path())?;
                if let Ok(module) = CompiledModule::deserialize_with_defaults(&bytes) {
                     let result = self.engine.analyze_module(&module, &self.config).await;
                     all_issues.extend(result.issues);
                }
            }
        }

        /*
        // Apply strict global limit for all modules combined
        if all_issues.len() > 9 {
            all_issues.sort_by(|a, b| {
                let a_score = self.issue_score(a);
                let b_score = self.issue_score(b);
                b_score.cmp(&a_score)
            });
            all_issues.truncate(9);
        }
        */
        
        Ok(AnalysisReport {
            issues: all_issues,
            stats: HashMap::new(),
        })
    }

    fn issue_score(&self, issue: &SecurityIssue) -> u32 {
        let s_score = match issue.severity {
            crate::types::Severity::Critical => 100,
            crate::types::Severity::High => 80,
            crate::types::Severity::Medium => 50,
            crate::types::Severity::Low => 20,
            crate::types::Severity::Info => 0,
        };
        let c_score = match issue.confidence {
            crate::types::Confidence::High => 10,
            crate::types::Confidence::Medium => 5,
            crate::types::Confidence::Low => 1,
        };
        s_score + c_score
    }

    pub async fn scan_directory(&mut self, path: &Path) -> Result<ScanResult, anyhow::Error> {
        let mut reports = HashMap::new();
        // Simple implementation
        for entry in walkdir::WalkDir::new(path) {
            let entry = entry?;
            if entry.path().extension().map_or(false, |e| e == "mv") {
                 let bytes = std::fs::read(entry.path())?;
                 if let Ok(module) = CompiledModule::deserialize_with_defaults(&bytes) {
                      let result = self.engine.analyze_module(&module, &self.config).await;
                      let report = AnalysisReport {
                          issues: result.issues,
                          stats: HashMap::new(),
                      };
                      reports.insert(entry.path().to_path_buf(), report);
                 }
            }
        }
        Ok(ScanResult { reports })
    }
}