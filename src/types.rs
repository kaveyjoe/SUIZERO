// src/types.rs
use move_binary_format::file_format::*;
use move_core_types::language_storage::ModuleId;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical = 5,
    High = 4,
    Medium = 3,
    Low = 2,
    Info = 1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    High = 3,
    Medium = 2,
    Low = 1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    pub id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub description: String,
    pub location: CodeLocation,
    pub source_code: Option<String>,
    pub recommendation: String,
    pub references: Vec<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub module_id: String,
    pub module_name: String,
    pub function_name: String,
    pub instruction_index: u16,
    pub byte_offset: u32,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DetectionContext {
    pub module: CompiledModule,
    pub module_bytes: Vec<u8>,
    pub module_id: ModuleId,
    pub dependencies: Vec<CompiledModule>,
    pub config: AnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub check_access_control: bool,
    pub check_reentrancy: bool,
    pub check_arithmetic: bool,
    pub check_objects: bool,
    pub check_events: bool,
    pub check_oracles: bool,
    pub check_gas: bool,
    pub severity_threshold: Severity,
    pub max_issues_per_rule: usize,
    pub include_test_code: bool,
    pub filter_getter_functions: bool,  // New field to filter getter functions
    pub filter_standard_library_patterns: bool,  // New field to filter standard library patterns
    pub filter_test_functions: bool,  // New field to filter test functions
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            check_access_control: true,
            check_reentrancy: true,
            check_arithmetic: true,
            check_objects: true,
            check_events: true,
            check_oracles: true,
            check_gas: true,
            severity_threshold: Severity::Low,
            max_issues_per_rule: 100,
            include_test_code: false,
            filter_getter_functions: true,  // Enable by default
            filter_standard_library_patterns: true,  // Enable by default
            filter_test_functions: true,  // Enable by default
        }
    }
}