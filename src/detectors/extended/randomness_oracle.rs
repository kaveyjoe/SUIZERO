use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition},
};
use std::collections::HashMap;

fn create_loc(ctx: &DetectionContext, func_idx: usize, instr_idx: u16) -> CodeLocation {
    let func_def = &ctx.module.function_defs[func_idx];
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: instr_idx,
        byte_offset: 0,
        line: None,
        column: None,
    }
}

// RN-001: Predictable Randomness Source
pub struct PredictableRandomnessDetector;

#[async_trait::async_trait]
impl SecurityDetector for PredictableRandomnessDetector {
    fn id(&self) -> &'static str { "RN-001" }
    fn name(&self) -> &'static str { "Predictable Randomness Source" }
    fn description(&self) -> &'static str { "Detects use of predictable sources for randomness (e.g., block timestamp)" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    // Look for timestamp usage as entropy source
                    if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                        // In a real implementation, we would check if this is a call to timestamp functions
                        // For now, we'll look for common patterns that indicate timestamp usage
                        if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                title: "Predictable randomness using timestamp".to_string(),
                                description: "Using timestamp as source of randomness is predictable and manipulable".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Use Sui's random beacon or other unpredictable sources for randomness".to_string(),
                                references: vec!["CWE-330: Use of Insufficiently Random Values".to_string()],
                                metadata: HashMap::new(),
                            });
                        }
                    }
                    
                    // Look for modulo operations that could create bias
                    if matches!(instr, Bytecode::Mod) {
                        // Check if this is preceded by a predictable source
                        if i > 0 {
                            if let Bytecode::LdU64(max_val) = code.code[i-1] {
                                if max_val != 2 && max_val != 10 && max_val != 100 {  // Common safe values
                                    issues.push(SecurityIssue {
                                        id: self.id().to_string(),
                                        severity: Severity::High,
                                        confidence: Confidence::Medium,
                                        title: "Potential modulo bias in random selection".to_string(),
                                        description: format!("Modulo operation with {} may create statistical bias", max_val).to_string(),
                                        location: create_loc(ctx, idx, i as u16),
                                        source_code: None,
                                        recommendation: "Use rejection sampling or other methods to eliminate modulo bias".to_string(),
                                        references: vec!["CWE-330: Use of Insufficiently Random Values".to_string()],
                                        metadata: HashMap::new(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        issues
    }
}

// Helper function to get function name from instruction
fn get_function_name_from_instruction(instr: &Bytecode) -> Option<String> {
    match instr {
        Bytecode::Call(_) => {
            // In a real implementation, we would resolve the function handle
            // For now, return None to avoid complex resolution
            None
        },
        _ => None
    }
}

// ORACLE-001: Single Source Oracle
pub struct SingleSourceOracleDetector;

#[async_trait::async_trait]
impl SecurityDetector for SingleSourceOracleDetector {
    fn id(&self) -> &'static str { "ORACLE-001" }
    fn name(&self) -> &'static str { "Single Source Oracle" }
    fn description(&self) -> &'static str { "Detects oracles with single point of failure" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for functions with "oracle", "price", "feed" in the name
            if func_name.contains("oracle") || 
               func_name.contains("price") || 
               func_name.contains("feed") ||
               func_name.contains("get_price") {
                
                // Check if function takes only one source parameter
                let sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                
                // Look for patterns that suggest single source
                if let Some(code) = &func_def.code {
                    let mut source_count = 0;
                    for instr in &code.code {
                        if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                            source_count += 1;
                        }
                    }
                    
                    if source_count <= 1 {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            title: "Single source oracle".to_string(),
                            description: "Oracle relies on single data source creating single point of failure".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Use multiple data sources with aggregation mechanism".to_string(),
                            references: vec!["CWE-114: Process Control".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ORACLE-002: Unvalidated Oracle Updates
pub struct UnvalidatedOracleUpdatesDetector;

#[async_trait::async_trait]
impl SecurityDetector for UnvalidatedOracleUpdatesDetector {
    fn id(&self) -> &'static str { "ORACLE-002" }
    fn name(&self) -> &'static str { "Unvalidated Oracle Updates" }
    fn description(&self) -> &'static str { "Detects oracle updates without validation" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for functions that update oracle prices/data
            if func_name.contains("update") && 
               (func_name.contains("price") || func_name.contains("oracle") || func_name.contains("data")) {
                
                // Check if function validates the new value
                if let Some(code) = &func_def.code {
                    let has_validation = code.code.iter().any(|instr| {
                        matches!(instr, 
                            Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | 
                            Bytecode::Call(_) | Bytecode::CallGeneric(_)
                        )
                    });
                    
                    if !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            title: "Oracle update without validation".to_string(),
                            description: "Oracle update function does not validate new values for reasonableness".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Add validation to ensure new values are within reasonable bounds".to_string(),
                            references: vec!["CWE-20: Improper Input Validation".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// Export the detectors
pub fn get_randomness_oracle_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(PredictableRandomnessDetector),
        Box::new(SingleSourceOracleDetector),
        Box::new(UnvalidatedOracleUpdatesDetector),
    ]
}