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

// STATE-001: Missing State Transition Validation
pub struct MissingStateTransitionValidationDetector;

#[async_trait::async_trait]
impl SecurityDetector for MissingStateTransitionValidationDetector {
    fn id(&self) -> &'static str { "STATE-001" }
    fn name(&self) -> &'static str { "Missing State Transition Validation" }
    fn description(&self) -> &'static str { "Detects state transitions without proper validation" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for functions that suggest state transition
            if func_name.contains("transition") || 
               func_name.contains("change") || 
               func_name.contains("update") ||
               func_name.contains("set_state") {
                
                if let Some(code) = &func_def.code {
                    // Check for state field modifications without validation
                    let mut has_write = false;
                    let mut has_validation = false;
                    
                    for instr in &code.code {
                        match instr {
                            Bytecode::WriteRef => {
                                has_write = true;
                            }
                            Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | 
                            Bytecode::Eq | Bytecode::Neq | Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                                has_validation = true;
                            }
                            _ => {}
                        }
                    }
                    
                    if has_write && !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            title: "State transition without validation".to_string(),
                            description: "State transition function does not validate new state value".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Add validation to ensure state transitions are allowed".to_string(),
                            references: vec!["CWE-694: Use of Multiple Resources with Duplicate Associated Handles".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// STATE-002: Invalid State Transition
pub struct InvalidStateTransitionDetector;

#[async_trait::async_trait]
impl SecurityDetector for InvalidStateTransitionDetector {
    fn id(&self) -> &'static str { "STATE-002" }
    fn name(&self) -> &'static str { "Invalid State Transition" }
    fn description(&self) -> &'static str { "Detects potentially invalid state transitions" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for functions that might perform invalid transitions
            if func_name.contains("transition") || 
               func_name.contains("change") || 
               func_name.contains("to_") ||
               func_name.contains("_to_") {
                
                if let Some(code) = &func_def.code {
                    // Look for patterns that might indicate invalid transitions
                    for (i, instr) in code.code.iter().enumerate() {
                        if matches!(instr, Bytecode::LdU8(3) | Bytecode::LdU8(4) | Bytecode::LdU64(255)) {
                            // Possible invalid state values
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Medium,
                                title: "Potentially invalid state transition".to_string(),
                                description: "Function sets state to potentially invalid value".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: Some(func_name.clone()),
                                recommendation: "Validate state values against defined state enum".to_string(),
                                references: vec!["CWE-694: Use of Multiple Resources with Duplicate Associated Handles".to_string()],
                                metadata: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        
        issues
    }
}

// STATE-003: Race Condition in State Update
pub struct RaceConditionStateUpdateDetector;

#[async_trait::async_trait]
impl SecurityDetector for RaceConditionStateUpdateDetector {
    fn id(&self) -> &'static str { "STATE-003" }
    fn name(&self) -> &'static str { "Race Condition in State Update" }
    fn description(&self) -> &'static str { "Detects check-then-act patterns that can cause race conditions" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for functions that might have check-then-act patterns
            if func_name.contains("claim") || 
               func_name.contains("mint") || 
               func_name.contains("transfer") ||
               func_name.contains("withdraw") {
                
                if let Some(code) = &func_def.code {
                    // Look for read-modify-write patterns without atomic operations
                    let mut read_positions = Vec::new();
                    let mut write_positions = Vec::new();
                    
                    for (i, instr) in code.code.iter().enumerate() {
                        match instr {
                            Bytecode::ReadRef => {
                                read_positions.push(i);
                            }
                            Bytecode::WriteRef => {
                                write_positions.push(i);
                            }
                            _ => {}
                        }
                    }
                    
                    // If we have reads followed by writes without proper synchronization
                    if !read_positions.is_empty() && !write_positions.is_empty() {
                        for &read_pos in &read_positions {
                            for &write_pos in &write_positions {
                                if read_pos < write_pos {
                                    // Check if there are any validation calls between read and write
                                    let mut has_validation = false;
                                    for j in read_pos..write_pos {
                                        if j < code.code.len() {
                                            if matches!(code.code[j], 
                                                Bytecode::Call(_) | Bytecode::CallGeneric(_) |
                                                Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge |
                                                Bytecode::Eq | Bytecode::Neq) {
                                                    has_validation = true;
                                                    break;
                                                }
                                        }
                                    }
                                    
                                    if !has_validation {
                                        issues.push(SecurityIssue {
                                            id: self.id().to_string(),
                                            severity: Severity::High,
                                            confidence: Confidence::Medium,
                                            title: "Potential race condition in state update".to_string(),
                                            description: "Check-then-act pattern without atomic operation".to_string(),
                                            location: create_loc(ctx, idx, write_pos as u16),
                                            source_code: Some(func_name.clone()),
                                            recommendation: "Use atomic operations or proper synchronization".to_string(),
                                            references: vec!["CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')".to_string()],
                                            metadata: HashMap::new(),
                                        });
                                    }
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

// STATE-004: Double Spending Vulnerability
pub struct DoubleSpendingDetector;

#[async_trait::async_trait]
impl SecurityDetector for DoubleSpendingDetector {
    fn id(&self) -> &'static str { "STATE-004" }
    fn name(&self) -> &'static str { "Double Spending Vulnerability" }
    fn description(&self) -> &'static str { "Detects potential double spending vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for functions related to spending/usage
            if func_name.contains("spend") || 
               func_name.contains("use") || 
               func_name.contains("consume") ||
               func_name.contains("transfer") ||
               func_name.contains("withdraw") {
                
                if let Some(code) = &func_def.code {
                    // Look for patterns where spent flag is not properly set
                    for (i, instr) in code.code.iter().enumerate() {
                        if matches!(instr, Bytecode::WriteRef) {
                            // Check if this is setting a spent flag to false when it should be true
                            if i > 0 && i < code.code.len() {
                                if let Bytecode::LdU8(0) | Bytecode::LdU64(0) = code.code[i-1] {
                                    issues.push(SecurityIssue {
                                        id: self.id().to_string(),
                                        severity: Severity::Critical,
                                        confidence: Confidence::High,
                                        title: "Potential double spending vulnerability".to_string(),
                                        description: "Resource marked as unspent when it should be spent".to_string(),
                                        location: create_loc(ctx, idx, i as u16),
                                        source_code: Some(func_name.clone()),
                                        recommendation: "Ensure spent flags are properly set to prevent double usage".to_string(),
                                        references: vec!["CWE-841: Improper Enforcement of Behavioral Workflow".to_string()],
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

// Export the detectors
pub fn get_state_machine_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(MissingStateTransitionValidationDetector),
        Box::new(InvalidStateTransitionDetector),
        Box::new(RaceConditionStateUpdateDetector),
        Box::new(DoubleSpendingDetector),
    ]
}