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

// VAL-001: Missing State Transition Validation
pub struct MissingStateTransitionValidationDetector;

#[async_trait::async_trait]
impl SecurityDetector for MissingStateTransitionValidationDetector {
    fn id(&self) -> &'static str { "VAL-001" }
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

// VAL-002: Improper Capability Validation
pub struct ImproperCapabilityValidationDetector;

#[async_trait::async_trait]
impl SecurityDetector for ImproperCapabilityValidationDetector {
    fn id(&self) -> &'static str { "VAL-002" }
    fn name(&self) -> &'static str { "Improper Capability Validation" }
    fn description(&self) -> &'static str { "Detects functions that receive capabilities but don't validate them properly" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            if let Some(code) = &func_def.code {
                // Check if function takes a capability as parameter
                let sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                
                let mut has_capability_param = false;
                for param in &sig.0 {
                    let param_type_name = format!("{:?}", param);
                    if param_type_name.to_lowercase().contains("cap") || 
                       param_type_name.to_lowercase().contains("admin") {
                        has_capability_param = true;
                        break;
                    }
                }
                
                if has_capability_param {
                    // Check if the capability is validated in the function body
                    let mut has_validation = false;
                    
                    for instr in &code.code {
                        match instr {
                            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                                // In a real implementation, we would check if this validates the capability
                                // For now, we'll just look for validation patterns
                                has_validation = true;
                            }
                            Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | 
                            Bytecode::Eq | Bytecode::Neq => {
                                has_validation = true;
                            }
                            _ => {}
                        }
                    }
                    
                    if !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            title: "Improper capability validation".to_string(),
                            description: "Function receives capability parameter but does not validate it properly".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Validate capability parameters to ensure they are authentic and authorized".to_string(),
                            references: vec!["SUI-027: Capability Validation".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// VAL-003: Missing Input Validation
pub struct MissingInputValidationDetector;

#[async_trait::async_trait]
impl SecurityDetector for MissingInputValidationDetector {
    fn id(&self) -> &'static str { "VAL-003" }
    fn name(&self) -> &'static str { "Missing Input Validation" }
    fn description(&self) -> &'static str { "Detects functions that lack proper input validation" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            if let Some(code) = &func_def.code {
                // Check if function has numeric parameters that should be validated
                let sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                
                let mut has_numeric_param = false;
                for param in &sig.0 {
                    if matches!(param, move_binary_format::file_format::SignatureToken::U8 | 
                                      move_binary_format::file_format::SignatureToken::U64 | 
                                      move_binary_format::file_format::SignatureToken::U128) {
                        has_numeric_param = true;
                        break;
                    }
                }
                
                if has_numeric_param {
                    // Check if the function validates its inputs
                    let mut has_validation = false;
                    
                    for instr in &code.code {
                        match instr {
                            Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | 
                            Bytecode::Eq | Bytecode::Neq => {
                                has_validation = true;
                            }
                            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                                // Could be a validation call
                                has_validation = true;
                            }
                            _ => {}
                        }
                    }
                    
                    if !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            title: "Missing input validation".to_string(),
                            description: "Function accepts numeric parameters without proper validation".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Add input validation to prevent invalid values".to_string(),
                            references: vec!["CWE-125: Out-of-bounds Read".to_string()],
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
pub fn get_improper_validation_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(MissingStateTransitionValidationDetector),
        Box::new(ImproperCapabilityValidationDetector),
        Box::new(MissingInputValidationDetector),
    ]
}