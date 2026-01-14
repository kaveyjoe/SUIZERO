use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition, SignatureToken},
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

// SPEC-001: Missing Check-Effects-Interactions Pattern
pub struct MissingCEIPatternDetector;

#[async_trait::async_trait]
impl SecurityDetector for MissingCEIPatternDetector {
    fn id(&self) -> &'static str { "SPEC-001" }
    fn name(&self) -> &'static str { "Missing Check-Effects-Interactions Pattern" }
    fn description(&self) -> &'static str { "Detects functions that don't follow the Checks-Effects-Interactions pattern" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            if let Some(code) = &func_def.code {
                let mut has_external_call = false;
                let mut has_state_write_after_external_call = false;
                
                // Track positions of external calls and state writes
                for (i, instr) in code.code.iter().enumerate() {
                    match instr {
                        Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                            // Check if this is an external call (transfer, etc.)
                            if func_name.contains("withdraw") || func_name.contains("transfer") {
                                has_external_call = true;
                                
                                // Check if there are state writes after this point
                                for j in (i + 1)..code.code.len() {
                                    if matches!(code.code[j], Bytecode::WriteRef | 
                                                              Bytecode::MoveTo(_) | 
                                                              Bytecode::MoveToGeneric(_)) {
                                        has_state_write_after_external_call = true;
                                        break;
                                    }
                                }
                            }
                        }
                        Bytecode::WriteRef | 
                        Bytecode::MoveTo(_) | 
                        Bytecode::MoveToGeneric(_) => {
                            if has_external_call {
                                has_state_write_after_external_call = true;
                            }
                        }
                        _ => {}
                    }
                }
                
                if has_external_call && has_state_write_after_external_call {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: Severity::Critical,
                        confidence: Confidence::High,
                        title: "Missing Checks-Effects-Interactions pattern".to_string(),
                        description: "Function performs external calls before updating state, creating reentrancy risk".to_string(),
                        location: create_loc(ctx, idx, 0),
                        source_code: Some(func_name),
                        recommendation: "Follow the Checks-Effects-Interactions pattern: checks first, then effects, then interactions".to_string(),
                        references: vec!["SWC-107: Reentrancy".to_string()],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// SPEC-002: Unprotected Capability Minting
pub struct UnprotectedCapabilityMintingDetector;

#[async_trait::async_trait]
impl SecurityDetector for UnprotectedCapabilityMintingDetector {
    fn id(&self) -> &'static str { "SPEC-002" }
    fn name(&self) -> &'static str { "Unprotected Capability Minting" }
    fn description(&self) -> &'static str { "Detects functions that allow anyone to mint capabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for functions that create new objects that look like capabilities
            if func_name.contains("mint") || func_name.contains("create") || func_name.contains("new") {
                if let Some(code) = &func_def.code {
                    for (i, instr) in code.code.iter().enumerate() {
                        if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                            // Check if this creates a new capability object
                            if func_name.contains("cap") || func_name.contains("admin") {
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(),
                                    severity: Severity::Critical,
                                    confidence: Confidence::High,
                                    title: "Unprotected capability minting".to_string(),
                                    description: "Function allows minting of capability objects without proper authorization".to_string(),
                                    location: create_loc(ctx, idx, i as u16),
                                    source_code: Some(func_name.clone()),
                                    recommendation: "Add proper authorization checks before minting capability objects".to_string(),
                                    references: vec!["SUI-029: Capability Security".to_string()],
                                    metadata: HashMap::new(),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        issues
    }
}

// SPEC-003: Predictable Random Number Generation
pub struct PredictableRandomNumberDetector;

#[async_trait::async_trait]
impl SecurityDetector for PredictableRandomNumberDetector {
    fn id(&self) -> &'static str { "SPEC-003" }
    fn name(&self) -> &'static str { "Predictable Random Number Generation" }
    fn description(&self) -> &'static str { "Detects use of predictable sources for random number generation" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    match instr {
                        Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                            // Look for calls that might be accessing predictable sources
                            // In the bytecode, we'd need to check the specific function being called
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::Medium,
                                title: "Potential predictable random number source".to_string(),
                                description: "Function may be using predictable source for randomness".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Use Sui's random beacon or other cryptographically secure randomness sources".to_string(),
                                references: vec!["SWC-120: Weak Randomness".to_string()],
                                metadata: HashMap::new(),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        
        issues
    }
}

// SPEC-004: Missing Access Control Validation
pub struct MissingAccessControlValidationDetector;

#[async_trait::async_trait]
impl SecurityDetector for MissingAccessControlValidationDetector {
    fn id(&self) -> &'static str { "SPEC-004" }
    fn name(&self) -> &'static str { "Missing Access Control Validation" }
    fn description(&self) -> &'static str { "Detects functions that receive authorization parameters but don't validate them" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            if let Some(code) = &func_def.code {
                // Check function signature for potential authz parameters
                let sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                
                let mut has_auth_param = false;
                for param in &sig.0 {
                    if let SignatureToken::Struct(_) = param {
                        let param_str = format!("{:?}", param).to_lowercase();
                        if param_str.contains("cap") || param_str.contains("auth") || param_str.contains("admin") {
                            has_auth_param = true;
                            break;
                        }
                    }
                }
                
                if has_auth_param {
                    // Check if the auth parameter is actually validated in the function
                    let mut has_validation = false;
                    for instr in &code.code {
                        match instr {
                            Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | 
                            Bytecode::Eq | Bytecode::Neq | Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                                has_validation = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    
                    if !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            title: "Missing access control validation".to_string(),
                            description: "Function receives authorization parameter but does not validate it".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Validate authorization parameters before performing sensitive operations".to_string(),
                            references: vec!["SWC-105: Insufficient Gas Limit".to_string()],
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
pub fn get_specific_vulnerability_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(MissingCEIPatternDetector),
        Box::new(UnprotectedCapabilityMintingDetector),
        Box::new(PredictableRandomNumberDetector),
        Box::new(MissingAccessControlValidationDetector),
    ]
}