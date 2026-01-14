// Nonce Enforcement Detector
// Detects when nonces are incremented without proper enforcement

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use async_trait::async_trait;
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition},
};

// Helper function to create location
fn create_location(ctx: &DetectionContext, func_def: &FunctionDefinition, idx: u16) -> CodeLocation {
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: idx,
        byte_offset: 0,
        line: None,
        column: None,
    }
}

fn create_module_location(ctx: &DetectionContext) -> CodeLocation {
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: "module".to_string(),
        instruction_index: 0,
        byte_offset: 0,
        line: None,
        column: None,
    }
}

// ========== NONCE ENFORCEMENT DETECTOR ==========
pub struct NonceEnforcementDetector;

#[async_trait]
impl SecurityDetector for NonceEnforcementDetector {
    fn id(&self) -> &'static str { "SEM-006" }
    fn name(&self) -> &'static str { "Nonce Enforcement" }
    fn description(&self) -> &'static str { "Detects when nonces are incremented without proper enforcement" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if let Some(code) = &func_def.code {
                // Check for nonce increment operations
                let has_nonce_increment = code.code.iter().any(|instr| {
                    if let Some(called_func) = get_function_name(instr, &ctx.module) {
                        called_func.contains("nonce") && 
                        (called_func.contains("inc") || called_func.contains("add") || called_func.contains("++"))
                    } else {
                        // Check for Add operations that might be incrementing nonce
                        matches!(instr, Bytecode::Add)
                    }
                });
                
                // Check for nonce usage in comparisons (enforcement)
                let has_nonce_check = code.code.iter().any(|instr| {
                    if let Some(called_func) = get_function_name(instr, &ctx.module) {
                        called_func.contains("nonce") && 
                        (called_func.contains("check") || called_func.contains("compare") || 
                         called_func.contains("assert") || called_func.contains("verify") ||
                         called_func.contains("gt") || called_func.contains("lt") || 
                         called_func.contains(">") || called_func.contains("<"))
                    } else {
                        matches!(instr, Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | 
                                       Bytecode::Eq | Bytecode::Neq)
                    }
                });
                
                // Check for storing used nonces
                let has_nonce_storage = code.code.iter().any(|instr| {
                    if let Some(called_func) = get_function_name(instr, &ctx.module) {
                        called_func.contains("nonce") && 
                        (called_func.contains("store") || called_func.contains("insert") || 
                         called_func.contains("used") || called_func.contains("seen"))
                    } else { false }
                });
                
                // If function increments nonce but doesn't enforce it
                if has_nonce_increment && !has_nonce_check && !has_nonce_storage {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Nonce replay risk in '{}'", func_name),
                        description: format!("Function '{}' increments nonce but doesn't enforce it, creating replay attack risk", func_name),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement proper nonce enforcement. Store used nonces and check against them. Compare new nonce with expected value before proceeding.".to_string(),
                        references: vec![
                            "https://docs.sui.io/concepts/programming-model/objects".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// Helper function to get function name from bytecode
fn get_function_name(instr: &Bytecode, module: &move_binary_format::CompiledModule) -> Option<String> {
    crate::utils::get_function_name(instr, module).map(|s| s.to_string())
}