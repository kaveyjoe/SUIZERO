// Unauthenticated Emergency Function Detector
// Detects when emergency functions don't properly authenticate

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use async_trait::async_trait;
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition, SignatureToken},
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

// ========== UNAUTHENTICATED EMERGENCY FUNCTION DETECTOR ==========
pub struct UnauthenticatedEmergencyFunctionDetector;

#[async_trait]
impl SecurityDetector for UnauthenticatedEmergencyFunctionDetector {
    fn id(&self) -> &'static str { "SEM-005" }
    fn name(&self) -> &'static str { "Unauthenticated Emergency Function" }
    fn description(&self) -> &'static str { "Detects when emergency functions don't properly authenticate" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Check if function name suggests it's an emergency function
            let is_emergency_function = func_name.as_str().to_lowercase().contains("emergency") ||
                                       func_name.as_str().to_lowercase().contains("drain") ||
                                       func_name.as_str().to_lowercase().contains("rescue") ||
                                       func_name.as_str().to_lowercase().contains("force") ||
                                       func_name.as_str().to_lowercase().contains("admin") ||
                                       func_name.as_str().to_lowercase().contains("kill") ||
                                       func_name.as_str().to_lowercase().contains("shutdown") ||
                                       func_name.as_str().to_lowercase().contains("pause");
            
            if is_emergency_function {
                if let Some(code) = &func_def.code {
                    // Check if function mutates shared/global state
                    let mutates_global_state = code.code.iter().any(|instr| {
                        matches!(
                            instr,
                            Bytecode::MutBorrowGlobal(_) |
                            Bytecode::MutBorrowGlobalGeneric(_) |
                            Bytecode::MoveFrom(_) |
                            Bytecode::MoveFromGeneric(_) |
                            Bytecode::MoveTo(_) |
                            Bytecode::MoveToGeneric(_)
                        )
                    });
                    
                    // Check if function performs destructive operations
                    let performs_destructive_ops = func_name.as_str().to_lowercase().contains("drain") ||
                                                  func_name.as_str().to_lowercase().contains("rescue") ||
                                                  func_name.as_str().to_lowercase().contains("kill") ||
                                                  func_name.as_str().to_lowercase().contains("delete") ||
                                                  func_name.as_str().to_lowercase().contains("destroy");
                    
                    // Check if function validates capabilities or authentication
                    let validates_auth = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("assert") || 
                            called_func.contains("check") ||
                            called_func.contains("verify") ||
                            called_func.contains("sender") ||
                            called_func.contains("auth") ||
                            called_func.contains("cap") ||
                            called_func.contains("admin")
                        } else { false }
                    });
                    
                    // Check for capability parameters - simplified to avoid complex nested syntax
                    let has_capability_param = {
                        let params_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                        let mut found_cap = false;
                        for param in &params_sig.0 {
                            match param {
                                SignatureToken::Struct(struct_idx) | 
                                SignatureToken::StructInstantiation(struct_idx, _) => {
                                    let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                    let struct_name = ctx.module.identifier_at(struct_handle.name);
                                    let struct_name_lower = struct_name.as_str().to_lowercase();
                                    if struct_name_lower.contains("cap") || 
                                       struct_name_lower.contains("admin") || 
                                       struct_name_lower.contains("owner") ||
                                       struct_name_lower.contains("auth") {
                                        found_cap = true;
                                        break;
                                    }
                                },
                                SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                                    match &**inner {
                                        SignatureToken::Struct(struct_idx) | 
                                        SignatureToken::StructInstantiation(struct_idx, _) => {
                                            let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                            let struct_name = ctx.module.identifier_at(struct_handle.name);
                                            let struct_name_lower = struct_name.as_str().to_lowercase();
                                            if struct_name_lower.contains("cap") || 
                                               struct_name_lower.contains("admin") || 
                                               struct_name_lower.contains("owner") ||
                                               struct_name_lower.contains("auth") {
                                                found_cap = true;
                                                break;
                                            }
                                        },
                                        _ => {}
                                    }
                                },
                                _ => {}
                            }
                        }
                        found_cap
                    };
                    
                    // If function is emergency-related and mutates global state without auth validation
                    if mutates_global_state && performs_destructive_ops && !validates_auth && !has_capability_param {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Unauthenticated emergency function '{}'", func_name),
                            description: format!("Emergency function '{}' mutates global state without proper authentication", func_name),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Require proper authentication for emergency functions. Use capability-based access control or sender validation before performing destructive operations.".to_string(),
                            references: vec![
                                "https://docs.sui.io/concepts/programming-model/capabilities".to_string(),
                            ],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
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