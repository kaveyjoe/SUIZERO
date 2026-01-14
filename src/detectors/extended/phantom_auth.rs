// Phantom Authorization Detector
// Detects when authorization structures can be forged without proper validation

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition, SignatureToken, AbilitySet, Ability},
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

// ========== PHANTOM AUTHORIZATION DETECTOR ==========
pub struct PhantomAuthorizationDetector;

#[async_trait::async_trait]
impl SecurityDetector for PhantomAuthorizationDetector {
    fn id(&self) -> &'static str { "SEM-002" }
    fn name(&self) -> &'static str { "Phantom Authorization" }
    fn description(&self) -> &'static str { "Detects when authorization structures can be forged without proper validation" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Find all structs that might act as authorization
        for (struct_idx, struct_def) in ctx.module.struct_defs.iter().enumerate() {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str();
            
            // Check if this struct looks like an authorization structure
            let is_auth_like = struct_name.to_lowercase().contains("receipt") ||
                              struct_name.to_lowercase().contains("proof") ||
                              struct_name.to_lowercase().contains("ticket") ||
                              struct_name.to_lowercase().contains("claim") ||
                              struct_name.to_lowercase().contains("auth") ||
                              struct_name.to_lowercase().contains("permit");
            
            if is_auth_like {
                // Check if the struct has the drop ability (making it forgeable)
                let abilities = struct_handle.abilities;
                let has_drop = abilities.has_drop();
                
                if has_drop {
                    // Check if there are public functions that return this struct without proper validation
                    for func_def in &ctx.module.function_defs {
                        let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                        let func_name = ctx.module.identifier_at(func_handle.name);
                        
                        // Check if function is public and returns this struct
                        if matches!(func_def.visibility, move_binary_format::file_format::Visibility::Public) {
                            let returns_auth_struct = {
                                let return_sig = &ctx.module.signatures[func_handle.return_.0 as usize];
                                return_sig.0.iter().any(|ret_type| {
                                    match ret_type {
                                        SignatureToken::Struct(ret_struct_idx) | 
                                        SignatureToken::StructInstantiation(ret_struct_idx, _) => {
                                            ret_struct_idx.0 as usize == struct_idx
                                        },
                                        SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                                            match &**inner {
                                                SignatureToken::Struct(ret_struct_idx) | 
                                                SignatureToken::StructInstantiation(ret_struct_idx, _) => {
                                                    ret_struct_idx.0 as usize == struct_idx
                                                },
                                                _ => false
                                            }
                                        },
                                        _ => false
                                    }
                                })
                            };
                            
                            // Check if function name suggests forging/creation
                            let is_forging_like = func_name.as_str().contains("forge") ||
                                                 func_name.as_str().contains("create") ||
                                                 func_name.as_str().contains("make") ||
                                                 func_name.as_str().contains("new") ||
                                                 func_name.as_str().contains("gen");
                            
                            if returns_auth_struct && is_forging_like {
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(),
                                    severity: self.default_severity(),
                                    confidence: Confidence::High,
                                    title: format!("Phantom authorization structure '{}'", struct_name),
                                    description: format!("Struct '{}' has drop ability and can be forged through public functions", struct_name),
                                    location: create_location(ctx, func_def, 0),
                                    source_code: Some(format!("{} returns {}", func_name, struct_name)),
                                    recommendation: "Remove drop ability from authorization structures. Require proper validation before issuing authorization tokens. Use cryptographic commitments or issuer tracking.".to_string(),
                                    references: vec![
                                        "https://docs.sui.io/concepts/programming-model/capabilities".to_string(),
                                    ],
                                    metadata: std::collections::HashMap::new(),
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

// Helper function to get function name from bytecode
fn get_function_name(instr: &Bytecode, module: &move_binary_format::CompiledModule) -> Option<String> {
    crate::utils::get_function_name(instr, module).map(|s| s.to_string())
}