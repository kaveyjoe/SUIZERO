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
                              struct_name.to_lowercase().contains("permit") ||
                              struct_name.to_lowercase().contains("cap") ||
                              struct_name.to_lowercase().contains("admin");
            
            if is_auth_like {
                // Check if this struct has the drop ability (making it forgeable) OR is just used as phantom auth
                let abilities = struct_handle.abilities;
                let has_drop = abilities.has_drop();
                
                // Check if there are functions that take this struct as parameter but don't validate it
                for func_def in &ctx.module.function_defs {
                    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                    let func_name = ctx.module.identifier_at(func_handle.name);
                    
                    // Check if function takes the auth struct as parameter
                    let takes_auth_struct = {
                        let param_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                        param_sig.0.iter().any(|param| {
                            match param {
                                SignatureToken::Struct(param_struct_idx) | 
                                SignatureToken::StructInstantiation(param_struct_idx, _) => {
                                    param_struct_idx.0 as usize == struct_idx
                                },
                                SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                                    match &**inner {
                                        SignatureToken::Struct(param_struct_idx) | 
                                        SignatureToken::StructInstantiation(param_struct_idx, _) => {
                                            param_struct_idx.0 as usize == struct_idx
                                        },
                                        _ => false
                                    }
                                },
                                _ => false
                            }
                        })
                    };
                    
                    if takes_auth_struct {
                        // Check if function actually validates the capability
                        let is_validated = {
                            if let Some(code) = &func_def.code {
                                // Look for comparisons or assertions involving the parameter
                                let mut validated = false;
                                let mut param_index = 0;
                                
                                // Find the index of the auth struct parameter
                                let param_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                                for (idx, param) in param_sig.0.iter().enumerate() {
                                    match param {
                                        SignatureToken::Struct(param_struct_idx) | 
                                        SignatureToken::StructInstantiation(param_struct_idx, _) => {
                                            if param_struct_idx.0 as usize == struct_idx {
                                                param_index = idx;
                                                break;
                                            }
                                        },
                                        SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                                            match &**inner {
                                                SignatureToken::Struct(param_struct_idx) | 
                                                SignatureToken::StructInstantiation(param_struct_idx, _) => {
                                                    if param_struct_idx.0 as usize == struct_idx {
                                                        param_index = idx;
                                                        break;
                                                    }
                                                },
                                                _ => {}
                                            }
                                        },
                                        _ => {}
                                    }
                                }
                                
                                // Check if the parameter is used in comparisons or assertions
                                for instr in &code.code {
                                    match instr {
                                        Bytecode::MoveLoc(loc_idx) | Bytecode::CopyLoc(loc_idx) | Bytecode::ImmBorrowLoc(loc_idx) | Bytecode::MutBorrowLoc(loc_idx) => {
                                            if *loc_idx == param_index as u8 {
                                                // Parameter is moved/copied, check if used in meaningful way
                                                validated = true;
                                                break;
                                            }
                                        },
                                        Bytecode::Eq | Bytecode::Neq | Bytecode::Abort | Bytecode::BrTrue(_) | Bytecode::BrFalse(_) => {
                                            // These instructions often indicate validation
                                            validated = true;
                                            break;
                                        },
                                        _ => {}
                                    }
                                }
                                validated
                            } else { false }
                        };
                        
                        if !is_validated {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: format!("Phantom authorization in '{}'", func_name),
                                description: format!("Function '{}' takes authorization struct '{}' as parameter but does not validate it properly. This gives a false sense of security and may allow unauthorized access to sensitive operations.", func_name, struct_name),
                                location: create_location(ctx, func_def, 0),
                                source_code: Some(format!("{} takes {}", func_name, struct_name)),
                                recommendation: "Properly validate authorization structures by checking their ID or other identifying characteristics. Either use the capability for access control or remove it from the function signature.".to_string(),
                                references: vec![
                                    "https://docs.sui.io/concepts/programming-model/capabilities".to_string(),
                                ],
                                metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                    
                    // Also check if function returns this struct without proper validation (original logic)
                    if has_drop {
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
        
        issues
    }
}

// Helper function to get function name from bytecode
fn get_function_name(instr: &Bytecode, module: &move_binary_format::CompiledModule) -> Option<String> {
    crate::utils::get_function_name(instr, module).map(|s| s.to_string())
}