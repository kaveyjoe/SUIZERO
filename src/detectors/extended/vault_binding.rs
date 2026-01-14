// Extended Vault-Potato Binding Security Detector
// Detects when potatoes can be redeemed without proper vault binding

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
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

// ========== VAULT-POTATO BINDING DETECTOR ==========
pub struct VaultPotatoBindingDetector;

#[async_trait::async_trait]
impl SecurityDetector for VaultPotatoBindingDetector {
    fn id(&self) -> &'static str { "SUI-033" }
    fn name(&self) -> &'static str { "Vault-Potato Binding" }
    fn description(&self) -> &'static str { "Detects missing vault-potato binding validation allowing unauthorized redemption" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Look for functions that might redeem or process potatoes
            if func_name.as_str().contains("redeem") || 
               func_name.as_str().contains("withdraw") || 
               func_name.as_str().contains("process") ||
               func_name.as_str().contains("burn") {
                
                if let Some(code) = &func_def.code {
                    // Check if function accepts a Potato struct
                    let has_potato_param = {
                        let params_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                        params_sig.0.iter().any(|param| {
                            match param {
                                SignatureToken::Struct(struct_idx) | 
                                SignatureToken::StructInstantiation(struct_idx, _) => {
                                    let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                    let struct_name = ctx.module.identifier_at(struct_handle.name);
                                    struct_name.as_str().contains("Potato") || struct_name.as_str().contains("potato")
                                },
                                SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                                    match &**inner {
                                        SignatureToken::Struct(struct_idx) | 
                                        SignatureToken::StructInstantiation(struct_idx, _) => {
                                            let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                            let struct_name = ctx.module.identifier_at(struct_handle.name);
                                            struct_name.as_str().contains("Potato") || struct_name.as_str().contains("potato")
                                        },
                                        _ => false
                                    }
                                },
                                _ => false
                            }
                        })
                    };
                    
                    // Check if function accepts a Vault struct
                    let has_vault_param = {
                        let params_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                        params_sig.0.iter().any(|param| {
                            match param {
                                SignatureToken::Struct(struct_idx) | 
                                SignatureToken::StructInstantiation(struct_idx, _) => {
                                    let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                    let struct_name = ctx.module.identifier_at(struct_handle.name);
                                    struct_name.as_str().contains("Vault") || struct_name.as_str().contains("vault")
                                },
                                SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                                    match &**inner {
                                        SignatureToken::Struct(struct_idx) | 
                                        SignatureToken::StructInstantiation(struct_idx, _) => {
                                            let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                            let struct_name = ctx.module.identifier_at(struct_handle.name);
                                            struct_name.as_str().contains("Vault") || struct_name.as_str().contains("vault")
                                        },
                                        _ => false
                                    }
                                },
                                _ => false
                            }
                        })
                    };
                    
                    // Check for vault-potato binding validation
                    let has_binding_check = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("binding") || 
                            called_func.contains("validate") || 
                            called_func.contains("check") ||
                            called_func.contains("verify") ||
                            called_func.contains("owns") ||
                            called_func.contains("issuer") ||
                            called_func.contains("origin")
                        } else { false }
                    });
                    
                    // Flag issue if function processes potatoes without proper vault binding validation
                    if has_potato_param && (!has_vault_param || !has_binding_check) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Missing vault-potato binding in '{}'", func_name),
                            description: "Function processes Potato without verifying it belongs to the correct vault, enabling unauthorized redemption".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement vault-potato binding validation. Verify that the Potato was issued by the specified vault before processing. Use cryptographic commitments or issuer tracking.".to_string(),
                            references: vec![
                                "https://docs.sui.io/concepts/programming-model/objects".to_string(),
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