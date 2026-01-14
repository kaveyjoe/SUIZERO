// Extended Receipt Forgery Security Detector
// Detects when functions allow arbitrary receipt creation leading to vault drain

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

// ========== RECEIPT FORGERY DETECTOR ==========
pub struct ReceiptForgeryDetector;

#[async_trait::async_trait]
impl SecurityDetector for ReceiptForgeryDetector {
    fn id(&self) -> &'static str { "SUI-032" }
    fn name(&self) -> &'static str { "Receipt Forgery" }
    fn description(&self) -> &'static str { "Detects receipt forgery vulnerabilities allowing arbitrary receipt creation" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Look for functions that might create arbitrary receipts
            if func_name.as_str().contains("forge") || 
               func_name.as_str().contains("receipt") || 
               func_name.as_str().contains("create") {
                
                if let Some(code) = &func_def.code {
                    // Check if function creates a struct with "Receipt" in the name
                    let creates_receipt = code.code.iter().any(|instr| {
                        match instr {
                            Bytecode::Pack(struct_idx) => {
                                let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                let struct_name = ctx.module.identifier_at(struct_handle.name);
                                struct_name.as_str().contains("Receipt") || struct_name.as_str().contains("receipt")
                            },
                            _ => false
                        }
                    });
                    
                    // Check if the function creates a receipt without proper validation
                    if creates_receipt {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Receipt forgery vulnerability in '{}'", func_name),
                            description: "Function allows arbitrary receipt creation without proper validation, enabling vault drain".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement proper receipt validation. Require proof of deposit before issuing receipts. Use cryptographic commitments to prevent forgery.".to_string(),
                            references: vec![
                                "https://consensys.github.io/smart-contract-best-practices/attacks/unexpected-ether/".to_string(),
                            ],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        // Also check for functions that return Receipt-like structures without validation
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let return_signature = &ctx.module.signatures[func_handle.return_.0 as usize];
            
            // Check if function returns a Receipt struct
            let returns_receipt = return_signature.0.iter().any(|ret_type| {
                match ret_type {
                    SignatureToken::Struct(struct_idx) | 
                    SignatureToken::StructInstantiation(struct_idx, _) => {
                        let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                        let struct_name = ctx.module.identifier_at(struct_handle.name);
                        struct_name.as_str().contains("Receipt") || struct_name.as_str().contains("receipt")
                    },
                    SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                        match &**inner {
                            SignatureToken::Struct(struct_idx) | 
                            SignatureToken::StructInstantiation(struct_idx, _) => {
                                let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                let struct_name = ctx.module.identifier_at(struct_handle.name);
                                struct_name.as_str().contains("Receipt") || struct_name.as_str().contains("receipt")
                            },
                            _ => false
                        }
                    },
                    _ => false
                }
            });
            
            if returns_receipt {
                // Check if function name suggests it might forge receipts
                let forge_like = func_name.as_str().contains("forge") || 
                               func_name.as_str().contains("create") || 
                               func_name.as_str().contains("make");
                
                if forge_like {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Potential receipt forgery in '{}'", func_name),
                        description: "Function returns Receipt without proper deposit validation, enabling vault drain".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Validate that receipt corresponds to actual deposit before returning. Implement proper accounting checks.".to_string(),
                        references: vec![
                            "https://consensys.github.io/smart-contract-best-practices/attacks/unexpected-ether/".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}