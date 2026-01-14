// Value Duplication via Split/Merge Detector
// Detects when value can be duplicated through split/merge operations

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

// ========== VALUE DUPLICATION VIA SPLIT/MERGE DETECTOR ==========
pub struct ValueDuplicationDetector;

#[async_trait]
impl SecurityDetector for ValueDuplicationDetector {
    fn id(&self) -> &'static str { "SEM-008" }
    fn name(&self) -> &'static str { "Value Duplication via Split/Merge" }
    fn description(&self) -> &'static str { "Detects when value can be duplicated through split/merge operations" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Look for functions with split/merge-like names
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Check if function name suggests splitting or merging
            let is_split_merge_function = func_name.as_str().to_lowercase().contains("split") ||
                                         func_name.as_str().to_lowercase().contains("merge") ||
                                         func_name.as_str().to_lowercase().contains("divide") ||
                                         func_name.as_str().to_lowercase().contains("combine") ||
                                         func_name.as_str().to_lowercase().contains("multiply");
            
            if is_split_merge_function {
                if let Some(code) = &func_def.code {
                    // Check for arithmetic operations that might duplicate value
                    let has_arithmetic = code.code.iter().any(|instr| {
                        matches!(instr, Bytecode::Add | Bytecode::Sub | Bytecode::Mul | Bytecode::Div)
                    });
                    
                    // Check for multiple packing operations (creating multiple objects)
                    let has_multiple_pack = {
                        let mut pack_count = 0;
                        for instr in &code.code {
                            if matches!(instr, Bytecode::Pack(_) | Bytecode::PackGeneric(_)) {
                                pack_count += 1;
                                if pack_count >= 2 {
                                    break;
                                }
                            }
                        }
                        pack_count >= 2
                    };
                    
                    // Check if function takes value-containing parameters and returns multiple objects
                    let params_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                    let return_sig = &ctx.module.signatures[func_handle.return_.0 as usize];
                    
                    let has_value_params = params_sig.0.iter().any(|param| {
                        // Look for parameters that might contain value (u64, u128 fields)
                        match param {
                            SignatureToken::Struct(struct_idx) | 
                            SignatureToken::StructInstantiation(struct_idx, _) => {
                                // Check if struct contains value-like fields
                                let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                let struct_name = ctx.module.identifier_at(struct_handle.name);
                                struct_name.as_str().to_lowercase().contains("value") ||
                                struct_name.as_str().to_lowercase().contains("amount") ||
                                struct_name.as_str().to_lowercase().contains("balance")
                            },
                            SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                                match &**inner {
                                    SignatureToken::Struct(struct_idx) | 
                                    SignatureToken::StructInstantiation(struct_idx, _) => {
                                        let struct_handle = &ctx.module.struct_handles[struct_idx.0 as usize];
                                        let struct_name = ctx.module.identifier_at(struct_handle.name);
                                        struct_name.as_str().to_lowercase().contains("value") ||
                                        struct_name.as_str().to_lowercase().contains("amount") ||
                                        struct_name.as_str().to_lowercase().contains("balance")
                                    },
                                    _ => false
                                }
                            },
                            _ => false
                        }
                    });
                    
                    let has_multiple_returns = return_sig.0.len() > 1 || 
                        return_sig.0.iter().any(|ret| {
                            match ret {
                                SignatureToken::Struct(_) | SignatureToken::StructInstantiation(_, _) => {
                                    // If it returns a struct that could be a value container
                                    true
                                },
                                _ => false
                            }
                        });
                    
                    // Flag potential value duplication if it has arithmetic, multiple pack ops, and value params
                    if has_arithmetic && has_multiple_pack && has_value_params {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Value duplication risk in '{}'", func_name),
                            description: format!("Function '{}' shows patterns that could enable value duplication via split/merge operations", func_name),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement proper value accounting in split/merge operations. Ensure total value is conserved across all operations. Validate that split operations have corresponding merge constraints.".to_string(),
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