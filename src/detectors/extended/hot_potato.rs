// Hot Potato Lifecycle Escape Detector
// Detects when hot-potato resources can escape their intended lifecycle

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition, SignatureToken, AbilitySet, StructDefinition, Ability},
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

// ========== HOT POTATO LIFECYCLE ESCAPE DETECTOR ==========
pub struct HotPotatoLifecycleEscapeDetector;

#[async_trait::async_trait]
impl SecurityDetector for HotPotatoLifecycleEscapeDetector {
    fn id(&self) -> &'static str { "SEM-001" }
    fn name(&self) -> &'static str { "Hot Potato Lifecycle Escape" }
    fn description(&self) -> &'static str { "Detects when hot-potato resources can escape their intended lifecycle" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Find all structs that could be "hot potato" candidates
        // These are structs with key ability but not drop ability
        let hot_potato_candidates: Vec<(usize, String)> = ctx.module.struct_defs
            .iter()
            .enumerate()
            .filter_map(|(idx, struct_def)| {
                let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
                let struct_name = ctx.module.identifier_at(struct_handle.name).to_string();
                
                // Get the abilities for this struct
                let abilities = get_struct_abilities(struct_def, &ctx.module);
                
                // Check if it has key but not drop (making it a potential hot potato)
                if abilities.has_key() && !abilities.has_drop() {
                    Some((idx, struct_name))
                } else {
                    None
                }
            })
            .collect();
        
        // For each candidate, check all functions that might handle it
        for (struct_idx, struct_name) in hot_potato_candidates {
            for func_def in &ctx.module.function_defs {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                
                // Check if function takes the hot potato struct as parameter
                let takes_hot_potato = {
                    let params_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                    params_sig.0.iter().any(|param| {
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
                
                if takes_hot_potato {
                    if let Some(code) = &func_def.code {
                        // Check if function calls transfer::transfer on the hot potato
                        let transfers_hot_potato = code.code.iter().any(|instr| {
                            if let Some(called_func) = get_function_name(instr, &ctx.module) {
                                called_func.contains("transfer::transfer") && 
                                // Check if the transfer is for our hot potato type
                                // This is a heuristic since we can't easily check exact types in bytecode
                                (func_name.as_str().contains(&struct_name.replace("Potato", "").to_lowercase()) ||
                                 func_name.as_str().contains("send") || func_name.as_str().contains("transfer"))
                            } else { false }
                        });
                        
                        // Check if function returns the hot potato
                        let returns_hot_potato = {
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
                        
                        // If function takes the hot potato but doesn't properly consume it
                        if transfers_hot_potato || returns_hot_potato {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: format!("Hot potato lifecycle escape in '{}'", func_name),
                                description: format!("Function '{}' handles {} resource but allows it to escape intended lifecycle", 
                                                   func_name, struct_name),
                                location: create_location(ctx, func_def, 0),
                                source_code: Some(format!("{} takes {}", func_name, struct_name)),
                                recommendation: "Ensure hot potato resources are consumed exactly once and cannot be duplicated or stored illegally. Implement proper lifecycle constraints.".to_string(),
                                references: vec![
                                    "https://docs.sui.io/concepts/programming-model/ownership".to_string(),
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

// Helper function to get struct abilities
fn get_struct_abilities(struct_def: &StructDefinition, module: &move_binary_format::CompiledModule) -> AbilitySet {
    let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
    struct_handle.abilities
}

// Helper function to get function name from bytecode
fn get_function_name(instr: &Bytecode, module: &move_binary_format::CompiledModule) -> Option<String> {
    crate::utils::get_function_name(instr, module).map(|s| s.to_string())
}