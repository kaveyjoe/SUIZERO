// Capability Theater Detector
// Detects when capabilities are present but not properly validated

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

// ========== CAPABILITY THEATER DETECTOR ==========
pub struct CapabilityTheaterDetector;

#[async_trait::async_trait]
impl SecurityDetector for CapabilityTheaterDetector {
    fn id(&self) -> &'static str { "SEM-003" }
    fn name(&self) -> &'static str { "Capability Theater" }
    fn description(&self) -> &'static str { "Detects when capabilities are present but not properly validated" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Find all structs that look like capabilities
        for (struct_idx, struct_def) in ctx.module.struct_defs.iter().enumerate() {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str();
            
            // Check if this struct looks like a capability
            let is_capability_like = struct_name.to_lowercase().contains("cap") ||
                                    struct_name.to_lowercase().contains("admin") ||
                                    struct_name.to_lowercase().contains("owner") ||
                                    struct_name.to_lowercase().contains("auth") ||
                                    struct_name.to_lowercase().contains("permission") ||
                                    struct_name.to_lowercase().contains("authority");
            
            if is_capability_like {
                // Check functions that accept this capability but don't properly use it
                for func_def in &ctx.module.function_defs {
                    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                    let func_name = ctx.module.identifier_at(func_handle.name);
                    
                    // Check if function takes the capability as parameter
                    let takes_capability = {
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
                    
                    if takes_capability {
                        if let Some(code) = &func_def.code {
                            // Check if function mutates shared objects or performs sensitive operations
                            let mutates_shared = code.code.iter().any(|instr| {
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
                            
                            // Check if function reads the capability fields (validates it)
                            let reads_capability = code.code.iter().any(|instr| {
                                if let Some(called_func) = get_function_name(instr, &ctx.module) {
                                    called_func.contains(struct_name) && 
                                    (called_func.contains("read") || 
                                     called_func.contains("field") || 
                                     called_func.contains("id") ||
                                     called_func.contains("check"))
                                } else { false }
                            });
                            
                            // Check for field access operations on the capability
                            let accesses_fields = code.code.iter().any(|instr| {
                                matches!(
                                    instr,
                                    Bytecode::ImmBorrowField(_) |
                                    Bytecode::MutBorrowField(_) |
                                    Bytecode::ImmBorrowFieldGeneric(_) |
                                    Bytecode::MutBorrowFieldGeneric(_)
                                )
                            });
                            
                            // If function mutates shared state but doesn't validate the capability
                            if mutates_shared && !reads_capability && !accesses_fields {
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(),
                                    severity: self.default_severity(),
                                    confidence: Confidence::High,
                                    title: format!("Capability theater in '{}'", func_name),
                                    description: format!("Function '{}' takes {} capability but doesn't validate it before performing sensitive operations", func_name, struct_name),
                                    location: create_location(ctx, func_def, 0),
                                    source_code: Some(format!("{} takes {}", func_name, struct_name)),
                                    recommendation: "Properly validate capability before performing sensitive operations. Check capability fields, IDs, or use the capability in a meaningful way.".to_string(),
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