// Event-State Synchronization Detector
// Detects when events are emitted without corresponding state changes

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

// ========== EVENT-STATE SYNCHRONIZATION DETECTOR ==========
pub struct EventStateSyncDetector;

#[async_trait]
impl SecurityDetector for EventStateSyncDetector {
    fn id(&self) -> &'static str { "SEM-007" }
    fn name(&self) -> &'static str { "Event-State Synchronization" }
    fn description(&self) -> &'static str { "Detects when events are emitted without corresponding state changes" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if let Some(code) = &func_def.code {
                // Check for event emission
                let has_event_emit = code.code.iter().any(|instr| {
                    if let Some(called_func) = get_function_name(instr, &ctx.module) {
                        called_func.contains("event::emit") || called_func.contains("emit")
                    } else { false }
                });
                
                // Check for state mutation operations
                let has_state_mutation = code.code.iter().any(|instr| {
                    matches!(
                        instr,
                        Bytecode::MutBorrowGlobal(_) |
                        Bytecode::MutBorrowGlobalGeneric(_) |
                        Bytecode::MoveFrom(_) |
                        Bytecode::MoveFromGeneric(_) |
                        Bytecode::MoveTo(_) |
                        Bytecode::MoveToGeneric(_) |
                        Bytecode::WriteRef
                    )
                });
                
                // Check for value-related operations that should correspond to events
                let has_value_operation = func_name.as_str().to_lowercase().contains("deposit") ||
                                        func_name.as_str().to_lowercase().contains("withdraw") ||
                                        func_name.as_str().to_lowercase().contains("transfer") ||
                                        func_name.as_str().to_lowercase().contains("mint") ||
                                        func_name.as_str().to_lowercase().contains("burn") ||
                                        func_name.as_str().to_lowercase().contains("send");
                
                // If function emits events but doesn't appear to have corresponding state mutations
                if has_event_emit && has_value_operation && !has_state_mutation {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Event-state desync in '{}'", func_name),
                        description: format!("Function '{}' emits events without corresponding state changes", func_name),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Ensure that emitted events accurately reflect actual state changes. Events should correspond to actual value transfers or state modifications.".to_string(),
                        references: vec![
                            "https://docs.sui.io/concepts/programming-model/events".to_string(),
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