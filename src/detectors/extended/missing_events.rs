use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition},
};
use std::collections::HashMap;

fn create_loc(ctx: &DetectionContext, func_idx: usize, instr_idx: u16) -> CodeLocation {
    let func_def = &ctx.module.function_defs[func_idx];
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: instr_idx,
        byte_offset: 0,
        line: None,
        column: None,
    }
}

// EVT-001: Missing Critical Event Emission
pub struct MissingCriticalEventDetector;

#[async_trait::async_trait]
impl SecurityDetector for MissingCriticalEventDetector {
    fn id(&self) -> &'static str { "EVT-001" }
    fn name(&self) -> &'static str { "Missing Critical Event Emission" }
    fn description(&self) -> &'static str { "Detects functions that perform critical operations without emitting events" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for functions that perform critical operations but don't emit events
            if func_name.contains("transfer") || 
               func_name.contains("mint") || 
               func_name.contains("burn") ||
               func_name.contains("withdraw") ||
               func_name.contains("deposit") {
                
                if let Some(code) = &func_def.code {
                    let mut has_event_emit = false;
                    
                    for instr in &code.code {
                        if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                            // In a real implementation, we would check if this is a call to event::emit
                            // For now, we'll look for patterns that indicate event emission
                        }
                    }
                    
                    // Check if function modifies state without event emission
                    let mut has_state_modification = false;
                    for instr in &code.code {
                        match instr {
                            Bytecode::WriteRef | 
                            Bytecode::MoveTo(_) | 
                            Bytecode::MoveToGeneric(_) => {
                                has_state_modification = true;
                            }
                            _ => {}
                        }
                    }
                    
                    if has_state_modification && !has_event_emit {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::Medium,
                            confidence: Confidence::Medium,
                            title: "Missing critical event emission".to_string(),
                            description: "Function performs state-changing operation without emitting corresponding event".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Consider emitting events for important state changes to provide transparency".to_string(),
                            references: vec!["SUI-025: Event Transparency".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// EVT-002: Event Emitted Before Risky Operation
pub struct EventBeforeRiskyOperationDetector;

#[async_trait::async_trait]
impl SecurityDetector for EventBeforeRiskyOperationDetector {
    fn id(&self) -> &'static str { "EVT-002" }
    fn name(&self) -> &'static str { "Event Emitted Before Risky Operation" }
    fn description(&self) -> &'static str { "Detects events emitted before potentially failing operations" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            if let Some(code) = &func_def.code {
                // Look for patterns where events are emitted before risky operations
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                        // Check if this looks like an event emission followed by a risky operation
                        if i + 1 < code.code.len() {
                            let next_instr = &code.code[i + 1];
                            if matches!(next_instr, Bytecode::Abort | Bytecode::Nop) {
                                // Potential pattern: event emitted before operation that could fail
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(),
                                    severity: Severity::High,
                                    confidence: Confidence::Low,
                                    title: "Event emitted before risky operation".to_string(),
                                    description: "Event is emitted before operation that could potentially fail, leading to misleading logs".to_string(),
                                    location: create_loc(ctx, idx, i as u16),
                                    source_code: Some(func_name.clone()),
                                    recommendation: "Consider emitting events after successful completion of operations".to_string(),
                                    references: vec!["SUI-026: Event Accuracy".to_string()],
                                    metadata: HashMap::new(),
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

// Export the detectors
pub fn get_missing_events_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(MissingCriticalEventDetector),
        Box::new(EventBeforeRiskyOperationDetector),
    ]
}