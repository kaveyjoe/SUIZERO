use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition},
};
use std::collections::{HashMap, HashSet};

// Helper: Get function name
fn get_func_name<'a>(func_def: &'a FunctionDefinition, ctx: &'a DetectionContext) -> &'a str {
    let handle = &ctx.module.function_handles[func_def.function.0 as usize];
    ctx.module.identifier_at(handle.name).as_str()
}

// Helper: Create location
fn create_loc(ctx: &DetectionContext, func_idx: usize) -> CodeLocation {
    let func_def = &ctx.module.function_defs[func_idx];
    let func_name = get_func_name(func_def, ctx);
    
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: 0,
        byte_offset: 0,
        line: None,
        column: None,
    }
}

// ========== SUI-036: TOCTOU Detector ==========
pub struct TemporalTOCTOUDetector;

#[async_trait::async_trait]
impl SecurityDetector for TemporalTOCTOUDetector {
    fn id(&self) -> &'static str { "SUI-036" }
    fn name(&self) -> &'static str { "Time-of-Check Time-of-Use (TOCTOU)" }
    fn description(&self) -> &'static str { "Detects state that can be mutated between inspection and usage in separate transactions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        let mut readers: HashMap<usize, Vec<String>> = HashMap::new(); // FieldIdx -> Vec<FuncName>
        let mut writers: HashMap<usize, Vec<String>> = HashMap::new(); // FieldIdx -> Vec<FuncName>
        
        // 1. Map all fields to their readers and writers
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_name = get_func_name(func_def, ctx).to_string();
            
            if let Some(code) = &func_def.code {
                for instr in &code.code {
                    match instr {
                        Bytecode::ImmBorrowField(f) => {
                            readers.entry(f.0 as usize).or_insert_with(Vec::new).push(func_name.clone());
                        }
                        Bytecode::ImmBorrowFieldGeneric(f) => {
                            readers.entry(f.0 as usize).or_insert_with(Vec::new).push(func_name.clone());
                        }
                        Bytecode::MutBorrowField(f) => {
                            writers.entry(f.0 as usize).or_insert_with(Vec::new).push(func_name.clone());
                        }
                        Bytecode::MutBorrowFieldGeneric(f) => {
                            writers.entry(f.0 as usize).or_insert_with(Vec::new).push(func_name.clone());
                        }
                         _ => {}
                    }
                }
            }
        }
        
        // 2. Identify risks
        // Risk exists if:
        // - A field is READ in a public function (Inspection)
        // - The SAME field is WRITTEN in an entry function (Mutation)
        // - The SAME field is READ in another entry function (Usage)
        // - AND the Mutation function is seemingly unprotected (heuristic: has "_cap" param or no auth)
        
        for (field_idx, read_funcs) in &readers {
            if let Some(write_funcs) = writers.get(field_idx) {
                // Heuristic: Is there a "getter" pattern? e.g. "inspect", "get_price"
                let getters: Vec<_> = read_funcs.iter().filter(|n| n.contains("inspect") || n.contains("get_") || n.contains("preview")).collect();
                
                // Heuristic: Is there a "setter" pattern? e.g. "set_", "update_"
                let setters: Vec<_> = write_funcs.iter().filter(|n| n.contains("set_") || n.contains("update_")).collect();
                
                // Heuristic: Is there a "consumer"? e.g. "withdraw", "swap"
                let consumers: Vec<_> = read_funcs.iter().filter(|n| n.contains("withdraw") || n.contains("swap") || n.contains("exchange")).collect();
                
                if !getters.is_empty() && !setters.is_empty() && !consumers.is_empty() {
                    // We have the Triad: Get -> Set -> Use
                    // This is a classic TOCTOU surface
                    
                    for consumer in consumers {
                        // Find the func_idx for the consumer to report location
                        let consumer_idx = ctx.module.function_defs.iter().position(|f| get_func_name(f, ctx) == consumer).unwrap_or(0);
                        
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            title: "Potential TOCTOU / Front-Running Vulnerability".to_string(),
                            description: format!(
                                "Field #{} is part of a TOCTOU triad.\n1. Inspected by: {:?}\n2. Mutated by: {:?}\n3. consumed by: '{}'.\nUser inspections of state (via '{:?}') can be invalidated by front-running mutations (via '{:?}') before the consuming transaction ('{}') executes.",
                                field_idx, getters, setters, consumer, getters[0], setters[0], consumer
                            ),
                            location: create_loc(ctx, consumer_idx),
                            source_code: None,
                            recommendation: "Ensure critical state parameters (like price) cannot be changed instantly without a delay, or use slippage protection in the consuming function.".to_string(),
                            references: vec!["SUI-036: TOCTOU".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== SUI-038: Shared Object Race Detector ==========
pub struct SharedObjectRaceDetector;

#[async_trait::async_trait]
impl SecurityDetector for SharedObjectRaceDetector {
    fn id(&self) -> &'static str { "SUI-038" }
    fn name(&self) -> &'static str { "Shared Object Race Condition" }
    fn description(&self) -> &'static str { "Detects race conditions impacting shared objects" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
         // Placeholder for more complex race detection
         // For now, looking for multiple public-entry functions mutating same state without "locked" naming
         vec![]
    }
}
