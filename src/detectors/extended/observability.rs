use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition},
};
use std::collections::HashMap;

// Helper function to get function name
fn get_func_name<'a>(func_def: &'a FunctionDefinition, ctx: &'a DetectionContext) -> &'a str {
    let handle = &ctx.module.function_handles[func_def.function.0 as usize];
    ctx.module.identifier_at(handle.name).as_str()
}

// Helper function to create location
fn create_loc(ctx: &DetectionContext, func_idx: usize, instr_idx: u16) -> CodeLocation {
    let func_def = &ctx.module.function_defs[func_idx];
    let func_name = get_func_name(func_def, ctx);
    
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

// ========== SUI-037: Event Consistency Detector ==========
pub struct EventConsistencyDetector;

#[async_trait::async_trait]
impl SecurityDetector for EventConsistencyDetector {
    fn id(&self) -> &'static str { "SUI-037" }
    fn name(&self) -> &'static str { "Event-State Inconsistency" }
    fn description(&self) -> &'static str { "Detects events that report values differing from actual state changes or transfers" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Heuristic: Look for fee calculation followed by emit
                // If we see "Sub" (fee deduction) and then "Call(emit)"
                // And the Emit uses a value from BEFORE the Sub
                
                // This requires data flow analysis which is hard on raw bytecode
                // Simplified Heuristic: 
                // Look for functions purely by name/behavior that are known to have fees
                // e.g. "withdraw", "swap"
                // And check if they emit events using variables that are NOT the result of a generic "Sub"
                
                let check_consistency = get_func_name(func_def, ctx).contains("withdraw");
                
                if check_consistency {
                    // Check for "fee" related operations
                    // But without decompilation, we rely on pattern:
                    //   copy locX (original)
                    //   ... calculation ...
                    //   sub (deduction)
                    //   ...
                    //   emit (using locX instead of result)
                    
                    // Let's flag if we see a Sub operation, but the Event uses a Local that was defined/set BEFORE the Sub
                    // This is rough but effective enough for a prototype
                    
                    let mut has_sub = false;
                    let mut emit_idx = 0;
                    let mut has_emit = false;
                    
                    for (i, instr) in code.code.iter().enumerate() {
                        if matches!(instr, Bytecode::Sub) {
                            has_sub = true;
                        }
                        if let Bytecode::Call(_method_idx) = instr {
                            // Check if it's an emit function
                            // ... difficult to check external emit without resolution
                            // Assuming typical `event::emit` usage which is often a generic call
                            // Just flagging "Has Sub" and "Has Call" in a withdraw might be too noisy
                            // But let's assume if it's named "withdraw" and has arithmetic, it likely has fees.
                            has_emit = true; // simplifying
                            emit_idx = i;
                        }
                    }
                    
                    if has_sub && has_emit {
                         issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::Medium, // Medium because high false positive chance
                            confidence: Confidence::Low,
                            title: "Potential Event-State Inconsistency".to_string(),
                            description: "Function contains arithmetic (likely fee deduction) and event emission. Verify that the emitted event reports the FINAL amount (post-fee) rather than the requested amount.".to_string(),
                            location: create_loc(ctx, idx, emit_idx as u16),
                            source_code: None,
                            recommendation: "Ensure event payloads match the actual on-chain effects (e.g., net_amount vs gross_amount).".to_string(),
                            references: vec!["SUI-037: Observability".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}
