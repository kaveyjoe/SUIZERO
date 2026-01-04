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

// ========== SUI-034: Cross-Function Invariant Detector ==========
pub struct CrossFunctionInvariantDetector;

#[async_trait::async_trait]
impl SecurityDetector for CrossFunctionInvariantDetector {
    fn id(&self) -> &'static str { "SUI-034" }
    fn name(&self) -> &'static str { "Cross-Function Invariant Violation" }
    fn description(&self) -> &'static str { "Detects inconsistencies between coupled state-mutating functions (e.g., deposit vs withdraw)" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // 1. Map function names to their definitions and field writes
        let mut func_writes: HashMap<String, (usize, HashSet<usize>)> = HashMap::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let name = get_func_name(func_def, ctx).to_string();
            
            if let Some(code) = &func_def.code {
                let mut writes = HashSet::new();
                for instr in &code.code {
                    match instr {
                        Bytecode::MutBorrowField(f) => {
                            writes.insert(f.0 as usize);
                        }
                        Bytecode::MutBorrowFieldGeneric(f) => {
                            writes.insert(f.0 as usize);
                        }
                        _ => {}
                    }
                }
                func_writes.insert(name, (idx, writes));
            }
        }
        
        // 2. Define coupled pairs to check
        let pairs = vec![
            ("deposit", "withdraw"),
            ("stake", "unstake"),
            ("mint", "burn"),
            ("add_liquidity", "remove_liquidity"),
            ("supply", "borrow"),
        ];
        
        // 3. Analyze pairs for asymmetry
        for (f1_name, f2_name) in pairs {
            // Find functions that *contain* these tokens
            let f1_matches: Vec<_> = func_writes.keys().filter(|k| k.to_lowercase().contains(f1_name)).cloned().collect();
            let f2_matches: Vec<_> = func_writes.keys().filter(|k| k.to_lowercase().contains(f2_name)).cloned().collect();
            
            for m1 in &f1_matches {
                for m2 in &f2_matches {
                    if let (Some((idx1, writes1)), Some((idx2, writes2))) = (func_writes.get(m1), func_writes.get(m2)) {
                        // Logic: Opposing functions should generally touch the same state fields
                        // If one touches a superset of the other, identifying 'extra' fields is interesting
                        // Especially if the 'extra' field looks like a fee, protocol treasury, etc.
                        
                        // Check for symmetric difference size
                        let diff: Vec<_> = writes1.symmetric_difference(writes2).collect();
                        
                        if !diff.is_empty() {
                            // Heuristic: If meaningful difference in state access
                            // We need to verify if this is reasonable or suspicious
                            // For now, flag significant mismatches in core logic
                            
                            // Only report if they share at least ONE field (so they are related)
                            if !writes1.is_disjoint(writes2) {
                                // Filter out false positives where one just emits an extra event or unrelated counter
                                // We are looking for "Field A is modified in Withdraw but NOT in Deposit"
                                
                                // Let's simplify: Start with simply reporting asymmetry in "Vault" logic
                                if (m1.contains("deposit") && m2.contains("withdraw")) || 
                                   (m1.contains("stake") && m2.contains("unstake")) {
                                       
                                    // If withdraw writes to MORE fields than deposit
                                    if writes2.len() > writes1.len() {
                                         issues.push(SecurityIssue {
                                            id: self.id().to_string(),
                                            severity: Severity::High, // Start with High, Critical needs more proof
                                            confidence: Confidence::Medium,
                                            title: "Asymmetric State Access in Coupled Functions".to_string(),
                                            description: format!(
                                                "Function '{}' modifies {} fields, while coupled function '{}' modifies {} fields. This asymmetry suggests a potential invariant violation, such as hidden fees, accounting desynchronization, or logic gaps.",
                                                m2, writes2.len(), m1, writes1.len()
                                            ),
                                            location: create_loc(ctx, *idx2),
                                            source_code: None,
                                            recommendation: "Ensure state mutations are symmetric. If 'withdraw' applies effects (like fees) that 'deposit' does not, ensure this is intended and mathematically sound.".to_string(),
                                            references: vec!["SUI-034: Cross-Function Invariant".to_string()],
                                            metadata: HashMap::new(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        issues
    }
}
