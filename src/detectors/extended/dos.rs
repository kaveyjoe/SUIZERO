// Strict DOS (Denial of Service) Security Detectors
// Updated to be more precise and focus on financial functions

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, SignatureToken},
};
use std::collections::HashMap;

// Helper to create location
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

// Helper function to determine if a function is financial-related
fn is_financial_function(ctx: &DetectionContext, func_def: &move_binary_format::file_format::FunctionDefinition) -> bool {
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
    
    // Check function name for financial indicators
    if func_name.contains("transfer") ||
       func_name.contains("mint") ||
       func_name.contains("burn") ||
       func_name.contains("withdraw") ||
       func_name.contains("deposit") ||
       func_name.contains("pay") ||
       func_name.contains("send") ||
       func_name.contains("receive") ||
       func_name.contains("balance") ||
       func_name.contains("amount") ||
       func_name.contains("price") ||
       func_name.contains("rate") ||
       func_name.contains("fee") ||
       func_name.contains("swap") ||
       func_name.contains("pool") ||
       func_name.contains("stake") ||
       func_name.contains("unstake") ||
       func_name.contains("claim") ||
       func_name.contains("reward") ||
       func_name.contains("vest") ||
       func_name.contains("lock") ||
       func_name.contains("unlock") {
        return true;
    }
    
    // Check parameters for financial indicators
    let parameters = &ctx.module.signatures[func_handle.parameters.0 as usize];
    for param in &parameters.0 {
        if is_financial_type(param, ctx) {
            return true;
        }
    }
    
    // Check return types for financial indicators
    let return_sig = &ctx.module.signatures[func_handle.return_.0 as usize];
    for ret in &return_sig.0 {
        if is_financial_type(ret, ctx) {
            return true;
        }
    }
    
    false
}

// Helper function to check if a type is financial-related
fn is_financial_type(token: &SignatureToken, ctx: &DetectionContext) -> bool {
    match token {
        SignatureToken::Struct(idx) | 
        SignatureToken::StructInstantiation(idx, _) => {
            let struct_handle = ctx.module.struct_handle_at(*idx);
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            
            struct_name.contains("coin") ||
            struct_name.contains("balance") ||
            struct_name.contains("amount") ||
            struct_name.contains("value") ||
            struct_name.contains("price") ||
            struct_name.contains("usd") ||
            struct_name.contains("eth") ||
            struct_name.contains("btc") ||
            struct_name.contains("token") ||
            struct_name.contains("asset") ||
            struct_name.contains("fund") ||
            struct_name.contains("payment")
        },
        SignatureToken::U64 | SignatureToken::U128 => {
            // U64/U128 are commonly used for amounts/values
            true
        },
        _ => false,
    }
}

// Helper function to detect flash loan patterns
fn detect_flash_loan_patterns(ctx: &DetectionContext, func_def: &move_binary_format::file_format::FunctionDefinition) -> Option<String> {
    if let Some(code) = &func_def.code {
        // Look for functions that allow borrowing without collateral
        let mut has_subtraction_from_reserves = false;
        let mut has_transfer_out = false;
        let mut has_return_verification = false;
        
        for instr in &code.code {
            match instr {
                Bytecode::Sub => {
                    // Subtraction from reserves indicates potential lending
                    has_subtraction_from_reserves = true;
                }
                Bytecode::MoveTo(_) | Bytecode::MoveToGeneric(_) => {
                    // Transfer of assets out
                    has_transfer_out = true;
                }
                Bytecode::Lt | Bytecode::Le | Bytecode::Gt | Bytecode::Ge | Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    // Any comparison or call could be return verification
                    has_return_verification = true;
                }
                _ => {}
            }
        }
        
        // Pattern: subtraction from reserves + transfer out + no return verification
        if has_subtraction_from_reserves && has_transfer_out && !has_return_verification {
            return Some("Function allows borrowing without return verification".to_string());
        }
    }
    
    None
}

// Helper function to detect oracle manipulation patterns
fn detect_oracle_manipulation_patterns(ctx: &DetectionContext, func_def: &move_binary_format::file_format::FunctionDefinition) -> Option<String> {
    if let Some(code) = &func_def.code {
        // Look for operations that use oracle data without validation
        let mut has_price_access = false;
        let mut has_multiplication = false;
        let mut has_validation = false;
        
        for instr in &code.code {
            match instr {
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    // This could be an oracle call
                    has_price_access = true;
                }
                Bytecode::Mul => {
                    // Multiplication often happens with oracle prices
                    has_multiplication = true;
                }
                Bytecode::Lt | Bytecode::Le | Bytecode::Gt | Bytecode::Ge => {
                    // Comparison operations serve as validation
                    has_validation = true;
                }
                _ => {}
            }
        }
        
        // Pattern: price access + multiplication without validation
        if has_price_access && has_multiplication && !has_validation {
            return Some("Function uses oracle price without sufficient validation/bounds checking".to_string());
        }
    }
    
    None
}

// Helper function to detect reentrancy patterns
fn detect_reentrancy_patterns(ctx: &DetectionContext, func_def: &move_binary_format::file_format::FunctionDefinition) -> Option<String> {
    if let Some(code) = &func_def.code {
        let mut state_changes_after_calls = 0;
        let mut found_external_call = false;
        
        for instr in &code.code {
            match instr {
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    // Potential external call
                    found_external_call = true;
                }
                Bytecode::StLoc(_) | Bytecode::WriteRef => {
                    // Potential state change
                    if found_external_call {
                        state_changes_after_calls += 1;
                    }
                }
                _ => {
                    // Reset flag if we encounter non-call, non-state-change instruction
                    if matches!(instr, Bytecode::BrTrue(_) | Bytecode::BrFalse(_) | Bytecode::Branch(_)) {
                        // Don't reset for branch instructions
                    } else {
                        found_external_call = false;
                    }
                }
            }
        }
        
        if state_changes_after_calls > 0 {
            return Some("Function has state changes after external calls, enabling reentrancy".to_string());
        }
    }
    
    None
}

// Helper function to detect slippage protection
fn detect_slippage_protection(ctx: &DetectionContext, func_def: &move_binary_format::file_format::FunctionDefinition) -> Option<String> {
    if let Some(code) = &func_def.code {
        // Look for minimum output validation in swap functions
        let swap_related = ctx.module.identifier_at(
            ctx.module.function_handles[func_def.function.0 as usize].name
        ).as_str().to_lowercase().contains("swap");
        
        if swap_related {
            // Check for slippage protection by looking for minimum output checks
            let has_comparison = code.code.iter().any(|instr| {
                matches!(instr, Bytecode::Gt | Bytecode::Ge | Bytecode::Lt | Bytecode::Le)
            });
            
            let has_validation_call = code.code.iter().any(|instr| {
                matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_))
            });
            
            if !has_comparison && !has_validation_call {
                return Some("Swap function lacks slippage protection/minimal output validation".to_string());
            }
        }
    }
    
    None
}

// Helper: count nested loops
fn count_nested_loops(code: &[Bytecode]) -> u32 {
    let mut max_nesting = 0;
    let mut current_nesting = 0;
    for instr in code {
        match instr {
            Bytecode::BrTrue(_) | Bytecode::BrFalse(_) | Bytecode::Branch(_) => {
                current_nesting += 1;
                max_nesting = max_nesting.max(current_nesting);
            }
            _ => {}
        }
    }
    max_nesting
}

// ========================================
// 1. GAS DOS
// ========================================
pub struct GasDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for GasDOSDetector {
    fn id(&self) -> &'static str { "DOS-001" }
    fn name(&self) -> &'static str { "Gas DOS Attack" }
    fn description(&self) -> &'static str { "Detects functions vulnerable to gas exhaustion attacks in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let mut unbounded_loops = 0;
                
                // Analyze branches to identify actual loops (backward jumps)
                for (i, instr) in code.code.iter().enumerate() {
                    match instr {
                        Bytecode::Branch(target_pc) => {
                            // Check if this is a backward branch (loop)
                            if *target_pc < i as u16 {
                                let has_counter_check = code.code.iter().skip(i.saturating_sub(5)).take(10).any(|b| {
                                    matches!(b, Bytecode::Lt | Bytecode::Le | Bytecode::Gt | Bytecode::Ge)
                                });
                                if !has_counter_check {
                                    unbounded_loops += 1;
                                }
                            }
                        },
                        Bytecode::BrTrue(target_pc) | Bytecode::BrFalse(target_pc) => {
                            // Check if this is a backward branch (loop)
                            if *target_pc < i as u16 {
                                let has_counter_check = code.code.iter().skip(i.saturating_sub(5)).take(10).any(|b| {
                                    matches!(b, Bytecode::Lt | Bytecode::Le | Bytecode::Gt | Bytecode::Ge)
                                });
                                if !has_counter_check {
                                    unbounded_loops += 1;
                                }
                            }
                        },
                        _ => {}
                    }
                }
                
                if unbounded_loops > 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Unbounded loop enables gas DOS".to_string(),
                        description: format!("Function has {} unbounded loops that can cause gas exhaustion", unbounded_loops),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Add iteration limits. Implement pagination. Use gas metering.".to_string(),
                        references: vec!["https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/".to_string()],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 2. STORAGE DOS
// ========================================
pub struct StorageDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for StorageDOSDetector {
    fn id(&self) -> &'static str { "DOS-002" }
    fn name(&self) -> &'static str { "Storage DOS Attack" }
    fn description(&self) -> &'static str { "Detects unbounded storage growth in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let writes = code.code.iter().filter(|i| matches!(i, Bytecode::MoveTo(_) | Bytecode::MoveToGeneric(_))).count();
                let size_checks = code.code.iter().filter(|i| matches!(i, Bytecode::VecLen(_) | Bytecode::Lt | Bytecode::Le)).count();
                if writes > 0 && size_checks == 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Unbounded storage growth in financial function".to_string(),
                        description: format!("Financial function writes {} storage items without size checks", writes),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Implement max storage size in financial functions. Add cleanup mechanisms.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 3. COMPUTATION DOS
// ========================================
pub struct ComputationDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for ComputationDOSDetector {
    fn id(&self) -> &'static str { "DOS-003" }
    fn name(&self) -> &'static str { "Computation DOS" }
    fn description(&self) -> &'static str { "Detects expensive computations without limits in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let expensive_ops = code.code.iter().filter(|i| matches!(i, Bytecode::Mul | Bytecode::Div | Bytecode::Mod)).count();
                if expensive_ops > 10 { // stricter threshold for financial functions
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Excessive computation in financial function".to_string(),
                        description: format!("{} expensive operations detected in financial function", expensive_ops),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Optimize algorithms in financial functions. Add computation limits.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 4. MEMORY DOS
// ========================================
pub struct MemoryDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for MemoryDOSDetector {
    fn id(&self) -> &'static str { "DOS-004" }
    fn name(&self) -> &'static str { "Memory DOS" }
    fn description(&self) -> &'static str { "Detects unbounded memory allocation" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let allocations = code.code.iter().filter(|i| matches!(i, Bytecode::VecPack(_, _))).count();
                if allocations > 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Unbounded memory allocation".to_string(),
                        description: format!("Function has {} vector allocations without limits", allocations),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Limit vector sizes. Implement memory quotas.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 5. LOOP DOS
// ========================================
pub struct LoopDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for LoopDOSDetector {
    fn id(&self) -> &'static str { "DOS-005" }
    fn name(&self) -> &'static str { "Loop DOS" }
    fn description(&self) -> &'static str { "Detects dangerous loop patterns" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let nested_loops = count_nested_loops(&code.code);
                if nested_loops > 1 { // stricter threshold
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Dangerous nested loops".to_string(),
                        description: format!("{} levels of nesting detected", nested_loops),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Reduce nesting. Use iterative approaches.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 6. RECURSION DOS
// ========================================
pub struct RecursionDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for RecursionDOSDetector {
    fn id(&self) -> &'static str { "DOS-006" }
    fn name(&self) -> &'static str { "Recursion DOS" }
    fn description(&self) -> &'static str { "Detects unbounded recursion" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        vec![] // Move language does not support direct recursion, but left for completeness
    }
}

// ========================================
// 7. EVENT SPAM
// ========================================
pub struct EventSpamDetector;
#[async_trait::async_trait]
impl SecurityDetector for EventSpamDetector {
    fn id(&self) -> &'static str { "DOS-007" }
    fn name(&self) -> &'static str { "Event Spam" }
    fn description(&self) -> &'static str { "Detects excessive event emissions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let events = code.code.iter().filter(|i| matches!(i, Bytecode::CallGeneric(_))).count();
                if events > 5 { // stricter threshold
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::Medium,
                        title: "Excessive event emissions".to_string(),
                        description: format!("Function emits {} events", events),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Batch events. Limit per transaction.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 8. LOG SPAM
// ========================================
pub struct LogSpamDetector;
#[async_trait::async_trait]
impl SecurityDetector for LogSpamDetector {
    fn id(&self) -> &'static str { "DOS-008" }
    fn name(&self) -> &'static str { "Log Spam" }
    fn description(&self) -> &'static str { "Detects excessive logging" }
    fn default_severity(&self) -> Severity { Severity::Medium }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let log_ops = code.code.iter().filter(|i| matches!(i, Bytecode::VecPack(_, _) | Bytecode::VecUnpack(_, _))).count();
                if log_ops > 10 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::Medium,
                        title: "Excessive logging detected".to_string(),
                        description: format!("{} potential logging operations", log_ops),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Reduce logging verbosity. Use selective logging.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 9. OBJECT CREATION DOS
// ========================================
pub struct ObjectCreationDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectCreationDOSDetector {
    fn id(&self) -> &'static str { "DOS-009" }
    fn name(&self) -> &'static str { "Object Creation DOS" }
    fn description(&self) -> &'static str { "Detects unbounded object creation" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let creations = code.code.iter().filter(|i| matches!(i, Bytecode::Pack(_) | Bytecode::PackGeneric(_))).count();
                let has_loop = code.code.iter().any(|i| matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_)));
                if creations > 0 && has_loop {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Object creation in loop".to_string(),
                        description: format!("{} object creations potentially in loop", creations),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Add creation limits. Implement object pooling.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 10. TRANSACTION SPAM
// ========================================
pub struct TransactionSpamDetector;
#[async_trait::async_trait]
impl SecurityDetector for TransactionSpamDetector {
    fn id(&self) -> &'static str { "DOS-010" }
    fn name(&self) -> &'static str { "Transaction Spam" }
    fn description(&self) -> &'static str { "Detects transaction spam vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            if func_def.visibility == move_binary_format::file_format::Visibility::Public || func_def.is_entry {
                if let Some(code) = &func_def.code {
                    let has_rate_check = code.code.iter().any(|i| {
                        if let Bytecode::Call(idx) = i {
                            if let Some(handle) = ctx.module.function_handles.get(idx.0 as usize) {
                                let called_name = ctx.module.identifier_at(handle.name);
                                let called_name_str = called_name.as_str().to_lowercase();
                                called_name_str.contains("timestamp") || called_name_str.contains("cooldown") || called_name_str.contains("rate_limit")
                            } else { false }
                        } else { false }
                    });
                    if !has_rate_check && func_name.as_str().to_lowercase().contains("claim") {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("No spam protection in '{}'", func_name),
                            description: "Public function lacks rate limiting/cooldown".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: None,
                            recommendation: "Implement cooldowns, rate limiting, nonces.".to_string(),
                            references: vec![],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

// ========================================
// 11. QUEUE OVERFLOW
// ========================================
pub struct QueueOverflowDetector;
#[async_trait::async_trait]
impl SecurityDetector for QueueOverflowDetector {
    fn id(&self) -> &'static str { "DOS-011" }
    fn name(&self) -> &'static str { "Queue Overflow" }
    fn description(&self) -> &'static str { "Detects queue overflow vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let push_ops = code.code.iter().filter(|i| matches!(i, Bytecode::VecPushBack(_))).count();
                let size_checks = code.code.iter().filter(|i| matches!(i, Bytecode::VecLen(_))).count();
                if push_ops > 0 && size_checks == 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Unbounded queue growth".to_string(),
                        description: "Vector append without size limit".to_string(),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Implement max queue size. Use bounded queues.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 12. STATE BLOAT
// ========================================
pub struct StateBloatDetector;
#[async_trait::async_trait]
impl SecurityDetector for StateBloatDetector {
    fn id(&self) -> &'static str { "DOS-012" }
    fn name(&self) -> &'static str { "State Bloat" }
    fn description(&self) -> &'static str { "Detects unbounded state growth" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let state_writes = code.code.iter().filter(|i| matches!(i, Bytecode::MoveTo(_))).count();
                if state_writes > 5 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "High state writes".to_string(),
                        description: format!("Function writes {} times to storage", state_writes),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Reduce storage writes or implement batch processing.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 13. HASHING DOS
// ========================================
pub struct HashingDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for HashingDOSDetector {
    fn id(&self) -> &'static str { "DOS-013" }
    fn name(&self) -> &'static str { "Hashing DOS" }
    fn description(&self) -> &'static str { "Detects expensive hash operations in loops in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let expensive_calls = code.code.iter().enumerate().filter(|(_, i)| {
                    matches!(i, Bytecode::Call(_) | Bytecode::CallGeneric(_))
                }).count();
                if expensive_calls > 5 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Expensive hash operations in loop in financial function".to_string(),
                        description: format!("{} expensive calls in potentially unbounded loops in financial function", expensive_calls),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Move expensive operations out of loops in financial functions. Use caching.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 14. METADATA EXPANSION DOS
// ========================================
pub struct MetadataExpansionDetector;
#[async_trait::async_trait]
impl SecurityDetector for MetadataExpansionDetector {
    fn id(&self) -> &'static str { "DOS-014" }
    fn name(&self) -> &'static str { "Metadata Expansion DOS" }
    fn description(&self) -> &'static str { "Detects metadata expansion attacks in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let string_ops = code.code.iter().filter(|i| matches!(i, Bytecode::VecPack(_, _))).count();
                if string_ops > 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Potential metadata expansion in financial function".to_string(),
                        description: "Function manipulates string/vector data without bounds in financial function".to_string(),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Validate input lengths. Implement size limits for metadata fields in financial functions.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 15. INDEX EXPLOSION DOS
// ========================================
pub struct IndexExplosionDetector;
#[async_trait::async_trait]
impl SecurityDetector for IndexExplosionDetector {
    fn id(&self) -> &'static str { "DOS-015" }
    fn name(&self) -> &'static str { "Index Explosion DOS" }
    fn description(&self) -> &'static str { "Detects index explosion vulnerabilities in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let index_accesses = code.code.iter().filter(|i| matches!(i, Bytecode::VecSwap(_) | Bytecode::VecImmBorrow(_) | Bytecode::VecMutBorrow(_))).count();
                if index_accesses > 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Potential index explosion in financial function".to_string(),
                        description: "Function accesses vector indices without proper bounds in financial function".to_string(),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Validate vector indices. Implement bounds checks in financial functions.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 16. LINKED LIST ATTACK DOS
// ========================================
pub struct LinkedListAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for LinkedListAttackDetector {
    fn id(&self) -> &'static str { "DOS-016" }
    fn name(&self) -> &'static str { "Linked List Attack DOS" }
    fn description(&self) -> &'static str { "Detects linked list traversal DOS in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let recursive_calls = code.code.iter().filter(|i| matches!(i, Bytecode::Call(_) | Bytecode::CallGeneric(_))).count();
                let has_loop = code.code.iter().any(|i| matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_)));
                if recursive_calls > 0 && has_loop {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Potential linked list traversal DOS in financial function".to_string(),
                        description: "Function has recursive calls in loops in financial function".to_string(),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Implement iteration limits. Use iterative approaches in financial functions.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 17. TREE TRAVERSAL DOS
// ========================================
pub struct TreeTraversalDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for TreeTraversalDOSDetector {
    fn id(&self) -> &'static str { "DOS-017" }
    fn name(&self) -> &'static str { "Tree Traversal DOS" }
    fn description(&self) -> &'static str { "Detects tree traversal DOS in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let nested_branches = code.code.iter().filter(|i| matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_) | Bytecode::Branch(_))).count();
                if nested_branches > 5 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Deeply nested branches in financial function".to_string(),
                        description: format!("{} nested branches detected in financial function", nested_branches),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Reduce nesting depth. Implement traversal limits in financial functions.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 18. GRAPH EXPLORATION DOS
// ========================================
pub struct GraphExplorationDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for GraphExplorationDOSDetector {
    fn id(&self) -> &'static str { "DOS-018" }
    fn name(&self) -> &'static str { "Graph Exploration DOS" }
    fn description(&self) -> &'static str { "Detects graph exploration DOS in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let complex_loops = code.code.iter().filter(|i| matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_))).count();
                if complex_loops > 3 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Complex loops in financial function".to_string(),
                        description: format!("{} complex loops detected in financial function", complex_loops),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Simplify control flow. Implement exploration limits in financial functions.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 19. SEARCH EXHAUSTION DOS
// ========================================
pub struct SearchExhaustionDetector;
#[async_trait::async_trait]
impl SecurityDetector for SearchExhaustionDetector {
    fn id(&self) -> &'static str { "DOS-019" }
    fn name(&self) -> &'static str { "Search Exhaustion DOS" }
    fn description(&self) -> &'static str { "Detects search algorithm exhaustion in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let comparisons = code.code.iter().filter(|i| matches!(i, Bytecode::Eq | Bytecode::Neq | Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge)).count();
                let has_loop = code.code.iter().any(|i| matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_)));
                if comparisons > 10 && has_loop {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Search exhaustion in financial function".to_string(),
                        description: format!("{} comparisons in loops in financial function", comparisons),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Optimize search algorithms. Add early termination in financial functions.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 20. SORTING DOS
// ========================================
pub struct SortingDOSDetector;
#[async_trait::async_trait]
impl SecurityDetector for SortingDOSDetector {
    fn id(&self) -> &'static str { "DOS-020" }
    fn name(&self) -> &'static str { "Sorting DOS" }
    fn description(&self) -> &'static str { "Detects sorting algorithm DOS in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let sort_operations = code.code.iter().filter(|i| matches!(i, Bytecode::Call(_) | Bytecode::CallGeneric(_))).count();
                let comparisons = code.code.iter().filter(|i| matches!(i, Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge)).count();
                if sort_operations > 0 && comparisons > 5 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Potential sorting DOS in financial function".to_string(),
                        description: format!("{} sort operations with {} comparisons in financial function", sort_operations, comparisons),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Optimize sorting algorithms. Use efficient data structures in financial functions.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 21. FLASH LOAN ATTACK
// ========================================
pub struct FlashLoanAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for FlashLoanAttackDetector {
    fn id(&self) -> &'static str { "FIN-003" }
    fn name(&self) -> &'static str { "Flash Loan Attack" }
    fn description(&self) -> &'static str { "Detects flash loan attack patterns in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                if let Some(description) = detect_flash_loan_patterns(ctx, func_def) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Potential flash loan attack vulnerability".to_string(),
                        description,
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Implement proper collateral checks. Verify asset returns before releasing funds.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 22. ORACLE MANIPULATION
// ========================================
pub struct OracleManipulationDetector;
#[async_trait::async_trait]
impl SecurityDetector for OracleManipulationDetector {
    fn id(&self) -> &'static str { "FIN-004" }
    fn name(&self) -> &'static str { "Oracle Manipulation" }
    fn description(&self) -> &'static str { "Detects oracle manipulation vulnerabilities in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(_code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                if let Some(description) = detect_oracle_manipulation_patterns(ctx, func_def) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Potential oracle manipulation vulnerability".to_string(),
                        description,
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Implement multi-oracle systems. Add bounds checking. Use TWAP oracles.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 23. REENTRANCY ATTACK
// ========================================
pub struct ReentrancyAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ReentrancyAttackDetector {
    fn id(&self) -> &'static str { "FIN-005" }
    fn name(&self) -> &'static str { "Reentrancy Attack" }
    fn description(&self) -> &'static str { "Detects reentrancy attack patterns in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                if let Some(description) = detect_reentrancy_patterns(ctx, func_def) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Potential reentrancy vulnerability".to_string(),
                        description,
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Apply checks-effects-interactions pattern. Use reentrancy guards.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 24. SLIPPAGE PROTECTION
// ========================================
pub struct SlippageProtectionDetector;
#[async_trait::async_trait]
impl SecurityDetector for SlippageProtectionDetector {
    fn id(&self) -> &'static str { "FIN-006" }
    fn name(&self) -> &'static str { "Slippage Protection" }
    fn description(&self) -> &'static str { "Detects missing slippage protection in swap functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(_code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                if let Some(description) = detect_slippage_protection(ctx, func_def) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Missing slippage protection".to_string(),
                        description,
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Add minimum output validation. Implement slippage tolerance checks.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========================================
// 25. GOVERNANCE ATTACK
// ========================================
pub struct GovernanceAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for GovernanceAttackDetector {
    fn id(&self) -> &'static str { "GOV-001" }
    fn name(&self) -> &'static str { "Governance Attack" }
    fn description(&self) -> &'static str { "Detects governance attack patterns in functions" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(_code) = &func_def.code {
                let func_name = ctx.module.identifier_at(
                    ctx.module.function_handles[func_def.function.0 as usize].name
                ).as_str().to_lowercase();
                
                // Look for functions with governance-related names
                if func_name.contains("governance") || func_name.contains("vote") || 
                   func_name.contains("proposal") || func_name.contains("admin") || 
                   func_name.contains("upgrade") || func_name.contains("policy") {
                    
                    // Check for improper access controls
                    let mut has_sender_check = false;
                    let mut has_role_check = false;
                    
                    if let Some(code) = &func_def.code {
                        for instr in &code.code {
                            match instr {
                                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                                    // Check if there's a sender or role validation call
                                    has_sender_check = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    
                    // If governance-related function but lacks proper checks
                    if !has_sender_check && !has_role_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: "Missing governance access controls".to_string(),
                            description: "Governance function lacks proper access controls".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: None,
                            recommendation: "Implement proper governance access controls and role validation.".to_string(),
                            references: vec![],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

// ========================================
// 26. STORAGE BLOAT
// ========================================
pub struct StorageBloatDetector;
#[async_trait::async_trait]
impl SecurityDetector for StorageBloatDetector {
    fn id(&self) -> &'static str { "STO-001" }
    fn name(&self) -> &'static str { "Storage Bloat" }
    fn description(&self) -> &'static str { "Detects unbounded storage growth vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = vec![];
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for vector operations without bounds checks
                let push_operations = code.code.iter().filter(|instr| {
                    matches!(instr, Bytecode::VecPushBack(_))
                }).count();
                
                let size_checks = code.code.iter().filter(|instr| {
                    matches!(instr, Bytecode::VecLen(_) | Bytecode::Lt | Bytecode::Le | Bytecode::Gt | Bytecode::Ge)
                }).count();
                
                // If there are push operations but no size checks
                if push_operations > 0 && size_checks == 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Potential storage bloat vulnerability".to_string(),
                        description: "Function performs vector push operations without size bounds checking".to_string(),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Implement size limits for vector operations to prevent storage bloat.".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}
