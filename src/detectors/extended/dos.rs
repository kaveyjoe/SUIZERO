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
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let mut unbounded_loops = 0;
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::BrTrue(_) | Bytecode::BrFalse(_) | Bytecode::Branch(_)) {
                        let has_counter_check = code.code.iter().skip(i.saturating_sub(5)).take(10).any(|b| {
                            matches!(b, Bytecode::Lt | Bytecode::Le | Bytecode::Gt | Bytecode::Ge)
                        });
                        if !has_counter_check {
                            unbounded_loops += 1;
                        }
                    }
                }
                if unbounded_loops > 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Unbounded loop enables gas DOS in financial function".to_string(),
                        description: format!("Financial function has {} unbounded loops that can cause gas exhaustion", unbounded_loops),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Add iteration limits in financial functions. Implement pagination. Use gas metering.".to_string(),
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
