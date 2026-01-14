// Extended Sui-Specific Security Detectors
// Updated to be more precise and focus on financial functions

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, Visibility, SignatureToken, StructFieldInformation},
};

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

// ========== 1. SHARED OBJECT CONFLICT ==========
pub struct SharedObjectConflictDetector;

#[async_trait::async_trait]
impl SecurityDetector for SharedObjectConflictDetector {
    fn id(&self) -> &'static str { "SUI-001" }
    fn name(&self) -> &'static str { "Shared Object Conflict" }
    fn description(&self) -> &'static str { "Detects conflicting shared object access patterns in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                // Check for multiple mutable borrows of globals (shared objects)
                let mut_global_borrows = code.code.iter().filter(|i| {
                    matches!(i, Bytecode::MutBorrowGlobal(_) | Bytecode::MutBorrowGlobalGeneric(_))
                }).count();
                
                if mut_global_borrows > 1 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Multiple shared object mutations in financial function".to_string(),
                        description: format!("{} mutable borrows may cause transaction conflicts in financial function", mut_global_borrows),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Minimize shared object mutations in financial functions. Use owned objects when possible. Batch updates.".to_string(),
                        references: vec!["https://docs.sui.io/concepts/object-ownership/shared".to_string()],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// ========== 2. SHARED OBJECT DEADLOCK ==========
pub struct SharedObjectDeadlockDetector;

#[async_trait::async_trait]
impl SecurityDetector for SharedObjectDeadlockDetector {
    fn id(&self) -> &'static str { "SUI-002" }
    fn name(&self) -> &'static str { "Shared Object Deadlock" }
    fn description(&self) -> &'static str { "Detects potential shared object deadlocks in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                // Look for nested shared object access - include both generic and non-generic versions
                let has_nested_globals = code.code.windows(10).any(|window| {
                    let first_global = window.iter().any(|i| {
                        matches!(i, Bytecode::MutBorrowGlobal(_) | Bytecode::MutBorrowGlobalGeneric(_))
                    });
                    let second_global = window.iter().skip(1).any(|i| {
                        matches!(i, Bytecode::MutBorrowGlobal(_) | Bytecode::MutBorrowGlobalGeneric(_))
                    });
                    first_global && second_global
                });
                
                if has_nested_globals {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Potential shared object deadlock in financial function".to_string(),
                        description: "Nested shared object access may cause deadlock in financial function".to_string(),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Access shared objects in consistent order in financial functions. Avoid nested shared object locks.".to_string(),
                        references: vec![],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// ========== 3. SHARED OBJECT STARVATION ==========
pub struct SharedObjectStarvationDetector;

#[async_trait::async_trait]
impl SecurityDetector for SharedObjectStarvationDetector {
    fn id(&self) -> &'static str { "SUI-003" }
    fn name(&self) -> &'static str { "Shared Object Starvation" }
    fn description(&self) -> &'static str { "Detects operations that may starve shared object access in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                // Check for long-running operations on shared objects - include both generic and non-generic versions
                let has_shared = code.code.iter().any(|i| {
                    matches!(i, Bytecode::MutBorrowGlobal(_) | Bytecode::MutBorrowGlobalGeneric(_))
                });
                
                let has_loop = code.code.iter().any(|i| {
                    matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_) | Bytecode::Branch(_))
                });
                
                if has_shared && has_loop {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: "Loop with shared object access in financial function".to_string(),
                        description: "Long-running loop on shared object may starve other transactions in financial function".to_string(),
                        location: create_loc(ctx, idx, 0),
                        source_code: None,
                        recommendation: "Keep shared object operations short in financial functions. Use owned objects for loops.".to_string(),
                        references: vec![],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// ========== 4-20: Remaining Sui-Specific Detectors ==========

pub struct OwnedObjectAbuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for OwnedObjectAbuseDetector {
    fn id(&self) -> &'static str { "SUI-004" }
    fn name(&self) -> &'static str { "Owned Object Abuse" }
    fn description(&self) -> &'static str { "Detects misuse of owned objects in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            // Only check financial functions
            if !is_financial_function(ctx, func_def) {
                continue;
            }
            
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("transfer") {
                if let Some(code) = &func_def.code {
                    let has_owner_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Eq | Bytecode::Neq)
                    });
                    
                    if !has_owner_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: "Transfer without ownership check in financial function".to_string(),
                            description: format!("Function '{}' transfers object without verifying ownership", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Verify object ownership before transfer in financial functions. Check sender matches owner.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct ObjectWrappingAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectWrappingAttackDetector {
    fn id(&self) -> &'static str { "SUI-005" }
    fn name(&self) -> &'static str { "Object Wrapping Attack" }
    fn description(&self) -> &'static str { "Detects unsafe object wrapping in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                // Look for packing operations (object wrapping)
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Pack(_) | Bytecode::PackGeneric(_)) {
                        // Only flag as dangerous if it's a critical struct (e.g. contains 'Cap' or 'Policy')
                        let struct_idx = match instr {
                            Bytecode::Pack(idx) => Some(idx.0),
                            Bytecode::PackGeneric(idx) => ctx.module.struct_instantiations().get(idx.0 as usize).map(|si| si.def.0),
                            _ => None
                        };

                        if let Some(s_idx) = struct_idx {
                            let struct_handle = &ctx.module.struct_handles[ctx.module.struct_defs[s_idx as usize].struct_handle.0 as usize];
                            let name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
                            if !name.contains("cap") && !name.contains("policy") && !name.contains("admin") {
                                continue;
                            }
                        }

                        let has_validation = code.code.iter()
                            .take(i)
                            .rev()
                            .take(15) // Check a bit deeper
                            .any(|b| matches!(b, Bytecode::Abort | Bytecode::BrFalse(_)));
                        
                        if !has_validation {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: "Sensitive object wrapping without validation in financial function".to_string(),
                                description: "Critical object (Cap/Policy) wrapped without checking state in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Validate object state before wrapping in financial functions. Ensure wrapped object is safe.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

pub struct ObjectUnwrappingAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectUnwrappingAttackDetector {
    fn id(&self) -> &'static str { "SUI-006" }
    fn name(&self) -> &'static str { "Object Unwrapping Attack" }
    fn description(&self) -> &'static str { "Detects unsafe object unwrapping in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Unpack(_) | Bytecode::UnpackGeneric(_)) {
                        let has_type_check = code.code.iter()
                            .take(i)
                            .rev()
                            .take(5)
                            .any(|b| matches!(b, Bytecode::BrTrue(_) | Bytecode::BrFalse(_)));
                        
                        if !has_type_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: "Unsafe object unwrapping in financial function".to_string(),
                                description: "Unwrapping without type validation in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Verify object type before unwrapping in financial functions. Add runtime checks.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

pub struct ObjectSplittingAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectSplittingAttackDetector {
    fn id(&self) -> &'static str { "SUI-007" }
    fn name(&self) -> &'static str { "Object Splitting Attack" }
    fn description(&self) -> &'static str { "Detects improper object splitting" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("split") {
                if let Some(code) = &func_def.code {
                    let has_balance_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Ge | Bytecode::Gt)
                    });
                    
                    if !has_balance_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Object split without balance check".to_string(),
                            description: format!("'{}' splits object without validating amounts", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Verify total balance before splitting. Ensure sum equals original.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct ObjectMergingAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectMergingAttackDetector {
    fn id(&self) -> &'static str { "SUI-008" }
    fn name(&self) -> &'static str { "Object Merging Attack" }
    fn description(&self) -> &'static str { "Detects unsafe object merging" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("merge") || func_name.as_str().contains("join") {
                if let Some(code) = &func_def.code {
                    // Check for overflow protection
                    let has_overflow_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Add) 
                    }) && code.code.iter().any(|i| {
                        matches!(i, Bytecode::Lt | Bytecode::Ge)
                    });
                    
                    if !has_overflow_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Object merge without overflow check".to_string(),
                            description: format!("'{}' merges without checking for overflow", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Check for overflow when merging values. Use checked arithmetic.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct ObjectFreezingBypassDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectFreezingBypassDetector {
    fn id(&self) -> &'static str { "SUI-009" }
    fn name(&self) -> &'static str { "Object Freezing Bypass" }
    fn description(&self) -> &'static str { "Detects potential freezing bypasses" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("freeze") {
                if let Some(code) = &func_def.code {
                    // After freeze, there shouldn't be mutable operations
                    let has_mut_after_freeze = code.code.windows(5).any(|window| {
                        window.first().map(|i| matches!(i, Bytecode::FreezeRef)).unwrap_or(false) &&
                        window.iter().skip(1).any(|i| matches!(i, Bytecode::WriteRef))
                    });
                    
                    if has_mut_after_freeze {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: "Mutation after freeze".to_string(),
                            description: "Object modified after being frozen".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Ensure frozen objects cannot be modified.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct ObjectDeletionBypassDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectDeletionBypassDetector {
    fn id(&self) -> &'static str { "SUI-010" }
    fn name(&self) -> &'static str { "Object Deletion Bypass" }
    fn description(&self) -> &'static str { "Detects improper object deletion" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("delete") || func_name.as_str().contains("destroy") {
                if let Some(code) = &func_def.code {
                    let has_unpack = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Unpack(_) | Bytecode::UnpackGeneric(_))
                    });
                    
                    if !has_unpack {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Incomplete object deletion".to_string(),
                            description: format!("'{}' doesn't properly unpack object", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Properly unpack and destroy all object fields.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct TxContextForgeryDetector;
#[async_trait::async_trait]
impl SecurityDetector for TxContextForgeryDetector {
    fn id(&self) -> &'static str { "SUI-011" }
    fn name(&self) -> &'static str { "TxContext Forgery" }
    fn description(&self) -> &'static str { "Detects potential TxContext manipulation" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for TxContext being unpacked/modified
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::MutBorrowField(_)) {
                        // Check if it's followed by WriteRef (modification)
                        if code.code.get(i+1..i+3).map(|s| {
                            s.iter().any(|b| matches!(b, Bytecode::WriteRef))
                        }).unwrap_or(false) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "TxContext field modification".to_string(),
                                description: "Modifying context fields may bypass security checks".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Never modify TxContext. Treat it as read-only.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

pub struct EphemeralObjectLeakDetector;
#[async_trait::async_trait]
impl SecurityDetector for EphemeralObjectLeakDetector {
    fn id(&self) -> &'static str { "SUI-012" }
    fn name(&self) -> &'static str { "Ephemeral Object Leak" }
    fn description(&self) -> &'static str { "Detects ephemeral objects not properly destroyed" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let pack_count = code.code.iter().filter(|i| matches!(i, Bytecode::Pack(_) | Bytecode::PackGeneric(_))).count();
                let unpack_count = code.code.iter().filter(|i| matches!(i, Bytecode::Unpack(_) | Bytecode::UnpackGeneric(_))).count();
                
                if pack_count > unpack_count + 1 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Ephemeral objects not destroyed".to_string(),
                        description: format!("{} packs but only {} unpacks", pack_count, unpack_count),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Ensure all ephemeral objects are properly destroyed.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct DynamicFieldAbuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for DynamicFieldAbuseDetector {
    fn id(&self) -> &'static str { "SUI-013" }
    fn name(&self) -> &'static str { "Dynamic Field Abuse" }
    fn description(&self) -> &'static str { "Detects unsafe dynamic field operations" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("add_field") || func_name.as_str().contains("borrow_field") {
                if let Some(code) = &func_def.code {
                    let has_exists_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Exists(_) | Bytecode::ExistsGeneric(_))
                    });
                    
                    if !has_exists_check && func_name.as_str().contains("borrow") {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Dynamic field access without existence check".to_string(),
                            description: format!("'{}' accesses field without checking existence", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Check field exists before borrowing. Handle missing fields gracefully.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct TableOverflowDetector;
#[async_trait::async_trait]
impl SecurityDetector for TableOverflowDetector {
    fn id(&self) -> &'static str { "SUI-014" }
    fn name(&self) -> &'static str { "Table Overflow" }
    fn description(&self) -> &'static str { "Detects unbounded table growth" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("add") && func_name.as_str().contains("table") {
                if let Some(code) = &func_def.code {
                    let has_size_limit = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Lt | Bytecode::Le)
                    });
                    
                    if !has_size_limit {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Unbounded table growth".to_string(),
                            description: "Table addition without size limits".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Implement maximum table size. Add cleanup mechanisms.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct BagManipulationDetector;
#[async_trait::async_trait]
impl SecurityDetector for BagManipulationDetector {
    fn id(&self) -> &'static str { "SUI-015" }
    fn name(&self) -> &'static str { "Bag Manipulation" }
    fn description(&self) -> &'static str { "Detects unsafe bag operations" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("bag") && func_name.as_str().contains("remove") {
                if let Some(code) = &func_def.code {
                    let has_contains_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_))
                    });
                    
                    if !has_contains_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Bag removal without existence check".to_string(),
                            description: "Removing from bag without checking if key exists".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Check bag contains key before removal.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct VectorOverflowDetector;
#[async_trait::async_trait]
impl SecurityDetector for VectorOverflowDetector {
    fn id(&self) -> &'static str { "SUI-016" }
    fn name(&self) -> &'static str { "Vector Overflow" }
    fn description(&self) -> &'static str { "Detects vector overflow in Sui context for financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::VecPushBack(_)) {
                        let has_limit = code.code.iter()
                            .skip(i.saturating_sub(5))
                            .take(10)
                            .any(|b| matches!(b, Bytecode::VecLen(_) | Bytecode::Lt));
                        
                        if !has_limit {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: "Vector push without capacity check in financial function".to_string(),
                                description: "Pushing to vector without checking size limit in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Check vector length before push in financial functions. Implement maximum size.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

pub struct ObjectReferenceLeakDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectReferenceLeakDetector {
    fn id(&self) -> &'static str { "SUI-017" }
    fn name(&self) -> &'static str { "Object Reference Leak" }
    fn description(&self) -> &'static str { "Detects object references that escape scope" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for global borrows that might leak
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::ImmBorrowGlobal(_) | Bytecode::MutBorrowGlobal(_) | Bytecode::ImmBorrowGlobalGeneric(_) | Bytecode::MutBorrowGlobalGeneric(_)) {
                        // Check if stored in struct
                        let may_leak = code.code.get(i+1..i+4).map(|s| {
                            s.iter().any(|b| matches!(b, Bytecode::Pack(_) | Bytecode::PackGeneric(_)))
                        }).unwrap_or(false);
                        
                        if may_leak {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "Object reference may leak".to_string(),
                                description: "Storing object reference in struct".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Don't store object references. Use object IDs instead.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

pub struct IdCollisionDetector;
#[async_trait::async_trait]
impl SecurityDetector for IdCollisionDetector {
    fn id(&self) -> &'static str { "SUI-018" }
    fn name(&self) -> &'static str { "ID Collision" }
    fn description(&self) -> &'static str { "Detects potential object ID collisions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("new") || func_name.as_str().contains("create") {
                if let Some(code) = &func_def.code {
                    // Check if it calls object::new but has no TxContext validation
                    let calls_object_new = code.code.iter().any(|instr| {
                        if let Some(name) = crate::utils::get_function_name(instr, &ctx.module) {
                            name.as_str() == "object::new" || name.as_str() == "new_uid"
                        } else {
                            false
                        }
                    });
                    
                    if calls_object_new {
                        // Check if it has a TxContext parameter by type, not just count
                        let has_tx_context_param = has_tx_context_parameter(ctx, func_handle);
                        
                        if !has_tx_context_param {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "Object creation without TxContext".to_string(),
                                description: format!("'{}' creates a new UID but lacks TxContext in parameters", func_name),
                                location: create_loc(ctx, idx, 0), source_code: None,
                                recommendation: "Use TxContext to generate unique object IDs.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

pub struct UidReuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for UidReuseDetector {
    fn id(&self) -> &'static str { "SUI-019" }
    fn name(&self) -> &'static str { "UID Reuse" }
    fn description(&self) -> &'static str { "Detects potential UID reuse" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("delete") || func_name.as_str().contains("destroy") {
                if let Some(code) = &func_def.code {
                    // After unpacking, UID should be properly deleted
                    let has_unpack = code.code.iter().any(|i| matches!(i, Bytecode::Unpack(_) | Bytecode::UnpackGeneric(_)));
                    let consumes_all_fields = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::Pop)
                    }).count() > 0;
                    
                    if has_unpack && !consumes_all_fields {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "UID not properly consumed".to_string(),
                            description: "Object destroyed but UID may be reusable".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Ensure UID is consumed after object deletion.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct ObjectMetadataTamperingDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectMetadataTamperingDetector {
    fn id(&self) -> &'static str { "SUI-020" }
    fn name(&self) -> &'static str { "Object Metadata Tampering" }
    fn description(&self) -> &'static str { "Detects potential object metadata tampering" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for field writes that might modify metadata
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::MutBorrowField(_)) {
                        // Check if followed by WriteRef
                        if code.code.get(i+1).map(|n| matches!(n, Bytecode::WriteRef)).unwrap_or(false) {
                            // Verify there's authorization
                            let has_auth = code.code.iter()
                                .take(i)
                                .rev()
                                .take(10)
                                .any(|b| matches!(b, Bytecode::Eq | Bytecode::Abort));
                            
                            if !has_auth {
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                    title: "Field modification without authorization".to_string(),
                                    description: "Modifying object field without checking permissions".to_string(),
                                    location: create_loc(ctx, idx, i as u16), source_code: None,
                                    recommendation: "Verify caller authorization before modifying object fields.".to_string(),
                                    references: vec![], metadata: std::collections::HashMap::new(),
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

// ========== 21. UNRESTRICTED SHARED OBJECT INITIALIZATION ==========
pub struct UnrestrictedSharedObjectInitDetector;

#[async_trait::async_trait]
impl SecurityDetector for UnrestrictedSharedObjectInitDetector {
    fn id(&self) -> &'static str { "SUI-021" }
    fn name(&self) -> &'static str { "Unrestricted Shared Object Initialization" }
    fn description(&self) -> &'static str { "Detects public entry functions that share objects without access control" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if func_def.is_entry && func_def.visibility == Visibility::Public {
                if let Some(code) = &func_def.code {
                    let mut calls_share = false;
                    let mut has_access_control = false;
                    
                    for instr in &code.code {
                        if let Some(name) = crate::utils::get_function_name(instr, &ctx.module) {
                            let name_low = name.as_str().to_lowercase();
                            if name_low.contains("share_object") {
                                calls_share = true;
                            }
                            if name_low.contains("tx_context::sender") || name_low.contains("ctx::sender") {
                                has_access_control = true;
                            }
                        }
                        if matches!(instr, Bytecode::Abort | Bytecode::BrFalse(_) | Bytecode::BrTrue(_)) {
                            has_access_control = true;
                        }
                    }
                    
                    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                    let signature = &ctx.module.signatures[func_handle.parameters.0 as usize];
                    for param_type in &signature.0 {
                        let mut check_type = param_type;
                        while let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = check_type {
                            check_type = inner;
                        }
                        if let SignatureToken::Struct(s_idx) | SignatureToken::StructInstantiation(s_idx, _) = check_type {
                            let s_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                            let s_name = ctx.module.identifier_at(s_handle.name).as_str().to_lowercase();
                            if s_name.contains("cap") || s_name.contains("admin") || s_name.contains("owner") {
                                has_access_control = true;
                            }
                        }
                    }

                    if calls_share && !has_access_control {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: self.name().to_string(),
                            description: "Entry function shares an object without any visible access control or capability check. This may allow anyone to spam shared objects or create unauthorized protocol instances.".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Add 'assert!(tx_context::sender(ctx) == @admin, E_NOT_AUTHORIZED)' or require a Capability object as a parameter.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

// ========== 22. UNPROTECTED SHARED OBJECT MUTATION ==========
pub struct UnprotectedSharedObjectMutationDetector;

#[async_trait::async_trait]
impl SecurityDetector for UnprotectedSharedObjectMutationDetector {
    fn id(&self) -> &'static str { "SUI-022" }
    fn name(&self) -> &'static str { "Unprotected Shared Object Mutation" }
    fn description(&self) -> &'static str { "Detects unprotected mutation of shared objects in entry functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if func_def.is_entry && func_def.visibility == Visibility::Public {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let signature = &ctx.module.signatures[func_handle.parameters.0 as usize];
                
                let mut has_mut_ref_param = false;
                for param in &signature.0 {
                    if let SignatureToken::MutableReference(inner) = param {
                        if matches!(**inner, SignatureToken::Struct(_) | SignatureToken::StructInstantiation(_, _)) {
                            has_mut_ref_param = true;
                            break;
                        }
                    }
                }
                
                if has_mut_ref_param {
                    if let Some(code) = &func_def.code {
                        let mut performs_write = false;
                        let mut has_sender_check = false;
                        
                        for instr in &code.code {
                            if matches!(instr, Bytecode::WriteRef | Bytecode::MutBorrowField(_) | Bytecode::MutBorrowFieldGeneric(_)) {
                                performs_write = true;
                            }
                            if let Some(name) = crate::utils::get_function_name(instr, &ctx.module) {
                                let name_low = name.as_str().to_lowercase();
                                if name_low.contains("tx_context::sender") || name_low.contains("ctx::sender") {
                                    has_sender_check = true;
                                }
                            }
                            if matches!(instr, Bytecode::Abort | Bytecode::BrFalse(_) | Bytecode::BrTrue(_)) {
                                has_sender_check = true;
                            }
                        }
                        
                        // Check if this is a legitimate burn function (which is safe as it requires ownership of the token)
                        let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                        let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
                        
                        // Skip if it's a legitimate burn function that operates on Coin<T>
                        let is_legitimate_burn = func_name.contains("burn") && {
                            let sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                            sig.0.iter().any(|param| {
                                if let SignatureToken::MutableReference(inner) = param {
                                    if let SignatureToken::Struct(s_idx) | SignatureToken::StructInstantiation(s_idx, _) = &**inner {
                                        let s_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                                        let s_name = ctx.module.identifier_at(s_handle.name).as_str().to_lowercase();
                                        s_name.contains("treasurycapwrapper") || s_name.contains("wrapper")
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            }) && sig.0.iter().any(|param| {
                                // Check if there's a Coin<T> parameter that must be owned by the caller
                                if let SignatureToken::Struct(s_idx) | SignatureToken::StructInstantiation(s_idx, _) = param {
                                    let s_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                                    let s_name = ctx.module.identifier_at(s_handle.name).as_str().to_lowercase();
                                    s_name.contains("coin")
                                } else {
                                    false
                                }
                            })
                        };
                        
                        if performs_write && !has_sender_check && !is_legitimate_burn {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: self.name().to_string(),
                                description: "Function takes a mutable reference to a struct and modifies it without verifying the sender. On Sui, shared objects can be passed by mutable reference to any entry function by any user.".to_string(),
                                location: create_loc(ctx, idx, 0), source_code: None,
                                recommendation: "Verify that 'tx_context::sender(ctx)' has permission to mutate the shared object, typically by comparing it to an 'owner' field in the object.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

// ========== 23. MEANINGLESS ASSERTION ==========
pub struct MeaninglessAssertionDetector;

#[async_trait::async_trait]
impl SecurityDetector for MeaninglessAssertionDetector {
    fn id(&self) -> &'static str { "SUI-023" }
    fn name(&self) -> &'static str { "Meaningless Assertion" }
    fn description(&self) -> &'static str { "Detects assertions that are always true (e.g., u64 >= 0)" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for i in 0..code.code.len().saturating_sub(1) {
                    let instr = &code.code[i];
                    let next = &code.code[i+1];
                    
                    if matches!(instr, Bytecode::LdU64(0)) && matches!(next, Bytecode::Ge | Bytecode::Gt) {
                        let is_assert = code.code.iter().skip(i+2).take(10).any(|b| {
                            if let Some(name) = crate::utils::get_function_name(b, &ctx.module) {
                                name.as_str().contains("assert") || name.as_str().contains("require")
                            } else {
                                matches!(b, Bytecode::Abort)
                            }
                        });
                        
                        if is_assert {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: self.name().to_string(),
                                description: "Detected 'assert!(x >= 0)' or similar on an unsigned integer (u64). This check is always true and provides a false sense of security.".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Remove the redundant check or ensure you are checking against a meaningful minimum value (> 0).".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

// ========== 24. FAKE BALANCE ACCOUNTING ==========
pub struct FakeBalanceAccountingDetector;

#[async_trait::async_trait]
impl SecurityDetector for FakeBalanceAccountingDetector {
    fn id(&self) -> &'static str { "SUI-024" }
    fn name(&self) -> &'static str { "Fake Balance Accounting" }
    fn description(&self) -> &'static str { "Detects structs using 'u64' for balance without backing 'Coin' or 'Balance' objects in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        for struct_def in &ctx.module.struct_defs {
            let handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(handle.name).as_str().to_lowercase();
            
            // Check if this is a financial-related struct
            if struct_name.contains("vault") || struct_name.contains("pool") || struct_name.contains("bank") || struct_name.contains("account") {
                let mut has_u64_balance = false;
                let mut has_real_funds = false;
                
                if let StructFieldInformation::Declared(fields) = &struct_def.field_information {
                    for field in fields {
                        let field_name = ctx.module.identifier_at(field.name).as_str().to_lowercase();
                        if field_name.contains("balance") || field_name.contains("amount") {
                            let mut t = &field.signature.0;
                            while let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = t { t = inner; }
                            if matches!(t, SignatureToken::U64 | SignatureToken::U128) {
                                has_u64_balance = true;
                            }
                        }
                        
                        let mut t = &field.signature.0;
                        while let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = t { t = inner; }
                        if let SignatureToken::Struct(s_idx) | SignatureToken::StructInstantiation(s_idx, _) = t {
                            let s_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                            let s_name = ctx.module.identifier_at(s_handle.name).as_str().to_lowercase();
                            if s_name == "coin" || s_name == "balance" {
                                has_real_funds = true;
                            }
                        }
                    }
                }
                
                if has_u64_balance && !has_real_funds {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                        title: self.name().to_string(),
                        description: format!("Struct '{}' tracks a balance using 'u64' but does not hold any 'Coin<T>' or 'Balance<T>' objects. This is a dangerous 'accounting fraud' pattern where the contract's internal ledger is not backed by actual funds.", struct_name),
                        location: create_loc(ctx, 0, 0),
                        source_code: None,
                        recommendation: "Use 'sui::balance::Balance<T>' or 'sui::coin::Coin<T>' to store the actual funds within the struct.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

// ========== 25. PAUSE FLAG ILLUSION ==========
pub struct PauseFlagIllusionDetector;

#[async_trait::async_trait]
impl SecurityDetector for PauseFlagIllusionDetector {
    fn id(&self) -> &'static str { "SUI-025" }
    fn name(&self) -> &'static str { "Pause Flag Illusion" }
    fn description(&self) -> &'static str { "Detects 'paused' flags that are written to but never checked" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        let mut paused_fields = Vec::new();

        // 1. Find all 'paused' fields in structs
        for (s_idx, struct_def) in ctx.module.struct_defs.iter().enumerate() {
            if let StructFieldInformation::Declared(fields) = &struct_def.field_information {
                for (f_idx, field) in fields.iter().enumerate() {
                    let field_name = ctx.module.identifier_at(field.name).as_str().to_lowercase();
                    if field_name.contains("paused") || field_name == "pause" {
                        paused_fields.push((s_idx as u16, f_idx as u16, field_name));
                    }
                }
            }
        }

        if paused_fields.is_empty() { return issues; }

        // 2. Check if these fields are ever read (BrTrue/BrFalse)
        for (s_idx, f_idx, field_name) in paused_fields {
            let mut is_read = false;
            let target_struct_handle = ctx.module.struct_defs[s_idx as usize].struct_handle;

            for func_def in &ctx.module.function_defs {
                if let Some(code) = &func_def.code {
                    for (i, instr) in code.code.iter().enumerate() {
                        let fh_idx = match instr {
                            Bytecode::ImmBorrowField(idx) | Bytecode::MutBorrowField(idx) => Some(*idx),
                            Bytecode::ImmBorrowFieldGeneric(idx) | Bytecode::MutBorrowFieldGeneric(idx) => {
                                let inst = &ctx.module.field_instantiations()[idx.0 as usize];
                                Some(inst.handle)
                            }
                            _ => None,
                        };

                        if let Some(fh) = fh_idx {
                            let field_handle = ctx.module.field_handle_at(fh);
                            if field_handle.owner.0 == target_struct_handle.0 && field_handle.field == f_idx {
                                // Field is borrowed, check if it's read
                                if code.code.get(i+1..i+10).map(|s| {
                                    s.iter().any(|b| matches!(b, Bytecode::ReadRef | Bytecode::LdU64(_) | Bytecode::LdU8(_) | Bytecode::LdTrue | Bytecode::LdFalse))
                                }).unwrap_or(false) {
                                    // Check for branch after reading
                                    if code.code.iter().skip(i+1).take(20).any(|b| matches!(b, Bytecode::BrTrue(_) | Bytecode::BrFalse(_))) {
                                        is_read = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                if is_read { break; }
            }

            if !is_read {
                issues.push(SecurityIssue {
                    id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                    title: self.name().to_string(),
                    description: format!("The field '{}' is defined and likely settable, but its value is never checked in any conditional logic. This creates a false sense of security where users/auditors believe a 'paused' state exists, but the protocol remains operational regardless.", field_name),
                    location: create_loc(ctx, 0, 0), source_code: None,
                    recommendation: "Ensure that all critical state-modifying functions check the 'paused' flag: 'assert!(!vault.paused, E_CONTRACT_PAUSED)'.".to_string(),
                    references: vec![], metadata: std::collections::HashMap::new(),
                });
            }
        }
        issues
    }
}

// ========== 26. ZERO AMOUNT DEPOSIT ==========
pub struct ZeroAmountDepositDetector;

#[async_trait::async_trait]
impl SecurityDetector for ZeroAmountDepositDetector {
    fn id(&self) -> &'static str { "SUI-026" }
    fn name(&self) -> &'static str { "Zero-Amount Deposit State Poisoning" }
    fn description(&self) -> &'static str { "Detects deposit functions that allow zero-amount inputs in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Medium }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            if func_name.contains("deposit") || func_name.contains("add_liquidity") {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                if let Some(code) = &func_def.code {
                    let mut checks_amount = false;
                    for (i, instr) in code.code.iter().enumerate() {
                        // Check for 'amount > 0' pattern
                        if matches!(instr, Bytecode::LdU64(0)) {
                            if code.code.iter().skip(i+1).take(5).any(|b| matches!(b, Bytecode::Gt | Bytecode::Neq)) {
                                checks_amount = true;
                                break;
                            }
                        }
                    }
                    
                    if !checks_amount {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: self.name().to_string(),
                            description: format!("Function '{}' allows zero-amount deposits. This can lead to state poisoning, unnecessary vector growth, and potential logic exploitation in reward calculations.", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Add 'assert!(amount > 0, E_ZERO_AMOUNT)' at the beginning of the function.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

// ========== 27. CAPABILITY THEATER ==========
pub struct CapabilityTheaterDetector;

#[async_trait::async_trait]
impl SecurityDetector for CapabilityTheaterDetector {
    fn id(&self) -> &'static str { "SUI-027" }
    fn name(&self) -> &'static str { "Capability Theater" }
    fn description(&self) -> &'static str { "Detects capability objects that are never used for authentication" }
    fn default_severity(&self) -> Severity { Severity::High }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        let mut cap_structs = Vec::new();

        // 1. Find all structs that look like capabilities
        for (s_idx, struct_def) in ctx.module.struct_defs.iter().enumerate() {
            let handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let name = ctx.module.identifier_at(handle.name).as_str();
            if name.contains("Cap") || name.contains("Owner") || name.contains("Admin") {
                cap_structs.push((s_idx as u16, name.to_string()));
            }
        }

        // 2. Check if these structs are ever required as parameters in sensitive functions
        for (s_idx, name) in cap_structs {
            let mut is_used = false;
            for func_def in &ctx.module.function_defs {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let signature = &ctx.module.signatures[func_handle.parameters.0 as usize];
                
                // Check if this struct is used as a parameter in any function
                for param in &signature.0 {
                    let mut t = param;
                    while let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = t { t = inner; }
                    if let SignatureToken::Struct(idx) | SignatureToken::StructInstantiation(idx, _) = t {
                        if idx.0 == s_idx {
                            // Check if the function actually uses the capability parameter
                            if let Some(code) = &func_def.code {
                                for instr in &code.code {
                                    match instr {
                                        Bytecode::MoveLoc(loc_idx) | Bytecode::CopyLoc(loc_idx) | Bytecode::ImmBorrowLoc(loc_idx) | Bytecode::MutBorrowLoc(loc_idx) => {
                                            let param_sig = &signature.0;
                                            if (*loc_idx as usize) < param_sig.len() {
                                                let param_type = &param_sig[*loc_idx as usize];
                                                let mut pt = param_type;
                                                while let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = pt { pt = inner; }
                                                if let SignatureToken::Struct(check_idx) | SignatureToken::StructInstantiation(check_idx, _) = pt {
                                                    if check_idx.0 == s_idx {
                                                        is_used = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            
                            // Also check if it's used in assert statements or access control
                            if func_name_is_sensitive(ctx.module.identifier_at(func_handle.name).as_str()) {
                                if let Some(code) = &func_def.code {
                                    for instr in &code.code {
                                        if let Some(called_func) = crate::utils::get_function_name(instr, &ctx.module) {
                                            if called_func.to_string().contains("tx_context::sender") || called_func.to_string().contains("ctx::sender") {
                                                is_used = true;
                                                break;
                                            }
                                        }
                                        if matches!(instr, Bytecode::Abort | Bytecode::BrTrue(_) | Bytecode::BrFalse(_)) {
                                            is_used = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            
                            // Check if capability is used in comparisons or assertions
                            if !is_used {
                                if let Some(code) = &func_def.code {
                                    for instr in &code.code {
                                        if matches!(instr, Bytecode::Eq | Bytecode::Neq) {
                                            // Check if comparison involves the capability parameter
                                            // This would indicate the capability is being used for auth checks
                                            is_used = true;
                                            break;
                                        }
                                    }
                                }
                            }
                            
                            if is_used {
                                break;
                            }
                        }
                    }
                }
                if is_used { break; }
            }

            if !is_used {
                issues.push(SecurityIssue {
                    id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                    title: self.name().to_string(),
                    description: format!("The capability struct '{}' exists but is never used for authentication in any sensitive function. This gives a false impression of security to reviewers and may indicate a partially implemented or bypassed access control system.", name),
                    location: create_loc(ctx, 0, 0), source_code: None,
                    recommendation: "Ensure that 'admin' functions require the appropriate Capability object as a parameter.".to_string(),
                    references: vec![], metadata: std::collections::HashMap::new(),
                });
            }
        }
        issues
    }
}

fn func_name_is_sensitive(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("drain") || n.contains("withdraw") || n.contains("set_") || n.contains("update_") || n.contains("emergency") || n.contains("pause")
}

fn has_tx_context_parameter(ctx: &DetectionContext, func_handle: &move_binary_format::file_format::FunctionHandle) -> bool {
    let param_types = &ctx.module.signatures[func_handle.parameters.0 as usize];
    
    param_types.0.iter().any(|param| {
        if let SignatureToken::Struct(s_idx) = param {
            let struct_handle = &ctx.module.struct_handles[s_idx.0 as usize];
            let module_handle = &ctx.module.module_handles[struct_handle.module.0 as usize];
            let module_name = ctx.module.identifier_at(module_handle.name);
            let struct_name = ctx.module.identifier_at(struct_handle.name);
            
            // Check if this is TxContext from the sui framework
            module_name.as_str().to_lowercase().contains("tx_context") && 
            struct_name.as_str().to_lowercase().contains("txcontext")
        } else {
            false
        }
    })
}

// ========== 28. REFERENCE EXPOSURE ==========
pub struct ReferenceExposureDetector;

#[async_trait::async_trait]
impl SecurityDetector for ReferenceExposureDetector {
    fn id(&self) -> &'static str { "SUI-028" }
    fn name(&self) -> &'static str { "Internal Reference Exposure" }
    fn description(&self) -> &'static str { "Detects public functions that leak internal struct references" }
    fn default_severity(&self) -> Severity { Severity::Medium }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if func_def.visibility == Visibility::Public {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let return_sig = &ctx.module.signatures[func_handle.return_.0 as usize];
                
                for ret_type in &return_sig.0 {
                    if let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = ret_type {
                        if let SignatureToken::Struct(_) | SignatureToken::StructInstantiation(_, _) = **inner {
                            let func_name = ctx.module.identifier_at(func_handle.name).as_str();
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: self.name().to_string(),
                                description: format!("Public function '{}' returns a reference to a struct. This may leak internal protocol state or allow bypass of encapsulation, especially in a shared object context.", func_name),
                                location: create_loc(ctx, idx, 0), source_code: None,
                                recommendation: "Instead of returning references, return specific values or use getter functions for individual fields.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

// ========== 29. UNPROTECTED CAPABILITY MINTING ==========
pub struct UnprotectedCapabilityMintingDetector;

#[async_trait::async_trait]
impl SecurityDetector for UnprotectedCapabilityMintingDetector {
    fn id(&self) -> &'static str { "AC-CAP-001" }
    fn name(&self) -> &'static str { "Unprotected Capability Minting" }
    fn description(&self) -> &'static str { "Detects functions that mint capabilities without access control" }
    fn default_severity(&self) -> Severity { Severity::Critical }

    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if func_def.visibility == Visibility::Public || func_def.is_entry {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let _func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
                
                if let Some(code) = &func_def.code {
                    let mut mints_cap = false;
                    let mut has_access_control = false;
                    
                    for instr in &code.code {
                        let s_handle_idx = match instr {
                            Bytecode::Pack(idx) => Some(ctx.module.struct_defs[idx.0 as usize].struct_handle),
                            Bytecode::PackGeneric(idx) => {
                                let inst = &ctx.module.struct_instantiations()[idx.0 as usize];
                                Some(ctx.module.struct_defs[inst.def.0 as usize].struct_handle)
                            }
                            _ => None,
                        };

                        if let Some(h_idx) = s_handle_idx {
                            let s_name = ctx.module.identifier_at(ctx.module.struct_handle_at(h_idx).name).as_str();
                            if s_name.contains("Cap") || s_name.contains("Owner") || s_name.contains("Admin") {
                                mints_cap = true;
                            }
                        }
                        
                        if let Some(called_name) = crate::utils::get_function_name(instr, &ctx.module) {
                            let cn = called_name.as_str().to_lowercase();
                            if cn.contains("tx_context::sender") || cn.contains("ctx::sender") {
                                has_access_control = true;
                            }
                        }
                        if matches!(instr, Bytecode::Abort | Bytecode::BrFalse(_) | Bytecode::BrTrue(_)) {
                            has_access_control = true;
                        }
                    }

                    if mints_cap && !has_access_control {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: self.name().to_string(),
                            description: format!("Function '{}' allows anyone to mint a capability object. Capabilities should be strictly protected by existing capabilities or limited to the module initializer.", ctx.module.identifier_at(func_handle.name)),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Ensure capability minting is restricted to restricted 'init' functions or requires a high-level admin capability.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct LinearScanAuthDetector;
#[async_trait::async_trait]
impl SecurityDetector for LinearScanAuthDetector {
    fn id(&self) -> &'static str { "SUI-029" }
    fn name(&self) -> &'static str { "Linear Scan for Authorization" }
    fn description(&self) -> &'static str { "Detects O(n) linear scans for authorization, which can lead to DoS or gas exhaustion" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                let mut has_loop = false;
                let mut has_vector_borrow = false;
                let mut has_comparison = false;

                for (idx, instr) in code.code.iter().enumerate() {
                    match instr {
                        Bytecode::Branch(target) | Bytecode::BrTrue(target) | Bytecode::BrFalse(target) => {
                            if (*target as usize) < idx {
                                has_loop = true;
                            }
                        }
                        _ => {}
                    }
                    if let Some((_, mod_name, func_name)) = crate::utils::get_function_name_full(instr, &ctx.module) {
                        if mod_name == "vector" && func_name == "borrow" {
                            has_vector_borrow = true;
                        }
                    }
                    if matches!(instr, Bytecode::Eq | Bytecode::Neq) {
                        has_comparison = true;
                    }
                }

                if has_loop && has_vector_borrow && has_comparison {
                    let func_name = ctx.module.identifier_at(ctx.module.function_handle_at(func_def.function).name).as_str();
                    if func_name.contains("whitelisted") || func_name.contains("authorized") || func_name.contains("check") {
                         issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: self.name().to_string(),
                            description: format!("Function '{}' performs a linear scan over a vector for authorization. As the vector grows, gas costs will increase linearly, potentially leading to DoS.", func_name),
                            location: create_loc(ctx, 0, 0), source_code: None,
                            recommendation: "Use a Table or Set for O(1) authorization checks.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct UnboundedStorageDetector;
#[async_trait::async_trait]
impl SecurityDetector for UnboundedStorageDetector {
    fn id(&self) -> &'static str { "SUI-030" }
    fn name(&self) -> &'static str { "Unbounded Table/Bag Storage" }
    fn description(&self) -> &'static str { "Detects tables or bags that can grow indefinitely without size limits or authentication" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            if (func_def.visibility == Visibility::Public || func_def.is_entry) {
                if let Some(code) = &func_def.code {
                    let mut has_table_add = false;
                    let mut has_size_limit = false;

                    for instr in &code.code {
                        if let Some((_, mod_name, func_name)) = crate::utils::get_function_name_full(instr, &ctx.module) {
                            if (mod_name == "table" || mod_name == "bag" || mod_name == "object_table" || mod_name == "object_bag") && func_name == "add" {
                                has_table_add = true;
                            }
                            if func_name == "length" || func_name == "size" {
                                has_size_limit = true; // Heuristic
                            }
                        }
                    }

                    if has_table_add && !has_size_limit {
                        // Check if it's an admin function. If it is, maybe it's okay, but still risky.
                        let func_name = ctx.module.identifier_at(ctx.module.function_handle_at(func_def.function).name).as_str();
                        
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: self.name().to_string(),
                            description: format!("Function '{}' adds entries to a Table/Bag without an apparent size limit. This can lead to unbounded storage growth and potential storage griefing.", func_name),
                            location: create_loc(ctx, 0, 0), source_code: None,
                            recommendation: "Implement a maximum size limit for the collection or restrict entry to authorized users only.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct UnboundCapabilityDetector;
#[async_trait::async_trait]
impl SecurityDetector for UnboundCapabilityDetector {
    fn id(&self) -> &'static str { "SUI-031" }
    fn name(&self) -> &'static str { "Unbound Capability" }
    fn description(&self) -> &'static str { "Detects capability objects that are not cryptographically or logically bound to the objects they control" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for struct_def in &ctx.module.struct_defs {
            let handle = ctx.module.struct_handle_at(struct_def.struct_handle);
            let name = ctx.module.identifier_at(handle.name).as_str().to_lowercase();
            
            if name.contains("cap") || name.contains("admin") {
                if let StructFieldInformation::Declared(fields) = &struct_def.field_information {
                    let mut has_binding = false;
                    for field in fields {
                        let field_name = ctx.module.identifier_at(field.name).as_str().to_lowercase();
                        if field_name != "id" {
                            has_binding = true;
                        }
                    }
                    
                    if !has_binding {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: self.name().to_string(),
                            description: format!("Capability struct '{}' has no binding fields. It should ideally contain the ID of the object it manages to prevent unauthorized use across different instances of the protocol.", ctx.module.identifier_at(handle.name)),
                            location: create_loc(ctx, 0, 0), source_code: None,
                            recommendation: "Add a field to the capability struct that stores the ID of the target object (e.g., 'vault_id: ID').".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct PrecisionLossDetector;
#[async_trait::async_trait]
impl SecurityDetector for PrecisionLossDetector {
    fn id(&self) -> &'static str { "SUI-032" }
    fn name(&self) -> &'static str { "Precision Loss in Financial Calculations" }
    fn description(&self) -> &'static str { "Detects division before multiplication which leads to precision loss in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let mut div_index = None;
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Div) {
                        div_index = Some(i);
                    }
                    if matches!(instr, Bytecode::Mul) {
                        if let Some(_) = div_index {
                            let func_name = ctx.module.identifier_at(ctx.module.function_handle_at(func_def.function).name).as_str();
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: self.name().to_string(),
                                description: format!("Function '{}' performs division before multiplication. This can lead to significant precision loss in financial calculations.", func_name),
                                location: create_loc(ctx, 0, i as u16), source_code: None,
                                recommendation: "Always perform multiplication before division when possible to preserve precision in financial functions.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                            break;
                        }
                    }
                }
            }
        }
        issues
    }
}

pub struct PhantomAuthParameterDetector;
#[async_trait::async_trait]
impl SecurityDetector for PhantomAuthParameterDetector {
    fn id(&self) -> &'static str { "SUI-033" }
    fn name(&self) -> &'static str { "Phantom Authorization Parameter" }
    fn description(&self) -> &'static str { "Detects capability/authorization parameters that exist but are never actually used in the function body in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            if func_def.visibility != Visibility::Public && !func_def.is_entry {
                continue;
            }
            
            // Only check financial functions
            if !is_financial_function(ctx, func_def) {
                continue;
            }
            
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).as_str();
            let parameters = ctx.module.signature_at(func_handle.parameters);
            
            // Find capability parameters
            let mut cap_params = Vec::new();
            for (idx, token) in parameters.0.iter().enumerate() {
                let struct_handle_idx = match token {
                    SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                        match &**inner {
                            SignatureToken::Struct(sidx) => Some(*sidx),
                            SignatureToken::StructInstantiation(sidx, _) => Some(*sidx),
                            _ => None,
                        }
                    }
                    SignatureToken::Struct(sidx) => Some(*sidx),
                    SignatureToken::StructInstantiation(sidx, _) => Some(*sidx),
                    _ => None,
                };
                
                if let Some(sidx) = struct_handle_idx {
                    let struct_handle = ctx.module.struct_handle_at(sidx);
                    let name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
                    if name.contains("cap") || name.contains("admin") || name.contains("owner") || name.contains("auth") {
                        cap_params.push((idx, ctx.module.identifier_at(struct_handle.name).as_str()));
                    }
                }
            }
            
            // Check if capability parameters are actually used
            if let Some(code) = &func_def.code {
                for (param_idx, cap_name) in cap_params {
                    let mut is_used = false;
                    
                    // Check if parameter is referenced in bytecode
                    for instr in &code.code {
                        match instr {
                            // Parameter is copied or moved
                            Bytecode::MoveLoc(idx) | Bytecode::CopyLoc(idx) => {
                                if *idx as usize == param_idx {
                                    is_used = true;
                                    break;
                                }
                            }
                            // Parameter is borrowed (most common for &Cap)
                            Bytecode::ImmBorrowLoc(idx) | Bytecode::MutBorrowLoc(idx) => {
                                if *idx as usize == param_idx {
                                    is_used = true;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    
                    // CRITICAL: Capability parameter exists but never used!
                    if !is_used {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: self.name().to_string(),
                            description: format!(
                                "Function '{}' has a capability parameter '{}' that is NEVER USED in the function body. This creates false security - the parameter suggests authorization but provides none. Attackers can call this function without possessing the capability.",
                                func_name, cap_name
                            ),
                            location: create_loc(ctx, 0, 0),
                            source_code: None,
                            recommendation: format!(
                                "Either remove the '{}' parameter if not needed, or actually use it to enforce authorization. Common pattern: verify capability ownership, check capability role, or validate capability binding to target object.",
                                cap_name
                            ),
                            references: vec![
                                "CWE-285: Improper Authorization".to_string(),
                                "Phantom Authorization Anti-Pattern".to_string(),
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
