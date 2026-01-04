// Extended Storage Security Detectors
// Ported from addmores/storage.rs to SecurityDetector API

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, SignatureToken},
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

// ========== 1. UNINITIALIZED STORAGE ==========
pub struct UninitializedStorageDetector;

#[async_trait::async_trait]
impl SecurityDetector for UninitializedStorageDetector {
    fn id(&self) -> &'static str { "STOR-001" }
    fn name(&self) -> &'static str { "Uninitialized Storage" }
    fn description(&self) -> &'static str { "Detects use of uninitialized storage" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    // Check for reads before writes
                    if matches!(instr, Bytecode::MoveFrom(_) | Bytecode::ImmBorrowGlobal(_)) {
                        // Look back to see if there was a MoveTo first
                        let has_prior_init = code.code.iter()
                            .take(i)
                            .any(|b| matches!(b, Bytecode::MoveTo(_)));
                        
                        if !has_prior_init {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::Medium,
                                title: "Potential uninitialized storage read".to_string(),
                                description: "Reading from storage without prior initialization".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Ensure storage is initialized before reading. Add existence checks.".to_string(),
                                references: vec!["CWE-457: Use of Uninitialized Variable".to_string()],
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

// ========== 2. STORAGE COLLISION ==========
pub struct StorageCollisionDetector;

#[async_trait::async_trait]
impl SecurityDetector for StorageCollisionDetector {
    fn id(&self) -> &'static str { "STOR-002" }
    fn name(&self) -> &'static str { "Storage Collision" }
    fn description(&self) -> &'static str { "Detects potential storage key collisions" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check for multiple MoveTo of same type
        let mut storage_types = std::collections::HashMap::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if let Bytecode::MoveTo(struct_idx) = instr {
                        *storage_types.entry(struct_idx.0).or_insert(0) += 1;
                        
                        if storage_types[&struct_idx.0] > 1 {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::Low,
                                title: "Potential storage collision".to_string(),
                                description: "Multiple writes to same storage type without unique keys".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Use unique identifiers for storage keys. Implement collision prevention.".to_string(),
                                references: vec![],
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

// ========== 3. STORAGE OVERWRITE ==========
pub struct StorageOverwriteDetector;

#[async_trait::async_trait]
impl SecurityDetector for StorageOverwriteDetector {
    fn id(&self) -> &'static str { "STOR-003" }
    fn name(&self) -> &'static str { "Storage Overwrite" }
    fn description(&self) -> &'static str { "Detects unconditional storage overwrites" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::MoveTo(_)) {
                        // Check if there's an existence check first
                        let has_exists_check = code.code.iter()
                            .take(i)
                            .rev()
                            .take(10)
                            .any(|b| matches!(b, Bytecode::Exists(_) | Bytecode::ExistsGeneric(_)));
                        
                        if !has_exists_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::Medium,
                                title: "Unconditional storage write".to_string(),
                                description: "Writing to storage without checking if data already exists".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Check storage existence before writing. Prevent accidental overwrites.".to_string(),
                                references: vec![],
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

// ========== 4. STORAGE LEAK ==========
pub struct StorageLeakDetector;

#[async_trait::async_trait]
impl SecurityDetector for StorageLeakDetector {
    fn id(&self) -> &'static str { "STOR-004" }
    fn name(&self) -> &'static str { "Storage Leak" }
    fn description(&self) -> &'static str { "Detects storage that is never cleaned up" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Track storage writes vs deletes
        let mut has_move_to = false;
        let mut has_move_from = false;
        
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                has_move_to = has_move_to || code.code.iter().any(|i| matches!(i, Bytecode::MoveTo(_)));
                has_move_from = has_move_from || code.code.iter().any(|i| matches!(i, Bytecode::MoveFrom(_)));
            }
        }
        
        if has_move_to && !has_move_from {
            issues.push(SecurityIssue {
                id: self.id().to_string(),
                severity: self.default_severity(),
                confidence: Confidence::Low,
                title: "No storage cleanup mechanism".to_string(),
                description: "Module writes to storage but has no cleanup function".to_string(),
                location: CodeLocation {
                    module_id: ctx.module_id.to_string(),
                    module_name: ctx.module.self_id().name().to_string(),
                    function_name: "module".to_string(),
                    instruction_index: 0, byte_offset: 0, line: None, column: None,
                },
                source_code: None,
                recommendation: "Implement cleanup functions to remove unused storage.".to_string(),
                references: vec![],
                metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}

// ========== 5-20: Remaining Storage Detectors ==========

pub struct MemoryExhaustionDetector;
#[async_trait::async_trait]
impl SecurityDetector for MemoryExhaustionDetector {
    fn id(&self) -> &'static str { "STOR-005" }
    fn name(&self) -> &'static str { "Memory Exhaustion" }
    fn description(&self) -> &'static str { "Detects unbounded memory allocation" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let vec_ops = code.code.iter().filter(|i| {
                    matches!(i, Bytecode::VecPack(_, _) | Bytecode::VecPushBack(_))
                }).count();
                
                let has_limit = code.code.iter().any(|i| {
                    matches!(i, Bytecode::VecLen(_) | Bytecode::Lt)
                });
                
                if vec_ops > 0 && !has_limit {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                        title: "Unbounded vector allocation".to_string(),
                        description: "Vector operations without size limits".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Add size limits to vector operations.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct GasExhaustionDetector;
#[async_trait::async_trait]
impl SecurityDetector for GasExhaustionDetector {
    fn id(&self) -> &'static str { "STOR-006" }
    fn name(&self) -> &'static str { "Gas Exhaustion" }
    fn description(&self) -> &'static str { "Detects operations that may exhaust gas" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Count expensive operations
                let expensive_ops = code.code.iter().filter(|i| {
                    matches!(i, Bytecode::MoveTo(_) | Bytecode::MoveFrom(_) | 
                             Bytecode::ImmBorrowGlobal(_) | Bytecode::MutBorrowGlobal(_))
                }).count();
                
                if expensive_ops > 10 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Many expensive storage operations".to_string(),
                        description: format!("{} storage operations may exhaust gas", expensive_ops),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Optimize storage access patterns. Batch operations.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct StackOverflowDetector;
#[async_trait::async_trait]
impl SecurityDetector for StackOverflowDetector {
    fn id(&self) -> &'static str { "STOR-007" }
    fn name(&self) -> &'static str { "Stack Overflow" }
    fn description(&self) -> &'static str { "Detects deep call stacks that may overflow" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let call_depth = code.code.iter().filter(|i| {
                    matches!(i, Bytecode::Call(_) | Bytecode::CallGeneric(_))
                }).count();
                
                if call_depth > 15 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Deep call stack detected".to_string(),
                        description: format!("{} function calls may cause stack overflow", call_depth),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Reduce call depth. Flatten call hierarchy.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct HeapOverflowDetector;
#[async_trait::async_trait]
impl SecurityDetector for HeapOverflowDetector {
    fn id(&self) -> &'static str { "STOR-008" }
    fn name(&self) -> &'static str { "Heap Overflow" }
    fn description(&self) -> &'static str { "Detects potential heap overflow" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::VecPushBack(_)) {
                        let has_capacity_check = code.code.iter()
                            .skip(i.saturating_sub(5))
                            .take(10)
                            .any(|b| matches!(b, Bytecode::VecLen(_)));
                        
                        if !has_capacity_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                                title: "Unbounded vector growth".to_string(),
                                description: "Vector push without capacity check".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Check vector capacity before push operations.".to_string(),
                                references: vec!["CWE-122: Heap-based Buffer Overflow".to_string()],
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

pub struct BufferOverflowDetector;
#[async_trait::async_trait]
impl SecurityDetector for BufferOverflowDetector {
    fn id(&self) -> &'static str { "STOR-009" }
    fn name(&self) -> &'static str { "Buffer Overflow" }
    fn description(&self) -> &'static str { "Detects buffer overflow vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::VecMutBorrow(_) | Bytecode::VecImmBorrow(_)) {
                        let has_bounds = code.code.iter()
                            .skip(i.saturating_sub(5))
                            .take(10)
                            .any(|b| matches!(b, Bytecode::VecLen(_) | Bytecode::Lt));
                        
                        if !has_bounds {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: "Vector access without bounds check".to_string(),
                                description: "Accessing vector element without validating index".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Validate index is within vector bounds.".to_string(),
                                references: vec!["CWE-119: Buffer Overflow".to_string()],
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

pub struct ArrayOutOfBoundsDetector;
#[async_trait::async_trait]
impl SecurityDetector for ArrayOutOfBoundsDetector {
    fn id(&self) -> &'static str { "STOR-010" }
    fn name(&self) -> &'static str { "Array Out Of Bounds" }
    fn description(&self) -> &'static str { "Detects array access out of bounds" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::VecSwap(_)) {
                        let has_check = code.code.iter()
                            .skip(i.saturating_sub(7))
                            .take(14)
                            .any(|b| matches!(b, Bytecode::VecLen(_)));
                        
                        if !has_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: "Vector swap without bounds check".to_string(),
                                description: "Swapping vector elements without validating indices".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Validate both indices before swap operation.".to_string(),
                                references: vec!["CWE-125: Out-of-bounds Read".to_string()],
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

pub struct StringOverflowDetector;
#[async_trait::async_trait]
impl SecurityDetector for StringOverflowDetector {
    fn id(&self) -> &'static str { "STOR-011" }
    fn name(&self) -> &'static str { "String Overflow" }
    fn description(&self) -> &'static str { "Detects string buffer overflow" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for vector of u8 (common string representation)
                let has_string_ops = code.code.iter().any(|i| {
                    matches!(i, Bytecode::VecPack(_, _) | Bytecode::VecUnpack(_, _))
                });
                
                if has_string_ops {
                    let has_length_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::VecLen(_) | Bytecode::Lt)
                    });
                    
                    if !has_length_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Unbounded string operation".to_string(),
                            description: "String manipulation without length validation".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Validate string lengths. Implement maximum size limits.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct BytesManipulationDetector;
#[async_trait::async_trait]
impl SecurityDetector for BytesManipulationDetector {
    fn id(&self) -> &'static str { "STOR-012" }
    fn name(&self) -> &'static str { "Unsafe Bytes Manipulation" }
    fn description(&self) -> &'static str { "Detects unsafe byte array manipulation" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::VecUnpack(_, _)) {
                        let has_validation = code.code.iter()
                            .skip(i.saturating_sub(3))
                            .take(6)
                            .any(|b| matches!(b, Bytecode::VecLen(_)));
                        
                        if !has_validation {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "Unsafe bytes unpacking".to_string(),
                                description: "Unpacking bytes without size validation".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Validate byte array size before unpacking.".to_string(),
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

pub struct OptionNoneExploitDetector;
#[async_trait::async_trait]
impl SecurityDetector for OptionNoneExploitDetector {
    fn id(&self) -> &'static str { "STOR-013" }
    fn name(&self) -> &'static str { "Option None Exploit" }
    fn description(&self) -> &'static str { "Detects unwrapping None values" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for variant operations (used for Option)
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Unpack(_) | Bytecode::UnpackGeneric(_)) {
                        let has_variant_check = code.code.iter()
                            .skip(i.saturating_sub(5))
                            .take(10)
                            .any(|b| matches!(b, Bytecode::BrTrue(_) | Bytecode::BrFalse(_)));
                        
                        if !has_variant_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "Unchecked variant unpacking".to_string(),
                                description: "Unpacking variant without checking discriminant".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Check variant type before unpacking. Handle None case.".to_string(),
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

pub struct VectorSideEffectDetector;
#[async_trait::async_trait]
impl SecurityDetector for VectorSideEffectDetector {
    fn id(&self) -> &'static str { "STOR-014" }
    fn name(&self) -> &'static str { "Vector Side Effect" }
    fn description(&self) -> &'static str { "Detects unexpected vector modifications" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Count mutable vector operations
                let mut_vec_ops = code.code.iter().filter(|i| {
                    matches!(i, Bytecode::VecMutBorrow(_) | Bytecode::VecSwap(_) | 
                             Bytecode::VecPushBack(_) | Bytecode::VecPopBack(_))
                }).count();
                
                if mut_vec_ops > 5 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Many vector modifications".to_string(),
                        description: format!("{} mutable vector operations", mut_vec_ops),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Review vector mutations for unintended side effects.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct ReferenceAliasingDetector;
#[async_trait::async_trait]
impl SecurityDetector for ReferenceAliasingDetector {
    fn id(&self) -> &'static str { "STOR-015" }
    fn name(&self) -> &'static str { "Reference Aliasing" }
    fn description(&self) -> &'static str { "Detects potentially aliased references" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Count reference operations
                let ref_count = code.code.iter().filter(|i| {
                    matches!(i, Bytecode::ImmBorrowLoc(_) | Bytecode::MutBorrowLoc(_) |
                             Bytecode::ImmBorrowField(_) | Bytecode::MutBorrowField(_))
                }).count();
                
                if ref_count > 10 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Complex reference usage".to_string(),
                        description: format!("{} borrow operations may indicate aliasing", ref_count),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Review reference patterns. Ensure no aliasing violations.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct MutableReferenceEscapeDetector;
#[async_trait::async_trait]
impl SecurityDetector for MutableReferenceEscapeDetector {
    fn id(&self) -> &'static str { "STOR-016" }
    fn name(&self) -> &'static str { "Mutable Reference Escape" }
    fn description(&self) -> &'static str { "Detects mutable references that escape scope" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    // Check for mutable borrow that might be stored
                    if matches!(instr, Bytecode::MutBorrowLoc(_) | Bytecode::MutBorrowField(_)) {
                        // Check if followed by pack or store
                        let may_escape = code.code.get(i+1..i+3).map(|slice| {
                            slice.iter().any(|b| matches!(b, Bytecode::Pack(_) | Bytecode::StLoc(_)))
                        }).unwrap_or(false);
                        
                        if may_escape {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                                title: "Mutable reference may escape".to_string(),
                                description: "Mutable borrow stored in struct or local".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Ensure mutable references don't escape their scope.".to_string(),
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

pub struct ImmutableReferenceMutationDetector;
#[async_trait::async_trait]
impl SecurityDetector for ImmutableReferenceMutationDetector {
    fn id(&self) -> &'static str { "STOR-017" }
    fn name(&self) -> &'static str { "Immutable Reference Mutation" }
    fn description(&self) -> &'static str { "Detects mutations through immutable references" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::ImmBorrowLoc(_) | Bytecode::ImmBorrowField(_)) {
                        // Check for write operations nearby
                        let has_write = code.code.get(i+1..i+5).map(|slice| {
                            slice.iter().any(|b| matches!(b, Bytecode::WriteRef))
                        }).unwrap_or(false);
                        
                        if has_write {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: "Write through immutable reference".to_string(),
                                description: "Attempting to modify data through immutable borrow".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Use mutable borrow for modifications.".to_string(),
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

pub struct BorrowCheckerBypassDetector;
#[async_trait::async_trait]
impl SecurityDetector for BorrowCheckerBypassDetector {
    fn id(&self) -> &'static str { "STOR-018" }
    fn name(&self) -> &'static str { "Borrow Checker Bypass" }
    fn description(&self) -> &'static str { "Detects attempts to bypass borrow checker" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for freeze/thaw patterns
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::FreezeRef) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Reference freezing detected".to_string(),
                            description: "Converting mutable to immutable reference".to_string(),
                            location: create_loc(ctx, idx, i as u16), source_code: None,
                            recommendation: "Review freeze operation for correctness.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct MoveSemanticsAbuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for MoveSemanticsAbuseDetector {
    fn id(&self) -> &'static str { "STOR-019" }
    fn name(&self) -> &'static str { "Move Semantics Abuse" }
    fn description(&self) -> &'static str { "Detects abuse of Move semantics" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    // Check for MoveLoc followed immediately by another MoveLoc on same location
                    if let Bytecode::MoveLoc(loc) = instr {
                        if let Some(Bytecode::MoveLoc(loc2)) = code.code.get(i+1) {
                            if loc == loc2 {
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                    title: "Double move detected".to_string(),
                                    description: "Attempting to move same value twice".to_string(),
                                    location: create_loc(ctx, idx, i as u16), source_code: None,
                                    recommendation: "Ensure values are only moved once.".to_string(),
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

pub struct CopySemanticsAbuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for CopySemanticsAbuseDetector {
    fn id(&self) -> &'static str { "STOR-020" }
    fn name(&self) -> &'static str { "Copy Semantics Abuse" }
    fn description(&self) -> &'static str { "Detects abuse of Copy semantics" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Count CopyLoc operations (excessive copying)
                let copy_count = code.code.iter().filter(|i| {
                    matches!(i, Bytecode::CopyLoc(_))
                }).count();
                
                if copy_count > 20 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Excessive value copying".to_string(),
                        description: format!("{} copy operations detected", copy_count),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Use references instead of copying. Optimize value usage.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}
