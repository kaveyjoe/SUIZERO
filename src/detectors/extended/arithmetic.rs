// Extended Arithmetic Security Detectors
// Ported from addmores/arithmetic.rs to SecurityDetector API

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::Bytecode,
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

// ========== 1. INTEGER OVERFLOW ADD ==========
pub struct IntegerOverflowAddDetector;

#[async_trait::async_trait]
impl SecurityDetector for IntegerOverflowAddDetector {
    fn id(&self) -> &'static str { "ARITH-001" }
    fn name(&self) -> &'static str { "Integer Overflow Add" }
    fn description(&self) -> &'static str { "Detects unchecked addition that may overflow" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Add) {
                        // Check if there's overflow protection nearby
                        let has_check = code.code.iter()
                            .skip(i.saturating_sub(3))
                            .take(7)
                            .any(|b| matches!(b, Bytecode::Lt | Bytecode::Ge | Bytecode::Abort));
                        
                        if !has_check {
                            // Only flag if it's not a simple loop increment (heuristic: LdU64(1) then Add)
                            let is_simple_increment = i > 0 && matches!(code.code.get(i-1), Some(Bytecode::LdU64(1) | Bytecode::LdU8(1)));
                            
                            if !is_simple_increment {
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(),
                                    severity: Severity::Medium, // Reduced
                                    confidence: Confidence::Low, // Reduced
                                    title: "Unchecked addition may overflow".to_string(),
                                    description: "Addition operation without overflow protection".to_string(),
                                    location: create_loc(ctx, idx, i as u16),
                                    source_code: None,
                                    recommendation: "Use checked arithmetic or add explicit overflow checks before addition".to_string(),
                                    references: vec!["CWE-190: Integer Overflow".to_string()],
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

// ========== 2. INTEGER OVERFLOW MUL ==========
pub struct IntegerOverflowMulDetector;

#[async_trait::async_trait]
impl SecurityDetector for IntegerOverflowMulDetector {
    fn id(&self) -> &'static str { "ARITH-002" }
    fn name(&self) -> &'static str { "Integer Overflow Mul" }
    fn description(&self) -> &'static str { "Detects unchecked multiplication that may overflow" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Mul) {
                        let has_check = code.code.iter()
                            .skip(i.saturating_sub(3))
                            .take(7)
                            .any(|b| matches!(b, Bytecode::Lt | Bytecode::Div | Bytecode::Abort));
                        
                        if !has_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: "Unchecked multiplication may overflow".to_string(),
                                description: "Multiplication without overflow checks".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Add overflow checks or use saturating multiplication".to_string(),
                                references: vec!["CWE-190: Integer Overflow".to_string()],
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

// ========== 3. INTEGER UNDERFLOW SUB ==========
pub struct IntegerUnderflowSubDetector;

#[async_trait::async_trait]
impl SecurityDetector for IntegerUnderflowSubDetector {
    fn id(&self) -> &'static str { "ARITH-003" }
    fn name(&self) -> &'static str { "Integer Underflow Sub" }
    fn description(&self) -> &'static str { "Detects unchecked subtraction that may underflow" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Sub) {
                        let mut has_check = code.code.iter()
                            .skip(i.saturating_sub(5))
                            .take(10)
                            .any(|b| matches!(b, Bytecode::Ge | Bytecode::Gt | Bytecode::Le | Bytecode::Lt | Bytecode::Abort));
                        
                        // Additional check: maybe the comparison happened earlier and we branched?
                        // For a simple single-block heuristic, let's look for any comparison in the preceding 15 instructions
                        if !has_check && i > 0 {
                            has_check = code.code.iter()
                                .skip(i.saturating_sub(15))
                                .take(15)
                                .any(|b| matches!(b, Bytecode::Ge | Bytecode::Gt | Bytecode::Le | Bytecode::Lt));
                        }
                        
                        if !has_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: "Unchecked subtraction may underflow".to_string(),
                                description: "Subtraction without underflow protection".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Add underflow checks before subtraction".to_string(),
                                references: vec!["CWE-191: Integer Underflow".to_string()],
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

// ========== 4-20: Remaining Arithmetic Detectors ==========

pub struct IntegerUnderflowDecDetector;
#[async_trait::async_trait]
impl SecurityDetector for IntegerUnderflowDecDetector {
    fn id(&self) -> &'static str { "ARITH-004" }
    fn name(&self) -> &'static str { "Integer Underflow Dec" }
    fn description(&self) -> &'static str { "Detects decrement operations that may underflow" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if let Bytecode::Sub = instr {
                        // Check if subtracting 1 (common decrement pattern)
                        if i > 0 && matches!(code.code.get(i-1), Some(Bytecode::LdU64(1) | Bytecode::LdU8(1))) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                                title: "Potential decrement underflow".to_string(),
                                description: "Decrement operation may underflow at zero".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Check value is greater than zero before decrementing".to_string(),
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

pub struct DivisionByZeroDetector;
#[async_trait::async_trait]
impl SecurityDetector for DivisionByZeroDetector {
    fn id(&self) -> &'static str { "ARITH-005" }
    fn name(&self) -> &'static str { "Division By Zero" }
    fn description(&self) -> &'static str { "Detects division operations without zero checks" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Div) {
                        let has_zero_check = code.code.iter()
                            .skip(i.saturating_sub(5))
                            .take(10)
                            .any(|b| matches!(b, Bytecode::Neq | Bytecode::Gt));
                        
                        if !has_zero_check {
                            if i > 0 {
                                let is_zero = match code.code[i-1] {
                                    Bytecode::LdU8(v) => v == 0,
                                    Bytecode::LdU16(v) => v == 0,
                                    Bytecode::LdU32(v) => v == 0,
                                    Bytecode::LdU64(v) => v == 0,
                                    Bytecode::LdU128(v) => v == 0,
                                    _ => false,
                                };
                                if !is_zero && matches!(code.code[i-1], Bytecode::LdU8(_) | Bytecode::LdU16(_) | Bytecode::LdU32(_) | Bytecode::LdU64(_) | Bytecode::LdU128(_)) {
                                    continue;
                                }
                            }

                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: "Division without zero check".to_string(),
                                description: "Division may cause panic if divisor is zero".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Add explicit check that divisor is not zero".to_string(),
                                references: vec!["CWE-369: Divide By Zero".to_string()],
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

pub struct ModuloByZeroDetector;
#[async_trait::async_trait]
impl SecurityDetector for ModuloByZeroDetector {
    fn id(&self) -> &'static str { "ARITH-006" }
    fn name(&self) -> &'static str { "Modulo By Zero" }
    fn description(&self) -> &'static str { "Detects modulo operations without zero checks" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Mod) {
                        let has_check = code.code.iter()
                            .skip(i.saturating_sub(5))
                            .take(10)
                            .any(|b| matches!(b, Bytecode::Neq | Bytecode::Gt));
                        
                        if !has_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                                title: "Modulo without zero check".to_string(),
                                description: "Modulo operation may panic if divisor is zero".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Ensure modulo divisor is not zero".to_string(),
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

pub struct PrecisionLossDetector;
#[async_trait::async_trait]
impl SecurityDetector for PrecisionLossDetector {
    fn id(&self) -> &'static str { "ARITH-007" }
    fn name(&self) -> &'static str { "Precision Loss" }
    fn description(&self) -> &'static str { "Detects operations that may lose precision" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for divide then multiply pattern (precision loss)
                for i in 0..code.code.len().saturating_sub(2) {
                    if matches!(code.code[i], Bytecode::Div) {
                        if matches!(code.code.get(i+1).or(code.code.get(i+2)), Some(Bytecode::Mul)) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                                title: "Precision loss in arithmetic".to_string(),
                                description: "Division before multiplication causes precision loss".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Multiply before dividing to preserve precision".to_string(),
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

pub struct RoundingErrorDetector;
#[async_trait::async_trait]
impl SecurityDetector for RoundingErrorDetector {
    fn id(&self) -> &'static str { "ARITH-008" }
    fn name(&self) -> &'static str { "Rounding Error" }
    fn description(&self) -> &'static str { "Detects potential rounding errors in calculations" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let div_count = code.code.iter().filter(|i| matches!(i, Bytecode::Div)).count();
                if div_count > 5 { // Increased from 2
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: Severity::Low, confidence: Confidence::Low,
                        title: "Multiple divisions may accumulate rounding errors".to_string(),
                        description: format!("{} division operations detected", div_count),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Use higher precision or reorder operations".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct UncheckedCastDetector;
#[async_trait::async_trait]
impl SecurityDetector for UncheckedCastDetector {
    fn id(&self) -> &'static str { "ARITH-009" }
    fn name(&self) -> &'static str { "Unchecked Cast" }
    fn description(&self) -> &'static str { "Detects type casts without range validation" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::CastU8 | Bytecode::CastU64 | Bytecode::CastU128) {
                        let has_range_check = code.code.iter()
                            .skip(i.saturating_sub(3))
                            .take(6)
                            .any(|b| matches!(b, Bytecode::Lt | Bytecode::Le));
                        
                        if !has_range_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                                title: "Unchecked type cast".to_string(),
                                description: "Cast may truncate or overflow without validation".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Add range checks before casting to smaller types".to_string(),
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

pub struct TypeOverflowDetector;
#[async_trait::async_trait]
impl SecurityDetector for TypeOverflowDetector {
    fn id(&self) -> &'static str { "ARITH-010" }
    fn name(&self) -> &'static str { "Type Overflow" }
    fn description(&self) -> &'static str { "Detects operations exceeding type limits" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Check for u8 operations without bounds
                let has_u8_ops = code.code.iter().any(|i| matches!(i, Bytecode::CastU8 | Bytecode::LdU8(_)));
                let has_arithmetic = code.code.iter().any(|i| matches!(i, Bytecode::Add | Bytecode::Mul));
                
                if has_u8_ops && has_arithmetic {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "u8 arithmetic may overflow".to_string(),
                        description: "Operations on small types without overflow protection".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Use wider types or add overflow checks".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct BoundaryConditionDetector;
#[async_trait::async_trait]
impl SecurityDetector for BoundaryConditionDetector {
    fn id(&self) -> &'static str { "ARITH-011" }
    fn name(&self) -> &'static str { "Boundary Condition" }
    fn description(&self) -> &'static str { "Detects missing boundary condition checks" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::VecImmBorrow(_) | Bytecode::VecMutBorrow(_)) {
                        let has_bounds = code.code.iter()
                            .skip(i.saturating_sub(3))
                            .take(6)
                            .any(|b| matches!(b, Bytecode::VecLen(_) | Bytecode::Lt));
                        
                        if !has_bounds {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                                title: "Vector access without bounds check".to_string(),
                                description: "Array/vector indexing may be out of bounds".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Validate index is within bounds before access".to_string(),
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

pub struct OffByOneErrorDetector;
#[async_trait::async_trait]
impl SecurityDetector for OffByOneErrorDetector {
    fn id(&self) -> &'static str { "ARITH-012" }
    fn name(&self) -> &'static str { "Off-By-One Error" }
    fn description(&self) -> &'static str { "Detects potential off-by-one errors in loops" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for <= with length (should often be <)
                for i in 0..code.code.len().saturating_sub(2) {
                    if matches!(code.code[i], Bytecode::VecLen(_)) {
                        if matches!(code.code.get(i+1).or(code.code.get(i+2)), Some(Bytecode::Le)) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "Potential off-by-one error".to_string(),
                                description: "Using <= with length may cause off-by-one".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Use < for length comparisons, not <=".to_string(),
                                references: vec!["CWE-193: Off-by-one Error".to_string()],
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

pub struct LogicInversionDetector;
#[async_trait::async_trait]
impl SecurityDetector for LogicInversionDetector {
    fn id(&self) -> &'static str { "ARITH-013" }
    fn name(&self) -> &'static str { "Logic Inversion" }
    fn description(&self) -> &'static str { "Detects inverted logic conditions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Not) {
                        let near_branch = code.code.iter()
                            .skip(i)
                            .take(3)
                            .any(|b| matches!(b, Bytecode::BrTrue(_) | Bytecode::BrFalse(_)));
                        
                        if near_branch {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "Logic inversion before branch".to_string(),
                                description: "NOT operation before branch may indicate inverted logic".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Verify boolean logic is correct".to_string(),
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

pub struct ConditionalBypassDetector;
#[async_trait::async_trait]
impl SecurityDetector for ConditionalBypassDetector {
    fn id(&self) -> &'static str { "ARITH-014" }
    fn name(&self) -> &'static str { "Conditional Bypass" }
    fn description(&self) -> &'static str { "Detects conditions that may be bypassed" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for Or operations that might allow bypass
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Or) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "OR condition may allow bypass".to_string(),
                            description: "Logical OR in security check may be exploitable".to_string(),
                            location: create_loc(ctx, idx, i as u16), source_code: None,
                            recommendation: "Review OR conditions in authorization checks".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct LoopInvariantDetector;
#[async_trait::async_trait]
impl SecurityDetector for LoopInvariantDetector {
    fn id(&self) -> &'static str { "ARITH-015" }
    fn name(&self) -> &'static str { "Loop Invariant" }
    fn description(&self) -> &'static str { "Detects loop invariants that should be outside loop" }
    fn default_severity(&self) -> Severity { Severity::Low }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        vec![] // Complex static analysis required
    }
}

pub struct InfiniteLoopDetector;
#[async_trait::async_trait]
impl SecurityDetector for InfiniteLoopDetector {
    fn id(&self) -> &'static str { "ARITH-016" }
    fn name(&self) -> &'static str { "Infinite Loop" }
    fn description(&self) -> &'static str { "Detects potential infinite loops" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for backward branches without increment
                for (i, instr) in code.code.iter().enumerate() {
                    if let Bytecode::Branch(target) = instr {
                        if *target <= i as u16 {
                            // Backward branch - check for increment
                            let has_increment = code.code.iter()
                                .skip(*target as usize)
                                .take(i - *target as usize)
                                .any(|b| matches!(b, Bytecode::Add | Bytecode::Sub));
                            
                            if !has_increment {
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                                    title: "Potential infinite loop".to_string(),
                                    description: "Loop without apparent termination condition".to_string(),
                                    location: create_loc(ctx, idx, i as u16), source_code: None,
                                    recommendation: "Ensure loop has proper termination condition".to_string(),
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

pub struct UnboundedIterationDetector;
#[async_trait::async_trait]
impl SecurityDetector for UnboundedIterationDetector {
    fn id(&self) -> &'static str { "ARITH-017" }
    fn name(&self) -> &'static str { "Unbounded Iteration" }
    fn description(&self) -> &'static str { "Detects iterations without upper bounds" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let has_loop = code.code.iter().any(|i| {
                    matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_))
                });
                
                let has_bound = code.code.iter().any(|i| {
                    matches!(i, Bytecode::Lt | Bytecode::Le)
                });
                
                if has_loop && !has_bound {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                        title: "Loop without upper bound".to_string(),
                        description: "Iteration may run indefinitely".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Add maximum iteration limit".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct EarlyExitVulnerabilityDetector;
#[async_trait::async_trait]
impl SecurityDetector for EarlyExitVulnerabilityDetector {
    fn id(&self) -> &'static str { "ARITH-018" }
    fn name(&self) -> &'static str { "Early Exit Vulnerability" }
    fn description(&self) -> &'static str { "Detects early returns that skip security checks" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let return_count = code.code.iter().filter(|i| matches!(i, Bytecode::Ret)).count();
                
                if return_count > 10 { // Increased from 3
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: Severity::Info, confidence: Confidence::Low,
                        title: "High number of return points".to_string(),
                        description: format!("{} return statements may make code harder to audit", return_count),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Consider consolidating returns for better readability".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct LateExitVulnerabilityDetector;
#[async_trait::async_trait]
impl SecurityDetector for LateExitVulnerabilityDetector {
    fn id(&self) -> &'static str { "ARITH-019" }
    fn name(&self) -> &'static str { "Late Exit Vulnerability" }
    fn description(&self) -> &'static str { "Detects delayed exits that allow state changes" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Check for state changes before abort
                for i in 0..code.code.len() {
                    if matches!(code.code[i], Bytecode::Abort) {
                        let has_state_change = code.code.iter()
                            .take(i)
                            .rev()
                            .take(10)
                            .any(|b| matches!(b, Bytecode::MoveTo(_) | Bytecode::WriteRef));
                        
                        if has_state_change {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "State change before abort".to_string(),
                                description: "State modified before error abort".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Check conditions before state changes".to_string(),
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

pub struct StateInconsistencyDetector;
#[async_trait::async_trait]
impl SecurityDetector for StateInconsistencyDetector {
    fn id(&self) -> &'static str { "ARITH-020" }
    fn name(&self) -> &'static str { "State Inconsistency" }
    fn description(&self) -> &'static str { "Detects operations causing inconsistent state" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Multiple state writes without validation
                let state_writes = code.code.iter().filter(|i| {
                    matches!(i, Bytecode::MoveTo(_) | Bytecode::WriteRef)
                }).count();
                
                if state_writes > 2 {
                    let has_validation = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Abort | Bytecode::BrTrue(_))
                    });
                    
                    if !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Multiple state changes without validation".to_string(),
                            description: format!("{} state modifications without checks", state_writes),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Add validation between state changes".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct LoopPrecisionLossDetector;
#[async_trait::async_trait]
impl SecurityDetector for LoopPrecisionLossDetector {
    fn id(&self) -> &'static str { "SUI-035" }
    fn name(&self) -> &'static str { "Loop Precision Loss Accumulation" }
    fn description(&self) -> &'static str { "Detects precision loss (division) that accumulates inside loops" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // 1. Identify loops via backward branches
                let mut loops = Vec::new();
                for (i, instr) in code.code.iter().enumerate() {
                    match instr {
                        Bytecode::Branch(target) | Bytecode::BrTrue(target) | Bytecode::BrFalse(target) => {
                            if *target < i as u16 {
                                loops.push((*target as usize, i));
                            }
                        }
                        _ => {}
                    }
                }

                // 2. Check for division inside loops
                for (loop_start, loop_end) in loops {
                    for i in loop_start..=loop_end {
                        if matches!(code.code[i], Bytecode::Div) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::Medium,
                                title: "Precision loss accumulation in loop".to_string(),
                                description: "Division operation inside a loop may cause significant cumulative precision loss (dust extraction risk).".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Avoid division inside loops. Perform division after the loop or use higher precision types.".to_string(),
                                references: vec!["SUI-035: Loop Precision Loss".to_string()],
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
