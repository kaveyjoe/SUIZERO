// Extended Arithmetic Security Detectors
// Updated to be more precise and focus on financial functions

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, CodeUnit, FunctionDefinition, SignatureToken},
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
fn is_financial_function(ctx: &DetectionContext, func_def: &FunctionDefinition) -> bool {
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

// ========== 1. INTEGER OVERFLOW ADD ==========
pub struct IntegerOverflowAddDetector;

#[async_trait::async_trait]
impl SecurityDetector for IntegerOverflowAddDetector {
    fn id(&self) -> &'static str { "ARITH-001" }
    fn name(&self) -> &'static str { "Integer Overflow Add" }
    fn description(&self) -> &'static str { "Detects unchecked addition that may overflow in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
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
                                    severity: Severity::High, // High for financial functions
                                    confidence: Confidence::Medium, // Medium in financial context
                                    title: "Unchecked addition may overflow in financial function".to_string(),
                                    description: "Addition operation without overflow protection in financial function".to_string(),
                                    location: create_loc(ctx, idx, i as u16),
                                    source_code: None,
                                    recommendation: "Use checked arithmetic or add explicit overflow checks before addition in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects unchecked multiplication that may overflow in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Mul) {
                        // Skip if this is in a fixed-point math library or safe context
                        if is_in_fixed_point_context(code, i) {
                            continue;
                        }
                        
                        // Check if there's overflow protection nearby
                        let has_check = code.code.iter()
                            .skip(i.saturating_sub(3))
                            .take(7)
                            .any(|b| matches!(b, Bytecode::Lt | Bytecode::Div | Bytecode::Abort));
                        
                        // Also check for function name patterns that indicate safe math
                        let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                        let func_name = ctx.module.identifier_at(func_handle.name);
                        let func_name_lower = func_name.as_str().to_lowercase();
                        
                        if func_name_lower.contains("fixed_point") || 
                           func_name_lower.contains("safe_") ||
                           func_name_lower.contains("is_safe") {
                            continue; // Skip functions that suggest safety
                        }
                        
                        // Check if this is a post-condition check (like verify_k) that aborts safely
                        if !has_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: Severity::High, // High for financial functions
                                confidence: Confidence::Medium, // Medium in financial context
                                title: "Multiplication may overflow in financial function".to_string(),
                                description: "Multiplication without explicit overflow handling in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Consider using fixed-point math libraries or verifying inputs are bounded in financial functions".to_string(),
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

// Helper function to detect if multiplication is in fixed-point math context
fn is_in_fixed_point_context(code: &CodeUnit, instr_idx: usize) -> bool {
    // Check for common fixed-point math patterns
    let start = instr_idx.saturating_sub(5);
    let end = std::cmp::min(instr_idx + 5, code.code.len());
    
    for i in start..end {
        if let Bytecode::Call(idx) = &code.code[i] {
            // Check if it's a call to fixed-point math functions
            // In real implementation, we'd need to look up the function name
            // For now, we'll use a heuristic approach
        }
        
        // Look for patterns that suggest fixed-point math
        if let Bytecode::LdU64(value) = &code.code[i] {
            // Common scaling factors in fixed-point math
            if *value == 10000 || *value == 1000000 || *value == 1000000000 {
                return true;
            }
        }
    }
    
    false
}

// ========== 3. INTEGER UNDERFLOW SUB ==========
pub struct IntegerUnderflowSubDetector;

#[async_trait::async_trait]
impl SecurityDetector for IntegerUnderflowSubDetector {
    fn id(&self) -> &'static str { "ARITH-003" }
    fn name(&self) -> &'static str { "Integer Underflow Sub" }
    fn description(&self) -> &'static str { "Detects unchecked subtraction that may underflow in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Sub) {
                        // Skip if this is in a safe fee calculation context
                        if is_in_safe_fee_calculation_context(code, i, ctx, func_def) {
                            continue;
                        }
                        
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
                                severity: Severity::High, // High for financial functions
                                confidence: Confidence::Medium, // Medium in financial context
                                title: "Subtraction may underflow in financial function".to_string(),
                                description: "Subtraction without explicit underflow handling in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Verify that inputs are properly constrained to prevent underflow in financial functions".to_string(),
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

// Helper function to detect if subtraction is in a safe fee calculation context
fn is_in_safe_fee_calculation_context(
    code: &CodeUnit, 
    instr_idx: usize, 
    ctx: &DetectionContext, 
    func_def: &FunctionDefinition
) -> bool {
    // Get function name
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    let func_name_lower = func_name.as_str().to_lowercase();
    
    // Check if function name suggests safe fee calculation
    if func_name_lower.contains("calculate_fee") || 
       func_name_lower.contains("fee") {
        // Check if the subtraction is of the form: amount - fee1 - fee2 - fee3
        // where fees are calculated as amount * rate / basis_points
        let mut sub_count = 0;
        let mut const_divisor = 0;
        
        for instr in &code.code {
            if let Bytecode::Div = instr {
                if instr_idx > 0 {
                    if let Bytecode::LdU64(val) = &code.code[instr_idx.saturating_sub(1)] {
                        // Check if divisor is a constant like BASIS_POINTS
                        if *val == 10000 || *val == 100 {  // Common basis point values
                            const_divisor = *val;
                        }
                    }
                }
            } else if let Bytecode::Sub = instr {
                sub_count += 1;
            }
        }
        
        // If this looks like a fee calculation with constant divisor, it's likely safe
        if const_divisor != 0 && sub_count <= 3 {
            return true;
        }
    }
    
    false
}

// ========== 4-20: Remaining Arithmetic Detectors ==========

pub struct IntegerUnderflowDecDetector;
#[async_trait::async_trait]
impl SecurityDetector for IntegerUnderflowDecDetector {
    fn id(&self) -> &'static str { "ARITH-004" }
    fn name(&self) -> &'static str { "Integer Underflow Dec" }
    fn description(&self) -> &'static str { "Detects decrement operations that may underflow in financial functions" }
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
                    if let Bytecode::Sub = instr {
                        // Check if subtracting 1 (common decrement pattern)
                        if i > 0 && matches!(code.code.get(i-1), Some(Bytecode::LdU64(1) | Bytecode::LdU8(1))) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: Severity::High, confidence: Confidence::Medium,
                                title: "Potential decrement underflow in financial function".to_string(),
                                description: "Decrement operation may underflow at zero in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Check value is greater than zero before decrementing in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects division operations without zero checks in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Div) {
                        // Skip if this is division by compile-time constants that are never zero
                        if is_division_by_nonzero_constant(code, i) {
                            continue;
                        }
                        
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
                                id: self.id().to_string(), 
                                severity: Severity::High, // High for financial functions
                                confidence: Confidence::Medium, // Medium in financial context
                                title: "Division without explicit zero check in financial function".to_string(),
                                description: "Division by variable without explicit zero check in financial function (Move will panic if divisor is zero)".to_string(),
                                location: create_loc(ctx, idx, i as u16), 
                                source_code: None,
                                recommendation: "Ensure divisor is not zero before division in financial functions".to_string(),
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

// Helper function to detect if division is by compile-time constants that are never zero
fn is_division_by_nonzero_constant(code: &CodeUnit, instr_idx: usize) -> bool {
    if instr_idx == 0 {
        return false;
    }
    
    // Look for constants loaded right before the division
    if let Bytecode::LdU64(const_val) = code.code[instr_idx - 1] {
        // Common compile-time constants that are never zero in financial contexts
        if const_val == 10000 || const_val == 100 || const_val == 30 || const_val == 10 {  // BASIS_POINTS, TOTAL_FEE, etc.
            return true;
        }
    } else if let Bytecode::LdU32(const_val) = code.code[instr_idx - 1] {
        if const_val == 10000 || const_val == 100 || const_val == 30 || const_val == 10 {
            return true;
        }
    }
    
    false
}

pub struct ModuloByZeroDetector;
#[async_trait::async_trait]
impl SecurityDetector for ModuloByZeroDetector {
    fn id(&self) -> &'static str { "ARITH-006" }
    fn name(&self) -> &'static str { "Modulo By Zero" }
    fn description(&self) -> &'static str { "Detects modulo operations without zero checks in financial functions" }
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
                    if matches!(instr, Bytecode::Mod) {
                        let has_check = code.code.iter()
                            .skip(i.saturating_sub(5))
                            .take(10)
                            .any(|b| matches!(b, Bytecode::Neq | Bytecode::Gt));
                        
                        if !has_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: Severity::High, confidence: Confidence::High,
                                title: "Modulo without zero check in financial function".to_string(),
                                description: "Modulo operation may panic if divisor is zero in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Ensure modulo divisor is not zero in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects operations that may lose precision in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                // Look for divide then multiply pattern (precision loss)
                for i in 0..code.code.len().saturating_sub(2) {
                    if matches!(code.code[i], Bytecode::Div) {
                        if matches!(code.code.get(i+1).or(code.code.get(i+2)), Some(Bytecode::Mul)) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: Severity::High, confidence: Confidence::High,
                                title: "Precision loss in arithmetic in financial function".to_string(),
                                description: "Division before multiplication causes precision loss in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Multiply before dividing to preserve precision in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects potential rounding errors in financial calculations" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let div_count = code.code.iter().filter(|i| matches!(i, Bytecode::Div)).count();
                if div_count > 3 { // Reduced threshold for financial functions
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: Severity::High, confidence: Confidence::Medium,
                        title: "Multiple divisions may accumulate rounding errors in financial function".to_string(),
                        description: format!("{} division operations detected in financial function", div_count),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Use higher precision or reorder operations in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects type casts without range validation in financial functions" }
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
                    if matches!(instr, Bytecode::CastU8 | Bytecode::CastU64 | Bytecode::CastU128) {
                        let has_range_check = code.code.iter()
                            .skip(i.saturating_sub(3))
                            .take(6)
                            .any(|b| matches!(b, Bytecode::Lt | Bytecode::Le));
                        
                        if !has_range_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: Severity::High, confidence: Confidence::High,
                                title: "Unchecked type cast in financial function".to_string(),
                                description: "Cast may truncate or overflow without validation in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Add range checks before casting to smaller types in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects operations exceeding type limits in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                // Check for u8 operations without bounds
                let has_u8_ops = code.code.iter().any(|i| matches!(i, Bytecode::CastU8 | Bytecode::LdU8(_)));
                let has_arithmetic = code.code.iter().any(|i| matches!(i, Bytecode::Add | Bytecode::Mul));
                
                if has_u8_ops && has_arithmetic {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: Severity::High, confidence: Confidence::Medium,
                        title: "u8 arithmetic may overflow in financial function".to_string(),
                        description: "Operations on small types without overflow protection in financial function".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Use wider types or add overflow checks in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects missing boundary condition checks in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::VecImmBorrow(_) | Bytecode::VecMutBorrow(_)) {
                        let has_bounds = code.code.iter()
                            .skip(i.saturating_sub(3))
                            .take(6)
                            .any(|b| matches!(b, Bytecode::VecLen(_) | Bytecode::Lt));
                        
                        if !has_bounds {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: Severity::High, confidence: Confidence::Medium,
                                title: "Vector access without bounds check in financial function".to_string(),
                                description: "Array/vector indexing may be out of bounds in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Validate index is within bounds before access in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects potential off-by-one errors in loops in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                // Look for <= with length (should often be <)
                for i in 0..code.code.len().saturating_sub(2) {
                    if matches!(code.code[i], Bytecode::VecLen(_)) {
                        if matches!(code.code.get(i+1).or(code.code.get(i+2)), Some(Bytecode::Le)) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: Severity::High, confidence: Confidence::Medium,
                                title: "Potential off-by-one error in financial function".to_string(),
                                description: "Using <= with length may cause off-by-one in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Use < for length comparisons, not <= in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects inverted logic conditions in financial functions" }
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
                    if matches!(instr, Bytecode::Not) {
                        let near_branch = code.code.iter()
                            .skip(i)
                            .take(3)
                            .any(|b| matches!(b, Bytecode::BrTrue(_) | Bytecode::BrFalse(_)));
                        
                        if near_branch {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: Severity::High, confidence: Confidence::Medium,
                                title: "Logic inversion before branch in financial function".to_string(),
                                description: "NOT operation before branch may indicate inverted logic in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Verify boolean logic is correct in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects conditions that may be bypassed in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                // Look for Or operations that might allow bypass
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::Or) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: Severity::High, confidence: Confidence::High,
                            title: "OR condition may allow bypass in financial function".to_string(),
                            description: "Logical OR in security check may be exploitable in financial function".to_string(),
                            location: create_loc(ctx, idx, i as u16), source_code: None,
                            recommendation: "Review OR conditions in authorization checks in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects potential infinite loops in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
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
                                    id: self.id().to_string(), severity: Severity::Critical, confidence: Confidence::High,
                                    title: "Potential infinite loop in financial function".to_string(),
                                    description: "Loop without apparent termination condition in financial function".to_string(),
                                    location: create_loc(ctx, idx, i as u16), source_code: None,
                                    recommendation: "Ensure loop has proper termination condition in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects iterations without upper bounds in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let has_loop = code.code.iter().any(|i| {
                    matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_))
                });
                
                let has_bound = code.code.iter().any(|i| {
                    matches!(i, Bytecode::Lt | Bytecode::Le)
                });
                
                if has_loop && !has_bound {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: Severity::High, confidence: Confidence::High,
                        title: "Loop without upper bound in financial function".to_string(),
                        description: "Iteration may run indefinitely in financial function".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Add maximum iteration limit in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects early returns that skip security checks in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                let return_count = code.code.iter().filter(|i| matches!(i, Bytecode::Ret)).count();
                
                if return_count > 3 { // Lowered threshold for financial functions
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: Severity::High, confidence: Confidence::Medium,
                        title: "High number of return points in financial function".to_string(),
                        description: format!("{} return statements may make code harder to audit in financial function", return_count),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Consider consolidating returns for better readability in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects delayed exits that allow state changes in financial functions" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
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
                                id: self.id().to_string(), severity: Severity::High, confidence: Confidence::High,
                                title: "State change before abort in financial function".to_string(),
                                description: "State modified before error abort in financial function".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Check conditions before state changes in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects operations causing inconsistent state in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
                // Multiple state writes without validation
                let state_writes = code.code.iter().filter(|i| {
                    matches!(i, Bytecode::MoveTo(_) | Bytecode::WriteRef)
                }).count();
                
                if state_writes > 1 { // Lowered threshold for financial functions
                    let has_validation = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Abort | Bytecode::BrTrue(_))
                    });
                    
                    if !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: Severity::High, confidence: Confidence::High,
                            title: "Multiple state changes without validation in financial function".to_string(),
                            description: format!("{} state modifications without checks in financial function", state_writes),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Add validation between state changes in financial functions".to_string(),
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
    fn description(&self) -> &'static str { "Detects precision loss (division) that accumulates inside loops in financial functions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Only check financial functions
                if !is_financial_function(ctx, func_def) {
                    continue;
                }
                
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
                                confidence: Confidence::High,
                                title: "Precision loss accumulation in loop in financial function".to_string(),
                                description: "Division operation inside a loop may cause significant cumulative precision loss in financial function (dust extraction risk).".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Avoid division inside loops in financial functions. Perform division after the loop or use higher precision types.".to_string(),
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
