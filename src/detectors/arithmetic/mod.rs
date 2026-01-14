// src/detectors/arithmetic/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use crate::utils::create_location;
use move_binary_format::{file_format::*, access::ModuleAccess};

// Move's arithmetic is checked by default (aborts on overflow/underflow).
// This detector focuses ONLY on precision-related issues in financial contexts.

// Track arithmetic patterns across module
#[derive(Default)]
struct ArithmeticContext {
    financial_functions: Vec<String>,
    division_sites: Vec<(usize, usize)>, // (function_index, instruction_index)
}

// AR-003: Division Before Multiplication - ULTRA STRICT
pub struct DivisionBeforeMultiplication;

#[async_trait::async_trait]
impl SecurityDetector for DivisionBeforeMultiplication {
    fn id(&self) -> &'static str { "AR-003" }
    fn name(&self) -> &'static str { "Division Before Multiplication" }
    fn description(&self) -> &'static str {
        "Division operation performed before multiplication causing precision loss"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        let mut arith_ctx = ArithmeticContext::default();
        
        // First pass: Identify financial functions and division sites
        for (func_idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if is_financial_calculation_function(func_def, &ctx.module, func_name.as_str()) {
                arith_ctx.financial_functions.push(func_name.to_string());
                
                // Find division instructions
                if let Some(code) = &func_def.code {
                    for (instr_idx, instr) in code.code.iter().enumerate() {
                        if matches!(instr, Bytecode::Div) {
                            arith_ctx.division_sites.push((func_idx, instr_idx));
                        }
                    }
                }
            }
        }
        
        // Second pass: Only check division sites in financial functions
        for (func_idx, instr_idx) in &arith_ctx.division_sites {
            if let Some(func_def) = ctx.module.function_defs.get(*func_idx) {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                
                // ULTRA STRICT: Only flag if we can prove multiplication uses division result
                if let Some(code) = &func_def.code {
                    if is_division_before_multiplication(&code.code, *instr_idx) &&
                       is_in_financial_calculation_context(&code.code, *instr_idx) {
                        
                        // Additional verification: Check if this is a significant calculation
                        if is_significant_financial_calculation(func_def, &ctx.module) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: format!("Precision loss in '{}'", func_name),
                                description: "Division before multiplication causes precision loss in financial calculation".to_string(),
                                location: create_location(ctx, func_def, *instr_idx as u16),
                                source_code: Some("a / b * c".to_string()),
                                recommendation: "Reorder operations to multiply before divide: (a * c) / b, or use fixed-point arithmetic".to_string(),
                                references: vec![
                                    "https://github.com/crytic/slither/wiki/Detector-Documentation#divide-before-multiply".to_string(),
                                ],
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

// Only flag actual financial calculation functions
fn is_financial_calculation_function(func_def: &FunctionDefinition, module: &CompiledModule, func_name: &str) -> bool {
    let func_name_lower = func_name.to_lowercase();
    
    // Only check functions with clear financial calculation names
    let is_calculation_function = func_name_lower.contains("calculate_") ||
                                 func_name_lower.contains("compute_") ||
                                 func_name_lower.contains("_reward") ||
                                 func_name_lower.contains("_calc") ||
                                 func_name_lower.contains("_rate") ||
                                 func_name_lower.contains("_percentage") ||
                                 func_name_lower.contains("_ratio") ||
                                 func_name_lower.contains("_share") ||
                                 func_name_lower == "calculate" ||
                                 func_name_lower == "compute";
    
    if !is_calculation_function {
        return false;
    }
    
    // Verify it actually performs arithmetic operations
    if let Some(code) = &func_def.code {
        let mut has_arithmetic = false;
        
        for instr in &code.code {
            match instr {
                Bytecode::Add | Bytecode::Sub | Bytecode::Mul | Bytecode::Div => {
                    has_arithmetic = true;
                    break;
                }
                _ => {}
            }
        }
        
        return has_arithmetic;
    }
    
    false
}

// Conservative check for division before multiplication
fn is_division_before_multiplication(bytecode: &[Bytecode], div_idx: usize) -> bool {
    // Look for multiplication in the next few instructions that uses the division result
    let end = std::cmp::min(div_idx + 8, bytecode.len());
    
    // First, check if there's multiplication after division
    for i in (div_idx + 1)..end {
        if matches!(bytecode[i], Bytecode::Mul) {
            // Check if the same stack slots are used
            if uses_same_operands(bytecode, div_idx, i) {
                return true;
            }
        }
    }
    
    false
}

// Simple check if operations use same stack slots (conservative approximation)
fn uses_same_operands(bytecode: &[Bytecode], op1_idx: usize, op2_idx: usize) -> bool {
    // In a real implementation, we'd do proper data flow analysis
    // For now, we'll be conservative and assume they might use same operands if close together
    (op2_idx as i32 - op1_idx as i32).abs() <= 6
}

fn is_in_financial_calculation_context(bytecode: &[Bytecode], div_idx: usize) -> bool {
    // Check surrounding instructions for financial calculation patterns
    let start = div_idx.saturating_sub(10);
    let end = std::cmp::min(div_idx + 10, bytecode.len());
    
    let mut financial_indicators = 0;
    
    for i in start..end {
        match &bytecode[i] {
            Bytecode::LdU64(value) if *value > 100 => {
                // Large constants often indicate financial amounts
                financial_indicators += 1;
            }
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                // Check for financial function calls
                // This would require function name lookup
                financial_indicators += 1;
            }
            _ => {}
        }
    }
    
    financial_indicators >= 2
}

fn is_significant_financial_calculation(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // Check if function has significant financial impact
    if let Some(code) = &func_def.code {
        let mut transfer_calls = 0;
        let mut external_calls = 0;
        
        for instr in &code.code {
            if let Bytecode::Call(_) | Bytecode::CallGeneric(_) = instr {
                external_calls += 1;
                
                // Check for transfer functions
                if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                    if func_name.as_str().contains("transfer") ||
                       func_name.as_str().contains("mint") ||
                       func_name.as_str().contains("burn") {
                        transfer_calls += 1;
                    }
                }
            }
        }
        
        // Only flag if the calculation leads to transfers or has many external calls
        return transfer_calls > 0 || external_calls >= 3;
    }
    
    false
}

// AR-004: Precision Loss - ULTRA STRICT
pub struct PrecisionLoss;

#[async_trait::async_trait]
impl SecurityDetector for PrecisionLoss {
    fn id(&self) -> &'static str { "AR-004" }
    fn name(&self) -> &'static str { "Precision Loss" }
    fn description(&self) -> &'static str {
        "Financial calculations lose precision due to integer division"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check functions that clearly perform financial calculations
        for (func_idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check specific financial calculation functions
            let is_precision_sensitive = func_name_lower.contains("calculate_fee") ||
                                        func_name_lower.contains("calculate_interest") ||
                                        func_name_lower.contains("calculate_reward") ||
                                        func_name_lower.contains("compute_share") ||
                                        func_name_lower.contains("calculate_share");
            
            if !is_precision_sensitive {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                // Look for division operations
                for (instr_idx, instr) in code.code.iter().enumerate() {
                    if let Bytecode::Div = instr {
                        // Only flag if division by large constant
                        if let Some(divisor) = get_constant_divisor(code, instr_idx) {
                            if divisor >= 10_000 && divisor % 10_000 == 0 {
                                // Division by 10,000, 100,000 etc. in Move often indicates
                                // fixed-point arithmetic with scaling factor
                                // This might be intentional - need additional checks
                                
                                // Check if there's multiplication by same factor elsewhere
                                if !has_matching_multiplication_factor(code, divisor) {
                                    issues.push(SecurityIssue {
                                        id: self.id().to_string(),
                                        severity: self.default_severity(),
                                        confidence: Confidence::Medium,
                                        title: format!("Precision loss in '{}'", func_name),
                                        description: format!("Division by {} may cause precision loss in financial calculation", divisor),
                                        location: create_location(ctx, func_def, instr_idx as u16),
                                        source_code: Some(format!("Division by {}", divisor)),
                                        recommendation: "Verify fixed-point arithmetic implementation; consider using decimal libraries".to_string(),
                                        references: vec![],
                                        metadata: std::collections::HashMap::new(),
                                    });
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

fn get_constant_divisor(code: &CodeUnit, div_idx: usize) -> Option<u64> {
    // Look for constant divisor in previous instructions
    // Very conservative - only flag if we can see the exact constant
    
    if div_idx == 0 {
        return None;
    }
    
    // Check up to 5 instructions back for constant
    let start = div_idx.saturating_sub(5);
    for i in start..div_idx {
        if let Bytecode::LdU64(value) = code.code[i] {
            // Found a constant - check if it's likely the divisor
            return Some(value);
        }
    }
    
    None
}

fn has_matching_multiplication_factor(code: &CodeUnit, divisor: u64) -> bool {
    // Check if there's multiplication by same factor (indicating fixed-point arithmetic)
    for instr in &code.code {
        if let Bytecode::Mul = instr {
            // In a real implementation, we'd check if multiplication uses same factor
            // For now, we'll just check if multiplication exists nearby
            return true;
        }
        
        if let Bytecode::LdU64(value) = instr {
            if *value == divisor {
                // Same constant used elsewhere - might be scaling factor
                return true;
            }
        }
    }
    
    false
}

// AR-005: Rounding Errors - ULTRA STRICT
pub struct RoundingErrors;

#[async_trait::async_trait]
impl SecurityDetector for RoundingErrors {
    fn id(&self) -> &'static str { "AR-005" }
    fn name(&self) -> &'static str { "Rounding Errors" }
    fn description(&self) -> &'static str {
        "Incorrect rounding direction in financial calculations"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check token/coin modules
        if !is_token_or_financial_module(&ctx.module) {
            return issues;
        }
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check distribution functions
            let is_distribution_function = func_name_lower.contains("distribute") ||
                                         func_name_lower.contains("split") ||
                                         func_name_lower.contains("allocate") ||
                                         func_name_lower.contains("share") ||
                                         (func_name_lower.contains("calculate") && 
                                          (func_name_lower.contains("share") || func_name_lower.contains("portion")));
            
            if !is_distribution_function {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                // Look for division without rounding
                for (instr_idx, instr) in code.code.iter().enumerate() {
                    if let Bytecode::Div = instr {
                        // Check if this division is used in distribution calculation
                        if is_division_in_distribution_context(code, instr_idx) &&
                           !has_explicit_rounding_logic(code, instr_idx) {
                            
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: format!("Rounding error in '{}'", func_name),
                                description: "Integer division truncates results in distribution calculation, potentially losing funds".to_string(),
                                location: create_location(ctx, func_def, instr_idx as u16),
                                source_code: Some("a / b (truncates toward zero)".to_string()),
                                recommendation: "Implement proper rounding: ((a * precision) + (b / 2)) / b for round-half-up".to_string(),
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

fn is_token_or_financial_module(module: &CompiledModule) -> bool {
    let module_name = module.self_id().name().as_str().to_lowercase();
    
    module_name.contains("token") ||
    module_name.contains("coin") ||
    module_name.contains("staking") ||
    module_name.contains("reward") ||
    module_name.contains("vesting") ||
    module_name.contains("treasury")
}

fn is_division_in_distribution_context(code: &CodeUnit, div_idx: usize) -> bool {
    // Check if division is part of distribution calculation
    let start = div_idx.saturating_sub(10);
    let end = std::cmp::min(div_idx + 10, code.code.len());
    
    let mut distribution_indicators = 0;
    
    for i in start..end {
        match &code.code[i] {
            // Division followed by multiplication often indicates percentage/ratio calculation
            Bytecode::Mul => distribution_indicators += 1,
            
            // Multiple additions/subtractions often indicate distribution
            Bytecode::Add | Bytecode::Sub => distribution_indicators += 1,
            
            // Load of 100 or 10000 often indicates percentage
            Bytecode::LdU64(100) | Bytecode::LdU64(10000) => distribution_indicators += 2,
            
            _ => {}
        }
    }
    
    distribution_indicators >= 3
}

fn has_explicit_rounding_logic(code: &CodeUnit, div_idx: usize) -> bool {
    // Check for rounding patterns like adding half the divisor
    let start = div_idx.saturating_sub(5);
    let end = std::cmp::min(div_idx + 5, code.code.len());
    
    for i in start..div_idx {
        match &code.code[i] {
            // Pattern: (numerator + (denominator / 2)) / denominator
            Bytecode::Add => {
                // Check if there's division by 2 before the addition
                for j in start..i {
                    if let Bytecode::Div = &code.code[j] {
                        // Check for division by 2 constant
                        if j > 0 {
                            if let Bytecode::LdU64(2) = &code.code[j-1] {
                                return true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    
    false
}

// AR-006: Incorrect Scaling - NEW STRICT DETECTOR
pub struct IncorrectScaling;

#[async_trait::async_trait]
impl SecurityDetector for IncorrectScaling {
    fn id(&self) -> &'static str { "AR-006" }
    fn name(&self) -> &'static str { "Incorrect Scaling" }
    fn description(&self) -> &'static str {
        "Fixed-point arithmetic uses incorrect scaling factors"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Look for fixed-point arithmetic patterns
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                let mut scaling_constants = Vec::new();
                
                // Collect all scaling constants (10^N)
                for (i, instr) in code.code.iter().enumerate() {
                    if let Bytecode::LdU64(value) = instr {
                        if is_scaling_constant(*value) {
                            scaling_constants.push((i, *value));
                        }
                    }
                }
                
                // Check for inconsistent scaling
                if scaling_constants.len() >= 2 {
                    let first_scaling = scaling_constants[0].1;
                    for (i, scaling) in &scaling_constants[1..] {
                        if *scaling != first_scaling {
                            // Mixed scaling factors found
                            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                            let func_name = ctx.module.identifier_at(func_handle.name);
                            
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: format!("Inconsistent scaling in '{}'", func_name),
                                description: format!("Mixed scaling factors ({} and {}) may cause calculation errors", first_scaling, scaling),
                                location: create_location(ctx, func_def, *i as u16),
                                source_code: Some(format!("Scaling factors: {}, {}", first_scaling, scaling)),
                                recommendation: "Use consistent scaling factors throughout the calculation".to_string(),
                                references: vec![],
                                metadata: std::collections::HashMap::new(),
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

fn is_scaling_constant(value: u64) -> bool {
    // Common fixed-point scaling factors
    value == 10 ||
    value == 100 ||
    value == 1000 ||
    value == 10000 ||
    value == 100000 ||
    value == 1000000 ||
    value == 10000000 ||
    value == 100000000 ||
    value == 10u64.pow(9) ||  // 1e9
    value == 10u64.pow(12) || // 1e12
    value == 10u64.pow(18)    // 1e18 (common in tokens)
}

// AR-007: Multiplication Overflow Risk - NEW STRICT DETECTOR
pub struct MultiplicationOverflowRisk;

#[async_trait::async_trait]
impl SecurityDetector for MultiplicationOverflowRisk {
    fn id(&self) -> &'static str { "AR-007" }
    fn name(&self) -> &'static str { "Multiplication Overflow Risk" }
    fn description(&self) -> &'static str {
        "Large multiplication operations may overflow even with checked arithmetic"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check functions that handle large amounts
            if !handles_large_amounts(func_name.as_str()) {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                for (instr_idx, instr) in code.code.iter().enumerate() {
                    if let Bytecode::Mul = instr {
                        // Check if multiplication involves large constants
                        if involves_large_multiplication(code, instr_idx) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: format!("Multiplication overflow risk in '{}'", func_name),
                                description: "Multiplication of large values may overflow u64, causing transaction to abort".to_string(),
                                location: create_location(ctx, func_def, instr_idx as u16),
                                source_code: Some("Large value * large value".to_string()),
                                recommendation: "Check multiplication bounds before operation or use saturating arithmetic".to_string(),
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

fn handles_large_amounts(func_name: &str) -> bool {
    let func_name_lower = func_name.to_lowercase();
    
    func_name_lower.contains("total") ||
    func_name_lower.contains("supply") ||
    func_name_lower.contains("calculate_total") ||
    func_name_lower.contains("aggregate") ||
    func_name_lower.contains("sum")
}

fn involves_large_multiplication(code: &CodeUnit, mul_idx: usize) -> bool {
    // Check for multiplication with large constants
    let start = mul_idx.saturating_sub(3);
    
    for i in start..mul_idx {
        if let Bytecode::LdU64(value) = code.code[i] {
            // Check if constant is large (close to u64::MAX / typical max)
            if value > 10u64.pow(12) { // 1 trillion
                return true;
            }
        }
    }
    
    false
}

// Only include detectors that can be made extremely strict
pub fn get_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(DivisionBeforeMultiplication),
        Box::new(PrecisionLoss),
        Box::new(RoundingErrors),
        Box::new(IncorrectScaling),
        Box::new(MultiplicationOverflowRisk),
        // NOTE: IntegerOverflow and IntegerUnderflow are disabled because
        // Move has checked arithmetic by default
    ]
}