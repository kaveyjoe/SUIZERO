// src/detectors/oracles/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use crate::utils::{create_location, create_module_location};
use move_binary_format::{file_format::*, access::ModuleAccess};
use std::collections::{HashMap, HashSet};

// ULTRA STRICT: Determine if this is an oracle-dependent module
fn is_oracle_dependent_module(module: &CompiledModule) -> bool {
    // Check for explicit oracle module dependencies
    let has_oracle_module = module.module_handles.iter().any(|handle| {
        let module_name = module.identifier_at(handle.name).as_str().to_lowercase();
        module_name.contains("oracle") ||
        module_name.contains("price") ||
        module_name.contains("pyth") ||
        module_name.contains("chainlink")
    });
    
    if !has_oracle_module {
        return false;
    }
    
    // Check for oracle-related structs
    let has_oracle_structs = module.struct_defs.iter().any(|struct_def| {
        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
        let struct_name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
        struct_name.contains("price") ||
        struct_name.contains("oracle") ||
        struct_name.contains("feed")
    });
    
    // Check for actual oracle calls in functions
    let oracle_call_count = module.function_defs.iter()
        .filter(|func_def| has_oracle_calls(func_def, module))
        .count();
    
    has_oracle_module && (has_oracle_structs || oracle_call_count >= 2)
}

fn has_oracle_calls(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if is_explicit_oracle_call(instr, module) {
                return true;
            }
        }
    }
    false
}

fn is_explicit_oracle_call(instr: &Bytecode, module: &CompiledModule) -> bool {
    if let Some(func_name) = crate::utils::get_function_name(instr, module) {
        let func_name_lower = func_name.as_str().to_lowercase();
        
        // Strict: Only count explicit oracle functions
        func_name_lower.contains("oracle::get_price") ||
        func_name_lower.contains("price_feed::get_price") ||
        func_name_lower.contains("pyth::get_price") ||
        func_name_lower.contains("chainlink::latest_answer")
    } else {
        false
    }
}

// OR-001: Flash Loan Vulnerability - ULTRA STRICT
pub struct FlashLoanVulnerability;

#[async_trait::async_trait]
impl SecurityDetector for FlashLoanVulnerability {
    fn id(&self) -> &'static str { "OR-001" }
    fn name(&self) -> &'static str { "Flash Loan Vulnerability" }
    fn description(&self) -> &'static str {
        "Protocol vulnerable to flash loan attacks through price manipulation"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_oracle_dependent_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Find price oracle usage patterns
        let oracle_usage = find_oracle_usage_strict(&ctx.module);
        
        for (func_idx, oracle_calls) in oracle_usage {
            let func_def = &ctx.module.function_defs[func_idx];
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check critical financial operations
            let is_critical_operation = func_name_lower.contains("liquidate") ||
                                       func_name_lower.contains("swap_exact") ||
                                       func_name_lower.contains("borrow") ||
                                       func_name_lower.contains("mint");
            
            if is_critical_operation {
                // Check for flash loan protections with strict criteria
                let protection_score = calculate_flash_loan_protection_score(func_def, &ctx.module);
                
                if protection_score < 3 { // Require strong protections
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if protection_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Flash loan vulnerability in '{}'", func_name),
                        description: "Critical financial operation uses oracle price without adequate flash loan protection".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement TWAPs, price deviation limits, or circuit breakers for oracle-dependent operations".to_string(),
                        references: vec![
                            "https://blog.openzeppelin.com/exploiting-math-in-smart-contracts-flash-loans-and-manipulation/".to_string(),
                            "CWE-682: Incorrect Calculation".to_string(),
                        ],
                        metadata: {
                            let mut map = HashMap::new();
                            map.insert("protection_score".to_string(), protection_score.to_string());
                            map.insert("oracle_calls".to_string(), oracle_calls.len().to_string());
                            map
                        },
                    });
                }
            }
        }
        
        issues
    }
}

fn find_oracle_usage_strict(module: &CompiledModule) -> HashMap<usize, Vec<usize>> {
    let mut usage = HashMap::new();
    
    for (func_idx, func_def) in module.function_defs.iter().enumerate() {
        if let Some(code) = &func_def.code {
            let oracle_calls: Vec<usize> = code.code.iter()
                .enumerate()
                .filter(|(_, instr)| is_explicit_oracle_call(instr, module))
                .map(|(i, _)| i)
                .collect();
            
            if !oracle_calls.is_empty() {
                usage.insert(func_idx, oracle_calls);
            }
        }
    }
    
    usage
}

fn calculate_flash_loan_protection_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("twap") { score += 3; }
                if func_name_lower.contains("time_weighted") { score += 3; }
                if func_name_lower.contains("price_deviation") { score += 2; }
                if func_name_lower.contains("max_price_change") { score += 2; }
                if func_name_lower.contains("circuit_breaker") { score += 3; }
                if func_name_lower.contains("emergency_pause") { score += 2; }
            }
        }
    }
    
    score
}

// OR-002: Single Source Oracle - ULTRA STRICT
pub struct SingleSourceOracle;

#[async_trait::async_trait]
impl SecurityDetector for SingleSourceOracle {
    fn id(&self) -> &'static str { "OR-002" }
    fn name(&self) -> &'static str { "Single Source Oracle" }
    fn description(&self) -> &'static str {
        "Relies on single oracle source without fallbacks"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_oracle_dependent_module(&ctx.module) { return Vec::new(); }
        
        // Find all distinct oracle sources
        let oracle_sources = find_oracle_sources_strict(&ctx.module);
        
        // Only flag if there's exactly one oracle source AND it's used for critical operations
        if oracle_sources.len() == 1 && has_critical_oracle_usage(&ctx.module) {
            let oracle_source = oracle_sources.iter().next().unwrap();
            
            return vec![SecurityIssue {
                id: self.id().to_string(),
                severity: self.default_severity(),
                confidence: Confidence::High,
                title: "Single source oracle dependency".to_string(),
                description: format!("Contract relies exclusively on '{}' without redundancy", oracle_source),
                location: create_module_location(ctx),
                source_code: None,
                recommendation: "Use multiple oracle sources, implement fallback mechanisms, or use decentralized oracle networks".to_string(),
                references: vec![
                    "https://consensys.github.io/smart-contract-best-practices/development-recommendations/oracles/".to_string(),
                ],
                metadata: {
                    let mut map = HashMap::new();
                    map.insert("oracle_source".to_string(), oracle_source.clone());
                    map
                },
            }];
        }
        
        Vec::new()
    }
}

fn find_oracle_sources_strict(module: &CompiledModule) -> HashSet<String> {
    let mut sources = HashSet::new();
    
    for func_def in &module.function_defs {
        if let Some(code) = &func_def.code {
            for instr in &code.code {
                if let Bytecode::Call(func_idx) = instr {
                    if let Some(func_handle) = module.function_handles.get(func_idx.0 as usize) {
                        if let Some(module_handle) = module.module_handles.get(func_handle.module.0 as usize) {
                            let module_name = module.identifier_at(module_handle.name).to_string();
                            
                            // Only count explicit oracle modules
                            let module_name_lower = module_name.to_lowercase();
                            if module_name_lower.contains("oracle") ||
                               module_name_lower.contains("pyth") ||
                               module_name_lower.contains("chainlink") ||
                               module_name_lower.contains("price") {
                                sources.insert(module_name);
                            }
                        }
                    }
                }
            }
        }
    }
    
    sources
}

fn has_critical_oracle_usage(module: &CompiledModule) -> bool {
    // Check if oracle is used in critical operations
    for func_def in &module.function_defs {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        
        let is_critical_function = func_name.contains("liquidate") ||
                                  func_name.contains("swap") ||
                                  func_name.contains("mint") ||
                                  func_name.contains("burn");
        
        if is_critical_function && has_oracle_calls(func_def, module) {
            return true;
        }
    }
    
    false
}

// OR-003: No Price Validation - ULTRA STRICT
pub struct NoPriceValidation;

#[async_trait::async_trait]
impl SecurityDetector for NoPriceValidation {
    fn id(&self) -> &'static str { "OR-003" }
    fn name(&self) -> &'static str { "No Price Validation" }
    fn description(&self) -> &'static str {
        "Oracle prices used without validation checks"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_oracle_dependent_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // Only check functions that use oracle for financial operations
            let is_financial_oracle_function = (func_name_lower.contains("liquidate") ||
                                               func_name_lower.contains("swap") ||
                                               func_name_lower.contains("calculate")) &&
                                               has_oracle_calls(func_def, &ctx.module);
            
            if is_financial_oracle_function {
                if let Some(code) = &func_def.code {
                    // Find oracle reads
                    let oracle_reads: Vec<usize> = code.code.iter()
                        .enumerate()
                        .filter(|(_, instr)| is_explicit_oracle_call(instr, &ctx.module))
                        .map(|(i, _)| i)
                        .collect();
                    
                    for read_idx in oracle_reads {
                        // Check for validation with strict criteria
                        let validation_score = calculate_price_validation_score(&code.code, read_idx, &ctx.module);
                        
                        if validation_score < 2 { // Require at least some validation
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: if validation_score == 0 { Confidence::High } else { Confidence::Medium },
                                title: format!("Unvalidated oracle price in '{}'", func_name),
                                description: "Oracle price used without validation for staleness or deviation".to_string(),
                                location: create_location(ctx, func_def, read_idx as u16),
                                source_code: Some("oracle.get_price()".to_string()),
                                recommendation: "Validate oracle prices: check timestamp, min/max bounds, deviation from previous values".to_string(),
                                references: vec![
                                    "CWE-20: Improper Input Validation".to_string(),
                                ],
                                metadata: {
                                    let mut map = HashMap::new();
                                    map.insert("validation_score".to_string(), validation_score.to_string());
                                    map
                                },
                            });
                        }
                    }
                }
            }
        }
        
        issues
    }
}

fn calculate_price_validation_score(bytecode: &[Bytecode], oracle_idx: usize, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    // Check next 10 instructions for validation
    let start = oracle_idx + 1;
    let end = bytecode.len().min(oracle_idx + 11);
    
    for i in start..end {
        match &bytecode[i] {
            // Price bounds checking
            Bytecode::LdU64(value) => {
                // Check if this is used for min/max price bounds
                if i + 1 < end {
                    match &bytecode[i + 1] {
                        Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge => score += 2,
                        _ => {}
                    }
                }
            }
            
            // Timestamp/freshness checking
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                if let Some(func_name) = crate::utils::get_function_name(&bytecode[i], module) {
                    let func_name_lower = func_name.as_str().to_lowercase();
                    
                    if func_name_lower.contains("timestamp") { score += 2; }
                    if func_name_lower.contains("freshness") { score += 3; }
                    if func_name_lower.contains("validate_price") { score += 3; }
                    if func_name_lower.contains("check_price") { score += 2; }
                }
            }
            
            _ => {}
        }
    }
    
    score
}

// OR-004: Stale Price Usage - ULTRA STRICT
pub struct StalePriceUsage;

#[async_trait::async_trait]
impl SecurityDetector for StalePriceUsage {
    fn id(&self) -> &'static str { "OR-004" }
    fn name(&self) -> &'static str { "Stale Price Usage" }
    fn description(&self) -> &'static str {
        "Uses stale oracle prices without freshness checks"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_oracle_dependent_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Only check time-sensitive operations
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check highly time-sensitive operations
            let is_highly_time_sensitive = func_name_lower.contains("liquidate") ||
                                          (func_name_lower.contains("swap") && 
                                           (func_name_lower.contains("exact") || func_name_lower.contains("market")));
            
            if is_highly_time_sensitive {
                if let Some(code) = &func_def.code {
                    // Check for oracle calls without freshness checks
                    for (i, instr) in code.code.iter().enumerate() {
                        if is_explicit_oracle_call(instr, &ctx.module) {
                            // Check for timestamp validation
                            if !has_timestamp_validation(&code.code, i, &ctx.module) {
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(),
                                    severity: self.default_severity(),
                                    confidence: Confidence::High,
                                    title: format!("Stale price usage in '{}'", func_name),
                                    description: "Time-sensitive operation uses oracle price without freshness validation".to_string(),
                                    location: create_location(ctx, func_def, i as u16),
                                    source_code: Some("oracle.get_price()".to_string()),
                                    recommendation: "Check oracle price timestamp and reject stale prices (e.g., > 1 minute old for liquidations)".to_string(),
                                    references: vec![],
                                    metadata: HashMap::new(),
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

fn has_timestamp_validation(bytecode: &[Bytecode], oracle_idx: usize, module: &CompiledModule) -> bool {
    // Look for timestamp checking in next 15 instructions
    let start = oracle_idx + 1;
    let end = bytecode.len().min(oracle_idx + 16);
    
    for i in start..end {
        if let Some(func_name) = crate::utils::get_function_name(&bytecode[i], module) {
            let func_name_lower = func_name.as_str().to_lowercase();
            
            if func_name_lower.contains("timestamp") ||
               func_name_lower.contains("freshness") ||
               func_name_lower.contains("staleness") ||
               func_name_lower.contains("updated_at") {
                return true;
            }
        }
    }
    
    false
}

// OR-009: Incorrect Decimals - ULTRA STRICT
pub struct IncorrectDecimals;

#[async_trait::async_trait]
impl SecurityDetector for IncorrectDecimals {
    fn id(&self) -> &'static str { "OR-009" }
    fn name(&self) -> &'static str { "Incorrect Decimals" }
    fn description(&self) -> &'static str {
        "Incorrect decimal handling in price calculations"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_oracle_dependent_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Look for price scaling operations in oracle-dependent functions
        for func_def in &ctx.module.function_defs {
            if has_oracle_calls(func_def, &ctx.module) {
                if let Some(code) = &func_def.code {
                    for (i, instr) in code.code.iter().enumerate() {
                        if let Bytecode::LdU64(scale) = instr {
                            // Check if this is used for decimal scaling in price calculations
                            if is_decimal_scaling_in_price_calc(&code.code, i, *scale) {
                                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                                let func_name = ctx.module.identifier_at(func_handle.name);
                                
                                // Check for unusual decimal scales
                                if is_unusual_decimal_scale(*scale) {
                                    issues.push(SecurityIssue {
                                        id: self.id().to_string(),
                                        severity: self.default_severity(),
                                        confidence: Confidence::Medium,
                                        title: format!("Unusual decimal scaling in '{}'", func_name),
                                        description: format!("Using scale factor {} which may not match token/oracle decimals", scale),
                                        location: create_location(ctx, func_def, i as u16),
                                        source_code: Some(format!("scale: {}", scale)),
                                        recommendation: "Ensure scaling factor matches token decimals (typically 10^8 or 10^18) and oracle precision".to_string(),
                                        references: vec![],
                                        metadata: {
                                            let mut map = HashMap::new();
                                            map.insert("scale_factor".to_string(), scale.to_string());
                                            map
                                        },
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

fn is_decimal_scaling_in_price_calc(bytecode: &[Bytecode], idx: usize, _scale: u64) -> bool {
    // Check if this scale is used with multiplication/division in price context
    if idx + 2 < bytecode.len() {
        // Pattern: load scale, multiply/divide, use result
        match (&bytecode[idx + 1], &bytecode[idx + 2]) {
            (Bytecode::Mul, _) | (Bytecode::Div, _) => {
                // Check if result is used in financial operation
                return true;
            }
            _ => {}
        }
    }
    
    false
}

fn is_unusual_decimal_scale(scale: u64) -> bool {
    // Common decimal scales in crypto
    let common_scales = [
        100_000_000,          // 10^8 (typical for many tokens)
        1_000_000_000,        // 10^9
        10_000_000_000,       // 10^10
        100_000_000_000,      // 10^11
        1_000_000_000_000,    // 10^12
        10_000_000_000_000,   // 10^13
        100_000_000_000_000,  // 10^14
        1_000_000_000_000_000, // 10^15
        10_000_000_000_000_000, // 10^16
        100_000_000_000_000_000, // 10^17
        1_000_000_000_000_000_000, // 10^18 (ETH standard)
    ];
    
    !common_scales.contains(&scale) && scale > 1000
}

// OR-010: Missing Circuit Breaker - ULTRA STRICT
pub struct MissingCircuitBreaker;

#[async_trait::async_trait]
impl SecurityDetector for MissingCircuitBreaker {
    fn id(&self) -> &'static str { "OR-010" }
    fn name(&self) -> &'static str { "Missing Circuit Breaker" }
    fn description(&self) -> &'static str {
        "No circuit breaker for extreme price movements"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_oracle_dependent_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Look for critical oracle-dependent operations
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check highly critical operations
            let is_highly_critical = func_name_lower.contains("liquidate") ||
                                    (func_name_lower.contains("swap") && func_name_lower.contains("large")) ||
                                    func_name_lower == "execute_flash_loan";
            
            if is_highly_critical && has_oracle_calls(func_def, &ctx.module) {
                // Check for circuit breaker with strict criteria
                let circuit_breaker_score = calculate_circuit_breaker_score(func_def, &ctx.module);
                
                if circuit_breaker_score < 2 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if circuit_breaker_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Missing circuit breaker in '{}'", func_name),
                        description: "Critical oracle-dependent operation lacks circuit breaker for extreme market conditions".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement price deviation limits, volume-based circuit breakers, or emergency pause mechanisms".to_string(),
                        references: vec![],
                        metadata: {
                            let mut map = HashMap::new();
                            map.insert("circuit_breaker_score".to_string(), circuit_breaker_score.to_string());
                            map
                        },
                    });
                }
            }
        }
        
        issues
    }
}

fn calculate_circuit_breaker_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("max_price_change") { score += 3; }
                if func_name_lower.contains("price_deviation_limit") { score += 3; }
                if func_name_lower.contains("circuit_breaker") { score += 3; }
                if func_name_lower.contains("emergency_pause") { score += 2; }
                if func_name_lower.contains("trading_halt") { score += 2; }
                if func_name_lower.contains("volatility_check") { score += 2; }
            }
        }
    }
    
    score
}

// OR-011: Oracle Front-Running Risk - NEW STRICT DETECTOR
pub struct OracleFrontRunningRisk;

#[async_trait::async_trait]
impl SecurityDetector for OracleFrontRunningRisk {
    fn id(&self) -> &'static str { "OR-011" }
    fn name(&self) -> &'static str { "Oracle Front-Running Risk" }
    fn description(&self) -> &'static str {
        "Oracle price updates vulnerable to front-running"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_oracle_dependent_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Look for functions that submit oracle updates
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // Check for oracle update functions
            let is_oracle_update_function = func_name_lower.contains("update_price") ||
                                           func_name_lower.contains("submit_price") ||
                                           func_name_lower.contains("set_price");
            
            if is_oracle_update_function && func_def.visibility == Visibility::Public {
                // Check for anti-front-running mechanisms
                if !has_anti_frontrunning_mechanisms(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Oracle front-running risk in '{}'", func_name),
                        description: "Oracle price update function vulnerable to front-running attacks".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement commit-reveal schemes, time-weighted updates, or permissioned updaters".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn has_anti_frontrunning_mechanisms(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("commit") { return true; }
                if func_name_lower.contains("reveal") { return true; }
                if func_name_lower.contains("time_weighted") { return true; }
                if func_name_lower.contains("delayed_update") { return true; }
            }
        }
    }
    
    false
}

// Only include detectors that can be made extremely strict
pub fn get_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(FlashLoanVulnerability),
        Box::new(SingleSourceOracle),
        Box::new(NoPriceValidation),
        Box::new(StalePriceUsage),
        Box::new(IncorrectDecimals),
        Box::new(MissingCircuitBreaker),
        Box::new(OracleFrontRunningRisk),
    ]
}