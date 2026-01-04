// src/detectors/timing/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use move_binary_format::{file_format::*, access::ModuleAccess};

// TM-001: Front-Running Vulnerability
pub struct FrontRunningVulnerability;

#[async_trait::async_trait]
impl SecurityDetector for FrontRunningVulnerability {
    fn id(&self) -> &'static str { "TM-001" }
    fn name(&self) -> &'static str { "Front-Running Vulnerability" }
    fn description(&self) -> &'static str {
        "Transactions can be front-run due to predictable outcomes"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check functions that are CRITICAL for front-running
        let critical_ops = ["swap", "trade", "buy", "sell", "limit_order", "market_order", 
                            "arbitrage", "liquidate", "auction"];
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // Strict: Must be a trading/market function
            let is_market_function = critical_ops.iter()
                .any(|&op| func_name_lower.contains(op));
            
            if !is_market_function {
                continue;
            }
            
            // Check if this function actually has MEV-extractable value
            if !has_mev_extractable_value(func_def, &ctx.module) {
                continue;
            }
            
            // Analyze for specific front-running patterns
            let patterns = analyze_frontrunning_patterns(func_def, &ctx.module);
            
            // Only flag if there are clear front-running patterns AND no protections
            if patterns.has_dangerous_pattern && !patterns.has_protections {
                // Verify this is not a false positive (e.g., internal calculation)
                if !is_benign_frontrunning_context(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: patterns.confidence,
                        title: format!("Front-running vulnerability in '{}'", func_name),
                        description: patterns.description,
                        location: create_location(ctx, func_def, patterns.location as u16),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement commit-reveal, use deadline parameters with validation, or batch auctions".to_string(),
                        references: vec![
                            "https://consensys.github.io/smart-contract-best-practices/attacks/frontrunning/".to_string(),
                            "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization".to_string(),
                            "https://arxiv.org/abs/1904.05234".to_string(), // SoK: MEV
                        ],
                        metadata: {
                            let mut map = std::collections::HashMap::new();
                            map.insert("pattern_type".to_string(), patterns.pattern_type);
                            map.insert("mev_potential".to_string(), patterns.mev_potential.to_string());
                            map
                        },
                    });
                }
            }
        }
        
        issues
    }
}

// TM-002: Timestamp Dependence
pub struct TimestampDependence;

#[async_trait::async_trait]
impl SecurityDetector for TimestampDependence {
    fn id(&self) -> &'static str { "TM-002" }
    fn name(&self) -> &'static str { "Timestamp Dependence" }
    fn description(&self) -> &'static str {
        "Critical logic depends on block timestamp which can be manipulated"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                
                // Find timestamp usages with context analysis
                let timestamp_uses = find_timestamp_usages_strict(code, &ctx.module);
                
                for usage in timestamp_uses {
                    // Critical: timestamp used in AUTHORIZATION or FINANCIAL decisions
                    if usage.usage_type == TimestampUsageType::Authorization || 
                       usage.usage_type == TimestampUsageType::Financial {
                        
                        // Check if there's tolerance or safe usage
                        if !has_timestamp_safety_mechanisms(code, usage.location, &ctx.module) {
                            
                            // Verify this is actually dangerous (not just logging)
                            if is_dangerous_timestamp_usage(code, usage.location, &ctx.module) {
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(),
                                    severity: self.default_severity(),
                                    confidence: Confidence::High,
                                    title: format!("Critical timestamp dependence in '{}'", func_name),
                                    description: format!("Uses manipulable timestamp for {} decisions", 
                                                         usage.usage_type.as_str()),
                                    location: create_location(ctx, func_def, usage.location as u16),
                                    source_code: Some(get_instruction_context(code, usage.location)),
                                    recommendation: "Use block height (epoch) instead of timestamp, add tolerance windows (±30-300s), or use oracle-based time".to_string(),
                                    references: vec![
                                        "https://consensys.github.io/smart-contract-best-practices/attacks/timestamp-dependence/".to_string(),
                                        "https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/block-proposal/#timestamp-manipulation".to_string(),
                                    ],
                                    metadata: {
                                        let mut map = std::collections::HashMap::new();
                                        map.insert("usage_context".to_string(), usage.context);
                                        map.insert("comparison_type".to_string(), usage.comparison_type);
                                        map
                                    },
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

// TM-004: Transaction Ordering Dependence
pub struct TransactionOrdering;

#[async_trait::async_trait]
impl SecurityDetector for TransactionOrdering {
    fn id(&self) -> &'static str { "TM-004" }
    fn name(&self) -> &'static str { "Transaction Ordering Dependence" }
    fn description(&self) -> &'static str {
        "Race conditions due to transaction ordering in shared state"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Find shared state with WRITE conflicts
        let shared_state_conflicts = find_shared_state_conflicts_strict(&ctx.module);
        
        for (struct_idx, conflicts) in &shared_state_conflicts {
            let struct_handle = &ctx.module.struct_handles[*struct_idx as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name);
            
            // Only flag CRITICAL shared state (financial/access control)
            if !is_critical_shared_state(struct_name.as_str()) {
                continue;
            }
            
            // Group conflicts by severity
            let high_severity_conflicts: Vec<_> = conflicts.iter()
                .filter(|c| c.severity == ConflictSeverity::High)
                .collect();
            
            let medium_severity_conflicts: Vec<_> = conflicts.iter()
                .filter(|c| c.severity == ConflictSeverity::Medium)
                .collect();
            
            if !high_severity_conflicts.is_empty() {
                let conflict_descriptions: Vec<String> = high_severity_conflicts.iter()
                    .map(|c| c.description.clone())
                    .collect();
                
                issues.push(SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::High,
                    title: format!("Transaction ordering dependence on '{}'", struct_name),
                    description: format!("Multiple functions have write-write conflicts on shared state: {}", 
                                         conflict_descriptions.join("; ")),
                    location: create_module_location(ctx),
                    source_code: Some(struct_name.to_string()),
                    recommendation: "Implement locking mechanisms, use atomic updates, or redesign to avoid shared mutable state".to_string(),
                    references: vec![
                        "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization".to_string(),
                        "https://arxiv.org/abs/2302.03686".to_string(), // SoK: Atomicity
                    ],
                    metadata: {
                        let mut map = std::collections::HashMap::new();
                        map.insert("conflict_count".to_string(), high_severity_conflicts.len().to_string());
                        map.insert("state_type".to_string(), get_state_type(struct_name.as_str()));
                        map
                    },
                });
            }
        }
        
        issues
    }
}

// TM-005: Race Conditions
pub struct RaceConditions;

#[async_trait::async_trait]
impl SecurityDetector for RaceConditions {
    fn id(&self) -> &'static str { "TM-005" }
    fn name(&self) -> &'static str { "Race Conditions" }
    fn description(&self) -> &'static str {
        "Classic race conditions in concurrent execution"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check functions that are likely to have race conditions
            if !is_race_condition_candidate(func_name.as_str(), func_def, &ctx.module) {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                // Find check-then-act patterns with precise detection
                let race_patterns = find_race_condition_patterns_strict(code, &ctx.module);
                
                for pattern in race_patterns {
                    // Verify this is a true race condition (not atomic)
                    if !is_atomic_operation(code, pattern.check_location, pattern.act_location) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: pattern.confidence,
                            title: format!("Race condition in '{}'", func_name),
                            description: pattern.description,
                            location: create_location(ctx, func_def, pattern.check_location as u16),
                            source_code: Some(get_pattern_context(code, pattern.check_location, pattern.act_location)),
                            recommendation: "Use atomic operations (e.g., compare-and-swap), locks, or redesign to avoid TOCTOU patterns".to_string(),
                            references: vec![
                                "CWE-366: Race Condition within a Thread".to_string(),
                                "CWE-367: Time-of-check Time-of-use (TOCTOU)".to_string(),
                            ],
                            metadata: {
                                let mut map = std::collections::HashMap::new();
                                map.insert("pattern_type".to_string(), pattern.pattern_type);
                                map.insert("distance".to_string(), 
                                    (pattern.act_location - pattern.check_location).to_string());
                                map
                            },
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// TM-006: Deadline Bypass
pub struct DeadlineBypass;

#[async_trait::async_trait]
impl SecurityDetector for DeadlineBypass {
    fn id(&self) -> &'static str { "TM-006" }
    fn name(&self) -> &'static str { "Deadline Bypass Vulnerability" }
    fn description(&self) -> &'static str {
        "Deadline checks can be bypassed or manipulated"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check functions that have deadline parameters
            if !has_deadline_parameter(func_def, &ctx.module) {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                let deadline_checks = find_deadline_checks_strict(code, &ctx.module);
                
                for check in deadline_checks {
                    // Check for common bypass patterns
                    if check.has_bypass_risk && !check.has_mitigations {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: check.severity,
                            confidence: check.confidence,
                            title: format!("Deadline bypass risk in '{}'", func_name),
                            description: check.description,
                            location: create_location(ctx, func_def, check.location as u16),
                            source_code: Some(get_deadline_check_context(code, check.location)),
                            recommendation: "Validate deadline strictly: require deadline > block.timestamp, add minimum duration, prevent underflow".to_string(),
                            references: vec![
                                "https://github.com/Uniswap/v2-periphery/blob/master/contracts/UniswapV2Router02.sol#L161-L175".to_string(),
                            ],
                            metadata: {
                                let mut map = std::collections::HashMap::new();
                                map.insert("bypass_type".to_string(), check.bypass_type);
                                map.insert("comparison".to_string(), check.comparison);
                                map
                            },
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// TM-008: Miner Extractable Value (MEV) Patterns
pub struct MevPatterns;

#[async_trait::async_trait]
impl SecurityDetector for MevPatterns {
    fn id(&self) -> &'static str { "TM-008" }
    fn name(&self) -> &'static str { "Miner Extractable Value Patterns" }
    fn description(&self) -> &'static str {
        "Patterns that enable MEV extraction, harming users"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Look for specific MEV patterns
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                
                let mev_patterns = analyze_mev_patterns(code, &ctx.module);
                
                for pattern in mev_patterns {
                    if pattern.is_dangerous && pattern.mev_impact > 0 {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: pattern.severity,
                            confidence: pattern.confidence,
                            title: format!("MEV vulnerability in '{}'", func_name),
                            description: pattern.description,
                            location: create_location(ctx, func_def, pattern.location as u16),
                            source_code: Some(func_name.to_string()),
                            recommendation: pattern.recommendation,
                            references: vec![
                                "https://arxiv.org/abs/1904.05234".to_string(), // SoK: MEV
                                "https://github.com/flashbots/mev-research".to_string(),
                            ],
                            metadata: {
                                let mut map = std::collections::HashMap::new();
                                map.insert("mev_type".to_string(), pattern.mev_type);
                                map.insert("impact_score".to_string(), pattern.mev_impact.to_string());
                                map
                            },
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// Strict helper structures
#[derive(Debug, Clone)]
struct FrontrunningAnalysis {
    has_dangerous_pattern: bool,
    has_protections: bool,
    confidence: Confidence,
    description: String,
    location: usize,
    pattern_type: String,
    mev_potential: u8,
}

#[derive(Debug, Clone)]
struct TimestampUsage {
    location: usize,
    usage_type: TimestampUsageType,
    context: String,
    comparison_type: String,
}

#[derive(Debug, Clone, PartialEq)]
enum TimestampUsageType {
    Authorization,
    Financial,
    Logging,
    Validation,
    Other,
}

impl TimestampUsageType {
    fn as_str(&self) -> &str {
        match self {
            Self::Authorization => "authorization",
            Self::Financial => "financial",
            Self::Logging => "logging",
            Self::Validation => "validation",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
struct SharedStateConflict {
    func1_idx: usize,
    func2_idx: usize,
    severity: ConflictSeverity,
    description: String,
}

#[derive(Debug, Clone, PartialEq)]
enum ConflictSeverity {
    High,    // Write-write conflict on critical state
    Medium,  // Write-read or read-write conflict
    Low,     // Read-read conflict
}

#[derive(Debug, Clone)]
struct RaceConditionPattern {
    check_location: usize,
    act_location: usize,
    confidence: Confidence,
    description: String,
    pattern_type: String,
}

#[derive(Debug, Clone)]
struct DeadlineCheck {
    location: usize,
    has_bypass_risk: bool,
    has_mitigations: bool,
    severity: Severity,
    confidence: Confidence,
    description: String,
    bypass_type: String,
    comparison: String,
}

#[derive(Debug, Clone)]
struct MevPattern {
    location: usize,
    is_dangerous: bool,
    mev_impact: u8, // 0-10 scale
    severity: Severity,
    confidence: Confidence,
    description: String,
    mev_type: String,
    recommendation: String,
}

// Strict helper functions
fn has_mev_extractable_value(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // Check if function has value transfer or price-sensitive operations
    if let Some(code) = &func_def.code {
        // Look for coin transfers
        let has_coin_transfers = code.code.iter().any(|instr| {
            match instr {
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    if let Some((func_name, _)) = get_function_call_details(instr, module) {
                        func_name.contains("transfer") || func_name.contains("coin") ||
                        func_name.contains("swap") || func_name.contains("price")
                    } else {
                        false
                    }
                }
                _ => false
            }
        });
        
        // Look for state that affects pricing
        let has_price_state = code.code.iter().any(|instr| {
            match instr {
                Bytecode::MutBorrowGlobal(idx) => {
                    if let Some(struct_handle) = module.struct_handles.get(idx.0 as usize) {
                        let struct_name = module.identifier_at(struct_handle.name);
                        struct_name.as_str().contains("Price") ||
                        struct_name.as_str().contains("Oracle") ||
                        struct_name.as_str().contains("Rate")
                    } else {
                        false
                    }
                }
                Bytecode::MutBorrowGlobalGeneric(idx) => {
                    let type_inst = &module.struct_instantiations()[idx.0 as usize];
                    if let Some(struct_handle) = module.struct_handles.get(type_inst.def.0 as usize) {
                        let struct_name = module.identifier_at(struct_handle.name);
                        struct_name.as_str().contains("Price") ||
                        struct_name.as_str().contains("Oracle") ||
                        struct_name.as_str().contains("Rate")
                    } else {
                        false
                    }
                }
                _ => false
            }
        });
        
        has_coin_transfers || has_price_state
    } else {
        false
    }
}

fn analyze_frontrunning_patterns(func_def: &FunctionDefinition, module: &CompiledModule) -> FrontrunningAnalysis {
    let mut analysis = FrontrunningAnalysis {
        has_dangerous_pattern: false,
        has_protections: false,
        confidence: Confidence::Low,
        description: String::new(),
        location: 0,
        pattern_type: String::new(),
        mev_potential: 0,
    };
    
    if let Some(code) = &func_def.code {
        // Pattern 1: Slippage without deadline
        if has_slippage_without_deadline(code, module) {
            analysis.has_dangerous_pattern = true;
            analysis.pattern_type = "slippage_without_deadline".to_string();
            analysis.description = "Slippage protection without deadline allows front-running".to_string();
            analysis.location = find_slippage_location(code);
            analysis.mev_potential = 7;
            analysis.confidence = Confidence::Medium;
        }
        
        // Pattern 2: Price-sensitive operations without commit-reveal
        if has_price_sensitive_operations(code, module) && !has_commit_reveal_pattern(code, module) {
            analysis.has_dangerous_pattern = true;
            analysis.pattern_type = "price_sensitive_no_commit".to_string();
            analysis.description = "Price-sensitive operations without commit-reveal are front-runnable".to_string();
            analysis.location = find_price_op_location(code, module);
            analysis.mev_potential = 8;
            analysis.confidence = Confidence::High;
        }
        
        // Check for protections
        analysis.has_protections = has_frontrunning_protections_strict(func_def, module);
    }
    
    analysis
}

fn has_slippage_without_deadline(code: &CodeUnit, module: &CompiledModule) -> bool {
    // Look for minimum output amount checks without deadline validation
    let mut has_slippage_check = false;
    let mut has_deadline_check = false;
    
    for (i, instr) in code.code.iter().enumerate() {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("min_amount") || func_name.contains("slippage") {
                has_slippage_check = true;
            }
            if func_name.contains("deadline") || func_name.contains("timestamp") {
                // Check if it's actually validating deadline
                if i + 2 < code.code.len() {
                    if let Bytecode::Lt | Bytecode::Gt = &code.code[i + 2] {
                        has_deadline_check = true;
                    }
                }
            }
        }
    }
    
    has_slippage_check && !has_deadline_check
}

fn has_price_sensitive_operations(code: &CodeUnit, module: &CompiledModule) -> bool {
    // Check for operations that depend on external price
    for instr in &code.code {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("price") || func_name.contains("rate") || 
               func_name.contains("oracle") || func_name.contains("amm") {
                return true;
            }
        }
    }
    false
}

fn has_commit_reveal_pattern(code: &CodeUnit, module: &CompiledModule) -> bool {
    // Look for commit-then-reveal pattern
    let mut commit_found = false;
    let mut reveal_found = false;
    
    for instr in &code.code {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("commit") {
                commit_found = true;
            }
            if func_name.contains("reveal") {
                reveal_found = true;
            }
        }
    }
    
    commit_found && reveal_found
}

fn find_slippage_location(code: &CodeUnit) -> usize {
    // Find the location of slippage check
    for (i, instr) in code.code.iter().enumerate() {
        if let Bytecode::LdU64(_) | Bytecode::LdU128(_) = instr {
            // Could be min amount
            return i;
        }
    }
    0
}

fn find_price_op_location(code: &CodeUnit, module: &CompiledModule) -> usize {
    for (i, instr) in code.code.iter().enumerate() {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("price") || func_name.contains("swap") {
                return i;
            }
        }
    }
    0
}

fn has_frontrunning_protections_strict(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        // Check for deadline parameter with validation
        let mut has_valid_deadline = false;
        let mut has_tolerance = false;
        
        for i in 0..code.code.len() {
            if let Some((func_name, _)) = get_function_call_details(&code.code[i], module) {
                if func_name.contains("deadline") {
                    // Check if deadline is properly validated
                    if i + 3 < code.code.len() {
                        // Pattern: timestamp, deadline, comparison
                        if let (Bytecode::Call(_), Bytecode::LdU64(_), Bytecode::Lt) = 
                            (&code.code[i], &code.code[i+1], &code.code[i+2]) {
                            has_valid_deadline = true;
                        }
                    }
                }
                if func_name.contains("tolerance") || func_name.contains("window") {
                    has_tolerance = true;
                }
            }
        }
        
        // Also check for commit-reveal
        has_valid_deadline || has_tolerance || has_commit_reveal_pattern(code, module)
    } else {
        false
    }
}

fn is_benign_frontrunning_context(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // Check if this is a view function or internal calculation
    let func_handle = &module.function_handles[func_def.function.0 as usize];
    let func_name = module.identifier_at(func_handle.name);
    
    // View functions can't be front-run
    if func_name.as_str().starts_with("get_") || 
       func_name.as_str().contains("view") || 
       func_name.as_str().contains("calculate") {
        return true;
    }
    
    // Check if function modifies state
    if let Some(code) = &func_def.code {
        let modifies_state = code.code.iter().any(|instr| {
            matches!(instr,
                Bytecode::MutBorrowGlobal(_) | Bytecode::MutBorrowGlobalGeneric(_)
            )
        });
        
        !modifies_state
    } else {
        true
    }
}

fn find_timestamp_usages_strict(code: &CodeUnit, module: &CompiledModule) -> Vec<TimestampUsage> {
    let mut usages = Vec::new();
    
    for (i, instr) in code.code.iter().enumerate() {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("timestamp") || func_name.contains("clock") {
                let usage_type = determine_timestamp_usage_type(code, i, module);
                let context = get_usage_context(code, i);
                let comparison_type = get_comparison_type(code, i);
                
                usages.push(TimestampUsage {
                    location: i,
                    usage_type,
                    context,
                    comparison_type,
                });
            }
        }
    }
    
    usages
}

fn determine_timestamp_usage_type(code: &CodeUnit, location: usize, module: &CompiledModule) -> TimestampUsageType {
    // Analyze how timestamp is used
    let end = code.code.len().min(location + 8);
    
    for i in location + 1..end {
        match &code.code[i] {
            Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge => {
                // Comparison - check what it's compared with
                if i > 0 {
                    if let Bytecode::LdU64(_) | Bytecode::LdU128(_) = &code.code[i-1] {
                        // Compared with constant - likely deadline
                        return TimestampUsageType::Authorization;
                    }
                }
            }
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                if let Some((func_name, _)) = get_function_call_details(&code.code[i], module) {
                    if func_name.contains("require") || func_name.contains("assert") {
                        return TimestampUsageType::Authorization;
                    }
                    if func_name.contains("transfer") || func_name.contains("pay") {
                        return TimestampUsageType::Financial;
                    }
                }
            }
            Bytecode::Branch(_) => {
                // Used in control flow
                return TimestampUsageType::Authorization;
            }
            _ => {}
        }
    }
    
    // Check for logging/event patterns
    for i in location..end {
        if let Some((func_name, _)) = get_function_call_details(&code.code[i], module) {
            if func_name.contains("emit") || func_name.contains("log") {
                return TimestampUsageType::Logging;
            }
        }
    }
    
    TimestampUsageType::Other
}

fn has_timestamp_safety_mechanisms(code: &CodeUnit, location: usize, module: &CompiledModule) -> bool {
    // Check for safety mechanisms like tolerance windows
    let start = location.saturating_sub(5);
    let end = code.code.len().min(location + 10);
    
    // Look for tolerance patterns
    for i in start..end {
        if let Some((func_name, _)) = get_function_call_details(&code.code[i], module) {
            if func_name.contains("tolerance") || func_name.contains("window") || 
               func_name.contains("grace") || func_name.contains("buffer") {
                return true;
            }
        }
        
        // Look for range checks (min and max)
        if i + 3 < end {
            if let (Bytecode::LdU64(_), Bytecode::Lt, Bytecode::LdU64(_), Bytecode::Gt) = 
                (&code.code[i], &code.code[i+1], &code.code[i+2], &code.code[i+3]) {
                return true; // Range check pattern
            }
        }
    }
    
    false
}

fn is_dangerous_timestamp_usage(code: &CodeUnit, location: usize, module: &CompiledModule) -> bool {
    // Timestamp usage is dangerous if it affects financial outcomes
    let end = code.code.len().min(location + 15);
    
    // Track if timestamp affects financial operations
    let mut affects_financial = false;
    
    for i in location + 1..end {
        if let Some((func_name, _)) = get_function_call_details(&code.code[i], module) {
            if func_name.contains("transfer") || func_name.contains("coin") ||
               func_name.contains("amount") || func_name.contains("value") {
                affects_financial = true;
                break;
            }
        }
        
        // Check for state modifications after timestamp check
        match &code.code[i] {
            Bytecode::MutBorrowGlobal(_) | Bytecode::MutBorrowGlobalGeneric(_) => {
                affects_financial = true;
                break;
            }
            _ => {}
        }
    }
    
    affects_financial
}

fn find_shared_state_conflicts_strict(module: &CompiledModule) -> 
    std::collections::HashMap<u16, Vec<SharedStateConflict>> {
    
    let mut conflicts = std::collections::HashMap::new();
    
    // First, collect all state accesses by function
    let mut state_accesses: std::collections::HashMap<u16, Vec<(usize, AccessType, Vec<usize>)>> = 
        std::collections::HashMap::new();
    
    for (func_idx, func_def) in module.function_defs.iter().enumerate() {
        if let Some(code) = &func_def.code {
            for (i, instr) in code.code.iter().enumerate() {
                let (access_type, struct_idx, call_sites) = match instr {
                    Bytecode::MutBorrowGlobal(idx) => {
                        (AccessType::Write, idx.0, get_call_sites_before(code, i))
                    }
                    Bytecode::ImmBorrowGlobal(idx) => {
                        (AccessType::Read, idx.0, get_call_sites_before(code, i))
                    }
                    Bytecode::MutBorrowGlobalGeneric(idx) => {
                        let type_inst = &module.struct_instantiations()[idx.0 as usize];
                        (AccessType::Write, type_inst.def.0, get_call_sites_before(code, i))
                    }
                    Bytecode::ImmBorrowGlobalGeneric(idx) => {
                        let type_inst = &module.struct_instantiations()[idx.0 as usize];
                        (AccessType::Read, type_inst.def.0, get_call_sites_before(code, i))
                    }
                    _ => continue,
                };
                
                state_accesses.entry(struct_idx)
                    .or_insert_with(Vec::new)
                    .push((func_idx, access_type.clone(), call_sites));
            }
        }
    }
    
    // Now find conflicts
    for (struct_idx, accesses) in &state_accesses {
        for i in 0..accesses.len() {
            for j in i+1..accesses.len() {
                let (func1_idx, access1_type, calls1) = &accesses[i];
                let (func2_idx, access2_type, calls2) = &accesses[j];
                
                // Check if there's a potential conflict
                let conflict_type = match (access1_type, access2_type) {
                    (AccessType::Write, AccessType::Write) => ConflictSeverity::High,
                    (AccessType::Write, AccessType::Read) | 
                    (AccessType::Read, AccessType::Write) => ConflictSeverity::Medium,
                    (AccessType::Read, AccessType::Read) => ConflictSeverity::Low,
                };
                
                // Only flag if functions have external calls that could interleave
                let has_external_calls_interleaving = 
                    has_potential_interleaving(calls1, calls2, module);
                
                if conflict_type != ConflictSeverity::Low && has_external_calls_interleaving {
                    let func1_name = get_function_name(*func1_idx, module);
                    let func2_name = get_function_name(*func2_idx, module);
                    
                    conflicts.entry(*struct_idx)
                        .or_insert_with(Vec::new)
                        .push(SharedStateConflict {
                            func1_idx: *func1_idx,
                            func2_idx: *func2_idx,
                            severity: conflict_type,
                            description: format!("{} ({}), {} ({})", 
                                func1_name, access1_type.as_str(),
                                func2_name, access2_type.as_str()),
                        });
                }
            }
        }
    }
    
    conflicts
}

fn has_potential_interleaving(calls1: &[usize], calls2: &[usize], module: &CompiledModule) -> bool {
    // Check if calls in both sequences could allow interleaving
    !calls1.is_empty() && !calls2.is_empty()
}

fn is_critical_shared_state(struct_name: &str) -> bool {
    let name_lower = struct_name.to_lowercase();
    name_lower.contains("balance") || name_lower.contains("coin") ||
    name_lower.contains("stake") || name_lower.contains("pool") ||
    name_lower.contains("vault") || name_lower.contains("lock") ||
    name_lower.contains("owner") || name_lower.contains("admin")
}

fn is_race_condition_candidate(func_name: &str, func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    let name_lower = func_name.to_lowercase();
    
    // Functions that typically have race conditions
    let race_keywords = ["withdraw", "claim", "redeem", "swap", "transfer", "update"];
    
    let has_race_keyword = race_keywords.iter().any(|&kw| name_lower.contains(kw));
    
    if !has_race_keyword {
        return false;
    }
    
    // Check if function accesses shared state
    if let Some(code) = &func_def.code {
        code.code.iter().any(|instr| {
            matches!(instr,
                Bytecode::MutBorrowGlobal(_) | Bytecode::ImmBorrowGlobal(_) |
                Bytecode::MutBorrowGlobalGeneric(_) | Bytecode::ImmBorrowGlobalGeneric(_)
            )
        })
    } else {
        false
    }
}

fn find_race_condition_patterns_strict(code: &CodeUnit, module: &CompiledModule) -> Vec<RaceConditionPattern> {
    let mut patterns = Vec::new();
    
    // Look for TOCTOU (Time-of-check, time-of-use) patterns
    for i in 0..code.code.len().saturating_sub(4) {
        let struct_idx1 = match &code.code[i] {
            Bytecode::ImmBorrowGlobal(idx) => Some(idx.0),
            Bytecode::ImmBorrowGlobalGeneric(idx) => {
                module.struct_instantiations().get(idx.0 as usize).map(|inst| inst.def.0)
            }
            _ => None,
        };

        if let Some(s1) = struct_idx1 {
            for j in i+1..code.code.len().min(i+10) {
                let struct_idx2 = match &code.code[j] {
                    Bytecode::MutBorrowGlobal(idx) => Some(idx.0),
                    Bytecode::MutBorrowGlobalGeneric(idx) => {
                        module.struct_instantiations().get(idx.0 as usize).map(|inst| inst.def.0)
                    }
                    _ => None,
                };

                if let Some(s2) = struct_idx2 {
                    if s1 == s2 {
                        // Look for control flow between check and use
                        if has_control_flow_between(code, i, j) {
                            patterns.push(RaceConditionPattern {
                                check_location: i,
                                act_location: j,
                                confidence: Confidence::High,
                                description: format!("TOCTOU race condition on state at instructions {}->{}", i, j),
                                pattern_type: "toctou".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    
    patterns
}

fn is_atomic_operation(code: &CodeUnit, check_loc: usize, act_loc: usize) -> bool {
    // Check if operations between check and act are atomic
    // Simplified: if distance is very small, might be atomic
    act_loc - check_loc <= 3
}

fn has_deadline_parameter(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    {
        let func_handle_idx = func_def.function;
        let func_handle = &module.function_handles[func_handle_idx.0 as usize];
        let _param_count = func_handle.parameters.0;
        
        // In practice, would check parameter signatures for u64/u128 (deadline types)
        // For now, check function name
        let func_name = module.identifier_at(func_handle.name);
        func_name.as_str().contains("deadline") || 
        func_name.as_str().contains("expire") ||
        func_name.as_str().contains("until")
    }
}

fn find_deadline_checks_strict(code: &CodeUnit, module: &CompiledModule) -> Vec<DeadlineCheck> {
    let mut checks = Vec::new();
    
    for (i, instr) in code.code.iter().enumerate() {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("timestamp") || func_name.contains("clock") {
                // Check if this is used for deadline validation
                if i + 3 < code.code.len() {
                    if let (Bytecode::LdU64(_) | Bytecode::LdU128(_), Bytecode::Lt | Bytecode::Le) = 
                        (&code.code[i+1], &code.code[i+2]) {
                        
                        let check = analyze_deadline_check(code, i, module);
                        checks.push(check);
                    }
                }
            }
        }
    }
    
    checks
}

fn analyze_deadline_check(code: &CodeUnit, location: usize, module: &CompiledModule) -> DeadlineCheck {
    let mut check = DeadlineCheck {
        location,
        has_bypass_risk: false,
        has_mitigations: false,
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        description: String::new(),
        bypass_type: String::new(),
        comparison: String::new(),
    };
    
    // Check comparison type
    if location + 2 < code.code.len() {
        if let Bytecode::Lt = &code.code[location + 2] {
            check.comparison = "block.timestamp < deadline".to_string();
            // This is correct pattern
            check.has_bypass_risk = false;
        } else if let Bytecode::Le = &code.code[location + 2] {
            check.comparison = "block.timestamp <= deadline".to_string();
            // Might allow exact timestamp manipulation
            check.has_bypass_risk = true;
            check.bypass_type = "exact_timestamp".to_string();
        } else if let Bytecode::Gt = &code.code[location + 2] {
            check.comparison = "block.timestamp > deadline".to_string();
            // Wrong comparison - always passes until deadline
            check.has_bypass_risk = true;
            check.bypass_type = "wrong_comparison".to_string();
            check.severity = Severity::High;
            check.confidence = Confidence::High;
        }
    }
    
    // Check for underflow protection
    check.has_mitigations = has_underflow_protection(code, location);
    
    check.description = format!("Deadline check with {} comparison", check.comparison);
    
    check
}

fn has_underflow_protection(code: &CodeUnit, location: usize) -> bool {
    // Check for underflow checks around the deadline
    let start = location.saturating_sub(3);
    let end = code.code.len().min(location + 5);
    
    for i in start..end {
        if let Bytecode::Call(_) = &code.code[i] {
            // Look for overflow/underflow checks
            // In practice, would check function names
            return true; // Simplified
        }
    }
    
    false
}

fn analyze_mev_patterns(code: &CodeUnit, module: &CompiledModule) -> Vec<MevPattern> {
    let mut patterns = Vec::new();
    
    // Pattern 1: Sandwich attacks
    if has_sandwich_attack_pattern(code, module) {
        patterns.push(MevPattern {
            location: find_first_price_op(code, module),
            is_dangerous: true,
            mev_impact: 9,
            severity: Severity::High,
            confidence: Confidence::Medium,
            description: "Potential sandwich attack vulnerability".to_string(),
            mev_type: "sandwich".to_string(),
            recommendation: "Use batch auctions, TWAP, or limit order books".to_string(),
        });
    }
    
    // Pattern 2: Liquidations without randomness
    if has_liquidation_pattern(code, module) && !has_randomness_in_liquidation(code, module) {
        patterns.push(MevPattern {
            location: find_liquidation_call(code, module),
            is_dangerous: true,
            mev_impact: 8,
            severity: Severity::High,
            confidence: Confidence::High,
            description: "Liquidation without randomness enables MEV races".to_string(),
            mev_type: "liquidation".to_string(),
            recommendation: "Add randomness to liquidation selection, use Dutch auctions".to_string(),
        });
    }
    
    patterns
}

fn has_sandwich_attack_pattern(code: &CodeUnit, module: &CompiledModule) -> bool {
    // Check for AMM swaps with predictable price impact
    let mut has_swap = false;
    let mut has_slippage_check = false;
    
    for instr in &code.code {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("swap") || func_name.contains("amm") {
                has_swap = true;
            }
            if func_name.contains("slippage") || func_name.contains("min_amount") {
                has_slippage_check = true;
            }
        }
    }
    
    has_swap && !has_slippage_check
}

fn has_liquidation_pattern(code: &CodeUnit, module: &CompiledModule) -> bool {
    for instr in &code.code {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("liquidate") || func_name.contains("seize") {
                return true;
            }
        }
    }
    false
}

fn has_randomness_in_liquidation(code: &CodeUnit, module: &CompiledModule) -> bool {
    for instr in &code.code {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("random") || func_name.contains("shuffle") {
                return true;
            }
        }
    }
    false
}

fn find_first_price_op(code: &CodeUnit, module: &CompiledModule) -> usize {
    for (i, instr) in code.code.iter().enumerate() {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("price") || func_name.contains("swap") {
                return i;
            }
        }
    }
    0
}

fn find_liquidation_call(code: &CodeUnit, module: &CompiledModule) -> usize {
    for (i, instr) in code.code.iter().enumerate() {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("liquidate") {
                return i;
            }
        }
    }
    0
}

// Additional strict helper functions
#[derive(Debug, Clone, PartialEq)]
enum AccessType {
    Read,
    Write,
}

impl AccessType {
    fn as_str(&self) -> &str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

fn get_function_call_details(instr: &Bytecode, module: &CompiledModule) -> Option<(String, String)> {
    match instr {
        Bytecode::Call(idx) => {
            let func_handle = &module.function_handles[idx.0 as usize];
            let module_handle = &module.module_handles[func_handle.module.0 as usize];
            let module_name = module.identifier_at(module_handle.name);
            let func_name = module.identifier_at(func_handle.name);
            Some((format!("{}::{}", module_name, func_name), format!("{:?}", func_handle)))
        }
        Bytecode::CallGeneric(idx) => {
            let func_inst = &module.function_instantiations[idx.0 as usize];
            let func_handle = &module.function_handles[func_inst.handle.0 as usize];
            let module_handle = &module.module_handles[func_handle.module.0 as usize];
            let module_name = module.identifier_at(module_handle.name);
            let func_name = module.identifier_at(func_handle.name);
            Some((format!("{}::{}", module_name, func_name), format!("{:?}", func_inst)))
        }
        _ => None,
    }
}

fn get_usage_context(code: &CodeUnit, location: usize) -> String {
    let start = location.saturating_sub(2);
    let end = code.code.len().min(location + 3);
    
    let mut context = String::new();
    for i in start..end {
        if i == location {
            context.push_str("[TIMESTAMP] ");
        } else {
            context.push_str(&format!("{:?} ", &code.code[i]));
        }
    }
    context
}

fn get_comparison_type(code: &CodeUnit, location: usize) -> String {
    if location + 2 < code.code.len() {
        match &code.code[location + 2] {
            Bytecode::Lt => "<".to_string(),
            Bytecode::Gt => ">".to_string(),
            Bytecode::Le => "<=".to_string(),
            Bytecode::Ge => ">=".to_string(),
            Bytecode::Eq => "==".to_string(),
            _ => "unknown".to_string(),
        }
    } else {
        "none".to_string()
    }
}

fn get_instruction_context(code: &CodeUnit, location: usize) -> String {
    let start = location.saturating_sub(1);
    let end = code.code.len().min(location + 2);
    
    let mut context = String::new();
    for i in start..end {
        context.push_str(&format!("{}: {:?} ", i, &code.code[i]));
    }
    context
}

fn get_pattern_context(code: &CodeUnit, check_loc: usize, act_loc: usize) -> String {
    format!("Check at {}: {:?}, Act at {}: {:?}", 
            check_loc, &code.code[check_loc], act_loc, &code.code[act_loc])
}

fn get_deadline_check_context(code: &CodeUnit, location: usize) -> String {
    let end = code.code.len().min(location + 4);
    let mut context = String::new();
    for i in location..end {
        context.push_str(&format!("{:?} ", &code.code[i]));
    }
    context
}

fn get_call_sites_before(code: &CodeUnit, location: usize) -> Vec<usize> {
    let mut calls = Vec::new();
    let start = location.saturating_sub(10);
    
    for i in start..location {
        match &code.code[i] {
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                calls.push(i);
            }
            _ => {}
        }
    }
    
    calls
}

fn get_function_name(func_idx: usize, module: &CompiledModule) -> String {
    if let Some(func_def) = module.function_defs.get(func_idx) {
        let func_handle_idx = func_def.function;
        let func_handle = &module.function_handles[func_handle_idx.0 as usize];
        module.identifier_at(func_handle.name).to_string()
    } else {
        "unknown".to_string()
    }
}

fn get_generic_struct_idx(instr: &Bytecode, module: &CompiledModule) -> u16 {
    match instr {
        Bytecode::ImmBorrowGlobalGeneric(idx) | Bytecode::MutBorrowGlobalGeneric(idx) => {
            let type_inst = &module.struct_instantiations()[idx.0 as usize];
            type_inst.def.0
        }
        _ => 0,
    }
}

fn has_control_flow_between(code: &CodeUnit, start: usize, end: usize) -> bool {
    for i in start..end {
        match &code.code[i] {
            Bytecode::Branch(_) | Bytecode::BrTrue(_) | Bytecode::BrFalse(_) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn get_state_type(struct_name: &str) -> String {
    let name_lower = struct_name.to_lowercase();
    
    if name_lower.contains("balance") || name_lower.contains("coin") {
        "financial".to_string()
    } else if name_lower.contains("stake") || name_lower.contains("pool") {
        "staking".to_string()
    } else if name_lower.contains("lock") || name_lower.contains("access") {
        "access_control".to_string()
    } else {
        "other".to_string()
    }
}

fn create_location(ctx: &DetectionContext, func_def: &FunctionDefinition, instruction_idx: u16) -> CodeLocation {
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: instruction_idx,
        byte_offset: 0,
        line: None,
        column: None,
    }
}

fn create_module_location(ctx: &DetectionContext) -> CodeLocation {
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: "module".to_string(),
        instruction_index: 0,
        byte_offset: 0,
        line: None,
        column: None,
    }
}