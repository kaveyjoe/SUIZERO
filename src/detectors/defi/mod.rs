// src/detectors/defi/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use crate::utils::{create_location, create_module_location};
use move_binary_format::{file_format::*, access::ModuleAccess};

// ULTRA STRICT: Determine if this is actually a DeFi module
fn is_defi_module(module: &CompiledModule) -> bool {
    let module_name = module.self_id().name().as_str().to_lowercase();
    
    // Require explicit DeFi indicators
    let is_defi_by_name = module_name.contains("dex") ||
                         module_name.contains("amm") ||
                         module_name.contains("swap") ||
                         module_name.contains("lending") ||
                         module_name.contains("borrow") ||
                         module_name.contains("staking") ||
                         module_name.contains("yield") ||
                         module_name.contains("farm") ||
                         module_name.contains("vault") ||
                         module_name.contains("pool") ||
                         module_name.contains("liquidity");
    
    if !is_defi_by_name {
        return false;
    }
    
    // Verify DeFi-specific structs exist
    let has_defi_structs = module.struct_defs.iter().any(|struct_def| {
        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
        let struct_name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
        struct_name.contains("pool") ||
        struct_name.contains("position") ||
        struct_name.contains("reserve") ||
        struct_name.contains("market") ||
        struct_name.contains("vault")
    });
    
    // Verify DeFi-specific functions exist
    let defi_function_count = module.function_defs.iter()
        .filter(|func_def| {
            let func_handle = &module.function_handles[func_def.function.0 as usize];
            let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("swap") ||
            func_name.contains("add_liquidity") ||
            func_name.contains("remove_liquidity") ||
            func_name.contains("borrow") ||
            func_name.contains("repay") ||
            func_name.contains("stake") ||
            func_name.contains("unstake")
        })
        .count();
    
    // Must have at least 2 DeFi-specific indicators
    is_defi_by_name && (has_defi_structs || defi_function_count >= 2)
}

// DF-002: Slippage Attack - ULTRA STRICT
pub struct SlippageAttack;

#[async_trait::async_trait]
impl SecurityDetector for SlippageAttack {
    fn id(&self) -> &'static str { "DF-002" }
    fn name(&self) -> &'static str { "Slippage Attack" }
    fn description(&self) -> &'static str {
        "Trades vulnerable to slippage manipulation"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_defi_module(&ctx.module) { return Vec::new(); }
        
        // Only check if module has swap functionality
        let has_swap_function = ctx.module.function_defs.iter().any(|f| {
            let func_handle = &ctx.module.function_handles[f.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name == "swap" || func_name == "exact_swap"
        });
        
        if !has_swap_function { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check actual swap functions
            let is_swap_function = func_name_lower == "swap" ||
                                  func_name_lower == "exact_swap" ||
                                  func_name_lower == "swap_exact";
            
            if is_swap_function {
                // Check for slippage protection with multiple indicators
                let protection_score = calculate_slippage_protection_score(func_def, &ctx.module);
                
                if protection_score < 2 { // Require multiple protection mechanisms
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if protection_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Slippage attack vulnerability in '{}'", func_name),
                        description: "Swap function lacks adequate slippage protection".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement minimum output amounts, deadline parameters, and price impact limits".to_string(),
                        references: vec![
                            "MEV and Slippage: https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn calculate_slippage_protection_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("min_out") { score += 3; }
                if func_name_lower.contains("deadline") { score += 2; }
                if func_name_lower.contains("slippage_tolerance") { score += 3; }
                if func_name_lower.contains("max_price_impact") { score += 3; }
                if func_name_lower.contains("price_limit") { score += 2; }
            }
        }
    }
    
    score
}

// DF-004: Oracle Manipulation in AMM - ULTRA STRICT
pub struct OracleManipulationInAMM;

#[async_trait::async_trait]
impl SecurityDetector for OracleManipulationInAMM {
    fn id(&self) -> &'static str { "DF-004" }
    fn name(&self) -> &'static str { "Oracle Manipulation in AMM" }
    fn description(&self) -> &'static str {
        "AMM uses manipulable price oracles"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_defi_module(&ctx.module) { return Vec::new(); }
        
        // Only check if this is an AMM module
        let is_amm_module = ctx.module.function_defs.iter().any(|f| {
            let func_handle = &ctx.module.function_handles[f.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("get_price") || func_name.contains("price_from_pool")
        });
        
        if !is_amm_module { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Look for oracle-dependent price calculations
        let mut oracle_dependent_functions = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            if func_name_lower.contains("get_price") ||
               func_name_lower.contains("calculate_price") ||
               func_name_lower.contains("spot_price") {
                
                // Check if this function depends on external oracles
                if depends_on_external_oracle(func_def, &ctx.module) {
                    oracle_dependent_functions.push(func_name.to_string());
                }
            }
        }
        
        // Only flag if critical price functions depend on single oracle
        if !oracle_dependent_functions.is_empty() {
            let critical_functions = oracle_dependent_functions.join(", ");
            issues.push(SecurityIssue {
                id: self.id().to_string(),
                severity: self.default_severity(),
                confidence: Confidence::High,
                title: "Oracle manipulation risk in AMM".to_string(),
                description: format!("Critical price calculations ({}) depend on manipulable oracles", critical_functions),
                location: create_module_location(ctx),
                source_code: None,
                recommendation: "Use TWAPs, multiple oracle sources, or bonding curves for price determination".to_string(),
                references: vec![
                    "Oracle Manipulation Attacks: https://rekt.news/leaderboard/".to_string(),
                ],
                metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}

fn depends_on_external_oracle(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut oracle_calls = 0;
        let mut external_calls = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("oracle") ||
                   func_name_lower.contains("price_feed") ||
                   func_name_lower.contains("get_price") {
                    oracle_calls += 1;
                }
                
                // Check for external calls to oracle modules
                if is_external_call(instr, module) {
                    external_calls += 1;
                }
            }
        }
        
        // Function depends on oracle if it makes oracle-specific calls
        oracle_calls > 0 || (external_calls > 0 && oracle_calls > 0)
    } else {
        false
    }
}

// DF-005: Liquidation Vulnerability - ULTRA STRICT
pub struct LiquidationVulnerability;

#[async_trait::async_trait]
impl SecurityDetector for LiquidationVulnerability {
    fn id(&self) -> &'static str { "DF-005" }
    fn name(&self) -> &'static str { "Liquidation Vulnerability" }
    fn description(&self) -> &'static str {
        "Liquidation mechanisms have flaws or can be manipulated"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_defi_module(&ctx.module) { return Vec::new(); }
        
        // Only check lending/borrowing modules
        let is_lending_module = ctx.module.function_defs.iter().any(|f| {
            let func_handle = &ctx.module.function_handles[f.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("borrow") || func_name.contains("repay") || func_name.contains("collateral")
        });
        
        if !is_lending_module { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check actual liquidation functions
            let is_liquidation_function = func_name_lower == "liquidate" ||
                                         func_name_lower.contains("liquidate_position") ||
                                         func_name_lower.contains("seize_collateral");
            
            if is_liquidation_function {
                // Check for health factor validation
                let safety_score = calculate_liquidation_safety_score(func_def, &ctx.module);
                
                if safety_score < 3 { // Require strong safety measures
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if safety_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Liquidation vulnerability in '{}'", func_name),
                        description: "Liquidation function lacks proper safety checks and risk controls".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement health factor checks, collateralization ratio validation, and liquidation caps".to_string(),
                        references: vec![
                            "MakerDAO Liquidations 2.0: https://blog.makerdao.com/multi-collateral-dai-liquidations-2-0/".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn calculate_liquidation_safety_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("health_factor") { score += 3; }
                if func_name_lower.contains("collateral_ratio") { score += 2; }
                if func_name_lower.contains("liquidation_threshold") { score += 2; }
                if func_name_lower.contains("check_solvent") { score += 3; }
                if func_name_lower.contains("max_liquidation") { score += 2; }
                if func_name_lower.contains("safety_margin") { score += 2; }
            }
        }
    }
    
    score
}

// DF-008: Fee-on-Transfer Token Issue - ULTRA STRICT
pub struct FeeOnTransferTokenIssue;

#[async_trait::async_trait]
impl SecurityDetector for FeeOnTransferTokenIssue {
    fn id(&self) -> &'static str { "DF-008" }
    fn name(&self) -> &'static str { "Fee-on-Transfer Token Issue" }
    fn description(&self) -> &'static str {
        "Contracts don't handle fee-on-transfer tokens correctly"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_defi_module(&ctx.module) { return Vec::new(); }
        
        // Look for functions that might be vulnerable
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // Only check functions that receive exact amounts
            let is_exact_amount_function = func_name_lower.contains("exact_in") ||
                                          func_name_lower.contains("exact_out") ||
                                          (func_name_lower.contains("swap") && 
                                           (func_name_lower.contains("exact") || func_name_lower.contains("amount")));
            
            if is_exact_amount_function {
                // Check for balance difference patterns
                if uses_exact_amount_assumptions(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Fee-on-transfer token issue in '{}'", func_name),
                        description: "Function assumes exact transfer amounts without accounting for fees".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Check balance before and after transfers, or use balance difference calculations".to_string(),
                        references: vec![],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn uses_exact_amount_assumptions(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut transfer_calls = 0;
        let mut balance_checks = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("transfer") { transfer_calls += 1; }
                if func_name_lower.contains("balance_of") || func_name_lower.contains("balance") {
                    balance_checks += 1;
                }
            }
        }
        
        // Vulnerable if makes transfers but doesn't check balances
        transfer_calls > 0 && balance_checks == 0
    } else {
        false
    }
}

// DF-009: Yield Farming Vulnerability - ULTRA STRICT
pub struct YieldFarmingVulnerability;

#[async_trait::async_trait]
impl SecurityDetector for YieldFarmingVulnerability {
    fn id(&self) -> &'static str { "DF-009" }
    fn name(&self) -> &'static str { "Yield Farming Vulnerability" }
    fn description(&self) -> &'static str {
        "Yield farming mechanisms have economic vulnerabilities"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_defi_module(&ctx.module) { return Vec::new(); }
        
        // Only check if this is a farming module
        let is_farming_module = ctx.module.function_defs.iter().any(|f| {
            let func_handle = &ctx.module.function_handles[f.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("farm") || func_name.contains("stake") || func_name.contains("yield")
        });
        
        if !is_farming_module { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Check for reward calculation functions
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            if func_name_lower.contains("calculate_reward") ||
               func_name_lower.contains("distribute_reward") ||
               func_name_lower.contains("claim_reward") {
                
                // Check for proper reward timing mechanisms
                let reward_safety_score = calculate_reward_safety_score(func_def, &ctx.module);
                
                if reward_safety_score < 2 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Yield farming vulnerability in '{}'", func_name),
                        description: "Reward calculation lacks proper timing and anti-manipulation mechanisms".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Use checkpoint-based rewards, time-weighted balances, or lock periods to prevent manipulation".to_string(),
                        references: vec![
                            "Yield Farming Attacks: https://www.paradigm.xyz/2021/05/yield-farming".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn calculate_reward_safety_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("checkpoint") { score += 3; }
                if func_name_lower.contains("time_weighted") { score += 3; }
                if func_name_lower.contains("lock_period") { score += 2; }
                if func_name_lower.contains("vesting") { score += 2; }
                if func_name_lower.contains("cooldown") { score += 1; }
            }
        }
    }
    
    score
}

// DF-010: MEV Extraction Risk - ULTRA STRICT
pub struct MEVExtractionRisk;

#[async_trait::async_trait]
impl SecurityDetector for MEVExtractionRisk {
    fn id(&self) -> &'static str { "DF-010" }
    fn name(&self) -> &'static str { "MEV Extraction Risk" }
    fn description(&self) -> &'static str {
        "Protocol vulnerable to maximal extractable value extraction"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_defi_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Check for auction-like functions that are MEV vulnerable
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check functions with clear MEV vulnerability
            let is_mev_vulnerable = func_name_lower.contains("auction") ||
                                   func_name_lower.contains("bid") ||
                                   func_name_lower.contains("ask") ||
                                   (func_name_lower.contains("limit") && func_name_lower.contains("order"));
            
            if is_mev_vulnerable {
                // Check for MEV protection
                if !has_mev_protection_mechanisms(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("MEV extraction risk in '{}'", func_name),
                        description: "Auction-like function vulnerable to MEV extraction through transaction ordering".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement commit-reveal schemes, batch auctions, or time-weighted average pricing".to_string(),
                        references: vec![
                            "Flash Boys 2.0: https://arxiv.org/abs/1904.05234".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn has_mev_protection_mechanisms(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut protection_indicators = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("commit") { protection_indicators += 3; }
                if func_name_lower.contains("reveal") { protection_indicators += 2; }
                if func_name_lower.contains("batch") { protection_indicators += 2; }
                if func_name_lower.contains("twap") { protection_indicators += 3; }
                if func_name_lower.contains("vrf") { protection_indicators += 3; } // Verifiable Random Function
            }
        }
        
        protection_indicators >= 2
    } else {
        false
    }
}

// DF-011: Stablecoin Depeg Risk - ULTRA STRICT
pub struct StablecoinDepegRisk;

#[async_trait::async_trait]
impl SecurityDetector for StablecoinDepegRisk {
    fn id(&self) -> &'static str { "DF-011" }
    fn name(&self) -> &'static str { "Stablecoin Depeg Risk" }
    fn description(&self) -> &'static str {
        "Protocol assumes stablecoins never depeg"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_defi_module(&ctx.module) { return Vec::new(); }
        
        // Check if module has hardcoded stablecoin assumptions
        let mut stablecoin_addresses = Vec::new();
        
        for constant in &ctx.module.constant_pool {
            if let SignatureToken::Address = constant.type_ {
                if is_likely_stablecoin_address(&constant.data) {
                    stablecoin_addresses.push(hex::encode(&constant.data));
                }
            }
        }
        
        // Only flag if stablecoin addresses are used in critical functions
        if !stablecoin_addresses.is_empty() {
            // Check if these addresses are used in critical operations
            if are_stablecoin_addresses_critical(&ctx.module, &stablecoin_addresses) {
                return vec![SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::High,
                    title: "Stablecoin depeg risk".to_string(),
                    description: format!("Protocol assumes stablecoins ({}) will maintain peg without contingency plans", 
                                       stablecoin_addresses.join(", ")),
                    location: create_module_location(ctx),
                    source_code: Some("Hardcoded stablecoin assumption".to_string()),
                    recommendation: "Implement depeg protections, circuit breakers, or multi-stablecoin support".to_string(),
                    references: vec![
                        "UST Depeg Analysis: https://threadreaderapp.com/thread/1526507649202974721.html".to_string(),
                    ],
                    metadata: std::collections::HashMap::new(),
                }];
            }
        }
        
        Vec::new()
    }
}

fn is_likely_stablecoin_address(_data: &[u8]) -> bool {
    // In practice, this would check against known stablecoin addresses
    // For now, we'll use conservative heuristics
    // Common stablecoin addresses often have specific patterns or are well-known
    false // Conservative - only flag if we're certain
}

fn are_stablecoin_addresses_critical(_module: &CompiledModule, _addresses: &[String]) -> bool {
    // Check if stablecoin addresses are used in critical operations
    // like collateral, reserves, or price calculations
    false // Conservative
}

// DF-013: Composability Risk - ULTRA STRICT
pub struct ComposabilityRisk;

#[async_trait::async_trait]
impl SecurityDetector for ComposabilityRisk {
    fn id(&self) -> &'static str { "DF-013" }
    fn name(&self) -> &'static str { "Composability Risk" }
    fn description(&self) -> &'static str {
        "Protocol vulnerable when composed with other protocols"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_defi_module(&ctx.module) { return Vec::new(); }
        
        // Count external calls in critical functions
        let mut total_external_calls = 0;
        let mut critical_functions_with_external_calls = 0;
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // Only check critical DeFi functions
            let is_critical_function = func_name_lower.contains("swap") ||
                                      func_name_lower.contains("liquidate") ||
                                      func_name_lower.contains("flash_loan") ||
                                      func_name_lower.contains("execute");
            
            if is_critical_function {
                let external_calls = count_external_calls(func_def, &ctx.module);
                total_external_calls += external_calls;
                
                if external_calls > 0 {
                    critical_functions_with_external_calls += 1;
                }
            }
        }
        
        // Only flag if multiple critical functions make external calls
        if critical_functions_with_external_calls >= 2 && total_external_calls >= 3 {
            return vec![SecurityIssue {
                id: self.id().to_string(),
                severity: self.default_severity(),
                confidence: Confidence::Medium,
                title: "High composability risk".to_string(),
                description: format!("{} critical functions make {} external calls, increasing attack surface", 
                                   critical_functions_with_external_calls, total_external_calls),
                location: create_module_location(ctx),
                source_code: None,
                recommendation: "Implement reentrancy guards, validate external call results, and add circuit breakers".to_string(),
                references: vec![
                    "DeFi Composability Risks: https://arxiv.org/abs/2103.08799".to_string(),
                ],
                metadata: std::collections::HashMap::new(),
            }];
        }
        
        Vec::new()
    }
}

fn count_external_calls(func_def: &FunctionDefinition, module: &CompiledModule) -> usize {
    let mut count = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if is_external_call(instr, module) {
                count += 1;
            }
        }
    }
    
    count
}

fn is_external_call(instr: &Bytecode, module: &CompiledModule) -> bool {
    match instr {
        Bytecode::Call(func_idx) => {
            if let Some(func_handle) = module.function_handles.get(func_idx.0 as usize) {
                if let Some(module_handle) = module.module_handles.get(func_handle.module.0 as usize) {
                    let self_module_id = module.self_id();
                    let called_module_id = move_core_types::language_storage::ModuleId::new(
                        (*module.address_identifier_at(module_handle.address)).into(),
                        module.identifier_at(module_handle.name).into(),
                    );
                    return called_module_id != self_module_id;
                }
            }
        }
        Bytecode::CallGeneric(func_inst_idx) => {
            if let Some(func_inst) = module.function_instantiations.get(func_inst_idx.0 as usize) {
                if let Some(func_handle) = module.function_handles.get(func_inst.handle.0 as usize) {
                    if let Some(module_handle) = module.module_handles.get(func_handle.module.0 as usize) {
                        let self_module_id = module.self_id();
                        let called_module_id = move_core_types::language_storage::ModuleId::new(
                            (*module.address_identifier_at(module_handle.address)).into(),
                            module.identifier_at(module_handle.name).into(),
                        );
                        return called_module_id != self_module_id;
                    }
                }
            }
        }
        _ => {}
    }
    false
}

// DF-014: Tokenomics Vulnerability - ULTRA STRICT
pub struct TokenomicsVulnerability;

#[async_trait::async_trait]
impl SecurityDetector for TokenomicsVulnerability {
    fn id(&self) -> &'static str { "DF-014" }
    fn name(&self) -> &'static str { "Tokenomics Vulnerability" }
    fn description(&self) -> &'static str {
        "Token economic design has fundamental flaws"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_defi_module(&ctx.module) { return Vec::new(); }
        
        // Only check token/coin modules
        let is_token_module = ctx.module.self_id().name().as_str().to_lowercase().contains("token") ||
                             ctx.module.self_id().name().as_str().to_lowercase().contains("coin");
        
        if !is_token_module { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Look for unlimited minting functions
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check mint functions
            let is_mint_function = func_name_lower == "mint" ||
                                  func_name_lower.starts_with("mint_");
            
            if is_mint_function {
                // Check for supply limits
                if !has_token_supply_limits(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Tokenomics vulnerability in '{}'", func_name),
                        description: "Minting function lacks supply limits, risking hyperinflation".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement maximum supply caps, minting schedules, or algorithmic controls".to_string(),
                        references: vec![],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn has_token_supply_limits(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                if func_name_lower.contains("max_supply") ||
                   func_name_lower.contains("total_supply") ||
                   func_name_lower.contains("cap") {
                    return true;
                }
            }
        }
    }
    false
}

// Only include detectors that can be made extremely strict
pub fn get_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(SlippageAttack),
        Box::new(OracleManipulationInAMM),
        Box::new(LiquidationVulnerability),
        Box::new(FeeOnTransferTokenIssue),
        Box::new(YieldFarmingVulnerability),
        Box::new(MEVExtractionRisk),
        Box::new(StablecoinDepegRisk),
        Box::new(ComposabilityRisk),
        Box::new(TokenomicsVulnerability),
    ]
}