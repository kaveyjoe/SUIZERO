// Extended Financial Security Detectors
// Ported from addmores/financial.rs to SecurityDetector API

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition, SignatureToken},
};

// Helper function to check if function has Coin<T> parameters
fn has_coin_parameters(ctx: &DetectionContext, func_def: &FunctionDefinition) -> bool {
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let params_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
    
    params_sig.0.iter().any(|param| {
        match param {
            SignatureToken::Struct(s_idx) | 
            SignatureToken::StructInstantiation(s_idx, _) => {
                let struct_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                let struct_name = ctx.module.identifier_at(struct_handle.name);
                struct_name.as_str().to_lowercase().contains("coin")
            },
            SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                match &**inner {
                    SignatureToken::Struct(s_idx) | 
                    SignatureToken::StructInstantiation(s_idx, _) => {
                        let struct_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                        let struct_name = ctx.module.identifier_at(struct_handle.name);
                        struct_name.as_str().to_lowercase().contains("coin")
                    },
                    _ => false
                }
            },
            _ => false
        }
    })
}

// Helper function to check if function has a specific Coin<T> parameter (singular)
fn has_coin_parameter(ctx: &DetectionContext, func_def: &FunctionDefinition) -> bool {
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let params_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
    
    params_sig.0.iter().any(|param| {
        match param {
            SignatureToken::Struct(s_idx) | 
            SignatureToken::StructInstantiation(s_idx, _) => {
                let struct_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                let struct_name = ctx.module.identifier_at(struct_handle.name);
                struct_name.as_str().to_lowercase().contains("coin")
            },
            SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                match &**inner {
                    SignatureToken::Struct(s_idx) | 
                    SignatureToken::StructInstantiation(s_idx, _) => {
                        let struct_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                        let struct_name = ctx.module.identifier_at(struct_handle.name);
                        struct_name.as_str().to_lowercase().contains("coin")
                    },
                    _ => false
                }
            },
            _ => false
        }
    })
}

// Helper function to check if function is financial in nature
fn is_financial_function(ctx: &DetectionContext, func_def: &FunctionDefinition) -> bool {
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    let func_name_lower = func_name.as_str().to_lowercase();
    
    // Check for financial keywords in function name
    let has_financial_keywords = [
        "swap", "trade", "buy", "sell", "mint", "burn", "transfer", "deposit",
        "withdraw", "stake", "unstake", "claim", "reward", "vest", "unlock",
        "fund", "pool", "liquidity", "lp", "pair", "router", "factory",
        "coin", "token", "usdc", "usdt", "eth", "btc", "weth", "wrapped",
        "amm", "dex", "farm", "harvest", "governance", "vote", "treasury"
    ].iter().any(|&keyword| func_name_lower.contains(keyword));
    
    // Check for financial parameters
    let has_financial_params = {
        let params_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
        params_sig.0.iter().any(|param| {
            match param {
                SignatureToken::Struct(s_idx) | 
                SignatureToken::StructInstantiation(s_idx, _) => {
                    let struct_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                    let struct_name = ctx.module.identifier_at(struct_handle.name);
                    let struct_name_lower = struct_name.as_str().to_lowercase();
                    struct_name_lower.contains("coin") || struct_name_lower.contains("token") || 
                    struct_name_lower.contains("balance") || struct_name_lower.contains("wallet")
                },
                SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                    match &**inner {
                        SignatureToken::Struct(s_idx) | 
                        SignatureToken::StructInstantiation(s_idx, _) => {
                            let struct_handle = &ctx.module.struct_handles[s_idx.0 as usize];
                            let struct_name = ctx.module.identifier_at(struct_handle.name);
                            let struct_name_lower = struct_name.as_str().to_lowercase();
                            struct_name_lower.contains("coin") || struct_name_lower.contains("token") || 
                            struct_name_lower.contains("balance") || struct_name_lower.contains("wallet")
                        },
                        _ => false
                    }
                },
                _ => false
            }
        })
    };
    
    // Check for financial operations in bytecode
    let has_financial_ops = if let Some(code) = &func_def.code {
        code.code.iter().any(|instr| {
            if let Some(called_func) = get_function_name(instr, &ctx.module) {
                let called_lower = called_func.to_lowercase();
                called_lower.contains("balance") || called_lower.contains("transfer") || 
                called_lower.contains("coin") || called_lower.contains("token")
            } else { false }
        })
    } else { false };
    
    has_financial_keywords || has_financial_params || has_financial_ops
}

// Helper function to create location
fn create_location(ctx: &DetectionContext, func_def: &FunctionDefinition, idx: u16) -> CodeLocation {
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: idx,
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

// ========== 1. FLASH LOAN ATTACK ==========
pub struct FlashLoanAttackDetector;

#[async_trait::async_trait]
impl SecurityDetector for FlashLoanAttackDetector {
    fn id(&self) -> &'static str { "FIN-001" }
    fn name(&self) -> &'static str { "Flash Loan Attack" }
    fn description(&self) -> &'static str { "Detects flash loan attack vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) {
                // Check for lending/borrowing patterns
                if func_name.as_str().contains("borrow") || func_name.as_str().contains("lend") || 
                   func_name.as_str().contains("loan") {
                    
                    if let Some(code) = &func_def.code {
                        // Check for price oracle usage without flash loan protection
                        let has_oracle = code.code.iter().any(|instr| {
                            if let Some(called_func) = get_function_name(instr, &ctx.module) {
                                called_func.contains("price") || called_func.contains("oracle")
                            } else { false }
                        });
                        
                        let has_protection = code.code.iter().any(|instr| {
                            if let Some(called_func) = get_function_name(instr, &ctx.module) {
                                called_func.contains("twap") || called_func.contains("time_weighted") ||
                                called_func.contains("flash_loan_check")
                            } else { false }
                        });
                        
                        if has_oracle && !has_protection {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: format!("Flash loan vulnerability in '{}'", func_name),
                                description: "Lending function uses price oracles without flash loan protection".to_string(),
                                location: create_location(ctx, func_def, 0),
                                source_code: Some(func_name.to_string()),
                                recommendation: "Use time-weighted average prices (TWAP). Implement transaction volume limits. Add minimum time requirements for loan positions.".to_string(),
                                references: vec![
                                    "https://blog.openzeppelin.com/exploiting-math-in-smart-contracts-flash-loans-and-manipulation/".to_string(),
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

// ========== 2. FLASH MINT ATTACK ==========
pub struct FlashMintAttackDetector;

#[async_trait::async_trait]
impl SecurityDetector for FlashMintAttackDetector {
    fn id(&self) -> &'static str { "FIN-002" }
    fn name(&self) -> &'static str { "Flash Mint Attack" }
    fn description(&self) -> &'static str { "Detects flash mint attack vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("mint") || func_name.as_str().contains("create_")) {
                if let Some(code) = &func_def.code {
                    // Check if it's minting a capability (should be handled by AC detectors)
                    let is_cap_mint = code.code.iter().any(|instr| {
                        if let Bytecode::Pack(idx) = instr {
                            let struct_def = &ctx.module.struct_defs[idx.0 as usize];
                            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
                            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str();
                            struct_name.contains("Cap") || struct_name.contains("Owner") || struct_name.contains("Admin")
                        } else { false }
                    });

                    if is_cap_mint { continue; }

                    // Check if function has proper authorization (e.g., requires capability)
                    let has_auth_check = {
                        let mut found_sender_check = false;
                        let mut found_assert = false;
                        
                        for instr in &code.code {
                            if let Some(called_func) = get_function_name(instr, &ctx.module) {
                                let name = called_func.to_string().to_lowercase();
                                if name.contains("tx_context::sender") || name.contains("ctx::sender") {
                                    found_sender_check = true;
                                }
                                if name.contains("assert") {
                                    found_assert = true;
                                }
                            }
                            
                            // Check for comparison operations that might be part of authorization checks
                            if matches!(instr, Bytecode::Eq | Bytecode::Neq) {
                                found_assert = true; // Likely part of an assert statement
                            }
                        }
                        
                        // Check function parameters to see if it accepts a capability
                        let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                        let func_name = ctx.module.identifier_at(func_handle.name);
                        let func_name_lower = func_name.as_str().to_lowercase();
                        
                        // Skip if this is LP minting (not token minting)
                        let is_lp_mint = func_name_lower.contains("mint") && (
                            has_coin_parameters(ctx, func_def) ||
                            func_name_lower.contains("pair") ||
                            func_name_lower.contains("liquidity") ||
                            func_name_lower.contains("lp")
                        );
                        
                        if is_lp_mint {
                            continue; // Skip LP minting functions
                        }
                        
                        let params_sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                        let has_cap_param = params_sig.0.iter().any(|param| {
                            if let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = param {
                                if let SignatureToken::Struct(s_idx) | SignatureToken::StructInstantiation(s_idx, _) = &**inner {
                                    let idx = s_idx.0 as usize;
                                    if idx < ctx.module.struct_defs.len() {
                                        let struct_def = &ctx.module.struct_defs[idx];
                                        let handle_idx = struct_def.struct_handle.0 as usize;
                                        if handle_idx < ctx.module.struct_handles.len() {
                                            let struct_handle = &ctx.module.struct_handles[handle_idx];
                                            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
                                            struct_name.contains("cap") || struct_name.contains("admin") || struct_name.contains("owner")
                                        } else { false }
                                    } else { false }
                                } else { false }
                            } else { false }
                        });
                        
                        // Authorization is confirmed if we have both sender check and assert, OR if function has capability parameter
                        (found_sender_check && found_assert) || has_cap_param
                    };
                    
                    // Check for supply cap
                    let has_supply_cap = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            let name = called_func.to_lowercase();
                            name.contains("total_supply") || name.contains("cap") ||
                            name.contains("max_supply") || name.contains("supply_cap")
                        } else { false }
                    });
                    
                    // Check for time delay
                    let has_time_delay = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("timestamp") || called_func.contains("delay") ||
                            called_func.contains("cooldown")
                        } else { false }
                    });
                    
                    // Only flag as vulnerability if no authorization checks AND no supply/time limits
                    if !has_auth_check && (!has_supply_cap || !has_time_delay) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Flash mint vulnerability in '{}'", func_name),
                            description: "Minting function lacks proper authorization checks or supply/time limits".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement minting limits per transaction. Add time delays between mints. Require proper capability-based authorization.".to_string(),
                            references: vec![
                                "https://ethereum.org/en/developers/tutorials/erc20-permit-transfer-from/".to_string(),
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

// ========== 3. INTEREST RATE MANIPULATION ==========
pub struct InterestRateManipulationDetector;

#[async_trait::async_trait]
impl SecurityDetector for InterestRateManipulationDetector {
    fn id(&self) -> &'static str { "FIN-003" }
    fn name(&self) -> &'static str { "Interest Rate Manipulation" }
    fn description(&self) -> &'static str { "Detects interest rate manipulation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("interest") || func_name.as_str().contains("rate")) {
                if let Some(code) = &func_def.code {
                    let has_governance = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("governance") || called_func.contains("admin") ||
                            called_func.contains("owner")
                        } else { false }
                    });
                    
                    if !has_governance {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Medium,
                            title: format!("Interest rate manipulation risk in '{}'", func_name),
                            description: "Interest rate can be manipulated without governance controls".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Use time-weighted interest calculations. Add governance controls for rate changes. Implement rate change limits.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 4. LIQUIDITY DRAIN ==========
pub struct LiquidityDrainDetector;

#[async_trait::async_trait]
impl SecurityDetector for LiquidityDrainDetector {
    fn id(&self) -> &'static str { "FIN-004" }
    fn name(&self) -> &'static str { "Liquidity Drain" }
    fn description(&self) -> &'static str { "Detects liquidity drain vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) {
                // Check if this is a canonical AMM burn function (which is safe by design)
                let is_canonical_burn = func_name.as_str().contains("burn") && has_coin_parameter(ctx, func_def);
                
                if (func_name.as_str().contains("withdraw") || func_name.as_str().contains("remove_liquidity") || func_name.as_str().contains("burn")) && !is_canonical_burn {
                    if let Some(code) = &func_def.code {
                        let has_limit = code.code.iter().any(|instr| {
                            if let Some(called_func) = get_function_name(instr, &ctx.module) {
                                called_func.contains("limit") || called_func.contains("cap") ||
                                called_func.contains("max_withdrawal")
                            } else { false }
                        });
                        
                        if !has_limit {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: format!("Liquidity drain risk in '{}'", func_name),
                                description: "Withdrawal function lacks limits allowing complete liquidity drain".to_string(),
                                location: create_location(ctx, func_def, 0),
                                source_code: Some(func_name.to_string()),
                                recommendation: "Implement withdrawal limits. Add time locks for large withdrawals. Use bonding curves for liquidity.".to_string(),
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

// ========== 5. SLIPPAGE ATTACK ==========
pub struct SlippageAttackDetector;

#[async_trait::async_trait]
impl SecurityDetector for SlippageAttackDetector {
    fn id(&self) -> &'static str { "FIN-005" }
    fn name(&self) -> &'static str { "Slippage Attack" }
    fn description(&self) -> &'static str { "Detects slippage attack vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("swap") || func_name.as_str().contains("trade")) {
                if let Some(code) = &func_def.code {
                    let has_slippage_protection = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("min_amount") || called_func.contains("slippage") ||
                            called_func.contains("min_output")
                        } else { false }
                    });
                    
                    if !has_slippage_protection {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Slippage attack vulnerability in '{}'", func_name),
                            description: "Trading function lacks slippage protection".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement maximum slippage limits. Use TWAP for large trades. Add price impact calculations.".to_string(),
                            references: vec![
                                "https://www.paradigm.xyz/2020/08/ethereum-is-a-dark-forest".to_string(),
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

// ========== 6. PRICE IMPACT ABUSE ==========
pub struct PriceImpactAbuseDetector;

#[async_trait::async_trait]
impl SecurityDetector for PriceImpactAbuseDetector {
    fn id(&self) -> &'static str { "FIN-006" }
    fn name(&self) -> &'static str { "Price Impact Abuse" }
    fn description(&self) -> &'static str { "Detects price impact abuse vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("swap") || func_name.as_str().contains("buy")) {
                if let Some(code) = &func_def.code {
                    let has_impact_limit = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("price_impact") || called_func.contains("max_trade_size")
                        } else { false }
                    });
                    
                    if !has_impact_limit {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Medium,
                            title: format!("Price impact abuse in '{}'", func_name),
                            description: "Large trades can manipulate prices without impact limits".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement trade size limits. Use time-weighted prices. Add circuit breakers for price movements.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 7. ARBITRAGE EXPLOITATION ==========
pub struct ArbitrageExploitationDetector;

#[async_trait::async_trait]
impl SecurityDetector for ArbitrageExploitationDetector {
    fn id(&self) -> &'static str { "FIN-007" }
    fn name(&self) -> &'static str { "Arbitrage Exploitation" }
    fn description(&self) -> &'static str { "Detects arbitrage exploitation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Low }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check for multiple price sources without synchronization in financial functions
        let mut price_functions = Vec::new();
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only consider financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("get_price") || func_name.as_str().contains("price_of")) {
                price_functions.push(func_name.to_string());
            }
        }
        
        if price_functions.len() > 1 {
            issues.push(SecurityIssue {
                id: self.id().to_string(),
                severity: self.default_severity(),
                confidence: Confidence::Low,
                title: "Arbitrage opportunity detected".to_string(),
                description: format!("Multiple price sources ({}) may enable arbitrage", price_functions.len()),
                location: create_module_location(ctx),
                source_code: None,
                recommendation: "Implement price synchronization. Use common oracle sources. Add arbitrage resistance.".to_string(),
                references: vec![],
                metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}

// ========== 8. ECONOMIC CENSORSHIP ==========
pub struct EconomicCensorshipDetector;

#[async_trait::async_trait]
impl SecurityDetector for EconomicCensorshipDetector {
    fn id(&self) -> &'static str { "FIN-008" }
    fn name(&self) -> &'static str { "Economic Censorship" }
    fn description(&self) -> &'static str { "Detects economic censorship vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Low }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("vote") || func_name.as_str().contains("governance")) {
                if let Some(code) = &func_def.code {
                    let uses_token_weight = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("balance") || called_func.contains("weight")
                        } else { false }
                    });
                    
                    let has_anti_whale = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("quadratic") || called_func.contains("cap") ||
                            called_func.contains("max_vote")
                        } else { false }
                    });
                    
                    if uses_token_weight && !has_anti_whale {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Whale dominance risk in '{}'", func_name),
                            description: "Voting power based solely on token balance enables whale control".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement quadratic voting. Use vote capping. Add time-weighted voting power.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 9. TOKEN IMBALANCE ==========
pub struct TokenImbalanceDetector;

#[async_trait::async_trait]
impl SecurityDetector for TokenImbalanceDetector {
    fn id(&self) -> &'static str { "FIN-009" }
    fn name(&self) -> &'static str { "Token Imbalance" }
    fn description(&self) -> &'static str { "Detects token imbalance vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && func_name.as_str().contains("add_liquidity") {
                if let Some(code) = &func_def.code {
                    let requires_balanced = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("balance_check") || called_func.contains("ratio")
                        } else { false }
                    });
                    
                    if !requires_balanced {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Token imbalance risk in '{}'", func_name),
                            description: "Liquidity provision allows one-sided deposits".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Require balanced liquidity provision. Implement incentives for balanced liquidity. Add maximum imbalance limits.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 10. REWARD MANIPULATION ==========
pub struct RewardManipulationDetector;

#[async_trait::async_trait]
impl SecurityDetector for RewardManipulationDetector {
    fn id(&self) -> &'static str { "FIN-010" }
    fn name(&self) -> &'static str { "Reward Manipulation" }
    fn description(&self) -> &'static str { "Detects reward manipulation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("claim") || func_name.as_str().contains("reward")) {
                if let Some(code) = &func_def.code {
                    let has_rate_limit = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("cooldown") || called_func.contains("rate_limit") ||
                            called_func.contains("last_claim")
                        } else { false }
                    });
                    
                    if !has_rate_limit {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Reward manipulation in '{}'", func_name),
                            description: "Reward claiming lacks rate limits or cooldowns".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement claiming cooldowns. Add reward rate limits. Use time-weighted reward calculations.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 11. STAKING EXPLOIT ==========
pub struct StakingExploitDetector;

#[async_trait::async_trait]
impl SecurityDetector for StakingExploitDetector {
    fn id(&self) -> &'static str { "FIN-011" }
    fn name(&self) -> &'static str { "Staking Exploit" }
    fn description(&self) -> &'static str { "Detects staking exploit vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("stake") || func_name.as_str().contains("unstake")) {
                if let Some(code) = &func_def.code {
                    let has_lock_period = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("lock") || called_func.contains("unlock_time") ||
                            called_func.contains("vesting")
                        } else { false }
                    });
                    
                    if !has_lock_period && func_name.as_str().contains("unstake") {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Instant unstaking in '{}'", func_name),
                            description: "Unstaking lacks lock period enabling flash staking attacks".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement minimum staking periods. Add unstaking delays. Use vesting schedules.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 12. YIELD FARMING ATTACK ==========
pub struct YieldFarmingAttackDetector;

#[async_trait::async_trait]
impl SecurityDetector for YieldFarmingAttackDetector {
    fn id(&self) -> &'static str { "FIN-012" }
    fn name(&self) -> &'static str { "Yield Farming Attack" }
    fn description(&self) -> &'static str { "Detects yield farming attack vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("farm") || func_name.as_str().contains("harvest")) {
                if let Some(code) = &func_def.code {
                    let has_anti_farm_hop = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("deposit_time") || called_func.contains("min_duration")
                        } else { false }
                    });
                    
                    if !has_anti_farm_hop {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Yield farming exploit in '{}'", func_name),
                            description: "Farming rewards lack minimum duration enabling farm hopping".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement minimum farming duration. Add deposit time tracking. Use time-weighted rewards.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 13. LIQUIDITY POOL DRAIN ==========
pub struct LiquidityPoolDrainDetector;

#[async_trait::async_trait]
impl SecurityDetector for LiquidityPoolDrainDetector {
    fn id(&self) -> &'static str { "FIN-013" }
    fn name(&self) -> &'static str { "Liquidity Pool Drain" }
    fn description(&self) -> &'static str { "Detects liquidity pool drain vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("remove_liquidity") || func_name.as_str().contains("withdraw_pool")) {
                if let Some(code) = &func_def.code {
                    let has_min_liquidity = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("min_liquidity") || called_func.contains("reserve_ratio")
                        } else { false }
                    });
                    
                    if !has_min_liquidity {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Pool drain risk in '{}'", func_name),
                            description: "Pool withdrawal lacks minimum liquidity protection".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Enforce minimum pool liquidity. Implement withdrawal limits. Add emergency pause functionality.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 14. AMM MANIPULATION ==========
pub struct AMMManipulationDetector;

#[async_trait::async_trait]
impl SecurityDetector for AMMManipulationDetector {
    fn id(&self) -> &'static str { "FIN-014" }
    fn name(&self) -> &'static str { "AMM Manipulation" }
    fn description(&self) -> &'static str { "Detects AMM manipulation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && func_name.as_str().contains("swap") {
                if let Some(code) = &func_def.code {
                    // Check for constant product formula usage
                    let uses_constant_product = code.code.iter().any(|instr| {
                        matches!(instr, Bytecode::Mul)
                    });
                    
                    let has_fee = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("fee") || called_func.contains("commission")
                        } else { false }
                    });
                    
                    if uses_constant_product && !has_fee {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("AMM manipulation risk in '{}'", func_name),
                            description: "AMM swap lacks trading fees making manipulation cheaper".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement trading fees. Add price impact limits. Use TWAP for price discovery.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 15. CONSTANT PRODUCT EXPLOIT ==========
pub struct ConstantProductExploitDetector;

#[async_trait::async_trait]
impl SecurityDetector for ConstantProductExploitDetector {
    fn id(&self) -> &'static str { "FIN-015" }
    fn name(&self) -> &'static str { "Constant Product Exploit" }
    fn description(&self) -> &'static str { "Detects constant product formula exploit vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("swap") || func_name.as_str().contains("get_amount")) {
                if let Some(code) = &func_def.code {
                    // Look for division operations (common in AMM formulas)
                    let has_division = code.code.iter().any(|instr| {
                        matches!(instr, Bytecode::Div)
                    });
                    
                    let has_overflow_check = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("checked") || called_func.contains("safe")
                        } else { false }
                    });
                    
                    if has_division && !has_overflow_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Constant product calculation issue in '{}'", func_name),
                            description: "AMM calculations lack overflow protection".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Use checked arithmetic. Implement proper rounding. Add overflow/underflow protection.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 16. BONDING CURVE ATTACK ==========
pub struct BondingCurveAttackDetector;

#[async_trait::async_trait]
impl SecurityDetector for BondingCurveAttackDetector {
    fn id(&self) -> &'static str { "FIN-016" }
    fn name(&self) -> &'static str { "Bonding Curve Attack" }
    fn description(&self) -> &'static str { "Detects bonding curve attack vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("bonding") || func_name.as_str().contains("curve")) {
                if let Some(code) = &func_def.code {
                    let has_curve_params = code.code.iter().any(|instr| {
                        matches!(instr, Bytecode::LdU64(_) | Bytecode::LdU128(_))
                    });
                    
                    if has_curve_params {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Bonding curve manipulation risk in '{}'", func_name),
                            description: "Bonding curve parameters may be manipulatable".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Validate curve parameters. Implement parameter bounds. Add governance for curve changes.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 17. VESTING SCHEDULE BYPASS ==========
pub struct VestingScheduleBypassDetector;

#[async_trait::async_trait]
impl SecurityDetector for VestingScheduleBypassDetector {
    fn id(&self) -> &'static str { "FIN-017" }
    fn name(&self) -> &'static str { "Vesting Schedule Bypass" }
    fn description(&self) -> &'static str { "Detects vesting schedule bypass vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("vest") || func_name.as_str().contains("unlock")) {
                if let Some(code) = &func_def.code {
                    let has_time_check = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("timestamp") || called_func.contains("epoch") ||
                            called_func.contains("time")
                        } else { false }
                    });
                    
                    if !has_time_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Vesting bypass in '{}'", func_name),
                            description: "Vesting function lacks time validation enabling bypasses".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement strict time checks. Validate vesting schedules. Add cliff periods.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 18. AIRDROP EXPLOITATION ==========
pub struct AirdropExploitationDetector;

#[async_trait::async_trait]
impl SecurityDetector for AirdropExploitationDetector {
    fn id(&self) -> &'static str { "FIN-018" }
    fn name(&self) -> &'static str { "Airdrop Exploitation" }
    fn description(&self) -> &'static str { "Detects airdrop exploitation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Low }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("airdrop") || func_name.as_str().contains("claim")) {
                if let Some(code) = &func_def.code {
                    let has_sybil_protection = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("merkle") || called_func.contains("proof") ||
                            called_func.contains("whitelist")
                        } else { false }
                    });
                    
                    if !has_sybil_protection {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Airdrop sybil attack in '{}'", func_name),
                            description: "Airdrop lacks sybil resistance enabling multiple claims".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement merkle proofs. Use whitelists. Add identity verification. Limit claims per address.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 19. TOKEN WHITELIST BYPASS ==========
pub struct TokenWhitelistBypassDetector;

#[async_trait::async_trait]
impl SecurityDetector for TokenWhitelistBypassDetector {
    fn id(&self) -> &'static str { "FIN-019" }
    fn name(&self) -> &'static str { "Token Whitelist Bypass" }
    fn description(&self) -> &'static str { "Detects token whitelist bypass vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Low }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && func_name.as_str().contains("whitelist") {
                if let Some(code) = &func_def.code {
                    let has_validation = code.code.iter().any(|instr| {
                        matches!(instr, Bytecode::BrTrue(_) | Bytecode::BrFalse(_))
                    });
                    
                    if !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Whitelist bypass risk in '{}'", func_name),
                            description: "Whitelist function may lack proper validation".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement strict whitelist checks. Validate token addresses. Add removal mechanisms.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 20. FEE MANIPULATION ==========
pub struct FeeManipulationDetector;

#[async_trait::async_trait]
impl SecurityDetector for FeeManipulationDetector {
    fn id(&self) -> &'static str { "FIN-020" }
    fn name(&self) -> &'static str { "Fee Manipulation" }
    fn description(&self) -> &'static str { "Detects fee manipulation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Low }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check financial functions
            if is_financial_function(ctx, func_def) && (func_name.as_str().contains("set_fee") || func_name.as_str().contains("update_fee")) {
                if let Some(code) = &func_def.code {
                    let has_bounds_check = code.code.iter().any(|instr| {
                        matches!(instr, Bytecode::Lt | Bytecode::Le | Bytecode::Gt | Bytecode::Ge)
                    });
                    
                    let has_governance = code.code.iter().any(|instr| {
                        if let Some(called_func) = get_function_name(instr, &ctx.module) {
                            called_func.contains("admin") || called_func.contains("owner") ||
                            called_func.contains("governance")
                        } else { false }
                    });
                    
                    if !has_bounds_check || !has_governance {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Low,
                            title: format!("Fee manipulation in '{}'", func_name),
                            description: "Fee setting lacks bounds checks or governance controls".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement fee bounds (e.g., max 5%). Add governance controls. Use time-locked fee changes.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// Helper function to get function name from bytecode
fn get_function_name(instr: &Bytecode, module: &move_binary_format::CompiledModule) -> Option<String> {
    crate::utils::get_function_name(instr, module).map(|s| s.to_string())
}
