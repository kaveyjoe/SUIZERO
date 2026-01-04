// src/detectors/bridges/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use crate::utils::{create_location, create_module_location};
use move_binary_format::{file_format::*, access::ModuleAccess};

// STRICTER: Determine if this is actually a bridge module
fn is_bridge_related_context(ctx: &DetectionContext) -> bool {
    let module_name = ctx.module.self_id().name().as_str().to_lowercase();
    
    // Require explicit bridge indicators
    let has_bridge_name = module_name.contains("bridge") || 
                         module_name.contains("crosschain") ||
                         module_name.contains("portal") ||
                         module_name.contains("router") ||
                         module_name.contains("wormhole") ||
                         module_name.contains("layerzero") ||
                         module_name.contains("axelar") ||
                         module_name.contains("multichain");
    
    if !has_bridge_name {
        return false;
    }
    
    // Additional validation: Check for bridge-related structs
    let has_bridge_structs = ctx.module.struct_defs.iter().any(|struct_def| {
        let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
        let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
        struct_name.contains("message") ||
        struct_name.contains("payload") ||
        struct_name.contains("vault") ||
        struct_name.contains("lockbox") ||
        struct_name.contains("validator") ||
        struct_name.contains("proof")
    });
    
    // Check for bridge-specific functions
    let bridge_function_count = ctx.module.function_defs.iter()
        .filter(|func_def| {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("lock") ||
            func_name.contains("unlock") ||
            func_name.contains("mint") ||
            func_name.contains("burn") ||
            func_name.contains("relay") ||
            func_name.contains("attest")
        })
        .count();
    
    // Only flag as bridge if multiple indicators present
    has_bridge_name && (has_bridge_structs || bridge_function_count >= 2)
}

// BR-001: Validator Collusion - STRICTER
pub struct ValidatorCollusion;

#[async_trait::async_trait]
impl SecurityDetector for ValidatorCollusion {
    fn id(&self) -> &'static str { "BR-001" }
    fn name(&self) -> &'static str { "Validator Collusion" }
    fn description(&self) -> &'static str {
        "Bridge validators can collude to steal funds"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_bridge_related_context(ctx) { return Vec::new(); }
        
        // Only check if module has validator-related structs
        let has_validator_struct = ctx.module.struct_defs.iter().any(|struct_def| {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            struct_name.contains("validator") || struct_name.contains("signer") || struct_name.contains("guardian")
        });
        
        if !has_validator_struct { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: Only check actual validation functions
            let is_validation_function = func_name_lower.contains("validate_transfer") ||
                                        func_name_lower.contains("verify_signatures") ||
                                        func_name_lower.contains("check_quorum") ||
                                        (func_name_lower.contains("consensus") && 
                                         func_name_lower.contains("verify"));
            
            if is_validation_function {
                // Check for proper threshold signatures with stricter criteria
                let security_score = calculate_validator_security_score(func_def, &ctx.module);
                
                if security_score < 3 { // Require multiple security measures
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: calculate_confidence(func_def, &ctx.module),
                        title: format!("Validator collusion risk in '{}'", func_name),
                        description: "Bridge validation lacks adequate protection against validator collusion".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement multi-sig with 2/3+ thresholds, validator slashing, decentralized selection, and fraud proofs".to_string(),
                        references: vec![
                            "Bridge Security Best Practices: https://ethereum.org/en/developers/docs/bridges/security/".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// BR-002: Message Replay Attack - STRICTER
pub struct MessageReplayAttack;

#[async_trait::async_trait]
impl SecurityDetector for MessageReplayAttack {
    fn id(&self) -> &'static str { "BR-002" }
    fn name(&self) -> &'static str { "Message Replay Attack" }
    fn description(&self) -> &'static str {
        "Cross-chain messages can be replayed"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_bridge_related_context(ctx) { return Vec::new(); }
        
        // Check if this module actually handles cross-chain messages
        let has_message_struct = ctx.module.struct_defs.iter().any(|struct_def| {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            struct_name.contains("message") || struct_name.contains("crosschain") || struct_name.contains("payload")
        });
        
        if !has_message_struct { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: Only check functions that process incoming messages
            let is_message_processing_function = func_name_lower.contains("receive_message") ||
                                                func_name_lower.contains("process_payload") ||
                                                func_name_lower.contains("execute_vault") ||
                                                (func_name_lower.contains("handle") && 
                                                 (func_name_lower.contains("message") || func_name_lower.contains("transfer")));
            
            if is_message_processing_function {
                // Check for replay protection with stricter criteria
                let replay_protection_score = calculate_replay_protection_score(func_def, &ctx.module);
                
                if replay_protection_score < 2 { // Require multiple replay protection measures
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if replay_protection_score == 0 { 
                            Confidence::High 
                        } else { 
                            Confidence::Medium 
                        },
                        title: format!("Message replay attack in '{}'", func_name),
                        description: "Bridge message processing lacks robust replay protection".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Include unique nonces, chain IDs, timestamps, and message hashes in all cross-chain messages".to_string(),
                        references: vec![
                            "CWE-294".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// BR-003: Economic Attack - STRICTER
pub struct EconomicAttack;

#[async_trait::async_trait]
impl SecurityDetector for EconomicAttack {
    fn id(&self) -> &'static str { "BR-003" }
    fn name(&self) -> &'static str { "Economic Attack" }
    fn description(&self) -> &'static str {
        "Bridge can be economically attacked through liquidity manipulation"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_bridge_related_context(ctx) { return Vec::new(); }
        
        // Check for liquidity pool mechanisms
        let has_liquidity_pool = ctx.module.struct_defs.iter().any(|struct_def| {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            struct_name.contains("pool") || struct_name.contains("vault") || struct_name.contains("reserve")
        });
        
        if !has_liquidity_pool { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: Only check liquidity management functions
            let is_liquidity_function = func_name_lower.contains("withdraw_liquidity") ||
                                       func_name_lower.contains("add_reserves") ||
                                       func_name_lower.contains("drain_pool") ||
                                       (func_name_lower.contains("liquidity") && 
                                        (func_name_lower.contains("remove") || func_name_lower.contains("withdraw")));
            
            if is_liquidity_function {
                // Check for economic attack protections
                let economic_security_score = calculate_economic_security_score(func_def, &ctx.module);
                
                if economic_security_score < 2 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: calculate_confidence(func_def, &ctx.module),
                        title: format!("Economic attack risk in '{}'", func_name),
                        description: "Bridge liquidity function vulnerable to economic attacks".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement withdrawal limits, time delays, collateral requirements, and circuit breakers".to_string(),
                        references: vec![
                            "https://vitalik.ca/general/2021/01/11/recovery.html".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// BR-005: Oracle Dependency Risk - STRICTER
pub struct OracleDependencyRisk;

#[async_trait::async_trait]
impl SecurityDetector for OracleDependencyRisk {
    fn id(&self) -> &'static str { "BR-005" }
    fn name(&self) -> &'static str { "Oracle Dependency Risk" }
    fn description(&self) -> &'static str {
        "Bridge depends on vulnerable price oracles"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_bridge_related_context(ctx) { return Vec::new(); }
        
        // Count oracle dependencies with stricter criteria
        let mut oracle_calls = 0;
        let mut unvalidated_oracle_calls = 0;
        
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                for instr in &code.code {
                    if is_oracle_call(instr, &ctx.module) {
                        oracle_calls += 1;
                        
                        // Check if this oracle call is validated
                        if !is_validated_oracle_call(func_def, &ctx.module) {
                            unvalidated_oracle_calls += 1;
                        }
                    }
                }
            }
        }
        
        // Only flag if there are multiple unvalidated oracle calls
        if unvalidated_oracle_calls >= 2 {
            return vec![SecurityIssue {
                id: self.id().to_string(),
                severity: self.default_severity(),
                confidence: if unvalidated_oracle_calls > 3 { 
                    Confidence::High 
                } else { 
                    Confidence::Medium 
                },
                title: "Oracle dependency risk in bridge".to_string(),
                description: format!("Bridge depends on {} unvalidated oracle calls, creating single points of failure", unvalidated_oracle_calls),
                location: create_module_location(ctx),
                source_code: None,
                recommendation: "Use multiple oracle sources, implement price validation, add circuit breakers, and require consensus".to_string(),
                references: vec![],
                metadata: std::collections::HashMap::new(),
            }];
        }
        
        Vec::new()
    }
}

// BR-006: Infinite Mint Attack - STRICTER
pub struct InfiniteMintAttack;

#[async_trait::async_trait]
impl SecurityDetector for InfiniteMintAttack {
    fn id(&self) -> &'static str { "BR-006" }
    fn name(&self) -> &'static str { "Infinite Mint Attack" }
    fn description(&self) -> &'static str {
        "Bridge can mint unlimited tokens on destination chain"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_bridge_related_context(ctx) { return Vec::new(); }
        
        // Check if this is a minting bridge (wrapped assets)
        let is_minting_bridge = ctx.module.struct_defs.iter().any(|struct_def| {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            struct_name.contains("wrapped") || struct_name.contains("bridged") || struct_name.contains("synthetic")
        });
        
        if !is_minting_bridge { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: Only check actual minting functions
            let is_minting_function = func_name_lower == "mint" ||
                                     func_name_lower.contains("mint_bridged") ||
                                     func_name_lower.contains("create_wrapped") ||
                                     (func_name_lower.contains("mint") && 
                                      func_name_lower.contains("token"));
            
            if is_minting_function {
                // Check for minting limits with stricter criteria
                let minting_limit_score = calculate_minting_limit_score(func_def, &ctx.module);
                
                if minting_limit_score < 2 { // Require multiple limit checks
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if minting_limit_score == 0 { 
                            Confidence::High 
                        } else { 
                            Confidence::Medium 
                        },
                        title: format!("Infinite mint attack risk in '{}'", func_name),
                        description: "Bridge minting function lacks adequate limits and controls".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement daily limits, collateral requirements, governance controls, and emergency shutdowns".to_string(),
                        references: vec![],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// BR-009: Governance Takeover - STRICTER
pub struct GovernanceTakeover;

#[async_trait::async_trait]
impl SecurityDetector for GovernanceTakeover {
    fn id(&self) -> &'static str { "BR-009" }
    fn name(&self) -> &'static str { "Governance Takeover" }
    fn description(&self) -> &'static str {
        "Bridge governance can be taken over by attackers"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_bridge_related_context(ctx) { return Vec::new(); }
        
        // Check if module has governance capabilities
        let has_governance_struct = ctx.module.struct_defs.iter().any(|struct_def| {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            struct_name.contains("governance") || struct_name.contains("admin") || struct_name.contains("owner")
        });
        
        if !has_governance_struct { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: Only check critical governance functions
            let is_critical_governance_function = func_name_lower.contains("upgrade_contract") ||
                                                 func_name_lower.contains("change_admin") ||
                                                 func_name_lower.contains("set_validators") ||
                                                 func_name_lower.contains("emergency_pause") ||
                                                 (func_name_lower.contains("transfer") && 
                                                  func_name_lower.contains("ownership"));
            
            if is_critical_governance_function {
                // Check for governance security measures
                let governance_security_score = calculate_governance_security_score(func_def, &ctx.module);
                
                if governance_security_score < 3 { // Require strong governance security
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: calculate_confidence(func_def, &ctx.module),
                        title: format!("Governance takeover risk in '{}'", func_name),
                        description: "Critical bridge governance function lacks adequate security measures".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement time-locks, multi-sig requirements, emergency shutdown mechanisms, and voting delays".to_string(),
                        references: vec![],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// Enhanced helper functions with stricter criteria
fn calculate_validator_security_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("threshold") { score += 2; }
                if func_name_lower.contains("multisig") { score += 2; }
                if func_name_lower.contains("quorum") { score += 1; }
                if func_name_lower.contains("consensus") { score += 1; }
                if func_name_lower.contains("slashing") { score += 3; }
                if func_name_lower.contains("fraud_proof") { score += 3; }
                if func_name_lower.contains("bond") { score += 2; }
            }
        }
    }
    
    score
}

fn calculate_replay_protection_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("check_nonce") { score += 3; }
                if func_name_lower.contains("validate_sequence") { score += 3; }
                if func_name_lower.contains("replay_protection") { score += 2; }
                if func_name_lower.contains("chain_id") { score += 2; }
                if func_name_lower.contains("timestamp") { score += 1; }
                if func_name_lower.contains("message_hash") { score += 1; }
            }
        }
    }
    
    score
}

fn is_oracle_call(instr: &Bytecode, module: &CompiledModule) -> bool {
    if let Some(func_name) = crate::utils::get_function_name(instr, module) {
        let func_name_lower = func_name.as_str().to_lowercase();
        
        // Only flag actual oracle calls, not just functions with "oracle" in name
        return func_name_lower.contains("get_price") ||
               func_name_lower.contains("price_feed") ||
               func_name_lower.contains("oracle_read") ||
               (func_name_lower.contains("oracle") && 
                (func_name_lower.contains("get") || func_name_lower.contains("query")));
    }
    false
}

fn is_validated_oracle_call(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut validation_checks = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("validate_price") { validation_checks += 2; }
                if func_name_lower.contains("check_oracle") { validation_checks += 1; }
                if func_name_lower.contains("consensus_oracle") { validation_checks += 3; }
                if func_name_lower.contains("circuit_breaker") { validation_checks += 2; }
            }
        }
        
        validation_checks >= 1
    } else {
        false
    }
}

fn calculate_minting_limit_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("check_limit") { score += 3; }
                if func_name_lower.contains("daily_cap") { score += 2; }
                if func_name_lower.contains("max_mint") { score += 2; }
                if func_name_lower.contains("require_collateral") { score += 3; }
                if func_name_lower.contains("governance_approval") { score += 2; }
                if func_name_lower.contains("emergency_stop") { score += 3; }
            }
        }
    }
    
    score
}

fn calculate_economic_security_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("withdrawal_limit") { score += 3; }
                if func_name_lower.contains("time_lock") { score += 2; }
                if func_name_lower.contains("circuit_breaker") { score += 3; }
                if func_name_lower.contains("collateral_ratio") { score += 2; }
                if func_name_lower.contains("rate_limit") { score += 2; }
            }
        }
    }
    
    score
}

fn calculate_governance_security_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("timelock") { score += 3; }
                if func_name_lower.contains("multisig") { score += 3; }
                if func_name_lower.contains("voting_delay") { score += 2; }
                if func_name_lower.contains("emergency_executor") { score += 2; }
                if func_name_lower.contains("governance_guard") { score += 2; }
            }
        }
    }
    
    score
}

fn calculate_confidence(func_def: &FunctionDefinition, module: &CompiledModule) -> Confidence {
    // Calculate confidence based on function complexity and context
    if let Some(code) = &func_def.code {
        let mut external_calls = 0;
        let mut state_changes = 0;
        
        for instr in &code.code {
            match instr {
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => external_calls += 1,
                Bytecode::MoveTo(_) | Bytecode::MoveToGeneric(_) |
                Bytecode::MoveFrom(_) | Bytecode::MoveFromGeneric(_) => state_changes += 2,
                Bytecode::MutBorrowGlobal(_) | Bytecode::MutBorrowGlobalGeneric(_) => state_changes += 1,
                _ => {}
            }
        }
        
        let risk_score = external_calls + state_changes;
        
        match risk_score {
            0..=2 => Confidence::Low,
            3..=5 => Confidence::Medium,
            _ => Confidence::High,
        }
    } else {
        Confidence::Low
    }
}

// New helper: Check if function modifies critical bridge state
fn is_critical_bridge_function(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    let func_handle = &module.function_handles[func_def.function.0 as usize];
    let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
    
    // List of critical bridge operations
    let critical_operations = [
        "mint", "burn", "lock", "unlock", "withdraw", "deposit", 
        "upgrade", "pause", "emergency", "validator", "governance"
    ];
    
    critical_operations.iter().any(|op| func_name.contains(op))
}