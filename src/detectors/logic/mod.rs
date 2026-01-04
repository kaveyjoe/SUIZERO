// src/detectors/logic/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use crate::utils::{create_location, create_module_location};
use move_binary_format::{file_format::*, access::ModuleAccess};
use std::collections::{HashMap, HashSet};

// LG-001: Uninitialized Storage - ULTRA STRICT
pub struct UninitializedStorage;

#[async_trait::async_trait]
impl SecurityDetector for UninitializedStorage {
    fn id(&self) -> &'static str { "LG-001" }
    fn name(&self) -> &'static str { "Uninitialized Storage" }
    fn description(&self) -> &'static str {
        "Global singleton objects used before initialization"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check if module has singleton patterns
        if !has_singleton_pattern(&ctx.module) {
            return issues;
        }
        
        for struct_def in &ctx.module.struct_defs {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name);
            
            // ULTRA STRICT: Only check structs with singleton naming patterns
            if !is_singleton_struct(struct_name.as_str()) {
                continue;
            }
            
            // Check if this singleton is used before initialization
            if is_singleton_used_without_init_check(&ctx.module, struct_name.as_str()) {
                issues.push(SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::High,
                    title: format!("Uninitialized singleton '{}'", struct_name),
                    description: "Global singleton may be accessed before initialization".to_string(),
                    location: CodeLocation {
                        module_id: ctx.module_id.to_string(),
                        module_name: ctx.module.self_id().name().to_string(),
                        function_name: "struct_def".to_string(),
                        instruction_index: 0,
                        byte_offset: 0,
                        line: None,
                        column: None,
                    },
                    source_code: Some(struct_name.to_string()),
                    recommendation: "Add initialization flag or require initialization before use".to_string(),
                    references: vec![
                        "CWE-456: Missing Initialization of a Variable".to_string(),
                    ],
                    metadata: {
                        let mut map = HashMap::new();
                        map.insert("struct_name".to_string(), struct_name.to_string());
                        map.insert("singleton_type".to_string(), "global".to_string());
                        map
                    },
                });
            }
        }
        
        issues
    }
}

fn has_singleton_pattern(module: &CompiledModule) -> bool {
    // Check for singleton-related functions
    let has_singleton_functions = module.function_defs.iter().any(|f| {
        let func_handle = &module.function_handles[f.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        func_name.contains("singleton") ||
        func_name.contains("global") ||
        func_name.contains("shared")
    });
    
    // Check for singleton structs
    let has_singleton_structs = module.struct_defs.iter().any(|s| {
        let struct_handle = &module.struct_handles[s.struct_handle.0 as usize];
        let struct_name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
        is_singleton_struct(&struct_name)
    });
    
    has_singleton_functions || has_singleton_structs
}

fn is_singleton_struct(struct_name: &str) -> bool {
    let name_lower = struct_name.to_lowercase();
    
    // Common singleton naming patterns
    name_lower == "singleton" ||
    name_lower.contains("global") ||
    name_lower.contains("shared") ||
    name_lower == "state" ||
    name_lower == "storage"
}

fn is_singleton_used_without_init_check(module: &CompiledModule, singleton_name: &str) -> bool {
    // Track initialization and usage
    let mut is_initialized = false;
    let mut is_used = false;
    
    for func_def in &module.function_defs {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        
        // Check for initialization function
        if func_name.contains("init") || func_name.contains("initialize") {
            is_initialized = true;
        }
        
        // Check for usage of singleton
        if let Some(code) = &func_def.code {
            // Simplified check for singleton usage
            // In practice, would need to analyze type usage
            for instr in &code.code {
                if let Bytecode::MoveFrom(_) | Bytecode::MoveTo(_) = instr {
                    // Might be accessing singleton
                    if !is_initialized {
                        is_used = true;
                    }
                }
            }
        }
    }
    
    is_used && !is_initialized
}

// LG-004: Input Validation Missing - ULTRA STRICT
pub struct InputValidationMissing;

#[async_trait::async_trait]
impl SecurityDetector for InputValidationMissing {
    fn id(&self) -> &'static str { "LG-004" }
    fn name(&self) -> &'static str { "Input Validation Missing" }
    fn description(&self) -> &'static str {
        "Critical functions missing input validation"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check public/entry functions with parameters
        for func_def in &ctx.module.function_defs {
            if func_def.visibility != Visibility::Public && !func_def.is_entry {
                continue;
            }
            
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check functions with clear security implications
            let is_critical_function = func_name_lower.contains("transfer") ||
                                      func_name_lower.contains("mint") ||
                                      func_name_lower.contains("burn") ||
                                      func_name_lower.contains("withdraw") ||
                                      func_name_lower.contains("set_") ||
                                      func_name_lower.contains("update_");
            
            if !is_critical_function {
                continue;
            }
            
            // Check if function has parameters that need validation
            if has_parameters_needing_validation(func_def, &ctx.module) {
                // Check for validation with strict criteria
                let validation_score = calculate_validation_score(func_def, &ctx.module);
                
                if validation_score < 2 { // Require multiple validation checks
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if validation_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Missing input validation in '{}'", func_name),
                        description: "Critical function lacks adequate input validation".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Add range checks, format validation, and business rule validation for all inputs".to_string(),
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
        
        issues
    }
}

fn has_parameters_needing_validation(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    let func_handle = &module.function_handles[func_def.function.0 as usize];
    let signature = &module.signatures[func_handle.parameters.0 as usize];
    
    // Check if there are any non-capability parameters
    for param_type in &signature.0 {
        let mut inner_type = param_type;
        while let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = inner_type {
            inner_type = inner;
        }

        // Skip system types and capabilities
        if let SignatureToken::Struct(idx) | SignatureToken::StructInstantiation(idx, _) = inner_type {
            let struct_handle = &module.struct_handles[idx.0 as usize];
            let struct_name = module.identifier_at(struct_handle.name).as_str();
            
            // System types and capabilities don't need validation
            if struct_name == "TxContext" || struct_name == "Clock" || 
               struct_name.contains("Cap") || struct_name.contains("Owner") {
                continue;
            }
        }
        
        // Found parameter that might need validation
        return true;
    }
    
    false
}

fn calculate_validation_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("assert") { score += 2; }
                if func_name_lower.contains("check") { score += 2; }
                if func_name_lower.contains("validate") { score += 3; }
                if func_name_lower.contains("verify") { score += 2; }
                if func_name_lower.contains("require") { score += 2; }
                if func_name_lower.contains("ensure") { score += 1; }
            }
            
            // Check for specific validation patterns
            match instr {
                Bytecode::Abort => score += 1,
                Bytecode::LdU64(0) | Bytecode::LdU64(1) => {
                    // Often used in bounds checking
                    score += 1;
                }
                Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | Bytecode::Eq | Bytecode::Neq => {
                    // Comparison operations
                    score += 1;
                }
                _ => {}
            }
        }
    }
    
    score
}

// LG-006: Incorrect Fee Calculation - ULTRA STRICT
pub struct IncorrectFeeCalculation;

#[async_trait::async_trait]
impl SecurityDetector for IncorrectFeeCalculation {
    fn id(&self) -> &'static str { "LG-006" }
    fn name(&self) -> &'static str { "Incorrect Fee Calculation" }
    fn description(&self) -> &'static str {
        "Potential errors in fee calculations"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check financial modules
        if !is_financial_module(&ctx.module) {
            return issues;
        }
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check explicit fee calculation functions
            let is_fee_function = func_name_lower == "calculate_fee" ||
                                 func_name_lower.starts_with("calculate_fee_") ||
                                 func_name_lower == "compute_fee" ||
                                 func_name_lower.contains("fee_calculation");
            
            if is_fee_function {
                // Check for common fee calculation errors
                if has_division_before_multiplication(func_def, &ctx.module) ||
                   has_rounding_error_pattern(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Fee calculation issue in '{}'", func_name),
                        description: "Potential error in fee calculation logic".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Review fee calculation for precision loss and rounding errors".to_string(),
                        references: vec![
                            "CWE-682: Incorrect Calculation".to_string(),
                        ],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn is_financial_module(module: &CompiledModule) -> bool {
    let module_name = module.self_id().name().as_str().to_lowercase();
    
    module_name.contains("coin") ||
    module_name.contains("token") ||
    module_name.contains("fee") ||
    module_name.contains("price") ||
    module_name.contains("swap") ||
    module_name.contains("trade")
}

fn has_division_before_multiplication(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let bytecode = &code.code;
        
        // Look for division followed by multiplication pattern
        for i in 0..bytecode.len().saturating_sub(2) {
            if let Bytecode::Div = bytecode[i] {
                // Check if multiplication follows within 5 instructions
                for j in i+1..std::cmp::min(i+6, bytecode.len()) {
                    if let Bytecode::Mul = bytecode[j] {
                        return true;
                    }
                }
            }
        }
    }
    
    false
}

fn has_rounding_error_pattern(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        // Look for division without proper rounding
        let mut has_division = false;
        let mut has_rounding = false;
        
        for instr in &code.code {
            match instr {
                Bytecode::Div => has_division = true,
                Bytecode::Add | Bytecode::Sub => {
                    // Check if these are used for rounding
                    // (numerator + (denominator / 2)) / denominator pattern
                    has_rounding = true;
                }
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                        if func_name.as_str().contains("round") {
                            has_rounding = true;
                        }
                    }
                }
                _ => {}
            }
        }
        
        // Division without rounding is suspicious for fee calculations
        has_division && !has_rounding
    } else {
        false
    }
}

// LG-007: Reward Distribution Error - ULTRA STRICT
pub struct RewardDistributionError;

#[async_trait::async_trait]
impl SecurityDetector for RewardDistributionError {
    fn id(&self) -> &'static str { "LG-007" }
    fn name(&self) -> &'static str { "Reward Distribution Error" }
    fn description(&self) -> &'static str {
        "Potential errors in reward distribution logic"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check staking/reward modules
        if !is_reward_module(&ctx.module) {
            return issues;
        }
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check explicit distribution functions
            let is_distribution_function = func_name_lower == "distribute_rewards" ||
                                          func_name_lower == "claim_rewards" ||
                                          func_name_lower.contains("calculate_reward");
            
            if is_distribution_function {
                // Check for distribution patterns
                if has_loop_based_distribution(func_def, &ctx.module) &&
                   !has_overflow_protection(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Reward distribution issue in '{}'", func_name),
                        description: "Loop-based reward distribution may have rounding or overflow issues".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement checkpoint-based rewards or use fixed-point arithmetic".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn is_reward_module(module: &CompiledModule) -> bool {
    let module_name = module.self_id().name().as_str().to_lowercase();
    
    module_name.contains("staking") ||
    module_name.contains("reward") ||
    module_name.contains("farm") ||
    module_name.contains("yield") ||
    module_name.contains("dividend")
}

fn has_loop_based_distribution(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        // Check for loops
        let mut has_loop = false;
        for (i, instr) in code.code.iter().enumerate() {
            if let Bytecode::Branch(target) = instr {
                if (*target as usize) < i {
                    has_loop = true;
                    break;
                }
            }
        }
        
        if !has_loop {
            return false;
        }
        
        // Check for division in loop (indicating per-item distribution)
        let mut has_division_in_loop = false;
        let mut in_loop = false;
        
        for instr in &code.code {
            match instr {
                Bytecode::Branch(target) => {
                    in_loop = true;
                }
                Bytecode::Ret => {
                    in_loop = false;
                }
                Bytecode::Div if in_loop => {
                    has_division_in_loop = true;
                }
                _ => {}
            }
        }
        
        has_division_in_loop
    } else {
        false
    }
}

fn has_overflow_protection(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                if func_name.as_str().contains("check") ||
                   func_name.as_str().contains("assert") ||
                   func_name.as_str().contains("saturating") {
                    return true;
                }
            }
        }
    }
    
    false
}

// LG-008: Voting Mechanism Bug - ULTRA STRICT
pub struct VotingMechanismBug;

#[async_trait::async_trait]
impl SecurityDetector for VotingMechanismBug {
    fn id(&self) -> &'static str { "LG-008" }
    fn name(&self) -> &'static str { "Voting Mechanism Bug" }
    fn description(&self) -> &'static str {
        "Potential issues in voting/governance mechanisms"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check governance modules
        if !is_governance_module(&ctx.module) {
            return issues;
        }
        
        // Look for critical voting functions
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check core voting functions
            let is_core_voting_function = func_name_lower == "vote" ||
                                         func_name_lower == "cast_vote" ||
                                         func_name_lower == "execute_proposal";
            
            if is_core_voting_function && func_def.visibility == Visibility::Public {
                // Check for common voting vulnerabilities
                if !has_vote_weight_validation(func_def, &ctx.module) ||
                   !has_quorum_check(&ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::Medium,
                        title: format!("Voting mechanism issue in '{}'", func_name),
                        description: "Voting function lacks proper validation or quorum checks".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement vote weight validation, quorum checks, and time-based restrictions".to_string(),
                        references: vec![
                            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/governance/".to_string(),
                        ],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn is_governance_module(module: &CompiledModule) -> bool {
    let module_name = module.self_id().name().as_str().to_lowercase();
    
    module_name.contains("governance") ||
    module_name.contains("dao") ||
    module_name.contains("vote") ||
    module_name.contains("proposal")
}

fn has_vote_weight_validation(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                if func_name.as_str().contains("balance") ||
                   func_name.as_str().contains("weight") ||
                   func_name.as_str().contains("stake") {
                    return true;
                }
            }
        }
    }
    
    false
}

fn has_quorum_check(module: &CompiledModule) -> bool {
    // Check for quorum-related functions or structs
    for func_def in &module.function_defs {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        
        if func_name.contains("quorum") ||
           func_name.contains("threshold") ||
           func_name.contains("minimum") {
            return true;
        }
    }
    
    for struct_def in &module.struct_defs {
        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
        let struct_name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
        
        if struct_name.contains("quorum") ||
           struct_name.contains("proposal") ||
           struct_name.contains("vote") {
            return true;
        }
    }
    
    false
}

// LG-010: Cross-Chain Bridge Bug - ULTRA STRICT
pub struct CrossChainBridgeBug;

#[async_trait::async_trait]
impl SecurityDetector for CrossChainBridgeBug {
    fn id(&self) -> &'static str { "LG-010" }
    fn name(&self) -> &'static str { "Cross-Chain Bridge Bug" }
    fn description(&self) -> &'static str {
        "Critical bridge functions require extreme caution"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check if this is a bridge module
        if !is_bridge_module(&ctx.module) {
            return issues;
        }
        
        // Look for critical bridge operations
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check critical bridge operations
            let is_critical_bridge_operation = func_name_lower == "lock" ||
                                              func_name_lower == "unlock" ||
                                              func_name_lower == "mint" ||
                                              func_name_lower == "burn" ||
                                              func_name_lower == "withdraw";
            
            if is_critical_bridge_operation && func_def.visibility == Visibility::Public {
                // Check for safety mechanisms
                let safety_score = calculate_bridge_safety_score(func_def, &ctx.module);
                
                if safety_score < 3 { // Require strong safety measures
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if safety_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Critical bridge operation '{}'", func_name),
                        description: "Bridge function lacks adequate safety mechanisms".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement multi-sig, timelocks, rate limits, and pause mechanisms for bridge operations".to_string(),
                        references: vec![
                            "https://github.com/crytic/not-so-smart-contracts/tree/master/bridge".to_string(),
                        ],
                        metadata: {
                            let mut map = HashMap::new();
                            map.insert("safety_score".to_string(), safety_score.to_string());
                            map
                        },
                    });
                }
            }
        }
        
        issues
    }
}

fn is_bridge_module(module: &CompiledModule) -> bool {
    let module_name = module.self_id().name().as_str().to_lowercase();
    
    module_name.contains("bridge") ||
    module_name.contains("portal") ||
    module_name.contains("wormhole") ||
    module_name.contains("crosschain") ||
    module_name.contains("multichain")
}

fn calculate_bridge_safety_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("multisig") { score += 3; }
                if func_name_lower.contains("timelock") { score += 3; }
                if func_name_lower.contains("pause") { score += 2; }
                if func_name_lower.contains("emergency") { score += 2; }
                if func_name_lower.contains("limit") { score += 1; }
                if func_name_lower.contains("cap") { score += 1; }
                if func_name_lower.contains("threshold") { score += 2; }
                if func_name_lower.contains("validate") { score += 2; }
            }
        }
    }
    
    score
}

// Only include detectors that can be made extremely strict
pub fn get_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(UninitializedStorage),
        Box::new(InputValidationMissing),
        Box::new(IncorrectFeeCalculation),
        Box::new(RewardDistributionError),
        Box::new(VotingMechanismBug),
        Box::new(CrossChainBridgeBug),
    ]
}