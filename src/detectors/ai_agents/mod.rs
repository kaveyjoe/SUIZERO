// src/detectors/ai_agents/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use crate::utils::{create_location, create_module_location};
use move_binary_format::{file_format::*, access::ModuleAccess};

// Enhanced AI detection with stricter criteria
fn is_ai_related_context(ctx: &DetectionContext) -> bool {
    let module_name = ctx.module.self_id().name().as_str().to_lowercase();
    
    // STRICTER: Require stronger AI indicators
    let has_explicit_ai_name = module_name.contains("ai_") || 
                               module_name.contains("_ai") ||
                               module_name.contains("agent") ||
                               module_name.contains("model") ||
                               module_name.contains("neural") ||
                               module_name.contains("llm") ||
                               module_name.contains("gpt");
    
    if !has_explicit_ai_name {
        return false;
    }
    
    // Additional validation: Check for AI-related structs/functions
    let ai_struct_count = ctx.module.struct_defs.iter()
        .filter(|struct_def| {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            struct_name.contains("neural") ||
            struct_name.contains("layer") ||
            struct_name.contains("tensor") ||
            struct_name.contains("weight") ||
            struct_name.contains("model") ||
            struct_name.contains("agent") ||
            struct_name.contains("prompt")
        })
        .count();
    
    let ai_function_count = ctx.module.function_defs.iter()
        .filter(|func_def| {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("infer") ||
            func_name.contains("predict") ||
            func_name.contains("train") ||
            func_name.contains("forward") ||
            func_name.contains("backward") ||
            func_name.contains("embed") ||
            func_name.contains("attention")
        })
        .count();
    
    // Only flag as AI if there are multiple AI indicators
    has_explicit_ai_name && (ai_struct_count > 0 || ai_function_count > 1)
}

// AI-001: Unbounded AI Action - STRICTER
pub struct UnboundedAIAction;

#[async_trait::async_trait]
impl SecurityDetector for UnboundedAIAction {
    fn id(&self) -> &'static str { "AI-001" }
    fn name(&self) -> &'static str { "Unbounded AI Action" }
    fn description(&self) -> &'static str {
        "AI agents can take unlimited actions without constraints"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_ai_related_context(ctx) { return Vec::new(); }
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: Only check functions that clearly indicate autonomous action
            let is_autonomous_function = func_name_lower.contains("autonomous") ||
                                        func_name_lower.contains("execute_action") ||
                                        func_name_lower.contains("run_agent") ||
                                        func_name_lower.contains("take_action") ||
                                        (func_name_lower.contains("agent") && 
                                         (func_name_lower.contains("execute") || 
                                          func_name_lower.contains("run")));
            
            if is_autonomous_function {
                // Check for spending limits or action caps with stricter criteria
                if !has_action_limits(func_def, &ctx.module) {
                    // Verify this is actually an action-taking function
                    if is_action_taking_function(func_def, &ctx.module) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: calculate_confidence(func_def, &ctx.module),
                            title: format!("Unbounded AI action in '{}'", func_name),
                            description: "AI agent function lacks action limits or spending caps".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement daily/weekly limits, transaction caps, and cooling periods for autonomous agents".to_string(),
                            references: vec![
                                "AI Security Best Practices: https://arxiv.org/abs/2308.12808".to_string(),
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

// AI-002: Model Manipulation - STRICTER
pub struct ModelManipulation;

#[async_trait::async_trait]
impl SecurityDetector for ModelManipulation {
    fn id(&self) -> &'static str { "AI-002" }
    fn name(&self) -> &'static str { "Model Manipulation" }
    fn description(&self) -> &'static str {
        "AI model parameters can be manipulated by users"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_ai_related_context(ctx) { return Vec::new(); }
        let mut issues = Vec::new();
        
        // First, check if there are model-related structs
        let has_model_struct = ctx.module.struct_defs.iter().any(|struct_def| {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            struct_name.contains("model") || struct_name.contains("weights")
        });
        
        if !has_model_struct { return Vec::new(); }
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: Only check functions that explicitly update models
            let is_model_update_function = func_name_lower.contains("update_model") ||
                                          func_name_lower.contains("set_weights") ||
                                          func_name_lower.contains("modify_model") ||
                                          (func_name_lower.contains("model") && 
                                           func_name_lower.contains("update") &&
                                           !func_name_lower.contains("check"));
            
            if is_model_update_function {
                // Check if model updates are properly restricted
                if !has_model_update_restrictions(func_def, &ctx.module) {
                    // Verify this function actually modifies model state
                    if is_state_modifying_function(func_def, &ctx.module) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: calculate_confidence(func_def, &ctx.module),
                            title: format!("Model manipulation risk in '{}'", func_name),
                            description: "AI model parameters can be updated without proper restrictions".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement governance-controlled model updates, time-locks, and validation checks".to_string(),
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

// AI-003: Prompt Injection - STRICTER
pub struct PromptInjection;

#[async_trait::async_trait]
impl SecurityDetector for PromptInjection {
    fn id(&self) -> &'static str { "AI-003" }
    fn name(&self) -> &'static str { "Prompt Injection" }
    fn description(&self) -> &'static str {
        "User input can inject malicious prompts into AI systems"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_ai_related_context(ctx) { return Vec::new(); }
        let mut issues = Vec::new();
        
        // Check if module has prompt-related structs
        let has_prompt_struct = ctx.module.struct_defs.iter().any(|struct_def| {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            struct_name.contains("prompt") || struct_name.contains("message")
        });
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: More specific criteria
            let is_prompt_function = (func_name_lower.contains("prompt") && 
                                     (func_name_lower.contains("submit") || 
                                      func_name_lower.contains("send") ||
                                      func_name_lower.contains("query"))) ||
                                    (has_prompt_struct && 
                                     func_name_lower.contains("input") &&
                                     func_name_lower.contains("process"));
            
            if is_prompt_function {
                // Check for prompt sanitization with stricter criteria
                let sanitization_score = calculate_sanitization_score(func_def, &ctx.module);
                
                if sanitization_score < 2 { // Require multiple sanitization methods
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if sanitization_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Prompt injection risk in '{}'", func_name),
                        description: "User input used in AI prompts without adequate sanitization".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement input validation, prompt escaping, context separation, and allow-list based filtering".to_string(),
                        references: vec![
                            "OWASP LLM Security: https://owasp.org/www-project-top-10-for-large-language-model-applications/".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// AI-005: Reward Hacking - STRICTER
pub struct RewardHacking;

#[async_trait::async_trait]
impl SecurityDetector for RewardHacking {
    fn id(&self) -> &'static str { "AI-005" }
    fn name(&self) -> &'static str { "Reward Hacking" }
    fn description(&self) -> &'static str {
        "AI agents can exploit reward function flaws"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_ai_related_context(ctx) { return Vec::new(); }
        let mut issues = Vec::new();
        
        // Only check if there's evidence of reinforcement learning
        let has_rl_indicators = ctx.module.function_defs.iter().any(|f| {
            let func_handle = &ctx.module.function_handles[f.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("reinforcement") || func_name.contains("rl_") || func_name.contains("q_learning")
        });
        
        if !has_rl_indicators { return Vec::new(); }
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: Only explicit reward functions
            let is_reward_function = func_name_lower.starts_with("reward_") ||
                                    func_name_lower.contains("calculate_reward") ||
                                    func_name_lower == "reward" ||
                                    func_name_lower.contains("get_reward");
            
            if is_reward_function {
                // Check for reward function manipulation with stricter criteria
                if is_reward_function_manipulable(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::Medium,
                        title: format!("Reward hacking risk in '{}'", func_name),
                        description: "Reward function can be gamed or manipulated through oracle dependencies".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement multi-objective rewards, adversarial testing, and reward validation".to_string(),
                        references: vec![
                            "Specification Gaming: https://www.alignmentforum.org/posts/HBxe6wdjxK239zajf/what-failure-looks-like".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// AI-007: Emergent Behavior Risk - STRICTER
pub struct EmergentBehaviorRisk;

#[async_trait::async_trait]
impl SecurityDetector for EmergentBehaviorRisk {
    fn id(&self) -> &'static str { "AI-007" }
    fn name(&self) -> &'static str { "Emergent Behavior Risk" }
    fn description(&self) -> &'static str {
        "Complex AI systems may exhibit unexpected emergent behaviors"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_ai_related_context(ctx) { return Vec::new(); }
        
        // Count only explicit multi-agent interactions
        let agent_interaction_functions: Vec<_> = ctx.module.function_defs.iter()
            .filter(|f| {
                let func_handle = &ctx.module.function_handles[f.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
                (func_name.contains("agent") && func_name.contains("interact")) ||
                func_name.contains("multi_agent") ||
                func_name.contains("coordinated")
            })
            .collect();
        
        // Require at least 5 agent interaction functions to flag
        if agent_interaction_functions.len() >= 5 {
            return vec![SecurityIssue {
                id: self.id().to_string(),
                severity: self.default_severity(),
                confidence: if agent_interaction_functions.len() > 7 { 
                    Confidence::High 
                } else { 
                    Confidence::Medium 
                },
                title: "Emergent behavior risk in multi-agent system".to_string(),
                description: format!("{} interacting AI agents may exhibit unexpected emergent behaviors", 
                                   agent_interaction_functions.len()),
                location: create_module_location(ctx),
                source_code: None,
                recommendation: "Implement circuit breakers, behavior monitoring, and emergency shutdown mechanisms".to_string(),
                references: vec![
                    "Multi-Agent Safety: https://arxiv.org/abs/2305.15351".to_string(),
                ],
                metadata: std::collections::HashMap::new(),
            }];
        }
        
        Vec::new()
    }
}

// AI-011: Corrigibility Issue - STRICTER
pub struct CorrigibilityIssue;

#[async_trait::async_trait]
impl SecurityDetector for CorrigibilityIssue {
    fn id(&self) -> &'static str { "AI-011" }
    fn name(&self) -> &'static str { "Corrigibility Issue" }
    fn description(&self) -> &'static str {
        "AI resists shutdown or modification attempts"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_ai_related_context(ctx) { return Vec::new(); }
        
        // Only check for autonomous AI systems
        let has_autonomous_functions = ctx.module.function_defs.iter().any(|f| {
            let func_handle = &ctx.module.function_handles[f.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("autonomous") || func_name.contains("self_")
        });
        
        if !has_autonomous_functions { return Vec::new(); }
        
        // Look for comprehensive shutdown mechanisms
        let mut shutdown_mechanisms = 0;
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            if func_name.contains("emergency_shutdown") ||
               func_name.contains("force_pause") ||
               func_name.contains("kill_switch") ||
               (func_name.contains("shutdown") && !func_name.contains("check")) {
                shutdown_mechanisms += 1;
            }
        }
        
        // Require at least 2 distinct shutdown mechanisms for critical AI
        if shutdown_mechanisms < 2 {
            return vec![SecurityIssue {
                id: self.id().to_string(),
                severity: self.default_severity(),
                confidence: if shutdown_mechanisms == 0 { 
                    Confidence::High 
                } else { 
                    Confidence::Medium 
                },
                title: "Inadequate AI shutdown mechanisms".to_string(),
                description: format!("Autonomous AI system has only {} shutdown mechanism(s)", shutdown_mechanisms),
                location: create_module_location(ctx),
                source_code: None,
                recommendation: "Implement multiple independent shutdown mechanisms with time-delays and multi-sig requirements".to_string(),
                references: vec![
                    "Corrigibility: https://www.alignmentforum.org/posts/4CZ5LbryMzGbgZkyY/corrigibility".to_string(),
                ],
                metadata: std::collections::HashMap::new(),
            }];
        }
        
        Vec::new()
    }
}

// AI-015: Adversarial Example Risk - STRICTER
pub struct AdversarialExampleRisk;

#[async_trait::async_trait]
impl SecurityDetector for AdversarialExampleRisk {
    fn id(&self) -> &'static str { "AI-015" }
    fn name(&self) -> &'static str { "Adversarial Example Risk" }
    fn description(&self) -> &'static str {
        "AI vulnerable to adversarial inputs"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_ai_related_context(ctx) { return Vec::new(); }
        let mut issues = Vec::new();
        
        // Check if this is a vision/classification module
        let is_vision_module = ctx.module.struct_defs.iter().any(|struct_def| {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            struct_name.contains("image") || struct_name.contains("vision") || struct_name.contains("classifier")
        });
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // STRICTER: Only check actual classification functions
            let is_classification_function = (func_name_lower.contains("classify") && 
                                             !func_name_lower.contains("check")) ||
                                            (func_name_lower.contains("predict") && 
                                             is_vision_module) ||
                                            func_name_lower.contains("inference");
            
            if is_classification_function {
                // Check for adversarial defenses
                let defense_score = calculate_adversarial_defense_score(func_def, &ctx.module);
                
                if defense_score < 1 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if defense_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Adversarial example risk in '{}'", func_name),
                        description: "AI classification function lacks adversarial defenses".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement adversarial training, input validation, and ensemble methods".to_string(),
                        references: vec![
                            "Adversarial Machine Learning: https://arxiv.org/abs/1412.6572".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// Enhanced helper functions with stricter criteria
fn has_action_limits(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut limit_checks = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("check_limit") ||
                   func_name_lower.contains("validate_spending") ||
                   func_name_lower.contains("enforce_cap") ||
                   (func_name_lower.contains("limit") && func_name_lower.contains("check")) {
                    limit_checks += 1;
                }
            }
        }
        
        // Require at least 2 different limit checks
        limit_checks >= 2
    } else {
        false
    }
}

fn has_model_update_restrictions(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut restriction_checks = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("require_governance") ||
                   func_name_lower.contains("check_multisig") ||
                   func_name_lower.contains("validate_vote") ||
                   func_name_lower.contains("time_lock") {
                    restriction_checks += 1;
                }
            }
        }
        
        // Require multiple restriction mechanisms
        restriction_checks >= 2
    } else {
        false
    }
}

fn calculate_sanitization_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("validate_input") { score += 2; }
                if func_name_lower.contains("sanitize") { score += 2; }
                if func_name_lower.contains("escape") { score += 1; }
                if func_name_lower.contains("filter") { score += 1; }
                if func_name_lower.contains("check_allowlist") { score += 3; }
                if func_name_lower.contains("context_separate") { score += 2; }
            }
        }
    }
    
    score
}

fn is_reward_function_manipulable(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut oracle_dependencies = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("oracle") ||
                   func_name_lower.contains("price_feed") ||
                   func_name_lower.contains("external_data") {
                    oracle_dependencies += 1;
                }
                
                // Also check for lack of validation
                if func_name_lower.contains("validate_source") ||
                   func_name_lower.contains("check_consensus") ||
                   func_name_lower.contains("multiple_oracles") {
                    oracle_dependencies -= 1; // These are mitigations
                }
            }
        }
        
        oracle_dependencies > 1 // Multiple unvalidated oracle dependencies
    } else {
        false
    }
}

fn calculate_adversarial_defense_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("adversarial_defense") { score += 3; }
                if func_name_lower.contains("ensemble") { score += 2; }
                if func_name_lower.contains("input_validation") { score += 1; }
                if func_name_lower.contains("robust_training") { score += 2; }
            }
        }
    }
    
    score
}

fn is_action_taking_function(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut external_calls = 0;
        
        for instr in &code.code {
            match instr {
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    external_calls += 1;
                }
                Bytecode::Pack(_) | Bytecode::PackGeneric(_) => {
                    // State modification
                    return true;
                }
                _ => {}
            }
        }
        
        external_calls > 2 // Function makes multiple external calls
    } else {
        false
    }
}

fn is_state_modifying_function(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            match instr {
                Bytecode::MutBorrowGlobal(_) | Bytecode::MutBorrowGlobalGeneric(_) |
                Bytecode::Pack(_) | Bytecode::PackGeneric(_) => {
                    return true;
                }
                _ => {}
            }
        }
    }
    false
}

fn calculate_confidence(func_def: &FunctionDefinition, module: &CompiledModule) -> Confidence {
    if let Some(code) = &func_def.code {
        let complexity_score = code.code.len();
        
        match complexity_score {
            0..=10 => Confidence::Low,
            11..=30 => Confidence::Medium,
            _ => Confidence::High,
        }
    } else {
        Confidence::Low
    }
}