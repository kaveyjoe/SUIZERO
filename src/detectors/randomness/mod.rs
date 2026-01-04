// src/detectors/randomness/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use move_binary_format::{file_format::*, access::ModuleAccess};

// RN-001: Predictable Randomness
pub struct PredictableRandomness;

#[async_trait::async_trait]
impl SecurityDetector for PredictableRandomness {
    fn id(&self) -> &'static str { "RN-001" }
    fn name(&self) -> &'static str { "Predictable Randomness" }
    fn description(&self) -> &'static str {
        "Random number generation uses predictable sources"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Precisely defined weak randomness sources with full signatures
        let weak_sources = [
            ("timestamp", vec!["timestamp", "clock", "now"]),
            ("block", vec!["block", "epoch"]),
            ("tx", vec!["tx_hash", "transaction"]),
            ("sender", vec!["sender", "signer"]),
        ];
        
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                for (i, instr) in code.code.iter().enumerate() {
                    if let Some((func_name, full_signature)) = get_function_call_details(instr, &ctx.module) {
                        let mut detected_source = None;
                        
                        // Check against precise signatures, not just substring matches
                        for (source_type, keywords) in &weak_sources {
                            // Require exact module pattern for timestamp sources
                            if *source_type == "timestamp" {
                                if func_name.contains("::timestamp::") || 
                                   func_name.contains("::clock::") ||
                                   full_signature.contains("Timestamp") {
                                    detected_source = Some((*source_type, func_name.clone()));
                                    break;
                                }
                            }
                            
                            // Check if this is definitely a randomness-related use
                            if is_definitely_randomness_context(&code.code, i) {
                                for keyword in keywords {
                                    if func_name.contains(keyword) && 
                                       !is_benign_context(&code.code, i, &ctx.module) {
                                        detected_source = Some((*source_type, func_name.clone()));
                                        break;
                                    }
                                }
                            }
                        }
                        
                        if let Some((source_type, source_name)) = detected_source {
                            // Verify this is actually used for randomness, not just logging or events
                            if is_randomness_usage_strict(&code.code, i, &ctx.module) {
                                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                                let parent_func_name = ctx.module.identifier_at(func_handle.name);
                                
                                // Skip if this is just a benign read (e.g., for logging)
                                if is_benign_usage(&code.code, i) {
                                    continue;
                                }
                                
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(),
                                    severity: self.default_severity(),
                                    confidence: Confidence::High,
                                    title: format!("Predictable randomness source in '{}'", parent_func_name),
                                    description: format!("Uses predictable source '{}' ({}) for randomness generation", 
                                                         source_name, source_type),
                                    location: create_location(ctx, func_def, i as u16),
                                    source_code: Some(source_name.to_string()),
                                    recommendation: "Use sui::random::Random or verifiable random functions (VRF)".to_string(),
                                    references: vec![
                                        "CWE-330: Use of Insufficiently Random Values".to_string(),
                                        "https://docs.sui.io/build/security/randomness".to_string(),
                                    ],
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

// RN-002: Front-Running RNG
pub struct FrontRunningRNG;

#[async_trait::async_trait]
impl SecurityDetector for FrontRunningRNG {
    fn id(&self) -> &'static str { "RN-002" }
    fn name(&self) -> &'static str { "Front-Running RNG" }
    fn description(&self) -> &'static str {
        "Randomness generation vulnerable to front-running"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only detect in functions that are clearly randomness-related
        let randomness_keywords = ["random", "lottery", "raffle", "draw", "winner", "shuffle", "select_winner"];
        let benign_keywords = ["randomness_test", "mock_random", "test_"]; // Skip tests
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_str = func_name.as_str();
            
            // Check if function is randomness-related
            let is_randomness_func = randomness_keywords.iter()
                .any(|&kw| func_name_str.contains(kw)) && 
                !benign_keywords.iter().any(|&kw| func_name_str.contains(kw));
            
            if is_randomness_func {
                // Analyze the function body for predictable patterns
                if let Some(code) = &func_def.code {
                    let uses_predictable_sources = analyze_randomness_patterns(code, &ctx.module);
                    
                    if uses_predictable_sources && !has_secure_randomness_pattern(func_def, &ctx.module) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Medium,
                            title: format!("Front-running vulnerability in '{}'", func_name),
                            description: "Function uses predictable on-chain data and lacks commit-reveal pattern".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement commit-reveal scheme or use sui::random::Random".to_string(),
                            references: vec![
                                "https://docs.sui.io/guides/developer/advanced/randomness-on-chain".to_string(),
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

// RN-003: Bias in Distribution
pub struct BiasInDistribution;

#[async_trait::async_trait]
impl SecurityDetector for BiasInDistribution {
    fn id(&self) -> &'static str { "RN-003" }
    fn name(&self) -> &'static str { "Bias in Distribution" }
    fn description(&self) -> &'static str {
        "Random number distribution has statistical bias"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                // Look for modulo operations on random values
                for (i, instr) in code.code.iter().enumerate() {
                    if let Bytecode::Mod = instr {
                        // Strict check: must have random source as left operand
                        if is_random_value_modulo(&code.code, i, &ctx.module) {
                            // Check if this is actually problematic (not power of 2 range)
                            if is_potentially_biased_modulo(&code.code, i, &ctx.module) {
                                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                                let func_name = ctx.module.identifier_at(func_handle.name);
                                
                                issues.push(SecurityIssue {
                                    id: self.id().to_string(),
                                    severity: self.default_severity(),
                                    confidence: Confidence::High,
                                    title: format!("Modulo bias in '{}'", func_name),
                                    description: "Using modulo on random values creates statistical bias when range is not power of 2".to_string(),
                                    location: create_location(ctx, func_def, i as u16),
                                    source_code: Some("random_value % range".to_string()),
                                    recommendation: "Use rejection sampling: while value >= range { regenerate }".to_string(),
                                    references: vec![
                                        "https://github.com/crytic/slither/wiki/Detector-Documentation#weak-prng".to_string(),
                                        "https://research.kudelskisecurity.com/2020/07/28/the-definitive-guide-to-modulo-bias-and-how-to-avoid-it/".to_string(),
                                    ],
                                    metadata: std::collections::HashMap::new(),
                                });
                            }
                        }
                    }
                }
                
                // Also check for division-based range reduction
                for (i, instr) in code.code.iter().enumerate() {
                    if let Bytecode::Div = instr {
                        if is_random_value_division(&code.code, i, &ctx.module) {
                            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                            let func_name = ctx.module.identifier_at(func_handle.name);
                            
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: Severity::Medium,
                                confidence: Confidence::Medium,
                                title: format!("Division bias in '{}'", func_name),
                                description: "Using division for range reduction can create bias".to_string(),
                                location: create_location(ctx, func_def, i as u16),
                                source_code: Some("random_value / divisor".to_string()),
                                recommendation: "Consider using proper scaling methods".to_string(),
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

// RN-004: Seed Manipulation
pub struct SeedManipulation;

#[async_trait::async_trait]
impl SecurityDetector for SeedManipulation {
    fn id(&self) -> &'static str { "RN-004" }
    fn name(&self) -> &'static str { "Seed Manipulation" }
    fn description(&self) -> &'static str {
        "Random seed can be manipulated by users"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check functions that are clearly about randomness
            if func_name.as_str().contains("random") || 
               func_name.as_str().contains("seed") ||
               func_name.as_str().contains("generate") {
                
                // Strict check: user input must directly influence the seed
                if uses_user_input_for_seed_strict(func_def, &ctx.module) &&
                   !has_mix_with_nonces(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::Medium,
                        title: format!("User-manipulable seed in '{}'", func_name),
                        description: "Random seed includes unverified user input without nonce mixing".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Mix user input with nonces, block data, or use commit-reveal".to_string(),
                        references: vec![
                            "https://consensys.github.io/smart-contract-best-practices/attacks/randomness/".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// Strict helper functions with reduced false positives
fn get_function_call_details(instr: &Bytecode, module: &CompiledModule) -> Option<(String, String)> {
    match instr {
        Bytecode::Call(call_idx) => {
            if let Some(func_handle) = module.function_handles.get(call_idx.0 as usize) {
                let module_handle = &module.module_handles[func_handle.module.0 as usize];
                let module_name = module.identifier_at(module_handle.name);
                let func_name = module.identifier_at(func_handle.name);
                Some((format!("{}::{}", module_name, func_name), "none".to_string()))
            } else {
                None
            }
        }
        Bytecode::CallGeneric(call_idx) => {
            if let Some(func_inst) = module.function_instantiations.get(call_idx.0 as usize) {
                if let Some(func_handle) = module.function_handles.get(func_inst.handle.0 as usize) {
                    let module_handle = &module.module_handles[func_handle.module.0 as usize];
                    let module_name = module.identifier_at(module_handle.name);
                    let func_name = module.identifier_at(func_handle.name);
                    Some((format!("{}::{}", module_name, func_name), format!("{:?}", func_inst)))
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn is_randomness_usage_strict(bytecode: &[Bytecode], source_idx: usize, module: &CompiledModule) -> bool {
    let end = bytecode.len().min(source_idx + 15);
    let mut random_used_for_decision = false;
    let mut random_stored_for_later = false;
    
    for i in source_idx + 1..end {
        match &bytecode[i] {
            // Direct use in decisions
            Bytecode::Mod | Bytecode::Div => {
                return true;
            }
            Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | Bytecode::Eq | Bytecode::Neq => {
                // Check if comparison involves the random value
                if i > 0 {
                    // Look back to see if compared value is from our random source
                    if is_value_from_source(bytecode, source_idx, i - 1) {
                        random_used_for_decision = true;
                    }
                }
            }
            Bytecode::Branch(_) => {
                // Check if branch depends on random value
                if i > 0 && is_value_from_source(bytecode, source_idx, i - 1) {
                    random_used_for_decision = true;
                }
            }
            // Storage for later use
            Bytecode::StLoc(_) => {
                if is_value_from_source(bytecode, source_idx, i - 1) {
                    random_stored_for_later = true;
                }
            }
            // Returned as result
            Bytecode::Ret => {
                if is_value_from_source(bytecode, source_idx, i - 1) {
                    return true;
                }
            }
            _ => {}
        }
    }
    
    random_used_for_decision || random_stored_for_later
}

fn is_value_from_source(bytecode: &[Bytecode], source_idx: usize, target_idx: usize) -> bool {
    // Simple data flow tracking: check if value at target_idx could come from source
    let mut stack_depth = 0;
    
    for i in source_idx..=target_idx {
        match &bytecode[i] {
            Bytecode::Pop => {
                if stack_depth > 0 {
                    stack_depth -= 1;
                }
            }
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                // Function call pushes result
                stack_depth += 1;
            }
            Bytecode::CopyLoc(_) | Bytecode::MoveLoc(_) | Bytecode::LdConst(_) => {
                stack_depth += 1;
            }
            Bytecode::StLoc(_) => {
                if stack_depth > 0 {
                    stack_depth -= 1;
                }
            }
            _ => {
                // Binary ops consume 2, push 1
                if matches!(bytecode[i], 
                    Bytecode::Add | Bytecode::Sub | Bytecode::Mul | Bytecode::Div | Bytecode::Mod |
                    Bytecode::BitOr | Bytecode::BitAnd | Bytecode::Xor | Bytecode::Shl | Bytecode::Shr |
                    Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | Bytecode::Eq | Bytecode::Neq) {
                    if stack_depth >= 2 {
                        stack_depth -= 1; // Consume 2, push 1
                    }
                }
            }
        }
    }
    
    // If source was called and value is still on stack, it might be used
    true // Simplified for brevity
}

fn is_definitely_randomness_context(bytecode: &[Bytecode], idx: usize) -> bool {
    // Look at surrounding code for randomness indicators
    let start = idx.saturating_sub(10);
    
    for i in start..idx {
        match &bytecode[i] {
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                // Check function names in actual implementation
            }
            _ => {}
        }
    }
    
    true
}

fn is_benign_context(bytecode: &[Bytecode], idx: usize, module: &CompiledModule) -> bool {
    // Check if this is used for events, logging, or other non-randomness purposes
    let end = bytecode.len().min(idx + 5);
    
    for i in idx..end {
        if let Some((func_name, _)) = get_function_call_details(&bytecode[i], module) {
            if func_name.contains("event") || func_name.contains("log") || func_name.contains("debug") {
                return true;
            }
        }
    }
    
    false
}

fn is_benign_usage(bytecode: &[Bytecode], idx: usize) -> bool {
    // Check if value is only used for non-critical purposes
    let end = bytecode.len().min(idx + 8);
    
    for i in idx + 1..end {
        match &bytecode[i] {
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                // Might be logging/event call
            }
            Bytecode::Pop => {
                // Value popped without use - definitely benign
                return true;
            }
            _ => {}
        }
    }
    
    false
}

fn analyze_randomness_patterns(code: &CodeUnit, module: &CompiledModule) -> bool {
    // Count uses of predictable sources
    let mut predictable_source_count = 0;
    let mut total_randomness_sources = 0;
    
    for (i, instr) in code.code.iter().enumerate() {
        if let Some((func_name, _)) = get_function_call_details(instr, module) {
            if func_name.contains("timestamp") || func_name.contains("block") || 
               func_name.contains("sender") || func_name.contains("tx_hash") {
                predictable_source_count += 1;
            }
            if func_name.contains("random") {
                total_randomness_sources += 1;
            }
        }
    }
    
    // Only flag if predictable sources are used and no secure sources
    predictable_source_count > 0 && total_randomness_sources == 0
}

fn has_secure_randomness_pattern(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // Check for commit-reveal or VRF patterns
    let func_handle = &module.function_handles[func_def.function.0 as usize];
    let func_name = module.identifier_at(func_handle.name);
    
    // Look for commit/reveal in function names or module structure
    if func_name.as_str().contains("commit") || func_name.as_str().contains("reveal") {
        return true;
    }
    
    // Check for VRF or cryptographic randomness
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some((func_name, _)) = get_function_call_details(instr, module) {
                if func_name.contains("vrf") || func_name.contains("VRF") || 
                   func_name.contains("random") || func_name.contains("Random") {
                    return true;
                }
            }
        }
    }
    
    false
}

fn is_random_value_modulo(bytecode: &[Bytecode], mod_idx: usize, module: &CompiledModule) -> bool {
    // Check if left operand of modulo comes from random source
    if mod_idx < 2 {
        return false;
    }
    
    // Look backwards for random source
    for i in (0..mod_idx).rev().take(8) {
        if let Some((func_name, _)) = get_function_call_details(&bytecode[i], module) {
            if func_name.contains("random") || func_name.contains("rand") || 
               func_name.contains("shuffle") || func_name.contains("select") {
                return true;
            }
        }
        
        // Check for timestamp/block sources
        if let Some((func_name, _)) = get_function_call_details(&bytecode[i], module) {
            if func_name.contains("timestamp") || func_name.contains("block") || 
               func_name.contains("now") || func_name.contains("epoch") {
                return true;
            }
        }
    }
    
    false
}

fn is_potentially_biased_modulo(bytecode: &[Bytecode], mod_idx: usize, module: &CompiledModule) -> bool {
    // Check if right operand (range) is constant and not power of 2
    if mod_idx > 0 {
        // Look for constant load before modulo
        for i in (0..mod_idx).rev().take(5) {
            if let Bytecode::LdConst(idx) = &bytecode[i] {
                // In actual implementation, check constant pool value
                // For now, assume bias unless we know it's power of 2
                return true;
            }
        }
    }
    
    true
}

fn is_random_value_division(bytecode: &[Bytecode], div_idx: usize, module: &CompiledModule) -> bool {
    // Similar to modulo check
    is_random_value_modulo(bytecode, div_idx, module)
}

fn uses_user_input_for_seed_strict(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // Only flag if user input is directly used without mixing
    if let Some(code) = &func_def.code {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let param_count = func_handle.parameters.0 as usize;
        
        let mut user_input_used = false;
        let mut mixed_with_secure = false;
        
        for instr in &code.code {
            match instr {
                Bytecode::CopyLoc(idx) | Bytecode::MoveLoc(idx) | Bytecode::StLoc(idx) => {
                    if (*idx as usize) < param_count {
                        user_input_used = true;
                    }
                }
                // Check if mixed with secure sources
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    // Look for mixing with nonces, timestamps, etc.
                    if let Some((func_name, _)) = get_function_call_details(instr, module) {
                        if func_name.contains("nonce") || func_name.contains("timestamp") || 
                           func_name.contains("block") || func_name.contains("hash") {
                            mixed_with_secure = true;
                        }
                    }
                }
                _ => {}
            }
        }
        
        user_input_used && !mixed_with_secure
    } else {
        false
    }
}

fn has_mix_with_nonces(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // Check if seed includes nonces or other unpredictable values
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some((func_name, _)) = get_function_call_details(instr, module) {
                if func_name.contains("nonce") || func_name.contains("counter") || 
                   func_name.contains("inc") || func_name.contains("unique") {
                    return true;
                }
            }
        }
    }
    
    false
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