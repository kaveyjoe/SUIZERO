// src/detectors/access_control/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use move_binary_format::{file_format::*, access::ModuleAccess};
use std::collections::{HashSet, HashMap};

// Track critical state across module analysis
#[derive(Default)]
struct ModuleSecurityContext {
    sensitive_functions: HashSet<String>,
    admin_controls: Vec<String>,
    validation_patterns: Vec<String>,
}

// AC-001: Missing Sender Validation 
pub struct MissingSenderValidation;

#[async_trait::async_trait]
impl SecurityDetector for MissingSenderValidation {
    fn id(&self) -> &'static str { "AC-001" }
    fn name(&self) -> &'static str { "Missing Sender Validation" }
    fn description(&self) -> &'static str {
        "Critical functions that modify state or transfer assets should validate the caller's identity"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        let mut security_ctx = ModuleSecurityContext::default();
        
        // First pass: Collect all validation patterns in module
        collect_validation_patterns(ctx, &mut security_ctx);
        
        for (func_idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            // Only check public/entry functions that ACTUALLY modify critical state
            if (func_def.visibility == Visibility::Public || func_def.is_entry) &&
               is_critical_state_modifier(func_def, &ctx.module) {
                
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                let func_name_str = func_name.as_str();
                
                //  Only flag if function name indicates admin/owner privilege
                let requires_privilege = func_name_str.contains("admin") ||
                                        func_name_str.contains("owner") ||
                                        func_name_str.contains("set_") ||
                                        func_name_str.contains("update_") ||
                                        func_name_str.contains("grant_") ||
                                        func_name_str.contains("revoke_");
                
                if requires_privilege {
                    // Check for explicit sender validation with bytecode analysis
                    if !has_explicit_sender_validation(func_def, &ctx.module) &&
                       !has_role_based_access_control(func_def, &ctx.module) {
                        
                        // Additional verification: Check if this is actually a dangerous function
                        if is_dangerous_function(func_def, &ctx.module) {
                            issues.push(create_access_issue(
                                self, ctx, func_idx, func_name_str,
                                "Critical function lacks sender validation and could be called by anyone",
                                "Add explicit sender validation: assert!(tx_context::sender(ctx) == admin_address, E_UNAUTHORIZED)",
                                vec!["CWE-284".to_string()],
                                Confidence::High,
                            ));
                        }
                    }
                }
            }
        }
        
        issues
    }
}

// Bytecode-level analysis for sender validation
fn has_explicit_sender_validation(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut tx_context_calls = Vec::new();
        let mut assert_calls = Vec::new();
        
        for (i, instr) in code.code.iter().enumerate() {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_str = func_name.as_str();
                
                // Look for tx_context::sender() calls
                if func_name_str.contains("tx_context::sender") ||
                   func_name_str.contains("ctx::sender") ||
                   func_name_str == "sender" {
                    tx_context_calls.push(i);
                }
                
                // Look for assertion calls
                if func_name_str.contains("assert") ||
                   func_name_str.contains("require") ||
                   func_name_str.contains("abort") {
                    assert_calls.push(i);
                }
            }
        }
        
        // Check if assertions happen after sender calls (validation pattern)
        for tx_call in tx_context_calls {
            for assert_call in &assert_calls {
                // If assertion happens close after sender call, likely validation
                if *assert_call > tx_call && (*assert_call - tx_call) <= 5 {
                    return true;
                }
            }
        }
    }
    
    false
}

// Check for role-based access control
fn has_role_based_access_control(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_str = func_name.as_str();
                if func_name_str.contains("has_role") ||
                   func_name_str.contains("check_role") ||
                   func_name_str.contains("only_role") ||
                   func_name_str.contains("require_role") {
                    return true;
                }
            }
        }
    }
    false
}

// Only flag truly dangerous functions
fn is_dangerous_function(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut dangerous_ops = 0;
        
        for instr in &code.code {
            match instr {
                // Global state modifications (MutBorrowGlobal is dangerous, MutBorrowField is less so)
                Bytecode::MutBorrowGlobal(_) |
                Bytecode::MutBorrowGlobalGeneric(_) => dangerous_ops += 2,
                
                // Critical function calls
                Bytecode::Call(_) |
                Bytecode::CallGeneric(_) => {
                    if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                        let func_name_str = func_name.as_str();
                        if func_name_str.contains("transfer") ||
                           func_name_str.contains("mint") ||
                           func_name_str.contains("burn") ||
                           func_name_str.contains("withdraw") {
                            dangerous_ops += 2;
                        }
                        if func_name_str.contains("share_object") ||
                           func_name_str.contains("freeze_object") {
                            dangerous_ops += 3;
                        }
                    }
                }
                _ => {}
            }
        }
        
        dangerous_ops >= 3
    } else {
        false
    }
}

// Only flag functions that modify critical state
fn is_critical_state_modifier(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            match instr {
                // Direct state modifications
                Bytecode::MutBorrowGlobal(_) |
                Bytecode::MutBorrowGlobalGeneric(_) => {
                    return true;
                }
                // Critical external calls
                Bytecode::Call(_) |
                Bytecode::CallGeneric(_) => {
                    if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                        let func_name_str = func_name.as_str();
                        if func_name_str.contains("transfer") ||
                           func_name_str.contains("mint") ||
                           func_name_str.contains("burn") ||
                           func_name_str.contains("share_object") {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    false
}

// AC-002: Hardcoded Addresses 
pub struct HardcodedAddress;

#[async_trait::async_trait]
impl SecurityDetector for HardcodedAddress {
    fn id(&self) -> &'static str { "AC-002" }
    fn name(&self) -> &'static str { "Hardcoded Addresses" }
    fn description(&self) -> &'static str {
        "Critical admin or treasury addresses are hardcoded without governance control"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        let mut critical_addresses = HashMap::new();
        
        // Collect all address constants and their usage
        for (const_idx, constant) in ctx.module.constant_pool.iter().enumerate() {
            if let SignatureToken::Address = constant.type_ {
                let address_bytes = &constant.data;
                
                // Skip zero address and test addresses
                if !is_zero_address(address_bytes) && 
                   !is_test_address(address_bytes) &&
                   !is_known_library_address(address_bytes) {
                    
                    // Track where this address is used
                    let usage_context = get_address_usage_context(&ctx.module, const_idx as u16);
                    
                    if is_critical_usage_context(&usage_context) {
                        critical_addresses.insert(const_idx, (address_bytes.clone(), usage_context));
                    }
                }
            }
        }
        
        // Only flag if addresses are used in critical operations
        for (const_idx, (address_bytes, usage_context)) in critical_addresses {
            let address_hex = hex::encode(address_bytes);
            
            // Check if this address is used as admin/owner in sensitive functions
            if is_admin_address_usage(&ctx.module, const_idx as u16) {
                issues.push(SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::High,
                    title: "Hardcoded admin address creates centralization risk".to_string(),
                    description: format!("Admin/owner address 0x{} is hardcoded and cannot be changed without contract upgrade", &address_hex[0..8]),
                    location: find_address_usage_location(ctx, const_idx as u16),
                    source_code: Some(format!("const ADMIN: address = 0x{}", &address_hex[0..16])),
                    recommendation: "Store admin addresses in config objects controlled by governance or multi-sig".to_string(),
                    references: vec![
                        "CWE-547: Use of Hard-coded, Security-relevant Constants".to_string(),
                    ],
                    metadata: {
                        let mut map = HashMap::new();
                        map.insert("address".to_string(), format!("0x{}", address_hex));
                        map.insert("usage_context".to_string(), usage_context);
                        map
                    },
                });
            }
        }
        
        issues
    }
}

fn is_admin_address_usage(module: &CompiledModule, const_idx: u16) -> bool {
    for func_def in &module.function_defs {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        
        // Check if function uses this constant and is admin-related
        if func_name.contains("admin") ||
           func_name.contains("owner") ||
           func_name.contains("set_") ||
           func_name.contains("update_") {
            
            if uses_constant(func_def, const_idx) {
                return true;
            }
        }
    }
    false
}

fn uses_constant(func_def: &FunctionDefinition, const_idx: u16) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Bytecode::LdConst(idx) = instr {
                if *idx == ConstantPoolIndex(const_idx) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_test_address(bytes: &[u8]) -> bool {
    // Common test addresses
    let test_patterns = [
        [0x01; 32], // Sequential pattern
        [0xAA; 32], // Alternating pattern
        [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // deadbeef pattern
    ];
    
    test_patterns.iter().any(|pattern| bytes.starts_with(pattern))
}

fn is_zero_address(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn is_known_library_address(bytes: &[u8]) -> bool {
    // Check for known system/library addresses
    let known_addresses: Vec<&[u8]> = vec![
        // SUI system addresses would go here
    ];
    
    known_addresses.iter().any(|addr| bytes == *addr)
}

fn is_critical_usage_context(context: &str) -> bool {
    context.contains("admin") ||
    context.contains("owner") ||
    context.contains("treasury") ||
    context.contains("fee_collector")
}

fn get_address_usage_context(module: &CompiledModule, const_idx: u16) -> String {
    // Simplified context analysis
    for func_def in &module.function_defs {
        if uses_constant(func_def, const_idx) {
            let func_handle = &module.function_handles[func_def.function.0 as usize];
            return module.identifier_at(func_handle.name).to_string();
        }
    }
    "unknown".to_string()
}

// AC-004: Missing Role Check
pub struct MissingRoleCheck;

#[async_trait::async_trait]
impl SecurityDetector for MissingRoleCheck {
    fn id(&self) -> &'static str { "AC-004" }
    fn name(&self) -> &'static str { "Missing Role Check" }
    fn description(&self) -> &'static str {
        "Admin/owner functions lack proper role validation"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Build map of role-checking functions
        let mut role_check_functions = HashSet::new();
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            if func_name.as_str().contains("has_role") || func_name.as_str().contains("require_role") {
                role_check_functions.insert(func_name.to_string());
            }
        }
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_str = func_name.as_str();
            
            // ULTRA STRICT: Only check functions with clear admin/privilege names
            let is_privileged_function = func_name_str.starts_with("set_") ||
                                        func_name_str.starts_with("update_") ||
                                        func_name_str.starts_with("grant_") ||
                                        func_name_str.starts_with("revoke_") ||
                                        func_name_str.contains("admin_") ||
                                        func_name_str.contains("owner_");
            
            if is_privileged_function && 
               (func_def.visibility == Visibility::Public || func_def.is_entry) &&
               !has_explicit_role_check(func_def, &ctx.module, &role_check_functions) &&
               is_critical_state_modifier(func_def, &ctx.module) {
                
                issues.push(create_access_issue(
                    self, ctx, 0, func_name_str,
                    "Privileged function lacks role-based access control",
                    "Implement role checking: require(has_role(msg.sender, ADMIN_ROLE), 'Unauthorized')",
                    vec!["CWE-862: Missing Authorization".to_string()],
                    Confidence::High,
                ));
            }
        }
        
        issues
    }
}

fn has_explicit_role_check(func_def: &FunctionDefinition, module: &CompiledModule, 
                           role_check_functions: &HashSet<String>) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                if role_check_functions.contains(func_name.as_str()) {
                    return true;
                }
                
                // Also check for inline role checks
                let func_name_str = func_name.as_str();
                if func_name_str.contains("sender") && 
                   (func_name_str.contains("admin") || func_name_str.contains("owner")) {
                    return true;
                }
            }
        }
    }
    false
}

// AC-006: Privilege Escalation 
pub struct PrivilegeEscalation;

#[async_trait::async_trait]
impl SecurityDetector for PrivilegeEscalation {
    fn id(&self) -> &'static str { "AC-006" }
    fn name(&self) -> &'static str { "Privilege Escalation" }
    fn description(&self) -> &'static str {
        "Functions that modify permissions lack proper authorization checks"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // ULTRA STRICT: Only look for permission-modifying functions
        let permission_modifiers = ["grant_role", "revoke_role", "set_admin", "transfer_ownership", 
                                   "add_owner", "remove_owner", "update_permissions"];
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_str = func_name.as_str();
            
            if permission_modifiers.iter().any(|&modifier| func_name_str == modifier) {
                // This is a permission-modifying function - it MUST have strong validation
                if !has_strong_authorization_check(func_def, &ctx.module) {
                    issues.push(create_access_issue(
                        self, ctx, 0, func_name_str,
                        "Permission-modifying function lacks sufficient authorization checks",
                        "Implement multi-sig, timelock, or governance-controlled permission changes",
                        vec!["CWE-269: Improper Privilege Management".to_string()],
                        Confidence::High,
                    ));
                }
            }
        }
        
        issues
    }
}

fn has_strong_authorization_check(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut validation_count = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_str = func_name.as_str();
                
                // Count strong validation patterns
                if func_name_str.contains("tx_context::sender") { validation_count += 2; }
                if func_name_str.contains("assert") { validation_count += 1; }
                if func_name_str.contains("require") { validation_count += 1; }
                if func_name_str.contains("only_owner") { validation_count += 3; }
                if func_name_str.contains("has_role") { validation_count += 2; }
                
                // Multi-sig checks
                if func_name_str.contains("multisig") || func_name_str.contains("signature") {
                    validation_count += 3;
                }
            }
        }
        
        // Require strong validation for permission-modifying functions
        validation_count >= 3
    } else {
        false
    }
}

// AC-008: Unlimited Minting 
pub struct UnlimitedMinting;

#[async_trait::async_trait]
impl SecurityDetector for UnlimitedMinting {
    fn id(&self) -> &'static str { "AC-008" }
    fn name(&self) -> &'static str { "Unlimited Minting" }
    fn description(&self) -> &'static str {
        "Token minting functions lack supply caps or rate limits"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check if this is a token module
        if !is_token_module(&ctx.module) {
            return issues;
        }
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_str = func_name.as_str();
            
            // ULTRA STRICT: Only check explicit minting functions
            if func_name_str == "mint" || func_name_str.starts_with("mint_") {
                // Check for supply limit validation
                if !has_supply_validation(func_def, &ctx.module) {
                    issues.push(create_access_issue(
                        self, ctx, 0, func_name_str,
                        "Minting function lacks supply limit checks",
                        "Add total supply cap and/or rate limiting mechanisms",
                        vec!["CWE-770: Allocation of Resources Without Limits or Throttling".to_string()],
                        Confidence::High,
                    ));
                }
            }
        }
        
        issues
    }
}

fn is_token_module(module: &CompiledModule) -> bool {
    let module_name = module.self_id().name().as_str().to_lowercase();
    module_name.contains("token") ||
    module_name.contains("coin") ||
    module_name.contains("fungible")
}

fn has_supply_validation(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_str = func_name.as_str();
                if func_name_str.contains("total_supply") ||
                   func_name_str.contains("max_supply") ||
                   func_name_str.contains("cap") ||
                   func_name_str.contains("limit") {
                    return true;
                }
            }
        }
    }
    false
}

// AC-010: Centralization Risk 
pub struct CentralizationRisk;

#[async_trait::async_trait]
impl SecurityDetector for CentralizationRisk {
    fn id(&self) -> &'static str { "AC-010" }
    fn name(&self) -> &'static str { "Centralization Risk" }
    fn description(&self) -> &'static str {
        "Contracts have single points of failure with no recovery mechanisms"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check for single admin/owner pattern without recovery
        let mut single_admin_detected = false;
        let mut has_recovery_mechanism = false;
        
        // Look for admin-related functions
        let admin_functions: Vec<_> = ctx.module.function_defs.iter()
            .filter(|f| {
                let func_handle = &ctx.module.function_handles[f.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
                func_name.contains("admin") || func_name.contains("owner") || func_name.contains("set_")
            })
            .collect();
        
        // Check if there's only one admin control mechanism
        if admin_functions.len() == 1 {
            // Look for recovery mechanisms
            has_recovery_mechanism = has_emergency_recovery(&ctx.module);
            
            if !has_recovery_mechanism {
                let location = create_module_location(ctx);
                
                issues.push(SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::Medium,
                    title: "Centralization risk: Single admin without recovery".to_string(),
                    description: "Contract relies on single admin/owner address without emergency recovery mechanism".to_string(),
                    location,
                    source_code: None,
                    recommendation: "Implement multi-sig, timelock-controlled admin changes, or emergency recovery mechanisms".to_string(),
                    references: vec![
                        "CWE-1298: Hard-coded Credentials".to_string(),
                    ],
                    metadata: HashMap::new(),
                });
            }
        }
        
        issues
    }
}

fn has_emergency_recovery(module: &CompiledModule) -> bool {
    // Check for emergency recovery functions
    let recovery_functions = ["emergency_pause", "timelock", "multisig", "governance"];
    
    for func_def in &module.function_defs {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        
        if recovery_functions.iter().any(|&rf| func_name.contains(rf)) {
            return true;
        }
    }
    false
}

// AC-011: Signature Replay 
pub struct SignatureReplay;

#[async_trait::async_trait]
impl SecurityDetector for SignatureReplay {
    fn id(&self) -> &'static str { "AC-011" }
    fn name(&self) -> &'static str { "Signature Replay" }
    fn description(&self) -> &'static str {
        "Signature-based authorization lacks replay protection"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check if module uses signature verification
        if !uses_signature_verification(&ctx.module) {
            return issues;
        }
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("verify") || func_name.as_str().contains("signature") {
                if !has_replay_protection_mechanism(func_def, &ctx.module) {
                    issues.push(create_access_issue(
                        self, ctx, 0, func_name.as_str(),
                        "Signature verification lacks replay protection",
                        "Include nonce, timestamp, and chain ID in signed messages; track used signatures",
                        vec!["CWE-294: Authentication Bypass by Capture-replay".to_string()],
                        Confidence::High,
                    ));
                }
            }
        }
        
        issues
    }
}

fn uses_signature_verification(module: &CompiledModule) -> bool {
    for func_def in &module.function_defs {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        if func_name.contains("verify") || func_name.contains("signature") {
            return true;
        }
    }
    false
}

fn has_replay_protection_mechanism(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut protection_elements = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_str = func_name.as_str();
                
                if func_name_str.contains("nonce") { protection_elements += 2; }
                if func_name_str.contains("timestamp") { protection_elements += 1; }
                if func_name_str.contains("chain_id") { protection_elements += 2; }
                if func_name_str.contains("deadline") { protection_elements += 1; }
                if func_name_str.contains("used_signatures") { protection_elements += 3; }
            }
        }
        
        protection_elements >= 2
    } else {
        false
    }
}

// Helper functions
fn create_access_issue(
    detector: &impl SecurityDetector,
    ctx: &DetectionContext,
    func_idx: usize,
    func_name: &str,
    description: &str,
    recommendation: &str,
    references: Vec<String>,
    confidence: Confidence,
) -> SecurityIssue {
    let func_def = &ctx.module.function_defs[func_idx];
    let location = create_code_location(ctx, func_def, 0);
    
    SecurityIssue {
        id: detector.id().to_string(),
        severity: detector.default_severity(),
        confidence,
        title: format!("{} in '{}'", detector.name(), func_name),
        description: description.to_string(),
        location,
        source_code: Some(func_name.to_string()),
        recommendation: recommendation.to_string(),
        references,
        metadata: {
            let mut map = HashMap::new();
            map.insert("function_name".to_string(), func_name.to_string());
            map
        },
    }
}

fn create_code_location(ctx: &DetectionContext, func_def: &FunctionDefinition, instruction_idx: u16) -> CodeLocation {
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

fn find_address_usage_location(ctx: &DetectionContext, const_idx: u16) -> CodeLocation {
    // Find first function that uses this constant
    for (func_idx, func_def) in ctx.module.function_defs.iter().enumerate() {
        if uses_constant(func_def, const_idx) {
            return create_code_location(ctx, func_def, 0);
        }
    }
    create_module_location(ctx)
}

fn collect_validation_patterns(ctx: &DetectionContext, security_ctx: &mut ModuleSecurityContext) {
    // Collect validation patterns from the module
    for func_def in &ctx.module.function_defs {
        let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
        let func_name = ctx.module.identifier_at(func_handle.name);
        
        if func_name.as_str().contains("assert") ||
           func_name.as_str().contains("require") ||
           func_name.as_str().contains("validate") {
            security_ctx.validation_patterns.push(func_name.to_string());
        }
        
        if func_name.as_str().contains("admin") ||
           func_name.as_str().contains("owner") {
            security_ctx.admin_controls.push(func_name.to_string());
        }
    }
}

// Only include detectors that can be made extremely strict
pub fn get_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(MissingSenderValidation),
        Box::new(HardcodedAddress),
        Box::new(MissingRoleCheck),
        Box::new(PrivilegeEscalation),
        Box::new(UnlimitedMinting),
        Box::new(CentralizationRisk),
        Box::new(SignatureReplay),
    ]
}
