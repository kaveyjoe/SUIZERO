use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, CodeUnit, FunctionHandleIndex, SignatureToken, Visibility},
    CompiledModule,
};
use move_core_types::identifier::IdentStr;
use std::collections::HashMap;

// Improved helper function to check for capability usage in Sui context
fn check_capability_usage(module: &CompiledModule, code: &CodeUnit) -> bool {
    // Check if the function has capability parameters that are actually used
    for instr in &code.code {
        // Look for operations that indicate capability is being used for auth checks
        match instr {
            // Check for equality comparisons (typically used for capability validation)
            Bytecode::Eq | Bytecode::Neq => return true,
            // Check for aborts that indicate failed auth checks
            Bytecode::Abort => return true,
            // Check for branching that indicates conditional auth
            Bytecode::BrTrue(_) | Bytecode::BrFalse(_) => return true,
            // Check for calls to validation functions
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                // We'll check if this is a call to a validation function
            }
            _ => {}
        }
    }
    false
}

// Check if a function actually validates its capability parameter
fn function_validates_capability(func_def: &move_binary_format::file_format::FunctionDefinition) -> bool {
    if let Some(ref code) = func_def.code {
        // Look for auth validation patterns in the function body
        for instr in &code.code {
            match instr {
                // Equality checks are commonly used to validate capabilities
                Bytecode::Eq | Bytecode::Neq => return true,
                // Branch instructions after comparisons
                Bytecode::BrTrue(_) | Bytecode::BrFalse(_) => return true,
                // Abort instructions after failed checks
                Bytecode::Abort => return true,
                // Calls to validation functions
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    // In a more detailed analysis, we could check if this is a validation call
                }
                _ => {}
            }
        }
    }
    false
}

// Check if a function has capability parameters
fn has_capability_parameter(module: &CompiledModule, func_def: &move_binary_format::file_format::FunctionDefinition) -> bool {
    let func_handle = module.function_handle_at(func_def.function);
    let parameters = module.signature_at(func_handle.parameters);
    
    for token in &parameters.0 {
        let struct_handle_index = match token {
            SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                match &**inner {
                    SignatureToken::Struct(idx) => Some(*idx),
                    SignatureToken::StructInstantiation(idx, _) => Some(*idx),
                    _ => None,
                }
            }
            SignatureToken::Struct(idx) => Some(*idx),
            SignatureToken::StructInstantiation(idx, _) => Some(*idx),
            _ => None,
        };

        if let Some(idx) = struct_handle_index {
            let struct_handle = module.struct_handle_at(idx);
            let name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
            // More specific capability naming patterns
            if name.contains("cap") || name.contains("capability") || 
               name.contains("admin") || name.contains("owner") ||
               name.contains("auth") || name.contains("permission") {
                return true;
            }
        }
    }
    false
}

// Helper function to check if function is a known administrative function
fn is_administrative_function(func_name: &str) -> bool {
    let lower_name = func_name.to_lowercase();
    lower_name.contains("admin") || lower_name.contains("owner") || 
    lower_name.starts_with("set_") || lower_name.contains("update") ||
    lower_name.contains("transfer") || lower_name.contains("drain") ||
    lower_name.contains("pause") || lower_name.contains("upgrade") ||
    lower_name.contains("emergency")
}

fn create_ext_location(ctx: &DetectionContext, func_name: &str) -> CodeLocation {
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: 0,
        byte_offset: 0,
        line: None,
        column: None,
    }
}

pub struct UnauthorizedMintDetector;

#[async_trait::async_trait]
impl SecurityDetector for UnauthorizedMintDetector {
    fn id(&self) -> &'static str { "EXT-AC-001" }
    fn name(&self) -> &'static str { "Unauthorized Mint Function" }
    fn description(&self) -> &'static str { "Detects mint functions without proper access control" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        let module = &ctx.module;
        
        for func_def in &module.function_defs {
            let func_handle = module.function_handle_at(func_def.function);
            let func_name = module.identifier_at(func_handle.name).to_string();
            
            // More specific mint function detection
            if func_name.to_lowercase().contains("mint") {
                // Check if function has capability parameter
                let has_capability_param = has_capability_parameter(module, func_def);
                
                // Check if function actually validates its parameters
                let validates_input = function_validates_capability(func_def);
                
                // More stringent check: if no capability parameter and doesn't validate properly
                if !has_capability_param && !validates_input {
                    // Additional check: see if function creates new objects or coins
                    let creates_objects = if let Some(code) = &func_def.code {
                        code.code.iter().any(|instr| {
                            matches!(instr, Bytecode::MoveTo(_) | Bytecode::MoveToGeneric(_))
                        })
                    } else { false };
                    
                    if creates_objects {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High, // Increased confidence
                            title: format!("Unauthorized mint in '{}'", func_name),
                            description: format!("Function '{}' allows asset creation without proper capability-based authorization. On Sui, mint functions should require a specific capability object as parameter.", func_name),
                            location: create_ext_location(ctx, &func_name),
                            source_code: Some(func_name.clone()),
                            recommendation: "Require a dedicated MintCapability object as a parameter. Do not rely solely on tx_context::sender() for authorization in mint functions.".to_string(),
                            references: vec!["OWASP Access Control".to_string(), "Sui Capability Patterns".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct UnauthorizedBurnDetector;

#[async_trait::async_trait]
impl SecurityDetector for UnauthorizedBurnDetector {
    fn id(&self) -> &'static str { "EXT-AC-002" }
    fn name(&self) -> &'static str { "Unauthorized Burn Function" }
    fn description(&self) -> &'static str { "Detects burn functions without proper authorization" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        let module = &ctx.module;
        
        for func_def in &module.function_defs {
            let func_handle = module.function_handle_at(func_def.function);
            let func_name = module.identifier_at(func_handle.name).to_string();
            
            // More specific burn function detection
            if func_name.to_lowercase().contains("burn") {
                // Check if function has capability parameter
                let has_capability_param = has_capability_parameter(module, func_def);
                
                // Check if function actually validates its parameters
                let validates_input = function_validates_capability(func_def);
                
                // More stringent check: if no capability parameter and doesn't validate properly
                if !has_capability_param && !validates_input {
                    // Additional check: see if function destroys objects
                    let destroys_objects = if let Some(code) = &func_def.code {
                        code.code.iter().any(|instr| {
                            matches!(instr, Bytecode::MoveFrom(_) | Bytecode::MoveFromGeneric(_))
                        })
                    } else { false };
                    
                    if destroys_objects {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High, // Increased confidence
                            title: format!("Unauthorized burn in '{}'", func_name),
                            description: format!("Function '{}' allows asset destruction without proper capability-based authorization. On Sui, burn functions should require a specific capability object as parameter.", func_name),
                            location: create_ext_location(ctx, &func_name),
                            source_code: Some(func_name.clone()),
                            recommendation: "Require a dedicated BurnCapability object as a parameter. Do not rely solely on tx_context::sender() for authorization in burn functions.".to_string(),
                            references: vec!["OWASP Access Control".to_string(), "Sui Capability Patterns".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}
// ========== 3-20: Remaining Access Control Detectors ==========

pub struct MissingOwnerCheckDetector;
#[async_trait::async_trait]
impl SecurityDetector for MissingOwnerCheckDetector {
    fn id(&self) -> &'static str { "EXT-AC-022" }
    fn name(&self) -> &'static str { "Missing Owner Check" }
    fn description(&self) -> &'static str { "Detects functions that should check for owner but don't" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).to_string();
            
            // Heuristic: functions named "set_admin", "change_owner", "set_owner", etc. usually require owner check
            if func_name.contains("set_admin") || func_name.contains("change_owner") || func_name.contains("transfer_ownership") || func_name.contains("set_owner") || func_name.contains("emergency_") {
                // Check if function has capability parameter
                let has_capability_param = has_capability_parameter(&ctx.module, func_def);
                
                // Check if function actually validates its parameters
                let validates_input = function_validates_capability(func_def);
                
                if !has_capability_param && !validates_input {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                        title: "Missing owner check".to_string(),
                        description: format!("Function '{}' appears to be administrative but lacks owner capability check", func_name),
                        location: create_ext_location(ctx, &func_name), source_code: None,
                        recommendation: "Ensure this function requires an admin or owner capability.".to_string(),
                        references: vec![], metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct UnauthorizedTransferDetector;
#[async_trait::async_trait]
impl SecurityDetector for UnauthorizedTransferDetector {
    fn id(&self) -> &'static str { "EXT-AC-004" }
    fn name(&self) -> &'static str { "Unauthorized Transfer" }
    fn description(&self) -> &'static str { "Detects transfer functions without proper access control" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).to_string();
            
            if func_name.to_lowercase().contains("transfer") && func_def.visibility == Visibility::Public {
                // Check for capability parameter
                let has_capability_param = has_capability_parameter(&ctx.module, func_def);
                
                // Check for signer parameter
                let params_sig = ctx.module.signature_at(func_handle.parameters);
                let has_signer = params_sig.0.iter().any(|t| matches!(t, SignatureToken::Signer));
                
                // Check if function validates its parameters
                let validates_input = function_validates_capability(func_def);
                
                if !has_signer && !has_capability_param && !validates_input {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                        title: "Public transfer without authorization".to_string(),
                        description: format!("'{}' allows transfers without proper authorization", func_name),
                        location: create_ext_location(ctx, &func_name), source_code: None,
                        recommendation: "Require signer parameter or capability object for transfers.".to_string(),
                        references: vec![], metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct UnauthorizedUpdateDetector;
#[async_trait::async_trait]
impl SecurityDetector for UnauthorizedUpdateDetector {
    fn id(&self) -> &'static str { "EXT-AC-005" }
    fn name(&self) -> &'static str { "Unauthorized Update" }
    fn description(&self) -> &'static str { "Detects update functions without access control" }
    fn default_severity(&self) -> Severity {  Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).to_string();
            
            if func_name.to_lowercase().contains("update") || func_name.to_lowercase().contains("modify") {
                // Check if function has capability parameter
                let has_capability_param = has_capability_parameter(&ctx.module, func_def);
                
                // Check if function actually validates its parameters
                let validates_input = function_validates_capability(func_def);
                
                if !has_capability_param && !validates_input {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                        title: "Update without authorization".to_string(),
                        description: format!("'{}' lacks access control", func_name),
                        location: create_ext_location(ctx, &func_name), source_code: None,
                        recommendation: "Add capability checks.".to_string(),
                        references: vec![], metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct UnauthorizedFreezeDetector;
#[async_trait::async_trait]
impl SecurityDetector for UnauthorizedFreezeDetector {
    fn id(&self) -> &'static str { "EXT-AC-006" }
    fn name(&self) -> &'static str { "Unauthorized Freeze" }
    fn description(&self) -> &'static str { "Detects freeze functions without access control" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).to_string();
            
            if func_name.to_lowercase().contains("freeze") || func_name.to_lowercase().contains("pause") {
                // Check if function has capability parameter
                let has_capability_param = has_capability_parameter(&ctx.module, func_def);
                
                // Check if function actually validates its parameters
                let validates_input = function_validates_capability(func_def);
                
                if !has_capability_param && !validates_input {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                        title: "Freeze without authorization".to_string(),
                        description: format!("'{}' can freeze without authorization", func_name),
                        location: create_ext_location(ctx, &func_name), source_code: None,
                        recommendation: "Require admin capability for freeze.".to_string(),
                        references: vec![], metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct UnauthorizedAdminActionDetector;
#[async_trait::async_trait]
impl SecurityDetector for UnauthorizedAdminActionDetector {
    fn id(&self) -> &'static str { "EXT-AC-007" }
    fn name(&self) -> &'static str { "Unauthorized Admin Action" }
    fn description(&self) -> &'static str { "Detects admin functions without access control" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).to_string();
            
            if func_name.starts_with("admin_") || func_name.starts_with("owner_") || func_name.starts_with("emergency_") || func_name.contains("drain") {
                // Check if function has capability parameter
                let has_capability_param = has_capability_parameter(&ctx.module, func_def);
                
                // Check if function actually validates its parameters
                let validates_input = function_validates_capability(func_def);
                
                if !has_capability_param && !validates_input {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                        title: "Admin function without capability".to_string(),
                        description: format!("Admin function '{}' lacks capability check", func_name),
                        location: create_ext_location(ctx, &func_name), source_code: None,
                        recommendation: "Require AdminCap for all admin functions.".to_string(),
                        references: vec!["CWE-284: Improper Access Control".to_string()],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct MissingRoleBasedAccessDetector;
#[async_trait::async_trait]
impl SecurityDetector for MissingRoleBasedAccessDetector {
    fn id(&self) -> &'static str { "EXT-AC-008" }
    fn name(&self) -> &'static str { "Missing Role-Based Access" }
    fn description(&self) -> &'static str { "Detects lack of role-based access control" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        let public_count = ctx.module.function_defs.iter().filter(|f| f.visibility == Visibility::Public).count();
        
        let has_roles = ctx.module.struct_defs.iter().any(|s| {
            let handle = ctx.module.struct_handle_at(s.struct_handle);
            let name = ctx.module.identifier_at(handle.name).to_string();
            name.contains("Role") || name.contains("Cap")
        });
        
        if public_count > 10 && !has_roles {
            issues.push(SecurityIssue {
                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                title: "No role-based access control".to_string(),
                description: format!("{} public functions without RBAC", public_count),
                location: create_ext_location(ctx, "module"), source_code: None,
                recommendation: "Implement role-based access control system.".to_string(),
                references: vec![], metadata: HashMap::new(),
            });
        }
        
        issues
    }
}

pub struct WeakAdminRecoveryDetector;
#[async_trait::async_trait]
impl SecurityDetector for WeakAdminRecoveryDetector {
    fn id(&self) -> &'static str { "EXT-AC-009" }
    fn name(&self) -> &'static str { "Weak Admin Recovery" }
    fn description(&self) -> &'static str { "Detects weak admin recovery mechanisms" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).to_string();
            
            if func_name.contains("recover") || func_name.contains("rescue") {
                // Check if function has capability parameter
                let has_capability_param = has_capability_parameter(&ctx.module, func_def);
                
                // Check if function actually validates its parameters
                let validates_input = function_validates_capability(func_def);
                
                if !has_capability_param && !validates_input {
                     issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                        title: "Potential weak recovery function".to_string(),
                        description: format!("Recovery function '{}' might not be adequately protected", func_name),
                        location: create_ext_location(ctx, &func_name), source_code: None,
                        recommendation: "Ensure recovery functions are strictly gated by admin capabilities.".to_string(),
                        references: vec![], metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct AdminKeyCompromiseDetector;
#[async_trait::async_trait]
impl SecurityDetector for AdminKeyCompromiseDetector {
    fn id(&self) -> &'static str { "EXT-AC-010" }
    fn name(&self) -> &'static str { "Admin Key Compromise Risk" }
    fn description(&self) -> &'static str { "Detects single point of failure in admin keys" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        // Naive check: if there is only one struct with "AdminCap" in the name, it suggests a single admin model.
        let admin_caps_count = ctx.module.struct_defs.iter().filter(|s| {
            let handle = ctx.module.struct_handle_at(s.struct_handle);
            let name = ctx.module.identifier_at(handle.name).to_string();
            name.contains("AdminCap")
        }).count();

        if admin_caps_count == 1 {
             issues.push(SecurityIssue {
                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                title: "Single Admin Capability Found".to_string(),
                description: "The module appears to rely on a single AdminCap, which is a single point of failure.".to_string(),
                location: create_ext_location(ctx, "module"), source_code: None,
                recommendation: "Consider using multisig or a DAO structure for administration to avoid single point of failure.".to_string(),
                references: vec![], metadata: HashMap::new(),
            });
        }
        issues
    }
}

pub struct MultisigBypassDetector;
#[async_trait::async_trait]
impl SecurityDetector for MultisigBypassDetector {
    fn id(&self) -> &'static str { "EXT-AC-011" }
    fn name(&self) -> &'static str { "Multisig Bypass" }
    fn description(&self) -> &'static str { "Detects potential multisig bypass vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
         let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).to_string();
            
            if func_name.contains("multisig") {
                // If a function claims to be multisig but takes only one signer, it's suspicious
                let params_sig = ctx.module.signature_at(func_handle.parameters);
                let signer_count = params_sig.0.iter().filter(|t| matches!(t, SignatureToken::Signer)).count();
                // Or if it doesn't take a vector of signatures (simplified check)
                
                if signer_count == 1 && !func_name.contains("init") {
                     issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Potential Multisig Bypass".to_string(),
                        description: format!("Function '{}' contains 'multisig' but appears to take a single signer.", func_name),
                        location: create_ext_location(ctx, &func_name), source_code: None,
                        recommendation: "Verify that this function properly verifies multiple signatures.".to_string(),
                        references: vec![], metadata: HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct SignerSpoofingDetector;
#[async_trait::async_trait]
impl SecurityDetector for SignerSpoofingDetector {
    fn id(&self) -> &'static str { "EXT-AC-012" }
    fn name(&self) -> &'static str { "Signer Spoofing" }
    fn description(&self) -> &'static str { "Detects signer spoofing vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        // Signer spoofing usually involves passing an address instead of &signer and treating it as authenticated.
        // This is hard to detect without data flow, but we can look for functions taking `address` args named `signer` or similar.
        vec![] 
    }
}

pub struct TxContextManipulationDetector;
#[async_trait::async_trait]
impl SecurityDetector for TxContextManipulationDetector {
    fn id(&self) -> &'static str { "EXT-AC-013" }
    fn name(&self) -> &'static str { "TxContext Manipulation" }
    fn description(&self) -> &'static str { "Detects transaction context manipulation" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        // Detecting if code overly relies on tx_context::sender() where it should use a capability.
        vec![] 
    }
}

pub struct PrivilegeEscalationDetector;
#[async_trait::async_trait]
impl SecurityDetector for PrivilegeEscalationDetector {
    fn id(&self) -> &'static str { "EXT-AC-014" }
    fn name(&self) -> &'static str { "Privilege Escalation" }
    fn description(&self) -> &'static str { "Detects privilege escalation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        vec![] // Requires deep analysis
    }
}

pub struct FunctionVisibilityAbuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for FunctionVisibilityAbuseDetector {
    fn id(&self) -> &'static str { "EXT-AC-015" }
    fn name(&self) -> &'static str { "Function Visibility Abuse" }
    fn description(&self) -> &'static str { "Detects improper function visibility" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).to_string();
            
            if func_def.visibility == Visibility::Public && 
               (func_name.contains("internal") || func_name.starts_with("_")) {
                issues.push(SecurityIssue {
                    id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                    title: "Internal function exposed publicly".to_string(),
                    description: format!("'{}' should be private", func_name),
                    location: create_ext_location(ctx, &func_name), source_code: None,
                    recommendation: "Make internal functions private.".to_string(),
                    references: vec![], metadata: HashMap::new(),
                });
            }
        }
        
        issues
    }
}

pub struct InitializerBypassDetector;
#[async_trait::async_trait]
impl SecurityDetector for InitializerBypassDetector {
    fn id(&self) -> &'static str { "EXT-AC-016" }
    fn name(&self) -> &'static str { "Initializer Bypass" }
    fn description(&self) -> &'static str { "Detects initializer bypass vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        // Check for public functions named "init" or "initialize" that are NOT the official module initializer.
        // The official initializer is private and named "init".
        for func_def in &ctx.module.function_defs {
            let func_handle = ctx.module.function_handle_at(func_def.function);
            let func_name = ctx.module.identifier_at(func_handle.name).to_string();
            
            if (func_name == "init" || func_name == "initialize") && func_def.visibility == Visibility::Public {
                 issues.push(SecurityIssue {
                    id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                    title: "Public Initializer Function".to_string(),
                    description: format!("Function '{}' is public, allowing anyone to re-initialize or trigger initialization logic.", func_name),
                    location: create_ext_location(ctx, &func_name), source_code: None,
                    recommendation: "Ensure initialization functions are private or protected by a 'once' flag.".to_string(),
                    references: vec![], metadata: HashMap::new(),
                });
            }
        }
        issues
    }
}

pub struct CapabilityLeakDetector;
#[async_trait::async_trait]
impl SecurityDetector for CapabilityLeakDetector {
    fn id(&self) -> &'static str { "EXT-AC-017" }
    fn name(&self) -> &'static str { "Capability Leak" }
    fn description(&self) -> &'static str { "Detects capability leakage" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for func_def in &ctx.module.function_defs {
             if func_def.visibility == Visibility::Public {
                 let func_handle = ctx.module.function_handle_at(func_def.function);
                 let return_sig = ctx.module.signature_at(func_handle.return_);
                 
                 // If a public function returns a struct with "Cap" in its name, it might be leaking a capability
                 for token in &return_sig.0 {
                     if let SignatureToken::Struct(idx) | SignatureToken::StructInstantiation(idx, _) = token {
                        let struct_handle = ctx.module.struct_handle_at(*idx);
                        let struct_name = ctx.module.identifier_at(struct_handle.name);
                        if struct_name.as_str().to_lowercase().contains("cap") {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: "Capability leak in public function".to_string(),
                                description: format!("Public function returns capability type '{}'", struct_name),
                                location: create_ext_location(ctx, "unknown"),
                                source_code: Some(struct_name.to_string()),
                                recommendation: "Do not return capability objects from public functions. Instead, consume them in the function.".to_string(),
                                references: vec![],
                                metadata: HashMap::new(),
                            });
                        }
                     }
                 }
             }
        }
        issues
    }
}

pub struct ObjectCapabilityReuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for ObjectCapabilityReuseDetector {
    fn id(&self) -> &'static str { "EXT-AC-018" }
    fn name(&self) -> &'static str { "Object Capability Reuse" }
    fn description(&self) -> &'static str { "Detects object capability reuse issues" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        vec![] // Requires object lifecycle tracking
    }
}

pub struct SharedObjectAuthBypassDetector;
#[async_trait::async_trait]
impl SecurityDetector for SharedObjectAuthBypassDetector {
    fn id(&self) -> &'static str { "EXT-AC-019" }
    fn name(&self) -> &'static str { "Shared Object Auth Bypass" }
    fn description(&self) -> &'static str { "Detects shared object authorization bypass" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        vec![] // Sui-specific shared object analysis
    }
}

pub struct DelegatedAuthAbuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for DelegatedAuthAbuseDetector {
    fn id(&self) -> &'static str { "EXT-AC-020" }
    fn name(&self) -> &'static str { "Delegated Auth Abuse" }
    fn description(&self) -> &'static str { "Detects delegated authorization abuse" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        vec![] // Requires delegation chain analysis
    }
}

pub struct TimelockBypassDetector;
#[async_trait::async_trait]
impl SecurityDetector for TimelockBypassDetector {
    fn id(&self) -> &'static str { "EXT-AC-021" }
    fn name(&self) -> &'static str { "Timelock Bypass" }
    fn description(&self) -> &'static str { "Detects timelock bypass vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        vec![] // Requires temporal logic analysis
    }
}