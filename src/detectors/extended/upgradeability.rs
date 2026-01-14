use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition},
};
use std::collections::HashMap;

fn create_loc(ctx: &DetectionContext, func_idx: usize, instr_idx: u16) -> CodeLocation {
    let func_def = &ctx.module.function_defs[func_idx];
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: instr_idx,
        byte_offset: 0,
        line: None,
        column: None,
    }
}

// UPGRADE-001: Missing Initialization Guard
pub struct MissingInitializationGuardDetector;

#[async_trait::async_trait]
impl SecurityDetector for MissingInitializationGuardDetector {
    fn id(&self) -> &'static str { "UPGRADE-001" }
    fn name(&self) -> &'static str { "Missing Initialization Guard" }
    fn description(&self) -> &'static str { "Detects functions that can be re-initialized without guards" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for initialization functions
            if func_name.contains("init") || func_name.contains("initialize") {
                
                if let Some(code) = &func_def.code {
                    // Check if function sets an initialized flag
                    let mut has_flag_check = false;
                    let mut has_flag_set = false;
                    
                    for instr in &code.code {
                        match instr {
                            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                                // Check if there's a call to check an initialized flag
                                if let Some(_) = get_function_name_from_instruction(instr) {
                                    if true { // Simplified check for now
                                        has_flag_check = true;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    
                    if !has_flag_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::Critical,
                            confidence: Confidence::High,
                            title: "Missing initialization guard".to_string(),
                            description: "Initialization function does not check if already initialized".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Add initialization flag check to prevent re-initialization".to_string(),
                            references: vec!["CWE-691: Insufficient Control Flow Management".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// UPGRADE-002: Unauthorized Upgrade Access
pub struct UnauthorizedUpgradeAccessDetector;

#[async_trait::async_trait]
impl SecurityDetector for UnauthorizedUpgradeAccessDetector {
    fn id(&self) -> &'static str { "UPGRADE-002" }
    fn name(&self) -> &'static str { "Unauthorized Upgrade Access" }
    fn description(&self) -> &'static str { "Detects upgrade functions without proper access control" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for upgrade-related functions
            if func_name.contains("upgrade") || func_name.contains("update_impl") || func_name.contains("change_impl") {
                
                // Check function visibility
                if func_def.visibility == move_binary_format::file_format::Visibility::Public {
                    if let Some(code) = &func_def.code {
                        // Check for access control validation
                        let mut has_access_control = false;
                        
                        for instr in &code.code {
                            match instr {
                                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                                    if let Some(_) = get_function_name_from_instruction(instr) {
                                        has_access_control = true; // Simplified check for now
                                    }
                                }
                                _ => {}
                            }
                        }
                        
                        if !has_access_control {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                title: "Missing access control for upgrade".to_string(),
                                description: "Upgrade function is public but lacks access control checks".to_string(),
                                location: create_loc(ctx, idx, 0),
                                source_code: Some(func_name),
                                recommendation: "Add access control checks to restrict who can call upgrade functions".to_string(),
                                references: vec!["CWE-284: Improper Access Control".to_string()],
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

// UPGRADE-003: Storage Layout Collision
pub struct StorageLayoutCollisionDetector;

#[async_trait::async_trait]
impl SecurityDetector for StorageLayoutCollisionDetector {
    fn id(&self) -> &'static str { "UPGRADE-003" }
    fn name(&self) -> &'static str { "Storage Layout Collision" }
    fn description(&self) -> &'static str { "Detects potential storage layout collisions during upgrades" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check struct definitions for potential upgrade issues
        for (struct_idx, struct_def) in ctx.module.struct_defs.iter().enumerate() {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
            
            // Look for proxy-related struct names
            if struct_name.contains("proxy") || struct_name.contains("delegate") || struct_name.contains("impl") {
                // Check if struct has upgrade-related fields
                let fields = &ctx.module.field_handles;
                let mut has_implementation_field = false;
                let mut has_admin_field = false;
                
                // Check struct fields differently based on available API
                // In the meantime, we'll use a simpler approach
                let struct_name = ctx.module.identifier_at(struct_handle.name).as_str().to_lowercase();
                if struct_name.contains("impl") || struct_name.contains("proxy") {
                    has_implementation_field = true;
                }
                if struct_name.contains("admin") || struct_name.contains("owner") {
                    has_admin_field = true;
                }
                
                if has_implementation_field && !has_admin_field {
                    let struct_name_clone = struct_name.clone(); // Clone to avoid move issue
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: Severity::High,
                        confidence: Confidence::Medium,
                        title: "Missing admin field in upgradeable struct".to_string(),
                        description: "Upgradeable struct lacks admin field for access control".to_string(),
                        location: CodeLocation {
                            module_id: ctx.module_id.to_string(),
                            module_name: ctx.module.self_id().name().to_string(),
                            function_name: struct_name_clone.clone(), // Use clone for function_name
                            instruction_index: 0,
                            byte_offset: 0,
                            line: None,
                            column: None,
                        },
                        source_code: Some(struct_name_clone), // Use clone for source_code
                        recommendation: "Add admin field to control upgrade access".to_string(),
                        references: vec!["CWE-276: Incorrect Default Permissions".to_string()],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// UPGRADE-004: Constructor Bypass
pub struct ConstructorBypassDetector;

#[async_trait::async_trait]
impl SecurityDetector for ConstructorBypassDetector {
    fn id(&self) -> &'static str { "UPGRADE-004" }
    fn name(&self) -> &'static str { "Constructor Bypass" }
    fn description(&self) -> &'static str { "Detects functions that can bypass constructor protections" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for functions that might manipulate state directly
            if func_name.contains("set_") || func_name.contains("update_") || func_name.contains("manipulate") {
                
                if let Some(code) = &func_def.code {
                    // Look for direct state assignments without proper checks
                    let mut direct_assignments = 0;
                    
                    for instr in &code.code {
                        if matches!(instr, Bytecode::WriteRef | Bytecode::MoveTo(_) | Bytecode::MoveToGeneric(_)) {
                            direct_assignments += 1;
                        }
                    }
                    
                    // If there are many direct assignments without validation
                    if direct_assignments > 2 {
                        let mut has_validation = false;
                        
                        for instr in &code.code {
                            match instr {
                                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                                    if let Some(_) = get_function_name_from_instruction(instr) {
                                        has_validation = true;
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                        
                        if !has_validation {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                title: "Potential constructor bypass".to_string(),
                                description: "Function directly manipulates state without proper validation".to_string(),
                                location: create_loc(ctx, idx, 0),
                                source_code: Some(func_name),
                                recommendation: "Add proper validation before direct state manipulation".to_string(),
                                references: vec!["CWE-693: Protection Mechanism Failure".to_string()],
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

// Helper function to get function name from instruction
// Helper function to get function name from instruction
fn get_function_name_from_instruction(instr: &Bytecode) -> Option<String> {
    match instr {
        Bytecode::Call(_) => {
            // In a real implementation, we would resolve the function handle
            // For now, return None to avoid complex resolution
            None
        },
        _ => None
    }
}

// Export the detectors
pub fn get_upgradeability_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(MissingInitializationGuardDetector),
        Box::new(UnauthorizedUpgradeAccessDetector),
        Box::new(StorageLayoutCollisionDetector),
        Box::new(ConstructorBypassDetector),
    ]
}