// src/detectors/objects/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use crate::utils::{create_location, create_module_location};
use move_binary_format::{file_format::*, access::ModuleAccess};
use std::collections::{HashMap, HashSet};

// ULTRA STRICT: Determine if this is a Sui object module
fn is_sui_object_module(module: &CompiledModule) -> bool {
    let module_name = module.self_id().name().as_str().to_lowercase();
    
    // Check for object-related naming patterns
    let is_object_module = module_name.contains("object") ||
                          module_name.contains("asset") ||
                          module_name.contains("token") ||
                          module_name.contains("nft") ||
                          module_name.contains("collection");
    
    if !is_object_module {
        return false;
    }
    
    // Check for key ability structs (required for Sui objects)
    let has_key_structs = module.struct_defs.iter().any(|struct_def| {
        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
        struct_handle.abilities.has_ability(Ability::Key)
    });
    
    // Check for object-related functions
    let object_function_count = module.function_defs.iter()
        .filter(|func_def| {
            let func_handle = &module.function_handles[func_def.function.0 as usize];
            let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("transfer") ||
            func_name.contains("mint") ||
            func_name.contains("burn") ||
            func_name.contains("share")
        })
        .count();
    
    // Must have key structs and object functions
    has_key_structs && object_function_count >= 2
}

// OB-001: Lost Object Reference - ULTRA STRICT
pub struct LostObjectReference;

#[async_trait::async_trait]
impl SecurityDetector for LostObjectReference {
    fn id(&self) -> &'static str { "OB-001" }
    fn name(&self) -> &'static str { "Lost Object Reference" }
    fn description(&self) -> &'static str {
        "Objects created but never transferred, stored, or deleted"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_sui_object_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        let mut object_tracker = StrictObjectTracker::new();
        
        // Only check public functions where objects can be created
        for func_def in &ctx.module.function_defs {
            if func_def.visibility != Visibility::Public && !func_def.is_entry {
                continue;
            }
            
            object_tracker.track_function_strict(func_def, &ctx.module);
            
            // Check for lost objects with strict criteria
            for lost_obj in object_tracker.get_definitely_lost_objects() {
                issues.push(SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::High,
                    title: "Object may be permanently lost".to_string(),
                    description: format!("Object of type '{}' is created but never transferred or stored", lost_obj.type_name),
                    location: lost_obj.location.clone(),
                    source_code: Some("Object creation without transfer".to_string()),
                    recommendation: "Ensure all objects are either transferred to an address, stored in global storage, or explicitly deleted".to_string(),
                    references: vec![
                        "https://docs.sui.io/build/sui-objects".to_string(),
                    ],
                    metadata: HashMap::new(),
                });
            }
        }
        
        issues
    }
}

struct StrictObjectTracker {
    objects: HashMap<String, StrictObjectInfo>,
}

struct StrictObjectInfo {
    type_name: String,
    created_at: Option<usize>, // Instruction index where created
    last_used_at: Option<usize>, // Instruction index where last used
    transferred: bool,
    stored: bool,
    location: CodeLocation,
}

impl StrictObjectTracker {
    fn new() -> Self {
        Self {
            objects: HashMap::new(),
        }
    }
    
    fn track_function_strict(&mut self, func_def: &FunctionDefinition, module: &CompiledModule) {
        if let Some(code) = &func_def.code {
            for (i, instr) in code.code.iter().enumerate() {
                match instr {
                    Bytecode::Pack(idx) => {
                        // Object creation - only track key-able structs
                        let struct_def = &module.struct_defs[idx.0 as usize];
                        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
                        
                        // Only track structs with key ability (Sui objects)
                        if struct_handle.abilities.has_ability(Ability::Key) {
                            let type_name = module.identifier_at(struct_handle.name).to_string();
                            
                            self.objects.insert(type_name.clone(), StrictObjectInfo {
                                type_name: type_name.clone(),
                                created_at: Some(i),
                                last_used_at: Some(i),
                                transferred: false,
                                stored: false,
                                location: create_location_from_index(module, func_def, i as u16),
                            });
                        }
                    }
                    
                    // Check for transfers of tracked objects
                    Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                        if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                            let name = func_name.as_str().to_lowercase();
                            
                            // Strict: Only track actual transfer operations
                            if name == "transfer::transfer" ||
                               name.contains("transfer_object") ||
                               name == "share_object" {
                                
                                for obj in self.objects.values_mut() {
                                    obj.transferred = true;
                                    obj.last_used_at = Some(i);
                                }
                            }
                            
                            // Check for storage operations
                            if name.contains("move_to") ||
                               name.contains("dynamic_field::add") ||
                               name.contains("table::add") {
                                
                                for obj in self.objects.values_mut() {
                                    obj.stored = true;
                                    obj.last_used_at = Some(i);
                                }
                            }
                        }
                    }
                    
                    _ => {}
                }
            }
        }
    }
    
    fn get_definitely_lost_objects(&self) -> Vec<&StrictObjectInfo> {
        self.objects.values()
            .filter(|obj| {
                // Object is definitely lost if:
                // 1. It was created (has creation index)
                // 2. It was never transferred or stored
                // 3. It was used at creation but not after
                obj.created_at.is_some() &&
                !obj.transferred && 
                !obj.stored &&
                obj.last_used_at == obj.created_at // Only used at creation, not later
            })
            .collect()
    }
}

// OB-002: Double Transfer Risk - ULTRA STRICT
pub struct DoubleTransferRisk;

#[async_trait::async_trait]
impl SecurityDetector for DoubleTransferRisk {
    fn id(&self) -> &'static str { "OB-002" }
    fn name(&self) -> &'static str { "Double Transfer Risk" }
    fn description(&self) -> &'static str {
        "Object could be transferred multiple times in error conditions"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_sui_object_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            // Only check public functions
            if func_def.visibility != Visibility::Public && !func_def.is_entry {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                // Strict: Only flag if we can see multiple actual transfer operations
                let mut transfer_count = 0;
                let mut transfer_locations = Vec::new();
                
                for (i, instr) in code.code.iter().enumerate() {
                    if let Some(func_name) = crate::utils::get_function_name(instr, &ctx.module) {
                        let func_name_str = func_name.as_str().to_lowercase();
                        
                        // Strict: Only count actual transfer operations
                        if func_name_str == "transfer::transfer" ||
                           func_name_str.contains("transfer_object") {
                            
                            transfer_count += 1;
                            transfer_locations.push(i);
                        }
                    }
                }
                
                // Only flag if multiple transfers AND they're close together (indicating possible error)
                if transfer_count >= 2 && transfers_are_close_together(&transfer_locations) {
                    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                    let func_name = ctx.module.identifier_at(func_handle.name);
                    
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Double transfer risk in '{}'", func_name),
                        description: "Multiple transfer operations in same function could lead to double spending".to_string(),
                        location: create_location(ctx, func_def, transfer_locations[0] as u16),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Ensure transfer operations are conditional and objects are properly consumed".to_string(),
                        references: vec![
                            "https://docs.sui.io/build/sui-objects/transfer".to_string(),
                        ],
                        metadata: {
                            let mut map = HashMap::new();
                            map.insert("transfer_count".to_string(), transfer_count.to_string());
                            map
                        },
                    });
                }
            }
        }
        
        issues
    }
}

fn transfers_are_close_together(locations: &[usize]) -> bool {
    if locations.len() < 2 {
        return false;
    }
    
    // Check if transfers are within 10 instructions of each other
    for i in 0..locations.len() - 1 {
        if locations[i + 1] - locations[i] <= 10 {
            return true;
        }
    }
    
    false
}

// OB-003: Improper Shared Object Usage - ULTRA STRICT
pub struct ImproperSharedObjectUsage;

#[async_trait::async_trait]
impl SecurityDetector for ImproperSharedObjectUsage {
    fn id(&self) -> &'static str { "OB-003" }
    fn name(&self) -> &'static str { "Improper Shared Object Usage" }
    fn description(&self) -> &'static str {
        "Shared objects accessed without proper access control"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_sui_object_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Find shared object types (structs with key ability)
        let shared_structs = find_shared_object_structs_strict(&ctx.module);
        
        if shared_structs.is_empty() {
            return issues;
        }
        
        for func_def in &ctx.module.function_defs {
            // Only check public functions
            if func_def.visibility != Visibility::Public && !func_def.is_entry {
                continue;
            }
            
            if uses_shared_objects_strict(func_def, &ctx.module, &shared_structs) {
                // Check for proper access control with strict criteria
                let access_control_score = calculate_access_control_score(func_def, &ctx.module);
                
                if access_control_score < 2 { // Require at least some access control
                    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                    let func_name = ctx.module.identifier_at(func_handle.name);
                    
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if access_control_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Improper shared object usage in '{}'", func_name),
                        description: "Shared object accessed without proper access control mechanisms".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement access control, locking mechanisms, or permission checks for shared objects".to_string(),
                        references: vec![
                            "https://docs.sui.io/build/sui-objects/shared".to_string(),
                        ],
                        metadata: {
                            let mut map = HashMap::new();
                            map.insert("access_control_score".to_string(), access_control_score.to_string());
                            map
                        },
                    });
                }
            }
        }
        
        issues
    }
}

fn find_shared_object_structs_strict(module: &CompiledModule) -> Vec<u16> {
    let mut shared_structs = Vec::new();
    
    for (idx, struct_def) in module.struct_defs.iter().enumerate() {
        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
        
        // Only consider structs with key ability as potential shared objects
        if struct_handle.abilities.has_ability(Ability::Key) {
            // Additional check: struct name suggests shared usage
            let struct_name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
            if struct_name.contains("shared") ||
               struct_name.contains("global") ||
               struct_name.contains("pool") ||
               struct_name.contains("market") {
                shared_structs.push(idx as u16);
            }
        }
    }
    
    shared_structs
}

fn uses_shared_objects_strict(func_def: &FunctionDefinition, module: &CompiledModule, shared_structs: &[u16]) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            match instr {
                Bytecode::MoveFrom(idx) | Bytecode::MoveTo(idx) => {
                    if shared_structs.contains(&idx.0) {
                        return true;
                    }
                }
                Bytecode::MutBorrowGlobal(idx) | Bytecode::ImmBorrowGlobal(idx) => {
                    if shared_structs.contains(&idx.0) {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn calculate_access_control_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    // Check function parameters for capabilities
    let func_handle = &module.function_handles[func_def.function.0 as usize];
    let signature = &module.signatures[func_handle.parameters.0 as usize];
    
    for param_type in &signature.0 {
        let mut inner_type = param_type;
        while let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = inner_type {
            inner_type = inner;
        }

        if let SignatureToken::Struct(idx) | SignatureToken::StructInstantiation(idx, _) = inner_type {
            let struct_handle = &module.struct_handles[idx.0 as usize];
            let struct_name = module.identifier_at(struct_handle.name).as_str();
            
            if struct_name.ends_with("Cap") || 
               struct_name.contains("Admin") ||
               struct_name.contains("Guardian") {
                score += 2;
            }
        }
    }
    
    // Check bytecode for access control patterns
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("only_owner") { score += 3; }
                if func_name_lower.contains("require_admin") { score += 3; }
                if func_name_lower.contains("check_access") { score += 2; }
                if func_name_lower.contains("verify") { score += 1; }
                if func_name_lower.contains("assert") { score += 1; }
            }
        }
    }
    
    score
}

// OB-004: Missing Key Ability - ULTRA STRICT
pub struct MissingKeyAbility;

#[async_trait::async_trait]
impl SecurityDetector for MissingKeyAbility {
    fn id(&self) -> &'static str { "OB-004" }
    fn name(&self) -> &'static str { "Missing Key Ability" }
    fn description(&self) -> &'static str {
        "Struct used as Sui object but missing key ability"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_sui_object_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Identify structs that are used as objects but missing key ability
        for (struct_idx, struct_def) in ctx.module.struct_defs.iter().enumerate() {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name);
            let struct_name_lower = struct_name.as_str().to_lowercase();
            
            // Skip if struct already has key ability
            if struct_handle.abilities.has_ability(Ability::Key) {
                continue;
            }
            
            // Strict: Only check structs that look like objects
            let looks_like_object = struct_name_lower.contains("token") ||
                                   struct_name_lower.contains("nft") ||
                                   struct_name_lower.contains("asset") ||
                                   struct_name_lower.contains("coin") ||
                                   struct_name_lower.contains("object");
            
            if looks_like_object {
                // Additional check: is this struct actually used in object contexts?
                if is_struct_used_as_object(struct_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Struct '{}' missing key ability", struct_name),
                        description: "Struct appears to be used as a Sui object but doesn't have key ability".to_string(),
                        location: CodeLocation {
                            module_id: ctx.module_id.to_string(),
                            module_name: ctx.module.self_id().name().to_string(),
                            function_name: "struct_def".to_string(),
                            instruction_index: struct_idx as u16,
                            byte_offset: 0,
                            line: None,
                            column: None,
                        },
                        source_code: Some(format!("struct {}", struct_name)),
                        recommendation: "Add key ability to struct if it's meant to be a Sui object".to_string(),
                        references: vec![
                            "https://docs.sui.io/build/sui-objects/defining".to_string(),
                        ],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn is_struct_used_as_object(struct_def: &StructDefinition, module: &CompiledModule) -> bool {
    let struct_handle_idx = struct_def.struct_handle;
    let struct_handle = &module.struct_handles[struct_handle_idx.0 as usize];
    let struct_name = module.identifier_at(struct_handle.name);
    
    // Check if struct is used in transfer or object-related functions
    for func_def in &module.function_defs {
        if let Some(code) = &func_def.code {
            for instr in &code.code {
                if let Bytecode::Call(_) | Bytecode::CallGeneric(_) = instr {
                    if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                        let func_name_str = func_name.as_str().to_lowercase();
                        
                        if (func_name_str.contains("transfer") || 
                            func_name_str.contains("mint") ||
                            func_name_str.contains("burn")) {
                            
                            // Check if this function might use our struct
                            // This is simplified - in practice would need type analysis
                            return true;
                        }
                    }
                }
            }
        }
    }
    
    false
}

// OB-020: Copy Ability Abuse - ULTRA STRICT
pub struct CopyAbilityAbuse;

#[async_trait::async_trait]
impl SecurityDetector for CopyAbilityAbuse {
    fn id(&self) -> &'static str { "OB-020" }
    fn name(&self) -> &'static str { "Copy Ability Abuse" }
    fn description(&self) -> &'static str {
        "Unique assets have copy ability allowing duplication"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_sui_object_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for struct_def in &ctx.module.struct_defs {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name);
            let struct_name_lower = struct_name.as_str().to_lowercase();
            
            // Check if struct has both key and copy abilities
            let has_key = struct_handle.abilities.has_ability(Ability::Key);
            let has_copy = struct_handle.abilities.has_ability(Ability::Copy);
            
            if has_key && has_copy {
                // Strict: Only flag if this looks like a unique asset
                let is_unique_asset = struct_name_lower.contains("token") ||
                                     struct_name_lower.contains("nft") ||
                                     struct_name_lower.contains("unique") ||
                                     struct_name_lower.contains("nonfungible");
                
                if is_unique_asset {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Copy ability abuse in '{}'", struct_name),
                        description: "Unique asset has copy ability allowing unauthorized duplication".to_string(),
                        location: CodeLocation {
                            module_id: ctx.module_id.to_string(),
                            module_name: ctx.module.self_id().name().to_string(),
                            function_name: "struct_def".to_string(),
                            instruction_index: 0,
                            byte_offset: 0,
                            line: None,
                            column: None,
                        },
                        source_code: Some(format!("struct {} has key, copy {{ ... }}", struct_name)),
                        recommendation: "Remove copy ability from unique assets to prevent unauthorized duplication".to_string(),
                        references: vec![
                            "https://docs.sui.io/build/move/abilities".to_string(),
                        ],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// OB-021: Improper ID Field - NEW STRICT DETECTOR
pub struct ImproperIDField;

#[async_trait::async_trait]
impl SecurityDetector for ImproperIDField {
    fn id(&self) -> &'static str { "OB-021" }
    fn name(&self) -> &'static str { "Improper ID Field" }
    fn description(&self) -> &'static str {
        "Sui objects missing proper ID field or using incorrect ID type"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_sui_object_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for struct_def in &ctx.module.struct_defs {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            
            // Only check structs with key ability (Sui objects)
            if !struct_handle.abilities.has_ability(Ability::Key) {
                continue;
            }
            
            let struct_name = ctx.module.identifier_at(struct_handle.name);
            
            // Check for proper ID field
            let (has_id_field, id_field_type) = check_id_field(struct_def, &ctx.module);
            
            if !has_id_field {
                issues.push(SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::High,
                    title: format!("Missing ID field in '{}'", struct_name),
                    description: "Sui object missing required ID field".to_string(),
                    location: CodeLocation {
                        module_id: ctx.module_id.to_string(),
                        module_name: ctx.module.self_id().name().to_string(),
                        function_name: "struct_def".to_string(),
                        instruction_index: 0,
                        byte_offset: 0,
                        line: None,
                        column: None,
                    },
                    source_code: Some(format!("struct {} {{ ... }}", struct_name)),
                    recommendation: "Add 'id: UID' field to all Sui objects".to_string(),
                    references: vec![
                        "https://docs.sui.io/build/sui-objects/defining".to_string(),
                    ],
                    metadata: HashMap::new(),
                });
            } else if id_field_type != "UID" {
                issues.push(SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::High,
                    title: format!("Incorrect ID field type in '{}'", struct_name),
                    description: format!("Sui object ID field has type '{}' instead of 'UID'", id_field_type),
                    location: CodeLocation {
                        module_id: ctx.module_id.to_string(),
                        module_name: ctx.module.self_id().name().to_string(),
                        function_name: "struct_def".to_string(),
                        instruction_index: 0,
                        byte_offset: 0,
                        line: None,
                        column: None,
                    },
                    source_code: Some(format!("struct {} {{ id: {} }}", struct_name, id_field_type)),
                    recommendation: "Change ID field type to 'UID' for proper Sui object handling".to_string(),
                    references: vec![
                        "https://docs.sui.io/build/sui-objects/defining".to_string(),
                    ],
                    metadata: HashMap::new(),
                });
            }
        }
        
        issues
    }
}

fn check_id_field(struct_def: &StructDefinition, module: &CompiledModule) -> (bool, String) {
    if let StructFieldInformation::Declared(fields) = &struct_def.field_information {
        for field in fields {
            let field_name = module.identifier_at(field.name);
            if field_name.as_str() == "id" {
                // Get the field type
                let type_str = format!("{:?}", field.signature.0);
                return (true, type_str);
            }
        }
    }
    
    (false, String::new())
}

// Only include detectors that can be made extremely strict
pub fn get_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(LostObjectReference),
        Box::new(DoubleTransferRisk),
        Box::new(ImproperSharedObjectUsage),
        Box::new(MissingKeyAbility),
        Box::new(CopyAbilityAbuse),
        Box::new(ImproperIDField),
    ]
}

// Helper functions
fn create_location_from_index(module: &CompiledModule, func_def: &FunctionDefinition, instruction_idx: u16) -> CodeLocation {
    let func_handle = &module.function_handles[func_def.function.0 as usize];
    let func_name = module.identifier_at(func_handle.name);
    
    CodeLocation {
        module_id: module.self_id().to_string(),
        module_name: module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: instruction_idx,
        byte_offset: 0,
        line: None,
        column: None,
    }
}