// src/detectors/events/mod.rs
use crate::utils::{create_location, create_module_location, emits_event, is_event_emission, transitively_emits_event};
use crate::{core::detector::SecurityDetector, types::*};
use move_binary_format::{file_format::*, access::ModuleAccess};
use std::collections::{HashSet, HashMap};

// ULTRA STRICT: Determine if module actually uses events
fn module_uses_events(module: &CompiledModule) -> bool {
    // Check if module has any event structs
    let has_event_structs = module.struct_defs.iter().any(|struct_def| {
        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
        let struct_name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
        struct_name.ends_with("event") || struct_name == "event"
    });
    
    // Check if module actually emits events
    let emits_events = module.function_defs.iter().any(|func_def| {
        if let Some(code) = &func_def.code {
            code.code.iter().any(|instr| is_event_emission(instr, module))
        } else {
            false
        }
    });
    
    has_event_structs && emits_events
}

// EV-001: Missing Critical Events - ULTRA STRICT
pub struct MissingCriticalEvents;

#[async_trait::async_trait]
impl SecurityDetector for MissingCriticalEvents {
    fn id(&self) -> &'static str { "EV-001" }
    fn name(&self) -> &'static str { "Missing Critical Events" }
    fn description(&self) -> &'static str {
        "Critical state changes don't emit events for monitoring"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !module_uses_events(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // ULTRA STRICT: Only check truly critical financial operations
        let critical_financial_operations = [
            "transfer", // Asset transfers
            "mint",     // Token minting
            "burn",     // Token burning
            "withdraw", // Fund withdrawals
            "deposit",  // Fund deposits
            "no_event", // Explicitly named functions that don't emit events
        ];
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // Only check public functions that modify state
            if (func_def.visibility == Visibility::Public || func_def.is_entry) &&
               is_state_modifying_function(func_def, &ctx.module) {
                
                // ULTRA STRICT: Only flag exact function names for critical operations
                let is_critical_operation = critical_financial_operations.iter().any(|&op| {
                    func_name_lower == op || 
                    func_name_lower.starts_with(&format!("{}_", op)) ||
                    func_name_lower.ends_with(&format!("_{}", op))
                });
                
                if is_critical_operation {
                    // Check if function emits events (transitively with depth limit)
                    if !transitively_emits_event(func_def, &ctx.module, 2) {
                        // Additional check: verify this is actually a significant operation
                        if is_significant_financial_operation(func_def, &ctx.module) {
                            issues.push(create_event_issue(
                                self, ctx, func_def, 0,
                                "Critical financial operation doesn't emit event",
                                "Emit events after all asset transfers, mints, burns, withdrawals, and deposits",
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

fn is_state_modifying_function(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            match instr {
                Bytecode::Pack(_) | Bytecode::PackGeneric(_) => {
                    return true;
                }
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                        if func_name.as_str().contains("transfer") ||
                           func_name.as_str().contains("mint") ||
                           func_name.as_str().contains("burn") {
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

fn is_significant_financial_operation(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut financial_indicators = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                if func_name_lower.contains("coin") ||
                   func_name_lower.contains("token") ||
                   func_name_lower.contains("balance") ||
                   func_name_lower.contains("amount") {
                    financial_indicators += 1;
                }
            }
        }
        
        financial_indicators >= 2
    } else {
        false
    }
}

// EV-002: Event After Revert - ULTRA STRICT
pub struct EventAfterRevert;

#[async_trait::async_trait]
impl SecurityDetector for EventAfterRevert {
    fn id(&self) -> &'static str { "EV-002" }
    fn name(&self) -> &'static str { "Event After Revert" }
    fn description(&self) -> &'static str {
        "Events emitted before operations that could revert"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !module_uses_events(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                // Find event emissions
                let event_indices: Vec<usize> = code.code.iter()
                    .enumerate()
                    .filter(|(_, instr)| is_event_emission(instr, &ctx.module))
                    .map(|(i, _)| i)
                    .collect();
                
                for event_idx in event_indices {
                    // ULTRA STRICT: Only flag if there are clear revert risks AFTER event
                    if has_clear_revert_risk_after(&code.code, event_idx, &ctx.module) {
                        let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                        let func_name = ctx.module.identifier_at(func_handle.name);
                        
                        // Additional check: ensure this is in a critical function
                        if is_critical_function(func_name.as_str()) {
                            issues.push(create_event_issue(
                                self, ctx, func_def, event_idx as u16,
                                "Event emitted before potentially reverting operation",
                                "Emit events after all operations that could revert, especially in critical functions",
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

fn has_clear_revert_risk_after(bytecode: &[Bytecode], after_idx: usize, module: &CompiledModule) -> bool {
    let end = std::cmp::min(after_idx + 10, bytecode.len());
    
    for i in after_idx + 1..end {
        match &bytecode[i] {
            // Division by potentially zero
            Bytecode::Div | Bytecode::Mod => {
                // Check if divisor is loaded from function argument or could be zero
                if i > 0 {
                    if let Bytecode::LdU64(0) = bytecode[i-1] {
                        return true; // Division by zero literal
                    }
                }
            }
            
            // External calls that could fail
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                // Check if it's an external transfer or critical call
                if let Some(func_name) = crate::utils::get_function_name(&bytecode[i], module) {
                    if func_name.as_str().contains("transfer") ||
                       func_name.as_str().contains("withdraw") ||
                       func_name.as_str().contains("deposit") {
                        return true;
                    }
                }
            }
            
            // Explicit abort
            Bytecode::Abort => return true,
            
            _ => {}
        }
    }
    
    false
}

fn is_critical_function(func_name: &str) -> bool {
    let func_name_lower = func_name.to_lowercase();
    func_name_lower.contains("transfer") ||
    func_name_lower.contains("withdraw") ||
    func_name_lower.contains("deposit") ||
    func_name_lower.contains("mint") ||
    func_name_lower.contains("burn")
}

// EV-003: Incorrect Event Data - ULTRA STRICT
pub struct IncorrectEventData;

#[async_trait::async_trait]
impl SecurityDetector for IncorrectEventData {
    fn id(&self) -> &'static str { "EV-003" }
    fn name(&self) -> &'static str { "Incorrect Event Data" }
    fn description(&self) -> &'static str {
        "Events missing critical data fields or containing incorrect data"
    }
    fn default_severity(&self) -> Severity { Severity::Low }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !module_uses_events(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Analyze only event structs that are actually used
        for struct_def in &ctx.module.struct_defs {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name);
            let struct_name_lower = struct_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check structs that are clearly events
            let is_clear_event = struct_name_lower.ends_with("event") || struct_name_lower == "event";
            
            if is_clear_event && is_event_struct_used(struct_def, &ctx.module) {
                // Check for missing critical fields based on event type
                let critical_missing_fields = check_critical_missing_fields(struct_def, &ctx.module, struct_name.as_str());
                
                if !critical_missing_fields.is_empty() {
                    issues.push(create_event_struct_issue(
                        self, ctx, struct_name.as_str(),
                        &format!("Event '{}' missing critical fields: {}", 
                                struct_name, critical_missing_fields.join(", ")),
                        "Include all relevant transaction context in events for auditability",
                        Confidence::Medium,
                    ));
                }
            }
        }
        
        issues
    }
}

fn is_event_struct_used(struct_def: &StructDefinition, module: &CompiledModule) -> bool {
    let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
    let struct_name = module.identifier_at(struct_handle.name);
    
    // Check if this struct is used in any event emission
    for func_def in &module.function_defs {
        if let Some(code) = &func_def.code {
            for instr in &code.code {
                if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                    if func_name.as_str().contains("emit") || func_name.as_str().contains("event") {
                        // Check if this function creates or uses our struct
                        // This is a simplified check - in practice would need type analysis
                        return true;
                    }
                }
            }
        }
    }
    
    false
}

fn check_critical_missing_fields(struct_def: &StructDefinition, module: &CompiledModule, struct_name: &str) -> Vec<String> {
    let mut missing = Vec::new();
    
    // Get existing field names
    let existing_fields: HashSet<String> = match &struct_def.field_information {
        StructFieldInformation::Declared(fields) => {
            fields.iter()
                .map(|field| module.identifier_at(field.name).to_string().to_lowercase())
                .collect()
        }
        _ => HashSet::new(),
    };
    
    // Determine required fields based on event type
    let required_fields = get_required_fields_for_event_type(struct_name, &existing_fields);
    
    // Check which required fields are missing
    for field in required_fields {
        if !existing_fields.iter().any(|f| f.contains(&field)) {
            missing.push(field);
        }
    }
    
    missing
}

fn get_required_fields_for_event_type(event_name: &str, existing_fields: &HashSet<String>) -> Vec<String> {
    let event_name_lower = event_name.to_lowercase();
    let mut required = Vec::new();
    
    // Common required fields for all events
    required.push("sender".to_string());
    
    // Type-specific required fields
    if event_name_lower.contains("transfer") {
        required.push("from".to_string());
        required.push("to".to_string());
        required.push("amount".to_string());
    } else if event_name_lower.contains("mint") || event_name_lower.contains("burn") {
        required.push("amount".to_string());
        required.push("to".to_string()); // For mint: to whom; for burn: from whom
    } else if event_name_lower.contains("withdraw") || event_name_lower.contains("deposit") {
        required.push("amount".to_string());
        required.push("user".to_string());
    } else if event_name_lower.contains("swap") || event_name_lower.contains("trade") {
        required.push("amount_in".to_string());
        required.push("amount_out".to_string());
        required.push("token_in".to_string());
        required.push("token_out".to_string());
    }
    
    // Remove fields that might have alternative names
    required.retain(|field| {
        !existing_fields.iter().any(|existing| {
            matches_alternative_field_name(existing, field)
        })
    });
    
    required
}

fn matches_alternative_field_name(existing_field: &str, required_field: &str) -> bool {
    match &required_field[..] {
        "sender" => existing_field.contains("sender") || existing_field.contains("caller") || existing_field.contains("initiator"),
        "amount" => existing_field.contains("amount") || existing_field.contains("value") || existing_field.contains("quantity"),
        "from" => existing_field.contains("from") || existing_field.contains("source"),
        "to" => existing_field.contains("to") || existing_field.contains("recipient") || existing_field.contains("destination"),
        "user" => existing_field.contains("user") || existing_field.contains("account") || existing_field.contains("address"),
        _ => existing_field.contains(required_field),
    }
}

// EV-006: Logging DoS - ULTRA STRICT
pub struct LoggingDoS;

#[async_trait::async_trait]
impl SecurityDetector for LoggingDoS {
    fn id(&self) -> &'static str { "EV-006" }
    fn name(&self) -> &'static str { "Logging DoS" }
    fn description(&self) -> &'static str {
        "Excessive event logging could cause performance issues"
    }
    fn default_severity(&self) -> Severity { Severity::Low }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !module_uses_events(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                let mut event_in_loop = false;
                let mut loop_depth = 0;
                let mut event_count_in_loop = 0;
                
                for (i, instr) in code.code.iter().enumerate() {
                    match instr {
                        // Track loop entry
                        Bytecode::Branch(back_target) if *back_target < i as u16 => {
                            loop_depth += 1;
                            event_in_loop = true;
                            event_count_in_loop = 0;
                        }
                        
                        // Track loop exit
                        Bytecode::Ret => {
                            if loop_depth > 0 {
                                loop_depth -= 1;
                                if loop_depth == 0 {
                                    event_in_loop = false;
                                }
                            }
                        }
                        
                        // Count events in loop
                        _ => {
                            if event_in_loop && is_event_emission(instr, &ctx.module) {
                                event_count_in_loop += 1;
                                
                                // ULTRA STRICT: Only flag if many events in deep loop
                                if event_count_in_loop > 20 && loop_depth >= 2 {
                                    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                                    let func_name = ctx.module.identifier_at(func_handle.name);
                                    
                                    issues.push(create_event_issue(
                                        self, ctx, func_def, i as u16,
                                        &format!("Excessive event emission in nested loop ({} events)", event_count_in_loop),
                                        "Limit event emissions in loops, batch events, or emit summary events",
                                        Confidence::Medium,
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        issues
    }
}

// EV-008: Missing Timestamp - ULTRA STRICT
pub struct MissingTimestamp;

#[async_trait::async_trait]
impl SecurityDetector for MissingTimestamp {
    fn id(&self) -> &'static str { "EV-008" }
    fn name(&self) -> &'static str { "Missing Timestamp" }
    fn description(&self) -> &'static str {
        "Events missing timestamp field for chronological ordering"
    }
    fn default_severity(&self) -> Severity { Severity::Low }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !module_uses_events(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Only check event structs for financial operations
        for struct_def in &ctx.module.struct_defs {
            let struct_handle = &ctx.module.struct_handles[struct_def.struct_handle.0 as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name);
            let struct_name_lower = struct_name.as_str().to_lowercase();
            
            // Only check financial event structs
            let is_financial_event = struct_name_lower.contains("transfer") ||
                                    struct_name_lower.contains("mint") ||
                                    struct_name_lower.contains("burn") ||
                                    struct_name_lower.contains("withdraw") ||
                                    struct_name_lower.contains("deposit") ||
                                    struct_name_lower.contains("swap");
            
            if is_financial_event && is_clear_event_struct(struct_name.as_str()) {
                // Check for timestamp or block number field
                if !has_timestamp_or_sequence_field(struct_def, &ctx.module) {
                    issues.push(create_event_struct_issue(
                        self, ctx, struct_name.as_str(),
                        &format!("Financial event '{}' missing timestamp/sequence field", struct_name),
                        "Add timestamp, block number, or sequence number to financial events for audit trail",
                        Confidence::Medium,
                    ));
                }
            }
        }
        
        issues
    }
}

fn is_clear_event_struct(struct_name: &str) -> bool {
    let name_lower = struct_name.to_lowercase();
    name_lower.ends_with("event") || name_lower == "event"
}

fn has_timestamp_or_sequence_field(struct_def: &StructDefinition, module: &CompiledModule) -> bool {
    match &struct_def.field_information {
        StructFieldInformation::Declared(fields) => {
            fields.iter().any(|field| {
                let field_name = module.identifier_at(field.name).as_str().to_lowercase();
                field_name.contains("timestamp") ||
                field_name.contains("time") ||
                field_name.contains("block") ||
                field_name.contains("sequence") ||
                field_name.contains("nonce")
            })
        }
        _ => false,
    }
}

// Helper functions
fn create_event_issue(
    detector: &impl SecurityDetector,
    ctx: &DetectionContext,
    func_def: &FunctionDefinition,
    instruction_idx: u16,
    description: &str,
    recommendation: &str,
    confidence: Confidence,
) -> SecurityIssue {
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    
    SecurityIssue {
        id: detector.id().to_string(),
        severity: detector.default_severity(),
        confidence,
        title: format!("{} in '{}'", detector.name(), func_name),
        description: description.to_string(),
        location: create_location(ctx, func_def, instruction_idx),
        source_code: Some(func_name.to_string()),
        recommendation: recommendation.to_string(),
        references: vec![],
        metadata: {
            let mut map = HashMap::new();
            map.insert("function_name".to_string(), func_name.to_string());
            map
        },
    }
}

fn create_event_struct_issue(
    detector: &impl SecurityDetector,
    ctx: &DetectionContext,
    struct_name: &str,
    description: &str,
    recommendation: &str,
    confidence: Confidence,
) -> SecurityIssue {
    SecurityIssue {
        id: detector.id().to_string(),
        severity: detector.default_severity(),
        confidence,
        title: format!("{} in event '{}'", detector.name(), struct_name),
        description: description.to_string(),
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
        recommendation: recommendation.to_string(),
        references: vec![],
        metadata: {
            let mut map = HashMap::new();
            map.insert("struct_name".to_string(), struct_name.to_string());
            map
        },
    }
}

// Only include detectors that can be made extremely strict
pub fn get_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(MissingCriticalEvents),
        Box::new(EventAfterRevert),
        Box::new(IncorrectEventData),
        Box::new(LoggingDoS),
        Box::new(MissingTimestamp),
    ]
}