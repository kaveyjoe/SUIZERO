// src/detectors/gas/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use crate::utils::create_location;
use move_binary_format::{file_format::*, access::ModuleAccess};

// GA-001: Gas Griefing Attack - ULTRA STRICT
pub struct GasGriefingAttack;

#[async_trait::async_trait]
impl SecurityDetector for GasGriefingAttack {
    fn id(&self) -> &'static str { "GA-001" }
    fn name(&self) -> &'static str { "Gas Griefing Attack" }
    fn description(&self) -> &'static str {
        "Loops with expensive operations can be exploited for gas griefing"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // ULTRA STRICT: Only check public functions that can be griefed
            if func_def.visibility != Visibility::Public && !func_def.is_entry {
                continue;
            }
            
            // Only check functions that process user-controlled data
            if !handles_user_input(func_def, &ctx.module) {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                // Find loops with expensive operations
                let loops = find_loops_with_expensive_operations(code, &ctx.module);
                
                for (loop_start, loop_end, expensive_ops) in loops {
                    // Only flag if loop has multiple expensive operations
                    if expensive_ops >= 3 {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Gas griefing attack in '{}'", func_name),
                            description: format!("Loop with {} expensive operations can be exploited to consume excessive gas", expensive_ops),
                            location: create_location(ctx, func_def, loop_start as u16),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement iteration limits, batch operations, or gas refunds".to_string(),
                            references: vec![
                                "CWE-400: Uncontrolled Resource Consumption".to_string(),
                                "https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/".to_string(),
                            ],
                            metadata: {
                                let mut map = std::collections::HashMap::new();
                                map.insert("expensive_operations".to_string(), expensive_ops.to_string());
                                map.insert("loop_start".to_string(), loop_start.to_string());
                                map.insert("loop_end".to_string(), loop_end.to_string());
                                map
                            },
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ULTRA STRICT: Only flag functions that actually process user input
fn handles_user_input(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    let func_handle = &module.function_handles[func_def.function.0 as usize];
    let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
    
    // Check for function names that indicate user input processing
    let processes_input = func_name.contains("process") ||
                         func_name.contains("handle") ||
                         func_name.contains("batch") ||
                         func_name.contains("multi");
    
    if !processes_input {
        return false;
    }
    
    // Verify the function actually has parameters
    let signature = &module.signatures[func_handle.parameters.0 as usize];
    signature.0.len() > 0
}

fn find_loops_with_expensive_operations(code: &CodeUnit, module: &CompiledModule) -> Vec<(usize, usize, usize)> {
    let mut loops = Vec::new();
    
    // Find loops by looking for back edges
    let mut back_edges = Vec::new();
    for (i, instr) in code.code.iter().enumerate() {
        if let Bytecode::Branch(target) = instr {
            let target_idx = *target as usize;
            if target_idx < i {
                // Back edge found
                back_edges.push((target_idx, i));
            }
        }
    }
    
    // Analyze each loop for expensive operations
    for (loop_start, loop_end) in back_edges {
        let mut expensive_op_count = 0;
        
        // Analyze loop body
        for i in loop_start..=loop_end {
            let instr = &code.code[i];
            
            // Count expensive operations
            if is_expensive_operation(instr, module) {
                expensive_op_count += 1;
            }
        }
        
        // Only include loops with expensive operations
        if expensive_op_count > 0 {
            loops.push((loop_start, loop_end, expensive_op_count));
        }
    }
    
    loops
}

fn is_expensive_operation(instr: &Bytecode, module: &CompiledModule) -> bool {
    match instr {
        // Storage operations are expensive
        Bytecode::Pack(_) | Bytecode::PackGeneric(_) => true,
        
        // External calls can be expensive
        Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                // Specific expensive operations
                func_name_lower.contains("vector::push_back") ||
                func_name_lower.contains("dynamic_field::add") ||
                func_name_lower.contains("table::add") ||
                func_name_lower.contains("event::emit")
            } else {
                false
            }
        }
        
        // Complex math can be expensive (but less so in Move)
        Bytecode::Div | Bytecode::Mod => true,
        
        _ => false
    }
}

// GA-002: Out of Gas Revert - ULTRA STRICT
pub struct OutOfGasRevert;

#[async_trait::async_trait]
impl SecurityDetector for OutOfGasRevert {
    fn id(&self) -> &'static str { "GA-002" }
    fn name(&self) -> &'static str { "Out of Gas Revert" }
    fn description(&self) -> &'static str {
        "Unbounded operations may run out of gas and revert"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check critical functions
            if !is_critical_gas_function(func_name.as_str()) {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                // Look for truly unbounded loops (no clear termination)
                if has_truly_unbounded_loop(code, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Out-of-gas risk in '{}'", func_name),
                        description: "Function contains unbounded loop that could consume excessive gas".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Add iteration limits, implement pagination, or split operations".to_string(),
                        references: vec![
                            "CWE-770: Allocation of Resources Without Limits or Throttling".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn is_critical_gas_function(func_name: &str) -> bool {
    let func_name_lower = func_name.to_lowercase();
    
    // Only flag functions that clearly perform bulk operations
    func_name_lower.contains("batch") ||
    func_name_lower.contains("bulk") ||
    func_name_lower.contains("process_all") ||
    func_name_lower.contains("distribute") ||
    func_name_lower.contains("airdrop")
}

fn has_truly_unbounded_loop(code: &CodeUnit, module: &CompiledModule) -> bool {
    // Find all loops
    let mut loops = Vec::new();
    for (i, instr) in code.code.iter().enumerate() {
        if let Bytecode::Branch(target) = instr {
            let target_idx = *target as usize;
            if target_idx < i {
                loops.push((target_idx, i));
            }
        }
    }
    
    // Check each loop for proper termination
    for (loop_start, loop_end) in loops {
        let mut has_termination_check = false;
        
        // Look for termination conditions in loop header
        for i in loop_start..loop_start + 5 {
            if i >= code.code.len() {
                break;
            }
            
            match &code.code[i] {
                // Comparisons that could be termination checks
                Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | Bytecode::Eq | Bytecode::Neq => {
                    has_termination_check = true;
                    break;
                }
                // Function calls that might check bounds
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    if let Some(func_name) = crate::utils::get_function_name(&code.code[i], module) {
                        if func_name.as_str().contains("length") ||
                           func_name.as_str().contains("size") ||
                           func_name.as_str().contains("is_empty") {
                            has_termination_check = true;
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        
        // If no termination check found, loop might be unbounded
        if !has_termination_check {
            return true;
        }
    }
    
    false
}

// GA-004: Storage Bloat - ULTRA STRICT
pub struct StorageBloat;

#[async_trait::async_trait]
impl SecurityDetector for StorageBloat {
    fn id(&self) -> &'static str { "GA-004" }
    fn name(&self) -> &'static str { "Storage Bloat" }
    fn description(&self) -> &'static str {
        "Unbounded storage growth causing high gas costs"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check for vector/table operations without limits
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check functions that add to collections
            if !function_adds_to_collection(func_name.as_str()) {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                // Count collection add operations
                let add_operations = count_collection_add_operations(code, &ctx.module);
                
                if add_operations >= 3 {
                    // Check if these operations are in a loop
                    if has_loop_with_collection_ops(code, &ctx.module) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Storage bloat in '{}'", func_name),
                            description: "Function adds multiple items to collections without size limits".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement collection size limits, cleanup mechanisms, or pagination".to_string(),
                            references: vec![
                                "CWE-770: Allocation of Resources Without Limits or Throttling".to_string(),
                            ],
                            metadata: {
                                let mut map = std::collections::HashMap::new();
                                map.insert("add_operations".to_string(), add_operations.to_string());
                                map
                            },
                        });
                    }
                }
            }
        }
        
        issues
    }
}

fn function_adds_to_collection(func_name: &str) -> bool {
    let func_name_lower = func_name.to_lowercase();
    
    func_name_lower.contains("add") ||
    func_name_lower.contains("push") ||
    func_name_lower.contains("insert") ||
    func_name_lower.contains("append") ||
    func_name_lower.contains("register") ||
    func_name_lower.contains("enroll")
}

fn count_collection_add_operations(code: &CodeUnit, module: &CompiledModule) -> usize {
    let mut count = 0;
    
    for instr in &code.code {
        if let Bytecode::Call(_) | Bytecode::CallGeneric(_) = instr {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                if func_name_lower.contains("vector::push_back") ||
                   func_name_lower.contains("table::add") ||
                   func_name_lower.contains("dynamic_field::add") ||
                   func_name_lower.contains("bag::add") {
                    count += 1;
                }
            }
        }
    }
    
    count
}

fn has_loop_with_collection_ops(code: &CodeUnit, module: &CompiledModule) -> bool {
    // Find loops
    let mut loops = Vec::new();
    for (i, instr) in code.code.iter().enumerate() {
        if let Bytecode::Branch(target) = instr {
            let target_idx = *target as usize;
            if target_idx < i {
                loops.push((target_idx, i));
            }
        }
    }
    
    // Check if any loop contains collection operations
    for (start, end) in loops {
        for i in start..=end {
            let instr = &code.code[i];
            if let Bytecode::Call(_) | Bytecode::CallGeneric(_) = instr {
                if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                    let func_name_lower = func_name.as_str().to_lowercase();
                    if func_name_lower.contains("vector::push_back") ||
                       func_name_lower.contains("table::add") ||
                       func_name_lower.contains("dynamic_field::add") {
                        return true;
                    }
                }
            }
        }
    }
    
    false
}

// GA-006: Dynamic Vector Growth - NEW STRICT DETECTOR
pub struct DynamicVectorGrowth;

#[async_trait::async_trait]
impl SecurityDetector for DynamicVectorGrowth {
    fn id(&self) -> &'static str { "GA-006" }
    fn name(&self) -> &'static str { "Dynamic Vector Growth" }
    fn description(&self) -> &'static str {
        "Vectors grow based on user input without size limits"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Only check public functions with "add" or "push" in name
            if (func_def.visibility != Visibility::Public && !func_def.is_entry) ||
               !function_name_suggests_growth(func_name.as_str()) {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                // Check for vector push operations without size checks
                if has_vector_push_without_limit(code, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Dynamic vector growth in '{}'", func_name),
                        description: "Vector push operations without size limits can cause storage bloat".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement vector size limits or use fixed-size arrays when possible".to_string(),
                        references: vec![],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn function_name_suggests_growth(func_name: &str) -> bool {
    let func_name_lower = func_name.to_lowercase();
    
    func_name_lower.contains("push") ||
    func_name_lower.contains("add") ||
    func_name_lower.contains("append") ||
    func_name_lower.contains("insert")
}

fn has_vector_push_without_limit(code: &CodeUnit, module: &CompiledModule) -> bool {
    let mut vector_push_count = 0;
    let mut size_check_count = 0;
    
    for instr in &code.code {
        match instr {
            Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                    let func_name_lower = func_name.as_str().to_lowercase();
                    
                    if func_name_lower.contains("vector::push_back") {
                        vector_push_count += 1;
                    } else if func_name_lower.contains("vector::length") ||
                              func_name_lower.contains("vector::is_empty") ||
                              func_name_lower.contains("vector::borrow") {
                        // These might indicate size checks
                        size_check_count += 1;
                    }
                }
            }
            Bytecode::Lt | Bytecode::Gt | Bytecode::Le | Bytecode::Ge | Bytecode::Eq | Bytecode::Neq => {
                // Comparison operations might be size checks
                size_check_count += 1;
            }
            _ => {}
        }
    }
    
    // If we have vector pushes but no apparent size checks, flag it
    vector_push_count > 0 && size_check_count == 0
}

// GA-007: Recursive Calls - NEW STRICT DETECTOR
pub struct RecursiveCalls;

#[async_trait::async_trait]
impl SecurityDetector for RecursiveCalls {
    fn id(&self) -> &'static str { "GA-007" }
    fn name(&self) -> &'static str { "Recursive Calls" }
    fn description(&self) -> &'static str {
        "Recursive function calls without depth limits"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Build call graph
        let mut call_graph = std::collections::HashMap::new();
        
        for (func_idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let mut called_funcs = Vec::new();
                
                for instr in &code.code {
                    if let Bytecode::Call(called_idx) = instr {
                        // Check if it's a call within the same module
                        let func_handle = &ctx.module.function_handles[called_idx.0 as usize];
                        let module_handle = &ctx.module.module_handles[func_handle.module.0 as usize];
                        let self_module_id = ctx.module.self_id();
                        let called_module_id = move_core_types::language_storage::ModuleId::new(
                            (*ctx.module.address_identifier_at(module_handle.address)).into(),
                            ctx.module.identifier_at(module_handle.name).into(),
                        );
                        
                        if called_module_id == self_module_id {
                            called_funcs.push(called_idx.0 as usize);
                        }
                    }
                }
                
                call_graph.insert(func_idx, called_funcs);
            }
        }
        
        // Check for recursion
        for (func_idx, called_funcs) in &call_graph {
            // Direct recursion
            if called_funcs.contains(func_idx) {
                let func_handle = &ctx.module.function_handles[ctx.module.function_defs[*func_idx].function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                
                issues.push(SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::High,
                    title: format!("Direct recursion in '{}'", func_name),
                    description: "Function calls itself directly without recursion depth limit".to_string(),
                    location: create_location(ctx, &ctx.module.function_defs[*func_idx], 0),
                    source_code: Some(func_name.to_string()),
                    recommendation: "Implement recursion depth limit or convert to iterative solution".to_string(),
                    references: vec![
                        "CWE-674: Uncontrolled Recursion".to_string(),
                    ],
                    metadata: std::collections::HashMap::new(),
                });
            }
            
            // Indirect recursion (simplified check)
            for called_idx in called_funcs {
                if let Some(indirect_calls) = call_graph.get(called_idx) {
                    if indirect_calls.contains(func_idx) {
                        let func_handle = &ctx.module.function_handles[ctx.module.function_defs[*func_idx].function.0 as usize];
                        let func_name = ctx.module.identifier_at(func_handle.name);
                        
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Medium,
                            title: format!("Indirect recursion in '{}'", func_name),
                            description: "Function participates in indirect recursion without depth limit".to_string(),
                            location: create_location(ctx, &ctx.module.function_defs[*func_idx], 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement call depth tracking or break recursive cycle".to_string(),
                            references: vec![
                                "CWE-674: Uncontrolled Recursion".to_string(),
                            ],
                            metadata: std::collections::HashMap::new(),
                        });
                        break;
                    }
                }
            }
        }
        
        issues
    }
}

// Only include detectors that can be made extremely strict
pub fn get_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(GasGriefingAttack),
        Box::new(OutOfGasRevert),
        Box::new(StorageBloat),
        Box::new(DynamicVectorGrowth),
        Box::new(RecursiveCalls),
    ]
}