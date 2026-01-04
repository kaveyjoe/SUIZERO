// src/detectors/reentrancy/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use move_binary_format::{file_format::*, access::ModuleAccess};

// RE-001: State Change After Call
pub struct StateChangeAfterCall;

#[async_trait::async_trait]
impl SecurityDetector for StateChangeAfterCall {
    fn id(&self) -> &'static str { "RE-001" }
    fn name(&self) -> &'static str { "State Change After Call" }
    fn description(&self) -> &'static str {
        "State modifications happen after external calls, violating checks-effects-interactions"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                
                // Strict filtering: Only check functions that are CRITICAL for reentrancy
                if !is_critical_reentrancy_function(func_name.as_str(), func_def, &ctx.module) {
                    continue;
                }
                
                // Build control flow graph to accurately determine execution paths
                let cfg = build_control_flow_graph(code);
                
                // Find all external calls with their data flow context
                let external_calls = find_external_calls_strict(func_def, &ctx.module);
                
                // Find all state modifications with their types
                let state_mods = find_state_modifications_strict(func_def, &ctx.module);
                
                // For each external call, check if there's a REACHABLE state modification after it
                for call in &external_calls {
                    // Only consider calls that transfer value or modify external state
                    if !is_potentially_reentrant_call(call, func_def, &ctx.module) {
                        continue;
                    }
                    
                    for state_mod in &state_mods {
                        // State modification must be after the call in execution order
                        if state_mod.instruction_index > call.instruction_index {
                            // CRITICAL: Check if there's an actual control flow path
                            if is_reachable_after_call(&cfg, call.instruction_index as usize, 
                                                      state_mod.instruction_index as usize) {
                                
                                // Check if the state modification affects CRITICAL state
                                if affects_critical_state(state_mod, func_def, &ctx.module) {
                                    // Verify this is not a benign pattern (e.g., logging, cleanup)
                                    if !is_benign_state_change_after_call(state_mod, &external_calls, 
                                                                          func_def, &ctx.module) {
                                        
                                        // Check if there's any reentrancy guard in place
                                        if !has_reentrancy_guard(func_def, &ctx.module) {
                                            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                                            let func_name = ctx.module.identifier_at(func_handle.name);
                                            
                                            issues.push(SecurityIssue {
                                                id: self.id().to_string(),
                                                severity: self.default_severity(),
                                                confidence: Confidence::High,
                                                title: format!("Critical reentrancy risk in '{}'", func_name),
                                                description: format!(
                                                    "State change after external call at instruction {}. Modifies critical state at {}",
                                                    call.instruction_index, state_mod.instruction_index
                                                ),
                                                location: call.location.clone(),
                                                source_code: Some(format!("{}::{}", 
                                                    ctx.module.self_id().name(), func_name)),
                                                recommendation: "Apply checks-effects-interactions: 1. Validate, 2. Update state, 3. External calls. Add reentrancy guard.".to_string(),
                                                references: vec![
                                                    "CWE-841: Improper Enforcement of Behavioral Workflow".to_string(),
                                                    "https://docs.sui.io/concepts/security/reentrancy".to_string(),
                                                    "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/".to_string(),
                                                ],
                                                metadata: {
                                                    let mut map = std::collections::HashMap::new();
                                                    map.insert("call_type".to_string(), call.call_type.clone());
                                                    map.insert("state_type".to_string(), state_mod.state_type.clone());
                                                    map.insert("distance".to_string(), 
                                                        (state_mod.instruction_index - call.instruction_index).to_string());
                                                    map
                                                },
                                            });
                                            break; // One issue per dangerous call is enough
                                        }
                                    }
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

// RE-002: Cross-Function Reentrancy
pub struct CrossFunctionReentrancy;

#[async_trait::async_trait]
impl SecurityDetector for CrossFunctionReentrancy {
    fn id(&self) -> &'static str { "RE-002" }
    fn name(&self) -> &'static str { "Cross-Function Reentrancy" }
    fn description(&self) -> &'static str {
        "Multiple functions access shared state without proper synchronization"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Find shared state accesses across functions with strict filtering
        let shared_state_accesses = find_shared_state_accesses_strict(&ctx.module);
        
        // Only flag critical shared state (financial/access control)
        for (struct_idx, accesses) in &shared_state_accesses {
            let struct_handle = &ctx.module.struct_handles[*struct_idx as usize];
            let struct_name = ctx.module.identifier_at(struct_handle.name);
            
            // Only check critical shared state
            if !is_critical_shared_state(struct_name.as_str()) {
                continue;
            }
            
            // Group by access type (read/write)
            let mut write_accesses = Vec::new();
            let mut read_accesses = Vec::new();
            
            for (func_idx, access_type, location) in accesses {
                if *access_type == AccessType::Write {
                    write_accesses.push((*func_idx, location));
                } else {
                    read_accesses.push((*func_idx, location));
                }
            }
            
            // Only flag if there are multiple write accesses OR
            // write access combined with external calls
            if write_accesses.len() > 1 {
                // Multiple functions can write to the same critical state
                let func_names: Vec<String> = write_accesses.iter()
                    .map(|(func_idx, _)| {
                        let func_def = &ctx.module.function_defs[*func_idx];
                        let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                        ctx.module.identifier_at(func_handle.name).to_string()
                    })
                    .collect();
                
                // Check if these functions have external calls
                let functions_with_external_calls = write_accesses.iter()
                    .filter(|(func_idx, _)| {
                        let func_def = &ctx.module.function_defs[*func_idx];
                        has_external_calls(func_def, &ctx.module)
                    })
                    .count();
                
                if functions_with_external_calls > 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if functions_with_external_calls > 1 { 
                            Confidence::High 
                        } else { 
                            Confidence::Medium 
                        },
                        title: format!("Cross-function reentrancy on '{}'", struct_name),
                        description: format!(
                            "{} functions write to shared critical state '{}': {}. {} have external calls.",
                            write_accesses.len(), struct_name, func_names.join(", "), functions_with_external_calls
                        ),
                        location: create_module_location(ctx),
                        source_code: Some(struct_name.to_string()),
                        recommendation: "Implement locking mechanisms, use atomic types, or ensure serializable execution".to_string(),
                        references: vec![
                            "https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-2".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// RE-003: Read-Only Reentrancy
pub struct ReadOnlyReentrancy;

#[async_trait::async_trait]
impl SecurityDetector for ReadOnlyReentrancy {
    fn id(&self) -> &'static str { "RE-003" }
    fn name(&self) -> &'static str { "Read-Only Reentrancy" }
    fn description(&self) -> &'static str {
        "View functions return inconsistent state due to reentrancy"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Only check functions that are explicitly view/pure
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Strict: Only functions that are clearly view functions
            if !is_strict_view_function(func_name.as_str(), func_def) {
                continue;
            }
            
            // View function that reads MUTABLE global state
            if reads_mutable_global_state(func_def, &ctx.module) {
                // Check if this view function is called by other functions with external calls
                if is_called_by_functions_with_external_calls(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::Medium,
                        title: format!("Read-only reentrancy in '{}'", func_name),
                        description: "View function reads mutable global state that could be inconsistent during reentrancy".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Make view functions read-only or use snapshot patterns for consistent state views".to_string(),
                        references: vec![
                            "https://blog.trailofbits.com/2022/04/14/read-only-reentrancy-the-new-silent-killer-of-smart-contracts/".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// RE-010: Batch Operation Reentrancy
pub struct BatchOperationReentrancy;

#[async_trait::async_trait]
impl SecurityDetector for BatchOperationReentrancy {
    fn id(&self) -> &'static str { "RE-010" }
    fn name(&self) -> &'static str { "Batch Operation Reentrancy" }
    fn description(&self) -> &'static str {
        "Reentrancy in batch processing functions with loops"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            // Strict: Only functions that are clearly batch operations
            if !is_batch_operation_function(func_name.as_str(), func_def, &ctx.module) {
                continue;
            }
            
            if let Some(code) = &func_def.code {
                // Find loops and check for dangerous patterns
                let loops = find_loops(code);
                
                for (loop_start, loop_end) in loops {
                    // Check if loop contains external calls
                    let has_external_calls_in_loop = has_external_calls_in_range(
                        code, loop_start, loop_end, &ctx.module);
                    
                    // Check if loop modifies state that affects subsequent iterations
                    let has_state_mods_in_loop = has_state_modifications_in_range(
                        code, loop_start, loop_end, &ctx.module);
                    
                    if has_external_calls_in_loop && has_state_mods_in_loop {
                        // Check for cross-iteration dependencies
                        if has_cross_iteration_dependencies(code, loop_start, loop_end, &ctx.module) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: format!("Batch operation reentrancy in '{}'", func_name),
                                description: "Batch loop with external calls and state modifications creates reentrancy risk across iterations".to_string(),
                                location: create_location(ctx, func_def, loop_start as u16),
                                source_code: Some(func_name.to_string()),
                                recommendation: "Separate batch processing: 1. Validate all inputs, 2. Update all states, 3. Make external calls. Or use atomic batch operations.".to_string(),
                                references: vec![
                                    "https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-3".to_string(),
                                ],
                                metadata: std::collections::HashMap::new(),
                            });
                            break;
                        }
                    }
                }
            }
        }
        
        issues
    }
}

// Strict helper structures
#[derive(Debug, Clone)]
struct ExternalCallInfo {
    location: CodeLocation,
    instruction_index: u16,
    call_type: String,
    target_module: String,
    transfers_value: bool,
}

#[derive(Debug, Clone)]
struct StateModificationInfo {
    location: CodeLocation,
    instruction_index: u16,
    state_type: String,
    struct_name: String,
    modification_type: ModificationType,
}

#[derive(Debug, Clone, PartialEq)]
enum ModificationType {
    MoveTo,
    MoveFrom,
    BorrowMut,
}

#[derive(Debug, Clone, PartialEq)]
enum AccessType {
    Read,
    Write,
}

// Strict helper functions
fn is_critical_reentrancy_function(func_name: &str, func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // Check function name patterns
    let name_lower = func_name.to_lowercase();
    let critical_patterns = [
        "transfer", "withdraw", "deposit", "send", "mint", "burn", 
        "stake", "unstake", "claim", "swap", "redeem", "liquidate"
    ];
    
    let has_critical_name = critical_patterns.iter()
        .any(|pattern| name_lower.contains(pattern));
    
    if !has_critical_name {
        return false;
    }
    
    // Check if function actually handles valuable assets
    if let Some(code) = &func_def.code {
        // Look for coin operations
        let has_coin_operations = code.code.iter().any(|instr| {
            match instr {
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    if let Some((func_name, _)) = get_function_call_details(instr, module) {
                        func_name.contains("coin") || func_name.contains("balance")
                    } else {
                        false
                    }
                }
                _ => false
            }
        });
        
        if !has_coin_operations {
            return false;
        }
    }
    
    true
}

fn find_external_calls_strict(func_def: &FunctionDefinition, module: &CompiledModule) -> Vec<ExternalCallInfo> {
    let mut calls = Vec::new();
    
    if let Some(code) = &func_def.code {
        for (i, instr) in code.code.iter().enumerate() {
            if let Some((func_name, signature)) = get_function_call_details(instr, module) {
                // Check if it's truly external (different module)
                let is_external = is_external_function_call(&func_name, module);
                
                if is_external {
                    let func_handle = &module.function_handles[func_def.function.0 as usize];
                    let parent_func_name = module.identifier_at(func_handle.name);
                    
                    // Determine if this call transfers value
                    let transfers_value = signature.contains("Coin") || 
                                         signature.contains("balance") ||
                                         func_name.contains("transfer");
                    
                    calls.push(ExternalCallInfo {
                        location: CodeLocation {
                            module_id: module.self_id().to_string(),
                            module_name: module.self_id().name().to_string(),
                            function_name: parent_func_name.to_string(),
                            instruction_index: i as u16,
                            byte_offset: 0,
                            line: None,
                            column: None,
                        },
                        instruction_index: i as u16,
                        call_type: if transfers_value { "value_transfer".to_string() } else { "regular".to_string() },
                        target_module: func_name.split("::").next().unwrap_or("").to_string(),
                        transfers_value,
                    });
                }
            }
        }
    }
    
    calls
}

fn find_state_modifications_strict(func_def: &FunctionDefinition, module: &CompiledModule) -> Vec<StateModificationInfo> {
    let mut modifications = Vec::new();
    
    if let Some(code) = &func_def.code {
        for (i, instr) in code.code.iter().enumerate() {
            let (mod_type, struct_idx) = match instr {
                Bytecode::MoveTo(idx) => (ModificationType::MoveTo, *idx),
                Bytecode::MoveFrom(idx) => (ModificationType::MoveFrom, *idx),
                Bytecode::MutBorrowGlobal(idx) => (ModificationType::BorrowMut, *idx),
                Bytecode::MoveToGeneric(idx) |
                Bytecode::MoveFromGeneric(idx) |
                Bytecode::MutBorrowGlobalGeneric(idx) => {
                    // For generic calls, get the base struct
                    let type_inst = &module.struct_instantiations()[idx.0 as usize];
                    let mod_type = match instr {
                        Bytecode::MoveToGeneric(_) => ModificationType::MoveTo,
                        Bytecode::MoveFromGeneric(_) => ModificationType::MoveFrom,
                        Bytecode::MutBorrowGlobalGeneric(_) => ModificationType::BorrowMut,
                        _ => continue,
                    };
                    (mod_type, type_inst.def)
                }
                _ => continue,
            };
            
            let struct_handle = module.struct_handles.get(struct_idx.0 as usize);
            if let Some(handle) = struct_handle {
                let struct_name = module.identifier_at(handle.name);
                
                let func_handle = &module.function_handles[func_def.function.0 as usize];
                let parent_func_name = module.identifier_at(func_handle.name);
                
                modifications.push(StateModificationInfo {
                    location: CodeLocation {
                        module_id: module.self_id().to_string(),
                        module_name: module.self_id().name().to_string(),
                        function_name: parent_func_name.to_string(),
                        instruction_index: i as u16,
                        byte_offset: 0,
                        line: None,
                        column: None,
                    },
                    instruction_index: i as u16,
                    state_type: get_state_type(struct_name),
                    struct_name: struct_name.to_string(),
                    modification_type: mod_type,
                });
            }
        }
    }
    
    modifications
}

fn build_control_flow_graph(code: &CodeUnit) -> petgraph::graph::DiGraph<usize, ()> {
    let mut graph = petgraph::graph::DiGraph::new();
    let mut node_map = std::collections::HashMap::new();
    
    // Add nodes for each instruction
    for i in 0..code.code.len() {
        let node = graph.add_node(i);
        node_map.insert(i, node);
    }
    
    // Add edges based on control flow
    for (i, instr) in code.code.iter().enumerate() {
        if let Some(node) = node_map.get(&i) {
            match instr {
                Bytecode::Branch(target) => {
                    // Branch edge
                    if let Some(target_node) = node_map.get(&(*target as usize)) {
                        graph.add_edge(*node, *target_node, ());
                    }
                    // Fall-through edge (if not unconditional branch)
                    if i + 1 < code.code.len() {
                        if let Some(next_node) = node_map.get(&(i + 1)) {
                            graph.add_edge(*node, *next_node, ());
                        }
                    }
                }
                Bytecode::BrTrue(target) | Bytecode::BrFalse(target) => {
                    // Conditional branch edges
                    if let Some(target_node) = node_map.get(&(*target as usize)) {
                        graph.add_edge(*node, *target_node, ());
                    }
                    // Fall-through edge
                    if i + 1 < code.code.len() {
                        if let Some(next_node) = node_map.get(&(i + 1)) {
                            graph.add_edge(*node, *next_node, ());
                        }
                    }
                }
                Bytecode::Ret => {
                    // No outgoing edges
                }
                _ => {
                    // Sequential execution
                    if i + 1 < code.code.len() {
                        if let Some(next_node) = node_map.get(&(i + 1)) {
                            graph.add_edge(*node, *next_node, ());
                        }
                    }
                }
            }
        }
    }
    
    graph
}

fn is_reachable_after_call(cfg: &petgraph::graph::DiGraph<usize, ()>, 
                          call_idx: usize, 
                          state_idx: usize) -> bool {
    use petgraph::visit::Dfs;
    
    let start_node = cfg.node_indices().find(|&n| cfg[n] == call_idx);
    let end_node = cfg.node_indices().find(|&n| cfg[n] == state_idx);
    
    match (start_node, end_node) {
        (Some(start), Some(end)) => {
            // Use DFS to check reachability
            let mut dfs = Dfs::new(&cfg, start);
            while let Some(node) = dfs.next(&cfg) {
                if node == end {
                    return true;
                }
            }
            false
        }
        _ => false
    }
}

fn is_potentially_reentrant_call(call: &ExternalCallInfo, 
                                func_def: &FunctionDefinition, 
                                module: &CompiledModule) -> bool {
    // Calls that transfer value are always potentially reentrant
    if call.transfers_value {
        return true;
    }
    
    // Calls to functions that have callbacks or events
    // This would require analyzing the called function's behavior
    call.call_type == "value_transfer" || call.target_module != module.self_id().name().as_str()
}

fn affects_critical_state(state_mod: &StateModificationInfo, 
                         func_def: &FunctionDefinition, 
                         module: &CompiledModule) -> bool {
    // Only flag modifications to critical state
    let critical_state_types = [
        "balance", "coin", "token", "stake", "reward", 
        "vault", "pool", "lock", "access_control"
    ];
    
    let state_type_lower = state_mod.state_type.to_lowercase();
    critical_state_types.iter().any(|&typ| state_type_lower.contains(typ))
}

fn is_benign_state_change_after_call(state_mod: &StateModificationInfo,
                                    external_calls: &[ExternalCallInfo],
                                    func_def: &FunctionDefinition,
                                    module: &CompiledModule) -> bool {
    // Check if this is a benign pattern like:
    // 1. Event emission after call
    // 2. Cleanup operations
    // 3. Logging
    
    let state_type_lower = state_mod.state_type.to_lowercase();
    
    // Benign state types
    let benign_types = ["counter", "nonce", "index", "timestamp", "log", "event"];
    
    if benign_types.iter().any(|&typ| state_type_lower.contains(typ)) {
        return true;
    }
    
    // Check if this state change is independent of the call
    // (e.g., updating a timestamp that doesn't affect logic)
    state_mod.modification_type == ModificationType::BorrowMut && 
    !state_type_lower.contains("balance")
}

fn has_reentrancy_guard(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // Look for reentrancy guard patterns
    if let Some(code) = &func_def.code {
        // Check for mutex/lock patterns
        for instr in &code.code {
            match instr {
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                    if let Some((func_name, _)) = get_function_call_details(instr, module) {
                        if func_name.contains("lock") || 
                           func_name.contains("guard") || 
                           func_name.contains("mutex") ||
                           func_name.contains("nonce") {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        
        // Check for boolean flag patterns
        let mut has_flag_check = false;
        let mut has_flag_set = false;
        
        for i in 0..code.code.len() {
            match &code.code[i] {
                Bytecode::LdConst(_) => {
                    // Look for flag loading
                    if i + 1 < code.code.len() {
                        if let Bytecode::Eq = &code.code[i + 1] {
                            has_flag_check = true;
                        }
                    }
                }
                Bytecode::LdTrue | Bytecode::LdFalse => {
                    // Look for flag setting
                    if i + 1 < code.code.len() {
                        if matches!(&code.code[i + 1], Bytecode::StLoc(_)) {
                            has_flag_set = true;
                        }
                    }
                }
                _ => {}
            }
        }
        
        if has_flag_check && has_flag_set {
            return true;
        }
    }
    
    false
}

fn find_shared_state_accesses_strict(module: &CompiledModule) -> 
    std::collections::HashMap<u16, Vec<(usize, AccessType, CodeLocation)>> {
    
    let mut accesses = std::collections::HashMap::new();
    
    for (func_idx, func_def) in module.function_defs.iter().enumerate() {
        if let Some(code) = &func_def.code {
            for (i, instr) in code.code.iter().enumerate() {
                let (access_type, struct_idx) = match instr {
                    Bytecode::MutBorrowGlobal(idx) => (AccessType::Write, *idx),
                    Bytecode::ImmBorrowGlobal(idx) => (AccessType::Read, *idx),
                    Bytecode::MoveFrom(idx) => (AccessType::Write, *idx),
                    Bytecode::MoveTo(idx) => (AccessType::Write, *idx),
                    Bytecode::MutBorrowGlobalGeneric(idx) => {
                        let type_inst = &module.struct_instantiations()[idx.0 as usize];
                        (AccessType::Write, type_inst.def)
                    }
                    Bytecode::ImmBorrowGlobalGeneric(idx) => {
                        let type_inst = &module.struct_instantiations()[idx.0 as usize];
                        (AccessType::Read, type_inst.def)
                    }
                    Bytecode::MoveFromGeneric(idx) => {
                        let type_inst = &module.struct_instantiations()[idx.0 as usize];
                        (AccessType::Write, type_inst.def)
                    }
                    Bytecode::MoveToGeneric(idx) => {
                        let type_inst = &module.struct_instantiations()[idx.0 as usize];
                        (AccessType::Write, type_inst.def)
                    }
                    _ => continue,
                };
                
                let location = create_location_from_index(module, func_def, i as u16);
                accesses.entry(struct_idx.0)
                    .or_insert_with(Vec::new)
                    .push((func_idx, access_type, location));
            }
        }
    }
    
    accesses
}

fn is_critical_shared_state(struct_name: &str) -> bool {
    let name_lower = struct_name.to_lowercase();
    let critical_patterns = [
        "balance", "coin", "token", "stake", "pool", "vault",
        "treasury", "reserve", "lock", "access", "admin", "owner"
    ];
    
    critical_patterns.iter().any(|&pattern| name_lower.contains(pattern))
}

fn has_external_calls(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    find_external_calls_strict(func_def, module).iter()
        .any(|call| call.transfers_value)
}

fn is_strict_view_function(func_name: &str, func_def: &FunctionDefinition) -> bool {
    // Only functions that are explicitly read-only
    let name_lower = func_name.to_lowercase();
    
    // Check name patterns
    let view_patterns = ["view_", "get_", "read_", "query_", "is_", "has_"];
    let is_view_by_name = view_patterns.iter().any(|&pattern| name_lower.starts_with(pattern));
    
    if !is_view_by_name {
        return false;
    }
    
    // Check function doesn't modify state
    // (Would need to check for write operations)
    true
}

fn reads_mutable_global_state(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            match instr {
                Bytecode::MutBorrowGlobal(_) |
                Bytecode::MutBorrowGlobalGeneric(_) |
                Bytecode::MoveFrom(_) |
                Bytecode::MoveFromGeneric(_) => {
                    // Reading mutable state
                    return true;
                }
                _ => {}
            }
        }
    }
    false
}

fn is_called_by_functions_with_external_calls(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // In practice, would need call graph analysis
    // For now, assume potential
    true
}

fn is_batch_operation_function(func_name: &str, func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    let name_lower = func_name.to_lowercase();
    
    // Check name patterns
    let batch_patterns = ["batch_", "multi_", "bulk_", "process_many", "handle_multiple"];
    let is_batch_by_name = batch_patterns.iter().any(|&pattern| name_lower.contains(pattern));
    
    if !is_batch_by_name {
        return false;
    }
    
    // Check for vector/iterable parameters
    let func_handle_idx = func_def.function;
    let _func_handle = &module.function_handles[func_handle_idx.0 as usize];
    // Check signature for vector types (simplified)
    // In practice, would analyze type parameters
    true
}

fn find_loops(code: &CodeUnit) -> Vec<(usize, usize)> {
    let mut loops = Vec::new();
    let mut _loop_stack: Vec<usize> = Vec::new();
    
    for (i, instr) in code.code.iter().enumerate() {
        match instr {
            Bytecode::Branch(target) => {
                let target_idx = *target as usize;
                if target_idx < i {
                    // Backward branch indicates a loop
                    loops.push((target_idx, i));
                }
            }
            Bytecode::BrTrue(target) | Bytecode::BrFalse(target) => {
                let target_idx = *target as usize;
                if target_idx < i {
                    // Potential loop with conditional back edge
                    loops.push((target_idx, i));
                }
            }
            _ => {}
        }
    }
    
    loops
}

fn has_external_calls_in_range(code: &CodeUnit, start: usize, end: usize, module: &CompiledModule) -> bool {
    for i in start..=end {
        if let Some((func_name, _)) = get_function_call_details(&code.code[i], module) {
            if is_external_function_call(&func_name, module) {
                return true;
            }
        }
    }
    false
}

fn has_state_modifications_in_range(code: &CodeUnit, start: usize, end: usize, module: &CompiledModule) -> bool {
    for i in start..=end {
        match &code.code[i] {
            Bytecode::MoveTo(_) |
            Bytecode::MoveFrom(_) |
            Bytecode::MutBorrowGlobal(_) |
            Bytecode::MoveToGeneric(_) |
            Bytecode::MoveFromGeneric(_) |
            Bytecode::MutBorrowGlobalGeneric(_) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn has_cross_iteration_dependencies(code: &CodeUnit, start: usize, end: usize, module: &CompiledModule) -> bool {
    // Check if loop iterations depend on state modified within the loop
    // Simplified: look for global state reads after modifications
    let mut found_modification = false;
    
    for i in start..=end {
        match &code.code[i] {
            Bytecode::MoveTo(_) |
            Bytecode::MutBorrowGlobal(_) |
            Bytecode::MoveToGeneric(_) |
            Bytecode::MutBorrowGlobalGeneric(_) => {
                found_modification = true;
            }
            Bytecode::ImmBorrowGlobal(_) |
            Bytecode::MoveFrom(_) |
            Bytecode::ImmBorrowGlobalGeneric(_) |
            Bytecode::MoveFromGeneric(_) => {
                if found_modification {
                    return true;
                }
            }
            _ => {}
        }
    }
    
    false
}

fn get_function_call_details(instr: &Bytecode, module: &CompiledModule) -> Option<(String, String)> {
    match instr {
        Bytecode::Call(idx) => {
            let func_handle = &module.function_handles[idx.0 as usize];
            let module_handle = &module.module_handles[func_handle.module.0 as usize];
            let module_name = module.identifier_at(module_handle.name);
            let func_name = module.identifier_at(func_handle.name);
            Some((format!("{}::{}", module_name, func_name), format!("{:?}", func_handle)))
        }
        Bytecode::CallGeneric(idx) => {
            let func_inst = &module.function_instantiations[idx.0 as usize];
            let func_handle = &module.function_handles[func_inst.handle.0 as usize];
            let module_handle = &module.module_handles[func_handle.module.0 as usize];
            let module_name = module.identifier_at(module_handle.name);
            let func_name = module.identifier_at(func_handle.name);
            Some((format!("{}::{}", module_name, func_name), format!("{:?}", func_inst)))
        }
        _ => None,
    }
}

fn is_external_function_call(func_name: &str, module: &CompiledModule) -> bool {
    // Check if function is from a different module
    if let Some(module_name) = func_name.split("::").next() {
        module_name != module.self_id().name().as_str()
    } else {
        false
    }
}

fn get_state_type(struct_name: &move_core_types::identifier::IdentStr) -> String {
    let name_str = struct_name.as_str().to_lowercase();
    
    if name_str.contains("balance") || name_str.contains("coin") {
        "balance".to_string()
    } else if name_str.contains("stake") {
        "stake".to_string()
    } else if name_str.contains("pool") || name_str.contains("vault") {
        "pool".to_string()
    } else if name_str.contains("lock") || name_str.contains("guard") {
        "lock".to_string()
    } else if name_str.contains("admin") || name_str.contains("owner") {
        "access_control".to_string()
    } else if name_str.contains("counter") || name_str.contains("nonce") {
        "counter".to_string()
    } else {
        "other".to_string()
    }
}

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

fn create_module_location(ctx: &DetectionContext) -> CodeLocation {
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: "".to_string(),
        instruction_index: 0,
        byte_offset: 0,
        line: None,
        column: None,
    }
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