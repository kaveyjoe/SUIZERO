use move_binary_format::{file_format::*, access::ModuleAccess};
use crate::types::*;


pub fn create_location(ctx: &DetectionContext, func_def: &FunctionDefinition, instruction_idx: u16) -> CodeLocation {
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

pub fn create_module_location(ctx: &DetectionContext) -> CodeLocation {
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

pub fn emits_event(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    // Check local instructions
    if let Some(code) = &func_def.code {
        return code.code.iter().any(|instr| is_event_emission(instr, module));
    }
    false
}

// Check with recursion limit (simple interprocedural within module)
pub fn transitively_emits_event(func_def: &FunctionDefinition, module: &CompiledModule, depth: usize) -> bool {
    if depth == 0 { return false; }
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if is_event_emission(instr, module) {
                return true;
            }
            
            // Check calls to internal functions
            if let Some(func_idx) = get_internal_call_idx(instr, module) {
                 if let Some(callee_def) = module.function_defs.iter().find(|f| {
                     // Match definition to handle index
                     // FunctionDefinition has 'function' field which is FunctionHandleIndex
                     f.function == func_idx
                 }) {
                     if transitively_emits_event(callee_def, module, depth - 1) {
                         return true;
                     }
                 }
            }
        }
    }
    false
}

fn get_internal_call_idx(instr: &Bytecode, module: &CompiledModule) -> Option<FunctionHandleIndex> {
    match instr {
        Bytecode::Call(idx) => {
             // Check if it's internal (same module)
             // We can check if the handle's module index matches self.
             // Self module handle is usually index 0? Or we check module ID.
             let func_handle = &module.function_handles[idx.0 as usize];
             if func_handle.module.0 == 0 { // Heuristic: 0 is usually self, but better check.
                 // Actually standard Move binary format: ModuleHandle 0 is usually self if strictly compiled?
                 // Safer: Compare Handle Address/Name with Self ID.
                 return Some(*idx);
             }
             // Better check:
             let self_handle = module.module_handle_at(move_binary_format::file_format::ModuleHandleIndex(0));
             let call_module_handle = module.module_handle_at(func_handle.module);
             if self_handle == call_module_handle {
                 return Some(*idx);
             }
             None
        }
        _ => None
    }
}

pub fn is_event_emission(instr: &Bytecode, module: &CompiledModule) -> bool {
    let func_name_opt = get_function_name_full(instr, module);
    if let Some((_mod_addr, mod_name, func_name)) = func_name_opt {
        // Direct event emit
        if (mod_name == "event" || mod_name == "sui::event") && (func_name == "emit") {
            return true;
        }
        
        // Known helpers that wrap emit
        // This list can be expanded based on "God Mode" knowledge
        let known_wrappers = [
            "emit_event",
            "emit",
            "notify",
            "log",
            "record"
        ];
        
        if known_wrappers.contains(&func_name.as_str()) {
            return true;
        }
    }
    false
}

pub fn find_event_emissions(func_def: &FunctionDefinition, module: &CompiledModule) -> Vec<usize> {
    let mut indices = Vec::new();
    if let Some(code) = &func_def.code {
        for (i, instr) in code.code.iter().enumerate() {
            if is_event_emission(instr, module) {
                indices.push(i);
            }
        }
    }
    indices
}

/// Safely get function name from Call or CallGeneric bytecode instruction
pub fn get_function_name<'a>(instr: &Bytecode, module: &'a CompiledModule) -> Option<&'a move_core_types::identifier::IdentStr> {
    match instr {
        Bytecode::Call(func_idx) => {
            module.function_handles.get(func_idx.0 as usize)
                .map(|fh| module.identifier_at(fh.name))
        }
        Bytecode::CallGeneric(func_inst_idx) => {
            module.function_instantiations.get(func_inst_idx.0 as usize)
                .and_then(|fi| module.function_handles.get(fi.handle.0 as usize))
                .map(|fh| module.identifier_at(fh.name))
        }
        _ => None
    }
}

pub fn get_function_name_full(instr: &Bytecode, module: &CompiledModule) -> Option<(String, String, String)> {
     match instr {
        Bytecode::Call(idx) => resolve_full(idx.0 as usize, module),
        Bytecode::CallGeneric(idx) => {
             let inst = &module.function_instantiations[idx.0 as usize];
             resolve_full(inst.handle.0 as usize, module)
        }
        _ => None
    }
}

fn resolve_full(idx: usize, module: &CompiledModule) -> Option<(String, String, String)> {
    if let Some(fh) = module.function_handles.get(idx) {
        let m_handle = module.module_handle_at(fh.module);
        let m_addr = module.address_identifiers[m_handle.address.0 as usize].to_string();
        let m_name = module.identifier_at(m_handle.name).to_string();
        let f_name = module.identifier_at(fh.name).to_string();
        Some((m_addr, m_name, f_name))
    } else {
        None
    }
}

/// Safely check if a bytecode instruction calls a function with a specific name pattern
pub fn calls_function_matching(instr: &Bytecode, module: &CompiledModule, pattern: &str) -> bool {
    get_function_name(instr, module)
        .map(|name| name.as_str().contains(pattern))
        .unwrap_or(false)
}

pub fn is_external_call(instr: &Bytecode, module: &CompiledModule) -> bool {
    if let Some((mod_addr, mod_name, func_name)) = get_function_name_full(instr, module) {
        let self_addr = module.self_id().address().to_string().to_lowercase();
        let mod_addr_low = mod_addr.to_lowercase();
        
        let is_mod_zero = mod_addr_low.chars().all(|c| c == '0' || c == 'x');
        let is_self_zero = self_addr.chars().all(|c| c == '0' || c == 'x');

        // Whitelist internal package calls (same module address or both zero)
        if mod_addr_low == self_addr || (is_mod_zero && is_self_zero) {
            return false;
        }

        // Whitelist safe framework modules
        let mod_str = mod_name.as_str();
        let func_str = func_name.as_str();
        if (mod_str == "event" && func_str == "emit") || 
           (mod_str == "tx_context" && func_str == "sender") ||
           mod_str == "vector" ||
           mod_str == "option" ||
           mod_str == "timeout" ||
           mod_str == "table" ||
           mod_str == "table_ext" ||
           mod_str == "bag" ||
           mod_str == "object_bag" ||
           mod_str == "buffer_writer" {
            return false;
        }
        
        return true;
    }
    false
}
