use crate::types::{SecurityIssue, Severity, Confidence, CodeLocation, DetectionContext};
use move_binary_format::file_format::{Bytecode, CompiledModule, FunctionDefinition};
use move_binary_format::access::ModuleAccess;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq)]
enum TaintState {
    Clean,
    Tainted(String), // Origin of taint (e.g., "Arg 0")
}

pub struct TaintAnalyzer {
    // Configuration for sinks
    sinks: HashSet<String>,
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        let mut sinks = HashSet::new();
        // Critical sinks where user input should be validated
        sinks.insert("transfer::transfer".to_string());
        sinks.insert("transfer::public_transfer".to_string());
        sinks.insert("transfer::public_share_object".to_string());
        sinks.insert("coin::join".to_string());
        // User requested: Delegation points
        sinks.insert("transfer_policy::new_request".to_string());
        sinks.insert("dynamic_field::remove".to_string());
        sinks.insert("dynamic_object_field::remove".to_string());
        sinks.insert("object::delete".to_string());
        Self { sinks }
    }

    pub fn analyze(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();

        for func_def in &ctx.module.function_defs {
            if let Some(code) = &func_def.code {
                if func_def.is_entry || func_def.visibility == move_binary_format::file_format::Visibility::Public {
                     issues.extend(self.analyze_function(func_def, &ctx.module));
                }
            }
        }
        issues
    }

    fn analyze_function(&self, func_def: &FunctionDefinition, module: &CompiledModule) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        if func_def.code.is_none() { return issues; }
        let code = func_def.code.as_ref().unwrap();

        // 1. Initialize Locals with Taint (Arguments are tainted)
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let parameters = &module.signatures[func_handle.parameters.0 as usize];
        let func_name_str = module.identifier_at(func_handle.name).as_str().to_string();
        
        let mut locals_taint: HashMap<u8, TaintState> = HashMap::new();
        
        for (i, param_type) in parameters.0.iter().enumerate() {
            let mut source = format!("Arg {}", i);
            if let Some(struct_name) = self.get_struct_name(param_type, module) {
                source = format!("Arg {} ({})", i, struct_name);
            }
            locals_taint.insert(i as u8, TaintState::Tainted(source));
        }

        // Initialize stack
        let mut stack: Vec<TaintState> = Vec::new();
        
        // Authorization State (Heuristic)
        // Check if function arguments include a "Capability" or "Owner" struct
        let mut is_authorized = false;
        
        for param_type in &parameters.0 {
            if let Some(struct_name) = self.get_struct_name(param_type, module) {
                if struct_name.contains("Cap") || 
                   struct_name.contains("Capability") || 
                   struct_name.contains("Admin") ||
                   struct_name.contains("Owner") ||
                   struct_name.contains("Ticket") {
                    is_authorized = true;
                    // Note: We don't break, maybe useful to log.
                }
            }
        }

        // 2. Abstract Interpretation
        for (pc, instr) in code.code.iter().enumerate() {
            match instr {
                // Taint Sources/Propagation via Locals
                Bytecode::MoveLoc(idx) | Bytecode::CopyLoc(idx) => {
                    let state = locals_taint.get(idx).cloned().unwrap_or(TaintState::Clean);
                    stack.push(state);
                }
                Bytecode::StLoc(idx) => {
                    if let Some(state) = stack.pop() {
                        locals_taint.insert(*idx, state);
                    }
                }
                Bytecode::Pop => {
                    stack.pop();
                }

                // Call Sinks & Checks
                Bytecode::Call(_) | Bytecode::CallGeneric(_) => {
                     self.handle_call(instr, module, &mut stack, &mut issues, pc, &func_name_str, &mut is_authorized);
                }

                // Constants (Clean)
                Bytecode::LdU8(_) | Bytecode::LdU64(_) | Bytecode::LdU128(_) | Bytecode::LdConst(_) | Bytecode::LdTrue | Bytecode::LdFalse => {
                    stack.push(TaintState::Clean);
                }

                // Math (Propagate)
                // Move arithmetic is checked, but taint flows through results
                Bytecode::Add | Bytecode::Sub | Bytecode::Mul | Bytecode::Div | Bytecode::Mod |
                Bytecode::BitAnd | Bytecode::BitOr | Bytecode::Xor | Bytecode::Shl | Bytecode::Shr => {
                   let v2 = stack.pop().unwrap_or(TaintState::Clean);
                   let v1 = stack.pop().unwrap_or(TaintState::Clean);
                   if v1 != TaintState::Clean || v2 != TaintState::Clean {
                       stack.push(TaintState::Tainted("Derived".to_string()));
                   } else {
                       stack.push(TaintState::Clean);
                   }
                }
                
                // Pack 
                Bytecode::Pack(idx) => {
                    let (args, _) = self.get_pack_counts(instr, module, Some(*idx));
                    self.handle_pack(args, &mut stack);
                }
                Bytecode::PackGeneric(idx) => {
                     let struct_inst = &module.struct_def_instantiations[idx.0 as usize];
                     let (args, _) = self.get_pack_counts(instr, module, Some(struct_inst.def));
                     self.handle_pack(args, &mut stack);
                }
                
                // Unpack (Propagate? Conserves taint?)
                // If we unpack a tainted struct, fields are tainted.
                Bytecode::Unpack(idx) => {
                    let (fields, _) = self.get_pack_counts(instr, module, Some(*idx)); // Pack count == Unpack count usually
                    self.handle_unpack(fields, &mut stack);
                }
                Bytecode::UnpackGeneric(idx) => {
                     let struct_inst = &module.struct_def_instantiations[idx.0 as usize];
                     let (fields, _) = self.get_pack_counts(instr, module, Some(struct_inst.def));
                     self.handle_unpack(fields, &mut stack);
                }

                _ => {
                    // Default behavior
                }
            }
        }

        issues
    }
    
    fn handle_pack(&self, args: usize, stack: &mut Vec<TaintState>) {
        let mut is_tainted = false;
        for _ in 0..args {
             if let Some(TaintState::Tainted(_)) = stack.pop() {
                 is_tainted = true;
             }
        }
        stack.push(if is_tainted { TaintState::Tainted("Struct".to_string()) } else { TaintState::Clean });
    }

    fn handle_unpack(&self, fields: usize, stack: &mut Vec<TaintState>) {
        let is_tainted = if let Some(TaintState::Tainted(_)) = stack.pop() { true } else { false };
        // Push N fields. If struct was tainted, fields are tainted.
        for _ in 0..fields {
            stack.push(if is_tainted { TaintState::Tainted("Field".to_string()) } else { TaintState::Clean });
        }
    }

    // Helper to deduplicate logic
    fn handle_call(&self, instr: &Bytecode, module: &CompiledModule, stack: &mut Vec<TaintState>, issues: &mut Vec<SecurityIssue>, pc: usize, caller_name: &str, is_authorized: &mut bool) {
        let full_name_opt = self.resolve_function_name(instr, module);
        
        let mut call_has_tainted_args = false;
        let mut tainted_source = String::new();

        let arg_count = self.get_arg_count(instr, module);
        let mut args_states = Vec::new();

        // Pop args (reverse order)
        for _ in 0..arg_count {
            if let Some(state) = stack.pop() {
                if let TaintState::Tainted(s) = &state {
                    call_has_tainted_args = true;
                    tainted_source = s.clone();
                }
                args_states.push(state);
            }
        }
        
        if let Some(name) = &full_name_opt {
            // Check Sanitizer / Authorization
            if self.is_sanitizer(name) {
                // If we hit a sanitizer (like check_owner), we assume the function context becomes authorized.
                *is_authorized = true;
            }

            // Recognize "Self-Authorized" types (Linear Resources)
            // If the function is called with a Coin, Balance, or UID, it's implicitly authorized in Sui.
            let mut is_self_authorized_type = false;
            for arg_state in &args_states {
                 if let TaintState::Tainted(source) = arg_state {
                     if source.contains("Coin") || source.contains("Balance") || source.contains("UID") {
                         is_self_authorized_type = true;
                     }
                 }
            }

            let effective_authorized = *is_authorized || is_self_authorized_type;

            // Dynamic Fields Special Handling
            if name.contains("dynamic_field") || name.contains("dynamic_object_field") {
                self.handle_dynamic_field_ops(name, &args_states, issues, module, caller_name, pc, effective_authorized);
            } else if self.is_sink(name) && call_has_tainted_args {
                 // Generic Sink Logic
                 let severity = if effective_authorized { Severity::Low } else { Severity::Critical };
                 let title_prefix = if effective_authorized { "Authorized Data Flow (Info)" } else { "Unsafe Data Flow" };
                 
                 issues.push(SecurityIssue {
                    id: "TAINT-001".to_string(),
                    severity,
                    confidence: if effective_authorized { Confidence::Medium } else { Confidence::High },
                    title: format!("{} into '{}'", title_prefix, name),
                    description: format!("User-controlled input ({}) flows into critical function '{}'. Authorization detected: {}.", tainted_source, name, effective_authorized),
                    location: CodeLocation {
                        module_id: module.self_id().to_string(),
                        module_name: module.self_id().name().to_string(),
                        function_name: caller_name.to_string(),
                        instruction_index: pc as u16,
                        byte_offset: 0,
                        line: None,
                        column: None,
                    },
                    source_code: Some(name.clone()),
                    recommendation: "Ensure input is validated before use. If authorized, verify scope.".to_string(),
                    references: vec!["OWASP Taint Analysis".to_string()],
                    metadata: HashMap::new(),
                });
            }
            
            // Interprocedural Propagation:
            // High-confidence heuristic: If we pass tainted args to ANY function,
            // assume the return values are tainted.
            // Exception: specific sanitizers (none defined yet).
            // Also Exception: Helper functions like `vector` ops might just pass it validly. 
            // But "Taint Spreading" is safer for security.
        }

        let (args, _) = self.get_sig_counts(instr, module);
        // We already popped `args` (calculated by get_arg_count which should equal `args`)
        // Actually `stack.pop()` above popped them.
        
        // Push returns
        let returns_tokens = self.get_return_tokens(instr, module);
        for return_type in returns_tokens { 
            let mut result_state = if call_has_tainted_args {
                let mut source = "Result".to_string();
                if let Some(struct_name) = self.get_struct_name(&return_type, module) {
                    source = format!("Result ({})", struct_name);
                }
                TaintState::Tainted(source)
            } else {
                TaintState::Clean
            };

            // Exception: object::new returns fresh (Clean) UID even if ctx is tainted
            if let Some(name) = &full_name_opt {
                if name.contains("object::new") {
                    result_state = TaintState::Clean;
                }
            }

            stack.push(result_state);
        }
    }

    fn get_return_tokens(&self, instr: &Bytecode, module: &CompiledModule) -> Vec<move_binary_format::file_format::SignatureToken> {
        match instr {
            Bytecode::Call(idx) => {
                let func_handle = &module.function_handles[idx.0 as usize];
                let returns = &module.signatures[func_handle.return_.0 as usize];
                returns.0.clone()
            }
            Bytecode::CallGeneric(idx) => {
                let func_inst = &module.function_instantiations[idx.0 as usize];
                let func_handle = &module.function_handles[func_inst.handle.0 as usize];
                let returns = &module.signatures[func_handle.return_.0 as usize];
                returns.0.clone()
            }
            _ => vec![]
        }
    }

    fn handle_dynamic_field_ops(&self, name: &str, args: &[TaintState], issues: &mut Vec<SecurityIssue>, module: &CompiledModule, caller_name: &str, pc: usize, is_authorized: bool) {
        // Args are popped in reverse order: [Value??, Key, UID] -> Stack pops Value, then Key, then UID.
        // Stack push: UID, Name, Value.
        // Stack pop: Value, Name, UID.
        // my `args_states` vector pushed items as they were popped. 
        // So args_states[0] = Value, args[1] = Name, args[2] = UID.
        
        let op_type = if name.contains("::add") { "add" } 
                 else if name.contains("::remove") { "remove" }
                 else if name.contains("::borrow") { "borrow" }
                 else { return }; // exists, etc.

        // Check Key Taint (Arg 1)
        if args.len() >= 2 {
            if let TaintState::Tainted(src) = &args[1] {
                // Tainted Key
                let (severity, title, desc, id) = match op_type {
                    "add" => (
                        Severity::Medium, 
                        "Dynamic Field Key Control", 
                        "User can create dynamic fields with arbitrary keys. Risk of collision or storage bloat.",
                        "TAINT-002"
                    ),
                    "remove" => (
                        if is_authorized { Severity::Low } else { Severity::Critical },
                        "Arbitrary Dynamic Field Removal",
                        "User can remove arbitrary dynamic fields. This is a critical griefing or consistency attack vector.",
                        "TAINT-003"
                    ),
                    "borrow" => (
                         Severity::Low,
                         "Arbitrary Dynamic Field Access",
                         "User can read arbitrary dynamic fields. Ensure returned data is not trusted blindly.",
                         "TAINT-004"
                    ),
                    _ => (Severity::Low, "Dynamic Field Op", "Tainted key usage", "TAINT-DF")
                };
                
                issues.push(SecurityIssue {
                    id: id.to_string(),
                    severity,
                    confidence: if is_authorized { Confidence::Medium } else { Confidence::High },
                    title: title.to_string(),
                    description: format!("{} (Source: {}). Auth: {}", desc, src, is_authorized),
                    location: CodeLocation {
                        module_id: module.self_id().to_string(),
                        module_name: module.self_id().name().to_string(),
                        function_name: caller_name.to_string(),
                        instruction_index: pc as u16,
                        byte_offset: 0,
                        line: None,
                        column: None,
                    },
                    source_code: Some(name.to_string()),
                    recommendation: "Validate dynamic field keys, use derived keys, or ensure proper authorization.".to_string(),
                    references: vec!["Sui Dynamic Field Security".to_string()],
                    metadata: HashMap::new(),
                });
            }
        }
    }

    fn resolve_function_name(&self, instr: &Bytecode, module: &CompiledModule) -> Option<String> {
        match instr {
            Bytecode::Call(idx) => {
                let func_handle = &module.function_handles[idx.0 as usize];
                let mod_handle = &module.module_handles[func_handle.module.0 as usize];
                let mod_name = module.identifier_at(mod_handle.name).as_str();
                let func_name = module.identifier_at(func_handle.name).as_str();
                Some(format!("{}::{}", mod_name, func_name))
            }
            Bytecode::CallGeneric(idx) => {
                let func_inst = &module.function_instantiations[idx.0 as usize];
                let func_handle = &module.function_handles[func_inst.handle.0 as usize];
                let mod_handle = &module.module_handles[func_handle.module.0 as usize];
                let mod_name = module.identifier_at(mod_handle.name).as_str();
                let func_name = module.identifier_at(func_handle.name).as_str();
                Some(format!("{}::{}", mod_name, func_name))
            }
            _ => None
        }
    }

    fn is_sanitizer(&self, name: &str) -> bool {
        let sanitizers = [
            "has_access", 
            "check_owner", 
            "assert_owner", 
            "validate", 
            "verify",
            "kiosk_extension::is_installed", 
            "tx_context::sender"
        ];
        sanitizers.iter().any(|s| name.contains(s))
    }

    fn is_sink(&self, name: &str) -> bool {
        self.sinks.iter().any(|sink| name.contains(sink))
    }

    fn get_arg_count(&self, instr: &Bytecode, module: &CompiledModule) -> usize {
        self.get_sig_counts(instr, module).0
    }

    fn get_sig_counts(&self, instr: &Bytecode, module: &CompiledModule) -> (usize, usize) {
        match instr {
            Bytecode::Call(idx) => {
                let func_handle = &module.function_handles[idx.0 as usize];
                let params = &module.signatures[func_handle.parameters.0 as usize];
                let returns = &module.signatures[func_handle.return_.0 as usize];
                (params.0.len(), returns.0.len())
            }
            Bytecode::CallGeneric(idx) => {
                let func_inst = &module.function_instantiations[idx.0 as usize];
                let func_handle = &module.function_handles[func_inst.handle.0 as usize];
                let params = &module.signatures[func_handle.parameters.0 as usize];
                let returns = &module.signatures[func_handle.return_.0 as usize];
                (params.0.len(), returns.0.len())
            }
            _ => (0, 0)
        }
    }

    fn get_struct_name(&self, type_token: &move_binary_format::file_format::SignatureToken, module: &CompiledModule) -> Option<String> {
        use move_binary_format::file_format::SignatureToken;
        match type_token {
            SignatureToken::Struct(idx) => {
                let struct_handle = &module.struct_handles[idx.0 as usize];
                let name = module.identifier_at(struct_handle.name).as_str();
                Some(name.to_string())
            },
            SignatureToken::StructInstantiation(idx, _) => {
                let struct_handle = &module.struct_handles[idx.0 as usize];
                let name = module.identifier_at(struct_handle.name).as_str();
                Some(name.to_string())
            },
            SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) => {
                self.get_struct_name(inner, module)
            },
             _ => None
        }
    }

    fn get_pack_counts(&self, _instr: &Bytecode, module: &CompiledModule, idx_opt: Option<move_binary_format::file_format::StructDefinitionIndex>) -> (usize, usize) {
        if let Some(idx) = idx_opt {
             let struct_def = &module.struct_defs[idx.0 as usize];
             let field_count = match &struct_def.field_information {
                 move_binary_format::file_format::StructFieldInformation::Declared(fields) => fields.len(),
                 _ => 0
             };
             (field_count, 1)
        } else {
            (0, 0)
        }
    }
}
