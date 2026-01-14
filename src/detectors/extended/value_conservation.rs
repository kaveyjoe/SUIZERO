// Value Conservation Violation Detector
// Detects when value conservation is violated across functions

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition, SignatureToken},
};

// Helper function to create location
fn create_location(ctx: &DetectionContext, func_def: &FunctionDefinition, idx: u16) -> CodeLocation {
    let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
    let func_name = ctx.module.identifier_at(func_handle.name);
    
    CodeLocation {
        module_id: ctx.module_id.to_string(),
        module_name: ctx.module.self_id().name().to_string(),
        function_name: func_name.to_string(),
        instruction_index: idx,
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

// ========== VALUE CONSERVATION VIOLATION DETECTOR ==========
pub struct ValueConservationViolationDetector;

#[async_trait::async_trait]
impl SecurityDetector for ValueConservationViolationDetector {
    fn id(&self) -> &'static str { "SEM-004" }
    fn name(&self) -> &'static str { "Value Conservation Violation" }
    fn description(&self) -> &'static str { "Detects when value conservation is violated across functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Find functions that might manipulate value fields
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if let Some(code) = &func_def.code {
                // Check for value manipulation patterns
                let mutates_value_fields = code.code.iter().any(|instr| {
                    matches!(instr, Bytecode::WriteRef | Bytecode::Add | Bytecode::Sub | Bytecode::Mul | Bytecode::Div)
                });
                
                // Look for operations that suggest value splitting/merging
                let has_split_merge_pattern = func_name.as_str().to_lowercase().contains("split") ||
                                             func_name.as_str().to_lowercase().contains("merge") ||
                                             func_name.as_str().to_lowercase().contains("combine") ||
                                             func_name.as_str().to_lowercase().contains("divide");
                
                // Check for functions that pack new objects (possibly duplicating value)
                let creates_new_objects = code.code.iter().any(|instr| {
                    matches!(instr, Bytecode::Pack(_) | Bytecode::PackGeneric(_))
                });
                
                // Check for arithmetic operations that might cause value inflation
                let has_arithmetic_operations = code.code.iter().any(|instr| {
                    matches!(instr, Bytecode::Add | Bytecode::Sub | Bytecode::Mul | Bytecode::Div | Bytecode::BitOr | Bytecode::BitAnd | Bytecode::Xor)
                });
                
                // If function has patterns that suggest value manipulation without proper checks
                if (has_split_merge_pattern || creates_new_objects) && has_arithmetic_operations {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Potential value inflation in '{}'", func_name),
                        description: format!("Function '{}' shows patterns that could violate value conservation", func_name),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement proper value accounting. Ensure that total value remains constant across operations. Validate that splits have corresponding merges and vice versa.".to_string(),
                        references: vec![
                            "https://docs.sui.io/concepts/programming-model/objects".to_string(),
                        ],
                        metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

// Helper function to get function name from bytecode
fn get_function_name(instr: &Bytecode, module: &move_binary_format::CompiledModule) -> Option<String> {
    crate::utils::get_function_name(instr, module).map(|s| s.to_string())
}