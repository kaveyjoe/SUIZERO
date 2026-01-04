// Extended Reentrancy Security Detectors
// Ported from addmores/reentrancy.rs to SecurityDetector API

use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, Visibility},
};

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

// ========== 1. SINGLE FUNCTION REENTRANCY ==========
pub struct SingleFunctionReentrancyDetector;

#[async_trait::async_trait]
impl SecurityDetector for SingleFunctionReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-001" }
    fn name(&self) -> &'static str { "Single Function Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy within a single function" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Check for state writes followed by external calls
                for i in 0..code.code.len() {
                    if matches!(code.code[i], Bytecode::WriteRef | Bytecode::MoveTo(_)) {
                        // Look ahead for external calls
                        let has_external_call = code.code.iter()
                            .skip(i + 1)
                            .take(20)
                            .any(|instr| crate::utils::is_external_call(instr, &ctx.module));
                        
                        // Check if state is read again after call
                        let reads_after = code.code.iter()
                            .skip(i + 1)
                            .any(|instr| matches!(instr, Bytecode::ReadRef | Bytecode::MoveFrom(_)));
                        
                        if has_external_call && reads_after {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::High,
                                title: "Potential reentrancy vulnerability".to_string(),
                                description: "State write followed by external call, then state read".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Follow checks-effects-interactions pattern. Update state before external calls.".to_string(),
                                references: vec!["CWE-841: Improper Enforcement of Behavioral Workflow".to_string()],
                                metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 2. CROSS FUNCTION REENTRANCY ==========
pub struct CrossFunctionReentrancyDetector;

#[async_trait::async_trait]
impl SecurityDetector for CrossFunctionReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-002" }
    fn name(&self) -> &'static str { "Cross Function Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy across different functions" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Track functions that modify shared state
        let mut state_modifiers = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let modifies_state = code.code.iter().any(|i| {
                    matches!(i, Bytecode::MoveTo(_) | Bytecode::MutBorrowGlobal(_) | Bytecode::WriteRef)
                });
                
                let has_external_call = code.code.iter().any(|i| {
                    crate::utils::is_external_call(i, &ctx.module)
                });
                
                if modifies_state && has_external_call {
                    state_modifiers.push(idx);
                }
            }
        }
        
        // If multiple functions modify state and make external calls
        if state_modifiers.len() > 1 {
            for idx in state_modifiers {
                issues.push(SecurityIssue {
                    id: self.id().to_string(),
                    severity: self.default_severity(),
                    confidence: Confidence::Medium,
                    title: "Potential cross-function reentrancy".to_string(),
                    description: "Multiple functions modify shared state and make external calls".to_string(),
                    location: create_loc(ctx, idx, 0),
                    source_code: None,
                    recommendation: "Implement reentrancy guard. Use mutex pattern for shared state.".to_string(),
                    references: vec![],
                    metadata: std::collections::HashMap::new(),
                });
            }
        }
        
        issues
    }
}

// ========== 3. CROSS MODULE REENTRANCY ==========
pub struct CrossModuleReentrancyDetector;

#[async_trait::async_trait]
impl SecurityDetector for CrossModuleReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-003" }
    fn name(&self) -> &'static str { "Cross Module Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy across module boundaries" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if func_def.visibility == Visibility::Public || func_def.is_entry {
                if let Some(code) = &func_def.code {
                    // Public functions that modify global state
                    let modifies_global = code.code.iter().any(|i| {
                        matches!(i, Bytecode::MoveTo(_) | Bytecode::MutBorrowGlobal(_))
                    });
                    
                    // And make external calls
                    let has_call = code.code.iter().any(|i| {
                        crate::utils::is_external_call(i, &ctx.module)
                    });
                    
                    if modifies_global && has_call {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Medium,
                            title: "Cross-module reentrancy risk".to_string(),
                            description: "Public function modifies global state and makes calls".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: None,
                            recommendation: "Add reentrancy guards for public functions. Minimize cross-module calls.".to_string(),
                            references: vec![],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 4-20: Remaining Reentrancy Detectors ==========

pub struct SharedObjectReentrancyDetector;
#[async_trait::async_trait]
impl SecurityDetector for SharedObjectReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-004" }
    fn name(&self) -> &'static str { "Shared Object Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy on shared objects" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let mut_shared = code.code.iter().enumerate().find(|(_, i)| {
                    matches!(i, Bytecode::MutBorrowGlobal(_))
                });
                
                if let Some((pos, _)) = mut_shared {
                    let has_call_after = code.code.iter().skip(pos + 1).any(|i| {
                        crate::utils::is_external_call(i, &ctx.module)
                    });
                    
                    if has_call_after {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: "Shared object reentrancy risk".to_string(),
                            description: "Mutable borrow of shared object before external call".to_string(),
                            location: create_loc(ctx, idx, pos as u16), source_code: None,
                            recommendation: "Complete shared object operations before external calls.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct ReadonlyReentrancyDetector;
#[async_trait::async_trait]
impl SecurityDetector for ReadonlyReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-005" }
    fn name(&self) -> &'static str { "Readonly Reentrancy" }
    fn description(&self) -> &'static str { "Detects read-only reentrancy vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for patterns where values are read, external call made, then decision based on read value
                for i in 0..code.code.len().saturating_sub(10) {
                    if matches!(code.code[i], Bytecode::ImmBorrowGlobal(_) | Bytecode::ReadRef) {
                        let has_call = code.code[i+1..i+10].iter().any(|b| matches!(b, Bytecode::Call(_)));
                        let has_decision = code.code[i+1..i+10].iter().any(|b| {
                            matches!(b, Bytecode::BrTrue(_) | Bytecode::BrFalse(_))
                        });
                        
                        if has_call && has_decision {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "Read-only reentrancy pattern".to_string(),
                                description: "Decision based on stale read value after external call".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Re-read state after external calls before making decisions.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

pub struct ViewFunctionReentrancyDetector;
#[async_trait::async_trait]
impl SecurityDetector for ViewFunctionReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-006" }
    fn name(&self) -> &'static str { "View Function Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy in view/read functions" }
    fn default_severity(&self) -> Severity { Severity::Low }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().starts_with("get_") || func_name.as_str().starts_with("view_") {
                if let Some(code) = &func_def.code {
                    let has_external_call = code.code.iter().any(|i| matches!(i, Bytecode::Call(_)));
                    
                    if has_external_call {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "View function makes external calls".to_string(),
                            description: format!("View function '{}' contains external calls", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "View functions should be pure. Avoid external calls in getters.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct EventBasedReentrancyDetector;
#[async_trait::async_trait]
impl SecurityDetector for EventBasedReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-007" }
    fn name(&self) -> &'static str { "Event-Based Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy through event emissions" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Events in Move might be represented as struct packing and calls
                let event_like_pattern = code.code.windows(3).enumerate().any(|(_, window)| {
                    matches!(window[0], Bytecode::Pack(_)) &&
                    window[1..3].iter().any(|b| matches!(b, Bytecode::Call(_)))
                });
                
                let modifies_state = code.code.iter().any(|i| matches!(i, Bytecode::WriteRef));
                
                if event_like_pattern && modifies_state {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Event emission with state changes".to_string(),
                        description: "State modifications around event-like patterns".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Emit events after all state changes complete.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct CallbackReentrancyDetector;
#[async_trait::async_trait]
impl SecurityDetector for CallbackReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-008" }
    fn name(&self) -> &'static str { "Callback Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy through callbacks" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("callback") || func_name.as_str().contains("hook") {
                if let Some(code) = &func_def.code {
                    let modifies_state = code.code.iter().any(|i| {
                        matches!(i, Bytecode::WriteRef | Bytecode::MoveTo(_))
                    });
                    
                    if modifies_state {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Callback modifies state".to_string(),
                            description: format!("Callback '{}' can be exploited via reentrancy", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Protect callbacks with reentrancy guards. Validate caller.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct DelegateCallReentrancyDetector;
#[async_trait::async_trait]
impl SecurityDetector for DelegateCallReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-009" }
    fn name(&self) -> &'static str { "Delegate Call Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy through delegate patterns" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("delegate") || func_name.as_str().contains("proxy") {
                if let Some(code) = &func_def.code {
                    let has_dynamic_call = code.code.iter().any(|i| matches!(i, Bytecode::CallGeneric(_)));
                    
                    if has_dynamic_call {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Delegate call with reentrancy risk".to_string(),
                            description: "Dynamic calls in delegate pattern may allow reentrancy".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Validate delegate targets. Implement reentrancy protection.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct StateCorruptionReentrancyDetector;
#[async_trait::async_trait]
impl SecurityDetector for StateCorruptionReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-010" }
    fn name(&self) -> &'static str { "State Corruption Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy causing state corruption" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for inconsistent state updates
                let write_refs = code.code.iter().enumerate().filter(|(_, i)| {
                    matches!(i, Bytecode::WriteRef)
                }).count();
                
                let has_calls = code.code.iter().any(|i| matches!(i, Bytecode::Call(_)));
                
                if write_refs > 2 && has_calls {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                        title: "Multiple state writes with external calls".to_string(),
                        description: format!("{} state writes may lead to corruption via reentrancy", write_refs),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Atomic state updates. Complete all writes before external calls.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct GasLimitReentrancyDetector;
#[async_trait::async_trait]
impl SecurityDetector for GasLimitReentrancyDetector {
    fn id(&self) -> &'static str { "REEN-011" }
    fn name(&self) -> &'static str { "Gas Limit Reentrancy" }
    fn description(&self) -> &'static str { "Detects reentrancy exploiting gas limits" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Loops with external calls are risky
                let has_loop = code.code.iter().any(|i| matches!(i, Bytecode::BrTrue(_) | Bytecode::BrFalse(_)));
                let has_call = code.code.iter().any(|i| matches!(i, Bytecode::Call(_)));
                
                if has_loop && has_call {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Loop with external calls".to_string(),
                        description: "Unbounded loop with calls may hit gas limits".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Limit loop iterations. Avoid calls in loops.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct FrontRunningDetector;
#[async_trait::async_trait]
impl SecurityDetector for FrontRunningDetector {
    fn id(&self) -> &'static str { "REEN-012" }
    fn name(&self) -> &'static str { "Front-Running Vulnerability" }
    fn description(&self) -> &'static str { "Detects front-running vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_def.is_entry && (func_name.as_str().contains("buy") || 
                                     func_name.as_str().contains("sell") ||
                                     func_name.as_str().contains("swap")) {
                if let Some(code) = &func_def.code {
                    let has_price_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Lt | Bytecode::Le | Bytecode::Gt | Bytecode::Ge)
                    });
                    
                    if !has_price_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Front-running risk in trading function".to_string(),
                            description: format!("'{}' lacks slippage protection", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Add slippage limits. Use deadline parameters. Implement commit-reveal.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct BackRunningDetector;
#[async_trait::async_trait]
impl SecurityDetector for BackRunningDetector {
    fn id(&self) -> &'static str { "REEN-013" }
    fn name(&self) -> &'static str { "Back-Running Vulnerability" }
    fn description(&self) -> &'static str { "Detects back-running attack vectors" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("claim") || func_name.as_str().contains("withdraw") {
                if let Some(code) = &func_def.code {
                    let has_timestamp = code.code.iter().any(|i| matches!(i, Bytecode::Lt | Bytecode::Ge));
                    
                    if !has_timestamp {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Back-running risk".to_string(),
                            description: "Claim/withdraw without timing protection".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Add timing constraints. Implement cooldown periods.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct SandwichAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for SandwichAttackDetector {
    fn id(&self) -> &'static str { "REEN-014" }
    fn name(&self) -> &'static str { "Sandwich Attack Vulnerability" }
    fn description(&self) -> &'static str { "Detects sandwich attack vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("swap") || func_name.as_str().contains("trade") {
                if let Some(code) = &func_def.code {
                    let has_slippage = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Ge | Bytecode::Le)
                    });
                    
                    if !has_slippage {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: "Sandwich attack vulnerability".to_string(),
                            description: format!("'{}' vulnerable to sandwich attacks", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Implement minimum output amount. Add maximum slippage parameter.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct MEVExtractionDetector;
#[async_trait::async_trait]
impl SecurityDetector for MEVExtractionDetector {
    fn id(&self) -> &'static str { "REEN-015" }
    fn name(&self) -> &'static str { "MEV Extraction Risk" }
    fn description(&self) -> &'static str { "Detects MEV extraction opportunities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check for arbitrage-vulnerable patterns
        let has_price_oracle = ctx.module.function_defs.iter().any(|f| {
            let handle = &ctx.module.function_handles[f.function.0 as usize];
            let name = ctx.module.identifier_at(handle.name);
            name.as_str().contains("price") || name.as_str().contains("oracle")
        });
        
        let has_swap = ctx.module.function_defs.iter().any(|f| {
            let handle = &ctx.module.function_handles[f.function.0 as usize];
            let name = ctx.module.identifier_at(handle.name);
            name.as_str().contains("swap")
        });
        
        if has_price_oracle && has_swap {
            issues.push(SecurityIssue {
                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                title: "MEV extraction opportunity".to_string(),
                description: "Price oracle and swap functions may enable MEV".to_string(),
                location: CodeLocation {
                    module_id: ctx.module_id.to_string(),
                    module_name: ctx.module.self_id().name().to_string(),
                    function_name: "module".to_string(),
                    instruction_index: 0, byte_offset: 0, line: None, column: None,
                },
                source_code: None,
                recommendation: "Use TWAP oracles. Implement MEV protection mechanisms.".to_string(),
                references: vec![], metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}

pub struct TransactionOrderingDetector;
#[async_trait::async_trait]
impl SecurityDetector for TransactionOrderingDetector {
    fn id(&self) -> &'static str { "REEN-016" }
    fn name(&self) -> &'static str { "Transaction Ordering Dependency" }
    fn description(&self) -> &'static str { "Detects transaction ordering dependencies" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Functions that read and write global state
                let reads_global = code.code.iter().any(|i| matches!(i, Bytecode::ImmBorrowGlobal(_)));
                let writes_global = code.code.iter().any(|i| matches!(i, Bytecode::MoveTo(_)));
                
                if reads_global && writes_global {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Transaction ordering dependency".to_string(),
                        description: "Function behavior depends on global state order".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Make operations atomic. Avoid race conditions.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct DependencyReorderingDetector;
#[async_trait::async_trait]
impl SecurityDetector for DependencyReorderingDetector {
    fn id(&self) -> &'static str { "REEN-017" }
    fn name(&self) -> &'static str { "Dependency Reordering" }
    fn description(&self) -> &'static str { "Detects reorderable dependency issues" }
    fn default_severity(&self) -> Severity { Severity::Low }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Multiple external calls without ordering protection
                let call_count = code.code.iter().filter(|i| matches!(i, Bytecode::Call(_))).count();
                
                if call_count > 2 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Multiple external calls".to_string(),
                        description: format!("{} external calls may have ordering issues", call_count),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Ensure call order independence or add explicit ordering.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct StateRaceConditionDetector;
#[async_trait::async_trait]
impl SecurityDetector for StateRaceConditionDetector {
    fn id(&self) -> &'static str { "REEN-018" }
    fn name(&self) -> &'static str { "State Race Condition" }
    fn description(&self) -> &'static str { "Detects state race conditions" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Check-then-act pattern
                for i in 0..code.code.len().saturating_sub(5) {
                    if matches!(code.code[i], Bytecode::ImmBorrowGlobal(_) | Bytecode::ReadRef) {
                        let has_check = code.code[i+1..i+3].iter().any(|b| {
                            matches!(b, Bytecode::BrTrue(_) | Bytecode::BrFalse(_))
                        });
                        let has_write = code.code[i+1..i+5].iter().any(|b| {
                            matches!(b, Bytecode::WriteRef | Bytecode::MoveTo(_))
                        });
                        
                        if has_check && has_write {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                                title: "State race condition - TOCTOU".to_string(),
                                description: "Time-of-check to time-of-use gap".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Use atomic check-and-set operations.".to_string(),
                                references: vec!["CWE-367: Time-of-check Time-of-use Race Condition".to_string()],
                                metadata: std::collections::HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        issues
    }
}

pub struct ConcurrentModificationDetector;
#[async_trait::async_trait]
impl SecurityDetector for ConcurrentModificationDetector {
    fn id(&self) -> &'static str { "REEN-019" }
    fn name(&self) -> &'static str { "Concurrent Modification" }
    fn description(&self) -> &'static str { "Detects concurrent modification issues" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Track shared objects modified across multiple functions
        let mut global_writers = 0;
        
        for func_def in &ctx.module.function_defs {
            if func_def.visibility == Visibility::Public || func_def.is_entry {
                if let Some(code) = &func_def.code {
                    if code.code.iter().any(|i| matches!(i, Bytecode::MutBorrowGlobal(_))) {
                        global_writers += 1;
                    }
                }
            }
        }
        
        if global_writers > 2 {
            issues.push(SecurityIssue {
                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                title: "Multiple concurrent writers".to_string(),
                description: format!("{} public functions modify shared state", global_writers),
                location: CodeLocation {
                    module_id: ctx.module_id.to_string(),
                    module_name: ctx.module.self_id().name().to_string(),
                    function_name: "module".to_string(),
                    instruction_index: 0, byte_offset: 0, line: None, column: None,
                },
                source_code: None,
                recommendation: "Implement locking mechanism. Ensure state consistency.".to_string(),
                references: vec![], metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}

pub struct AtomicityViolationDetector;
#[async_trait::async_trait]
impl SecurityDetector for AtomicityViolationDetector {
    fn id(&self) -> &'static str { "REEN-020" }
    fn name(&self) -> &'static str { "Atomicity Violation" }
    fn description(&self) -> &'static str { "Detects atomicity violations" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Multiple state modifications separated by external calls
                let mut state_write_positions = Vec::new();
                let mut call_positions = Vec::new();
                
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::WriteRef | Bytecode::MoveTo(_)) {
                        state_write_positions.push(i);
                    }
                    if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                        if crate::utils::is_external_call(instr, &ctx.module) {
                            call_positions.push(i);
                        }
                    }
                }
                
                // Check if calls are between writes
                for call_pos in &call_positions {
                    let writes_before = state_write_positions.iter().filter(|&&w| w < *call_pos).count();
                    let writes_after = state_write_positions.iter().filter(|&&w| w > *call_pos).count();
                    
                    if writes_before > 0 && writes_after > 0 {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: "Atomicity violation".to_string(),
                            description: "State writes separated by external call - not atomic".to_string(),
                            location: create_loc(ctx, idx, *call_pos as u16), source_code: None,
                            recommendation: "Complete all state updates before external calls. Ensure atomicity.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                        break;
                    }
                }
            }
        }
        issues
    }
}
