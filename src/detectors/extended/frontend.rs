// Extended Frontend Security Detectors
// Ported from addmores/frontend.rs to SecurityDetector API

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

// ========== 1. ABI ENCODING ATTACK ==========
pub struct ABIEncodingAttackDetector;

#[async_trait::async_trait]
impl SecurityDetector for ABIEncodingAttackDetector {
    fn id(&self) -> &'static str { "FRONT-001" }
    fn name(&self) -> &'static str { "ABI Encoding Attack" }
    fn description(&self) -> &'static str { "Detects ABI encoding vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Look for pack/unpack operations without size validation
                for (i, instr) in code.code.iter().enumerate() {
                    if matches!(instr, Bytecode::VecPack(_, _) | Bytecode::VecUnpack(_, _)) {
                        let has_size_check = code.code.iter()
                            .skip(i.saturating_sub(3))
                            .take(6)
                            .any(|b| matches!(b, Bytecode::VecLen(_) | Bytecode::Lt));
                        
                        if !has_size_check {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: self.default_severity(),
                                confidence: Confidence::Medium,
                                title: "Unchecked encoding/decoding".to_string(),
                                description: "Pack/unpack without size validation".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: None,
                                recommendation: "Validate data sizes before encoding/decoding. Use safe deserialization.".to_string(),
                                references: vec!["CWE-502: Deserialization of Untrusted Data".to_string()],
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

// ========== 2. CALLDATA MANIPULATION ==========
pub struct CalldataManipulationDetector;

#[async_trait::async_trait]
impl SecurityDetector for CalldataManipulationDetector {
    fn id(&self) -> &'static str { "FRONT-002" }
    fn name(&self) -> &'static str { "Calldata Manipulation" }
    fn description(&self) -> &'static str { "Detects calldata manipulation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if func_def.is_entry {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let signature = &ctx.module.signatures[func_handle.parameters.0 as usize];
                let param_count = signature.0.len();
                
                if let Some(code) = &func_def.code {
                    // Entry functions should validate all input parameters
                    let has_validation = code.code.iter().take(20).any(|i| {
                        matches!(i, Bytecode::Abort | Bytecode::BrFalse(_))
                    });
                    
                    if param_count > 2 && !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::Medium,
                            title: "Unvalidated entry function parameters".to_string(),
                            description: format!("Entry function with {} parameters lacks input validation", param_count),
                            location: create_loc(ctx, idx, 0),
                            source_code: None,
                            recommendation: "Validate all entry function parameters. Check bounds and ranges.".to_string(),
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

// ========== 3-20: Remaining Frontend Detectors ==========

pub struct EventLoggingAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for EventLoggingAttackDetector {
    fn id(&self) -> &'static str { "FRONT-003" }
    fn name(&self) -> &'static str { "Event Logging Attack" }
    fn description(&self) -> &'static str { "Detects event logging vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("emit") || func_name.as_str().contains("event") {
                if let Some(code) = &func_def.code {
                    // Events emitted before state changes (incorrect order)
                    let pack_pos = code.code.iter().position(|i| matches!(i, Bytecode::Pack(_)));
                    let write_pos = code.code.iter().position(|i| matches!(i, Bytecode::WriteRef));
                    
                    if let (Some(p), Some(w)) = (pack_pos, write_pos) {
                        if p < w {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "Event emitted before state change".to_string(),
                                description: "Events should be emitted after state updates".to_string(),
                                location: create_loc(ctx, idx, p as u16), source_code: None,
                                recommendation: "Emit events after all state changes complete.".to_string(),
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

pub struct ReturnDataExploitDetector;
#[async_trait::async_trait]
impl SecurityDetector for ReturnDataExploitDetector {
    fn id(&self) -> &'static str { "FRONT-004" }
    fn name(&self) -> &'static str { "Return Data Exploit" }
    fn description(&self) -> &'static str { "Detects return data exploitation" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if func_def.visibility == Visibility::Public {
                if let Some(code) = &func_def.code {
                    // Public functions returning sensitive data
                    let returns_value = code.code.iter().rev().take(5).any(|i| {
                        matches!(i, Bytecode::Ret)
                    });
                    
                    let accesses_global = code.code.iter().any(|i| {
                        matches!(i, Bytecode::ImmBorrowGlobal(_))
                    });
                    
                    if returns_value && accesses_global {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Public function returns global state".to_string(),
                            description: "May expose sensitive data".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Sanitize return values. Don't expose internal state directly.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct ErrorHandlingAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ErrorHandlingAttackDetector {
    fn id(&self) -> &'static str { "FRONT-005" }
    fn name(&self) -> &'static str { "Error Handling Attack" }
    fn description(&self) -> &'static str { "Detects error handling vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Functions with external calls but no error handling
                let has_call = code.code.iter().any(|i| matches!(i, Bytecode::Call(_)));
                let has_abort = code.code.iter().any(|i| matches!(i, Bytecode::Abort));
                
                if has_call && !has_abort {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Missing error handling".to_string(),
                        description: "External calls without error handling".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Add proper error handling. Validate call results.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct RevertExploitationDetector;
#[async_trait::async_trait]
impl SecurityDetector for RevertExploitationDetector {
    fn id(&self) -> &'static str { "FRONT-006" }
    fn name(&self) -> &'static str { "Revert Exploitation" }
    fn description(&self) -> &'static str { "Detects revert exploitation patterns" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // State changes before abort
                for i in 0..code.code.len() {
                    if matches!(code.code[i], Bytecode::Abort) {
                        let prior_writes = code.code.iter().take(i).filter(|b| {
                            matches!(b, Bytecode::WriteRef | Bytecode::MoveTo(_))
                        }).count();
                        
                        if prior_writes > 0 {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "State modified before abort".to_string(),
                                description: format!("{} state changes before abort", prior_writes),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Validate before state changes. Use checks-effects pattern.".to_string(),
                                references: vec![], metadata: std::collections::HashMap::new(),
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

pub struct AssertManipulationDetector;
#[async_trait::async_trait]
impl SecurityDetector for AssertManipulationDetector {
    fn id(&self) -> &'static str { "FRONT-007" }
    fn name(&self) -> &'static str { "Assert Manipulation" }
    fn description(&self) -> &'static str { "Detects assert manipulation risks" }
    fn default_severity(&self) -> Severity { Severity::Low }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("assert") {
                if let Some(code) = &func_def.code {
                    let has_complex_logic = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::And | Bytecode::Or | Bytecode::Not)
                    }).count() > 2;
                    
                    if has_complex_logic {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Complex assertion logic".to_string(),
                            description: "Complex boolean logic in assertions may have bugs".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Simplify assertion logic. Test edge cases.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct AbortExploitationDetector;
#[async_trait::async_trait]
impl SecurityDetector for AbortExploitationDetector {
    fn id(&self) -> &'static str { "FRONT-008" }
    fn name(&self) -> &'static str { "Abort Exploitation" }
    fn description(&self) -> &'static str { "Detects abort code exploitation" }
    fn default_severity(&self) -> Severity { Severity::Low }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                let abort_count = code.code.iter().filter(|i| matches!(i, Bytecode::Abort)).count();
                
                if abort_count > 5 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Many abort statements".to_string(),
                        description: format!("{} abort statements may indicate poor error handling", abort_count),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Consolidate error handling. Use structured error codes.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct ConditionalRevertAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ConditionalRevertAttackDetector {
    fn id(&self) -> &'static str { "FRONT-009" }
    fn name(&self) -> &'static str { "Conditional Revert Attack" }
    fn description(&self) -> &'static str { "Detects exploitable conditional reverts" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Branch followed by abort
                for i in 0..code.code.len().saturating_sub(2) {
                    if matches!(code.code[i], Bytecode::BrTrue(_) | Bytecode::BrFalse(_)) {
                        if matches!(code.code.get(i+1).or(code.code.get(i+2)), Some(Bytecode::Abort)) {
                            issues.push(SecurityIssue {
                                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                                title: "Conditional abort pattern".to_string(),
                                description: "Branch directly to abort may be exploitable".to_string(),
                                location: create_loc(ctx, idx, i as u16), source_code: None,
                                recommendation: "Review abort conditions. Ensure they can't be bypassed.".to_string(),
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

pub struct GasPriceManipulationDetector;
#[async_trait::async_trait]
impl SecurityDetector for GasPriceManipulationDetector {
    fn id(&self) -> &'static str { "FRONT-010" }
    fn name(&self) -> &'static str { "Gas Price Manipulation" }
    fn description(&self) -> &'static str { "Detects gas price manipulation risks" }
    fn default_severity(&self) -> Severity { Severity::Low }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check for gas-dependent logic
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("gas") {
                issues.push(SecurityIssue {
                    id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                    title: "Gas-dependent logic".to_string(),
                    description: format!("Function '{}' may depend on gas parameters", func_name),
                    location: create_loc(ctx, idx, 0), source_code: None,
                    recommendation: "Avoid gas-dependent logic. Use deterministic parameters.".to_string(),
                    references: vec![], metadata: std::collections::HashMap::new(),
                });
            }
        }
        
        issues
    }
}

pub struct TransactionOrderDependencyDetector;
#[async_trait::async_trait]
impl SecurityDetector for TransactionOrderDependencyDetector {
    fn id(&self) -> &'static str { "FRONT-011" }
    fn name(&self) -> &'static str { "Transaction Order Dependency" }
    fn description(&self) -> &'static str { "Detects transaction ordering issues" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if func_def.is_entry {
                if let Some(code) = &func_def.code {
                    // Entry that reads then writes same resource
                    let reads_global = code.code.iter().any(|i| matches!(i, Bytecode::ImmBorrowGlobal(_)));
                    let writes_global = code.code.iter().any(|i| matches!(i, Bytecode::MoveTo(_)));
                    
                    if reads_global && writes_global {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Read-modify-write on global state".to_string(),
                            description: "Entry function vulnerable to transaction ordering".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Use atomic operations. Implement optimistic locking.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct BlockGasLimitAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for BlockGasLimitAttackDetector {
    fn id(&self) -> &'static str { "FRONT-012" }
    fn name(&self) -> &'static str { "Block Gas Limit Attack" }
    fn description(&self) -> &'static str { "Detects block gas limit DoS" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Unbounded loops
                let has_loop = code.code.iter().any(|i| matches!(i, Bytecode::BrTrue(_)));
                let has_bound = code.code.iter().any(|i| matches!(i, Bytecode::Lt | Bytecode::Le));
                
                if has_loop && !has_bound {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                        title: "Unbounded loop may hit gas limit".to_string(),
                        description: "Loop without clear upper bound".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Add maximum iteration limits. Paginate large operations.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct MempoolSnoopingDetector;
#[async_trait::async_trait]
impl SecurityDetector for MempoolSnoopingDetector {
    fn id(&self) -> &'static str { "FRONT-013" }
    fn name(&self) -> &'static str { "Mempool Snooping" }
    fn description(&self) -> &'static str { "Detects mempool front-running risks" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Public functions with valuable operations
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if func_def.visibility == Visibility::Public || func_def.is_entry {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                
                if func_name.as_str().contains("buy") || func_name.as_str().contains("claim") {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Public valuable operation".to_string(),
                        description: format!("'{}' may be front-runnable", func_name),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Use commit-reveal. Add transaction batching. Implement FCFS queue.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

pub struct NetworkPartitionAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for NetworkPartitionAttackDetector {
    fn id(&self) -> &'static str { "FRONT-014" }
    fn name(&self) -> &'static str { "Network Partition Attack" }
    fn description(&self) -> &'static str { "Detects network partition vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Low }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Functions requiring external data
        let external_dependencies = ctx.module.function_defs.iter().filter(|f| {
            if let Some(code) = &f.code {
                code.code.iter().any(|i| matches!(i, Bytecode::ImmBorrowGlobal(_) | Bytecode::Call(_)))
            } else {
                false
            }
        }).count();
        
        if external_dependencies > 10 {
            issues.push(SecurityIssue {
                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                title: "High external dependency".to_string(),
                description: format!("{} functions depend on external data", external_dependencies),
                location: CodeLocation {
                    module_id: ctx.module_id.to_string(),
                    module_name: ctx.module.self_id().name().to_string(),
                    function_name: "module".to_string(),
                    instruction_index: 0, byte_offset: 0, line: None, column: None,
                },
                source_code: None,
                recommendation: "Reduce external dependencies. Implement fallback mechanisms.".to_string(),
                references: vec![], metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}

pub struct ConsensusExploitDetector;
#[async_trait::async_trait]
impl SecurityDetector for ConsensusExploitDetector {
    fn id(&self) -> &'static str { "FRONT-015" }
    fn name(&self) -> &'static str { "Consensus Exploit" }
    fn description(&self) -> &'static str { "Detects consensus-level exploits" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        // Consensus exploits are typically at protocol level, not contract level
        vec![]
    }
}

pub struct ValidatorCollusionDetector;
#[async_trait::async_trait]
impl SecurityDetector for ValidatorCollusionDetector {
    fn id(&self) -> &'static str { "FRONT-016" }
    fn name(&self) -> &'static str { "Validator Collusion" }
    fn description(&self) -> &'static str { "Detects validator collusion risks" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Functions related to validator operations
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("validator") || func_name.as_str().contains("stake") {
                if let Some(code) = &func_def.code {
                    let has_multi_sig = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::Eq)
                    }).count() > 2;
                    
                    if !has_multi_sig {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Validator function without multi-sig".to_string(),
                            description: "Validator operations should require multiple signatures".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Implement multi-signature validation. Use threshold schemes.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

pub struct StakeSlashingAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for StakeSlashingAttackDetector {
    fn id(&self) -> &'static str { "FRONT-017" }
    fn name(&self) -> &'static str { "Stake Slashing Attack" }
    fn description(&self) -> &'static str { "Detects stake slashing vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("slash") {
                if let Some(code) = &func_def.code {
                    // Slashing without proper validation
                    let has_validation = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::BrFalse(_) | Bytecode::Abort)
                    }).count() > 2;
                    
                    if !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Slashing without adequate validation".to_string(),
                            description: "Stake slashing should have multiple checks".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Add comprehensive validation. Require governance approval. Add appeals process.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

pub struct ProtocolUpgradeAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ProtocolUpgradeAttackDetector {
    fn id(&self) -> &'static str { "FRONT-018" }
    fn name(&self) -> &'static str { "Protocol Upgrade Attack" }
    fn description(&self) -> &'static str { "Detects upgrade vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("upgrade") || func_name.as_str().contains("migrate") {
                if let Some(code) = &func_def.code {
                    let has_auth = code.code.iter().any(|i| matches!(i, Bytecode::Eq | Bytecode::Abort));
                    
                    if !has_auth {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: "Upgrade function without authorization".to_string(),
                            description: format!("'{}' lacks access control", func_name),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Require admin权限. Add timelock. Implement upgrade proposal system.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

pub struct ForkAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ForkAttackDetector {
    fn id(&self) -> &'static str { "FRONT-019" }
    fn name(&self) -> &'static str { "Fork Attack" }
    fn description(&self) -> &'static str { "Detects fork attack vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Low }
    async fn detect(&self, _ctx: &DetectionContext) -> Vec<SecurityIssue> {
        // Fork attacks are protocol-level, not detectable at contract level
        vec![]
    }
}

pub struct ChainReorgAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for ChainReorgAttackDetector {
    fn id(&self) -> &'static str { "FRONT-020" }
    fn name(&self) -> &'static str { "Chain Reorg Attack" }
    fn description(&self) -> &'static str { "Detects chain reorganization risks" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Functions that finalize important operations immediately
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("finalize") || func_name.as_str().contains("settle") {
                if let Some(code) = &func_def.code {
                    // Check for confirmation depth check
                    let has_depth_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Ge | Bytecode::Gt)
                    });
                    
                    if !has_depth_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Finalization without confirmation depth".to_string(),
                            description: "Important operations should wait for confirmations".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Wait for block confirmations. Implement finality checks.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}
