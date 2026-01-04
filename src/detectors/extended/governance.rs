// Extended Governance Security Detectors
// Ported from addmores/governance.rs to SecurityDetector API

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

// ========== 1. UPGRADE BACKDOOR ==========
pub struct UpgradeBackdoorDetector;

#[async_trait::async_trait]
impl SecurityDetector for UpgradeBackdoorDetector {
    fn id(&self) -> &'static str { "GOV-001" }
    fn name(&self) -> &'static str { "Upgrade Backdoor" }
    fn description(&self) -> &'static str { "Detects upgrade backdoor vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("upgrade") || func_name.as_str().contains("migrate") {
                if let Some(code) = &func_def.code {
                    // Check for proper authorization
                    let has_auth_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Eq | Bytecode::Neq)
                    });
                    
                    let has_timelock = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Ge | Bytecode::Gt)
                    });
                    
                    if !has_auth_check || !has_timelock {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: "Upgrade function lacks proper protections".to_string(),
                            description: format!("'{}' missing authorization or timelock", func_name),
                            location: create_loc(ctx, idx, 0),
                            source_code: None,
                            recommendation: "Require multi-sig + timelock for upgrades. Emit upgrade events.".to_string(),
                            references: vec!["CWE-269: Improper Privilege Management".to_string()],
                            metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// ========== 2-20: Remaining Governance Detectors ==========

pub struct GovernanceTakeoverDetector;
#[async_trait::async_trait]
impl SecurityDetector for GovernanceTakeoverDetector {
    fn id(&self) -> &'static str { "GOV-002" }
    fn name(&self) -> &'static str { "Governance Takeover" }
    fn description(&self) -> &'static str { "Detects governance takeover vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("transfer") && func_name.as_str().contains("admin") {
                if let Some(code) = &func_def.code {
                    let has_multi_step = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::WriteRef | Bytecode::MoveTo(_))
                    }).count() > 1;
                    
                    if !has_multi_step {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: "Single-step admin transfer".to_string(),
                            description: "Admin transfer should be two-step (propose + accept)".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Use two-step transfer: propose and accept pattern.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct VoteManipulationDetector;
#[async_trait::async_trait]
impl SecurityDetector for VoteManipulationDetector {
    fn id(&self) -> &'static str { "GOV-003" }
    fn name(&self) -> &'static str { "Vote Manipulation" }
    fn description(&self) -> &'static str { "Detects vote manipulation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("vote") || func_name.as_str().contains("cast") {
                if let Some(code) = &func_def.code {
                    // Check for double voting prevention
                    let checks_voted = code.code.iter().any(|i| {
                        matches!(i, Bytecode::ImmBorrowGlobal(_))
                    });
                    
                    let prevents_double = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Abort)
                    });
                    
                    if !checks_voted || !prevents_double {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Missing double-vote prevention".to_string(),
                            description: "Vote function may allow multiple votes".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Track voter addresses. Prevent double voting.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct QuorumAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for QuorumAttackDetector {
    fn id(&self) -> &'static str { "GOV-004" }
    fn name(&self) -> &'static str { "Quorum Attack" }
    fn description(&self) -> &'static str { "Detects quorum manipulation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("quorum") || func_name.as_str().contains("threshold") {
                if let Some(code) = &func_def.code {
                    // Quorum changes should be protected
                    let has_governance = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Eq | Bytecode::Ge)
                    });
                    
                    if !has_governance {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Unprotected quorum modification".to_string(),
                            description: "Quorum can be changed without proper governance".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Quorum changes require governance vote. Add minimum/maximum bounds.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct TimelockExploitDetector;
#[async_trait::async_trait]
impl SecurityDetector for TimelockExploitDetector {
    fn id(&self) -> &'static str { "GOV-005" }
    fn name(&self) -> &'static str { "Timelock Exploit" }
    fn description(&self) -> &'static str { "Detects timelock bypass vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("execute") && func_name.as_str().contains("proposal") {
                if let Some(code) = &func_def.code {
                    // Check for timelock validation
                    let has_time_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Ge | Bytecode::Gt)
                    });
                    
                    if !has_time_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: "Missing timelock enforcement".to_string(),
                            description: "Proposal execution without timelock check".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Enforce minimum timelock delay. Validate execution time.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct ProposalSpamDetector;
#[async_trait::async_trait]
impl SecurityDetector for ProposalSpamDetector {
    fn id(&self) -> &'static str { "GOV-006" }
    fn name(&self) -> &'static str { "Proposal Spam" }
    fn description(&self) -> &'static str { "Detects proposal spam vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("propose") || func_name.as_str().contains("create_proposal") {
                if let Some(code) = &func_def.code {
                    // Check for proposal threshold/deposit
                    let has_threshold = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Ge | Bytecode::Gt)
                    });
                    
                    if !has_threshold {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "No proposal creation threshold".to_string(),
                            description: "Anyone can create proposals without stake".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Require minimum token stake. Add proposal deposit.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct DelegationAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for DelegationAttackDetector {
    fn id(&self) -> &'static str { "GOV-007" }
    fn name(&self) -> &'static str { "Delegation Attack" }
    fn description(&self) -> &'static str { "Detects vote delegation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("delegate") {
                if let Some(code) = &func_def.code {
                    // Check for circular delegation prevention
                    let has_circular_check = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::Neq | Bytecode::Eq)
                    }).count() > 1;
                    
                    if !has_circular_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "No circular delegation check".to_string(),
                            description: "May allow circular delegation".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Prevent circular delegation. Limit delegation depth.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct GovernanceTokenAbuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for GovernanceTokenAbuseDetector {
    fn id(&self) -> &'static str { "GOV-008" }
    fn name(&self) -> &'static str { "Governance Token Abuse" }
    fn description(&self) -> &'static str { "Detects governance token manipulation" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check for flash loan attacks on governance
        let has_vote_func = ctx.module.function_defs.iter().any(|f| {
            let handle = &ctx.module.function_handles[f.function.0 as usize];
            let name = ctx.module.identifier_at(handle.name);
            name.as_str().contains("vote")
        });
        
        let has_token_transfer = ctx.module.function_defs.iter().any(|f| {
            let handle = &ctx.module.function_handles[f.function.0 as usize];
            let name = ctx.module.identifier_at(handle.name);
            name.as_str().contains("transfer")
        });
        
        if has_vote_func && has_token_transfer {
            issues.push(SecurityIssue {
                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                title: "Potential flash loan governance attack".to_string(),
                description: "Governance voting with transferable tokens".to_string(),
                location: CodeLocation {
                    module_id: ctx.module_id.to_string(),
                    module_name: ctx.module.self_id().name().to_string(),
                    function_name: "module".to_string(),
                    instruction_index: 0, byte_offset: 0, line: None, column: None,
                },
                source_code: None,
                recommendation: "Use snapshot-based voting. Lock tokens during voting period.".to_string(),
                references: vec![], metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}

pub struct SnapshotManipulationDetector;
#[async_trait::async_trait]
impl SecurityDetector for SnapshotManipulationDetector {
    fn id(&self) -> &'static str { "GOV-009" }
    fn name(&self) -> &'static str { "Snapshot Manipulation" }
    fn description(&self) -> &'static str { "Detects snapshot manipulation risks" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("snapshot") {
                if let Some(code) = &func_def.code {
                    // Check for block number usage
                    let uses_block = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Sub | Bytecode::Add)
                    });
                    
                    if !uses_block {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Snapshot without block reference".to_string(),
                            description: "Snapshot should reference specific block".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Tie snapshots to block numbers. Prevent retroactive changes.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct VotingPowerExploitDetector;
#[async_trait::async_trait]
impl SecurityDetector for VotingPowerExploitDetector {
    fn id(&self) -> &'static str { "GOV-010" }
    fn name(&self) -> &'static str { "Voting Power Exploit" }
    fn description(&self) -> &'static str { "Detects voting power calculation flaws" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("voting_power") || func_name.as_str().contains("get_power") {
                if let Some(code) = &func_def.code {
                    // Check for overflow in power calculation
                    let has_overflow_check = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Abort)
                    });
                    
                    let has_mul = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Mul)
                    });
                    
                    if has_mul && !has_overflow_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Voting power overflow risk".to_string(),
                            description: "Multiplication without overflow check".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Use checked arithmetic. Cap maximum voting power.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct WeightedVotingAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for WeightedVotingAttackDetector {
    fn id(&self) -> &'static str { "GOV-011" }
    fn name(&self) -> &'static str { "Weighted Voting Attack" }
    fn description(&self) -> &'static str { "Detects weighted voting vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            if let Some(code) = &func_def.code {
                // Weighted voting with multiplication
                let mul_count = code.code.iter().filter(|i| matches!(i, Bytecode::Mul)).count();
                let div_count = code.code.iter().filter(|i| matches!(i, Bytecode::Div)).count();
                
                if mul_count > 0 && div_count == 0 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                        title: "Weight multiplication without normalization".to_string(),
                        description: "Weights multiplied but not normalized".to_string(),
                        location: create_loc(ctx, idx, 0), source_code: None,
                        recommendation: "Normalize weighted votes. Prevent weight manipulation.".to_string(),
                        references: vec![], metadata: std::collections::HashMap::new(),
                    });
                }
            }
        }
        issues
    }
}

pub struct QuadraticVotingExploitDetector;
#[async_trait::async_trait]
impl SecurityDetector for QuadraticVotingExploitDetector {
    fn id(&self) -> &'static str { "GOV-012" }
    fn name(&self) -> &'static str { "Quadratic Voting Exploit" }
    fn description(&self) -> &'static str { "Detects quadratic voting vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("quadratic") {
                if let Some(code) = &func_def.code {
                    // Check for sybil resistance
                    let has_identity_check = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::Eq | Bytecode::Neq)
                    }).count() > 2;
                    
                    if !has_identity_check {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                            title: "Quadratic voting without sybil resistance".to_string(),
                            description: "Vulnerable to sybil attacks".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Implement identity verification. Use proof of personhood.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct GovernanceDelayAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for GovernanceDelayAttackDetector {
    fn id(&self) -> &'static str { "GOV-013" }
    fn name(&self) -> &'static str { "Governance Delay Attack" }
    fn description(&self) -> &'static str { "Detects governance delay manipulation" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("set_delay") || func_name.as_str().contains("update_delay") {
                if let Some(code) = &func_def.code {
                    // Delay changes should have bounds
                    let has_bounds = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::Le | Bytecode::Ge)
                    }).count() >= 2;
                    
                    if !has_bounds {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Unbounded delay modification".to_string(),
                            description: "Delay can be set to extreme values".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Set minimum and maximum delay bounds.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct EmergencyPauseAbuseDetector;
#[async_trait::async_trait]
impl SecurityDetector for EmergencyPauseAbuseDetector {
    fn id(&self) -> &'static str { "GOV-014" }
    fn name(&self) -> &'static str { "Emergency Pause Abuse" }
    fn description(&self) -> &'static str { "Detects emergency pause abuse risks" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("pause") || func_name.as_str().contains("emergency") {
                if let Some(code) = &func_def.code {
                    // Emergency functions should have strict auth
                    let auth_checks = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::Eq | Bytecode::Abort)
                    }).count();
                    
                    if auth_checks < 2 {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::High,
                            title: "Weak emergency pause authorization".to_string(),
                            description: "Emergency pause with insufficient checks".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Require multi-sig for pause. Add automatic unpause timer.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct AdminKeyRotationFlawDetector;
#[async_trait::async_trait]
impl SecurityDetector for AdminKeyRotationFlawDetector {
    fn id(&self) -> &'static str { "GOV-015" }
    fn name(&self) -> &'static str { "Admin Key Rotation Flaw" }
    fn description(&self) -> &'static str { "Detects admin key rotation vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("rotate") && func_name.as_str().contains("key") {
                if let Some(code) = &func_def.code {
                    // Key rotation should be two-step
                    let write_count = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::WriteRef | Bytecode::MoveTo(_))
                    }).count();
                    
                    if write_count < 2 {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Single-step key rotation".to_string(),
                            description: "Key rotation should be two-step process".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Use propose-accept pattern. Add timelock. Emit events.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct MultisigUpgradeAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for MultisigUpgradeAttackDetector {
    fn id(&self) -> &'static str { "GOV-016" }
    fn name(&self) -> &'static str { "Multisig Upgrade Attack" }
    fn description(&self) -> &'static str { "Detects multisig upgrade vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Critical }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("multisig") && func_name.as_str().contains("threshold") {
                if let Some(code) = &func_def.code {
                    // Threshold changes should be protected
                    let has_governance = code.code.iter().filter(|i| {
                        matches!(i, Bytecode::Ge)
                    }).count() > 1;
                    
                    if !has_governance {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Unprotected threshold modification".to_string(),
                            description: "Multisig threshold can be changed without protection".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Threshold changes require supermajority. Add bounds.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct ProxyPatternExploitDetector;
#[async_trait::async_trait]
impl SecurityDetector for ProxyPatternExploitDetector {
    fn id(&self) -> &'static str { "GOV-017" }
    fn name(&self) -> &'static str { "Proxy Pattern Exploit" }
    fn description(&self) -> &'static str { "Detects proxy pattern vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::High }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            
            if func_name.as_str().contains("proxy") || func_name.as_str().contains("delegatecall") {
                if let Some(code) = &func_def.code {
                    // Proxy should validate implementation
                    let has_validation = code.code.iter().any(|i| {
                        matches!(i, Bytecode::Neq | Bytecode::Abort)
                    });
                    
                    if !has_validation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Medium,
                            title: "Proxy without implementation validation".to_string(),
                            description: "Proxy doesn't validate implementation address".to_string(),
                            location: create_loc(ctx, idx, 0), source_code: None,
                            recommendation: "Validate implementation address. Add initialization checks.".to_string(),
                            references: vec![], metadata: std::collections::HashMap::new(),
                        });
                    }
                }
            }
        }
        issues
    }
}

pub struct DiamondPatternAttackDetector;
#[async_trait::async_trait]
impl SecurityDetector for DiamondPatternAttackDetector {
    fn id(&self) -> &'static str { "GOV-018" }
    fn name(&self) -> &'static str { "Diamond Pattern Attack" }
    fn description(&self) -> &'static str { "Detects diamond pattern vulnerabilities" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Diamond pattern has multiple facets
        let call_count = ctx.module.function_defs.iter().filter(|f| {
            if let Some(code) = &f.code {
                code.code.iter().any(|i| matches!(i, Bytecode::Call(_)))
            } else {
                false
            }
        }).count();
        
        if call_count > 20 {
            issues.push(SecurityIssue {
                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                title: "Complex diamond pattern".to_string(),
                description: format!("{} functions with calls - high complexity", call_count),
                location: CodeLocation {
                    module_id: ctx.module_id.to_string(),
                    module_name: ctx.module.self_id().name().to_string(),
                    function_name: "module".to_string(),
                    instruction_index: 0, byte_offset: 0, line: None, column: None,
                },
                source_code: None,
                recommendation: "Simplify architecture. Validate facet selectors. Add access control.".to_string(),
                references: vec![], metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}

pub struct ModularityExploitationDetector;
#[async_trait::async_trait]
impl SecurityDetector for ModularityExploitationDetector {
    fn id(&self) -> &'static str { "GOV-019" }
    fn name(&self) -> &'static str { "Modularity Exploitation" }
    fn description(&self) -> &'static str { "Detects modularity design flaws" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check for excessive cross-module calls
        let public_funcs = ctx.module.function_defs.iter().filter(|f| {
            f.visibility == Visibility::Public
        }).count();
        
        if public_funcs > 30 {
            issues.push(SecurityIssue {
                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                title: "Excessive public interface".to_string(),
                description: format!("{} public functions - large attack surface", public_funcs),
                location: CodeLocation {
                    module_id: ctx.module_id.to_string(),
                    module_name: ctx.module.self_id().name().to_string(),
                    function_name: "module".to_string(),
                    instruction_index: 0, byte_offset: 0, line: None, column: None,
                },
                source_code: None,
                recommendation: "Minimize public interface. Use internal functions. Apply principle of least privilege.".to_string(),
                references: vec![], metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}

pub struct InterfaceUpgradeRiskDetector;
#[async_trait::async_trait]
impl SecurityDetector for InterfaceUpgradeRiskDetector {
    fn id(&self) -> &'static str { "GOV-020" }
    fn name(&self) -> &'static str { "Interface Upgrade Risk" }
    fn description(&self) -> &'static str { "Detects interface upgrade compatibility issues" }
    fn default_severity(&self) -> Severity { Severity::Medium }
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        // Check for version tracking
        let has_version = ctx.module.function_defs.iter().any(|f| {
            let handle = &ctx.module.function_handles[f.function.0 as usize];
            let name = ctx.module.identifier_at(handle.name);
            name.as_str().contains("version")
        });
        
        let has_upgrade = ctx.module.function_defs.iter().any(|f| {
            let handle = &ctx.module.function_handles[f.function.0 as usize];
            let name = ctx.module.identifier_at(handle.name);
            name.as_str().contains("upgrade")
        });
        
        if has_upgrade && !has_version {
            issues.push(SecurityIssue {
                id: self.id().to_string(), severity: self.default_severity(), confidence: Confidence::Low,
                title: "Upgrade without version tracking".to_string(),
                description: "Module supports upgrades but lacks version checks".to_string(),
                location: CodeLocation {
                    module_id: ctx.module_id.to_string(),
                    module_name: ctx.module.self_id().name().to_string(),
                    function_name: "module".to_string(),
                    instruction_index: 0, byte_offset: 0, line: None, column: None,
                },
                source_code: None,
                recommendation: "Implement version tracking. Validate upgrade compatibility.".to_string(),
                references: vec![], metadata: std::collections::HashMap::new(),
            });
        }
        
        issues
    }
}
