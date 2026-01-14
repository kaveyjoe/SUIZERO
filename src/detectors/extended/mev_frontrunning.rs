use crate::core::detector::SecurityDetector;
use crate::types::{SecurityIssue, Severity, Confidence, DetectionContext, CodeLocation};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Bytecode, FunctionDefinition},
};
use std::collections::HashMap;

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

// MEV-001: Front-Running Vulnerable Auction
pub struct FrontRunningVulnerableAuctionDetector;

#[async_trait::async_trait]
impl SecurityDetector for FrontRunningVulnerableAuctionDetector {
    fn id(&self) -> &'static str { "MEV-001" }
    fn name(&self) -> &'static str { "Front-Running Vulnerable Auction" }
    fn description(&self) -> &'static str { "Detects auction mechanisms vulnerable to front-running" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for auction-related functions
            if func_name.contains("bid") || func_name.contains("auction") || func_name.contains("place_bid") {
                
                if let Some(code) = &func_def.code {
                    // Check if bid amount is visible in function parameters
                    let sig = &ctx.module.signatures[func_handle.parameters.0 as usize];
                    
                    // If function takes amount as parameter, it's visible to miners
                    let mut has_amount_param = false;
                    for param in &sig.0 {
                        if is_numeric_type(param) {
                            has_amount_param = true;
                            break;
                        }
                    }
                    
                    if has_amount_param {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            title: "Front-running vulnerable auction".to_string(),
                            description: "Bid amount is visible in transaction, making auction vulnerable to front-running".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Use commit-reveal scheme to hide bid amounts until all bids are submitted".to_string(),
                            references: vec!["CWE-411: Resource Lockout".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// MEV-002: Sandwich Attack Vulnerability
pub struct SandwichAttackVulnerabilityDetector;

#[async_trait::async_trait]
impl SecurityDetector for SandwichAttackVulnerabilityDetector {
    fn id(&self) -> &'static str { "MEV-002" }
    fn name(&self) -> &'static str { "Sandwich Attack Vulnerability" }
    fn description(&self) -> &'static str { "Detects DeFi functions vulnerable to sandwich attacks" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for swap/trading functions
            if func_name.contains("swap") || func_name.contains("trade") || func_name.contains("exchange") {
                
                if let Some(code) = &func_def.code {
                    // Check for functions that calculate price based on reserves
                    let mut has_reserve_calculation = false;
                    let mut has_price_impact = false;
                    
                    for instr in &code.code {
                        if matches!(instr, Bytecode::Div | Bytecode::Mul) {
                            has_reserve_calculation = true;
                        }
                        
                        // Look for patterns that suggest price impact calculation
                        if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                            // In a real implementation, we'd check for specific function calls
                            has_price_impact = true;
                        }
                    }
                    
                    if has_reserve_calculation && has_price_impact {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::High,
                            confidence: Confidence::High,
                            title: "Sandwich attack vulnerability".to_string(),
                            description: "Swap function may be vulnerable to sandwich attacks due to price impact".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name),
                            recommendation: "Add slippage protection and consider implementing TWAP swaps".to_string(),
                            references: vec!["CWE-411: Resource Lockout".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// MEV-003: Block Timestamp Manipulation
pub struct BlockTimestampManipulationDetector;

#[async_trait::async_trait]
impl SecurityDetector for BlockTimestampManipulationDetector {
    fn id(&self) -> &'static str { "MEV-003" }
    fn name(&self) -> &'static str { "Block Timestamp Manipulation" }
    fn description(&self) -> &'static str { "Detects functions vulnerable to block timestamp manipulation" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for time-dependent functions
            if func_name.contains("time") || func_name.contains("timestamp") || func_name.contains("execute") {
                
                if let Some(code) = &func_def.code {
                    // Check for timestamp usage in decision making
                    for (i, instr) in code.code.iter().enumerate() {
                        if matches!(instr, Bytecode::Call(_) | Bytecode::CallGeneric(_)) {
                            // In a real implementation, we'd check if this is a timestamp function
                            issues.push(SecurityIssue {
                                id: self.id().to_string(),
                                severity: Severity::High,
                                confidence: Confidence::Medium,
                                title: "Potential timestamp manipulation".to_string(),
                                description: "Function uses timestamp in decision making, which may be manipulable".to_string(),
                                location: create_loc(ctx, idx, i as u16),
                                source_code: Some(func_name.clone()),
                                recommendation: "Consider using median timestamps or other less manipulable time sources".to_string(),
                                references: vec!["CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization".to_string()],
                                metadata: HashMap::new(),
                            });
                        }
                    }
                }
            }
        }
        
        issues
    }
}

// MEV-004: Slippage Manipulation
pub struct SlippageManipulationDetector;

#[async_trait::async_trait]
impl SecurityDetector for SlippageManipulationDetector {
    fn id(&self) -> &'static str { "MEV-004" }
    fn name(&self) -> &'static str { "Slippage Manipulation" }
    fn description(&self) -> &'static str { "Detects functions vulnerable to slippage manipulation" }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        let mut issues = Vec::new();
        
        for (idx, func_def) in ctx.module.function_defs.iter().enumerate() {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name).as_str().to_lowercase();
            
            // Look for liquidity provision functions
            if func_name.contains("liquidity") || func_name.contains("add_") || func_name.contains("remove_") {
                
                if let Some(code) = &func_def.code {
                    // Look for division operations that calculate LP tokens
                    let mut division_count = 0;
                    let mut has_lp_calculation = false;
                    
                    for instr in &code.code {
                        if matches!(instr, Bytecode::Div) {
                            division_count += 1;
                        }
                        if matches!(instr, Bytecode::Mul) {
                            has_lp_calculation = true;
                        }
                    }
                    
                    if division_count > 0 && has_lp_calculation {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: Severity::High,
                            confidence: Confidence::Medium,
                            title: "Slippage manipulation vulnerability".to_string(),
                            description: "Liquidity function may be vulnerable to slippage manipulation".to_string(),
                            location: create_loc(ctx, idx, 0),
                            source_code: Some(func_name.clone()),
                            recommendation: "Implement proper slippage protection and validation".to_string(),
                            references: vec!["CWE-682: Incorrect Calculation".to_string()],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

// Helper function to check if type is numeric
fn is_numeric_type(param: &move_binary_format::file_format::SignatureToken) -> bool {
    matches!(param,
        move_binary_format::file_format::SignatureToken::U8 |
        move_binary_format::file_format::SignatureToken::U16 |
        move_binary_format::file_format::SignatureToken::U32 |
        move_binary_format::file_format::SignatureToken::U64 |
        move_binary_format::file_format::SignatureToken::U128 |
        move_binary_format::file_format::SignatureToken::U256
    )
}

// Export the detectors
pub fn get_mev_frontrunning_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(FrontRunningVulnerableAuctionDetector),
        Box::new(SandwichAttackVulnerabilityDetector),
        Box::new(BlockTimestampManipulationDetector),
        Box::new(SlippageManipulationDetector),
    ]
}