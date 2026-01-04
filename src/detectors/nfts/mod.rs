// src/detectors/nfts/mod.rs
use crate::{core::detector::SecurityDetector, types::*};
use crate::utils::{create_location, create_module_location};
use move_binary_format::{file_format::*, access::ModuleAccess};
use std::collections::{HashMap, HashSet};

// ULTRA STRICT: Determine if this is actually an NFT module
fn is_nft_module(module: &CompiledModule) -> bool {
    let module_name = module.self_id().name().as_str().to_lowercase();
    
    // Require explicit NFT indicators
    let is_nft_by_name = module_name.contains("nft") ||
                        module_name.contains("721") ||
                        module_name.contains("1155") ||
                        module_name.contains("collectible") ||
                        module_name.contains("token");
    
    if !is_nft_by_name {
        return false;
    }
    
    // Verify NFT-specific structs exist
    let has_nft_structs = module.struct_defs.iter().any(|struct_def| {
        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
        let struct_name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
        struct_name.contains("nft") ||
        struct_name.contains("token") ||
        struct_name.contains("metadata") ||
        struct_name.contains("collection")
    });
    
    // Verify NFT-specific functions exist
    let nft_function_count = module.function_defs.iter()
        .filter(|func_def| {
            let func_handle = &module.function_handles[func_def.function.0 as usize];
            let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
            func_name.contains("mint") ||
            func_name.contains("burn") ||
            func_name.contains("transfer") ||
            func_name.contains("royalty")
        })
        .count();
    
    // Must have multiple NFT indicators
    is_nft_by_name && (has_nft_structs || nft_function_count >= 2)
}

// NFT-001: Royalty Bypass - ULTRA STRICT
pub struct RoyaltyBypass;

#[async_trait::async_trait]
impl SecurityDetector for RoyaltyBypass {
    fn id(&self) -> &'static str { "NFT-001" }
    fn name(&self) -> &'static str { "Royalty Bypass" }
    fn description(&self) -> &'static str {
        "NFT royalties can be bypassed through alternative transfer methods"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_nft_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // First, check if module has royalty mechanisms
        let has_royalty_mechanism = has_royalty_mechanism(&ctx.module);
        
        if has_royalty_mechanism {
            // Look for transfer functions that bypass royalties
            for func_def in &ctx.module.function_defs {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                let func_name_lower = func_name.as_str().to_lowercase();
                
                // ULTRA STRICT: Only check core transfer functions
                let is_transfer_function = func_name_lower == "transfer" ||
                                          func_name_lower.starts_with("transfer_");
                
                if is_transfer_function && func_def.visibility == Visibility::Public {
                    // Check if this transfer enforces royalties
                    if !enforces_royalties_strict(func_def, &ctx.module) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Royalty bypass in '{}'", func_name),
                            description: "NFT transfer function doesn't enforce royalty payments".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Enforce royalties on all transfer paths or implement on-chain royalty standards".to_string(),
                            references: vec![
                                "EIP-2981: NFT Royalty Standard".to_string(),
                            ],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

fn has_royalty_mechanism(module: &CompiledModule) -> bool {
    // Check for royalty-related structs or functions
    for struct_def in &module.struct_defs {
        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
        let struct_name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
        if struct_name.contains("royalty") || struct_name.contains("fee") {
            return true;
        }
    }
    
    for func_def in &module.function_defs {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        if func_name.contains("royalty") || func_name.contains("fee") {
            return true;
        }
    }
    
    false
}

fn enforces_royalties_strict(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut royalty_indicators = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("royalty") { royalty_indicators += 3; }
                if func_name_lower.contains("fee") { royalty_indicators += 2; }
                if func_name_lower.contains("payment") { royalty_indicators += 1; }
                if func_name_lower.contains("distribute") { royalty_indicators += 1; }
            }
        }
        
        royalty_indicators >= 2
    } else {
        false
    }
}

// NFT-002: Metadata Manipulation - ULTRA STRICT
pub struct MetadataManipulation;

#[async_trait::async_trait]
impl SecurityDetector for MetadataManipulation {
    fn id(&self) -> &'static str { "NFT-002" }
    fn name(&self) -> &'static str { "Metadata Manipulation" }
    fn description(&self) -> &'static str {
        "NFT metadata can be changed after minting without restrictions"
    }
    fn default_severity(&self) -> Severity { Severity::Medium }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_nft_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Check if module has mutable metadata fields
        let has_mutable_metadata = has_mutable_metadata_structs(&ctx.module);
        
        if has_mutable_metadata {
            for func_def in &ctx.module.function_defs {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                let func_name_lower = func_name.as_str().to_lowercase();
                
                // ULTRA STRICT: Only check functions that explicitly update metadata
                let is_metadata_update_function = func_name_lower == "update_metadata" ||
                                                 func_name_lower == "set_metadata" ||
                                                 func_name_lower.contains("metadata_update");
                
                if is_metadata_update_function && func_def.visibility == Visibility::Public {
                    // Check if metadata updates are properly restricted
                    if !has_strict_metadata_update_restrictions(func_def, &ctx.module) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Metadata manipulation in '{}'", func_name),
                            description: "NFT metadata can be changed without proper authorization".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Restrict metadata updates to NFT owners/creators or make metadata immutable after minting".to_string(),
                            references: vec![],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

fn has_mutable_metadata_structs(module: &CompiledModule) -> bool {
    // Check for metadata structs with mutable fields
    for struct_def in &module.struct_defs {
        let struct_handle = &module.struct_handles[struct_def.struct_handle.0 as usize];
        let struct_name = module.identifier_at(struct_handle.name).as_str().to_lowercase();
        
        if struct_name.contains("metadata") || struct_name.contains("nft") {
            // Check if struct has fields that could be modified
            match &struct_def.field_information {
                StructFieldInformation::Declared(fields) => {
                    // If struct has more than just ID fields, it might have mutable metadata
                    if fields.len() > 2 { // ID + maybe one other field
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    
    false
}

fn has_strict_metadata_update_restrictions(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut authorization_indicators = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("only_owner") { authorization_indicators += 3; }
                if func_name_lower.contains("only_creator") { authorization_indicators += 3; }
                if func_name_lower.contains("check_owner") { authorization_indicators += 2; }
                if func_name_lower.contains("verify") { authorization_indicators += 2; }
                if func_name_lower.contains("assert") { authorization_indicators += 1; }
                if func_name_lower.contains("require") { authorization_indicators += 1; }
            }
        }
        
        authorization_indicators >= 2
    } else {
        false
    }
}

// NFT-003: Fake NFT Minting - ULTRA STRICT
pub struct FakeNFTMinting;

#[async_trait::async_trait]
impl SecurityDetector for FakeNFTMinting {
    fn id(&self) -> &'static str { "NFT-003" }
    fn name(&self) -> &'static str { "Fake NFT Minting" }
    fn description(&self) -> &'static str {
        "Unauthorized parties can mint NFTs"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_nft_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check mint functions
            let is_mint_function = func_name_lower == "mint" ||
                                  func_name_lower.starts_with("mint_");
            
            if is_mint_function && func_def.visibility == Visibility::Public {
                // Check for proper authorization with strict criteria
                let authorization_score = calculate_mint_authorization_score(func_def, &ctx.module);
                
                if authorization_score < 3 { // Require strong authorization
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if authorization_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("Fake NFT minting risk in '{}'", func_name),
                        description: "NFT minting function lacks proper authorization checks".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement signature verification, whitelists, or creator-only minting with proper validation".to_string(),
                        references: vec![],
                        metadata: {
                            let mut map = HashMap::new();
                            map.insert("authorization_score".to_string(), authorization_score.to_string());
                            map
                        },
                    });
                }
            }
        }
        
        issues
    }
}

fn calculate_mint_authorization_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    // Check function parameters for capabilities
    let func_handle = &module.function_handles[func_def.function.0 as usize];
    let signature = &module.signatures[func_handle.parameters.0 as usize];
    
    for param_type in &signature.0 {
        let mut inner_type = param_type;
        while let SignatureToken::Reference(inner) | SignatureToken::MutableReference(inner) = inner_type {
            inner_type = inner;
        }

        if let SignatureToken::Struct(idx) | SignatureToken::StructInstantiation(idx, _) = inner_type {
            let struct_handle = &module.struct_handles[idx.0 as usize];
            let struct_name = module.identifier_at(struct_handle.name).as_str();
            
            // Capabilities provide strong authorization
            if struct_name.ends_with("Cap") || 
               struct_name.contains("Owner") || 
               struct_name.contains("Admin") ||
               struct_name.contains("Minter") {
                score += 3;
            }
        }
    }
    
    // Check bytecode for validation
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("verify_signature") { score += 3; }
                if func_name_lower.contains("check_whitelist") { score += 2; }
                if func_name_lower.contains("only_creator") { score += 3; }
                if func_name_lower.contains("assert") { score += 1; }
            }
        }
    }
    
    score
}

// NFT-004: Burn Function Vulnerability - ULTRA STRICT
pub struct BurnFunctionVulnerability;

#[async_trait::async_trait]
impl SecurityDetector for BurnFunctionVulnerability {
    fn id(&self) -> &'static str { "NFT-004" }
    fn name(&self) -> &'static str { "Burn Function Vulnerability" }
    fn description(&self) -> &'static str {
        "NFT burn functions lack proper ownership validation"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_nft_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check burn functions
            let is_burn_function = func_name_lower == "burn" ||
                                  func_name_lower.starts_with("burn_");
            
            if is_burn_function && func_def.visibility == Visibility::Public {
                // Check for ownership validation
                if !has_ownership_validation_for_burn(func_def, &ctx.module) {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: Confidence::High,
                        title: format!("Burn function vulnerability in '{}'", func_name),
                        description: "NFT burn function doesn't properly validate ownership".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Verify NFT ownership and implement confirmation mechanisms before burning".to_string(),
                        references: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        issues
    }
}

fn has_ownership_validation_for_burn(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut validation_indicators = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("check_owner") { validation_indicators += 3; }
                if func_name_lower.contains("verify_owner") { validation_indicators += 3; }
                if func_name_lower.contains("owner_of") { validation_indicators += 2; }
                if func_name_lower.contains("balance_of") { validation_indicators += 1; }
                if func_name_lower.contains("assert") { validation_indicators += 1; }
            }
        }
        
        validation_indicators >= 2
    } else {
        false
    }
}

// NFT-008: Lazy Minting Risk - ULTRA STRICT
pub struct LazyMintingRisk;

#[async_trait::async_trait]
impl SecurityDetector for LazyMintingRisk {
    fn id(&self) -> &'static str { "NFT-008" }
    fn name(&self) -> &'static str { "Lazy Minting Risk" }
    fn description(&self) -> &'static str {
        "Lazy minting vulnerable to signature replay attacks"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_nft_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Check if module uses signature-based operations
        if uses_signature_verification(&ctx.module) {
            for func_def in &ctx.module.function_defs {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                let func_name_lower = func_name.as_str().to_lowercase();
                
                // ULTRA STRICT: Only check signature-based minting
                let is_signature_mint_function = func_name_lower.contains("signature") ||
                                                (func_name_lower.contains("mint") && 
                                                 (func_name_lower.contains("signed") || 
                                                  func_name_lower.contains("lazy")));
                
                if is_signature_mint_function && func_def.visibility == Visibility::Public {
                    // Check for replay protection
                    if !has_signature_replay_protection_strict(func_def, &ctx.module) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Lazy minting risk in '{}'", func_name),
                            description: "Signature-based minting vulnerable to replay attacks".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Include nonces, deadlines, and contract addresses in signed messages".to_string(),
                            references: vec![],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

fn uses_signature_verification(module: &CompiledModule) -> bool {
    for func_def in &module.function_defs {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        
        if func_name.contains("signature") || func_name.contains("verify") || func_name.contains("signed") {
            return true;
        }
    }
    
    false
}

fn has_signature_replay_protection_strict(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut protection_indicators = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("nonce") { protection_indicators += 3; }
                if func_name_lower.contains("deadline") { protection_indicators += 2; }
                if func_name_lower.contains("timestamp") { protection_indicators += 1; }
                if func_name_lower.contains("chain_id") { protection_indicators += 2; }
                if func_name_lower.contains("used_signatures") { protection_indicators += 3; }
            }
        }
        
        protection_indicators >= 2
    } else {
        false
    }
}

// NFT-010: Fractionalization Risk - ULTRA STRICT
pub struct FractionalizationRisk;

#[async_trait::async_trait]
impl SecurityDetector for FractionalizationRisk {
    fn id(&self) -> &'static str { "NFT-010" }
    fn name(&self) -> &'static str { "Fractionalization Risk" }
    fn description(&self) -> &'static str {
        "NFT fractionalization mechanisms require careful design"
    }
    fn default_severity(&self) -> Severity { Severity::High }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_nft_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        // Check if module has fractionalization functions
        let has_fractionalization = has_fractionalization_functions(&ctx.module);
        
        if has_fractionalization {
            for func_def in &ctx.module.function_defs {
                let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
                let func_name = ctx.module.identifier_at(func_handle.name);
                let func_name_lower = func_name.as_str().to_lowercase();
                
                // ULTRA STRICT: Only check core fractionalization functions
                let is_fractionalization_function = func_name_lower == "fractionalize" ||
                                                   func_name_lower == "split" ||
                                                   func_name_lower.contains("fraction_");
                
                if is_fractionalization_function && func_def.visibility == Visibility::Public {
                    // Check for proper mechanisms
                    if !has_fractionalization_safeguards(func_def, &ctx.module) {
                        issues.push(SecurityIssue {
                            id: self.id().to_string(),
                            severity: self.default_severity(),
                            confidence: Confidence::High,
                            title: format!("Fractionalization risk in '{}'", func_name),
                            description: "NFT fractionalization function lacks proper safeguards".to_string(),
                            location: create_location(ctx, func_def, 0),
                            source_code: Some(func_name.to_string()),
                            recommendation: "Implement proper redemption mechanisms, voting rights, and governance for fractionalized NFTs".to_string(),
                            references: vec![
                                "Fractional NFT Standards".to_string(),
                            ],
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        issues
    }
}

fn has_fractionalization_functions(module: &CompiledModule) -> bool {
    for func_def in &module.function_defs {
        let func_handle = &module.function_handles[func_def.function.0 as usize];
        let func_name = module.identifier_at(func_handle.name).as_str().to_lowercase();
        
        if func_name.contains("fraction") || 
           func_name.contains("split") || 
           func_name.contains("share") ||
           func_name.contains("fractionalize") {
            return true;
        }
    }
    
    false
}

fn has_fractionalization_safeguards(func_def: &FunctionDefinition, module: &CompiledModule) -> bool {
    if let Some(code) = &func_def.code {
        let mut safeguard_indicators = 0;
        
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("redemption") { safeguard_indicators += 3; }
                if func_name_lower.contains("voting") { safeguard_indicators += 2; }
                if func_name_lower.contains("governance") { safeguard_indicators += 2; }
                if func_name_lower.contains("threshold") { safeguard_indicators += 1; }
                if func_name_lower.contains("quorum") { safeguard_indicators += 2; }
            }
        }
        
        safeguard_indicators >= 2
    } else {
        false
    }
}

// NFT-011: NFT Theft Risk - NEW STRICT DETECTOR
pub struct NFTTheftRisk;

#[async_trait::async_trait]
impl SecurityDetector for NFTTheftRisk {
    fn id(&self) -> &'static str { "NFT-011" }
    fn name(&self) -> &'static str { "NFT Theft Risk" }
    fn description(&self) -> &'static str {
        "NFT transfer functions vulnerable to unauthorized transfers"
    }
    fn default_severity(&self) -> Severity { Severity::Critical }
    
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue> {
        if !is_nft_module(&ctx.module) { return Vec::new(); }
        
        let mut issues = Vec::new();
        
        for func_def in &ctx.module.function_defs {
            let func_handle = &ctx.module.function_handles[func_def.function.0 as usize];
            let func_name = ctx.module.identifier_at(func_handle.name);
            let func_name_lower = func_name.as_str().to_lowercase();
            
            // ULTRA STRICT: Only check transfer functions
            let is_transfer_function = func_name_lower == "transfer" ||
                                      func_name_lower == "transfer_from" ||
                                      func_name_lower == "safe_transfer_from";
            
            if is_transfer_function && func_def.visibility == Visibility::Public {
                // Check for authorization validation
                let authorization_score = calculate_transfer_authorization_score(func_def, &ctx.module);
                
                if authorization_score < 2 {
                    issues.push(SecurityIssue {
                        id: self.id().to_string(),
                        severity: self.default_severity(),
                        confidence: if authorization_score == 0 { Confidence::High } else { Confidence::Medium },
                        title: format!("NFT theft risk in '{}'", func_name),
                        description: "NFT transfer function lacks proper authorization checks".to_string(),
                        location: create_location(ctx, func_def, 0),
                        source_code: Some(func_name.to_string()),
                        recommendation: "Implement proper owner verification and authorization checks for all transfers".to_string(),
                        references: vec![],
                        metadata: {
                            let mut map = HashMap::new();
                            map.insert("authorization_score".to_string(), authorization_score.to_string());
                            map
                        },
                    });
                }
            }
        }
        
        issues
    }
}

fn calculate_transfer_authorization_score(func_def: &FunctionDefinition, module: &CompiledModule) -> i32 {
    let mut score = 0;
    
    if let Some(code) = &func_def.code {
        for instr in &code.code {
            if let Some(func_name) = crate::utils::get_function_name(instr, module) {
                let func_name_lower = func_name.as_str().to_lowercase();
                
                if func_name_lower.contains("owner_of") { score += 3; }
                if func_name_lower.contains("check_owner") { score += 3; }
                if func_name_lower.contains("verify_owner") { score += 3; }
                if func_name_lower.contains("balance_of") { score += 1; }
                if func_name_lower.contains("assert") { score += 1; }
                if func_name_lower.contains("require") { score += 1; }
            }
        }
    }
    
    score
}

// Only include detectors that can be made extremely strict
pub fn get_detectors() -> Vec<Box<dyn SecurityDetector>> {
    vec![
        Box::new(RoyaltyBypass),
        Box::new(MetadataManipulation),
        Box::new(FakeNFTMinting),
        Box::new(BurnFunctionVulnerability),
        Box::new(LazyMintingRisk),
        Box::new(FractionalizationRisk),
        Box::new(NFTTheftRisk),
    ]
}