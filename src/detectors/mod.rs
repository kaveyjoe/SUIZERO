// src/detectors/mod.rs
pub mod access_control;
pub mod arithmetic;
pub mod reentrancy;
pub mod objects;
pub mod events;
pub mod oracles;
pub mod randomness;
pub mod timing;
pub mod gas;
pub mod logic;
pub mod ai_agents;
pub mod defi;
pub mod nfts;
pub mod bridges;
pub mod extended;

use crate::core::detector::SecurityDetector;
use std::collections::HashMap;

pub struct DetectorRegistry {
    detectors: HashMap<String, Box<dyn SecurityDetector>>,
}

impl DetectorRegistry {
    pub fn with_all_detectors() -> Self {
        let mut registry = Self {
            detectors: HashMap::new(),
        };
        
        // Access Control
        registry.add(Box::new(access_control::MissingSenderValidation));
        registry.add(Box::new(access_control::HardcodedAddress));
        registry.add(Box::new(access_control::MissingRoleCheck));
        registry.add(Box::new(access_control::PrivilegeEscalation));
        registry.add(Box::new(access_control::UnlimitedMinting));
        registry.add(Box::new(access_control::CentralizationRisk));
        registry.add(Box::new(access_control::SignatureReplay));
        
        // Arithmetic
        registry.add(Box::new(arithmetic::DivisionBeforeMultiplication));
        registry.add(Box::new(arithmetic::PrecisionLoss));
        registry.add(Box::new(arithmetic::RoundingErrors));
        registry.add(Box::new(arithmetic::IncorrectScaling));
        registry.add(Box::new(arithmetic::MultiplicationOverflowRisk));
        
        // Reentrancy
        registry.add(Box::new(reentrancy::StateChangeAfterCall));
        registry.add(Box::new(reentrancy::CrossFunctionReentrancy));
        registry.add(Box::new(reentrancy::ReadOnlyReentrancy));
        registry.add(Box::new(reentrancy::BatchOperationReentrancy));
        
        // Objects
        registry.add(Box::new(objects::LostObjectReference));
        registry.add(Box::new(objects::DoubleTransferRisk));
        registry.add(Box::new(objects::ImproperSharedObjectUsage));
        registry.add(Box::new(objects::MissingKeyAbility));
        registry.add(Box::new(objects::CopyAbilityAbuse));
        registry.add(Box::new(objects::ImproperIDField));
        
        // Events
        registry.add(Box::new(events::MissingCriticalEvents));
        registry.add(Box::new(events::EventAfterRevert));
        registry.add(Box::new(events::IncorrectEventData));
        registry.add(Box::new(events::LoggingDoS));
        registry.add(Box::new(events::MissingTimestamp));
        
        // Oracles
        registry.add(Box::new(oracles::FlashLoanVulnerability));
        registry.add(Box::new(oracles::SingleSourceOracle));
        registry.add(Box::new(oracles::NoPriceValidation));
        registry.add(Box::new(oracles::StalePriceUsage));
        registry.add(Box::new(oracles::IncorrectDecimals));
        registry.add(Box::new(oracles::MissingCircuitBreaker));
        registry.add(Box::new(oracles::OracleFrontRunningRisk));
        
        // Randomness
        registry.add(Box::new(randomness::PredictableRandomness));
        registry.add(Box::new(randomness::FrontRunningRNG));
        registry.add(Box::new(randomness::BiasInDistribution));
        registry.add(Box::new(randomness::SeedManipulation));
        
        // Timing
        registry.add(Box::new(timing::FrontRunningVulnerability));
        registry.add(Box::new(timing::TimestampDependence));
        registry.add(Box::new(timing::TransactionOrdering));
        registry.add(Box::new(timing::RaceConditions));
        registry.add(Box::new(timing::DeadlineBypass));
        registry.add(Box::new(timing::MevPatterns));
        
        // Gas
        registry.add(Box::new(gas::GasGriefingAttack));
        registry.add(Box::new(gas::OutOfGasRevert));
        registry.add(Box::new(gas::StorageBloat));
        registry.add(Box::new(gas::DynamicVectorGrowth));
        registry.add(Box::new(gas::RecursiveCalls));
        
        // Logic
        registry.add(Box::new(logic::UninitializedStorage));
        registry.add(Box::new(logic::InputValidationMissing));
        registry.add(Box::new(logic::IncorrectFeeCalculation));
        registry.add(Box::new(logic::RewardDistributionError));
        registry.add(Box::new(logic::VotingMechanismBug));
        registry.add(Box::new(logic::CrossChainBridgeBug));

        // AI Agents
        registry.add(Box::new(ai_agents::UnboundedAIAction));
        registry.add(Box::new(ai_agents::ModelManipulation));
        registry.add(Box::new(ai_agents::PromptInjection));
        registry.add(Box::new(ai_agents::RewardHacking));
        registry.add(Box::new(ai_agents::EmergentBehaviorRisk));
        registry.add(Box::new(ai_agents::CorrigibilityIssue));
        registry.add(Box::new(ai_agents::AdversarialExampleRisk));

        // DeFi
        registry.add(Box::new(defi::SlippageAttack));
        registry.add(Box::new(defi::OracleManipulationInAMM));
        registry.add(Box::new(defi::LiquidationVulnerability));
        registry.add(Box::new(defi::FeeOnTransferTokenIssue));
        registry.add(Box::new(defi::YieldFarmingVulnerability));
        registry.add(Box::new(defi::MEVExtractionRisk));
        registry.add(Box::new(defi::StablecoinDepegRisk));
        registry.add(Box::new(defi::ComposabilityRisk));
        registry.add(Box::new(defi::TokenomicsVulnerability));

        // NFTs
        registry.add(Box::new(nfts::RoyaltyBypass));
        registry.add(Box::new(nfts::MetadataManipulation));
        registry.add(Box::new(nfts::FakeNFTMinting));
        registry.add(Box::new(nfts::BurnFunctionVulnerability));
        registry.add(Box::new(nfts::LazyMintingRisk));
        registry.add(Box::new(nfts::FractionalizationRisk));
        registry.add(Box::new(nfts::NFTTheftRisk));

        // Bridges
        registry.add(Box::new(bridges::ValidatorCollusion));
        registry.add(Box::new(bridges::MessageReplayAttack));
        registry.add(Box::new(bridges::EconomicAttack));
        registry.add(Box::new(bridges::OracleDependencyRisk));
        registry.add(Box::new(bridges::InfiniteMintAttack));
        registry.add(Box::new(bridges::GovernanceTakeover));

        // Extended Detectors - Access Control (20 detectors)
        registry.add(Box::new(extended::access_control::UnauthorizedMintDetector));
        registry.add(Box::new(extended::access_control::MissingOwnerCheckDetector));
        registry.add(Box::new(extended::access_control::UnauthorizedBurnDetector));
        registry.add(Box::new(extended::access_control::UnauthorizedTransferDetector));
        registry.add(Box::new(extended::access_control::UnauthorizedUpdateDetector));
        registry.add(Box::new(extended::access_control::UnauthorizedFreezeDetector));
        registry.add(Box::new(extended::access_control::UnauthorizedAdminActionDetector));
        registry.add(Box::new(extended::access_control::MissingRoleBasedAccessDetector));
        registry.add(Box::new(extended::access_control::WeakAdminRecoveryDetector));
        registry.add(Box::new(extended::access_control::AdminKeyCompromiseDetector));
        registry.add(Box::new(extended::access_control::MultisigBypassDetector));
        registry.add(Box::new(extended::access_control::SignerSpoofingDetector));
        registry.add(Box::new(extended::access_control::TxContextManipulationDetector));
        registry.add(Box::new(extended::access_control::PrivilegeEscalationDetector));
        registry.add(Box::new(extended::access_control::FunctionVisibilityAbuseDetector));
        registry.add(Box::new(extended::access_control::InitializerBypassDetector));
        registry.add(Box::new(extended::access_control::CapabilityLeakDetector));
        registry.add(Box::new(extended::access_control::ObjectCapabilityReuseDetector));
        registry.add(Box::new(extended::access_control::SharedObjectAuthBypassDetector));
        registry.add(Box::new(extended::access_control::DelegatedAuthAbuseDetector));
        registry.add(Box::new(extended::access_control::TimelockBypassDetector));
        
        // Extended Detectors - Financial (20 detectors)
        registry.add(Box::new(extended::financial::FlashLoanAttackDetector));
        registry.add(Box::new(extended::financial::FlashMintAttackDetector));
        registry.add(Box::new(extended::financial::InterestRateManipulationDetector));
        registry.add(Box::new(extended::financial::LiquidityDrainDetector));
        registry.add(Box::new(extended::financial::SlippageAttackDetector));
        registry.add(Box::new(extended::financial::PriceImpactAbuseDetector));
        registry.add(Box::new(extended::financial::ArbitrageExploitationDetector));
        registry.add(Box::new(extended::financial::EconomicCensorshipDetector));
        registry.add(Box::new(extended::financial::TokenImbalanceDetector));
        registry.add(Box::new(extended::financial::RewardManipulationDetector));
        registry.add(Box::new(extended::financial::StakingExploitDetector));
        registry.add(Box::new(extended::financial::YieldFarmingAttackDetector));
        registry.add(Box::new(extended::financial::LiquidityPoolDrainDetector));
        registry.add(Box::new(extended::financial::AMMManipulationDetector));
        registry.add(Box::new(extended::financial::ConstantProductExploitDetector));
        registry.add(Box::new(extended::financial::BondingCurveAttackDetector));
        registry.add(Box::new(extended::financial::VestingScheduleBypassDetector));
        registry.add(Box::new(extended::financial::AirdropExploitationDetector));
        registry.add(Box::new(extended::financial::TokenWhitelistBypassDetector));
        registry.add(Box::new(extended::financial::FeeManipulationDetector));
        
        // Extended Detectors - DOS (20 detectors)
        registry.add(Box::new(extended::dos::GasDOSDetector));
        registry.add(Box::new(extended::dos::StorageDOSDetector));
        registry.add(Box::new(extended::dos::ComputationDOSDetector));
        registry.add(Box::new(extended::dos::MemoryDOSDetector));
        registry.add(Box::new(extended::dos::LoopDOSDetector));
        registry.add(Box::new(extended::dos::RecursionDOSDetector));
        registry.add(Box::new(extended::dos::EventSpamDetector));
        registry.add(Box::new(extended::dos::LogSpamDetector));
        registry.add(Box::new(extended::dos::ObjectCreationDOSDetector));
        registry.add(Box::new(extended::dos::TransactionSpamDetector));
        registry.add(Box::new(extended::dos::QueueOverflowDetector));
        registry.add(Box::new(extended::dos::StateBloatDetector));
        registry.add(Box::new(extended::dos::MetadataExpansionDetector));
        registry.add(Box::new(extended::dos::IndexExplosionDetector));
        registry.add(Box::new(extended::dos::LinkedListAttackDetector));
        registry.add(Box::new(extended::dos::TreeTraversalDOSDetector));
        registry.add(Box::new(extended::dos::GraphExplorationDOSDetector));
        registry.add(Box::new(extended::dos::SearchExhaustionDetector));
        registry.add(Box::new(extended::dos::SortingDOSDetector));
        registry.add(Box::new(extended::dos::HashingDOSDetector));
        
        // Extended Detectors - New Financial Detectors
        registry.add(Box::new(extended::dos::FlashLoanAttackDetector));
        registry.add(Box::new(extended::dos::OracleManipulationDetector));
        registry.add(Box::new(extended::dos::ReentrancyAttackDetector));
        registry.add(Box::new(extended::dos::SlippageProtectionDetector));
        
        // Extended Detectors - Arithmetic (20 detectors)
        registry.add(Box::new(extended::arithmetic::IntegerOverflowAddDetector));
        registry.add(Box::new(extended::arithmetic::IntegerOverflowMulDetector));
        registry.add(Box::new(extended::arithmetic::IntegerUnderflowSubDetector));
        registry.add(Box::new(extended::arithmetic::IntegerUnderflowDecDetector));
        registry.add(Box::new(extended::arithmetic::DivisionByZeroDetector));
        registry.add(Box::new(extended::arithmetic::ModuloByZeroDetector));
        registry.add(Box::new(extended::arithmetic::PrecisionLossDetector));
        registry.add(Box::new(extended::arithmetic::RoundingErrorDetector));
        registry.add(Box::new(extended::arithmetic::UncheckedCastDetector));
        registry.add(Box::new(extended::arithmetic::TypeOverflowDetector));
        registry.add(Box::new(extended::arithmetic::BoundaryConditionDetector));
        registry.add(Box::new(extended::arithmetic::OffByOneErrorDetector));
        registry.add(Box::new(extended::arithmetic::LogicInversionDetector));
        registry.add(Box::new(extended::arithmetic::ConditionalBypassDetector));
        registry.add(Box::new(extended::arithmetic::LoopInvariantDetector));
        registry.add(Box::new(extended::arithmetic::InfiniteLoopDetector));
        registry.add(Box::new(extended::arithmetic::UnboundedIterationDetector));
        registry.add(Box::new(extended::arithmetic::EarlyExitVulnerabilityDetector));
        registry.add(Box::new(extended::arithmetic::LateExitVulnerabilityDetector));
        registry.add(Box::new(extended::arithmetic::StateInconsistencyDetector));
        registry.add(Box::new(extended::arithmetic::LoopPrecisionLossDetector));
        
        // Extended Detectors - Storage (20 detectors)
        registry.add(Box::new(extended::storage::UninitializedStorageDetector));
        registry.add(Box::new(extended::storage::StorageCollisionDetector));
        registry.add(Box::new(extended::storage::StorageOverwriteDetector));
        registry.add(Box::new(extended::storage::StorageLeakDetector));
        registry.add(Box::new(extended::storage::MemoryExhaustionDetector));
        registry.add(Box::new(extended::storage::GasExhaustionDetector));
        registry.add(Box::new(extended::storage::StackOverflowDetector));
        registry.add(Box::new(extended::storage::HeapOverflowDetector));
        registry.add(Box::new(extended::storage::BufferOverflowDetector));
        registry.add(Box::new(extended::storage::ArrayOutOfBoundsDetector));
        registry.add(Box::new(extended::storage::StringOverflowDetector));
        registry.add(Box::new(extended::storage::BytesManipulationDetector));
        registry.add(Box::new(extended::storage::OptionNoneExploitDetector));
        registry.add(Box::new(extended::storage::VectorSideEffectDetector));
        registry.add(Box::new(extended::storage::ReferenceAliasingDetector));
        registry.add(Box::new(extended::storage::MutableReferenceEscapeDetector));
        registry.add(Box::new(extended::storage::ImmutableReferenceMutationDetector));
        registry.add(Box::new(extended::storage::BorrowCheckerBypassDetector));
        registry.add(Box::new(extended::storage::MoveSemanticsAbuseDetector));
        registry.add(Box::new(extended::storage::CopySemanticsAbuseDetector));
        
        // Extended Detectors - Sui-Specific (20 detectors)
        registry.add(Box::new(extended::sui_specific::SharedObjectConflictDetector));
        registry.add(Box::new(extended::sui_specific::SharedObjectDeadlockDetector));
        registry.add(Box::new(extended::sui_specific::SharedObjectStarvationDetector));
        registry.add(Box::new(extended::sui_specific::OwnedObjectAbuseDetector));
        registry.add(Box::new(extended::sui_specific::ObjectWrappingAttackDetector));
        registry.add(Box::new(extended::sui_specific::ObjectUnwrappingAttackDetector));
        registry.add(Box::new(extended::sui_specific::ObjectSplittingAttackDetector));
        registry.add(Box::new(extended::sui_specific::ObjectMergingAttackDetector));
        registry.add(Box::new(extended::sui_specific::ObjectFreezingBypassDetector));
        registry.add(Box::new(extended::sui_specific::ObjectDeletionBypassDetector));
        registry.add(Box::new(extended::sui_specific::TxContextForgeryDetector));
        registry.add(Box::new(extended::sui_specific::EphemeralObjectLeakDetector));
        registry.add(Box::new(extended::sui_specific::DynamicFieldAbuseDetector));
        registry.add(Box::new(extended::sui_specific::TableOverflowDetector));
        registry.add(Box::new(extended::sui_specific::BagManipulationDetector));
        registry.add(Box::new(extended::sui_specific::VectorOverflowDetector));
        registry.add(Box::new(extended::sui_specific::ObjectReferenceLeakDetector));
        registry.add(Box::new(extended::sui_specific::IdCollisionDetector));
        registry.add(Box::new(extended::sui_specific::UidReuseDetector));
        registry.add(Box::new(extended::sui_specific::ObjectMetadataTamperingDetector));
        registry.add(Box::new(extended::sui_specific::UnrestrictedSharedObjectInitDetector));
        registry.add(Box::new(extended::sui_specific::UnprotectedSharedObjectMutationDetector));
        registry.add(Box::new(extended::sui_specific::MeaninglessAssertionDetector));
        registry.add(Box::new(extended::sui_specific::FakeBalanceAccountingDetector));
        registry.add(Box::new(extended::sui_specific::PauseFlagIllusionDetector));
        registry.add(Box::new(extended::sui_specific::ZeroAmountDepositDetector));
        registry.add(Box::new(extended::sui_specific::CapabilityTheaterDetector));
        registry.add(Box::new(extended::sui_specific::ReferenceExposureDetector));
        registry.add(Box::new(extended::sui_specific::UnprotectedCapabilityMintingDetector));
        registry.add(Box::new(extended::sui_specific::LinearScanAuthDetector));
        registry.add(Box::new(extended::sui_specific::UnboundedStorageDetector));
        registry.add(Box::new(extended::sui_specific::UnboundCapabilityDetector));
        registry.add(Box::new(extended::sui_specific::PrecisionLossDetector));
        registry.add(Box::new(extended::sui_specific::PhantomAuthParameterDetector));
        
        // Extended Detectors - Reentrancy (20 detectors)
        registry.add(Box::new(extended::reentrancy::SingleFunctionReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::CrossFunctionReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::CrossModuleReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::SharedObjectReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::ReadonlyReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::ViewFunctionReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::EventBasedReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::CallbackReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::DelegateCallReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::StateCorruptionReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::GasLimitReentrancyDetector));
        registry.add(Box::new(extended::reentrancy::FrontRunningDetector));
        registry.add(Box::new(extended::reentrancy::BackRunningDetector));
        registry.add(Box::new(extended::reentrancy::SandwichAttackDetector));
        registry.add(Box::new(extended::reentrancy::MEVExtractionDetector));
        registry.add(Box::new(extended::reentrancy::TransactionOrderingDetector));
        registry.add(Box::new(extended::reentrancy::DependencyReorderingDetector));
        registry.add(Box::new(extended::reentrancy::StateRaceConditionDetector));
        registry.add(Box::new(extended::reentrancy::ConcurrentModificationDetector));
        registry.add(Box::new(extended::reentrancy::AtomicityViolationDetector));
        
        // Extended Detectors - Oracle (20 detectors)
        registry.add(Box::new(extended::oracle::OracleManipulationDetector));
        registry.add(Box::new(extended::oracle::PriceFeedAttackDetector));
        registry.add(Box::new(extended::oracle::TimestampManipulationDetector));
        registry.add(Box::new(extended::oracle::BlockHeightManipulationDetector));
        registry.add(Box::new(extended::oracle::RandomnessAttackDetector));
        registry.add(Box::new(extended::oracle::EntropyMiningDetector));
        registry.add(Box::new(extended::oracle::PseudoRandomGuessDetector));
        registry.add(Box::new(extended::oracle::ExternalCallSpoofingDetector));
        registry.add(Box::new(extended::oracle::CrossChainOracleAttackDetector));
        registry.add(Box::new(extended::oracle::DataFeedLatencyDetector));
        registry.add(Box::new(extended::oracle::StaleDataUseDetector));
        registry.add(Box::new(extended::oracle::DataAvailabilityAttackDetector));
        registry.add(Box::new(extended::oracle::SignatureReplayDetector));
        registry.add(Box::new(extended::oracle::MessageForgeryDetector));
        registry.add(Box::new(extended::oracle::CryptographicWeaknessDetector));
        registry.add(Box::new(extended::oracle::HashCollisionDetector));
        registry.add(Box::new(extended::oracle::DigestForgeryDetector));
        registry.add(Box::new(extended::oracle::KeyManagementFlawDetector));
        registry.add(Box::new(extended::oracle::SecretLeakageDetector));
        registry.add(Box::new(extended::oracle::ZeroKnowledgeBypassDetector));
        
        // Extended Detectors - Frontend (20 detectors)
        registry.add(Box::new(extended::frontend::ABIEncodingAttackDetector));
        registry.add(Box::new(extended::frontend::CalldataManipulationDetector));
        registry.add(Box::new(extended::frontend::EventLoggingAttackDetector));
        registry.add(Box::new(extended::frontend::ReturnDataExploitDetector));
        registry.add(Box::new(extended::frontend::ErrorHandlingAttackDetector));
        registry.add(Box::new(extended::frontend::RevertExploitationDetector));
        registry.add(Box::new(extended::frontend::AssertManipulationDetector));
        registry.add(Box::new(extended::frontend::AbortExploitationDetector));
        registry.add(Box::new(extended::frontend::ConditionalRevertAttackDetector));
        registry.add(Box::new(extended::frontend::GasPriceManipulationDetector));
        registry.add(Box::new(extended::frontend::TransactionOrderDependencyDetector));
        registry.add(Box::new(extended::frontend::BlockGasLimitAttackDetector));
        registry.add(Box::new(extended::frontend::MempoolSnoopingDetector));
        registry.add(Box::new(extended::frontend::NetworkPartitionAttackDetector));
        registry.add(Box::new(extended::frontend::ConsensusExploitDetector));
        registry.add(Box::new(extended::frontend::ValidatorCollusionDetector));
        registry.add(Box::new(extended::frontend::StakeSlashingAttackDetector));
        registry.add(Box::new(extended::frontend::ProtocolUpgradeAttackDetector));
        registry.add(Box::new(extended::frontend::ForkAttackDetector));
        registry.add(Box::new(extended::frontend::ChainReorgAttackDetector));
        
        // Extended Detectors - Governance (20 detectors)
        registry.add(Box::new(extended::governance::UpgradeBackdoorDetector));
        registry.add(Box::new(extended::governance::GovernanceTakeoverDetector));
        registry.add(Box::new(extended::governance::VoteManipulationDetector));
        registry.add(Box::new(extended::governance::QuorumAttackDetector));
        registry.add(Box::new(extended::governance::TimelockExploitDetector));
        registry.add(Box::new(extended::governance::ProposalSpamDetector));
        registry.add(Box::new(extended::governance::DelegationAttackDetector));
        registry.add(Box::new(extended::governance::GovernanceTokenAbuseDetector));
        registry.add(Box::new(extended::governance::SnapshotManipulationDetector));
        registry.add(Box::new(extended::governance::VotingPowerExploitDetector));
        registry.add(Box::new(extended::governance::WeightedVotingAttackDetector));
        registry.add(Box::new(extended::governance::QuadraticVotingExploitDetector));
        registry.add(Box::new(extended::governance::GovernanceDelayAttackDetector));
        registry.add(Box::new(extended::governance::EmergencyPauseAbuseDetector));
        registry.add(Box::new(extended::governance::AdminKeyRotationFlawDetector));
        registry.add(Box::new(extended::governance::MultisigUpgradeAttackDetector));
        registry.add(Box::new(extended::governance::ProxyPatternExploitDetector));
        registry.add(Box::new(extended::governance::DiamondPatternAttackDetector));
        registry.add(Box::new(extended::governance::ModularityExploitationDetector));
        registry.add(Box::new(extended::governance::InterfaceUpgradeRiskDetector));
        
        // Extended Detectors - State (SUI-034)
        registry.add(Box::new(extended::state::CrossFunctionInvariantDetector));

        // Extended Detectors - Temporal (SUI-036)
        registry.add(Box::new(extended::temporal::TemporalTOCTOUDetector));

        // Extended Detectors - Observability (SUI-037)
        registry.add(Box::new(extended::observability::EventConsistencyDetector));

        // Extended Detectors - Race Conditions (SUI-038)
        registry.add(Box::new(extended::temporal::SharedObjectRaceDetector));

        // Extended Detectors - Receipt Forgery (SUI-032)
        registry.add(Box::new(extended::receipt_forgery::ReceiptForgeryDetector));

        // Extended Detectors - Vault-Potato Binding (SUI-033)
        registry.add(Box::new(extended::vault_binding::VaultPotatoBindingDetector));

        // Extended Detectors - Hot Potato Lifecycle (SEM-001)
        registry.add(Box::new(extended::hot_potato::HotPotatoLifecycleEscapeDetector));

        // Extended Detectors - Phantom Authorization (SEM-002)
        registry.add(Box::new(extended::phantom_auth::PhantomAuthorizationDetector));

        // Extended Detectors - Capability Theater (SEM-003)
        registry.add(Box::new(extended::capability_theater::CapabilityTheaterDetector));

        // Extended Detectors - Value Conservation (SEM-004)
        registry.add(Box::new(extended::value_conservation::ValueConservationViolationDetector));

        // Extended Detectors - Emergency Auth (SEM-005)
        registry.add(Box::new(extended::emergency_auth::UnauthenticatedEmergencyFunctionDetector));

        // Extended Detectors - Event-State Sync (SEM-007)
        registry.add(Box::new(extended::event_state_sync::EventStateSyncDetector));

        // Extended Detectors - Nonce Enforcement (SEM-006)
        registry.add(Box::new(extended::nonce_enforcement::NonceEnforcementDetector));

        // Extended Detectors - Value Duplication (SEM-008)
        registry.add(Box::new(extended::value_duplication::ValueDuplicationDetector));

        registry
    }
    
    fn add(&mut self, detector: Box<dyn SecurityDetector>) {
        self.detectors.insert(detector.id().to_string(), detector);
    }
    
    pub fn get_detector(&self, id: &str) -> Option<&Box<dyn SecurityDetector>> {
        self.detectors.get(id)
    }
    
    // Returns detectors suitable for iteration (values)
    pub fn detectors(&self) -> Vec<&Box<dyn SecurityDetector>> {
        self.detectors.values().collect()
    }

    pub fn all_detectors(&self) -> Vec<&Box<dyn SecurityDetector>> {
        self.detectors.values().collect()
    }
}