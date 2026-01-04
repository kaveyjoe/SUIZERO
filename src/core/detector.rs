// src/core/detector.rs
use crate::types::{SecurityIssue, DetectionContext, Severity};
use async_trait::async_trait;

#[async_trait]
pub trait SecurityDetector: Send + Sync {
    /// Unique identifier for the detector
    fn id(&self) -> &'static str;
    
    /// Human-readable name
    fn name(&self) -> &'static str;
    
    /// Description of what the detector checks
    fn description(&self) -> &'static str;
    
    /// Severity of issues found by this detector
    fn default_severity(&self) -> Severity;
    
    /// Categories this detector belongs to
    fn categories(&self) -> Vec<&'static str> {
        // Default implementation based on ID prefix or empty
        Vec::new()
    }
    
    /// Entry point for detection logic
    async fn detect(&self, ctx: &DetectionContext) -> Vec<SecurityIssue>;
    
    /// Whether this detector should run based on config
    fn should_run(&self, ctx: &DetectionContext) -> bool {
        match self.default_severity() {
            Severity::Critical | Severity::High => true,
            Severity::Medium => ctx.config.severity_threshold <= Severity::Medium,
            Severity::Low => ctx.config.severity_threshold <= Severity::Low,
            Severity::Info => ctx.config.severity_threshold <= Severity::Info,
        }
    }
}
