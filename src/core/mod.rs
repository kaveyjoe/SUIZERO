pub mod analyzer;
pub mod detector;
pub mod engine;
pub mod optimizer;
pub mod patterns;
pub mod taint;
// re-export commonly used types
pub use analyzer::SuiSecurityAnalyzer;
pub use detector::SecurityDetector;
