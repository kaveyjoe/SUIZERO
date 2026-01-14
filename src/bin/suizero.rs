// src/bin/sui_analyzer.rs
use clap::{Parser, Subcommand, Args, ValueEnum};
use clap_complete::{generate, Shell};
use colored::*;
use comfy_table::{Table, Cell, ContentArrangement};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use sui_security_analyzer::{
    SuiSecurityAnalyzer, AnalysisConfig, Severity, AnalysisReport,
    detectors::DetectorRegistry,
    reporters::{ConsoleReporter, JsonReporter, MarkdownReporter, HtmlReporter, ReportGenerator},
    types::{DetectionContext, SecurityIssue},
    core::detector::SecurityDetector,
};
use tokio::fs;
use clap::CommandFactory;

#[derive(Parser)]
#[command(name = "suizero")]
#[command(about = "SUIZERO: The Advanced SUI Move Security Analyzer")]
#[command(version = "1.2.0")]
#[command(long_about = "SUIZERO: The industry-standard security analyzer for SUI Move smart contracts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a module or directory
    Analyze(AnalyzeArgs),
    
    /// Scan directory with specific configurations
    Scan(ScanArgs),
    
    /// List all available detectors
    List(ListArgs),
    
    /// Test specific detectors
    Test(TestArgs),
    
    /// Generate configuration file
    Config(ConfigArgs),
    
    /// Generate shell completions
    Completions(CompletionsArgs),
    
    /// Show statistics and metrics
    Stats,
}

#[derive(Args)]
struct AnalyzeArgs {
    /// Path to module file or directory
    path: PathBuf,
    
    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Console)]
    format: OutputFormat,
    
    /// Minimum severity to report
    #[arg(short, long, value_enum, default_value_t = SeverityArg::Low)]
    severity: SeverityArg,
    
    /// Output file (for json/markdown/html)
    #[arg(short, long)]
    output: Option<PathBuf>,
    
    /// Enable specific detector categories
    #[arg(long, value_delimiter = ',')]
    categories: Option<Vec<Category>>,
    
    /// Enable specific detectors by ID
    #[arg(long, value_delimiter = ',')]
    detectors: Option<Vec<String>>,
    
    /// Disable specific detectors
    #[arg(long, value_delimiter = ',')]
    exclude: Option<Vec<String>>,
    
    /// Run in parallel (faster but uses more memory)
    #[arg(long, default_value_t = true)]
    parallel: bool,
    
    /// Show progress bar
    #[arg(long, default_value_t = true)]
    progress: bool,
    
    /// Generate fix suggestions
    #[arg(long, default_value_t = false)]
    fixes: bool,
    
    /// Include test code in analysis
    #[arg(long, default_value_t = false)]
    include_tests: bool,
}

#[derive(Args)]
struct ScanArgs {
    /// Directory to scan
    path: PathBuf,
    
    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Console)]
    format: OutputFormat,
    
    /// Output directory for reports
    #[arg(short, long)]
    output_dir: Option<PathBuf>,
    
    /// Generate summary report
    #[arg(long, default_value_t = true)]
    summary: bool,
    
    /// Generate per-module reports
    #[arg(long, default_value_t = false)]
    per_module: bool,
    
    /// Generate HTML dashboard
    #[arg(long, default_value_t = false)]
    dashboard: bool,
    
    /// Fail on critical issues
    #[arg(long, default_value_t = false)]
    fail_on_critical: bool,
    
    /// Fail on high or critical issues
    #[arg(long, default_value_t = false)]
    fail_on_high: bool,
    
    /// Maximum issues to report per module
    #[arg(long, default_value_t = 100)]
    max_issues: usize,
}

#[derive(Args)]
struct ListArgs {
    /// List by category
    #[arg(short, long)]
    category: Option<Category>,
    
    /// Show detailed information
    #[arg(short, long)]
    detailed: bool,
    
    /// Show only enabled detectors
    #[arg(long)]
    enabled: bool,
    
    /// Show only disabled detectors
    #[arg(long)]
    disabled: bool,
    
    /// Export as JSON
    #[arg(long)]
    json: bool,
    
    /// Export as CSV
    #[arg(long)]
    csv: bool,
}

#[derive(Args)]
struct TestArgs {
    /// Test specific detectors
    #[arg(value_delimiter = ',')]
    detectors: Vec<String>,
    
    /// Test file or directory
    path: PathBuf,
    
    /// Expected number of issues
    #[arg(long)]
    expected: Option<usize>,
    
    /// Update expected results
    #[arg(long)]
    update: bool,
}

#[derive(Args)]
struct ConfigArgs {
    /// Generate default configuration
    #[arg(long)]
    default: bool,
    
    /// Configuration file to create
    output: PathBuf,
    
    /// Include all detectors
    #[arg(long, default_value_t = true)]
    all_detectors: bool,
}

#[derive(Args)]
struct CompletionsArgs {
    /// Shell to generate completions for
    shell: Shell,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Console,
    Json,
    Markdown,
    Html,
    Sarif, // For CI/CD integration
    Junit, // For test reporting
}

#[derive(Clone, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
    All,
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
            SeverityArg::All => Severity::Info, // Lowest level
        }
    }
}

#[derive(Clone, ValueEnum, PartialEq)]
enum Category {
    AccessControl,
    Arithmetic,
    Reentrancy,
    Objects,
    Events,
    Oracles,
    Randomness,
    Timing,
    Gas,
    Logic,
    All,
}

impl Category {
    fn detector_ids(&self) -> Vec<&'static str> {
        match self {
            Category::AccessControl => vec![
                "AC-001", "AC-002", "AC-003", "AC-004", "AC-005",
                "AC-006", "AC-007", "AC-008", "AC-009", "AC-010",
                "AC-011", "AC-012", "AC-013", "AC-014", "AC-015",
            ],
            Category::Arithmetic => vec![
                "AR-001", "AR-002", "AR-003", "AR-004", "AR-005",
                "AR-006", "AR-007", "AR-008", "AR-009", "AR-010",
                "AR-011", "AR-012", "AR-013", "AR-014", "AR-015",
                "AR-016", "AR-017", "AR-018",
            ],
            Category::Reentrancy => vec![
                "RE-001", "RE-002", "RE-003", "RE-004", "RE-005",
                "RE-006", "RE-007", "RE-008", "RE-009", "RE-010",
                "RE-011", "RE-012",
            ],
            Category::Objects => vec![
                "OB-001", "OB-002", "OB-003", "OB-004", "OB-005",
                "OB-006", "OB-007", "OB-008", "OB-009", "OB-010",
                "OB-011", "OB-012", "OB-013", "OB-014", "OB-015",
                "OB-016", "OB-017", "OB-018", "OB-019", "OB-020",
            ],
            Category::Events => vec![
                "EV-001", "EV-002", "EV-003", "EV-004", "EV-005",
                "EV-006", "EV-007", "EV-008",
            ],
            Category::Oracles => vec![
                "OR-001", "OR-002", "OR-003", "OR-004", "OR-005",
                "OR-006", "OR-007", "OR-008", "OR-009", "OR-010",
            ],
            Category::Randomness => vec![
                "RN-001", "RN-002", "RN-003", "RN-004", "RN-005",
            ],
            Category::Timing => vec![
                "TM-001", "TM-002", "TM-003", "TM-004", "TM-005",
                "TM-006", "TM-007",
            ],
            Category::Gas => vec![
                "GA-001", "GA-002", "GA-003", "GA-004", "GA-005",
            ],
            Category::Logic => vec![
                "LG-001", "LG-002", "LG-003", "LG-004", "LG-005",
                "LG-006", "LG-007", "LG-008", "LG-009", "LG-010",
            ],
            Category::All => {
                let mut all = Vec::new();
                all.extend(Category::AccessControl.detector_ids());
                all.extend(Category::Arithmetic.detector_ids());
                all.extend(Category::Reentrancy.detector_ids());
                all.extend(Category::Objects.detector_ids());
                all.extend(Category::Events.detector_ids());
                all.extend(Category::Oracles.detector_ids());
                all.extend(Category::Randomness.detector_ids());
                all.extend(Category::Timing.detector_ids());
                all.extend(Category::Gas.detector_ids());
                all.extend(Category::Logic.detector_ids());
                all
            }
        }
    }
    
    fn display_name(&self) -> &'static str {
        match self {
            Category::AccessControl => "Access Control",
            Category::Arithmetic => "Arithmetic",
            Category::Reentrancy => "Reentrancy",
            Category::Objects => "Objects",
            Category::Events => "Events",
            Category::Oracles => "Oracles",
            Category::Randomness => "Randomness",
            Category::Timing => "Timing",
            Category::Gas => "Gas",
            Category::Logic => "Logic",
            Category::All => "All Categories",
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Analyze(args) => {
            analyze_command(args).await?;
        }
        Commands::Scan(args) => {
            scan_command(args).await?;
        }
        Commands::List(args) => {
            list_command(args).await?;
        }
        Commands::Test(args) => {
            test_command(args).await?;
        }
        Commands::Config(args) => {
            config_command(args).await?;
        }
        Commands::Completions(args) => {
            completions_command(args).await?;
        }
        Commands::Stats => {
            stats_command().await?;
        }
    }
    
    Ok(())
}

async fn analyze_command(args: AnalyzeArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== SUI Security Analyzer ===".bold().green());
    println!("Analyzing: {}", args.path.display());
    
    // Create configuration
    let config = AnalysisConfig {
        severity_threshold: args.severity.into(),
        include_test_code: args.include_tests,
        ..AnalysisConfig::default()
    };
    
    // Setup detector filters
    let mut enabled_detectors = Vec::new();
    
    if let Some(categories) = &args.categories {
        for category in categories {
            enabled_detectors.extend(category.detector_ids());
        }
    } else if let Some(detectors) = &args.detectors {
        enabled_detectors.extend(detectors.iter().map(|s| s.as_str()));
    }
    
    // Create analyzer
    let mut analyzer = SuiSecurityAnalyzer::new(config);
    
    if !enabled_detectors.is_empty() {
        analyzer.enable_detectors(&enabled_detectors);
    }
    
    if let Some(excluded) = &args.exclude {
        analyzer.disable_detectors(excluded);
    }
    
    // Setup progress bar
    let pb = if args.progress {
        Some(ProgressBar::new_spinner().with_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")?
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        ))
    } else {
        None
    };
    
    if let Some(pb) = &pb {
        pb.set_message("Analyzing module...");
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
    }
    
    // Run analysis
    let result = if args.path.is_dir() {
        analyzer.analyze_directory(&args.path, args.parallel).await?
    } else {
        let module_bytes = fs::read(&args.path).await?;
        analyzer.analyze_module(&module_bytes).await?
    };
    
    if let Some(pb) = &pb {
        pb.finish_with_message("Analysis complete!");
    }
    
    // Display results
    display_results(&result, &args.format, args.output.as_ref()).await?;
    
    // Count all severity levels
    let critical_count = result.issues.iter()
        .filter(|i| i.severity == Severity::Critical)
        .count();
    
    let high_count = result.issues.iter()
        .filter(|i| i.severity == Severity::High)
        .count();
    
    let medium_count = result.issues.iter()
        .filter(|i| i.severity == Severity::Medium)
        .count();
    
    if critical_count > 0 || high_count > 0 || medium_count > 0 {
        let mut summary_parts = Vec::new();
        if critical_count > 0 {
            summary_parts.push(format!("{} critical", critical_count));
        }
        if high_count > 0 {
            summary_parts.push(format!("{} high", high_count));
        }
        if medium_count > 0 {
            summary_parts.push(format!("{} medium", medium_count));
        }
        
        let summary = summary_parts.join(" and ");
        println!("\n{} {} severity issues found!", 
            "⚠️".yellow(), summary);
    }
    
    Ok(())
}

async fn scan_command(args: ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== SUI Security Scanner ===".bold().green());
    println!("Scanning directory: {}", args.path.display());
    
    // Create analyzer
    let config = AnalysisConfig::default();
    let mut analyzer = SuiSecurityAnalyzer::new(config);
    
    // Setup progress
    let pb = ProgressBar::new_spinner().with_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")?
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    
    pb.set_message("Scanning directory...");
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    
    // Scan directory
    let results = analyzer.scan_directory(&args.path).await?;
    
    pb.finish_with_message("Scan complete!");
    
    // Process results
    let mut all_issues = Vec::new();
    let mut module_reports = Vec::new();
    
    for (module_path, report) in results.reports {
        all_issues.extend(report.issues.clone());
        module_reports.push((module_path.to_string_lossy().into_owned(), report));
    }
    
    // Display summary
    display_scan_summary(&module_reports, &all_issues);
    
    // Generate reports
    if let Some(output_dir) = &args.output_dir {
        generate_reports(&module_reports, &all_issues, &args.format, output_dir, args.dashboard).await?;
    }
    
    // Check for failure conditions
    if args.fail_on_critical {
        let critical_count = all_issues.iter()
            .filter(|i| i.severity == Severity::Critical)
            .count();
        
        if critical_count > 0 {
            return Err(format!("Found {} critical issues", critical_count).into());
        }
    }
    
    if args.fail_on_high {
        let high_critical_count = all_issues.iter()
            .filter(|i| i.severity == Severity::Critical || i.severity == Severity::High)
            .count();
        
        if high_critical_count > 0 {
            return Err(format!("Found {} high/critical issues", high_critical_count).into());
        }
    }
    
    Ok(())
}

async fn list_command(args: ListArgs) -> Result<(), Box<dyn std::error::Error>> {
    let registry = DetectorRegistry::with_all_detectors();
    
    if args.json {
        // Export as JSON
        let detectors: Vec<_> = registry.all_detectors()
            .into_iter()
            .map(|d| DetectorInfo::from(d))
            .collect();
        
        let json = serde_json::to_string_pretty(&detectors)?;
        println!("{}", json);
        return Ok(());
    }
    
    if args.csv {
        // Export as CSV
        println!("id,name,severity,category,description");
        for detector in registry.all_detectors() {
            println!("\"{}\",\"{}\",\"{:?}\",\"{}\",\"{}\"",
                detector.id(),
                detector.name(),
                detector.default_severity(),
                detector.id().split('-').next().unwrap_or("unknown"),
                detector.description().replace('"', "'"));
        }
        return Ok(());
    }
    
    // Display in console
    println!("{}", "=== Available Detectors ===".bold().green());
    
    let categories = [
        (Category::AccessControl, 15),
        (Category::Arithmetic, 18),
        (Category::Reentrancy, 12),
        (Category::Objects, 20),
        (Category::Events, 8),
        (Category::Oracles, 10),
        (Category::Randomness, 5),
        (Category::Timing, 7),
        (Category::Gas, 5),
        (Category::Logic, 10),
    ];
    
    let mut total = 0;
    
    for (category, count) in &categories {
        if let Some(filter) = &args.category {
            if *filter != *category && *filter != Category::All {
                continue;
            }
        }
        
        println!("\n{} ({} detectors):", category.display_name().bold(), count);
        total += count;
        
        if args.detailed {
            let detector_ids = category.detector_ids();
            for (i, id) in detector_ids.iter().enumerate() {
                if let Some(detector) = registry.get_detector(id) {
                    let severity = match detector.default_severity() {
                        Severity::Critical => "CRIT".red(),
                        Severity::High => "HIGH".yellow(),
                        Severity::Medium => "MED".cyan(),
                        Severity::Low => "LOW".green(),
                        Severity::Info => "INFO".blue(),
                    };
                    
                    println!("  {:3}. [{}] {}: {}", 
                        i + 1, 
                        severity, 
                        detector.id(), 
                        detector.name());
                    
                    if args.detailed {
                        println!("      {}", detector.description());
                    }
                }
            }
        } else {
            let detector_ids = category.detector_ids();
            let ids_str = detector_ids.iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            
            println!("  IDs: {}", ids_str);
        }
    }
    
    println!("\n{}: {} detectors across {} categories", 
        "Total".bold(), total, categories.len());
    
    Ok(())
}

async fn test_command(args: TestArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== Detector Testing ===".bold().green());
    
    let registry = DetectorRegistry::with_all_detectors();
    
    // Test specific detectors
    for detector_id in &args.detectors {
        if let Some(detector) = registry.get_detector(detector_id) {
            println!("\nTesting {}: {}", detector.id(), detector.name());
            println!("  Description: {}", detector.description());
            
            // Load test module
            let module_bytes = fs::read(&args.path).await?;
            
            // Create test context
            let config = AnalysisConfig::default();
            let ctx = DetectionContext {
                module: move_binary_format::CompiledModule::deserialize_with_defaults(&module_bytes)?,
                module_bytes,
                module_id: move_core_types::language_storage::ModuleId::new(
                    move_core_types::account_address::AccountAddress::ZERO,
                    move_core_types::identifier::Identifier::new("test").unwrap(),
                ),
                dependencies: Vec::new(),
                config,
            };
            
            // Run detector
            let issues = detector.detect(&ctx).await;
            
            println!("  Found {} issues", issues.len());
            
            for issue in &issues {
                println!("    - [{:?}] {}", issue.severity, issue.title);
            }
            
            // Check expected results
            if let Some(expected) = args.expected {
                if issues.len() != expected {
                    println!("  {} Expected {} issues, found {}", 
                        "FAIL".red(), expected, issues.len());
                } else {
                    println!("  {}", "PASS".green());
                }
            }
        } else {
            println!("{} Detector not found: {}", "ERROR".red(), detector_id);
        }
    }
    
    Ok(())
}

async fn config_command(args: ConfigArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating configuration file: {}", args.output.display());
    
    let config = if args.all_detectors {
        generate_full_config()
    } else {
        generate_default_config()
    };
    
    let toml = toml::to_string_pretty(&config)?;
    fs::write(&args.output, toml).await?;
    
    println!("{} Configuration file created", "✓".green());
    
    Ok(())
}

async fn completions_command(args: CompletionsArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Cli::command();
    generate(args.shell, &mut cmd, "sui-analyzer", &mut std::io::stdout());
    Ok(())
}

async fn stats_command() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== Analyzer Statistics ===".bold().green());
    
    let registry = DetectorRegistry::with_all_detectors();
    
    // Count detectors by category and severity
    let mut category_counts = std::collections::HashMap::new();
    let mut severity_counts = std::collections::HashMap::new();
    
    for detector in registry.all_detectors() {
        let category = detector.id().split('-').next().unwrap_or("unknown");
        *category_counts.entry(category).or_insert(0) += 1;
        
        let severity = format!("{:?}", detector.default_severity());
        *severity_counts.entry(severity).or_insert(0) += 1;
    }
    
    // Display statistics
    println!("\n{}", "Detector Statistics:".bold());
    
    let mut table = Table::new();
    table
        .set_header(vec!["Category", "Count", "Percentage"])
        .set_content_arrangement(ContentArrangement::Dynamic);
    
    let total = registry.all_detectors().len();
    
    let categories = [
        ("AC", "Access Control"),
        ("AR", "Arithmetic"),
        ("RE", "Reentrancy"),
        ("OB", "Objects"),
        ("EV", "Events"),
        ("OR", "Oracles"),
        ("RN", "Randomness"),
        ("TM", "Timing"),
        ("GA", "Gas"),
        ("LG", "Logic"),
    ];
    
    for (code, name) in categories {
        if let Some(&count) = category_counts.get(code) {
            let percentage = (count as f32 / total as f32 * 100.0) as u32;
            table.add_row(vec![
                Cell::new(name),
                Cell::new(count.to_string()),
                Cell::new(format!("{}%", percentage)),
            ]);
        }
    }
    
    println!("{}", table);
    
    println!("\n{}", "Severity Distribution:".bold());
    
    let mut table = Table::new();
    table
        .set_header(vec!["Severity", "Count", "Percentage"])
        .set_content_arrangement(ContentArrangement::Dynamic);
    
    for (severity, count) in &severity_counts {
        let percentage = (*count as f32 / total as f32 * 100.0) as u32;
        table.add_row(vec![
            Cell::new(severity),
            Cell::new(count.to_string()),
            Cell::new(format!("{}%", percentage)),
        ]);
    }
    
    println!("{}", table);
    
    println!("\n{}: {} detectors", "Total".bold(), total);
    
    Ok(())
}

async fn display_results(
    result: &AnalysisReport,
    format: &OutputFormat,
    output_path: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Console => {
            let reporter = ConsoleReporter;
            let report = reporter.generate(&result.issues);
            println!("{}", report);
        }
        OutputFormat::Json => {
            let reporter = JsonReporter;
            let report = reporter.generate(&result.issues);
            
            if let Some(path) = output_path {
                fs::write(path, report).await?;
                println!("Report saved to: {}", path.display());
            } else {
                println!("{}", report);
            }
        }
        OutputFormat::Markdown => {
            let reporter = MarkdownReporter;
            let report = reporter.generate(&result.issues);
            
            if let Some(path) = output_path {
                fs::write(path, report).await?;
                println!("Report saved to: {}", path.display());
            } else {
                println!("{}", report);
            }
        }
        OutputFormat::Html => {
            let reporter = HtmlReporter;
            let report = reporter.generate(&result.issues);
            
            if let Some(path) = output_path {
                fs::write(path, report).await?;
                println!("HTML report saved to: {}", path.display());
            } else {
                println!("HTML report generated (use --output to save)");
            }
        }
        OutputFormat::Sarif => {
            // SARIF format for CI/CD integration
            let sarif = generate_sarif_report(result);
            
            if let Some(path) = output_path {
                fs::write(path, sarif).await?;
                println!("SARIF report saved to: {}", path.display());
            } else {
                println!("{}", sarif);
            }
        }
        OutputFormat::Junit => {
            // JUnit XML format for test reporting
            let junit = generate_junit_report(result);
            
            if let Some(path) = output_path {
                fs::write(path, junit).await?;
                println!("JUnit report saved to: {}", path.display());
            } else {
                println!("{}", junit);
            }
        }
    }
    
    Ok(())
}

fn display_scan_summary(
    module_reports: &[(String, AnalysisReport)],
    all_issues: &[SecurityIssue],
) {
    println!("\n{}", "=== Scan Summary ===".bold().green());
    
    let mut table = Table::new();
    table
        .set_header(vec!["Severity", "Count", "Modules Affected"])
        .set_content_arrangement(ContentArrangement::Dynamic);
    
    let severities = [
        (Severity::Critical, "Critical"),
        (Severity::High, "High"),
        (Severity::Medium, "Medium"),
        (Severity::Low, "Low"),
        (Severity::Info, "Info"),
    ];
    
    for (severity, name) in severities {
        let count = all_issues.iter()
            .filter(|i| i.severity == severity)
            .count();
        
        let modules_affected = module_reports.iter()
            .filter(|(_, report)| report.issues.iter().any(|i| i.severity == severity))
            .count();
        
        let severity_cell = match severity {
            Severity::Critical => Cell::new(name).fg(comfy_table::Color::Red),
            Severity::High => Cell::new(name).fg(comfy_table::Color::Yellow),
            Severity::Medium => Cell::new(name).fg(comfy_table::Color::Cyan),
            Severity::Low => Cell::new(name).fg(comfy_table::Color::Green),
            Severity::Info => Cell::new(name).fg(comfy_table::Color::Blue),
        };
        
        table.add_row(vec![
            severity_cell,
            Cell::new(count.to_string()),
            Cell::new(modules_affected.to_string()),
        ]);
    }
    
    println!("{}", table);
    
    println!("\n{} modules scanned, {} total issues found",
        module_reports.len(), all_issues.len());
    
    // Show top categories
    let mut category_counts = std::collections::HashMap::new();
    for issue in all_issues {
        let category = issue.id.split('-').next().unwrap_or("unknown");
        *category_counts.entry(category).or_insert(0) += 1;
    }
    
    if !category_counts.is_empty() {
        println!("\n{}", "Top Issue Categories:".bold());
        
        let mut categories: Vec<_> = category_counts.into_iter().collect();
        categories.sort_by(|a, b| b.1.cmp(&a.1));
        
        for (category, count) in categories.iter().take(5) {
            let category_name = match *category {
                "AC" => "Access Control",
                "AR" => "Arithmetic",
                "RE" => "Reentrancy",
                "OB" => "Objects",
                "EV" => "Events",
                "OR" => "Oracles",
                "RN" => "Randomness",
                "TM" => "Timing",
                "GA" => "Gas",
                "LG" => "Logic",
                _ => "Other",
            };
            
            println!("  {}: {} issues", category_name, count);
        }
    }
}

async fn generate_reports(
    module_reports: &[(String, AnalysisReport)],
    all_issues: &[SecurityIssue],
    format: &OutputFormat,
    output_dir: &PathBuf,
    dashboard: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create output directory
    fs::create_dir_all(output_dir).await?;
    
    match format {
        OutputFormat::Console => {
            // Already displayed
        }
        OutputFormat::Json => {
            let reporter = JsonReporter;
            
            // Overall report
            let summary_path = output_dir.join("summary.json");
            let summary_report = reporter.generate(all_issues);
            fs::write(summary_path, summary_report).await?;
            
            // Per-module reports
            if !module_reports.is_empty() {
                let modules_dir = output_dir.join("modules");
                fs::create_dir_all(&modules_dir).await?;
                
                for (module_path, report) in module_reports {
                    let file_name = PathBuf::from(module_path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .replace(".mv", ".json");
                    
                    let module_report_path = modules_dir.join(file_name);
                    let module_report = reporter.generate(&report.issues);
                    fs::write(module_report_path, module_report).await?;
                }
            }
        }
        OutputFormat::Markdown => {
            let reporter = MarkdownReporter;
            
            // Overall report
            let summary_path = output_dir.join("summary.md");
            let summary_report = reporter.generate(all_issues);
            fs::write(summary_path, summary_report).await?;
            
            // Per-module reports
            if !module_reports.is_empty() {
                let modules_dir = output_dir.join("modules");
                fs::create_dir_all(&modules_dir).await?;
                
                for (module_path, report) in module_reports {
                    let file_name = PathBuf::from(module_path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .replace(".mv", ".md");
                    
                    let module_report_path = modules_dir.join(file_name);
                    let module_report = reporter.generate(&report.issues);
                    fs::write(module_report_path, module_report).await?;
                }
            }
        }
        OutputFormat::Html => {
            let reporter = HtmlReporter;
            
            // Overall report
            let summary_path = output_dir.join("summary.html");
            let summary_report = reporter.generate(all_issues);
            fs::write(summary_path, summary_report).await?;
            
            if dashboard {
                // Generate interactive dashboard
                generate_html_dashboard(module_reports, all_issues, output_dir).await?;
            }
        }
        _ => {
            println!("Format not supported for directory scanning");
        }
    }
    
    println!("Reports saved to: {}", output_dir.display());
    
    Ok(())
}

async fn generate_html_dashboard(
    module_reports: &[(String, AnalysisReport)],
    all_issues: &[SecurityIssue],
    output_dir: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let dashboard_path = output_dir.join("dashboard.html");
    
    let mut html = String::new();
    
    // HTML header
    html.push_str("<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>SUI Security Dashboard</title>
    <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { border: 1px solid #ddd; border-radius: 5px; padding: 15px; }
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .severity-info { color: #17a2b8; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>SUI Security Analysis Dashboard</h1>
    <p>Generated: ");
    
    html.push_str(&chrono::Utc::now().to_rfc3339());
    html.push_str("</p>
    <p>Modules scanned: ");
    html.push_str(&module_reports.len().to_string());
    html.push_str(" | Total issues: ");
    html.push_str(&all_issues.len().to_string());
    html.push_str("</p>
    
    <div class=\"dashboard\">
        <div class=\"card\">
            <h3>Severity Distribution</h3>
            <canvas id=\"severityChart\"></canvas>
        </div>
        
        <div class=\"card\">
            <h3>Issue Categories</h3>
            <canvas id=\"categoryChart\"></canvas>
        </div>
        
        <div class=\"card\">
            <h3>Top Issues</h3>
            <table>
                <tr><th>ID</th><th>Count</th><th>Severity</th></tr>");
    
    // Count issues by ID
    let mut issue_counts = std::collections::HashMap::new();
    let mut issue_severities = std::collections::HashMap::new();
    
    for issue in all_issues {
        *issue_counts.entry(&issue.id).or_insert(0) += 1;
        issue_severities.insert(&issue.id, &issue.severity);
    }
    
    let mut top_issues: Vec<_> = issue_counts.into_iter().collect();
    top_issues.sort_by(|a, b| b.1.cmp(&a.1));
    
    for (id, count) in top_issues.iter().take(10) {
        let severity = issue_severities.get(id).unwrap_or(&&Severity::Info);
        let severity_class = match severity {
            Severity::Critical => "severity-critical",
            Severity::High => "severity-high",
            Severity::Medium => "severity-medium",
            Severity::Low => "severity-low",
            Severity::Info => "severity-info",
        };
        
        html.push_str(&format!("
                <tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td class=\"{}\">{:?}</td>
                </tr>", id, count, severity_class, severity));
    }
    
    html.push_str("
            </table>
        </div>
        
        <div class=\"card\">
            <h3>Module Overview</h3>
            <table>
                <tr><th>Module</th><th>Issues</th><th>Critical</th><th>High</th></tr>");
    
    for (module_path, report) in module_reports.iter().take(10) {
        let critical = report.issues.iter()
            .filter(|i| i.severity == Severity::Critical)
            .count();
        
        let high = report.issues.iter()
            .filter(|i| i.severity == Severity::High)
            .count();
        
        let total = report.issues.len();
        
        let path_buf = PathBuf::from(module_path);
    let module_name = path_buf
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
        
        html.push_str(&format!("
                <tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td class=\"severity-critical\">{}</td>
                    <td class=\"severity-high\">{}</td>
                </tr>", module_name, total, critical, high));
    }
    
    html.push_str("
            </table>
        </div>
    </div>
    
    <script>
        // Severity chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        const severityChart = new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [");
    
    // Add severity data
    let severities = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];
    for severity in severities {
        let count = all_issues.iter()
            .filter(|i| i.severity == severity)
            .count();
        html.push_str(&count.to_string());
        html.push_str(", ");
    }
    
    html.push_str("],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#28a745',
                        '#17a2b8'
                    ]
                }]
            }
        });
        
        // Category chart
        const categoryCtx = document.getElementById('categoryChart').getContext('2d');
        const categoryChart = new Chart(categoryCtx, {
            type: 'bar',
            data: {
                labels: [");
    
    // Add category labels
    let categories = ["AC", "AR", "RE", "OB", "EV", "OR", "RN", "TM", "GA", "LG"];
    let category_names = [
        "Access Control", "Arithmetic", "Reentrancy", "Objects", 
        "Events", "Oracles", "Randomness", "Timing", "Gas", "Logic"
    ];
    
    for name in category_names.iter() {
        html.push_str(&format!("'{}', ", name));
    }
    
    html.push_str("],
                datasets: [{
                    label: 'Issues by Category',
                    data: [");
    
    // Add category data
    for category in categories {
        let count = all_issues.iter()
            .filter(|i| i.id.starts_with(category))
            .count();
        html.push_str(&count.to_string());
        html.push_str(", ");
    }
    
    html.push_str("],
                    backgroundColor: '#007bff'
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    </script>
</body>
</html>");
    
    fs::write(dashboard_path, html).await?;
    Ok(())
}

fn generate_sarif_report(result: &AnalysisReport) -> String {
    // Generate SARIF (Static Analysis Results Interchange Format) report
    // This format is used by GitHub Code Scanning and other CI/CD tools
    
    let mut sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SUI Security Analyzer",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/sui-security/sui-analyzer",
                    "rules": []
                }
            },
            "results": []
        }]
    });
    
    // Add rules (detectors)
    let registry = DetectorRegistry::with_all_detectors();
    
    for detector in registry.all_detectors() {
        let rule = serde_json::json!({
            "id": detector.id(),
            "name": detector.name(),
            "shortDescription": {
                "text": detector.description()
            },
            "defaultConfiguration": {
                "level": match detector.default_severity() {
                    Severity::Critical => "error",
                    Severity::High => "error",
                    Severity::Medium => "warning",
                    Severity::Low => "note",
                    Severity::Info => "note",
                }
            }
        });
        
        sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array_mut()
            .unwrap()
            .push(rule);
    }
    
    // Add results (issues)
    for issue in &result.issues {
        let result_obj = serde_json::json!({
            "ruleId": issue.id,
            "level": match issue.severity {
                Severity::Critical => "error",
                Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
                Severity::Info => "note",
            },
            "message": {
                "text": issue.title
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": format!("{}.mv", issue.location.module_name)
                    },
                    "region": {
                        "startLine": issue.location.line.unwrap_or(1) as i64,
                        "startColumn": issue.location.column.unwrap_or(1) as i64
                    }
                }
            }]
        });
        
        sarif["runs"][0]["results"]
            .as_array_mut()
            .unwrap()
            .push(result_obj);
    }
    
    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

fn generate_junit_report(result: &AnalysisReport) -> String {
    // Generate JUnit XML report for test integration
    
    let mut xml = String::new();
    
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!("<testsuite name=\"SUI Security Analysis\" tests=\"{}\" failures=\"{}\" errors=\"0\">\n",
        result.issues.len(),
        result.issues.iter().filter(|i| i.severity == Severity::Critical || i.severity == Severity::High).count()
    ));
    
    for issue in &result.issues {
        let test_name = format!("{}.{}", issue.id, issue.location.function_name);
        let failure_type = match issue.severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        };
        
        xml.push_str(&format!("  <testcase name=\"{}\" classname=\"{}\">\n", 
            test_name, issue.location.module_name));
        
        if issue.severity != Severity::Info {
            xml.push_str(&format!("    <failure message=\"{}\" type=\"{}\">\n", 
                issue.title, failure_type));
            xml.push_str(&format!("      {}\n", issue.description));
            xml.push_str(&format!("      Recommendation: {}\n", issue.recommendation));
            xml.push_str("    </failure>\n");
        }
        
        xml.push_str("  </testcase>\n");
    }
    
    xml.push_str("</testsuite>\n");
    
    xml
}

fn generate_full_config() -> Config {
    Config {
        general: GeneralConfig {
            severity_threshold: Severity::Low,
            include_test_code: false,
            max_issues_per_module: 100,
            parallel_analysis: true,
        },
        detectors: generate_detector_configs(),
        reporting: ReportingConfig {
            output_format: "console".to_string(),
            include_recommendations: true,
            include_references: true,
            group_by_severity: true,
            group_by_category: true,
        },
        paths: PathsConfig {
            exclude_patterns: vec!["test_*.mv".to_string(), "*_test.mv".to_string()],
            include_patterns: vec!["*.mv".to_string()],
        },
    }
}

fn generate_default_config() -> Config {
    Config {
        general: GeneralConfig {
            severity_threshold: Severity::Medium,
            include_test_code: false,
            max_issues_per_module: 50,
            parallel_analysis: true,
        },
        detectors: generate_essential_detector_configs(),
        reporting: ReportingConfig {
            output_format: "console".to_string(),
            include_recommendations: true,
            include_references: true,
            group_by_severity: true,
            group_by_category: false,
        },
        paths: PathsConfig {
            exclude_patterns: vec!["test_*.mv".to_string()],
            include_patterns: vec!["*.mv".to_string()],
        },
    }
}

fn generate_detector_configs() -> Vec<DetectorConfig> {
    let mut configs = Vec::new();
    
    // Access Control detectors
    for i in 1..=15 {
        configs.push(DetectorConfig {
            id: format!("AC-{:03}", i),
            enabled: true,
            severity: match i {
                1..=3 => Severity::Critical,
                4..=6 => Severity::High,
                7..=10 => Severity::Medium,
                _ => Severity::Low,
            },
        });
    }
    
    // Add all other detectors similarly...
    
    configs
}

fn generate_essential_detector_configs() -> Vec<DetectorConfig> {
    // Only enable critical and high severity detectors by default
    vec![
        // Critical access control
        DetectorConfig { id: "AC-001".to_string(), enabled: true, severity: Severity::Critical },
        DetectorConfig { id: "AC-002".to_string(), enabled: true, severity: Severity::Critical },
        DetectorConfig { id: "AC-003".to_string(), enabled: true, severity: Severity::Critical },
        
        // Critical arithmetic
        DetectorConfig { id: "AR-001".to_string(), enabled: true, severity: Severity::Critical },
        DetectorConfig { id: "AR-002".to_string(), enabled: true, severity: Severity::Critical },
        DetectorConfig { id: "AR-011".to_string(), enabled: true, severity: Severity::Critical },
        
        // Critical reentrancy
        DetectorConfig { id: "RE-001".to_string(), enabled: true, severity: Severity::Critical },
        
        // Critical objects
        DetectorConfig { id: "OB-001".to_string(), enabled: true, severity: Severity::Critical },
        DetectorConfig { id: "OB-002".to_string(), enabled: true, severity: Severity::Critical },
    ]
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Config {
    general: GeneralConfig,
    detectors: Vec<DetectorConfig>,
    reporting: ReportingConfig,
    paths: PathsConfig,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct GeneralConfig {
    severity_threshold: Severity,
    include_test_code: bool,
    max_issues_per_module: usize,
    parallel_analysis: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DetectorConfig {
    id: String,
    enabled: bool,
    severity: Severity,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ReportingConfig {
    output_format: String,
    include_recommendations: bool,
    include_references: bool,
    group_by_severity: bool,
    group_by_category: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PathsConfig {
    exclude_patterns: Vec<String>,
    include_patterns: Vec<String>,
}

#[derive(serde::Serialize)]
struct DetectorInfo {
    id: String,
    name: String,
    description: String,
    severity: String,
    category: String,
    enabled: bool,
}

impl From<&Box<dyn SecurityDetector>> for DetectorInfo {
    fn from(detector: &Box<dyn SecurityDetector>) -> Self {
        DetectorInfo {
            id: detector.id().to_string(),
            name: detector.name().to_string(),
            description: detector.description().to_string(),
            severity: format!("{:?}", detector.default_severity()),
            category: detector.id().split('-').next().unwrap_or("unknown").to_string(),
            enabled: true, // Default to enabled
        }
    }
}