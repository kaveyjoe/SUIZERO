// src/reporters/mod.rs
use crate::types::{SecurityIssue, Severity};
use serde_json;
use std::fs;
use comfy_table::{Table, Cell, ContentArrangement};

pub trait ReportGenerator {
    fn generate(&self, issues: &[SecurityIssue]) -> String;
    fn save(&self, issues: &[SecurityIssue], path: &str) -> Result<(), String>;
}

pub struct ConsoleReporter;

impl ReportGenerator for ConsoleReporter {
    fn generate(&self, issues: &[SecurityIssue]) -> String {
        let mut table = Table::new();
        table
            .set_header(vec![
                "ID", "Severity", "Title", "Location", "Description"
            ])
            .set_content_arrangement(ContentArrangement::Dynamic);
        
        for issue in issues {
            table.add_row(vec![
                Cell::new(&issue.id),
                Cell::new(format!("{:?}", issue.severity))
                    .fg(match issue.severity {
                        Severity::Critical => comfy_table::Color::Red,
                        Severity::High => comfy_table::Color::Red,
                        Severity::Medium => comfy_table::Color::Yellow,
                        Severity::Low => comfy_table::Color::Green,
                        Severity::Info => comfy_table::Color::Blue,
                    }),
                Cell::new(&issue.title),
                Cell::new(format!("{}::{}", issue.location.module_name, issue.location.function_name)),
                Cell::new(issue.description.chars().take(100).collect::<String>()),
            ]);
        }
        
        format!("{}\n\nTotal issues found: {}", table, issues.len())
    }
    
    fn save(&self, issues: &[SecurityIssue], path: &str) -> Result<(), String> {
        let output = self.generate(issues);
        fs::write(path, output)
            .map_err(|e| format!("Failed to write report: {}", e))
    }
}

pub struct JsonReporter;

impl ReportGenerator for JsonReporter {
    fn generate(&self, issues: &[SecurityIssue]) -> String {
        serde_json::to_string_pretty(issues)
            .unwrap_or_else(|_| "[]".to_string())
    }
    
    fn save(&self, issues: &[SecurityIssue], path: &str) -> Result<(), String> {
        let json = self.generate(issues);
        fs::write(path, json)
            .map_err(|e| format!("Failed to write JSON report: {}", e))
    }
}

pub struct MarkdownReporter;

impl ReportGenerator for MarkdownReporter {
    fn generate(&self, issues: &[SecurityIssue]) -> String {
        let mut md = String::new();
        
        md.push_str("# Security Analysis Report\n\n");
        
        // Summary table
        let critical = issues.iter().filter(|i| i.severity == Severity::Critical).count();
        let high = issues.iter().filter(|i| i.severity == Severity::High).count();
        let medium = issues.iter().filter(|i| i.severity == Severity::Medium).count();
        let low = issues.iter().filter(|i| i.severity == Severity::Low).count();
        
        md.push_str("## Summary\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("|----------|-------|\n");
        md.push_str(&format!("| Critical | {} |\n", critical));
        md.push_str(&format!("| High | {} |\n", high));
        md.push_str(&format!("| Medium | {} |\n", medium));
        md.push_str(&format!("| Low | {} |\n", low));
        md.push_str(&format!("| Total | {} |\n\n", issues.len()));
        
        // Detailed findings
        md.push_str("## Detailed Findings\n\n");
        
        for issue in issues {
            md.push_str(&format!("### {}: {}\n\n", issue.id, issue.title));
            md.push_str(&format!("**Severity**: {:?}\n\n", issue.severity));
            md.push_str(&format!("**Location**: {}::{}\n\n", 
                issue.location.module_name, issue.location.function_name));
            md.push_str(&format!("**Description**: {}\n\n", issue.description));
            
            if let Some(source) = &issue.source_code {
                md.push_str("**Code**:\n```move\n");
                md.push_str(source);
                md.push_str("\n```\n\n");
            }
            
            md.push_str("**Recommendation**:\n");
            md.push_str(&issue.recommendation);
            md.push_str("\n\n");
            
            if !issue.references.is_empty() {
                md.push_str("**References**:\n");
                for ref_url in &issue.references {
                    md.push_str(&format!("- {}\n", ref_url));
                }
                md.push_str("\n");
            }
            
            md.push_str("---\n\n");
        }
        
        md
    }
    
    fn save(&self, issues: &[SecurityIssue], path: &str) -> Result<(), String> {
        let md = self.generate(issues);
        fs::write(path, md)
            .map_err(|e| format!("Failed to write Markdown report: {}", e))
    }
}

pub struct HtmlReporter;

impl ReportGenerator for HtmlReporter {
    fn generate(&self, issues: &[SecurityIssue]) -> String {
        let mut html = String::new();
        html.push_str("<html><head><title>SUI Security Analysis Report</title>");
        html.push_str("<style>");
        html.push_str("body { font-family: sans-serif; margin: 20px; }");
        html.push_str(".issue { border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; border-radius: 5px; }");
        html.push_str(".critical { border-left: 5px solid red; }");
        html.push_str(".high { border-left: 5px solid orange; }");
        html.push_str(".medium { border-left: 5px solid yellow; }");
        html.push_str(".low { border-left: 5px solid green; }");
        html.push_str(".info { border-left: 5px solid blue; }");
        html.push_str("</style></head><body>");
        html.push_str("<h1>Security Analysis Report</h1>");
        html.push_str(&format!("<p>Total issues found: {}</p>", issues.len()));
        
        for issue in issues {
            let severity_class = match issue.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            
            html.push_str(&format!("<div class='issue {}'>", severity_class));
            html.push_str(&format!("<h3>[{}] {}</h3>", issue.id, issue.title));
            html.push_str(&format!("<p><strong>Severity:</strong> {:?}</p>", issue.severity));
            html.push_str(&format!("<p><strong>Location:</strong> {}::{}</p>", 
                issue.location.module_name, issue.location.function_name));
            html.push_str(&format!("<p><strong>Description:</strong> {}</p>", issue.description));
            
            if let Some(source) = &issue.source_code {
                html.push_str("<pre><code>");
                html.push_str(source);
                html.push_str("</code></pre>");
            }
            
            html.push_str(&format!("<p><strong>Recommendation:</strong> {}</p>", issue.recommendation));
            
            if !issue.references.is_empty() {
                html.push_str("<ul>");
                for ref_url in &issue.references {
                    html.push_str(&format!("<li><a href='{}'>{}</a></li>", ref_url, ref_url));
                }
                html.push_str("</ul>");
            }
            html.push_str("</div>");
        }
        
        html.push_str("</body></html>");
        html
    }
    
    fn save(&self, issues: &[SecurityIssue], path: &str) -> Result<(), String> {
        let html = self.generate(issues);
        fs::write(path, html)
            .map_err(|e| format!("Failed to write HTML report: {}", e))
    }
}