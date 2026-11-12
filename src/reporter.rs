use crate::models::{Severity, Vulnerability};
use colored::*;
use serde_json::json;

pub fn print_report(vulnerabilities: &[Vulnerability]) {
    println!("\n{}", "=== REPORTE DE AUDITORÍA LARAVEL (AST TREE-SITTER) ===".bold().cyan());
    println!("Total de hallazgos encontrados: {}\n", vulnerabilities.len());

    for vuln in vulnerabilities {
        let sev_tag = match vuln.severity {
            Severity::Critical => "[CRITICAL]".bold().on_red().white(),
            Severity::High => "[HIGH]".red().bold(),
            Severity::Medium => "[MEDIUM]".yellow().bold(),
            Severity::Low => "[LOW]".blue().bold(),
        };

        println!(
            "{} {} ({}:{})",
            sev_tag,
            vuln.rule_id.bold(),
            vuln.file.bold(),
            vuln.line
        );
        println!("   Regla: {}", vuln.description);
        println!("   Código: {}\n", vuln.snippet.italic().dimmed());
    }
}

pub fn generate_sarif(vulnerabilities: &[Vulnerability]) -> String {
    let results: Vec<_> = vulnerabilities
        .iter()
        .map(|v| {
            let level = match v.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low => "note",
            };

            json!({
                "ruleId": v.rule_id,
                "level": level,
                "message": { "text": v.description },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": v.file },
                        "region": { "startLine": v.line }
                    }
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Larascan",
                    "informationUri": "https://github.com/tu-usuario/larascan",
                    "version": "0.2.0"
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}