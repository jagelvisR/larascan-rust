use clap::Parser;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Escáner SAST AST de alto rendimiento para proyectos Laravel")]
pub struct Args {
    /// Ruta del proyecto Laravel a analizar
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Generar salida estructurada en formato JSON
    #[arg(short, long)]
    pub json: bool,

    /// Exportar reporte en formato SARIF v2.1.0 para GitHub Security / GitLab CI
    #[arg(long)]
    pub sarif: bool,

    /// Finalizar con código de salida 1 si se detectan hallazgos Críticos o Altos
    #[arg(long)]
    pub fail_on_high: bool,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug)]
pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub query_str: &'static str,
    pub severity: Severity,
}

#[derive(Debug, Serialize, Clone)]
pub struct Vulnerability {
    pub file: String,
    pub line: usize,
    pub rule_id: String,
    pub description: String,
    pub snippet: String,
    pub severity: Severity,
}