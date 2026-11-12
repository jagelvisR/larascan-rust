mod models;
mod reporter;
mod rules;
mod scanner;

use clap::Parser;
use models::{Args, Severity, Vulnerability};
use rayon::prelude::*;
use reporter::{generate_sarif, print_report};
use rules::{compile_rules, get_rules};
use scanner::scan_file;
use std::path::{Path, PathBuf};
use std::process::exit;
use walkdir::{DirEntry, WalkDir};

fn include_entry(entry: &DirEntry, root: &Path) -> bool {
    let relative = match entry.path().strip_prefix(root) {
        Ok(relative) => relative,
        Err(_) => return false,
    };

    if relative.as_os_str().is_empty() {
        return true;
    }

    let name = entry.file_name();
    if entry.file_type().is_dir()
        && (name == "vendor" || name == "storage" || name == "node_modules" || name == ".git")
    {
        return false;
    }

    !(entry.file_type().is_dir()
        && name == "cache"
        && relative.parent().and_then(Path::file_name) == Some("bootstrap".as_ref()))
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>, walkdir::Error> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| include_entry(entry, root))
    {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "php") {
            files.push(entry.into_path());
        }
    }
    Ok(files)
}

fn main() {
    let args = Args::parse();
    let language = tree_sitter::Language::from(tree_sitter_php::LANGUAGE_PHP);
    let rules = match compile_rules(get_rules(), &language) {
        Ok(rules) => rules,
        Err(err) => {
            eprintln!("Error al compilar reglas: {err}");
            exit(1);
        }
    };

    let files = match collect_files(&args.path) {
        Ok(files) => files,
        Err(err) => {
            eprintln!("Error al recorrer el proyecto: {err}");
            exit(1);
        }
    };

    // Procesar archivos concurrentemente con Rayon
    let results: Result<Vec<Vec<Vulnerability>>, _> = files
        .par_iter()
        .map(|path| scan_file(path, &args.path, &rules, &language))
        .collect();
    let vulnerabilities: Vec<Vulnerability> = match results {
        Ok(results) => results.into_iter().flatten().collect(),
        Err(err) => {
            eprintln!("Error al analizar el proyecto: {err}");
            exit(1);
        }
    };

    if args.sarif {
        println!("{}", generate_sarif(&vulnerabilities));
    } else if args.json {
        match serde_json::to_string_pretty(&vulnerabilities) {
            Ok(json_output) => println!("{}", json_output),
            Err(err) => eprintln!("Error al serializar el reporte JSON: {}", err),
        }
    } else {
        print_report(&vulnerabilities);
    }

    // Código de salida para pipelines de CI/CD
    if args.fail_on_high
        && vulnerabilities
            .iter()
            .any(|v| v.severity == Severity::Critical || v.severity == Severity::High)
    {
        eprintln!("Fallo en auditoría de seguridad: se encontraron hallazgos Críticos o Altos.");
        exit(1);
    }
}
