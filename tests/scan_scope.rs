use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    base: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "larascan-scope-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let project = base.join("vendor").join("project");
        fs::create_dir_all(&project).unwrap();
        Self { base, project }
    }

    fn write(&self, path: &str, content: &str) {
        let path = self.project.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_larascan"))
            .arg("--path")
            .arg(&self.project)
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.base).unwrap();
    }
}

fn project_fixture() -> Fixture {
    let fixture = Fixture::new();
    for path in [
        "app/Controller.php",
        "routes/web.php",
        "config/app.php",
        "database/migrations/create.php",
        "tests/Example.php",
        "custom/Feature.php",
        "bootstrap/app.php",
        "public/index.php",
    ] {
        fixture.write(path, "<?php\n");
    }
    fixture.write("resources/views/home.blade.php", "{!! $content !!}");
    for path in [
        "vendor/package/src/Library.php",
        "storage/framework/views/compiled.php",
        "bootstrap/cache/packages.php",
        "node_modules/package/index.php",
        ".git/hooks/hook.php",
        "custom/vendor/package.php",
        "custom/bootstrap/cache/generated.php",
    ] {
        fixture.write(path, "<?php\nexec('command');\n");
    }
    fixture
}

fn normalized(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[test]
fn json_and_sarif_include_only_project_sources() {
    let fixture = project_fixture();
    let expected: Vec<String> = [
        "app/Controller.php",
        "routes/web.php",
        "config/app.php",
        "database/migrations/create.php",
        "tests/Example.php",
        "custom/Feature.php",
        "bootstrap/app.php",
        "public/index.php",
        "resources/views/home.blade.php",
    ]
    .iter()
    .map(|path| normalized(&fixture.project.join(path)))
    .collect();

    for format in ["--json", "--sarif"] {
        let output = fixture.run(&[format]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let results = if format == "--json" {
            report.as_array().unwrap()
        } else {
            report["runs"][0]["results"].as_array().unwrap()
        };
        let mut files: Vec<&str> = results
            .iter()
            .map(|result| {
                if format == "--json" {
                    result["file"].as_str().unwrap()
                } else {
                    result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                        .as_str()
                        .unwrap()
                }
            })
            .collect();
        files.sort_unstable();
        let mut expected_files: Vec<&str> = expected.iter().map(String::as_str).collect();
        expected_files.sort_unstable();
        assert_eq!(files, expected_files);
    }
}

#[test]
fn excluded_findings_do_not_fail_ci_but_project_findings_do() {
    let fixture = project_fixture();
    fixture.write("resources/views/home.blade.php", "{{ $content }}");
    let output = fixture.run(&["--json", "--fail-on-high"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    fixture.write("app/Controller.php", "<?php\nexec('command');\n");
    let output = fixture.run(&["--json", "--fail-on-high"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Fallo en auditoría"));
}

#[test]
fn nonexistent_project_fails_instead_of_reporting_success() {
    let fixture = Fixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_larascan"))
        .arg("--path")
        .arg(fixture.project.join("missing"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Error al recorrer el proyecto"));
}

#[test]
fn unreadable_source_fails_instead_of_reporting_success() {
    let fixture = Fixture::new();
    fs::write(fixture.project.join("invalid.php"), [0xff]).unwrap();
    let output = fixture.run(&["--json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error al analizar el proyecto"));
    assert!(stderr.contains("invalid.php"));
}
