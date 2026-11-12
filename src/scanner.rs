use crate::models::{Severity, Vulnerability};
use crate::rules::CompiledRule;
use std::fs;
use std::io;
use std::path::{Component, Path};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Node, Parser, QueryCursor};

pub fn scan_file(
    path: &Path,
    root: &Path,
    rules: &[CompiledRule],
    language: &Language,
) -> io::Result<Vec<Vulnerability>> {
    let content = fs::read_to_string(path)
        .map_err(|err| io::Error::new(err.kind(), format!("{}: {err}", path.display())))?;
    let relative = path.strip_prefix(root).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: {err}", path.display()),
        )
    })?;
    scan_source(path, relative, &content, rules, language)
}

fn is_suppressed(lines: &[&str], row: usize, rule_id: &str) -> bool {
    let tag = format!("larascan-ignore {rule_id}");
    lines.get(row).is_some_and(|line| line.contains(&tag))
        || row
            .checked_sub(1)
            .and_then(|i| lines.get(i))
            .is_some_and(|line| line.contains(&tag))
}

fn has_strict_types(root: Node<'_>, source: &str) -> bool {
    let mut cursor = root.walk();
    let mut children = root.named_children(&mut cursor);
    let first = children.find(|node| !matches!(node.kind(), "php_tag" | "comment" | "text"));
    let Some(declaration) = first.filter(|node| node.kind() == "declare_statement") else {
        return false;
    };
    let mut cursor = declaration.walk();
    declaration.named_children(&mut cursor).any(|node| {
        if node.kind() != "declare_directive" {
            return false;
        }
        let text = &source[node.byte_range()];
        text.split_once('=')
            .is_some_and(|(name, value)| name.trim() == "strict_types" && value.trim() == "1")
    })
}

fn scan_source(
    path: &Path,
    relative: &Path,
    content: &str,
    rules: &[CompiledRule],
    language: &Language,
) -> io::Result<Vec<Vulnerability>> {
    let mut vulnerabilities = Vec::new();
    let file = path.to_string_lossy().replace('\\', "/");
    let lines: Vec<&str> = content.lines().collect();

    if file.ends_with(".blade.php") {
        for (row, line) in lines.iter().enumerate() {
            if line.contains("{!!")
                && line.contains("!!}")
                && !is_suppressed(&lines, row, "SEC-004")
            {
                vulnerabilities.push(Vulnerability {
                    file: file.clone(),
                    line: row + 1,
                    rule_id: "SEC-004".to_string(),
                    description: "Impresión de variables sin escapar en vistas Blade (Riesgo XSS)"
                        .to_string(),
                    snippet: line.trim().to_string(),
                    severity: Severity::High,
                });
            }
        }
        return Ok(vulnerabilities);
    }

    let mut parser = Parser::new();
    parser.set_language(language).map_err(|err| {
        io::Error::other(format!(
            "{}: error al iniciar el parser PHP: {err}",
            path.display()
        ))
    })?;
    let tree = parser.parse(content, None).ok_or_else(|| {
        io::Error::other(format!(
            "{}: no se pudo analizar el archivo PHP",
            path.display()
        ))
    })?;
    if !has_strict_types(tree.root_node(), content) && !is_suppressed(&lines, 0, "STD-002") {
        vulnerabilities.push(Vulnerability {
            file: file.clone(),
            line: 1,
            rule_id: "STD-002".to_string(),
            description: "Falta declaración de strict_types al inicio del archivo PHP".to_string(),
            snippet: lines.first().unwrap_or(&"").to_string(),
            severity: Severity::Low,
        });
    }

    let in_config =
        matches!(relative.components().next(), Some(Component::Normal(name)) if name == "config");
    for compiled in rules {
        let rule = &compiled.rule;
        if rule.id == "STD-001" && in_config {
            continue;
        }
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&compiled.query, tree.root_node(), content.as_bytes());
        while let Some(m) = matches.next() {
            if rule.id == "SEC-003" {
                let value_index = compiled
                    .query
                    .capture_index_for_name("value")
                    .ok_or_else(|| io::Error::other("Regla SEC-003: falta la captura @value"))?;
                let value = m
                    .captures()
                    .iter()
                    .find(|capture| capture.index == value_index)
                    .ok_or_else(|| io::Error::other("Regla SEC-003: no se capturó el valor"))?;
                let mut value_cursor = value.node.walk();
                if value.node.kind() == "encapsed_string"
                    && value
                        .node
                        .named_children(&mut value_cursor)
                        .any(|child| !matches!(child.kind(), "string_content" | "escape_sequence"))
                {
                    continue;
                }
            }
            if rule.id == "SEC-005" {
                let Some(array_index) = compiled.query.capture_index_for_name("array") else {
                    return Err(io::Error::other("Regla SEC-005: falta la captura @array"));
                };
                let Some(array) = m
                    .captures()
                    .iter()
                    .find(|capture| capture.index == array_index)
                else {
                    return Err(io::Error::other("Regla SEC-005: no se capturó el arreglo"));
                };
                let mut array_cursor = array.node.walk();
                if array
                    .node
                    .named_children(&mut array_cursor)
                    .any(|child| child.kind() == "array_element_initializer")
                {
                    continue;
                }
            }
            for capture in m
                .captures()
                .iter()
                .filter(|capture| capture.index == compiled.finding_capture)
            {
                let row = capture.node.start_position().row;
                if is_suppressed(&lines, row, rule.id) {
                    continue;
                }
                vulnerabilities.push(Vulnerability {
                    file: file.clone(),
                    line: row + 1,
                    rule_id: rule.id.to_string(),
                    description: rule.description.to_string(),
                    snippet: lines
                        .get(row)
                        .map(|line| line.trim().to_string())
                        .unwrap_or_default(),
                    severity: rule.severity.clone(),
                });
            }
        }
    }
    Ok(vulnerabilities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{compile_rules, get_rules};

    fn findings(path: &str, content: &str, rule_id: &str) -> Vec<Vulnerability> {
        let language = Language::from(tree_sitter_php::LANGUAGE_PHP);
        let rules = compile_rules(get_rules(), &language).unwrap();
        scan_source(Path::new(path), Path::new(path), content, &rules, &language)
            .unwrap()
            .into_iter()
            .filter(|finding| finding.rule_id == rule_id)
            .collect()
    }

    #[test]
    fn every_ast_rule_detects_expected_calls_and_ignores_safe_examples() {
        let cases = [
            ("SEC-001", "<?php\nDB::raw($sql);", true),
            ("SEC-001", "<?php\n$query->whereRaw($sql);", true),
            ("SEC-001", "<?php\n$query?->selectRaw($sql);", true),
            (
                "SEC-001",
                "<?php\n// DB::raw($sql);\n$query->where('id', 1);",
                false,
            ),
            ("SEC-002", "<?php\nexec($command);", true),
            ("SEC-002", "<?php\neval($code);", true),
            ("SEC-002", "<?php\n`ls`;", true),
            (
                "SEC-002",
                "<?php\n// exec($command);\n$text = 'system($cmd)';",
                false,
            ),
            ("SEC-003", "<?php\n$password = 'hardcoded';", true),
            ("SEC-003", "<?php\n$api_key = \"hardcoded\";", true),
            ("SEC-003", "<?php\n$token = \"$input\";", false),
            (
                "SEC-003",
                "<?php\n$token = $request->input('token');",
                false,
            ),
            (
                "SEC-005",
                "<?php\nclass User { protected $guarded = []; }",
                true,
            ),
            (
                "SEC-005",
                "<?php\nclass User { protected $guarded = array(); }",
                true,
            ),
            (
                "SEC-005",
                "<?php\nclass User { protected $guarded = ['id']; }",
                false,
            ),
            ("SEC-006", "<?php\nunserialize($input);", true),
            (
                "SEC-006",
                "<?php\n// unserialize($input);\nserialize($input);",
                false,
            ),
            ("STD-001", "<?php\nenv('APP_KEY');", true),
            ("STD-001", "<?php\nconfig('app.key');", false),
            ("STD-003", "<?php\ndd($input);", true),
            ("STD-003", "<?php\n// dd($input);\nlogger($input);", false),
        ];
        for (rule, source, expected) in cases {
            let actual = findings("app/test.php", source, rule);
            assert_eq!(actual.len(), usize::from(expected), "{rule}: {source}");
        }
    }

    #[test]
    fn documented_method_and_function_variants_are_detected() {
        let cases = [
            ("SEC-001", "raw", "DB::{name}($x);"),
            ("SEC-001", "whereRaw", "$q->{name}($x);"),
            ("SEC-001", "selectRaw", "$q->{name}($x);"),
            ("SEC-001", "orderByRaw", "$q->{name}($x);"),
            ("SEC-001", "havingRaw", "$q->{name}($x);"),
            ("SEC-002", "eval", "{name}($x);"),
            ("SEC-002", "exec", "{name}($x);"),
            ("SEC-002", "passthru", "{name}($x);"),
            ("SEC-002", "shell_exec", "{name}($x);"),
            ("SEC-002", "system", "{name}($x);"),
            ("STD-003", "dd", "{name}($x);"),
            ("STD-003", "dump", "{name}($x);"),
            ("STD-003", "var_dump", "{name}($x);"),
            ("STD-003", "ray", "{name}($x);"),
        ];
        for (rule, name, template) in cases {
            let source = format!("<?php\n{}", template.replace("{name}", name));
            assert_eq!(
                findings("app/test.php", &source, rule).len(),
                1,
                "{rule}: {source}"
            );
        }
    }

    #[test]
    fn matches_report_once_per_call_and_support_suppression() {
        let source = "<?php\nexec($first);\nexec($second);\n// larascan-ignore SEC-002\nexec($ignored);\nexec($ignoredToo); // larascan-ignore SEC-002\n";
        let result = findings("app/test.php", source, "SEC-002");
        assert_eq!(
            result.iter().map(|f| f.line).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(
            result
                .iter()
                .all(|finding| finding.severity == Severity::Critical)
        );
        assert_eq!(
            findings("app/test.php", "<?php\nexec('a'); exec('b');", "SEC-002").len(),
            2
        );
    }

    #[test]
    fn env_is_exempt_only_in_project_config_directory() {
        let source = "<?php\nenv('APP_KEY');";
        assert_eq!(findings("config/app.php", source, "STD-001").len(), 0);
        assert_eq!(
            findings("app/config/feature.php", source, "STD-001").len(),
            1
        );
        assert_eq!(
            findings("app/myconfig/feature.php", source, "STD-001").len(),
            1
        );
    }

    #[test]
    fn strict_types_must_be_an_initial_declaration_not_a_comment_or_string() {
        for source in [
            "<?php\ndeclare(strict_types=1);\n",
            "<?php\n// comment\ndeclare ( strict_types = 1 );",
        ] {
            assert!(
                findings("app/test.php", source, "STD-002").is_empty(),
                "{source}"
            );
        }
        for source in [
            "<?php\n",
            "<?php\n// declare(strict_types=1)\n",
            "<?php\n$x = 'declare(strict_types=1)';",
            "<?php\n$x = 1;\ndeclare(strict_types=1);",
            "<?php\ndeclare(strict_types=0);",
        ] {
            assert_eq!(
                findings("app/test.php", source, "STD-002").len(),
                1,
                "{source}"
            );
        }
    }

    #[test]
    fn blade_finding_supports_suppression_and_does_not_run_php_rules() {
        let source = "{{ $safe }}\n{!! $unsafe !!}\n{{-- larascan-ignore SEC-004 --}}\n{!! $ignored !!}\n{!! $other !!} {{-- larascan-ignore SEC-004 --}}\n";
        let result = findings("resources/views/test.blade.php", source, "SEC-004");
        assert_eq!(result.iter().map(|f| f.line).collect::<Vec<_>>(), vec![2]);
        assert!(findings("resources/views/test.blade.php", source, "STD-002").is_empty());
    }
}
