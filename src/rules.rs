use crate::models::{Rule, Severity};
use tree_sitter::{Language, Query};

pub struct CompiledRule {
    pub rule: Rule,
    pub query: Query,
    pub finding_capture: u32,
}

pub fn compile_rules(rules: Vec<Rule>, language: &Language) -> Result<Vec<CompiledRule>, String> {
    rules
        .into_iter()
        .map(|rule| {
            let query = Query::new(language, rule.query_str)
                .map_err(|error| format!("Regla {}: {error}", rule.id))?;
            let finding_capture = query
                .capture_index_for_name("finding")
                .ok_or_else(|| format!("Regla {}: falta la captura @finding", rule.id))?;
            Ok(CompiledRule {
                rule,
                query,
                finding_capture,
            })
        })
        .collect()
}

pub fn get_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SEC-001",
            description: "Posible Inyección SQL: invocación de métodos RAW (raw, whereRaw, selectRaw, etc.)",
            query_str: r#"
                (scoped_call_expression
                  name: (name) @method
                  (#match? @method "(?i)^(raw|whereRaw|selectRaw|orderByRaw|havingRaw)$")) @finding
                (member_call_expression
                  name: (name) @method
                  (#match? @method "(?i)^(raw|whereRaw|selectRaw|orderByRaw|havingRaw)$")) @finding
                (nullsafe_member_call_expression
                  name: (name) @method
                  (#match? @method "(?i)^(raw|whereRaw|selectRaw|orderByRaw|havingRaw)$")) @finding
            "#,
            severity: Severity::High,
        },
        Rule {
            id: "SEC-002",
            description: "Uso de funciones peligrosas para ejecución de comandos del sistema",
            query_str: r#"
                (function_call_expression
                  function: (name) @func_name
                  (#match? @func_name "(?i)^(eval|exec|passthru|shell_exec|system)$")) @finding
                (shell_command_expression) @finding
            "#,
            severity: Severity::Critical,
        },
        Rule {
            id: "SEC-003",
            description: "Posible credencial o token codificado en duro (hardcoded secret)",
            query_str: r#"
                (assignment_expression
                  left: (variable_name) @var
                  (#match? @var "(?i)(api_key|secret|password|token)")
                  right: [(string) (encapsed_string)] @value) @finding
            "#,
            severity: Severity::High,
        },
        Rule {
            id: "SEC-005",
            description: "Mass Assignment vulnerable: asignación masiva sin protección ($guarded = [])",
            query_str: r#"
                (property_declaration
                  (property_element
                    name: (variable_name) @prop (#eq? @prop "$guarded")
                    default_value: (array_creation_expression) @array)) @finding
            "#,
            severity: Severity::Medium,
        },
        Rule {
            id: "SEC-006",
            description: "Deserialización insegura de datos no confiables vía unserialize()",
            query_str: r#"
                (function_call_expression
                  function: (name) @func (#match? @func "(?i)^unserialize$")) @finding
            "#,
            severity: Severity::Critical,
        },
        Rule {
            id: "STD-001",
            description: "Uso directo del helper env() fuera del directorio config/",
            query_str: r#"
                (function_call_expression
                  function: (name) @func (#match? @func "(?i)^env$")) @finding
            "#,
            severity: Severity::Medium,
        },
        Rule {
            id: "STD-003",
            description: "Fuga de código de depuración en producción (dd, dump, var_dump, ray)",
            query_str: r#"
                (function_call_expression
                  function: (name) @func (#match? @func "(?i)^(dd|dump|var_dump|ray)$")) @finding
            "#,
            severity: Severity::Low,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rules_compilation() {
        let language = Language::from(tree_sitter_php::LANGUAGE_PHP);
        assert_eq!(compile_rules(get_rules(), &language).unwrap().len(), 7);
    }

    #[test]
    fn invalid_rule_is_reported() {
        let language = Language::from(tree_sitter_php::LANGUAGE_PHP);
        let rule = Rule {
            id: "INVALID",
            description: "",
            query_str: "(nonexistent_node) @finding",
            severity: Severity::Low,
        };
        assert!(
            compile_rules(vec![rule], &language)
                .err()
                .unwrap()
                .contains("INVALID")
        );
    }
}
