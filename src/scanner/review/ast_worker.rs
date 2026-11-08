//! Fixed-pattern AST parsing, normally entered only by the confined worker process.
use super::{
    MAX_RESULTS, MAX_SOURCE,
    json::{Value, object},
    rules,
};
use crate::{Result, invalid};
use ast_grep_core::{
    AstGrep, Language, Pattern, PatternError,
    matcher::PatternBuilder,
    tree_sitter::{LanguageExt, StrDoc, TSLanguage},
};
use std::{
    borrow::Cow,
    ffi::OsStr,
    io::{self, Read, Write},
};

#[derive(Clone, Copy)]
enum Grammar {
    JavaScript,
    TypeScript,
    Tsx,
    Python,
    Rust,
}
impl Grammar {
    fn named(name: &str) -> Result<Self> {
        match name {
            "JavaScript" => Ok(Self::JavaScript),
            "TypeScript" => Ok(Self::TypeScript),
            "Tsx" => Ok(Self::Tsx),
            "Python" => Ok(Self::Python),
            "Rust" => Ok(Self::Rust),
            _ => Err(invalid("unsupported built-in AST language")),
        }
    }
}
impl LanguageExt for Grammar {
    fn get_ts_language(&self) -> TSLanguage {
        match self {
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
        }
    }
}
impl Language for Grammar {
    fn kind_to_id(&self, kind: &str) -> u16 {
        self.get_ts_language().id_for_node_kind(kind, true)
    }
    fn field_to_id(&self, field: &str) -> Option<u16> {
        self.get_ts_language()
            .field_id_for_name(field)
            .map(|id| id.get())
    }
    fn expando_char(&self) -> char {
        if matches!(self, Self::Python | Self::Rust) {
            'µ'
        } else {
            '$'
        }
    }
    fn pre_process_pattern<'q>(&self, query: &'q str) -> Cow<'q, str> {
        // These are CB's fixed patterns, consisting of literal syntax and $ metavariables.
        // Python/Rust identifiers cannot start with $, so use a valid placeholder.
        if self.expando_char() == '$' {
            Cow::Borrowed(query)
        } else {
            Cow::Owned(query.replace('$', "µ"))
        }
    }
    fn build_pattern(
        &self,
        builder: &PatternBuilder,
    ) -> std::result::Result<Pattern, PatternError> {
        builder.build(|source| StrDoc::try_new(source, *self))
    }
}

fn query(language: &str, rule: &str, source: &str) -> Result<Value> {
    let grammar = Grammar::named(language)?;
    let rule = rules(language)
        .iter()
        .find(|candidate| candidate.id == rule)
        .ok_or_else(|| invalid("unknown built-in AST rule for this language"))?;
    if source.len() > MAX_SOURCE || source.contains('\0') {
        return Err(invalid("AST worker source exceeds the text budget"));
    }
    let doc =
        StrDoc::try_new(source, grammar).map_err(|_| invalid("built-in AST parser failed"))?;
    // An error-recovery tree is useful for editors, but cannot support a complete scan.
    if doc.tree.root_node().has_error() {
        return Err(invalid("selected source has unsupported or invalid syntax"));
    }
    let tree = AstGrep::doc(doc);
    let root = tree.root();
    let pattern = Pattern::try_new(rule.pattern, grammar)
        .map_err(|_| invalid("invalid built-in AST pattern"))?;
    let mut matches = Vec::new();
    for found in root.find_all(pattern) {
        if matches.len() == MAX_RESULTS {
            return Err(invalid("AST worker match budget exceeded"));
        }
        matches.push(object([(
            "range",
            object([("start", object([("line", found.start_pos().line().into())]))]),
        )]));
    }
    Ok(matches.into())
}

pub(super) fn execute(language: &OsStr, rule: &OsStr) -> Result<i32> {
    let language = language
        .to_str()
        .ok_or_else(|| invalid("invalid AST language"))?;
    let rule = rule.to_str().ok_or_else(|| invalid("invalid AST rule"))?;
    // Reject unknown requests before reading any source. No pattern, parser path,
    // repository configuration, file route or fix can be supplied to this protocol.
    Grammar::named(language)?;
    if !rules(language).iter().any(|candidate| candidate.id == rule) {
        return Err(invalid("unknown built-in AST rule for this language"));
    }
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_SOURCE + 1) as u64)
        .read_to_end(&mut bytes)?;
    let source = std::str::from_utf8(&bytes).map_err(|_| invalid("AST source is not UTF-8"))?;
    let matches = query(language, rule, source)?;
    writeln!(io::stdout().lock(), "{matches}")?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn the_bundled_grammars_match_each_fixed_execution_surface() {
        for (language, source, expected) in [
            (
                "JavaScript",
                "eval(input);\nnew Function(input);\nchild.exec(input);\nchild.spawn(input);\n",
                4,
            ),
            (
                "TypeScript",
                "eval(input);\nnew Function(input);\nchild.exec(input);\nchild.spawn(input);\n",
                4,
            ),
            (
                "Tsx",
                "eval(input);\nnew Function(input);\nchild.exec(input);\nchild.spawn(input);\nconst component = <div />;",
                4,
            ),
            (
                "Python",
                "eval(input)\nexec(input)\nsubprocess.run(input)\n",
                3,
            ),
            (
                "Rust",
                "fn main() { let _ = Command::new(input); let _ = std::process::Command::new(input); }",
                2,
            ),
        ] {
            let mut count = 0;
            for rule in rules(language) {
                let value = query(language, rule.id, source).unwrap();
                let matches = value.as_array().unwrap();
                assert!(!matches.is_empty(), "{language}: {}", rule.id);
                count += matches.len();
            }
            assert_eq!(count, expected, "{language}");
        }
    }
    #[test]
    fn comments_and_strings_are_not_execution_matches() {
        for (language, source, rule) in [
            (
                "JavaScript",
                "// eval(input)\nconst text = 'eval(input)';",
                "JS_EVAL",
            ),
            ("Python", "# eval(input)\ntext = 'eval(input)'", "PY_EVAL"),
            (
                "Rust",
                "// Command::new(input)\nfn main() { let _ = \"Command::new(input)\"; }",
                "RS_COMMAND",
            ),
        ] {
            assert!(
                query(language, rule, source)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        }
    }
    #[test]
    fn worker_protocol_rejects_configuration_patterns_and_unsupported_inputs() {
        assert!(query("Custom", "JS_EVAL", "eval(input)").is_err());
        assert!(query("JavaScript", "eval($$$ARGS)", "eval(input)").is_err());
        assert!(query("JavaScript", "PY_EVAL", "eval(input)").is_err());
        assert!(query("JavaScript", "JS_EVAL", "\0").is_err());
        assert!(query("JavaScript", "JS_EVAL", "function {").is_err());
        assert!(query("JavaScript", "JS_EVAL", &" ".repeat(MAX_SOURCE + 1)).is_err());
        assert!(
            query(
                "JavaScript",
                "JS_EVAL",
                &"eval(input);\n".repeat(MAX_RESULTS + 1)
            )
            .is_err()
        );
    }
}
