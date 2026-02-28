use std::collections::BTreeMap;
use std::fmt;

use crate::ast::Span;
use crate::hir::types;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSchemaDecl {
    pub function: String,
    pub span: Span,
    pub channel_key: String,
    pub canonical_schema: String,
    pub schema_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSendUse {
    pub function: String,
    pub span: Span,
    pub channel_key: String,
    pub canonical_schema: String,
    pub schema_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaValidationIssue {
    InvalidChannelDeclarationArgs,
    InvalidChannelDeclarationChannelKey,
    InvalidChannelDeclarationSchema,
    InvalidSendArgs,
    InvalidSendChannelKey,
    InvalidSendSchema,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingIssue {
    pub function: String,
    pub span: Span,
    pub issue: SchemaValidationIssue,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SchemaValidationReport {
    pub channel_declarations: Vec<ChannelSchemaDecl>,
    pub send_uses: Vec<ChannelSendUse>,
    pub pending_issues: Vec<PendingIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaValidationErrorKind {
    InvalidChannelDeclarationArgs,
    InvalidChannelDeclarationChannelKey,
    InvalidChannelDeclarationSchema,
    InvalidSendArgs,
    InvalidSendChannelKey,
    InvalidSendSchema,
    DuplicateChannelSchema {
        channel_key: String,
        first_schema: String,
        second_schema: String,
    },
    MissingChannelSchema {
        channel_key: String,
    },
    ChannelSchemaMismatch {
        channel_key: String,
        expected_schema: String,
        found_schema: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaValidationError {
    pub kind: SchemaValidationErrorKind,
    pub function: String,
    pub span: Span,
}

impl fmt::Display for SchemaValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SchemaValidationErrorKind::InvalidChannelDeclarationArgs => write!(
                f,
                "schema-validation violation [invalid_channel_declaration] at line {}, col {} in fn {}: bus.channel requires 2 args: (channel_key, schema_sig)",
                self.span.line, self.span.col, self.function
            ),
            SchemaValidationErrorKind::InvalidChannelDeclarationChannelKey => write!(
                f,
                "schema-validation violation [invalid_channel_key] at line {}, col {} in fn {}: channel_key must be a string or int literal",
                self.span.line, self.span.col, self.function
            ),
            SchemaValidationErrorKind::InvalidChannelDeclarationSchema => write!(
                f,
                "schema-validation violation [invalid_schema_signature] at line {}, col {} in fn {}: schema signature must be a string literal",
                self.span.line, self.span.col, self.function
            ),
            SchemaValidationErrorKind::InvalidSendArgs => write!(
                f,
                "schema-validation violation [invalid_send_call] at line {}, col {} in fn {}: bus.send requires at least 2 args: (channel_key, schema_sig, ...payload)",
                self.span.line, self.span.col, self.function
            ),
            SchemaValidationErrorKind::InvalidSendChannelKey => write!(
                f,
                "schema-validation violation [invalid_channel_key] at line {}, col {} in fn {}: send channel_key must be a string or int literal",
                self.span.line, self.span.col, self.function
            ),
            SchemaValidationErrorKind::InvalidSendSchema => write!(
                f,
                "schema-validation violation [invalid_schema_signature] at line {}, col {} in fn {}: send schema signature must be a string literal",
                self.span.line, self.span.col, self.function
            ),
            SchemaValidationErrorKind::DuplicateChannelSchema {
                channel_key,
                first_schema,
                second_schema,
            } => write!(
                f,
                "schema-validation violation [duplicate_channel_schema] at line {}, col {} in fn {}: channel {} declared with conflicting schemas {} vs {}",
                self.span.line,
                self.span.col,
                self.function,
                channel_key,
                first_schema,
                second_schema
            ),
            SchemaValidationErrorKind::MissingChannelSchema { channel_key } => write!(
                f,
                "schema-validation violation [missing_channel_schema] at line {}, col {} in fn {}: no schema declaration for channel {}",
                self.span.line, self.span.col, self.function, channel_key
            ),
            SchemaValidationErrorKind::ChannelSchemaMismatch {
                channel_key,
                expected_schema,
                found_schema,
            } => write!(
                f,
                "schema-validation violation [schema_mismatch] at line {}, col {} in fn {}: channel {} expects schema {}, send uses {}",
                self.span.line,
                self.span.col,
                self.function,
                channel_key,
                expected_schema,
                found_schema
            ),
        }
    }
}

impl std::error::Error for SchemaValidationError {}

pub fn analyze(program: &types::Program) -> SchemaValidationReport {
    let mut walker = Walker::default();
    walker.walk_program(program);
    walker.report
}

pub fn enforce(report: &SchemaValidationReport) -> Result<(), SchemaValidationError> {
    if let Some(first_issue) = report.pending_issues.first() {
        return Err(SchemaValidationError {
            kind: map_issue_kind(&first_issue.issue),
            function: first_issue.function.clone(),
            span: first_issue.span,
        });
    }

    let mut channel_map: BTreeMap<String, (String, u64)> = BTreeMap::new();

    for decl in &report.channel_declarations {
        if let Some((existing_schema, existing_id)) = channel_map.get(&decl.channel_key) {
            if *existing_id != decl.schema_id {
                return Err(SchemaValidationError {
                    kind: SchemaValidationErrorKind::DuplicateChannelSchema {
                        channel_key: decl.channel_key.clone(),
                        first_schema: existing_schema.clone(),
                        second_schema: decl.canonical_schema.clone(),
                    },
                    function: decl.function.clone(),
                    span: decl.span,
                });
            }
        } else {
            channel_map.insert(
                decl.channel_key.clone(),
                (decl.canonical_schema.clone(), decl.schema_id),
            );
        }
    }

    for send in &report.send_uses {
        let Some((expected_schema, expected_id)) = channel_map.get(&send.channel_key) else {
            return Err(SchemaValidationError {
                kind: SchemaValidationErrorKind::MissingChannelSchema {
                    channel_key: send.channel_key.clone(),
                },
                function: send.function.clone(),
                span: send.span,
            });
        };

        if *expected_id != send.schema_id {
            return Err(SchemaValidationError {
                kind: SchemaValidationErrorKind::ChannelSchemaMismatch {
                    channel_key: send.channel_key.clone(),
                    expected_schema: expected_schema.clone(),
                    found_schema: send.canonical_schema.clone(),
                },
                function: send.function.clone(),
                span: send.span,
            });
        }
    }

    Ok(())
}

fn map_issue_kind(issue: &SchemaValidationIssue) -> SchemaValidationErrorKind {
    match issue {
        SchemaValidationIssue::InvalidChannelDeclarationArgs => {
            SchemaValidationErrorKind::InvalidChannelDeclarationArgs
        }
        SchemaValidationIssue::InvalidChannelDeclarationChannelKey => {
            SchemaValidationErrorKind::InvalidChannelDeclarationChannelKey
        }
        SchemaValidationIssue::InvalidChannelDeclarationSchema => {
            SchemaValidationErrorKind::InvalidChannelDeclarationSchema
        }
        SchemaValidationIssue::InvalidSendArgs => SchemaValidationErrorKind::InvalidSendArgs,
        SchemaValidationIssue::InvalidSendChannelKey => {
            SchemaValidationErrorKind::InvalidSendChannelKey
        }
        SchemaValidationIssue::InvalidSendSchema => SchemaValidationErrorKind::InvalidSendSchema,
    }
}

pub fn canonicalize_schema_signature(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn derive_schema_id(raw_schema_sig: &str) -> u64 {
    let canonical = canonicalize_schema_signature(raw_schema_sig);
    fnv1a64(canonical.as_bytes())
}

#[derive(Default)]
struct Walker {
    report: SchemaValidationReport,
    current_function: Option<String>,
}

impl Walker {
    fn walk_program(&mut self, program: &types::Program) {
        for item in &program.items {
            if let types::Item::Function(function) = item {
                self.current_function = Some(function.name.clone());
                self.walk_block(&function.body);
                self.current_function = None;
            }
        }
    }

    fn walk_block(&mut self, block: &types::Block) {
        for stmt in &block.stmts {
            self.walk_stmt(stmt);
        }
    }

    fn walk_stmt(&mut self, stmt: &types::Stmt) {
        match stmt {
            types::Stmt::Let { value, .. } => self.walk_expr(value),
            types::Stmt::Return(Some(expr)) => self.walk_expr(expr),
            types::Stmt::Return(None) => {}
            types::Stmt::Expr(expr) => self.walk_expr(expr),
            types::Stmt::If {
                cond,
                then_block,
                else_block,
            } => {
                self.walk_expr(cond);
                self.walk_block(then_block);
                if let Some(else_block) = else_block {
                    self.walk_block(else_block);
                }
            }
            types::Stmt::Loop(block) | types::Stmt::Defer(block) => self.walk_block(block),
        }
    }

    fn walk_expr(&mut self, expr: &types::Expr) {
        match expr {
            types::Expr::Literal(_) | types::Expr::Variable(_) => {}
            types::Expr::Call { func, args, span } => {
                self.record_call(func, args, *span);
                for arg in args {
                    self.walk_expr(arg);
                }
            }
            types::Expr::BinaryOp { left, right, .. } => {
                self.walk_expr(left);
                self.walk_expr(right);
            }
            types::Expr::If {
                cond,
                then_block,
                else_block,
            } => {
                self.walk_expr(cond);
                self.walk_block(then_block);
                if let Some(else_block) = else_block {
                    self.walk_block(else_block);
                }
            }
            types::Expr::Block(block) => self.walk_block(block),
            types::Expr::Spawn { block, .. } => self.walk_block(block),
        }
    }

    fn record_call(&mut self, func: &str, args: &[types::Expr], span: Span) {
        let normalized = func.trim().to_ascii_lowercase();

        if normalized == "bus.channel" {
            self.record_channel_declaration(args, span);
        }

        if normalized == "bus.send" {
            self.record_send(args, span);
        }
    }

    fn record_channel_declaration(&mut self, args: &[types::Expr], span: Span) {
        if args.len() != 2 {
            self.push_issue(span, SchemaValidationIssue::InvalidChannelDeclarationArgs);
            return;
        }

        let Some(channel_key) = literal_channel_key(&args[0]) else {
            self.push_issue(
                span,
                SchemaValidationIssue::InvalidChannelDeclarationChannelKey,
            );
            return;
        };

        let Some(raw_schema) = literal_string(&args[1]) else {
            self.push_issue(span, SchemaValidationIssue::InvalidChannelDeclarationSchema);
            return;
        };

        let canonical_schema = canonicalize_schema_signature(raw_schema);
        let schema_id = derive_schema_id(&canonical_schema);
        self.report.channel_declarations.push(ChannelSchemaDecl {
            function: self.current_function_name(),
            span,
            channel_key,
            canonical_schema,
            schema_id,
        });
    }

    fn record_send(&mut self, args: &[types::Expr], span: Span) {
        if args.len() < 2 {
            self.push_issue(span, SchemaValidationIssue::InvalidSendArgs);
            return;
        }

        let Some(channel_key) = literal_channel_key(&args[0]) else {
            self.push_issue(span, SchemaValidationIssue::InvalidSendChannelKey);
            return;
        };

        let Some(raw_schema) = literal_string(&args[1]) else {
            self.push_issue(span, SchemaValidationIssue::InvalidSendSchema);
            return;
        };

        let canonical_schema = canonicalize_schema_signature(raw_schema);
        let schema_id = derive_schema_id(&canonical_schema);

        self.report.send_uses.push(ChannelSendUse {
            function: self.current_function_name(),
            span,
            channel_key,
            canonical_schema,
            schema_id,
        });
    }

    fn push_issue(&mut self, span: Span, issue: SchemaValidationIssue) {
        self.report.pending_issues.push(PendingIssue {
            function: self.current_function_name(),
            span,
            issue,
        });
    }

    fn current_function_name(&self) -> String {
        self.current_function
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string())
    }
}

fn literal_string(expr: &types::Expr) -> Option<&str> {
    match expr {
        types::Expr::Literal(types::Literal::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

fn literal_channel_key(expr: &types::Expr) -> Option<String> {
    match expr {
        types::Expr::Literal(types::Literal::String(value)) => {
            Some(format!("str:{}", value.trim()))
        }
        types::Expr::Literal(types::Literal::Int(value)) => Some(format!("int:{}", value)),
        _ => None,
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{analyze, derive_schema_id, enforce, SchemaValidationErrorKind};
    use crate::hir::lower::lower_to_hir;
    use crate::runtime::agent_bus::Mailbox;

    #[test]
    fn schema_mismatch_is_deterministic_compile_error() {
        let source = r#"
            fn main() {
                bus.channel("alerts", "AlertV1");
                bus.send("alerts", "AuditV1", "payload");
                return;
            }
        "#;

        let report = analyze(&parse_and_lower(source));
        let err = enforce(&report).expect_err("schema mismatch must be compile-time error");

        assert_eq!(
            err.kind,
            SchemaValidationErrorKind::ChannelSchemaMismatch {
                channel_key: "str:alerts".to_string(),
                expected_schema: "AlertV1".to_string(),
                found_schema: "AuditV1".to_string(),
            }
        );
        assert_eq!(err.function, "main");
        assert_eq!(err.span.line, 4);
        assert_eq!(err.span.col, 17);
        assert_eq!(
            err.to_string(),
            "schema-validation violation [schema_mismatch] at line 4, col 17 in fn main: channel str:alerts expects schema AlertV1, send uses AuditV1"
        );
    }

    #[test]
    fn schema_id_derivation_is_stable_and_runtime_compatible() {
        let schema = "Msg<AlertV1>";
        let from_analysis = derive_schema_id(schema);
        let from_runtime = Mailbox::schema_id_from_type(schema);

        assert_eq!(from_analysis, from_runtime);
        assert_eq!(derive_schema_id(schema), derive_schema_id(schema));
    }

    #[test]
    fn valid_schema_program_passes() {
        let source = r#"
            fn main() {
                bus.channel("alerts", "AlertV1");
                bus.send("alerts", "AlertV1", "payload");
                return;
            }
        "#;

        let report = analyze(&parse_and_lower(source));
        enforce(&report).expect("valid schema program should pass");
    }

    fn parse_and_lower(source: &str) -> crate::hir::types::Program {
        let ast = crate::parser::parse(source).expect("source should parse");
        lower_to_hir(&ast)
    }
}
