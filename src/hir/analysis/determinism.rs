use std::fmt;

use crate::ast::Span;

use crate::hir::types;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeterminismFacts {
    pub uses_time: bool,
    pub uses_rng: bool,
    pub uses_io_proxy: bool,
    pub uses_net: bool,
    pub uses_bus: bool,
    pub uses_spawn: bool,
    pub uses_float_nondet: bool,
}

impl DeterminismFacts {
    pub fn to_canonical_json(self) -> String {
        format!(
            concat!(
                "{{",
                "\"uses_time\":{},",
                "\"uses_rng\":{},",
                "\"uses_io_proxy\":{},",
                "\"uses_net\":{},",
                "\"uses_bus\":{},",
                "\"uses_spawn\":{},",
                "\"uses_float_nondet\":{}",
                "}}"
            ),
            bool_token(self.uses_time),
            bool_token(self.uses_rng),
            bool_token(self.uses_io_proxy),
            bool_token(self.uses_net),
            bool_token(self.uses_bus),
            bool_token(self.uses_spawn),
            bool_token(self.uses_float_nondet),
        )
    }
}

fn bool_token(v: bool) -> &'static str {
    if v {
        "true"
    } else {
        "false"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeterminismReport {
    pub facts: DeterminismFacts,
    pub uses_time_span: Option<Span>,
    pub uses_rng_span: Option<Span>,
    pub uses_io_proxy_span: Option<Span>,
    pub uses_net_span: Option<Span>,
    pub uses_bus_span: Option<Span>,
    pub uses_spawn_span: Option<Span>,
    pub uses_float_nondet_span: Option<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictDeterminismKind {
    UsesTime,
    UsesRng,
    UsesIoProxy,
    UsesNet,
    UsesBus,
    UsesSpawn,
    UsesFloatNondet,
}

impl StrictDeterminismKind {
    fn code(self) -> &'static str {
        match self {
            StrictDeterminismKind::UsesTime => "uses_time",
            StrictDeterminismKind::UsesRng => "uses_rng",
            StrictDeterminismKind::UsesIoProxy => "uses_io_proxy",
            StrictDeterminismKind::UsesNet => "uses_net",
            StrictDeterminismKind::UsesBus => "uses_bus",
            StrictDeterminismKind::UsesSpawn => "uses_spawn",
            StrictDeterminismKind::UsesFloatNondet => "uses_float_nondet",
        }
    }

    fn message(self) -> &'static str {
        match self {
            StrictDeterminismKind::UsesTime => {
                "wall-clock/time-dependent behavior is forbidden under strict determinism"
            }
            StrictDeterminismKind::UsesRng => "randomness is forbidden under strict determinism",
            StrictDeterminismKind::UsesIoProxy => {
                "io-proxy dependent behavior is forbidden under strict determinism"
            }
            StrictDeterminismKind::UsesNet => {
                "network behavior is forbidden under strict determinism"
            }
            StrictDeterminismKind::UsesBus => {
                "agent bus behavior is forbidden under strict determinism"
            }
            StrictDeterminismKind::UsesSpawn => {
                "spawn/concurrency behavior is forbidden under strict determinism"
            }
            StrictDeterminismKind::UsesFloatNondet => {
                "floating-point nondeterminism markers are forbidden under strict determinism"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictDeterminismError {
    pub kind: StrictDeterminismKind,
    pub span: Span,
}

impl fmt::Display for StrictDeterminismError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "strict determinism violation [{}] at line {}, col {}: {}",
            self.kind.code(),
            self.span.line,
            self.span.col,
            self.kind.message()
        )
    }
}

impl std::error::Error for StrictDeterminismError {}

pub fn analyze(program: &types::Program) -> DeterminismReport {
    let mut analyzer = Analyzer::default();
    analyzer.walk_program(program);
    analyzer.report
}

pub fn enforce_strict_mode(
    program: &types::Program,
) -> Result<DeterminismFacts, StrictDeterminismError> {
    let report = analyze(program);
    if let Some(err) = first_violation(&report) {
        return Err(err);
    }

    Ok(report.facts)
}

fn first_violation(report: &DeterminismReport) -> Option<StrictDeterminismError> {
    let checks = [
        (
            report.facts.uses_time,
            StrictDeterminismKind::UsesTime,
            report.uses_time_span,
        ),
        (
            report.facts.uses_rng,
            StrictDeterminismKind::UsesRng,
            report.uses_rng_span,
        ),
        (
            report.facts.uses_io_proxy,
            StrictDeterminismKind::UsesIoProxy,
            report.uses_io_proxy_span,
        ),
        (
            report.facts.uses_net,
            StrictDeterminismKind::UsesNet,
            report.uses_net_span,
        ),
        (
            report.facts.uses_bus,
            StrictDeterminismKind::UsesBus,
            report.uses_bus_span,
        ),
        (
            report.facts.uses_spawn,
            StrictDeterminismKind::UsesSpawn,
            report.uses_spawn_span,
        ),
        (
            report.facts.uses_float_nondet,
            StrictDeterminismKind::UsesFloatNondet,
            report.uses_float_nondet_span,
        ),
    ];

    for (flag, kind, span) in checks {
        if flag {
            return Some(StrictDeterminismError {
                kind,
                span: span.unwrap_or(Span { line: 1, col: 1 }),
            });
        }
    }

    None
}

#[derive(Default)]
struct Analyzer {
    report: DeterminismReport,
    current_fn_span: Option<Span>,
}

impl Analyzer {
    fn walk_program(&mut self, program: &types::Program) {
        for item in &program.items {
            if let types::Item::Function(function) = item {
                self.walk_function(function);
            }
        }
    }

    fn walk_function(&mut self, function: &types::Function) {
        let previous = self.current_fn_span;
        self.current_fn_span = Some(function.name_span);

        for effect in &function.effects {
            match effect {
                types::Effect::Io => self.mark_io_proxy(Some(function.name_span)),
                types::Effect::Net => self.mark_net(Some(function.name_span)),
                types::Effect::Async => self.mark_spawn(Some(function.name_span)),
                types::Effect::Pure | types::Effect::Mut => {}
            }
        }

        if let Some(return_type) = &function.return_type {
            if is_float_type(return_type) {
                self.mark_float_nondet(None);
            }
        }

        for param in &function.params {
            if is_float_type(&param.ty) {
                self.mark_float_nondet(None);
            }
        }

        self.walk_block(&function.body);
        self.current_fn_span = previous;
    }

    fn walk_block(&mut self, block: &types::Block) {
        for stmt in &block.stmts {
            self.walk_stmt(stmt);
        }
    }

    fn walk_stmt(&mut self, stmt: &types::Stmt) {
        match stmt {
            types::Stmt::Let { ty, value, .. } => {
                if let Some(ty) = ty {
                    if is_float_type(ty) {
                        self.mark_float_nondet(None);
                    }
                }
                self.walk_expr(value);
            }
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
            types::Expr::Literal(types::Literal::Float(_)) => self.mark_float_nondet(None),
            types::Expr::Literal(_) | types::Expr::Variable(_) => {}
            types::Expr::Call { func, args, span } => {
                self.classify_call(func, *span);
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
            types::Expr::Spawn { block, span } => {
                self.mark_spawn(Some(*span));
                self.walk_block(block);
            }
        }
    }

    fn classify_call(&mut self, func: &str, span: Span) {
        let name = normalize_call_name(func);

        if is_time_symbol(&name) {
            self.mark_time(Some(span));
        }

        if is_rng_symbol(&name) {
            self.mark_rng(Some(span));
        }

        if is_io_proxy_symbol(&name) {
            self.mark_io_proxy(Some(span));
        }

        if is_net_symbol(&name) {
            self.mark_net(Some(span));
        }

        if is_bus_symbol(&name) {
            self.mark_bus(Some(span));
        }
    }

    fn canonical_span(&self, span: Option<Span>) -> Option<Span> {
        span.or(self.current_fn_span)
    }

    fn mark_time(&mut self, span: Option<Span>) {
        self.report.facts.uses_time = true;
        if self.report.uses_time_span.is_none() {
            self.report.uses_time_span = self.canonical_span(span);
        }
    }

    fn mark_rng(&mut self, span: Option<Span>) {
        self.report.facts.uses_rng = true;
        if self.report.uses_rng_span.is_none() {
            self.report.uses_rng_span = self.canonical_span(span);
        }
    }

    fn mark_io_proxy(&mut self, span: Option<Span>) {
        self.report.facts.uses_io_proxy = true;
        if self.report.uses_io_proxy_span.is_none() {
            self.report.uses_io_proxy_span = self.canonical_span(span);
        }
    }

    fn mark_net(&mut self, span: Option<Span>) {
        self.report.facts.uses_net = true;
        if self.report.uses_net_span.is_none() {
            self.report.uses_net_span = self.canonical_span(span);
        }
    }

    fn mark_bus(&mut self, span: Option<Span>) {
        self.report.facts.uses_bus = true;
        if self.report.uses_bus_span.is_none() {
            self.report.uses_bus_span = self.canonical_span(span);
        }
    }

    fn mark_spawn(&mut self, span: Option<Span>) {
        self.report.facts.uses_spawn = true;
        if self.report.uses_spawn_span.is_none() {
            self.report.uses_spawn_span = self.canonical_span(span);
        }
    }

    fn mark_float_nondet(&mut self, span: Option<Span>) {
        self.report.facts.uses_float_nondet = true;
        if self.report.uses_float_nondet_span.is_none() {
            self.report.uses_float_nondet_span = self.canonical_span(span);
        }
    }
}

fn is_float_type(ty: &types::Type) -> bool {
    matches!(ty, types::Type::F32)
}

fn normalize_call_name(func: &str) -> String {
    func.trim().to_ascii_lowercase()
}

fn is_time_symbol(name: &str) -> bool {
    name == "now"
        || name.starts_with("time.")
        || name.starts_with("clock.")
        || name.contains("timestamp")
        || name.contains("wall_clock")
        || name.contains("wallclock")
}

fn is_rng_symbol(name: &str) -> bool {
    name.contains("rand") || name.contains("rng") || name.contains("random")
}

fn is_io_proxy_symbol(name: &str) -> bool {
    name.starts_with("fs.")
        || name.starts_with("io_proxy.")
        || name.starts_with("net.")
        || name.starts_with("stdin.")
        || name.starts_with("stdout.")
}

fn is_net_symbol(name: &str) -> bool {
    name.starts_with("net.")
}

fn is_bus_symbol(name: &str) -> bool {
    name.starts_with("bus.")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{
        analyze, enforce_strict_mode, DeterminismFacts, StrictDeterminismError,
        StrictDeterminismKind,
    };
    use crate::ast::Span;
    use crate::hir::lower::lower_to_hir;

    struct GoldenCase {
        name: &'static str,
        source: &'static str,
        golden_relpath: &'static str,
    }

    const GOLDEN_CASES: &[GoldenCase] = &[
        GoldenCase {
            name: "pure_program",
            source: "fn main() {\n    let x: int = 7;\n    return;\n}\n",
            golden_relpath: "src/hir/golden/pure_program.determinism.json",
        },
        GoldenCase {
            name: "io_net_spawn_program",
            source: "fn main() !io !net !async {\n    fs.read(\"cfg/app.nex\");\n    net.connect(\"127.0.0.1\", 8080);\n    spawn {\n        return;\n    };\n    return;\n}\n",
            golden_relpath: "src/hir/golden/io_net_spawn_program.determinism.json",
        },
        GoldenCase {
            name: "time_rng_bus_float_program",
            source: "fn main() {\n    let x: float = 1.0;\n    time.now();\n    rand.next();\n    bus.send(1);\n    return;\n}\n",
            golden_relpath: "src/hir/golden/time_rng_bus_float_program.determinism.json",
        },
    ];

    #[test]
    fn io_proxy_usage_sets_determinism_facts() {
        let source = "fn main() {\n    fs.read(\"cfg/app.nex\");\n    return;\n}\n";
        let report = analyze(&parse_and_lower(source));

        assert_eq!(
            report.facts,
            DeterminismFacts {
                uses_time: false,
                uses_rng: false,
                uses_io_proxy: true,
                uses_net: false,
                uses_bus: false,
                uses_spawn: false,
                uses_float_nondet: false,
            }
        );
    }

    #[test]
    fn strict_mode_rejects_with_deterministic_diagnostic() {
        let source =
            "fn main() {\n    rand.next();\n    fs.read(\"cfg/app.nex\");\n    return;\n}\n";

        let err = enforce_strict_mode(&parse_and_lower(source))
            .expect_err("strict mode must reject nondeterministic constructs");

        assert_eq!(
            err,
            StrictDeterminismError {
                kind: StrictDeterminismKind::UsesRng,
                span: Span { line: 2, col: 5 },
            }
        );
        assert_eq!(
            err.to_string(),
            "strict determinism violation [uses_rng] at line 2, col 5: randomness is forbidden under strict determinism"
        );
    }

    #[test]
    fn strict_mode_reports_float_marker_with_function_span() {
        let source = "fn main() {\n    let x: float = 1.0;\n    return;\n}\n";

        let err = enforce_strict_mode(&parse_and_lower(source))
            .expect_err("strict mode must reject float nondeterminism markers");

        assert_eq!(
            err,
            StrictDeterminismError {
                kind: StrictDeterminismKind::UsesFloatNondet,
                span: Span { line: 1, col: 4 },
            }
        );
        assert_eq!(
            err.to_string(),
            "strict determinism violation [uses_float_nondet] at line 1, col 4: floating-point nondeterminism markers are forbidden under strict determinism"
        );
    }

    #[test]
    fn golden_determinism_facts_match_exactly() {
        let update = std::env::var("NEX_UPDATE_DETERMINISM_GOLDEN")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false);

        for case in GOLDEN_CASES {
            let facts = analyze(&parse_and_lower(case.source)).facts;
            let encoded = format!("{}\n", facts.to_canonical_json());
            let path = project_root().join(case.golden_relpath);

            if update {
                fs::write(&path, encoded.as_bytes()).expect("write determinism golden");
            }

            let expected = fs::read(&path).expect("read determinism golden");
            assert_eq!(
                encoded.as_bytes(),
                expected.as_slice(),
                "determinism golden bytes mismatch for {}",
                case.name
            );
        }
    }

    fn parse_and_lower(source: &str) -> crate::hir::types::Program {
        let ast = crate::parser::parse(source).expect("source should parse");
        lower_to_hir(&ast)
    }

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }
}
