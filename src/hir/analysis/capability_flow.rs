use std::fmt;

use crate::ast::Span;
use crate::hir::types;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCapabilityFlow {
    pub function: String,
    pub name_span: Span,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskBoundaryFlow {
    pub function: String,
    pub span: Span,
    pub required_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBoundaryFlow {
    pub function: String,
    pub span: Span,
    pub required_capability: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityFlowReport {
    pub function_flows: Vec<FunctionCapabilityFlow>,
    pub task_boundaries: Vec<TaskBoundaryFlow>,
    pub agent_boundaries: Vec<AgentBoundaryFlow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityFlowErrorKind {
    MissingFsReadCapability { required: String },
    MissingNetListenCapability { required_port: i64 },
    DynamicFsReadTarget,
    DynamicNetListenPort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityFlowError {
    pub kind: CapabilityFlowErrorKind,
    pub function: String,
    pub span: Span,
}

impl fmt::Display for CapabilityFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            CapabilityFlowErrorKind::MissingFsReadCapability { required } => write!(
                f,
                "capability-flow violation [missing_capability] at line {}, col {} in fn {}: missing declaration for {}",
                self.span.line, self.span.col, self.function, required
            ),
            CapabilityFlowErrorKind::MissingNetListenCapability { required_port } => write!(
                f,
                "capability-flow violation [missing_capability] at line {}, col {} in fn {}: missing declaration for net.listen:{}",
                self.span.line, self.span.col, self.function, required_port
            ),
            CapabilityFlowErrorKind::DynamicFsReadTarget => write!(
                f,
                "capability-flow violation [nondeterministic_capability_target] at line {}, col {} in fn {}: fs.read requires a string-literal path for static capability analysis",
                self.span.line, self.span.col, self.function
            ),
            CapabilityFlowErrorKind::DynamicNetListenPort => write!(
                f,
                "capability-flow violation [nondeterministic_capability_target] at line {}, col {} in fn {}: net.listen requires an int-literal port for static capability analysis",
                self.span.line, self.span.col, self.function
            ),
        }
    }
}

impl std::error::Error for CapabilityFlowError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CapabilityRequirement {
    FsReadLiteral(String),
    FsReadDynamic,
    NetListenLiteral(i64),
    NetListenDynamic,
    BusSend,
    BusRecv,
    IoProxy,
    NetProxy,
}

impl CapabilityRequirement {
    fn canonical_name(&self) -> String {
        match self {
            CapabilityRequirement::FsReadLiteral(path) => format!("fs.read:{}", path),
            CapabilityRequirement::FsReadDynamic => "fs.read:<dynamic>".to_string(),
            CapabilityRequirement::NetListenLiteral(port) => format!("net.listen:{}", port),
            CapabilityRequirement::NetListenDynamic => "net.listen:<dynamic>".to_string(),
            CapabilityRequirement::BusSend => "bus.send".to_string(),
            CapabilityRequirement::BusRecv => "bus.recv".to_string(),
            CapabilityRequirement::IoProxy => "io.proxy".to_string(),
            CapabilityRequirement::NetProxy => "net.proxy".to_string(),
        }
    }

    fn is_declaration_enforced(&self) -> bool {
        matches!(
            self,
            CapabilityRequirement::FsReadLiteral(_)
                | CapabilityRequirement::FsReadDynamic
                | CapabilityRequirement::NetListenLiteral(_)
                | CapabilityRequirement::NetListenDynamic
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequirementUse {
    function: String,
    function_span: Span,
    call_span: Span,
    requirement: CapabilityRequirement,
}

pub fn analyze(program: &types::Program) -> CapabilityFlowReport {
    let mut walker = Walker::default();
    walker.walk_program(program);
    walker.into_report()
}

pub fn enforce_declared_capabilities(
    program: &types::Program,
    report: &CapabilityFlowReport,
) -> Result<(), CapabilityFlowError> {
    let mut declared_fs_globs: Vec<String> = Vec::new();
    let mut declared_net_ranges: Vec<types::NetPortSpec> = Vec::new();

    for item in &program.items {
        if let types::Item::Capability(decl) = item {
            match &decl.cap {
                types::Capability::FsRead { glob } => declared_fs_globs.push(glob.clone()),
                types::Capability::NetListen { range } => declared_net_ranges.push(range.clone()),
            }
        }
    }

    let uses = collect_requirement_uses(program);
    for usage in uses {
        if !usage.requirement.is_declaration_enforced() {
            continue;
        }

        match &usage.requirement {
            CapabilityRequirement::FsReadLiteral(path) => {
                let matched = declared_fs_globs
                    .iter()
                    .any(|glob| fs_glob_matches(glob, path));
                if !matched {
                    return Err(CapabilityFlowError {
                        kind: CapabilityFlowErrorKind::MissingFsReadCapability {
                            required: usage.requirement.canonical_name(),
                        },
                        function: usage.function,
                        span: usage.call_span,
                    });
                }
            }
            CapabilityRequirement::FsReadDynamic => {
                return Err(CapabilityFlowError {
                    kind: CapabilityFlowErrorKind::DynamicFsReadTarget,
                    function: usage.function,
                    span: usage.call_span,
                });
            }
            CapabilityRequirement::NetListenLiteral(port) => {
                let matched = declared_net_ranges
                    .iter()
                    .any(|range| net_range_allows(range, *port));
                if !matched {
                    return Err(CapabilityFlowError {
                        kind: CapabilityFlowErrorKind::MissingNetListenCapability {
                            required_port: *port,
                        },
                        function: usage.function,
                        span: usage.call_span,
                    });
                }
            }
            CapabilityRequirement::NetListenDynamic => {
                return Err(CapabilityFlowError {
                    kind: CapabilityFlowErrorKind::DynamicNetListenPort,
                    function: usage.function,
                    span: usage.call_span,
                });
            }
            CapabilityRequirement::BusSend
            | CapabilityRequirement::BusRecv
            | CapabilityRequirement::IoProxy
            | CapabilityRequirement::NetProxy => {}
        }
    }

    // `report` is part of the public API and consumed by governancefacts encoding.
    // Access it here to keep strict deterministic checking wired through the same call path.
    let _ = report;

    Ok(())
}

fn collect_requirement_uses(program: &types::Program) -> Vec<RequirementUse> {
    let mut walker = Walker::default();
    walker.walk_program(program);
    walker.requirement_uses
}

#[derive(Default)]
struct Walker {
    function_flows: Vec<FunctionCapabilityFlow>,
    task_boundaries: Vec<TaskBoundaryFlow>,
    agent_boundaries: Vec<AgentBoundaryFlow>,
    requirement_uses: Vec<RequirementUse>,
    current_function: Option<String>,
    current_function_span: Option<Span>,
    current_function_caps: Vec<String>,
}

impl Walker {
    fn into_report(self) -> CapabilityFlowReport {
        CapabilityFlowReport {
            function_flows: self.function_flows,
            task_boundaries: self.task_boundaries,
            agent_boundaries: self.agent_boundaries,
        }
    }

    fn walk_program(&mut self, program: &types::Program) {
        for item in &program.items {
            if let types::Item::Function(function) = item {
                self.walk_function(function);
            }
        }
    }

    fn walk_function(&mut self, function: &types::Function) {
        self.current_function = Some(function.name.clone());
        self.current_function_span = Some(function.name_span);
        self.current_function_caps.clear();

        self.walk_block(&function.body);

        self.current_function_caps.sort();
        self.current_function_caps.dedup();

        self.function_flows.push(FunctionCapabilityFlow {
            function: function.name.clone(),
            name_span: function.name_span,
            required_capabilities: self.current_function_caps.clone(),
        });

        self.current_function = None;
        self.current_function_span = None;
        self.current_function_caps.clear();
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
                self.record_call_requirements(func, args, *span);
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
                if let Some(function) = &self.current_function {
                    self.task_boundaries.push(TaskBoundaryFlow {
                        function: function.clone(),
                        span: *span,
                        required_capabilities: self.current_function_caps.clone(),
                    });
                }
                self.walk_block(block);
            }
        }
    }

    fn record_call_requirements(&mut self, func: &str, args: &[types::Expr], call_span: Span) {
        let normalized = func.trim().to_ascii_lowercase();

        if normalized == "fs.read" {
            self.add_requirement(
                call_span,
                match args.first() {
                    Some(types::Expr::Literal(types::Literal::String(path))) => {
                        CapabilityRequirement::FsReadLiteral(path.clone())
                    }
                    _ => CapabilityRequirement::FsReadDynamic,
                },
            );
            self.add_requirement(call_span, CapabilityRequirement::IoProxy);
            self.record_agent_boundary(call_span, "io.proxy");
        }

        if normalized == "net.listen" {
            self.add_requirement(
                call_span,
                match args.first() {
                    Some(types::Expr::Literal(types::Literal::Int(port))) => {
                        CapabilityRequirement::NetListenLiteral(*port)
                    }
                    _ => CapabilityRequirement::NetListenDynamic,
                },
            );
            self.add_requirement(call_span, CapabilityRequirement::NetProxy);
            self.record_agent_boundary(call_span, "net.proxy");
        }

        if normalized.starts_with("net.") && normalized != "net.listen" {
            self.add_requirement(call_span, CapabilityRequirement::NetProxy);
            self.record_agent_boundary(call_span, "net.proxy");
        }

        if normalized == "bus.send" {
            self.add_requirement(call_span, CapabilityRequirement::BusSend);
            self.record_agent_boundary(call_span, "bus.send");
        }

        if normalized == "bus.recv" {
            self.add_requirement(call_span, CapabilityRequirement::BusRecv);
            self.record_agent_boundary(call_span, "bus.recv");
        }
    }

    fn add_requirement(&mut self, call_span: Span, requirement: CapabilityRequirement) {
        let Some(function) = self.current_function.clone() else {
            return;
        };
        let Some(function_span) = self.current_function_span else {
            return;
        };

        let canonical = requirement.canonical_name();
        self.current_function_caps.push(canonical);
        self.requirement_uses.push(RequirementUse {
            function,
            function_span,
            call_span,
            requirement,
        });
    }

    fn record_agent_boundary(&mut self, span: Span, required_capability: &str) {
        if let Some(function) = &self.current_function {
            self.agent_boundaries.push(AgentBoundaryFlow {
                function: function.clone(),
                span,
                required_capability: required_capability.to_string(),
            });
        }
    }
}

fn fs_glob_matches(glob: &str, path: &str) -> bool {
    if glob == "*" {
        return true;
    }

    if !glob.contains('*') {
        return glob == path;
    }

    let mut remainder = path;
    let mut first = true;
    let mut parts = glob.split('*').peekable();

    while let Some(part) = parts.next() {
        if part.is_empty() {
            continue;
        }

        if first && !glob.starts_with('*') {
            if let Some(rest) = remainder.strip_prefix(part) {
                remainder = rest;
            } else {
                return false;
            }
            first = false;
            continue;
        }

        if let Some(pos) = remainder.find(part) {
            let next_index = pos + part.len();
            remainder = &remainder[next_index..];
        } else {
            return false;
        }

        first = false;

        if parts.peek().is_none() && !glob.ends_with('*') && !remainder.is_empty() {
            return false;
        }
    }

    if !glob.ends_with('*') {
        let tail = glob.rsplit('*').next().unwrap_or_default();
        path.ends_with(tail)
    } else {
        true
    }
}

fn net_range_allows(range: &types::NetPortSpec, port: i64) -> bool {
    match range {
        types::NetPortSpec::Single(v) => *v == port,
        types::NetPortSpec::Range(start, end) => port >= *start && port <= *end,
    }
}

#[cfg(test)]
mod tests {
    use super::{analyze, enforce_declared_capabilities, CapabilityFlowErrorKind};
    use crate::hir::lower::lower_to_hir;

    #[test]
    fn missing_capability_is_deterministic_compile_error() {
        let source = r#"
            fn main() {
                fs.read("cfg/app.nex");
                return;
            }
        "#;

        let hir = parse_and_lower(source);
        let report = analyze(&hir);
        let err = enforce_declared_capabilities(&hir, &report)
            .expect_err("missing fs capability must fail deterministically");

        assert_eq!(
            err.kind,
            CapabilityFlowErrorKind::MissingFsReadCapability {
                required: "fs.read:cfg/app.nex".to_string(),
            }
        );
        assert_eq!(err.function, "main");
        assert_eq!(err.span.line, 3);
        assert_eq!(err.span.col, 17);
        assert_eq!(
            err.to_string(),
            "capability-flow violation [missing_capability] at line 3, col 17 in fn main: missing declaration for fs.read:cfg/app.nex"
        );
    }

    #[test]
    fn capability_flow_collects_task_and_agent_boundaries() {
        let source = r#"
            cap fs.read("cfg/*");

            fn main() {
                fs.read("cfg/app.nex");
                spawn {
                    bus.send("alerts", "AlertV1", "payload");
                    return;
                };
                return;
            }
        "#;

        let hir = parse_and_lower(source);
        let report = analyze(&hir);

        assert_eq!(report.function_flows.len(), 1);
        assert_eq!(report.function_flows[0].function, "main");
        assert_eq!(
            report.function_flows[0].required_capabilities,
            vec![
                "bus.send".to_string(),
                "fs.read:cfg/app.nex".to_string(),
                "io.proxy".to_string(),
            ]
        );
        assert_eq!(report.task_boundaries.len(), 1);
        assert_eq!(report.task_boundaries[0].span.line, 6);
        assert_eq!(report.agent_boundaries.len(), 2);
    }

    #[test]
    fn declared_net_range_satisfies_requirement() {
        let source = r#"
            cap net.listen(8000..9000);

            fn main() {
                net.listen(8080);
                return;
            }
        "#;

        let hir = parse_and_lower(source);
        let report = analyze(&hir);
        enforce_declared_capabilities(&hir, &report)
            .expect("declared net capability should satisfy requirement");
    }

    fn parse_and_lower(source: &str) -> crate::hir::types::Program {
        let ast = crate::parser::parse(source).expect("source should parse");
        lower_to_hir(&ast)
    }
}
