use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::ast::Span;
use crate::hir::types;
use crate::runtime::agent_bus;

pub const COSTFACTS_MAGIC: [u8; 8] = *b"NEXCOST\0";
pub const COSTFACTS_VERSION: u32 = 1;

const BASE_EXPR_COST: u64 = 1;
const BASE_STMT_COST: u64 = 1;
const DEFAULT_IO_PROXY_FUEL_COST: u64 = 1;
const DEFAULT_LOOP_FUEL_BUDGET: u64 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostPolicyConfig {
    pub max_static_cost: u64,
    pub require_loop_fuel_checks: bool,
    pub recursion_limit: u32,
}

impl Default for CostPolicyConfig {
    fn default() -> Self {
        Self {
            max_static_cost: 16_384,
            require_loop_fuel_checks: true,
            recursion_limit: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCostFact {
    pub function: String,
    pub name_span: Span,
    pub static_cost_upper: u64,
    pub has_unbounded_loop: bool,
    pub unbounded_loop_span: Option<Span>,
    pub has_fuel_bounded_loop: bool,
    pub recursive: bool,
    pub max_call_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCostFact {
    pub function: String,
    pub span: Span,
    pub static_cost_upper: u64,
    pub has_unbounded_loop: bool,
    pub has_fuel_bounded_loop: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CostModelReport {
    pub function_facts: Vec<FunctionCostFact>,
    pub task_facts: Vec<TaskCostFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostPolicyErrorKind {
    UnboundedLoopWithoutFuelCheck,
    RecursiveCallCycle,
    RecursionLimitExceeded {
        max_call_depth: u32,
        recursion_limit: u32,
    },
    MaxStaticCostExceeded {
        estimated: u64,
        max_allowed: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostPolicyError {
    pub kind: CostPolicyErrorKind,
    pub function: String,
    pub span: Span,
}

impl fmt::Display for CostPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            CostPolicyErrorKind::UnboundedLoopWithoutFuelCheck => write!(
                f,
                "cost-policy violation [unbounded_loop] at line {}, col {} in fn {}: loop is unbounded without an explicit fuel.consume/check/debit guard",
                self.span.line, self.span.col, self.function
            ),
            CostPolicyErrorKind::RecursiveCallCycle => write!(
                f,
                "cost-policy violation [recursive_cycle] at line {}, col {} in fn {}: recursive call cycle has no static upper bound",
                self.span.line, self.span.col, self.function
            ),
            CostPolicyErrorKind::RecursionLimitExceeded {
                max_call_depth,
                recursion_limit,
            } => write!(
                f,
                "cost-policy violation [recursion_limit] at line {}, col {} in fn {}: max call depth {} exceeds recursion limit {}",
                self.span.line, self.span.col, self.function, max_call_depth, recursion_limit
            ),
            CostPolicyErrorKind::MaxStaticCostExceeded {
                estimated,
                max_allowed,
            } => write!(
                f,
                "cost-policy violation [max_static_cost] at line {}, col {} in fn {}: static cost {} exceeds configured max {}",
                self.span.line, self.span.col, self.function, estimated, max_allowed
            ),
        }
    }
}

impl std::error::Error for CostPolicyError {}

#[derive(Debug, Clone, Default)]
struct CostSummary {
    base_cost: u64,
    user_calls: BTreeMap<String, u64>,
    has_unbounded_loop: bool,
    unbounded_loop_span: Option<Span>,
    has_fuel_bounded_loop: bool,
}

impl CostSummary {
    fn saturating_add_cost(&mut self, value: u64) {
        self.base_cost = self.base_cost.saturating_add(value);
    }

    fn add_user_call(&mut self, callee: &str, count: u64) {
        if count == 0 {
            return;
        }

        let entry = self.user_calls.entry(callee.to_string()).or_insert(0);
        *entry = entry.saturating_add(count);
    }

    fn merge_sum(&mut self, other: CostSummary) {
        self.base_cost = self.base_cost.saturating_add(other.base_cost);

        for (callee, count) in other.user_calls {
            let entry = self.user_calls.entry(callee).or_insert(0);
            *entry = entry.saturating_add(count);
        }

        self.has_unbounded_loop |= other.has_unbounded_loop;
        self.has_fuel_bounded_loop |= other.has_fuel_bounded_loop;
        self.unbounded_loop_span =
            earliest_span(self.unbounded_loop_span, other.unbounded_loop_span);
    }

    fn branch_upper(then_summary: CostSummary, else_summary: CostSummary) -> CostSummary {
        let mut merged_calls = BTreeMap::new();

        for (callee, count) in &then_summary.user_calls {
            merged_calls.insert(callee.clone(), *count);
        }

        for (callee, count) in &else_summary.user_calls {
            let entry = merged_calls.entry(callee.clone()).or_insert(0);
            *entry = (*entry).max(*count);
        }

        CostSummary {
            base_cost: then_summary.base_cost.max(else_summary.base_cost),
            user_calls: merged_calls,
            has_unbounded_loop: then_summary.has_unbounded_loop || else_summary.has_unbounded_loop,
            unbounded_loop_span: earliest_span(
                then_summary.unbounded_loop_span,
                else_summary.unbounded_loop_span,
            ),
            has_fuel_bounded_loop: then_summary.has_fuel_bounded_loop
                || else_summary.has_fuel_bounded_loop,
        }
    }

    fn multiplied(mut self, factor: u64) -> CostSummary {
        self.base_cost = self.base_cost.saturating_mul(factor);
        for count in self.user_calls.values_mut() {
            *count = (*count).saturating_mul(factor);
        }
        self
    }
}

#[derive(Debug, Clone)]
struct LocalFunctionSummary {
    function: String,
    name_span: Span,
    summary: CostSummary,
}

#[derive(Debug, Clone)]
struct PendingTaskFact {
    function: String,
    span: Span,
    summary: CostSummary,
}

pub fn analyze(program: &types::Program) -> CostModelReport {
    let mut functions: Vec<&types::Function> = Vec::new();
    for item in &program.items {
        if let types::Item::Function(function) = item {
            functions.push(function);
        }
    }

    functions.sort_by(|a, b| function_order_key(a).cmp(&function_order_key(b)));

    let mut function_names = BTreeSet::new();
    for function in &functions {
        function_names.insert(function.name.clone());
    }

    let mut locals: BTreeMap<String, LocalFunctionSummary> = BTreeMap::new();
    let mut pending_tasks: Vec<PendingTaskFact> = Vec::new();

    for function in &functions {
        let mut estimator = Estimator::new(&function_names, &function.name, function.name_span);
        let summary = estimator.estimate_block(&function.body);

        pending_tasks.extend(estimator.pending_tasks);

        locals.insert(
            function.name.clone(),
            LocalFunctionSummary {
                function: function.name.clone(),
                name_span: function.name_span,
                summary,
            },
        );
    }

    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (function, local) in &locals {
        let mut callees = BTreeSet::new();
        for callee in local.summary.user_calls.keys() {
            if locals.contains_key(callee) {
                callees.insert(callee.clone());
            }
        }
        edges.insert(function.clone(), callees);
    }

    let recursive_functions = detect_recursive_functions(&locals, &edges);

    let mut depth_cache: BTreeMap<String, u32> = BTreeMap::new();
    let mut cost_cache: BTreeMap<String, u64> = BTreeMap::new();

    let mut function_facts = Vec::new();
    for function in locals.keys() {
        let local = locals.get(function).expect("local summary must exist");
        let max_call_depth = if recursive_functions.contains(function) {
            u32::MAX
        } else {
            resolve_call_depth(
                function,
                &edges,
                &recursive_functions,
                &mut depth_cache,
                &mut BTreeSet::new(),
            )
        };

        let static_cost_upper =
            if local.summary.has_unbounded_loop || recursive_functions.contains(function) {
                u64::MAX
            } else {
                resolve_function_cost(
                    function,
                    &locals,
                    &recursive_functions,
                    &mut cost_cache,
                    &mut BTreeSet::new(),
                )
            };

        function_facts.push(FunctionCostFact {
            function: local.function.clone(),
            name_span: local.name_span,
            static_cost_upper,
            has_unbounded_loop: local.summary.has_unbounded_loop,
            unbounded_loop_span: local.summary.unbounded_loop_span,
            has_fuel_bounded_loop: local.summary.has_fuel_bounded_loop,
            recursive: recursive_functions.contains(function),
            max_call_depth,
        });
    }

    function_facts.sort_by(|a, b| function_fact_order_key(a).cmp(&function_fact_order_key(b)));

    let mut task_facts = Vec::new();
    for pending in pending_tasks {
        let static_cost_upper = if pending.summary.has_unbounded_loop {
            u64::MAX
        } else {
            resolve_summary_cost(
                &pending.summary,
                &locals,
                &recursive_functions,
                &mut cost_cache,
            )
        };

        task_facts.push(TaskCostFact {
            function: pending.function,
            span: pending.span,
            static_cost_upper,
            has_unbounded_loop: pending.summary.has_unbounded_loop,
            has_fuel_bounded_loop: pending.summary.has_fuel_bounded_loop,
        });
    }

    task_facts.sort_by(|a, b| task_fact_order_key(a).cmp(&task_fact_order_key(b)));

    CostModelReport {
        function_facts,
        task_facts,
    }
}

pub fn enforce_policy(
    report: &CostModelReport,
    config: CostPolicyConfig,
) -> Result<(), CostPolicyError> {
    let mut function_facts = report.function_facts.clone();
    function_facts.sort_by(|a, b| function_fact_order_key(a).cmp(&function_fact_order_key(b)));

    for fact in &function_facts {
        if config.require_loop_fuel_checks && fact.has_unbounded_loop {
            return Err(CostPolicyError {
                kind: CostPolicyErrorKind::UnboundedLoopWithoutFuelCheck,
                function: fact.function.clone(),
                span: fact.unbounded_loop_span.unwrap_or(fact.name_span),
            });
        }

        if fact.recursive {
            return Err(CostPolicyError {
                kind: CostPolicyErrorKind::RecursiveCallCycle,
                function: fact.function.clone(),
                span: fact.name_span,
            });
        }

        if fact.max_call_depth > config.recursion_limit {
            return Err(CostPolicyError {
                kind: CostPolicyErrorKind::RecursionLimitExceeded {
                    max_call_depth: fact.max_call_depth,
                    recursion_limit: config.recursion_limit,
                },
                function: fact.function.clone(),
                span: fact.name_span,
            });
        }

        if fact.static_cost_upper > config.max_static_cost {
            return Err(CostPolicyError {
                kind: CostPolicyErrorKind::MaxStaticCostExceeded {
                    estimated: fact.static_cost_upper,
                    max_allowed: config.max_static_cost,
                },
                function: fact.function.clone(),
                span: fact.name_span,
            });
        }
    }

    Ok(())
}

pub fn encode(report: &CostModelReport) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&COSTFACTS_MAGIC);
    write_u32(&mut out, COSTFACTS_VERSION);

    let mut function_facts = report.function_facts.clone();
    function_facts.sort_by(|a, b| function_fact_order_key(a).cmp(&function_fact_order_key(b)));

    write_len(&mut out, function_facts.len());
    for fact in &function_facts {
        write_string(&mut out, &fact.function);
        write_u64(&mut out, fact.name_span.line as u64);
        write_u64(&mut out, fact.name_span.col as u64);
        write_u64(&mut out, fact.static_cost_upper);
        write_bool(&mut out, fact.has_unbounded_loop);
        write_span_opt(&mut out, fact.unbounded_loop_span);
        write_bool(&mut out, fact.has_fuel_bounded_loop);
        write_bool(&mut out, fact.recursive);
        write_u32(&mut out, fact.max_call_depth);
    }

    let mut task_facts = report.task_facts.clone();
    task_facts.sort_by(|a, b| task_fact_order_key(a).cmp(&task_fact_order_key(b)));

    write_len(&mut out, task_facts.len());
    for fact in &task_facts {
        write_string(&mut out, &fact.function);
        write_u64(&mut out, fact.span.line as u64);
        write_u64(&mut out, fact.span.col as u64);
        write_u64(&mut out, fact.static_cost_upper);
        write_bool(&mut out, fact.has_unbounded_loop);
        write_bool(&mut out, fact.has_fuel_bounded_loop);
    }

    out
}

fn function_order_key(function: &types::Function) -> (String, usize, usize) {
    (
        function.name.clone(),
        function.name_span.line,
        function.name_span.col,
    )
}

fn function_fact_order_key(fact: &FunctionCostFact) -> (String, usize, usize) {
    (
        fact.function.clone(),
        fact.name_span.line,
        fact.name_span.col,
    )
}

fn task_fact_order_key(fact: &TaskCostFact) -> (String, usize, usize) {
    (fact.function.clone(), fact.span.line, fact.span.col)
}

struct Estimator<'a> {
    function_names: &'a BTreeSet<String>,
    current_function: String,
    current_function_span: Span,
    pending_tasks: Vec<PendingTaskFact>,
}

impl<'a> Estimator<'a> {
    fn new(function_names: &'a BTreeSet<String>, function: &str, function_span: Span) -> Self {
        Self {
            function_names,
            current_function: function.to_string(),
            current_function_span: function_span,
            pending_tasks: Vec::new(),
        }
    }

    fn estimate_block(&mut self, block: &types::Block) -> CostSummary {
        let mut summary = CostSummary::default();

        for stmt in &block.stmts {
            summary.merge_sum(self.estimate_stmt(stmt));
        }

        summary
    }

    fn estimate_stmt(&mut self, stmt: &types::Stmt) -> CostSummary {
        match stmt {
            types::Stmt::Let { value, .. } => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_STMT_COST);
                summary.merge_sum(self.estimate_expr(value));
                summary
            }
            types::Stmt::Return(Some(expr)) => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_STMT_COST);
                summary.merge_sum(self.estimate_expr(expr));
                summary
            }
            types::Stmt::Return(None) => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_STMT_COST);
                summary
            }
            types::Stmt::Expr(expr) => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_STMT_COST);
                summary.merge_sum(self.estimate_expr(expr));
                summary
            }
            types::Stmt::If {
                cond,
                then_block,
                else_block,
            } => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_STMT_COST);
                summary.merge_sum(self.estimate_expr(cond));

                let then_summary = self.estimate_block(then_block);
                let else_summary = else_block
                    .as_ref()
                    .map(|block| self.estimate_block(block))
                    .unwrap_or_default();

                summary.merge_sum(CostSummary::branch_upper(then_summary, else_summary));
                summary
            }
            types::Stmt::Loop(block) => self.estimate_loop(block),
            types::Stmt::Defer(block) => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_STMT_COST);
                summary.merge_sum(self.estimate_block(block));
                summary
            }
        }
    }

    fn estimate_loop(&mut self, block: &types::Block) -> CostSummary {
        let mut summary = CostSummary::default();
        summary.saturating_add_cost(BASE_STMT_COST);

        let body_summary = self.estimate_block(block);

        if body_summary.has_unbounded_loop {
            summary.has_unbounded_loop = true;
            summary.unbounded_loop_span = earliest_span(
                body_summary.unbounded_loop_span,
                span_from_block(block, self.current_function_span),
            );
            summary.base_cost = u64::MAX;
            return summary;
        }

        if let Some(debit) = loop_guard_debit(block) {
            let iterations = loop_iterations_from_debit(debit);
            let multiplied = body_summary.multiplied(iterations);
            summary.has_fuel_bounded_loop = true;
            summary.merge_sum(multiplied);
            return summary;
        }

        summary.has_unbounded_loop = true;
        summary.unbounded_loop_span = span_from_block(block, self.current_function_span);
        summary.base_cost = u64::MAX;
        summary
    }

    fn estimate_expr(&mut self, expr: &types::Expr) -> CostSummary {
        match expr {
            types::Expr::Literal(_) | types::Expr::Variable(_) => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_EXPR_COST);
                summary
            }
            types::Expr::Call { func, args, .. } => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_EXPR_COST);

                for arg in args {
                    summary.merge_sum(self.estimate_expr(arg));
                }

                let normalized = normalize_call_name(func);
                summary.saturating_add_cost(builtin_call_cost(&normalized, args));

                if self.function_names.contains(func) {
                    summary.add_user_call(func, 1);
                }

                summary
            }
            types::Expr::BinaryOp { left, right, .. } => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_EXPR_COST);
                summary.merge_sum(self.estimate_expr(left));
                summary.merge_sum(self.estimate_expr(right));
                summary
            }
            types::Expr::If {
                cond,
                then_block,
                else_block,
            } => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_EXPR_COST);
                summary.merge_sum(self.estimate_expr(cond));

                let then_summary = self.estimate_block(then_block);
                let else_summary = else_block
                    .as_ref()
                    .map(|block| self.estimate_block(block))
                    .unwrap_or_default();

                summary.merge_sum(CostSummary::branch_upper(then_summary, else_summary));
                summary
            }
            types::Expr::Block(block) => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_EXPR_COST);
                summary.merge_sum(self.estimate_block(block));
                summary
            }
            types::Expr::Spawn { block, span } => {
                let mut summary = CostSummary::default();
                summary.saturating_add_cost(BASE_EXPR_COST);

                let block_summary = self.estimate_block(block);
                self.pending_tasks.push(PendingTaskFact {
                    function: self.current_function.clone(),
                    span: *span,
                    summary: block_summary.clone(),
                });

                summary.merge_sum(block_summary);
                summary
            }
        }
    }
}

fn resolve_function_cost(
    function: &str,
    locals: &BTreeMap<String, LocalFunctionSummary>,
    recursive_functions: &BTreeSet<String>,
    cache: &mut BTreeMap<String, u64>,
    visiting: &mut BTreeSet<String>,
) -> u64 {
    if recursive_functions.contains(function) {
        return u64::MAX;
    }

    if let Some(cost) = cache.get(function) {
        return *cost;
    }

    if !visiting.insert(function.to_string()) {
        return u64::MAX;
    }

    let local = match locals.get(function) {
        Some(local) => local,
        None => {
            visiting.remove(function);
            return BASE_STMT_COST;
        }
    };

    if local.summary.has_unbounded_loop {
        visiting.remove(function);
        cache.insert(function.to_string(), u64::MAX);
        return u64::MAX;
    }

    let mut total = local.summary.base_cost;

    for (callee, count) in &local.summary.user_calls {
        if !locals.contains_key(callee) {
            continue;
        }

        let callee_cost =
            resolve_function_cost(callee, locals, recursive_functions, cache, visiting);
        total = total.saturating_add(callee_cost.saturating_mul(*count));
    }

    visiting.remove(function);
    cache.insert(function.to_string(), total);
    total
}

fn resolve_summary_cost(
    summary: &CostSummary,
    locals: &BTreeMap<String, LocalFunctionSummary>,
    recursive_functions: &BTreeSet<String>,
    function_cost_cache: &mut BTreeMap<String, u64>,
) -> u64 {
    let mut total = summary.base_cost;

    for (callee, count) in &summary.user_calls {
        if !locals.contains_key(callee) {
            continue;
        }

        let callee_cost = resolve_function_cost(
            callee,
            locals,
            recursive_functions,
            function_cost_cache,
            &mut BTreeSet::new(),
        );
        total = total.saturating_add(callee_cost.saturating_mul(*count));
    }

    total
}

fn detect_recursive_functions(
    locals: &BTreeMap<String, LocalFunctionSummary>,
    edges: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut recursive = BTreeSet::new();

    for function in locals.keys() {
        if reaches(function, function, edges, &mut BTreeSet::new()) {
            recursive.insert(function.clone());
        }
    }

    recursive
}

fn reaches(
    current: &str,
    target: &str,
    edges: &BTreeMap<String, BTreeSet<String>>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if !visited.insert(current.to_string()) {
        return false;
    }

    let Some(callees) = edges.get(current) else {
        return false;
    };

    for callee in callees {
        if callee == target {
            return true;
        }

        if reaches(callee, target, edges, visited) {
            return true;
        }
    }

    false
}

fn resolve_call_depth(
    function: &str,
    edges: &BTreeMap<String, BTreeSet<String>>,
    recursive_functions: &BTreeSet<String>,
    cache: &mut BTreeMap<String, u32>,
    visiting: &mut BTreeSet<String>,
) -> u32 {
    if recursive_functions.contains(function) {
        return u32::MAX;
    }

    if let Some(depth) = cache.get(function) {
        return *depth;
    }

    if !visiting.insert(function.to_string()) {
        return u32::MAX;
    }

    let mut max_child_depth = 0u32;

    if let Some(callees) = edges.get(function) {
        for callee in callees {
            let depth = resolve_call_depth(callee, edges, recursive_functions, cache, visiting);
            max_child_depth = max_child_depth.max(depth);
        }
    }

    visiting.remove(function);

    let depth = 1u32.saturating_add(max_child_depth);
    cache.insert(function.to_string(), depth);
    depth
}

fn normalize_call_name(func: &str) -> String {
    func.trim().to_ascii_lowercase()
}

fn builtin_call_cost(normalized: &str, args: &[types::Expr]) -> u64 {
    if is_fuel_guard_name(normalized) {
        return fuel_guard_debit_from_args(args).unwrap_or(1);
    }

    if normalized == "bus.send" {
        return agent_bus::DEFAULT_BASE_SEND_COST;
    }

    if normalized == "bus.recv" {
        return 1;
    }

    if normalized.starts_with("fs.")
        || normalized.starts_with("net.")
        || normalized.starts_with("io_proxy.")
    {
        return DEFAULT_IO_PROXY_FUEL_COST;
    }

    BASE_EXPR_COST
}

fn is_fuel_guard_name(normalized: &str) -> bool {
    normalized == "fuel.consume" || normalized == "fuel.check" || normalized == "fuel.debit"
}

fn fuel_guard_debit_from_args(args: &[types::Expr]) -> Option<u64> {
    let first = args.first()?;
    match first {
        types::Expr::Literal(types::Literal::Int(value)) if *value > 0 => {
            u64::try_from(*value).ok()
        }
        _ => None,
    }
}

fn loop_guard_debit(block: &types::Block) -> Option<u64> {
    let first_stmt = block.stmts.first()?;
    match first_stmt {
        types::Stmt::Expr(types::Expr::Call { func, args, .. }) => {
            let normalized = normalize_call_name(func);
            if is_fuel_guard_name(&normalized) {
                return fuel_guard_debit_from_args(args);
            }
            None
        }
        _ => None,
    }
}

fn loop_iterations_from_debit(debit: u64) -> u64 {
    let safe_debit = debit.max(1);
    DEFAULT_LOOP_FUEL_BUDGET.saturating_add(safe_debit - 1) / safe_debit
}

fn earliest_span(lhs: Option<Span>, rhs: Option<Span>) -> Option<Span> {
    match (lhs, rhs) {
        (Some(a), Some(b)) => {
            if (a.line, a.col) <= (b.line, b.col) {
                Some(a)
            } else {
                Some(b)
            }
        }
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn span_from_block(block: &types::Block, fallback: Span) -> Option<Span> {
    first_span_in_block(block).or(Some(fallback))
}

fn first_span_in_block(block: &types::Block) -> Option<Span> {
    for stmt in &block.stmts {
        if let Some(span) = span_from_stmt(stmt) {
            return Some(span);
        }
    }
    None
}

fn span_from_stmt(stmt: &types::Stmt) -> Option<Span> {
    match stmt {
        types::Stmt::Let { value, .. } => span_from_expr(value),
        types::Stmt::Return(Some(expr)) => span_from_expr(expr),
        types::Stmt::Return(None) => None,
        types::Stmt::Expr(expr) => span_from_expr(expr),
        types::Stmt::If {
            cond,
            then_block,
            else_block,
        } => earliest_span(
            span_from_expr(cond),
            earliest_span(
                first_span_in_block(then_block),
                else_block.as_ref().and_then(first_span_in_block),
            ),
        ),
        types::Stmt::Loop(block) | types::Stmt::Defer(block) => first_span_in_block(block),
    }
}

fn span_from_expr(expr: &types::Expr) -> Option<Span> {
    match expr {
        types::Expr::Call { span, .. } => Some(*span),
        types::Expr::BinaryOp { left, right, .. } => {
            earliest_span(span_from_expr(left), span_from_expr(right))
        }
        types::Expr::If {
            cond,
            then_block,
            else_block,
        } => earliest_span(
            span_from_expr(cond),
            earliest_span(
                first_span_in_block(then_block),
                else_block.as_ref().and_then(first_span_in_block),
            ),
        ),
        types::Expr::Block(block) => first_span_in_block(block),
        types::Expr::Spawn { span, .. } => Some(*span),
        types::Expr::Literal(_) | types::Expr::Variable(_) => None,
    }
}

fn write_u32(dst: &mut Vec<u8>, value: u32) {
    dst.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(dst: &mut Vec<u8>, value: u64) {
    dst.extend_from_slice(&value.to_le_bytes());
}

fn write_len(dst: &mut Vec<u8>, len: usize) {
    let len_u64 = u64::try_from(len).expect("length must fit in u64");
    write_u64(dst, len_u64);
}

fn write_string(dst: &mut Vec<u8>, value: &str) {
    write_len(dst, value.len());
    dst.extend_from_slice(value.as_bytes());
}

fn write_bool(dst: &mut Vec<u8>, value: bool) {
    dst.push(if value { 1 } else { 0 });
}

fn write_span_opt(dst: &mut Vec<u8>, span: Option<Span>) {
    match span {
        Some(span) => {
            write_bool(dst, true);
            write_u64(dst, span.line as u64);
            write_u64(dst, span.col as u64);
        }
        None => {
            write_bool(dst, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{analyze, encode, enforce_policy, CostPolicyConfig, CostPolicyErrorKind};
    use crate::hir::lower::lower_to_hir;

    struct GoldenCase {
        name: &'static str,
        source: &'static str,
        golden_relpath: &'static str,
    }

    const GOLDEN_CASES: &[GoldenCase] = &[
        GoldenCase {
            name: "simple_program_costfacts",
            source: r#"
                fn worker() {
                    fs.read("cfg/app.nex");
                    return;
                }

                fn main() {
                    worker();
                    return;
                }
            "#,
            golden_relpath: "src/hir/golden/simple_program.costfacts.hex",
        },
        GoldenCase {
            name: "fuel_guarded_loop_costfacts",
            source: r#"
                fn main() {
                    loop {
                        fuel.consume(1);
                    }
                }
            "#,
            golden_relpath: "src/hir/golden/fuel_guarded_loop.costfacts.hex",
        },
    ];

    #[test]
    fn unbounded_loop_fails_under_strict_policy() {
        let source = "fn main() {\n    loop {\n        let x: int = 1;\n    }\n}\n";
        let report = analyze(&parse_and_lower(source));

        let err = enforce_policy(&report, CostPolicyConfig::default())
            .expect_err("strict policy must reject unbounded loop");

        assert_eq!(err.kind, CostPolicyErrorKind::UnboundedLoopWithoutFuelCheck);
        assert_eq!(err.function, "main");
        assert_eq!(err.span.line, 1);
        assert_eq!(err.span.col, 4);
        assert_eq!(
            err.to_string(),
            "cost-policy violation [unbounded_loop] at line 1, col 4 in fn main: loop is unbounded without an explicit fuel.consume/check/debit guard"
        );
    }

    #[test]
    fn bounded_loop_passes_under_strict_policy() {
        let source = "fn main() {\n    loop {\n        fuel.consume(1);\n    }\n}\n";
        let report = analyze(&parse_and_lower(source));

        enforce_policy(
            &report,
            CostPolicyConfig {
                max_static_cost: u64::MAX,
                require_loop_fuel_checks: true,
                recursion_limit: u32::MAX,
            },
        )
        .expect("fuel-guarded loop should pass strict policy");
    }

    #[test]
    fn golden_costfacts_bytes_match_exactly() {
        let update = std::env::var("NEX_UPDATE_COSTFACTS_GOLDEN")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false);

        for case in GOLDEN_CASES {
            let report = analyze(&parse_and_lower(case.source));
            let encoded = encode(&report);
            let path = project_root().join(case.golden_relpath);

            if update {
                fs::write(&path, format!("{}\n", to_hex(&encoded)))
                    .expect("write costfacts golden");
            }

            let expected_hex = fs::read_to_string(&path).expect("read costfacts golden");
            let expected = from_hex(&expected_hex).expect("parse costfacts golden");

            assert_eq!(
                encoded, expected,
                "costfacts golden mismatch for {}",
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

    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(nibble_to_hex((byte >> 4) & 0x0f));
            out.push(nibble_to_hex(byte & 0x0f));
        }
        out
    }

    fn nibble_to_hex(nibble: u8) -> char {
        match nibble {
            0..=9 => (b'0' + nibble) as char,
            10..=15 => (b'a' + (nibble - 10)) as char,
            _ => unreachable!("nibble out of range"),
        }
    }

    fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
        let mut filtered = String::with_capacity(hex.len());
        for ch in hex.chars() {
            if !ch.is_whitespace() {
                filtered.push(ch);
            }
        }

        if filtered.len() % 2 != 0 {
            return Err("hex length must be even".to_string());
        }

        let mut out = Vec::with_capacity(filtered.len() / 2);
        let bytes = filtered.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let hi = hex_value(bytes[i]).ok_or_else(|| "invalid hex".to_string())?;
            let lo = hex_value(bytes[i + 1]).ok_or_else(|| "invalid hex".to_string())?;
            out.push((hi << 4) | lo);
            i += 2;
        }

        Ok(out)
    }

    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
}
