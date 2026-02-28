use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::ast::Span;
use crate::hir::types;

pub const DEADLOCK_RISK_MAGIC: [u8; 8] = *b"NEXDLK\0\0";
pub const DEADLOCK_RISK_VERSION: u32 = 1;

const MAX_GRAPH_NODES: usize = 4096;
const MAX_GRAPH_EDGES: usize = 16384;
const MAX_GRAPH_TRAVERSAL_STEPS: usize = 32768;

const MAX_DECODE_WARNINGS: usize = 10000;
const MAX_DECODE_NODES: usize = 20000;
const MAX_DECODE_EDGES: usize = 50000;
const MAX_DECODE_STRING_LEN: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlockRiskPolicy {
    pub deny_risk: bool,
}

impl Default for DeadlockRiskPolicy {
    fn default() -> Self {
        Self { deny_risk: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadlockRiskKind {
    WaitCycle,
    RecvWithoutKnownSender,
    DynamicRecvPattern,
    DynamicSendPattern,
    GraphTruncated,
}

impl DeadlockRiskKind {
    fn code(&self) -> &'static str {
        match self {
            DeadlockRiskKind::WaitCycle => "wait_cycle",
            DeadlockRiskKind::RecvWithoutKnownSender => "recv_without_known_sender",
            DeadlockRiskKind::DynamicRecvPattern => "dynamic_recv_pattern",
            DeadlockRiskKind::DynamicSendPattern => "dynamic_send_pattern",
            DeadlockRiskKind::GraphTruncated => "graph_truncated",
        }
    }

    fn message(&self) -> &'static str {
        match self {
            DeadlockRiskKind::WaitCycle => {
                "wait-for cycle risk detected in static channel approximation"
            }
            DeadlockRiskKind::RecvWithoutKnownSender => {
                "recv observed with no statically known sender on the same channel"
            }
            DeadlockRiskKind::DynamicRecvPattern => {
                "dynamic recv channel target prevents precise static wait-for analysis"
            }
            DeadlockRiskKind::DynamicSendPattern => {
                "dynamic send channel target prevents precise static wait-for analysis"
            }
            DeadlockRiskKind::GraphTruncated => {
                "wait-for graph exceeded static analysis bounds; risk report is conservative"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadlockRiskWarning {
    pub kind: DeadlockRiskKind,
    pub function: String,
    pub span: Span,
}

impl fmt::Display for DeadlockRiskWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "deadlock-risk warning [{}] at line {}, col {} in fn {}: {}",
            self.kind.code(),
            self.span.line,
            self.span.col,
            self.function,
            self.kind.message()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadlockRiskError {
    pub warning: DeadlockRiskWarning,
}

impl fmt::Display for DeadlockRiskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "deadlock-risk policy violation [{}] at line {}, col {} in fn {}: {}",
            self.warning.kind.code(),
            self.warning.span.line,
            self.warning.span.col,
            self.warning.function,
            self.warning.kind.message()
        )
    }
}

impl std::error::Error for DeadlockRiskError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WaitForNode {
    Function(String),
    Channel(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitForEdge {
    pub from: WaitForNode,
    pub to: WaitForNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WaitForGraph {
    pub nodes: Vec<WaitForNode>,
    pub edges: Vec<WaitForEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeadlockRiskReport {
    pub warnings: Vec<DeadlockRiskWarning>,
    pub graph: WaitForGraph,
    pub graph_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    InvalidMagic,
    UnsupportedVersion {
        found: u32,
    },
    Truncated {
        context: &'static str,
    },
    InvalidTag {
        context: &'static str,
        tag: u8,
    },
    LengthLimitExceeded {
        context: &'static str,
        len: usize,
    },
    Utf8 {
        context: &'static str,
    },
    InvalidNodeIndex {
        from: usize,
        to: usize,
        node_count: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::InvalidMagic => write!(f, "invalid deadlock-risk magic"),
            DecodeError::UnsupportedVersion { found } => {
                write!(f, "unsupported deadlock-risk version: {}", found)
            }
            DecodeError::Truncated { context } => {
                write!(f, "truncated deadlock-risk stream at {}", context)
            }
            DecodeError::InvalidTag { context, tag } => {
                write!(f, "invalid tag for {}: {}", context, tag)
            }
            DecodeError::LengthLimitExceeded { context, len } => {
                write!(f, "length limit exceeded for {}: {}", context, len)
            }
            DecodeError::Utf8 { context } => write!(f, "invalid utf8 for {}", context),
            DecodeError::InvalidNodeIndex {
                from,
                to,
                node_count,
            } => write!(
                f,
                "invalid edge indices ({}, {}) for node_count {}",
                from, to, node_count
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

pub fn analyze(program: &types::Program) -> DeadlockRiskReport {
    let mut walker = Walker::default();
    walker.walk_program(program);
    let function_map = walker.function_map;

    let mut edge_map: BTreeMap<WaitForNode, BTreeSet<WaitForNode>> = BTreeMap::new();
    let mut nodes: BTreeSet<WaitForNode> = BTreeSet::new();
    let mut edge_count = 0usize;
    let mut graph_truncated = false;

    for (function, endpoints) in &function_map {
        let fn_node = WaitForNode::Function(function.clone());
        add_node_bounded(&mut nodes, fn_node.clone(), &mut graph_truncated);

        for channel in endpoints.recv_channels.keys() {
            let channel_node = WaitForNode::Channel(channel.clone());
            add_edge_bounded(
                &mut nodes,
                &mut edge_map,
                &mut edge_count,
                fn_node.clone(),
                channel_node,
                &mut graph_truncated,
            );
        }

        for channel in endpoints.send_channels.keys() {
            let channel_node = WaitForNode::Channel(channel.clone());
            add_edge_bounded(
                &mut nodes,
                &mut edge_map,
                &mut edge_count,
                channel_node,
                fn_node.clone(),
                &mut graph_truncated,
            );
        }
    }

    let graph = WaitForGraph {
        nodes: nodes.iter().cloned().collect(),
        edges: collect_edges(&edge_map),
    };

    let mut warnings = collect_warnings(&function_map, &edge_map, graph_truncated);
    sort_and_dedup_warnings(&mut warnings);

    DeadlockRiskReport {
        warnings,
        graph,
        graph_truncated,
    }
}

pub fn enforce_policy(
    report: &DeadlockRiskReport,
    policy: DeadlockRiskPolicy,
) -> Result<(), DeadlockRiskError> {
    if !policy.deny_risk {
        return Ok(());
    }

    if let Some(warning) = report.warnings.first() {
        return Err(DeadlockRiskError {
            warning: warning.clone(),
        });
    }

    Ok(())
}

pub fn encode(report: &DeadlockRiskReport) -> Vec<u8> {
    let mut warnings = report.warnings.clone();
    sort_and_dedup_warnings(&mut warnings);

    let mut nodes = report.graph.nodes.clone();
    nodes.sort();

    let mut index_by_node = BTreeMap::new();
    for (idx, node) in nodes.iter().enumerate() {
        index_by_node.insert(node.clone(), idx);
    }

    let mut edges = report.graph.edges.clone();
    edges.sort_by(|a, b| wait_for_edge_key(a).cmp(&wait_for_edge_key(b)));
    edges.dedup_by(|a, b| a == b);

    let mut out = Vec::new();
    out.extend_from_slice(&DEADLOCK_RISK_MAGIC);
    write_u32(&mut out, DEADLOCK_RISK_VERSION);

    write_len(&mut out, warnings.len());
    for warning in &warnings {
        write_u8(&mut out, warning_kind_tag(&warning.kind));
        write_string(&mut out, &warning.function);
        write_u64(&mut out, warning.span.line as u64);
        write_u64(&mut out, warning.span.col as u64);
    }

    write_bool(&mut out, report.graph_truncated);

    write_len(&mut out, nodes.len());
    for node in &nodes {
        match node {
            WaitForNode::Function(name) => {
                write_u8(&mut out, 1);
                write_string(&mut out, name);
            }
            WaitForNode::Channel(channel) => {
                write_u8(&mut out, 2);
                write_string(&mut out, channel);
            }
        }
    }

    write_len(&mut out, edges.len());
    for edge in &edges {
        let from_idx = *index_by_node
            .get(&edge.from)
            .expect("edge source must be present in node index");
        let to_idx = *index_by_node
            .get(&edge.to)
            .expect("edge destination must be present in node index");
        write_u64(&mut out, from_idx as u64);
        write_u64(&mut out, to_idx as u64);
    }

    out
}

pub fn decode(bytes: &[u8]) -> Result<DeadlockRiskReport, DecodeError> {
    let mut reader = Reader::new(bytes);

    let magic = reader.read_fixed::<8>("magic")?;
    if magic != DEADLOCK_RISK_MAGIC {
        return Err(DecodeError::InvalidMagic);
    }

    let version = reader.read_u32("version")?;
    if version != DEADLOCK_RISK_VERSION {
        return Err(DecodeError::UnsupportedVersion { found: version });
    }

    let warning_len = reader.read_len("warnings.len", MAX_DECODE_WARNINGS)?;
    let mut warnings = Vec::with_capacity(warning_len);
    for _ in 0..warning_len {
        let kind_tag = reader.read_u8("warning.kind")?;
        let kind = parse_warning_kind(kind_tag)?;
        let function = reader.read_string("warning.function", MAX_DECODE_STRING_LEN)?;
        let line = reader.read_u64("warning.line")?;
        let col = reader.read_u64("warning.col")?;
        warnings.push(DeadlockRiskWarning {
            kind,
            function,
            span: span_from_u64(line, col),
        });
    }

    let graph_truncated = reader.read_bool("graph_truncated")?;

    let node_len = reader.read_len("nodes.len", MAX_DECODE_NODES)?;
    let mut nodes = Vec::with_capacity(node_len);
    for _ in 0..node_len {
        let tag = reader.read_u8("node.tag")?;
        let value = reader.read_string("node.value", MAX_DECODE_STRING_LEN)?;
        let node = match tag {
            1 => WaitForNode::Function(value),
            2 => WaitForNode::Channel(value),
            _ => {
                return Err(DecodeError::InvalidTag {
                    context: "node.tag",
                    tag,
                });
            }
        };
        nodes.push(node);
    }

    let edge_len = reader.read_len("edges.len", MAX_DECODE_EDGES)?;
    let mut edges = Vec::with_capacity(edge_len);
    for _ in 0..edge_len {
        let from_idx = reader.read_len("edge.from", MAX_DECODE_NODES)?;
        let to_idx = reader.read_len("edge.to", MAX_DECODE_NODES)?;

        if from_idx >= nodes.len() || to_idx >= nodes.len() {
            return Err(DecodeError::InvalidNodeIndex {
                from: from_idx,
                to: to_idx,
                node_count: nodes.len(),
            });
        }

        edges.push(WaitForEdge {
            from: nodes[from_idx].clone(),
            to: nodes[to_idx].clone(),
        });
    }

    warnings.sort_by(|a, b| warning_order_key(a).cmp(&warning_order_key(b)));
    warnings.dedup_by(|a, b| warning_order_key(a) == warning_order_key(b));

    Ok(DeadlockRiskReport {
        warnings,
        graph: WaitForGraph { nodes, edges },
        graph_truncated,
    })
}

fn span_from_u64(line: u64, col: u64) -> Span {
    let line = usize::try_from(line).unwrap_or(usize::MAX);
    let col = usize::try_from(col).unwrap_or(usize::MAX);
    Span { line, col }
}

fn warning_kind_tag(kind: &DeadlockRiskKind) -> u8 {
    match kind {
        DeadlockRiskKind::WaitCycle => 1,
        DeadlockRiskKind::RecvWithoutKnownSender => 2,
        DeadlockRiskKind::DynamicRecvPattern => 3,
        DeadlockRiskKind::DynamicSendPattern => 4,
        DeadlockRiskKind::GraphTruncated => 5,
    }
}

fn parse_warning_kind(tag: u8) -> Result<DeadlockRiskKind, DecodeError> {
    match tag {
        1 => Ok(DeadlockRiskKind::WaitCycle),
        2 => Ok(DeadlockRiskKind::RecvWithoutKnownSender),
        3 => Ok(DeadlockRiskKind::DynamicRecvPattern),
        4 => Ok(DeadlockRiskKind::DynamicSendPattern),
        5 => Ok(DeadlockRiskKind::GraphTruncated),
        _ => Err(DecodeError::InvalidTag {
            context: "warning.kind",
            tag,
        }),
    }
}

fn wait_for_edge_key(edge: &WaitForEdge) -> (WaitForNode, WaitForNode) {
    (edge.from.clone(), edge.to.clone())
}

fn collect_edges(edge_map: &BTreeMap<WaitForNode, BTreeSet<WaitForNode>>) -> Vec<WaitForEdge> {
    let mut edges = Vec::new();
    for (from, tos) in edge_map {
        for to in tos {
            edges.push(WaitForEdge {
                from: from.clone(),
                to: to.clone(),
            });
        }
    }
    edges
}

#[derive(Debug, Clone, Default)]
struct FunctionEndpoints {
    name_span: Option<Span>,
    recv_channels: BTreeMap<String, Span>,
    send_channels: BTreeMap<String, Span>,
    dynamic_recv_spans: Vec<Span>,
    dynamic_send_spans: Vec<Span>,
}

#[derive(Default)]
struct Walker {
    function_map: BTreeMap<String, FunctionEndpoints>,
    current_function: Option<String>,
    current_function_span: Option<Span>,
}

impl Walker {
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

        let entry = self.function_map.entry(function.name.clone()).or_default();
        if entry.name_span.is_none() {
            entry.name_span = Some(function.name_span);
        }

        self.walk_block(&function.body);

        self.current_function = None;
        self.current_function_span = None;
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
        let normalized = normalize_call_name(func);
        if normalized == "bus.recv" {
            if let Some(channel) = literal_channel_key(args.first()) {
                self.current_endpoints_mut()
                    .recv_channels
                    .entry(channel)
                    .or_insert(span);
            } else {
                self.current_endpoints_mut().dynamic_recv_spans.push(span);
            }
        }

        if normalized == "bus.send" {
            if let Some(channel) = literal_channel_key(args.first()) {
                self.current_endpoints_mut()
                    .send_channels
                    .entry(channel)
                    .or_insert(span);
            } else {
                self.current_endpoints_mut().dynamic_send_spans.push(span);
            }
        }
    }

    fn current_endpoints_mut(&mut self) -> &mut FunctionEndpoints {
        let function = self
            .current_function
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());

        let entry = self.function_map.entry(function).or_default();
        if entry.name_span.is_none() {
            entry.name_span = self.current_function_span;
        }
        entry
    }
}

fn literal_channel_key(expr: Option<&types::Expr>) -> Option<String> {
    match expr {
        Some(types::Expr::Literal(types::Literal::String(value))) => {
            Some(format!("str:{}", value.trim()))
        }
        Some(types::Expr::Literal(types::Literal::Int(value))) => Some(format!("int:{}", value)),
        _ => None,
    }
}

fn normalize_call_name(func: &str) -> String {
    func.trim().to_ascii_lowercase()
}

fn add_node_bounded(
    nodes: &mut BTreeSet<WaitForNode>,
    node: WaitForNode,
    truncated: &mut bool,
) -> bool {
    if nodes.contains(&node) {
        return true;
    }

    if nodes.len() >= MAX_GRAPH_NODES {
        *truncated = true;
        return false;
    }

    nodes.insert(node);
    true
}

fn add_edge_bounded(
    nodes: &mut BTreeSet<WaitForNode>,
    edges: &mut BTreeMap<WaitForNode, BTreeSet<WaitForNode>>,
    edge_count: &mut usize,
    from: WaitForNode,
    to: WaitForNode,
    truncated: &mut bool,
) {
    if !add_node_bounded(nodes, from.clone(), truncated) {
        return;
    }
    if !add_node_bounded(nodes, to.clone(), truncated) {
        return;
    }

    let entry = edges.entry(from).or_default();
    if entry.contains(&to) {
        return;
    }

    if *edge_count >= MAX_GRAPH_EDGES {
        *truncated = true;
        return;
    }

    entry.insert(to);
    *edge_count = edge_count.saturating_add(1);
}

fn collect_warnings(
    function_map: &BTreeMap<String, FunctionEndpoints>,
    edges: &BTreeMap<WaitForNode, BTreeSet<WaitForNode>>,
    graph_truncated: bool,
) -> Vec<DeadlockRiskWarning> {
    let mut warnings = Vec::new();

    let mut known_senders: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut any_dynamic_sender = false;

    for (function, endpoints) in function_map {
        if !endpoints.dynamic_send_spans.is_empty() {
            any_dynamic_sender = true;
        }

        for channel in endpoints.send_channels.keys() {
            known_senders
                .entry(channel.clone())
                .or_default()
                .insert(function.clone());
        }
    }

    for (function, endpoints) in function_map {
        for span in &endpoints.dynamic_recv_spans {
            warnings.push(DeadlockRiskWarning {
                kind: DeadlockRiskKind::DynamicRecvPattern,
                function: function.clone(),
                span: *span,
            });
        }

        for span in &endpoints.dynamic_send_spans {
            warnings.push(DeadlockRiskWarning {
                kind: DeadlockRiskKind::DynamicSendPattern,
                function: function.clone(),
                span: *span,
            });
        }

        for (channel, recv_span) in &endpoints.recv_channels {
            if !any_dynamic_sender && !known_senders.contains_key(channel) {
                warnings.push(DeadlockRiskWarning {
                    kind: DeadlockRiskKind::RecvWithoutKnownSender,
                    function: function.clone(),
                    span: *recv_span,
                });
            }

            let recv_node = WaitForNode::Channel(channel.clone());
            let function_node = WaitForNode::Function(function.clone());
            if path_exists(&recv_node, &function_node, edges, MAX_GRAPH_TRAVERSAL_STEPS) {
                warnings.push(DeadlockRiskWarning {
                    kind: DeadlockRiskKind::WaitCycle,
                    function: function.clone(),
                    span: *recv_span,
                });
            }
        }
    }

    if graph_truncated {
        let (function, span) = function_map
            .iter()
            .map(|(function, endpoints)| {
                (
                    function.clone(),
                    endpoints.name_span.unwrap_or(Span { line: 1, col: 1 }),
                )
            })
            .min_by(|a, b| (a.1.line, a.1.col, &a.0).cmp(&(b.1.line, b.1.col, &b.0)))
            .unwrap_or(("<program>".to_string(), Span { line: 1, col: 1 }));

        warnings.push(DeadlockRiskWarning {
            kind: DeadlockRiskKind::GraphTruncated,
            function,
            span,
        });
    }

    warnings
}

fn path_exists(
    start: &WaitForNode,
    target: &WaitForNode,
    edges: &BTreeMap<WaitForNode, BTreeSet<WaitForNode>>,
    max_steps: usize,
) -> bool {
    let mut visited: BTreeSet<WaitForNode> = BTreeSet::new();
    let mut stack = vec![start.clone()];
    let mut steps = 0usize;

    while let Some(node) = stack.pop() {
        if !visited.insert(node.clone()) {
            continue;
        }

        if &node == target {
            return true;
        }

        steps = steps.saturating_add(1);
        if steps >= max_steps {
            return true;
        }

        if let Some(next_nodes) = edges.get(&node) {
            for next in next_nodes.iter().rev() {
                stack.push(next.clone());
            }
        }
    }

    false
}

fn warning_order_key(warning: &DeadlockRiskWarning) -> (usize, usize, String, String) {
    (
        warning.span.line,
        warning.span.col,
        warning.function.clone(),
        warning.kind.code().to_string(),
    )
}

fn sort_and_dedup_warnings(warnings: &mut Vec<DeadlockRiskWarning>) {
    warnings.sort_by(|a, b| warning_order_key(a).cmp(&warning_order_key(b)));
    warnings.dedup_by(|a, b| warning_order_key(a) == warning_order_key(b));
}

fn write_u8(dst: &mut Vec<u8>, value: u8) {
    dst.push(value);
}

fn write_u32(dst: &mut Vec<u8>, value: u32) {
    dst.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(dst: &mut Vec<u8>, value: u64) {
    dst.extend_from_slice(&value.to_le_bytes());
}

fn write_len(dst: &mut Vec<u8>, len: usize) {
    let len_u64 = u64::try_from(len).expect("length must fit into u64");
    write_u64(dst, len_u64);
}

fn write_string(dst: &mut Vec<u8>, value: &str) {
    write_len(dst, value.len());
    dst.extend_from_slice(value.as_bytes());
}

fn write_bool(dst: &mut Vec<u8>, value: bool) {
    write_u8(dst, if value { 1 } else { 0 });
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_fixed<const N: usize>(
        &mut self,
        context: &'static str,
    ) -> Result<[u8; N], DecodeError> {
        let slice = self.take(N, context)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn read_u8(&mut self, context: &'static str) -> Result<u8, DecodeError> {
        let bytes = self.take(1, context)?;
        Ok(bytes[0])
    }

    fn read_u32(&mut self, context: &'static str) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_fixed::<4>(context)?))
    }

    fn read_u64(&mut self, context: &'static str) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_fixed::<8>(context)?))
    }

    fn read_len(&mut self, context: &'static str, limit: usize) -> Result<usize, DecodeError> {
        let raw = self.read_u64(context)?;
        let len = usize::try_from(raw).map_err(|_| DecodeError::LengthLimitExceeded {
            context,
            len: usize::MAX,
        })?;
        if len > limit {
            return Err(DecodeError::LengthLimitExceeded { context, len });
        }
        Ok(len)
    }

    fn read_string(
        &mut self,
        context: &'static str,
        max_len: usize,
    ) -> Result<String, DecodeError> {
        let len = self.read_len(context, max_len)?;
        let bytes = self.take(len, context)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::Utf8 { context })
    }

    fn read_bool(&mut self, context: &'static str) -> Result<bool, DecodeError> {
        match self.read_u8(context)? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(DecodeError::InvalidTag { context, tag }),
        }
    }

    fn take(&mut self, n: usize, context: &'static str) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or(DecodeError::Truncated { context })?;
        if end > self.bytes.len() {
            return Err(DecodeError::Truncated { context });
        }

        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        analyze, decode, encode, enforce_policy, DeadlockRiskKind, DeadlockRiskPolicy,
        DEADLOCK_RISK_MAGIC,
    };
    use crate::hir::lower::lower_to_hir;

    #[test]
    fn static_cycle_risk_warning_is_deterministic() {
        let source = concat!(
            "fn alpha() {\n",
            "    bus.recv(\"a\");\n",
            "    bus.send(\"b\", \"Schema\", \"x\");\n",
            "    return;\n",
            "}\n",
            "\n",
            "fn beta() {\n",
            "    bus.recv(\"b\");\n",
            "    bus.send(\"a\", \"Schema\", \"x\");\n",
            "    return;\n",
            "}\n",
        );

        let report = analyze(&parse_and_lower(source));
        assert!(report.warnings.len() >= 2, "expected at least 2 warnings");

        let first = &report.warnings[0];
        assert_eq!(first.kind, DeadlockRiskKind::WaitCycle);
        assert_eq!(first.function, "alpha");
        assert_eq!(first.span.line, 2);
        assert_eq!(first.span.col, 5);
        assert_eq!(
            first.to_string(),
            "deadlock-risk warning [wait_cycle] at line 2, col 5 in fn alpha: wait-for cycle risk detected in static channel approximation"
        );
    }

    #[test]
    fn recv_without_sender_risk_is_deterministic() {
        let source = "fn main() {\n    bus.recv(\"alerts\");\n    return;\n}\n";

        let report = analyze(&parse_and_lower(source));
        assert_eq!(report.warnings.len(), 1);
        let warning = &report.warnings[0];

        assert_eq!(warning.kind, DeadlockRiskKind::RecvWithoutKnownSender);
        assert_eq!(warning.function, "main");
        assert_eq!(warning.span.line, 2);
        assert_eq!(warning.span.col, 5);
    }

    #[test]
    fn policy_deny_mode_rejects_first_warning_deterministically() {
        let source = "fn main() {\n    bus.recv(\"alerts\");\n    return;\n}\n";
        let report = analyze(&parse_and_lower(source));

        let err = enforce_policy(&report, DeadlockRiskPolicy { deny_risk: true })
            .expect_err("deny mode should reject deadlock risk warnings");

        assert_eq!(err.warning.kind, DeadlockRiskKind::RecvWithoutKnownSender);
        assert_eq!(err.warning.function, "main");
        assert_eq!(
            err.to_string(),
            "deadlock-risk policy violation [recv_without_known_sender] at line 2, col 5 in fn main: recv observed with no statically known sender on the same channel"
        );
    }

    #[test]
    fn encode_decode_roundtrip_is_stable() {
        let source = "fn main() {\n    bus.recv(\"alerts\");\n    return;\n}\n";
        let report = analyze(&parse_and_lower(source));
        let encoded = encode(&report);
        let decoded = decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded, report);
        assert_eq!(encode(&decoded), encoded);
    }

    #[test]
    fn decode_rejects_unsupported_version_deterministically() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&DEADLOCK_RISK_MAGIC);
        bytes.extend_from_slice(&999u32.to_le_bytes());

        let err = decode(&bytes).expect_err("unsupported version should fail deterministically");
        assert_eq!(err.to_string(), "unsupported deadlock-risk version: 999");
    }

    #[test]
    fn malformed_decode_is_fail_closed_and_never_panics() {
        let mut seed = 0x4d595df4d0f33173u64;

        for len in 0usize..512 {
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (seed >> 32) as u8;
            }

            let result = std::panic::catch_unwind(|| decode(&bytes));
            assert!(result.is_ok(), "decode panicked for len {}", len);

            let decoded = result.expect("catch_unwind checked");
            if bytes.len() < DEADLOCK_RISK_MAGIC.len()
                || bytes[..DEADLOCK_RISK_MAGIC.len()] != DEADLOCK_RISK_MAGIC
            {
                assert!(decoded.is_err(), "non-magic input must fail closed");
            }
        }
    }

    fn parse_and_lower(source: &str) -> crate::hir::types::Program {
        let ast = crate::parser::parse(source).expect("source should parse");
        lower_to_hir(&ast)
    }
}
