// src/checker.rs
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use crate::ast::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CheckError {
    pub message: String,
    pub hint: Option<String>,
    pub cause: Option<String>,
    pub span: Option<Span>,
    pub note_span: Option<Span>,
    pub note: Option<String>,
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.message)?;
        if let Some(sp) = self.span {
            writeln!(f, "Location: line {}, col {}", sp.line, sp.col)?;
        }
        if let Some(c) = &self.cause {
            writeln!(f, "Cause: {}", c)?;
        }
        if let Some(h) = &self.hint {
            writeln!(f, "Hint: {}", h)?;
        }
        if let Some(sp) = self.note_span {
            writeln!(f, "Note location: line {}, col {}", sp.line, sp.col)?;
        }
        if let Some(n) = &self.note {
            writeln!(f, "Note: {}", n)?;
        }
        Ok(())
    }
}

impl std::error::Error for CheckError {}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub capabilities: Vec<Capability>,
    pub neural_models: Vec<String>,
    pub functions: Vec<String>,
}

// -------------------- Effects --------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DeclaredEffects {
    io: bool,
    net: bool,
    r#async: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct EffectReported {
    io: bool,
    net: bool,
    r#async: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct MissingEffects {
    io: bool,
    net: bool,
    r#async: bool,
}

impl MissingEffects {
    fn any(&self) -> bool {
        self.io || self.net || self.r#async
    }

    fn to_hint_list(&self) -> String {
        let mut out: Vec<&'static str> = Vec::new();
        if self.io {
            out.push("`!io`");
        }
        if self.net {
            out.push("`!net`");
        }
        if self.r#async {
            out.push("`!async`");
        }
        out.join(", ")
    }
}

fn effects_from_vec(v: &[Effect]) -> DeclaredEffects {
    let mut d = DeclaredEffects::default();
    for e in v {
        match e {
            Effect::Io => d.io = true,
            Effect::Net => d.net = true,
            Effect::Async => d.r#async = true,
            _ => {}
        }
    }
    d
}

fn union_effects(a: DeclaredEffects, b: DeclaredEffects) -> DeclaredEffects {
    DeclaredEffects {
        io: a.io || b.io,
        net: a.net || b.net,
        r#async: a.r#async || b.r#async,
    }
}

fn missing_effects(required: DeclaredEffects, declared: DeclaredEffects) -> MissingEffects {
    MissingEffects {
        io: required.io && !declared.io,
        net: required.net && !declared.net,
        r#async: required.r#async && !declared.r#async,
    }
}

// -------------------- Types (minimal) --------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleType {
    Void,
    I32,
    F32,
    Bool,
    String,
    Task,
    PoisonedTask,
    Unknown,
}

fn simple_type_name(t: SimpleType) -> &'static str {
    match t {
        SimpleType::Void => "void",
        SimpleType::I32 => "i32",
        SimpleType::F32 => "f32",
        SimpleType::Bool => "bool",
        SimpleType::String => "string",
        SimpleType::Task => "task",
        SimpleType::PoisonedTask => "task (poisoned)",
        SimpleType::Unknown => "unknown",
    }
}

type TypeEnv = HashMap<String, SimpleType>;

fn type_to_simple(t: &Type) -> Option<SimpleType> {
    Some(match t {
        Type::I32 => SimpleType::I32,
        Type::F32 => SimpleType::F32,
        Type::Bool => SimpleType::Bool,
        Type::String => SimpleType::String,
        Type::Task => SimpleType::Task,
        Type::Named(_) => SimpleType::Unknown,
    })
}

fn return_type_to_simple(rt: &Option<Type>) -> SimpleType {
    match rt {
        None => SimpleType::Void,
        Some(t) => type_to_simple(t).unwrap_or(SimpleType::Unknown),
    }
}

// -------------------- Builtins --------------------

#[derive(Debug, Clone)]
struct FnSig {
    name_span: Span,
    params: Vec<SimpleType>,
    ret: SimpleType,
    effects: DeclaredEffects,
}

fn builtin_sig(name: &str) -> Option<FnSig> {
    match name {
        "fs.read" => Some(FnSig {
            name_span: Span { line: 0, col: 0 },
            params: vec![SimpleType::String],
            ret: SimpleType::String,
            effects: DeclaredEffects {
                io: true,
                net: false,
                r#async: false,
            },
        }),
        "net.listen" => Some(FnSig {
            name_span: Span { line: 0, col: 0 },
            params: vec![SimpleType::I32],
            ret: SimpleType::Void,
            effects: DeclaredEffects {
                io: false,
                net: true,
                r#async: false,
            },
        }),
        "spawn" => Some(FnSig {
            name_span: Span { line: 0, col: 0 },
            params: vec![],
            ret: SimpleType::Task,
            effects: DeclaredEffects {
                io: false,
                net: false,
                r#async: true,
            },
        }),
        "join" => Some(FnSig {
            name_span: Span { line: 0, col: 0 },
            params: vec![SimpleType::Task],
            ret: SimpleType::Void,
            effects: DeclaredEffects {
                io: false,
                net: false,
                r#async: false,
            },
        }),
        "cancel" => Some(FnSig {
            name_span: Span { line: 0, col: 0 },
            params: vec![SimpleType::Task],
            ret: SimpleType::Void,
            effects: DeclaredEffects {
                io: false,
                net: false,
                r#async: false,
            },
        }),
        "cancelled" => Some(FnSig {
            name_span: Span { line: 0, col: 0 },
            params: vec![],
            ret: SimpleType::Bool,
            effects: DeclaredEffects {
                io: false,
                net: false,
                r#async: false,
            },
        }),
        _ => None,
    }
}

// -------------------- Capability helpers --------------------

fn capability_sort_key(c: &Capability) -> String {
    match c {
        Capability::FsRead { glob } => format!("fs.read:{}", glob),
        Capability::NetListen { range } => match range {
            NetPortSpec::Single(p) => format!("net.listen:{}-{}", p, p),
            NetPortSpec::Range(a, b) => format!("net.listen:{}-{}", a, b),
        },
    }
}

fn net_port_spec_to_string(r: &NetPortSpec) -> String {
    match r {
        NetPortSpec::Single(p) => format!("{}", p),
        NetPortSpec::Range(a, b) => format!("{}..{}", a, b),
    }
}

fn net_port_spec_allows(r: &NetPortSpec, port: i64) -> bool {
    match r {
        NetPortSpec::Single(p) => *p == port,
        NetPortSpec::Range(a, b) => port >= *a && port <= *b,
    }
}

// -------------------- Call graph (effects inference) --------------------

fn collect_calls_expr(e: &Expr, out: &mut Vec<(String, Span)>) {
    match e {
        Expr::Call { func, args, span } => {
            out.push((func.clone(), *span));
            for a in args {
                collect_calls_expr(a, out);
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            collect_calls_expr(left, out);
            collect_calls_expr(right, out);
        }
        Expr::If {
            cond,
            then_block,
            else_block,
        } => {
            collect_calls_expr(cond, out);
            collect_calls_block(then_block, out);
            if let Some(b) = else_block {
                collect_calls_block(b, out);
            }
        }
        Expr::Block(b) => collect_calls_block(b, out),
        Expr::Spawn { block, .. } => collect_calls_block(block, out),
        _ => {}
    }
}

fn collect_calls_stmt(s: &Stmt, out: &mut Vec<(String, Span)>) {
    match s {
        Stmt::Let { value, .. } => collect_calls_expr(value, out),
        Stmt::Return(Some(e)) => collect_calls_expr(e, out),
        Stmt::Return(None) => {}
        Stmt::Expr(e) => collect_calls_expr(e, out),
        Stmt::If {
            cond,
            then_block,
            else_block,
        } => {
            collect_calls_expr(cond, out);
            collect_calls_block(then_block, out);
            if let Some(b) = else_block {
                collect_calls_block(b, out);
            }
        }
        Stmt::Loop(b) => collect_calls_block(b, out),
        Stmt::Defer(b) => collect_calls_block(b, out),
    }
}

fn collect_calls_block(b: &Block, out: &mut Vec<(String, Span)>) {
    for s in &b.stmts {
        collect_calls_stmt(s, out);
    }
}

fn infer_transitive_effects(
    fn_bodies: &HashMap<String, Function>,
) -> HashMap<String, DeclaredEffects> {
    let mut inferred: HashMap<String, DeclaredEffects> = HashMap::new();
    let mut calls: HashMap<String, Vec<String>> = HashMap::new();

    for (name, f) in fn_bodies {
        let mut cs: Vec<(String, Span)> = Vec::new();
        collect_calls_block(&f.body, &mut cs);

        let mut direct = DeclaredEffects::default();
        let mut callee_names = Vec::new();

        for (c, _) in cs {
            callee_names.push(c.clone());
            if let Some(sig) = builtin_sig(&c) {
                direct = union_effects(direct, sig.effects);
            }
        }

        calls.insert(name.clone(), callee_names);
        inferred.insert(name.clone(), direct);
    }

    loop {
        let mut changed = false;
        let snapshot = inferred.clone();

        for (name, old) in snapshot {
            let mut new = old;

            if let Some(cs) = calls.get(&name) {
                for callee in cs {
                    if let Some(req) = inferred.get(callee).copied() {
                        new = union_effects(new, req);
                    }
                }
            }

            if new != old {
                inferred.insert(name, new);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    inferred
}

// -------------------- Public entry --------------------

pub fn check(program: &Program) -> Result<CheckResult, CheckError> {
    let mut caps: Vec<Capability> = Vec::new();
    let mut models: Vec<String> = Vec::new();
    let mut funcs: Vec<String> = Vec::new();
    let mut fn_bodies: HashMap<String, Function> = HashMap::new();

    for item in &program.items {
        match item {
            Item::Capability(c) => caps.push(c.cap.clone()),
            Item::Neural(n) => models.push(n.name.clone()),
            Item::Function(f) => {
                funcs.push(f.name.clone());
                fn_bodies.insert(f.name.clone(), f.clone());
            }
        }
    }

    caps.sort_by(|a, b| capability_sort_key(a).cmp(&capability_sort_key(b)));
    models.sort();
    funcs.sort();

    if !fn_bodies.contains_key("main") {
        return Err(CheckError {
            message: "❌ Program has no `fn main()` entrypoint.".to_string(),
            hint: Some("Add: fn main() { ... }".to_string()),
            cause: None,
            span: None,
            note_span: None,
            note: None,
        });
    }

    // Step: signature must cover transitive effects.
    let inferred_effects = infer_transitive_effects(&fn_bodies);

    for fn_name in &funcs {
        let f = fn_bodies.get(fn_name).unwrap();
        let declared = effects_from_vec(&f.effects);
        let required = inferred_effects.get(fn_name).copied().unwrap_or_default();
        let miss = missing_effects(required, declared);

        if miss.any() {
            let list = miss.to_hint_list();
            return Err(CheckError {
                message: format!(
                    "❌ Missing effect declaration(s) in fn `{}` (required by its body and callees).",
                    f.name
                ),
                hint: Some(format!("Add {} to the function signature.", list)),
                cause: Some("transitive effects".to_string()),
                span: None,
                note_span: Some(f.name_span),
                note: Some(format!("Add {} here.", list)),
            });
        }
    }

    Ok(CheckResult {
        capabilities: caps,
        neural_models: models,
        functions: funcs,
    })
}
