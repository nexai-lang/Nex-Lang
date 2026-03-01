use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::ast::Span;
use crate::hir;

use super::types;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagnosticCode {
    MissingMain,
    MissingEffectIo,
    MissingEffectNet,
    MissingEffectAsync,
    InvalidJumpTarget,
    InvalidBranchTarget,
    NonBooleanBranchCondition,
    ReturnTypeMismatch,
    CallArgCountMismatch,
    CallArgTypeMismatch,
    AssignTypeMismatch,
}

impl DiagnosticCode {
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticCode::MissingMain => "MIR-E0001",
            DiagnosticCode::MissingEffectIo => "MIR-E1001",
            DiagnosticCode::MissingEffectNet => "MIR-E1002",
            DiagnosticCode::MissingEffectAsync => "MIR-E1003",
            DiagnosticCode::InvalidJumpTarget => "MIR-E2001",
            DiagnosticCode::InvalidBranchTarget => "MIR-E2002",
            DiagnosticCode::NonBooleanBranchCondition => "MIR-E2003",
            DiagnosticCode::ReturnTypeMismatch => "MIR-E2004",
            DiagnosticCode::CallArgCountMismatch => "MIR-E2005",
            DiagnosticCode::CallArgTypeMismatch => "MIR-E2006",
            DiagnosticCode::AssignTypeMismatch => "MIR-E2007",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckError {
    pub code: DiagnosticCode,
    pub function: String,
    pub span: Span,
    pub detail: String,
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mir-check violation [{}] at line {}, col {} in fn {}: {}",
            self.code.as_str(),
            self.span.line,
            self.span.col,
            self.function,
            self.detail
        )
    }
}

impl std::error::Error for CheckError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DeclaredEffects {
    io: bool,
    net: bool,
    async_effect: bool,
}

impl DeclaredEffects {
    fn union(self, other: Self) -> Self {
        Self {
            io: self.io || other.io,
            net: self.net || other.net,
            async_effect: self.async_effect || other.async_effect,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SimpleType {
    Void,
    I32,
    F32,
    Bool,
    String,
    Task,
    Unknown,
}

impl SimpleType {
    fn name(self) -> &'static str {
        match self {
            SimpleType::Void => "void",
            SimpleType::I32 => "int",
            SimpleType::F32 => "float",
            SimpleType::Bool => "bool",
            SimpleType::String => "string",
            SimpleType::Task => "task",
            SimpleType::Unknown => "unknown",
        }
    }

    fn known(self) -> bool {
        self != SimpleType::Unknown
    }
}

#[derive(Debug, Clone)]
struct FunctionSignature {
    name: String,
    span: Span,
    params: Vec<(String, SimpleType)>,
    return_type: SimpleType,
    declared_effects: DeclaredEffects,
}

#[derive(Debug, Clone)]
struct CallSignature {
    params: Vec<SimpleType>,
    return_type: SimpleType,
    effects: DeclaredEffects,
}

pub fn check(
    hir_program: &hir::types::Program,
    mir_program: &types::Program,
) -> Result<(), CheckError> {
    let signatures = collect_signatures(hir_program);

    ensure_main_exists(mir_program)?;
    check_effects(&signatures, mir_program)?;
    check_types(&signatures, mir_program)?;

    Ok(())
}

fn collect_signatures(program: &hir::types::Program) -> BTreeMap<String, FunctionSignature> {
    let mut signatures = BTreeMap::new();

    for item in &program.items {
        if let hir::types::Item::Function(function) = item {
            let mut params = Vec::with_capacity(function.params.len());
            for param in &function.params {
                params.push((param.name.clone(), hir_type_to_simple(&param.ty)));
            }

            signatures.insert(
                function.name.clone(),
                FunctionSignature {
                    name: function.name.clone(),
                    span: function.name_span,
                    params,
                    return_type: hir_return_type_to_simple(function.return_type.as_ref()),
                    declared_effects: effects_from_hir(&function.effects),
                },
            );
        }
    }

    signatures
}

fn ensure_main_exists(mir_program: &types::Program) -> Result<(), CheckError> {
    if mir_program.functions.iter().any(|f| f.name == "main") {
        return Ok(());
    }

    Err(CheckError {
        code: DiagnosticCode::MissingMain,
        function: "<program>".to_string(),
        span: Span { line: 1, col: 1 },
        detail: "program has no `fn main()` entrypoint".to_string(),
    })
}

fn check_effects(
    signatures: &BTreeMap<String, FunctionSignature>,
    mir_program: &types::Program,
) -> Result<(), CheckError> {
    let mut function_names = BTreeSet::new();
    for function in &mir_program.functions {
        function_names.insert(function.name.clone());
    }

    let mut direct_effects: BTreeMap<String, DeclaredEffects> = BTreeMap::new();
    let mut call_edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for function in &mir_program.functions {
        let mut local_effects = DeclaredEffects::default();
        let mut callees = BTreeSet::new();

        for block in &function.blocks {
            for stmt in &block.stmts {
                let Some(func) = stmt_func_name(stmt) else {
                    continue;
                };

                if function_names.contains(func) {
                    callees.insert(func.to_string());
                }

                if let Some(sig) = builtin_signature(func) {
                    local_effects = local_effects.union(sig.effects);
                }
            }
        }

        direct_effects.insert(function.name.clone(), local_effects);
        call_edges.insert(function.name.clone(), callees);
    }

    let mut inferred = direct_effects.clone();
    loop {
        let mut changed = false;

        for function_name in direct_effects.keys() {
            let mut combined = *inferred
                .get(function_name)
                .unwrap_or(&DeclaredEffects::default());

            let Some(callees) = call_edges.get(function_name) else {
                continue;
            };

            for callee in callees {
                let callee_effects = *inferred.get(callee).unwrap_or(&DeclaredEffects::default());
                combined = combined.union(callee_effects);
            }

            if inferred.get(function_name).copied().unwrap_or_default() != combined {
                inferred.insert(function_name.clone(), combined);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    for function_name in direct_effects.keys() {
        let required = inferred
            .get(function_name)
            .copied()
            .unwrap_or(DeclaredEffects::default());

        let signature = signatures.get(function_name);
        let declared = signature
            .map(|s| s.declared_effects)
            .unwrap_or(DeclaredEffects::default());

        let missing_io = required.io && !declared.io;
        let missing_net = required.net && !declared.net;
        let missing_async = required.async_effect && !declared.async_effect;

        if missing_io {
            let (function, span) = function_context(signature, function_name);
            return Err(CheckError {
                code: DiagnosticCode::MissingEffectIo,
                function,
                span,
                detail: "missing required effect declaration `!io` (required by body or callees)"
                    .to_string(),
            });
        }

        if missing_net {
            let (function, span) = function_context(signature, function_name);
            return Err(CheckError {
                code: DiagnosticCode::MissingEffectNet,
                function,
                span,
                detail: "missing required effect declaration `!net` (required by body or callees)"
                    .to_string(),
            });
        }

        if missing_async {
            let (function, span) = function_context(signature, function_name);
            return Err(CheckError {
                code: DiagnosticCode::MissingEffectAsync,
                function,
                span,
                detail:
                    "missing required effect declaration `!async` (required by body or callees)"
                        .to_string(),
            });
        }
    }

    Ok(())
}

fn check_types(
    signatures: &BTreeMap<String, FunctionSignature>,
    mir_program: &types::Program,
) -> Result<(), CheckError> {
    let mut functions = mir_program.functions.iter().collect::<Vec<_>>();
    functions.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));

    for function in functions {
        let signature = signatures.get(&function.name);
        let expected_return = signature
            .map(|sig| sig.return_type)
            .unwrap_or(SimpleType::Void);

        let span = signature
            .map(|sig| sig.span)
            .unwrap_or(Span { line: 1, col: 1 });

        let mut env: BTreeMap<String, SimpleType> = BTreeMap::new();
        if let Some(sig) = signature {
            for (name, ty) in &sig.params {
                env.insert(name.clone(), *ty);
            }
        }

        let mut block_ids = BTreeSet::new();
        for block in &function.blocks {
            block_ids.insert(block.id);
        }

        let mut blocks = function.blocks.iter().collect::<Vec<_>>();
        blocks.sort_by_key(|b| b.id);

        for block in blocks {
            for stmt in &block.stmts {
                match stmt {
                    types::Stmt::Let { name, value } => {
                        let value_ty = infer_expr_type(value, &env);
                        env.insert(name.clone(), value_ty);
                    }
                    types::Stmt::Assign { name, value } => {
                        let value_ty = infer_expr_type(value, &env);
                        if let Some(existing_ty) = env.get(name).copied() {
                            if existing_ty.known() && value_ty.known() && existing_ty != value_ty {
                                return Err(CheckError {
                                    code: DiagnosticCode::AssignTypeMismatch,
                                    function: function.name.clone(),
                                    span,
                                    detail: format!(
                                        "assignment to `{}` expects {}, got {}",
                                        name,
                                        existing_ty.name(),
                                        value_ty.name()
                                    ),
                                });
                            }
                        }
                        env.insert(name.clone(), value_ty);
                    }
                    types::Stmt::Call { dest, func, args }
                    | types::Stmt::Send { dest, func, args }
                    | types::Stmt::Recv { dest, func, args }
                    | types::Stmt::IoRead { dest, func, args }
                    | types::Stmt::IoWrite { dest, func, args } => {
                        let return_ty =
                            check_call_site(signatures, &function.name, span, func, args, &env)?;

                        if let Some(dest_name) = dest {
                            if let Some(existing_ty) = env.get(dest_name).copied() {
                                if existing_ty.known()
                                    && return_ty.known()
                                    && existing_ty != return_ty
                                {
                                    return Err(CheckError {
                                        code: DiagnosticCode::AssignTypeMismatch,
                                        function: function.name.clone(),
                                        span,
                                        detail: format!(
                                            "assignment to `{}` expects {}, got {}",
                                            dest_name,
                                            existing_ty.name(),
                                            return_ty.name()
                                        ),
                                    });
                                }
                            }
                            env.insert(dest_name.clone(), return_ty);
                        }
                    }
                }
            }

            match &block.terminator {
                types::Term::Return(value) => {
                    let actual = value
                        .as_ref()
                        .map(|expr| infer_expr_type(expr, &env))
                        .unwrap_or(SimpleType::Void);

                    if !types_compatible(expected_return, actual) {
                        return Err(CheckError {
                            code: DiagnosticCode::ReturnTypeMismatch,
                            function: function.name.clone(),
                            span,
                            detail: format!(
                                "return type mismatch: expected {}, got {}",
                                expected_return.name(),
                                actual.name()
                            ),
                        });
                    }
                }
                types::Term::Jump(target) => {
                    if !block_ids.contains(target) {
                        return Err(CheckError {
                            code: DiagnosticCode::InvalidJumpTarget,
                            function: function.name.clone(),
                            span,
                            detail: format!("jump target block {} does not exist", target),
                        });
                    }
                }
                types::Term::Branch {
                    cond,
                    then_block,
                    else_block,
                } => {
                    if !block_ids.contains(then_block) {
                        return Err(CheckError {
                            code: DiagnosticCode::InvalidBranchTarget,
                            function: function.name.clone(),
                            span,
                            detail: format!(
                                "branch then-target block {} does not exist",
                                then_block
                            ),
                        });
                    }
                    if !block_ids.contains(else_block) {
                        return Err(CheckError {
                            code: DiagnosticCode::InvalidBranchTarget,
                            function: function.name.clone(),
                            span,
                            detail: format!(
                                "branch else-target block {} does not exist",
                                else_block
                            ),
                        });
                    }

                    let cond_ty = infer_expr_type(cond, &env);
                    if cond_ty.known() && cond_ty != SimpleType::Bool {
                        return Err(CheckError {
                            code: DiagnosticCode::NonBooleanBranchCondition,
                            function: function.name.clone(),
                            span,
                            detail: format!(
                                "branch condition must be bool, got {}",
                                cond_ty.name()
                            ),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

fn check_call_site(
    signatures: &BTreeMap<String, FunctionSignature>,
    function: &str,
    span: Span,
    callee: &str,
    args: &[types::Expr],
    env: &BTreeMap<String, SimpleType>,
) -> Result<SimpleType, CheckError> {
    let signature = call_signature(signatures, callee);

    let Some(signature) = signature else {
        return Ok(SimpleType::Unknown);
    };

    if args.len() != signature.params.len() {
        return Err(CheckError {
            code: DiagnosticCode::CallArgCountMismatch,
            function: function.to_string(),
            span,
            detail: format!(
                "call to `{}` expects {} arg(s), got {}",
                callee,
                signature.params.len(),
                args.len()
            ),
        });
    }

    for (index, (arg, expected_ty)) in args.iter().zip(signature.params.iter()).enumerate() {
        let actual_ty = infer_expr_type(arg, env);
        if expected_ty.known() && actual_ty.known() && *expected_ty != actual_ty {
            return Err(CheckError {
                code: DiagnosticCode::CallArgTypeMismatch,
                function: function.to_string(),
                span,
                detail: format!(
                    "call to `{}` arg {} expects {}, got {}",
                    callee,
                    index,
                    expected_ty.name(),
                    actual_ty.name()
                ),
            });
        }
    }

    Ok(signature.return_type)
}

fn call_signature(
    signatures: &BTreeMap<String, FunctionSignature>,
    name: &str,
) -> Option<CallSignature> {
    if let Some(builtin) = builtin_signature(name) {
        return Some(builtin);
    }

    signatures.get(name).map(|sig| CallSignature {
        params: sig.params.iter().map(|(_, ty)| *ty).collect(),
        return_type: sig.return_type,
        effects: sig.declared_effects,
    })
}

fn function_context(signature: Option<&FunctionSignature>, fallback_name: &str) -> (String, Span) {
    match signature {
        Some(sig) => (sig.name.clone(), sig.span),
        None => (fallback_name.to_string(), Span { line: 1, col: 1 }),
    }
}

fn stmt_func_name(stmt: &types::Stmt) -> Option<&str> {
    match stmt {
        types::Stmt::Call { func, .. }
        | types::Stmt::Send { func, .. }
        | types::Stmt::Recv { func, .. }
        | types::Stmt::IoRead { func, .. }
        | types::Stmt::IoWrite { func, .. } => Some(func.as_str()),
        types::Stmt::Let { .. } | types::Stmt::Assign { .. } => None,
    }
}

fn infer_expr_type(expr: &types::Expr, env: &BTreeMap<String, SimpleType>) -> SimpleType {
    match expr {
        types::Expr::Literal(literal) => match literal {
            types::Literal::Int(_) => SimpleType::I32,
            types::Literal::FloatBits(_) => SimpleType::F32,
            types::Literal::Bool(_) => SimpleType::Bool,
            types::Literal::String(_) => SimpleType::String,
            types::Literal::Unit => SimpleType::Void,
        },
        types::Expr::Variable(name) => env.get(name).copied().unwrap_or(SimpleType::Unknown),
        types::Expr::BinaryOp { left, op, right } => {
            let lhs = infer_expr_type(left, env);
            let rhs = infer_expr_type(right, env);

            match op {
                types::BinOp::Add | types::BinOp::Sub | types::BinOp::Mul | types::BinOp::Div => {
                    if lhs == rhs && (lhs == SimpleType::I32 || lhs == SimpleType::F32) {
                        lhs
                    } else {
                        SimpleType::Unknown
                    }
                }
                types::BinOp::Eq
                | types::BinOp::Ne
                | types::BinOp::Lt
                | types::BinOp::Le
                | types::BinOp::Gt
                | types::BinOp::Ge => SimpleType::Bool,
            }
        }
    }
}

fn types_compatible(expected: SimpleType, actual: SimpleType) -> bool {
    if expected == SimpleType::Unknown || actual == SimpleType::Unknown {
        return true;
    }

    expected == actual
}

fn effects_from_hir(effects: &[hir::types::Effect]) -> DeclaredEffects {
    let mut declared = DeclaredEffects::default();

    for effect in effects {
        match effect {
            hir::types::Effect::Io => declared.io = true,
            hir::types::Effect::Net => declared.net = true,
            hir::types::Effect::Async => declared.async_effect = true,
            hir::types::Effect::Pure | hir::types::Effect::Mut => {}
        }
    }

    declared
}

fn hir_type_to_simple(ty: &hir::types::Type) -> SimpleType {
    match ty {
        hir::types::Type::I32 => SimpleType::I32,
        hir::types::Type::F32 => SimpleType::F32,
        hir::types::Type::Bool => SimpleType::Bool,
        hir::types::Type::String => SimpleType::String,
        hir::types::Type::Task => SimpleType::Task,
        hir::types::Type::Named(_) => SimpleType::Unknown,
    }
}

fn hir_return_type_to_simple(ty: Option<&hir::types::Type>) -> SimpleType {
    match ty {
        Some(value) => hir_type_to_simple(value),
        None => SimpleType::Void,
    }
}

fn builtin_signature(name: &str) -> Option<CallSignature> {
    match name {
        "fs.read" => Some(CallSignature {
            params: vec![SimpleType::String],
            return_type: SimpleType::String,
            effects: DeclaredEffects {
                io: true,
                net: false,
                async_effect: false,
            },
        }),
        "net.listen" => Some(CallSignature {
            params: vec![SimpleType::I32],
            return_type: SimpleType::Void,
            effects: DeclaredEffects {
                io: false,
                net: true,
                async_effect: false,
            },
        }),
        "spawn" => Some(CallSignature {
            params: vec![],
            return_type: SimpleType::Task,
            effects: DeclaredEffects {
                io: false,
                net: false,
                async_effect: true,
            },
        }),
        "join" => Some(CallSignature {
            params: vec![SimpleType::Unknown],
            return_type: SimpleType::Void,
            effects: DeclaredEffects::default(),
        }),
        "cancel" => Some(CallSignature {
            params: vec![SimpleType::Unknown],
            return_type: SimpleType::Void,
            effects: DeclaredEffects::default(),
        }),
        "cancelled" => Some(CallSignature {
            params: vec![],
            return_type: SimpleType::Bool,
            effects: DeclaredEffects::default(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{check, DiagnosticCode};

    struct DiagGoldenCase {
        name: &'static str,
        source: &'static str,
        golden_relpath: &'static str,
    }

    const GOLDEN_CASES: &[DiagGoldenCase] = &[
        DiagGoldenCase {
            name: "missing_effect_io",
            source: "fn helper() { fs.read(\"x\"); return; }\nfn main() { helper(); return; }\n",
            golden_relpath: "src/mir/golden/mir_checker_missing_effect_io.diag.txt",
        },
        DiagGoldenCase {
            name: "non_boolean_branch",
            source: "fn main() { if 1 { return; } else { return; } }\n",
            golden_relpath: "src/mir/golden/mir_checker_non_boolean_branch.diag.txt",
        },
        DiagGoldenCase {
            name: "return_type_mismatch",
            source: "fn main(): int { return; }\n",
            golden_relpath: "src/mir/golden/mir_checker_return_type_mismatch.diag.txt",
        },
    ];

    #[test]
    fn golden_mir_checker_diagnostics_match_exactly() {
        let update = std::env::var("NEX_UPDATE_MIR_CHECK_GOLDEN")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false);

        for case in GOLDEN_CASES {
            let diagnostic = render_diagnostic(case.source);
            let path = project_root().join(case.golden_relpath);

            if update {
                fs::write(&path, format!("{}\n", diagnostic)).expect("write diag golden");
            }

            let expected = fs::read_to_string(&path).expect("read diag golden");
            assert_eq!(
                format!("{}\n", diagnostic),
                expected,
                "golden mismatch for {}",
                case.name
            );
        }
    }

    #[test]
    fn diagnostic_codes_are_stable() {
        let all_codes = [
            DiagnosticCode::MissingMain,
            DiagnosticCode::MissingEffectIo,
            DiagnosticCode::MissingEffectNet,
            DiagnosticCode::MissingEffectAsync,
            DiagnosticCode::InvalidJumpTarget,
            DiagnosticCode::InvalidBranchTarget,
            DiagnosticCode::NonBooleanBranchCondition,
            DiagnosticCode::ReturnTypeMismatch,
            DiagnosticCode::CallArgCountMismatch,
            DiagnosticCode::CallArgTypeMismatch,
            DiagnosticCode::AssignTypeMismatch,
        ];

        let rendered = all_codes
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                "MIR-E0001",
                "MIR-E1001",
                "MIR-E1002",
                "MIR-E1003",
                "MIR-E2001",
                "MIR-E2002",
                "MIR-E2003",
                "MIR-E2004",
                "MIR-E2005",
                "MIR-E2006",
                "MIR-E2007",
            ]
        );
    }

    fn render_diagnostic(source: &str) -> String {
        let ast = crate::parser::parse(source).expect("source should parse");
        let hir = crate::hir::lower::lower_to_hir(&ast);
        let mir = crate::mir::lower::lower_to_mir(&hir);

        let err = check(&hir, &mir).expect_err("checker should reject fixture");
        err.to_string()
    }

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }
}
