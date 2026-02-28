use crate::ast;

use super::types;

pub fn lower_to_hir(program: &ast::Program) -> types::Program {
    let mut items = Vec::with_capacity(program.items.len());
    let mut governance = types::GovernanceFacts::default();

    for item in &program.items {
        match item {
            ast::Item::Function(f) => {
                items.push(types::Item::Function(lower_function(f)));
            }
            ast::Item::Capability(c) => {
                let lowered = lower_capability_decl(c);
                governance.capabilities.push(types::CapabilityFact {
                    canonical: canonical_capability(&lowered.cap),
                });
                items.push(types::Item::Capability(lowered));
            }
            ast::Item::Neural(n) => {
                let lowered = lower_neural_decl(n);
                governance.neural_models.push(types::NeuralModelFact {
                    name: lowered.name.clone(),
                });
                items.push(types::Item::Neural(lowered));
            }
        }
    }

    governance
        .capabilities
        .sort_by(|a, b| a.canonical.cmp(&b.canonical));
    governance.neural_models.sort_by(|a, b| a.name.cmp(&b.name));

    types::Program { items, governance }
}

pub fn hir_node_count(program: &types::Program) -> usize {
    let mut count = 1usize;

    count += program.governance.capabilities.len();
    count += program.governance.neural_models.len();
    count += program.governance.policy_fragments.len();

    for item in &program.items {
        count += count_item(item);
    }

    count
}

fn count_item(item: &types::Item) -> usize {
    match item {
        types::Item::Capability(_) => 1,
        types::Item::Neural(n) => {
            let mut count = 1 + n.params.len() + count_type(&n.return_type);
            for p in &n.params {
                count += count_type(&p.ty);
            }
            count
        }
        types::Item::Function(f) => {
            let mut count = 1 + f.params.len() + f.effects.len() + count_block(&f.body);
            if let Some(t) = &f.return_type {
                count += count_type(t);
            }
            for p in &f.params {
                count += count_type(&p.ty);
            }
            count
        }
    }
}

fn count_block(block: &types::Block) -> usize {
    let mut count = 1usize;
    for stmt in &block.stmts {
        count += count_stmt(stmt);
    }
    count
}

fn count_stmt(stmt: &types::Stmt) -> usize {
    match stmt {
        types::Stmt::Let { ty, value, .. } => {
            let mut count = 1 + count_expr(value);
            if let Some(ty) = ty {
                count += count_type(ty);
            }
            count
        }
        types::Stmt::Return(Some(expr)) => 1 + count_expr(expr),
        types::Stmt::Return(None) => 1,
        types::Stmt::Expr(expr) => 1 + count_expr(expr),
        types::Stmt::If {
            cond,
            then_block,
            else_block,
        } => {
            let mut count = 1 + count_expr(cond) + count_block(then_block);
            if let Some(else_block) = else_block {
                count += count_block(else_block);
            }
            count
        }
        types::Stmt::Loop(block) | types::Stmt::Defer(block) => 1 + count_block(block),
    }
}

fn count_expr(expr: &types::Expr) -> usize {
    match expr {
        types::Expr::Literal(_) | types::Expr::Variable(_) => 1,
        types::Expr::Call { args, .. } => {
            let mut count = 1usize;
            for arg in args {
                count += count_expr(arg);
            }
            count
        }
        types::Expr::BinaryOp { left, right, .. } => 1 + count_expr(left) + count_expr(right),
        types::Expr::If {
            cond,
            then_block,
            else_block,
        } => {
            let mut count = 1 + count_expr(cond) + count_block(then_block);
            if let Some(else_block) = else_block {
                count += count_block(else_block);
            }
            count
        }
        types::Expr::Block(block) | types::Expr::Spawn { block, .. } => 1 + count_block(block),
    }
}

fn count_type(_ty: &types::Type) -> usize {
    1
}

fn lower_function(function: &ast::Function) -> types::Function {
    types::Function {
        name: function.name.clone(),
        name_span: function.name_span,
        params: function.params.iter().map(lower_param).collect(),
        return_type: function.return_type.as_ref().map(lower_type),
        effects: function.effects.iter().copied().map(lower_effect).collect(),
        body: lower_block(&function.body),
    }
}

fn lower_param(param: &ast::Param) -> types::Param {
    types::Param {
        name: param.name.clone(),
        ty: lower_type(&param.ty),
    }
}

fn lower_block(block: &ast::Block) -> types::Block {
    types::Block {
        stmts: block.stmts.iter().map(lower_stmt).collect(),
    }
}

fn lower_stmt(stmt: &ast::Stmt) -> types::Stmt {
    match stmt {
        ast::Stmt::Let { name, ty, value } => types::Stmt::Let {
            name: name.clone(),
            ty: ty.as_ref().map(lower_type),
            value: lower_expr(value),
        },
        ast::Stmt::Return(value) => types::Stmt::Return(value.as_ref().map(lower_expr)),
        ast::Stmt::Expr(expr) => types::Stmt::Expr(lower_expr(expr)),
        ast::Stmt::If {
            cond,
            then_block,
            else_block,
        } => types::Stmt::If {
            cond: lower_expr(cond),
            then_block: lower_block(then_block),
            else_block: else_block.as_ref().map(lower_block),
        },
        ast::Stmt::Loop(block) => types::Stmt::Loop(lower_block(block)),
        ast::Stmt::Defer(block) => types::Stmt::Defer(lower_block(block)),
    }
}

fn lower_expr(expr: &ast::Expr) -> types::Expr {
    match expr {
        ast::Expr::Literal(lit) => types::Expr::Literal(lower_literal(lit)),
        ast::Expr::Variable(name) => types::Expr::Variable(name.clone()),
        ast::Expr::Call { func, args, span } => types::Expr::Call {
            func: func.clone(),
            args: args.iter().map(lower_expr).collect(),
            span: *span,
        },
        ast::Expr::BinaryOp { left, op, right } => types::Expr::BinaryOp {
            left: Box::new(lower_expr(left)),
            op: lower_binop(*op),
            right: Box::new(lower_expr(right)),
        },
        ast::Expr::If {
            cond,
            then_block,
            else_block,
        } => types::Expr::If {
            cond: Box::new(lower_expr(cond)),
            then_block: lower_block(then_block),
            else_block: else_block.as_ref().map(lower_block),
        },
        ast::Expr::Block(block) => types::Expr::Block(lower_block(block)),
        ast::Expr::Spawn { block, span } => types::Expr::Spawn {
            block: lower_block(block),
            span: *span,
        },
    }
}

fn lower_literal(literal: &ast::Literal) -> types::Literal {
    match literal {
        ast::Literal::Int(v) => types::Literal::Int(*v),
        ast::Literal::Float(v) => types::Literal::Float(*v),
        ast::Literal::Bool(v) => types::Literal::Bool(*v),
        ast::Literal::String(v) => types::Literal::String(v.clone()),
    }
}

fn lower_binop(op: ast::BinOp) -> types::BinOp {
    match op {
        ast::BinOp::Add => types::BinOp::Add,
        ast::BinOp::Sub => types::BinOp::Sub,
        ast::BinOp::Mul => types::BinOp::Mul,
        ast::BinOp::Div => types::BinOp::Div,
        ast::BinOp::Eq => types::BinOp::Eq,
        ast::BinOp::Ne => types::BinOp::Ne,
        ast::BinOp::Lt => types::BinOp::Lt,
        ast::BinOp::Le => types::BinOp::Le,
        ast::BinOp::Gt => types::BinOp::Gt,
        ast::BinOp::Ge => types::BinOp::Ge,
    }
}

fn lower_effect(effect: ast::Effect) -> types::Effect {
    match effect {
        ast::Effect::Pure => types::Effect::Pure,
        ast::Effect::Io => types::Effect::Io,
        ast::Effect::Net => types::Effect::Net,
        ast::Effect::Async => types::Effect::Async,
        ast::Effect::Mut => types::Effect::Mut,
    }
}

fn lower_capability_decl(capability_decl: &ast::CapabilityDecl) -> types::CapabilityDecl {
    types::CapabilityDecl {
        cap: lower_capability(&capability_decl.cap),
    }
}

fn lower_capability(capability: &ast::Capability) -> types::Capability {
    match capability {
        ast::Capability::FsRead { glob } => types::Capability::FsRead { glob: glob.clone() },
        ast::Capability::NetListen { range } => types::Capability::NetListen {
            range: lower_net_port_spec(range),
        },
    }
}

fn lower_net_port_spec(range: &ast::NetPortSpec) -> types::NetPortSpec {
    match range {
        ast::NetPortSpec::Single(v) => types::NetPortSpec::Single(*v),
        ast::NetPortSpec::Range(a, b) => types::NetPortSpec::Range(*a, *b),
    }
}

fn lower_neural_decl(neural_decl: &ast::NeuralDecl) -> types::NeuralDecl {
    types::NeuralDecl {
        name: neural_decl.name.clone(),
        params: neural_decl.params.iter().map(lower_param).collect(),
        return_type: lower_type(&neural_decl.return_type),
        format: neural_decl.format.clone(),
        path: neural_decl.path.clone(),
    }
}

fn lower_type(ty: &ast::Type) -> types::Type {
    match ty {
        ast::Type::I32 => types::Type::I32,
        ast::Type::F32 => types::Type::F32,
        ast::Type::Bool => types::Type::Bool,
        ast::Type::String => types::Type::String,
        ast::Type::Task => types::Type::Task,
        ast::Type::Named(name) => types::Type::Named(name.clone()),
    }
}

fn canonical_capability(capability: &types::Capability) -> String {
    match capability {
        types::Capability::FsRead { glob } => format!("fs.read:{}", glob),
        types::Capability::NetListen { range } => match range {
            types::NetPortSpec::Single(v) => format!("net.listen:{}", v),
            types::NetPortSpec::Range(a, b) => format!("net.listen:{}-{}", a, b),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{hir_node_count, lower_to_hir};
    use crate::hir::types;

    #[test]
    fn parse_and_lower_has_stable_shape() {
        let src = r#"
            cap fs.read("config/*.nex");

            fn main() !io {
                let value: int = 7;
                fs.read("config/app.nex");
                return;
            }
        "#;

        let ast_program = crate::parser::parse(src).expect("source should parse");
        let hir_program = lower_to_hir(&ast_program);

        assert_eq!(hir_program.items.len(), 2);
        assert_eq!(hir_program.governance.capabilities.len(), 1);
        assert_eq!(hir_program.governance.neural_models.len(), 0);
        assert_eq!(
            hir_program.governance.capabilities[0].canonical,
            "fs.read:config/*.nex"
        );

        let main_function = hir_program
            .items
            .iter()
            .find_map(|item| match item {
                types::Item::Function(function) if function.name == "main" => Some(function),
                _ => None,
            })
            .expect("main function should exist");

        assert_eq!(main_function.effects.len(), 1);
        assert_eq!(main_function.body.stmts.len(), 3);
        assert_eq!(hir_node_count(&hir_program), 13);
    }
}
