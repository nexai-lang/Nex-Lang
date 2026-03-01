use crate::hir;

use super::types;

pub fn lower_to_mir(program: &hir::types::Program) -> types::Program {
    let mut next_fn_id: types::FnId = 0;
    let mut functions = Vec::new();

    for item in &program.items {
        if let hir::types::Item::Function(function) = item {
            functions.push(lower_function(function, next_fn_id));
            next_fn_id = next_fn_id.saturating_add(1);
        }
    }

    let entry = functions
        .iter()
        .find(|function| function.name == "main")
        .map(|function| function.id);

    types::Program { functions, entry }
}

fn lower_function(function: &hir::types::Function, fn_id: types::FnId) -> types::Function {
    let mut builder = FunctionBuilder::new();
    lower_hir_block(&function.body, &mut builder);

    if !builder.is_current_terminated() {
        builder.set_terminator(types::Term::Return(None));
    }

    types::Function {
        id: fn_id,
        name: function.name.clone(),
        blocks: builder.finalize(),
    }
}

fn lower_hir_block(block: &hir::types::Block, builder: &mut FunctionBuilder) {
    for (index, stmt) in block.stmts.iter().enumerate() {
        lower_stmt(stmt, builder);

        if builder.is_current_terminated() && index + 1 < block.stmts.len() {
            let unreachable = builder.new_block();
            builder.switch_to(unreachable);
        }
    }
}

fn lower_stmt(stmt: &hir::types::Stmt, builder: &mut FunctionBuilder) {
    match stmt {
        hir::types::Stmt::Let { name, value, .. } => {
            lower_expr_into_named(value, name.clone(), true, builder);
        }
        hir::types::Stmt::Return(value) => {
            let lowered = value
                .as_ref()
                .map(|expr| lower_expr_to_value(expr, builder));
            builder.set_terminator(types::Term::Return(lowered));
        }
        hir::types::Stmt::Expr(expr) => {
            lower_expr_for_side_effect(expr, builder);
        }
        hir::types::Stmt::If {
            cond,
            then_block,
            else_block,
        } => {
            lower_if_stmt(cond, then_block, else_block.as_ref(), builder);
        }
        hir::types::Stmt::Loop(loop_block) => {
            let loop_block_id = builder.new_block();
            let after_loop = builder.new_block();

            builder.set_terminator(types::Term::Jump(loop_block_id));

            builder.switch_to(loop_block_id);
            lower_hir_block(loop_block, builder);
            if !builder.is_current_terminated() {
                builder.set_terminator(types::Term::Jump(loop_block_id));
            }

            builder.switch_to(after_loop);
        }
        hir::types::Stmt::Defer(deferred_block) => {
            lower_hir_block(deferred_block, builder);
        }
    }
}

fn lower_if_stmt(
    cond: &hir::types::Expr,
    then_block: &hir::types::Block,
    else_block: Option<&hir::types::Block>,
    builder: &mut FunctionBuilder,
) {
    let cond_value = lower_expr_to_value(cond, builder);

    let then_block_id = builder.new_block();
    let else_block_id = builder.new_block();
    let join_block_id = builder.new_block();

    builder.set_terminator(types::Term::Branch {
        cond: cond_value,
        then_block: then_block_id,
        else_block: else_block_id,
    });

    builder.switch_to(then_block_id);
    lower_hir_block(then_block, builder);
    if !builder.is_current_terminated() {
        builder.set_terminator(types::Term::Jump(join_block_id));
    }

    builder.switch_to(else_block_id);
    if let Some(else_block) = else_block {
        lower_hir_block(else_block, builder);
    }
    if !builder.is_current_terminated() {
        builder.set_terminator(types::Term::Jump(join_block_id));
    }

    builder.switch_to(join_block_id);
}

fn lower_expr_for_side_effect(expr: &hir::types::Expr, builder: &mut FunctionBuilder) {
    match expr {
        hir::types::Expr::Literal(_)
        | hir::types::Expr::Variable(_)
        | hir::types::Expr::BinaryOp { .. } => {}
        hir::types::Expr::Call { func, args, .. } => {
            emit_classified_call(builder, func, args, None);
        }
        hir::types::Expr::If {
            cond,
            then_block,
            else_block,
        } => {
            lower_if_stmt(cond, then_block, else_block.as_ref(), builder);
        }
        hir::types::Expr::Block(block) => {
            lower_hir_block(block, builder);
        }
        hir::types::Expr::Spawn { .. } => {
            builder.emit_stmt(types::Stmt::Call {
                dest: None,
                func: "__spawn".to_string(),
                args: Vec::new(),
            });
        }
    }
}

fn lower_expr_into_named(
    expr: &hir::types::Expr,
    name: String,
    is_let: bool,
    builder: &mut FunctionBuilder,
) {
    match expr {
        hir::types::Expr::Call { func, args, .. } => {
            emit_classified_call(builder, func, args, Some(name));
        }
        hir::types::Expr::If {
            cond,
            then_block,
            else_block,
        } => {
            lower_if_expr_into_named(cond, then_block, else_block.as_ref(), name, is_let, builder);
        }
        hir::types::Expr::Block(block) => {
            lower_hir_block(block, builder);
            emit_named_binding(
                builder,
                name,
                types::Expr::Literal(types::Literal::Unit),
                is_let,
            );
        }
        hir::types::Expr::Spawn { .. } => {
            builder.emit_stmt(types::Stmt::Call {
                dest: Some(name),
                func: "__spawn".to_string(),
                args: Vec::new(),
            });
        }
        _ => {
            let value = lower_expr_to_value(expr, builder);
            emit_named_binding(builder, name, value, is_let);
        }
    }
}

fn lower_if_expr_into_named(
    cond: &hir::types::Expr,
    then_block: &hir::types::Block,
    else_block: Option<&hir::types::Block>,
    name: String,
    is_let: bool,
    builder: &mut FunctionBuilder,
) {
    if is_let {
        builder.emit_stmt(types::Stmt::Let {
            name: name.clone(),
            value: types::Expr::Literal(types::Literal::Unit),
        });
    }

    let cond_value = lower_expr_to_value(cond, builder);

    let then_block_id = builder.new_block();
    let else_block_id = builder.new_block();
    let join_block_id = builder.new_block();

    builder.set_terminator(types::Term::Branch {
        cond: cond_value,
        then_block: then_block_id,
        else_block: else_block_id,
    });

    builder.switch_to(then_block_id);
    lower_hir_block(then_block, builder);
    if !builder.is_current_terminated() {
        builder.emit_stmt(types::Stmt::Assign {
            name: name.clone(),
            value: types::Expr::Literal(types::Literal::Unit),
        });
        builder.set_terminator(types::Term::Jump(join_block_id));
    }

    builder.switch_to(else_block_id);
    if let Some(else_block) = else_block {
        lower_hir_block(else_block, builder);
    }
    if !builder.is_current_terminated() {
        builder.emit_stmt(types::Stmt::Assign {
            name,
            value: types::Expr::Literal(types::Literal::Unit),
        });
        builder.set_terminator(types::Term::Jump(join_block_id));
    }

    builder.switch_to(join_block_id);
}

fn lower_expr_to_value(expr: &hir::types::Expr, builder: &mut FunctionBuilder) -> types::Expr {
    match expr {
        hir::types::Expr::Literal(literal) => types::Expr::Literal(lower_literal(literal)),
        hir::types::Expr::Variable(name) => types::Expr::Variable(name.clone()),
        hir::types::Expr::BinaryOp { left, op, right } => types::Expr::BinaryOp {
            left: Box::new(lower_expr_to_value(left, builder)),
            op: lower_bin_op(*op),
            right: Box::new(lower_expr_to_value(right, builder)),
        },
        hir::types::Expr::Call { func, args, .. } => {
            let tmp = builder.next_temp_name();
            emit_classified_call(builder, func, args, Some(tmp.clone()));
            types::Expr::Variable(tmp)
        }
        hir::types::Expr::If {
            cond,
            then_block,
            else_block,
        } => {
            let tmp = builder.next_temp_name();
            lower_if_expr_into_named(
                cond,
                then_block,
                else_block.as_ref(),
                tmp.clone(),
                true,
                builder,
            );
            types::Expr::Variable(tmp)
        }
        hir::types::Expr::Block(block) => {
            lower_hir_block(block, builder);
            types::Expr::Literal(types::Literal::Unit)
        }
        hir::types::Expr::Spawn { .. } => {
            let tmp = builder.next_temp_name();
            builder.emit_stmt(types::Stmt::Call {
                dest: Some(tmp.clone()),
                func: "__spawn".to_string(),
                args: Vec::new(),
            });
            types::Expr::Variable(tmp)
        }
    }
}

fn emit_named_binding(
    builder: &mut FunctionBuilder,
    name: String,
    value: types::Expr,
    is_let: bool,
) {
    if is_let {
        builder.emit_stmt(types::Stmt::Let { name, value });
    } else {
        builder.emit_stmt(types::Stmt::Assign { name, value });
    }
}

fn emit_classified_call(
    builder: &mut FunctionBuilder,
    func: &str,
    args: &[hir::types::Expr],
    dest: Option<String>,
) {
    let lowered_args = args
        .iter()
        .map(|arg| lower_expr_to_value(arg, builder))
        .collect::<Vec<_>>();

    match classify_call(func) {
        CallKind::Call => builder.emit_stmt(types::Stmt::Call {
            dest,
            func: func.to_string(),
            args: lowered_args,
        }),
        CallKind::Send => builder.emit_stmt(types::Stmt::Send {
            dest,
            func: func.to_string(),
            args: lowered_args,
        }),
        CallKind::Recv => builder.emit_stmt(types::Stmt::Recv {
            dest,
            func: func.to_string(),
            args: lowered_args,
        }),
        CallKind::IoRead => builder.emit_stmt(types::Stmt::IoRead {
            dest,
            func: func.to_string(),
            args: lowered_args,
        }),
        CallKind::IoWrite => builder.emit_stmt(types::Stmt::IoWrite {
            dest,
            func: func.to_string(),
            args: lowered_args,
        }),
    }
}

fn lower_literal(literal: &hir::types::Literal) -> types::Literal {
    match literal {
        hir::types::Literal::Int(v) => types::Literal::Int(*v),
        hir::types::Literal::Float(v) => types::Literal::FloatBits(v.to_bits()),
        hir::types::Literal::Bool(v) => types::Literal::Bool(*v),
        hir::types::Literal::String(v) => types::Literal::String(v.clone()),
    }
}

fn lower_bin_op(op: hir::types::BinOp) -> types::BinOp {
    match op {
        hir::types::BinOp::Add => types::BinOp::Add,
        hir::types::BinOp::Sub => types::BinOp::Sub,
        hir::types::BinOp::Mul => types::BinOp::Mul,
        hir::types::BinOp::Div => types::BinOp::Div,
        hir::types::BinOp::Eq => types::BinOp::Eq,
        hir::types::BinOp::Ne => types::BinOp::Ne,
        hir::types::BinOp::Lt => types::BinOp::Lt,
        hir::types::BinOp::Le => types::BinOp::Le,
        hir::types::BinOp::Gt => types::BinOp::Gt,
        hir::types::BinOp::Ge => types::BinOp::Ge,
    }
}

#[derive(Clone, Copy)]
enum CallKind {
    Call,
    Send,
    Recv,
    IoRead,
    IoWrite,
}

fn classify_call(func: &str) -> CallKind {
    if func == "bus.send" {
        return CallKind::Send;
    }
    if func == "bus.recv" {
        return CallKind::Recv;
    }

    if func == "fs.read" || func == "io_proxy.read" {
        return CallKind::IoRead;
    }

    if func == "fs.write" || func == "io_proxy.write" {
        return CallKind::IoWrite;
    }

    if func.starts_with("net.") {
        if func.ends_with("recv") {
            return CallKind::IoRead;
        }
        return CallKind::IoWrite;
    }

    CallKind::Call
}

struct BlockBuilder {
    id: types::BlockId,
    stmts: Vec<types::Stmt>,
    terminator: Option<types::Term>,
}

struct FunctionBuilder {
    blocks: Vec<BlockBuilder>,
    current: usize,
    next_temp: u32,
}

impl FunctionBuilder {
    fn new() -> Self {
        Self {
            blocks: vec![BlockBuilder {
                id: 0,
                stmts: Vec::new(),
                terminator: None,
            }],
            current: 0,
            next_temp: 0,
        }
    }

    fn new_block(&mut self) -> types::BlockId {
        let id = self.blocks.len() as types::BlockId;
        self.blocks.push(BlockBuilder {
            id,
            stmts: Vec::new(),
            terminator: None,
        });
        id
    }

    fn switch_to(&mut self, block_id: types::BlockId) {
        self.current = block_id as usize;
    }

    fn emit_stmt(&mut self, stmt: types::Stmt) {
        self.blocks[self.current].stmts.push(stmt);
    }

    fn set_terminator(&mut self, term: types::Term) {
        self.blocks[self.current].terminator = Some(term);
    }

    fn is_current_terminated(&self) -> bool {
        self.blocks[self.current].terminator.is_some()
    }

    fn next_temp_name(&mut self) -> String {
        let id = self.next_temp;
        self.next_temp = self.next_temp.saturating_add(1);
        format!("_mir_tmp{}", id)
    }

    fn finalize(self) -> Vec<types::Block> {
        let mut out = Vec::with_capacity(self.blocks.len());
        for block in self.blocks {
            out.push(types::Block {
                id: block.id,
                stmts: block.stmts,
                terminator: block.terminator.unwrap_or(types::Term::Return(None)),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::lower_to_mir;
    use crate::hir::lower::lower_to_hir;

    #[test]
    fn lower_builds_deterministic_entry() {
        let src = r#"
            fn helper() {
                return;
            }

            fn main() {
                helper();
                return;
            }
        "#;

        let ast = crate::parser::parse(src).expect("source should parse");
        let hir = lower_to_hir(&ast);
        let mir = lower_to_mir(&hir);

        assert_eq!(mir.functions.len(), 2);
        assert_eq!(mir.entry, Some(1));
        assert_eq!(mir.functions[0].name, "helper");
        assert_eq!(mir.functions[1].name, "main");
    }
}
