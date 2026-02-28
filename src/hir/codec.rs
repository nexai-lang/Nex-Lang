use std::fmt;

use crate::ast::Span;

use super::types;
use super::HIR_VERSION;

pub const HIR_MAGIC: [u8; 8] = *b"NEXHIR\0\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEof {
        offset: usize,
        needed: usize,
        remaining: usize,
    },
    InvalidMagic,
    UnsupportedVersion {
        found: u32,
        supported: u32,
    },
    InvalidTag {
        context: &'static str,
        tag: u8,
    },
    InvalidUtf8 {
        context: &'static str,
    },
    LengthOverflow {
        context: &'static str,
        value: u64,
    },
    IntegerOverflow {
        context: &'static str,
        value: u64,
    },
    TrailingBytes {
        offset: usize,
        remaining: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnexpectedEof {
                offset,
                needed,
                remaining,
            } => write!(
                f,
                "unexpected eof at offset {}: need {} bytes, have {}",
                offset, needed, remaining
            ),
            DecodeError::InvalidMagic => write!(f, "invalid HIR magic"),
            DecodeError::UnsupportedVersion { found, supported } => write!(
                f,
                "unsupported HIR version: {} (supported: {})",
                found, supported
            ),
            DecodeError::InvalidTag { context, tag } => {
                write!(f, "invalid tag for {}: {}", context, tag)
            }
            DecodeError::InvalidUtf8 { context } => write!(f, "invalid utf-8 in {}", context),
            DecodeError::LengthOverflow { context, value } => {
                write!(f, "length overflow in {}: {}", context, value)
            }
            DecodeError::IntegerOverflow { context, value } => {
                write!(f, "integer overflow in {}: {}", context, value)
            }
            DecodeError::TrailingBytes { offset, remaining } => write!(
                f,
                "trailing bytes after HIR payload at offset {}: {}",
                offset, remaining
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

pub fn encode(program: &types::Program) -> Vec<u8> {
    program.encode()
}

pub fn decode(bytes: &[u8]) -> Result<types::Program, DecodeError> {
    types::Program::decode(bytes)
}

impl types::Program {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&HIR_MAGIC);
        write_u32(&mut out, HIR_VERSION);
        encode_program_payload(self, &mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);

        let magic = reader.read_fixed::<8>()?;
        if magic != HIR_MAGIC {
            return Err(DecodeError::InvalidMagic);
        }

        let version = reader.read_u32()?;
        if version != HIR_VERSION {
            return Err(DecodeError::UnsupportedVersion {
                found: version,
                supported: HIR_VERSION,
            });
        }

        let program = decode_program_payload(&mut reader)?;
        if reader.remaining() != 0 {
            return Err(DecodeError::TrailingBytes {
                offset: reader.offset(),
                remaining: reader.remaining(),
            });
        }

        Ok(program)
    }
}

fn encode_program_payload(program: &types::Program, dst: &mut Vec<u8>) {
    encode_items(&program.items, dst);
    encode_governance(&program.governance, dst);
}

fn decode_program_payload(reader: &mut Reader<'_>) -> Result<types::Program, DecodeError> {
    Ok(types::Program {
        items: decode_items(reader)?,
        governance: decode_governance(reader)?,
    })
}

fn encode_governance(governance: &types::GovernanceFacts, dst: &mut Vec<u8>) {
    write_len(dst, governance.capabilities.len());
    for cap in &governance.capabilities {
        write_string(dst, &cap.canonical);
    }

    write_len(dst, governance.neural_models.len());
    for model in &governance.neural_models {
        write_string(dst, &model.name);
    }

    write_len(dst, governance.policy_fragments.len());
    for fragment in &governance.policy_fragments {
        write_string(dst, fragment);
    }
}

fn decode_governance(reader: &mut Reader<'_>) -> Result<types::GovernanceFacts, DecodeError> {
    let capabilities_len = reader.read_len("governance.capabilities")?;
    let mut capabilities = Vec::with_capacity(capabilities_len);
    for _ in 0..capabilities_len {
        capabilities.push(types::CapabilityFact {
            canonical: reader.read_string("governance.capabilities[].canonical")?,
        });
    }

    let models_len = reader.read_len("governance.neural_models")?;
    let mut neural_models = Vec::with_capacity(models_len);
    for _ in 0..models_len {
        neural_models.push(types::NeuralModelFact {
            name: reader.read_string("governance.neural_models[].name")?,
        });
    }

    let fragments_len = reader.read_len("governance.policy_fragments")?;
    let mut policy_fragments = Vec::with_capacity(fragments_len);
    for _ in 0..fragments_len {
        policy_fragments.push(reader.read_string("governance.policy_fragments[]")?);
    }

    Ok(types::GovernanceFacts {
        capabilities,
        neural_models,
        policy_fragments,
    })
}

fn encode_items(items: &[types::Item], dst: &mut Vec<u8>) {
    write_len(dst, items.len());
    for item in items {
        encode_item(item, dst);
    }
}

fn decode_items(reader: &mut Reader<'_>) -> Result<Vec<types::Item>, DecodeError> {
    let len = reader.read_len("program.items")?;
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        items.push(decode_item(reader)?);
    }
    Ok(items)
}

fn encode_item(item: &types::Item, dst: &mut Vec<u8>) {
    match item {
        types::Item::Function(func) => {
            write_u8(dst, 1);
            encode_function(func, dst);
        }
        types::Item::Capability(cap) => {
            write_u8(dst, 2);
            encode_capability_decl(cap, dst);
        }
        types::Item::Neural(neural) => {
            write_u8(dst, 3);
            encode_neural_decl(neural, dst);
        }
    }
}

fn decode_item(reader: &mut Reader<'_>) -> Result<types::Item, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::Item::Function(decode_function(reader)?)),
        2 => Ok(types::Item::Capability(decode_capability_decl(reader)?)),
        3 => Ok(types::Item::Neural(decode_neural_decl(reader)?)),
        _ => Err(DecodeError::InvalidTag {
            context: "item",
            tag,
        }),
    }
}

fn encode_function(function: &types::Function, dst: &mut Vec<u8>) {
    write_string(dst, &function.name);
    encode_span(&function.name_span, dst);

    write_len(dst, function.params.len());
    for param in &function.params {
        encode_param(param, dst);
    }

    match &function.return_type {
        Some(ty) => {
            write_u8(dst, 1);
            encode_type(ty, dst);
        }
        None => write_u8(dst, 0),
    }

    write_len(dst, function.effects.len());
    for effect in &function.effects {
        encode_effect(*effect, dst);
    }

    encode_block(&function.body, dst);
}

fn decode_function(reader: &mut Reader<'_>) -> Result<types::Function, DecodeError> {
    let name = reader.read_string("function.name")?;
    let name_span = decode_span(reader)?;

    let params_len = reader.read_len("function.params")?;
    let mut params = Vec::with_capacity(params_len);
    for _ in 0..params_len {
        params.push(decode_param(reader)?);
    }

    let has_return_type = reader.read_u8()?;
    let return_type = match has_return_type {
        0 => None,
        1 => Some(decode_type(reader)?),
        tag => {
            return Err(DecodeError::InvalidTag {
                context: "function.return_type",
                tag,
            });
        }
    };

    let effects_len = reader.read_len("function.effects")?;
    let mut effects = Vec::with_capacity(effects_len);
    for _ in 0..effects_len {
        effects.push(decode_effect(reader)?);
    }

    let body = decode_block(reader)?;

    Ok(types::Function {
        name,
        name_span,
        params,
        return_type,
        effects,
        body,
    })
}

fn encode_param(param: &types::Param, dst: &mut Vec<u8>) {
    write_string(dst, &param.name);
    encode_type(&param.ty, dst);
}

fn decode_param(reader: &mut Reader<'_>) -> Result<types::Param, DecodeError> {
    Ok(types::Param {
        name: reader.read_string("param.name")?,
        ty: decode_type(reader)?,
    })
}

fn encode_block(block: &types::Block, dst: &mut Vec<u8>) {
    write_len(dst, block.stmts.len());
    for stmt in &block.stmts {
        encode_stmt(stmt, dst);
    }
}

fn decode_block(reader: &mut Reader<'_>) -> Result<types::Block, DecodeError> {
    let len = reader.read_len("block.stmts")?;
    let mut stmts = Vec::with_capacity(len);
    for _ in 0..len {
        stmts.push(decode_stmt(reader)?);
    }
    Ok(types::Block { stmts })
}

fn encode_stmt(stmt: &types::Stmt, dst: &mut Vec<u8>) {
    match stmt {
        types::Stmt::Let { name, ty, value } => {
            write_u8(dst, 1);
            write_string(dst, name);
            match ty {
                Some(t) => {
                    write_u8(dst, 1);
                    encode_type(t, dst);
                }
                None => write_u8(dst, 0),
            }
            encode_expr(value, dst);
        }
        types::Stmt::Return(expr) => {
            write_u8(dst, 2);
            match expr {
                Some(e) => {
                    write_u8(dst, 1);
                    encode_expr(e, dst);
                }
                None => write_u8(dst, 0),
            }
        }
        types::Stmt::Expr(expr) => {
            write_u8(dst, 3);
            encode_expr(expr, dst);
        }
        types::Stmt::If {
            cond,
            then_block,
            else_block,
        } => {
            write_u8(dst, 4);
            encode_expr(cond, dst);
            encode_block(then_block, dst);
            match else_block {
                Some(b) => {
                    write_u8(dst, 1);
                    encode_block(b, dst);
                }
                None => write_u8(dst, 0),
            }
        }
        types::Stmt::Loop(block) => {
            write_u8(dst, 5);
            encode_block(block, dst);
        }
        types::Stmt::Defer(block) => {
            write_u8(dst, 6);
            encode_block(block, dst);
        }
    }
}

fn decode_stmt(reader: &mut Reader<'_>) -> Result<types::Stmt, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => {
            let name = reader.read_string("stmt.let.name")?;
            let has_ty = reader.read_u8()?;
            let ty = match has_ty {
                0 => None,
                1 => Some(decode_type(reader)?),
                bad => {
                    return Err(DecodeError::InvalidTag {
                        context: "stmt.let.type",
                        tag: bad,
                    });
                }
            };
            let value = decode_expr(reader)?;
            Ok(types::Stmt::Let { name, ty, value })
        }
        2 => {
            let has_value = reader.read_u8()?;
            let value = match has_value {
                0 => None,
                1 => Some(decode_expr(reader)?),
                bad => {
                    return Err(DecodeError::InvalidTag {
                        context: "stmt.return",
                        tag: bad,
                    });
                }
            };
            Ok(types::Stmt::Return(value))
        }
        3 => Ok(types::Stmt::Expr(decode_expr(reader)?)),
        4 => {
            let cond = decode_expr(reader)?;
            let then_block = decode_block(reader)?;
            let has_else = reader.read_u8()?;
            let else_block = match has_else {
                0 => None,
                1 => Some(decode_block(reader)?),
                bad => {
                    return Err(DecodeError::InvalidTag {
                        context: "stmt.if.else",
                        tag: bad,
                    });
                }
            };
            Ok(types::Stmt::If {
                cond,
                then_block,
                else_block,
            })
        }
        5 => Ok(types::Stmt::Loop(decode_block(reader)?)),
        6 => Ok(types::Stmt::Defer(decode_block(reader)?)),
        _ => Err(DecodeError::InvalidTag {
            context: "stmt",
            tag,
        }),
    }
}

fn encode_expr(expr: &types::Expr, dst: &mut Vec<u8>) {
    match expr {
        types::Expr::Literal(literal) => {
            write_u8(dst, 1);
            encode_literal(literal, dst);
        }
        types::Expr::Variable(name) => {
            write_u8(dst, 2);
            write_string(dst, name);
        }
        types::Expr::Call { func, args, span } => {
            write_u8(dst, 3);
            write_string(dst, func);
            write_len(dst, args.len());
            for arg in args {
                encode_expr(arg, dst);
            }
            encode_span(span, dst);
        }
        types::Expr::BinaryOp { left, op, right } => {
            write_u8(dst, 4);
            encode_expr(left, dst);
            encode_bin_op(*op, dst);
            encode_expr(right, dst);
        }
        types::Expr::If {
            cond,
            then_block,
            else_block,
        } => {
            write_u8(dst, 5);
            encode_expr(cond, dst);
            encode_block(then_block, dst);
            match else_block {
                Some(block) => {
                    write_u8(dst, 1);
                    encode_block(block, dst);
                }
                None => write_u8(dst, 0),
            }
        }
        types::Expr::Block(block) => {
            write_u8(dst, 6);
            encode_block(block, dst);
        }
        types::Expr::Spawn { block, span } => {
            write_u8(dst, 7);
            encode_block(block, dst);
            encode_span(span, dst);
        }
    }
}

fn decode_expr(reader: &mut Reader<'_>) -> Result<types::Expr, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::Expr::Literal(decode_literal(reader)?)),
        2 => Ok(types::Expr::Variable(reader.read_string("expr.variable")?)),
        3 => {
            let func = reader.read_string("expr.call.func")?;
            let args_len = reader.read_len("expr.call.args")?;
            let mut args = Vec::with_capacity(args_len);
            for _ in 0..args_len {
                args.push(decode_expr(reader)?);
            }
            let span = decode_span(reader)?;
            Ok(types::Expr::Call { func, args, span })
        }
        4 => {
            let left = Box::new(decode_expr(reader)?);
            let op = decode_bin_op(reader)?;
            let right = Box::new(decode_expr(reader)?);
            Ok(types::Expr::BinaryOp { left, op, right })
        }
        5 => {
            let cond = Box::new(decode_expr(reader)?);
            let then_block = decode_block(reader)?;
            let has_else = reader.read_u8()?;
            let else_block = match has_else {
                0 => None,
                1 => Some(decode_block(reader)?),
                bad => {
                    return Err(DecodeError::InvalidTag {
                        context: "expr.if.else",
                        tag: bad,
                    });
                }
            };
            Ok(types::Expr::If {
                cond,
                then_block,
                else_block,
            })
        }
        6 => Ok(types::Expr::Block(decode_block(reader)?)),
        7 => {
            let block = decode_block(reader)?;
            let span = decode_span(reader)?;
            Ok(types::Expr::Spawn { block, span })
        }
        _ => Err(DecodeError::InvalidTag {
            context: "expr",
            tag,
        }),
    }
}

fn encode_literal(literal: &types::Literal, dst: &mut Vec<u8>) {
    match literal {
        types::Literal::Int(v) => {
            write_u8(dst, 1);
            write_i64(dst, *v);
        }
        types::Literal::Float(v) => {
            write_u8(dst, 2);
            write_f64(dst, *v);
        }
        types::Literal::Bool(v) => {
            write_u8(dst, 3);
            write_u8(dst, if *v { 1 } else { 0 });
        }
        types::Literal::String(v) => {
            write_u8(dst, 4);
            write_string(dst, v);
        }
    }
}

fn decode_literal(reader: &mut Reader<'_>) -> Result<types::Literal, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::Literal::Int(reader.read_i64()?)),
        2 => Ok(types::Literal::Float(reader.read_f64()?)),
        3 => {
            let value = reader.read_u8()?;
            match value {
                0 => Ok(types::Literal::Bool(false)),
                1 => Ok(types::Literal::Bool(true)),
                _ => Err(DecodeError::InvalidTag {
                    context: "literal.bool",
                    tag: value,
                }),
            }
        }
        4 => Ok(types::Literal::String(
            reader.read_string("literal.string")?,
        )),
        _ => Err(DecodeError::InvalidTag {
            context: "literal",
            tag,
        }),
    }
}

fn encode_bin_op(op: types::BinOp, dst: &mut Vec<u8>) {
    let tag = match op {
        types::BinOp::Add => 1,
        types::BinOp::Sub => 2,
        types::BinOp::Mul => 3,
        types::BinOp::Div => 4,
        types::BinOp::Eq => 5,
        types::BinOp::Ne => 6,
        types::BinOp::Lt => 7,
        types::BinOp::Le => 8,
        types::BinOp::Gt => 9,
        types::BinOp::Ge => 10,
    };
    write_u8(dst, tag);
}

fn decode_bin_op(reader: &mut Reader<'_>) -> Result<types::BinOp, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::BinOp::Add),
        2 => Ok(types::BinOp::Sub),
        3 => Ok(types::BinOp::Mul),
        4 => Ok(types::BinOp::Div),
        5 => Ok(types::BinOp::Eq),
        6 => Ok(types::BinOp::Ne),
        7 => Ok(types::BinOp::Lt),
        8 => Ok(types::BinOp::Le),
        9 => Ok(types::BinOp::Gt),
        10 => Ok(types::BinOp::Ge),
        _ => Err(DecodeError::InvalidTag {
            context: "bin_op",
            tag,
        }),
    }
}

fn encode_effect(effect: types::Effect, dst: &mut Vec<u8>) {
    let tag = match effect {
        types::Effect::Pure => 1,
        types::Effect::Io => 2,
        types::Effect::Net => 3,
        types::Effect::Async => 4,
        types::Effect::Mut => 5,
    };
    write_u8(dst, tag);
}

fn decode_effect(reader: &mut Reader<'_>) -> Result<types::Effect, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::Effect::Pure),
        2 => Ok(types::Effect::Io),
        3 => Ok(types::Effect::Net),
        4 => Ok(types::Effect::Async),
        5 => Ok(types::Effect::Mut),
        _ => Err(DecodeError::InvalidTag {
            context: "effect",
            tag,
        }),
    }
}

fn encode_capability_decl(decl: &types::CapabilityDecl, dst: &mut Vec<u8>) {
    encode_capability(&decl.cap, dst);
}

fn decode_capability_decl(reader: &mut Reader<'_>) -> Result<types::CapabilityDecl, DecodeError> {
    Ok(types::CapabilityDecl {
        cap: decode_capability(reader)?,
    })
}

fn encode_capability(capability: &types::Capability, dst: &mut Vec<u8>) {
    match capability {
        types::Capability::FsRead { glob } => {
            write_u8(dst, 1);
            write_string(dst, glob);
        }
        types::Capability::NetListen { range } => {
            write_u8(dst, 2);
            encode_net_port_spec(range, dst);
        }
    }
}

fn decode_capability(reader: &mut Reader<'_>) -> Result<types::Capability, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::Capability::FsRead {
            glob: reader.read_string("capability.fs_read.glob")?,
        }),
        2 => Ok(types::Capability::NetListen {
            range: decode_net_port_spec(reader)?,
        }),
        _ => Err(DecodeError::InvalidTag {
            context: "capability",
            tag,
        }),
    }
}

fn encode_net_port_spec(range: &types::NetPortSpec, dst: &mut Vec<u8>) {
    match range {
        types::NetPortSpec::Single(v) => {
            write_u8(dst, 1);
            write_i64(dst, *v);
        }
        types::NetPortSpec::Range(a, b) => {
            write_u8(dst, 2);
            write_i64(dst, *a);
            write_i64(dst, *b);
        }
    }
}

fn decode_net_port_spec(reader: &mut Reader<'_>) -> Result<types::NetPortSpec, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::NetPortSpec::Single(reader.read_i64()?)),
        2 => {
            let a = reader.read_i64()?;
            let b = reader.read_i64()?;
            Ok(types::NetPortSpec::Range(a, b))
        }
        _ => Err(DecodeError::InvalidTag {
            context: "net_port_spec",
            tag,
        }),
    }
}

fn encode_neural_decl(neural: &types::NeuralDecl, dst: &mut Vec<u8>) {
    write_string(dst, &neural.name);

    write_len(dst, neural.params.len());
    for param in &neural.params {
        encode_param(param, dst);
    }

    encode_type(&neural.return_type, dst);
    write_string(dst, &neural.format);
    write_string(dst, &neural.path);
}

fn decode_neural_decl(reader: &mut Reader<'_>) -> Result<types::NeuralDecl, DecodeError> {
    let name = reader.read_string("neural.name")?;

    let params_len = reader.read_len("neural.params")?;
    let mut params = Vec::with_capacity(params_len);
    for _ in 0..params_len {
        params.push(decode_param(reader)?);
    }

    let return_type = decode_type(reader)?;
    let format = reader.read_string("neural.format")?;
    let path = reader.read_string("neural.path")?;

    Ok(types::NeuralDecl {
        name,
        params,
        return_type,
        format,
        path,
    })
}

fn encode_type(ty: &types::Type, dst: &mut Vec<u8>) {
    match ty {
        types::Type::I32 => write_u8(dst, 1),
        types::Type::F32 => write_u8(dst, 2),
        types::Type::Bool => write_u8(dst, 3),
        types::Type::String => write_u8(dst, 4),
        types::Type::Task => write_u8(dst, 5),
        types::Type::Named(name) => {
            write_u8(dst, 6);
            write_string(dst, name);
        }
    }
}

fn decode_type(reader: &mut Reader<'_>) -> Result<types::Type, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::Type::I32),
        2 => Ok(types::Type::F32),
        3 => Ok(types::Type::Bool),
        4 => Ok(types::Type::String),
        5 => Ok(types::Type::Task),
        6 => Ok(types::Type::Named(reader.read_string("type.named")?)),
        _ => Err(DecodeError::InvalidTag {
            context: "type",
            tag,
        }),
    }
}

fn encode_span(span: &Span, dst: &mut Vec<u8>) {
    let line = u64::try_from(span.line).expect("span.line must fit into u64");
    let col = u64::try_from(span.col).expect("span.col must fit into u64");
    write_u64(dst, line);
    write_u64(dst, col);
}

fn decode_span(reader: &mut Reader<'_>) -> Result<Span, DecodeError> {
    let line_u64 = reader.read_u64()?;
    let col_u64 = reader.read_u64()?;

    let line = usize::try_from(line_u64).map_err(|_| DecodeError::IntegerOverflow {
        context: "span.line",
        value: line_u64,
    })?;

    let col = usize::try_from(col_u64).map_err(|_| DecodeError::IntegerOverflow {
        context: "span.col",
        value: col_u64,
    })?;

    Ok(Span { line, col })
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

fn write_i64(dst: &mut Vec<u8>, value: i64) {
    dst.extend_from_slice(&value.to_le_bytes());
}

fn write_f64(dst: &mut Vec<u8>, value: f64) {
    write_u64(dst, value.to_bits());
}

fn write_len(dst: &mut Vec<u8>, len: usize) {
    let value = u64::try_from(len).expect("length must fit into u64");
    write_u64(dst, value);
}

fn write_string(dst: &mut Vec<u8>, value: &str) {
    write_len(dst, value.len());
    dst.extend_from_slice(value.as_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_fixed::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_fixed::<8>()?))
    }

    fn read_i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.read_fixed::<8>()?))
    }

    fn read_f64(&mut self) -> Result<f64, DecodeError> {
        Ok(f64::from_bits(self.read_u64()?))
    }

    fn read_len(&mut self, context: &'static str) -> Result<usize, DecodeError> {
        let raw = self.read_u64()?;
        usize::try_from(raw).map_err(|_| DecodeError::LengthOverflow {
            context,
            value: raw,
        })
    }

    fn read_string(&mut self, context: &'static str) -> Result<String, DecodeError> {
        let len = self.read_len(context)?;
        let bytes = self.take(len)?;
        let s = std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8 { context })?;
        Ok(s.to_owned())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::UnexpectedEof {
                offset: self.offset,
                needed: n,
                remaining: self.remaining(),
            });
        }

        let start = self.offset;
        self.offset += n;
        Ok(&self.bytes[start..self.offset])
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn offset(&self) -> usize {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{DecodeError, HIR_MAGIC};
    use crate::hir::lower::lower_to_hir;
    use crate::hir::types;
    use crate::hir::HIR_VERSION;

    struct GoldenCase {
        name: &'static str,
        source: &'static str,
        golden_relpath: &'static str,
    }

    const GOLDEN_CASES: &[GoldenCase] = &[
        GoldenCase {
            name: "capability_fs_read",
            source: r#"
                cap fs.read("config/*.nex");

                fn main() !io {
                    fs.read("config/app.nex");
                    return;
                }
            "#,
            golden_relpath: "src/hir/golden/capability_fs_read.hir.hex",
        },
        GoldenCase {
            name: "net_listen_range_if",
            source: r#"
                cap net.listen(8000..8001);

                fn main() !net {
                    if true {
                        net.listen(8000);
                    } else {
                        net.listen(8001);
                    }
                    return;
                }
            "#,
            golden_relpath: "src/hir/golden/net_listen_range_if.hir.hex",
        },
        GoldenCase {
            name: "neural_and_spawn",
            source: r#"
                neural embed(x: str): str {
                    format "onnx";
                    path "models/embed.onnx";
                }

                fn main() !async {
                    spawn {
                        return;
                    };
                    return;
                }
            "#,
            golden_relpath: "src/hir/golden/neural_and_spawn.hir.hex",
        },
    ];

    #[test]
    fn encode_decode_encode_is_byte_identical() {
        let src = r#"
            cap fs.read("cfg/*.nex");

            fn helper(v: int): int {
                return v;
            }

            fn main() !io {
                let x: int = helper(7);
                fs.read("cfg/app.nex");
                if x == 7 {
                    return;
                } else {
                    return;
                }
            }
        "#;

        let hir = parse_and_lower(src);
        let encoded = hir.encode();
        let decoded = types::Program::decode(&encoded).expect("decode should succeed");
        let reencoded = decoded.encode();

        assert_eq!(encoded, reencoded);
    }

    #[test]
    fn golden_program_encodings_match_exactly() {
        let update = std::env::var("NEX_UPDATE_HIR_GOLDEN")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false);

        for case in GOLDEN_CASES {
            let encoded = parse_and_lower(case.source).encode();
            let path = project_root().join(case.golden_relpath);

            if update {
                fs::write(&path, format!("{}\n", to_hex(&encoded))).expect("write golden hex");
            }

            let expected_hex = fs::read_to_string(&path).expect("read golden hex");
            let expected_bytes = from_hex(&expected_hex).expect("parse golden hex");
            assert_eq!(
                encoded, expected_bytes,
                "golden bytes mismatch for {}",
                case.name
            );
        }
    }

    #[test]
    fn decode_rejects_unsupported_version_deterministically() {
        let src = r#"
            fn main() {
                return;
            }
        "#;

        let mut bytes = parse_and_lower(src).encode();
        let unsupported = HIR_VERSION + 7;
        bytes[8..12].copy_from_slice(&unsupported.to_le_bytes());

        let err =
            types::Program::decode(&bytes).expect_err("decode must reject unsupported version");
        assert_eq!(
            err,
            DecodeError::UnsupportedVersion {
                found: unsupported,
                supported: HIR_VERSION
            }
        );
        assert_eq!(
            err.to_string(),
            format!(
                "unsupported HIR version: {} (supported: {})",
                unsupported, HIR_VERSION
            )
        );
    }

    #[test]
    fn decode_rejects_bad_magic_deterministically() {
        let src = r#"
            fn main() { return; }
        "#;

        let mut bytes = parse_and_lower(src).encode();
        assert_eq!(&bytes[..8], &HIR_MAGIC);
        bytes[0] ^= 0xFF;

        let err = types::Program::decode(&bytes).expect_err("decode must reject bad magic");
        assert_eq!(err, DecodeError::InvalidMagic);
        assert_eq!(err.to_string(), "invalid HIR magic");
    }

    fn parse_and_lower(source: &str) -> types::Program {
        let ast = crate::parser::parse(source).expect("source should parse");
        lower_to_hir(&ast)
    }

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(nibble_to_hex((byte >> 4) & 0x0F));
            out.push(nibble_to_hex(byte & 0x0F));
        }
        out
    }

    fn nibble_to_hex(v: u8) -> char {
        match v {
            0..=9 => (b'0' + v) as char,
            10..=15 => (b'a' + (v - 10)) as char,
            _ => unreachable!("nibble out of range"),
        }
    }

    fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
        let mut filtered = String::with_capacity(hex.len());
        for c in hex.chars() {
            if !c.is_whitespace() {
                filtered.push(c);
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

    fn hex_value(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
}
