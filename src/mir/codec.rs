use std::fmt;

use super::types;
use super::MIR_VERSION_V1;

pub const MIR_MAGIC: [u8; 4] = *b"NEXM";

const MAX_COLLECTION_LEN: usize = 1_000_000;
const MAX_STRING_LEN: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEof {
        offset: usize,
        needed: usize,
        remaining: usize,
    },
    InvalidMagic,
    UnsupportedVersion {
        found: u16,
        supported: u16,
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
    LengthLimitExceeded {
        context: &'static str,
        value: u64,
        limit: usize,
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
            DecodeError::InvalidMagic => write!(f, "invalid MIR magic"),
            DecodeError::UnsupportedVersion { found, supported } => write!(
                f,
                "unsupported MIR version: {} (supported: {})",
                found, supported
            ),
            DecodeError::InvalidTag { context, tag } => {
                write!(f, "invalid tag for {}: {}", context, tag)
            }
            DecodeError::InvalidUtf8 { context } => write!(f, "invalid utf-8 in {}", context),
            DecodeError::LengthOverflow { context, value } => {
                write!(f, "length overflow in {}: {}", context, value)
            }
            DecodeError::LengthLimitExceeded {
                context,
                value,
                limit,
            } => write!(
                f,
                "length exceeds limit in {}: {} (limit: {})",
                context, value, limit
            ),
            DecodeError::TrailingBytes { offset, remaining } => write!(
                f,
                "trailing bytes after MIR payload at offset {}: {}",
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
        out.extend_from_slice(&MIR_MAGIC);
        write_u16(&mut out, MIR_VERSION_V1);
        encode_program_payload(self, &mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);

        let magic = reader.read_fixed::<4>()?;
        if magic != MIR_MAGIC {
            return Err(DecodeError::InvalidMagic);
        }

        let version = reader.read_u16()?;
        if version != MIR_VERSION_V1 {
            return Err(DecodeError::UnsupportedVersion {
                found: version,
                supported: MIR_VERSION_V1,
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
    write_len(dst, program.functions.len());
    for function in &program.functions {
        encode_function(function, dst);
    }

    match program.entry {
        Some(entry) => {
            write_u8(dst, 1);
            write_u32(dst, entry);
        }
        None => write_u8(dst, 0),
    }
}

fn decode_program_payload(reader: &mut Reader<'_>) -> Result<types::Program, DecodeError> {
    let functions_len = reader.read_len("program.functions", MAX_COLLECTION_LEN)?;
    let mut functions = Vec::with_capacity(functions_len);
    for _ in 0..functions_len {
        functions.push(decode_function(reader)?);
    }

    let entry = match reader.read_u8()? {
        0 => None,
        1 => Some(reader.read_u32()?),
        tag => {
            return Err(DecodeError::InvalidTag {
                context: "program.entry",
                tag,
            });
        }
    };

    Ok(types::Program { functions, entry })
}

fn encode_function(function: &types::Function, dst: &mut Vec<u8>) {
    write_u32(dst, function.id);
    write_string(dst, &function.name);

    write_len(dst, function.blocks.len());
    for block in &function.blocks {
        encode_block(block, dst);
    }
}

fn decode_function(reader: &mut Reader<'_>) -> Result<types::Function, DecodeError> {
    let id = reader.read_u32()?;
    let name = reader.read_string("function.name")?;

    let blocks_len = reader.read_len("function.blocks", MAX_COLLECTION_LEN)?;
    let mut blocks = Vec::with_capacity(blocks_len);
    for _ in 0..blocks_len {
        blocks.push(decode_block(reader)?);
    }

    Ok(types::Function { id, name, blocks })
}

fn encode_block(block: &types::Block, dst: &mut Vec<u8>) {
    write_u32(dst, block.id);
    write_len(dst, block.stmts.len());
    for stmt in &block.stmts {
        encode_stmt(stmt, dst);
    }
    encode_term(&block.terminator, dst);
}

fn decode_block(reader: &mut Reader<'_>) -> Result<types::Block, DecodeError> {
    let id = reader.read_u32()?;

    let stmts_len = reader.read_len("block.stmts", MAX_COLLECTION_LEN)?;
    let mut stmts = Vec::with_capacity(stmts_len);
    for _ in 0..stmts_len {
        stmts.push(decode_stmt(reader)?);
    }

    let terminator = decode_term(reader)?;

    Ok(types::Block {
        id,
        stmts,
        terminator,
    })
}

fn encode_stmt(stmt: &types::Stmt, dst: &mut Vec<u8>) {
    match stmt {
        types::Stmt::Let { name, value } => {
            write_u8(dst, 1);
            write_string(dst, name);
            encode_expr(value, dst);
        }
        types::Stmt::Assign { name, value } => {
            write_u8(dst, 2);
            write_string(dst, name);
            encode_expr(value, dst);
        }
        types::Stmt::Call { dest, func, args } => {
            write_u8(dst, 3);
            encode_optional_string(dest, dst);
            write_string(dst, func);
            encode_args(args, dst);
        }
        types::Stmt::Send { dest, func, args } => {
            write_u8(dst, 4);
            encode_optional_string(dest, dst);
            write_string(dst, func);
            encode_args(args, dst);
        }
        types::Stmt::Recv { dest, func, args } => {
            write_u8(dst, 5);
            encode_optional_string(dest, dst);
            write_string(dst, func);
            encode_args(args, dst);
        }
        types::Stmt::IoRead { dest, func, args } => {
            write_u8(dst, 6);
            encode_optional_string(dest, dst);
            write_string(dst, func);
            encode_args(args, dst);
        }
        types::Stmt::IoWrite { dest, func, args } => {
            write_u8(dst, 7);
            encode_optional_string(dest, dst);
            write_string(dst, func);
            encode_args(args, dst);
        }
    }
}

fn decode_stmt(reader: &mut Reader<'_>) -> Result<types::Stmt, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::Stmt::Let {
            name: reader.read_string("stmt.let.name")?,
            value: decode_expr(reader)?,
        }),
        2 => Ok(types::Stmt::Assign {
            name: reader.read_string("stmt.assign.name")?,
            value: decode_expr(reader)?,
        }),
        3 => Ok(types::Stmt::Call {
            dest: decode_optional_string(reader, "stmt.call.dest")?,
            func: reader.read_string("stmt.call.func")?,
            args: decode_args(reader, "stmt.call.args")?,
        }),
        4 => Ok(types::Stmt::Send {
            dest: decode_optional_string(reader, "stmt.send.dest")?,
            func: reader.read_string("stmt.send.func")?,
            args: decode_args(reader, "stmt.send.args")?,
        }),
        5 => Ok(types::Stmt::Recv {
            dest: decode_optional_string(reader, "stmt.recv.dest")?,
            func: reader.read_string("stmt.recv.func")?,
            args: decode_args(reader, "stmt.recv.args")?,
        }),
        6 => Ok(types::Stmt::IoRead {
            dest: decode_optional_string(reader, "stmt.ioread.dest")?,
            func: reader.read_string("stmt.ioread.func")?,
            args: decode_args(reader, "stmt.ioread.args")?,
        }),
        7 => Ok(types::Stmt::IoWrite {
            dest: decode_optional_string(reader, "stmt.iowrite.dest")?,
            func: reader.read_string("stmt.iowrite.func")?,
            args: decode_args(reader, "stmt.iowrite.args")?,
        }),
        _ => Err(DecodeError::InvalidTag {
            context: "stmt",
            tag,
        }),
    }
}

fn encode_term(term: &types::Term, dst: &mut Vec<u8>) {
    match term {
        types::Term::Return(value) => {
            write_u8(dst, 1);
            match value {
                Some(v) => {
                    write_u8(dst, 1);
                    encode_expr(v, dst);
                }
                None => write_u8(dst, 0),
            }
        }
        types::Term::Jump(block_id) => {
            write_u8(dst, 2);
            write_u32(dst, *block_id);
        }
        types::Term::Branch {
            cond,
            then_block,
            else_block,
        } => {
            write_u8(dst, 3);
            encode_expr(cond, dst);
            write_u32(dst, *then_block);
            write_u32(dst, *else_block);
        }
    }
}

fn decode_term(reader: &mut Reader<'_>) -> Result<types::Term, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => {
            let value = match reader.read_u8()? {
                0 => None,
                1 => Some(decode_expr(reader)?),
                bad => {
                    return Err(DecodeError::InvalidTag {
                        context: "term.return.value",
                        tag: bad,
                    });
                }
            };
            Ok(types::Term::Return(value))
        }
        2 => Ok(types::Term::Jump(reader.read_u32()?)),
        3 => Ok(types::Term::Branch {
            cond: decode_expr(reader)?,
            then_block: reader.read_u32()?,
            else_block: reader.read_u32()?,
        }),
        _ => Err(DecodeError::InvalidTag {
            context: "term",
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
        types::Expr::BinaryOp { left, op, right } => {
            write_u8(dst, 3);
            encode_expr(left, dst);
            encode_bin_op(*op, dst);
            encode_expr(right, dst);
        }
    }
}

fn decode_expr(reader: &mut Reader<'_>) -> Result<types::Expr, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::Expr::Literal(decode_literal(reader)?)),
        2 => Ok(types::Expr::Variable(reader.read_string("expr.variable")?)),
        3 => Ok(types::Expr::BinaryOp {
            left: Box::new(decode_expr(reader)?),
            op: decode_bin_op(reader)?,
            right: Box::new(decode_expr(reader)?),
        }),
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
        types::Literal::FloatBits(v) => {
            write_u8(dst, 2);
            write_u64(dst, *v);
        }
        types::Literal::Bool(v) => {
            write_u8(dst, 3);
            write_u8(dst, if *v { 1 } else { 0 });
        }
        types::Literal::String(v) => {
            write_u8(dst, 4);
            write_string(dst, v);
        }
        types::Literal::Unit => {
            write_u8(dst, 5);
        }
    }
}

fn decode_literal(reader: &mut Reader<'_>) -> Result<types::Literal, DecodeError> {
    let tag = reader.read_u8()?;
    match tag {
        1 => Ok(types::Literal::Int(reader.read_i64()?)),
        2 => Ok(types::Literal::FloatBits(reader.read_u64()?)),
        3 => match reader.read_u8()? {
            0 => Ok(types::Literal::Bool(false)),
            1 => Ok(types::Literal::Bool(true)),
            bad => Err(DecodeError::InvalidTag {
                context: "literal.bool",
                tag: bad,
            }),
        },
        4 => Ok(types::Literal::String(
            reader.read_string("literal.string")?,
        )),
        5 => Ok(types::Literal::Unit),
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

fn encode_args(args: &[types::Expr], dst: &mut Vec<u8>) {
    write_len(dst, args.len());
    for arg in args {
        encode_expr(arg, dst);
    }
}

fn decode_args(
    reader: &mut Reader<'_>,
    context: &'static str,
) -> Result<Vec<types::Expr>, DecodeError> {
    let len = reader.read_len(context, MAX_COLLECTION_LEN)?;
    let mut args = Vec::with_capacity(len);
    for _ in 0..len {
        args.push(decode_expr(reader)?);
    }
    Ok(args)
}

fn encode_optional_string(value: &Option<String>, dst: &mut Vec<u8>) {
    match value {
        Some(v) => {
            write_u8(dst, 1);
            write_string(dst, v);
        }
        None => write_u8(dst, 0),
    }
}

fn decode_optional_string(
    reader: &mut Reader<'_>,
    context: &'static str,
) -> Result<Option<String>, DecodeError> {
    match reader.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(reader.read_string(context)?)),
        tag => Err(DecodeError::InvalidTag { context, tag }),
    }
}

fn write_u8(dst: &mut Vec<u8>, value: u8) {
    dst.push(value);
}

fn write_u16(dst: &mut Vec<u8>, value: u16) {
    dst.extend_from_slice(&value.to_le_bytes());
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

fn write_len(dst: &mut Vec<u8>, len: usize) {
    write_u64(dst, len as u64);
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

    fn read_u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.read_fixed::<2>()?))
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

    fn read_len(&mut self, context: &'static str, limit: usize) -> Result<usize, DecodeError> {
        let raw = self.read_u64()?;
        let len = usize::try_from(raw).map_err(|_| DecodeError::LengthOverflow {
            context,
            value: raw,
        })?;

        if len > limit {
            return Err(DecodeError::LengthLimitExceeded {
                context,
                value: raw,
                limit,
            });
        }

        Ok(len)
    }

    fn read_string(&mut self, context: &'static str) -> Result<String, DecodeError> {
        let len = self.read_len(context, MAX_STRING_LEN)?;
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

    use super::{DecodeError, MIR_MAGIC};
    use crate::hir::lower::lower_to_hir;
    use crate::mir::lower::lower_to_mir;
    use crate::mir::types;
    use crate::mir::MIR_VERSION_V1;

    struct GoldenCase {
        name: &'static str,
        source: &'static str,
        golden_relpath: &'static str,
    }

    const GOLDEN_CASES: &[GoldenCase] = &[
        GoldenCase {
            name: "simple_call_flow",
            source: r#"
                fn helper(v: int): int {
                    return v;
                }

                fn main() {
                    let x: int = helper(7);
                    return;
                }
            "#,
            golden_relpath: "src/mir/golden/simple_call_flow.mir.hex",
        },
        GoldenCase {
            name: "if_branch_send_recv",
            source: r#"
                fn main() !io {
                    if true {
                        bus.send("chan", 1);
                    } else {
                        bus.recv("chan");
                    }
                    return;
                }
            "#,
            golden_relpath: "src/mir/golden/if_branch_send_recv.mir.hex",
        },
        GoldenCase {
            name: "spawn_and_net_io",
            source: r#"
                fn main() !async {
                    spawn {
                        net.send("127.0.0.1:9", "ping");
                        return;
                    };
                    net.recv("127.0.0.1:9");
                    return;
                }
            "#,
            golden_relpath: "src/mir/golden/spawn_and_net_io.mir.hex",
        },
    ];

    #[test]
    fn mir_encode_decode_roundtrip_bytes_equal() {
        let src = r#"
            fn helper(v: int): int {
                return v;
            }

            fn main() {
                let x: int = helper(7);
                if x == 7 {
                    return;
                } else {
                    return;
                }
            }
        "#;

        let mir = parse_and_lower(source_trim(src));
        let encoded = mir.encode();
        let decoded = types::Program::decode(&encoded).expect("decode should succeed");
        let reencoded = decoded.encode();

        assert_eq!(encoded, reencoded);
    }

    #[test]
    fn golden_mir_bytes_match_exactly() {
        let update = std::env::var("NEX_UPDATE_MIR_GOLDEN")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false);

        for case in GOLDEN_CASES {
            let encoded = parse_and_lower(source_trim(case.source)).encode();
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
    fn mir_decode_rejects_unsupported_version() {
        let src = r#"
            fn main() {
                return;
            }
        "#;

        let mut bytes = parse_and_lower(source_trim(src)).encode();
        assert_eq!(&bytes[..4], &MIR_MAGIC);

        let unsupported = MIR_VERSION_V1.wrapping_add(7);
        bytes[4..6].copy_from_slice(&unsupported.to_le_bytes());

        let err =
            types::Program::decode(&bytes).expect_err("decode must reject unsupported version");
        assert_eq!(
            err,
            DecodeError::UnsupportedVersion {
                found: unsupported,
                supported: MIR_VERSION_V1,
            }
        );
        assert_eq!(
            err.to_string(),
            format!(
                "unsupported MIR version: {} (supported: {})",
                unsupported, MIR_VERSION_V1
            )
        );
    }

    #[test]
    fn mir_decode_is_fail_closed_on_malformed_length() {
        let src = r#"
            fn main() {
                return;
            }
        "#;

        let mut bytes = parse_and_lower(source_trim(src)).encode();
        bytes[6..14].copy_from_slice(&u64::MAX.to_le_bytes());

        let err =
            types::Program::decode(&bytes).expect_err("decode must fail closed on bad lengths");
        assert_eq!(
            err,
            DecodeError::LengthLimitExceeded {
                context: "program.functions",
                value: u64::MAX,
                limit: 1_000_000,
            }
        );
    }

    fn parse_and_lower(source: &str) -> types::Program {
        let ast = crate::parser::parse(source).expect("source should parse");
        let hir = lower_to_hir(&ast);
        lower_to_mir(&hir)
    }

    fn source_trim(source: &str) -> &str {
        source
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
