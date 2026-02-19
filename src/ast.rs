// src/ast.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

pub type Ident = String;

#[derive(Debug, Clone)]
pub struct Program {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone)]
pub enum Item {
    Function(Function),
    Capability(CapabilityDecl),
    Neural(NeuralDecl),
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub name_span: Span,
    pub params: Vec<Param>,
    pub return_type: Option<Type>,
    pub effects: Vec<Effect>,
    pub body: Block,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub ty: Type,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub stmts: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Let {
        name: String,
        ty: Option<Type>, // ✅ Step 40 used by parser now
        value: Expr,
    },
    Return(Expr),
    Expr(Expr),
    If {
        cond: Expr,
        then_block: Block,
        else_block: Option<Block>,
    },
    Loop(Block),
    Defer(Block),
}

#[derive(Debug, Clone)]
pub enum Expr {
    Literal(Literal),
    Variable(String),

    Call {
        func: String,
        args: Vec<Expr>,
        span: Span,
    },

    BinaryOp {
        left: Box<Expr>,
        op: BinOp,
        right: Box<Expr>,
    },

    If {
        cond: Box<Expr>,
        then_block: Block,
        else_block: Option<Block>,
    },

    Block(Block),

    Spawn {
        block: Block,
        span: Span,
    },
}

#[derive(Debug, Clone)]
pub enum Literal {
    Int(i64),
    Float(f64),
    Bool(bool),
    String(String),
}

#[derive(Debug, Clone, Copy)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    Pure,
    Io,
    Net,
    Async,
    Mut,
}

#[derive(Debug, Clone)]
pub struct CapabilityDecl {
    pub cap: Capability,
}

#[derive(Debug, Clone)]
pub enum Capability {
    FsRead { glob: String },
    NetListen { port: i64 },
}

#[derive(Debug, Clone)]
pub struct NeuralDecl {
    pub name: String,
    pub params: Vec<Param>,
    pub return_type: Type,
    pub format: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    I32,
    F32,
    Bool,
    String,
    Task,          // ✅ Step 40: real task type
    Named(String), // keep for future
}
