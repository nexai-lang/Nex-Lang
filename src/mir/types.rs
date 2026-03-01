#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub functions: Vec<Function>,
    pub entry: Option<FnId>,
}

pub type FnId = u32;
pub type BlockId = u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub id: FnId,
    pub name: String,
    pub blocks: Vec<Block>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub id: BlockId,
    pub stmts: Vec<Stmt>,
    pub terminator: Term,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    Let {
        name: String,
        value: Expr,
    },
    Assign {
        name: String,
        value: Expr,
    },
    Call {
        dest: Option<String>,
        func: String,
        args: Vec<Expr>,
    },
    Send {
        dest: Option<String>,
        func: String,
        args: Vec<Expr>,
    },
    Recv {
        dest: Option<String>,
        func: String,
        args: Vec<Expr>,
    },
    IoRead {
        dest: Option<String>,
        func: String,
        args: Vec<Expr>,
    },
    IoWrite {
        dest: Option<String>,
        func: String,
        args: Vec<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Return(Option<Expr>),
    Jump(BlockId),
    Branch {
        cond: Expr,
        then_block: BlockId,
        else_block: BlockId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Literal(Literal),
    Variable(String),
    BinaryOp {
        left: Box<Expr>,
        op: BinOp,
        right: Box<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    Int(i64),
    FloatBits(u64),
    Bool(bool),
    String(String),
    Unit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
