// src/parser.rs
use crate::ast::*;
use crate::lexer::{LexToken, Lexer, Token};

#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\nLocation: line {}, col {}\n",
            self.message, self.line, self.col
        )
    }
}

type PResult<T> = Result<T, ParseError>;

pub struct Parser<'a> {
    lexer: Lexer<'a>,
    cur: LexToken,
    errors: Vec<ParseError>,
}

impl<'a> Parser<'a> {
    pub fn new(mut lexer: Lexer<'a>) -> Self {
        let first = lexer.next_token();
        Self {
            lexer,
            cur: first,
            errors: Vec::new(),
        }
    }

    fn bump(&mut self) -> LexToken {
        let prev = self.cur.clone();
        self.cur = self.lexer.next_token();
        prev
    }

    fn at(&self, t: Token) -> bool {
        self.cur == t
    }

    fn span(&self) -> Span {
        self.cur.span
    }

    fn err_here<T>(&self, msg: impl Into<String>) -> PResult<T> {
        let sp = self.span();
        Err(ParseError {
            message: msg.into(),
            line: sp.line,
            col: sp.col,
        })
    }

    fn push_err(&mut self, msg: impl Into<String>, sp: Span) {
        self.errors.push(ParseError {
            message: msg.into(),
            line: sp.line,
            col: sp.col,
        });
    }

    fn expect(&mut self, t: Token) -> PResult<Span> {
        if self.at(t.clone()) {
            let sp = self.span();
            self.bump();
            Ok(sp)
        } else {
            self.err_here(format!("Expected {:?} but got {:?}", t, self.cur.kind))
        }
    }

    fn consume(&mut self, t: Token) -> Option<Span> {
        if self.at(t.clone()) {
            let sp = self.span();
            self.bump();
            Some(sp)
        } else {
            None
        }
    }

    fn expect_ident(&mut self) -> PResult<(String, Span)> {
        match &self.cur.kind {
            Token::Ident(s) => {
                let sp = self.span();
                let out = s.clone();
                self.bump();
                Ok((out, sp))
            }
            _ => self.err_here(format!("Expected Ident but got {:?}", self.cur.kind)),
        }
    }

    fn expect_string(&mut self) -> PResult<(String, Span)> {
        match &self.cur.kind {
            Token::Str(s) => {
                let sp = self.span();
                let out = s.clone();
                self.bump();
                Ok((out, sp))
            }
            _ => self.err_here(format!("Expected string literal but got {:?}", self.cur.kind)),
        }
    }

    fn expect_int(&mut self) -> PResult<(i64, Span)> {
        match &self.cur.kind {
            Token::Int(i) => {
                let sp = self.span();
                let out = *i;
                self.bump();
                Ok((out, sp))
            }
            _ => self.err_here(format!("Expected int literal but got {:?}", self.cur.kind)),
        }
    }

    // ---------------------------
    // Entry
    // ---------------------------
    pub fn parse_program_recovering(&mut self) -> (Program, Vec<ParseError>) {
        let mut items = Vec::new();

        while !self.at(Token::Eof) {
            match self.parse_item() {
                Ok(it) => items.push(it),
                Err(e) => {
                    self.errors.push(e);
                    self.sync_toplevel();
                }
            }
        }

        (Program { items }, std::mem::take(&mut self.errors))
    }

    fn sync_toplevel(&mut self) {
        while !self.at(Token::Eof) {
            if self.at(Token::Fn) || self.at(Token::Cap) || self.at(Token::Neural) {
                return;
            }
            self.bump();
        }
    }

    fn parse_item(&mut self) -> PResult<Item> {
        if self.at(Token::Fn) {
            Ok(Item::Function(self.parse_function()?))
        } else if self.at(Token::Cap) {
            Ok(Item::Capability(self.parse_cap_decl()?))
        } else if self.at(Token::Neural) {
            Ok(Item::Neural(self.parse_neural_decl()?))
        } else {
            self.err_here(format!("Unexpected token at top-level: {:?}", self.cur.kind))
        }
    }

    // cap fs.read("..."); | cap net.listen(8080);
  fn parse_cap_decl(&mut self) -> PResult<CapabilityDecl> {
    self.expect(Token::Cap)?;

    let (a, _) = self.expect_ident()?;
    self.expect(Token::Dot)?;
    let (b, _) = self.expect_ident()?;
    self.expect(Token::LParen)?;

    let cap = match (a.as_str(), b.as_str()) {
        ("fs", "read") => {
            let (glob, _) = self.expect_string()?;
            self.expect(Token::RParen)?;
            self.expect(Token::Semi)?;
            Capability::FsRead { glob }
        }
        ("net", "listen") => {
            let (start, _) = self.expect_int()?;

            // Check if it's a range: 8000..9000
            let range = if self.consume(Token::Dot).is_some() {
                self.expect(Token::Dot)?; // second dot

                let (end, _) = self.expect_int()?;
                NetPortSpec::Range(start, end)
            } else {
                NetPortSpec::Single(start)
            };

            self.expect(Token::RParen)?;
            self.expect(Token::Semi)?;

            Capability::NetListen { range }
        }
        _ => return self.err_here(
            "Unknown capability. Expected fs.read(...) or net.listen(...).",
        ),
    };

    Ok(CapabilityDecl { cap })
}
    // neural name(params): type { format "..."; path "..."; }
    fn parse_neural_decl(&mut self) -> PResult<NeuralDecl> {
        self.expect(Token::Neural)?;
        let (name, _) = self.expect_ident()?;
        self.expect(Token::LParen)?;
        let params = self.parse_params()?;
        self.expect(Token::RParen)?;
        self.expect(Token::Colon)?;
        let return_type = self.parse_type()?;

        self.expect(Token::LBrace)?;

        let (k1, _) = self.expect_ident()?;
        if k1 != "format" {
            return self.err_here("Expected `format \"...\";` in neural block");
        }
        let (format, _) = self.expect_string()?;
        self.expect(Token::Semi)?;

        let (k2, _) = self.expect_ident()?;
        if k2 != "path" {
            return self.err_here("Expected `path \"...\";` in neural block");
        }
        let (path, _) = self.expect_string()?;
        self.expect(Token::Semi)?;

        self.expect(Token::RBrace)?;

        Ok(NeuralDecl {
            name,
            params,
            return_type,
            format,
            path,
        })
    }

    // fn name(params) [: type]? (!io !async ...)* { ... }
    fn parse_function(&mut self) -> PResult<Function> {
        self.expect(Token::Fn)?;
        let (name, name_span) = self.expect_ident()?;

        self.expect(Token::LParen)?;
        let params = self.parse_params()?;
        self.expect(Token::RParen)?;

        let return_type = if self.consume(Token::Colon).is_some() {
            Some(self.parse_type()?)
        } else {
            None
        };

        // ✅ Multi-effects
        let mut effects: Vec<Effect> = Vec::new();
        while self.consume(Token::Bang).is_some() {
            let (eff, sp) = self.expect_ident()?;
            match eff.as_str() {
                "io" => effects.push(Effect::Io),
                "net" => effects.push(Effect::Net),
                "async" => effects.push(Effect::Async),
                "mut" => effects.push(Effect::Mut),
                "pure" => effects.push(Effect::Pure),
                _ => self.push_err(format!("Unknown effect: !{}", eff), sp),
            }
        }

        let body = self.parse_block()?;

        Ok(Function {
            name,
            name_span,
            params,
            return_type,
            effects,
            body,
        })
    }

    fn parse_params(&mut self) -> PResult<Vec<Param>> {
        let mut out = Vec::new();
        if self.at(Token::RParen) {
            return Ok(out);
        }
        loop {
            let (name, _) = self.expect_ident()?;
            self.expect(Token::Colon)?;
            let ty = self.parse_type()?;
            out.push(Param { name, ty });

            if self.consume(Token::Comma).is_some() {
                continue;
            }
            break;
        }
        Ok(out)
    }

    fn parse_type(&mut self) -> PResult<Type> {
        let (s, sp) = self.expect_ident()?;
        match s.as_str() {
            "int" => Ok(Type::I32),
            "float" => Ok(Type::F32),
            "bool" => Ok(Type::Bool),
            "str" => Ok(Type::String),
            "task" => Ok(Type::Task),
            _ => {
                if s == "void" {
                    self.push_err(
                        "V1 has no `void` type. For void functions, omit `: <type>`.".to_string(),
                        sp,
                    );
                }
                Ok(Type::Named(s))
            }
        }
    }

    fn parse_block(&mut self) -> PResult<Block> {
        self.expect(Token::LBrace)?;
        let mut stmts = Vec::new();
        while !self.at(Token::RBrace) && !self.at(Token::Eof) {
            stmts.push(self.parse_stmt()?);
        }
        self.expect(Token::RBrace)?;
        Ok(Block { stmts })
    }

    fn parse_stmt(&mut self) -> PResult<Stmt> {
        if self.at(Token::Let) {
            self.parse_let()
        } else if self.at(Token::Return) {
            self.parse_return()
        } else if self.at(Token::If) {
            self.parse_if_stmt()
        } else if self.at(Token::Loop) {
            self.parse_loop()
        } else if self.at(Token::Defer) {
            self.parse_defer()
        } else {
            let e = self.parse_expr()?;
            self.expect(Token::Semi)?;
            Ok(Stmt::Expr(e))
        }
    }

    fn parse_let(&mut self) -> PResult<Stmt> {
        self.expect(Token::Let)?;
        let (name, _) = self.expect_ident()?;

        let ty = if self.consume(Token::Colon).is_some() {
            Some(self.parse_type()?)
        } else {
            None
        };

        self.expect(Token::Eq)?;
        let value = self.parse_expr()?;
        self.expect(Token::Semi)?;

        Ok(Stmt::Let { name, ty, value })
    }

    fn parse_return(&mut self) -> PResult<Stmt> {
        self.expect(Token::Return)?;
        let e = self.parse_expr()?;
        self.expect(Token::Semi)?;
        Ok(Stmt::Return(Some(e)))
    }

    fn parse_if_stmt(&mut self) -> PResult<Stmt> {
        self.expect(Token::If)?;
        let cond = self.parse_expr()?;
        let then_block = self.parse_block()?;

        let else_block = if self.consume(Token::Else).is_some() {
            Some(self.parse_block()?)
        } else {
            None
        };

        Ok(Stmt::If {
            cond,
            then_block,
            else_block,
        })
    }

    fn parse_loop(&mut self) -> PResult<Stmt> {
        self.expect(Token::Loop)?;
        let b = self.parse_block()?;
        Ok(Stmt::Loop(b))
    }

    fn parse_defer(&mut self) -> PResult<Stmt> {
        self.expect(Token::Defer)?;
        let b = self.parse_block()?;
        Ok(Stmt::Defer(b))
    }

    // ---- Expressions (precedence) ----
    fn parse_expr(&mut self) -> PResult<Expr> {
        self.parse_equality()
    }

    fn parse_equality(&mut self) -> PResult<Expr> {
        let mut e = self.parse_comparison()?;
        loop {
            if self.consume(Token::EqEq).is_some() {
                let r = self.parse_comparison()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Eq,
                    right: Box::new(r),
                };
            } else if self.consume(Token::Ne).is_some() {
                let r = self.parse_comparison()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Ne,
                    right: Box::new(r),
                };
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn parse_comparison(&mut self) -> PResult<Expr> {
        let mut e = self.parse_term()?;
        loop {
            if self.consume(Token::Lt).is_some() {
                let r = self.parse_term()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Lt,
                    right: Box::new(r),
                };
            } else if self.consume(Token::Le).is_some() {
                let r = self.parse_term()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Le,
                    right: Box::new(r),
                };
            } else if self.consume(Token::Gt).is_some() {
                let r = self.parse_term()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Gt,
                    right: Box::new(r),
                };
            } else if self.consume(Token::Ge).is_some() {
                let r = self.parse_term()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Ge,
                    right: Box::new(r),
                };
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn parse_term(&mut self) -> PResult<Expr> {
        let mut e = self.parse_factor()?;
        loop {
            if self.consume(Token::Plus).is_some() {
                let r = self.parse_factor()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Add,
                    right: Box::new(r),
                };
            } else if self.consume(Token::Minus).is_some() {
                let r = self.parse_factor()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Sub,
                    right: Box::new(r),
                };
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn parse_factor(&mut self) -> PResult<Expr> {
        let mut e = self.parse_call()?;
        loop {
            if self.consume(Token::Star).is_some() {
                let r = self.parse_call()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Mul,
                    right: Box::new(r),
                };
            } else if self.consume(Token::Slash).is_some() {
                let r = self.parse_call()?;
                e = Expr::BinaryOp {
                    left: Box::new(e),
                    op: BinOp::Div,
                    right: Box::new(r),
                };
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn parse_call(&mut self) -> PResult<Expr> {
        let start = self.span();
        let base = self.parse_primary()?;

        let mut func_name = match &base {
            Expr::Variable(v) => v.clone(),
            _ => return Ok(base),
        };

        while self.consume(Token::Dot).is_some() {
            let (seg, _) = self.expect_ident()?;
            func_name.push('.');
            func_name.push_str(&seg);
        }

        if self.consume(Token::LParen).is_some() {
            let args = self.parse_args()?;
            self.expect(Token::RParen)?;
            Ok(Expr::Call {
                func: func_name,
                args,
                span: start,
            })
        } else {
            if func_name.contains('.') {
                return self.err_here("Dotted names must be called like fs.read(...);");
            }
            Ok(Expr::Variable(func_name))
        }
    }

    fn parse_args(&mut self) -> PResult<Vec<Expr>> {
        let mut out = Vec::new();
        if self.at(Token::RParen) {
            return Ok(out);
        }
        loop {
            out.push(self.parse_expr()?);
            if self.consume(Token::Comma).is_some() {
                continue;
            }
            break;
        }
        Ok(out)
    }

    fn parse_primary(&mut self) -> PResult<Expr> {
        match &self.cur.kind {
            Token::True => {
                self.bump();
                Ok(Expr::Literal(Literal::Bool(true)))
            }
            Token::False => {
                self.bump();
                Ok(Expr::Literal(Literal::Bool(false)))
            }
            Token::Int(i) => {
                let v = *i;
                self.bump();
                Ok(Expr::Literal(Literal::Int(v)))
            }
            Token::Float(f) => {
                let v = *f;
                self.bump();
                Ok(Expr::Literal(Literal::Float(v)))
            }
            Token::Str(s) => {
                let v = s.clone();
                self.bump();
                Ok(Expr::Literal(Literal::String(v)))
            }
            Token::Ident(_) => {
                let (name, _) = self.expect_ident()?;
                Ok(Expr::Variable(name))
            }
            Token::Spawn => {
                let sp = self.span();
                self.bump();
                let block = self.parse_block()?;
                Ok(Expr::Spawn { block, span: sp })
            }
            Token::If => {
                self.bump();
                let cond = self.parse_expr()?;
                let then_block = self.parse_block()?;
                let else_block = if self.consume(Token::Else).is_some() {
                    Some(self.parse_block()?)
                } else {
                    None
                };
                Ok(Expr::If {
                    cond: Box::new(cond),
                    then_block,
                    else_block,
                })
            }
            Token::LBrace => {
                let b = self.parse_block()?;
                Ok(Expr::Block(b))
            }
            _ => self.err_here(format!("Unexpected token in expression: {:?}", self.cur.kind)),
        }
    }
}
