// src/lexer.rs
use crate::ast::Span;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Keywords
    Fn,
    Cap,
    Neural,
    Let,
    Return,
    If,
    Else,
    Defer,
    Loop,
    Spawn,
    True,
    False,

    // Ident + literals
    Ident(String),
    Int(i64),
    Float(f64),
    Str(String),

    // Punct / operators
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
    Semi,
    Dot,
    Bang,
    Colon,
    Eq,
    Plus,
    Minus,
    Star,
    Slash,

    EqEq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,

    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexToken {
    pub kind: Token,
    pub span: Span,
}

// Allow: if current == Token::Fn, etc.
impl PartialEq<Token> for LexToken {
    fn eq(&self, other: &Token) -> bool {
        &self.kind == other
    }
}

#[derive(Debug, Clone)]
pub struct Lexer<'a> {
    src: &'a str,
    i: usize,
    len: usize,

    // position tracking
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Self {
            src,
            i: 0,
            len: src.len(),
            line: 1,
            col: 1,
        }
    }

    fn peek(&self) -> Option<char> {
        if self.i >= self.len {
            return None;
        }
        self.src[self.i..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.i += ch.len_utf8();

        if ch == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }

    fn starts_with(&self, s: &str) -> bool {
        if self.i >= self.len {
            return false;
        }
        self.src[self.i..].starts_with(s)
    }

    fn current_span(&self) -> Span {
        Span {
            line: self.line,
            col: self.col,
        }
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            while matches!(self.peek(), Some(c) if c.is_whitespace()) {
                self.bump();
            }
            if self.starts_with("//") {
                while let Some(c) = self.bump() {
                    if c == '\n' {
                        break;
                    }
                }
                continue;
            }
            break;
        }
    }

    fn lex_number(&mut self, first: char) -> Token {
        let mut s = String::new();
        s.push(first);

        let mut is_float = false;

        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                s.push(self.bump().unwrap());
                continue;
            }

            // v0.3.3 fix:
            // If we see ".." after an integer, that is a range operator, not a float.
            // Example: 8000..9000 must lex as Int(8000) then Dot then Dot then Int(9000).
            if c == '.' && !is_float {
                if self.starts_with("..") {
                    // Do NOT consume '.' here; leave it for the main token loop to emit Dot, Dot.
                    break;
                }
                // Otherwise it's a normal float dot (e.g., 3.14)
                is_float = true;
                s.push(self.bump().unwrap());
                continue;
            }

            break;
        }

        if is_float {
            Token::Float(s.parse::<f64>().unwrap_or(0.0))
        } else {
            Token::Int(s.parse::<i64>().unwrap_or(0))
        }
    }

    fn lex_ident(&mut self, first: char) -> Token {
        let mut s = String::new();
        s.push(first);

        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                s.push(self.bump().unwrap());
            } else {
                break;
            }
        }

        match s.as_str() {
            "fn" => Token::Fn,
            "cap" => Token::Cap,
            "neural" => Token::Neural,
            "let" => Token::Let,
            "return" => Token::Return,
            "if" => Token::If,
            "else" => Token::Else,
            "defer" => Token::Defer,
            "loop" => Token::Loop,
            "spawn" => Token::Spawn,
            "true" => Token::True,
            "false" => Token::False,
            _ => Token::Ident(s),
        }
    }

    fn lex_string(&mut self) -> Token {
        let mut s = String::new();
        while let Some(c) = self.bump() {
            match c {
                '"' => break,
                '\\' => {
                    if let Some(n) = self.bump() {
                        match n {
                            'n' => s.push('\n'),
                            't' => s.push('\t'),
                            '"' => s.push('"'),
                            '\\' => s.push('\\'),
                            _ => s.push(n),
                        }
                    }
                }
                _ => s.push(c),
            }
        }
        Token::Str(s)
    }

    pub fn next_token(&mut self) -> LexToken {
        self.skip_ws_and_comments();

        let start = self.current_span();

        let ch = match self.bump() {
            Some(c) => c,
            None => {
                return LexToken {
                    kind: Token::Eof,
                    span: start,
                };
            }
        };

        let kind = match ch {
            '(' => Token::LParen,
            ')' => Token::RParen,
            '{' => Token::LBrace,
            '}' => Token::RBrace,
            ',' => Token::Comma,
            ';' => Token::Semi,
            '.' => Token::Dot,
            '!' => {
                if self.starts_with("=") {
                    self.bump();
                    Token::Ne
                } else {
                    Token::Bang
                }
            }
            ':' => Token::Colon,
            '=' => {
                if self.starts_with("=") {
                    self.bump();
                    Token::EqEq
                } else {
                    Token::Eq
                }
            }
            '<' => {
                if self.starts_with("=") {
                    self.bump();
                    Token::Le
                } else {
                    Token::Lt
                }
            }
            '>' => {
                if self.starts_with("=") {
                    self.bump();
                    Token::Ge
                } else {
                    Token::Gt
                }
            }
            '+' => Token::Plus,
            '-' => Token::Minus,
            '*' => Token::Star,
            '/' => Token::Slash,

            '"' => self.lex_string(),

            c if c.is_ascii_digit() => self.lex_number(c),
            c if c.is_ascii_alphabetic() || c == '_' => self.lex_ident(c),

            _ => Token::Eof,
        };

        LexToken { kind, span: start }
    }
}
