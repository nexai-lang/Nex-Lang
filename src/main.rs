// src/main.rs
mod ast;
mod cli;
mod codegen;
mod lexer;
mod parser;
mod checker;

use clap::Parser as _;
use cli::{Cli, Commands};

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { file } => {
            let src = fs::read_to_string(&file)?;
            let (program, parse_errors) = parse_program_with_errors(&src);

            if !parse_errors.is_empty() {
                eprintln!("{}", render_parse_errors(&parse_errors));
            }

            println!("✅ Parsed AST:\n{:#?}", program);

            if !parse_errors.is_empty() {
                return Err(anyhow::anyhow!("❌ Parse had errors (see above)."));
            }
        }

        Commands::Check { file } => {
            let src = fs::read_to_string(&file)?;
            let (program, parse_errors) = parse_program_with_errors(&src);

            let mut failed = false;

            if !parse_errors.is_empty() {
                failed = true;
                eprintln!("{}", render_parse_errors(&parse_errors));
            }

            match checker::check(&program) {
                Ok(info) => {
                    println!("✅ CHECK PASSED");
                    println!("Declared capabilities: {:#?}", info.capabilities);
                    println!("Neural models: {:#?}", info.neural_models);
                    println!("Functions: {:#?}", info.functions);
                }
                Err(e) => {
                    failed = true;
                    eprintln!("❌ Check failed:\n{}", e);
                }
            }

            if failed {
                return Err(anyhow::anyhow!("❌ CHECK FAILED (parse and/or check errors)."));
            }
        }

        Commands::Build { file } => {
            let src = fs::read_to_string(&file)?;
            let (program, parse_errors) = parse_program_with_errors(&src);

            if !parse_errors.is_empty() {
                eprintln!("{}", render_parse_errors(&parse_errors));
                return Err(anyhow::anyhow!("❌ Build aborted: parse errors."));
            }

            checker::check(&program).map_err(|e| anyhow::anyhow!("❌ Check failed: {}", e))?;

            let out_dir = write_generated_cargo_project(&program)?;
            println!("✅ BUILD OK: {}", out_dir.display());
        }

        Commands::Run { file } => {
            let src = fs::read_to_string(&file)?;
            let (program, parse_errors) = parse_program_with_errors(&src);

            if !parse_errors.is_empty() {
                eprintln!("{}", render_parse_errors(&parse_errors));
                return Err(anyhow::anyhow!("❌ Run aborted: parse errors."));
            }

            let info = checker::check(&program).map_err(|e| anyhow::anyhow!("❌ Check failed: {}", e))?;

            println!("✅ CHECK PASSED");
            println!("Declared capabilities: {:#?}", info.capabilities);
            println!("Neural models: {:#?}", info.neural_models);
            println!("Functions: {:#?}", info.functions);

            let out_dir = write_generated_cargo_project(&program)?;
            run_generated_cargo(&out_dir)?;
        }
    }

    Ok(())
}

fn parse_program_with_errors(src: &str) -> (ast::Program, Vec<parser::ParseError>) {
    let lexer = lexer::Lexer::new(src);
    let mut parser = parser::Parser::new(lexer);
    parser.parse_program_recovering()
}

fn render_parse_errors(errors: &[parser::ParseError]) -> String {
    let mut msg = String::new();
    msg.push_str(&format!("❌ Parse reported {} error(s):\n", errors.len()));
    for (i, e) in errors.iter().enumerate() {
        msg.push_str(&format!("\n---- Parse Error {} ----\n", i + 1));
        msg.push_str(&format!("{}", e));
    }
    msg
}

fn write_generated_cargo_project(program: &ast::Program) -> anyhow::Result<PathBuf> {
    let async_mode = has_async_main(program);
    let rust_code = codegen::generate_rust(program, async_mode);

    let out_dir = PathBuf::from("target/nex_out");
    let src_dir = out_dir.join("src");
    fs::create_dir_all(&src_dir)?;

    let cargo_toml = if async_mode {
        r#"[package]
name = "nex_out"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
tokio-util = "0.7"
"#
    } else {
        r#"[package]
name = "nex_out"
version = "0.1.0"
edition = "2021"

[dependencies]
"#
    };

    fs::write(out_dir.join("Cargo.toml"), cargo_toml)?;
    fs::write(src_dir.join("main.rs"), rust_code)?;

    let host_sandbox = PathBuf::from("sandbox_data");
    if host_sandbox.exists() && host_sandbox.is_dir() {
        let dest = out_dir.join("sandbox_data");
        copy_dir_recursive(&host_sandbox, &dest)?;
    }

    Ok(out_dir)
}

fn run_generated_cargo(out_dir: &Path) -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .arg("run")
        .current_dir(out_dir)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if !status.success() {
        return Err(anyhow::anyhow!("❌ generated program failed"));
    }
    Ok(())
}

fn has_async_main(program: &ast::Program) -> bool {
    for item in &program.items {
        if let ast::Item::Function(f) = item {
            if f.name == "main" {
                return f.effects.iter().any(|e| matches!(e, ast::Effect::Async));
            }
        }
    }
    false
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    if dst.exists() {
        fs::remove_dir_all(dst)?;
    }
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if ty.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if ty.is_file() {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
