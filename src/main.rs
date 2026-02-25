// src/main.rs (crate root)

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::env;
use std::path::PathBuf;

mod ast;
mod checker;
mod codegen;
mod lexer;
mod parser;
mod replay;
mod runtime;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage:");
        eprintln!("  nex run <file.nex>");
        eprintln!("  nex replay <events.bin>");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "run" => cmd_run(&args[2]),
        "replay" => cmd_replay(&args[2]),
        other => {
            eprintln!("Unknown command: {other}");
            std::process::exit(1);
        }
    }
}

fn cmd_run(file: &str) -> Result<()> {
    let src = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read source file: {file}"))?;

    let program = parser::parse(&src).map_err(|e| anyhow::anyhow!(e))?;
    let check = checker::check(&program).map_err(|e| anyhow::anyhow!(e))?;

    println!("✅ CHECK PASSED");
    println!("Declared capabilities: {:?}", check.capabilities);
    println!("Neural models: {:?}", check.neural_models);
    println!("Functions: {:?}", check.functions);

    let build_dir = resolve_build_dir();
    let runtime_out_dir = resolve_out_dir();

    let codegen_hash = sha256_32(b"NEX_CODEGEN_V0_5_7_CANON");
    let source_hash = sha256_32(src.as_bytes());

    codegen::build_project(
        &program,
        &build_dir,
        &runtime_out_dir,
        codegen_hash,
        source_hash,
    )?;

    let bin_path = build_dir.join("target").join("debug").join("nex_out");

    let status = std::process::Command::new(&bin_path)
        .env("NEX_OUT_DIR", runtime_out_dir.to_string_lossy().to_string())
        .status()
        .with_context(|| format!("Failed to execute runner: {}", bin_path.display()))?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

fn cmd_replay(events_bin: &str) -> Result<()> {
    let r = replay::verify_log(events_bin).map_err(|e| anyhow::anyhow!(e))?;

    println!("✅ REPLAY OK");
    println!("events_seen: {}", r.events_seen);
    println!("run_finished_seq: {}", r.run_finished_seq);
    println!("exit_code: {}", r.exit_code);
    println!("run_hash_hex: {}", r.run_hash_hex);
    println!("codegen_hash_hex: {}", r.codegen_hash_hex);
    println!("source_hash_hex: {}", r.source_hash_hex);
    println!("cap_allowed_total: {}", r.cap_allowed_total);
    println!("cap_denied_total: {}", r.cap_denied_total);

    Ok(())
}

fn resolve_build_dir() -> PathBuf {
    if let Ok(v) = env::var("NEX_BUILD_DIR") {
        if !v.trim().is_empty() {
            return PathBuf::from(v);
        }
    }
    PathBuf::from("/tmp/nex_build")
}

fn resolve_out_dir() -> PathBuf {
    if let Ok(v) = env::var("NEX_OUT_DIR") {
        if !v.trim().is_empty() {
            return PathBuf::from(v);
        }
    }
    PathBuf::from("./nex_out")
}

fn sha256_32(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
