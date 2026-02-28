// src/main.rs (crate root)

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::env;
use std::path::PathBuf;

mod ast;
mod bundle;
mod checker;
mod codegen;
mod lexer;
mod parser;
mod replay;
mod runtime;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  nex run <file.nex>");
        eprintln!("  nex bundle <events.bin> --out <bundle.nexbundle>");
        eprintln!("  nex replay <events.bin> [--zero-trust]");
        eprintln!("  nex replay --bundle <bundle.nexbundle> [--zero-trust]");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "run" => {
            if args.len() != 3 {
                eprintln!("Usage:");
                eprintln!("  nex run <file.nex>");
                std::process::exit(1);
            }
            cmd_run(&args[2])
        }
        "bundle" => cmd_bundle(&args[2..]),
        "replay" => cmd_replay(&args[2..]),
        other => {
            eprintln!("Unknown command: {other}");
            std::process::exit(1);
        }
    }
}

fn cmd_run(file: &str) -> Result<()> {
    let src_bytes =
        std::fs::read(file).with_context(|| format!("Failed to read source file bytes: {file}"))?;
    let src = String::from_utf8(src_bytes.clone())
        .with_context(|| format!("Source is not valid UTF-8: {file}"))?;

    let program = parser::parse(&src).map_err(|e| anyhow::anyhow!(e))?;
    let check = checker::check(&program).map_err(|e| anyhow::anyhow!(e))?;

    println!("✅ CHECK PASSED");
    println!("Declared capabilities: {:?}", check.capabilities);
    println!("Neural models: {:?}", check.neural_models);
    println!("Functions: {:?}", check.functions);

    let build_dir = resolve_build_dir();
    let runtime_out_dir = resolve_out_dir();
    let agent_id = resolve_agent_id();

    let source_hash = sha256_32(&src_bytes);
    let policy_hash = sha256_32(&policy_snapshot_bytes(&check));
    let codegen_hash = codegen::compute_codegen_hash(&program, source_hash, policy_hash, agent_id);

    codegen::build_project(
        &program,
        &build_dir,
        codegen_hash,
        source_hash,
        policy_hash,
        agent_id,
    )?;

    let bin_path = build_dir.join("target").join("debug").join("nex_out");

    let status = std::process::Command::new(&bin_path)
        .env("NEX_OUT_DIR", runtime_out_dir.to_string_lossy().to_string())
        .env("NEX_AGENT_ID", agent_id.to_string())
        .status()
        .with_context(|| format!("Failed to execute runner: {}", bin_path.display()))?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

fn cmd_bundle(args: &[String]) -> Result<()> {
    let mut events_path: Option<&str> = None;
    let mut out_path: Option<&str> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                let out = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --out"))?;
                out_path = Some(out.as_str());
            }
            v if v.starts_with("--") => {
                return Err(anyhow::anyhow!(format!("unknown bundle option: {}", v)));
            }
            v => {
                if events_path.is_some() {
                    return Err(anyhow::anyhow!(format!(
                        "unexpected extra bundle argument: {}",
                        v
                    )));
                }
                events_path = Some(v);
            }
        }
        i += 1;
    }

    let events_path = events_path.ok_or_else(|| {
        anyhow::anyhow!(
            "missing events path for bundle (usage: nex bundle <events.bin> --out <bundle.nexbundle>)"
        )
    })?;

    let out_path = out_path.ok_or_else(|| {
        anyhow::anyhow!(
            "missing --out path for bundle (usage: nex bundle <events.bin> --out <bundle.nexbundle>)"
        )
    })?;

    bundle::create_bundle(events_path, out_path).map_err(|e| anyhow::anyhow!(e))?;
    println!("✅ BUNDLE OK");
    Ok(())
}

fn cmd_replay(args: &[String]) -> Result<()> {
    let mut events_bin: Option<&str> = None;
    let mut bundle_path: Option<String> = replay_bundle_env_path();
    let mut zero_trust = replay_zero_trust_env_enabled();

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--zero-trust" => zero_trust = true,
            "--bundle" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --bundle"))?;
                bundle_path = Some(value.clone());
            }
            v if v.starts_with("--") => {
                return Err(anyhow::anyhow!(format!("unknown replay option: {}", v)));
            }
            v => {
                if events_bin.is_some() {
                    return Err(anyhow::anyhow!(format!(
                        "unexpected extra replay argument: {}",
                        v
                    )));
                }
                events_bin = Some(v);
            }
        }
        i += 1;
    }

    if events_bin.is_some() && bundle_path.is_some() {
        return Err(anyhow::anyhow!(
            "cannot provide both events path and --bundle for replay"
        ));
    }

    let r = if let Some(bundle_path) = bundle_path {
        bundle::replay_bundle_with_options(bundle_path, replay::ReplayOptions { zero_trust })
            .map_err(|e| anyhow::anyhow!(e))?
    } else {
        let events_bin = events_bin.ok_or_else(|| {
            anyhow::anyhow!(
                "missing replay input (usage: nex replay <events.bin> [--zero-trust] or nex replay --bundle <bundle.nexbundle> [--zero-trust])"
            )
        })?;

        replay::verify_log_with_options(events_bin, replay::ReplayOptions { zero_trust })
            .map_err(|e| anyhow::anyhow!(e))?
    };

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

fn replay_zero_trust_env_enabled() -> bool {
    match env::var("NEX_REPLAY_ZERO_TRUST") {
        Ok(v) => {
            let t = v.trim();
            t == "1"
                || t.eq_ignore_ascii_case("true")
                || t.eq_ignore_ascii_case("yes")
                || t.eq_ignore_ascii_case("on")
        }
        Err(_) => false,
    }
}

fn replay_bundle_env_path() -> Option<String> {
    match env::var("NEX_REPLAY_BUNDLE") {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
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

fn resolve_agent_id() -> u32 {
    match env::var("NEX_AGENT_ID") {
        Ok(v) => v.trim().parse::<u32>().unwrap_or(0),
        Err(_) => 0,
    }
}

fn policy_snapshot_bytes(check: &checker::CheckResult) -> Vec<u8> {
    let mut caps = check
        .capabilities
        .iter()
        .map(capability_to_canonical)
        .collect::<Vec<_>>();
    caps.sort();

    let mut out = String::new();
    out.push_str("{\"capabilities\":[");
    for (idx, cap) in caps.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&escape_json(cap));
        out.push('"');
    }

    out.push_str(
        "],\"io\":{\"default_capabilities\":[\"fs.read\",\"fs.write\",\"net.connect\",\"net.send\",\"net.recv\"],\"fuel_remaining\":\"18446744073709551615\",\"fuel_base_cost\":1,\"fuel_per_byte_cost\":0,\"max_io_bytes\":\"18446744073709551615\"}",
    );

    out.push_str(&format!(
        ",\"bus\":{{\"allow_send\":true,\"allow_recv\":true,\"max_msg_bytes\":{},\"max_queue_per_receiver\":{},\"fuel_remaining\":\"18446744073709551615\",\"base_send_cost\":{},\"per_byte_cost\":{}}}",
        runtime::agent_bus::DEFAULT_MAX_MSG_BYTES,
        runtime::agent_bus::DEFAULT_MAX_QUEUE_PER_RECEIVER,
        runtime::agent_bus::DEFAULT_BASE_SEND_COST,
        runtime::agent_bus::DEFAULT_PER_BYTE_COST
    ));

    out.push_str(&format!(
        ",\"spawn\":{{\"coop_scheduler\":{},\"mode\":\"{}\"}}",
        if cfg!(feature = "coop_scheduler") {
            "true"
        } else {
            "false"
        },
        if cfg!(feature = "coop_scheduler") {
            "coop"
        } else {
            "threaded"
        }
    ));

    out.push('}');
    out.into_bytes()
}

fn capability_to_canonical(cap: &ast::Capability) -> String {
    match cap {
        ast::Capability::FsRead { glob } => format!("fs.read:{}", glob),
        ast::Capability::NetListen { range } => match range {
            ast::NetPortSpec::Single(v) => format!("net.listen:{}", v),
            ast::NetPortSpec::Range(a, b) => format!("net.listen:{}-{}", a, b),
        },
    }
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn sha256_32(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
