// src/main.rs (crate root)

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};

mod ast;
mod bundle;
mod checker;
mod codegen;
mod hir;
mod lexer;
mod parser;
mod replay;
mod runtime;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  nex run <file.nex>");
        eprintln!("  nex run --strict-determinism <file.nex>");
        eprintln!(
            "  nex run --strict-governance-policy [--max-static-cost <u64>] [--recursion-limit <u32>] [--require-loop-fuel-checks|--allow-unbounded-loops] [--deny-deadlock-risk|--allow-deadlock-risk] <file.nex>"
        );
        eprintln!("  nex bundle <events.bin> --out <bundle.nexbundle>");
        eprintln!("  nex replay <events.bin> [--zero-trust]");
        eprintln!("  nex replay --bundle <bundle.nexbundle> [--zero-trust]");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "run" => cmd_run_cli(&args[2..]),
        "bundle" => cmd_bundle(&args[2..]),
        "replay" => cmd_replay(&args[2..]),
        other => {
            eprintln!("Unknown command: {other}");
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RunOptions<'a> {
    file: &'a str,
    strict_determinism: bool,
    strict_governance_policy: bool,
    max_static_cost: Option<u64>,
    require_loop_fuel_checks: Option<bool>,
    recursion_limit: Option<u32>,
    deny_deadlock_risk: Option<bool>,
}

fn cmd_run_cli(args: &[String]) -> Result<()> {
    let mut file: Option<&str> = None;
    let mut strict_determinism = false;
    let mut strict_governance_policy = false;
    let mut max_static_cost: Option<u64> = None;
    let mut require_loop_fuel_checks: Option<bool> = None;
    let mut recursion_limit: Option<u32> = None;
    let mut deny_deadlock_risk: Option<bool> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--strict-determinism" => strict_determinism = true,
            "--strict-governance-policy" => strict_governance_policy = true,
            "--require-loop-fuel-checks" => {
                strict_governance_policy = true;
                require_loop_fuel_checks = Some(true);
            }
            "--allow-unbounded-loops" => {
                strict_governance_policy = true;
                require_loop_fuel_checks = Some(false);
            }
            "--deny-deadlock-risk" => {
                strict_governance_policy = true;
                deny_deadlock_risk = Some(true);
            }
            "--allow-deadlock-risk" => {
                strict_governance_policy = true;
                deny_deadlock_risk = Some(false);
            }
            "--max-static-cost" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --max-static-cost"))?;
                let parsed = raw.parse::<u64>().map_err(|_| {
                    anyhow::anyhow!(format!("invalid --max-static-cost value: {}", raw))
                })?;
                strict_governance_policy = true;
                max_static_cost = Some(parsed);
            }
            "--recursion-limit" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("missing value for --recursion-limit"))?;
                let parsed = raw.parse::<u32>().map_err(|_| {
                    anyhow::anyhow!(format!("invalid --recursion-limit value: {}", raw))
                })?;
                strict_governance_policy = true;
                recursion_limit = Some(parsed);
            }
            value if value.starts_with("--") => {
                return Err(anyhow::anyhow!(format!("unknown run option: {}", value)));
            }
            value => {
                if file.is_some() {
                    return Err(anyhow::anyhow!(format!(
                        "unexpected extra run argument: {}",
                        value
                    )));
                }
                file = Some(value);
            }
        }
        i += 1;
    }

    let options = RunOptions {
        file: file.ok_or_else(|| {
            anyhow::anyhow!(
                "missing source file for run (usage: nex run [--strict-determinism] [--strict-governance-policy] [--max-static-cost <u64>] [--recursion-limit <u32>] [--require-loop-fuel-checks|--allow-unbounded-loops] [--deny-deadlock-risk|--allow-deadlock-risk] <file.nex>)"
            )
        })?,
        strict_determinism,
        strict_governance_policy,
        max_static_cost,
        require_loop_fuel_checks,
        recursion_limit,
        deny_deadlock_risk,
    };

    cmd_run(options)
}

fn cmd_run(options: RunOptions<'_>) -> Result<()> {
    let src_bytes = std::fs::read(options.file)
        .with_context(|| format!("Failed to read source file bytes: {}", options.file))?;
    let src = String::from_utf8(src_bytes.clone())
        .with_context(|| format!("Source is not valid UTF-8: {}", options.file))?;

    let program = parser::parse(&src).map_err(|e| anyhow::anyhow!(e))?;
    let hir_program = hir::lower_to_hir(&program);
    let check = checker::check(&program).map_err(|e| anyhow::anyhow!(e))?;

    if options.strict_determinism {
        hir::analysis::determinism::enforce_strict_mode(&hir_program)
            .map_err(|e| anyhow::anyhow!(e))?;
    }

    let capability_report = hir::analysis::capability_flow::analyze(&hir_program);
    hir::analysis::capability_flow::enforce_declared_capabilities(&hir_program, &capability_report)
        .map_err(|e| anyhow::anyhow!(e))?;

    let schema_report = hir::analysis::schema_validation::analyze(&hir_program);
    hir::analysis::schema_validation::enforce(&schema_report).map_err(|e| anyhow::anyhow!(e))?;

    let governancefacts_bytes =
        hir::analysis::governancefacts::encode_from_reports(&capability_report, &schema_report);

    let cost_report = hir::analysis::cost_model::analyze(&hir_program);
    let deadlock_report = hir::analysis::deadlock_risk::analyze(&hir_program);

    for warning in &deadlock_report.warnings {
        eprintln!("warning: {}", warning);
    }

    if options.strict_governance_policy {
        let mut policy = hir::analysis::cost_model::CostPolicyConfig::default();
        if let Some(max_static_cost) = options.max_static_cost {
            policy.max_static_cost = max_static_cost;
        }
        if let Some(require_loop_fuel_checks) = options.require_loop_fuel_checks {
            policy.require_loop_fuel_checks = require_loop_fuel_checks;
        }
        if let Some(recursion_limit) = options.recursion_limit {
            policy.recursion_limit = recursion_limit;
        }

        hir::analysis::cost_model::enforce_policy(&cost_report, policy)
            .map_err(|e| anyhow::anyhow!(e))?;

        let deadlock_policy = hir::analysis::deadlock_risk::DeadlockRiskPolicy {
            deny_risk: options.deny_deadlock_risk.unwrap_or(true),
        };

        hir::analysis::deadlock_risk::enforce_policy(&deadlock_report, deadlock_policy)
            .map_err(|e| anyhow::anyhow!(e))?;
    }

    let costfacts_bytes = hir::analysis::cost_model::encode(&cost_report);

    println!("✅ CHECK PASSED");
    println!("Declared capabilities: {:?}", check.capabilities);
    println!("Neural models: {:?}", check.neural_models);
    println!("Functions: {:?}", check.functions);

    let build_dir = resolve_build_dir();
    let runtime_out_dir = resolve_out_dir();
    let agent_id = resolve_agent_id();

    emit_governancefacts_artifact(&runtime_out_dir, &governancefacts_bytes)?;
    emit_costfacts_artifact(&runtime_out_dir, &costfacts_bytes)?;

    let source_hash = sha256_32(&src_bytes);
    let policy_hash = sha256_32(&policy_snapshot_bytes(&check, &governancefacts_bytes));
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

fn emit_governancefacts_artifact(out_dir: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("Failed to create output dir: {}", out_dir.display()))?;

    let path = out_dir.join("governancefacts.bin");
    std::fs::write(&path, bytes).with_context(|| {
        format!(
            "Failed to write governancefacts artifact: {}",
            path.display()
        )
    })
}

fn emit_costfacts_artifact(out_dir: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("Failed to create output dir: {}", out_dir.display()))?;

    let path = out_dir.join("costfacts.bin");
    std::fs::write(&path, bytes)
        .with_context(|| format!("Failed to write costfacts artifact: {}", path.display()))
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

fn policy_snapshot_bytes(check: &checker::CheckResult, governancefacts_bytes: &[u8]) -> Vec<u8> {
    let mut caps = check
        .capabilities
        .iter()
        .map(capability_to_canonical)
        .collect::<Vec<_>>();
    caps.sort();

    let governancefacts_hash = sha256_32(governancefacts_bytes);

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

    out.push_str(&format!(
        ",\"ir\":{{\"hir_version\":{},\"mir_version\":{}}}",
        hir::HIR_VERSION,
        hir::MIR_VERSION
    ));

    out.push_str(&format!(
        ",\"governancefacts\":{{\"sha256\":\"{}\",\"bytes\":{}}}",
        hex_lower(&governancefacts_hash),
        governancefacts_bytes.len()
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

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_nibble((byte >> 4) & 0x0f));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

fn hex_nibble(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!("nibble out of range"),
    }
}

#[cfg(test)]
mod tests {
    use super::{hex_lower, policy_snapshot_bytes, sha256_32};
    use crate::checker;

    #[test]
    fn policy_snapshot_includes_governancefacts_hash_and_ir_versions() {
        let check = empty_check_result();
        let governancefacts = b"governancefacts-v0.9.5";

        let snapshot = policy_snapshot_bytes(&check, governancefacts);
        let text = String::from_utf8(snapshot).expect("policy snapshot should be utf8");

        assert!(text.contains("\"hir_version\":1"));
        assert!(text.contains("\"mir_version\":0"));

        let expected_hash = hex_lower(&sha256_32(governancefacts));
        assert!(
            text.contains(&format!("\"sha256\":\"{}\"", expected_hash)),
            "governancefacts hash must be embedded in policy snapshot"
        );
    }

    #[test]
    fn policy_snapshot_hash_changes_when_governancefacts_change() {
        let check = empty_check_result();

        let hash_a = sha256_32(&policy_snapshot_bytes(&check, b"governancefacts-a"));
        let hash_b = sha256_32(&policy_snapshot_bytes(&check, b"governancefacts-b"));

        assert_ne!(hash_a, hash_b);
    }

    fn empty_check_result() -> checker::CheckResult {
        checker::CheckResult {
            capabilities: Vec::new(),
            neural_models: Vec::new(),
            functions: vec!["main".to_string()],
        }
    }
}
