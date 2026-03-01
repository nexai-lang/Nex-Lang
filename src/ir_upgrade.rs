use std::fmt;

use crate::{hir, mir};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrKind {
    Hir,
    Mir,
}

impl IrKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IrKind::Hir => "hir",
            IrKind::Mir => "mir",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeResult {
    pub kind: IrKind,
    pub from_version: u32,
    pub to_version: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeError {
    UnexpectedEof {
        context: &'static str,
        needed: usize,
        remaining: usize,
    },
    InvalidMagic {
        expected: Option<IrKind>,
    },
    UnsupportedVersion {
        kind: IrKind,
        found: u32,
        min_supported: u32,
        max_supported: u32,
    },
    DecodeFailed {
        kind: IrKind,
        detail: String,
    },
}

impl fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpgradeError::UnexpectedEof {
                context,
                needed,
                remaining,
            } => write!(
                f,
                "unexpected eof while reading {}: need {} bytes, have {}",
                context, needed, remaining
            ),
            UpgradeError::InvalidMagic { expected } => match expected {
                Some(kind) => write!(f, "invalid {} magic", kind.as_str().to_uppercase()),
                None => write!(f, "invalid IR magic (expected HIR or MIR)"),
            },
            UpgradeError::UnsupportedVersion {
                kind,
                found,
                min_supported,
                max_supported,
            } => write!(
                f,
                "unsupported {} version: {} (supported: {}..={})",
                kind.as_str().to_uppercase(),
                found,
                min_supported,
                max_supported
            ),
            UpgradeError::DecodeFailed { kind, detail } => write!(
                f,
                "{} decode failed during upgrade: {}",
                kind.as_str().to_uppercase(),
                detail
            ),
        }
    }
}

impl std::error::Error for UpgradeError {}

pub fn supported_range(kind: IrKind) -> (u32, u32) {
    match kind {
        IrKind::Hir => (hir::HIR_VERSION_MIN, hir::HIR_VERSION_MAX),
        IrKind::Mir => (
            u32::from(mir::MIR_VERSION_MIN),
            u32::from(mir::MIR_VERSION_MAX),
        ),
    }
}

pub fn detect_kind(bytes: &[u8]) -> Result<IrKind, UpgradeError> {
    ensure_len(bytes, 4, "ir.magic")?;

    if bytes.len() >= hir::HIR_MAGIC.len() && bytes[..hir::HIR_MAGIC.len()] == hir::HIR_MAGIC {
        return Ok(IrKind::Hir);
    }

    if bytes.len() >= mir::MIR_MAGIC.len() && bytes[..mir::MIR_MAGIC.len()] == mir::MIR_MAGIC {
        return Ok(IrKind::Mir);
    }

    Err(UpgradeError::InvalidMagic { expected: None })
}

pub fn upgrade_bytes_auto(bytes: &[u8]) -> Result<UpgradeResult, UpgradeError> {
    match detect_kind(bytes)? {
        IrKind::Hir => upgrade_hir_bytes(bytes),
        IrKind::Mir => upgrade_mir_bytes(bytes),
    }
}

pub fn upgrade_hir_bytes(bytes: &[u8]) -> Result<UpgradeResult, UpgradeError> {
    ensure_len(bytes, hir::HIR_MAGIC.len(), "hir.magic")?;
    if bytes[..hir::HIR_MAGIC.len()] != hir::HIR_MAGIC {
        return Err(UpgradeError::InvalidMagic {
            expected: Some(IrKind::Hir),
        });
    }

    ensure_len(bytes, hir::HIR_MAGIC.len() + 4, "hir.version")?;
    let found = u32::from_le_bytes(
        bytes[hir::HIR_MAGIC.len()..hir::HIR_MAGIC.len() + 4]
            .try_into()
            .expect("slice size is checked"),
    );

    negotiate_version(IrKind::Hir, found)?;

    let mut normalized = bytes.to_vec();
    normalized[hir::HIR_MAGIC.len()..hir::HIR_MAGIC.len() + 4]
        .copy_from_slice(&hir::HIR_VERSION.to_le_bytes());

    let decoded =
        hir::types::Program::decode(&normalized).map_err(|e| UpgradeError::DecodeFailed {
            kind: IrKind::Hir,
            detail: e.to_string(),
        })?;

    Ok(UpgradeResult {
        kind: IrKind::Hir,
        from_version: found,
        to_version: hir::HIR_VERSION,
        bytes: decoded.encode(),
    })
}

pub fn upgrade_mir_bytes(bytes: &[u8]) -> Result<UpgradeResult, UpgradeError> {
    ensure_len(bytes, mir::MIR_MAGIC.len(), "mir.magic")?;
    if bytes[..mir::MIR_MAGIC.len()] != mir::MIR_MAGIC {
        return Err(UpgradeError::InvalidMagic {
            expected: Some(IrKind::Mir),
        });
    }

    ensure_len(bytes, mir::MIR_MAGIC.len() + 2, "mir.version")?;
    let found_u16 = u16::from_le_bytes(
        bytes[mir::MIR_MAGIC.len()..mir::MIR_MAGIC.len() + 2]
            .try_into()
            .expect("slice size is checked"),
    );
    let found = u32::from(found_u16);

    negotiate_version(IrKind::Mir, found)?;

    let mut normalized = bytes.to_vec();
    normalized[mir::MIR_MAGIC.len()..mir::MIR_MAGIC.len() + 2]
        .copy_from_slice(&mir::MIR_VERSION_V1.to_le_bytes());

    let decoded =
        mir::types::Program::decode(&normalized).map_err(|e| UpgradeError::DecodeFailed {
            kind: IrKind::Mir,
            detail: e.to_string(),
        })?;

    Ok(UpgradeResult {
        kind: IrKind::Mir,
        from_version: found,
        to_version: u32::from(mir::MIR_VERSION_V1),
        bytes: decoded.encode(),
    })
}

fn negotiate_version(kind: IrKind, found: u32) -> Result<(), UpgradeError> {
    let (min_supported, max_supported) = supported_range(kind);

    if found < min_supported || found > max_supported {
        return Err(UpgradeError::UnsupportedVersion {
            kind,
            found,
            min_supported,
            max_supported,
        });
    }

    Ok(())
}

fn ensure_len(bytes: &[u8], needed: usize, context: &'static str) -> Result<(), UpgradeError> {
    if bytes.len() < needed {
        return Err(UpgradeError::UnexpectedEof {
            context,
            needed,
            remaining: bytes.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{upgrade_bytes_auto, upgrade_hir_bytes, upgrade_mir_bytes, IrKind, UpgradeError};
    use crate::{bundle, checker, codegen, hir, mir, parser, replay};

    struct CorpusCase {
        name: &'static str,
        expect_deadlock_warning: bool,
        expect_unbounded_loop: bool,
        expect_fuel_bounded_loop: bool,
    }

    const CORPUS_CASES: &[CorpusCase] = &[
        CorpusCase {
            name: "01_pure_return",
            expect_deadlock_warning: false,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "02_io_read",
            expect_deadlock_warning: false,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "03_bus_schema_roundtrip",
            expect_deadlock_warning: true,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "04_spawn_join",
            expect_deadlock_warning: false,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "05_spawn_cancel",
            expect_deadlock_warning: false,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "06_io_spawn_combo",
            expect_deadlock_warning: false,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "07_fuel_guarded_loop_branch",
            expect_deadlock_warning: false,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: true,
        },
        CorpusCase {
            name: "08_unbounded_loop_branch",
            expect_deadlock_warning: false,
            expect_unbounded_loop: true,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "09_schema_int_channel",
            expect_deadlock_warning: true,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "10_deadlock_recv_without_sender",
            expect_deadlock_warning: true,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "11_dynamic_recv_pattern",
            expect_deadlock_warning: true,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
        CorpusCase {
            name: "12_bus_send_only",
            expect_deadlock_warning: false,
            expect_unbounded_loop: false,
            expect_fuel_bounded_loop: false,
        },
    ];

    #[derive(Debug, Clone)]
    struct CompileArtifacts {
        hir: Vec<u8>,
        mir: Vec<u8>,
        governancefacts: Vec<u8>,
        costfacts: Vec<u8>,
        deadlock_warning_count: usize,
        has_unbounded_loop: bool,
        has_fuel_bounded_loop: bool,
    }

    #[derive(Debug, Clone)]
    struct ReplayArtifacts {
        replay_transcript: String,
        bundle_replay_transcript: String,
        events_bytes: Vec<u8>,
        bundle_bytes: Vec<u8>,
    }

    #[test]
    fn hir_v0_golden_upgrades_to_canonical_current_bytes() {
        let current = read_hex_fixture("src/hir/golden/capability_fs_read.hir.hex");
        let legacy = read_hex_fixture("src/hir/golden/capability_fs_read.v0.hir.hex");

        let upgraded = upgrade_hir_bytes(&legacy).expect("HIR legacy fixture must upgrade");
        assert_eq!(upgraded.kind, IrKind::Hir);
        assert_eq!(upgraded.from_version, 0);
        assert_eq!(upgraded.to_version, hir::HIR_VERSION);
        assert_eq!(upgraded.bytes, current);
    }

    #[test]
    fn mir_v0_golden_upgrades_to_canonical_current_bytes() {
        let current = read_hex_fixture("src/mir/golden/simple_call_flow.mir.hex");
        let legacy = read_hex_fixture("src/mir/golden/simple_call_flow.v0.mir.hex");

        let upgraded = upgrade_mir_bytes(&legacy).expect("MIR legacy fixture must upgrade");
        assert_eq!(upgraded.kind, IrKind::Mir);
        assert_eq!(upgraded.from_version, 0);
        assert_eq!(upgraded.to_version, u32::from(mir::MIR_VERSION_V1));
        assert_eq!(upgraded.bytes, current);
    }

    #[test]
    fn upgrade_auto_detects_kind_for_legacy_fixtures() {
        let hir_legacy = read_hex_fixture("src/hir/golden/capability_fs_read.v0.hir.hex");
        let mir_legacy = read_hex_fixture("src/mir/golden/simple_call_flow.v0.mir.hex");

        let hir_result = upgrade_bytes_auto(&hir_legacy).expect("auto-upgrade HIR should pass");
        let mir_result = upgrade_bytes_auto(&mir_legacy).expect("auto-upgrade MIR should pass");

        assert_eq!(hir_result.kind, IrKind::Hir);
        assert_eq!(mir_result.kind, IrKind::Mir);
    }

    #[test]
    fn version_negotiation_rejects_out_of_range_deterministically() {
        let mut hir_bytes = read_hex_fixture("src/hir/golden/capability_fs_read.hir.hex");
        let unsupported_hir = hir::HIR_VERSION_MAX + 1;
        hir_bytes[8..12].copy_from_slice(&unsupported_hir.to_le_bytes());

        let hir_err = upgrade_hir_bytes(&hir_bytes).expect_err("unsupported HIR version must fail");
        assert_eq!(
            hir_err,
            UpgradeError::UnsupportedVersion {
                kind: IrKind::Hir,
                found: unsupported_hir,
                min_supported: hir::HIR_VERSION_MIN,
                max_supported: hir::HIR_VERSION_MAX,
            }
        );
        assert_eq!(
            hir_err.to_string(),
            format!(
                "unsupported HIR version: {} (supported: {}..={})",
                unsupported_hir,
                hir::HIR_VERSION_MIN,
                hir::HIR_VERSION_MAX
            )
        );

        let mut mir_bytes = read_hex_fixture("src/mir/golden/simple_call_flow.mir.hex");
        let unsupported_mir = u32::from(mir::MIR_VERSION_MAX) + 1;
        mir_bytes[4..6].copy_from_slice(&(unsupported_mir as u16).to_le_bytes());

        let mir_err = upgrade_mir_bytes(&mir_bytes).expect_err("unsupported MIR version must fail");
        assert_eq!(
            mir_err,
            UpgradeError::UnsupportedVersion {
                kind: IrKind::Mir,
                found: unsupported_mir,
                min_supported: u32::from(mir::MIR_VERSION_MIN),
                max_supported: u32::from(mir::MIR_VERSION_MAX),
            }
        );
        assert_eq!(
            mir_err.to_string(),
            format!(
                "unsupported MIR version: {} (supported: {}..={})",
                unsupported_mir,
                mir::MIR_VERSION_MIN,
                mir::MIR_VERSION_MAX
            )
        );
    }

    #[test]
    fn malformed_inputs_are_fail_closed_and_never_panic() {
        let valid_hir = read_hex_fixture("src/hir/golden/capability_fs_read.hir.hex");
        let valid_mir = read_hex_fixture("src/mir/golden/simple_call_flow.mir.hex");

        let mut corpus: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0x00],
            vec![0x4e, 0x45, 0x58],
            b"BAD!".to_vec(),
            vec![0xFF; 12],
            valid_hir[..11].to_vec(),
            valid_mir[..5].to_vec(),
        ];

        for i in 0..valid_hir.len() {
            corpus.push(valid_hir[..i].to_vec());
        }

        for i in 0..valid_mir.len() {
            corpus.push(valid_mir[..i].to_vec());
        }

        let mut hir_trailing = valid_hir.clone();
        hir_trailing.extend_from_slice(&[0xAA]);
        corpus.push(hir_trailing);

        let mut mir_trailing = valid_mir.clone();
        mir_trailing.extend_from_slice(&[0xAA]);
        corpus.push(mir_trailing);

        for (index, bytes) in corpus.iter().enumerate() {
            let caught = std::panic::catch_unwind(|| upgrade_bytes_auto(bytes));
            assert!(
                caught.is_ok(),
                "upgrade panicked on malformed case {}",
                index
            );

            let result = caught.expect("catch_unwind should produce result");
            assert!(result.is_err(), "malformed case {} must fail closed", index);
        }
    }

    #[test]
    fn corpus_artifacts_and_replay_match_golden() {
        if cfg!(feature = "coop_scheduler") {
            return;
        }

        let update = std::env::var("NEX_UPDATE_CORPUS_GOLDEN")
            .ok()
            .map(|v| v == "1")
            .unwrap_or(false);

        ensure_runtime_fixture_input();

        let workspace = runtime_workspace();
        if workspace.exists() {
            fs::remove_dir_all(&workspace).expect("remove stale corpus workspace");
        }
        fs::create_dir_all(&workspace).expect("create corpus workspace");

        let shared_build_dir = workspace.join("build");
        fs::create_dir_all(&shared_build_dir).expect("create shared build dir");

        for case in CORPUS_CASES {
            let source = read_case_source(case.name);
            let compile = compile_case_artifacts(&source);

            assert_eq!(
                compile.deadlock_warning_count > 0,
                case.expect_deadlock_warning,
                "deadlock warning expectation mismatch for {}",
                case.name
            );
            assert_eq!(
                compile.has_unbounded_loop, case.expect_unbounded_loop,
                "unbounded loop expectation mismatch for {}",
                case.name
            );
            assert_eq!(
                compile.has_fuel_bounded_loop, case.expect_fuel_bounded_loop,
                "fuel-bounded loop expectation mismatch for {}",
                case.name
            );

            assert_bytes_golden(
                &golden_path(case.name, "hir.bin"),
                &compile.hir,
                update,
                case.name,
                "HIR",
            );
            assert_bytes_golden(
                &golden_path(case.name, "mir.bin"),
                &compile.mir,
                update,
                case.name,
                "MIR",
            );
            assert_bytes_golden(
                &golden_path(case.name, "governancefacts.bin"),
                &compile.governancefacts,
                update,
                case.name,
                "governancefacts",
            );
            assert_bytes_golden(
                &golden_path(case.name, "costfacts.bin"),
                &compile.costfacts,
                update,
                case.name,
                "costfacts",
            );

            let replay = run_case_and_collect_replay(case.name, &source, &shared_build_dir);
            assert_bytes_golden(
                &golden_path(case.name, "events.bin"),
                &replay.events_bytes,
                update,
                case.name,
                "events",
            );
            assert_bytes_golden(
                &golden_path(case.name, "nexbundle"),
                &replay.bundle_bytes,
                update,
                case.name,
                "bundle",
            );
            assert_text_golden(
                &golden_path(case.name, "replay.txt"),
                &replay.replay_transcript,
                update,
                case.name,
                "replay",
            );
            assert_text_golden(
                &golden_path(case.name, "bundle_replay.txt"),
                &replay.bundle_replay_transcript,
                update,
                case.name,
                "bundle replay",
            );
        }
    }

    fn compile_case_artifacts(source: &str) -> CompileArtifacts {
        let ast = parser::parse(source).expect("corpus source should parse");
        checker::check(&ast).expect("checker should accept corpus source");

        let hir_program = hir::lower::lower_to_hir(&ast);
        let mir_program = mir::lower::lower_to_mir(&hir_program);
        mir::check::check(&hir_program, &mir_program).expect("MIR checker should accept corpus");

        let capability_report = hir::analysis::capability_flow::analyze(&hir_program);
        hir::analysis::capability_flow::enforce_declared_capabilities(
            &hir_program,
            &capability_report,
        )
        .expect("capability flow should pass corpus source");

        let schema_report = hir::analysis::schema_validation::analyze(&hir_program);
        hir::analysis::schema_validation::enforce(&schema_report)
            .expect("schema validation should pass corpus source");

        let governancefacts =
            hir::analysis::governancefacts::encode_from_reports(&capability_report, &schema_report);

        let cost_report = hir::analysis::cost_model::analyze(&hir_program);
        let costfacts = hir::analysis::cost_model::encode(&cost_report);

        let deadlock_report = hir::analysis::deadlock_risk::analyze(&hir_program);

        let main_fact = cost_report
            .function_facts
            .iter()
            .find(|fact| fact.function == "main")
            .expect("main function cost fact must exist");

        CompileArtifacts {
            hir: hir_program.encode(),
            mir: mir_program.encode(),
            governancefacts,
            costfacts,
            deadlock_warning_count: deadlock_report.warnings.len(),
            has_unbounded_loop: main_fact.has_unbounded_loop,
            has_fuel_bounded_loop: main_fact.has_fuel_bounded_loop,
        }
    }

    fn run_case_and_collect_replay(
        case_name: &str,
        source: &str,
        shared_build_dir: &Path,
    ) -> ReplayArtifacts {
        let case_root = runtime_workspace().join(case_name);
        if case_root.exists() {
            fs::remove_dir_all(&case_root).expect("remove previous case runtime dir");
        }

        let out_dir = case_root.join("out");
        let home_dir = case_root.join("nex_home");
        fs::create_dir_all(&out_dir).expect("create case out dir");
        write_deterministic_agent_key(&home_dir, 0);

        let ast = parser::parse(source).expect("corpus source should parse");
        checker::check(&ast).expect("checker should accept corpus source");

        let source_hash = sha256_32(source.as_bytes());
        let policy_hash = sha256_32(b"nex-corpus-policy-v1");
        let codegen_hash = codegen::compute_codegen_hash(&ast, source_hash, policy_hash, 0);

        codegen::build_project(
            &ast,
            shared_build_dir,
            codegen_hash,
            source_hash,
            policy_hash,
            0,
        )
        .expect("build_project should succeed for corpus case");

        let runner = shared_build_dir
            .join("target")
            .join("debug")
            .join("nex_out");
        let output = Command::new(&runner)
            .current_dir(project_root())
            .env("NEX_OUT_DIR", &out_dir)
            .env("NEX_HOME", &home_dir)
            .env("NEX_AGENT_ID", "0")
            .output()
            .expect("run generated runtime binary");

        assert!(
            output.status.success(),
            "corpus runtime failed for {}\nstdout:\n{}\nstderr:\n{}",
            case_name,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let events_path = out_dir.join("events.bin");
        assert!(
            events_path.exists(),
            "events.bin missing for corpus case {}",
            case_name
        );

        let replay_result = replay::verify_log_with_options(
            &events_path,
            replay::ReplayOptions { zero_trust: false },
        )
        .expect("replay should accept corpus events");

        let bundle_path = case_root.join("events.nexbundle");
        bundle::create_bundle(&events_path, &bundle_path).expect("bundle creation should succeed");

        let bundle_replay_result = bundle::replay_bundle_with_options(
            &bundle_path,
            replay::ReplayOptions { zero_trust: false },
        )
        .expect("bundle replay should accept corpus bundle");

        let events_bytes = fs::read(&events_path).expect("read corpus events.bin");
        let bundle_bytes = fs::read(&bundle_path).expect("read corpus bundle");

        ReplayArtifacts {
            replay_transcript: render_replay_transcript(&replay_result),
            bundle_replay_transcript: render_replay_transcript(&bundle_replay_result),
            events_bytes,
            bundle_bytes,
        }
    }

    fn render_replay_transcript(result: &replay::ReplayResult) -> String {
        format!(
            "✅ REPLAY OK\nevents_seen: {}\nrun_finished_seq: {}\nexit_code: {}\nrun_hash_hex: {}\ncap_allowed_total: {}\ncap_denied_total: {}\n",
            result.events_seen,
            result.run_finished_seq,
            result.exit_code,
            result.run_hash_hex,
            result.cap_allowed_total,
            result.cap_denied_total,
        )
    }

    fn write_deterministic_agent_key(home: &Path, agent_id: u32) {
        let keys_dir = home.join("keys");
        fs::create_dir_all(&keys_dir).expect("create deterministic keys dir");

        let secret = [7u8; 32];
        let signing = SigningKey::from_bytes(&secret);
        let public = signing.verifying_key().to_bytes();

        let json = format!(
            "{{\"agent_id\":{},\"public_key_b64\":\"{}\",\"secret_key_b64\":\"{}\",\"created_epoch\":null}}\n",
            agent_id,
            STANDARD.encode(public),
            STANDARD.encode(secret)
        );

        fs::write(
            keys_dir.join(format!("agent_{}.json", agent_id)),
            json.as_bytes(),
        )
        .expect("write deterministic agent key json");
    }

    fn ensure_runtime_fixture_input() {
        let path = project_root().join("tests/corpus/runtime/input.txt");
        fs::create_dir_all(path.parent().expect("runtime input parent"))
            .expect("create runtime input parent");
        fs::write(path, b"CORPUS-INPUT-STATIC\n").expect("write runtime input fixture");
    }

    fn read_case_source(case_name: &str) -> String {
        let path = project_root()
            .join("tests/corpus/cases")
            .join(format!("{}.nex", case_name));
        fs::read_to_string(&path).expect("read corpus source file")
    }

    fn golden_path(case_name: &str, suffix: &str) -> PathBuf {
        project_root()
            .join("tests/corpus/golden")
            .join(format!("{}.{}", case_name, suffix))
    }

    fn assert_bytes_golden(path: &Path, bytes: &[u8], update: bool, case_name: &str, label: &str) {
        if update {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create golden parent");
            }
            fs::write(path, bytes).expect("write corpus bytes golden");
        }

        let expected = fs::read(path).expect("read corpus bytes golden");
        assert_eq!(
            bytes,
            expected.as_slice(),
            "corpus {} golden mismatch for {}",
            label,
            case_name
        );
    }

    fn assert_text_golden(path: &Path, text: &str, update: bool, case_name: &str, label: &str) {
        let actual = if text.ends_with('\n') {
            text.to_string()
        } else {
            format!("{}\n", text)
        };

        if update {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create golden parent");
            }
            fs::write(path, actual.as_bytes()).expect("write corpus text golden");
        }

        let expected = fs::read_to_string(path).expect("read corpus text golden");
        assert_eq!(
            actual, expected,
            "corpus {} golden mismatch for {}",
            label, case_name
        );
    }

    fn runtime_workspace() -> PathBuf {
        project_root()
            .join("target")
            .join(format!("corpus_ci_runtime_{}", std::process::id()))
    }

    fn sha256_32(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    fn read_hex_fixture(relpath: &str) -> Vec<u8> {
        let path = project_root().join(relpath);
        let content = fs::read_to_string(&path).expect("read fixture hex");
        from_hex(&content).expect("parse fixture hex")
    }

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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
