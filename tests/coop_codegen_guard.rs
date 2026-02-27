#![cfg(feature = "coop_scheduler")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn generated_runtime_is_threadless_in_coop_mode() {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "nex_coop_codegen_guard_{}_{}",
        std::process::id(),
        id
    ));
    let out_dir = base.join("out");
    let build_dir = base.join("build");
    let src_file = base.join("guard_minimal.nex");

    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&out_dir).expect("create out dir");
    fs::create_dir_all(&build_dir).expect("create build dir");
    fs::write(&src_file, "fn main() {}\n").expect("write guard source");

    let run = Command::new(env!("CARGO_BIN_EXE_nex"))
        .args(["run", src_file.to_str().expect("src path utf8")])
        .env("NEX_OUT_DIR", &out_dir)
        .env("NEX_BUILD_DIR", &build_dir)
        .output()
        .expect("execute nex run");

    assert!(
        run.status.success(),
        "nex run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    let generated_src = build_dir.join("src");
    assert!(generated_src.exists(), "generated src missing");

    let mut offenders = Vec::new();
    collect_thread_tokens(&generated_src, &mut offenders);

    assert!(
        offenders.is_empty(),
        "coop generated source contains thread artifacts: {}",
        offenders.join(" | ")
    );
}

fn collect_thread_tokens(dir: &Path, offenders: &mut Vec<String>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {} failed: {}", dir.display(), e));

    let mut paths: Vec<PathBuf> = entries.map(|e| e.expect("dir entry").path()).collect();
    paths.sort();

    for path in paths {
        if path.is_dir() {
            collect_thread_tokens(&path, offenders);
            continue;
        }

        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }

        let content = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {} failed: {}", path.display(), e));

        for token in ["thread::spawn", "JoinHandle", "std::thread"] {
            if content.contains(token) {
                offenders.push(format!("{} contains {}", path.display(), token));
            }
        }
    }
}
