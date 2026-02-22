// tests/golden.rs
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn out_dir_for(test_name: &str) -> PathBuf {
    PathBuf::from("target").join(format!("nex_out_{}", test_name))
}

fn ensure_out_dirs(out_dir: &Path) {
    let _ = fs::create_dir_all(out_dir.join("src"));
}

fn audit_path_for(test_name: &str) -> String {
    // Generated program runs with cwd = out_dir, so a filename is enough.
    format!("nex_audit_{}.jsonl", test_name)
}

fn remove_audit_file(out_dir: &Path, test_name: &str) {
    ensure_out_dirs(out_dir);
    let p = out_dir.join(audit_path_for(test_name));
    if p.exists() {
        let _ = fs::remove_file(p);
    }
}

fn read_audit_file(out_dir: &Path, test_name: &str) -> String {
    fs::read_to_string(out_dir.join(audit_path_for(test_name))).unwrap_or_default()
}

fn run_nex(args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new("./target/debug/nex");
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }

    let out = cmd
        .output()
        .expect("failed to run ./target/debug/nex (did you run `cargo build`?)");

    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

#[test]
fn caps_missing_is_rejected() {
    // check: no out dir needed
    let (code, out, err) = run_nex(&["check", "examples/caps_missing.nex"], &[]);
    assert!(
        code != 0,
        "expected non-zero exit for missing capabilities\nexit={code}\nstdout:\n{out}\nstderr:\n{err}"
    );
}

#[test]
fn return_all_paths_is_enforced() {
    let (code, out, err) = run_nex(&["check", "examples/return_all_paths_bad.nex"], &[]);
    assert!(
        code != 0,
        "expected non-zero exit for missing return paths\nexit={code}\nstdout:\n{out}\nstderr:\n{err}"
    );
}

#[test]
fn cancelled_in_main_runs() {
    let tname = "cancelled_in_main_runs";
    let out_dir = out_dir_for(tname);
    remove_audit_file(&out_dir, tname);

    let audit_file = audit_path_for(tname);
    let out_dir_s = out_dir.to_string_lossy().to_string();

    let env = [
        ("NEX_OUT_DIR", out_dir_s.as_str()),
        ("NEX_AUDIT_PATH", audit_file.as_str()),
    ];

    let (code, out, err) = run_nex(&["run", "examples/cancelled_in_main.nex"], &env);
    assert_eq!(
        code, 0,
        "expected exit code 0\nstdout:\n{out}\nstderr:\n{err}"
    );
}

#[test]
fn fuel_exhaustion_is_logged() {
    let tname = "fuel_exhaustion_is_logged";
    let out_dir = out_dir_for(tname);
    remove_audit_file(&out_dir, tname);

    let audit_file = audit_path_for(tname);
    let out_dir_s = out_dir.to_string_lossy().to_string();

    let env = [
        ("NEX_OUT_DIR", out_dir_s.as_str()),
        ("NEX_AUDIT_PATH", audit_file.as_str()),
    ];

    let (code, out, err) = run_nex(&["run", "examples/fuel_spin.nex"], &env);
    assert_eq!(
        code, 0,
        "expected governed termination with code 0\nstdout:\n{out}\nstderr:\n{err}"
    );

    let audit = read_audit_file(&out_dir, tname);
    assert!(
        audit.contains(r#""type":"ResourceViolation""#)
            && audit.contains(r#""kind":"FuelExhausted""#),
        "expected FuelExhausted in audit log, got:\n{audit}"
    );
}

#[test]
fn memory_exceeded_is_logged() {
    let tname = "memory_exceeded_is_logged";
    let out_dir = out_dir_for(tname);
    remove_audit_file(&out_dir, tname);

    let audit_file = audit_path_for(tname);
    let out_dir_s = out_dir.to_string_lossy().to_string();

    let env = [
        ("NEX_OUT_DIR", out_dir_s.as_str()),
        ("NEX_AUDIT_PATH", audit_file.as_str()),
        ("NEX_MEM_BUDGET", "256"),
        ("NEX_FUEL_BUDGET", "1000000"),
    ];

    let (code, out, err) = run_nex(&["run", "examples/mem_spin.nex"], &env);
    assert_eq!(
        code, 0,
        "expected governed termination with code 0\nstdout:\n{out}\nstderr:\n{err}"
    );

    let audit = read_audit_file(&out_dir, tname);
    assert!(
        audit.contains(r#""type":"ResourceViolation""#)
            && audit.contains(r#""kind":"MemoryExceeded""#),
        "expected MemoryExceeded in audit log, got:\n{audit}"
    );
}
