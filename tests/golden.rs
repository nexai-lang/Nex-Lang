use std::path::PathBuf;
use std::process::Command;

fn nex() -> &'static str {
    env!("CARGO_BIN_EXE_nex")
}

fn fx(name: &str) -> PathBuf {
    PathBuf::from("tests").join("fixtures").join(name)
}

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(nex()).args(args).output().expect("run nex");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn combined(stdout: &str, stderr: &str) -> String {
    format!("--- STDOUT ---\n{stdout}\n--- STDERR ---\n{stderr}\n")
}

#[test]
fn caps_missing_is_rejected() {
    let p = fx("caps_missing_fail.nex");
    let (ok, stdout, stderr) = run(&["check", p.to_str().unwrap()]);
    assert!(!ok, "expected failure\n{}", combined(&stdout, &stderr));

    let all = format!("{stdout}\n{stderr}");
    assert!(
        all.contains("Capability missing"),
        "expected 'Capability missing'\n{}",
        combined(&stdout, &stderr)
    );
}

#[test]
fn return_all_paths_is_enforced() {
    let p = fx("return_all_paths_fail.nex");
    let (ok, stdout, stderr) = run(&["check", p.to_str().unwrap()]);
    assert!(!ok, "expected failure\n{}", combined(&stdout, &stderr));

    let all = format!("{stdout}\n{stderr}");
    assert!(
        all.contains("Return error") || all.contains("Return Error"),
        "expected return error marker\n{}",
        combined(&stdout, &stderr)
    );
    assert!(
        all.contains("not all paths return"),
        "expected 'not all paths return'\n{}",
        combined(&stdout, &stderr)
    );
}

#[test]
fn cancelled_in_main_runs() {
    let p = fx("cancelled_in_main_ok.nex");
    let (ok, stdout, stderr) = run(&["run", p.to_str().unwrap()]);
    assert!(ok, "expected success\n{}", combined(&stdout, &stderr));

    let all = format!("{stdout}\n{stderr}");
    assert!(all.contains("✅ CHECK PASSED"), "missing check pass\n{}", combined(&stdout, &stderr));
    assert!(all.contains("NOT CANCELLED"), "missing program output\n{}", combined(&stdout, &stderr));
}
