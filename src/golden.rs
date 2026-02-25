#![allow(dead_code)]
// src/golden.rs
//
// v0.5.5 — Golden test upgrade (CI hardening)
//
// Golden directory layout:
// tests/golden/<name>.nex
// tests/golden/<name>.nex.stdout
// tests/golden/<name>.nex.events.bin
// tests/golden/<name>.nex.events.jsonl
//
// IMPORTANT FIX:
// - If the test file is already in tests/golden/, DO NOT copy-to-self.
//   Copy-to-self can corrupt/truncate the file on some systems.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct GoldenPaths {
    pub golden_dir: PathBuf,
    pub test_nex: PathBuf,
    pub stdout: PathBuf,
    pub events_bin: PathBuf,
    pub events_jsonl: PathBuf,
}

pub fn golden_paths_for(test_nex_path: &Path) -> io::Result<GoldenPaths> {
    let test_nex = test_nex_path.to_path_buf();
    let name = test_nex_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad test filename"))?;

    if !name.ends_with(".nex") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a .nex file path",
        ));
    }

    let golden_dir = PathBuf::from("tests").join("golden");
    let stdout = golden_dir.join(format!("{name}.stdout"));
    let events_bin = golden_dir.join(format!("{name}.events.bin"));
    let events_jsonl = golden_dir.join(format!("{name}.events.jsonl"));

    Ok(GoldenPaths {
        golden_dir,
        test_nex,
        stdout,
        events_bin,
        events_jsonl,
    })
}

pub fn save_golden_artifacts(
    test_nex_path: &Path,
    run_out_dir: &Path,
    captured_stdout: &str,
) -> io::Result<GoldenPaths> {
    let gp = golden_paths_for(test_nex_path)?;
    fs::create_dir_all(&gp.golden_dir)?;

    // Only copy the .nex into tests/golden if it is NOT already there.
    // This avoids copy-to-self corruption.
    let dest_nex = gp.golden_dir.join(
        test_nex_path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad test filename"))?,
    );

    let src_abs = fs::canonicalize(test_nex_path)?;
    let dst_abs = if dest_nex.exists() {
        fs::canonicalize(&dest_nex)?
    } else {
        // If it doesn't exist yet, canonicalize parent + filename
        // by canonicalizing the parent directory.
        let parent = dest_nex
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad dest path"))?;
        fs::canonicalize(parent)?.join(
            dest_nex
                .file_name()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad dest filename"))?,
        )
    };

    if src_abs != dst_abs {
        fs::copy(test_nex_path, &dest_nex)?;
    }

    // Save stdout
    fs::write(&gp.stdout, captured_stdout.as_bytes())?;

    // Copy logs from run_out_dir
    let src_bin = run_out_dir.join("run.events.bin");
    let src_jsonl = run_out_dir.join("run.events.jsonl");

    if !src_bin.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing run.events.bin in {}", run_out_dir.display()),
        ));
    }
    if !src_jsonl.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing run.events.jsonl in {}", run_out_dir.display()),
        ));
    }

    fs::copy(src_bin, &gp.events_bin)?;
    fs::copy(src_jsonl, &gp.events_jsonl)?;

    Ok(gp)
}

pub fn verify_golden_artifacts(
    test_nex_path: &Path,
    run_out_dir: &Path,
    captured_stdout: &str,
) -> io::Result<()> {
    let gp = golden_paths_for(test_nex_path)?;

    // Must exist
    for p in [&gp.stdout, &gp.events_bin, &gp.events_jsonl] {
        if !p.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "missing golden artifact: {} (run: nex run <test>.nex --save-golden)",
                    p.display()
                ),
            ));
        }
    }

    // stdout exact
    let golden_stdout = fs::read_to_string(&gp.stdout)?;
    if golden_stdout != captured_stdout {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stdout mismatch vs golden (re-run with --save-golden to update)",
        ));
    }

    // logs exact
    let fresh_bin = run_out_dir.join("run.events.bin");
    let fresh_jsonl = run_out_dir.join("run.events.jsonl");

    byte_eq_or_err(&gp.events_bin, &fresh_bin, "events.bin")?;
    byte_eq_or_err(&gp.events_jsonl, &fresh_jsonl, "events.jsonl")?;

    Ok(())
}

fn byte_eq_or_err(golden: &Path, fresh: &Path, label: &str) -> io::Result<()> {
    let a = fs::read(golden)?;
    let b = fs::read(fresh)?;
    if a != b {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} mismatch vs golden (re-run with --save-golden to update)"),
        ));
    }
    Ok(())
}
