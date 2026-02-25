// src/tamper.rs
//
// v0.5.5 — Deterministic tamper trials (CI-stable).
// No RNG. Offsets derived from SHA-256(file || trial).

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::replay;
use crate::runtime::event_reader::LOG_HEADER_LEN;

pub fn run_tamper_trials(golden_bin: &Path, trials: u32) -> io::Result<()> {
    let bytes = fs::read(golden_bin)?;
    if bytes.len() <= LOG_HEADER_LEN + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "golden log too small for tamper tests",
        ));
    }

    for i in 0..trials {
        let offset = pick_offset(&bytes, i)?;
        let tampered = write_tampered_copy(golden_bin, &bytes, offset, i)?;
        let ok = replay::verify_log(&tampered).is_ok();

        if ok {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "tamper trial {}/{} FAILED: tampered log still verified (offset={})",
                    i + 1,
                    trials,
                    offset
                ),
            ));
        }

        println!(
            "✅ Tamper test {}/{}: PASS (byte {} flipped → hash mismatch)",
            i + 1,
            trials,
            offset
        );

        let _ = fs::remove_file(&tampered);
    }

    println!("✅ All {} tamper tests passed", trials);
    Ok(())
}

fn pick_offset(bytes: &[u8], trial: u32) -> io::Result<usize> {
    let mut h = Sha256::new();
    h.update(bytes);
    h.update(&trial.to_le_bytes());
    let d = h.finalize();

    let mut x = [0u8; 8];
    x.copy_from_slice(&d[0..8]);
    let v = u64::from_le_bytes(x);

    let start = LOG_HEADER_LEN;
    let end = bytes.len() - 1;
    let span = end
        .checked_sub(start)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad span"))?;
    Ok(start + (v as usize % span))
}

fn write_tampered_copy(
    original: &Path,
    bytes: &[u8],
    offset: usize,
    trial: u32,
) -> io::Result<PathBuf> {
    let mut out = bytes.to_vec();
    out[offset] ^= 0x01;

    let name = original
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("run.events.bin");

    let mut p = original.to_path_buf();
    p.set_file_name(format!("{name}.trial{trial}.tampered"));

    fs::write(&p, &out)?;
    Ok(p)
}
