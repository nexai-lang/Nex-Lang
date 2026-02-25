// src/cli.rs
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "nex", version, about = "NEX — Governed Execution Kernel")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Parse {
        file: PathBuf,
    },
    Check {
        file: PathBuf,
    },
    Build {
        file: PathBuf,
    },

    Run {
        file: PathBuf,

        /// Save golden artifacts to tests/golden/<name>.*
        #[arg(long)]
        save_golden: bool,
    },

    Replay {
        log: PathBuf,
    },
    TamperTest {
        log: PathBuf,
    },

    VerifyGolden {
        test: PathBuf,
    },

    TestTamper {
        test: PathBuf,

        /// Number of trials (default 10).
        #[arg(long, default_value_t = 10)]
        trials: u32,
    },
}
