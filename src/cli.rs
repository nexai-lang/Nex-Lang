// src/cli.rs
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "nex")]
#[command(about="NEX language toolchain (MVP)", long_about=None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Parse { file: String },
    Check { file: String },
    Build { file: String },
    Run { file: String },
}
