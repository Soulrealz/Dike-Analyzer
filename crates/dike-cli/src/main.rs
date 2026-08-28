mod commands;
mod config;
mod pipeline;

use clap::{Parser, Subcommand};
use config::{Format, RunConfig};

#[derive(Parser)]
#[command(name = "dike", version, about = "Security triage for Solana Anchor programs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a program directory and print a triage report.
    Analyze {
        path: std::path::PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Md)]
        format: Format,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        #[arg(long)]
        llm: bool,
    },
    /// Debug: parse a program directory and print its IR as JSON.
    Ir { path: std::path::PathBuf },
    /// Manage the retrieval corpus (fetch, index, query, hash).
    Corpus {
        #[command(subcommand)]
        command: CorpusCommand,
    },
}

#[derive(Subcommand)]
enum CorpusCommand {
    /// Fetch every source in `corpus/sources.toml` into `corpus/cache`.
    Fetch {
        /// Rewrite `corpus/sources.toml` with the freshly fetched hashes.
        #[arg(long, conflicts_with = "verify")]
        update_hashes: bool,
        /// Treat any changed source as an error instead of a warning
        /// (the CI / reproducibility mode). Mutually exclusive with
        /// `--update-hashes`: running both would rewrite the checked-in
        /// manifest to match the new content and *then* exit non-zero,
        /// masking exactly the drift `--verify` exists to detect.
        #[arg(long, conflicts_with = "update_hashes")]
        verify: bool,
    },
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Analyze { path, format, out, llm } => {
            commands::analyze::run(RunConfig { root: path, format, out, llm })
        }
        Command::Ir { path } => commands::ir::run(path),
        Command::Corpus { command } => match command {
            CorpusCommand::Fetch { update_hashes, verify } => {
                commands::corpus::fetch(update_hashes, verify)
            }
        },
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        // Non-zero is tool failure only, never "findings exist".
        Err(err) => {
            eprintln!("dike: {err:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
