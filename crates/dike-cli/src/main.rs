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
        #[arg(long, default_value = commands::corpus::DEFAULT_OLLAMA_HOST)]
        ollama_host: String,
        /// Generation model for Track 2.
        #[arg(long, default_value = "qwen2.5-coder:14b")]
        model: String,
        #[arg(long, default_value = commands::corpus::DEFAULT_EMBED_MODEL)]
        embed_model: String,
        /// Corpus index directory built by `dike corpus index`.
        #[arg(long, default_value = commands::corpus::INDEX_DIR)]
        index_dir: std::path::PathBuf,
        /// Documents retrieved per handler.
        #[arg(long, default_value_t = 5)]
        top_k: usize,
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
    /// Build the hybrid retrieval index from the fetched corpus.
    ///
    /// This is the first command that needs a live embedding model.
    Index {
        /// Delete the existing index first, so IDs that have left the
        /// corpus do not survive in the vector store.
        #[arg(long)]
        rebuild: bool,
        #[arg(long, default_value = commands::corpus::DEFAULT_EMBED_MODEL)]
        embed_model: String,
        #[arg(long, default_value = commands::corpus::DEFAULT_OLLAMA_HOST)]
        ollama_host: String,
    },
    /// Search the corpus index and report whether the result is grounded.
    Query {
        text: String,
        #[arg(long, default_value_t = 5)]
        top_k: usize,
        #[arg(long, default_value = commands::corpus::DEFAULT_EMBED_MODEL)]
        embed_model: String,
        #[arg(long, default_value = commands::corpus::DEFAULT_OLLAMA_HOST)]
        ollama_host: String,
    },
    /// Print the corpus hash that goes into a report's metadata.
    Hash,
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Analyze {
            path,
            format,
            out,
            llm,
            ollama_host,
            model,
            embed_model,
            index_dir,
            top_k,
        } => commands::analyze::run(RunConfig {
            root: path,
            format,
            out,
            llm,
            ollama_host,
            model,
            embed_model,
            index_dir,
            top_k,
        }),
        Command::Ir { path } => commands::ir::run(path),
        Command::Corpus { command } => match command {
            CorpusCommand::Fetch { update_hashes, verify } => {
                commands::corpus::fetch(update_hashes, verify)
            }
            CorpusCommand::Index { rebuild, embed_model, ollama_host } => {
                commands::corpus::index(rebuild, &embed_model, &ollama_host)
            }
            CorpusCommand::Query { text, top_k, embed_model, ollama_host } => {
                commands::corpus::query(&text, top_k, &embed_model, &ollama_host)
            }
            CorpusCommand::Hash => commands::corpus::hash(),
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
