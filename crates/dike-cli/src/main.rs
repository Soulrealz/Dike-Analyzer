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
        /// Strip this prefix from paths in SARIF output. Defaults to the
        /// current directory, which is what a CI checkout root is.
        #[arg(long)]
        base_dir: Option<std::path::PathBuf>,
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
    /// Build and validate the mutant corpus the eval harness scores against.
    Eval {
        #[command(subcommand)]
        command: EvalCommand,
    },
    /// Manage the retrieval corpus (fetch, index, query, hash).
    Corpus {
        #[command(subcommand)]
        command: CorpusCommand,
    },
}

#[derive(Subcommand)]
enum EvalCommand {
    /// Score the analyzer against injected defects: mutate, validate, run both
    /// programs, diff, and append the result to the history series.
    Run {
        /// Clean programs to mutate. A mutation applied to already-broken code
        /// cannot be attributed.
        #[arg(required = true)]
        programs: Vec<std::path::PathBuf>,
        /// Which tracks to run. `static` needs no model and no network.
        #[arg(long, value_enum, default_value_t = commands::eval::TrackSelection::Static)]
        track: commands::eval::TrackSelection,
        /// The history series to append to.
        #[arg(long, default_value = "benchmarks/history.json")]
        out: std::path::PathBuf,
        /// Where mutant trees are materialized.
        #[arg(long, default_value = "target/eval")]
        work_dir: std::path::PathBuf,
        /// Skip `cargo check` on each mutant. Findings on a mutant that no
        /// longer compiles inflate recall — for iteration, never for
        /// numbers you intend to quote.
        #[arg(long)]
        no_compile_check: bool,
        /// Identifies this run in the series. Defaults to the timestamp.
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long, default_value = commands::corpus::DEFAULT_OLLAMA_HOST)]
        ollama_host: String,
        #[arg(long, default_value = "qwen2.5-coder:14b")]
        model: String,
        #[arg(long, default_value = commands::corpus::DEFAULT_EMBED_MODEL)]
        embed_model: String,
        #[arg(long, default_value = commands::corpus::INDEX_DIR)]
        index_dir: std::path::PathBuf,
        #[arg(long, default_value_t = 5)]
        top_k: usize,
    },
    /// List the real holdout with the memorization caveat, or score it once.
    Holdout {
        /// Spend the one scored run this set permits: check out each
        /// case's program at its recorded commit, analyze it, and record the
        /// result. Without it the command only lists the cases.
        #[arg(long)]
        score: bool,
        /// Score a holdout that has already been scored once. Doing so is
        /// tuning on the test set; the flag exists so that choice is explicit.
        #[arg(long)]
        force: bool,
        /// Never fetch. Cases without a checkout already on disk are reported
        /// as not scored rather than as misses.
        #[arg(long)]
        offline: bool,
        /// Where checked-out programs live. Gitignored: these are other
        /// people's repositories at other people's commits.
        #[arg(long, default_value = commands::holdout::HOLDOUT_CHECKOUTS)]
        checkout_dir: std::path::PathBuf,
        /// The case manifest to score.
        #[arg(long, default_value = commands::holdout::HOLDOUT_CASES)]
        cases: std::path::PathBuf,
        /// Where scored runs are recorded. This file is what makes the
        /// run-once guard enforceable, so pointing it elsewhere exempts a run
        /// from the guard — which is why the tests do it and you should not.
        #[arg(long, default_value = commands::holdout::HOLDOUT_RUNS)]
        runs: std::path::PathBuf,
    },
    /// Inject one vulnerability per site into a clean program and write one
    /// case directory per mutant.
    Mutate {
        /// A clean program: a mutation applied to already-broken code cannot
        /// be attributed.
        program: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
        /// Skip `cargo check` on each mutant. A mutant that no longer compiles
        /// is not a vulnerable program but a broken one, and a finding on it
        /// counts as a true positive and inflates recall — so this is for
        /// iterating on operators, never for producing numbers.
        #[arg(long)]
        no_compile_check: bool,
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
    // INFO by default, `RUST_LOG` when set. The builder's own default filter
    // is a fixed INFO that ignores `RUST_LOG` entirely, which silently
    // swallowed the `debug!` carrying the model reply that failed the schema
    // — the one piece of evidence that says why Track 2 dropped a unit
    // (`RUST_LOG=dike_core=debug dike analyze <path> --llm`).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Analyze {
            path,
            format,
            out,
            base_dir,
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
            // Not in a `?`-friendly context (`main` returns `ExitCode`, not a
            // `Result`): an unreadable working directory degrades to "no
            // stripping" rather than failing the run (Rule 4).
            base_dir: base_dir
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))),
            llm,
            ollama_host,
            model,
            embed_model,
            index_dir,
            top_k,
        }),
        Command::Ir { path } => commands::ir::run(path),
        Command::Eval { command } => match command {
            EvalCommand::Mutate { program, out, no_compile_check } => {
                commands::eval::mutate(program, out, no_compile_check)
            }
            EvalCommand::Run {
                programs,
                track,
                out,
                work_dir,
                no_compile_check,
                run_id,
                ollama_host,
                model,
                embed_model,
                index_dir,
                top_k,
            } => commands::eval::run(commands::eval::EvalRunConfig {
                programs,
                track,
                out,
                work_dir,
                no_compile_check,
                run_id,
                llm: RunConfig {
                    root: std::path::PathBuf::new(),
                    format: Format::Md,
                    out: None,
                    // Dead for this path: eval always renders Markdown, and
                    // `base_dir` is only ever read by the SARIF renderer's
                    // path relativization. Left populated rather than
                    // special-cased, since nothing downstream reads it here.
                    base_dir: std::env::current_dir().unwrap_or_default(),
                    llm: true,
                    ollama_host,
                    model,
                    embed_model,
                    index_dir,
                    top_k,
                },
            }),
            EvalCommand::Holdout { score, force, offline, checkout_dir, cases, runs } => {
                commands::holdout::holdout(commands::holdout::HoldoutOptions {
                    score,
                    force,
                    offline,
                    checkout_dir,
                    cases_path: cases,
                    runs_path: runs,
                })
            }
        },
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
