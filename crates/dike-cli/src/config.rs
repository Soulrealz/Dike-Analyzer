#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Md,
    Json,
    Sarif,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub root: std::path::PathBuf,
    pub format: Format,
    pub out: Option<std::path::PathBuf>,
    /// Stripped from emitted paths so they resolve against a repository root.
    /// SARIF only; accepted for every format because a flag whose validity
    /// depends on another flag is worse than one that is simply inert.
    pub base_dir: std::path::PathBuf,
    /// Track 2 is opt-in: it needs a model and an indexed corpus, and a run
    /// without it is still a complete Track 1 run.
    pub llm: bool,
    pub ollama_host: String,
    /// Generation model. A parameter, never a constant.
    pub model: String,
    pub embed_model: String,
    pub index_dir: std::path::PathBuf,
    pub top_k: usize,
}
