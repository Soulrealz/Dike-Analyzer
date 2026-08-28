#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Md,
    Json,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub root: std::path::PathBuf,
    pub format: Format,
    pub out: Option<std::path::PathBuf>,
    /// Track 2 is opt-in until Phase 6 lands; the flag exists from day one so the
    /// pipeline signature never changes underneath callers.
    pub llm: bool,
}
