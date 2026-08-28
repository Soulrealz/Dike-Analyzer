use super::Report;

pub fn render(report: &Report) -> serde_json::Result<String> {
    serde_json::to_string_pretty(report)
}
