#[derive(Debug, Clone, PartialEq)]
pub enum Severity { Warning, Critical }

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self { Self::Warning => "warning", Self::Critical => "critical" }
    }
}

#[derive(Debug, Clone)]
pub struct Variance {
    pub severity: Severity,
    pub rule:     &'static str,
    pub detail:   String,
}
