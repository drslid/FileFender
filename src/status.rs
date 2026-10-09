use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineStatus {
    Disabled,
    Starting,
    Downloading,
    Loading,
    Ready,
    Reloading,
    Error,
}

impl EngineStatus {
    /// Whether the engine can scan right now (a reload keeps the previous rules active).
    pub fn usable(self) -> bool {
        matches!(self, EngineStatus::Ready | EngineStatus::Reloading)
    }
}
