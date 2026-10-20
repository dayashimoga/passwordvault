use thiserror::Error;

/// Generator error conditions.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum GeneratorError {
    /// Failure acquiring entropy from OS CSPRNG.
    #[error("RNG entropy failure: {0}")]
    EntropyFailed(String),
    /// Invalid generator options or conflicting constraints.
    #[error("Invalid generator configuration: {0}")]
    InvalidConfig(&'static str),
}
